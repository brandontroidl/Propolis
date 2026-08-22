use core_scoring::is_reserved_ip;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EgressReject {
    Reserved,
    ExtraRange,
    OwnHost,
    Teredo,
    V4Compat,
}

fn canonicalize(ip: IpAddr) -> Result<IpAddr, EgressReject> {
    let IpAddr::V6(v6) = ip else {
        return Ok(ip);
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Ok(IpAddr::V4(v4)); // ::ffff:a.b.c.d
    }
    let seg = v6.segments();
    if seg[0] == 0x64 && seg[1] == 0xff9b {
        // NAT64 well-known prefix space (RFC 6052 / RFC 8215). Decode the well-known /96 form to its
        // embedded IPv4 and re-check; reject any other NAT64 address (e.g. the 64:ff9b:1::/48
        // local-use prefix) outright. Propolis has a v4 WAN (no NAT64 route), so a NAT64 address can
        // only be an attacker steering us at a translated target, and only the /96 form decodes
        // cleanly; over-blocking the rest is safe here.
        if seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                (seg[6] >> 8) as u8,
                seg[6] as u8,
                (seg[7] >> 8) as u8,
                seg[7] as u8,
            )));
        }
        return Err(EgressReject::ExtraRange);
    }
    if seg[0] == 0x2002 {
        // 6to4 2002::/16
        return Ok(IpAddr::V4(Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        )));
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        return Err(EgressReject::Teredo); // 2001::/32
    }
    // ::a.b.c.d IPv4-compatible (deprecated) -> reject outright
    if seg[0..6].iter().all(|&s| s == 0) && (seg[6] != 0 || seg[7] > 1) {
        return Err(EgressReject::V4Compat);
    }
    Ok(ip)
}

fn in_extra_egress_deny(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0                               // 0.0.0.0/8
              || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => v6 == Ipv6Addr::UNSPECIFIED, // ::
    }
}

pub fn is_forbidden_egress_target(ip: IpAddr, own: &HashSet<IpAddr>) -> Option<EgressReject> {
    let c = match canonicalize(ip) {
        Ok(c) => c,
        Err(r) => return Some(r),
    };
    if own.contains(&c) {
        return Some(EgressReject::OwnHost);
    }
    if is_reserved_ip(c) {
        return Some(EgressReject::Reserved);
    }
    if in_extra_egress_deny(c) {
        return Some(EgressReject::ExtraRange);
    }
    None
}

/// Egress-allowed URL schemes. `Tftp` is only reachable for the initial fetch URL (never a
/// redirect target); callers enforce that by passing `allow_tftp: false` on hop revalidation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scheme {
    Http,
    Https,
    Tftp,
}

/// A URL that has cleared `vet`: the connect path uses `ip` only, never re-resolving `host`.
#[derive(Debug, Clone, PartialEq)]
pub struct Pinned {
    pub host: String,
    pub ip: IpAddr,
    pub port: u16,
    pub scheme: Scheme,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuardReject {
    BadUrl,
    Userinfo,
    BadScheme,
    NoHost,
    ResolveFailed,
    Forbidden(EgressReject),
    /// A `tftp://` URL named an explicit port other than 69. Spec section 7: force destination
    /// port 69 and reject any other explicit port, so a `tftp://host:PORT/x` cannot be used to
    /// aim arbitrary UDP traffic at some other service on the target host.
    TftpPortForbidden,
}

/// Resolves a hostname to its address set. Abstracted so tests never touch a live resolver.
pub trait HostResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// Production resolver: the OS stub resolver via `getaddrinfo`.
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        // Port 0 is a placeholder; only the resolved address set is used.
        (host, 0u16)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|sa| sa.ip()).collect())
    }
}

/// Vet + pin a fetch URL, load-bearing SSRF guard. Run identically on the initial URL and on
/// every redirect hop (with `allow_tftp: false` on hops, since a redirect may never cross into
/// tftp). Fail-closed at every step.
pub fn vet(
    url: &str,
    own: &HashSet<IpAddr>,
    r: &dyn HostResolver,
    allow_tftp: bool,
) -> Result<Pinned, GuardReject> {
    let parsed = url::Url::parse(url).map_err(|_| GuardReject::BadUrl)?;

    // `user:pass@host` defeats naive host extraction; reject outright.
    let has_userinfo =
        !parsed.username().is_empty() || parsed.password().is_some_and(|p| !p.is_empty());
    if has_userinfo {
        return Err(GuardReject::Userinfo);
    }

    let scheme = match parsed.scheme() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        "tftp" if allow_tftp => Scheme::Tftp,
        _ => return Err(GuardReject::BadScheme),
    };

    // IDN hosts are already punycode-ASCII here; the `url` crate normalized them during parse.
    let host = parsed.host().ok_or(GuardReject::NoHost)?;
    let (host_str, ips): (String, Vec<IpAddr>) = match host {
        // IP literal (including decimal/octal/hex forms the parser folded to canonical dotted
        // form): use it directly and skip DNS so the resolver can never be consulted for it.
        url::Host::Ipv4(v4) => (v4.to_string(), vec![IpAddr::V4(v4)]),
        url::Host::Ipv6(v6) => (v6.to_string(), vec![IpAddr::V6(v6)]),
        // A non-special scheme (tftp) never gets WHATWG numeric-host normalization, so a
        // canonical dotted-quad or v6 literal still arrives here as an opaque domain string.
        // Recognize it ourselves before falling back to DNS, so the literal fast path (and the
        // DNS skip it guarantees) holds for every allowed scheme, not just http/https.
        url::Host::Domain(d) => match d.parse::<IpAddr>() {
            Ok(literal) => (d.to_string(), vec![literal]),
            Err(_) => {
                let resolved = r.resolve(d).map_err(|_| GuardReject::ResolveFailed)?;
                (d.to_string(), resolved)
            }
        },
    };
    if ips.is_empty() {
        return Err(GuardReject::ResolveFailed);
    }

    // A mixed public+internal resolve set is a rebinding attack: any forbidden address rejects
    // the whole host rather than cherry-picking a surviving public one.
    for ip in &ips {
        if let Some(reason) = is_forbidden_egress_target(*ip, own) {
            return Err(GuardReject::Forbidden(reason));
        }
    }
    let ip = ips[0];

    // `url` only knows default ports for the WHATWG "special" schemes (http/https/ws/wss/ftp);
    // tftp isn't one, so an explicit port still comes through but a bare `tftp://host/x` needs
    // its default (69) supplied here. tftp additionally forces the destination port to 69
    // outright (spec section 7): an explicit non-69 port is rejected rather than honored, so a
    // tftp:// url can never be used to aim arbitrary UDP traffic at some other service on the
    // target host. `Url::port()` (not `port_or_known_default()`) is used for tftp specifically
    // to distinguish "no port in the url" from "port present" - tftp has no WHATWG default, so
    // `port_or_known_default()` would already return `None` in both cases.
    let port = if scheme == Scheme::Tftp {
        match parsed.port() {
            Some(p) if p != 69 => return Err(GuardReject::TftpPortForbidden),
            _ => 69,
        }
    } else {
        match parsed.port_or_known_default() {
            Some(p) => p,
            None => return Err(GuardReject::BadUrl),
        }
    };

    Ok(Pinned {
        host: host_str,
        ip,
        port,
        scheme,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forbidden_targets_are_all_rejected() {
        let own: HashSet<IpAddr> = [ip("203.0.113.9")].into_iter().collect(); // pretend our WAN
        for bad in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1", // v4-mapped
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",   // NAT64
            "64:ff9b:1::7f00:1", // NAT64 local-use /48, not the well-known /96
            "2002:7f00:1::",     // 6to4 -> 127.0.0.1
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "fe80::1",
            "fc00::1",
            "224.0.0.1",
            "203.0.113.9", // last = own
        ] {
            assert!(
                is_forbidden_egress_target(ip(bad), &own).is_some(),
                "should reject {bad}"
            );
        }
    }
    #[test]
    fn public_targets_including_mapped_are_allowed() {
        let own = HashSet::new();
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "::ffff:8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            assert!(
                is_forbidden_egress_target(ip(ok), &own).is_none(),
                "should allow {ok}"
            );
        }
    }
    // Regression: document that the base is_reserved_ip misses the mapped form (F-1 target).
    #[test]
    fn base_is_reserved_ip_misses_v4_mapped() {
        assert!(!core_scoring::is_reserved_ip(ip("::ffff:10.0.0.1")));
    }

    struct MockResolver(Vec<IpAddr>);
    impl HostResolver for MockResolver {
        fn resolve(&self, _h: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }
    fn pub_resolver() -> MockResolver {
        MockResolver(vec!["93.184.216.34".parse().unwrap()])
    }

    #[test]
    fn vet_rejects_bad_schemes_and_userinfo() {
        let own = HashSet::new();
        for bad in [
            "file:///etc/passwd",
            "gopher://x/",
            "data:text/plain,x",
            "ftp://x/",
            "dict://x/",
        ] {
            assert!(matches!(
                vet(bad, &own, &pub_resolver(), true),
                Err(GuardReject::BadScheme)
            ));
        }
        assert!(matches!(
            vet(
                "http://trusted.com@169.254.169.254/",
                &own,
                &pub_resolver(),
                true
            ),
            Err(GuardReject::Userinfo)
        ));
    }
    #[test]
    fn vet_rejects_internal_and_mixed_sets() {
        let own = HashSet::new();
        assert!(matches!(
            vet(
                "http://127.0.0.1/",
                &own,
                &MockResolver(vec!["127.0.0.1".parse().unwrap()]),
                true
            ),
            Err(GuardReject::Forbidden(_))
        ));
        // literal decimal/octal/hex normalize to 127.0.0.1 via the url crate
        for enc in [
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
        ] {
            assert!(
                matches!(
                    vet(enc, &own, &pub_resolver(), true),
                    Err(GuardReject::Forbidden(_))
                ),
                "enc {enc} should reject (host is a reserved literal, resolver unused)"
            );
        }
        // mixed public+internal resolve -> reject the whole host
        let mixed = MockResolver(vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ]);
        assert!(matches!(
            vet("http://evil.example/", &own, &mixed, true),
            Err(GuardReject::Forbidden(_))
        ));
    }
    #[test]
    fn vet_pins_a_public_ip() {
        let own = HashSet::new();
        let p = vet("http://example.com/x", &own, &pub_resolver(), true).unwrap();
        assert_eq!(p.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
        assert!(matches!(p.scheme, Scheme::Http));
    }
    #[test]
    fn vet_redirect_context_forbids_tftp() {
        let own = HashSet::new();
        assert!(matches!(
            vet("tftp://example.com/x", &own, &pub_resolver(), false),
            Err(GuardReject::BadScheme)
        ));
    }

    /// Panics if `resolve` is ever called - proves an IP-literal host skips DNS entirely.
    struct PanicResolver;
    impl HostResolver for PanicResolver {
        fn resolve(&self, _h: &str) -> std::io::Result<Vec<IpAddr>> {
            panic!("resolver must not be called for an IP literal host");
        }
    }

    #[test]
    fn vet_ipv6_literal_loopback_rejected_without_dns() {
        let own = HashSet::new();
        assert!(matches!(
            vet("http://[::1]/x", &own, &PanicResolver, false),
            Err(GuardReject::Forbidden(_))
        ));
    }

    #[test]
    fn vet_tftp_literal_pins_default_port_69() {
        let own = HashSet::new();
        let p = vet("tftp://8.8.8.8/mal", &own, &PanicResolver, true).unwrap();
        assert!(matches!(p.scheme, Scheme::Tftp));
        assert_eq!(p.port, 69);
        assert_eq!(p.ip, ip("8.8.8.8"));
    }

    // Fix round 1, #4 (important): spec section 7 - force destination port 69, reject any
    // explicit non-69 port (blocks arbitrary-UDP-service abuse / amplification via a tftp:// url
    // aimed at some other UDP service on the target host).
    #[test]
    fn vet_tftp_explicit_non69_port_is_rejected() {
        let own = HashSet::new();
        assert!(matches!(
            vet("tftp://8.8.8.8:6900/mal", &own, &PanicResolver, true),
            Err(GuardReject::TftpPortForbidden)
        ));
    }

    #[test]
    fn vet_tftp_explicit_port_69_is_allowed() {
        let own = HashSet::new();
        let p = vet("tftp://8.8.8.8:69/mal", &own, &PanicResolver, true).unwrap();
        assert_eq!(p.port, 69);
    }

    struct EmptyResolver;
    impl HostResolver for EmptyResolver {
        fn resolve(&self, _h: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(vec![])
        }
    }

    #[test]
    fn vet_empty_resolve_set_fails_closed() {
        let own = HashSet::new();
        assert!(matches!(
            vet("http://nothing.example/x", &own, &EmptyResolver, false),
            Err(GuardReject::ResolveFailed)
        ));
    }
}
