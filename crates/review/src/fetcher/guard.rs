use core_scoring::{embedded_ipv4, is_reserved_ip};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EgressReject {
    Reserved,
    ExtraRange,
    OwnHost,
    Teredo,
    V4Compat,
    /// A well-known public anycast resolver. Bots probe wget/curl/tftp/ftpget against dummy URLs on
    /// these (observed: `http://1.1.1.1/wget.sh`); no malware is hosted there, so a fetch is only
    /// traffic to a third party's service.
    PublicResolver,
}

const SRC_CLOUDFLARE: &str = "https://developers.cloudflare.com/1.1.1.1/ip-addresses/";
const SRC_GOOGLE: &str = "https://developers.google.com/speed/public-dns/docs/using";
const SRC_QUAD9: &str = "https://quad9.net/service/service-addresses-and-features/";
const SRC_UMBRELLA_V4: &str = "https://umbrella.cisco.com/products/recursive-dns-services";
const SRC_UMBRELLA_V6: &str = "https://www.cisco.com/c/en/us/support/docs/security/umbrella/225331-understand-umbrella-support-for-ipv6.html";

/// Addresses the operators publish as their public resolver service, each with the operator's own
/// page that lists it. All sixteen were read from those pages on 2026-10-09:
///
/// - Cloudflare, "1.1.1.1 (standard resolver)": 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111 and
///   2606:4700:4700::1001. The same page lists the malware-blocking (1.1.1.2, 1.0.0.2,
///   2606:4700:4700::1112, ::1002) and adult-content-blocking (1.1.1.3, 1.0.0.3, ::1113, ::1003)
///   variants, which are deliberately not blocked here.
/// - Google Public DNS: 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888 and 2001:4860:4860::8844.
/// - Quad9, "Recommended: Malware Blocking, DNSSEC Validation": 9.9.9.9, 149.112.112.112,
///   2620:fe::fe and 2620:fe::9. The page also lists the ECS (9.9.9.11, 149.112.112.11,
///   2620:fe::11, 2620:fe::fe:11) and unsecured (9.9.9.10, 149.112.112.10, 2620:fe::10,
///   2620:fe::fe:10) services, also not blocked here.
/// - Cisco Umbrella (OpenDNS): "Our IPv4 addresses are: 208.67.222.222 208.67.220.220" on the
///   recursive DNS services page; "Umbrella's IPv6 DNS server addresses are: 2620:119:35::35
///   2620:119:53::53" on Cisco's IPv6 support article. Cisco's ASA guide repeats all four. The
///   old support.opendns.com pages now redirect to a Cisco community forum and are not a source.
///   The IPv6 pair could not be queried from the verifying host (no IPv6 route), so Cisco's
///   published text is the evidence for it; the IPv4 pair answered `debug.opendns.com` there.
const PUBLIC_RESOLVERS: [(&str, &str); 16] = [
    ("1.1.1.1", SRC_CLOUDFLARE),
    ("1.0.0.1", SRC_CLOUDFLARE),
    ("8.8.8.8", SRC_GOOGLE),
    ("8.8.4.4", SRC_GOOGLE),
    ("9.9.9.9", SRC_QUAD9),
    ("149.112.112.112", SRC_QUAD9),
    ("208.67.222.222", SRC_UMBRELLA_V4),
    ("208.67.220.220", SRC_UMBRELLA_V4),
    ("2606:4700:4700::1111", SRC_CLOUDFLARE),
    ("2606:4700:4700::1001", SRC_CLOUDFLARE),
    ("2001:4860:4860::8888", SRC_GOOGLE),
    ("2001:4860:4860::8844", SRC_GOOGLE),
    ("2620:fe::fe", SRC_QUAD9),
    ("2620:fe::9", SRC_QUAD9),
    ("2620:119:35::35", SRC_UMBRELLA_V6),
    ("2620:119:53::53", SRC_UMBRELLA_V6),
];

/// Matches against the canonicalized address, so v4-mapped, 6to4 and NAT64 forms of a resolver
/// are caught as well.
fn is_public_resolver(ip: IpAddr) -> bool {
    PUBLIC_RESOLVERS
        .iter()
        .any(|(s, _)| s.parse::<IpAddr>().is_ok_and(|r| r == ip))
}

fn canonicalize(ip: IpAddr) -> Result<IpAddr, EgressReject> {
    let IpAddr::V6(v6) = ip else {
        return Ok(ip);
    };
    // IPv4-mapped, the NAT64 well-known /96 and 6to4: dial-checked as the IPv4 host they name.
    if let Some(v4) = embedded_ipv4(v6) {
        return Ok(IpAddr::V4(v4));
    }
    let seg = v6.segments();
    if seg[0] == 0x64 && seg[1] == 0xff9b {
        // Any other NAT64 address (e.g. the 64:ff9b:1::/48 local-use prefix). Propolis has a v4 WAN
        // (no NAT64 route), so a NAT64 address can only be an attacker steering us at a translated
        // target, and only the well-known /96 decodes cleanly; over-blocking the rest is safe here.
        return Err(EgressReject::ExtraRange);
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

/// Never-dial entries checked after the shared never-publish list. All three are in that list too;
/// they are repeated here so the fetcher's deny set cannot shrink if that list is ever narrowed
/// for publishing reasons.
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
    if is_public_resolver(c) {
        return Some(EgressReject::PublicResolver);
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
///
/// `Send + Sync` supertraits: `FetchDeps.resolver` is `Box<dyn HostResolver + Send + Sync>`, and
/// `http.rs`'s `RealHopFetcher` holds a `&dyn HostResolver` across an `.await` point - without
/// these supertraits that reference is not `Send`, which only surfaces once something calls
/// `run_cycle` from a real multi-threaded `tokio::spawn` (as the `propolis` daemon's
/// `spawn_supervised` does); every existing `#[tokio::test]` here runs on the single-threaded
/// current-thread runtime by default, so the gap never showed up in this crate's own test suite.
pub trait HostResolver: Send + Sync {
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
/// Async wrapper around [`vet`]: runs the (blocking, `getaddrinfo`-backed) resolution on the
/// blocking pool with an independent `dns_timeout`, so a slow or hostile DNS response can neither
/// stall a shared async worker nor hang unbounded. [`vet`]'s SSRF-vetting logic is unchanged - only
/// its invocation moves off the worker. A timeout, or a resolver task that panics, fails CLOSED to
/// [`GuardReject::ResolveFailed`] (an unresolvable target is rejected, never fetched).
pub async fn vet_async(
    url: &str,
    own: &HashSet<IpAddr>,
    resolver: std::sync::Arc<dyn HostResolver + Send + Sync>,
    allow_tftp: bool,
    dns_timeout: std::time::Duration,
) -> Result<Pinned, GuardReject> {
    let own = own.clone();
    let url = url.to_string();
    match tokio::time::timeout(
        dns_timeout,
        tokio::task::spawn_blocking(move || vet(&url, &own, resolver.as_ref(), allow_tftp)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_join)) => Err(GuardReject::ResolveFailed),
        Err(_elapsed) => Err(GuardReject::ResolveFailed),
    }
}

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
            "93.184.216.34",
            "1.1.1.2", // next to a resolver, not one
            "9.9.9.10",
            "::ffff:93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
            "2606:4700:4700::1112",
        ] {
            assert!(
                is_forbidden_egress_target(ip(ok), &own).is_none(),
                "should allow {ok}"
            );
        }
    }
    /// The special-purpose blocks the shared reserved list gained from the IANA registries are
    /// never dialed, up to their edges, and the addresses just past each edge still are. Blocks
    /// the guard already refused before that (`0.0.0.0/8`, `100.64.0.0/10`, `::`, the NAT64
    /// prefixes) stay covered by `forbidden_targets_are_all_rejected`.
    #[test]
    fn special_purpose_blocks_are_rejected_exactly_to_their_edges() {
        let own = HashSet::new();
        let blocks: [(&str, &[&str], &[&str]); 9] = [
            (
                "192.0.0.0/24",
                &["192.0.0.0", "192.0.0.9", "192.0.0.255"],
                &["191.255.255.255", "192.0.1.0"],
            ),
            (
                "192.88.99.2/32",
                &["192.88.99.2"],
                &["192.88.99.1", "192.88.99.3"],
            ),
            (
                "198.18.0.0/15",
                &["198.18.0.0", "198.19.255.255"],
                &["198.17.255.255", "198.20.0.0"],
            ),
            (
                "240.0.0.0/4",
                &["240.0.0.0", "255.255.255.254"],
                &["223.255.255.255"],
            ),
            (
                "100::/64",
                &["100::", "100::ffff:ffff:ffff:ffff"],
                &["ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            ),
            (
                "100:0:0:1::/64",
                &["100:0:0:1::", "100:0:0:1:ffff:ffff:ffff:ffff"],
                &["100:0:0:2::"],
            ),
            (
                "2001::/23",
                &[
                    "2001:1::1",
                    "2001:2::1",
                    "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
                &["2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:200::"],
            ),
            (
                "3fff::/20",
                &["3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"],
                &["3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff:1000::"],
            ),
            (
                "5f00::/16",
                &["5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
                &["5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "5f01::"],
            ),
        ];
        for (block, inside, outside) in blocks {
            for bad in inside {
                assert!(
                    is_forbidden_egress_target(ip(bad), &own).is_some(),
                    "should reject {bad} ({block})"
                );
            }
            for ok in outside {
                assert!(
                    is_forbidden_egress_target(ip(ok), &own).is_none(),
                    "should allow {ok}, just outside {block}"
                );
            }
        }
    }

    // core_scoring::is_reserved_ip now canonicalizes the v4-mapped form itself (F-1), so this
    // guard's own `canonicalize` is defense-in-depth rather than the only place that catches it.
    #[test]
    fn base_is_reserved_ip_now_catches_v4_mapped() {
        assert!(core_scoring::is_reserved_ip(ip("::ffff:10.0.0.1")));
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

    #[tokio::test]
    async fn vet_async_preserves_the_ssrf_rejection() {
        // Resolver maps the host to our own WAN IP; `vet` rejects an own-IP target (an SSRF
        // self-hit) and the async wrapper must surface that rejection unchanged.
        let own: HashSet<IpAddr> = [ip("203.0.113.9")].into_iter().collect();
        let resolver: std::sync::Arc<dyn HostResolver + Send + Sync> =
            std::sync::Arc::new(MockResolver(vec![ip("203.0.113.9")]));
        let result = vet_async(
            "http://evil.test/x",
            &own,
            resolver,
            false,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            result.is_err(),
            "an own-IP target must still be rejected through vet_async"
        );
    }

    #[tokio::test]
    async fn vet_async_times_out_a_slow_resolver_and_fails_closed() {
        struct SlowResolver;
        impl HostResolver for SlowResolver {
            fn resolve(&self, _h: &str) -> std::io::Result<Vec<IpAddr>> {
                std::thread::sleep(std::time::Duration::from_millis(500));
                Ok(vec!["93.184.216.34".parse().unwrap()])
            }
        }
        let own: HashSet<IpAddr> = HashSet::new();
        let resolver: std::sync::Arc<dyn HostResolver + Send + Sync> =
            std::sync::Arc::new(SlowResolver);
        // The 50ms DNS timeout fires before the 500ms resolver returns: fail closed to ResolveFailed.
        let result = vet_async(
            "http://slow.test/x",
            &own,
            resolver,
            false,
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(result, Err(GuardReject::ResolveFailed)),
            "a slow resolver must time out and reject, got {result:?}"
        );
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
        let p = vet("tftp://93.184.216.34/mal", &own, &PanicResolver, true).unwrap();
        assert!(matches!(p.scheme, Scheme::Tftp));
        assert_eq!(p.port, 69);
        assert_eq!(p.ip, ip("93.184.216.34"));
    }

    // Fix round 1, #4 (important): spec section 7 - force destination port 69, reject any
    // explicit non-69 port (blocks arbitrary-UDP-service abuse / amplification via a tftp:// url
    // aimed at some other UDP service on the target host).
    #[test]
    fn vet_tftp_explicit_non69_port_is_rejected() {
        let own = HashSet::new();
        assert!(matches!(
            vet("tftp://93.184.216.34:6900/mal", &own, &PanicResolver, true),
            Err(GuardReject::TftpPortForbidden)
        ));
    }

    #[test]
    fn vet_tftp_explicit_port_69_is_allowed() {
        let own = HashSet::new();
        let p = vet("tftp://93.184.216.34:69/mal", &own, &PanicResolver, true).unwrap();
        assert_eq!(p.port, 69);
    }

    const RESOLVER_V4: [&str; 8] = [
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        "208.67.220.220",
    ];
    const RESOLVER_V6: [&str; 8] = [
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2620:fe::fe",
        "2620:fe::9",
        "2620:119:35::35",
        "2620:119:53::53",
    ];

    fn is_resolver_reject(r: Result<Pinned, GuardReject>) -> bool {
        matches!(r, Err(GuardReject::Forbidden(EgressReject::PublicResolver)))
    }

    #[test]
    fn every_listed_resolver_cites_an_operator_page_and_the_list_is_exactly_the_verified_set() {
        let listed: Vec<&str> = PUBLIC_RESOLVERS.iter().map(|(a, _)| *a).collect();
        let verified: Vec<&str> = RESOLVER_V4
            .iter()
            .chain(RESOLVER_V6.iter())
            .copied()
            .collect();
        assert_eq!(listed, verified);
        for (addr, source) in PUBLIC_RESOLVERS {
            assert!(
                source.starts_with("https://") && source.len() > "https://".len(),
                "{addr} has no source"
            );
            // Each family's source page is its operator's, not a third-party listing.
            let host_ok = [
                "developers.cloudflare.com",
                "developers.google.com",
                "quad9.net",
                "umbrella.cisco.com",
                "www.cisco.com",
            ]
            .iter()
            .any(|h| source.starts_with(&format!("https://{h}/")));
            assert!(host_ok, "{addr}: {source}");
        }
    }

    #[test]
    fn every_public_resolver_is_forbidden_with_its_own_reason() {
        let own = HashSet::new();
        for a in RESOLVER_V4.iter().chain(RESOLVER_V6.iter()) {
            assert_eq!(
                is_forbidden_egress_target(ip(a), &own),
                Some(EgressReject::PublicResolver),
                "{a}"
            );
        }
        assert_eq!(
            PUBLIC_RESOLVERS.len(),
            RESOLVER_V4.len() + RESOLVER_V6.len()
        );
    }

    #[test]
    fn resolver_probe_urls_from_a_telnet_bot_are_rejected_for_http_and_tftp() {
        let own = HashSet::new();
        for url in [
            "http://1.1.1.1/wget.sh",
            "http://1.1.1.1/curl.sh",
            "tftp://1.1.1.1/tftp.sh",
            "http://[2606:4700:4700::1111]/wget.sh",
            "tftp://8.8.4.4/tftp.sh",
        ] {
            assert!(
                is_resolver_reject(vet(url, &own, &PanicResolver, true)),
                "{url}"
            );
        }
        // ftp:// is not an allowed scheme at all.
        assert!(matches!(
            vet("ftp://1.1.1.1/ftpget.sh", &own, &PanicResolver, true),
            Err(GuardReject::BadScheme)
        ));
    }

    #[test]
    fn ipv4_mapped_nat64_and_6to4_forms_of_a_resolver_are_forbidden() {
        let own = HashSet::new();
        for url in [
            "http://[::ffff:1.1.1.1]/x",
            "http://[::ffff:808:808]/x",
            "http://[64:ff9b::808:808]/x",
            "http://[2002:808:808::]/x",
            "tftp://[::ffff:9.9.9.9]/x",
        ] {
            assert!(
                is_resolver_reject(vet(url, &own, &PanicResolver, true)),
                "{url}"
            );
        }
    }

    #[test]
    fn a_hostname_resolving_to_a_resolver_is_forbidden_dns_rebinding_style() {
        let own = HashSet::new();
        for a in ["1.1.1.1", "2001:4860:4860::8888", "208.67.220.220"] {
            let r = MockResolver(vec![ip(a)]);
            assert!(
                is_resolver_reject(vet("http://payload.example/x", &own, &r, true)),
                "{a}"
            );
        }
        // A public address first and a resolver second still rejects the whole host.
        let mixed = MockResolver(vec![ip("93.184.216.34"), ip("9.9.9.9")]);
        assert!(is_resolver_reject(vet(
            "http://payload.example/x",
            &own,
            &mixed,
            true
        )));
    }

    #[test]
    fn a_neighbour_of_a_resolver_address_is_still_fetchable() {
        let own = HashSet::new();
        let r = MockResolver(vec![ip("1.1.1.3")]);
        assert_eq!(
            vet("http://payload.example/x", &own, &r, true).unwrap().ip,
            ip("1.1.1.3")
        );
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
