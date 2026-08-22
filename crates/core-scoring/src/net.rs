//! Address ranges that must never be published or reported, regardless of what a sensor observed
//! or what an operator approved.
//!
//! This lives in `core-scoring` rather than in `feed` because BOTH outbound paths need it and they
//! do not share a crate: the blocklist feed publishes addresses, and the review submission runner
//! reports them to third-party vendors. It previously existed only in `feed::exclusion`, so the
//! vendor path had no such guard at all - an operator's own RFC1918 workstation could reach
//! `recommended_for_vendor` from ordinary sensor testing and be one approval click away from being
//! reported to AbuseIPDB, DShield and OTX as an attacker. One definition, both callers.

use std::net::IpAddr;
use std::sync::LazyLock;

use ipnet::IpNet;

/// Special-purpose ranges no outbound record may ever carry, regardless of operator
/// configuration: RFC1918 private space, RFC5737 documentation ranges, loopback, link-local,
/// multicast, the limited broadcast address, and their IPv6 equivalents (loopback, link-local,
/// unique-local, multicast, and the documentation range). Fixed and not operator-configurable, so
/// this is computed once and shared by every caller.
static RESERVED_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        // RFC1918 private address space.
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        // RFC5737 documentation ranges (TEST-NET-1/2/3).
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        // Loopback.
        "127.0.0.0/8",
        "::1/128",
        // Link-local.
        "169.254.0.0/16",
        "fe80::/10",
        // Multicast.
        "224.0.0.0/4",
        "ff00::/8",
        // Limited broadcast.
        "255.255.255.255/32",
        // IPv6 unique local addresses (ULA).
        "fc00::/7",
        // IPv6 documentation range.
        "2001:db8::/32",
    ]
    .iter()
    .map(|s| {
        s.parse()
            .expect("hardcoded reserved-range literal must parse")
    })
    .collect()
});

/// True if `ip` falls in a reserved or special-purpose range that must never be published to a
/// blocklist or reported to a threat-intelligence vendor.
///
/// Canonicalizes an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its embedded IPv4 form first,
/// so a mapped private/reserved address cannot slip past this check the way a bare
/// `RESERVED_RANGES` lookup would miss it (the ranges list only carries the unmapped `::1`/
/// `fe80::/10`/etc forms, never the `::ffff:0:0/96` wrapper). The fetcher's own SSRF guard
/// (`review::fetcher::guard::canonicalize`) already does this unwrap before calling in; this
/// backports the same behavior here so every caller of the shared function gets it.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    RESERVED_RANGES.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1918_space_is_reserved() {
        for ip in ["10.20.30.109", "172.16.4.4", "192.168.1.1"] {
            assert!(is_reserved_ip(ip.parse().unwrap()), "{ip} must be reserved");
        }
    }

    #[test]
    fn documentation_loopback_linklocal_and_multicast_are_reserved() {
        for ip in [
            "192.0.2.5",
            "198.51.100.5",
            "203.0.113.5",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff00::1",
            "2001:db8::1",
        ] {
            assert!(is_reserved_ip(ip.parse().unwrap()), "{ip} must be reserved");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_reserved_addresses_are_caught() {
        // The fetcher's own SSRF guard (review::fetcher::guard::canonicalize) already unwraps
        // `::ffff:a.b.c.d` before checking; this backports the same canonicalization here so
        // every caller of the shared function gets it, not just the fetcher.
        for ip in [
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                is_reserved_ip(ip.parse().unwrap()),
                "{ip} (v4-mapped) must be reserved"
            );
        }
    }

    #[test]
    fn ordinary_public_addresses_are_not_reserved() {
        // Deliberately NOT RFC5737 documentation space: those ranges are themselves reserved (see
        // the test above), so this case needs globally-routable addresses. Uses only well-known
        // public resolver anycast addresses, never a real address observed in honeypot traffic -
        // an attacker's IP must not be committed to the repo.
        for ip in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "2606:4700::1"] {
            assert!(
                !is_reserved_ip(ip.parse().unwrap()),
                "{ip} must not be reserved"
            );
        }
    }
}
