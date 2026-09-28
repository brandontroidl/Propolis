//! Address ranges that must never be published or reported, regardless of what a sensor observed
//! or what an operator approved.
//!
//! This lives in `core-scoring` rather than in `feed` because BOTH outbound paths need it and they
//! do not share a crate: the blocklist feed publishes addresses, and the review submission runner
//! reports them to third-party vendors. It previously existed only in `feed::exclusion`, so the
//! vendor path had no such guard at all - an operator's own RFC1918 workstation could reach
//! `recommended_for_vendor` from ordinary sensor testing and be one approval click away from being
//! reported to AbuseIPDB, DShield and OTX as an attacker. One definition, both callers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use ipnet::IpNet;

/// Ranges no outbound record may ever carry, regardless of operator configuration: none of them
/// is an attacking host's own internet address. Every block the IANA IPv4 and IPv6
/// Special-Purpose Address Registries mark not globally reachable is here (both registries last
/// updated 2025-10-09, compared 2026-09-28), plus multicast, except the IPv4-mapped prefix
/// `::ffff:0:0/96`, which [`is_reserved_ip`] unwraps to the embedded IPv4 address instead. Fixed
/// and not operator-configurable, so this is computed once and shared by every caller.
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
        // "This network" (RFC 791), including the unspecified address 0.0.0.0.
        "0.0.0.0/8",
        // Shared address space for carrier-grade NAT (RFC 6598), also used by overlay networks.
        "100.64.0.0/10",
        // IETF protocol assignments (RFC 6890). Its globally reachable members, the PCP and TURN
        // anycast addresses, answer from the nearest service instance, not from one host.
        "192.0.0.0/24",
        // 6a44 relay anycast (RFC 6751). The deprecated 6to4 relay block around it has no
        // reachability status in the registry and stays publishable.
        "192.88.99.2/32",
        // Benchmarking (RFC 2544).
        "198.18.0.0/15",
        // Reserved for future use (RFC 1112); holds the limited broadcast address above.
        "240.0.0.0/4",
        // IPv6 unspecified address.
        "::/128",
        // Local-use IPv4/IPv6 translation (RFC 8215). The well-known 64:ff9b::/96 is globally
        // reachable and not listed.
        "64:ff9b:1::/48",
        // Discard-only (RFC 6666) and dummy (RFC 9780) prefixes.
        "100::/64",
        "100:0:0:1::/64",
        // IETF protocol assignments (RFC 2928), including the benchmarking prefix and Teredo, whose
        // addresses name a Teredo server and a NAT mapping rather than a host. Its globally
        // reachable members are anycast service prefixes and identifier prefixes (ORCHIDv2, drone
        // entity tags). 6to4 (2002::/16) is deliberately absent: a 6to4 address belongs to whoever
        // holds its embedded public IPv4 address.
        "2001::/23",
        // IPv6 documentation range (RFC 9637).
        "3fff::/20",
        // SRv6 segment identifiers (RFC 9602).
        "5f00::/16",
    ]
    .iter()
    .map(|s| {
        s.parse()
            .expect("hardcoded reserved-range literal must parse")
    })
    .collect()
});

/// The IPv4 address an IPv6 address carries, for the forms that name an IPv4 host: IPv4-mapped
/// (`::ffff:a.b.c.d`), the NAT64 well-known prefix (`64:ff9b::a.b.c.d`, RFC 6052) and 6to4
/// (`2002:aabb:ccdd::/48`, RFC 3056). `None` for every other address. Shared by
/// [`is_reserved_ip`] and the fetcher's SSRF guard so both decode the same forms the same way.
pub fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = v6.segments();
    let from =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
        return Some(from(seg[6], seg[7]));
    }
    if seg[0] == 0x2002 {
        return Some(from(seg[1], seg[2]));
    }
    None
}

/// True if `ip` falls in a reserved or special-purpose range that must never be published to a
/// blocklist or reported to a threat-intelligence vendor.
///
/// An IPv6 address that carries an IPv4 one ([`embedded_ipv4`]) is reserved if either is: the
/// ranges list holds the unwrapped forms, so without this `::ffff:10.0.0.1`, `64:ff9b::7f00:1` or
/// `2002:a00:1::` would pass as ordinary public addresses.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    let in_ranges = |ip: IpAddr| RESERVED_RANGES.iter().any(|net| net.contains(&ip));
    match ip {
        IpAddr::V4(_) => in_ranges(ip),
        IpAddr::V6(v6) => {
            in_ranges(ip) || embedded_ipv4(v6).is_some_and(|v4| in_ranges(IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every IPv6 form that carries an IPv4 host is judged by that host too, and only those forms
    /// are decoded: the same wrappers around a public IPv4 address stay publishable.
    #[test]
    fn an_ipv6_wrapper_around_a_reserved_ipv4_address_is_reserved() {
        for wrapped in [
            "::ffff:10.0.0.1",    // IPv4-mapped
            "64:ff9b::7f00:1",    // NAT64 well-known prefix, 127.0.0.1
            "64:ff9b::a9fe:a9fe", // NAT64 well-known prefix, 169.254.169.254
            "2002:a00:1::",       // 6to4, 10.0.0.1
            "2002:c0a8:101::5",   // 6to4, 192.168.1.1
        ] {
            assert!(
                is_reserved_ip(wrapped.parse().unwrap()),
                "{wrapped} must be reserved"
            );
        }
        for public in ["::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"] {
            assert!(
                !is_reserved_ip(public.parse().unwrap()),
                "{public} wraps a public address and must stay publishable"
            );
        }
        assert_eq!(
            embedded_ipv4("64:ff9b::7f00:1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            embedded_ipv4("2002:a00:1::".parse().unwrap()),
            Some("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            embedded_ipv4("64:ff9b:1::a00:1".parse().unwrap()),
            None,
            "only the well-known /96 NAT64 prefix carries a decodable address"
        );
        assert_eq!(embedded_ipv4("2600::1".parse().unwrap()), None);
    }

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

    /// Each block added from the IANA special-purpose registries, with the addresses at its edges
    /// that must be reserved and the neighbors just past them that must not, so a missing entry
    /// and a prefix one bit too short both fail.
    #[test]
    fn special_purpose_blocks_are_reserved_exactly_to_their_edges() {
        let blocks: [(&str, &[&str], &[&str]); 13] = [
            ("0.0.0.0/8", &["0.0.0.0", "0.255.255.255"], &["1.0.0.0"]),
            (
                "100.64.0.0/10",
                &["100.64.0.0", "100.127.255.255"],
                &["100.63.255.255", "100.128.0.0"],
            ),
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
            // Multicast sits directly below this block and nothing lies above it, so the nearest
            // unreserved neighbor is below multicast.
            (
                "240.0.0.0/4",
                &["240.0.0.0", "255.255.255.254"],
                &["223.255.255.255"],
            ),
            // ::1, between this and ::2, is loopback.
            ("::/128", &["::"], &["::2"]),
            (
                "64:ff9b:1::/48",
                &["64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"],
                &["64:ff9b:0:ffff:ffff:ffff:ffff:ffff", "64:ff9b:2::"],
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
                    "2001::",
                    "2001:0:c000:201::1",
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
            for ip in inside {
                assert!(
                    is_reserved_ip(ip.parse().unwrap()),
                    "{ip} ({block}) must be reserved"
                );
            }
            for ip in outside {
                assert!(
                    !is_reserved_ip(ip.parse().unwrap()),
                    "{ip}, just outside {block}, must not be reserved"
                );
            }
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
