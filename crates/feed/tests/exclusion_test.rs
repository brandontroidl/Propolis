//! Pure in-memory tests for `ExclusionEngine` - no database needed. Covers every reserved
//! category the design lists (RFC1918, RFC5737, loopback, link-local, multicast, broadcast, and
//! their IPv6 equivalents) plus the operator-configurable allowlist and delist.
//!
//! `1.2.3.4` / `5.6.7.8` / `9.9.9.9` / `2003:aaaa:bbbb::1` stand in for "an ordinary public
//! address" in the "passes" cases below. There is no address range that is simultaneously
//! guaranteed-never-real AND outside this filter's reserved ranges - RFC5737/RFC1918/2001:db8 ARE
//! those guaranteed-fake ranges, and this filter's whole job is to exclude them. These values are
//! arbitrary placeholder numbers, not an assertion about any real host.

use std::net::IpAddr;

use feed::ExclusionEngine;

fn permissive() -> ExclusionEngine {
    ExclusionEngine::new(Vec::new(), Vec::new())
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn rfc1918_private_ranges_are_excluded() {
    let e = permissive();
    for addr in [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ] {
        assert!(
            e.is_excluded(ip(addr)),
            "{addr} should be excluded (RFC1918)"
        );
    }
}

#[test]
fn addresses_just_outside_rfc1918_are_not_caught_by_that_rule() {
    // Adjacent-but-outside addresses prove the ranges are bounded correctly, not open-ended.
    let e = permissive();
    assert!(!e.is_excluded(ip("11.0.0.1")));
    assert!(!e.is_excluded(ip("172.32.0.1")));
    assert!(!e.is_excluded(ip("192.169.0.1")));
}

#[test]
fn rfc5737_documentation_ranges_are_excluded() {
    let e = permissive();
    for addr in [
        "192.0.2.1",
        "192.0.2.255",
        "198.51.100.1",
        "198.51.100.255",
        "203.0.113.1",
        "203.0.113.255",
    ] {
        assert!(
            e.is_excluded(ip(addr)),
            "{addr} should be excluded (RFC5737)"
        );
    }
}

#[test]
fn loopback_is_excluded_v4_and_v6() {
    let e = permissive();
    assert!(e.is_excluded(ip("127.0.0.1")));
    assert!(e.is_excluded(ip("127.255.255.255")));
    assert!(e.is_excluded(ip("::1")));
}

#[test]
fn link_local_is_excluded_v4_and_v6() {
    let e = permissive();
    assert!(e.is_excluded(ip("169.254.1.1")));
    assert!(e.is_excluded(ip("fe80::1")));
}

#[test]
fn multicast_is_excluded_v4_and_v6() {
    let e = permissive();
    assert!(e.is_excluded(ip("224.0.0.1")));
    assert!(e.is_excluded(ip("239.255.255.255")));
    assert!(e.is_excluded(ip("ff02::1")));
}

#[test]
fn limited_broadcast_is_excluded() {
    let e = permissive();
    assert!(e.is_excluded(ip("255.255.255.255")));
}

#[test]
fn ipv6_unique_local_addresses_are_excluded() {
    let e = permissive();
    assert!(e.is_excluded(ip("fc00::1")));
    assert!(e.is_excluded(ip("fd12:3456:789a::1")));
}

#[test]
fn ipv6_documentation_range_is_excluded() {
    let e = permissive();
    assert!(e.is_excluded(ip("2001:db8::1")));
    assert!(e.is_excluded(ip("2001:db8:ffff:ffff::1")));
}

#[test]
fn public_ip_passes_with_no_configured_exclusions() {
    let e = permissive();
    for addr in ["1.2.3.4", "5.6.7.8", "9.9.9.9", "2003:aaaa:bbbb::1"] {
        assert!(
            !e.is_excluded(ip(addr)),
            "{addr} should pass (not reserved)"
        );
    }
}

#[test]
fn empty_allowlist_passes_all_public_ips() {
    let e = ExclusionEngine::new(Vec::new(), Vec::new());
    assert!(!e.is_excluded(ip("1.2.3.4")));
    assert!(!e.is_excluded(ip("9.9.9.9")));
    assert!(!e.is_excluded(ip("2003:aaaa:bbbb::1")));
}

#[test]
fn allowlisted_range_is_excluded() {
    let allowlist = vec!["1.2.3.0/24".parse().unwrap()];
    let e = ExclusionEngine::new(allowlist, Vec::new());
    assert!(e.is_excluded(ip("1.2.3.4")));
    // An address outside the allowlisted block is unaffected by it.
    assert!(!e.is_excluded(ip("9.9.9.9")));
}

#[test]
fn allowlisted_single_host_via_slash32_is_excluded() {
    let allowlist = vec!["9.9.9.9/32".parse().unwrap()];
    let e = ExclusionEngine::new(allowlist, Vec::new());
    assert!(e.is_excluded(ip("9.9.9.9")));
    assert!(!e.is_excluded(ip("9.9.9.8")));
}

#[test]
fn delisted_ip_is_excluded() {
    let delist = vec![ip("1.2.3.4")];
    let e = ExclusionEngine::new(Vec::new(), delist);
    assert!(e.is_excluded(ip("1.2.3.4")));
    // A different address is unaffected.
    assert!(!e.is_excluded(ip("1.2.3.5")));
}

#[test]
fn mismatched_address_family_never_matches_a_reserved_or_allowlisted_net() {
    // An IPv4 net must never "contain" an IPv6 address or vice versa (ipnet's own Contains impl
    // returns false across families rather than panicking); confirm that holds through this
    // crate's own allowlist path too.
    let allowlist = vec!["10.0.0.0/8".parse().unwrap()];
    let e = ExclusionEngine::new(allowlist, Vec::new());
    assert!(!e.is_excluded(ip("::a")));
}
