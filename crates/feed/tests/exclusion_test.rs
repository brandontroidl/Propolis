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

// ---- operator range file (PROPOLIS_FEED_ALLOWLIST_FILE) ----

use feed::AllowlistFileError;
use feed::exclusion::{ALLOWLIST_FILE_MAX_BYTES, ALLOWLIST_FILE_MAX_ENTRIES, parse_allowlist_text};

#[test]
fn a_range_file_with_comments_and_blank_lines_excludes_exactly_its_ranges() {
    let text =
        "# crawler ranges, checked 2026-10-08\n\n45.10.30.0/24   # v4 block\n2003:aaaa:bbbb::/48\n";
    let nets = parse_allowlist_text(text).unwrap();
    assert_eq!(nets.len(), 2);
    let e = ExclusionEngine::new(nets, Vec::new());
    assert!(e.is_excluded(ip("45.10.30.77")));
    assert!(e.is_excluded(ip("2003:aaaa:bbbb::5")));
    assert!(
        !e.is_excluded(ip("45.10.31.77")),
        "outside the listed range"
    );
    assert!(!e.is_excluded(ip("2003:aaaa:cccc::5")));
}

#[test]
fn a_malformed_line_rejects_the_whole_file_not_just_that_line() {
    // The valid first line must NOT survive: a partial list from a corrupted file would look valid.
    let err = parse_allowlist_text("45.10.30.0/24\nnot-a-cidr\n").unwrap_err();
    assert_eq!(
        err,
        AllowlistFileError::InvalidCidr {
            line: 2,
            value: "not-a-cidr".into()
        }
    );
}

#[test]
fn a_bare_address_without_a_prefix_is_rejected() {
    assert!(matches!(
        parse_allowlist_text("45.10.30.9\n"),
        Err(AllowlistFileError::InvalidCidr { line: 1, .. })
    ));
}

#[test]
fn an_all_address_space_entry_is_an_error_not_a_wide_exclusion() {
    // The failure to rule out: a list that turns into "exclude everything".
    for wide in ["0.0.0.0/0", "::/0", "0.0.0.0/7", "2000::/15"] {
        assert!(
            matches!(
                parse_allowlist_text(&format!("45.10.30.0/24\n{wide}\n")),
                Err(AllowlistFileError::TooWide { line: 2, .. })
            ),
            "{wide} must be refused"
        );
    }
    // The boundary itself is accepted.
    assert_eq!(
        parse_allowlist_text("10.0.0.0/8\n2000::/16\n")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn the_entry_count_is_bounded() {
    let at_limit: String = (0..ALLOWLIST_FILE_MAX_ENTRIES)
        .map(|i| {
            format!(
                "{}.{}.{}.{}/32\n",
                45,
                (i >> 16) & 255,
                (i >> 8) & 255,
                i & 255
            )
        })
        .collect();
    assert_eq!(
        parse_allowlist_text(&at_limit).unwrap().len(),
        ALLOWLIST_FILE_MAX_ENTRIES
    );
    let over = format!("{at_limit}46.0.0.0/32\n");
    assert_eq!(
        parse_allowlist_text(&over).unwrap_err(),
        AllowlistFileError::TooManyEntries
    );
}

#[test]
fn an_empty_or_comment_only_file_excludes_nothing() {
    assert!(parse_allowlist_text("").unwrap().is_empty());
    assert!(
        parse_allowlist_text("# nothing yet\n\n")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn loading_a_file_fails_closed_on_unreadable_oversized_and_non_text_input() {
    let dir = tempfile::tempdir().unwrap();

    let good = dir.path().join("good.txt");
    std::fs::write(&good, "45.10.30.0/24\n").unwrap();
    assert_eq!(feed::load_allowlist_file(&good).unwrap().len(), 1);

    assert!(matches!(
        feed::load_allowlist_file(&dir.path().join("absent.txt")),
        Err(AllowlistFileError::Unreadable { .. })
    ));

    let big = dir.path().join("big.txt");
    std::fs::write(&big, vec![b'#'; ALLOWLIST_FILE_MAX_BYTES + 1]).unwrap();
    assert_eq!(
        feed::load_allowlist_file(&big).unwrap_err(),
        AllowlistFileError::TooLarge
    );

    let binary = dir.path().join("binary.bin");
    std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x80]).unwrap();
    assert_eq!(
        feed::load_allowlist_file(&binary).unwrap_err(),
        AllowlistFileError::NotText
    );

    let bad = dir.path().join("bad.txt");
    std::fs::write(&bad, "45.10.30.0/24\n<html>\n").unwrap();
    assert!(matches!(
        feed::load_allowlist_file(&bad),
        Err(AllowlistFileError::InvalidCidr { line: 2, .. })
    ));
}
