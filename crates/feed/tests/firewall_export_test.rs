//! The firewall and DNS-policy renderings, held to their exact text.
//!
//! These files are applied by other people's machines, as root, on a timer, so what matters is
//! what the consumer's tool does with them: the second application must work and must remove
//! what the feed dropped, an empty feed must load, and each address must be in a set of its own
//! family.
//!
//! The text pinned here is text the real tools were given, so that it cannot drift from what
//! was checked:
//! - nftables 1.0.9, `nft -f`: applied, applied again, then a smaller and an empty feed (the sets
//!   shrank and emptied), with a consumer's chain and rules in the same table left in place, and a
//!   second feed's sets beside the first.
//! - ipset 7.19, `ipset -exist restore`: loaded, loaded again while iptables and ip6tables rules
//!   used the sets, then a smaller and an empty feed, and the longest set name.
//! - BIND 9.18, as a response policy zone: every trigger form below was accepted without a
//!   complaint, and the forms this replaced were refused (`invalid rpz IP address ... too small
//!   prefix length`, and `not the canonical` for a zero run chosen differently).

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use feed::FeedEntry;
use feed::export::{export_ipset, export_nftables, export_pf, export_pfsense_alias, export_rpz};

fn generated() -> DateTime<Utc> {
    "2026-07-29T14:37:52Z".parse().unwrap()
}

fn entry(ip: &str) -> FeedEntry {
    let at: DateTime<Utc> = "2026-07-29T13:00:00Z".parse().unwrap();
    FeedEntry {
        source_ip: ip.parse::<IpAddr>().unwrap(),
        tier: None,
        first_seen: at,
        last_seen: at,
        event_count: 7,
        distinct_categories: 2,
        categories: vec!["port_scan".into()],
        valid_from: at,
        valid_until: at,
    }
}

fn entries(ips: &[&str]) -> Vec<FeedEntry> {
    ips.iter().map(|ip| entry(ip)).collect()
}

/// Both families, in the order the builder sorts them (IPv4 first), with an IPv4-mapped IPv6
/// address that names the same host as a plain IPv4 entry.
fn mixed() -> Vec<FeedEntry> {
    entries(&[
        "45.10.30.7",
        "45.10.30.90",
        "2003:aaaa:bbbb::7",
        "::ffff:45.10.30.7",
        "::ffff:45.10.31.1",
    ])
}

// ---------- nftables ----------

#[test]
fn nftables_declares_one_named_set_per_family_empties_them_and_adds_the_feed() {
    assert_eq!(
        export_nftables("aggressive", &mixed()),
        "table inet propolis {\n\
         \tset propolis_aggressive_v4 {\n\
         \t\ttype ipv4_addr\n\
         \t}\n\
         \tset propolis_aggressive_v6 {\n\
         \t\ttype ipv6_addr\n\
         \t}\n\
         }\n\
         flush set inet propolis propolis_aggressive_v4\n\
         flush set inet propolis propolis_aggressive_v6\n\
         add element inet propolis propolis_aggressive_v4 {\n\
         \t45.10.30.7,\n\
         \t45.10.30.90,\n\
         \t45.10.31.1\n\
         }\n\
         add element inet propolis propolis_aggressive_v6 {\n\
         \t2003:aaaa:bbbb::7\n\
         }\n"
    );
}

#[test]
fn an_empty_nftables_feed_is_a_file_that_loads_and_empties_both_sets() {
    // The old `define x = {}` was a syntax error, so a quiet day stopped the consumer's whole
    // ruleset from loading. A named set may be empty; an `add element` may not, so there is none.
    let out = export_nftables("standard", &[]);
    assert_eq!(
        out,
        "table inet propolis {\n\
         \tset propolis_standard_v4 {\n\
         \t\ttype ipv4_addr\n\
         \t}\n\
         \tset propolis_standard_v6 {\n\
         \t\ttype ipv6_addr\n\
         \t}\n\
         }\n\
         flush set inet propolis propolis_standard_v4\n\
         flush set inet propolis propolis_standard_v6\n"
    );
    assert!(!out.contains("add element"));
    assert!(!out.contains("define"));
}

#[test]
fn nftables_with_one_family_only_adds_to_that_family_and_still_empties_the_other() {
    let v6_only = export_nftables("all-7d", &entries(&["2003:aaaa:bbbb::7"]));
    assert!(v6_only.contains("flush set inet propolis propolis_all-7d_v4\n"));
    assert!(!v6_only.contains("add element inet propolis propolis_all-7d_v4"));
    assert!(
        v6_only
            .ends_with("add element inet propolis propolis_all-7d_v6 {\n\t2003:aaaa:bbbb::7\n}\n")
    );
}

// ---------- ipset ----------

#[test]
fn ipset_fills_a_scratch_set_per_family_and_swaps_it_in() {
    assert_eq!(
        export_ipset("aggressive", &mixed()),
        "create propolis_aggressive_v4 hash:ip family inet hashsize 4096 maxelem 1048576\n\
         create propolis_aggressive_v4-new hash:ip family inet hashsize 4096 maxelem 1048576\n\
         flush propolis_aggressive_v4-new\n\
         add propolis_aggressive_v4-new 45.10.30.7\n\
         add propolis_aggressive_v4-new 45.10.30.90\n\
         add propolis_aggressive_v4-new 45.10.31.1\n\
         swap propolis_aggressive_v4-new propolis_aggressive_v4\n\
         destroy propolis_aggressive_v4-new\n\
         create propolis_aggressive_v6 hash:ip family inet6 hashsize 4096 maxelem 1048576\n\
         create propolis_aggressive_v6-new hash:ip family inet6 hashsize 4096 maxelem 1048576\n\
         flush propolis_aggressive_v6-new\n\
         add propolis_aggressive_v6-new 2003:aaaa:bbbb::7\n\
         swap propolis_aggressive_v6-new propolis_aggressive_v6\n\
         destroy propolis_aggressive_v6-new\n"
    );
}

#[test]
fn ipset_parameters_do_not_follow_the_feed_so_a_set_that_exists_can_be_created_again() {
    // `create -exist` succeeds only with the parameters the set already has. `maxelem` used to
    // be the entry count, so the second load failed whenever the feed had grown.
    let small = export_ipset("standard", &entries(&["45.10.30.7"]));
    let large: Vec<String> = (0..3000)
        .map(|n| format!("45.{}.{}.7", n / 250, n % 250))
        .collect();
    let large = export_ipset(
        "standard",
        &entries(&large.iter().map(String::as_str).collect::<Vec<_>>()),
    );
    let creates = |out: &str| -> Vec<String> {
        out.lines()
            .filter(|l| l.starts_with("create "))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(creates(&small), creates(&large));
    assert_eq!(creates(&small).len(), 4);
}

#[test]
fn an_empty_ipset_feed_empties_both_live_sets() {
    let out = export_ipset("all-24h", &[]);
    assert!(!out.contains("add "));
    assert_eq!(out.lines().count(), 10);
    assert!(out.contains("swap propolis_all-24h_v4-new propolis_all-24h_v4\n"));
    assert!(out.contains("swap propolis_all-24h_v6-new propolis_all-24h_v6\n"));
}

#[test]
fn no_ipset_or_nftables_set_ever_holds_an_address_of_the_other_family() {
    // A typed set refuses the other family and the tool stops at that line: with IPv6 in the
    // IPv4 set, as before, one IPv6 attacker meant the feed could not be loaded at all.
    let ipset = export_ipset("aggressive", &mixed());
    for line in ipset.lines().filter(|l| l.starts_with("add ")) {
        let mut parts = line.split(' ');
        let (set, address) = (parts.nth(1).unwrap(), parts.next().unwrap());
        let address: IpAddr = address.parse().unwrap();
        assert_eq!(set.contains("_v4"), address.is_ipv4(), "{line}");
        assert_eq!(set.contains("_v6"), address.is_ipv6(), "{line}");
    }
    let nft = export_nftables("aggressive", &mixed());
    let mut current = "";
    for line in nft.lines() {
        if let Some(rest) = line.strip_prefix("add element inet propolis ") {
            current = rest;
        } else if line.starts_with('\t') && !current.is_empty() {
            let address: IpAddr = line.trim().trim_end_matches(',').parse().unwrap();
            assert_eq!(current.contains("_v4"), address.is_ipv4(), "{line}");
        }
    }
}

#[test]
fn set_names_stay_within_what_ipset_allows() {
    // ipset names are at most 31 characters. The longest feed name the publisher can write is a
    // five-digit window, and the scratch set carries the longest suffix.
    let out = export_ipset("all-99999h", &[]);
    for line in out.lines() {
        for word in line.split(' ').filter(|w| w.starts_with("propolis_")) {
            assert!(word.len() <= 31, "{word} is {} characters", word.len());
        }
    }
}

// ---------- RPZ ----------

#[test]
fn rpz_is_a_whole_zone_with_a_trigger_for_every_address_of_both_families() {
    assert_eq!(
        export_rpz("aggressive", generated(), &mixed()),
        "; Propolis RPZ - aggressive tier\n\
         ; Generated: 2026-07-29T14:00:00Z\n\
         $TTL 300\n\
         @ IN SOA localhost. hostmaster.localhost. 2026072914 3600 600 86400 300\n\
         @ IN NS localhost.\n\
         32.7.30.10.45.rpz-ip CNAME .\n\
         32.90.30.10.45.rpz-ip CNAME .\n\
         32.1.31.10.45.rpz-ip CNAME .\n\
         128.7.zz.bbbb.aaaa.2003.rpz-ip CNAME .\n"
    );
}

#[test]
fn an_empty_rpz_feed_is_a_valid_empty_zone() {
    let out = export_rpz("standard", generated(), &[]);
    assert_eq!(out.lines().count(), 5);
    assert!(out.contains("\n@ IN SOA localhost. hostmaster.localhost. 2026072914 "));
    assert!(out.ends_with("@ IN NS localhost.\n"));
}

#[test]
fn the_rpz_serial_is_the_build_hour_and_nothing_finer() {
    // Every timestamp the feed states is an hour boundary, so that no two published values can
    // be subtracted to recover when a particular event happened. The serial must not be the
    // exception.
    let at = |text: &str| export_rpz("aggressive", text.parse().unwrap(), &[]);
    assert!(at("2026-07-29T14:00:00Z").contains(" 2026072914 "));
    assert_eq!(at("2026-07-29T14:00:00Z"), at("2026-07-29T14:59:59Z"));
    assert!(at("2026-07-29T15:00:00Z").contains(" 2026072915 "));
    assert!(at("2027-01-02T03:04:05Z").contains(" 2027010203 "));
}

// ---------- pf and the pfSense alias ----------

#[test]
fn pf_and_the_alias_list_every_address_of_both_families_one_per_line() {
    let list = entries(&["45.10.30.7", "2003:aaaa:bbbb::7"]);
    assert_eq!(
        export_pf("aggressive", generated(), &list),
        "# Propolis blocklist - aggressive tier\n\
         # Generated: 2026-07-29T14:00:00Z\n\
         45.10.30.7\n\
         2003:aaaa:bbbb::7\n"
    );
    assert_eq!(
        export_pfsense_alias("aggressive", &list),
        "45.10.30.7\n2003:aaaa:bbbb::7\n"
    );
    assert_eq!(export_pfsense_alias("aggressive", &[]), "");
    assert_eq!(export_pf("standard", generated(), &[]).lines().count(), 2);
}

// ---------- across the formats ----------

#[test]
fn no_firewall_format_carries_a_score_a_count_or_a_time_finer_than_the_hour() {
    let list = mixed();
    for out in [
        export_ipset("aggressive", &list),
        export_nftables("aggressive", &list),
        export_pf("aggressive", generated(), &list),
        export_pfsense_alias("aggressive", &list),
        export_rpz("aggressive", generated(), &list),
    ] {
        let lower = out.to_lowercase();
        for word in ["score", "confidence", "port_scan", ":37", ":52"] {
            assert!(!lower.contains(word), "{word} in:\n{out}");
        }
    }
}
