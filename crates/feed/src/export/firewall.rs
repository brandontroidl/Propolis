//! The firewall and DNS-policy renderings: ipset, nftables, pf, pfSense alias and RPZ.
//!
//! Three rules hold for every one of them, and the tests in `tests/firewall_export_test.rs` pin
//! each against the exact text:
//!
//! - **A file can be applied again.** A consumer fetches the feed on a timer and applies it, so
//!   the second application must succeed and must REMOVE what the feed no longer lists. A file
//!   that only adds, or fails when its set already exists, leaves a delisted address blocked
//!   for ever.
//! - **An empty feed is a valid file.** A feed with no entries is normal (a quiet day), and its
//!   file must load and empty the consumer's set, not stop their ruleset from loading.
//! - **Each address family goes where its family is accepted.** ipset and nftables sets are
//!   typed: an IPv6 address in an IPv4 set aborts the load. So those formats carry one set per
//!   family, and [`families`] decides which an entry belongs to.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::FeedEntry;

use super::format_timestamp;

/// The entries split by family, each sorted and without repeats.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is filed as the IPv4 address it maps: it names
/// an IPv4 peer as a dual-stack socket saw it, the packets to match are IPv4 packets, and a rule
/// on the mapped IPv6 form matches nothing. Filing it as IPv4 can meet the same address listed in
/// its plain form, hence the sets.
fn families(entries: &[FeedEntry]) -> (BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>) {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for entry in entries {
        match entry.source_ip {
            IpAddr::V4(ip) => {
                v4.insert(ip);
            }
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(mapped) => {
                    v4.insert(mapped);
                }
                None => {
                    v6.insert(ip);
                }
            },
        }
    }
    (v4, v6)
}

/// `maxelem` of every ipset this module creates. It has to be a constant: `create` on a set that
/// already exists succeeds (under `-exist`) only when every parameter is the same as before, so a
/// value that followed the entry count failed the second load whenever the feed had grown. It is
/// a cap, not an allocation, and sits well above any feed a node has published.
pub const IPSET_MAXELEM: u32 = 1_048_576;

/// The initial hash size of every ipset this module creates. Constant for the same reason; the
/// kernel grows the hash as entries are added.
pub const IPSET_HASHSIZE: u32 = 4096;

/// An `ipset restore` file for `ipset -exist restore < FILE`, to be applied on every refresh.
///
/// Two sets, `propolis_<feed>_v4` (`family inet`) and `propolis_<feed>_v6` (`family inet6`). For
/// each, the file creates the live set if it is missing, fills a scratch set from nothing, swaps
/// the two and destroys the scratch one. The swap is atomic and keeps every iptables rule
/// pointing at the live name, so the live set goes from the old contents to exactly the new
/// ones: entries the feed dropped are gone. If the load fails part way, it has not reached the
/// swap and the live set is untouched.
///
/// `-exist` is required: without it the `create` of a set that already exists is an error, which
/// is every load after the first. The file holds no comment lines.
pub fn export_ipset(tier_name: &str, entries: &[FeedEntry]) -> String {
    let (v4, v6) = families(entries);
    let mut out = String::new();
    ipset_family(&mut out, tier_name, "v4", "inet", v4.iter());
    ipset_family(&mut out, tier_name, "v6", "inet6", v6.iter());
    out
}

fn ipset_family<A: std::fmt::Display>(
    out: &mut String,
    tier_name: &str,
    suffix: &str,
    family: &str,
    addresses: impl Iterator<Item = A>,
) {
    let live = format!("propolis_{tier_name}_{suffix}");
    let scratch = format!("{live}-new");
    let params =
        format!("hash:ip family {family} hashsize {IPSET_HASHSIZE} maxelem {IPSET_MAXELEM}");
    out.push_str(&format!("create {live} {params}\n"));
    out.push_str(&format!("create {scratch} {params}\n"));
    out.push_str(&format!("flush {scratch}\n"));
    for address in addresses {
        out.push_str(&format!("add {scratch} {address}\n"));
    }
    out.push_str(&format!("swap {scratch} {live}\n"));
    out.push_str(&format!("destroy {scratch}\n"));
}

/// The nftables table every feed's sets live in. A rule can only name a set in its own table, so
/// a consumer adds their chain and rules to this table once.
pub const NFT_TABLE: &str = "inet propolis";

/// An nftables file for `nft -f FILE`, to be applied on every refresh.
///
/// It declares the table and two named sets, `propolis_<feed>_v4` (`ipv4_addr`) and
/// `propolis_<feed>_v6` (`ipv6_addr`), empties both and adds the feed's addresses. A file is one
/// transaction, so the sets go from the old contents to exactly the new ones with no moment in
/// between, and nothing else in the table (the consumer's chain and rules) is touched.
///
/// A named set may be empty, which a `define` cannot be: an empty feed is a file that loads and
/// empties both sets. An `add element` with no elements is a syntax error, so it is left out for
/// an empty family.
pub fn export_nftables(tier_name: &str, entries: &[FeedEntry]) -> String {
    let (v4, v6) = families(entries);
    let v4_set = format!("propolis_{tier_name}_v4");
    let v6_set = format!("propolis_{tier_name}_v6");
    let mut out = format!(
        "table {NFT_TABLE} {{\n\
         \tset {v4_set} {{\n\
         \t\ttype ipv4_addr\n\
         \t}}\n\
         \tset {v6_set} {{\n\
         \t\ttype ipv6_addr\n\
         \t}}\n\
         }}\n\
         flush set {NFT_TABLE} {v4_set}\n\
         flush set {NFT_TABLE} {v6_set}\n"
    );
    nft_elements(&mut out, &v4_set, v4.iter());
    nft_elements(&mut out, &v6_set, v6.iter());
    out
}

fn nft_elements<A: std::fmt::Display>(
    out: &mut String,
    set: &str,
    addresses: impl Iterator<Item = A>,
) {
    let mut addresses = addresses.peekable();
    if addresses.peek().is_none() {
        return;
    }
    out.push_str(&format!("add element {NFT_TABLE} {set} {{\n"));
    while let Some(address) = addresses.next() {
        let separator = if addresses.peek().is_some() { "," } else { "" };
        out.push_str(&format!("\t{address}{separator}\n"));
    }
    out.push_str("}\n");
}

/// A pf table file: one address per line, both families in the one table, `#` comments. Loaded
/// with `table <name> persist file "FILE"` and refreshed with `pfctl -t <name> -T replace -f
/// FILE`, which removes what the file no longer lists. An empty feed is the two header lines.
pub fn export_pf(tier_name: &str, generated: DateTime<Utc>, entries: &[FeedEntry]) -> String {
    let mut out = format!(
        "# Propolis blocklist - {} tier\n# Generated: {}\n",
        tier_name,
        format_timestamp(generated),
    );
    for entry in entries {
        out.push_str(&entry.source_ip.to_string());
        out.push('\n');
    }
    out
}

/// A pfSense / OPNsense URL Table alias source: bare addresses, one per line, both families.
pub fn export_pfsense_alias(_tier_name: &str, entries: &[FeedEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&entry.source_ip.to_string());
        out.push('\n');
    }
    out
}

/// A response policy zone (RPZ) file for BIND, Unbound and other RPZ resolvers: one `rpz-ip`
/// trigger per listed address, each answered NXDOMAIN (`CNAME .`).
///
/// `rpz-ip` is the response-address trigger: the resolver refuses to hand its clients an answer
/// that points AT a listed address. (It does not stop a listed address from querying the
/// resolver; that is `rpz-client-ip`, a different policy.)
///
/// The file is a complete zone: an SOA and an NS record, without which a resolver will not load
/// it, then the triggers. Owner names are relative, so the zone's name is whatever the consumer
/// gives it. An empty feed is the SOA and NS alone, a valid empty zone. The serial is the build
/// hour as `YYYYMMDDHH`: it rises with every hourly build and reveals nothing finer than the hour
/// the other formats already state.
pub fn export_rpz(tier_name: &str, generated: DateTime<Utc>, entries: &[FeedEntry]) -> String {
    let (v4, v6) = families(entries);
    let hour = crate::coarsen_to_hour(generated);
    let serial = format!(
        "{:04}{:02}{:02}{:02}",
        hour.year(),
        hour.month(),
        hour.day(),
        hour.hour()
    );
    let mut out = format!(
        "; Propolis RPZ - {} tier\n\
         ; Generated: {}\n\
         $TTL 300\n\
         @ IN SOA localhost. hostmaster.localhost. {serial} 3600 600 86400 300\n\
         @ IN NS localhost.\n",
        tier_name,
        format_timestamp(generated),
    );
    for address in &v4 {
        out.push_str(&format!("{}.rpz-ip CNAME .\n", rpz_ipv4_owner(*address)));
    }
    for address in &v6 {
        out.push_str(&format!("{}.rpz-ip CNAME .\n", rpz_ipv6_owner(*address)));
    }
    out
}

/// The RPZ owner-name labels for one IPv4 address: the prefix length, then the octets reversed.
/// `45.10.30.7` is `32.7.30.10.45`. Without the leading `32` the name is not an address trigger
/// at all and the resolver ignores it.
fn rpz_ipv4_owner(address: Ipv4Addr) -> String {
    let [a, b, c, d] = address.octets();
    format!("32.{d}.{c}.{b}.{a}")
}

/// The RPZ owner-name labels for one IPv6 address: the prefix length, then the eight 16-bit
/// groups in REVERSE order, in hexadecimal without leading zeros, with the longest run of two or
/// more zero groups written as the single label `zz` (the `::` of the text form). `2a01:4f8::7`
/// is `128.7.zz.4f8.2a01`.
///
/// A resolver accepts only this canonical form, so the run is chosen as BIND chooses it: the
/// longest, and of equal runs the one that comes first in the address as written.
fn rpz_ipv6_owner(address: Ipv6Addr) -> String {
    let mut groups = address.segments();
    groups.reverse();

    // (start, length) of the run to write as `zz`, in the reversed order the name uses. `>=`
    // makes a later run of the same length win here, which is the earlier one as written.
    let mut best: Option<(usize, usize)> = None;
    let mut run_start = 0;
    let mut run_len = 0;
    for (at, group) in groups.iter().enumerate() {
        if *group != 0 {
            run_len = 0;
            continue;
        }
        if run_len == 0 {
            run_start = at;
        }
        run_len += 1;
        if run_len >= 2 && best.is_none_or(|(_, len)| run_len >= len) {
            best = Some((run_start, run_len));
        }
    }

    let mut labels = vec!["128".to_string()];
    let mut at = 0;
    while at < groups.len() {
        match best {
            Some((start, len)) if at == start => {
                labels.push("zz".to_string());
                at += len;
            }
            _ => {
                labels.push(format!("{:x}", groups[at]));
                at += 1;
            }
        }
    }
    labels.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(text: &str) -> String {
        rpz_ipv6_owner(text.parse().unwrap())
    }

    #[test]
    fn an_ipv4_rpz_owner_is_the_prefix_length_then_the_octets_reversed() {
        assert_eq!(
            rpz_ipv4_owner("45.10.30.7".parse().unwrap()),
            "32.7.30.10.45"
        );
        assert_eq!(rpz_ipv4_owner("0.0.0.1".parse().unwrap()), "32.1.0.0.0");
    }

    #[test]
    fn an_ipv6_rpz_owner_reverses_the_groups_and_writes_the_zero_run_as_zz() {
        // The example in the BIND reference manual's response policy zone section.
        assert_eq!(owner("2001::57"), "128.57.zz.2001");
        assert_eq!(owner("2a01:4f8::7"), "128.7.zz.4f8.2a01");
        // No zero group at all: eight labels, leading zeros dropped, lower case.
        assert_eq!(
            owner("2001:db8:1:2:3:4:5:ABCD"),
            "128.abcd.5.4.3.2.1.db8.2001"
        );
        // One zero group is written as 0, not zz, exactly as the text form keeps it.
        assert_eq!(owner("2001:db8:0:1:1:1:1:1"), "128.1.1.1.1.1.0.db8.2001");
        // The longest run wins.
        assert_eq!(owner("2001:0:0:1:0:0:0:1"), "128.1.zz.1.0.0.2001");
        // Two runs of the same length: the first as written, as the text form compresses it
        // (2001:db8::1:0:0:1).
        assert_eq!(owner("2001:db8:0:0:1:0:0:1"), "128.1.0.0.1.zz.db8.2001");
        // Runs at either end.
        assert_eq!(owner("::1"), "128.1.zz");
        assert_eq!(owner("2001:db8::"), "128.zz.db8.2001");
    }

    #[test]
    fn the_zz_choice_matches_the_text_form_for_every_shape_of_address() {
        // The text form (RFC 5952, which `Ipv6Addr`'s Display follows) compresses the same run.
        // Rebuild the address from the owner name and compare, over every pattern of zero and
        // non-zero groups.
        for pattern in 0u16..256 {
            let mut segments = [0u16; 8];
            for (i, segment) in segments.iter_mut().enumerate() {
                if pattern & (1 << i) != 0 {
                    *segment = 0x100 + i as u16;
                }
            }
            let address = Ipv6Addr::from(segments);
            if address.to_ipv4_mapped().is_some() || segments == [0; 8] {
                continue;
            }
            let name = rpz_ipv6_owner(address);
            let labels: Vec<&str> = name.split('.').skip(1).collect();
            let written = labels.iter().filter(|l| **l != "zz").count();
            let mut rebuilt: Vec<u16> = Vec::new();
            for label in &labels {
                if *label == "zz" {
                    rebuilt.extend(std::iter::repeat_n(0, 8 - written));
                } else {
                    rebuilt.push(u16::from_str_radix(label, 16).unwrap());
                }
            }
            rebuilt.reverse();
            assert_eq!(rebuilt, segments, "{address} as {name}");

            // And the compressed run is the one the text form compresses.
            let text = address.to_string();
            let compressed_in_text = text.contains("::");
            assert_eq!(
                labels.contains(&"zz"),
                compressed_in_text,
                "{address} as {name}"
            );
            if compressed_in_text {
                let before = text.split("::").next().unwrap();
                let groups_before = before.split(':').filter(|g| !g.is_empty()).count();
                let zz_at = labels.iter().position(|l| *l == "zz").unwrap();
                let groups_after_in_name = zz_at;
                assert_eq!(
                    groups_before + (8 - written) + groups_after_in_name,
                    8,
                    "{address} as {name}"
                );
            }
        }
    }
}
