//! CIDR exporter: one host route per line. See the design's "CIDR" format example and its
//! "Inherited invariants" ("Collateral safety"): entries are host routes - /32 for IPv4, /128 for
//! IPv6 - by default. Safe aggregation to a shorter prefix (emitting a block only when every
//! address in it is independently listed) is explicitly deferred by the spec's "Decisions closed
//! by this spec": "CIDR aggregation: host routes only (/32) for initial implementation."
//!
//! IPv6 still needs its own suffix even though the spec's shorthand says "/32": a /32 on an IPv6
//! address covers roughly 2^96 addresses instead of one, which is exactly the collateral-blocking
//! failure the "Collateral safety" invariant forbids. `export_cidr` uses /128 for IPv6 host
//! routes, per that invariant.

use std::net::IpAddr;

use crate::FeedEntry;

/// Render `entries` (already built, sorted, and exclusion-filtered by `FeedBuilder`) as one host
/// route per line, e.g. `203.0.113.7/32`.
///
/// An IPv4-mapped IPv6 address is written as the IPv4 host route it stands for
/// (`super::listed_addresses`): `::ffff:203.0.113.7/128` is a route no IPv4 packet takes.
pub fn export_cidr(entries: &[FeedEntry]) -> String {
    let mut out = String::new();
    for ip in super::listed_addresses(entries) {
        let suffix = match ip {
            IpAddr::V4(_) => "/32",
            IpAddr::V6(_) => "/128",
        };
        out.push_str(&ip.to_string());
        out.push_str(suffix);
        out.push('\n');
    }
    out
}
