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
pub fn export_cidr(entries: &[FeedEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        let suffix = match entry.source_ip {
            IpAddr::V4(_) => "/32",
            IpAddr::V6(_) => "/128",
        };
        out.push_str(&entry.source_ip.to_string());
        out.push_str(suffix);
        out.push('\n');
    }
    out
}
