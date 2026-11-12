//! Exporters: convert a tier's already-built `FeedEntry` values into a specific on-the-wire
//! format. See `internal/design/05-blocklist-feed.md` ("Exporters").
//!
//! Every exporter is a pure, free function - no I/O, no database, no exclusion re-checking (the
//! builder already applied exclusions; the publisher, a later task in this sub-project,
//! re-validates before writing). `export_csv`/`export_cidr` take only `entries`, matching the
//! design's header-less CSV/CIDR formats; `export_plaintext`/`export_json` also take `tier_name`,
//! `generated`, and `valid_until` explicitly rather than deriving them from `entries[0]` - the
//! design requires a zero-entry feed to publish normally (see the spec's "Error handling": "An
//! empty feed... is published normally"), and a header/meta block must still render correctly
//! when there is no `entries[0]` to read them from.

pub mod cidr;
pub mod csv;
pub mod firewall;
pub mod json;
pub mod plaintext;

pub use cidr::export_cidr;
pub use csv::export_csv;
pub use firewall::{
    export_hosts, export_ipset, export_nftables, export_pf, export_pfsense_alias, export_rpz,
};
pub use json::export_json;
pub use plaintext::export_plaintext;

use chrono::{DateTime, SecondsFormat, Utc};

/// Render a timestamp exactly as every export format needs it: RFC 3339, whole seconds, and a
/// literal `Z` for UTC rather than `+00:00` - e.g. `2026-07-29T14:00:00Z`, matching the design's
/// format examples byte for byte.
///
/// Defensively re-coarsens to the hour boundary rather than trusting the caller already did:
/// `FeedBuilder` already coarsens every timestamp it produces, but the anti-deanonymization
/// guarantee is contractually a property of the *export*, so this is the last-mile enforcement
/// point before a timestamp leaves the process - the same defense-in-depth posture the design
/// applies to the exclusion engine, which the publisher re-validates even though the builder
/// already filtered.
pub(crate) fn format_timestamp(dt: DateTime<Utc>) -> String {
    crate::coarsen_to_hour(dt).to_rfc3339_opts(SecondsFormat::Secs, true)
}
