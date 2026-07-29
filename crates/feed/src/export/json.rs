//! JSON exporter: structured `{ "meta": ..., "entries": [...] }` document. See the design's
//! "JSON" format example.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::FeedEntry;

use super::format_timestamp;

/// One tier's JSON export document: `meta` describes the file (generator, tier, build/expiry
/// timestamps, entry count); `entries` carries only what an operator needs to act on an address.
/// No raw score, no confidence, and no per-entry tier label - the tier is the file, not the
/// entry (see the design's "JSON" section).
#[derive(Serialize)]
struct FeedDocument {
    meta: Meta,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Meta {
    generator: &'static str,
    tier: String,
    generated: String,
    valid_until: String,
    count: usize,
}

#[derive(Serialize)]
struct Entry {
    ip: String,
    first_seen: String,
    last_seen: String,
    categories: i32,
    events: i32,
}

/// Render `entries` (already built, sorted, and exclusion-filtered by `FeedBuilder`) as this
/// tier's JSON export document. `tier_name`, `generated`, and `valid_until` are explicit
/// parameters rather than read off `entries[0]` - see the module-level doc comment on
/// `crate::export` for why (a zero-entry tier must still render a valid `meta` block).
pub fn export_json(
    tier_name: &str,
    generated: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    entries: &[FeedEntry],
) -> String {
    let doc = FeedDocument {
        meta: Meta {
            generator: "propolis",
            tier: tier_name.to_string(),
            generated: format_timestamp(generated),
            valid_until: format_timestamp(valid_until),
            count: entries.len(),
        },
        entries: entries
            .iter()
            .map(|e| Entry {
                ip: e.source_ip.to_string(),
                first_seen: format_timestamp(e.first_seen),
                last_seen: format_timestamp(e.last_seen),
                categories: e.distinct_categories,
                events: e.event_count,
            })
            .collect(),
    };

    // Every field is a plain String, &'static str, i32, or usize - none of serde_json's fallible
    // cases (non-string map keys, non-finite floats) apply, so this cannot fail in practice.
    serde_json::to_string(&doc).expect("FeedDocument serialization is infallible by construction")
}
