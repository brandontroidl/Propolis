//! CSV exporter: `ip,first_seen,last_seen,categories,events`. See the design's "CSV" format
//! example.

use crate::FeedEntry;

use super::format_timestamp;

/// Render `entries` (already built, sorted, and exclusion-filtered by `FeedBuilder`) as CSV for
/// one tier. No header/meta parameters: unlike plain text and JSON, the design's CSV format
/// carries no generated/valid_until/tier-name preamble, only the column header row.
///
/// Fields are written with plain `format!`, not a CSV-writer crate: every value is an `IpAddr`
/// Display, an RFC 3339 timestamp, or an integer - none of which can ever contain a comma, quote,
/// or newline, so there is no escaping case a dedicated writer would need to handle.
pub fn export_csv(entries: &[FeedEntry]) -> String {
    let mut out = String::from("ip,first_seen,last_seen,categories,events\n");
    for entry in entries {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            entry.source_ip,
            format_timestamp(entry.first_seen),
            format_timestamp(entry.last_seen),
            entry.distinct_categories,
            entry.event_count,
        ));
    }
    out
}
