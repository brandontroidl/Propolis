//! Plain text exporter: one IP per line behind a `#`-comment header. See the design's "Plain
//! text" format example.

use chrono::{DateTime, Utc};

use crate::FeedEntry;

use super::format_timestamp;

/// Render `entries` (already built, sorted, and exclusion-filtered by `FeedBuilder`) as a
/// plain-text blocklist for one tier:
///
/// ```text
/// # Propolis blocklist - Aggressive tier
/// # Generated: 2026-07-29T14:00:00Z
/// # Valid until: 2026-07-30T14:00:00Z
/// # Entries: 42
/// 203.0.113.7
/// ```
///
/// The list is `super::listed_addresses`: an IPv4-mapped IPv6 address is written as the IPv4
/// address it maps, once, and `Entries` counts the lines that follow it.
///
/// `tier_name` is a bare, caller-supplied label ("aggressive"/"standard", matching the JSON
/// exporter's `meta.tier` and the publisher's per-tier file names); only this function's header
/// line capitalizes it for human readability. `generated` and `valid_until` are explicit
/// parameters rather than read off `entries[0]` - see the module doc comment for why.
pub fn export_plaintext(
    tier_name: &str,
    generated: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    entries: &[FeedEntry],
) -> String {
    let addresses = super::listed_addresses(entries);
    let mut out = format!(
        "# Propolis blocklist - {} tier\n# Generated: {}\n# Valid until: {}\n# Entries: {}\n",
        titlecase(tier_name),
        format_timestamp(generated),
        format_timestamp(valid_until),
        addresses.len(),
    );
    for ip in addresses {
        out.push_str(&ip.to_string());
        out.push('\n');
    }
    out
}

/// Capitalizes only the first character (`"aggressive"` -> `"Aggressive"`), leaving the rest
/// untouched. Local to the plain-text header - the JSON exporter's `meta.tier` keeps the
/// caller's casing verbatim, matching the design's own JSON example (`"tier":"aggressive"`).
fn titlecase(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
