//! Small display-formatting helpers shared by multiple route modules. Factored out of
//! `routes::queue` (the original sole owner of both) once `routes::detail` needed the same two -
//! one shared copy rather than two that can drift on the next edit.

use chrono::{DateTime, Utc};
use core_scoring::FeedTier;

/// Renders a UTC timestamp the same way on every page: `2026-07-17 00:00 UTC`.
pub(crate) fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// The lowercase display label for a feed tier, matching the CSS class suffixes in
/// `templates/base_head.html` (`.tier-aggressive` / `.tier-standard`).
pub(crate) fn tier_label(t: FeedTier) -> &'static str {
    match t {
        FeedTier::Aggressive => "aggressive",
        FeedTier::Standard => "standard",
    }
}
