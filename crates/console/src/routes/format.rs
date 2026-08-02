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

/// Coarsens a UTC timestamp to "how long ago", in the largest whole unit that fits - used by the
/// dashboard's recent-activity table, where an exact `format_timestamp` value is more precision
/// than an operator scanning twenty rows needs.
pub(crate) fn format_relative_time(dt: DateTime<Utc>) -> String {
    let elapsed = Utc::now() - dt;
    if elapsed.num_seconds() < 60 {
        return format!("{}s ago", elapsed.num_seconds());
    }
    if elapsed.num_minutes() < 60 {
        return format!("{}m ago", elapsed.num_minutes());
    }
    if elapsed.num_hours() < 24 {
        return format!("{}h ago", elapsed.num_hours());
    }
    format!("{}d ago", elapsed.num_days())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn format_relative_time_under_a_minute_shows_seconds() {
        let dt = Utc::now() - Duration::seconds(45);
        assert_eq!(format_relative_time(dt), "45s ago");
    }

    #[test]
    fn format_relative_time_under_an_hour_shows_minutes() {
        let dt = Utc::now() - Duration::seconds(90);
        assert_eq!(format_relative_time(dt), "1m ago");
    }

    #[test]
    fn format_relative_time_under_a_day_shows_hours() {
        let dt = Utc::now() - Duration::seconds(3661);
        assert_eq!(format_relative_time(dt), "1h ago");
    }

    #[test]
    fn format_relative_time_a_day_or_more_shows_days() {
        let dt = Utc::now() - Duration::seconds(90_000);
        assert_eq!(format_relative_time(dt), "1d ago");
    }
}
