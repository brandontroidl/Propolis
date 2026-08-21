use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use crate::domain::enums::FeedTier;
use crate::scoring::constants::{
    BLOCKLIST_FLOOR, VOLUME_LIST_THRESHOLD, VOLUME_LIST_WINDOW_SECONDS,
};

pub fn tier(raw_score: Decimal, max_confidence: Decimal) -> Option<FeedTier> {
    // AGGRESSIVE tested first: raw >= 90 && confidence >= 0.95
    if raw_score >= dec!(90) && max_confidence >= dec!(0.95) {
        return Some(FeedTier::Aggressive);
    }
    // STANDARD: raw >= 75 && confidence >= 0.70
    if raw_score >= dec!(75) && max_confidence >= dec!(0.70) {
        return Some(FeedTier::Standard);
    }
    None
}

pub fn recommended_for_vendor(eligible: bool, tier: Option<FeedTier>) -> bool {
    eligible && tier.is_some()
}

pub fn recommended_for_blocklist(eligible: bool, effective_score: Decimal) -> bool {
    eligible && effective_score >= BLOCKLIST_FLOOR
}

/// A high-VOLUME source recommended for the blocklist on connection volume alone - no confirmed-real
/// latch, no score threshold. A flood of unsolicited connections is itself hostile on a honeypot,
/// and the 60s same-signal dedup otherwise collapses such a flood to one scored event so it never
/// clears the merit path. Gated on recent activity so a long-stopped flood ages out, and on
/// `!delisted` like every other blocklist path.
pub fn recommended_by_volume(
    delisted: bool,
    event_count: u32,
    seconds_since_last_seen: i64,
) -> bool {
    !delisted
        && event_count >= VOLUME_LIST_THRESHOLD
        && seconds_since_last_seen <= VOLUME_LIST_WINDOW_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_runs_on_raw_not_effective() {
        // raw 60, high breadth -> effective 96, but tier must be None (raw < 75)
        assert_eq!(tier(dec!(60), dec!(0.90)), None);
    }

    #[test]
    fn tier_floors_require_both_axes() {
        assert_eq!(tier(dec!(92), dec!(0.80)), Some(FeedTier::Standard)); // conf fails AGGRESSIVE
        assert_eq!(tier(dec!(90), dec!(0.95)), Some(FeedTier::Aggressive));
        assert_eq!(tier(dec!(74), dec!(0.99)), None);
    }

    #[test]
    fn recommendation_split() {
        assert!(!recommended_for_vendor(true, None));
        assert!(recommended_for_vendor(true, Some(FeedTier::Standard)));
        assert!(recommended_for_blocklist(true, dec!(50)));
        assert!(!recommended_for_blocklist(true, dec!(49)));
        assert!(!recommended_for_blocklist(false, dec!(90))); // eligibility-gated
    }

    #[test]
    fn tier_boundaries_exact() {
        // Floors are inclusive (>=): exactly on both STANDARD axes -> Standard.
        assert_eq!(tier(dec!(75), dec!(0.70)), Some(FeedTier::Standard));
        // Just below either STANDARD axis -> None.
        assert_eq!(tier(dec!(74.999), dec!(0.70)), None);
        assert_eq!(tier(dec!(75), dec!(0.699)), None);
        // Exactly on both AGGRESSIVE axes -> Aggressive; a hair below conf drops to Standard.
        assert_eq!(tier(dec!(90), dec!(0.95)), Some(FeedTier::Aggressive));
        assert_eq!(tier(dec!(90), dec!(0.949)), Some(FeedTier::Standard));
        // Below AGGRESSIVE raw with high conf -> Standard (still clears STANDARD raw).
        assert_eq!(tier(dec!(89.999), dec!(0.99)), Some(FeedTier::Standard));
    }

    #[test]
    fn volume_lists_a_recent_flood_but_not_a_stale_small_or_delisted_one() {
        // A recent high-volume flood is listed on volume alone (no confirmed-real, no score).
        assert!(recommended_by_volume(false, 1000, 3600));
        assert!(recommended_by_volume(false, 50_000, 0));
        // Below the threshold: not listed.
        assert!(!recommended_by_volume(false, 999, 60));
        // Over threshold but last seen more than the window ago: aged out.
        assert!(!recommended_by_volume(
            false,
            50_000,
            VOLUME_LIST_WINDOW_SECONDS + 1
        ));
        // Delisted overrides volume.
        assert!(!recommended_by_volume(true, 50_000, 60));
    }
}
