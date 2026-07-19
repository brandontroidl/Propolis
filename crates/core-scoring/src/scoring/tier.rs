use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use crate::domain::enums::FeedTier;
use crate::scoring::constants::BLOCKLIST_FLOOR;

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
}
