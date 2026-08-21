//! Persistence bonus: score points earned by being active across many distinct days.
//!
//! The 6-hour decay half-life (`decay.rs`) means a burst of activity over a few hours dominates the
//! score while a slow, methodical attacker who probes once a day barely accumulates - between two
//! daily hits, four half-lives erase ~94% of the prior score. That under-punishes exactly the
//! patient, long-horizon exploitation this bonus is meant to catch.
//!
//! `active_days` is an unbounded, non-decaying count of distinct calendar days an address was seen
//! (maintained on `ip_score`, folded in `engine::apply_event`). This function turns it into a
//! points bonus ADDED to the gate-facing score in `engine::derive_projection`, so a persistent
//! attacker climbs the tiers over weeks the same way a loud one does in a single burst.

use rust_decimal::Decimal;

use crate::scoring::constants::{PERSIST_CAP, PERSIST_GRACE_DAYS, PERSIST_PER_DAY};

/// Score points to add for `active_days` distinct active days.
///
/// Zero up to and including [`PERSIST_GRACE_DAYS`] (short-lived addresses are scored exactly as
/// before), then linear at [`PERSIST_PER_DAY`] per additional day, saturating at [`PERSIST_CAP`].
pub fn persistence_points(active_days: i64) -> Decimal {
    let beyond_grace = active_days.saturating_sub(PERSIST_GRACE_DAYS).max(0);
    std::cmp::min(PERSIST_CAP, PERSIST_PER_DAY * Decimal::from(beyond_grace))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn grace_days_earn_nothing() {
        assert_eq!(persistence_points(0), dec!(0));
        assert_eq!(persistence_points(1), dec!(0));
        assert_eq!(persistence_points(PERSIST_GRACE_DAYS), dec!(0));
    }

    #[test]
    fn thirty_days_clears_standard_for_a_base_sixty_attacker() {
        // base ~60 (command-exec) + points(30) must reach STANDARD (75).
        let pts = persistence_points(30);
        assert!(
            pts >= dec!(15),
            "points(30) = {pts}, need >= 15 for 60 -> 75"
        );
    }

    #[test]
    fn sixty_days_clears_aggressive_for_a_base_sixty_attacker() {
        // base ~60 + points(60) must reach AGGRESSIVE (90).
        let pts = persistence_points(60);
        assert!(
            pts >= dec!(30),
            "points(60) = {pts}, need >= 30 for 60 -> 90"
        );
    }

    #[test]
    fn saturates_at_the_cap() {
        assert_eq!(persistence_points(100_000), PERSIST_CAP);
    }

    #[test]
    fn monotonic_non_decreasing() {
        let mut prev = dec!(-1);
        for d in [0i64, 3, 10, 30, 60, 90, 200] {
            let p = persistence_points(d);
            assert!(p >= prev, "not monotonic at {d}");
            prev = p;
        }
    }
}
