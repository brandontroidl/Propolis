//! Pure projection accumulate step: the load-bearing state transition of the
//! scoring system. `apply_event` folds one `EventInput` into the prior
//! `IpScore` projection, decaying the stored raw score and each category's
//! accumulated weight to the event's `observed_at`, adding this event's
//! contribution (unless deduped), and recomputing every derived flag.
//!
//! It is a pure function: no DB, no clock, no I/O. The repository layer
//! (Task 12) supplies the un-projected stored `raw_score` and the breadth
//! counts; the engine never re-projects a read-projected value (double-decay
//! guard) and never recomputes breadth itself.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use crate::domain::enums::{Category, is_confirmed_real};
use crate::domain::types::{EventInput, IpScore};
use crate::scoring::breadth::effective_score;
use crate::scoring::constants::SCORE_CAP;
use crate::scoring::decay::decay;
use crate::scoring::eligibility::eligible;
use crate::scoring::persistence::persistence_points;
use crate::scoring::tier::{recommended_for_blocklist, recommended_for_vendor, tier};

/// Per-category accumulator stored inside `IpScore.category_breakdown`.
///
/// `weight` is the decayed accumulated signal weight for the category and is
/// what the 0.5 live floor is applied to. `max_confidence` is the maximum
/// confidence ever seen for the category and does NOT decay - the category
/// drops out of the confidence/breadth math via its `weight` crossing the
/// floor, not via confidence shrinking.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CategoryStat {
    pub weight: Decimal,
    pub max_confidence: Decimal,
}

/// The 0.5 live weight floor: a category contributes to `distinct_categories`
/// and to `max_confidence` only while its decayed weight is strictly above it.
const LIVE_FLOOR: Decimal = dec!(0.5);

/// Fold `event` into `prev`, returning the new projection anchored at
/// `event.observed_at`.
///
/// `deduped` = this sighting is a duplicate within the dedup window: it decays
/// prior state to now and still records the sighting (`event_count += 1`, can
/// latch `has_confirmed_real`) but adds NO weight. `distinct_wan_count` /
/// `distinct_sensor_count` are computed by the repository from its vantage and
/// sensor tracking and threaded through verbatim; the engine does not recompute
/// breadth.
pub fn apply_event(
    prev: Option<IpScore>,
    event: &EventInput,
    half_life_seconds: i64,
    deduped: bool,
    distinct_wan_count: i32,
    distinct_sensor_count: i32,
) -> IpScore {
    let now = event.observed_at;

    // Step 1-2: seed or decay prior state to `now`.
    let (
        decayed_raw,
        mut breakdown,
        first_seen,
        prev_event_count,
        prev_has_confirmed_real,
        delisted,
        prev_active_days,
        prev_last_active_day,
    ) = match prev {
        None => (
            dec!(0),
            BTreeMap::<Category, CategoryStat>::new(),
            now,
            0i32,
            false,
            false,
            0i32,
            None::<NaiveDate>,
        ),
        Some(p) => {
            let elapsed = (now - p.decay_anchor).num_seconds();
            let decayed_raw = decay(p.raw_score, elapsed, half_life_seconds);
            let mut map: BTreeMap<Category, CategoryStat> =
                serde_json::from_value(p.category_breakdown)
                    .expect("category_breakdown is a well-formed CategoryStat map");
            for stat in map.values_mut() {
                stat.weight = decay(stat.weight, elapsed, half_life_seconds);
            }
            (
                decayed_raw,
                map,
                p.first_seen,
                p.event_count,
                p.has_confirmed_real,
                p.delisted,
                p.active_days,
                Some(p.last_active_day),
            )
        }
    };

    // Distinct-active-day counter (never decays): this event opens a new active day iff its UTC
    // date is strictly later than the last one counted. Same-day repeats and out-of-order older
    // events do not add a day. Computed here in the pure fold so the incremental path and a full
    // replay (which folds these same events in order) produce an identical count.
    let event_day = now.date_naive();
    let (active_days, last_active_day) = match prev_last_active_day {
        None => (1, event_day),
        Some(last) => {
            let days = if event_day > last {
                prev_active_days + 1
            } else {
                prev_active_days
            };
            (days, std::cmp::max(last, event_day))
        }
    };

    // Step 3: add this event's contribution unless it is a deduped sighting.
    let new_raw = if deduped {
        decayed_raw
    } else {
        let entry = breakdown.entry(event.category).or_insert(CategoryStat {
            weight: dec!(0),
            max_confidence: dec!(0),
        });
        entry.weight += Decimal::from(event.weight);
        if event.confidence > entry.max_confidence {
            entry.max_confidence = event.confidence;
        }
        std::cmp::min(SCORE_CAP, decayed_raw + Decimal::from(event.weight))
    };

    // Step 4: sticky latch + counts (a deduped sighting still counts).
    let has_confirmed_real = prev_has_confirmed_real
        || is_confirmed_real(event.protocol, event.authenticated, event.category);
    let event_count = prev_event_count + 1;

    // Steps 5-6: derive facts + assemble. Both decay_anchor and last_seen are `now`
    // (the event's observed_at) because an event WAS seen at this instant.
    derive_projection(
        event.source_ip,
        new_raw,
        breakdown,
        has_confirmed_real,
        event_count,
        distinct_wan_count,
        distinct_sensor_count,
        active_days,
        last_active_day,
        first_seen,
        now,
        now,
        delisted,
    )
}

/// Compute all derived facts (eligibility, tier, recommendations, live-decayed `max_confidence`)
/// over an already-decayed `breakdown` + `raw_score`, and assemble the `IpScore`. Single source of
/// truth for the derivation, shared by [`apply_event`] (write path) and [`project_to_now`] (read
/// path) so the gate logic cannot drift between them.
#[allow(clippy::too_many_arguments)]
fn derive_projection(
    source_ip: IpAddr,
    raw_score: Decimal,
    breakdown: BTreeMap<Category, CategoryStat>,
    has_confirmed_real: bool,
    event_count: i32,
    distinct_wan_count: i32,
    distinct_sensor_count: i32,
    active_days: i32,
    last_active_day: NaiveDate,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    decay_anchor: DateTime<Utc>,
    delisted: bool,
) -> IpScore {
    let distinct_categories = breakdown.values().filter(|s| s.weight > LIVE_FLOOR).count() as i32;
    // Live-decayed confidence: a category whose weight has decayed to/below the floor no longer
    // holds the tier confidence gate open. Empty -> 0 (fail-closed).
    let max_confidence = breakdown
        .values()
        .filter(|s| s.weight > LIVE_FLOOR)
        .map(|s| s.max_confidence)
        .max()
        .unwrap_or(dec!(0));

    let is_eligible = eligible(
        has_confirmed_real,
        event_count as u32,
        distinct_categories as u32,
        delisted,
    );
    // Persistence lifts the GATE-facing score, never the stored raw. A methodical attacker seen
    // across many distinct days climbs the tiers even though the 6h decay keeps each day's raw
    // low; the stored raw_score stays the decayed accumulation so the next decay cannot
    // double-count the bonus. The confidence axis of `tier` and the `eligible` gate still apply,
    // so a persistent low-confidence scanner is lifted but never actually promoted.
    let gated_raw = std::cmp::min(
        SCORE_CAP,
        raw_score + persistence_points(active_days as i64),
    );
    let effective = effective_score(gated_raw, distinct_wan_count as u32);
    let feed_tier = tier(gated_raw, max_confidence); // gated raw (base + persistence), not effective.
    let rec_vendor = recommended_for_vendor(is_eligible, feed_tier);
    let rec_blocklist = recommended_for_blocklist(is_eligible, effective);

    // The map is well-formed Decimals, so serialization cannot fail.
    let category_breakdown =
        serde_json::to_value(&breakdown).expect("CategoryStat map serializes to JSON");

    IpScore {
        source_ip,
        raw_score,
        decay_anchor,
        max_confidence,
        event_count,
        distinct_categories,
        category_breakdown,
        has_confirmed_real,
        distinct_wan_count,
        distinct_sensor_count,
        active_days,
        last_active_day,
        first_seen,
        last_seen,
        eligible: is_eligible,
        recommended_for_vendor: rec_vendor,
        recommended_for_blocklist: rec_blocklist,
        tier: feed_tier,
        delisted,
    }
}

/// Project a stored projection forward to `now` for a READ: decay `raw_score` and each category's
/// weight to `now`, then RE-DERIVE the gate flags over the live-decayed breakdown, so a read
/// reflects the current state rather than the flags frozen at the last write. Pure; the caller must
/// NOT persist the result (the stored row stays un-projected for the double-decay guard).
/// `last_seen` is unchanged (no new event was seen); `decay_anchor` becomes `now`.
pub(crate) fn project_to_now(
    stored: IpScore,
    now: DateTime<Utc>,
    half_life_seconds: i64,
) -> IpScore {
    let elapsed = (now - stored.decay_anchor).num_seconds();
    let raw_score = decay(stored.raw_score, elapsed, half_life_seconds);
    let mut breakdown: BTreeMap<Category, CategoryStat> =
        serde_json::from_value(stored.category_breakdown)
            .expect("category_breakdown is a well-formed CategoryStat map");
    for stat in breakdown.values_mut() {
        stat.weight = decay(stat.weight, elapsed, half_life_seconds);
    }
    derive_projection(
        stored.source_ip,
        raw_score,
        breakdown,
        stored.has_confirmed_real,
        stored.event_count,
        stored.distinct_wan_count,
        stored.distinct_sensor_count,
        stored.active_days,
        stored.last_active_day,
        stored.first_seen,
        stored.last_seen,
        now,
        stored.delisted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::enums::{Protocol, SignalType};
    use chrono::{DateTime, Duration, Utc};
    use proptest::prelude::*;

    const HALF_LIFE: i64 = 21600;

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    /// tcp + authenticated + honeypot -> confirmed-real latches.
    fn auth_honeypot_event(t: &str) -> EventInput {
        EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            ts(t),
            serde_json::json!({}),
            None,
        )
    }

    /// udp / non-honeypot -> never confirmed-real.
    fn udp_probe_event(t: &str) -> EventInput {
        EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::PortScan,
            Protocol::Udp,
            false,
            ts(t),
            serde_json::json!({}),
            None,
        )
    }

    #[test]
    fn confirmed_real_latch_sticks_and_never_unsets() {
        let e1 = auth_honeypot_event("2026-07-17T00:00:00Z");
        let s1 = apply_event(None, &e1, HALF_LIFE, false, 1, 1);
        assert!(s1.has_confirmed_real);
        let e2 = udp_probe_event("2026-07-20T00:00:00Z"); // days later, decayed
        let s2 = apply_event(Some(s1), &e2, HALF_LIFE, false, 1, 1);
        assert!(s2.has_confirmed_real); // still true, never unset
    }

    fn command_exec_at(when: DateTime<Utc>) -> EventInput {
        EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::HoneypotCommandExec, // weight 60, conf 0.950, honeypot
            Protocol::Tcp,
            true,
            when,
            serde_json::json!({}),
            None,
        )
    }

    /// Fold `days` once-a-day command-exec events for one IP, 24h apart (far past the 60s dedup
    /// window, so each adds weight). A once-a-day attacker's base raw converges to ~64 (60 plus the
    /// residual of four half-lives of decay), which never reaches a tier on its own - persistence
    /// is what promotes it.
    fn daily_command_exec(days: i64) -> IpScore {
        let start = ts("2026-01-01T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for d in 0..days {
            let e = command_exec_at(start + Duration::days(d));
            acc = Some(apply_event(acc, &e, HALF_LIFE, false, 1, 1));
        }
        acc.unwrap()
    }

    #[test]
    fn active_days_counts_distinct_days_not_events() {
        // Three events in ONE day -> 1 active day (a burst is not persistence).
        let start = ts("2026-01-01T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for h in [0i64, 1, 2] {
            let e = command_exec_at(start + Duration::hours(h));
            acc = Some(apply_event(acc, &e, HALF_LIFE, false, 1, 1));
        }
        assert_eq!(acc.unwrap().active_days, 1);
        // Three events on three distinct days -> 3 active days.
        assert_eq!(daily_command_exec(3).active_days, 3);
    }

    #[test]
    fn short_lived_addresses_are_scored_exactly_as_before_persistence() {
        // At <= PERSIST_GRACE_DAYS the bonus is 0, so a base-~64 attacker is NOT tiered: the
        // persistence change is inert for short-lived addresses (both directions of the guard).
        let s = daily_command_exec(2);
        assert_eq!(s.active_days, 2);
        assert!(
            s.raw_score < dec!(75),
            "base raw {} unexpectedly >= 75",
            s.raw_score
        );
        assert_eq!(s.tier, None);
    }

    #[test]
    fn thirty_active_days_reaches_standard() {
        let s = daily_command_exec(30);
        assert_eq!(s.active_days, 30);
        // The stored base raw stays below Standard on its own; only persistence lifts the gate.
        assert!(
            s.raw_score < dec!(75),
            "base raw {} should stay below Standard",
            s.raw_score
        );
        assert_eq!(s.tier, Some(crate::domain::enums::FeedTier::Standard));
    }

    #[test]
    fn sixty_active_days_reaches_aggressive() {
        let s = daily_command_exec(60);
        assert_eq!(s.active_days, 60);
        // Command-exec confidence (0.95) clears the AGGRESSIVE confidence axis; persistence carries
        // the score axis over 90.
        assert_eq!(s.tier, Some(crate::domain::enums::FeedTier::Aggressive));
    }

    #[test]
    fn persistent_low_confidence_scanner_is_never_promoted() {
        // A once-a-day port-scanner over 90 distinct days: the persistence bonus lifts the gate
        // score, but PortScan confidence (0.60) never clears even the STANDARD 0.70 axis, and it is
        // not confirmed-real, so it stays untiered and unrecommended. Persistence cannot promote noise.
        let start = ts("2026-01-01T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for d in 0..90 {
            let e = udp_probe_event_at(start + Duration::days(d));
            acc = Some(apply_event(acc, &e, HALF_LIFE, false, 1, 1));
        }
        let s = acc.unwrap();
        assert_eq!(s.active_days, 90);
        assert_eq!(s.tier, None);
        assert!(!s.recommended_for_vendor);
    }

    fn udp_probe_event_at(when: DateTime<Utc>) -> EventInput {
        EventInput::from_signal(
            "198.51.100.9".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::PortScan, // weight 20, conf 0.600, network, never confirmed-real
            Protocol::Udp,
            false,
            when,
            serde_json::json!({}),
            None,
        )
    }

    /// A high-confidence category whose weight decays below the 0.5 live floor
    /// stops contributing to `max_confidence`, so the tier confidence floor is
    /// no longer held open (fail-closed -> tier None). Deterministic.
    #[test]
    fn live_decayed_max_confidence_releases_tier_floor() {
        // High-weight, high-confidence honeypot event: raw 80, conf 0.98.
        let e1 = EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::HoneypotMalwareUpload, // weight 80, conf 0.980, honeypot
            Protocol::Tcp,
            true,
            ts("2026-07-17T00:00:00Z"),
            serde_json::json!({}),
            None,
        );
        let s1 = apply_event(None, &e1, HALF_LIFE, false, 1, 1);
        assert_eq!(s1.raw_score, dec!(80));
        assert_eq!(s1.max_confidence, dec!(0.980));
        assert_eq!(s1.tier, Some(crate::domain::enums::FeedTier::Standard)); // raw>=75, conf>=0.70

        // 10 half-lives later, a deduped sighting: pure decay, no weight added.
        // 80 * 2^-10 = 0.078125 < 0.5 -> honeypot drops out of the live breakdown.
        let later = ts("2026-07-17T00:00:00Z") + Duration::seconds(10 * HALF_LIFE);
        let e2 = EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            later,
            serde_json::json!({}),
            None,
        );
        let s2 = apply_event(Some(s1), &e2, HALF_LIFE, true, 1, 1);
        assert!(s2.raw_score < dec!(0.5));
        assert_eq!(s2.distinct_categories, 0);
        assert_eq!(s2.max_confidence, dec!(0)); // fail-closed: no category clears the floor
        assert_eq!(s2.tier, None); // confidence floor no longer held open
    }

    // --- proptest anti-spoof invariant --------------------------------------

    /// Non-honeypot signals: `is_confirmed_real` is false for these regardless
    /// of protocol/auth, so no sequence drawn from them can latch it. They span
    /// Ids/Network/Waf/Auth, so breadth (distinct categories) CAN accrue - which
    /// is exactly what the invariant must resist.
    const NON_CONFIRMED: [SignalType; 10] = [
        SignalType::SuricataSev1,
        SignalType::SuricataSev2,
        SignalType::SuricataSev3,
        SignalType::PortScan,
        SignalType::SynFlood,
        SignalType::BlockedConnection,
        SignalType::WafSqliXss,
        SignalType::WafGenericBlock,
        SignalType::SshBruteForce,
        SignalType::RemoteAuthFailure,
    ];

    prop_compose! {
        /// Sequences of non-confirmed-real events, each paired with an arbitrary
        /// `distinct_wan_count` to thread through `apply_event`. Timestamps are
        /// monotonic. `auth`/`udp` are free because none of these categories can
        /// ever be confirmed-real anyway.
        fn event_seq_no_confirmed_real()(
            specs in prop::collection::vec(
                (0usize..NON_CONFIRMED.len(), any::<bool>(), any::<bool>(), 0i64..500_000i64, 0i32..8i32),
                1..12usize,
            )
        ) -> Vec<(EventInput, i32)> {
            let base: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
            let mut acc = 0i64;
            specs
                .into_iter()
                .map(|(idx, auth, udp, secs, wan)| {
                    acc += secs;
                    let sig = NON_CONFIRMED[idx];
                    let proto = if udp { Protocol::Udp } else { Protocol::Tcp };
                    let e = EventInput::from_signal(
                        "203.0.113.7".parse().unwrap(),
                        None,
                        "sensor-a".into(),
                        sig,
                        proto,
                        auth,
                        base + Duration::seconds(acc),
                        serde_json::json!({}),
                        None,
                    );
                    (e, wan)
                })
                .collect()
        }
    }

    proptest! {
        #[test]
        fn breadth_never_flips_eligibility_without_confirmed_real(
            seq in event_seq_no_confirmed_real()
        ) {
            let mut s: Option<IpScore> = None;
            for (e, wan) in seq {
                s = Some(apply_event(s.take(), &e, HALF_LIFE, false, wan, 1));
            }
            let s = s.unwrap();
            // No confirmed-real event was ever fed, so the latch stays false and
            // eligibility cannot flip true no matter how much breadth accrued.
            prop_assert!(!s.has_confirmed_real);
            prop_assert!(!s.eligible);
        }
    }
}
