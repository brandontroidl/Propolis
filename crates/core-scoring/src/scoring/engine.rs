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

use crate::domain::enums::{Category, Protocol, SignalType, is_confirmed_real};
use crate::domain::types::{EventInput, IpScore};
use crate::scoring::breadth::effective_score;
use crate::scoring::constants::{
    EVENT_SUMMARY_KEY, MAX_SUMMARY_EVENTS, OVERFLOW_SUMMARY_KEY, SCORE_CAP,
};
use crate::scoring::decay::decay;
use crate::scoring::eligibility::eligible;
use crate::scoring::persistence::persistence_points;
use crate::scoring::tier::{
    recommended_by_volume, recommended_for_blocklist, recommended_for_vendor, tier,
};

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
        prev_established_event_count,
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
                p.established_event_count,
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
    let unattributed = is_unattributed_summary(event);
    let new_raw = if deduped || unattributed {
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
    // An overflow summary is attributed to the first address it folded, which may only have
    // connected: it proves nothing about that address.
    let has_confirmed_real = prev_has_confirmed_real
        || (!unattributed
            && is_confirmed_real(event.protocol, event.authenticated, event.category));
    let represented = represented_events(event);
    let event_count = prev_event_count.saturating_add(represented);
    // Non-spoofable count: only a completed TCP connection proves the source address is genuine (a
    // spoofed source cannot finish the handshake). UDP/ICMP datagrams carry a forgeable sender, so
    // they never count toward volume-based blocklisting - otherwise a spoofed flood could list an
    // innocent third party (see `recommended_by_volume` in `derive_projection`).
    let established_event_count = if event.protocol == Protocol::Tcp {
        prev_established_event_count.saturating_add(represented)
    } else {
        prev_established_event_count
    };

    // Steps 5-6: derive facts + assemble. Both decay_anchor and last_seen are `now`
    // (the event's observed_at) because an event WAS seen at this instant.
    derive_projection(
        event.source_ip,
        new_raw,
        breakdown,
        has_confirmed_real,
        event_count,
        established_event_count,
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

/// Whether `event` is a sensor's overflow or per-network summary: it stands for many addresses but
/// carries one of them as its source, so it adds no weight and latches nothing for that address.
pub(crate) fn is_unattributed_summary(event: &EventInput) -> bool {
    event.metadata.get(OVERFLOW_SUMMARY_KEY) == Some(&serde_json::Value::Bool(true))
}

/// How many sightings `event` counts as in `event_count` and `established_event_count`: one, or for
/// a sensor's connection or login summary (`event_summary: true` on a `honeypot_connection` or
/// `honeypot_login_attempt`) the `suppressed_count` events it replaces, so a source whose events a
/// per-source budget folded away measures the same volume as if each had been written. Anything
/// else (other signals, the overflow summary, which stands for many addresses), and a summary whose
/// count is missing or not a positive integer, is one. Clamped to [`MAX_SUMMARY_EVENTS`].
pub(crate) fn represented_events(event: &EventInput) -> i32 {
    let flagged = |key: &str| event.metadata.get(key) == Some(&serde_json::Value::Bool(true));
    let is_summary = matches!(
        event.signal_type,
        SignalType::HoneypotConnection | SignalType::HoneypotLoginAttempt
    ) && flagged(EVENT_SUMMARY_KEY)
        && !flagged(OVERFLOW_SUMMARY_KEY);
    let count = is_summary
        .then(|| event.metadata.get("suppressed_count")?.as_u64())
        .flatten()
        .filter(|&n| n > 0)
        .map_or(1, |n| n.min(MAX_SUMMARY_EVENTS));
    i32::try_from(count).unwrap_or(i32::MAX)
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
    established_event_count: i32,
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
    // A high-volume connection flood is recommended for the blocklist on volume alone (no
    // confirmed-real latch): dedup collapses such a flood to one scored event, so the merit path
    // never fires. It counts only ESTABLISHED (completed-TCP) events, never spoofable UDP/ICMP, so a
    // spoofed datagram flood cannot volume-list an innocent third party. Vendor reporting still
    // gates on confirmed-real (rec_vendor above), so a bare flood is blocked locally but not
    // reported upstream.
    let seconds_since_last_seen = (decay_anchor - last_seen).num_seconds();
    let rec_blocklist = recommended_for_blocklist(is_eligible, effective)
        || recommended_by_volume(
            delisted,
            established_event_count as u32,
            seconds_since_last_seen,
        );

    // The map is well-formed Decimals, so serialization cannot fail.
    let category_breakdown =
        serde_json::to_value(&breakdown).expect("CategoryStat map serializes to JSON");

    IpScore {
        source_ip,
        raw_score,
        decay_anchor,
        max_confidence,
        event_count,
        established_event_count,
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
        stored.established_event_count,
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

    /// A TCP probe: an ESTABLISHED (completed-handshake) but non-confirmed-real event. Same shape as
    /// `udp_probe_event_at` but over TCP, so the source address cannot be spoofed.
    fn tcp_probe_event_at(when: DateTime<Utc>) -> EventInput {
        EventInput::from_signal(
            "198.51.100.9".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::PortScan, // weight 20, conf 0.600, network, never confirmed-real
            Protocol::Tcp,
            false,
            when,
            serde_json::json!({}),
            None,
        )
    }

    #[test]
    fn a_high_volume_tcp_flood_is_blocklisted_on_volume_without_confirmed_real() {
        // A TCP connection flood: many non-confirmed-real but ESTABLISHED events. Dedup keeps the
        // score near zero and the confirmed-real latch never sets, so the merit path never
        // recommends it - but crossing the volume threshold on established (non-spoofable) events
        // while recently active must.
        let threshold = crate::scoring::constants::VOLUME_LIST_THRESHOLD as i64;
        let base = ts("2026-08-21T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for i in 0..threshold {
            let e = tcp_probe_event_at(base + Duration::seconds(i));
            acc = Some(apply_event(acc, &e, HALF_LIFE, i > 0, 1, 1));
        }
        let s = acc.unwrap();
        assert!(!s.has_confirmed_real, "flood must not be confirmed-real");
        assert!(
            s.established_event_count >= threshold as i32,
            "TCP events count as established"
        );
        assert!(
            s.recommended_for_blocklist,
            "a recent high-volume TCP flood must be volume-listed (raw {}, established {})",
            s.raw_score, s.established_event_count
        );
        // Vendor reporting still requires confirmed-real, so a bare flood is NOT reported upstream.
        assert!(!s.recommended_for_vendor);
    }

    /// Security regression (audit): a spoofable UDP flood must NEVER be volume-listed. A UDP sender
    /// address is forgeable, so counting it would let a spoofed flood blocklist an innocent third
    /// party. UDP events do not count as established, so event_count crosses the threshold but
    /// established_event_count stays 0 and the volume path never fires. Fails without the fix (the
    /// old code counted raw event_count and WOULD list this IP).
    #[test]
    fn a_udp_only_flood_is_not_volume_listed_even_over_the_threshold() {
        let threshold = crate::scoring::constants::VOLUME_LIST_THRESHOLD as i64;
        let base = ts("2026-08-21T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for i in 0..threshold {
            let e = udp_probe_event_at(base + Duration::seconds(i));
            acc = Some(apply_event(acc, &e, HALF_LIFE, i > 0, 1, 1));
        }
        let s = acc.unwrap();
        assert!(
            s.event_count >= threshold as i32,
            "raw events are still counted"
        );
        assert_eq!(
            s.established_event_count, 0,
            "no UDP datagram counts as an established (non-spoofable) event"
        );
        assert!(
            !s.recommended_for_blocklist,
            "a spoofable UDP flood must not be volume-listed - a spoofed source would blocklist an innocent IP"
        );
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

    fn vnc_event(
        signal: SignalType,
        when: DateTime<Utc>,
        metadata: serde_json::Value,
    ) -> EventInput {
        EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "vnc".into(),
            signal,
            Protocol::Tcp,
            signal == SignalType::HoneypotLoginAttempt,
            when,
            metadata,
            None,
        )
    }

    /// Fold `events` in time order with the repository's dedup rule (a same-signal sighting within
    /// the dedup window of the newest earlier one adds no weight).
    fn fold_with_dedup(mut events: Vec<EventInput>) -> IpScore {
        events.sort_by_key(|e| e.observed_at);
        let mut newest: std::collections::HashMap<SignalType, DateTime<Utc>> = Default::default();
        let mut acc: Option<IpScore> = None;
        for e in &events {
            let deduped = newest.get(&e.signal_type).is_some_and(|prior| {
                (e.observed_at - *prior).num_seconds().abs()
                    <= crate::scoring::constants::DEDUP_WINDOW_SECONDS
            });
            newest.insert(e.signal_type, e.observed_at);
            acc = Some(apply_event(acc, e, HALF_LIFE, deduped, 1, 1));
        }
        acc.unwrap()
    }

    /// The flood the VNC sensor wrote about 10,000 lines an hour for: a connection and a login
    /// every 1.4 s for two hours. `bounded` is what the sensor now writes for it: the first ten of
    /// each kind per ten-minute window verbatim and one login summary per window carrying the
    /// rest. The two streams must measure the same volume, and the bounded one must not score
    /// lower.
    fn vnc_flood(bounded: bool) -> Vec<EventInput> {
        const WINDOW_MS: i64 = 600_000;
        const BUDGET: i64 = 10;
        let start = ts("2026-10-19T00:00:00Z");
        let mut out = Vec::new();
        let (mut window, mut seen, mut folded) = (0i64, 0i64, 0u64);
        let close = |out: &mut Vec<EventInput>, window: i64, folded: u64| {
            if folded > 0 {
                out.push(vnc_event(
                    SignalType::HoneypotLoginAttempt,
                    start + Duration::milliseconds((window + 1) * WINDOW_MS),
                    serde_json::json!({
                        "event_summary": true,
                        "suppressed_count": folded * 2,
                        "suppressed_connections": folded,
                        "suppressed_attempts": folded,
                    }),
                ));
            }
        };
        for i in 0..(7_200_000 / 1400) {
            let at = i * 1400;
            if at / WINDOW_MS != window {
                close(&mut out, window, folded);
                (window, seen, folded) = (at / WINDOW_MS, 0, 0);
            }
            seen += 1;
            if !bounded || seen <= BUDGET {
                let when = start + Duration::milliseconds(at);
                out.push(vnc_event(
                    SignalType::HoneypotConnection,
                    when,
                    serde_json::json!({}),
                ));
                out.push(vnc_event(
                    SignalType::HoneypotLoginAttempt,
                    when,
                    serde_json::json!({}),
                ));
            } else {
                folded += 1;
            }
        }
        close(&mut out, window, folded);
        out
    }

    #[test]
    fn a_bounded_flood_measures_the_same_volume_and_never_scores_lower() {
        let before = fold_with_dedup(vnc_flood(false));
        let after = fold_with_dedup(vnc_flood(true));
        assert!(before.event_count > 5000, "the fixture is a real flood");
        assert_eq!(after.event_count, before.event_count);
        assert_eq!(
            after.established_event_count,
            before.established_event_count
        );
        assert_eq!(after.has_confirmed_real, before.has_confirmed_real);
        assert_eq!(after.eligible, before.eligible);
        assert!(
            after.raw_score >= before.raw_score,
            "raw {} fell below {}",
            after.raw_score,
            before.raw_score
        );
        // The volume path is what separates them if a summary counted as one event: the bounded
        // stream has about 100 events and would not be volume-listed.
        assert!(before.recommended_for_blocklist);
        assert!(after.recommended_for_blocklist);
    }

    #[test]
    fn only_an_event_summary_stands_for_more_than_one_event() {
        let when = ts("2026-10-19T00:00:00Z");
        let signal = SignalType::HoneypotLoginAttempt;
        let count =
            |metadata: serde_json::Value| represented_events(&vnc_event(signal, when, metadata));
        let summary = |n: serde_json::Value| serde_json::json!({"event_summary": true, "suppressed_count": n});
        assert_eq!(count(serde_json::json!({})), 1);
        assert_eq!(count(summary(serde_json::json!(84))), 84);
        // A malformed or hostile count is one event or a clamped one, never a wrap or a panic.
        for bad in [
            serde_json::json!(0),
            serde_json::json!(-5),
            serde_json::json!("84"),
            serde_json::json!(1.5),
            serde_json::json!(null),
        ] {
            assert_eq!(count(summary(bad.clone())), 1, "{bad}");
        }
        assert_eq!(count(summary(serde_json::json!(u64::MAX))), 1_000_000);
        // A count without the marker (a command summary, a UDP rate-limit summary) is one event.
        assert_eq!(count(serde_json::json!({"suppressed_count": 500})), 1);
        // The overflow summary stands for many addresses but belongs to one: one event.
        assert_eq!(
            count(
                serde_json::json!({"event_summary": true, "overflow_summary": true, "suppressed_count": 7952})
            ),
            1
        );
        // Only a connection or login summary is expanded, whatever else carries the marker.
        let other =
            |signal| represented_events(&vnc_event(signal, when, summary(serde_json::json!(500))));
        assert_eq!(other(SignalType::HoneypotCommandExec), 1);
        assert_eq!(other(SignalType::HoneypotMalwareUpload), 1);
        assert_eq!(other(SignalType::HoneypotConnection), 500);
        assert_eq!(
            count(serde_json::json!({"event_summary": "true", "suppressed_count": 500})),
            1
        );
        // Folding saturates instead of overflowing the i32 counter.
        let big = || vnc_event(signal, when, summary(serde_json::json!(1_000_000)));
        let mut s = apply_event(None, &big(), HALF_LIFE, false, 1, 1);
        for _ in 0..3000 {
            s = apply_event(Some(s), &big(), HALF_LIFE, true, 1, 1);
        }
        assert_eq!(s.event_count, i32::MAX);
        assert_eq!(s.established_event_count, i32::MAX);
    }

    /// The overflow summary is attributed to the first address it folded. If that address only
    /// connected, a login summary written under it (the shape before the sensor stopped writing
    /// one, still in stored logs) must not make it confirmed-real, eligible or heavier.
    #[test]
    fn an_overflow_summary_latches_nothing_and_weighs_nothing() {
        let when = ts("2026-10-19T00:00:00Z");
        let overflow = |signal| {
            vnc_event(
                signal,
                when,
                serde_json::json!({
                    "event_summary": true, "overflow_summary": true,
                    "suppressed_count": 900, "suppressed_attempts": 450,
                }),
            )
        };
        for signal in [
            SignalType::HoneypotLoginAttempt,
            SignalType::HoneypotConnection,
        ] {
            let s = apply_event(None, &overflow(signal), HALF_LIFE, false, 1, 1);
            assert!(!s.has_confirmed_real, "{signal:?}");
            assert!(!s.eligible, "{signal:?}");
            assert_eq!(s.raw_score, dec!(0), "{signal:?}");
            assert_eq!(s.event_count, 1, "{signal:?}");
        }
        // A real login of the same address still latches, and the summary does not undo it.
        let real = vnc_event(
            SignalType::HoneypotLoginAttempt,
            when,
            serde_json::json!({}),
        );
        let s = apply_event(None, &real, HALF_LIFE, false, 1, 1);
        assert!(s.has_confirmed_real);
        let s = apply_event(
            Some(s),
            &overflow(SignalType::HoneypotConnection),
            HALF_LIFE,
            false,
            1,
            1,
        );
        assert!(s.has_confirmed_real);
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
