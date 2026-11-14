//! Pure projection accumulate step: the load-bearing state transition of the
//! scoring system. `apply_event` folds one `EventInput` into the prior
//! `IpScore` projection, decaying the stored raw score and each category's
//! accumulated weight to the event's `observed_at` (or leaving them at the
//! stored anchor when the event is older than it: time never runs backwards
//! here), adding this event's contribution (unless deduped), and recomputing
//! every derived flag.
//!
//! That is the fold for an ESTABLISHED event: one from a completed TCP connection, whose
//! source address the handshake proved. A datagram's source address is whatever the sender
//! wrote, so an event that is not established is only recorded ([`record_sighting`]): it is
//! counted and dated, and changes nothing a score, a tier or a listing is derived from.
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

use crate::domain::enums::{Category, FeedTier, Protocol, SignalType, is_confirmed_real};
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
/// `event.observed_at`, or at the previous anchor when that is later.
///
/// `decay_anchor` and `last_seen` never move backwards. An event dated before the stored anchor
/// (a backlog read late, a collector whose clock is slow, a forged timestamp) is still counted
/// and is folded in at the anchor already reached, adding what its own age leaves of its weight
/// (its weight decayed from its time to the anchor), which is what it would have added had it
/// been read in order. Taking its
/// time as the new anchor would make the next event, and every read, decay the whole accumulated
/// score across the gap a second time, so one line dated years back would erase everything
/// other sensors had gathered about the address; taking it as `last_seen` would drop a listed
/// address out of every feed window. Replay folds the same events in the same order through
/// this function, so the rule holds for a rebuilt projection exactly as for the stored one.
///
/// `deduped` = this sighting is a duplicate within the dedup window: it decays
/// prior state to now and still records the sighting (`event_count += 1`, can
/// latch `has_confirmed_real`) but adds NO weight. `distinct_wan_count` /
/// `distinct_sensor_count` are computed by the repository from its vantage and
/// sensor tracking and threaded through verbatim; the engine does not recompute
/// breadth.
///
/// An event that is not established ([`is_established`]) takes none of these steps: see
/// [`record_sighting`].
pub fn apply_event(
    prev: Option<IpScore>,
    event: &EventInput,
    half_life_seconds: i64,
    deduped: bool,
    distinct_wan_count: i32,
    distinct_sensor_count: i32,
) -> IpScore {
    if !is_established(event) {
        return record_sighting(prev, event, distinct_wan_count, distinct_sensor_count);
    }
    let now = event.observed_at;

    // A row no established event has reached holds nothing a score may build on: it was opened
    // by a forgeable sighting (or, before this rule, scored by them). This event starts it as it
    // would a new row, keeping only the record of those sightings, so a datagram can neither add
    // to what the connection scores nor, by dating the row's anchor, take from it.
    let (sightings, prev) = match prev {
        Some(p) if p.established_event_count == 0 => (
            Some((p.event_count, p.first_seen, p.last_seen, p.delisted)),
            None,
        ),
        other => (None, other),
    };

    // Step 1-2: seed or decay prior state to the new anchor.
    let (
        decayed_raw,
        mut breakdown,
        first_seen,
        last_seen,
        decay_anchor,
        prev_event_count,
        prev_established_event_count,
        prev_has_confirmed_real,
        delisted,
        prev_active_days,
        prev_last_active_day,
        prev_established_last_seen,
        prev_aggressive_earned_at,
        prev_standard_earned_at,
    ) = match prev {
        None => {
            let (event_count, first_seen, last_seen, delisted) =
                sightings.unwrap_or((0, now, now, false));
            (
                dec!(0),
                BTreeMap::<Category, CategoryStat>::new(),
                first_seen,
                std::cmp::max(now, last_seen),
                now,
                event_count,
                0i32,
                false,
                delisted,
                0i32,
                None::<NaiveDate>,
                None::<DateTime<Utc>>,
                None::<DateTime<Utc>>,
                None::<DateTime<Utc>>,
            )
        }
        Some(p) => {
            // The later of the event's time and what is stored, for each: see the function doc.
            // The decay runs from the previous anchor to the new one, so it is zero for an event
            // that is not newer and exactly the real gap for one that is.
            let decay_anchor = std::cmp::max(now, p.decay_anchor);
            let last_seen = std::cmp::max(now, p.last_seen);
            let elapsed = (decay_anchor - p.decay_anchor).num_seconds();
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
                last_seen,
                decay_anchor,
                p.event_count,
                p.established_event_count,
                p.has_confirmed_real,
                p.delisted,
                p.active_days,
                Some(p.last_active_day),
                p.established_last_seen,
                p.aggressive_earned_at,
                p.standard_earned_at,
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
        // What this event is worth at the anchor. An event that is not newer than the anchor is
        // added as of its own time and decayed to the anchor, like everything already in the
        // score. Read late (a backlog drained after an outage, one log read behind another) it
        // then counts for what it would have counted read in order, where its full weight at the
        // anchor would turn a session from days ago into a current one; and a back-dated line
        // adds only what its claimed age leaves of it. For the newest event the gap is zero.
        let worth = decay(
            Decimal::from(event.weight),
            (decay_anchor - now).num_seconds(),
            half_life_seconds,
        );
        entry.weight += worth;
        if event.confidence > entry.max_confidence {
            entry.max_confidence = event.confidence;
        }
        std::cmp::min(SCORE_CAP, decayed_raw + worth)
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
    // they never reach this point and never count toward eligibility or volume-based blocklisting
    // - otherwise a spoofed flood could list an innocent third party (see `recommended_by_volume`
    // in `derive_projection`).
    let established_event_count = prev_established_event_count.saturating_add(represented);
    let established_last_seen = Some(prev_established_last_seen.map_or(now, |seen| seen.max(now)));

    // Steps 5-6: derive facts + assemble. `last_seen` and `decay_anchor` are the event's
    // observed_at (an event WAS seen at this instant) unless the stored ones are later.
    let mut next = derive_projection(
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
        last_seen,
        decay_anchor,
        delisted,
        established_last_seen,
        prev_aggressive_earned_at,
        prev_standard_earned_at,
    );

    // Step 7: the listing clocks. An established event that adds its weight and leaves the
    // address eligible and holding a tier has earned that tier as of the anchor it was derived
    // at. One that leaves it below the tier changes neither clock, so a listing runs its full TTL
    // from the last time it was earned: a weak event cannot end it early, and nothing but earning
    // the tier again can extend it. An event that adds nothing earns nothing either: a repeat
    // inside the dedup window, or an overflow summary, which proves nothing about the address it
    // names.
    //
    // A clock never moves back. The anchor does not move back either, but a row can carry a
    // clock ahead of its anchor: before the anchor was a running maximum it was the time of the
    // last event read, and migration 0027 seeds the clocks from the latest established sighting,
    // which on a row whose events were read out of order is later than that. Earning the tier
    // at such an anchor keeps the later clock.
    if !deduped && !unattributed && next.recommended_for_vendor {
        let held = Some(next.decay_anchor);
        match next.tier {
            Some(FeedTier::Aggressive) => {
                next.aggressive_earned_at = next.aggressive_earned_at.max(held);
            }
            Some(FeedTier::Standard) => next.standard_earned_at = next.standard_earned_at.max(held),
            None => {}
        }
    }
    next
}

/// Whether the event's source address is proven: it came over a completed TCP connection, which
/// a sender cannot finish from an address it does not hold. A UDP or ICMP datagram carries
/// whatever source its sender wrote.
pub(crate) fn is_established(event: &EventInput) -> bool {
    event.protocol == Protocol::Tcp
}

/// Record a forgeable sighting: the event is counted (`event_count`), dated (`last_seen`, and
/// `first_seen` when it opens the row) and its sensor noted (`distinct_sensor_count`). Nothing
/// else moves. The score, its anchor, the category breakdown, the confirmed-real latch, the
/// active days, every derived flag and the listing clocks are returned exactly as stored, with
/// no decay step and no re-derivation: anyone can send a datagram under any address, so it must
/// not be able to raise that address's score, change its tier, end its listing, or keep it
/// listed or reported.
///
/// A row such a sighting opens holds a zero score, no active day and no tier. Its `decay_anchor`
/// and `last_active_day` are placeholders: the first established event starts the row over
/// ([`apply_event`]), so a history scores the same with its forgeable sightings removed.
fn record_sighting(
    prev: Option<IpScore>,
    event: &EventInput,
    distinct_wan_count: i32,
    distinct_sensor_count: i32,
) -> IpScore {
    let now = event.observed_at;
    let represented = represented_events(event);
    match prev {
        Some(mut score) => {
            score.event_count = score.event_count.saturating_add(represented);
            score.last_seen = std::cmp::max(now, score.last_seen);
            score.distinct_sensor_count = distinct_sensor_count;
            score
        }
        None => IpScore {
            source_ip: event.source_ip,
            raw_score: dec!(0),
            decay_anchor: now,
            max_confidence: dec!(0),
            event_count: represented,
            established_event_count: 0,
            distinct_categories: 0,
            category_breakdown: serde_json::to_value(BTreeMap::<Category, CategoryStat>::new())
                .expect("an empty CategoryStat map serializes to JSON"),
            has_confirmed_real: false,
            distinct_wan_count,
            distinct_sensor_count,
            active_days: 0,
            last_active_day: now.date_naive(),
            first_seen: now,
            last_seen: now,
            eligible: false,
            recommended_for_vendor: false,
            recommended_for_blocklist: false,
            tier: None,
            delisted: false,
            established_last_seen: None,
            aggressive_earned_at: None,
            standard_earned_at: None,
        },
    }
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
/// else (other signals, the overflow and per-network summaries, which stand for many addresses
/// and carry `overflow_summary: true`), and a summary whose
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
    established_last_seen: Option<DateTime<Utc>>,
    aggressive_earned_at: Option<DateTime<Utc>>,
    standard_earned_at: Option<DateTime<Utc>>,
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

    // Established events only: a forged datagram must not be the second sighting of an address
    // that authenticated once.
    let is_eligible = eligible(
        has_confirmed_real,
        established_event_count as u32,
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
    // Recency is measured from the last ESTABLISHED sighting for the same reason: `last_seen`
    // moves on any datagram naming the address.
    let seconds_since_established =
        established_last_seen.map(|seen| (decay_anchor - seen).num_seconds());
    let rec_blocklist = recommended_for_blocklist(is_eligible, effective)
        || recommended_by_volume(
            delisted,
            established_event_count as u32,
            seconds_since_established,
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
        established_last_seen,
        aggressive_earned_at,
        standard_earned_at,
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
        stored.established_last_seen,
        stored.aggressive_earned_at,
        stored.standard_earned_at,
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
            let e = tcp_probe_event_at(start + Duration::days(d));
            acc = Some(apply_event(acc, &e, HALF_LIFE, false, 1, 1));
        }
        let s = acc.unwrap();
        assert_eq!(s.active_days, 90);
        assert_eq!(s.tier, None);
        assert!(!s.recommended_for_vendor);
    }

    // ---- Forgeable sightings and the listing clocks ----------------------------------------

    const ATTACKER: &str = "203.0.113.7";

    fn event_at(
        signal: SignalType,
        protocol: Protocol,
        authenticated: bool,
        when: DateTime<Utc>,
    ) -> EventInput {
        EventInput::from_signal(
            ATTACKER.parse().unwrap(),
            None,
            "sensor-a".into(),
            signal,
            protocol,
            authenticated,
            when,
            serde_json::json!({}),
            None,
        )
    }

    /// An authenticated upload (80) and a command (60) a minute apart: capped at 100 with
    /// confidence 0.98, two established events, confirmed real. Aggressive, earned at `t + 1 min`.
    fn aggressive_at(t: DateTime<Utc>) -> IpScore {
        let upload = event_at(SignalType::HoneypotMalwareUpload, Protocol::Tcp, true, t);
        let command = event_at(
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            t + Duration::minutes(1),
        );
        let s = apply_event(None, &upload, HALF_LIFE, false, 1, 1);
        let s = apply_event(Some(s), &command, HALF_LIFE, false, 1, 1);
        assert_eq!(s.tier, Some(FeedTier::Aggressive));
        assert!(s.eligible && s.recommended_for_vendor);
        s
    }

    fn datagram_at(when: DateTime<Utc>) -> EventInput {
        // What one forged packet at the DNS or TFTP listener produces: weight 40, conf 0.90.
        event_at(SignalType::HoneypotConnection, Protocol::Udp, false, when)
    }

    #[test]
    fn a_forgeable_sighting_is_counted_and_dated_and_changes_nothing_else() {
        let t = ts("2026-09-01T00:00:00Z");
        let listed = aggressive_at(t);
        // Twelve hours on the score has decayed to a quarter. Re-derived here, the row would lose
        // its tier; given the datagram's 40 points it would be worth 65.
        let later = t + Duration::hours(12);
        let after = apply_event(
            Some(listed.clone()),
            &datagram_at(later),
            HALF_LIFE,
            false,
            1,
            3,
        );

        let expected = IpScore {
            event_count: listed.event_count + 1,
            last_seen: later,
            distinct_sensor_count: 3,
            ..listed.clone()
        };
        assert_eq!(after, expected);
        assert_eq!(
            after.raw_score, listed.raw_score,
            "no decay step, no weight"
        );
        assert_eq!(after.decay_anchor, listed.decay_anchor);
        assert_eq!(
            after.tier,
            Some(FeedTier::Aggressive),
            "the stored tier is not re-derived"
        );
        assert_eq!(after.established_last_seen, listed.established_last_seen);
        assert_eq!(after.aggressive_earned_at, listed.aggressive_earned_at);

        // ICMP is no more a proof of source than UDP.
        let icmp = event_at(SignalType::PortScan, Protocol::Icmp, false, later);
        let after_icmp = apply_event(Some(listed.clone()), &icmp, HALF_LIFE, false, 1, 3);
        assert_eq!(after_icmp, expected);
    }

    #[test]
    fn a_row_opened_by_a_forgeable_sighting_holds_no_score_no_day_and_no_tier() {
        let t = ts("2026-09-01T00:00:00Z");
        let s = apply_event(None, &datagram_at(t), HALF_LIFE, false, 0, 1);
        assert_eq!(s.event_count, 1);
        assert_eq!((s.first_seen, s.last_seen), (t, t));
        assert_eq!(s.raw_score, dec!(0));
        assert_eq!(s.category_breakdown, serde_json::json!({}));
        assert_eq!(s.distinct_categories, 0);
        assert_eq!(s.max_confidence, dec!(0));
        assert_eq!(s.established_event_count, 0);
        assert_eq!(s.active_days, 0);
        assert_eq!(s.tier, None);
        assert!(!s.has_confirmed_real && !s.eligible);
        assert!(!s.recommended_for_vendor && !s.recommended_for_blocklist);
        assert_eq!(s.established_last_seen, None);
        assert_eq!(s.tier_earned_at(), None);

        // A thousand more change only the count and the date.
        let mut acc = s.clone();
        for i in 1..=1000 {
            let e = datagram_at(t + Duration::seconds(i * 61));
            acc = apply_event(Some(acc), &e, HALF_LIFE, false, 0, 1);
        }
        let expected = IpScore {
            event_count: 1001,
            last_seen: t + Duration::seconds(61_000),
            ..s
        };
        assert_eq!(acc, expected);
        // And a read projected to now derives nothing from them either.
        let read = project_to_now(acc, t + Duration::days(1), HALF_LIFE);
        assert!(!read.recommended_for_blocklist && read.tier.is_none());
    }

    #[test]
    fn datagrams_on_ninety_days_add_no_active_day() {
        // Persistence points are added to the score the tiers gate on, so a day only a forged
        // datagram marks must not count.
        let start = ts("2026-01-01T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for d in 0..90 {
            let e = datagram_at(start + Duration::days(d));
            acc = Some(apply_event(acc, &e, HALF_LIFE, false, 0, 1));
        }
        let s = acc.unwrap();
        assert_eq!(s.active_days, 0);
        // The first connection then opens day one, on its own date.
        let first = event_at(
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            false,
            start + Duration::days(90),
        );
        let s = apply_event(Some(s), &first, HALF_LIFE, false, 0, 1);
        assert_eq!(s.active_days, 1);
        assert_eq!(s.last_active_day, (start + Duration::days(90)).date_naive());
    }

    #[test]
    fn a_datagram_is_not_the_second_sighting_eligibility_asks_for() {
        let t = ts("2026-09-01T00:00:00Z");
        let upload = event_at(SignalType::HoneypotMalwareUpload, Protocol::Tcp, true, t);
        let s = apply_event(None, &upload, HALF_LIFE, false, 1, 1);
        assert!(s.has_confirmed_real);
        assert!(!s.eligible, "one established event is one sighting");

        let s = apply_event(
            Some(s),
            &datagram_at(t + Duration::minutes(5)),
            HALF_LIFE,
            false,
            1,
            1,
        );
        assert_eq!(s.event_count, 2);
        assert!(!s.eligible, "a forged datagram must not make it two");
        assert!(!s.recommended_for_vendor);
        assert_eq!(s.tier_earned_at(), None);

        let command = event_at(
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            t + Duration::minutes(6),
        );
        let s = apply_event(Some(s), &command, HALF_LIFE, false, 1, 1);
        assert!(s.eligible, "a second connection does");
        assert_eq!(s.aggressive_earned_at, Some(t + Duration::minutes(6)));
    }

    #[test]
    fn a_weak_event_neither_ends_nor_extends_what_was_earned() {
        let t = ts("2026-09-01T00:00:00Z");
        let listed = aggressive_at(t);
        let earned = t + Duration::minutes(1);
        assert_eq!(listed.aggressive_earned_at, Some(earned));
        assert_eq!(listed.standard_earned_at, None);

        // Twelve hours later one real, low-weight probe: 25 left of the score, plus 20.
        let weak = event_at(
            SignalType::PortScan,
            Protocol::Tcp,
            false,
            t + Duration::hours(12),
        );
        let after = apply_event(Some(listed), &weak, HALF_LIFE, false, 1, 1);
        assert_eq!(after.tier, None, "the stored tier is what this event left");
        assert!(!after.recommended_for_vendor);
        assert_eq!(
            after.aggressive_earned_at,
            Some(earned),
            "the listing clock is neither cleared nor advanced"
        );
        assert_eq!(after.established_last_seen, Some(t + Duration::hours(12)));
    }

    #[test]
    fn earning_a_tier_again_advances_its_clock_and_each_tier_keeps_its_own() {
        let t = ts("2026-09-01T00:00:00Z");
        let listed = aggressive_at(t);

        // Four hours later: 63 left, plus a probe's 20 is 83. Standard, not aggressive.
        let at_standard = t + Duration::hours(4);
        let probe = event_at(SignalType::PortScan, Protocol::Tcp, false, at_standard);
        let s = apply_event(Some(listed), &probe, HALF_LIFE, false, 1, 1);
        assert_eq!(s.tier, Some(FeedTier::Standard));
        assert_eq!(s.aggressive_earned_at, Some(t + Duration::minutes(1)));
        assert_eq!(s.standard_earned_at, Some(at_standard));
        assert_eq!(s.tier_earned_at(), Some(at_standard));

        // An upload five minutes on takes it back over 90: aggressive is earned again, and the
        // standard clock stays where it was.
        let at_aggressive = at_standard + Duration::minutes(5);
        let upload = event_at(
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            at_aggressive,
        );
        let s = apply_event(Some(s), &upload, HALF_LIFE, false, 1, 1);
        assert_eq!(s.tier, Some(FeedTier::Aggressive));
        assert_eq!(s.aggressive_earned_at, Some(at_aggressive));
        assert_eq!(s.standard_earned_at, Some(at_standard));
    }

    #[test]
    fn a_repeat_inside_the_dedup_window_adds_nothing_and_earns_nothing() {
        // The score still clears the tier when the repeat arrives, but the repeat added nothing
        // to it: a listing is extended by evidence, not by a sample of what is already counted.
        let t = ts("2026-09-01T00:00:00Z");
        let listed = aggressive_at(t);
        let again = event_at(
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            t + Duration::minutes(2),
        );
        let s = apply_event(Some(listed), &again, HALF_LIFE, true, 1, 1);
        assert_eq!(s.tier, Some(FeedTier::Aggressive));
        assert_eq!(s.aggressive_earned_at, Some(t + Duration::minutes(1)));
        assert_eq!(s.established_last_seen, Some(t + Duration::minutes(2)));
    }

    #[test]
    fn a_row_scored_only_by_datagrams_starts_over_at_its_first_connection() {
        // A row as an earlier version left it: scored, dated and given active days by datagrams
        // alone. None of that may be what a connection builds on.
        let t = ts("2026-09-01T00:00:00Z");
        let legacy = IpScore {
            raw_score: dec!(95),
            category_breakdown: serde_json::json!({
                "honeypot": { "weight": "95", "max_confidence": "0.900" },
            }),
            max_confidence: dec!(0.900),
            distinct_categories: 1,
            decay_anchor: t,
            event_count: 400,
            active_days: 9,
            last_active_day: t.date_naive(),
            first_seen: t - Duration::days(9),
            last_seen: t,
            tier: Some(FeedTier::Standard),
            ..apply_event(None, &datagram_at(t), HALF_LIFE, false, 0, 1)
        };
        assert_eq!(legacy.established_event_count, 0);

        let login = event_at(
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
            t + Duration::minutes(5),
        );
        let after = apply_event(Some(legacy), &login, HALF_LIFE, false, 1, 1);
        let alone = apply_event(None, &login, HALF_LIFE, false, 1, 1);
        let expected = IpScore {
            event_count: 401,
            first_seen: t - Duration::days(9),
            ..alone
        };
        assert_eq!(after, expected);
        assert_eq!(
            after.raw_score,
            dec!(50),
            "the login's own weight and nothing under it"
        );
        assert_eq!(after.active_days, 1);
        assert_eq!(after.tier, None);
    }

    #[test]
    fn an_overflow_summary_earns_nothing() {
        // It names the first address it folded and proves nothing about that address, so it must
        // not renew a listing however high the stored score still is.
        let t = ts("2026-09-01T00:00:00Z");
        let listed = aggressive_at(t);
        let overflow = EventInput::from_signal(
            ATTACKER.parse().unwrap(),
            None,
            "vnc".into(),
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            false,
            t + Duration::minutes(10),
            serde_json::json!({
                "event_summary": true, "overflow_summary": true, "suppressed_count": 5000,
            }),
            None,
        );
        let s = apply_event(Some(listed), &overflow, HALF_LIFE, false, 1, 1);
        assert_eq!(
            s.tier,
            Some(FeedTier::Aggressive),
            "the score is still there"
        );
        assert_eq!(s.aggressive_earned_at, Some(t + Duration::minutes(1)));
    }

    #[test]
    fn a_delisted_address_earns_nothing() {
        let t = ts("2026-09-01T00:00:00Z");
        let mut delisted = aggressive_at(t);
        delisted.delisted = true;
        delisted.aggressive_earned_at = None;
        let upload = event_at(
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            t + Duration::minutes(30),
        );
        let s = apply_event(Some(delisted), &upload, HALF_LIFE, false, 1, 1);
        assert!(!s.eligible);
        assert_eq!(s.tier_earned_at(), None);
    }

    #[test]
    fn a_late_event_earns_as_of_the_anchor_and_not_of_its_own_time() {
        let t = ts("2026-09-01T00:00:00Z");
        let listed = aggressive_at(t);
        // Twelve hours on, a weak probe: 25 left of the score plus 20, no tier. It moves the
        // anchor and leaves the clock where the tier was last earned.
        let anchor = t + Duration::hours(12);
        let weak = event_at(SignalType::PortScan, Protocol::Tcp, false, anchor);
        let s = apply_event(Some(listed), &weak, HALF_LIFE, false, 1, 1);
        assert_eq!(s.tier, None);
        assert_eq!(s.aggressive_earned_at, Some(t + Duration::minutes(1)));

        // An upload from an hour before the anchor, read late: worth 71 at the anchor, which
        // takes the score back over 90. The row is derived at the anchor, so that is when the
        // tier is held: not the line's own time, and not the time it was earned before.
        let late = event_at(
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            anchor - Duration::hours(1),
        );
        let s = apply_event(Some(s), &late, HALF_LIFE, false, 1, 1);
        assert_eq!(s.tier, Some(FeedTier::Aggressive));
        assert_eq!(s.decay_anchor, anchor);
        assert_eq!(s.aggressive_earned_at, Some(anchor));
        assert_eq!(s.established_last_seen, Some(anchor), "a running maximum");
    }

    #[test]
    fn a_clock_ahead_of_the_anchor_is_not_moved_back() {
        // What migration 0027 leaves on a row an earlier version read out of order: the anchor
        // is the time of the last event read, the clock the latest established sighting.
        let t = ts("2026-09-01T00:00:00Z");
        let mut listed = aggressive_at(t);
        let seeded = t + Duration::minutes(10);
        listed.established_last_seen = Some(seeded);
        listed.aggressive_earned_at = Some(seeded);
        assert_eq!(listed.decay_anchor, t + Duration::minutes(1));

        // A lagging sensor's upload from between the two earns the tier at its own time, which
        // is now the anchor and is still behind the clock.
        let between = t + Duration::minutes(2);
        let upload = event_at(
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            between,
        );
        let s = apply_event(Some(listed), &upload, HALF_LIFE, false, 1, 1);
        assert_eq!(s.tier, Some(FeedTier::Aggressive));
        assert!(s.recommended_for_vendor);
        assert_eq!(s.decay_anchor, between);
        assert_eq!(
            s.aggressive_earned_at,
            Some(seeded),
            "earning the tier again cannot shorten the listing it already has"
        );
    }

    #[test]
    fn a_datagram_cannot_make_an_earlier_connection_count_as_late() {
        // The datagram is read first and opens the row; the connection, from ten hours before
        // it, is read after. Anchored at the datagram the connection would be worth a third of
        // its weight. It must score as if the datagram had never been sent.
        let t = ts("2026-09-01T00:00:00Z");
        let command = event_at(SignalType::HoneypotCommandExec, Protocol::Tcp, true, t);
        let alone = apply_event(None, &command, HALF_LIFE, false, 1, 1);

        let opened = apply_event(
            None,
            &datagram_at(t + Duration::hours(10)),
            HALF_LIFE,
            false,
            1,
            1,
        );
        let after = apply_event(Some(opened), &command, HALF_LIFE, false, 1, 1);
        assert_eq!(after.raw_score, dec!(60));
        assert_eq!(after.decay_anchor, t);
        let expected = IpScore {
            event_count: 2,
            first_seen: t + Duration::hours(10),
            last_seen: t + Duration::hours(10),
            ..alone
        };
        assert_eq!(after, expected);
    }

    #[test]
    fn volume_recency_is_measured_from_the_last_connection_not_the_last_datagram() {
        let threshold = crate::scoring::constants::VOLUME_LIST_THRESHOLD as i64;
        let base = ts("2026-08-21T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for i in 0..threshold {
            let e = tcp_probe_event_at(base + Duration::seconds(i));
            acc = Some(apply_event(acc, &e, HALF_LIFE, i > 0, 1, 1));
        }
        let flood = acc.unwrap();
        let stopped = base + Duration::seconds(threshold - 1);
        assert_eq!(flood.established_last_seen, Some(stopped));
        assert!(flood.recommended_for_blocklist);

        // Thirty hours after the flood stopped, a datagram names the address.
        let named = stopped + Duration::hours(30);
        let s = apply_event(
            Some(flood),
            &udp_probe_event_at(named),
            HALF_LIFE,
            false,
            1,
            1,
        );
        assert_eq!(s.last_seen, named);
        assert_eq!(s.established_last_seen, Some(stopped));
        let read = project_to_now(s, named + Duration::minutes(1), HALF_LIFE);
        assert!(
            !read.recommended_for_blocklist,
            "a flood that stopped more than a day ago is not kept listed by a datagram"
        );
    }

    proptest! {
        /// The rule in one property: take any history, remove every forgeable sighting, and the
        /// address scores exactly the same. Only the record of having been named differs.
        #[test]
        fn a_history_scores_the_same_with_its_forgeable_sightings_removed(
            steps in prop::collection::vec(
                (0usize..6, any::<bool>(), 0i64..200_000, any::<bool>()),
                1..40,
            )
        ) {
            const SIGNALS: [SignalType; 6] = [
                SignalType::HoneypotMalwareUpload,
                SignalType::HoneypotCommandExec,
                SignalType::HoneypotLoginAttempt,
                SignalType::HoneypotConnection,
                SignalType::CatchallProbe,
                SignalType::PortScan,
            ];
            let base = ts("2026-09-01T00:00:00Z");
            // Times are drawn independently of position, so the history is read out of order.
            let events: Vec<EventInput> = steps
                .iter()
                .map(|&(signal, forgeable, at, authenticated)| {
                    let protocol = if forgeable { Protocol::Udp } else { Protocol::Tcp };
                    event_at(SIGNALS[signal], protocol, authenticated, base + Duration::seconds(at))
                })
                .collect();
            let fold = |events: &[&EventInput]| {
                events.iter().fold(None, |acc: Option<IpScore>, e| {
                    Some(apply_event(acc, e, HALF_LIFE, false, 1, 1))
                })
            };
            let all: Vec<&EventInput> = events.iter().collect();
            let established: Vec<&EventInput> =
                events.iter().filter(|e| is_established(e)).collect();
            let with = fold(&all).expect("at least one event");
            match fold(&established) {
                Some(without) => {
                    let expected = IpScore {
                        event_count: with.event_count,
                        first_seen: with.first_seen,
                        last_seen: with.last_seen,
                        ..without
                    };
                    prop_assert_eq!(with, expected);
                }
                None => {
                    prop_assert_eq!(with.raw_score, dec!(0));
                    prop_assert_eq!(with.active_days, 0);
                    prop_assert!(with.tier.is_none() && !with.eligible);
                    prop_assert!(!with.recommended_for_blocklist);
                    prop_assert_eq!(with.established_last_seen, None);
                    prop_assert_eq!(with.tier_earned_at(), None);
                }
            }
        }
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

    /// An event dated before what is already stored is still a sighting (it counts, and adds what
    /// its age leaves of its weight) but it moves neither `last_seen` nor the decay anchor back,
    /// and it does not rewrite `first_seen` either.
    #[test]
    fn an_older_event_counts_and_weighs_by_its_age_but_moves_neither_last_seen_nor_the_anchor_back()
    {
        let seen = ts("2026-11-01T12:00:00Z");
        let s1 = apply_event(None, &command_exec_at(seen), HALF_LIFE, false, 1, 1);
        assert_eq!(s1.raw_score, dec!(60));

        // One half-life back, another category (port_scan, weight 20) so the weight is visible:
        // read in order it would have decayed to half by the time of the event already stored.
        let mut old = tcp_probe_event_at(seen - Duration::seconds(HALF_LIFE));
        old.source_ip = s1.source_ip;
        let s2 = apply_event(Some(s1.clone()), &old, HALF_LIFE, false, 1, 1);
        assert_eq!(s2.last_seen, seen);
        assert_eq!(s2.decay_anchor, seen);
        assert_eq!(s2.first_seen, seen, "first_seen is the first event folded");
        assert_eq!(s2.event_count, 2);
        assert_eq!(s2.established_event_count, 2);
        assert_eq!(
            s2.raw_score,
            dec!(70),
            "what was stored has not decayed; the older event adds half its weight"
        );
        assert_eq!(s2.distinct_categories, 2);
        assert_eq!(
            s2.active_days, 1,
            "an older day does not open a new active day"
        );

        // A duplicate sighting from the past changes the counters and nothing else.
        let s3 = apply_event(Some(s2.clone()), &old, HALF_LIFE, true, 1, 1);
        assert_eq!(
            (s3.last_seen, s3.decay_anchor, s3.raw_score),
            (seen, seen, dec!(70))
        );
        assert_eq!(s3.event_count, 3);
    }

    /// A whole session read late is worth what it would have been worth read in order. One log
    /// read eleven days behind another (an outage, a drained backlog) used to add every event of
    /// it at full weight as of the newest sighting, which made a session from last week a
    /// current top-tier address. Folded in either order, the score is the same.
    #[test]
    fn a_session_read_late_scores_what_it_would_have_scored_read_in_order() {
        let now = ts("2026-11-12T12:00:00Z");
        let then = now - Duration::days(11);
        let probe = tcp_probe_event_at(now);
        let session: Vec<EventInput> = (0..4)
            .map(|i| {
                let mut e = command_exec_at(then + Duration::seconds(i * 120));
                e.source_ip = probe.source_ip;
                e
            })
            .collect();

        let mut in_order: Option<IpScore> = None;
        for e in session.iter().chain(std::iter::once(&probe)) {
            in_order = Some(apply_event(in_order, e, HALF_LIFE, false, 1, 1));
        }
        let mut late: Option<IpScore> = None;
        for e in std::iter::once(&probe).chain(session.iter()) {
            late = Some(apply_event(late, e, HALF_LIFE, false, 1, 1));
        }
        let (in_order, late) = (in_order.unwrap(), late.unwrap());

        assert_eq!(late.last_seen, now);
        assert_eq!(late.decay_anchor, now);
        assert!(
            (late.raw_score - in_order.raw_score).abs() < dec!(0.001),
            "late {} against in order {}",
            late.raw_score,
            in_order.raw_score
        );
        assert!(
            late.raw_score < dec!(21),
            "eleven days is forty-four half-lives: {}",
            late.raw_score
        );
        assert_eq!(late.tier, in_order.tier);
        assert_eq!(late.tier, None, "one probe today is not a listing");
        assert_eq!(late.event_count, in_order.event_count);
    }

    /// Security regression (audit): one line dated years back must not erase an address's score.
    /// It used to become the decay anchor, so the next real event (and every read) decayed the
    /// whole accumulation across those years, to nothing. The next event must decay from the
    /// true anchor: one hour on, the earlier weight is still there.
    #[test]
    fn a_back_dated_line_does_not_wipe_the_score_at_the_next_event_or_read() {
        let seen = ts("2026-11-01T12:00:00Z");
        let s1 = apply_event(None, &command_exec_at(seen), HALF_LIFE, false, 1, 1);
        let back_dated = command_exec_at(seen - Duration::days(3 * 365));
        let s2 = apply_event(Some(s1), &back_dated, HALF_LIFE, true, 1, 1);
        assert_eq!(s2.raw_score, dec!(60));

        let hour_later = seen + Duration::hours(1);
        let kept = decay(dec!(60), 3600, HALF_LIFE);
        assert!(kept > dec!(53), "one hour of a six-hour half-life: {kept}");

        // The read path projects from the stored anchor.
        let read = project_to_now(s2.clone(), hour_later, HALF_LIFE);
        assert_eq!(read.raw_score, kept);
        assert_eq!(read.last_seen, seen);

        // The next event decays from the true anchor, then becomes the anchor itself.
        let mut next = tcp_probe_event_at(hour_later);
        next.source_ip = s2.source_ip;
        let s3 = apply_event(Some(s2), &next, HALF_LIFE, false, 1, 1);
        assert_eq!(s3.raw_score, kept + dec!(20));
        assert_eq!(s3.decay_anchor, hour_later);
        assert_eq!(s3.last_seen, hour_later);
        assert_eq!(s3.event_count, 3);
    }

    /// A volume listing is published while `last_seen` is inside a feed window, so a back-dated
    /// line must not be able to take a listed address out of it.
    #[test]
    fn a_back_dated_line_does_not_move_a_volume_listed_address_out_of_its_window() {
        let threshold = crate::scoring::constants::VOLUME_LIST_THRESHOLD as i64;
        let base = ts("2026-08-21T00:00:00Z");
        let mut acc: Option<IpScore> = None;
        for i in 0..threshold {
            let e = tcp_probe_event_at(base + Duration::seconds(i));
            acc = Some(apply_event(acc, &e, HALF_LIFE, i > 0, 1, 1));
        }
        let listed = acc.unwrap();
        assert!(listed.recommended_for_blocklist);
        let newest = base + Duration::seconds(threshold - 1);
        assert_eq!(listed.last_seen, newest);

        let back_dated = tcp_probe_event_at(base - Duration::days(400));
        let after = apply_event(Some(listed), &back_dated, HALF_LIFE, false, 1, 1);
        assert_eq!(after.last_seen, newest);
        assert_eq!(after.decay_anchor, newest);
        assert!(after.recommended_for_blocklist);
    }

    proptest! {
        /// Whatever order events are folded in, `last_seen` and the anchor end at the latest
        /// time among them and never step back on the way; `first_seen` stays the first folded.
        #[test]
        fn last_seen_and_the_anchor_are_the_latest_time_folded_in_any_order(
            offsets in prop::collection::vec(-2_000_000i64..2_000_000i64, 1..24usize),
            deduped in prop::collection::vec(any::<bool>(), 24),
        ) {
            let base = ts("2026-06-01T00:00:00Z");
            let mut acc: Option<IpScore> = None;
            let mut latest: Option<DateTime<Utc>> = None;
            for (offset, deduped) in offsets.iter().zip(deduped) {
                let when = base + Duration::seconds(*offset);
                latest = Some(latest.map_or(when, |l| l.max(when)));
                let next = apply_event(acc.clone(), &command_exec_at(when), HALF_LIFE, deduped, 1, 1);
                if let Some(prev) = &acc {
                    prop_assert!(next.last_seen >= prev.last_seen);
                    prop_assert!(next.decay_anchor >= prev.decay_anchor);
                    prop_assert!(next.raw_score >= decay(
                        prev.raw_score,
                        (next.decay_anchor - prev.decay_anchor).num_seconds(),
                        HALF_LIFE,
                    ));
                }
                prop_assert_eq!(Some(next.last_seen), latest);
                prop_assert_eq!(Some(next.decay_anchor), latest);
                prop_assert_eq!(next.first_seen, base + Duration::seconds(offsets[0]));
                acc = Some(next);
            }
        }

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
