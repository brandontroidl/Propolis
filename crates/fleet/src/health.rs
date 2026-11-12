//! The fail-closed rules. Pure functions, no I/O, so the invariants that decide whether an
//! operator is told "fine" can be tested exhaustively and mutated one at a time.
//!
//! Every rule here leans the same way: **the absence of evidence is never health.** A monitoring
//! page that renders its own failure as good news is worse than no page, because it converts an
//! unknown into a false assurance and the operator stops looking.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::store::{ProbeOutcome, ProbeRow};

/// A listener has been quiet long enough to be worth a glance. Not an alarm: a honeypot listener
/// with no traffic for a day is common and proves nothing is broken, so this is the weakest signal
/// the pane emits, and it never outranks a real reachability failure.
const EVENT_QUIET_AFTER: chrono::TimeDelta = chrono::TimeDelta::hours(24);

/// The state of one check, and of a row or a page once [`combine`]d.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Alarm,
    Unknown,
}

impl Level {
    /// The CSS state class the templates key on. Kept semantic rather than presentational so a
    /// theme change cannot silently invert what a state means.
    pub fn class(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Alarm => "alarm",
            Level::Unknown => "unknown",
        }
    }

    /// How bad this state is. `Unknown` outranks `Warn` on purpose: an unmeasured check is a
    /// stronger reason to look than a measured one that came back merely soft.
    fn rank(self) -> u8 {
        match self {
            Level::Ok => 0,
            Level::Warn => 1,
            Level::Unknown => 2,
            Level::Alarm => 3,
        }
    }
}

/// The reachability verdict for one listener, from its stored probe row (or the absence of one).
///
/// Rule order matters and is the whole content of the function:
/// 1. No row at all: never probed, so `Unknown`.
/// 2. A row older than two sweep intervals: `Alarm`, whatever it says. A prober that died leaves
///    its last-known-good result on screen forever otherwise.
/// 3. A failed connect: `Alarm`. `refused` and `timeout` both alarm, and the stored `detail`
///    keeps them apart for diagnosis (`refused` means the path works and nothing is listening;
///    `timeout` means the packet was dropped).
/// 4. UDP, which a connect cannot decide: `Unknown`, never green.
/// 5. Reachable AND recently confirmed at intake: `Ok`. This is the only path to `Ok`.
/// 6. Reachable without a recent confirmation: `Warn`. The socket answered but nothing reached the
///    far end, which localizes the break to the log, shipper, gateway or intake path.
pub fn reach_level(row: Option<&ProbeRow>, now: DateTime<Utc>, interval: Duration) -> Level {
    let Some(row) = row else {
        return Level::Unknown;
    };
    let window = chrono::Duration::from_std(interval.saturating_mul(2))
        .unwrap_or_else(|_| chrono::Duration::seconds(0));
    if row.attempted_at < now - window {
        return Level::Alarm;
    }
    match row.outcome {
        ProbeOutcome::Refused | ProbeOutcome::Timeout | ProbeOutcome::Error => Level::Alarm,
        ProbeOutcome::NotProbeable => Level::Unknown,
        ProbeOutcome::Reachable => match row.confirmed_at {
            Some(confirmed) if confirmed >= now - window => Level::Ok,
            _ => Level::Warn,
        },
    }
}

/// The liveness verdict from a listener's most recent event.
///
/// Evidence of traffic is evidence of life; the absence of traffic is not evidence of death, so
/// the worst this returns for a configured, long-quiet listener is `Warn`. A listener that has
/// NEVER produced an event is `Unknown` rather than `Warn`: a brand-new node must not claim health
/// it has not shown, and a unit that was never enabled looks exactly like this.
pub fn event_age_level(last_event: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Level {
    match last_event {
        None => Level::Unknown,
        Some(seen) if now - seen < EVENT_QUIET_AFTER => Level::Ok,
        Some(_) => Level::Warn,
    }
}

/// The one sentence the fleet page leads with, chosen from what the two checks ACTUALLY say.
///
/// `reach` is the worst reachability verdict across the inventory and `events` the worst event-age
/// verdict; the dot beside the sentence is [`combine`]d from the same pair. The two are kept apart
/// here because they fail for unrelated reasons and folding them into one severity loses which one
/// it was: a fleet whose listeners are all probed and confirmed, one of which has simply been
/// quiet for a day, combines to `Warn` - and a sentence written for `Warn` alone then tells the
/// operator the evidence path is unconfirmed, which is the opposite of what the probes proved and
/// sends them to debug a shipper that is working.
///
/// Reachability is stated first when both have something to say: it is the more actionable of the
/// two, and a listener that is not answering makes its event age uninteresting.
pub fn headline(reach: Level, events: Level) -> &'static str {
    match (reach, events) {
        (Level::Alarm, _) => "a listener is not answering",
        (Level::Unknown, _) => "reachability unproven",
        (Level::Warn, _) => "listeners answering, evidence path unconfirmed",
        // Reachability is proven from here on, so anything left to say is about traffic - and
        // quiet is not a fault. Both of these read as "nothing is broken, here is what is thin".
        (Level::Ok, Level::Unknown) => "every listener proven, one has produced no events yet",
        (Level::Ok, Level::Warn) => "every listener proven, one has been quiet over a day",
        (Level::Ok, Level::Ok) | (Level::Ok, Level::Alarm) => "every listener proven",
    }
}

/// Worst wins, and an empty slice is `Unknown`.
///
/// The empty case is the one that matters: an inventory nobody configured has no checks to fail,
/// and folding that into `Ok` would let an unconfigured console report a healthy fleet.
pub fn combine(levels: &[Level]) -> Level {
    levels
        .iter()
        .copied()
        .max_by_key(|l| l.rank())
        .unwrap_or(Level::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Listener, Proto};

    fn listener(sensor: &str, protocol: Proto, port: u16) -> Listener {
        Listener {
            collector_id: "local".into(),
            sensor: sensor.into(),
            protocol,
            port,
        }
    }

    fn row(
        outcome: ProbeOutcome,
        attempted_at: DateTime<Utc>,
        confirmed_at: Option<DateTime<Utc>>,
        detail: Option<&str>,
    ) -> ProbeRow {
        ProbeRow {
            listener: listener("ssh", Proto::Tcp, 22),
            target: "198.51.100.7:22".into(),
            attempted_at,
            outcome,
            detail: detail.map(str::to_string),
            latency_ms: None,
            confirmed_at,
        }
    }

    const INTERVAL: Duration = Duration::from_secs(300);

    #[test]
    fn a_listener_never_probed_is_unknown_not_ok() {
        assert_eq!(reach_level(None, Utc::now(), INTERVAL), Level::Unknown);
    }

    #[test]
    fn a_probe_older_than_two_intervals_is_an_alarm_even_when_the_last_outcome_was_reachable() {
        let now = Utc::now();
        let stale = row(
            ProbeOutcome::Reachable,
            now - chrono::Duration::seconds(601),
            Some(now),
            None,
        );
        assert_eq!(reach_level(Some(&stale), now, INTERVAL), Level::Alarm);

        // Just inside the window, the same row is not an alarm - the rule is the age, not the
        // outcome, and a fixture that could not tell those apart would prove nothing.
        let fresh = row(
            ProbeOutcome::Reachable,
            now - chrono::Duration::seconds(599),
            Some(now),
            None,
        );
        assert_eq!(reach_level(Some(&fresh), now, INTERVAL), Level::Ok);
    }

    #[test]
    fn refused_and_timeout_are_both_alarms_and_carry_distinct_detail() {
        let now = Utc::now();
        let refused = row(ProbeOutcome::Refused, now, None, Some("connection refused"));
        let timed_out = row(ProbeOutcome::Timeout, now, None, Some("timed out"));
        assert_eq!(reach_level(Some(&refused), now, INTERVAL), Level::Alarm);
        assert_eq!(reach_level(Some(&timed_out), now, INTERVAL), Level::Alarm);
        // Same verdict, different diagnosis: refused proves the path works and nothing is
        // listening; a timeout proves the packet never arrived. The pane must keep them apart.
        assert_ne!(refused.detail, timed_out.detail);
        assert_ne!(refused.outcome.label(), timed_out.outcome.label());
    }

    #[test]
    fn udp_is_not_probeable_and_is_never_green() {
        let now = Utc::now();
        let mut udp = row(ProbeOutcome::NotProbeable, now, Some(now), None);
        udp.listener = listener("catchall", Proto::Udp, 1024);
        // Even with a fresh confirmation, a connect proves nothing about UDP.
        assert_eq!(reach_level(Some(&udp), now, INTERVAL), Level::Unknown);
    }

    #[test]
    fn reachable_without_a_recent_confirmation_is_a_warning_not_ok() {
        let now = Utc::now();
        let never_confirmed = row(ProbeOutcome::Reachable, now, None, None);
        assert_eq!(
            reach_level(Some(&never_confirmed), now, INTERVAL),
            Level::Warn
        );

        let stale_confirmation = row(
            ProbeOutcome::Reachable,
            now,
            Some(now - chrono::Duration::seconds(601)),
            None,
        );
        assert_eq!(
            reach_level(Some(&stale_confirmation), now, INTERVAL),
            Level::Warn
        );
    }

    #[test]
    fn combine_never_returns_ok_when_any_input_is_unknown() {
        assert_eq!(combine(&[Level::Ok, Level::Unknown]), Level::Unknown);
        assert_eq!(combine(&[Level::Ok, Level::Ok]), Level::Ok);
        assert_eq!(combine(&[Level::Warn, Level::Unknown]), Level::Unknown);
        // An alarm still outranks an unknown: a measured failure is worse than an unmeasured one.
        assert_eq!(combine(&[Level::Unknown, Level::Alarm]), Level::Alarm);
    }

    #[test]
    fn an_empty_inventory_yields_an_unknown_headline_not_an_ok_one() {
        assert_eq!(combine(&[]), Level::Unknown);
    }

    #[test]
    fn a_listener_that_never_produced_an_event_is_unknown_and_a_quiet_one_is_only_a_warning() {
        let now = Utc::now();
        assert_eq!(event_age_level(None, now), Level::Unknown);
        assert_eq!(
            event_age_level(Some(now - chrono::Duration::minutes(90)), now),
            Level::Ok
        );
        assert_eq!(
            event_age_level(Some(now - chrono::Duration::hours(25)), now),
            Level::Warn
        );
    }

    /// The regression this function exists for: every listener probed AND confirmed, one of them
    /// merely quiet. The combined level is `Warn`, but saying "evidence path unconfirmed" there
    /// contradicts the confirmations the probes recorded.
    #[test]
    fn a_proven_but_quiet_fleet_is_not_reported_as_an_unconfirmed_evidence_path() {
        let line = headline(Level::Ok, Level::Warn);
        assert!(
            !line.contains("unconfirmed"),
            "reachability was proven; the headline must not deny it: {line}"
        );
        assert!(
            line.contains("quiet"),
            "the headline must name what is actually thin: {line}"
        );
        // Same for a listener that has never produced an event: unmeasured traffic, proven path.
        let never = headline(Level::Ok, Level::Unknown);
        assert!(
            !never.contains("unconfirmed") && !never.contains("reachability"),
            "a proven listener that has produced nothing yet is not a reachability finding: \
             {never}"
        );
    }

    #[test]
    fn a_real_reachability_finding_still_leads_the_headline() {
        assert_eq!(
            headline(Level::Warn, Level::Ok),
            "listeners answering, evidence path unconfirmed"
        );
        assert_eq!(
            headline(Level::Alarm, Level::Ok),
            "a listener is not answering"
        );
        assert_eq!(headline(Level::Unknown, Level::Ok), "reachability unproven");
        // Reachability outranks event age when both have something to say.
        assert_eq!(
            headline(Level::Alarm, Level::Warn),
            "a listener is not answering"
        );
        assert_eq!(
            headline(Level::Warn, Level::Unknown),
            "listeners answering, evidence path unconfirmed"
        );
    }

    #[test]
    fn only_an_all_clear_fleet_gets_the_all_clear_sentence() {
        assert_eq!(headline(Level::Ok, Level::Ok), "every listener proven");
        for reach in [Level::Warn, Level::Alarm, Level::Unknown] {
            for events in [Level::Ok, Level::Warn, Level::Alarm, Level::Unknown] {
                assert_ne!(
                    headline(reach, events),
                    "every listener proven",
                    "reach={reach:?} events={events:?} must not read as an all-clear"
                );
            }
        }
    }

    #[test]
    fn class_names_are_stable() {
        assert_eq!(Level::Ok.class(), "ok");
        assert_eq!(Level::Warn.class(), "warn");
        assert_eq!(Level::Alarm.class(), "alarm");
        assert_eq!(Level::Unknown.class(), "unknown");
    }
}
