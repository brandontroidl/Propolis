//! Condition #12: a sensor's intake is consuming its log but not keeping up with it.
//!
//! `intake-stalled` cannot see this. It fires only when the cursor stops, and in October 2026 a
//! telnet intake kept moving at about one event a second for eleven days while 6.6 GB piled up
//! behind it. Each poll publishes how many bytes of the log are unread and the `observed_at` of
//! the last event appended (`SensorIntake`); this condition pages when either says the log is
//! running away:
//!
//! - **age**: lines have waited longer than [`age_threshold`] continuously for [`AGE_HOLD`]. The
//!   wait is measured from the last appended event, which is how long the next unread line has
//!   waited at most, and is only counted while the latest poll left complete lines unread.
//! - **growth**: the unread bytes rose at each of three consecutive monitor polls, each of which
//!   found complete lines waiting. This fires within minutes, long before the age rule can.
//!
//! An idle sensor never fires: nothing unread means no age and no growth, and an unfinished last
//! line, which is unread but not waiting to be read, neither ages nor grows. Once firing, a sensor
//! clears when its log is read to the end, or when its wait is back under the threshold and its
//! backlog has not grown for three consecutive polls; the same three polls that raise the alert
//! are needed to drop it, so a backlog hovering at the edge does not page and recover in turn.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome, SensorIntake};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// The age threshold never drops below this, however fast the intake polls.
pub const AGE_FLOOR: Duration = Duration::from_secs(600);

/// How long a log must stay over the age threshold before it pages.
pub const AGE_HOLD: Duration = Duration::from_secs(600);

/// Consecutive monitor polls of rising backlog that page, and of flat or falling backlog that let
/// a firing sensor clear.
const GROWTH_POLLS: usize = 3;

/// How long the oldest unread line may wait before the log counts as behind: ten minutes, or three
/// intake polls if the intake polls slower than every 200 s, so a slow poll alone never reads as
/// lag.
pub fn age_threshold(intake_poll: Duration) -> Duration {
    AGE_FLOOR.max(intake_poll.saturating_mul(3))
}

/// How long the oldest unread line of this log has waited, as of its latest poll. Zero when that
/// poll read every complete line (bytes may still be unread: an unfinished last line, or lines
/// written since). The time since the last appended event's `observed_at` when the poll left
/// complete lines waiting. `None` when there is no reading yet, or lines are waiting but nothing
/// has been appended since the daemon started, so there is nothing to measure from.
pub fn oldest_unread_age(intake: &SensorIntake, now: DateTime<Utc>) -> Option<Duration> {
    match intake.bytes_behind? {
        0 => Some(Duration::ZERO),
        _ if !intake.backlog => Some(Duration::ZERO),
        _ => intake
            .last_ingested_observed_at
            .map(|t| (now - t).to_std().unwrap_or(Duration::ZERO)),
    }
}

/// Whether the log is behind right now: its oldest unread line has waited past `threshold`. The
/// instantaneous half of the age rule, shared with the fleet pane's badge.
pub fn is_behind(age: Option<Duration>, threshold: Duration) -> bool {
    age.is_some_and(|age| age > threshold)
}

/// One monitor poll's reading of one log.
#[derive(Debug, Clone, Copy)]
struct Reading {
    bytes_behind: u64,
    /// The latest intake poll left complete lines unread.
    backlog: bool,
    behind: bool,
}

/// What the condition remembers about one log between monitor polls.
#[derive(Debug, Default)]
struct LagTrack {
    behind_since: Option<Instant>,
    /// The last `GROWTH_POLLS + 1` readings, oldest first.
    samples: VecDeque<(u64, bool)>,
    lagging: bool,
}

/// Folds one reading into `track` and returns whether the log is lagging. Split from I/O so the
/// timing rules are tested against an injected clock.
fn step(track: &mut LagTrack, reading: Reading, now: Instant) -> bool {
    track.behind_since = if reading.behind {
        Some(track.behind_since.unwrap_or(now))
    } else {
        None
    };
    track
        .samples
        .push_back((reading.bytes_behind, reading.backlog));
    if track.samples.len() > GROWTH_POLLS + 1 {
        track.samples.pop_front();
    }
    let full = track.samples.len() == GROWTH_POLLS + 1;
    let transitions = || track.samples.iter().zip(track.samples.iter().skip(1));
    let growing = full
        && track.samples.iter().all(|&(_, backlog)| backlog)
        && transitions().all(|(before, after)| after.0 > before.0);
    let settled = full && transitions().all(|(before, after)| after.0 <= before.0);
    let held = track
        .behind_since
        .is_some_and(|since| now.duration_since(since) >= AGE_HOLD);

    if track.lagging {
        if reading.bytes_behind == 0 || (!reading.behind && settled) {
            track.lagging = false;
        }
    } else if held || growing {
        track.lagging = true;
    }
    track.lagging
}

/// #12: a sensor's intake is falling behind its log.
pub struct IntakeLagging {
    tracks: Mutex<HashMap<&'static str, LagTrack>>,
}

impl IntakeLagging {
    pub fn new() -> Self {
        Self {
            tracks: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for IntakeLagging {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Condition for IntakeLagging {
    fn id(&self) -> &'static str {
        "intake-lagging"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // The age rule's hold and the growth rule's three polls are this condition's debounce.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let now = Instant::now();
        let wall = Utc::now();
        let threshold = age_threshold(ctx.intake_poll_interval);
        let snapshot: Vec<(&'static str, SensorIntake)> = {
            let map = ctx
                .intake_progress
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.iter().map(|(name, s)| (*name, s.clone())).collect()
        };

        let mut lagging = Vec::new();
        let mut unmeasured = Vec::new();
        {
            let mut tracks = self.tracks.lock().unwrap_or_else(|p| p.into_inner());
            tracks.retain(|name, _| snapshot.iter().any(|(n, _)| n == name));
            for (name, intake) in &snapshot {
                let Some(bytes_behind) = intake.bytes_behind else {
                    unmeasured.push(*name);
                    continue;
                };
                let age = oldest_unread_age(intake, wall);
                let reading = Reading {
                    bytes_behind,
                    backlog: intake.backlog,
                    behind: is_behind(age, threshold),
                };
                if step(tracks.entry(name).or_default(), reading, now) {
                    lagging.push(format!(
                        "{name} ({})",
                        console::intake_lag::format_backlog(bytes_behind, age)
                    ));
                }
            }
        }

        if !lagging.is_empty() {
            lagging.sort_unstable();
            return Outcome::Firing {
                severity: Severity::Warning,
                detail: format!(
                    "intake falling behind its log (unread bytes / oldest unread line): {}",
                    lagging.join(", ")
                ),
            };
        }
        if !unmeasured.is_empty() {
            unmeasured.sort_unstable();
            return Outcome::Unknown {
                why: format!("no backlog reading yet from {}", unmeasured.join(", ")),
            };
        }
        Outcome::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_alert::condition::IntakeProgress;
    use crate::ops_alert::config::parse_ops_alert;
    use std::sync::Arc;

    const POLL: Duration = Duration::from_secs(30);

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    fn reading(bytes_behind: u64, backlog: bool, behind: bool) -> Reading {
        Reading {
            bytes_behind,
            backlog,
            behind,
        }
    }

    fn intake(bytes: Option<u64>, backlog: bool, last: Option<DateTime<Utc>>) -> SensorIntake {
        SensorIntake {
            last_advanced_at: Instant::now(),
            backlog,
            bytes_behind: bytes,
            last_ingested_observed_at: last,
            reported_sensors: vec!["telnet".into()],
            wedge: None,
            last_quarantine: None,
        }
    }

    #[test]
    fn the_threshold_is_ten_minutes_or_three_polls_whichever_is_longer() {
        assert_eq!(age_threshold(Duration::from_secs(1)), AGE_FLOOR);
        assert_eq!(age_threshold(Duration::from_secs(200)), AGE_FLOOR);
        assert_eq!(
            age_threshold(Duration::from_secs(300)),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn oldest_unread_age_is_only_measured_while_complete_lines_wait() {
        let now = Utc::now();
        let eleven_days_ago = now - chrono::Duration::days(11);
        assert_eq!(oldest_unread_age(&intake(None, false, None), now), None);
        assert_eq!(
            oldest_unread_age(&intake(Some(0), true, Some(eleven_days_ago)), now),
            Some(Duration::ZERO),
            "nothing unread"
        );
        assert_eq!(
            oldest_unread_age(&intake(Some(40), false, Some(eleven_days_ago)), now),
            Some(Duration::ZERO),
            "the poll read to the end; an unfinished last line is not waiting"
        );
        assert_eq!(
            oldest_unread_age(
                &intake(Some(6_600_000_000), true, Some(eleven_days_ago)),
                now
            ),
            Some(Duration::from_secs(11 * 86_400))
        );
        assert_eq!(
            oldest_unread_age(&intake(Some(4_096), true, None), now),
            None,
            "lines waiting and nothing appended yet: unknown, not zero"
        );
        assert_eq!(
            oldest_unread_age(
                &intake(Some(1), true, Some(now + chrono::Duration::hours(1))),
                now
            ),
            Some(Duration::ZERO),
            "a sensor clock ahead of ours is not negative lag"
        );
    }

    #[test]
    fn the_age_rule_fires_only_after_holding_behind_for_ten_minutes() {
        let base = Instant::now();
        let mut track = LagTrack::default();
        assert!(!step(&mut track, reading(500, true, true), base));
        assert!(!step(&mut track, reading(400, true, true), at(base, 599)));
        assert!(step(&mut track, reading(300, true, true), at(base, 600)));
    }

    #[test]
    fn a_break_in_being_behind_restarts_the_hold() {
        let base = Instant::now();
        let mut track = LagTrack::default();
        step(&mut track, reading(500, true, true), base);
        step(&mut track, reading(400, true, false), at(base, 300));
        assert!(!step(&mut track, reading(300, true, true), at(base, 600)));
        assert!(!step(&mut track, reading(250, true, true), at(base, 1_199)));
        assert!(step(&mut track, reading(200, true, true), at(base, 1_200)));
    }

    #[test]
    fn three_consecutive_rises_with_lines_waiting_fire_at_once() {
        let base = Instant::now();
        let mut track = LagTrack::default();
        assert!(!step(&mut track, reading(1_000, true, false), base));
        assert!(!step(&mut track, reading(2_000, true, false), at(base, 30)));
        assert!(!step(&mut track, reading(3_000, true, false), at(base, 60)));
        assert!(step(&mut track, reading(4_000, true, false), at(base, 90)));
    }

    #[test]
    fn rises_seen_at_polls_that_read_to_the_end_are_traffic_not_lag() {
        let base = Instant::now();
        let mut track = LagTrack::default();
        for (i, bytes) in [100u64, 200, 300, 400, 500].into_iter().enumerate() {
            let backlog = i != 2;
            assert!(!step(
                &mut track,
                reading(bytes, backlog, false),
                at(base, 30 * i as u64)
            ));
        }
    }

    #[test]
    fn an_idle_sensor_or_an_unfinished_last_line_never_fires() {
        let base = Instant::now();
        let mut idle = LagTrack::default();
        let mut partial = LagTrack::default();
        for i in 0..200u64 {
            assert!(!step(&mut idle, reading(0, false, false), at(base, 30 * i)));
            assert!(!step(
                &mut partial,
                reading(87, false, false),
                at(base, 30 * i)
            ));
        }
    }

    #[test]
    fn a_firing_sensor_clears_once_drained_or_after_three_polls_without_growth() {
        let base = Instant::now();
        let mut track = LagTrack::default();
        for i in 0..4u64 {
            step(
                &mut track,
                reading(1_000 * (i + 1), true, false),
                at(base, 30 * i),
            );
        }
        assert!(track.lagging);
        // Flat, and the wait is under the threshold: still firing until three flat transitions.
        assert!(step(&mut track, reading(4_000, true, false), at(base, 120)));
        assert!(step(&mut track, reading(3_000, true, false), at(base, 150)));
        assert!(!step(
            &mut track,
            reading(3_000, true, false),
            at(base, 180)
        ));

        // Raised again, then read to the end: clears on the spot.
        for i in 0..4u64 {
            step(
                &mut track,
                reading(10_000 * (i + 1), true, false),
                at(base, 300 + 30 * i),
            );
        }
        assert!(track.lagging);
        assert!(!step(&mut track, reading(0, false, false), at(base, 420)));
    }

    #[test]
    fn a_sensor_still_waiting_past_the_threshold_does_not_clear_on_a_flat_backlog() {
        let base = Instant::now();
        let mut track = LagTrack::default();
        step(&mut track, reading(9_000, true, true), base);
        assert!(step(&mut track, reading(9_000, true, true), at(base, 600)));
        for i in 1..10u64 {
            assert!(step(
                &mut track,
                reading(9_000, true, true),
                at(base, 600 + 30 * i)
            ));
        }
    }

    fn ctx(progress: IntakeProgress) -> MonitorCtx {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused/unused")
            .unwrap();
        MonitorCtx {
            pool,
            pg_data_volume: "/".into(),
            spool_dir: "/".into(),
            spool_dirs: Vec::new(),
            vt_enabled: false,
            fetch_enabled: false,
            supervisor: Arc::new(Mutex::new(HashMap::new())),
            intake_progress: progress,
            intake_poll_interval: POLL,
            feed_marker_path: "/nonexistent".into(),
            feed_push_marker_path: "/nonexistent".into(),
            feed_build_interval: Duration::from_secs(300),
            rotation: crate::ops_alert::condition::RotationCtx::production(Vec::new()),
            cfg: parse_ops_alert(&|_: &str| None).unwrap(),
        }
    }

    /// Through the trait, against the map the intake loops write: a log whose backlog keeps
    /// rising pages on the fourth poll with its size and wait in the detail, an unmeasured log is
    /// unknown rather than healthy, and a quiet one is fine.
    #[tokio::test]
    async fn evaluate_reads_the_intake_map_and_names_the_lagging_log() {
        let progress: IntakeProgress = Arc::new(Mutex::new(HashMap::new()));
        let condition = IntakeLagging::new();
        let ctx = ctx(progress.clone());

        progress
            .lock()
            .unwrap()
            .insert("telnet", SensorIntake::started(Instant::now()));
        assert!(matches!(
            condition.evaluate(&ctx).await,
            Outcome::Unknown { why } if why.contains("telnet")
        ));

        progress
            .lock()
            .unwrap()
            .insert("ssh", intake(Some(0), false, None));
        let eleven_days_ago = Utc::now() - chrono::Duration::days(11);
        let mut last = Outcome::Ok;
        for bytes in [
            1_000_000_000u64,
            2_000_000_000,
            4_000_000_000,
            6_600_000_000,
        ] {
            progress
                .lock()
                .unwrap()
                .insert("telnet", intake(Some(bytes), true, Some(eleven_days_ago)));
            last = condition.evaluate(&ctx).await;
        }
        match last {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Warning);
                assert!(detail.contains("telnet (6.6 GB / 11 d)"), "{detail}");
                assert!(!detail.contains("ssh"), "{detail}");
            }
            other => panic!("expected the rising telnet backlog to fire, got {other:?}"),
        }

        progress
            .lock()
            .unwrap()
            .insert("telnet", intake(Some(0), false, Some(eleven_days_ago)));
        assert_eq!(condition.evaluate(&ctx).await, Outcome::Ok);
    }
}
