//! Intake set a log line aside. The database refused the same line on three polls
//! in a row, so intake wrote it to the quarantine directory and moved past it
//! (`intake::runner::IntakeRunner::quarantine_line`). Nothing is stuck any more, but a real line
//! from a sensor is not in the ledger, and an operator should look at why.
//!
//! An event, not a level: the loops publish when the last line was quarantined, and the condition
//! fires while that is recent. It holds for the re-page cooldown, so one quarantined line pages
//! once and clears (with a recovered notice) a cooldown later, and a second line inside that window
//! extends it. It cannot re-page within that window, because the window is the cooldown itself.

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome, SensorIntake};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// Whether a quarantine at `at` still counts as recent at `now`.
fn is_recent(at: Instant, now: Instant, window: Duration) -> bool {
    now.saturating_duration_since(at) <= window
}

/// Each sensor with a recent quarantine, newest note per sensor, sorted by sensor name.
fn recent_notes<'a>(
    sensors: impl Iterator<Item = (&'a str, &'a SensorIntake)>,
    now: Instant,
    window: Duration,
) -> Vec<String> {
    let mut notes: Vec<String> = sensors
        .filter_map(|(_, intake)| {
            let (at, note) = intake.last_quarantine.as_ref()?;
            is_recent(*at, now, window).then(|| note.clone())
        })
        .collect();
    notes.sort_unstable();
    notes
}

/// Intake quarantined a line the database always refuses.
pub struct IntakeLineQuarantined;

#[async_trait]
impl Condition for IntakeLineQuarantined {
    fn id(&self) -> &'static str {
        "intake-line-quarantined"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // The quarantine already happened; waiting would only delay telling the operator.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let notes = {
            let map = ctx
                .intake_progress
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            recent_notes(
                map.iter().map(|(name, s)| (*name, s)),
                Instant::now(),
                ctx.cfg.repage_cooldown,
            )
        };
        if notes.is_empty() {
            return Outcome::Ok;
        }
        Outcome::Firing {
            severity: Severity::Warning,
            detail: format!(
                "intake quarantined a line the database refuses; it was skipped, not ingested. \
                 Inspect the quarantine files: {}",
                notes.join("; ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_alert::condition::IntakeProgress;
    use crate::ops_alert::config::parse_ops_alert;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const WINDOW: Duration = Duration::from_secs(5400);

    fn quarantined(at: Instant, note: &str) -> SensorIntake {
        let mut s = SensorIntake::started(Instant::now());
        s.last_quarantine = Some((at, note.into()));
        s
    }

    #[test]
    fn a_quarantine_is_recent_up_to_the_window_and_not_after() {
        let base = Instant::now();
        assert!(is_recent(base, base, WINDOW));
        assert!(is_recent(base, base + WINDOW, WINDOW));
        assert!(!is_recent(
            base,
            base + WINDOW + Duration::from_secs(1),
            WINDOW
        ));
    }

    #[test]
    fn only_recent_quarantines_are_listed_in_sensor_order() {
        let old = Instant::now();
        let now = old + WINDOW + Duration::from_secs(60);
        let map: HashMap<&str, SensorIntake> = HashMap::from([
            ("ssh", quarantined(now, "ssh: line 2")),
            ("telnet", quarantined(now, "telnet: line 1")),
            ("ftp", quarantined(old, "ftp: long ago")),
            ("vnc", SensorIntake::started(now)),
        ]);
        assert_eq!(
            recent_notes(map.iter().map(|(k, v)| (*k, v)), now, WINDOW),
            ["ssh: line 2", "telnet: line 1"]
        );
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
            intake_poll_interval: Duration::from_secs(30),
            feed_marker_path: "/nonexistent".into(),
            feed_push_marker_path: "/nonexistent".into(),
            feed_build_interval: Duration::from_secs(300),
            rotation: crate::ops_alert::condition::RotationCtx::production(Vec::new()),
            cfg: parse_ops_alert(&|_: &str| None).unwrap(),
        }
    }

    /// Through the trait, against the map the intake loops write: quiet is fine, a fresh
    /// quarantine fires naming the sensor, offset, SQLSTATE and file the loop reported, and one
    /// older than the cooldown has cleared.
    #[tokio::test]
    async fn evaluate_fires_on_a_recent_quarantine_and_clears_after_the_window() {
        let progress: IntakeProgress = Arc::new(Mutex::new(HashMap::new()));
        let ctx = ctx(progress.clone());
        let condition = IntakeLineQuarantined;
        assert_eq!(condition.id(), "intake-line-quarantined");
        progress
            .lock()
            .unwrap()
            .insert("telnet", SensorIntake::started(Instant::now()));
        assert_eq!(condition.evaluate(&ctx).await, Outcome::Ok);

        let note = "telnet: the line at byte offset 4096 of /l was refused by the database \
                    (SQLSTATE 22P05) and quarantined to /q/telnet.jsonl";
        progress
            .lock()
            .unwrap()
            .insert("telnet", quarantined(Instant::now(), note));
        match condition.evaluate(&ctx).await {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Warning);
                assert!(detail.contains(note), "{detail}");
            }
            other => panic!("expected a firing outcome, got {other:?}"),
        }

        // Wait out a (shortened) cooldown rather than subtract from the clock, which has no
        // guaranteed history to subtract an hour from right after boot.
        let mut short = ctx.clone();
        short.cfg.repage_cooldown = Duration::from_millis(1);
        progress
            .lock()
            .unwrap()
            .insert("telnet", quarantined(Instant::now(), note));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(condition.evaluate(&short).await, Outcome::Ok);
    }
}
