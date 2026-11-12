//! Condition #1: a sensor's intake tailer has unconsumed input but is not advancing - the ingest
//! pipeline is wedged (typically `append_event` failing on a database problem). Distinct from a
//! quiet honeypot with nothing to read, which is not a stall; the `backlog` flag is the guard.

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// Derive `(advanced, backlog)` from one batch's counts. Lives here (not in the intake crate, which
/// cannot depend on propolis types) and is called by the sensor loop in `main.rs`.
///
/// `advanced` = the read cursor moved (at least one line consumed: ingested, dropped-as-rejected,
/// or dropped as a reachability-probe line).
/// `backlog` = the poll left unconsumed input: an append error stopped the batch with a line in
/// hand, or the batch filled (100 lines) so more is very likely waiting.
///
/// `probe_confirmations` counts toward progress but is deliberately NOT folded into `ingested` by
/// the caller: consuming a probe line IS the cursor moving, so a tailer reading nothing but probe
/// lines is not stalled - but a probe line is not attacker evidence, and letting it inflate the
/// ingest counters would hide a pipeline that has stopped ingesting anything real.
pub fn progress_from_batch(
    ingested: usize,
    rejected: usize,
    probe_confirmations: usize,
    errors: usize,
) -> (bool, bool) {
    let consumed = ingested + rejected + probe_confirmations;
    let advanced = consumed > 0;
    let backlog = errors > 0 || consumed >= 100;
    (advanced, backlog)
}

/// Stall test, split from I/O: unconsumed input present AND no forward progress for `stall_for`.
fn is_stalled(last_advanced: Instant, now: Instant, stall_for: Duration, backlog: bool) -> bool {
    backlog && now.duration_since(last_advanced) > stall_for
}

/// #1: intake stalled with backlog.
pub struct IntakeStalled;

#[async_trait]
impl Condition for IntakeStalled {
    fn id(&self) -> &'static str {
        "intake-stalled"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // is_stalled already requires `stall_for` of no progress, so that IS the debounce; page
        // as soon as a sensor crosses it.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let now = Instant::now();
        let stall_for = ctx.cfg.stall_for;
        let mut stalled: Vec<String> = {
            let map = ctx
                .intake_progress
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.iter()
                .filter(|(_, s)| is_stalled(s.last_advanced_at, now, stall_for, s.backlog))
                .map(|(name, s)| match &s.wedge {
                    Some(why) => format!("{name} [{why}]"),
                    None => (*name).to_string(),
                })
                .collect()
        };
        if stalled.is_empty() {
            return Outcome::Ok;
        }
        stalled.sort_unstable();
        Outcome::Firing {
            severity: Severity::Warning,
            detail: format!(
                "intake stalled (input pending, no progress for over {}s): {}",
                stall_for.as_secs(),
                stalled.join(", ")
            ),
        }
    }
}

/// How long `intake-rotation-loss` stays up after the last loss. A loss is an event, not a state
/// that can clear by itself, so this only sets how long the page is held before it recovers; the
/// WARN each loss logs is the permanent record.
pub const ROTATION_LOSS_HOLD: Duration = Duration::from_secs(3600);

/// Logs that lost input to a `copytruncate` rotation within `hold` of `now`, as
/// `name (events, at least bytes)`, sorted. Split from the lock so the window is tested directly.
fn recent_rotation_losses(
    logs: impl Iterator<Item = (&'static str, crate::ops_alert::condition::SensorIntake)>,
    now: Instant,
    hold: Duration,
) -> Vec<String> {
    let mut lost: Vec<String> = logs
        .filter(|(_, s)| {
            s.rotation_loss_at
                .is_some_and(|at| now.saturating_duration_since(at) < hold)
        })
        .map(|(name, s)| {
            format!(
                "{name} ({} rotation{}, at least {} bytes)",
                s.rotation_loss.events,
                if s.rotation_loss.events == 1 { "" } else { "s" },
                s.rotation_loss.bytes_estimated
            )
        })
        .collect();
    lost.sort_unstable();
    lost
}

/// #15: a `copytruncate` rotation took input the intake had not read and the rotated copy
/// (`<log>.1`) could not supply - it was missing, compressed, or not the old content. The tailer
/// reads the copy whenever it can (`LogTailer`'s `copytruncate` drain), so this fires only when
/// lines were actually lost, not on every rotation. A loss the tailer could not size after a
/// restart reads as `at least 0 bytes`.
pub struct IntakeRotationLoss;

#[async_trait]
impl Condition for IntakeRotationLoss {
    fn id(&self) -> &'static str {
        "intake-rotation-loss"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let lost = {
            let map = ctx
                .intake_progress
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            recent_rotation_losses(
                map.iter().map(|(name, s)| (*name, s.clone())),
                Instant::now(),
                ROTATION_LOSS_HOLD,
            )
        };
        if lost.is_empty() {
            return Outcome::Ok;
        }
        Outcome::Firing {
            severity: Severity::Warning,
            detail: format!(
                "a log rotation discarded unread intake input that the rotated copy could not supply: {}",
                lost.join(", ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STALL_FOR: Duration = Duration::from_secs(600);

    fn lossy(
        events: u64,
        bytes: u64,
        at: Option<Instant>,
    ) -> crate::ops_alert::condition::SensorIntake {
        let mut s = crate::ops_alert::condition::SensorIntake::started(Instant::now());
        s.rotation_loss = log_tailer::RotationLoss {
            events,
            bytes_estimated: bytes,
        };
        s.rotation_loss_at = at;
        s
    }

    #[test]
    fn a_recent_rotation_loss_is_named_with_its_size_and_an_old_or_absent_one_is_not() {
        let now = Instant::now() + Duration::from_secs(10_000);
        let recent = now - Duration::from_secs(60);
        let old = now - ROTATION_LOSS_HOLD - Duration::from_secs(1);
        let logs = vec![
            ("telnet", lossy(2, 4096, Some(recent))),
            ("ssh", lossy(1, 0, Some(old))),
            ("http", lossy(0, 0, None)),
            ("cred-vnc", lossy(1, 10, Some(recent))),
        ];
        assert_eq!(
            recent_rotation_losses(logs.into_iter(), now, ROTATION_LOSS_HOLD),
            vec![
                "cred-vnc (1 rotation, at least 10 bytes)".to_string(),
                "telnet (2 rotations, at least 4096 bytes)".to_string(),
            ]
        );
    }

    #[test]
    fn the_hold_boundary_is_exclusive() {
        let now = Instant::now() + Duration::from_secs(10_000);
        let at = now - ROTATION_LOSS_HOLD;
        let logs = vec![("telnet", lossy(1, 1, Some(at)))];
        assert!(recent_rotation_losses(logs.into_iter(), now, ROTATION_LOSS_HOLD).is_empty());
    }

    #[test]
    fn within_the_window_is_not_stalled() {
        let base = Instant::now();
        assert!(!is_stalled(
            base,
            base + Duration::from_secs(300),
            STALL_FOR,
            true
        ));
    }

    #[test]
    fn no_backlog_is_never_stalled_even_when_long_idle() {
        // Quiet-honeypot guard: idle far past the window, but nothing waiting to read.
        let base = Instant::now();
        assert!(!is_stalled(
            base,
            base + Duration::from_secs(100_000),
            STALL_FOR,
            false
        ));
    }

    #[test]
    fn past_the_window_with_backlog_is_stalled() {
        let base = Instant::now();
        assert!(is_stalled(
            base,
            base + Duration::from_secs(601),
            STALL_FOR,
            true
        ));
    }

    #[test]
    fn progress_from_batch_classifies_the_cases() {
        assert_eq!(progress_from_batch(0, 0, 0, 0), (false, false)); // quiet
        assert_eq!(progress_from_batch(5, 0, 0, 0), (true, false)); // advancing, caught up
        assert_eq!(progress_from_batch(0, 0, 0, 1), (false, true)); // append wedged, line stuck
        assert_eq!(progress_from_batch(100, 0, 0, 0), (true, true)); // full batch, more waiting
        assert_eq!(progress_from_batch(0, 100, 0, 0), (true, true)); // full batch of rejects
    }

    /// A tailer reading nothing but probe lines has a moving cursor and is not stalled. Before the
    /// probe existed every consumed line was ingested or rejected, so this case could not arise;
    /// leaving it out would have paged the operator every sweep on a quiet honeypot.
    #[test]
    fn progress_from_batch_counts_a_probe_confirmation_as_forward_progress() {
        assert_eq!(progress_from_batch(0, 0, 1, 0), (true, false));
        assert_eq!(progress_from_batch(0, 0, 100, 0), (true, true));
        // And it still cannot mask a wedge: the append error keeps the backlog flag up.
        assert_eq!(progress_from_batch(0, 0, 1, 1), (true, true));
    }
}
