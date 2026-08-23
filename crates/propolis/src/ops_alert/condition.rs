//! The `Condition` trait every failure-mode check implements, the `Outcome` it returns, and the
//! `MonitorCtx` of shared read handles it evaluates against.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sqlx::PgPool;

use super::config::OpsAlertConfig;
use super::debounce::Signal;
use super::dispatch::Severity;

/// Per-subsystem liveness state the supervisor publishes and the subsystem conditions read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsysState {
    Running,
    BackingOff { consecutive: u32 },
    GaveUp,
}

/// Shared map from subsystem name to its current supervised state. The supervisor writes it; the
/// `subsystem-gaveup` and `sensor-down` conditions read it.
pub type SupervisorHandle = Arc<Mutex<HashMap<&'static str, SubsysState>>>;

/// The monitor-clock instant the intake tailer last advanced its read offset. `None` = it has not
/// advanced yet (startup grace). The intake runner writes it; the `intake-stalled` condition reads it.
pub type IntakeProgress = Arc<Mutex<Option<Instant>>>;

/// One condition's result for a single evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Healthy.
    Ok,
    /// The failure condition holds.
    Firing { severity: Severity, detail: String },
    /// The probe could not read its source this tick (a query error, an unreadable path). This does
    /// NOT fire the primary condition - fail-open on a read error, so one broken probe cannot mask
    /// the others. The monitor separately warns if a probe stays Unknown for too long.
    Unknown { why: String },
}

impl Outcome {
    pub fn to_signal(&self) -> Signal {
        match self {
            Outcome::Firing { .. } => Signal::Firing,
            Outcome::Ok | Outcome::Unknown { .. } => Signal::Ok,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Outcome::Unknown { .. })
    }
}

/// The shared handles conditions read from. Cloneable so the supervised monitor task can own a copy.
#[derive(Clone)]
pub struct MonitorCtx {
    pub pool: PgPool,
    /// A path on the volume backing the Postgres data directory (for `statvfs` free-space).
    pub pg_data_volume: PathBuf,
    /// The sensor spool directory (for `statvfs` free-space + a size walk).
    pub spool_dir: PathBuf,
    pub supervisor: SupervisorHandle,
    pub intake_progress: IntakeProgress,
    pub cfg: OpsAlertConfig,
}

/// One operational failure mode to check on each poll.
#[async_trait]
pub trait Condition: Send + Sync {
    /// Stable identifier, used as the dedup/debounce key.
    fn id(&self) -> &'static str;
    /// How long the condition must hold before it pages (debounce). Zero pages immediately.
    fn for_dur(&self, cfg: &OpsAlertConfig) -> Duration;
    /// Evaluate the condition against the current context.
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_alert::debounce::{Action, DebounceMachine};

    #[test]
    fn firing_maps_to_the_firing_signal_and_pages_immediately_at_zero_debounce() {
        let out = Outcome::Firing {
            severity: Severity::Critical,
            detail: "db 4% free".into(),
        };
        let mut m = DebounceMachine::new(Duration::from_secs(0), Duration::from_secs(300));
        // for_dur == 0, so the first firing tick pages.
        assert_eq!(m.step(out.to_signal(), Instant::now()), Action::Page);
    }

    #[test]
    fn ok_and_unknown_both_map_to_the_ok_signal() {
        assert_eq!(Outcome::Ok.to_signal(), Signal::Ok);
        assert_eq!(
            Outcome::Unknown {
                why: "query failed".into()
            }
            .to_signal(),
            Signal::Ok
        );
        assert!(Outcome::Unknown { why: "x".into() }.is_unknown());
        assert!(!Outcome::Ok.is_unknown());
    }
}
