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

/// The daemon's own supervised subsystems, by the exact name each is spawned under in `main.rs`.
/// Every other entry in the supervisor handle is a per-sensor intake tailer (sensor names are
/// operator-chosen via `PROPOLIS_SENSOR_LOGS`, e.g. `ssh`, `catchall`, `cred-vnc`, so they cannot
/// be recognised by a name prefix). The `subsystem-gaveup` condition watches these; `sensor-down`
/// watches the complement. Keep this in sync with the `spawn_supervised` call sites; the coverage
/// test `daemon_subsystems_are_disjoint_from_sensor_names` guards the classification.
pub const DAEMON_SUBSYSTEMS: &[&str] = &[
    "review",
    "feed",
    "virustotal",
    "fetcher",
    "console",
    "ops-monitor",
];

/// True when `name` is a per-sensor intake tailer rather than a daemon subsystem.
pub fn is_sensor(name: &str) -> bool {
    !DAEMON_SUBSYSTEMS.contains(&name)
}

/// Per-sensor intake liveness, written by each sensor's intake loop and read by the
/// `intake-stalled` condition. `last_advanced_at` is the monitor-clock instant that sensor last
/// consumed input; `backlog` is whether the most recent poll left unconsumed input (a full batch,
/// or an append error with a line in hand). A sensor is stalled when it has backlog but has not
/// advanced for `stall_for` - the backlog flag is what distinguishes a wedged ingest pipeline from
/// a quiet honeypot with simply nothing to read.
#[derive(Debug, Clone, Copy)]
pub struct SensorIntake {
    pub last_advanced_at: Instant,
    pub backlog: bool,
}

/// Shared per-sensor intake map, keyed by the same leaked sensor name the supervisor uses. Each
/// sensor's loop writes only its own entry (no cross-sensor write race).
pub type IntakeProgress = Arc<Mutex<HashMap<&'static str, SensorIntake>>>;

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
