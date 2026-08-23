//! Conditions #8 (a supervised subsystem gave up restarting) and #2 (a sensor intake tailer gave
//! up). Both read the shared supervisor handle only - no database. The daemon subsystems and the
//! per-sensor tailers live in the same handle; `is_sensor` splits them (see `condition.rs`).

use std::collections::HashMap;

use async_trait::async_trait;

use crate::ops_alert::condition::{
    Condition, MonitorCtx, Outcome, SubsysState, SupervisorHandle, is_sensor,
};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;
use std::time::Duration;

/// Collect the names in `map` that gave up, restricted to those matching `want_sensor`, sorted for
/// a stable detail string.
fn gave_up_names(map: &HashMap<&'static str, SubsysState>, want_sensor: bool) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = map
        .iter()
        .filter(|(name, state)| {
            is_sensor(name) == want_sensor && matches!(state, SubsysState::GaveUp)
        })
        .map(|(name, _)| *name)
        .collect();
    names.sort_unstable();
    names
}

/// Pure core of #8: any daemon subsystem that stopped restarting is a critical page.
fn eval_subsystem_gaveup(map: &HashMap<&'static str, SubsysState>) -> Outcome {
    let down = gave_up_names(map, false);
    if down.is_empty() {
        return Outcome::Ok;
    }
    Outcome::Firing {
        severity: Severity::Critical,
        detail: format!("subsystems stopped restarting: {}", down.join(", ")),
    }
}

/// Pure core of #2: any sensor tailer that stopped restarting means that sensor is no longer being
/// ingested (its log is gone or unreadable). Warning for some, Critical when every known sensor is
/// down.
fn eval_sensor_down(map: &HashMap<&'static str, SubsysState>) -> Outcome {
    let total_sensors = map.keys().filter(|name| is_sensor(name)).count();
    // No sensor has published state yet (startup grace): nothing to judge.
    if total_sensors == 0 {
        return Outcome::Ok;
    }
    let down = gave_up_names(map, true);
    if down.is_empty() {
        return Outcome::Ok;
    }
    let severity = if down.len() == total_sensors {
        Severity::Critical
    } else {
        Severity::Warning
    };
    Outcome::Firing {
        severity,
        detail: format!(
            "sensor intake stopped: {} ({} of {} sensors)",
            down.join(", "),
            down.len(),
            total_sensors
        ),
    }
}

/// Reads the supervisor handle with poison recovery.
fn snapshot(handle: &SupervisorHandle) -> HashMap<&'static str, SubsysState> {
    handle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// #8: a daemon subsystem exhausted its restart budget.
pub struct SubsystemGaveUp;

#[async_trait]
impl Condition for SubsystemGaveUp {
    fn id(&self) -> &'static str {
        "subsystem-gaveup"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // GaveUp is a terminal state the supervisor only sets after repeated rapid panics; page now.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        eval_subsystem_gaveup(&snapshot(&ctx.supervisor))
    }
}

/// #2: a sensor's intake tailer exhausted its restart budget.
pub struct SensorDown;

#[async_trait]
impl Condition for SensorDown {
    fn id(&self) -> &'static str {
        "sensor-down"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        eval_sensor_down(&snapshot(&ctx.supervisor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_alert::condition::DAEMON_SUBSYSTEMS;

    fn map(entries: &[(&'static str, SubsysState)]) -> HashMap<&'static str, SubsysState> {
        entries.iter().copied().collect()
    }

    #[test]
    fn a_daemon_subsystem_gaveup_is_critical_and_not_a_sensor_alert() {
        let m = map(&[
            ("feed", SubsysState::GaveUp),
            ("ssh", SubsysState::Running),
            ("telnet", SubsysState::Running),
        ]);
        match eval_subsystem_gaveup(&m) {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Critical);
                assert!(
                    detail.contains("feed"),
                    "detail names the subsystem: {detail}"
                );
            }
            other => panic!("expected Firing, got {other:?}"),
        }
        // The same feed give-up must NOT be reported as a sensor being down.
        assert_eq!(eval_sensor_down(&m), Outcome::Ok);
    }

    #[test]
    fn one_sensor_down_is_a_warning() {
        let m = map(&[
            ("ssh", SubsysState::GaveUp),
            ("telnet", SubsysState::Running),
            ("catchall", SubsysState::Running),
        ]);
        match eval_sensor_down(&m) {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Warning);
                assert!(detail.contains("ssh"), "detail names the sensor: {detail}");
                assert!(detail.contains("1 of 3"), "detail counts sensors: {detail}");
            }
            other => panic!("expected Firing/Warning, got {other:?}"),
        }
        // A sensor give-up is not a daemon-subsystem alert.
        assert_eq!(eval_subsystem_gaveup(&m), Outcome::Ok);
    }

    #[test]
    fn all_sensors_down_is_critical() {
        let m = map(&[
            ("ssh", SubsysState::GaveUp),
            ("telnet", SubsysState::GaveUp),
            ("feed", SubsysState::Running),
        ]);
        match eval_sensor_down(&m) {
            Outcome::Firing { severity, .. } => assert_eq!(severity, Severity::Critical),
            other => panic!("expected Firing/Critical, got {other:?}"),
        }
    }

    #[test]
    fn a_backing_off_sensor_is_not_yet_down() {
        // BackingOff is transient (the supervisor is still retrying); only GaveUp pages.
        let m = map(&[
            ("ssh", SubsysState::BackingOff { consecutive: 2 }),
            ("telnet", SubsysState::Running),
        ]);
        assert_eq!(eval_sensor_down(&m), Outcome::Ok);
        assert_eq!(eval_subsystem_gaveup(&m), Outcome::Ok);
    }

    #[test]
    fn all_running_is_ok_for_both() {
        let m = map(&[
            ("feed", SubsysState::Running),
            ("ssh", SubsysState::Running),
        ]);
        assert_eq!(eval_subsystem_gaveup(&m), Outcome::Ok);
        assert_eq!(eval_sensor_down(&m), Outcome::Ok);
    }

    #[test]
    fn empty_handle_at_startup_is_ok() {
        let m = map(&[]);
        assert_eq!(eval_subsystem_gaveup(&m), Outcome::Ok);
        assert_eq!(eval_sensor_down(&m), Outcome::Ok);
    }

    #[test]
    fn daemon_subsystems_are_disjoint_from_sensor_names() {
        // The daemon set is load-bearing: these names must match the spawn_supervised call-site
        // literals in main.rs exactly, or a gave-up subsystem is misclassified and pages at the
        // wrong severity (Warning sensor-down vs Critical subsystem-gaveup). Pin it so an edit to
        // either side is a conscious, reviewed change rather than silent drift. (Asserting
        // `!is_sensor(daemon)` for names drawn FROM the set would be tautological - is_sensor is
        // literally `!DAEMON_SUBSYSTEMS.contains` - so it would guard nothing.)
        assert_eq!(
            DAEMON_SUBSYSTEMS,
            &[
                "review",
                "feed",
                "virustotal",
                "fetcher",
                "console",
                "ops-monitor"
            ],
        );
        // The real deployed sensor names (INSTALL.md) must all classify as sensors.
        for sensor in [
            "catchall",
            "ssh",
            "telnet",
            "redis",
            "adb",
            "http",
            "ftp",
            "smtp",
            "cred-vnc",
            "cred-mysql",
            "cred-mssql",
            "cred-pg",
            "cred-mongo",
        ] {
            assert!(is_sensor(sensor), "{sensor} must classify as a sensor");
        }
    }
}
