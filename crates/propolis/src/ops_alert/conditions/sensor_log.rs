//! Conditions #13 and #14: the sensor event logs are not being kept in check by rotation.
//!
//! In October 2026 the distro's logrotate timer sat inactive for eleven days. Nothing rotated, one
//! telnet log reached 6.6 GB and `/var` reached 80% before anyone noticed, because the other
//! disk alarm (`capacity`) watches the database and spool volumes, not the log volume, and
//! `intake-lagging` only sees an intake that has fallen behind, not a log that has grown.
//!
//! - `sensor-log-oversized`: any configured sensor log is more than three times the rotation size,
//!   or the filesystem holding the logs is over 85% used. A healthy rotation keeps a log near its
//!   `size` and at most an hour of traffic past it, so three times the size means rotation has not
//!   run or cannot (the free-space guard refused it).
//! - `rotation-stale`: the logrotate state file has not been rewritten for over three hours.
//!   `propolis-logrotate.service` rewrites it on every run, whether or not any log was due, so its
//!   modification time is the last time rotation ran (verified against logrotate 3.22). The daemon
//!   cannot ask systemd whether the timer is active, so it reads the file the timer's service
//!   writes: a file that stops moving is a timer that stopped firing.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use nix::sys::statvfs::statvfs;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// Where `deploy/propolis-logrotate.service` keeps its state (`--state`). The daemon only stats it.
pub const LOGROTATE_STATE_PATH: &str = "/var/lib/propolis/logrotate.state";

/// The installed rotation policy (`deploy/logrotate-sensors.conf`), read for its `size` line.
pub const LOGROTATE_POLICY_PATH: &str = "/etc/logrotate.d/propolis-sensors";

/// The directory every sensor writes its log under (`deploy/provision.sh`); its filesystem is the
/// one the disk-use half of `sensor-log-oversized` measures.
pub const SENSOR_LOG_ROOT: &str = "/var/log/propolis";

/// The rotation size assumed when the policy file cannot be read or has no parsable `size` line.
/// Matches `size 100M` in `deploy/logrotate-sensors.conf`.
pub const DEFAULT_ROTATION_SIZE: u64 = 100 * 1024 * 1024;

/// A log pages above this many times the rotation size, and stays paged until it is back under
/// [`CLEAR_SIZE_MULT`].
const FIRE_SIZE_MULT: u64 = 3;
const CLEAR_SIZE_MULT: u64 = 2;

/// The log filesystem pages above this percentage used (`df`'s Use%), and clears at or below the
/// lower mark, so a volume hovering on the line does not page and recover in turn.
const FIRE_USED_PCT: f64 = 85.0;
const CLEAR_USED_PCT: f64 = 80.0;

/// Three timer periods. The timer runs hourly, so a healthy state file is never older than about
/// an hour; three hours tolerates a missed run or two without paging.
pub const STATE_STALE_AFTER: Duration = Duration::from_secs(3 * 3600);

/// A disk or log breach is not a blip but a temp spike should not page: hold briefly.
const OVERSIZED_HOLD: Duration = Duration::from_secs(120);

/// Parses logrotate's `size` argument: an integer with an optional `k`, `M` or `G` suffix (any
/// case, powers of 1024; logrotate(8)). `None` for anything else, including zero and overflow.
fn parse_size(arg: &str) -> Option<u64> {
    let arg = arg.trim();
    let (digits, mult) = match arg.chars().last()? {
        'k' | 'K' => (&arg[..arg.len() - 1], 1024u64),
        'm' | 'M' => (&arg[..arg.len() - 1], 1024 * 1024),
        'g' | 'G' => (&arg[..arg.len() - 1], 1024 * 1024 * 1024),
        c if c.is_ascii_digit() => (arg, 1),
        _ => return None,
    };
    let n: u64 = digits.parse().ok()?;
    n.checked_mul(mult).filter(|&bytes| bytes > 0)
}

/// The rotation size from the text of a logrotate policy: the first `size` directive. Split from
/// the file read so it is tested without a file.
fn rotation_size_from(policy: &str) -> Option<u64> {
    policy.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("size"))
            .then(|| words.next())
            .flatten()
            .and_then(parse_size)
    })
}

/// The size the policy rotates at, falling back to [`DEFAULT_ROTATION_SIZE`] when it cannot say.
/// Read on every evaluation: the file is a few hundred bytes and an upgrade can change it under a
/// running daemon.
fn rotation_size(policy_path: &Path) -> u64 {
    std::fs::read_to_string(policy_path)
        .ok()
        .and_then(|policy| rotation_size_from(&policy))
        .unwrap_or(DEFAULT_ROTATION_SIZE)
}

/// Used percentage of the filesystem holding `path`, computed as `df` does (used over used plus
/// the space available to an unprivileged writer), so the number matches what the operator sees.
fn used_pct(path: &Path) -> Result<f64, String> {
    let st = statvfs(path).map_err(|e| format!("statvfs {}: {e}", path.display()))?;
    let used = st.blocks().saturating_sub(st.blocks_free()) as f64;
    let denom = used + st.blocks_available() as f64;
    if denom == 0.0 {
        // A pseudo-filesystem with no blocks cannot be "full".
        return Ok(0.0);
    }
    Ok(used / denom * 100.0)
}

/// Why the log set is over its limits, given the thresholds in force. `was_firing` selects the
/// clear marks (lower) over the fire marks, which is the hysteresis.
#[derive(Debug, PartialEq)]
struct Breach {
    /// `(name, bytes)` of each log over the size mark, in the order given.
    oversized: Vec<(String, u64)>,
    /// The filesystem's used percentage, when over its mark.
    disk_used_pct: Option<f64>,
}

impl Breach {
    fn is_empty(&self) -> bool {
        self.oversized.is_empty() && self.disk_used_pct.is_none()
    }
}

fn judge(was_firing: bool, rotation_size: u64, logs: &[(String, u64)], used_pct: f64) -> Breach {
    let size_mult = if was_firing {
        CLEAR_SIZE_MULT
    } else {
        FIRE_SIZE_MULT
    };
    let used_mark = if was_firing {
        CLEAR_USED_PCT
    } else {
        FIRE_USED_PCT
    };
    let size_mark = rotation_size.saturating_mul(size_mult);
    Breach {
        oversized: logs
            .iter()
            .filter(|(_, bytes)| *bytes > size_mark)
            .cloned()
            .collect(),
        disk_used_pct: (used_pct > used_mark).then_some(used_pct),
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// #13: a sensor log, or the volume holding the logs, has outgrown what rotation should allow.
pub struct SensorLogOversized {
    firing: Mutex<bool>,
}

impl SensorLogOversized {
    pub fn new() -> Self {
        Self {
            firing: Mutex::new(false),
        }
    }
}

impl Default for SensorLogOversized {
    fn default() -> Self {
        Self::new()
    }
}

impl SensorLogOversized {
    /// The verdict for the log set given the log volume's `used` percentage; split from the
    /// `statvfs` read so the disk half is tested at chosen fullness.
    fn assess(&self, ctx: &MonitorCtx, used: f64) -> Outcome {
        let rot = &ctx.rotation;
        let mut sizes = Vec::with_capacity(rot.logs.len());
        let mut unreadable = Vec::new();
        for log in &rot.logs {
            match std::fs::metadata(&log.log_path) {
                Ok(md) => sizes.push((log.name.clone(), md.len())),
                // A sensor that has not logged yet has no file; that is not oversized.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => unreadable.push(format!("{}: {e}", log.log_path.display())),
            }
        }
        let size = rotation_size(&rot.policy_path);

        let mut firing = self.firing.lock().unwrap_or_else(|p| p.into_inner());
        let breach = judge(*firing, size, &sizes, used);
        if breach.is_empty() {
            *firing = false;
            if unreadable.is_empty() {
                return Outcome::Ok;
            }
            // Only claim healthy for the logs that could be measured.
            return Outcome::Unknown {
                why: format!("cannot stat sensor log {}", unreadable.join("; ")),
            };
        }
        *firing = true;

        let mut parts = Vec::new();
        if !breach.oversized.is_empty() {
            let logs: Vec<String> = breach
                .oversized
                .iter()
                .map(|(name, bytes)| format!("{name} {}", human_bytes(*bytes)))
                .collect();
            parts.push(format!(
                "over {}x the {} rotation size: {}",
                FIRE_SIZE_MULT,
                human_bytes(size),
                logs.join(", ")
            ));
        }
        if let Some(pct) = breach.disk_used_pct {
            parts.push(format!(
                "{} is {pct:.0}% used (limit {FIRE_USED_PCT:.0}%)",
                rot.volume.display()
            ));
        }
        Outcome::Firing {
            // A full log volume takes the database and the other sensors down with it; an
            // oversized log alone is rotation failing but the disk still has room.
            severity: if breach.disk_used_pct.is_some() {
                Severity::Critical
            } else {
                Severity::Warning
            },
            detail: format!(
                "sensor logs outgrowing rotation: {}. Check `systemctl status propolis-logrotate.timer` and `journalctl -u propolis-logrotate.service`; a log too large to rotate needs docs/operations/retention.md, \"A log too large to rotate\"",
                parts.join("; ")
            ),
        }
    }
}

#[async_trait]
impl Condition for SensorLogOversized {
    fn id(&self) -> &'static str {
        "sensor-log-oversized"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        OVERSIZED_HOLD
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        match used_pct(&ctx.rotation.volume) {
            Ok(used) => self.assess(ctx, used),
            Err(why) => Outcome::Unknown { why },
        }
    }
}

/// The age of the state file at `now`, `None` when it does not exist. A modification time in the
/// future (a clock step) reads as zero rather than as a huge age.
fn state_age(path: &Path, now: SystemTime) -> Result<Option<Duration>, String> {
    match std::fs::metadata(path) {
        Ok(md) => {
            let modified = md
                .modified()
                .map_err(|e| format!("mtime {}: {e}", path.display()))?;
            Ok(Some(now.duration_since(modified).unwrap_or(Duration::ZERO)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("stat {}: {e}", path.display())),
    }
}

/// #14: the Propolis rotation timer has stopped running logrotate.
pub struct RotationStale;

#[async_trait]
impl Condition for RotationStale {
    fn id(&self) -> &'static str {
        "rotation-stale"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // The three-hour age is the debounce: it already spans several missed hourly runs.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let path = &ctx.rotation.state_path;
        match state_age(path, SystemTime::now()) {
            Err(why) => Outcome::Unknown { why },
            // Never run: the timer is not installed or not enabled, or this is a node that has
            // not been upgraded yet. Unknown, not firing, so a node that opted out is not paged,
            // while the monitor's own probe-stale warning still surfaces it after half an hour.
            Ok(None) => Outcome::Unknown {
                why: format!(
                    "{} does not exist: propolis-logrotate.timer has never run on this node",
                    path.display()
                ),
            },
            Ok(Some(age)) if age > STATE_STALE_AFTER => Outcome::Firing {
                severity: Severity::Warning,
                detail: format!(
                    "no log rotation run for {} h (limit {} h; state {}). Check `systemctl status propolis-logrotate.timer`; sensor logs are growing unbounded until it runs",
                    age.as_secs() / 3600,
                    STATE_STALE_AFTER.as_secs() / 3600,
                    path.display()
                ),
            },
            Ok(Some(_)) => Outcome::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_alert::condition::RotationCtx;
    use crate::ops_alert::config::parse_ops_alert;
    use log_tailer::SensorLogConfig;
    use std::collections::HashMap;
    use std::sync::Arc;

    const MIB: u64 = 1024 * 1024;

    fn logs(sizes: &[(&str, u64)]) -> Vec<(String, u64)> {
        sizes.iter().map(|(n, b)| (n.to_string(), *b)).collect()
    }

    fn ctx(rotation: RotationCtx) -> MonitorCtx {
        MonitorCtx {
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://unused/unused")
                .unwrap(),
            pg_data_volume: "/".into(),
            spool_dir: "/".into(),
            spool_dirs: Vec::new(),
            vt_enabled: false,
            fetch_enabled: false,
            supervisor: Arc::new(Mutex::new(HashMap::new())),
            intake_progress: Arc::new(Mutex::new(HashMap::new())),
            intake_poll_interval: Duration::from_secs(1),
            feed_marker_path: "/nonexistent".into(),
            feed_push_marker_path: "/nonexistent".into(),
            feed_build_interval: Duration::from_secs(300),
            rotation,
            cfg: parse_ops_alert(&|_: &str| None).unwrap(),
        }
    }

    fn rotation_in(dir: &Path, names: &[&str]) -> RotationCtx {
        RotationCtx {
            logs: names
                .iter()
                .map(|n| SensorLogConfig {
                    name: n.to_string(),
                    log_path: dir.join(format!("{n}.jsonl")),
                })
                .collect(),
            volume: dir.to_path_buf(),
            state_path: dir.join("logrotate.state"),
            policy_path: dir.join("policy"),
        }
    }

    /// Sparse, so a "6.6 GB" log costs no disk.
    fn make_log(dir: &Path, name: &str, bytes: u64) {
        let f = std::fs::File::create(dir.join(format!("{name}.jsonl"))).unwrap();
        f.set_len(bytes).unwrap();
    }

    #[test]
    fn parse_size_reads_logrotate_units_and_rejects_the_rest() {
        assert_eq!(parse_size("100M"), Some(100 * MIB));
        assert_eq!(parse_size("100m"), Some(100 * MIB));
        assert_eq!(parse_size("512k"), Some(512 * 1024));
        assert_eq!(parse_size("2G"), Some(2 * 1024 * MIB));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(
            parse_size("0"),
            None,
            "a zero size must not disable the alert"
        );
        assert_eq!(parse_size("0M"), None);
        assert_eq!(parse_size("M"), None);
        assert_eq!(parse_size("ten"), None);
        assert_eq!(parse_size("99999999999999999999G"), None);
    }

    /// The daemon reads the file the unit writes: a path edited on one side only would leave
    /// `rotation-stale` reporting on a file nothing touches.
    #[test]
    fn the_paths_the_daemon_reads_are_the_ones_the_shipped_unit_writes() {
        let unit = include_str!("../../../../../deploy/propolis-logrotate.service");
        assert!(
            unit.contains(&format!(
                "--state {LOGROTATE_STATE_PATH} {LOGROTATE_POLICY_PATH}"
            )),
            "ExecStart must pass the daemon's state and policy paths"
        );
        let provision = include_str!("../../../../../deploy/provision.sh");
        assert!(provision.contains(&format!("ensure_dir {SENSOR_LOG_ROOT} ")));
    }

    #[test]
    fn rotation_size_comes_from_the_shipped_policy() {
        let shipped = include_str!("../../../../../deploy/logrotate-sensors.conf");
        assert_eq!(rotation_size_from(shipped), Some(DEFAULT_ROTATION_SIZE));
        assert_eq!(
            rotation_size_from("# size 5M in a comment\n{\n    size 7M\n}\n"),
            Some(7 * MIB),
            "a comment is not the directive"
        );
        assert_eq!(rotation_size_from("{\n    rotate 5\n}\n"), None);
        assert_eq!(
            rotation_size("/nonexistent/policy".as_ref()),
            DEFAULT_ROTATION_SIZE
        );
    }

    #[test]
    fn a_log_fires_only_strictly_above_three_times_the_rotation_size() {
        let at = logs(&[("telnet", 300 * MIB)]);
        assert!(
            judge(false, 100 * MIB, &at, 10.0).is_empty(),
            "exactly 3x is rotation's overshoot"
        );
        let over = logs(&[("telnet", 300 * MIB + 1), ("ssh", 5 * MIB)]);
        let breach = judge(false, 100 * MIB, &over, 10.0);
        assert_eq!(breach.oversized, logs(&[("telnet", 300 * MIB + 1)]));
        assert_eq!(breach.disk_used_pct, None);
    }

    #[test]
    fn the_disk_fires_only_strictly_above_85_percent() {
        assert!(judge(false, 100 * MIB, &[], 85.0).is_empty());
        assert_eq!(judge(false, 100 * MIB, &[], 85.1).disk_used_pct, Some(85.1));
    }

    #[test]
    fn a_firing_log_clears_only_below_two_times_and_a_firing_disk_at_80() {
        // 250 MiB is under the 3x fire mark but over the 2x clear mark: a firing alert holds.
        let mid = logs(&[("telnet", 250 * MIB)]);
        assert!(judge(false, 100 * MIB, &mid, 10.0).is_empty());
        assert!(!judge(true, 100 * MIB, &mid, 10.0).is_empty());
        let low = logs(&[("telnet", 200 * MIB)]);
        assert!(judge(true, 100 * MIB, &low, 10.0).is_empty());
        // 82% is under the 85% fire mark but over the 80% clear mark.
        assert!(judge(false, 100 * MIB, &[], 82.0).is_empty());
        assert!(!judge(true, 100 * MIB, &[], 82.0).is_empty());
        assert!(judge(true, 100 * MIB, &[], 80.0).is_empty());
    }

    #[tokio::test]
    async fn it_names_the_oversized_log_then_holds_through_the_hysteresis_band_then_clears() {
        let tmp = tempfile::tempdir().unwrap();
        // Not the 100 MiB default, so a condition that ignored the policy file would disagree
        // with every threshold below: 150 MiB to fire, 100 MiB to clear.
        std::fs::write(tmp.path().join("policy"), "{\n    size 50M\n}\n").unwrap();
        let cond = SensorLogOversized::new();
        let ctx = ctx(rotation_in(tmp.path(), &["telnet", "ssh", "dns"]));

        make_log(tmp.path(), "telnet", 6_600_000_000);
        make_log(tmp.path(), "ssh", 5 * MIB);
        // "dns" has no file: a sensor that never logged is not a breach.
        match cond.assess(&ctx, 10.0) {
            Outcome::Firing { severity, detail } => {
                assert_eq!(
                    severity,
                    Severity::Warning,
                    "the disk is fine, rotation is not"
                );
                assert!(detail.contains("telnet 6.1 GiB"), "{detail}");
                assert!(detail.contains("50.0 MiB"), "{detail}");
                assert!(!detail.contains("ssh"), "{detail}");
            }
            other => panic!("expected the 6.6 GB telnet log to fire, got {other:?}"),
        }

        make_log(tmp.path(), "telnet", 120 * MIB);
        assert!(
            matches!(cond.assess(&ctx, 10.0), Outcome::Firing { .. }),
            "between the 2x and 3x marks a firing alert holds"
        );
        make_log(tmp.path(), "telnet", 90 * MIB);
        assert_eq!(cond.assess(&ctx, 10.0), Outcome::Ok);
        make_log(tmp.path(), "telnet", 120 * MIB);
        assert_eq!(
            cond.assess(&ctx, 10.0),
            Outcome::Ok,
            "once cleared, the 3x mark applies again"
        );
    }

    #[tokio::test]
    async fn a_full_log_volume_fires_critical_even_with_every_log_small() {
        let tmp = tempfile::tempdir().unwrap();
        make_log(tmp.path(), "ssh", MIB);
        let ctx = ctx(rotation_in(tmp.path(), &["ssh"]));
        let cond = SensorLogOversized::new();
        match cond.assess(&ctx, 91.0) {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Critical);
                assert!(detail.contains("91% used"), "{detail}");
                assert!(
                    !detail.contains("rotation size"),
                    "no log is oversized: {detail}"
                );
            }
            other => panic!("expected a 91% used volume to fire, got {other:?}"),
        }
        assert_eq!(cond.assess(&ctx, 70.0), Outcome::Ok);
    }

    #[tokio::test]
    async fn evaluate_measures_the_real_volume_and_never_calls_an_unstattable_one_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let used = used_pct(tmp.path()).unwrap();
        assert!((0.0..=100.0).contains(&used), "{used}");
        let mut rot = rotation_in(tmp.path(), &["ssh"]);
        rot.volume = "/nonexistent/volume".into();
        assert!(matches!(
            SensorLogOversized::new().evaluate(&ctx(rot)).await,
            Outcome::Unknown { why } if why.contains("statvfs")
        ));
    }

    #[tokio::test]
    async fn a_log_it_cannot_stat_is_unknown_not_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        // assess, not evaluate: the tempdir's real fullness must not decide this test.
        // A path under a regular file stats as ENOTDIR, not NotFound.
        std::fs::write(tmp.path().join("plain"), b"x").unwrap();
        let mut rot = rotation_in(tmp.path(), &["ssh"]);
        rot.logs[0].log_path = tmp.path().join("plain").join("events.jsonl");
        let cond = SensorLogOversized::new();
        assert!(matches!(
            cond.assess(&ctx(rot), 10.0),
            Outcome::Unknown { why } if why.contains("events.jsonl")
        ));
    }

    fn age_state(path: &Path, age: Duration) {
        std::fs::write(path, b"logrotate state -- version 2\n").unwrap();
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    #[tokio::test]
    async fn rotation_stale_fires_after_three_hours_and_clears_on_the_next_run() {
        let tmp = tempfile::tempdir().unwrap();
        let rot = rotation_in(tmp.path(), &["ssh"]);
        let state = rot.state_path.clone();
        let ctx = ctx(rot);

        assert!(
            matches!(RotationStale.evaluate(&ctx).await, Outcome::Unknown { why } if why.contains("never run")),
            "no state file: unknown, not firing and not healthy"
        );

        age_state(&state, Duration::from_secs(2 * 3600 + 59 * 60));
        assert_eq!(RotationStale.evaluate(&ctx).await, Outcome::Ok);

        age_state(&state, Duration::from_secs(3 * 3600 + 60));
        match RotationStale.evaluate(&ctx).await {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Warning);
                assert!(detail.contains("3 h"), "{detail}");
            }
            other => panic!("expected a 3 h old state file to fire, got {other:?}"),
        }

        age_state(&state, Duration::from_secs(60));
        assert_eq!(RotationStale.evaluate(&ctx).await, Outcome::Ok);
    }

    #[test]
    fn a_state_file_dated_in_the_future_is_not_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::write(&state, b"x").unwrap();
        let now = SystemTime::now() - Duration::from_secs(10 * 3600);
        assert_eq!(state_age(&state, now).unwrap(), Some(Duration::ZERO));
    }
}
