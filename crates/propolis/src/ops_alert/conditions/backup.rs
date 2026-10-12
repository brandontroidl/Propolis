//! `backup-stale`: no good backup (`deploy/backup.sh`, run nightly by propolis-backup.timer and by
//! upgrade.sh) for longer than `backup_max_age`. Reads the status files the script writes:
//! `last-success` (rewritten after every good run) and `last-failure` (written by a failed run,
//! removed by the next good one), both root-written and world-readable.
//!
//! Before the first good run there is nothing to measure an age from, so the status directory's own
//! age stands in: `deploy/provision.sh` creates it when the timer is installed, so a node that has
//! had the timer longer than the limit and still no good backup pages, while a node installed an
//! hour ago does not.

use std::path::Path;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// Where `deploy/backup.sh` writes its status (its `STATUS_DIR`).
pub const BACKUP_STATUS_DIR: &str = "/var/lib/propolis/backup-status";

/// The value of `"key":"value"` in one of the script's one-line JSON status files. The files are
/// written by the script's own printf with fixed keys, so a field reader is all that is needed.
fn field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":\"");
    let start = json.find(&marker)? + marker.len();
    let len = json[start..].find('"')?;
    Some(&json[start..start + len])
}

fn age_of(timestamp: &str, now: SystemTime) -> Option<Duration> {
    let then = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let then = SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(then.timestamp()).ok()?);
    Some(now.duration_since(then).unwrap_or(Duration::ZERO))
}

/// The outcome for the status directory `dir` at `now`.
fn backup_outcome(dir: &Path, max_age: Duration, now: SystemTime) -> Outcome {
    let dir_meta = match std::fs::metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Outcome::Unknown {
                why: format!(
                    "{} does not exist: the backup timer is not installed on this node",
                    dir.display()
                ),
            };
        }
        Err(e) => {
            return Outcome::Unknown {
                why: format!("{}: {e}", dir.display()),
            };
        }
    };
    let failure = std::fs::read_to_string(dir.join("last-failure")).ok();
    let failed_step = failure
        .as_deref()
        .and_then(|f| field(f, "step"))
        .map(|s| format!(" The last run failed while {s}."))
        .unwrap_or_default();
    let fix = "Check `systemctl status propolis-backup.service` and `journalctl -u propolis-backup.service`.";
    let limit_h = max_age.as_secs() / 3600;

    match std::fs::read_to_string(dir.join("last-success")) {
        Ok(success) => match field(&success, "completed_at").and_then(|t| age_of(t, now)) {
            Some(age) if age > max_age => Outcome::Firing {
                severity: Severity::Warning,
                detail: format!(
                    "no good backup for {} h (limit {limit_h} h; last set {}).{failed_step} {fix}",
                    age.as_secs() / 3600,
                    field(&success, "set").unwrap_or("unknown")
                ),
            },
            Some(_) => Outcome::Ok,
            None => Outcome::Unknown {
                why: format!(
                    "{} has no readable completed_at",
                    dir.join("last-success").display()
                ),
            },
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let installed_for = dir_meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or(Duration::ZERO);
            if installed_for > max_age || failure.is_some() {
                Outcome::Firing {
                    severity: Severity::Warning,
                    detail: format!(
                        "no backup has ever completed on this node.{failed_step} {fix}"
                    ),
                }
            } else {
                Outcome::Ok
            }
        }
        Err(e) => Outcome::Unknown {
            why: format!("{}: {e}", dir.join("last-success").display()),
        },
    }
}

/// `backup-stale`.
pub struct BackupStale;

#[async_trait]
impl Condition for BackupStale {
    fn id(&self) -> &'static str {
        "backup-stale"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // The age limit is the debounce: it already spans a missed night.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        backup_outcome(
            &ctx.backup_status_dir,
            ctx.cfg.backup_max_age,
            SystemTime::now(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);
    const LIMIT: Duration = Duration::from_secs(129_600);

    fn success(at: &str) -> String {
        format!(
            "{{\"completed_at\":\"{at}\",\"reason\":\"scheduled\",\"set\":\"20261010T033000Z-scheduled\",\"encrypted\":true,\"dump_bytes\":1,\"archive_bytes\":1}}\n"
        )
    }

    fn at(timestamp: &str) -> SystemTime {
        let t = chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
        SystemTime::UNIX_EPOCH + Duration::from_secs(t.timestamp() as u64)
    }

    #[test]
    fn a_recent_backup_is_ok_and_a_stale_one_fires_with_the_failed_step() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("last-success"),
            success("2026-10-10T03:31:00Z"),
        )
        .unwrap();
        assert_eq!(
            backup_outcome(dir.path(), LIMIT, at("2026-10-11T03:31:00Z")),
            Outcome::Ok,
            "a day old is within 36 h"
        );
        std::fs::write(
            dir.path().join("last-failure"),
            "{\"failed_at\":\"2026-10-11T03:31:00Z\",\"reason\":\"scheduled\",\"step\":\"checking free space\",\"exit_code\":1}\n",
        )
        .unwrap();
        match backup_outcome(dir.path(), LIMIT, at("2026-10-12T03:31:00Z")) {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Warning);
                assert!(detail.contains("48 h"), "{detail}");
                assert!(detail.contains("checking free space"), "{detail}");
                assert!(detail.contains("20261010T033000Z-scheduled"), "{detail}");
            }
            other => panic!("expected Firing, got {other:?}"),
        }
    }

    #[test]
    fn before_the_first_backup_the_directory_age_decides() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        assert_eq!(
            backup_outcome(dir.path(), LIMIT, now),
            Outcome::Ok,
            "a node installed moments ago has not missed a night"
        );
        assert!(
            matches!(
                backup_outcome(dir.path(), LIMIT, now + 2 * DAY),
                Outcome::Firing { .. }
            ),
            "two days with the timer and no backup pages"
        );
        std::fs::write(
            dir.path().join("last-failure"),
            "{\"failed_at\":\"x\",\"reason\":\"scheduled\",\"step\":\"dumping the database\",\"exit_code\":1}\n",
        )
        .unwrap();
        match backup_outcome(dir.path(), LIMIT, now) {
            Outcome::Firing { detail, .. } => assert!(detail.contains("dumping the database")),
            other => panic!("a first run that failed pages at once, got {other:?}"),
        }
    }

    #[test]
    fn no_status_directory_is_unknown_and_a_garbled_file_is_unknown() {
        let missing = Path::new("/nonexistent/backup-status");
        assert!(backup_outcome(missing, LIMIT, SystemTime::now()).is_unknown());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("last-success"), "{}\n").unwrap();
        assert!(backup_outcome(dir.path(), LIMIT, SystemTime::now()).is_unknown());
    }
}
