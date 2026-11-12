//! Condition #3: the volume backing Postgres or the sensor spool is running low on free space.
//! The binding signal is `statvfs` free-percentage on each volume; `pg_database_size` is best-effort
//! context that a query hiccup must never let mask the disk alarm.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use nix::sys::statvfs::statvfs;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// Disk-full is not a momentary blip, but a temp-file spike that clears on its own should not page;
/// hold the firing state briefly before alerting.
const CAPACITY_HOLD: Duration = Duration::from_secs(120);

/// Free percentage of the filesystem containing `path`, or an error string. `f_bavail / f_blocks`
/// (the fragment size cancels), i.e. space available to an unprivileged writer.
fn volume_free_pct(path: &Path) -> Result<f64, String> {
    let st = statvfs(path).map_err(|e| format!("statvfs {}: {e}", path.display()))?;
    let total = st.blocks();
    if total == 0 {
        // A pseudo-filesystem reporting zero blocks cannot be "full"; do not fire on it.
        return Ok(100.0);
    }
    Ok(st.blocks_available() as f64 / total as f64 * 100.0)
}

/// The lower of the two volumes' free percentages - the binding constraint.
fn worst_free_pct(pg_free: f64, spool_free: f64) -> f64 {
    pg_free.min(spool_free)
}

/// Below-threshold test, split out so the boundary is unit-tested without a filesystem.
fn is_low(worst_free: f64, threshold_pct: u8) -> bool {
    worst_free < threshold_pct as f64
}

fn human_bytes(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

async fn pg_database_size(pool: &sqlx::PgPool) -> Option<i64> {
    sqlx::query_scalar::<_, i64>("SELECT pg_database_size(current_database())")
        .fetch_one(pool)
        .await
        .ok()
}

/// #3: low free space on the pg data volume or the sensor spool volume.
pub struct Capacity;

#[async_trait]
impl Condition for Capacity {
    fn id(&self) -> &'static str {
        "capacity"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        CAPACITY_HOLD
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let pg_free = match volume_free_pct(&ctx.pg_data_volume) {
            Ok(p) => p,
            Err(why) => return Outcome::Unknown { why },
        };
        let spool_free = match volume_free_pct(&ctx.spool_dir) {
            Ok(p) => p,
            Err(why) => return Outcome::Unknown { why },
        };
        let worst = worst_free_pct(pg_free, spool_free);
        if !is_low(worst, ctx.cfg.capacity_free_pct) {
            return Outcome::Ok;
        }
        // Enrichment only: a DB-size query failure must not blind the disk alarm.
        let db_ctx = match pg_database_size(&ctx.pool).await {
            Some(bytes) => format!(", db {}", human_bytes(bytes)),
            None => String::new(),
        };
        Outcome::Firing {
            severity: Severity::Critical,
            detail: format!(
                "low disk: {} {pg_free:.1}% free, {} {spool_free:.1}% free (threshold {}%){db_ctx}",
                ctx.pg_data_volume.display(),
                ctx.spool_dir.display(),
                ctx.cfg.capacity_free_pct
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_free_pct_picks_the_lower_volume() {
        assert_eq!(worst_free_pct(20.0, 5.0), 5.0);
        assert_eq!(worst_free_pct(3.0, 50.0), 3.0);
        assert_eq!(worst_free_pct(15.0, 15.0), 15.0);
    }

    #[test]
    fn is_low_boundary_is_exclusive_at_the_threshold() {
        // Exactly at the threshold is still OK; only strictly below fires.
        assert!(!is_low(15.0, 15));
        assert!(is_low(14.9, 15));
        assert!(!is_low(100.0, 15));
        assert!(is_low(0.0, 15));
    }

    #[test]
    fn volume_free_pct_reads_a_real_volume_and_errors_on_a_bogus_path() {
        let root = volume_free_pct(Path::new("/")).expect("root volume is statable");
        assert!(
            (0.0..=100.0).contains(&root),
            "free pct in range, got {root}"
        );
        assert!(volume_free_pct(Path::new("/nonexistent/does/not/exist")).is_err());
    }

    #[test]
    fn human_bytes_scales_units() {
        assert_eq!(human_bytes(512), "512.0 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
