//! Condition #5: a threat-intel vendor is persistently rejecting our submissions - our reports are
//! not landing, so the feed's outbound value is silently degraded.
//!
//! The signal comes from `vendor_submission` (written on every gate-passed submit: `vendor`,
//! `submitted_at`, `success`), so no separate outcome log is needed. Because that table is
//! idempotent per (ip, vendor, day), the rate measures the fraction of distinct recently-submitted
//! IPs currently failing for a vendor - a persistent-failure signal that a retry storm cannot inflate.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::Row;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// The failure rate over the window is only meaningful once enough submissions have accrued; a short
/// hold then damps flap when the rate hovers at the threshold.
const VENDOR_HOLD: Duration = Duration::from_secs(300);

/// Firing test, split from I/O. Fires only with at least `min_samples` submissions AND a failure
/// fraction strictly over `pct` percent. Integer math (no float) avoids rounding at the boundary.
fn over_fail_threshold(fails: u64, total: u64, min_samples: u32, pct: u8) -> bool {
    total >= min_samples as u64 && fails * 100 > total * pct as u64
}

/// #5: persistent vendor submission failures.
pub struct VendorFailures;

#[async_trait]
impl Condition for VendorFailures {
    fn id(&self) -> &'static str {
        "vendor-failures"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        VENDOR_HOLD
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let interval = format!("{} seconds", ctx.cfg.vendor_window.as_secs());
        let rows = match sqlx::query(
            "SELECT vendor, \
                    count(*) FILTER (WHERE NOT success) AS fails, \
                    count(*) AS total \
             FROM vendor_submission \
             WHERE submitted_at > now() - $1::interval \
             GROUP BY vendor",
        )
        .bind(&interval)
        .fetch_all(&ctx.pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                return Outcome::Unknown {
                    why: format!("vendor_submission window query: {e}"),
                };
            }
        };

        // Track the worst offender past the threshold, by failure fraction.
        let mut worst: Option<(String, u64, u64)> = None;
        for row in &rows {
            let vendor: String = match row.try_get("vendor") {
                Ok(v) => v,
                Err(e) => {
                    return Outcome::Unknown {
                        why: format!("vendor column: {e}"),
                    };
                }
            };
            let fails: i64 = match row.try_get("fails") {
                Ok(v) => v,
                Err(e) => {
                    return Outcome::Unknown {
                        why: format!("fails column: {e}"),
                    };
                }
            };
            let total: i64 = match row.try_get("total") {
                Ok(v) => v,
                Err(e) => {
                    return Outcome::Unknown {
                        why: format!("total column: {e}"),
                    };
                }
            };
            let (fails, total) = (fails.max(0) as u64, total.max(0) as u64);
            if over_fail_threshold(
                fails,
                total,
                ctx.cfg.vendor_min_samples,
                ctx.cfg.vendor_fail_pct,
            ) {
                let worse = worst.as_ref().is_none_or(|(_, wf, wt)| {
                    // Compare fractions by cross-multiplication (no float).
                    fails * wt > *wf * total
                });
                if worse {
                    worst = Some((vendor, fails, total));
                }
            }
        }

        match worst {
            Some((vendor, fails, total)) => Outcome::Firing {
                severity: Severity::Warning,
                detail: format!(
                    "vendor {vendor} failing {fails}/{total} submissions ({}%) over the last {}s",
                    fails * 100 / total,
                    ctx.cfg.vendor_window.as_secs()
                ),
            },
            None => Outcome::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u32 = 20;
    const PCT: u8 = 50;

    #[test]
    fn below_min_samples_never_fires() {
        // 100% failing but only 15 samples: not enough evidence.
        assert!(!over_fail_threshold(15, 15, MIN, PCT));
    }

    #[test]
    fn below_the_pct_does_not_fire() {
        // 5/20 = 25% <= 50%.
        assert!(!over_fail_threshold(5, 20, MIN, PCT));
    }

    #[test]
    fn exactly_at_the_pct_does_not_fire() {
        // 10/20 = exactly 50%, strict threshold.
        assert!(!over_fail_threshold(10, 20, MIN, PCT));
    }

    #[test]
    fn over_both_thresholds_fires() {
        assert!(over_fail_threshold(11, 20, MIN, PCT)); // 55%, 20 samples
        assert!(over_fail_threshold(20, 20, MIN, PCT)); // 100%, at min samples
    }
}
