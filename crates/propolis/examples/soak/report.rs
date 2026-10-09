//! Line accounting (source lines against ledger rows, per sensor) and the PASS/FAIL evaluation.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sqlx::PgPool;

use crate::sample::{Point, percentile, sorted};
use crate::traffic::{Rotation, WriterLedger};

/// The explicit thresholds. Each is a flag of the same name on the command line; the defaults are
/// the acceptance bar for the long soak (`docs/development/intake-soak.md` explains each one).
#[derive(Clone, Debug)]
pub struct Thresholds {
    /// A sensor's steady-state 95th percentile of lag.
    pub lag_p95_secs: f64,
    /// The longest lag any steady-state sample of any sensor may show.
    pub lag_max_secs: f64,
    /// How long a sensor may take to first get under `lag_max_secs` (a prefilled backlog drains).
    pub catchup_secs: f64,
    /// Steady-state ingest rate as a fraction of the rate the writers produced.
    pub keep_up_ratio: f64,
    pub rss_max_mb: f64,
    /// Growth allowed between the first and last quarter of the steady state: last <= first *
    /// factor + slack. Skipped when the intake was restarted (RSS resets).
    pub rss_growth_factor: f64,
    pub rss_growth_slack_mb: f64,
    /// What a second writer queueing on the append lock waits, the lock-hold time it sees.
    pub lock_p95_ms: f64,
    pub lock_max_ms: f64,
    /// Lines a copytruncate may cost per rotation, as seconds of that sensor's traffic.
    pub rotation_loss_secs: f64,
    /// The longest a completed submission pass may be overdue.
    pub submit_gap_secs: f64,
    /// Duplicate ledger rows allowed per intake restart (the batch cap: the at-least-once price).
    pub dup_per_restart: u64,
    /// How long the final drain may take after the writers stop.
    pub drain_secs: f64,
}

#[derive(Clone, Debug, Default)]
pub struct SensorAccount {
    pub name: String,
    pub written: u64,
    pub rows: u64,
    pub distinct: u64,
    pub duplicates: u64,
    pub designed_written: u64,
    pub designed_missing: u64,
    pub blocked_behind_poison: u64,
    pub rotation_lost: u64,
    pub unexplained: u64,
    pub unexplained_in_rename_windows: u64,
    /// (rotation, lines lost) for every rotation, copytruncate or rename.
    pub per_rotation: Vec<(Rotation, u64)>,
    pub unexplained_ranges: Vec<(i64, i64)>,
    pub rejected_by_runner: u64,
    pub malformed_written: u64,
    pub rate_lps: f64,
}

struct Gaps {
    designed: Vec<u64>,
    malformed: Vec<u64>,
    poison_first: Option<u64>,
}

fn count_in(sorted_seqs: &[u64], a: i64, b: i64) -> u64 {
    if a > b {
        return 0;
    }
    let lo = sorted_seqs.partition_point(|&s| (s as i64) < a);
    let hi = sorted_seqs.partition_point(|&s| (s as i64) <= b);
    (hi - lo) as u64
}

/// Lines in `[a, b]` that are not designed absences.
fn non_designed(g: &Gaps, a: i64, b: i64) -> u64 {
    if a > b {
        return 0;
    }
    (b - a + 1) as u64 - count_in(&g.designed, a, b)
}

/// Splits every missing sequence number into: designed absences, blocked behind a poison line,
/// inside a copytruncate rotation window, and unexplained.
fn classify(acc: &mut SensorAccount, ledger: &WriterLedger, missing: &[(i64, i64)]) {
    let mut designed: Vec<u64> = ledger
        .malformed
        .iter()
        .chain(&ledger.overlength)
        .chain(&ledger.poison)
        .copied()
        .collect();
    designed.sort_unstable();
    let g = Gaps {
        designed,
        malformed: ledger.malformed.clone(),
        poison_first: ledger.poison.iter().copied().min(),
    };
    acc.designed_written = g.designed.len() as u64;
    acc.malformed_written = g.malformed.len() as u64;
    acc.per_rotation = ledger.rotations.iter().cloned().map(|r| (r, 0)).collect();

    for &(a, b) in missing {
        acc.designed_missing += count_in(&g.designed, a, b);
        let before_poison_end = match g.poison_first {
            Some(p) => {
                let lo = a.max(p as i64 + 1);
                acc.blocked_behind_poison += non_designed(&g, lo, b);
                b.min(p as i64)
            }
            None => b,
        };
        let mut rotation_nd = 0;
        for (rotation, lost) in acc.per_rotation.iter_mut() {
            let lo = a.max(rotation.first_seq as i64);
            let hi = before_poison_end.min(rotation.end_seq_exclusive as i64 - 1);
            let nd = non_designed(&g, lo, hi);
            if nd == 0 {
                continue;
            }
            *lost += nd;
            if rotation.copytruncate {
                rotation_nd += nd;
            } else {
                acc.unexplained_in_rename_windows += nd;
            }
        }
        acc.rotation_lost += rotation_nd;
        let total_nd = non_designed(&g, a, before_poison_end);
        let unexplained = total_nd - rotation_nd;
        if unexplained > 0 {
            acc.unexplained += unexplained;
            if acc.unexplained_ranges.len() < 8 {
                acc.unexplained_ranges.push((a, before_poison_end));
            }
        }
    }
}

/// Matches every line the writers produced for `run` against the ledger.
pub async fn account(
    pool: &PgPool,
    run: &str,
    writers: &[(String, u64, WriterLedger, f64)],
) -> Result<Vec<SensorAccount>, sqlx::Error> {
    // Both queries sort every row of the run (millions on a long soak); a larger work_mem keeps
    // the sort in memory. Transaction-local, so it changes nothing for other sessions.
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL work_mem = '256MB'")
        .execute(&mut *tx)
        .await?;
    type Totals = (String, i64, i64, Option<i64>, Option<i64>);
    let totals: Vec<Totals> = sqlx::query_as(
        "SELECT sensor, count(*), count(DISTINCT n), min(n), max(n) FROM \
         (SELECT sensor, (metadata->>'soak_seq')::bigint AS n FROM event \
          WHERE metadata->>'soak_run' = $1) t GROUP BY sensor",
    )
    .bind(run)
    .fetch_all(&mut *tx)
    .await?;
    let gaps: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT sensor, p + 1, n - 1 FROM \
         (SELECT sensor, n, lag(n) OVER (PARTITION BY sensor ORDER BY n) AS p FROM \
          (SELECT DISTINCT sensor, (metadata->>'soak_seq')::bigint AS n FROM event \
           WHERE metadata->>'soak_run' = $1) d) g \
         WHERE p IS NOT NULL AND n - p > 1 ORDER BY sensor, 2",
    )
    .bind(run)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;

    let mut accounts = Vec::new();
    for (name, written, ledger, rate) in writers {
        let mut acc = SensorAccount {
            name: name.clone(),
            written: *written,
            rate_lps: *rate,
            ..Default::default()
        };
        let mut missing: Vec<(i64, i64)> = Vec::new();
        match totals.iter().find(|t| &t.0 == name) {
            Some((_, rows, distinct, Some(min), Some(max))) => {
                acc.rows = *rows as u64;
                acc.distinct = *distinct as u64;
                acc.duplicates = acc.rows - acc.distinct;
                if *min > 0 {
                    missing.push((0, min - 1));
                }
                missing.extend(gaps.iter().filter(|g| &g.0 == name).map(|g| (g.1, g.2)));
                if (*max as u64) + 1 < *written {
                    missing.push((max + 1, *written as i64 - 1));
                }
            }
            _ => {
                if *written > 0 {
                    missing.push((0, *written as i64 - 1));
                }
            }
        }
        classify(&mut acc, ledger, &missing);
        accounts.push(acc);
    }
    Ok(accounts)
}

pub struct Check {
    pub name: &'static str,
    pub pass: bool,
    pub detail: String,
}

pub struct RunFacts {
    pub points: Vec<Point>,
    /// The reading taken after the writers stopped and the intake drained.
    pub final_point: Option<Point>,
    pub sensors: Vec<String>,
    pub restarts: u32,
    pub accounts: Vec<SensorAccount>,
    pub chain: String,
    pub chain_ok: bool,
    pub mid_chain: Vec<(f64, bool, f64)>,
    pub child_unexpected_exit: bool,
    pub harness_errors: Vec<String>,
    pub drained: bool,
    pub drain_took_secs: f64,
    pub faults: Vec<String>,
    pub duration_secs: f64,
    pub generated_lps: f64,
    pub rotations_copytruncate: usize,
    pub rotations_rename: usize,
}

/// The first sample at which `sensor` is caught up: its lag is within the steady-state p95 limit.
/// Everything from there on is judged against the steady-state limits, so a later spike (a
/// restart, a stall) counts against the run.
fn steady_start(points: &[Point], sensor: &str, th: &Thresholds) -> Option<usize> {
    points.iter().position(|p| {
        p.sensors
            .get(sensor)
            .and_then(|s| s.lag_secs)
            .is_some_and(|l| l <= th.lag_p95_secs)
    })
}

pub fn evaluate(th: &Thresholds, f: &RunFacts) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut push = |name: &'static str, pass: bool, detail: String| {
        checks.push(Check { name, pass, detail });
    };

    push(
        "harness healthy",
        f.harness_errors.is_empty() && !f.child_unexpected_exit,
        if f.harness_errors.is_empty() && !f.child_unexpected_exit {
            "writers, rotator and intake process ran to the end".into()
        } else {
            format!(
                "{}{}",
                f.harness_errors.join("; "),
                if f.child_unexpected_exit {
                    " intake process exited without being killed by a fault"
                } else {
                    ""
                }
            )
        },
    );

    // Catch-up and lag, per sensor.
    let mut catch = Vec::new();
    let mut lag_lines = Vec::new();
    let mut lag_ok = true;
    let mut caught_ok = true;
    let mut steady_all: usize = 0;
    for s in &f.sensors {
        match steady_start(&f.points, s, th) {
            None => {
                caught_ok = false;
                catch.push(format!("{s}: never under {:.0}s", th.lag_p95_secs));
            }
            Some(i) => {
                let t = f.points[i].t;
                if t > th.catchup_secs {
                    caught_ok = false;
                }
                catch.push(format!("{s}: {t:.0}s"));
                steady_all = steady_all.max(i);
                let lags = sorted(
                    f.points[i..]
                        .iter()
                        .filter_map(|p| p.sensors.get(s).and_then(|x| x.lag_secs))
                        .collect(),
                );
                let (p95, max) = (percentile(&lags, 0.95), percentile(&lags, 1.0));
                if p95 > th.lag_p95_secs || max > th.lag_max_secs {
                    lag_ok = false;
                }
                lag_lines.push(format!(
                    "{s}: p50 {:.1} p95 {:.1} max {:.1}",
                    percentile(&lags, 0.5),
                    p95,
                    max
                ));
            }
        }
    }
    push(
        "caught up",
        caught_ok,
        format!(
            "first sample with lag <= {:.0}s, which must come within {:.0}s of the start: {}",
            th.lag_p95_secs,
            th.catchup_secs,
            catch.join(", ")
        ),
    );
    push(
        "lag bounded",
        lag_ok && caught_ok,
        format!(
            "steady-state seconds, limits p95 <= {:.0} and max <= {:.0}: {}",
            th.lag_p95_secs,
            th.lag_max_secs,
            lag_lines.join("; ")
        ),
    );

    // The interval in which the last sensor finished catching up still carries catch-up load, so
    // the run-wide steady state (ingest rate, memory, lock wait) starts one sample later.
    let steady_all = if f.sensors.is_empty() {
        0
    } else {
        steady_all + 1
    };
    let steady: &[Point] = f.points.get(steady_all..).unwrap_or(&[]);
    let mean = |v: Vec<f64>| {
        if v.is_empty() {
            0.0
        } else {
            v.iter().sum::<f64>() / v.len() as f64
        }
    };
    let eps = mean(steady.iter().map(|p| p.ingest_eps).collect());
    let written = mean(steady.iter().map(|p| p.written_lps).collect());
    push(
        "keeps up",
        written > 0.0 && eps >= th.keep_up_ratio * written,
        format!(
            "steady-state ingest {eps:.0}/s against {written:.0}/s written (limit {:.0}% of written)",
            th.keep_up_ratio * 100.0
        ),
    );

    // Memory.
    let rss: Vec<f64> = f
        .points
        .iter()
        .filter_map(|p| p.rss_kb)
        .map(|k| k as f64 / 1024.0)
        .collect();
    let rss_max = rss.iter().cloned().fold(0.0, f64::max);
    let hwm = f
        .points
        .iter()
        .filter_map(|p| p.hwm_kb)
        .max()
        .map_or(0.0, |k| k as f64 / 1024.0);
    let steady_rss: Vec<f64> = steady
        .iter()
        .filter_map(|p| p.rss_kb)
        .map(|k| k as f64 / 1024.0)
        .collect();
    let (growth_ok, growth_text) = if f.restarts > 0 {
        (true, "growth not judged (intake restarted)".to_string())
    } else if steady_rss.len() < 8 {
        (
            true,
            "growth not judged (fewer than 8 steady samples)".to_string(),
        )
    } else {
        let q = steady_rss.len() / 4;
        let first = percentile(&sorted(steady_rss[..q].to_vec()), 0.5);
        let last = percentile(&sorted(steady_rss[steady_rss.len() - q..].to_vec()), 0.5);
        (
            last <= first * th.rss_growth_factor + th.rss_growth_slack_mb,
            format!(
                "first-quarter median {first:.0} MB, last-quarter median {last:.0} MB (limit x{:.1} + {:.0} MB)",
                th.rss_growth_factor, th.rss_growth_slack_mb
            ),
        )
    };
    push(
        "memory bounded",
        !rss.is_empty() && rss_max <= th.rss_max_mb && growth_ok,
        format!(
            "intake RSS max {rss_max:.0} MB (peak {hwm:.0} MB, limit {:.0} MB); {growth_text}",
            th.rss_max_mb
        ),
    );

    // Append lock.
    let lock_p95 = steady
        .iter()
        .filter(|p| p.lock_n > 0)
        .map(|p| p.lock_p95_ms)
        .fold(0.0, f64::max);
    let lock_max = steady
        .iter()
        .filter(|p| p.lock_n > 0)
        .map(|p| p.lock_max_ms)
        .fold(0.0, f64::max);
    let catching_up = f.points.get(..steady_all).unwrap_or(&[]);
    let catchup_lock_p95 = catching_up
        .iter()
        .filter(|p| p.lock_n > 0)
        .map(|p| p.lock_p95_ms)
        .fold(0.0, f64::max);
    push(
        "append lock wait",
        lock_p95 <= th.lock_p95_ms && lock_max <= th.lock_max_ms,
        format!(
            "steady state: worst per-interval p95 {lock_p95:.0} ms (limit {:.0}), max {lock_max:.0} ms (limit {:.0}); \
             while catching up (not judged): worst p95 {catchup_lock_p95:.0} ms",
            th.lock_p95_ms, th.lock_max_ms
        ),
    );

    // Wedge and append errors.
    let wedges: Vec<String> = f
        .points
        .iter()
        .flat_map(|p| {
            p.sensors
                .iter()
                .filter_map(|(n, s)| s.wedged.as_ref().map(|w| format!("{n}: {w}")))
        })
        .collect();
    push(
        "no wedge reported",
        wedges.is_empty(),
        match wedges.first() {
            None => "no sensor reported a wedge".into(),
            Some(first) => format!("first report: {first}"),
        },
    );
    let errors: u64 = f
        .final_point
        .as_ref()
        .map(|p| p.sensors.values().map(|s| s.errors).sum())
        .unwrap_or(0);
    push(
        "no append errors",
        errors == 0,
        format!("{errors} batches ended in an append error"),
    );

    // Line accounting.
    let mut acct_ok = true;
    let mut acct_lines = Vec::new();
    let mut dup_ok = true;
    let mut rot_ok = true;
    let mut rot_lines = Vec::new();
    let mut rejected_ok = true;
    let dup_allow = f.restarts as u64 * th.dup_per_restart;
    for a in &f.accounts {
        let present_designed = a.designed_written - a.designed_missing.min(a.designed_written);
        if a.unexplained > 0 || present_designed > 0 {
            acct_ok = false;
        }
        if a.duplicates > dup_allow {
            dup_ok = false;
        }
        let rejected_limit = a.malformed_written + dup_allow;
        if a.rejected_by_runner > rejected_limit {
            rejected_ok = false;
        }
        acct_lines.push(format!(
            "{}: written {} = ledger {} + designed-absent {} + rotation-lost {} + behind-poison {} + unexplained {} \
             (duplicates {}, designed lines ingested {}, runner rejected {} of {} malformed)",
            a.name,
            a.written,
            a.distinct,
            a.designed_missing,
            a.rotation_lost,
            a.blocked_behind_poison,
            a.unexplained,
            a.duplicates,
            present_designed,
            a.rejected_by_runner,
            a.malformed_written,
        ));
        if a.unexplained > 0 {
            acct_lines.push(format!(
                "  {} unexplained ranges (first): {:?}{}",
                a.name,
                a.unexplained_ranges,
                if a.unexplained_in_rename_windows > 0 {
                    format!(
                        "; {} of them inside rename-rotation windows",
                        a.unexplained_in_rename_windows
                    )
                } else {
                    String::new()
                }
            ));
        }
        let allowed = (a.rate_lps * th.rotation_loss_secs).ceil() as u64;
        for (rotation, lost) in &a.per_rotation {
            if rotation.copytruncate && *lost > allowed {
                rot_ok = false;
            }
        }
        let ct: Vec<u64> = a
            .per_rotation
            .iter()
            .filter(|(r, _)| r.copytruncate)
            .map(|(_, l)| *l)
            .collect();
        if !ct.is_empty() {
            rot_lines.push(format!(
                "{}: {} copytruncate rotations, lines lost per rotation {:?} (limit {allowed})",
                a.name,
                ct.len(),
                ct
            ));
        }
    }
    push(
        "no unexplained loss",
        acct_ok,
        acct_lines.join("\n          "),
    );
    push(
        "duplicates within at-least-once",
        dup_ok,
        format!(
            "ledger duplicates per sensor {:?}, allowed {} ({} restarts x {} batch cap)",
            f.accounts
                .iter()
                .map(|a| (a.name.as_str(), a.duplicates))
                .collect::<Vec<_>>(),
            dup_allow,
            f.restarts,
            th.dup_per_restart
        ),
    );
    push(
        "copytruncate loss within window",
        rot_ok,
        if rot_lines.is_empty() {
            "no copytruncate rotation happened".into()
        } else {
            rot_lines.join("; ")
        },
    );
    push(
        "rejects are the designed ones",
        rejected_ok,
        "the runner rejected no more lines than the malformed ones the writers produced".into(),
    );

    push(
        "final drain",
        f.drained,
        format!(
            "{} after {:.0}s (limit {:.0}s)",
            if f.drained {
                "every log read to its end"
            } else {
                "NOT drained"
            },
            f.drain_took_secs,
            th.drain_secs
        ),
    );
    push(
        "chain verifies",
        f.chain_ok && f.mid_chain.iter().all(|c| c.1),
        format!(
            "final: {}; mid-run walks: {}",
            f.chain,
            if f.mid_chain.is_empty() {
                "none".to_string()
            } else {
                f.mid_chain
                    .iter()
                    .map(|(t, ok, secs)| {
                        format!(
                            "t={t:.0}s {} in {secs:.1}s",
                            if *ok { "intact" } else { "BROKEN" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
    );

    // Submission loop.
    let worst_overdue = steady
        .iter()
        .filter_map(|p| p.secs_since_pass)
        .fold(0.0, f64::max);
    let last = f.final_point.as_ref().or(f.points.last());
    let passes = last.map_or(0, |p| p.passes);
    let pass_max = f.points.iter().map(|p| p.pass_ms_max).max().unwrap_or(0);
    push(
        "submission passes keep flowing",
        passes > 0 && worst_overdue <= th.submit_gap_secs,
        format!(
            "{passes} passes, worst overdue {worst_overdue:.0}s (limit {:.0}s), longest pass {pass_max} ms; \
             approved {}, submitted {}, vendor calls {} (the gatekeeper holds the documentation-range sources, so no call is expected)",
            th.submit_gap_secs,
            last.map_or(0, |p| p.approved),
            last.map_or(0, |p| p.submitted),
            last.map_or(0, |p| p.vendor_calls),
        ),
    );
    checks
}

pub fn render(th: &Thresholds, f: &RunFacts, checks: &[Check]) -> String {
    let mut out = String::new();
    let pass = checks.iter().all(|c| c.pass);
    let _ = writeln!(out, "SOAK REPORT: {}", if pass { "PASS" } else { "FAIL" });
    let _ = writeln!(
        out,
        "duration {:.0}s, generated {:.0} lines/s, intake restarts {}, faults [{}], copytruncate rotations {}, rename rotations {}",
        f.duration_secs,
        f.generated_lps,
        f.restarts,
        f.faults.join(", "),
        f.rotations_copytruncate,
        f.rotations_rename,
    );
    let _ = writeln!(out, "thresholds: {th:?}");
    for c in checks {
        let _ = writeln!(
            out,
            "  [{}] {}: {}",
            if c.pass { "PASS" } else { "FAIL" },
            c.name,
            c.detail
        );
    }
    let mut by_sensor: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for a in &f.accounts {
        by_sensor.insert(&a.name, (a.written, a.distinct));
    }
    let _ = writeln!(
        out,
        "per-sensor (written, distinct ledger rows): {by_sensor:?}"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rotation(copytruncate: bool, first: u64, end: u64) -> Rotation {
        Rotation {
            copytruncate,
            first_seq: first,
            end_seq_exclusive: end,
        }
    }

    fn classified(ledger: &WriterLedger, missing: &[(i64, i64)]) -> SensorAccount {
        let mut acc = SensorAccount::default();
        classify(&mut acc, ledger, missing);
        acc
    }

    #[test]
    fn a_gap_inside_a_copytruncate_window_is_rotation_loss_and_nothing_else() {
        let ledger = WriterLedger {
            rotations: vec![rotation(true, 100, 200)],
            ..Default::default()
        };
        let acc = classified(&ledger, &[(150, 170)]);
        assert_eq!((acc.rotation_lost, acc.unexplained), (21, 0));
        assert_eq!(acc.per_rotation[0].1, 21);
    }

    #[test]
    fn a_gap_that_straddles_the_window_edge_loses_only_the_inside_to_rotation() {
        let ledger = WriterLedger {
            rotations: vec![rotation(true, 100, 200)],
            ..Default::default()
        };
        let acc = classified(&ledger, &[(190, 209)]);
        assert_eq!((acc.rotation_lost, acc.unexplained), (10, 10));
        assert_eq!(acc.unexplained_ranges, vec![(190, 209)]);
    }

    #[test]
    fn a_gap_in_a_rename_window_is_unexplained_because_the_old_inode_stays_readable() {
        let ledger = WriterLedger {
            rotations: vec![rotation(false, 0, 100)],
            ..Default::default()
        };
        let acc = classified(&ledger, &[(10, 14)]);
        assert_eq!(
            (
                acc.rotation_lost,
                acc.unexplained,
                acc.unexplained_in_rename_windows
            ),
            (0, 5, 5)
        );
    }

    #[test]
    fn designed_absences_are_not_counted_twice_inside_a_rotation_window() {
        let ledger = WriterLedger {
            malformed: vec![120],
            overlength: vec![130],
            rotations: vec![rotation(true, 100, 200)],
            ..Default::default()
        };
        let acc = classified(&ledger, &[(110, 139)]);
        assert_eq!(acc.designed_missing, 2);
        assert_eq!(acc.rotation_lost, 28);
        assert_eq!(acc.unexplained, 0);
    }

    #[test]
    fn everything_behind_a_poison_line_is_blocked_not_lost() {
        let ledger = WriterLedger {
            poison: vec![50],
            malformed: vec![70],
            ..Default::default()
        };
        let acc = classified(&ledger, &[(50, 99)]);
        assert_eq!(acc.designed_missing, 2);
        assert_eq!(acc.blocked_behind_poison, 48);
        assert_eq!(acc.unexplained, 0);
    }

    #[test]
    fn a_missing_line_with_no_cause_is_unexplained() {
        let acc = classified(&WriterLedger::default(), &[(7, 7), (20, 22)]);
        assert_eq!(acc.unexplained, 4);
    }

    #[test]
    fn the_threshold_names_every_check_in_the_report() {
        let facts = RunFacts {
            points: Vec::new(),
            final_point: None,
            sensors: vec!["telnet".into()],
            restarts: 0,
            accounts: Vec::new(),
            chain: "Intact".into(),
            chain_ok: true,
            mid_chain: Vec::new(),
            child_unexpected_exit: false,
            harness_errors: Vec::new(),
            drained: true,
            drain_took_secs: 1.0,
            faults: Vec::new(),
            duration_secs: 1.0,
            generated_lps: 0.0,
            rotations_copytruncate: 0,
            rotations_rename: 0,
        };
        let th = Thresholds {
            lag_p95_secs: 10.0,
            lag_max_secs: 60.0,
            catchup_secs: 600.0,
            keep_up_ratio: 0.9,
            rss_max_mb: 1024.0,
            rss_growth_factor: 1.5,
            rss_growth_slack_mb: 64.0,
            lock_p95_ms: 500.0,
            lock_max_ms: 2000.0,
            rotation_loss_secs: 5.0,
            submit_gap_secs: 120.0,
            dup_per_restart: 1000,
            drain_secs: 120.0,
        };
        // A run that never sampled anything must not read as healthy.
        let checks = evaluate(&th, &facts);
        let failed: Vec<&str> = checks.iter().filter(|c| !c.pass).map(|c| c.name).collect();
        assert!(failed.contains(&"caught up"), "{failed:?}");
        assert!(failed.contains(&"memory bounded"), "{failed:?}");
        assert!(
            failed.contains(&"submission passes keep flowing"),
            "{failed:?}"
        );
    }
}
