//! One sampling interval's measurements, and the /proc readers behind them.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

#[derive(Clone, Debug, Default)]
pub struct SensorPoint {
    pub ingested: u64,
    pub rejected: u64,
    pub errors: u64,
    pub bytes_behind: u64,
    /// Seconds since the `observed_at` of the last event the intake appended for this sensor.
    /// Every sensor writes continuously during a soak, so this is how stale the sensor's ledger
    /// rows are; it is also the longest an unread line can have waited.
    pub lag_secs: Option<f64>,
    pub wedged: Option<String>,
    pub batch_mean_ms: f64,
    pub batch_max_ms: f64,
    pub log_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Point {
    pub t: f64,
    pub at: Option<DateTime<Utc>>,
    pub sensors: BTreeMap<String, SensorPoint>,
    pub rss_kb: Option<u64>,
    pub hwm_kb: Option<u64>,
    pub cpu_pct: Option<f64>,
    pub orch_rss_kb: Option<u64>,
    pub ingest_eps: f64,
    pub written_lps: f64,
    pub lock_n: usize,
    pub lock_p50_ms: f64,
    pub lock_p95_ms: f64,
    pub lock_max_ms: f64,
    pub ledger_bytes: i64,
    pub ledger_max_id: i64,
    pub passes: u64,
    pub secs_since_pass: Option<f64>,
    pub pass_ms_max: u64,
    pub submitted: u64,
    pub held: u64,
    pub vendor_calls: u64,
    pub approved: u64,
    pub child_alive: bool,
    pub restarts: u32,
}

impl Point {
    pub fn to_json(&self) -> Value {
        let sensors: serde_json::Map<String, Value> = self
            .sensors
            .iter()
            .map(|(name, s)| {
                (
                    name.clone(),
                    json!({
                        "ingested": s.ingested,
                        "rejected": s.rejected,
                        "errors": s.errors,
                        "bytes_behind": s.bytes_behind,
                        "lag_secs": s.lag_secs,
                        "wedged": s.wedged,
                        "batch_mean_ms": s.batch_mean_ms,
                        "batch_max_ms": s.batch_max_ms,
                        "log_bytes": s.log_bytes,
                    }),
                )
            })
            .collect();
        json!({
            "t": self.t,
            "at": self.at.map(|a| a.to_rfc3339()),
            "sensors": sensors,
            "rss_kb": self.rss_kb,
            "hwm_kb": self.hwm_kb,
            "cpu_pct": self.cpu_pct,
            "orch_rss_kb": self.orch_rss_kb,
            "ingest_eps": self.ingest_eps,
            "written_lps": self.written_lps,
            "lock_wait_ms": { "n": self.lock_n, "p50": self.lock_p50_ms, "p95": self.lock_p95_ms, "max": self.lock_max_ms },
            "ledger_bytes": self.ledger_bytes,
            "ledger_max_id": self.ledger_max_id,
            "review": {
                "passes": self.passes,
                "secs_since_pass": self.secs_since_pass,
                "pass_ms_max": self.pass_ms_max,
                "submitted": self.submitted,
                "held": self.held,
                "vendor_calls": self.vendor_calls,
                "approved": self.approved,
            },
            "child_alive": self.child_alive,
            "restarts": self.restarts,
        })
    }

    /// The one-line console form.
    pub fn line(&self) -> String {
        let lag = |name: &str| {
            self.sensors
                .get(name)
                .and_then(|s| s.lag_secs)
                .map_or("-".to_string(), |l| format!("{l:.1}"))
        };
        let behind_mb: f64 = self
            .sensors
            .values()
            .map(|s| s.bytes_behind as f64)
            .sum::<f64>()
            / 1e6;
        let wedged = self.sensors.values().filter(|s| s.wedged.is_some()).count();
        format!(
            "t={:>5.0}s eps={:>7.0} written={:>7.0}/s lag[telnet={} ssh={} http={} cred={} adb={}]s behind={:.1}MB \
             rss={}MB cpu={}% lockwait[p95={:.0} max={:.0}]ms ledger={:.0}MB pass={}({}s ago) wedged={} restarts={}{}",
            self.t,
            self.ingest_eps,
            self.written_lps,
            lag("telnet"),
            lag("ssh"),
            lag("http"),
            lag("cred"),
            lag("adb"),
            behind_mb,
            self.rss_kb
                .map_or("-".to_string(), |k| (k / 1024).to_string()),
            self.cpu_pct.map_or("-".to_string(), |c| format!("{c:.0}")),
            self.lock_p95_ms,
            self.lock_max_ms,
            self.ledger_bytes as f64 / 1e6,
            self.passes,
            self.secs_since_pass
                .map_or("-".to_string(), |s| format!("{s:.0}")),
            wedged,
            self.restarts,
            if self.child_alive { "" } else { " CHILD-DOWN" },
        )
    }
}

pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub fn sorted(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_by(|a, b| a.total_cmp(b));
    values
}

/// A `Vm*` line of `/proc/<pid>/status`, in kB.
pub fn proc_status_kb(pid: &str, key: &str) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
}

/// utime + stime of a process in clock ticks (`CLK_TCK` is 100 on Linux).
pub fn proc_cpu_ticks(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = text.rsplit_once(") ")?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
}
