//! Alerts the dispatcher could not deliver, kept so they are retried and reported rather than lost.
//!
//! The dispatcher already retries a send for a couple of seconds. A transport that is down for
//! longer (ntfy unreachable, a DNS outage, a revoked token) used to end there: the monitor logged
//! one ERROR line and forgot the alert, and the debounce machine would not page again for a full
//! re-page cooldown. This queue keeps the alert, retries it on a slower backoff at the end of later
//! monitor ticks, and writes the queue to disk so a restart does not erase the fact that an alert
//! never arrived: the next run reports it (journal WARN and one summary alert).
//!
//! Newest state wins per condition key: a "recovered" notice replaces a queued page for the same
//! key, because the operator needs the current state, not the history.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::dispatch::{OpsAlert, Severity};

/// First retry delay after a failed delivery; doubles per failure up to [`RETRY_CAP`].
const RETRY_BASE: Duration = Duration::from_secs(30);
const RETRY_CAP: Duration = Duration::from_secs(900);
/// Queue bound: an outage that makes every condition fail cannot grow this without limit.
const MAX_ENTRIES: usize = 64;
/// Retries attempted per monitor tick at most; the monitor also caps the pass in wall-clock time
/// (`RETRY_PASS_BUDGET`) because a hung transport costs about two minutes per attempt.
pub const MAX_RETRIES_PER_TICK: usize = 4;
/// The state file is small; refuse to parse anything larger (it lives in a daemon-writable dir).
const MAX_STATE_BYTES: u64 = 256 * 1024;
const SUMMARY_MAX_ENTRIES: usize = 20;
const SUMMARY_FIELD_MAX: usize = 200;

/// File name of the persisted queue, inside the daemon's cursor directory.
pub const STATE_FILE: &str = "ops-alert-undelivered.json";

/// Key of the alert that reports alerts lost across a restart.
pub const LOST_ALERTS_KEY: &str = "alert-delivery-lost";

#[derive(Debug, Clone)]
struct Entry {
    alert: OpsAlert,
    first_failed_unix: u64,
    attempts: u32,
    last_error: String,
    next_retry: Instant,
}

/// What a previous run left undelivered, as read back from the state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {
    pub key: String,
    pub title: String,
    pub recovered: bool,
    pub first_failed_unix: u64,
    pub attempts: u32,
    pub last_error: String,
}

pub struct UndeliveredQueue {
    entries: BTreeMap<String, Entry>,
    path: Option<PathBuf>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn retry_delay(attempts: u32) -> Duration {
    let shift = attempts.saturating_sub(1).min(16);
    RETRY_BASE.saturating_mul(1u32 << shift).min(RETRY_CAP)
}

fn clip(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
}

impl UndeliveredQueue {
    /// A queue that is not persisted (tests, and a daemon with no state directory).
    pub fn in_memory() -> Self {
        Self {
            entries: BTreeMap::new(),
            path: None,
        }
    }

    /// A queue persisted at `path`. Returns what the previous run left there, and removes the file:
    /// the caller reports those and, if it cannot, they are not silently re-promised.
    pub fn persisted(path: PathBuf) -> (Self, Vec<Lost>) {
        let lost = read_state(&path);
        if path.exists()
            && let Err(e) = std::fs::remove_file(&path)
        {
            tracing::warn!(error = %e, path = %path.display(), "ops-alert: cannot clear the old undelivered-alert state");
        }
        (
            Self {
                entries: BTreeMap::new(),
                path: Some(path),
            },
            lost,
        )
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// An alert for `key` reached the operator (or was legitimately suppressed): any queued older
    /// state for the key is superseded.
    pub fn delivered(&mut self, key: &str) {
        if self.entries.remove(key).is_some() {
            self.persist();
        }
    }

    /// A delivery of `alert` failed with `why`. A first failure queues it for retry after
    /// [`RETRY_BASE`]; the same alert failing again lengthens the delay. A different state for a
    /// key already queued replaces it and restarts the count.
    pub fn failed(&mut self, alert: OpsAlert, why: String, now: Instant) {
        let key = alert.key.clone();
        let (first, attempts) = match self.entries.get(&key) {
            Some(prev)
                if prev.alert.recovered == alert.recovered && prev.alert.body == alert.body =>
            {
                (prev.first_failed_unix, prev.attempts.saturating_add(1))
            }
            _ => (unix_now(), 1),
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
            // Evict the oldest failure; say so, since an evicted alert is now only in the journal.
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.first_failed_unix)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
                tracing::warn!(dropped = %oldest, "ops-alert: undelivered-alert queue full, dropped the oldest");
            }
        }
        self.entries.insert(
            key,
            Entry {
                alert,
                first_failed_unix: first,
                attempts,
                last_error: clip(&why, SUMMARY_FIELD_MAX),
                next_retry: now + retry_delay(attempts),
            },
        );
        self.persist();
    }

    /// Queue `alert` to be sent on the next retry pass, as if it had just failed once with `why`
    /// long enough ago to be due (used for the post-restart summary).
    pub fn enqueue_due(&mut self, alert: OpsAlert, why: &str, now: Instant) {
        self.entries.insert(
            alert.key.clone(),
            Entry {
                alert,
                first_failed_unix: unix_now(),
                attempts: 0,
                last_error: clip(why, SUMMARY_FIELD_MAX),
                next_retry: now,
            },
        );
        self.persist();
    }

    /// Up to [`MAX_RETRIES_PER_TICK`] alerts whose retry time has come, with their attempt count.
    pub fn due(&self, now: Instant) -> Vec<(OpsAlert, u32)> {
        self.entries
            .values()
            .filter(|e| e.next_retry <= now)
            .take(MAX_RETRIES_PER_TICK)
            .map(|e| (e.alert.clone(), e.attempts))
            .collect()
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        if self.entries.is_empty() {
            if path.exists()
                && let Err(e) = std::fs::remove_file(path)
            {
                tracing::warn!(error = %e, "ops-alert: cannot remove the undelivered-alert state");
            }
            return;
        }
        let records: Vec<serde_json::Value> = self
            .entries
            .values()
            .map(|e| {
                serde_json::json!({
                    "key": e.alert.key,
                    "severity": match e.alert.severity {
                        Severity::Warning => "warning",
                        Severity::Critical => "critical",
                    },
                    "title": e.alert.title,
                    "recovered": e.alert.recovered,
                    "first_failed_unix": e.first_failed_unix,
                    "attempts": e.attempts,
                    "last_error": e.last_error,
                })
            })
            .collect();
        // The alert body is not persisted: it can carry attacker-influenced telemetry, and the
        // report after a restart needs only which alert, since when, and why it failed.
        if let Err(e) = write_atomic(path, &serde_json::Value::Array(records)) {
            tracing::warn!(error = %e, path = %path.display(), "ops-alert: cannot persist the undelivered-alert state");
        }
    }
}

fn write_atomic(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(value)?)?;
    std::fs::rename(&tmp, path)
}

fn read_state(path: &Path) -> Vec<Lost> {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    if let Err(e) = file.take(MAX_STATE_BYTES + 1).read_to_end(&mut raw) {
        tracing::warn!(error = %e, "ops-alert: cannot read the undelivered-alert state");
        return Vec::new();
    }
    if raw.len() as u64 > MAX_STATE_BYTES {
        tracing::warn!("ops-alert: the undelivered-alert state is oversized; ignoring it");
        return Vec::new();
    }
    let Ok(serde_json::Value::Array(items)) = serde_json::from_slice::<serde_json::Value>(&raw)
    else {
        tracing::warn!("ops-alert: the undelivered-alert state is not valid; ignoring it");
        return Vec::new();
    };
    items
        .iter()
        .take(MAX_ENTRIES)
        .filter_map(|v| {
            Some(Lost {
                key: clip(v.get("key")?.as_str()?, SUMMARY_FIELD_MAX),
                title: clip(v.get("title")?.as_str()?, SUMMARY_FIELD_MAX),
                recovered: v.get("recovered")?.as_bool()?,
                first_failed_unix: v.get("first_failed_unix")?.as_u64()?,
                attempts: u32::try_from(v.get("attempts")?.as_u64()?).unwrap_or(u32::MAX),
                last_error: clip(v.get("last_error")?.as_str()?, SUMMARY_FIELD_MAX),
            })
        })
        .collect()
}

/// The one alert that tells the operator what the previous run failed to deliver.
pub fn lost_alert(lost: &[Lost]) -> OpsAlert {
    let now = unix_now();
    let mut body = format!(
        "{} alert(s) were never delivered before the previous run ended:\n",
        lost.len()
    );
    for l in lost.iter().take(SUMMARY_MAX_ENTRIES) {
        let age_min = now.saturating_sub(l.first_failed_unix) / 60;
        body.push_str(&format!(
            "- {}{} (key {}), first failed {} min ago, {} attempt(s): {}\n",
            if l.recovered { "[recovered] " } else { "" },
            l.title,
            l.key,
            age_min,
            l.attempts,
            l.last_error
        ));
    }
    if lost.len() > SUMMARY_MAX_ENTRIES {
        body.push_str(&format!(
            "- and {} more\n",
            lost.len() - SUMMARY_MAX_ENTRIES
        ));
    }
    OpsAlert {
        key: LOST_ALERTS_KEY.to_string(),
        severity: Severity::Warning,
        title: "propolis: alerts were not delivered".to_string(),
        body,
        recovered: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(key: &str, recovered: bool) -> OpsAlert {
        OpsAlert {
            key: key.into(),
            severity: Severity::Critical,
            title: format!("propolis: {key}"),
            body: "detail".into(),
            recovered,
        }
    }

    #[test]
    fn backoff_doubles_from_the_base_and_stops_at_the_cap() {
        let secs: Vec<u64> = (1..=8).map(|n| retry_delay(n).as_secs()).collect();
        assert_eq!(secs, vec![30, 60, 120, 240, 480, 900, 900, 900]);
        assert_eq!(retry_delay(u32::MAX), RETRY_CAP, "no overflow at any count");
    }

    #[test]
    fn a_failed_alert_is_due_only_after_its_backoff_and_lengthens_on_repeat() {
        let mut q = UndeliveredQueue::in_memory();
        let t0 = Instant::now();
        q.failed(alert("capacity", false), "boom".into(), t0);
        assert!(q.due(t0 + Duration::from_secs(29)).is_empty());
        assert_eq!(q.due(t0 + Duration::from_secs(30)).len(), 1);
        // The same alert failing again waits twice as long.
        q.failed(
            alert("capacity", false),
            "boom".into(),
            t0 + Duration::from_secs(30),
        );
        assert!(q.due(t0 + Duration::from_secs(89)).is_empty());
        let due = q.due(t0 + Duration::from_secs(90));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1, 2, "attempt count carried");
    }

    #[test]
    fn a_newer_state_for_the_same_key_replaces_the_queued_one() {
        let mut q = UndeliveredQueue::in_memory();
        let t0 = Instant::now();
        q.failed(alert("capacity", false), "x".into(), t0);
        q.failed(alert("capacity", true), "x".into(), t0);
        assert_eq!(q.len(), 1);
        let due = q.due(t0 + Duration::from_secs(30));
        assert!(due[0].0.recovered, "the recovered notice is what remains");
        assert_eq!(due[0].1, 1, "a different state restarts the count");
        q.delivered("capacity");
        assert!(q.is_empty());
    }

    #[test]
    fn the_queue_is_bounded_and_drops_the_oldest() {
        let mut q = UndeliveredQueue::in_memory();
        let t0 = Instant::now();
        for i in 0..(MAX_ENTRIES + 10) {
            q.failed(alert(&format!("k{i:03}"), false), "x".into(), t0);
        }
        assert_eq!(q.len(), MAX_ENTRIES);
    }

    #[test]
    fn at_most_the_per_tick_cap_comes_due() {
        let mut q = UndeliveredQueue::in_memory();
        let t0 = Instant::now();
        for i in 0..10 {
            q.failed(alert(&format!("k{i}"), false), "x".into(), t0);
        }
        assert_eq!(
            q.due(t0 + Duration::from_secs(60)).len(),
            MAX_RETRIES_PER_TICK
        );
    }

    #[test]
    fn the_state_survives_a_restart_and_omits_the_alert_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("undelivered.json");
        let t0 = Instant::now();
        {
            let (mut q, lost) = UndeliveredQueue::persisted(path.clone());
            assert!(lost.is_empty(), "nothing before the first failure");
            let mut a = alert("capacity", false);
            a.body = "secret-ish telemetry /tmp/x".into();
            q.failed(a, "ntfy returned 503 after 4 attempts".into(), t0);
            q.failed(alert("sensor-down", true), "timeout".into(), t0);
        }
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("telemetry"),
            "the body is never written: {on_disk}"
        );

        let (q2, lost) = UndeliveredQueue::persisted(path.clone());
        assert!(q2.is_empty(), "the new run starts with an empty queue");
        assert!(!path.exists(), "the old state is consumed once read");
        let keys: Vec<&str> = lost.iter().map(|l| l.key.as_str()).collect();
        assert_eq!(keys, vec!["capacity", "sensor-down"]);
        assert_eq!(lost[0].last_error, "ntfy returned 503 after 4 attempts");
        assert!(lost[1].recovered);
    }

    #[test]
    fn delivering_the_last_entry_removes_the_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("undelivered.json");
        let (mut q, _) = UndeliveredQueue::persisted(path.clone());
        q.failed(alert("capacity", false), "x".into(), Instant::now());
        assert!(path.exists());
        q.delivered("capacity");
        assert!(
            !path.exists(),
            "an empty queue leaves no stale report behind"
        );
    }

    #[test]
    fn a_corrupt_or_oversized_state_file_is_ignored_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("undelivered.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(UndeliveredQueue::persisted(path.clone()).1.is_empty());
        std::fs::write(&path, vec![b' '; (MAX_STATE_BYTES + 10) as usize]).unwrap();
        assert!(UndeliveredQueue::persisted(path.clone()).1.is_empty());
        // Wrong-typed fields drop that record only.
        std::fs::write(
            &path,
            br#"[{"key":1},{"key":"ok","title":"t","recovered":false,"first_failed_unix":5,"attempts":2,"last_error":"e"}]"#,
        )
        .unwrap();
        let lost = UndeliveredQueue::persisted(path).1;
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].key, "ok");
    }

    #[test]
    fn the_lost_alert_lists_each_entry_with_age_attempts_and_reason() {
        let lost = vec![Lost {
            key: "capacity".into(),
            title: "propolis: capacity".into(),
            recovered: false,
            first_failed_unix: unix_now().saturating_sub(600),
            attempts: 5,
            last_error: "ntfy transport error".into(),
        }];
        let a = lost_alert(&lost);
        assert_eq!(a.key, LOST_ALERTS_KEY);
        assert!(!a.recovered);
        assert!(
            a.body.contains("1 alert(s) were never delivered"),
            "{}",
            a.body
        );
        assert!(a.body.contains("propolis: capacity (key capacity), first failed 10 min ago, 5 attempt(s): ntfy transport error"), "{}", a.body);
    }
}
