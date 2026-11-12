//! Condition #6: the malware fetcher's pending queue is large and still growing. A large-but-
//! draining backlog (the fetcher catching up after a burst) must NOT page; only a backlog that is
//! both over the cap and higher than it was a full `backlog_for` window ago fires.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// Require the backlog to stay large-and-rising for this long before paging, damping flap when the
/// count hovers around its window-ago level.
const BACKLOG_HOLD: Duration = Duration::from_secs(300);

/// Keep at most this many samples; at a 30s poll and a 15m window this is ~60, the cap is a backstop.
const MAX_SAMPLES: usize = 256;

/// Firing test, split from I/O. `history` is prior `(sampled_at, count)` points (current excluded).
/// Fires when `count > max` AND `count` exceeds the most recent sample that is at least `window`
/// old. With no sample that old yet (fewer than `window` of history), it cannot judge rising, so it
/// stays quiet (startup grace).
fn is_growing_over_threshold(
    history: &[(Instant, u64)],
    now: Instant,
    count: u64,
    max: u64,
    window: Duration,
) -> bool {
    if count <= max {
        return false;
    }
    let reference = history
        .iter()
        .filter(|(t, _)| now.duration_since(*t) >= window)
        .max_by_key(|(t, _)| *t)
        .map(|(_, c)| *c);
    match reference {
        Some(c0) => count > c0,
        None => false,
    }
}

/// Append the current sample and drop anything older than two windows (plus a hard length cap).
fn record(history: &mut Vec<(Instant, u64)>, now: Instant, count: u64, window: Duration) {
    history.push((now, count));
    if let Some(cutoff) = now.checked_sub(window * 2) {
        history.retain(|(t, _)| *t >= cutoff);
    }
    if history.len() > MAX_SAMPLES {
        let excess = history.len() - MAX_SAMPLES;
        history.drain(0..excess);
    }
}

/// #6: fetcher pending queue over the cap and growing.
pub struct Backlog {
    history: Mutex<Vec<(Instant, u64)>>,
}

impl Backlog {
    pub fn new() -> Self {
        Self {
            history: Mutex::new(Vec::new()),
        }
    }
}

impl Default for Backlog {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Condition for Backlog {
    fn id(&self) -> &'static str {
        "fetcher-backlog"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        BACKLOG_HOLD
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let count: i64 =
            match sqlx::query_scalar("SELECT COUNT(*) FROM fetch_attempt WHERE status = 'pending'")
                .fetch_one(&ctx.pool)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    return Outcome::Unknown {
                        why: format!("fetch_attempt pending count: {e}"),
                    };
                }
            };
        let count = count.max(0) as u64;
        let now = Instant::now();
        let window = ctx.cfg.backlog_for;
        let max = ctx.cfg.backlog_max;

        let firing = {
            let history = self.history.lock().unwrap_or_else(|p| p.into_inner());
            is_growing_over_threshold(&history, now, count, max, window)
        };
        {
            let mut history = self.history.lock().unwrap_or_else(|p| p.into_inner());
            record(&mut history, now, count, window);
        }

        if firing {
            Outcome::Firing {
                severity: Severity::Warning,
                detail: format!("fetcher backlog {count} pending (cap {max}) and rising"),
            }
        } else {
            Outcome::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = 500;
    const WINDOW: Duration = Duration::from_secs(900);

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn below_the_cap_never_fires_even_if_rising() {
        let base = Instant::now();
        let hist = [(base, 100u64)];
        assert!(!is_growing_over_threshold(
            &hist,
            at(base, 900),
            400,
            MAX,
            WINDOW
        ));
    }

    #[test]
    fn over_the_cap_but_flat_or_draining_does_not_fire() {
        let base = Instant::now();
        let now = at(base, 1000);
        // A window-old reference of 600.
        let hist = [(base, 600u64)];
        assert!(!is_growing_over_threshold(&hist, now, 600, MAX, WINDOW)); // flat
        assert!(!is_growing_over_threshold(&hist, now, 550, MAX, WINDOW)); // draining
    }

    #[test]
    fn over_the_cap_and_rising_across_the_window_fires() {
        let base = Instant::now();
        let now = at(base, 1000);
        let hist = [(base, 550u64)];
        assert!(is_growing_over_threshold(&hist, now, 600, MAX, WINDOW));
    }

    #[test]
    fn first_sample_cannot_judge_rising() {
        let base = Instant::now();
        assert!(!is_growing_over_threshold(&[], base, 900, MAX, WINDOW));
    }

    #[test]
    fn a_reference_younger_than_the_window_is_grace_not_firing() {
        let base = Instant::now();
        // Only a 60s-old sample exists; not a full window, so cannot judge rising yet.
        let hist = [(at(base, 940), 550u64)];
        assert!(!is_growing_over_threshold(
            &hist,
            at(base, 1000),
            900,
            MAX,
            WINDOW
        ));
    }

    #[test]
    fn reference_is_the_most_recent_sample_at_least_a_window_old() {
        let base = Instant::now();
        let now = at(base, 2000);
        // Two window-old candidates: 400 at t=0 (2000s old) and 700 at t=1000 (1000s old, >= window).
        // The most recent qualifying one is 700, so count=650 is NOT rising vs 700.
        let hist = [(base, 400u64), (at(base, 1000), 700u64)];
        assert!(!is_growing_over_threshold(&hist, now, 650, MAX, WINDOW));
        // vs the older 400 it would look rising; picking the recent reference correctly says no.
        assert!(is_growing_over_threshold(&hist, now, 750, MAX, WINDOW));
    }

    #[test]
    fn record_prunes_beyond_two_windows_and_caps_length() {
        let base = Instant::now();
        let mut hist = vec![(base, 10u64)];
        // A sample 3 windows later prunes the original (older than 2 windows).
        record(&mut hist, at(base, 2700), 20, WINDOW);
        assert_eq!(hist, vec![(at(base, 2700), 20)]);
    }
}
