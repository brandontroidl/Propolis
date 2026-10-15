//! Scheduling-lag probe for the daemon's async runtime.
//!
//! sqlx reports a statement's elapsed time as everything between the task issuing it and the task
//! being polled with the answer, so a runtime whose workers are all inside synchronous code makes
//! a trivial statement look like a slow one while the database sits idle. This task separates the
//! two: it sleeps for a fixed interval and measures how much later than that it was actually
//! polled. That excess is time the runtime had no free worker for a ready task, and it is the same
//! delay a statement's completion waits out. A warning here with a quiet database means the stall
//! is the process; a quiet probe with slow statements means the database.
//!
//! The probe is deliberately small: one timer, two integer comparisons per wake-up, and a warning
//! that is rate limited, so it cannot add load to the condition it reports. Nothing in it can
//! panic on input, and it runs outside the supervisor: it is a measurement, not a subsystem, so its
//! absence must never page and its failure must never restart anything.
//!
//! Limit: with N workers, a single blocked worker is visible only when the probe's wake-up lands on
//! it (the task is scheduled by the worker that drives the timer). A probe that stays quiet does
//! not prove no worker was ever blocked; `examples/cpu_budget.rs` measures the individual steps.

use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

/// How often the probe wakes. Short enough to see a stall of a few hundred milliseconds from
/// several samples, long enough to cost nothing (ten wake-ups a second).
pub const PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// Lag beyond the interval that is worth a warning. The stalls this exists for were 1-2 s; 250 ms
/// is well above the jitter of a loaded host and well below anything an operator would call a stall.
pub const WARN_THRESHOLD: Duration = Duration::from_millis(250);

/// At most one warning per this long. A stall lasting a minute is one line with the worst lag seen
/// and how many wake-ups were late, not 600 lines.
pub const WARN_EVERY: Duration = Duration::from_secs(10);

/// What one warning says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LagReport {
    /// The worst lag since the previous report (or since start), in whole milliseconds.
    pub worst_ms: u64,
    /// Wake-ups over the threshold since the previous report, this one included.
    pub late_wakeups: u64,
}

/// Decides when a lag measurement becomes a warning. Pure state, no clock of its own, so the
/// rate limit is testable without sleeping.
#[derive(Debug)]
pub struct LagReporter {
    threshold: Duration,
    every: Duration,
    last_report: Option<Instant>,
    worst: Duration,
    late: u64,
}

impl LagReporter {
    pub fn new(threshold: Duration, every: Duration) -> Self {
        Self {
            threshold,
            every,
            last_report: None,
            worst: Duration::ZERO,
            late: 0,
        }
    }

    /// Records one wake-up that arrived `lag` after it was due, at `now`. Returns a report when the
    /// lag is over the threshold and the previous report is at least `every` ago.
    pub fn observe(&mut self, lag: Duration, now: Instant) -> Option<LagReport> {
        if lag <= self.threshold {
            return None;
        }
        self.late = self.late.saturating_add(1);
        self.worst = self.worst.max(lag);
        let due = self
            .last_report
            .is_none_or(|at| now.saturating_duration_since(at) >= self.every);
        if !due {
            return None;
        }
        let report = LagReport {
            worst_ms: u64::try_from(self.worst.as_millis()).unwrap_or(u64::MAX),
            late_wakeups: self.late,
        };
        self.last_report = Some(now);
        self.worst = Duration::ZERO;
        self.late = 0;
        Some(report)
    }
}

/// Runs until `cancel` fires, handing every report to `sink`. The production sink logs a warning;
/// a test passes one that records.
pub async fn run(
    interval: Duration,
    mut reporter: LagReporter,
    cancel: CancellationToken,
    mut sink: impl FnMut(LagReport) + Send,
) {
    loop {
        let started = Instant::now();
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => return,
        }
        let now = Instant::now();
        let lag = now
            .saturating_duration_since(started)
            .saturating_sub(interval);
        if let Some(report) = reporter.observe(lag, now) {
            sink(report);
        }
    }
}

/// The daemon's probe: [`PROBE_INTERVAL`], [`WARN_THRESHOLD`], [`WARN_EVERY`], reporting through
/// the log with the runtime's own view of its load beside the lag.
pub async fn run_in_daemon(cancel: CancellationToken) {
    let handle = tokio::runtime::Handle::current();
    run(
        PROBE_INTERVAL,
        LagReporter::new(WARN_THRESHOLD, WARN_EVERY),
        cancel,
        move |report| {
            let metrics = handle.metrics();
            tracing::warn!(
                worst_lag_ms = report.worst_ms,
                late_wakeups = report.late_wakeups,
                workers = metrics.num_workers(),
                queued_tasks = metrics.global_queue_depth(),
                "runtime: the async runtime was slow to poll a ready task; statements timed in \
                 this window include time waiting for a free worker, not only database time"
            );
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    const T: Duration = Duration::from_millis(250);
    const EVERY: Duration = Duration::from_secs(10);

    #[test]
    fn lag_at_or_under_the_threshold_is_never_reported() {
        let mut r = LagReporter::new(T, EVERY);
        let now = Instant::now();
        assert_eq!(r.observe(Duration::ZERO, now), None);
        assert_eq!(r.observe(T, now), None);
    }

    #[test]
    fn lag_over_the_threshold_reports_at_once_and_then_at_most_once_per_window() {
        let mut r = LagReporter::new(T, EVERY);
        let t0 = Instant::now();
        let first = r.observe(Duration::from_millis(900), t0).expect("first");
        assert_eq!(first.worst_ms, 900);
        assert_eq!(first.late_wakeups, 1);

        // Inside the window: counted, not reported.
        assert_eq!(r.observe(Duration::from_millis(400), t0 + EVERY / 2), None);
        assert_eq!(r.observe(Duration::from_millis(1500), t0 + EVERY / 2), None);

        // At the window's end the next late wake-up reports what was held back: the worst lag and
        // the count since the last report.
        let next = r
            .observe(Duration::from_millis(300), t0 + EVERY)
            .expect("window elapsed");
        assert_eq!(next.worst_ms, 1500);
        assert_eq!(next.late_wakeups, 3);

        // And the counters start over.
        let again = r
            .observe(Duration::from_millis(260), t0 + EVERY * 2)
            .expect("second window");
        assert_eq!((again.worst_ms, again.late_wakeups), (260, 1));
    }

    #[test]
    fn a_clock_that_runs_backwards_does_not_panic_or_report() {
        let mut r = LagReporter::new(T, EVERY);
        let t0 = Instant::now();
        assert!(r.observe(Duration::from_secs(1), t0 + EVERY).is_some());
        // `now` earlier than the last report: saturating, so not due, and no panic.
        assert_eq!(r.observe(Duration::from_secs(1), t0), None);
    }

    /// The probe sees what it exists for: a worker held in synchronous code. One worker thread, so
    /// the blocked task is the only thing that could poll the probe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_blocked_worker_is_reported_with_its_lag() {
        let seen = Arc::new(Mutex::new(Vec::<LagReport>::new()));
        let cancel = CancellationToken::new();
        let probe = tokio::spawn({
            let (seen, cancel) = (seen.clone(), cancel.clone());
            run(
                Duration::from_millis(20),
                LagReporter::new(Duration::from_millis(100), Duration::from_secs(60)),
                cancel,
                move |r| seen.lock().unwrap().push(r),
            )
        });
        // Let the probe start its first sleep, then hold the only worker from inside a task (the
        // test body itself runs on this thread, not on the worker).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let held = Duration::from_millis(400);
        tokio::spawn(async move { std::thread::sleep(held) })
            .await
            .unwrap();
        // The probe is polled once the worker is free again.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        probe.await.unwrap();

        let reports = seen.lock().unwrap();
        assert_eq!(reports.len(), 1, "one report for one stall: {reports:?}");
        // The hold is `held`; the probe's own interval was already running, so the measured lag is
        // somewhat under it. Anything over the threshold and in the right order of magnitude is a
        // faithful reading; the exact value depends on the scheduler.
        assert!(
            (200..=600).contains(&reports[0].worst_ms),
            "lag {} ms for a {} ms hold",
            reports[0].worst_ms,
            held.as_millis()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn an_idle_runtime_reports_nothing() {
        let seen = Arc::new(Mutex::new(Vec::<LagReport>::new()));
        let cancel = CancellationToken::new();
        let probe = tokio::spawn({
            let (seen, cancel) = (seen.clone(), cancel.clone());
            run(
                Duration::from_millis(10),
                LagReporter::new(Duration::from_millis(200), Duration::from_secs(60)),
                cancel,
                move |r| seen.lock().unwrap().push(r),
            )
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
        probe.await.unwrap();
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancellation_ends_the_probe_promptly() {
        let cancel = CancellationToken::new();
        let probe = tokio::spawn(run(
            Duration::from_secs(3600),
            LagReporter::new(T, EVERY),
            cancel.clone(),
            |_| {},
        ));
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), probe)
            .await
            .expect("the probe must not sleep out its interval after cancellation")
            .unwrap();
    }
}
