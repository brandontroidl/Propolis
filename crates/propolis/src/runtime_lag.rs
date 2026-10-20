//! Scheduling-lag probe for the daemon's async runtime.
//!
//! sqlx reports a statement's elapsed time as everything between the task issuing it and the task
//! being polled with the answer, so a runtime whose workers are all inside synchronous code makes
//! a trivial statement look like a slow one while the database sits idle. This task separates the
//! two: it sleeps for a fixed interval and measures how much later than that it was actually
//! polled. That excess is the same delay a statement's completion waits out. A warning here with a
//! quiet database means the stall is the process; a quiet probe with slow statements means the
//! database.
//!
//! Lag alone does not say WHY the process was slow to poll. Workers all inside synchronous code is
//! one cause; the others freeze every thread of the process at once and read identically: CFS
//! bandwidth throttling (the unit's `CPUQuota=`) and direct memory reclaim near `MemoryMax=`. So
//! each report carries the cgroup's own counters over the same window (`cpu.stat` throttling,
//! `memory.events`): throttle or reclaim deltas beside the lag name the cgroup, and a lag with
//! zero deltas names the workers.
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

    /// Records one wake-up that arrived `lag` after it was due, at `now`. Returns a report when
    /// something over the threshold is pending and the previous report is at least `every` ago.
    ///
    /// The window is checked on EVERY wake-up, not only late ones: a stall that landed inside the
    /// window is held back, and the next on-time wake-up after the window flushes it. Gating the
    /// flush on a further late wake-up would drop the worst stall of a burst whenever the runtime
    /// then recovered.
    pub fn observe(&mut self, lag: Duration, now: Instant) -> Option<LagReport> {
        if lag > self.threshold {
            self.late = self.late.saturating_add(1);
            self.worst = self.worst.max(lag);
        }
        if self.late == 0 {
            return None;
        }
        let due = self
            .last_report
            .is_none_or(|at| now.saturating_duration_since(at) >= self.every);
        if !due {
            return None;
        }
        self.last_report = Some(now);
        Some(self.take())
    }

    /// Hands out whatever is still held back, ignoring the window; for shutdown, so a stall inside
    /// the final window is not lost with the task.
    pub fn flush(&mut self) -> Option<LagReport> {
        (self.late > 0).then(|| self.take())
    }

    fn take(&mut self) -> LagReport {
        let report = LagReport {
            worst_ms: u64::try_from(self.worst.as_millis()).unwrap_or(u64::MAX),
            late_wakeups: self.late,
        };
        self.worst = Duration::ZERO;
        self.late = 0;
        report
    }
}

/// The process's cgroup counters that rival a blocked worker as the cause of a scheduling stall.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupCounters {
    /// `cpu.stat` `nr_throttled`: periods in which the quota ran out.
    pub nr_throttled: u64,
    /// `cpu.stat` `throttled_usec`: time all threads spent frozen by the quota.
    pub throttled_usec: u64,
    /// `memory.events` `high`: times the cgroup was pushed into reclaim over `memory.high`.
    pub mem_high: u64,
    /// `memory.events` `max`: times usage hit `memory.max` and allocation had to reclaim.
    pub mem_max: u64,
    /// `memory.events` `oom` and `oom_kill`, summed.
    pub mem_oom: u64,
}

impl CgroupCounters {
    /// Parses the two files' text. Unknown keys and unparsable lines are skipped: a kernel that adds
    /// or lacks a key must not blind the probe.
    pub fn parse(cpu_stat: &str, memory_events: &str) -> Self {
        let mut c = Self::default();
        for (key, value) in kv(cpu_stat) {
            match key {
                "nr_throttled" => c.nr_throttled = value,
                "throttled_usec" => c.throttled_usec = value,
                _ => {}
            }
        }
        for (key, value) in kv(memory_events) {
            match key {
                "high" => c.mem_high = value,
                "max" => c.mem_max = value,
                "oom" | "oom_kill" => c.mem_oom = c.mem_oom.saturating_add(value),
                _ => {}
            }
        }
        c
    }

    /// Growth since `earlier` (a counter that went backwards, e.g. a cgroup recreated, reads as 0).
    pub fn since(self, earlier: Self) -> Self {
        Self {
            nr_throttled: self.nr_throttled.saturating_sub(earlier.nr_throttled),
            throttled_usec: self.throttled_usec.saturating_sub(earlier.throttled_usec),
            mem_high: self.mem_high.saturating_sub(earlier.mem_high),
            mem_max: self.mem_max.saturating_sub(earlier.mem_max),
            mem_oom: self.mem_oom.saturating_sub(earlier.mem_oom),
        }
    }

    /// Reads this process's own cgroup (v2). `None` where there is no cgroup v2 hierarchy or the
    /// files are unreadable; the probe then reports lag without the cause counters.
    pub fn read_own() -> Option<Self> {
        let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let rel = membership
            .lines()
            .find_map(|l| l.strip_prefix("0::"))?
            .trim();
        let dir = std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
        let cpu = std::fs::read_to_string(dir.join("cpu.stat")).ok()?;
        // memory.events is absent when the memory controller is not delegated; cpu.stat alone
        // still separates quota throttling.
        let mem = std::fs::read_to_string(dir.join("memory.events")).unwrap_or_default();
        Some(Self::parse(&cpu, &mem))
    }
}

fn kv(text: &str) -> impl Iterator<Item = (&str, u64)> {
    text.lines().filter_map(|l| {
        let (k, v) = l.split_once(' ')?;
        Some((k, v.trim().parse().ok()?))
    })
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
            _ = cancel.cancelled() => {
                if let Some(report) = reporter.flush() {
                    sink(report);
                }
                return;
            }
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
/// the log with the runtime's own view of its load and the cgroup's throttle and reclaim deltas
/// over the same window beside the lag.
pub async fn run_in_daemon(cancel: CancellationToken) {
    let handle = tokio::runtime::Handle::current();
    let mut previous = CgroupCounters::read_own();
    run(
        PROBE_INTERVAL,
        LagReporter::new(WARN_THRESHOLD, WARN_EVERY),
        cancel,
        move |report| {
            let metrics = handle.metrics();
            // Delta since the previous report (or since start): the window the lag is from.
            let now = CgroupCounters::read_own();
            let delta = match (now, previous) {
                (Some(n), Some(p)) => Some(n.since(p)),
                _ => None,
            };
            if now.is_some() {
                previous = now;
            }
            let d = delta.unwrap_or_default();
            tracing::warn!(
                worst_lag_ms = report.worst_ms,
                late_wakeups = report.late_wakeups,
                workers = metrics.num_workers(),
                queued_tasks = metrics.global_queue_depth(),
                cgroup_visible = delta.is_some(),
                cgroup_nr_throttled = d.nr_throttled,
                cgroup_throttled_ms = d.throttled_usec / 1000,
                cgroup_mem_high = d.mem_high,
                cgroup_mem_max = d.mem_max,
                cgroup_mem_oom = d.mem_oom,
                "runtime: the async runtime was slow to poll a ready task; statements timed in \
                 this window include that delay, not only database time. Cause is one of: workers \
                 held in synchronous code (cgroup deltas all zero), CPUQuota throttling \
                 (cgroup_throttled_ms), or memory reclaim at MemoryMax (cgroup_mem_*)"
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

    #[test]
    fn a_stall_inside_the_window_is_flushed_by_the_next_on_time_wakeup() {
        let mut r = LagReporter::new(T, EVERY);
        let t0 = Instant::now();
        let first = r.observe(Duration::from_millis(300), t0).expect("first");
        assert_eq!(first.worst_ms, 300);
        // The real stall lands inside the window and is held back.
        assert_eq!(r.observe(Duration::from_secs(2), t0 + EVERY / 2), None);
        // Normal wake-ups inside the window stay quiet.
        assert_eq!(r.observe(Duration::ZERO, t0 + EVERY / 2 + EVERY / 4), None);
        // The first on-time wake-up after the window carries it.
        let carried = r
            .observe(Duration::ZERO, t0 + EVERY)
            .expect("the held-back stall must be reported once the window has passed");
        assert_eq!((carried.worst_ms, carried.late_wakeups), (2000, 1));
        // Nothing pending afterwards.
        assert_eq!(r.observe(Duration::ZERO, t0 + EVERY * 3), None);
    }

    #[test]
    fn flush_hands_out_pending_and_only_pending() {
        let mut r = LagReporter::new(T, EVERY);
        let t0 = Instant::now();
        assert_eq!(r.flush(), None);
        r.observe(Duration::from_millis(300), t0);
        r.observe(Duration::from_secs(2), t0 + EVERY / 2);
        let f = r.flush().expect("pending");
        assert_eq!((f.worst_ms, f.late_wakeups), (2000, 1));
        assert_eq!(r.flush(), None);
    }

    #[tokio::test]
    async fn a_stall_pending_at_cancellation_is_reported() {
        let seen = Arc::new(Mutex::new(Vec::<LagReport>::new()));
        let cancel = CancellationToken::new();
        let probe = tokio::spawn({
            let (seen, cancel) = (seen.clone(), cancel.clone());
            run(
                Duration::from_millis(10),
                LagReporter::new(Duration::from_millis(30), Duration::from_secs(60)),
                cancel,
                move |r| seen.lock().unwrap().push(r),
            )
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Two blocking holds on the current-thread runtime: the first reports at once, the second
        // is inside the 60 s window and is held back until cancellation.
        std::thread::sleep(Duration::from_millis(120));
        tokio::time::sleep(Duration::from_millis(30)).await;
        std::thread::sleep(Duration::from_millis(150));
        // Long enough for the probe's timer to fire and be observed first: its select is unbiased,
        // so cancelling at once could win the race and skip the stall this test is about.
        tokio::time::sleep(Duration::from_millis(15)).await;
        cancel.cancel();
        probe.await.unwrap();
        let reports = seen.lock().unwrap();
        let total: u64 = reports.iter().map(|r| r.late_wakeups).sum();
        assert!(
            reports.len() >= 2 && total >= 2,
            "second stall lost: {reports:?}"
        );
    }

    const CPU: &str = "usage_usec 9\nuser_usec 5\nsystem_usec 4\nnr_periods 100\n\
                       nr_throttled 7\nthrottled_usec 1234567\nnr_bursts 0\n";
    const MEM: &str = "low 0\nhigh 3\nmax 5\noom 1\noom_kill 2\noom_group_kill 0\n";

    #[test]
    fn cgroup_counters_parse_the_kernel_formats_and_diff() {
        let a = CgroupCounters::parse(CPU, MEM);
        assert_eq!(
            a,
            CgroupCounters {
                nr_throttled: 7,
                throttled_usec: 1_234_567,
                mem_high: 3,
                mem_max: 5,
                mem_oom: 3,
            }
        );
        let b = CgroupCounters::parse(
            "nr_throttled 10\nthrottled_usec 1300000\n",
            "high 3\nmax 9\n",
        );
        let d = b.since(CgroupCounters::parse(
            "nr_throttled 8\nthrottled_usec 1000000\n",
            MEM,
        ));
        assert_eq!(
            (d.nr_throttled, d.throttled_usec, d.mem_max),
            (2, 300_000, 4)
        );
        // Garbage and a missing memory.events degrade to zeros, not a panic.
        assert_eq!(
            CgroupCounters::parse("x\n nr_throttled y\n", ""),
            CgroupCounters::default()
        );
    }
}
