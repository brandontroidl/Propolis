//! Running synchronous work without holding an async worker.
//!
//! A tokio worker running a long synchronous step cannot poll any other task until the step
//! returns: a 16 MiB SHA-256 (140 ms), an 8 MiB chain hash (77 ms) or a spool directory walk (85 ms
//! for 20,000 files) is that long of every task's scheduling latency, and sqlx's statement timings
//! include it (backlog J10; `examples/cpu_budget.rs` in the `propolis` crate has the numbers).
//!
//! [`off_worker`] runs the step in place but tells the runtime to hand the rest of this worker's
//! queue to another thread first (`block_in_place`), so the step may borrow the caller's data and
//! needs no `'static` copy, unlike `spawn_blocking`. It costs a thread handoff, so call it for a
//! step that can take milliseconds, not for one that never will.
//!
//! On a current-thread runtime, or outside a runtime, there is no other worker to hand to and
//! `block_in_place` would panic, so the step simply runs in place. The daemon runs on the
//! multi-thread runtime; the single-threaded case is the test harness.

use tokio::runtime::{Handle, RuntimeFlavor};

/// Runs `step` now, on this thread, after moving the other tasks queued on this worker elsewhere.
pub fn off_worker<R>(step: impl FnOnce() -> R) -> R {
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(step)
        }
        _ => step(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    /// Longest gap between two polls of a ticker task over the time `work` takes, on a runtime
    /// with ONE worker, so the step can only avoid starving the ticker by getting off the worker.
    async fn longest_ticker_gap(work: impl FnOnce() + Send + 'static) -> Duration {
        let worst_us = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ticker = tokio::spawn({
            let (worst_us, stop) = (worst_us.clone(), stop.clone());
            async move {
                let mut last = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    let now = Instant::now();
                    worst_us.fetch_max((now - last).as_micros() as u64, Ordering::Relaxed);
                    last = now;
                }
            }
        });
        // Let the ticker settle into its rhythm, then run the step as a task would.
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::spawn(async move { work() }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.store(true, Ordering::Relaxed);
        ticker.await.unwrap();
        Duration::from_micros(worst_us.load(Ordering::Relaxed))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_step_run_in_place_stalls_the_only_worker() {
        let gap = longest_ticker_gap(|| std::thread::sleep(Duration::from_millis(400))).await;
        assert!(
            gap >= Duration::from_millis(300),
            "control: the ticker should have been starved, gap {gap:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_step_run_off_the_worker_leaves_the_runtime_responsive() {
        let gap =
            longest_ticker_gap(|| off_worker(|| std::thread::sleep(Duration::from_millis(400))))
                .await;
        assert!(
            gap < Duration::from_millis(150),
            "the ticker was starved for {gap:?} while the step ran"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn the_step_borrows_and_returns_its_value() {
        let data = [1u8, 2, 3];
        let sum: u32 = off_worker(|| data.iter().map(|&b| u32::from(b)).sum());
        assert_eq!(sum, 6);
        assert_eq!(data.len(), 3);
    }

    #[tokio::test]
    async fn on_a_current_thread_runtime_it_runs_in_place() {
        assert_eq!(off_worker(|| 7), 7);
    }

    #[test]
    fn outside_a_runtime_it_runs_in_place() {
        assert_eq!(off_worker(|| 7), 7);
    }
}
