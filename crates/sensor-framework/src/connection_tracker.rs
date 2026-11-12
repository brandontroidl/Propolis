//! Tracks the live connection (or transfer) tasks of one sensor so shutdown can end them in a
//! known order: let them finish for a short grace period, then cancel the stragglers, and only
//! then drain the capture queue.
//!
//! Why it exists: a capture still being assembled on a live connection is held by a guard whose
//! `Drop` submits what it has buffered, marked cut (`CaptureEnd::Cancelled`). That submit only
//! helps if the connection future is dropped BEFORE the hand-off stops accepting work. Left to
//! the runtime, teardown drops those futures after `CaptureHandoff::drain` has already closed the
//! queue, so the partial upload is refused and lost. [`ConnectionTracker::quiesce`] drops them
//! first and waits until each task has actually ended, so every Drop-time submit has landed in the
//! queue by the time the drain starts.
//!
//! Cancellation is cooperative at the future level: [`ConnectionTracker::run`] races the
//! connection future against the cancel signal and drops the future when the signal wins. The
//! count of live connections is a [`ConnectionGuard`] held for the task's whole lifetime, so it is
//! released on finish, panic, timeout and abort alike.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// How long live connections get to finish on their own before being cancelled at shutdown. A
/// small upload completes inside it; a slow or stalled one is cut and recorded as truncated.
pub const CONNECTION_GRACE: Duration = Duration::from_secs(3);

/// How a [`ConnectionTracker::quiesce`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceOutcome {
    /// Every connection ended on its own within the grace period (or there were none).
    Idle,
    /// This many connections were still live after the grace period; they were cancelled and
    /// have all ended, so anything they buffered has been submitted.
    Cancelled(usize),
    /// This many connections had still not ended after cancellation (a task wedged in blocking
    /// code). What they hold is lost.
    Stuck(usize),
}

impl QuiesceOutcome {
    /// Whether no connection's capture was left behind.
    pub fn is_clean(self) -> bool {
        !matches!(self, Self::Stuck(_))
    }
}

struct Inner {
    /// Number of live connections; a `watch` so `quiesce` can wait for zero without polling.
    live: watch::Sender<usize>,
    /// Latched true by `quiesce`. Stays true, so a connection accepted after shutdown began is
    /// cancelled before its handler runs.
    cancel: watch::Sender<bool>,
}

/// Cheap to clone; every clone shares one set of connections.
#[derive(Clone)]
pub struct ConnectionTracker {
    inner: Arc<Inner>,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                live: watch::channel(0).0,
                cancel: watch::channel(false).0,
            }),
        }
    }

    /// Count one connection as live until the returned guard is dropped. Call it before the task
    /// is spawned, so there is no window in which a live connection is uncounted.
    pub fn register(&self) -> ConnectionGuard {
        self.inner.live.send_modify(|n| *n += 1);
        ConnectionGuard {
            inner: self.inner.clone(),
        }
    }

    /// Connections currently live.
    pub fn live(&self) -> usize {
        *self.inner.live.borrow()
    }

    /// Run `fut` to completion, or drop it and return `None` if shutdown cancels it first. A
    /// cancellation that was already latched returns `None` without polling `fut`.
    pub async fn run<F: Future>(&self, fut: F) -> Option<F::Output> {
        let mut cancel = self.inner.cancel.subscribe();
        tokio::select! {
            biased;
            _ = cancel.wait_for(|cancelled| *cancelled) => None,
            out = fut => Some(out),
        }
    }

    /// Wait up to `grace` for the live connections to end on their own, then cancel the rest and
    /// wait up to `cancel_wait` for them to end. Total time is at most `grace + cancel_wait`.
    pub async fn quiesce(&self, grace: Duration, cancel_wait: Duration) -> QuiesceOutcome {
        if self.wait_idle(grace).await {
            self.inner.cancel.send_replace(true);
            return QuiesceOutcome::Idle;
        }
        let live = self.live();
        self.inner.cancel.send_replace(true);
        if self.wait_idle(cancel_wait).await {
            QuiesceOutcome::Cancelled(live)
        } else {
            QuiesceOutcome::Stuck(self.live())
        }
    }

    async fn wait_idle(&self, within: Duration) -> bool {
        let mut live = self.inner.live.subscribe();
        tokio::time::timeout(within, live.wait_for(|n| *n == 0))
            .await
            .is_ok()
    }
}

/// Holds one connection's slot in a [`ConnectionTracker`]; dropping it releases the slot.
pub struct ConnectionGuard {
    inner: Arc<Inner>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.inner.live.send_modify(|n| *n -= 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct SetOnDrop(Arc<AtomicBool>);
    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn quiesce_with_no_connections_is_idle_at_once() {
        let tracker = ConnectionTracker::new();
        let outcome = tracker
            .quiesce(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert_eq!(outcome, QuiesceOutcome::Idle);
    }

    #[tokio::test]
    async fn a_connection_that_finishes_inside_the_grace_is_not_cancelled() {
        let tracker = ConnectionTracker::new();
        let guard = tracker.register();
        let t = tracker.clone();
        let task = tokio::spawn(async move {
            let _guard = guard;
            t.run(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                7
            })
            .await
        });
        let outcome = tracker
            .quiesce(Duration::from_secs(5), Duration::from_secs(1))
            .await;
        assert_eq!(outcome, QuiesceOutcome::Idle);
        assert_eq!(task.await.unwrap(), Some(7));
    }

    #[tokio::test]
    async fn a_connection_still_live_after_the_grace_is_dropped_and_waited_for() {
        let tracker = ConnectionTracker::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = tracker.register();
        let t = tracker.clone();
        let flag = dropped.clone();
        let task = tokio::spawn(async move {
            let _guard = guard;
            t.run(async move {
                let _held = SetOnDrop(flag);
                std::future::pending::<()>().await;
            })
            .await
        });
        let outcome = tracker
            .quiesce(Duration::from_millis(50), Duration::from_secs(5))
            .await;
        assert_eq!(outcome, QuiesceOutcome::Cancelled(1));
        assert!(
            dropped.load(Ordering::SeqCst),
            "quiesce must not return before the connection future was dropped"
        );
        assert_eq!(tracker.live(), 0);
        assert_eq!(task.await.unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_that_never_ends_is_reported_stuck_within_the_bound() {
        let tracker = ConnectionTracker::new();
        let guard = tracker.register();
        // Holds its slot without ever yielding to the cancel signal.
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::thread::sleep(Duration::from_millis(600));
        });
        let started = std::time::Instant::now();
        let outcome = tracker
            .quiesce(Duration::from_millis(50), Duration::from_millis(100))
            .await;
        assert_eq!(outcome, QuiesceOutcome::Stuck(1));
        assert!(!outcome.is_clean());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "bounded by grace + cancel_wait, not by the stuck task"
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_registered_after_shutdown_is_cancelled_without_running() {
        let tracker = ConnectionTracker::new();
        tracker
            .quiesce(Duration::from_millis(10), Duration::from_millis(10))
            .await;
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        let out = tracker
            .run(async move {
                flag.store(true, Ordering::SeqCst);
            })
            .await;
        assert_eq!(out, None);
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_guard_releases_its_slot_on_drop() {
        let tracker = ConnectionTracker::new();
        let a = tracker.register();
        let b = tracker.register();
        assert_eq!(tracker.live(), 2);
        drop(a);
        assert_eq!(tracker.live(), 1);
        drop(b);
        assert_eq!(tracker.live(), 0);
    }
}
