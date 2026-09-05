//! Per-subsystem task supervision with restart-on-panic and exponential backoff.
//!
//! `spawn_supervised` wraps a subsystem factory in a tokio task that catches panics (via
//! `JoinHandle` inspection) and restarts the subsystem with exponential backoff (1s, 2s, 4s, 8s,
//! 16s, cap 60s). Three consecutive panics within 60 seconds stops restarting that subsystem and
//! logs an alert; the counter resets after 5 minutes of healthy operation.

use std::future::Future;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ops_alert::condition::{SubsysState, SupervisorHandle};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_CONSECUTIVE_PANICS: u32 = 3;
const PANIC_WINDOW: Duration = Duration::from_secs(60);
const HEALTHY_RESET: Duration = Duration::from_secs(300);

/// Spawns `factory(cancel.child_token())` as a supervised tokio task. If the task panics, it is
/// restarted with exponential backoff. Three consecutive panics within 60 seconds stops
/// restarting. The failure counter resets after 5 minutes of healthy operation.
///
/// A clean return (the task's future completes without panicking) is treated as intentional
/// shutdown - no restart.
/// Publish `name`'s current supervised state into the shared map the ops-monitor reads.
fn publish(state: &SupervisorHandle, name: &'static str, s: SubsysState) {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(name, s);
}

pub fn spawn_supervised<F, Fut>(
    name: &'static str,
    cancel: CancellationToken,
    state: SupervisorHandle,
    factory: F,
) -> JoinHandle<()>
where
    F: Fn(CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut consecutive_panics: u32 = 0;
        let mut first_panic_at: Option<Instant> = None;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            if cancel.is_cancelled() {
                tracing::info!(subsystem = name, "supervisor: cancelled, not restarting");
                return;
            }

            let child_token = cancel.child_token();
            let started_at = Instant::now();
            let handle = tokio::spawn(factory(child_token));
            publish(&state, name, SubsysState::Running);

            match handle.await {
                // Clean return. On shutdown that is the cancellation token firing; otherwise the
                // task ended on its own (a startup refusal, a loop that returned) and, since a
                // clean return is never restarted, the subsystem is down from here on. Publish
                // that: left as `Running`, /ready and the ops-monitor kept calling it healthy.
                Ok(()) => {
                    if cancel.is_cancelled() {
                        tracing::info!(subsystem = name, "supervisor: subsystem exited cleanly");
                    } else {
                        tracing::error!(
                            subsystem = name,
                            "supervisor: subsystem exited on its own without a shutdown; it is \
                             down and will not be restarted"
                        );
                        publish(&state, name, SubsysState::Exited);
                    }
                    return;
                }
                // Panic - the JoinError is a panic.
                Err(join_error) => {
                    let elapsed_healthy = started_at.elapsed();

                    // Reset the panic counter if the subsystem ran healthy for long enough.
                    if elapsed_healthy >= HEALTHY_RESET {
                        consecutive_panics = 0;
                        first_panic_at = None;
                        backoff = INITIAL_BACKOFF;
                    }

                    consecutive_panics += 1;
                    let now = Instant::now();
                    if first_panic_at.is_none() {
                        first_panic_at = Some(now);
                    }

                    tracing::error!(
                        subsystem = name,
                        panic = %join_error,
                        consecutive = consecutive_panics,
                        "supervisor: subsystem panicked"
                    );

                    // Check if we've hit the consecutive panic limit within the window.
                    if consecutive_panics >= MAX_CONSECUTIVE_PANICS
                        && let Some(first) = first_panic_at
                        && now.duration_since(first) < PANIC_WINDOW
                    {
                        tracing::error!(
                            subsystem = name,
                            consecutive = consecutive_panics,
                            "supervisor: {} consecutive panics within {}s, stopping restarts",
                            MAX_CONSECUTIVE_PANICS,
                            PANIC_WINDOW.as_secs()
                        );
                        publish(&state, name, SubsysState::GaveUp);
                        return;
                    }
                    if consecutive_panics >= MAX_CONSECUTIVE_PANICS {
                        // Outside the window - reset and keep going.
                        consecutive_panics = 1;
                        first_panic_at = Some(now);
                        backoff = INITIAL_BACKOFF;
                    }

                    if cancel.is_cancelled() {
                        return;
                    }

                    publish(
                        &state,
                        name,
                        SubsysState::BackingOff {
                            consecutive: consecutive_panics,
                        },
                    );
                    tracing::info!(
                        subsystem = name,
                        backoff_secs = backoff.as_secs(),
                        "supervisor: restarting after backoff"
                    );

                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = cancel.cancelled() => {
                            tracing::info!(subsystem = name, "supervisor: cancelled during backoff");
                            return;
                        }
                    }

                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    fn new_state() -> SupervisorHandle {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[tokio::test]
    async fn clean_exit_does_not_restart() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let handle = spawn_supervised("test-clean", cancel.clone(), new_state(), move |_token| {
            let count = count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
            }
        });

        handle.await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_stops_supervisor() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let handle = spawn_supervised("test-cancel", cancel.clone(), new_state(), move |token| {
            let count = count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                token.cancelled().await;
            }
        });

        // Give the task a moment to start.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn panics_trigger_restart() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let handle = spawn_supervised("test-panic", cancel.clone(), new_state(), move |_token| {
            let count = count_clone.clone();
            async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    panic!("test panic #{n}");
                }
                // Third invocation exits cleanly, stopping the supervisor.
            }
        });

        // The supervisor will restart after each panic (with backoff). Eventually the third
        // call exits cleanly.
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("supervisor should finish within timeout")
            .unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn three_rapid_panics_stops_restarting() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let state = new_state();
        let handle = spawn_supervised(
            "test-rapid-panic",
            cancel.clone(),
            state.clone(),
            move |_token| {
                let count = count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    panic!("rapid panic");
                }
            },
        );

        // After 3 rapid panics the supervisor should give up. The backoff (1s + 2s) means
        // this takes about 3s. Allow generous timeout.
        tokio::time::timeout(Duration::from_secs(15), handle)
            .await
            .expect("supervisor should stop after 3 rapid panics")
            .unwrap();

        // Exactly 3 attempts: the first, plus two restarts, then give up.
        assert_eq!(count.load(Ordering::SeqCst), 3);
        // And the shared state records the give-up, which the ops-monitor pages on.
        assert_eq!(
            state.lock().unwrap().get("test-rapid-panic"),
            Some(&SubsysState::GaveUp)
        );
    }

    /// A task that returns on its own, with no shutdown in progress, is dead: the supervisor never
    /// restarts a clean return. It used to stay `Running` in the shared map forever, so a startup
    /// refusal (the fetcher with no own-IP set) left /ready green and the ops-monitor quiet.
    #[tokio::test]
    async fn a_voluntary_exit_without_shutdown_is_published_as_exited() {
        let cancel = CancellationToken::new();
        let state = new_state();
        let handle = spawn_supervised("test-exit", cancel.clone(), state.clone(), |_token| async {
        });
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor should finish")
            .unwrap();
        assert_eq!(
            state.lock().unwrap().get("test-exit"),
            Some(&SubsysState::Exited)
        );
        assert!(SubsysState::Exited.is_down());
    }

    /// The same clean return during shutdown is the normal path and must not read as a failure.
    #[tokio::test]
    async fn a_clean_exit_during_shutdown_is_not_marked_exited() {
        let cancel = CancellationToken::new();
        let state = new_state();
        let handle = spawn_supervised(
            "test-shutdown",
            cancel.clone(),
            state.clone(),
            |token| async move { token.cancelled().await },
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor should finish")
            .unwrap();
        assert_eq!(
            state.lock().unwrap().get("test-shutdown"),
            Some(&SubsysState::Running),
            "a shutdown exit keeps the last live state; it is not a subsystem failure"
        );
    }
}
