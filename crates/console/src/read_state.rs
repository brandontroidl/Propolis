//! Per-process state the pages keep between requests so that a derived read stays cheap: whether the
//! roll-up refresh is working ([`crate::rollup::Health`]) and the one panel whose answer is held for
//! a short while ([`SwrCell`]).
//!
//! It is one `Arc` on [`crate::AppState`] rather than process-wide statics because the tests run
//! several consoles over several databases in one process, and a static would let one test's cached
//! answer reach another's page.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::routes::dashboard::MostActiveRow;

/// How long the dashboard's most-active panel counts as current. The panel ranks the busiest
/// sources of the last 24 hours, which no 30 seconds of traffic reorders in a way an operator could
/// act on. Past this (or once the quarter hour turns) the held answer is still what a load gets,
/// while a new one is computed behind it.
const MOST_ACTIVE_FRESH: Duration = Duration::from_secs(30);

/// The oldest held panel a load is served: the owner's bound on how far the panel may lag. Age is
/// counted from when the computation that produced the panel started, so the data shown is never
/// more than this old. The background refresher replaces the panel before it reaches the cap (at
/// each quarter-hour boundary and at two thirds of the cap, see [`ReadState::spawn_refresher`]),
/// so this only bites when refreshes keep failing or the process was stopped for longer than the
/// cap (SIGSTOP, a frozen container: the monotonic clock keeps running). The load then waits for
/// a fresh computation (and a failure of it reaches the page's degraded banner) instead of showing
/// an answer of any age. Across a system suspend `CLOCK_MONOTONIC`, which `Instant` reads on
/// Linux, stops, so the panel does not age by the suspended time; the wall-clock quarter hour does
/// advance, and a panel more than one quarter hour behind it is not served.
const MOST_ACTIVE_MAX_AGE: Duration = Duration::from_secs(15 * 60);

/// How often the refresher looks at the quarter hour and the held panel's age; a check is a clock
/// read. A refresh is therefore started within this of the moment it is due.
const MOST_ACTIVE_POLL: Duration = Duration::from_secs(5);

/// What the pages remember between requests; see the module doc comment.
pub struct ReadState {
    pub(crate) rollup: crate::rollup::Health,
    pub(crate) most_active: Arc<SwrCell<Vec<MostActiveRow>>>,
    quarter_hour: Box<dyn Fn() -> u64 + Send + Sync>,
    poll: Duration,
}

/// The current quarter hour since the epoch: the key the most-active panel is held under.
fn wall_clock_quarter_hour() -> u64 {
    (chrono::Utc::now().timestamp() / 900) as u64
}

impl ReadState {
    /// The state a running console uses.
    pub fn new() -> Arc<Self> {
        Self::with_most_active(
            MOST_ACTIVE_FRESH,
            MOST_ACTIVE_MAX_AGE,
            MOST_ACTIVE_POLL,
            true,
            wall_clock_quarter_hour,
        )
    }

    /// A state that never serves a held answer and runs no refresher: every page computes its own.
    /// What the tests that insert events and then read a page need, and what a caller that wants no
    /// caching gets.
    pub fn uncached() -> Arc<Self> {
        Self::with_most_active(
            Duration::ZERO,
            Duration::ZERO,
            MOST_ACTIVE_POLL,
            false,
            wall_clock_quarter_hour,
        )
    }

    /// [`Self::new`] with an explicit freshness, age cap, refresher poll interval, stale-serving
    /// switch and quarter-hour source, for tests of the cache (a test that injects the quarter hour
    /// does not depend on the wall clock turning mid-run).
    pub fn with_most_active(
        fresh: Duration,
        max_age: Duration,
        poll: Duration,
        serve_stale: bool,
        quarter_hour: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_clocks(
            fresh,
            max_age,
            poll,
            serve_stale,
            quarter_hour,
            Instant::now,
        )
    }

    /// [`Self::with_most_active`] with the monotonic clock the held panel's age is read from
    /// injected as well, so a test can move time by exact amounts instead of sleeping.
    pub fn with_clocks(
        fresh: Duration,
        max_age: Duration,
        poll: Duration,
        serve_stale: bool,
        quarter_hour: impl Fn() -> u64 + Send + Sync + 'static,
        now: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            rollup: crate::rollup::Health::default(),
            most_active: Arc::new(SwrCell::with_clock(fresh, max_age, serve_stale, now)),
            quarter_hour: Box::new(quarter_hour),
            poll,
        })
    }

    /// The key the most-active panel is held under right now.
    pub(crate) fn quarter_hour(&self) -> u64 {
        (self.quarter_hour)()
    }

    /// Starts the task that keeps the most-active panel replaced before it can reach the age cap,
    /// so a load never waits for the aggregate once the panel has been computed. It computes at
    /// start (warming a cold console), then whenever the quarter hour has changed and whenever
    /// two thirds of the age cap have passed since the last attempt (10 minutes for the 15 minute
    /// cap). The second trigger is what keeps an idle console covered: the cap equals the quarter
    /// hour, so a refresh that waited for the boundary alone would land after the held panel had
    /// already passed the cap. The panel is at most the cap old, measured from when its
    /// computation started, and a refresh has a third of the cap to land. A failed computation is
    /// logged and retried at the next trigger, not every poll; the request path covers the gap (its
    /// own refresh, then its own load once the held panel passes the age cap). The task ends when
    /// `shutdown` completes, including while a computation is in flight. Returns `None` for a state
    /// that holds nothing ([`Self::uncached`]), which has nothing to refresh.
    pub(crate) fn spawn_refresher(
        self: &Arc<Self>,
        load: Loader<Vec<MostActiveRow>>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if !self.most_active.serve_stale {
            return None;
        }
        let this = Arc::clone(self);
        let every = (this.most_active.max_age * 2 / 3).max(this.poll);
        Some(tokio::spawn(async move {
            tokio::pin!(shutdown);
            let mut last: Option<(u64, Instant)> = None;
            loop {
                let stamp = this.quarter_hour();
                let now = this.most_active.now();
                let due = last.is_none_or(|(done, at)| {
                    done != stamp || now.saturating_duration_since(at) >= every
                });
                if due {
                    last = Some((stamp, now));
                    let refresh = this.most_active.refresh(stamp, load.clone());
                    tokio::select! {
                        () = &mut shutdown => return,
                        result = refresh => {
                            if let Err(error) = result {
                                tracing::warn!(%error, "console: scheduled refresh of the most-active panel failed; retrying at the next trigger");
                            }
                        }
                    }
                }
                tokio::select! {
                    () = &mut shutdown => return,
                    () = tokio::time::sleep(this.poll) => {}
                }
            }
        }))
    }
}

/// How a held answer is recomputed: called on a miss and, off the request path, to refresh a stale
/// answer.
pub(crate) type Loader<T> =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<T, sqlx::Error>> + Send>> + Send + Sync>;

struct Entry<T> {
    /// When the computation that produced the answer started, so the data is no older than its
    /// age says. The store never lets a computation that started earlier overwrite this one.
    at: Instant,
    /// The quarter hour the answer was computed in. A different one marks it out of date (it is
    /// still served while young enough, and replaced behind the request). An entry whose stamp is
    /// ahead of the current one (the wall clock stepped back) is replaced like any other: ordering
    /// is by `at`, which cannot go backwards.
    stamp: u64,
    value: T,
}

enum Held<T> {
    Fresh(T),
    Stale(T),
    Miss,
}

/// One held answer with stale-while-revalidate: an answer for the current `stamp` younger than
/// `fresh_for` is served as is; a held answer past that is served too while one background task
/// recomputes it, but only if it is at most `max_age` old (counted from when its computation
/// started) and not more than one stamp behind; anything else (nothing held, too old, more than one stamp behind) waits for a load. With
/// `serve_stale` off nothing is ever served past `fresh_for`, so a zero `fresh_for` loads every
/// time. Concurrent misses share one computation (the second waits on the first and reads its
/// result). An error is never held; a failed background refresh keeps the previous answer until the
/// age cap, and a load that fails past it returns the error.
pub(crate) struct SwrCell<T> {
    fresh_for: Duration,
    max_age: Duration,
    serve_stale: bool,
    slot: Mutex<Option<Entry<T>>>,
    refreshing: AtomicBool,
    gate: tokio::sync::Mutex<()>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

/// Clears [`SwrCell::refreshing`] when the background task ends by any route, a panicking loader
/// included; a flag left set would stop every later refresh.
struct RefreshGuard<T>(Arc<SwrCell<T>>);

impl<T> Drop for RefreshGuard<T> {
    fn drop(&mut self) {
        self.0.refreshing.store(false, Ordering::Release);
    }
}

impl<T: Clone + Send + Sync + 'static> SwrCell<T> {
    #[cfg(test)]
    pub(crate) fn new(fresh_for: Duration, max_age: Duration, serve_stale: bool) -> Self {
        Self::with_clock(fresh_for, max_age, serve_stale, Instant::now)
    }

    pub(crate) fn with_clock(
        fresh_for: Duration,
        max_age: Duration,
        serve_stale: bool,
        now: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            fresh_for,
            max_age,
            serve_stale,
            slot: Mutex::new(None),
            refreshing: AtomicBool::new(false),
            gate: tokio::sync::Mutex::new(()),
            now: Box::new(now),
        }
    }

    pub(crate) fn now(&self) -> Instant {
        (self.now)()
    }

    fn held(&self, stamp: u64) -> Held<T> {
        let slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(e) = slot.as_ref() else {
            return Held::Miss;
        };
        let age = self.now().saturating_duration_since(e.at);
        if e.stamp == stamp && age < self.fresh_for && age <= self.max_age {
            return Held::Fresh(e.value.clone());
        }
        // Served stale only while the answer is at most `max_age` old and not more than one
        // quarter hour behind (an entry ahead of the current stamp, after a backward clock step,
        // is served too and replaced); anything older is a miss, so a failing refresher cannot
        // keep an answer on the page for days.
        if self.serve_stale && e.stamp.saturating_add(1) >= stamp && age <= self.max_age {
            return Held::Stale(e.value.clone());
        }
        Held::Miss
    }

    /// Computes the answer for `stamp` off the request path and stores it, unless another refresh
    /// is running. The caller decides when a refresh is due ([`ReadState::spawn_refresher`]); this
    /// does not skip on a current-looking entry, because an entry can look current (same stamp, or
    /// a stamp ahead after a backward clock step) while being about to pass the age cap.
    pub(crate) async fn refresh(
        self: &Arc<Self>,
        stamp: u64,
        load: Loader<T>,
    ) -> Result<(), sqlx::Error> {
        if self.refreshing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _guard = RefreshGuard(Arc::clone(self));
        let started = self.now();
        self.store(stamp, started, load().await?);
        Ok(())
    }

    /// Keeps the answer whose computation started last: a refresh that started earlier and
    /// finishes after a later one was stored must not put the older answer back. Ordering by start
    /// time rather than by quarter hour keeps a wall clock stepped back from pinning a stale entry
    /// (nothing newer could replace it until the clock caught up, so every load would recompute).
    fn store(&self, stamp: u64, started: Instant, value: T) {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_some_and(|e| e.at > started) {
            return;
        }
        *slot = Some(Entry {
            at: started,
            stamp,
            value,
        });
    }

    /// The answer for `stamp`: the held one when fresh, the held one plus a background refresh when
    /// stale, otherwise `load`'s.
    pub(crate) async fn get(
        self: &Arc<Self>,
        stamp: u64,
        load: Loader<T>,
    ) -> Result<T, sqlx::Error> {
        match self.held(stamp) {
            Held::Fresh(v) => return Ok(v),
            Held::Stale(v) => {
                self.refresh_in_background(stamp, load);
                return Ok(v);
            }
            Held::Miss => {}
        }
        let _one_loader = self.gate.lock().await;
        if let Held::Fresh(v) = self.held(stamp) {
            return Ok(v);
        }
        let started = self.now();
        let value = load().await?;
        self.store(stamp, started, value.clone());
        Ok(value)
    }

    fn refresh_in_background(self: &Arc<Self>, stamp: u64, load: Loader<T>) {
        if self.refreshing.swap(true, Ordering::AcqRel) {
            return;
        }
        let guard = RefreshGuard(Arc::clone(self));
        tokio::spawn(async move {
            let started = guard.0.now();
            match load().await {
                Ok(value) => guard.0.store(stamp, started, value),
                Err(error) => {
                    tracing::warn!(%error, "console: background refresh of a held panel failed; the previous answer stays");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    const HOUR: Duration = Duration::from_secs(3600);

    fn counting(calls: &Arc<AtomicUsize>, fail_after: usize) -> Loader<usize> {
        let calls = Arc::clone(calls);
        Arc::new(move || {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n > fail_after {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(n)
                }
            })
        })
    }

    async fn settled(cell: &SwrCell<usize>, calls: &AtomicUsize, at_least: usize) {
        for _ in 0..400 {
            if calls.load(Ordering::SeqCst) >= at_least && !cell.refreshing.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the background refresh did not finish");
    }

    #[tokio::test]
    async fn a_fresh_answer_is_served_without_loading() {
        let cell = Arc::new(SwrCell::new(HOUR, HOUR, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn without_stale_serving_another_stamp_is_a_miss() {
        let cell = Arc::new(SwrCell::new(HOUR, HOUR, false));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        assert_eq!(cell.get(2, load.clone()).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn zero_freshness_without_stale_serving_loads_every_time() {
        let cell = Arc::new(SwrCell::new(Duration::ZERO, Duration::ZERO, false));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_stale_answer_is_served_at_once_and_replaced_in_the_background() {
        let cell = Arc::new(SwrCell::new(Duration::ZERO, HOUR, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        // Nothing held: the first call loads and waits.
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        // Held but past `fresh_for`: the old value comes back without waiting for a load.
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        settled(&cell, &calls, 2).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one background load ran");
        assert_eq!(
            cell.get(1, load).await.unwrap(),
            2,
            "and replaced the answer"
        );
    }

    #[tokio::test]
    async fn an_answer_from_an_earlier_quarter_hour_is_served_while_the_new_one_loads() {
        let cell = Arc::new(SwrCell::new(HOUR, HOUR, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        // The quarter hour turned: the old answer is what the caller gets, never a wait.
        assert_eq!(cell.get(2, load.clone()).await.unwrap(), 1);
        settled(&cell, &calls, 2).await;
        assert_eq!(cell.get(2, load).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn an_error_is_not_held_and_a_failed_refresh_keeps_the_old_answer() {
        let cell = Arc::new(SwrCell::new(Duration::ZERO, HOUR, true));
        let calls = Arc::new(AtomicUsize::new(0));
        // The first load succeeds, every later one fails.
        let load = counting(&calls, 1);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        settled(&cell, &calls, 2).await;
        assert_eq!(
            cell.get(1, load.clone()).await.unwrap(),
            1,
            "still the old answer"
        );
        // A cell with nothing held has nothing to fall back on, so the error reaches the caller.
        let empty = Arc::new(SwrCell::new(Duration::ZERO, HOUR, true));
        assert!(empty.get(2, load).await.is_err());
    }

    #[tokio::test]
    async fn a_panicking_refresh_does_not_stop_later_refreshes() {
        let cell = Arc::new(SwrCell::new(Duration::ZERO, HOUR, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let ok = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1, ok.clone()).await.unwrap(), 1);
        let boom: Loader<usize> = Arc::new(|| Box::pin(async { panic!("loader panicked") }));
        assert_eq!(cell.get(1, boom).await.unwrap(), 1);
        for _ in 0..400 {
            if !cell.refreshing.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            !cell.refreshing.load(Ordering::SeqCst),
            "the flag is cleared when the task panics"
        );
        // A later stale hit starts a refresh again.
        assert_eq!(cell.get(1, ok.clone()).await.unwrap(), 1);
        settled(&cell, &calls, 2).await;
        assert_eq!(cell.get(1, ok).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn an_answer_past_the_age_cap_is_reloaded_not_served() {
        let cap = Duration::from_millis(60);
        let cell = Arc::new(SwrCell::new(Duration::ZERO, cap, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        assert_eq!(
            cell.get(1, load.clone()).await.unwrap(),
            1,
            "inside the cap"
        );
        settled(&cell, &calls, 2).await;
        tokio::time::sleep(cap * 2).await;
        // The entry written by the background load above is also past the cap by now.
        assert_eq!(
            cell.get(1, load.clone()).await.unwrap(),
            3,
            "past the cap the caller waits for a load"
        );
    }

    #[tokio::test]
    async fn a_failed_load_past_the_age_cap_reaches_the_caller() {
        let cap = Duration::from_millis(40);
        let cell = Arc::new(SwrCell::new(Duration::ZERO, cap, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, 1);
        assert_eq!(cell.get(1, load.clone()).await.unwrap(), 1);
        tokio::time::sleep(cap * 3).await;
        assert!(
            cell.get(1, load).await.is_err(),
            "an old answer is not a fallback for a failing load"
        );
    }

    #[tokio::test]
    async fn an_answer_more_than_one_stamp_behind_is_reloaded_not_served() {
        let cell = Arc::new(SwrCell::new(HOUR, HOUR, true));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(10, load.clone()).await.unwrap(), 1);
        assert_eq!(
            cell.get(11, load.clone()).await.unwrap(),
            1,
            "one stamp behind is still served"
        );
        settled(&cell, &calls, 2).await;
        assert_eq!(cell.get(11, load.clone()).await.unwrap(), 2);
        assert_eq!(
            cell.get(13, load).await.unwrap(),
            3,
            "two stamps behind waits for a load"
        );
    }

    fn state_with_clock(poll: Duration) -> (Arc<ReadState>, Arc<AtomicU64>) {
        let clock = Arc::new(AtomicU64::new(1000));
        let handle = Arc::clone(&clock);
        let state = ReadState::with_most_active(HOUR, HOUR, poll, true, move || {
            handle.load(Ordering::SeqCst)
        });
        (state, clock)
    }

    fn row_loader(calls: &Arc<AtomicUsize>, fail: Arc<AtomicBool>) -> Loader<Vec<MostActiveRow>> {
        let calls = Arc::clone(calls);
        Arc::new(move || {
            let calls = Arc::clone(&calls);
            let fail = Arc::clone(&fail);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if fail.load(Ordering::SeqCst) {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(Vec::new())
                }
            })
        })
    }

    /// Waits for the refresher task to end; a task that ignores its shutdown fails the test rather
    /// than hanging it.
    async fn joined(task: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the refresher ends on shutdown")
            .unwrap();
    }

    async fn until(mut condition: impl FnMut() -> bool, what: &str) {
        for _ in 0..400 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn the_refresher_replaces_the_panel_at_each_quarter_hour_boundary() {
        let (state, clock) = state_with_clock(Duration::from_millis(5));
        let calls = Arc::new(AtomicUsize::new(0));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = state
            .spawn_refresher(
                row_loader(&calls, Arc::new(AtomicBool::new(false))),
                async move {
                    let _ = stopped.await;
                },
            )
            .expect("a caching state runs a refresher");
        until(
            || matches!(state.most_active.held(1000), Held::Fresh(_)),
            "the warm-up",
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Within the same quarter hour nothing more is computed.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The boundary passes with no request in sight: the panel is replaced anyway.
        clock.store(1001, Ordering::SeqCst);
        until(
            || matches!(state.most_active.held(1001), Held::Fresh(_)),
            "the boundary refresh",
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        stop.send(()).unwrap();
        joined(task).await;
    }

    #[tokio::test]
    async fn the_refresher_stops_when_told_to_and_computes_nothing_after() {
        let (state, clock) = state_with_clock(Duration::from_millis(5));
        let calls = Arc::new(AtomicUsize::new(0));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = state
            .spawn_refresher(
                row_loader(&calls, Arc::new(AtomicBool::new(false))),
                async move {
                    let _ = stopped.await;
                },
            )
            .unwrap();
        until(|| calls.load(Ordering::SeqCst) == 1, "the warm-up").await;
        stop.send(()).unwrap();
        joined(task).await;
        clock.store(1001, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failing_scheduled_refresh_keeps_the_panel_and_retries_next_boundary() {
        let (state, clock) = state_with_clock(Duration::from_millis(5));
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = state
            .spawn_refresher(row_loader(&calls, Arc::clone(&fail)), async move {
                let _ = stopped.await;
            })
            .unwrap();
        until(
            || matches!(state.most_active.held(1000), Held::Fresh(_)),
            "the warm-up",
        )
        .await;
        fail.store(true, Ordering::SeqCst);
        clock.store(1001, Ordering::SeqCst);
        until(|| calls.load(Ordering::SeqCst) == 2, "the failing attempt").await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a failed attempt is not retried every poll"
        );
        assert!(
            matches!(state.most_active.held(1001), Held::Stale(_)),
            "the previous panel stays"
        );
        fail.store(false, Ordering::SeqCst);
        clock.store(1002, Ordering::SeqCst);
        until(
            || matches!(state.most_active.held(1002), Held::Fresh(_)),
            "the next boundary",
        )
        .await;
        stop.send(()).unwrap();
        joined(task).await;
    }

    #[tokio::test]
    async fn an_uncached_state_runs_no_refresher() {
        let calls = Arc::new(AtomicUsize::new(0));
        let none = ReadState::uncached().spawn_refresher(
            row_loader(&calls, Arc::new(AtomicBool::new(false))),
            std::future::pending(),
        );
        assert!(none.is_none());
    }

    #[test]
    fn a_computation_that_started_earlier_never_replaces_a_later_one() {
        let cell = SwrCell::new(HOUR, HOUR, true);
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(1);
        cell.store(2, later, 20usize);
        cell.store(1, t0, 10usize);
        assert!(matches!(cell.held(2), Held::Fresh(20)));
        cell.store(2, later, 21usize);
        assert!(matches!(cell.held(2), Held::Fresh(21)));
    }

    /// A virtual monotonic clock and a quarter hour derived from it, both moved by the test.
    struct Virtual {
        base: Instant,
        ms: Arc<AtomicU64>,
    }

    impl Virtual {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                ms: Arc::new(AtomicU64::new(0)),
            }
        }
        fn advance(&self, by: Duration) {
            self.ms.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
        }
        fn now_fn(&self) -> impl Fn() -> Instant + Send + Sync + 'static {
            let (base, ms) = (self.base, Arc::clone(&self.ms));
            move || base + Duration::from_millis(ms.load(Ordering::SeqCst))
        }
        fn quarter_hour_fn(&self) -> impl Fn() -> u64 + Send + Sync + 'static {
            let ms = Arc::clone(&self.ms);
            move || 1000 + ms.load(Ordering::SeqCst) / 900_000
        }
    }

    /// The owner's decision: a held panel is shown at most 15 minutes old. Pinned against the
    /// production constants, through the state the console runs with and through the cell's
    /// behaviour at both sides of the line.
    #[test]
    fn the_owners_fifteen_minute_bound_is_what_the_console_runs_with() {
        assert_eq!(MOST_ACTIVE_MAX_AGE, Duration::from_secs(15 * 60));
        assert_eq!(
            ReadState::new().most_active.max_age,
            Duration::from_secs(15 * 60)
        );
        let clock = Virtual::new();
        let cell =
            SwrCell::with_clock(MOST_ACTIVE_FRESH, MOST_ACTIVE_MAX_AGE, true, clock.now_fn());
        cell.store(1, clock.now_fn()(), 1usize);
        clock.advance(Duration::from_secs(14 * 60 + 59));
        assert!(matches!(cell.held(1), Held::Stale(1)), "14:59 is served");
        clock.advance(Duration::from_secs(2));
        assert!(matches!(cell.held(1), Held::Miss), "15:01 is not");
    }

    /// The age is counted from the start of the computation, so the data shown is at most the cap
    /// old even when the computation itself took a while.
    #[tokio::test]
    async fn the_age_is_counted_from_when_the_computation_started() {
        let clock = Virtual::new();
        let cell = Arc::new(SwrCell::with_clock(
            Duration::ZERO,
            Duration::from_secs(900),
            true,
            clock.now_fn(),
        ));
        let ms = Arc::clone(&clock.ms);
        let slow: Loader<usize> = Arc::new(move || {
            let ms = Arc::clone(&ms);
            Box::pin(async move {
                ms.fetch_add(600_000, Ordering::SeqCst);
                Ok(7)
            })
        });
        assert_eq!(cell.get(1, slow).await.unwrap(), 7);
        clock.advance(Duration::from_secs(301));
        // 301 s after it finished, 901 s after it started.
        assert!(matches!(cell.held(1), Held::Miss));
    }

    /// The wall clock stepping back by more than a quarter hour leaves the stored entry's stamp
    /// ahead of the current one. It is served while young and replaced by the next computation,
    /// instead of pinning the cell until the clock catches up (every request would load).
    #[tokio::test]
    async fn an_entry_ahead_of_a_stepped_back_clock_is_replaced() {
        let clock = Virtual::new();
        let cell = Arc::new(SwrCell::with_clock(
            Duration::from_secs(30),
            Duration::from_secs(900),
            true,
            clock.now_fn(),
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let load = counting(&calls, usize::MAX);
        assert_eq!(cell.get(1000, load.clone()).await.unwrap(), 1);
        clock.advance(Duration::from_secs(60));
        // The clock is now 45 minutes behind where the entry was computed.
        assert_eq!(cell.get(997, load.clone()).await.unwrap(), 1, "served");
        settled(&cell, &calls, 2).await;
        assert!(
            matches!(cell.held(997), Held::Fresh(2)),
            "and replaced, not refused"
        );
        // The same through the scheduled path.
        clock.advance(Duration::from_secs(60));
        cell.refresh(990, load).await.unwrap();
        assert!(matches!(cell.held(990), Held::Fresh(3)));
    }

    fn timed_loader(
        calls: &Arc<AtomicUsize>,
        clock_ms: &Arc<AtomicU64>,
        load_ms: u64,
    ) -> Loader<Vec<MostActiveRow>> {
        let calls = Arc::clone(calls);
        let clock_ms = Arc::clone(clock_ms);
        Arc::new(move || {
            let calls = Arc::clone(&calls);
            let clock_ms = Arc::clone(&clock_ms);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                clock_ms.fetch_add(load_ms, Ordering::SeqCst);
                Ok(Vec::new())
            })
        })
    }

    /// The production shape: the age cap equals the quarter hour. An idle console (no request
    /// ever calls `get`) must still have a panel to serve at every moment across several
    /// boundaries, so a first view never waits. Time is virtual (30 s steps, a 1.5 s computation,
    /// as measured on the live node), so the outcome does not depend on the machine's load.
    #[tokio::test]
    async fn an_idle_console_always_has_a_panel_to_serve_with_the_cap_equal_to_the_cadence() {
        let clock = Virtual::new();
        let state = ReadState::with_clocks(
            Duration::from_secs(30),
            Duration::from_secs(900),
            Duration::from_millis(1),
            true,
            clock.quarter_hour_fn(),
            clock.now_fn(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = state
            .spawn_refresher(timed_loader(&calls, &clock.ms, 1_500), async move {
                let _ = stopped.await;
            })
            .unwrap();
        until(|| calls.load(Ordering::SeqCst) >= 1, "the warm-up").await;
        for step in 1..=150 {
            clock.advance(Duration::from_secs(30));
            // Checked before the refresher gets a turn: a panel it has not yet replaced must
            // still be servable at this moment, or a first view here would wait.
            let stamp = state.quarter_hour();
            assert!(
                !matches!(state.most_active.held(stamp), Held::Miss),
                "no panel to serve {} s in (quarter hour {stamp})",
                step * 30
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // 75 virtual minutes: the warm-up, five boundaries and a ten-minute trigger between each,
        // and no more: a refresher that fired on every poll would cost a backend, not 0.33% of one.
        let calls = calls.load(Ordering::SeqCst);
        assert!(
            (10..=12).contains(&calls),
            "{calls} computations in 75 minutes"
        );
        stop.send(()).unwrap();
        joined(task).await;
    }

    #[tokio::test]
    async fn the_refresher_ends_on_shutdown_while_a_computation_is_in_flight() {
        let (state, _clock) = state_with_clock(Duration::from_millis(5));
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = Arc::clone(&entered);
        let hangs: Loader<Vec<MostActiveRow>> = Arc::new(move || {
            signal.notify_one();
            Box::pin(std::future::pending::<
                Result<Vec<MostActiveRow>, sqlx::Error>,
            >())
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = state
            .spawn_refresher(hangs, async move {
                let _ = stopped.await;
            })
            .unwrap();
        entered.notified().await;
        stop.send(()).unwrap();
        joined(task).await;
        assert!(
            !state.most_active.refreshing.load(Ordering::SeqCst),
            "the in-flight claim is released"
        );
    }
}
