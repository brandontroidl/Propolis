//! Who holds the sensor's output budget, and how a session that cannot be served gets some.
//!
//! The output budget (`OUTPUT_BUDGET_BYTES`) is one pool charged by every connection for the bytes
//! it queues for its peer and the input it holds behind them. A pool alone starves: a few peers
//! that never read can fill it, and then every other session is refused. So each connection
//! registers here and keeps its total charge current. A session that cannot get what it needs
//! evicts the connection holding the most (never itself, never one holding less than it), waits
//! for the refund, and retries; a connection whose queue has made no progress for the stall limit
//! closes on its own.
//!
//! Nothing here changes what is charged to the budget or how it is refunded: that stays the RAII
//! `Reservation` of `sensor_framework::capture_budget`. This only decides who is asked to let go.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sensor_framework::{CaptureMemoryBudget, Reservation};
use tokio::sync::Notify;

/// How long a connection's queued output may go without a byte being sent before the connection
/// is closed with `end_reason: output_stalled`.
pub const OUTPUT_STALL_LIMIT: Duration = Duration::from_secs(30);

/// How many times a session that cannot get budget evicts a larger holder and waits for the
/// refund before it gives up and defers the work, and how long it waits each time.
const EVICTION_ROUNDS: usize = 3;
const EVICTION_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct Holder {
    /// Bytes this connection holds of the budget (queued output, deferred input), refreshed by the
    /// session each time round its loop. A little stale is fine: it only ranks holders.
    charged: AtomicU64,
    evicted: AtomicBool,
    wake: Notify,
}

#[derive(Debug)]
pub struct OutputLedger {
    budget: Arc<CaptureMemoryBudget>,
    stall_limit: Duration,
    holders: Mutex<HashMap<u64, Arc<Holder>>>,
    next_id: AtomicU64,
}

impl OutputLedger {
    pub fn new(budget_bytes: u64, stall_limit: Duration) -> Arc<Self> {
        Arc::new(Self {
            budget: Arc::new(CaptureMemoryBudget::new(budget_bytes)),
            stall_limit,
            holders: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    pub fn budget(&self) -> &Arc<CaptureMemoryBudget> {
        &self.budget
    }

    pub fn stall_limit(&self) -> Duration {
        self.stall_limit
    }

    /// Register a connection; it leaves the ledger when the registration is dropped.
    pub fn register(self: &Arc<Self>) -> Registration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let holder = Arc::new(Holder {
            charged: AtomicU64::new(0),
            evicted: AtomicBool::new(false),
            wake: Notify::new(),
        });
        self.lock().insert(id, holder.clone());
        Registration {
            ledger: self.clone(),
            id,
            holder,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<Holder>>> {
        self.holders.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ask the connection holding the most to let go, if another holds more than `my_charge`.
    /// Returns whether a refund is on its way: a holder was asked just now, or was already.
    fn evict_largest_other(&self, me: u64, my_charge: u64) -> bool {
        let holders = self.lock();
        let mut largest: Option<(&u64, &Arc<Holder>, u64)> = None;
        for (id, holder) in holders.iter().filter(|(id, _)| **id != me) {
            let charged = holder.charged.load(Ordering::Relaxed);
            if holder.evicted.load(Ordering::Acquire) && charged > 0 {
                return true;
            }
            if charged > my_charge && largest.is_none_or(|(_, _, best)| charged > best) {
                largest = Some((id, holder, charged));
            }
        }
        match largest {
            Some((_, holder, _)) => {
                holder.evicted.store(true, Ordering::Release);
                holder.wake.notify_one();
                true
            }
            None => false,
        }
    }
}

/// One connection's place in the ledger.
#[derive(Debug)]
pub struct Registration {
    ledger: Arc<OutputLedger>,
    id: u64,
    holder: Arc<Holder>,
}

impl Registration {
    pub fn set_charged(&self, bytes: u64) {
        self.holder.charged.store(bytes, Ordering::Relaxed);
    }

    pub fn charged(&self) -> u64 {
        self.holder.charged.load(Ordering::Relaxed)
    }

    pub fn is_evicted(&self) -> bool {
        self.holder.evicted.load(Ordering::Acquire)
    }

    /// Completes when this connection has been asked to let go. Cancel-safe.
    pub async fn evicted(&self) {
        loop {
            let woken = self.holder.wake.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            if self.is_evicted() {
                return;
            }
            woken.await;
        }
    }

    /// Reserve `bytes` of the output budget for this connection. When the budget is full this
    /// evicts the connection holding the most (if it holds more than this one), waits for the
    /// refund, and tries again; `None` means nothing larger could be asked to let go, and the
    /// caller defers its work until budget is refunded.
    pub async fn acquire(&self, bytes: u64) -> Option<Reservation> {
        let budget = &self.ledger.budget;
        for _ in 0..EVICTION_ROUNDS {
            // Armed before the attempt, so a refund between a failed attempt and the wait is seen.
            let refund = budget.refunded();
            tokio::pin!(refund);
            refund.as_mut().enable();
            if let Some(reservation) = budget.try_reserve(bytes) {
                return Some(reservation);
            }
            if !self.ledger.evict_largest_other(self.id, self.charged()) {
                return None;
            }
            let _ = tokio::time::timeout(EVICTION_WAIT, refund).await;
        }
        budget.try_reserve(bytes)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.ledger.lock().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_session_that_cannot_be_served_evicts_the_largest_holder_and_gets_its_budget() {
        let ledger = OutputLedger::new(100, OUTPUT_STALL_LIMIT);
        let small = ledger.register();
        let big = ledger.register();
        let newcomer = ledger.register();
        let hold_small = ledger.budget().try_reserve(30).unwrap();
        let hold_big = ledger.budget().try_reserve(70).unwrap();
        small.set_charged(30);
        big.set_charged(70);

        let evictee = tokio::spawn(async move {
            big.evicted().await;
            drop(hold_big);
            big
        });
        let got = newcomer.acquire(50).await;
        assert!(got.is_some(), "the newcomer was served");
        assert!(evictee.await.unwrap().is_evicted());
        assert!(!small.is_evicted(), "the smaller holder was left alone");
        drop(hold_small);
    }

    #[tokio::test]
    async fn a_session_holding_the_most_is_never_evicted_for_a_smaller_one_and_defers() {
        let ledger = OutputLedger::new(100, OUTPUT_STALL_LIMIT);
        let big = ledger.register();
        let other = ledger.register();
        let _hold = ledger.budget().try_reserve(100).unwrap();
        big.set_charged(80);
        other.set_charged(20);
        assert!(big.acquire(10).await.is_none());
        assert!(!other.is_evicted());
        assert!(!big.is_evicted());
    }

    #[test]
    fn a_dropped_registration_leaves_the_ledger() {
        let ledger = OutputLedger::new(10, OUTPUT_STALL_LIMIT);
        let a = ledger.register();
        let b = ledger.register();
        drop(a);
        assert_eq!(ledger.lock().len(), 1);
        drop(b);
        assert_eq!(ledger.lock().len(), 0);
    }
}
