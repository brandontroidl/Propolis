//! A process-wide byte budget for capture bodies held in memory.
//!
//! Distinct from [`crate::budget::ConnectionBudget`]: that one is per connection and charges the
//! fake filesystem and shell state. A [`CaptureMemoryBudget`] is per sensor process and charges
//! the bytes of captured upload and payload bodies buffered before they reach the quarantine
//! spool, so many concurrent connections cannot together push a sensor past its systemd
//! `MemoryMax` (an OOM kill loses every in-flight capture, not just the greedy one).
//!
//! Pure and synchronous: std atomics only, no I/O, no async. Reservations are RAII, so a refund
//! happens on normal drop, early return and panic unwinding alike.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Granularity at which a [`CaptureBody`] charges the budget. The charge is the allocated
/// capacity, so it is a whole number of chunks, never the (smaller) byte length.
pub const CAPTURE_CHUNK_BYTES: u64 = 64 * 1024;

/// Share of a unit's `MemoryMax` given to capture bodies. The remaining 60% is headroom for the
/// tokio runtime, protocol parsers, shell and fake-filesystem state, event queues and allocator
/// overhead, none of which this budget charges. Unverified choice, not a measurement.
const CAPTURE_BUDGET_PERCENT: u64 = 40;

/// [`default_capture_budget_bytes`] for a 256 MiB unit (107_374_182, about 102.4 MiB). Derived
/// from the formula rather than a separate constant so the two cannot disagree.
pub const DEFAULT_CAPTURE_BUDGET_BYTES_256M: u64 = default_capture_budget_bytes(256 * 1024 * 1024);

/// The capture budget for a sensor whose unit has `unit_memory_max_bytes` of `MemoryMax`: 40%,
/// rounded down. Saturates rather than wrapping on an absurd limit.
pub const fn default_capture_budget_bytes(unit_memory_max_bytes: u64) -> u64 {
    unit_memory_max_bytes.saturating_mul(CAPTURE_BUDGET_PERCENT) / 100
}

#[derive(Debug)]
struct Inner {
    ceiling: u64,
    current: AtomicU64,
    high_water: AtomicU64,
    refused: AtomicU64,
}

/// The shared pool. Cloning is cheap and every clone charges the same counters.
#[derive(Debug, Clone)]
pub struct CaptureMemoryBudget {
    inner: Arc<Inner>,
}

impl CaptureMemoryBudget {
    pub fn new(ceiling_bytes: u64) -> Self {
        Self {
            inner: Arc::new(Inner {
                ceiling: ceiling_bytes,
                current: AtomicU64::new(0),
                high_water: AtomicU64::new(0),
                refused: AtomicU64::new(0),
            }),
        }
    }

    /// Reserves `bytes` or returns `None` without blocking.
    ///
    /// The check and the increment are one compare-exchange, so two racing callers cannot both
    /// observe room that only one of them fits in: a loser's exchange fails, it reloads the new
    /// total and re-checks. `current` therefore never exceeds the ceiling, and the sum of live
    /// reservations equals `current`. A request whose sum would overflow `u64` is refused.
    pub fn try_reserve(&self, bytes: u64) -> Option<Reservation> {
        let inner = &self.inner;
        let mut observed = inner.current.load(Ordering::Acquire);
        loop {
            let next = match observed.checked_add(bytes) {
                Some(next) if next <= inner.ceiling => next,
                _ => {
                    inner.refused.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            };
            match inner.current.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    inner.high_water.fetch_max(next, Ordering::Relaxed);
                    return Some(Reservation {
                        inner: Arc::clone(inner),
                        bytes,
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    /// A reservation of nothing, for a holder that has not yet been granted anything.
    pub fn empty_reservation(&self) -> Reservation {
        Reservation {
            inner: Arc::clone(&self.inner),
            bytes: 0,
        }
    }

    pub fn ceiling_bytes(&self) -> u64 {
        self.inner.ceiling
    }

    pub fn current_bytes(&self) -> u64 {
        self.inner.current.load(Ordering::Acquire)
    }

    pub fn high_water_bytes(&self) -> u64 {
        self.inner.high_water.load(Ordering::Relaxed)
    }

    pub fn refused_reservations(&self) -> u64 {
        self.inner.refused.load(Ordering::Relaxed)
    }
}

/// Bytes held against a [`CaptureMemoryBudget`]; refunded exactly once when dropped.
#[derive(Debug)]
pub struct Reservation {
    inner: Arc<Inner>,
    bytes: u64,
}

impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Moves `bytes` of this reservation into a reservation of its own, or `None` when it holds
    /// less. The budget's total does not change: the two halves refund exactly what the whole
    /// would have, each on its own drop. This is how a worst-case allowance reserved before work
    /// runs is handed out to the pieces of output the work produces.
    pub fn split_off(&mut self, bytes: u64) -> Option<Reservation> {
        self.bytes = self.bytes.checked_sub(bytes)?;
        Some(Reservation {
            inner: Arc::clone(&self.inner),
            bytes,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.inner.current.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// The budget has no room for another chunk. Bytes buffered before the refusal are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureExhausted;

impl std::fmt::Display for CaptureExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("capture memory budget exhausted")
    }
}

impl std::error::Error for CaptureExhausted {}

/// A growable capture buffer charged to a [`CaptureMemoryBudget`] in [`CAPTURE_CHUNK_BYTES`]
/// chunks. The charge is the buffer's capacity (chunks held times the chunk size), which is
/// never below `len`. Capacity is grown with `reserve_exact` to exactly the charged size, so
/// `Vec`'s own over-allocation cannot make the real allocation outrun the charge. A grow
/// reallocates, so the old and new buffers briefly coexist; that transient is not charged.
#[derive(Debug)]
pub struct CaptureBody {
    budget: Arc<CaptureMemoryBudget>,
    buf: Vec<u8>,
    chunks: Vec<Reservation>,
    /// Sticky: set the first time an append was refused for lack of budget, so the hand-off can
    /// mark the capture truncated without every sensor threading its own flag.
    exhausted: bool,
}

impl CaptureBody {
    /// An empty body. Nothing is reserved until bytes are pushed.
    pub fn with_budget(budget: Arc<CaptureMemoryBudget>) -> Self {
        Self {
            budget,
            buf: Vec::new(),
            chunks: Vec::new(),
            exhausted: false,
        }
    }

    /// A body charged to a private budget that can never refuse. For tests and fixtures only: a
    /// sensor that used it would hold capture memory outside the process-wide ceiling.
    pub fn unbudgeted() -> Self {
        Self::with_budget(Arc::new(CaptureMemoryBudget::new(u64::MAX)))
    }

    /// Whether any append was refused for lack of budget (the body is then a truncated prefix).
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    fn charged_capacity(&self) -> usize {
        let chunk = CAPTURE_CHUNK_BYTES as usize;
        self.chunks.len().saturating_mul(chunk)
    }

    /// Appends `data`, reserving more chunks as needed. If a chunk cannot be reserved, as much of
    /// `data` as fits in already-charged capacity is still appended, nothing further is, and
    /// `Err(CaptureExhausted)` is returned: the caller keeps the prefix and marks truncation.
    ///
    /// Exhaustion is latched: once refused, every later call returns `Err` without appending or
    /// reserving, even if other captures have since freed budget. Otherwise a continuing caller
    /// would splice later bytes after the dropped ones and the hand-off would hash that gapped
    /// body as a contiguous prefix.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), CaptureExhausted> {
        if self.exhausted {
            return Err(CaptureExhausted);
        }
        let wanted = self.buf.len().saturating_add(data.len());
        let mut exhausted = false;
        while self.charged_capacity() < wanted {
            match self.budget.try_reserve(CAPTURE_CHUNK_BYTES) {
                Some(r) => {
                    self.chunks.push(r);
                    let target = self.charged_capacity();
                    self.buf
                        .reserve_exact(target.saturating_sub(self.buf.len()));
                }
                None => {
                    exhausted = true;
                    break;
                }
            }
        }
        let room = self.charged_capacity().saturating_sub(self.buf.len());
        let take = data.len().min(room);
        if let Some(head) = data.get(..take) {
            self.buf.extend_from_slice(head);
        }
        if exhausted {
            self.exhausted = true;
            Err(CaptureExhausted)
        } else {
            Ok(())
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Bytes currently charged to the budget by this body.
    pub fn charged_bytes(&self) -> u64 {
        (self.chunks.len() as u64).saturating_mul(CAPTURE_CHUNK_BYTES)
    }

    /// Moves the bytes out to be read in place by something that must own them (the fake shell's
    /// standard input), leaving the body empty. The chunk reservations stay with the body, so the
    /// bytes remain charged for as long as the body lives, whichever way the borrower ends -
    /// including a panic, which drops the body and refunds. Give them back with
    /// [`Self::restore_bytes`].
    pub fn lend_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Returns bytes taken by [`Self::lend_bytes`].
    pub fn restore_bytes(&mut self, bytes: Vec<u8>) {
        self.buf = bytes;
    }

    /// Consumes the body and returns its bytes. The chunk reservations are released on return, so
    /// the returned `Vec` is no longer charged: the caller owns that memory from here.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn reserve_to_ceiling_then_refuse_and_count() {
        let b = CaptureMemoryBudget::new(100);
        let a = b.try_reserve(60).unwrap();
        let c = b.try_reserve(40).unwrap();
        assert_eq!(b.current_bytes(), 100);
        assert!(b.try_reserve(1).is_none());
        assert!(b.try_reserve(1).is_none());
        assert_eq!(b.refused_reservations(), 2);
        assert_eq!(b.current_bytes(), 100);
        assert_eq!((a.bytes(), c.bytes()), (60, 40));
    }

    #[test]
    fn oversized_and_overflowing_requests_are_refused() {
        let b = CaptureMemoryBudget::new(100);
        let _held = b.try_reserve(10).unwrap();
        assert!(b.try_reserve(91).is_none());
        assert!(b.try_reserve(u64::MAX).is_none());
        assert_eq!(b.current_bytes(), 10);
        assert_eq!(b.refused_reservations(), 2);
    }

    #[test]
    fn drop_refunds_to_prior_value_and_frees_room() {
        let b = CaptureMemoryBudget::new(100);
        let _base = b.try_reserve(30).unwrap();
        let before = b.current_bytes();
        {
            let _r = b.try_reserve(70).unwrap();
            assert_eq!(b.current_bytes(), 100);
            assert!(b.try_reserve(1).is_none());
        }
        assert_eq!(b.current_bytes(), before);
        assert!(b.try_reserve(70).is_some());
    }

    #[test]
    fn panic_unwind_refunds() {
        let b = CaptureMemoryBudget::new(100);
        let b2 = b.clone();
        let res = thread::spawn(move || {
            let _r = b2.try_reserve(80).unwrap();
            panic!("boom");
        })
        .join();
        assert!(res.is_err());
        assert_eq!(b.current_bytes(), 0);
    }

    #[test]
    fn split_off_hands_out_part_of_a_reservation_without_changing_the_total() {
        let b = CaptureMemoryBudget::new(100);
        let mut whole = b.try_reserve(60).unwrap();
        let part = whole.split_off(25).unwrap();
        assert_eq!((whole.bytes(), part.bytes()), (35, 25));
        assert_eq!(b.current_bytes(), 60);
        assert!(whole.split_off(36).is_none(), "more than it holds");
        assert_eq!(whole.bytes(), 35, "a refused split takes nothing");
        drop(part);
        assert_eq!(b.current_bytes(), 35);
        drop(whole);
        assert_eq!(b.current_bytes(), 0);
        assert_eq!(b.empty_reservation().bytes(), 0);
        assert_eq!(b.current_bytes(), 0);
    }

    #[test]
    fn lent_bytes_stay_charged_until_the_body_drops_and_come_back_whole() {
        let b = Arc::new(CaptureMemoryBudget::new(10 * CAPTURE_CHUNK_BYTES));
        let mut body = CaptureBody::with_budget(b.clone());
        body.extend_from_slice(b"payload").unwrap();
        let charged = b.current_bytes();
        assert_eq!(charged, CAPTURE_CHUNK_BYTES);
        let lent = body.lend_bytes();
        assert_eq!(lent, b"payload");
        assert!(body.is_empty());
        assert_eq!(
            b.current_bytes(),
            charged,
            "lending does not release the charge"
        );
        body.restore_bytes(lent);
        assert_eq!(body.as_slice(), b"payload");
        // A borrower that never returns the bytes (it panicked) still refunds with the body.
        let lent = body.lend_bytes();
        drop(body);
        assert_eq!(b.current_bytes(), 0);
        drop(lent);
    }

    #[test]
    fn high_water_records_peak_not_current() {
        let b = CaptureMemoryBudget::new(1000);
        let a = b.try_reserve(300).unwrap();
        let c = b.try_reserve(500).unwrap();
        drop(c);
        drop(a);
        let _d = b.try_reserve(100).unwrap();
        assert_eq!(b.current_bytes(), 100);
        assert_eq!(b.high_water_bytes(), 800);
    }

    #[test]
    fn concurrent_reserve_never_exceeds_ceiling() {
        const CEILING: u64 = 1000;
        const THREADS: usize = 16;
        let b = CaptureMemoryBudget::new(CEILING);
        // 16 threads x 20 attempts x 7 bytes = 2240 requested against a 1000 ceiling: the
        // contended window is real, and 7 does not divide 1000 so the last grant is partial-fit.
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let b = b.clone();
                thread::spawn(move || {
                    let mut held = Vec::new();
                    for _ in 0..20 {
                        assert!(b.current_bytes() <= CEILING);
                        if let Some(r) = b.try_reserve(7) {
                            held.push(r);
                        }
                    }
                    held
                })
            })
            .collect();
        let held: Vec<Vec<Reservation>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let granted: u64 = held.iter().flatten().map(Reservation::bytes).sum();
        assert!(granted <= CEILING);
        assert_eq!(
            granted, 994,
            "142 grants of 7 fit; any other count is a race"
        );
        assert_eq!(b.current_bytes(), granted);
        assert!(b.high_water_bytes() <= CEILING);
        assert_eq!(b.refused_reservations(), 16 * 20 - 142);
        drop(held);
        assert_eq!(b.current_bytes(), 0);
    }

    #[test]
    fn one_byte_charges_a_whole_chunk() {
        let b = Arc::new(CaptureMemoryBudget::new(10 * CAPTURE_CHUNK_BYTES));
        let mut body = CaptureBody::with_budget(Arc::clone(&b));
        assert_eq!(b.current_bytes(), 0);
        body.extend_from_slice(b"x").unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(b.current_bytes(), CAPTURE_CHUNK_BYTES);
        assert_eq!(body.charged_bytes(), CAPTURE_CHUNK_BYTES);
        // filling the chunk exactly does not charge a second one; one more byte does
        body.extend_from_slice(&vec![0u8; CAPTURE_CHUNK_BYTES as usize - 1])
            .unwrap();
        assert_eq!(b.current_bytes(), CAPTURE_CHUNK_BYTES);
        body.extend_from_slice(b"y").unwrap();
        assert_eq!(b.current_bytes(), 2 * CAPTURE_CHUNK_BYTES);
    }

    #[test]
    fn charge_covers_real_capacity() {
        let b = Arc::new(CaptureMemoryBudget::new(100 * CAPTURE_CHUNK_BYTES));
        let mut body = CaptureBody::with_budget(b);
        for _ in 0..50 {
            body.extend_from_slice(&[7u8; 5000]).unwrap();
            assert!(body.buf.capacity() as u64 <= body.charged_bytes());
            assert!(body.len() as u64 <= body.charged_bytes());
        }
    }

    #[test]
    fn exhaustion_keeps_prefix_and_stops() {
        let chunk = CAPTURE_CHUNK_BYTES as usize;
        let b = Arc::new(CaptureMemoryBudget::new(2 * CAPTURE_CHUNK_BYTES));
        let mut body = CaptureBody::with_budget(Arc::clone(&b));
        let first: Vec<u8> = (0..chunk).map(|i| (i % 251) as u8).collect();
        body.extend_from_slice(&first).unwrap();
        // 1.5 chunks more: the second chunk fits, the third does not
        let more: Vec<u8> = (0..chunk + chunk / 2).map(|i| (i % 241) as u8).collect();
        assert_eq!(body.extend_from_slice(&more), Err(CaptureExhausted));
        assert_eq!(body.len(), 2 * chunk);
        assert_eq!(&body.as_slice()[..chunk], &first[..]);
        assert_eq!(&body.as_slice()[chunk..], &more[..chunk]);
        assert_eq!(b.refused_reservations(), 1);
        // already exhausted and full: nothing more is appended
        assert_eq!(body.extend_from_slice(b"z"), Err(CaptureExhausted));
        assert_eq!(body.len(), 2 * chunk);
        assert_eq!(b.current_bytes(), 2 * CAPTURE_CHUNK_BYTES);
        assert_eq!(body.into_bytes().len(), 2 * chunk);
    }

    #[test]
    fn exhaustion_is_latched_even_after_budget_frees() {
        let chunk = CAPTURE_CHUNK_BYTES as usize;
        let b = Arc::new(CaptureMemoryBudget::new(2 * CAPTURE_CHUNK_BYTES));
        let mut body = CaptureBody::with_budget(Arc::clone(&b));
        // Another capture holds one chunk, so the body can only get one.
        let other = b.try_reserve(CAPTURE_CHUNK_BYTES).unwrap();
        let first: Vec<u8> = (0..chunk + 10).map(|i| (i % 251) as u8).collect();
        assert_eq!(body.extend_from_slice(&first), Err(CaptureExhausted));
        assert_eq!(body.len(), chunk);
        let prefix = body.as_slice().to_vec();
        assert_eq!(&prefix[..], &first[..chunk]);
        // Room appears: without the latch this would append after the dropped bytes.
        drop(other);
        assert_eq!(body.extend_from_slice(b"later"), Err(CaptureExhausted));
        assert_eq!(body.as_slice(), &prefix[..]);
        assert_eq!(b.current_bytes(), CAPTURE_CHUNK_BYTES);
        assert!(body.is_exhausted());
    }

    #[test]
    fn dropping_body_refunds_every_chunk() {
        let b = Arc::new(CaptureMemoryBudget::new(10 * CAPTURE_CHUNK_BYTES));
        let _other = b.try_reserve(123).unwrap();
        let mut body = CaptureBody::with_budget(Arc::clone(&b));
        body.extend_from_slice(&vec![1u8; 3 * CAPTURE_CHUNK_BYTES as usize])
            .unwrap();
        assert_eq!(b.current_bytes(), 123 + 3 * CAPTURE_CHUNK_BYTES);
        drop(body);
        assert_eq!(b.current_bytes(), 123);
    }

    #[test]
    fn into_bytes_returns_data_and_releases_charge() {
        let b = Arc::new(CaptureMemoryBudget::new(4 * CAPTURE_CHUNK_BYTES));
        let mut body = CaptureBody::with_budget(Arc::clone(&b));
        body.extend_from_slice(b"hello ").unwrap();
        body.extend_from_slice(b"world").unwrap();
        assert!(!body.is_empty());
        let bytes = body.into_bytes();
        assert_eq!(bytes, b"hello world");
        assert_eq!(b.current_bytes(), 0);
    }

    #[test]
    fn two_bodies_share_one_ceiling() {
        let b = Arc::new(CaptureMemoryBudget::new(CAPTURE_CHUNK_BYTES));
        let mut a = CaptureBody::with_budget(Arc::clone(&b));
        let mut c = CaptureBody::with_budget(Arc::clone(&b));
        a.extend_from_slice(b"a").unwrap();
        assert_eq!(c.extend_from_slice(b"c"), Err(CaptureExhausted));
        assert!(c.is_empty());
        drop(a);
        // The refused body stays refused (latched); freed room serves a new body.
        assert_eq!(c.extend_from_slice(b"c"), Err(CaptureExhausted));
        assert!(c.is_empty());
        let mut d = CaptureBody::with_budget(Arc::clone(&b));
        d.extend_from_slice(b"d").unwrap();
        assert_eq!(d.as_slice(), b"d");
    }

    #[test]
    fn default_budget_is_forty_percent_rounded_down() {
        assert_eq!(default_capture_budget_bytes(1000), 400);
        assert_eq!(default_capture_budget_bytes(0), 0);
        assert_eq!(default_capture_budget_bytes(256 * 1024 * 1024), 107_374_182);
        assert_eq!(DEFAULT_CAPTURE_BUDGET_BYTES_256M, 107_374_182);
        // saturates instead of wrapping
        assert_eq!(default_capture_budget_bytes(u64::MAX), u64::MAX / 100);
    }
}
