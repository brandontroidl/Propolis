//! The gateway's per-collector verification state machine: turns a wire `Batch` into an
//! accept/duplicate/reject/retry `Ack` decision. Monotonic seq plus an unbroken rolling-hash
//! chain reject gaps, reordering, and tamper; an already-accepted seq is an idempotent
//! duplicate re-ack that never re-touches the spool (closing the crash-retry duplicate
//! window); state is persisted durably (see `state.rs`) only after the spool write succeeds,
//! so the on-crash window is at-least-once, matching intake's existing
//! read-then-persist_cursor contract.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use collector_wire::ack::{Ack, AckReason, AckStatus};
use collector_wire::frame::Batch;

use crate::server::BatchSink;
use crate::state::CollectorState;

/// Appends a batch's records to the durable spool for `collector_id`. `spool::SpoolWriter` is
/// the real, production implementation; this crate's own tests inject a stub (a no-op,
/// counting, or failing implementation) so `GatewaySink::accept` is testable without touching
/// the filesystem.
pub trait SpoolWrite: Send + Sync + 'static {
    fn write_records(&self, collector_id: &str, records: &[Vec<u8>]) -> std::io::Result<()>;
}

/// The gateway's `BatchSink`: verifies each batch against per-collector durable state (seq +
/// rolling hash) before handing its records to the spool. See `accept` for the exact,
/// order-sensitive verification steps.
pub struct GatewaySink<S: SpoolWrite> {
    state_dir: PathBuf,
    spool: S,
    states: Mutex<HashMap<String, CollectorState>>,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    reused_batches: AtomicU64,
    reused_records: AtomicU64,
    reuse_log: Mutex<ReuseLogLimiter>,
}

/// The shortest gap between two reused-seq ERROR lines for one collector. A compromised or
/// looping collector can resend at will, and one line per batch would flood the journal.
pub const REUSED_SEQ_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// How many collectors the reused-seq limiter remembers at once. Ids come from certificates the
/// CA issued, so this is far above any real deployment, but the map is bounded regardless.
pub const REUSED_SEQ_TRACKED_COLLECTORS: usize = 1024;

/// What one collector's reused-seq lines have held back since the last one was logged.
struct ReuseLogEntry {
    last_logged: Instant,
    suppressed_batches: u64,
    suppressed_records: u64,
}

/// Per-collector rate limit for the reused-seq line: at most one per
/// [`REUSED_SEQ_LOG_INTERVAL`], and the next one carries what was held back in between.
struct ReuseLogLimiter {
    entries: HashMap<String, ReuseLogEntry>,
}

impl ReuseLogLimiter {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Records one reused-seq batch of `records` records at `now`. Returns the suppressed
    /// (batches, records) to report when this one should be logged, or `None` when it falls
    /// inside the collector's window and is only added to the held-back totals.
    fn note(&mut self, collector_id: &str, records: u64, now: Instant) -> Option<(u64, u64)> {
        if let Some(entry) = self.entries.get_mut(collector_id) {
            if now.saturating_duration_since(entry.last_logged) < REUSED_SEQ_LOG_INTERVAL {
                entry.suppressed_batches += 1;
                entry.suppressed_records += records;
                return None;
            }
            let suppressed = (entry.suppressed_batches, entry.suppressed_records);
            *entry = ReuseLogEntry {
                last_logged: now,
                suppressed_batches: 0,
                suppressed_records: 0,
            };
            return Some(suppressed);
        }
        if self.entries.len() >= REUSED_SEQ_TRACKED_COLLECTORS {
            // Forget the collector logged longest ago. Its held-back totals are lost from the
            // next line only; the sink's counters still hold them.
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_logged)
                .map(|(id, _)| id.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            collector_id.to_string(),
            ReuseLogEntry {
                last_logged: now,
                suppressed_batches: 0,
                suppressed_records: 0,
            },
        );
        Some((0, 0))
    }
}

/// How many batches arrived under the last accepted seq of their collector with content that
/// differs from the batch accepted under it, and how many records they carried. Every one of
/// those batches was acknowledged `Duplicate` and nothing was stored from it. `records` is
/// their size, not what is missing: a batch the shipper rebuilt by reading the same log again
/// from the same offset begins with the lines of the earlier batch under that seq, which are
/// stored, and only its lines after those never arrived. A batch built from another log, or
/// from a cursor that had moved on, has none of its lines stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReusedSeqCounts {
    pub batches: u64,
    pub records: u64,
}

impl<S: SpoolWrite> GatewaySink<S> {
    pub fn new(state_dir: PathBuf, spool: S) -> Self {
        Self::with_clock(state_dir, spool, Instant::now)
    }

    /// `new` with the clock the reused-seq log limiter reads, so a test can step time instead
    /// of sleeping through the limiter's window.
    pub fn with_clock(
        state_dir: PathBuf,
        spool: S,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            state_dir,
            spool,
            states: Mutex::new(HashMap::new()),
            clock: Box::new(clock),
            reused_batches: AtomicU64::new(0),
            reused_records: AtomicU64::new(0),
            reuse_log: Mutex::new(ReuseLogLimiter::new()),
        }
    }

    /// Counts a batch that reused the collector's last accepted seq with different content and
    /// logs it, rate-limited per collector. The message says only that this batch was not
    /// stored: the gateway cannot tell how many of its lines it already holds from the earlier
    /// batch under this seq (see [`ReusedSeqCounts`]). `collector_id` reaches here only after a
    /// batch was stored under it, which `CollectorState::store` refuses for an unsafe id, and it
    /// goes out as a field, never inside the message. No record content is logged.
    fn note_reused_seq(&self, collector_id: &str, batch: &Batch) {
        let records = batch.records.len() as u64;
        self.reused_batches.fetch_add(1, Ordering::Relaxed);
        self.reused_records.fetch_add(records, Ordering::Relaxed);
        let now = (self.clock)();
        let decision = self
            .reuse_log
            .lock()
            .expect("reused-seq log limiter lock poisoned")
            .note(collector_id, records, now);
        if let Some((suppressed_batches, suppressed_records)) = decision {
            tracing::error!(
                %collector_id,
                seq = batch.seq,
                records,
                suppressed_batches,
                suppressed_records,
                "gateway: batch reuses the last accepted seq with different content; \
                 acknowledged as Duplicate without storing it"
            );
        }
    }

    /// Totals since this sink was built. The gateway has no metrics endpoint; this is what
    /// tests (and anything embedding the sink) read.
    pub fn reused_seq_counts(&self) -> ReusedSeqCounts {
        ReusedSeqCounts {
            batches: self.reused_batches.load(Ordering::Relaxed),
            records: self.reused_records.load(Ordering::Relaxed),
        }
    }
}

impl<S: SpoolWrite> BatchSink for GatewaySink<S> {
    fn accept(&self, collector_id: &str, batch: &Batch) -> Ack {
        let mut states = self.states.lock().expect("collector state lock poisoned");

        // 1. Load/lookup the collector's in-memory state, seeding from disk on first sight.
        // An unreadable or unsafe collector_id folds into "never seen" (fresh) exactly like a
        // missing state file - `CollectorState::store` below still fails closed on it, so a
        // bad id can never actually reach Accepted.
        let current = match states.get(collector_id) {
            Some(state) => *state,
            None => {
                let loaded = CollectorState::load(&self.state_dir, collector_id)
                    .ok()
                    .flatten()
                    .unwrap_or_else(CollectorState::fresh);
                states.insert(collector_id.to_string(), loaded);
                loaded
            }
        };

        // 2. An already-accepted (or lower) seq is an idempotent replay: re-ack without
        // writing the spool.
        if batch.seq <= current.last_seq {
            // The shipper takes this ack as "delivered" and moves its cursor on, so a batch
            // rebuilt under a used number after a lost ack is dropped here for good. Only
            // seq == last_seq can be told apart from a true replay: the gateway keeps one hash,
            // the last accepted batch's, so an older seq has nothing to compare against.
            // last_seq 0 means nothing was ever accepted, so there is no stored batch either.
            // The ack stays exactly what a replay gets; this only makes the loss visible.
            if current.last_seq > 0
                && batch.seq == current.last_seq
                && batch.batch_hash != current.last_batch_hash
            {
                self.note_reused_seq(collector_id, batch);
            }
            return Ack {
                status: AckStatus::Duplicate,
                reason: AckReason::None,
                next_expected_seq: current.last_seq + 1,
            };
        }

        // 3. Anything other than exactly the next seq is a gap.
        if batch.seq != current.last_seq + 1 {
            return Ack {
                status: AckStatus::Reject,
                reason: AckReason::SeqGap,
                next_expected_seq: current.last_seq + 1,
            };
        }

        // 4. The batch must chain from the last accepted hash.
        if batch.prev_batch_hash != current.last_batch_hash {
            return Ack {
                status: AckStatus::Reject,
                reason: AckReason::HashMismatch,
                next_expected_seq: current.last_seq + 1,
            };
        }

        // 5. Write records to the spool; a failure retries without advancing state.
        if let Err(error) = self.spool.write_records(collector_id, &batch.records) {
            tracing::warn!(%collector_id, %error, "spool write failed; retrying");
            return Ack {
                status: AckStatus::Retry,
                reason: AckReason::SpoolWriteFailed,
                next_expected_seq: current.last_seq + 1,
            };
        }

        // 6. Persist durable state. A failure here also retries: the records are already
        // appended, so a retry re-appends them - at-least-once, not exactly-once.
        let new_state = CollectorState {
            last_seq: batch.seq,
            last_batch_hash: batch.batch_hash,
        };
        if let Err(error) = new_state.store(&self.state_dir, collector_id) {
            tracing::warn!(%collector_id, %error, "state persist failed; retrying");
            return Ack {
                status: AckStatus::Retry,
                reason: AckReason::SpoolWriteFailed,
                next_expected_seq: current.last_seq + 1,
            };
        }

        // 7. Update in-memory state and accept.
        states.insert(collector_id.to_string(), new_state);
        Ack {
            status: AckStatus::Accepted,
            reason: AckReason::None,
            next_expected_seq: batch.seq + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reused_seq_limiter_never_tracks_more_than_its_bound_and_forgets_the_oldest_first() {
        let mut limiter = ReuseLogLimiter::new();
        let start = Instant::now();
        let extra = 10;
        for i in 0..REUSED_SEQ_TRACKED_COLLECTORS + extra {
            let at = start + Duration::from_millis(i as u64);
            assert_eq!(limiter.note(&format!("c{i}"), 1, at), Some((0, 0)));
            assert!(limiter.entries.len() <= REUSED_SEQ_TRACKED_COLLECTORS);
        }
        assert_eq!(limiter.entries.len(), REUSED_SEQ_TRACKED_COLLECTORS);
        for i in 0..extra {
            assert!(!limiter.entries.contains_key(&format!("c{i}")));
        }
        // The newest is still remembered, so its next batch inside the window stays quiet.
        let newest = format!("c{}", REUSED_SEQ_TRACKED_COLLECTORS + extra - 1);
        assert_eq!(limiter.note(&newest, 1, start), None);
    }
}
