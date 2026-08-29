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
}

impl<S: SpoolWrite> GatewaySink<S> {
    pub fn new(state_dir: PathBuf, spool: S) -> Self {
        Self {
            state_dir,
            spool,
            states: Mutex::new(HashMap::new()),
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
