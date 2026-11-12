//! Integration tests for `GatewaySink::accept`, the gateway's per-collector verification state
//! machine: drives it directly (no network, no real spool) so the seq/hash/duplicate/restart/
//! isolation behavior in `verify.rs` and `state.rs` is exercised at the decision level.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use collector_wire::ack::{AckReason, AckStatus};
use collector_wire::frame::Batch;
use collector_wire::hash::ZERO_HASH;
use gateway::{BatchSink, GatewaySink, SpoolWrite};

/// A spool stub that never fails and counts how many times it was called, via a shared
/// counter so a test can keep its own handle after the stub is moved into a `GatewaySink`.
struct CountingSpool {
    calls: Arc<AtomicUsize>,
}

impl SpoolWrite for CountingSpool {
    fn write_records(&self, _collector_id: &str, _records: &[Vec<u8>]) -> std::io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn counting_spool() -> (CountingSpool, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        CountingSpool {
            calls: Arc::clone(&calls),
        },
        calls,
    )
}

fn batch(seq: u64, prev: [u8; 32]) -> Batch {
    Batch::new(seq, prev, vec![b"{\"x\":1}".to_vec()])
}

#[test]
fn in_order_batches_are_accepted_and_chain_forward() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, _calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    let b1 = batch(1, ZERO_HASH);
    let ack1 = sink.accept("c1", &b1);
    assert_eq!(ack1.status, AckStatus::Accepted);
    assert_eq!(ack1.next_expected_seq, 2);

    let b2 = batch(2, b1.batch_hash);
    let ack2 = sink.accept("c1", &b2);
    assert_eq!(ack2.status, AckStatus::Accepted);
    assert_eq!(ack2.next_expected_seq, 3);
}

#[test]
fn a_sequence_gap_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, _calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    sink.accept("c1", &batch(1, ZERO_HASH));

    // The seq check runs before the hash check, so the prev hash here is irrelevant.
    let ack = sink.accept("c1", &batch(3, ZERO_HASH));
    assert_eq!(ack.status, AckStatus::Reject);
    assert_eq!(ack.reason, AckReason::SeqGap);
    assert_eq!(ack.next_expected_seq, 2);
}

#[test]
fn a_rolling_hash_mismatch_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, _calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    sink.accept("c1", &batch(1, ZERO_HASH));

    let wrong_prev = [0xAAu8; 32];
    let ack = sink.accept("c1", &batch(2, wrong_prev));
    assert_eq!(ack.status, AckStatus::Reject);
    assert_eq!(ack.reason, AckReason::HashMismatch);
    assert_eq!(ack.next_expected_seq, 2);
}

#[test]
fn an_already_accepted_seq_is_an_idempotent_duplicate_and_skips_the_spool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    let b1 = batch(1, ZERO_HASH);
    sink.accept("c1", &b1);
    let b2 = batch(2, b1.batch_hash);
    sink.accept("c1", &b2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let replay_ack = sink.accept("c1", &b2);
    assert_eq!(replay_ack.status, AckStatus::Duplicate);
    assert_eq!(replay_ack.next_expected_seq, 3);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a duplicate replay must not write the spool again"
    );
}

#[test]
fn state_survives_restart_via_the_same_state_dir() {
    let dir = tempfile::tempdir().expect("tempdir");

    let (spool1, _calls1) = counting_spool();
    let sink1 = GatewaySink::new(dir.path().to_path_buf(), spool1);
    let b1 = batch(1, ZERO_HASH);
    sink1.accept("c1", &b1);
    let b2 = batch(2, b1.batch_hash);
    sink1.accept("c1", &b2);
    drop(sink1);

    // A fresh sink on the same state_dir must resume from disk, not start over.
    let (spool2, _calls2) = counting_spool();
    let sink2 = GatewaySink::new(dir.path().to_path_buf(), spool2);
    let b3 = batch(3, b2.batch_hash);
    let ack = sink2.accept("c1", &b3);
    assert_eq!(ack.status, AckStatus::Accepted);
    assert_eq!(ack.next_expected_seq, 4);
}

#[test]
fn collectors_are_isolated_from_each_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, _calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    let b1 = batch(1, ZERO_HASH);
    sink.accept("c1", &b1);
    sink.accept("c1", &batch(2, b1.batch_hash));

    // c2 has never been seen, so its first batch starts fresh at seq=1 even though c1 is
    // already at seq=2.
    let ack = sink.accept("c2", &batch(1, ZERO_HASH));
    assert_eq!(ack.status, AckStatus::Accepted);
    assert_eq!(ack.next_expected_seq, 2);
}

#[test]
fn an_unsafe_collector_id_is_rejected_fail_closed_and_never_persists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, _calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    for bad_id in ["../evil", "a/b", "..", "c1\u{0000}bad", ""] {
        let ack = sink.accept(bad_id, &batch(1, ZERO_HASH));
        // Never persists, so it can never reach Accepted; the failure path retries.
        assert_eq!(ack.status, AckStatus::Retry, "id: {bad_id:?}");
        assert_eq!(ack.reason, AckReason::SpoolWriteFailed, "id: {bad_id:?}");
    }

    // Nothing escaped into (or was written inside) the state dir.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read state dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "an unsafe collector id must not create any state file"
    );
}
