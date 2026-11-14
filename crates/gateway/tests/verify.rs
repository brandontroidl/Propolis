//! Integration tests for `GatewaySink::accept`, the gateway's per-collector verification state
//! machine: drives it directly (no network, no real spool) so the seq/hash/duplicate/restart/
//! isolation behavior in `verify.rs` and `state.rs` is exercised at the decision level.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use collector_wire::ack::{AckReason, AckStatus};
use collector_wire::frame::Batch;
use collector_wire::hash::ZERO_HASH;
use gateway::{BatchSink, GatewaySink, ReusedSeqCounts, SpoolWrite};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata};

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

/// A batch under `seq` whose content differs from `batch(seq, prev)`: what a collector builds
/// for a reused number after its log or cursor moved.
fn other_batch(seq: u64, prev: [u8; 32], records: usize) -> Batch {
    let records = (0..records)
        .map(|i| format!("{{\"other\":{i}}}").into_bytes())
        .collect();
    Batch::new(seq, prev, records)
}

/// The fixed wording of the reused-seq ERROR line, as operators grep for it and the
/// troubleshooting docs quote it.
const REUSED_SEQ_MESSAGE: &str = "gateway: batch reuses the last accepted seq with different content; \
     acknowledged as Duplicate without storing it";

/// A spool stub that keeps every record it is given, so a test can see exactly which lines
/// the gateway stored.
#[derive(Clone, Default)]
struct RecordingSpool(Arc<Mutex<Vec<Vec<u8>>>>);

impl SpoolWrite for RecordingSpool {
    fn write_records(&self, _collector_id: &str, records: &[Vec<u8>]) -> std::io::Result<()> {
        self.0.lock().unwrap().extend_from_slice(records);
        Ok(())
    }
}

/// `count` distinct records, numbered from 0, as one sensor log's lines in order.
fn log_lines(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| format!("{{\"line\":{i}}}").into_bytes())
        .collect()
}

/// One captured event: its level and every field rendered as text (`message` included).
#[derive(Debug, Clone)]
struct Captured {
    level: Level,
    fields: BTreeMap<String, String>,
}

struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

/// A subscriber that keeps every event, so a test can assert on exactly what the gateway
/// logged (wording, level and fields) without adding a subscriber crate to the gateway.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Captured>>>);

impl Capture {
    fn events(&self) -> Vec<Captured> {
        self.0.lock().unwrap().clone()
    }
}

impl tracing::Subscriber for Capture {
    // `sometimes` keeps a callsite first hit under another test's (or no) dispatcher from
    // caching an interest that would hide it from this one.
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(Captured {
            level: *event.metadata().level(),
            fields: fields.0,
        });
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// The reused-seq lines among `events`.
fn reused_seq_lines(events: &[Captured]) -> Vec<Captured> {
    events
        .iter()
        .filter(|e| e.fields.get("message").map(String::as_str) == Some(REUSED_SEQ_MESSAGE))
        .cloned()
        .collect()
}

/// A clock the test steps by hand, shared with the sink.
fn manual_clock() -> (
    Arc<Mutex<Instant>>,
    impl Fn() -> Instant + Send + Sync + 'static,
) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let reader = Arc::clone(&now);
    (now, move || *reader.lock().unwrap())
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
fn different_content_under_the_last_accepted_seq_is_acked_duplicate_not_stored_and_counted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    let b1 = batch(1, ZERO_HASH);
    assert_eq!(sink.accept("c1", &b1).status, AckStatus::Accepted);

    let capture = Capture::default();
    let ack = tracing::subscriber::with_default(capture.clone(), || {
        sink.accept("c1", &other_batch(1, ZERO_HASH, 3))
    });
    // The wire behaviour is unchanged: the same ack an identical replay gets.
    assert_eq!(ack.status, AckStatus::Duplicate);
    assert_eq!(ack.reason, AckReason::None);
    assert_eq!(ack.next_expected_seq, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the spool must not be written"
    );
    assert_eq!(
        sink.reused_seq_counts(),
        ReusedSeqCounts {
            batches: 1,
            records: 3
        }
    );

    let lines = reused_seq_lines(&capture.events());
    assert_eq!(lines.len(), 1, "{:?}", capture.events());
    let line = &lines[0];
    assert_eq!(line.level, Level::ERROR);
    assert_eq!(line.fields["collector_id"], "c1");
    assert_eq!(line.fields["seq"], "1");
    assert_eq!(line.fields["records"], "3");
    assert_eq!(line.fields["suppressed_batches"], "0");
    assert_eq!(line.fields["suppressed_records"], "0");
}

#[test]
fn a_batch_rebuilt_from_the_same_log_with_more_lines_keeps_its_stored_lines_and_is_reported_without_calling_them_lost()
 {
    let dir = tempfile::tempdir().expect("tempdir");
    let spool = RecordingSpool::default();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool.clone());

    // A quiet log: the first batch under seq 1 is short, three lines. Its ack is lost, five
    // more lines arrive, and the shipper reads the log again from the same offset, so the
    // rebuilt seq-1 batch starts with the same three lines.
    let lines = log_lines(8);
    let stored = Batch::new(1, ZERO_HASH, lines[..3].to_vec());
    assert_eq!(sink.accept("c1", &stored).status, AckStatus::Accepted);
    let rebuilt = Batch::new(1, ZERO_HASH, lines.clone());

    let capture = Capture::default();
    let ack = tracing::subscriber::with_default(capture.clone(), || sink.accept("c1", &rebuilt));
    assert_eq!(ack.status, AckStatus::Duplicate);

    // The first three lines are in the spool from the earlier batch; only the last five never
    // arrived. The line and the counter report the rebuilt batch's size, which is why their
    // wording must not call every one of its records lost.
    assert_eq!(*spool.0.lock().unwrap(), lines[..3].to_vec());
    assert_eq!(
        sink.reused_seq_counts(),
        ReusedSeqCounts {
            batches: 1,
            records: 8
        }
    );
    let events = capture.events();
    let reused = reused_seq_lines(&events);
    assert_eq!(reused.len(), 1, "{events:?}");
    assert_eq!(reused[0].level, Level::ERROR);
    assert_eq!(reused[0].fields["seq"], "1");
    assert_eq!(reused[0].fields["records"], "8");
    for event in &events {
        let message = event
            .fields
            .get("message")
            .map(String::as_str)
            .unwrap_or("");
        assert!(
            !message.contains("NOT stored") && !message.contains("lost"),
            "{message}"
        );
    }
}

#[test]
fn an_identical_replay_of_the_last_accepted_batch_stays_silent_and_uncounted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    let b1 = batch(1, ZERO_HASH);
    sink.accept("c1", &b1);
    sink.accept("c1", &other_batch(1, ZERO_HASH, 3));

    let capture = Capture::default();
    let ack = tracing::subscriber::with_default(capture.clone(), || sink.accept("c1", &b1));
    assert_eq!(ack.status, AckStatus::Duplicate);
    assert_eq!(ack.next_expected_seq, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        sink.reused_seq_counts(),
        ReusedSeqCounts {
            batches: 1,
            records: 3
        },
        "an identical replay is a crash-retry echo, not a reused seq"
    );
    assert!(capture.events().is_empty(), "{:?}", capture.events());
}

#[test]
fn the_reused_seq_line_is_logged_once_a_minute_per_collector_and_reports_what_it_suppressed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, _calls) = counting_spool();
    let (now, clock) = manual_clock();
    let sink = GatewaySink::with_clock(dir.path().to_path_buf(), spool, clock);
    let step = |by: Duration| {
        let mut t = now.lock().unwrap();
        *t += by;
    };

    sink.accept("c1", &batch(1, ZERO_HASH));
    sink.accept("c2", &batch(1, ZERO_HASH));

    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        sink.accept("c1", &other_batch(1, ZERO_HASH, 3));
        step(Duration::from_secs(30));
        sink.accept("c1", &other_batch(1, ZERO_HASH, 5));
        // Another collector has its own budget.
        sink.accept("c2", &other_batch(1, ZERO_HASH, 2));
        step(Duration::from_secs(29));
        sink.accept("c1", &other_batch(1, ZERO_HASH, 7));
        step(Duration::from_secs(1));
        sink.accept("c1", &other_batch(1, ZERO_HASH, 4));
        // The window restarts at the line just logged, not at the first one: a second later is
        // inside it again.
        step(Duration::from_secs(1));
        sink.accept("c1", &other_batch(1, ZERO_HASH, 6));
        // A minute after the previous line: it reports only what was held back since then.
        step(Duration::from_secs(59));
        sink.accept("c1", &other_batch(1, ZERO_HASH, 1));
    });

    assert_eq!(
        sink.reused_seq_counts(),
        ReusedSeqCounts {
            batches: 7,
            records: 28
        },
        "suppressed lines are still counted"
    );
    let lines = reused_seq_lines(&capture.events());
    let summary: Vec<(&str, &str, &str, &str)> = lines
        .iter()
        .map(|l| {
            (
                l.fields["collector_id"].as_str(),
                l.fields["records"].as_str(),
                l.fields["suppressed_batches"].as_str(),
                l.fields["suppressed_records"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("c1", "3", "0", "0"),
            ("c2", "2", "0", "0"),
            // A minute after the first c1 line: the two batches in between (5 + 7 records).
            ("c1", "4", "2", "12"),
            // The batch of 6 a second after that line, not the totals of the window before.
            ("c1", "1", "1", "6"),
        ]
    );
}

#[test]
fn an_older_seq_with_any_content_stays_a_silent_uncounted_duplicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    let b1 = batch(1, ZERO_HASH);
    sink.accept("c1", &b1);
    sink.accept("c1", &batch(2, b1.batch_hash));

    // The gateway keeps only the last accepted batch's hash, so it cannot tell a different
    // seq-1 batch from the one it stored; it does not pretend to.
    let capture = Capture::default();
    let ack = tracing::subscriber::with_default(capture.clone(), || {
        sink.accept("c1", &other_batch(1, ZERO_HASH, 3))
    });
    assert_eq!(ack.status, AckStatus::Duplicate);
    assert_eq!(ack.next_expected_seq, 3);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(sink.reused_seq_counts(), ReusedSeqCounts::default());
    assert!(capture.events().is_empty(), "{:?}", capture.events());
}

#[test]
fn seq_zero_from_a_collector_with_nothing_accepted_is_not_a_reused_seq() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool, calls) = counting_spool();
    let sink = GatewaySink::new(dir.path().to_path_buf(), spool);

    // A fresh collector's last_seq is 0 with no batch behind it, so there is no stored batch
    // to differ from.
    let capture = Capture::default();
    let ack = tracing::subscriber::with_default(capture.clone(), || {
        sink.accept("c1", &other_batch(0, ZERO_HASH, 3))
    });
    assert_eq!(ack.status, AckStatus::Duplicate);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.reused_seq_counts(), ReusedSeqCounts::default());
    assert!(capture.events().is_empty(), "{:?}", capture.events());
}

#[test]
fn a_reused_seq_is_still_recognised_after_a_gateway_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (spool1, _calls1) = counting_spool();
    let sink1 = GatewaySink::new(dir.path().to_path_buf(), spool1);
    sink1.accept("c1", &batch(1, ZERO_HASH));
    drop(sink1);

    // The stored hash comes back from the state file, so the check does not depend on the
    // gateway having stayed up since the batch was accepted.
    let (spool2, calls2) = counting_spool();
    let sink2 = GatewaySink::new(dir.path().to_path_buf(), spool2);
    let ack = sink2.accept("c1", &other_batch(1, ZERO_HASH, 2));
    assert_eq!(ack.status, AckStatus::Duplicate);
    assert_eq!(calls2.load(Ordering::SeqCst), 0);
    assert_eq!(
        sink2.reused_seq_counts(),
        ReusedSeqCounts {
            batches: 1,
            records: 2
        }
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
