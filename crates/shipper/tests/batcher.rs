use collector_wire::hash::ZERO_HASH;
use log_tailer::LogTailer;
use shipper::batcher::Batcher;

#[test]
fn builds_the_first_batch_from_whole_tailed_lines_then_drains_to_none() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));

    let batch1 = Batcher::next_batch(&mut tailer, 0, ZERO_HASH, 100)
        .expect("three whole lines are available");
    assert_eq!(batch1.seq, 1);
    assert_eq!(batch1.prev_batch_hash, ZERO_HASH);
    assert_eq!(batch1.records.len(), 3);
    assert_eq!(batch1.records[0], b"{\"a\":1}".to_vec());
    assert_eq!(batch1.records[1], b"{\"b\":2}".to_vec());
    assert_eq!(batch1.records[2], b"{\"c\":3}".to_vec());

    // The tailer is drained: a second call must return None, not an empty-records batch
    // (`Batch::new` panics on empty records, so `None` is the only sane empty signal).
    assert!(Batcher::next_batch(&mut tailer, batch1.seq, batch1.batch_hash, 100).is_none());

    // A new line arrives; the next batch chains onto batch1's hash and increments seq.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    use std::io::Write;
    f.write_all(b"{\"d\":4}\n").unwrap();
    drop(f);

    let batch2 = Batcher::next_batch(&mut tailer, batch1.seq, batch1.batch_hash, 100)
        .expect("one more whole line is available");
    assert_eq!(batch2.seq, 2);
    assert_eq!(batch2.prev_batch_hash, batch1.batch_hash);
    assert_eq!(batch2.records, vec![b"{\"d\":4}".to_vec()]);
}

#[test]
fn caps_the_batch_at_max_records() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "1\n2\n3\n4\n5\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    let batch = Batcher::next_batch(&mut tailer, 0, ZERO_HASH, 2).unwrap();
    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records, vec![b"1".to_vec(), b"2".to_vec()]);

    let batch2 = Batcher::next_batch(&mut tailer, batch.seq, batch.batch_hash, 2).unwrap();
    assert_eq!(batch2.records, vec![b"3".to_vec(), b"4".to_vec()]);
}

#[test]
fn an_empty_log_yields_no_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    assert!(Batcher::next_batch(&mut tailer, 0, ZERO_HASH, 100).is_none());
}

#[test]
fn default_max_records_keeps_a_worst_case_batch_within_the_frame_bound() {
    // See the module doc on `shipper::batcher::DEFAULT_MAX_RECORDS` for the exact accounting;
    // this just pins the chosen constant so a future change is deliberate, not accidental.
    assert_eq!(shipper::batcher::DEFAULT_MAX_RECORDS, 16);
}
