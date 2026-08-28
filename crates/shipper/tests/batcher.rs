use collector_wire::frame::{Batch, MAX_FRAME_LEN, MAX_RECORD_LEN, decode_frame, encode_frame};
use collector_wire::hash::ZERO_HASH;
use log_tailer::LogTailer;
use shipper::batcher::{Batcher, MAX_RECORDS_FRAME_SAFE};

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
fn default_max_records_is_the_frame_safe_ceiling() {
    // See the module doc on `shipper::batcher::DEFAULT_MAX_RECORDS` for the exact accounting;
    // this just pins the chosen constant so a future change is deliberate, not accidental.
    assert_eq!(shipper::batcher::DEFAULT_MAX_RECORDS, 15);
    assert_eq!(MAX_RECORDS_FRAME_SAFE, 15);
}

/// Proves the guarantee `MAX_RECORDS_FRAME_SAFE` claims, at the wire encoding, not just in
/// arithmetic: a batch of `MAX_RECORDS_FRAME_SAFE` records each at the true `MAX_RECORD_LEN`
/// ceiling (the worst case a compromised or malfunctioning collector could actually produce,
/// since `log-tailer` bounds every tailed line to exactly `MAX_RECORD_LEN`) must still encode to
/// no more than `MAX_FRAME_LEN` bytes, and must round-trip cleanly through `decode_frame`.
#[test]
fn a_worst_case_max_size_batch_still_encodes_within_the_frame_bound() {
    let records: Vec<Vec<u8>> = (0..MAX_RECORDS_FRAME_SAFE)
        .map(|_| vec![b'a'; MAX_RECORD_LEN as usize])
        .collect();
    let batch = Batch::new(1, ZERO_HASH, records);

    let bytes = encode_frame(&batch);
    assert!(
        bytes.len() <= MAX_FRAME_LEN,
        "encoded frame of {} bytes exceeds MAX_FRAME_LEN ({})",
        bytes.len(),
        MAX_FRAME_LEN
    );

    let decoded = decode_frame(&bytes).expect("a within-bound frame must decode cleanly");
    assert_eq!(decoded, batch);
}

/// F2 regression proof: `log_tailer` decodes a raw tailed line with `String::from_utf8_lossy`,
/// which can expand invalid UTF-8 up to 3x (each bad byte becomes a 3-byte U+FFFD). A raw line at
/// or under log-tailer's own MAX_LINE_BYTES cap (== MAX_RECORD_LEN) can therefore come back from
/// `read_batch` as a record OVER MAX_RECORD_LEN. `next_batch` must not let such a record into the
/// batch it builds (an oversized record makes an unshippable frame the gateway rejects, and
/// because a rejected cycle never advances the cursor, the shipper would otherwise re-read - and
/// re-skip-or-reject - the same pathological line forever, wedging the whole collector's serial
/// chain). This exercises the `tracing::warn!` drop path in `Batcher::next_batch` (not asserted
/// on directly, since there is no log-capture harness in this crate's dev-dependencies) and
/// proves its effect: the oversized record is silently dropped while the following normal record
/// still ships.
#[test]
fn an_over_length_lossy_expanded_record_is_dropped_and_does_not_block_the_next_record() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    // 400_000 raw bytes of 0xFF: each byte is individually invalid UTF-8, so
    // `String::from_utf8_lossy` replaces each with a 3-byte U+FFFD, expanding this single line to
    // 1_200_000 bytes - over MAX_RECORD_LEN (1_048_576) - while the RAW line (400_000 bytes) stays
    // safely under log-tailer's own MAX_LINE_BYTES cap so it is not itself truncated or discarded
    // before ever reaching the batcher.
    let mut content = vec![0xFFu8; 400_000];
    content.push(b'\n');
    content.extend_from_slice(b"{\"a\":1}\n");
    std::fs::write(&log_path, &content).unwrap();

    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let batch = Batcher::next_batch(&mut tailer, 0, ZERO_HASH, 100)
        .expect("the normal second line still yields a batch");

    assert_eq!(
        batch.records.len(),
        1,
        "the over-length lossy-expanded record must be dropped, not shipped"
    );
    assert_eq!(batch.records[0], b"{\"a\":1}".to_vec());

    // Both raw lines were consumed from the tailer (the oversized one dropped, not left
    // unconsumed to be re-read forever) - a third call finds nothing left.
    assert!(Batcher::next_batch(&mut tailer, batch.seq, batch.batch_hash, 100).is_none());
}

/// When EVERY line a read produces is over-length, `next_batch` must return `None` (not build a
/// zero-record batch, which `Batch::new` cannot represent) rather than stalling: the cursor still
/// advances past the dropped line so a later poll is not stuck re-reading it.
#[test]
fn a_read_where_every_line_is_over_length_yields_none_not_a_stall() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    let mut content = vec![0xFFu8; 400_000];
    content.push(b'\n');
    std::fs::write(&log_path, &content).unwrap();

    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert!(
        Batcher::next_batch(&mut tailer, 0, ZERO_HASH, 100).is_none(),
        "a read producing only over-length records must yield None, not panic or an empty batch"
    );

    // The dropped line's bytes were still consumed (read_batch advanced the in-memory cursor),
    // so appending a normal line and reading again must return only the new line, proving the
    // tailer did not stall re-reading the same oversized line.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    use std::io::Write;
    f.write_all(b"{\"b\":2}\n").unwrap();
    drop(f);

    let batch = Batcher::next_batch(&mut tailer, 0, ZERO_HASH, 100)
        .expect("the newly appended normal line yields a batch");
    assert_eq!(batch.records, vec![b"{\"b\":2}".to_vec()]);
}

/// Even when the caller asks for more than the frame-safe ceiling (e.g. the shipper config's
/// own default of 16, or any other larger value), `next_batch` must never hand back more than
/// `MAX_RECORDS_FRAME_SAFE` records - and must clamp at the tailer READ, not merely truncate the
/// result, so the untaken lines stay unread rather than being silently lost from the cursor.
#[test]
fn next_batch_never_exceeds_the_frame_safe_ceiling_even_when_asked_for_more() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let line_count = MAX_RECORDS_FRAME_SAFE + 5;
    let content: String = (0..line_count).map(|i| format!("{i}\n")).collect();
    std::fs::write(&log_path, content).unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    let requested = MAX_RECORDS_FRAME_SAFE + 50; // deliberately far over the ceiling
    let batch =
        Batcher::next_batch(&mut tailer, 0, ZERO_HASH, requested).expect("lines are available");
    assert_eq!(batch.records.len(), MAX_RECORDS_FRAME_SAFE);
    for (i, record) in batch.records.iter().enumerate() {
        assert_eq!(record, &i.to_string().into_bytes());
    }

    // The 5 lines beyond the ceiling were never read (clamped at the tailer read, not dropped
    // after), so they are still there for the next batch.
    let batch2 = Batcher::next_batch(&mut tailer, batch.seq, batch.batch_hash, requested)
        .expect("the remaining 5 lines are available");
    assert_eq!(batch2.records.len(), 5);
    for (i, record) in batch2.records.iter().enumerate() {
        assert_eq!(
            record,
            &(MAX_RECORDS_FRAME_SAFE + i).to_string().into_bytes()
        );
    }
}
