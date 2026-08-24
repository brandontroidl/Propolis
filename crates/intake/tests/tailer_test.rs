use intake::tailer::LogTailer;
use std::io::Write;

#[test]
fn reads_complete_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "line1\nline2\nline3\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["line1", "line2", "line3"]);
}

#[test]
fn incomplete_trailing_line_not_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "complete\nincomplete").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["complete"]);
    // Append the newline.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    f.write_all(b"\n").unwrap();
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["incomplete"]);
}

#[test]
fn respects_max_batch_size() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a\nb\nc\nd\ne\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(2);
    assert_eq!(lines.len(), 2);
    let lines = tailer.read_batch(10);
    assert_eq!(lines.len(), 3); // remaining
}

#[test]
fn survives_copytruncate_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    // Write initial events.
    std::fs::write(&log_path, "event1\nevent2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["event1", "event2"]);
    tailer.persist_cursor().unwrap();
    // Simulate copytruncate: truncate the file to 0.
    std::fs::write(&log_path, "").unwrap();
    // Write new events.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    f.write_all(b"event3\nevent4\n").unwrap();
    drop(f);
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["event3", "event4"]);
}

#[test]
fn persist_and_resume_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "first\nsecond\nthird\n").unwrap();
    let cursor_dir = dir.path().join("cursors");
    // First run: read first two lines.
    {
        let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
        let lines = tailer.read_batch(2);
        assert_eq!(lines, vec!["first", "second"]);
        tailer.persist_cursor().unwrap();
    }
    // Second run: resume from cursor.
    {
        let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
        let lines = tailer.read_batch(10);
        assert_eq!(lines, vec!["third"]);
    }
}

#[test]
fn missing_log_file_returns_empty_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nonexistent.jsonl");
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert!(lines.is_empty());
}

// --- Tests added during self-review, beyond the brief's given 6 ---

/// `compute_fingerprint` (Task 2) hashes `min(256, current_size)` bytes: for any file that has
/// never reached 256 bytes, a plain append changes that window and therefore the hash, even
/// though nothing was replaced. Verified independently of the incomplete-line mechanic (unlike
/// `incomplete_trailing_line_not_consumed`, every line here is complete) that ordinary growth of
/// a small file does not cause already-read lines to be re-emitted.
#[test]
fn growing_small_file_does_not_falsely_reset_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["a"]);

    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    f.write_all(b"b\n").unwrap();
    drop(f);

    let lines = tailer.read_batch(10);
    assert_eq!(
        lines,
        vec!["b"],
        "must not re-emit \"a\"; growth alone is not a real replacement"
    );
}

/// A genuine same-size in-place content swap (not merely growth) must still reset to offset 0,
/// matching the design doc's stated `Replaced` handling. Distinguishes the false-positive
/// suppression above from actually ignoring real replacement.
#[test]
fn genuine_same_size_replacement_resets_to_zero() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "aaaa\nbbbb\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(1);
    assert_eq!(lines, vec!["aaaa"]);

    // Same inode, same total size, different content: a true in-place replacement.
    std::fs::write(&log_path, "cccc\ndddd\n").unwrap();

    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["cccc", "dddd"]);
}

/// Rotation by rename (not the deployed copytruncate strategy, but a documented failure mode):
/// if the tailer still holds an open handle to the old inode from a prior read, unread bytes are
/// drained from it before the new file (at the same path, offset 0) is read.
#[test]
fn inode_change_drains_old_file_when_handle_still_open() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "old1\nold2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(1);
    assert_eq!(lines, vec!["old1"]); // "old2" left unread, held by the tailer's open handle

    // Rotate by rename: move the old file aside, create a fresh one at the same path.
    let rotated_path = dir.path().join("events.jsonl.1");
    std::fs::rename(&log_path, &rotated_path).unwrap();
    std::fs::write(&log_path, "new1\nnew2\n").unwrap();

    let lines = tailer.read_batch(10);
    assert_eq!(
        lines,
        vec!["old2", "new1", "new2"],
        "must drain the old inode's remaining unread line before reading the new file"
    );
}

/// Same rotation-by-rename scenario, but the tailer never had a live handle to the old inode
/// (e.g. process just started against a cursor persisted before the rotation happened). The old
/// content is not accessible through the stored path anymore, so the tailer falls back to
/// reading the new file from offset 0 - a documented, bounded loss, not a panic or hang.
/// Regression (audit finding): rotation by rename where the old inode's unread backlog is LARGER
/// than one batch. The old code drained at most `max_lines` from the old inode and then switched to
/// the new inode, permanently losing the remainder. The full backlog must be drained across
/// batches, oldest-first, before the new file, with nothing lost.
#[test]
fn inode_change_drains_a_backlog_larger_than_one_batch_without_loss() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "old1\nold2\nold3\nold4\nold5\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(1), vec!["old1"]); // old2..old5 unread, held by the open handle

    // Rotate by rename; the new file has two lines.
    let rotated = dir.path().join("events.jsonl.1");
    std::fs::rename(&log_path, &rotated).unwrap();
    std::fs::write(&log_path, "new1\nnew2\n").unwrap();

    // Drain in 2-line batches (smaller than the 4-line old backlog). Nothing may be lost.
    let mut collected = Vec::new();
    for _ in 0..10 {
        let batch = tailer.read_batch(2);
        if batch.is_empty() {
            break;
        }
        collected.extend(batch);
    }
    assert_eq!(
        collected,
        vec!["old2", "old3", "old4", "old5", "new1", "new2"],
        "the old inode's full backlog (> one batch) must be drained before the new file, nothing lost"
    );
}

#[test]
fn inode_change_without_live_handle_starts_new_file_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursors");
    std::fs::write(&log_path, "old1\nold2\n").unwrap();
    {
        let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
        let lines = tailer.read_batch(10);
        assert_eq!(lines, vec!["old1", "old2"]);
        tailer.persist_cursor().unwrap();
    }
    // Rotate by rename while no tailer instance is alive to hold an open handle.
    let rotated_path = dir.path().join("events.jsonl.1");
    std::fs::rename(&log_path, &rotated_path).unwrap();
    std::fs::write(&log_path, "new1\n").unwrap();

    let mut tailer = LogTailer::new(log_path, cursor_dir);
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["new1"]);
}

#[test]
fn zero_max_lines_returns_empty_without_advancing() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a\nb\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(0);
    assert!(lines.is_empty());
    // Offset must not have moved: a follow-up real read still sees everything.
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["a", "b"]);
}

#[test]
fn advance_moves_offset_independently_of_read_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "aa\nbb\ncc\n").unwrap();
    let cursor_dir = dir.path().join("cursors");
    let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
    let lines = tailer.read_batch(1);
    assert_eq!(lines, vec!["aa"]);
    // Manually skip past "bb\n" (3 bytes) without going through read_batch.
    tailer.advance(3);
    tailer.persist_cursor().unwrap();

    let mut tailer2 = LogTailer::new(log_path, cursor_dir);
    let lines = tailer2.read_batch(10);
    assert_eq!(lines, vec!["cc"]);
}
