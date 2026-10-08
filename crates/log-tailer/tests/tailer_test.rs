use log_tailer::LogTailer;
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

#[test]
fn over_length_line_is_discarded_and_the_tailer_advances_past_it() {
    // A compromised/malfunctioning sensor writes a line far larger than intake's MAX_LINE_BYTES
    // (1 MiB) cap. Intake must discard it (never buffer it whole) and still advance to the next
    // real line, rather than allocating unboundedly or wedging on the giant line forever.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let giant = "x".repeat(1_048_577); // 1 MiB + 1 byte
    std::fs::write(&log_path, format!("good1\n{giant}\ngood2\n")).unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(
        lines,
        vec!["good1", "good2"],
        "the over-length line must be dropped and the tailer must advance to the next real line"
    );
}

// --- Batch commit / rewind -------------------------------------------------------------------
//
// `read_batch` advances the in-memory offset for everything it hands out. Declining to persist
// the cursor only defers a loss for a caller that keeps the same tailer across polls: the next
// read starts past the unprocessed lines, and the next successful persist makes that durable.
// These cover the rewind that closes it.

#[test]
fn rewound_batch_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "first\nsecond\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    assert_eq!(tailer.read_batch(10), vec!["first", "second"]);
    tailer.rewind_batch();
    assert_eq!(
        tailer.read_batch(10),
        vec!["first", "second"],
        "a rewound batch must be offered again, not skipped"
    );
}

#[test]
fn committed_batch_is_not_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "first\nsecond\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    assert_eq!(tailer.read_batch(10), vec!["first", "second"]);
    tailer.commit_batch();
    assert!(
        tailer.read_batch(10).is_empty(),
        "a committed batch must not be replayed"
    );
    // A rewind after a commit has nothing to undo.
    tailer.rewind_batch();
    assert!(tailer.read_batch(10).is_empty());
}

#[test]
fn rewind_spans_every_read_since_the_last_commit() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a\nb\nc\nd\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    assert_eq!(tailer.read_batch(2), vec!["a", "b"]);
    assert_eq!(tailer.read_batch(2), vec!["c", "d"]);
    tailer.rewind_batch();
    assert_eq!(
        tailer.read_batch(10),
        vec!["a", "b", "c", "d"],
        "an uncommitted run of reads must rewind as a whole"
    );
}

#[test]
fn rewind_recovers_a_rotated_out_inode_drained_in_the_same_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "old1\nold2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));

    // Read nothing yet - just open the inode so rotation has a handle to preserve.
    assert_eq!(tailer.read_batch(1), vec!["old1"]);
    tailer.commit_batch();

    // Rotate by rename, leaving the old inode reachable only through the held-open descriptor.
    std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::write(&log_path, "new1\n").unwrap();

    // One batch that spans the drained old inode and the new file, then fails.
    assert_eq!(tailer.read_batch(10), vec!["old2", "new1"]);
    tailer.rewind_batch();
    assert_eq!(
        tailer.read_batch(10),
        vec!["old2", "new1"],
        "the rotated-out inode's descriptor must survive a rewind - nothing else can reach it"
    );
}

/// The same rotation, but with the pre-rotation read still UNCOMMITTED. The displaced inode is
/// queued for draining at the offset the cursor happens to sit at, which is already past the
/// lines this uncommitted batch read from it - so a rewind that is supposed to put every read
/// since the last commit back has to restore the offset the batch STARTED at on that inode, not
/// the one it ended at. Without that, `old1` is read once, never delivered, and never re-read.
#[test]
fn rewind_recovers_reads_made_before_a_rotation_in_the_same_uncommitted_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "old1\nold2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));

    // Read one line and do NOT commit it: the caller has not accepted this batch yet.
    assert_eq!(tailer.read_batch(1), vec!["old1"]);

    // Rotate by rename underneath the still-open batch.
    std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::write(&log_path, "new1\n").unwrap();

    // Keep reading into the same uncommitted batch, then fail it.
    assert_eq!(tailer.read_batch(10), vec!["old2", "new1"]);
    tailer.rewind_batch();

    assert_eq!(
        tailer.read_batch(10),
        vec!["old1", "old2", "new1"],
        "a rewind must put back every read since the last commit, including the ones made on the \
         inode that was rotated away mid-batch"
    );
}

/// A rewind spanning two rotations: each displaced inode must go back to where reading of it
/// began within this batch, which is the start of the file for every inode after the first.
#[test]
fn rewind_recovers_reads_across_two_rotations_in_one_uncommitted_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a1\na2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));

    assert_eq!(tailer.read_batch(1), vec!["a1"]);

    std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::write(&log_path, "b1\nb2\n").unwrap();
    // Drains a2 off the first inode, then reads b1 off the second.
    assert_eq!(tailer.read_batch(2), vec!["a2", "b1"]);

    std::fs::rename(&log_path, dir.path().join("events.jsonl.2")).unwrap();
    std::fs::write(&log_path, "c1\n").unwrap();
    assert_eq!(tailer.read_batch(10), vec!["b2", "c1"]);

    tailer.rewind_batch();
    assert_eq!(
        tailer.read_batch(10),
        vec!["a1", "a2", "b1", "b2", "c1"],
        "every inode read during the uncommitted batch must rewind to where this batch began \
         reading it"
    );
}

fn append(path: &std::path::Path, text: &str) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

#[test]
fn backlog_counts_unread_bytes_and_reaches_zero_when_caught_up() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "aaaa\nbb\ncc\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.backlog_bytes(), 11, "nothing read yet");

    assert_eq!(tailer.read_batch(1), vec!["aaaa"]);
    tailer.commit_batch();
    assert_eq!(tailer.backlog_bytes(), 6);

    assert_eq!(tailer.read_batch(10), vec!["bb", "cc"]);
    tailer.commit_batch();
    assert_eq!(tailer.backlog_bytes(), 0, "caught up");

    append(&log_path, "dd\nee");
    assert_eq!(
        tailer.backlog_bytes(),
        5,
        "growth counts before the next read"
    );
    assert_eq!(tailer.read_batch(10), vec!["dd"]);
    tailer.commit_batch();
    assert_eq!(
        tailer.backlog_bytes(),
        2,
        "an incomplete trailing line is still unread"
    );
}

#[test]
fn backlog_after_a_rewind_counts_the_rewound_lines_again() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a\nb\nc\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(2), vec!["a", "b"]);
    tailer.rewind_batch();
    assert_eq!(tailer.backlog_bytes(), 6);
}

#[test]
fn backlog_includes_a_rotated_out_inode_still_being_drained() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "old1\nold2\nold3\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(1), vec!["old1"]);
    tailer.commit_batch();

    std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::write(&log_path, "new1\n").unwrap();
    assert_eq!(
        tailer.backlog_bytes(),
        10,
        "until the next read notices the rotation, the open descriptor's remainder is the backlog"
    );

    assert_eq!(tailer.read_batch(1), vec!["old2"]);
    tailer.commit_batch();
    assert_eq!(
        tailer.backlog_bytes(),
        5 + 5,
        "old3 left in the rotated-out inode, plus all of the new file"
    );

    assert_eq!(tailer.read_batch(10), vec!["old3", "new1"]);
    tailer.commit_batch();
    assert_eq!(tailer.backlog_bytes(), 0);
}

#[test]
fn backlog_counts_a_truncated_file_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "event1\nevent2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(10).len(), 2);
    tailer.commit_batch();
    assert_eq!(tailer.backlog_bytes(), 0);

    // copytruncate: same inode, shorter than the offset, read again from 0.
    std::fs::write(&log_path, "e3\n").unwrap();
    assert_eq!(tailer.backlog_bytes(), 3);
}

#[test]
fn backlog_before_any_read_follows_the_persisted_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursors");
    std::fs::write(&log_path, "one\ntwo\n").unwrap();
    {
        let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
        assert_eq!(tailer.read_batch(1), vec!["one"]);
        tailer.commit_batch();
        tailer.persist_cursor().unwrap();
    }
    assert_eq!(
        LogTailer::new(log_path.clone(), cursor_dir.clone()).backlog_bytes(),
        4,
        "a restart resumes at the persisted offset"
    );

    // Replaced by rename while no tailer ran: the next read starts the new inode from 0.
    std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::write(&log_path, "three\n").unwrap();
    assert_eq!(LogTailer::new(log_path, cursor_dir).backlog_bytes(), 6);
}

#[test]
fn backlog_of_a_missing_file_or_a_reader_started_at_the_end_is_zero() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    assert_eq!(
        LogTailer::new(log_path.clone(), dir.path().join("cursors")).backlog_bytes(),
        0
    );

    std::fs::write(&log_path, "already there\n").unwrap();
    let tailer = LogTailer::without_cursor(log_path.clone(), log_tailer::StartAt::End);
    assert_eq!(tailer.backlog_bytes(), 0);
    append(&log_path, "later\n");
    assert_eq!(tailer.backlog_bytes(), 6);
}

/// A batch stops BEFORE the line that would pass the byte budget, and that line is not consumed:
/// the next read starts at it.
#[test]
fn a_byte_budget_stops_the_batch_before_the_line_that_would_pass_it() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "aaaa\nbbbb\ncccc\ndddd\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    // 5 bytes a line with its newline: 12 bytes holds two.
    assert_eq!(tailer.read_batch_bounded(100, 12), vec!["aaaa", "bbbb"]);
    assert_eq!(tailer.read_batch_bounded(100, 12), vec!["cccc", "dddd"]);
    assert!(tailer.read_batch_bounded(100, 12).is_empty());
}

/// The first line of a batch goes through whatever the budget, so a budget below one line cannot
/// stall the reader.
#[test]
fn a_budget_smaller_than_one_line_still_returns_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "aaaa\nbbbb\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    assert_eq!(tailer.read_batch_bounded(100, 1), vec!["aaaa"]);
    assert_eq!(tailer.read_batch_bounded(100, 0), vec!["bbbb"]);
}

/// The budget spans a rotated-out inode being drained and the new file: the batch stops inside the
/// drain at the budget, and nothing is lost or repeated across the batches.
#[test]
fn a_byte_budget_applies_across_a_draining_inode_and_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "old1\nold2\nold3\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(1), vec!["old1"]);
    tailer.commit_batch();
    std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::write(&log_path, "new1\nnew2\n").unwrap();

    let mut seen = Vec::new();
    for _ in 0..10 {
        let batch = tailer.read_batch_bounded(100, 10);
        if batch.is_empty() {
            break;
        }
        assert!(batch.len() <= 2, "{batch:?}");
        seen.extend(batch);
        tailer.commit_batch();
    }
    assert_eq!(seen, vec!["old2", "old3", "new1", "new2"]);
}

fn numbered(prefix: &str, n: usize) -> String {
    (0..n)
        .map(|i| format!("{prefix}-{i:03}-padding-padding-padding-padding\n"))
        .collect()
}

fn line_of(prefix: &str, i: usize) -> String {
    format!("{prefix}-{i:03}-padding-padding-padding-padding")
}

/// Accepting a prefix moves the positions over exactly those lines without reading them again;
/// the next read starts at the first line not accepted.
#[test]
fn commit_batch_through_starts_the_next_read_after_the_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, numbered("l", 12)).unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(8).len(), 8);
    assert!(tailer.commit_batch_through(5));
    assert_eq!(tailer.read_batch(100)[0], line_of("l", 5));
    // Nothing to accept past what the batch returned, and nothing uncommitted after a commit.
    tailer.commit_batch();
    assert!(!tailer.commit_batch_through(1));
}

/// A `copytruncate` that lands between the read and the accept (the append is in flight) must
/// not make the accept skip lines: the tailer refuses, and after a rewind the next read starts
/// at the NEW file's first line, not at the line count of the old batch.
/// A file under the 256-byte fingerprint window changes its fingerprint with every append, so an
/// ordinary append between the read and the accept must not read as a replacement: the prefix is
/// accepted and nothing is replayed.
#[test]
fn commit_batch_through_accepts_a_small_file_that_only_grew() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "aaaaaaaaa\nbbbbbbbbb\nccccccccc\nddddddddd\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(4).len(), 4);
    append(&log_path, "eeeeeeeee\nfffffffff\n");
    assert!(
        tailer.commit_batch_through(2),
        "an append is not a rotation"
    );
    assert_eq!(
        tailer.read_batch(10),
        vec!["ccccccccc", "ddddddddd", "eeeeeeeee", "fffffffff"]
    );
}

#[test]
fn commit_batch_through_refuses_after_a_copytruncate_and_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, numbered("old", 13)).unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert_eq!(tailer.read_batch(3).len(), 3);
    tailer.commit_batch();
    assert_eq!(tailer.read_batch(10).len(), 10);

    // copytruncate: the same inode is emptied and refilled.
    std::fs::write(&log_path, "").unwrap();
    append(&log_path, &numbered("new", 20));

    assert!(
        !tailer.commit_batch_through(5),
        "must not accept over a replaced file"
    );
    tailer.rewind_batch();
    assert_eq!(
        tailer.read_batch(3),
        vec![line_of("new", 0), line_of("new", 1), line_of("new", 2)]
    );
}

/// The positions are right across a rotated-out inode that is still being drained: the prefix may
/// end inside the drain or in the new file.
#[test]
fn commit_batch_through_spans_a_draining_inode_and_the_new_file() {
    for (prefix, next) in [(2usize, line_of("old", 3)), (6, line_of("new", 1))] {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        std::fs::write(&log_path, numbered("old", 6)).unwrap();
        let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
        assert_eq!(tailer.read_batch(1).len(), 1);
        tailer.commit_batch();
        std::fs::rename(&log_path, dir.path().join("events.jsonl.1")).unwrap();
        std::fs::write(&log_path, numbered("new", 4)).unwrap();

        // old-001 .. old-005 then new-000 .. new-003.
        assert_eq!(tailer.read_batch(9).len(), 9);
        assert!(tailer.commit_batch_through(prefix), "prefix {prefix}");
        let rest = tailer.read_batch(100);
        assert_eq!(rest[0], next, "prefix {prefix}");
        assert_eq!(rest.len(), 9 - prefix, "prefix {prefix}");
    }
}
