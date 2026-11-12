//! `copytruncate` rotation while the reader is behind: what the tailer had not read lives only in
//! `<log>.1` once the log is truncated, and must be read from there, once, before the new file.
//! See `deploy/logrotate-sensors.conf`.

use std::io::Write;
use std::path::{Path, PathBuf};

use log_tailer::{DurableCursor, LogTailer, RotationLoss, compute_fingerprint};

fn line(prefix: &str, i: usize) -> String {
    format!("{prefix}-{i:03}-padding-padding-padding-padding")
}

fn lines(prefix: &str, range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|i| line(prefix, i)).collect()
}

fn text(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

fn append(path: &Path, text: &str) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

fn rotated_copy(log: &Path) -> PathBuf {
    let mut p = log.as_os_str().to_owned();
    p.push(".1");
    PathBuf::from(p)
}

/// What logrotate's `copytruncate` does to the log: copy it to `<log>.1`, then empty the same
/// inode in place. The sensor's open descriptor keeps appending to it.
fn copytruncate(log: &Path) {
    std::fs::copy(log, rotated_copy(log)).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(log)
        .unwrap();
}

/// Reads to the end in commit-sized batches, as the intake loop does.
fn drain(tailer: &mut LogTailer, batch: usize, budget: u64) -> Vec<String> {
    let mut seen = Vec::new();
    for _ in 0..1000 {
        let got = tailer.read_batch_bounded(batch, budget);
        if got.is_empty() {
            break;
        }
        seen.extend(got);
        tailer.commit_batch();
    }
    seen
}

fn behind_tailer(dir: &Path, log: &Path, total: usize, read: usize) -> LogTailer {
    std::fs::write(log, text(&lines("old", 0..total))).unwrap();
    let mut tailer = LogTailer::new(log.to_path_buf(), dir.join("cursors"));
    assert_eq!(tailer.read_batch(read).len(), read);
    tailer.commit_batch();
    tailer
}

/// The soak's failing case, in miniature: behind at the moment of rotation. Every unread line of
/// the old content is read from `.1`, in order, then the new file, with no line lost or repeated -
/// across batch boundaries and a byte budget that stops mid-drain.
#[test]
fn truncation_while_behind_drains_the_rest_of_the_rotated_copy_then_continues() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 40, 10);
    // Written after the last poll and before the copy: in the copy, not yet seen.
    append(&log, &text(&lines("old", 40..43)));
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..7)));

    // 50 lines of ~45 bytes: batches of 8 lines or 150 bytes, whichever stops first.
    let seen = drain(&mut tailer, 8, 150);

    let mut expected = lines("old", 10..43);
    expected.extend(lines("new", 0..7));
    assert_eq!(seen, expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
    assert_eq!(tailer.backlog_bytes(), 0);
}

/// The new file already holds more than the read offset when the tailer next looks, so this is
/// seen as a changed fingerprint rather than a shorter file; it is the same rotation.
#[test]
fn a_truncation_refilled_past_the_offset_is_recovered_the_same_way() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 20, 5);
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..40)));

    let seen = drain(&mut tailer, 7, u64::MAX);

    let mut expected = lines("old", 5..20);
    expected.extend(lines("new", 0..40));
    assert_eq!(seen, expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// A `.1` left by an EARLIER rotation is another generation's content: reading it would ingest
/// lines the ledger already has. It is not read, and the unread lines it cannot replace are
/// reported as lost, sized by what the last poll saw.
#[test]
fn a_rotated_copy_of_another_generation_is_not_read_and_the_loss_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 30, 10);
    let unread: u64 = lines("old", 10..30)
        .iter()
        .map(|l| l.len() as u64 + 1)
        .sum();
    std::fs::write(
        rotated_copy(&log),
        text(&lines("ancient", 0..60)), // longer than the offset, different head
    )
    .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..3)));

    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("new", 0..3));
    assert_eq!(
        tailer.rotation_loss(),
        RotationLoss {
            events: 1,
            bytes_estimated: unread
        }
    );
}

/// The same content, but shorter than the offset: it cannot be the whole old file.
#[test]
fn a_rotated_copy_that_ends_before_the_offset_is_not_read_and_the_loss_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 30, 20);
    std::fs::write(rotated_copy(&log), text(&lines("old", 0..10))).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..2)));

    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("new", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1);
}

/// `compress` without `delaycompress`, or a second rotation that already compressed `.1`: only
/// `.1.gz` exists. It is not decompressed or read; the loss is reported.
#[test]
fn a_compressed_rotated_copy_is_not_read_and_the_loss_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 30, 10);
    let unread: u64 = lines("old", 10..30)
        .iter()
        .map(|l| l.len() as u64 + 1)
        .sum();
    let mut gz = rotated_copy(&log).into_os_string();
    gz.push(".gz");
    std::fs::write(&gz, b"\x1f\x8bnot read").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..3)));

    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("new", 0..3));
    assert_eq!(
        tailer.rotation_loss(),
        RotationLoss {
            events: 1,
            bytes_estimated: unread
        }
    );
}

/// Caught up when the log was truncated and no `.1` exists: nothing the tailer knows of was
/// lost, so nothing is reported (the copy-to-truncate gap is the policy's accepted loss).
#[test]
fn a_truncation_when_caught_up_with_no_rotated_copy_reports_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 10, 10);
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..3)));

    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("new", 0..3));
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// Caught up, with a `.1` that matches: the lines written between the last poll and the copy are
/// in `.1` and are read, which the old behaviour lost too.
#[test]
fn a_truncation_when_caught_up_still_reads_what_landed_before_the_copy() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 10, 10);
    append(&log, &text(&lines("old", 10..12)));
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..2)));

    let mut expected = lines("old", 10..12);
    expected.extend(lines("new", 0..2));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), expected);
}

/// A rewound batch that read the rotated copy is read again, from the same place.
#[test]
fn a_rewound_batch_re_reads_the_rotated_copy() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 20, 5);
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..3)));

    let first = tailer.read_batch(6);
    assert_eq!(first, lines("old", 5..11));
    tailer.rewind_batch();
    assert_eq!(tailer.read_batch(6), first);
    tailer.commit_batch();
    let mut expected = lines("old", 11..20);
    expected.extend(lines("new", 0..3));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), expected);
}

/// The truncation lands while an earlier read of the same batch is still uncommitted: rewinding
/// puts the copy back to where that first read began, not to where the second one found it.
#[test]
fn a_rewind_across_a_truncation_in_one_batch_re_reads_from_the_batch_start() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 20, 5);

    assert_eq!(tailer.read_batch(3), lines("old", 5..8));
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..3)));
    assert_eq!(tailer.read_batch(5), lines("old", 8..13));
    tailer.rewind_batch();

    let mut expected = lines("old", 5..20);
    expected.extend(lines("new", 0..3));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), expected);
}

/// While the copy is being drained the saved cursor points into the OLD content, under its
/// fingerprint: a restart resumes the drain instead of losing the rest, and the rotation guard
/// can tell the copy is unread. Once the drain ends the saved cursor is the new file's.
#[test]
fn the_saved_cursor_stays_in_the_old_content_until_the_copy_is_drained() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    let mut tailer = behind_tailer(dir.path(), &log, 40, 10);
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..4)));
    let old_fingerprint = compute_fingerprint(&rotated_copy(&log));

    let mut seen = tailer.read_batch(8);
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    let saved = DurableCursor::new(log.clone(), cursors.clone())
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(saved.fingerprint, old_fingerprint);
    let consumed: u64 = lines("old", 0..18).iter().map(|l| l.len() as u64 + 1).sum();
    assert_eq!(saved.offset, consumed);
    drop(tailer);

    // The process restarts mid-drain.
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    seen.extend(drain(&mut tailer, 8, u64::MAX));
    let mut expected = lines("old", 10..40);
    expected.extend(lines("new", 0..4));
    assert_eq!(
        seen, expected,
        "nothing lost or repeated across the restart"
    );
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());

    tailer.persist_cursor().unwrap();
    let done = DurableCursor::new(log.clone(), cursors)
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(done.fingerprint, compute_fingerprint(&log));
    assert_eq!(done.offset, std::fs::metadata(&log).unwrap().len());
}

/// The real guard (`deploy/logrotate-guard.sh`) reading what the real tailer saves, at each point
/// of a rotation: rotation is skipped while the saved position is short of the end of `.1`, with
/// the truncation not yet noticed or noticed and the copy half drained, and allowed once the copy
/// is drained. Neither side is stubbed: the file format and the fingerprint rule are the contract.
#[test]
fn the_rotation_guard_reads_the_cursor_the_tailer_saves() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    let guard = |max_unread: &str| {
        std::process::Command::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/logrotate-guard.sh"
        ))
        .arg(&log)
        .env("PROPOLIS_LOGROTATE_RESERVE_BYTES", "0")
        .env("PROPOLIS_LOGROTATE_MAX_UNREAD_BYTES", max_unread)
        .env("PROPOLIS_CURSOR_DIR", &cursors)
        .env("PROPOLIS_SHIPPER_CURSOR_DIR", dir.path().join("none"))
        .output()
        .unwrap()
    };
    let stderr = |o: &std::process::Output| String::from_utf8_lossy(&o.stderr).into_owned();

    let mut tailer = behind_tailer(dir.path(), &log, 40, 10);
    tailer.persist_cursor().unwrap();
    // Live log, 30 lines unread (about 1.4 KB): over a 100 byte bound, under a 1 MiB one.
    let behind = guard("100");
    assert_eq!(behind.status.code(), Some(1), "{}", stderr(&behind));
    let fine = guard("1048576");
    assert!(fine.status.success(), "{}", stderr(&fine));
    assert!(!stderr(&fine).contains("no usable"), "{}", stderr(&fine));

    // Rotated, the tailer not yet aware: its saved cursor is inside what is now `.1`.
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..4)));
    let unnoticed = guard("1048576");
    assert_eq!(unnoticed.status.code(), Some(1), "{}", stderr(&unnoticed));
    assert!(
        stderr(&unnoticed).contains("not fully read"),
        "{}",
        stderr(&unnoticed)
    );

    // Noticed, half drained.
    assert_eq!(tailer.read_batch(8).len(), 8);
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    let half = guard("1048576");
    assert_eq!(half.status.code(), Some(1), "{}", stderr(&half));
    assert!(
        stderr(&half).contains("not fully read"),
        "{}",
        stderr(&half)
    );

    // Drained: the saved cursor is the new file's, and the guard lets the next rotation run.
    drain(&mut tailer, 8, u64::MAX);
    tailer.persist_cursor().unwrap();
    let done = guard("1048576");
    assert!(done.status.success(), "{}", stderr(&done));
    assert!(!stderr(&done).contains("no usable"), "{}", stderr(&done));
}

/// A copytruncate lands while a batch is in flight and the append fails partway: the runner accepts
/// the committed prefix and rewinds nothing. The next read continues `.1` AFTER that prefix, so
/// the committed lines are not appended a second time.
#[test]
fn a_prefix_committed_across_a_copytruncate_is_not_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 13, 3);
    let batch = tailer.read_batch_bounded(100, u64::MAX);
    assert_eq!(batch, lines("old", 3..13));
    copytruncate(&log);
    append(&log, &text(&lines("new", 0..4)));

    assert!(
        tailer.commit_batch_through(5),
        "the copy is verifiable, so the prefix can be placed"
    );
    let mut expected = lines("old", 8..13);
    expected.extend(lines("new", 0..4));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// Same, with the prefix ending exactly at, and past, the old/new boundary.
#[test]
fn a_prefix_across_the_copy_and_new_file_boundary_is_placed_exactly() {
    for reached in [7usize, 8, 9] {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let mut tailer = behind_tailer(dir.path(), &log, 10, 3);
        copytruncate(&log);
        append(&log, &text(&lines("new", 0..4)));
        let batch = tailer.read_batch_bounded(100, u64::MAX);
        assert_eq!(batch.len(), 11);
        assert!(tailer.commit_batch_through(reached), "reached {reached}");
        let mut all = lines("old", 3..10);
        all.extend(lines("new", 0..4));
        assert_eq!(
            drain(&mut tailer, 100, u64::MAX),
            all[reached..].to_vec(),
            "reached {reached}"
        );
    }
}

/// Without a copy to read the prefix cannot be placed in the new file: still refused, and the
/// whole batch is replayed (never skipped).
#[test]
fn a_prefix_is_still_refused_across_a_copytruncate_with_no_rotated_copy() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 13, 3);
    assert_eq!(tailer.read_batch(10).len(), 10);
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..4)));
    assert!(!tailer.commit_batch_through(5));
}

/// A restart mid-drain while the live file is still under 256 bytes and grows before the first
/// poll: the stored (old) fingerprint never matches a file that small, which looks like growth
/// of a small file. The rotated copy carrying that fingerprint proves it is a copytruncate.
#[test]
fn a_restart_mid_drain_with_a_tiny_growing_live_file_still_resumes_the_copy() {
    let short = |p: &str, r: std::ops::Range<usize>| -> Vec<String> {
        r.map(|i| format!("{p}-{i:03}-xxxx")).collect()
    };
    for grows in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let cursors = dir.path().join("cursors");
        std::fs::write(&log, text(&short("o", 0..10))).unwrap(); // 150 bytes, under the window
        let mut tailer = LogTailer::new(log.clone(), cursors.clone());
        assert_eq!(tailer.read_batch(2).len(), 2);
        tailer.commit_batch();
        tailer.persist_cursor().unwrap();
        copytruncate(&log);
        append(&log, &text(&short("n", 0..4)));
        assert_eq!(tailer.read_batch(1), short("o", 2..3));
        tailer.commit_batch();
        tailer.persist_cursor().unwrap();
        drop(tailer);

        let mut tailer = LogTailer::new(log.clone(), cursors);
        let mut expected = short("o", 3..10);
        expected.extend(short("n", 0..4));
        if grows {
            append(&log, &text(&short("n", 4..5)));
            expected.extend(short("n", 4..5));
        }
        assert_eq!(drain(&mut tailer, 100, u64::MAX), expected, "grows {grows}");
        assert_eq!(tailer.rotation_loss(), RotationLoss::default());
    }
}

/// A second rotation lands while the first copy is still being drained, then the process
/// restarts. The saved cursor names the FIRST generation (now `.2`) and the restart reads it
/// there, then the second generation (`.1`), then the live file: nothing lost, nothing repeated.
#[test]
fn a_second_copytruncate_mid_drain_then_a_restart_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    std::fs::write(&log, text(&lines("A", 0..10))).unwrap();
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(tailer.read_batch(2), lines("A", 0..2));
    tailer.commit_batch();
    // The first generation's copy is `.1`; the tailer starts draining it.
    copytruncate(&log);
    append(&log, &text(&lines("B", 0..10)));
    assert_eq!(tailer.read_batch(1), lines("A", 2..3));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();

    // A second rotation, past the guard: A moves to `.2` uncompressed, B is copied to `.1`.
    std::fs::rename(rotated_copy(&log), dir.path().join("events.jsonl.2")).unwrap();
    copytruncate(&log);
    append(&log, &text(&lines("C", 0..2)));
    assert_eq!(tailer.read_batch(3), lines("A", 3..6));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    drop(tailer);

    let mut tailer = LogTailer::new(log.clone(), cursors);
    let mut expected = lines("A", 6..10);
    expected.extend(lines("B", 0..10));
    expected.extend(lines("C", 0..2));
    assert_eq!(drain(&mut tailer, 7, u64::MAX), expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// The same, but the first generation was compressed by the second rotation (the shipped
/// `delaycompress` behaviour): it cannot be read, and the restart says so instead of silently
/// starting at the live file.
#[test]
fn a_second_copytruncate_mid_drain_then_a_restart_reports_the_compressed_generation() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    std::fs::write(&log, text(&lines("A", 0..10))).unwrap();
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(tailer.read_batch(2).len(), 2);
    tailer.commit_batch();
    copytruncate(&log);
    append(&log, &text(&lines("B", 0..10)));
    assert_eq!(tailer.read_batch(1), lines("A", 2..3));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    std::fs::rename(rotated_copy(&log), dir.path().join("events.jsonl.2.gz")).unwrap();
    copytruncate(&log);
    append(&log, &text(&lines("C", 0..2)));
    assert_eq!(tailer.read_batch(3).len(), 3);
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    drop(tailer);

    // `.2.gz` here is not gzip at all: the first generation cannot be found. The cursor records no
    // finished copy, so `.1` (B) cannot be shown to be newer than what was ingested: nothing is
    // read from it, and the loss is reported.
    let mut tailer = LogTailer::new(log.clone(), cursors);
    let seen = drain(&mut tailer, 100, u64::MAX);
    assert_eq!(seen, lines("C", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1, "the loss is reported");
}

fn gzip(path: &Path, content: &[u8]) {
    let mut encoder = flate2::write::GzEncoder::new(
        std::fs::File::create(path).unwrap(),
        flate2::Compression::default(),
    );
    encoder.write_all(content).unwrap();
    encoder.finish().unwrap();
}

/// The shipped policy (`compress` + `delaycompress`): the second rotation compresses the first
/// copy, so after it the first generation is only `.2.gz`. A restart finds the generation the
/// cursor names inside it, reads its remainder, then B from `.1`, then the live file: no loss.
#[test]
fn a_second_copytruncate_mid_drain_then_a_restart_resumes_from_the_gzip_of_the_first_generation() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    std::fs::write(&log, text(&lines("A", 0..10))).unwrap();
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(tailer.read_batch(2).len(), 2);
    tailer.commit_batch();
    copytruncate(&log);
    append(&log, &text(&lines("B", 0..10)));
    assert_eq!(tailer.read_batch(1), lines("A", 2..3));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();

    // What logrotate does at the second rotation: `.1` is compressed to `.2.gz`, then B is
    // copied to a fresh `.1`.
    let first = std::fs::read(rotated_copy(&log)).unwrap();
    gzip(&dir.path().join("events.jsonl.2.gz"), &first);
    std::fs::remove_file(rotated_copy(&log)).unwrap();
    copytruncate(&log);
    append(&log, &text(&lines("C", 0..2)));
    assert_eq!(tailer.read_batch(3), lines("A", 3..6));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    drop(tailer);

    let mut tailer = LogTailer::new(log.clone(), cursors);
    let mut expected = lines("A", 6..10);
    expected.extend(lines("B", 0..10));
    expected.extend(lines("C", 0..2));
    assert_eq!(drain(&mut tailer, 7, u64::MAX), expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// The same restart with a `.2.gz` cut short: the stream cannot be expanded to the end, so the
/// first generation is reported as lost, and B and the live file are still read.
#[test]
fn a_truncated_gzip_of_the_first_generation_is_a_reported_loss_and_the_rest_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    std::fs::write(&log, text(&lines("A", 0..40))).unwrap();
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(tailer.read_batch(2).len(), 2);
    tailer.commit_batch();
    copytruncate(&log);
    append(&log, &text(&lines("B", 0..10)));
    assert_eq!(tailer.read_batch(1), lines("A", 2..3));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    let first = std::fs::read(rotated_copy(&log)).unwrap();
    let gz = dir.path().join("events.jsonl.2.gz");
    gzip(&gz, &first);
    let bytes = std::fs::read(&gz).unwrap();
    // Keep the header and the start of the stream (enough for the first 256 bytes), drop the tail.
    std::fs::write(&gz, &bytes[..bytes.len() - 12]).unwrap();
    std::fs::remove_file(rotated_copy(&log)).unwrap();
    copytruncate(&log);
    append(&log, &text(&lines("C", 0..2)));
    tailer.persist_cursor().unwrap();
    drop(tailer);

    let mut tailer = LogTailer::new(log.clone(), cursors);
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("C", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1);
}

/// Sets up a cursor that records a finished earlier copy (Z) and is reading the live file (A),
/// persisted. Returns the log path and the cursor directory.
fn reader_that_finished_a_copy(dir: &Path) -> (PathBuf, PathBuf) {
    let log = dir.join("events.jsonl");
    let cursors = dir.join("cursors");
    std::fs::write(&log, text(&lines("Z", 0..6))).unwrap();
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(tailer.read_batch(1), lines("Z", 0..1));
    tailer.commit_batch();
    copytruncate(&log);
    append(&log, &text(&lines("A", 0..10)));
    assert_eq!(tailer.read_batch(5), lines("Z", 1..6));
    tailer.commit_batch();
    // The next read finds the copy empty, releases it and moves on to the live file.
    assert_eq!(tailer.read_batch(2), lines("A", 0..2));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    (log, cursors)
}

fn set_modified_in_the_future(path: &Path) {
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(later)
        .unwrap();
}

/// The documented manual recovery, with the reader stopped: `truncate -s 0` leaves `.1` as the
/// previous generation, which the reader finished long ago. The restart must not read it again.
#[test]
fn a_manual_truncate_while_the_reader_is_stopped_re_ingests_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (log, cursors) = reader_that_finished_a_copy(dir.path());
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("C", 0..2)));

    let mut tailer = LogTailer::new(log, cursors);
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("C", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1, "the discard is reported");
}

/// The reviewer's stale case: the reader drained one copy (Z), then a later rotation (A) landed
/// while it was caught up, so no drain recorded anything about it. A manual truncate while stopped
/// leaves `.1` holding A, which the reader ingested in full. The restart must not read it.
#[test]
fn a_copy_left_by_a_rotation_at_a_caught_up_moment_is_not_re_ingested_after_a_manual_truncate() {
    let dir = tempfile::tempdir().unwrap();
    let (log, cursors) = reader_that_finished_a_copy(dir.path());
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(
        drain(&mut tailer, 100, u64::MAX),
        lines("A", 2..10),
        "read to the end"
    );
    copytruncate(&log); // caught up: `.1` is now all of A, already ingested
    append(&log, &text(&lines("T", 0..3)));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("T", 0..3));
    tailer.persist_cursor().unwrap();
    drop(tailer);

    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("U", 0..2)));

    let mut tailer = LogTailer::new(log, cursors);
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("U", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1);
}

/// An unfindable generation reads NO rotated copy, however newer it looks: nothing says whether it
/// was ingested or not, and re-reading it would repeat up to a whole generation.
#[test]
fn an_unfindable_generation_reads_no_rotated_copy_even_one_that_looks_newer() {
    let dir = tempfile::tempdir().unwrap();
    let (log, cursors) = reader_that_finished_a_copy(dir.path());
    std::fs::write(rotated_copy(&log), text(&lines("B", 0..10))).unwrap();
    set_modified_in_the_future(&rotated_copy(&log));
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("C", 0..2)));

    let mut tailer = LogTailer::new(log, cursors);
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("C", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1);
}

/// A first stamp taken while only the start of a first line was visible names a window shorter
/// than a line. Once the file grows past it the window is widened, so a copytruncate and refill
/// past the offset while the reader is stopped is still recognised, and `.1` is drained.
#[test]
fn a_stamp_taken_on_a_partial_first_line_is_widened_as_the_file_grows() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    let json = |g: &str, i: usize| {
        format!("{{\"v\":1,\"source_ip\":\"192.0.2.1\",\"gen\":\"{g}\",\"n\":{i}}}")
    };
    let all =
        |g: &str, r: std::ops::Range<usize>| -> Vec<String> { r.map(|i| json(g, i)).collect() };

    std::fs::write(&log, "{\"v\":1,\"so").unwrap(); // a line being written: 10 bytes visible
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert!(tailer.read_batch(100).is_empty()); // stamps the 10-byte window
    tailer.commit_batch();
    append(&log, &format!("{}\n", &json("A", 0)[10..]));
    append(&log, &text(&all("A", 1..6)));
    assert_eq!(tailer.read_batch(2), all("A", 0..2));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    let saved = DurableCursor::new(log.clone(), cursors.clone())
        .load()
        .unwrap()
        .unwrap();
    assert!(saved.fingerprint_len > Some(10), "widened: {saved:?}");
    drop(tailer);

    copytruncate(&log);
    append(&log, &text(&all("B", 0..6)));

    let mut tailer = LogTailer::new(log, cursors);
    let mut expected = all("A", 2..6);
    expected.extend(all("B", 0..6));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// A cursor saved while the live file was under 256 bytes names a shorter window. After the file
/// grew and was rotated, `.1` is compared over that window: the rest of it is read from the
/// offset, nothing twice, no loss. The real guard sees `.1` as unread by the same rule.
#[test]
fn a_cursor_saved_on_a_small_file_still_finds_the_grown_and_rotated_copy() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let cursors = dir.path().join("cursors");
    std::fs::write(&log, text(&lines("S", 0..1))).unwrap(); // 45 bytes: under the window
    let mut tailer = LogTailer::new(log.clone(), cursors.clone());
    assert_eq!(tailer.read_batch(100), lines("S", 0..1));
    tailer.commit_batch();
    tailer.persist_cursor().unwrap();
    drop(tailer);

    append(&log, &text(&lines("S", 1..20)));
    copytruncate(&log);
    append(&log, &text(&lines("T", 0..2)));

    let guard = std::process::Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/logrotate-guard.sh"
    ))
    .arg(&log)
    .env("PROPOLIS_LOGROTATE_RESERVE_BYTES", "0")
    .env("PROPOLIS_CURSOR_DIR", &cursors)
    .env("PROPOLIS_SHIPPER_CURSOR_DIR", dir.path().join("none"))
    .output()
    .unwrap();
    assert_eq!(guard.status.code(), Some(1), "{guard:?}");
    assert!(String::from_utf8_lossy(&guard.stderr).contains("not fully read"));

    let mut tailer = LogTailer::new(log, cursors);
    let mut expected = lines("S", 1..20);
    expected.extend(lines("T", 0..2));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), expected);
    assert_eq!(tailer.rotation_loss(), RotationLoss::default());
}

/// A stale `.1` is not read by a RUNNING tailer when the generation it follows is unfindable (it
/// is an older generation, already ingested), unlike the first poll after a start.
#[test]
fn a_running_tailer_does_not_read_a_stale_rotated_copy_when_its_generation_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = behind_tailer(dir.path(), &log, 30, 10);
    std::fs::write(rotated_copy(&log), text(&lines("stale", 0..40))).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..2)));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("new", 0..2));
    assert_eq!(tailer.rotation_loss().events, 1);
}

/// A restart after a truncation with nothing to resume from: the old size was never observed, so
/// the loss cannot be sized, but it is still reported rather than assumed zero.
#[test]
fn a_truncation_found_at_start_with_no_rotated_copy_is_reported_unsized() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let tailer = behind_tailer(dir.path(), &log, 30, 10);
    tailer.persist_cursor().unwrap();
    drop(tailer);
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log)
        .unwrap();
    append(&log, &text(&lines("new", 0..2)));

    let mut tailer = LogTailer::new(log, dir.path().join("cursors"));
    assert_eq!(drain(&mut tailer, 100, u64::MAX), lines("new", 0..2));
    assert_eq!(
        tailer.rotation_loss(),
        RotationLoss {
            events: 1,
            bytes_estimated: 0
        }
    );
}
