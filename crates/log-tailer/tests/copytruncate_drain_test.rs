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
