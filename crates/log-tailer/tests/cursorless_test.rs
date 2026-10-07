//! The cursorless mode (`LogTailer::without_cursor`) a live reader uses: it must follow the file
//! exactly as the cursor-backed tailer does while never writing anything, and it must say where
//! an over-length line was discarded instead of skipping it silently.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use log_tailer::{LogTailer, MAX_LINE_BYTES, StartAt, TailEntry};

fn append(path: &Path, text: &str) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

fn listing(dir: &Path) -> BTreeMap<String, (u64, SystemTime)> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let m = e.metadata().unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                (m.len(), m.modified().unwrap()),
            )
        })
        .collect()
}

fn line(s: &str) -> TailEntry {
    TailEntry::Line(s.to_string())
}

#[test]
fn start_at_end_reads_only_lines_appended_after_start() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    std::fs::write(&log, "old1\nold2\n").unwrap();
    let mut tailer = LogTailer::without_cursor(log.clone(), StartAt::End);
    assert!(tailer.read_batch(10).is_empty());
    append(&log, "new1\n");
    assert_eq!(tailer.read_batch(10), vec!["new1"]);
}

#[test]
fn start_at_end_backs_up_to_the_start_of_an_unfinished_line() {
    // A writer mid-line at the moment the reader starts: the reader must deliver that line whole
    // once it is finished, not its tail as a fragment.
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    std::fs::write(&log, "old\n{\"half\":").unwrap();
    let mut tailer = LogTailer::without_cursor(log.clone(), StartAt::End);
    assert!(tailer.read_batch(10).is_empty());
    append(&log, "1}\n");
    assert_eq!(tailer.read_batch(10), vec!["{\"half\":1}"]);
}

#[test]
fn start_at_beginning_replays_the_current_file() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    std::fs::write(&log, "a\nb\n").unwrap();
    let mut tailer = LogTailer::without_cursor(log, StartAt::Beginning);
    assert_eq!(tailer.read_batch(10), vec!["a", "b"]);
}

#[test]
fn a_file_that_appears_after_start_is_read_from_its_first_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut tailer = LogTailer::without_cursor(log.clone(), StartAt::End);
    assert!(tailer.read_batch(10).is_empty());
    append(&log, "first\nsecond\n");
    assert_eq!(tailer.read_batch(10), vec!["first", "second"]);
}

#[test]
fn follows_a_copytruncate_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    std::fs::write(&log, "before1\nbefore2\n").unwrap();
    let mut tailer = LogTailer::without_cursor(log.clone(), StartAt::Beginning);
    assert_eq!(tailer.read_batch(10), vec!["before1", "before2"]);
    std::fs::copy(&log, dir.path().join("events.jsonl.1")).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(0)
        .unwrap();
    append(&log, "after\n");
    assert_eq!(tailer.read_batch(10), vec!["after"]);
}

#[test]
fn reports_an_over_length_line_in_place_and_counts_only_lines_toward_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let giant = "x".repeat(MAX_LINE_BYTES as usize + 1);
    std::fs::write(&log, format!("good1\n{giant}\ngood2\ngood3\n")).unwrap();
    let mut tailer = LogTailer::without_cursor(log, StartAt::Beginning);
    assert_eq!(
        tailer.read_batch_entries(2),
        vec![
            line("good1"),
            TailEntry::Discarded {
                bytes: MAX_LINE_BYTES + 2
            },
            line("good2"),
        ]
    );
    assert_eq!(tailer.read_batch_entries(2), vec![line("good3")]);
}

#[test]
fn never_writes_a_file_and_refuses_to_persist() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    std::fs::write(&log, "a\n").unwrap();
    let before = listing(dir.path());
    let mut tailer = LogTailer::without_cursor(log.clone(), StartAt::Beginning);
    assert_eq!(tailer.read_batch(10), vec!["a"]);
    tailer.commit_batch();
    let err = tailer.persist_cursor().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(listing(dir.path()), before, "nothing created or modified");
}
