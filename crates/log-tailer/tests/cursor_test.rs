use log_tailer::*;
use std::path::PathBuf;

#[test]
fn save_and_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "line1\nline2\n").unwrap();
    let cursor = DurableCursor::new(log_path, dir.path().join("cursors"));
    let state = CursorState {
        inode: 12345,
        offset: 6,
        fingerprint: [0u8; 32],
    };
    cursor.save(&state).unwrap();
    let loaded = cursor.load().unwrap().unwrap();
    assert_eq!(loaded.inode, 12345);
    assert_eq!(loaded.offset, 6);
}

#[test]
fn missing_cursor_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = DurableCursor::new(dir.path().join("events.jsonl"), dir.path().join("cursors"));
    assert!(cursor.load().unwrap().is_none());
}

#[test]
fn corrupt_cursor_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let cursor_dir = dir.path().join("cursors");
    std::fs::create_dir_all(&cursor_dir).unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor = DurableCursor::new(log_path, cursor_dir.clone());
    // Write garbage to the cursor file.
    let cursor_file = cursor.cursor_file_path();
    std::fs::write(&cursor_file, "not json").unwrap();
    assert!(cursor.load().unwrap().is_none());
}

#[test]
fn detect_truncation_when_offset_exceeds_size() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "short").unwrap();
    let cursor = DurableCursor::new(log_path.clone(), dir.path().join("cursors"));
    let state = CursorState {
        inode: get_inode(&log_path),
        offset: 1000, // way past file size
        fingerprint: compute_fingerprint(&log_path),
    };
    let rotation = cursor.detect_rotation(&state);
    assert!(matches!(rotation, RotationEvent::Truncated));
}

#[test]
fn detect_no_rotation_when_offset_within_size() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "some content here\n").unwrap();
    let cursor = DurableCursor::new(log_path.clone(), dir.path().join("cursors"));
    let state = CursorState {
        inode: get_inode(&log_path),
        offset: 5,
        fingerprint: compute_fingerprint(&log_path),
    };
    let rotation = cursor.detect_rotation(&state);
    assert!(matches!(rotation, RotationEvent::None));
}

#[test]
fn detect_inode_changed_when_inode_differs() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "some content here\n").unwrap();
    let cursor = DurableCursor::new(log_path.clone(), dir.path().join("cursors"));
    let state = CursorState {
        // Bitwise complement is guaranteed to differ from the real current inode.
        inode: !get_inode(&log_path),
        offset: 5,
        fingerprint: compute_fingerprint(&log_path),
    };
    let rotation = cursor.detect_rotation(&state);
    assert!(matches!(rotation, RotationEvent::InodeChanged));
}

#[test]
fn detect_replaced_when_same_inode_but_fingerprint_differs() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "some content here\n").unwrap();
    let cursor = DurableCursor::new(log_path.clone(), dir.path().join("cursors"));
    let mut wrong_fingerprint = compute_fingerprint(&log_path);
    wrong_fingerprint[0] ^= 0xFF; // guaranteed to differ from the real fingerprint
    let state = CursorState {
        inode: get_inode(&log_path),
        offset: 5, // still within the file's size
        fingerprint: wrong_fingerprint,
    };
    let rotation = cursor.detect_rotation(&state);
    assert!(matches!(rotation, RotationEvent::Replaced));
}

#[test]
fn cursor_file_path_is_deterministic_per_log_path() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursors");
    let a = DurableCursor::new(log_path.clone(), cursor_dir.clone());
    let b = DurableCursor::new(log_path, cursor_dir);
    assert_eq!(a.cursor_file_path(), b.cursor_file_path());
}

/// Every spelling of one log shares one cursor file, whether the log exists yet or not: the rotation
/// guard resolves the path with `readlink -f` and must land on the file the daemon wrote.
#[test]
fn cursor_file_path_is_the_same_for_every_spelling_of_a_log() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
    let cursor_dir = dir.path().join("cursors");
    let at = |p: PathBuf| DurableCursor::new(p, cursor_dir.clone()).cursor_file_path();

    for exists in [false, true] {
        if exists {
            std::fs::write(real.join("events.jsonl"), "x").unwrap();
        }
        let canonical = at(real.join("events.jsonl"));
        assert_eq!(at(dir.path().join("link/events.jsonl")), canonical);
        assert_eq!(
            at(PathBuf::from(format!(
                "{}//real/./events.jsonl",
                dir.path().display()
            ))),
            canonical
        );
        assert_eq!(at(dir.path().join("real/../link/events.jsonl")), canonical);
    }
    // Nothing resolvable: the path as given, still deterministic.
    let ghost = PathBuf::from("/nonexistent-ctdrain/x/events.jsonl");
    assert_eq!(at(ghost.clone()), at(ghost));
}

/// A cursor written under the name derived from the path as configured (before names were derived
/// from the resolved path) is picked up once, moved to the resolved name, and the old file removed.
#[test]
fn a_cursor_named_by_the_configured_path_is_migrated_not_lost() {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
    std::fs::write(real.join("events.jsonl"), "a\nb\nc\nd\n").unwrap();
    let configured = dir.path().join("link/events.jsonl");
    let cursor_dir = dir.path().join("cursors");
    std::fs::create_dir_all(&cursor_dir).unwrap();

    let legacy_hash: String = Sha256::digest(configured.as_os_str().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let legacy = cursor_dir.join(format!("{legacy_hash}.json"));
    let inode = get_inode(&configured);
    let fingerprint = compute_fingerprint(&configured);
    let state = CursorState {
        inode,
        offset: 4,
        fingerprint,
    };
    std::fs::write(&legacy, serde_json::to_vec(&state).unwrap()).unwrap();

    let mut tailer = LogTailer::new(configured.clone(), cursor_dir.clone());
    assert_eq!(
        tailer.read_batch(10),
        vec!["c", "d"],
        "resumed, not re-read"
    );
    let cursor = DurableCursor::new(configured, cursor_dir);
    assert!(
        cursor.cursor_file_path().exists(),
        "saved under the resolved name"
    );
    assert!(!legacy.exists(), "the configured-name file is gone");
    assert_eq!(cursor.load().unwrap(), Some(state));
}

#[test]
fn cursor_file_path_differs_for_different_log_paths() {
    let dir = tempfile::tempdir().unwrap();
    let cursor_dir = dir.path().join("cursors");
    let a = DurableCursor::new(dir.path().join("sensor-a.jsonl"), cursor_dir.clone());
    let b = DurableCursor::new(dir.path().join("sensor-b.jsonl"), cursor_dir);
    assert_ne!(a.cursor_file_path(), b.cursor_file_path());
}

#[test]
fn get_inode_returns_zero_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.jsonl");
    assert_eq!(get_inode(&missing), 0);
}

#[test]
fn compute_fingerprint_returns_zero_digest_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.jsonl");
    assert_eq!(compute_fingerprint(&missing), [0u8; 32]);
}

#[test]
fn compute_fingerprint_ignores_bytes_beyond_256() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");

    let mut content = vec![b'a'; 256];
    content.extend_from_slice(b"tail-content-one");
    std::fs::write(&path, &content).unwrap();
    let fp1 = compute_fingerprint(&path);

    let mut content2 = vec![b'a'; 256];
    content2.extend_from_slice(b"a-completely-different-and-longer-tail");
    std::fs::write(&path, &content2).unwrap();
    let fp2 = compute_fingerprint(&path);

    assert_eq!(
        fp1, fp2,
        "bytes beyond the first 256 must not affect the fingerprint"
    );
}

#[test]
fn compute_fingerprint_differs_when_leading_bytes_differ() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, "aaaa").unwrap();
    let fp1 = compute_fingerprint(&path);
    std::fs::write(&path, "bbbb").unwrap();
    let fp2 = compute_fingerprint(&path);
    assert_ne!(fp1, fp2);
}

#[test]
fn atomic_save_does_not_corrupt_on_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "content").unwrap();
    let cursor = DurableCursor::new(log_path, dir.path().join("cursors"));
    let state1 = CursorState {
        inode: 1,
        offset: 10,
        fingerprint: [1u8; 32],
    };
    cursor.save(&state1).unwrap();
    let state2 = CursorState {
        inode: 2,
        offset: 20,
        fingerprint: [2u8; 32],
    };
    cursor.save(&state2).unwrap();
    let loaded = cursor.load().unwrap().unwrap();
    // Must be state2, not a corrupt mix of state1 and state2.
    assert_eq!(loaded.inode, 2);
    assert_eq!(loaded.offset, 20);
}
