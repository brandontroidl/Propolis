//! The heartbeat's per-file status against real filesystem states.

use std::os::unix::fs::PermissionsExt;

use watch::status::{FileStatus, file_status};

#[test]
fn a_readable_file_is_following_with_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, "abc\n").unwrap();
    assert_eq!(file_status(&path), (FileStatus::Following, Some(4)));
}

#[test]
fn an_absent_path_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        file_status(&dir.path().join("typo.jsonl")),
        (FileStatus::Missing, None)
    );
}

#[test]
fn a_directory_is_unreadable_not_following() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(file_status(dir.path()).0, FileStatus::Unreadable);
}

#[test]
fn a_file_this_user_cannot_open_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, "abc\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&path).is_ok() {
        // Running as root: permission bits do not stop it, so there is nothing to observe.
        return;
    }
    assert_eq!(file_status(&path), (FileStatus::Unreadable, Some(4)));
}

#[test]
fn a_file_under_a_directory_this_user_cannot_search_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sensor");
    std::fs::create_dir(&sub).unwrap();
    let path = sub.join("events.jsonl");
    std::fs::write(&path, "abc\n").unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
    let blocked = std::fs::metadata(&path).is_err();
    let status = file_status(&path);
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
    if blocked {
        assert_eq!(status, (FileStatus::Unreadable, None));
    }
}
