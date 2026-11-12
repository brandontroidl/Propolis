//! What the heartbeat says about each configured log: whether the watcher can actually read it.
//! A label whose path is wrong (a typo in `PROPOLIS_SENSOR_LOGS` once silently dropped two
//! sensors) shows as `missing` here on every heartbeat instead of as a quiet stream.

use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// Opened read-only just now.
    Following,
    /// Nothing at the path.
    Missing,
    /// Something is there but this user cannot read it as a regular file: a permission error on
    /// the file or a directory above it, or a path that names a directory or device.
    Unreadable,
}

impl FileStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Following => "following",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
        }
    }
}

/// The status of `path` and, when it can be stat'd, its current size.
pub fn file_status(path: &Path) -> (FileStatus, Option<u64>) {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return (FileStatus::Missing, None),
        Err(_) => return (FileStatus::Unreadable, None),
    };
    let size = Some(metadata.len());
    if !metadata.is_file() {
        return (FileStatus::Unreadable, size);
    }
    match File::open(path) {
        Ok(_) => (FileStatus::Following, size),
        Err(_) => (FileStatus::Unreadable, size),
    }
}
