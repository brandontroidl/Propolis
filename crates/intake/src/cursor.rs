//! Durable log cursor: tracks the read position in one sensor's NDJSON log file across process
//! restarts and log rotation. See "The durable log cursor" in
//! `internal/design/03-event-intake-aggregation.md`.
//!
//! Fails closed: a missing or corrupt cursor file is treated identically - start over from
//! offset 0. Re-reading events the ledger already has is safe (the dedup window in
//! `append_event` catches the overlap); silently trusting an unreadable cursor is not.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The read position in a sensor's log file, persisted as JSON between batches.
///
/// `inode` and `fingerprint` exist to detect rotation, not just to resume a plain read:
/// `offset` alone can't tell a truncated-and-refilled file from one still growing normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorState {
    pub inode: u64,
    pub offset: u64,
    /// SHA-256 of the first `min(256, file_size)` bytes at offset 0, computed via
    /// [`compute_fingerprint`].
    pub fingerprint: [u8; 32],
}

/// What, if anything, changed about the log file since `CursorState` was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationEvent {
    /// The file matches the recorded state; keep reading from `offset`.
    None,
    /// `offset` is past the current file size: a `copytruncate` rotation reset the file to
    /// zero length (and it may already have new content written after the truncate).
    Truncated,
    /// The file at this path now has a different inode: rotation by rename created a fresh
    /// file, and the old inode (if still open) should be drained to EOF separately.
    InodeChanged,
    /// Same inode, `offset` still within the current size, but the leading bytes no longer
    /// match the recorded fingerprint: the content was replaced in place.
    Replaced,
}

/// Persists and loads the read-position cursor for one sensor log file.
///
/// One `DurableCursor` per log path; `cursor_file_path` derives a stable, collision-free file
/// name from the log path itself, so distinct log paths never share a cursor file and the same
/// log path always resolves to the same one across restarts.
pub struct DurableCursor {
    log_path: PathBuf,
    cursor_dir: PathBuf,
}

impl DurableCursor {
    pub fn new(log_path: PathBuf, cursor_dir: PathBuf) -> Self {
        Self {
            log_path,
            cursor_dir,
        }
    }

    /// The on-disk path of this instance's persisted cursor file: the cursor directory joined
    /// with a SHA-256 hex digest of the log path's raw bytes. Hashing rather than reusing the
    /// log file's own name avoids collisions between sensors whose logs share a basename in
    /// different directories, and needs no filesystem access, so it works even before the log
    /// file or the cursor directory exist.
    pub fn cursor_file_path(&self) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(self.log_path.as_os_str().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        self.cursor_dir
            .join(format!("{}.json", hex_encode(&digest)))
    }

    /// Loads the persisted state, or `Ok(None)` if the cursor file is missing or its content
    /// isn't valid JSON for `CursorState` - both are "no usable cursor", handled identically so
    /// callers always fail closed to offset 0 rather than branching on which happened. An
    /// `Err` is reserved for a read failure that is neither (e.g. permission denied), which is
    /// worth surfacing rather than silently folding into "missing".
    pub fn load(&self) -> io::Result<Option<CursorState>> {
        let bytes = match std::fs::read(self.cursor_file_path()) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }

    /// Persists `state` atomically: write JSON to a temp file in the same directory, fsync it,
    /// then rename over the final path. The rename is atomic on POSIX filesystems, so a reader
    /// (a concurrent `load`, or this process reloading after a crash mid-write) always sees
    /// either the complete previous state or the complete new one, never a partial mix.
    pub fn save(&self, state: &CursorState) -> io::Result<()> {
        std::fs::create_dir_all(&self.cursor_dir)?;

        let final_path = self.cursor_file_path();
        let tmp_path = final_path.with_extension("json.tmp");
        let json = serde_json::to_vec(state).map_err(io::Error::other)?;

        let mut tmp_file = File::create(&tmp_path)?;
        tmp_file.write_all(&json)?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        std::fs::rename(&tmp_path, &final_path)
    }

    /// Compares `state` against the log file's current on-disk metadata. Checked in order:
    /// inode change first (rotation by rename - the cheapest and most conclusive signal), then
    /// truncation (`copytruncate`, the deployed logrotate strategy: `offset` now past the
    /// current size), then content replacement (same inode, `offset` still in range, but the
    /// leading bytes drifted). If the log file can't be stat'd at all, returns `None`: a
    /// missing log file is the tailer's own case to handle (poll until it appears), not
    /// evidence of rotation.
    pub fn detect_rotation(&self, state: &CursorState) -> RotationEvent {
        let metadata = match std::fs::metadata(&self.log_path) {
            Ok(m) => m,
            Err(_) => return RotationEvent::None,
        };

        if metadata.ino() != state.inode {
            return RotationEvent::InodeChanged;
        }
        if state.offset > metadata.len() {
            return RotationEvent::Truncated;
        }
        if compute_fingerprint(&self.log_path) != state.fingerprint {
            return RotationEvent::Replaced;
        }
        RotationEvent::None
    }
}

/// Reads `path`'s inode number, or `0` (never a real inode on Linux) if it can't be stat'd.
pub fn get_inode(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
}

/// Hashes the first `min(256, file_size)` bytes of `path`, or the all-zero digest if the file
/// can't be opened or read - an infallible signature (this feeds directly into `CursorState`
/// construction, including before the file necessarily exists) so errors fold into a sentinel
/// rather than a panic.
pub fn compute_fingerprint(path: &Path) -> [u8; 32] {
    let Ok(file) = File::open(path) else {
        return [0u8; 32];
    };
    let mut buf = Vec::with_capacity(256);
    if file.take(256).read_to_end(&mut buf).is_err() {
        return [0u8; 32];
    }
    Sha256::digest(&buf).into()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
