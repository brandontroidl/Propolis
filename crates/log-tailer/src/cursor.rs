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
    /// How many bytes `fingerprint` covers: `min(256, file_size)` when it was taken, so a file
    /// that has since grown (or been rotated into `<log>.1`) is compared over the same window.
    /// Absent in a cursor written by an older version, which means "the first 256 bytes".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_len: Option<u16>,
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
    /// The path the cursor file name is derived from: `log_path` with symlinks, `.`, `..` and
    /// repeated slashes resolved, so every spelling of one log shares one cursor (and the rotation
    /// guard, which resolves the same way with `readlink -f`, finds it). See `canonical_key`.
    key_path: PathBuf,
    cursor_dir: PathBuf,
}

/// `log_path` resolved as far as the filesystem allows, fixed once at construction: the whole
/// path if it exists; otherwise its parent directory resolved with the file name appended (a log
/// that has not been created yet); otherwise the path exactly as given. The fallbacks mean a
/// cursor is never refused for want of a file, and agree with `readlink -f`, which the rotation
/// guard uses.
fn canonical_key(log_path: &Path) -> PathBuf {
    if let Ok(path) = std::fs::canonicalize(log_path) {
        return path;
    }
    let resolved_parent = log_path
        .file_name()
        .zip(log_path.parent().filter(|p| !p.as_os_str().is_empty()))
        .and_then(|(name, parent)| Some(std::fs::canonicalize(parent).ok()?.join(name)));
    resolved_parent.unwrap_or_else(|| log_path.to_path_buf())
}

impl DurableCursor {
    pub fn new(log_path: PathBuf, cursor_dir: PathBuf) -> Self {
        let key_path = canonical_key(&log_path);
        Self {
            log_path,
            key_path,
            cursor_dir,
        }
    }

    /// The on-disk path of this instance's persisted cursor file: the cursor directory joined
    /// with a SHA-256 hex digest of the log path, resolved as `canonical_key` describes (the
    /// bytes of the path as given when nothing of it can be resolved). Hashing rather than
    /// reusing the log file's own name avoids collisions between sensors whose logs share a
    /// basename in different directories. Resolution happens once, at construction, so a cursor
    /// file is stable for the life of the instance.
    pub fn cursor_file_path(&self) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(self.key_path.as_os_str().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        self.cursor_dir
            .join(format!("{}.json", hex_encode(&digest)))
    }

    /// Loads the persisted state, or `Ok(None)` if the cursor file is missing or its content
    /// isn't valid JSON for `CursorState` - both are "no usable cursor", handled identically so
    /// callers always fail closed to offset 0 rather than branching on which happened. An
    /// `Err` is reserved for a read failure that is neither (e.g. permission denied), which is
    /// worth surfacing rather than silently folding into "missing".
    ///
    /// One-time migration: cursors written before the file name was derived from the resolved
    /// path were named by the path exactly as configured. When the resolved name has no cursor and
    /// the as-configured name does (a symlinked or non-normalized spelling, or a log whose parent
    /// directory did not exist when the name was first derived), that cursor is loaded, saved under
    /// the resolved name and the old file removed, so one canonical path remains. Remove this
    /// fallback (and `legacy_file_path`) once every deployment has restarted on this version.
    ///
    /// When both names exist (a rollback to the old version after an upgrade left a newer
    /// as-configured file beside the resolved one), the one written later wins and the other is
    /// removed.
    pub fn load(&self) -> io::Result<Option<CursorState>> {
        let canonical = self.cursor_file_path();
        let legacy = self.legacy_file_path();
        let read = |path: &Path| -> io::Result<Option<Vec<u8>>> {
            match std::fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        };
        let current = read(&canonical)?;
        if legacy == canonical {
            return Ok(current.and_then(|b| serde_json::from_slice(&b).ok()));
        }
        let old = read(&legacy)?;
        let modified = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();
        match (current, old) {
            (Some(current), None) => Ok(serde_json::from_slice(&current).ok()),
            (None, None) => Ok(None),
            (None, Some(old)) => self.adopt_legacy(&legacy, &old),
            (Some(current), Some(old)) => {
                if modified(&legacy) > modified(&canonical) {
                    self.adopt_legacy(&legacy, &old)
                } else {
                    let _ = std::fs::remove_file(&legacy);
                    Ok(serde_json::from_slice(&current).ok())
                }
            }
        }
    }

    /// The cursor file name derived from the log path as configured, before resolution.
    fn legacy_file_path(&self) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(self.log_path.as_os_str().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        self.cursor_dir
            .join(format!("{}.json", hex_encode(&digest)))
    }

    fn adopt_legacy(&self, legacy: &Path, bytes: &[u8]) -> io::Result<Option<CursorState>> {
        let Some(state) = serde_json::from_slice::<CursorState>(bytes).ok() else {
            return Ok(None);
        };
        // Only drop the old file once the new one is durably in place.
        if self.save(&state).is_ok() {
            let _ = std::fs::remove_file(legacy);
        }
        Ok(Some(state))
    }

    /// The directory cursor files live in; the tailer also expands a compressed rotated copy
    /// there (as an unlinked file), the one place it is known to be able to write.
    pub(crate) fn dir(&self) -> &Path {
        &self.cursor_dir
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
        detect_rotation(&self.log_path, state)
    }
}

/// [`DurableCursor::detect_rotation`] without a cursor: it only ever reads `log_path`, so a
/// tailer that never persists a position (see `LogTailer::without_cursor`) uses it directly.
pub(crate) fn detect_rotation(log_path: &Path, state: &CursorState) -> RotationEvent {
    let metadata = match std::fs::metadata(log_path) {
        Ok(m) => m,
        Err(_) => return RotationEvent::None,
    };

    if metadata.ino() != state.inode {
        return RotationEvent::InodeChanged;
    }
    if state.offset > metadata.len() {
        return RotationEvent::Truncated;
    }
    match read_head(log_path) {
        // A file that was empty when stamped is unchanged while it is still empty.
        Some(head) if head_matches(state, &head) => RotationEvent::None,
        Some(head) if state.fingerprint_len == Some(0) && head.is_empty() => RotationEvent::None,
        _ => RotationEvent::Replaced,
    }
}

/// The first up to 256 bytes of `path`, or `None` if it can't be read.
pub(crate) fn read_head(path: &Path) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    let mut buf = Vec::with_capacity(256);
    file.take(256).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Whether `head` (the first up to 256 bytes of a file) carries the fingerprint in `state`, over
/// the window the fingerprint was taken on. An empty window (a fingerprint of nothing) identifies
/// no file and matches none.
pub(crate) fn head_matches(state: &CursorState, head: &[u8]) -> bool {
    match state.fingerprint_len {
        None => Sha256::digest(head).as_slice() == state.fingerprint,
        Some(0) => false,
        Some(n) => {
            let n = usize::from(n);
            head.len() >= n && Sha256::digest(&head[..n]).as_slice() == state.fingerprint
        }
    }
}

/// [`compute_fingerprint`] together with the number of bytes it covered, which is what
/// [`CursorState::fingerprint_len`] records. An unreadable file is the zero digest over 0 bytes.
pub(crate) fn fingerprint_with_len(path: &Path) -> ([u8; 32], u16) {
    match read_head(path) {
        Some(head) => (Sha256::digest(&head).into(), head.len() as u16),
        None => ([0u8; 32], 0),
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
