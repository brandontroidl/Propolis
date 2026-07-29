//! Log tailer: reads complete NDJSON lines from a sensor's log file, tracking position via
//! `DurableCursor` across polls, process restarts, and log rotation. See "The runner" and "The
//! durable log cursor" in `internal/design/03-event-intake-aggregation.md`.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;

use crate::cursor::{CursorState, DurableCursor, RotationEvent, compute_fingerprint, get_inode};

/// Below this size, `compute_fingerprint`'s `min(256, size)` window can shift from ordinary
/// append growth alone (no rotation at all), producing a fingerprint "mismatch" that does not
/// reflect real content replacement. See [`LogTailer::maybe_false_positive_replaced`].
const FINGERPRINT_STABLE_SIZE: u64 = 256;

/// Tails one sensor's NDJSON log file. Holds the in-memory [`CursorState`] for the lifetime of
/// this instance; [`Self::persist_cursor`] is the only thing that durably saves it; a crash
/// between reads and persistence re-reads the unpersisted portion on restart (tolerated by the
/// ledger's dedup window, per the design doc's at-least-once model).
pub struct LogTailer {
    log_path: PathBuf,
    cursor: DurableCursor,
    state: CursorState,
    /// Handle most recently opened for `log_path`, corresponding to `state.inode`. Kept across
    /// calls so that if the path is rotated out from under us (rotation by rename), the old
    /// inode's remaining unread bytes can still be drained through this still-open descriptor -
    /// POSIX keeps an inode's data readable via an already-open fd even after the directory
    /// entry is renamed or unlinked elsewhere - before switching to the new file at the same
    /// path. `None` means we have no such handle (fresh instance, or the old inode was already
    /// drained and abandoned).
    file: Option<File>,
    /// The log file's size as of the last time we observed it. Not persisted (restarting a
    /// process legitimately loses this - the old inode is gone regardless); exists purely to
    /// disambiguate a `RotationEvent::Replaced` signal caused by ordinary growth of a
    /// sub-256-byte file from a genuine in-place content swap.
    last_known_size: u64,
}

impl LogTailer {
    /// Loads any persisted cursor for `log_path` (falling back to a fresh zero state - fail
    /// closed, matching `DurableCursor::load`'s own missing/corrupt handling), and records the
    /// log file's current size, if it exists, as the initial growth baseline.
    pub fn new(log_path: PathBuf, cursor_dir: PathBuf) -> Self {
        let cursor = DurableCursor::new(log_path.clone(), cursor_dir);
        let state = cursor.load().ok().flatten().unwrap_or(CursorState {
            inode: 0, // never a real inode (see `get_inode`); guarantees the first
            // `detect_rotation` call reports `InodeChanged` so we stamp real state below.
            offset: 0,
            fingerprint: [0u8; 32],
        });
        let last_known_size = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
        Self {
            log_path,
            cursor,
            state,
            file: None,
            last_known_size,
        }
    }

    /// Reads up to `max_lines` complete (`\n`-terminated) lines starting at the current cursor
    /// position, handling rotation first. An incomplete trailing line is left unconsumed: the
    /// cursor stays at its start so the next call re-reads it once it is complete. A missing log
    /// file yields an empty batch, not an error (the sensor may not have started yet).
    pub fn read_batch(&mut self, max_lines: usize) -> Vec<String> {
        if max_lines == 0 {
            return Vec::new();
        }

        let mut lines = self.handle_rotation(max_lines);
        if lines.len() >= max_lines {
            self.refresh_last_known_size();
            return lines;
        }

        let Ok(mut file) = File::open(&self.log_path) else {
            // Missing (or otherwise unopenable) log file: nothing more to read this round.
            return lines;
        };

        let remaining = max_lines - lines.len();
        if let Ok((new_lines, consumed)) = read_lines_from(&mut file, self.state.offset, remaining)
        {
            self.advance(consumed as usize);
            lines.extend(new_lines);
        }
        self.file = Some(file);
        self.refresh_last_known_size();
        lines
    }

    /// Manually advances the cursor's read position by `bytes`, independent of any particular
    /// `read_batch` call. `read_batch` itself uses this for the lines it consumes; exposed
    /// publicly for a caller that needs finer-grained control (e.g. skipping a line without
    /// going through a batch read).
    pub fn advance(&mut self, bytes: usize) {
        self.state.offset += bytes as u64;
    }

    /// Persists the current cursor state via `DurableCursor::save`.
    pub fn persist_cursor(&self) -> io::Result<()> {
        self.cursor.save(&self.state)
    }

    fn refresh_last_known_size(&mut self) {
        if let Ok(metadata) = std::fs::metadata(&self.log_path) {
            self.last_known_size = metadata.len();
        }
    }

    /// Checks for rotation and reacts before the batch read proper. Returns lines drained from a
    /// displaced old inode (`InodeChanged` only); empty in every other case.
    fn handle_rotation(&mut self, max_lines: usize) -> Vec<String> {
        match self.cursor.detect_rotation(&self.state) {
            RotationEvent::None => Vec::new(),
            RotationEvent::Truncated => {
                self.reset_to_current_file();
                Vec::new()
            }
            RotationEvent::Replaced => {
                if self.maybe_false_positive_replaced() {
                    // Ordinary growth of a still-small file, not a real replacement (see
                    // `maybe_false_positive_replaced`): re-stamp and keep reading from the same
                    // offset rather than discarding it.
                    self.state.fingerprint = compute_fingerprint(&self.log_path);
                } else {
                    self.reset_to_current_file();
                }
                Vec::new()
            }
            RotationEvent::InodeChanged => {
                let drained = self
                    .file
                    .take()
                    .and_then(|mut old_file| {
                        read_lines_from(&mut old_file, self.state.offset, max_lines).ok()
                    })
                    .map(|(drained_lines, _consumed)| drained_lines)
                    .unwrap_or_default();
                self.state.inode = get_inode(&self.log_path);
                self.reset_to_current_file();
                drained
            }
        }
    }

    /// Resets the offset to 0 and recomputes the fingerprint against the log file's current
    /// content; the stale file handle (if any) is dropped since it no longer corresponds to
    /// where we're about to read.
    fn reset_to_current_file(&mut self) {
        self.state.offset = 0;
        self.state.fingerprint = compute_fingerprint(&self.log_path);
        self.file = None;
    }

    /// `compute_fingerprint` hashes `min(256, current_size)` bytes: for a file that has never
    /// reached 256 bytes, every append changes that window and therefore the hash, even though
    /// nothing was replaced. Distinguishes that from a genuine in-place swap by checking whether
    /// the file only grew since we last looked while still under the stable-window threshold -
    /// growth alone cannot explain a mismatch once the window has stabilized at exactly 256
    /// bytes on both sides, so a mismatch there is trusted as a real replacement.
    fn maybe_false_positive_replaced(&self) -> bool {
        self.last_known_size < FINGERPRINT_STABLE_SIZE
            && std::fs::metadata(&self.log_path)
                .map(|m| m.len() > self.last_known_size)
                .unwrap_or(false)
    }
}

/// Reads up to `max_lines` complete (`\n`-terminated) lines from `file`, starting at
/// `start_offset`. Returns the lines and the number of bytes actually consumed (the sum of each
/// accepted line's length including its trailing `\n`). An incomplete trailing line - EOF reached
/// without a `\n` - is left unconsumed: `consumed` stops short of it so the next read starts at
/// its beginning again.
fn read_lines_from(
    file: &mut File,
    start_offset: u64,
    max_lines: usize,
) -> io::Result<(Vec<String>, u64)> {
    file.seek(SeekFrom::Start(start_offset))?;
    let mut reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut consumed: u64 = 0;

    while lines.len() < max_lines {
        let mut buf = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut buf)?;
        if bytes_read == 0 || buf.last() != Some(&b'\n') {
            break; // EOF, or an incomplete trailing line - neither is consumed.
        }
        consumed += bytes_read as u64;
        buf.pop(); // drop the trailing '\n'
        // Lossy rather than a hard error: a corrupt line should not crash the tailer. The
        // converter (Task 1) applies the real, fail-closed NDJSON validation downstream.
        lines.push(String::from_utf8_lossy(&buf).into_owned());
    }

    Ok((lines, consumed))
}
