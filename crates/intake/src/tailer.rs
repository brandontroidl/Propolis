//! Log tailer: reads complete NDJSON lines from a sensor's log file, tracking position via
//! `DurableCursor` across polls, process restarts, and log rotation. See "The runner" and "The
//! durable log cursor" in `internal/design/03-event-intake-aggregation.md`.

use std::collections::VecDeque;
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
    /// calls so that when the path is rotated out from under us (rotation by rename), this handle
    /// is moved to `pending_drains` and the old inode's remaining bytes are drained through it -
    /// POSIX keeps an inode's data readable via an already-open fd even after the directory entry
    /// is renamed or unlinked. `None` means we have no such handle (fresh instance, or it was just
    /// handed to `pending_drains`).
    file: Option<File>,
    /// Inodes that were rotated out from under us (by rename) and are still being drained through
    /// their held-open descriptors, oldest-first, each with our read offset into it. They are
    /// drained to exhaustion BEFORE the current file, so a backlog larger than one batch is not
    /// lost across a rotation. Not persisted: a crash mid-drain loses the in-flight tail (the inode
    /// is reachable only via the open fd, which the crash closes) - the same bounded loss the
    /// at-least-once model already tolerates, and far narrower than the old always-lose-past-one-
    /// batch behavior.
    pending_drains: VecDeque<(File, u64)>,
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
            pending_drains: VecDeque::new(),
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

        self.handle_rotation();

        // 1. Drain any inodes rotated out from under us, oldest-first and to exhaustion, BEFORE the
        //    current file - otherwise a backlog larger than one batch is lost across a rotation.
        let mut lines = Vec::new();
        while lines.len() < max_lines {
            let want = max_lines - lines.len();
            let exhausted = match self.pending_drains.front_mut() {
                None => break,
                Some((old_file, old_offset)) => {
                    match read_lines_from(old_file, *old_offset, want) {
                        Ok((drained, consumed)) => {
                            *old_offset += consumed;
                            let got = drained.len();
                            lines.extend(drained);
                            got < want // fewer than requested => this old inode has no more lines
                        }
                        // Unreadable old handle: abandon it (its data is unrecoverable regardless).
                        Err(_) => true,
                    }
                }
            };
            if exhausted {
                self.pending_drains.pop_front();
            }
        }
        if lines.len() >= max_lines {
            self.refresh_last_known_size();
            return lines;
        }

        // 2. Read the current inode for the remainder.
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

    /// Checks for rotation and reacts before the batch read proper. On a rename-based rotation the
    /// displaced inode's still-open handle is moved to `pending_drains`, which `read_batch` then
    /// drains to exhaustion before the new file.
    fn handle_rotation(&mut self) {
        match self.cursor.detect_rotation(&self.state) {
            RotationEvent::None => {}
            RotationEvent::Truncated => self.reset_to_current_file(),
            RotationEvent::Replaced => {
                if self.maybe_false_positive_replaced() {
                    // Ordinary growth of a still-small file, not a real replacement (see
                    // `maybe_false_positive_replaced`): re-stamp and keep reading from the same
                    // offset rather than discarding it.
                    self.state.fingerprint = compute_fingerprint(&self.log_path);
                } else {
                    self.reset_to_current_file();
                }
            }
            RotationEvent::InodeChanged => {
                // Preserve the rotated-out inode (with our read position) so read_batch drains its
                // full backlog before the new file, then point the cursor at the new inode.
                if let Some(old_file) = self.file.take() {
                    self.pending_drains.push_back((old_file, self.state.offset));
                }
                self.state.inode = get_inode(&self.log_path);
                self.reset_to_current_file();
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
