//! The batch in flight, kept on disk from before its first send until its acknowledgement is
//! recorded, so that every send under its sequence number is that exact batch.
//!
//! The gateway answers a batch under a sequence number it already holds with `Duplicate`, and
//! compares only the number. A shipper that lost the ack for batch N and then built batch N again
//! from whatever its tailers held next (the same log with more lines, or another log, since one
//! sequence serves every log on the collector) took that `Duplicate` as confirmation of lines the
//! gateway never stored. With this record the shipper resends the stored frame byte for byte,
//! across reconnects and restarts, so a `Duplicate` can only confirm the batch the gateway holds.
//!
//! One file, `<state dir>/<key>.pending`: a JSON header line, then the encoded frame as sent. The
//! header names the chain key, the batch's place in the chain, the log it was read from, how many
//! lines the tailer handed out for it (refused ones included), the saved read position it was
//! read from and the position reading it ended at, which is what lets the owning log move its
//! cursor past exactly those lines once the gateway confirms them (`crate::client::ship_cycle`). It is written like
//! `crate::state::ConfirmedState`: a temporary file, fsynced, renamed over the final path, then
//! the directory fsynced. That is the one extra durable write per batch; the file holds at most
//! one frame (`collector_wire::frame::MAX_FRAME_LEN`, under 16 MiB, and a few KiB for ordinary
//! lines) and is deleted once the batch is confirmed.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use collector_wire::frame::decode_frame;
use log_tailer::CursorState;
use serde::{Deserialize, Serialize};

use crate::state::{ConfirmedState, is_safe_path_component};

/// The header layout this release writes and reads. A record with any other version (written by
/// a newer release before a rollback) is treated as unreadable.
pub const RECORD_VERSION: u32 = 1;

/// Longest header line read: a real one is well under 1 KiB, so anything longer is damage.
const MAX_HEADER_LEN: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Header {
    version: u32,
    key: String,
    label: String,
    /// The log path's raw bytes, so a path that is not UTF-8 is kept exactly.
    log_path: Vec<u8>,
    seq: u64,
    prev_batch_hash: [u8; 32],
    batch_hash: [u8; 32],
    lines_read: usize,
    cursor_before: Option<CursorState>,
    cursor_after: Option<CursorState>,
    frame_len: u64,
}

/// One batch that may have reached the gateway and whose acknowledgement is not yet recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBatch {
    /// The `PROPOLIS_SHIPPER_SENSOR_LOGS` name of the log the batch was read from.
    pub label: String,
    /// That log's path, as its tailer was given it.
    pub log_path: PathBuf,
    pub seq: u64,
    pub prev_batch_hash: [u8; 32],
    pub batch_hash: [u8; 32],
    /// Lines the tailer handed out for this batch, refused and over-length ones included.
    pub lines_read: usize,
    /// The log's saved read position when the batch was read, as `LogTailer::saved_cursor`
    /// returned it.
    pub cursor_before: Option<CursorState>,
    /// What `LogTailer::cursor_to_persist` returned right after the batch was read: the position
    /// the persist confirming it writes. Reading the batch's lines again must end exactly here
    /// before the cursor is moved. The saved position alone cannot tell: while a rename-rotated
    /// file is drained over several batches it names the new file at its start before and after
    /// each of them, and lines in the new file that repeat a batch make the same hash.
    pub cursor_after: Option<CursorState>,
    /// The encoded frame exactly as sent.
    pub frame: Vec<u8>,
}

/// What [`PendingBatch::load`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one value per pass, held on the stack and never collected, so boxing saves nothing"
)]
pub enum Loaded {
    /// No batch is in flight.
    Nothing,
    Found(PendingBatch),
    /// A record is there and cannot be used, for the reason given: what it names cannot be
    /// resent.
    Unreadable(String),
}

/// Where a record stands against the confirmed state of its chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// It is the next batch of the chain and not confirmed yet: it must be sent again.
    Unconfirmed,
    /// The confirmed state already ends with it: the gateway holds it, and only moving the
    /// cursor past its lines and dropping the record are left.
    Confirmed,
    /// It belongs to no position the chain is at: left from before a reset or a rollback.
    Stale,
}

impl PendingBatch {
    /// Whether this batch was read from the log `label` at `log_path`.
    pub fn is_for(&self, label: &str, log_path: &Path) -> bool {
        self.label == label && self.log_path == log_path
    }

    pub fn standing(&self, confirmed: &ConfirmedState) -> Standing {
        if confirmed.last_seq.checked_add(1) == Some(self.seq)
            && self.prev_batch_hash == confirmed.last_batch_hash
        {
            Standing::Unconfirmed
        } else if self.seq == confirmed.last_seq && self.batch_hash == confirmed.last_batch_hash {
            Standing::Confirmed
        } else {
            Standing::Stale
        }
    }

    /// Writes the record for `key` durably, replacing any earlier one. Nothing may be sent for
    /// this batch unless this returned `Ok`.
    pub fn store(&self, dir: &Path, key: &str) -> io::Result<()> {
        let final_path = record_path(dir, key)?;
        std::fs::create_dir_all(dir)?;
        let header = Header {
            version: RECORD_VERSION,
            key: key.to_string(),
            label: self.label.clone(),
            log_path: self.log_path.as_os_str().as_bytes().to_vec(),
            seq: self.seq,
            prev_batch_hash: self.prev_batch_hash,
            batch_hash: self.batch_hash,
            lines_read: self.lines_read,
            cursor_before: self.cursor_before,
            cursor_after: self.cursor_after,
            frame_len: self.frame.len() as u64,
        };
        let json = serde_json::to_vec(&header).map_err(io::Error::other)?;

        let tmp_path = dir.join(format!("{key}.pending.tmp"));
        let written = (|| {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(&json)?;
            tmp.write_all(b"\n")?;
            tmp.write_all(&self.frame)?;
            tmp.sync_all()?;
            drop(tmp);
            std::fs::rename(&tmp_path, &final_path)?;
            File::open(dir)?.sync_all()
        })();
        if written.is_err() {
            // A half-written temporary file is never read, but it holds disk that is short.
            let _ = std::fs::remove_file(&tmp_path);
        }
        written
    }

    /// Reads the record for `key`. A read error other than a missing file is returned as is:
    /// the caller cannot tell whether a batch is in flight, so it must not send.
    pub fn load(dir: &Path, key: &str) -> io::Result<Loaded> {
        let path = record_path(dir, key)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Loaded::Nothing),
            Err(e) => return Err(e),
        };
        Ok(match parse(&bytes, key) {
            Ok(batch) => Loaded::Found(batch),
            Err(why) => Loaded::Unreadable(why),
        })
    }

    /// The log the record for `key` names, from its header alone, or `None` when there is no
    /// readable record.
    pub fn owner(dir: &Path, key: &str) -> io::Result<Option<(String, PathBuf)>> {
        let path = record_path(dir, key)?;
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut line = Vec::new();
        BufReader::new(file)
            .take(MAX_HEADER_LEN)
            .read_until(b'\n', &mut line)?;
        let header = serde_json::from_slice::<Header>(line.strip_suffix(b"\n").unwrap_or(&line));
        Ok(header
            .ok()
            .filter(|h| h.version == RECORD_VERSION && h.key == key)
            .map(|h| (h.label, path_from_bytes(h.log_path))))
    }

    /// Deletes the record for `key`; a record already gone is not an error.
    pub fn remove(dir: &Path, key: &str) -> io::Result<()> {
        match std::fs::remove_file(record_path(dir, key)?) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Moves an unreadable record out of the way to `<key>.pending.damaged`, kept for the
    /// operator. While that file exists the chain cannot prove what the gateway holds under the
    /// next sequence number (see [`Self::unreadable_set_aside`]).
    pub fn set_aside_unreadable(dir: &Path, key: &str) -> io::Result<()> {
        std::fs::rename(record_path(dir, key)?, damaged_path(dir, key)?)?;
        File::open(dir)?.sync_all()
    }

    /// Whether an unreadable record was set aside and no batch has been accepted since.
    pub fn unreadable_set_aside(dir: &Path, key: &str) -> bool {
        damaged_path(dir, key).is_ok_and(|p| p.exists())
    }

    /// Deletes the set-aside unreadable record, once a batch the gateway accepted under the
    /// next sequence number proves it never stored the batch that record described.
    pub fn clear_unreadable(dir: &Path, key: &str) -> io::Result<()> {
        match std::fs::remove_file(damaged_path(dir, key)?) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Records in `dir` that belong to a chain key other than `key`, as left by a collector id
    /// that was changed. They are never read; the caller reports them.
    pub fn foreign_records(dir: &Path, key: &str) -> Vec<PathBuf> {
        let own = format!("{key}.pending");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|ext| ext == "pending")
                    && p.file_name().is_some_and(|name| name != own.as_str())
            })
            .collect();
        found.sort();
        found
    }
}

fn record_path(dir: &Path, key: &str) -> io::Result<PathBuf> {
    checked(key)?;
    Ok(dir.join(format!("{key}.pending")))
}

fn damaged_path(dir: &Path, key: &str) -> io::Result<PathBuf> {
    checked(key)?;
    Ok(dir.join(format!("{key}.pending.damaged")))
}

fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn checked(key: &str) -> io::Result<()> {
    if is_safe_path_component(key) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe state key: {key:?}"),
        ))
    }
}

/// Parses and checks a record: its header, its version and key, and a frame that decodes and
/// is the batch the header names. The reason is for the operator.
fn parse(bytes: &[u8], key: &str) -> Result<PendingBatch, String> {
    let newline = bytes
        .iter()
        .take(MAX_HEADER_LEN as usize)
        .position(|&b| b == b'\n')
        .ok_or("it has no header line")?;
    let header: Header = serde_json::from_slice(&bytes[..newline])
        .map_err(|e| format!("its header does not parse: {e}"))?;
    if header.version != RECORD_VERSION {
        return Err(format!(
            "it has version {}, and this release reads version {RECORD_VERSION}",
            header.version
        ));
    }
    if header.key != key {
        return Err(format!(
            "it was written for the collector id {:?}",
            header.key
        ));
    }
    let frame = &bytes[newline + 1..];
    if frame.len() as u64 != header.frame_len {
        return Err(format!(
            "its frame is {} bytes and its header says {}",
            frame.len(),
            header.frame_len
        ));
    }
    let batch = decode_frame(frame).map_err(|e| format!("its frame does not decode: {e}"))?;
    if batch.seq != header.seq
        || batch.prev_batch_hash != header.prev_batch_hash
        || batch.batch_hash != header.batch_hash
    {
        return Err("its frame is not the batch its header names".to_string());
    }
    if header.lines_read < batch.records.len() {
        return Err("it counts fewer lines read than its frame carries".to_string());
    }
    Ok(PendingBatch {
        label: header.label,
        log_path: path_from_bytes(header.log_path),
        seq: header.seq,
        prev_batch_hash: header.prev_batch_hash,
        batch_hash: header.batch_hash,
        lines_read: header.lines_read,
        cursor_before: header.cursor_before,
        cursor_after: header.cursor_after,
        frame: frame.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_wire::frame::{Batch, encode_frame};
    use collector_wire::hash::ZERO_HASH;

    fn sample() -> PendingBatch {
        let batch = Batch::new(3, [9u8; 32], vec![b"one".to_vec(), b"two".to_vec()]);
        PendingBatch {
            label: "ssh".to_string(),
            log_path: PathBuf::from("/var/log/propolis/ssh/events.jsonl"),
            seq: batch.seq,
            prev_batch_hash: batch.prev_batch_hash,
            batch_hash: batch.batch_hash,
            lines_read: 3,
            cursor_before: Some(CursorState {
                inode: 7,
                offset: 40,
                fingerprint: [1u8; 32],
                fingerprint_len: Some(40),
            }),
            cursor_after: Some(CursorState {
                inode: 7,
                offset: 48,
                fingerprint: [1u8; 32],
                fingerprint_len: Some(48),
            }),
            frame: encode_frame(&batch),
        }
    }

    #[test]
    fn a_stored_record_loads_back_unchanged_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let record = sample();
        record.store(dir.path(), "c1").unwrap();
        assert_eq!(
            PendingBatch::load(dir.path(), "c1").unwrap(),
            Loaded::Found(record.clone())
        );
        assert_eq!(
            PendingBatch::owner(dir.path(), "c1").unwrap(),
            Some((record.label.clone(), record.log_path.clone()))
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["c1.pending"]);
        PendingBatch::remove(dir.path(), "c1").unwrap();
        PendingBatch::remove(dir.path(), "c1").unwrap();
        assert_eq!(
            PendingBatch::load(dir.path(), "c1").unwrap(),
            Loaded::Nothing
        );
    }

    #[test]
    fn a_damaged_record_of_another_version_or_another_key_is_unreadable_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c1.pending");
        let unreadable = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            matches!(
                PendingBatch::load(dir.path(), "c1").unwrap(),
                Loaded::Unreadable(_)
            )
        };
        assert!(unreadable(b"garbage"), "no header line");
        assert!(unreadable(b"{\"version\":1}\n"), "a header missing fields");

        sample().store(dir.path(), "c1").unwrap();
        let good = std::fs::read(&path).unwrap();
        assert!(unreadable(&good[..good.len() - 1]), "a truncated frame");
        let mut flipped = good.clone();
        let last = flipped.len() - 40;
        flipped[last] ^= 0xff;
        assert!(unreadable(&flipped), "a frame that fails its own hash");

        let text = String::from_utf8_lossy(&good).replacen("\"version\":1", "\"version\":2", 1);
        assert!(unreadable(text.as_bytes()), "an unknown version");
        sample().store(dir.path(), "c2").unwrap();
        let other = std::fs::read(dir.path().join("c2.pending")).unwrap();
        assert!(unreadable(&other), "a record written for another key");
        assert_eq!(PendingBatch::owner(dir.path(), "c1").unwrap(), None);
    }

    #[test]
    fn a_header_that_names_another_seq_prev_or_hash_than_its_frame_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let good = sample();
        let mismatched = [
            PendingBatch {
                seq: good.seq + 1,
                ..good.clone()
            },
            PendingBatch {
                prev_batch_hash: [0u8; 32],
                ..good.clone()
            },
            PendingBatch {
                batch_hash: [0u8; 32],
                ..good.clone()
            },
        ];
        for record in mismatched {
            record.store(dir.path(), "c1").unwrap();
            assert!(
                matches!(
                    PendingBatch::load(dir.path(), "c1").unwrap(),
                    Loaded::Unreadable(_)
                ),
                "{record:?}"
            );
        }
    }

    #[test]
    fn a_header_counting_fewer_lines_read_than_its_frame_carries_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        PendingBatch {
            lines_read: 1,
            ..sample()
        }
        .store(dir.path(), "c1")
        .unwrap();
        assert!(matches!(
            PendingBatch::load(dir.path(), "c1").unwrap(),
            Loaded::Unreadable(_)
        ));
        PendingBatch {
            lines_read: 2,
            ..sample()
        }
        .store(dir.path(), "c1")
        .unwrap();
        assert!(matches!(
            PendingBatch::load(dir.path(), "c1").unwrap(),
            Loaded::Found(_)
        ));
    }

    #[test]
    fn a_record_stands_unconfirmed_confirmed_or_stale_against_the_confirmed_state() {
        let record = sample();
        let before = ConfirmedState {
            last_seq: 2,
            last_batch_hash: [9u8; 32],
        };
        assert_eq!(record.standing(&before), Standing::Unconfirmed);
        let after = ConfirmedState {
            last_seq: 3,
            last_batch_hash: record.batch_hash,
        };
        assert_eq!(record.standing(&after), Standing::Confirmed);
        assert_eq!(record.standing(&ConfirmedState::fresh()), Standing::Stale);
        let other_branch = ConfirmedState {
            last_seq: 2,
            last_batch_hash: ZERO_HASH,
        };
        assert_eq!(record.standing(&other_branch), Standing::Stale);
    }

    #[test]
    fn an_unreadable_record_set_aside_is_remembered_until_cleared() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("c1.pending"), b"garbage").unwrap();
        assert!(!PendingBatch::unreadable_set_aside(dir.path(), "c1"));
        PendingBatch::set_aside_unreadable(dir.path(), "c1").unwrap();
        assert!(PendingBatch::unreadable_set_aside(dir.path(), "c1"));
        assert_eq!(
            PendingBatch::load(dir.path(), "c1").unwrap(),
            Loaded::Nothing
        );
        PendingBatch::clear_unreadable(dir.path(), "c1").unwrap();
        assert!(!PendingBatch::unreadable_set_aside(dir.path(), "c1"));
    }

    #[test]
    fn records_of_other_chain_keys_are_listed_and_this_keys_is_not() {
        let dir = tempfile::tempdir().unwrap();
        sample().store(dir.path(), "c1").unwrap();
        sample().store(dir.path(), "old-id").unwrap();
        std::fs::write(dir.path().join("c1.json"), b"{}").unwrap();
        assert_eq!(
            PendingBatch::foreign_records(dir.path(), "c1"),
            [dir.path().join("old-id.pending")]
        );
    }
}
