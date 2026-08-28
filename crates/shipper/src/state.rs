//! Durable confirmed-ack state: the last CONFIRMED sequence number and rolling batch hash the
//! gateway has acked `Accepted` or `Duplicate`, persisted per shipping key so a restarted ship
//! cycle resumes from the last confirmed point rather than re-deriving it from the tailer cursor
//! alone. `key` is caller-chosen (Task 12 keys it `<collector_id>-<sensor>` so one collector's
//! several sensor logs each get an independent confirmed-seq chain); this module has no opinion
//! on its shape beyond "safe single path component". Same atomic-write discipline as
//! `gateway::state::CollectorState`: write to a temp file, fsync it, rename over the final path
//! (atomic on POSIX), then fsync the containing directory so the rename's own directory-entry
//! update is durable too.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use collector_wire::hash::ZERO_HASH;
use serde::{Deserialize, Serialize};

/// The last CONFIRMED sequence number and rolling batch hash for one shipping key, persisted as
/// JSON at `<dir>/<key>.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedState {
    pub last_seq: u64,
    pub last_batch_hash: [u8; 32],
}

impl ConfirmedState {
    /// The state of a key the shipper has never confirmed anything for: no batches accepted
    /// yet, so the first batch built against this state must be `seq = 1` with
    /// `prev_batch_hash == ZERO_HASH`, matching `gateway::state::CollectorState::fresh`'s
    /// symmetric starting point on the gateway side.
    pub fn fresh() -> Self {
        Self {
            last_seq: 0,
            last_batch_hash: ZERO_HASH,
        }
    }

    /// Loads the persisted state for `key` from `dir`, or `Ok(None)` if no state file exists yet
    /// (this key's first-ever confirmed batch) or its content isn't valid JSON for
    /// `ConfirmedState` - both fold to "no usable state" so callers fail closed to `fresh()`
    /// rather than branching on which happened. Fails closed on an unsafe `key` before any
    /// filesystem access.
    pub fn load(dir: &Path, key: &str) -> io::Result<Option<Self>> {
        let path = safe_state_file_path(dir, key)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }

    /// `load` folded to `fresh()` on any missing/unreadable/corrupt state - the caller-facing
    /// convenience `ship_cycle` uses at the top of every cycle. Falling back to `fresh()` here is
    /// safe, not merely convenient: re-shipping from seq 1 is exactly the at-least-once path the
    /// gateway's idempotent `Duplicate` ack already absorbs for any seq it has already accepted.
    pub fn load_or_fresh(dir: &Path, key: &str) -> Self {
        Self::load(dir, key)
            .ok()
            .flatten()
            .unwrap_or_else(Self::fresh)
    }

    /// Persists this state atomically for `key` under `dir`. Fails closed on an unsafe `key`
    /// before any filesystem access.
    pub fn store(&self, dir: &Path, key: &str) -> io::Result<()> {
        let final_path = safe_state_file_path(dir, key)?;
        std::fs::create_dir_all(dir)?;

        let tmp_path = dir.join(format!("{key}.tmp"));
        let json = serde_json::to_vec(self).map_err(io::Error::other)?;

        let mut tmp_file = File::create(&tmp_path)?;
        tmp_file.write_all(&json)?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        std::fs::rename(&tmp_path, &final_path)?;

        let dir_handle = File::open(dir)?;
        dir_handle.sync_all()?;

        Ok(())
    }
}

/// Validates `key` as a safe single path component and returns the state file path
/// `<dir>/<key>.json`. Rejects empty, `.`, `..`, an embedded path separator, or a control
/// character, any of which could otherwise escape `dir` or misbehave as a filename.
fn safe_state_file_path(dir: &Path, key: &str) -> io::Result<PathBuf> {
    if !is_safe_path_component(key) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe state key: {key:?}"),
        ));
    }
    Ok(dir.join(format!("{key}.json")))
}

fn is_safe_path_component(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && !id.contains('/')
        && !id.contains('\\')
        && !id.chars().any(|c| c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = ConfirmedState {
            last_seq: 5,
            last_batch_hash: [7u8; 32],
        };
        state.store(dir.path(), "k1").expect("store");
        let loaded = ConfirmedState::load(dir.path(), "k1")
            .expect("load")
            .expect("present");
        assert_eq!(loaded, state);
    }

    #[test]
    fn a_missing_state_file_is_none_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            ConfirmedState::load(dir.path(), "never-seen").expect("load"),
            None
        );
    }

    #[test]
    fn load_or_fresh_falls_back_when_nothing_is_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            ConfirmedState::load_or_fresh(dir.path(), "never-seen"),
            ConfirmedState::fresh()
        );
    }

    #[test]
    fn unsafe_keys_are_rejected_before_touching_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fresh = ConfirmedState::fresh();
        for bad_key in ["a/b", "..", ".", "k1\u{0000}bad", "", "a\\b"] {
            assert!(
                ConfirmedState::load(dir.path(), bad_key).is_err(),
                "load should reject {bad_key:?}"
            );
            assert!(
                fresh.store(dir.path(), bad_key).is_err(),
                "store should reject {bad_key:?}"
            );
        }
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(entries.is_empty());
    }
}
