//! Durable per-collector verification state: the last accepted sequence number and rolling
//! batch hash, persisted so `verify::GatewaySink` can resume the seq/hash chain across
//! restarts without re-trusting whatever a reconnecting collector claims.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use collector_wire::hash::ZERO_HASH;
use serde::{Deserialize, Serialize};

/// The last accepted sequence number and rolling batch hash for one collector, persisted as
/// JSON at `<dir>/<collector_id>.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorState {
    pub last_seq: u64,
    pub last_batch_hash: [u8; 32],
}

impl CollectorState {
    /// The state of a collector the gateway has never seen: no batches accepted yet, so the
    /// first accepted seq must be 1 with `prev_batch_hash == ZERO_HASH`.
    pub fn fresh() -> Self {
        Self {
            last_seq: 0,
            last_batch_hash: ZERO_HASH,
        }
    }

    /// Loads the persisted state for `collector_id` from `dir`, or `Ok(None)` if no state file
    /// exists yet (this collector's first-ever batch) or its content isn't valid JSON for
    /// `CollectorState` - both fold to "no usable state" so callers fail closed to `fresh()`
    /// rather than branching on which happened. Fails closed on an unsafe `collector_id`
    /// before any filesystem access (see [`safe_state_file_path`]).
    pub fn load(dir: &Path, collector_id: &str) -> io::Result<Option<Self>> {
        let path = safe_state_file_path(dir, collector_id)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }

    /// Persists this state atomically for `collector_id` under `dir`: write JSON to a temp
    /// file, fsync it, rename over the final path (atomic on POSIX filesystems, so a reader -
    /// including this process reloading after a crash mid-write - always sees either the
    /// complete previous state or the complete new one), then fsync the containing directory
    /// so the rename's directory-entry update is itself durable. Fails closed on an unsafe
    /// `collector_id` before any filesystem access.
    pub fn store(&self, dir: &Path, collector_id: &str) -> io::Result<()> {
        let final_path = safe_state_file_path(dir, collector_id)?;
        std::fs::create_dir_all(dir)?;

        let tmp_path = dir.join(format!("{collector_id}.tmp"));
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

/// Validates `collector_id` as a safe single path component and returns the state file path
/// `<dir>/<collector_id>.json`. The id is a verified certificate CommonName (see
/// `gateway::server`), but it is still validated fail-closed before it is ever used to open a
/// file: rejects empty, `.`, `..`, an embedded path separator, or a control character, any of
/// which could otherwise escape `dir` or misbehave as a filename.
fn safe_state_file_path(dir: &Path, collector_id: &str) -> io::Result<PathBuf> {
    if !is_safe_path_component(collector_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe collector id: {collector_id:?}"),
        ));
    }
    Ok(dir.join(format!("{collector_id}.json")))
}

pub(crate) fn is_safe_path_component(id: &str) -> bool {
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
        let state = CollectorState {
            last_seq: 5,
            last_batch_hash: [7u8; 32],
        };
        state.store(dir.path(), "c1").expect("store");
        let loaded = CollectorState::load(dir.path(), "c1")
            .expect("load")
            .expect("present");
        assert_eq!(loaded, state);
    }

    #[test]
    fn a_missing_state_file_is_none_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            CollectorState::load(dir.path(), "never-seen").expect("load"),
            None
        );
    }

    #[test]
    fn unsafe_collector_ids_are_rejected_before_touching_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fresh = CollectorState::fresh();
        for bad_id in ["a/b", "..", ".", "c1\u{0000}bad", "", "a\\b"] {
            assert!(
                CollectorState::load(dir.path(), bad_id).is_err(),
                "load should reject {bad_id:?}"
            );
            assert!(
                fresh.store(dir.path(), bad_id).is_err(),
                "store should reject {bad_id:?}"
            );
        }
        // Rejection must happen before any file is created.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(entries.is_empty());
    }
}
