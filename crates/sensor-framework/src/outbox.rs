//! Durable per-capture outbox manifest (SP-B-1b). When a body is captured, exactly one manifest
//! row is written fsync-durable here, recording which collector produced which capture_id +
//! occurrence_id + sha256 + size, and the three custody states - all `pending` at creation. The
//! three-stage custody protocol (SP-B-2/SP-B-3) transitions the states and authorizes deletion;
//! this module only makes the record exist. One JSON file per capture at `<dir>/<capture_id>.json`,
//! using the same atomic-write discipline as `shipper::state::ConfirmedState`: write tmp -> fsync
//! file -> rename -> fsync dir.

use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Durability of one channel's copy of a captured body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyState {
    Pending,
    Durable,
}

/// Whether the full three-stage custody handshake has completed (only then may the collector
/// delete its only copy of the body). SP-B-1b always writes `Pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyDisposition {
    Pending,
    Complete,
}

/// One durable custody record for one captured body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRow {
    pub collector_id: String,
    pub capture_id: Uuid,
    pub occurrence_id: Uuid,
    pub sha256: String,   // lowercase hex; equals body_key (the on-disk file name)
    pub size: u64,
    pub body_key: String, // the spool file name; today identical to sha256 hex
    pub gateway_spool_state: CustodyState,
    pub cas_state: CustodyState,
    pub custody_state: CustodyDisposition,
}

/// Writes/reads per-capture manifest files under one directory.
pub struct OutboxManifest {
    dir: PathBuf,
}

impl OutboxManifest {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Persist `row` atomically and durably, keyed by its `capture_id`. Fails closed on an unsafe
    /// capture id before any filesystem access.
    pub fn write(&self, row: &ManifestRow) -> io::Result<()> {
        let key = row.capture_id.to_string();
        let final_path = self.safe_path(&key)?;
        std::fs::create_dir_all(&self.dir)?;

        let tmp_path = self.dir.join(format!("{key}.tmp"));
        let json = serde_json::to_vec(row).map_err(io::Error::other)?;

        let mut tmp = File::create(&tmp_path)?;
        tmp.write_all(&json)?;
        tmp.sync_all()?;
        drop(tmp);

        std::fs::rename(&tmp_path, &final_path)?;

        let dir_handle = File::open(&self.dir)?;
        dir_handle.sync_all()?;
        Ok(())
    }

    pub fn load(&self, capture_id: Uuid) -> io::Result<Option<ManifestRow>> {
        let path = self.safe_path(&capture_id.to_string())?;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }

    fn safe_path(&self, key: &str) -> io::Result<PathBuf> {
        if !is_safe_path_component(key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsafe capture id: {key:?}"),
            ));
        }
        Ok(self.dir.join(format!("{key}.json")))
    }
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

    fn row(cid: uuid::Uuid, oid: uuid::Uuid) -> ManifestRow {
        ManifestRow {
            collector_id: "collector-1".into(),
            capture_id: cid,
            occurrence_id: oid,
            sha256: "a".repeat(64),
            size: 42,
            body_key: "a".repeat(64),
            gateway_spool_state: CustodyState::Pending,
            cas_state: CustodyState::Pending,
            custody_state: CustodyDisposition::Pending,
        }
    }

    #[test]
    fn write_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let m = OutboxManifest::new(dir.path().to_path_buf());
        let cid = uuid::Uuid::now_v7();
        let oid = uuid::Uuid::now_v7();
        let r = row(cid, oid);
        m.write(&r).unwrap();
        let back = m.load(cid).unwrap().expect("present");
        assert_eq!(back, r);
    }

    #[test]
    fn a_missing_capture_is_none_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let m = OutboxManifest::new(dir.path().to_path_buf());
        assert!(m.load(uuid::Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn new_rows_are_pending() {
        let r = row(uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
        assert_eq!(r.gateway_spool_state, CustodyState::Pending);
        assert_eq!(r.cas_state, CustodyState::Pending);
        assert_eq!(r.custody_state, CustodyDisposition::Pending);
    }

    #[test]
    fn write_leaves_no_temp_file_behind() {
        // Proves the tmp -> rename discipline completes (no <capture>.tmp left in the dir).
        let dir = tempfile::tempdir().unwrap();
        let m = OutboxManifest::new(dir.path().to_path_buf());
        let cid = uuid::Uuid::now_v7();
        m.write(&row(cid, uuid::Uuid::now_v7())).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "tmp").unwrap_or(false))
            .collect();
        assert!(leftovers.is_empty(), "no .tmp file may survive a successful write");
    }
}
