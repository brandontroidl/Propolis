//! The gateway's `SpoolWrite` implementation: appends each accepted batch's records to a
//! per-collector spool file that is byte-identical in shape to a sensor's `events.jsonl`, so
//! intake's existing `LogTailer` consumes gateway output unchanged. Records are already
//! guaranteed newline-free by `collector_wire::frame::decode_frame`, so joining them with `\n`
//! reconstitutes exact sensor NDJSON.
//!
//! Append discipline mirrors `sensor_framework::emit::EventEmitter::append`: open with
//! `OpenOptions::create(true).append(true)`, write each line, then `flush` - no fsync, matching
//! the at-least-once boundary intake's tailer already tolerates on the sensor side. Unlike
//! `EventEmitter`, this is synchronous std I/O (the `SpoolWrite` trait it implements is a
//! blocking call), not `tokio::fs`.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::state::is_safe_path_component;
use crate::verify::SpoolWrite;

/// Appends accepted records under `<root>/<collector_id>/events.jsonl`.
pub struct SpoolWriter {
    pub root: PathBuf,
}

impl SpoolWriter {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl SpoolWrite for SpoolWriter {
    fn write_records(&self, collector_id: &str, records: &[Vec<u8>]) -> io::Result<()> {
        let dir = safe_collector_dir(&self.root, collector_id)?;
        std::fs::create_dir_all(&dir)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.jsonl"))?;
        for record in records {
            file.write_all(record)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        Ok(())
    }
}

/// Validates `collector_id` as a safe single path component (the same fail-closed rule
/// `state.rs` applies to its state file names) and returns `<root>/<collector_id>` - never
/// touching the filesystem for an unsafe id, so no directory or file is created for one.
fn safe_collector_dir(root: &Path, collector_id: &str) -> io::Result<PathBuf> {
    if !is_safe_path_component(collector_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe collector id: {collector_id:?}"),
        ));
    }
    Ok(root.join(collector_id))
}
