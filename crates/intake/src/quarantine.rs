//! The quarantine store: where a log line the database will never accept is set aside so intake
//! can move past it. One append-only JSON-lines file per sensor label under one directory.
//!
//! The runner moves its cursor past a line only after [`Quarantine::append`] has returned, which is
//! after the record is fsynced. A failure here (full disk, bad permissions, a cap reached) is
//! returned, never swallowed, and the runner then stays on the line: a line is skipped only if it
//! is on disk somewhere an operator can find it.
//!
//! Bounded on purpose: a sensor emitting nothing but refused lines would otherwise fill the volume
//! the ledger lives on. At the cap new lines are not quarantined, intake stays wedged on the next
//! one, and the stall alert says why.

use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};

/// Total size of every quarantine file in the directory past which no further line is quarantined.
pub const MAX_QUARANTINE_BYTES: u64 = 64 * 1024 * 1024;

/// Total records across the directory past which no further line is quarantined.
pub const MAX_QUARANTINE_RECORDS: u64 = 10_000;

/// Characters of the database's error text a record keeps. Postgres can quote a fragment of the
/// offending value in its message, so the text is capped as well as flattened.
const MAX_ERROR_CHARS: usize = 512;

/// A line to set aside, as the runner knows it.
#[derive(Debug, Clone, Copy)]
pub struct QuarantinedLine<'a> {
    /// The `PROPOLIS_SENSOR_LOGS` label; also names the file.
    pub sensor: &'a str,
    /// The log the line was read from.
    pub log_path: &'a Path,
    /// Byte offset of the line's first byte in the file it was read from.
    pub byte_offset: u64,
    pub sqlstate: Option<&'a str>,
    /// The database's error text; sanitised and capped here.
    pub error: &'a str,
    /// The line's exact bytes, newline excluded.
    pub raw: &'a [u8],
}

/// Why a line could not be set aside. Either way the runner stays on the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineError {
    /// A cap is reached; stated with the numbers so the alert is self-explanatory.
    Full(String),
    /// The directory or file could not be created, written or synced.
    Io(String),
}

impl fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuarantineError::Full(why) => write!(f, "quarantine is full: {why}"),
            QuarantineError::Io(why) => write!(f, "quarantine write failed: {why}"),
        }
    }
}

impl std::error::Error for QuarantineError {}

/// The quarantine directory and its caps.
#[derive(Debug, Clone)]
pub struct Quarantine {
    dir: PathBuf,
    max_bytes: u64,
    max_records: u64,
}

impl Quarantine {
    /// A store at `dir` with the production caps ([`MAX_QUARANTINE_BYTES`],
    /// [`MAX_QUARANTINE_RECORDS`]). The directory is created, mode 0750, on first use.
    pub fn new(dir: PathBuf) -> Self {
        Self::with_limits(dir, MAX_QUARANTINE_BYTES, MAX_QUARANTINE_RECORDS)
    }

    /// A store with explicit caps; production code uses [`Self::new`].
    pub fn with_limits(dir: PathBuf, max_bytes: u64, max_records: u64) -> Self {
        Self {
            dir,
            max_bytes,
            max_records,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file `sensor`'s lines go to. The label is operator-chosen, so anything outside
    /// `[A-Za-z0-9_-]` becomes `_` and the name cannot leave the directory or start with a dot.
    pub fn file_for(&self, sensor: &str) -> PathBuf {
        let name: String = sensor
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let name = if name.is_empty() {
            "_".to_string()
        } else {
            name
        };
        self.dir.join(format!("{name}.jsonl"))
    }

    /// Appends one record for `line` and fsyncs it (and the directory entry) before returning.
    /// Returns the file written. Refuses, writing nothing, when a cap would be exceeded.
    pub fn append(&self, line: &QuarantinedLine<'_>) -> Result<PathBuf, QuarantineError> {
        let record = render_record(line);
        self.ensure_dir()?;
        self.check_caps(record.len() as u64)?;

        let path = self.file_for(line.sensor);
        let io = |what: &str, e: std::io::Error| {
            QuarantineError::Io(format!("{what} {}: {e}", path.display()))
        };
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o640)
            .open(&path)
            .map_err(|e| io("open", e))?;

        // A crash mid-append leaves a record without its newline; starting a new one on the same
        // line would corrupt both.
        let mut buf = Vec::with_capacity(record.len() + 1);
        if ends_mid_record(&mut file).map_err(|e| io("read", e))? {
            buf.push(b'\n');
        }
        buf.extend_from_slice(record.as_bytes());

        file.write_all(&buf).map_err(|e| io("write", e))?;
        file.sync_all().map_err(|e| io("sync", e))?;
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| io("sync directory of", e))?;
        Ok(path)
    }

    fn ensure_dir(&self) -> Result<(), QuarantineError> {
        if self.dir.is_dir() {
            return Ok(());
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(&self.dir)
            .map_err(|e| {
                QuarantineError::Io(format!("create directory {}: {e}", self.dir.display()))
            })
    }

    /// Refuses when adding `incoming` bytes and one record would pass either cap. The byte total
    /// comes from file metadata alone; the records are counted by reading only if that passes, so
    /// a store full by bytes costs no read on every poll of a wedged line.
    fn check_caps(&self, incoming: u64) -> Result<(), QuarantineError> {
        let files = self.record_files()?;
        let mut bytes = 0u64;
        for path in &files {
            bytes += std::fs::metadata(path)
                .map_err(|e| QuarantineError::Io(format!("stat {}: {e}", path.display())))?
                .len();
        }
        if bytes.saturating_add(incoming) > self.max_bytes {
            return Err(QuarantineError::Full(format!(
                "{bytes} of {} bytes used in {}",
                self.max_bytes,
                self.dir.display()
            )));
        }
        let mut records = 0u64;
        for path in &files {
            records += count_newlines(path)
                .map_err(|e| QuarantineError::Io(format!("read {}: {e}", path.display())))?;
        }
        if records >= self.max_records {
            return Err(QuarantineError::Full(format!(
                "{records} of {} records in {}",
                self.max_records,
                self.dir.display()
            )));
        }
        Ok(())
    }

    fn record_files(&self) -> Result<Vec<PathBuf>, QuarantineError> {
        let entries = std::fs::read_dir(&self.dir).map_err(|e| {
            QuarantineError::Io(format!("list directory {}: {e}", self.dir.display()))
        })?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                QuarantineError::Io(format!("list directory {}: {e}", self.dir.display()))
            })?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl") && path.is_file() {
                files.push(path);
            }
        }
        Ok(files)
    }
}

/// Whether `file` is non-empty and does not end in a newline.
fn ends_mid_record(file: &mut File) -> std::io::Result<bool> {
    if file.metadata()?.len() == 0 {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] != b'\n')
}

fn count_newlines(path: &Path) -> std::io::Result<u64> {
    let mut reader = BufReader::with_capacity(64 * 1024, File::open(path)?);
    let mut chunk = [0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(count);
        }
        count += chunk[..n].iter().filter(|&&b| b == b'\n').count() as u64;
    }
}

/// One record as a single line of JSON, newline-terminated.
fn render_record(line: &QuarantinedLine<'_>) -> String {
    let cap = log_tailer::MAX_LINE_BYTES as usize;
    let kept = &line.raw[..line.raw.len().min(cap)];
    let (encoding, text) = match std::str::from_utf8(kept) {
        Ok(s) => ("utf8", s.to_string()),
        Err(_) => ("base64", base64(kept)),
    };
    let record = serde_json::json!({
        "quarantined_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "sensor": line.sensor,
        "log_path": line.log_path.to_string_lossy(),
        "byte_offset": line.byte_offset,
        "line_sha256": log_tailer::sha256_hex(line.raw),
        "sqlstate": line.sqlstate,
        "error": sanitize_error(line.error),
        "line_encoding": encoding,
        "line_truncated": line.raw.len() > cap,
        "line": text,
    });
    let mut out = record.to_string();
    out.push('\n');
    out
}

/// One line, no control characters, at most [`MAX_ERROR_CHARS`] characters.
fn sanitize_error(error: &str) -> String {
    let flat: String = error
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= MAX_ERROR_CHARS {
        return flat;
    }
    let mut cut: String = flat.chars().take(MAX_ERROR_CHARS).collect();
    cut.push_str("...");
    cut
}

/// RFC 4648 base64 with padding.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn line<'a>(raw: &'a [u8], log: &'a Path) -> QuarantinedLine<'a> {
        QuarantinedLine {
            sensor: "telnet",
            log_path: log,
            byte_offset: 4096,
            sqlstate: Some("22P05"),
            error: "unsupported Unicode escape sequence",
            raw,
        }
    }

    fn read_records(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want);
        }
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
    }

    #[test]
    fn a_label_cannot_leave_the_directory_or_hide() {
        let q = Quarantine::new(PathBuf::from("/q"));
        assert_eq!(q.file_for("cred-vnc"), PathBuf::from("/q/cred-vnc.jsonl"));
        assert_eq!(q.file_for("../etc/x"), PathBuf::from("/q/___etc_x.jsonl"));
        assert_eq!(q.file_for(".hidden"), PathBuf::from("/q/_hidden.jsonl"));
        assert_eq!(q.file_for(""), PathBuf::from("/q/_.jsonl"));
    }

    #[test]
    fn a_record_holds_the_line_its_offset_and_the_sqlstate() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("quarantine"));
        let log = Path::new("/var/log/propolis/telnet/events.jsonl");
        let path = q.append(&line(b"{\"a\":1}", log)).unwrap();
        assert_eq!(path, dir.path().join("quarantine/telnet.jsonl"));
        let records = read_records(&path);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r["sensor"], "telnet");
        assert_eq!(r["log_path"], log.to_str().unwrap());
        assert_eq!(r["byte_offset"], 4096);
        assert_eq!(r["sqlstate"], "22P05");
        assert_eq!(r["line"], "{\"a\":1}");
        assert_eq!(r["line_encoding"], "utf8");
        assert_eq!(r["line_truncated"], false);
        assert_eq!(r["line_sha256"], log_tailer::sha256_hex(b"{\"a\":1}"));
        assert!(r["quarantined_at"].as_str().unwrap().ends_with('Z'), "{r}");
    }

    #[test]
    fn a_line_that_is_not_utf8_is_kept_byte_for_byte_as_base64() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("q"));
        let raw = [b'{', 0xff, 0xfe, b'}'];
        let path = q.append(&line(&raw, Path::new("/l"))).unwrap();
        let r = &read_records(&path)[0];
        assert_eq!(r["line_encoding"], "base64");
        assert_eq!(r["line"], base64(&raw));
        assert_eq!(r["line_sha256"], log_tailer::sha256_hex(&raw));
    }

    #[test]
    fn an_over_long_line_is_cut_at_the_tailer_cap_but_hashed_whole() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("q"));
        let raw = vec![b'x'; log_tailer::MAX_LINE_BYTES as usize + 10];
        let path = q.append(&line(&raw, Path::new("/l"))).unwrap();
        let r = &read_records(&path)[0];
        assert_eq!(r["line_truncated"], true);
        assert_eq!(
            r["line"].as_str().unwrap().len(),
            log_tailer::MAX_LINE_BYTES as usize
        );
        assert_eq!(r["line_sha256"], log_tailer::sha256_hex(&raw));
    }

    #[test]
    fn the_error_text_is_one_line_and_capped() {
        let mut l = line(b"x", Path::new("/l"));
        let long = format!("bad\nvalue\t{}", "e".repeat(2000));
        l.error = &long;
        let rendered = render_record(&l);
        assert_eq!(rendered.matches('\n').count(), 1, "one record, one line");
        let r: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let error = r["error"].as_str().unwrap();
        assert!(error.starts_with("bad value "));
        assert_eq!(error.chars().count(), MAX_ERROR_CHARS + 3);
        assert!(error.ends_with("..."));
    }

    #[test]
    fn the_directory_is_0750_and_the_files_are_0640() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("a/b/quarantine"));
        let path = q.append(&line(b"x", Path::new("/l"))).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(q.dir()), 0o750);
        assert_eq!(mode(&path), 0o640);
    }

    #[test]
    fn records_append_and_a_torn_final_record_is_not_extended() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("q"));
        let path = q.append(&line(b"one", Path::new("/l"))).unwrap();
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"torn\":").unwrap();
        }
        q.append(&line(b"two", Path::new("/l"))).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], "{\"torn\":");
        assert!(serde_json::from_str::<serde_json::Value>(lines[2]).is_ok());
    }

    #[test]
    fn the_byte_cap_stops_quarantining_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let one = render_record(&line(b"x", Path::new("/l"))).len() as u64;
        let q = Quarantine::with_limits(dir.path().join("q"), one + one / 2, 1000);
        let path = q.append(&line(b"x", Path::new("/l"))).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = q.append(&line(b"x", Path::new("/l"))).unwrap_err();
        assert!(matches!(err, QuarantineError::Full(_)), "{err}");
        assert!(err.to_string().contains("bytes"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn the_record_cap_counts_every_sensors_file() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::with_limits(dir.path().join("q"), u64::MAX, 2);
        q.append(&line(b"x", Path::new("/l"))).unwrap();
        let mut other = line(b"y", Path::new("/l"));
        other.sensor = "ssh";
        q.append(&other).unwrap();
        let err = q.append(&line(b"z", Path::new("/l"))).unwrap_err();
        assert!(matches!(err, QuarantineError::Full(_)), "{err}");
        assert!(err.to_string().contains("2 of 2 records"), "{err}");
    }

    #[test]
    fn a_directory_that_cannot_be_written_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();
        let q = Quarantine::new(blocker.join("quarantine"));
        let err = q.append(&line(b"x", Path::new("/l"))).unwrap_err();
        assert!(matches!(err, QuarantineError::Io(_)), "{err}");
    }
}
