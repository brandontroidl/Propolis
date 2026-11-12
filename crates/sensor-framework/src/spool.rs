//! Quarantine spool: stores a captured file body under an isolated directory, named by its
//! SHA-256 rather than any attacker-supplied name, size-bounded per file and by a global byte
//! budget. See "Sample side channel" in `internal/design/02-sensor-framework.md` for the four
//! load-bearing properties this implements: SHA-256 naming (never the attacker's filename, which
//! makes path traversal structurally impossible rather than a validation problem), no-execute
//! permissions (0640), re-hash-on-read with fail-closed on mismatch, and a store-wide byte budget
//! rather than only a per-transfer cap. The `noexec,nosuid,nodev` mount option and dedicated
//! spool-user ownership are deployment-level properties (the service unit, a later task); this
//! module owns only the naming, sizing, and budget logic.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sensor_wire::SampleRef;
use sha2::{Digest, Sha256};

use crate::sanitize::to_hex_bounded;

/// A SHA-256 digest is always exactly this many bytes.
const SHA256_DIGEST_LEN: usize = 32;

/// Subdirectory of the spool where a body is written before it is given its digest name. Not a
/// digest name, and not a regular file, so readers and the budget scan both pass over it.
const STAGING_DIR: &str = ".staging";

/// A staged file older than this was left by a process that stopped mid-store; one that is still
/// being written is far younger, since a store writes at most one capped body.
const STALE_STAGING: std::time::Duration = std::time::Duration::from_secs(3600);

/// How `QuarantineSpool::publish` ended when it did not publish a fresh name.
enum Publish {
    /// Another store published the same digest first.
    Lost,
    /// Nothing was published.
    NotPublished(std::io::Error),
    /// The body is published under its name, but syncing the directory failed.
    NameNotSynced(std::io::Error),
}

/// The least time between two rescans of the spool directory. A rescan reads the directory to
/// find space freed by whatever removes files from it (the sensor's own retention pass, an
/// operator), and happens only when a store would otherwise be refused; the interval keeps a
/// flood of refused uploads from becoming a flood of directory scans.
const RESCAN_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// How long a sample stays in a sensor's spool before the sensor removes it. A compile-time
/// constant, not a setting: it is the documented retention policy, and the daemon's pass over the
/// malware fetcher's spool uses the same number.
pub const SAMPLE_RETENTION: Duration = Duration::from_secs(30 * 86_400);

/// How often a sensor looks for samples past [`SAMPLE_RETENTION`] (once at start, then this).
pub const SAMPLE_RETENTION_INTERVAL: Duration = Duration::from_secs(3600);

/// What one [`QuarantineSpool::prune_older_than`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneReport {
    /// Entries removed.
    pub removed: u64,
    /// Entries that were due and could not be removed (permissions, a read-only mount).
    pub failed: u64,
}

/// What the budget counts. Both fields change only under the spool's lock, which is what lets a
/// rescan replace `used` without losing a reservation made while it ran.
struct Accounting {
    /// Bytes of published files plus bytes reserved by stores still in progress, against
    /// `global_budget`. Recovered at construction from the directory's existing contents (see
    /// `scan_existing_usage`) so a restart does not reset the ceiling to zero while previously
    /// spooled files still occupy it, and again by a rescan when space was freed under it.
    used: u64,
    /// The part of `used` reserved by stores that have not yet finished. A rescan counts files on
    /// disk, which cannot include a body still being written, so it adds these back.
    in_flight: u64,
    last_rescan: Option<Instant>,
}

/// Hex-encode a digest via the crate's shared hex helper rather than `{:x}` - the `sha2`/
/// `digest` version this workspace resolves returns a `hybrid-array` `Array<u8, U32>`, which
/// does not implement `LowerHex` (verified against the crate's own source; there is no format
/// specifier that does this for us here, unlike older `generic-array`-based digest versions).
fn hex_digest(bytes: &[u8]) -> String {
    to_hex_bounded(bytes, SHA256_DIGEST_LEN)
}

#[derive(Debug)]
pub enum SpoolError {
    /// The body's byte length exceeds the operator-configured per-file cap.
    FileSizeExceeded {
        size: u64,
        limit: u64,
    },
    /// Storing `attempted` more bytes would push the spool past its global byte budget.
    BudgetExhausted {
        used: u64,
        budget: u64,
        attempted: u64,
    },
    /// A file's content no longer hashes to the name it is filed under: treated as corrupt,
    /// never passed downstream.
    HashMismatch {
        expected: String,
        actual: String,
    },
    /// `verify`'s `sha256` argument is not a well-formed SHA-256 hex digest, so it is rejected
    /// before ever being joined onto the spool directory path.
    InvalidHash {
        given: String,
    },
    /// The spool entry is a symlink, FIFO, directory or anything else that is not a regular
    /// file. Only the spool writer creates entries, and it only ever creates regular files, so
    /// anything else was planted and is refused rather than followed.
    NotRegularFile,
    Io(std::io::Error),
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpoolError::FileSizeExceeded { size, limit } => write!(
                f,
                "captured body of {size} bytes exceeds the spool's {limit}-byte file limit"
            ),
            SpoolError::BudgetExhausted {
                used,
                budget,
                attempted,
            } => write!(
                f,
                "spool budget exhausted: {used} of {budget} bytes used, {attempted} more attempted"
            ),
            SpoolError::HashMismatch { expected, actual } => write!(
                f,
                "spool file {expected} is corrupted: recomputed hash {actual} does not match"
            ),
            SpoolError::InvalidHash { given } => {
                write!(f, "not a valid sha-256 hex digest: {given:?}")
            }
            SpoolError::NotRegularFile => write!(f, "spool entry is not a regular file"),
            SpoolError::Io(e) => write!(f, "spool i/o error: {e}"),
        }
    }
}

impl SpoolError {
    /// The `not_stored_reason` an upload event carries when the spool refused its body. A closed
    /// set of short labels, so an analyst can filter on it and nothing attacker-supplied reaches
    /// the event through it.
    pub fn not_stored_reason(&self) -> &'static str {
        match self {
            SpoolError::BudgetExhausted { .. } => "spool_full",
            SpoolError::FileSizeExceeded { .. } => "file_too_large",
            SpoolError::HashMismatch { .. } | SpoolError::NotRegularFile => "spool_entry_invalid",
            SpoolError::InvalidHash { .. } | SpoolError::Io(_) => "spool_error",
        }
    }
}

impl std::error::Error for SpoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpoolError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SpoolError {
    fn from(e: std::io::Error) -> Self {
        SpoolError::Io(e)
    }
}

/// The largest body a sensor keeps (16 MiB): the SSH sensor's spool per-file cap and its capture
/// limit, and the indicator scan's size limit, so nothing a sensor keeps is then refused for size
/// by a later stage. The other spooling sensors keep at most 10 MB, under it. 16 MiB, not 10 MB:
/// a miner sent over an exec's stdin was cut at 10,000,000 on every attempt (its true size is
/// unknown, only that it exceeds 10,000,000).
pub const SPOOL_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// A directory of captured bodies, each named by its SHA-256, guarded by a per-file size cap and
/// a global byte budget shared across every call. Safe to call concurrently: `store` and `verify`
/// take `&self` because production capture hand-off shares one instance across every sensor
/// connection's task (see Task 6's plan).
pub struct QuarantineSpool {
    dir: PathBuf,
    max_file_size: u64,
    global_budget: u64,
    accounting: Mutex<Accounting>,
}

impl QuarantineSpool {
    /// The directory this spool stores into, for log lines that must say which one.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn new(dir: PathBuf, max_file_size: u64, global_budget: u64) -> Self {
        remove_stale_staging(&dir.join(STAGING_DIR));
        let used = scan_existing_usage(&dir);
        Self {
            dir,
            max_file_size,
            global_budget,
            accounting: Mutex::new(Accounting {
                used,
                in_flight: 0,
                last_rescan: None,
            }),
        }
    }

    /// Bytes the budget currently counts: published files plus stores in progress.
    #[cfg(test)]
    fn used_bytes(&self) -> u64 {
        self.accounting.lock().unwrap().used
    }

    /// Write `body` to the spool, named by its SHA-256, and return the reference an event
    /// carries. `orig_name` is always empty here: the spool has no knowledge of the
    /// attacker-supplied filename, so the caller (the SSH SCP/SFTP capture hand-off) fills it in
    /// on the returned `SampleRef` afterward - and must route it through `sanitize_value` first,
    /// same as every other attacker-controlled value entering an event.
    ///
    /// Storing a body already on disk (matching SHA-256) is a no-op beyond re-confirming the
    /// existing file's integrity: it costs no additional budget, since it costs no additional
    /// disk. Without this, a single popular sample delivered by many bots would exhaust the
    /// budget on its own despite never actually filling the disk.
    pub fn store(&self, body: &[u8]) -> Result<SampleRef, SpoolError> {
        // Minted once per call, regardless of which branch below returns: identical bytes still
        // dedup to the same sha256 (content), but each `store` call is a distinct capture
        // occurrence and gets its own id.
        let capture_id = Some(uuid::Uuid::now_v7());

        let size = body.len() as u64;
        if size > self.max_file_size {
            return Err(SpoolError::FileSizeExceeded {
                size,
                limit: self.max_file_size,
            });
        }

        let hash = hex_digest(&Sha256::digest(body));
        let file_path = self.dir.join(&hash);

        if file_path.exists() {
            // Dedup hit (this call, an earlier call, or a prior process run). Re-hash on read
            // rather than trusting the name, same discipline `verify` uses, so a corrupted
            // existing file is refused instead of silently accepted as a successful store.
            self.verify_on_disk(&hash)?;
            return Ok(SampleRef {
                sha256: hash,
                size,
                orig_name: String::new(),
                capture_id,
            });
        }

        self.reserve_budget(size)?;
        let sample = SampleRef {
            sha256: hash.clone(),
            size,
            orig_name: String::new(),
            capture_id,
        };
        match self.publish(&file_path, body) {
            Ok(()) => {
                self.finish_reservation(size);
                Ok(sample)
            }
            Err(Publish::Lost) => {
                // Another call published this exact content between the existence check above
                // and our publish. Its file is complete (a name is only ever linked to a written,
                // synced body), and it holds the budget for those bytes, so give ours back and
                // confirm what is on disk.
                self.release_budget(size);
                self.verify_on_disk(&hash)?;
                Ok(sample)
            }
            Err(Publish::NotPublished(e)) => {
                self.release_budget(size);
                Err(e.into())
            }
            // The body is on disk under its name and keeps its budget; only the name's
            // durability across a crash is unconfirmed, so the caller must not treat it as stored.
            Err(Publish::NameNotSynced(e)) => {
                self.finish_reservation(size);
                Err(e.into())
            }
        }
    }

    /// Remove the samples in this spool that were last modified more than `max_age` ago, and
    /// recount the budget from what is left. A sample is a regular file, or any other entry, named
    /// with a canonical digest directly in the spool directory: `remove_file` removes a planted
    /// link itself and never follows it, and nothing below the root (the outbox manifest, staging)
    /// or under another name is touched.
    ///
    /// A sensor prunes its own spool because it is the account that owns the directory and the
    /// files: the daemon runs under a different user with the spool read-only, and cannot.
    ///
    /// Runs under the budget lock, so a store cannot reserve against a count that is about to
    /// change, and the recount that follows cannot be undone by one that was already running.
    /// Blocking file I/O: call it from a blocking thread.
    pub fn prune_older_than(&self, max_age: Duration) -> PruneReport {
        let mut report = PruneReport::default();
        let Some(cutoff) = std::time::SystemTime::now().checked_sub(max_age) else {
            return report;
        };
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return report;
        };
        let mut acct = self.accounting.lock().unwrap();
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_str()
                .is_some_and(is_canonical_sha256_hex)
            {
                continue;
            }
            // `DirEntry::metadata` does not traverse a link, so a link is aged by its own time.
            let due = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|modified| modified < cutoff);
            if !due {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => report.removed += 1,
                // Removed by someone else between the listing and now: nothing left to do.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => report.failed += 1,
            }
        }
        if report.removed > 0 {
            acct.used = scan_existing_usage(&self.dir).saturating_add(acct.in_flight);
            acct.last_rescan = Some(Instant::now());
        }
        report
    }

    /// The reference a body would have had, without storing it: its digest and length. For a body
    /// the spool refused, so the event that records the observation can still carry the hash and
    /// size the sensor saw. `capture_id` is `None` because no capture was made.
    pub fn describe(body: &[u8]) -> SampleRef {
        SampleRef {
            sha256: hex_digest(&Sha256::digest(body)),
            size: body.len() as u64,
            orig_name: String::new(),
            capture_id: None,
        }
    }

    /// Write `body` to a staging file and give it its final name only once it is complete and
    /// synced, so a digest name never holds a partial body. Writing at the final name directly
    /// let a concurrent `store` of the same bytes (the malware fetcher runs several fetches at
    /// once) find the name while the first write was still in progress, re-hash the partial file
    /// and fail it as corrupt. The final name is created with a hard link, which, unlike a rename,
    /// never replaces an existing name; the directory is then synced so the new name is as durable
    /// as the body it names.
    fn publish(&self, file_path: &Path, body: &[u8]) -> Result<(), Publish> {
        let staging = self.dir.join(STAGING_DIR);
        std::fs::create_dir_all(&staging).map_err(Publish::NotPublished)?;
        let staged = staging.join(uuid::Uuid::now_v7().to_string());
        let linked = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .and_then(|mut file| write_and_seal(&mut file, body))
            .and_then(|()| std::fs::hard_link(&staged, file_path));
        let _ = std::fs::remove_file(&staged);
        match linked {
            Ok(()) => sync_dir(&self.dir).map_err(Publish::NameNotSynced),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Publish::Lost),
            Err(e) => Err(Publish::NotPublished(e)),
        }
    }

    /// Re-hash the file named `sha256` and fail closed if it does not match: a body whose
    /// content no longer matches the digest it is filed under is corrupt and refused, never
    /// passed downstream. `sha256` is untrusted input from the caller's perspective (this is a
    /// public library boundary), so it is validated as a well-formed hex digest before it ever
    /// reaches a path join - the same "safe by alphabet" reasoning as
    /// `sanitize::to_hex_bounded`: a hex-only string cannot express `/`, `\`, or a `..` segment,
    /// so a malformed argument can never escape `self.dir` no matter what the caller passes.
    pub fn verify(&self, sha256: &str) -> Result<(), SpoolError> {
        self.verify_on_disk(sha256)
    }

    /// Shared re-hash-on-read logic for both `verify` and `store`'s dedup path; `read_verified`
    /// does the name validation.
    fn verify_on_disk(&self, hash: &str) -> Result<(), SpoolError> {
        // No size cap here: a file stored under a larger cap by an earlier run is still a valid
        // dedup target. Streamed, not read whole: `store` still holds the charged body it was
        // given, and a second full copy of the file would sit outside every memory budget.
        verify_streamed(&self.dir, hash)
    }

    /// Check-and-reserve `size` bytes against the global budget, atomically under the lock. When
    /// the budget would be exceeded, the directory is rescanned first (at most once per
    /// `RESCAN_MIN_INTERVAL`) in case files were removed since the count was last taken, and the
    /// reservation is retried against the corrected count. The scan runs under the lock so a
    /// concurrent reservation is neither lost nor counted twice.
    fn reserve_budget(&self, size: u64) -> Result<(), SpoolError> {
        let mut acct = self.accounting.lock().unwrap();
        let fits = |used: u64| used.checked_add(size).filter(|&n| n <= self.global_budget);
        if fits(acct.used).is_none()
            && acct
                .last_rescan
                .is_none_or(|at| at.elapsed() >= RESCAN_MIN_INTERVAL)
        {
            acct.last_rescan = Some(Instant::now());
            acct.used = scan_existing_usage(&self.dir).saturating_add(acct.in_flight);
        }
        let Some(next) = fits(acct.used) else {
            return Err(SpoolError::BudgetExhausted {
                used: acct.used,
                budget: self.global_budget,
                attempted: size,
            });
        };
        acct.used = next;
        acct.in_flight += size;
        Ok(())
    }

    /// Give back a reservation that turned out not to be needed (the write failed, or another
    /// caller already published the same content). Saturating: the counter that gates a
    /// security-relevant guard must never wrap silently even if release were ever called out of
    /// balance with reserve.
    fn release_budget(&self, size: u64) {
        let mut acct = self.accounting.lock().unwrap();
        acct.used = acct.used.saturating_sub(size);
        acct.in_flight = acct.in_flight.saturating_sub(size);
    }

    /// A reservation became a file on disk: it keeps its bytes in `used` and is no longer in
    /// progress, so a rescan (which counts the file itself) must not add it again.
    fn finish_reservation(&self, size: u64) {
        let mut acct = self.accounting.lock().unwrap();
        acct.in_flight = acct.in_flight.saturating_sub(size);
    }
}

/// Open the entry filed as `sha256` in `dir` for reading: a canonical name, no symlink followed
/// (`O_NOFOLLOW`), no block on a FIFO (`O_NONBLOCK`), and a regular file by `fstat` of the opened
/// descriptor. Returns the descriptor with that metadata.
fn open_spooled(
    dir: &Path,
    sha256: &str,
) -> Result<(std::fs::File, std::fs::Metadata), SpoolError> {
    if !is_canonical_sha256_hex(sha256) {
        let given: String = sha256.chars().take(128).collect();
        return Err(SpoolError::InvalidHash { given });
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(dir.join(sha256)) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(SpoolError::NotRegularFile);
        }
        Err(e) => return Err(e.into()),
    };

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(SpoolError::NotRegularFile);
    }
    Ok((file, metadata))
}

/// Hash the body filed as `sha256` in `dir` in fixed-size chunks and fail closed if it does not
/// match its name. Same checks as `read_verified` without holding the body: a body already in
/// memory (the one being stored) must not be joined by a second full-size copy of the file.
fn verify_streamed(dir: &Path, sha256: &str) -> Result<(), SpoolError> {
    use std::io::Read;

    let (file, metadata) = open_spooled(dir, sha256)?;
    // Bounded by one byte past the fstat length, as `read_verified` is: a file still growing
    // under a writer must not turn this into an unbounded read (the extra byte changes the hash).
    let mut reader = file.take(metadata.len().saturating_add(1));
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; VERIFY_CHUNK_BYTES];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(chunk.get(..n).unwrap_or_default());
    }
    let actual = hex_digest(&hasher.finalize());
    if actual != sha256 {
        return Err(SpoolError::HashMismatch {
            expected: sha256.to_string(),
            actual,
        });
    }
    Ok(())
}

/// The read size `verify_streamed` hashes in.
const VERIFY_CHUNK_BYTES: usize = 64 * 1024;

/// Read the body filed as `sha256` in `dir`, returning it only if it is a regular file of at most
/// `max_len` bytes whose content hashes to exactly that name.
///
/// This is the one way anything outside the writing sensor may read a spooled body. The spool
/// directory is written by internet-facing sensor processes, so its contents are untrusted from
/// the reader's side: a file NAME is a claim about the content, not proof of it. So the entry is
/// opened without following a symlink (`O_NOFOLLOW`) and without blocking on a FIFO
/// (`O_NONBLOCK`), must be a regular file by `fstat` of the opened descriptor, and is read from
/// that descriptor - never re-opened by path - so what is hashed is exactly what is returned.
/// `sha256` must be the canonical lowercase form the writer produces; an uppercase spelling
/// names no file the writer could have created.
pub fn read_verified(dir: &Path, sha256: &str, max_len: u64) -> Result<Vec<u8>, SpoolError> {
    use std::io::Read;

    let (file, metadata) = open_spooled(dir, sha256)?;
    if metadata.len() > max_len {
        return Err(SpoolError::FileSizeExceeded {
            size: metadata.len(),
            limit: max_len,
        });
    }

    // Bounded by `max_len + 1` rather than trusting the fstat length: a file still growing under
    // a writer must not turn this into an unbounded read.
    let mut body = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.len() as u64 > max_len {
        return Err(SpoolError::FileSizeExceeded {
            size: body.len() as u64,
            limit: max_len,
        });
    }

    let actual = hex_digest(&Sha256::digest(&body));
    if actual != sha256 {
        return Err(SpoolError::HashMismatch {
            expected: sha256.to_string(),
            actual,
        });
    }
    Ok(body)
}

/// Whether `name` is the exact form the spool writer names a body: 64 lowercase hex characters.
/// Readers use this to decide what counts as a sample; anything else in a spool directory (a
/// staging file, the `outbox/` directory, a planted name) is not one. The alphabet also
/// structurally excludes `/`, `\` and `.`, which is what makes joining a checked name onto the
/// spool directory traversal-safe without a traversal-specific check.
pub fn is_canonical_sha256_hex(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sync `dir` itself, so a name just linked into it survives a crash along with the body.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Delete staged files a stopped process left behind. They carry no digest name, so nothing
/// reads them, and they sit outside the budget scan, so without this they would take disk space
/// the budget never sees. Best-effort, like `scan_existing_usage`.
fn remove_stale_staging(staging: &Path) {
    let Ok(entries) = std::fs::read_dir(staging) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|at| at.elapsed().is_ok_and(|age| age > STALE_STAGING));
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Write the body to a freshly created, empty staging file and lock down its permissions.
/// `create_new` on the caller's side already guarantees this file did not exist a moment ago, so
/// there is nothing to dedup here - only the write and the permission bits.
fn write_and_seal(file: &mut std::fs::File, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    file.write_all(body)?;
    // Durable before the outbox manifest (SP-B-1b) is ever allowed to claim this body exists:
    // the manifest's ordering guarantee (handoff.rs's process_job doc) depends on the body being
    // on disk by the time the manifest row is written, not merely handed to the OS write buffer.
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    }
    Ok(())
}

/// Sum the size of every regular file already in `dir`, so a restart recovers accurate budget
/// accounting for spool contents a prior run already wrote, rather than starting `used` at zero
/// while the disk already holds bytes against the same budget. Best-effort: an unreadable
/// directory, or an entry that vanishes mid-scan (external cleanup, a race with another writer),
/// is skipped rather than failing construction - `store` still fails closed on the real write if
/// the directory itself is not writable.
fn scan_existing_usage(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .map(|metadata| metadata.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn test_spool(max_file: u64, budget: u64) -> (tempfile::TempDir, QuarantineSpool) {
        let dir = tempfile::tempdir().unwrap();
        let spool = QuarantineSpool::new(dir.path().to_path_buf(), max_file, budget);
        (dir, spool)
    }

    #[test]
    fn store_and_verify_round_trip() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let body = b"this is malware content";
        let sample = spool.store(body).unwrap();
        assert_eq!(sample.size, body.len() as u64);
        assert!(!sample.sha256.is_empty());
        spool.verify(&sample.sha256).unwrap();
    }

    #[test]
    fn sha256_naming() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let body = b"test body";
        let sample = spool.store(body).unwrap();
        // Verify the file is named by its SHA-256.
        use sha2::{Digest, Sha256};
        let expected = hex_digest(&Sha256::digest(body));
        assert_eq!(sample.sha256, expected);
    }

    #[test]
    fn duplicate_body_is_idempotent() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let body = b"same body twice";
        let s1 = spool.store(body).unwrap();
        let s2 = spool.store(body).unwrap();
        assert_eq!(s1.sha256, s2.sha256);
    }

    #[test]
    fn size_limit_enforced() {
        let (_dir, spool) = test_spool(10, 1_000_000);
        let body = b"this body exceeds the ten byte limit";
        let result = spool.store(body);
        assert!(matches!(result, Err(SpoolError::FileSizeExceeded { .. })));
    }

    #[test]
    fn global_budget_enforced() {
        let (_dir, spool) = test_spool(100, 150);
        let body1 = vec![0u8; 100];
        spool.store(&body1).unwrap();
        let body2 = vec![1u8; 100];
        let result = spool.store(&body2);
        assert!(matches!(result, Err(SpoolError::BudgetExhausted { .. })));
    }

    #[test]
    fn verify_fails_on_corrupted_body() {
        let (dir, spool) = test_spool(1024, 1_000_000);
        let body = b"original content";
        let sample = spool.store(body).unwrap();
        // Corrupt the file on disk.
        let file_path = dir.path().join(&sample.sha256);
        std::fs::write(&file_path, b"corrupted").unwrap();
        let result = spool.verify(&sample.sha256);
        assert!(matches!(result, Err(SpoolError::HashMismatch { .. })));
    }

    #[test]
    fn verify_fails_on_missing_file() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let result = spool.verify("nonexistent_hash");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, spool) = test_spool(1024, 1_000_000);
        let sample = spool.store(b"test body").unwrap();
        let file_path = dir.path().join(&sample.sha256);
        let perms = std::fs::metadata(&file_path).unwrap().permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(mode, 0o640, "spool file must be 0640, got {mode:o}");
    }

    // The tests below are not in the task brief's given suite. Each closes a gap the given suite
    // states as a property but does not exercise, discovered while checking the brief's sample
    // implementation against `internal/design/02-sensor-framework.md`'s "spool carries a global
    // byte budget" property before committing to it as-is (see the task report for the full
    // analysis).

    #[test]
    fn duplicate_store_does_not_consume_additional_budget() {
        // Budget fits exactly one copy of this body. The brief's own sample implementation
        // reserves budget on every `store` call regardless of whether the file already exists,
        // so it would fail this second call - treating a duplicate upload (zero additional disk
        // bytes) as if it cost a second 100 bytes. A dedup hit must be free.
        let (_dir, spool) = test_spool(200, 100);
        let body = vec![7u8; 100];
        spool.store(&body).unwrap();
        spool.store(&body).unwrap();
        spool.store(&body).unwrap();
    }

    #[test]
    fn new_recovers_used_bytes_from_files_already_on_disk() {
        // Simulates a sensor restart: the directory already holds a file from a prior process
        // (or a prior `QuarantineSpool` instance), and a freshly constructed spool must count it
        // against the budget rather than starting `used` at zero while the disk already holds
        // bytes against the same ceiling.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("preexisting"), vec![0u8; 80]).unwrap();
        let spool = QuarantineSpool::new(dir.path().to_path_buf(), 1024, 100);
        let body = vec![1u8; 30]; // 80 + 30 = 110 > 100 budget
        let result = spool.store(&body);
        assert!(matches!(result, Err(SpoolError::BudgetExhausted { .. })));
    }

    #[test]
    fn store_mints_a_capture_id() {
        let dir = tempfile::tempdir().unwrap();
        let spool = QuarantineSpool::new(dir.path().to_path_buf(), 10_000_000, 100_000_000);
        let s = spool.store(b"hello").unwrap();
        assert!(s.capture_id.is_some(), "store must mint a capture_id");
    }

    #[test]
    fn store_mints_a_distinct_capture_id_per_call_even_for_identical_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let spool = QuarantineSpool::new(dir.path().to_path_buf(), 10_000_000, 100_000_000);
        let a = spool.store(b"same").unwrap();
        let b = spool.store(b"same").unwrap();
        // Same content dedups to the same sha256 (existing behavior)...
        assert_eq!(a.sha256, b.sha256);
        // ...but each capture is a distinct OCCURRENCE, so capture_id differs.
        assert_ne!(a.capture_id, b.capture_id);
        assert!(a.capture_id.is_some() && b.capture_id.is_some());
    }

    #[test]
    fn verify_rejects_path_traversal_attempt() {
        // `verify`'s `sha256` parameter reaches a path join; the on-disk name must be safe by
        // its alphabet (hex only, like `sanitize::to_hex_bounded`), not by trusting the caller.
        // A path-shaped string must never be treated as a lookup key.
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let result = spool.verify("../../../../etc/passwd");
        assert!(matches!(result, Err(SpoolError::InvalidHash { .. })));
    }

    #[test]
    fn outbox_manifest_file_does_not_consume_spool_budget() {
        // SP-B-1c: each sensor's outbox manifest now lives at `<spool_dir>/outbox`, a
        // subdirectory of the same directory this spool scans on construction. `used` must only
        // ever be recovered from regular files directly in `dir` (`scan_existing_usage` above is
        // `is_file`-only and non-recursive), so a manifest file sitting one level down in
        // `outbox/` must never count against the capture body budget - verified here by budget
        // exhaustion rather than a `used` accessor (none exists; same technique as
        // `new_recovers_used_bytes_from_files_already_on_disk`).
        let dir = tempfile::tempdir().unwrap();
        let outbox_dir = dir.path().join("outbox");
        std::fs::create_dir_all(&outbox_dir).unwrap();
        // Larger than the budget below: if this were ever counted, every store would fail.
        std::fs::write(outbox_dir.join("some-capture-id.json"), vec![0u8; 500]).unwrap();

        let spool = QuarantineSpool::new(dir.path().to_path_buf(), 1024, 100);
        let body = vec![1u8; 100]; // exactly the budget; fails if the manifest bytes were counted
        spool
            .store(&body)
            .expect("a same-level outbox/ file must not count against the spool budget");
    }

    #[test]
    fn read_verified_returns_a_stored_body() {
        let (dir, spool) = test_spool(1024, 1_000_000);
        let sample = spool.store(b"captured payload").unwrap();
        let body = read_verified(dir.path(), &sample.sha256, 1024).unwrap();
        assert_eq!(body, b"captured payload");
    }

    #[test]
    #[cfg(unix)]
    fn read_verified_refuses_a_symlink_named_as_a_sample() {
        // The audit reproduction: a link named like a digest, pointing at a file outside the
        // spool. The reader must refuse the link itself, not read through it.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"not a sample").unwrap();
        let name = hex_digest(&Sha256::digest(b"not a sample"));
        std::os::unix::fs::symlink(&secret, dir.path().join(&name)).unwrap();

        let result = read_verified(dir.path(), &name, 1024);
        assert!(
            matches!(result, Err(SpoolError::NotRegularFile)),
            "a symlink must be refused even when its target hashes to its name, got {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn read_verified_does_not_block_on_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let name = "c".repeat(64);
        let path = dir.path().join(&name);
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path owned for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // A blocking open of a FIFO with no writer never returns; this must fail fast instead.
        let result = read_verified(dir.path(), &name, 1024);
        assert!(matches!(result, Err(SpoolError::NotRegularFile)));
    }

    #[test]
    fn read_verified_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let name = "d".repeat(64);
        std::fs::create_dir(dir.path().join(&name)).unwrap();
        assert!(matches!(
            read_verified(dir.path(), &name, 1024),
            Err(SpoolError::NotRegularFile)
        ));
    }

    #[test]
    fn read_verified_refuses_content_that_does_not_match_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let name = hex_digest(&Sha256::digest(b"claimed"));
        std::fs::write(dir.path().join(&name), b"actual").unwrap();
        assert!(matches!(
            read_verified(dir.path(), &name, 1024),
            Err(SpoolError::HashMismatch { .. })
        ));
    }

    #[test]
    fn read_verified_refuses_a_file_over_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let body = vec![5u8; 11];
        let name = hex_digest(&Sha256::digest(&body));
        std::fs::write(dir.path().join(&name), &body).unwrap();
        assert!(matches!(
            read_verified(dir.path(), &name, 10),
            Err(SpoolError::FileSizeExceeded {
                size: 11,
                limit: 10
            })
        ));
        assert_eq!(read_verified(dir.path(), &name, 11).unwrap(), body);
    }

    #[test]
    fn read_verified_accepts_only_the_canonical_lowercase_name() {
        let (dir, spool) = test_spool(1024, 1_000_000);
        let sample = spool.store(b"case").unwrap();
        let upper = sample.sha256.to_ascii_uppercase();
        assert!(matches!(
            read_verified(dir.path(), &upper, 1024),
            Err(SpoolError::InvalidHash { .. })
        ));
        assert!(matches!(
            read_verified(dir.path(), "../../etc/passwd", 1024),
            Err(SpoolError::InvalidHash { .. })
        ));
    }

    /// Several callers storing the same body at once, as the malware fetcher does when two URLs
    /// serve the same bytes. Every one must succeed with the same digest: none may read another's
    /// file while it is still being written and take it for corrupt.
    #[test]
    fn concurrent_stores_of_one_body_all_succeed() {
        const WRITERS: usize = 8;
        let body = std::sync::Arc::new(vec![0x5au8; 2 * 1024 * 1024]);
        for round in 0..24 {
            let (_dir, spool) = test_spool(8 * 1024 * 1024, 64 * 1024 * 1024);
            let spool = std::sync::Arc::new(spool);
            let start = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
            // Every writer is spawned before any is joined: they meet at the barrier together.
            let writers: Vec<_> = (0..WRITERS)
                .map(|_| {
                    let (spool, start, body) = (spool.clone(), start.clone(), body.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        spool.store(&body)
                    })
                })
                .collect();
            let results: Vec<_> = writers.into_iter().map(|w| w.join().unwrap()).collect();
            for result in &results {
                assert!(
                    result.is_ok(),
                    "round {round}: a concurrent store of the same body failed: {result:?}"
                );
            }
            // One body is on disk, so the budget is charged for one: every caller that found
            // the name already published gave its reservation back.
            assert_eq!(
                spool.used_bytes(),
                body.len() as u64,
                "round {round}: the budget was charged more than once for one stored body"
            );
        }
    }

    /// The budget is bytes on disk, and something else removes files from the spool (an operator,
    /// an external sweep): a spool that only counted up stayed full until the sensor
    /// restarted, so capture stopped for good once 100 MB had ever been written. Space freed
    /// outside the spool is picked up from the directory when a store would otherwise be refused.
    #[test]
    fn space_freed_outside_the_spool_is_reclaimed() {
        let (dir, spool) = test_spool(100, 150);
        let first = spool.store(&[0u8; 100]).unwrap();
        assert!(matches!(
            spool.store(&[1u8; 100]),
            Err(SpoolError::BudgetExhausted { .. })
        ));

        std::fs::remove_file(dir.path().join(&first.sha256)).unwrap();
        std::thread::sleep(RESCAN_MIN_INTERVAL + std::time::Duration::from_millis(200));

        spool
            .store(&[1u8; 100])
            .expect("the freed 100 bytes are available again");
        assert!(matches!(
            spool.store(&[2u8; 100]),
            Err(SpoolError::BudgetExhausted { .. })
        ));
    }

    /// Re-reading the directory must never forgive bytes that are still there: a refused store
    /// that rescans, with nothing removed, leaves the spool exactly as full as it was.
    #[test]
    fn a_rescan_with_nothing_removed_frees_nothing() {
        let (_dir, spool) = test_spool(100, 150);
        spool.store(&[0u8; 100]).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                spool.store(&[1u8; 100]),
                Err(SpoolError::BudgetExhausted { .. })
            ));
            std::thread::sleep(RESCAN_MIN_INTERVAL + std::time::Duration::from_millis(200));
        }
        assert_eq!(spool.used_bytes(), 100);
    }

    fn backdate(path: &Path, age: Duration) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
    }

    const THIRTY_ONE_DAYS: Duration = Duration::from_secs(31 * 86_400);

    /// A sensor removes the samples that have outlived retention from its own spool, and the bytes
    /// are available to the next capture at once, not a rescan later.
    #[test]
    fn prune_removes_old_samples_and_frees_their_budget_at_once() {
        let (dir, spool) = test_spool(100, 250);
        let old = spool.store(&[0u8; 100]).unwrap();
        let young = spool.store(&[1u8; 100]).unwrap();
        backdate(&dir.path().join(&old.sha256), THIRTY_ONE_DAYS);
        assert!(matches!(
            spool.store(&[2u8; 100]),
            Err(SpoolError::BudgetExhausted { .. })
        ));

        let report = spool.prune_older_than(SAMPLE_RETENTION);
        assert_eq!((report.removed, report.failed), (1, 0));
        assert!(!dir.path().join(&old.sha256).exists());
        assert!(
            dir.path().join(&young.sha256).exists(),
            "a young sample stays"
        );
        assert_eq!(spool.used_bytes(), 100);
        spool
            .store(&[2u8; 100])
            .expect("the pruned space is usable without waiting for a rescan");
    }

    /// Only what the spool itself filed is touched: a planted old link is removed as a link (its
    /// target is not followed), and a file that is not a sample, or sits below the spool root
    /// (the outbox manifest, staging), is never listed.
    #[test]
    #[cfg(unix)]
    fn prune_touches_only_digest_named_entries_in_the_spool_root() {
        let (dir, spool) = test_spool(100, 1000);
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("precious");
        std::fs::write(&target, b"not a sample").unwrap();
        let link = dir.path().join("c".repeat(64));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let other = dir.path().join("not-a-digest");
        std::fs::write(&other, b"x").unwrap();
        let outbox = dir.path().join("outbox");
        std::fs::create_dir(&outbox).unwrap();
        let manifest = outbox.join(format!("{}.json", "d".repeat(64)));
        std::fs::write(&manifest, b"{}").unwrap();
        for old in [&other, &manifest] {
            backdate(old, THIRTY_ONE_DAYS);
        }
        // `set_modified` follows a link, so age the link itself with utimensat.
        let name = std::ffi::CString::new(link.to_str().unwrap()).unwrap();
        let long_ago = libc::timespec {
            tv_sec: 1_000_000,
            tv_nsec: 0,
        };
        let times = [long_ago, long_ago];
        // SAFETY: `name` is a valid NUL-terminated path and `times` holds the two timespecs.
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                name.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0);

        let report = spool.prune_older_than(SAMPLE_RETENTION);
        assert_eq!(report.removed, 1, "only the digest-named link");
        assert!(link.symlink_metadata().is_err(), "the link is gone");
        assert!(target.exists(), "its target was not followed");
        assert!(other.exists() && manifest.exists());
    }

    /// A store that has reserved its bytes but not yet written them is not on disk for a rescan to
    /// count; forgetting it would let a second store take the same space.
    #[test]
    fn a_rescan_keeps_the_reservation_of_a_store_in_progress() {
        let (_dir, spool) = test_spool(100, 150);
        spool.reserve_budget(100).unwrap();
        assert!(matches!(
            spool.store(&[1u8; 100]),
            Err(SpoolError::BudgetExhausted { used: 100, .. })
        ));
        spool.finish_reservation(100);
        assert_eq!(spool.used_bytes(), 100);
    }

    /// A refused upload flood must not turn into a directory scan per upload.
    #[test]
    fn rescans_are_rate_limited() {
        let (dir, spool) = test_spool(100, 150);
        let first = spool.store(&[0u8; 100]).unwrap();
        assert!(spool.store(&[1u8; 100]).is_err());
        std::fs::remove_file(dir.path().join(&first.sha256)).unwrap();
        assert!(
            matches!(
                spool.store(&[1u8; 100]),
                Err(SpoolError::BudgetExhausted { .. })
            ),
            "a second refusal inside the interval does not rescan"
        );
    }

    /// Stores race a thread that keeps deleting and a reader that keeps measuring the directory:
    /// reclaiming must never let the bytes on disk pass the budget, whichever way the rescan
    /// interleaves with a store that has reserved but not yet published.
    #[test]
    fn rescans_racing_stores_never_exceed_the_budget() {
        const BUDGET: u64 = 1000;
        let (dir, spool) = test_spool(100, BUDGET);
        let spool = std::sync::Arc::new(spool);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writers: Vec<_> = (0u8..6)
            .map(|w| {
                let (spool, stop) = (spool.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut n = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        let mut body = vec![w; 100];
                        body[..4].copy_from_slice(&n.to_le_bytes());
                        let _ = spool.store(&body);
                        n += 1;
                    }
                })
            })
            .collect();
        let deleter = {
            let (path, stop) = (dir.path().to_path_buf(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Some(Ok(entry)) = std::fs::read_dir(&path).unwrap().next()
                        && entry.metadata().is_ok_and(|m| m.is_file())
                    {
                        let _ = std::fs::remove_file(entry.path());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
            })
        };
        let mut worst = 0;
        let until = std::time::Instant::now() + std::time::Duration::from_millis(3500);
        while std::time::Instant::now() < until {
            worst = worst.max(scan_existing_usage(dir.path()));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        stop.store(true, Ordering::Relaxed);
        for t in writers {
            t.join().unwrap();
        }
        deleter.join().unwrap();
        assert!(
            worst <= BUDGET,
            "{worst} bytes were on disk against a budget of {BUDGET}"
        );
        assert!(
            worst > 0,
            "the writers stored nothing, so nothing was tested"
        );
    }

    #[test]
    fn a_store_leaves_nothing_staged() {
        let (dir, spool) = test_spool(1024, 1_000_000);
        spool.store(b"first").unwrap();
        spool.store(b"first").unwrap();
        spool.store(b"second").unwrap();
        let staged: Vec<_> = std::fs::read_dir(dir.path().join(STAGING_DIR))
            .unwrap()
            .collect();
        assert!(staged.is_empty(), "left behind: {staged:?}");
    }

    /// A process that stops mid-store leaves its staged file. Nothing reads it and the budget scan
    /// does not see it, so the next start removes it once it is clearly abandoned; a younger one
    /// may belong to another process still writing, and stays.
    #[test]
    fn new_removes_only_abandoned_staged_files_and_never_counts_them() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join(STAGING_DIR);
        std::fs::create_dir(&staging).unwrap();
        let abandoned = staging.join("abandoned");
        let in_flight = staging.join("in-flight");
        std::fs::write(&abandoned, vec![0u8; 500]).unwrap();
        std::fs::write(&in_flight, vec![0u8; 500]).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&abandoned)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - STALE_STAGING * 2)
            .unwrap();

        let spool = QuarantineSpool::new(dir.path().to_path_buf(), 1024, 100);
        assert!(
            !abandoned.exists(),
            "an abandoned staged file must be removed"
        );
        assert!(
            in_flight.exists(),
            "a recent staged file must be left alone"
        );
        spool
            .store(&[1u8; 100])
            .expect("staged files must not count against the budget");
    }

    #[test]
    #[cfg(unix)]
    fn store_refuses_to_dedup_against_a_planted_symlink() {
        // A link already sitting at the name `store` would write must not be accepted as the
        // stored copy of this body, even when the link's target has the right content.
        let (dir, spool) = test_spool(1024, 1_000_000);
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("body");
        std::fs::write(&target, b"payload").unwrap();
        let name = hex_digest(&Sha256::digest(b"payload"));
        std::os::unix::fs::symlink(&target, dir.path().join(&name)).unwrap();

        assert!(matches!(
            spool.store(b"payload"),
            Err(SpoolError::NotRegularFile)
        ));
    }
}
