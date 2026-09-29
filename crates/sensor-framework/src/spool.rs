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
use std::sync::atomic::{AtomicU64, Ordering};

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

/// A directory of captured bodies, each named by its SHA-256, guarded by a per-file size cap and
/// a global byte budget shared across every call. Safe to call concurrently: `store` and `verify`
/// take `&self` because production capture hand-off shares one instance across every sensor
/// connection's task (see Task 6's plan).
pub struct QuarantineSpool {
    dir: PathBuf,
    max_file_size: u64,
    global_budget: u64,
    /// Bytes currently on disk against `global_budget`. Recovered at construction from the
    /// directory's existing contents (see `scan_existing_usage`) so a restart does not reset the
    /// ceiling to zero while previously spooled files still occupy it.
    used: AtomicU64,
}

impl QuarantineSpool {
    pub fn new(dir: PathBuf, max_file_size: u64, global_budget: u64) -> Self {
        remove_stale_staging(&dir.join(STAGING_DIR));
        let used = scan_existing_usage(&dir);
        Self {
            dir,
            max_file_size,
            global_budget,
            used: AtomicU64::new(used),
        }
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
            Ok(()) => Ok(sample),
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
            Err(Publish::NameNotSynced(e)) => Err(e.into()),
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
        // dedup target, and the cap this call would apply is about memory, which `store` already
        // bounded when it accepted `body`.
        read_verified(&self.dir, hash, u64::MAX).map(drop)
    }

    /// Atomically check-and-reserve `size` bytes against the global budget. `SeqCst` throughout:
    /// this counter is touched once per capture, so disk I/O dominates cost by orders of
    /// magnitude and the ordering choice is not a performance concern - it is chosen only so the
    /// operation is trivially correct to reason about.
    fn reserve_budget(&self, size: u64) -> Result<(), SpoolError> {
        loop {
            let current = self.used.load(Ordering::SeqCst);
            let Some(next) = current
                .checked_add(size)
                .filter(|&n| n <= self.global_budget)
            else {
                return Err(SpoolError::BudgetExhausted {
                    used: current,
                    budget: self.global_budget,
                    attempted: size,
                });
            };
            if self
                .used
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Give back a reservation that turned out not to be needed (the write failed, or another
    /// caller already published the same content). Saturating: the counter that gates a
    /// security-relevant guard must never wrap silently even if release were ever called out of
    /// balance with reserve.
    fn release_budget(&self, size: u64) {
        let _ = self
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                Some(used.saturating_sub(size))
            });
    }
}

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
                spool.used.load(Ordering::SeqCst),
                body.len() as u64,
                "round {round}: the budget was charged more than once for one stored body"
            );
        }
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
