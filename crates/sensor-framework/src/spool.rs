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

        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
        {
            Ok(mut file) => {
                if let Err(e) = write_and_seal(&mut file, body) {
                    self.release_budget(size);
                    drop(file);
                    let _ = std::fs::remove_file(&file_path);
                    return Err(e.into());
                }
                Ok(SampleRef {
                    sha256: hash,
                    size,
                    orig_name: String::new(),
                    capture_id,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lost a narrow race: another call published this exact content between our
                // existence check above and this attempt. We do not own that write, so give
                // back the speculative reservation and confirm what is actually on disk rather
                // than assume the winner's write has already finished.
                self.release_budget(size);
                self.verify_on_disk(&hash)?;
                Ok(SampleRef {
                    sha256: hash,
                    size,
                    orig_name: String::new(),
                    capture_id,
                })
            }
            Err(e) => {
                self.release_budget(size);
                Err(e.into())
            }
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
        if !is_valid_sha256_hex(sha256) {
            let given: String = sha256.chars().take(128).collect();
            return Err(SpoolError::InvalidHash { given });
        }
        self.verify_on_disk(sha256)
    }

    /// Shared re-hash-on-read logic for both `verify` and `store`'s dedup path. Only ever called
    /// with a hash already known to be well-formed (either computed internally, or checked by
    /// `verify` above), so it does no format validation of its own.
    fn verify_on_disk(&self, hash: &str) -> Result<(), SpoolError> {
        let body = std::fs::read(self.dir.join(hash))?;
        let actual = hex_digest(&Sha256::digest(&body));
        if actual != hash {
            return Err(SpoolError::HashMismatch {
                expected: hash.to_string(),
                actual,
            });
        }
        Ok(())
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

/// Write the body to a freshly created, empty spool file and lock down its permissions.
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

/// A SHA-256 hex digest is exactly 64 lowercase-or-uppercase hex characters. This alphabet
/// structurally excludes `/`, `\`, and `.`, so confirming it is enough to make a path-traversal
/// payload impossible to smuggle through `verify`'s `sha256` argument - safe by alphabet, not by
/// a traversal-specific check that could be bypassed by some encoding this one overlooks.
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
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
}
