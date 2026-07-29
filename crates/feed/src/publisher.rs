//! The publisher: the last stage of a feed build. See `internal/design/05-blocklist-feed.md`'s
//! "Publisher" and "Error handling".
//!
//! Two responsibilities, run in this order:
//!
//! 1. Re-validate every entry in the snapshot against the exclusion engine. This is
//!    defense-in-depth - `FeedBuilder::build` already applies `ExclusionEngine::is_excluded` - but
//!    the design is explicit that a bug in the builder must not leak a reserved/allowlisted/
//!    delisted address into a published feed. Unlike the builder (which drops individual
//!    offending entries and keeps building), the publisher rejects the WHOLE build on the first
//!    violation: "a single leaked reserved IP would invalidate the operator's trust in the whole
//!    feed" (design's "Exclusion engine").
//! 2. Render every exporter format for both tiers plus `manifest.json`, write them to a
//!    same-filesystem staging directory, and atomically swap that directory into `output_dir` -
//!    see `swap_into_place` for exactly what "atomic" means here.
//!
//! Any error aborts before `output_dir` is touched (re-validation failures, staging I/O errors) or
//! leaves it holding its previous, complete content (an error surfacing after staging succeeded
//! but before the swap): "A file write error fails the entire publish. The previous feed version
//! stays in place" (design's "Error handling").
//!
//! `output_dir`'s PARENT must be writable, not merely `output_dir` itself: an atomic swap of the
//! whole file set requires renaming a staging directory into place, and `rename(2)` acts on a
//! directory ENTRY within a shared parent, not on the target directory's own contents. The shipped
//! `deploy/feed.service` grants this correctly - `ReadWritePaths=/var/lib/propolis/feed`, a
//! dedicated root scoped to this service alone (never the shared `/var/lib/propolis`), with the
//! default `PROPOLIS_FEED_OUTPUT_DIR` one level inside it (`/var/lib/propolis/feed/current`) so
//! the sibling staging/previous directories this module creates land inside that same granted
//! root. See that file's header comment for the full reasoning.

use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use core_scoring::FeedTier;

use crate::export::{export_cidr, export_csv, export_json, export_plaintext, format_timestamp};
use crate::{ExclusionEngine, FeedConfig, FeedEntry, FeedSnapshot};

/// Errors from [`Publisher::publish`]. Every variant rejects the build in its entirety - there is
/// no partial publish. See the module doc comment.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// An entry failed re-validation against the exclusion engine. Fails the whole snapshot, not
    /// just this entry - see the module doc comment.
    #[error(
        "entry {ip} in the {tier:?} tier failed publisher re-validation against exclusions; \
         rejecting the entire build"
    )]
    ExclusionViolation { ip: IpAddr, tier: FeedTier },

    /// `output_dir` has no file-name component (e.g. `/`), so a same-filesystem sibling staging
    /// directory cannot be derived. Fails closed rather than falling back to a system temp
    /// directory (e.g. `/tmp`), which may be a different filesystem and would silently break the
    /// atomic-rename guarantee (`rename(2)` returns `EXDEV` across filesystems).
    #[error("output directory {0:?} has no file name; refusing to publish")]
    InvalidOutputDir(PathBuf),

    /// A filesystem error while staging, writing, verifying, or swapping in the new build.
    #[error("i/o error during publish: {0}")]
    Io(#[from] io::Error),

    /// `manifest.json` serialization failed. Not expected in practice - every field is a plain
    /// `String` or `usize` - but `serde_json::to_string` is fallible in general, so this is
    /// handled rather than `expect`-ed.
    #[error("manifest serialization error: {0}")]
    Manifest(#[from] serde_json::Error),

    /// The staged plain-text file's content, re-read from disk, did not hash to the same SHA-256
    /// just computed from the in-memory string. An integrity self-check - confirming a write's
    /// post-state landed rather than assuming it did - not expected to ever fire absent a
    /// filesystem-level bug.
    #[error(
        "checksum self-check failed for {0:?}: on-disk content does not match what was generated"
    )]
    ChecksumMismatch(PathBuf),
}

/// Stateless namespace for the publish step (mirrors `FeedBuilder`'s own shape).
pub struct Publisher;

impl Publisher {
    /// Re-validates `snapshot` against `exclusions`, renders every export format for both tiers
    /// plus `manifest.json`, and atomically publishes the result to `output_dir`.
    ///
    /// `config` supplies the tier TTLs used to compute each tier's `valid_until` independent of
    /// whether that tier has any entries: `FeedSnapshot` carries `valid_until` only per-entry, so
    /// an empty tier has no entry to read it from, and the design requires an empty feed to
    /// "publish normally" with valid output (design's "Error handling") - callers pass the same
    /// `FeedConfig` used to build the snapshot.
    pub fn publish(
        snapshot: &FeedSnapshot,
        output_dir: &Path,
        exclusions: &ExclusionEngine,
        config: &FeedConfig,
    ) -> Result<(), PublishError> {
        revalidate(snapshot, exclusions)?;

        let file_name = output_dir
            .file_name()
            .ok_or_else(|| PublishError::InvalidOutputDir(output_dir.to_path_buf()))?;
        let parent = match output_dir.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };

        let staging = create_staging_dir(parent, file_name)?;
        // From here on, any early return via `?` leaves only a stray staging directory on disk
        // (overwritten by the next run's `create_staging_dir`, which clears a same-named
        // leftover) - `output_dir` itself is untouched until `swap_into_place`, the last step.
        let aggressive = write_tier(
            &staging,
            "aggressive",
            snapshot.build_time,
            snapshot.build_time + config.aggressive_ttl,
            &snapshot.aggressive,
        )?;
        let standard = write_tier(
            &staging,
            "standard",
            snapshot.build_time,
            snapshot.build_time + config.standard_ttl,
            &snapshot.standard,
        )?;

        let manifest = Manifest {
            build_time: format_timestamp(snapshot.build_time),
            tiers: ManifestTiers {
                aggressive,
                standard,
            },
        };
        let manifest_json = serde_json::to_string(&manifest)?;
        write_file_synced(&staging.join("manifest.json"), manifest_json.as_bytes())?;

        swap_into_place(&staging, output_dir)?;
        Ok(())
    }
}

/// Fails the whole build on the first entry that should never have reached a `FeedSnapshot` at
/// all. See the module doc comment for why this is whole-snapshot, not per-entry.
fn revalidate(snapshot: &FeedSnapshot, exclusions: &ExclusionEngine) -> Result<(), PublishError> {
    for (tier, entries) in [
        (FeedTier::Aggressive, &snapshot.aggressive),
        (FeedTier::Standard, &snapshot.standard),
    ] {
        for entry in entries {
            if exclusions.is_excluded(entry.source_ip) {
                tracing::error!(
                    ip = %entry.source_ip,
                    tier = ?tier,
                    "publisher: entry failed re-validation against exclusions; rejecting the entire build"
                );
                return Err(PublishError::ExclusionViolation {
                    ip: entry.source_ip,
                    tier,
                });
            }
        }
    }
    Ok(())
}

/// Creates a clean same-filesystem staging directory as a sibling of the eventual `output_dir`
/// (both under `parent`), so the final `swap_into_place` rename is guaranteed same-filesystem.
///
/// Uses a FIXED name (`.{file_name}.staging`), not one salted with a pid/timestamp: this crate's
/// deployment model is a single systemd instance (`deploy/feed.service`, `Type=simple`, no
/// concurrent invocation), the same single-writer assumption `intake::cursor`'s own
/// write-temp-then-rename helper makes for its cursor file. A leftover from a run that crashed
/// after staging began must not silently mix its files with this run's, so an existing leftover is
/// removed before starting.
fn create_staging_dir(parent: &Path, file_name: &std::ffi::OsStr) -> io::Result<PathBuf> {
    std::fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".{}.staging", file_name.to_string_lossy()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    Ok(staging)
}

/// Renders and writes all four export formats for one tier, verifies the plain-text file's
/// on-disk content against a freshly computed digest, and returns that tier's `manifest.json`
/// entry. `generated`/`valid_until` are passed explicitly (never derived from `entries`) so a
/// zero-entry tier still renders a correct header/meta and manifest entry - see the exporters'
/// own doc comments (`crate::export`'s module doc) for why they take the same two parameters
/// explicitly rather than reading `entries[0]`.
fn write_tier(
    staging: &Path,
    name: &str,
    generated: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    entries: &[FeedEntry],
) -> Result<TierManifest, PublishError> {
    let txt = export_plaintext(name, generated, valid_until, entries);
    write_file_synced(&staging.join(format!("{name}.txt")), txt.as_bytes())?;
    write_file_synced(
        &staging.join(format!("{name}.json")),
        export_json(name, generated, valid_until, entries).as_bytes(),
    )?;
    write_file_synced(
        &staging.join(format!("{name}.csv")),
        export_csv(entries).as_bytes(),
    )?;
    write_file_synced(
        &staging.join(format!("{name}.cidr")),
        export_cidr(entries).as_bytes(),
    )?;

    // Integrity self-check: re-read the plain-text file just written and confirm its on-disk
    // digest matches what was just generated, before that digest is recorded in `manifest.json` -
    // read the post-state, don't assume the write landed.
    let sha256 = sha256_hex(txt.as_bytes());
    let txt_path = staging.join(format!("{name}.txt"));
    let on_disk = std::fs::read(&txt_path)?;
    if sha256_hex(&on_disk) != sha256 {
        return Err(PublishError::ChecksumMismatch(txt_path));
    }

    Ok(TierManifest {
        count: entries.len(),
        sha256,
        valid_until: format_timestamp(valid_until),
    })
}

/// Writes `bytes` to `path` and `fsync`s before returning, matching
/// `intake::cursor::CursorStore::save`'s own durability idiom: a rename that follows a write not
/// yet flushed to disk can be reordered ahead of it by the filesystem on a crash, so every file
/// this module writes is synced before the directory that holds it is ever renamed into view.
fn write_file_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Atomically replaces `output_dir`'s content with `staging`'s.
///
/// If `output_dir` does not exist yet, a single `rename` is already atomic and sufficient. If it
/// does exist, `rename(2)` cannot replace a non-empty directory directly (`ENOTEMPTY` on Linux),
/// so this takes two rename steps instead: move the old directory aside, then move staging into
/// its place. Both steps are individually atomic and same-filesystem (`old_aside` and `staging`
/// are both siblings of `output_dir` under the same parent), so a reader of `output_dir` always
/// sees either the complete previous build or the complete new one. The one gap this leaves is the
/// instant between the two renames where `output_dir` does not exist at all - a concurrent reader
/// at exactly that instant sees "not found yet", never a torn mix of old and new files, which is
/// the guarantee the design's "Atomic publish" asks for ("consumers never see a partially-written
/// feed").
fn swap_into_place(staging: &Path, output_dir: &Path) -> io::Result<()> {
    if !output_dir.exists() {
        return std::fs::rename(staging, output_dir);
    }

    let parent = match output_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = output_dir
        .file_name()
        .expect("output_dir already exists, so it was created with a valid file name");
    let old_aside = parent.join(format!(".{}.previous", file_name.to_string_lossy()));
    if old_aside.exists() {
        std::fs::remove_dir_all(&old_aside)?;
    }

    std::fs::rename(output_dir, &old_aside)?;
    std::fs::rename(staging, output_dir)?;

    // Best-effort cleanup: every consumer-visible guarantee already holds by this point (the
    // rename above completed), so a failure here is logged, not propagated as a publish failure.
    if let Err(e) = std::fs::remove_dir_all(&old_aside) {
        tracing::warn!(
            path = %old_aside.display(),
            error = %e,
            "publisher: failed to clean up the previous build directory after a successful publish"
        );
    }
    Ok(())
}

/// `manifest.json`'s document shape - see the design's "Manifest".
#[derive(Debug, Serialize)]
struct Manifest {
    build_time: String,
    tiers: ManifestTiers,
}

#[derive(Debug, Serialize)]
struct ManifestTiers {
    aggressive: TierManifest,
    standard: TierManifest,
}

#[derive(Debug, Serialize)]
struct TierManifest {
    count: usize,
    sha256: String,
    valid_until: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_a_known_vector() {
        // SHA-256("") - the standard empty-input test vector.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_is_deterministic_and_input_sensitive() {
        assert_eq!(sha256_hex(b"abc"), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
    }
}
