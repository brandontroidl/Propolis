//! Canonical list of the sensors that spool captured bodies, and their spool directories.
//! Single source of truth for VT scanning, retention cleanup, and the console samples view, so a
//! new body-capturing sensor is wired in ONE place rather than several hand-maintained lists (the
//! omission that left telnet's malware un-scanned and un-cleaned).
//!
//! Paths are RESOLVED, never hardcoded. Each sensor already reads its own spool directory from
//! `PROPOLIS_<SENSOR>_SPOOL_DIR`, so this reads the same variables: a hardcoded path here would
//! silently diverge from an operator override, and the platform side (scan, retention, console)
//! would look in a directory nothing writes to and simply find nothing - the same silent-divergence
//! failure class as a config the binary never reads.
use std::env;
use std::path::PathBuf;

/// Root that per-sensor spool directories default under, overridable with `PROPOLIS_SPOOL_ROOT`
/// (`deploy/install.sh` provisions this tree, and the systemd units grant it in `ReadWritePaths`).
pub const DEFAULT_SPOOL_ROOT: &str = "/var/spool/propolis";
const ENV_SPOOL_ROOT: &str = "PROPOLIS_SPOOL_ROOT";

/// The sensors that spool captured bodies, paired with the env var each one reads for its own spool
/// directory. catchall is deliberately absent: it never spools a body (crates/sensor-catchall/src/
/// handler.rs module doc; its Config carries no spool fields), so listing it - as an earlier version
/// of this file did - made the VT scan, retention and console walk a directory nothing writes to.
const BODY_SPOOLERS: [(&str, Option<&str>); 4] = [
    ("ssh", Some("PROPOLIS_SSH_SPOOL_DIR")),
    ("adb", Some("PROPOLIS_ADB_SPOOL_DIR")),
    ("ftp", Some("PROPOLIS_FTP_SPOOL_DIR")),
    ("telnet", Some("PROPOLIS_TELNET_SPOOL_DIR")),
];

/// The spool tree root: `PROPOLIS_SPOOL_ROOT`, else [`DEFAULT_SPOOL_ROOT`].
pub fn spool_root() -> PathBuf {
    env::var(ENV_SPOOL_ROOT)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SPOOL_ROOT))
}

/// A subdirectory of the spool root, for callers that need a non-sensor bucket (e.g. the malware
/// fetcher's own output) without hardcoding the root.
pub fn spool_subdir(name: &str) -> PathBuf {
    spool_root().join(name)
}

/// (sensor name, spool dir) for every sensor that spools captured bodies: ssh/adb/ftp/telnet, all via
/// the framework CaptureHandoff. Their bodies must be scanned, retention-cleaned, and listed. Each directory honours that sensor's own
/// `PROPOLIS_<SENSOR>_SPOOL_DIR` override so this never disagrees with where the sensor actually
/// writes.
pub fn body_spool_dirs() -> Vec<(&'static str, PathBuf)> {
    let root = spool_root();
    BODY_SPOOLERS
        .into_iter()
        .map(|(name, env_var)| {
            let dir = env_var
                .and_then(|v| env::var(v).ok())
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join(name));
            (name, dir)
        })
        .collect()
}

/// Every directory that holds captured bodies: the sensor spools plus the malware fetcher's own
/// `fetched` bucket. The VT scan, sample retention and the console samples view all walk this one
/// list, so `fetched` is appended here once rather than hand-appended at each caller (which is how
/// one of them ends up walking three directories while another walks four).
pub fn all_body_dirs() -> Vec<(&'static str, PathBuf)> {
    let mut dirs = body_spool_dirs();
    dirs.push(("fetched", spool_subdir("fetched")));
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_body_dirs_is_every_sensor_spool_plus_fetched() {
        let names: Vec<&str> = all_body_dirs().iter().map(|(n, _)| *n).collect();
        for sensor in body_spool_dirs().iter().map(|(n, _)| *n) {
            assert!(
                names.contains(&sensor),
                "{sensor} missing from all_body_dirs"
            );
        }
        assert_eq!(
            names.iter().filter(|n| **n == "fetched").count(),
            1,
            "fetched must be present exactly once"
        );
        assert_eq!(names.len(), body_spool_dirs().len() + 1);
    }

    #[test]
    fn canonical_list_is_the_full_body_spooler_set_including_telnet() {
        let names: Vec<&str> = body_spool_dirs().iter().map(|(n, _)| *n).collect();
        // Every sensor that spools bodies must be here - telnet was the one that got dropped.
        assert!(
            names.contains(&"telnet"),
            "telnet must be in the canonical body-spool list"
        );
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec!["adb", "ftp", "ssh", "telnet"],
            "canonical body-spool set changed - update every consumer deliberately, in one place"
        );
    }

    #[test]
    fn every_body_spooler_resolves_under_the_active_root_by_default() {
        // Derived from spool_root() rather than a literal, so the assertion still holds under a
        // PROPOLIS_SPOOL_ROOT override and never re-hardcodes what this module exists to resolve.
        let root = spool_root();
        for (name, dir) in body_spool_dirs() {
            // A per-sensor override (set in this process's environment) legitimately points
            // elsewhere; absent one, the dir must sit under the active root.
            let overridden = BODY_SPOOLERS
                .iter()
                .find(|(n, _)| *n == name)
                .and_then(|(_, e)| *e)
                .and_then(|e| env::var(e).ok())
                .is_some_and(|v| !v.trim().is_empty());
            if !overridden {
                assert_eq!(dir, root.join(name));
            }
        }
    }

    #[test]
    fn spool_subdir_hangs_off_the_same_root() {
        assert_eq!(spool_subdir("fetched"), spool_root().join("fetched"));
    }
}
