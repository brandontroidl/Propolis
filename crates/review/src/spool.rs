//! Canonical list of the sensors that spool captured bodies, and their spool directories.
//! Single source of truth for VT scanning, retention cleanup, and the console samples view, so a
//! new body-capturing sensor is wired in ONE place rather than several hand-maintained lists (the
//! omission that left telnet's malware un-scanned and un-cleaned).
use std::path::PathBuf;

pub const SPOOL_ROOT: &str = "/var/spool/propolis";

/// (sensor name, spool dir) for every sensor that spools captured bodies. ssh/adb/ftp/telnet capture
/// via the framework CaptureHandoff; catchall spools raw payloads directly. All produce bodies that
/// must be scanned, retention-cleaned, and listed.
pub fn body_spool_dirs() -> Vec<(&'static str, PathBuf)> {
    ["ssh", "adb", "ftp", "telnet", "catchall"]
        .into_iter()
        .map(|n| (n, PathBuf::from(format!("{SPOOL_ROOT}/{n}"))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            vec!["adb", "catchall", "ftp", "ssh", "telnet"],
            "canonical body-spool set changed - update every consumer deliberately, in one place"
        );
        // paths are under the shared spool root
        for (name, dir) in body_spool_dirs() {
            assert_eq!(dir, PathBuf::from(format!("/var/spool/propolis/{name}")));
        }
    }
}
