//! Sample retention against the shipped units and provisioning.
//!
//! Retention failed silently on the production layout: the daemon's `sample-retention` pass walked
//! every sensor spool, but `deploy/propolis.service` mounts those read-only (`ProtectSystem=strict`
//! with `ReadWritePaths` for `fetched` only), and `deploy/provision.sh` gives each spool to its
//! sensor's account at `0750` with the daemon only a reader through the sensor's group. Nothing in
//! the unit or the code said so; the spools simply filled to their budget and stayed full.
//!
//! The fix puts each deletion where the permission is: a sensor ages out its own spool
//! (`CaptureHandoff::start_worker` starts it, covered by the sensor crates' own tests), and the
//! daemon ages out only the spool it owns. These tests read the shipped files and check, for every
//! directory a retention pass walks, that the account running the pass owns the directory with
//! write permission and has the path writable in its unit. The population comes from
//! `review::spool`, not from a list typed here, so a sensor added there is checked without anyone
//! remembering to.

use std::path::{Path, PathBuf};

fn deploy_file(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The value of every `key=` line in a unit, in order (a directive may repeat).
fn unit_values(unit: &str, key: &str) -> Vec<String> {
    unit.lines()
        .filter_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(str::to_string)
        .collect()
}

/// The paths a unit lists under `key` (`ReadWritePaths`, ...), with the optional-path `-` prefix
/// removed.
fn unit_paths(unit: &str, key: &str) -> Vec<PathBuf> {
    unit_values(unit, key)
        .iter()
        .flat_map(|v| v.split_whitespace())
        .map(|p| PathBuf::from(p.trim_start_matches('-')))
        .collect()
}

/// Whether `dir` is one of `paths` or below one (a bind mount covers the subtree).
fn covered(dir: &Path, paths: &[PathBuf]) -> bool {
    paths.iter().any(|p| dir.starts_with(p))
}

struct Provisioned {
    mode: u32,
    owner: String,
}

/// `ensure_dir <path> <mode> <owner> <group>` for `dir` in `provision.sh`.
fn provisioned(script: &str, dir: &Path) -> Option<Provisioned> {
    script.lines().find_map(|l| {
        let mut words = l.split_whitespace();
        (words.next()? == "ensure_dir" && Path::new(words.next()?) == dir).then(|| {
            let mode = u32::from_str_radix(words.next().unwrap(), 8).expect("octal mode");
            Provisioned {
                mode,
                owner: words.next().expect("owner").to_string(),
            }
        })
    })
}

/// A spool directory must be created for its owner with read, write and search, or the owner
/// cannot unlink the files in it.
fn assert_owner_can_remove(script: &str, dir: &Path, user: &str, what: &str) {
    let p = provisioned(script, dir)
        .unwrap_or_else(|| panic!("{what}: provision.sh does not create {}", dir.display()));
    assert_eq!(
        p.owner,
        user,
        "{what}: {} is created for {}, but the unit that removes its files runs as {user}",
        dir.display(),
        p.owner
    );
    assert_eq!(
        p.mode & 0o700,
        0o700,
        "{what}: {} is created {:04o}; its owner needs rwx to remove a file",
        dir.display(),
        p.mode
    );
}

#[test]
fn every_spooling_sensor_can_remove_files_from_its_own_spool() {
    let provision = deploy_file("provision.sh");
    let sensors = review::spool::body_spool_dirs();
    assert!(
        sensors.len() >= 6,
        "the body-spool population shrank: {sensors:?}"
    );
    for (name, dir) in sensors {
        let unit = deploy_file(&format!("sensor-{name}.service"));
        let user = unit_values(&unit, "User")
            .pop()
            .unwrap_or_else(|| panic!("sensor-{name}.service has no User="));

        // The path must be writable inside the unit's sandbox and not shadowed read-only.
        assert!(
            covered(&dir, &unit_paths(&unit, "ReadWritePaths")),
            "sensor-{name}.service does not list {} in ReadWritePaths",
            dir.display()
        );
        for blocked in ["ReadOnlyPaths", "InaccessiblePaths", "NoExecPaths"] {
            assert!(
                !unit_paths(&unit, blocked)
                    .iter()
                    .any(|p| p != Path::new("/") && dir.starts_with(p)),
                "sensor-{name}.service lists {} under {blocked}, which would stop it deleting there",
                dir.display()
            );
        }
        assert_owner_can_remove(&provision, &dir, &user, &format!("sensor {name}"));
    }
}

/// Retention for a sensor's spool is started by `CaptureHandoff::start_worker`, so a sensor that
/// stores samples through the framework has it exactly when it starts its worker.
#[test]
fn every_spooling_sensor_starts_the_worker_that_starts_retention() {
    for (name, _) in review::spool::body_spool_dirs() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../sensor-{name}/src"));
        let mut found = false;
        let mut dirs = vec![src.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    found |= std::fs::read_to_string(&path)
                        .unwrap()
                        .contains("handoff.start_worker();");
                }
            }
        }
        assert!(found, "sensor-{name} never calls handoff.start_worker()");
    }
}

/// The daemon's pass is limited to spools its own unit can write, and its unit grants nothing
/// else under the spool tree: a sensor spool added to `ReadWritePaths` here would be the
/// cross-account write the design avoids (a compromised daemon could then unlink or replace
/// entries in a sensor's directory).
#[test]
fn the_daemon_walks_only_spools_it_can_write_and_its_unit_grants_no_more() {
    let provision = deploy_file("provision.sh");
    let unit = deploy_file("propolis.service");
    let user = unit_values(&unit, "User")
        .pop()
        .expect("propolis.service User=");
    let writable = unit_paths(&unit, "ReadWritePaths");

    let walked = review::spool::daemon_retention_dirs();
    assert!(!walked.is_empty());
    for (name, dir) in &walked {
        assert!(
            covered(dir, &writable),
            "the daemon's retention walks {name} ({}) but propolis.service cannot write it",
            dir.display()
        );
        assert_owner_can_remove(&provision, dir, &user, &format!("daemon spool {name}"));
    }

    let spool_tree = Path::new(review::spool::DEFAULT_SPOOL_ROOT);
    let mut granted: Vec<&PathBuf> = writable
        .iter()
        .filter(|p| p.starts_with(spool_tree))
        .collect();
    let mut expected: Vec<PathBuf> = walked.iter().map(|(_, d)| d.clone()).collect();
    granted.sort();
    expected.sort();
    assert_eq!(
        granted,
        expected.iter().collect::<Vec<_>>(),
        "propolis.service may write under {} only where its retention pass walks",
        spool_tree.display()
    );
    for (name, dir) in review::spool::body_spool_dirs() {
        assert!(
            !covered(&dir, &writable),
            "propolis.service can write sensor {name}'s spool {}",
            dir.display()
        );
    }
}
