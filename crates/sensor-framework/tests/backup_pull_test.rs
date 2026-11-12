//! The off-host copy end to end: `deploy/backup-pull.sh` (the workstation side) against
//! `deploy/backup-serve.sh` (the box's forced command), joined by a stub `ssh` that runs the serve
//! script with the client's request in `SSH_ORIGINAL_COMMAND`, exactly as sshd's `command=` does.
//! Asserts that only encrypted sets are ever served, that the serve script answers nothing but
//! `list` and `get`, and that a pulled set is kept only when every digest matches.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const SERVE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/backup-serve.sh");
const PULL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/backup-pull.sh");

/// Everything after `user@host` is the remote command, joined as sshd hands it over.
const SSH_STUB: &str = r#"#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >> "$STUB_LOG"
while [ "$#" -gt 0 ]; do case "$1" in *@*) shift; break ;; *) shift ;; esac; done
if [ -n "${STUB_TAMPER:-}" ] && [ "${1:-}" = get ] && [ "${3:-}" = state.tgz.age ]; then
    SSH_ORIGINAL_COMMAND="$*" bash "$SERVE" | sed 's/state/STATE/'
else
    SSH_ORIGINAL_COMMAND="$*" exec bash "$SERVE"
fi
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    served: PathBuf,
    dest: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

fn write_exec(path: &Path, body: &str) {
    let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A set as deploy/backup.sh writes it, encrypted or not, with correct digests.
fn make_set(dir: &Path, name: &str, encrypted: bool) {
    let set = dir.join(name);
    std::fs::create_dir_all(&set).unwrap();
    let files: &[&str] = if encrypted {
        &["propolis.dump.age", "state.tgz.age"]
    } else {
        &["propolis.dump", "state.tgz"]
    };
    for f in files {
        std::fs::write(set.join(f), format!("{name} {f} contents\n")).unwrap();
    }
    let sums = Command::new("sha256sum")
        .args(files)
        .current_dir(&set)
        .output()
        .unwrap();
    std::fs::write(set.join("SHA256SUMS"), sums.stdout).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let served = dir.path().join("served");
        std::fs::create_dir_all(&served).unwrap();
        make_set(&served, "20261009T033000Z-scheduled", true);
        make_set(&served, "20261010T033000Z-scheduled", true);
        // The newest set is plaintext (recipients removed since): it must never leave.
        make_set(&served, "20261011T033000Z-scheduled", false);
        std::fs::create_dir_all(served.join(".partial-20261012T033000Z-scheduled")).unwrap();
        let bin = dir.path().join("bin");
        write_exec(&bin.join("ssh"), SSH_STUB);
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        Fixture {
            dest: dir.path().join("copies"),
            _dir: dir,
            served,
            bin,
            log,
        }
    }

    fn serve(&self, request: &str) -> Output {
        Command::new("bash")
            .arg(SERVE)
            .env("SSH_ORIGINAL_COMMAND", request)
            .env("PROPOLIS_BACKUP_SERVE_DIR", &self.served)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn pull(&self, extra: &[&str], env: &[(&str, &str)]) -> Output {
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg(PULL)
            .args([
                "--host",
                "honeybox.example",
                "--port",
                "2180",
                "--key",
                "/nonexistent/key",
            ])
            .arg("--dest")
            .arg(&self.dest)
            .args(extra)
            .env("PATH", path)
            .env("SERVE", SERVE)
            .env("PROPOLIS_BACKUP_SERVE_DIR", &self.served)
            .env("STUB_LOG", &self.log)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        child.wait_with_output().unwrap()
    }

    fn pulled(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dest)
            .map(|e| {
                e.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn list_names_only_encrypted_sets_newest_first() {
    let fx = Fixture::new();
    let out = fx.serve("list");
    assert!(out.status.success());
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        6,
        "three files of each of two encrypted sets: {text}"
    );
    assert!(
        lines[0].starts_with("20261010T033000Z-scheduled "),
        "{text}"
    );
    assert!(
        !text.contains("20261011T033000Z"),
        "the plaintext set is never listed: {text}"
    );
    assert!(!text.contains(".partial"), "{text}");
    assert!(lines.iter().all(|l| l.split(' ').count() == 3), "{text}");
}

#[test]
fn get_serves_only_known_files_of_encrypted_sets_and_nothing_else_runs() {
    let fx = Fixture::new();
    let out = fx.serve("get 20261010T033000Z-scheduled state.tgz.age");
    assert!(out.status.success());
    assert_eq!(
        stdout(&out),
        "20261010T033000Z-scheduled state.tgz.age contents\n"
    );
    for request in [
        "get 20261011T033000Z-scheduled propolis.dump",
        "get 20261011T033000Z-scheduled SHA256SUMS",
        "get 20261010T033000Z-scheduled ../../../etc/passwd",
        "get ../served/20261010T033000Z-scheduled state.tgz.age",
        "get 20261010T033000Z-scheduled propolis.dump",
        "get 20261010T033000Z-scheduled",
        "list extra",
        "sh -c id",
        "",
        "scp -f /etc/propolis/propolis.env",
    ] {
        let out = fx.serve(request);
        assert_eq!(out.status.code(), Some(2), "{request:?} must be refused");
        assert!(out.stdout.is_empty(), "{request:?} served bytes");
    }
}

#[test]
fn a_pull_fetches_and_verifies_the_newest_encrypted_set_once() {
    let fx = Fixture::new();
    let out = fx.pull(&[], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fx.pulled(), ["20261010T033000Z-scheduled"]);
    let set = fx.dest.join("20261010T033000Z-scheduled");
    for f in ["propolis.dump.age", "state.tgz.age", "SHA256SUMS"] {
        assert_eq!(
            std::fs::read(set.join(f)).unwrap(),
            std::fs::read(fx.served.join("20261010T033000Z-scheduled").join(f)).unwrap(),
            "{f} arrived byte for byte"
        );
    }
    let log = std::fs::read_to_string(&fx.log).unwrap();
    assert!(
        log.lines()
            .all(|l| l.contains("-o BatchMode=yes") && l.contains("-p 2180"))
    );

    let again = fx.pull(&[], &[]);
    assert!(again.status.success());
    assert!(stdout(&again).contains("already here"));
    assert_eq!(
        std::fs::read_to_string(&fx.log)
            .unwrap()
            .matches(" get ")
            .count(),
        3,
        "nothing fetched twice"
    );
}

#[test]
fn a_set_that_does_not_match_its_digests_is_not_kept() {
    let fx = Fixture::new();
    let out = fx.pull(&[], &[("STUB_TAMPER", "1")]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not match its digests"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fx.pulled().is_empty(), "{:?}", fx.pulled());
}

#[test]
fn old_copies_beyond_keep_are_pruned() {
    let fx = Fixture::new();
    for name in [
        "20261001T033000Z-scheduled",
        "20261002T033000Z-scheduled",
        "notes",
    ] {
        std::fs::create_dir_all(fx.dest.join(name)).unwrap();
    }
    assert!(fx.pull(&["--keep", "2"], &[]).status.success());
    assert_eq!(
        fx.pulled(),
        [
            "20261002T033000Z-scheduled",
            "20261010T033000Z-scheduled",
            "notes"
        ]
    );
}

#[test]
fn a_box_with_no_encrypted_set_is_a_failed_pull() {
    let fx = Fixture::new();
    std::fs::remove_dir_all(fx.served.join("20261009T033000Z-scheduled")).unwrap();
    std::fs::remove_dir_all(fx.served.join("20261010T033000Z-scheduled")).unwrap();
    let out = fx.pull(&[], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no encrypted backup set"));
}

#[test]
fn bad_arguments_are_usage_errors() {
    let fx = Fixture::new();
    for extra in [vec!["--keep", "0"], vec!["--keep", "lots"], vec!["--bogus"]] {
        assert_eq!(fx.pull(&extra, &[]).status.code(), Some(2), "{extra:?}");
    }
}
