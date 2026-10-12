//! Runs `deploy/backup.sh` against a scratch filesystem root (`PROPOLIS_BACKUP_ROOT`) with stub
//! `propolis`, `pg_restore` and `age` programs on `PATH`, and asserts what a set holds, that a
//! failed run leaves nothing a reader could mistake for a backup, and that the database password
//! never reaches a stub's command line. The real tar, sha256sum, flock, df and du run as shipped.
//! Lives beside deploy_test.rs, which asserts how the deploy scripts install and enable it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const SECRET: &str = "s3cret-pw";

/// The text deploy/backup.sh looks for in the binary before it runs pg-exec.
const PG_EXEC_MARKER: &str = "propolis pg-exec: DATABASE_URL is not set";

const PROPOLIS_STUB: &str = r#"#!/usr/bin/env bash
# propolis pg-exec: DATABASE_URL is not set
[ "$1" = pg-exec ] || exit 99
shift
printf '%s | url=%s\n' "$*" "${DATABASE_URL:+set}" >> "$STUB_LOG"
case "$1" in
    psql) echo "${STUB_DB_BYTES:-4096}" ;;
    pg_dump)
        [ -n "${STUB_DUMP_FAIL:-}" ] && exit 3
        if [ -n "${STUB_DUMP_SLOW:-}" ]; then
            for a in "$@"; do
                case "$a" in --file=*) printf 'PGDMP partial\n' > "${a#--file=}" ;; esac
            done
            touch "$STUB_DUMP_SLOW"
            sleep 30
        fi
        for a in "$@"; do
            case "$a" in --file=*) printf 'PGDMP fake dump\n' > "${a#--file=}" ;; esac
        done
        ;;
esac
"#;

const PG_RESTORE_STUB: &str = r#"#!/usr/bin/env bash
[ "$1" = --list ] && head -c 5 "$2" | grep -q PGDMP
"#;

const AGE_STUB: &str = r#"#!/usr/bin/env bash
[ "$1" = -R ] && [ "$3" = -o ] || exit 2
{ printf 'age-encryption.org/v1 stub\n'; cat "$5"; } > "$4"
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch dir");
        let root = dir.path().join("root");
        let bin = dir.path().join("bin");
        for sub in [
            "etc/propolis",
            "var/spool/propolis/ssh",
            "var/lib/propolis/ssh",
        ] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(
            root.join("etc/propolis/propolis.env"),
            format!("PROPOLIS_FEED_ENABLED=true\nDATABASE_URL=\"postgres://propolis:{SECRET}@localhost/propolis\"\n"),
        )
        .unwrap();
        std::fs::write(root.join("var/spool/propolis/ssh/abc"), b"sample body").unwrap();
        std::fs::write(root.join("var/lib/propolis/ssh/host_key"), b"key").unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            for (name, body) in [
                ("propolis", PROPOLIS_STUB),
                ("pg_restore", PG_RESTORE_STUB),
                ("age", AGE_STUB),
            ] {
                let path = bin.join(name);
                std::fs::write(&path, body).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        Fixture {
            _dir: dir,
            root,
            bin,
            log,
        }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/backup.sh");
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg(script)
            .args(args)
            .env("PATH", path)
            .env("PROPOLIS_BACKUP_ROOT", &self.root)
            .env("STUB_LOG", &self.log)
            .env_remove("PROPOLIS_BACKUP_DIR")
            .env_remove("PROPOLIS_BACKUP_KEEP")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().expect("bash runs")
        };
        child.wait_with_output().expect("backup.sh finishes")
    }

    fn backups(&self) -> PathBuf {
        self.root.join("var/backups/propolis")
    }

    fn sets(&self) -> Vec<String> {
        let mut sets: Vec<String> = std::fs::read_dir(self.backups())
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        sets.sort();
        sets
    }

    fn status(&self, name: &str) -> Option<serde_json::Value> {
        let text =
            std::fs::read_to_string(self.root.join("var/lib/propolis/backup-status").join(name))
                .ok()?;
        Some(serde_json::from_str(&text).expect("status file is JSON"))
    }

    fn stub_log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    files
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "backup.sh failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_set_holds_the_dump_the_state_archive_and_their_digests() {
    let fx = Fixture::new();
    let output = fx.run(&[], &[]);
    assert_ok(&output);

    let sets = fx.sets();
    assert_eq!(sets.len(), 1, "one set and no leftover partial: {sets:?}");
    let set = &sets[0];
    assert!(set.ends_with("-scheduled"), "{set}");
    let dir = fx.backups().join(set);
    assert_eq!(files_in(&dir), ["SHA256SUMS", "propolis.dump", "state.tgz"]);

    let check = Command::new("sha256sum")
        .args(["--check", "--quiet", "SHA256SUMS"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(check.status.success(), "the recorded digests verify");

    // Member names are relative to /, so `tar -xpzf state.tgz -C /` restores each file in place.
    let list = Command::new("tar")
        .args(["-tzf", "state.tgz"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let members = String::from_utf8_lossy(&list.stdout);
    for member in [
        "etc/propolis/propolis.env",
        "var/spool/propolis/ssh/abc",
        "var/lib/propolis/ssh/host_key",
    ] {
        assert!(
            members.lines().any(|m| m == member),
            "{member} missing from {members}"
        );
    }

    let status = fx.status("last-success").expect("last-success written");
    assert_eq!(status["set"], set.as_str());
    assert_eq!(status["encrypted"], false);
    assert!(fx.status("last-failure").is_none());

    let log = fx.stub_log();
    assert!(log.contains("pg_dump --format=custom --file="), "{log}");
    assert!(
        log.lines().all(|l| l.ends_with("url=set")),
        "DATABASE_URL reaches pg-exec: {log}"
    );
    assert!(
        !log.contains(SECRET),
        "the password never reaches a command line: {log}"
    );
}

#[test]
fn with_recipients_a_set_holds_only_ciphertext() {
    let fx = Fixture::new();
    std::fs::write(
        fx.root.join("etc/propolis/backup-recipients.txt"),
        "age1examplerecipient\n",
    )
    .unwrap();
    assert_ok(&fx.run(&[], &[]));
    let dir = fx.backups().join(&fx.sets()[0]);
    assert_eq!(
        files_in(&dir),
        ["SHA256SUMS", "propolis.dump.age", "state.tgz.age"],
        "no plaintext copy is kept beside the ciphertext"
    );
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    assert!(sums.contains("propolis.dump.age") && sums.contains("state.tgz.age"));
    assert_eq!(fx.status("last-success").unwrap()["encrypted"], true);
}

#[test]
fn recipients_without_age_installed_fail_closed() {
    let fx = Fixture::new();
    std::fs::remove_file(fx.bin.join("age")).unwrap();
    std::fs::write(
        fx.root.join("etc/propolis/backup-recipients.txt"),
        "age1examplerecipient\n",
    )
    .unwrap();
    // A PATH without the stub, but still with the system tools.
    let output = fx.run(&[], &[]);
    if Command::new("sh")
        .args(["-c", "command -v age"])
        .output()
        .unwrap()
        .status
        .success()
    {
        // A host with a real age installed would encrypt for real; nothing to assert here.
        return;
    }
    assert!(
        !output.status.success(),
        "must not fall back to a plaintext set"
    );
    assert!(fx.sets().is_empty(), "{:?}", fx.sets());
    assert_eq!(
        fx.status("last-failure").unwrap()["step"],
        "finding the tools"
    );
}

#[test]
fn a_failed_dump_leaves_no_set_and_records_the_step() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&[], &[]));
    let before = fx.status("last-success").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let output = fx.run(&[], &[("STUB_DUMP_FAIL", "1")]);
    assert!(!output.status.success());
    assert_eq!(
        fx.sets().len(),
        1,
        "only the earlier good set remains: {:?}",
        fx.sets()
    );
    assert!(fx.sets().iter().all(|s| !s.starts_with(".partial")));
    let failure = fx.status("last-failure").expect("last-failure written");
    assert_eq!(failure["step"], "dumping the database");
    assert_eq!(
        fx.status("last-success").unwrap(),
        before,
        "a failure leaves the last good backup's record alone"
    );

    // The next good run clears the failure.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_ok(&fx.run(&[], &[]));
    assert!(fx.status("last-failure").is_none());
}

#[test]
fn without_a_database_url_it_records_not_configured_and_succeeds() {
    let fx = Fixture::new();
    std::fs::write(
        fx.root.join("etc/propolis/propolis.env"),
        "PROPOLIS_FEED_ENABLED=true\n",
    )
    .unwrap();
    assert_ok(&fx.run(&[], &[]));
    assert!(fx.sets().is_empty());
    let status = fx.status("last-failure").unwrap();
    assert!(
        status["step"]
            .as_str()
            .unwrap()
            .starts_with("not configured"),
        "{status}"
    );
    assert!(fx.stub_log().is_empty(), "nothing was dumped");
}

#[test]
fn too_little_space_refuses_before_dumping() {
    let fx = Fixture::new();
    let output = fx.run(&[], &[("STUB_DB_BYTES", "900000000000000000")]);
    assert!(!output.status.success());
    assert!(fx.sets().is_empty());
    assert_eq!(
        fx.status("last-failure").unwrap()["step"],
        "checking free space"
    );
    assert!(
        !fx.stub_log().contains("pg_dump"),
        "refused before the dump started"
    );
}

#[test]
fn old_sets_beyond_keep_are_pruned_and_the_other_reason_is_left_alone() {
    let fx = Fixture::new();
    for set in [
        "20200101T000000Z-scheduled",
        "20200102T000000Z-scheduled",
        "20200103T000000Z-scheduled",
        "20200101T000000Z-pre-upgrade",
    ] {
        std::fs::create_dir_all(fx.backups().join(set)).unwrap();
    }
    std::fs::create_dir_all(fx.backups().join("not-a-set")).unwrap();
    assert_ok(&fx.run(&[], &[("PROPOLIS_BACKUP_KEEP", "2")]));
    let sets = fx.sets();
    assert!(
        !sets.contains(&"20200101T000000Z-scheduled".to_string()),
        "{sets:?}"
    );
    assert!(
        !sets.contains(&"20200102T000000Z-scheduled".to_string()),
        "{sets:?}"
    );
    assert!(
        sets.contains(&"20200103T000000Z-scheduled".to_string()),
        "{sets:?}"
    );
    assert!(
        sets.contains(&"20200101T000000Z-pre-upgrade".to_string()),
        "{sets:?}"
    );
    assert!(
        sets.contains(&"not-a-set".to_string()),
        "never deletes a name it did not make"
    );
    assert_eq!(sets.iter().filter(|s| s.ends_with("-scheduled")).count(), 2);
}

#[test]
fn a_pre_upgrade_set_is_named_for_its_reason() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--reason", "pre-upgrade"], &[]));
    assert!(fx.sets()[0].ends_with("-pre-upgrade"), "{:?}", fx.sets());
    assert_eq!(fx.status("last-success").unwrap()["reason"], "pre-upgrade");
}

#[test]
fn bad_arguments_and_a_bad_keep_are_usage_errors() {
    let fx = Fixture::new();
    for (args, env) in [
        (vec!["--reason", "nightly"], vec![]),
        (vec!["--bogus"], vec![]),
        (vec![], vec![("PROPOLIS_BACKUP_KEEP", "0")]),
        (vec![], vec![("PROPOLIS_BACKUP_KEEP", "7days")]),
    ] {
        let output = fx.run(&args, &env);
        assert_eq!(output.status.code(), Some(2), "{args:?} {env:?}");
    }
    assert!(fx.sets().is_empty());
}

/// A propolis binary from before pg-exec would start the daemon when handed `pg-exec`; the script
/// looks for pg-exec's own message in the binary and refuses one without it, running nothing.
#[test]
fn a_binary_without_pg_exec_is_refused_without_running_it() {
    let fx = Fixture::new();
    {
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        let old = PROPOLIS_STUB.replace(PG_EXEC_MARKER, "an older release");
        std::fs::write(fx.bin.join("propolis"), old).unwrap();
    }
    let output = fx.run(&[], &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("has no pg-exec"));
    assert!(fx.stub_log().is_empty(), "the binary was never run");
    assert!(fx.sets().is_empty());

    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../propolis/src/pg_exec.rs"
    ))
    .unwrap();
    assert!(
        source.contains(PG_EXEC_MARKER),
        "deploy/backup.sh looks for text pg_exec.rs no longer prints"
    );
    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/backup.sh"
    ))
    .unwrap();
    assert!(script.contains(PG_EXEC_MARKER));
}

/// The spools' .staging directories (a sample between its write and its rename) stay out of the
/// archive, and a half-written set a killed run left behind is cleared under the lock.
#[test]
fn staging_files_are_not_archived_and_a_killed_runs_partial_set_is_cleared() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.root.join("var/spool/propolis/ssh/.staging")).unwrap();
    std::fs::write(
        fx.root.join("var/spool/propolis/ssh/.staging/inflight"),
        b"x",
    )
    .unwrap();
    let stale = fx.backups().join(".partial-20200101T000000Z-scheduled");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("propolis.dump"), b"plaintext").unwrap();

    assert_ok(&fx.run(&[], &[]));
    assert!(!stale.exists(), "the leftover partial set is gone");
    let set = fx.backups().join(&fx.sets()[0]);
    let list = Command::new("tar")
        .args(["-tzf", "state.tgz"])
        .current_dir(&set)
        .output()
        .unwrap();
    let members = String::from_utf8_lossy(&list.stdout);
    assert!(!members.contains(".staging"), "{members}");
    assert!(members.contains("var/spool/propolis/ssh/abc"), "{members}");
}

/// Stopped mid-dump the way systemd stops a unit (TERM to the whole group), the run removes its
/// half-written set and records where it was.
#[test]
fn a_run_stopped_mid_dump_leaves_no_partial_set() {
    use std::os::unix::process::CommandExt;
    let fx = Fixture::new();
    let started = fx.root.join("dump-started");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/backup.sh");
    let path = format!("{}:{}", fx.bin.display(), std::env::var("PATH").unwrap());
    let mut command = Command::new("bash");
    command
        .arg(script)
        .env("PATH", path)
        .env("PROPOLIS_BACKUP_ROOT", &fx.root)
        .env("STUB_LOG", &fx.log)
        .env("STUB_DUMP_SLOW", &started)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = {
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        command.spawn().unwrap()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !started.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the dump never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let group = format!("-{}", child.id());
    Command::new("kill")
        .args(["-TERM", "--", &group])
        .status()
        .unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());
    let leftovers: Vec<String> = std::fs::read_dir(fx.backups())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "nothing is left behind: {leftovers:?}"
    );
    let failure = fx
        .status("last-failure")
        .expect("the interruption is recorded");
    assert_eq!(failure["step"], "interrupted while dumping the database");
}
