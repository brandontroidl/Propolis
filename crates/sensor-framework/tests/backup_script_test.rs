//! Runs `deploy/backup.sh` against a scratch filesystem root (`PROPOLIS_BACKUP_ROOT`) with stub
//! `propolis`, `pg_restore` and `age` programs on `PATH`, and asserts what a set holds, that a
//! failed run leaves nothing a reader could mistake for a backup, and that the database password
//! never reaches a stub's command line. The real tar, sha256sum, flock and du run as shipped; `df` is a
//! stub so the volume's size and free space are whatever each test says.
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
        [ -n "${STUB_SNAPSHOT:-}" ] && ls -1A "$PROPOLIS_BACKUP_ROOT/var/backups/propolis" > "$STUB_SNAPSHOT"
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

/// A `df` that reports the volume the test says it is, so the headroom rules do not depend on how
/// full the machine running the tests is. By default it is a roomy 1 TiB volume. STUB_DF_SIZE and
/// STUB_DF_AVAIL set the figures; STUB_DF_SHARE_DIR makes the free space shrink with the apparent
/// size of that directory, so a prune that happens before the check is visible to it.
const DF_STUB: &str = r#"#!/usr/bin/env bash
size="${STUB_DF_SIZE:-1099511627776}"
avail="${STUB_DF_AVAIL:-$size}"
if [ -n "${STUB_DF_SHARE_DIR:-}" ]; then
    used="$(du -s -b --apparent-size "$STUB_DF_SHARE_DIR" | cut -f1)"
    avail=$(( size - used ))
fi
case "$1" in
    --output=avail) printf 'Avail\n%s\n' "$avail" ;;
    --output=size,avail) printf 'Size Avail\n%s %s\n' "$size" "$avail" ;;
    *) exit 2 ;;
esac
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
                ("df", DF_STUB),
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

/// Write a `last-success` status as an earlier run would have left it.
fn seed_last_success(fx: &Fixture, body: &str) {
    let dir = fx.root.join("var/lib/propolis/backup-status");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("last-success"), format!("{body}\n")).unwrap();
}

// The database size alone (here far past any disk) would refuse the run; the last set's real size,
// scaled by how much the source grew since it was taken, is what the check must use. Live, a 5.9 GB
// source made a 1.07 GB set and the raw-size rule refused an upgrade on a disk with 6 GB free.
#[test]
fn the_space_check_scales_the_last_sets_real_size_not_the_raw_database() {
    let fx = Fixture::new();
    seed_last_success(
        &fx,
        r#"{"completed_at":"2026-10-14T09:04:27Z","reason":"pre-upgrade","set":"20261014T090129Z-pre-upgrade","encrypted":false,"dump_bytes":1000,"archive_bytes":1000,"source_bytes":900000000000000000}"#,
    );
    let output = fx.run(&[], &[("STUB_DB_BYTES", "900000000000000000")]);
    assert_ok(&output);
    assert_eq!(fx.sets().len(), 1, "the set was written");
}

// A status from before source_bytes was recorded (the live box's, the first night after this
// change) has no growth figure: half again the last set is allowed, never more than the raw rule.
#[test]
fn a_status_without_source_bytes_allows_half_again_the_last_set() {
    let fx = Fixture::new();
    seed_last_success(
        &fx,
        r#"{"completed_at":"2026-10-14T09:04:27Z","reason":"pre-upgrade","set":"20261014T090129Z-pre-upgrade","encrypted":false,"dump_bytes":1000,"archive_bytes":1000}"#,
    );
    let output = fx.run(&[], &[("STUB_DB_BYTES", "900000000000000000")]);
    assert_ok(&output);
}

// The scaling must still refuse a run that will not fit: a last set as large as this disk could
// ever hold is a real "no room", whatever the raw rule would say.
#[test]
fn a_last_set_too_large_for_the_disk_still_refuses() {
    let fx = Fixture::new();
    seed_last_success(
        &fx,
        r#"{"completed_at":"2026-10-14T09:04:27Z","reason":"scheduled","set":"20261014T033000Z-scheduled","encrypted":false,"dump_bytes":900000000000000,"archive_bytes":900000000000000,"source_bytes":4096}"#,
    );
    let output = fx.run(&[], &[]);
    assert!(!output.status.success(), "a set this size cannot fit");
    assert_eq!(
        fx.status("last-failure").unwrap()["step"],
        "checking free space"
    );
    assert!(!fx.stub_log().contains("pg_dump"), "refused before dumping");
}

#[test]
fn a_good_run_records_the_source_size_for_the_next_estimate() {
    let fx = Fixture::new();
    let output = fx.run(&[], &[("STUB_DB_BYTES", "4096")]);
    assert_ok(&output);
    let status = fx.status("last-success").unwrap();
    let source = status["source_bytes"]
        .as_u64()
        .expect("source_bytes recorded");
    assert!(
        source >= 4096,
        "source_bytes counts the database ({source})"
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

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn make_set(fx: &Fixture, name: &str) {
    let dir = fx.backups().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("propolis.dump"), b"PGDMP old").unwrap();
}

// Retention used to run only after a good write, so the volume held KEEP+1 sets while the new one
// was written. The old sets beyond KEEP-1 must be gone by the time the dump starts.
#[test]
fn old_sets_are_pruned_before_the_dump_starts() {
    let fx = Fixture::new();
    for day in 1..=4 {
        make_set(&fx, &format!("2020010{day}T000000Z-scheduled"));
    }
    make_set(&fx, "20200101T000000Z-pre-upgrade");
    let snapshot = fx.root.join("listing-at-dump");
    assert_ok(&fx.run(
        &[],
        &[
            ("PROPOLIS_BACKUP_KEEP", "3"),
            ("STUB_SNAPSHOT", snapshot.to_str().unwrap()),
        ],
    ));
    let at_dump: Vec<String> = std::fs::read_to_string(&snapshot)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let scheduled_at_dump: Vec<&String> = at_dump
        .iter()
        .filter(|n| n.ends_with("-scheduled") && !n.starts_with('.'))
        .collect();
    assert_eq!(
        scheduled_at_dump,
        ["20200103T000000Z-scheduled", "20200104T000000Z-scheduled"],
        "KEEP-1 newest sets remain when the dump starts: {at_dump:?}"
    );
    assert!(
        at_dump.contains(&"20200101T000000Z-pre-upgrade".to_string()),
        "the other reason is untouched: {at_dump:?}"
    );
    assert_eq!(
        fx.sets()
            .iter()
            .filter(|s| s.ends_with("-scheduled"))
            .count(),
        3,
        "KEEP sets once the new one lands: {:?}",
        fx.sets()
    );
}

// Pruning ahead of the write must never cost the newest good set: a run that then fails leaves the
// newest KEEP-1 sets, and with KEEP=1 the only good set survives both the prune and the failure.
#[test]
fn pruning_before_the_write_keeps_the_newest_good_sets() {
    let fx = Fixture::new();
    for day in 1..=3 {
        make_set(&fx, &format!("2020010{day}T000000Z-scheduled"));
    }
    let snapshot = fx.root.join("listing-at-dump");
    let output = fx.run(
        &[],
        &[
            ("PROPOLIS_BACKUP_KEEP", "1"),
            ("STUB_DUMP_FAIL", "1"),
            ("STUB_SNAPSHOT", snapshot.to_str().unwrap()),
        ],
    );
    assert!(!output.status.success());
    assert_eq!(
        fx.sets(),
        ["20200103T000000Z-scheduled"],
        "KEEP=1 still leaves the newest good set after a failed run"
    );
    let at_dump = std::fs::read_to_string(&snapshot).unwrap();
    assert!(
        at_dump.contains("20200103T000000Z-scheduled"),
        "the only good set was present while the new one was dumped: {at_dump}"
    );

    let fx = Fixture::new();
    for day in 1..=4 {
        make_set(&fx, &format!("2020010{day}T000000Z-pre-upgrade"));
    }
    let output = fx.run(&["--reason", "pre-upgrade"], &[("STUB_DUMP_FAIL", "1")]);
    assert!(!output.status.success());
    assert_eq!(
        fx.sets(),
        [
            "20200103T000000Z-pre-upgrade",
            "20200104T000000Z-pre-upgrade"
        ],
        "pre-upgrade keeps 3, so 2 stand while the third is written"
    );
}

// Free space that retention gives back counts: three 600 MiB sets leave a 2 GiB volume under the
// 512 MiB reserve, and the run passes only because the prune ran before the check.
#[test]
fn the_prune_frees_room_the_headroom_check_then_counts() {
    let fx = Fixture::new();
    for day in 1..=3 {
        let name = format!("2020010{day}T000000Z-scheduled");
        make_set(&fx, &name);
        let dump = std::fs::OpenOptions::new()
            .write(true)
            .open(fx.backups().join(&name).join("propolis.dump"))
            .unwrap();
        dump.set_len(600 * MIB).unwrap();
    }
    let backups = fx.backups();
    let output = fx.run(
        &[],
        &[
            ("PROPOLIS_BACKUP_KEEP", "2"),
            ("STUB_DF_SIZE", &(2 * GIB).to_string()),
            ("STUB_DF_SHARE_DIR", backups.to_str().unwrap()),
        ],
    );
    assert_ok(&output);
    assert_eq!(fx.sets().len(), 2, "{:?}", fx.sets());
}

// The live incident: a set that fits, written to a volume it leaves under the monitor's 15%
// low-disk line, starved log rotation. The run must refuse before pg_dump, naming the shortfall
// and the two fixes.
#[test]
fn a_set_that_would_leave_the_volume_under_the_low_disk_threshold_refuses() {
    let fx = Fixture::new();
    // 100 GiB volume, 14 GiB free: the set fits but free space is already under 15%.
    let output = fx.run(
        &[],
        &[
            ("STUB_DF_SIZE", &(100 * GIB).to_string()),
            ("STUB_DF_AVAIL", &(14 * GIB).to_string()),
        ],
    );
    assert!(!output.status.success());
    assert!(fx.sets().is_empty());
    assert!(
        !fx.stub_log().contains("pg_dump"),
        "refused before the dump started"
    );
    assert_eq!(
        fx.status("last-failure").unwrap()["step"],
        "checking free space"
    );
    let err = stderr_of(&output);
    for needle in [
        "15%",
        "short by",
        "PROPOLIS_BACKUP_KEEP",
        "PROPOLIS_BACKUP_DIR",
    ] {
        assert!(err.contains(needle), "{needle} missing from: {err}");
    }
}

// The threshold is the monitor's own setting, read from propolis.env, not a copy.
#[test]
fn the_threshold_is_read_from_the_monitors_setting() {
    let fx = Fixture::new();
    let env = fx.root.join("etc/propolis/propolis.env");
    let base = std::fs::read_to_string(&env).unwrap();
    let df = [
        ("STUB_DF_SIZE", (100 * GIB).to_string()),
        ("STUB_DF_AVAIL", (14 * GIB).to_string()),
    ];
    let df: Vec<(&str, &str)> = df.iter().map(|(k, v)| (*k, v.as_str())).collect();

    std::fs::write(&env, format!("{base}PROPOLIS_OPS_CAPACITY_FREE_PCT=10\n")).unwrap();
    assert_ok(&fx.run(&[], &df));

    std::fs::write(&env, format!("{base}PROPOLIS_OPS_CAPACITY_FREE_PCT=30\n")).unwrap();
    let output = fx.run(&[], &df);
    assert!(!output.status.success(), "30% of 100 GiB is not free");
    assert!(stderr_of(&output).contains("30%"), "{}", stderr_of(&output));

    // A value the daemon would refuse to start on leaves its default in force.
    std::fs::write(&env, format!("{base}PROPOLIS_OPS_CAPACITY_FREE_PCT=0\n")).unwrap();
    let output = fx.run(&[], &df);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("15%"), "{}", stderr_of(&output));
}

// The value is read as the daemon reads it: whitespace around the key, the '=' and the value, a
// leading '+' and leading zeros accepted, the last assignment wins, and a value the daemon refuses
// to start on (0, over 100, not a number, too long for a u64) leaves 15. Every row is at least 15,
// so the volume below (14% free) refuses under all of them and the message names the figure used.
// config_check_test.rs runs the same table through config-check.sh.
#[test]
fn the_threshold_is_parsed_as_the_daemon_parses_it() {
    const TABLE: &[(&str, u32)] = include!("fixtures/low_disk_table.in");
    let df = [
        ("STUB_DF_SIZE", (100 * GIB).to_string()),
        ("STUB_DF_AVAIL", (14 * GIB).to_string()),
    ];
    let df: Vec<(&str, &str)> = df.iter().map(|(k, v)| (*k, v.as_str())).collect();
    for (line, pct) in TABLE {
        let fx = Fixture::new();
        let env = fx.root.join("etc/propolis/propolis.env");
        let base = std::fs::read_to_string(&env).unwrap();
        std::fs::write(&env, format!("{base}{line}\n")).unwrap();
        let output = fx.run(&[], &df);
        assert!(
            !output.status.success(),
            "{line:?} left 14% free acceptable"
        );
        let want = format!("the larger of the {pct}% low-disk threshold");
        assert!(
            stderr_of(&output).contains(&want),
            "{line:?} should read as {pct}: {}",
            stderr_of(&output)
        );
    }
}

// The line is `avail >= need + keep_free`: exactly that much free passes and one byte less does not,
// and the threshold's share is rounded UP (15% of 10 000 000 050 is 1 500 000 007.5, so 8 not 7).
// With no source size recorded and a small database the estimate is the last set, to the byte.
#[test]
fn the_free_space_line_is_exact_and_the_share_is_rounded_up() {
    let size: u64 = 10_000_000_050;
    let keep_free: u64 = 1_500_000_008;
    let set: u64 = 100_000_000;
    let last = r#"{"completed_at":"2026-10-14T09:04:27Z","reason":"scheduled","set":"20261014T033000Z-scheduled","encrypted":false,"dump_bytes":99999000,"archive_bytes":1000}"#;
    for (avail, passes) in [(set + keep_free, true), (set + keep_free - 1, false)] {
        let fx = Fixture::new();
        seed_last_success(&fx, last);
        let output = fx.run(
            &[],
            &[
                ("STUB_DF_SIZE", &size.to_string()),
                ("STUB_DF_AVAIL", &avail.to_string()),
            ],
        );
        assert_eq!(
            output.status.success(),
            passes,
            "avail {avail}: {}",
            stderr_of(&output)
        );
        if !passes {
            assert!(
                stderr_of(&output).contains("short by 1 bytes"),
                "{}",
                stderr_of(&output)
            );
        }
    }
}

// A refusal names the remedy that works for the run that was refused. A scheduled run's KEEP is the
// operator's to lower; a pre-upgrade run's is fixed at 3, so "lower KEEP" would be advice that
// changes nothing, and the way out of a blocked upgrade is different.
#[test]
fn the_refusal_names_the_remedy_for_its_reason() {
    let df = [
        ("STUB_DF_SIZE", (100 * GIB).to_string()),
        ("STUB_DF_AVAIL", (14 * GIB).to_string()),
    ];
    let df: Vec<(&str, &str)> = df.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let fx = Fixture::new();
    let output = fx.run(&["--reason", "scheduled"], &df);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("Lower PROPOLIS_BACKUP_KEEP (now 7)"), "{err}");
    assert!(err.contains("PROPOLIS_BACKUP_DIR"), "{err}");
    assert!(!err.contains("PROPOLIS_UPGRADE_SKIP_BACKUP"), "{err}");

    let fx = Fixture::new();
    let output = fx.run(&["--reason", "pre-upgrade"], &df);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("PROPOLIS_UPGRADE_SKIP_BACKUP=1"), "{err}");
    assert!(
        err.contains("run a scheduled backup with a lower PROPOLIS_BACKUP_KEEP"),
        "{err}"
    );
    assert!(err.contains("PROPOLIS_BACKUP_DIR"), "{err}");
    assert!(!err.contains("(now"), "pre-upgrade's KEEP is fixed: {err}");
    assert!(!err.contains("Lower PROPOLIS_BACKUP_KEEP"), "{err}");
}

// Under the threshold's share the logrotate guard's 512 MiB reserve still binds: a small volume has
// 15% below the reserve.
#[test]
fn the_logrotate_reserve_binds_on_a_small_volume() {
    let fx = Fixture::new();
    // 15% of 2 GiB is 307 MiB; 450 MiB free is over that and under the 512 MiB reserve.
    let output = fx.run(
        &[],
        &[
            ("STUB_DF_SIZE", &(2 * GIB).to_string()),
            ("STUB_DF_AVAIL", &(450 * MIB).to_string()),
        ],
    );
    assert!(!output.status.success());
    assert!(!fx.stub_log().contains("pg_dump"));
    assert!(
        stderr_of(&output).contains("536870912"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn a_volume_with_room_to_spare_writes_the_set() {
    let fx = Fixture::new();
    let output = fx.run(
        &[],
        &[
            ("STUB_DF_SIZE", &(100 * GIB).to_string()),
            ("STUB_DF_AVAIL", &(50 * GIB).to_string()),
        ],
    );
    assert_ok(&output);
    assert_eq!(fx.sets().len(), 1);
}

// The script cannot import the daemon's default or the guard's reserve, so it carries both and
// this fails when either source moves.
#[test]
fn the_headroom_constants_agree_with_the_monitor_and_the_guard() {
    let read = |rel: &str| {
        std::fs::read_to_string(format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    };
    let script = read("deploy/backup.sh");
    let config = read("crates/propolis/src/ops_alert/config.rs");
    let guard = read("deploy/logrotate-guard.sh");

    let daemon_default = config
        .lines()
        .find_map(|l| {
            l.split("get_pct(get, \"PROPOLIS_OPS_CAPACITY_FREE_PCT\", ")
                .nth(1)
        })
        .and_then(|rest| rest.split(')').next())
        .expect("the daemon's default is readable");
    assert!(
        script.contains(&format!("DEFAULT_LOW_DISK_PCT={daemon_default}\n")),
        "backup.sh default differs from the daemon's {daemon_default}"
    );

    let guard_reserve = guard
        .lines()
        .find_map(|l| l.split("PROPOLIS_LOGROTATE_RESERVE_BYTES:-").nth(1))
        .and_then(|rest| rest.split('}').next())
        .expect("the guard's reserve is readable");
    assert!(
        script.contains(&format!("LOGROTATE_RESERVE_BYTES={guard_reserve}\n")),
        "backup.sh reserve differs from the guard's {guard_reserve}"
    );
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
