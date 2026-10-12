//! Runs `deploy/rollback.sh` against a scratch filesystem root (`PROPOLIS_ROLLBACK_ROOT`) with stub
//! `systemctl`, `runuser`, `journalctl`, `id`, `age` and `propolis` programs on `PATH`, and
//! asserts what `--save` keeps, that a rollback puts exactly those files back and restarts in
//! order, that a database rollback renames the current database aside rather than dropping it,
//! and that every refusal happens before a service is stopped.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const SET: &str = "20261011T120000Z-pre-upgrade";

const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$STUB_LOG"
case "$1" in
    is-enabled) [[ " ${STUB_ENABLED:-} " == *" ${3:-$2} "* ]] ;;
    is-active) [ -z "${STUB_INACTIVE:-}" ] ;;
    *) exit 0 ;;
esac
"#;

const RUNUSER_STUB: &str = r#"#!/usr/bin/env bash
shift 3
printf 'runuser %s\n' "$*" >> "$STUB_LOG"
if [ -n "${STUB_RUNUSER_FAIL:-}" ] && [[ "$*" == *"$STUB_RUNUSER_FAIL"* ]]; then exit 1; fi
if [ "$1" = pg_restore ]; then printf 'restored %s bytes\n' "$(wc -c)" >> "$STUB_LOG"; fi
"#;

const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
printf '%s\n' "${STUB_JOURNAL:-}"
"#;

const ID_STUB: &str = r#"#!/usr/bin/env bash
if [ "$1" = -u ] && [ "${2:-}" = postgres ]; then
    [ -n "${STUB_NO_POSTGRES:-}" ] && exit 1
    echo 26
else
    exec /usr/bin/id "$@"
fi
"#;

const AGE_STUB: &str = r#"#!/usr/bin/env bash
[ "$1" = --decrypt ] && [ "$2" = -i ] || exit 2
tail -n +2 "$4"
"#;

fn propolis_stub(commit: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
case "$1" in
    --version) echo "propolis 0.4.0 ({commit}, built 2026-10-11T00:00:00Z)" ;;
    pg-exec)
        [ -n "${{DATABASE_URL:-}}" ] || {{ echo "propolis pg-exec: DATABASE_URL is not set" >&2; exit 1; }}
        case "$*" in
            *current_database*) echo propolis ;;
            *current_user*) echo propolis ;;
        esac
        ;;
esac
"#
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

fn write_exec(path: &Path, body: &str) {
    let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    /// A box running release `abc000000001` with a pre-upgrade backup on record.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch dir");
        let root = dir.path().join("root");
        let bin = dir.path().join("bin");
        write_exec(
            &root.join("usr/local/bin/propolis"),
            &propolis_stub("abc000000001"),
        );
        write_exec(
            &root.join("usr/local/bin/sensor-ssh"),
            "#!/bin/sh\necho old sensor\n",
        );
        write_exec(
            &root.join("usr/local/sbin/propolis-backup"),
            "#!/bin/sh\necho old backup\n",
        );
        let units = root.join("etc/systemd/system");
        std::fs::create_dir_all(&units).unwrap();
        for (name, body) in [
            ("propolis.service", "[Service]\nExecStart=old\n"),
            ("sensor-ssh.service", "[Service]\nExecStart=old-ssh\n"),
            ("propolis-backup.timer", "[Timer]\nOnCalendar=old\n"),
            ("unrelated.service", "[Service]\n"),
        ] {
            std::fs::write(units.join(name), body).unwrap();
        }
        std::fs::create_dir_all(root.join("etc/propolis")).unwrap();
        std::fs::write(
            root.join("etc/propolis/propolis.env"),
            "DATABASE_URL=\"postgres://propolis:pw@localhost/propolis\"\n",
        )
        .unwrap();
        let state = root.join("var/lib/propolis");
        std::fs::create_dir_all(state.join("backup-status")).unwrap();
        std::fs::write(state.join("deploy-stamp.json"), "{\"head\":\"old\"}\n").unwrap();
        std::fs::write(
            state.join("backup-status/last-success"),
            format!("{{\"completed_at\":\"2026-10-11T12:00:01Z\",\"reason\":\"pre-upgrade\",\"set\":\"{SET}\",\"encrypted\":false}}\n"),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("var/backups/propolis").join(SET)).unwrap();
        std::fs::write(
            root.join("var/backups/propolis")
                .join(SET)
                .join("propolis.dump"),
            "PGDMP0123456789",
        )
        .unwrap();
        for (name, body) in [
            ("systemctl", SYSTEMCTL_STUB),
            ("runuser", RUNUSER_STUB),
            ("journalctl", JOURNALCTL_STUB),
            ("id", ID_STUB),
            ("age", AGE_STUB),
        ] {
            write_exec(&bin.join(name), body);
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

    fn run(&self, args: &[&str], env: &[(&str, &str)], stdin: Option<&str>) -> Output {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/rollback.sh");
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg(script)
            .args(args)
            .env("PATH", path)
            .env("PROPOLIS_ROLLBACK_ROOT", &self.root)
            .env("PROPOLIS_ROLLBACK_WAIT_SECS", "2")
            .env("STUB_LOG", &self.log)
            .env("STUB_ENABLED", "propolis.service sensor-ssh.service")
            .envs(env.iter().copied())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().expect("bash runs")
        };
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        child.wait_with_output().expect("rollback.sh finishes")
    }

    fn store(&self) -> PathBuf {
        self.root.join("var/lib/propolis/rollback")
    }

    fn releases(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.store())
            .map(|e| {
                e.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }

    /// What the upgrade does after `--save`: new binaries, helpers and units on disk.
    fn upgrade(&self) {
        write_exec(
            &self.root.join("usr/local/bin/propolis"),
            &propolis_stub("def000000002"),
        );
        write_exec(
            &self.root.join("usr/local/bin/sensor-ssh"),
            "#!/bin/sh\necho new sensor\n",
        );
        std::fs::write(
            self.root.join("etc/systemd/system/propolis.service"),
            "[Service]\nExecStart=new\n",
        )
        .unwrap();
        std::fs::write(
            self.root.join("var/lib/propolis/deploy-stamp.json"),
            "{\"head\":\"new\"}\n",
        )
        .unwrap();
    }
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "rollback.sh failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn save_keeps_the_named_binaries_the_units_the_helpers_the_stamp_and_the_backup_set() {
    let fx = Fixture::new();
    assert_ok(&fx.run(
        &[
            "--save",
            "--backup-set",
            SET,
            "propolis",
            "sensor-ssh",
            "gateway",
        ],
        &[],
        None,
    ));
    let releases = fx.releases();
    assert_eq!(releases.len(), 1, "{releases:?}");
    assert!(releases[0].ends_with("-abc000000001"), "{releases:?}");
    let kept = fx.store().join(&releases[0]);
    assert!(read(&kept.join("bin/sensor-ssh")).contains("old sensor"));
    assert!(kept.join("bin/propolis").exists());
    assert!(
        !kept.join("bin/gateway").exists(),
        "a binary not installed is skipped"
    );
    assert!(read(&kept.join("sbin/propolis-backup")).contains("old backup"));
    for unit in [
        "propolis.service",
        "sensor-ssh.service",
        "propolis-backup.timer",
    ] {
        assert!(kept.join("units").join(unit).exists(), "{unit} kept");
    }
    assert!(
        !kept.join("units/unrelated.service").exists(),
        "only Propolis units are kept"
    );
    assert!(read(&kept.join("deploy-stamp.json")).contains("old"));
    let manifest = read(&kept.join("manifest"));
    assert!(manifest.contains("commit=abc000000001"), "{manifest}");
    assert!(
        manifest.contains(&format!("backup_set={SET}")),
        "{manifest}"
    );
}

#[test]
fn save_keeps_the_newest_three_and_never_deletes_a_name_it_did_not_make() {
    let fx = Fixture::new();
    for name in [
        "20200101T000000Z-aaaa00000001",
        "20200102T000000Z-aaaa00000002",
        "20200103T000000Z-aaaa00000003",
        "not-a-release",
    ] {
        std::fs::create_dir_all(fx.store().join(name)).unwrap();
    }
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let releases = fx.releases();
    assert!(
        !releases.contains(&"20200101T000000Z-aaaa00000001".to_string()),
        "{releases:?}"
    );
    assert!(
        releases.contains(&"20200102T000000Z-aaaa00000002".to_string()),
        "{releases:?}"
    );
    assert!(releases.contains(&"not-a-release".to_string()));
    assert_eq!(
        releases.len(),
        4,
        "three releases plus the foreign name: {releases:?}"
    );
}

/// The kept release records only the set upgrade.sh names. An older pre-upgrade set on record is
/// never picked up in its place: restoring it would roll the database back past an earlier upgrade.
#[test]
fn save_records_only_the_named_set_never_an_older_one_on_record() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "propolis"], &[], None));
    let kept = fx.store().join(&fx.releases()[0]);
    let manifest = read(&kept.join("manifest"));
    assert!(manifest.contains("backup_set=\n"), "{manifest}");
    assert_eq!(
        fx.run(
            &["--save", "--backup-set", "../../etc", "propolis"],
            &[],
            None
        )
        .status
        .code(),
        Some(2),
        "a set name of the wrong shape is refused"
    );
}

/// The database names are read, and a missing DATABASE_URL refused, while everything still runs.
#[test]
fn a_database_rollback_without_a_url_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    std::fs::write(
        fx.root.join("etc/propolis/propolis.env"),
        "PROPOLIS_FEED_ENABLED=true\n",
    )
    .unwrap();
    let out = fx.run(&["--with-database", "--yes"], &[], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no DATABASE_URL"));
    assert!(!fx.log().contains("systemctl stop"), "{}", fx.log());
}

/// A step that fails after the services are stopped says where the box is, names the database it
/// renamed aside, and starts the services again rather than leaving the honeypot dark.
#[test]
fn a_failure_after_stopping_reports_the_state_and_starts_the_services_again() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_RUNUSER_FAIL", "CREATE DATABASE")],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("while creating the empty database"),
        "{stderr}"
    );
    assert!(
        stderr.contains("renamed to propolis_before_rollback_"),
        "{stderr}"
    );
    let log = fx.log();
    let failed = log.find("CREATE DATABASE").unwrap();
    assert!(
        log[failed..].contains("systemctl start propolis.service"),
        "the services are started again after the failure: {log}"
    );
}

/// Rolling back to a release from before the nightly backup turns its timer off: that release's
/// binary has no pg-exec, and the newer backup script would start it as the daemon.
#[test]
fn rolling_back_past_the_backup_helper_disables_the_backup_timer() {
    let fx = Fixture::new();
    std::fs::remove_file(fx.root.join("usr/local/sbin/propolis-backup")).unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    assert_ok(&fx.run(&["--yes"], &[], None));
    assert!(
        fx.log()
            .contains("systemctl disable --now propolis-backup.timer"),
        "{}",
        fx.log()
    );
}

#[test]
fn save_without_an_installed_binary_keeps_nothing_and_succeeds() {
    let fx = Fixture::new();
    std::fs::remove_file(fx.root.join("usr/local/bin/propolis")).unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    assert!(fx.releases().is_empty());
}

#[test]
fn a_rollback_puts_exactly_the_kept_files_back_and_restarts_in_order() {
    let fx = Fixture::new();
    assert_ok(&fx.run(
        &["--save", "--backup-set", SET, "propolis", "sensor-ssh"],
        &[],
        None,
    ));
    fx.upgrade();
    let output = fx.run(&["--yes"], &[], None);
    assert_ok(&output);

    assert!(read(&fx.root.join("usr/local/bin/sensor-ssh")).contains("old sensor"));
    let version = Command::new(fx.root.join("usr/local/bin/propolis"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains("abc000000001"));
    assert!(read(&fx.root.join("etc/systemd/system/propolis.service")).contains("ExecStart=old"));
    assert!(read(&fx.root.join("var/lib/propolis/deploy-stamp.json")).contains("old"));

    let log = fx.log();
    let at = |needle: &str| {
        log.find(needle)
            .unwrap_or_else(|| panic!("{needle:?} missing from {log}"))
    };
    assert!(at("systemctl stop propolis.service") < at("systemctl daemon-reload"));
    assert!(at("systemctl stop sensor-ssh.service") < at("systemctl daemon-reload"));
    assert!(at("systemctl daemon-reload") < at("systemctl start sensor-ssh.service"));
    assert!(at("systemctl start sensor-ssh.service") < at("systemctl start propolis.service"));
    assert!(
        !log.contains("runuser"),
        "no database change without --with-database: {log}"
    );
}

#[test]
fn a_database_rollback_renames_the_current_database_aside_and_restores_the_dump() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let output = fx.run(&["--with-database", "--yes"], &[], None);
    assert_ok(&output);
    let log = fx.log();
    assert!(
        log.contains("ALTER DATABASE \"propolis\" RENAME TO \"propolis_before_rollback_"),
        "{log}"
    );
    assert!(
        log.contains("CREATE DATABASE \"propolis\" OWNER \"propolis\" TEMPLATE template0"),
        "{log}"
    );
    assert!(!log.contains("DROP"), "nothing is dropped: {log}");
    assert!(
        log.contains("pg_restore --exit-on-error --dbname=propolis"),
        "{log}"
    );
    assert!(
        log.contains("restored 15 bytes"),
        "the dump reached pg_restore: {log}"
    );
    assert!(log.find("RENAME").unwrap() < log.find("systemctl start propolis.service").unwrap());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("is kept as propolis_before_rollback_"),
        "{stdout}"
    );
}

#[test]
fn an_encrypted_dump_is_decrypted_with_the_identity_on_the_way_to_pg_restore() {
    let fx = Fixture::new();
    let set = fx.root.join("var/backups/propolis").join(SET);
    std::fs::remove_file(set.join("propolis.dump")).unwrap();
    std::fs::write(
        set.join("propolis.dump.age"),
        "age-encryption.org/v1\nPGDMP-decrypted",
    )
    .unwrap();
    std::fs::write(
        fx.root.join("etc/propolis-identity"),
        "AGE-SECRET-KEY-1TEST\n",
    )
    .unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));

    let without = fx.run(&["--with-database", "--yes"], &[], None);
    assert_eq!(
        without.status.code(),
        Some(1),
        "an encrypted dump needs the identity"
    );
    assert!(
        !fx.log().contains("systemctl stop"),
        "refused before stopping anything"
    );

    let identity = fx.root.join("etc/propolis-identity");
    let with = fx.run(
        &[
            "--with-database",
            "--identity",
            identity.to_str().unwrap(),
            "--yes",
        ],
        &[],
        None,
    );
    assert_ok(&with);
    assert!(fx.log().contains("restored 15 bytes"), "{}", fx.log());
}

#[test]
fn every_refusal_happens_before_a_service_is_stopped() {
    let fx = Fixture::new();
    // No kept release yet.
    assert_eq!(fx.run(&["--yes"], &[], None).status.code(), Some(1));
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let release = fx.releases()[0].clone();

    // A wrong confirmation, a malformed name, a database rollback with no local PostgreSQL, and
    // one whose backup set is gone.
    assert_eq!(fx.run(&[], &[], Some("nope\n")).status.code(), Some(1));
    assert_eq!(
        fx.run(&["../etc", "--yes"], &[], None).status.code(),
        Some(2)
    );
    assert_eq!(
        fx.run(
            &["--with-database", "--yes"],
            &[("STUB_NO_POSTGRES", "1")],
            None
        )
        .status
        .code(),
        Some(1)
    );
    std::fs::remove_dir_all(fx.root.join("var/backups/propolis").join(SET)).unwrap();
    assert_eq!(
        fx.run(&["--with-database", "--yes"], &[], None)
            .status
            .code(),
        Some(1)
    );
    assert!(!fx.log().contains("systemctl stop"), "{}", fx.log());

    // The typed name is the confirmation.
    assert_ok(&fx.run(&[], &[], Some(&format!("{release}\n"))));
}

#[test]
fn a_daemon_that_does_not_come_back_names_a_migration_problem() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let output = fx.run(
        &["--yes"],
        &[
            ("STUB_INACTIVE", "1"),
            (
                "STUB_JOURNAL",
                "error: migration 21 was previously applied but is missing",
            ),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--with-database"), "{stderr}");
}

#[test]
fn list_shows_the_kept_releases_newest_first() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.store().join("20200101T000000Z-aaaa00000001")).unwrap();
    std::fs::write(
        fx.store().join("20200101T000000Z-aaaa00000001/manifest"),
        "commit=aaaa00000001\nbackup_set=\n",
    )
    .unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let output = fx.run(&["--list"], &[], None);
    assert_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert!(
        lines[0].contains("commit abc000000001") && lines[0].contains(SET),
        "{stdout}"
    );
    assert!(lines[1].contains("database (none)"), "{stdout}");
}
