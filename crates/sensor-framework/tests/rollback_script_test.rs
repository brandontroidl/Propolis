//! Runs `deploy/rollback.sh` against a scratch filesystem root (`PROPOLIS_ROLLBACK_ROOT`) with stub
//! `systemctl`, `runuser`, `journalctl`, `id`, `age`, `df`, `logger`, `propolis` and
//! `propolis-migrate` programs, and asserts what `--save` keeps, that a rollback puts exactly those files back and
//! restarts in order, that a database rollback renames the current database aside rather than
//! dropping it and gives the new one the same owner, that the backup set is verified and every
//! refusal happens before a service is stopped, that a node with split database roles has the
//! split put back and checked before anything starts, and that a restore that fails, or a run
//! ended by a signal, leaves the node on its real database or with the daemon stopped. The real
//! `sha256sum` runs as shipped.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

/// `runuser -u postgres -- CMD`. Its psql works on a cluster that is one file per database under
/// `$STUB_PG`, so a rename or a create fails where the real one would and a test can read
/// afterwards which database ended up under which name. Its `pg_restore --list` reads the head of
/// the archive and stops, as the real one does; `STUB_RESTORE_FAIL` fails the restore itself,
/// after the dump reached it, and `STUB_RESTORE_HOLD` names a file the restore waits for after
/// writing `<file>.started`, so a test can act while the restore is running; `STUB_PSQL_HOLD`
/// does the same for the psql command containing that text, after the command has taken effect
/// (`STUB_PSQL_HOLD_FILE` is the file). Asked about the
/// restored database, its psql says who owns the `event` table (`STUB_EVENT_OWNER`) and whether
/// the daemon's role is confined (`STUB_CONFINED`, the three booleans as psql prints them). A
/// command run through `env` is run: that is how the superuser step reaches the propolis stub.
const RUNUSER_STUB: &str = r#"#!/usr/bin/env bash
shift 3
printf 'runuser %s\n' "$*" >> "$STUB_LOG"
if [ -n "${STUB_RUNUSER_FAIL:-}" ] && [[ "$*" == *"$STUB_RUNUSER_FAIL"* ]]; then exit 1; fi
rename='ALTER DATABASE "([a-z0-9_]+)" RENAME TO "([a-z0-9_]+)"'
create='CREATE DATABASE "([a-z0-9_]+)"'
exists="FROM pg_database WHERE datname = '([a-z0-9_]+)'"
case "$1" in
    pg_restore)
        if [[ "$*" == *--list* ]]; then
            [ "$(head -c 5)" = PGDMP ] && exit 0
            echo "pg_restore: error: input file does not appear to be a valid archive" >&2
            exit 1
        fi
        printf 'restored %s bytes\n' "$(wc -c)" >> "$STUB_LOG"
        if [ -n "${STUB_RESTORE_HOLD:-}" ]; then
            : > "$STUB_RESTORE_HOLD.started"
            for _ in $(seq 1 600); do [ -e "$STUB_RESTORE_HOLD" ] && break; sleep 0.05; done
        fi
        [ -z "${STUB_RESTORE_FAIL:-}" ] || exit 1
        if [[ "$*" =~ --dbname=([a-z0-9_]+) ]]; then echo "restored from the dump" > "$STUB_PG/${BASH_REMATCH[1]}"; fi
        ;;
    psql)
        if [[ "$*" =~ $rename ]]; then
            [ -e "$STUB_PG/${BASH_REMATCH[1]}" ] && [ ! -e "$STUB_PG/${BASH_REMATCH[2]}" ] || exit 1
            mv "$STUB_PG/${BASH_REMATCH[1]}" "$STUB_PG/${BASH_REMATCH[2]}"
        elif [[ "$*" =~ $create ]]; then
            [ ! -e "$STUB_PG/${BASH_REMATCH[1]}" ] || exit 1
            echo "created empty" > "$STUB_PG/${BASH_REMATCH[1]}"
        elif [[ "$*" =~ $exists ]]; then
            if [ -e "$STUB_PG/${BASH_REMATCH[1]}" ]; then echo 1; else echo 0; fi
        elif [[ "$*" == *data_directory* ]]; then
            echo "${STUB_DATA_DIRECTORY-/var/lib/postgresql/16/main}"
        elif [[ "$*" == *unix_socket_directories* ]]; then
            echo "${STUB_SOCKET_DIRECTORIES-/var/run/postgresql, /tmp}|5433"
        elif [[ "$*" == *has_schema_privilege* ]]; then
            echo "${STUB_CONFINED-f|f|f}"
        elif [[ "$*" == *"pg_get_userbyid(c.relowner)"* ]]; then
            echo "${STUB_EVENT_OWNER-propolis_owner}"
        fi
        if [ -n "${STUB_PSQL_HOLD:-}" ] && [[ "$*" == *"$STUB_PSQL_HOLD"* ]]; then
            : > "$STUB_PSQL_HOLD_FILE.started"
            for _ in $(seq 1 600); do [ -e "$STUB_PSQL_HOLD_FILE" ] && break; sleep 0.05; done
        fi
        ;;
    env)
        shift
        exec env "$@"
        ;;
esac
"#;

/// `logger -t TAG -p PRIORITY -- TEXT`: what a failed run sends to the journal.
const LOGGER_STUB: &str = r#"#!/usr/bin/env bash
printf 'logger %s\n' "$*" >> "$STUB_LOG"
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

/// `age --decrypt -i IDENTITY FILE`: the file minus its header line, for the one identity the
/// fixture's sets are encrypted to. Any other identity is refused the way age refuses it.
const AGE_STUB: &str = r#"#!/usr/bin/env bash
[ "$1" = --decrypt ] && [ "$2" = -i ] || exit 2
grep -q -x "AGE-SECRET-KEY-1TEST" "$3" || { echo "age: error: no identity matched any of the recipients" >&2; exit 1; }
tail -n +2 "$4"
"#;

/// `df --output=avail -B1 -- DIR`: the space free on the volume PostgreSQL keeps its data on.
const DF_STUB: &str = r#"#!/usr/bin/env bash
printf 'df %s\n' "$*" >> "$STUB_LOG"
[ -z "${STUB_DF_FAIL:-}" ] || exit 1
printf '       Avail\n%12s\n' "${STUB_DF_AVAIL:-1099511627776}"
"#;

/// `/usr/local/sbin/propolis-migrate`. `--configured` says whether this is a node that splits its
/// database roles and, like the real script, prints and logs nothing. The two forms that touch
/// the database log themselves with the binary they were told to run, and `STUB_MIGRATE_FAIL`
/// names the one that fails (`migrate` or `--check`).
const MIGRATE_STUB: &str = r#"#!/usr/bin/env bash
if [ "${1:-}" = --configured ]; then [ -n "${STUB_SPLIT_ROLES:-}" ]; exit; fi
printf 'propolis-migrate%s\n' "${1:+ $1}" >> "$STUB_LOG"
printf 'propolis-migrate runs %s\n' "$("$PROPOLIS_BIN" --version)" >> "$STUB_LOG"
[ "${STUB_MIGRATE_FAIL:-}" != "${1:-migrate}" ] || { echo "propolis migrate: it failed" >&2; exit 1; }
"#;

/// The propolis binary of release `commit`. Its `pg-exec psql` answers as the database the daemon
/// connects to: named `propolis`, connected to as the role `DATABASE_URL` names (`propolis` in
/// propolis.env, `propolis_owner` in migrate.env; `STUB_OWNER_LOGIN_FAIL` makes the latter fail
/// to connect), owned by `STUB_DB_OWNER` (`propolis` unless a test says the roles are split) and
/// `STUB_DB_SIZE` bytes large. Its `migrate` logs itself, and carries the usage text the deploy
/// scripts look for to tell a release that has the subcommand.
fn propolis_stub(commit: &str) -> String {
    propolis_stub_with(
        commit,
        &format!(
            r#"    migrate)
        # usage: propolis migrate [--check | --init-roles --owner ROLE --runtime ROLE]
        printf 'propolis %s ({commit})\n' "$*" >> "$STUB_LOG"
        ;;
"#
        ),
    )
}

/// The same binary from a release before `propolis migrate` existed.
fn propolis_stub_before_migrate(commit: &str) -> String {
    propolis_stub_with(commit, "")
}

fn propolis_stub_with(commit: &str, more_subcommands: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
case "$1" in
    --version) echo "propolis 0.4.0 ({commit}, built 2026-10-11T00:00:00Z)" ;;
    pg-exec)
        [ -n "${{DATABASE_URL:-}}" ] || {{ echo "propolis pg-exec: DATABASE_URL is not set" >&2; exit 1; }}
        case "$*" in
            *pg_database_size*) echo "${{STUB_DB_SIZE-1048576}}" ;;
            *datdba*) echo "${{STUB_DB_OWNER-propolis}}" ;;
            *current_database*) echo propolis ;;
            *current_user*)
                [[ "$DATABASE_URL" =~ ^postgres://([a-z_]+) ]] || exit 1
                if [ -n "${{STUB_OWNER_LOGIN_FAIL:-}}" ] && [ "${{BASH_REMATCH[1]}}" != propolis ]; then
                    echo "psql: error: FATAL:  password authentication failed for user \"${{BASH_REMATCH[1]}}\"" >&2
                    exit 1
                fi
                echo "${{BASH_REMATCH[1]}}"
                ;;
        esac
        ;;
{more_subcommands}esac
"#
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
    /// The stub cluster: one file per database, holding what that database is.
    pg: PathBuf,
}

/// What the stub cluster's database holds before a rollback touches it.
const LIVE: &str = "the database from before the rollback\n";

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
        // Installed by every upgrade and never part of a kept release, so a rollback finds the
        // newer release's copy.
        write_exec(&root.join("usr/local/sbin/propolis-migrate"), MIGRATE_STUB);
        // The owner role's URL. The stub above is what says whether the node is split
        // (`STUB_SPLIT_ROLES`); rollback.sh reads this file only on a node that is.
        std::fs::write(
            root.join("etc/propolis/migrate.env"),
            "PROPOLIS_MIGRATE_DATABASE_URL=postgres://propolis_owner:pw@localhost/propolis\n",
        )
        .unwrap();
        for (name, body) in [
            ("systemctl", SYSTEMCTL_STUB),
            ("runuser", RUNUSER_STUB),
            ("journalctl", JOURNALCTL_STUB),
            ("id", ID_STUB),
            ("age", AGE_STUB),
            ("df", DF_STUB),
            ("logger", LOGGER_STUB),
        ] {
            write_exec(&bin.join(name), body);
        }
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        let pg = dir.path().join("pg");
        std::fs::create_dir_all(&pg).unwrap();
        std::fs::write(pg.join("propolis"), LIVE).unwrap();
        let fx = Fixture {
            _dir: dir,
            root,
            bin,
            log,
            pg,
        };
        fx.write_sums(&["propolis.dump"]);
        fx
    }

    fn set_dir(&self) -> PathBuf {
        self.root.join("var/backups/propolis").join(SET)
    }

    /// The set's `SHA256SUMS` as `deploy/backup.sh` writes it: the real `sha256sum` over the
    /// files as stored, then the chain-head comment line.
    fn write_sums(&self, files: &[&str]) {
        let sums = Command::new("sha256sum")
            .arg("--")
            .args(files)
            .current_dir(self.set_dir())
            .output()
            .expect("sha256sum runs");
        assert!(sums.status.success(), "sha256sum failed over {files:?}");
        let mut body = sums.stdout;
        body.extend_from_slice(b"# chain-head empty\n");
        std::fs::write(self.set_dir().join("SHA256SUMS"), body).unwrap();
    }

    /// Replaces the set's plaintext dump with one encrypted to the fixture's identity, and
    /// writes that identity where the returned path says.
    fn encrypt_dump(&self, plaintext: &[u8]) -> PathBuf {
        std::fs::remove_file(self.set_dir().join("propolis.dump")).unwrap();
        let mut body = b"age-encryption.org/v1\n".to_vec();
        body.extend_from_slice(plaintext);
        std::fs::write(self.set_dir().join("propolis.dump.age"), body).unwrap();
        self.write_sums(&["propolis.dump.age"]);
        let identity = self.root.join("etc/propolis-identity");
        std::fs::write(&identity, "AGE-SECRET-KEY-1TEST\n").unwrap();
        identity
    }

    /// Every database in the stub cluster with what it holds, by name.
    fn databases(&self) -> Vec<(String, String)> {
        let mut all: Vec<(String, String)> = std::fs::read_dir(&self.pg)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    read(&e.path()),
                )
            })
            .collect();
        all.sort();
        all
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)], stdin: Option<&str>) -> Output {
        let mut child = self.spawn(args, env, stdin.is_some());
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

    /// Starts rollback.sh in a process group of its own, so a test can signal the script and
    /// everything it runs the way a terminal that goes away does.
    fn spawn(&self, args: &[&str], env: &[(&str, &str)], stdin: bool) -> Child {
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
            .env("STUB_PG", &self.pg)
            .env("STUB_ENABLED", "propolis.service sensor-ssh.service")
            .envs(env.iter().copied())
            .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        command.spawn().expect("bash runs")
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

/// The rollback refused: it exited 1 and stopped nothing. Returns what it said.
fn assert_refused_before_stopping(fx: &Fixture, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let log = fx.log();
    assert!(
        !log.contains("systemctl stop"),
        "a service was stopped: {log}"
    );
    assert!(
        !log.contains("ALTER DATABASE") && !log.contains("CREATE DATABASE"),
        "the database was touched: {log}"
    );
    stderr
}

/// Where each needle first appears in the stub log, which must be in the order given.
fn assert_in_order(log: &str, needles: &[&str]) {
    let mut last = 0;
    for needle in needles {
        let at = log[last..]
            .find(needle)
            .unwrap_or_else(|| panic!("{needle:?} is missing, or out of order, in:\n{log}"));
        last += at + needle.len();
    }
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

/// A step that fails after the services are stopped says which step. Here the rename aside
/// worked and creating the new database did not, so the name the daemon connects to holds
/// nothing: the database from before the rollback gets its name back before anything starts.
#[test]
fn a_failed_create_puts_the_database_back_under_its_name_and_starts_the_services_again() {
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
        stderr.contains("back under its own name, propolis"),
        "{stderr}"
    );
    let log = fx.log();
    assert_in_order(
        &log,
        &[
            "ALTER DATABASE \"propolis\" RENAME TO \"propolis_before_rollback_",
            "CREATE DATABASE \"propolis\"",
            "ALTER DATABASE \"propolis_before_rollback_",
            "RENAME TO \"propolis\"",
            "systemctl start propolis.service",
        ],
    );
    assert!(
        !log.contains("_failed_restore_"),
        "no database of that name was left to move out of the way: {log}"
    );
    assert_eq!(
        fx.databases(),
        vec![("propolis".to_string(), LIVE.to_string())],
        "the only database is the one from before the rollback, under its own name"
    );
}

/// When the rename aside itself fails nothing has moved: the database is still under its name,
/// there is nothing to put back, and the services are started on it as they were.
#[test]
fn a_failed_rename_aside_leaves_the_database_where_it_was_and_starts_the_services_again() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_RUNUSER_FAIL", "RENAME TO")],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("while renaming the current database aside"),
        "{stderr}"
    );
    // The script asks PostgreSQL whether the database moved before it touches anything, and
    // says what it found: the operator is not left to wonder which name holds the data.
    assert!(
        stderr.contains("The database was not renamed: propolis is as it was"),
        "{stderr}"
    );
    let log = fx.log();
    assert_eq!(
        log.matches("RENAME TO").count(),
        1,
        "only the rename that failed was tried: {log}"
    );
    assert!(log.contains("systemctl start propolis.service"), "{log}");
    assert_eq!(
        fx.databases(),
        vec![("propolis".to_string(), LIVE.to_string())]
    );
}

/// A signal is acted on the moment the step in progress returns, which is before the script's
/// next line runs. For the rename aside that means the database HAS moved and nothing after the
/// rename has run. The name it was moved to is recorded before the rename is asked for, and the
/// trap asks PostgreSQL what is where, so the database is given its name back. Recorded after
/// the step, as it was, the trap saw nothing to put back and started the daemon on a name with
/// no database under it.
#[test]
fn a_signal_right_after_the_rename_aside_gives_the_database_its_name_back() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let hold = fx.root.join("rename-may-return");
    let started = fx.root.join("rename-may-return.started");
    let child = fx.spawn(
        &["--with-database", "--yes"],
        &[
            ("STUB_PSQL_HOLD", "RENAME TO \"propolis_before_rollback_"),
            ("STUB_PSQL_HOLD_FILE", hold.to_str().unwrap()),
        ],
        false,
    );
    wait_for(&started);
    assert!(
        !fx.pg.join("propolis").exists(),
        "precondition: the rename has taken effect and psql has not returned yet"
    );
    signal("TERM", &child.id().to_string());
    std::fs::write(&hold, b"").unwrap();
    let out = child.wait_with_output().expect("rollback.sh ends");
    assert_eq!(out.status.code(), Some(143), "{:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("back under its own name, propolis"),
        "{stderr}"
    );
    let log = fx.log();
    assert!(!log.contains("CREATE DATABASE"), "{log}");
    assert_in_order(
        &log,
        &[
            "ALTER DATABASE \"propolis\" RENAME TO \"propolis_before_rollback_",
            "ALTER DATABASE \"propolis_before_rollback_",
            "systemctl start propolis.service",
        ],
    );
    assert_eq!(
        fx.databases(),
        vec![("propolis".to_string(), LIVE.to_string())],
        "the only database is the real one, under its own name"
    );
}

/// The trap cannot ask PostgreSQL where the database is (the server went away, which is also a
/// likely reason for the restore to have failed). It must not guess: the daemon is left stopped
/// and the message names both places the data can be.
#[test]
fn when_postgresql_cannot_say_where_the_database_is_the_daemon_is_left_stopped() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let out = fx.run(
        &["--with-database", "--yes"],
        &[
            ("STUB_RESTORE_FAIL", "1"),
            ("STUB_RUNUSER_FAIL", "count(*) FROM pg_database"),
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("PostgreSQL did not answer")
            && stderr.contains(
                "still under its name, propolis, or was renamed to propolis_before_rollback_"
            )
            && stderr.contains("propolis.service is left stopped"),
        "{stderr}"
    );
    let log = fx.log();
    let after = &log[log.find("pg_restore --exit-on-error").unwrap()..];
    assert!(
        !after.contains("systemctl start propolis.service"),
        "the daemon was started without knowing what its database name holds: {log}"
    );
    assert!(
        after.contains("systemctl start sensor-ssh.service"),
        "{log}"
    );
    assert_eq!(
        log.matches("runuser psql -X -v ON_ERROR_STOP=1 -c ALTER DATABASE")
            .count(),
        1,
        "nothing is renamed on a guess: {log}"
    );
}

/// The restore itself fails with the live database already renamed aside and a new one created.
/// Started now, the daemon would find an empty or half-restored database under its name and, on
/// a node with one role, begin a new ledger there. The incomplete database is moved out of the
/// way, the real one gets its name back, and only then are the services started. Nothing is
/// dropped, and the operator is told the way out is forward.
#[test]
fn a_restore_that_fails_puts_the_real_database_back_before_starting_the_services() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_RESTORE_FAIL", "1")],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("while restoring the dump"), "{stderr}");
    assert!(
        stderr.contains("back under its own name, propolis"),
        "{stderr}"
    );
    assert!(
        stderr.contains("renamed to propolis_failed_restore_"),
        "{stderr}"
    );
    assert!(stderr.contains("deploy/upgrade.sh"), "{stderr}");

    let log = fx.log();
    assert_in_order(
        &log,
        &[
            "ALTER DATABASE \"propolis\" RENAME TO \"propolis_before_rollback_",
            "CREATE DATABASE \"propolis\"",
            "pg_restore --exit-on-error --dbname=propolis",
            "ALTER DATABASE \"propolis\" RENAME TO \"propolis_failed_restore_",
            "ALTER DATABASE \"propolis_before_rollback_",
            "RENAME TO \"propolis\"",
            "systemctl start sensor-ssh.service",
            "systemctl start propolis.service",
        ],
    );
    assert!(!log.contains("DROP"), "nothing is dropped: {log}");

    let databases = fx.databases();
    assert_eq!(databases.len(), 2, "{databases:?}");
    assert_eq!(
        databases[0],
        ("propolis".to_string(), LIVE.to_string()),
        "the daemon's database is the one from before the rollback"
    );
    assert!(
        databases[1].0.starts_with("propolis_failed_restore_")
            && databases[1].1 == "created empty\n",
        "the incomplete restore is kept under another name: {databases:?}"
    );
}

/// The restore failed and the real database could not be given its name back either: because the
/// incomplete one could not be moved out of the way, so the name is still taken, or because the
/// rename back itself failed. Either way the name the daemon connects to does not hold the real
/// ledger, so the daemon stays stopped: it must not start a new one there. The sensors, gateway
/// and shipper are started, and the message names the database that holds the real data.
#[test]
fn when_the_database_cannot_be_put_back_the_daemon_is_left_stopped_and_the_real_one_named() {
    for failing_rename in ["_failed_restore_", "RENAME TO \"propolis\""] {
        let fx = Fixture::new();
        assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
        fx.upgrade();
        let out = fx.run(
            &["--with-database", "--yes"],
            &[
                ("STUB_RESTORE_FAIL", "1"),
                ("STUB_RUNUSER_FAIL", failing_rename),
                (
                    "STUB_ENABLED",
                    "propolis.service sensor-ssh.service gateway.service shipper.service",
                ),
            ],
            None,
        );
        assert_eq!(out.status.code(), Some(1), "{failing_rename}");
        let log = fx.log();
        let databases = fx.databases();
        let aside = &databases
            .iter()
            .find(|(_, holds)| holds == LIVE)
            .unwrap_or_else(|| panic!("the real database is gone: {databases:?}"))
            .0;
        assert!(aside.starts_with("propolis_before_rollback_"), "{aside}");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("the real data is in database {aside}")),
            "{failing_rename}: {stderr}"
        );
        assert!(
            stderr.contains("propolis.service is left stopped")
                && stderr.contains("cannot start a new ledger in an empty database"),
            "{failing_rename}: {stderr}"
        );
        let after = &log[log.find("pg_restore --exit-on-error").unwrap()..];
        assert!(
            !after.contains("systemctl start propolis.service"),
            "{failing_rename}: the daemon was started on a database that is not the real one: {log}"
        );
        for unit in ["sensor-ssh", "gateway", "shipper"] {
            assert!(
                after.contains(&format!("systemctl start {unit}.service")),
                "{failing_rename}: {unit} was not started again: {log}"
            );
        }
        assert!(!log.contains("DROP"), "nothing is dropped: {log}");
    }
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

/// The new database gets the owner the current one has. On a node that splits its database roles
/// that is the owner role, not the role `DATABASE_URL` connects as: created for the connecting
/// role, the daemon's role would own the database and the split would be undone without a word.
#[test]
fn a_database_rollback_renames_the_current_database_aside_and_restores_the_dump() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let output = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_DB_OWNER", "propolis_owner")],
        None,
    );
    assert_ok(&output);
    let log = fx.log();
    assert!(
        log.contains("ALTER DATABASE \"propolis\" RENAME TO \"propolis_before_rollback_"),
        "{log}"
    );
    assert!(
        log.contains("CREATE DATABASE \"propolis\" OWNER \"propolis_owner\" TEMPLATE template0"),
        "the new database is not given the previous one's owner: {log}"
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
    let databases = fx.databases();
    assert_eq!(databases.len(), 2, "{databases:?}");
    assert_eq!(
        databases[0],
        (
            "propolis".to_string(),
            "restored from the dump\n".to_string()
        )
    );
    assert!(
        databases[1].0.starts_with("propolis_before_rollback_") && databases[1].1 == LIVE,
        "{databases:?}"
    );
    // The set was verified, and the dump listed, while everything was still running.
    assert_in_order(&log, &["pg_restore --list", "systemctl stop"]);
    // Without an owner role in migrate.env there is no split to put back.
    assert!(!log.contains("propolis-migrate"), "{log}");
}

/// A single-role node: the database's owner is the role the daemon connects as, and that is who
/// the new one is created for, as before.
#[test]
fn a_database_owned_by_the_daemons_role_is_recreated_for_that_role() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    assert_ok(&fx.run(&["--with-database", "--yes"], &[], None));
    let log = fx.log();
    assert!(
        log.contains("CREATE DATABASE \"propolis\" OWNER \"propolis\" TEMPLATE template0"),
        "{log}"
    );
}

/// The owner is statement text in `CREATE DATABASE`, so it must be read and be a plain name. A
/// database whose owner cannot be read is not recreated for a guess.
#[test]
fn an_owner_that_cannot_be_read_or_is_not_a_plain_name_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));

    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_DB_OWNER", "")],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(
        stderr.contains("could not read which role owns database"),
        "{stderr}"
    );

    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_DB_OWNER", "owner\"; DROP DATABASE propolis; --")],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(stderr.contains("is not a plain name"), "{stderr}");
}

/// A set whose files no longer match the digests the backup recorded is refused while the node
/// still runs, and the message names the file.
#[test]
fn a_set_that_does_not_match_its_checksums_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    // Still a dump pg_restore would list: only the digest can tell it changed.
    std::fs::write(fx.set_dir().join("propolis.dump"), "PGDMP0123456780").unwrap();
    let out = fx.run(&["--with-database", "--yes"], &[], None);
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(stderr.contains("propolis.dump: FAILED"), "{stderr}");
    assert!(stderr.contains("does not match its SHA256SUMS"), "{stderr}");
}

/// The digests are of the files as the backup stored them. A plaintext dump placed next to the
/// encrypted one is the file the restore would read, and the digests say nothing about it.
#[test]
fn a_dump_the_checksums_do_not_list_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    fx.encrypt_dump(b"PGDMP-decrypted");
    std::fs::write(fx.set_dir().join("propolis.dump"), "PGDMP-decrypted").unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(&["--with-database", "--yes"], &[], None);
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(
        stderr.contains("SHA256SUMS does not list propolis.dump"),
        "{stderr}"
    );
}

/// A set written before backups recorded digests has nothing to check against. The rollback says
/// so and goes on: the dump must still list.
#[test]
fn a_set_without_checksums_is_said_to_be_unverified_and_still_restored() {
    let fx = Fixture::new();
    std::fs::remove_file(fx.set_dir().join("SHA256SUMS")).unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(&["--with-database", "--yes"], &[], None);
    assert_ok(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("has no SHA256SUMS") && stdout.contains("cannot be verified"),
        "{stdout}"
    );
    assert_in_order(
        &fx.log(),
        &["pg_restore --list", "systemctl stop", "restored 15 bytes"],
    );
}

/// A file with the right digest that is not a dump (the backup recorded what it wrote, and what
/// it wrote was wrong) is found by listing it, with the services still up.
#[test]
fn a_dump_that_pg_restore_cannot_list_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    std::fs::write(fx.set_dir().join("propolis.dump"), "not a dump at all").unwrap();
    fx.write_sums(&["propolis.dump"]);
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(&["--with-database", "--yes"], &[], None);
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(stderr.contains("pg_restore cannot list"), "{stderr}");

    // The same for what an encrypted dump decrypts to.
    let fx = Fixture::new();
    let identity = fx.encrypt_dump(b"not a dump at all");
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &[
            "--with-database",
            "--identity",
            identity.to_str().unwrap(),
            "--yes",
        ],
        &[],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(
        stderr.contains("decrypts, but pg_restore cannot list it"),
        "{stderr}"
    );
}

/// An identity that is readable but is not the one the set was encrypted to. Found at the restore
/// step this would leave the services stopped and the live database renamed aside.
#[test]
fn an_identity_that_does_not_decrypt_the_dump_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    fx.encrypt_dump(b"PGDMP-decrypted");
    let wrong = fx.root.join("etc/another-identity");
    std::fs::write(&wrong, "AGE-SECRET-KEY-1OTHER\n").unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &[
            "--with-database",
            "--identity",
            wrong.to_str().unwrap(),
            "--yes",
        ],
        &[],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(stderr.contains("does not decrypt"), "{stderr}");
    assert!(stderr.contains("another-identity"), "{stderr}");
}

/// pg_restore stops reading where the dump's table of contents ends, long before the end of a
/// dump of any size. That must not read as a failed decryption: the rest is drained.
#[test]
fn an_encrypted_dump_larger_than_a_pipe_is_listed_without_being_refused() {
    let fx = Fixture::new();
    let mut dump = b"PGDMP".to_vec();
    dump.resize(1024 * 1024, b'x');
    let identity = fx.encrypt_dump(&dump);
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &[
            "--with-database",
            "--identity",
            identity.to_str().unwrap(),
            "--yes",
        ],
        &[],
        None,
    );
    assert_ok(&out);
    assert!(fx.log().contains("restored 1048576 bytes"), "{}", fx.log());
}

/// The restore loads a second copy while the current database is kept aside. A volume with less
/// free than the database's size cannot hold it, and running out part-way is the failed restore
/// this check exists to avoid.
#[test]
fn too_little_free_space_for_a_second_copy_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &["--with-database", "--yes"],
        &[
            ("STUB_DB_SIZE", "5000000000"),
            ("STUB_DF_AVAIL", "4999999999"),
        ],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(
        stderr.contains("5000000000 bytes") && stderr.contains("4999999999 bytes free"),
        "{stderr}"
    );
    assert!(
        fx.log()
            .contains("df --output=avail -B1 -- /var/lib/postgresql/16/main"),
        "the space asked about is not where PostgreSQL keeps its data: {}",
        fx.log()
    );

    // Exactly enough is enough.
    assert_ok(&fx.run(
        &["--with-database", "--yes"],
        &[
            ("STUB_DB_SIZE", "5000000000"),
            ("STUB_DF_AVAIL", "5000000000"),
        ],
        None,
    ));
}

/// The free-space check is advisory. Where the size, the data directory or the free space cannot
/// be read it says the check was not made and the rollback goes on.
#[test]
fn a_free_space_check_that_cannot_be_made_is_reported_and_does_not_refuse() {
    for unanswered in [
        ("STUB_DF_FAIL", "1"),
        ("STUB_DB_SIZE", ""),
        ("STUB_DATA_DIRECTORY", ""),
    ] {
        let fx = Fixture::new();
        assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
        let out = fx.run(&["--with-database", "--yes"], &[unanswered], None);
        assert_ok(&out);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("free space could not be checked"),
            "{unanswered:?}: {stdout}"
        );
        assert!(fx.log().contains("restored 15 bytes"), "{unanswered:?}");
    }
}

/// On a node that splits its database roles the split is put back by the owner role and then
/// checked as the daemon's role, with the rolled-back binary, after the dump is in and before
/// anything is started.
#[test]
fn on_a_split_node_the_roles_are_reapplied_and_checked_before_any_service_starts() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let out = fx.run(
        &["--with-database", "--yes"],
        &[
            ("STUB_SPLIT_ROLES", "1"),
            ("STUB_DB_OWNER", "propolis_owner"),
        ],
        None,
    );
    assert_ok(&out);
    let log = fx.log();
    assert_in_order(
        &log,
        &[
            "restored 15 bytes",
            "propolis-migrate\n",
            "propolis-migrate --check\n",
            "systemctl start",
        ],
    );
    assert_in_order(
        &log,
        &[
            "propolis-migrate --check\n",
            "has_schema_privilege('propolis', c.relnamespace, 'CREATE')",
            "systemctl start propolis.service",
        ],
    );
    assert_eq!(
        log.matches("propolis-migrate runs propolis 0.4.0 (abc000000001,")
            .count(),
        2,
        "both ran the binary that was rolled back to: {log}"
    );
    assert!(
        log.contains("CREATE DATABASE \"propolis\" OWNER \"propolis_owner\" TEMPLATE template0"),
        "{log}"
    );
    // The dump is from after the split (the owner role owns its tables), so nothing is moved.
    assert!(!log.contains("--init-roles"), "{log}");
}

/// A split node whose database belongs to the daemon's role: what this script left behind when
/// it created the restored database for the role `DATABASE_URL` connects as. Recreating it for
/// that role again would keep the split undone, and a kept release from before
/// `propolis migrate --check` looked at the database's owner calls that protected. The restored
/// database is created for the owner role migrate.env names.
#[test]
fn on_a_split_node_a_database_the_daemons_role_owns_is_recreated_for_the_owner_role() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_SPLIT_ROLES", "1"), ("STUB_DB_OWNER", "propolis")],
        None,
    );
    assert_ok(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("the role split is undone on this node")
            && stdout.contains("created for the owner role, 'propolis_owner'"),
        "{stdout}"
    );
    let log = fx.log();
    assert!(
        log.contains("CREATE DATABASE \"propolis\" OWNER \"propolis_owner\" TEMPLATE template0"),
        "{log}"
    );
    assert!(!log.contains("OWNER \"propolis\""), "{log}");
    // Said before anything is stopped, so the operator reads it at the confirmation.
    let said = stdout.find("the role split is undone").unwrap();
    assert!(
        said < stdout.find("==> stopping services").unwrap(),
        "{stdout}"
    );
}

/// The roles are read while everything still runs. An owner URL that does not connect, or one
/// that names the daemon's own role, means the split cannot be put back after the restore, and
/// that is a refusal, not something to find out with the services stopped.
#[test]
fn on_a_split_node_an_owner_role_that_cannot_be_read_refuses_before_stopping_anything() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_SPLIT_ROLES", "1"), ("STUB_OWNER_LOGIN_FAIL", "1")],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(
        stderr.contains("could not be read as two different plain names")
            && stderr.contains("migrate.env"),
        "{stderr}"
    );
    // What the attempt said is shown, so a URL psql cannot be handed is told apart from a role
    // that cannot log in.
    assert!(
        stderr.contains(
            "Connecting with the owner's URL said: psql: error: FATAL:  password authentication failed"
        ),
        "{stderr}"
    );

    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    std::fs::write(
        fx.root.join("etc/propolis/migrate.env"),
        "PROPOLIS_MIGRATE_DATABASE_URL=postgres://propolis:pw@localhost/propolis\n",
    )
    .unwrap();
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_SPLIT_ROLES", "1")],
        None,
    );
    let stderr = assert_refused_before_stopping(&fx, &out);
    assert!(stderr.contains("two different plain names"), "{stderr}");

    // The owner's URL holds a password. It reaches the binary in its environment only.
    assert!(!fx.log().contains("pw@"), "{}", fx.log());
    assert!(!stderr.contains("pw@"), "{stderr}");
}

/// A dump taken before the node split its roles has every table owned by the daemon's role.
/// The owner role cannot migrate that and the daemon, which no longer owns the database, cannot
/// either, so without help the rollback ends with a daemon that will not start. The split's own
/// first step is run first, as the postgres superuser over the server's socket, with the binary
/// that was rolled back to.
#[test]
fn a_dump_from_before_the_role_split_has_its_tables_handed_to_the_owner_role_first() {
    let split = [
        ("STUB_SPLIT_ROLES", "1"),
        ("STUB_DB_OWNER", "propolis_owner"),
        ("STUB_EVENT_OWNER", "propolis"),
    ];
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let out = fx.run(&["--with-database", "--yes"], &split, None);
    assert_ok(&out);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("the dump is from before the roles were split"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_in_order(
        &fx.log(),
        &[
            "restored 15 bytes",
            "runuser env PROPOLIS_ADMIN_DATABASE_URL=postgres://postgres@%2Fvar%2Frun%2Fpostgresql:5433/propolis ",
            "propolis migrate --init-roles --owner propolis_owner --runtime propolis (abc000000001)",
            "propolis-migrate\n",
            "propolis-migrate --check\n",
            "has_schema_privilege",
            "systemctl start propolis.service",
        ],
    );

    // The step failing fails the rollback before the owner role's run, and the way out is said.
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let mut failing = split.to_vec();
    failing.push(("STUB_RUNUSER_FAIL", "--init-roles"));
    let out = fx.run(&["--with-database", "--yes"], &failing, None);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("while moving the restored tables to the owner role")
            && stderr.contains("role split is NOT confirmed")
            && stderr.contains("refuse to start"),
        "{stderr}"
    );
    assert!(!fx.log().contains("propolis-migrate\n"), "{}", fx.log());

    // A socket directory that cannot be read is said, not guessed.
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    let mut no_socket = split.to_vec();
    no_socket.push(("STUB_SOCKET_DIRECTORIES", ""));
    let out = fx.run(&["--with-database", "--yes"], &no_socket, None);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("socket directory and port could not be read"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!fx.log().contains("runuser env"), "{}", fx.log());
}

/// `propolis-migrate --check` is answered by the kept release's binary, and a release from
/// before that binary looked at the database's owner prints "protected" for a daemon role that
/// owns the database. So the script asks PostgreSQL itself, after that check and before any
/// service starts, and anything but three times "no" fails the rollback.
#[test]
fn a_daemon_role_that_is_not_confined_fails_the_rollback_whatever_the_kept_binary_says() {
    for answer in ["f|t|t", "f|f|t", "t|f|f", "", "f|f|f|f"] {
        let fx = Fixture::new();
        assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
        let out = fx.run(
            &["--with-database", "--yes"],
            &[
                ("STUB_SPLIT_ROLES", "1"),
                ("STUB_DB_OWNER", "propolis_owner"),
                ("STUB_CONFINED", answer),
            ],
            None,
        );
        assert_eq!(out.status.code(), Some(1), "{answer:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("the daemon's role propolis is not confined")
                && stderr.contains(&format!("answered '{answer}'"))
                && stderr.contains("role split is NOT confirmed"),
            "{answer:?}: {stderr}"
        );
        let log = fx.log();
        // The kept binary's check ran and passed; the rollback fails all the same.
        assert_in_order(
            &log,
            &["propolis-migrate --check\n", "has_schema_privilege"],
        );
        assert!(
            fx.databases().contains(&(
                "propolis".to_string(),
                "restored from the dump\n".to_string()
            )),
            "{answer:?}"
        );
    }
}

/// Waits for `path` to exist: the restore stub writes it once the dump has reached it.
fn wait_for(path: &Path) {
    for _ in 0..600 {
        if path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("{} never appeared", path.display());
}

fn signal(name: &str, target: &str) {
    let status = Command::new("kill")
        .args([&format!("-{name}"), "--", target])
        .status()
        .expect("kill runs");
    assert!(status.success(), "kill -{name} {target}");
}

/// The restore is the long step, and a rollback is usually run over SSH. A run ended there by a
/// signal used to skip the put-back altogether: bash enters the EXIT trap with the status of the
/// last command that finished, which is 0, and the trap took that for success. Every service
/// was left stopped with a half-restored database under the daemon's name, and nothing said so.
///
/// Sent to the script alone, a signal is acted on once the step in progress ends. Here the
/// script's output has gone away as well, which is what a dropped session does to it: reporting
/// to it fails, and that must not end the trap before the database is back. The report still
/// reaches the journal.
#[test]
fn a_run_ended_by_a_signal_during_the_restore_puts_the_real_database_back() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let hold = fx.root.join("restore-may-finish");
    let started = fx.root.join("restore-may-finish.started");
    let mut child = fx.spawn(
        &["--with-database", "--yes"],
        &[("STUB_RESTORE_HOLD", hold.to_str().unwrap())],
        false,
    );
    wait_for(&started);
    drop(child.stdout.take());
    drop(child.stderr.take());
    signal("TERM", &child.id().to_string());
    std::fs::write(&hold, b"").unwrap();
    let status = child.wait().expect("rollback.sh ends");
    assert_eq!(status.code(), Some(143), "{status:?}");

    let log = fx.log();
    assert_in_order(
        &log,
        &[
            "pg_restore --exit-on-error --dbname=propolis",
            "logger -t propolis-rollback -p daemon.err -- error: the rollback failed while restoring the dump",
            "ALTER DATABASE \"propolis\" RENAME TO \"propolis_failed_restore_",
            "ALTER DATABASE \"propolis_before_rollback_",
            "logger -t propolis-rollback -p daemon.err -- The database from before the rollback is back under its own name, propolis",
            "systemctl start sensor-ssh.service",
            "systemctl start propolis.service",
        ],
    );
    let databases = fx.databases();
    assert_eq!(databases.len(), 2, "{databases:?}");
    assert_eq!(
        databases[0],
        ("propolis".to_string(), LIVE.to_string()),
        "the daemon's database is the one from before the rollback"
    );
    assert!(
        databases[1].0.starts_with("propolis_failed_restore_"),
        "{databases:?}"
    );
}

/// A terminal that goes away signals everything the script is running too, so the restore
/// itself dies part-way. The same end state: the real database under its name, the part-restored
/// one aside, the services started.
#[test]
fn a_hangup_that_kills_the_restore_too_puts_the_real_database_back() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let hold = fx.root.join("restore-may-finish");
    let started = fx.root.join("restore-may-finish.started");
    let child = fx.spawn(
        &["--with-database", "--yes"],
        &[("STUB_RESTORE_HOLD", hold.to_str().unwrap())],
        false,
    );
    wait_for(&started);
    signal("HUP", &format!("-{}", child.id()));
    let out = child.wait_with_output().expect("rollback.sh ends");
    assert_eq!(out.status.code(), Some(129), "{:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("while restoring the dump"), "{stderr}");
    assert!(
        stderr.contains("back under its own name, propolis"),
        "{stderr}"
    );

    let log = fx.log();
    assert!(log.contains("systemctl start propolis.service"), "{log}");
    let databases = fx.databases();
    assert_eq!(databases.len(), 2, "{databases:?}");
    assert_eq!(databases[0], ("propolis".to_string(), LIVE.to_string()));
    assert!(
        databases[1].0.starts_with("propolis_failed_restore_")
            && databases[1].1 == "created empty\n",
        "the restore never finished: {databases:?}"
    );
}

/// A signal before anything was stopped ends the run and changes nothing.
#[test]
fn a_signal_before_the_services_are_stopped_changes_nothing() {
    let fx = Fixture::new();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    // No --yes: the run waits at the confirmation, with everything still running.
    let child = fx.spawn(&["--with-database"], &[], true);
    for _ in 0..600 {
        if fx.log().contains("pg_restore --list") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    signal("TERM", &child.id().to_string());
    let out = child.wait_with_output().expect("rollback.sh ends");
    assert_eq!(out.status.code(), Some(143), "{:?}", out.status);
    let log = fx.log();
    assert!(!log.contains("systemctl stop"), "{log}");
    assert!(
        !log.contains("logger"),
        "nothing failed, nothing is reported: {log}"
    );
    assert_eq!(
        fx.databases(),
        vec![("propolis".to_string(), LIVE.to_string())]
    );
}

/// The check is the gate: a restored database on which the daemon's role is not confined fails
/// the rollback, and the failure says the split is not confirmed. The same when the owner role's
/// run fails, and then the check is not reached. The dump is in, so nothing is renamed back.
#[test]
fn a_role_split_that_cannot_be_reapplied_or_does_not_check_out_fails_the_rollback() {
    for (failing, step) in [
        ("--check", "while checking the database role split"),
        ("migrate", "while re-applying the database role split"),
    ] {
        let fx = Fixture::new();
        assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
        let out = fx.run(
            &["--with-database", "--yes"],
            &[
                ("STUB_SPLIT_ROLES", "1"),
                ("STUB_DB_OWNER", "propolis_owner"),
                ("STUB_MIGRATE_FAIL", failing),
            ],
            None,
        );
        assert_eq!(out.status.code(), Some(1), "{failing}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(step), "{failing}: {stderr}");
        assert!(
            stderr.contains("role split is NOT confirmed"),
            "{failing}: {stderr}"
        );
        // The way out starts with the step that cannot fail on who owns what, so following it
        // does not lead back to the same error.
        assert!(
            stderr.contains("`propolis migrate --init-roles`"),
            "{failing}: {stderr}"
        );
        assert!(
            !fx.log().contains("has_schema_privilege"),
            "{failing}: the last check is not reached"
        );
        let log = fx.log();
        assert_eq!(
            log.contains("propolis-migrate --check\n"),
            failing == "--check",
            "{log}"
        );
        assert_eq!(
            log.matches("RENAME TO").count(),
            1,
            "{failing}: the restored database stays under its name: {log}"
        );
        assert!(
            fx.databases().contains(&(
                "propolis".to_string(),
                "restored from the dump\n".to_string()
            )),
            "{failing}"
        );
    }
}

/// The same through the real `deploy/migrate.sh`, installed as an upgrade leaves it. It reads
/// `migrate.env` under the same root, takes the node for split because that file names an owner
/// role, and hands both URLs to the rolled-back binary's `migrate` and `migrate --check`. Without
/// the file the node has one role and nothing is run.
#[test]
fn the_installed_migrate_script_runs_migrate_and_the_check_with_the_rolled_back_binary() {
    let install_real_helper = |fx: &Fixture| {
        write_exec(
            &fx.root.join("usr/local/sbin/propolis-migrate"),
            &read(Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/migrate.sh"
            ))),
        );
    };

    let fx = Fixture::new();
    install_real_helper(&fx);
    let migrate_env = fx.root.join("etc/propolis/migrate.env");
    std::fs::write(
        &migrate_env,
        "PROPOLIS_MIGRATE_DATABASE_URL=postgres://propolis_owner:pw@localhost/propolis\n",
    )
    .unwrap();
    std::fs::set_permissions(&migrate_env, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    assert_ok(&fx.run(
        &["--with-database", "--yes"],
        &[("STUB_DB_OWNER", "propolis_owner")],
        None,
    ));
    assert_in_order(
        &fx.log(),
        &[
            "restored 15 bytes",
            "propolis migrate (abc000000001)\n",
            "propolis migrate --check (abc000000001)\n",
            "systemctl start",
        ],
    );

    let fx = Fixture::new();
    install_real_helper(&fx);
    std::fs::remove_file(fx.root.join("etc/propolis/migrate.env")).unwrap();
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    assert_ok(&fx.run(&["--with-database", "--yes"], &[], None));
    assert!(!fx.log().contains("propolis migrate"), "{}", fx.log());
}

/// A kept release from before `propolis migrate` cannot put the split back, and running its
/// binary with that argument would start the daemon as root. The rollback does not fail: it says,
/// where it cannot be missed, that ownership has to be handed back by hand, and goes on.
#[test]
fn on_a_split_node_a_release_from_before_migrate_is_rolled_back_with_a_warning() {
    let fx = Fixture::new();
    write_exec(
        &fx.root.join("usr/local/bin/propolis"),
        &propolis_stub_before_migrate("abc000000001"),
    );
    assert_ok(&fx.run(&["--save", "--backup-set", SET, "propolis"], &[], None));
    fx.upgrade();
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_SPLIT_ROLES", "1")],
        None,
    );
    assert_ok(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("WARNING: this node splits").count(),
        2,
        "said when it is found and again at the end: {stderr}"
    );
    assert!(
        stderr.trim_end().ends_with("\"Going back to one role\"."),
        "the warning is the last thing printed: {stderr}"
    );
    let log = fx.log();
    assert!(!log.contains("propolis-migrate"), "{log}");
    assert!(log.contains("systemctl start propolis.service"), "{log}");

    // That release's daemon cannot start under the split, so the usual end of such a rollback
    // is a daemon that does not stay up. The warning is then still the last thing on the screen.
    let out = fx.run(
        &["--with-database", "--yes"],
        &[("STUB_SPLIT_ROLES", "1"), ("STUB_INACTIVE", "1")],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("did not stay up"), "{stderr}");
    assert_eq!(stderr.matches("WARNING: this node splits").count(), 2);
    assert!(
        stderr.trim_end().ends_with("\"Going back to one role\"."),
        "the warning is the last thing printed: {stderr}"
    );
}

#[test]
fn an_encrypted_dump_is_decrypted_with_the_identity_on_the_way_to_pg_restore() {
    let fx = Fixture::new();
    let identity = fx.encrypt_dump(b"PGDMP-decrypted");
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
