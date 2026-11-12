//! deploy/migrate.sh, the root wrapper that runs `propolis migrate` as the schema's owner role.
//! Run against a stub `propolis` that records its arguments and which URLs reached its
//! environment, under a scratch root (PROPOLIS_MIGRATE_ROOT), so no database is needed: what the
//! binary then does with the URLs is covered in crates/propolis (db_roles, tests/migrate_cli.rs).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

/// Serialises writing a stub and spawning it, as in backup_script_test.rs: a file still open for
/// writing in another thread cannot be executed (ETXTBSY).
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const OWNER_SECRET: &str = "owner-pw-7Q";
const RUNTIME_SECRET: &str = "runtime-pw-3Z";

/// Carries the usage text the wrapper looks for before it will run the binary.
const PROPOLIS_STUB: &str = r#"#!/usr/bin/env bash
# usage: propolis migrate
printf 'args=%s owner=%s runtime=%s\n' "$*" "${PROPOLIS_MIGRATE_DATABASE_URL:-unset}" "${DATABASE_URL:-unset}" >> "$STUB_LOG"
exit "${STUB_EXIT:-0}"
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
        std::fs::create_dir_all(root.join("etc/propolis")).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        let fx = Fixture {
            _dir: dir,
            root,
            bin,
            log,
        };
        fx.write_stub(PROPOLIS_STUB);
        fx.write_env(
            "propolis.env",
            &format!(
                "PROPOLIS_FEED_ENABLED=true\nDATABASE_URL=\"postgres://propolis:{RUNTIME_SECRET}@localhost/propolis\"\n"
            ),
            0o600,
        );
        fx
    }

    fn write_stub(&self, body: &str) {
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.bin.join("propolis");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write_env(&self, name: &str, body: &str, mode: u32) {
        let path = self.root.join("etc/propolis").join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn owner_env(&self, mode: u32) {
        self.write_env(
            "migrate.env",
            &format!(
                "PROPOLIS_MIGRATE_DATABASE_URL=postgres://propolis_owner:{OWNER_SECRET}@localhost/propolis\n"
            ),
            mode,
        );
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/migrate.sh");
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg(script)
            .args(args)
            .env("PATH", path)
            .env("PROPOLIS_MIGRATE_ROOT", &self.root)
            .env("STUB_LOG", &self.log)
            .env_remove("PROPOLIS_BIN")
            .env_remove("DATABASE_URL")
            .env_remove("PROPOLIS_MIGRATE_DATABASE_URL")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().expect("bash runs")
        };
        child.wait_with_output().expect("migrate.sh finishes")
    }

    fn stub_log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn with_an_owner_url_it_hands_both_urls_to_the_binary_in_its_environment() {
    let fx = Fixture::new();
    fx.owner_env(0o600);
    let output = fx.run(&[], &[]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let log = fx.stub_log();
    assert_eq!(
        log.trim_end(),
        format!(
            "args=migrate owner=postgres://propolis_owner:{OWNER_SECRET}@localhost/propolis \
             runtime=postgres://propolis:{RUNTIME_SECRET}@localhost/propolis"
        )
    );
    // The arguments are the one word: neither URL, and so neither password, is on a command line.
    let args = log.split(" owner=").next().unwrap();
    assert!(!args.contains("postgres://"), "{args}");
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr_of(&output)
    );
    assert!(!printed.contains(OWNER_SECRET) && !printed.contains(RUNTIME_SECRET));
}

/// A node that has not split its roles: the wrapper changes nothing and says why, with an exit
/// code upgrade.sh never sees because it asks `--configured` first.
#[test]
fn without_an_owner_url_it_runs_nothing_and_exits_3() {
    let fx = Fixture::new();
    for body in [
        None,
        Some(""),
        Some("# PROPOLIS_MIGRATE_DATABASE_URL=later\n"),
    ] {
        if let Some(body) = body {
            fx.write_env("migrate.env", body, 0o600);
        }
        let configured = fx.run(&["--configured"], &[]);
        assert_eq!(configured.status.code(), Some(1));
        assert!(configured.stdout.is_empty() && configured.stderr.is_empty());

        let output = fx.run(&[], &[]);
        assert_eq!(output.status.code(), Some(3), "{}", stderr_of(&output));
        assert!(stderr_of(&output).contains("the roles are not split"));
    }
    assert_eq!(fx.stub_log(), "", "the binary was never run");
}

#[test]
fn configured_is_true_once_the_owner_url_is_written_and_runs_nothing() {
    let fx = Fixture::new();
    fx.owner_env(0o600);
    let output = fx.run(&["--configured"], &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fx.stub_log(), "");
}

/// The file is the owner's credential. Readable by group or other it is the control undone, so
/// the wrapper stops instead of using it.
#[test]
fn an_owner_file_others_can_read_is_refused() {
    let fx = Fixture::new();
    for mode in [0o644, 0o640, 0o604] {
        fx.owner_env(mode);
        let output = fx.run(&[], &[]);
        assert_eq!(output.status.code(), Some(1), "mode {mode:o}");
        assert!(
            stderr_of(&output).contains("must be 0600"),
            "{}",
            stderr_of(&output)
        );
    }
    assert_eq!(fx.stub_log(), "");
    fx.owner_env(0o400);
    assert!(fx.run(&[], &[]).status.success());
}

#[test]
fn check_runs_as_the_daemons_role_and_never_sees_the_owner_url() {
    let fx = Fixture::new();
    fx.owner_env(0o600);
    let output = fx.run(&["--check"], &[("STUB_EXIT", "1")]);
    // The binary's verdict is the wrapper's exit code.
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fx.stub_log().trim_end(),
        format!(
            "args=migrate --check owner=unset \
             runtime=postgres://propolis:{RUNTIME_SECRET}@localhost/propolis"
        )
    );
}

#[test]
fn the_last_assignment_wins_and_quotes_are_dropped_as_systemd_reads_the_file() {
    let fx = Fixture::new();
    fx.write_env(
        "migrate.env",
        "PROPOLIS_MIGRATE_DATABASE_URL=postgres://old@localhost/propolis\n\
         PROPOLIS_MIGRATE_DATABASE_URL='postgres://new@localhost/propolis'\n",
        0o600,
    );
    assert!(fx.run(&[], &[]).status.success());
    assert!(
        fx.stub_log()
            .contains("owner=postgres://new@localhost/propolis runtime="),
        "{}",
        fx.stub_log()
    );
}

/// A propolis binary from before `migrate` would treat the word as nothing and start the daemon,
/// as root. The wrapper looks for the subcommand's usage text and refuses a binary without it.
#[test]
fn a_binary_without_the_subcommand_is_refused_without_running_it() {
    let fx = Fixture::new();
    fx.owner_env(0o600);
    fx.write_stub("#!/usr/bin/env bash\necho ran >> \"$STUB_LOG\"\n");
    for args in [&[][..], &["--check"][..]] {
        let output = fx.run(args, &[]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr_of(&output).contains("has no migrate subcommand"),
            "{}",
            stderr_of(&output)
        );
    }
    assert_eq!(fx.stub_log(), "");
}

#[test]
fn a_missing_daemon_url_and_unknown_arguments_are_errors() {
    let fx = Fixture::new();
    fx.owner_env(0o600);
    for args in [&["--force"][..], &["--check", "--check"][..]] {
        assert_eq!(fx.run(args, &[]).status.code(), Some(2));
    }
    fx.write_env("propolis.env", "PROPOLIS_FEED_ENABLED=true\n", 0o600);
    for args in [&[][..], &["--check"][..]] {
        let output = fx.run(args, &[]);
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr_of(&output).contains("no DATABASE_URL"));
    }
    assert_eq!(fx.stub_log(), "");
}

/// upgrade.sh asks `--configured`, and only then stops propolis, migrates and starts it; a failed
/// migration must not be followed by a start. Read from the script so the order cannot drift.
#[test]
fn upgrade_migrates_between_stopping_and_starting_propolis_and_stops_on_failure() {
    let upgrade = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/upgrade.sh"
    ))
    .unwrap();
    let at = |needle: &str| {
        upgrade
            .find(needle)
            .unwrap_or_else(|| panic!("upgrade.sh has no `{needle}`"))
    };
    let install = at("install -m 0755 \"$SCRIPT_DIR/migrate.sh\" /usr/local/sbin/propolis-migrate");
    let asked = at("if /usr/local/sbin/propolis-migrate --configured; then");
    let stop = at("systemctl stop propolis.service");
    let migrate = at("if ! /usr/local/sbin/propolis-migrate; then");
    let start = at("systemctl start propolis.service");
    assert!(install < asked && asked < stop && stop < migrate && migrate < start);
    let failure = &upgrade[migrate..start];
    assert!(
        failure.contains("exit 1"),
        "a failed migration must end the upgrade: {failure}"
    );
    // A node without split roles restarts as before.
    assert!(upgrade[start..].contains("systemctl restart propolis.service"));

    let install_sh = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/install.sh"
    ))
    .unwrap();
    assert!(install_sh.contains("\"$SCRIPT_DIR/migrate.sh\" /usr/local/sbin/propolis-migrate"));
}
