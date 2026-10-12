//! Runs `deploy/alert.sh` (the OnFailure= hook) against a scratch root with stub `curl`,
//! `journalctl`, `logger` and `hostname` on `PATH`, and asserts where an alert goes, that a
//! crash loop pages once per cooldown, that journal text never reaches a header, and that the
//! ntfy token never reaches a command line.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const TOKEN: &str = "tk_secret_token";

/// Records argv, the header file it was handed and the body it read on stdin.
const CURL_STUB: &str = r#"#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$STUB_LOG"
for a in "$@"; do
    case "$a" in @/*) printf 'header-file:\n' >> "$STUB_LOG"; cat "${a#@}" >> "$STUB_LOG" ;; esac
done
printf 'body:\n' >> "$STUB_LOG"
cat >> "$STUB_LOG"
printf '\n' >> "$STUB_LOG"
[ -z "${STUB_CURL_FAIL:-}" ]
"#;

const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
printf '2026-10-11T12:00:00+0000 host sensor[1]: panicked at boom\r\nTitle: injected\n'
"#;

const LOGGER_STUB: &str = r#"#!/usr/bin/env bash
printf 'logger %s\n' "$*" >> "$STUB_LOG"
"#;

const HOSTNAME_STUB: &str = "#!/bin/sh\necho honeybox\n";

fn write_exec(path: &Path, body: &str) {
    let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new(env_file: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("etc/propolis")).unwrap();
        std::fs::write(root.join("etc/propolis/propolis.env"), env_file).unwrap();
        let bin = dir.path().join("bin");
        for (name, body) in [
            ("curl", CURL_STUB),
            ("journalctl", JOURNALCTL_STUB),
            ("logger", LOGGER_STUB),
            ("hostname", HOSTNAME_STUB),
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

    fn with_ntfy() -> Self {
        Self::new(&format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example/\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\nPROPOLIS_OPS_NTFY_TOKEN=\"{TOKEN}\"\n"
        ))
    }

    fn run(&self, unit: &str, env: &[(&str, &str)]) -> Output {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert.sh");
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg(script)
            .arg(unit)
            .env("PATH", path)
            .env("PROPOLIS_ALERT_ROOT", &self.root)
            .env("STUB_LOG", &self.log)
            .env_remove("PROPOLIS_ALERT_COOLDOWN_SECS")
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

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "alert.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_failure_posts_to_the_ops_topic_with_the_journal_in_the_body_only() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    let log = fx.log();
    assert!(log.contains("https://ntfy.example/propolis-ops"), "{log}");
    assert!(
        log.contains("Title: propolis: sensor-ssh.service failed on honeybox"),
        "{log}"
    );
    assert!(log.contains("Priority: 5"), "{log}");
    assert!(
        log.contains("Authorization: Bearer tk_secret_token"),
        "token in the header file: {log}"
    );
    let argv: Vec<&str> = log.lines().filter(|l| l.starts_with("curl ")).collect();
    assert!(
        argv.iter().all(|l| !l.contains(TOKEN)),
        "the token never reaches argv: {argv:?}"
    );

    let headers = log
        .split("header-file:\n")
        .nth(1)
        .unwrap()
        .split("body:\n")
        .next()
        .unwrap();
    assert!(
        !headers.contains("injected"),
        "journal text never becomes a header: {headers}"
    );
    let body = log.split("body:\n").nth(1).unwrap();
    assert!(body.contains("panicked at boom"), "{body}");
    assert!(
        !log.contains("logger"),
        "a delivered alert is not also logged: {log}"
    );
}

#[test]
fn a_crash_loop_pages_once_per_cooldown() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[]));
    assert_ok(&fx.run("propolis.service", &[]));
    assert_ok(&fx.run("propolis.service", &[]));
    let log = fx.log();
    assert_eq!(log.matches("curl ").count(), 1, "{log}");
    assert_eq!(log.matches("not repeating").count(), 2, "{log}");

    // Another unit is its own cooldown, and a zero cooldown pages every time.
    assert_ok(&fx.run("sensor-telnet.service", &[]));
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_COOLDOWN_SECS", "0")]));
    assert_eq!(fx.log().matches("curl ").count(), 3, "{}", fx.log());
}

#[test]
fn without_ntfy_or_when_the_post_fails_the_alert_goes_to_the_journal() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n");
    assert_ok(&fx.run("propolis-backup.service", &[]));
    let log = fx.log();
    assert!(!log.contains("curl"), "{log}");
    assert!(
        log.contains("logger -p daemon.err -t propolis-alert"),
        "{log}"
    );
    assert!(
        log.contains("propolis-backup.service entered the failed state"),
        "{log}"
    );

    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    let log = fx.log();
    assert!(log.contains("could not post to ntfy"), "{log}");
    assert!(
        log.contains("propolis.service entered the failed state"),
        "{log}"
    );
}

#[test]
fn an_unsafe_unit_name_is_refused() {
    let fx = Fixture::with_ntfy();
    for unit in ["", "bad unit", "x\nTitle: y", "../../etc"] {
        assert_eq!(fx.run(unit, &[]).status.code(), Some(2), "{unit:?}");
    }
    assert!(fx.log().is_empty());
}
