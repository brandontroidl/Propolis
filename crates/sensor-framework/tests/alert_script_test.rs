//! Runs `deploy/alert.sh` (the OnFailure= hook) against a scratch root with stub `curl`,
//! `journalctl`, `logger` and `hostname` on `PATH`, and asserts where an alert goes, that a
//! crash loop pages once per cooldown, that an alert that was not delivered neither arms that
//! cooldown nor floods ntfy or the journal, that journal text never reaches a header, and that the
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
            .env_remove("PROPOLIS_ALERT_RETRY_SECS")
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

    /// The stamp that arms the full cooldown once an alert for `unit` was delivered.
    fn delivered_stamp(&self, unit: &str) -> PathBuf {
        self.root.join("run/propolis-alert").join(unit)
    }

    /// The stamp that holds the retry and counts failures while an alert for `unit` is undelivered.
    fn undelivered_stamp(&self, unit: &str) -> PathBuf {
        self.root.join("run/propolis-alert/undelivered").join(unit)
    }

    /// Takes curl off `PATH`. The real one is almost certainly installed on the test host, so the
    /// script runs with the stubs first and then a directory of links to every other program on
    /// the test's `PATH`, which leaves bash and the coreutils the script needs but no curl.
    fn remove_curl(&self) -> String {
        std::fs::remove_file(self.bin.join("curl")).unwrap();
        let farm = self._dir.path().join("no-curl");
        std::fs::create_dir_all(&farm).unwrap();
        let real = std::env::var("PATH").unwrap();
        for dir in std::env::split_paths(&real) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let link = farm.join(&name);
                if name == "curl" || link.symlink_metadata().is_ok() {
                    continue;
                }
                let _ = std::os::unix::fs::symlink(entry.path(), link);
            }
        }
        format!("{}:{}", self.bin.display(), farm.display())
    }

    fn restore_curl(&self) {
        write_exec(&self.bin.join("curl"), CURL_STUB);
    }
}

/// How many times the full alert text went to the journal (the curl stub records the body too).
fn journal_bodies(log: &str) -> usize {
    log.lines()
        .filter(|l| l.starts_with("logger ") && l.contains("entered the failed state"))
        .count()
}

/// Dates `path` a day into the future, as a clock stepped back by a day would leave it.
fn date_in_the_future(path: &Path) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(86_400))
        .unwrap();
}

/// Dates `path` `secs` seconds into the past, as that much time passing would leave it.
fn age_by(path: &Path, secs: u64) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(secs))
        .unwrap();
}

/// Seconds since `path` was last modified.
fn age_of(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .elapsed()
        .unwrap_or_default()
        .as_secs()
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The numeric value that follows `flag` in a recorded curl argv line.
fn curl_flag_value(argv: &str, flag: &str) -> u64 {
    let mut words = argv.split_whitespace();
    while let Some(w) = words.next() {
        if w == flag {
            return words
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{flag} has no numeric value: {argv}"));
        }
    }
    panic!("curl is run without {flag}: {argv}");
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
fn a_delivered_alert_still_suppresses_repeats_of_a_crash_loop_for_the_cooldown() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[]));
    assert_ok(&fx.run("propolis.service", &[]));
    // The retry hold only paces an undelivered alert; it never shortens a delivered one's cooldown.
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "0")]));
    let log = fx.log();
    assert_eq!(log.matches("curl ").count(), 1, "{log}");
    assert_eq!(log.matches("not repeating").count(), 2, "{log}");
    assert!(!log.contains("daemon.err"), "{log}");
    assert!(fx.delivered_stamp("propolis.service").exists());
    assert!(!fx.undelivered_stamp("propolis.service").exists());

    // Another unit is its own cooldown, and a zero cooldown pages every time.
    assert_ok(&fx.run("sensor-telnet.service", &[]));
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_COOLDOWN_SECS", "0")]));
    assert_eq!(fx.log().matches("curl ").count(), 3, "{}", fx.log());
}

#[test]
fn a_failed_post_does_not_arm_the_cooldown_and_the_next_failure_posts_after_the_retry_hold() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    assert!(
        !fx.delivered_stamp("propolis.service").exists(),
        "an alert nobody received must not arm the cooldown"
    );
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "0")]));
    let log = fx.log();
    assert_eq!(log.matches("curl ").count(), 2, "{log}");
    assert!(!log.contains("not repeating"), "{log}");
    assert!(fx.delivered_stamp("propolis.service").exists());
    assert!(
        !fx.undelivered_stamp("propolis.service").exists(),
        "a delivered alert clears the undelivered state"
    );
}

#[test]
fn within_the_retry_hold_no_second_post_is_attempted_and_the_full_body_is_not_written_twice() {
    let fx = Fixture::with_ntfy();
    let failing = [("STUB_CURL_FAIL", "1")];
    assert_ok(&fx.run("propolis.service", &failing));
    assert_ok(&fx.run("propolis.service", &failing));
    let log = fx.log();
    assert_eq!(log.matches("curl ").count(), 1, "{log}");
    assert_eq!(journal_bodies(&log), 1, "{log}");
    let short: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("still undelivered since"))
        .collect();
    assert_eq!(short.len(), 1, "{log}");
    assert!(short[0].starts_with("logger -p daemon.err"), "{log}");
    assert!(short[0].contains("propolis.service"), "{log}");

    // Past the hold it posts again, and a second failed post still writes only the short line,
    // because the full text went to the journal less than a cooldown ago.
    assert_ok(&fx.run(
        "propolis.service",
        &[("STUB_CURL_FAIL", "1"), ("PROPOLIS_ALERT_RETRY_SECS", "0")],
    ));
    let log = fx.log();
    assert_eq!(log.matches("curl ").count(), 2, "{log}");
    assert_eq!(journal_bodies(&log), 1, "{log}");
    assert_eq!(log.matches("still undelivered since").count(), 2, "{log}");

    // Once a full cooldown has passed since then, the full text is written again.
    assert_ok(&fx.run(
        "propolis.service",
        &[
            ("STUB_CURL_FAIL", "1"),
            ("PROPOLIS_ALERT_RETRY_SECS", "0"),
            ("PROPOLIS_ALERT_COOLDOWN_SECS", "0"),
        ],
    ));
    assert_eq!(journal_bodies(&fx.log()), 2, "{}", fx.log());
}

#[test]
fn a_success_after_undelivered_failures_reports_how_many_went_undelivered() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    std::fs::write(&fx.log, b"").unwrap();
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "0")]));
    let log = fx.log();
    let headers = log
        .split("header-file:\n")
        .nth(1)
        .unwrap()
        .split("body:\n")
        .next()
        .unwrap();
    let body = log.split("body:\n").nth(1).unwrap();
    assert!(
        body.contains("2 earlier failures of this unit since "),
        "{body}"
    );
    assert!(body.contains("went undelivered"), "{body}");
    assert!(!headers.contains("undelivered"), "{headers}");

    // The count starts again after a delivery.
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_COOLDOWN_SECS", "0")]));
    let body = fx.log().rsplit("body:\n").next().unwrap().to_string();
    assert!(!body.contains("undelivered"), "{body}");
}

#[test]
fn a_stamp_dated_in_the_future_does_not_suppress_the_alert() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[]));
    date_in_the_future(&fx.delivered_stamp("propolis.service"));
    assert_ok(&fx.run("propolis.service", &[]));
    let log = fx.log();
    assert_eq!(log.matches("curl ").count(), 2, "{log}");
    assert!(!log.contains("not repeating"), "{log}");

    // The same holds for the retry hold of an undelivered alert.
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("sensor-ssh.service", &[("STUB_CURL_FAIL", "1")]));
    date_in_the_future(&fx.undelivered_stamp("sensor-ssh.service"));
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    assert_eq!(fx.log().matches("curl ").count(), 2, "{}", fx.log());
}

#[test]
fn a_missing_curl_is_named_in_the_journal_line_and_does_not_arm_the_cooldown() {
    let fx = Fixture::with_ntfy();
    let path = fx.remove_curl();
    assert_ok(&fx.run("propolis.service", &[("PATH", &path)]));
    let log = fx.log();
    assert!(
        log.contains("logger -p daemon.err -t propolis-alert curl is not installed, so this host cannot push alerts; install it"),
        "{log}"
    );
    assert!(!log.contains("could not post to ntfy"), "{log}");
    assert!(
        log.contains("propolis.service entered the failed state"),
        "{log}"
    );
    assert!(!fx.delivered_stamp("propolis.service").exists());

    fx.restore_curl();
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "0")]));
    assert_eq!(fx.log().matches("curl -").count(), 1, "{}", fx.log());
}

#[test]
fn with_no_target_configured_the_journal_line_is_the_alert_and_arms_the_cooldown() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n");
    assert_ok(&fx.run("propolis.service", &[]));
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "0")]));
    let log = fx.log();
    assert_eq!(log.matches("entered the failed state").count(), 1, "{log}");
    assert_eq!(log.matches("not repeating").count(), 1, "{log}");
    assert!(!log.contains("undelivered"), "{log}");
    assert!(fx.delivered_stamp("propolis.service").exists());
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

#[test]
fn the_post_is_bounded_in_total_time_so_it_ends_before_the_hook_unit_is_killed() {
    // curl obeys a server's Retry-After between retries; without a bound on the whole retry
    // period a long one outlives TimeoutStartSec, and systemd kills the hook before it records
    // the failure or journals the alert.
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/propolis-alert@.service"
    ))
    .unwrap();
    let timeout: u64 = unit
        .lines()
        .find_map(|l| l.trim().strip_prefix("TimeoutStartSec="))
        .map(|v| v.trim().trim_end_matches('s').parse().unwrap())
        .expect("propolis-alert@.service sets TimeoutStartSec= in seconds");

    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[]));
    let log = fx.log();
    let argv = log.lines().find(|l| l.starts_with("curl ")).unwrap();
    let retry_max = curl_flag_value(argv, "--retry-max-time");
    let max_time = curl_flag_value(argv, "--max-time");
    // The last attempt may start just inside the retry period and then run its full --max-time,
    // and the script needs a few seconds after that to record the result.
    assert!(
        retry_max + max_time + 10 <= timeout,
        "--retry-max-time {retry_max} plus --max-time {max_time} leaves no room under TimeoutStartSec={timeout}"
    );
}

#[test]
fn an_earlier_undelivered_failure_is_reported_as_its_own_fact_without_calling_the_alert_late() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    let pending = fx.undelivered_stamp("propolis.service");
    let month_ago = now_epoch() - 30 * 86_400;
    std::fs::write(&pending, format!("{month_ago} 1 {month_ago}\n")).unwrap();
    age_by(&pending, 30 * 86_400);
    std::fs::write(&fx.log, b"").unwrap();
    assert_ok(&fx.run("propolis.service", &[]));
    let body = fx.log().split("body:\n").nth(1).unwrap().to_string();
    assert!(
        body.contains("1 earlier failures of this unit since "),
        "{body}"
    );
    assert!(!body.contains("is late"), "{body}");
}

#[test]
fn the_held_line_after_a_missing_curl_does_not_blame_a_post() {
    let fx = Fixture::with_ntfy();
    let path = fx.remove_curl();
    assert_ok(&fx.run("propolis.service", &[("PATH", &path)]));
    assert_ok(&fx.run("propolis.service", &[("PATH", &path)]));
    let log = fx.log();
    let held: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("not retrying yet"))
        .collect();
    assert_eq!(held.len(), 1, "{log}");
    assert!(!held[0].contains("post failed"), "{log}");
    assert!(held[0].contains("still undelivered since"), "{log}");
}

#[test]
fn the_retry_hold_runs_from_the_last_post_attempt_not_from_the_last_held_failure() {
    let fx = Fixture::with_ntfy();
    let failing = [("STUB_CURL_FAIL", "1")];
    assert_ok(&fx.run("propolis.service", &failing));
    let pending = fx.undelivered_stamp("propolis.service");
    age_by(&pending, 100);
    assert_ok(&fx.run("propolis.service", &failing));
    assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
    let age = age_of(&pending);
    assert!(
        (98..=105).contains(&age),
        "a held failure keeps the last post attempt's date, age {age}"
    );

    // 130 s since the post, 30 s since the held failure: the hold has passed.
    age_by(&pending, 130);
    assert_ok(&fx.run("propolis.service", &failing));
    assert_eq!(fx.log().matches("curl ").count(), 2, "{}", fx.log());
}

#[test]
fn a_damaged_undelivered_state_file_is_started_over() {
    for damaged in ["abc 1 2", "", "1 2"] {
        let fx = Fixture::with_ntfy();
        let pending = fx.undelivered_stamp("propolis.service");
        std::fs::create_dir_all(pending.parent().unwrap()).unwrap();
        std::fs::write(&pending, damaged).unwrap();
        let output = fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]);
        assert_ok(&output);
        let log = fx.log();
        assert_eq!(log.matches("curl ").count(), 1, "{damaged:?}: {log}");
        assert_eq!(journal_bodies(&log), 1, "{damaged:?}: {log}");
        assert!(!log.contains("earlier failures"), "{damaged:?}: {log}");
        let state = std::fs::read_to_string(&pending).unwrap();
        let fields: Vec<&str> = state.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "{damaged:?}: {state:?}");
        assert!(
            fields
                .iter()
                .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit())),
            "{damaged:?}: {state:?}"
        );
    }
}

#[test]
fn an_invalid_retry_setting_falls_back_to_the_default_hold() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    age_by(&fx.undelivered_stamp("propolis.service"), 200);
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "2m")]));
    assert_eq!(fx.log().matches("curl ").count(), 2, "{}", fx.log());
    assert!(fx.delivered_stamp("propolis.service").exists());
}

#[test]
fn the_first_undelivered_failure_keeps_its_date_across_later_failures() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    let pending = fx.undelivered_stamp("propolis.service");
    let state = std::fs::read_to_string(&pending).unwrap();
    let logged = state.split_whitespace().nth(2).unwrap().to_string();
    std::fs::write(&pending, format!("1700000000 1 {logged}\n")).unwrap();
    age_by(&pending, 1000);
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    let log = fx.log();
    assert!(
        log.contains("still undelivered since 2023-11-14T22:13:20Z"),
        "{log}"
    );

    std::fs::write(&fx.log, b"").unwrap();
    assert_ok(&fx.run("propolis.service", &[("PROPOLIS_ALERT_RETRY_SECS", "0")]));
    let body = fx.log().split("body:\n").nth(1).unwrap().to_string();
    assert!(
        body.contains("2 earlier failures of this unit since 2023-11-14T22:13:20Z"),
        "{body}"
    );
}

#[test]
fn a_header_file_that_cannot_be_created_leaves_the_alert_undelivered_in_the_journal() {
    let fx = Fixture::with_ntfy();
    let missing = fx._dir.path().join("no-such-tmp");
    let output = fx.run("propolis.service", &[("TMPDIR", missing.to_str().unwrap())]);
    assert_ok(&output);
    let log = fx.log();
    assert!(
        log.contains(
            "logger -p daemon.err -t propolis-alert could not create the ntfy header file"
        ),
        "{log}"
    );
    assert!(!log.contains("curl "), "{log}");
    assert_eq!(journal_bodies(&log), 1, "{log}");
    assert!(!fx.delivered_stamp("propolis.service").exists());
    assert!(fx.undelivered_stamp("propolis.service").exists());
}

#[test]
fn the_default_retry_hold_is_two_minutes() {
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    age_by(&fx.undelivered_stamp("propolis.service"), 121);
    assert_ok(&fx.run("propolis.service", &[]));
    assert_eq!(fx.log().matches("curl ").count(), 2, "{}", fx.log());

    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis.service", &[("STUB_CURL_FAIL", "1")]));
    age_by(&fx.undelivered_stamp("propolis.service"), 110);
    assert_ok(&fx.run("propolis.service", &[]));
    assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
}
