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

/// The hook's own `journalctl -u UNIT ...` gets the same two lines for every unit. A query by
/// trusted fields (the record step's) is recorded in `$STUB_JLOG` and answered from the file
/// `$STUB_RUN_JOURNAL` only when it carries every word of `$STUB_RUN_MATCH`.
const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
case " $* " in
    *" -u "*) printf '2026-10-11T12:00:00+0000 host sensor[1]: panicked at boom\r\nTitle: injected\n' ;;
    *)
        printf 'journalctl %s\n' "$*" >> "${STUB_JLOG:-/dev/null}"
        [ -n "${STUB_RUN_JOURNAL:-}" ] || exit 0
        for w in ${STUB_RUN_MATCH:-}; do [[ " $* " == *" $w "* ]] || exit 0; done
        cat "$STUB_RUN_JOURNAL"
        ;;
esac
"#;

/// `systemctl show ... -- UNIT` answers from the file `$STUB_SHOW_DIR/UNIT` and fails when there
/// is none, as it does for a unit systemd cannot be asked about. Every call is recorded in
/// `$STUB_JLOG`.
const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${STUB_JLOG:-/dev/null}"
[ "$1" = show ] || exit 1
f="${STUB_SHOW_DIR:-/nonexistent}/${!#}"
[ -f "$f" ] || exit 1
cat "$f"
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
        // Where the record step keeps state, as provisioning leaves it.
        std::fs::create_dir_all(root.join("var/lib/propolis/witness")).unwrap();
        std::fs::write(root.join("var/lib/propolis/witness/state.lock"), b"").unwrap();
        std::fs::create_dir_all(root.join("run/propolis-witness")).unwrap();
        std::fs::create_dir_all(dir.path().join("show")).unwrap();
        for (name, body) in [
            ("curl", CURL_STUB),
            ("journalctl", JOURNALCTL_STUB),
            ("logger", LOGGER_STUB),
            ("hostname", HOSTNAME_STUB),
            ("systemctl", SYSTEMCTL_STUB),
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
        self.run_grouped(unit, env, false)
    }

    /// `run`, with the hook leading a process group of its own, so a stub may signal that whole
    /// group (as systemd stopping the unit signals its cgroup) without reaching the test runner.
    fn run_in_own_group(&self, unit: &str, env: &[(&str, &str)]) -> Output {
        self.run_grouped(unit, env, true)
    }

    fn run_grouped(&self, unit: &str, env: &[(&str, &str)], own_group: bool) -> Output {
        use std::os::unix::process::CommandExt;
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert.sh");
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg(script)
            .arg(unit)
            .env("PATH", path)
            .env("PROPOLIS_ALERT_ROOT", &self.root)
            .env("STUB_LOG", &self.log)
            .env("STUB_SHOW_DIR", self._dir.path().join("show"))
            .env("STUB_JLOG", self.jlog())
            .env_remove("PROPOLIS_ALERT_COOLDOWN_SECS")
            .env_remove("PROPOLIS_ALERT_RETRY_SECS")
            .env_remove("SECONDS")
            .env_remove("MONITOR_SERVICE_RESULT")
            .env_remove("MONITOR_EXIT_CODE")
            .env_remove("MONITOR_EXIT_STATUS")
            .env_remove("MONITOR_INVOCATION_ID")
            .env_remove("PA_HOOK_OUT")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if own_group {
            command.process_group(0);
        }
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

    /// Where the stubs record the record step's `systemctl` and journal queries.
    fn jlog(&self) -> PathBuf {
        self._dir.path().join("queries.log")
    }

    fn queries(&self) -> String {
        std::fs::read_to_string(self.jlog()).unwrap_or_default()
    }

    /// What `systemctl show` says about `unit`.
    fn show(&self, unit: &str, answer: &str) {
        std::fs::write(self._dir.path().join("show").join(unit), answer).unwrap();
    }

    /// Installs `body` where the hook looks for the shared library.
    fn install_lib(&self, body: &str) {
        let path = self.root.join("usr/local/sbin/propolis-alert-lib");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// The shipped library, installed.
    fn with_lib(self) -> Self {
        self.install_lib(&shipped_lib());
        self
    }

    /// The `I` records of the incidents file at `rel` under the root, fields numbered as the
    /// format numbers them (index 0 is the type, 1 the id, 2 the key).
    fn records_at(&self, rel: &str) -> Vec<Vec<String>> {
        std::fs::read_to_string(self.root.join(rel))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("I\t"))
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect()
    }

    fn records(&self) -> Vec<Vec<String>> {
        self.records_at("var/lib/propolis/witness/incidents")
    }

    /// The one record for `unit`.
    fn record(&self, unit: &str) -> Vec<String> {
        let key = format!("unit:{unit}");
        let found: Vec<Vec<String>> = self
            .records()
            .into_iter()
            .filter(|f| f.get(2) == Some(&key))
            .collect();
        assert_eq!(found.len(), 1, "one record for {unit}: {found:?}");
        found.into_iter().next().unwrap()
    }
}

fn shipped_lib() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/alert-lib.sh"
    ))
    .unwrap()
}

fn shipped_hook() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/alert.sh"
    ))
    .unwrap()
}

/// The library version the hook states on its `# needs-alert-lib: <n>` line.
fn hook_needs() -> u32 {
    shipped_hook()
        .lines()
        .find_map(|l| l.strip_prefix("# needs-alert-lib: "))
        .and_then(|v| v.parse().ok())
        .expect("deploy/alert.sh carries `# needs-alert-lib: <n>`")
}

/// `text` with every `YYYY-MM-DDTHH:MM:SSZ` time replaced by `<time>`, so two runs a second apart
/// compare equal.
fn without_times(text: &str) -> String {
    let b = text.as_bytes();
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let fits = i + shape.len() <= b.len()
            && shape.iter().zip(&b[i..]).all(|(s, c)| match s {
                b'd' => c.is_ascii_digit(),
                other => other == c,
            });
        if fits {
            out.push_str("<time>");
            i += shape.len();
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// What the hook sent and logged as itself: the stub log without the record step's own line, and
/// with the random name `mktemp` gave the header file left out.
fn todays_part(log: &str) -> String {
    without_times(
        &log.lines()
            .filter(|l| !l.contains("-t propolis-witness"))
            .map(|l| {
                if l.starts_with("curl ") {
                    l.split(' ')
                        .map(|w| {
                            if w.starts_with("@/") {
                                "@<header file>"
                            } else {
                                w
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The record step's lines under its own tag.
fn witness_lines(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| l.contains("-t propolis-witness"))
        .map(str::to_string)
        .collect()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

/// A `systemctl show` answer.
fn show_answer(result: &str, status: &str, restart: &str, nrestarts: &str) -> String {
    format!(
        "Result={result}\nExecMainCode=1\nExecMainStatus={status}\nInvocationID={INVOCATION}\nRestart={restart}\nType=simple\nNRestarts={nrestarts}\n"
    )
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
        !log.contains("-t propolis-alert"),
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

/// Every way today's hook can end, as (name, what legacy_out records, how many runs).
const SCENARIOS: [(&str, &str, usize); 8] = [
    ("delivered", "delivered", 1),
    ("undelivered", "undelivered", 1),
    ("held", "undelivered", 2),
    ("cooldown", "cooldown", 2),
    ("no-target", "journal", 1),
    ("no-curl", "undelivered", 1),
    ("header-file", "undelivered", 1),
    ("bad-argument", "-", 0),
];

/// Runs scenario `name` in `fx` and returns each run's exit status.
fn run_scenario(fx: &Fixture, name: &str) -> Vec<Option<i32>> {
    let unit = "sensor-ssh.service";
    fx.show(unit, &show_answer("exit-code", "1", "always", "2"));
    let failing = [("STUB_CURL_FAIL", "1")];
    let runs: Vec<Output> = match name {
        "delivered" | "no-target" => vec![fx.run(unit, &[])],
        "undelivered" => vec![fx.run(unit, &failing)],
        "held" => vec![fx.run(unit, &failing), fx.run(unit, &failing)],
        "cooldown" => vec![fx.run(unit, &[]), fx.run(unit, &[])],
        "no-curl" => {
            let path = fx.remove_curl();
            vec![fx.run(unit, &[("PATH", &path)])]
        }
        "header-file" => {
            let missing = fx._dir.path().join("no-such-tmp");
            vec![fx.run(unit, &[("TMPDIR", missing.to_str().unwrap())])]
        }
        "bad-argument" => vec![fx.run("bad unit", &[])],
        other => panic!("no scenario {other}"),
    };
    runs.iter().map(|o| o.status.code()).collect()
}

fn scenario_fixture(name: &str) -> Fixture {
    if name == "no-target" {
        Fixture::new("PROPOLIS_FEED_ENABLED=true\n")
    } else {
        Fixture::with_ntfy()
    }
}

/// What the hook leaves in its own state directory: for the delivered stamp and the undelivered
/// file, whether each exists, its mode and how many fields it holds.
fn hook_state(fx: &Fixture) -> Vec<Option<(u32, usize)>> {
    let unit = "sensor-ssh.service";
    [fx.delivered_stamp(unit), fx.undelivered_stamp(unit)]
        .iter()
        .map(|p| {
            p.exists().then(|| {
                (
                    mode_of(p),
                    std::fs::read_to_string(p)
                        .unwrap()
                        .split_whitespace()
                        .count(),
                )
            })
        })
        .collect()
}

#[test]
fn legacy_with_the_library_installed_sends_todays_bytes_and_records_one_incident() {
    for (name, outcome, runs) in SCENARIOS {
        let bare = scenario_fixture(name);
        let bare_codes = run_scenario(&bare, name);
        let with = scenario_fixture(name).with_lib();
        let with_codes = run_scenario(&with, name);

        assert_eq!(with_codes, bare_codes, "{name}: exit status");
        assert_eq!(
            todays_part(&with.log()),
            todays_part(&bare.log()),
            "{name}: what was sent and logged as propolis-alert"
        );
        assert_eq!(hook_state(&with), hook_state(&bare), "{name}: hook state");
        for state in hook_state(&with).into_iter().flatten() {
            assert_eq!(state.0, 0o600, "{name}: the hook's own files stay 0600");
        }

        // Without the library each run says the record is missing; with it, nothing is said.
        assert_eq!(
            witness_lines(&bare.log()).len(),
            runs,
            "{name}: {}",
            bare.log()
        );
        for line in witness_lines(&bare.log()) {
            assert!(
                line.starts_with("logger -p daemon.notice -t propolis-witness incident not recorded for sensor-ssh.service"),
                "{name}: {line}"
            );
        }
        assert_eq!(witness_lines(&with.log()), Vec::<String>::new(), "{name}");

        if runs == 0 {
            assert!(with.records().is_empty(), "{name}");
            continue;
        }
        let f = with.record("sensor-ssh.service");
        assert_eq!(f[33], outcome, "{name}: legacy_out");
        assert_eq!(f[31], runs.to_string(), "{name}: occ");
        assert_eq!(f[11], "proc.exit:1", "{name}: cause");
        assert_eq!(f[7], "pending", "{name}: a sensor restarts itself");
        assert_eq!(
            mode_of(&with.root.join("var/lib/propolis/witness/incidents")),
            0o600
        );
    }
}

/// A library that is not in the shape the hook expects, in each way a growing shell file can
/// break: what is sent, logged and returned is today's.
#[test]
fn a_library_with_an_unbound_variable_or_a_division_by_zero_cannot_stop_todays_page() {
    let shipped = shipped_lib();
    let broken = [
        (
            "unbound",
            format!("set -u\n: \"$PA_NO_SUCH_VARIABLE\"\n{shipped}"),
        ),
        (
            "division",
            format!("{shipped}\npa_hook_record() {{\n    local x=$((1/0))\n}}\n"),
        ),
        (
            "exit",
            format!("{shipped}\npa_hook_record() {{\n    exit 0\n}}\n"),
        ),
        (
            "hang",
            format!("{shipped}\npa_init() {{\n    sleep 300\n}}\n"),
        ),
        ("garbage", "this is not ( a shell file\n".to_string()),
        (
            "noisy",
            format!(
                "{shipped}\npa_hook_record() {{\n    echo to-stdout\n    echo to-stderr >&2\n}}\n"
            ),
        ),
    ];
    let bare = Fixture::with_ntfy();
    let bare_output = bare.run("sensor-ssh.service", &[]);
    assert_ok(&bare_output);
    for (name, body) in broken {
        let fx = Fixture::with_ntfy();
        fx.install_lib(&body);
        // A hook that has used most of its 90 s: the record gets what is left.
        let started = std::time::Instant::now();
        let output = fx.run("sensor-ssh.service", &[("SECONDS", "80")]);
        let took = started.elapsed();
        assert_ok(&output);
        // systemd journals the hook's own output as propolis-alert: a library cannot add to it.
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&bare_output.stdout),
            "{name}: stdout"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&bare_output.stderr),
            "{name}: stderr"
        );
        let log = fx.log();
        assert_eq!(todays_part(&log), todays_part(&bare.log()), "{name}");
        assert!(
            log.contains("Title: propolis: sensor-ssh.service failed on honeybox"),
            "{name}: {log}"
        );
        assert!(fx.delivered_stamp("sensor-ssh.service").exists(), "{name}");
        assert!(
            took < std::time::Duration::from_secs(60),
            "{name}: the hook took {took:?}, past the unit's 90 s budget once systemd's own start is counted"
        );
        if name == "exit" || name == "noisy" {
            // The library ended its own child cleanly: nothing is said, nothing recorded.
            assert!(fx.records().is_empty(), "{name}");
            assert_eq!(witness_lines(&log), Vec::<String>::new(), "{name}");
        } else {
            assert_eq!(witness_lines(&log).len(), 1, "{name}: {log}");
        }
        assert!(
            !log.contains("-t propolis-alert incident"),
            "{name}: the record step never logs as the hook"
        );
    }
}

#[test]
fn a_library_older_than_the_hook_needs_records_nothing_and_changes_nothing() {
    let need = hook_needs();
    let old: String = shipped_lib()
        .lines()
        .map(|l| {
            if l.starts_with("PA_LIB_VERSION=") {
                format!("PA_LIB_VERSION={}", need - 1)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let fx = Fixture::with_ntfy();
    fx.install_lib(&old);
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    assert!(fx.records().is_empty(), "{:?}", fx.records());
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
    assert!(
        fx.queries().is_empty(),
        "a library that is too old is not asked to read anything: {}",
        fx.queries()
    );

    // At exactly the version the hook needs, it records. The shipped library may be newer: a
    // newer library only adds functions, so it serves an older consumer.
    let shipped: u32 = shipped_lib()
        .lines()
        .find_map(|l| l.strip_prefix("PA_LIB_VERSION="))
        .and_then(|v| v.parse().ok())
        .unwrap();
    assert!(
        shipped >= need,
        "the shipped library ({shipped}) must serve the shipped hook ({need})"
    );
    let at_need: String = shipped_lib()
        .lines()
        .map(|l| {
            if l.starts_with("PA_LIB_VERSION=") {
                format!("PA_LIB_VERSION={need}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let fx = Fixture::with_ntfy();
    fx.install_lib(&at_need);
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    assert_eq!(fx.records().len(), 1);
}

#[test]
fn the_exit_handler_keeps_the_status_and_survives_an_unset_headers() {
    // The cooldown path ends before the header file exists.
    let fx = Fixture::with_ntfy().with_lib();
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    let output = fx.run("sensor-ssh.service", &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("unbound"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fx.record("sensor-ssh.service")[33], "cooldown");

    // A failing rm in the handler does not replace the status, either way.
    let fx = Fixture::with_ntfy().with_lib();
    write_exec(&fx.bin.join("rm"), "#!/bin/sh\nexit 1\n");
    assert_eq!(fx.run("sensor-ssh.service", &[]).status.code(), Some(0));
    assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
    write_exec(&fx.bin.join("hostname"), "#!/bin/sh\nexit 3\n");
    let bare = Fixture::with_ntfy();
    write_exec(&bare.bin.join("hostname"), "#!/bin/sh\nexit 3\n");
    let today = bare.run("propolis.service", &[]).status.code();
    assert_eq!(today, Some(3), "today's hook ends on the failing command");
    assert_eq!(
        fx.run("propolis.service", &[]).status.code(),
        today,
        "the record step keeps the status the hook ended with"
    );
    assert_eq!(fx.record("propolis.service")[33], "-");
}

#[test]
fn a_witness_unit_is_decided_by_name_before_any_library_code() {
    for unit in [
        "propolis-witness@light.service",
        "propolis-witness@hourly.service",
    ] {
        let fx = Fixture::with_ntfy().with_lib();
        fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
        let output = fx.run(unit, &[]);
        assert_ok(&output);
        let log = fx.log();
        assert!(!log.contains("curl"), "{unit}: no post: {log}");
        assert!(!log.contains("-t propolis-alert"), "{unit}: {log}");
        assert!(!fx.delivered_stamp(unit).exists());
        let f = fx.record(unit);
        assert_eq!(f[3], "unit-failed");
        assert_eq!(f[4], "witness");
        assert_eq!(f[6], "ACT");
        assert_eq!(f[33], "-", "today's hook did nothing for it");

        // Without the library it still posts nothing; the record step says it could not record.
        let fx = Fixture::with_ntfy();
        assert_ok(&fx.run(unit, &[]));
        assert!(!fx.log().contains("curl"), "{}", fx.log());
        assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
    }
    // A name that only looks like one is today's unit and pages.
    let fx = Fixture::with_ntfy();
    assert_ok(&fx.run("propolis-witness@Light.service", &[]));
    assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
}

/// Now that a witness pass runs on a timer and can fail, its failure is still never a page:
/// however the pass failed (a bad argument, a library it could not load, the unit's time limit),
/// with or without a push target and whatever the cooldown stamps say, the hook records it and
/// posts nothing, logs nothing as itself and exits 0.
#[test]
fn legacy_never_posts_for_a_witness_unit() {
    for (result, status) in [("exit-code", "2"), ("exit-code", "3"), ("timeout", "")] {
        for fx in [
            Fixture::with_ntfy().with_lib(),
            Fixture::new("").with_lib(),
            Fixture::with_ntfy(),
        ] {
            let unit = "propolis-witness@light.service";
            fx.show(unit, &show_answer(result, status, "no", "0"));
            let monitor = [
                ("MONITOR_SERVICE_RESULT", result),
                ("MONITOR_EXIT_CODE", "exited"),
                ("MONITOR_EXIT_STATUS", status),
            ];
            let output = fx.run(unit, &monitor);
            assert_eq!(output.status.code(), Some(0), "{result} {status}");
            let log = fx.log();
            assert!(!log.contains("curl"), "{result}: no post: {log}");
            assert!(!log.contains("-t propolis-alert"), "{result}: {log}");
            assert!(!fx.delivered_stamp(unit).exists());
            assert!(!fx.undelivered_stamp(unit).exists());
            // A second failure inside what would be the cooldown is not a page either.
            assert_eq!(fx.run(unit, &monitor).status.code(), Some(0));
            assert!(!fx.log().contains("curl"), "{}", fx.log());
        }
    }
}

#[test]
fn the_cause_comes_from_the_monitor_variables_and_falls_back_to_systemctl_show() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    let rows: [(&str, &str, &str, &str); 11] = [
        ("exit-code", "exited", "3", "proc.exit:3"),
        ("exit-code", "exited", "226", "proc.sandbox:226"),
        ("signal", "killed", "TERM", "proc.signal:15"),
        ("core-dump", "dumped", "SEGV", "proc.signal:11"),
        ("signal", "killed", "SYS", "proc.sigsys"),
        ("oom-kill", "killed", "KILL", "proc.oom"),
        ("timeout", "killed", "TERM", "proc.timeout"),
        ("watchdog", "killed", "ABRT", "proc.watchdog"),
        ("start-limit-hit", "", "", "proc.start_limit"),
        ("resources", "", "", "proc.resources"),
        ("protocol", "", "", "unknown"),
    ];
    for (i, (result, code, status, want)) in rows.iter().enumerate() {
        let unit = format!("monitor-{i}.service");
        // systemctl says something else: the monitor variables win.
        fx.show(&unit, &show_answer("exit-code", "9", "no", "0"));
        assert_ok(&fx.run(
            &unit,
            &[
                ("MONITOR_SERVICE_RESULT", result),
                ("MONITOR_EXIT_CODE", code),
                ("MONITOR_EXIT_STATUS", status),
                ("MONITOR_INVOCATION_ID", INVOCATION),
            ],
        ));
        assert_eq!(fx.record(&unit)[11], *want, "{result} {status}");
    }
    // Without them (systemd before 251), systemctl show's numbers.
    for (i, (result, status, want)) in [
        ("exit-code", "3", "proc.exit:3"),
        ("exit-code", "203", "proc.sandbox:203"),
        ("signal", "9", "proc.signal:9"),
        ("signal", "31", "proc.sigsys"),
        ("oom-kill", "9", "proc.oom"),
    ]
    .iter()
    .enumerate()
    {
        let unit = format!("show-{i}.service");
        fx.show(&unit, &show_answer(result, status, "no", "0"));
        assert_ok(&fx.run(&unit, &[]));
        assert_eq!(fx.record(&unit)[11], *want, "{result} {status}");
    }
    // Neither: unknown, and still recorded.
    assert_ok(&fx.run("silent.service", &[]));
    assert_eq!(fx.record("silent.service")[11], "unknown");
    assert!(
        fx.queries()
            .contains("systemctl show -p Result,ExecMainCode,ExecMainStatus,InvocationID,Restart,Type,NRestarts -- silent.service"),
        "{}",
        fx.queries()
    );
}

#[test]
fn a_panic_is_a_code_and_its_text_stays_out_of_the_record() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    let journal = fx._dir.path().join("run-journal");
    std::fs::write(
        &journal,
        "starting\nthread 'main' panicked at src/secret-path.rs:7:1: PLANTED-TEXT\nnote: run with RUST_BACKTRACE\n",
    )
    .unwrap();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "101", "always", "1"),
    );
    let output = fx.run(
        "sensor-ssh.service",
        &[
            ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
            (
                "STUB_RUN_MATCH",
                &format!("_SYSTEMD_UNIT=sensor-ssh.service _SYSTEMD_INVOCATION_ID={INVOCATION}"),
            ),
        ],
    );
    assert_ok(&output);
    assert_eq!(fx.record("sensor-ssh.service")[11], "proc.panic");
    let text = std::fs::read_to_string(fx.root.join("var/lib/propolis/witness/incidents")).unwrap();
    for planted in ["PLANTED-TEXT", "secret-path", "panicked", "main"] {
        assert!(!text.contains(planted), "{planted} in the record: {text}");
    }
}

#[test]
fn a_restarting_unit_is_a_first_sighting_and_a_oneshot_opens_at_once() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "4"),
    );
    fx.show(
        "propolis.service",
        &show_answer("exit-code", "1", "on-failure", "0"),
    );
    fx.show(
        "propolis-backup.service",
        &show_answer("exit-code", "1", "no", "0"),
    );
    for unit in [
        "sensor-ssh.service",
        "propolis.service",
        "propolis-backup.service",
        "unasked.service",
    ] {
        assert_ok(&fx.run(unit, &[]));
    }
    let ssh = fx.record("sensor-ssh.service");
    assert_eq!(
        (ssh[3].as_str(), ssh[4].as_str(), ssh[6].as_str()),
        ("unit-failed", "listen", "PAGE")
    );
    assert_eq!(ssh[7], "pending");
    assert_eq!(ssh[9], "-");
    assert_eq!(ssh[32], "4", "nr_seen");
    assert_eq!(ssh[29], "0", "nothing v2 would push yet");

    let daemon = fx.record("propolis.service");
    assert_eq!(
        (daemon[3].as_str(), daemon[4].as_str(), daemon[6].as_str()),
        ("daemon-down", "intake", "PAGE")
    );
    assert_eq!(daemon[7], "pending");

    let backup = fx.record("propolis-backup.service");
    assert_eq!(
        (backup[3].as_str(), backup[4].as_str(), backup[6].as_str()),
        ("unit-failed", "backup", "ACT")
    );
    assert_eq!(backup[7], "open");
    assert_ne!(backup[9], "-", "opened");
    assert_eq!(backup[29], "1", "the open v2 would have pushed");
    assert_eq!(backup[33], "journal");

    // systemd could not be asked whether it restarts: the light pass decides, so it waits.
    let unasked = fx.record("unasked.service");
    assert_eq!(unasked[7], "pending");
    assert_eq!(unasked[32], "-");
    assert_eq!(unasked[4], "host");

    let ids: Vec<String> = fx.records().iter().map(|f| f[1].clone()).collect();
    assert_eq!(ids, ["w#1", "w#2", "w#3", "w#4"]);
}

#[test]
fn a_maintenance_marker_keeps_an_open_pending_and_flags_it() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    let boot: String = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .replace('-', "")
        .chars()
        .take(8)
        .collect();
    std::fs::write(
        fx.root.join("run/propolis-witness/maintenance"),
        format!(
            "#maintenance v1 g=1\nX\t{}\t{boot}\tupgrade\n",
            now_epoch() + 600
        ),
    )
    .unwrap();
    fx.show(
        "propolis-backup.service",
        &show_answer("exit-code", "1", "no", "0"),
    );
    assert_ok(&fx.run("propolis-backup.service", &[]));
    let f = fx.record("propolis-backup.service");
    assert_eq!(f[7], "pending");
    assert_eq!(f[30], "maint");
    assert_eq!(f[29], "0");
    assert!(
        fx.log().contains("entered the failed state"),
        "the journal alert still goes out: {}",
        fx.log()
    );
}

/// Runs the rotation hook against a journal of the failed run holding `lines`, logged with the
/// trusted fields of `match_words`.
fn rotation_run(lines: &str, match_words: &str) -> (Fixture, Vec<String>) {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    let f = fire_rotation(&fx, lines, match_words);
    (fx, f)
}

/// One more failed rotation run in `fx`, whose journal holds `lines` under the trusted fields of
/// `match_words`; returns the rotation unit's record afterwards.
fn fire_rotation(fx: &Fixture, lines: &str, match_words: &str) -> Vec<String> {
    let journal = fx._dir.path().join("run-journal");
    std::fs::write(&journal, lines).unwrap();
    fx.show(
        "propolis-logrotate.service",
        &show_answer("exit-code", "1", "no", "0"),
    );
    assert_ok(&fx.run(
        "propolis-logrotate.service",
        &[
            ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
            ("STUB_RUN_MATCH", match_words),
        ],
    ));
    fx.record("propolis-logrotate.service")
}

const TRUSTED_ROTATION: &str = "_SYSTEMD_UNIT=propolis-logrotate.service _UID=0";

/// What the guard and logrotate log when the guard skips one log: the guard's line and
/// logrotate's companion line for the prerotate script that failed.
const GUARD_SKIP: &str = "propolis-logrotate-guard: skipping rotation of /var/log/propolis/ssh/ssh.log: the reader is behind\n\
                          error: error running non-shared prerotate script for /var/log/propolis/ssh/ssh.log\n";

const GUARD_COMPANION: &str =
    "error: error running non-shared prerotate script for /var/log/propolis/ssh/ssh.log\n";

const GUARD_REFUSAL: &str = "propolis-logrotate-guard: refusing to rotate /var/log/propolis/http/http.log: too little free space\n";

const STAT_ERROR: &str = "error: stat of /var/log/propolis/x.log failed: Permission denied\n";

#[test]
fn a_guard_skip_is_a_notice_and_a_refusal_is_act() {
    let (fx, f) = rotation_run(GUARD_SKIP, TRUSTED_ROTATION);
    assert_eq!(
        (f[3].as_str(), f[4].as_str(), f[6].as_str(), f[11].as_str()),
        ("rotation-skipped", "source", "NOTICE", "guard.behind")
    );
    assert_eq!(f[29], "0", "a NOTICE is never pushed");
    assert!(
        fx.queries().contains(&format!(
            "journalctl -q -o cat _SYSTEMD_UNIT=propolis-logrotate.service _UID=0 _SYSTEMD_INVOCATION_ID={INVOCATION}"
        )),
        "{}",
        fx.queries()
    );
    assert!(
        fx.log()
            .contains("propolis-logrotate.service entered the failed state"),
        "today's alert still goes out: {}",
        fx.log()
    );

    let refusal = format!("{GUARD_SKIP}{GUARD_REFUSAL}");
    let (_, f) = rotation_run(&refusal, TRUSTED_ROTATION);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "ACT", "guard.no_space")
    );
    assert_eq!(f[29], "1");

    let other = format!("{GUARD_SKIP}{STAT_ERROR}");
    let (_, f) = rotation_run(&other, TRUSTED_ROTATION);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "ACT", "proc.exit:1")
    );

    let (_, f) = rotation_run("reading config file\n", TRUSTED_ROTATION);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "ACT", "proc.exit:1"),
        "no guard line is an ordinary failure"
    );
}

#[test]
fn a_forged_guard_line_from_another_unit_is_ignored() {
    let skip = "propolis-logrotate-guard: skipping rotation of /var/log/propolis/ssh/ssh.log: the reader is behind\n";
    // The line is in the journal, but under another unit and another account: what `logger -t`
    // from a login session leaves. Only a query by the rotation unit's trusted fields is used.
    for forged_under in ["_SYSTEMD_UNIT=session-4.scope _UID=1000", "_UID=1000"] {
        let (_, f) = rotation_run(skip, forged_under);
        assert_eq!(
            (f[3].as_str(), f[6].as_str(), f[11].as_str()),
            ("unit-failed", "ACT", "proc.exit:1"),
            "{forged_under}"
        );
    }
}

#[test]
fn a_repeat_failure_only_counts() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.show(
        "propolis-backup.service",
        &show_answer("exit-code", "1", "no", "0"),
    );
    for _ in 0..3 {
        assert_ok(&fx.run("propolis-backup.service", &[]));
    }
    assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
    let records = fx.records();
    assert_eq!(records.len(), 1, "{records:?}");
    let f = &records[0];
    assert_eq!(f[7], "open");
    assert_eq!(f[31], "3", "occ");
    assert_eq!(f[29], "1", "one open, not three");
    assert_eq!(f[33], "cooldown");
}

/// Holds an exclusive flock on `path` until the returned file is dropped.
fn hold_lock(path: &Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: flock on a descriptor this process owns has no other precondition.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0, "could not take the lock");
    file
}

#[test]
fn a_held_lock_spools_and_the_legacy_send_is_unchanged() {
    let bare = Fixture::with_ntfy();
    assert_ok(&bare.run("sensor-ssh.service", &[]));

    let fx = Fixture::with_ntfy().with_lib();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    let lock = hold_lock(&fx.root.join("var/lib/propolis/witness/state.lock"));
    let output = fx.run("sensor-ssh.service", &[]);
    drop(lock);
    assert_ok(&output);
    assert_eq!(todays_part(&fx.log()), todays_part(&bare.log()));
    assert!(
        fx.records().is_empty(),
        "nothing is written without the lock"
    );
    let spool = std::fs::read_to_string(
        fx.root
            .join("var/lib/propolis/witness/hook/sensor-ssh.service"),
    )
    .unwrap();
    let lines: Vec<&str> = spool.lines().collect();
    assert_eq!(lines[0], "#hook v1 g=1", "{spool}");
    let h: Vec<&str> = lines[1].split('\t').collect();
    assert_eq!(h.len(), 10, "{spool}");
    assert_eq!(h[0], "H");
    assert_eq!(h[3], "1", "count");
    assert_eq!(h[4], "exit-code");
    assert_eq!(h[7], "proc.exit:1");
    assert_eq!(h[8], "2", "nrestarts");
    assert_eq!(h[9], "delivered", "what today's hook did");
    assert_eq!(witness_lines(&fx.log()), Vec::<String>::new());
}

#[test]
fn the_record_step_is_bounded_inside_the_unit_timeout() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/propolis-alert@.service"
    ))
    .unwrap();
    let timeout: u64 = unit
        .lines()
        .find_map(|l| l.trim().strip_prefix("TimeoutStartSec="))
        .map(|v| v.trim().trim_end_matches('s').parse().unwrap())
        .unwrap();
    let hook = shipped_hook();
    let budget_line = hook
        .lines()
        .find(|l| l.contains("- SECONDS"))
        .expect("the record step's budget is counted down from the hook's SECONDS");
    let ceiling: u64 = budget_line
        .split("$((")
        .nth(1)
        .and_then(|r| r.split('-').next())
        .map(|n| n.trim().parse().unwrap())
        .unwrap_or_else(|| panic!("{budget_line}"));
    let kill_after: u64 = hook
        .split("--kill-after=")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("the record step runs under timeout --kill-after=");
    assert!(
        ceiling + kill_after < timeout,
        "the record step can end at {ceiling} + {kill_after} s, not under TimeoutStartSec={timeout}"
    );

    // Past 70 s the record goes straight to the spool, without asking systemd or the journal.
    let fx = Fixture::with_ntfy().with_lib();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    assert_ok(&fx.run(
        "sensor-ssh.service",
        &[
            ("SECONDS", "72"),
            ("MONITOR_SERVICE_RESULT", "exit-code"),
            ("MONITOR_EXIT_CODE", "exited"),
            ("MONITOR_EXIT_STATUS", "4"),
        ],
    ));
    assert_eq!(fx.log().matches("curl ").count(), 1);
    assert!(fx.records().is_empty());
    assert_eq!(fx.queries(), "", "no read past 70 s");
    let spool = std::fs::read_to_string(
        fx.root
            .join("var/lib/propolis/witness/hook/sensor-ssh.service"),
    )
    .unwrap();
    assert!(
        spool.contains("\texit-code\texited\t4\tproc.exit:4\t-\tdelivered\n"),
        "{spool}"
    );
}

#[test]
fn an_unwritable_state_directory_falls_back_to_run_and_still_sends() {
    let fx = Fixture::with_ntfy().with_lib();
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::remove_dir_all(&witness).unwrap();
    // A file where the directory should be refuses every write, whoever runs the test.
    std::fs::write(&witness, "not a directory").unwrap();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
    let records = fx.records_at("run/propolis-witness/fallback/incidents");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0][2], "unit:sensor-ssh.service");
    assert_eq!(records[0][33], "delivered");
    assert_eq!(witness_lines(&fx.log()), Vec::<String>::new());
    // Where the record went is stated for the walk, in the copy that was written.
    let meta = std::fs::read_to_string(fx.root.join("run/propolis-witness/fallback/meta")).unwrap();
    assert!(meta.lines().any(|l| l == "M\twhere\trun"), "{meta}");
}

/// A record made in /run's fallback moves back to the persistent directory with the next firing
/// once it accepts writes again. Its opaque id stays `-` both times: the hook sees one unit, and
/// an id widened against every configured unit is the witness's to give.
#[test]
fn a_record_made_in_the_fallback_moves_back_when_the_disk_accepts_writes_again() {
    let fx = Fixture::with_ntfy().with_lib();
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::remove_dir_all(&witness).unwrap();
    std::fs::write(&witness, "not a directory").unwrap();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    let records = fx.records_at("run/propolis-witness/fallback/incidents");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0][5], "-", "inst");

    std::fs::remove_file(&witness).unwrap();
    std::fs::create_dir_all(&witness).unwrap();
    std::fs::write(witness.join("state.lock"), b"").unwrap();
    assert_ok(&fx.run("sensor-ssh.service", &[]));
    let f = fx.record("sensor-ssh.service");
    assert_eq!(f[1], records[0][1], "the same incident");
    assert_eq!(f[31], "2", "occ");
    assert_eq!(f[5], "-", "inst");
    assert!(
        !fx.root
            .join("run/propolis-witness/fallback/incidents")
            .exists()
    );
    let meta = std::fs::read_to_string(witness.join("meta")).unwrap();
    assert!(meta.lines().any(|l| l == "M\twhere\tpersistent"), "{meta}");
    assert_eq!(witness_lines(&fx.log()), Vec::<String>::new());
}

/// The record step always gets at least a second. A hook that reaches its handler with 85 s or
/// more gone would otherwise hand `timeout` a 0 (which means no limit, so a hung library runs
/// until systemd kills the unit) or a negative value (which `timeout` refuses).
#[test]
fn a_hung_library_is_still_cut_off_when_the_hook_reaches_its_handler_past_85_seconds() {
    let hang = format!("{}\npa_init() {{\n    sleep 300\n}}\n", shipped_lib());
    let bare = Fixture::with_ntfy();
    assert_ok(&bare.run("sensor-ssh.service", &[]));
    for seconds in ["85", "89"] {
        let fx = Fixture::with_ntfy();
        fx.install_lib(&hang);
        let started = std::time::Instant::now();
        let output = fx.run("sensor-ssh.service", &[("SECONDS", seconds)]);
        let took = started.elapsed();
        assert_ok(&output);
        assert!(
            took < std::time::Duration::from_secs(10),
            "SECONDS={seconds}: the hook took {took:?}"
        );
        let log = fx.log();
        assert_eq!(log.matches("curl ").count(), 1, "SECONDS={seconds}: {log}");
        assert_eq!(
            todays_part(&log),
            todays_part(&bare.log()),
            "SECONDS={seconds}"
        );
        assert_eq!(witness_lines(&log).len(), 1, "SECONDS={seconds}: {log}");
    }
}

/// A post that systemd cuts short (the unit stopped, the host shutting down) still ends the hook
/// by the signal, as today. The post had started, so the record says the alert is undelivered,
/// never that no hook handled the failure.
#[test]
fn a_post_cut_short_by_a_signal_is_recorded_as_undelivered() {
    use std::os::unix::process::ExitStatusExt;
    let killing_curl =
        "#!/usr/bin/env bash\nprintf 'curl %s\\n' \"$*\" >> \"$STUB_LOG\"\nkill -TERM 0\nsleep 5\n";
    let bare = Fixture::with_ntfy();
    write_exec(&bare.bin.join("curl"), killing_curl);
    let today = bare.run_in_own_group("sensor-ssh.service", &[]);
    assert_eq!(
        today.status.signal(),
        Some(15),
        "today's hook ends by the signal"
    );

    let fx = Fixture::with_ntfy().with_lib();
    write_exec(&fx.bin.join("curl"), killing_curl);
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    let output = fx.run_in_own_group("sensor-ssh.service", &[]);
    assert_eq!(output.status.signal(), today.status.signal());
    assert_eq!(todays_part(&fx.log()), todays_part(&bare.log()));
    assert!(!fx.delivered_stamp("sensor-ssh.service").exists());
    assert_eq!(fx.record("sensor-ssh.service")[33], "undelivered");
}

/// Every file under `dir`, at any depth, whose name holds `.tmp.`: what pa_write leaves behind
/// when it is stopped between writing its temporary file and renaming it.
fn temporary_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path);
            } else if entry.file_name().to_string_lossy().contains(".tmp.") {
                found.push(path);
            }
        }
    }
    found
}

/// The record child is stopped by its time limit while a state file is being flushed; its own
/// EXIT handler removes the temporary file, and what the hook sent is today's.
#[test]
fn the_record_child_removes_its_temporary_files_when_its_time_runs_out() {
    let bare = Fixture::with_ntfy();
    assert_ok(&bare.run("sensor-ssh.service", &[]));
    let fx = Fixture::with_ntfy().with_lib();
    write_exec(&fx.bin.join("sync"), "#!/usr/bin/env bash\nsleep 10\n");
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    let started = std::time::Instant::now();
    let output = fx.run("sensor-ssh.service", &[("SECONDS", "83")]);
    let took = started.elapsed();
    assert_ok(&output);
    assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    let log = fx.log();
    assert_eq!(todays_part(&log), todays_part(&bare.log()));
    assert_eq!(witness_lines(&log).len(), 1, "{log}");
    let witness = fx.root.join("var/lib/propolis/witness");
    assert!(
        witness.join("hook").is_dir(),
        "the record step got as far as the spool write"
    );
    let left = temporary_files_under(&witness);
    assert!(left.is_empty(), "left behind: {left:?}");
}

/// A routine skip that follows a failed rotation is a repeat of the same open incident: it only
/// counts, and the failure stays recorded as ACT with its own cause. The tier never falls while
/// the incident is open.
#[test]
fn a_skip_only_rotation_after_a_failed_one_keeps_the_failure_recorded_as_act() {
    for (first, cause) in [
        (format!("{GUARD_SKIP}{GUARD_REFUSAL}"), "guard.no_space"),
        (format!("{GUARD_SKIP}{STAT_ERROR}"), "proc.exit:1"),
    ] {
        let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
        let f = fire_rotation(&fx, &first, TRUSTED_ROTATION);
        assert_eq!(
            (f[3].as_str(), f[6].as_str(), f[11].as_str()),
            ("unit-failed", "ACT", cause)
        );
        assert_eq!((f[7].as_str(), f[29].as_str()), ("open", "1"));

        let f = fire_rotation(&fx, GUARD_SKIP, TRUSTED_ROTATION);
        assert_eq!(
            (f[3].as_str(), f[4].as_str(), f[6].as_str(), f[11].as_str()),
            ("unit-failed", "source", "ACT", cause),
            "{first}"
        );
        assert_eq!(f[7], "open");
        assert_eq!(f[31], "2", "occ");
        assert_eq!(f[29], "1", "would_push");
    }
}

/// A journalctl whose query by trusted fields prints a skip, then stalls past the 3 s limit,
/// then would have printed a refusal.
const STALLING_RUN_JOURNAL_STUB: &str = r#"#!/usr/bin/env bash
case " $* " in
    *" -u "*) printf 'one line\n' ;;
    *)
        printf 'journalctl %s\n' "$*" >> "${STUB_JLOG:-/dev/null}"
        printf '%s\n' 'propolis-logrotate-guard: skipping rotation of /var/log/propolis/ssh/ssh.log: the reader is behind'
        sleep 5
        printf '%s\n' 'propolis-logrotate-guard: refusing to rotate /var/log/propolis/http/http.log: too little free space'
        ;;
esac
"#;

/// The routine skip is a NOTICE only when every line read is a skip or its companion, there is
/// no more companion than skip, and the whole journal was read. A guard that broke on another
/// log, or a read cut short, is a failure like any other.
#[test]
fn a_guard_skip_is_a_notice_only_when_every_line_read_is_a_skip_or_its_companion() {
    let (_, f) = rotation_run(GUARD_SKIP, TRUSTED_ROTATION);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str()),
        ("rotation-skipped", "NOTICE", "guard.behind")
    );

    for lines in [
        format!(
            "{GUARD_SKIP}/usr/local/sbin/propolis-logrotate-guard: line 64: $1: unbound variable\n{GUARD_COMPANION}"
        ),
        format!("{GUARD_SKIP}{GUARD_COMPANION}"),
        format!(
            "{GUARD_SKIP}stat: cannot statx '/var/log/propolis/http/http.log': Permission denied\n{GUARD_COMPANION}"
        ),
        format!(
            "{GUARD_SKIP}propolis-logrotate-guard: no usable intake cursor for /var/log/propolis/http/http.log; rotating without an unread-input check\n"
        ),
        format!("{GUARD_SKIP}reading config file /etc/logrotate.d/propolis-sensors\n"),
        GUARD_COMPANION.to_string(),
    ] {
        let (_, f) = rotation_run(&lines, TRUSTED_ROTATION);
        assert_eq!(
            (f[3].as_str(), f[6].as_str(), f[11].as_str()),
            ("unit-failed", "ACT", "proc.exit:1"),
            "{lines}"
        );
    }

    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    write_exec(&fx.bin.join("journalctl"), STALLING_RUN_JOURNAL_STUB);
    let f = fire_rotation(&fx, "", TRUSTED_ROTATION);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "ACT", "proc.exit:1"),
        "a read cut short by its time limit is not a pass"
    );
}

/// Without an invocation id the failed run cannot be told from another, so neither the panic
/// count nor the guard's lines are read, and the failure stays an ordinary ACT one.
#[test]
fn without_an_invocation_id_the_rotation_journal_is_not_read_and_the_failure_stays_act() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    let journal = fx._dir.path().join("run-journal");
    std::fs::write(
        &journal,
        format!("{GUARD_SKIP}thread 'main' panicked at src/main.rs:1:1\n"),
    )
    .unwrap();
    fx.show(
        "propolis-logrotate.service",
        "Result=exit-code\nExecMainCode=1\nExecMainStatus=1\nRestart=no\nType=oneshot\nNRestarts=0\n",
    );
    assert_ok(&fx.run(
        "propolis-logrotate.service",
        &[
            ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
            ("STUB_RUN_MATCH", "_SYSTEMD_UNIT=propolis-logrotate.service"),
        ],
    ));
    let f = fx.record("propolis-logrotate.service");
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "ACT", "proc.exit:1")
    );
    assert!(
        !fx.queries().contains("_SYSTEMD_INVOCATION_ID="),
        "{}",
        fx.queries()
    );
}

/// The result and the status of a run come from one source: a MONITOR_SERVICE_RESULT without
/// its MONITOR_EXIT_STATUS is not completed from systemctl show, which may describe another run.
#[test]
fn a_monitor_result_without_its_status_is_unknown_and_never_takes_the_status_from_systemctl() {
    let fx = Fixture::new("PROPOLIS_FEED_ENABLED=true\n").with_lib();
    fx.show(
        "one-source.service",
        &show_answer("exit-code", "9", "no", "0"),
    );
    assert_ok(&fx.run(
        "one-source.service",
        &[
            ("MONITOR_SERVICE_RESULT", "exit-code"),
            ("MONITOR_EXIT_CODE", "exited"),
        ],
    ));
    assert_eq!(fx.record("one-source.service")[11], "unknown");
}

/// A unit name the hook accepts (up to 200 characters) can make a key longer than a record
/// holds: the alert is today's, nothing is recorded, and one line says why.
#[test]
fn a_unit_name_too_long_for_a_record_key_changes_nothing_sent_and_is_logged_once() {
    let unit = format!("{}.service", "x".repeat(142));
    assert_eq!(unit.len(), 150);
    let bare = Fixture::with_ntfy();
    let today = bare.run(&unit, &[]);
    assert_ok(&today);
    let fx = Fixture::with_ntfy().with_lib();
    let output = fx.run(&unit, &[]);
    assert_eq!(output.status.code(), today.status.code());
    assert_eq!(todays_part(&fx.log()), todays_part(&bare.log()));
    assert!(fx.records().is_empty(), "{:?}", fx.records());
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].ends_with(&format!(
            "incident not recorded for {unit}: the unit name is too long for a record"
        )),
        "{}",
        lines[0]
    );
}

#[test]
fn the_hook_states_the_library_it_needs_and_its_contract_on_one_line_each() {
    let hook = shipped_hook();
    let needs: Vec<&str> = hook
        .lines()
        .filter(|l| l.contains("needs-alert-lib"))
        .collect();
    assert_eq!(needs, [format!("# needs-alert-lib: {}", hook_needs())]);
    let contract: Vec<&str> = hook
        .lines()
        .filter(|l| l.contains("hook-contract"))
        .collect();
    assert_eq!(contract, ["# hook-contract: 1"]);
    assert!(
        hook.lines()
            .any(|l| l.trim() == "# shellcheck source=deploy/alert-lib.sh"),
        "the deploy tests count the hook as a script that sources the library"
    );
}
