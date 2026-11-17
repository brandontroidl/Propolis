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

/// Records argv, the header file it was handed and the body it read on stdin. A config file
/// (`-K FILE`, the test page's form) goes to `$STUB_LOG.conf` with its mode, never to `$STUB_LOG`,
/// and the call answers `STUB_POST_CODE` (default 200) as the write-out the file asks for, after
/// `STUB_CURL_SLEEP` seconds; it then leaves `$STUB_LOG.posted`, and with `STUB_HOLD_LOCK` set it
/// first starts a process that takes that lock file and holds it for a minute, its pid in
/// `$STUB_LOG.holder`. `STUB_DURING`, when set, is run by bash while the post is in flight, as
/// another process acting meanwhile would.
const CURL_STUB: &str = r#"#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$STUB_LOG"
prev=""
for a in "$@"; do
    case "$a" in @/*) printf 'header-file:\n' >> "$STUB_LOG"; cat "${a#@}" >> "$STUB_LOG" ;; esac
    if [ "$prev" = -K ]; then
        { printf -- '--- %s\n' "$(stat -c %a -- "$a")"; cat -- "$a"; } >> "$STUB_LOG.conf"
        printf 'body:\n' >> "$STUB_LOG"
        cat >> "$STUB_LOG"
        printf '\n' >> "$STUB_LOG"
        [ -z "${STUB_CURL_SLEEP:-}" ] || sleep "$STUB_CURL_SLEEP"
        [ -z "${STUB_DURING:-}" ] || bash -c "$STUB_DURING" < /dev/null > /dev/null 2>&1
        if [ -n "${STUB_HOLD_LOCK:-}" ]; then
            ( exec 9< "$STUB_HOLD_LOCK"; flock -x 9; echo "$BASHPID" > "$STUB_LOG.holder"; exec sleep 60 ) > /dev/null 2>&1 &
            until [ -s "$STUB_LOG.holder" ]; do sleep 0.1; done
        fi
        : > "$STUB_LOG.posted"
        printf '%s' "${STUB_POST_CODE:-200}"
        exit 0
    fi
    prev="$a"
done
printf 'body:\n' >> "$STUB_LOG"
cat >> "$STUB_LOG"
printf '\n' >> "$STUB_LOG"
[ -z "${STUB_CURL_FAIL:-}" ]
"#;

/// The hook's own `journalctl -u UNIT ...` gets the same two lines for every unit. A query by
/// trusted fields (the record step's) is recorded in `$STUB_JLOG`, fails when `$STUB_JOURNAL_FAIL`
/// is set, and is answered from the file `$STUB_RUN_JOURNAL` only when it carries every word of
/// `$STUB_RUN_MATCH`.
const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
case " $* " in
    *" -u "*) printf '2026-10-11T12:00:00+0000 host sensor[1]: panicked at boom\r\nTitle: injected\n' ;;
    *)
        printf 'journalctl %s\n' "$*" >> "${STUB_JLOG:-/dev/null}"
        [ -z "${STUB_JOURNAL_FAIL:-}" ] || exit 1
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

/// Records its arguments and the line it read, and fails when `STUB_CAT_FAIL` is set, as
/// systemd-cat does when it cannot reach the journal.
const SYSTEMD_CAT_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemd-cat %s %s\n' "$*" "$(cat)" >> "$STUB_LOG"
[ -z "${STUB_CAT_FAIL:-}" ]
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
            ("systemd-cat", SYSTEMD_CAT_STUB),
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
        let mut command = self.command(unit, env);
        if own_group {
            command.process_group(0);
        }
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        child.wait_with_output().unwrap()
    }

    /// The hook for `unit` with these extra variables, ready to spawn.
    fn command(&self, unit: &str, env: &[(&str, &str)]) -> Command {
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
        command
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

/// Today's failure hook reads propolis.env alone, always: an alert.env naming another target,
/// another token and the v2 profile changes nothing it sends or logs, with the library installed
/// or not; and neither the hook nor the daemon's source names alert.env.
#[test]
fn todays_failure_hook_and_the_daemon_never_read_alert_env() {
    let alert_env = "PROPOLIS_OPS_NTFY_URL=https://other.example\nPROPOLIS_OPS_NTFY_TOPIC=other-topic\n\
                     PROPOLIS_OPS_NTFY_TOKEN=tk_other\nPROPOLIS_ALERT_PROFILE=v2\n";
    for lib in [false, true] {
        let plain = Fixture::with_ntfy();
        let fx = Fixture::with_ntfy();
        let (plain, fx) = if lib {
            (plain.with_lib(), fx.with_lib())
        } else {
            (plain, fx)
        };
        std::fs::write(fx.root.join("etc/propolis/alert.env"), alert_env).unwrap();
        assert_ok(&plain.run("sensor-ssh.service", &[]));
        assert_ok(&fx.run("sensor-ssh.service", &[]));
        assert_eq!(
            todays_part(&fx.log()),
            todays_part(&plain.log()),
            "lib {lib}"
        );
        let log = fx.log();
        assert!(log.contains("https://ntfy.example/propolis-ops"), "{log}");
        for other in ["other.example", "other-topic", "tk_other"] {
            assert!(!log.contains(other), "{other} in: {log}");
        }
    }
    assert!(!shipped_hook().contains("alert.env"));
    let mut dirs = vec![PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../propolis/src"
    ))];
    let mut read = 0;
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                read += 1;
                let text = std::fs::read_to_string(&p).unwrap();
                assert!(
                    !text.contains("alert.env"),
                    "{} names alert.env",
                    p.display()
                );
            }
        }
    }
    assert!(read > 10, "the daemon's sources were read: {read}");
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
    assert_eq!(contract, ["# hook-contract: 2"]);
    assert!(
        hook.lines()
            .any(|l| l.trim() == "# shellcheck source=deploy/alert-lib.sh"),
        "the deploy tests count the hook as a script that sources the library"
    );
}

// ---- the test page --------------------------------------------------------------------------

const TP_SALT: &str = "0123456789abcdef0123456789abcdef";
/// The library's time seam for these cases: wall 1_000_000, boot abcdef01, 5000 s of uptime.
const TP_NOW: [(&str, &str); 3] = [
    ("PA_TEST_WALL", "1000000"),
    ("PA_TEST_BOOT", "abcdef01"),
    ("PA_TEST_UP", "5000"),
];

impl Fixture {
    /// A stored test page with this code and result, recorded `ago` seconds before TP_NOW, and its
    /// pending ledger line.
    fn test_page(&self, code: &str, ago: u64, result: &str) -> String {
        let stamp = format!("{}/abcdef01/{}", 1_000_000 - ago, 5000 - ago);
        let dir = self.root.join("var/lib/propolis/witness");
        std::fs::write(dir.join("id-salt"), format!("{TP_SALT}\n")).unwrap();
        std::fs::write(
            dir.join("testpage"),
            format!("#testpage v1 g=1\nT\t{code}\t{stamp}\t0123456789abcdef\t-\t{result}\t-\t-\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("send-ledger"),
            format!("#send-ledger v1 g=1\nL\t{stamp}\ttest\t-\topen\tfull\tpending\tstatus\n"),
        )
        .unwrap();
        stamp
    }

    fn state(&self, name: &str) -> String {
        std::fs::read_to_string(self.root.join("var/lib/propolis/witness").join(name))
            .unwrap_or_default()
    }

    fn confs(&self) -> String {
        std::fs::read_to_string(format!("{}.conf", self.log.display())).unwrap_or_default()
    }
}

/// The hook sends a test page only for the code the stored record holds, while that record is
/// pending and under 10 minutes old: a wrong code, a code that came too late and a code already
/// used each send nothing, log one line under propolis-witness and exit 0. A late code marks its
/// own pending record nomatch; a wrong or used one changes nothing. The page that does go out
/// carries the alias and the code, and curl gets the topic and the token only in its config file.
#[test]
fn the_test_page_unit_sends_only_with_the_recorded_code() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    let before = fx.state("testpage");
    let out = fx.run("propolis-test-page-000000", &TP_NOW);
    assert_ok(&out);
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert_eq!(fx.state("testpage"), before, "a wrong code changes nothing");
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
    assert!(
        fx.log().contains("test page 000000 not sent"),
        "{}",
        fx.log()
    );

    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 700, "pending");
    assert_ok(&fx.run("propolis-test-page-abc123", &TP_NOW));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert!(
        fx.state("testpage").contains("\tnomatch\t"),
        "{}",
        fx.state("testpage")
    );
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());

    let fx = Fixture::with_ntfy().with_lib();
    let stamp = fx.test_page("abc123", 100, "pending");
    let out = fx.run("propolis-test-page-abc123", &TP_NOW);
    assert_ok(&out);
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
    let log = fx.log();
    let calls: Vec<&str> = log.lines().filter(|l| l.starts_with("curl ")).collect();
    assert_eq!(calls.len(), 1, "{log}");
    let argv: Vec<&str> = calls[0].split(' ').collect();
    assert_eq!(&argv[..3], ["curl", "-q", "-K"], "{}", calls[0]);
    assert_eq!(argv.len(), 4, "nothing but the config file: {}", calls[0]);
    assert!(log.contains("body:\nType back on host-"), "{log}");
    assert!(log.contains(": status --ack-test abc123"), "{log}");
    assert!(witness_lines(&log).is_empty(), "{log}");
    for secret in [TOKEN, "propolis-ops", "honeybox"] {
        assert!(!log.contains(secret), "{secret} in {log}");
        assert!(!fx.state("testpage").contains(secret));
        assert!(!fx.state("send-ledger").contains(secret));
    }
    let conf = fx.confs();
    assert!(conf.starts_with("--- 600\n"), "{conf}");
    assert!(
        conf.contains("url = \"https://ntfy.example/propolis-ops\""),
        "{conf}"
    );
    assert!(
        conf.contains(&format!("header = \"Authorization: Bearer {TOKEN}\"")),
        "{conf}"
    );
    assert!(conf.contains(": test page abc123\""), "{conf}");
    assert!(
        !conf.contains("honeybox") && !conf.contains("propolis:"),
        "{conf}"
    );
    assert!(
        fx.state("testpage")
            .contains(&format!("\tabc123\t{stamp}\t"))
            && fx.state("testpage").contains("\tok\t-\t-"),
        "{}",
        fx.state("testpage")
    );
    assert!(
        fx.state("send-ledger")
            .contains(&format!("L\t{stamp}\ttest\t-\topen\tfull\tok\thook")),
        "{}",
        fx.state("send-ledger")
    );
    // The same code again: already used, nothing sent, nothing changed.
    let sent = fx.state("testpage");
    assert_ok(&fx.run("propolis-test-page-abc123", &TP_NOW));
    assert_eq!(fx.log().matches("curl ").count(), 1);
    assert_eq!(fx.state("testpage"), sent);
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());

    // A refusal is recorded as such and logged, still with exit 0.
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    assert_ok(&fx.run(
        "propolis-test-page-abc123",
        &[TP_NOW[0], TP_NOW[1], TP_NOW[2], ("STUB_POST_CODE", "403")],
    ));
    assert!(
        fx.state("testpage").contains("\tperm:403\t"),
        "{}",
        fx.state("testpage")
    );
    assert!(
        fx.log().contains("not delivered (perm:403)"),
        "{}",
        fx.log()
    );
}

/// systemd passes a failed unit's full name, which ends in `.service`, so a real unit named like
/// a test page still takes today's path: today's title, today's post, no config file.
#[test]
fn a_unit_named_like_the_test_page_with_its_type_takes_the_legacy_path() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    assert_ok(&fx.run("propolis-test-page-abc123.service", &TP_NOW));
    let log = fx.log();
    assert!(
        log.contains("Title: propolis: propolis-test-page-abc123.service failed on honeybox"),
        "{log}"
    );
    assert!(!log.contains(" -K "), "{log}");
    assert!(fx.confs().is_empty());
    assert!(fx.state("testpage").contains("\tpending\t"));
}

/// A library that is missing, older than the test page needs, or broken (an unbound variable at
/// its top level, a division by zero in the test-page function) cannot change the hook's exit
/// status or make it send: one line under propolis-witness, exit 0, no post. The line does not
/// claim nothing was sent, since a child stopped by its time limit may have sent already.
#[test]
fn a_missing_old_or_broken_library_on_the_test_page_path_logs_one_line_and_exits_zero() {
    let shipped = shipped_lib();
    let cases = [
        ("missing", None),
        (
            "older",
            Some(shipped.replace(
                &format!("PA_LIB_VERSION={}", shipped_lib_version()),
                "PA_LIB_VERSION=8",
            )),
        ),
        (
            "unbound",
            Some(format!("set -u\n: \"$PA_NO_SUCH_VARIABLE\"\n{shipped}")),
        ),
        (
            "division",
            Some(format!(
                "{shipped}\npa_hook_test_page() {{\n    local x=$((1/0))\n}}\n"
            )),
        ),
    ];
    for (name, body) in cases {
        let fx = Fixture::with_ntfy();
        if let Some(body) = body {
            fx.install_lib(&body);
        }
        fx.test_page("abc123", 100, "pending");
        let out = fx.run("propolis-test-page-abc123", &TP_NOW);
        assert_ok(&out);
        assert!(
            out.stdout.is_empty() && out.stderr.is_empty(),
            "{name}: {out:?}"
        );
        let log = fx.log();
        assert!(!log.contains("curl "), "{name}: {log}");
        let lines = witness_lines(&log);
        assert_eq!(lines.len(), 1, "{name}: {log}");
        assert!(
            lines[0].contains("test page outcome unknown for propolis-test-page-abc123 (library missing, too old, failed or timed out)"),
            "{name}: {}",
            lines[0]
        );
        assert!(fx.state("testpage").contains("\tpending\t"), "{name}");
    }
    assert!(
        shipped_hook().contains("TP_NEEDS=9") && shipped_lib_version() >= 9,
        "the test-page path asks for the library version that brought it, which the shipped library meets"
    );
}

/// The shipped library's version, from its `PA_LIB_VERSION=<n>` line.
fn shipped_lib_version() -> u32 {
    shipped_lib()
        .lines()
        .find_map(|l| l.strip_prefix("PA_LIB_VERSION="))
        .and_then(|v| v.parse().ok())
        .expect("deploy/alert-lib.sh carries `PA_LIB_VERSION=<n>`")
}

/// The shell code sends the test page, the witness's daily message and, under profile v2 alone,
/// the failure hook's and the witness's new-format messages: pa_send is called from exactly four
/// places in deploy/, the hook's test-page function, the witness's daily_send, which only its two
/// passes call, the v2 path's one post (_pa_hv2_post), which only the v2 path's own functions
/// call, and the witness's send_one, which only its send_post calls, which only its two passes
/// call and which posts nothing unless profile v2 is in force
/// (only_the_hooks_v2_path_and_the_witness_send_step_call_the_incident_code). The test-page
/// function is run only from the failure hook's test-page path, and the v2 path only from the
/// hook's v2 child, which follows a decision no run without a test root passes
/// (a_run_without_a_test_root_never_reaches_v2_whatever_the_env_files_and_the_seam_say).
#[test]
fn pa_send_is_called_only_by_the_test_page_path_the_daily_message_and_the_two_v2_senders() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy");
    let mut send_calls = Vec::new();
    let mut runs = Vec::new();
    let mut daily = Vec::new();
    let mut posts = Vec::new();
    let mut v2 = Vec::new();
    let mut one = Vec::new();
    let mut step = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "sh") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut function = String::new();
        let mut in_list = false;
        for line in text.lines() {
            let t = line.trim();
            if let Some(f) = t.strip_suffix("() {")
                && !line.starts_with(' ')
            {
                function = f.to_string();
            }
            if t.starts_with('#') {
                continue;
            }
            // The witness's list of the library functions it needs, a line of names alone inside
            // its WITNESS_LIB_FUNCS="..." assignment, calls nothing.
            if name == "witness.sh" && (in_list || t.starts_with("WITNESS_LIB_FUNCS=\"")) {
                in_list = !t.ends_with('"');
                if t.trim_start_matches("WITNESS_LIB_FUNCS=\"")
                    .trim_end_matches('"')
                    .split_whitespace()
                    .all(|w| w.starts_with("pa_"))
                {
                    continue;
                }
            }
            if t.contains("pa_send") && !t.starts_with("pa_send()") {
                send_calls.push(format!("{name}:{function}"));
            }
            if t.contains("send_one ") && !t.starts_with("send_one()") {
                one.push(format!("{name}:{function}"));
            }
            if t.contains("send_post") && !t.starts_with("send_post()") {
                step.push(format!("{name}:{function}"));
            }
            if t.contains("pa_hook_test_page") && !t.starts_with("pa_hook_test_page()") {
                runs.push(name.clone());
            }
            if t.contains("daily_send") && !t.starts_with("daily_send()") {
                daily.push(format!("{name}:{function}"));
            }
            if t.contains("_pa_hv2_post") && !t.starts_with("_pa_hv2_post()") {
                posts.push(format!("{name}:{function}"));
            }
            if t.contains("pa_hook_v2") && !t.starts_with("pa_hook_v2()") {
                v2.push(name.clone());
            }
        }
    }
    send_calls.sort();
    daily.sort();
    assert_eq!(
        send_calls,
        [
            "alert-lib.sh:_pa_hv2_post",
            "alert-lib.sh:pa_hook_test_page",
            "witness.sh:daily_send",
            "witness.sh:send_one"
        ],
        "pa_send call sites"
    );
    assert!(!one.is_empty());
    assert!(
        one.iter().all(|c| c == "witness.sh:send_post"),
        "send_one call sites: {one:?}"
    );
    step.sort();
    assert_eq!(
        step,
        ["witness.sh:hourly_pass", "witness.sh:light_pass"],
        "send_post call sites"
    );
    assert!(!posts.is_empty());
    for p in &posts {
        assert!(
            p.starts_with("alert-lib.sh:_pa_hv2_") || p == "alert-lib.sh:pa_hook_v2",
            "_pa_hv2_post call sites: {posts:?}"
        );
    }
    assert_eq!(v2, ["alert.sh"], "pa_hook_v2 call sites");
    assert_eq!(runs, ["alert.sh"], "pa_hook_test_page call sites");
    assert_eq!(
        daily,
        ["witness.sh:hourly_pass", "witness.sh:light_pass"],
        "daily_send call sites"
    );
}

impl Fixture {
    /// The process the curl stub started to hold the state lock, stopped.
    fn release_holder(&self) {
        let pid =
            std::fs::read_to_string(format!("{}.holder", self.log.display())).unwrap_or_default();
        if let Ok(pid) = pid.trim().parse::<i32>() {
            // SAFETY: kill has no memory preconditions; the pid is the stub's own child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }

    /// The posts the test page path made.
    fn tp_posts(&self) -> usize {
        self.log()
            .lines()
            .filter(|l| l.starts_with("curl -q -K "))
            .count()
    }

    fn state_lock(&self) -> PathBuf {
        self.root.join("var/lib/propolis/witness/state.lock")
    }
}

/// The page is claimed (result `sending`) under the lock before it goes out. When the result
/// cannot be written afterwards, because another writer holds the state lock past the hook's
/// second wait, the claim stays: one line says the page was delivered and its result not
/// recorded, and a second start for the same code sends nothing.
#[test]
fn a_page_whose_result_cannot_be_recorded_stays_claimed_and_is_never_sent_twice() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    let lock = fx.state_lock();
    let env = [
        TP_NOW[0],
        TP_NOW[1],
        TP_NOW[2],
        ("STUB_HOLD_LOCK", lock.to_str().unwrap()),
    ];
    let out = fx.run("propolis-test-page-abc123", &env);
    fx.release_holder();
    assert_ok(&out);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert!(
        fx.state("testpage").contains("\tabc123\t") && fx.state("testpage").contains("\tsending\t"),
        "{}",
        fx.state("testpage")
    );
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("test page abc123 delivered; the result could not be recorded"),
        "{}",
        lines[0]
    );
    assert_ok(&fx.run("propolis-test-page-abc123", &TP_NOW));
    assert_eq!(
        fx.tp_posts(),
        1,
        "the claimed page went out again: {}",
        fx.log()
    );
    assert!(fx.state("testpage").contains("\tsending\t"));
}

/// A page goes out only once its ledger line reads as claimed, so a page that went out is always
/// counted toward the three a day. When the send ledger cannot be written at claim time (here its
/// every write fails, as on a full disk and a full /run), nothing is posted, the record says so in
/// a word that is not `sending`, and one line says why.
#[test]
fn a_page_whose_ledger_claim_cannot_be_written_is_not_sent() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    write_exec(
        &fx.bin.join("sync"),
        "#!/usr/bin/env bash\nfor a in \"$@\"; do\n    case \"$a\" in */send-ledger.tmp.*) exit 1 ;; esac\ndone\nexit 0\n",
    );
    let out = fx.run("propolis-test-page-abc123", &TP_NOW);
    assert_ok(&out);
    assert_eq!(fx.tp_posts(), 0, "{}", fx.log());
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    let record = fx.state("testpage");
    assert!(
        record.contains("\tabc123\t") && record.contains("\tnoclaim\t"),
        "{record}"
    );
    assert!(!record.contains("\tsending\t"), "{record}");
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0]
            .contains("test page abc123 not sent: the claim on the ledger could not be written"),
        "{}",
        lines[0]
    );
}

/// The status command reports a record that reads `sending` as sent and takes its code back, and
/// a ledger line that reads `sending` counts toward the three a day. So whichever write fails
/// around the claim, a page that was not posted leaves `sending` in neither. Two cases the test
/// above does not reach: the ledger refuses its claim and the record then refuses the mark that
/// says so; the ledger takes its claim and the record refuses its own.
#[test]
fn a_page_that_was_not_posted_never_reads_as_claimed() {
    for (ledger_fails, refused_word) in [(true, "noclaim"), (false, "sending")] {
        let fx = Fixture::with_ntfy().with_lib();
        let stamp = fx.test_page("abc123", 100, "pending");
        // The stub refuses a write by what it would store: every send-ledger write in the first
        // case, and in both any testpage write that holds the word.
        let ledger_rule = if ledger_fails {
            "*/send-ledger.tmp.*) exit 1 ;;"
        } else {
            "*/send-ledger.tmp.*) ;;"
        };
        write_exec(
            &fx.bin.join("sync"),
            &format!(
                "#!/usr/bin/env bash\nfor a in \"$@\"; do\n    case \"$a\" in\n        {ledger_rule}\n        */testpage.tmp.*) if grep -q -- $'\\t{refused_word}\\t' \"$a\" 2> /dev/null; then exit 1; fi ;;\n    esac\ndone\nexit 0\n"
            ),
        );
        let out = fx.run("propolis-test-page-abc123", &TP_NOW);
        assert_ok(&out);
        assert_eq!(fx.tp_posts(), 0, "{refused_word}: {}", fx.log());
        assert!(!fx.log().contains("curl "), "{refused_word}: {}", fx.log());
        let record = fx.state("testpage");
        assert!(
            record.contains("\tabc123\t") && record.contains("\tpending\t"),
            "{refused_word}: {record}"
        );
        assert!(!record.contains("\tsending\t"), "{refused_word}: {record}");
        let ledger = fx.state("send-ledger");
        assert!(!ledger.contains("\tsending\t"), "{refused_word}: {ledger}");
        if !ledger_fails {
            // The claim the ledger took is given back in a word the budget does not count.
            assert!(
                ledger.contains(&format!("L\t{stamp}\ttest\t-\topen\tfull\tnoclaim\thook")),
                "{ledger}"
            );
        }
        // Nothing went to the fallback copies either, which `state` does not read.
        for name in ["testpage", "send-ledger"] {
            assert!(
                !fx.root
                    .join("run/propolis-witness/fallback")
                    .join(name)
                    .exists(),
                "{refused_word}: {name}"
            );
        }
        let lines = witness_lines(&fx.log());
        assert_eq!(lines.len(), 1, "{refused_word}: {}", fx.log());
        let said = if ledger_fails {
            "test page abc123 not sent: the claim on the ledger could not be written"
        } else {
            "test page abc123 not sent: the claim on it could not be written"
        };
        assert!(lines[0].contains(said), "{}", lines[0]);
    }
}

/// What decides that nothing can go out (no curl on the host, a page that cannot be put together
/// for want of an alias) is looked at before the claim. Such a page is never marked `sending`,
/// the word the status command reports as sent: its record and its ledger line get the word that
/// says why, and a record that refuses even that stays `pending`.
#[test]
fn a_page_that_cannot_go_out_is_never_claimed() {
    // No curl, and the record refuses the word for it.
    let fx = Fixture::with_ntfy().with_lib();
    let stamp = fx.test_page("abc123", 100, "pending");
    let path = fx.remove_curl();
    write_exec(
        &fx.bin.join("sync"),
        "#!/usr/bin/env bash\nfor a in \"$@\"; do\n    case \"$a\" in\n        */testpage.tmp.*) if grep -q -- $'\\tnocurl\\t' \"$a\" 2> /dev/null; then exit 1; fi ;;\n    esac\ndone\nexit 0\n",
    );
    let env = [TP_NOW[0], TP_NOW[1], TP_NOW[2], ("PATH", path.as_str())];
    let out = fx.run("propolis-test-page-abc123", &env);
    assert_ok(&out);
    assert_eq!(fx.tp_posts(), 0, "{}", fx.log());
    let record = fx.state("testpage");
    assert!(
        record.contains("\tabc123\t") && record.contains("\tpending\t"),
        "{record}"
    );
    assert!(!record.contains("\tsending\t"), "{record}");
    let ledger = fx.state("send-ledger");
    assert!(
        ledger.contains(&format!("L\t{stamp}\ttest\t-\topen\tfull\tnocurl\thook")),
        "{ledger}"
    );
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("test page abc123 not delivered (nocurl)"),
        "{}",
        lines[0]
    );

    // No id salt, so no alias and no page: the record and the ledger line both say norender.
    let fx = Fixture::with_ntfy().with_lib();
    let stamp = fx.test_page("abc123", 100, "pending");
    std::fs::remove_file(fx.root.join("var/lib/propolis/witness/id-salt")).unwrap();
    let out = fx.run("propolis-test-page-abc123", &TP_NOW);
    assert_ok(&out);
    assert_eq!(fx.tp_posts(), 0, "{}", fx.log());
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    let record = fx.state("testpage");
    assert!(
        record.contains("\tabc123\t") && record.contains("\tnorender\t"),
        "{record}"
    );
    let ledger = fx.state("send-ledger");
    assert!(
        ledger.contains(&format!("L\t{stamp}\ttest\t-\topen\tfull\tnorender\thook")),
        "{ledger}"
    );
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("test page abc123 not delivered (norender)"),
        "{}",
        lines[0]
    );
}

/// Two starts of the hook for one code at once send one page: the first claims the record before
/// its send, so the second finds it used. The ledger keeps one line, with the result.
#[test]
fn two_hook_runs_for_one_code_send_one_page() {
    let fx = Fixture::with_ntfy().with_lib();
    let stamp = fx.test_page("abc123", 100, "pending");
    let env = [TP_NOW[0], TP_NOW[1], TP_NOW[2], ("STUB_CURL_SLEEP", "3")];
    let mut children = Vec::new();
    for _ in 0..2 {
        let mut command = fx.command("propolis-test-page-abc123", &env);
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        children.push(command.spawn().unwrap());
    }
    for child in children {
        assert_ok(&child.wait_with_output().unwrap());
    }
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let ledger: Vec<String> = fx
        .state("send-ledger")
        .lines()
        .filter(|l| l.starts_with("L\t"))
        .map(str::to_string)
        .collect();
    assert_eq!(
        ledger,
        [format!("L\t{stamp}\ttest\t-\topen\tfull\tok\thook")],
        "{}",
        fx.state("send-ledger")
    );
}

/// The test-page child is bounded inside the unit's 90 s: a library whose test-page function
/// hangs is cut off (here with 80 s of the hook's time already gone), the hook exits 0, logs one
/// line, posts nothing and leaves no config file.
#[test]
fn a_hung_test_page_function_is_cut_off_and_the_hook_exits_zero() {
    let fx = Fixture::with_ntfy();
    fx.install_lib(&format!(
        "{}\npa_hook_test_page() {{\n    sleep 200\n}}\n",
        shipped_lib()
    ));
    fx.test_page("abc123", 100, "pending");
    let started = std::time::Instant::now();
    let out = fx.run(
        "propolis-test-page-abc123",
        &[TP_NOW[0], TP_NOW[1], TP_NOW[2], ("SECONDS", "80")],
    );
    let took = started.elapsed();
    assert_ok(&out);
    assert!(took < std::time::Duration::from_secs(30), "{took:?}");
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("test page outcome unknown for propolis-test-page-abc123"),
        "{}",
        lines[0]
    );
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert!(fx.confs().is_empty());
}

/// A child stopped by its time limit after the page went out (here the flush of the result write
/// stalls) is logged as an outcome unknown, never as a page not sent.
#[test]
fn a_child_stopped_after_the_post_logs_an_outcome_unknown() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    write_exec(
        &fx.bin.join("sync"),
        "#!/usr/bin/env bash\n[ ! -e \"$STUB_LOG.posted\" ] || exec sleep 30\n",
    );
    let out = fx.run(
        "propolis-test-page-abc123",
        &[TP_NOW[0], TP_NOW[1], TP_NOW[2], ("SECONDS", "80")],
    );
    assert_ok(&out);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("test page outcome unknown for propolis-test-page-abc123 (library missing, too old, failed or timed out)"),
        "{}",
        lines[0]
    );
}

/// A pending page whose sent stamp is ahead of now on this boot, or exactly ten minutes old, is
/// not sent: it is marked nomatch.
#[test]
fn a_page_dated_ahead_or_exactly_ten_minutes_old_is_marked_nomatch_and_not_sent() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    let dir = fx.root.join("var/lib/propolis/witness");
    std::fs::write(
        dir.join("testpage"),
        "#testpage v1 g=1\nT\tabc123\t1000600/abcdef01/5600\t0123456789abcdef\t-\tpending\t-\t-\n",
    )
    .unwrap();
    assert_ok(&fx.run("propolis-test-page-abc123", &TP_NOW));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert!(
        fx.state("testpage").contains("\tnomatch\t"),
        "{}",
        fx.state("testpage")
    );

    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 600, "pending");
    assert_ok(&fx.run("propolis-test-page-abc123", &TP_NOW));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert!(
        fx.state("testpage").contains("\tnomatch\t"),
        "{}",
        fx.state("testpage")
    );
}

/// A state lock held for the whole run sends nothing and logs one line, exit 0; one freed while
/// the hook still waits gets the page marked `lockbusy`, so the status command can tell this
/// from a unit that did not run.
#[test]
fn a_busy_state_lock_sends_nothing_and_is_recorded_once_it_frees() {
    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    let before = fx.state("testpage");
    let lock = hold_lock(&fx.state_lock());
    let out = fx.run("propolis-test-page-abc123", &TP_NOW);
    drop(lock);
    assert_ok(&out);
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("test page abc123 not sent: the state lock was not free"),
        "{}",
        lines[0]
    );
    assert_eq!(fx.state("testpage"), before);

    let fx = Fixture::with_ntfy().with_lib();
    fx.test_page("abc123", 100, "pending");
    let lock = hold_lock(&fx.state_lock());
    let freer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(14));
        drop(lock);
    });
    let out = fx.run("propolis-test-page-abc123", &TP_NOW);
    freer.join().unwrap();
    assert_ok(&out);
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert!(
        fx.state("testpage").contains("\tlockbusy\t"),
        "{}",
        fx.state("testpage")
    );
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
}

// ---- the decision and the v2 path ------------------------------------------------------------

/// The test seam that puts profile v2 in force (the library honours it only under the test root)
/// and the clock of TP_NOW.
const V2: [(&str, &str); 4] = [("PA_TEST_PROFILE", "v2"), TP_NOW[0], TP_NOW[1], TP_NOW[2]];

/// `V2` and `extra`, the later of two settings of one name winning.
fn v2_env<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut env: Vec<(&'a str, &'a str)> = V2.to_vec();
    env.extend_from_slice(extra);
    env
}

/// The hex sha256 of `text`, from the real sha256sum.
fn sha256_hex(text: &str) -> String {
    use std::io::Write;
    let mut child = {
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        Command::new("sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Records each `timeout` the hook runs in `$STUB_LOG.children`, then runs the real one from the
/// test's `PATH`. With `STUB_MAP_LIB` set, the library path of a run without a test root is
/// replaced: by that file for the decision child, by a path that does not exist for every other
/// child, so such a run reads no library a host may have installed. With `STUB_V2_LIB` set, the v2
/// child is given that file as its library instead of the one under the test root; with
/// `STUB_BAD_MARKER` set, the v2 child is told that path as its marker. The marker path the hook
/// gave the v2 child, and the mode of the directory it is in, go to `$STUB_LOG.marker`.
fn timeout_stub() -> String {
    let real = std::env::split_paths(&std::env::var("PATH").unwrap())
        .map(|d| d.join("timeout"))
        .find(|p| p.is_file())
        .expect("timeout is on PATH");
    format!(
        r#"#!/usr/bin/env bash
printf 'timeout %s\n' "$*" >> "$STUB_LOG.children"
case " $* " in
    *pa_hook_v2*)
        printf '%s %s\n' "${{PA_HOOK_MARKER:-}}" \
            "$(stat -c %a -- "$(dirname -- "${{PA_HOOK_MARKER:-/nonexistent/none}}")" 2> /dev/null)" >> "$STUB_LOG.marker"
        [ -z "${{STUB_BAD_MARKER:-}}" ] || export PA_HOOK_MARKER="$STUB_BAD_MARKER"
        if [ -n "${{STUB_V2_LIB:-}}" ]; then
            args=()
            for a in "$@"; do
                [[ $a != */usr/local/sbin/propolis-alert-lib ]] || a="$STUB_V2_LIB"
                args+=("$a")
            done
            set -- "${{args[@]}}"
        fi
        ;;
esac
if [ -n "${{STUB_MAP_LIB:-}}" ]; then
    want=/nonexistent/propolis-alert-lib
    case " $* " in *pa_hook_profile*) want="$STUB_MAP_LIB" ;; esac
    args=()
    for a in "$@"; do
        [ "$a" != /usr/local/sbin/propolis-alert-lib ] || a="$want"
        args+=("$a")
    done
    set -- "${{args[@]}}"
fi
exec {} "$@"
"#,
        real.display()
    )
}

/// A curl that, as soon as it is run, stops the process group of the v2 child that posts through
/// it, as the child's time limit or systemd stopping the unit mid-post would. pa_send's own
/// `timeout` leads a group of its own, so the group is the one of that timeout's parent. Run by
/// anything but that `timeout` (today's code posts without one), it only fails.
const KILLING_CURL: &str = r#"#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$STUB_LOG"
[ "$(cat "/proc/$PPID/comm")" = timeout ] || exit 22
fields() { local s; s="$(cat "/proc/$1/stat")"; printf '%s\n' "${s##*) }"; }
read -r _ up _ < <(fields "$PPID")
read -r _ _ group _ < <(fields "$up")
kill -TERM -- "-$group"
sleep 5
"#;

impl Fixture {
    /// A host the v2 path may send from under TP_NOW: a target without a token (so the gate needs
    /// no role), its read check a refusal 1000 s old over https, the salt, and a light pass that
    /// completed 100 s before.
    fn v2() -> Self {
        let fx = Self::new(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example/\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n",
        )
        .with_lib();
        fx.v2_state("var/lib/propolis/witness");
        std::fs::write(
            fx.root.join("var/lib/propolis/witness/id-salt"),
            format!("{TP_SALT}\n"),
        )
        .unwrap();
        fx
    }

    /// The read check and the light pass's last completion, in the state directory `rel`.
    fn v2_state(&self, rel: &str) {
        let dir = self.root.join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        let binding = sha256_hex("https://ntfy.example\npropolis-ops\n")[..16].to_string();
        std::fs::write(
            dir.join("readcheck"),
            format!(
                "#readcheck v1 g=1\nR\t{binding}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\t-\t403\t403\tboth\t403\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("meta"),
            "#meta v1 g=1\nM\tlight_last\t999900/abcdef01/4900\n",
        )
        .unwrap();
    }

    /// The light pass's last completion, `secs` (under 5000) before TP_NOW.
    fn light_pass_ago(&self, secs: u64) {
        std::fs::write(
            self.root.join("var/lib/propolis/witness/meta"),
            format!(
                "#meta v1 g=1\nM\tlight_last\t{}/abcdef01/{}\n",
                1_000_000 - secs,
                5000 - secs
            ),
        )
        .unwrap();
    }

    /// Puts the `timeout` stub first on the hook's `PATH`.
    fn log_children(&self) {
        write_exec(&self.bin.join("timeout"), &timeout_stub());
    }

    fn children(&self) -> String {
        std::fs::read_to_string(format!("{}.children", self.log.display())).unwrap_or_default()
    }

    /// The titles of the posts made with a config file, in order.
    fn v2_titles(&self) -> Vec<String> {
        self.confs()
            .lines()
            .filter_map(|l| l.strip_prefix("header = \"Title: "))
            .map(|t| t.trim_end_matches('"').to_string())
            .collect()
    }

    /// The body of the `n`th post (from 0), as the curl stub read it.
    fn v2_body(&self, n: usize) -> String {
        let log = self.log();
        let after = log.split("body:\n").nth(n + 1).unwrap_or("").to_string();
        let end = ["\ncurl ", "\nlogger "]
            .iter()
            .filter_map(|m| after.find(m))
            .min()
            .unwrap_or(after.len());
        after[..end].trim_end_matches('\n').to_string()
    }

    /// The `W` lines of the persistent incidents file, split into fields.
    fn w_lines(&self) -> Vec<Vec<String>> {
        self.state("incidents")
            .lines()
            .filter(|l| l.starts_with("W\t"))
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect()
    }

    /// The `L` lines of the persistent send ledger, split into fields.
    fn ledger(&self) -> Vec<Vec<String>> {
        self.state("send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t"))
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect()
    }

    /// The hook for `unit` with `input` on its stdin.
    fn run_with_stdin(&self, unit: &str, env: &[(&str, &str)], input: &str) -> Output {
        use std::io::Write;
        let mut command = self.command(unit, env);
        command.stdin(Stdio::piped());
        let mut child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        child.wait_with_output().unwrap()
    }
}

/// A run without a test root, which is how every unit runs the hook, never reaches v2: with
/// PROPOLIS_ALERT_ROOT unset or empty, a v2 profile in both env files and the test seam set,
/// neither the decision child nor the v2 child is started, whatever file sits at the library's
/// path (the shipped library, or a file that ends its shell with the very status that means v2),
/// and what goes out is what goes out with no library at all. The same fixture under its test
/// root does start the v2 child, so the case can tell.
#[test]
fn a_run_without_a_test_root_never_reaches_v2_whatever_the_env_files_and_the_seam_say() {
    let run = |fx: &Fixture, root: Option<&str>, lib: &Path| {
        fx.log_children();
        let state = fx.root.join("run/propolis-alert");
        let mut command = fx.command(
            "sensor-ssh.service",
            &[
                ("PA_TEST_PROFILE", "v2"),
                ("STUB_MAP_LIB", lib.to_str().unwrap()),
                ("PROPOLIS_ALERT_STATE_DIR", state.to_str().unwrap()),
            ],
        );
        match root {
            None => command.env_remove("PROPOLIS_ALERT_ROOT"),
            Some(r) => command.env("PROPOLIS_ALERT_ROOT", r),
        };
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        child.wait_with_output().unwrap()
    };
    for (root, shipped) in [
        (None, true),
        (None, false),
        (Some(""), true),
        (Some(""), false),
    ] {
        let fx = Fixture::v2();
        let v2 = "PROPOLIS_OPS_NTFY_URL=https://ntfy.example/\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\nPROPOLIS_ALERT_PROFILE=v2\n";
        std::fs::write(fx.root.join("etc/propolis/propolis.env"), v2).unwrap();
        std::fs::write(fx.root.join("etc/propolis/alert.env"), v2).unwrap();
        let lib = if shipped {
            fx.root.join("usr/local/sbin/propolis-alert-lib")
        } else {
            let says_v2 = fx.root.join("says-v2");
            std::fs::write(&says_v2, "exit 20\n").unwrap();
            says_v2
        };
        let out = run(&fx, root, &lib);
        let bare = Fixture::new("");
        let bare_out = run(&bare, root, &bare.root.join("no-such-library"));
        assert_eq!(out.status.code(), bare_out.status.code(), "{root:?}");
        assert_eq!(out.stdout, bare_out.stdout, "{root:?}");
        assert_eq!(out.stderr, bare_out.stderr, "{root:?}");
        assert_eq!(todays_part(&fx.log()), todays_part(&bare.log()), "{root:?}");
        assert!(
            fx.log().contains("entered the failed state"),
            "{root:?}: today's message: {}",
            fx.log()
        );
        let children = fx.children();
        assert!(
            !children.contains("pa_hook_profile") && !children.contains("pa_hook_v2"),
            "{root:?} shipped {shipped}: neither child is started: {children}"
        );

        assert_ok(&fx.run("sensor-ssh.service", &V2));
        assert!(fx.children().contains("pa_hook_v2"), "{}", fx.children());
    }
}

/// Whatever is wrong with the library, the decision leaves the failure to today's code: a library
/// that is missing, older than the two children need, has an unbound variable at its top level,
/// ends the shell with status 0 at its top level, or whose pa_hook_profile divides by zero, hangs
/// (cut off by the decision's limit) or writes to both streams and would say v2 if it could read
/// its stdin. Each run is under the test seam, sends today's title, body and curl call, prints and
/// returns what the hook does without a library, and starts no v2 child. A library that ends the
/// shell with status 0 records nothing either, and one line says the library ended early.
#[test]
fn a_missing_old_broken_or_hung_library_leaves_the_failure_to_todays_code() {
    let shipped = shipped_lib();
    let older = shipped
        .lines()
        .map(|l| {
            if l.starts_with("PA_LIB_VERSION=") {
                "PA_LIB_VERSION=11".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let cases = [
        ("missing", None),
        ("older", Some(older)),
        (
            "unbound",
            Some(format!("set -u\n: \"$PA_NO_SUCH_VARIABLE\"\n{shipped}")),
        ),
        ("exit0", Some(format!("exit 0\n{shipped}"))),
        (
            "division",
            Some(format!(
                "{shipped}\npa_hook_profile() {{\n    local x=$((1/0))\n    return 0\n}}\n"
            )),
        ),
        (
            "hang",
            Some(format!(
                "{shipped}\npa_hook_profile() {{\n    sleep 300\n    return 0\n}}\n"
            )),
        ),
        (
            "noisy",
            Some(format!(
                "{shipped}\npa_hook_profile() {{\n    echo to-stdout\n    echo to-stderr >&2\n    if read -r _; then : > \"$STUB_LOG.stdin\"; return 0; fi\n    return 10\n}}\n"
            )),
        ),
    ];
    let bare = Fixture::with_ntfy();
    bare.log_children();
    let bare_out = bare.run_with_stdin("sensor-ssh.service", &V2, "v2\n");
    for (name, lib) in cases {
        let fx = Fixture::with_ntfy();
        fx.log_children();
        if let Some(body) = &lib {
            fx.install_lib(body);
        }
        let started = std::time::Instant::now();
        let out = fx.run_with_stdin("sensor-ssh.service", &V2, "v2\n");
        let took = started.elapsed();
        assert_eq!(out.status.code(), bare_out.status.code(), "{name}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&bare_out.stdout),
            "{name}: stdout"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&bare_out.stderr),
            "{name}: stderr"
        );
        let log = fx.log();
        assert_eq!(todays_part(&log), todays_part(&bare.log()), "{name}");
        assert!(
            log.contains("Title: propolis: sensor-ssh.service failed on honeybox"),
            "{name}: {log}"
        );
        assert!(
            fx.children().contains("pa_hook_profile"),
            "{name}: {}",
            fx.children()
        );
        assert!(
            !fx.children().contains("pa_hook_v2"),
            "{name}: {}",
            fx.children()
        );
        assert!(
            !Path::new(&format!("{}.stdin", fx.log.display())).exists(),
            "{name}: the decision child reads no stdin"
        );
        assert!(
            took < std::time::Duration::from_secs(30),
            "{name}: the hook took {took:?}"
        );
        if name == "exit0" {
            let lines = witness_lines(&log);
            assert_eq!(lines.len(), 1, "{name}: {log}");
            assert!(
                lines[0].contains("the alert library ended before it said which profile")
                    && lines[0].contains("sensor-ssh.service"),
                "{name}: {}",
                lines[0]
            );
            // It promises no alert: for a failed witness pass today's code sends none.
            assert!(!lines[0].contains("follows"), "{name}: {}", lines[0]);
        }
    }
}

/// The time budget adds up in every path inside TimeoutStartSec: the decision's limit and its
/// kill-after; the v2 child's limit, counted from the hook's start, and its kill-after; today's
/// worst case, which covers the post's --retry-max-time and its last --max-time with 5 s for the
/// rest; the latest start of today's code after a v2 child that failed; and the record step's
/// ceiling with its kill-after. The children need a library newer than the record step does, and
/// the shipped one serves them.
#[test]
fn the_time_budget_of_every_path_fits_inside_the_unit_timeout() {
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
    let value = |name: &str| -> u64 {
        hook.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("deploy/alert.sh sets {name}=<n>"))
    };
    let decide = value("DECIDE_LIMIT");
    let v2 = value("V2_LIMIT");
    let worst = value("LEGACY_WORST");
    let needs = value("V2_NEEDS");
    // The latest start of today's code is what the record step's ceiling leaves of its worst case.
    let last = 85 - worst;
    for fragment in [
        "LEGACY_LAST_START=$(( 85 - LEGACY_WORST ))",
        "[ \"$SECONDS\" -gt \"$LEGACY_LAST_START\" ]",
        "timeout --kill-after=1 \"$decide_budget\"",
        "timeout --kill-after=2 \"$v2_budget\"",
        "budget=$(( 85 - SECONDS ))",
    ] {
        assert!(hook.contains(fragment), "deploy/alert.sh runs {fragment}");
    }
    let record_ceiling = 85;
    let argv = hook
        .lines()
        .find(|l| l.contains("curl -fsS"))
        .expect("today's curl line");
    let post = curl_flag_value(argv, "--retry-max-time") + curl_flag_value(argv, "--max-time");
    assert!(
        worst >= post + 5,
        "today's worst case {worst} s covers the post's {post} s"
    );
    // Legacy: the decision, today's code, then the record step to its ceiling.
    assert!(decide + 1 + worst <= record_ceiling, "legacy");
    assert!(record_ceiling + 1 + 2 <= timeout, "the record step");
    // v2 handled: the decision and the child end by the child's limit, with no record step.
    assert!(decide + 1 < v2 && v2 + 2 < timeout, "v2");
    // v2 failed without its marker in time: today's code, then the record step.
    assert!(last + worst <= record_ceiling, "the fallback");
    assert!(needs > u64::from(hook_needs()) && needs <= u64::from(shipped_lib_version()));
}

/// A v2 open: one post in the contract format and nothing of today's. A oneshot opens at once;
/// the host name, the unit's name, its journal text and the word propolis are planted and are in
/// neither the title nor the body; curl is given only its config file; the record is the hook's
/// open (hookopen), its pending transition cleared once the post got through and the open marked
/// delivered; the ledger line is the hook's; the legacy record step does not run, so the firing
/// counts once; nothing goes under tag propolis-alert, and today's stamp for the unit is set, so a
/// later firing that finds the lock busy honours the cooldown of this delivered open.
#[test]
fn a_v2_title_carries_the_alias_and_no_planted_name() {
    let fx = Fixture::v2();
    let unit = "propolis-backup.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    let journal = fx._dir.path().join("run-journal");
    std::fs::write(&journal, "thread main panicked at PLANTEDPANIC\n").unwrap();
    let matching = format!("_SYSTEMD_INVOCATION_ID={INVOCATION}");
    let out = fx.run(
        unit,
        &v2_env(&[
            ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
            ("STUB_RUN_MATCH", &matching),
        ]),
    );
    assert_ok(&out);
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
    let log = fx.log();
    let calls: Vec<&str> = log.lines().filter(|l| l.starts_with("curl ")).collect();
    assert_eq!(calls.len(), 1, "{log}");
    assert_eq!(
        calls[0].split(' ').count(),
        4,
        "nothing but the config file: {}",
        calls[0]
    );
    let titles = fx.v2_titles();
    assert_eq!(titles.len(), 1, "{}", fx.confs());
    let title = &titles[0];
    let body = fx.v2_body(0);
    assert!(
        title.starts_with("ACT host-") && title.ends_with(" - backup: unit ? failed"),
        "{title}"
    );
    assert!(
        fx.confs().contains("header = \"Priority: 3\""),
        "{}",
        fx.confs()
    );
    assert!(
        body.contains("Why: panicked (proc.panic), seen by hook@host-"),
        "{body}"
    );
    assert!(
        body.lines()
            .last()
            .unwrap()
            .starts_with("w#1 opened - next reminder "),
        "{body}"
    );
    for planted in [
        "honeybox",
        "propolis",
        "backup.service",
        "PLANTEDPANIC",
        "boom",
        "injected",
        "ntfy.example",
    ] {
        assert!(!title.contains(planted), "{planted} in {title}");
        assert!(!body.contains(planted), "{planted} in {body}");
    }
    let f = fx.record(unit);
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "proc.panic"));
    assert!(f[30].split(',').any(|w| w == "hookopen"), "{f:?}");
    assert_eq!(f[14], "1", "sends");
    assert_eq!(f[17], "1", "delivered_open");
    assert_eq!((f[26].as_str(), f[27].as_str()), ("-", "-"), "pending_tx");
    assert_eq!(f[31], "1", "occ: the record step did not run");
    assert_eq!(f[33], "-", "legacy_out");
    let ledger = fx.ledger();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    let l = &ledger[0];
    assert_eq!(l.len(), 10, "{l:?}");
    assert_eq!(
        (
            l[2].as_str(),
            l[4].as_str(),
            l[5].as_str(),
            l[6].as_str(),
            l[7].as_str(),
            l[8].as_str()
        ),
        ("pool", "open", "full", "ok", "hook", "w#1"),
        "{l:?}"
    );
    assert!(witness_lines(&log).is_empty(), "{log}");
    assert!(!log.contains("-t propolis-alert"), "{log}");
    assert_eq!(mode_of(&fx.delivered_stamp(unit)), 0o600);
    assert_eq!(mode_of(&fx.root.join("run/propolis-alert")), 0o700);
}

/// A unit that restarts itself is a first sighting under v2 too: written pending and nothing sent
/// while the light pass is fresh, since that pass judges it; opened at once and sent when the
/// light pass's last completion is over 900 s old, or none is on record after the first half hour
/// of uptime; kept pending and flagged maint under a maintenance marker, stale or not. A sensor
/// with an open no-config finding fails as unit-nobind, at ACT.
#[test]
fn a_restarting_unit_is_pending_under_v2_unless_the_light_pass_is_stale() {
    let unit = "sensor-ssh.service";
    let answer = show_answer("exit-code", "1", "always", "2");
    let fresh = |ago: Option<u64>, extra: &[(&str, &str)]| {
        let fx = Fixture::v2();
        match ago {
            Some(s) => fx.light_pass_ago(s),
            None => std::fs::remove_file(fx.root.join("var/lib/propolis/witness/meta")).unwrap(),
        }
        fx.show(unit, &answer);
        assert_ok(&fx.run(unit, &v2_env(extra)));
        assert!(!fx.log().contains("curl -fsS"), "{}", fx.log());
        fx
    };
    for (ago, extra, sends) in [
        (Some(100), vec![], 0),
        (Some(900), vec![], 0),
        (Some(901), vec![], 1),
        (None, vec![], 1),
        (None, vec![("PA_TEST_UP", "1000")], 0),
    ] {
        let fx = fresh(ago, &extra);
        let f = fx.record(unit);
        assert_eq!(fx.tp_posts(), sends, "{ago:?} {extra:?}: {}", fx.log());
        assert_eq!(f[32], "2", "nr_seen");
        if sends == 0 {
            assert_eq!(f[7], "pending", "{ago:?} {extra:?}");
            assert!(!f[30].contains("hookopen"), "{f:?}");
            assert!(fx.ledger().is_empty());
        } else {
            assert_eq!(f[7], "open", "{ago:?}");
            assert!(f[30].contains("hookopen"), "{f:?}");
            let t = &fx.v2_titles()[0];
            assert!(
                t.starts_with("PAGE host-") && t.ends_with(" - listen: unit ? failed"),
                "{t}"
            );
            assert!(fx.confs().contains("header = \"Priority: 5\""));
        }
    }

    // Under a maintenance marker, even with the light pass stale.
    let fx = Fixture::v2();
    fx.light_pass_ago(4000);
    std::fs::write(
        fx.root.join("run/propolis-witness/maintenance"),
        "#maintenance v1 g=1\nX\t1000600\tabcdef01\tmanual\n",
    )
    .unwrap();
    fx.show(unit, &answer);
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 0, "{}", fx.log());
    let f = fx.record(unit);
    assert_eq!(f[7], "pending");
    assert!(f[30].split(',').any(|w| w == "maint"), "{f:?}");

    // A sensor that restarts on a bind its config never set.
    let fx = Fixture::v2();
    fx.light_pass_ago(901);
    let k12 = sha256_hex("noconfig:sensor-ssh")[..12].to_string();
    std::fs::write(
        fx.root.join("var/lib/propolis/witness/incidents"),
        format!(
            "#incidents v1 g=1\nN\t2\nI\tw#1\tfinding:noconfig:{k12}\tfinding\tlisten\t-\tACT\topen{}\n",
            "\t-".repeat(27)
        ),
    )
    .unwrap();
    fx.show(unit, &answer);
    assert_ok(&fx.run(unit, &V2));
    let f = fx.record(unit);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str()),
        ("unit-nobind", "ACT", "open")
    );
    let t = &fx.v2_titles()[0];
    assert!(
        t.starts_with("ACT host-") && t.ends_with(" - listen: unit ? restarting on an unset bind"),
        "{t}"
    );
}

/// A unit already open only counts a repeat failure and sends nothing, unless the cause changed
/// class, which is a change and is sent as one.
#[test]
fn a_repeat_failure_under_v2_only_counts_unless_the_cause_class_changes() {
    let fx = Fixture::v2();
    let unit = "propolis-backup.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let f = fx.record(unit);
    assert_eq!((f[7].as_str(), f[31].as_str()), ("open", "2"));
    let path = fx.root.join("var/lib/propolis/witness/incidents");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches("\tproc.exit:1\t").count(), 1, "{text}");
    std::fs::write(&path, text.replace("\tproc.exit:1\t", "\tguard.no_space\t")).unwrap();
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 2, "{}", fx.log());
    let titles = fx.v2_titles();
    assert!(
        titles[1].ends_with(" - backup: unit ? failed (changed)"),
        "{titles:?}"
    );
    let body = fx.v2_body(1);
    assert!(
        body.lines()
            .last()
            .unwrap()
            .starts_with("w#1 changed: guard.no_space -> proc.exit 1"),
        "{body}"
    );
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 2, "{}", fx.log());
    let f = fx.record(unit);
    assert_eq!((f[16].as_str(), f[31].as_str()), ("change", "4"));
    assert!(witness_lines(&fx.log()).is_empty(), "{}", fx.log());
}

/// With a gate other than full (no read check on record, or a target over plain http) the v2 hook
/// records the open and admits and sends nothing: the pointer message is not built yet.
#[test]
fn with_a_gate_other_than_full_the_v2_hook_records_and_sends_nothing() {
    let unit = "propolis-backup.service";
    let check = |fx: &Fixture| {
        fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
        assert_ok(&fx.run(unit, &V2));
        assert!(!fx.log().contains("curl "), "{}", fx.log());
        let f = fx.record(unit);
        assert_eq!(
            (f[7].as_str(), f[14].as_str(), f[26].as_str()),
            ("open", "0", "-")
        );
        assert!(fx.ledger().is_empty(), "{:?}", fx.ledger());
        assert!(fx.w_lines().is_empty());
    };
    let fx = Fixture::v2();
    std::fs::remove_file(fx.root.join("var/lib/propolis/witness/readcheck")).unwrap();
    check(&fx);
    let fx = Fixture::v2();
    std::fs::write(
        fx.root.join("etc/propolis/propolis.env"),
        "PROPOLIS_OPS_NTFY_URL=http://ntfy.example/\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\n",
    )
    .unwrap();
    let binding = sha256_hex("http://ntfy.example\npropolis-ops\n")[..16].to_string();
    std::fs::write(
        fx.root.join("var/lib/propolis/witness/readcheck"),
        format!(
            "#readcheck v1 g=1\nR\t{binding}\t999000/abcdef01/4000\trefused\t999000/abcdef01/4000\trefused\t-\t403\t403\tboth\t403\n"
        ),
    )
    .unwrap();
    check(&fx);
}

/// A withheld open (the pool's four an hour already spent on other keys) writes the W line that
/// says so and sends nothing; the ledger gains no line.
#[test]
fn a_withheld_v2_open_writes_a_w_line_and_sends_nothing() {
    let fx = Fixture::v2();
    let unit = "propolis-backup.service";
    let mut ledger = "#send-ledger v1 g=1\n".to_string();
    for i in 0..4 {
        let s = format!("{}/abcdef01/{}", 999_900 + i, 4900 + i);
        ledger += &format!("L\t{s}\tpool\t0000000{i}\topen\tfull\tok\thook\tw#9{i}\t{s}\n");
    }
    std::fs::write(
        fx.root.join("var/lib/propolis/witness/send-ledger"),
        &ledger,
    )
    .unwrap();
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert_eq!(fx.state("send-ledger"), ledger);
    let kh = sha256_hex(&format!("unit:{unit}"))[..8].to_string();
    assert_eq!(
        fx.w_lines(),
        [[
            "W",
            "1000000/abcdef01/5000",
            kh.as_str(),
            "open",
            "1",
            "-",
            "pool"
        ]
        .map(str::to_string)
        .to_vec()]
    );
    let f = fx.record(unit);
    assert_eq!(
        (f[7].as_str(), f[14].as_str(), f[26].as_str()),
        ("open", "0", "-")
    );
}

/// The claim comes before the send: a v2 child stopped while its message is being posted leaves
/// the transition pending in the record and its ledger line pending, for a later retry, and the
/// hook adds nothing of today's.
#[test]
fn pending_tx_is_set_before_the_send() {
    let fx = Fixture::v2();
    let unit = "propolis-backup.service";
    write_exec(&fx.bin.join("curl"), KILLING_CURL);
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    let out = fx.run_in_own_group(unit, &V2);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let log = fx.log();
    assert_eq!(log.matches("curl -q -K ").count(), 1, "{log}");
    assert!(!log.contains("curl -fsS"), "{log}");
    let f = fx.record(unit);
    assert_eq!(
        (f[7].as_str(), f[26].as_str(), f[17].as_str()),
        ("open", "open", "0")
    );
    assert!(is_stamp(&f[27]), "{f:?}");
    let ledger = fx.ledger();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(
        (ledger[0][1].as_str(), ledger[0][6].as_str()),
        (f[27].as_str(), "pending")
    );
    assert_eq!(f[31], "1", "the record step did not run");
}

/// A `WALL/BOOT/UP` stamp.
fn is_stamp(s: &str) -> bool {
    let p: Vec<&str> = s.split('/').collect();
    p.len() == 3 && p.iter().all(|x| !x.is_empty())
}

/// The result is written under the lock once the post is done: a transient answer keeps the
/// transition pending for a retry, a permanent refusal clears it, and only an answer that got
/// through clears it and marks the open delivered. The hook ends 0 in each.
#[test]
fn the_send_result_is_written_under_the_lock_and_only_ok_marks_the_open_delivered() {
    let unit = "propolis-backup.service";
    for (code, result, pending, delivered) in [
        ("503", "transient:503", "open", "0"),
        ("403", "perm:403", "-", "0"),
        ("200", "ok", "-", "1"),
    ] {
        let fx = Fixture::v2();
        fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
        assert_ok(&fx.run(unit, &v2_env(&[("STUB_POST_CODE", code)])));
        assert_eq!(fx.tp_posts(), 1, "{code}: {}", fx.log());
        let f = fx.record(unit);
        assert_eq!(
            (f[26].as_str(), f[17].as_str()),
            (pending, delivered),
            "{code}: {f:?}"
        );
        let l = &fx.ledger()[0];
        assert_eq!(
            (l[6].as_str(), l[7].as_str()),
            (result, "hook"),
            "{code}: {l:?}"
        );
        assert!(!fx.log().contains("curl -fsS"), "{code}");
    }
}

/// When the state lock is not had in 10 s the v2 hook writes the spool file, as the record step
/// does, and sends one message for this unit only while its own stamp is absent or older than the
/// cooldown, with `(id pending)` for the id. Only a post that got through sets the stamp; the
/// post's result goes into the spool file's last field, and a firing that sends nothing keeps the
/// last result there. Each firing is counted once in the spool and none is recorded.
#[test]
fn a_held_lock_spools_and_sends_once_per_cooldown() {
    let fx = Fixture::v2();
    let unit = "propolis-backup.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    let spool_path = fx.root.join("var/lib/propolis/witness/hook").join(unit);
    let spool = || -> Vec<String> {
        let text = std::fs::read_to_string(&spool_path).unwrap();
        text.lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .map(str::to_string)
            .collect()
    };
    let stamp = fx.delivered_stamp(unit);
    let lock = hold_lock(&fx.state_lock());

    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let body = fx.v2_body(0);
    assert!(
        body.lines()
            .last()
            .unwrap()
            .starts_with("(id pending) opened"),
        "{body}"
    );
    assert!(!fx.v2_titles()[0].contains("propolis"));
    assert_eq!(mode_of(&stamp), 0o600);
    let h = spool();
    assert_eq!(h.len(), 10, "{h:?}");
    assert_eq!(
        (h[3].as_str(), h[7].as_str(), h[9].as_str()),
        ("1", "proc.exit:1", "ok")
    );

    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "within the cooldown: {}", fx.log());
    let h = spool();
    assert_eq!((h[3].as_str(), h[9].as_str()), ("2", "ok"), "{h:?}");

    age_by(&stamp, 1801);
    age_by(&fx.tried_stamp(unit), 1801);
    assert_ok(&fx.run(unit, &v2_env(&[("STUB_POST_CODE", "403")])));
    assert_eq!(fx.tp_posts(), 2, "past the cooldown: {}", fx.log());
    let h = spool();
    assert_eq!((h[3].as_str(), h[9].as_str()), ("3", "perm:403"), "{h:?}");
    assert!(age_of(&stamp) >= 1800, "a refused post sets no stamp");
    drop(lock);

    assert!(fx.records().is_empty(), "{:?}", fx.records());
    assert!(!fx.log().contains("curl -fsS"), "{}", fx.log());
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("not delivered (perm:403)"),
        "{}",
        lines[0]
    );
}

/// With neither state directory usable (no lock and no spool can be had) the journal is the v2
/// hook's memory: it sends only when no `hook sent` line of this unit's hook is in the journal of
/// the last 30 minutes, and logs that line before it sends; when the journal cannot be asked, it
/// sends only for the daemon. The line is written over a stream connection (systemd-cat), whose
/// sender journald identifies when it connects, so the query by the hook unit's trusted field
/// finds it; a datagram from logger, which exits at once, often reaches journald too late for it
/// to name the unit.
#[test]
fn with_nothing_writable_the_journal_bounds_the_sends() {
    let fx = Fixture::v2();
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::remove_file(witness.join("state.lock")).unwrap();
    std::fs::write(witness.join("hook"), "not a directory").unwrap();
    let run = fx.root.join("run/propolis-witness");
    std::fs::remove_dir_all(&run).unwrap();
    std::fs::write(&run, "not a directory").unwrap();
    let unit = "propolis-backup.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));

    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let log = fx.log();
    let claim = log
        .find("systemd-cat -t propolis-witness -p notice hook sent - 1000000/abcdef01/5000")
        .unwrap_or_else(|| panic!("{log}"));
    assert!(
        !log.lines()
            .any(|l| l.starts_with("logger ") && l.contains("hook sent")),
        "{log}"
    );
    assert!(
        claim < log.find("curl -q -K").unwrap(),
        "the line comes first: {log}"
    );
    let q = fx.queries();
    assert!(
        q.lines().any(|l| l
            .contains("_SYSTEMD_UNIT=propolis-alert@propolis-backup.service.service")
            && l.contains("-t propolis-witness")
            && l.contains("--since=-30min")),
        "{q}"
    );

    let journal = fx._dir.path().join("hook-journal");
    std::fs::write(&journal, "hook sent - 999999/abcdef01/4999\n").unwrap();
    assert_ok(&fx.run(
        unit,
        &v2_env(&[
            ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
            (
                "STUB_RUN_MATCH",
                "_SYSTEMD_UNIT=propolis-alert@propolis-backup.service.service",
            ),
        ]),
    ));
    assert_eq!(
        fx.tp_posts(),
        1,
        "a line in the last 30 minutes: {}",
        fx.log()
    );

    assert_ok(&fx.run(unit, &v2_env(&[("STUB_JOURNAL_FAIL", "1")])));
    assert_eq!(
        fx.tp_posts(),
        1,
        "no journal: only the daemon: {}",
        fx.log()
    );

    fx.show(
        "propolis.service",
        &show_answer("exit-code", "1", "always", "0"),
    );
    assert_ok(&fx.run("propolis.service", &v2_env(&[("STUB_JOURNAL_FAIL", "1")])));
    assert_eq!(fx.tp_posts(), 2, "{}", fx.log());
    assert!(
        fx.v2_titles()[1].ends_with(" - intake: monitor and intake down"),
        "{:?}",
        fx.v2_titles()
    );
    assert!(!fx.log().contains("curl -fsS"), "{}", fx.log());
}

/// With the persistent directory unusable the v2 hook records in /run's fallback and still sends,
/// and its message says the state is not persisted.
#[test]
fn an_unusable_persistent_directory_records_in_run_and_the_message_says_not_persisted() {
    let fx = Fixture::new(
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example/\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\nPROPOLIS_OPS_HOST_ALIAS=edge-one\n",
    )
    .with_lib();
    fx.v2_state("run/propolis-witness/fallback");
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::remove_dir_all(&witness).unwrap();
    std::fs::write(&witness, "not a directory").unwrap();
    let unit = "propolis-backup.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert!(
        fx.v2_titles()[0].starts_with("ACT edge-one - backup"),
        "{:?}",
        fx.v2_titles()
    );
    let body = fx.v2_body(0);
    assert!(
        body.lines().last().unwrap().contains("not persisted"),
        "{body}"
    );
    let records = fx.records_at("run/propolis-witness/fallback/incidents");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        (records[0][7].as_str(), records[0][17].as_str()),
        ("open", "1")
    );
}

/// Under v2 a failed witness pass is an incident like any unit's: the witness rail at ACT, sent.
#[test]
fn a_failed_witness_pass_is_sent_as_a_witness_rail_incident_under_v2() {
    let fx = Fixture::v2();
    let unit = "propolis-witness@light.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let t = &fx.v2_titles()[0];
    assert!(
        t.starts_with("ACT host-") && t.ends_with(" - witness: unit ? failed"),
        "{t}"
    );
    let f = fx.record(unit);
    assert_eq!(
        (f[3].as_str(), f[4].as_str(), f[6].as_str()),
        ("unit-failed", "witness", "ACT")
    );
}

/// A v2 child that fails before it has changed anything (no marker) leaves the failure to today's
/// code while enough of the unit's time is left for today's worst case, which then sends today's
/// message and records the firing; once that time is gone it logs one line and the hook ends 0.
#[test]
fn a_v2_child_that_fails_without_its_marker_sends_todays_message_only_while_time_is_left() {
    let unit = "sensor-ssh.service";
    for broken in [
        "pa_hook_v2() {\n    return 3\n}\n",
        "pa_hook_v2() {\n    local x=$((1/0))\n    return 0\n}\n",
    ] {
        let fx = Fixture::v2();
        fx.install_lib(&format!("{}\n{broken}", shipped_lib()));
        fx.show(unit, &show_answer("exit-code", "1", "always", "2"));
        let out = fx.run(unit, &v2_env(&[("SECONDS", "15")]));
        assert_ok(&out);
        assert!(
            fx.log()
                .contains("Title: propolis: sensor-ssh.service failed on honeybox"),
            "{}",
            fx.log()
        );
        assert_eq!(fx.log().matches("curl ").count(), 1, "{}", fx.log());
        assert_eq!(
            fx.record(unit)[33],
            "delivered",
            "the record step recorded it once"
        );

        let fx = Fixture::v2();
        fx.install_lib(&format!("{}\n{broken}", shipped_lib()));
        let out = fx.run(unit, &v2_env(&[("SECONDS", "25")]));
        assert_ok(&out);
        assert!(!fx.log().contains("curl "), "{}", fx.log());
        let lines = witness_lines(&fx.log());
        assert_eq!(lines.len(), 1, "{}", fx.log());
        assert!(
            lines[0].contains(&format!("alert for {unit} not sent")),
            "{}",
            lines[0]
        );
        assert!(fx.records().is_empty());
        assert!(!fx.delivered_stamp(unit).exists());
    }
}

/// A v2 child that fails after it made its marker may have sent: the hook adds neither today's
/// message nor a second record, logs one line and ends 0.
#[test]
fn a_v2_child_that_fails_after_its_marker_sends_nothing_more() {
    let fx = Fixture::v2();
    fx.install_lib(&format!(
        "{}\npa_hook_v2() {{\n    : > \"$PA_HOOK_MARKER\"\n    return 3\n}}\n",
        shipped_lib()
    ));
    let unit = "sensor-ssh.service";
    assert_ok(&fx.run(unit, &V2));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert!(fx.records().is_empty());
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
    assert!(!fx.delivered_stamp(unit).exists());
}

/// A v2 child that hangs is cut off by its limit, counted from the hook's start; without its
/// marker and with too little time left, the hook logs one line and ends 0.
#[test]
fn a_hung_v2_child_is_cut_off_at_its_limit_and_the_hook_ends_zero() {
    let fx = Fixture::v2();
    fx.install_lib(&format!(
        "{}\npa_hook_v2() {{\n    sleep 300\n}}\n",
        shipped_lib()
    ));
    let started = std::time::Instant::now();
    let out = fx.run("sensor-ssh.service", &v2_env(&[("SECONDS", "70")]));
    let took = started.elapsed();
    assert_ok(&out);
    assert!(
        took < std::time::Duration::from_secs(30),
        "the hook took {took:?}"
    );
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
}

/// A record that is not whole (an empty field) is not one the tables know: the firing is recorded
/// and nothing is sent.
#[test]
fn a_v2_record_that_is_not_whole_is_recorded_and_nothing_is_sent() {
    let fx = Fixture::v2();
    let unit = "propolis-backup.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1);
    let path = fx.root.join("var/lib/propolis/witness/incidents");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("\thookopen\t", "\t\t")).unwrap();
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(fx.records().len(), 1, "{:?}", fx.records());
    assert!(!fx.log().contains("curl -fsS"), "{}", fx.log());
    assert_eq!(fx.ledger().len(), 1);
}

/// A claim that cannot be written sends nothing: a ledger line that cannot be written, or a
/// record that cannot take the claim (its ledger line is given back as noclaim). The withheld
/// open leaves its W line, with the reason `ledger`, where the record can be written.
#[test]
fn a_claim_that_cannot_be_written_sends_nothing() {
    let unit = "propolis-backup.service";
    let fx = Fixture::v2();
    fx.install_lib(&format!(
        "{}\npa_ledger_add() {{\n    return 1\n}}\n",
        shipped_lib()
    ));
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    let f = fx.record(unit);
    assert_eq!(
        (f[7].as_str(), f[26].as_str(), f[14].as_str()),
        ("open", "-", "0")
    );
    let kh = sha256_hex(&format!("unit:{unit}"))[..8].to_string();
    assert_eq!(
        fx.w_lines(),
        [[
            "W",
            "1000000/abcdef01/5000",
            kh.as_str(),
            "open",
            "1",
            "-",
            "ledger"
        ]
        .map(str::to_string)
        .to_vec()]
    );

    let fx = Fixture::v2();
    fx.install_lib(&format!(
        "{}\npa_incident_write() {{\n    return 1\n}}\n",
        shipped_lib()
    ));
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    let ledger = fx.ledger();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(ledger[0][6], "noclaim");
    assert!(fx.records().is_empty());
}

// ---- the v2 path's corners -------------------------------------------------------------------

impl Fixture {
    /// The stamp of the last post the v2 hook attempted for `unit` without the state lock.
    fn tried_stamp(&self, unit: &str) -> PathBuf {
        self.root.join("run/propolis-alert/v2-tried").join(unit)
    }

    /// The fields of the `H` line of `unit`'s persistent spool file.
    fn spool(&self, unit: &str) -> Vec<String> {
        let text =
            std::fs::read_to_string(self.root.join("var/lib/propolis/witness/hook").join(unit))
                .unwrap();
        text.lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .map(str::to_string)
            .collect()
    }

    /// Sets the numbered fields of `unit`'s record in the persistent incidents file.
    fn edit_record(&self, unit: &str, edits: &[(usize, &str)]) {
        let path = self.root.join("var/lib/propolis/witness/incidents");
        let key = format!("unit:{unit}");
        let text = std::fs::read_to_string(&path).unwrap();
        let out: Vec<String> = text
            .lines()
            .map(|l| {
                let mut f: Vec<String> = l.split('\t').map(str::to_string).collect();
                if f.first().map(String::as_str) == Some("I") && f.get(2) == Some(&key) {
                    for (i, v) in edits {
                        f[*i] = v.to_string();
                    }
                }
                f.join("\t")
            })
            .collect();
        std::fs::write(&path, out.join("\n") + "\n").unwrap();
    }

    /// No lock file can be opened and no spool or state file written in either directory.
    fn nothing_writable(&self) {
        let witness = self.root.join("var/lib/propolis/witness");
        std::fs::remove_file(witness.join("state.lock")).unwrap();
        std::fs::write(witness.join("hook"), "not a directory").unwrap();
        let run = self.root.join("run/propolis-witness");
        std::fs::remove_dir_all(&run).unwrap();
        std::fs::write(&run, "not a directory").unwrap();
    }
}

/// The time limit the hook gave the child that runs `function`, from the `timeout` stub's log.
fn child_limit(children: &str, function: &str) -> i64 {
    let line = children
        .lines()
        .find(|l| l.contains(function))
        .unwrap_or_else(|| panic!("no child runs {function}: {children}"));
    line.split_whitespace()
        .nth(2)
        .and_then(|w| w.parse().ok())
        .unwrap_or_else(|| panic!("no limit in {line}"))
}

const BACKUP: &str = "propolis-backup.service";

/// A hook started late gives the decision only what is left of 85 s, so the record step keeps
/// its time: started at SECONDS 83, a hung decision is limited to 2 s at most (and its
/// kill-after), and today's message is still sent.
#[test]
fn a_decision_started_late_is_limited_to_what_is_left_of_85_seconds() {
    let fx = Fixture::with_ntfy();
    fx.install_lib(&format!(
        "{}\npa_hook_profile() {{\n    sleep 300\n}}\n",
        shipped_lib()
    ));
    fx.log_children();
    let started = std::time::Instant::now();
    let out = fx.run("sensor-ssh.service", &v2_env(&[("SECONDS", "83")]));
    let took = started.elapsed();
    assert_ok(&out);
    assert!(
        took < std::time::Duration::from_secs(20),
        "the hook took {took:?}"
    );
    assert!(
        fx.log()
            .contains("Title: propolis: sensor-ssh.service failed on honeybox"),
        "{}",
        fx.log()
    );
    let limit = child_limit(&fx.children(), "pa_hook_profile");
    assert!((1..=2).contains(&limit), "{}", fx.children());
}

/// A v2 child started at or past its limit (75 s from the hook's start) still gets a limit of one
/// second: `timeout 0` would mean no limit at all. Cut off without its marker and with too little
/// time left, it leaves one line and the hook ends 0.
#[test]
fn a_v2_child_started_at_its_limit_still_gets_a_limit_of_one_second() {
    let fx = Fixture::v2();
    fx.install_lib(&format!(
        "{}\npa_hook_v2() {{\n    sleep 30\n}}\n",
        shipped_lib()
    ));
    fx.log_children();
    let started = std::time::Instant::now();
    let out = fx.run("sensor-ssh.service", &v2_env(&[("SECONDS", "75")]));
    let took = started.elapsed();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(
        took < std::time::Duration::from_secs(15),
        "the hook took {took:?}"
    );
    assert_eq!(
        child_limit(&fx.children(), "pa_hook_v2"),
        1,
        "{}",
        fx.children()
    );
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    assert_eq!(witness_lines(&fx.log()).len(), 1, "{}", fx.log());
}

/// The v2 child gets no stdin and its output is discarded, as the record step's is: systemd
/// journals the hook's own streams under propolis-alert.
#[test]
fn the_v2_child_reads_no_stdin_and_its_output_is_discarded() {
    let fx = Fixture::v2();
    fx.install_lib(&format!(
        "{}\npa_hook_v2() {{\n    echo to-stdout\n    echo to-stderr >&2\n    if read -r _; then : > \"$STUB_LOG.stdin\"; fi\n    : > \"$PA_HOOK_MARKER\"\n    return 0\n}}\n",
        shipped_lib()
    ));
    let out = fx.run_with_stdin("sensor-ssh.service", &V2, "v2\n");
    assert_ok(&out);
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    assert!(!Path::new(&format!("{}.stdin", fx.log.display())).exists());
    assert!(!fx.log().contains("curl "), "{}", fx.log());
}

/// The hook goes by the v2 child's marker, not its status: a library swapped between the decision
/// and the v2 child for one that ends the shell with status 0 at its top level made no marker and
/// handled nothing, and today's message goes out.
#[test]
fn a_v2_child_that_ends_zero_without_its_marker_leaves_the_failure_to_todays_code() {
    let fx = Fixture::v2();
    fx.log_children();
    let path = fx._dir.path().join("exit0-lib");
    std::fs::write(&path, format!("exit 0\n{}", shipped_lib())).unwrap();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    let out = fx.run(
        "sensor-ssh.service",
        &v2_env(&[("STUB_V2_LIB", path.to_str().unwrap()), ("SECONDS", "15")]),
    );
    assert_ok(&out);
    assert!(fx.children().contains("pa_hook_v2"), "{}", fx.children());
    assert!(
        fx.log()
            .contains("Title: propolis: sensor-ssh.service failed on honeybox"),
        "{}",
        fx.log()
    );
}

/// The v2 child checks the library version it needs itself: a library swapped for an older one
/// between the decision and the v2 child is never asked for pa_hook_v2, even where it has one,
/// and today's message goes out.
#[test]
fn the_v2_child_checks_the_library_version_it_needs_itself() {
    let fx = Fixture::v2();
    fx.log_children();
    let older: String = shipped_lib()
        .lines()
        .map(|l| {
            if l.starts_with("PA_LIB_VERSION=") {
                "PA_LIB_VERSION=11"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let path = fx._dir.path().join("older-lib");
    std::fs::write(
        &path,
        format!("{older}\npa_hook_v2() {{\n    : > \"$STUB_LOG.v2ran\"\n    : > \"$PA_HOOK_MARKER\"\n    return 0\n}}\n"),
    )
    .unwrap();
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    let out = fx.run(
        "sensor-ssh.service",
        &v2_env(&[("STUB_V2_LIB", path.to_str().unwrap()), ("SECONDS", "15")]),
    );
    assert_ok(&out);
    assert!(
        fx.children().contains("pa_hook_v2"),
        "the v2 child ran: {}",
        fx.children()
    );
    assert!(!Path::new(&format!("{}.v2ran", fx.log.display())).exists());
    assert!(
        fx.log()
            .contains("Title: propolis: sensor-ssh.service failed on honeybox"),
        "{}",
        fx.log()
    );
}

/// The marker is made in a directory the hook creates for this run alone, which no other account
/// can enter, never under a name another account could have prepared where the hook is run by
/// hand in a shared temporary directory (a link there would be followed when the marker is
/// made). Nothing of it is left afterwards, whether the v2 child handled the failure or failed
/// without making it.
#[test]
fn the_marker_lives_in_a_directory_of_the_hooks_own_making() {
    for handled in [true, false] {
        let fx = Fixture::v2();
        fx.log_children();
        if !handled {
            fx.install_lib(&format!(
                "{}\npa_hook_v2() {{\n    return 3\n}}\n",
                shipped_lib()
            ));
        }
        let tmp = fx._dir.path().join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
        let out = fx.run(
            BACKUP,
            &v2_env(&[("TMPDIR", tmp.to_str().unwrap()), ("SECONDS", "15")]),
        );
        assert_ok(&out);
        let seen = std::fs::read_to_string(format!("{}.marker", fx.log.display())).unwrap();
        let (path, mode) = seen.trim().split_once(' ').unwrap();
        let dir = Path::new(path).parent().unwrap();
        assert!(dir != tmp.as_path() && dir.starts_with(&tmp), "{seen}");
        assert_eq!(mode, "700", "{seen}");
        assert_eq!(
            std::fs::read_dir(&tmp).unwrap().count(),
            0,
            "handled {handled}: nothing is left"
        );
        if handled {
            assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
        } else {
            assert!(
                fx.log()
                    .contains("Title: propolis: propolis-backup.service failed on honeybox"),
                "{}",
                fx.log()
            );
        }
    }
}

/// With neither directory taking a write while the lock can still be had (a read-only disk and a
/// /run the unit may not write), a first sighting that no light pass can keep is sent with the
/// journal as the memory, whatever the unit's Restart= says: the `hook sent` line, then the post.
#[test]
fn a_first_sighting_that_no_state_directory_can_keep_is_sent_with_the_journal_as_memory() {
    let fx = Fixture::v2();
    fx.light_pass_ago(100);
    fx.install_lib(&format!(
        "{}\npa_write() {{\n    return 1\n}}\n",
        shipped_lib()
    ));
    let unit = "propolis.service";
    fx.show(unit, &show_answer("exit-code", "1", "always", "0"));
    assert_ok(&fx.run(unit, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let log = fx.log();
    let claim = log
        .find("systemd-cat -t propolis-witness -p notice hook sent - 1000000/abcdef01/5000")
        .unwrap_or_else(|| panic!("{log}"));
    assert!(
        claim < log.find("curl -q -K").unwrap(),
        "the line comes first: {log}"
    );
    assert!(
        fx.v2_titles()[0].ends_with(" - intake: monitor and intake down"),
        "{:?}",
        fx.v2_titles()
    );
    assert!(fx.records().is_empty(), "{:?}", fx.records());
}

/// A send ledger with no readable copy admits nothing on its first read, which writes an empty
/// ledger; the hook asks again, and the open is counted from empty and sent.
#[test]
fn a_damaged_send_ledger_is_counted_from_empty_and_the_open_is_sent() {
    let fx = Fixture::v2();
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::write(witness.join("send-ledger"), "garbage\n").unwrap();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let ledger = fx.ledger();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(
        (ledger[0][2].as_str(), ledger[0][6].as_str()),
        ("pool", "ok")
    );
    let f = fx.record(BACKUP);
    assert_eq!((f[17].as_str(), f[26].as_str()), ("1", "-"));
    assert!(fx.w_lines().is_empty(), "{:?}", fx.w_lines());
    assert!(
        std::fs::read_dir(&witness).unwrap().flatten().any(|e| e
            .file_name()
            .to_string_lossy()
            .starts_with("send-ledger.unreadable.")),
        "the damaged copy is kept aside"
    );
}

/// A post made without the lock is claimed in the spool file first: while it is in flight the
/// file's last field reads `sending`, so a light pass that takes the file in meanwhile charges a
/// send that may have gone, and so does a child stopped mid-post, whose file keeps `sending`.
#[test]
fn a_send_made_without_the_lock_is_claimed_in_the_spool_while_it_is_posted() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let spool = fx.root.join("var/lib/propolis/witness/hook").join(BACKUP);
    let copy = fx._dir.path().join("spool-during-post");
    let during = format!("cp -- '{}' '{}'", spool.display(), copy.display());
    let lock = hold_lock(&fx.state_lock());
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_DURING", &during)])));
    drop(lock);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let text = std::fs::read_to_string(&copy).unwrap();
    let h: Vec<&str> = text.lines().nth(1).unwrap().split('\t').collect();
    assert_eq!(h.len(), 10, "{text}");
    assert_eq!(h[9], "sending", "{text}");
    assert_eq!(fx.spool(BACKUP)[9], "ok");

    let fx = Fixture::v2();
    write_exec(&fx.bin.join("curl"), KILLING_CURL);
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let lock = hold_lock(&fx.state_lock());
    let out = fx.run_in_own_group(BACKUP, &V2);
    drop(lock);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(fx.spool(BACKUP)[9], "sending");
}

/// An open delivered under the lock sets today's stamp for the unit, so a later firing that finds
/// the lock busy honours its cooldown: it spools and sends no second open.
#[test]
fn a_firing_that_finds_the_lock_busy_honours_the_cooldown_of_an_open_delivered_under_it() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(fx.record(BACKUP)[17], "1");
    let lock = hold_lock(&fx.state_lock());
    assert_ok(&fx.run(BACKUP, &V2));
    drop(lock);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let h = fx.spool(BACKUP);
    assert_eq!((h[3].as_str(), h[9].as_str()), ("1", "-"), "{h:?}");
}

/// A change of cause class while the incident's open or reopen is still pending (claimed, its
/// post not yet through) is only recorded. Admitted as a change it would replace the pending
/// transition and the open would never be delivered; sent as that open it could go out beside a
/// post still in flight and would be counted twice. The pending transition stays as it was for
/// the retry, which renders the record as it then is, with the new cause.
#[test]
fn a_class_change_while_the_open_is_still_pending_is_recorded_and_left_to_the_retry() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_POST_CODE", "503")])));
    let before = fx.record(BACKUP);
    assert_eq!((before[26].as_str(), before[17].as_str()), ("open", "0"));
    let ledger = fx.state("send-ledger");
    fx.edit_record(BACKUP, &[(11, "guard.no_space")]);
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(fx.state("send-ledger"), ledger);
    assert!(fx.w_lines().is_empty(), "{:?}", fx.w_lines());
    let f = fx.record(BACKUP);
    assert_eq!(
        (
            f[26].as_str(),
            f[27].as_str(),
            f[17].as_str(),
            f[11].as_str()
        ),
        ("open", before[27].as_str(), "0", "proc.exit:1")
    );
    // The same for a reopen still pending on an incident whose first open was delivered.
    fx.edit_record(BACKUP, &[(11, "guard.no_space"), (17, "1"), (26, "reopen")]);
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(fx.state("send-ledger"), ledger);
    let f = fx.record(BACKUP);
    assert_eq!((f[26].as_str(), f[11].as_str()), ("reopen", "proc.exit:1"));
}

/// Without the lock, a post that did not get through holds the next one for the retry time
/// (PROPOLIS_ALERT_RETRY_SECS, 120 s), as today's hook does, so a crash loop cannot post on every
/// firing while the lock stays busy; once that time has passed the next firing posts.
#[test]
fn without_the_lock_a_post_that_did_not_get_through_holds_the_next_for_the_retry_time() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let lock = hold_lock(&fx.state_lock());
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_POST_CODE", "503")])));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_POST_CODE", "503")])));
    assert_eq!(fx.tp_posts(), 1, "within the retry time: {}", fx.log());
    assert_eq!(mode_of(&fx.tried_stamp(BACKUP)), 0o600);
    age_by(&fx.tried_stamp(BACKUP), 121);
    assert_ok(&fx.run(BACKUP, &V2));
    drop(lock);
    assert_eq!(fx.tp_posts(), 2, "past the retry time: {}", fx.log());
    let h = fx.spool(BACKUP);
    assert_eq!((h[3].as_str(), h[9].as_str()), ("3", "ok"), "{h:?}");
}

/// In journal mode a post that did not get through logs a second line after its claim; the pair
/// stops holding the next firing once the retry time (120 s) has passed since the claim, and
/// holds it before that.
#[test]
fn in_journal_mode_a_send_that_failed_stops_holding_the_next_after_the_retry_time() {
    let fx = Fixture::v2();
    fx.nothing_writable();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_POST_CODE", "503")])));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert!(
        fx.log().contains(
            "systemd-cat -t propolis-witness -p notice hook send failed 1000000/abcdef01/5000"
        ),
        "{}",
        fx.log()
    );
    let journal = fx._dir.path().join("hook-journal");
    for (stamp, posts) in [("999800/abcdef01/4800", 2), ("999950/abcdef01/4950", 2)] {
        std::fs::write(
            &journal,
            format!("hook sent - {stamp}\nhook send failed {stamp}\n"),
        )
        .unwrap();
        assert_ok(&fx.run(
            BACKUP,
            &v2_env(&[
                ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
                (
                    "STUB_RUN_MATCH",
                    "_SYSTEMD_UNIT=propolis-alert@propolis-backup.service.service",
                ),
            ]),
        ));
        assert_eq!(fx.tp_posts(), posts, "{stamp}: {}", fx.log());
    }
}

/// Without the lock nothing is sent under a maintenance marker or with a gate other than full,
/// and the firing is still spooled.
#[test]
fn without_the_lock_nothing_is_sent_under_maintenance_or_with_a_gate_other_than_full() {
    for case in ["maintenance", "gate"] {
        let fx = Fixture::v2();
        if case == "maintenance" {
            std::fs::write(
                fx.root.join("run/propolis-witness/maintenance"),
                "#maintenance v1 g=1\nX\t1000600\tabcdef01\tmanual\n",
            )
            .unwrap();
        } else {
            std::fs::remove_file(fx.root.join("var/lib/propolis/witness/readcheck")).unwrap();
        }
        fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
        let lock = hold_lock(&fx.state_lock());
        assert_ok(&fx.run(BACKUP, &V2));
        drop(lock);
        assert!(!fx.log().contains("curl "), "{case}: {}", fx.log());
        let h = fx.spool(BACKUP);
        assert_eq!((h[3].as_str(), h[9].as_str()), ("1", "-"), "{case}: {h:?}");
    }
}

/// The result of a post is written under the lock; when another writer holds it past the hook's
/// 10 s wait, the ledger line stays pending and the record keeps its pending transition for a
/// retry, and one line says so.
#[test]
fn a_result_that_finds_the_lock_busy_leaves_the_transition_pending_and_says_so() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let lock = fx.state_lock();
    let out = fx.run(
        BACKUP,
        &v2_env(&[("STUB_HOLD_LOCK", lock.to_str().unwrap())]),
    );
    fx.release_holder();
    assert_ok(&out);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let ledger = fx.ledger();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(ledger[0][6], "pending");
    let f = fx.record(BACKUP);
    assert_eq!((f[26].as_str(), f[17].as_str()), ("open", "0"));
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("was not recorded: the state lock was busy"),
        "{}",
        lines[0]
    );
}

/// Only an open, a reopen or a reminder that got through marks the incident delivered (the
/// record's field 17), by the one rule the hook and the witness write a result by: a change sent on a
/// record whose open never got through leaves it undelivered, and a reopen of a resolved record
/// inside its reopen window, sent as `(again)`, marks it delivered.
#[test]
fn delivered_open_is_set_only_by_an_open_a_reopen_or_a_reminder_that_got_through() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_POST_CODE", "403")])));
    let f = fx.record(BACKUP);
    assert_eq!((f[26].as_str(), f[17].as_str()), ("-", "0"));
    fx.edit_record(BACKUP, &[(11, "guard.no_space")]);
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 2, "{}", fx.log());
    assert!(
        fx.v2_titles()[1].ends_with(" (changed)"),
        "{:?}",
        fx.v2_titles()
    );
    let f = fx.record(BACKUP);
    assert_eq!((f[17].as_str(), f[26].as_str()), ("0", "-"));

    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &V2));
    fx.edit_record(
        BACKUP,
        &[
            (7, "resolved"),
            (9, "999000/abcdef01/4000"),
            (16, "resolve"),
            (17, "0"),
            (21, "999900/abcdef01/4900"),
            (22, "nextrun"),
        ],
    );
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 2, "{}", fx.log());
    assert!(
        fx.v2_titles()[1].ends_with(" (again)"),
        "{:?}",
        fx.v2_titles()
    );
    let f = fx.record(BACKUP);
    assert_eq!(
        (f[7].as_str(), f[17].as_str(), f[26].as_str()),
        ("open", "1", "-")
    );
}

/// A result whose record no longer has this transition pending (another writer changed it while
/// the post was in flight) reaches only its ledger line; the record keeps what it has.
#[test]
fn a_result_for_a_transition_no_longer_pending_reaches_only_its_ledger_line() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let incidents = fx.root.join("var/lib/propolis/witness/incidents");
    let during = format!(
        "f='{}'; awk -F'\\t' -v OFS='\\t' '$1==\"I\" {{ $28=\"999999/abcdef01/4999\" }} 1' \"$f\" > \"$f.new\" && mv -f \"$f.new\" \"$f\"",
        incidents.display()
    );
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_DURING", &during)])));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let ledger = fx.ledger();
    assert_eq!(ledger[0][6], "ok", "{ledger:?}");
    let f = fx.record(BACKUP);
    assert_eq!(
        (f[26].as_str(), f[27].as_str(), f[17].as_str()),
        ("open", "999999/abcdef01/4999", "0")
    );
}

/// A firing of a lower tier on an open record only counts: a routine rotation skip (NOTICE) after
/// a refused rotation (ACT) leaves the record unit-failed at ACT with its cause, sends nothing and
/// raises occ.
#[test]
fn a_lower_tier_firing_on_an_open_record_only_counts() {
    let fx = Fixture::v2();
    let unit = "propolis-logrotate.service";
    fx.show(unit, &show_answer("exit-code", "1", "no", "0"));
    let journal = fx._dir.path().join("run-journal");
    let fire = |lines: &str| {
        std::fs::write(&journal, lines).unwrap();
        assert_ok(&fx.run(
            unit,
            &v2_env(&[
                ("STUB_RUN_JOURNAL", journal.to_str().unwrap()),
                ("STUB_RUN_MATCH", TRUSTED_ROTATION),
            ]),
        ));
        fx.record(unit)
    };
    let f = fire(GUARD_REFUSAL);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str(), f[7].as_str()),
        ("unit-failed", "ACT", "guard.no_space", "open")
    );
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let f = fire(GUARD_SKIP);
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str(), f[31].as_str()),
        ("unit-failed", "ACT", "guard.no_space", "2")
    );
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
}

/// A light pass whose last completion is dated ahead of the clock cannot be aged, so whether it
/// is stale is decided by uptime: within the first half hour it is not (the first sighting stays
/// pending), after it it is (the failure opens). An uptime that is not a count opens at once.
#[test]
fn a_light_pass_dated_ahead_is_judged_by_uptime_and_an_uptime_not_a_count_opens() {
    let unit = "sensor-ssh.service";
    let answer = show_answer("exit-code", "1", "always", "2");
    for (up, state) in [("1000", "pending"), ("5000", "open")] {
        let fx = Fixture::v2();
        std::fs::write(
            fx.root.join("var/lib/propolis/witness/meta"),
            "#meta v1 g=1\nM\tlight_last\t1000100/abcdef01/5100\n",
        )
        .unwrap();
        fx.show(unit, &answer);
        assert_ok(&fx.run(unit, &v2_env(&[("PA_TEST_UP", up)])));
        assert_eq!(fx.record(unit)[7], state, "uptime {up}");
    }
    let fx = Fixture::v2();
    std::fs::remove_file(fx.root.join("var/lib/propolis/witness/meta")).unwrap();
    fx.show(unit, &answer);
    assert_ok(&fx.run(
        unit,
        &v2_env(&[("PA_TEST_BOOT", "12345678"), ("PA_TEST_UP", "x")]),
    ));
    assert_eq!(fx.record(unit)[7], "open");
}

/// Without the lock, today's stamp is read as today's hook reads it: one dated ahead of the clock
/// has expired, and a cooldown setting that is not a number is the default 1800 s, so a stamp
/// 1000 s old still holds the send.
#[test]
fn without_the_lock_a_stamp_dated_ahead_allows_the_send_and_a_mistyped_cooldown_is_the_default() {
    for (cooldown, posts) in [("", 1), ("abc", 0)] {
        let fx = Fixture::v2();
        fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
        let stamp = fx.delivered_stamp(BACKUP);
        std::fs::create_dir_all(stamp.parent().unwrap()).unwrap();
        std::fs::write(&stamp, b"").unwrap();
        if cooldown.is_empty() {
            date_in_the_future(&stamp);
        } else {
            age_by(&stamp, 1000);
        }
        let lock = hold_lock(&fx.state_lock());
        let mut env = V2.to_vec();
        if !cooldown.is_empty() {
            env.push(("PROPOLIS_ALERT_COOLDOWN_SECS", cooldown));
        }
        assert_ok(&fx.run(BACKUP, &env));
        drop(lock);
        assert_eq!(fx.tp_posts(), posts, "{cooldown:?}: {}", fx.log());
    }
}

/// Without the lock, a post that got through but whose stamp cannot be set says so in one line,
/// since the next failure sends again; a missing stamp directory is made 0700, the stamp 0600.
#[test]
fn without_the_lock_a_stamp_that_cannot_be_set_is_said_and_a_missing_directory_is_made() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    std::fs::create_dir_all(fx.root.join("run")).unwrap();
    std::fs::write(fx.root.join("run/propolis-alert"), "not a directory").unwrap();
    let lock = hold_lock(&fx.state_lock());
    assert_ok(&fx.run(BACKUP, &V2));
    drop(lock);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(
        lines[0].contains("its stamp could not be set"),
        "{}",
        lines[0]
    );

    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert!(!fx.root.join("run/propolis-alert").exists());
    let lock = hold_lock(&fx.state_lock());
    assert_ok(&fx.run(BACKUP, &V2));
    drop(lock);
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(mode_of(&fx.root.join("run/propolis-alert")), 0o700);
    assert_eq!(mode_of(&fx.delivered_stamp(BACKUP)), 0o600);
    assert!(witness_lines(&fx.log()).is_empty(), "{}", fx.log());
}

/// In journal mode a claim that cannot be logged sends nothing while the journal can be asked,
/// since nothing would then bound the next send; when it cannot be asked either, the daemon's
/// failure is still sent.
#[test]
fn in_journal_mode_a_claim_that_cannot_be_logged_sends_only_for_the_daemon_with_no_journal() {
    let fx = Fixture::v2();
    fx.nothing_writable();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    fx.show(
        "propolis.service",
        &show_answer("exit-code", "1", "always", "0"),
    );
    assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_CAT_FAIL", "1")])));
    assert_ok(&fx.run("propolis.service", &v2_env(&[("STUB_CAT_FAIL", "1")])));
    assert_eq!(fx.tp_posts(), 0, "{}", fx.log());
    assert_ok(&fx.run(
        "propolis.service",
        &v2_env(&[("STUB_CAT_FAIL", "1"), ("STUB_JOURNAL_FAIL", "1")]),
    ));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
}

/// The v2 path posts only with its marker in place: with the marker not made, or made and then
/// gone, _pa_hv2_post does not call pa_send and reports norender.
#[test]
fn the_v2_post_is_made_only_with_the_marker_in_place() {
    for (case, want, sent) in [
        ("", "0 ok", true),
        ("unmarked", "1 norender", false),
        ("removed", "1 norender", false),
    ] {
        let fx = Fixture::v2();
        fx.install_lib(&format!(
            "{}\npa_send() {{\n    : > \"$STUB_LOG.sent\"\n    PA_SEND_RESULT=ok\n}}\n\
             pa_hook_v2() {{\n    _pa_hv2_mark || return 1\n    case \"${{STUB_CASE:-}}\" in\n        \
             unmarked) _PA_HV2_MARKED=0 ;;\n        removed) rm -f -- \"$PA_HOOK_MARKER\" ;;\n    esac\n    \
             _pa_hv2_post T 3 B\n    printf '%s %s\\n' \"$?\" \"$PA_SEND_RESULT\" > \"$STUB_LOG.result\"\n    \
             : > \"$PA_HOOK_MARKER\"\n    return 0\n}}\n",
            shipped_lib()
        ));
        assert_ok(&fx.run(BACKUP, &v2_env(&[("STUB_CASE", case)])));
        let result =
            std::fs::read_to_string(format!("{}.result", fx.log.display())).unwrap_or_default();
        assert_eq!(result.trim(), want, "{case:?}");
        assert_eq!(
            Path::new(&format!("{}.sent", fx.log.display())).exists(),
            sent,
            "{case:?}"
        );
    }
}

/// After a v2 send, meta says where the state went: `persistent`, or `run` when the persistent
/// directory refused it.
#[test]
fn meta_says_where_the_v2_hook_wrote_its_state() {
    let fx = Fixture::v2();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let meta = fx.state("meta");
    assert!(meta.lines().any(|l| l == "M\twhere\tpersistent"), "{meta}");

    let fx = Fixture::v2();
    fx.v2_state("run/propolis-witness/fallback");
    // The salt that names the host is kept only on the persistent disk, so the alias is set.
    std::fs::write(
        fx.root.join("etc/propolis/propolis.env"),
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example/\nPROPOLIS_OPS_NTFY_TOPIC=propolis-ops\nPROPOLIS_OPS_HOST_ALIAS=edge-one\n",
    )
    .unwrap();
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::remove_dir_all(&witness).unwrap();
    std::fs::write(&witness, "not a directory").unwrap();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let meta = std::fs::read_to_string(fx.root.join("run/propolis-witness/fallback/meta")).unwrap();
    assert!(meta.lines().any(|l| l == "M\twhere\trun"), "{meta}");
}

/// A failure no record can hold is still sent: a unit name too long for a record key goes to
/// today's code, and a new unit past the 512 open records gets the message without an id,
/// stamp-gated as the lockless path's, and its firing is spooled.
#[test]
fn a_failure_no_record_can_hold_is_still_sent() {
    let long = format!("sensor-{}.service", "a".repeat(130 - 15));
    assert_eq!(long.len(), 130);
    let fx = Fixture::v2();
    fx.log_children();
    fx.show(&long, &show_answer("exit-code", "1", "always", "2"));
    assert_ok(&fx.run(&long, &V2));
    assert!(
        fx.log()
            .contains(&format!("Title: propolis: {long} failed on honeybox")),
        "{}",
        fx.log()
    );
    assert!(!fx.children().contains("pa_hook_v2"), "{}", fx.children());

    let fx = Fixture::v2();
    let mut text = "#incidents v1 g=1\nN\t513\n".to_string();
    for i in 1..=512 {
        text += &format!(
            "I\tw#{i}\tunit:x{i}.service\tunit-failed\tbackup\t-\tACT\topen{}\n",
            "\t-".repeat(27)
        );
    }
    let path = fx.root.join("var/lib/propolis/witness/incidents");
    std::fs::write(&path, &text).unwrap();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    assert_ok(&fx.run(BACKUP, &V2));
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    let body = fx.v2_body(0);
    assert!(
        body.lines()
            .last()
            .unwrap()
            .starts_with("(id pending) opened"),
        "{body}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(fx.spool(BACKUP)[9], "ok");
    assert!(!fx.log().contains("curl -fsS"), "{}", fx.log());
}

/// The role is asked with a bounded wait: a systemctl that hangs on `is-enabled` costs seconds,
/// not the v2 child's whole limit, and the failure is still recorded and sent.
#[test]
fn a_hung_systemctl_is_enabled_does_not_use_up_the_v2_child_s_time() {
    let fx = Fixture::v2();
    write_exec(
        &fx.bin.join("systemctl"),
        &format!(
            "#!/usr/bin/env bash\n[ \"$1\" != is-enabled ] || exec sleep 30\n{}",
            SYSTEMCTL_STUB.trim_start_matches("#!/usr/bin/env bash\n")
        ),
    );
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let started = std::time::Instant::now();
    assert_ok(&fx.run(BACKUP, &V2));
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(25),
        "the hook took {took:?}"
    );
    assert_eq!(fx.tp_posts(), 1, "{}", fx.log());
    assert_eq!(fx.record(BACKUP)[7], "open");
}

/// The record step's handler is set before the decision, so a hook stopped by a signal while the
/// decision hangs (the unit stopped, the host shutting down) still records the failure.
#[test]
fn a_hook_stopped_during_a_hung_decision_still_records_the_failure() {
    let fx = Fixture::with_ntfy();
    fx.install_lib(&format!(
        "{}\npa_hook_profile() {{\n    local s up\n    s=\"$(cat \"/proc/$PPID/stat\")\"\n    s=\"${{s##*) }}\"\n    read -r _ up _ <<< \"$s\"\n    sleep 1\n    kill -TERM -- \"-$up\" 0\n    sleep 300\n}}\n",
        shipped_lib()
    ));
    fx.show(
        "sensor-ssh.service",
        &show_answer("exit-code", "1", "always", "2"),
    );
    let started = std::time::Instant::now();
    let _ = fx.run_in_own_group("sensor-ssh.service", &V2);
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    assert!(!fx.log().contains("curl "), "{}", fx.log());
    let f = fx.record("sensor-ssh.service");
    assert_eq!((f[7].as_str(), f[33].as_str()), ("pending", "-"));
}

/// The marker is made before any state file is read under the lock: a v2 child whose marker
/// cannot be made changes nothing, not even by setting aside a damaged incidents file, before it
/// leaves the failure to the hook.
#[test]
fn a_v2_child_whose_marker_cannot_be_made_sets_no_damaged_file_aside() {
    let fx = Fixture::v2();
    fx.log_children();
    let witness = fx.root.join("var/lib/propolis/witness");
    std::fs::write(witness.join("incidents"), "garbage\n").unwrap();
    fx.show(BACKUP, &show_answer("exit-code", "1", "no", "0"));
    let out = fx.run(
        BACKUP,
        &v2_env(&[
            ("STUB_BAD_MARKER", "/nonexistent/propolis-test/marker"),
            ("SECONDS", "25"),
        ]),
    );
    assert_ok(&out);
    assert!(fx.children().contains("pa_hook_v2"), "{}", fx.children());
    assert_eq!(
        std::fs::read_to_string(witness.join("incidents")).unwrap(),
        "garbage\n"
    );
    let aside: Vec<String> = std::fs::read_dir(&witness)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".unreadable."))
        .collect();
    assert!(aside.is_empty(), "{aside:?}");
    let lines = witness_lines(&fx.log());
    assert_eq!(lines.len(), 1, "{}", fx.log());
    assert!(lines[0].contains("not sent"), "{}", lines[0]);
}

/// The paths reference names the v2 hook as a writer of meta and incidents, the claim word of
/// the spool's last field, and the stamp of its lockless attempts.
#[test]
fn the_paths_reference_names_what_the_v2_hook_writes() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/reference/filesystem-paths.md"
    ))
    .unwrap();
    let row = |path: &str| -> String {
        doc.lines()
            .find(|l| l.starts_with(&format!("| `{path}`")))
            .unwrap_or_else(|| panic!("no row for {path}"))
            .to_string()
    };
    for path in [
        "/var/lib/propolis/witness/meta",
        "/var/lib/propolis/witness/incidents",
    ] {
        let writers = row(path).rsplit('|').nth(1).unwrap().to_string();
        assert!(
            writers.contains("`deploy/alert-lib.sh#pa_hook_v2`"),
            "{path}: {writers}"
        );
    }
    assert!(
        row("/var/lib/propolis/witness/hook/<unit>").contains("`sending`"),
        "the spool's claim word"
    );
    assert!(
        row("/run/propolis-alert/v2-tried/<unit>").contains("deploy/alert-lib.sh#_pa_hv2_lockless")
    );
}
