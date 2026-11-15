//! Runs `deploy/witness.sh light` (the witness's light pass) under a scratch root with
//! `PROPOLIS_ALERT_ROOT` and a fixed `PROPOLIS_WITNESS_NOW`, with stub `systemctl`, `journalctl`,
//! `logger`, `curl` and `setpriv` on `PATH`, the real `flock`, and the shipped alert library
//! installed under the root. Each pass is given the time it runs at, so the light passes of a
//! case are five minutes apart in the library's clock however fast the test runs.
//!
//! The `systemctl` stub answers `show` for each unit from a file of `key=value` lines and
//! `is-enabled` from the same file; a unit without a file is one systemd does not know.

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/witness.sh");
const LIB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert-lib.sh");
const INSTALL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/install.sh");

/// The wall clock and uptime of the first pass of every case (boot `abcdef01`).
const WALL: u64 = 1_800_000_000;
const UP: u64 = 900_000;
const BOOT: &str = "abcdef01";
const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

/// Records its argv. `show` prints one block per unit asked about, from `$UNITS/<unit>`, with a
/// blank line between blocks; `is-enabled` succeeds for a unit whose file says it is enabled.
/// `SYSTEMCTL_FAIL` makes every call fail.
const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$STUB_LOG"
[ -z "${SYSTEMCTL_FAIL:-}" ] || exit 1
[ -z "${SYSTEMCTL_SLEEP:-}" ] || [ "$1" != show ] || sleep "$SYSTEMCTL_SLEEP"
case "$1" in
    is-enabled)
        f="$UNITS/${!#}"
        [ -f "$f" ] && grep -qx 'UnitFileState=enabled' "$f"
        exit
        ;;
    show)
        while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
        shift
        first=1
        for u in "$@"; do
            [ "$first" = 1 ] || echo
            first=0
            echo "Id=$u"
            if [ -f "$UNITS/$u" ]; then cat "$UNITS/$u"; else printf 'LoadState=not-found\nActiveState=inactive\n'; fi
        done
        ;;
    *) exit 1 ;;
esac
"#;

/// Records its argv and prints `$JOURNAL_FILE` when it is set. With `LOCK_PROBE` set to the lock
/// file it also records whether the state lock was free while it ran.
const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'journalctl %s\n' "$*" >> "$STUB_LOG"
if [ -n "${LOCK_PROBE:-}" ]; then
    if flock -n "$LOCK_PROBE" true; then echo 'journalctl lock free' >> "$STUB_LOG"; else echo 'journalctl lock held' >> "$STUB_LOG"; fi
fi
[ -z "${JOURNAL_FILE:-}" ] || cat "$JOURNAL_FILE"
"#;

/// The real `head`, and once, right after it has read `$RACE_SPOOL` (or the copy a pass claimed
/// under another name in the same directory), what the failure hook does when it spools without
/// the lock: it rewrites that path with the count raised, or starts it at 1 when it is gone.
const HEAD_RACE_STUB: &str = r#"#!/usr/bin/env bash
/usr/bin/head "$@"
rc=$?
f="${!#}"
base="${f##*/}"
if [[ $base =~ ^\.ingest\.[0-9]+\.(.+)$ ]]; then base="${BASH_REMATCH[1]}"; fi
if [ -n "${RACE_SPOOL:-}" ] && [ ! -e "$RACE_MARK" ] && [ "${f%/*}/$base" = "$RACE_SPOOL" ]; then
    : > "$RACE_MARK"
    count=1
    if [ -f "$RACE_SPOOL" ]; then
        IFS=$'\t' read -r _ _ _ n _ < <(/usr/bin/head -n 2 "$RACE_SPOOL" | /usr/bin/tail -n 1)
        count=$((n + 1))
    fi
    printf '#hook v1 g=9\nH\t%s\t%s\t%s\texit-code\texited\t1\tproc.exit:1\t0\tundelivered\n' \
        "$RACE_FIRST" "$RACE_FIRST" "$count" > "$RACE_SPOOL.tmp.1"
    mv -f "$RACE_SPOOL.tmp.1" "$RACE_SPOOL"
fi
exit "$rc"
"#;

const LOGGER_STUB: &str = r#"#!/usr/bin/env bash
printf 'logger %s\n' "$*" >> "$STUB_LOG"
"#;

/// The witness of this release pushes nothing: any call is recorded and fails.
const CURL_STUB: &str = r#"#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$STUB_LOG"
exit 7
"#;

const SETPRIV_STUB: &str = r#"#!/usr/bin/env bash
printf 'setpriv %s\n' "$*" >> "$STUB_LOG"
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
exec "$@"
"#;

fn write_exec(path: &Path, body: &str) {
    let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The stamp of time `t` (seconds after the first pass) in this boot.
fn stamp(t: u64) -> String {
    format!("{}/{BOOT}/{}", WALL + t, UP + t)
}

/// `ActiveEnterTimestampMonotonic` of a unit that, at time `t`, has been active for `secs`.
fn entered(t: u64, secs: u64) -> String {
    ((UP + t - secs) * 1_000_000).to_string()
}

/// The stamp of time `t` in a boot whose first pass runs at 600 s of uptime, just past the grace.
fn early(t: u64) -> String {
    format!("{}/{BOOT}/{}", WALL + t, 600 + t)
}

/// `record` (an `incidents` line) with field `i` (numbered as `Fx::record` numbers them) set to
/// `v`.
fn with_field(record: &str, i: usize, v: &str) -> String {
    let mut f: Vec<String> = record
        .trim_end_matches('\n')
        .split('\t')
        .map(str::to_string)
        .collect();
    f[i] = v.to_string();
    format!("{}\n", f.join("\t"))
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

struct Fx {
    dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
    env: Vec<(String, String)>,
}

impl Fx {
    /// A single box: the daemon and two sensors running, the oneshots idle after a good run,
    /// every timer enabled, a push target set, the library installed and the state directories
    /// as provisioning leaves them.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let bin = dir.path().join("bin");
        for (name, body) in [
            ("systemctl", SYSTEMCTL_STUB),
            ("journalctl", JOURNALCTL_STUB),
            ("logger", LOGGER_STUB),
            ("curl", CURL_STUB),
            ("setpriv", SETPRIV_STUB),
        ] {
            write_exec(&bin.join(name), body);
        }
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        std::fs::create_dir_all(dir.path().join("units")).unwrap();
        let fx = Fx {
            dir,
            root,
            bin,
            log,
            env: Vec::new(),
        };
        for d in [
            "usr/local/sbin",
            "etc/propolis",
            "var/lib/propolis/witness",
            "run/propolis-witness",
            "run/motd.d",
        ] {
            std::fs::create_dir_all(fx.p(d)).unwrap();
        }
        for d in ["", "usr", "usr/local", "usr/local/sbin"] {
            std::fs::set_permissions(fx.p(d), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::copy(LIB, fx.p("usr/local/sbin/propolis-alert-lib")).unwrap();
        std::fs::set_permissions(
            fx.p("usr/local/sbin/propolis-alert-lib"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fx.write("var/lib/propolis/witness/state.lock", "");
        std::fs::set_permissions(
            fx.p("var/lib/propolis/witness/state.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fx.write(
            "etc/propolis/propolis.env",
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n",
        );
        fx.unit("propolis.service", &[("Restart", "on-failure")]);
        fx.unit("sensor-ssh.service", &[]);
        fx.unit("sensor-http.service", &[]);
        for oneshot in ["propolis-backup.service", "propolis-logrotate.service"] {
            fx.unit(
                oneshot,
                &[
                    ("ActiveState", "inactive"),
                    ("SubState", "dead"),
                    ("Restart", "no"),
                    ("UnitFileState", "static"),
                ],
            );
        }
        fx.unit(
            "propolis-witness@light.service",
            &[
                ("ActiveState", "activating"),
                ("SubState", "start"),
                ("Restart", "no"),
                ("UnitFileState", "static"),
            ],
        );
        for timer in [
            "propolis-backup.timer",
            "propolis-logrotate.timer",
            "propolis-witness@light.timer",
        ] {
            fx.unit(timer, &[("SubState", "waiting")]);
        }
        fx
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.p(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.p(rel)).unwrap_or_default()
    }

    fn setenv(&mut self, k: &str, v: &str) {
        self.env.retain(|(name, _)| name != k);
        self.env.push((k.to_string(), v.to_string()));
    }

    /// What `systemctl show` says about `name`: a running, enabled unit that restarts itself and
    /// entered the active state a day before the first pass, with these properties changed.
    fn unit(&self, name: &str, changes: &[(&str, &str)]) {
        let day_before = entered(0, 86_400);
        let mut props: Vec<(String, String)> = [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("NRestarts", "0"),
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "0"),
            ("ActiveEnterTimestampMonotonic", day_before.as_str()),
            ("InactiveEnterTimestampMonotonic", "0"),
            ("UnitFileState", "enabled"),
            ("InvocationID", INVOCATION),
            ("Restart", "always"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in changes {
            match props.iter_mut().find(|(name, _)| name == k) {
                Some(p) => p.1 = v.to_string(),
                None => props.push((k.to_string(), v.to_string())),
            }
        }
        let text: String = props.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        std::fs::write(self.dir.path().join("units").join(name), text).unwrap();
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }

    fn run_args(&self, args: &[&str], t: u64) -> Run {
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        // Started under the umask a case asks for (WITNESS_UMASK), as systemd or a shell might.
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg("umask \"${WITNESS_UMASK:-022}\"; exec \"$0\" \"$@\"")
            .arg(SCRIPT)
            .args(args)
            .env("PATH", path)
            .env("PROPOLIS_ALERT_ROOT", &self.root)
            .env("PROPOLIS_WITNESS_NOW", stamp(t))
            .env("PA_TEST_READ_AS_SELF", "1")
            .env("STUB_LOG", &self.log)
            .env("UNITS", self.dir.path().join("units"))
            .env_remove("PA_TEST_WALL")
            .env_remove("PA_TEST_BOOT")
            .env_remove("PA_TEST_UP")
            .env_remove("PA_TEST_UID")
            .env_remove("PA_LOCK_FD")
            .env_remove("PA_CLEANUP")
            .env_remove("PROPOLIS_WITNESS_LOCK_WAIT")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &self.env {
            command.env(k, v);
        }
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        let output = child.wait_with_output().unwrap();
        Run {
            code: output.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&output.stdout).into_owned(),
            err: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// One light pass at time `t`; every pass must exit 0.
    fn pass(&self, t: u64) -> Run {
        let r = self.run_args(&["light"], t);
        assert_eq!(r.code, 0, "pass at {t}: {}\n{}", r.out, r.err);
        r
    }

    fn records(&self) -> Vec<Vec<String>> {
        self.read("var/lib/propolis/witness/incidents")
            .lines()
            .filter(|l| l.starts_with("I\t"))
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect()
    }

    fn record(&self, key: &str) -> Option<Vec<String>> {
        self.records().into_iter().find(|f| f[2] == key)
    }

    fn meta(&self, key: &str) -> Option<String> {
        self.read("var/lib/propolis/witness/meta")
            .lines()
            .find_map(|l| l.strip_prefix(&format!("M\t{key}\t")).map(str::to_string))
    }

    /// Writes these records as the incidents file.
    fn incidents(&self, records: &[String]) {
        self.write(
            "var/lib/propolis/witness/incidents",
            &format!("#incidents v1 g=1\nN\t50\n{}", records.concat()),
        );
    }

    /// Every file under the root's alerting directories (not the lock the fixture made).
    fn state_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for d in [
            "var/lib/propolis/witness",
            "run/propolis-witness",
            "run/motd.d",
        ] {
            walk(&self.p(d), &mut out);
        }
        out.retain(|p| !p.ends_with("var/lib/propolis/witness/state.lock"));
        out
    }

    /// Writes these lines as the observe file.
    fn observe(&self, lines: &str) {
        self.write(
            "var/lib/propolis/witness/observe",
            &format!("#observe v1 g=1\n{lines}"),
        );
    }

    /// One firing of the failure hook's record step for `unit` at time `t`, by the installed
    /// library, as deploy/alert.sh runs it after today's alert went out: it reads the unit from
    /// the same `systemctl` stub the pass reads.
    fn hook_fires(&self, unit: &str, t: u64) {
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(". \"$1\" && pa_init \"$2\" && pa_hook_record")
            .arg("_")
            .arg(self.p("usr/local/sbin/propolis-alert-lib"))
            .arg(&self.root)
            .env("PATH", path)
            .env("STUB_LOG", &self.log)
            .env("UNITS", self.dir.path().join("units"))
            .env("PA_TEST_WALL", (WALL + t).to_string())
            .env("PA_TEST_BOOT", BOOT)
            .env("PA_TEST_UP", (UP + t).to_string())
            .env("PA_HOOK_UNIT", unit)
            .env("PA_HOOK_OUT", "delivered")
            .env("PA_HOOK_T0", "0")
            .env_remove("PA_LOCK_FD")
            .env_remove("PA_CLEANUP")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Takes the state lock in a child process and returns once it holds it.
    fn hold_lock(&self) -> Child {
        let mut child = Command::new("bash")
            .arg("-c")
            .arg("exec 9< \"$1\"; flock 9; echo held; exec sleep 60")
            .arg("_")
            .arg(self.p("var/lib/propolis/witness/state.lock"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "held\n");
        child
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// An `incidents` record of 34 fields as the failure hook writes it, first seen at `t`.
fn hook_record(id: &str, unit: &str, tier: &str, state: &str, t: u64, nr_seen: &str) -> String {
    hook_record_at(id, unit, tier, state, &stamp(t), nr_seen)
}

/// `hook_record` first seen at stamp `s`.
fn hook_record_at(id: &str, unit: &str, tier: &str, state: &str, s: &str, nr_seen: &str) -> String {
    let s = s.to_string();
    let opened = if state == "open" {
        s.clone()
    } else {
        "-".into()
    };
    let stage = match unit {
        "propolis-backup.service" => "backup",
        "propolis-logrotate.service" => "source",
        "shipper.service" => "ship",
        "propolis.service" => "intake",
        _ => "listen",
    };
    let kind = if unit == "propolis.service" {
        "daemon-down"
    } else {
        "unit-failed"
    };
    let pushed = if state == "open" { "1" } else { "0" };
    let f: Vec<String> = [
        id,
        &format!("unit:{unit}"),
        kind,
        stage,
        "-",
        tier,
        state,
        &s,
        &opened,
        &s,
        "proc.exit:1",
        &s,
        "-",
        "0",
        "-",
        "-",
        "0",
        "0",
        "-",
        "-",
        "-",
        "-",
        "0",
        "-",
        "-",
        "-",
        "-",
        "-",
        pushed,
        "-",
        "1",
        nr_seen,
        "delivered",
        "-",
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(f.len(), 34);
    format!("I\t{}\n", f.join("\t"))
}

/// A crash loop is a count, not a state: three restarts or more between two light passes
/// (NRestarts from systemctl show), on two passes in a row, open one incident on the unit's key
/// with the unit map's stage and tier. One such pass opens nothing.
#[test]
fn a_crash_loop_opens_after_two_fast_passes_and_not_after_one() {
    let fx = Fx::new();
    fx.pass(0);
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "4"),
            ("ActiveEnterTimestampMonotonic", &entered(300, 20)),
        ],
    );
    fx.pass(300);
    assert!(
        fx.record("unit:sensor-ssh.service").is_none(),
        "one pass opens nothing"
    );
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "8"),
            ("ActiveEnterTimestampMonotonic", &entered(600, 20)),
        ],
    );
    fx.pass(600);
    let f = fx
        .record("unit:sensor-ssh.service")
        .unwrap_or_else(|| panic!("{}", fx.read("var/lib/propolis/witness/incidents")));
    assert_eq!(f[3], "unit-crashloop");
    assert_eq!(f[4], "listen");
    assert_eq!(f[6], "PAGE");
    assert_eq!(f[7], "open");
    assert_eq!(f[9], stamp(600), "opened");
    assert_eq!(f[16], "open");
    assert_eq!(
        f[19],
        format!("{}/{BOOT}/{}", WALL + 600 + 3600, UP + 600 + 3600)
    );
    assert_eq!(f[29], "1", "the open v2 would have pushed");
    assert!(
        f[5].starts_with('u') && f[5].len() == 6,
        "an opaque id: {}",
        f[5]
    );
    assert!(!fx.log().contains("curl"), "{}", fx.log());

    // The daemon's own loop is its reserve kind.
    let fx = Fx::new();
    fx.pass(0);
    for (t, n) in [(300, "3"), (600, "6")] {
        fx.unit(
            "propolis.service",
            &[
                ("NRestarts", n),
                ("Restart", "on-failure"),
                ("ActiveEnterTimestampMonotonic", &entered(t, 5)),
            ],
        );
        fx.pass(t);
    }
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (f[3].as_str(), f[4].as_str(), f[6].as_str()),
        ("daemon-down", "intake", "PAGE")
    );
}

/// A reboot restarts everything at once: no unit kind opens in the first ten minutes of uptime.
#[test]
fn no_unit_kind_opens_under_ten_minutes_of_uptime() {
    let mut fx = Fx::new();
    let early = |t: u64| format!("{}/{BOOT}/{}", WALL + t, 100 + t);
    for (t, n) in [(0u64, "0"), (100, "4"), (200, "8"), (300, "12")] {
        fx.setenv("PROPOLIS_WITNESS_NOW", &early(t));
        fx.unit(
            "shipper.service",
            &[
                ("NRestarts", n),
                (
                    "ActiveEnterTimestampMonotonic",
                    &((100 + t - 5) * 1_000_000).to_string(),
                ),
            ],
        );
        fx.pass(t);
    }
    assert!(fx.record("unit:shipper.service").is_none(), "uptime 400 s");
    for (t, n) in [(500u64, "16"), (600, "20")] {
        fx.setenv("PROPOLIS_WITNESS_NOW", &early(t));
        fx.unit(
            "shipper.service",
            &[
                ("NRestarts", n),
                (
                    "ActiveEnterTimestampMonotonic",
                    &((100 + t - 5) * 1_000_000).to_string(),
                ),
            ],
        );
        fx.pass(t);
    }
    assert_eq!(
        fx.record("unit:shipper.service")
            .map(|f| f[3].clone())
            .as_deref(),
        Some("unit-crashloop"),
        "past 600 s of uptime the loop opens"
    );
}

/// A manual start or restart resets NRestarts, which is not a loop.
#[test]
fn a_restart_count_that_went_down_is_a_reset_and_not_a_loop() {
    let fx = Fx::new();
    fx.unit("sensor-ssh.service", &[("NRestarts", "9")]);
    fx.pass(0);
    for (t, n) in [(300, "0"), (600, "2"), (900, "3")] {
        fx.unit("sensor-ssh.service", &[("NRestarts", n)]);
        fx.pass(t);
    }
    assert!(fx.record("unit:sensor-ssh.service").is_none());
}

/// A sensor that loops while config-check says its bind is not configured is restarting on an
/// unset bind: one ACT open with no reminders, not a crash-loop PAGE.
#[test]
fn a_sensor_looping_on_an_unset_bind_opens_one_unit_nobind_act_with_no_reminder() {
    let fx = Fx::new();
    let k12 = {
        use std::io::Write;
        let mut child = Command::new("sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"noconfig:sensor-ssh")
            .unwrap();
        String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()[..12].to_string()
    };
    let finding = hook_record("w#7", "x", "NOTICE", "open", 0, "-")
        .replace("unit:x", &format!("finding:noconfig:{k12}"));
    fx.incidents(&[finding]);
    fx.pass(0);
    for (t, n) in [(300, "4"), (600, "8")] {
        fx.unit(
            "sensor-ssh.service",
            &[
                ("NRestarts", n),
                ("ActiveEnterTimestampMonotonic", &entered(t, 5)),
            ],
        );
        fx.pass(t);
    }
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[4].as_str()),
        ("unit-nobind", "ACT", "listen")
    );
    assert_eq!(f[19], "-", "never reminded");
    assert_eq!(f[29], "1");
}

/// Retired on purpose: a unit disabled (or masked) and inactive or failed opens nothing, and an
/// incident open on it resolves with proof `disabled`.
#[test]
fn a_disabled_unit_opens_nothing_and_an_open_incident_on_it_resolves_as_disabled() {
    let fx = Fx::new();
    let failed = [
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
        ("UnitFileState", "disabled"),
    ];
    fx.unit("sensor-ssh.service", &failed);
    fx.incidents(&[hook_record(
        "w#3",
        "sensor-http.service",
        "PAGE",
        "open",
        0,
        "-",
    )]);
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("UnitFileState", "masked"),
        ],
    );
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    assert!(fx.record("unit:sensor-ssh.service").is_none());
    let f = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));
    assert_eq!(f[29], "2", "its open and its resolve");
}

/// The slow rule catches a unit that crashes every half hour on a systemd that does not run the
/// hook for automatic restarts: six restarts within six hours, on two passes in a row.
#[test]
fn the_slow_rule_opens_at_six_restarts_within_six_hours() {
    let fx = Fx::new();
    for k in 0..=6u64 {
        fx.unit("sensor-ssh.service", &[("NRestarts", &k.to_string())]);
        fx.pass(k * 300);
        assert!(
            fx.record("unit:sensor-ssh.service").is_none(),
            "after {k} restarts"
        );
    }
    fx.unit("sensor-ssh.service", &[("NRestarts", "7")]);
    fx.pass(7 * 300);
    assert_eq!(
        fx.record("unit:sensor-ssh.service")
            .map(|f| f[3].clone())
            .as_deref(),
        Some("unit-crashloop")
    );
}

/// A unit that crashes every 45 minutes is up for over half an hour between two crashes, and
/// with no incident open those quiet spells answer nothing: the slow rule still counts its
/// restarts and opens once the sixth falls within six hours of the first pass.
#[test]
fn the_slow_rule_opens_on_a_unit_that_crashes_every_forty_five_minutes() {
    let fx = Fx::new();
    let mut opened = None;
    for t in (0..=17_100u64).step_by(300) {
        let k = t / 2700;
        fx.unit(
            "sensor-ssh.service",
            &[
                ("NRestarts", &k.to_string()),
                ("ActiveEnterTimestampMonotonic", &entered(t, t - k * 2700)),
            ],
        );
        fx.pass(t);
        if let Some(f) = fx.record("unit:sensor-ssh.service") {
            assert_eq!((f[3].as_str(), f[7].as_str()), ("unit-crashloop", "open"));
            opened.get_or_insert(t);
        }
    }
    assert_eq!(
        opened,
        Some(16_500),
        "the sixth restart came at 16200 s; two passes in a row see it"
    );
}

/// A long-running unit left in the failed state opens on the second pass that sees it, with the
/// cause systemd gives.
#[test]
fn a_failed_long_running_unit_opens_after_two_passes() {
    let fx = Fx::new();
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "2"),
        ],
    );
    fx.pass(0);
    assert!(fx.record("unit:shipper.service").is_none());
    fx.pass(300);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!(
        (f[3].as_str(), f[4].as_str(), f[6].as_str(), f[11].as_str()),
        ("unit-failed", "ship", "ACT", "proc.exit:2")
    );
}

/// A oneshot stays failed until its next run, so it resolves on the next run that succeeded
/// after the failure was recorded: `nextrun`.
#[test]
fn a_failed_oneshot_resolves_on_the_next_successful_run() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#4",
        "propolis-backup.service",
        "ACT",
        "open",
        0,
        "-",
    )]);
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
            (
                "InactiveEnterTimestampMonotonic",
                &((UP - 5) * 1_000_000).to_string(),
            ),
        ],
    );
    fx.pass(300);
    assert_eq!(
        fx.record("unit:propolis-backup.service").unwrap()[7],
        "open"
    );
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Result", "success"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
            (
                "InactiveEnterTimestampMonotonic",
                &((UP + 500) * 1_000_000).to_string(),
            ),
        ],
    );
    fx.pass(600);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "nextrun"));
    assert_eq!(f[21], stamp(600));
    assert_eq!(f[29], "2");
}

/// The hook leaves a self-restarting unit's failure pending. One restart that healed shows as
/// NRestarts one above what the hook read, with the unit up for over a minute: dropped and
/// counted. Two above means it failed again: opened.
#[test]
fn a_single_healed_crash_is_dropped_and_counted_and_a_second_restart_opens() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "PAGE",
        "pending",
        0,
        "4",
    )]);
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "5"),
            ("ActiveEnterTimestampMonotonic", &entered(300, 290)),
        ],
    );
    fx.pass(300);
    assert!(
        fx.record("unit:sensor-ssh.service").is_none(),
        "{:?}",
        fx.records()
    );
    assert!(
        fx.meta("healed").is_some_and(|v| v.starts_with("1/")),
        "{}",
        fx.read("var/lib/propolis/witness/meta")
    );

    fx.incidents(&[hook_record(
        "w#2",
        "sensor-http.service",
        "PAGE",
        "pending",
        300,
        "4",
    )]);
    fx.unit(
        "sensor-http.service",
        &[
            ("NRestarts", "6"),
            ("ActiveEnterTimestampMonotonic", &entered(600, 200)),
        ],
    );
    fx.pass(600);
    let f = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!(
        (f[1].as_str(), f[7].as_str(), f[29].as_str()),
        ("w#2", "open", "1")
    );
    assert_eq!(f[33], "delivered", "what today's hook did is kept");
    assert_eq!(
        f[31], "1",
        "the hook's count of firings is kept: the open adds none"
    );

    // A record the hook raised four times, the latest undelivered, keeps both.
    let fx = Fx::new();
    let fired = with_field(
        &with_field(
            &hook_record("w#3", "sensor-http.service", "PAGE", "pending", 0, "4"),
            31,
            "4",
        ),
        33,
        "undelivered",
    );
    fx.incidents(&[fired]);
    fx.unit(
        "sensor-http.service",
        &[
            ("NRestarts", "6"),
            ("ActiveEnterTimestampMonotonic", &entered(300, 200)),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!(
        (f[7].as_str(), f[31].as_str(), f[33].as_str()),
        ("open", "4", "undelivered")
    );
}

/// A first sighting whose unit is up for under a minute on this pass only waits one pass (the
/// sample may have landed just after the one restart); under a minute on two passes opens.
#[test]
fn a_first_sighting_up_for_under_a_minute_waits_one_pass_and_opens_on_the_second() {
    let fx = Fx::new();
    fx.pass(0);
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "PAGE",
        "pending",
        100,
        "-",
    )]);
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "1"),
            ("ActiveEnterTimestampMonotonic", &entered(300, 20)),
        ],
    );
    fx.pass(300);
    assert_eq!(fx.record("unit:sensor-ssh.service").unwrap()[7], "pending");
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "2"),
            ("ActiveEnterTimestampMonotonic", &entered(600, 30)),
        ],
    );
    fx.pass(600);
    assert_eq!(fx.record("unit:sensor-ssh.service").unwrap()[7], "open");
}

/// When the lock is held past its wait the pass writes no state and sends nothing, logs one line
/// and counts the miss in `lockwait`; the next pass that gets the lock clears the count.
#[test]
fn a_held_lock_skips_the_pass_without_writing_state_and_counts_it_in_lockwait() {
    let mut fx = Fx::new();
    fx.setenv("PROPOLIS_WITNESS_LOCK_WAIT", "1");
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.write(
        "run/propolis-witness/heartbeat",
        &format!(
            "#heartbeat v1 g=4\nB\tlight\t{}\tpersistent\tok\n",
            stamp(0)
        ),
    );
    let mut holder = fx.hold_lock();
    fx.pass(0);
    fx.pass(300);
    holder.kill().unwrap();
    holder.wait().unwrap();
    for name in ["incidents", "observe", "meta", "id-salt"] {
        assert!(
            !fx.p(&format!("var/lib/propolis/witness/{name}")).exists(),
            "{name} written while the lock was held"
        );
    }
    let hb = fx.read("run/propolis-witness/heartbeat");
    assert!(
        hb.contains(&format!("B\tlight\t{}\tpersistent\tpartial\n", stamp(300))),
        "a skipped pass is partial: {hb}"
    );
    assert_eq!(fx.read("run/propolis-witness/lockwait"), "light\t2\n");
    let log = fx.log();
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with("logger") && l.contains("state lock busy for 1 s; pass skipped"))
        .collect();
    assert_eq!(lines.len(), 2, "one line a pass: {log}");
    assert!(lines[0].contains("-t propolis-witness"), "{log}");
    assert!(!log.contains("curl"), "{log}");
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("state LOCK BUSY - run: sudo propolis-status"),
        "{}",
        fx.read("run/motd.d/propolis")
    );

    fx.pass(600);
    assert!(!fx.p("run/propolis-witness/lockwait").exists(), "cleared");
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("B\tlight\t")
    );
}

/// Planned work: while a maintenance marker holds (`propolis-status --maint`), unit kinds open
/// nothing, and a first sighting stays pending, flagged `maint`.
#[test]
fn a_manual_maintenance_marker_holds_unit_kinds() {
    let fx = Fx::new();
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tmanual\n", WALL + 3600),
    );
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-http.service",
        "PAGE",
        "pending",
        0,
        "0",
    )]);
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.pass(0);
    for (t, n) in [(300, "4"), (600, "8")] {
        fx.unit(
            "sensor-ssh.service",
            &[
                ("NRestarts", n),
                ("ActiveEnterTimestampMonotonic", &entered(t, 5)),
            ],
        );
        fx.pass(t);
    }
    assert!(fx.record("unit:sensor-ssh.service").is_none());
    let f = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!(f[7], "pending");
    assert!(f[30].split(',').any(|x| x == "maint"), "{}", f[30]);
}

/// A writer killed between its temporary file and the rename leaves `NAME.tmp.<pid>`; each pass
/// removes those older than ten minutes, in both state directories, and leaves younger ones.
#[test]
fn stale_temporary_files_are_removed_and_young_ones_kept() {
    let fx = Fx::new();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let stale = [
        "var/lib/propolis/witness/incidents.tmp.12345",
        "var/lib/propolis/witness/hook/sensor-ssh.service.tmp.7",
        "run/propolis-witness/heartbeat.tmp.99",
        "run/propolis-witness/fallback/meta.tmp.4",
        // A pid above any pid_max, so no banner write of this pass shares the name.
        "run/motd.d/.propolis.tmp.999999991",
    ];
    for rel in stale {
        fx.write(rel, "x");
        std::fs::File::options()
            .write(true)
            .open(fx.p(rel))
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    fx.write("var/lib/propolis/witness/meta.tmp.31337", "x");
    fx.write("run/motd.d/.propolis.tmp.999999992", "x");
    fx.pass(0);
    for rel in stale {
        assert!(!fx.p(rel).exists(), "{rel} kept");
    }
    assert!(fx.p("var/lib/propolis/witness/meta.tmp.31337").exists());
    assert!(fx.p("run/motd.d/.propolis.tmp.999999992").exists());
}

/// Every file a pass creates is root's alone, whatever the umask it was started with, the
/// banner included: it says whether alerting works.
#[test]
fn every_file_a_pass_writes_is_mode_0600() {
    let mut fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!(
            "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t0\tdelivered\n",
            s = stamp(0)
        ),
    );
    std::fs::set_permissions(
        fx.p("var/lib/propolis/witness/hook/propolis-backup.service"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fx.setenv("WITNESS_UMASK", "000");
    fx.pass(0);
    fx.pass(300);
    let files = fx.state_files();
    for name in [
        "incidents",
        "observe",
        "meta",
        "id-salt",
        "heartbeat",
        "propolis",
    ] {
        assert!(
            files.iter().any(|p| p.file_name().unwrap() == name),
            "{name} not written: {files:?}"
        );
    }
    for path in files {
        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }
}

/// The library is checked before anything is written: missing, unloadable or older than the
/// script's `# needs-alert-lib` line, the pass exits 3 and the state stays as it was.
#[test]
fn a_library_that_is_missing_broken_or_older_than_needed_exits_3_before_any_write() {
    let lib = std::fs::read_to_string(LIB).unwrap();
    let version = lib
        .lines()
        .find_map(|l| l.strip_prefix("PA_LIB_VERSION="))
        .unwrap()
        .to_string();
    let older = lib.replace(
        &format!("\nPA_LIB_VERSION={version}\n"),
        "\nPA_LIB_VERSION=3\n",
    );
    for body in [
        Some(older),
        Some("echo $UNSET_AT_TOP\n".to_string()),
        Some("exit 0\n".to_string()),
        None,
    ] {
        let fx = Fx::new();
        match &body {
            Some(text) => fx.write("usr/local/sbin/propolis-alert-lib", text),
            None => std::fs::remove_file(fx.p("usr/local/sbin/propolis-alert-lib")).unwrap(),
        }
        let r = fx.run_args(&["light"], 0);
        assert_eq!(
            r.code,
            3,
            "{:?}: {}",
            body.as_deref().map(|b| &b[..b.len().min(30)]),
            r.err
        );
        assert!(r.err.contains("alert library"), "{}", r.err);
        assert!(fx.state_files().is_empty(), "{:?}", fx.state_files());
    }
}

/// A library a group can replace is never sourced as root.
#[test]
fn a_library_in_a_group_writable_directory_is_never_sourced() {
    let fx = Fx::new();
    std::fs::set_permissions(
        fx.p("usr/local/sbin"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let r = fx.run_args(&["light"], 0);
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(
        r.err.contains("usr/local/sbin: group-writable"),
        "{}",
        r.err
    );
    assert!(fx.state_files().is_empty());
}

/// The hook spools a firing when it cannot take the lock; the next pass takes each spool file in
/// under the lock, applies it as the hook would have, and removes it, so it is counted once.
#[test]
fn a_spooled_hook_firing_is_taken_in_once_and_its_file_removed() {
    let fx = Fx::new();
    let s = stamp(0);
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!(
            "#hook v1 g=3\nH\t{s}\t{s}\t3\texit-code\texited\t1\tproc.exit:1\t0\tundelivered\n"
        ),
    );
    fx.write(
        "run/propolis-witness/fallback/hook-sensor-http.service",
        &format!("#hook v1 g=1\nH\t{s}\t{s}\t1\tsignal\tkilled\t9\tproc.signal:9\t2\tdelivered\n"),
    );
    fx.write(
        "var/lib/propolis/witness/hook/..evil",
        "#hook v1 g=1\nH\tx\n",
    );
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "activating"),
            ("SubState", "auto-restart"),
            ("NRestarts", "3"),
        ],
    );
    fx.pass(300);
    let backup = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(
        (backup[7].as_str(), backup[31].as_str()),
        ("open", "3"),
        "{backup:?}"
    );
    assert_eq!(backup[33], "undelivered");
    assert!(
        backup[30].split(',').any(|f| f == "hookspool"),
        "{}",
        backup[30]
    );
    assert_eq!(backup[8], s, "first seen when the hook first spooled it");
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!(
        (http[7].as_str(), http[11].as_str()),
        ("open", "proc.signal:9")
    );
    assert_eq!(http[32], "2", "nr_seen from the spool");
    assert!(
        !fx.p("var/lib/propolis/witness/hook/propolis-backup.service")
            .exists()
    );
    assert!(
        !fx.p("run/propolis-witness/fallback/hook-sensor-http.service")
            .exists()
    );
    assert!(
        !fx.p("var/lib/propolis/witness/send-ledger").exists(),
        "nothing was sent"
    );
    fx.pass(600);
    assert_eq!(
        fx.record("unit:propolis-backup.service").unwrap()[31],
        "3",
        "counted once"
    );
}

/// A check that cannot run is recorded, never a failed unit: the pass exits 0 and marks its
/// heartbeat partial; three such passes in a row open the NOTICE `tool-unusable`, and two clean
/// passes resolve it.
#[test]
fn a_check_that_cannot_run_marks_the_pass_partial_and_three_in_a_row_open_tool_unusable() {
    let mut fx = Fx::new();
    fx.setenv("SYSTEMCTL_FAIL", "1");
    fx.pass(0);
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("\tpartial"),
        "{}",
        fx.read("run/propolis-witness/heartbeat")
    );
    fx.pass(300);
    assert!(fx.record("tool:units").is_none());
    fx.pass(600);
    let f = fx.record("tool:units").unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str()),
        ("tool-unusable", "NOTICE", "open")
    );
    assert_eq!(f[29], "0", "a NOTICE is never pushed");
    fx.env.clear();
    fx.pass(900);
    assert!(fx.read("run/propolis-witness/heartbeat").contains("\tok"));
    assert_eq!(
        fx.record("tool:units").unwrap()[7],
        "open",
        "one clean pass resolves nothing"
    );
    fx.pass(1200);
    let f = fx.record("tool:units").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
}

/// With nowhere to keep state the banner is still written (`/run/motd.d` is its own tmpfs), says
/// so, and the pass logs one line about it.
#[test]
fn the_banner_is_written_when_no_state_can_be_written() {
    let fx = Fx::new();
    std::fs::remove_dir_all(fx.p("var/lib/propolis/witness")).unwrap();
    fx.write(
        "run/propolis-witness/fallback",
        "a file where the directory would go",
    );
    fx.pass(0);
    let banner = fx.read("run/motd.d/propolis");
    assert!(
        banner.contains("state NOT PERSISTED - run: sudo propolis-status"),
        "{banner}"
    );
    assert_eq!(mode_of(&fx.p("run/motd.d/propolis")), 0o600);
    assert!(
        fx.log().contains("-t propolis-witness state not persisted"),
        "{}",
        fx.log()
    );
}

/// Record only: whatever happens, no pass posts anything, and every transition v2 would have
/// pushed (open, reminder, resolve) adds one to would_push instead.
#[test]
fn no_pass_ever_posts_and_every_transition_counts_toward_would_push() {
    let fx = Fx::new();
    let failed = [
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "3"),
    ];
    fx.unit("shipper.service", &failed);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("unit:shipper.service").unwrap()[29], "1");
    fx.pass(300 + 14_400);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!((f[16].as_str(), f[29].as_str()), ("remind", "2"));
    let back = 15_000;
    fx.unit(
        "shipper.service",
        &[("ActiveEnterTimestampMonotonic", &entered(back, 0))],
    );
    for t in [back, back + 300] {
        fx.pass(t);
        assert_eq!(
            fx.record("unit:shipper.service").unwrap()[7],
            "open",
            "at {t}"
        );
    }
    fx.pass(back + 600);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!(
        (f[7].as_str(), f[22].as_str(), f[29].as_str()),
        ("resolved", "active10", "3")
    );
    assert!(!fx.log().contains("curl"), "{}", fx.log());
}

/// An incident the hook opened before the witness existed carries no reminder schedule; the
/// light pass gives it the one its tier and open time give, and reminds it when that comes due.
#[test]
fn a_record_opened_before_the_witness_existed_gets_its_reminder_schedule() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#8",
        "sensor-ssh.service",
        "PAGE",
        "open",
        0,
        "-",
    )]);
    fx.unit(
        "sensor-ssh.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(f[19], stamp(3600), "next_due");
    assert_eq!(f[29], "1", "nothing due yet");
    fx.pass(3600);
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(
        (f[16].as_str(), f[29].as_str(), f[19].clone()),
        ("remind", "2", stamp(14_400))
    );
}

/// After a reboot the records are a continuation: a proof met on the first look resolves the
/// incident with the proof word `seen after restart`.
#[test]
fn after_a_reboot_a_met_proof_resolves_as_seen_after_restart() {
    let fx = Fx::new();
    let before = hook_record("w#5", "propolis-backup.service", "ACT", "open", 0, "-")
        .replace(&format!("/{BOOT}/"), "/11111111/");
    fx.incidents(&[before]);
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Result", "success"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
            (
                "InactiveEnterTimestampMonotonic",
                &((UP - 100) * 1_000_000).to_string(),
            ),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "restart"));
}

/// The only arguments are the pass names; this release has the light pass alone.
#[test]
fn an_argument_other_than_light_exits_2_before_anything_is_read() {
    let fx = Fx::new();
    for args in [
        vec![],
        vec!["hourly"],
        vec!["Light"],
        vec!["light", "light"],
        vec!["light;x"],
    ] {
        let r = fx.run_args(&args, 0);
        assert_eq!(r.code, 2, "{args:?}: {}", r.err);
        assert!(r.err.contains("usage: propolis-witness light"), "{}", r.err);
    }
    assert_eq!(fx.log(), "");
    assert!(fx.state_files().is_empty());
}

/// The witness samples every sensor unit install.sh installs, so a sensor added there is watched.
#[test]
fn the_witness_samples_every_sensor_unit_install_sh_installs() {
    let install = std::fs::read_to_string(INSTALL).unwrap();
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let first_loop = install
        .lines()
        .find(|l| l.trim_start().starts_with("for unit in ") && l.contains("sensor-"))
        .unwrap();
    let sensors: Vec<&str> = first_loop
        .split_whitespace()
        .map(|t| t.trim_end_matches(';'))
        .filter(|t| t.starts_with("sensor-") && t.ends_with(".service"))
        .collect();
    assert_eq!(sensors.len(), 12, "{first_loop}");
    let list = script
        .lines()
        .find(|l| l.starts_with("WITNESS_UNITS=("))
        .expect("deploy/witness.sh has a WITNESS_UNITS=( line");
    for unit in sensors {
        assert!(
            list.split_whitespace().any(|t| t == unit),
            "{unit} not in {list}"
        );
    }
}

/// The pass writes its line in the heartbeat file and `meta light_last`, and the banner after
/// them, from the state files alone.
#[test]
fn a_pass_writes_its_heartbeat_line_light_last_and_the_banner() {
    let fx = Fx::new();
    fx.write(
        "run/propolis-witness/heartbeat",
        &format!(
            "#heartbeat v1 g=7\nB\thourly\t{}\tpersistent\tok\n",
            stamp(0)
        ),
    );
    fx.pass(300);
    let hb = fx.read("run/propolis-witness/heartbeat");
    assert!(hb.starts_with("#heartbeat v1 g=8\n"), "{hb}");
    assert!(
        hb.contains(&format!("B\thourly\t{}\tpersistent\tok\n", stamp(0))),
        "the other instance's line is kept: {hb}"
    );
    assert!(
        hb.contains(&format!("B\tlight\t{}\tpersistent\tok\n", stamp(300))),
        "{hb}"
    );
    assert_eq!(fx.meta("light_last"), Some(stamp(300)));
    assert_eq!(fx.meta("where").as_deref(), Some("persistent"));
    let banner = fx.read("run/motd.d/propolis");
    assert_eq!(
        banner,
        "[propolis 08:05 UTC] nothing open; profile legacy\n\
         [propolis 08:05 UTC] alerts: topic not checked yet\n\
         [propolis 08:05 UTC] run: sudo propolis-status\n\
         [propolis 08:05 UTC] rewritten every 5 min; older means the witness stopped\n"
    );
}

// ---- the lifecycle over many passes -----------------------------------------------------------

/// The restarts of a crash loop that has gone quiet stay within six hours of the baseline, but
/// 30 quiet minutes answered them: the loop resolves `quiet30` once and does not reopen on the
/// same count for the rest of the six hours.
#[test]
fn a_crash_loop_resolves_after_thirty_quiet_minutes_and_never_reopens_on_the_restarts_it_answered()
{
    let fx = Fx::new();
    fx.pass(0);
    for (t, n) in [(300, "4"), (600, "8")] {
        fx.unit(
            "sensor-ssh.service",
            &[
                ("NRestarts", n),
                ("ActiveEnterTimestampMonotonic", &entered(t, 20)),
            ],
        );
        fx.pass(t);
    }
    assert_eq!(fx.record("unit:sensor-ssh.service").unwrap()[7], "open");
    for t in (900..=23_100).step_by(300) {
        fx.pass(t);
        let f = fx.record("unit:sensor-ssh.service").unwrap();
        if t < 2400 {
            assert_eq!(f[7], "open", "{} min of quiet", (t - 600) / 60);
        } else {
            assert_eq!(
                (f[7].as_str(), f[22].as_str(), f[21].clone()),
                ("resolved", "quiet30", stamp(2400)),
                "at {t}"
            );
        }
    }
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(
        (f[16].as_str(), f[23].as_str(), f[29].as_str()),
        ("resolve", "0", "2"),
        "{f:?}"
    );
}

/// The quiet time of a resolve counts from the last restart or start: a unit whose NRestarts or
/// ActiveEnterTimestampMonotonic changed between two passes ten minutes apart has not been up
/// ten minutes.
#[test]
fn a_restart_or_a_new_start_between_two_passes_starts_the_quiet_time_again() {
    for change in ["NRestarts", "ActiveEnterTimestampMonotonic"] {
        let fx = Fx::new();
        fx.incidents(&[hook_record("w#2", "shipper.service", "ACT", "open", 0, "-")]);
        fx.unit("shipper.service", &[]);
        fx.pass(0);
        let restarted = entered(300, 100);
        let value = if change == "NRestarts" {
            "1"
        } else {
            restarted.as_str()
        };
        fx.unit("shipper.service", &[(change, value)]);
        fx.pass(300);
        fx.pass(600);
        assert_eq!(
            fx.record("unit:shipper.service").unwrap()[7],
            "open",
            "{change} changed at 300"
        );
        fx.pass(900);
        let f = fx.record("unit:shipper.service").unwrap();
        assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "active10"));
    }
}

/// The time a unit has been up since is kept between passes. One that cannot be read, or is dated
/// ahead of the clock, counts from this pass: it must not keep an open incident from ever
/// resolving while the unit stays up.
#[test]
fn an_up_since_time_that_cannot_be_read_starts_the_quiet_time_again() {
    for kept in ["garbage".to_string(), stamp(86_400)] {
        let fx = Fx::new();
        fx.incidents(&[hook_record("w#2", "shipper.service", "ACT", "open", 0, "-")]);
        fx.unit("shipper.service", &[]);
        fx.observe(&format!(
            "U\tshipper.service\t{}\t0\t{BOOT}\tactive\t{}\t0\t{kept}\n",
            stamp(0),
            entered(0, 86_400)
        ));
        fx.pass(300);
        fx.pass(600);
        assert_eq!(
            fx.record("unit:shipper.service").unwrap()[7],
            "open",
            "{kept}: five minutes after the pass that could not read it"
        );
        fx.pass(900);
        let f = fx.record("unit:shipper.service").unwrap();
        assert_eq!(
            (f[7].as_str(), f[22].as_str()),
            ("resolved", "active10"),
            "{kept}"
        );
    }
}

/// A word that is not a unit name is never put to systemd, which answers for a unit of its own
/// naming (`sensor-ssh.service` for `sensor-ssh`) or refuses the whole question: a record under
/// such a word is not sampled, and a spool file for one is removed with a note.
#[test]
fn a_word_that_is_not_a_unit_name_is_never_put_to_systemd() {
    let fx = Fx::new();
    fx.incidents(&[hook_record("w#2", "sensor-ssh", "PAGE", "pending", 0, "0")]);
    let s = stamp(0);
    let words = ["test", "@x.service", "x@.service"];
    for word in words {
        fx.write(
            &format!("var/lib/propolis/witness/hook/{word}"),
            &format!(
                "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t0\tdelivered\n"
            ),
        );
    }
    fx.pass(300);
    let log = fx.log();
    let show = log
        .lines()
        .find(|l| l.starts_with("systemctl show"))
        .unwrap();
    let asked: Vec<&str> = show.split(" -- ").nth(1).unwrap().split(' ').collect();
    assert!(asked.contains(&"sensor-ssh.service"), "{show}");
    for word in ["sensor-ssh", "test", "@x.service", "x@.service"] {
        assert!(!asked.contains(&word), "{word} was put to systemd: {show}");
    }
    for word in words {
        assert!(
            !fx.p(&format!("var/lib/propolis/witness/hook/{word}"))
                .exists(),
            "{word}"
        );
        assert!(fx.record(&format!("unit:{word}")).is_none(), "{word}");
    }
    let notes = log
        .lines()
        .filter(|l| l.starts_with("logger") && l.ends_with("is not a unit's name; removed"))
        .count();
    assert_eq!(notes, words.len(), "{log}");
}

/// A oneshot's proof is a successful run that ended after the failure was recorded: a run that
/// ended at the onset, or before it, proves nothing.
#[test]
fn a_oneshot_run_that_ended_at_or_before_the_failure_proves_nothing() {
    for unit in ["propolis-backup.service", "propolis-witness@light.service"] {
        let fx = Fx::new();
        fx.incidents(&[hook_record("w#4", unit, "ACT", "open", 0, "-")]);
        let ran = |ended: u64| {
            fx.unit(
                unit,
                &[
                    ("ActiveState", "inactive"),
                    ("SubState", "dead"),
                    ("Result", "success"),
                    ("Restart", "no"),
                    ("UnitFileState", "static"),
                    (
                        "InactiveEnterTimestampMonotonic",
                        &(ended * 1_000_000).to_string(),
                    ),
                ],
            );
        };
        ran(UP - 50);
        fx.pass(300);
        ran(UP);
        fx.pass(600);
        assert_eq!(
            fx.record(&format!("unit:{unit}")).unwrap()[7],
            "open",
            "{unit}"
        );
        ran(UP + 1);
        fx.pass(900);
        let f = fx.record(&format!("unit:{unit}")).unwrap();
        assert_eq!(
            (f[7].as_str(), f[22].as_str()),
            ("resolved", "nextrun"),
            "{unit}"
        );
    }
}

/// Off on purpose: a oneshot whose timer is disabled resolves `disabled`; so does an open record
/// of a unit systemd no longer knows, and a pending one is dropped.
#[test]
fn a_oneshot_whose_timer_is_disabled_and_a_unit_systemd_no_longer_knows_resolve_as_disabled() {
    let fx = Fx::new();
    fx.incidents(&[
        hook_record("w#4", "propolis-backup.service", "ACT", "open", 0, "-"),
        hook_record("w#5", "sensor-telnet.service", "PAGE", "open", 0, "-"),
        hook_record("w#6", "sensor-dns.service", "PAGE", "pending", 0, "0"),
    ]);
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    fx.unit(
        "propolis-backup.timer",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("UnitFileState", "disabled"),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));
    let f = fx.record("unit:sensor-telnet.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));
    assert!(
        fx.record("unit:sensor-dns.service").is_none(),
        "{:?}",
        fx.records()
    );
}

/// An open unit-failed record whose unit starts looping becomes a crash loop: the same fault,
/// so nothing more v2 would push. A fresh failure whose cause is another class is a change,
/// which it would; one of the same class (every `proc.*` code) is not.
#[test]
fn an_open_record_becomes_a_crash_loop_without_a_push_and_a_new_cause_class_is_a_change() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "PAGE",
        "open",
        0,
        "0",
    )]);
    fx.pass(0);
    for (t, n) in [(300, "3"), (600, "6")] {
        fx.unit(
            "sensor-ssh.service",
            &[
                ("NRestarts", n),
                ("ActiveEnterTimestampMonotonic", &entered(t, 5)),
            ],
        );
        fx.pass(t);
    }
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(
        (f[3].as_str(), f[7].as_str(), f[16].as_str(), f[29].as_str()),
        ("unit-crashloop", "open", "-", "1"),
        "a kind change is not a transition: {f:?}"
    );

    let fx = Fx::new();
    fx.incidents(&[
        hook_record("w#2", "shipper.service", "ACT", "open", 0, "-"),
        hook_record("w#3", "propolis-logrotate.service", "ACT", "open", 0, "-"),
    ]);
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "oom-kill"),
        ],
    );
    fx.unit(
        "propolis-logrotate.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    let journal = fx.dir.path().join("journal");
    std::fs::write(
        &journal,
        "propolis-logrotate-guard: refusing to rotate /var/log/propolis: 2% free\n",
    )
    .unwrap();
    let mut fx = fx;
    fx.setenv("JOURNAL_FILE", journal.to_str().unwrap());
    fx.pass(300);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!(
        (f[11].as_str(), f[16].as_str(), f[29].as_str()),
        ("proc.exit:1", "-", "1"),
        "proc.oom is the class of proc.exit: {f:?}"
    );
    let f = fx.record("unit:propolis-logrotate.service").unwrap();
    assert_eq!(
        (f[11].as_str(), f[16].as_str(), f[29].as_str()),
        ("guard.no_space", "change", "2"),
        "{f:?}"
    );
}

// ---- holds: maintenance, the boot grace, the first config-check --------------------------------

/// A spooled firing of a unit that does not restart itself would open at once; under a manual
/// maintenance marker it stays pending, flagged as spooled and as maintenance.
#[test]
fn a_spooled_firing_of_a_oneshot_stays_pending_under_a_maintenance_marker() {
    let fx = Fx::new();
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tmanual\n", WALL + 3600),
    );
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!(
            "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t-\tdelivered\n",
            s = stamp(0)
        ),
    );
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(
        (f[7].as_str(), f[30].as_str()),
        ("pending", "hookspool,maint")
    );
    assert_eq!(f[29], "0");
}

/// No unit kind opens in the first ten minutes after a boot: a spooled firing of a oneshot stays
/// pending, and a first sighting of a unit still failed stays pending too. Neither is flagged
/// `maint`, which says planned work under a marker; past ten minutes both, still failed, open.
#[test]
fn nothing_opens_in_the_boot_grace_and_what_it_holds_opens_once_it_ends() {
    let mut fx = Fx::new();
    let boot = |t: u64| format!("{}/{BOOT}/{}", WALL + t, t);
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!(
            "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t-\tdelivered\n",
            s = boot(200)
        ),
    );
    fx.incidents(&[hook_record_at(
        "w#1",
        "shipper.service",
        "ACT",
        "pending",
        &boot(100),
        "0",
    )]);
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ActiveEnterTimestampMonotonic", "0"),
        ],
    );
    fx.setenv("PROPOLIS_WITNESS_NOW", &boot(300));
    fx.pass(300);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((f[7].as_str(), f[30].as_str()), ("pending", "hookspool"));
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!((f[7].as_str(), f[30].as_str()), ("pending", "-"));
    fx.setenv("PROPOLIS_WITNESS_NOW", &boot(700));
    fx.pass(700);
    assert_eq!(fx.record("unit:shipper.service").unwrap()[7], "open");
    assert_eq!(
        fx.record("unit:propolis-backup.service").unwrap()[7],
        "open"
    );
}

/// A first sighting held by a maintenance marker is judged once the marker has been gone ten
/// minutes: a oneshot whose next run succeeded meanwhile is dropped and never opened, and one
/// still failed opens only then.
#[test]
fn a_first_sighting_held_by_a_maintenance_marker_is_judged_ten_minutes_after_it_ends() {
    for still_failed in [false, true] {
        let fx = Fx::new();
        fx.write(
            "run/propolis-witness/maintenance",
            &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tupgrade\n", WALL + 400),
        );
        fx.incidents(&[with_field(
            &hook_record("w#1", "propolis-backup.service", "ACT", "pending", 0, "-"),
            30,
            "maint",
        )]);
        let failed = [
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ];
        fx.unit("propolis-backup.service", &failed);
        fx.pass(300);
        assert_eq!(
            fx.record("unit:propolis-backup.service").unwrap()[7],
            "pending"
        );
        if !still_failed {
            fx.unit(
                "propolis-backup.service",
                &[
                    ("ActiveState", "inactive"),
                    ("SubState", "dead"),
                    ("Result", "success"),
                    ("Restart", "no"),
                    ("UnitFileState", "static"),
                    (
                        "InactiveEnterTimestampMonotonic",
                        &((UP + 500) * 1_000_000).to_string(),
                    ),
                ],
            );
        }
        for t in [600, 900] {
            fx.pass(t);
            let state = fx
                .record("unit:propolis-backup.service")
                .map(|f| f[7].clone());
            if still_failed {
                let want = if t == 600 { "pending" } else { "open" };
                assert_eq!(state.as_deref(), Some(want), "at {t}");
            } else {
                assert_ne!(state.as_deref(), Some("open"), "at {t}");
            }
        }
        if !still_failed {
            assert!(fx.record("unit:propolis-backup.service").is_none());
        }
    }
}

/// An upgrade's marker often comes and goes between two passes, so no pass sees it. A first
/// sighting the hook flagged `maint` under it is still held for ten minutes from the sighting:
/// pending on the passes 200 and 500 s after it, opened on the pass 800 s after it.
#[test]
fn a_first_sighting_flagged_maint_is_held_ten_minutes_when_no_pass_saw_the_marker() {
    let fx = Fx::new();
    fx.incidents(&[with_field(
        &hook_record("w#1", "shipper.service", "ACT", "pending", 100, "0"),
        30,
        "maint",
    )]);
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    for t in [300, 600] {
        fx.pass(t);
        assert_eq!(
            fx.record("unit:shipper.service").unwrap()[7],
            "pending",
            "at {t}: {:?}",
            fx.records()
        );
    }
    fx.pass(900);
    assert_eq!(fx.record("unit:shipper.service").unwrap()[7], "open");
}

/// The boot grace holds a first sighting without calling it planned work: the `maint` flag is
/// for a marker alone. So a failure in the first minutes after a boot opens on the first pass
/// past the grace, not ten minutes after its sighting.
#[test]
fn a_first_sighting_held_by_the_boot_grace_is_not_flagged_maint_and_opens_once_the_grace_ends() {
    let mut fx = Fx::new();
    let early = |t: u64| format!("{}/{BOOT}/{}", WALL + t, 100 + t);
    fx.incidents(&[with_field(
        &hook_record_at("w#1", "shipper.service", "ACT", "pending", &early(200), "0"),
        10,
        &early(200),
    )]);
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.setenv("PROPOLIS_WITNESS_NOW", &early(400));
    fx.pass(400);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!(f[7], "pending", "uptime 500 s is inside the grace: {f:?}");
    assert!(!f[30].split(',').any(|x| x == "maint"), "{}", f[30]);
    fx.setenv("PROPOLIS_WITNESS_NOW", &early(700));
    fx.pass(700);
    assert_eq!(
        fx.record("unit:shipper.service").unwrap()[7],
        "open",
        "uptime 800 s: the first pass past the grace"
    );
}

/// Restarts made while planned work held (a marker, then the ten minutes after it) were
/// announced: once the hold ends they no longer count toward the slow rule, so a unit that
/// settled during the work does not open as a crash loop afterwards.
#[test]
fn restarts_under_a_maintenance_marker_do_not_open_a_crash_loop_after_it() {
    let fx = Fx::new();
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tmanual\n", WALL + 3600),
    );
    for t in (0..=5400u64).step_by(300) {
        let (n, up_for) = if t == 0 { ("0", 5) } else { ("6", t - 250) };
        fx.unit(
            "sensor-ssh.service",
            &[
                ("NRestarts", n),
                ("ActiveEnterTimestampMonotonic", &entered(t, up_for)),
            ],
        );
        fx.pass(t);
        assert!(
            fx.record("unit:sensor-ssh.service").is_none(),
            "at {t}: {:?}",
            fx.records()
        );
    }
}

/// The ten minutes after a marker hold a spooled firing too: a oneshot's failure the hook
/// spooled after the last pass that saw a marker stays pending until those ten minutes are over,
/// and opens then if the unit is still failed.
#[test]
fn a_spooled_firing_of_a_oneshot_stays_pending_in_the_ten_minutes_after_a_marker() {
    let fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\nM\tmaint_seen\t{}\n", stamp(0)),
    );
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!(
            "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t-\tdelivered\n",
            s = stamp(200)
        ),
    );
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((f[7].as_str(), f[29].as_str()), ("pending", "0"), "{f:?}");
    fx.pass(900);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((f[7].as_str(), f[29].as_str()), ("open", "1"), "{f:?}");
}

/// In the first half hour after a boot, before a config-check result exists, a sensor's loop
/// cannot be told from an unset bind: it stays pending, whether the witness saw the loop alone
/// or the hook saw a failure first, and opens once uptime passes 1800 s.
#[test]
fn a_sensor_loop_waits_for_a_config_check_result_in_the_first_half_hour_after_a_boot() {
    for hook_first in [false, true] {
        let mut fx = Fx::new();
        if hook_first {
            fx.incidents(&[hook_record_at(
                "w#1",
                "sensor-ssh.service",
                "PAGE",
                "pending",
                &early(100),
                "0",
            )]);
        }
        for (t, n) in [(0u64, 0u64), (300, 4), (600, 8), (900, 12), (1200, 16)] {
            fx.setenv("PROPOLIS_WITNESS_NOW", &early(t));
            fx.unit(
                "sensor-ssh.service",
                &[
                    ("NRestarts", &n.to_string()),
                    (
                        "ActiveEnterTimestampMonotonic",
                        &((600 + t - 5) * 1_000_000).to_string(),
                    ),
                ],
            );
            fx.pass(t);
            let f = fx.record("unit:sensor-ssh.service");
            let want = match (t, hook_first) {
                (0 | 300, false) => None,
                (1200, _) => Some("open"),
                _ => Some("pending"),
            };
            assert_eq!(
                f.as_ref().map(|f| f[7].as_str()),
                want,
                "hook first {hook_first}, uptime {}",
                600 + t
            );
        }
        let f = fx.record("unit:sensor-ssh.service").unwrap();
        assert_eq!(f[3], "unit-crashloop", "hook first {hook_first}");
    }
}

// ---- what a pass judges, and when ------------------------------------------------------------

/// A first sighting the hook recorded after the pass took its sample is judged against a sample
/// from before the failure (the unit up for a day, NRestarts as the hook read it): it waits for
/// the next pass instead of being dropped as healed.
#[test]
fn a_first_sighting_recorded_after_the_pass_took_its_sample_waits_for_the_next_pass() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "PAGE",
        "pending",
        300,
        "0",
    )]);
    fx.pass(300);
    assert_eq!(fx.record("unit:sensor-ssh.service").unwrap()[7], "pending");
    assert!(
        fx.meta("healed").is_none(),
        "{}",
        fx.read("var/lib/propolis/witness/meta")
    );
}

/// Only a sighting from this boot can have been written after this pass's sample. One from the
/// boot before, dated by a wall clock ahead of today's (a host without a clock battery, before
/// NTP), is judged like any other: the unit still failed on two passes opens.
#[test]
fn a_first_sighting_from_another_boot_dated_ahead_of_the_clock_is_still_judged() {
    let fx = Fx::new();
    fx.incidents(&[hook_record_at(
        "w#1",
        "shipper.service",
        "ACT",
        "pending",
        &format!("{}/11111111/500", WALL + 3600),
        "0",
    )]);
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!((f[7].as_str(), f[29].as_str()), ("open", "1"), "{f:?}");
}

/// The hook's first sighting of a fault back inside the reopen window is judged on what the
/// hook read this time: one healed restart puts the record back as resolved, reopens nothing,
/// adds nothing v2 would push, and counts as a restart that healed.
#[test]
fn a_healed_restart_inside_the_reopen_window_is_dropped_and_counted() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "PAGE",
        "open",
        0,
        "0",
    )]);
    fx.unit("sensor-ssh.service", &[("NRestarts", "3")]);
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!((f[7].as_str(), f[29].as_str()), ("resolved", "2"));
    fx.unit(
        "sensor-ssh.service",
        &[
            ("ActiveState", "activating"),
            ("SubState", "auto-restart"),
            ("NRestarts", "3"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.hook_fires("sensor-ssh.service", 700);
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!((f[7].as_str(), f[32].as_str()), ("pending", "3"), "{f:?}");
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "4"),
            ("ActiveEnterTimestampMonotonic", &entered(900, 200)),
        ],
    );
    fx.pass(900);
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(
        (
            f[1].as_str(),
            f[7].as_str(),
            f[21].clone(),
            f[23].as_str(),
            f[29].as_str()
        ),
        ("w#1", "resolved", stamp(600), "0", "2"),
        "{f:?}"
    );
    assert!(
        fx.meta("healed").is_some_and(|v| v.starts_with("1/")),
        "{}",
        fx.read("var/lib/propolis/witness/meta")
    );
}

/// NRestarts that rise by one an hour reach six only after six hours, when the baseline has
/// been replaced: never a slow loop. A rise of three measured across a gap of more than 900 s
/// (passes that did not run) is not fast.
#[test]
fn restarts_spread_over_more_than_six_hours_are_no_loop_and_a_rise_across_missed_passes_is_not_fast()
 {
    let fx = Fx::new();
    for k in 0..=8u64 {
        fx.unit("sensor-ssh.service", &[("NRestarts", &k.to_string())]);
        fx.pass(k * 3700);
        assert!(
            fx.record("unit:sensor-ssh.service").is_none(),
            "after {k} restarts"
        );
    }

    let fx = Fx::new();
    fx.observe(&format!(
        "U\tsensor-ssh.service\t{s}\t0\t{BOOT}\tactive\t{a}\t1\t-\nR\tsensor-ssh.service\t{s}\t0\n",
        s = stamp(0),
        a = entered(0, 86_400)
    ));
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "3"),
            ("ActiveEnterTimestampMonotonic", &entered(1000, 5)),
        ],
    );
    fx.pass(1000);
    assert!(fx.record("unit:sensor-ssh.service").is_none());
}

/// The first pass of a new boot replaces the samples of the old one and judges nothing on them:
/// neither a loop from a count that looks risen nor the failed state on two passes.
#[test]
fn a_sample_from_another_boot_judges_nothing_on_the_first_pass_of_the_new_one() {
    let fx = Fx::new();
    let old = format!("{}/11111111/500", WALL - 300);
    fx.observe(&format!(
        "U\tshipper.service\t{old}\t20\t11111111\tfailed\t-\t1\t-\n\
         U\tsensor-ssh.service\t{old}\t0\t11111111\tactive\t1\t1\t-\n\
         R\tsensor-ssh.service\t{old}\t0\n"
    ));
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "10"),
            ("ActiveEnterTimestampMonotonic", &entered(0, 5)),
        ],
    );
    fx.pass(0);
    assert!(fx.records().is_empty(), "{:?}", fx.records());
}

/// Unknown never resolves anything: after 72 passes in a row without an answer from systemd an
/// open unit record is flagged `cannotverify`, and still not resolved; 71 do not flag it.
#[test]
fn seventy_two_passes_without_systemd_flag_open_unit_records_cannotverify_and_resolve_none() {
    let mut fx = Fx::new();
    fx.observe(&format!("P\tunits\t{}\tunknown\tunknown\t70\n", stamp(0)));
    fx.incidents(&[hook_record("w#2", "shipper.service", "ACT", "open", 0, "-")]);
    fx.setenv("SYSTEMCTL_FAIL", "1");
    fx.pass(300);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!((f[7].as_str(), f[30].as_str()), ("open", "-"));
    fx.pass(600);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!((f[7].as_str(), f[30].as_str()), ("open", "cannotverify"));
}

/// A record of a witness instance this release has no timer for can never be proved fixed by a
/// next run: it resolves `disabled`.
#[test]
fn a_record_of_a_witness_instance_with_no_timer_resolves_as_disabled() {
    let fx = Fx::new();
    fx.incidents(&[hook_record(
        "w#3",
        "propolis-witness@foo.service",
        "ACT",
        "open",
        0,
        "-",
    )]);
    fx.unit(
        "propolis-witness@foo.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "2"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    fx.pass(300);
    let f = fx.record("unit:propolis-witness@foo.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));
}

/// A reminder the hook's old open missed by hours is recorded once, not once a pass until the
/// schedule catches up.
#[test]
fn a_reminder_missed_while_no_pass_ran_is_recorded_once() {
    let fx = Fx::new();
    let before = format!("{}/{BOOT}/{}", WALL - 46_800, UP - 46_800);
    fx.incidents(&[hook_record_at(
        "w#8",
        "sensor-ssh.service",
        "PAGE",
        "open",
        &before,
        "-",
    )]);
    fx.unit(
        "sensor-ssh.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    let f = fx.record("unit:sensor-ssh.service").unwrap();
    assert_eq!(
        (f[16].as_str(), f[19].as_str(), f[29].as_str()),
        ("remind", "-", "2"),
        "{f:?}"
    );
    assert_eq!(f[18], "1", "the skipped reminders are not counted");
}

// ---- the spool, the lock, the deadline ---------------------------------------------------------

/// The hook spools without the lock and rewrites its file by rename. A rewrite that lands while
/// a pass is taking the file in is not lost: it is left for the next pass, which counts it.
#[test]
fn a_spool_file_the_hook_rewrites_during_the_pass_is_counted_by_the_next_pass() {
    let mut fx = Fx::new();
    write_exec(&fx.bin.join("head"), HEAD_RACE_STUB);
    let spool = fx.p("var/lib/propolis/witness/hook/propolis-backup.service");
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!(
            "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t-\tdelivered\n",
            s = stamp(0)
        ),
    );
    fx.setenv("RACE_SPOOL", spool.to_str().unwrap());
    fx.setenv("RACE_MARK", fx.dir.path().join("raced").to_str().unwrap());
    fx.setenv("RACE_FIRST", &stamp(100));
    fx.pass(300);
    assert!(
        fx.dir.path().join("raced").exists(),
        "the hook ran during the pass"
    );
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(f[7], "open");
    fx.pass(600);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(
        (f[31].as_str(), f[33].as_str()),
        ("2", "undelivered"),
        "{f:?}"
    );
    let left: Vec<PathBuf> = fx
        .state_files()
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("/hook/"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// When no state can be written the spooled firing is not taken in, so its file stays for a
/// pass that can write.
#[test]
fn a_spool_file_is_kept_when_no_state_can_be_written() {
    let fx = Fx::new();
    // Every state write flushes before its rename: a flush that fails refuses them all.
    write_exec(&fx.bin.join("sync"), "#!/usr/bin/env bash\nexit 1\n");
    let body = format!(
        "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t-\tdelivered\n",
        s = stamp(0)
    );
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &body,
    );
    fx.pass(300);
    assert!(fx.record("unit:propolis-backup.service").is_none());
    assert_eq!(
        fx.read("var/lib/propolis/witness/hook/propolis-backup.service"),
        body
    );
    let names: Vec<String> = std::fs::read_dir(fx.p("var/lib/propolis/witness/hook"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["propolis-backup.service"]);
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("state NOT PERSISTED")
    );
}

/// A spooled firing whose record cannot be kept (512 records open, none resolved to make room)
/// is not taken in, so its file stays for a pass that can keep it.
#[test]
fn a_spooled_firing_that_cannot_be_recorded_keeps_its_file() {
    let fx = Fx::new();
    let open: Vec<String> = (0..512)
        .map(|i| {
            hook_record(&format!("w#{}", i + 100), "x", "NOTICE", "open", 0, "-")
                .replace("unit:x", &format!("finding:test:{i:012}"))
        })
        .collect();
    fx.incidents(&open);
    let body = format!(
        "#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t-\tdelivered\n",
        s = stamp(0)
    );
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &body,
    );
    fx.pass(300);
    assert_eq!(fx.records().len(), 512);
    assert!(fx.record("unit:propolis-backup.service").is_none());
    assert_eq!(
        fx.read("var/lib/propolis/witness/hook/propolis-backup.service"),
        body
    );
    assert!(
        fx.log()
            .contains("incident not recorded: the record of unit:propolis-backup.service"),
        "{}",
        fx.log()
    );
}

/// The rotation guard's routine skip on two passes opens the NOTICE rotation-skipped, which v2
/// would never push; its journal is read while the state lock is free, as the hook reads it.
#[test]
fn a_rotation_skip_opens_a_notice_and_its_journal_is_read_without_the_lock() {
    let mut fx = Fx::new();
    fx.unit(
        "propolis-logrotate.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    let journal = fx.dir.path().join("journal");
    std::fs::write(
        &journal,
        "propolis-logrotate-guard: skipping rotation of /var/log/propolis/ssh.log: reader behind\n\
         error: error running non-shared prerotate script for /var/log/propolis/ssh.log\n",
    )
    .unwrap();
    fx.setenv("JOURNAL_FILE", journal.to_str().unwrap());
    fx.setenv(
        "LOCK_PROBE",
        fx.p("var/lib/propolis/witness/state.lock")
            .to_str()
            .unwrap(),
    );
    fx.pass(0);
    fx.pass(300);
    let f = fx.record("unit:propolis-logrotate.service").unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[11].as_str(), f[29].as_str()),
        ("rotation-skipped", "NOTICE", "guard.behind", "0")
    );
    let log = fx.log();
    assert!(
        log.contains(&format!("_SYSTEMD_INVOCATION_ID={INVOCATION}")),
        "{log}"
    );
    assert!(log.contains("journalctl lock free"), "{log}");
    assert!(!log.contains("journalctl lock held"), "{log}");
}

/// A systemctl that hangs is cut off by its time limit; the pass still completes, partial, and
/// counts the check as unknown.
#[test]
fn a_systemctl_that_hangs_is_cut_off_and_the_pass_completes_as_partial() {
    let mut fx = Fx::new();
    fx.setenv("SYSTEMCTL_SLEEP", "30");
    fx.pass(0);
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains(&format!("B\tlight\t{}\tpersistent\tpartial\n", stamp(0))),
        "{}",
        fx.read("run/propolis-witness/heartbeat")
    );
    assert!(
        fx.read("var/lib/propolis/witness/observe")
            .contains(&format!("P\tunits\t{}\tunknown\tunknown\t1\n", stamp(0))),
        "{}",
        fx.read("var/lib/propolis/witness/observe")
    );
}

/// A pass that has used up its time (240 s; here a test deadline of 0) stops judging, keeps what
/// it did and marks its heartbeat partial.
#[test]
fn a_pass_past_its_deadline_judges_nothing_more_and_is_partial() {
    let mut fx = Fx::new();
    fx.setenv("PROPOLIS_WITNESS_DEADLINE", "0");
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    assert!(fx.record("unit:shipper.service").is_none());
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("\tpartial\n"),
        "{}",
        fx.read("run/propolis-witness/heartbeat")
    );
    assert_eq!(fx.meta("light_last"), Some(stamp(300)));
}

/// When no lock file can be opened at all (both state directories gone), the pass can keep
/// nothing, and the banner says so.
#[test]
fn a_pass_that_can_open_no_lock_file_says_state_not_persisted() {
    let fx = Fx::new();
    std::fs::remove_dir_all(fx.p("var/lib/propolis/witness")).unwrap();
    std::fs::remove_dir_all(fx.p("run/propolis-witness")).unwrap();
    fx.pass(0);
    let banner = fx.read("run/motd.d/propolis");
    assert!(
        banner.contains("state NOT PERSISTED - run: sudo propolis-status"),
        "{banner}"
    );
}

/// A library in a directory anyone can write is never sourced as root, and the witness says
/// which directory.
#[test]
fn a_library_in_a_world_writable_directory_is_never_sourced() {
    let fx = Fx::new();
    // A library that leaves a mark when it is sourced: the library's own check, run once it is
    // loaded, would refuse it too, but only after its code had run as root.
    let sourced = fx.dir.path().join("sourced");
    let lib = std::fs::read_to_string(LIB).unwrap();
    fx.write(
        "usr/local/sbin/propolis-alert-lib",
        &format!(": > '{}'\n{lib}", sourced.display()),
    );
    std::fs::set_permissions(
        fx.p("usr/local/sbin"),
        std::fs::Permissions::from_mode(0o757),
    )
    .unwrap();
    let r = fx.run_args(&["light"], 0);
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(
        r.err.contains("usr/local/sbin: world-writable"),
        "{}",
        r.err
    );
    assert!(!sourced.exists(), "the library was sourced");
    assert!(fx.state_files().is_empty());
}
