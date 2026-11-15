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

/// The witness pushes nothing; its only requests are the read check's GETs. Records its argv in
/// the stub log and its environment in `curl.env`; with no `curl.answer` beside the units it
/// fails as an unreachable server does, and with one (`code|content type`) it answers every GET
/// with that, an empty body, in the `-w` form asked for.
const CURL_STUB: &str = r#"#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$STUB_LOG"
d="${UNITS%/units}"
env | sed 's/^/curl-env /' >> "$d/curl.env"
[ -f "$d/curl.answer" ] || exit 7
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in -o) out="$2"; shift ;; esac
    shift
done
: > "$out"
IFS='|' read -r code ct < "$d/curl.answer"
printf '%s\t%s' "$code" "$ct"
"#;

/// The installed config-check: records its argv, runs `cc.during` (a bash script) when there is
/// one, as something else that happens on the host while it runs, prints `cc.tsv` and exits with
/// the status in `cc.rc` (0 without one).
const CC_STUB: &str = r#"#!/usr/bin/env bash
printf 'config-check %s\n' "$*" >> "$STUB_LOG"
d="${UNITS%/units}"
[ ! -f "$d/cc.during" ] || bash "$d/cc.during"
[ ! -f "$d/cc.tsv" ] || cat "$d/cc.tsv"
rc=0
[ ! -f "$d/cc.rc" ] || rc="$(cat "$d/cc.rc")"
exit "$rc"
"#;

/// The read-check binding of the fixture's target (https://ntfy.example.invalid, t0p1c-secret).
const FX_BINDING: &str = "8f24b729c8ebd3c1";

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

/// The readcheck file every fixture starts with: one attempt for the fixture's target, no answer.
fn fixture_readcheck() -> String {
    format!(
        "#readcheck v1 g=1\nR\t{FX_BINDING}\t{}\ttransient\t-\t-\t-\t000\t000\tboth\t000\n",
        stamp(0)
    )
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
        // The hourly timer was enabled ten minutes before the first pass, and the hourly pass has
        // not run yet: what a host sees just after the upgrade that brought it.
        fx.unit(
            "propolis-witness@hourly.timer",
            &[
                ("SubState", "waiting"),
                ("ActiveEnterTimestampMonotonic", &entered(0, 600)),
            ],
        );
        // An attempt of the read check is stored for the fixture's target, without an answer, so a
        // light pass has nothing to check and the banner reads `topic not checked yet`.
        fx.write("var/lib/propolis/witness/readcheck", &fixture_readcheck());
        std::fs::set_permissions(
            fx.p("var/lib/propolis/witness/readcheck"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
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

    /// One hourly pass at time `t`, with the light pass's heartbeat line made fresh first (on a
    /// host the light pass runs every five minutes); every pass must exit 0.
    fn hourly(&self, t: u64) -> Run {
        let hb = self.read("run/propolis-witness/heartbeat");
        let mut body: String = hb
            .lines()
            .filter(|l| l.starts_with("B\t") && !l.starts_with("B\tlight\t"))
            .map(|l| format!("{l}\n"))
            .collect();
        body.push_str(&format!("B\tlight\t{}\tpersistent\tok\n", stamp(t)));
        self.write(
            "run/propolis-witness/heartbeat",
            &format!("#heartbeat v1 g=1\n{body}"),
        );
        self.hourly_alone(t)
    }

    /// One hourly pass at time `t`, the heartbeat file left as it is; it must exit 0.
    fn hourly_alone(&self, t: u64) -> Run {
        let r = self.run_args(&["hourly"], t);
        assert_eq!(r.code, 0, "hourly pass at {t}: {}\n{}", r.out, r.err);
        r
    }

    /// Installs the config-check stub where the witness runs it from, under directories the
    /// ownership check accepts.
    fn install_cc(&self) {
        write_exec(&self.p("usr/local/lib/propolis/config-check.sh"), CC_STUB);
        // What the installed config-check sources beside itself, as the deploy scripts install it.
        self.write(
            "usr/local/lib/propolis/listeners-lib.sh",
            "# the listener inventory\n",
        );
        std::fs::set_permissions(
            self.p("usr/local/lib/propolis/listeners-lib.sh"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        for d in ["usr/local/lib", "usr/local/lib/propolis"] {
            std::fs::set_permissions(self.p(d), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// What the config-check stub prints on its next run (and with what status).
    fn cc(&self, tsv: &str, rc: i32) {
        std::fs::write(self.dir.path().join("cc.tsv"), tsv).unwrap();
        std::fs::write(self.dir.path().join("cc.rc"), rc.to_string()).unwrap();
    }

    /// A bash script the config-check stub runs while it runs.
    fn cc_during(&self, script: &str) {
        std::fs::write(self.dir.path().join("cc.during"), script).unwrap();
    }

    /// What the curl stub answers every GET with (`code|content type`).
    fn curl_answers(&self, answer: &str) {
        std::fs::write(self.dir.path().join("curl.answer"), answer).unwrap();
    }

    fn curl_env(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("curl.env")).unwrap_or_default()
    }

    fn observe_text(&self) -> String {
        self.read("var/lib/propolis/witness/observe")
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

    /// Every file under the root's alerting directories (not the lock the fixture made, nor its
    /// read-check line while no pass has rewritten it).
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
        out.retain(|p| {
            !(p.ends_with("var/lib/propolis/witness/readcheck")
                && std::fs::read_to_string(p).unwrap_or_default() == fixture_readcheck())
        });
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
        vec!["Hourly"],
        vec!["hourly", "light"],
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

// ---- the hourly pass --------------------------------------------------------------------------

/// The first 12 hex of sha256(KEY), as config-check's TSV carries a finding's key.
fn k12(key: &str) -> String {
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
        .write_all(key.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)[..12].to_string()
}

/// A completed config-check run in its TSV form: `lines` (G and R records) as written, then one
/// F record (with an X fix line) per finding, given as (level, full key, scope), and the E count.
fn cc_tsv(lines: &[&str], findings: &[(&str, &str, &str)]) -> String {
    let mut s = String::from("#config-check tsv v1\nS\tfail\t2\t1\t0\t0\t1\t1800000000\t1\n");
    for l in lines {
        s.push_str(l);
        s.push('\n');
    }
    for (level, key, scope) in findings {
        let id = key.split(':').next().unwrap();
        s.push_str(&format!(
            "F\t{level}\t{id}\t{}\t{scope}\tmanual\tthe message\nX\tthe fix\n",
            k12(key)
        ));
    }
    s.push_str(&format!("E\t{}\n", findings.len()));
    s
}

/// A listener row of the TSV: scope, unit, and every cell ok but the firewall cell given.
fn r_line(scope: &str, unit: &str, firewall: &str) -> String {
    format!("R\t{scope}\t{unit}\tfail\tok\tfail\t{firewall}\tok\tok\tok")
}

/// Every page row of WITNESS_CC_TABLE, fed twice by a completed run, opens one finding record at
/// the table's tier and stage with the instance the row says how to find, and v2 would push each
/// open once. A daily row opens a NOTICE that would push nothing; a never row, and an id with no
/// row, are not recorded; every unlisted spool folds into one record that counts them.
#[test]
fn every_page_row_of_the_eligibility_table_opens_once_after_two_completed_runs() {
    let fx = Fx::new();
    fx.install_cc();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_SENSOR_LOGS=ssh:/var/log/propolis/ssh/events.jsonl,http:/var/log/propolis/http/events.jsonl,c1:/var/spool/propolis/gateway/c1/events.jsonl\n",
    );
    fx.unit(
        "sensor-redis.service",
        &[("ActiveState", "inactive"), ("SubState", "dead")],
    );
    let page: &[(&str, &str, &str, &str, &str, char)] = &[
        (
            "fail",
            "unit-missing:sensor-telnet",
            "sensor-telnet",
            "PAGE",
            "listen",
            'u',
        ),
        (
            "fail",
            "unit-down:sensor-redis",
            "sensor-redis",
            "PAGE",
            "listen",
            'u',
        ),
        (
            "fail",
            "listen-foreign:tcp:22",
            "ssh/tcp",
            "PAGE",
            "listen",
            'u',
        ),
        (
            "fail",
            "listen-loopback:tcp:80",
            "http/tcp",
            "PAGE",
            "listen",
            'u',
        ),
        (
            "fail",
            "listen-none:udp:69",
            "tftp/udp",
            "PAGE",
            "listen",
            'u',
        ),
        ("warn", "fw:tcp:21", "ftp/tcp", "ACT", "listen", 'u'),
        ("fail", "danger:tcp:25", "smtp/tcp", "PAGE", "listen", 'u'),
        (
            "fail",
            "spool-label-sensor:/var/spool/propolis/gateway/c1/events.jsonl",
            "gateway-spool",
            "PAGE",
            "gateway",
            's',
        ),
        (
            "fail",
            "intake-wrongpath:/var/log/propolis/ssh/events.jsonl",
            "ssh/tcp",
            "ACT",
            "intake",
            's',
        ),
        (
            "fail",
            "intake-absent:/var/log/propolis/mqtt/events.jsonl",
            "mqtt/tcp",
            "ACT",
            "intake",
            '-',
        ),
        (
            "fail",
            "logsize-fail:/var/log/propolis/http/events.jsonl",
            "http/tcp",
            "ACT",
            "source",
            's',
        ),
        ("fail", "stale", "logrotate", "ACT", "source", '-'),
        ("fail", "backup-timer", "backup", "ACT", "backup", '-'),
        ("fail", "backup-stale", "backup", "ACT", "backup", '-'),
        ("fail", "ops-failure-hook", "alerting", "ACT", "alert", '-'),
    ];
    let mut findings: Vec<(&str, &str, &str)> = page.iter().map(|p| (p.0, p.1, p.2)).collect();
    findings.extend([
        ("fail", "spool-unlisted:collector-01", "gateway-spool"),
        ("fail", "spool-unlisted:collector-02", "gateway-spool"),
        ("warn", "unit-notenabled:sensor-ssh", "sensor-ssh"),
        ("warn", "stamp-behind", "deploy-stamp"),
        ("fail", "made-up-finding:x", "x"),
    ]);
    let rows = [
        r_line("ssh/tcp", "sensor-ssh", "ok"),
        r_line("http/tcp", "sensor-http", "ok"),
        r_line("tftp/udp", "sensor-tftp", "ok"),
        r_line("ftp/tcp", "sensor-ftp", "fail"),
        r_line("smtp/tcp", "sensor-smtp", "ok"),
        r_line("mqtt/tcp", "sensor-mqtt", "ok"),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    fx.cc(&cc_tsv(&rows, &findings), 0);
    fx.hourly(0);
    for p in page {
        let key = format!("finding:{}:{}", p.1.split(':').next().unwrap(), k12(p.1));
        let f = fx.record(&key).unwrap_or_else(|| {
            panic!(
                "{} not recorded:\n{}",
                p.1,
                fx.read("var/lib/propolis/witness/incidents")
            )
        });
        assert_eq!(f[7], "pending", "{}: one run opens nothing", p.1);
    }
    fx.hourly(3600);
    for (_, key_text, _, tier, stage, inst) in page {
        let key = format!(
            "finding:{}:{}",
            key_text.split(':').next().unwrap(),
            k12(key_text)
        );
        let f = fx.record(&key).unwrap();
        assert_eq!(
            (f[3].as_str(), f[4].as_str(), f[6].as_str(), f[7].as_str()),
            ("finding", *stage, *tier, "open"),
            "{key_text}"
        );
        assert_eq!(
            (f[11].as_str(), f[29].as_str()),
            ("config.finding", "1"),
            "{key_text}"
        );
        if *inst == '-' {
            assert_eq!(f[5], "-", "{key_text}");
        } else {
            assert!(
                f[5].starts_with(*inst) && f[5].len() == 6,
                "{key_text}: instance {}",
                f[5]
            );
        }
    }
    let f = fx.record("finding:spool-unlisted:all").unwrap();
    assert_eq!(
        (f[6].as_str(), f[7].as_str(), f[34].as_str()),
        ("ACT", "open", "2"),
        "every unlisted spool in one record"
    );
    let f = fx
        .record(&format!(
            "finding:unit-notenabled:{}",
            k12("unit-notenabled:sensor-ssh")
        ))
        .unwrap();
    assert_eq!(
        (f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("NOTICE", "open", "0")
    );
    for absent in ["stamp-behind", "made-up-finding:x"] {
        let id = absent.split(':').next().unwrap();
        assert!(
            fx.record(&format!("finding:{id}:{}", k12(absent)))
                .is_none(),
            "{absent} recorded"
        );
    }
    assert_eq!(
        fx.records().len(),
        page.len() + 2,
        "{}",
        fx.read("var/lib/propolis/witness/incidents")
    );
    assert!(
        fx.log()
            .contains("config-check --tsv --no-events --report-only\n"),
        "{}",
        fx.log()
    );
    let hb = fx.read("run/propolis-witness/heartbeat");
    assert!(
        hb.contains(&format!("B\thourly\t{}\t", stamp(3600))),
        "{hb}"
    );
    assert_eq!(fx.meta("hourly_last"), Some(stamp(3600)));
    assert!(
        fx.meta("cc_last")
            .is_some_and(|v| v.starts_with(&format!("{}/0/", stamp(3600)))),
        "{:?}",
        fx.meta("cc_last")
    );
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("0"));
}

/// A finding seen once is dropped when the next completed run lacks it. An open one resolves
/// clean2 on the second completed run in a row without it, and a run whose row for the finding
/// could not be checked says nothing either way. A unit-down whose unit systemd calls failed and
/// a listen-foreign on a port a danger finding holds are daily for those passes (a NOTICE); a fw
/// finding whose firewall cell is unknown is held: neither opened nor counted clean.
#[test]
fn a_finding_resolves_after_two_clean_runs_and_a_limited_row_or_a_held_finding_says_nothing() {
    let fx = Fx::new();
    fx.install_cc();
    fx.unit(
        "sensor-redis.service",
        &[("ActiveState", "failed"), ("SubState", "failed")],
    );
    let held = [
        ("fail", "unit-down:sensor-redis", "sensor-redis"),
        ("fail", "listen-foreign:tcp:25", "smtp/tcp"),
        ("fail", "danger:tcp:25", "smtp/tcp"),
        ("warn", "fw:tcp:21", "ftp/tcp"),
    ];
    let rows = [
        r_line("smtp/tcp", "sensor-smtp", "ok"),
        r_line("ftp/tcp", "sensor-ftp", "unknown"),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    let mut first = vec![
        ("fail", "stale", "logrotate"),
        ("fail", "backup-timer", "backup"),
    ];
    first.extend(held);
    fx.cc(&cc_tsv(&rows, &first), 0);
    fx.hourly(0);
    let stale = format!("finding:stale:{}", k12("stale"));
    let timer = format!("finding:backup-timer:{}", k12("backup-timer"));
    assert_eq!(fx.record(&stale).unwrap()[7], "pending");
    assert_eq!(fx.record(&timer).unwrap()[7], "pending");
    let mut second = vec![("fail", "stale", "logrotate")];
    second.extend(held);
    fx.cc(&cc_tsv(&rows, &second), 0);
    fx.hourly(3600);
    assert_eq!(fx.record(&stale).unwrap()[7], "open");
    assert!(
        fx.record(&timer).is_none(),
        "seen once, then absent: dropped"
    );
    // A unit-down whose unit systemd calls failed (unit-failed pages it) and a listen-foreign on a
    // port a danger finding holds (danger pages it) are daily for those passes: a NOTICE that would
    // push nothing. A fw finding whose firewall cell is unknown is held: never opened.
    for (_, key, _) in held {
        let id = key.split(':').next().unwrap();
        let f = fx.record(&format!("finding:{id}:{}", k12(key)));
        match id {
            "danger" => {}
            "unit-down" | "listen-foreign" => {
                let f = f.unwrap_or_else(|| panic!("{key} not recorded"));
                assert_eq!(
                    (f[6].as_str(), f[7].as_str(), f[29].as_str()),
                    ("NOTICE", "open", "0"),
                    "{key}"
                );
            }
            _ => assert!(f.is_none(), "{key} is held, never opened"),
        }
    }
    fx.cc(
        &cc_tsv(&["G\tlogrotate\tunknown\tstate file not readable"], &[]),
        0,
    );
    fx.hourly(7200);
    assert_eq!(
        fx.record(&stale).unwrap()[7],
        "open",
        "a limited row says nothing"
    );
    assert!(
        !fx.observe_text().contains(&format!("clean:{stale}")),
        "{}",
        fx.observe_text()
    );
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.hourly(10800);
    assert_eq!(
        fx.record(&stale).unwrap()[7],
        "open",
        "one clean run is not two"
    );
    assert!(
        fx.observe_text().contains(&format!("P\tclean:{stale}\t")),
        "{}",
        fx.observe_text()
    );
    fx.hourly(14400);
    let f = fx.record(&stale).unwrap();
    assert_eq!(
        (f[7].as_str(), f[22].as_str(), f[29].as_str()),
        ("resolved", "clean2", "2")
    );
    assert!(
        !fx.observe_text().contains(&format!("clean:{stale}")),
        "{}",
        fx.observe_text()
    );
}

/// A config-check that does not complete (an exit with no output, an output cut off before its E
/// line, a missing or untrusted script) raises meta cc_fail and marks the pass partial; the second
/// hourly pass in a row opens cc-stopped, an ACT on the witness rail with cause cc.stopped. Two
/// completed runs resolve it. The pass still exits 0, and a finding of the last completed run
/// keeps its state.
#[test]
fn config_check_failing_twice_opens_cc_stopped_and_two_completed_runs_resolve_it() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.hourly(0);
    fx.hourly(3600);
    let stale = format!("finding:stale:{}", k12("stale"));
    assert_eq!(fx.record(&stale).unwrap()[7], "open");
    fx.cc("", 70);
    fx.hourly(7200);
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("1"));
    assert!(fx.record("tool:config-check").is_none());
    assert!(
        fx.read("run/propolis-witness/heartbeat").contains(&format!(
            "B\thourly\t{}\tpersistent\tpartial\n",
            stamp(7200)
        )),
        "{}",
        fx.read("run/propolis-witness/heartbeat")
    );
    let cut = cc_tsv(&[], &[("fail", "stale", "logrotate")]);
    let cut = cut.rsplit_once("E\t").unwrap().0.to_string();
    fx.cc(&cut, 0);
    fx.hourly(10800);
    let f = fx.record("tool:config-check").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str()
        ),
        ("cc-stopped", "witness", "ACT", "open", "cc.stopped")
    );
    assert_eq!(f[29], "1", "v2 would push it");
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("2"));
    assert_eq!(
        fx.record(&stale).unwrap()[7],
        "open",
        "the last completed run's finding stays"
    );
    assert!(
        fx.log()
            .contains("config-check did not complete: output cut off or incomplete"),
        "{}",
        fx.log()
    );
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.hourly(14400);
    assert_eq!(fx.record("tool:config-check").unwrap()[7], "open");
    fx.hourly(18000);
    let f = fx.record("tool:config-check").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("0"));

    // Missing, then not trusted: not run, a failure all the same, and no exit status is claimed
    // for a run that did not take place.
    let fx = Fx::new();
    fx.hourly(0);
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("1"));
    assert_eq!(fx.meta("cc_last"), Some(format!("{}/-/0", stamp(0))));
    assert!(
        fx.log()
            .contains("config-check did not complete: not installed"),
        "{}",
        fx.log()
    );
    fx.install_cc();
    std::fs::set_permissions(
        fx.p("usr/local/lib/propolis"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    fx.hourly(3600);
    assert!(
        !fx.log().contains("config-check --tsv"),
        "an untrusted config-check never runs"
    );
    assert!(
        fx.log()
            .contains("config-check did not complete: not trusted: "),
        "{}",
        fx.log()
    );
    assert_eq!(fx.record("tool:config-check").unwrap()[7], "open");
}

/// config-check's output is untrusted text: a finding line whose id or key hash is not in its
/// form is skipped and counted, and a finding's tier comes from the table, not from its level.
#[test]
fn a_finding_line_out_of_form_is_skipped_and_the_tier_comes_from_the_table() {
    let fx = Fx::new();
    fx.install_cc();
    let good = cc_tsv(&[], &[("fail", "unit-notenabled:sensor-ssh", "sensor-ssh")]);
    let bad = good.replace(
        "E\t1\n",
        "F\tfail\tunit missing\t0123456789ab\tx\t-\tm\nF\tfail\tstale\tnot-hex-at-a\tx\t-\tm\nE\t3\n",
    );
    fx.cc(&bad, 0);
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx
        .record(&format!(
            "finding:unit-notenabled:{}",
            k12("unit-notenabled:sensor-ssh")
        ))
        .unwrap();
    assert_eq!((f[6].as_str(), f[7].as_str()), ("NOTICE", "open"));
    assert_eq!(
        fx.records().len(),
        1,
        "{}",
        fx.read("var/lib/propolis/witness/incidents")
    );
    assert!(
        fx.log()
            .contains("config-check printed 2 finding lines that are not in its form; skipped"),
        "{}",
        fx.log()
    );
    assert_eq!(fx.meta("cc_skipped").as_deref(), Some("2"));
    fx.cc(&good, 0);
    fx.hourly(7200);
    assert_eq!(fx.meta("cc_skipped").as_deref(), Some("0"));
}

/// The hourly pass computes without the lock and then reads the state files afresh: a record the
/// failure hook changed while config-check ran keeps that change, the light pass's observe lines
/// stay exactly as written, and the hourly pass adds only its own.
#[test]
fn a_record_the_hook_changes_while_the_hourly_pass_computes_keeps_the_change() {
    let fx = Fx::new();
    fx.install_cc();
    fx.incidents(&[hook_record("w#8", "shipper.service", "ACT", "open", 0, "0")]);
    let light_lines = format!(
        "U\tsensor-ssh.service\t{s}\t0\t{BOOT}\tactive\t{a}\t0\t{s}\nR\tsensor-ssh.service\t{s}\t0\nP\tunits\t{s}\tok\t-\t4\n",
        s = stamp(0),
        a = entered(0, 86_400)
    );
    fx.observe(&light_lines);
    fx.cc_during(
        ". \"$PROPOLIS_ALERT_ROOT/usr/local/sbin/propolis-alert-lib\" && pa_init \"$PROPOLIS_ALERT_ROOT\" \
         && PA_HOOK_UNIT=shipper.service PA_HOOK_OUT=undelivered PA_HOOK_T0=0 pa_hook_record\n\
         . \"$PROPOLIS_ALERT_ROOT/usr/local/sbin/propolis-alert-lib\" && pa_init \"$PROPOLIS_ALERT_ROOT\" \
         && PA_HOOK_UNIT=sensor-ssh.service PA_HOOK_OUT=delivered PA_HOOK_T0=0 pa_hook_record\n",
    );
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.hourly(300);
    let f = fx.record("unit:shipper.service").unwrap();
    assert_eq!(
        (f[7].as_str(), f[31].as_str(), f[33].as_str()),
        ("open", "2", "undelivered"),
        "the hook's firing during the pass is kept"
    );
    assert_eq!(fx.record("unit:sensor-ssh.service").unwrap()[7], "pending");
    assert_eq!(
        fx.record(&format!("finding:stale:{}", k12("stale")))
            .unwrap()[7],
        "pending"
    );
    let observe = fx.observe_text();
    for line in light_lines.lines() {
        assert!(
            observe.contains(&format!("{line}\n")),
            "{line} lost:\n{observe}"
        );
    }
    assert!(observe.contains("P\tconfig-check\t"), "{observe}");
}

/// The readcheck file may hold lines of a type this release does not know (a later release's): a
/// pass that stores its own answer keeps them as read.
#[test]
fn a_readcheck_line_of_an_unknown_type_survives_a_pass_that_stores_its_answer() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=7\nR\t{FX_BINDING}\t{s}\ttransient\t-\t-\t-\t000\t000\tboth\t000\nZ\tkept\tfor-a-later-release\n",
            s = stamp(0)
        ),
    );
    fx.curl_answers("403|text/plain; charset=utf-8");
    fx.hourly(300);
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert!(
        rc.contains(&format!("\trefused\t{}\trefused\t", stamp(300))),
        "the pass stored its answer: {rc}"
    );
    assert!(rc.contains("Z\tkept\tfor-a-later-release\n"), "{rc}");
}

/// The read check from the hourly pass: three anonymous GETs and, with a token set, a fourth with
/// it; the topic and the token reach curl through files, never its arguments or environment. The
/// answer is stored for the gate and the banner; a light pass does not ask again while the
/// target is the same, and asks within five minutes once the topic changes. Nothing is posted.
#[test]
fn the_hourly_read_check_stores_its_answer_and_a_changed_topic_is_checked_by_the_light_pass() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_s3cret-value\n",
    );
    fx.curl_answers("403|text/plain; charset=utf-8");
    fx.hourly(0);
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert!(
        rc.contains(&format!(
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\tnoread\t403\t403\tboth\t403\n",
            s = stamp(0)
        )),
        "{rc}"
    );
    let calls: Vec<String> = fx
        .log()
        .lines()
        .filter(|l| l.starts_with("curl "))
        .map(str::to_string)
        .collect();
    assert_eq!(calls.len(), 4, "{calls:?}");
    for call in &calls {
        assert!(call.contains(" -K "), "{call}");
        for word in [" -d", "--data", " -X", " -T", "POST"] {
            assert!(!call.contains(word), "{call}");
        }
    }
    for secret in ["t0p1c-secret", "tk_s3cret-value"] {
        assert!(!fx.log().contains(secret), "{secret} on a command line");
        assert!(
            !fx.curl_env().contains(secret),
            "{secret} in curl's environment"
        );
    }
    fx.pass(300);
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        4,
        "the light pass does not ask again for the same target"
    );
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("alerts: topic refuses anonymous reads"),
        "{}",
        fx.read("run/motd.d/propolis")
    );

    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=n3w-topic\n",
    );
    fx.curl_answers("200|application/x-ndjson");
    fx.pass(600);
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        7
    );
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert_eq!(
        rc.lines().filter(|l| l.starts_with("R\t")).count(),
        1,
        "{rc}"
    );
    assert!(
        rc.contains(&format!(
            "\treadable\t{}\treadable\t-\t200\t200\tboth\t200\n",
            stamp(600)
        )),
        "{rc}"
    );
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("alerts: topic READABLE by anyone"),
        "{}",
        fx.read("run/motd.d/propolis")
    );
    assert!(!fx.log().contains("n3w-topic"));
}

/// A read check that keeps getting no answer is a check that cannot run: unknown on three hourly
/// passes in a row opens the NOTICE tool-unusable on tool:readcheck, and each such pass is partial.
#[test]
fn a_read_check_without_an_answer_on_three_hourly_passes_opens_tool_unusable() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    for t in [0, 3600, 7200] {
        fx.hourly(t);
    }
    let f = fx.record("tool:readcheck").unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str(), f[11].as_str()),
        ("tool-unusable", "NOTICE", "open", "net.connect")
    );
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("\tpartial\n")
    );
}

/// The light pass judges the hourly pass: a stopped hourly timer opens witness-stale on
/// witness:hourly on the second light pass, and two fresh checks resolve it fresh2. A host just
/// upgraded, whose hourly timer started ten minutes ago and has not run yet, is not stale; one
/// whose timer has run for over three hours without a pass is.
#[test]
fn a_stopped_hourly_timer_opens_witness_stale_and_a_new_one_has_three_hours_to_run() {
    let fx = Fx::new();
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    assert!(
        fx.record("witness:hourly").is_none(),
        "a timer started 10 min ago is fresh"
    );
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveState", "inactive"), ("UnitFileState", "disabled")],
    );
    fx.pass(900);
    assert_eq!(fx.record("witness:hourly").unwrap()[7], "pending");
    fx.pass(1200);
    let f = fx.record("witness:hourly").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        (
            "witness-stale",
            "witness",
            "ACT",
            "open",
            "witness.stale",
            "1"
        )
    );
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveEnterTimestampMonotonic", &entered(1500, 60))],
    );
    fx.pass(1500);
    assert_eq!(
        fx.record("witness:hourly").unwrap()[7],
        "open",
        "one fresh check is not two"
    );
    fx.pass(1800);
    let f = fx.record("witness:hourly").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "fresh2"));

    let fx = Fx::new();
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveEnterTimestampMonotonic", &entered(0, 10_900))],
    );
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("witness:hourly").unwrap()[7], "open");
}

/// The other pass's age is the newer of its heartbeat line and its meta stamp: after a reboot
/// /run is empty, and a recent meta stamp still counts. Nothing is judged in the first 1800 s of
/// uptime, when the hourly timer's first run may still be minutes away.
#[test]
fn witness_stale_is_not_judged_after_a_boot_and_a_recent_meta_stamp_counts_without_run() {
    let mut fx = Fx::new();
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveEnterTimestampMonotonic", &entered(0, 20_000))],
    );
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\thourly_last\t{}/{BOOT}/{}\n",
            WALL - 3000,
            UP - 3000
        ),
    );
    fx.pass(0);
    fx.pass(300);
    assert!(fx.record("witness:hourly").is_none(), "{:?}", fx.records());

    fx.write("var/lib/propolis/witness/meta", "#meta v1 g=1\n");
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveState", "inactive"), ("UnitFileState", "disabled")],
    );
    for t in [600u64, 900, 1200] {
        fx.setenv(
            "PROPOLIS_WITNESS_NOW",
            &format!("{}/{BOOT}/{}", WALL + t, 100 + t),
        );
        fx.pass(t);
    }
    assert!(fx.record("witness:hourly").is_none(), "{:?}", fx.records());
}

/// The hourly pass judges the light pass: a light pass over twenty minutes old opens
/// witness-stale on witness:light on the second hourly pass.
#[test]
fn the_hourly_pass_opens_witness_stale_for_a_light_pass_over_twenty_minutes_old() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\nM\tlight_last\t{}\n", stamp(0)),
    );
    fx.hourly_alone(1500);
    assert_eq!(fx.record("witness:light").unwrap()[7], "pending");
    fx.hourly_alone(5100);
    let f = fx.record("witness:light").unwrap();
    assert_eq!((f[3].as_str(), f[7].as_str()), ("witness-stale", "open"));
    fx.pass(5200);
    fx.hourly_alone(5300);
    assert_eq!(fx.record("witness:light").unwrap()[7], "open");
    fx.pass(5400);
    fx.hourly_alone(5500);
    assert_eq!(fx.record("witness:light").unwrap()[22], "fresh2");
}

/// An hourly pass past its deadline judges nothing more: its findings stay unrecorded, its
/// heartbeat line is partial, and it still exits 0.
#[test]
fn an_hourly_pass_past_its_deadline_judges_nothing_more_and_is_partial() {
    let mut fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.setenv("PROPOLIS_WITNESS_DEADLINE", "0");
    fx.hourly(0);
    fx.hourly(3600);
    assert!(fx.records().is_empty(), "{:?}", fx.records());
    assert!(
        fx.read("run/propolis-witness/heartbeat").contains(&format!(
            "B\thourly\t{}\tpersistent\tpartial\n",
            stamp(3600)
        )),
        "{}",
        fx.read("run/propolis-witness/heartbeat")
    );
    assert!(
        fx.log().lines().all(|l| !l.starts_with("curl ")),
        "{}",
        fx.log()
    );
    // A pass that judged nothing says nothing of config-check either.
    assert_eq!(fx.meta("hourly_last"), Some(stamp(3600)));
    assert_eq!(fx.meta("cc_last"), None);
    assert_eq!(fx.meta("cc_fail"), None);
}

/// A backup too old because the nightly run keeps failing is the failed run's to report: while
/// the backup unit's record is open and its last failure is newer than its last success, the
/// backup-stale finding folds under it and v2 would push nothing for it. Without that failure
/// it opens on its own.
#[test]
fn backup_stale_folds_under_an_open_failed_backup_and_opens_alone_without_one() {
    let fx = Fx::new();
    fx.install_cc();
    fx.incidents(&[hook_record(
        "w#8",
        "propolis-backup.service",
        "ACT",
        "open",
        0,
        "-",
    )]);
    fx.write(
        "var/lib/propolis/backup-status/last-failure",
        "{\"failed_at\":\"2027-01-15T02:00:00Z\",\"step\":\"dumping the database\"}\n",
    );
    fx.cc(&cc_tsv(&[], &[("fail", "backup-stale", "backup")]), 0);
    fx.hourly(0);
    fx.hourly(3600);
    let key = format!("finding:backup-stale:{}", k12("backup-stale"));
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (f[7].as_str(), f[13].as_str(), f[29].as_str()),
        ("open", "w#8", "0"),
        "folded under the failed run"
    );
    assert!(f[30].contains("folded"), "{}", f[30]);

    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "backup-stale", "backup")]), 0);
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (f[7].as_str(), f[13].as_str(), f[29].as_str()),
        ("open", "-", "1")
    );
}

/// An hourly pass that cannot get the lock writes no state and counts the miss on its own
/// lockwait line.
#[test]
fn an_hourly_pass_that_misses_the_lock_counts_it_on_its_own_lockwait_line() {
    let mut fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.setenv("PROPOLIS_WITNESS_LOCK_WAIT", "1");
    fx.write("run/propolis-witness/lockwait", "light\t3\n");
    let mut holder = fx.hold_lock();
    fx.hourly(0);
    holder.kill().unwrap();
    holder.wait().unwrap();
    assert_eq!(
        fx.read("run/propolis-witness/lockwait"),
        "light\t3\nhourly\t1\n"
    );
    assert!(!fx.p("var/lib/propolis/witness/meta").exists());
    assert!(fx.records().is_empty());
    assert!(
        fx.log()
            .contains("state lock busy for 1 s; hourly pass skipped"),
        "{}",
        fx.log()
    );
}

/// The state word of `key`'s record, or `none`.
fn state_of(fx: &Fx, key: &str) -> String {
    fx.record(key)
        .map(|f| f[7].clone())
        .unwrap_or_else(|| "none".into())
}

/// An F line out of form cannot be tied to a key, so the run that printed it cannot prove a
/// finding of that id absent: an open finding whose line turns malformed (its key hash `-`, which
/// config-check prints when sha256sum fails) stays open with no clean count, and a line whose id
/// is out of form keeps every absent finding from counting clean. A malformed line of another id
/// does not hold this one, and the count of such lines is kept for the walk.
#[test]
fn an_open_finding_whose_line_turns_malformed_stays_open_with_no_clean_count() {
    let fx = Fx::new();
    fx.install_cc();
    let good = cc_tsv(&[], &[("fail", "stale", "logrotate")]);
    fx.cc(&good, 0);
    fx.hourly(0);
    fx.hourly(3600);
    let stale = format!("finding:stale:{}", k12("stale"));
    assert_eq!(state_of(&fx, &stale), "open");
    fx.cc(&good.replace(&k12("stale"), "-"), 0);
    for t in [7200, 10800] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &stale), "open", "at {t}");
        assert!(
            !fx.observe_text().contains(&format!("clean:{stale}")),
            "{}",
            fx.observe_text()
        );
    }
    assert_eq!(fx.meta("cc_skipped").as_deref(), Some("1"));
    let bad_id = cc_tsv(&[], &[]).replace(
        "E\t0\n",
        "F\tfail\tnot an id\t0123456789ab\tx\t-\tm\nE\t1\n",
    );
    fx.cc(&bad_id, 0);
    for t in [14400, 18000] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &stale), "open", "at {t}");
        assert!(!fx.observe_text().contains(&format!("clean:{stale}")));
    }
    let other = cc_tsv(&[], &[("fail", "backup-timer", "backup")]);
    fx.cc(&other.replace(&k12("backup-timer"), "-"), 0);
    fx.hourly(21600);
    assert!(
        fx.observe_text().contains(&format!("P\tclean:{stale}\t")),
        "a malformed line of another id holds nothing of this one: {}",
        fx.observe_text()
    );
}

/// A run whose L lines name a limit of a finding's group says nothing of that group, whatever its
/// G row reads: config-check leaves the backup row at fail when df is missing, yet the headroom
/// check did not run. An open backup finding then stays open with no clean count; a run without
/// the limit starts the count, and an L line no group is known for holds every group.
#[test]
fn an_absent_finding_in_a_group_whose_limit_line_names_it_stays_open() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "backup-timer", "backup")]), 0);
    fx.hourly(0);
    fx.hourly(3600);
    let timer = format!("finding:backup-timer:{}", k12("backup-timer"));
    assert_eq!(state_of(&fx, &timer), "open");
    let g = "G\tbackup\tfail\tthe last backup run failed";
    let limited = cc_tsv(
        &[
            g,
            "L\tdf is not installed: the backup volume's headroom was not checked",
        ],
        &[("fail", "backup-failing", "backup")],
    );
    fx.cc(&limited, 0);
    for t in [7200, 10800] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &timer), "open", "at {t}");
        assert!(
            !fx.observe_text().contains(&format!("clean:{timer}")),
            "{}",
            fx.observe_text()
        );
    }
    fx.cc(&cc_tsv(&[g], &[("fail", "backup-failing", "backup")]), 0);
    fx.hourly(14400);
    assert!(
        fx.observe_text().contains(&format!("P\tclean:{timer}\t")),
        "{}",
        fx.observe_text()
    );
    fx.cc(
        &cc_tsv(
            &[g, "L\ta limit no release before this one printed"],
            &[("fail", "backup-failing", "backup")],
        ),
        0,
    );
    fx.hourly(18000);
    assert_eq!(state_of(&fx, &timer), "open");
    assert!(
        !fx.observe_text().contains(&format!("clean:{timer}")),
        "an unknown limit holds every group: {}",
        fx.observe_text()
    );
}

/// What the installed config-check sources beside itself runs as root too: a listeners-lib.sh
/// another account can write, or an alert-lib.sh beside it that can be, keeps config-check from
/// running at all, and that counts toward cc-stopped like a missing script.
#[test]
fn a_config_check_library_another_account_can_write_keeps_config_check_from_running() {
    for (name, mode) in [("listeners-lib.sh", 0o664), ("alert-lib.sh", 0o666)] {
        let fx = Fx::new();
        fx.install_cc();
        fx.cc(&cc_tsv(&[], &[]), 0);
        let rel = format!("usr/local/lib/propolis/{name}");
        if name == "alert-lib.sh" {
            fx.write(&rel, "# the alert library beside config-check\n");
        }
        std::fs::set_permissions(fx.p(&rel), std::fs::Permissions::from_mode(mode)).unwrap();
        fx.hourly(0);
        assert!(!fx.log().contains("config-check --tsv"), "{name}: it ran");
        assert!(
            fx.log()
                .contains("config-check did not complete: not trusted: "),
            "{name}: {}",
            fx.log()
        );
        assert_eq!(fx.meta("cc_fail").as_deref(), Some("1"), "{name}");
        assert_eq!(fx.meta("cc_last"), Some(format!("{}/-/0", stamp(0))));
        fx.hourly(3600);
        assert_eq!(state_of(&fx, "tool:config-check"), "open", "{name}");
    }
}

/// Two passes means two consecutive passes: a pending finding that a run could not check (its
/// group limited) and did not show is dropped, so seen again it is pending, not open.
#[test]
fn a_pending_finding_not_seen_on_a_run_that_could_not_check_it_is_dropped() {
    let fx = Fx::new();
    fx.install_cc();
    let stale = format!("finding:stale:{}", k12("stale"));
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.hourly(0);
    assert_eq!(state_of(&fx, &stale), "pending");
    fx.cc(
        &cc_tsv(&["G\tlogrotate\tunknown\tstate file not readable"], &[]),
        0,
    );
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &stale), "none");
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.hourly(7200);
    assert_eq!(state_of(&fx, &stale), "pending");
}

/// The same for witness-stale: one stale check, then a check that cannot judge (the first half
/// hour after a boot), then a stale check, is not two stale checks in a row.
#[test]
fn a_pending_witness_stale_is_dropped_by_a_check_that_could_not_judge_it() {
    let mut fx = Fx::new();
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveState", "inactive"), ("UnitFileState", "disabled")],
    );
    fx.pass(0);
    assert_eq!(state_of(&fx, "witness:hourly"), "pending");
    fx.setenv(
        "PROPOLIS_WITNESS_NOW",
        &format!("{}/abcdef02/400", WALL + 900),
    );
    fx.pass(900);
    assert_eq!(state_of(&fx, "witness:hourly"), "none");
    fx.setenv(
        "PROPOLIS_WITNESS_NOW",
        &format!("{}/abcdef02/2100", WALL + 2600),
    );
    fx.pass(2600);
    assert_eq!(state_of(&fx, "witness:hourly"), "pending");
}

/// A listener finding resolves only on runs that could check listeners: its own R line with an
/// unknown cell (here the socket owner) keeps it open with no clean count, and two runs with
/// every cell known resolve it.
#[test]
fn an_open_listener_finding_stays_open_while_its_row_has_an_unknown_cell() {
    let fx = Fx::new();
    fx.install_cc();
    let ok_row = r_line("telnet/tcp", "sensor-telnet", "ok");
    let unknown_row = "R\ttelnet/tcp\tsensor-telnet\tfail\tok\tunknown\tok\tok\tok\tok";
    let missing = format!("finding:unit-missing:{}", k12("unit-missing:sensor-telnet"));
    fx.cc(
        &cc_tsv(
            &[&ok_row],
            &[("fail", "unit-missing:sensor-telnet", "sensor-telnet")],
        ),
        0,
    );
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &missing), "open");
    fx.cc(&cc_tsv(&[unknown_row], &[]), 0);
    for t in [7200, 10800] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &missing), "open", "at {t}");
        assert!(!fx.observe_text().contains(&format!("clean:{missing}")));
    }
    fx.cc(&cc_tsv(&[&ok_row], &[]), 0);
    fx.hourly(14400);
    assert_eq!(state_of(&fx, &missing), "open");
    fx.hourly(18000);
    let f = fx.record(&missing).unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
}

/// The config-check result a sensor's early loop waits for is a completed one: in the first half
/// hour after a boot, a recent cc_last whose run did not complete (cc_fail 1) keeps the loop
/// pending as no result would; with cc_fail 0 the same loop opens.
#[test]
fn a_sensor_loop_in_the_first_half_hour_waits_while_the_last_config_check_failed() {
    for (fail, want) in [("1", "pending"), ("0", "open")] {
        let mut fx = Fx::new();
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!(
                "#meta v1 g=1\nM\tcc_last\t{}/0/12\nM\tcc_fail\t{fail}\n",
                early(0)
            ),
        );
        for (t, n) in [(0u64, 0u64), (300, 4), (600, 8), (900, 12)] {
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
        }
        assert_eq!(
            state_of(&fx, "unit:sensor-ssh.service"),
            want,
            "cc_fail {fail}"
        );
    }
}

/// The light pass wants the hourly timer active and enabled: one active but disabled, or masked,
/// will not come back after a reboot, and opens witness-stale on the second light pass.
#[test]
fn an_hourly_timer_that_is_active_but_disabled_or_masked_opens_witness_stale() {
    for file in ["disabled", "masked"] {
        let fx = Fx::new();
        fx.unit(
            "propolis-witness@hourly.timer",
            &[
                ("SubState", "waiting"),
                ("ActiveEnterTimestampMonotonic", &entered(0, 600)),
                ("UnitFileState", file),
            ],
        );
        fx.pass(0);
        fx.pass(300);
        assert_eq!(state_of(&fx, "witness:hourly"), "open", "{file}");
    }
}

/// One stale check is a first sighting: a fresh check after it drops it, never opens it.
#[test]
fn one_stale_check_then_a_fresh_one_drops_witness_stale() {
    let fx = Fx::new();
    fx.unit(
        "propolis-witness@hourly.timer",
        &[("ActiveState", "inactive"), ("UnitFileState", "disabled")],
    );
    fx.pass(0);
    assert_eq!(state_of(&fx, "witness:hourly"), "pending");
    fx.unit(
        "propolis-witness@hourly.timer",
        &[
            ("SubState", "waiting"),
            ("ActiveEnterTimestampMonotonic", &entered(300, 60)),
        ],
    );
    fx.pass(300);
    assert_eq!(state_of(&fx, "witness:hourly"), "none");
}

/// The hourly pass computes without the lock and applies its result to the state files as they
/// are when it takes the lock: a light pass that runs while config-check runs (storing the read
/// check's refusal, its observe lines and meta light_last), and a healed count written meanwhile,
/// all survive exactly; the hourly pass adds its own P lines and meta keys, keeps the refusal
/// through its own unanswered attempt, and judges the light pass by the light_last written
/// meanwhile.
#[test]
fn a_light_pass_during_config_check_loses_nothing_to_the_hourly_pass() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    // Bound to another target: the light pass checks the current one.
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t0000000000000000\t{}\ttransient\t-\t-\t-\t000\t000\tboth\t000\n",
            stamp(0)
        ),
    );
    let healed = format!("3/{}", stamp(200));
    fx.cc_during(&format!(
        "d=\"${{UNITS%/units}}\"\n\
         st=\"$PROPOLIS_ALERT_ROOT/var/lib/propolis/witness\"\n\
         printf '403|text/plain\\n' > \"$d/curl.answer\"\n\
         bash '{SCRIPT}' light > /dev/null 2>&1; echo \"$?\" > \"$d/light.rc\"\n\
         rm -f \"$d/curl.answer\"\n\
         . \"$PROPOLIS_ALERT_ROOT/usr/local/sbin/propolis-alert-lib\" && pa_init \"$PROPOLIS_ALERT_ROOT\" \
         && pa_lock 10 && _pa_meta_set healed '{healed}' && pa_unlock\n\
         cp \"$st/observe\" \"$d/observe.light\"\n\
         grep -v \"^B\tlight\t\" \"$PROPOLIS_ALERT_ROOT/run/propolis-witness/heartbeat\" > \"$d/hb\"\n\
         cat \"$d/hb\" > \"$PROPOLIS_ALERT_ROOT/run/propolis-witness/heartbeat\"\n"
    ));
    fx.hourly(300);
    let d = fx.dir.path();
    assert_eq!(
        std::fs::read_to_string(d.join("light.rc")).unwrap(),
        "0\n",
        "the light pass ran"
    );
    let observe = fx.observe_text();
    let light_lines: Vec<String> = std::fs::read_to_string(d.join("observe.light"))
        .unwrap()
        .lines()
        .filter(|l| {
            l.starts_with("U\t")
                || l.starts_with("R\t")
                || l.starts_with("P\tunits\t")
                || l.starts_with("P\twitness-hourly\t")
        })
        .map(str::to_string)
        .collect();
    assert!(
        light_lines.iter().any(|l| l.starts_with("U\t")),
        "{light_lines:?}"
    );
    for line in &light_lines {
        assert!(
            observe.contains(&format!("{line}\n")),
            "{line} lost:\n{observe}"
        );
    }
    for own in ["P\tconfig-check\t", "P\treadcheck\t"] {
        assert!(observe.contains(own), "{own} missing:\n{observe}");
    }
    assert_eq!(fx.meta("light_last"), Some(stamp(300)));
    assert_eq!(fx.meta("healed"), Some(healed));
    assert_eq!(fx.meta("hourly_last"), Some(stamp(300)));
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("0"));
    assert!(
        fx.meta("cc_last")
            .is_some_and(|v| v.starts_with(&format!("{}/0/", stamp(300)))),
        "{:?}",
        fx.meta("cc_last")
    );
    assert_eq!(
        fx.read("var/lib/propolis/witness/readcheck")
            .lines()
            .filter(|l| l.starts_with("R\t"))
            .collect::<Vec<_>>(),
        vec![format!(
            "R\t{FX_BINDING}\t{s}\ttransient\t{s}\trefused\t-\t403\t403\tboth\t403",
            s = stamp(300)
        )],
        "the refusal the light pass stored stands through the hourly pass's unanswered attempt"
    );
    assert_eq!(
        state_of(&fx, "witness:light"),
        "none",
        "light_last written meanwhile shows the light pass fresh"
    );
    assert_eq!(
        state_of(&fx, &format!("finding:stale:{}", k12("stale"))),
        "pending"
    );
}

/// A fw finding seen on a run where its firewall cell is unknown is present, if held: the clean
/// count it had restarts, so one clean run after it does not resolve it.
#[test]
fn an_open_fw_finding_seen_held_between_two_clean_runs_restarts_its_clean_count() {
    let fx = Fx::new();
    fx.install_cc();
    let known = r_line("ftp/tcp", "sensor-ftp", "fail");
    let unknown = r_line("ftp/tcp", "sensor-ftp", "unknown");
    let fw = format!("finding:fw:{}", k12("fw:tcp:21"));
    let present = [("warn", "fw:tcp:21", "ftp/tcp")];
    fx.cc(&cc_tsv(&[&known], &present), 0);
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &fw), "open");
    fx.cc(&cc_tsv(&[&known], &[]), 0);
    fx.hourly(7200);
    assert!(fx.observe_text().contains(&format!("P\tclean:{fw}\t")));
    fx.cc(&cc_tsv(&[&unknown], &present), 0);
    fx.hourly(10800);
    fx.cc(&cc_tsv(&[&known], &[]), 0);
    fx.hourly(14400);
    assert_eq!(state_of(&fx, &fw), "open", "the clean count restarted");
}

/// The unlisted spools of a run all fold into one record whose count follows the latest run.
#[test]
fn unlisted_spools_fold_into_one_record_whose_count_follows_the_latest_run() {
    let fx = Fx::new();
    fx.install_cc();
    let names = ["c-a", "c-b", "c-c", "c-d", "c-e"];
    let spools = |n: usize| -> Vec<(String, String, String)> {
        names[..n]
            .iter()
            .map(|c| {
                (
                    "fail".to_string(),
                    format!("spool-unlisted:{c}"),
                    "gateway-spool".to_string(),
                )
            })
            .collect()
    };
    let tsv = |n: usize| {
        let s = spools(n);
        let f: Vec<(&str, &str, &str)> = s
            .iter()
            .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
            .collect();
        cc_tsv(&[], &f)
    };
    fx.cc(&tsv(3), 0);
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx.record("finding:spool-unlisted:all").unwrap();
    assert_eq!((f[7].as_str(), f[34].as_str()), ("open", "3"));
    fx.cc(&tsv(5), 0);
    fx.hourly(7200);
    let f = fx.record("finding:spool-unlisted:all").unwrap();
    assert_eq!((f[7].as_str(), f[34].as_str()), ("open", "5"));
    assert_eq!(
        fx.records()
            .iter()
            .filter(|f| f[2].starts_with("finding:"))
            .count(),
        1,
        "{:?}",
        fx.records()
    );
}

/// config-check prints at most 20 spool-unlisted lines (SPOOL_MAX_REPORTED), so a run that
/// reaches that many is counted as at least that many, not as exactly 20.
#[test]
fn unlisted_spools_at_config_checks_cap_are_counted_as_at_least_the_cap() {
    let cc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/config-check.sh"
    ))
    .unwrap();
    assert!(cc.contains("\nSPOOL_MAX_REPORTED=20\n"));
    assert!(
        std::fs::read_to_string(SCRIPT)
            .unwrap()
            .contains("\nWITNESS_SPOOL_REPORTED=20\n")
    );
    let fx = Fx::new();
    fx.install_cc();
    let keys: Vec<String> = (0..20).map(|i| format!("spool-unlisted:c{i:02}")).collect();
    let f: Vec<(&str, &str, &str)> = keys
        .iter()
        .map(|k| ("fail", k.as_str(), "gateway-spool"))
        .collect();
    let g = "G\tgateway-spool\tfail\t50 collectors in /var/spool/propolis/gateway, not in PROPOLIS_SENSOR_LOGS: c00, c01, c02, c03, c04 and 45 more";
    fx.cc(&cc_tsv(&[g], &f), 0);
    fx.hourly(0);
    let f = fx.record("finding:spool-unlisted:all").unwrap();
    assert_eq!(f[34], "20+");
}

/// The TSV reader accepts only the form it knows: another header version, or a G line before the
/// S line, is a run that did not complete, and raises cc_fail.
#[test]
fn a_config_check_output_with_another_header_or_a_line_before_s_is_not_completed() {
    let fx = Fx::new();
    fx.install_cc();
    let good = cc_tsv(&[], &[("fail", "stale", "logrotate")]);
    fx.cc(&good.replace("tsv v1", "tsv v2"), 0);
    fx.hourly(0);
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("1"));
    assert!(
        fx.log()
            .contains("config-check did not complete: not in the TSV form"),
        "{}",
        fx.log()
    );
    fx.cc(
        &good.replacen(
            "#config-check tsv v1\n",
            "#config-check tsv v1\nG\tlogrotate\tok\trotation ran\n",
            1,
        ),
        0,
    );
    fx.hourly(3600);
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("2"));
    assert_eq!(state_of(&fx, "tool:config-check"), "open");
    assert_eq!(
        state_of(&fx, &format!("finding:stale:{}", k12("stale"))),
        "none"
    );
}

/// A config-check that timed out did not complete, even with a whole TSV printed; nor did one
/// whose output passed the 2 MiB cap before its E line.
#[test]
fn a_config_check_that_times_out_or_prints_past_the_cap_is_not_completed() {
    let fx = Fx::new();
    fx.install_cc();
    let good = cc_tsv(&[], &[("fail", "stale", "logrotate")]);
    fx.cc(&good, 124);
    fx.hourly(0);
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("1"));
    assert!(
        fx.log()
            .contains("config-check did not complete: timed out after 300 s"),
        "{}",
        fx.log()
    );
    let pad: String = (0..2200)
        .map(|i| format!("G\tpad{i}\tok\t{}\n", "x".repeat(1000)))
        .collect();
    let (head, tail) = good.rsplit_once("E\t").unwrap();
    fx.cc(&format!("{head}{pad}E\t{tail}"), 0);
    fx.hourly(3600);
    assert_eq!(fx.meta("cc_fail").as_deref(), Some("2"));
    assert!(
        fx.log()
            .contains("config-check did not complete: output cut off or incomplete"),
        "{}",
        fx.log()
    );
    assert_eq!(
        state_of(&fx, &format!("finding:stale:{}", k12("stale"))),
        "none"
    );
}

/// A unit-down finding is judged by what systemd says of the unit now: when systemctl cannot be
/// asked, nothing opens, and an open one gets no clean count from the run either.
#[test]
fn a_unit_down_finding_whose_unit_cannot_be_read_neither_opens_nor_counts_clean() {
    let mut fx = Fx::new();
    fx.install_cc();
    fx.unit(
        "sensor-redis.service",
        &[("ActiveState", "inactive"), ("SubState", "dead")],
    );
    let down = format!("finding:unit-down:{}", k12("unit-down:sensor-redis"));
    let present = cc_tsv(&[], &[("fail", "unit-down:sensor-redis", "sensor-redis")]);
    fx.cc(&present, 0);
    fx.setenv("SYSTEMCTL_FAIL", "1");
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &down), "none");
    fx.setenv("SYSTEMCTL_FAIL", "");
    fx.hourly(7200);
    fx.hourly(10800);
    assert_eq!(state_of(&fx, &down), "open");
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.hourly(14400);
    assert!(fx.observe_text().contains(&format!("P\tclean:{down}\t")));
    fx.cc(&present, 0);
    fx.setenv("SYSTEMCTL_FAIL", "1");
    fx.hourly(18000);
    fx.setenv("SYSTEMCTL_FAIL", "");
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.hourly(21600);
    assert_eq!(state_of(&fx, &down), "open", "the clean count restarted");
}

/// The table makes unit-down daily for a pass where systemd calls the unit failed (unit-failed
/// pages that): the finding is recorded as a NOTICE that would push nothing, and once the unit is
/// inactive, a dead listener nothing else reports, its tier rises to PAGE, which v2 would push.
#[test]
fn a_unit_down_on_a_failed_unit_is_a_notice_and_rises_to_page_once_the_unit_is_inactive() {
    let fx = Fx::new();
    fx.install_cc();
    fx.unit(
        "sensor-redis.service",
        &[("ActiveState", "failed"), ("SubState", "failed")],
    );
    let down = format!("finding:unit-down:{}", k12("unit-down:sensor-redis"));
    fx.cc(
        &cc_tsv(&[], &[("fail", "unit-down:sensor-redis", "sensor-redis")]),
        0,
    );
    fx.hourly(0);
    let f = fx.record(&down).unwrap();
    assert_eq!((f[6].as_str(), f[7].as_str()), ("NOTICE", "pending"));
    fx.hourly(3600);
    let f = fx.record(&down).unwrap();
    assert_eq!(
        (f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("NOTICE", "open", "0")
    );
    fx.unit(
        "sensor-redis.service",
        &[("ActiveState", "inactive"), ("SubState", "dead")],
    );
    fx.hourly(7200);
    let f = fx.record(&down).unwrap();
    assert_eq!(
        (f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("PAGE", "open", "1")
    );
}

/// Without a target there is nothing to check and nothing to keep: a stored line goes.
#[test]
fn an_hourly_pass_with_no_target_leaves_no_read_check_line() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n",
            s = stamp(0)
        ),
    );
    fx.write("etc/propolis/propolis.env", "");
    fx.hourly(300);
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert!(!rc.lines().any(|l| l.starts_with("R\t")), "{rc}");
    assert!(fx.log().lines().all(|l| !l.starts_with("curl ")));
}

/// A stored shell line for a target the shell and the daemon now share is not that target's
/// both line: the light pass checks it again and stores one line with role both.
#[test]
fn a_stored_shell_line_for_a_target_both_roles_share_is_checked_again_as_both() {
    let fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tshell\t403\n",
            s = stamp(0)
        ),
    );
    fx.curl_answers("403|text/plain");
    fx.pass(300);
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        3
    );
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    let lines: Vec<&str> = rc.lines().filter(|l| l.starts_with("R\t")).collect();
    assert_eq!(
        lines,
        vec![format!(
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403",
            s = stamp(300)
        )],
        "{rc}"
    );
}
