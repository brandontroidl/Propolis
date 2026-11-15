//! Runs `deploy/witness.sh light` (the witness's light pass) under a scratch root with
//! `PROPOLIS_ALERT_ROOT` and a fixed `PROPOLIS_WITNESS_NOW`, with stub `systemctl`, `journalctl`,
//! `logger`, `curl`, `setpriv`, `id`, `ss`, `sync`, `df` and `psql` on `PATH`, the real `flock`,
//! `stat`, `find` and `sha256sum`, and the shipped
//! alert library
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
const UPGRADE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/upgrade.sh");

/// The wall clock and uptime of the first pass of every case (boot `abcdef01`).
const WALL: u64 = 1_800_000_000;
const UP: u64 = 900_000;
const BOOT: &str = "abcdef01";
const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

/// Records its argv. `show` prints one block per unit asked about, from `$UNITS/<unit>`, with a
/// blank line between blocks; `is-enabled` succeeds for a unit whose file says it is enabled.
/// `SYSTEMCTL_FAIL` makes every call fail, `SYSTEMCTL_FAIL_ON` every call whose arguments hold it.
const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$STUB_LOG"
[ -z "${SYSTEMCTL_FAIL:-}" ] || exit 1
[ -z "${SYSTEMCTL_FAIL_ON:-}" ] || [[ "$*" != *"$SYSTEMCTL_FAIL_ON"* ]] || exit 1
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
    list-units)
        f="${UNITS%/units}/failed-alert-units"
        [ ! -f "$f" ] || cat "$f"
        ;;
    *) exit 1 ;;
esac
"#;

/// Records its argv and prints `$JOURNAL_FILE` when it is set. With `LOCK_PROBE` set to the lock
/// file it also records whether the state lock was free while it ran. Each read of the light
/// pass is told apart by its matches (hook, guard, journald, daemon for the daemon's runs): it
/// prints `journal.<class>` beside the units when there is one, logs the cursor it was handed,
/// copies `journal.<class>.cursor` into its cursor file as journalctl writes its last cursor,
/// and exits with `journal.<class>.rc` when there is one (124: what `timeout` returns). A run of
/// the daemon named in `journal.daemon.fresh` has logged nothing yet: a read narrowed to that
/// invocation id prints nothing.
const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'journalctl %s\n' "$*" >> "$STUB_LOG"
if [ -n "${LOCK_PROBE:-}" ]; then
    if flock -n "$LOCK_PROBE" true; then echo 'journalctl lock free' >> "$STUB_LOG"; else echo 'journalctl lock held' >> "$STUB_LOG"; fi
fi
d="${UNITS%/units}"
class="" cf=""
case " $* " in
    *" SYSLOG_IDENTIFIER=propolis-alert "*) class=hook ;;
    *" MESSAGE_ID="*) class=journald ;;
    *" _SYSTEMD_UNIT=propolis.service "*) class=daemon ;;
    *"_SYSTEMD_INVOCATION_ID="*) class=run ;;
    *" _SYSTEMD_UNIT=propolis-logrotate.service "*) class=guard ;;
esac
for a in "$@"; do
    case "$a" in --cursor-file=*) cf="${a#--cursor-file=}" ;; esac
done
if [ "$class" = daemon ] && [ -f "$d/journal.daemon.fresh" ] \
    && [[ " $* " == *" _SYSTEMD_INVOCATION_ID=$(cat "$d/journal.daemon.fresh") "* ]]; then
    class=fresh
fi
if [ -n "$cf" ] && [ -f "$cf" ]; then printf 'journalctl %s cursor %s\n' "$class" "$(cat "$cf")" >> "$STUB_LOG"; fi
[ -z "${JOURNAL_FILE:-}" ] || cat "$JOURNAL_FILE"
[ -z "$class" ] || [ ! -f "$d/journal.$class" ] || cat "$d/journal.$class"
if [ -n "$cf" ] && [ -f "$d/journal.$class.cursor" ]; then cat "$d/journal.$class.cursor" > "$cf"; fi
[ -z "$class" ] || [ ! -f "$d/journal.$class.rc" ] || exit "$(cat "$d/journal.$class.rc")"
exit 0
"#;

/// `id`: records its argv; the uid (and the same number as its gid) of an account the case named
/// in `uid.<name>` beside the units (`none`: no such account), else the real `id`.
const ID_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
name="${!#}"
printf 'id %s\n' "$*" >> "$STUB_LOG"
if { [ "${1:-}" = -u ] || [ "${1:-}" = -g ]; } && [ -f "$d/uid.$name" ]; then
    [ "$(cat "$d/uid.$name")" != none ] || exit 1
    cat "$d/uid.$name"
    exit 0
fi
exec /usr/bin/id "$@"
"#;

/// `ss`: records its argv; prints `ss.out` beside the units when there is one (empty: nothing
/// listens), else one listener on the port asked about, on every address of both families (as
/// ss shows a dual-stack wildcard socket), held by pid 4242 (every unit's MainPID in the
/// fixture) under uid 998.
const SS_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
printf 'ss %s\n' "$*" >> "$STUB_LOG"
if [ -f "$d/ss.out" ]; then cat "$d/ss.out"; exit 0; fi
port="${*##*sport = :}"
port="${port%% *}"
printf 'LISTEN 0      4096       *:%s      *:*    users:(("propolis",pid=4242,fd=9)) uid:998 ino:31337 sk:1 <->\n' "$port"
"#;

/// `sync`: fails, as a disk that refuses writes does, for a path that matches a glob listed in
/// `disk.refuses` beside the units; otherwise the real `sync`.
const SYNC_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
if [ -f "$d/disk.refuses" ]; then
    while IFS= read -r glob; do
        for a in "$@"; do
            [[ $a != $glob ]] || exit 1
        done
    done < "$d/disk.refuses"
fi
exec /usr/bin/sync "$@"
"#;

/// The daemon binary, as far as pg-exec goes: it carries pg-exec's guard string, records its
/// argv, and answers from `pg.answer` beside the units (`exit status|stdout|stderr`, `0|f|`
/// without one).
/// The hourly pass's state query (the one that reads `datfrozenxid`) is answered from `pg.state`
/// instead when there is one, printed as it is, with the status in `pg.state.rc` (0 without one).
const PROPOLIS_STUB: &str = r#"#!/usr/bin/env bash
# propolis pg-exec: DATABASE_URL is not set
d="${UNITS%/units}"
printf 'propolis %s\n' "$*" >> "$STUB_LOG"
case "$*" in
    *datfrozenxid*)
        if [ -f "$d/pg.state" ]; then
            cat "$d/pg.state"
            rc=0
            [ ! -f "$d/pg.state.rc" ] || rc="$(cat "$d/pg.state.rc")"
            exit "$rc"
        fi
        ;;
esac
answer='0|f|'
[ ! -f "$d/pg.answer" ] || answer="$(cat "$d/pg.answer")"
IFS='|' read -r rc out err <<< "$answer"
[ -z "$err" ] || printf '%s\n' "$err" >&2
[ -z "$out" ] || printf '%s\n' "$out"
exit "$rc"
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

/// The witness pushes nothing; its requests that leave the host are the read check's GETs and the
/// heartbeat URL's. Records the argv of those in the stub log as `curl ...`, its environment in
/// `curl.env` and the config file it was handed in `curl.conf`; with no `curl.answer` beside the
/// units it fails as an unreachable server does, and with one (`code|content type`) it answers
/// every GET with that, an empty body, in the `-w` form asked for, and the mode of the config file
/// goes to `curl.confmode`. The GET of the daemon's `/ready` on loopback is logged apart, as
/// `ready <url>` and its argv as `ready-argv ...`, and answered from `ready.code` (200 without
/// one; 000 fails as a closed port does, 000t as a request that timed out) and `ready.body`.
const CURL_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
args="$*"
out="" conf="" url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
        -K) conf="$2"; shift ;;
        http://* | https://*) url="$1" ;;
    esac
    shift
done
case "$url" in
    */ready)
        printf 'ready %s\n' "$url" >> "$STUB_LOG"
        printf 'ready-argv %s\n' "$args" >> "$STUB_LOG"
        code=200
        [ ! -f "$d/ready.code" ] || code="$(cat "$d/ready.code")"
        if [ "$code" = 000 ]; then printf '000'; exit 7; fi
        if [ "$code" = 000t ]; then printf '000'; exit 28; fi
        if [ -f "$d/ready.body" ]; then cat "$d/ready.body" > "$out"; else printf '{"status":"ok"}' > "$out"; fi
        printf '%s' "$code"
        exit 0
        ;;
esac
printf 'curl %s\n' "$args" >> "$STUB_LOG"
env | sed 's/^/curl-env /' >> "$d/curl.env"
[ -z "$conf" ] || cat "$conf" >> "$d/curl.conf"
[ -z "$conf" ] || stat -c %a "$conf" > "$d/curl.confmode"
[ -f "$d/curl.answer" ] || exit 7
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

/// The daemon's database URL in the cases that give it one; its password must never reach a
/// command line.
const DB_URL: &str = "postgres://propolis:db-s3cret@127.0.0.1:5432/propolis";

/// What psql says through pg-exec when the server refuses the connection.
const PG_REFUSED: &str =
    "2||psql: error: connection to server at \"127.0.0.1\", port 5432 failed: Connection refused";

/// Records its argv and runs the command after `--` as the caller; it exits 1 instead when its
/// arguments hold `--reuid=$SETPRIV_FAIL`, as a drop that fails does. A command run through
/// `/usr/bin/env PATH=/usr/bin:/bin` gets this directory in front of that PATH, since the stubs
/// stand in for the system's programs.
const SETPRIV_STUB: &str = r#"#!/usr/bin/env bash
printf 'setpriv %s\n' "$*" >> "$STUB_LOG"
[ -z "${SETPRIV_FAIL:-}" ] || [[ " $* " != *" --reuid=$SETPRIV_FAIL "* ]] || exit 1
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
if [ "${1:-}" = /usr/bin/env ] && [ "${2:-}" = PATH=/usr/bin:/bin ]; then
    shift 2
    set -- /usr/bin/env "PATH=${0%/*}:/usr/bin:/bin" "$@"
fi
exec "$@"
"#;

/// `df -B1 --output=size,avail,itotal,iavail,target -- PATH`: records its argv and prints GNU df's
/// header and one line: the answer `df.map` beside the units gives PATH (lines `path<TAB>answer`,
/// the path as on the host, without the test root), else `df.answer`
/// (`size avail itotal iavail target`), else a roomy filesystem mounted on `/`. `hang` exits 124,
/// as `timeout` does when it cuts off a df stuck on a mount that does not answer.
const DF_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
printf 'df %s\n' "$*" >> "$STUB_LOG"
ans="100000000000 60000000000 6000000 5000000 /"
[ ! -f "$d/df.answer" ] || ans="$(cat "$d/df.answer")"
rel="${!#}"
rel="${rel#"${PROPOLIS_ALERT_ROOT:-}"}"
if [ -f "$d/df.map" ]; then
    while IFS=$'\t' read -r p a; do [ "$p" != "$rel" ] || ans="$a"; done < "$d/df.map"
fi
[ "$ans" != hang ] || exit 124
echo "     1B-blocks        Avail  Inodes   IFree Mounted on"
echo "$ans"
"#;

/// `psql`, as the hourly pass runs it as the postgres account for `SHOW data_directory`: records
/// its argv, its HOME and its PATH, prints `psql.out` beside the units (a Debian data directory
/// without one) and an error line on stderr, which must never be kept, and exits with `psql.rc`
/// (0 without one).
const PSQL_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
printf 'psql %s HOME=%s PATH=%s\n' "$*" "${HOME:-unset}" "${PATH:-unset}" >> "$STUB_LOG"
echo 'psql: warning: s3cret-error-text' >&2
if [ -f "$d/psql.out" ]; then cat "$d/psql.out"; else echo /var/lib/postgresql/16/main; fi
[ ! -f "$d/psql.rc" ] || exit "$(cat "$d/psql.rc")"
"#;

/// `stat`, installed by the cases that place stores on filesystems of their own or date a file's
/// last change: an answer from `stat.map` beside the units (lines `path<TAB>L<TAB>format<TAB>value`,
/// the path as on the host, L `-L` for a call that follows links and `-` for one that does not),
/// else the real `stat`.
const STAT_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
l=- fmt="" prev=""
for a in "$@"; do
    [ "$a" != -L ] || l=-L
    [ "$prev" != -c ] || fmt="$a"
    prev="$a"
done
rel="${!#}"
rel="${rel#"${PROPOLIS_ALERT_ROOT:-}"}"
if [ -f "$d/stat.map" ]; then
    while IFS=$'\t' read -r p f c v; do
        if [ "$p" = "$rel" ] && [ "$f" = "$l" ] && [ "$c" = "$fmt" ]; then
            printf '%s\n' "$v"
            exit 0
        fi
    done < "$d/stat.map"
fi
exec /usr/bin/stat "$@"
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
            ("id", ID_STUB),
            ("ss", SS_STUB),
            ("sync", SYNC_STUB),
            ("df", DF_STUB),
            ("psql", PSQL_STUB),
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
        // Every unit's main process (pid 4242) runs the binary it started with.
        std::fs::create_dir_all(fx.p("proc/4242")).unwrap();
        std::os::unix::fs::symlink("/usr/local/bin/propolis", fx.p("proc/4242/exe")).unwrap();
        fx
    }

    /// What `df` answers for each of these host paths (`size avail itotal iavail target`, or
    /// `hang`).
    fn df_map(&self, entries: &[(&str, &str)]) {
        let text: String = entries.iter().map(|(p, a)| format!("{p}\t{a}\n")).collect();
        self.stub_file("df.map", &text);
    }

    /// Installs the `stat` stub with these answers: `(host path, -L or -, format, value)`.
    fn stat_map(&self, entries: &[(&str, &str, &str, &str)]) {
        write_exec(&self.bin.join("stat"), STAT_STUB);
        let text: String = entries
            .iter()
            .map(|(p, l, f, v)| format!("{p}\t{l}\t{f}\t{v}\n"))
            .collect();
        self.stub_file("stat.map", &text);
    }

    /// Places each of these host directories (made under the root) on a filesystem of its own,
    /// device `dev`, as `stat -L` reports it.
    fn filesystems(&self, dirs: &[(&str, u32)]) {
        let entries: Vec<(String, u32)> = dirs.iter().map(|(d, n)| (d.to_string(), *n)).collect();
        for (d, _) in &entries {
            std::fs::create_dir_all(self.p(d.trim_start_matches('/'))).unwrap();
        }
        let values: Vec<String> = entries
            .iter()
            .map(|(_, n)| format!("{n} directory"))
            .collect();
        let map: Vec<(&str, &str, &str, &str)> = entries
            .iter()
            .zip(values.iter())
            .map(|((d, _), v)| (d.as_str(), "-L", "%d %F", v.as_str()))
            .collect();
        self.stat_map(&map);
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
            ("MainPID", "4242"),
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
            .env_remove("DATABASE_URL")
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

    /// A file beside the units, where the stubs read what to answer.
    fn stub_file(&self, name: &str, body: &str) {
        std::fs::write(self.dir.path().join(name), body).unwrap();
    }

    /// A database for the daemon: DATABASE_URL in propolis.env (with the push target), the daemon
    /// binary's stub installed where pg-exec runs from, and what psql answers through it
    /// (`exit status|stdout|stderr`).
    fn database(&self, answer: &str) {
        self.write(
            "etc/propolis/propolis.env",
            &format!(
                "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
                 DATABASE_URL={DB_URL}\n"
            ),
        );
        write_exec(&self.p("usr/local/bin/propolis"), PROPOLIS_STUB);
        std::fs::set_permissions(
            self.p("usr/local/bin"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        self.stub_file("pg.answer", answer);
    }

    /// The `propolis` account, uid 998, as `id` reports it.
    fn daemon_account(&self) {
        self.stub_file("uid.propolis", "998\n");
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

// ---- the light pass's probes ------------------------------------------------------------------

/// The daemon's own journal line for a database it cannot reach, as journald keeps it.
const CONNECT_LINE: &str = "2026-11-15T08:00:00.000000Z ERROR propolis: failed to connect to PostgreSQL error=pool timed out\n";

/// What `systemctl show` says of a daemon that failed and waits to be restarted.
fn restarting_daemon(fx: &Fx) {
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "activating"),
            ("SubState", "auto-restart"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Restart", "on-failure"),
            ("NRestarts", "1"),
        ],
    );
}

/// The stub log from now on only: what one pass does.
fn clear_log(fx: &Fx) {
    std::fs::write(&fx.log, b"").unwrap();
}

/// Every file under the root's alerting directories, with its text.
fn state_text(fx: &Fx) -> String {
    let mut out = String::new();
    for p in fx.state_files() {
        out.push_str(&String::from_utf8_lossy(
            &std::fs::read(&p).unwrap_or_default(),
        ));
    }
    out
}

/// A database outage reaches the daemon first: the failure hook records the daemon's failure
/// before any pass has seen the database fail. The probe runs before the units are judged, and
/// while it fails with a database cause and the daemon's last run logged that it could not
/// connect (read by that run's own fields), the daemon's record waits pending with the
/// database's cause, then folds under db-unreachable when that opens on the second pass: one
/// PAGE, on the ledger stage. A folded child sends nothing while its parent is open, even once
/// the database answers again; a daemon still restarting half an hour after db-unreachable
/// resolved opens as an incident of its own with systemd's cause, and not before.
#[test]
fn a_daemon_failure_the_hook_saw_first_waits_for_db_unreachable_and_folds_under_it() {
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    restarting_daemon(&fx);
    fx.hook_fires("propolis.service", 0);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "pending");

    clear_log(&fx);
    fx.pass(300);
    let log = fx.log();
    let probe = log.find("propolis pg-exec").expect(&log);
    let sample = log.find("systemctl show").expect(&log);
    assert!(probe < sample, "the probe runs first:\n{log}");
    assert!(
        log.contains(&format!(
            "_SYSTEMD_UNIT=propolis.service _UID=998 _SYSTEMD_INVOCATION_ID={INVOCATION}"
        )),
        "{log}"
    );
    let db = fx.record("db:local").unwrap();
    assert_eq!(
        (db[7].as_str(), db[11].as_str()),
        ("pending", "db.unreachable")
    );
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[3].as_str(), d[7].as_str(), d[11].as_str(), d[13].as_str()),
        ("daemon-down", "pending", "db.unreachable", "-")
    );

    fx.pass(600);
    let db = fx.record("db:local").unwrap();
    assert_eq!(
        (
            db[3].as_str(),
            db[4].as_str(),
            db[6].as_str(),
            db[7].as_str(),
            db[29].as_str()
        ),
        ("db-unreachable", "ledger", "PAGE", "open", "1")
    );
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!((d[7].as_str(), d[13].as_str()), ("pending", db[1].as_str()));
    assert!(d[30].split(',').any(|f| f == "folded"), "{}", d[30]);
    assert_eq!(d[29], "0", "the daemon's record sends nothing of its own");
    let log = fx.log();
    assert!(
        !log.contains("db-s3cret"),
        "the database URL on a command line:\n{log}"
    );
    assert!(
        !state_text(&fx).contains("Connection refused"),
        "psql's words kept"
    );

    fx.stub_file("pg.answer", "0|f|");
    fx.pass(900);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[13].as_str(), d[29].as_str()),
        ("pending", db[1].as_str(), "0"),
        "folded while its parent is open"
    );
    assert_eq!(
        fx.record("db:local").unwrap()[7],
        "open",
        "one answer is not two"
    );
    fx.pass(1200);
    let db = fx.record("db:local").unwrap();
    assert_eq!((db[7].as_str(), db[22].as_str()), ("resolved", "db2"));
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "pending");
    fx.pass(1200 + 1500);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[29].as_str()),
        ("pending", "0"),
        "not before half an hour"
    );
    fx.pass(1200 + 1800);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (
            d[7].as_str(),
            d[11].as_str(),
            d[13].as_str(),
            d[29].as_str()
        ),
        ("open", "proc.exit:1", "-", "1")
    );
    assert!(!d[30].split(',').any(|f| f == "folded"), "{}", d[30]);
}

/// The daemon's crash loop in a fresh attempt: while it tries to connect it is active under a new
/// invocation id that has logged nothing yet. The tie reads its last completed run instead, the
/// newest connect or start line in the daemon's own journal, so its failure still waits for
/// db-unreachable and folds under it with nothing sent of its own.
#[test]
fn a_daemon_failure_in_a_fresh_attempt_folds_under_db_unreachable_by_its_last_completed_run() {
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.daemon_account();
    fx.stub_file(
        "journal.daemon",
        &format!(
            "2026-11-15T07:59:00.000000Z INFO propolis: starting unified daemon\n{CONNECT_LINE}"
        ),
    );
    fx.stub_file("journal.daemon.fresh", INVOCATION);
    fx.stub_file("ss.out", "");
    fx.stub_file("ready.code", "000");
    let attempt = |fx: &Fx, t: u64, nr: u64| {
        fx.unit(
            "propolis.service",
            &[
                ("Restart", "on-failure"),
                ("NRestarts", &nr.to_string()),
                ("ActiveEnterTimestampMonotonic", &entered(t, 3)),
            ],
        );
    };
    attempt(&fx, 0, 1);
    fx.hook_fires("propolis.service", 0);
    attempt(&fx, 300, 9);
    fx.pass(300);
    assert!(
        fx.log()
            .contains("_SYSTEMD_UNIT=propolis.service _UID=998 --since=-15min"),
        "{}",
        fx.log()
    );
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[11].as_str(), d[29].as_str()),
        ("pending", "db.unreachable", "0")
    );
    attempt(&fx, 600, 17);
    fx.pass(600);
    let db = fx.record("db:local").unwrap();
    assert_eq!(db[7], "open");
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[13].as_str(), d[29].as_str()),
        ("pending", db[1].as_str(), "0")
    );
    assert!(d[30].split(',').any(|f| f == "folded"), "{}", d[30]);

    // A start line newer than the connect line: the last run connected, so there is no tie.
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.daemon_account();
    fx.stub_file(
        "journal.daemon",
        &format!(
            "{CONNECT_LINE}2026-11-15T08:01:00.000000Z INFO propolis: starting unified daemon\n"
        ),
    );
    fx.stub_file("journal.daemon.fresh", INVOCATION);
    fx.stub_file("ss.out", "");
    attempt(&fx, 0, 1);
    fx.hook_fires("propolis.service", 0);
    attempt(&fx, 300, 9);
    fx.pass(300);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!((d[7].as_str(), d[13].as_str()), ("open", "-"));
}

/// A folded daemon-down waits for its parent whatever the tie says meanwhile: a journal read that
/// lapses mid-outage leaves it pending and folded. Once the database answers and the daemon is
/// ready again it opens nothing, and when db-unreachable resolves the record is dropped as a
/// healed restart.
#[test]
fn a_folded_daemon_down_stays_pending_while_its_parent_is_open_and_heals_once_it_resolves() {
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    restarting_daemon(&fx);
    fx.hook_fires("propolis.service", 0);
    fx.pass(300);
    fx.pass(600);
    let db = fx.record("db:local").unwrap();
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!((d[7].as_str(), d[13].as_str()), ("pending", db[1].as_str()));

    fx.stub_file("journal.daemon", "");
    fx.pass(900);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[13].as_str(), d[29].as_str()),
        ("pending", db[1].as_str(), "0"),
        "the tie lapsed while the parent is open"
    );
    assert_eq!(fx.record("db:local").unwrap()[7], "open");

    fx.stub_file("pg.answer", "0|f|");
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            ("NRestarts", "5"),
            ("ActiveEnterTimestampMonotonic", &entered(1200, 60)),
        ],
    );
    fx.pass(1200);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!((d[7].as_str(), d[29].as_str()), ("pending", "0"));
    fx.pass(1500);
    let db = fx.record("db:local").unwrap();
    assert_eq!((db[7].as_str(), db[22].as_str()), ("resolved", "db2"));
    assert!(
        fx.record("unit:propolis.service").is_none(),
        "{:?}",
        fx.records()
    );
    assert!(
        fx.meta("healed").unwrap_or_default().starts_with("1/"),
        "{:?}",
        fx.meta("healed")
    );
}

/// A daemon-down that opened before its parent and folded under it by the late-parent rule
/// becomes its own incident again, counted once more, when it is still failing half an hour
/// after db-unreachable resolved, and not before.
#[test]
fn a_folded_open_daemon_down_still_failing_half_an_hour_after_its_parent_resolves_opens_on_its_own()
{
    let fx = Fx::new();
    fx.database("0|f|");
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    fx.stub_file("pg.answer", PG_REFUSED);
    fx.pass(600);
    fx.pass(900);
    let db = fx.record("db:local").unwrap();
    assert_eq!(fx.record("unit:propolis.service").unwrap()[13], db[1]);
    fx.stub_file("pg.answer", "0|f|");
    fx.pass(1200);
    fx.pass(1500);
    assert_eq!(fx.record("db:local").unwrap()[7], "resolved");
    fx.pass(1500 + 1500);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!((d[13].as_str(), d[29].as_str()), (db[1].as_str(), "1"));
    fx.pass(1500 + 1800);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[13].as_str(), d[29].as_str()),
        ("open", "-", "2")
    );
}

/// A folded daemon-down is not made its own incident again while the daemon runs: one that is up
/// but answers /ready 503 half an hour after db-unreachable resolved is daemon-degraded's to
/// report, and the folded record stays as it is.
#[test]
fn a_folded_open_daemon_down_whose_daemon_runs_again_is_not_reopened_on_its_own() {
    let fx = Fx::new();
    fx.database("0|f|");
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    fx.stub_file("pg.answer", PG_REFUSED);
    fx.pass(600);
    fx.pass(900);
    let db = fx.record("db:local").unwrap();
    assert_eq!(fx.record("unit:propolis.service").unwrap()[13], db[1]);
    fx.stub_file("pg.answer", "0|f|");
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            ("NRestarts", "1"),
            ("ActiveEnterTimestampMonotonic", &entered(1200, 30)),
        ],
    );
    fx.stub_file("ready.code", "503");
    fx.pass(1200);
    fx.pass(1500);
    assert_eq!(fx.record("db:local").unwrap()[7], "resolved");
    fx.pass(1500 + 1800);
    fx.pass(1500 + 2100);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[13].as_str(), d[29].as_str()),
        ("open", db[1].as_str(), "1"),
        "{d:?}"
    );
}

/// The late-parent rule holds for a daemon caught in a fresh attempt too: an open daemon-down
/// whose daemon is active again for a few seconds, between two failed connects, still takes
/// db-unreachable as its parent, with the database's cause, and counts nothing more.
#[test]
fn an_open_daemon_down_in_a_fresh_attempt_still_takes_db_unreachable_as_its_late_parent() {
    let fx = Fx::new();
    fx.database("0|f|");
    fx.daemon_account();
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!((d[7].as_str(), d[29].as_str()), ("open", "1"));
    fx.stub_file("pg.answer", PG_REFUSED);
    fx.stub_file(
        "journal.daemon",
        &format!(
            "2026-11-15T07:59:00.000000Z INFO propolis: starting unified daemon\n{CONNECT_LINE}"
        ),
    );
    fx.stub_file("journal.daemon.fresh", INVOCATION);
    fx.stub_file("ss.out", "");
    fx.stub_file("ready.code", "000");
    for (t, restarts) in [(600u64, 9u64), (900, 17)] {
        fx.unit(
            "propolis.service",
            &[
                ("Restart", "on-failure"),
                ("NRestarts", &restarts.to_string()),
                ("ActiveEnterTimestampMonotonic", &entered(t, 3)),
            ],
        );
        fx.pass(t);
    }
    let db = fx.record("db:local").unwrap();
    assert_eq!(db[7], "open");
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (
            d[7].as_str(),
            d[11].as_str(),
            d[13].as_str(),
            d[29].as_str()
        ),
        ("open", "db.unreachable", db[1].as_str(), "1"),
        "{d:?}"
    );
}

/// A daemon-down that opened before the database was seen to fail takes db-unreachable as its
/// parent once that opens, with the database's cause: no change is counted for it, and no
/// reminder of its own comes due.
#[test]
fn a_daemon_down_already_open_takes_db_unreachable_as_its_late_parent_and_counts_nothing_more() {
    let fx = Fx::new();
    fx.database("0|f|");
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[11].as_str(), d[29].as_str()),
        ("open", "proc.exit:1", "1")
    );
    fx.stub_file("pg.answer", PG_REFUSED);
    fx.pass(600);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[13], "-");
    fx.pass(900);
    let db = fx.record("db:local").unwrap();
    assert_eq!(db[7], "open");
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (
            d[7].as_str(),
            d[11].as_str(),
            d[13].as_str(),
            d[19].as_str(),
            d[29].as_str()
        ),
        ("open", "db.unreachable", db[1].as_str(), "-", "1")
    );
    fx.pass(900 + 3600);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[29], "1");
}

/// /ready 503 while root's probe reaches the database is daemon-degraded (ACT, cause ready.db)
/// after two passes, and two ready answers five minutes apart resolve it; `"gave_up"` in the body
/// makes the cause ready.gave_up. A 503 while the probe fails too opens nothing new:
/// db-unreachable carries it. A 503 while the probe cannot run at all (tool.exec) still opens
/// daemon-degraded, since the daemon's answer is then the only word on the database, and the
/// probe's tool.exec never opens db-unreachable: three of them open tool-unusable.
#[test]
fn a_ready_503_opens_daemon_degraded_unless_the_probe_fails_too_and_counts_when_the_probe_cannot_run()
 {
    let fx = Fx::new();
    fx.database("0|f|");
    fx.stub_file("ready.code", "503");
    fx.stub_file("ready.body", "{\"status\":\"unavailable\"}");
    fx.pass(0);
    assert_eq!(fx.record("ready:local").unwrap()[7], "pending");
    fx.pass(300);
    let f = fx.record("ready:local").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        ("daemon-degraded", "intake", "ACT", "open", "ready.db", "1")
    );
    assert!(
        fx.log().contains("ready http://127.0.0.1:8080/ready"),
        "{}",
        fx.log()
    );
    fx.stub_file("ready.code", "200");
    fx.pass(600);
    assert_eq!(fx.record("ready:local").unwrap()[7], "open");
    fx.pass(900);
    let f = fx.record("ready:local").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "ready2"));

    let fx = Fx::new();
    fx.database("0|f|");
    fx.stub_file("ready.code", "503");
    fx.stub_file(
        "ready.body",
        "{\"status\":\"unavailable\",\"gave_up\":[\"review\"]}",
    );
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("ready:local").unwrap()[11], "ready.gave_up");

    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.stub_file("ready.code", "503");
    fx.pass(0);
    fx.pass(300);
    assert!(fx.record("ready:local").is_none());
    assert_eq!(fx.record("db:local").unwrap()[7], "open");

    let fx = Fx::new();
    fx.database("127||propolis pg-exec: cannot run psql: No such file or directory");
    fx.stub_file("ready.code", "503");
    fx.pass(0);
    fx.pass(300);
    let f = fx.record("ready:local").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "ready.db"));
    fx.pass(600);
    assert!(fx.record("db:local").is_none());
    let t = fx.record("tool:pg").unwrap();
    assert_eq!(
        (t[3].as_str(), t[6].as_str(), t[7].as_str(), t[11].as_str()),
        ("tool-unusable", "NOTICE", "open", "tool.exec")
    );
}

/// A daemon up for half an hour whose console does not answer /ready is down (cause
/// net.connect) on the second such pass, and daemon-down resolves only on two ready answers five
/// minutes apart (ready2), not on ten quiet minutes of running. One up for under half an hour is
/// still starting: nothing opens.
#[test]
fn a_daemon_up_half_an_hour_without_a_ready_answer_is_down_and_resolves_only_by_ready_twice() {
    let fx = Fx::new();
    fx.stub_file("ready.code", "000");
    fx.pass(0);
    assert!(fx.record("unit:propolis.service").is_none());
    fx.pass(300);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (f[3].as_str(), f[7].as_str(), f[11].as_str(), f[29].as_str()),
        ("daemon-down", "open", "net.connect", "1")
    );
    fx.pass(1200);
    assert_eq!(
        fx.record("unit:propolis.service").unwrap()[7],
        "open",
        "running is not ready"
    );
    fx.stub_file("ready.code", "200");
    fx.pass(1500);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "open");
    fx.pass(1800);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "ready2"));

    let fx = Fx::new();
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            ("ActiveEnterTimestampMonotonic", &entered(0, 600)),
        ],
    );
    fx.stub_file("ready.code", "000");
    fx.pass(0);
    fx.pass(300);
    assert!(
        fx.record("unit:propolis.service").is_none(),
        "{:?}",
        fx.records()
    );
}

/// The database kinds wait out the first fifteen minutes of uptime, when a database is still
/// recovering from the boot, and a maintenance marker of planned work (reason manual); an
/// upgrade's marker does not hold them.
#[test]
fn db_unreachable_waits_out_fifteen_minutes_of_uptime_and_a_manual_marker() {
    let mut fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.setenv("PROPOLIS_WITNESS_NOW", &early(0));
    fx.pass(0);
    fx.setenv("PROPOLIS_WITNESS_NOW", &early(250));
    fx.pass(250);
    assert_eq!(fx.record("db:local").unwrap()[7], "pending");
    fx.setenv("PROPOLIS_WITNESS_NOW", &early(400));
    fx.pass(400);
    assert_eq!(fx.record("db:local").unwrap()[7], "open");

    for (reason, state) in [("manual", "pending"), ("upgrade", "open")] {
        let fx = Fx::new();
        fx.database(PG_REFUSED);
        fx.write(
            "run/propolis-witness/maintenance",
            &format!(
                "#maintenance v1 g=1\nX\t{}\t{BOOT}\t{reason}\n",
                WALL + 3600
            ),
        );
        fx.pass(0);
        fx.pass(300);
        assert_eq!(fx.record("db:local").unwrap()[7], state, "{reason}");
    }
}

/// The address the daemon's console binds is asked on loopback only: 0.0.0.0 as 127.0.0.1, [::]
/// as [::1], and any other address is not asked at all, the check reading unknown (a partial
/// pass) instead.
#[test]
fn ready_is_asked_only_on_a_loopback_address_and_any_other_reads_unknown() {
    let fx = Fx::new();
    for (bind, asked) in [
        ("0.0.0.0:9090", Some("http://127.0.0.1:9090/ready")),
        ("[::]:8080", Some("http://[::1]:8080/ready")),
        ("192.0.2.10:8080", None),
        ("127.0.0.256:8080", None),
    ] {
        fx.write(
            "etc/propolis/propolis.env",
            &format!(
                "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\nPROPOLIS_CONSOLE_BIND={bind}\n"
            ),
        );
        clear_log(&fx);
        fx.pass(0);
        let log = fx.log();
        match asked {
            Some(url) => assert!(log.contains(&format!("ready {url}\n")), "{bind}: {log}"),
            None => {
                assert!(!log.contains("ready "), "{bind}: {log}");
                assert!(
                    fx.observe_text().contains("P\tready\t")
                        && fx.observe_text().contains("\tunknown\tconfig.invalid\t"),
                    "{}",
                    fx.observe_text()
                );
                assert!(
                    fx.read("run/propolis-witness/heartbeat")
                        .contains("\tpartial")
                );
            }
        }
    }
}

/// The heartbeat URL (alert.env over propolis.env) is asked once after a clean pass, through a
/// curl config file, never on a command line, in curl's environment or in any state file, and its
/// result is kept as a stamp and a word. A pass whose core failed skips it, and it resumes only
/// after 30 clean minutes; an open alert-path and a transition pending over 15 minutes skip it too;
/// a URL that is not https is never asked.
#[test]
fn the_heartbeat_url_is_skipped_under_each_gate_rule_and_resumes_after_thirty_clean_minutes() {
    let mut fx = Fx::new();
    let secret = "hb-s3cret-0123";
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_WITNESS_HEARTBEAT_URL=http://hc.example.invalid/plain\n",
    );
    fx.write(
        "etc/propolis/alert.env",
        &format!("PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/{secret}\n"),
    );
    fx.curl_answers("200|text/plain");
    let pings = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    fx.pass(0);
    assert_eq!(pings(&fx), 1, "{}", fx.log());
    assert_eq!(
        fx.meta("hb_last").as_deref(),
        Some(format!("{}/ok", stamp(0)).as_str())
    );
    let conf = std::fs::read_to_string(fx.dir.path().join("curl.conf")).unwrap();
    assert!(
        conf.contains(&format!("https://hc.example.invalid/ping/{secret}")),
        "{conf}"
    );
    assert!(!fx.log().contains(secret), "{}", fx.log());
    assert!(!fx.curl_env().contains(secret));
    assert!(!state_text(&fx).contains(secret));
    let ping = fx
        .log()
        .lines()
        .find(|l| l.starts_with("curl "))
        .unwrap()
        .to_string();
    assert!(ping.starts_with("curl -q -K "), "{ping}");
    assert!(
        ping.contains("--proto =https") && ping.contains("--max-redirs 0"),
        "{ping}"
    );
    assert_eq!(
        std::fs::read_to_string(fx.dir.path().join("curl.confmode"))
            .unwrap()
            .trim(),
        "600"
    );

    fx.setenv("SYSTEMCTL_FAIL", "1");
    fx.pass(300);
    assert_eq!(pings(&fx), 1);
    assert_eq!(
        fx.meta("hb_skip").as_deref(),
        Some(format!("{}/core", stamp(300)).as_str())
    );
    fx.env.clear();
    fx.pass(1800);
    assert_eq!(pings(&fx), 1, "30 clean minutes have not passed");
    fx.pass(2100);
    assert_eq!(pings(&fx), 2);

    let open = with_field(
        &with_field(
            &with_field(
                &hook_record("w#1", "propolis.service", "PAGE", "open", 2000, "-"),
                2,
                "alert:shell",
            ),
            3,
            "alert-path",
        ),
        4,
        "alert",
    );
    fx.incidents(&[open]);
    // The alert the hook could not deliver is still waiting, so the path is still broken.
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        "1800000000 1 1800000000\n",
    );
    fx.pass(2400);
    assert_eq!(pings(&fx), 2);
    assert_eq!(
        fx.meta("hb_skip").as_deref(),
        Some(format!("{}/alert-path", stamp(2400)).as_str())
    );

    let waiting = with_field(
        &with_field(
            &hook_record("w#2", "sensor-ssh.service", "PAGE", "open", 2400, "0"),
            26,
            "open",
        ),
        27,
        &stamp(2400),
    );
    fx.incidents(&[waiting]);
    fx.pass(2400 + 1200);
    assert_eq!(pings(&fx), 2);
    assert_eq!(
        fx.meta("hb_skip").as_deref(),
        Some(format!("{}/pending", stamp(3600)).as_str())
    );

    let fx = Fx::new();
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=http://hc.example.invalid/ping\n",
    );
    fx.curl_answers("200|text/plain");
    fx.pass(0);
    assert_eq!(pings(&fx), 0);
    assert!(
        fx.log().contains("heartbeat URL not requested"),
        "{}",
        fx.log()
    );
}

/// On a host where psql cannot run (a PGDG layout the unit does not grant), the probe is
/// tool.exec on every pass: the ping is skipped while that is a check error nobody has recorded,
/// and once tool-unusable records it the ping resumes after 30 clean minutes, so the operator's
/// dead-man check does not fire every day for a known limitation.
#[test]
fn a_standing_tool_exec_stops_skipping_the_ping_once_tool_unusable_is_open() {
    let fx = Fx::new();
    fx.database("127||propolis pg-exec: cannot run psql: No such file or directory");
    let mut env = fx.read("etc/propolis/propolis.env");
    env.push_str("PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n");
    fx.write("etc/propolis/propolis.env", &env);
    fx.curl_answers("200|text/plain");
    let pings = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    assert_eq!(fx.record("tool:pg").unwrap()[7], "open");
    assert_eq!(pings(&fx), 0);
    assert_eq!(
        fx.meta("hb_skip").as_deref(),
        Some(format!("{}/check", stamp(300)).as_str())
    );
    fx.pass(1800);
    assert_eq!(pings(&fx), 0);
    fx.pass(2100);
    assert_eq!(pings(&fx), 1);
}

/// A journal class reads to the end of its entries and keeps only the lines that carry a pattern
/// before it cuts anything, so a flood of 2 MiB of other lines from the same unit neither hides a
/// guard line past the first MiB nor holds its cursor back; the cursor journalctl leaves is kept
/// 0600 and handed back on the next pass. A read cut off by its time limit is unknown, leaves the
/// cursor where it was, starts again without it on the second cut in a row (the walk is told), and
/// on the third opens tool-unusable. No line of it is kept anywhere.
#[test]
fn a_journal_class_finds_its_line_past_a_flood_keeps_its_cursor_and_a_cut_read_is_unknown() {
    let fx = Fx::new();
    let mut flood = String::with_capacity(2_200_000);
    while flood.len() < 2 * 1024 * 1024 {
        flood.push_str("propolis-logrotate: rotating /var/log/propolis/sensor.log as planned\n");
    }
    flood.push_str(
        "propolis-logrotate-guard: skipping rotation of /var/log/propolis/ssh.log: reader behind\n",
    );
    fx.stub_file("journal.guard", &flood);
    let cursor = "s=0123456789abcdef0123456789abcdef;i=1f;b=fedcba9876543210fedcba9876543210;m=2a;t=5e1;x=9c";
    fx.stub_file("journal.guard.cursor", &format!("{cursor}\n"));
    fx.pass(0);
    assert!(
        fx.meta("jlines").unwrap_or_default().contains("guard:1"),
        "{:?}",
        fx.meta("jlines")
    );
    let kept = fx.p("var/lib/propolis/witness/jcursor/guard");
    assert_eq!(
        std::fs::read_to_string(&kept).unwrap(),
        format!("{cursor}\n")
    );
    assert_eq!(mode_of(&kept), 0o600);
    fx.pass(300);
    assert!(
        fx.log()
            .contains(&format!("journalctl guard cursor {cursor}")),
        "{}",
        fx.log()
    );
    assert!(fx.meta("jlines").unwrap_or_default().contains("guard:2"));
    assert!(fx.read("run/propolis-witness/heartbeat").contains("\tok"));

    fx.stub_file("journal.guard.rc", "124");
    fx.stub_file("journal.guard.cursor", "s=ffff;i=1\n");
    fx.pass(600);
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("\tpartial")
    );
    assert_eq!(
        std::fs::read_to_string(&kept).unwrap(),
        format!("{cursor}\n")
    );
    fx.pass(900);
    assert!(
        !kept.exists(),
        "the second cut in a row starts the class again"
    );
    assert_eq!(
        fx.meta("jskip").as_deref(),
        Some(format!("{}/guard", stamp(900)).as_str())
    );
    fx.pass(1200);
    assert_eq!(fx.record("tool:journal:guard").unwrap()[7], "open");
    assert!(!state_text(&fx).contains("rotating /var/log"));
}

/// The hook class keeps an entry only when journald's own _SYSTEMD_UNIT field names a failure
/// hook, and matches only the first line of its message: an alert the hook logged in full counts
/// as one failure alert however its quoted journal lines read, and a line in the same words from
/// another unit, or a field name inside a message, counts as nothing. The legacy hook's own
/// undelivered line opens alert-path (PAGE) at once, cause from its reason, and it resolves once
/// its undelivered file is gone, no such line comes, and an alert went out after the open.
#[test]
fn the_hook_class_reads_the_unit_from_each_entry_and_only_the_hooks_own_line_opens_alert_path() {
    let fx = Fx::new();
    let body = "{\"__CURSOR\":\"s=2\",\"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\",\
        \"MESSAGE\":\"sensor-ssh.service entered the failed state on h at t.\\n\\nLast journal lines:\\n\
        x could not post to ntfy; alert follows\\n{\\\"_SYSTEMD_UNIT\\\":\\\"propolis-alert@x\\\",\
        \\\"MESSAGE\\\":\\\"y; alert follows\\\"}\"}\n";
    let other = "{\"__CURSOR\":\"s=3\",\"_SYSTEMD_UNIT\":\"sensor-ssh.service\",\
        \"MESSAGE\":\"could not post to ntfy; alert follows\"}\n";
    let inner = "{\"__CURSOR\":\"s=4\",\"_SYSTEMD_UNIT\":\"sensor-http.service\",\
        \"MESSAGE\":\"x\\\",\\\"_SYSTEMD_UNIT\\\":\\\"propolis-alert@y\\\",\\\"MESSAGE\\\":\\\"could not post to ntfy; alert follows\"}\n";
    fx.stub_file("journal.hook", &format!("{body}{other}{inner}"));
    fx.pass(0);
    assert!(fx.record("alert:shell").is_none(), "{:?}", fx.records());
    assert_eq!(
        fx.meta("jlines").as_deref(),
        Some("undelivered:0,journal:1,guard:0,suppressed:0")
    );
    assert!(
        fx.log()
            .contains("-o json --output-fields=_SYSTEMD_UNIT,MESSAGE"),
        "{}",
        fx.log()
    );

    let real = "{\"__CURSOR\":\"s=5\",\"MESSAGE\":\"curl is not installed, so this host cannot push alerts; install it; alert follows\",\
        \"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\"}\n";
    fx.stub_file("journal.hook", real);
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        "1800000000 1 1800000000\n",
    );
    fx.pass(300);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        ("alert-path", "alert", "PAGE", "open", "nocurl", "1")
    );
    fx.stub_file("journal.hook", "");
    fx.pass(600);
    assert_eq!(
        fx.record("alert:shell").unwrap()[7],
        "open",
        "its file is still there"
    );
    std::fs::remove_file(fx.p("run/propolis-alert/undelivered/sensor-ssh.service")).unwrap();
    fx.pass(900);
    assert_eq!(
        fx.record("alert:shell").unwrap()[7],
        "open",
        "a file gone is not an alert delivered"
    );
    delivered_at(&fx, "sensor-ssh.service", 1000);
    fx.pass(1200);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "sent2xx"));
}

/// The legacy hook's delivered stamp for `unit` (`/run/propolis-alert/<unit>`, which
/// deploy/alert.sh touches when an alert goes out), dated at time `t`.
fn delivered_at(fx: &Fx, unit: &str, t: u64) {
    let rel = format!("run/propolis-alert/{unit}");
    fx.write(&rel, "");
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(WALL + t);
    std::fs::File::options()
        .write(true)
        .open(fx.p(&rel))
        .unwrap()
        .set_modified(at)
        .unwrap();
}

/// An alert-path record (PAGE, the alert rail) opened at stamp `s`.
fn alert_path_record(s: &str) -> String {
    let r = with_field(
        &with_field(
            &with_field(
                &hook_record_at("w#1", "propolis.service", "PAGE", "open", s, "-"),
                2,
                "alert:shell",
            ),
            3,
            "alert-path",
        ),
        4,
        "alert",
    );
    with_field(&r, 11, "nocurl")
}

/// alert-path resolves on an alert delivered after its open, across a reboot too (a reboot empties
/// /run, which alone proves nothing, but a delivery after it does), and a failure hook that failed
/// before the open and was never reset does not hold the resolve back.
#[test]
fn alert_path_resolves_on_a_delivery_after_its_open_across_a_boot_and_past_an_older_failed_hook() {
    let fx = Fx::new();
    fx.incidents(&[alert_path_record("1799990000/12345678/5000")]);
    fx.pass(0);
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open", "no delivery");
    delivered_at(&fx, "sensor-ssh.service", 100);
    fx.pass(300);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "sent2xx"));

    let fx = Fx::new();
    let hook = "propolis-alert@sensor-ssh.service.service";
    fx.stub_file(
        "failed-alert-units",
        &format!("{hook} loaded failed failed Propolis alert\n"),
    );
    fx.unit(
        hook,
        &[
            ("ActiveState", "failed"),
            ("Result", "timeout"),
            ("InactiveEnterTimestampMonotonic", &entered(0, 60)),
        ],
    );
    fx.incidents(&[alert_path_record(&stamp(0))]);
    delivered_at(&fx, "sensor-ssh.service", 100);
    fx.pass(300);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "sent2xx"));

    // A failure hook that failed after the open still holds it.
    let fx = Fx::new();
    fx.stub_file(
        "failed-alert-units",
        &format!("{hook} loaded failed failed Propolis alert\n"),
    );
    fx.unit(
        hook,
        &[
            ("ActiveState", "failed"),
            ("Result", "timeout"),
            ("InactiveEnterTimestampMonotonic", &entered(0, 60)),
        ],
    );
    fx.incidents(&[alert_path_record(
        &stamp(0).replace(&format!("/{UP}"), &format!("/{}", UP - 120)),
    )]);
    delivered_at(&fx, "sensor-ssh.service", 100);
    fx.pass(300);
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open");
}

/// alert-path never resolves on absence: opened by a failure hook that timed out, then reset, with
/// no undelivered line, no undelivered file and no delivery, it stays open; a hook firing that
/// delivered its alert after the open resolves it.
#[test]
fn alert_path_opened_by_a_failed_hook_never_resolves_on_absence_and_resolves_on_a_delivery() {
    let fx = Fx::new();
    let hook = "propolis-alert@sensor-ssh.service.service";
    fx.stub_file(
        "failed-alert-units",
        &format!("{hook} loaded failed failed Propolis alert\n"),
    );
    fx.unit(
        hook,
        &[
            ("ActiveState", "failed"),
            ("Result", "timeout"),
            ("InactiveEnterTimestampMonotonic", &entered(0, 60)),
        ],
    );
    fx.pass(0);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "proc.timeout"));
    std::fs::remove_file(fx.dir.path().join("failed-alert-units")).unwrap();
    fx.pass(300);
    fx.pass(600);
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open");
    fx.hook_fires("sensor-ssh.service", 700);
    fx.pass(900);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "sent2xx"));
}

/// A failure hook that itself failed (a failed propolis-alert@ instance) opens alert-path with
/// its own cause when its failure is newer than the key's last resolve; one that failed before
/// that resolve, and was never reset, opens nothing again.
#[test]
fn a_failure_hook_that_failed_after_the_last_resolve_opens_alert_path_and_an_older_one_does_not() {
    let fx = Fx::new();
    let hook = "propolis-alert@sensor-ssh.service.service";
    fx.stub_file(
        "failed-alert-units",
        &format!("{hook} loaded failed failed Propolis alert\n"),
    );
    fx.unit(
        hook,
        &[
            ("ActiveState", "failed"),
            ("Result", "timeout"),
            ("InactiveEnterTimestampMonotonic", &entered(0, 60)),
        ],
    );
    fx.pass(0);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "proc.timeout"));

    let resolved = with_field(
        &with_field(&with_field(&f.join("\t"), 7, "resolved"), 21, &stamp(100)),
        22,
        "sent2xx",
    );
    fx.incidents(&[format!("{}\n", resolved.trim_end())]);
    fx.pass(300);
    assert_eq!(fx.record("alert:shell").unwrap()[7], "resolved");
    fx.unit(
        hook,
        &[
            ("ActiveState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("InactiveEnterTimestampMonotonic", &entered(600, 10)),
        ],
    );
    fx.pass(600);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "proc.exit:1"));
}

/// journald's own notice that it suppressed lines (its catalog id, from its own unit and uid)
/// opens journal-dropped, a NOTICE, for a unit this witness watches, named as journald names it
/// (the unit name since systemd 236, a cgroup path before) and counted; a unit it does not watch
/// opens nothing. A day without the notice resolves it.
#[test]
fn the_journald_class_matches_the_catalog_id_and_a_watched_unit_by_name_or_cgroup_path() {
    let fx = Fx::new();
    fx.stub_file(
        "journal.journald",
        "Suppressed 1234 messages from sensor-ssh.service\n\
         Suppressed 9 messages from /system.slice/cron.service\n",
    );
    fx.pass(0);
    assert_eq!(
        fx.meta("jlines").as_deref(),
        Some("undelivered:0,journal:0,guard:0,suppressed:1234")
    );
    let log = fx.log();
    assert!(
        log.contains(
            "MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e _SYSTEMD_UNIT=systemd-journald.service _UID=0"
        ),
        "{log}"
    );
    let f = fx.record("journal:sensor-ssh.service").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        (
            "journal-dropped",
            "NOTICE",
            "open",
            "journal.suppressed",
            "0"
        )
    );
    assert!(fx.record("journal:cron.service").is_none());
    fx.stub_file(
        "journal.journald",
        "Suppressed 7 messages from /system.slice/sensor-http.service\n",
    );
    fx.pass(300);
    assert_eq!(fx.record("journal:sensor-ssh.service").unwrap()[7], "open");
    assert_eq!(fx.record("journal:sensor-http.service").unwrap()[7], "open");
    assert!(
        fx.meta("jlines")
            .unwrap_or_default()
            .ends_with("suppressed:1241")
    );
    fx.stub_file("journal.journald", "");
    fx.pass(86_700);
    let f = fx.record("journal:sensor-ssh.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "quiet24"));
}

/// A second suppression notice for the same unit restarts its quiet day: the record stays open
/// until 24 hours after the latest notice, not the first.
#[test]
fn a_second_suppression_notice_keeps_journal_dropped_open_a_day_from_that_notice() {
    let fx = Fx::new();
    let line = "Suppressed 5 messages from sensor-ssh.service\n";
    fx.stub_file("journal.journald", line);
    fx.pass(0);
    fx.stub_file("journal.journald", "");
    fx.pass(300);
    fx.stub_file("journal.journald", line);
    fx.pass(72_000);
    fx.stub_file("journal.journald", "");
    fx.pass(86_700);
    assert_eq!(fx.record("journal:sensor-ssh.service").unwrap()[7], "open");
    fx.pass(72_000 + 86_100);
    assert_eq!(fx.record("journal:sensor-ssh.service").unwrap()[7], "open");
    fx.pass(72_000 + 86_400);
    let f = fx.record("journal:sensor-ssh.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "quiet24"));
}

/// Each journal class's text occurs verbatim in the source of the program that writes it, so a
/// reworded message fails here instead of leaving its class blind; so does each start of the
/// legacy hook's reasons the witness maps to a cause. journald's class is exempt: systemd writes
/// it, matched by its catalog id.
#[test]
fn every_journal_class_names_a_literal_its_writer_prints() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let lib = std::fs::read_to_string(LIB).unwrap();
    let start = lib
        .find("PA_JOURNAL_CLASSES='")
        .expect("PA_JOURNAL_CLASSES")
        + "PA_JOURNAL_CLASSES='".len();
    let table = &lib[start..start + lib[start..].find('\'').unwrap()];
    let mut classes = std::collections::BTreeSet::new();
    for line in table.lines().filter(|l| !l.is_empty()) {
        let mut parts = line.splitn(3, '|');
        let (class, writer, text) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        classes.insert(class.to_string());
        assert!(!text.trim().is_empty(), "{line}");
        if writer == "systemd" {
            assert_eq!(class, "journald", "{line}");
            continue;
        }
        let source = std::fs::read_to_string(format!("{root}/{writer}"))
            .unwrap_or_else(|e| panic!("{writer}: {e}"));
        assert!(source.contains(text), "{writer} does not print {text:?}");
    }
    for class in ["hook", "guard", "daemon", "journald"] {
        assert!(classes.contains(class), "no class {class}: {classes:?}");
    }
    let witness = std::fs::read_to_string(SCRIPT).unwrap();
    let reasons = witness
        .lines()
        .find_map(|l| l.strip_prefix("WITNESS_HOOK_REASONS='"))
        .expect("WITNESS_HOOK_REASONS")
        .trim_end_matches('\'');
    let alert = std::fs::read_to_string(format!("{root}/deploy/alert.sh")).unwrap();
    for entry in reasons.split(';') {
        let (_, start) = entry.split_once('|').unwrap();
        assert!(
            alert.contains(&format!("undelivered \"{start}")),
            "deploy/alert.sh gives no reason starting {start:?}"
        );
    }
}

/// The observe file with its P line `name` set to `rest` (the fields after the name).
fn seed_p(fx: &Fx, name: &str, rest: &str) {
    let text = fx.observe_text();
    let prefix = format!("P\t{name}\t");
    let mut body: String = text
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with(&prefix))
        .map(|l| format!("{l}\n"))
        .collect();
    body.push_str(&format!("{prefix}{rest}\n"));
    fx.observe(&body);
}

/// The P line `name` of the observe file, without its type and name.
fn p_line(fx: &Fx, name: &str) -> String {
    let prefix = format!("P\t{name}\t");
    fx.observe_text()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(str::to_string))
        .unwrap_or_default()
}

/// An open daemon-down record, as the hook would have left it, opened at time `t`.
fn open_daemon_down(t: u64) -> String {
    hook_record("w#1", "propolis.service", "PAGE", "open", t, "0")
}

/// pg_is_in_recovery() true on two passes opens db-readonly (db:recovery, PAGE, ledger, cause
/// db.recovery); the uptime grace and a manual marker hold it pending; one writable answer between
/// two standby ones resolves nothing, and two writable answers in a row resolve it db2.
#[test]
fn db_readonly_opens_after_two_standby_answers_and_resolves_on_two_writable_ones() {
    let fx = Fx::new();
    fx.database("0|t|");
    fx.pass(0);
    assert_eq!(fx.record("db:recovery").unwrap()[7], "pending");
    fx.pass(300);
    let f = fx.record("db:recovery").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str()
        ),
        ("db-readonly", "ledger", "PAGE", "open", "db.recovery")
    );
    assert!(fx.record("db:local").is_none());
    for (t, answer, state) in [
        (600, "0|f|", "open"),
        (900, "0|t|", "open"),
        (1200, "0|f|", "open"),
        (1500, "0|f|", "resolved"),
    ] {
        fx.stub_file("pg.answer", answer);
        fx.pass(t);
        assert_eq!(fx.record("db:recovery").unwrap()[7], state, "at {t}");
    }
    assert_eq!(fx.record("db:recovery").unwrap()[22], "db2");

    let mut fx = Fx::new();
    fx.database("0|t|");
    for t in [0, 250] {
        fx.setenv("PROPOLIS_WITNESS_NOW", &early(t));
        fx.pass(t);
    }
    assert_eq!(fx.record("db:recovery").unwrap()[7], "pending");

    let fx = Fx::new();
    fx.database("0|t|");
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tmanual\n", WALL + 3600),
    );
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("db:recovery").unwrap()[7], "pending");
}

/// A database on another host is keyed db:remote: an outage there may be one several nodes
/// share, and is never this host's db:local.
#[test]
fn a_remote_database_url_refused_on_two_passes_opens_db_remote_not_db_local() {
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         DATABASE_URL=postgres://propolis@10.0.0.5/propolis\n",
    );
    fx.pass(0);
    fx.pass(300);
    let f = fx.record("db:remote").unwrap();
    assert_eq!(
        (f[3].as_str(), f[7].as_str(), f[11].as_str()),
        ("db-unreachable", "open", "db.unreachable")
    );
    assert!(fx.record("db:local").is_none());
}

/// Whether the daemon binary carries pg-exec's guard is read once per binary (its inode, size and
/// mtime, kept in meta): the same binary is not read again, and one replaced by a binary without
/// the guard is read again, found wanting and never run as root.
#[test]
fn the_pg_exec_guard_is_read_once_per_binary_and_a_replaced_binary_without_it_is_never_run() {
    let fx = Fx::new();
    fx.database("0|f|");
    write_exec(
        &fx.bin.join("grep"),
        "#!/usr/bin/env bash\n\
         case \"$*\" in *'propolis pg-exec: DATABASE_URL is not set'*) printf 'grep-guard %s\\n' \"${!#}\" >> \"$STUB_LOG\" ;; esac\n\
         exec /usr/bin/grep \"$@\"\n",
    );
    fx.pass(0);
    assert!(fx.log().contains("grep-guard "), "{}", fx.log());
    assert_eq!(fx.meta("pgexec_ok").as_deref(), Some("1"));
    let id = fx.meta("pgexec_id").unwrap();
    clear_log(&fx);
    fx.pass(300);
    let log = fx.log();
    assert!(!log.contains("grep-guard "), "{log}");
    assert!(log.contains("propolis pg-exec"), "{log}");
    assert_eq!(fx.meta("pgexec_id").as_deref(), Some(id.as_str()));

    write_exec(
        &fx.p("usr/local/bin/propolis"),
        "#!/usr/bin/env bash\nprintf 'propolis %s\\n' \"$*\" >> \"$STUB_LOG\"\n",
    );
    clear_log(&fx);
    fx.pass(600);
    let log = fx.log();
    assert!(log.contains("grep-guard "), "{log}");
    assert!(!log.contains("propolis pg-exec"), "run as root: {log}");
    assert!(
        p_line(&fx, "pg").contains("\tunknown\ttool.exec\t"),
        "{}",
        fx.observe_text()
    );
    assert_eq!(fx.meta("pgexec_ok").as_deref(), Some("0"));
    assert_ne!(fx.meta("pgexec_id").as_deref(), Some(id.as_str()));
}

/// When a proof's input has been unknown for six hours (72 light passes) while its record is open,
/// the record is flagged cannotverify and stays open: the database probe that cannot run psql for
/// db-unreachable, a /ready that times out for daemon-down, and a /ready that cannot be asked for
/// a daemon that never runs ten minutes steady.
#[test]
fn records_whose_proof_input_is_unknown_for_six_hours_are_flagged_cannotverify() {
    let flagged = |f: &[String]| f[30].split(',').any(|x| x == "cannotverify");
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("db:local").unwrap()[7], "open");
    fx.stub_file(
        "pg.answer",
        "127||propolis pg-exec: cannot run psql: No such file or directory",
    );
    seed_p(
        &fx,
        "pg",
        &format!("{}\tunknown\ttool.exec\t70", stamp(300)),
    );
    fx.pass(600);
    assert!(!flagged(&fx.record("db:local").unwrap()));
    fx.pass(900);
    let f = fx.record("db:local").unwrap();
    assert!(flagged(&f), "{f:?}");
    assert_eq!(f[7], "open");

    let fx = Fx::new();
    fx.stub_file("ready.code", "000t");
    fx.pass(0);
    fx.pass(300);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "net.timeout"));
    seed_p(&fx, "ready-code", &format!("{}\t000\t-\t70", stamp(300)));
    fx.pass(600);
    assert!(!flagged(&fx.record("unit:propolis.service").unwrap()));
    fx.pass(900);
    let f = fx.record("unit:propolis.service").unwrap();
    assert!(flagged(&f), "{f:?}");
    assert_eq!(f[7], "open");

    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_CONSOLE_BIND=192.0.2.10:8080\n",
    );
    fx.incidents(&[open_daemon_down(0)]);
    fx.observe(&format!(
        "P\tready\t{}\tunknown\tconfig.invalid\t70\n",
        stamp(300)
    ));
    for (t, flag) in [(600, false), (900, true)] {
        fx.unit(
            "propolis.service",
            &[
                ("Restart", "on-failure"),
                ("ActiveEnterTimestampMonotonic", &entered(t, 30)),
            ],
        );
        fx.pass(t);
        let f = fx.record("unit:propolis.service").unwrap();
        assert_eq!((flagged(&f), f[7].as_str()), (flag, "open"), "at {t}");
    }
}

/// A daemon whose console binds an address that is not loopback cannot be asked /ready, so
/// daemon-down resolves by the fallback proof active10: up ten minutes with the same start and no
/// restart.
#[test]
fn a_daemon_whose_console_is_not_on_loopback_resolves_daemon_down_after_ten_steady_minutes() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_CONSOLE_BIND=192.0.2.10:8080\n",
    );
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "open");
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            ("ActiveEnterTimestampMonotonic", &entered(600, 0)),
        ],
    );
    fx.pass(600);
    fx.pass(900);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "open");
    fx.pass(1200);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "active10"));
    assert!(!fx.log().contains("ready http"), "{}", fx.log());
}

/// /ready is believed only from a listener the daemon owns (its MainPID, or the propolis
/// account's uid): another local account that took the console port while the daemon restarted
/// could otherwise answer 200 for it. Such an answer reads unknown, resolves nothing and makes the
/// pass partial; nothing listening at all is 000, with no request made.
#[test]
fn ready_answered_by_a_listener_the_daemon_does_not_own_is_unknown_and_resolves_nothing() {
    let fx = Fx::new();
    fx.incidents(&[open_daemon_down(0)]);
    fx.stub_file(
        "ss.out",
        "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"python3\",pid=777,fd=3)) uid:1001 ino:9 sk:2 <->\n",
    );
    fx.pass(300);
    fx.pass(600);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "open");
    assert!(
        p_line(&fx, "ready").contains("\tunknown\t"),
        "{}",
        fx.observe_text()
    );
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("\tpartial")
    );
    assert!(
        fx.log().contains("ss -Hltnpe sport = :8080"),
        "{}",
        fx.log()
    );
    assert!(!fx.log().contains("ready http"), "{}", fx.log());

    fx.stub_file("ss.out", "");
    clear_log(&fx);
    fx.pass(900);
    assert!(!fx.log().contains("ready http"), "{}", fx.log());
    assert!(p_line(&fx, "ready-code").contains("\t000\t"));

    std::fs::remove_file(fx.dir.path().join("ss.out")).unwrap();
    fx.pass(1200);
    fx.pass(1500);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "ready2"));

    // The propolis account's uid stands in for a pid ss could not name.
    let fx = Fx::new();
    fx.daemon_account();
    fx.incidents(&[open_daemon_down(0)]);
    fx.stub_file(
        "ss.out",
        "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* uid:998 ino:9 sk:2 <->\n",
    );
    fx.pass(300);
    fx.pass(600);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "ready2"));
}

/// Only a listener that can take a connection to the console's own address counts as holding it.
/// Another service on the same port number at another address (an HTTP sensor on the public
/// address at 8080 while the console holds 127.0.0.1:8080) is not in the way: /ready is asked and
/// believed. A wildcard listener does take such a connection, so one held by another account is
/// not believed.
#[test]
fn only_a_listener_on_the_consoles_own_address_or_a_wildcard_decides_who_answers_ready() {
    let fx = Fx::new();
    fx.incidents(&[open_daemon_down(0)]);
    fx.stub_file(
        "ss.out",
        "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:((\"propolis\",pid=4242,fd=9)) uid:998 ino:1 sk:1 <->\n\
         LISTEN 0 4096 192.0.2.10:8080 0.0.0.0:* users:((\"sensor-http\",pid=777,fd=3)) uid:1001 ino:2 sk:2 <->\n\
         LISTEN 0 4096 [2001:db8::10]:8080 [::]:* users:((\"sensor-http\",pid=777,fd=4)) uid:1001 ino:3 sk:3 <->\n\
         LISTEN 0 4096 [::]:8080 [::]:* users:((\"sensor-http\",pid=777,fd=5)) uid:1001 ino:4 sk:4 <->\n",
    );
    fx.pass(300);
    fx.pass(600);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (f[7].as_str(), f[22].as_str()),
        ("resolved", "ready2"),
        "{}",
        fx.observe_text()
    );
    assert!(
        fx.log().contains("ready http://127.0.0.1:8080/ready"),
        "{}",
        fx.log()
    );

    // The same for a console on the IPv6 loopback: an IPv4 wildcard takes none of its connections.
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\nPROPOLIS_CONSOLE_BIND=[::1]:8080\n",
    );
    fx.stub_file(
        "ss.out",
        "LISTEN 0 4096 [::1]:8080 [::]:* users:((\"propolis\",pid=4242,fd=9)) uid:998 ino:1 sk:1 <->\n\
         LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"sensor-http\",pid=777,fd=3)) uid:1001 ino:2 sk:2 <->\n",
    );
    fx.pass(300);
    assert!(
        fx.log().contains("ready http://[::1]:8080/ready"),
        "{}",
        fx.log()
    );

    for wildcard in ["0.0.0.0:8080", "*:8080"] {
        let fx = Fx::new();
        fx.incidents(&[open_daemon_down(0)]);
        fx.stub_file(
            "ss.out",
            &format!(
                "LISTEN 0 4096 {wildcard} 0.0.0.0:* users:((\"python3\",pid=777,fd=3)) uid:1001 ino:9 sk:2 <->\n"
            ),
        );
        fx.pass(300);
        fx.pass(600);
        assert_eq!(
            fx.record("unit:propolis.service").unwrap()[7],
            "open",
            "{wildcard}"
        );
        assert!(!fx.log().contains("ready http"), "{wildcard}: {}", fx.log());
    }
}

/// The ping stays skipped for 30 minutes after a pass that missed the lock or could write no
/// state, though neither could write meta: the skip is kept in /run beside the heartbeat and moved
/// into meta by the next pass that can write it.
#[test]
fn the_heartbeat_stays_skipped_for_thirty_minutes_after_a_pass_that_missed_the_lock_or_wrote_no_state()
 {
    let pings = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    for case in ["lock", "nowhere"] {
        let mut fx = Fx::new();
        fx.write(
            "etc/propolis/alert.env",
            "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n",
        );
        fx.curl_answers("200|text/plain");
        fx.pass(0);
        assert_eq!(pings(&fx), 1, "{case}");
        if case == "lock" {
            let mut holder = fx.hold_lock();
            fx.setenv("PROPOLIS_WITNESS_LOCK_WAIT", "1");
            fx.pass(300);
            holder.kill().unwrap();
            holder.wait().unwrap();
            fx.env.clear();
        } else {
            fx.stub_file(
                "disk.refuses",
                "*/var/lib/propolis/witness/*\n*/run/propolis-witness/fallback/*\n",
            );
            fx.pass(300);
            assert!(
                fx.log().contains("state not persisted"),
                "{case}: {}",
                fx.log()
            );
            std::fs::remove_file(fx.dir.path().join("disk.refuses")).unwrap();
        }
        assert_eq!(pings(&fx), 1, "{case}");
        fx.pass(600);
        assert_eq!(pings(&fx), 1, "{case}: a clean pass within 30 minutes");
        assert_eq!(
            fx.meta("hb_skip").as_deref(),
            Some(format!("{}/core", stamp(300)).as_str()),
            "{case}"
        );
        fx.pass(1800);
        assert_eq!(pings(&fx), 1, "{case}");
        fx.pass(2100);
        assert_eq!(pings(&fx), 2, "{case}");
    }
}

/// A pass the deadline cut short skips the ping (check), and a last skip dated ahead of the clock
/// starts the 30 minutes again from now instead of never ending.
#[test]
fn a_pass_cut_by_its_deadline_skips_the_heartbeat_and_a_skip_dated_ahead_restarts_the_thirty_minutes()
 {
    let pings = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    let mut fx = Fx::new();
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n",
    );
    fx.curl_answers("200|text/plain");
    fx.setenv("PROPOLIS_WITNESS_DEADLINE", "0");
    fx.pass(0);
    assert_eq!(pings(&fx), 0);
    assert_eq!(
        fx.meta("hb_skip").as_deref(),
        Some(format!("{}/check", stamp(0)).as_str())
    );
    fx.env.clear();
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=9\nM\thb_skip\t{}/check\n", stamp(90_000)),
    );
    fx.pass(300);
    assert_eq!(pings(&fx), 0);
    assert_eq!(
        fx.meta("hb_skip").as_deref(),
        Some(format!("{}/clean30", stamp(300)).as_str())
    );
    fx.pass(2100);
    assert_eq!(pings(&fx), 1);
}

/// A journal class's cursor moves only after its lines were judged and the result kept: a pass
/// past its deadline judges nothing, so the hook's undelivered line it read is read again by the
/// next pass, from the old cursor, and opens alert-path then.
#[test]
fn journal_cursors_stay_put_when_the_pass_judged_nothing_and_the_next_pass_reads_the_lines_again() {
    let mut fx = Fx::new();
    let old = "s=0123;i=1";
    fx.write("var/lib/propolis/witness/jcursor/hook", &format!("{old}\n"));
    fx.stub_file(
        "journal.hook",
        "{\"__CURSOR\":\"s=5\",\"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\",\
         \"MESSAGE\":\"could not post to ntfy; alert follows\"}\n",
    );
    fx.stub_file("journal.hook.cursor", "s=0123;i=2\n");
    fx.setenv("PROPOLIS_WITNESS_DEADLINE", "0");
    fx.pass(0);
    assert!(fx.record("alert:shell").is_none());
    assert_eq!(
        fx.read("var/lib/propolis/witness/jcursor/hook"),
        format!("{old}\n")
    );
    assert!(!fx.p("run/propolis-witness/jcursor/hook").exists());
    fx.env.clear();
    clear_log(&fx);
    fx.pass(300);
    assert!(
        fx.log().contains(&format!("journalctl hook cursor {old}")),
        "{}",
        fx.log()
    );
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open");
    assert_eq!(
        fx.read("var/lib/propolis/witness/jcursor/hook"),
        "s=0123;i=2\n"
    );
}

/// While the disk refuses writes a class's cursor goes to /run and is handed back from there; once
/// the disk takes writes again it moves to the state directory and the copy in /run is removed.
#[test]
fn a_cursor_goes_to_run_while_the_disk_refuses_writes_and_back_to_the_disk_after() {
    let fx = Fx::new();
    let first = "s=0abc;i=7";
    fx.stub_file("journal.guard.cursor", &format!("{first}\n"));
    fx.stub_file("disk.refuses", "*/var/lib/propolis/witness/*\n");
    fx.pass(0);
    assert_eq!(
        fx.read("run/propolis-witness/jcursor/guard"),
        format!("{first}\n")
    );
    assert!(!fx.p("var/lib/propolis/witness/jcursor/guard").exists());
    std::fs::remove_file(fx.dir.path().join("disk.refuses")).unwrap();
    fx.stub_file("journal.guard.cursor", "s=0abc;i=8\n");
    clear_log(&fx);
    fx.pass(300);
    assert!(
        fx.log()
            .contains(&format!("journalctl guard cursor {first}")),
        "{}",
        fx.log()
    );
    assert_eq!(
        fx.read("var/lib/propolis/witness/jcursor/guard"),
        "s=0abc;i=8\n"
    );
    assert!(!fx.p("run/propolis-witness/jcursor/guard").exists());
}

/// A cursor file that is a symbolic link, or a cursor directory that is one, is neither read nor
/// written through: the class reads the last 15 minutes instead, and what the link points at is
/// left as it was.
#[test]
fn a_cursor_file_or_directory_that_is_a_symbolic_link_is_neither_read_nor_written_through() {
    let fx = Fx::new();
    let elsewhere = fx.dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("hook"), "s=dead;i=1\n").unwrap();
    std::fs::create_dir_all(fx.p("var/lib/propolis/witness/jcursor")).unwrap();
    std::os::unix::fs::symlink(
        elsewhere.join("hook"),
        fx.p("var/lib/propolis/witness/jcursor/hook"),
    )
    .unwrap();
    fx.stub_file("journal.hook.cursor", "s=beef;i=2\n");
    fx.pass(0);
    let log = fx.log();
    let hook = log
        .lines()
        .find(|l| l.contains("SYSLOG_IDENTIFIER=propolis-alert"))
        .unwrap();
    assert!(hook.contains("--since=-15min"), "{log}");
    assert!(!log.contains("cursor s=dead"), "{log}");
    assert_eq!(
        std::fs::read_to_string(elsewhere.join("hook")).unwrap(),
        "s=dead;i=1\n"
    );

    let fx = Fx::new();
    let elsewhere = fx.dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("hook"), "s=dead;i=1\n").unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.p("var/lib/propolis/witness/jcursor")).unwrap();
    fx.stub_file("journal.hook.cursor", "s=beef;i=2\n");
    fx.pass(0);
    let log = fx.log();
    assert!(!log.contains("cursor s=dead"), "{log}");
    assert_eq!(
        std::fs::read_to_string(elsewhere.join("hook")).unwrap(),
        "s=dead;i=1\n"
    );
    assert!(!elsewhere.join("guard").exists());
}

/// daemon-degraded waits out the first ten minutes of uptime and a maintenance marker, pending.
#[test]
fn a_ready_503_under_ten_minutes_of_uptime_or_under_a_marker_stays_pending() {
    let mut fx = Fx::new();
    fx.database("0|f|");
    fx.stub_file("ready.code", "503");
    for t in [0, 300] {
        fx.setenv(
            "PROPOLIS_WITNESS_NOW",
            &format!("{}/{BOOT}/{}", WALL + t, 100 + t),
        );
        fx.pass(t);
    }
    assert_eq!(fx.record("ready:local").unwrap()[7], "pending");

    let fx = Fx::new();
    fx.database("0|f|");
    fx.stub_file("ready.code", "503");
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tupgrade\n", WALL + 3600),
    );
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("ready:local").unwrap()[7], "pending");
}

/// A daemon systemd is still starting is down once it has been starting for over half an hour:
/// on the eighth pass in a row, not the seventh. It is never asked /ready meanwhile.
#[test]
fn a_daemon_starting_for_over_half_an_hour_opens_daemon_down_on_the_eighth_pass() {
    let fx = Fx::new();
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("Restart", "on-failure"),
        ],
    );
    for i in 0..7 {
        fx.pass(i * 300);
    }
    assert!(
        fx.record("unit:propolis.service").is_none(),
        "{:?}",
        fx.records()
    );
    fx.pass(7 * 300);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[3].as_str(), f[7].as_str()), ("daemon-down", "open"));
    assert!(!fx.log().contains("ready http"), "{}", fx.log());
}

/// ready2 needs the same start across its two answers: two 200s with a restart between them, or a
/// new start, prove nothing; the next answer five minutes after the new start does.
#[test]
fn two_ready_answers_across_a_restart_or_a_new_start_do_not_resolve_daemon_down() {
    for change in ["NRestarts", "ActiveEnterTimestampMonotonic"] {
        let fx = Fx::new();
        fx.incidents(&[open_daemon_down(0)]);
        fx.pass(300);
        let v = if change == "NRestarts" {
            "1".to_string()
        } else {
            entered(600, 20)
        };
        fx.unit(
            "propolis.service",
            &[("Restart", "on-failure"), (change, &v)],
        );
        fx.pass(600);
        assert_eq!(
            fx.record("unit:propolis.service").unwrap()[7],
            "open",
            "{change}"
        );
        fx.pass(900);
        let f = fx.record("unit:propolis.service").unwrap();
        assert_eq!(
            (f[7].as_str(), f[22].as_str()),
            ("resolved", "ready2"),
            "{change}"
        );
    }
}

/// Two light passes five minutes apart by their timer can carry stamps a second short of it:
/// answers 299 s apart with the same start still prove ready2.
#[test]
fn ready_answers_299_seconds_apart_with_the_same_start_resolve_daemon_down() {
    let fx = Fx::new();
    fx.incidents(&[open_daemon_down(0)]);
    fx.pass(0);
    assert_eq!(fx.record("unit:propolis.service").unwrap()[7], "open");
    fx.pass(299);
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "ready2"));
}

/// /ready is asked only of a daemon that is enabled and up: one stopped, failed or still starting,
/// or not enabled, is never asked, since any local account could hold its port.
#[test]
fn ready_is_not_asked_of_a_daemon_that_is_stopped_failed_starting_or_not_enabled() {
    let fx = Fx::new();
    for (what, changes) in [
        (
            "stopped",
            vec![("ActiveState", "inactive"), ("SubState", "dead")],
        ),
        (
            "failed",
            vec![
                ("ActiveState", "failed"),
                ("SubState", "failed"),
                ("Result", "exit-code"),
            ],
        ),
        (
            "starting",
            vec![("ActiveState", "activating"), ("SubState", "start")],
        ),
        ("static", vec![("UnitFileState", "static")]),
        ("disabled", vec![("UnitFileState", "disabled")]),
    ] {
        fx.unit("propolis.service", &changes);
        clear_log(&fx);
        fx.pass(0);
        assert!(!fx.log().contains("ready http"), "{what}: {}", fx.log());
    }
    fx.unit("propolis.service", &[]);
    clear_log(&fx);
    fx.pass(0);
    assert!(fx.log().contains("ready http"), "{}", fx.log());
}

/// The /ready GET goes straight to loopback whatever the environment says: no .curlrc (-q), no
/// proxy even with http_proxy set, plain http only, no redirect and a 64 KiB cap on the body.
#[test]
fn ready_is_asked_with_no_proxy_no_redirect_plain_http_and_a_size_cap() {
    let mut fx = Fx::new();
    for proxy in [None, Some("http://proxy.example.invalid:3128")] {
        if let Some(p) = proxy {
            fx.setenv("http_proxy", p);
            fx.setenv("HTTP_PROXY", p);
        }
        clear_log(&fx);
        fx.pass(0);
        let log = fx.log();
        let argv = log
            .lines()
            .find_map(|l| l.strip_prefix("ready-argv "))
            .expect(&log);
        for want in [
            "-q ",
            "--noproxy * ",
            "--proto =http ",
            "--max-redirs 0 ",
            "--max-filesize 65536 ",
        ] {
            assert!(argv.contains(want), "{want:?} in {argv} ({proxy:?})");
        }
    }
}

/// The legacy hook's retry hold (`the last attempt to deliver was less than ...`) is a delivery
/// that is not getting through: alert-path, cause net.connect. A reason the witness does not know
/// opens it too, cause unknown.
#[test]
fn the_legacy_hooks_retry_hold_is_net_connect_and_an_unknown_reason_is_unknown() {
    for (msg, cause) in [
        (
            "the last attempt to deliver was less than 300 s ago, not retrying yet; the alert for sensor-ssh.service is still undelivered since 2027-01-15T08:00:00Z (2 failures since then; the full text was logged at 2027-01-15T08:00:00Z)",
            "net.connect",
        ),
        ("something nobody planned for; alert follows", "unknown"),
    ] {
        let fx = Fx::new();
        fx.stub_file(
            "journal.hook",
            &format!(
                "{{\"__CURSOR\":\"s=6\",\"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\",\"MESSAGE\":\"{msg}\"}}\n"
            ),
        );
        fx.pass(0);
        let f = fx.record("alert:shell").unwrap();
        assert_eq!((f[7].as_str(), f[11].as_str()), ("open", cause), "{msg}");
    }
}

/// The hook reader finds the unit and the message whichever comes first in an entry, reads past an
/// escaped backslash before an escaped quote inside a message, and skips a message journald gives
/// in binary form.
#[test]
fn the_hook_reader_finds_unit_and_message_in_any_order_and_reads_past_escaped_backslashes() {
    let fx = Fx::new();
    fx.stub_file(
        "journal.hook",
        "{\"MESSAGE\":\"sensor-ssh.service entered the failed state on h at t.\",\"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\"}\n\
         {\"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\",\"MESSAGE\":[115,101]}\n",
    );
    fx.pass(0);
    assert_eq!(
        fx.meta("jlines").as_deref(),
        Some("undelivered:0,journal:1,guard:0,suppressed:0")
    );
    fx.stub_file(
        "journal.hook",
        "{\"_SYSTEMD_UNIT\":\"propolis-alert@c.service.service\",\"MESSAGE\":\"q\\\\\\\"x; alert follows\"}\n\
         {\"_SYSTEMD_UNIT\":\"propolis-alert@a.service.service\",\"MESSAGE\":\"could not post to ntfy; alert follows\"}\n\
         {\"MESSAGE\":\"could not post to ntfy; the alert for b.service is still undelivered since x\",\"_SYSTEMD_UNIT\":\"propolis-alert@b.service.service\"}\n",
    );
    fx.pass(300);
    assert_eq!(
        fx.meta("jlines").as_deref(),
        Some("undelivered:3,journal:1,guard:0,suppressed:0")
    );
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "net.connect"));
}

/// journalctl before systemd 246 prints its json with blanks around the colons and commas; the
/// hook reader takes that form too.
#[test]
fn the_hook_reader_accepts_the_spaced_json_older_journalctl_prints() {
    let fx = Fx::new();
    fx.stub_file(
        "journal.hook",
        "{ \"__CURSOR\" : \"s=5\", \"_SYSTEMD_UNIT\" : \"propolis-alert@sensor-ssh.service.service\", \"MESSAGE\" : \"curl is not installed, so this host cannot push alerts; install it; alert follows\" }\n",
    );
    fx.pass(0);
    let f = fx.record("alert:shell").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "nocurl"));
}

/// Without the daemon's account there is no tie: its journal is not read, and the daemon's
/// failure is judged on its own while the database is down.
#[test]
fn without_the_daemon_account_there_is_no_tie_and_the_daemon_failure_is_judged_on_its_own() {
    let fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.stub_file("uid.propolis", "none");
    fx.stub_file("journal.daemon", CONNECT_LINE);
    restarting_daemon(&fx);
    fx.hook_fires("propolis.service", 0);
    clear_log(&fx);
    fx.pass(300);
    assert!(
        !fx.log()
            .contains("journalctl -q --no-pager -o cat _SYSTEMD_UNIT=propolis.service"),
        "{}",
        fx.log()
    );
    let f = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (
            f[7].as_str(),
            f[11].as_str(),
            f[13].as_str(),
            f[29].as_str()
        ),
        ("open", "proc.exit:1", "-", "1")
    );
}

/// No probe starts unless its whole time limit ends by the soft deadline: one that cannot is
/// skipped, its check reads unknown and the pass is partial.
#[test]
fn a_probe_that_cannot_finish_by_the_soft_deadline_is_skipped_and_reads_unknown() {
    let mut fx = Fx::new();
    fx.database(PG_REFUSED);
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    write_exec(
        &fx.bin.join("find"),
        "#!/usr/bin/env bash\nprintf 'find %s\\n' \"$*\" >> \"$STUB_LOG\"\nexec /usr/bin/find \"$@\"\n",
    );
    std::fs::create_dir_all(fx.p("run/propolis-alert/undelivered")).unwrap();
    fx.pass(0);
    assert_eq!(fx.meta("pgexec_ok").as_deref(), Some("1"));

    fx.setenv("PROPOLIS_WITNESS_SOFT_DEADLINE", "30");
    clear_log(&fx);
    fx.pass(300);
    let log = fx.log();
    assert!(log.contains("propolis pg-exec"), "{log}");
    assert!(!log.contains("id -u"), "{log}");
    assert!(!log.contains("journalctl"), "{log}");
    assert!(!log.contains("list-units"), "{log}");
    assert!(log.contains("ready http"), "{log}");
    // The probe's own listings (the banner's count of the same directory comes after the pass).
    let undelivered =
        "run/propolis-alert/undelivered -mindepth 1 -maxdepth 1 -type f -printf %f\\n";
    let stamps = "run/propolis-alert -mindepth 1 -maxdepth 1 -type f -printf %T@ %f\\0";
    assert!(log.contains(undelivered) && log.contains(stamps), "{log}");
    for check in [
        "journal:daemon",
        "journal:hook",
        "journal:guard",
        "journal:journald",
        "alertunit",
    ] {
        assert!(
            p_line(&fx, check).contains("\tunknown\t"),
            "{check}: {}",
            fx.observe_text()
        );
    }
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("\tpartial")
    );

    fx.setenv("PROPOLIS_WITNESS_SOFT_DEADLINE", "4");
    clear_log(&fx);
    fx.pass(600);
    let log = fx.log();
    assert!(!log.contains("propolis pg-exec"), "{log}");
    assert!(!log.contains("ready http"), "{log}");
    assert!(!log.contains(undelivered) && !log.contains(stamps), "{log}");
    for check in ["pg", "ready"] {
        assert!(
            p_line(&fx, check).contains("\tunknown\t"),
            "{check}: {}",
            fx.observe_text()
        );
    }
}

/// The salt the volume cases give the witness, so a mount id is a known value.
const VOL_SALT: &str = "0123456789abcdef0123456789abcdef";

/// Gives the fixture a known salt (the witness never replaces a valid one).
fn salt(fx: &Fx) {
    fx.write("var/lib/propolis/witness/id-salt", &format!("{VOL_SALT}\n"));
    std::fs::set_permissions(
        fx.p("var/lib/propolis/witness/id-salt"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

/// The opaque id of the mount point `target` under `VOL_SALT`: `m` and 5 hex of
/// sha256(salt NUL "mount" NUL target).
fn mount_id(target: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg("printf '%s\\0%s\\0%s' \"$1\" mount \"$2\" | sha256sum")
        .arg("_")
        .arg(VOL_SALT)
        .arg(target)
        .output()
        .unwrap();
    format!("m{}", &String::from_utf8_lossy(&out.stdout)[..5])
}

/// A stamp `secs` before the first pass, in the same boot.
fn before(secs: u64) -> String {
    format!("{}/{BOOT}/{}", WALL - secs, UP - secs)
}

/// Every file the state directories hold and the stub log, as one text, to look for words that
/// must never be kept.
fn everything(fx: &Fx) -> String {
    let mut text = fx.log();
    for f in fx.state_files() {
        text.push_str(&std::fs::read_to_string(&f).unwrap_or_default());
    }
    text
}

/// A filesystem of a store with free space under the daemon's share (15% by default) opens
/// volume-filling (ACT, host rail) on the second hourly pass, keyed and named by the mount's
/// opaque id: the mount point is in no record and no observe line. Each pass keeps one `Z` sample
/// of the filesystem, from one `df` asked for bytes and inodes. Room again on two passes resolves
/// it room2.
#[test]
fn a_volume_short_of_free_space_opens_volume_filling_on_the_second_hourly_pass_and_resolves_on_room_twice()
 {
    let fx = Fx::new();
    salt(&fx);
    std::fs::create_dir_all(fx.p("var/log/propolis")).unwrap();
    fx.stub_file(
        "df.answer",
        "100000000000 10000000000 6000000 5000000 /srv/data7",
    );
    let key = format!("vol:{}", mount_id("/srv/data7"));
    fx.hourly(0);
    let f = fx
        .record(&key)
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[5].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str()
        ),
        (
            "volume-filling",
            "host",
            &key[4..],
            "ACT",
            "pending",
            "vol.low"
        )
    );
    let log = fx.log();
    let df: Vec<&str> = log.lines().filter(|l| l.starts_with("df ")).collect();
    assert_eq!(df.len(), 1, "one df for the one filesystem: {df:?}");
    assert!(
        df[0].starts_with("df -B1 --output=size,avail,itotal,iavail,target -- "),
        "{}",
        df[0]
    );
    let z = format!(
        "Z\t{}\t{}\t100000000000\t10000000000\t6000000\t5000000\n",
        &key[4..],
        stamp(0)
    );
    assert!(fx.observe_text().contains(&z), "{}", fx.observe_text());
    fx.hourly(3600);
    let f = fx.record(&key).unwrap();
    assert_eq!((f[7].as_str(), f[29].as_str()), ("open", "1"));
    assert!(
        !fx.read("var/lib/propolis/witness/incidents")
            .contains("/srv/data7")
    );
    assert!(!fx.observe_text().contains("/srv/data7"));
    assert_eq!(
        fx.observe_text()
            .lines()
            .filter(|l| l.starts_with("Z\t"))
            .count(),
        2
    );

    fx.stub_file(
        "df.answer",
        "100000000000 60000000000 6000000 5000000 /srv/data7",
    );
    fx.hourly(7200);
    assert_eq!(
        state_of(&fx, &key),
        "open",
        "one roomy pass resolves nothing"
    );
    fx.hourly(10800);
    let f = fx.record(&key).unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "room2"));
}

/// Free space under 1 GiB and the guard's 512 MiB reserve is volume-full-soon (PAGE): on a record
/// already open as volume-filling it is a rise of tier, a change v2 would push, and the same
/// record (one key per mount) carries it.
#[test]
fn a_volume_that_falls_under_a_gibibyte_and_a_half_rises_to_volume_full_soon_as_a_change() {
    let fx = Fx::new();
    salt(&fx);
    fx.stub_file("df.answer", "100000000000 10000000000 6000000 5000000 /");
    let key = format!("vol:{}", mount_id("/"));
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[29].as_str()),
        ("volume-filling", "ACT", "1")
    );
    fx.stub_file("df.answer", "100000000000 1000000000 6000000 5000000 /");
    fx.hourly(7200);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[16].as_str(),
            f[29].as_str()
        ),
        ("volume-full-soon", "PAGE", "open", "change", "2")
    );
    assert_eq!(
        fx.records()
            .iter()
            .filter(|r| r[2].starts_with("vol:"))
            .count(),
        1
    );
}

/// A filesystem that reports no inodes (btrfs) has no inode trigger, and the share of free space
/// is the daemon's PROPOLIS_OPS_CAPACITY_FREE_PCT: 10% free under a setting of 5 opens nothing. A
/// df that does not answer (a hung mount) is unknown for that filesystem, never a value: nothing
/// opens, the pass is partial, and the third such pass in a row opens tool-unusable on
/// tool:volume.
#[test]
fn a_filesystem_with_no_inodes_and_a_df_that_does_not_answer_open_nothing() {
    let fx = Fx::new();
    salt(&fx);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_CAPACITY_FREE_PCT=5\n",
    );
    fx.stub_file("df.answer", "100000000000 10000000000 0 0 /");
    fx.hourly(0);
    fx.hourly(3600);
    assert!(
        !fx.records().iter().any(|r| r[2].starts_with("vol:")),
        "{}",
        state_text(&fx)
    );
    fx.stub_file("df.answer", "hang");
    seed_p(
        &fx,
        "volume",
        &format!("{}\tunknown\tunknown\t2", stamp(3600)),
    );
    fx.hourly(7200);
    assert!(!fx.records().iter().any(|r| r[2].starts_with("vol:")));
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("B\thourly\t")
            && fx
                .read("run/propolis-witness/heartbeat")
                .contains("\tpartial")
    );
    let f = fx
        .record("tool:volume")
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!((f[3].as_str(), f[7].as_str()), ("tool-unusable", "open"));
    assert!(
        fx.observe_text()
            .lines()
            .filter(|l| l.starts_with("Z\t"))
            .count()
            == 2,
        "the samples of a filesystem that did not answer are kept: {}",
        fx.observe_text()
    );
}

/// Three days of samples falling 1 GiB an hour project the volume full of its last GiB in 19
/// hours: volume-filling opens on the projection alone (cause vol.projected), with 20% still free.
/// The `Z` lines stay bounded: a sample over seven days old is dropped, one under 45 minutes old
/// is replaced by this pass's, a filesystem no store lives on any more drops out, and a light pass
/// keeps every `Z` line exactly as the hourly pass wrote it.
#[test]
fn a_fall_over_three_days_opens_volume_filling_on_its_projection_and_the_samples_stay_bounded() {
    let fx = Fx::new();
    salt(&fx);
    let gib: u64 = 1_073_741_824;
    let m = mount_id("/");
    let mut lines = String::new();
    lines.push_str(&format!(
        "Z\t{m}\t{}\t{}\t{}\t6000000\t5000000\n",
        before(8 * 86_400),
        100 * gib,
        99 * gib
    ));
    for h in 1..=73u64 {
        lines.push_str(&format!(
            "Z\t{m}\t{}\t{}\t{}\t6000000\t5000000\n",
            before(h * 3600),
            100 * gib,
            (20 + h) * gib
        ));
    }
    lines.push_str(&format!(
        "Z\t{m}\t{}\t{}\t{}\t6000000\t5000000\n",
        before(600),
        100 * gib,
        20 * gib
    ));
    lines.push_str(&format!("Z\tm00000\t{}\t1000\t500\t10\t5\n", before(3600)));
    lines.push_str(&format!(
        "U\tsensor-ssh.service\t{}\t0\t{BOOT}\n",
        before(300)
    ));
    fx.observe(&lines);
    fx.stub_file(
        "df.answer",
        &format!("{} {} 6000000 5000000 /", 100 * gib, 20 * gib),
    );
    fx.hourly(0);
    let f = fx
        .record(&format!("vol:{m}"))
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!(
        (f[3].as_str(), f[7].as_str(), f[11].as_str()),
        ("volume-filling", "pending", "vol.projected")
    );
    let obs = fx.observe_text();
    let z: Vec<&str> = obs.lines().filter(|l| l.starts_with("Z\t")).collect();
    assert_eq!(z.len(), 74, "73 hourly samples kept and this pass's: {obs}");
    assert!(!obs.contains(&before(8 * 86_400)), "{obs}");
    assert!(!obs.contains(&before(600)), "{obs}");
    assert!(!obs.contains("m00000"), "{obs}");
    assert!(
        obs.contains(&format!("U\tsensor-ssh.service\t{}", before(300))),
        "{obs}"
    );
    let zs: Vec<String> = z.iter().map(|l| l.to_string()).collect();
    fx.pass(60);
    let after: Vec<String> = fx
        .observe_text()
        .lines()
        .filter(|l| l.starts_with("Z\t"))
        .map(str::to_string)
        .collect();
    assert_eq!(after, zs);
}

/// The hourly PostgreSQL state comes from one pa_pg call with four statements: transaction-id age
/// over 1,000,000,000 opens db-xid (ACT), connections at 90% of max_connections less the reserved
/// slots db-slots (ACT), lock waits over 120 s db-locks (NOTICE), each on the second hourly pass,
/// on the ledger stage; the database size is recorded only (meta pg_state). Two clean passes
/// resolve them clean2. The local data directory is read once a day as the postgres account
/// through setpriv, with a reset environment, cached in meta, and psql's error text is never kept;
/// a path out of form is never stored.
#[test]
fn the_hourly_database_state_opens_db_xid_db_slots_and_db_locks_from_one_query() {
    let fx = Fx::new();
    fx.database("0|f|");
    fx.stub_file("uid.postgres", "117\n");
    fx.stub_file("pg.state", "1500000000\n91|100|3\n2\n123456789\n");
    fx.hourly(0);
    let calls: Vec<String> = fx
        .log()
        .lines()
        .filter(|l| l.starts_with("propolis pg-exec"))
        .map(str::to_string)
        .collect();
    assert_eq!(calls.len(), 1, "{calls:?}");
    for sql in [
        "datfrozenxid",
        "pg_stat_activity",
        "pg_locks",
        "pg_database_size",
    ] {
        assert!(calls[0].contains(sql), "{sql}: {}", calls[0]);
    }
    // Only client connections take one of the slots the count is held against: the server's own
    // background processes are rows of pg_stat_activity too, and are left out.
    assert!(
        calls[0].contains("backend_type") && calls[0].contains("'client backend'"),
        "{}",
        calls[0]
    );
    assert!(!calls[0].contains("db-s3cret"));
    for key in ["dbstate:xid", "dbstate:slots", "dbstate:locks"] {
        assert_eq!(state_of(&fx, key), "pending", "{key}");
    }
    assert_eq!(
        fx.meta("pg_state").unwrap(),
        format!("{}/1500000000/91/97/2/123456789", stamp(0))
    );
    let log = fx.log();
    assert!(
        log.contains("setpriv --reuid=postgres --regid=postgres --init-groups --reset-env -- /usr/bin/env PATH=/usr/bin:/bin psql -X -A -t -c SHOW data_directory"),
        "{log}"
    );
    // psql is looked for in the system's directories only: a program under /usr/local can never
    // stand in for it.
    let psql = log.lines().find(|l| l.starts_with("psql ")).unwrap();
    assert!(!psql.contains("/usr/local"), "{psql}");
    assert_eq!(
        fx.meta("pg_datadir").as_deref(),
        Some("/var/lib/postgresql/16/main")
    );
    assert_eq!(fx.meta("pg_datadir_stamp"), Some(stamp(0)));

    clear_log(&fx);
    fx.hourly(3600);
    assert!(
        !fx.log().contains("setpriv --reuid=postgres"),
        "read once a day: {}",
        fx.log()
    );
    let x = fx.record("dbstate:xid").unwrap();
    let s = fx.record("dbstate:slots").unwrap();
    let l = fx.record("dbstate:locks").unwrap();
    assert_eq!(
        (
            x[3].as_str(),
            x[4].as_str(),
            x[6].as_str(),
            x[7].as_str(),
            x[11].as_str(),
            x[29].as_str()
        ),
        ("db-xid", "ledger", "ACT", "open", "db.xid", "1")
    );
    assert_eq!(
        (s[3].as_str(), s[6].as_str(), s[11].as_str()),
        ("db-slots", "ACT", "db.slots")
    );
    assert_eq!(
        (l[3].as_str(), l[6].as_str(), l[7].as_str(), l[29].as_str()),
        ("db-locks", "NOTICE", "open", "0")
    );

    fx.stub_file("pg.state", "100\n10|100|3\n0\n123456789\n");
    fx.hourly(7200);
    assert_eq!(state_of(&fx, "dbstate:xid"), "open");
    fx.hourly(10800);
    for key in ["dbstate:xid", "dbstate:slots", "dbstate:locks"] {
        let f = fx.record(key).unwrap();
        assert_eq!(
            (f[7].as_str(), f[22].as_str()),
            ("resolved", "clean2"),
            "{key}"
        );
    }
    assert!(!everything(&fx).contains("s3cret-error-text"));

    let fx = Fx::new();
    fx.database("0|f|");
    fx.stub_file("uid.postgres", "117\n");
    fx.stub_file("pg.state", "100\n10|100|3\n0\n1\n");
    fx.stub_file("psql.out", "/var/lib/pg main\n");
    fx.hourly(0);
    assert_eq!(fx.meta("pg_datadir"), None);
}

/// An env file changed after the unit that loads it started (`EnvironmentFiles` from systemctl,
/// the change seen by a pass after the unit's start, in the same boot) is edited and not in force:
/// change-pending (NOTICE, host) on change:<unit> on the second hourly pass. A unit restarted
/// since the edit is not. An env file's `H` line holds a hash of the whole file and a hash of its
/// sorted key names, and nothing of its values.
#[test]
fn an_env_file_edited_after_its_unit_started_opens_change_pending_and_no_value_is_kept() {
    let fx = Fx::new();
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            (
                "EnvironmentFiles",
                "/etc/propolis/propolis.env (ignore_errors=no)",
            ),
            ("NeedDaemonReload", "no"),
        ],
    );
    fx.unit(
        "sensor-http.service",
        &[(
            "EnvironmentFiles",
            "/etc/propolis/sensors.env (ignore_errors=yes)",
        )],
    );
    fx.write(
        "etc/propolis/sensors.env",
        "PROPOLIS_HTTP_BIND=0.0.0.0:80\n",
    );
    fx.hourly(0);
    let h = fx
        .observe_text()
        .lines()
        .find(|l| l.starts_with("H\t/etc/propolis/propolis.env\t"))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{}", fx.observe_text()));
    let f: Vec<&str> = h.split('\t').collect();
    assert_eq!(f[3], "-", "a file first seen has no change: {h}");
    let keys = Command::new("bash")
        .arg("-c")
        .arg("printf 'PROPOLIS_OPS_NTFY_TOPIC\\nPROPOLIS_OPS_NTFY_URL\\n' | sha256sum")
        .output()
        .unwrap();
    assert_eq!(f[4], &String::from_utf8_lossy(&keys.stdout)[..8], "{h}");
    assert!(fx.records().iter().all(|r| !r[2].starts_with("change:")));

    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk-s3cret-value\n",
    );
    fx.write(
        "etc/propolis/sensors.env",
        "PROPOLIS_HTTP_BIND=0.0.0.0:8080\n",
    );
    fx.unit(
        "sensor-http.service",
        &[
            (
                "EnvironmentFiles",
                "/etc/propolis/sensors.env (ignore_errors=yes)",
            ),
            ("ActiveEnterTimestampMonotonic", &entered(3600, 600)),
        ],
    );
    // sensors.env was edited at 2000 s, before sensor-http restarted at 3000 s.
    fx.stat_map(&[(
        "/etc/propolis/sensors.env",
        "-",
        "%Z",
        &(WALL + 2000).to_string(),
    )]);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "change:propolis.service"), "pending");
    assert_eq!(state_of(&fx, "change:sensor-http.service"), "none");
    fx.hourly(7200);
    let f = fx.record("change:propolis.service").unwrap();
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
            "change-pending",
            "host",
            "NOTICE",
            "open",
            "change.env",
            "0"
        )
    );
    assert_eq!(state_of(&fx, "change:sensor-http.service"), "none");
    let kept = everything(&fx);
    for secret in [
        "t0p1c-secret",
        "tk-s3cret-value",
        "ntfy.example.invalid",
        "0.0.0.0:8080",
    ] {
        assert!(!kept.contains(secret), "{secret} was kept");
    }
}

/// A unit systemd says needs a daemon reload (its unit file changed under it) and a unit whose
/// running binary was replaced (its /proc exe link ends in ` (deleted)`) open change-pending on
/// the second hourly pass, causes change.unit and change.binary; clean on two passes resolves them.
#[test]
fn a_unit_needing_a_reload_or_running_a_deleted_binary_opens_change_pending() {
    let fx = Fx::new();
    fx.unit("sensor-ssh.service", &[("NeedDaemonReload", "yes")]);
    fx.unit("sensor-http.service", &[("MainPID", "5151")]);
    std::fs::create_dir_all(fx.p("proc/5151")).unwrap();
    std::os::unix::fs::symlink(
        "/usr/local/bin/sensor-http (deleted)",
        fx.p("proc/5151/exe"),
    )
    .unwrap();
    fx.hourly(0);
    fx.hourly(3600);
    let s = fx
        .record("change:sensor-ssh.service")
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    let h = fx.record("change:sensor-http.service").unwrap();
    assert_eq!((s[7].as_str(), s[11].as_str()), ("open", "change.unit"));
    assert_eq!((h[7].as_str(), h[11].as_str()), ("open", "change.binary"));
    fx.unit("sensor-ssh.service", &[("NeedDaemonReload", "no")]);
    std::fs::remove_file(fx.p("proc/5151/exe")).unwrap();
    std::os::unix::fs::symlink("/usr/local/bin/sensor-http", fx.p("proc/5151/exe")).unwrap();
    fx.hourly(7200);
    fx.hourly(10800);
    for key in ["change:sensor-ssh.service", "change:sensor-http.service"] {
        let f = fx.record(key).unwrap();
        assert_eq!(
            (f[7].as_str(), f[22].as_str()),
            ("resolved", "clean2"),
            "{key}"
        );
    }
}

/// A rotation the guard refused for want of space (cause guard.no_space) folds under the open
/// volume record of the filesystem that holds the sensor logs, by the late-parent rule: it counts
/// nothing more. While the volume record is only pending there is no parent.
#[test]
fn a_rotation_refused_for_space_folds_under_the_open_volume_record_of_the_log_filesystem() {
    let fx = Fx::new();
    salt(&fx);
    std::fs::create_dir_all(fx.p("var/log/propolis")).unwrap();
    let rot = with_field(
        &hook_record("w#7", "propolis-logrotate.service", "ACT", "open", 0, "-"),
        11,
        "guard.no_space",
    );
    fx.incidents(&[rot]);
    fx.stub_file("df.answer", "100000000000 10000000000 6000000 5000000 /");
    let vol = format!("vol:{}", mount_id("/"));
    fx.hourly(0);
    assert_eq!(
        fx.record("unit:propolis-logrotate.service").unwrap()[13],
        "-"
    );
    fx.hourly(3600);
    let parent = fx.record(&vol).unwrap();
    assert_eq!(parent[7], "open");
    let f = fx.record("unit:propolis-logrotate.service").unwrap();
    assert_eq!((f[13].as_str(), f[29].as_str()), (parent[1].as_str(), "1"));
    assert!(f[30].contains("folded"), "{}", f[30]);
}

/// The witness watches, by inode, size and modification time, every binary deploy/upgrade.sh
/// installs in /usr/local/bin (its INSTALL_BINS, which is install.sh's list and the split
/// deployment's two).
#[test]
fn the_witness_watches_every_binary_upgrade_sh_installs() {
    let upgrade = std::fs::read_to_string(UPGRADE).unwrap();
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let names = |text: &str, prefix: &str| -> Vec<String> {
        let line = text
            .lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no {prefix} line"));
        line[prefix.len()..]
            .trim_end_matches(')')
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    let installed = names(&upgrade, "INSTALL_BINS=(");
    assert!(installed.len() >= 16, "{installed:?}");
    assert_eq!(names(&script, "WITNESS_BINS=("), installed);
}

/// A filesystem of 100 GB with 10% free, under the daemon's default share of 15%.
const VOL_LOW: &str = "100000000000 10000000000 6000000 5000000";
/// The same with 60% free.
const VOL_ROOMY: &str = "100000000000 60000000000 6000000 5000000";
/// The same with 1 GB free: under 1 GiB and the guard's 512 MiB reserve.
const VOL_SOON: &str = "100000000000 1000000000 6000000 5000000";
/// The data directory a Debian PostgreSQL 16 gives `SHOW data_directory`.
const DATA_DIR: &str = "/var/lib/postgresql/16/main";

/// A df answer for a filesystem mounted on `target`.
fn vol(answer: &str, target: &str) -> String {
    format!("{answer} {target}")
}

/// How many `df` calls the stub log holds for the host path `path`.
fn df_calls(fx: &Fx, path: &str) -> usize {
    let tail = format!(" {}", fx.p(path.trim_start_matches('/')).display());
    fx.log()
        .lines()
        .filter(|l| l.starts_with("df ") && l.ends_with(&tail))
        .count()
}

/// The `Z` lines of mount id `m` in the observe file.
fn z_lines(fx: &Fx, m: &str) -> Vec<String> {
    let prefix = format!("Z\t{m}\t");
    fx.observe_text()
        .lines()
        .filter(|l| l.starts_with(&prefix))
        .map(str::to_string)
        .collect()
}

/// The result (ok or unknown) of the P line `name`.
fn result_of(fx: &Fx, name: &str) -> String {
    p_line(fx, name)
        .split('\t')
        .nth(1)
        .unwrap_or("")
        .to_string()
}

/// The backup unit, idle, with this Environment property.
fn backup_env(fx: &Fx, env: &str) {
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
            ("Environment", env),
        ],
    );
}

/// A local database whose state query answers with nothing to report, and the postgres account.
fn quiet_database(fx: &Fx) {
    fx.database("0|f|");
    fx.stub_file("uid.postgres", "117\n");
    fx.stub_file("pg.state", "100\n10|100|3\n0\n1\n");
}

/// The push target, the database and these lines, as propolis.env.
fn propolis_env_with(fx: &Fx, lines: &str) {
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
             DATABASE_URL={DB_URL}\n{lines}"
        ),
    );
}

/// The H line of `path` in the observe file, its fields after `H` and the path.
fn h_line(fx: &Fx, path: &str) -> Option<String> {
    let prefix = format!("H\t{path}\t");
    fx.observe_text()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(str::to_string))
}

/// The first 8 hex of sha256 of `text`.
fn sha8(text: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg("printf '%s' \"$1\" | sha256sum")
        .arg("_")
        .arg(text)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)[..8].to_string()
}

/// Every store's filesystem gets one df: the backups where a drop-in of the backup unit moves
/// them (PROPOLIS_BACKUP_DIR in its Environment property), the gateway's spool where gateway.env
/// moves it, and the local data directory, each on a filesystem of its own here. The pass
/// completes, writes its heartbeat line and the volume check reads ok. A backup directory with a
/// `..` component and a gateway spool with a blank in it are not used: their defaults are sampled.
#[test]
fn every_store_filesystem_gets_one_df_including_the_backup_directory_its_unit_sets() {
    let fx = Fx::new();
    salt(&fx);
    quiet_database(&fx);
    backup_env(&fx, "PROPOLIS_BACKUP_DIR=/srv/b");
    fx.write(
        "etc/propolis/gateway.env",
        "PROPOLIS_GATEWAY_SPOOL_DIR=/srv/gw\n",
    );
    fx.filesystems(&[
        ("/var/lib/propolis", 801),
        ("/srv/b", 802),
        ("/srv/gw", 803),
        (DATA_DIR, 804),
    ]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_ROOMY, "/")),
        ("/srv/b", &vol(VOL_ROOMY, "/srv/b")),
        ("/srv/gw", &vol(VOL_ROOMY, "/srv/gw")),
        (DATA_DIR, &vol(VOL_ROOMY, "/pg")),
    ]);
    fx.hourly(0);
    for p in ["/var/lib/propolis", "/srv/b", "/srv/gw", DATA_DIR] {
        assert_eq!(df_calls(&fx, p), 1, "{p}: {}", fx.log());
    }
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("df ")).count(),
        4,
        "{}",
        fx.log()
    );
    for t in ["/", "/srv/b", "/srv/gw", "/pg"] {
        assert_eq!(
            z_lines(&fx, &mount_id(t)).len(),
            1,
            "{t}: {}",
            fx.observe_text()
        );
    }
    assert!(
        fx.read("run/propolis-witness/heartbeat")
            .contains("B\thourly\t")
    );
    assert_eq!(result_of(&fx, "volume"), "ok", "{}", fx.observe_text());

    backup_env(&fx, "PROPOLIS_BACKUP_DIR=/srv/../etc");
    fx.write(
        "etc/propolis/gateway.env",
        "PROPOLIS_GATEWAY_SPOOL_DIR=\"/srv/g w\"\n",
    );
    fx.filesystems(&[
        ("/var/lib/propolis", 801),
        ("/srv/b", 802),
        ("/srv/gw", 803),
        (DATA_DIR, 804),
        ("/var/spool/propolis", 805),
        ("/var/spool/propolis/gateway", 806),
        ("/var/backups/propolis", 807),
    ]);
    clear_log(&fx);
    fx.hourly(3600);
    for p in ["/var/spool/propolis/gateway", "/var/backups/propolis"] {
        assert_eq!(df_calls(&fx, p), 1, "{p}: {}", fx.log());
    }
    for p in ["/srv/b", "/srv/gw"] {
        assert_eq!(df_calls(&fx, p), 0, "{p}: {}", fx.log());
    }
    assert!(!fx.log().contains("/srv/../etc"), "{}", fx.log());
}

/// A store's path that could not be learnt on a pass (here the backup directory, while systemd
/// does not answer the change sample) leaves the open volume record of its filesystem open and
/// its samples kept, and the volume check reads unknown: a filesystem missing from the samples
/// proves nothing unless every store's path was known. Three such passes in a row open
/// tool-unusable on tool:changes.
#[test]
fn a_store_path_that_could_not_be_learnt_keeps_its_volume_record_and_samples() {
    let mut fx = Fx::new();
    salt(&fx);
    backup_env(&fx, "PROPOLIS_BACKUP_DIR=/srv/b");
    fx.filesystems(&[("/var/lib/propolis", 801), ("/srv/b", 802)]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_ROOMY, "/")),
        ("/srv/b", &vol(VOL_LOW, "/srv/b")),
    ]);
    let m = mount_id("/srv/b");
    let key = format!("vol:{m}");
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &key), "open", "{}", state_text(&fx));
    fx.setenv("SYSTEMCTL_FAIL_ON", "NeedDaemonReload");
    for t in [7200, 10800, 14400] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &key), "open", "at {t}: {}", state_text(&fx));
        assert_eq!(z_lines(&fx, &m).len(), 2, "at {t}: {}", fx.observe_text());
        assert_eq!(result_of(&fx, "volume"), "unknown", "at {t}");
        assert_eq!(result_of(&fx, "changes"), "unknown", "at {t}");
    }
    assert_eq!(state_of(&fx, "tool:changes"), "open");
}

/// A data directory the pass had no time to place (the state query could not start by the soft
/// deadline, so where the database is was not learnt) is still sampled from its cached path, the
/// volume record on its filesystem stays open, and the volume check reads unknown.
#[test]
fn a_data_directory_the_pass_could_not_place_is_sampled_from_its_cache_and_its_record_kept() {
    let mut fx = Fx::new();
    salt(&fx);
    quiet_database(&fx);
    fx.filesystems(&[("/var/lib/propolis", 801), (DATA_DIR, 804)]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_ROOMY, "/")),
        (DATA_DIR, &vol(VOL_LOW, "/pg")),
    ]);
    let key = format!("vol:{}", mount_id("/pg"));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &key), "open", "{}", state_text(&fx));
    fx.setenv("PROPOLIS_WITNESS_SOFT_DEADLINE", "50");
    for t in [7200, 10800] {
        clear_log(&fx);
        fx.hourly(t);
        assert!(
            !fx.log().contains("datfrozenxid"),
            "the state query had no time: {}",
            fx.log()
        );
        assert_eq!(df_calls(&fx, DATA_DIR), 1, "at {t}: {}", fx.log());
        assert_eq!(state_of(&fx, &key), "open", "at {t}: {}", state_text(&fx));
        assert_eq!(result_of(&fx, "volume"), "unknown", "at {t}");
        assert_eq!(result_of(&fx, "pgstate"), "unknown", "at {t}");
    }
}

/// A store whose stat fails for another reason than its absence (here the drop to the postgres
/// account fails) is unknown, not gone: the volume record on its filesystem stays open and the
/// volume check reads unknown.
#[test]
fn a_store_whose_stat_fails_for_another_reason_than_absence_keeps_its_volume_record() {
    let mut fx = Fx::new();
    fx.setenv("PA_TEST_READ_AS_SELF", "0");
    fx.setenv("PA_TEST_UID", "0");
    salt(&fx);
    quiet_database(&fx);
    fx.filesystems(&[("/var/lib/propolis", 801), (DATA_DIR, 804)]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_ROOMY, "/")),
        (DATA_DIR, &vol(VOL_LOW, "/pg")),
    ]);
    let key = format!("vol:{}", mount_id("/pg"));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &key), "open", "{}", state_text(&fx));
    fx.setenv("SETPRIV_FAIL", "117");
    for t in [7200, 10800] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &key), "open", "at {t}: {}", state_text(&fx));
        assert_eq!(result_of(&fx, "volume"), "unknown", "at {t}");
    }
}

/// While df does not answer (a hung mount), an open volume record is unknown, never clean: it
/// stays open over two such passes, and its samples are kept.
#[test]
fn an_open_volume_record_stays_open_while_df_does_not_answer() {
    let fx = Fx::new();
    salt(&fx);
    let m = mount_id("/");
    fx.stub_file("df.answer", &vol(VOL_LOW, "/"));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &format!("vol:{m}")), "open");
    fx.stub_file("df.answer", "hang");
    for t in [7200, 10800] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, &format!("vol:{m}")), "open", "at {t}");
        assert_eq!(z_lines(&fx, &m).len(), 2, "at {t}");
    }
}

/// The rule of two passes opens a volume record at the lower tier of its two passes: full soon
/// and then only filling opens volume-filling (ACT); filling and then full soon opens
/// volume-filling too, and the next full-soon pass raises it to volume-full-soon (PAGE) as a
/// change. Open at PAGE, it stays volume-full-soon on a pass that sees it only filling, with
/// nothing more to push.
#[test]
fn a_volume_record_opens_at_the_lower_tier_of_its_two_passes() {
    let fx = Fx::new();
    salt(&fx);
    let key = format!("vol:{}", mount_id("/"));
    fx.stub_file("df.answer", &vol(VOL_SOON, "/"));
    fx.hourly(0);
    let f = fx.record(&key).unwrap();
    assert_eq!((f[6].as_str(), f[7].as_str()), ("PAGE", "pending"));
    fx.stub_file("df.answer", &vol(VOL_LOW, "/"));
    fx.hourly(3600);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("volume-filling", "ACT", "open", "1")
    );

    let fx = Fx::new();
    salt(&fx);
    fx.stub_file("df.answer", &vol(VOL_LOW, "/"));
    fx.hourly(0);
    fx.stub_file("df.answer", &vol(VOL_SOON, "/"));
    fx.hourly(3600);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("volume-filling", "ACT", "open", "1")
    );
    fx.hourly(7200);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[16].as_str(),
            f[29].as_str()
        ),
        ("volume-full-soon", "PAGE", "open", "change", "2")
    );
    fx.stub_file("df.answer", &vol(VOL_LOW, "/"));
    fx.hourly(10800);
    let f = fx.record(&key).unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("volume-full-soon", "PAGE", "open", "2")
    );
}

/// A data directory reached through a symbolic link (PGDATA moved to a bigger disk, with `SHOW
/// data_directory` naming the link) is sampled where the link leads: the postgres account's stat
/// follows it as root's does, its filesystem gets a df and a Z line, and the record opened on it
/// stays open. A configured sensor log directory that is a link counts the filesystem it leads
/// to as the logs' own: a rotation the guard refused for space folds under that filesystem's
/// open record.
#[test]
fn a_store_reached_through_a_symbolic_link_is_sampled_where_the_link_leads() {
    let fx = Fx::new();
    salt(&fx);
    quiet_database(&fx);
    fx.daemon_account();
    propolis_env_with(&fx, "PROPOLIS_SENSOR_LOGS=ssh:/srv/logs/x.jsonl\n");
    for d in ["data/pg", "data/logs", "var/lib/postgresql/16", "srv"] {
        std::fs::create_dir_all(fx.p(d)).unwrap();
    }
    std::os::unix::fs::symlink(fx.p("data/pg"), fx.p(&DATA_DIR[1..])).unwrap();
    std::os::unix::fs::symlink(fx.p("data/logs"), fx.p("srv/logs")).unwrap();
    // The link to the logs leads to a filesystem of its own; the data directory's target is the
    // test's own filesystem, which no other store here is on.
    fx.stat_map(&[
        ("/var/lib/propolis", "-L", "%d %F", "801 directory"),
        ("/srv/logs", "-L", "%d %F", "806 directory"),
    ]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_ROOMY, "/")),
        (DATA_DIR, &vol(VOL_LOW, "/data/pg")),
        ("/srv/logs", &vol(VOL_LOW, "/data/logs")),
    ]);
    let rot = with_field(
        &hook_record("w#7", "propolis-logrotate.service", "ACT", "open", 0, "-"),
        11,
        "guard.no_space",
    );
    fx.incidents(&[rot]);
    let pg = format!("vol:{}", mount_id("/data/pg"));
    let logs = format!("vol:{}", mount_id("/data/logs"));
    fx.hourly(0);
    assert_eq!(df_calls(&fx, DATA_DIR), 1, "{}", fx.log());
    assert_eq!(
        z_lines(&fx, &mount_id("/data/pg")).len(),
        1,
        "{}",
        fx.observe_text()
    );
    fx.hourly(3600);
    assert_eq!(state_of(&fx, &pg), "open", "{}", state_text(&fx));
    let parent = fx.record(&logs).unwrap();
    assert_eq!(parent[7], "open");
    assert_eq!(
        fx.record("unit:propolis-logrotate.service").unwrap()[13],
        parent[1]
    );
    fx.hourly(7200);
    assert_eq!(state_of(&fx, &pg), "open", "{}", state_text(&fx));
}

/// A configured sensor log directory on a filesystem no fixed store is on is a store of its own:
/// one df, a Z line under its mount id, and its volume record is the one a rotation refused for
/// space folds under, never the open record of a filesystem that holds no logs.
#[test]
fn a_configured_log_directory_on_its_own_filesystem_is_sampled_and_takes_the_rotation_fold() {
    let fx = Fx::new();
    salt(&fx);
    fx.daemon_account();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_SENSOR_LOGS=ssh:/srv/logs/x.jsonl\n",
    );
    fx.filesystems(&[("/var/lib/propolis", 801), ("/srv/logs", 806)]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_LOW, "/varlib")),
        ("/srv/logs", &vol(VOL_LOW, "/srv/logs")),
    ]);
    let rot = with_field(
        &hook_record("w#7", "propolis-logrotate.service", "ACT", "open", 0, "-"),
        11,
        "guard.no_space",
    );
    fx.incidents(&[rot]);
    let m = mount_id("/srv/logs");
    fx.hourly(0);
    assert_eq!(df_calls(&fx, "/srv/logs"), 1, "{}", fx.log());
    assert_eq!(z_lines(&fx, &m).len(), 1, "{}", fx.observe_text());
    fx.hourly(3600);
    let logs = fx.record(&format!("vol:{m}")).unwrap();
    let other = fx.record(&format!("vol:{}", mount_id("/varlib"))).unwrap();
    assert_eq!((logs[7].as_str(), other[7].as_str()), ("open", "open"));
    let f = fx.record("unit:propolis-logrotate.service").unwrap();
    assert_eq!(f[13], logs[1], "{}", state_text(&fx));
}

/// An env file edited after its unit restarted, where the restart came after the pass that last
/// saw the old content, is edited and not in force: the file's last change (its ctime) lies after
/// the unit's start, so change.env opens on the second hourly pass. An edit made before the
/// restart, in the same window, opens nothing.
#[test]
fn an_env_file_edited_after_a_restart_that_followed_the_last_pass_opens_change_pending() {
    let fx = Fx::new();
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            (
                "EnvironmentFiles",
                "/etc/propolis/propolis.env (ignore_errors=no)",
            ),
        ],
    );
    fx.unit(
        "sensor-http.service",
        &[(
            "EnvironmentFiles",
            "/etc/propolis/sensors.env (ignore_errors=yes)",
        )],
    );
    fx.write(
        "etc/propolis/sensors.env",
        "PROPOLIS_HTTP_BIND=0.0.0.0:80\n",
    );
    fx.hourly(0);
    // Both units restart at 3000 s; propolis.env is edited at 3300 s, sensors.env at 2000 s.
    fx.unit(
        "propolis.service",
        &[
            ("Restart", "on-failure"),
            (
                "EnvironmentFiles",
                "/etc/propolis/propolis.env (ignore_errors=no)",
            ),
            ("ActiveEnterTimestampMonotonic", &entered(3600, 600)),
        ],
    );
    fx.unit(
        "sensor-http.service",
        &[
            (
                "EnvironmentFiles",
                "/etc/propolis/sensors.env (ignore_errors=yes)",
            ),
            ("ActiveEnterTimestampMonotonic", &entered(3600, 600)),
        ],
    );
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-other\n",
    );
    fx.write(
        "etc/propolis/sensors.env",
        "PROPOLIS_HTTP_BIND=0.0.0.0:8080\n",
    );
    fx.stat_map(&[
        (
            "/etc/propolis/propolis.env",
            "-",
            "%Z",
            &(WALL + 3300).to_string(),
        ),
        (
            "/etc/propolis/sensors.env",
            "-",
            "%Z",
            &(WALL + 2000).to_string(),
        ),
    ]);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "change:propolis.service"), "pending");
    fx.hourly(7200);
    let f = fx.record("change:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "change.env"));
    assert_eq!(state_of(&fx, "change:sensor-http.service"), "none");
}

/// A pass of another boot that last saw an env file's old content proves nothing about a unit
/// started in this boot, whatever its uptime: the file's ctime decides, and an edit before the
/// unit's start opens nothing while one after it opens change.env. Once the clock was stepped
/// since the unit started, the ctime is no measure and the pass that first saw the new content
/// decides, as uptime against uptime.
#[test]
fn a_pass_of_another_boot_that_last_saw_the_old_content_proves_no_edit_after_a_start() {
    // The last pass of the boot before saw other content, at an uptime past this unit's start.
    let other = format!("{}/0badb007/{}", WALL - 7200, UP + 50_000);
    let setup = |ctime: u64, meta: &str| -> Fx {
        let fx = Fx::new();
        fx.unit(
            "propolis.service",
            &[
                ("Restart", "on-failure"),
                (
                    "EnvironmentFiles",
                    "/etc/propolis/propolis.env (ignore_errors=no)",
                ),
                ("ActiveEnterTimestampMonotonic", &entered(0, 600)),
            ],
        );
        fx.observe(&format!(
            "H\t/etc/propolis/propolis.env\t0000000000000000\t-\t-\t{other}\t-\n"
        ));
        if !meta.is_empty() {
            fx.write(
                "var/lib/propolis/witness/meta",
                &format!("#meta v1 g=1\n{meta}"),
            );
        }
        fx.stat_map(&[("/etc/propolis/propolis.env", "-", "%Z", &ctime.to_string())]);
        fx.hourly(0);
        fx.hourly(3600);
        fx
    };
    let fx = setup(WALL - 3600, "");
    let h = h_line(&fx, "/etc/propolis/propolis.env").unwrap();
    assert!(h.ends_with(&format!("\t{other}")), "{h}");
    assert_eq!(
        state_of(&fx, "change:propolis.service"),
        "none",
        "{}",
        state_text(&fx)
    );
    let fx = setup(WALL - 300, "");
    let f = fx.record("change:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "change.env"));
    let fx = setup(WALL - 3600, &format!("M\tclock_step\t{}/+500\n", stamp(0)));
    let f = fx.record("change:propolis.service").unwrap();
    assert_eq!((f[7].as_str(), f[11].as_str()), ("open", "change.env"));
}

/// The data directory belongs to the postgres account, which can swap any part of the path for a
/// link between a check and a use: its stat (following links) and its df both run as postgres
/// through setpriv, never as root, so whatever the path leads to is opened with that account's
/// rights.
#[test]
fn the_data_directory_is_stat_and_df_as_the_postgres_account() {
    let mut fx = Fx::new();
    fx.setenv("PA_TEST_READ_AS_SELF", "0");
    fx.setenv("PA_TEST_UID", "0");
    salt(&fx);
    quiet_database(&fx);
    std::fs::create_dir_all(fx.p(&DATA_DIR[1..])).unwrap();
    fx.filesystems(&[("/var/lib/propolis", 801)]);
    fx.hourly(0);
    let log = fx.log();
    let path = fx.p(&DATA_DIR[1..]).display().to_string();
    let drops: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with("setpriv --reuid=117 ") && l.contains(&path))
        .collect();
    assert!(drops.iter().any(|l| l.contains("stat -L -c")), "{log}");
    let df = format!("-- df -B1 --output=size,avail,itotal,iavail,target -- {path}");
    assert!(drops.iter().any(|l| l.ends_with(&df)), "{log}");
    let dfs = log
        .lines()
        .filter(|l| l.starts_with("df ") && l.ends_with(&path))
        .count();
    let dropped = drops.iter().filter(|l| l.contains(" df ")).count();
    assert_eq!((dfs, dropped), (1, 1), "{log}");
}

/// The deploy stamp lies in the daemon account's own directory, which that account can rearrange
/// between the listing and the hash (a name swapped for a link to a file only root may read, or
/// to one that never ends): it is hashed as that account, never opened by root.
#[test]
fn a_watched_file_in_the_daemons_own_directory_is_hashed_as_the_daemon_account() {
    let mut fx = Fx::new();
    fx.setenv("PA_TEST_READ_AS_SELF", "0");
    fx.setenv("PA_TEST_UID", "0");
    fx.daemon_account();
    fx.write(
        "var/lib/propolis/deploy-stamp.json",
        "{\"commit\":\"abc\"}\n",
    );
    fx.hourly(0);
    let log = fx.log();
    let path = fx
        .p("var/lib/propolis/deploy-stamp.json")
        .display()
        .to_string();
    assert!(
        log.lines().any(|l| l.starts_with("setpriv --reuid=998 ")
            && l.contains(" sha256sum ")
            && l.ends_with(&path)),
        "{log}"
    );
    assert!(
        h_line(&fx, "/var/lib/propolis/deploy-stamp.json").is_some(),
        "{}",
        fx.observe_text()
    );
}

/// A local database whose data directory could never be read (psql cannot run as the postgres
/// account here, or the server refuses it) leaves the volume check unknown with the cause of
/// that read, not a bare unknown, so the record of the unusable check says what to mend.
#[test]
fn a_data_directory_that_was_never_read_names_why_the_volume_check_is_unknown() {
    for (rc, cause) in [("127", "tool.exec"), ("2", "db.unreachable")] {
        let fx = Fx::new();
        salt(&fx);
        quiet_database(&fx);
        fx.filesystems(&[("/var/lib/propolis", 801)]);
        fx.stub_file("psql.rc", rc);
        fx.hourly(0);
        assert!(fx.meta("pg_datadir").is_none(), "{rc}");
        let p = p_line(&fx, "volume");
        assert!(
            p.contains(&format!("\tunknown\t{cause}\t")),
            "psql status {rc}: {p}"
        );
    }
}

/// The key names of an env file are those of the lines that start an entry: a value that runs
/// on over lines inside a quote, or past a trailing backslash, and a line a comment ending in a
/// backslash runs into, put nothing in the key-name hash, whatever they look like.
#[test]
fn the_key_name_hash_takes_no_line_of_a_value_that_runs_over_lines() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_X=\"line1\nsecretpart=foo\"\n",
    );
    fx.hourly(0);
    let h = h_line(&fx, "/etc/propolis/propolis.env").unwrap();
    assert_eq!(
        h.split('\t').nth(2),
        Some(sha8("PROPOLIS_X\n").as_str()),
        "{h}"
    );

    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_X=\"line1\nsecretpart=foo\"\nPROPOLIS_Y=a\\\ncontinued=b\n# comment\\\nhidden=c\n\
         PROPOLIS_Z='q\nsq=1'\nPROPOLIS_W = \"a \\\" b\"\n",
    );
    fx.hourly(0);
    let h = h_line(&fx, "/etc/propolis/propolis.env").unwrap();
    assert_eq!(
        h.split('\t').nth(2),
        Some(sha8("PROPOLIS_W\nPROPOLIS_X\nPROPOLIS_Y\nPROPOLIS_Z\n").as_str()),
        "{h}"
    );
}

/// When no running unit's /proc exe link can be read (a capability bounding set without
/// CAP_SYS_PTRACE, say), change.binary could never open: the change check reads unknown
/// (tool.exec), and three such passes in a row open tool-unusable on tool:changes.
#[test]
fn a_change_check_that_cannot_read_any_running_binary_reads_unknown() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("proc/4242/exe")).unwrap();
    for t in [0, 3600, 7200] {
        fx.hourly(t);
        let p = p_line(&fx, "changes");
        assert!(p.contains("\tunknown\ttool.exec\t"), "at {t}: {p}");
    }
    assert_eq!(state_of(&fx, "tool:changes"), "open");
}

/// An open change.binary record whose /proc exe link cannot be read is unknown, never clean: it
/// stays open and its clean count starts again, so it resolves only after two readable clean
/// passes in a row.
#[test]
fn an_open_change_binary_record_stays_open_while_the_exe_link_cannot_be_read() {
    let fx = Fx::new();
    fx.unit("sensor-http.service", &[("MainPID", "5151")]);
    std::fs::create_dir_all(fx.p("proc/5151")).unwrap();
    let exe = fx.p("proc/5151/exe");
    std::os::unix::fs::symlink("/usr/local/bin/sensor-http (deleted)", &exe).unwrap();
    fx.hourly(0);
    fx.hourly(3600);
    let key = "change:sensor-http.service";
    assert_eq!(fx.record(key).unwrap()[11], "change.binary");
    std::fs::remove_file(&exe).unwrap();
    std::os::unix::fs::symlink("/usr/local/bin/sensor-http", &exe).unwrap();
    fx.hourly(7200);
    assert_eq!(state_of(&fx, key), "open");
    std::fs::remove_file(&exe).unwrap();
    fx.hourly(10800);
    assert_eq!(state_of(&fx, key), "open");
    std::os::unix::fs::symlink("/usr/local/bin/sensor-http", &exe).unwrap();
    fx.hourly(14400);
    assert_eq!(state_of(&fx, key), "open", "the clean count started again");
    fx.hourly(18000);
    let f = fx.record(key).unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
}

/// Two stores on filesystems stat tells apart but df reports on one mount point (btrfs
/// subvolumes without mounts of their own) are one volume: judged once a pass, so the record is
/// pending after the first pass and not open, and one Z line a pass.
#[test]
fn two_stores_that_df_puts_on_one_mount_point_are_judged_once() {
    let fx = Fx::new();
    salt(&fx);
    fx.filesystems(&[("/var/lib/propolis", 801), ("/var/spool/propolis", 802)]);
    fx.df_map(&[
        ("/var/lib/propolis", &vol(VOL_LOW, "/")),
        ("/var/spool/propolis", &vol(VOL_LOW, "/")),
    ]);
    let m = mount_id("/");
    fx.hourly(0);
    assert_eq!(
        state_of(&fx, &format!("vol:{m}")),
        "pending",
        "{}",
        state_text(&fx)
    );
    assert_eq!(z_lines(&fx, &m).len(), 1, "{}", fx.observe_text());
}

/// The database's state kinds wait out the boot grace: db-xid seen on two hourly passes under
/// 900 s of uptime stays pending and opens on the next pass after it. A manual maintenance marker
/// holds it pending too; an upgrade's marker does not.
#[test]
fn the_database_state_waits_out_the_boot_grace_and_a_manual_marker_but_not_an_upgrade_marker() {
    let mut fx = Fx::new();
    quiet_database(&fx);
    fx.stub_file("pg.state", "1500000000\n10|100|3\n0\n1\n");
    for t in [0, 200] {
        fx.setenv("PROPOLIS_WITNESS_NOW", &early(t));
        fx.hourly_alone(t);
        assert_eq!(state_of(&fx, "dbstate:xid"), "pending", "at {t}");
    }
    fx.setenv("PROPOLIS_WITNESS_NOW", &early(400));
    fx.hourly_alone(400);
    assert_eq!(state_of(&fx, "dbstate:xid"), "open");

    for (reason, state) in [("manual", "pending"), ("upgrade", "open")] {
        let fx = Fx::new();
        quiet_database(&fx);
        fx.stub_file("pg.state", "1500000000\n10|100|3\n0\n1\n");
        fx.write(
            "run/propolis-witness/maintenance",
            &format!(
                "#maintenance v1 g=1\nX\t{}\t{BOOT}\t{reason}\n",
                WALL + 7200
            ),
        );
        fx.hourly(0);
        fx.hourly(3600);
        assert_eq!(state_of(&fx, "dbstate:xid"), state, "{reason}");
    }
}

/// The cached data directory is read again once its stamp is a day old, and when the stamp lies
/// ahead of the clock (no proof the cache is fresh); a read that fails keeps the cached path,
/// which is still sampled as a store.
#[test]
fn the_data_directory_is_read_again_after_a_day_or_a_stamp_ahead_and_a_failed_read_keeps_the_cache()
{
    let fx = Fx::new();
    salt(&fx);
    quiet_database(&fx);
    fx.filesystems(&[("/var/lib/propolis", 801), (DATA_DIR, 804)]);
    let meta = |stamp: &str| {
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!("#meta v1 g=1\nM\tpg_datadir\t{DATA_DIR}\nM\tpg_datadir_stamp\t{stamp}\n"),
        );
    };
    let psql = |fx: &Fx| fx.log().lines().any(|l| l.starts_with("psql "));
    meta(&before(86_400));
    fx.hourly(0);
    assert!(psql(&fx), "a day old: {}", fx.log());
    meta(&stamp(90_000));
    clear_log(&fx);
    fx.hourly(3600);
    assert!(psql(&fx), "ahead of the clock: {}", fx.log());
    meta(&before(86_400));
    fx.stub_file("psql.rc", "2");
    clear_log(&fx);
    fx.hourly(7200);
    assert!(psql(&fx), "{}", fx.log());
    assert_eq!(df_calls(&fx, DATA_DIR), 1, "{}", fx.log());
    assert_eq!(fx.meta("pg_datadir").as_deref(), Some(DATA_DIR));
}

/// A watched directory whose listing fails keeps every line of its files exactly as read, though
/// a file in it changed, and the change check reads unknown.
#[test]
fn a_watched_directory_whose_listing_fails_keeps_its_files_lines_and_the_change_check_reads_unknown()
 {
    let fx = Fx::new();
    fx.hourly(0);
    let lines = |fx: &Fx| -> Vec<String> {
        let mut v: Vec<String> = fx
            .observe_text()
            .lines()
            .filter(|l| l.starts_with("H\t/etc/propolis/"))
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };
    let before = lines(&fx);
    assert!(!before.is_empty(), "{}", fx.observe_text());
    write_exec(
        &fx.bin.join("find"),
        "#!/usr/bin/env bash\nd=\"${UNITS%/units}\"\n\
         if [[ $1 == */etc/propolis ]] && [ -f \"$d/find.fail\" ]; then exit 1; fi\n\
         exec /usr/bin/find \"$@\"\n",
    );
    fx.stub_file("find.fail", "");
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-other\n",
    );
    fx.hourly(3600);
    assert_eq!(lines(&fx), before);
    assert_eq!(result_of(&fx, "changes"), "unknown");
}

/// A filesystem's samples are held to the newest 224 (seven days of passes 45 minutes apart): with
/// 230 kept and this pass's added, the seven oldest go.
#[test]
fn the_samples_of_one_filesystem_are_held_to_224_and_the_oldest_go_first() {
    let fx = Fx::new();
    salt(&fx);
    let m = mount_id("/");
    let ages: Vec<u64> = (0..230u64).map(|i| 518_400 - i * 2248).collect();
    let text: String = ages
        .iter()
        .map(|a| format!("Z\t{m}\t{}\t{VOL_ROOMY_TAB}\n", before(*a)))
        .collect();
    fx.observe(&text);
    fx.hourly(0);
    let z = z_lines(&fx, &m);
    assert_eq!(z.len(), 224);
    for a in &ages[..7] {
        assert!(
            !z.iter().any(|l| l.contains(&before(*a))),
            "{} was kept",
            before(*a)
        );
    }
    assert!(z[0].contains(&before(ages[7])), "{}", z[0]);
    assert!(z[223].contains(&stamp(0)), "{}", z[223]);
}

/// VOL_ROOMY as the four tab-separated fields of a Z line.
const VOL_ROOMY_TAB: &str = "100000000000\t60000000000\t6000000\t5000000";

/// PROPOLIS_OPS_CAPACITY_FREE_PCT outside the daemon's 1 to 100 would make it refuse to start, so
/// the witness judges by the default of 15 then: 12% free opens volume-filling.
#[test]
fn a_free_share_setting_out_of_range_judges_by_the_default_of_fifteen() {
    for pct in ["0", "101"] {
        let fx = Fx::new();
        salt(&fx);
        fx.write(
            "etc/propolis/propolis.env",
            &format!(
                "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
                 PROPOLIS_OPS_CAPACITY_FREE_PCT={pct}\n"
            ),
        );
        fx.stub_file("df.answer", "100000000000 12000000000 6000000 5000000 /");
        fx.hourly(0);
        fx.hourly(3600);
        let f = fx
            .record(&format!("vol:{}", mount_id("/")))
            .unwrap_or_else(|| panic!("{pct}: {}", state_text(&fx)));
        assert_eq!(
            (f[3].as_str(), f[7].as_str()),
            ("volume-filling", "open"),
            "{pct}"
        );
    }
}

/// A state query that fails on three hourly passes in a row opens tool-unusable on tool:pgstate.
#[test]
fn a_state_query_that_fails_three_times_opens_tool_unusable() {
    let fx = Fx::new();
    quiet_database(&fx);
    fx.stub_file("pg.state.rc", "2");
    for t in [0, 3600, 7200] {
        fx.hourly(t);
        assert_eq!(result_of(&fx, "pgstate"), "unknown", "at {t}");
    }
    assert_eq!(state_of(&fx, "tool:pgstate"), "open");
}

/// A server whose reserved slots take every connection (max_connections 3, 3 reserved) has no
/// usable slot to count against: no db-slots, and no arithmetic error.
#[test]
fn a_server_with_every_slot_reserved_opens_no_db_slots() {
    let fx = Fx::new();
    quiet_database(&fx);
    fx.stub_file("pg.state", "100\n3|3|3\n0\n1\n");
    fx.hourly(0);
    let r = fx.hourly(3600);
    assert_eq!(
        state_of(&fx, "dbstate:slots"),
        "none",
        "{}",
        state_text(&fx)
    );
    assert_eq!(result_of(&fx, "pgstate"), "ok");
    assert!(
        !r.err.contains("division") && !r.err.contains("syntax error"),
        "{}",
        r.err
    );
}

/// An open db-xid record is unknown, never clean, while the state query fails: it stays open over
/// two such passes and the check reads unknown.
#[test]
fn an_open_database_state_record_stays_open_while_the_query_fails() {
    let fx = Fx::new();
    quiet_database(&fx);
    fx.stub_file("pg.state", "1500000000\n10|100|3\n0\n1\n");
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "dbstate:xid"), "open");
    fx.stub_file("pg.state.rc", "2");
    for t in [7200, 10800] {
        fx.hourly(t);
        assert_eq!(state_of(&fx, "dbstate:xid"), "open", "at {t}");
        assert_eq!(result_of(&fx, "pgstate"), "unknown", "at {t}");
    }
}

/// A data directory psql names with a `..` component is never stored, and an EnvironmentFiles
/// value with a blank in it (which would split into two paths) is not used: a unit that loads
/// some other file opens no change.env for an edit of propolis.env.
#[test]
fn paths_out_of_form_from_psql_or_a_unit_are_never_used() {
    let fx = Fx::new();
    quiet_database(&fx);
    fx.stub_file("psql.out", "/var/lib/../etc\n");
    fx.hourly(0);
    assert_eq!(fx.meta("pg_datadir"), None);

    let fx = Fx::new();
    fx.unit(
        "sensor-http.service",
        &[(
            "EnvironmentFiles",
            "/etc/propolis/x.env /etc/propolis/propolis.env (ignore_errors=yes)",
        )],
    );
    fx.hourly(0);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-other\n",
    );
    fx.hourly(3600);
    fx.hourly(7200);
    assert_eq!(
        state_of(&fx, "change:sensor-http.service"),
        "none",
        "{}",
        state_text(&fx)
    );
}

/// An env file over 1 MiB is no env file systemd would load whole: its key names are not read
/// (keys8 `-`). A file in /etc/propolis that root does not own gets no H line; only a run as root
/// can give a file another owner, so a run without root checks the other half, that root's own
/// file gets one.
#[test]
fn an_env_file_over_a_mebibyte_has_no_key_hash_and_a_file_root_does_not_own_no_h_line() {
    let fx = Fx::new();
    let big = format!("PROPOLIS_A=1\n#{}\n", "x".repeat(1_048_576));
    fx.write("etc/propolis/big.env", &big);
    fx.write("etc/propolis/other.env", "PROPOLIS_B=1\n");
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        std::os::unix::fs::chown(fx.p("etc/propolis/other.env"), Some(65534), Some(65534)).unwrap();
    } else {
        eprintln!(
            "not root: a file of another owner cannot be made; checking root's own file instead"
        );
    }
    fx.hourly(0);
    let h = h_line(&fx, "/etc/propolis/big.env").unwrap_or_else(|| panic!("{}", fx.observe_text()));
    assert_eq!(h.split('\t').nth(2), Some("-"), "{h}");
    assert_eq!(h_line(&fx, "/etc/propolis/other.env").is_some(), !root);
}
