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
/// pass is told apart by its matches (hook, guard, journald, gateway, shipper, pull, daemon for the
/// daemon's runs): it
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
    *" SYSLOG_IDENTIFIER=propolis-backup-serve "*) class=pull ;;
    *" _SYSTEMD_UNIT=gateway.service "*) class=gateway ;;
    *" _SYSTEMD_UNIT=shipper.service "*) class=shipper ;;
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
/// in `uid.<name>` beside the units (`none`: no such account; `rc=N`: a lookup that fails with
/// status N, as `timeout` gives 124 for one that hangs), else the real `id`.
const ID_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
name="${!#}"
printf 'id %s\n' "$*" >> "$STUB_LOG"
if { [ "${1:-}" = -u ] || [ "${1:-}" = -g ]; } && [ -f "$d/uid.$name" ]; then
    [ "$(cat "$d/uid.$name")" != none ] || exit 1
    case "$(cat "$d/uid.$name")" in rc=*) v="$(cat "$d/uid.$name")"; exit "${v#rc=}" ;; esac
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
/// `disk.refuses` beside the units; otherwise the real `sync`. With `disk.refuses.after` (a count)
/// that many such writes are let through first, the count lowered by each.
const SYNC_STUB: &str = r#"#!/usr/bin/env bash
d="${UNITS%/units}"
if [ -f "$d/disk.refuses" ]; then
    while IFS= read -r glob; do
        for a in "$@"; do
            [[ $a != $glob ]] && continue
            n=0
            [ ! -f "$d/disk.refuses.after" ] || n="$(cat "$d/disk.refuses.after")"
            if [ "$n" -gt 0 ]; then
                echo "$((n - 1))" > "$d/disk.refuses.after"
                break 2
            fi
            exit 1
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

/// Under the legacy profile the one message the witness posts is the daily message (under the
/// test seam's v2 profile, incident messages too), through a config file with
/// `data-binary`: its argv goes to the stub log as `post ...`, the config file to
/// `curl.post.conf` and its mode to `curl.post.mode`, its environment to `curl.post.env`, the body
/// it reads on stdin to `curl.posts` (each followed by a `--` line), and it is answered with the
/// status in `curl.post` (200 without one). With `curl.post.hold` (the path of the state lock) it
/// first starts a process that takes that lock and keeps it, its pid in `curl.post.holder`, as
/// another writer would that holds it past the witness's wait. With `curl.post.snap` it keeps, at
/// each post, the send ledger and the incidents as they then are (`curl.snap.ledger`,
/// `curl.snap.incidents`, each copy followed by a `--` line) and whether the state lock was free
/// (`curl.snap.lock`); with `curl.post.run` it runs that script at each post, the stub's directory
/// its argument, as another writer would act while the post is in flight; with `curl.post.sleep`
/// it sleeps that many seconds before it answers, its pid in `curl.post.pid`. Its other requests that leave the host are the read
/// check's GETs and the heartbeat URL's. Records the argv of those in the stub log as `curl ...`,
/// its environment in
/// `curl.env` and the config file it was handed in `curl.conf`; with no `curl.answer` beside the
/// units it fails as an unreachable server does, and with one (`code|content type`) it answers
/// every GET with that, an empty body, in the `-w` form asked for (a GET whose URL carries a user
/// and password is answered from `curl.answer.userinfo` instead, when there is one, as a server
/// answers credentials it refuses), and the mode of the config file
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
if [ -n "$conf" ] && grep -q '^data-binary' "$conf"; then
    printf 'post %s\n' "$args" >> "$STUB_LOG"
    cat "$conf" >> "$d/curl.post.conf"
    stat -c %a "$conf" > "$d/curl.post.mode"
    env | sed 's/^/curl-env /' >> "$d/curl.post.env"
    { cat; printf '\n--\n'; } >> "$d/curl.posts"
    if [ -f "$d/curl.post.hold" ]; then
        bash -c 'exec 9< "$1"; flock 9; : > "$2"; exec sleep 120' _ "$(cat "$d/curl.post.hold")" \
            "$d/curl.post.held" < /dev/null > /dev/null 2>&1 &
        echo "$!" > "$d/curl.post.holder"
        n=0
        while [ ! -e "$d/curl.post.held" ] && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
    fi
    if [ -f "$d/curl.post.snap" ]; then
        w="$d/root/var/lib/propolis/witness"
        { cat "$w/send-ledger" 2> /dev/null; printf -- '--\n'; } >> "$d/curl.snap.ledger"
        { cat "$w/incidents" 2> /dev/null; printf -- '--\n'; } >> "$d/curl.snap.incidents"
        if flock -n -x "$w/state.lock" true; then echo free; else echo held; fi >> "$d/curl.snap.lock"
    fi
    if [ -f "$d/curl.post.run" ]; then
        bash "$d/curl.post.run" "$d" < /dev/null > /dev/null 2>&1
    fi
    if [ -f "$d/curl.post.sleep" ]; then
        echo "$$" > "$d/curl.post.pid"
        sleep "$(cat "$d/curl.post.sleep")"
    fi
    code=200
    [ ! -f "$d/curl.post" ] || code="$(cat "$d/curl.post")"
    printf '%s' "$code"
    exit 0
fi
printf 'curl %s\n' "$args" >> "$STUB_LOG"
env | sed 's/^/curl-env /' >> "$d/curl.env"
# Which header file, if any, went with which URL: the pairing a token must not cross.
if [ -n "$conf" ]; then
    hdr="nohdr"
    set -- $args
    while [ "$#" -gt 0 ]; do
        if [ "$1" = -H ] && [ -f "${2#@}" ]; then hdr="$(tr '\n' ' ' < "${2#@}")"; fi
        shift
    done
    printf '%s %s\n' "$(sed -n 's/^url = "\(.*\)"$/\1/p' "$conf")" "$hdr" >> "$d/curl.pairs"
fi
[ -z "$conf" ] || cat "$conf" >> "$d/curl.conf"
[ -z "$conf" ] || stat -c %a "$conf" > "$d/curl.confmode"
[ -f "$d/curl.answer" ] || exit 7
answer="$d/curl.answer"
if [ -f "$d/curl.answer.userinfo" ] && [ -n "$conf" ] && grep -q '^url = "[a-z]*://[^/"]*@' "$conf"; then
    answer="$d/curl.answer.userinfo"
fi
: > "$out"
IFS='|' read -r code ct < "$answer"
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
    /// Variables the pass is started without, as a unit that sets none of them starts it.
    unset: Vec<String>,
}

impl Fx {
    /// A single box: the daemon and two sensors running, the oneshots idle after a good run,
    /// every timer enabled, a push target set, the public push scheduled by a crontab line, the
    /// library installed and the state directories
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
            unset: Vec::new(),
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
        // The public push runs from a crontab line, as the install docs set it up; with nothing to
        // run it the hourly pass would record the NOTICE push-off on every case.
        fx.write(
            "etc/cron.d/propolis-blocklist",
            "17 * * * * propolis-blocklist /opt/propolis/deploy/blocklist-sync.sh\n",
        );
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
        self.unset.retain(|name| name != k);
        self.env.push((k.to_string(), v.to_string()));
    }

    /// The pass is started without `k` at all.
    fn unsetenv(&mut self, k: &str) {
        self.env.retain(|(name, _)| name != k);
        self.unset.push(k.to_string());
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
        let child = self.start(args, t, true);
        let output = child.wait_with_output().unwrap();
        Run {
            code: output.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&output.stdout).into_owned(),
            err: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// A pass started at time `t` and left running, its output kept (`piped`) or dropped.
    fn start(&self, args: &[&str], t: u64, piped: bool) -> Child {
        let output = || if piped { Stdio::piped() } else { Stdio::null() };
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
            // The zone the witness is started with is the host's for the daily message; a case
            // that needs another sets TZ itself.
            .env("TZ", "UTC0")
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
            .env_remove("PROPOLIS_WITNESS_SEND_CUT")
            .env_remove("PA_TEST_PROFILE")
            .env_remove("DATABASE_URL")
            .stdin(Stdio::null())
            .stdout(output())
            .stderr(output());
        for (k, v) in &self.env {
            command.env(k, v);
        }
        for k in &self.unset {
            command.env_remove(k);
        }
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        command.spawn().unwrap()
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

    /// The fixture's topic proven private at time `t`: a read check of that moment found every
    /// anonymous read refused.
    fn private_topic(&self, t: u64) {
        self.write(
            "var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n",
                s = stamp(t)
            ),
        );
    }

    /// The bodies the curl stub was posted, in order.
    fn posts(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("curl.posts"))
            .unwrap_or_default()
            .split("\n--\n")
            .filter(|b| !b.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// A file the curl stub wrote beside the units, empty when it wrote none.
    fn stub_text(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
    }

    /// The send ledger's lines of class daily.
    fn daily_lines(&self) -> Vec<String> {
        self.read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t") && l.split('\t').nth(2) == Some("daily"))
            .map(str::to_string)
            .collect()
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
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\tnoread\t403\t403\tboth\t403\ttoken:",
            s = stamp(0)
        )),
        "the answer names the token it is about: {rc}"
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
            .contains("alerts: NOT VERIFIED (never)"),
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

/// The read-check binding of URL and TOPIC: the first 16 hex of sha256(URL LF TOPIC LF).
fn binding_of(url: &str, topic: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg("printf '%s\\n%s\\n' \"$1\" \"$2\" | sha256sum | cut -c1-16")
        .arg("_")
        .arg(url)
        .arg(topic)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// With alert.env giving the shell senders a target of their own, the read check runs on both:
/// the hourly pass stores a line of role shell for alert.env's target and one of role daemon for
/// propolis.env's, where the daemon and today's failure hook post. A changed alert.env topic is
/// checked by the next light pass and voids only the shell line; once alert.env is gone the two
/// targets are one again and a single line of role both replaces them.
#[test]
fn with_two_targets_the_read_check_runs_on_both_and_a_change_voids_only_its_own_line() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=a1ert-topic\n",
    );
    let shell = binding_of("https://alert.example.invalid", "a1ert-topic");
    fx.curl_answers("403|text/plain");
    fx.hourly(0);
    let curls = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    assert_eq!(curls(&fx), 6, "three GETs for each target");
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    let lines: Vec<String> = rc
        .lines()
        .filter(|l| l.starts_with("R\t"))
        .map(str::to_string)
        .collect();
    assert_eq!(
        lines,
        vec![
            format!(
                "R\t{shell}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tshell\t403",
                s = stamp(0)
            ),
            format!(
                "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tdaemon\t403",
                s = stamp(0)
            ),
        ],
        "{rc}"
    );
    let conf = std::fs::read_to_string(fx.dir.path().join("curl.conf")).unwrap();
    assert!(conf.contains("https://alert.example.invalid/a1ert-topic/json"));
    assert!(conf.contains("https://ntfy.example.invalid/t0p1c-secret/json"));
    fx.pass(300);
    assert_eq!(
        curls(&fx),
        6,
        "the light pass asks nothing while both are bound"
    );

    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=n3w-topic\n",
    );
    fx.curl_answers("200|application/x-ndjson");
    fx.pass(600);
    assert_eq!(curls(&fx), 9, "only the changed target is asked");
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert!(
        rc.contains(&format!(
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tdaemon\t403\n",
            s = stamp(0)
        )),
        "the daemon's line is untouched: {rc}"
    );
    assert!(
        rc.contains(&format!(
            "R\t{}\t{s}\treadable\t{s}\treadable\t-\t200\t200\tshell\t200\n",
            binding_of("https://alert.example.invalid", "n3w-topic"),
            s = stamp(600)
        )),
        "{rc}"
    );
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("alerts: topic READABLE by anyone"),
        "{}",
        fx.read("run/motd.d/propolis")
    );

    std::fs::remove_file(fx.p("etc/propolis/alert.env")).unwrap();
    fx.curl_answers("403|text/plain");
    fx.pass(900);
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    let lines: Vec<&str> = rc.lines().filter(|l| l.starts_with("R\t")).collect();
    assert_eq!(
        lines,
        vec![format!(
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403",
            s = stamp(900)
        )],
        "{rc}"
    );
    assert_eq!(fx.posts().len(), 0, "nothing is posted, to either target");
}

/// A both line stored before alert.env named a target of its own still stands for the daemon's
/// target, which it is bound to: the first light pass after the targets part asks only the new
/// shell target and keeps what was known of the daemon's.
#[test]
fn the_first_pass_after_the_targets_part_keeps_the_daemons_answer_from_the_both_line() {
    let fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n",
            s = stamp(0)
        ),
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=a1ert-topic\n",
    );
    fx.curl_answers("200|application/x-ndjson");
    fx.pass(300);
    assert_eq!(
        fx.log().lines().filter(|l| l.starts_with("curl ")).count(),
        3
    );
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert!(
        rc.contains(&format!(
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tdaemon\t403\n",
            s = stamp(0)
        )),
        "{rc}"
    );
    assert!(rc.contains("\treadable\t-\t200\t200\tshell\t200\n"), "{rc}");

    // With a token in propolis.env the both line carries that token's answer, which says
    // nothing of the daemon's target, checked without one: the daemon line keeps no token class
    // and names no credential.
    let fx = Fx::new();
    let env = fx.read("etc/propolis/propolis.env");
    fx.write(
        "etc/propolis/propolis.env",
        &format!("{env}PROPOLIS_OPS_NTFY_TOKEN=tk_first-value\n"),
    );
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\tnoread\t403\t403\tboth\t403\ttoken:0123abcd\n",
            s = stamp(0)
        ),
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=a1ert-topic\n",
    );
    fx.curl_answers("200|application/x-ndjson");
    fx.pass(300);
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    assert!(
        rc.contains(&format!(
            "R\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tdaemon\t403\n",
            s = stamp(0)
        )),
        "{rc}"
    );
}

/// The stored answer about a credential names it (kind and salted hash), never the credential:
/// a light pass asks again when the token a post carries is not the one the answer is about, as it
/// does for a changed target, and not while it is the same.
#[test]
fn a_changed_token_is_checked_again_by_the_light_pass_and_the_line_names_no_token() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_first-value\n",
    );
    fx.curl_answers("403|text/plain");
    fx.hourly(0);
    let cred = |fx: &Fx| -> String {
        let rc = fx.read("var/lib/propolis/witness/readcheck");
        let line = rc
            .lines()
            .find(|l| l.starts_with("R\t"))
            .unwrap()
            .to_string();
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 12, "{line}");
        f[11].to_string()
    };
    let first = cred(&fx);
    assert!(
        first.starts_with("token:")
            && first.len() == 14
            && first[6..].bytes().all(|b| b.is_ascii_hexdigit()),
        "{first}"
    );
    let curls = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    assert_eq!(curls(&fx), 4);
    fx.pass(300);
    assert_eq!(curls(&fx), 4, "the same token: nothing asked");
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_second-value\n",
    );
    fx.pass(600);
    assert_eq!(
        curls(&fx),
        8,
        "a changed token is asked within one light pass"
    );
    let second = cred(&fx);
    assert!(second.starts_with("token:") && second != first, "{second}");
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    for secret in ["tk_first-value", "tk_second-value", "t0p1c-secret"] {
        assert!(!rc.contains(secret), "{secret} stored");
        assert!(!fx.log().contains(secret), "{secret} on a command line");
    }
}

/// With two targets on two servers, each with its own token, a token goes only to the server of
/// its own file: the read check of propolis.env's target carries no header at all (the daemon's
/// target is asked anonymously), and alert.env's token goes only with alert.env's host.
#[test]
fn with_two_targets_each_token_goes_only_to_the_server_of_its_own_file() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://daemon.ntfy.invalid\nPROPOLIS_OPS_NTFY_TOPIC=d-topic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_daemon\n",
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://alert.ntfy.invalid\nPROPOLIS_OPS_NTFY_TOPIC=a-topic\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_alert\n",
    );
    fx.curl_answers("403|text/plain");
    fx.hourly(0);
    let pairs = fx.stub_text("curl.pairs");
    let daemon: Vec<&str> = pairs
        .lines()
        .filter(|l| l.starts_with("https://daemon.ntfy.invalid/"))
        .collect();
    assert_eq!(daemon.len(), 3, "{pairs}");
    assert!(daemon.iter().all(|l| l.ends_with(" nohdr")), "{pairs}");
    let with_alert: Vec<&str> = pairs.lines().filter(|l| l.contains("tk_alert")).collect();
    assert_eq!(with_alert.len(), 1, "{pairs}");
    assert!(
        with_alert[0].starts_with("https://alert.ntfy.invalid/a-topic/json"),
        "{pairs}"
    );
    assert!(!pairs.contains("tk_daemon"), "{pairs}");
}

/// A line an older release wrote names no credential. With a token set and the server giving no
/// answer, the first light pass stores the token it was asked with (class unknown), so the next
/// light pass finds the line about the current credential and asks nothing until the hourly pass.
#[test]
fn a_line_that_names_no_credential_is_asked_once_by_a_light_pass_while_the_server_does_not_answer()
{
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_first-value\n",
    );
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\tnoread\t403\t403\tboth\t403\n",
            s = stamp(0)
        ),
    );
    fx.write(
        "var/lib/propolis/witness/id-salt",
        "0123456789abcdef0123456789abcdef\n",
    );
    let curls = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    fx.pass(300);
    let asked = curls(&fx);
    assert!(asked > 0, "the line names no credential: asked once");
    let rc = fx.read("var/lib/propolis/witness/readcheck");
    let line = rc.lines().find(|l| l.starts_with("R\t")).unwrap();
    let f: Vec<&str> = line.split('\t').collect();
    assert_eq!(f.len(), 12, "{line}");
    assert_eq!(f[6], "unknown", "{line}");
    assert!(f[11].starts_with("token:"), "{line}");
    fx.pass(600);
    assert_eq!(curls(&fx), asked, "the second light pass asks nothing");
}

/// Without an id salt a credential cannot be named, which is no reason to ask: a light pass over
/// a line bound to the target makes no read check, whatever credential the line names, and once
/// the salt exists the next light pass asks, since the line is not about the token set now.
#[test]
fn a_light_pass_without_a_salt_asks_nothing_and_asks_once_the_salt_exists() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_first-value\n",
    );
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\tnoread\t403\t403\tboth\t403\ttoken:0123abcd\n",
            s = stamp(0)
        ),
    );
    let _ = std::fs::remove_file(fx.p("var/lib/propolis/witness/id-salt"));
    fx.curl_answers("403|text/plain");
    let curls = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    // The read check runs before the lock, and the pass writes the salt under it.
    fx.pass(300);
    assert_eq!(curls(&fx), 0, "no salt: nothing asked");
    assert!(
        fx.read("var/lib/propolis/witness/id-salt").len() > 30,
        "the pass wrote the salt"
    );
    fx.pass(600);
    assert_eq!(
        curls(&fx),
        4,
        "the line names no credential: asked once the salt exists"
    );
}

/// The legacy hook posts to propolis.env's target, whatever alert.env gives the shell senders: on
/// a host whose propolis.env names no target its failure alerts go to the journal, so a failure
/// alert logged with no undelivered line beside it is the delivery alert-path waits for, even with
/// a target in alert.env; with a target in propolis.env it is not.
#[test]
fn alert_path_counts_a_journal_alert_as_delivered_by_propolis_envs_target_not_alert_envs() {
    let c_line = "{\"__CURSOR\":\"s=1\",\"_SYSTEMD_UNIT\":\"propolis-alert@sensor-ssh.service.service\",\
        \"MESSAGE\":\"sensor-ssh.service entered the failed state on edge\"}\n";
    let run = |daemon_target: bool| {
        let fx = Fx::new();
        let env: String = fx
            .read("etc/propolis/propolis.env")
            .lines()
            .filter(|l| daemon_target || !l.starts_with("PROPOLIS_OPS_NTFY_"))
            .map(|l| format!("{l}\n"))
            .collect();
        fx.write("etc/propolis/propolis.env", &env);
        fx.write(
            "etc/propolis/alert.env",
            "PROPOLIS_OPS_NTFY_URL=https://alert.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=a1ert-topic\n",
        );
        fx.incidents(&[alert_path_record(&stamp(0))]);
        fx.stub_file("journal.hook", c_line);
        fx.pass(300);
        fx.record("alert:shell").unwrap()
    };
    let f = run(false);
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "sent2xx"));
    let f = run(true);
    assert_eq!(
        f[7], "open",
        "propolis.env names a target: the journal is no delivery"
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
    for class in [
        "hook", "guard", "daemon", "journald", "gateway", "shipper", "pull",
    ] {
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

/// The steps by which the witness ties a failed backup to its cause are deploy/backup.sh's own:
/// each step the fold names is one the backup script sets, word for word, so a reworded step
/// fails here instead of leaving a failed backup untied.
#[test]
fn every_backup_step_the_fold_names_is_one_the_backup_script_sets() {
    let witness = std::fs::read_to_string(SCRIPT).unwrap();
    let body = witness
        .split_once("\ntie_backup() {\n")
        .expect("tie_backup")
        .1;
    let cases = body
        .split_once("case \"$BACKUP_STEP\" in\n")
        .expect("the case on the step")
        .1
        .split_once("[ -n \"$parent\" ]")
        .expect("the end of the case")
        .0;
    let mut steps = Vec::new();
    for line in cases.lines().map(str::trim) {
        if line.starts_with('"') || line.starts_with("| \"") {
            steps.extend(line.split('"').skip(1).step_by(2).map(str::to_string));
        }
    }
    assert_eq!(
        steps,
        [
            "reading the ledger's chain head",
            "dumping the database",
            "checking the ledger against the chain heads earlier sets recorded",
            "checking free space"
        ],
        "{cases}"
    );
    let backup = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/backup.sh"
    ))
    .unwrap();
    for step in &steps {
        assert!(
            backup.contains(&format!("\nSTEP=\"{step}\"\n")),
            "deploy/backup.sh sets no step {step:?}"
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

// ---- the public push, backups and collectors ------------------------------------------------

/// The opaque id of the collector `cn` under `VOL_SALT`: `c` and 5 hex of
/// sha256(salt NUL "collector" NUL cn).
fn collector_id(cn: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg("printf '%s\\0%s\\0%s' \"$1\" collector \"$2\" | sha256sum")
        .arg("_")
        .arg(VOL_SALT)
        .arg(cn)
        .output()
        .unwrap();
    format!("c{}", &String::from_utf8_lossy(&out.stdout)[..5])
}

/// The file `rel` under the root (made when missing), last modified at wall-clock second `wall`.
fn file_at(fx: &Fx, rel: &str, wall: u64) {
    if !fx.p(rel).exists() {
        fx.write(rel, "x\n");
    }
    std::fs::File::options()
        .write(true)
        .open(fx.p(rel))
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(wall))
        .unwrap();
}

/// A control node: the daemon and the gateway enabled and up for a day, the salt known, and
/// PROPOLIS_SENSOR_LOGS listing a local log and the gateway spool of each collector in `listed`.
fn control_node(fx: &Fx, listed: &[&str]) {
    salt(fx);
    fx.unit("gateway.service", &[]);
    let spools: String = listed
        .iter()
        .map(|c| format!(",{c}:/var/spool/propolis/gateway/{c}/events.jsonl"))
        .collect();
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
             PROPOLIS_SENSOR_LOGS=ssh:/var/log/propolis/ssh/events.jsonl{spools}\n"
        ),
    );
}

/// Collector `cn`'s spool file on the gateway, last written at wall-clock second `wall`.
fn spool_at(fx: &Fx, cn: &str, wall: u64) {
    file_at(
        fx,
        &format!("var/spool/propolis/gateway/{cn}/events.jsonl"),
        wall,
    );
}

/// The S line of collector id `cid` in the observe file, its fields after `S` and the id.
fn s_line(fx: &Fx, cid: &str) -> Option<String> {
    let prefix = format!("S\t{cid}\t");
    fx.observe_text()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(str::to_string))
}

/// An observe file whose one line is collector `cid`'s S line: its spool last written at `lastm`
/// (wall-clock seconds), the longest gap of the window, the window's start and the gap of the
/// window before (`-` for none), no advance in a row.
fn seed_s(fx: &Fx, cid: &str, lastm: u64, maxgap: u64, window: &str, prevgap: &str) {
    fx.observe(&format!(
        "S\t{cid}\t{lastm}\t{}\t{maxgap}\t{window}\t{prevgap}\t0\n",
        before(WALL - lastm)
    ));
}

/// An open or pending record of 34 fields as the witness writes one for a kind it sees itself.
#[allow(clippy::too_many_arguments)]
fn witness_record(
    id: &str,
    key: &str,
    kind: &str,
    stage: &str,
    inst: &str,
    tier: &str,
    state: &str,
    cause: &str,
) -> String {
    let mut r = hook_record(id, "propolis-backup.service", tier, state, 0, "-");
    for (i, v) in [
        (2, key),
        (3, kind),
        (4, stage),
        (5, inst),
        (11, cause),
        (33, "-"),
    ] {
        r = with_field(&r, i, v);
    }
    r
}

/// The meta file with `key` set to `value`, every other line kept.
fn set_meta(fx: &Fx, key: &str, value: &str) {
    let text = fx.read("var/lib/propolis/witness/meta");
    let prefix = format!("M\t{key}\t");
    let mut body: String = text
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with(&prefix))
        .map(|l| format!("{l}\n"))
        .collect();
    body.push_str(&format!("{prefix}{value}\n"));
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\n{body}"),
    );
}

/// A backup run's start or end as `ExecMain*TimestampMonotonic` gives it: `secs` before time `t`.
fn mono(t: u64, secs: u64) -> String {
    entered(t, secs)
}

/// A backup run that takes past three times the last run's length opens backup-hung (ACT, the
/// backup rail, cause backup.long) on the second light pass that sees it, and resolves `ended`
/// once the unit is no longer activating. `meta backup_dur` is the last run's length, from a pass
/// that saw the unit inactive with an exit after its start; the limit is the larger of two hours
/// and three times that, so a run past two hours but under three times the usual is no hang.
#[test]
fn a_backup_run_past_its_limit_opens_backup_hung_on_the_second_pass_and_resolves_when_it_ends() {
    let fx = Fx::new();
    let backup = |changes: &[(&str, &str)]| {
        let mut all = vec![
            ("SubState", "dead"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ];
        all.extend_from_slice(changes);
        fx.unit("propolis-backup.service", &all);
    };
    backup(&[
        ("ActiveState", "inactive"),
        ("ExecMainStartTimestampMonotonic", &mono(0, 7600)),
        ("ExecMainExitTimestampMonotonic", &mono(0, 3600)),
    ]);
    fx.pass(0);
    assert_eq!(fx.meta("backup_dur").as_deref(), Some("4000"));
    // Started 11000 s before the pass at 300: past two hours, under three times 4000 s.
    let start = mono(300, 11_000);
    backup(&[
        ("ActiveState", "activating"),
        ("SubState", "start"),
        ("ExecMainStartTimestampMonotonic", &start),
        ("ExecMainExitTimestampMonotonic", "0"),
    ]);
    fx.pass(300);
    assert_eq!(state_of(&fx, "backup:run"), "none", "{}", state_text(&fx));
    fx.pass(1600);
    assert_eq!(state_of(&fx, "backup:run"), "pending");
    fx.pass(1900);
    let f = fx.record("backup:run").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        ("backup-hung", "backup", "ACT", "open", "backup.long", "1")
    );
    assert_eq!(fx.meta("backup_dur").as_deref(), Some("4000"));
    backup(&[
        ("ActiveState", "inactive"),
        ("ExecMainStartTimestampMonotonic", &start),
        ("ExecMainExitTimestampMonotonic", &mono(2200, 100)),
    ]);
    fx.pass(2200);
    let f = fx.record("backup:run").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "ended"));
    assert_eq!(fx.meta("backup_dur").as_deref(), Some("12800"));
}

/// A collector named in PROPOLIS_SENSOR_LOGS whose spool has not been written for longer than
/// max(1800 s, twice the longest gap of its week) opens spool-quiet (ACT, the ship stage, cause
/// spool.quiet) on the second light pass, keyed and named by its opaque id alone: its name is in
/// no record and no observe line. A spool directory nobody listed is config-check's to report
/// and gets nothing here. The spool written on two passes in a row resolves it spool2.
#[test]
fn a_listed_collector_quiet_past_twice_its_longest_gap_opens_spool_quiet_and_two_arrivals_resolve_it()
 {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 7200);
    spool_at(&fx, "c-zz", WALL - 90_000);
    fx.pass(0);
    assert_eq!(
        state_of(&fx, &format!("spool:{cid}")),
        "pending",
        "{}",
        state_text(&fx)
    );
    fx.pass(300);
    let f = fx.record(&format!("spool:{cid}")).unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[5].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        (
            "spool-quiet",
            "ship",
            cid.as_str(),
            "ACT",
            "open",
            "spool.quiet",
            "1"
        )
    );
    assert_eq!(
        fx.records()
            .iter()
            .filter(|f| f[2].starts_with("spool:"))
            .count(),
        1,
        "{}",
        state_text(&fx)
    );
    assert!(s_line(&fx, &collector_id("c-zz")).is_none());
    let text = state_text(&fx);
    assert!(!text.contains("c-01") && !text.contains("c-zz"), "{text}");

    spool_at(&fx, "c-01", WALL + 500);
    fx.pass(600);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "open");
    spool_at(&fx, "c-01", WALL + 800);
    fx.pass(900);
    let f = fx.record(&format!("spool:{cid}")).unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "spool2"));
    let s = s_line(&fx, &cid).unwrap();
    assert_eq!(
        s.split('\t').next(),
        Some((WALL + 800).to_string().as_str())
    );
}

/// spool-quiet does not cry wolf: not before its window is a day old, not before the quiet time
/// passes 1800 s, not before it passes twice the longest gap seen, and not while the gateway has
/// been up under fifteen minutes (a restarted gateway has not heard from its collectors yet):
/// that first sighting waits and opens once the gateway has been up that long.
#[test]
fn spool_quiet_waits_for_a_day_old_window_its_floor_twice_the_longest_gap_and_a_settled_gateway() {
    for (what, lastm, maxgap, window) in [
        ("window an hour old", WALL - 7200, 600, before(3600)),
        ("quiet under 1800 s", WALL - 1500, 600, before(172_800)),
        (
            "quiet under twice the gap",
            WALL - 7200,
            5000,
            before(172_800),
        ),
    ] {
        let fx = Fx::new();
        control_node(&fx, &["c-01"]);
        let cid = collector_id("c-01");
        seed_s(&fx, &cid, lastm, maxgap, &window, "-");
        spool_at(&fx, "c-01", lastm);
        fx.pass(0);
        fx.pass(300);
        assert_eq!(
            state_of(&fx, &format!("spool:{cid}")),
            "none",
            "{what}: {}",
            state_text(&fx)
        );
    }

    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    fx.unit(
        "gateway.service",
        &[("ActiveEnterTimestampMonotonic", &entered(0, 300))],
    );
    let cid = collector_id("c-01");
    seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 7200);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "pending");
    fx.pass(600);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "open");
}

/// A maintenance marker whose reason is manual (`sudo propolis-status --maint`, how an operator
/// says a collector is off on purpose) holds spool-quiet pending; an upgrade's marker does not.
#[test]
fn a_manual_maintenance_marker_holds_spool_quiet_and_an_upgrade_marker_does_not() {
    for (reason, want) in [("manual", "pending"), ("upgrade", "open")] {
        let fx = Fx::new();
        control_node(&fx, &["c-01"]);
        fx.write(
            "run/propolis-witness/maintenance",
            &format!(
                "#maintenance v1 g=1\nX\t{}\t{BOOT}\t{reason}\n",
                WALL + 3600
            ),
        );
        let cid = collector_id("c-01");
        seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
        spool_at(&fx, "c-01", WALL - 7200);
        fx.pass(0);
        fx.pass(300);
        assert_eq!(
            state_of(&fx, &format!("spool:{cid}")),
            want,
            "{reason}: {}",
            state_text(&fx)
        );
    }
}

/// A collector taken out of PROPOLIS_SENSOR_LOGS resolves its spool-quiet record `disabled`.
/// Directories nobody listed, however many and whatever their names, open nothing and leave no
/// line, so they cannot fill the record bound. The spool is listed as the gateway account, which
/// owns it, never as root.
#[test]
fn a_collector_taken_off_the_list_resolves_disabled_and_unlisted_spools_open_nothing() {
    let mut fx = Fx::new();
    control_node(&fx, &["c-02"]);
    let cid = collector_id("c-01");
    fx.incidents(&[witness_record(
        "w#1",
        &format!("spool:{cid}"),
        "spool-quiet",
        "ship",
        &cid,
        "ACT",
        "open",
        "spool.quiet",
    )]);
    for n in 0..600 {
        spool_at(&fx, &format!("u-{n}"), WALL - 90_000);
    }
    spool_at(&fx, "bad\nname", WALL - 90_000);
    // The spool's owner is the gateway account: the listing drops to it.
    let owner = std::fs::metadata(fx.p("var/spool/propolis/gateway"))
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    fx.stub_file("uid.propolis-gateway", &format!("{owner}\n"));
    fx.setenv("PA_TEST_UID", "0");
    fx.setenv("PA_TEST_READ_AS_SELF", "0");
    fx.pass(0);
    let f = fx.record(&format!("spool:{cid}")).unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));
    assert_eq!(fx.records().len(), 1, "{}", state_text(&fx));
    assert!(
        !fx.observe_text().contains("\nS\t"),
        "{}",
        fx.observe_text()
    );
    let log = fx.log();
    assert!(
        log.lines()
            .any(|l| l.starts_with(&format!("setpriv --reuid={owner} "))
                && l.contains(" find ")
                && l.contains("var/spool/propolis/gateway")),
        "{log}"
    );
}

/// The gateway's duplicate line, read by the fields journald sets itself (gateway.service and the
/// gateway account's uid), opens gateway-dup (ACT, the gateway stage, cause gw.dup) on first
/// sight, keyed by the collector's opaque id when its collector_id is a listed collector and by
/// `unlisted` otherwise; the records and suppressed records it counts are summed for the walk. No
/// part of the line is kept. A day without the line resolves it quiet24.
#[test]
fn the_gateways_duplicate_line_opens_gateway_dup_on_first_sight_and_a_quiet_day_resolves_it() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    fx.stub_file("uid.propolis-gateway", "997\n");
    let line = |cn: &str, records: &str, suppressed: &str| {
        format!(
            "2026-11-15T08:00:00.000000Z ERROR gateway::verify: gateway: batch reuses the last \
             accepted seq with different content; acknowledged as Duplicate without storing it \
             collector_id={cn} seq=7 records={records} suppressed_batches=1 \
             suppressed_records={suppressed}\n"
        )
    };
    fx.stub_file(
        "journal.gateway",
        &format!(
            "{}{}{}",
            line("c-01", "3", "2"),
            line("c-other", "4", "0"),
            line("c-01", "x9", "1")
        ),
    );
    fx.pass(0);
    let cid = collector_id("c-01");
    let f = fx
        .record(&format!("gwdup:{cid}"))
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[5].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        (
            "gateway-dup",
            "gateway",
            cid.as_str(),
            "ACT",
            "open",
            "gw.dup",
            "1"
        )
    );
    assert_eq!(
        p_line(&fx, &format!("seen:gwdup:{cid}")).split('\t').nth(3),
        Some("6")
    );
    let f = fx.record("gwdup:unlisted").unwrap();
    assert_eq!((f[5].as_str(), f[7].as_str()), ("-", "open"));
    assert!(
        fx.log().contains("_SYSTEMD_UNIT=gateway.service _UID=997"),
        "{}",
        fx.log()
    );
    let text = state_text(&fx);
    for word in ["c-01", "c-other", "records=", "Duplicate"] {
        assert!(!text.contains(word), "{word}: {text}");
    }

    fx.stub_file("journal.gateway", "");
    fx.pass(86_100);
    assert_eq!(state_of(&fx, &format!("gwdup:{cid}")), "open");
    fx.pass(86_400);
    let f = fx.record(&format!("gwdup:{cid}")).unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "quiet24"));
}

/// A collector: the shipper unit running under the `propolis-shipper` account (uid 995), its
/// env file present and the daemon not enabled.
fn collector_host(fx: &Fx) {
    fx.write("etc/propolis/shipper.env", "");
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("UnitFileState", "disabled"),
        ],
    );
    fx.unit("shipper.service", &[]);
    fx.stub_file("uid.propolis-shipper", "995\n");
}

/// The shipper's lines as `journalctl -o cat` prints them: the log format's timestamp, the level
/// padded to five columns, the target, the message and then the fields.
const SHIP_CONNECT: &str = "2026-11-15T08:00:00.000000Z ERROR shipper: shipper: failed to connect \
     to gateway; will retry next pass error=connection refused\n";
const SHIP_IO: &str = "2026-11-15T08:00:00.000000Z ERROR shipper: shipper: ship cycle IO error; \
     will retry next pass error=broken pipe\n";
const SHIP_REJECTED: &str = "2026-11-15T08:00:00.000000Z ERROR shipper: shipper: gateway rejected \
     a batch; the shared seq/hash chain is out of step seq=7\n";

/// A buffer the log format writes into.
#[derive(Clone, Default)]
struct LogBuf(std::sync::Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

/// What `journalctl -o cat` prints for the events `emit` logs: each rendered by the format every
/// Propolis binary uses when its output is the journal, less the priority prefix journald takes
/// off. The fixtures above are written by hand in this form; a test that needs to know the form
/// is the real one builds its lines here.
fn journal_lines(emit: impl FnOnce()) -> String {
    use tracing_subscriber::layer::SubscriberExt as _;
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::registry().with(log_format::layer_for(
        log_format::Mode::Journal,
        buf.clone(),
    ));
    tracing::subscriber::with_default(subscriber, emit);
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    text.lines()
        .map(|l| {
            let (prefix, rest) = l.split_once('>').expect("a priority prefix");
            assert!(prefix.starts_with('<'), "{l}");
            format!("{rest}\n")
        })
        .collect()
}

/// The shipper's WARN line for a line the origin policy refused, its error quoting the sensor
/// name the line claimed (Debug-quoted, cut to 64 characters, as sensor-wire's claim() does).
fn ship_warn(claimed: &str) -> String {
    format!(
        "2026-11-15T08:00:01.000000Z  WARN shipper::batcher: shipper: dropping a line the origin \
         policy refuses for this log sensor=ssh error=log \"ssh\": the line names sensor \
         {claimed:?}, which is not a known sensor\n"
    )
}

/// On a collector, the shipper's ERROR lines (read by shipper.service and the shipper account's
/// uid) on three light passes in a row open ship-failing (ACT, key ship:local, cause from the
/// line: ship.connect here), and two passes without one resolve it clean2. Its WARN lines, shown
/// only with RUST_LOG set, open the NOTICE ship-dropped on first sight.
#[test]
fn shipper_errors_on_three_passes_open_ship_failing_and_its_warnings_open_ship_dropped() {
    let fx = Fx::new();
    collector_host(&fx);
    fx.stub_file(
        "journal.shipper",
        &format!("{SHIP_CONNECT}{}", ship_warn("ssh")),
    );
    fx.pass(0);
    assert_eq!(
        state_of(&fx, "ship:local"),
        "pending",
        "{}",
        state_text(&fx)
    );
    let f = fx.record("shipdrop:local").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        ("ship-dropped", "NOTICE", "open", "ship.dropped", "0")
    );
    assert!(
        fx.log().contains("_SYSTEMD_UNIT=shipper.service _UID=995"),
        "{}",
        fx.log()
    );
    fx.pass(300);
    assert_eq!(state_of(&fx, "ship:local"), "pending");
    fx.pass(600);
    let f = fx.record("ship:local").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str()
        ),
        ("ship-failing", "ship", "ACT", "open", "ship.connect")
    );
    fx.stub_file("journal.shipper", "");
    fx.pass(900);
    assert_eq!(state_of(&fx, "ship:local"), "open");
    fx.pass(1200);
    let f = fx.record("ship:local").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
}

/// The off-host pull's `served` line, read by the pull account's uid and the serve script's fixed
/// identifier, sets `meta pull_last` to the pass that saw it; a line out of the served form
/// does not.
#[test]
fn a_served_line_from_the_pull_account_sets_meta_pull_last() {
    let fx = Fx::new();
    write_exec(
        &fx.p("usr/local/sbin/propolis-backup-serve"),
        "#!/usr/bin/env bash\n",
    );
    fx.stub_file("uid.propolis-backup-pull", "996\n");
    fx.stub_file(
        "journal.pull",
        "served 20261010T033000Z-scheduled state.tgz.age\n",
    );
    fx.pass(0);
    assert_eq!(fx.meta("pull_last"), Some(stamp(0)));
    assert!(
        fx.log()
            .contains("_UID=996 SYSLOG_IDENTIFIER=propolis-backup-serve"),
        "{}",
        fx.log()
    );
    fx.stub_file("journal.pull", "served ../../etc/passwd x\n");
    fx.pass(300);
    assert_eq!(fx.meta("pull_last"), Some(stamp(0)));
}

/// A crontab line that runs the push, the push marker last written at `pushed` and the feed's
/// publish marker at `published` (wall-clock seconds; None: no such file).
fn push_host(fx: &Fx, pushed: Option<u64>, published: Option<u64>) {
    fx.write(
        "etc/cron.d/propolis-blocklist",
        "17 * * * * propolis-blocklist /opt/propolis/deploy/blocklist-sync.sh\n",
    );
    if let Some(w) = pushed {
        file_at(fx, "var/lib/propolis/blocklist-status/last-pushed", w);
    }
    if let Some(w) = published {
        file_at(fx, "var/lib/propolis/feed/.current.last_published", w);
    }
}

/// A scheduled push whose feed was published after the last push, and whose last push is over
/// six hours old, opens push-failing (ACT, the publish stage, cause push.stale) on the second
/// hourly pass, its onset the push marker's time; a push after that onset resolves it `pushed`.
#[test]
fn push_failing_opens_when_the_feed_moved_on_and_the_push_is_six_hours_old_and_a_push_resolves_it()
{
    let fx = Fx::new();
    push_host(&fx, Some(WALL - 25_200), Some(WALL - 3600));
    fx.hourly(0);
    let f = fx
        .record("push:cron")
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!(
        (f[7].as_str(), f[10].clone()),
        ("pending", format!("{}/-/0", WALL - 25_200))
    );
    fx.hourly(3600);
    let f = fx.record("push:cron").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str(),
            f[29].as_str()
        ),
        ("push-failing", "publish", "ACT", "open", "push.stale", "1")
    );
    file_at(
        &fx,
        "var/lib/propolis/blocklist-status/last-pushed",
        WALL + 3700,
    );
    fx.hourly(7200);
    let f = fx.record("push:cron").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "pushed"));
}

/// No false red from the push: a feed that did not change since the last push (its publish
/// marker older than the push marker) is not stale however old the push, and a push under six
/// hours old is not failing whatever was published since.
#[test]
fn an_unchanged_feed_or_a_push_under_six_hours_old_opens_no_push_failing() {
    for (what, pushed, published) in [
        ("feed unchanged", WALL - 25_200, WALL - 30_000),
        ("push five hours old", WALL - 18_000, WALL - 3600),
    ] {
        let fx = Fx::new();
        push_host(&fx, Some(pushed), Some(published));
        fx.hourly(0);
        fx.hourly(3600);
        assert_eq!(
            state_of(&fx, "push:cron"),
            "none",
            "{what}: {}",
            state_text(&fx)
        );
    }
}

/// With no push marker at all, push-failing waits until the scheduler has been seen for six
/// hours (meta push_sched_since) and a publish came after it was first seen.
#[test]
fn with_no_push_marker_push_failing_counts_six_hours_from_the_scheduler_first_seen() {
    let fx = Fx::new();
    push_host(&fx, None, Some(WALL - 3600));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "push:cron"), "none");
    assert_eq!(fx.meta("push_sched_since"), Some(stamp(0)));

    let fx = Fx::new();
    push_host(&fx, None, Some(WALL - 3600));
    set_meta(&fx, "push_sched_since", &before(25_200));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "push:cron"), "open", "{}", state_text(&fx));
}

/// With the feed enabled and nothing to run the push: push-unscheduled (ACT) when
/// PROPOLIS_OPS_FEED_PUSH_EXPECTED is set, the NOTICE push-off when it is not, each on the
/// second hourly pass.
#[test]
fn no_scheduler_is_push_unscheduled_when_a_push_is_expected_and_a_notice_push_off_when_not() {
    let unscheduled = || {
        let fx = Fx::new();
        std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
        fx
    };
    let fx = unscheduled();
    propolis_env_with(&fx, "PROPOLIS_OPS_FEED_PUSH_EXPECTED=true\n");
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx
        .record("push:none")
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str(), f[11].as_str()),
        ("push-unscheduled", "ACT", "open", "push.none")
    );
    assert_eq!(state_of(&fx, "push:off"), "none");

    let fx = unscheduled();
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx.record("push:off").unwrap();
    assert_eq!(
        (f[3].as_str(), f[6].as_str(), f[7].as_str(), f[29].as_str()),
        ("push-off", "NOTICE", "open", "0")
    );
    assert_eq!(state_of(&fx, "push:none"), "none");
}

/// The name deploy/backup.sh gives a set made at wall-clock second `wall`.
fn set_name(wall: u64) -> String {
    let out = Command::new("date")
        .arg("-u")
        .arg("-d")
        .arg(format!("@{wall}"))
        .arg("+%Y%m%dT%H%M%SZ")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Fewer scheduled sets than PROPOLIS_BACKUP_KEEP (from the backup unit's environment) while the
/// oldest set's name is dated more than KEEP days ago opens the NOTICE backup-retention on the
/// second hourly pass; `meta backup_sets` holds the count against KEEP. Only names in the shape
/// backup.sh prunes count. Enough sets again on two passes resolve it clean2.
#[test]
fn fewer_backup_sets_than_keep_with_the_oldest_past_keep_days_opens_backup_retention() {
    let fx = Fx::new();
    backup_env(&fx, "PROPOLIS_BACKUP_KEEP=3 PROPOLIS_BACKUP_DIR=/srv/bk");
    for (wall, reason) in [
        (WALL - 864_000, "scheduled"),
        (WALL - 777_600, "scheduled"),
        (WALL - 691_200, "pre-upgrade"),
    ] {
        std::fs::create_dir_all(fx.p(&format!("srv/bk/{}-{reason}", set_name(wall)))).unwrap();
    }
    std::fs::create_dir_all(fx.p("srv/bk/notaset-scheduled")).unwrap();
    fx.hourly(0);
    assert_eq!(
        state_of(&fx, "backup:keep"),
        "pending",
        "{}",
        state_text(&fx)
    );
    fx.hourly(3600);
    let f = fx.record("backup:keep").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str()
        ),
        (
            "backup-retention",
            "backup",
            "NOTICE",
            "open",
            "backup.keep"
        )
    );
    assert_eq!(fx.meta("backup_sets").as_deref(), Some("2/3"));
    std::fs::create_dir_all(fx.p(&format!("srv/bk/{}-scheduled", set_name(WALL - 3600)))).unwrap();
    fx.hourly(7200);
    fx.hourly(10_800);
    let f = fx.record("backup:keep").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
}

/// The pull account's authorized_keys, its one key line or only a comment.
fn pull_keys(fx: &Fx, key: bool) {
    fx.stub_file("uid.propolis-backup-pull", "996\n");
    let line = if key {
        "restrict,command=\"/usr/local/sbin/propolis-backup-serve\" ssh-ed25519 AAAA... backup-pull\n"
    } else {
        ""
    };
    fx.write(
        "var/lib/propolis-backup-pull/.ssh/authorized_keys",
        &format!("# the off-host pull\n{line}"),
    );
}

/// A scheduled set in the default backup directory, made at wall-clock second `wall`.
fn scheduled_set(fx: &Fx, wall: u64) {
    std::fs::create_dir_all(fx.p(&format!(
        "var/backups/propolis/{}-scheduled",
        set_name(wall)
    )))
    .unwrap();
}

/// With a pull configured (a key line in the pull account's authorized_keys), a scheduled set
/// made after the last served line that has waited over 72 hours opens the NOTICE backup-offhost
/// on the second hourly pass, and a newer served line resolves it `pulled`. With no key line
/// nothing opens. The authorized_keys file lies in the pull account's home, so it is read as
/// that account.
#[test]
fn an_off_host_pull_that_stopped_for_three_days_opens_backup_offhost_and_a_new_pull_resolves_it() {
    let mut fx = Fx::new();
    pull_keys(&fx, true);
    set_meta(&fx, "pull_last", &before(345_600));
    scheduled_set(&fx, WALL - 300_000);
    fx.setenv("PA_TEST_UID", "0");
    fx.setenv("PA_TEST_READ_AS_SELF", "0");
    fx.hourly(0);
    assert_eq!(
        state_of(&fx, "backup:pull"),
        "pending",
        "{}",
        state_text(&fx)
    );
    // The reading program spans lines, so each setpriv call is taken up to the next log entry.
    let log = fx.log();
    assert!(
        log.split("\nsetpriv ")
            .any(|call| call.starts_with("--reuid=996 ")
                && call
                    .lines()
                    .take_while(|l| !l.starts_with("id ") && !l.starts_with("systemctl "))
                    .any(|l| l.contains("var/lib/propolis-backup-pull/.ssh/authorized_keys"))),
        "{log}"
    );
    fx.hourly(3600);
    let f = fx.record("backup:pull").unwrap();
    assert_eq!(
        (
            f[3].as_str(),
            f[4].as_str(),
            f[6].as_str(),
            f[7].as_str(),
            f[11].as_str()
        ),
        ("backup-offhost", "backup", "NOTICE", "open", "backup.pull")
    );
    set_meta(&fx, "pull_last", &stamp(3700));
    fx.hourly(7200);
    let f = fx.record("backup:pull").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "pulled"));

    let fx = Fx::new();
    pull_keys(&fx, false);
    set_meta(&fx, "pull_last", &before(345_600));
    scheduled_set(&fx, WALL - 300_000);
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "backup:pull"), "none");
}

/// The pull fetches only the newest set and writes no served line when it already holds it, so
/// a pull that works says nothing while no new set appears. With the last served line four days
/// old and no set made since (the backups stopped, which their own records report), nothing
/// opens: no set is waiting. A set made since that is under 72 hours old is not waiting long
/// enough either.
#[test]
fn a_pull_with_no_set_waiting_for_it_opens_no_backup_offhost() {
    for (what, made) in [
        ("no set since the last pull", WALL - 432_000),
        ("a set since, a day old", WALL - 86_400),
    ] {
        let fx = Fx::new();
        pull_keys(&fx, true);
        set_meta(&fx, "pull_last", &before(345_600));
        scheduled_set(&fx, made);
        fx.hourly(0);
        fx.hourly(3600);
        assert_eq!(
            state_of(&fx, "backup:pull"),
            "none",
            "{what}: {}",
            state_text(&fx)
        );
    }
    // A pull switched back on after a time without one (meta pull_since `-`) counts from now:
    // the sets made meanwhile were never its to fetch, however old its last served line is.
    let fx = Fx::new();
    pull_keys(&fx, true);
    set_meta(&fx, "pull_last", &before(864_000));
    set_meta(&fx, "pull_since", "-");
    scheduled_set(&fx, WALL - 300_000);
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "backup:pull"), "none", "{}", state_text(&fx));
    assert_eq!(fx.meta("pull_since"), Some(stamp(0)));
}

/// A pull that never served anything is not silent for ever: the first hourly pass that sees a
/// pull configured starts a clock (meta pull_since), and a set made after it that has waited
/// over 72 hours opens backup-offhost although no served line was ever seen; the first served
/// line resolves it. Sets made before that pass are not counted (whether they were pulled is not
/// known). While the installed serve script is an older one that logs no served line there is
/// no clock, and nothing opens.
#[test]
fn a_pull_that_never_served_is_reported_once_a_set_made_since_has_waited_three_days() {
    let fx = Fx::new();
    pull_keys(&fx, true);
    scheduled_set(&fx, WALL - 300_000);
    fx.hourly(0);
    assert_eq!(fx.meta("pull_since"), Some(stamp(0)));
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "backup:pull"), "none", "{}", state_text(&fx));
    scheduled_set(&fx, WALL + 7200);
    fx.hourly(262_800);
    assert_eq!(state_of(&fx, "backup:pull"), "none", "71 h: not yet");
    fx.hourly(270_000);
    assert_eq!(
        state_of(&fx, "backup:pull"),
        "pending",
        "{}",
        state_text(&fx)
    );
    fx.hourly(273_600);
    assert_eq!(fx.record("backup:pull").unwrap()[7], "open");
    assert_eq!(fx.meta("pull_since"), Some(stamp(0)));
    set_meta(&fx, "pull_last", &stamp(273_700));
    fx.hourly(277_200);
    let f = fx.record("backup:pull").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "pulled"));

    let fx = Fx::new();
    pull_keys(&fx, true);
    fx.write(
        "usr/local/sbin/propolis-backup-serve",
        "#!/bin/bash\n# an older serve script: it serves and logs nothing\n",
    );
    fx.hourly(0);
    assert_eq!(fx.meta("pull_since").as_deref(), Some("-"));
    scheduled_set(&fx, WALL + 7200);
    fx.hourly(270_000);
    fx.hourly(273_600);
    assert_eq!(state_of(&fx, "backup:pull"), "none", "{}", state_text(&fx));

    // The serve script of this tree is never taken for an older one.
    let fx = Fx::new();
    pull_keys(&fx, true);
    let serve = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/backup-serve.sh");
    fx.write(
        "usr/local/sbin/propolis-backup-serve",
        &std::fs::read_to_string(serve).unwrap(),
    );
    fx.hourly(0);
    assert_eq!(fx.meta("pull_since"), Some(stamp(0)));
}

/// With an older serve script installed nothing opens even when a served line was seen once (a
/// newer script served, then an older one was put back): there is no line to wait for. And a
/// serve script that could not be read is not taken for one that logs: the pull is unknown for
/// the pass, so no clock starts, nothing opens and an open record is neither resolved nor judged.
#[test]
fn an_older_or_unreadable_serve_script_never_counts_a_set_as_waiting() {
    let fx = Fx::new();
    pull_keys(&fx, true);
    fx.write(
        "usr/local/sbin/propolis-backup-serve",
        "#!/bin/bash\n# an older serve script: it serves and logs nothing\n",
    );
    set_meta(&fx, "pull_last", &before(345_600));
    scheduled_set(&fx, WALL - 300_000);
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "backup:pull"), "none", "{}", state_text(&fx));
    assert_eq!(fx.meta("pull_since").as_deref(), Some("-"));

    let fx = Fx::new();
    pull_keys(&fx, true);
    fx.write("usr/local/sbin/propolis-backup-serve", "#!/bin/bash\n");
    write_exec(
        &fx.bin.join("grep"),
        "#!/usr/bin/env bash\n\
         case \"$*\" in *'logger -t propolis-backup-serve'*) exit 2 ;; esac\n\
         exec /usr/bin/grep \"$@\"\n",
    );
    fx.incidents(&[witness_record(
        "w#1",
        "backup:pull",
        "backup-offhost",
        "backup",
        "-",
        "NOTICE",
        "open",
        "backup.pull",
    )]);
    fx.hourly(0);
    assert_eq!(fx.meta("pull_since"), None, "{}", state_text(&fx));
    assert_eq!(p_result(&fx, "backups"), "unknown");
    assert_eq!(state_of(&fx, "backup:pull"), "open");
}

/// The backup's status files as deploy/backup.sh writes them: a success before a failure in
/// `step`.
fn backup_failed_in(fx: &Fx, step: &str) {
    fx.write(
        "var/lib/propolis/backup-status/last-success",
        "{\"completed_at\":\"2027-01-14T03:30:00Z\",\"set\":\"20270114T033000Z-scheduled\"}\n",
    );
    file_at(
        fx,
        "var/lib/propolis/backup-status/last-success",
        WALL - 90_000,
    );
    fx.write(
        "var/lib/propolis/backup-status/last-failure",
        &format!(
            "{{\"failed_at\":\"2027-01-15T03:30:00Z\",\"reason\":\"scheduled\",\"step\":\"{step}\",\"exit_code\":1}}\n"
        ),
    );
    file_at(
        fx,
        "var/lib/propolis/backup-status/last-failure",
        WALL - 3600,
    );
}

/// `record` first seen, opened and with its onset at stamp `s`.
fn sighted_at(record: &str, s: &str) -> String {
    with_field(&with_field(&with_field(record, 8, s), 9, s), 10, s)
}

/// A failed backup whose last step read the database folds under an open db-unreachable; one that
/// failed checking free space folds under the open volume record of the backup directory's
/// filesystem, and under nothing else, though the database is down too; one that failed on a
/// ledger mismatch folds under nothing. Each parent was first seen before the failure.
#[test]
fn a_failed_backup_folds_under_db_unreachable_or_the_backup_volume_by_its_last_step() {
    let backup_open = hook_record("w#1", "propolis-backup.service", "ACT", "open", 0, "-");
    let db_open = sighted_at(
        &witness_record(
            "w#2",
            "db:local",
            "db-unreachable",
            "ledger",
            "-",
            "PAGE",
            "open",
            "db.unreachable",
        ),
        &before(7200),
    );

    let fx = Fx::new();
    backup_failed_in(&fx, "dumping the database");
    fx.incidents(&[backup_open.clone(), db_open.clone()]);
    fx.hourly(0);
    let f = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(f[13], "w#2", "{}", state_text(&fx));
    assert!(f[30].split(',').any(|x| x == "folded"), "{}", f[30]);

    // The volume record first seen two hours before the failure takes it; one first seen an hour
    // after it (the failure written an hour before this pass) does not.
    for (seen, want) in [(7200, "w#3"), (0, "-")] {
        let fx = Fx::new();
        salt(&fx);
        backup_failed_in(&fx, "checking free space");
        backup_env(&fx, "PROPOLIS_BACKUP_DIR=/srv/bk");
        fx.filesystems(&[("/srv/bk", 77)]);
        fx.df_map(&[("/srv/bk", &vol(VOL_LOW, "/srv/bk"))]);
        let vol_open = sighted_at(
            &witness_record(
                "w#3",
                &format!("vol:{}", mount_id("/srv/bk")),
                "volume-filling",
                "host",
                &mount_id("/srv/bk"),
                "ACT",
                "open",
                "vol.low",
            ),
            &before(seen),
        );
        fx.incidents(&[backup_open.clone(), db_open.clone(), vol_open]);
        fx.hourly(0);
        let f = fx.record("unit:propolis-backup.service").unwrap();
        assert_eq!(
            f[13],
            want,
            "volume seen {seen} s before: {}",
            state_text(&fx)
        );
    }

    let fx = Fx::new();
    backup_failed_in(&fx, "checking the ledger: chain head 5 differs");
    fx.incidents(&[backup_open, db_open]);
    fx.hourly(0);
    assert_eq!(fx.record("unit:propolis-backup.service").unwrap()[13], "-");
}

/// The one unlisted spool of a run names its collector by opaque id in the folded finding's
/// instance, found by matching config-check's key hash against the spool's plain names; with two
/// the instance is none.
#[test]
fn a_single_unlisted_spool_names_its_collector_by_opaque_id() {
    let fx = Fx::new();
    salt(&fx);
    fx.install_cc();
    spool_at(&fx, "c-zz", WALL - 100);
    spool_at(&fx, "c-yy", WALL - 100);
    let one = cc_tsv(&[], &[("fail", "spool-unlisted:c-zz", "gateway-spool")]);
    fx.cc(&one, 0);
    fx.hourly(0);
    fx.hourly(3600);
    let f = fx
        .record("finding:spool-unlisted:all")
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!(
        (f[5].clone(), f[7].as_str(), f[34].as_str()),
        (collector_id("c-zz"), "open", "1")
    );
    let two = cc_tsv(
        &[],
        &[
            ("fail", "spool-unlisted:c-zz", "gateway-spool"),
            ("fail", "spool-unlisted:c-yy", "gateway-spool"),
        ],
    );
    fx.cc(&two, 0);
    fx.hourly(7200);
    let f = fx.record("finding:spool-unlisted:all").unwrap();
    assert_eq!((f[5].as_str(), f[34].as_str()), ("-", "2"));
}

// ---- the public push, backups and collectors: the edges of each rule ----------------------

/// The result field of the P line of check `name` (`ok`, `unknown`), empty when there is none.
fn p_result(fx: &Fx, name: &str) -> String {
    p_line(fx, name)
        .split('\t')
        .nth(1)
        .unwrap_or("")
        .to_string()
}

/// The fields of collector `cid`'s S line, after the id: lastm, lastadv, maxgap, window start,
/// prevgap, advances in a row.
fn s_fields(fx: &Fx, cid: &str) -> Vec<String> {
    s_line(fx, cid)
        .unwrap_or_else(|| panic!("no S line for {cid}: {}", fx.observe_text()))
        .split('\t')
        .map(str::to_string)
        .collect()
}

/// A listed collector's open spool-quiet record.
fn open_spool_quiet(id: &str, cid: &str) -> String {
    witness_record(
        id,
        &format!("spool:{cid}"),
        "spool-quiet",
        "ship",
        cid,
        "ACT",
        "open",
        "spool.quiet",
    )
}

/// A week whose window is over seven days old rolls over: its longest gap becomes the week
/// before's, which alone sets the threshold of the new week's first day. With a longest gap of
/// 3000 s the threshold is 6000 s, so a quiet of 7000 s opens on the second pass and one of 5000 s
/// does not. A window an hour old with no week before it judges nothing.
#[test]
fn a_week_old_window_rolls_its_longest_gap_into_the_week_before_which_sets_the_threshold() {
    for (quiet, want) in [(7000, "open"), (5000, "none")] {
        let fx = Fx::new();
        control_node(&fx, &["c-01"]);
        let cid = collector_id("c-01");
        seed_s(&fx, &cid, WALL - quiet, 3000, &before(8 * 86_400), "-");
        spool_at(&fx, "c-01", WALL - quiet);
        fx.pass(0);
        fx.pass(300);
        assert_eq!(
            state_of(&fx, &format!("spool:{cid}")),
            want,
            "quiet {quiet}: {}",
            state_text(&fx)
        );
        let s = s_fields(&fx, &cid);
        assert_eq!(
            (s[2].as_str(), s[3].clone(), s[4].as_str()),
            ("0", stamp(0), "3000"),
            "{s:?}"
        );
    }
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    seed_s(&fx, &cid, WALL - 7000, 3000, &before(3600), "-");
    spool_at(&fx, "c-01", WALL - 7000);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "none");
}

/// A spool listing that reaches its bound (lowered here to no entry at all) cannot tell a listed
/// collector it did not reach from one without a spool file: the check `spool` is unknown, three
/// such passes open tool-unusable on it, and the collector's open spool-quiet stays open, neither
/// resolved nor judged, its S line kept.
#[test]
fn a_spool_listing_cut_at_its_bound_leaves_a_listed_collector_it_did_not_reach_unknown() {
    let mut fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    fx.incidents(&[open_spool_quiet("w#1", &cid)]);
    seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 300);
    spool_at(&fx, "u-1", WALL - 300);
    fx.setenv("PROPOLIS_WITNESS_SPOOL_MAX", "0");
    fx.pass(0);
    assert_eq!(p_result(&fx, "spool"), "unknown", "{}", fx.observe_text());
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "open");
    fx.pass(300);
    fx.pass(600);
    assert_eq!(state_of(&fx, "tool:spool"), "open", "{}", state_text(&fx));
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "open");
    assert_eq!(s_fields(&fx, &cid)[0], (WALL - 7200).to_string());
}

/// A spool with more entries than the listing reads ends the pass as usual, and the listed
/// collector, written a minute ago though its S line last saw it two hours ago, is either judged
/// by that fresh write or, past the bound, unknown for the pass: never judged from the S line as
/// if its spool file were gone, which would read it as quiet. Which one depends on the
/// directory's order, so the case with the bound lowered is the one that always reaches it.
#[test]
fn a_spool_of_more_entries_than_the_bound_never_reads_a_listed_collector_as_absent() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 60);
    for n in 0..1100 {
        spool_at(&fx, &format!("u-{n}"), WALL - 300);
    }
    fx.pass(0);
    let result = p_result(&fx, "spool");
    assert!(
        result == "ok" || result == "unknown",
        "{}",
        fx.observe_text()
    );
    assert_eq!(
        state_of(&fx, &format!("spool:{cid}")),
        "none",
        "spool check {result}: {}",
        state_text(&fx)
    );
}

/// `find`, failing for the gateway spool as a listing that broke off does, and the real `find`
/// for anything else.
const FIND_SPOOL_FAILS: &str = r#"#!/usr/bin/env bash
case " $* " in *"/var/spool/propolis/gateway"*) exit 1 ;; esac
exec /usr/bin/find "$@"
"#;

/// A spool listing that fails judges nothing: an open spool-quiet stays open, a pending one is
/// dropped (the next sighting would not be the second in a row), the check `spool` is unknown and
/// three such passes open tool-unusable on it.
#[test]
fn a_spool_listing_that_fails_keeps_an_open_spool_quiet_and_drops_a_pending_one() {
    let fx = Fx::new();
    control_node(&fx, &["c-01", "c-02"]);
    let (c1, c2) = (collector_id("c-01"), collector_id("c-02"));
    fx.incidents(&[open_spool_quiet("w#1", &c2)]);
    seed_s(&fx, &c1, WALL - 7200, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 7200);
    spool_at(&fx, "c-02", WALL - 7200);
    fx.pass(0);
    assert_eq!(state_of(&fx, &format!("spool:{c1}")), "pending");
    write_exec(&fx.bin.join("find"), FIND_SPOOL_FAILS);
    fx.pass(300);
    assert_eq!(state_of(&fx, &format!("spool:{c1}")), "none");
    assert_eq!(state_of(&fx, &format!("spool:{c2}")), "open");
    assert_eq!(p_result(&fx, "spool"), "unknown");
    fx.pass(600);
    assert!(fx.record("tool:spool").is_none());
    fx.pass(900);
    assert_eq!(state_of(&fx, "tool:spool"), "open");
    assert_eq!(state_of(&fx, &format!("spool:{c2}")), "open");
}

/// A listed collector whose spool file is gone (its directory lost on the gateway while its
/// shipper is down, which never brings it back) is judged from the last write its S line holds:
/// quiet for two hours, it opens on the second pass. A listed collector never written, with no
/// S line, has nothing to judge.
#[test]
fn a_listed_collector_whose_spool_file_is_gone_is_judged_from_the_last_write_seen() {
    let fx = Fx::new();
    control_node(&fx, &["c-01", "c-02"]);
    let cid = collector_id("c-01");
    seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
    std::fs::create_dir_all(fx.p("var/spool/propolis/gateway")).unwrap();
    fx.pass(0);
    assert_eq!(
        state_of(&fx, &format!("spool:{cid}")),
        "pending",
        "{}",
        state_text(&fx)
    );
    fx.pass(300);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "open");
    assert_eq!(s_fields(&fx, &cid)[0], (WALL - 7200).to_string());
    let c2 = collector_id("c-02");
    assert_eq!(state_of(&fx, &format!("spool:{c2}")), "none");
    assert!(s_line(&fx, &c2).is_none());
}

/// A spool modification time ahead of the clock (a clock step, or a touch by the gateway
/// account) is neither quiet nor an advance: the S line stays as it was, so the week's longest
/// gap is not widened and spool-quiet still opens when that collector goes quiet later. A year
/// ahead, then a real write, then two hours of quiet: it opens on the second quiet pass with the
/// longest gap still 600 s. An hour ahead: nothing changes while it is ahead, and a real write
/// after it leaves the longest gap as it was.
#[test]
fn a_spool_modification_time_ahead_of_the_clock_neither_opens_nor_widens_the_longest_gap() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    seed_s(&fx, &cid, WALL - 300, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL + 31_536_000);
    fx.pass(0);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "none");
    let s = s_fields(&fx, &cid);
    assert_eq!(
        (s[0].clone(), s[2].as_str()),
        ((WALL - 300).to_string(), "600"),
        "{s:?}"
    );
    spool_at(&fx, "c-01", WALL + 200);
    fx.pass(300);
    let s = s_fields(&fx, &cid);
    assert_eq!(
        (s[0].clone(), s[2].as_str()),
        ((WALL + 200).to_string(), "600"),
        "{s:?}"
    );
    fx.pass(7400);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "pending");
    fx.pass(7700);
    assert_eq!(
        state_of(&fx, &format!("spool:{cid}")),
        "open",
        "{}",
        state_text(&fx)
    );
    assert_eq!(s_fields(&fx, &cid)[2], "600");

    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    seed_s(&fx, &cid, WALL - 100, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL + 3600);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "none");
    let s = s_fields(&fx, &cid);
    assert_eq!(
        (s[0].clone(), s[2].as_str()),
        ((WALL - 100).to_string(), "600"),
        "{s:?}"
    );
    spool_at(&fx, "c-01", WALL + 400);
    fx.pass(600);
    let s = s_fields(&fx, &cid);
    assert_eq!(
        (s[0].clone(), s[2].as_str()),
        ((WALL + 400).to_string(), "600"),
        "{s:?}"
    );
}

/// A gap that was itself reported is not learnt as the week's longest gap: the write that ends a
/// quiet period whose spool-quiet record is open leaves the longest gap as it was, so the same
/// collector going quiet again is reported again after the same half hour, not after twice the
/// length of its last outage.
#[test]
fn a_gap_that_was_reported_is_not_learnt_so_the_next_outage_is_reported_as_soon() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    let key = format!("spool:{cid}");
    seed_s(&fx, &cid, WALL - 7200, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 7200);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(state_of(&fx, &key), "open", "{}", state_text(&fx));
    spool_at(&fx, "c-01", WALL + 500);
    fx.pass(600);
    assert_eq!(s_fields(&fx, &cid)[2], "600", "the reported gap was learnt");
    spool_at(&fx, "c-01", WALL + 800);
    fx.pass(900);
    assert_eq!(fx.record(&key).unwrap()[22], "spool2");
    assert_eq!(s_fields(&fx, &cid)[2], "600");
    // Quiet again since WALL + 800: past 1800 s at the pass of 2700, open on the next.
    fx.pass(2700);
    assert_eq!(state_of(&fx, &key), "pending", "{}", state_text(&fx));
    fx.pass(3000);
    assert_eq!(state_of(&fx, &key), "open", "{}", state_text(&fx));
}

/// A gap between two writes is learnt only when the pass before listed the spool too: after a
/// time the witness did not watch (its timer stopped, the host off, the listing failing) the
/// distance between the last write it saw and the one it sees now says how long it was away, not
/// how long the collector was quiet. A gap seen from one pass to the next is learnt.
#[test]
fn a_gap_is_learnt_only_between_two_passes_that_both_listed_the_spool() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    let cid = collector_id("c-01");
    // The last pass that saw this spool is a day back: no line of the check `spool` is kept.
    seed_s(&fx, &cid, WALL - 86_400, 600, &before(172_800), "-");
    spool_at(&fx, "c-01", WALL - 30);
    fx.pass(0);
    let s = s_fields(&fx, &cid);
    assert_eq!(
        (s[0].clone(), s[2].as_str()),
        ((WALL - 30).to_string(), "600"),
        "{s:?}"
    );
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "none");
    // No pass between 300 and 1500: the 1280 s between the two writes it saw are not learnt.
    fx.pass(300);
    spool_at(&fx, "c-01", WALL + 1250);
    fx.pass(1500);
    let s = s_fields(&fx, &cid);
    assert_eq!(
        (s[0].clone(), s[2].as_str()),
        ((WALL + 1250).to_string(), "600"),
        "{s:?}"
    );
    // Watched from the pass at 1800 to the pass at 2100: the 800 s between two writes are.
    fx.pass(1800);
    spool_at(&fx, "c-01", WALL + 2050);
    fx.pass(2100);
    assert_eq!(s_fields(&fx, &cid)[2], "800");
    assert_eq!(state_of(&fx, &format!("spool:{cid}")), "none");
}

/// In one pass the worst ERROR line sets ship-failing's cause: a rejected batch outranks a failed
/// connection, and a failed cycle outranks one too, whatever their order.
#[test]
fn a_rejected_batch_and_a_failed_cycle_each_outrank_a_failed_connection_as_the_cause() {
    for (lines, want) in [
        (
            format!("{SHIP_CONNECT}{SHIP_REJECTED}{SHIP_CONNECT}"),
            "ship.rejected",
        ),
        (format!("{SHIP_CONNECT}{SHIP_IO}{SHIP_CONNECT}"), "ship.io"),
    ] {
        let fx = Fx::new();
        collector_host(&fx);
        fx.stub_file("journal.shipper", &lines);
        for t in [0, 300, 600] {
            fx.pass(t);
        }
        let f = fx
            .record("ship:local")
            .unwrap_or_else(|| panic!("{want}: {}", state_text(&fx)));
        assert_eq!((f[7].as_str(), f[11].as_str()), ("open", want));
    }
}

/// The shipper's other ERROR lines that mean nothing is being shipped count too, each with its
/// cause: the line it logs before every exit on a permanent stop (the only line shared by a
/// rejected batch, a diverged chain, an unprovable duplicate and the stops for a log no longer
/// configured) is ship.rejected; a batch it cannot record in its state directory and a gateway
/// that keeps answering Retry are ship.io. Rendered by the real log format, from the targets the
/// shipper logs them under.
#[test]
fn the_shippers_other_error_lines_that_stop_shipping_count_with_their_cause() {
    let stop = journal_lines(|| {
        tracing::error!(
            target: "shipper",
            "shipper: ship loop terminated on a permanent stop condition (gateway rejection, \
             chain divergence or an unprovable duplicate); exiting non-zero so this is visible \
             as a failed unit rather than a silently idle process"
        )
    });
    let record = journal_lines(|| {
        tracing::error!(
            target: "shipper::client",
            key = "c-01",
            sensor = "ssh",
            seq = 7u64,
            error = %"No space left on device (os error 28)",
            "shipper: cannot record the batch about to be sent in the state directory; not \
             sending it. Its lines stay in the log and are tried again next pass; check that \
             the state directory's filesystem is writable and not full"
        )
    });
    let retry = journal_lines(|| {
        tracing::error!(
            target: "shipper::client",
            key = "c-01",
            seq = 7u64,
            attempts = 6u32,
            "gateway kept returning Retry past the consecutive-retry bound; stopping ship cycle"
        )
    });
    for (what, lines, want) in [
        ("a permanent stop", stop, "ship.rejected"),
        ("a batch that cannot be recorded", record, "ship.io"),
        ("a gateway that keeps answering Retry", retry, "ship.io"),
    ] {
        let fx = Fx::new();
        collector_host(&fx);
        fx.stub_file("journal.shipper", &lines);
        for t in [0, 300, 600] {
            fx.pass(t);
        }
        let f = fx
            .record("ship:local")
            .unwrap_or_else(|| panic!("{what}: {lines}{}", state_text(&fx)));
        assert_eq!(
            (f[7].as_str(), f[11].as_str()),
            ("open", want),
            "{what}: {lines}"
        );
    }
}

/// The hand-written fixtures have the form the real log format gives: a failed connection and a
/// dropped line rendered by it, under the shipper's targets, are classed as ERROR and WARN, and
/// the gateway's duplicate line rendered by it gives the collector and the two counts. The
/// gateway's call is copied here field for field, and its source is checked to still log those
/// fields in that form, so a change to how the gateway logs the line fails this test instead of
/// leaving the witness unable to read it.
#[test]
fn lines_rendered_by_the_real_log_format_are_read_as_the_fixtures_are() {
    let fx = Fx::new();
    collector_host(&fx);
    let lines = journal_lines(|| {
        tracing::error!(
            target: "shipper",
            sensor = %"ssh",
            error = %"connection refused",
            "shipper: failed to connect to gateway; will retry next pass"
        );
        tracing::warn!(
            target: "shipper::batcher",
            sensor = %"ssh",
            error = %"log \"ssh\": the line names sensor \"x\", which is not a known sensor",
            "shipper: dropping a line the origin policy refuses for this log"
        );
    });
    fx.stub_file("journal.shipper", &lines);
    fx.pass(0);
    assert_eq!(
        (state_of(&fx, "ship:local"), state_of(&fx, "shipdrop:local")),
        ("pending".to_string(), "open".to_string()),
        "{lines}{}",
        state_text(&fx)
    );

    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/gateway/src/verify.rs"
    ))
    .unwrap();
    let flat: String = source.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains(
            "tracing::error!( %collector_id, seq = batch.seq, records, suppressed_batches, \
             suppressed_records, \"gateway: batch reuses the last accepted seq with different \
             content; \\ acknowledged as Duplicate without storing it\" );"
        ),
        "the gateway's duplicate line no longer logs the fields the witness reads, in the form \
         it reads them"
    );
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    fx.stub_file("uid.propolis-gateway", "997\n");
    let cid = collector_id("c-01");
    let (collector_id, records, suppressed_batches, suppressed_records) =
        ("c-01", 3u64, 1u64, 4u64);
    let lines = journal_lines(|| {
        tracing::error!(
            target: "gateway::verify",
            %collector_id,
            seq = 7u64,
            records,
            suppressed_batches,
            suppressed_records,
            "gateway: batch reuses the last accepted seq with different content; \
             acknowledged as Duplicate without storing it"
        )
    });
    fx.stub_file("journal.gateway", &lines);
    fx.pass(0);
    assert_eq!(
        state_of(&fx, &format!("gwdup:{cid}")),
        "open",
        "{lines}{}",
        state_text(&fx)
    );
    assert_eq!(
        p_line(&fx, &format!("seen:gwdup:{cid}")).split('\t').nth(3),
        Some("7"),
        "{lines}"
    );
}

/// An ERROR line that also says the shipper refuses to start is the unit kinds' to report: on
/// three passes it opens no ship-failing.
#[test]
fn a_shipper_error_line_that_refuses_to_start_opens_no_ship_failing() {
    let fx = Fx::new();
    collector_host(&fx);
    fx.stub_file(
        "journal.shipper",
        "2026-11-15T08:00:00.000000Z ERROR shipper: shipper: failed to connect to gateway; \
         refusing to start error=no route\n",
    );
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    assert_eq!(state_of(&fx, "ship:local"), "none", "{}", state_text(&fx));
}

/// A WARN line is classed by its level and its own message, never by what its fields quote: the
/// policy line's error quotes the sensor name a line claimed, which whoever writes that sensor's
/// log chooses. One that claims an ERROR text, or a text that says the shipper refuses to start,
/// counts only toward ship-dropped, on every pass.
#[test]
fn a_warn_line_quoting_an_error_text_counts_only_toward_ship_dropped() {
    let fx = Fx::new();
    collector_host(&fx);
    fx.stub_file(
        "journal.shipper",
        &format!(
            "{}{}",
            ship_warn("shipper: gateway rejected a batch"),
            ship_warn("shipper: failed to connect to gateway; refusing to start")
        ),
    );
    for t in [0, 300, 600] {
        fx.pass(t);
    }
    assert_eq!(state_of(&fx, "ship:local"), "none", "{}", state_text(&fx));
    assert_eq!(state_of(&fx, "shipdrop:local"), "open");
    assert_eq!(
        p_line(&fx, "seen:shipdrop:local").split('\t').next(),
        Some(stamp(600).as_str())
    );
}

/// Lines kept past the 1 MiB cap cannot be read whole, so an ERROR line after a flood of WARN
/// lines may be cut off: the read is unknown for the pass, and an open ship-failing is neither
/// resolved nor counted clean.
#[test]
fn a_shipper_read_whose_kept_lines_pass_the_cap_is_unknown_and_resolves_nothing() {
    let fx = Fx::new();
    collector_host(&fx);
    fx.incidents(&[witness_record(
        "w#1",
        "ship:local",
        "ship-failing",
        "ship",
        "-",
        "ACT",
        "open",
        "ship.connect",
    )]);
    let mut text = String::new();
    while text.len() <= 1_048_576 {
        text.push_str(&ship_warn("ssh"));
    }
    text.push_str(SHIP_CONNECT);
    fx.stub_file("journal.shipper", &text);
    fx.pass(0);
    assert_eq!(p_result(&fx, "journal:shipper"), "unknown");
    fx.pass(300);
    assert_eq!(state_of(&fx, "ship:local"), "open", "{}", state_text(&fx));
    assert_eq!(p_result(&fx, "journal:shipper"), "unknown");
}

/// A read of the shipper's journal that could not tell breaks the run of ERROR passes: two
/// passes with errors, one cut off, then errors again leave ship-failing pending, not open.
#[test]
fn a_shipper_read_that_could_not_tell_breaks_the_run_of_error_passes() {
    let fx = Fx::new();
    collector_host(&fx);
    fx.stub_file("journal.shipper", SHIP_CONNECT);
    fx.pass(0);
    fx.pass(300);
    assert_eq!(state_of(&fx, "ship:local"), "pending");
    fx.stub_file("journal.shipper.rc", "124");
    fx.pass(600);
    std::fs::remove_file(fx.dir.path().join("journal.shipper.rc")).unwrap();
    fx.pass(900);
    assert_eq!(
        state_of(&fx, "ship:local"),
        "pending",
        "{}",
        state_text(&fx)
    );
}

/// ship-dropped resolves quiet24 once a day has passed without a WARN line.
#[test]
fn ship_dropped_resolves_after_a_day_without_a_dropped_line() {
    let fx = Fx::new();
    collector_host(&fx);
    fx.stub_file("journal.shipper", &ship_warn("ssh"));
    fx.pass(0);
    assert_eq!(state_of(&fx, "shipdrop:local"), "open");
    fx.stub_file("journal.shipper", "");
    fx.pass(86_100);
    assert_eq!(state_of(&fx, "shipdrop:local"), "open");
    fx.pass(86_400);
    let f = fx.record("shipdrop:local").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "quiet24"));
}

/// The gateway's duplicate line for collector `cn`.
fn gw_dup_line(cn: &str) -> String {
    format!(
        "2026-11-15T08:00:00.000000Z ERROR gateway::verify: gateway: batch reuses the last \
         accepted seq with different content; acknowledged as Duplicate without storing it \
         collector_id={cn} seq=7 records=3 suppressed_batches=1 suppressed_records=0\n"
    )
}

/// Two cursors in journalctl's form.
const CURSOR_A: &str =
    "s=0123456789abcdef0123456789abcdef;i=1f;b=fedcba9876543210fedcba9876543210;m=2a;t=5e1;x=9c";
const CURSOR_B: &str =
    "s=0123456789abcdef0123456789abcdef;i=2f;b=fedcba9876543210fedcba9876543210;m=3a;t=6e1;x=9d";

/// Before the listed collectors can be keyed (no salt yet on a fresh host, whose first pass takes
/// it under the lock), the gateway's line cannot be told from an unlisted collector's: the class
/// is unknown for the pass, no gwdup:unlisted opens, its cursor stays where it was, and the next
/// pass reads the line again and keys it by the collector's opaque id.
#[test]
fn a_gateway_line_read_before_the_collectors_can_be_keyed_waits_for_the_next_pass() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    std::fs::remove_file(fx.p("var/lib/propolis/witness/id-salt")).unwrap();
    fx.stub_file("uid.propolis-gateway", "997\n");
    fx.stub_file("journal.gateway", &gw_dup_line("c-01"));
    fx.write(
        "var/lib/propolis/witness/jcursor/gateway",
        &format!("{CURSOR_A}\n"),
    );
    fx.stub_file("journal.gateway.cursor", &format!("{CURSOR_B}\n"));
    fx.pass(0);
    assert!(
        !fx.records().iter().any(|f| f[2].starts_with("gwdup:")),
        "{}",
        state_text(&fx)
    );
    assert_eq!(p_result(&fx, "journal:gateway"), "unknown");
    assert_eq!(
        fx.read("var/lib/propolis/witness/jcursor/gateway"),
        format!("{CURSOR_A}\n")
    );
    salt(&fx);
    fx.pass(300);
    let cid = collector_id("c-01");
    assert_eq!(
        state_of(&fx, &format!("gwdup:{cid}")),
        "open",
        "{}",
        state_text(&fx)
    );
    assert!(fx.record("gwdup:unlisted").is_none());
    assert_eq!(
        fx.read("var/lib/propolis/witness/jcursor/gateway"),
        format!("{CURSOR_B}\n")
    );
}

/// A collector_id out of the plain-id form is no listed collector's, however it starts.
#[test]
fn a_gateway_line_whose_collector_id_is_out_of_form_is_keyed_unlisted() {
    let fx = Fx::new();
    control_node(&fx, &["c-01"]);
    fx.stub_file("uid.propolis-gateway", "997\n");
    fx.stub_file("journal.gateway", &gw_dup_line("c-01;x"));
    fx.pass(0);
    assert_eq!(state_of(&fx, "gwdup:unlisted"), "open");
    assert_eq!(
        state_of(&fx, &format!("gwdup:{}", collector_id("c-01"))),
        "none"
    );
}

/// The 64 hex of sha256(VOL_SALT NUL "collector" NUL cn), which an opaque id is cut from.
fn collector_hash(cn: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(VOL_SALT.as_bytes());
    h.update([0u8]);
    h.update(b"collector");
    h.update([0u8]);
    h.update(cn.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Two plain collector names whose ids share their first 5 hex under VOL_SALT, found by search.
fn colliding_collectors() -> (String, String) {
    let mut seen = std::collections::HashMap::new();
    for n in 0u32.. {
        let name = format!("c-{n}");
        if let Some(prev) = seen.insert(collector_hash(&name)[..5].to_string(), name.clone()) {
            return (prev, name);
        }
    }
    unreachable!()
}

/// The witness keys a listed collector by the id the walk shows for it: pa_id_table widens two
/// colliding ids to 8 hex within its input, so both programs give it every plain spool name and
/// every listed name. With an unlisted spool whose id collides with a listed collector's, the
/// listed one's record and S line carry the widened id.
#[test]
fn a_listed_collectors_id_is_widened_against_an_unlisted_spool_name_it_collides_with() {
    let (a, b) = colliding_collectors();
    let fx = Fx::new();
    control_node(&fx, &[a.as_str()]);
    fx.stub_file("uid.propolis-gateway", "997\n");
    spool_at(&fx, &a, WALL - 100);
    spool_at(&fx, &b, WALL - 100);
    fx.stub_file("journal.gateway", &gw_dup_line(&a));
    fx.pass(0);
    let id = format!("c{}", &collector_hash(&a)[..8]);
    assert_eq!(
        state_of(&fx, &format!("gwdup:{id}")),
        "open",
        "{a} {b}: {}",
        state_text(&fx)
    );
    assert!(s_line(&fx, &id).is_some(), "{}", fx.observe_text());
}

/// With the feed turned off (`false` in any case) nothing needs pushing: no scheduler opens
/// neither push-off nor push-unscheduled. An open push-off resolves clean2 after two passes on
/// which a crontab line runs the push.
#[test]
fn a_disabled_feed_needs_no_push_and_push_off_resolves_once_a_scheduler_runs_it() {
    for value in ["FALSE", "false", "False"] {
        let fx = Fx::new();
        std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
        propolis_env_with(
            &fx,
            &format!("PROPOLIS_FEED_ENABLED={value}\nPROPOLIS_OPS_FEED_PUSH_EXPECTED=true\n"),
        );
        fx.hourly(0);
        fx.hourly(3600);
        assert_eq!(
            (state_of(&fx, "push:off"), state_of(&fx, "push:none")),
            ("none".to_string(), "none".to_string()),
            "{value}: {}",
            state_text(&fx)
        );
    }
    let fx = Fx::new();
    fx.incidents(&[witness_record(
        "w#1",
        "push:off",
        "push-off",
        "publish",
        "-",
        "NOTICE",
        "open",
        "push.none",
    )]);
    fx.hourly(0);
    assert_eq!(state_of(&fx, "push:off"), "open");
    fx.hourly(3600);
    let f = fx.record("push:off").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "clean2"));
}

/// With no push marker the first sighting's onset is the pass that saw it, and the first push
/// after that onset resolves the record `pushed`.
#[test]
fn push_failing_without_a_push_marker_opens_on_the_second_pass_and_a_later_push_resolves_it() {
    let fx = Fx::new();
    push_host(&fx, None, Some(WALL - 3600));
    set_meta(&fx, "push_sched_since", &before(25_200));
    fx.hourly(0);
    let f = fx
        .record("push:cron")
        .unwrap_or_else(|| panic!("{}", state_text(&fx)));
    assert_eq!((f[7].as_str(), f[10].clone()), ("pending", stamp(0)));
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "push:cron"), "open");
    file_at(
        &fx,
        "var/lib/propolis/blocklist-status/last-pushed",
        WALL + 3700,
    );
    fx.hourly(7200);
    let f = fx.record("push:cron").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "pushed"));
}

/// A push that keeps failing while the operator moves it from a crontab line to a timer is one
/// fault: the open push:cron record carries it, and no second record opens on push:timer.
#[test]
fn a_failing_push_moved_from_cron_to_a_timer_stays_one_record() {
    let fx = Fx::new();
    push_host(&fx, Some(WALL - 25_200), Some(WALL - 3600));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "push:cron"), "open");
    std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
    fx.write(
        "etc/systemd/system/blocklist-sync.service",
        "[Service]\nUser=propolis-blocklist\nExecStart=/opt/propolis/deploy/blocklist-sync.sh\n",
    );
    fx.unit("blocklist-sync.timer", &[("SubState", "waiting")]);
    fx.hourly(7200);
    fx.hourly(10_800);
    let live: Vec<String> = fx
        .records()
        .iter()
        .filter(|f| f[2].starts_with("push:") && f[7] != "resolved")
        .map(|f| format!("{} {}", f[2], f[7]))
        .collect();
    assert_eq!(
        live,
        vec!["push:cron open".to_string()],
        "{}",
        state_text(&fx)
    );
}

/// An open push-failing does not outlive its scheduler: once nothing runs the push any more (the
/// operator took the crontab line out), no later push can resolve it, so it resolves `disabled`
/// on that pass and the missing scheduler is push-off's or push-unscheduled's to say.
#[test]
fn an_open_push_failing_resolves_disabled_once_nothing_runs_the_push() {
    let fx = Fx::new();
    push_host(&fx, Some(WALL - 25_200), Some(WALL - 3600));
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "push:cron"), "open");
    std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
    fx.hourly(7200);
    let f = fx.record("push:cron").unwrap();
    assert_eq!(
        (f[7].as_str(), f[22].as_str()),
        ("resolved", "disabled"),
        "{}",
        state_text(&fx)
    );
    assert_eq!(state_of(&fx, "push:off"), "pending");
}

/// PROPOLIS_OPS_FEED_PUSH_EXPECTED is true for `true`, `1`, `yes` and `on` in any case and with
/// blanks around it, false for anything else: with no scheduler it picks push-unscheduled
/// (push:none) or the NOTICE push-off.
#[test]
fn the_push_expected_setting_reads_true_1_yes_and_on_in_any_case_and_nothing_else() {
    for (value, key, other) in [
        ("1", "push:none", "push:off"),
        ("yes", "push:none", "push:off"),
        ("on", "push:none", "push:off"),
        ("  true  ", "push:none", "push:off"),
        ("TRUE", "push:none", "push:off"),
        ("false", "push:off", "push:none"),
        ("0", "push:off", "push:none"),
        ("maybe", "push:off", "push:none"),
    ] {
        let fx = Fx::new();
        std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
        propolis_env_with(&fx, &format!("PROPOLIS_OPS_FEED_PUSH_EXPECTED={value}\n"));
        fx.hourly(0);
        assert_eq!(
            (state_of(&fx, key), state_of(&fx, other)),
            ("pending".to_string(), "none".to_string()),
            "{value:?}: {}",
            state_text(&fx)
        );
    }
}

/// The feed's publish marker lies in the daemon account's directory, so its stat runs as that
/// account (uid 998), never as root.
#[test]
fn the_publish_marker_is_read_as_the_daemon_account() {
    let mut fx = Fx::new();
    fx.daemon_account();
    push_host(&fx, Some(WALL - 100), Some(WALL - 50));
    fx.setenv("PA_TEST_UID", "0");
    fx.setenv("PA_TEST_READ_AS_SELF", "0");
    fx.hourly(0);
    let log = fx.log();
    assert!(
        log.lines().any(|l| l.starts_with("setpriv --reuid=998 ")
            && l.contains("var/lib/propolis/feed/.current.last_published")),
        "{log}"
    );
    assert_eq!(p_result(&fx, "push"), "ok");
}

/// A push marker that is a symbolic link is not followed, however fresh its target: the push
/// check is unknown for the pass, and an open push-failing neither resolves `pushed` nor counts
/// clean.
#[test]
fn a_push_marker_that_is_a_symbolic_link_is_unknown_and_resolves_nothing() {
    let fx = Fx::new();
    push_host(&fx, None, Some(WALL - 3600));
    file_at(&fx, "var/lib/propolis/blocklist-status/fresh", WALL - 10);
    std::os::unix::fs::symlink(
        "fresh",
        fx.p("var/lib/propolis/blocklist-status/last-pushed"),
    )
    .unwrap();
    fx.incidents(&[sighted_at(
        &witness_record(
            "w#1",
            "push:cron",
            "push-failing",
            "publish",
            "-",
            "ACT",
            "open",
            "push.stale",
        ),
        &before(25_200),
    )]);
    fx.hourly(0);
    assert_eq!(p_result(&fx, "push"), "unknown", "{}", fx.observe_text());
    assert_eq!(state_of(&fx, "push:cron"), "open", "{}", state_text(&fx));
}

/// A host whose role is unknown (no daemon or gateway enabled, no shipper.env) publishes no feed,
/// so nothing runs the push there for a reason: no push-off opens and the push check is not run.
#[test]
fn a_host_of_unknown_role_opens_no_push_off() {
    let fx = Fx::new();
    std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("UnitFileState", "disabled"),
        ],
    );
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "push:off"), "none", "{}", state_text(&fx));
    assert_eq!(p_line(&fx, "push"), "");
}

/// backup-offhost resolves `disabled` only when no pull is configured: its key line removed, or
/// the pull account known to be gone (`id` says there is no such user). An account lookup that
/// fails otherwise, such as one cut off by its time limit, cannot tell: the record stays open and
/// the backups check is unknown.
#[test]
fn backup_offhost_resolves_disabled_only_when_the_pull_is_known_to_be_gone() {
    let offhost = || {
        witness_record(
            "w#1",
            "backup:pull",
            "backup-offhost",
            "backup",
            "-",
            "NOTICE",
            "open",
            "backup.pull",
        )
    };
    let fx = Fx::new();
    pull_keys(&fx, false);
    fx.incidents(&[offhost()]);
    fx.hourly(0);
    let f = fx.record("backup:pull").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));

    let fx = Fx::new();
    pull_keys(&fx, true);
    fx.stub_file("uid.propolis-backup-pull", "rc=124\n");
    fx.incidents(&[offhost()]);
    fx.hourly(0);
    assert_eq!(state_of(&fx, "backup:pull"), "open", "{}", state_text(&fx));
    assert_eq!(p_result(&fx, "backups"), "unknown");
    fx.stub_file("uid.propolis-backup-pull", "none\n");
    fx.hourly(3600);
    let f = fx.record("backup:pull").unwrap();
    assert_eq!((f[7].as_str(), f[22].as_str()), ("resolved", "disabled"));
}

/// A backup directory of more entries than the listing reads (4096) is unknown for the pass:
/// backup-retention neither opens nor resolves.
#[test]
fn a_backup_directory_past_the_listing_bound_is_unknown_and_resolves_no_retention() {
    let fx = Fx::new();
    backup_env(&fx, "PROPOLIS_BACKUP_DIR=/srv/bk");
    for n in 0..4100 {
        std::fs::create_dir_all(fx.p(&format!("srv/bk/d{n}"))).unwrap();
    }
    fx.incidents(&[witness_record(
        "w#1",
        "backup:keep",
        "backup-retention",
        "backup",
        "-",
        "NOTICE",
        "open",
        "backup.keep",
    )]);
    fx.hourly(0);
    fx.hourly(3600);
    assert_eq!(state_of(&fx, "backup:keep"), "open", "{}", state_text(&fx));
    assert_eq!(p_result(&fx, "backups"), "unknown");
}

/// The backup run's guards: a start time past the uptime (from another boot, or out of form)
/// while activating opens nothing, and a run that ended failed does not set the last run's length.
#[test]
fn a_backup_start_past_the_uptime_opens_nothing_and_a_failed_run_sets_no_length() {
    let fx = Fx::new();
    let ahead = ((UP + 5000) * 1_000_000).to_string();
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
            ("ExecMainStartTimestampMonotonic", &ahead),
            ("ExecMainExitTimestampMonotonic", "0"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    assert_eq!(state_of(&fx, "backup:run"), "none");

    let fx = Fx::new();
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
            ("ExecMainStartTimestampMonotonic", &mono(0, 7600)),
            ("ExecMainExitTimestampMonotonic", &mono(0, 3600)),
        ],
    );
    fx.pass(0);
    assert_eq!(fx.meta("backup_dur"), None);
}

/// A start time that belongs to a run which has already ended says nothing of this one: while
/// the unit is activating with an exit later than its start, its main command has not started
/// yet (a command that runs before it, added by a drop-in, is still going) and the start shown
/// is the last run's. Nine hours after that start, nothing opens. With a main process running
/// the start is that process's whatever the exit says, and the run is judged by it.
#[test]
fn a_backup_start_left_from_the_run_before_opens_no_backup_hung() {
    for (main_pid, want) in [(Some("0"), "none"), (Some("4242"), "open")] {
        let fx = Fx::new();
        for t in [0, 300] {
            let (start, exit) = (mono(t, 32_400), mono(t, 28_800));
            let mut props = vec![
                ("ActiveState", "activating"),
                ("SubState", "start-pre"),
                ("Restart", "no"),
                ("UnitFileState", "static"),
                ("ExecMainStartTimestampMonotonic", start.as_str()),
                ("ExecMainExitTimestampMonotonic", exit.as_str()),
            ];
            if let Some(pid) = main_pid {
                props.push(("MainPID", pid));
            }
            fx.unit("propolis-backup.service", &props);
            fx.pass(t);
        }
        assert_eq!(
            state_of(&fx, "backup:run"),
            want,
            "main pid {main_pid:?}: {}",
            state_text(&fx)
        );
    }
}

/// A failed backup folds only under a parent a trusted fact ties it to: not under a
/// db-unreachable first seen six hours after the backup failed, not under db-unreachable when it
/// failed checking free space with no volume record open, and not at all once a later run
/// succeeded.
#[test]
fn a_failed_backup_folds_only_under_a_parent_whose_fault_was_there_when_it_failed() {
    let backup_open = hook_record("w#1", "propolis-backup.service", "ACT", "open", 0, "-");
    let db_open = |s: &str| {
        sighted_at(
            &witness_record(
                "w#2",
                "db:local",
                "db-unreachable",
                "ledger",
                "-",
                "PAGE",
                "open",
                "db.unreachable",
            ),
            s,
        )
    };
    let parent = |step: &str, failed: u64, succeeded: Option<u64>, db_seen: u64| {
        let fx = Fx::new();
        backup_failed_in(&fx, step);
        file_at(
            &fx,
            "var/lib/propolis/backup-status/last-failure",
            WALL - failed,
        );
        if let Some(s) = succeeded {
            file_at(&fx, "var/lib/propolis/backup-status/last-success", WALL - s);
        }
        fx.incidents(&[backup_open.clone(), db_open(&before(db_seen))]);
        fx.hourly(0);
        fx.record("unit:propolis-backup.service").unwrap()[13].clone()
    };
    assert_eq!(
        parent("dumping the database", 3600 + 21_600, None, 3600),
        "-",
        "failed six hours before the outage"
    );
    assert_eq!(
        parent("checking free space", 3600, None, 7200),
        "-",
        "free space with only the database down"
    );
    assert_eq!(
        parent("dumping the database", 3600, Some(60), 7200),
        "-",
        "a later run succeeded"
    );
    assert_eq!(
        parent("dumping the database", 3600, None, 3800),
        "w#2",
        "failed during the outage"
    );
}

/// The pull class's regex is the line deploy/backup-serve.sh logs, held to it here: the logger
/// call's message is `served $set $file`, and judge_pull's regex is `^served `, the serve script's
/// set shape and its three file names, so a reworded logger line fails the build instead of
/// leaving `meta pull_last` unset.
#[test]
fn the_pull_class_matches_exactly_the_line_backup_serve_logs() {
    let serve = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/backup-serve.sh"
    ))
    .unwrap();
    let logger: Vec<&str> = serve
        .lines()
        .filter(|l| l.trim_start().starts_with("timeout 5 logger "))
        .collect();
    assert_eq!(logger.len(), 1, "{logger:?}");
    assert!(
        logger[0].contains("-t propolis-backup-serve ")
            && logger[0].contains("\"served $set $file\""),
        "{}",
        logger[0]
    );
    let set_re = serve
        .lines()
        .find_map(|l| l.strip_prefix("SET_RE='"))
        .and_then(|l| l.strip_suffix('\''))
        .unwrap();
    let files = serve
        .lines()
        .find_map(|l| l.strip_prefix("FILES=("))
        .and_then(|l| l.strip_suffix(')'))
        .unwrap();
    let files: Vec<String> = files.split(' ').map(|f| f.replace('.', "\\.")).collect();
    let want = format!(
        "^served {} ({})$",
        set_re.trim_start_matches('^').trim_end_matches('$'),
        files.join("|")
    );
    let witness = std::fs::read_to_string(SCRIPT).unwrap();
    let re = witness
        .lines()
        .find_map(|l| {
            l.trim_start()
                .strip_prefix("local line re='")
                .and_then(|l| l.strip_suffix('\''))
        })
        .unwrap();
    assert_eq!(re, want);
}

// ---- the daily message -------------------------------------------------------------------------

/// The fixture's push settings with these lines added.
fn push_env(extra: &str) -> String {
    format!(
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n{extra}"
    )
}

/// Past 08:41 UTC on a topic a fresh read check proved private, the light pass sends one daily
/// message at priority 2, titled with the alias. The URL, the topic and the token reach curl only
/// in a 0600 config file that is gone once the pass ends, never on a command line or in its
/// environment. The message is counted before it goes, in meta (the local date and the stamp)
/// and in a send-ledger line claimed as sending, which takes the result; a pass five minutes on
/// sends nothing.
#[test]
fn the_light_pass_sends_one_daily_message_to_a_proven_private_topic_and_counts_it_before_the_send()
{
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        &push_env("PROPOLIS_OPS_NTFY_TOKEN=tk_s3cret-value\n"),
    );
    fx.private_topic(3600);
    fx.pass(3600);
    let posts = fx.posts();
    assert_eq!(posts.len(), 1, "{}", fx.log());
    let conf = fx.stub_text("curl.post.conf");
    let title = conf
        .lines()
        .find_map(|l| l.strip_prefix("header = \"Title: "))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{conf}"));
    assert!(
        title.starts_with("host-") && title.ends_with(": daily") && title.len() == 16,
        "{title}"
    );
    assert!(conf.contains("header = \"Priority: 2\"\n"), "{conf}");
    assert!(
        conf.contains("url = \"https://ntfy.example.invalid/t0p1c-secret\"\n"),
        "{conf}"
    );
    assert!(
        conf.contains("header = \"Authorization: Bearer tk_s3cret-value\"\n"),
        "{conf}"
    );
    assert_eq!(fx.stub_text("curl.post.mode").trim(), "600");
    let log = fx.log();
    let post = log.lines().find(|l| l.starts_with("post ")).unwrap();
    let file = post.strip_prefix("post -q -K ").unwrap();
    assert!(!file.contains(' '), "{post}");
    assert!(!Path::new(file).exists(), "the config file is removed");
    for secret in ["t0p1c-secret", "tk_s3cret-value"] {
        assert!(!log.contains(secret), "{secret} on a command line: {log}");
        assert!(
            !fx.stub_text("curl.post.env").contains(secret),
            "{secret} in curl's environment"
        );
    }
    assert_eq!(
        posts[0].lines().collect::<Vec<_>>(),
        [
            "open: 0 (PAGE 0, ACT 0)",
            "resolved 24 h: 0; withheld by budget 24 h: 0",
            "new notices 24 h: 0",
            "alerts: NOT VERIFIED (never); profile legacy",
            "v2 would have pushed 0 in 24 h",
            "state: persisted",
            "Do: status",
        ]
    );
    assert_eq!(
        fx.daily_lines(),
        [format!(
            "L\t{}\tdaily\t-\tdaily\tfull\tok\tlight",
            stamp(3600)
        )]
    );
    assert_eq!(fx.meta("daily_last").as_deref(), Some("2027-01-15"));
    assert_eq!(fx.meta("daily_last_stamp"), Some(stamp(3600)));
    fx.pass(3900);
    assert_eq!(fx.posts().len(), 1, "one a day");
}

/// The daily message goes only where the gate is full: never over plain http (where anyone on
/// the path can answer the read check's 403 and read what is posted), never to a topic that is
/// readable, that no check has answered for (a check that could not be made is no refusal), whose
/// refusal is over a day old or whose checker has not tried for three hours, and never without a
/// target.
#[test]
fn no_daily_message_goes_over_http_to_an_unproven_topic_on_a_stale_check_or_without_a_target() {
    let line = |attempt: &str, aclass: &str, definite: &str, dclass: &str| {
        format!(
            "#readcheck v1 g=1\nR\t{FX_BINDING}\t{attempt}\t{aclass}\t{definite}\t{dclass}\t-\t403\t403\tboth\t403\n"
        )
    };
    let cases: [(&str, u64); 6] = [
        ("http", 3600),
        ("readable", 3600),
        ("never answered", 3600),
        ("refusal over a day old", 93_600),
        ("no attempt for three hours", 14_400),
        ("no target", 3600),
    ];
    for (name, t) in cases {
        let fx = Fx::new();
        match name {
            "http" => {
                fx.write(
                    "etc/propolis/propolis.env",
                    "PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n",
                );
                fx.curl_answers("403|text/plain");
            }
            "readable" => fx.write(
                "var/lib/propolis/witness/readcheck",
                &line(&stamp(t), "readable", &stamp(t), "readable"),
            ),
            "never answered" => {}
            "refusal over a day old" => fx.write(
                "var/lib/propolis/witness/readcheck",
                &line(&stamp(t), "transient", &stamp(3600), "refused"),
            ),
            "no attempt for three hours" => fx.private_topic(0),
            _ => {
                fx.private_topic(t);
                fx.write("etc/propolis/propolis.env", "");
            }
        }
        fx.pass(t);
        assert!(fx.posts().is_empty(), "{name}: {}", fx.log());
        assert!(fx.daily_lines().is_empty(), "{name}");
        assert_eq!(fx.meta("daily_last"), None, "{name}");
        if name == "http" {
            let rc = fx.read("var/lib/propolis/witness/readcheck");
            assert!(
                rc.contains(&format!("\trefused\t{}\trefused\t", stamp(t))),
                "the read check over http was refused, and that proves nothing: {rc}"
            );
        }
    }
}

/// PROPOLIS_OPS_DAILY_AT=off sends nothing; a value that is neither off nor HH:MM keeps the
/// default time, 08:41, and the pass still ends as every pass does.
#[test]
fn daily_at_off_sends_nothing_and_a_value_out_of_form_keeps_the_default_time() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        &push_env("PROPOLIS_OPS_DAILY_AT=off\n"),
    );
    fx.private_topic(3600);
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.daily_lines().is_empty());

    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        &push_env("PROPOLIS_OPS_DAILY_AT=9am\n"),
    );
    fx.private_topic(3600);
    fx.pass(3600);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
}

/// The daily time is the host's local time, from the zone the pass was started with: at 08:00
/// UTC, 09:00 an hour east, a message set for 08:50 goes, and is dated by that zone's day, while
/// the rest of the pass (the banner here) keeps UTC.
#[test]
fn the_daily_time_is_read_in_the_hosts_zone_while_the_pass_keeps_utc() {
    let mut fx = Fx::new();
    fx.setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3");
    fx.write(
        "etc/propolis/propolis.env",
        &push_env("PROPOLIS_OPS_DAILY_AT=08:50\n"),
    );
    fx.private_topic(0);
    fx.pass(0);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(fx.meta("daily_last").as_deref(), Some("2027-01-15"));
    assert!(
        fx.read("run/motd.d/propolis")
            .starts_with("[propolis 08:00 UTC] "),
        "{}",
        fx.read("run/motd.d/propolis")
    );
}

/// The message is counted before it goes, so a send that failed is not tried again that day, and
/// a pass killed while it sent leaves what keeps the next from sending a second: either the
/// claimed ledger line or meta's date holds it on its own.
#[test]
fn a_daily_message_that_failed_or_whose_pass_was_killed_is_not_sent_again_that_day() {
    let fx = Fx::new();
    fx.stub_file("curl.post", "503");
    fx.private_topic(3600);
    fx.pass(3600);
    assert_eq!(fx.posts().len(), 1);
    assert_eq!(
        fx.daily_lines(),
        [format!(
            "L\t{}\tdaily\t-\tdaily\tfull\ttransient:503\tlight",
            stamp(3600)
        )]
    );
    assert!(
        fx.log()
            .contains("-t propolis-witness daily message not delivered (transient:503)"),
        "{}",
        fx.log()
    );
    fx.pass(3900);
    assert_eq!(fx.posts().len(), 1, "not tried again");

    let fx = Fx::new();
    fx.private_topic(3600);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\nL\t{}\tdaily\t-\tdaily\tfull\tsending\tlight\n",
            stamp(2700)
        ),
    );
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "the claimed line holds it");

    let fx = Fx::new();
    fx.private_topic(3600);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\tdaily_last\t2027-01-15\nM\tdaily_last_stamp\t{}\n",
            stamp(2700)
        ),
    );
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "meta's date holds it");
}

/// Where no state can be kept, nothing would remember the message, so none is sent.
#[test]
fn no_daily_message_is_sent_while_no_state_can_be_kept() {
    let fx = Fx::new();
    fx.write(
        "var/lib/propolis/witness/id-salt",
        "0123456789abcdef0123456789abcdef\n",
    );
    fx.private_topic(3600);
    fx.stub_file("disk.refuses", "*/var/lib/propolis/witness/*\n");
    fx.write(
        "run/propolis-witness/fallback",
        "a file where the directory would go",
    );
    fx.pass(3600);
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("state NOT PERSISTED"),
        "{}",
        fx.read("run/motd.d/propolis")
    );
    assert!(fx.posts().is_empty(), "{}", fx.log());
}

/// The hourly pass sends the daily message only while the light pass is stale (its last pass over
/// 15 minutes old), with itself as the sender in the ledger; the light pass that runs again
/// afterwards finds it counted and sends no second.
#[test]
fn the_hourly_pass_sends_the_daily_message_only_while_the_light_pass_is_stale_and_never_twice() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(3600);
    assert!(
        fx.read("var/lib/propolis/witness/readcheck")
            .contains(&format!("\trefused\t{}\trefused\t", stamp(3600))),
        "the topic is proven private"
    );
    assert!(fx.posts().is_empty(), "the light pass is fresh");
    fx.hourly_alone(7200);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(
        fx.daily_lines(),
        [format!(
            "L\t{}\tdaily\t-\tdaily\tfull\tok\thourly",
            stamp(7200)
        )]
    );
    fx.pass(7500);
    assert_eq!(fx.posts().len(), 1, "never twice");
}

/// The daily message names the host by its alias alone and carries nothing a record, the host or
/// another account chose: no host name, unit, finding, collector, cause or label, no path, address,
/// topic or token, and not the word that names the software. Notices count only when opened in
/// the last 24 hours, the legacy profile adds what v2 would have pushed, and no line says the
/// daemon is not verified, which nothing could clear before the daemon gets a test page of its own.
#[test]
fn the_daily_message_names_nothing_but_the_alias_and_holds_no_line_that_cannot_clear() {
    let fx = Fx::new();
    write_exec(
        &fx.bin.join("hostname"),
        "#!/usr/bin/env bash\necho plantedhost\n",
    );
    fx.write(
        "etc/propolis/propolis.env",
        &push_env(
            "PROPOLIS_OPS_HOST_ALIAS=north-relay\n\
             PROPOLIS_SENSOR_LOGS=plantedlabel:/var/log/propolis/plantedlog/events.jsonl\n",
        ),
    );
    let planted = |id: &str, key: &str, tier: &str, t: u64| {
        let r = hook_record(id, "sensor-plantedunit.service", tier, "open", t, "0");
        let r = with_field(&r, 2, key);
        let r = with_field(&r, 3, "plantedkind");
        let r = with_field(&r, 5, "uplanted");
        with_field(&r, 11, "planted.cause")
    };
    fx.incidents(&[
        planted("w#3", "finding:plantedfinding:0123456789ab", "ACT", 1800),
        planted("w#4", "spool:cplanted", "NOTICE", 1800),
        with_field(
            &planted("w#5", "tool:plantedtool", "NOTICE", 0),
            9,
            &format!("{}/0000aaaa/1", WALL - 172_800),
        ),
        // An id out of form: counted as open, never copied.
        with_field(
            &planted("w#3planted", "tool:otherplanted", "NOTICE", 0),
            9,
            &format!("{}/0000aaaa/1", WALL - 172_800),
        ),
    ]);
    // A clock step with words after its offset is out of form and left out whole.
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\nM\tclock_step\t{}/+300planted\n", stamp(0)),
    );
    fx.private_topic(3600);
    fx.pass(3600);
    let posts = fx.posts();
    assert_eq!(posts.len(), 1, "{}", fx.log());
    let conf = fx.stub_text("curl.post.conf");
    assert!(
        conf.contains("header = \"Title: north-relay: daily\"\n"),
        "{conf}"
    );
    let body = &posts[0];
    assert!(
        body.starts_with("open: 4 (PAGE 0, ACT 1) w#3 w#4 w#5\n"),
        "{body}"
    );
    assert!(body.contains("\nnew notices 24 h: 1\n"), "{body}");
    assert!(
        body.contains("\nv2 would have pushed 1 in 24 h\n"),
        "{body}"
    );
    assert!(
        fx.read("run/motd.d/propolis")
            .contains("daemon not verified")
    );
    let headers: String = conf
        .lines()
        .filter(|l| l.starts_with("header = \"Title") || l.starts_with("header = \"Priority"))
        .collect();
    for word in [
        "planted",
        "propolis",
        "honey",
        "daemon not verified",
        "t0p1c-secret",
        "ntfy.example.invalid",
        "sensor-",
        ".service",
        "/",
        "127.0.0.1",
    ] {
        assert!(!body.contains(word), "{word} in the body: {body}");
        assert!(!headers.contains(word), "{word} in the title: {headers}");
    }

    // An alias that is the host's own name is refused, and the fallback names the host instead.
    let fx = Fx::new();
    write_exec(
        &fx.bin.join("hostname"),
        "#!/usr/bin/env bash\necho plantedhost\n",
    );
    fx.write(
        "etc/propolis/propolis.env",
        &push_env("PROPOLIS_OPS_HOST_ALIAS=plantedhost\n"),
    );
    fx.private_topic(3600);
    fx.pass(3600);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    let conf = fx.stub_text("curl.post.conf");
    let title = conf
        .lines()
        .find_map(|l| l.strip_prefix("header = \"Title: "))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{conf}"));
    assert!(
        title.len() == 16
            && title.starts_with("host-")
            && title[5..9].bytes().all(|b| b.is_ascii_hexdigit())
            && title.ends_with(": daily"),
        "{title}"
    );
    assert!(!fx.posts()[0].contains("planted"), "{:?}", fx.posts());
}

/// A zone file of one fixed offset an hour east of UTC, `XPT`, in the TZif form the C library
/// reads: no transitions, one local time type, and the POSIX rule after the data.
fn tzif_plus_one() -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..2 {
        v.extend_from_slice(b"TZif2");
        v.extend_from_slice(&[0u8; 15]);
        for count in [0u32, 0, 0, 0, 1, 4] {
            v.extend_from_slice(&count.to_be_bytes());
        }
        v.extend_from_slice(&3600i32.to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(b"XPT\0");
    }
    v.extend_from_slice(b"\nXPT-1\n");
    v
}

/// The units set no TZ, so a pass started without one reads the daily time in the host's
/// /etc/localtime (the root's here, an hour east of UTC), not in the UTC it keeps for the rest:
/// at 08:00 UTC, 09:00 local, a message set for 08:50 goes and is dated by the local day.
#[test]
fn a_pass_started_without_a_zone_reads_the_daily_time_in_the_hosts_localtime() {
    let mut fx = Fx::new();
    fx.unsetenv("TZ");
    std::fs::write(fx.p("etc/localtime"), tzif_plus_one()).unwrap();
    fx.write(
        "etc/propolis/propolis.env",
        &push_env("PROPOLIS_OPS_DAILY_AT=08:50\n"),
    );
    fx.private_topic(0);
    fx.pass(0);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(fx.meta("daily_last").as_deref(), Some("2027-01-15"));
    assert!(
        fx.read("run/motd.d/propolis")
            .starts_with("[propolis 08:00 UTC] "),
        "{}",
        fx.read("run/motd.d/propolis")
    );
}

/// A message sent late, at 15:05, holds the next back for 20 hours: none at 08:41 the next day,
/// one at 11:05.
#[test]
fn a_daily_message_sent_at_15_05_is_not_followed_at_08_41_but_twenty_hours_after_it() {
    let fx = Fx::new();
    // 15:05 UTC on 2027-01-15, then 08:41 and 11:05 on the 16th.
    let first = 25_500;
    for (t, want) in [
        (first, 1),
        (first + 300, 1),
        (88_860, 1),
        (first + 72_000, 2),
    ] {
        fx.private_topic(t);
        fx.pass(t);
        assert_eq!(fx.posts().len(), want, "at {t}: {}", fx.log());
    }
    assert_eq!(fx.meta("daily_last").as_deref(), Some("2027-01-16"));
}

/// A pass that has used the time it may judge for counts and sends no daily message.
#[test]
fn a_pass_past_its_deadline_sends_no_daily_message() {
    let mut fx = Fx::new();
    fx.setenv("PROPOLIS_WITNESS_DEADLINE", "0");
    fx.private_topic(3600);
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.daily_lines().is_empty());
    assert_eq!(fx.meta("daily_last"), None);
    assert!(fx.meta("light_last").is_some(), "the pass did write meta");
}

/// A directory of links to every program on `PATH` (the fixture's stubs first) but `curl`.
fn path_without_curl(fx: &Fx) -> PathBuf {
    let dir = fx.dir.path().join("nocurl");
    std::fs::create_dir_all(&dir).unwrap();
    let path = format!("{}:{}", fx.bin.display(), std::env::var("PATH").unwrap());
    for d in path.split(':') {
        let Ok(entries) = std::fs::read_dir(d) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let link = dir.join(&name);
            if name == "curl" || link.symlink_metadata().is_ok() {
                continue;
            }
            std::os::unix::fs::symlink(entry.path(), &link).unwrap();
        }
    }
    dir
}

/// Without curl the message could not leave the host whatever the server said: nothing is
/// counted for it, so the day's message is still owed once curl is back.
#[test]
fn without_curl_no_daily_message_is_counted() {
    let mut fx = Fx::new();
    fx.private_topic(3600);
    let dir = path_without_curl(&fx);
    fx.setenv("PATH", &dir.display().to_string());
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.daily_lines().is_empty());
    assert_eq!(fx.meta("daily_last"), None);
    assert!(fx.meta("light_last").is_some(), "the pass did write meta");
}

/// A write of this pass that nothing took (the incidents file here, refused in both directories
/// while the pass resolves a record) leaves the pass's state not kept even though meta still takes
/// its lines: no daily message is counted or sent then, since what remembers it may be what was
/// lost.
#[test]
fn a_pass_whose_earlier_write_was_kept_nowhere_sends_no_daily_message() {
    let fx = Fx::new();
    fx.private_topic(3600);
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "ACT",
        "open",
        0,
        "0",
    )]);
    fx.stub_file("disk.refuses", "*/incidents.tmp.*\n");
    fx.pass(3600);
    assert_eq!(fx.meta("where").as_deref(), Some("none"), "{}", fx.log());
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.daily_lines().is_empty());
    assert_eq!(fx.meta("daily_last"), None);
}

/// The result is written under the lock after the send; a lock not had within 30 s leaves the
/// ledger line claimed as `sending`, which counts as sent, so no second message follows.
#[test]
fn a_lock_held_past_thirty_seconds_after_the_send_leaves_the_line_claimed_and_nothing_follows() {
    let fx = Fx::new();
    fx.private_topic(3600);
    fx.stub_file(
        "curl.post.hold",
        &fx.p("var/lib/propolis/witness/state.lock")
            .display()
            .to_string(),
    );
    fx.pass(3600);
    let holder = fx.stub_text("curl.post.holder");
    let _ = Command::new("kill").arg(holder.trim()).status();
    assert!(
        fx.dir.path().join("curl.post.held").exists(),
        "the lock was taken"
    );
    std::fs::remove_file(fx.dir.path().join("curl.post.hold")).unwrap();
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(
        fx.daily_lines(),
        [format!(
            "L\t{}\tdaily\t-\tdaily\tfull\tsending\tlight",
            stamp(3600)
        )]
    );
    fx.private_topic(3900);
    fx.pass(3900);
    assert_eq!(fx.posts().len(), 1, "nothing follows");
}

/// With no light pass to date at all, the hourly pass takes it as stale only after the first half
/// hour of uptime, when one should have run: at 1700 s it sends nothing, at 1900 s it sends the
/// daily message as its sender.
#[test]
fn with_no_light_pass_on_record_the_hourly_pass_stands_in_only_after_half_an_hour_of_uptime() {
    let mut fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    let _ = std::fs::remove_file(fx.p("run/propolis-witness/heartbeat"));
    let _ = std::fs::remove_file(fx.p("var/lib/propolis/witness/meta"));
    let at = |up: u64| format!("{}/{BOOT}/{up}", WALL + 3600 + up - 1700);
    fx.setenv("PROPOLIS_WITNESS_NOW", &at(1700));
    fx.hourly_alone(3600);
    assert!(
        fx.read("var/lib/propolis/witness/readcheck")
            .contains(&format!("\trefused\t{}\trefused\t", at(1700))),
        "{}",
        fx.read("var/lib/propolis/witness/readcheck")
    );
    assert_eq!(fx.meta("light_last"), None);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    fx.setenv("PROPOLIS_WITNESS_NOW", &at(1900));
    fx.hourly_alone(3800);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(
        fx.daily_lines(),
        [format!(
            "L\t{}\tdaily\t-\tdaily\tfull\tok\thourly",
            at(1900)
        )]
    );
}

/// On a control node the message counts the listed collectors, whichever pass sends it: the
/// light pass, and the hourly pass standing in for a stale light pass, which loads the list
/// itself.
#[test]
fn on_a_control_node_both_passes_count_the_listed_collectors_in_the_daily_message() {
    for hourly in [false, true] {
        let fx = Fx::new();
        control_node(&fx, &["c-north", "c-south"]);
        for cn in ["c-north", "c-south"] {
            spool_at(&fx, cn, WALL + 3500);
        }
        fx.private_topic(3600);
        if hourly {
            fx.install_cc();
            fx.cc(&cc_tsv(&[], &[]), 0);
            fx.curl_answers("403|text/plain");
            fx.hourly_alone(3600);
        } else {
            fx.pass(3600);
        }
        let posts = fx.posts();
        assert_eq!(posts.len(), 1, "hourly {hourly}: {}", fx.log());
        assert!(
            posts[0].contains("\ncollectors: 2 listed, 0 quiet\n"),
            "hourly {hourly}: {}",
            posts[0]
        );
    }
}

/// The read check is anonymous even where the URL carries a user and password: a server that
/// refuses those credentials with 401 but serves anonymous reads must not pass for a private
/// topic, so no daily message goes.
#[test]
fn credentials_in_the_url_never_make_a_topic_pass_for_private() {
    let fx = Fx::new();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=https://alice:pw@ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n",
    );
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("404|text/plain");
    fx.stub_file("curl.answer.userinfo", "401|text/plain");
    fx.hourly(3600);
    fx.pass(3600);
    let confs = fx.stub_text("curl.conf");
    assert!(
        confs.contains("url = \"https://ntfy.example.invalid/t0p1c-secret/json"),
        "{confs}"
    );
    // The three anonymous requests never hold the user. With no token set a fourth asks whether
    // the URL's own credentials can read the topic, and is the only one that holds them.
    let urls: Vec<&str> = confs.lines().filter(|l| l.starts_with("url = ")).collect();
    assert!(urls.len() >= 4, "{confs}");
    for line in &urls[..3] {
        assert!(!line.contains("alice"), "{line}");
    }
    assert_eq!(
        urls[3],
        "url = \"https://alice:pw@ntfy.example.invalid/t0p1c-secret/json?poll=1&since=1s\""
    );
    let stored = fx.read("var/lib/propolis/witness/readcheck");
    assert!(!stored.contains("\trefused\t"), "{stored}");
    assert!(stored.contains("\tnoread\t"), "{stored}");
    assert!(fx.posts().is_empty(), "{}", fx.log());
}

/// Under the legacy profile only the host that runs the daemon sends the daily message: a split
/// deployment gets one a day, from its control node, and whether a credential kept on a collector
/// can read the topic never decides a send. A collector, and a host whose role cannot be told,
/// send none and count none, on a topic proven private, at a time a single box sends at.
#[test]
fn only_the_host_that_runs_the_daemon_sends_the_daily_message() {
    let fx = Fx::new();
    fx.write("etc/propolis/propolis.env", &push_env(""));
    collector_host(&fx);
    fx.private_topic(3600);
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "collector: {}", fx.log());
    assert!(fx.daily_lines().is_empty(), "collector");
    assert!(
        !fx.read("var/lib/propolis/witness/meta")
            .contains("daily_last"),
        "collector: {}",
        fx.read("var/lib/propolis/witness/meta")
    );

    let fx = Fx::new();
    fx.write("etc/propolis/propolis.env", &push_env(""));
    fx.unit(
        "propolis.service",
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("UnitFileState", "disabled"),
        ],
    );
    fx.private_topic(3600);
    fx.pass(3600);
    assert!(fx.posts().is_empty(), "unknown role: {}", fx.log());
    assert!(fx.daily_lines().is_empty(), "unknown role");

    // The same topic and time on a single box: one message.
    let fx = Fx::new();
    fx.write("etc/propolis/propolis.env", &push_env(""));
    fx.private_topic(3600);
    fx.pass(3600);
    assert_eq!(fx.posts().len(), 1, "single box: {}", fx.log());
}

// ---- the v2 send step ---------------------------------------------------------------------------

impl Fx {
    /// The v2 profile, through the library's test seam: no host can set it.
    fn v2(&mut self) {
        self.setenv("PA_TEST_PROFILE", "v2");
    }

    /// The send ledger's lines of incident messages (every class but the daily message's, the
    /// test page's and the notices'), split into their fields.
    fn incident_lines(&self) -> Vec<Vec<String>> {
        self.read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t"))
            .map(|l| l.split('\t').map(str::to_string).collect::<Vec<_>>())
            .filter(|f| !NOTICE_CLASSES.contains(&f[2].as_str()))
            .collect()
    }

    /// The send ledger's lines of the pointer message, whole.
    fn pointer_lines(&self) -> Vec<String> {
        self.read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t") && l.split('\t').nth(2) == Some("pointer"))
            .map(str::to_string)
            .collect()
    }

    /// The send ledger's lines of the storm notice and the summary, split into their fields.
    fn notice_lines(&self) -> Vec<Vec<String>> {
        self.read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t"))
            .map(|l| l.split('\t').map(str::to_string).collect::<Vec<_>>())
            .filter(|f| f[2] == "storm" || f[2] == "summary")
            .collect()
    }

    /// Each post as (title, priority, body), in order.
    fn sent(&self) -> Vec<(String, String, String)> {
        let conf = self.stub_text("curl.post.conf");
        let mut heads: Vec<(String, String)> = Vec::new();
        for l in conf.lines() {
            if let Some(t) = l.strip_prefix("header = \"Title: ") {
                heads.push((t.trim_end_matches('"').to_string(), String::new()));
            } else if let Some(p) = l.strip_prefix("header = \"Priority: ")
                && let Some(last) = heads.last_mut()
            {
                last.1 = p.trim_end_matches('"').to_string();
            }
        }
        heads
            .into_iter()
            .zip(self.posts())
            .map(|((t, p), b)| (t, p, b))
            .collect()
    }

    /// The storm notices and summaries posted, as (title, priority, body), in order.
    fn notices(&self) -> Vec<(String, String, String)> {
        self.sent()
            .into_iter()
            .filter(|(t, _, b)| is_notice(t, b))
            .collect()
    }

    /// Adds these W lines to the incidents file as it now stands.
    fn add_w(&self, lines: &[String]) {
        let mut text = self.read("var/lib/propolis/witness/incidents");
        if text.is_empty() {
            text = "#incidents v1 g=1\nN\t50\n".to_string();
        }
        for l in lines {
            text.push_str(l);
            text.push('\n');
        }
        self.write("var/lib/propolis/witness/incidents", &text);
    }

    /// The title of each post, in order.
    fn titles(&self) -> Vec<String> {
        self.stub_text("curl.post.conf")
            .lines()
            .filter_map(|l| l.strip_prefix("header = \"Title: "))
            .map(|l| l.trim_end_matches('"').to_string())
            .collect()
    }

    /// The withheld transitions recorded, split into their fields.
    fn w_lines(&self) -> Vec<Vec<String>> {
        self.read("var/lib/propolis/witness/incidents")
            .lines()
            .filter(|l| l.starts_with("W\t"))
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect()
    }
}

/// A ledger line of the pointer message, `L stamp pointer - pointer pointer result sender`.
fn ptr_line(s: &str, result: &str, sender: &str) -> String {
    format!("L\t{s}\tpointer\t-\tpointer\tpointer\t{result}\t{sender}")
}

/// The first 8 hex of sha256 of a key, as the ledger and the W lines name it.
fn kh8(key: &str) -> String {
    k12(key)[..8].to_string()
}

/// The shipper failed, as two light passes in a row see it: an ACT open of a long-running unit,
/// charged to the pool.
fn failed_shipper(fx: &Fx) {
    fx.unit(
        "shipper.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "2"),
        ],
    );
}

/// A ledger line of an incident message on KEY as the senders write it, `L stamp class keyhash tx
/// full result sender id tried`, from `[stamp, class, tx, result, sender, id, tried]`.
fn inc_line(key: &str, f: [&str; 7]) -> Vec<String> {
    let [s, class, tx, result, sender, id, tried] = f;
    let kh = kh8(key);
    [
        "L",
        s,
        class,
        kh.as_str(),
        tx,
        "full",
        result,
        sender,
        id,
        tried,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect()
}

/// Under v2 with the gate full, the transition that would add to would_push is claimed under the
/// lock before anything is posted: its pending ledger line and the record's pending transition
/// are on disk when the post is made, and the lock is free then. The message is what the renderer
/// gave for the record, and the post's result goes to that ledger line and the record: the
/// transition ends, the incident is delivered. A pass five minutes on sends nothing more.
#[test]
fn under_v2_an_open_is_claimed_under_the_lock_and_posted_without_it() {
    let mut fx = Fx::new();
    fx.v2();
    failed_shipper(&fx);
    fx.private_topic(0);
    fx.stub_file("curl.post.snap", "");
    fx.pass(0);
    assert!(fx.posts().is_empty(), "one pass opens nothing");
    fx.pass(300);
    let titles = fx.titles();
    assert_eq!(titles.len(), 1, "{}", fx.log());
    assert!(
        titles[0].starts_with("ACT host-") && titles[0].contains(" - ship: "),
        "{titles:?}"
    );
    let posts = fx.posts();
    assert!(posts[0].starts_with("Since "), "{}", posts[0]);
    let rec = fx.record("unit:shipper.service").unwrap();
    let id = rec[1].clone();
    let key = "unit:shipper.service";
    let s = stamp(300);
    assert_eq!(
        fx.incident_lines(),
        [inc_line(key, [&s, "pool", "open", "ok", "light", &id, &s])]
    );
    // (sends, delivered_open, pending_tx, pending_since)
    assert_eq!(
        (
            rec[14].as_str(),
            rec[17].as_str(),
            rec[26].as_str(),
            rec[27].as_str()
        ),
        ("1", "1", "-", "-")
    );
    let ledger = fx.stub_text("curl.snap.ledger");
    assert!(
        ledger.contains(&format!(
            "\tpool\t{}\topen\tfull\tpending\tlight\t{id}\t",
            kh8(key)
        )),
        "{ledger}"
    );
    let at_post = fx.stub_text("curl.snap.incidents");
    let claimed = at_post
        .lines()
        .find(|l| l.contains(&format!("\t{key}\t")))
        .unwrap_or_else(|| panic!("{at_post}"));
    let f: Vec<&str> = claimed.split('\t').collect();
    assert_eq!((f[26], f[27]), ("open", stamp(300).as_str()), "{claimed}");
    assert_eq!(fx.stub_text("curl.snap.lock"), "free\n");
    fx.pass(600);
    assert_eq!(fx.posts().len(), 1);
}

/// Under the legacy profile, which is all a host can run, the witness claims and sends no
/// incident message: the open adds to would_push, the send ledger holds the daily message alone,
/// no record holds a pending transition, and the daily message is the one post.
#[test]
fn under_the_legacy_profile_no_incident_message_is_claimed_or_sent() {
    let fx = Fx::new();
    failed_shipper(&fx);
    fx.private_topic(0);
    fx.pass(0);
    fx.pass(300);
    fx.pass(3600);
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].ends_with(": daily"));
    assert!(fx.incident_lines().is_empty());
    assert!(fx.records().iter().all(|f| f[26] == "-" && f[27] == "-"));
    assert_eq!(fx.record("unit:shipper.service").unwrap()[29], "1");
    assert!(fx.w_lines().is_empty());
}

/// With the gate short of full (here no read check has answered) a v2 pass records the
/// transition as legacy does and admits no incident message: no incident ledger line, no pending
/// transition, no W line. What goes is one pointer message, the alias and a ref at priority 4,
/// claimed in the ledger's pointer class; its ok writes the ref into the record, which it told,
/// and sets no delivered_open. A pass five minutes on sends nothing more. No journal line names
/// the target, the topic, the ref, an instance or an incident id.
#[test]
fn under_v2_with_the_gate_short_of_full_no_incident_message_is_admitted_and_the_pointer_is_the_only_post()
 {
    let mut fx = Fx::new();
    fx.v2();
    failed_shipper(&fx);
    fx.pass(0);
    assert!(fx.posts().is_empty(), "one pass opens nothing");
    fx.pass(300);
    let sent = fx.sent();
    assert_eq!(sent.len(), 1, "{sent:?}\n{}", fx.log());
    let (title, prio, body) = &sent[0];
    let alias = title
        .strip_suffix(": needs attention")
        .unwrap_or_else(|| panic!("{title}"));
    assert!(alias.starts_with("host-"), "{title}");
    assert_eq!(prio, "4");
    let reference = body
        .strip_prefix(&format!("Run the status command on {alias}. ref "))
        .unwrap_or_else(|| panic!("{body}"))
        .trim_end()
        .to_string();
    assert!(
        reference.len() == 6 && reference.bytes().all(|b| b.is_ascii_hexdigit()),
        "{body}"
    );
    assert!(fx.incident_lines().is_empty());
    assert!(fx.w_lines().is_empty());
    assert!(fx.notice_lines().is_empty());
    assert_eq!(fx.pointer_lines(), [ptr_line(&stamp(300), "ok", "light")]);
    let rec = fx.record("unit:shipper.service").unwrap();
    // (state, sends, delivered_open, pending_tx, ref, would_push)
    assert_eq!(
        (
            rec[7].as_str(),
            rec[14].as_str(),
            rec[17].as_str(),
            rec[26].as_str(),
            rec[28].as_str(),
            rec[29].as_str()
        ),
        ("open", "0", "0", "-", reference.as_str(), "1")
    );
    assert_eq!(
        fx.meta("pointer_last"),
        Some(format!("{}/{reference}", stamp(300)))
    );
    let log = fx.log();
    for word in [
        reference.as_str(),
        "t0p1c",
        "ntfy.example",
        rec[1].as_str(),
        rec[5].as_str(),
    ] {
        if word == "-" {
            continue;
        }
        assert!(
            !log.lines()
                .any(|l| l.starts_with("logger ") && l.contains(word)),
            "{word}: {log}"
        );
    }
    fx.pass(600);
    fx.pass(2400);
    assert_eq!(fx.posts().len(), 1, "told, so nothing is due");
}

/// No post starts once the pass is past its send cut (200 s; a test seam sets it to 0 here): the
/// admitted transition stays pending with its ledger line. A pass under 120 s after the admission
/// leaves it alone; the first one after posts it again once, updating that line rather than adding
/// one, so the retry is not counted twice; then it is done.
#[test]
fn no_post_starts_past_the_send_cut_and_what_is_left_is_retried_once_after_the_floor() {
    let mut fx = Fx::new();
    fx.v2();
    failed_shipper(&fx);
    fx.private_topic(0);
    fx.pass(0);
    fx.setenv("PROPOLIS_WITNESS_SEND_CUT", "0");
    fx.pass(300);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    let key = "unit:shipper.service";
    let id = fx.record(key).unwrap()[1].clone();
    let line = |result: &str, tried: u64| {
        let (s, t) = (stamp(300), stamp(tried));
        inc_line(key, [&s, "pool", "open", result, "light", &id, &t])
    };
    assert_eq!(fx.incident_lines(), [line("pending", 300)]);
    let rec = fx.record(key).unwrap();
    assert_eq!(
        (rec[26].clone(), rec[27].clone()),
        ("open".into(), stamp(300))
    );
    fx.unsetenv("PROPOLIS_WITNESS_SEND_CUT");
    fx.pass(360);
    assert!(fx.posts().is_empty(), "under the 120 s floor");
    fx.pass(420);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(fx.incident_lines(), [line("ok", 420)]);
    let rec = fx.record(key).unwrap();
    assert_eq!((rec[17].as_str(), rec[26].as_str()), ("1", "-"));
    fx.pass(720);
    assert_eq!(fx.posts().len(), 1);
}

/// A pass killed while it posts leaves the transition pending with its line: the next pass under
/// 120 s does not post it again, the first after 120 s does, once.
#[test]
fn a_pass_killed_during_a_post_leaves_it_pending_for_one_retry_after_the_floor() {
    let mut fx = Fx::new();
    fx.v2();
    failed_shipper(&fx);
    fx.private_topic(0);
    fx.pass(0);
    fx.stub_file("curl.post.sleep", "30");
    let mut child = fx.start(&["light"], 300, false);
    let pid_file = fx.dir.path().join("curl.post.pid");
    let mut waited = 0;
    while !pid_file.exists() && waited < 600 {
        std::thread::sleep(Duration::from_millis(50));
        waited += 1;
    }
    assert!(pid_file.exists(), "the post began: {}", fx.log());
    child.kill().unwrap();
    child.wait().unwrap();
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: kill has no memory preconditions; the pid is the stub's own.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    std::fs::remove_file(fx.dir.path().join("curl.post.sleep")).unwrap();
    assert_eq!(fx.posts().len(), 1);
    let key = "unit:shipper.service";
    let id = fx.record(key).unwrap()[1].clone();
    let s = stamp(300);
    assert_eq!(
        fx.incident_lines(),
        [inc_line(
            key,
            [&s, "pool", "open", "pending", "light", &id, &s]
        )]
    );
    assert_eq!(fx.record(key).unwrap()[26], "open");
    fx.pass(360);
    assert_eq!(fx.posts().len(), 1, "never twice inside 120 s");
    fx.pass(420);
    assert_eq!(fx.posts().len(), 2, "{}", fx.log());
    let t = stamp(420);
    assert_eq!(
        fx.incident_lines(),
        [inc_line(key, [&s, "pool", "open", "ok", "light", &id, &t])]
    );
    fx.pass(600);
    assert_eq!(fx.posts().len(), 2);
}

/// Nothing is posted that is not claimed: with a send ledger that takes no write the transition
/// is withheld (its W line says why), and with incidents that take none it is not claimed either;
/// in neither case is anything posted.
#[test]
fn a_send_ledger_or_a_record_that_cannot_be_written_sends_nothing() {
    for refused in ["*send-ledger*", "*incidents*"] {
        let mut fx = Fx::new();
        fx.v2();
        failed_shipper(&fx);
        fx.private_topic(0);
        fx.pass(0);
        fx.stub_file("disk.refuses", &format!("{refused}\n"));
        fx.pass(300);
        assert!(fx.posts().is_empty(), "{refused}: {}", fx.log());
        assert!(
            fx.incident_lines().iter().all(|f| f[6] != "pending"),
            "{refused}"
        );
        if refused == "*send-ledger*" {
            let w = fx.w_lines();
            assert_eq!(w.len(), 1, "{refused}");
            assert_eq!(
                (w[0][2].as_str(), w[0][3].as_str(), w[0][6].as_str()),
                (kh8("unit:shipper.service").as_str(), "open", "ledger")
            );
        }
    }
}

/// The failure hook's claim is the record's pending transition and its ledger line: a pass that
/// sees the same failure admits nothing more, leaves the claim alone under 120 s, and retries it
/// once after. A change the pass sees meanwhile is recorded (its new cause, one more would_push)
/// and not admitted, since the open has not got through; the retry renders the record as it then
/// is and so delivers the incident with its current cause.
#[test]
fn the_hook_and_a_pass_that_see_one_failure_send_one_message_between_them() {
    let mut fx = Fx::new();
    fx.v2();
    failed_shipper(&fx);
    fx.private_topic(0);
    let key = "unit:shipper.service";
    let mut rec = hook_record("w#7", "shipper.service", "ACT", "open", 0, "0");
    for (i, v) in [
        (3, "unit-failed"),
        (4, "ship"),
        (11, "db.unreachable"),
        (14, "1"),
        (15, &stamp(0)),
        (16, "open"),
        (26, "open"),
        (27, &stamp(0)),
        (30, "hookopen"),
        (33, "-"),
    ] {
        rec = with_field(&rec, i, v);
    }
    fx.incidents(&[rec]);
    let s = stamp(0);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(key, [&s, "pool", "open", "pending", "hook", "w#7", &s]).join("\t")
        ),
    );
    fx.pass(60);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    let r = fx.record(key).unwrap();
    assert_eq!(
        (r[11].as_str(), r[26].as_str(), r[27].as_str()),
        ("proc.exit:2", "open", stamp(0).as_str()),
        "the change is recorded and the open stays claimed"
    );
    assert_eq!(fx.incident_lines().len(), 1, "nothing admitted again");
    fx.pass(120);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].starts_with("ACT "), "{:?}", fx.titles());
    assert!(
        fx.posts()[0].contains("Why: process exited (proc.exit 2)"),
        "{}",
        fx.posts()[0]
    );
    let t = stamp(120);
    assert_eq!(
        fx.incident_lines(),
        [inc_line(
            key,
            [&s, "pool", "open", "ok", "light", "w#7", &t]
        )]
    );
    fx.pass(300);
    assert_eq!(fx.posts().len(), 1);
}

/// Unknown never counts as good: a record with an empty field, which the reader would place a
/// field early, a kind the tables do not know, and a send ledger no copy of which can be read
/// each send no incident message; each leaves a W line that says so, which the storm notice of
/// the same pass counts (a ledger no copy of which can be read holds the notice too, for that
/// pass).
#[test]
fn a_record_not_whole_a_kind_not_known_or_a_ledger_not_countable_sends_nothing() {
    let due = stamp(0);
    let open = |key: &str, kind: &str| {
        let mut r = hook_record("w#1", "shipper.service", "ACT", "open", 0, "-");
        for (i, v) in [
            (1, if kind == "frobnicate" { "w#2" } else { "w#3" }),
            (2, key),
            (3, kind),
            (4, "publish"),
            (11, "push.stale"),
            (19, due.as_str()),
            (33, "-"),
        ] {
            r = with_field(&r, i, v);
        }
        r
    };
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let unknown = open("push:timer", "frobnicate");
    let broken = with_field(&open("push:cron", "push-failing"), 28, "");
    fx.incidents(&[unknown, broken]);
    fx.pass(300);
    assert!(incident_titles(&fx).is_empty(), "{}", fx.log());
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}", fx.sent());
    assert_eq!(
        fx.sent().len(),
        1,
        "the notice is the one post: {:?}",
        fx.sent()
    );
    assert!(
        notices[0].0.ends_with(": alert budget reached")
            && notices[0].2.starts_with("Withheld: 2 messages since "),
        "{:?}",
        notices[0]
    );
    let mut reasons: Vec<(String, String)> = fx
        .w_lines()
        .iter()
        .map(|w| (w[2].clone(), w[6].clone()))
        .collect();
    reasons.sort();
    let mut want = vec![
        (kh8("push:timer"), "unknown".to_string()),
        (kh8("push:cron"), "unknown".to_string()),
    ];
    want.sort();
    assert_eq!(reasons, want);

    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_shipper(&fx);
    fx.pass(0);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v9 g=1\nL\tdamaged\n",
    );
    fx.pass(300);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    let w = fx.w_lines();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0][6], "ledger");
}

/// Under v2 a transition still pending an hour after its admission is dropped: the incident waits
/// for its next reminder, and the heartbeat's rule about a transition waiting over 15 minutes
/// stops holding the ping (alert-path, which a transition undelivered that long opened, holds it
/// instead). Under the legacy profile the pass leaves the record as the previous release leaves
/// it, the pending transition and the skipped ping included: nothing in legacy changes.
#[test]
fn a_transition_pending_for_an_hour_is_dropped_under_v2_and_left_as_it_was_under_legacy() {
    // Admitted 3500 s before the first pass.
    let since = format!("{}/{BOOT}/{}", WALL - 3500, UP - 3500);
    let pings = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    for v2 in [false, true] {
        let mut fx = Fx::new();
        if v2 {
            fx.v2();
        }
        fx.write(
            "etc/propolis/alert.env",
            "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n",
        );
        fx.curl_answers("200|text/plain");
        let mut rec = hook_record("w#7", "shipper.service", "ACT", "open", 0, "0");
        for (i, v) in [(26, "open"), (27, since.as_str()), (33, "-")] {
            rec = with_field(&rec, i, v);
        }
        fx.incidents(&[rec]);
        // Its claim, tried as it was admitted, and answered for now only.
        let line = inc_line(
            "unit:shipper.service",
            [
                &since,
                "pool",
                "open",
                "transient:503",
                "hook",
                "w#7",
                &since,
            ],
        );
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{}\n", line.join("\t")),
        );
        fx.pass(0);
        assert_eq!(
            fx.record("unit:shipper.service").unwrap()[26],
            "open",
            "{v2}"
        );
        fx.pass(100);
        let r = fx.record("unit:shipper.service").unwrap();
        if v2 {
            assert_eq!((r[26].as_str(), r[27].as_str()), ("-", "-"));
        } else {
            assert_eq!((r[26].as_str(), r[27].as_str()), ("open", since.as_str()));
            assert_eq!(
                fx.meta("hb_skip").as_deref(),
                Some(format!("{}/pending", stamp(100)).as_str())
            );
        }
        // No incident message: under v2 the gate is short of full, and the one post is the
        // pointer message for the open incident, not yet told.
        let titles = fx.titles();
        assert!(
            titles.iter().all(|t| t.ends_with(": needs attention")),
            "{v2}: {titles:?}\n{}",
            fx.log()
        );
        assert_eq!(titles.len(), usize::from(v2), "{v2}: {titles:?}");
        fx.pass(1900);
        let skip = fx.meta("hb_skip").unwrap_or_default();
        if v2 {
            // Undelivered for over 15 minutes, it opened alert-path, which holds the ping
            // now; the dropped transition itself holds nothing.
            assert_eq!(fx.record("alert:shell").unwrap()[7], "open");
            assert!(skip.ends_with("/alert-path"), "{skip}");
        } else {
            assert_eq!(pings(&fx), 0, "{}", fx.log());
            assert_eq!(fx.record("unit:shipper.service").unwrap()[26], "open");
            assert!(skip.ends_with("/pending"), "{skip}");
            assert!(fx.record("alert:shell").is_none());
        }
    }
}

/// The hook's spool files for two firings it sent without the lock: the sensor's message got
/// through, the backup's was claimed (sending) and never answered.
fn spooled_sends(fx: &Fx) {
    let s = stamp(0);
    fx.write(
        "run/propolis-witness/fallback/hook-sensor-http.service",
        &format!("#hook v1 g=1\nH\t{s}\t{s}\t1\tsignal\tkilled\t9\tproc.signal:9\t2\tok\n"),
    );
    fx.write(
        "var/lib/propolis/witness/hook/propolis-backup.service",
        &format!("#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t0\tsending\n"),
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
}

/// A message the hook sent without the lock is charged to the send ledger once, when the pass
/// takes in its spool file: one line per send, in the class the budget would have given the kind
/// (a listener's stage1, the backup's pool) whatever room there was, its last attempt the hook's
/// firing (the spool file's last stamp), not the pass. The record carries hookspool; the one that
/// got through is open and delivered, so its RESOLVED can follow, and the pass sends no second
/// message for it. The one whose result never came (sending: a post in flight when the pass took
/// the file, or a hook stopped mid-post) may not have gone, so it is not taken as sent: its line
/// is pending and the record holds the open as its pending transition (never an open with
/// delivered_open 0 that nobody retries), and the first pass 120 s on retries it once, rewriting
/// that line. Under the legacy profile the same files are taken in as before and charge nothing.
#[test]
fn the_hooks_send_without_the_lock_is_charged_once_when_its_spool_file_is_taken_in() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    spooled_sends(&fx);
    fx.pass(300);
    let http = fx.record("unit:sensor-http.service").unwrap();
    let backup = fx.record("unit:propolis-backup.service").unwrap();
    assert!(http[30].split(',').any(|f| f == "hookspool"), "{http:?}");
    // (state, sends, delivered_open, pending_tx, pending_since)
    let facts = |r: &[String]| {
        (
            r[7].clone(),
            r[14].clone(),
            r[17].clone(),
            r[26].clone(),
            r[27].clone(),
        )
    };
    let s = |a: &str, b: &str, c: &str, d: &str, e: &str| {
        (
            a.to_string(),
            b.to_string(),
            c.to_string(),
            d.to_string(),
            e.to_string(),
        )
    };
    let (t, fired) = (stamp(300), stamp(0));
    assert_eq!(facts(&http), s("open", "1", "1", "-", "-"));
    assert_eq!(facts(&backup), s("open", "1", "0", "open", &t));
    let mut lines = fx.incident_lines();
    lines.sort();
    let mut want = vec![
        inc_line(
            "unit:sensor-http.service",
            [&t, "stage1", "hook-open", "ok", "hook", &http[1], &fired],
        ),
        inc_line(
            "unit:propolis-backup.service",
            [&t, "pool", "open", "pending", "hook", &backup[1], &fired],
        ),
    ];
    want.sort();
    assert_eq!(lines, want);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    fx.pass(360);
    assert!(fx.posts().is_empty(), "under the 120 s floor");
    fx.pass(420);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].contains(" - backup: "), "{:?}", fx.titles());
    let backup = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(facts(&backup), s("open", "1", "1", "-", "-"));
    assert!(
        fx.incident_lines().contains(&inc_line(
            "unit:propolis-backup.service",
            [&t, "pool", "open", "ok", "light", &backup[1], &stamp(420)],
        )),
        "{:?}",
        fx.incident_lines()
    );
    fx.pass(720);
    assert_eq!(fx.incident_lines().len(), 2, "charged once");
    assert_eq!(fx.posts().len(), 1);

    let fx = Fx::new();
    fx.private_topic(0);
    spooled_sends(&fx);
    fx.pass(300);
    assert!(fx.incident_lines().is_empty(), "legacy");
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!((http[14].as_str(), http[17].as_str()), ("0", "0"), "legacy");
}

/// A child folded under a parent that resolved, and still failing half an hour later, opens on
/// its own: under v2 the record keeps the former parent's id as its 35th field and its open says
/// it was folded under it. The legacy profile writes no such field.
#[test]
fn a_child_that_opens_on_its_own_after_its_parent_resolved_names_the_parent() {
    for v2 in [true, false] {
        let mut fx = Fx::new();
        if v2 {
            fx.v2();
        }
        fx.private_topic(0);
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
        let db = fx.record("db:local").unwrap()[1].clone();
        fx.stub_file("pg.answer", "0|f|");
        fx.pass(1200);
        fx.pass(1500);
        fx.pass(3000);
        let before = fx.posts().len();
        fx.pass(3300);
        let d = fx.record("unit:propolis.service").unwrap();
        assert_eq!((d[7].as_str(), d[13].as_str()), ("open", "-"), "{v2}");
        if v2 {
            assert_eq!(d.get(35).map(String::as_str), Some(db.as_str()), "{d:?}");
            let posts = fx.posts();
            assert_eq!(posts.len(), before + 1, "{}", fx.log());
            assert!(
                posts[before].contains(&format!(" - was folded under {db}")),
                "{}",
                posts[before]
            );
        } else {
            assert_eq!(d.len(), 35, "{d:?}");
        }
    }
}

/// A server that refuses an incident message for good (perm:403) ends its transition and opens
/// alert-path on the next pass, with the cause the renderer reads (http.auth:403). The refusal is
/// one fact: passes after it change nothing more. An incident message that gets through after the
/// open is the proof that the path works again.
#[test]
fn a_permanent_refusal_opens_alert_path_and_a_later_delivery_resolves_it() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_shipper(&fx);
    fx.stub_file("curl.post", "403");
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.posts().len(), 1);
    let ship = fx.record("unit:shipper.service").unwrap();
    assert_eq!((ship[17].as_str(), ship[26].as_str()), ("0", "-"));
    assert_eq!(fx.incident_lines()[0][6], "perm:403");
    fx.pass(600);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[3].as_str(), a[7].as_str(), a[11].as_str()),
        ("alert-path", "open", "http.auth:403")
    );
    assert_eq!(fx.posts().len(), 2, "its own open goes, and is refused too");
    let occ = a[31].clone();
    fx.pass(900);
    assert_eq!(fx.record("alert:shell").unwrap()[31], occ, "one fact");
    assert_eq!(fx.posts().len(), 2);
    // The server takes posts again: a new incident's open gets through, after alert-path opened.
    fx.stub_file("curl.post", "200");
    fx.unit(
        "gateway.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "2"),
        ],
    );
    fx.pass(1200);
    fx.pass(1500);
    assert_eq!(fx.posts().len(), 3, "{}", fx.log());
    fx.pass(1800);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!((a[7].as_str(), a[22].as_str()), ("resolved", "sent2xx"));
}

/// While the light pass is stale (its last pass over 15 minutes old) the hourly pass stands in
/// for it: it judges the first sighting the hook left pending by the light pass's rule (here
/// NRestarts past the sighting's count plus one: still failing), opens it and sends it with
/// itself as the sender, and sends the open of witness-stale for the light pass, which it opens
/// on its second stale check. A light pass that runs meanwhile sends neither again.
#[test]
fn while_the_light_pass_is_stale_the_hourly_pass_completes_hook_sightings_and_sends() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(3600);
    assert!(fx.posts().is_empty(), "the light pass is fresh");
    let mut rec = hook_record("w#7", "sensor-http.service", "PAGE", "pending", 3700, "1");
    rec = with_field(&rec, 33, "-");
    fx.incidents(&[rec]);
    fx.unit("sensor-http.service", &[("NRestarts", "5")]);
    fx.hourly_alone(7200);
    let titles = fx.titles();
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("PAGE host-") && t.contains(" - listen: ")),
        "{titles:?}\n{}",
        fx.log()
    );
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!((http[7].as_str(), http[17].as_str()), ("open", "1"));
    let t = stamp(7200);
    assert!(
        fx.incident_lines().contains(&inc_line(
            "unit:sensor-http.service",
            [&t, "stage1", "open", "ok", "hourly", "w#7", &t]
        )),
        "{:?}",
        fx.incident_lines()
    );
    let sent = fx.posts().len();
    fx.pass(7260);
    assert_eq!(fx.posts().len(), sent, "not sent again by the light pass");
    fx.hourly_alone(10800);
    let stale = fx.record("witness:light").unwrap();
    assert_eq!(stale[7], "open");
    assert!(
        fx.titles().iter().any(|t| t.contains(" - witness: ")),
        "{:?}",
        fx.titles()
    );
    assert!(
        fx.incident_lines()
            .iter()
            .any(|f| f[3] == kh8("witness:light") && f[7] == "hourly"),
        "{:?}",
        fx.incident_lines()
    );
}

/// The hourly pass posts what it admitted itself, whether or not the light pass runs. Its kinds
/// are judged by no other pass, so a message left for the light pass to retry would be dropped
/// after an hour if that pass had stopped, and a change would reach the operator without the
/// cause it changed from. It claims the line under the lock with itself as the sender, and a
/// light pass that then finds the line done posts nothing more.
#[test]
fn the_hourly_pass_posts_the_transitions_of_its_own_kinds_itself() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[("fail", "stale", "logrotate")]), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(0);
    assert!(fx.posts().is_empty());
    fx.hourly(3600);
    let key = format!("finding:stale:{}", k12("stale"));
    let f = fx.record(&key).unwrap();
    let t = stamp(3600);
    assert_eq!(
        (f[7].as_str(), f[26].as_str(), f[17].as_str()),
        ("open", "-", "1"),
        "{}",
        fx.log()
    );
    let titles = incident_titles(&fx);
    assert_eq!(titles.len(), 1, "{}", fx.log());
    assert!(titles[0].starts_with("ACT host-"), "{titles:?}");
    assert_eq!(
        fx.incident_lines(),
        [inc_line(
            &key,
            [&t, "pool", "open", "ok", "hourly", &f[1], &t]
        )]
    );
    for at in [3660, 3720, 4020] {
        fx.pass(at);
    }
    assert_eq!(incident_titles(&fx).len(), 1, "{}", fx.log());
}

/// An admission no pass ever posted is not lost to the hour rule. A pass claims a line just
/// before it posts, so a line of a pass that is still pending with its last attempt at its
/// admission was never tried: a pass killed between admitting and posting, with none after it for
/// over an hour (a host that was down), leaves a message that still goes, once. The failure hook
/// posts without that claim, so a line of its own that looks the same may have gone, and is
/// dropped at the hour as before.
#[test]
fn an_admission_no_pass_ever_posted_is_posted_late_and_not_dropped_at_the_hour() {
    for (sender, goes) in [("light", true), ("hourly", true), ("hook", false)] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(3600);
        failed_backup(&fx);
        pending_backup_open(&fx);
        let key = "unit:propolis-backup.service";
        let s = stamp(0);
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!(
                "#send-ledger v1 g=1\n{}\n",
                inc_line(key, [&s, "pool", "open", "pending", sender, "w#7", &s]).join("\t")
            ),
        );
        fx.pass(3700);
        let r = fx.record(key).unwrap();
        assert_eq!(r[26], "-", "{sender}: {}", fx.log());
        assert_eq!(
            (incident_titles(&fx).len(), r[17].as_str()),
            if goes { (1, "1") } else { (0, "0") },
            "{sender}: {}",
            fx.log()
        );
        if goes {
            assert_eq!(
                fx.incident_lines(),
                [inc_line(
                    key,
                    [&s, "pool", "open", "ok", "light", "w#7", &stamp(3700)]
                )],
                "{sender}"
            );
        }
        fx.pass(4000);
        assert_eq!(incident_titles(&fx).len(), usize::from(goes), "{sender}");
    }
}

/// The same late first post, claimed by a pass whose claim takes it past the send cut (a test
/// seam counts 200 s for the claim against a cut of 100 s): that pass posts it. Left unposted, its
/// line would hold the claim's attempt, it would no longer read as never posted, and the next
/// pass would drop it at the hour with its one message unsent.
#[test]
fn a_late_first_post_claimed_near_the_send_cut_still_goes() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(3600);
    failed_backup(&fx);
    pending_backup_open(&fx);
    let key = "unit:propolis-backup.service";
    let s = stamp(0);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(key, [&s, "pool", "open", "pending", "light", "w#7", &s]).join("\t")
        ),
    );
    fx.setenv("PROPOLIS_WITNESS_SEND_CUT", "100");
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "200");
    fx.pass(3700);
    assert_eq!(incident_titles(&fx).len(), 1, "{}", fx.log());
    let r = fx.record(key).unwrap();
    assert_eq!((r[17].as_str(), r[26].as_str()), ("1", "-"), "{}", fx.log());
    fx.unsetenv("PROPOLIS_WITNESS_SEND_CUT");
    fx.unsetenv("PROPOLIS_WITNESS_POST_SECS");
    fx.pass(4000);
    assert_eq!(incident_titles(&fx).len(), 1);
}

/// A message that got through but whose record could not be written afterwards (its ledger line
/// says ok, the record still names the transition as pending) is closed from the line on the
/// next pass, as its result would have closed it: nothing is pending, the open is delivered, and
/// it is not taken for a message that cannot be delivered, which would open alert-path over one
/// that arrived.
#[test]
fn a_pending_transition_whose_line_holds_its_result_is_closed_from_the_line() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_backup(&fx);
    pending_backup_open(&fx);
    let key = "unit:propolis-backup.service";
    let s = stamp(0);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(key, [&s, "pool", "open", "ok", "light", "w#7", &s]).join("\t")
        ),
    );
    fx.pass(1200);
    let r = fx.record(key).unwrap();
    assert_eq!(
        (r[26].as_str(), r[27].as_str(), r[17].as_str()),
        ("-", "-", "1"),
        "{}",
        fx.log()
    );
    assert!(fx.record("alert:shell").is_none(), "{}", fx.log());
    assert!(incident_titles(&fx).is_empty(), "{:?}", fx.titles());
}

/// The daily message is the same under either profile: the same body, title, ledger line and
/// meta keys, beside an incident that v2 also sends as its own message.
#[test]
fn the_daily_message_is_the_same_under_either_profile() {
    let daily = |v2: bool| {
        let mut fx = Fx::new();
        if v2 {
            fx.v2();
        }
        // One salt for both, so both have one alias.
        fx.write(
            "var/lib/propolis/witness/id-salt",
            "0123456789abcdef0123456789abcdef\n",
        );
        failed_shipper(&fx);
        fx.private_topic(3600);
        fx.pass(3300);
        fx.pass(3600);
        let titles = fx.titles();
        let at = titles
            .iter()
            .position(|t| t.ends_with(": daily"))
            .unwrap_or_else(|| panic!("{v2}: {titles:?}"));
        (
            titles[at].clone(),
            fx.posts()[at].clone(),
            fx.daily_lines(),
            fx.meta("daily_last"),
            fx.meta("daily_last_stamp"),
            titles.len(),
        )
    };
    let (legacy, v2) = (daily(false), daily(true));
    assert_eq!(legacy.5, 1, "legacy posts the daily message alone");
    assert_eq!(v2.5, 2, "v2 posts the shipper's open too");
    assert_eq!(
        (&legacy.0, &legacy.1, &legacy.2, &legacy.3, &legacy.4),
        (&v2.0, &v2.1, &v2.2, &v2.3, &v2.4)
    );
}

/// The titles of the incident messages posted, in order (every post but the daily message).
fn incident_titles(fx: &Fx) -> Vec<String> {
    fx.sent()
        .into_iter()
        .filter(|(t, _, b)| !t.ends_with(": daily") && !is_notice(t, b))
        .map(|(t, _, _)| t)
        .collect()
}

/// The ledger classes that are not an incident message's.
const NOTICE_CLASSES: [&str; 6] = ["daily", "test", "storm", "summary", "switch", "pointer"];

/// A post is a storm notice or a summary: its body says what was withheld.
fn is_notice(_title: &str, body: &str) -> bool {
    body.lines().any(|l| l.starts_with("Withheld: "))
}

/// A W line as the senders write it, `W stamp keyhash tx new inst reason`.
fn w_text(s: &str, key: &str, tx: &str, new: &str, inst: &str, reason: &str) -> String {
    format!("W\t{s}\t{}\t{tx}\t{new}\t{inst}\t{reason}", kh8(key))
}

/// A ledger line of a notice, `L stamp class - class full result sender`.
fn notice_text(s: &str, class: &str, result: &str, sender: &str) -> String {
    format!("L\t{s}\t{class}\t-\t{class}\tfull\t{result}\t{sender}")
}

/// A hook spool file at `rel` for one firing at time `t` (`count` in all), with that cause and the
/// hook's last field `out`.
fn spool_file(fx: &Fx, rel: &str, t: u64, count: u32, cause: &str, out: &str) {
    let s = stamp(t);
    fx.write(
        rel,
        &format!("#hook v1 g=1\nH\t{s}\t{s}\t{count}\texit-code\texited\t1\t{cause}\t0\t{out}\n"),
    );
}

/// The backup run failed, a oneshot of Restart=no: a spooled firing of it opens at once.
fn failed_backup(fx: &Fx) {
    backup_unit(fx, &[]);
}

/// The backup unit as `failed_backup` leaves it, with these properties changed.
fn backup_unit(fx: &Fx, changes: &[(&str, &str)]) {
    let mut props = vec![
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("Restart", "no"),
        ("UnitFileState", "static"),
    ];
    for (k, v) in changes {
        props.retain(|(name, _)| name != k);
        props.push((k, v));
    }
    fx.unit("propolis-backup.service", &props);
}

/// The backup's open, claimed at time 0 by the failure hook and still pending: a record of
/// `w#7` with its pending ledger line, the post never answered.
fn pending_backup_open(fx: &Fx) {
    let key = "unit:propolis-backup.service";
    let mut rec = hook_record("w#7", "propolis-backup.service", "ACT", "open", 0, "-");
    for (i, v) in [
        (14, "1"),
        (15, stamp(0).as_str()),
        (16, "open"),
        (26, "open"),
        (27, stamp(0).as_str()),
        (30, "hookopen"),
        (33, "-"),
    ] {
        rec = with_field(&rec, i, v);
    }
    fx.incidents(&[rec]);
    let s = stamp(0);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(key, [&s, "pool", "open", "pending", "hook", "w#7", &s]).join("\t")
        ),
    );
}

/// A send ledger of these incident lines, each `(key, stamp, class, result)`, sent by the light
/// pass on their admission.
fn ledger_of(fx: &Fx, lines: &[(&str, String, &str, &str)]) {
    let mut body = String::from("#send-ledger v1 g=1\n");
    for (i, (key, s, class, result)) in lines.iter().enumerate() {
        let id = format!("w#{}", 300 + i);
        body.push_str(&inc_line(key, [s, class, "open", result, "light", &id, s]).join("\t"));
        body.push('\n');
    }
    fx.write("var/lib/propolis/witness/send-ledger", &body);
}

/// The hourly pass claims each message it admitted under the lock just before its post, as a retry
/// is claimed: a light pass that runs while the hourly pass's third post is in flight, 200 s after
/// the admission, finds each of the hourly pass's transitions done or claimed under 120 s ago, and
/// posts none of them again. Each ledger line ends with one result, the hourly pass's. (A test
/// seam moves the hourly pass's clock on by 100 s at each claim, as posts in a row take time.)
#[test]
fn a_light_pass_while_the_hourly_pass_posts_sends_none_of_its_transitions_again() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    let found = [
        ("fail", "stale", "logrotate"),
        ("fail", "ops-failure-hook", "alerting"),
        ("fail", "backup-timer", "backup"),
    ];
    fx.cc(&cc_tsv(&[], &found), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(0);
    assert!(fx.posts().is_empty());
    // The third post waits for the light pass.
    fx.stub_file(
        "curl.post.run",
        "d=\"$1\"; n=$(( $(cat \"$d/post.n\" 2> /dev/null || echo 0) + 1 )); echo \"$n\" > \"$d/post.n\"\n\
         if [ \"$n\" = 3 ]; then : > \"$d/post.third\"; while [ ! -e \"$d/post.go\" ]; do sleep 0.1; done; fi\n",
    );
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "100");
    // Stale: the light pass last ran 1200 s ago.
    let mut hourly = fx.start(&["hourly"], 1200, false);
    let third = fx.dir.path().join("post.third");
    let mut waited = 0;
    while !third.exists() && waited < 1200 {
        std::thread::sleep(Duration::from_millis(50));
        waited += 1;
    }
    assert!(third.exists(), "the third post began: {}", fx.log());
    fx.unsetenv("PROPOLIS_WITNESS_POST_SECS");
    fx.pass(1400);
    fx.stub_file("post.go", "");
    assert!(hourly.wait().unwrap().success());
    let titles = fx.titles();
    assert_eq!(titles.len(), 3, "{titles:?}\n{}", fx.log());
    let lines = fx.incident_lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    for l in &lines {
        assert_eq!((l[6].as_str(), l[7].as_str()), ("ok", "hourly"), "{l:?}");
    }
    for (_, k, _) in found {
        let r = fx.record(&format!("finding:{k}:{}", k12(k))).unwrap();
        assert_eq!((r[17].as_str(), r[26].as_str()), ("1", "-"), "{k}");
    }
}

/// A change that gets through does not stand for the open that never did: on an incident whose
/// open was refused (one send, delivered_open 0, nothing pending) a change of cause class that got
/// through leaves it undelivered, so when the unit heals its RESOLVED is withheld without a W line
/// (withhold:undelivered), and the operator never hears of the end of an incident whose start was
/// not delivered.
#[test]
fn a_change_that_got_through_after_a_refused_open_sends_no_resolved() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let mut rec = hook_record("w#7", "shipper.service", "ACT", "open", 0, "-");
    for (i, v) in [
        (11, "fs.no_space"),
        (14, "1"),
        (15, stamp(0).as_str()),
        (16, "open"),
        (33, "-"),
    ] {
        rec = with_field(&rec, i, v);
    }
    fx.incidents(&[rec]);
    failed_shipper(&fx);
    fx.pass(300);
    let ship = |fx: &Fx| {
        fx.titles()
            .into_iter()
            .filter(|t| t.contains(" - ship: "))
            .collect::<Vec<_>>()
    };
    assert_eq!(ship(&fx).len(), 1, "the change: {}", fx.log());
    assert!(ship(&fx)[0].ends_with(" (changed)"), "{:?}", ship(&fx));
    let r = fx.record("unit:shipper.service").unwrap();
    assert_eq!((r[17].as_str(), r[26].as_str()), ("0", "-"));
    fx.unit(
        "shipper.service",
        &[("ActiveEnterTimestampMonotonic", &entered(600, 60))],
    );
    for t in [600, 900, 1200, 1500] {
        fx.pass(t);
    }
    assert_eq!(fx.record("unit:shipper.service").unwrap()[7], "resolved");
    assert_eq!(ship(&fx).len(), 1, "{:?}", ship(&fx));
    let kh = kh8("unit:shipper.service");
    assert!(
        fx.w_lines().iter().all(|w| w[2] != kh),
        "{:?}",
        fx.w_lines()
    );
}

/// Standing in for a stale light pass, the hourly pass reads the units only when what that costs
/// (two spool listings, the sample and the rotation guard's journal: 43 s) still fits before its
/// soft deadline: with 30 s left it does not sample, and the sighting stays pending.
#[test]
fn the_hourly_pass_samples_the_units_only_when_the_whole_sample_fits_before_its_soft_deadline() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(3600);
    let rec = with_field(
        &hook_record("w#7", "sensor-http.service", "PAGE", "pending", 3700, "1"),
        33,
        "-",
    );
    fx.incidents(&[rec]);
    fx.unit("sensor-http.service", &[("NRestarts", "5")]);
    fx.setenv("PROPOLIS_WITNESS_SOFT_DEADLINE", "30");
    clear_log(&fx);
    fx.hourly_alone(7200);
    assert!(
        !fx.log().lines().any(|l| l.contains("ExecMainCode")),
        "{}",
        fx.log()
    );
    assert_eq!(fx.record("unit:sensor-http.service").unwrap()[7], "pending");
    assert!(incident_titles(&fx).is_empty(), "{:?}", fx.titles());
}

/// Standing in for a stale light pass, the hourly pass does the light pass's work for the hook's
/// records: it takes in a hook spool file, opening the Restart=no unit's failure and sending its
/// open; and it sends a reminder that falls due on a hook-opened record, here the late open of a
/// listener whose open was withheld (class late, sender hourly), which marks it delivered.
#[test]
fn while_the_light_pass_is_stale_the_hourly_pass_takes_in_spool_files_and_sends_due_reminders() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(3600);
    let spool = "run/propolis-witness/fallback/hook-propolis-backup.service";
    spool_file(&fx, spool, 3700, 1, "proc.exit:1", "-");
    failed_backup(&fx);
    let mut rec = hook_record("w#7", "sensor-http.service", "PAGE", "open", 3700, "1");
    for (i, v) in [
        (19, stamp(7000).as_str()),
        (29, "0"),
        (30, "hookopen"),
        (33, "-"),
    ] {
        rec = with_field(&rec, i, v);
    }
    let w = format!(
        "W\t{}\t{}\topen\t1\t-\tstage1-cap\n",
        stamp(3700),
        kh8("unit:sensor-http.service")
    );
    fx.incidents(&[rec, w]);
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.hourly_alone(7200);
    assert!(!fx.p(spool).exists(), "taken in");
    let backup = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!((backup[7].as_str(), backup[17].as_str()), ("open", "1"));
    let t = stamp(7200);
    let lines = fx.incident_lines();
    assert!(
        lines.contains(&inc_line(
            "unit:propolis-backup.service",
            [&t, "pool", "open", "ok", "hourly", &backup[1], &t]
        )),
        "{lines:?}\n{}",
        fx.log()
    );
    assert!(
        lines.contains(&inc_line(
            "unit:sensor-http.service",
            [&t, "late", "remind", "ok", "hourly", "w#7", &t]
        )),
        "{lines:?}"
    );
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!((http[17].as_str(), http[18].as_str()), ("1", "1"));
    assert_eq!(incident_titles(&fx).len(), 2, "{:?}", fx.titles());
}

/// Standing in for a stale light pass, the hourly pass judges pending sightings by the light
/// pass's rule: one whose unit healed is dropped and counted in meta healed; one under a
/// maintenance marker, in the ten minutes after a marker was last seen, or in the boot's first ten
/// minutes stays pending.
#[test]
fn the_hourly_pass_standing_in_drops_healed_sightings_and_keeps_the_light_passs_holds() {
    for case in ["healed", "marker", "after marker", "boot grace"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.install_cc();
        fx.cc(&cc_tsv(&[], &[]), 0);
        fx.curl_answers("403|text/plain");
        fx.hourly(3600);
        let mut rec = with_field(
            &hook_record("w#7", "sensor-http.service", "PAGE", "pending", 3700, "1"),
            33,
            "-",
        );
        match case {
            "healed" => fx.unit(
                "sensor-http.service",
                &[
                    ("NRestarts", "1"),
                    ("ActiveEnterTimestampMonotonic", &entered(7200, 3000)),
                ],
            ),
            "marker" => {
                fx.unit("sensor-http.service", &[("NRestarts", "5")]);
                fx.write(
                    "run/propolis-witness/maintenance",
                    &format!("#maintenance v1 g=1\nX\t{}\t{BOOT}\tmanual\n", WALL + 9000),
                );
            }
            "after marker" => {
                fx.unit("sensor-http.service", &[("NRestarts", "5")]);
                set_meta(&fx, "maint_seen", &stamp(6900));
            }
            _ => {
                fx.unit("sensor-http.service", &[("NRestarts", "5")]);
                // A boot 300 s ago: the record's sighting is of the boot before.
                fx.setenv(
                    "PROPOLIS_WITNESS_NOW",
                    &format!("{}/abcdef02/300", WALL + 7200),
                );
                rec = with_field(&rec, 8, &stamp(3700));
            }
        }
        fx.incidents(&[rec]);
        fx.hourly_alone(7200);
        let r = fx.record("unit:sensor-http.service");
        if case == "healed" {
            assert!(r.is_none(), "{case}: {r:?}");
            assert!(
                fx.meta("healed").is_some_and(|h| h.starts_with("1/")),
                "{case}: {:?}",
                fx.meta("healed")
            );
        } else {
            assert_eq!(
                r.map(|r| r[7].clone()).as_deref(),
                Some("pending"),
                "{case}"
            );
            assert_eq!(fx.meta("healed"), None, "{case}");
        }
        assert!(incident_titles(&fx).is_empty(), "{case}: {:?}", fx.titles());
    }
}

/// Under the legacy profile the hourly pass never stands in for a stale light pass: it reads no
/// unit, judges no pending sighting, takes in no spool file and sends no reminder, and meta healed
/// is left as it was, as the previous release leaves them all.
#[test]
fn under_legacy_the_hourly_pass_never_stands_in_for_a_stale_light_pass() {
    let fx = Fx::new();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.hourly(3600);
    let pending = with_field(
        &hook_record("w#7", "sensor-http.service", "PAGE", "pending", 3700, "1"),
        33,
        "-",
    );
    let healed = with_field(
        &hook_record("w#8", "sensor-ssh.service", "PAGE", "pending", 3700, "1"),
        33,
        "-",
    );
    let mut due = hook_record("w#9", "shipper.service", "ACT", "open", 3700, "-");
    for (i, v) in [(19, stamp(7000).as_str()), (30, "hookopen"), (33, "-")] {
        due = with_field(&due, i, v);
    }
    fx.incidents(&[pending, healed, due]);
    fx.unit("sensor-http.service", &[("NRestarts", "5")]);
    fx.unit(
        "sensor-ssh.service",
        &[
            ("NRestarts", "1"),
            ("ActiveEnterTimestampMonotonic", &entered(7200, 3000)),
        ],
    );
    failed_shipper(&fx);
    let spool = "run/propolis-witness/fallback/hook-propolis-backup.service";
    spool_file(&fx, spool, 3700, 1, "proc.exit:1", "-");
    failed_backup(&fx);
    let before = fx.meta("healed");
    clear_log(&fx);
    fx.hourly_alone(7200);
    assert!(
        !fx.log().lines().any(|l| l.contains("ExecMainCode")),
        "{}",
        fx.log()
    );
    assert_eq!(fx.record("unit:sensor-http.service").unwrap()[7], "pending");
    assert_eq!(fx.record("unit:sensor-ssh.service").unwrap()[7], "pending");
    let r = fx.record("unit:shipper.service").unwrap();
    assert_eq!((r[18].as_str(), r[29].as_str()), ("0", "1"), "no reminder");
    assert!(fx.p(spool).exists(), "not taken in");
    assert!(fx.record("unit:propolis-backup.service").is_none());
    assert_eq!(fx.meta("healed"), before);
}

/// Under the legacy profile a send ledger no copy of which can be read holds the daily message on
/// that pass, as the previous release holds it: judging alert-path reads no ledger under legacy,
/// so the budget's own read is the first, finds nothing it can count and admits nothing; the next
/// pass counts from the empty ledger it left and sends.
#[test]
fn under_legacy_a_damaged_send_ledger_holds_the_daily_message_on_that_pass() {
    let fx = Fx::new();
    fx.private_topic(2460);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v9 g=1\nL\tdamaged\n",
    );
    fx.pass(2460);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.daily_lines().is_empty());
    fx.pass(2760);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
}

/// The same under v2: the pass's first read of the ledger, made before any other, decides that
/// nothing is admitted on this pass, the daily message included, though that read leaves an empty
/// ledger behind for a later read; the next pass sends it.
#[test]
fn under_v2_a_damaged_send_ledger_holds_the_daily_message_on_that_pass() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(2460);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v9 g=1\nL\tdamaged\n",
    );
    fx.pass(2460);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.daily_lines().is_empty());
    fx.pass(2760);
    let titles = fx.titles();
    assert_eq!(titles.len(), 1, "{}", fx.log());
    assert!(titles[0].ends_with(": daily"), "{titles:?}");
}

/// Under the legacy profile an incident message the send ledger says got through is no proof
/// that alerts get out (no such message is sent under legacy): alert-path stays open, as the
/// previous release leaves it. Under v2 the same line resolves it.
#[test]
fn under_legacy_an_incident_message_in_the_send_ledger_is_no_proof_for_alert_path() {
    for v2 in [false, true] {
        let mut fx = Fx::new();
        if v2 {
            fx.v2();
            fx.private_topic(0);
        }
        fx.incidents(&[alert_path_record(&stamp(0))]);
        ledger_of(&fx, &[("unit:shipper.service", stamp(100), "pool", "ok")]);
        fx.pass(300);
        fx.pass(600);
        let a = fx.record("alert:shell").unwrap();
        if v2 {
            assert_eq!((a[7].as_str(), a[22].as_str()), ("resolved", "sent2xx"));
        } else {
            assert_eq!(a[7], "open", "{}", fx.log());
        }
    }
}

/// Under v2 the daily message is a post of the witness to the target alert-path is about: one that
/// got through after alert-path opened is the proof that the path works (sent2xx), so an
/// alert-path whose reminders are spent resolves on a quiet host, and the heartbeat ping it held
/// is made again once 30 minutes have passed clean.
#[test]
fn under_v2_a_daily_message_that_got_through_resolves_alert_path() {
    let pings = |fx: &Fx| fx.log().lines().filter(|l| l.starts_with("curl ")).count();
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(2460);
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n",
    );
    fx.curl_answers("200|text/plain");
    let mut a = alert_path_record(&stamp(0));
    for (i, v) in [(11, "http.auth:403"), (18, "3"), (19, "-")] {
        a = with_field(&a, i, v);
    }
    fx.incidents(&[a]);
    fx.pass(2460);
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].ends_with(": daily"));
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open");
    fx.pass(2760);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!((a[7].as_str(), a[22].as_str()), ("resolved", "sent2xx"));
    assert_eq!(pings(&fx), 0, "{}", fx.log());
    fx.pass(4300);
    assert_eq!(pings(&fx), 1, "{}", fx.log());
}

/// With 512 open records a new open cannot be kept; its transition goes with it and is never
/// queued for another record: a pass that then only reschedules an open record's reminder (a
/// record with no schedule gets one) sends nothing for it.
#[test]
fn a_transition_whose_record_could_not_be_kept_is_sent_for_no_other_record() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let open: Vec<String> = (0..512)
        .map(|i| {
            let r = hook_record(&format!("w#{}", i + 100), "x", "ACT", "open", 0, "-")
                .replace("unit:x", &format!("finding:test:{i:012}"));
            with_field(&r, 33, "-")
        })
        .collect();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=1\nN\t700\n{}", open.concat()),
    );
    spool_file(
        &fx,
        "var/lib/propolis/witness/hook/propolis-backup.service",
        0,
        1,
        "proc.exit:1",
        "-",
    );
    failed_backup(&fx);
    fx.pass(300);
    assert!(
        fx.log()
            .contains("incident not recorded: the record of unit:propolis-backup.service"),
        "{}",
        fx.log()
    );
    assert!(fx.incident_lines().is_empty(), "{:?}", fx.incident_lines());
    assert!(fx.posts().is_empty(), "{:?}", fx.titles());
}

/// The hook's send charged at ingestion has its last attempt at the hook's firing, not at the pass
/// that took the file in: a message that got through before alert-path opened is no proof that the
/// path works since, and alert-path stays open.
#[test]
fn a_hook_send_made_before_alert_path_opened_does_not_resolve_it() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let mut a = alert_path_record(&stamp(200));
    a = with_field(&a, 11, "http.auth:403");
    fx.incidents(&[a]);
    spool_file(
        &fx,
        "run/propolis-witness/fallback/hook-sensor-http.service",
        100,
        1,
        "proc.signal:9",
        "ok",
    );
    fx.pass(300);
    fx.pass(600);
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open", "{}", fx.log());
}

/// A spool file taken in is removed once a write of the records holds it: an admission's write
/// holds it, so a later write of the pass that fails cannot give the file back to be counted
/// again; the next pass raises the occurrences and the sends once.
#[test]
fn a_spool_file_taken_in_is_counted_once_when_the_passs_last_write_fails() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_shipper(&fx);
    fx.pass(0);
    spool_file(
        &fx,
        "run/propolis-witness/fallback/hook-sensor-http.service",
        100,
        5,
        "proc.signal:9",
        "ok",
    );
    // Still failing, so nothing but the spool file moves its record.
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "signal"),
            ("ExecMainStatus", "9"),
        ],
    );
    // The admission's write of the incidents goes through; the pass's own write after it does not.
    fx.stub_file("disk.refuses", "*incidents*\n");
    fx.stub_file("disk.refuses.after", "1");
    fx.pass(300);
    std::fs::remove_file(fx.dir.path().join("disk.refuses")).unwrap();
    fx.pass(600);
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!(
        (http[14].as_str(), http[31].as_str()),
        ("1", "5"),
        "{}",
        fx.log()
    );
    let kh = kh8("unit:sensor-http.service");
    assert_eq!(
        fx.incident_lines().iter().filter(|l| l[3] == kh).count(),
        1,
        "{:?}",
        fx.incident_lines()
    );
}

/// A pending transition whose ledger line is gone (a damaged ledger replaced by an empty one) can
/// never be claimed: it is dropped at once, so the incident waits for its reminder, and neither
/// the heartbeat's rule about a transition pending over 15 minutes nor alert-path is held by it.
#[test]
fn a_pending_transition_whose_ledger_line_is_gone_is_dropped_at_once() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n",
    );
    fx.curl_answers("200|text/plain");
    failed_shipper(&fx);
    fx.stub_file("curl.post", "503");
    fx.pass(0);
    fx.pass(300);
    assert_eq!(fx.record("unit:shipper.service").unwrap()[26], "open");
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v9 g=1\nL\tdamaged\n",
    );
    fx.pass(420);
    let r = fx.record("unit:shipper.service").unwrap();
    assert_eq!((r[26].as_str(), r[27].as_str()), ("-", "-"), "{}", fx.log());
    fx.pass(1300);
    assert!(
        !fx.meta("hb_skip").unwrap_or_default().ends_with("/pending"),
        "{:?}",
        fx.meta("hb_skip")
    );
    assert!(fx.record("alert:shell").is_none());
}

/// A transition undelivered for more than 15 minutes opens alert-path, with the cause its
/// last answer names (here the server's 503: http.server); once messages get through again it
/// resolves on that proof.
#[test]
fn a_transition_undelivered_for_fifteen_minutes_opens_alert_path() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_shipper(&fx);
    fx.stub_file("curl.post", "503");
    for t in [0, 300, 600, 900, 1200] {
        fx.pass(t);
    }
    assert!(fx.record("alert:shell").is_none(), "{}", fx.log());
    fx.pass(1500);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str()),
        ("open", "http.server:503"),
        "{a:?}"
    );
    fx.stub_file("curl.post", "200");
    fx.pass(1800);
    fx.pass(2100);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!((a[7].as_str(), a[22].as_str()), ("resolved", "sent2xx"));
}

/// An open incident whose open never got through (delivered_open 0) and whose proof now holds is
/// resolved in the records, and its RESOLVED is neither sent nor recorded as withheld.
#[test]
fn the_resolve_of_an_incident_never_delivered_is_neither_sent_nor_withheld() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let mut rec = hook_record("w#7", "shipper.service", "ACT", "open", 0, "-");
    for (i, v) in [(14, "1"), (17, "0"), (33, "-")] {
        rec = with_field(&rec, i, v);
    }
    fx.incidents(&[rec]);
    fx.unit(
        "shipper.service",
        &[("ActiveEnterTimestampMonotonic", &entered(300, 60))],
    );
    for t in [300, 600, 900, 1200] {
        fx.pass(t);
    }
    assert_eq!(fx.record("unit:shipper.service").unwrap()[7], "resolved");
    assert!(fx.posts().is_empty(), "{:?}", fx.titles());
    assert!(fx.w_lines().is_empty(), "{:?}", fx.w_lines());
}

/// One message per incident and pass: a record that opens and changes its cause in the same pass
/// gets one ledger line, the open's, and one post; one that opens and resolves in the same pass
/// gets none, and no W line, since its open never got through.
#[test]
fn two_transitions_of_one_incident_in_one_pass_send_at_most_one_message() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let spool = "var/lib/propolis/witness/hook/propolis-backup.service";
    // The hook's cause is of another class than the one the pass's sample gives.
    spool_file(&fx, spool, 0, 1, "fs.no_space", "-");
    backup_unit(&fx, &[("ExecMainStatus", "1")]);
    fx.pass(300);
    let r = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(
        (r[7].as_str(), r[11].as_str()),
        ("open", "proc.exit:1"),
        "{}",
        fx.log()
    );
    let lines = fx.incident_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0][4], "open");
    assert_eq!(fx.posts().len(), 1);

    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    spool_file(&fx, spool, 0, 1, "proc.exit:1", "-");
    backup_unit(
        &fx,
        &[
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("ExecMainStartTimestampMonotonic", &mono(300, 60)),
            ("ExecMainExitTimestampMonotonic", &mono(300, 30)),
            ("InactiveEnterTimestampMonotonic", &entered(300, 30)),
        ],
    );
    fx.pass(300);
    let r = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(r[7], "resolved", "{}", fx.log());
    assert!(fx.incident_lines().is_empty(), "{:?}", fx.incident_lines());
    assert!(fx.posts().is_empty());
    assert!(fx.w_lines().is_empty(), "{:?}", fx.w_lines());
}

/// A retry is claimed only while the record still holds that transition with that admission:
/// another writer that changed it between the admission and the claim (here while the pass's
/// first post was in flight) has it, and the pass posts nothing for it.
#[test]
fn a_retry_whose_record_changed_since_it_was_listed_is_not_posted() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    pending_backup_open(&fx);
    failed_backup(&fx);
    failed_shipper(&fx);
    fx.pass(60);
    let f = fx.p("var/lib/propolis/witness/incidents");
    fx.stub_file(
        "curl.post.run",
        &format!(
            "[ -e \"$1/edited\" ] && exit 0; : > \"$1/edited\"\n\
             f='{}'; awk -F'\\t' -v OFS='\\t' '$1==\"I\" && $3==\"unit:propolis-backup.service\" {{ $28=\"{}\" }} 1' \"$f\" > \"$f.new\" && mv -f \"$f.new\" \"$f\"\n",
            f.display(),
            stamp(250)
        ),
    );
    fx.pass(300);
    let titles = fx.titles();
    assert_eq!(titles.len(), 1, "{titles:?}");
    assert!(titles[0].contains(" - ship: "), "{titles:?}");
    assert_eq!(
        fx.record("unit:propolis-backup.service").unwrap()[27],
        stamp(250)
    );
}

/// A claim is followed by its post. The claim moves the line's last attempt to now, which keeps
/// every other pass off the transition for 120 s and ends its standing as never posted, so a pass
/// that claimed and then did not post would leave a message the hour rule drops unsent. The send
/// cut is asked before a claim, never between a claim and its post. (A test seam counts 200 s for
/// each claim against a cut of 100 s.) One retry: claimed and posted. Two admissions in one pass:
/// the first is claimed and posted, the second is left as it was admitted, never claimed, and the
/// next pass posts it.
#[test]
fn a_transition_claimed_before_the_send_cut_is_always_posted() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    pending_backup_open(&fx);
    failed_backup(&fx);
    fx.setenv("PROPOLIS_WITNESS_SEND_CUT", "100");
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "200");
    fx.pass(300);
    assert_eq!(incident_titles(&fx).len(), 1, "{}", fx.log());
    let s = stamp(0);
    assert_eq!(
        fx.incident_lines(),
        [inc_line(
            "unit:propolis-backup.service",
            [&s, "pool", "open", "ok", "light", "w#7", &stamp(500)]
        )]
    );

    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    two_refused_hook_sends(&fx, "transient:503");
    fx.setenv("PROPOLIS_WITNESS_SEND_CUT", "100");
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "200");
    fx.pass(300);
    let titles = incident_titles(&fx);
    assert_eq!(titles.len(), 1, "{titles:?}\n{}", fx.log());
    assert!(titles[0].contains(" - backup: "), "{titles:?}");
    let t = stamp(300);
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!(
        (http[17].as_str(), http[26].as_str(), http[27].as_str()),
        ("0", "open", t.as_str()),
        "{}",
        fx.log()
    );
    assert!(
        fx.incident_lines().contains(&inc_line(
            "unit:sensor-http.service",
            [&t, "stage1", "open", "pending", "light", &http[1], &t]
        )),
        "{:?}",
        fx.incident_lines()
    );
    fx.unsetenv("PROPOLIS_WITNESS_SEND_CUT");
    fx.unsetenv("PROPOLIS_WITNESS_POST_SECS");
    fx.pass(600);
    let titles = incident_titles(&fx);
    assert_eq!(titles.len(), 2, "{titles:?}\n{}", fx.log());
    let http = fx.record("unit:sensor-http.service").unwrap();
    assert_eq!((http[17].as_str(), http[26].as_str()), ("1", "-"));
}

/// The firings of two units the hook sent without the lock, each post answered with `result`: the
/// backup's spool file in the state directory, taken in first, the sensor's in /run. Both units
/// are failed and do not restart, so each record opens when its file is taken in and its open is
/// the pass's to send.
fn two_refused_hook_sends(fx: &Fx, result: &str) {
    spool_file(
        fx,
        "var/lib/propolis/witness/hook/propolis-backup.service",
        0,
        1,
        "proc.exit:1",
        result,
    );
    spool_file(
        fx,
        "run/propolis-witness/fallback/hook-sensor-http.service",
        0,
        1,
        "proc.exit:1",
        result,
    );
    failed_backup(fx);
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
        ],
    );
}

/// What the hook's send without the lock cost the budget is an entry of its own in the send
/// ledger, never a transition's line. Written in the same pass and second as the admission of
/// that key's own open (the hook's post was refused, so the open is the pass's to send), with the
/// same stamp and key, it is not taken for that admission: its transition word is `hook-open`,
/// which no record ever holds as pending. Two units' firings taken in by one pass: the entry for
/// the second is written before the second's admission, and both opens are still posted, each
/// admission line ending ok and each entry keeping the hook's result.
#[test]
fn what_the_hooks_send_cost_is_never_taken_for_that_keys_admission() {
    for result in ["perm:403", "transient:503"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(0);
        two_refused_hook_sends(&fx, result);
        fx.pass(300);
        let titles = incident_titles(&fx);
        assert_eq!(titles.len(), 2, "{result}: {titles:?}\n{}", fx.log());
        let (t, fired) = (stamp(300), stamp(0));
        let mut want = Vec::new();
        for (unit, class) in [
            ("propolis-backup.service", "pool"),
            ("sensor-http.service", "stage1"),
        ] {
            let key = format!("unit:{unit}");
            let r = fx.record(&key).unwrap();
            assert_eq!(
                (
                    r[7].as_str(),
                    r[14].as_str(),
                    r[17].as_str(),
                    r[26].as_str()
                ),
                ("open", "2", "1", "-"),
                "{result} {unit}"
            );
            want.push(inc_line(
                &key,
                [&t, class, "hook-open", result, "hook", &r[1], &fired],
            ));
            want.push(inc_line(
                &key,
                [&t, class, "open", "ok", "light", &r[1], &t],
            ));
        }
        want.sort();
        let mut lines = fx.incident_lines();
        lines.sort();
        assert_eq!(lines, want, "{result}");
    }
}

/// A transition whose ledger line was lost when it had already waited over 15 minutes (a damaged
/// ledger replaced by an empty one) is dropped by the pass that finds the line gone, and is no
/// message waiting on the alert path: alert-path does not open over it.
#[test]
fn a_transition_whose_line_was_lost_after_15_minutes_opens_no_alert_path() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_backup(&fx);
    pending_backup_open(&fx);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=1\n",
    );
    fx.pass(1200);
    let r = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(
        (r[26].as_str(), r[27].as_str(), r[17].as_str()),
        ("-", "-", "0"),
        "{}",
        fx.log()
    );
    assert!(fx.record("alert:shell").is_none(), "{}", fx.log());
    assert!(incident_titles(&fx).is_empty(), "{:?}", fx.titles());
}

/// Two records that hold one id (a damaged incidents file) are each a transition of their own:
/// both pending opens are retried, neither standing in for the other.
#[test]
fn two_pending_records_with_one_id_are_both_retried() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    failed_backup(&fx);
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("Restart", "no"),
        ],
    );
    let s = stamp(0);
    let mut recs = Vec::new();
    let mut ledger = String::from("#send-ledger v1 g=1\n");
    for (unit, tier, class) in [
        ("propolis-backup.service", "ACT", "pool"),
        ("sensor-http.service", "PAGE", "stage1"),
    ] {
        let mut rec = hook_record("w#7", unit, tier, "open", 0, "-");
        for (i, v) in [
            (14, "1"),
            (15, s.as_str()),
            (16, "open"),
            (26, "open"),
            (27, s.as_str()),
            (30, "hookopen"),
            (33, "-"),
        ] {
            rec = with_field(&rec, i, v);
        }
        recs.push(rec);
        ledger.push_str(
            &inc_line(
                &format!("unit:{unit}"),
                [&s, class, "open", "pending", "hook", "w#7", &s],
            )
            .join("\t"),
        );
        ledger.push('\n');
    }
    fx.incidents(&recs);
    fx.write("var/lib/propolis/witness/send-ledger", &ledger);
    fx.pass(300);
    let titles = incident_titles(&fx);
    assert_eq!(titles.len(), 2, "{titles:?}\n{}", fx.log());
    for unit in ["propolis-backup.service", "sensor-http.service"] {
        let r = fx.record(&format!("unit:{unit}")).unwrap();
        assert_eq!((r[17].as_str(), r[26].as_str()), ("1", "-"), "{unit}");
    }
}

/// A pending transition is retried only with the gate full and only by a pass that sends: with
/// the gate short of full it stays pending, unsent (the one post is the pointer message for the
/// open incident); an hourly pass while the light pass runs leaves it to the light pass.
#[test]
fn a_pending_transition_is_retried_only_with_the_gate_full_and_by_a_pass_that_sends() {
    let mut fx = Fx::new();
    fx.v2();
    pending_backup_open(&fx);
    failed_backup(&fx);
    fx.pass(300);
    let titles = fx.titles();
    assert_eq!(titles.len(), 1, "{titles:?}\n{}", fx.log());
    assert!(titles[0].ends_with(": needs attention"), "{titles:?}");
    assert_eq!(
        fx.record("unit:propolis-backup.service").unwrap()[26],
        "open"
    );

    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    pending_backup_open(&fx);
    failed_backup(&fx);
    fx.hourly(300);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    let s = stamp(0);
    assert_eq!(
        fx.incident_lines(),
        [inc_line(
            "unit:propolis-backup.service",
            [&s, "pool", "open", "pending", "hook", "w#7", &s]
        )]
    );
}

/// A message the hook sent without the lock that a server refused for good or for now is charged
/// once, and the open is still the pass's to send, which it admits and posts; a refusal for good
/// opens alert-path on the next pass.
#[test]
fn a_hook_send_that_was_refused_is_charged_and_the_pass_sends_its_own_open() {
    for result in ["perm:403", "transient:503"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(0);
        spool_file(
            &fx,
            "var/lib/propolis/witness/hook/propolis-backup.service",
            0,
            1,
            "proc.exit:1",
            result,
        );
        failed_backup(&fx);
        fx.pass(300);
        let b = fx.record("unit:propolis-backup.service").unwrap();
        let key = "unit:propolis-backup.service";
        let (t, fired) = (stamp(300), stamp(0));
        let mut lines = fx.incident_lines();
        lines.sort();
        let mut want = vec![
            inc_line(
                key,
                [&t, "pool", "hook-open", result, "hook", &b[1], &fired],
            ),
            inc_line(key, [&t, "pool", "open", "ok", "light", &b[1], &t]),
        ];
        want.sort();
        assert_eq!(lines, want, "{result}");
        assert_eq!(fx.posts().len(), 1, "{result}");
        assert_eq!((b[14].as_str(), b[17].as_str()), ("2", "1"), "{result}");
        fx.pass(600);
        let a = fx.record("alert:shell");
        if result == "perm:403" {
            let a = a.unwrap();
            assert_eq!((a[7].as_str(), a[11].as_str()), ("open", "http.auth:403"));
        } else {
            assert!(a.is_none(), "{a:?}");
        }
    }
}

/// A child held pending by tie 1 (the daemon down while the database does not answer), folded
/// under the database's incident and still failing half an hour after that resolved, opens on its
/// own (folded_pending): under v2 it keeps the parent's id as its 35th field and its open says it
/// was folded under it.
#[test]
fn a_pending_child_that_opens_after_its_parent_resolved_names_the_parent() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.database("0|f|");
    fx.daemon_account();
    fx.stub_file("journal.daemon", CONNECT_LINE);
    fx.stub_file("pg.answer", PG_REFUSED);
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
    assert_eq!(d[7], "pending", "{d:?}");
    let db = fx.record("db:local").unwrap()[1].clone();
    fx.stub_file("pg.answer", "0|f|");
    let mut t = 600;
    while t <= 5400 && fx.record("unit:propolis.service").unwrap()[7] == "pending" {
        fx.pass(t);
        t += 300;
    }
    let d = fx.record("unit:propolis.service").unwrap();
    assert_eq!(
        (d[7].as_str(), d[13].as_str()),
        ("open", "-"),
        "{}",
        fx.log()
    );
    assert_eq!(d.get(35).map(String::as_str), Some(db.as_str()), "{d:?}");
    let posts = fx.posts();
    assert!(
        posts
            .iter()
            .any(|p| p.contains(&format!(" - was folded under {db}"))),
        "{posts:?}"
    );
}

/// The late open: a listener whose open the budget withheld for stage 1's hour (a W line,
/// no post) is reminded an hour on, and that reminder is admitted in the late class of its own,
/// posted, and marks the incident delivered, so its RESOLVED can follow.
#[test]
fn a_withheld_listener_open_goes_as_its_late_open_an_hour_on() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    ledger_of(
        &fx,
        &[
            ("unit:sensor-ssh.service", stamp(0), "stage1", "ok"),
            ("unit:sensor-ftp.service", stamp(0), "stage1", "ok"),
        ],
    );
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.pass(0);
    fx.pass(300);
    let kh = kh8("unit:sensor-http.service");
    assert_eq!(fx.record("unit:sensor-http.service").unwrap()[7], "open");
    assert!(incident_titles(&fx).is_empty(), "{}", fx.log());
    assert!(
        fx.w_lines()
            .iter()
            .any(|w| w[2] == kh && w[6] == "stage1-cap"),
        "{:?}",
        fx.w_lines()
    );
    let mut t = 600;
    while t <= 4500 && incident_titles(&fx).is_empty() {
        fx.pass(t);
        t += 300;
    }
    let lines: Vec<_> = fx
        .incident_lines()
        .into_iter()
        .filter(|l| l[3] == kh)
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}\n{}", fx.log());
    assert_eq!(
        (
            lines[0][2].as_str(),
            lines[0][4].as_str(),
            lines[0][6].as_str()
        ),
        ("late", "remind", "ok")
    );
    assert_eq!(fx.record("unit:sensor-http.service").unwrap()[17], "1");
}

/// The witness records each budget verdict it withholds by as a W line, its reason the budget's
/// word, and posts nothing for it: the pool full for the hour (a non-listener's open), stage 1
/// full (a listener's open) and the key's own cap (a reminder of a key that had six messages in a
/// day).
#[test]
fn the_witness_writes_a_w_line_for_each_budget_verdict_that_withholds() {
    for reason in ["pool", "stage1-cap", "key-cap"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(0);
        let key = match reason {
            "stage1-cap" => "unit:sensor-http.service",
            _ => "unit:shipper.service",
        };
        match reason {
            "pool" => {
                let others: Vec<(&str, String, &str, &str)> =
                    ["push:a", "push:b", "push:c", "push:d"]
                        .iter()
                        .map(|k| (*k, stamp(0), "pool", "ok"))
                        .collect();
                ledger_of(&fx, &others);
                failed_shipper(&fx);
            }
            "stage1-cap" => {
                ledger_of(
                    &fx,
                    &[
                        ("unit:sensor-ssh.service", stamp(0), "stage1", "ok"),
                        ("unit:sensor-ftp.service", stamp(0), "stage1", "ok"),
                    ],
                );
                fx.unit(
                    "sensor-http.service",
                    &[
                        ("ActiveState", "failed"),
                        ("SubState", "failed"),
                        ("Result", "exit-code"),
                    ],
                );
            }
            _ => {
                let early = format!("{}/{BOOT}/{}", WALL - 7200, UP - 7200);
                let six: Vec<(&str, String, &str, &str)> =
                    (0..6).map(|_| (key, early.clone(), "pool", "ok")).collect();
                ledger_of(&fx, &six);
                let mut rec = hook_record("w#7", "shipper.service", "ACT", "open", 0, "-");
                for (i, v) in [(14, "6"), (17, "1"), (19, stamp(200).as_str()), (33, "-")] {
                    rec = with_field(&rec, i, v);
                }
                fx.incidents(&[rec]);
                failed_shipper(&fx);
            }
        }
        fx.pass(0);
        fx.pass(300);
        assert!(
            incident_titles(&fx).is_empty(),
            "{reason}: {:?}",
            fx.titles()
        );
        let kh = kh8(key);
        let w = fx.w_lines();
        assert!(
            w.iter().any(|w| w[2] == kh && w[6] == reason),
            "{reason}: {w:?}\n{}",
            fx.log()
        );
    }
}

/// A spool file taken in on a pass whose records cannot be written is given back and charges
/// nothing that counts (a pending charge is given back as noclaim); the pass that can write takes
/// it in and charges each send once.
#[test]
fn a_spool_file_given_back_charges_nothing_and_is_charged_once_when_taken_in() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    spooled_sends(&fx);
    fx.stub_file("disk.refuses", "*incidents*\n");
    fx.pass(300);
    let counted = |fx: &Fx| {
        fx.incident_lines()
            .into_iter()
            .filter(|l| l[6] != "noclaim")
            .collect::<Vec<_>>()
    };
    assert!(counted(&fx).is_empty(), "{:?}", fx.incident_lines());
    assert!(
        fx.p("run/propolis-witness/fallback/hook-sensor-http.service")
            .exists()
    );
    assert!(
        fx.p("var/lib/propolis/witness/hook/propolis-backup.service")
            .exists()
    );
    std::fs::remove_file(fx.dir.path().join("disk.refuses")).unwrap();
    fx.pass(600);
    let lines = counted(&fx);
    assert_eq!(lines.len(), 2, "{lines:?}");
    for key in ["unit:sensor-http.service", "unit:propolis-backup.service"] {
        assert_eq!(
            lines.iter().filter(|l| l[3] == kh8(key)).count(),
            1,
            "{key}: {lines:?}"
        );
    }
}

// ---- the storm notice and the summary ----------------------------------------------------------

/// A v2 fixture whose pool is full for the hour (four pool messages at time 0) and whose shipper
/// fails, on a proven private topic: the second pass, at 300, withholds the shipper's open (W
/// reason pool). Each claim counts one second on the test clock, so a notice's claim falls a
/// second after the W lines its pass wrote.
fn pool_full_shipper() -> Fx {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "1");
    let others: Vec<(&str, String, &str, &str)> = ["push:a", "push:b", "push:c", "push:d"]
        .iter()
        .map(|k| (*k, stamp(0), "pool", "ok"))
        .collect();
    ledger_of(&fx, &others);
    failed_shipper(&fx);
    fx
}

/// The shipper's instance id, as the notices name it.
fn shipper_inst(fx: &Fx) -> String {
    fx.record("unit:shipper.service").unwrap()[5].clone()
}

/// The storm notice goes at once, on the pass that withheld the open, as the class's one message
/// in six hours: titled `alert budget reached` at priority 3 (an ACT incident), it counts the W
/// line and names the new incident by its instance id. Its ledger line is of class storm and got
/// ok, and meta storm_last holds its claim's stamp, so a pass after it lists nothing again.
#[test]
fn a_withheld_open_sends_one_storm_notice_at_once_and_its_claim_becomes_storm_last() {
    let fx = pool_full_shipper();
    fx.pass(0);
    fx.pass(300);
    let inst = shipper_inst(&fx);
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    let (title, prio, body) = &notices[0];
    assert!(
        title.starts_with("host-") && title.ends_with(": alert budget reached"),
        "{title}"
    );
    assert_eq!(prio, "3");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "{body}");
    assert!(
        lines[0].starts_with("Withheld: 1 message since ")
            && lines[0].ends_with(&format!("; new incidents: {inst}")),
        "{body}"
    );
    assert!(lines[1].starts_with("Next summary "), "{body}");
    assert!(incident_titles(&fx).is_empty(), "{:?}", fx.titles());
    let claim = stamp(301);
    assert_eq!(
        fx.notice_lines(),
        [notice_text(&claim, "storm", "ok", "light")
            .split('\t')
            .map(str::to_string)
            .collect::<Vec<_>>()]
    );
    assert_eq!(fx.meta("storm_last").as_deref(), Some(claim.as_str()));
    assert_eq!(fx.meta("summary_last"), None);
    let w = fx.w_lines();
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!(w[0][1], stamp(300), "stamped when it was written");
    fx.pass(600);
    fx.pass(900);
    assert_eq!(fx.notices().len(), 1, "{:?}", fx.sent());
}

/// The entry's own case, end to end. After eight listener opens in a day, two of them in the last
/// hour, a new listener's open is withheld for the hour (stage1-cap); while withheld it is named
/// in the title of the storm notice at priority 5, among any number of other withheld lines; and
/// it goes as its late open within the next hour.
#[test]
fn after_eight_listener_opens_in_a_day_a_new_one_is_named_at_priority_five_and_goes_within_the_hour()
 {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "1");
    let keys: Vec<String> = (0..8)
        .map(|i| format!("unit:sensor-a{i}.service"))
        .collect();
    let lines: Vec<(&str, String, &str, &str)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let at = if i < 2 { stamp(0) } else { before(7200) };
            (k.as_str(), at, "stage1", "ok")
        })
        .collect();
    ledger_of(&fx, &lines);
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.pass(0);
    // Twenty-five other transitions withheld between the two passes, of keys no record names.
    let others: Vec<String> = (0..25)
        .map(|i| w_text(&stamp(60), &format!("push:{i}"), "remind", "0", "-", "pool"))
        .collect();
    fx.add_w(&others);
    fx.pass(300);
    let key = "unit:sensor-http.service";
    let rec = fx.record(key).unwrap();
    let inst = rec[5].clone();
    assert_eq!((rec[6].as_str(), rec[7].as_str()), ("PAGE", "open"));
    assert!(
        fx.w_lines()
            .iter()
            .any(|w| w[2] == kh8(key) && w[3] == "open" && w[6] == "stage1-cap"),
        "{:?}",
        fx.w_lines()
    );
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    let (title, prio, body) = &notices[0];
    assert!(
        title.starts_with("host-") && title.ends_with(&format!(": PAGE withheld {inst}")),
        "{title}"
    );
    assert_eq!(prio, "5");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], format!("PAGE withheld: {inst}"), "{body}");
    assert!(
        lines[1].starts_with("Withheld: 26 messages since ")
            && lines[1].ends_with(&format!("; new incidents: {inst}")),
        "{body}"
    );
    let mut t = 600;
    while t <= 4200 && incident_titles(&fx).is_empty() {
        fx.pass(t);
        t += 300;
    }
    let titles = incident_titles(&fx);
    assert_eq!(titles.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert!(titles[0].starts_with("PAGE host-"), "{titles:?}");
}

/// With the storm notice spent for six hours, the summary carries the PAGE rule: a withheld open
/// of a PAGE incident is named in its title at priority 5 and on its first line, whatever else it
/// counts. Its ledger line is of class summary, and summary_last takes its claim while storm_last
/// stays as it was.
#[test]
fn a_summary_names_a_withheld_page_open_at_priority_five_when_the_storm_notice_is_spent() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "1");
    let mut ledger = String::from("#send-ledger v1 g=1\n");
    ledger.push_str(&notice_text(&before(3600), "storm", "ok", "light"));
    ledger.push('\n');
    for (i, k) in ["unit:sensor-a.service", "unit:sensor-b.service"]
        .iter()
        .enumerate()
    {
        let id = format!("w#{}", 300 + i);
        let s = stamp(0);
        ledger.push_str(&inc_line(k, [&s, "stage1", "open", "ok", "light", &id, &s]).join("\t"));
        ledger.push('\n');
    }
    fx.write("var/lib/propolis/witness/send-ledger", &ledger);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\nM\tstorm_last\t{}\n", before(3600)),
    );
    fx.unit(
        "sensor-http.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
        ],
    );
    fx.pass(0);
    // Twelve other transitions withheld between the two passes.
    let others: Vec<String> = (0..12)
        .map(|i| w_text(&stamp(60), &format!("push:{i}"), "change", "0", "-", "pool"))
        .collect();
    fx.add_w(&others);
    fx.pass(300);
    let inst = fx.record("unit:sensor-http.service").unwrap()[5].clone();
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    let (title, prio, body) = &notices[0];
    assert!(
        title.ends_with(&format!(": PAGE withheld {inst}")),
        "{title}"
    );
    assert_eq!(prio, "5");
    assert!(body.starts_with(&format!(
        "PAGE withheld: {inst}\nWithheld: 13 messages since "
    )));
    let claim = stamp(301);
    let classes: Vec<(String, String)> = fx
        .notice_lines()
        .iter()
        .map(|f| (f[2].clone(), f[6].clone()))
        .collect();
    assert_eq!(
        classes,
        [
            ("storm".to_string(), "ok".to_string()),
            ("summary".to_string(), "ok".to_string())
        ]
    );
    assert_eq!(fx.meta("summary_last").as_deref(), Some(claim.as_str()));
    assert_eq!(
        fx.meta("storm_last").as_deref(),
        Some(before(3600).as_str())
    );
}

/// Once the day's twelve summaries are spent (a storm that lasts, or a server that failed them),
/// a summary still goes for a withheld open of a PAGE incident, held only by the hour, and names
/// it at priority 5: the next storm notice could be six hours off. With nothing of PAGE tier
/// withheld the day's cap holds and the lines wait, a withheld new open of an ACT incident among
/// them (the backup's, in both cases).
#[test]
fn a_spent_day_of_summaries_still_names_a_withheld_page_open_within_the_hour() {
    for page in [true, false] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(0);
        let mut ledger = String::from("#send-ledger v1 g=1\n");
        ledger.push_str(&notice_text(&before(3600), "storm", "ok", "light"));
        ledger.push('\n');
        for i in 0..12u64 {
            ledger.push_str(&notice_text(
                &before(3900 + i * 6000),
                "summary",
                "ok",
                "light",
            ));
            ledger.push('\n');
        }
        // The hour's listener messages and the hour's pool are both spent, so a new open of
        // either kind is withheld.
        let spent = [
            ("unit:sensor-a.service", "stage1"),
            ("unit:sensor-b.service", "stage1"),
            ("push:a", "pool"),
            ("push:b", "pool"),
            ("push:c", "pool"),
            ("push:d", "pool"),
        ];
        for (i, (k, class)) in spent.iter().enumerate() {
            let id = format!("w#{}", 300 + i);
            let s = stamp(0);
            ledger.push_str(&inc_line(k, [&s, class, "open", "ok", "light", &id, &s]).join("\t"));
            ledger.push('\n');
        }
        fx.write("var/lib/propolis/witness/send-ledger", &ledger);
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!(
                "#meta v1 g=1\nM\tstorm_last\t{}\nM\tsummary_last\t{}\n",
                before(3600),
                before(3900)
            ),
        );
        failed_backup(&fx);
        if page {
            fx.unit(
                "sensor-http.service",
                &[
                    ("ActiveState", "failed"),
                    ("SubState", "failed"),
                    ("Result", "exit-code"),
                ],
            );
        }
        fx.pass(0);
        let others: Vec<String> = (0..3)
            .map(|i| w_text(&stamp(60), &format!("push:{i}"), "change", "0", "-", "pool"))
            .collect();
        fx.add_w(&others);
        fx.pass(300);
        let backup = kh8("unit:propolis-backup.service");
        assert!(
            fx.w_lines()
                .iter()
                .any(|w| w[2] == backup && w[3] == "open" && w[4] == "1" && w[6] == "pool"),
            "{:?}",
            fx.w_lines()
        );
        let notices = fx.notices();
        if !page {
            assert!(notices.is_empty(), "{:?}\n{}", fx.sent(), fx.log());
            assert_eq!(fx.notice_lines().len(), 13);
            continue;
        }
        let inst = fx.record("unit:sensor-http.service").unwrap()[5].clone();
        assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
        let (title, prio, _) = &notices[0];
        assert!(
            title.ends_with(&format!(": PAGE withheld {inst}")),
            "{title}"
        );
        assert_eq!(prio, "5");
        let lines = fx.notice_lines();
        assert_eq!(lines.len(), 14, "{lines:?}");
        assert_eq!(
            (lines[13][2].as_str(), lines[13][6].as_str()),
            ("summary", "ok")
        );
    }
}

/// A W line the failure hook writes while a notice is being posted (after its claim, before its
/// result; here in the claim's own second) is listed by the next notice: the meta key takes the
/// claim's stamp, and lines are listed from it on.
#[test]
fn a_w_line_the_hook_writes_while_a_notice_is_in_flight_is_in_the_next_notice() {
    let fx = pool_full_shipper();
    fx.pass(0);
    fx.stub_file(
        "curl.post.run",
        "lib=\"$1/root/usr/local/sbin/propolis-alert-lib\"\n\
         . \"$lib\" && pa_init \"$1/root\" && pa_lock 5 && pa_incident_load \\\n\
         && pa_w_line unit:sensor-ftp.service open 1 - stage1-cap && pa_incident_write \\\n\
         && echo wrote > \"$1/hook.wrote\"\npa_unlock\nrm -f \"$1/curl.post.run\"\n",
    );
    fx.pass(300);
    assert_eq!(fx.stub_text("hook.wrote"), "wrote\n", "{}", fx.log());
    let hook = fx
        .w_lines()
        .into_iter()
        .find(|w| w[2] == kh8("unit:sensor-ftp.service"))
        .unwrap();
    assert_eq!(hook[1], stamp(301), "in the claim's second");
    assert_eq!(fx.meta("storm_last").as_deref(), Some(stamp(301).as_str()));
    fx.pass(600);
    let notices = fx.notices();
    assert_eq!(notices.len(), 2, "{:?}\n{}", fx.sent(), fx.log());
    let (title, _, body) = &notices[1];
    assert!(
        title.ends_with(": 1 message withheld in the last hour"),
        "{title}"
    );
    assert!(
        body.starts_with("Withheld: 1 message since ")
            && body.contains("; new incidents: 1 not named"),
        "{body}"
    );
    assert_eq!(
        fx.meta("summary_last").as_deref(),
        Some(stamp(601).as_str())
    );
    fx.pass(900);
    assert_eq!(fx.notices().len(), 2);
}

/// A notice whose post failed, was refused for good or got no answer counts in its class (its line
/// holds the result) and leaves storm_last as it was: the next notice that goes, here the summary,
/// lists the same line again. The journal line names the class and the result alone.
#[test]
fn a_notice_that_failed_was_refused_or_got_no_answer_lists_its_lines_again() {
    for (code, result) in [
        ("503", "transient:503"),
        ("403", "perm:403"),
        ("000", "transient:000"),
    ] {
        let fx = pool_full_shipper();
        fx.pass(0);
        fx.stub_file("curl.post", code);
        fx.pass(300);
        let inst = shipper_inst(&fx);
        let lines = fx.notice_lines();
        assert_eq!(lines.len(), 1, "{code}: {lines:?}");
        assert_eq!(
            (lines[0][2].as_str(), lines[0][6].as_str()),
            ("storm", result)
        );
        assert_eq!(fx.meta("storm_last"), None, "{code}");
        let log = fx.log();
        assert!(
            log.contains(&format!("storm notice not delivered ({result})")),
            "{code}: {log}"
        );
        for l in log
            .lines()
            .filter(|l| l.starts_with("logger ") && l.contains("notice"))
        {
            assert!(!l.contains(&inst) && !l.contains("w#"), "{l}");
            assert!(!l.contains("t0p1c") && !l.contains("ntfy.example"), "{l}");
        }
        std::fs::remove_file(fx.dir.path().join("curl.post")).unwrap();
        fx.pass(600);
        let notices = fx.notices();
        assert_eq!(notices.len(), 2, "{code}: {:?}", fx.sent());
        let (title, _, body) = &notices[1];
        assert!(title.contains(": 1 message withheld"), "{code}: {title}");
        assert!(
            body.starts_with("Withheld: 1 message since ")
                && body.contains(&format!("; new incidents: {inst}")),
            "{code}: {body}"
        );
        assert_eq!(
            fx.meta("summary_last").as_deref(),
            Some(stamp(601).as_str()),
            "{code}"
        );
    }
}

/// A notice that got through but whose result could not be written (the lock held by another
/// writer past the 10 s its result waits) stays claimed and counted, storm_last stays as it was,
/// and the next notice lists its lines again.
#[test]
fn a_notice_whose_result_cannot_be_written_lists_its_lines_again() {
    let fx = pool_full_shipper();
    fx.pass(0);
    fx.stub_file(
        "curl.post.hold",
        &fx.p("var/lib/propolis/witness/state.lock")
            .display()
            .to_string(),
    );
    fx.pass(300);
    let holder: i32 = fx.stub_text("curl.post.holder").trim().parse().unwrap();
    // SAFETY: kill has no memory preconditions; the pid is the stub's own holder.
    unsafe { libc::kill(holder, libc::SIGKILL) };
    std::fs::remove_file(fx.dir.path().join("curl.post.hold")).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let lines = fx.notice_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        (lines[0][2].as_str(), lines[0][6].as_str()),
        ("storm", "sending")
    );
    assert_eq!(fx.meta("storm_last"), None);
    assert!(
        fx.log().contains(
            "the result of the storm notice (ok) was not recorded: the state lock was busy"
        ),
        "{}",
        fx.log()
    );
    fx.pass(600);
    let notices = fx.notices();
    assert_eq!(notices.len(), 2, "{:?}", fx.sent());
    assert!(
        notices[1].2.starts_with("Withheld: 1 message since "),
        "{:?}",
        notices[1]
    );
    assert!(notices[1].2.contains(&shipper_inst(&fx)));
}

/// A pass killed while its notice is posted leaves the notice claimed and counted (its line says
/// sending) and the meta key unchanged. A pass inside the 120 s such a post and its result can
/// take sends no notice of its own for the same lines; a later one lists them again.
#[test]
fn a_pass_killed_during_a_notice_leaves_it_claimed_and_the_next_one_lists_its_lines() {
    let fx = pool_full_shipper();
    fx.pass(0);
    fx.stub_file("curl.post.sleep", "30");
    let mut child = fx.start(&["light"], 300, false);
    let pid_file = fx.dir.path().join("curl.post.pid");
    let mut waited = 0;
    while !pid_file.exists() && waited < 600 {
        std::thread::sleep(Duration::from_millis(50));
        waited += 1;
    }
    assert!(pid_file.exists(), "the post began: {}", fx.log());
    child.kill().unwrap();
    child.wait().unwrap();
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: kill has no memory preconditions; the pid is the stub's own.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    std::fs::remove_file(fx.dir.path().join("curl.post.sleep")).unwrap();
    let lines = fx.notice_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        (
            lines[0][1].as_str(),
            lines[0][2].as_str(),
            lines[0][6].as_str()
        ),
        (stamp(301).as_str(), "storm", "sending")
    );
    assert_eq!(fx.meta("storm_last"), None);
    fx.pass(360);
    assert_eq!(fx.posts().len(), 1, "none inside 120 s of the claim");
    fx.pass(600);
    let notices = fx.notices();
    assert_eq!(notices.len(), 2, "{:?}", fx.sent());
    assert!(
        notices[1].2.contains(&shipper_inst(&fx)),
        "{:?}",
        notices[1]
    );
    assert_eq!(fx.notice_lines()[1][2], "summary");
}

/// Two passes at once cannot both tell the same lines: while the hourly pass, standing in for a
/// light pass that has not run, posts its storm notice, a light pass finds that notice claimed
/// moments ago with no result and sends no summary of its own for the same lines.
#[test]
fn while_one_pass_posts_a_notice_another_pass_sends_none_for_the_same_lines() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.private_topic(0);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    fx.stub_file("curl.post.sleep", "30");
    let mut child = fx.start(&["hourly"], 0, false);
    let pid_file = fx.dir.path().join("curl.post.pid");
    let mut waited = 0;
    while !pid_file.exists() && waited < 1200 {
        std::thread::sleep(Duration::from_millis(50));
        waited += 1;
    }
    assert!(
        pid_file.exists(),
        "the hourly pass's post began: {}",
        fx.log()
    );
    let lines = fx.notice_lines();
    assert_eq!(
        (lines.len(), lines[0][2].as_str(), lines[0][7].as_str()),
        (1, "storm", "hourly")
    );
    fx.pass(30);
    assert_eq!(fx.posts().len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert_eq!(fx.notice_lines().len(), 1);
    child.kill().unwrap();
    child.wait().unwrap();
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: kill has no memory preconditions; the pid is the stub's own.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    std::fs::remove_file(fx.dir.path().join("curl.post.sleep")).unwrap();
}

/// A notice held back by its class's cap leaves its lines for the next one admitted: with a storm
/// notice an hour old and a summary ten minutes old, the withheld open waits, and the first pass
/// at which the summary has room again (an hour after the last) lists it.
#[test]
fn a_notice_held_back_by_its_caps_leaves_its_lines_for_the_next_one_admitted() {
    let fx = pool_full_shipper();
    let mut ledger = String::from("#send-ledger v1 g=1\n");
    for (i, k) in ["push:a", "push:b", "push:c", "push:d"].iter().enumerate() {
        let id = format!("w#{}", 300 + i);
        let s = stamp(0);
        ledger.push_str(&inc_line(k, [&s, "pool", "open", "ok", "light", &id, &s]).join("\t"));
        ledger.push('\n');
    }
    for (s, class) in [(before(3600), "storm"), (before(600), "summary")] {
        ledger.push_str(&notice_text(&s, class, "ok", "light"));
        ledger.push('\n');
    }
    fx.write("var/lib/propolis/witness/send-ledger", &ledger);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\tstorm_last\t{}\nM\tsummary_last\t{}\n",
            before(3600),
            before(600)
        ),
    );
    fx.pass(0);
    fx.pass(300);
    assert!(fx.notices().is_empty(), "{:?}", fx.sent());
    assert_eq!(fx.w_lines().len(), 1);
    let mut t = 600;
    while t <= 3300 && fx.notices().is_empty() {
        fx.pass(t);
        t += 300;
    }
    assert_eq!(t - 300, 3000, "the summary's hour ends at 3000");
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}", fx.sent());
    assert!(
        notices[0]
            .0
            .ends_with(": 1 message withheld in the last hour"),
        "{:?}",
        notices[0]
    );
    assert!(notices[0].2.contains(&shipper_inst(&fx)));
}

/// A notice neither crowds out nor is crowded out by the incident messages: a pass that posts an
/// incident message still sends its notice after it, in a class of its own; a pass with no time
/// left (the send cut passed) claims neither, and a later pass sends both. The daily message,
/// due on the pass that sends them (past 08:41), goes once, as before, after them, and on that
/// pass whatever the send cut says.
#[test]
fn a_pass_that_sent_an_incident_message_still_sends_its_notice_and_one_with_no_time_left_sends_it_later()
 {
    for cut in [false, true] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(2400);
        failed_shipper(&fx);
        fx.pass(2400);
        assert!(fx.posts().is_empty(), "{:?}", fx.sent());
        fx.add_w(&[w_text(&stamp(2690), "push:z", "change", "0", "-", "pool")]);
        if cut {
            fx.setenv("PROPOLIS_WITNESS_SEND_CUT", "0");
        }
        fx.pass(2700);
        if cut {
            assert!(incident_titles(&fx).is_empty(), "{:?}", fx.sent());
            assert!(fx.notices().is_empty());
            assert!(fx.notice_lines().is_empty(), "nothing claimed past the cut");
            assert_eq!(
                fx.daily_lines().len(),
                1,
                "the daily message goes past the cut"
            );
            fx.unsetenv("PROPOLIS_WITNESS_SEND_CUT");
            fx.pass(3000);
        }
        let sent = fx.sent();
        let incident = sent
            .iter()
            .position(|(t, _, b)| t.starts_with("ACT host-") && !is_notice(t, b));
        let notice = sent.iter().position(|(t, _, b)| is_notice(t, b));
        assert!(
            matches!((incident, notice), (Some(i), Some(n)) if i < n),
            "cut {cut}: {sent:?}\n{}",
            fx.log()
        );
        let classes: Vec<String> = fx
            .read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t"))
            .map(|l| l.split('\t').nth(2).unwrap().to_string())
            .collect();
        assert_eq!(
            classes.iter().filter(|c| *c == "pool").count(),
            1,
            "{classes:?}"
        );
        assert_eq!(classes.iter().filter(|c| *c == "storm").count(), 1);
        assert_eq!(fx.daily_lines().len(), 1, "cut {cut}");
        let daily = sent.iter().position(|(t, _, _)| t.ends_with(": daily"));
        if cut {
            assert_eq!(daily, Some(0), "{sent:?}");
        } else {
            assert!(
                matches!((notice, daily), (Some(n), Some(d)) if n < d),
                "{sent:?}"
            );
        }
    }
}

/// In pointer mode (the gate short of full: here no read check has answered) there is neither a
/// storm notice nor a summary: none is rendered, claimed or posted, and no meta key is set. The
/// one post is the pointer message for the open.
#[test]
fn with_the_gate_short_of_full_no_notice_is_rendered_or_claimed_and_the_pointer_is_the_only_post() {
    let mut fx = Fx::new();
    fx.v2();
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    failed_shipper(&fx);
    fx.pass(0);
    fx.pass(300);
    let titles = fx.titles();
    assert_eq!(titles.len(), 1, "{:?}", fx.sent());
    assert!(titles[0].ends_with(": needs attention"), "{titles:?}");
    assert!(fx.notices().is_empty());
    assert!(fx.notice_lines().is_empty());
    assert_eq!(
        (fx.meta("storm_last"), fx.meta("summary_last")),
        (None, None)
    );
}

/// Under the legacy profile the witness reads no W line and sends no notice: with W lines and both
/// meta keys on disk, the daily message is the one post, no notice is claimed, and the meta keys
/// and the W lines are left as they were.
#[test]
fn under_legacy_no_notice_is_claimed_or_sent_and_its_meta_keys_are_left_as_they_were() {
    let fx = Fx::new();
    fx.private_topic(3300);
    let w = w_text(&stamp(3240), "push:a", "open", "1", "-", "pool");
    fx.add_w(std::slice::from_ref(&w));
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\tstorm_last\t{}\nM\tsummary_last\t{}\n",
            before(30000),
            before(9000)
        ),
    );
    failed_shipper(&fx);
    // Past 08:41, so the daily message is the one post.
    fx.pass(3300);
    fx.pass(3600);
    let titles = fx.titles();
    assert_eq!(titles.len(), 1, "{titles:?}");
    assert!(titles[0].ends_with(": daily"));
    assert!(fx.notice_lines().is_empty());
    assert_eq!(fx.meta("storm_last"), Some(before(30000)));
    assert_eq!(fx.meta("summary_last"), Some(before(9000)));
    let lines: Vec<String> = fx.w_lines().iter().map(|f| f.join("\t")).collect();
    assert_eq!(lines, [w]);
}

/// Unknown never counts as good. Meta keys ahead of the clock or out of form are not taken for
/// the last notice: the storm notice lists every W line, an old one and one with an empty field
/// among them. A storm_last in form beside a summary_last ahead of the clock lists from
/// storm_last.
#[test]
fn a_meta_key_out_of_form_or_ahead_of_the_clock_lists_every_w_line() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.add_w(&[
        w_text(&before(30000), "push:a", "remind", "0", "-", "pool"),
        w_text(&before(60), "push:b", "remind", "0", "-", "pool"),
        format!("W\t{}\t{}\tremind\t0\t\tpool", before(60), kh8("push:c")),
    ]);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\tstorm_last\t{}\nM\tsummary_last\tgarbage\n",
            stamp(5000)
        ),
    );
    fx.pass(0);
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert!(
        notices[0].2.starts_with("Withheld: 3 messages since "),
        "{:?}",
        notices[0]
    );

    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.add_w(&[
        w_text(&before(30000), "push:a", "remind", "0", "-", "pool"),
        w_text(&before(60), "push:b", "remind", "0", "-", "pool"),
    ]);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            notice_text(&before(20000), "storm", "ok", "light")
        ),
    );
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=1\nM\tstorm_last\t{}\nM\tsummary_last\t{}\n",
            before(20000),
            stamp(9000)
        ),
    );
    fx.pass(0);
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert!(
        notices[0].2.starts_with("Withheld: 1 message since "),
        "{:?}",
        notices[0]
    );
    assert_eq!(fx.notice_lines()[1][2], "summary");

    // Both keys in form: the notice lists from the later of the two, by uptime within one boot
    // and, across boots, the one of this boot, whatever the wall clock says of the other, be it
    // storm_last or summary_last.
    let other_boot = format!("{}/0badb007/5", WALL - 100);
    for (storm, summary) in [
        (before(20000), before(1000)),
        (other_boot.clone(), before(1000)),
        (before(1000), other_boot.clone()),
    ] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(0);
        fx.add_w(&[
            w_text(&before(2000), "push:a", "remind", "0", "-", "pool"),
            w_text(&before(500), "push:b", "remind", "0", "-", "pool"),
        ]);
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!("#meta v1 g=1\nM\tstorm_last\t{storm}\nM\tsummary_last\t{summary}\n"),
        );
        fx.pass(0);
        let notices = fx.notices();
        assert_eq!(notices.len(), 1, "{storm}: {:?}\n{}", fx.sent(), fx.log());
        assert!(
            notices[0].2.starts_with("Withheld: 1 message since "),
            "{storm}: {:?}",
            notices[0]
        );
    }
}

/// A send ledger no copy of which can be counted holds the notice on that pass, as it holds every
/// message, and never for good: the next pass sends it.
#[test]
fn a_send_ledger_that_cannot_be_counted_holds_the_notice_for_that_pass_only() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v9 g=1\nL\tdamaged\n",
    );
    fx.pass(0);
    assert!(fx.notices().is_empty(), "{:?}", fx.sent());
    fx.pass(300);
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert!(notices[0].2.starts_with("Withheld: 1 message since "));
}

/// The hourly pass sends a notice only while it stands in for a stale light pass, and then with
/// itself as the sender; while the light pass is fresh the light pass is the one that tells.
#[test]
fn the_hourly_pass_sends_a_notice_only_while_it_stands_in_for_a_stale_light_pass() {
    let mut fx = Fx::new();
    fx.v2();
    fx.install_cc();
    fx.cc(&cc_tsv(&[], &[]), 0);
    fx.curl_answers("403|text/plain");
    fx.private_topic(0);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    fx.hourly(0);
    assert!(fx.notices().is_empty(), "{:?}", fx.sent());
    assert!(fx.notice_lines().is_empty());
    fx.hourly_alone(3600);
    let lines = fx.notice_lines();
    assert_eq!(lines.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert_eq!(
        (
            lines[0][2].as_str(),
            lines[0][6].as_str(),
            lines[0][7].as_str()
        ),
        ("storm", "ok", "hourly")
    );
}

/// The witness needs the library version that writes its W lines and closes its notices: one a
/// version older is refused before anything is written, as any older library is, and the one it
/// needs is taken.
#[test]
fn a_library_one_version_older_than_the_witness_needs_is_refused_and_the_one_it_needs_is_taken() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let need: u32 = script
        .lines()
        .find_map(|l| l.strip_prefix("# needs-alert-lib: "))
        .unwrap()
        .parse()
        .unwrap();
    let lib = std::fs::read_to_string(LIB).unwrap();
    let version = lib
        .lines()
        .find_map(|l| l.strip_prefix("PA_LIB_VERSION="))
        .unwrap()
        .to_string();
    assert_eq!(
        version,
        need.to_string(),
        "the witness needs the shipped library"
    );
    for (v, code) in [(need - 1, 3), (need, 0)] {
        let fx = Fx::new();
        fx.write(
            "usr/local/sbin/propolis-alert-lib",
            &lib.replace(
                &format!("\nPA_LIB_VERSION={version}\n"),
                &format!("\nPA_LIB_VERSION={v}\n"),
            ),
        );
        let r = fx.run_args(&["light"], 0);
        assert_eq!(r.code, code, "version {v}: {}", r.err);
        if code == 3 {
            assert!(
                r.err.contains(&format!("older than version {need}")),
                "{}",
                r.err
            );
            assert!(fx.state_files().is_empty());
        }
    }
}

/// A script another writer runs (the curl stub's `curl.post.run`, the logger stub's `logger.run`),
/// its argument the stubs' directory: under the state lock, through the installed library, it adds
/// a W line for KEY (open, new) stamped `later` seconds after the clock the pass has exported, as
/// the failure hook would, marks `hook.wrote`, and then runs EXTRA.
fn hook_w_script(key: &str, later: u64, extra: &str) -> String {
    format!(
        "PA_TEST_WALL=$((PA_TEST_WALL + {later})) PA_TEST_UP=$((PA_TEST_UP + {later}))\n\
         lib=\"$1/root/usr/local/sbin/propolis-alert-lib\"\n\
         . \"$lib\" && pa_init \"$1/root\" && pa_lock 5 && pa_incident_load \\\n\
         && pa_w_line {key} open 1 - stage1-cap && pa_incident_write \\\n\
         && echo wrote > \"$1/hook.wrote\"\npa_unlock\n{extra}\n"
    )
}

/// The stub `logger` that also runs `logger.run` (once, renamed `logger.ran`) when a line says a
/// message was not delivered, as another writer acting between a failed post and what follows it.
const LOGGER_RUN_STUB: &str = r#"#!/usr/bin/env bash
printf 'logger %s\n' "$*" >> "$STUB_LOG"
d="${UNITS%/units}"
if [ -f "$d/logger.run" ] && [[ $* == *"not delivered"* ]]; then
    mv -f "$d/logger.run" "$d/logger.ran"
    bash "$d/logger.ran" "$d" < /dev/null > /dev/null 2>&1
fi
"#;

/// Adds TEXT to the end of the installed library, as a library that differs in one function.
fn lib_append(fx: &Fx, text: &str) {
    let mut lib = fx.read("usr/local/sbin/propolis-alert-lib");
    lib.push('\n');
    lib.push_str(text);
    lib.push('\n');
    fx.write("usr/local/sbin/propolis-alert-lib", &lib);
}

/// The storm_last a notice that got ok keeps is the stamp of its claim, never one taken when its
/// result is written: with the post counting two seconds on the test clock (the seam moves it on
/// over the post as over each claim), a W line the hook writes one second after the claim is
/// listed, once, by the next notice, and storm_last is the claim's stamp.
#[test]
fn a_w_line_written_after_the_claim_and_before_the_result_is_listed_once_by_the_next_notice() {
    let mut fx = pool_full_shipper();
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "2");
    fx.pass(0);
    fx.stub_file(
        "curl.post.run",
        &hook_w_script("unit:sensor-ftp.service", 1, "rm -f \"$1/curl.post.run\""),
    );
    fx.pass(300);
    assert_eq!(fx.stub_text("hook.wrote"), "wrote\n", "{}", fx.log());
    let lines = fx.notice_lines();
    assert_eq!(lines.len(), 1, "{lines:?}\n{}", fx.log());
    let claim = lines[0][1].clone();
    assert_eq!(
        (claim.as_str(), lines[0][2].as_str(), lines[0][6].as_str()),
        (stamp(302).as_str(), "storm", "ok")
    );
    let hook = fx
        .w_lines()
        .into_iter()
        .find(|w| w[2] == kh8("unit:sensor-ftp.service"))
        .unwrap();
    assert_eq!(hook[1], stamp(303), "a second after the claim");
    assert_eq!(fx.meta("storm_last").as_deref(), Some(claim.as_str()));
    fx.pass(600);
    let notices = fx.notices();
    assert_eq!(notices.len(), 2, "{:?}\n{}", fx.sent(), fx.log());
    assert!(
        notices[1].2.starts_with("Withheld: 1 message since ")
            && notices[1].2.contains("; new incidents: 1 not named"),
        "{:?}",
        notices[1]
    );
    fx.pass(900);
    assert_eq!(fx.notices().len(), 2, "{:?}", fx.sent());
}

/// The entry's case for the summary: with the storm notice spent for six hours, a W line the hook
/// writes while the summary is posted (a second after its claim, the result two seconds after)
/// is in the next summary, an hour later, once; summary_last is the summary's claim and storm_last
/// stays as it was.
#[test]
fn a_w_line_the_hook_writes_while_a_summary_is_in_flight_is_in_the_next_summary() {
    let mut fx = pool_full_shipper();
    fx.setenv("PROPOLIS_WITNESS_POST_SECS", "2");
    let mut ledger = String::from("#send-ledger v1 g=1\n");
    for (i, k) in ["push:a", "push:b", "push:c", "push:d"].iter().enumerate() {
        let id = format!("w#{}", 300 + i);
        let s = stamp(0);
        ledger.push_str(&inc_line(k, [&s, "pool", "open", "ok", "light", &id, &s]).join("\t"));
        ledger.push('\n');
    }
    ledger.push_str(&notice_text(&before(3600), "storm", "ok", "light"));
    ledger.push('\n');
    fx.write("var/lib/propolis/witness/send-ledger", &ledger);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=1\nM\tstorm_last\t{}\n", before(3600)),
    );
    fx.pass(0);
    fx.stub_file(
        "curl.post.run",
        &hook_w_script("unit:sensor-ftp.service", 1, "rm -f \"$1/curl.post.run\""),
    );
    fx.pass(300);
    assert_eq!(fx.stub_text("hook.wrote"), "wrote\n", "{}", fx.log());
    let lines = fx.notice_lines();
    assert_eq!(lines.len(), 2, "{lines:?}\n{}", fx.log());
    let claim = lines[1][1].clone();
    assert_eq!(
        (claim.as_str(), lines[1][2].as_str(), lines[1][6].as_str()),
        (stamp(302).as_str(), "summary", "ok")
    );
    let hook = fx
        .w_lines()
        .into_iter()
        .find(|w| w[2] == kh8("unit:sensor-ftp.service"))
        .unwrap();
    assert_eq!(hook[1], stamp(303), "a second after the claim");
    assert_eq!(fx.meta("summary_last").as_deref(), Some(claim.as_str()));
    assert_eq!(
        fx.meta("storm_last").as_deref(),
        Some(before(3600).as_str())
    );
    // The summary's hour from its claim at 302 ends at 3902: the pass at 4200 sends the next one.
    fx.pass(4200);
    let notices = fx.notices();
    assert_eq!(notices.len(), 2, "{:?}\n{}", fx.sent(), fx.log());
    assert!(
        notices[1].2.starts_with("Withheld: 1 message since ")
            && notices[1].2.contains("; new incidents: 1 not named"),
        "{:?}",
        notices[1]
    );
    assert_eq!(fx.notice_lines()[2][2], "summary");
}

/// The notice step reads the records afresh under its own lock: a W line another writer adds
/// after the pass's last incident post wrote its result (here while the pass notes that the post
/// failed) and before the notice is claimed is in that notice, and storm_last, taken from the
/// claim, never passes over it unlisted.
#[test]
fn a_w_line_written_after_the_last_incident_post_and_before_the_notice_claim_is_in_that_notice() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(2400);
    failed_shipper(&fx);
    fx.pass(2400);
    fx.add_w(&[w_text(&stamp(2690), "push:z", "change", "0", "-", "pool")]);
    fx.stub_file("curl.post", "503");
    write_exec(&fx.bin.join("logger"), LOGGER_RUN_STUB);
    // After the incident post failed: the line, and the server answers again.
    fx.stub_file(
        "logger.run",
        &hook_w_script("push:late", 0, "rm -f \"$1/curl.post\""),
    );
    fx.pass(2700);
    assert_eq!(fx.stub_text("hook.wrote"), "wrote\n", "{}", fx.log());
    assert!(
        fx.log().contains("not delivered (transient:503)"),
        "{}",
        fx.log()
    );
    let notices = fx.notices();
    assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
    assert!(
        notices[0].2.starts_with("Withheld: 2 messages since "),
        "{:?}",
        notices[0]
    );
    let lines = fx.notice_lines();
    assert_eq!(lines[0][6], "ok", "{lines:?}");
    assert_eq!(fx.meta("storm_last").as_deref(), Some(lines[0][1].as_str()));
}

/// A storm notice's claim dated ahead of the clock (a later wall time from another boot, or a
/// later uptime in this boot) is not taken as a post in flight: the pass still claims and sends
/// its notice, which errs toward telling.
#[test]
fn a_notice_claim_dated_ahead_of_the_clock_does_not_hold_this_passs_notice() {
    for ahead in [format!("{}/0badb007/5", WALL + 500), stamp(500)] {
        let mut fx = Fx::new();
        fx.v2();
        fx.private_topic(0);
        fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!(
                "#send-ledger v1 g=1\n{}\n",
                notice_text(&ahead, "storm", "sending", "light")
            ),
        );
        fx.pass(0);
        let notices = fx.notices();
        assert_eq!(notices.len(), 1, "{ahead}: {:?}\n{}", fx.sent(), fx.log());
        assert!(notices[0].2.starts_with("Withheld: 1 message since "));
        assert_eq!(fx.notice_lines()[0][1], stamp(0), "{ahead}");
    }
}

/// A notice that cannot be put together (a library whose check refuses every rendered notice) is
/// neither claimed nor posted, with W lines there to tell: nothing is counted for a message that
/// never went, and no summary takes its place.
#[test]
fn a_notice_that_cannot_be_rendered_is_neither_claimed_nor_posted() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    lib_append(
        &fx,
        "_pa_render_check() { PA_TITLE=\"\" PA_PRIO=\"\" PA_BODY=\"\"; return 1; }",
    );
    fx.pass(0);
    assert!(fx.notice_lines().is_empty(), "{}", fx.log());
    assert!(fx.sent().is_empty(), "{:?}", fx.sent());
    assert_eq!(
        (fx.meta("storm_last"), fx.meta("summary_last")),
        (None, None)
    );
}

/// Without curl a notice could not leave the host whatever the server said: none is claimed or
/// counted against its class, no meta key moves and no line says one was not delivered, so the
/// notice is still owed once curl is back.
#[test]
fn without_curl_no_notice_is_claimed_or_counted() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    let dir = path_without_curl(&fx);
    fx.setenv("PATH", &dir.display().to_string());
    fx.pass(0);
    assert!(fx.notice_lines().is_empty(), "{}", fx.log());
    assert_eq!(
        (fx.meta("storm_last"), fx.meta("summary_last")),
        (None, None)
    );
    assert!(!fx.log().contains("notice not delivered"), "{}", fx.log());
    let path = format!("{}:{}", fx.bin.display(), std::env::var("PATH").unwrap());
    fx.setenv("PATH", &path);
    fx.pass(300);
    assert_eq!(fx.notices().len(), 1, "{:?}\n{}", fx.sent(), fx.log());
}

/// A pass whose state was kept nowhere (the incidents file refused in both directories) claims no
/// notice, with W lines in memory to tell: with nothing to remember it by, the next pass would
/// tell the same lines again.
#[test]
fn a_pass_whose_state_was_kept_nowhere_claims_no_notice() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.incidents(&[hook_record(
        "w#1",
        "sensor-ssh.service",
        "ACT",
        "open",
        0,
        "0",
    )]);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    fx.stub_file("disk.refuses", "*/incidents.tmp.*\n");
    fx.pass(300);
    assert_eq!(fx.meta("where").as_deref(), Some("none"), "{}", fx.log());
    assert!(fx.notice_lines().is_empty(), "{}", fx.log());
    assert!(fx.sent().is_empty(), "{:?}", fx.sent());
    assert_eq!(
        (fx.meta("storm_last"), fx.meta("summary_last")),
        (None, None)
    );
}

/// A storm notice whose claim cannot be written to the send ledger (the write refused once, after
/// a read the budget could count) sends nothing on that pass: no summary stands in for a storm
/// notice the ledger could not count. The next pass sends the storm notice.
#[test]
fn a_storm_notice_whose_claim_cannot_be_written_sends_no_summary_in_its_place() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    fx.add_w(&[w_text(&before(60), "push:a", "open", "1", "-", "pool")]);
    lib_append(
        &fx,
        "eval \"_fx_orig_$(declare -f pa_state_write)\"\n\
         pa_state_write() {\n\
         \x20   if [ \"${1:-}\" = send-ledger ] && [ -f \"${UNITS%/units}/ledger.refuse\" ]; then\n\
         \x20       rm -f \"${UNITS%/units}/ledger.refuse\"\n\
         \x20       cat > /dev/null\n\
         \x20       return 1\n\
         \x20   fi\n\
         \x20   _fx_orig_pa_state_write \"$@\"\n\
         }",
    );
    fx.stub_file("ledger.refuse", "");
    fx.pass(0);
    assert!(
        !fx.dir.path().join("ledger.refuse").exists(),
        "the write was refused: {}",
        fx.log()
    );
    assert!(fx.notice_lines().is_empty(), "{}", fx.log());
    assert!(fx.sent().is_empty(), "{:?}", fx.sent());
    fx.pass(300);
    let lines = fx.notice_lines();
    assert_eq!(lines.len(), 1, "{lines:?}\n{}", fx.log());
    assert_eq!(lines[0][2], "storm");
}

/// The host's clock as the library reads it, as (wall seconds, the first 8 hex of the boot id,
/// whole seconds of uptime).
fn host_now() -> (u64, String, u64) {
    let wall = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let boot: String = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .replace('-', "")
        .chars()
        .take(8)
        .collect();
    let up: u64 = std::fs::read_to_string("/proc/uptime")
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    (wall, boot, up)
}

/// On the host's own clock (no test clock), the notice step dates what it reads at its claim and
/// not at the start of the pass: while an hourly pass that stands in for a stale light pass runs
/// config-check, before it takes the lock, another pass claims a storm notice. Sent but with no
/// result yet, that claim holds the hourly pass's notice; with its result ok and storm_last its
/// claim, the hourly pass sends a summary of the lines from that key on alone.
#[test]
fn a_notice_another_pass_claims_while_the_hourly_pass_runs_is_read_on_the_clock_of_the_claim() {
    for result in ["sending", "ok"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.unsetenv("PROPOLIS_WITNESS_NOW");
        fx.install_cc();
        fx.cc(&cc_tsv(&[], &[]), 0);
        fx.curl_answers("403|text/plain");
        let (wall, boot, up) = host_now();
        assert!(boot.len() == 8 && up > 0, "{boot} {up}");
        // Stamps of another boot, by the wall clock: the light pass's last 1000 s ago (stale
        // past 900 s, not yet witness-stale at 1200 s), the last summary two hours ago, a daily
        // message a minute ago (so none is due on this pass) and a withheld line ten minutes ago.
        let other = |back: u64| format!("{}/0badb007/5", wall - back);
        fx.write(
            "var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=1\nR\t{FX_BINDING}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n",
                s = other(60)
            ),
        );
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!(
                "#meta v1 g=1\nM\tlight_last\t{}\nM\tsummary_last\t{}\n",
                other(1000),
                other(7200)
            ),
        );
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!(
                "#send-ledger v1 g=1\nL\t{}\tdaily\t-\tdaily\tfull\tok\tlight\n",
                other(60)
            ),
        );
        fx.add_w(&[w_text(&other(600), "push:a", "open", "1", "-", "pool")]);
        let root = fx.root.display().to_string();
        let keep = if result == "ok" {
            "pa_meta_put storm_last \"$PA_LEDGER_STAMP\" && pa_incident_load \\\n\
             && pa_w_line push:b change 0 - pool && pa_incident_write \\\n&& "
        } else {
            ""
        };
        fx.cc_during(&format!(
            "sleep 2\n. \"{root}/usr/local/sbin/propolis-alert-lib\" && pa_init \"{root}\" \\\n\
             && pa_lock 10 && pa_ledger_add storm - storm full {result} light \\\n\
             && {keep}echo \"$PA_LEDGER_STAMP\" > \"{d}/cc.claimed\"\npa_unlock\n",
            d = fx.dir.path().display()
        ));
        fx.hourly_alone(0);
        let claimed = fx.stub_text("cc.claimed").trim().to_string();
        assert!(
            claimed.contains(&format!("/{boot}/")),
            "{result}: {claimed}\n{}",
            fx.log()
        );
        let lines = fx.notice_lines();
        assert_eq!(lines[0][1], claimed, "{result}: {lines:?}");
        let notices = fx.notices();
        if result == "sending" {
            assert!(notices.is_empty(), "{:?}\n{}", fx.sent(), fx.log());
            assert_eq!(lines.len(), 1, "{lines:?}");
        } else {
            assert_eq!(notices.len(), 1, "{:?}\n{}", fx.sent(), fx.log());
            assert!(
                notices[0].2.starts_with("Withheld: 1 message since "),
                "{:?}",
                notices[0]
            );
            assert_eq!(
                (lines.len(), lines[1][2].as_str(), lines[1][7].as_str()),
                (2, "summary", "hourly"),
                "{lines:?}"
            );
        }
    }
}

// ---- the pointer message --------------------------------------------------------------------

/// An open record of incident `w#<n>` at TIER on a key no pass judges (a finding of a test
/// kind), opened at stamp OPENED, its ref REF (`-` for none).
fn ptr_rec(n: usize, tier: &str, opened: &str, reference: &str) -> String {
    let r = hook_record_at(&format!("w#{n}"), "x", tier, "open", opened, "-")
        .replace("unit:x", &format!("finding:test:{n:012}"));
    with_field(&with_field(&r, 33, "-"), 28, reference)
}

/// The ref the pointer message posted at place AT carries.
fn posted_ref(fx: &Fx, at: usize) -> String {
    let body = fx.posts()[at].clone();
    body.trim_end()
        .rsplit(" ref ")
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Nothing but an open PAGE or ACT incident not yet told for its present occurrence makes a
/// pointer due: a told record whose reminder comes due, an acknowledged, a pending, a resolved, a
/// NOTICE, a folded and a duplicate record send nothing. An untold open then sends one.
#[test]
fn nothing_but_an_open_page_or_act_incident_not_yet_told_sends_a_pointer() {
    let mut fx = Fx::new();
    fx.v2();
    let t = before(600);
    let records = [
        with_field(&ptr_rec(1, "PAGE", &t, "0a1b2c"), 19, &before(60)),
        with_field(&ptr_rec(2, "PAGE", &t, "-"), 7, "acked"),
        with_field(&ptr_rec(3, "PAGE", &t, "-"), 7, "pending"),
        with_field(
            &with_field(
                &with_field(&ptr_rec(4, "ACT", &t, "-"), 7, "resolved"),
                21,
                &before(300),
            ),
            22,
            "active10",
        ),
        ptr_rec(5, "NOTICE", &t, "-"),
        with_field(
            &with_field(&ptr_rec(6, "PAGE", &t, "-"), 13, "w#1"),
            30,
            "folded",
        ),
        with_field(&ptr_rec(7, "PAGE", &t, "-"), 30, "dup"),
    ];
    fx.incidents(&records);
    fx.pass(0);
    assert!(fx.posts().is_empty(), "{:?}\n{}", fx.sent(), fx.log());
    assert!(fx.pointer_lines().is_empty());
    let r1 = fx.record("finding:test:000000000001").unwrap();
    assert_eq!(
        (r1[16].as_str(), r1[18].as_str()),
        ("remind", "1"),
        "the reminder was made"
    );
    let mut text = fx.read("var/lib/propolis/witness/incidents");
    text.push_str(&ptr_rec(8, "ACT", &stamp(100), "-"));
    fx.write("var/lib/propolis/witness/incidents", &text);
    fx.pass(300);
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].ends_with(": needs attention"));
    let r8 = fx.record("finding:test:000000000008").unwrap();
    assert_eq!(r8[28], posted_ref(&fx, 0));
    for n in 2..=7 {
        let r = fx.record(&format!("finding:test:{n:012}")).unwrap();
        assert_eq!(r[28], "-", "w#{n}");
    }
}

/// The pointer counts only against its own class: with the listener allowance and the pool spent
/// by ten cheap sensors that reopened (each told already), a new `danger` finding is still told
/// by a pointer, which adds nothing to the incident classes' lines.
#[test]
fn ten_reopening_cheap_sensors_leave_the_pointer_for_a_new_danger_finding() {
    let mut fx = Fx::new();
    fx.v2();
    let mut lines = String::new();
    let mut records = Vec::new();
    for n in 1..=10 {
        let key = format!("unit:sensor-n{n}.service");
        let rec = with_field(
            &with_field(
                &ptr_rec(n, "PAGE", &before(600), &format!("00000{n:x}")),
                2,
                &key,
            ),
            23,
            "1",
        );
        records.push(rec);
        for i in 0..2 {
            lines.push_str(&format!(
                "L\t{}\tstage1\t{}\treopen\tfull\tok\tlight\tw#{n}\t{}\n",
                before(3000 - 100 * i),
                kh8(&key),
                before(3000 - 100 * i)
            ));
        }
    }
    for i in 0..16 {
        lines.push_str(&format!(
            "L\t{s}\tpool\t00000000\topen\tfull\tok\tlight\tw#99\t{s}\n",
            s = before(2000 + i)
        ));
    }
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\n{lines}"),
    );
    let danger = format!("finding:danger:{}", k12("danger:scope-a"));
    let d = with_field(
        &with_field(
            &with_field(&ptr_rec(20, "PAGE", &before(60), "-"), 2, &danger),
            3,
            "finding",
        ),
        4,
        "listen",
    );
    records.push(d);
    fx.incidents(&records);
    let before_lines = fx.incident_lines();
    fx.pass(0);
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].ends_with(": needs attention"));
    assert_eq!(fx.record(&danger).unwrap()[28], posted_ref(&fx, 0));
    for n in 1..=10 {
        let r = fx.record(&format!("unit:sensor-n{n}.service")).unwrap();
        assert_eq!(r[28], format!("00000{n:x}"), "w#{n}");
    }
    assert_eq!(
        fx.incident_lines(),
        before_lines,
        "nothing taken from the incident classes"
    );
}

/// A server that fails every post gets one pointer attempt in 30 minutes and two an hour, the
/// claim counting whatever became of it: one that answers 503, one that refuses (403) and one
/// that never answers. The incident stays due throughout.
#[test]
fn a_server_that_fails_every_pointer_gets_one_attempt_in_thirty_minutes() {
    for code in ["503", "403", "000"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.incidents(&[ptr_rec(1, "ACT", &before(600), "-")]);
        fx.stub_file("curl.post", code);
        for t in (0..=7200).step_by(300) {
            fx.pass(t);
        }
        let at: Vec<String> = fx
            .pointer_lines()
            .iter()
            .map(|l| l.split('\t').nth(1).unwrap().to_string())
            .collect();
        let want: Vec<String> = [0, 1800, 3600, 5400, 7200]
            .iter()
            .map(|t| stamp(*t))
            .collect();
        assert_eq!(at, want, "{code}: {}", fx.log());
        assert_eq!(fx.posts().len(), 5, "{code}");
        assert_eq!(
            fx.record("finding:test:000000000001").unwrap()[28],
            "-",
            "{code}"
        );
    }
}

/// Two senders at once claim one pointer between them: a hook firing that claims while the light
/// pass's pointer is in flight is held by that claim, and so is a light pass that runs while an
/// hourly pass standing in for it posts its own.
#[test]
fn two_senders_at_once_claim_one_pointer_between_them() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.stub_file(
        "curl.post.run",
        "lib=\"$1/root/usr/local/sbin/propolis-alert-lib\"\n\
         . \"$lib\" && pa_init \"$1/root\" && pa_lock 5 && pa_now && pa_incident_load \\\n\
         && { pa_pointer_claim hook; echo \"$PA_PTR\" > \"$1/hook.ptr\"; }\npa_unlock\n",
    );
    fx.pass(0);
    assert_eq!(
        fx.stub_text("hook.ptr").trim(),
        "withhold:pointer-cap",
        "{}",
        fx.log()
    );
    assert_eq!(fx.posts().len(), 1);
    assert_eq!(fx.pointer_lines(), [ptr_line(&stamp(0), "ok", "light")]);

    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.stub_file(
        "curl.post.run",
        &format!(
            "mv -f \"$1/curl.post.run\" \"$1/curl.post.ran\"\nbash {SCRIPT} light > \"$1/light.out\" 2>&1\n\
             echo \"$?\" > \"$1/light.rc\"\n"
        ),
    );
    fx.hourly_alone(0);
    assert_eq!(
        fx.stub_text("light.rc").trim(),
        "0",
        "{}",
        fx.stub_text("light.out")
    );
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(fx.pointer_lines(), [ptr_line(&stamp(0), "ok", "hourly")]);
}

/// The alert path reads pointers under v2: one the server refused for good opens alert-path with
/// the cause of the refusal, and a pointer that then gets ok after the open is the proof that
/// resolves it.
#[test]
fn a_pointer_refused_for_good_opens_alert_path_and_one_that_gets_ok_resolves_it() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.stub_file("curl.post", "403");
    fx.pass(0);
    assert_eq!(
        fx.pointer_lines(),
        [ptr_line(&stamp(0), "perm:403", "light")]
    );
    fx.pass(300);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str(), a[28].as_str()),
        ("open", "http.auth:403", "-")
    );
    assert_eq!(fx.posts().len(), 1, "the half hour holds the next attempt");
    fx.stub_file("curl.post", "200");
    fx.pass(1800);
    assert_eq!(fx.posts().len(), 2, "{}", fx.log());
    let reference = posted_ref(&fx, 1);
    assert_eq!(fx.record("alert:shell").unwrap()[28], reference);
    fx.pass(2100);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!((a[7].as_str(), a[22].as_str()), ("resolved", "sent2xx"));
}

/// A pointer that got a transient answer opens alert-path once it is over 15 minutes old, with
/// the cause of that answer; the latest pointer line not dated ahead of the clock is the one read,
/// a claim still unanswered reads unknown, and a later ok or an hour's age opens
/// nothing.
#[test]
fn a_pointer_without_an_answer_opens_alert_path_after_fifteen_minutes() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.stub_file("curl.post", "503");
    fx.pass(0);
    fx.pass(900);
    assert!(
        fx.record("alert:shell").is_none(),
        "15 minutes not yet over"
    );
    fx.pass(1200);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!((a[7].as_str(), a[11].as_str()), ("open", "http.server:503"));

    for (lines, want) in [
        (
            vec![ptr_line(&before(1000), "sending", "light")],
            Some("unknown"),
        ),
        (
            vec![
                ptr_line(&before(1000), "transient:000", "light"),
                ptr_line(&stamp(600), "ok", "hook"),
            ],
            Some("net.connect"),
        ),
        (
            vec![
                ptr_line(&before(2000), "transient:503", "light"),
                ptr_line(&before(1000), "ok", "hook"),
            ],
            None,
        ),
        (
            vec![ptr_line(&before(3700), "transient:503", "light")],
            None,
        ),
        (vec![ptr_line(&before(800), "transient:503", "light")], None),
    ] {
        let mut fx = Fx::new();
        fx.v2();
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &format!("#send-ledger v1 g=1\n{}\n", lines.join("\n")),
        );
        fx.pass(0);
        let got = fx.record("alert:shell").map(|a| a[11].clone());
        assert_eq!(got.as_deref(), want, "{lines:?}");
    }
}

/// Under the legacy profile pointer lines are not read and no pointer is claimed or sent: a
/// refused and an unanswered pointer open nothing, an untold open PAGE incident sends nothing, and
/// no ref and no pointer_last is written.
#[test]
fn under_legacy_no_pointer_is_read_claimed_or_written() {
    let fx = Fx::new();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    let lines = [
        ptr_line(&before(2000), "perm:403", "light"),
        ptr_line(&before(1000), "transient:503", "hook"),
    ];
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!("#send-ledger v1 g=1\n{}\n", lines.join("\n")),
    );
    fx.pass(0);
    fx.pass(1800);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    assert!(fx.record("alert:shell").is_none());
    assert_eq!(fx.pointer_lines(), lines);
    assert_eq!(fx.record("finding:test:000000000001").unwrap()[28], "-");
    assert_eq!(fx.meta("pointer_last"), None);
}

/// PROPOLIS_OPS_PUSH_DETAIL=pointer on a topic proven private is a gate short of full like any
/// other: the pointer is the one post and no incident message is admitted. Without it the gate
/// is full and there is no pointer step: the open goes in full and no pointer line is written.
#[test]
fn detail_pointer_on_a_private_topic_sends_the_pointer_and_a_full_gate_sends_none() {
    for detail in [true, false] {
        let mut fx = Fx::new();
        fx.v2();
        if detail {
            fx.write(
                "etc/propolis/propolis.env",
                &push_env("PROPOLIS_OPS_PUSH_DETAIL=pointer\n"),
            );
        }
        fx.private_topic(0);
        failed_shipper(&fx);
        fx.pass(0);
        fx.pass(300);
        let titles = fx.titles();
        assert_eq!(titles.len(), 1, "{detail}: {titles:?}\n{}", fx.log());
        if detail {
            assert!(titles[0].ends_with(": needs attention"), "{titles:?}");
            assert!(fx.incident_lines().is_empty());
            assert_eq!(fx.pointer_lines().len(), 1);
        } else {
            assert!(titles[0].starts_with("ACT host-"), "{titles:?}");
            assert_eq!(fx.incident_lines().len(), 1);
            assert!(fx.pointer_lines().is_empty());
        }
    }
}

/// Unknown never counts as good: a send ledger no copy of which can be read sends no pointer on
/// that pass, and the next pass, which counts from the empty ledger the first left, sends it; a
/// pointer line dated ahead of the clock holds no attempt back.
#[test]
fn a_ledger_that_cannot_be_counted_holds_one_pass_and_a_line_ahead_of_the_clock_holds_none() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    fx.pass(0);
    assert!(fx.posts().is_empty(), "{}", fx.log());
    fx.pass(300);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());

    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            ptr_line(&stamp(600), "sending", "hook")
        ),
    );
    fx.pass(0);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
}

/// A first sighting whose stored line was not whole (an empty field, here the last) that this
/// pass opens is stored whole again, with every field after the empty one a place early as the
/// reader took them. What is left still reads as an open incident that counts and is not yet
/// told, so it is due like any other: one pointer tells of it, its ok marks it, and the next
/// passes send nothing more. One damaged line does not make a pointer due on every pass.
#[test]
fn a_damaged_record_whose_rewritten_line_is_due_is_told_by_one_pointer() {
    let mut fx = Fx::new();
    fx.v2();
    fx.unit(
        "propolis-backup.service",
        &[
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Restart", "no"),
            ("UnitFileState", "static"),
        ],
    );
    let rec = hook_record("w#7", "propolis-backup.service", "ACT", "pending", 0, "-");
    fx.incidents(&[with_field(&rec, 30, "")]);
    fx.pass(300);
    let rec = fx.record("unit:propolis-backup.service").unwrap();
    assert_eq!(rec[7], "open", "{rec:?}\n{}", fx.log());
    assert!(
        rec.iter().all(|f| !f.is_empty()),
        "written back whole: {rec:?}"
    );
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert_eq!(rec[28], posted_ref(&fx, 0));
    fx.pass(600);
    fx.pass(2400);
    fx.pass(4200);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
}

/// A record whose stored line was not whole in a field before the parent field (here field 10)
/// is stored whole again by the pass that opens it (alert-path, on an incident message a server
/// refused for good), but what is left no longer reads as a record that counts: every later field
/// moved a place early, so the parent field holds what was the next one. That is the limit the
/// health page states: nothing is told of it under either detail level, so no pointer is claimed
/// or posted and nothing is marked; the walk shows the record.
#[test]
fn an_open_of_a_damaged_record_that_no_longer_counts_sends_no_pointer_and_marks_nothing() {
    let mut fx = Fx::new();
    fx.v2();
    let rec = hook_record_at(
        "w#1",
        "propolis.service",
        "PAGE",
        "pending",
        &before(600),
        "-",
    );
    let rec = with_field(
        &with_field(&with_field(&rec, 2, "alert:shell"), 3, "alert-path"),
        4,
        "alert",
    );
    fx.incidents(&[with_field(&rec, 10, "")]);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(
                "unit:sensor-ssh.service",
                [
                    &before(200),
                    "pool",
                    "open",
                    "perm:403",
                    "hook",
                    "w#9",
                    &before(100)
                ]
            )
            .join("\t")
        ),
    );
    fx.pass(0);
    let rec = fx.record("alert:shell").unwrap();
    assert_eq!(
        (rec[7].as_str(), rec[11].as_str()),
        ("open", "http.auth:403"),
        "{rec:?}\n{}",
        fx.log()
    );
    assert!(
        rec.iter().all(|f| !f.is_empty()),
        "written back whole: {rec:?}"
    );
    assert_ne!(rec[13], "-", "it no longer counts: {rec:?}");
    assert!(fx.posts().is_empty(), "{:?}\n{}", fx.sent(), fx.log());
    assert!(fx.pointer_lines().is_empty(), "{}", fx.log());
    assert!(
        !(rec[28].len() == 6 && rec[28].bytes().all(|b| b.is_ascii_hexdigit())),
        "nothing marked: {rec:?}"
    );
    fx.pass(2400);
    assert!(fx.posts().is_empty(), "{:?}", fx.sent());
}

/// A change makes a record due only when it raises one that never counted to ACT or PAGE: an open
/// NOTICE incident, never told, sends nothing, and once a reading raises it to PAGE (alert-path,
/// on an incident message a server refused for good) it is told by one pointer, which writes its
/// ref into the record.
#[test]
fn an_open_notice_record_that_rises_to_page_is_told_by_one_pointer() {
    let mut fx = Fx::new();
    fx.v2();
    let rec = hook_record_at(
        "w#1",
        "propolis.service",
        "NOTICE",
        "open",
        &before(600),
        "-",
    );
    let rec = with_field(
        &with_field(&with_field(&rec, 2, "alert:shell"), 3, "alert-path"),
        4,
        "alert",
    );
    fx.incidents(&[with_field(&with_field(&rec, 33, "-"), 28, "-")]);
    fx.pass(0);
    assert!(
        fx.posts().is_empty(),
        "a NOTICE is not due: {:?}",
        fx.sent()
    );
    assert_eq!(fx.record("alert:shell").unwrap()[6], "NOTICE");
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(
                "unit:sensor-ssh.service",
                [
                    &stamp(100),
                    "pool",
                    "open",
                    "perm:403",
                    "hook",
                    "w#9",
                    &stamp(200)
                ]
            )
            .join("\t")
        ),
    );
    fx.pass(300);
    let rec = fx.record("alert:shell").unwrap();
    assert_eq!(rec[6], "PAGE", "the tier rose: {rec:?}\n{}", fx.log());
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].ends_with(": needs attention"));
    assert_eq!(rec[28], posted_ref(&fx, 0));
    assert_eq!(fx.pointer_lines(), [ptr_line(&stamp(300), "ok", "light")]);
}

/// The pass that sends for the host is the one pointer sender among the witness's passes: an
/// hourly pass while the light pass is fresh posts nothing and writes no pointer line, with an
/// open PAGE incident not yet told.
#[test]
fn an_hourly_pass_while_the_light_pass_is_fresh_sends_no_pointer() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.hourly(0);
    assert!(fx.posts().is_empty(), "{:?}\n{}", fx.sent(), fx.log());
    assert!(fx.pointer_lines().is_empty());
    assert_eq!(fx.record("finding:test:000000000001").unwrap()[28], "-");
}

/// A pass whose state was kept nowhere (the incidents file refused in both directories) claims no
/// pointer, though a due record is on disk: its ok could mark nothing, and the next pass would
/// point at the same record again.
#[test]
fn a_pass_whose_state_was_kept_nowhere_claims_no_pointer() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.stub_file("disk.refuses", "*/incidents.tmp.*\n");
    fx.pass(300);
    assert_eq!(fx.meta("where").as_deref(), Some("none"), "{}", fx.log());
    assert!(fx.pointer_lines().is_empty(), "{}", fx.log());
    assert!(fx.posts().is_empty(), "{:?}", fx.sent());
}

/// Without curl a pointer could not leave the host: none is claimed or counted against its class
/// and no line says one was not delivered, so the next pass with curl back sends it.
#[test]
fn without_curl_no_pointer_is_claimed_or_counted() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    let dir = path_without_curl(&fx);
    fx.setenv("PATH", &dir.display().to_string());
    fx.pass(0);
    assert!(fx.pointer_lines().is_empty(), "{}", fx.log());
    assert!(
        !fx.log().contains("pointer message not delivered"),
        "{}",
        fx.log()
    );
    let path = format!("{}:{}", fx.bin.display(), std::env::var("PATH").unwrap());
    fx.setenv("PATH", &path);
    fx.pass(300);
    assert_eq!(fx.posts().len(), 1, "{}", fx.log());
    assert_eq!(fx.pointer_lines(), [ptr_line(&stamp(300), "ok", "light")]);
}

/// A shell line, appended to the installed library, that runs the script `name` beside the units
/// once (it removes itself) at the end of the pass's first pa_settings_load: the start of the
/// pass's unlocked part, after its start stamp.
fn during_settings(fx: &Fx, name: &str, script: &str) {
    lib_append(
        fx,
        &format!(
            "eval \"_fx_orig_$(declare -f pa_settings_load)\"\n\
             pa_settings_load() {{\n\
             \x20   local _fx_rc=0\n\
             \x20   _fx_orig_pa_settings_load \"$@\" || _fx_rc=$?\n\
             \x20   if [ -f \"${{UNITS%/units}}/{name}\" ]; then\n\
             \x20       mv -f \"${{UNITS%/units}}/{name}\" \"${{UNITS%/units}}/{name}.ran\"\n\
             \x20       bash \"${{UNITS%/units}}/{name}.ran\" \"${{UNITS%/units}}\" < /dev/null\n\
             \x20   fi\n\
             \x20   return \"$_fx_rc\"\n\
             }}"
        ),
    );
    fx.stub_file(name, script);
}

/// No pointer is claimed once the pass is past its send cut: with the cut at 0 the pass claims and
/// posts none, and with a cut of 2 s that the pass's own unlocked part outlasts (it sleeps 3 s)
/// none either; the next pass, with the usual cut, sends it.
#[test]
fn no_pointer_is_claimed_past_the_send_cut_and_the_next_pass_sends_it() {
    for cut in ["0", "2"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
        fx.setenv("PROPOLIS_WITNESS_SEND_CUT", cut);
        if cut == "2" {
            during_settings(&fx, "slow.run", "sleep 3\n");
        }
        fx.pass(0);
        assert!(fx.pointer_lines().is_empty(), "{cut}: {}", fx.log());
        assert!(fx.posts().is_empty(), "{cut}");
        if cut == "2" {
            assert!(fx.dir.path().join("slow.run.ran").exists(), "the sleep ran");
        }
        fx.unsetenv("PROPOLIS_WITNESS_SEND_CUT");
        fx.pass(300);
        assert_eq!(fx.posts().len(), 1, "{cut}: {}", fx.log());
        assert_eq!(fx.pointer_lines(), [ptr_line(&stamp(300), "ok", "light")]);
    }
}

/// On the host's own clock (no test clock), the pointer step dates what it reads at its claim and
/// not at the start of the pass: a hook pointer claimed (sending) after the light pass began and
/// before its pointer step, while the pass is in its unlocked part, holds the pass's own pointer
/// by the half hour, so the two claim one between them.
#[test]
fn a_pointer_the_hook_claims_while_the_light_pass_runs_is_read_on_the_clock_of_the_claim() {
    let mut fx = Fx::new();
    fx.v2();
    fx.unsetenv("PROPOLIS_WITNESS_NOW");
    let (_, boot, up) = host_now();
    assert!(boot.len() == 8 && up > 0, "{boot} {up}");
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    let root = fx.root.display().to_string();
    during_settings(
        &fx,
        "hook.run",
        &format!(
            "sleep 2\n. \"{root}/usr/local/sbin/propolis-alert-lib\" && pa_init \"{root}\" \\\n\
             && pa_lock 10 && pa_ledger_add pointer - pointer pointer sending hook \\\n\
             && echo \"$PA_LEDGER_STAMP\" > \"$1/hook.claimed\"\npa_unlock\n"
        ),
    );
    fx.pass(0);
    let claimed = fx.stub_text("hook.claimed").trim().to_string();
    assert!(
        claimed.contains(&format!("/{boot}/")),
        "{claimed}\n{}",
        fx.log()
    );
    assert!(fx.posts().is_empty(), "{:?}\n{}", fx.sent(), fx.log());
    assert_eq!(fx.pointer_lines(), [ptr_line(&claimed, "sending", "hook")]);
    assert_eq!(fx.record("finding:test:000000000001").unwrap()[28], "-");
}

/// The journal lines of a pointer whose result could not be recorded: a state lock held past the
/// close's 10 s wait (`was not recorded: the state lock was busy`, the line left claimed), and a
/// claimed line gone by the close (`was not recorded in full`, the records still marked, since
/// the message arrived). Neither names the ref, the target, the topic or an id.
#[test]
fn a_pointer_result_that_could_not_be_recorded_is_journalled_without_the_ref_or_the_target() {
    for case in ["busy", "gone"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
        let script = if case == "busy" {
            "l=\"$1/root/var/lib/propolis/witness/state.lock\"\n\
             bash -c 'exec 9< \"$1\"; flock 9; : > \"$2\"; exec sleep 15' _ \"$l\" \"$1/held\" \
             < /dev/null > /dev/null 2>&1 &\n\
             n=0; while [ ! -e \"$1/held\" ] && [ \"$n\" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done\n"
        } else {
            "printf '#send-ledger v1 g=1\\n' > \"$1/root/var/lib/propolis/witness/send-ledger\"\n"
        };
        fx.stub_file("curl.post.run", script);
        fx.pass(0);
        let log = fx.log();
        let want = if case == "busy" {
            "the result of the pointer message (ok) was not recorded: the state lock was busy"
        } else {
            "the result of the pointer message (ok) was not recorded in full"
        };
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.starts_with("logger ") && l.contains("pointer message"))
            .collect();
        assert_eq!(lines.len(), 1, "{case}: {log}");
        assert!(lines[0].contains(want), "{case}: {lines:?}");
        assert_eq!(fx.posts().len(), 1, "{case}");
        let reference = posted_ref(&fx, 0);
        for word in [
            reference.as_str(),
            "t0p1c",
            "ntfy.example",
            "w#1",
            "finding:test",
        ] {
            assert!(!lines[0].contains(word), "{case} {word}: {lines:?}");
        }
        let rec = fx.record("finding:test:000000000001").unwrap();
        if case == "busy" {
            assert_eq!(rec[28], "-", "nothing marked without the lock");
            assert_eq!(
                fx.pointer_lines(),
                [ptr_line(&stamp(0), "sending", "light")]
            );
        } else {
            assert_eq!(rec[28], reference, "marked: the message arrived");
            assert!(fx.pointer_lines().is_empty());
        }
    }
}

/// Pointer messages go to the configured URL even when it is plain http (the gate pointer:insecure
/// sends the pointer as today's failure hook posts there), and then carry the access token in
/// clear, as today's hook does. The record is told by it.
#[test]
fn with_a_plain_http_url_the_pointer_goes_to_that_url_with_the_token() {
    let mut fx = Fx::new();
    fx.v2();
    fx.write(
        "etc/propolis/propolis.env",
        "PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n\
         PROPOLIS_OPS_NTFY_TOKEN=tk_s3cret-value\n",
    );
    // A fresh read check of this http target that found every anonymous read refused: the one
    // rule left that holds the gate short of full is the plain http URL.
    let binding = "e9960faaf48b78f0";
    assert!(binding.starts_with(&k12("http://ntfy.example.invalid\nt0p1c-secret\n")));
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=1\nR\t{binding}\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n",
            s = stamp(0)
        ),
    );
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    fx.pass(0);
    assert_eq!(fx.titles().len(), 1, "{}", fx.log());
    assert!(fx.titles()[0].ends_with(": needs attention"));
    let conf = fx.stub_text("curl.post.conf");
    assert!(
        conf.contains("url = \"http://ntfy.example.invalid/t0p1c-secret\"\n"),
        "{conf}"
    );
    assert!(
        conf.contains("header = \"Authorization: Bearer tk_s3cret-value\"\n"),
        "{conf}"
    );
    assert_eq!(
        fx.record("finding:test:000000000001").unwrap()[28],
        posted_ref(&fx, 0)
    );
}

/// A server's refusal for good opens alert-path once: the record's cause_since takes the stamp of
/// the refused line when that is later than its own, so a pointer the hook claimed and had refused
/// after the pass began (stamped five seconds after the pass's own clock, as a hook claims under
/// its lock while the pass is in its unlocked probes) is not found again on every later pass. A
/// later refusal is still a new fact and moves cause_since; once a message got through (a hook
/// pointer that got ok) alert-path resolves sent2xx and the heartbeat URL is asked again; and a
/// refusal after the resolve opens it again.
#[test]
fn a_pointer_refused_after_the_pass_began_opens_alert_path_once_and_a_later_ok_resolves_it() {
    let mut fx = Fx::new();
    fx.v2();
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/abc\n",
    );
    fx.curl_answers("200|text/plain");
    fx.incidents(&[ptr_rec(1, "PAGE", &before(600), "-")]);
    let mut ledger = vec![ptr_line(&stamp(5), "perm:403", "hook")];
    let write = |fx: &Fx, lines: &[String]| {
        let body: String = fx
            .read("var/lib/propolis/witness/send-ledger")
            .lines()
            .filter(|l| l.starts_with("L\t"))
            .map(|l| format!("{l}\n"))
            .collect();
        let mut text = format!("#send-ledger v1 g=1\n{body}");
        for l in lines {
            text.push_str(l);
            text.push('\n');
        }
        fx.write("var/lib/propolis/witness/send-ledger", &text);
    };
    write(&fx, &ledger);
    fx.pass(0);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str(), a[12].as_str()),
        ("open", "http.auth:403", stamp(5).as_str()),
        "{}",
        fx.log()
    );
    let occ = a[31].clone();
    fx.pass(300);
    fx.pass(600);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[12].as_str(), a[31].as_str()),
        ("open", stamp(5).as_str(), occ.as_str()),
        "one refusal is one fact"
    );
    // A second refusal, of a pointer the hook posted later, is a new fact.
    ledger = vec![ptr_line(&stamp(700), "perm:403", "hook")];
    write(&fx, &ledger);
    fx.pass(900);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[12].as_str()),
        ("open", stamp(700).as_str())
    );
    assert_ne!(a[31], occ, "counted as a new sighting");
    // A hook pointer that got ok: proof of delivery.
    write(&fx, &[ptr_line(&stamp(1800), "ok", "hook")]);
    fx.pass(2100);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[22].as_str()),
        ("resolved", "sent2xx"),
        "{}",
        fx.log()
    );
    fx.pass(2700);
    assert_eq!(
        fx.meta("hb_last"),
        Some(format!("{}/ok", stamp(2700))),
        "the heartbeat is no longer held back: {:?}",
        fx.meta("hb_skip")
    );
    // A refusal after the resolve opens it again; its cause_since is the reopen's own, later.
    write(&fx, &[ptr_line(&stamp(2800), "perm:404", "hook")]);
    fx.pass(3000);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str(), a[12].as_str()),
        ("open", "http.not_found:404", stamp(3000).as_str())
    );
    fx.pass(3300);
    let b = fx.record("alert:shell").unwrap();
    assert_eq!(b[31], a[31], "found once");
}

/// The same with the gate full: an incident message the hook had refused for good, last tried
/// after the pass began, opens alert-path once, and a later message that got through resolves it.
#[test]
fn an_incident_message_refused_after_the_pass_began_opens_alert_path_once_with_the_gate_full() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let key = "unit:sensor-ssh.service";
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n",
            inc_line(
                key,
                [
                    &stamp(0),
                    "pool",
                    "open",
                    "perm:403",
                    "hook",
                    "w#9",
                    &stamp(5)
                ]
            )
            .join("\t")
        ),
    );
    fx.pass(0);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str(), a[12].as_str()),
        ("open", "http.auth:403", stamp(5).as_str()),
        "{}",
        fx.log()
    );
    let occ = a[31].clone();
    fx.pass(300);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[12].as_str(), a[31].as_str()),
        (stamp(5).as_str(), occ.as_str())
    );
    let mut text = fx.read("var/lib/propolis/witness/send-ledger");
    text.push_str(&format!(
        "{}\n",
        inc_line(
            key,
            [
                &stamp(1700),
                "pool",
                "open",
                "ok",
                "hook",
                "w#9",
                &stamp(1800)
            ]
        )
        .join("\t")
    ));
    fx.write("var/lib/propolis/witness/send-ledger", &text);
    fx.private_topic(2000);
    fx.pass(2100);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[22].as_str()),
        ("resolved", "sent2xx"),
        "{}",
        fx.log()
    );
}

/// A message that got through before the refusal proves nothing about the path after it: with a
/// delivery and then a refusal both last tried after the pass began, alert-path opens and stays
/// open on the next pass, and resolves only once a message got through after the refusal.
#[test]
fn a_delivery_before_the_refusal_does_not_resolve_alert_path_and_one_after_it_does() {
    let mut fx = Fx::new();
    fx.v2();
    fx.private_topic(0);
    let line = |key: &str, at: u64, result: &str, tried: u64, id: &str| {
        inc_line(
            key,
            [
                &stamp(at),
                "pool",
                "open",
                result,
                "hook",
                id,
                &stamp(tried),
            ],
        )
        .join("\t")
    };
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\n{}\n{}\n",
            line("unit:sensor-http.service", 0, "ok", 2, "w#8"),
            line("unit:sensor-ssh.service", 0, "perm:403", 5, "w#9"),
        ),
    );
    fx.pass(0);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str(), a[12].as_str()),
        ("open", "http.auth:403", stamp(5).as_str()),
        "{}",
        fx.log()
    );
    fx.pass(300);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(a[7], "open", "{}", fx.log());
    let mut text = fx.read("var/lib/propolis/witness/send-ledger");
    text.push_str(&format!(
        "{}\n",
        line("unit:sensor-http.service", 1700, "ok", 1800, "w#8")
    ));
    fx.write("var/lib/propolis/witness/send-ledger", &text);
    fx.private_topic(2000);
    fx.pass(2100);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[22].as_str()),
        ("resolved", "sent2xx"),
        "{}",
        fx.log()
    );
}

/// The send ledger of these lines.
fn ledger_text(lines: &[String]) -> String {
    let mut text = String::from("#send-ledger v1 g=1\n");
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    text
}

/// In pointer mode only a pointer that gets through proves the path, and a pointer goes only
/// while a record is due. So an alert-path record a pointer already told is due again once a
/// new fact moves its cause, a refusal or an answer that never came: without that nothing would
/// ever be posted to prove the path, and the record, with the heartbeat it holds back, would stay
/// as it was for good. The next pointer tells of it, and its ok resolves it.
#[test]
fn a_told_alert_path_record_whose_cause_moves_is_due_again_and_its_pointer_resolves_it() {
    for (answer, judged_at, cause) in [
        ("perm:403", 2100, "http.auth:403"),
        ("transient:503", 2900, "http.server:503"),
    ] {
        let mut fx = Fx::new();
        fx.v2();
        fx.stub_file("curl.post", "200");
        // Told by a pointer that got through, and held open for an hour as a flapping record is.
        let told = with_field(
            &with_field(&alert_path_record(&before(600)), 28, "0a1b2c"),
            25,
            &stamp(0),
        );
        fx.incidents(&[told]);
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &ledger_text(&[ptr_line(&before(300), "ok", "light")]),
        );
        fx.pass(300);
        let a = fx.record("alert:shell").unwrap();
        assert_eq!(
            (a[7].as_str(), a[28].as_str()),
            ("open", "0a1b2c"),
            "{answer}: {}",
            fx.log()
        );
        let mut text = fx.read("var/lib/propolis/witness/send-ledger");
        text.push_str(&format!("{}\n", ptr_line(&stamp(1900), answer, "hook")));
        fx.write("var/lib/propolis/witness/send-ledger", &text);
        fx.pass(judged_at);
        let a = fx.record("alert:shell").unwrap();
        assert_eq!(
            (a[7].as_str(), a[11].as_str(), a[28].as_str()),
            ("open", cause, "-"),
            "{answer}: {}",
            fx.log()
        );
        assert!(fx.posts().is_empty(), "{answer}: the half hour holds");
        fx.pass(3900);
        assert_eq!(fx.posts().len(), 1, "{answer}: {}", fx.log());
        assert_eq!(fx.record("alert:shell").unwrap()[28], posted_ref(&fx, 0));
        fx.pass(4200);
        let a = fx.record("alert:shell").unwrap();
        assert_eq!(
            (a[7].as_str(), a[22].as_str()),
            ("resolved", "sent2xx"),
            "{answer}: {}",
            fx.log()
        );
    }
}

/// A pass does not resolve alert-path while a post is still in flight: one the hook claimed
/// seconds before the pass may yet be refused, and a refusal dated before the resolve would
/// never be read. The next pass decides with its answer.
#[test]
fn alert_path_is_not_resolved_while_a_post_is_in_flight_and_its_refusal_is_then_read() {
    let mut fx = Fx::new();
    fx.v2();
    fx.incidents(&[with_field(&alert_path_record(&before(4000)), 28, "0a1b2c")]);
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &ledger_text(&[
            ptr_line(&before(3900), "ok", "light"),
            ptr_line(&before(10), "sending", "hook"),
        ]),
    );
    fx.pass(0);
    assert_eq!(fx.record("alert:shell").unwrap()[7], "open", "{}", fx.log());
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &ledger_text(&[
            ptr_line(&before(3900), "ok", "light"),
            ptr_line(&before(10), "perm:403", "hook"),
        ]),
    );
    fx.pass(300);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str()),
        ("open", "http.auth:403"),
        "{}",
        fx.log()
    );
}

/// A ledger line of another boot dated ahead of the clock (that boot's clock ran fast) is no
/// fact about the path: a refusal so dated opens nothing and does not become the record's
/// cause_since, which would refuse every proof until the clock caught up, and a delivery so
/// dated is no proof.
#[test]
fn a_ledger_line_of_another_boot_dated_ahead_of_the_clock_neither_opens_nor_resolves_alert_path() {
    let ahead = format!("{}/11111111/900", WALL + 86400);
    // The rate is held, so no pass writes the ledger and drops the line.
    let held = ptr_line(&before(100), "transient:503", "light");
    let mut fx = Fx::new();
    fx.v2();
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &ledger_text(&[ptr_line(&ahead, "perm:403", "light"), held.clone()]),
    );
    fx.pass(0);
    assert!(fx.record("alert:shell").is_none(), "{}", fx.log());

    for result in ["perm:403", "ok"] {
        let mut fx = Fx::new();
        fx.v2();
        fx.incidents(&[with_field(&alert_path_record(&before(600)), 28, "0a1b2c")]);
        fx.write(
            "var/lib/propolis/witness/send-ledger",
            &ledger_text(&[ptr_line(&ahead, result, "light"), held.clone()]),
        );
        fx.pass(0);
        let a = fx.record("alert:shell").unwrap();
        assert_eq!(
            (a[7].as_str(), a[11].as_str(), a[12].as_str()),
            ("open", "nocurl", before(600).as_str()),
            "{result}: {}",
            fx.log()
        );
    }
}

/// When a failed failure hook gives the cause, a refusal read on the same pass is not what the
/// record was opened from: its time must not become the record's cause_since, or that refusal
/// would never be read once the hook's failure is the older fact.
#[test]
fn a_refusal_beside_a_failed_failure_hook_is_read_on_the_next_pass() {
    let mut fx = Fx::new();
    fx.v2();
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
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &ledger_text(&[
            ptr_line(&before(100), "ok", "light"),
            ptr_line(&stamp(5), "perm:403", "hook"),
        ]),
    );
    fx.pass(0);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str(), a[12].as_str()),
        ("open", "proc.timeout", stamp(0).as_str()),
        "{}",
        fx.log()
    );
    fx.pass(300);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[11].as_str()),
        ("open", "http.auth:403"),
        "{}",
        fx.log()
    );
}

/// Under the default profile alert-path resolves on a delivery after its open, as it always
/// did, whatever its cause_since says: the rule that the proof must come after the cause is the
/// new alerting's alone.
#[test]
fn under_legacy_alert_path_resolves_on_a_delivery_after_its_open_whatever_its_cause_since() {
    let fx = Fx::new();
    fx.incidents(&[with_field(&alert_path_record(&stamp(0)), 12, &stamp(1300))]);
    delivered_at(&fx, "sensor-ssh.service", 1100);
    fx.pass(1500);
    let a = fx.record("alert:shell").unwrap();
    assert_eq!(
        (a[7].as_str(), a[22].as_str()),
        ("resolved", "sent2xx"),
        "{}",
        fx.log()
    );
}
