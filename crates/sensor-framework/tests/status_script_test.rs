//! Runs `deploy/propolis-status.sh` (the walk) under a scratch root with `PROPOLIS_STATUS_ROOT`,
//! `PROPOLIS_STATUS_EUID=0` and a fixed `PROPOLIS_STATUS_NOW`, with stub `systemctl`,
//! `journalctl`, `curl`, `setpriv`, `id`, `timedatectl`, `df`, `hostname` and `logger` on `PATH`, a stub
//! daemon binary that carries pg-exec's guard string and answers the walk's queries, and a stub
//! config-check that prints fixture TSV. The shipped alert library is installed under the root.
//!
//! The library's reads as another account go through the `setpriv` stub in every run
//! (`PA_TEST_UID=0`), so the command line of the privilege drop is checked whether the tests run
//! as root or not, and a log the reader cannot open is simulated by the stub refusing it.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Writing an executable and spawning a child never overlap (ETXTBSY); see deploy_test.rs's fence.
static EXEC_FENCE: Mutex<()> = Mutex::new(());

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/propolis-status.sh"
);
const LIB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert-lib.sh");
const RUNBOOK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/operations/health-and-observability.md"
);
const COMMANDS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/reference/commands.md"
);

/// 2027-01-15 08:00:00 UTC.
const NOW: u64 = 1_800_000_000;
const STAMP: &str = "1800000000/abcdef01/900000";
const INVOCATION: &str = "0123456789abcdef0123456789abcdef";
const SALT: &str = "0123456789abcdef0123456789abcdef";

/// Records its argv; answers `is-enabled`, `list-unit-files` and `show` from the `UNITS` file
/// (`unit|ActiveState|SubState|Result|NRestarts|ActiveEnterTimestamp|UnitFileState|InvocationID`,
/// and for a timer optionally `|LastTriggerUSec`); `start` runs the failure hook (see below).
const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$STUB_LOG"
[ -z "${SYSTEMCTL_FAIL:-}" ] || exit 1
case "$1" in
    is-enabled)
        unit="${!#}"
        while IFS='|' read -r u a s r n t f i; do
            [ "$u" = "$unit" ] && [ "$f" = enabled ] && exit 0
        done < "$UNITS"
        exit 1
        ;;
    list-unit-files)
        while IFS='|' read -r u a s r n t f i; do
            case "$u" in sensor-*.service) echo "$u $f enabled" ;; esac
        done < "$UNITS"
        ;;
    show)
        shift
        props="" unit=""
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --property=*) props="${1#--property=}" ;;
                -p) props="$2"; shift ;;
                -*) ;;
                *) unit="$1" ;;
            esac
            shift
        done
        a=inactive s=dead r=success n=0 t="" f="" i="" l=""
        while IFS='|' read -r u a2 s2 r2 n2 t2 f2 i2 l2; do
            [ "$u" = "$unit" ] && a="$a2" s="$s2" r="$r2" n="$n2" t="$t2" f="$f2" i="$i2" l="$l2"
        done < "$UNITS"
        for p in ${props//,/ }; do
            case "$p" in
                ActiveState) v="$a" ;; SubState) v="$s" ;; Result) v="$r" ;; NRestarts) v="$n" ;;
                ActiveEnterTimestamp) v="$t" ;; UnitFileState) v="$f" ;; InvocationID) v="$i" ;;
                LastTriggerUSec) v="$l" ;;
                Environment) v=""; [ "$unit" != propolis-backup.service ] || v="${BACKUP_UNIT_ENV:-}" ;;
                NextElapseUSecRealtime) v="Sat 2027-01-16 03:30:00 UTC" ;; *) v="" ;;
            esac
            echo "$p=$v"
        done
        ;;
    start)
        # The failure-alert unit, as systemd would run it: deploy/alert.sh (HOOK_SCRIPT) with the
        # instance name, under the same root; START_FAIL makes the start itself fail.
        [ -z "${START_FAIL:-}" ] || exit 1
        # START_RESULT: the hook's run ended with this result, written as the hook writes it,
        # without running it (for results the fixture cannot bring about through the hook).
        if [ -n "${START_RESULT:-}" ]; then
            w="$PROPOLIS_STATUS_ROOT/var/lib/propolis/witness"
            sed "s/\tpending\t-\t-\$/\t$START_RESULT\t-\t-/" "$w/testpage" > "$w/testpage.new" && mv -f -- "$w/testpage.new" "$w/testpage"
            sed "s/\tpending\tstatus\$/\t$START_RESULT\thook/" "$w/send-ledger" > "$w/send-ledger.new" && mv -f -- "$w/send-ledger.new" "$w/send-ledger"
            exit 0
        fi
        [ -n "${HOOK_SCRIPT:-}" ] || exit 1
        u="${!#}" inst="${u#propolis-alert@}" inst="${inst%.service}"
        # START_REPLACE: another test page replaces the recorded code before the hook runs.
        if [ -n "${START_REPLACE:-}" ]; then
            f="$PROPOLIS_STATUS_ROOT/var/lib/propolis/witness/testpage"
            old="$(sed -n 's/^T\t\([0-9a-f]\{6\}\)\t.*/\1/p' "$f")" new=000000
            [ "$old" != 000000 ] || new=000001
            sed "s/^T\t$old\t/T\t$new\t/" "$f" > "$f.new" && mv -f -- "$f.new" "$f"
        fi
        PROPOLIS_ALERT_ROOT="$PROPOLIS_STATUS_ROOT" bash "$HOOK_SCRIPT" "$inst" > /dev/null 2>&1
        printf 'hook exit %s\n' "$?" >> "$STUB_LOG"
        ;;
    *) exit 1 ;;
esac
"#;

/// Records its argv; prints `JOURNAL_LINE` only for a query on `_SYSTEMD_UNIT=` the unit named in
/// `JOURNAL_LINE_UNIT` (default propolis.service) by uid 4242, followed by 200 KiB of other
/// lines when `JOURNAL_PAD` is set, the file `JOURNAL_TEXT` for a query of the last 20 lines,
/// and `LIST_BOOTS` for `--list-boots`.
const JOURNALCTL_STUB: &str = r#"#!/usr/bin/env bash
printf 'journalctl %s\n' "$*" >> "$STUB_LOG"
case " $* " in *" --disk-usage "*) echo "Archived and active journals take up 64.0M in the file system."; exit 0 ;; esac
case " $* " in *" --list-boots "*) [ -z "${LIST_BOOTS:-}" ] || printf '%s\n' "$LIST_BOOTS"; exit 0 ;; esac
if [ -n "${JOURNAL_LINE:-}" ] && [[ " $* " == *" _SYSTEMD_UNIT=${JOURNAL_LINE_UNIT:-propolis.service} "* ]] \
    && [[ " $* " == *" _UID=4242 "* ]]; then
    printf '%s\n' "$JOURNAL_LINE"
    [ -z "${JOURNAL_PAD:-}" ] || yes 'propolis: another line of the same run' | head -c 204800
fi
if [ -n "${JOURNAL_TEXT:-}" ] && [[ " $* " == *" -n 20 "* ]]; then cat "$JOURNAL_TEXT"; fi
exit 0
"#;

/// Records every argument in brackets and the content of a `-H @file` header file; answers
/// `/ready` with `STUB_READY_BODY` and `STUB_READY_CODE` (`none`: no answer) and `/metrics` with
/// `STUB_METRICS_BODY`. (The script has variables of its own named like the unprefixed ones, and
/// an assignment to an inherited name changes what its children see.)
///
/// A call given a config file (`-K FILE`, how the test page and the read check reach the alert
/// server) appends that file to `STUB_LOG.conf`, never to `STUB_LOG`, with its mode. A post (the
/// file names `data-binary`) appends the body it read to `STUB_LOG.post` and answers
/// `POST_CODE` (default 200); with `POST_HOLD_LOCK` set it first starts a process that takes that
/// lock file and holds it for a minute, its pid in `STUB_LOG.holder`; a GET answers from `RC_JSON`, `RC_RAW` and `RC_SSE` by the
/// endpoint the URL names (`code|content type`, default 403), and `RC_TOKEN_ANSWER` when a header
/// file is given. A URL on any host but ntfy.example.invalid answers nothing and exits 7.
const CURL_STUB: &str = r#"#!/usr/bin/env bash
{ printf 'curl'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$STUB_LOG"
conf="" prev="" hdr="" out=""
for a in "$@"; do
    case "$prev" in -K) conf="$a" ;; -H) hdr="${a#@}" ;; -o) out="$a" ;; esac
    prev="$a"
done
if [ -n "$conf" ]; then
    { printf -- '--- %s\n' "$(stat -c %a -- "$conf")"; cat -- "$conf"; } >> "$STUB_LOG.conf"
    url="$(sed -n 's/^url = "\(.*\)"$/\1/p' "$conf")"
    case "$url" in
        https://ntfy.example.invalid/* | http://ntfy.example.invalid/*) ;;
        *) exit 7 ;;
    esac
    if grep -q '^data-binary' "$conf"; then
        { printf -- '--- body\n'; cat; printf '\n'; } >> "$STUB_LOG.post"
        if [ -n "${POST_HOLD_LOCK:-}" ]; then
            ( exec 9< "$POST_HOLD_LOCK"; flock -x 9; echo "$BASHPID" > "$STUB_LOG.holder"; exec sleep 60 ) > /dev/null 2>&1 &
            until [ -s "$STUB_LOG.holder" ]; do sleep 0.1; done
        fi
        printf '%s' "${POST_CODE:-200}"
        exit 0
    fi
    ep="${url##*/}" ep="${ep%%\?*}"
    if [ -n "$hdr" ]; then v="${RC_TOKEN_ANSWER:-403|text/plain}"; else
        case "$ep" in json) v="${RC_JSON:-403|text/plain}" ;; raw) v="${RC_RAW:-403|text/plain}" ;; *) v="${RC_SSE:-403|text/plain}" ;; esac
    fi
    IFS='|' read -r code ct <<< "$v"
    [ -z "$out" ] || : > "$out"
    printf '%s\t%s' "$code" "$ct"
    exit 0
fi
url="${!#}" prev="" hdr=""
for a in "$@"; do [ "$prev" != -H ] || hdr="${a#@}"; prev="$a"; done
if [ -n "$hdr" ]; then { printf 'header-file %s: ' "$hdr"; cat -- "$hdr"; } >> "$STUB_LOG"; fi
case "$url" in
    */ready)
        if [ "${STUB_READY_CODE:-none}" = none ]; then printf '\n000'; exit 7; fi
        body="${STUB_READY_BODY:-}"
        [ -n "$body" ] || body='{"status":"ready"}'
        printf '%s\n%s' "$body" "$STUB_READY_CODE"
        ;;
    */metrics) printf '%s\n200' "${STUB_METRICS_BODY:-}" ;;
    *) printf '\n404' ;;
esac
"#;

/// Records its argv and runs the command after `--` as the caller, except that a command naming
/// `DENY_READ` among its arguments exits 6, as a reader that cannot open the file would, and one
/// naming `BREAK_READ` exits 1, as a read that failed for another reason would, and a `stat` of
/// `BREAK_STAT` exits 1.
const SETPRIV_STUB: &str = r#"#!/usr/bin/env bash
printf 'setpriv %s\n' "$*" >> "$STUB_LOG"
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
if [ -n "${DENY_READ:-}" ]; then
    for a in "$@"; do [ "$a" != "$DENY_READ" ] || exit 6; done
fi
if [ -n "${BREAK_READ:-}" ]; then
    for a in "$@"; do [ "$a" != "$BREAK_READ" ] || exit 1; done
fi
if [ -n "${BREAK_STAT:-}" ] && [ "$1" = stat ]; then
    for a in "$@"; do [ "$a" != "$BREAK_STAT" ] || exit 1; done
fi
exec "$@"
"#;

/// `id -u -- USER` and `id -g -- USER` answer 4242 and 4343; anything else is the real `id`.
const ID_STUB: &str = r#"#!/usr/bin/env bash
if [ "$1" = -u ] && [ "$2" = -- ]; then echo 4242
elif [ "$1" = -g ] && [ "$2" = -- ]; then echo 4343
else PATH=/usr/bin:/bin exec id "$@"; fi
"#;

const TIMEDATECTL_STUB: &str = r#"#!/usr/bin/env bash
echo "NTPSynchronized=${NTP:-yes}"
"#;

/// Records its argv; one line per directory asked about, with `DF_USE` (or `DF_IUSE` for inodes)
/// used, mounted on `/` or on the mount point the file `DF_MAP` gives the directory (lines
/// `path<TAB>mount point`, the path as on the host, without the test root).
const DF_STUB: &str = r#"#!/usr/bin/env bash
printf 'df %s\n' "$*" >> "$STUB_LOG"
use="${DF_USE:-61%}"
[ "$1" != -Pi ] || use="${DF_IUSE:-12%}"
shift
[ "$1" != -- ] || shift
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
for d in "$@"; do
    m=/
    rel="${d#"${PROPOLIS_STATUS_ROOT:-}"}"
    if [ -n "${DF_MAP:-}" ] && [ -f "$DF_MAP" ]; then
        while IFS=$'\t' read -r p t; do [ "$p" != "$rel" ] || m="$t"; done < "$DF_MAP"
    fi
    echo "/dev/sda1 1000 610 390 $use $m"
done
"#;

const HOSTNAME_STUB: &str = "#!/usr/bin/env bash\necho honeybox\n";

/// Records its argv, so a line the walk sent to the journal shows in `STUB_LOG`.
const LOGGER_STUB: &str = r#"#!/usr/bin/env bash
printf 'logger %s\n' "$*" >> "$STUB_LOG"
"#;

/// The daemon binary: carries pg-exec's guard string, records its argv, and answers the walk's
/// queries; `PG_RC` and `PG_ERR` make it fail. It answers `SHOW transaction_read_only` with `on`,
/// as every session the read-only probe opens would, and the role settings query with
/// `ROLE_SETTING` (nothing by default).
const PROPOLIS_STUB: &str = r#"#!/usr/bin/env bash
# propolis pg-exec: DATABASE_URL is not set
printf 'propolis %s\n' "$*" >> "$STUB_LOG"
[ -z "${PG_ERR:-}" ] || printf '%s\n' "$PG_ERR" >&2
[ "${PG_RC:-0}" = 0 ] || exit "$PG_RC"
sql="${!#}"
case "$sql" in
    'SELECT 1') echo 1 ;;
    'SHOW transaction_read_only') echo on ;;
    *pg_db_role_setting*) [ -z "${ROLE_SETTING:-}" ] || echo "$ROLE_SETTING" ;;
    *'FROM event'*) echo "9812440|$((NOW - 3))" ;;
    *'max(decided_at)'*) echo "3|$((NOW - 37))|$((NOW - 100))" ;;
    *'FROM review_queue'*) echo "$((NOW - 37))|3" ;;
    *last_ok*) printf '%s|%s|%s|500|4\n' "${VENDOR:-abuseipdb}" "$((NOW - 1020))" "$((NOW - 5000))" ;;
    *vendor_submission*) printf '%s|%s|%s|200\n' "${VENDOR:-abuseipdb}" "$((NOW - 1020))" "$((NOW - 1020))" ;;
esac
"#;

/// The installed config-check: records its argv, copies the walk's output so far to `CC_SEEN`
/// when asked, prints the file in `CC_TSV`, sleeps `CC_SLEEP` seconds and exits `CC_RC`.
const CONFIG_CHECK_STUB: &str = r#"#!/usr/bin/env bash
printf 'config-check %s\n' "$*" >> "$STUB_LOG"
[ -z "${CC_SEEN:-}" ] || cp -- "$CC_SEEN_FROM" "$CC_SEEN"
cat -- "$CC_TSV"
[ -z "${CC_SLEEP:-}" ] || exec sleep "$CC_SLEEP"
exit "${CC_RC:-0}"
"#;

fn write_exec(path: &Path, body: &str) {
    let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn set_mtime(path: &Path, epoch: u64) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(epoch))
        .unwrap();
}

/// The cursor file name the log tailer gives `path`: the SHA-256 of the resolved path.
fn cursor_name(path: &Path) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg(r#"printf '%s' "$(readlink -f -- "$1")" | sha256sum"#)
        .arg("_")
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    format!("{}.json", text.split_whitespace().next().unwrap())
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    /// The pipeline or rail row for `stage`.
    fn row(&self, stage: &str) -> String {
        self.out
            .lines()
            .find(|l| {
                let rest = l.get(4..).unwrap_or("");
                rest.starts_with(&format!("{stage} "))
                    && l.get(..4).is_some_and(|p| {
                        p.chars()
                            .all(|c| c == ' ' || c == '>' || c.is_ascii_digit())
                    })
            })
            .unwrap_or_else(|| panic!("no {stage} row in:\n{}\nstderr:\n{}", self.out, self.err))
            .to_string()
    }

    /// The state column of `stage`'s row.
    fn state(&self, stage: &str) -> String {
        let row = self.row(stage);
        row.get(64..)
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    }

    fn marked(&self) -> Option<String> {
        self.out
            .lines()
            .find(|l| l.get(2..3) == Some(">"))
            .map(|l| l[4..].split_whitespace().next().unwrap().to_string())
    }
}

struct Fx {
    dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
    units: Vec<String>,
    env: Vec<(String, String)>,
}

impl Fx {
    /// A healthy single box: the daemon, two sensors and their logs, cursors caught up, a recent
    /// backup, a feed and a push, a database that answers, and a clean config-check.
    fn single() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let bin = dir.path().join("bin");
        for (name, body) in [
            ("systemctl", SYSTEMCTL_STUB),
            ("journalctl", JOURNALCTL_STUB),
            ("curl", CURL_STUB),
            ("setpriv", SETPRIV_STUB),
            ("id", ID_STUB),
            ("timedatectl", TIMEDATECTL_STUB),
            ("df", DF_STUB),
            ("hostname", HOSTNAME_STUB),
            ("logger", LOGGER_STUB),
        ] {
            write_exec(&bin.join(name), body);
        }
        let log = dir.path().join("stub.log");
        std::fs::write(&log, b"").unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        let mut fx = Fx {
            dir,
            root,
            bin,
            log,
            units: Vec::new(),
            env: Vec::new(),
        };
        for d in [
            "usr/local/sbin",
            "usr/local/bin",
            "usr/local/lib/propolis",
            "etc/propolis",
            "var/lib/propolis/witness",
            "var/lib/propolis/cursors",
            "var/log/propolis",
            "run/propolis-witness",
        ] {
            std::fs::create_dir_all(fx.root.join(d)).unwrap();
        }
        for d in [
            "",
            "usr",
            "usr/local",
            "usr/local/sbin",
            "usr/local/bin",
            "usr/local/lib",
            "usr/local/lib/propolis",
        ] {
            std::fs::set_permissions(fx.root.join(d), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        std::fs::copy(LIB, fx.p("usr/local/sbin/propolis-alert-lib")).unwrap();
        std::fs::set_permissions(
            fx.p("usr/local/sbin/propolis-alert-lib"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        write_exec(&fx.p("usr/local/bin/propolis"), PROPOLIS_STUB);
        write_exec(
            &fx.p("usr/local/lib/propolis/config-check.sh"),
            CONFIG_CHECK_STUB,
        );
        fx.tsv(&[]);
        fx.write("var/lib/propolis/witness/id-salt", &format!("{SALT}\n"));

        fx.unit(
            "propolis.service",
            "active",
            "running",
            "success",
            "enabled",
        );
        fx.unit(
            "sensor-ssh.service",
            "active",
            "running",
            "success",
            "enabled",
        );
        fx.unit(
            "sensor-http.service",
            "active",
            "running",
            "success",
            "enabled",
        );
        fx.unit("gateway.service", "inactive", "dead", "success", "disabled");
        fx.unit(
            "propolis-backup.timer",
            "active",
            "waiting",
            "success",
            "enabled",
        );
        fx.light_timer();
        fx.readcheck("refused");

        let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
        let http = fx.p("var/log/propolis/http/events.jsonl");
        fx.write(
            "etc/propolis/propolis.env",
            &format!(
                "PROPOLIS_SENSOR_LOGS=ssh:{},http:{}\nDATABASE_URL=postgres://propolis:pw@localhost/propolis\n\
                 PROPOLIS_OPS_ENABLED=true\nPROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\n\
                 PROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\nPROPOLIS_OPS_NTFY_TOKEN=tk_secret\n\
                 PROPOLIS_OPS_FEED_PUSH_EXPECTED=true\n",
                ssh.display(),
                http.display()
            ),
        );
        for (label, path) in [("ssh", &ssh), ("http", &http)] {
            fx.write(
                &format!("var/log/propolis/{label}/events.jsonl"),
                &"x".repeat(100),
            );
            set_mtime(path, NOW - 6);
            fx.cursor("var/lib/propolis/cursors", path, 100, NOW - 3);
        }
        fx.write(
            "var/lib/propolis/backup-status/last-success",
            r#"{"completed_at":"2027-01-14T20:00:00Z","reason":"scheduled","set":"20270114T200000Z-scheduled","encrypted":true,"dump_bytes":10,"archive_bytes":10,"source_bytes":10}"#,
        );
        fx.write("var/lib/propolis/feed/current/manifest.json", "{}");
        set_mtime(
            &fx.p("var/lib/propolis/feed/current/manifest.json"),
            NOW - 1260,
        );
        fx.write("var/lib/propolis/blocklist-status/last-pushed", "");
        set_mtime(
            &fx.p("var/lib/propolis/blocklist-status/last-pushed"),
            NOW - 960,
        );
        fx.write(
            "etc/cron.d/propolis-blocklist",
            "5 * * * * propolis-blocklist /usr/local/lib/propolis/blocklist-sync.sh\n",
        );
        fx.setenv("STUB_READY_CODE", "200");
        fx
    }

    /// A collector: the shipper and one sensor, no daemon.
    fn collector() -> Self {
        let mut fx = Fx::single();
        fx.units.clear();
        fx.light_timer();
        fx.unit("shipper.service", "active", "running", "success", "enabled");
        fx.unit(
            "sensor-ssh.service",
            "active",
            "running",
            "success",
            "enabled",
        );
        let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
        fx.write(
            "etc/propolis/shipper.env",
            &format!("PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:{}\n", ssh.display()),
        );
        fx.write("etc/propolis/propolis.env", "");
        std::fs::create_dir_all(fx.p("var/lib/propolis/shipper/state")).unwrap();
        fx
    }

    /// A control node: the daemon and the gateway, collectors in the spool.
    fn control() -> Self {
        let mut fx = Fx::single();
        fx.units.retain(|u| !u.starts_with("gateway.service"));
        fx.unit("gateway.service", "active", "running", "success", "enabled");
        std::fs::create_dir_all(fx.p("var/spool/propolis/gateway")).unwrap();
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

    fn setenv(&mut self, k: &str, v: &str) {
        self.env.retain(|(name, _)| name != k);
        self.env.push((k.to_string(), v.to_string()));
    }

    fn unit(&mut self, name: &str, active: &str, sub: &str, result: &str, file: &str) {
        self.units.retain(|u| !u.starts_with(&format!("{name}|")));
        self.units.push(format!(
            "{name}|{active}|{sub}|{result}|0|Fri 2027-01-15 07:00:00 UTC|{file}|{INVOCATION}"
        ));
    }

    /// The witness's two timers, installed, enabled and waiting; the light one not yet fired.
    fn light_timer(&mut self) {
        for timer in [
            "propolis-witness@light.timer",
            "propolis-witness@hourly.timer",
        ] {
            self.unit(timer, "active", "waiting", "success", "enabled");
        }
    }

    /// The stored read check of the fixture's target (https://ntfy.example.invalid, t0p1c-secret):
    /// one line for the shell and the daemon, with this definite class, decided and attempted
    /// ten minutes ago.
    fn readcheck(&self, class: &str) {
        let s = stamp_ago(600);
        self.write(
            "var/lib/propolis/witness/readcheck",
            &format!(
                "#readcheck v1 g=2\nR\t8f24b729c8ebd3c1\t{s}\t{class}\t{s}\t{class}\treads\t403\t403\tboth\t403\n"
            ),
        );
    }

    /// The trace of a witness pass `ago` seconds before NOW: `meta light_last` (and `where`),
    /// the heartbeat line, and the banner it wrote then.
    fn witness_ran(&self, ago: u64) {
        let s = stamp_ago(ago);
        self.write(
            "var/lib/propolis/witness/meta",
            &format!("#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{s}\n"),
        );
        self.write(
            "run/propolis-witness/heartbeat",
            &format!("#heartbeat v1 g=3\nB\tlight\t{s}\tpersistent\tok\n"),
        );
        self.write(
            "run/motd.d/propolis",
            "[propolis 07:55 UTC] nothing open; profile legacy\n",
        );
        set_mtime(&self.p("run/motd.d/propolis"), NOW - ago);
    }

    /// A cursor for `log` in `dir` (relative to the root) at `offset`, written at `mtime`.
    fn cursor(&self, dir: &str, log: &Path, offset: u64, mtime: u64) {
        let ino = std::fs::metadata(log).unwrap().ino();
        let rel = format!("{dir}/{}", cursor_name(log));
        self.write(
            &rel,
            &format!("{{\"inode\":{ino},\"offset\":{offset},\"fingerprint\":\"00\"}}"),
        );
        set_mtime(&self.p(&rel), mtime);
    }

    /// The config-check TSV with these `F` lines (`level id scope`).
    fn tsv(&self, findings: &[(&str, &str, &str)]) {
        self.tsv_with(findings, &[]);
    }

    /// The config-check TSV with these `F` lines and these listener `R` lines (`scope unit
    /// firewall`).
    fn tsv_with(&self, findings: &[(&str, &str, &str)], rows: &[(&str, &str, &str)]) {
        let fails = findings.iter().filter(|f| f.0 == "fail").count();
        let warns = findings.len() - fails;
        let status = if fails > 0 {
            "fail"
        } else if warns > 0 {
            "warn"
        } else {
            "ok"
        };
        let mut text =
            format!("#config-check tsv v1\nS\t{status}\t0\t{fails}\t{warns}\t0\t1\t{NOW}\t1\n");
        for (scope, unit, firewall) in rows {
            text.push_str(&format!(
                "R\t{scope}\t{unit}\tok\tactive\t0.0.0.0:22\t{firewall}\n"
            ));
        }
        for (level, id, scope) in findings {
            text.push_str(&format!(
                "F\t{level}\t{id}\t0123456789ab\t{scope}\trun\tmessage\nX\tsudo true\n"
            ));
        }
        text.push_str(&format!("E\t{}\n", findings.len()));
        std::fs::write(self.dir.path().join("cc.tsv"), text).unwrap();
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }

    /// Appends `line` to `/etc/propolis/propolis.env`.
    fn env_line(&self, line: &str) {
        let path = self.p("etc/propolis/propolis.env");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::write(path, text + line + "\n").unwrap();
    }

    /// Removes every line of `/etc/propolis/propolis.env` that starts with `prefix`.
    fn env_drop(&self, prefix: &str) {
        let path = self.p("etc/propolis/propolis.env");
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().filter(|l| !l.starts_with(prefix)).collect();
        std::fs::write(path, kept.join("\n") + "\n").unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        std::fs::write(self.dir.path().join("units"), self.units.join("\n") + "\n").unwrap();
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let mut command = Command::new(SCRIPT);
        command
            .args(args)
            .env("PATH", path)
            .env("PROPOLIS_STATUS_ROOT", &self.root)
            .env("PROPOLIS_STATUS_EUID", "0")
            .env("PROPOLIS_STATUS_NOW", STAMP)
            .env("PA_TEST_UID", "0")
            .env("STUB_LOG", &self.log)
            .env("UNITS", self.dir.path().join("units"))
            .env("CC_TSV", self.dir.path().join("cc.tsv"))
            .env("NOW", NOW.to_string())
            .env("TMPDIR", self.dir.path().join("tmp"))
            .env_remove("PA_TEST_WALL")
            .env_remove("PA_TEST_BOOT")
            .env_remove("PA_TEST_UP")
            .env_remove("PA_TEST_READ_AS_SELF")
            .env_remove("PA_LOCK_FD")
            .env_remove("PA_CLEANUP")
            .env_remove("PROPOLIS_STATUS_CC")
            .env_remove("SUDO_UID")
            .stdin(Stdio::null());
        for (k, v) in &self.env {
            command.env(k, v);
        }
        command
    }

    fn run(&self, args: &[&str]) -> Run {
        let mut command = self.command(args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
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

    fn walk(&self) -> Run {
        self.run(&[])
    }
}

/// An `incidents` record of 34 fields as the failure hook writes it.
// The arguments are the fields a case varies, in the record's own field order, which reads more
// plainly at each call than a builder would.
#[allow(clippy::too_many_arguments)]
fn record(
    id: &str,
    key: &str,
    stage: &str,
    tier: &str,
    state: &str,
    first: u64,
    cause: &str,
    out: &str,
) -> String {
    let stamp = format!("{first}/abcdef01/{}", 900_000 - (NOW - first));
    let mut f: Vec<String> = vec![
        "I".into(),
        id.into(),
        key.into(),
        "unit-failed".into(),
        stage.into(),
        "-".into(),
        tier.into(),
        state.into(),
        stamp.clone(),
        "-".into(),
        stamp.clone(),
        cause.into(),
        stamp,
    ];
    f.extend(
        [
            "-", "0", "-", "-", "0", "0", "-", "-", "-", "-", "0", "-", "-", "-", "-", "-", "0",
            "-", "1", "-", out, "-",
        ]
        .map(String::from),
    );
    assert_eq!(f.len(), 35);
    f.join("\t") + "\n"
}

/// `rec` with field `k` (numbered from 1 after the `I`, as the library numbers them) set to `v`.
fn set_field(rec: &str, k: usize, v: &str) -> String {
    let mut f: Vec<String> = rec.trim_end().split('\t').map(String::from).collect();
    f[k] = v.to_string();
    f.join("\t") + "\n"
}

/// A stamp `ago` seconds before NOW, in the library's WALL/BOOT/UP form.
fn stamp_ago(ago: u64) -> String {
    format!("{}/abcdef01/{}", NOW - ago, 900_000u64.saturating_sub(ago))
}

#[test]
fn a_healthy_single_box_marks_nothing_and_exits_zero() {
    let fx = Fx::single();
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    assert_eq!(r.marked(), None, "{}", r.out);
    assert!(
        r.out.contains(
            "PIPELINE  no stage stopped that shell can see; stages 7 to 10 are shown, not judged"
        ),
        "{}",
        r.out
    );
    for (stage, state) in [
        ("listen", "ok"),
        ("source", "ok"),
        ("ship", "-"),
        ("gateway", "-"),
        ("intake", "ok"),
        ("ledger", "ok"),
        ("review", "info"),
        ("reports", "info"),
        ("feed", "info"),
        ("publish", "info"),
        ("alert", "ok"),
        ("backup", "ok"),
        ("chain", "info"),
        ("host", "ok"),
        ("monitor", "ok"),
        ("witness", "ok"),
        ("peers", "info"),
    ] {
        assert_eq!(r.state(stage), state, "{stage}:\n{}", r.out);
    }
    let header = r.out.lines().next().unwrap();
    assert!(
        header.starts_with("host-")
            && header.contains(" = honeybox - single box - 2027-01-15 08:00:00 UTC"),
        "{header}"
    );
    assert!(r.row("listen").contains("2 of 2 units active"), "{}", r.out);
    assert!(
        r.row("source").contains("all readable by propolis"),
        "{}",
        r.out
    );
    assert!(
        r.row("intake")
            .contains("0 B behind (cursor files); /ready 200"),
        "{}",
        r.out
    );
    assert!(r.row("ledger").contains("last event #9812440"), "{}", r.out);
    assert!(r.row("reports").contains("{abuseipdb} 200"), "{}", r.out);
    assert!(
        r.row("publish")
            .contains("scheduler found (cron); push expected"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("RECENT FAILURES  no incident record yet"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("daemon incidents: not on disk before step 3"),
        "{}",
        r.out
    );
    assert!(r.out.contains("ALERTS  target ntfy from propolis.env - gate full (checked 07:50:00, 10 min) - daemon monitor on - daemon queue empty - failure hook legacy, 0 units undelivered"), "{}", r.out);
    assert!(
        r.out.contains("CHECK   config-check 08:00:00 ("),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("NEXT    nothing stopped and nothing to look at"),
        "{}",
        r.out
    );
    assert!(r.out.contains("IDS     u"), "{}", r.out);
    assert!(
        r.out
            .contains("{...} = a name as found where another account writes"),
        "{}",
        r.out
    );
}

/// Until a witness pass has run on the host nothing has judged the records, so nothing is open;
/// and what later releases add (the heartbeat URL, the profile) is not shown. VERIFIED is, as
/// NOT VERIFIED (never): no test page has been asked for.
#[test]
fn before_a_witness_pass_the_walk_calls_nothing_open_and_shows_no_profile() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=2\nN\t2\n{}",
            record(
                "w#1",
                "unit:sensor-ssh.service",
                "listen",
                "PAGE",
                "open",
                NOW - 600,
                "proc.exit:1",
                "delivered"
            )
        ),
    );
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out
            .contains(" - NOT VERIFIED (never); daemon not verified\n"),
        "{}",
        r.out
    );
    for absent in [
        "OPEN ",
        " open ",
        "open since",
        "PAGE",
        "would remind",
        "heartbeat",
        "profile ",
    ] {
        assert!(!r.out.contains(absent), "{absent:?} in:\n{}", r.out);
    }
    assert!(
        r.out
            .contains("        witness light never - hourly never - state "),
        "{}",
        r.out
    );
    // The alert view lists every record with its fields, and still no tier or `open`: the hook
    // stores a oneshot as `ACT open` at once, and nothing has judged it.
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=2\nN\t3\n{}{}",
            record(
                "w#1",
                "unit:propolis-backup.service",
                "backup",
                "ACT",
                "open",
                NOW - 600,
                "proc.exit:1",
                "delivered"
            ),
            record(
                "w#2",
                "unit:sensor-ssh.service",
                "listen",
                "PAGE",
                "pending",
                NOW - 300,
                "proc.signal:9",
                "cooldown"
            ),
        ),
    );
    let view = fx.run(&["alert"]);
    assert_eq!(view.code, 0, "{}\n{}", view.out, view.err);
    assert!(
        view.out.contains("w#1 ") && view.out.contains("w#2 "),
        "{}",
        view.out
    );
    assert!(
        view.out
            .contains("key unit:sensor-ssh.service  kind unit-failed  cause proc.signal:9"),
        "{}",
        view.out
    );
    for absent in [" open ", "PAGE", " ACT ", "open since"] {
        assert!(!view.out.contains(absent), "{absent:?} in:\n{}", view.out);
    }
}

#[test]
fn a_stopped_listener_is_marked_at_stage_one() {
    let mut fx = Fx::single();
    fx.unit(
        "sensor-ssh.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("listen"), "{}", r.out);
    assert!(
        r.row("listen")
            .contains("1 enabled and not active: sensor-ssh.service"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("NEXT    sudo propolis-status listen  -  runbook docs/operations/health-and-observability.md#listen-down in the Propolis checkout"),
        "{}",
        r.out
    );
    fx.write("usr/local/lib/propolis/repo-dir", "/srv/propolis\n");
    let r = fx.walk();
    assert!(
        r.out.contains("NEXT    sudo propolis-status listen  -  runbook /srv/propolis/docs/operations/health-and-observability.md#listen-down"),
        "{}",
        r.out
    );
}

/// The stub refuses the reader for one log, as a mode-0000 log or a lost group would.
#[test]
fn a_log_the_reader_cannot_open_is_marked_at_stage_two() {
    let mut fx = Fx::single();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.setenv("DENY_READ", &ssh.display().to_string());
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("source"), "{}", r.out);
    assert!(
        r.row("source").contains("not readable by propolis: {ssh}"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("NEXT    sudo propolis-status source"),
        "{}",
        r.out
    );
}

/// Every readability test runs as the reader with the reader's own groups (the readers reach the
/// sensor logs only through them) and opens the file (MAX=0) instead of trusting its size.
#[test]
fn the_readability_test_uses_the_readers_groups() {
    let fx = Fx::single();
    std::fs::set_permissions(
        fx.p("var/log/propolis/ssh"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let r = fx.walk();
    assert_eq!(r.state("source"), "ok", "{}", r.out);
    let log = fx.log();
    for label in ["ssh", "http"] {
        let path = fx.p(&format!("var/log/propolis/{label}/events.jsonl"));
        let tail = format!(" _ {} 0", path.display());
        // One call per entry: the text up to the end of the line that holds its arguments.
        let calls: Vec<&str> = log
            .split("setpriv ")
            .filter_map(|c| {
                let at = c.find(" _ ")?;
                Some(&c[..at + c[at..].find('\n')?])
            })
            .filter(|c| c.contains(&format!(" _ {} ", path.display())))
            .collect();
        assert!(
            !calls.is_empty(),
            "no read as another account of {label}:\n{log}"
        );
        for call in calls {
            assert!(
                call.starts_with(
                    "--reuid=4242 --regid=4343 --init-groups --no-new-privs -- bash -c"
                ),
                "{call}"
            );
            assert!(
                call.ends_with(&tail),
                "a log is only ever tested, never read: {call}"
            );
        }
    }
}

/// The hook's records, with no witness pass ever run, are failures that happened: listed newest
/// first with their cause and what today's hook did, never open, never counted in the exit code.
/// Nothing resolves a record before the witness, so an unresolved one is listed however old its
/// first failure (it may have failed again a minute ago); only a resolved one ages out.
#[test]
fn hook_records_before_any_witness_pass_are_recent_failures_and_do_not_set_the_exit_code() {
    let fx = Fx::single();
    let looping = set_field(
        &record(
            "w#3",
            "unit:sensor-http.service",
            "listen",
            "PAGE",
            "pending",
            NOW - 9 * 86400,
            "proc.oom",
            "delivered",
        ),
        31,
        "40",
    );
    let healed = set_field(
        &record(
            "w#4",
            "unit:propolis-logrotate.service",
            "source",
            "ACT",
            "resolved",
            NOW - 10 * 86400,
            "proc.exit:2",
            "delivered",
        ),
        21,
        &stamp_ago(9 * 86400),
    );
    let unknown = set_field(
        &record(
            "w#5",
            "unit:propolis-backup.service",
            "backup",
            "ACT",
            "open",
            NOW - 60,
            "proc.exit:1",
            "journal",
        ),
        8,
        "?",
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t6\n{}{}{looping}{healed}{unknown}",
            record(
                "w#1",
                "unit:sensor-ssh.service",
                "listen",
                "PAGE",
                "pending",
                NOW - 3600,
                "proc.exit:1",
                "delivered"
            ),
            record(
                "w#2",
                "unit:propolis-backup.service",
                "backup",
                "ACT",
                "open",
                NOW - 600,
                "proc.signal:9",
                "cooldown"
            ),
        ),
    );
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    let block: Vec<&str> = r
        .out
        .lines()
        .skip_while(|l| !l.starts_with("RECENT FAILURES"))
        .take(6)
        .collect();
    assert_eq!(
        block[0], "RECENT FAILURES (not judged: no witness pass has run on this host)",
        "{}",
        r.out
    );
    assert!(
        block[1].trim_start().starts_with("w#2 "),
        "newest first: {block:?}"
    );
    assert!(block[1].contains("{propolis-backup.service}"), "{block:?}");
    assert!(block[1].contains("first failed 07:50:00"), "{block:?}");
    assert!(block[1].contains("cause proc.signal 9"), "{block:?}");
    assert!(block[1].contains("[legacy hook: cooldown]"), "{block:?}");
    assert!(
        block[2].contains("w#1 ") && block[2].contains("cause proc.exit 1"),
        "{block:?}"
    );
    assert!(block[2].contains("[legacy hook: delivered]"), "{block:?}");
    assert!(
        block[2].contains("=u") || block[2].contains(" u"),
        "an id for the unit: {block:?}"
    );
    assert!(
        block[3].contains("w#3 ") && block[3].contains("first failed 01-06 08:00"),
        "an unresolved record is listed however old: {block:?}"
    );
    assert!(
        block[3].contains("(40 firings, latest: legacy hook delivered)"),
        "{block:?}"
    );
    assert!(
        block[4].contains("w#5 ") && block[4].contains(" failed ?"),
        "a first failure that cannot be read is shown as such: {block:?}"
    );
    assert!(!block[4].contains("first failed"), "{block:?}");
    assert_eq!(
        block[5].trim(),
        "1 resolved, older than 7 days, not listed",
        "{block:?}"
    );
    assert!(!r.out.contains("w#4 "), "{}", r.out);
}

#[test]
fn a_parked_sensor_makes_stage_one_warn_and_never_takes_the_marker() {
    let mut fx = Fx::single();
    fx.unit(
        "sensor-ftp.service",
        "inactive",
        "dead",
        "success",
        "disabled",
    );
    fx.tsv(&[("fail", "unit-disabled", "sensor-ftp")]);
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/cursors", &ssh, 10, NOW - 3600);
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.state("listen"), "WARN", "{}", r.out);
    assert!(
        r.row("listen")
            .contains("1 unit disabled on purpose (unit-disabled)"),
        "{}",
        r.out
    );
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status intake  -  runbook"),
        "{}",
        r.out
    );
}

/// Every runbook key NEXT can print names a section of the runbook page that exists today.
#[test]
fn every_runbook_key_next_can_print_has_its_anchor() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let start = script
        .find("\nSTATUS_NEXT=(\n")
        .expect("deploy/propolis-status.sh has no `STATUS_NEXT=(` line at column 0");
    let body = &script[start + "\nSTATUS_NEXT=(\n".len()..];
    let body = &body[..body.find("\n)\n").expect("STATUS_NEXT=( is not closed")];
    let page = std::fs::read_to_string(RUNBOOK).unwrap();
    let lines: Vec<&str> = page.lines().collect();
    let mut keys = Vec::new();
    for entry in body.lines() {
        let entry = entry.trim().trim_matches('"');
        let words: Vec<&str> = entry.split_whitespace().collect();
        assert_eq!(words.len(), 3, "{entry:?} is not `condition view key`");
        if words[2] != "-" {
            keys.push(words[2]);
        }
    }
    assert!(keys.len() >= 10, "{keys:?}");
    for key in keys {
        let anchor = format!("<a id=\"{key}\"></a>");
        let at = lines
            .iter()
            .position(|l| l.trim() == anchor)
            .unwrap_or_else(|| panic!("{RUNBOOK} has no {anchor}"));
        assert!(
            lines
                .get(at + 1)
                .is_some_and(|l| l.starts_with("## ") || l.starts_with("### ")),
            "{anchor} must sit right above its heading"
        );
    }
}

/// The header, ALERTS and the recent failures are on the terminal before config-check, the slow
/// call, has even started: the config-check stub copies what the walk had printed when it ran.
#[test]
fn alerts_and_open_print_before_config_check_runs() {
    let mut fx = Fx::single();
    let out = fx.dir.path().join("walk.out");
    let seen = fx.dir.path().join("seen.out");
    fx.setenv("CC_SEEN", &seen.display().to_string());
    fx.setenv("CC_SEEN_FROM", &out.display().to_string());
    let mut command = fx.command(&[]);
    command
        .stdout(std::fs::File::create(&out).unwrap())
        .stderr(Stdio::null());
    let status = {
        let child = {
            let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
            command.spawn().unwrap()
        };
        child.wait_with_output().unwrap().status
    };
    assert_eq!(status.code(), Some(0));
    let before = std::fs::read_to_string(&seen).unwrap();
    assert!(before.contains("ALERTS  target"), "{before}");
    assert!(before.contains("RECENT FAILURES"), "{before}");
    assert!(!before.contains("PIPELINE"), "{before}");
    assert!(std::fs::read_to_string(&out).unwrap().contains("PIPELINE"));
}

#[test]
fn legacy_lines_say_what_todays_hook_did() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t3\n{}{}",
            record(
                "w#1",
                "unit:sensor-ssh.service",
                "listen",
                "PAGE",
                "pending",
                NOW - 60,
                "proc.exit:1",
                "delivered"
            ),
            record(
                "w#2",
                "finding:noconfig:0123456789ab",
                "listen",
                "ACT",
                "open",
                NOW - 120,
                "config.finding",
                "-"
            ),
        ),
    );
    let r = fx.walk();
    let one = r.out.lines().find(|l| l.contains("w#1 ")).unwrap();
    assert!(one.ends_with("[legacy hook: delivered]"), "{one}");
    let two = r.out.lines().find(|l| l.contains("w#2 ")).unwrap();
    assert!(two.ends_with("[not pushed: legacy]"), "{two}");
    for line in [one, two] {
        assert!(
            !line.contains("remind") && !line.contains("open") && !line.contains("PAGE"),
            "{line}"
        );
    }
}

#[test]
fn an_untrusted_usr_local_names_the_directory() {
    let fx = Fx::single();
    std::fs::set_permissions(
        fx.p("usr/local/sbin"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 70, "{}", r.err);
    assert!(r.err.contains("alert library not trusted: "), "{}", r.err);
    assert!(
        r.err.contains("/usr/local/sbin: group-writable ("),
        "{}",
        r.err
    );
    assert!(r.err.contains("chmod g-w"), "{}", r.err);
    assert!(r.out.is_empty(), "{}", r.out);
    assert!(
        !fx.log().contains("systemctl"),
        "nothing is asked before the library: {}",
        fx.log()
    );
}

#[test]
fn a_collector_with_unread_bytes_and_an_old_ack_is_marked_at_stage_three() {
    let fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/shipper/cursors", &ssh, 40, NOW - 4000);
    fx.write("var/lib/propolis/shipper/state/k1.json", "{}");
    set_mtime(&fx.p("var/lib/propolis/shipper/state/k1.json"), NOW - 3600);
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}\n{}", r.out, r.err);
    assert!(r.out.contains(" = honeybox - collector - "), "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("ship"), "{}", r.out);
    assert!(r.row("ship").contains("unread 60 B in {ssh}"), "{}", r.out);
    for stage in [
        "gateway", "intake", "ledger", "review", "reports", "feed", "publish",
    ] {
        assert_eq!(r.state(stage), "-", "{stage}: {}", r.out);
    }
    assert!(
        r.row("intake")
            .contains("on the control node: run sudo propolis-status there"),
        "{}",
        r.out
    );
    assert!(
        r.row("gateway").contains("on the control node"),
        "{}",
        r.out
    );
    for rail in ["backup", "chain", "monitor", "peers"] {
        assert_eq!(r.state(rail), "-", "{rail}: {}", r.out);
    }
    assert_eq!(r.state("alert"), "info", "{}", r.out);
    assert!(
        !fx.log().contains("propolis pg-exec"),
        "no database on a collector"
    );
}

#[test]
fn an_idle_collector_with_nothing_unread_is_not_marked() {
    let fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/shipper/cursors", &ssh, 100, NOW - 4000);
    let r = fx.walk();
    assert_eq!(r.marked(), None, "{}", r.out);
    assert_eq!(r.state("ship"), "idle", "{}", r.out);
}

/// Step 5 item 6 of the split deployment page quotes what the walk prints on a healthy collector,
/// where the installed config-check reports no finding (it leaves the daemon's checks to the
/// control node), and says the walk exits 0 there. Each quoted phrase must still be what the walk
/// prints, so a change of wording in the walk fails here instead of leaving the page describing
/// output nobody sees.
#[test]
fn the_walk_on_a_healthy_collector_prints_what_the_split_deployment_page_quotes() {
    let page = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/operations/split-deployment.md"
    ))
    .unwrap();
    let start = page
        .find("\n6. `sudo propolis-status` on each host")
        .expect("split-deployment.md step 5 has no item 6 on sudo propolis-status");
    let item: String = page[start + 1..]
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/shipper/cursors", &ssh, 100, NOW - 4000);
    // What the installed config-check reports on a healthy collector: nothing.
    fx.tsv(&[]);
    let r = fx.walk();
    for phrase in [
        "collector",
        "idle",
        "all readable by propolis-shipper",
        "on the control node: run sudo propolis-status there",
    ] {
        assert!(
            item.contains(&format!("`{phrase}`")),
            "item 6 no longer quotes `{phrase}`: {item}"
        );
        assert!(
            r.out.contains(phrase),
            "item 6 quotes `{phrase}`, which the walk on a collector does not print:\n{}",
            r.out
        );
    }
    assert!(r.out.contains(" = honeybox - collector - "), "{}", r.out);
    assert_eq!(r.state("ship"), "idle", "{}", r.out);
    assert!(
        r.row("source").contains("all readable by propolis-shipper"),
        "{}",
        r.out
    );
    assert!(
        r.row("gateway")
            .contains("on the control node: run sudo propolis-status there"),
        "{}",
        r.out
    );
    assert_eq!(r.marked(), None, "{}", r.out);
    let check = r
        .out
        .lines()
        .find(|l| l.starts_with("CHECK "))
        .unwrap_or_else(|| panic!("no CHECK line:\n{}", r.out));
    assert!(!check.contains("ids:"), "{check}");
    let item = item.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        item.contains("names no finding"),
        "item 6 must say the CHECK line names no finding on a healthy collector: {item}"
    );
    assert_eq!(
        r.code, 0,
        "item 6 says the walk exits 0 on a healthy collector:\n{}",
        r.out
    );
    assert!(item.contains("exits 0"), "{item}");
    assert!(!item.contains("exits 1"), "{item}");
}

#[test]
fn an_unlisted_spool_is_marked_at_the_gateway() {
    let fx = Fx::control();
    fx.write("var/spool/propolis/gateway/collector-01/events.jsonl", "x");
    fx.tsv(&[("fail", "spool-unlisted", "gateway-spool")]);
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert!(
        r.out.contains(" - control node (1 collectors in spool) - "),
        "{}",
        r.out
    );
    assert!(
        r.row("listen")
            .contains("listeners on collectors: run status there")
            || r.out.contains("collectors (remote)")
    );
    assert_eq!(r.marked().as_deref(), Some("gateway"), "{}", r.out);
    assert!(
        r.row("gateway").contains("findings: spool-unlisted"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status gateway  -  runbook"),
        "{}",
        r.out
    );
}

#[test]
fn a_dead_daemon_is_marked_at_intake_with_lag_from_cursor_files() {
    let mut fx = Fx::single();
    fx.unit(
        "propolis.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    fx.setenv("STUB_READY_CODE", "none");
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/cursors", &ssh, 0, NOW - 2640);
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    let row = r.row("intake");
    assert!(
        row.contains("propolis.service failed (Result=exit-code)"),
        "{row}"
    );
    assert!(row.contains("100 B behind (cursor files)"), "{row}");
    assert!(
        row.contains("/ready not asked (daemon not running)"),
        "{row}"
    );
    assert_eq!(r.state("monitor"), "FAIL", "{}", r.out);
    assert!(
        r.row("monitor").contains("down with the daemon"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("ALERTS  target ntfy from propolis.env - gate full (checked 07:50:00, 10 min) - daemon monitor down"),
        "{}",
        r.out
    );
}

/// `/ready` naming a subsystem that gave up stops intake directly; the names come from the
/// daemon and print only as plain ids.
#[test]
fn a_ready_answer_naming_a_subsystem_that_gave_up_stops_intake() {
    let mut fx = Fx::single();
    fx.setenv("STUB_READY_CODE", "503");
    fx.setenv(
        "STUB_READY_BODY",
        "{\"status\":\"unavailable\",\"gave_up\":[\"intake:ssh\",\"review\"]}",
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert!(
        r.row("intake")
            .contains("/ready 503 (gave up: {?} {review})"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status intake  -  runbook"),
        "{}",
        r.out
    );
    assert!(r.out.contains("#daemon-down"), "{}", r.out);
}

/// The names come from whoever answers on the console port; root never expands them as patterns
/// (the walk runs in `/`, where `*` would list the root directory).
#[test]
fn ready_names_that_are_glob_patterns_are_never_expanded() {
    let mut fx = Fx::single();
    fx.setenv("STUB_READY_CODE", "503");
    fx.setenv("STUB_READY_BODY", "{\"gave_up\":[\"*\",\"review\"]}");
    let r = fx.walk();
    assert!(
        r.row("intake").contains("(gave up: {?} {review})"),
        "{}",
        r.out
    );
    for entry in ["{etc}", "{usr}", "{bin}", "{proc}"] {
        assert!(!r.out.contains(entry), "{entry} in:\n{}", r.out);
    }
}

/// With the daemon down anyone could be listening on the console port, so the walk neither asks
/// it nor sends it the metrics token.
#[test]
fn a_daemon_that_is_not_running_is_not_asked_and_gets_no_token() {
    let mut fx = Fx::single();
    fx.env_line("PROPOLIS_CONSOLE_METRICS_TOKEN=metrics_secret");
    fx.unit(
        "propolis.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let r = fx.walk();
    assert!(
        r.row("intake")
            .contains("/ready not asked (daemon not running)"),
        "{}",
        r.out
    );
    let log = fx.log();
    assert!(
        !log.lines().any(|l| l.starts_with("curl ")),
        "the console was asked: {log}"
    );
    assert!(!log.contains("header-file "), "{log}");
}

#[test]
fn intake_behind_with_an_old_cursor_is_marked_and_the_ledger_is_not() {
    let fx = Fx::single();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/cursors", &ssh, 30, NOW - 1200);
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert!(r.row("intake").contains("70 B behind"), "{}", r.out);
    assert_eq!(r.state("ledger"), "ok", "{}", r.out);
}

/// A cursor is written by a less privileged account than the one that runs the walk. A number
/// with leading zeros there is read as decimal: bash arithmetic would take `08` for a bad octal
/// number, and that error ends the walk.
#[test]
fn a_cursor_offset_with_leading_zeros_is_read_as_decimal() {
    let fx = Fx::single();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    let rel = format!("var/lib/propolis/cursors/{}", cursor_name(&ssh));
    fx.write(&rel, "{\"offset\":08}");
    set_mtime(&fx.p(&rel), NOW - 1200);
    let r = fx.walk();
    assert!(!r.err.contains("value too great for base"), "{}", r.err);
    assert_eq!(
        r.marked().as_deref(),
        Some("intake"),
        "{}\n{}",
        r.out,
        r.err
    );
    assert!(r.row("intake").contains("92 B behind"), "{}", r.out);
    assert!(r.out.contains("IDS"), "the walk reached its end: {}", r.out);
}

#[test]
fn a_database_outage_with_the_connect_failure_line_marks_the_ledger() {
    let mut fx = Fx::single();
    fx.unit(
        "propolis.service",
        "activating",
        "auto-restart",
        "exit-code",
        "enabled",
    );
    fx.setenv("PG_RC", "2");
    fx.setenv(
        "PG_ERR",
        "psql: error: connection to server failed: could not connect: Connection refused",
    );
    fx.setenv(
        "JOURNAL_LINE",
        "2027-01-15T07:59:00Z ERROR propolis: failed to connect to PostgreSQL",
    );
    fx.setenv("STUB_READY_CODE", "none");
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("ledger"), "{}", r.out);
    assert!(
        r.row("ledger").contains("select 1: db.unreachable"),
        "{}",
        r.out
    );
    assert_eq!(r.state("intake"), "starved", "{}", r.out);
    assert!(
        r.row("intake").contains("cannot start: database"),
        "{}",
        r.out
    );
    assert_eq!(r.state("review"), "?", "{}", r.out);
    assert!(
        r.row("review").contains("database not answering"),
        "{}",
        r.out
    );
    let log = fx.log();
    assert!(
        log.contains(&format!(
            "_SYSTEMD_UNIT=propolis.service _UID=4242 _SYSTEMD_INVOCATION_ID={INVOCATION}"
        )),
        "matched only by trusted fields: {log}"
    );
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status ledger  -  runbook"),
        "{}",
        r.out
    );
}

#[test]
fn the_connect_failure_line_from_another_unit_does_not_move_the_marker() {
    let mut fx = Fx::single();
    fx.unit(
        "propolis.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    fx.setenv("PG_RC", "2");
    fx.setenv(
        "PG_ERR",
        "psql: error: could not connect: Connection refused",
    );
    fx.setenv("JOURNAL_LINE", "propolis: failed to connect to PostgreSQL");
    fx.setenv("JOURNAL_LINE_UNIT", "sensor-ssh.service");
    let r = fx.walk();
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert!(
        r.row("intake").contains("database also unreachable"),
        "{}",
        r.out
    );
    assert_eq!(r.state("ledger"), "FAIL", "{}", r.out);
    assert!(r.row("ledger").contains("(also)"), "{}", r.out);
}

#[test]
fn a_psql_that_cannot_run_is_unknown_not_an_outage() {
    let mut fx = Fx::single();
    fx.setenv("PG_RC", "126");
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert_eq!(r.state("ledger"), "?", "{}", r.out);
    assert!(r.row("ledger").contains("tool.exec"), "{}", r.out);
    assert_eq!(r.marked(), None, "{}", r.out);
    for stage in ["review", "reports"] {
        assert!(
            r.row(stage).contains("ledger not read (tool.exec)"),
            "{stage}: {}",
            r.out
        );
        assert!(
            !r.row(stage).contains("database not answering"),
            "nobody saw an outage: {}",
            r.out
        );
    }
}

#[test]
fn a_binary_without_pg_exec_is_never_run() {
    let fx = Fx::single();
    write_exec(
        &fx.p("usr/local/bin/propolis"),
        &PROPOLIS_STUB.replace("propolis pg-exec:", "old:"),
    );
    let r = fx.walk();
    assert_eq!(r.state("ledger"), "?", "{}", r.out);
    assert!(
        r.row("ledger").contains("daemon binary predates pg-exec"),
        "{}",
        r.out
    );
    assert!(!fx.log().contains("propolis pg-exec"), "{}", fx.log());
}

/// A FIFO would hang a plain read and a link would reach whatever it names; both read as
/// unknown with the reason, and the walk ends.
#[test]
fn a_cursor_that_is_a_fifo_or_a_link_reads_as_unknown_and_does_not_hang() {
    let fx = Fx::single();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    let http = fx.p("var/log/propolis/http/events.jsonl");
    let ssh_cursor = fx.p(&format!("var/lib/propolis/cursors/{}", cursor_name(&ssh)));
    let http_cursor = fx.p(&format!("var/lib/propolis/cursors/{}", cursor_name(&http)));
    std::fs::remove_file(&ssh_cursor).unwrap();
    std::fs::remove_file(&http_cursor).unwrap();
    let status = Command::new("mkfifo").arg(&ssh_cursor).status().unwrap();
    assert!(status.success());
    std::os::unix::fs::symlink("/etc/shadow", &http_cursor).unwrap();
    let started = std::time::Instant::now();
    let r = fx.walk();
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(r.state("intake"), "?", "{}", r.out);
    let row = r.row("intake");
    assert!(row.contains("{ssh} cursor not a regular file"), "{row}");
    assert!(row.contains("{http} cursor not a regular file"), "{row}");
}

#[test]
fn untrusted_names_are_braced_or_withheld() {
    let fx = Fx::control();
    for name in ["collector-01", "evil\u{1b}[31m", "bidi\u{202e}cn"] {
        fx.write(
            &format!("var/spool/propolis/gateway/{name}/events.jsonl"),
            "x",
        );
    }
    // The gateway account owns the collector directories: a file name holding a newline must not
    // forge a listing record whose size root then evaluates.
    fx.write(
        "var/spool/propolis/gateway/collector-01/junk\nBASH_VERSINFO[$(printf${IFS}PWNED>&2)0] 1 events.jsonl",
        "",
    );
    let r = fx.walk();
    assert!(!r.err.contains("PWNED"), "{}", r.err);
    assert!(r.out.contains("{collector-01}"), "{}", r.out);
    assert!(
        r.row("gateway").contains("1 collectors in spool, 1 B;"),
        "{}",
        r.out
    );
    assert!(
        r.row("gateway").contains("2 name withheld: not a plain id"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains(" - control node (3 collectors in spool) - "),
        "every directory counts, withheld names included: {}",
        r.out
    );
    assert!(
        !r.out.contains('\u{1b}') && !r.out.contains('\u{202e}'),
        "{}",
        r.out
    );
    assert!(r.out.is_ascii(), "{}", r.out);
}

#[test]
fn journal_text_is_cleaned_and_marked_in_the_stage_view_and_absent_from_the_walk() {
    let mut fx = Fx::single();
    fx.unit(
        "sensor-ssh.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let text = fx.dir.path().join("journal.txt");
    std::fs::write(
        &text,
        format!(
            "red \u{1b}[31malert\u{1b}[0m here\nreturn\rforged\nflip \u{202e}txt.exe\n{}\n",
            "y".repeat(500)
        ),
    )
    .unwrap();
    fx.setenv("JOURNAL_TEXT", &text.display().to_string());
    let walk = fx.walk();
    for raw in ["[untrusted] r", "[31m", "forged", "txt.exe", "yyyy"] {
        assert!(!walk.out.contains(raw), "{raw} in the walk:\n{}", walk.out);
    }
    let view = fx.run(&["listen"]);
    assert_eq!(view.code, 2, "{}\n{}", view.out, view.err);
    assert!(view.out.is_ascii(), "{}", view.out);
    assert!(
        !view.out.contains('\u{1b}') && !view.out.contains('\r'),
        "{:?}",
        view.out
    );
    let lines: Vec<&str> = view
        .out
        .lines()
        .filter(|l| l.contains("[untrusted] "))
        .collect();
    assert_eq!(lines.len(), 4, "{}", view.out);
    assert!(
        lines[0].contains("[untrusted] red ?[31malert?[0m here"),
        "{lines:?}"
    );
    assert!(lines[1].contains("return?forged"), "{lines:?}");
    assert!(lines[2].contains("flip ???txt.exe"), "{lines:?}");
    assert_eq!(
        lines[3].trim_start().len(),
        "[untrusted] ".len() + 200,
        "{lines:?}"
    );
}

/// The walk writes nothing (the tree under the root and the temporary directory are the same
/// after it) and connects only to the console on loopback.
#[test]
fn the_walk_writes_nothing_and_reaches_only_loopback() {
    let mut fx = Fx::single();
    fx.write(
        "etc/propolis/propolis.env",
        &(std::fs::read_to_string(fx.p("etc/propolis/propolis.env")).unwrap()
            + "PROPOLIS_CONSOLE_METRICS_TOKEN=metrics_secret\n"),
    );
    fx.setenv("UNUSED", "1");
    let snapshot = |root: &Path| {
        let out = Command::new("find")
            .arg(root)
            .arg("-printf")
            .arg("%p %y %s %m %T@\n")
            .output()
            .unwrap();
        let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(String::from)
            .collect();
        lines.sort();
        lines
    };
    let before = snapshot(&fx.root);
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    assert_eq!(snapshot(&fx.root), before);
    let tmp: Vec<_> = std::fs::read_dir(fx.dir.path().join("tmp"))
        .unwrap()
        .collect();
    assert!(tmp.is_empty(), "left in the temporary directory: {tmp:?}");
    let log = fx.log();
    let curls: Vec<&str> = log.lines().filter(|l| l.starts_with("curl ")).collect();
    assert_eq!(curls.len(), 2, "{log}");
    for call in curls {
        assert!(
            call.ends_with("[http://127.0.0.1:8080/ready]")
                || call.ends_with("[http://127.0.0.1:8080/metrics]"),
            "{call}"
        );
        assert!(
            call.contains("[--proto] [=http]") && call.contains("[--max-time] [5]"),
            "{call}"
        );
    }
}

#[test]
fn the_metrics_token_never_reaches_a_command_line() {
    let fx = Fx::single();
    fx.write(
        "etc/propolis/propolis.env",
        &(std::fs::read_to_string(fx.p("etc/propolis/propolis.env")).unwrap()
            + "PROPOLIS_CONSOLE_METRICS_TOKEN=metrics_secret\n"),
    );
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    let log = fx.log();
    assert!(
        log.lines()
            .filter(|l| !l.starts_with("header-file "))
            .all(|l| !l.contains("metrics_secret")),
        "{log}"
    );
    assert!(
        log.contains(": Authorization: Bearer metrics_secret"),
        "{log}"
    );
    for secret in [
        "metrics_secret",
        "tk_secret",
        "t0p1c-secret",
        "postgres://",
        ":pw@",
    ] {
        assert!(
            !r.out.contains(secret) && !r.err.contains(secret),
            "{secret} printed:\n{}",
            r.out
        );
    }
    let alert = fx.run(&["alert"]);
    for secret in ["tk_secret", "t0p1c-secret", "ntfy.example.invalid"] {
        assert!(
            !alert.out.contains(secret),
            "{secret} printed:\n{}",
            alert.out
        );
    }
    assert!(
        alert
            .out
            .contains("PROPOLIS_OPS_NTFY_TOKEN set in propolis.env"),
        "{}",
        alert.out
    );
}

#[test]
fn a_non_root_caller_is_refused() {
    let mut fx = Fx::single();
    fx.setenv("PROPOLIS_STATUS_EUID", "1000");
    std::fs::remove_file(fx.p("usr/local/sbin/propolis-alert-lib")).unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 3, "{}", r.err);
    assert_eq!(
        r.err.trim(),
        "propolis-status needs root: run sudo propolis-status"
    );
    assert!(r.out.is_empty());
    assert_eq!(fx.log(), "", "nothing read");
    let help = fx.run(&["-h"]);
    assert_eq!(help.code, 0, "{}", help.err);
    assert!(
        help.out.starts_with("usage: propolis-status"),
        "{}",
        help.out
    );
}

#[test]
fn bad_usage_exits_64() {
    let fx = Fx::single();
    for args in [
        vec!["nosuch"],
        vec!["listen", "ship"],
        vec!["--setup", "listen"],
        vec!["--test-page", "--setup"],
        vec!["--ack", "w#1"],
        vec!["--ack-test", "zzzzzz"],
        vec!["--ack-test"],
        vec!["--ack-test", "ABCDEF"],
        vec!["--ack-test", "abc12"],
        vec!["--ack-test", "abc1234"],
        vec!["--ack-test", "../../x"],
        vec!["--maint"],
        vec!["--maint", "121"],
        vec!["--maint", "-1"],
        vec!["--maint", "1000"],
        vec!["--maint", "3x"],
        vec!["--banner", "listen"],
        vec!["listen", "--banner"],
        vec!["--maint", "30", "--banner"],
    ] {
        let r = fx.run(&args);
        assert_eq!(r.code, 64, "{args:?}: {}", r.err);
        assert!(
            r.err.contains("usage: propolis-status"),
            "{args:?}: {}",
            r.err
        );
    }
    assert_eq!(fx.log(), "", "nothing read before the usage check");
    let help = fx.run(&["--help"]);
    for verb in ["--ack ", "--ack ID"] {
        assert!(!help.out.contains(verb), "{verb} offered:\n{}", help.out);
    }
    for verb in [
        "--banner",
        "--maint MINUTES",
        "witness",
        "--setup",
        "--test-page",
        "--ack-test CODE",
    ] {
        assert!(help.out.contains(verb), "{verb} not offered:\n{}", help.out);
    }
}

#[test]
fn exit_codes_follow_the_table() {
    let fx = Fx::single();
    assert_eq!(fx.walk().code, 0);

    let mut warn = Fx::single();
    warn.setenv("NTP", "no");
    let r = warn.walk();
    assert_eq!(r.code, 1, "a WARN rail: {}", r.out);
    assert_eq!(r.state("host"), "WARN");
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status host  -  runbook -"),
        "{}",
        r.out
    );

    let found = Fx::single();
    found.tsv(&[("warn", "env-none", "env-files")]);
    assert_eq!(found.walk().code, 1, "a finding no row maps still counts");

    let mut stopped = Fx::single();
    stopped.unit(
        "sensor-ssh.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    assert_eq!(stopped.walk().code, 2);

    let rail = Fx::single();
    rail.write(
        "var/lib/propolis/backup-status/last-failure",
        r#"{"failed_at":"2027-01-15T03:30:00Z","reason":"scheduled","step":"dumping the database","exit_code":1}"#,
    );
    let r = rail.walk();
    assert_eq!(r.code, 2, "a FAIL rail: {}", r.out);
    assert_eq!(r.marked(), None);
    assert!(
        r.row("backup")
            .contains("last run failed while dumping the database"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status backup  -  runbook"),
        "{}",
        r.out
    );

    let mut nonroot = Fx::single();
    nonroot.setenv("PROPOLIS_STATUS_EUID", "1000");
    assert_eq!(nonroot.walk().code, 3);
    assert_eq!(fx.run(&["nosuch"]).code, 64);

    let old = Fx::single();
    let lib = std::fs::read_to_string(LIB).unwrap();
    let version = lib
        .lines()
        .find_map(|l| l.strip_prefix("PA_LIB_VERSION="))
        .unwrap();
    old.write(
        "usr/local/sbin/propolis-alert-lib",
        &lib.replace(
            &format!("\nPA_LIB_VERSION={version}\n"),
            "\nPA_LIB_VERSION=2\n",
        ),
    );
    let r = old.walk();
    assert_eq!(r.code, 70, "an older library: {}", r.err);
    let needs = std::fs::read_to_string(SCRIPT)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("# needs-alert-lib: ").map(str::to_string))
        .unwrap();
    assert!(
        r.err.contains(&format!("older than version {needs}")),
        "{}",
        r.err
    );
    let missing = Fx::single();
    std::fs::remove_file(missing.p("usr/local/sbin/propolis-alert-lib")).unwrap();
    let r = missing.walk();
    assert_eq!(r.code, 70);
    assert!(
        r.err.contains("reinstall it from the checkout"),
        "{}",
        r.err
    );
    assert!(
        !r.err.contains("chmod"),
        "a missing file is not a permission fault: {}",
        r.err
    );
    let broken = Fx::single();
    broken.write("usr/local/sbin/propolis-alert-lib", "echo $UNSET_AT_TOP\n");
    assert_eq!(broken.walk().code, 70);
}

/// A lockless reader writes nothing, so a damaged state file is not set aside: the walk must say
/// it could not read it, or a damaged `meta` would show as an empty, healthy state.
#[test]
fn an_unreadable_state_file_is_named_and_counts_as_unknown() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v9 g=1\nM\twhere\tpersistent\n",
    );
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .contains("STATE   state file meta unreadable: shown as empty"),
        "{}",
        r.out
    );
    assert!(
        fx.p("var/lib/propolis/witness/meta").exists(),
        "not renamed"
    );
    assert!(!fx.log().contains("logger"), "nothing logged");
    assert!(
        r.out
            .contains("        witness light ? - hourly ? - state ? (meta unreadable) - banner "),
        "{}",
        r.out
    );
    assert!(!r.out.contains("nothing recorded yet"), "{}", r.out);

    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v2 g=3\nN\t2\n{}",
            record(
                "w#1",
                "unit:sensor-ssh.service",
                "listen",
                "PAGE",
                "pending",
                NOW - 60,
                "proc.exit:1",
                "delivered"
            )
        ),
    );
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .contains("STATE   state file incidents unreadable: shown as empty"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("RECENT FAILURES  ? (incidents unreadable: see STATE)"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("none recorded"), "{}", r.out);
    // Every other line that counts from the same file says so too.
    assert!(
        r.out
            .contains("24 H    ? (incidents unreadable: see STATE)"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("resolved 0"), "{}", r.out);

    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v9 g=1\nM\twhere\tpersistent\n",
    );
    let view = fx.run(&["host"]);
    assert!(
        view.out.contains("    state written: ? (meta unreadable)"),
        "{}",
        view.out
    );
    assert!(!view.out.contains("nothing recorded yet"), "{}", view.out);
}

#[test]
fn the_maintenance_marker_a_clock_step_and_where_state_landed_show_in_the_header() {
    let fx = Fx::single();
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\tabcdef01\tupgrade\n", NOW + 600),
    );
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=2\nM\twhere\trun\nM\tclock_step\t{}/abcdef01/899000/+300\n",
            NOW - 1000
        ),
    );
    let r = fx.walk();
    assert!(
        r.out
            .contains("MAINT   upgrade until 08:10:00 (10 min left): unit kinds held\n"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains(
            "CLOCK   stepped +300 s at 07:43:20: times in messages since then may be wrong"
        ),
        "{}",
        r.out
    );
    assert!(
        r.out.contains(" - state not persisted (run) - "),
        "{}",
        r.out
    );
    assert_eq!(r.state("host"), "WARN", "{}", r.out);
}

#[test]
fn a_config_check_that_does_not_finish_leaves_its_rows_unknown() {
    let fx = Fx::single();
    std::fs::write(
        fx.dir.path().join("cc.tsv"),
        "#config-check tsv v1\nS\tok\t0\t0\t0\t0\t1\t1\t1\nF\tfail\tx\t-\t-\t-\t-\n",
    )
    .unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .contains("CHECK   config-check did not finish (output cut short)"),
        "{}",
        r.out
    );
    assert!(r.row("listen").ends_with("findings ?"), "{}", r.out);
}

#[test]
fn every_stage_view_prints_its_row_and_ends() {
    let fx = Fx::single();
    fx.tsv_with(&[], &[("sensor-ssh", "sensor-ssh.service", "ok")]);
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    // What each view adds beyond its row; the ship and gateway views on the topologies
    // that have them are checked with those fixtures.
    let ssh_line = format!(
        "    {{ssh}} {}: regular, 100 bytes, modified 07:59:54, readable by propolis",
        ssh.display()
    );
    let adds: [(&str, &str); 17] = [
        (
            "listen",
            "    listener sensor-ssh (sensor-ssh.service): unit active, listen 0.0.0.0:22, firewall ok",
        ),
        ("source", ssh_line.as_str()),
        ("ship", ""),
        ("gateway", ""),
        ("intake", "    /ready 200"),
        (
            "ledger",
            "    default_transaction_read_only (database and role settings): not set",
        ),
        ("review", "    pending 3; last surfaced 07:59:23"),
        (
            "reports",
            "    {abuseipdb} last attempt 07:43:00, last success 06:36:40, last status 500, 4 attempts since the last success",
        ),
        ("feed", "    build_time not read"),
        ("publish", "    last pushed 07:44:00; push expected"),
        ("alert", "    daemon queue: empty"),
        (
            "backup",
            "    backup directory /var/backups/propolis: not present",
        ),
        ("chain", "verified inside the daemon"),
        ("host", "    clock: synchronized; no step in 24 h"),
        (
            "monitor",
            "    ops monitor on; /ready 200; daemon queue empty",
        ),
        (
            "witness",
            "    propolis-witness@light.timer: ActiveState=active UnitFileState=enabled",
        ),
        ("peers", "cannot be seen from this host"),
    ];
    for (stage, add) in adds {
        let r = fx.run(&[stage]);
        assert!(r.code == 0, "{stage}: {}\n{}", r.out, r.err);
        assert!(
            r.out.contains(" #  stage     instance"),
            "{stage}: {}",
            r.out
        );
        r.row(stage);
        assert!(!r.out.contains("RECENT FAILURES"), "{stage}: {}", r.out);
        assert!(r.out.is_ascii(), "{stage}");
        assert!(r.out.contains(add), "{stage} lacks {add:?}:\n{}", r.out);
    }
    let host = fx.run(&["host"]);
    assert!(host.out.contains("    id salt: present"), "{}", host.out);
}

/// The lines of the walk that are rows of `stage`.
fn rows<'a>(r: &'a Run, stage: &str) -> Vec<&'a str> {
    r.out
        .lines()
        .filter(|l| l.get(4..).unwrap_or("").starts_with(&format!("{stage} ")))
        .collect()
}

/// When the lock is busy or its time nearly spent, the hook writes the firing to its spool
/// instead of the record; nothing takes the spool in before the witness, so the walk lists it.
#[test]
fn a_hook_firing_that_went_to_the_spool_is_listed_as_spooled() {
    let fx = Fx::single();
    let s = stamp_ago(120);
    fx.write(
        "var/lib/propolis/witness/hook/sensor-http.service",
        &format!(
            "#hook v1 g=1\nH\t{s}\t{s}\t3\texit-code\texited\t1\tproc.exit:1\t3\tundelivered\n"
        ),
    );
    let f = stamp_ago(60);
    fx.write(
        "run/propolis-witness/fallback/hook-sensor-ssh.service",
        &format!("#hook v1 g=4\nH\t{f}\t{f}\t1\tsignal\tkilled\t9\tproc.signal:9\t1\t-\n"),
    );
    fx.write(
        "var/lib/propolis/witness/hook/forged",
        "#hook v1 g=1\nH\tnot a stamp\n",
    );
    // A file a witness pass claimed to take in, and did not finish: still firings no record has.
    fx.write(
        "var/lib/propolis/witness/hook/.ingest.4242.shipper.service",
        &format!("#hook v1 g=2\nH\t{f}\t{f}\t2\texit-code\texited\t1\tproc.exit:1\t-\t-\n"),
    );
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    let shipper = r
        .out
        .lines()
        .find(|l| l.contains("{shipper.service}") && l.contains("[spooled, not yet in the record]"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(shipper.contains("(2 firings)"), "{shipper}");
    assert!(!r.out.contains(".ingest."), "{}", r.out);
    assert!(
        r.out
            .contains("RECENT FAILURES (not judged: no witness pass has run on this host)"),
        "{}",
        r.out
    );
    let http = r
        .out
        .lines()
        .find(|l| l.contains("{sensor-http.service}"))
        .unwrap_or_else(|| panic!("{}", r.out));
    for part in [
        "failed 07:58:00",
        "(3 firings)",
        "cause proc.exit 1",
        "[legacy hook: undelivered]",
        "[spooled, not yet in the record]",
    ] {
        assert!(http.contains(part), "{part:?} not in {http}");
    }
    // The spooled line names the unit by the same opaque id the IDS line gives it.
    let ids = r
        .out
        .lines()
        .find(|l| l.starts_with("IDS"))
        .unwrap_or_else(|| panic!("{}", r.out));
    let id = ids
        .split_whitespace()
        .find(|t| t.ends_with("={sensor-http.service}"))
        .unwrap_or_else(|| panic!("no id for the spooled unit in {ids}"));
    assert!(
        id.starts_with('u') && id.len() > "={sensor-http.service}".len() + 5,
        "{id}"
    );
    assert!(http.contains(id), "{id} not in {http}");
    let ssh = r
        .out
        .lines()
        .find(|l| l.contains("{sensor-ssh.service}"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(
        ssh.contains("cause proc.signal 9") && ssh.contains("[spooled, not yet in the record]"),
        "{ssh}"
    );
    assert!(!r.out.contains("forged"), "{}", r.out);
}

/// The shipper resumes a rotated log at offset 0 once it notices: a young cursor on the old
/// inode is in between, an old one has stalled and its whole new file is unread.
#[test]
fn a_shipper_cursor_on_a_rotated_log_is_unknown_while_young_and_stalled_once_older_than_stall() {
    let fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    let rel = format!("var/lib/propolis/shipper/cursors/{}", cursor_name(&ssh));
    fx.write(&rel, "{\"inode\":1,\"offset\":50}");
    set_mtime(&fx.p(&rel), NOW - 60);
    fx.write("var/lib/propolis/shipper/state/k1.json", "{}");
    set_mtime(&fx.p("var/lib/propolis/shipper/state/k1.json"), NOW - 60);
    let r = fx.walk();
    assert_eq!(r.state("ship"), "?", "{}", r.out);
    assert!(
        r.row("ship").contains("{ssh} rotated, not resumed yet"),
        "{}",
        r.out
    );
    assert!(!r.row("ship").contains("nothing unread"), "{}", r.out);

    set_mtime(&fx.p(&rel), NOW - 86400);
    set_mtime(&fx.p("var/lib/propolis/shipper/state/k1.json"), NOW - 86400);
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.state("ship"), "FAIL", "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("ship"), "{}", r.out);
    assert!(r.row("ship").contains("unread 100 B in {ssh}"), "{}", r.out);
    assert!(r.out.contains("#ship-failing"), "{}", r.out);
}

#[test]
fn a_cursor_without_an_offset_or_a_time_is_unknown_not_a_failure() {
    let fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    let rel = format!("var/lib/propolis/shipper/cursors/{}", cursor_name(&ssh));
    fx.write(&rel, "{\"inode\":123");
    set_mtime(&fx.p(&rel), NOW - 86400);
    fx.write("var/lib/propolis/shipper/state/k1.json", "{}");
    set_mtime(&fx.p("var/lib/propolis/shipper/state/k1.json"), NOW - 86400);
    let r = fx.walk();
    assert_eq!(r.state("ship"), "?", "{}", r.out);
    assert!(r.row("ship").contains("{ssh} cursor unparsed"), "{}", r.out);
    assert_eq!(r.marked(), None, "{}", r.out);

    // Intake: a cursor behind whose time cannot be read is unknown, not old.
    let mut fx = Fx::single();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/cursors", &ssh, 30, NOW - 3);
    let cur = fx.p(&format!("var/lib/propolis/cursors/{}", cursor_name(&ssh)));
    fx.setenv("BREAK_STAT", &cur.display().to_string());
    let r = fx.walk();
    assert_eq!(r.state("intake"), "?", "{}", r.out);
    assert!(
        r.row("intake").contains("{ssh} cursor cannot be read"),
        "{}",
        r.out
    );
    assert_eq!(r.marked(), None, "{}", r.out);
}

#[test]
fn an_alert_env_on_a_collector_is_named_as_inert_under_legacy() {
    let fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/shipper/cursors", &ssh, 100, NOW - 60);
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC=t0p1c-secret\n",
    );
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert_eq!(r.state("alert"), "WARN", "{}", r.out);
    assert!(
        r.row("alert")
            .contains("alert.env present, profile legacy: it acts only under v2"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("t0p1c-secret"), "{}", r.out);
}

/// pa_pg opens every session read-only, so `SHOW transaction_read_only` would say `on` on a
/// healthy primary; the view shows the database's and the role's own setting instead.
#[test]
fn the_ledger_view_never_reports_its_own_read_only_session_as_the_servers_setting() {
    let mut fx = Fx::single();
    let r = fx.run(&["ledger"]);
    assert!(!r.out.contains("transaction_read_only: on"), "{}", r.out);
    assert!(
        r.out
            .contains("    default_transaction_read_only (database and role settings): not set"),
        "{}",
        r.out
    );
    fx.setenv("ROLE_SETTING", "default_transaction_read_only=on");
    let r = fx.run(&["ledger"]);
    assert!(
        r.out.contains(
            "    default_transaction_read_only (database and role settings): default_transaction_read_only=on"
        ),
        "{}",
        r.out
    );
}

/// The check before sourcing is what keeps an untrusted file from running as root: the library's
/// own check runs only after the file has been sourced.
#[test]
fn a_library_in_an_untrusted_directory_is_never_sourced() {
    let fx = Fx::single();
    let marker = fx.dir.path().join("sourced");
    let lib = std::fs::read_to_string(LIB).unwrap();
    fx.write(
        "usr/local/sbin/propolis-alert-lib",
        &format!("touch '{}'\n{lib}", marker.display()),
    );
    std::fs::set_permissions(
        fx.p("usr/local/sbin"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 70, "{}", r.err);
    assert!(r.err.contains("group-writable"), "{}", r.err);
    assert!(!marker.exists(), "the library ran before it was trusted");
}

#[test]
fn a_library_that_exits_at_its_top_level_ends_the_walk_with_70() {
    let fx = Fx::single();
    fx.write(
        "usr/local/sbin/propolis-alert-lib",
        "PA_LIB_VERSION=3; exit 0\n",
    );
    let r = fx.walk();
    assert_eq!(r.code, 70, "{}\n{}", r.out, r.err);
    assert!(
        r.err.contains("reinstall it from the checkout"),
        "{}",
        r.err
    );
    assert!(r.out.is_empty(), "{}", r.out);
}

#[test]
fn a_library_missing_a_function_the_walk_needs_ends_it_with_70() {
    let fx = Fx::single();
    let lib = std::fs::read_to_string(LIB).unwrap();
    assert!(lib.contains("\npa_pg() {"));
    fx.write(
        "usr/local/sbin/propolis-alert-lib",
        &lib.replace("\npa_pg() {", "\npa_pg_renamed() {"),
    );
    let r = fx.walk();
    assert_eq!(r.code, 70, "{}\n{}", r.out, r.err);
    assert!(
        r.err.contains("reinstall it from the checkout"),
        "{}",
        r.err
    );
}

#[test]
fn an_untrusted_config_check_or_daemon_binary_is_never_run_and_the_line_gives_the_fix() {
    let fx = Fx::single();
    std::fs::set_permissions(
        fx.p("usr/local/lib/propolis"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    let check = r
        .out
        .lines()
        .find(|l| l.starts_with("CHECK   "))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(
        check.contains("config-check did not finish (not trusted: "),
        "{check}"
    );
    assert!(check.contains("chmod g-w"), "{check}");
    assert!(
        !fx.log().lines().any(|l| l.starts_with("config-check")),
        "{}",
        fx.log()
    );

    let fx = Fx::single();
    std::fs::set_permissions(
        fx.p("usr/local/bin"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let r = fx.walk();
    assert_eq!(r.state("ledger"), "?", "{}", r.out);
    assert!(
        r.row("ledger").contains("not trusted: ") && r.row("ledger").contains("chmod g-w"),
        "{}",
        r.out
    );
    assert!(!fx.log().contains("propolis pg-exec"), "{}", fx.log());
}

#[test]
fn a_config_check_that_fails_times_out_or_prints_no_tsv_leaves_its_rows_unknown() {
    let mut fx = Fx::single();
    fx.setenv("CC_RC", "70");
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .contains("CHECK   config-check did not finish (exit 70)"),
        "{}",
        r.out
    );
    assert!(r.row("listen").ends_with("findings ?"), "{}", r.out);

    fx.setenv("CC_RC", "0");
    std::fs::write(fx.dir.path().join("cc.tsv"), "everything is fine\n").unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .contains("CHECK   config-check did not finish (no machine-readable output)"),
        "{}",
        r.out
    );
    assert!(r.row("source").ends_with("findings ?"), "{}", r.out);

    fx.tsv(&[]);
    fx.setenv("CC_SLEEP", "30");
    fx.setenv("PROPOLIS_STATUS_CC_LIMIT", "1");
    let started = std::time::Instant::now();
    let r = fx.walk();
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "{:?}",
        started.elapsed()
    );
    assert!(
        r.out
            .contains("CHECK   config-check did not finish (timed out after 1 s)"),
        "{}",
        r.out
    );
    assert_eq!(r.code, 1, "{}", r.out);
}

/// A production run (no test root) must not honour any test seam, the library's included.
#[test]
fn the_test_seams_are_cleared_outside_a_test_root() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let start = script
        .find("\nif [ -z \"$STATUS_ROOT\" ]; then\n")
        .expect("no production branch");
    let block = &script[start..];
    let block = &block[..block.find("\nfi\n").unwrap()];
    for seam in [
        "PA_TEST_WALL",
        "PA_TEST_BOOT",
        "PA_TEST_UP",
        "PA_TEST_READ_AS_SELF",
        "PA_TEST_UID",
        "PA_TEST_PROFILE",
        "PROPOLIS_STATUS_EUID",
        "PROPOLIS_STATUS_NOW",
        "PROPOLIS_STATUS_CC",
        "PROPOLIS_STATUS_CC_LIMIT",
    ] {
        assert!(
            block
                .lines()
                .any(|l| l.trim_start().starts_with("unset ")
                    && l.split_whitespace().any(|w| w == seam)),
            "{seam} is not unset in the production branch:\n{block}"
        );
    }
}

/// A link among the directories is followed and checked where it leads, as the library does.
#[test]
fn a_linked_directory_is_checked_where_it_leads() {
    let fx = Fx::single();
    std::fs::create_dir_all(fx.p("opt/sbin")).unwrap();
    std::fs::set_permissions(fx.p("opt"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::copy(
        fx.p("usr/local/sbin/propolis-alert-lib"),
        fx.p("opt/sbin/propolis-alert-lib"),
    )
    .unwrap();
    std::fs::remove_dir_all(fx.p("usr/local/sbin")).unwrap();
    std::os::unix::fs::symlink("../../opt/sbin", fx.p("usr/local/sbin")).unwrap();
    std::fs::set_permissions(fx.p("opt/sbin"), std::fs::Permissions::from_mode(0o775)).unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 70, "{}", r.err);
    assert!(r.err.contains("/opt/sbin: group-writable ("), "{}", r.err);
    std::fs::set_permissions(fx.p("opt/sbin"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
}

/// A row after the marked one that failed only for lack of progress is starved: the stall
/// upstream explains it.
#[test]
fn a_progress_failure_after_the_marked_stage_reads_starved() {
    let mut fx = Fx::single();
    fx.unit(
        "sensor-ssh.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/cursors", &ssh, 30, NOW - 1200);
    let r = fx.walk();
    assert_eq!(r.marked().as_deref(), Some("listen"), "{}", r.out);
    assert_eq!(r.state("intake"), "starved", "{}", r.out);
}

/// A stage before the marked one that could not be read is named on the marked row, since the
/// stall may lie there instead.
#[test]
fn a_stage_that_could_not_be_read_before_the_marked_one_is_named_on_it() {
    let mut fx = Fx::single();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.setenv("BREAK_READ", &ssh.display().to_string());
    fx.unit(
        "propolis.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let r = fx.walk();
    assert_eq!(r.state("source"), "?", "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert!(
        r.row("intake")
            .ends_with("an earlier stage could not be read: source"),
        "{}",
        r.out
    );
}

/// The override moves the marker only when the daemon itself is down: a `/ready` failure of a
/// running daemon stays on intake even with the trusted line and the database failing.
#[test]
fn a_ready_failure_with_the_daemon_running_keeps_the_marker_on_intake() {
    let mut fx = Fx::single();
    fx.setenv("STUB_READY_CODE", "503");
    fx.setenv("STUB_READY_BODY", "{\"gave_up\":[\"review\"]}");
    fx.setenv("PG_RC", "2");
    fx.setenv(
        "PG_ERR",
        "psql: error: connection to server failed: Connection refused",
    );
    fx.setenv("JOURNAL_LINE", "propolis: failed to connect to PostgreSQL");
    let r = fx.walk();
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert_eq!(r.state("ledger"), "FAIL", "{}", r.out);
    assert!(r.row("ledger").contains("(also)"), "{}", r.out);
}

#[test]
fn a_unit_down_finding_counts_only_while_systemd_says_the_unit_is_down() {
    let mut fx = Fx::single();
    fx.tsv(&[("fail", "unit-down", "sensor-ssh")]);
    let r = fx.walk();
    assert_eq!(r.state("listen"), "ok", "{}", r.out);
    assert_eq!(r.marked(), None, "{}", r.out);
    fx.unit(
        "sensor-ssh.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let r = fx.walk();
    assert_eq!(r.state("listen"), "FAIL", "{}", r.out);
    assert!(r.row("listen").contains("findings: unit-down"), "{}", r.out);
}

#[test]
fn a_firewall_finding_stops_listen_only_when_the_firewall_was_read() {
    let fx = Fx::single();
    fx.tsv_with(
        &[("fail", "fw", "sensor-ssh")],
        &[("sensor-ssh", "sensor-ssh.service", "unknown")],
    );
    let r = fx.walk();
    assert_ne!(r.state("listen"), "FAIL", "{}", r.out);
    assert_eq!(r.marked(), None, "{}", r.out);
    fx.tsv_with(
        &[("fail", "fw", "sensor-ssh")],
        &[("sensor-ssh", "sensor-ssh.service", "warn")],
    );
    let r = fx.walk();
    assert_eq!(r.state("listen"), "FAIL", "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("listen"), "{}", r.out);
}

#[test]
fn a_daily_tier_listen_finding_alone_warns_with_the_finding_key() {
    let fx = Fx::single();
    fx.tsv(&[("warn", "nofw", "sensor-ssh")]);
    let r = fx.walk();
    assert_eq!(r.state("listen"), "WARN", "{}", r.out);
    assert_eq!(r.marked(), None, "{}", r.out);
    assert!(
        r.out.contains("NEXT    sudo propolis-status listen  -  runbook docs/operations/health-and-observability.md#finding"),
        "{}",
        r.out
    );
}

#[test]
fn a_collector_whose_shipper_is_down_is_marked_at_ship() {
    let mut fx = Fx::collector();
    let ssh = fx.p("var/log/propolis/ssh/events.jsonl");
    fx.cursor("var/lib/propolis/shipper/cursors", &ssh, 100, NOW - 60);
    fx.unit(
        "shipper.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("ship"), "{}", r.out);
    assert!(
        r.row("ship").contains("shipper.service failed"),
        "{}",
        r.out
    );
    assert!(r.out.contains("#ship-down"), "{}", r.out);
}

#[test]
fn a_control_node_whose_gateway_is_down_is_marked_at_the_gateway() {
    let mut fx = Fx::control();
    fx.unit(
        "gateway.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("gateway"), "{}", r.out);
    assert!(r.out.contains("#gateway-down"), "{}", r.out);
}

#[test]
fn an_intake_none_finding_marks_intake_with_the_finding_key() {
    let fx = Fx::single();
    fx.tsv(&[("fail", "intake-none", "intake")]);
    let r = fx.walk();
    assert_eq!(r.marked().as_deref(), Some("intake"), "{}", r.out);
    assert!(
        r.out.contains("NEXT    sudo propolis-status intake  -  runbook docs/operations/health-and-observability.md#finding"),
        "{}",
        r.out
    );
}

#[test]
fn a_stale_rotation_finding_marks_source_with_the_rotation_key() {
    let fx = Fx::single();
    fx.tsv(&[("fail", "stale", "ssh")]);
    let r = fx.walk();
    assert_eq!(r.state("source"), "FAIL", "{}", r.out);
    assert!(
        r.out.contains("NEXT    sudo propolis-status source  -  runbook docs/operations/health-and-observability.md#rotation"),
        "{}",
        r.out
    );
}

#[test]
fn a_full_volume_warns_on_the_host_rail() {
    let mut fx = Fx::single();
    fx.setenv("DF_USE", "90%");
    let r = fx.walk();
    assert_eq!(r.state("host"), "WARN", "{}", r.out);
    assert!(
        r.row("host").contains("/var/lib/propolis 90% used"),
        "{}",
        r.out
    );
    assert!(r.out.contains("#volume"), "{}", r.out);
    fx.setenv("DF_USE", "61%");
    fx.setenv("DF_IUSE", "90%");
    let r = fx.walk();
    assert_eq!(r.state("host"), "WARN", "{}", r.out);
    assert!(
        r.row("host").contains("/var/lib/propolis inodes 90% used"),
        "{}",
        r.out
    );
    assert!(r.out.contains("#volume"), "{}", r.out);
}

#[test]
fn state_written_nowhere_fails_the_host_rail_without_marking_a_stage() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/meta",
        "#meta v1 g=1\nM\twhere\tnone\n",
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}", r.out);
    assert_eq!(r.state("host"), "FAIL", "{}", r.out);
    assert_eq!(r.marked(), None, "{}", r.out);
    assert!(
        r.out.contains("NEXT    sudo propolis-status host  -  runbook docs/operations/health-and-observability.md#state"),
        "{}",
        r.out
    );
}

#[test]
fn a_busy_state_lock_shows_in_the_header_and_warns_on_the_host_rail() {
    let fx = Fx::single();
    fx.write("run/propolis-witness/lockwait", "light 3\n");
    let r = fx.walk();
    assert!(
        r.out
            .contains("LOCK    state lock busy for 3 passes: the witness is not recording"),
        "{}",
        r.out
    );
    assert_eq!(r.state("host"), "WARN", "{}", r.out);
    assert!(
        r.row("host").contains("state lock busy (3 passes)"),
        "{}",
        r.out
    );
}

#[test]
fn undelivered_hook_alerts_and_a_daemon_queue_warn_on_the_alert_rail() {
    let fx = Fx::single();
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        "1799990000 2 1799990000\n",
    );
    let r = fx.walk();
    assert!(
        r.out
            .contains("failure hook legacy, 1 units undelivered since 05:13:20"),
        "{}",
        r.out
    );
    assert_eq!(r.state("alert"), "WARN", "{}", r.out);
    assert!(
        r.out.contains("NEXT    sudo propolis-status alert  -  runbook docs/operations/health-and-observability.md#alert-path"),
        "{}",
        r.out
    );

    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/cursors/ops-alert-undelivered.json",
        "[{\"first_failed_unix\":1799999000},{\"first_failed_unix\":1799998000}]",
    );
    let r = fx.walk();
    assert!(r.out.contains("daemon queue 2 - "), "{}", r.out);
    assert_eq!(r.state("alert"), "WARN", "{}", r.out);
    let view = fx.run(&["alert"]);
    assert!(
        view.out
            .contains("    daemon queue: 2, oldest first_failed_unix 07:26:40"),
        "{}",
        view.out
    );

    fx.write(
        "var/lib/propolis/cursors/ops-alert-undelivered.json",
        &" ".repeat(300 * 1024),
    );
    let r = fx.walk();
    assert!(r.out.contains("daemon queue ? (too large)"), "{}", r.out);
    assert_eq!(r.state("alert"), "?", "{}", r.out);
}

#[test]
fn an_old_backup_a_disabled_timer_or_a_backup_finding_shows_on_the_backup_rail() {
    let mut fx = Fx::single();
    fx.write(
        "var/lib/propolis/backup-status/last-success",
        r#"{"completed_at":"2027-01-13T08:00:00Z","set":"20270113T080000Z-scheduled"}"#,
    );
    let r = fx.walk();
    assert_eq!(r.state("backup"), "WARN", "{}", r.out);
    assert!(
        r.row("backup").contains("last good backup 2 d ago"),
        "{}",
        r.out
    );

    let mut fx2 = Fx::single();
    fx2.unit(
        "propolis-backup.timer",
        "inactive",
        "dead",
        "success",
        "disabled",
    );
    let r = fx2.walk();
    assert_eq!(r.state("backup"), "WARN", "{}", r.out);
    assert!(
        r.row("backup").contains("propolis-backup.timer disabled"),
        "{}",
        r.out
    );

    fx.unit(
        "propolis-backup.timer",
        "active",
        "waiting",
        "success",
        "enabled",
    );
    fx.write(
        "var/lib/propolis/backup-status/last-success",
        r#"{"completed_at":"2027-01-14T20:00:00Z","set":"20270114T200000Z-scheduled"}"#,
    );
    fx.tsv(&[("fail", "backup-stale", "backup")]);
    let r = fx.walk();
    assert_eq!(r.state("backup"), "FAIL", "{}", r.out);
    assert!(
        r.row("backup").contains("findings: backup-stale"),
        "{}",
        r.out
    );
}

#[test]
fn a_monitor_turned_off_warns_on_its_own_row_and_names_its_own_view() {
    let fx = Fx::single();
    fx.env_drop("PROPOLIS_OPS_ENABLED=");
    let r = fx.walk();
    assert!(r.out.contains("daemon monitor off"), "{}", r.out);
    assert_eq!(r.state("monitor"), "WARN", "{}", r.out);
    assert!(
        r.out
            .contains("NEXT    sudo propolis-status monitor  -  runbook -"),
        "{}",
        r.out
    );
}

#[test]
fn a_manual_maintenance_marker_also_holds_collector_and_database_kinds() {
    let fx = Fx::single();
    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\tabcdef01\tmanual\n", NOW + 600),
    );
    let r = fx.walk();
    assert!(
        r.out.contains(
            "MAINT   manual until 08:10:00 (10 min left): unit kinds held; collector and database kinds held\n"
        ),
        "{}",
        r.out
    );
}

#[test]
fn at_most_twenty_failures_are_listed_and_unknown_words_print_as_unknown() {
    let fx = Fx::single();
    let mut body = String::new();
    for i in 1..=22u64 {
        let (stage, cause) = match i {
            1 => ("listen", "bogus"),
            2 => ("listen", "proc.exit:abc"),
            3 => ("nowhere", "proc.oom"),
            _ => ("listen", "proc.exit:1"),
        };
        body.push_str(&record(
            &format!("w#{i}"),
            &format!("unit:sensor-s{i}.service"),
            stage,
            "PAGE",
            "pending",
            NOW - i * 60,
            cause,
            "delivered",
        ));
    }
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t23\n{body}"),
    );
    let r = fx.walk();
    assert_eq!(r.code, 0, "{}", r.out);
    let block: Vec<&str> = r
        .out
        .lines()
        .skip_while(|l| !l.starts_with("RECENT FAILURES"))
        .skip(1)
        .take_while(|l| l.trim_start().starts_with("w#"))
        .collect();
    assert_eq!(block.len(), 20, "{}", r.out);
    assert!(
        r.out
            .contains("        ... and 2 more: sudo propolis-status alert"),
        "{}",
        r.out
    );
    let line = |id: &str| {
        *block
            .iter()
            .find(|l| l.trim_start().starts_with(&format!("{id} ")))
            .unwrap()
    };
    assert!(line("w#1").contains("cause ?"), "{block:?}");
    assert!(line("w#2").contains("cause ?"), "{block:?}");
    assert!(
        line("w#3").trim_start().starts_with("w#3     ? "),
        "{block:?}"
    );
}

#[test]
fn the_24_hour_line_counts_resolved_records_and_withheld_messages() {
    let fx = Fx::single();
    let resolved = set_field(
        &record(
            "w#1",
            "unit:sensor-ssh.service",
            "listen",
            "PAGE",
            "resolved",
            NOW - 7200,
            "proc.exit:1",
            "delivered",
        ),
        21,
        &stamp_ago(3600),
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t2\n{resolved}W\t{}\tbudget\n",
            stamp_ago(600)
        ),
    );
    let r = fx.walk();
    assert!(
        r.out.contains(
            "24 H    resolved 1 - withheld by budget 1 - opened and resolved without delivery 1"
        ),
        "{}",
        r.out
    );
}

#[test]
fn an_unreadable_scheduler_or_a_marker_that_is_not_a_file_makes_publish_unknown() {
    let fx = Fx::single();
    std::fs::remove_file(fx.p("etc/cron.d/propolis-blocklist")).unwrap();
    fx.write("etc/cron.d/huge", &"#".repeat(70_000));
    let r = fx.walk();
    assert_eq!(r.state("publish"), "?", "{}", r.out);
    assert!(
        r.row("publish")
            .contains("a crontab or unit file could not be read"),
        "{}",
        r.out
    );

    let fx = Fx::single();
    let marker = fx.p("var/lib/propolis/blocklist-status/last-pushed");
    std::fs::remove_file(&marker).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&marker)
            .status()
            .unwrap()
            .success()
    );
    let r = fx.walk();
    assert_eq!(r.state("publish"), "?", "{}", r.out);
    assert!(
        r.row("publish")
            .contains("last-pushed is not a regular file"),
        "{}",
        r.out
    );
}

#[test]
fn a_console_not_on_loopback_is_not_asked() {
    let fx = Fx::single();
    fx.env_line("PROPOLIS_CONSOLE_BIND=192.0.2.5:8080");
    let r = fx.walk();
    assert!(
        r.row("intake")
            .contains("/ready not checked (console not on loopback)"),
        "{}",
        r.out
    );
    assert!(
        !fx.log().lines().any(|l| l.starts_with("curl ")),
        "{}",
        fx.log()
    );
}

/// A stage view exits as the walk would: 2 for any marked stage or FAIL rail, 1 for a WARN or `?`
/// anywhere, whichever row it shows.
#[test]
fn a_stage_view_exits_as_the_walk_would() {
    let mut fx = Fx::single();
    fx.unit(
        "sensor-ssh.service",
        "failed",
        "failed",
        "exit-code",
        "enabled",
    );
    assert_eq!(fx.run(&["alert"]).code, 2);
    let mut fx = Fx::single();
    fx.setenv("NTP", "no");
    assert_eq!(fx.run(&["listen"]).code, 1);
}

#[test]
fn others_arriving_counts_only_other_collectors() {
    let fx = Fx::control();
    fx.write("var/spool/propolis/gateway/collector-01/events.jsonl", "x");
    set_mtime(
        &fx.p("var/spool/propolis/gateway/collector-01/events.jsonl"),
        NOW - 10,
    );
    let r = fx.walk();
    let ship = rows(&r, "ship");
    assert_eq!(ship.len(), 1, "{}", r.out);
    assert!(!ship[0].contains("others arriving"), "{}", r.out);

    fx.write("var/spool/propolis/gateway/collector-02/events.jsonl", "x");
    set_mtime(
        &fx.p("var/spool/propolis/gateway/collector-02/events.jsonl"),
        NOW - 10,
    );
    let r = fx.walk();
    let ship = rows(&r, "ship");
    assert_eq!(ship.len(), 2, "{}", r.out);
    for row in ship {
        assert!(row.contains("others arriving"), "{}", r.out);
    }
}

/// The gateway's state file for a collector is written on every accepted batch, so it counts as
/// an arrival as much as the spool file does.
#[test]
fn a_collectors_last_arrival_takes_the_gateways_state_file_into_account() {
    let fx = Fx::control();
    fx.write("var/spool/propolis/gateway/collector-01/events.jsonl", "x");
    set_mtime(
        &fx.p("var/spool/propolis/gateway/collector-01/events.jsonl"),
        NOW - 7200,
    );
    fx.write("var/lib/propolis/gateway/collector-01.json", "{}");
    set_mtime(
        &fx.p("var/lib/propolis/gateway/collector-01.json"),
        NOW - 30,
    );
    let r = fx.walk();
    assert!(r.row("ship").contains("07:59:30"), "{}", r.out);
    let view = fx.run(&["gateway"]);
    assert!(
        view.out.contains(
            "    {collector-01}: 1 B, last arrival 07:59:30, last accepted 07:59:30, not listed in PROPOLIS_SENSOR_LOGS"
        ),
        "{}",
        view.out
    );
    let ship = Fx::collector();
    let ssh = ship.p("var/log/propolis/ssh/events.jsonl");
    ship.cursor("var/lib/propolis/shipper/cursors", &ssh, 100, NOW - 60);
    ship.write("var/lib/propolis/shipper/state/k1.json", "{}");
    set_mtime(&ship.p("var/lib/propolis/shipper/state/k1.json"), NOW - 120);
    let view = ship.run(&["ship"]);
    assert!(
        view.out
            .contains("    last accepted batch (newest state file): 07:58:00"),
        "{}",
        view.out
    );
}

#[test]
fn every_clock_query_has_a_time_limit() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let calls: Vec<&str> = script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && l.contains("timedatectl"))
        .collect();
    assert!(!calls.is_empty());
    for call in calls {
        assert!(call.contains("timeout 10 timedatectl "), "{call}");
    }
}

/// Under pipefail an early-exiting `grep -q` would kill the writer and fail the pipeline though
/// the line was found.
#[test]
fn the_trusted_connect_failure_line_is_found_in_a_long_journal() {
    let mut fx = Fx::single();
    fx.unit(
        "propolis.service",
        "activating",
        "auto-restart",
        "exit-code",
        "enabled",
    );
    fx.setenv("PG_RC", "2");
    fx.setenv(
        "PG_ERR",
        "psql: error: connection to server failed: Connection refused",
    );
    fx.setenv("JOURNAL_LINE", "propolis: failed to connect to PostgreSQL");
    fx.setenv("JOURNAL_PAD", "1");
    let r = fx.walk();
    assert_eq!(r.marked().as_deref(), Some("ledger"), "{}", r.out);
    assert_eq!(r.state("intake"), "starved", "{}", r.out);
}

/// A host cloned from another keeps the original's salt, so the two share every opaque id. The
/// machine id is what a clone gets anew, so a salt older than it is said in the host view. It is
/// never a warning: the journal's oldest boot moves as the journal is trimmed, and a machine id
/// can be rewritten on a host that was never cloned, so neither is proof.
#[test]
fn a_salt_older_than_the_machine_id_is_said_in_the_host_view_and_never_warns() {
    let mut fx = Fx::single();
    let salt = fx.p("var/lib/propolis/witness/id-salt");
    fx.write("etc/machine-id", "0123456789abcdef0123456789abcdef\n");
    let machine_id = fx.p("etc/machine-id");
    set_mtime(&salt, NOW - 1000);
    set_mtime(&machine_id, NOW - 10);
    // A journal trimmed to boots newer than the salt must not matter.
    fx.setenv(
        "LIST_BOOTS",
        " 0 fedcba9876543210fedcba9876543210 Thu 2099-01-01 02:00:00 UTC Thu 2099-01-01 03:00:00 UTC",
    );
    let r = fx.walk();
    assert_eq!(r.state("host"), "ok", "{}", r.out);
    assert!(!r.out.contains("clone"), "{}", r.out);
    let view = fx.run(&["host"]);
    assert!(
        view.out.contains(
            "    id salt: present, older than /etc/machine-id (a host cloned from another shares its ids)"
        ),
        "{}",
        view.out
    );

    set_mtime(&machine_id, NOW - 5000);
    let view = fx.run(&["host"]);
    assert!(view.out.contains("    id salt: present\n"), "{}", view.out);

    std::fs::remove_file(&machine_id).unwrap();
    let view = fx.run(&["host"]);
    assert!(view.out.contains("    id salt: present\n"), "{}", view.out);
}

/// A record line cut short (a damaged file, or a writer stopped part-way before the rename
/// protected it) must not end the walk: under `set -u` a field that is not there is an error
/// unless it is asked for with a default.
#[test]
fn a_record_line_cut_short_does_not_end_the_walk() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/incidents",
        "#incidents v1 g=3\nN\t2\nI\tw#1\tunit:sensor-ssh.service\t-\tlisten\t-\tPAGE\tresolved\nW\nI\n",
    );
    let r = fx.walk();
    assert!(!r.err.contains("unbound variable"), "{}", r.err);
    assert!(
        r.out.contains(
            "24 H    resolved 0 - withheld by budget 0 - opened and resolved without delivery 0"
        ),
        "{}\n{}",
        r.out,
        r.err
    );
    assert!(r.out.contains("IDS"), "the walk reached its end: {}", r.out);
}

/// What the docs promise about the walk, its verbs and the records is what the code does.
#[test]
fn the_docs_say_what_the_walk_and_its_verbs_write_and_that_the_witness_judges_the_records() {
    let commands = std::fs::read_to_string(COMMANDS).unwrap();
    let section = &commands[commands.find("\n## Status walk\n").unwrap()..];
    let section = &section[..section[1..].find("\n## ").unwrap()];
    for promise in [
        "temporary header file for the metrics token",
        "`--maint MINUTES`",
        "`--banner`",
        "/run/propolis-witness/maintenance",
    ] {
        assert!(section.contains(promise), "{promise:?} not in:\n{section}");
    }
    assert!(!section.contains("writes no\nfile"), "{section}");
    let page = std::fs::read_to_string(RUNBOOK).unwrap();
    let witness = &page[page.find("<a id=\"witness\"></a>").unwrap()..];
    let witness = &witness[..witness.find("\n## ").unwrap()];
    assert!(!witness.contains("nothing judges"), "{witness}");
    for promise in [
        "light pass",
        "every five minutes",
        "sends nothing",
        "banner not written",
    ] {
        assert!(witness.contains(promise), "{promise:?} not in:\n{witness}");
    }
}

// ---- the witness's light pass in the walk, the banner and --maint ----------------------------

/// Once a witness pass has run, the records are what it judged: an OPEN block lists the open,
/// acked and pending ones, PAGE first, then ACT, then NOTICE, then by id, with their stage,
/// instance, onset, cause, next reminder and what today's hook did. An open PAGE sets the exit
/// code to 2, an open ACT alone to 1; a pending one or a NOTICE does not count.
#[test]
fn after_a_witness_pass_the_records_are_listed_open_with_tier_and_next_reminder() {
    let fx = Fx::single();
    fx.witness_ran(300);
    let page = set_field(
        &record(
            "w#12",
            "unit:sensor-ssh.service",
            "listen",
            "PAGE",
            "open",
            NOW - 2640,
            "proc.exit:1",
            "delivered",
        ),
        19,
        &stamp_ago(1020),
    );
    let page = set_field(&page, 9, &stamp_ago(2640));
    let act = set_field(
        &record(
            "w#14",
            "unit:propolis-backup.service",
            "backup",
            "ACT",
            "open",
            NOW - 21600,
            "proc.exit:2",
            "-",
        ),
        9,
        &stamp_ago(21600),
    );
    let notice = record(
        "w#13",
        "tool:units",
        "host",
        "NOTICE",
        "pending",
        NOW - 600,
        "tool.exec",
        "-",
    );
    let gone = set_field(
        &record(
            "w#9",
            "unit:sensor-http.service",
            "listen",
            "PAGE",
            "resolved",
            NOW - 9000,
            "proc.exit:1",
            "delivered",
        ),
        21,
        &stamp_ago(3000),
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=9\nN\t15\n{act}{notice}{gone}{page}"),
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "an open PAGE: {}", r.out);
    let block: Vec<&str> = r
        .out
        .lines()
        .skip_while(|l| !l.starts_with("OPEN"))
        .take(4)
        .collect();
    assert!(
        block[0].starts_with("OPEN    w#12 PAGE   listen   u"),
        "{block:?}"
    );
    assert!(block[0].contains("={sensor-ssh.service}"), "{block:?}");
    assert!(
        block[0].contains("open since 07:16:00 (44 min)"),
        "{block:?}"
    );
    assert!(block[0].contains("cause proc.exit 1"), "{block:?}");
    assert!(block[0].contains("would remind 07:43"), "{block:?}");
    assert!(block[0].ends_with("[legacy hook: delivered]"), "{block:?}");
    assert!(
        block[1].trim_start().starts_with("w#14 ACT    backup"),
        "{block:?}"
    );
    assert!(block[1].ends_with("[not pushed: legacy]"), "{block:?}");
    assert!(
        block[2].trim_start().starts_with("w#13 NOTICE host"),
        "{block:?}"
    );
    assert!(block[2].contains("pending since 07:50:00"), "{block:?}");
    assert!(!block[2].contains("remind"), "{block:?}");
    assert_eq!(
        block[3].trim(),
        "daemon incidents: not on disk before step 3"
    );
    assert!(
        !r.out.contains("w#9 "),
        "a resolved record is not open: {}",
        r.out
    );
    assert!(!r.out.contains("RECENT FAILURES"), "{}", r.out);

    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=10\nN\t15\n{act}{notice}"),
    );
    assert_eq!(fx.walk().code, 1, "an open ACT alone");
    let acked = set_field(&page, 7, "acked");
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=11\nN\t15\n{acked}"),
    );
    assert_eq!(
        fx.walk().code,
        2,
        "an acknowledged PAGE is still a PAGE incident open"
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=11\nN\t15\n{notice}{gone}"),
    );
    let r = fx.walk();
    assert_eq!(
        r.code, 0,
        "pending and NOTICE records do not count: {}",
        r.out
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        "#incidents v1 g=12\nN\t15\n",
    );
    assert!(fx.walk().out.contains("OPEN    none recorded"));
    std::fs::remove_file(fx.p("var/lib/propolis/witness/incidents")).unwrap();
    assert!(fx.walk().out.contains("OPEN    no incident record yet"));
}

/// ALERTS line 3: when the light and hourly passes last completed, where state lands, when the
/// banner was written, and once a light pass has run whether the heartbeat URL is set.
#[test]
fn the_third_alerts_line_names_the_light_pass_the_state_and_the_banner() {
    let fx = Fx::single();
    let r = fx.walk();
    assert!(
        r.out.contains(
            "        witness light never - hourly never - state nothing recorded yet - banner not written\n"
        ),
        "{}",
        r.out
    );
    fx.witness_ran(300);
    let r = fx.walk();
    assert!(
        r.out.contains(
            "        witness light 07:55:00 (5 min) - hourly never - state persisted - banner 07:55:00 - heartbeat URL not set\n"
        ),
        "{}",
        r.out
    );
    fx.write(
        "run/propolis-witness/heartbeat",
        &format!(
            "#heartbeat v1 g=4\nB\tlight\t{}\tpersistent\tok\nB\thourly\t{}\tpersistent\tok\n",
            stamp_ago(300),
            stamp_ago(1800)
        ),
    );
    let r = fx.walk();
    assert!(
        r.out.contains(
            "        witness light 07:55:00 (5 min) - hourly 07:30:00 (30 min) - state persisted - banner 07:55:00 - heartbeat URL not set\n"
        ),
        "{}",
        r.out
    );
}

/// What the light pass's probes leave for the walk: the heartbeat URL's state with its last
/// request or skip on ALERTS line 3, never the URL itself (a URL that is not https reads
/// refused); an open alert-path fails the alert rail; an open tool-unusable warns on the host rail
/// with the check it names; and a journal class that started again without its cursor is noted on
/// the witness rail.
#[test]
fn the_walk_shows_the_heartbeat_url_alert_path_tool_unusable_and_skipped_journal_lines() {
    let fx = Fx::single();
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/ping/hb-s3cret\n",
    );
    fx.witness_ran(300);
    let s = stamp_ago(300);
    let meta = format!(
        "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{s}\nM\thb_last\t{}/ok\n",
        stamp_ago(600)
    );
    fx.write("var/lib/propolis/witness/meta", &meta);
    let r = fx.walk();
    assert!(
        r.out
            .contains(" - heartbeat URL set, asked 07:50:00 (ok)\n"),
        "{}",
        r.out
    );
    assert_eq!(r.code, 0, "{}", r.out);

    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("{meta}M\thb_skip\t{s}/check\nM\tjskip\t{s}/guard\n"),
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=2\nN\t3\n{}{}",
            set_field(
                &set_field(
                    &record(
                        "w#1",
                        "alert:shell",
                        "alert",
                        "PAGE",
                        "open",
                        NOW - 300,
                        "nocurl",
                        "-"
                    ),
                    3,
                    "alert-path"
                ),
                9,
                &s
            ),
            set_field(
                &set_field(
                    &record(
                        "w#2",
                        "tool:pg",
                        "host",
                        "NOTICE",
                        "open",
                        NOW - 300,
                        "tool.exec",
                        "-"
                    ),
                    3,
                    "tool-unusable"
                ),
                9,
                &s
            )
        ),
    );
    let r = fx.walk();
    assert!(
        r.out
            .contains(" - heartbeat URL set, skipped 07:55:00 (check)\n"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("hb-s3cret"), "{}", r.out);
    assert_eq!(r.state("alert"), "FAIL", "{}", r.out);
    assert!(r.row("alert").contains("alert-path open"), "{}", r.out);
    assert_eq!(r.state("host"), "WARN", "{}", r.out);
    assert!(
        r.row("host").contains("a check cannot run: pg"),
        "{}",
        r.out
    );
    assert!(
        r.row("witness")
            .contains("journal class guard: lines may have been skipped (07:55:00)"),
        "{}",
        r.out
    );
    assert_eq!(r.code, 2, "{}", r.out);

    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=http://hc.example.invalid/ping/hb-s3cret\n",
    );
    let r = fx.walk();
    assert!(
        r.out
            .contains(" - heartbeat URL refused (not an https URL)\n"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("hb-s3cret"), "{}", r.out);
}

/// The witness rail: FAIL when the light timer is not active, when the light pass is older than
/// 900 s (not judged in the first 1800 s of uptime), or when the banner is missing or older than
/// 900 s while the light pass is fresh; WARN for a hook spool file waiting more than 10 min.
#[test]
fn the_witness_rail_says_banner_not_written() {
    let fx = Fx::single();
    fx.witness_ran(120);
    let r = fx.walk();
    assert_eq!(r.state("witness"), "ok", "{}", r.out);
    assert_eq!(r.code, 0, "{}", r.out);

    std::fs::remove_file(fx.p("run/motd.d/propolis")).unwrap();
    let r = fx.walk();
    assert_eq!(r.state("witness"), "FAIL", "{}", r.out);
    assert!(r.row("witness").contains("banner not written"), "{}", r.out);
    assert_eq!(r.code, 2);
    assert!(
        r.out.contains("NEXT    sudo propolis-status witness  -  runbook docs/operations/health-and-observability.md#witness"),
        "{}",
        r.out
    );
    fx.write("run/motd.d/propolis", "old\n");
    set_mtime(&fx.p("run/motd.d/propolis"), NOW - 1000);
    let r = fx.walk();
    assert!(r.row("witness").contains("banner not written"), "{}", r.out);

    // A stale light pass: the banner's age then says nothing new.
    let stale = Fx::single();
    stale.witness_ran(1000);
    let r = stale.walk();
    assert_eq!(r.state("witness"), "FAIL", "{}", r.out);
    assert!(
        r.row("witness").contains("light pass 16 min old"),
        "{}",
        r.out
    );
    assert!(
        !r.row("witness").contains("banner not written"),
        "{}",
        r.out
    );
    // Not judged in the first half hour after a boot.
    let mut early = Fx::single();
    early.setenv("PROPOLIS_STATUS_NOW", &format!("{NOW}/abcdef01/1500"));
    early.witness_ran(1000);
    let r = early.walk();
    assert_ne!(r.state("witness"), "FAIL", "{}", r.out);

    let mut stopped = Fx::single();
    stopped.unit(
        "propolis-witness@light.timer",
        "inactive",
        "dead",
        "success",
        "disabled",
    );
    stopped.witness_ran(60);
    let r = stopped.walk();
    assert_eq!(r.state("witness"), "FAIL", "{}", r.out);
    assert!(
        r.row("witness")
            .contains("propolis-witness@light.timer inactive"),
        "{}",
        r.out
    );

    // A timer that fired but whose pass never completed.
    let mut never = Fx::single();
    never
        .units
        .retain(|u| !u.starts_with("propolis-witness@light.timer|"));
    never.units.push(
        "propolis-witness@light.timer|active|waiting|success|0||enabled||Fri 2027-01-15 07:55:00 UTC"
            .to_string(),
    );
    let r = never.walk();
    assert_eq!(r.state("witness"), "FAIL", "{}", r.out);
    assert!(
        r.row("witness").contains("no light pass has completed"),
        "{}",
        r.out
    );

    let spool = Fx::single();
    spool.witness_ran(60);
    let s = stamp_ago(1200);
    spool.write(
        "var/lib/propolis/witness/hook/sensor-ssh.service",
        &format!("#hook v1 g=1\nH\t{s}\t{s}\t1\texit-code\texited\t1\tproc.exit:1\t0\tdelivered\n"),
    );
    set_mtime(
        &spool.p("var/lib/propolis/witness/hook/sensor-ssh.service"),
        NOW - 1200,
    );
    let r = spool.walk();
    assert_eq!(r.state("witness"), "WARN", "{}", r.out);
    assert!(
        r.row("witness").contains("1 hook spool file waiting"),
        "{}",
        r.out
    );
}

/// The banner: four lines of at most 78 bytes, printable ASCII, each with the time, built from
/// closed words and counts only, in every case the login banner describes.
#[test]
fn the_banner_is_four_ascii_lines_of_closed_words() {
    let check = |r: &Run, case: &str| -> Vec<String> {
        assert_eq!(r.code, 0, "{case}: {}", r.err);
        let lines: Vec<String> = r.out.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 4, "{case}: {}", r.out);
        for l in &lines {
            assert!(l.len() <= 78, "{case}: {} bytes: {l}", l.len());
            assert!(
                l.bytes().all(|b| (b' '..=b'~').contains(&b)),
                "{case}: {l:?}"
            );
            assert!(l.starts_with("[propolis 08:00 UTC] "), "{case}: {l}");
            for planted in [
                "honeybox",
                "sensor-",
                "t0p1c",
                "ntfy",
                "propolis.service",
                "tk_",
            ] {
                assert!(!l.contains(planted), "{case}: {planted} in {l}");
            }
        }
        assert_eq!(
            lines[3],
            "[propolis 08:00 UTC] rewritten every 5 min; older means the witness stopped"
        );
        lines
    };

    let fx = Fx::single();
    fx.witness_ran(60);
    let l = check(&fx.run(&["--banner"]), "healthy");
    assert_eq!(l[0], "[propolis 08:00 UTC] nothing open; profile legacy");
    assert_eq!(
        l[1],
        "[propolis 08:00 UTC] alerts: NOT VERIFIED (never); daemon not verified"
    );
    assert_eq!(l[2], "[propolis 08:00 UTC] run: sudo propolis-status");
    assert!(!fx.log().contains("curl"), "no network: {}", fx.log());
    fx.readcheck("readable");
    let l = check(&fx.run(&["--banner"]), "readable");
    assert_eq!(
        l[1],
        "[propolis 08:00 UTC] alerts: topic READABLE by anyone"
    );
    for (class, word) in [
        ("redirect", "redirect"),
        ("not_found", "not found"),
        ("not_ntfy", "not a push server"),
        ("unexpected", "unexpected"),
    ] {
        fx.readcheck(class);
        let l = check(&fx.run(&["--banner"]), class);
        assert_eq!(
            l[1],
            format!("[propolis 08:00 UTC] alerts: topic not proven private ({word})"),
            "an answer that is not a refusal does not prove the topic readable"
        );
    }
    std::fs::remove_file(fx.p("var/lib/propolis/witness/readcheck")).unwrap();
    let l = check(&fx.run(&["--banner"]), "not checked");
    assert_eq!(l[1], "[propolis 08:00 UTC] alerts: topic not checked yet");

    let mut records = String::new();
    for n in 0..120 {
        let tier = if n % 3 == 0 { "PAGE" } else { "ACT" };
        records.push_str(&record(
            &format!("w#{n}"),
            &format!("unit:sensor-{n}.service"),
            "listen",
            tier,
            "open",
            NOW - 60,
            "proc.exit:1",
            "-",
        ));
    }
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=2\nN\t200\n{records}"),
    );
    let l = check(&fx.run(&["--banner"]), "open");
    assert_eq!(
        l[0],
        "[propolis 08:00 UTC] 120 open (PAGE 40, ACT 80); profile legacy"
    );
    fx.write(
        "run/propolis-witness/maintenance",
        &format!(
            "#maintenance v1 g=1\nX\t{}\tabcdef01\trollback\n",
            NOW + 600
        ),
    );
    let l = check(&fx.run(&["--banner"]), "open and maintenance");
    assert_eq!(
        l[0],
        "[propolis 08:00 UTC] 120 open; maint (rollback) until 08:10; profile legacy"
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        "#incidents v1 g=3\nN\t200\n",
    );
    let l = check(&fx.run(&["--banner"]), "maintenance alone");
    assert_eq!(
        l[0],
        "[propolis 08:00 UTC] maint (rollback) until 08:10; profile legacy"
    );
    std::fs::remove_file(fx.p("run/propolis-witness/maintenance")).unwrap();

    fx.write("run/propolis-witness/lockwait", "light\t2\n");
    let l = check(&fx.run(&["--banner"]), "lock busy");
    assert_eq!(
        l[2],
        "[propolis 08:00 UTC] state LOCK BUSY - run: sudo propolis-status"
    );
    std::fs::remove_file(fx.p("run/propolis-witness/lockwait")).unwrap();
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=4\nM\twhere\trun\nM\tlight_last\t{}\n",
            stamp_ago(60)
        ),
    );
    let l = check(&fx.run(&["--banner"]), "not persisted");
    assert_eq!(
        l[2],
        "[propolis 08:00 UTC] state NOT PERSISTED - run: sudo propolis-status"
    );
    fx.witness_ran(60);
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        "1800000000 2 1800000000\n",
    );
    fx.write(
        "var/lib/propolis/cursors/ops-alert-undelivered.json",
        r#"[{"first_failed_unix":1},{"first_failed_unix":2}]"#,
    );
    let l = check(&fx.run(&["--banner"]), "undelivered");
    assert_eq!(
        l[2],
        "[propolis 08:00 UTC] 3 alerts UNDELIVERED - run: sudo propolis-status"
    );

    fx.env_drop("PROPOLIS_OPS_NTFY_URL");
    let l = check(&fx.run(&["--banner"]), "no target");
    assert_eq!(
        l[1],
        "[propolis 08:00 UTC] alerts: NO PUSH TARGET (journal only)"
    );
    let collector = Fx::collector();
    let l = check(&collector.run(&["--banner"]), "collector");
    assert_eq!(
        l[1],
        "[propolis 08:00 UTC] alerts: no push path here (collector)"
    );
    assert_eq!(
        l[0],
        "[propolis 08:00 UTC] 0 recent failures, not judged; profile legacy"
    );
}

/// On a host where nothing of the witness exists yet the banner still prints, and says what it
/// cannot know: the topic is not checked, and recorded failures are not judged.
#[test]
fn the_banner_from_a_host_with_no_witness_state_says_not_checked() {
    let fx = Fx::single();
    std::fs::remove_dir_all(fx.p("var/lib/propolis/witness")).unwrap();
    std::fs::remove_dir_all(fx.p("run/propolis-witness")).unwrap();
    let r = fx.run(&["--banner"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out
            .contains("] 0 recent failures, not judged; profile legacy\n"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("] alerts: topic not checked yet\n"),
        "{}",
        r.out
    );
    assert!(
        !fx.p("run/motd.d/propolis").exists(),
        "--banner only prints"
    );
}

/// `--maint MINUTES` announces planned work: it writes the marker (reason manual, this boot, now
/// plus MINUTES), shows it in the walk's header and the banner, and `--maint 0` ends it whoever
/// wrote it. Out of range is bad usage; a marker that cannot be written is exit 1.
#[test]
fn maint_writes_and_removes_the_marker_and_the_walk_shows_it() {
    let fx = Fx::single();
    std::fs::create_dir_all(fx.p("run/motd.d")).unwrap();
    let r = fx.run(&["--maint", "30"]);
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    assert_eq!(
        r.out,
        "maintenance until 08:30:00 UTC: unit, collector and database kinds held on this host\n"
    );
    assert_eq!(
        std::fs::read_to_string(fx.p("run/propolis-witness/maintenance")).unwrap(),
        format!("#maintenance v1 g=1\nX\t{}\tabcdef01\tmanual\n", NOW + 1800)
    );
    let banner = fx.p("run/motd.d/propolis");
    assert_eq!(
        banner.metadata().unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(
        std::fs::read_to_string(&banner)
            .unwrap()
            .contains("maint (manual) until 08:30"),
        "{}",
        std::fs::read_to_string(&banner).unwrap()
    );
    let walk = fx.walk();
    assert!(
        walk.out.contains("MAINT   manual until 08:30:00 (30 min left): unit kinds held; collector and database kinds held\n"),
        "{}",
        walk.out
    );

    fx.write(
        "run/propolis-witness/maintenance",
        &format!("#maintenance v1 g=1\nX\t{}\tabcdef01\tupgrade\n", NOW + 600),
    );
    let r = fx.run(&["--maint", "0"]);
    assert_eq!(
        (r.code, r.out.as_str()),
        (0, "maintenance ended\n"),
        "{}",
        r.err
    );
    assert!(!fx.p("run/propolis-witness/maintenance").exists());
    assert!(!std::fs::read_to_string(&banner).unwrap().contains("maint"));

    assert_eq!(fx.run(&["--maint", "121"]).code, 64);
    std::fs::remove_dir_all(fx.p("run/propolis-witness")).unwrap();
    let r = fx.run(&["--maint", "10"]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.err.contains("could not be written"), "{}", r.err);
}

/// The verbs are root's like the walk.
#[test]
fn the_verbs_need_root() {
    let mut fx = Fx::single();
    fx.setenv("PROPOLIS_STATUS_EUID", "1000");
    for args in [vec!["--banner"], vec!["--maint", "5"]] {
        let r = fx.run(&args);
        assert_eq!(r.code, 3, "{args:?}");
    }
    assert!(!fx.p("run/propolis-witness/maintenance").exists());
}

/// The gate field and the alert rail come from the stored read check alone: never checked, or
/// answered readable, holds the gate in pointer mode and warns on the rail with the answer named;
/// a fresh refusal over https gives full and an ok rail.
#[test]
fn the_gate_field_and_the_alert_rail_follow_the_stored_read_check() {
    let fx = Fx::single();
    let r = fx.walk();
    assert_eq!(r.state("alert"), "ok", "{}", r.out);
    assert!(
        r.row("alert")
            .contains("shell and daemon topic refused (checked 07:50:00), token reads"),
        "{}",
        r.out
    );

    std::fs::remove_file(fx.p("var/lib/propolis/witness/readcheck")).unwrap();
    let r = fx.walk();
    assert!(r.out.contains(" - gate pointer:never - "), "{}", r.out);
    assert_eq!(r.state("alert"), "WARN", "{}", r.out);
    assert!(r.row("alert").contains("gate pointer:never"), "{}", r.out);
    assert!(
        r.row("alert")
            .contains("legacy hook carries host and unit names"),
        "{}",
        r.out
    );
    assert_eq!(r.code, 1, "{}", r.out);

    fx.readcheck("readable");
    let r = fx.walk();
    assert!(
        r.out
            .contains(" - gate pointer:readable (checked 07:50:00, 10 min) - "),
        "{}",
        r.out
    );
    assert!(
        r.row("alert").contains("shell and daemon topic READABLE"),
        "{}",
        r.out
    );
    for secret in ["t0p1c-secret", "tk_secret"] {
        assert!(!r.out.contains(secret), "{secret} printed");
    }
}

/// The daemon's topic (propolis.env), where today's hook sends host and unit names, is judged on
/// its own line: a private shell topic gives the gate full, and a readable daemon topic still
/// warns on the alert rail.
#[test]
fn a_readable_daemon_topic_warns_even_when_the_shell_topic_is_private() {
    let fx = Fx::single();
    let s = stamp_ago(600);
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=2\nR\t8f24b729c8ebd3c1\t{s}\trefused\t{s}\trefused\tnoread\t403\t403\tshell\t403\n\
             R\t8f24b729c8ebd3c1\t{s}\treadable\t{s}\treadable\t-\t200\t200\tdaemon\t200\n"
        ),
    );
    let r = fx.walk();
    assert!(r.out.contains(" - gate full (checked "), "{}", r.out);
    assert_eq!(r.state("alert"), "WARN", "{}", r.out);
    let row = r.row("alert");
    assert!(
        row.contains("daemon titles name this host's software (until step 3)"),
        "{row}"
    );
    assert!(
        row.contains("shell topic refused") && row.contains("daemon topic READABLE"),
        "{row}"
    );
}

/// The witness rail judges the hourly pass too: FAIL when its timer is not active or cc-stopped
/// is open (NEXT then names the tool runbook), WARN when the pass is over two hours and ten
/// minutes old or the last config-check exited above 2.
#[test]
fn the_witness_rail_judges_the_hourly_timer_its_age_and_cc_stopped() {
    let mut fx = Fx::single();
    fx.witness_ran(120);
    fx.unit(
        "propolis-witness@hourly.timer",
        "inactive",
        "dead",
        "success",
        "disabled",
    );
    let r = fx.walk();
    assert_eq!(r.state("witness"), "FAIL", "{}", r.out);
    assert!(
        r.row("witness")
            .contains("propolis-witness@hourly.timer inactive"),
        "{}",
        r.out
    );

    let fx = Fx::single();
    fx.witness_ran(120);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{}\nM\thourly_last\t{}\nM\tcc_last\t{}/124/300\n",
            stamp_ago(120),
            stamp_ago(10_800),
            stamp_ago(10_800)
        ),
    );
    let r = fx.walk();
    assert_eq!(r.state("witness"), "WARN", "{}", r.out);
    assert!(
        r.row("witness").contains("hourly pass 3 h old"),
        "{}",
        r.out
    );
    assert!(
        r.row("witness").contains("last config-check exited 124"),
        "{}",
        r.out
    );

    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=2\nN\t2\n{}",
            record(
                "w#1",
                "tool:config-check",
                "witness",
                "ACT",
                "open",
                NOW - 600,
                "cc.stopped",
                "-"
            )
        ),
    );
    let r = fx.walk();
    assert_eq!(r.state("witness"), "FAIL", "{}", r.out);
    assert!(r.row("witness").contains("cc-stopped"), "{}", r.out);
    assert!(
        r.out
            .contains("runbook docs/operations/health-and-observability.md#tool"),
        "{}",
        r.out
    );
}

/// The witness rail says what the last config-check left unsaid: a run that was not run at all
/// (missing or not trusted, exit field `-`) is named as such, never as an exit status, and a
/// completed run that printed lines out of form names how many.
#[test]
fn the_witness_rail_names_a_config_check_not_run_and_lines_printed_out_of_form() {
    let fx = Fx::single();
    fx.witness_ran(120);
    let meta = |extra: &str| {
        fx.write(
            "var/lib/propolis/witness/meta",
            &format!(
                "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{l}\nM\thourly_last\t{h}\n{extra}",
                l = stamp_ago(120),
                h = stamp_ago(600)
            ),
        );
    };
    meta(&format!("M\tcc_last\t{}/-/0\n", stamp_ago(600)));
    let r = fx.walk();
    assert_eq!(r.state("witness"), "WARN", "{}", r.out);
    assert!(
        r.row("witness")
            .contains("last config-check not run (missing or not trusted)"),
        "{}",
        r.out
    );
    assert!(!r.row("witness").contains("exited"), "{}", r.out);

    meta(&format!(
        "M\tcc_last\t{}/0/12\nM\tcc_skipped\t2\n",
        stamp_ago(600)
    ));
    let r = fx.walk();
    assert_eq!(r.state("witness"), "WARN", "{}", r.out);
    assert!(
        r.row("witness")
            .contains("config-check printed 2 lines out of form"),
        "{}",
        r.out
    );

    meta(&format!(
        "M\tcc_last\t{}/0/12\nM\tcc_skipped\t0\n",
        stamp_ago(600)
    ));
    assert_eq!(fx.walk().state("witness"), "ok");
}

/// An hourly timer that fired while no hourly pass ever completed (killed at its limit every
/// hour, say) is a witness that does not run: the rail warns, naming when the timer fired.
#[test]
fn the_witness_rail_warns_when_the_hourly_timer_fired_and_no_hourly_pass_completed() {
    let mut fx = Fx::single();
    fx.witness_ran(120);
    // Four hours of uptime, the light pass two minutes ago in this boot.
    let up = 14_400u64;
    let light = format!("{}/abcdef01/{}", NOW - 120, up - 120);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!("#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{light}\n"),
    );
    fx.write(
        "run/propolis-witness/heartbeat",
        &format!("#heartbeat v1 g=3\nB\tlight\t{light}\tpersistent\tok\n"),
    );
    fx.setenv("PROPOLIS_STATUS_NOW", &format!("{NOW}/abcdef01/{up}"));
    fx.units
        .retain(|u| !u.starts_with("propolis-witness@hourly.timer|"));
    fx.units.push(format!(
        "propolis-witness@hourly.timer|active|waiting|success|0|Fri 2027-01-15 04:00:00 UTC|enabled|{INVOCATION}|Fri 2027-01-15 05:00:00 UTC"
    ));
    let r = fx.walk();
    assert_eq!(r.state("witness"), "WARN", "{}", r.out);
    assert!(
        r.row("witness")
            .contains("no hourly pass has completed (the timer fired at 05:00:00)"),
        "{}",
        r.out
    );

    // The same timer, not fired yet: nothing to say.
    fx.units
        .retain(|u| !u.starts_with("propolis-witness@hourly.timer|"));
    fx.units.push(format!(
        "propolis-witness@hourly.timer|active|waiting|success|0|Fri 2027-01-15 04:00:00 UTC|enabled|{INVOCATION}|n/a"
    ));
    let r = fx.walk();
    assert_eq!(r.state("witness"), "ok", "{}", r.out);
}

/// The daemon's topic counts as private only on the gate's own terms: a refusal decided within
/// 24 h, an attempt within 3 h, over https. A refusal 25 h old, one over plain HTTP, and one
/// whose last attempt is over 3 h old each leave the legacy-hook warning on the alert rail.
#[test]
fn the_daemon_topic_is_private_only_when_its_refusal_is_fresh_checked_and_over_https() {
    let fx = Fx::single();
    let line = |binding: &str, astamp: &str, dstamp: &str| {
        format!(
            "#readcheck v1 g=2\nR\t{binding}\t{astamp}\trefused\t{dstamp}\trefused\tnoread\t403\t403\tboth\t403\n"
        )
    };
    let warns = |what: &str| {
        let r = fx.walk();
        assert_eq!(r.state("alert"), "WARN", "{what}: {}", r.out);
        let row = r.row("alert");
        assert!(
            row.contains("legacy hook carries host and unit names")
                && row.contains("daemon titles name this host's software"),
            "{what}: {row}"
        );
    };
    let https = "8f24b729c8ebd3c1";
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &line(https, &stamp_ago(600), &stamp_ago(90_000)),
    );
    warns("a refusal 25 h old");
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &line(https, &stamp_ago(14_400), &stamp_ago(72_000)),
    );
    warns("a refusal 20 h old whose last attempt is 4 h old");
    // The binding of http://ntfy.example.invalid and the fixture's topic.
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    fx.env_line("PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid");
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &line("e9960faaf48b78f0", &stamp_ago(600), &stamp_ago(600)),
    );
    warns("a fresh refusal over plain HTTP");
}

/// The opaque id of the mount point `target` under the fixture's salt.
fn mount_id(target: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg("printf '%s\\0%s\\0%s' \"$1\" mount \"$2\" | sha256sum")
        .arg("_")
        .arg(SALT)
        .arg(target)
        .output()
        .unwrap();
    format!("m{}", &String::from_utf8_lossy(&out.stdout)[..5])
}

/// An open volume record of the witness's hourly pass warns on the host rail by its opaque id
/// (exit 1, NEXT naming the `volume` runbook), and a unit whose change is not in force is noted
/// there without a warning; the host view maps the id to its mount point, shows the last sample,
/// and the projection from the week of `Z` samples: falling 1 GiB an hour, full of its last GiB
/// in 19 h. The walk itself never prints the mount point.
#[test]
fn an_open_volume_record_warns_on_the_host_rail_and_the_host_view_shows_its_projection() {
    let fx = Fx::single();
    fx.witness_ran(60);
    let m = mount_id("/");
    let vol = set_field(
        &set_field(
            &record(
                "w#4",
                &format!("vol:{m}"),
                "host",
                "ACT",
                "open",
                NOW - 3600,
                "vol.projected",
                "-",
            ),
            3,
            "volume-filling",
        ),
        5,
        &m,
    );
    let change = set_field(
        &record(
            "w#5",
            "change:sensor-ssh.service",
            "host",
            "NOTICE",
            "open",
            NOW - 3600,
            "change.env",
            "-",
        ),
        3,
        "change-pending",
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t6\n{vol}{change}"),
    );
    let gib: u64 = 1_073_741_824;
    let mut z = String::new();
    for h in (0..=73u64).rev() {
        z.push_str(&format!(
            "Z\t{m}\t{}\t{}\t{}\t6000000\t5000000\n",
            stamp_ago(h * 3600 + 120),
            100 * gib,
            (20 + h) * gib
        ));
    }
    fx.write(
        "var/lib/propolis/witness/observe",
        &format!("#observe v1 g=2\n{z}"),
    );
    let r = fx.walk();
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert_eq!(r.state("host"), "WARN", "{}", r.out);
    let row = r.row("host");
    assert!(row.contains(&format!("volume {m} filling")), "{row}");
    assert!(row.contains("changed, not in force: 1 units"), "{row}");
    assert!(r.out.contains("#volume"), "{}", r.out);
    let open = r.out.lines().find(|l| l.contains("w#4 ")).unwrap();
    assert!(
        open.contains(&m) && open.contains("cause vol.projected"),
        "{open}"
    );
    let view = fx.run(&["host"]);
    assert!(
        view.out
            .contains(&format!("volume {m} (/): 20.0 GiB of 100.0 GiB free")),
        "{}",
        view.out
    );
    assert!(view.out.contains("74 samples since"), "{}", view.out);
    assert!(
        view.out
            .contains("falling 1.0 GiB an hour; at that rate full of its last GiB in 19 h"),
        "{}",
        view.out
    );
    assert!(
        view.out
            .contains("{sensor-ssh.service} - an env file it loads changed after it started"),
        "{}",
        view.out
    );
}

/// The ledger row shows the database's state as the witness's hourly pass last read it (meta
/// pg_state: transaction-id age, slots, lock waits, size), and warns while it holds db-xid,
/// db-slots or db-locks open, with NEXT naming the `db-state` runbook; such a warning never
/// takes the marker.
#[test]
fn the_ledger_row_shows_the_hourly_database_state_and_warns_while_a_state_record_is_open() {
    let fx = Fx::single();
    fx.witness_ran(60);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{}\nM\tpg_state\t{}/1500000000/91/97/2/123456789\n",
            stamp_ago(60),
            stamp_ago(600)
        ),
    );
    let r = fx.walk();
    assert_eq!(r.state("ledger"), "ok", "{}", r.out);
    assert!(
        r.row("ledger")
            .contains("xid age 1500000000, slots 91 of 97, lock waits 2, size 117.7 MiB"),
        "{}",
        r.row("ledger")
    );
    let xid = set_field(
        &record(
            "w#2",
            "dbstate:xid",
            "ledger",
            "ACT",
            "open",
            NOW - 3600,
            "db.xid",
            "-",
        ),
        3,
        "db-xid",
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t3\n{xid}"),
    );
    let r = fx.walk();
    assert_eq!(r.state("ledger"), "WARN", "{}", r.out);
    assert!(r.row("ledger").contains("open: xid"), "{}", r.row("ledger"));
    assert_eq!(r.marked(), None, "{}", r.out);
    assert!(r.out.contains("sudo propolis-status ledger"), "{}", r.out);
    assert!(r.out.contains("#db-state"), "{}", r.out);
}

/// One `Z` sample of mount id `m`, `ago` seconds before NOW: 100 GiB, 60 GiB free.
fn z_line(m: &str, ago: u64) -> String {
    format!(
        "Z\t{m}\t{}\t107374182400\t64424509440\t6000000\t5000000\n",
        stamp_ago(ago)
    )
}

/// The host view maps every filesystem the witness samples back to its mount point, from the
/// same list of stores the witness takes: a backup directory a drop-in of the backup unit sets,
/// the gateway's spool gateway.env sets, and a store reached through a symbolic link. None of
/// them reads as having no store on it.
#[test]
fn the_host_view_maps_a_custom_backup_directory_a_gateway_spool_and_a_linked_store() {
    let mut fx = Fx::single();
    fx.witness_ran(60);
    fx.setenv("BACKUP_UNIT_ENV", "PROPOLIS_BACKUP_DIR=/srv/b");
    fx.write(
        "etc/propolis/gateway.env",
        "PROPOLIS_GATEWAY_SPOOL_DIR=/srv/gw\n",
    );
    for d in ["srv/b", "srv/gw", "data/spool", "var/spool"] {
        std::fs::create_dir_all(fx.p(d)).unwrap();
    }
    std::os::unix::fs::symlink(fx.p("data/spool"), fx.p("var/spool/propolis")).unwrap();
    let map = fx.dir.path().join("df.map");
    std::fs::write(
        &map,
        "/srv/b\t/srv/b\n/srv/gw\t/srv/gw\n/var/spool/propolis\t/data/spool\n",
    )
    .unwrap();
    fx.setenv("DF_MAP", &map.display().to_string());
    let ids: Vec<(String, &str)> = ["/srv/b", "/srv/gw", "/data/spool"]
        .iter()
        .map(|t| (mount_id(t), *t))
        .collect();
    let z: String = ids.iter().map(|(m, _)| z_line(m, 600)).collect();
    fx.write(
        "var/lib/propolis/witness/observe",
        &format!("#observe v1 g=2\n{z}"),
    );
    let view = fx.run(&["host"]);
    for (m, t) in &ids {
        assert!(
            view.out.contains(&format!("volume {m} ({t}): ")),
            "{t}: {}",
            view.out
        );
    }
    assert!(
        !view.out.contains("no store here is on it now"),
        "{}",
        view.out
    );
}

/// The walk runs as root with no sandbox, so it never has df open a path the postgres account
/// owns, which that account could swap for a link to anything: the data directory's df runs as
/// postgres through setpriv, and no df as root names it.
#[test]
fn the_walk_runs_the_data_directory_s_df_as_the_postgres_account() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{}\nM\tpg_datadir\t/var/lib/postgresql/16/main\n",
            stamp_ago(60)
        ),
    );
    std::fs::create_dir_all(fx.p("var/lib/postgresql/16/main")).unwrap();
    fx.write(
        "var/lib/propolis/witness/observe",
        &format!("#observe v1 g=2\n{}", z_line(&mount_id("/"), 600)),
    );
    let view = fx.run(&["host"]);
    let log = fx.log();
    let path = fx.p("var/lib/postgresql/16/main").display().to_string();
    let dropped = log
        .lines()
        .filter(|l| {
            l.starts_with("setpriv --reuid=4242 --regid=4343 ")
                && l.ends_with(&format!(" -- df -P -- {path}"))
        })
        .count();
    let dfs = log
        .lines()
        .filter(|l| l.starts_with("df ") && l.contains(&path))
        .count();
    assert_eq!((dropped, dfs), (1, 1), "{log}\n{}", view.out);
}

/// The projected day a volume fills is shown with its year once it lies outside the current
/// one, and as more than a year once it is over 8760 hours off: falling 50 MiB an hour with
/// 500 GiB free is over a year, never a bare month and day.
#[test]
fn a_projection_more_than_a_year_off_says_so_and_never_shows_a_bare_month_and_day() {
    let fx = Fx::single();
    fx.witness_ran(60);
    let m = mount_id("/");
    let gib: u64 = 1_073_741_824;
    let mib: u64 = 1_048_576;
    let mut z = String::new();
    for h in (0..=80u64).rev() {
        z.push_str(&format!(
            "Z\t{m}\t{}\t{}\t{}\t6000000\t5000000\n",
            stamp_ago(h * 3600 + 120),
            1000 * gib,
            500 * gib + h * 50 * mib
        ));
    }
    fx.write(
        "var/lib/propolis/witness/observe",
        &format!("#observe v1 g=2\n{z}"),
    );
    let view = fx.run(&["host"]);
    let line = view
        .out
        .lines()
        .find(|l| l.contains("falling "))
        .unwrap_or_else(|| panic!("{}", view.out));
    assert!(line.contains("at risk in more than a year"), "{line}");
    let bare = regex_like_month_day(line);
    assert!(!bare, "{line}");
}

/// Whether `line` holds a month and day (`MM-DD `) with no year before it.
fn regex_like_month_day(line: &str) -> bool {
    let b = line.as_bytes();
    (0..b.len().saturating_sub(5)).any(|i| {
        b[i].is_ascii_digit()
            && b[i + 1].is_ascii_digit()
            && b[i + 2] == b'-'
            && b[i + 3].is_ascii_digit()
            && b[i + 4].is_ascii_digit()
            && b[i + 5] == b' '
            && (i < 3 || b[i - 1] != b'-')
    })
}

/// With a remote database the data volume is not on this host: the host view says it is not
/// readable here, and a data directory a local database left in meta is not mapped.
#[test]
fn a_remote_database_s_data_volume_reads_not_readable_here() {
    let fx = Fx::single();
    fx.env_drop("DATABASE_URL=");
    fx.env_line("DATABASE_URL=postgres://propolis:pw@db.example.invalid/propolis");
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{}\nM\tpg_datadir\t/var/lib/postgresql/16/main\n",
            stamp_ago(60)
        ),
    );
    std::fs::create_dir_all(fx.p("var/lib/postgresql/16/main")).unwrap();
    fx.write(
        "var/lib/propolis/witness/observe",
        &format!("#observe v1 g=2\n{}", z_line(&mount_id("/"), 600)),
    );
    let view = fx.run(&["host"]);
    assert!(
        view.out
            .contains("data volume: not readable here (remote database)"),
        "{}",
        view.out
    );
    assert!(!fx.log().contains("var/lib/postgresql"), "{}", fx.log());
}

/// The opaque id of the collector `cn` under the fixture's salt.
fn collector_id(cn: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg("printf '%s\\0%s\\0%s' \"$1\" collector \"$2\" | sha256sum")
        .arg("_")
        .arg(SALT)
        .arg(cn)
        .output()
        .unwrap();
    format!("c{}", &String::from_utf8_lossy(&out.stdout)[..5])
}

/// A record of the witness's own kind `kind` on `key`, with instance `inst`, opened an hour ago.
fn witness_kind(id: &str, key: &str, kind: &str, stage: &str, tier: &str, inst: &str) -> String {
    let r = record(id, key, stage, tier, "open", NOW - 3600, "-", "-");
    set_field(&set_field(&r, 3, kind), 5, inst)
}

/// An open push-failing marks the publish stage (exit 2, NEXT naming the `push-failing`
/// runbook); on the backup rail an open backup-hung fails it, and the retention and off-host
/// records are noted with the count of sets against KEEP and when a pull was last served.
#[test]
fn an_open_push_failing_marks_publish_and_backup_hung_fails_the_backup_rail() {
    let fx = Fx::single();
    fx.witness_ran(60);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{}\nM\tbackup_sets\t2/7\nM\tpull_last\t{}\n",
            stamp_ago(60),
            stamp_ago(300_000)
        ),
    );
    let records = [
        witness_kind("w#1", "push:cron", "push-failing", "publish", "ACT", "-"),
        witness_kind("w#2", "backup:run", "backup-hung", "backup", "ACT", "-"),
        witness_kind(
            "w#3",
            "backup:keep",
            "backup-retention",
            "backup",
            "NOTICE",
            "-",
        ),
        witness_kind(
            "w#4",
            "backup:pull",
            "backup-offhost",
            "backup",
            "NOTICE",
            "-",
        ),
    ];
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t5\n{}", records.concat()),
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}\n{}", r.out, r.err);
    assert_eq!(r.state("publish"), "FAIL", "{}", r.out);
    assert_eq!(r.marked().as_deref(), Some("publish"), "{}", r.out);
    assert!(
        r.row("publish").contains("public push failing"),
        "{}",
        r.out
    );
    assert!(r.out.contains("#push-failing"), "{}", r.out);
    assert_eq!(r.state("backup"), "FAIL", "{}", r.out);
    let row = r.row("backup");
    assert!(row.contains("backup run has not ended"), "{row}");
    assert!(row.contains("sets 2 of 7"), "{row}");
    assert!(
        row.contains("a set has waited over 72 h for the off-host pull, last served ")
            && !row.contains("never seen"),
        "{row}"
    );
}

/// On a control node an open spool-quiet marks that collector's ship row (exit 2, NEXT naming the
/// `spool-quiet` runbook), and an open gateway-dup warns on the gateway row with the records it
/// counted lost, each collector shown by its braced name only in the walk.
#[test]
fn a_quiet_collector_marks_ship_and_a_dropped_rebuilt_batch_warns_at_the_gateway() {
    let fx = Fx::control();
    fx.witness_ran(60);
    fx.write("var/spool/propolis/gateway/c-01/events.jsonl", "x\n");
    set_mtime(
        &fx.p("var/spool/propolis/gateway/c-01/events.jsonl"),
        NOW - 7200,
    );
    let cid = collector_id("c-01");
    let records = [
        witness_kind(
            "w#1",
            &format!("spool:{cid}"),
            "spool-quiet",
            "ship",
            "ACT",
            &cid,
        ),
        witness_kind(
            "w#2",
            &format!("gwdup:{cid}"),
            "gateway-dup",
            "gateway",
            "ACT",
            &cid,
        ),
    ];
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=3\nN\t3\n{}", records.concat()),
    );
    fx.write(
        "var/lib/propolis/witness/observe",
        &format!(
            "#observe v1 g=2\nP\tseen:gwdup:{cid}\t{}\tok\t-\t5\n",
            stamp_ago(3600)
        ),
    );
    let r = fx.walk();
    assert_eq!(r.code, 2, "{}\n{}", r.out, r.err);
    assert_eq!(r.marked().as_deref(), Some("ship"), "{}", r.out);
    let ship = rows(&r, "ship").join("\n");
    assert!(
        ship.contains("{c-01}") && ship.contains("quiet") && ship.contains("FAIL"),
        "{ship}"
    );
    assert!(r.out.contains("#spool-quiet"), "{}", r.out);
    assert_eq!(r.state("gateway"), "WARN", "{}", r.out);
    let row = r.row("gateway");
    assert!(
        row.contains("rebuilt batch dropped from {c-01}") && row.contains("5 records counted lost"),
        "{row}"
    );
}

/// With only backup-offhost open the backup rail warns, and NEXT names the runbook section that
/// tells what to do about it (`backup-hung`, which holds the retention and off-host text), not
/// the one about a failed backup.
#[test]
fn an_open_backup_offhost_alone_points_next_at_the_section_that_explains_it() {
    let fx = Fx::single();
    fx.witness_ran(60);
    fx.write(
        "var/lib/propolis/witness/meta",
        &format!(
            "#meta v1 g=3\nM\twhere\tpersistent\nM\tlight_last\t{}\nM\tpull_last\t{}\n",
            stamp_ago(60),
            stamp_ago(345_600)
        ),
    );
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t2\n{}",
            witness_kind(
                "w#1",
                "backup:pull",
                "backup-offhost",
                "backup",
                "NOTICE",
                "-"
            )
        ),
    );
    let r = fx.walk();
    assert_eq!(r.state("backup"), "WARN", "{}", r.out);
    let next = r
        .out
        .lines()
        .find(|l| l.starts_with("NEXT "))
        .unwrap_or_default();
    assert!(
        next.contains("health-and-observability.md#backup-hung"),
        "{next}\n{}",
        r.out
    );
}

/// The 64 hex of sha256(SALT NUL "collector" NUL cn), which an opaque id is cut from.
fn collector_hash(cn: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(SALT.as_bytes());
    h.update([0u8]);
    h.update(b"collector");
    h.update([0u8]);
    h.update(cn.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The walk gives a listed collector the id the witness keys it by: pa_id_table widens two
/// colliding ids to 8 hex within its input, so both programs give it every plain spool name and
/// every listed name. A listed collector with no spool directory yet, whose id collides with an
/// unlisted spool's, is still named on the gateway row by the widened id the witness recorded.
#[test]
fn a_listed_collector_without_a_spool_gets_the_widened_id_the_witness_keys_it_by() {
    let mut seen = std::collections::HashMap::new();
    let (a, b) = (0u32..)
        .find_map(|n| {
            let name = format!("c-{n}");
            seen.insert(collector_hash(&name)[..5].to_string(), name.clone())
                .map(|prev| (prev, name))
        })
        .unwrap();
    let fx = Fx::control();
    fx.witness_ran(60);
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_SENSOR_LOGS={a}:{}\n",
            fx.p(&format!("var/spool/propolis/gateway/{a}/events.jsonl"))
                .display()
        ),
    );
    fx.write(
        &format!("var/spool/propolis/gateway/{b}/events.jsonl"),
        "x\n",
    );
    let id = format!("c{}", &collector_hash(&a)[..8]);
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t2\n{}",
            witness_kind(
                "w#1",
                &format!("gwdup:{id}"),
                "gateway-dup",
                "gateway",
                "ACT",
                &id
            )
        ),
    );
    let r = fx.walk();
    let row = r.row("gateway");
    assert!(
        row.contains(&format!("rebuilt batch dropped from {{{a}}}")),
        "{a} {b}: {row}\n{}",
        r.out
    );
    assert!(r.out.contains(&format!("{id}={{{a}}}")), "{}", r.out);
}

// ---- the test page, --ack-test, --setup and VERIFIED --------------------------------------------

const HOOK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert.sh");
const TOPIC: &str = "t0p1c-secret";
const TOKEN_SECRET: &str = "tk_secret";

impl Fx {
    /// A start of the failure-alert unit runs the real hook, deploy/alert.sh, under this root.
    fn with_hook(&mut self) {
        self.setenv("HOOK_SCRIPT", HOOK);
    }

    fn side(&self, ext: &str) -> String {
        std::fs::read_to_string(format!("{}.{ext}", self.log.display())).unwrap_or_default()
    }

    /// The bodies the curl stub was posted, one per post.
    fn posts(&self) -> Vec<String> {
        self.side("post")
            .split("--- body\n")
            .skip(1)
            .map(|b| b.trim_end_matches('\n').to_string())
            .collect()
    }

    /// The fields of the stored test page, numbered as the file numbers them (0 is the type).
    fn testpage(&self) -> Vec<String> {
        let text = std::fs::read_to_string(self.p("var/lib/propolis/witness/testpage"))
            .unwrap_or_default();
        text.lines()
            .find(|l| l.starts_with("T\t"))
            .map(|l| l.split('\t').map(String::from).collect())
            .unwrap_or_default()
    }

    fn ledger(&self) -> Vec<Vec<String>> {
        std::fs::read_to_string(self.p("var/lib/propolis/witness/send-ledger"))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("L\t"))
            .map(|l| l.split('\t').map(String::from).collect())
            .collect()
    }

    /// The alias the walk's header names.
    fn alias(&self) -> String {
        let r = self.walk();
        r.out.split(" = ").next().unwrap().to_string()
    }

    /// Everything this run left that a person or another program can read: what it printed,
    /// every argument a program was started with, every journal line, and every state file.
    fn readable_traces(&self, r: &Run) -> String {
        let mut all = format!("{}\n{}\n{}", r.out, r.err, self.log());
        for name in ["testpage", "send-ledger", "readcheck", "meta", "incidents"] {
            all.push_str(
                &std::fs::read_to_string(self.p(&format!("var/lib/propolis/witness/{name}")))
                    .unwrap_or_default(),
            );
        }
        all.push_str(&std::fs::read_to_string(self.p("run/motd.d/propolis")).unwrap_or_default());
        all
    }

    fn tmp_is_empty(&self) -> bool {
        std::fs::read_dir(self.dir.path().join("tmp"))
            .unwrap()
            .next()
            .is_none()
    }
}

fn hold_lock(path: &Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    if !path.exists() {
        std::fs::write(path, b"").unwrap();
    }
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: flock on a descriptor this process owns has no other precondition.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0, "could not take the lock");
    file
}

/// The test page goes out through the failure-alert unit, once, in its fixed shape: the alias
/// and the code and nothing that names the host, a unit or the software, at priority 3. The topic
/// and the token reach curl only in its config file (mode 0600, gone afterwards); curl's command
/// line is `-q -K <file>`, and neither secret is printed, logged or stored. The command prints
/// `sent test page <CODE>: ok` with the code the record holds, the one --ack-test takes; the
/// code is not a secret, since the unit's name carries it too.
#[test]
fn the_test_page_is_exact_and_carries_no_host_name() {
    let mut fx = Fx::single();
    fx.with_hook();
    let alias = fx.alias();
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 0, "{}\n{}\n{}", r.out, r.err, fx.log());
    let tp = fx.testpage();
    let code = tp[1].clone();
    assert_eq!(
        r.out,
        format!(
            "sent test page {code}: ok. When it arrives, type back the code it carries: sudo propolis-status --ack-test {code}\n"
        )
    );
    assert!(
        code.len() == 6
            && code
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "{tp:?}"
    );
    assert_eq!(
        (tp[5].as_str(), tp[6].as_str(), tp[7].as_str()),
        ("ok", "-", "-")
    );
    assert_eq!(
        fx.posts(),
        [format!("Type back on {alias}: status --ack-test {code}")],
        "{}",
        fx.side("post")
    );
    let conf = fx.side("conf");
    assert!(conf.starts_with("--- 600\n"), "{conf}");
    for line in [
        format!("url = \"https://ntfy.example.invalid/{TOPIC}\""),
        format!("header = \"Title: {alias}: test page {code}\""),
        "header = \"Priority: 3\"".to_string(),
        format!("header = \"Authorization: Bearer {TOKEN_SECRET}\""),
        "data-binary = \"@-\"".to_string(),
        "proto = \"=https,http\"".to_string(),
        "globoff".to_string(),
    ] {
        assert!(conf.lines().any(|l| l == line), "{line} not in:\n{conf}");
    }
    assert!(!conf.contains("Tags:"), "{conf}");
    for planted in ["honeybox", "sensor-", "propolis", "ntfy"] {
        assert!(!fx.posts()[0].contains(planted), "{planted}");
        assert!(
            !format!("{alias}: test page {code}").contains(planted),
            "{planted}"
        );
    }
    let log = fx.log();
    // The walk that named the alias asked the console on loopback; every other call is the post.
    let posts: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with("curl ") && !l.contains("127.0.0.1"))
        .collect();
    assert_eq!(posts.len(), 1, "{}", fx.log());
    assert!(
        posts[0].starts_with("curl [-q] [-K] [") && posts[0].matches('[').count() == 3,
        "{}",
        posts[0]
    );
    assert!(
        fx.log().contains(&format!(
            "systemctl start -- propolis-alert@propolis-test-page-{code}.service"
        )),
        "{}",
        fx.log()
    );
    let traces = fx.readable_traces(&r);
    for secret in [TOPIC, TOKEN_SECRET] {
        assert!(
            !traces.contains(secret),
            "{secret} left where it can be read"
        );
    }
    assert!(fx.tmp_is_empty(), "a temporary file outlived the send");
    let ledger = fx.ledger();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(
        (
            ledger[0][2].as_str(),
            ledger[0][6].as_str(),
            ledger[0][7].as_str()
        ),
        ("test", "ok", "hook"),
        "{ledger:?}"
    );
    for name in ["testpage", "send-ledger"] {
        let mode = std::fs::metadata(fx.p(&format!("var/lib/propolis/witness/{name}")))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name}");
    }
}

/// At most three test pages in 24 hours, counted before the send and whatever came of them; a
/// page that sent nothing (norender) and one over a day old do not count. The fourth is withheld
/// before any unit is started.
#[test]
fn the_fourth_test_page_in_a_day_is_withheld() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &format!(
            "#send-ledger v1 g=1\nL\t{}\ttest\t-\topen\tfull\ttransient:503\thook\nL\t{}\ttest\t-\topen\tfull\tnorender\thook\nL\t{}\ttest\t-\topen\tfull\tok\thook\n",
            stamp_ago(3600),
            stamp_ago(1800),
            stamp_ago(90_000)
        ),
    );
    for _ in 0..2 {
        let r = fx.run(&["--test-page"]);
        assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    }
    let starts = fx.log().matches("systemctl start ").count();
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out.contains("test page budget spent (3 in 24 h)"),
        "{}",
        r.out
    );
    assert_eq!(fx.log().matches("systemctl start ").count(), starts);
    assert_eq!(fx.posts().len(), 2);
}

/// A failure-alert unit that never runs (masked, not installed, its start refused) leaves each
/// attempt pending, and the hook claims a page as sending before it sends: once the hook's whole
/// time has passed, a pending attempt was never sent and no longer counts. So three such attempts
/// withhold a fourth only for that time: three minutes on, a fourth is admitted. Three pages that
/// went out still withhold a fourth, and the message says when the next is allowed.
#[test]
fn attempts_whose_unit_never_ran_do_not_spend_the_day() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.setenv("START_FAIL", "1");
    for _ in 0..3 {
        let r = fx.run(&["--test-page"]);
        assert!(
            r.out.contains("the failure-alert unit did not run"),
            "{}",
            r.out
        );
    }
    let r = fx.run(&["--test-page"]);
    assert_eq!(
        r.out,
        "test page budget spent (3 in 24 h): nothing sent; the next is allowed at 08:02 UTC\n"
    );
    fx.setenv("PROPOLIS_STATUS_NOW", "1800000180/abcdef01/900180");
    let starts = fx.log().matches("systemctl start ").count();
    let r = fx.run(&["--test-page"]);
    assert!(
        r.out.contains("the failure-alert unit did not run"),
        "three minutes on, a fourth is admitted: {}",
        r.out
    );
    assert_eq!(fx.log().matches("systemctl start ").count(), starts + 1);

    let mut fx = Fx::single();
    fx.with_hook();
    for _ in 0..3 {
        assert_eq!(fx.run(&["--test-page"]).code, 0);
    }
    fx.setenv("PROPOLIS_STATUS_NOW", "1800000180/abcdef01/900180");
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 1);
    assert_eq!(
        r.out,
        "test page budget spent (3 in 24 h): nothing sent; the next is allowed at 08:01 UTC\n"
    );
    assert_eq!(fx.posts().len(), 3);
}

/// --test-page prints `sent test page <CODE>` only for a page that left the host. When nothing
/// was sent it says so and why, in words; when the server did not take the page it says so with
/// the result and a next step, and that the page counted toward the three a day.
#[test]
fn the_test_page_says_in_words_what_became_of_a_page_that_was_not_taken() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "START_RESULT",
            "nocurl",
            "test page not sent: curl is not installed here; install it (today's failure hook cannot push without it either)",
        ),
        (
            "START_RESULT",
            "notarget",
            "test page not sent: the failure-alert unit found no push target; see sudo propolis-status --setup",
        ),
        (
            "START_RESULT",
            "norender",
            "test page not sent: it could not be put together (no alias yet, or a value that cannot be sent safely); see sudo propolis-status --setup",
        ),
        (
            "START_RESULT",
            "nomatch",
            "test page not sent: the failure-alert unit ran over 10 minutes after the page was asked for; send another",
        ),
        (
            "START_RESULT",
            "noclaim",
            "test page not sent: the failure-alert unit could not write its claim on the send ledger (/var/lib/propolis/witness, /run/propolis-witness); send another once there is room",
        ),
        (
            "POST_CODE",
            "403",
            "not accepted by the server (perm:403): check the token and that it may write to the topic; it counted toward the three a day",
        ),
        (
            "POST_CODE",
            "404",
            "not accepted by the server (perm:404): check PROPOLIS_OPS_NTFY_URL and the topic; it counted toward the three a day",
        ),
        (
            "POST_CODE",
            "503",
            "not accepted by the server (transient:503): try again later; it counted toward the three a day",
        ),
    ];
    for (k, v, want) in cases {
        let mut fx = Fx::single();
        fx.with_hook();
        fx.setenv(k, v);
        let r = fx.run(&["--test-page"]);
        assert_eq!(r.code, 1, "{v}: {}\n{}", r.out, r.err);
        assert!(r.out.contains(want), "{v}: {want} not in:\n{}", r.out);
        assert!(!r.out.contains("sent test page"), "{v}: {}", r.out);
        if *k == "POST_CODE" {
            let code = fx.testpage()[1].clone();
            assert!(
                r.out.starts_with(&format!("test page {code} not accepted")),
                "{v}: {}",
                r.out
            );
        }
    }
}

/// The VERIFIED field at the end of the walk's ALERTS line.
fn alerts_verified(fx: &Fx) -> String {
    let r = fx.walk();
    let line = r
        .out
        .lines()
        .find(|l| l.starts_with("ALERTS  "))
        .unwrap_or_else(|| panic!("{}", r.out))
        .to_string();
    line.rsplit(" - ").next().unwrap().to_string()
}

/// --ack-test sets VERIFIED once, for the code the page carried; a wrong code and a page over a
/// day old change nothing, and the same code a second time says it was acknowledged already and
/// changes nothing either. VERIFIED then holds only while every rule does: a changed topic or
/// token, a removed target, a month gone or an acknowledgement dated after now, a permanent
/// refusal, an alert-path incident or an undelivered hook alert after the acknowledgement each
/// undo it, and a stamp that cannot be dated counts as after it; a transient failure does not;
/// and a file that cannot be read is not VERIFIED.
#[test]
fn ack_test_verifies_once_and_each_rule_undoes_it() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.setenv("SUDO_UID", "1000");
    let verified = alerts_verified;
    assert_eq!(verified(&fx), "NOT VERIFIED (never); daemon not verified");
    assert_eq!(fx.run(&["--test-page"]).code, 0);
    assert_eq!(verified(&fx), "NOT VERIFIED (pending); daemon not verified");
    let tp = fx.testpage();
    let code = tp[1].clone();
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let r = fx.run(&["--ack-test", wrong]);
    assert_eq!((r.code, r.out.as_str()), (1, "wrong or expired code\n"));
    assert_eq!(fx.testpage(), tp, "a wrong code changes nothing");
    let r = fx.run(&["--ack-test", &code]);
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    assert_eq!(r.out, "VERIFIED: the test page reached you\n");
    let acked = fx.testpage();
    assert_eq!((acked[6].as_str(), acked[7].as_str()), (STAMP, "1000"));
    let file = std::fs::read(fx.p("var/lib/propolis/witness/testpage")).unwrap();
    let r = fx.run(&["--ack-test", &code]);
    assert_eq!(
        (r.code, r.out.as_str()),
        (0, "already acknowledged at 08:00 UTC: VERIFIED stands\n"),
        "a code is typed back once"
    );
    assert_eq!(
        std::fs::read(fx.p("var/lib/propolis/witness/testpage")).unwrap(),
        file
    );
    assert_eq!(verified(&fx), "VERIFIED 0 min (shell); daemon not verified");
    let banner = fx.run(&["--banner"]);
    assert!(
        banner
            .out
            .contains("[propolis 08:00 UTC] alerts: VERIFIED 0 min (shell); daemon not verified\n"),
        "{}",
        banner.out
    );

    // Each rule from here on, against a record acknowledged ten minutes ago.
    let write_tp = |fx: &Fx, sent: &str, result: &str, acked: &str| {
        fx.write(
            "var/lib/propolis/witness/testpage",
            &format!(
                "#testpage v1 g=9\nT\t{code}\t{sent}\t{}\t{}\t{result}\t{acked}\t1000\n",
                tp[3], tp[4]
            ),
        );
    };
    write_tp(&fx, &stamp_ago(900), "ok", &stamp_ago(600));
    assert_eq!(
        verified(&fx),
        "VERIFIED 10 min (shell); daemon not verified"
    );
    fx.env_drop("PROPOLIS_OPS_NTFY_TOPIC=");
    fx.env_line("PROPOLIS_OPS_NTFY_TOPIC=another-topic");
    assert!(verified(&fx).starts_with("NOT VERIFIED (changed)"));
    fx.env_drop("PROPOLIS_OPS_NTFY_TOPIC=");
    fx.env_line(&format!("PROPOLIS_OPS_NTFY_TOPIC={TOPIC}"));
    fx.env_drop("PROPOLIS_OPS_NTFY_TOKEN=");
    fx.env_line("PROPOLIS_OPS_NTFY_TOKEN=tk_other");
    assert!(verified(&fx).starts_with("NOT VERIFIED (changed)"));
    fx.env_drop("PROPOLIS_OPS_NTFY_TOKEN=");
    fx.env_line(&format!("PROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}"));
    assert!(verified(&fx).starts_with("VERIFIED"));
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    assert!(verified(&fx).starts_with("NOT VERIFIED (changed)"));
    fx.env_line("PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid");
    assert!(verified(&fx).starts_with("VERIFIED"));
    // A month back is another boot: its age comes from the wall clock.
    let month = |ago: u64| format!("{}/0000aaaa/1", NOW - ago);
    write_tp(&fx, &month(31 * 86400 + 60), "ok", &month(31 * 86400));
    assert!(verified(&fx).starts_with("NOT VERIFIED (expired)"));
    // An acknowledgement dated after now on this boot is not trusted either.
    write_tp(
        &fx,
        &stamp_ago(900),
        "ok",
        &format!("{}/abcdef01/{}", NOW + 600, 900_600),
    );
    assert!(verified(&fx).starts_with("NOT VERIFIED (expired)"));
    write_tp(&fx, &stamp_ago(900), "ok", &stamp_ago(600));
    let ledger = |result: &str| {
        format!(
            "#send-ledger v1 g=5\nL\t{}\ttest\t-\topen\tfull\tperm:403\thook\nL\t{}\ttest\t-\topen\tfull\t{result}\thook\n",
            stamp_ago(1200),
            stamp_ago(60)
        )
    };
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        &ledger("transient:503"),
    );
    assert!(
        verified(&fx).starts_with("VERIFIED"),
        "a refusal before the ack and a transient after it undo nothing"
    );
    fx.write("var/lib/propolis/witness/send-ledger", &ledger("perm:401"));
    assert!(verified(&fx).starts_with("NOT VERIFIED (refused)"));
    fx.write(
        "var/lib/propolis/witness/send-ledger",
        "#send-ledger v1 g=6\nL\tnot-a-stamp\ttest\t-\topen\tfull\tperm:401\thook\n",
    );
    assert!(
        verified(&fx).starts_with("NOT VERIFIED (refused)"),
        "a refusal that cannot be dated counts as after the ack"
    );
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    assert!(verified(&fx).starts_with("NOT VERIFIED (unreadable)"));
    std::fs::remove_file(fx.p("var/lib/propolis/witness/send-ledger")).unwrap();
    let mut path = record(
        "w#7",
        "alert:shell",
        "alert",
        "PAGE",
        "open",
        NOW - 60,
        "alert.undelivered",
        "-",
    );
    path = set_field(&path, 3, "alert-path");
    path = set_field(&path, 9, &stamp_ago(60));
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!("#incidents v1 g=2\nN\t8\n{path}"),
    );
    assert!(verified(&fx).starts_with("NOT VERIFIED (path-failed)"));
    fx.write(
        "var/lib/propolis/witness/incidents",
        &format!(
            "#incidents v1 g=3\nN\t8\n{}",
            set_field(&path, 9, "not-a-stamp")
        ),
    );
    assert!(
        verified(&fx).starts_with("NOT VERIFIED (path-failed)"),
        "an opening that cannot be dated counts as after the ack"
    );
    fx.write("var/lib/propolis/witness/incidents", "garbage\n");
    assert!(verified(&fx).starts_with("NOT VERIFIED (unreadable)"));
    std::fs::remove_file(fx.p("var/lib/propolis/witness/incidents")).unwrap();
    let undelivered = fx.p("run/propolis-alert/undelivered/sensor-ssh.service");
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        &format!("{} 1 {}\n", NOW - 60, NOW - 60),
    );
    set_mtime(&undelivered, NOW - 60);
    assert!(verified(&fx).starts_with("NOT VERIFIED (undelivered)"));
    // Either date after the acknowledgement is enough: the last attempt, or the first failure.
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        &format!("{} 1 {}\n", NOW - 900, NOW - 900),
    );
    set_mtime(&undelivered, NOW - 60);
    assert!(verified(&fx).starts_with("NOT VERIFIED (undelivered)"));
    fx.write(
        "run/propolis-alert/undelivered/sensor-ssh.service",
        &format!("{} 1 {}\n", NOW - 60, NOW - 60),
    );
    set_mtime(&undelivered, NOW - 900);
    assert!(verified(&fx).starts_with("NOT VERIFIED (undelivered)"));
    std::fs::remove_file(&undelivered).unwrap();
    assert!(verified(&fx).starts_with("VERIFIED"));
    // An undelivered list that is not a directory cannot be read: a file, then a link.
    let dir = fx.p("run/propolis-alert/undelivered");
    std::fs::remove_dir(&dir).unwrap();
    std::fs::write(&dir, "").unwrap();
    assert!(verified(&fx).starts_with("NOT VERIFIED (unreadable)"));
    std::fs::remove_file(&dir).unwrap();
    std::fs::create_dir_all(fx.p("run/elsewhere")).unwrap();
    std::os::unix::fs::symlink(fx.p("run/elsewhere"), &dir).unwrap();
    assert!(verified(&fx).starts_with("NOT VERIFIED (unreadable)"));
    std::fs::remove_file(&dir).unwrap();
    assert!(verified(&fx).starts_with("VERIFIED"));
    fx.write("var/lib/propolis/witness/testpage", "garbage\n");
    assert!(verified(&fx).starts_with("NOT VERIFIED (unreadable)"));
    // A page that went out over a day ago can no longer be acknowledged.
    fx.write(
        "var/lib/propolis/witness/testpage",
        &format!(
            "#testpage v1 g=9\nT\t{code}\t{}\t{}\t{}\tok\t-\t-\n",
            stamp_ago(86_460),
            tp[3],
            tp[4]
        ),
    );
    let r = fx.run(&["--ack-test", &code]);
    assert_eq!((r.code, r.out.as_str()), (1, "wrong or expired code\n"));
}

/// --setup runs the anonymous-read check now and says what it found in the check's own words,
/// with every code and content type; it stores the answer, keeps a stored refusal through a
/// transient answer, and exits 0 only when the gate is full. It never prints the token or the
/// topic (only how long the topic is) and of the URL only its scheme and host.
#[test]
fn setup_classifies_each_answer_and_never_prints_the_token_or_topic() {
    let mut fx = Fx::single();
    let cases: &[(&str, &str, &str, &str, i32)] = &[
        (
            "403|text/plain",
            "403|text/plain",
            "403|text/plain",
            "refused",
            0,
        ),
        ("503|", "403|text/plain", "403|text/plain", "transient", 0),
        (
            "200|application/x-ndjson; charset=utf-8",
            "403|text/plain",
            "403|text/plain",
            "readable",
            1,
        ),
        (
            "302|text/html",
            "302|text/html",
            "302|text/html",
            "redirect",
            1,
        ),
        (
            "200|text/html",
            "403|text/plain",
            "403|text/plain",
            "not_ntfy",
            1,
        ),
        (
            "404|text/plain",
            "404|text/plain",
            "404|text/plain",
            "not_found",
            1,
        ),
    ];
    for (json, raw, sse, class, code) in cases {
        fx.setenv("RC_JSON", json);
        fx.setenv("RC_RAW", raw);
        fx.setenv("RC_SSE", sse);
        let r = fx.run(&["--setup"]);
        assert_eq!(r.code, *code, "{class}:\n{}\n{}", r.out, r.err);
        let anon = r
            .out
            .lines()
            .find(|l| l.starts_with("anon read   checked now: "))
            .unwrap_or_else(|| panic!("{}", r.out));
        assert!(anon.ends_with(&format!(" -> {class}")), "{anon}");
        let jc: Vec<&str> = json.split('|').collect();
        let want_ct = jc[1].split(';').next().unwrap();
        let want_ct = if want_ct.is_empty() { "-" } else { want_ct };
        assert!(
            anon.contains(&format!("json {} ({want_ct})", jc[0])),
            "{anon}"
        );
        assert!(
            r.out.contains("target      ntfy from propolis.env: URL https://ntfy.example.invalid, topic set (12 chars), token set"),
            "{}",
            r.out
        );
        let traces = fx.readable_traces(&r);
        for secret in [TOPIC, TOKEN_SECRET] {
            assert!(
                !traces.contains(secret),
                "{class}: {secret} left where it can be read"
            );
        }
        let stored = std::fs::read_to_string(fx.p("var/lib/propolis/witness/readcheck")).unwrap();
        let line = stored.lines().find(|l| l.starts_with("R\t")).unwrap();
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f[9], "both", "{line}");
        if *class == "transient" {
            assert_eq!(
                (f[3], f[5]),
                ("transient", "refused"),
                "the refusal stands: {line}"
            );
            assert!(
                r.out
                    .contains("no definite answer: the one stored before stands")
            );
        } else {
            assert_eq!((f[3], f[5]), (*class, *class), "{line}");
        }
        let daemon = r.out.lines().any(|l| l.starts_with("daemon      "));
        assert_eq!(daemon, *code == 1, "{class}: the daemon line\n{}", r.out);
        assert!(r.out.contains("verified    NOT VERIFIED (never); daemon not verified. Run: sudo propolis-status --test-page"), "{}", r.out);
    }
    // A path, a user and a query in the URL stay out of the report.
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    fx.env_line("PROPOLIS_OPS_NTFY_URL=https://user:pw@ntfy.example.invalid/base?auth=q");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out
            .contains("URL https://ntfy.example.invalid, topic set"),
        "{}",
        r.out
    );
    for hidden in ["user", ":pw", "base", "auth="] {
        assert!(!r.out.contains(hidden), "{hidden} in:\n{}", r.out);
    }
}

/// On a collector whose token can read the topic, --setup says so, says a collector should use a
/// topic of its own, holds the gate at pointer and exits 1. The alert.env lines a later release
/// adds are not offered.
#[test]
fn setup_on_a_collector_with_a_reading_token_says_so() {
    let mut fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC={TOPIC}\nPROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}\n"),
    );
    fx.setenv("RC_TOKEN_ANSWER", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    for want in [
        "setup on host-",
        ", collector)",
        "token       reads (this token can read the topic)",
        "collectors should use their own topic: on ntfy.sh a token carries its user's read rights",
        "gate        pointer:token-reads",
        "verified    NOT VERIFIED (never). Run: sudo propolis-status --test-page",
    ] {
        assert!(r.out.contains(want), "{want} not in:\n{}", r.out);
    }
    for absent in [
        "alert.env",
        "PROPOLIS_ALERT_PROFILE",
        "daemon not verified",
        "daily",
        "profile",
    ] {
        assert!(!r.out.contains(absent), "{absent} in:\n{}", r.out);
    }
}

/// The channel line names the alias test pages name this host by, the same one the walk shows,
/// and says that today's failure alerts name it by its host name; off a single box it warns that a
/// fallback alias cannot be told from other hosts'. --setup makes the salt the alias comes from
/// when there is none yet, mode 0600.
#[test]
fn setup_prints_the_channel_alias_and_warns_on_a_fallback_off_a_single_box() {
    let fx = Fx::single();
    std::fs::remove_file(fx.p("var/lib/propolis/witness/id-salt")).unwrap();
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    assert!(r.out.contains("salt        created now"), "{}", r.out);
    let salt = fx.p("var/lib/propolis/witness/id-salt");
    assert_eq!(
        std::fs::metadata(&salt).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let alias = fx.alias();
    assert!(alias.starts_with("host-") && alias.len() == 9, "{alias}");
    assert!(
        r.out
            .starts_with(&format!("setup on {alias} (honeybox, single box)\n")),
        "{}",
        r.out
    );
    assert!(
        r.out.contains(&format!(
            "channel     test pages (and the shell messages of a later release) name this host by its alias, {alias}: record it; today's failure alerts name it by its host name, honeybox\n"
        )),
        "{}",
        r.out
    );
    assert!(!r.out.contains("warning"), "{}", r.out);
    let fx = Fx::control();
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains(
            "record it; today's failure alerts name it by its host name, honeybox; warning: a fallback alias cannot be told from other hosts' on a phone"
        ),
        "{}",
        r.out
    );
    assert!(r.out.contains("salt        ok"), "{}", r.out);
}

/// Over plain http a 403 proves nothing: anyone on the path could have answered it and can read
/// every push. --setup says the gate needs https, the gate is pointer:insecure, and it exits 1.
#[test]
fn setup_over_http_says_the_gate_needs_https() {
    let fx = Fx::single();
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    fx.env_line("PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid");
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert!(r.out.contains("-> refused"), "{}", r.out);
    assert!(
        r.out.contains("gate needs https: over http anyone on the path can fake this answer and read the pushes"),
        "{}",
        r.out
    );
    assert!(r.out.contains("gate        pointer:insecure"), "{}", r.out);
}

/// While another writer holds the state lock, --test-page, --ack-test and --setup each give up
/// after 10 s with exit 75: nothing is sent, no unit is started and no record changes.
#[test]
fn a_held_lock_makes_the_test_page_verbs_exit_75() {
    let mut fx = Fx::single();
    fx.with_hook();
    let lock = hold_lock(&fx.p("var/lib/propolis/witness/state.lock"));
    for args in [
        vec!["--test-page"],
        vec!["--ack-test", "abcdef"],
        vec!["--setup"],
    ] {
        let started = std::time::Instant::now();
        let r = fx.run(&args);
        assert_eq!(r.code, 75, "{args:?}: {}\n{}", r.out, r.err);
        assert!(r.err.contains("the state lock is busy"), "{}", r.err);
        assert!(started.elapsed() < Duration::from_secs(40), "{args:?}");
    }
    drop(lock);
    assert!(!fx.log().contains("systemctl start"), "{}", fx.log());
    assert!(fx.posts().is_empty());
    assert!(fx.testpage().is_empty());
}

/// Two --test-page runs at once each write their own record, the later replacing the earlier; a
/// hook started for a replaced code sends nothing, so every page that went out is one a run
/// reported as sent, no code goes out twice, and both attempts are in the ledger. A run whose
/// unit did not run says so; a missing state directory sends nothing at all.
#[test]
fn two_test_pages_at_once_or_a_replaced_code_never_send_twice() {
    let mut fx = Fx::single();
    fx.with_hook();
    let mut children = Vec::new();
    for _ in 0..2 {
        let mut command = fx.command(&["--test-page"]);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let _fence = EXEC_FENCE.lock().unwrap_or_else(|e| e.into_inner());
        children.push(command.spawn().unwrap());
    }
    let mut sent = 0;
    for child in children {
        let out = child.wait_with_output().unwrap();
        if out.status.code() == Some(0) {
            sent += 1;
        } else {
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(text.contains("replaced"), "{text}");
        }
    }
    let posts = fx.posts();
    assert_eq!(posts.len(), sent, "{posts:?}");
    assert!(sent >= 1);
    if posts.len() == 2 {
        assert_ne!(posts[0], posts[1]);
    }
    assert_eq!(fx.ledger().len(), 2, "{:?}", fx.ledger());

    fx.setenv("START_FAIL", "1");
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 1);
    // A record left pending is also what a unit leaves that ran and could not write it, so the
    // line names both and points at the unit's journal, which says which.
    assert!(
        r.out.contains("not sent: the failure-alert unit did not run, or could not write the page's record (see: journalctl -u propolis-alert@propolis-test-page-"),
        "{}",
        r.out
    );
    assert_eq!(fx.posts().len(), sent);
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains("The last test page was not sent: the failure-alert unit did not run, or could not write the page's record (see journalctl -u propolis-alert@propolis-test-page-"),
        "{}",
        r.out
    );

    let fx = Fx::single();
    std::fs::remove_dir_all(fx.p("var/lib/propolis/witness")).unwrap();
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert!(r.out.contains("test page not sent"), "{}", r.out);
    assert!(!fx.log().contains("systemctl start"), "{}", fx.log());
}

/// Without a push target there is nothing to test: --test-page sends nothing and says so, and
/// --setup says where the hook's alerts go instead, prints no channel line (nothing names this
/// host on a channel) and exits 1.
#[test]
fn without_a_target_the_test_page_sends_nothing_and_setup_says_so() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.env_drop("PROPOLIS_OPS_NTFY_");
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 1);
    assert!(
        r.out.starts_with("no push target: nothing sent"),
        "{}",
        r.out
    );
    assert!(!fx.log().contains("systemctl start"));
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 1);
    assert!(
        r.out
            .contains("target      none: the failure hook writes its alerts to the journal"),
        "{}",
        r.out
    );
    assert!(r.out.contains("gate        none:notarget"), "{}", r.out);
    assert!(
        !r.out.lines().any(|l| l.starts_with("channel ")),
        "no channel line without a target:\n{}",
        r.out
    );
    assert!(!fx.log().contains("curl "), "no request without a target");
}

impl Fx {
    /// Takes curl off `PATH`: the stubs first, then a directory of links to every other program
    /// on the test's `PATH`, so the script keeps bash and the coreutils but finds no curl.
    fn without_curl(&mut self) {
        std::fs::remove_file(self.bin.join("curl")).unwrap();
        let farm = self.dir.path().join("no-curl");
        std::fs::create_dir_all(&farm).unwrap();
        for dir in std::env::split_paths(&std::env::var("PATH").unwrap()) {
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
        let path = format!("{}:{}", self.bin.display(), farm.display());
        self.setenv("PATH", &path);
    }

    /// A `sync` on `PATH` that fails for every temporary file of the state file `name`, so both
    /// state directories refuse that one write whoever runs the test, and succeeds otherwise.
    fn refuse_writes_of(&self, name: &str) {
        write_exec(
            &self.bin.join("sync"),
            &format!("#!/usr/bin/env bash\ncase \"$*\" in *{name}.tmp.*) exit 1 ;; esac\nexit 0\n"),
        );
    }

    /// The `verified` line of --setup.
    fn setup_verified(&self) -> String {
        let r = self.run(&["--setup"]);
        r.out
            .lines()
            .find(|l| l.starts_with("verified    "))
            .unwrap_or_else(|| panic!("{}\n{}", r.out, r.err))
            .to_string()
    }

    /// The process the curl stub started to hold the state lock, stopped.
    fn release_holder(&self) {
        let pid = self.side("holder");
        if let Ok(pid) = pid.trim().parse::<i32>() {
            // SAFETY: kill has no memory preconditions; the pid is the stub's own child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// The banner's alerts line, without its prefix.
fn banner_alerts(fx: &Fx) -> String {
    let r = fx.run(&["--banner"]);
    r.out
        .lines()
        .find_map(|l| l.split_once("] alerts: ").map(|(_, a)| a.to_string()))
        .unwrap_or_else(|| panic!("{}", r.out))
}

/// One test page through the hook, and its code typed back; the code.
fn page_and_ack(fx: &Fx) -> String {
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 0, "{}\n{}\n{}", r.out, r.err, fx.log());
    let code = fx.testpage()[1].clone();
    let r = fx.run(&["--ack-test", &code]);
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
    code
}

/// The test page proves the path as the library reads propolis.env, and today's failure hook
/// reads the file with a rule of its own (the last line that starts with `KEY=`). Where the two
/// read the target differently no real failure page is proven: an indented `KEY = value` topic,
/// which the hook does not see at all, and a token with a trailing comment or over 256
/// characters, which the library ignores as invalid and the hook sends whole. The walk and the
/// banner say NOT VERIFIED, the acknowledgement itself says so and names the setting, and --setup
/// names the setting and its fix: for a value the shell senders ignore as invalid, the rule it
/// breaks; for one the hook reads otherwise, to write it plainly. Another test page cannot clear
/// `changed` there, so it is not offered. The same steps with the lines written plainly verify.
#[test]
fn a_target_todays_hook_reads_otherwise_is_never_verified() {
    let long = "k".repeat(300);
    let cases = [
        (
            "PROPOLIS_OPS_NTFY_TOPIC=",
            format!("  PROPOLIS_OPS_NTFY_TOPIC = {TOPIC}"),
            format!("PROPOLIS_OPS_NTFY_TOPIC={TOPIC}"),
            "PROPOLIS_OPS_NTFY_TOPIC",
        ),
        (
            "PROPOLIS_OPS_NTFY_TOKEN=",
            format!("PROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}  # ops phone"),
            format!("PROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}"),
            "PROPOLIS_OPS_NTFY_TOKEN",
        ),
        (
            "PROPOLIS_OPS_NTFY_TOKEN=",
            format!("PROPOLIS_OPS_NTFY_TOKEN={long}"),
            format!("PROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}"),
            "PROPOLIS_OPS_NTFY_TOKEN",
        ),
    ];
    let rule = "1 to 256 printable characters with no blank";
    for (prefix, odd, plain, key) in &cases {
        let invalid = *key == "PROPOLIS_OPS_NTFY_TOKEN";
        let (ack_why, verified_fix, setup_fix) = if invalid {
            (
                format!("the shell senders ignore {key} as invalid; set {key} to {rule}"),
                format!(
                    ". Set {key} in /etc/propolis/propolis.env to {rule}, written plainly on one line"
                ),
                format!(
                    "            the shell senders ignore {key} as invalid; set {key} to {rule}\n"
                ),
            )
        } else {
            (
                format!("today's failure hook reads {key} otherwise"),
                ". Write each push setting in /etc/propolis/propolis.env as KEY=value at the start of its line, with no blank or comment".to_string(),
                format!(
                    "            today's failure hook reads {key} otherwise: write each push setting as KEY=value at the start of its line, with no blank or comment\n"
                ),
            )
        };
        for (line, verified) in [(odd, false), (plain, true)] {
            let mut fx = Fx::single();
            fx.with_hook();
            fx.env_drop(prefix);
            fx.env_line(line);
            let r = fx.run(&["--test-page"]);
            assert_eq!(r.code, 0, "{}\n{}\n{}", r.out, r.err, fx.log());
            let code = fx.testpage()[1].clone();
            let ack = fx.run(&["--ack-test", &code]);
            assert_eq!(ack.code, 0, "{}\n{}", ack.out, ack.err);
            if verified {
                assert_eq!(ack.out, "VERIFIED: the test page reached you\n");
            } else {
                assert_eq!(
                    ack.out,
                    format!(
                        "acknowledged; NOT VERIFIED (changed): {ack_why}: see sudo propolis-status --setup\n"
                    )
                );
                let line = fx.setup_verified();
                assert!(!line.contains("--test-page"), "{line}");
                assert!(line.ends_with(&verified_fix), "{line}");
                if invalid {
                    assert!(!line.contains("Write each push setting"), "{line}");
                }
            }
            let field = alerts_verified(&fx);
            let banner = banner_alerts(&fx);
            assert_eq!(field.starts_with("VERIFIED"), verified, "{line}: {field}");
            assert_eq!(banner.starts_with("VERIFIED"), verified, "{line}: {banner}");
            if !verified {
                assert!(field.starts_with("NOT VERIFIED (changed)"), "{field}");
            }
            let r = fx.run(&["--setup"]);
            assert_eq!(r.out.contains(&setup_fix), !verified, "{line}:\n{}", r.out);
            if invalid {
                assert!(
                    !r.out.contains("today's failure hook reads"),
                    "{line}:\n{}",
                    r.out
                );
            }
            let traces = fx.readable_traces(&r);
            for secret in [TOPIC, TOKEN_SECRET, long.as_str()] {
                assert!(!traces.contains(secret), "{line}: {secret} printed");
            }
        }
    }
}

/// When the shell senders ignore the URL or the topic as invalid, --setup does not say that
/// nothing is pushed: today's failure hook reads the raw lines and still posts there with the
/// host and unit names, its journal lines and the token, and with no scheme curl uses plain
/// http. --setup says so, shows of the URL only its scheme and host, never the topic or the token,
/// and gives the fix.
#[test]
fn setup_says_todays_hook_still_posts_to_a_setting_the_shell_senders_ignore() {
    let fx = Fx::single();
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    fx.env_line("PROPOLIS_OPS_NTFY_URL=ntfy.example.invalid");
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    for absent in [
        "writes its alerts to the journal",
        "nothing is pushed",
        TOPIC,
        TOKEN_SECRET,
    ] {
        assert!(!r.out.contains(absent), "{absent} in:\n{}", r.out);
    }
    for want in [
        "target      none for the shell senders, which ignore PROPOLIS_OPS_NTFY_URL as invalid; today's failure hook still posts to it (no scheme: curl uses plain http), with the host and unit names, its journal lines and the token\n",
        "            fix (config-check alert-setting-invalid): in /etc/propolis/propolis.env set PROPOLIS_OPS_NTFY_URL to an http:// or https:// URL with a host and no blanks, written plainly on one line\n",
        "gate        none:notarget  - the shell senders push nothing; today's failure hook still posts (see target)\n",
    ] {
        assert!(r.out.contains(want), "{want} not in:\n{}", r.out);
    }

    let fx = Fx::single();
    fx.env_drop("PROPOLIS_OPS_NTFY_TOPIC=");
    fx.env_line("PROPOLIS_OPS_NTFY_TOPIC=has.a.dot");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains("target      none for the shell senders, which ignore PROPOLIS_OPS_NTFY_TOPIC as invalid; today's failure hook still posts to it (URL https://ntfy.example.invalid), with the host and unit names, its journal lines and the token\n"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("has.a.dot"), "{}", r.out);
}

/// Wherever the shell senders have no target and today's failure hook still finds a URL and a
/// topic, no output says the hook writes to the journal: the walk's alert row warns that the hook
/// still posts (on a collector too), --test-page says it sent nothing while the hook still posts,
/// and the verified line names the fix, a collector's included.
#[test]
fn no_output_says_the_hook_writes_to_the_journal_while_it_still_posts() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    fx.env_line("PROPOLIS_OPS_NTFY_URL=ntfy.example.invalid");
    let walk = fx.walk();
    let row = walk.row("alert");
    assert!(
        row.contains("the shell senders ignore PROPOLIS_OPS_NTFY_URL as invalid; today's failure hook still posts to it (see sudo propolis-status --setup)"),
        "{row}"
    );
    assert!(row.contains(" ntfy "), "{row}");
    assert_eq!(walk.state("alert"), "WARN", "{row}");
    assert!(
        walk.out.contains("ALERTS  target none for the shell senders; today's failure hook still posts (invalid value ignored: PROPOLIS_OPS_NTFY_URL) - gate "),
        "{}",
        walk.out
    );
    let page = fx.run(&["--test-page"]);
    assert_eq!(page.code, 1, "{}", page.out);
    assert_eq!(
        page.out,
        "no target the shell senders accept: nothing sent; today's failure hook still posts to the setting they ignore (see sudo propolis-status --setup)\n"
    );
    assert!(!fx.log().contains("systemctl start"), "{}", fx.log());
    for out in [&walk.out, &page.out] {
        for absent in ["writes its alerts to the journal", "writes to the journal"] {
            assert!(!out.contains(absent), "{absent} in:\n{out}");
        }
    }
    assert!(
        fx.setup_verified().ends_with(". Set PROPOLIS_OPS_NTFY_URL in /etc/propolis/propolis.env to an http:// or https:// URL with a host and no blanks, written plainly on one line"),
        "{}",
        fx.setup_verified()
    );

    let fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_NTFY_URL=ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC={TOPIC}\n"),
    );
    let walk = fx.walk();
    let row = walk.row("alert");
    assert_eq!(walk.state("alert"), "WARN", "{row}");
    assert!(!row.contains("collector default"), "{row}");
    assert!(
        row.contains("today's failure hook still posts to it"),
        "{row}"
    );
    let line = fx.setup_verified();
    assert!(!line.contains("No push target is expected"), "{line}");
    assert!(
        line.contains("Set PROPOLIS_OPS_NTFY_URL in /etc/propolis/propolis.env"),
        "{line}"
    );
}

/// An indented empty line meant to switch pushing off empties the URL for the shell senders,
/// with nothing invalid, while today's failure hook, which never sees an indented line, still
/// reads the earlier one and posts. --setup says the hook still posts, names the setting it reads
/// otherwise with its fix, and never says that the hook writes to the journal or that nothing is
/// pushed.
#[test]
fn an_indented_empty_line_the_hook_never_sees_is_reported_as_the_hook_still_posting() {
    let fx = Fx::single();
    fx.env_line("  PROPOLIS_OPS_NTFY_URL=");
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    for want in [
        "target      none for the shell senders, which read PROPOLIS_OPS_NTFY_URL otherwise; today's failure hook still posts to it (URL https://ntfy.example.invalid), with the host and unit names, its journal lines and the token\n",
        "            today's failure hook reads PROPOLIS_OPS_NTFY_URL otherwise: write each push setting as KEY=value at the start of its line, with no blank or comment\n",
        "gate        none:notarget  - the shell senders push nothing; today's failure hook still posts (see target)\n",
    ] {
        assert!(r.out.contains(want), "{want} not in:\n{}", r.out);
    }
    for absent in [
        "writes its alerts to the journal",
        "nothing is pushed",
        TOPIC,
        TOKEN_SECRET,
    ] {
        assert!(!r.out.contains(absent), "{absent} in:\n{}", r.out);
    }
}

/// The gate governs only the test page (and the shell messages of a later release); today's
/// failure hook is not gated. Over plain http, whatever the server answers, --setup says what
/// today's failure alerts carry and that the gate does not apply to them, and nothing says
/// without qualification that pushes carry no detail. Behind a fresh refusal over https that line
/// is not printed.
#[test]
fn setup_says_the_gate_does_not_apply_to_todays_failure_alerts() {
    let fx = Fx::single();
    fx.env_drop("PROPOLIS_OPS_NTFY_URL=");
    fx.env_line("PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid");
    let r = fx.run(&["--setup"]);
    assert!(r.out.contains("-> refused"), "{}", r.out);
    assert!(
        r.out.contains("failures    the gate does not apply to today's failure alerts: each carries this host's name, the failed unit and its last journal lines; over plain http they travel in clear, the token too\n"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("gate        pointer:insecure  - the test page (and the shell messages of a later release) carries no detail: over plain http a refusal proves nothing\n"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("pushes carry no detail"), "{}", r.out);

    let mut fx = Fx::single();
    fx.setenv("RC_JSON", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains("failures    the gate does not apply to today's failure alerts: each carries this host's name, the failed unit and its last journal lines; the topic is not proven to refuse anonymous reads\n"),
        "{}",
        r.out
    );
    let fx = Fx::single();
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains("gate        full - the shell messages of a later release may carry detail: the topic refuses anonymous reads (the test page carries only the alias and the code in every mode)\n"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("failures    "), "{}", r.out);
}

/// The next step on --setup's verified line follows from the word and the last result. After a
/// page that went out it is to type its code back: another page would replace the code on the
/// phone and spend one of the day's three. A page the server refused names the result and what to
/// check. Without a target it names the settings to set, and on a collector, where none is
/// expected, it says so. Only no page, an expired or a changed one is told to send a test page.
#[test]
fn the_verified_line_gives_the_next_step_the_state_calls_for() {
    let mut fx = Fx::single();
    fx.with_hook();
    assert!(
        fx.setup_verified()
            .ends_with(". Run: sudo propolis-status --test-page"),
        "{}",
        fx.setup_verified()
    );
    assert_eq!(fx.run(&["--test-page"]).code, 0);
    let line = fx.setup_verified();
    assert!(
        line.ends_with(
            ". Type back the code from the page: sudo propolis-status --ack-test <code>"
        ),
        "{line}"
    );
    assert!(!line.contains("--test-page"), "{line}");
    let tp = fx.testpage();
    // A code past the day --ack-test takes it for can only be replaced.
    fx.write(
        "var/lib/propolis/witness/testpage",
        &format!(
            "#testpage v1 g=9\nT\t{}\t{}\t{}\t{}\tok\t-\t-\n",
            tp[1],
            stamp_ago(86_460),
            tp[3],
            tp[4]
        ),
    );
    let line = fx.setup_verified();
    assert!(
        line.ends_with(
            ". The last test page's code has expired (over a day old). Run: sudo propolis-status --test-page"
        ),
        "{line}"
    );
    fx.write(
        "var/lib/propolis/witness/testpage",
        &format!(
            "#testpage v1 g=9\nT\t{}\t{}\t{}\t{}\tperm:403\t-\t-\n",
            tp[1], tp[2], tp[3], tp[4]
        ),
    );
    let line = fx.setup_verified();
    assert!(
        line.contains(". The last test page was refused (perm:403): check the token and that it may write to the topic"),
        "{line}"
    );
    assert!(
        !line.contains("Run: sudo propolis-status --test-page"),
        "{line}"
    );
    fx.env_drop("PROPOLIS_OPS_NTFY_");
    let line = fx.setup_verified();
    assert!(
        line.ends_with(
            ". Set PROPOLIS_OPS_NTFY_URL and PROPOLIS_OPS_NTFY_TOPIC in /etc/propolis/propolis.env"
        ),
        "{line}"
    );
    assert!(!line.contains("--test-page"), "{line}");
    let fx = Fx::collector();
    let line = fx.setup_verified();
    assert!(
        line.ends_with(". No push target is expected on a collector"),
        "{line}"
    );
    assert!(!line.contains("--test-page"), "{line}");
}

/// The page is claimed before it goes out. A page that went out but whose result the hook could
/// not write (another writer held the state lock past its second wait) is reported as sent with
/// its result not recorded, never as a unit that did not run, and its code can still be typed
/// back.
#[test]
fn a_page_whose_result_could_not_be_recorded_is_reported_as_sent() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.write("var/lib/propolis/witness/state.lock", "");
    let lock = fx.p("var/lib/propolis/witness/state.lock");
    fx.setenv("POST_HOLD_LOCK", lock.to_str().unwrap());
    let r = fx.run(&["--test-page"]);
    fx.release_holder();
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    let tp = fx.testpage();
    let code = &tp[1];
    assert!(
        r.out.starts_with(&format!(
            "sent test page {code}; the result could not be recorded (see: journalctl -u propolis-alert@propolis-test-page-{code}.service)"
        )),
        "{}",
        r.out
    );
    assert!(!r.out.contains("did not run"), "{}", r.out);
    assert_eq!(tp[5], "sending", "{tp:?}");
    assert_eq!(fx.posts().len(), 1);
    fx.env.retain(|(k, _)| k != "POST_HOLD_LOCK");
    let r = fx.run(&["--ack-test", code]);
    assert_eq!(r.code, 0, "{}\n{}", r.out, r.err);
}

/// A code replaced by another test page before the hook ran is never sent, and the command says
/// it was replaced (here the replacement is made by the start itself, so the case does not depend
/// on two runs overlapping).
#[test]
fn a_code_replaced_before_its_hook_ran_is_reported_and_never_sent() {
    let mut fx = Fx::single();
    fx.with_hook();
    fx.setenv("START_REPLACE", "1");
    let r = fx.run(&["--test-page"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert!(r.out.contains("replaced"), "{}", r.out);
    assert!(fx.posts().is_empty(), "{:?}", fx.posts());
}

/// A page whose sent stamp is ahead of now on this boot cannot be acknowledged.
#[test]
fn a_page_dated_after_now_cannot_be_acknowledged() {
    let fx = Fx::single();
    fx.write(
        "var/lib/propolis/witness/testpage",
        &format!(
            "#testpage v1 g=1\nT\tabc123\t{}/abcdef01/{}\t0123456789abcdef\t-\tok\t-\t-\n",
            NOW + 600,
            900_600
        ),
    );
    let before = std::fs::read(fx.p("var/lib/propolis/witness/testpage")).unwrap();
    let r = fx.run(&["--ack-test", "abc123"]);
    assert_eq!((r.code, r.out.as_str()), (1, "wrong or expired code\n"));
    assert_eq!(
        std::fs::read(fx.p("var/lib/propolis/witness/testpage")).unwrap(),
        before
    );
}

/// --setup never reports a full gate from a stored refusal that the answer just given (readable)
/// could not replace because neither state directory took the write: the gate is that answer's,
/// and the exit status follows it.
#[test]
fn setup_never_reports_a_full_gate_from_a_refusal_the_new_answer_could_not_replace() {
    let mut fx = Fx::single();
    fx.refuse_writes_of("readcheck");
    fx.setenv("RC_JSON", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert!(
        r.out.contains("the answer could not be stored"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("gate        full"), "{}", r.out);
    assert!(r.out.contains("gate        pointer:readable"), "{}", r.out);
}

/// --setup says what the token can read (noread, unknown when its read got no answer, none
/// without a token); without curl it says neither check was made and that today's failure hook
/// needs curl too, never that there is no token.
#[test]
fn setup_names_what_the_token_reads_and_says_when_nothing_was_checked() {
    let mut fx = Fx::single();
    for (answer, want) in [
        (
            "403|text/plain",
            "token       noread (this token cannot read the topic)\n",
        ),
        (
            "000|",
            "token       unknown (its read got no answer that says)\n",
        ),
    ] {
        fx.setenv("RC_TOKEN_ANSWER", answer);
        let r = fx.run(&["--setup"]);
        assert!(r.out.contains(want), "{want} not in:\n{}", r.out);
    }
    fx.env_drop("PROPOLIS_OPS_NTFY_TOKEN=");
    let r = fx.run(&["--setup"]);
    assert!(r.out.contains("token       none\n"), "{}", r.out);
    fx.env_line(&format!("PROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}"));
    fx.without_curl();
    let r = fx.run(&["--setup"]);
    for want in [
        "anon read   not checked: curl or a private temporary file was not to be had\n",
        "token       not checked\n",
        "            install curl: today's failure hook cannot push without it either\n",
    ] {
        assert!(r.out.contains(want), "{want} not in:\n{}", r.out);
    }
    assert!(!r.out.contains("token       none"), "{}", r.out);
}

/// --setup's heartbeat line: the recommendation when it is unset, `set` for an https URL in
/// alert.env, refused for plain http; the URL itself is never printed.
#[test]
fn setup_states_the_heartbeat_url_without_showing_it() {
    let fx = Fx::single();
    let heartbeat = |fx: &Fx| -> String {
        let r = fx.run(&["--setup"]);
        for hidden in ["hc.example.invalid", "s3cret-ping"] {
            assert!(!r.out.contains(hidden), "{hidden} in:\n{}", r.out);
        }
        r.out
            .lines()
            .find(|l| l.starts_with("heartbeat   "))
            .unwrap_or_else(|| panic!("{}", r.out))
            .to_string()
    };
    assert!(
        heartbeat(&fx)
            .starts_with("heartbeat   not set. Recommended: a private dead-man check URL"),
        "{}",
        heartbeat(&fx)
    );
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=https://hc.example.invalid/s3cret-ping\n",
    );
    assert_eq!(heartbeat(&fx), "heartbeat   set (the URL is not shown)");
    fx.write(
        "etc/propolis/alert.env",
        "PROPOLIS_WITNESS_HEARTBEAT_URL=http://hc.example.invalid/s3cret-ping\n",
    );
    assert_eq!(
        heartbeat(&fx),
        "heartbeat   refused (not an https URL): PROPOLIS_WITNESS_HEARTBEAT_URL is ignored"
    );
}

/// On a collector whose topic the check answers as readable, --setup says what today's failure
/// hook reveals there, and nothing of a daemon.
#[test]
fn setup_on_a_collector_with_a_readable_topic_names_what_todays_hook_reveals() {
    let mut fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC={TOPIC}\n"
        ),
    );
    fx.setenv("RC_JSON", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains("daemon      today's failure hook posts to this topic; its titles name the host and the unit that failed\n"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("the daemon and today's"), "{}", r.out);
}

/// The daemon line and the alert rail name today's failure hook only where the hook's own reader
/// finds the same URL and topic. With the topic only on an indented line the library and systemd
/// read it but the hook posts nothing, so the daemon is named alone; on a collector, where no
/// daemon runs either, nothing is said of the topic.
#[test]
fn the_daemon_line_names_the_failure_hook_only_where_the_hook_reads_the_same_topic() {
    let mut fx = Fx::single();
    fx.env_drop("PROPOLIS_OPS_NTFY_TOPIC=");
    fx.env_line(&format!("  PROPOLIS_OPS_NTFY_TOPIC={TOPIC}"));
    fx.setenv("RC_JSON", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out
            .contains("today's failure hook reads PROPOLIS_OPS_NTFY_TOPIC otherwise"),
        "{}",
        r.out
    );
    let daemon: Vec<&str> = r
        .out
        .lines()
        .filter(|l| l.starts_with("daemon      "))
        .collect();
    assert_eq!(
        daemon,
        [
            "daemon      the daemon posts to this topic; its titles name this host's software (until step 3)"
        ],
        "{}",
        r.out
    );
    let w = fx.walk();
    let row = w.row("alert");
    assert!(
        row.contains("daemon titles name this host's software"),
        "{row}"
    );
    assert!(!row.contains("legacy hook carries"), "{row}");

    let mut fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\n  PROPOLIS_OPS_NTFY_TOPIC={TOPIC}\n"
        ),
    );
    fx.setenv("RC_JSON", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert!(
        !r.out.lines().any(|l| l.starts_with("daemon      ")),
        "{}",
        r.out
    );
    assert!(!fx.walk().row("alert").contains("legacy hook carries"));

    // A collector whose hook reads the same topic: the hook is named, and no daemon is.
    let mut fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC={TOPIC}\n"
        ),
    );
    fx.setenv("RC_JSON", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains(
            "daemon      today's failure hook posts to this topic; its titles name the host and the unit that failed"
        ),
        "{}",
        r.out
    );
    let w = fx.walk();
    let row = w.row("alert");
    assert!(
        row.contains("legacy hook carries host and unit names"),
        "{row}"
    );
    assert!(!row.contains("daemon titles"), "{row}");
}

/// The banner of a collector with a target says VERIFIED or NOT VERIFIED without `daemon not
/// verified`, both when its token can read the topic and when the gate is full: no daemon runs
/// there.
#[test]
fn the_banner_on_a_collector_never_says_daemon_not_verified() {
    let fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!(
            "PROPOLIS_OPS_NTFY_URL=https://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC={TOPIC}\n"
        ),
    );
    // The fixture's stored check holds a token that reads: pointer:token-reads on a collector.
    assert_eq!(banner_alerts(&fx), "NOT VERIFIED (never)");
    let s = stamp_ago(600);
    fx.write(
        "var/lib/propolis/witness/readcheck",
        &format!(
            "#readcheck v1 g=3\nR\t8f24b729c8ebd3c1\t{s}\trefused\t{s}\trefused\t-\t403\t403\tboth\t403\n"
        ),
    );
    assert_eq!(banner_alerts(&fx), "NOT VERIFIED (never)");
    assert!(
        fx.run(&["--setup"]).out.contains("gate        full"),
        "the second case is the full gate"
    );
}

/// Over plain http a refusal proves nothing, whoever the token lets read. A collector whose URL
/// is http:// and whose token can read the topic has the gate word of the token, and the banner
/// still says the topic is not proven private, never a word about a test page.
#[test]
fn the_banner_over_plain_http_says_so_even_where_the_token_reads() {
    let mut fx = Fx::collector();
    fx.write(
        "etc/propolis/propolis.env",
        &format!("PROPOLIS_OPS_NTFY_URL=http://ntfy.example.invalid\nPROPOLIS_OPS_NTFY_TOPIC={TOPIC}\nPROPOLIS_OPS_NTFY_TOKEN={TOKEN_SECRET}\n"),
    );
    fx.setenv("RC_TOKEN_ANSWER", "200|application/x-ndjson");
    let r = fx.run(&["--setup"]);
    assert!(
        r.out.contains("gate        pointer:token-reads"),
        "{}",
        r.out
    );
    assert_eq!(banner_alerts(&fx), "topic not proven private (plain http)");
}

/// The acknowledging account is SUDO_UID only when that is a number: `1000x`, or no SUDO_UID at
/// all, records root (0).
#[test]
fn an_ack_without_a_numeric_sudo_uid_is_recorded_as_root() {
    for uid in [Some("1000x"), None] {
        let mut fx = Fx::single();
        fx.with_hook();
        if let Some(uid) = uid {
            fx.setenv("SUDO_UID", uid);
        }
        page_and_ack(&fx);
        assert_eq!(fx.testpage()[7], "0", "{uid:?}");
    }
}

/// A test page that cannot be named (the id salt cannot be written) or counted (the send ledger
/// cannot be read) is refused with its own message, before any unit is started.
#[test]
fn a_test_page_that_cannot_be_named_or_counted_starts_no_unit() {
    let mut fx = Fx::single();
    fx.with_hook();
    std::fs::remove_file(fx.p("var/lib/propolis/witness/id-salt")).unwrap();
    fx.refuse_writes_of("id-salt");
    let r = fx.run(&["--test-page"]);
    assert_eq!(
        (r.code, r.out.as_str()),
        (
            1,
            "test page not sent: the id salt could not be written in /var/lib/propolis/witness\n"
        ),
        "{}",
        r.err
    );
    assert!(!fx.log().contains("systemctl start"), "{}", fx.log());

    let mut fx = Fx::single();
    fx.with_hook();
    fx.write("var/lib/propolis/witness/send-ledger", "garbage\n");
    let r = fx.run(&["--test-page"]);
    assert_eq!(
        (r.code, r.out.as_str()),
        (
            1,
            "test page not sent: the send ledger cannot be read, so the budget cannot be counted\n"
        ),
        "{}",
        r.err
    );
    assert!(!fx.log().contains("systemctl start"), "{}", fx.log());
}

/// The alert view shows the VERIFIED field, the recorded test page (when it was asked for, its
/// result, when it was typed back) and the ledger, and never the code.
#[test]
fn the_alert_view_shows_the_test_page_and_the_ledger_but_never_the_code() {
    let mut fx = Fx::single();
    fx.with_hook();
    let before = fx.run(&["alert"]).out;
    assert_eq!(fx.run(&["--test-page"]).code, 0);
    let code = fx.testpage()[1].clone();
    let r = fx.run(&["alert"]);
    for want in [
        "    NOT VERIFIED (pending); daemon not verified\n",
        "    test page: asked 08:00:00, result ok, typed back -\n",
        "    ledger 08:00:00 class test key - open full ok by hook\n",
    ] {
        assert!(r.out.contains(want), "{want} not in:\n{}", r.out);
    }
    if !before.contains(&code) {
        assert!(!r.out.contains(&code), "the code {code} in:\n{}", r.out);
    }
}

/// When propolis.env changed after the running daemon started, the walk says the daemon loaded
/// an older configuration, which may hold an older topic or token until a restart; an older file
/// says nothing.
#[test]
fn the_walk_says_when_the_daemon_runs_an_older_configuration() {
    let fx = Fx::single();
    let env = fx.p("etc/propolis/propolis.env");
    let line = "the daemon loaded an older configuration: restart propolis to apply it";
    // The daemon entered active at 07:00, an hour before NOW.
    set_mtime(&env, NOW - 60);
    let r = fx.walk();
    assert!(r.out.contains(&format!("        {line}\n")), "{}", r.out);
    set_mtime(&env, NOW - 7200);
    let r = fx.walk();
    assert!(!r.out.contains(line), "{}", r.out);
}

/// A production run uses /tmp for its temporary files whatever TMPDIR the caller had: --setup is
/// run from an interactive root shell, and its curl config file holds the topic.
#[test]
fn the_production_branch_resets_tmpdir() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let start = script
        .find("\nif [ -z \"$STATUS_ROOT\" ]; then\n")
        .expect("no production branch");
    let block = &script[start..];
    let block = &block[..block.find("\nfi\n").unwrap()];
    assert!(
        block
            .lines()
            .any(|l| l.trim() == "unset TMPDIR" || l.trim() == "export TMPDIR=/tmp"),
        "TMPDIR is not reset in the production branch:\n{block}"
    );
}
