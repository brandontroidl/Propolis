#!/usr/bin/env bash
#
# Read-only deployment configuration check: compares what is CONFIGURED with what is RUNNING, one
# row per sensor listener, plus the host-wide pieces a listener depends on, and prints the next step
# for everything that is wrong: a `fix:` line is a command to paste as-is (non-root, with sudo
# where root is needed; explanation is in the finding text above it), a `do:` line is a manual
# step (edit a file, install a firewall) that is not a command and must not be pasted.
#
# WHY THIS EXISTS. Five faults on the production box (2026-10-07) were each found by accident: a
# typo in PROPOLIS_SENSOR_LOGS, MQTT's log absent from that list, sensor-cred's PostgreSQL listener
# never producing a log (the host's own PostgreSQL held port 5432 while the firewall exposed it),
# logrotate.timer silently dead, and an upgrade whose first run installed no new binary. Every one
# was a disagreement between two things that were each individually plausible. This compares them.
#
# WHAT IT CHECKS, per listener (derived by listeners-lib.sh, the same derivation the fleet
# inventory uses): the sensor unit is installed, enabled and active; the configured port is bound
# and by whom ("held by another process" is reported apart from "nothing listening"); whether the
# active host firewall (ufw, firewalld, nftables) allows the port, with the DANGEROUS case flagged
# where a firewall-open port is held by something that is not the sensor; the sensor's log file
# (age, size against the logrotate size); the log's entry in PROPOLIS_SENSOR_LOGS, parsed by the
# daemon's own rules (crates/log-tailer/src/sensor_logs.rs); and, when a database URL is readable,
# the newest event the ledger holds for the sensor. Host-wide: the log rotation timer and its state
# file, the binaries upgrade.sh installs against the deploy stamp, the watcher's env file, enabled
# sensor units with no bind configured, unreadable env files, an env file whose mode lets
# another account read it, and a setting written in a form systemd and the shell scripts read
# differently (env-systemd-only); whether the daemon's database role can do more to the event
# ledger than append to it; on a control plane with a gateway spool, each collector's spool
# against PROPOLIS_SENSOR_LOGS (one the gateway acknowledges and the daemon never reads); and
# whether the root witness and its library are installed and both its timers enabled; and the
# alert channel: push settings the shell senders ignore as invalid, and whether the stored
# anonymous-read check (made by the witness or `propolis-status --setup`, never by this script)
# found the topic readable by anyone, or got another answer that is not a refusal and so leaves
# it not proven private.
#
# BY ROLE. A collector and a gateway-only host (the alert library's pa_role) with no
# propolis.service enabled or running and a propolis.env that configures no daemon (names no
# DATABASE_URL and no PROPOLIS_SENSOR_LOGS) run no daemon, so what only exists beside the daemon
# is not checked there: the daemon's alert monitor and heartbeat, the backup of its database and
# the live watch of its intake list, which config-check checks on the host that runs
# propolis.service; and the binaries no unit on the host runs and, on a collector, the deploy
# stamp, which its hand upgrade never writes, which no host checks for this one. Those rows read
# skip and the report names both lists in one line. The failure hook stays checked, with the push
# target it reads from this host's propolis.env. Every other role, and any answer that is not
# certain, runs every check.
#
# NEVER MUTATES. It writes nothing outside a private temp directory it removes, restarts nothing,
# and changes no firewall rule. Every external tool is optional: a missing one makes its check
# "unknown" and is named under LIMITED CHECKS, never a crash. It does not execute any installed
# binary (an old binary that predates --version would START its service).
#
# WITHOUT ROOT it still runs, with these checks limited: sensor env files are 0600 and owned by
# root, so the listener inventory itself may be unreadable; `ss` cannot name a
# socket's owner; ufw and nft cannot list rules; /var/log/propolis/* is not traversable; the
# database URL is unreadable. A check that cannot be answered is reported as unknown ("?"), counts
# as a warning in the exit status, and is listed under LIMITED CHECKS: it is never a pass.
#
# WHERE IT RUNS. From the checkout (deploy/config-check.sh), and as the copy install.sh and
# upgrade.sh put in /usr/local/lib/propolis, which root can run from any directory and which a root
# timer can rely on. The copy is told apart by having no upgrade.sh beside it; it finds the
# checkout through repo-dir (one line, the checkout's absolute path) and the binary list through
# install-bins (upgrade.sh's INSTALL_BINS line), both written by the installer, and its fix lines
# name the checkout's scripts; a repo-dir that is missing, or names a path with no checkout in it,
# turns those fixes into manual steps under a limit line. Neither copy runs git: the checkout's
# HEAD is read from the files under .git as the checkout's owner, because a checkout's git config
# can name commands git would run as root. Files another account can write are read as that
# account through the alert library's pa_read_as, with a size cap and a timeout: the daemon's
# cursors as propolis, and, in the installed copy only, the build output as the checkout's owner.
# The checkout copy compares the build with cmp as whoever runs it, upgrade.sh's root run included.
#
# THE ALERT LIBRARY. Env values are read through its pa_env_get (systemd's reading of an
# EnvironmentFile=) and the intake list through its pa_sensor_logs, so the witness and the failure
# hook, which use the same library, parse both as this check does. Looked
# up in this order: PROPOLIS_CC_ALERT_LIB when set (tests), alert-lib.sh beside this script (the
# checkout), /usr/local/sbin/propolis-alert-lib (installed). Missing, unreadable, failing to load,
# or older than the version below, the run stops with exit 70 before it reads anything.
#
# Usage: config-check.sh [--json | --tsv] [--report-only] [--no-events] [--env-dir DIR] [--newest-event SENSOR]
#   --json         one JSON document on stdout instead of the table
#   --tsv          tab-separated records on stdout instead of the table, for scripts without a
#                  JSON parser: `#config-check tsv v1`, then S (status), G (host rows), R
#                  (listener rows), F (findings, each followed by its X fix line when it has one),
#                  L (limited checks) and E (the number of F lines), every field ASCII with no tab
#   --report-only  print the report but always exit 0 (upgrade.sh uses this)
#   --no-events    skip the ledger query
#   --newest-event SENSOR  print when the ledger last saw SENSOR (any age) and exit; the events
#                  findings' fix line, so the database URL never reaches a command line
#   --env-dir DIR  directory holding the env files   (default /etc/propolis)
# Exit status: 0 all ok, 1 warnings or unknown checks, 2 at least one failure, 64 bad usage, 70 the
# alert library is missing or too old (whatever --report-only says, since no check ran).
#
# Test seams (all default to the production path; set only by tests): PROPOLIS_CC_NOW (epoch),
# PROPOLIS_CC_EUID, PROPOLIS_CC_BIN_DIR, PROPOLIS_CC_REPO_DIR, PROPOLIS_CC_BUILD_DIR,
# PROPOLIS_CC_STAMP, PROPOLIS_CC_LOGROTATE_STATE, PROPOLIS_CC_LOGROTATE_POLICY,
# PROPOLIS_CC_LOGROTATE_GUARD, PROPOLIS_CC_WATCH_HOME, PROPOLIS_CC_WATCH_ACCOUNT,
# PROPOLIS_CC_BACKUP_DIR, PROPOLIS_CC_GATEWAY_SPOOL_DIR (the spool directory when gateway.env sets
# none), PROPOLIS_CC_ALERT_LIB (the only library looked at when set), PROPOLIS_CC_ALERT_ROOT (the
# root the library's paths sit under), PROPOLIS_CC_WITNESS (the installed witness program).
# PROPOLIS_CC_LOG_STALE_HOURS (default 24)
# is the age past which a log on a running sensor is reported as quiet.
#
# The output is plain ASCII: every value read from an env file is passed through `clean` first, so
# a hostile or corrupt file cannot inject terminal escapes or break the JSON.
#
# The library version this script needs; deploy/rollback.sh reads the line below.
# needs-alert-lib: 9

set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR=/etc/propolis
JSON=0
TSV=0
REPORT_ONLY=0
NO_EVENTS=0
NEWEST_EVENT=""

usage() {
    echo "usage: $0 [--json | --tsv] [--report-only] [--no-events] [--env-dir DIR] [--newest-event SENSOR]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --json) JSON=1 ;;
        --tsv) TSV=1 ;;
        --report-only) REPORT_ONLY=1 ;;
        --no-events) NO_EVENTS=1 ;;
        --newest-event)
            if [ "$#" -lt 2 ]; then
                usage
                exit 64
            fi
            case "$2" in
                '' | *[!a-z0-9_-]*)
                    echo "error: --newest-event takes a sensor name (a-z, 0-9, _ and -)" >&2
                    exit 64
                    ;;
            esac
            NEWEST_EVENT="$2"
            shift
            ;;
        --env-dir)
            if [ "$#" -lt 2 ]; then
                usage
                exit 64
            fi
            ENV_DIR="$2"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage
            exit 64
            ;;
    esac
    shift
done
if [ "$JSON" -eq 1 ] && [ "$TSV" -eq 1 ]; then
    echo "error: --json and --tsv are two output formats; give one" >&2
    usage
    exit 64
fi

# ---- the alert library ---------------------------------------------------------------------

CC_NEEDS_LIB=0
while IFS= read -r cc_line; do
    case "$cc_line" in
        '# needs-alert-lib: '*)
            CC_NEEDS_LIB="${cc_line#'# needs-alert-lib: '}"
            break
            ;;
    esac
done <"${BASH_SOURCE[0]}"
unset cc_line
if [ -n "${PROPOLIS_CC_ALERT_LIB:-}" ]; then
    CC_ALERT_LIB="$PROPOLIS_CC_ALERT_LIB"
elif [ -f "$SCRIPT_DIR/alert-lib.sh" ]; then
    CC_ALERT_LIB="$SCRIPT_DIR/alert-lib.sh"
else
    CC_ALERT_LIB=/usr/local/sbin/propolis-alert-lib
fi
cc_no_library() {
    echo "error: alert library not found (or too old) beside config-check.sh or at /usr/local/sbin/propolis-alert-lib" >&2
    exit 70
}
if [ ! -f "$CC_ALERT_LIB" ] || [ ! -r "$CC_ALERT_LIB" ]; then
    cc_no_library
fi
# Whatever an older or foreign file leaves behind must not read as a version or a function.
PA_LIB_VERSION=""
unset -f pa_init pa_env_get pa_read_as pa_sensor_logs pa_cleanup
# Loaded once in a subshell first: under set -u an unbound variable at the library's top level
# ends the shell that sources it, and an exit there ends it with the library's status, so either
# would end this run with no word instead of the exit 70 promised for an unusable library.
# shellcheck source=deploy/alert-lib.sh
if [ "$(set +e; . "$CC_ALERT_LIB" >/dev/null 2>&1 && echo loaded)" != loaded ]; then
    cc_no_library
fi
set +u
# shellcheck source=deploy/alert-lib.sh
if ! . "$CC_ALERT_LIB" 2>/dev/null; then
    cc_no_library
fi
set -u
if ! [[ "$PA_LIB_VERSION" =~ ^[0-9]{1,9}$ && "$CC_NEEDS_LIB" =~ ^[0-9]{1,9}$ ]] \
    || [ "$((10#$PA_LIB_VERSION))" -lt "$((10#$CC_NEEDS_LIB))" ] \
    || ! declare -F pa_init pa_env_get pa_read_as pa_sensor_logs pa_cleanup >/dev/null; then
    cc_no_library
fi
# pa_init sets umask 077, which only narrows the files this script makes in its own temp directory.
pa_init "${PROPOLIS_CC_ALERT_ROOT:-}"
PA_ENV_DIR="$ENV_DIR"

# ---- the checkout, from the checkout or from the installed copy ----------------------------

# Installed: no upgrade.sh beside this script. The copy in /usr/local/lib/propolis has none, and
# deploy/ always has it.
CC_INSTALLED=0
if [ ! -f "$SCRIPT_DIR/upgrade.sh" ]; then
    CC_INSTALLED=1
fi

# cc_repo_dir_from FILE: the checkout path FILE holds, when it is one line naming an absolute path
# with no control character; nothing otherwise.
cc_repo_dir_from() {
    local text="" re='^/[^[:cntrl:]]{1,4095}$'
    if [ -f "$1" ] && [ ! -L "$1" ]; then
        IFS= read -r -d '' text <"$1" 2>/dev/null || true
        text="${text%$'\n'}"
        if [[ "$text" =~ $re ]]; then
            printf '%s' "$text"
        fi
    fi
    return 0
}

CC_REPO_UNKNOWN=0
# The path repo-dir names when no checkout is there (moved, deleted, or hidden from a sandbox):
# fix lines naming its scripts would name files that do not exist, so it counts as unknown too.
CC_REPO_GONE=""
if [ -n "${PROPOLIS_CC_REPO_DIR:-}" ]; then
    REPO_DIR="$PROPOLIS_CC_REPO_DIR"
elif [ "$CC_INSTALLED" -eq 1 ]; then
    REPO_DIR="$(cc_repo_dir_from "$SCRIPT_DIR/repo-dir")"
    if [ -z "$REPO_DIR" ]; then
        CC_REPO_UNKNOWN=1
    elif [ ! -f "$REPO_DIR/deploy/upgrade.sh" ]; then
        CC_REPO_GONE="$REPO_DIR"
        REPO_DIR=""
    fi
else
    REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

# Where the fix lines find the checkout's scripts: beside this one in the checkout, the checkout's
# deploy/ for the installed copy, and nowhere when the installed copy does not know the checkout
# (those fixes are then written as manual steps).
if [ "$CC_INSTALLED" -eq 0 ]; then
    FIX_DIR="$SCRIPT_DIR"
elif [ -n "$REPO_DIR" ]; then
    FIX_DIR="$REPO_DIR/deploy"
else
    FIX_DIR=""
fi
if [ "$CC_INSTALLED" -eq 1 ]; then
    INSTALL_BINS_SRC="$SCRIPT_DIR/install-bins"
else
    INSTALL_BINS_SRC="$SCRIPT_DIR/upgrade.sh"
fi

# shellcheck source=deploy/listeners-lib.sh
. "$SCRIPT_DIR/listeners-lib.sh"

BIN_DIR="${PROPOLIS_CC_BIN_DIR:-/usr/local/bin}"
if [ -n "${PROPOLIS_CC_BUILD_DIR:-}" ]; then
    BUILD_DIR="$PROPOLIS_CC_BUILD_DIR"
elif [ -n "$REPO_DIR" ]; then
    BUILD_DIR="$REPO_DIR/target/release"
else
    BUILD_DIR=""
fi
STAMP_FILE="${PROPOLIS_CC_STAMP:-/var/lib/propolis/deploy-stamp.json}"
ROTATE_STATE="${PROPOLIS_CC_LOGROTATE_STATE:-/var/lib/propolis/logrotate.state}"
ROTATE_POLICY="${PROPOLIS_CC_LOGROTATE_POLICY:-/etc/logrotate.d/propolis-sensors}"
ROTATE_GUARD="${PROPOLIS_CC_LOGROTATE_GUARD:-/usr/local/sbin/propolis-logrotate-guard}"
WATCH_HOME="${PROPOLIS_CC_WATCH_HOME:-/var/lib/propolis-watch}"
WATCH_ACCOUNT="${PROPOLIS_CC_WATCH_ACCOUNT:-propolis-watch}"
BACKUP_STATUS="${PROPOLIS_CC_BACKUP_STATUS:-/var/lib/propolis/backup-status}"
ALERT_HOOK="${PROPOLIS_CC_ALERT_HOOK:-/usr/local/sbin/propolis-alert}"
WITNESS_BIN="${PROPOLIS_CC_WITNESS:-/usr/local/sbin/propolis-witness}"
STALE_HOURS="${PROPOLIS_CC_LOG_STALE_HOURS:-24}"
case "$STALE_HOURS" in '' | *[!0-9]*) STALE_HOURS=24 ;; esac
NOW="${PROPOLIS_CC_NOW:-$(date +%s)}"
EFFECTIVE_UID="${PROPOLIS_CC_EUID:-$(id -u)}"
IS_ROOT=0
if [ "$EFFECTIVE_UID" -eq 0 ]; then
    IS_ROOT=1
fi

# State-file staleness the daemon's rotation-stale alert uses
# (crates/propolis/src/ops_alert/conditions/sensor_log.rs STATE_STALE_AFTER).
ROTATE_STALE_SECS=$((3 * 3600))
# The daemon's backup-stale default (PROPOLIS_OPS_BACKUP_MAX_AGE_SECS, crates/propolis/src/
# ops_alert/config.rs).
BACKUP_STALE_SECS=$((36 * 3600))
DEFAULT_ROTATE_SIZE=$((100 * 1024 * 1024))
# What deploy/backup.sh keeps free on the backup volume: the daemon's low-disk default (crates/
# propolis/src/ops_alert/config.rs) and logrotate-guard.sh's reserve. backup_script_test.rs fails
# when backup.sh's copies of these drift, and config_check_test.rs holds this script's to backup.sh's.
DEFAULT_LOW_DISK_PCT=15
LOGROTATE_RESERVE_BYTES=536870912

# low_disk_pct FILE: the monitor's low-disk threshold as the daemon will read it from FILE. systemd
# strips whitespace around the key, the '=' and the value and the last assignment wins; the daemon
# then runs trim().parse::<u64>() (crates/propolis/src/ops_alert/config.rs, get_u64), which accepts
# a leading '+' and leading zeros, and refuses to start outside 1..=100. A value that is not a whole
# number in that range is one the daemon refuses to start on, so no alert runs on it; this returns
# the default 15 for it, the figure to size against while the operator fixes the file. Only the
# forms in fixtures/low_disk_table.in are held to systemd's reading. Forms this does not model and
# systemd reads differently: backslash escapes and line continuations inside a value, a ';' or '#'
# comment after a quoted value, and a line that is itself continued from the one above. The same
# function is in backup.sh (backup_script_test.rs and config_check_test.rs hold the two to one table).
low_disk_pct() {
    local v re='^\+?[0-9]+$'
    v="$(sed -n 's/^[[:space:]]*PROPOLIS_OPS_CAPACITY_FREE_PCT[[:space:]]*=//p' "$1" 2>/dev/null | tail -n 1 || true)"
    v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
    if [[ "$v" =~ $re ]]; then
        v="${v#+}"
        # With the zeros gone a match starts at a non-zero digit (zero itself is left empty and
        # fails the pattern), so only the upper bound needs testing.
        v="${v#"${v%%[!0]*}"}"
        if [[ "$v" =~ ^[0-9]{1,3}$ ]] && [ "$v" -le 100 ]; then
            printf '%s' "$v"
            return 0
        fi
    fi
    printf '%s' "$DEFAULT_LOW_DISK_PCT"
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"; pa_cleanup' EXIT

# ---- small helpers -------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# ASCII-only copy of a value: anything outside space..~ becomes '?'.
clean() {
    local LC_ALL=C
    printf '%s' "${1//[^ -~]/?}"
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

human_bytes() {
    local b="$1" t
    if [ "$b" -ge 1073741824 ]; then
        t=$(((b * 10 + 536870912) / 1073741824))
        printf '%s%sG' $((t / 10)) "$([ $((t % 10)) -eq 0 ] || printf '.%s' $((t % 10)))"
    elif [ "$b" -ge 1048576 ]; then
        t=$(((b * 10 + 524288) / 1048576))
        if [ "$t" -ge 10240 ]; then
            # Just under 1 GiB rounds to 1024.0M; the next unit up reads better and is the same size.
            printf '1G'
        else
            printf '%s%sM' $((t / 10)) "$([ $((t % 10)) -eq 0 ] || printf '.%s' $((t % 10)))"
        fi
    elif [ "$b" -ge 1024 ]; then
        printf '%sK' $((b / 1024))
    else
        printf '%sB' "$b"
    fi
}

human_age() {
    local s="$1"
    if [ "$s" -lt 0 ]; then
        s=0
    fi
    if [ "$s" -ge 172800 ]; then
        printf '%sd' $((s / 86400))
    elif [ "$s" -ge 7200 ]; then
        printf '%sh' $((s / 3600))
    elif [ "$s" -ge 120 ]; then
        printf '%sm' $((s / 60))
    else
        printf '%ss' "$s"
    fi
}

# logrotate's `size` argument: an integer with an optional k, M or G suffix (powers of 1024),
# matching crates/propolis/src/ops_alert/conditions/sensor_log.rs parse_size. Prints nothing for
# anything else, including zero.
parse_size() {
    local arg="$1" digits mult=1
    case "$arg" in
        *[kK]) digits="${arg%?}"; mult=1024 ;;
        *[mM]) digits="${arg%?}"; mult=1048576 ;;
        *[gG]) digits="${arg%?}"; mult=1073741824 ;;
        *) digits="$arg" ;;
    esac
    case "$digits" in '' | *[!0-9]*) return 0 ;; esac
    if [ "$((10#$digits))" -gt 0 ]; then
        printf '%s' $((10#$digits * mult))
    fi
}

# ---- findings, limits, cells ---------------------------------------------------------------

F_LEVEL=()
F_SCOPE=()
F_MSG=()
F_FIX=()
F_KIND=()
F_ID=()
F_KEY=()
declare -A F_SEEN=()
LIMITED=()
declare -A L_SEEN=()
UNKNOWN_COUNT=0

# finding LEVEL SCOPE KEY MESSAGE [FIX [KIND]]: KEY de-duplicates (five sensor-cred rows share one
# unit, and one unit finding is enough). The part of KEY before its first ':' is the finding's id,
# unique per call site (the test suite enumerates the ids from this file and requires each to be
# exercised).
#
# FIX is printed as `fix:` when KIND is run (the default): it must be one or more complete shell
# commands, joined with && or ;, that work exactly as pasted by a non-root operator in bash, with
# sudo wherever root is needed and no prose or placeholders. Anything that is an instruction rather
# than a command (edit a file, install a firewall) is passed with KIND manual and printed as `do:`.
# Explanation always belongs in MESSAGE, never in a run line.
finding() {
    local level="$1" scope="$2" key="$3" msg="$4" fix="${5:-}" kind="${6:-run}"
    if [ -n "${F_SEEN["$key"]+x}" ]; then
        return 0
    fi
    F_SEEN["$key"]=1
    if [ -z "$fix" ]; then
        kind=""
    fi
    if [[ "$key" == danger:* ]]; then
        # An exposed non-sensor service is what the operator must read first.
        F_LEVEL=("$level" "${F_LEVEL[@]}")
        F_SCOPE=("$(clean "$scope")" "${F_SCOPE[@]}")
        F_MSG=("$(clean "$msg")" "${F_MSG[@]}")
        F_FIX=("$(clean "$fix")" "${F_FIX[@]}")
        F_KIND=("$kind" "${F_KIND[@]}")
        F_ID=("${key%%:*}" "${F_ID[@]}")
        F_KEY=("$key" "${F_KEY[@]}")
        return 0
    fi
    F_LEVEL+=("$level")
    F_SCOPE+=("$(clean "$scope")")
    F_MSG+=("$(clean "$msg")")
    F_FIX+=("$(clean "$fix")")
    F_KIND+=("$kind")
    F_ID+=("${key%%:*}")
    # The whole key, instance included, for the TSV's k12: two unit-down findings share an id.
    F_KEY+=("$key")
}

# q VALUE: VALUE shell-quoted for a run line (a path with a space, or a quote, still pastes whole).
q() { printf '%q' "$1"; }

# The fix lines that run one of the checkout's scripts name it by absolute path, so they work from
# any directory. An installed copy that does not know the checkout cannot name one, so those fixes
# become manual steps that say where to run the script from (fix_kind_checkout gives their kind).
CHECKOUT_TOP="from the top of the Propolis checkout run:"
fix_kind_checkout() { if [ -n "$FIX_DIR" ]; then printf run; else printf manual; fi; }
# checkout_fix SCRIPT: a whole fix line that runs SCRIPT as root.
checkout_fix() {
    if [ -n "$FIX_DIR" ]; then
        printf 'sudo %s' "$(q "$FIX_DIR/$1")"
    else
        printf '%s sudo ./deploy/%s' "$CHECKOUT_TOP" "$1"
    fi
}
# checkout_cmd SCRIPT: the same run, as part of a longer manual step.
checkout_cmd() {
    if [ -n "$FIX_DIR" ]; then
        printf 'sudo %s' "$(q "$FIX_DIR/$1")"
    else
        printf 'sudo ./deploy/%s from the top of the Propolis checkout' "$1"
    fi
}
# checkout_install MODE FILE DEST: the fix that installs the checkout's deploy/FILE as DEST.
checkout_install() {
    if [ -n "$FIX_DIR" ]; then
        printf 'sudo install -m %s %s %s' "$1" "$(q "$FIX_DIR/$2")" "$(q "$3")"
    else
        printf '%s sudo install -m %s ./deploy/%s %s' "$CHECKOUT_TOP" "$1" "$2" "$(q "$3")"
    fi
}

# The upgrade run.
upgrade_fix() { checkout_fix upgrade.sh; }

limit() {
    if [ -z "${L_SEEN["$1"]+x}" ]; then
        L_SEEN["$1"]=1
        LIMITED+=("$1")
    fi
}

ROW_COUNT=0
R_SENSOR=()
R_PROTO=()
R_ADDR=()
R_PORT=()
R_UNIT=()
declare -A CELL=()
COLUMNS=(unit listen firewall log intake events)

# setcell ROW COLUMN LEVEL TEXT
setcell() {
    CELL["$1:$2"]="$3|$(clean "$4")"
    if [ "$3" = unknown ]; then
        UNKNOWN_COUNT=$((UNKNOWN_COUNT + 1))
    fi
}
cell_level() { local v="${CELL["$1:$2"]:-skip|-}"; printf '%s' "${v%%|*}"; }
cell_text() { local v="${CELL["$1:$2"]:-skip|-}"; printf '%s' "${v#*|}"; }

G_ID=()
G_LEVEL=()
G_TEXT=()
# global ID LEVEL TEXT
global() {
    G_ID+=("$1")
    G_LEVEL+=("$2")
    G_TEXT+=("$(clean "$3")")
    if [ "$2" = unknown ]; then
        UNKNOWN_COUNT=$((UNKNOWN_COUNT + 1))
    fi
}

# ---- mapping from a sensor's reported name to its unit, binary, log and label --------------

unit_of() {
    case "$1" in
        vnc | mysql | mssql | postgresql | mongodb) printf 'sensor-cred' ;;
        *) printf 'sensor-%s' "$1" ;;
    esac
}

# The PROPOLIS_SENSOR_LOGS label deploy/propolis.env.example uses for each sensor.
label_of() {
    case "$1" in
        vnc) printf 'cred-vnc' ;;
        mysql) printf 'cred-mysql' ;;
        mssql) printf 'cred-mssql' ;;
        postgresql) printf 'cred-pg' ;;
        mongodb) printf 'cred-mongo' ;;
        *) printf '%s' "$1" ;;
    esac
}

# The path the sensor writes its log to: its *_LOG_PATH, else the compiled default. Prints nothing
# for sensor-catchall's compiled default, which is a relative path that the unit's sandbox makes
# unwritable (deploy/sensor.env.example), so there is no path to check.
log_path_of() {
    local sensor="$1" dir var value upper
    case "$sensor" in
        vnc | mysql | mssql | postgresql | mongodb)
            dir="$(read_env_var PROPOLIS_CRED_LOG_DIR)"
            printf '%s/%s.jsonl' "${dir:-/var/log/propolis/cred}" "$sensor"
            return 0
            ;;
    esac
    upper="${sensor^^}"
    var="PROPOLIS_${upper}_LOG_PATH"
    value="$(read_env_var "$var")"
    if [ -z "$value" ] && [ "$sensor" = catchall ]; then
        value="$(read_env_var CATCHALL_LOG_PATH)"
    fi
    if [ -n "$value" ]; then
        printf '%s' "$value"
    elif [ "$sensor" != catchall ]; then
        printf '/var/log/propolis/%s/events.jsonl' "$sensor"
    fi
}

# ---- environment: which env files exist and which can be read ------------------------------

ENV_FILES=("$ENV_DIR"/*.env)
UNREADABLE_ENV=()
for f in "${ENV_FILES[@]}"; do
    if [ ! -r "$f" ]; then
        UNREADABLE_ENV+=("$f")
    fi
done

if [ "${#UNREADABLE_ENV[@]}" -gt 0 ]; then
    limit "env files not readable as this user (${#UNREADABLE_ENV[@]} of ${#ENV_FILES[@]}): the listener inventory and every value in them is incomplete; run as root"
fi
if [ "$IS_ROOT" -eq 0 ]; then
    limit "not root: socket owners, ufw/nft rules, /var/log/propolis files and the database URL may be unreadable"
fi
if [ "$CC_REPO_UNKNOWN" -eq 1 ]; then
    limit "checkout unknown: $SCRIPT_DIR/repo-dir missing or invalid; fix lines that need the checkout are manual"
elif [ -n "$CC_REPO_GONE" ]; then
    limit "checkout unknown: $SCRIPT_DIR/repo-dir names $CC_REPO_GONE, which holds no deploy/upgrade.sh (moved, deleted, or not visible from this sandbox); fix lines that need the checkout are manual"
fi

# ---- systemd -------------------------------------------------------------------------------

declare -A U_ENABLED=()
declare -A U_ACTIVE=()
SYSTEMCTL=1
if ! have systemctl; then
    SYSTEMCTL=0
    limit "systemctl not found: unit and timer state unknown"
fi

# The first line systemctl prints for a query. is-enabled and is-active exit non-zero for the very
# states being asked about (disabled, inactive), so the exit status carries nothing here.
sysq() {
    local out
    out="$(systemctl "$@" 2>/dev/null || true)"
    printf '%s' "${out%%$'\n'*}"
}

# The unit is held in `un`: the alert library sourced above has an array named `u`, and shellcheck
# reads every function of both files as one scope.
probe_unit() {
    local un="$1" e a
    if [ -n "${U_ACTIVE["$un"]+x}" ]; then
        return 0
    fi
    if [ "$SYSTEMCTL" -eq 0 ]; then
        U_ENABLED["$un"]=unavailable
        U_ACTIVE["$un"]=unavailable
        return 0
    fi
    e="$(sysq is-enabled "$un.service")"
    a="$(sysq is-active "$un.service")"
    # systemd 25x prints "not-found" for a unit with no file; older releases print nothing.
    if [ "$e" = not-found ]; then
        e=""
    fi
    U_ENABLED["$un"]="$e"
    U_ACTIVE["$un"]="${a:-inactive}"
}

unit_is_enabled() {
    case "${U_ENABLED["$1"]}" in
        enabled | enabled-runtime | alias | static | indirect | generated | linked | linked-runtime) return 0 ;;
        *) return 1 ;;
    esac
}

# ---- the host's role -----------------------------------------------------------------------

# propolis_env_configures_no_daemon: succeeds when propolis.env is absent, or readable and names
# neither DATABASE_URL nor PROPOLIS_SENSOR_LOGS. deploy/backup.sh dumps the database the first
# names and deploy/watch-env.sh writes watch.env from the second on whatever host they run, so a
# host whose propolis.env names either has a backup and a live watch to judge, whatever pa_role
# says of it (a control node with its daemon stopped reads gateway, a single box with a leftover
# shipper.env reads collector). A file that cannot be read is not known to name neither.
propolis_env_configures_no_daemon() {
    local penv="$ENV_DIR/propolis.env"
    [ -e "$penv" ] || return 0
    [ -r "$penv" ] || return 1
    [ -z "$(read_env_var_in DATABASE_URL "$penv")" ] && [ -z "$(read_env_var_in PROPOLIS_SENSOR_LOGS "$penv")" ]
}

# Asked once. pa_role judges the daemon from the exit status of `systemctl is-enabled`, which a
# systemctl that cannot answer fails too, and then calls a host with shipper.env a collector; so
# a host is taken to run no daemon (CC_DAEMONLESS, the role word) only when systemctl itself shows
# the daemon's unit installed or absent, not enabled, and stopped, and propolis.env configures no
# daemon. A library that cannot answer, a word that is not a role, a daemon that is enabled,
# running or not answered for, or a propolis.env that names the daemon's database or intake list
# or cannot be read leaves it empty, and then every check runs as it always has: a host that runs
# the daemon must never lose a finding to a role read wrong.
CC_ROLE=""
if declare -F pa_role >/dev/null; then
    CC_ROLE="$(pa_role 2>/dev/null)" || CC_ROLE=""
    CC_ROLE="${CC_ROLE##*$'\n'}"
fi
CC_DAEMONLESS=""
case "$CC_ROLE" in
    collector | gateway)
        # Belt and braces: without systemctl, sysq prints nothing and the case below would not
        # match either; the guard states the rule where it is read.
        if [ "$SYSTEMCTL" -eq 1 ] && propolis_env_configures_no_daemon; then
            case "$(sysq is-enabled propolis.service)" in
                disabled | masked | masked-runtime | not-found)
                    if [ "$(sysq is-active propolis.service)" = inactive ]; then
                        CC_DAEMONLESS="$CC_ROLE"
                    fi
                    ;;
            esac
        fi
        ;;
esac
# For the report's one line: the daemon's checks, which config-check runs on the host that runs
# propolis.service (CC_LEFT_OUT), and what no host checks for this one (CC_NOT_HERE), each entry
# with its own reason.
CC_LEFT_OUT=()
CC_NOT_HERE=()
# role_word: the role as the report and the rows name it.
role_word() {
    if [ "$CC_DAEMONLESS" = gateway ]; then printf 'gateway only'; else printf '%s' "$CC_DAEMONLESS"; fi
}

# ---- sockets -------------------------------------------------------------------------------

declare -A SS_OUT=()
SS_OK=1
if have ss; then
    SS_OUT[tcp]="$(ss -H -ltnp 2>/dev/null)" || SS_OK=0
    SS_OUT[udp]="$(ss -H -lunp 2>/dev/null)" || SS_OK=0
else
    SS_OK=0
fi
if [ "$SS_OK" -eq 0 ]; then
    limit "ss unavailable or failed: whether each port is bound, and by whom, is unknown"
fi

host_of() {
    local a="$1"
    a="${a%:*}"
    a="${a#[}"
    a="${a%]}"
    a="${a%%\%*}"
    printf '%s' "$a"
}

is_wildcard() {
    case "$1" in '' | '*' | 0.0.0.0 | '::') return 0 ;; *) return 1 ;; esac
}

is_loopback() {
    case "$1" in 127.* | '::1') return 0 ;; *) return 1 ;; esac
}

# The kernel truncates a process name (comm) to 15 characters; the longest sensor binary name,
# sensor-catchall, is exactly 15, so ss shows every sensor's name whole and equality is exact.
name_matches() {
    [ "$1" = "$2" ]
}

# listen_probe PROTO PORT BIND EXPECTED-BINARY: sets LISTEN_STATE (ours | foreign | ownerless |
# none | unavailable), LISTEN_NAMES (the foreign process names, comma separated) and
# LISTEN_EXPOSED (1 when a socket not owned by the sensor is bound to a non-loopback address).
# Exposure is judged from where the other socket is actually bound, not from the sensor's
# configured address: a database on 127.0.0.1:5432 blocks a sensor on 0.0.0.0:5432 but is not
# reachable from the network.
listen_probe() {
    local proto="$1" port="$2" bind="$3" expected="$4"
    local line state rq sq laddr peer rest lhost chost re name ours=0 foreign="" ownerless=0
    local line_foreign
    LISTEN_STATE=none
    LISTEN_NAMES=""
    LISTEN_EXPOSED=0
    if [ "$SS_OK" -eq 0 ]; then
        LISTEN_STATE=unavailable
        return 0
    fi
    chost="$(host_of "$bind")"
    re='\("([^"]*)",pid='
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        state="" rq="" sq="" laddr="" peer="" rest=""
        # shellcheck disable=SC2034 # rq, sq and peer only keep the ss columns aligned so laddr lands in the right field
        read -r state rq sq laddr peer rest <<<"$line" || true
        case "$laddr" in *:*) ;; *) continue ;; esac
        if [ "${laddr##*:}" != "$port" ]; then
            continue
        fi
        lhost="$(host_of "$laddr")"
        if ! is_wildcard "$lhost" && ! is_wildcard "$chost" && [ "$lhost" != "$chost" ]; then
            continue
        fi
        if [[ "$rest" != *'users:'* ]]; then
            ownerless=1
            is_loopback "$lhost" || LISTEN_EXPOSED=1
            continue
        fi
        line_foreign=0
        while [[ "$rest" =~ $re ]]; do
            name="${BASH_REMATCH[1]}"
            rest="${rest#*"${BASH_REMATCH[0]}"}"
            if name_matches "$name" "$expected"; then
                ours=1
            else
                line_foreign=1
                if [[ ",$foreign," != *",$name,"* ]]; then
                    foreign="${foreign:+$foreign,}$name"
                fi
            fi
        done
        if [ "$line_foreign" -eq 1 ] && ! is_loopback "$lhost"; then
            LISTEN_EXPOSED=1
        fi
    done <<<"${SS_OUT[$proto]}"
    if [ "$ours" -eq 1 ]; then
        LISTEN_STATE=ours
    elif [ -n "$foreign" ]; then
        LISTEN_STATE=foreign
        LISTEN_NAMES="$foreign"
    elif [ "$ownerless" -eq 1 ]; then
        LISTEN_STATE=ownerless
    fi
}

# ---- firewall ------------------------------------------------------------------------------

FW_KIND=none
FW_NOTE=""
FW_ALLOW_ALL=0
FW_SPECS=()

# add_portspec SPEC SOURCE: SPEC is `N`, `N/proto`, `A:B/proto`, `A-B/proto` or `A,B/proto`.
# SOURCE is `any` or `limited`. Each range is stored as proto:lo:hi:source.
add_portspec() {
    local spec="$1" src="${2:-any}" proto=any body list item lo hi
    case "$spec" in
        */*) proto="${spec##*/}"; body="${spec%/*}" ;;
        *) body="$spec" ;;
    esac
    case "$proto" in tcp | udp | any) ;; *) return 0 ;; esac
    IFS=',' read -r -a list <<<"$body" || true
    for item in "${list[@]}"; do
        case "$item" in
            *[:-]*) lo="${item%%[:-]*}"; hi="${item##*[:-]}" ;;
            *) lo="$item"; hi="$item" ;;
        esac
        case "$lo$hi" in '' | *[!0-9]*) continue ;; esac
        FW_SPECS+=("$proto:$lo:$hi:$src")
    done
}

detect_ufw() {
    local out line re default
    have ufw || return 1
    out="$(ufw status verbose 2>&1)" || true
    case "$out" in
        *'Status: active'*) ;;
        *'Status: inactive'*) return 1 ;;
        *)
            FW_NOTE="${FW_NOTE:+$FW_NOTE; }ufw is installed but its status is unreadable (run as root)"
            return 1
            ;;
    esac
    re='^Default:[[:space:]]+([a-z]+)[[:space:]]+\(incoming\)'
    while IFS= read -r line; do
        if [[ "$line" =~ $re ]]; then
            default="${BASH_REMATCH[1]}"
            if [ "$default" = allow ]; then
                FW_ALLOW_ALL=1
            fi
        fi
    done <<<"$out"
    re='^([0-9][0-9,:/a-z-]*)([[:space:]]+\(v6\))?[[:space:]]+(ALLOW|LIMIT)([[:space:]]+IN)?[[:space:]]+(.*)$'
    while IFS= read -r line; do
        if [[ "$line" == *' OUT '* ]]; then
            continue
        fi
        if [[ "$line" =~ $re ]]; then
            if [[ "${BASH_REMATCH[5]}" == Anywhere* ]]; then
                add_portspec "${BASH_REMATCH[1]}" any
            else
                add_portspec "${BASH_REMATCH[1]}" limited
            fi
        fi
    done <<<"$out"
    FW_KIND=ufw
    return 0
}

detect_firewalld() {
    local state zones zone info line key val tok svc ports
    have firewall-cmd || return 1
    state="$(firewall-cmd --state 2>/dev/null)" || state=""
    if [ "$state" != running ]; then
        return 1
    fi
    zones="$(firewall-cmd --get-active-zones 2>/dev/null | grep -E '^[^[:space:]]' || true)"
    while IFS= read -r zone; do
        [ -n "$zone" ] || continue
        info="$(firewall-cmd --zone="$zone" --list-all 2>/dev/null)" || info=""
        while IFS= read -r line; do
            line="$(trim "$line")"
            key="${line%%:*}"
            val="$(trim "${line#*:}")"
            case "$key" in
                ports)
                    for tok in $val; do
                        add_portspec "$tok" any
                    done
                    ;;
                services)
                    for svc in $val; do
                        ports="$(firewall-cmd --permanent --service="$svc" --get-ports 2>/dev/null)" || ports=""
                        for tok in $ports; do
                            add_portspec "$tok" any
                        done
                    done
                    ;;
                target)
                    if [ "$val" = ACCEPT ]; then
                        FW_ALLOW_ALL=1
                    fi
                    ;;
            esac
        done <<<"$info"
    done <<<"$zones"
    FW_KIND=firewalld
    return 0
}

detect_nft() {
    local out line in_input=0 found=0 policy_accept=0 policy_drop=0 has_drop=0 re items proto src
    have nft || return 1
    out="$(nft list ruleset 2>&1)" || {
        FW_NOTE="${FW_NOTE:+$FW_NOTE; }nft is installed but its ruleset is unreadable (run as root)"
        return 1
    }
    re='dport[[:space:]]+(\{[^}]*\}|[0-9]+(-[0-9]+)?)'
    while IFS= read -r line; do
        case "$line" in *'chain '*'{'*) in_input=0 ;; esac
        if [[ "$line" == *'hook input'* ]]; then
            in_input=1
            found=1
            if [[ "$line" == *'policy accept'* ]]; then
                policy_accept=1
            elif [[ "$line" == *'policy drop'* ]]; then
                policy_drop=1
            fi
            continue
        fi
        if [ "$in_input" -eq 0 ]; then
            continue
        fi
        if [[ "$line" == *drop* || "$line" == *reject* ]]; then
            has_drop=1
        fi
        if [[ "$line" == *accept* && "$line" =~ $re ]]; then
            items="${BASH_REMATCH[1]}"
            items="${items//[\{\} ]/}"
            proto=any
            if [[ "$line" =~ (tcp|udp)[[:space:]]+dport ]]; then
                proto="${BASH_REMATCH[1]}"
            fi
            src=any
            if [[ "$line" == *saddr* ]]; then
                src=limited
            fi
            add_portspec "$items/$proto" "$src"
        fi
    done <<<"$out"
    if [ "$found" -eq 0 ]; then
        return 1
    fi
    if [ "$policy_accept" -eq 1 ] && [ "$policy_drop" -eq 0 ] && [ "$has_drop" -eq 0 ]; then
        FW_ALLOW_ALL=1
    fi
    FW_KIND=nftables
    return 0
}

detect_firewall() {
    if detect_ufw; then return 0; fi
    if detect_firewalld; then return 0; fi
    if detect_nft; then return 0; fi
    if [ -n "$FW_NOTE" ]; then
        FW_KIND=unknown
        limit "firewall rules unreadable: $FW_NOTE"
    elif ! have ufw && ! have firewall-cmd && ! have nft; then
        FW_NOTE="no firewall tool found (ufw, firewall-cmd, nft)"
    else
        FW_NOTE="no active ufw, firewalld or nftables input rules"
    fi
}

# fw_state PROTO PORT: sets FW_STATE (open | limited | closed | none | unknown).
fw_state() {
    local proto="$1" port="$2" spec p lo hi src seen_limited=0
    case "$FW_KIND" in
        none) FW_STATE=none; return 0 ;;
        unknown) FW_STATE=unknown; return 0 ;;
    esac
    if [ "$FW_ALLOW_ALL" -eq 1 ]; then
        FW_STATE=open
        return 0
    fi
    for spec in "${FW_SPECS[@]}"; do
        IFS=':' read -r p lo hi src <<<"$spec"
        if [ "$p" != any ] && [ "$p" != "$proto" ]; then
            continue
        fi
        if [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ]; then
            if [ "$src" = any ]; then
                FW_STATE=open
                return 0
            fi
            seen_limited=1
        fi
    done
    if [ "$seen_limited" -eq 1 ]; then
        FW_STATE=limited
    else
        FW_STATE=closed
    fi
}

# The firewall fix is a command only for the two firewalls with a one-line rule command; for raw
# nftables (rules live in the operator's own ruleset file) it is an instruction.
fw_fix_kind() {
    case "$FW_KIND" in
        ufw | firewalld) printf 'run' ;;
        *) printf 'manual' ;;
    esac
}

fw_open_fix() {
    local proto="$1" port="$2"
    case "$FW_KIND" in
        ufw) printf 'sudo ufw allow %s/%s' "$port" "$proto" ;;
        firewalld) printf 'sudo firewall-cmd --permanent --add-port=%s/%s && sudo firewall-cmd --reload' "$port" "$proto" ;;
        *) printf 'add a rule accepting %s dport %s to your nftables input chain' "$proto" "$port" ;;
    esac
}

fw_close_fix() {
    local proto="$1" port="$2"
    case "$FW_KIND" in
        ufw) printf 'sudo ufw delete allow %s/%s' "$port" "$proto" ;;
        firewalld) printf 'sudo firewall-cmd --permanent --remove-port=%s/%s && sudo firewall-cmd --reload' "$port" "$proto" ;;
        *) printf 'remove the rule accepting %s dport %s from your nftables input chain' "$proto" "$port" ;;
    esac
}

# ledger_query_fix SENSOR: the newest event for one sensor, by running this script's own
# --newest-event mode as root. The operator's shell has no DATABASE_URL (it is in a root-only env
# file), and passing it to psql would put the password on psql's argv; the mode reads it itself and
# hands it to psql through PG* variables, like the report's own ledger query.
ledger_query_fix() {
    local sensor="$1" envarg=""
    if [ "$ENV_DIR" != /etc/propolis ]; then
        envarg=" --env-dir $(q "$ENV_DIR")"
    fi
    printf 'sudo %s%s --newest-event %s' "$(q "$SCRIPT_DIR/config-check.sh")" "$envarg" "$(q "$sensor")"
}

# ---- PROPOLIS_SENSOR_LOGS ------------------------------------------------------------------

INTAKE_VAR=""
INTAKE_FILE=""
INTAKE_RAW=""
INTAKE_STATE=missing # missing | unreadable | present
IN_LABEL=()
IN_PATH=()
IN_BAD=()
IN_BAD_WHY=()

# intake_restart [FILE]: what to run after an edit to the list of sensor logs in FILE (default:
# the file the list was read from). The shipper reads shipper.env and the daemon propolis.env, so
# a fix on a collector never tells the operator to start a daemon the host does not run.
intake_restart() {
    case "${1:-$INTAKE_FILE}" in
        */shipper.env) printf 'sudo systemctl restart shipper.service' ;;
        *) printf 'sudo systemctl restart propolis.service' ;;
    esac
}

# intake_restart_watch: the same for the file the list was read from, and where the daemon reads
# it also the script that copies the list to the live watch's env file.
intake_restart_watch() {
    case "$INTAKE_FILE" in
        */shipper.env) intake_restart ;;
        *) printf '%s && %s' "$(intake_restart)" "$(checkout_cmd watch-env.sh)" ;;
    esac
}

load_intake() {
    local f v
    for f in "$ENV_DIR/propolis.env:PROPOLIS_SENSOR_LOGS" "$ENV_DIR/shipper.env:PROPOLIS_SHIPPER_SENSOR_LOGS"; do
        local file="${f%%:*}" var="${f##*:}"
        if [ -e "$file" ] && [ ! -r "$file" ]; then
            INTAKE_STATE=unreadable
            continue
        fi
        [ -r "$file" ] || continue
        v="$(read_env_var_in "$var" "$file")"
        if [ -n "$v" ]; then
            INTAKE_VAR="$var"
            INTAKE_FILE="$file"
            INTAKE_RAW="$v"
            INTAKE_STATE=present
            return 0
        fi
    done
}

# The daemon's grammar (crates/log-tailer/src/sensor_logs.rs parse_sensor_logs): comma separated,
# each entry trimmed, blank entries skipped, split on the FIRST colon, both halves non-empty. One
# bad entry makes the daemon refuse to start. Parsed by the alert library, so the witness and
# propolis-status, when they come (later releases), read the list exactly as this does.
parse_intake() {
    pa_sensor_logs "$INTAKE_RAW"
    IN_LABEL=("${PA_LOG_LABEL[@]}")
    IN_PATH=("${PA_LOG_PATH[@]}")
    IN_BAD=("${PA_LOG_BAD[@]}")
    IN_BAD_WHY=("${PA_LOG_BAD_WHY[@]}")
}

# The most likely intended `label:path` for a malformed entry, or nothing.
suggest_entry() {
    local entry="$1" why="$2" i sep rest
    case "$why" in
        "no ':' separator")
            for sep in ';' '=' '|' ' ' ','; do
                case "$entry" in
                    *"$sep"/*)
                        printf '%s:%s' "${entry%%"$sep"*}" "/${entry#*"$sep"/}"
                        return 0
                        ;;
                esac
            done
            ;;
        "label with no path")
            for ((i = 0; i < ROW_COUNT; i++)); do
                if [ "$(label_of "${R_SENSOR[$i]}")" = "${entry%%:*}" ] && [ -n "${R_LOGPATH[$i]}" ]; then
                    printf '%s:%s' "${entry%%:*}" "${R_LOGPATH[$i]}"
                    return 0
                fi
            done
            ;;
        "empty label")
            rest="${entry#:}"
            for ((i = 0; i < ROW_COUNT; i++)); do
                if [ "${R_LOGPATH[$i]}" = "$rest" ]; then
                    printf '%s:%s' "$(label_of "${R_SENSOR[$i]}")" "$rest"
                    return 0
                fi
            done
            ;;
    esac
}

# ---- derive the listener inventory ---------------------------------------------------------

R_LOGPATH=()
R_BADBIND=()
R_VAR=()

while IFS=$'\t' read -r s_name s_proto s_port s_addr s_var; do
    [ -n "$s_name" ] || continue
    R_SENSOR+=("$(clean "$s_name")")
    R_PROTO+=("$s_proto")
    R_ADDR+=("$(clean "$s_addr")")
    R_PORT+=("$s_port")
    R_VAR+=("$s_var")
    R_UNIT+=("$(unit_of "$s_name")")
    R_LOGPATH+=("$(clean "$(log_path_of "$s_name")")")
    bad=0
    case "$s_port" in '' | *[!0-9]*) bad=1 ;; esac
    if [ "$bad" -eq 0 ] && { [ "$s_port" -lt 1 ] || [ "$s_port" -gt 65535 ]; }; then
        bad=1
    fi
    R_BADBIND+=("$bad")
    ROW_COUNT=$((ROW_COUNT + 1))
done < <(derive_listeners)

load_intake
if [ "$INTAKE_STATE" = present ]; then
    parse_intake
fi

# ---- events (optional) ---------------------------------------------------------------------

declare -A EV_AGE=()
EV_STATE=skip # skip | ok
EV_REASON=""

# Splits a postgres:// URL into libpq environment variables, so the password never appears on a
# command line (argv is world-readable in /proc). Prints nothing and returns 1 on a URL it does
# not understand.
pg_urldecode() {
    local s="$1"
    s="${s//\\/\\\\}"
    printf '%b' "${s//%/\\x}"
}

# ledger_psql SQL: runs one read-only statement against the ledger with psql's unaligned,
# tuples-only output on stdout. The connection comes from DATABASE_URL in propolis.env and reaches
# psql only through PG* variables. Returns 10 (env file unreadable), 11 (no DATABASE_URL), 12 (no
# psql) or 13 (not a postgres:// URL) without running anything; otherwise psql's own status.
ledger_psql() {
    local sql="$1" url rest query db auth hostport user pass host port q kv key val
    if [ -e "$ENV_DIR/propolis.env" ] && [ ! -r "$ENV_DIR/propolis.env" ]; then
        return 10
    fi
    url="$(read_env_var_in DATABASE_URL "$ENV_DIR/propolis.env")"
    if [ -z "$url" ]; then
        return 11
    fi
    if ! have psql; then
        return 12
    fi
    case "$url" in
        postgres://* | postgresql://*) rest="${url#*://}" ;;
        *) return 13 ;;
    esac
    query=""
    case "$rest" in *\?*) query="${rest#*\?}"; rest="${rest%%\?*}" ;; esac
    db=""
    case "$rest" in */*) db="${rest#*/}"; rest="${rest%%/*}" ;; esac
    auth=""
    hostport="$rest"
    case "$rest" in *@*) auth="${rest%@*}"; hostport="${rest##*@}" ;; esac
    user="${auth%%:*}"
    pass=""
    case "$auth" in *:*) pass="${auth#*:}" ;; esac
    host="$hostport"
    port=""
    case "$hostport" in
        \[*\]*) host="${hostport%%]*}"; host="${host#[}"; q="${hostport#*]}"; port="${q#:}" ;;
        *:*) host="${hostport%%:*}"; port="${hostport##*:}" ;;
    esac
    # A Unix socket directory in the host position is percent-encoded (postgres://u@%2Frun%2F
    # postgresql/db), which is how the daemon's parser reads it; undecoded, psql looked the
    # literal text up as a host name.
    host="$(pg_urldecode "$host")"
    local sslmode=""
    IFS='&' read -r -a kvs <<<"$query" || true
    for kv in "${kvs[@]}"; do
        key="${kv%%=*}"
        val="${kv#*=}"
        case "$key" in
            host) host="$(pg_urldecode "$val")" ;;
            port) port="$val" ;;
            sslmode) sslmode="$val" ;;
        esac
    done
    (
        PGUSER="$(pg_urldecode "$user")"
        PGPASSWORD="$(pg_urldecode "$pass")"
        PGDATABASE="$(pg_urldecode "$db")"
        export PGUSER PGPASSWORD PGDATABASE
        export PGHOST="$host" PGCONNECT_TIMEOUT=5 PGAPPNAME=propolis-config-check
        export PGOPTIONS='-c statement_timeout=3000 -c default_transaction_read_only=on'
        if [ -n "$port" ]; then export PGPORT="$port"; fi
        if [ -n "$sslmode" ]; then export PGSSLMODE="$sslmode"; fi
        if have timeout; then
            exec timeout 10 psql -X -A -t -F '|' -c "$sql"
        else
            exec psql -X -A -t -F '|' -c "$sql"
        fi
    )
}

run_events() {
    local out rc=0 key val
    if [ "$NO_EVENTS" -eq 1 ]; then
        EV_REASON="disabled by --no-events"
        return 0
    fi
    out="$TMP_DIR/events.out"
    ledger_psql "SELECT sensor, (extract(epoch FROM now() - max(observed_at)))::bigint FROM event WHERE observed_at > now() - interval '7 days' GROUP BY sensor" >"$out" 2>/dev/null || rc=$?
    case "$rc" in
        0)
            EV_STATE=ok
            while IFS='|' read -r key val; do
                case "$val" in '' | *[!0-9]*) continue ;; esac
                [ -n "$key" ] || continue
                EV_AGE["$key"]="$val"
            done <"$out"
            ;;
        10)
            EV_REASON="$ENV_DIR/propolis.env not readable"
            limit "ledger query skipped: $EV_REASON (run as root)"
            ;;
        11) EV_REASON="no DATABASE_URL in $ENV_DIR/propolis.env" ;;
        12)
            EV_REASON="psql not installed"
            limit "ledger query skipped: psql not installed"
            ;;
        13) EV_REASON="DATABASE_URL is not a postgres:// URL" ;;
        *)
            EV_REASON="ledger query failed or timed out"
            limit "ledger query skipped: the database could not be queried read-only within its timeout"
            ;;
    esac
}

# Whether the role the daemon connects as can do more to the ledger than append to it. The
# append-only control is a revoke, which does not bind the table's owner: a daemon connected as
# the role that ran the migrations can grant itself UPDATE and DELETE back or disable the chain
# trigger (docs/operations/database-roles.md). A role that owns the database the table is in, or
# may create objects in its schema, is confined by nothing on the table either: that is what a
# database restored for the wrong owner leaves. One row comes back,
# role|controls|privileges|owns_database|can_create: controls is t when the role owns `event` or
# is a superuser, privileges lists what it holds beyond SELECT and INSERT, owns_database is t when
# it owns the database and can_create when it may create in the schema `event` is in. Asked as the
# daemon's own role, read-only, through the same connection path as the events query; skipped
# wherever that query could not run, which is already reported.
check_ledger_role() {
    local out role="" controls="" privs="" owns_db="" can_create="" extra="" flag what=""
    if [ "$EV_STATE" != ok ]; then
        return 0
    fi
    out="$TMP_DIR/ledger-role.out"
    ledger_psql "SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) OR pg_has_role(current_user, c.relowner, 'USAGE'), concat_ws(' ', CASE WHEN has_table_privilege(c.oid, 'UPDATE') THEN 'UPDATE' END, CASE WHEN has_table_privilege(c.oid, 'DELETE') THEN 'DELETE' END, CASE WHEN has_table_privilege(c.oid, 'TRUNCATE') THEN 'TRUNCATE' END, CASE WHEN has_table_privilege(c.oid, 'TRIGGER') THEN 'TRIGGER' END), (SELECT pg_has_role(current_user, d.datdba, 'USAGE') FROM pg_database d WHERE d.datname = current_database()), has_schema_privilege(c.relnamespace, 'CREATE') FROM pg_class c WHERE c.oid = to_regclass('event')" >"$out" 2>/dev/null || return 0
    # The last name takes whatever is left of the line, so one more name than the query has
    # columns keeps a column this function does not know out of the ones it reads.
    IFS='|' read -r role controls privs owns_db can_create extra <"$out" || true
    # Each column has a closed vocabulary: three booleans as psql prints them, and a list that can
    # only be capitals and spaces. A row that is anything else (no row, fewer columns, more, other
    # text) is not this query's answer, and nothing is claimed from it either way.
    for flag in "$controls" "$owns_db" "$can_create"; do
        case "$flag" in t | f) ;; *) return 0 ;; esac
    done
    case "$privs" in *[!A-Z\ ]*) return 0 ;; esac
    if [ -n "$extra" ]; then
        return 0
    fi
    if [ "$controls" = t ]; then
        finding warn "ledger" "ledger-owner" "the daemon connects to the database as role $role, which owns the event table (or is a superuser): the ledger's append-only revoke does not bind an owner, so this role can grant itself UPDATE and DELETE or disable the chain trigger" \
            "split the database roles so an owner role migrates and the daemon's role only appends: docs/operations/database-roles.md" manual
        return 0
    fi
    if [ "$owns_db" = t ]; then
        what="owns the database: it can put a schema of its own ahead of the ledger's in every session's search path, the owner role's migrations included"
    elif [ "$can_create" = t ]; then
        what="may create objects in the ledger's schema: it can plant functions and tables there for the owner role's migrations to call or adopt"
    fi
    if [ -n "$what" ]; then
        finding warn "ledger" "ledger-database" "the daemon's database role $role does not own the event table but $what" \
            "stop propolis, give the database and its schema back to the owner role (propolis migrate --init-roles) and run propolis-migrate: docs/operations/database-roles.md" manual
    fi
    if [ -n "$privs" ]; then
        finding warn "ledger" "ledger-grants" "the daemon's database role $role holds $privs on the event table; it needs only SELECT and INSERT" \
            "sudo propolis-migrate"
    fi
}

# --newest-event SENSOR: prints when the ledger last received an event from SENSOR (any age) and
# exits. Read-only, through the same connection path as the report; the target of the events
# findings' fix line.
newest_event() {
    local sensor="$1" rc=0 out
    out="$(ledger_psql "SELECT max(observed_at) FROM event WHERE sensor = '$sensor'")" || rc=$?
    case "$rc" in
        0) printf 'sensor %s: newest event %s\n' "$sensor" "${out:-none in the ledger}" ;;
        10) echo "error: $ENV_DIR/propolis.env is not readable (run as root)" >&2 ;;
        11) echo "error: no DATABASE_URL in $ENV_DIR/propolis.env" >&2 ;;
        12) echo "error: psql is not installed" >&2 ;;
        13) echo "error: DATABASE_URL is not a postgres:// URL" >&2 ;;
        *) echo "error: the ledger query failed or timed out" >&2 ;;
    esac
    return "$rc"
}

if [ -n "$NEWEST_EVENT" ]; then
    newest_event "$NEWEST_EVENT" || exit 1
    exit 0
fi

# ---- per-listener checks -------------------------------------------------------------------

ROTATE_SIZE="$DEFAULT_ROTATE_SIZE"
ROTATE_SIZE_NOTE="assumed ${DEFAULT_ROTATE_SIZE} (policy not readable)"
load_rotate_size() {
    local line first rest size
    if [ -r "$ROTATE_POLICY" ]; then
        while IFS= read -r line; do
            read -r first rest _ <<<"$line" || true
            if [ "$first" = size ]; then
                size="$(parse_size "$rest")"
                if [ -n "$size" ]; then
                    ROTATE_SIZE="$size"
                    ROTATE_SIZE_NOTE="size $rest from $ROTATE_POLICY"
                    return 0
                fi
            fi
        done <"$ROTATE_POLICY"
    fi
}

check_listener() {
    local i="$1" sensor proto addr port unit expected scope
    sensor="${R_SENSOR[$i]}" proto="${R_PROTO[$i]}" addr="${R_ADDR[$i]}" port="${R_PORT[$i]}"
    unit="${R_UNIT[$i]}" expected="${R_UNIT[$i]}"
    scope="$sensor/$proto"

    if [ "${R_BADBIND[$i]}" -eq 1 ]; then
        for c in "${COLUMNS[@]}"; do setcell "$i" "$c" skip "-"; done
        setcell "$i" listen fail "bad bind"
        finding fail "$scope" "badbind:${R_VAR[$i]}:$addr" \
            "${R_VAR[$i]}=$addr has no usable port, so $unit refuses to start" \
            "edit ${R_VAR[$i]} in $ENV_DIR/*.env to ip:port (1-65535), then run: sudo systemctl restart $unit.service" manual
        return 0
    fi

    # 1. unit
    probe_unit "$unit"
    local e="${U_ENABLED["$unit"]}" a="${U_ACTIVE["$unit"]}" unit_down=0 unit_known=1
    local ufile="$REPO_DIR/deploy/$unit.service"
    if [ "$a" = unavailable ]; then
        unit_known=0
        setcell "$i" unit unknown "?"
    elif [ -z "$e" ]; then
        unit_down=1
        setcell "$i" unit fail "not installed"
        local ufix ukind=run
        ufix="sudo install -m 0644 $(q "$ufile")"
        if [ -z "$REPO_DIR" ]; then
            ufix="$CHECKOUT_TOP sudo install -m 0644 ./deploy/$unit.service"
            ukind=manual
        fi
        finding fail "$unit" "unit-missing:$unit" "$unit.service is not installed but $scope is configured (${R_VAR[$i]})" \
            "$ufix /etc/systemd/system/$unit.service && sudo systemctl daemon-reload && sudo systemctl enable --now $unit.service" "$ukind"
    elif [ "$e" = masked ]; then
        unit_down=1
        setcell "$i" unit fail "masked"
        finding fail "$unit" "unit-masked:$unit" "$unit.service is masked" \
            "sudo systemctl unmask $unit.service && sudo systemctl enable --now $unit.service"
    elif [ "$a" = active ]; then
        if unit_is_enabled "$unit"; then
            setcell "$i" unit ok "active"
        else
            setcell "$i" unit warn "active, not enabled"
            finding warn "$unit" "unit-notenabled:$unit" "$unit.service is running but not enabled, so it will not start after a reboot" \
                "sudo systemctl enable $unit.service"
        fi
    else
        unit_down=1
        if unit_is_enabled "$unit"; then
            setcell "$i" unit fail "$a"
            finding fail "$unit" "unit-down:$unit" "$unit.service is enabled but $a: read its log, fix what it reports, then run: sudo systemctl restart $unit.service" \
                "sudo journalctl -u $unit.service -n 50 --no-pager"
        else
            setcell "$i" unit fail "not enabled ($a)"
            finding fail "$unit" "unit-disabled:$unit" "$unit.service is configured (${R_VAR[$i]}) but not enabled and $a" \
                "sudo systemctl enable --now $unit.service"
        fi
    fi

    # 2. listening
    local listen_ok=0 foreign=0
    listen_probe "$proto" "$port" "$addr" "$expected"
    case "$LISTEN_STATE" in
        unavailable) setcell "$i" listen unknown "?" ;;
        ours)
            listen_ok=1
            setcell "$i" listen ok "sensor"
            ;;
        foreign)
            foreign=1
            setcell "$i" listen fail "OTHER:$LISTEN_NAMES"
            if [ "$LISTEN_EXPOSED" -eq 1 ]; then
                finding fail "$scope" "listen-foreign:$proto:$port" \
                    "$proto/$port is held by another process ($LISTEN_NAMES), not $expected: $unit cannot bind it, so $scope is not being collected. Stop that process or move it off $proto/$port (a database belongs on 127.0.0.1), then run: sudo systemctl restart $unit.service" \
                    "sudo ss -$([ "$proto" = udp ] && echo lunp || echo ltnp) 'sport = :$port'"
            else
                finding fail "$scope" "listen-loopback:$proto:$port" \
                    "$proto/$port is held on loopback only by another process ($LISTEN_NAMES), so it is not reachable from the network, but $unit cannot bind ${addr} over it and $scope is not being collected" \
                    "keep that process on loopback and give the sensor this host's network address instead (a specific address can share the port with a loopback listener): set ${R_VAR[$i]}=<this host's address>:$port in $ENV_DIR/*.env, then run: sudo systemctl restart $unit.service" manual
            fi
            ;;
        ownerless)
            if [ "$unit_known" -eq 1 ] && [ "$a" != active ]; then
                foreign=1
                setcell "$i" listen fail "OTHER:owner unknown"
                finding fail "$scope" "listen-ownerless:$proto:$port" \
                    "$proto/$port is bound by a process that is not $expected ($unit is not running); its name is hidden without root. Name it with the command below, stop it or move it off $proto/$port, then run: sudo systemctl restart $unit.service" \
                    "sudo ss -$([ "$proto" = udp ] && echo lunp || echo ltnp) 'sport = :$port'"
            else
                setcell "$i" listen unknown "bound, owner unknown"
                limit "socket owners hidden: ports show 'bound, owner unknown (run as root to name it)'"
            fi
            ;;
        none)
            setcell "$i" listen fail "nothing listening"
            if [ "$unit_down" -eq 0 ]; then
                finding fail "$scope" "listen-none:$proto:$port" \
                    "nothing is listening on $proto/$port although $unit is active (the bind failed and the sensor skipped it, or it is bound to another address)" \
                    "sudo journalctl -u $unit.service -n 50 --no-pager | grep -i bind"
            fi
            ;;
    esac

    # 3. firewall
    local chost
    chost="$(host_of "$addr")"
    if is_loopback "$chost"; then
        setcell "$i" firewall ok "loopback"
    else
        fw_state "$proto" "$port"
        case "$FW_STATE" in
            unknown) setcell "$i" firewall unknown "?" ;;
            none) setcell "$i" firewall ok "none detected" ;;
            open) setcell "$i" firewall ok "open" ;;
            limited) setcell "$i" firewall ok "open (limited)" ;;
            closed)
                if [ "$listen_ok" -eq 1 ]; then
                    setcell "$i" firewall warn "closed"
                    finding warn "$scope" "fw:$proto:$port" \
                        "$proto/$port is served by $expected but the $FW_KIND firewall does not allow it, so nothing reaches this sensor" \
                        "$(fw_open_fix "$proto" "$port")" "$(fw_fix_kind)"
                else
                    setcell "$i" firewall ok "closed"
                fi
                ;;
        esac
        if [ "$foreign" -eq 1 ] && [ "$LISTEN_EXPOSED" -eq 1 ] && [ "$FW_STATE" = open ]; then
            setcell "$i" firewall fail "OPEN to a non-sensor"
            finding fail "$scope" "danger:$proto:$port" \
                "DANGEROUS: $proto/$port is open in the $FW_KIND firewall and bound by a process that is not $expected${LISTEN_NAMES:+ ($LISTEN_NAMES)}: a real service is exposed to the internet through a honeypot port. Close the port with the line below, or stop/rebind that service to 127.0.0.1 and then run: sudo systemctl restart $unit.service" \
                "$(fw_close_fix "$proto" "$port")" "$(fw_fix_kind)"
        elif [ "$foreign" -eq 1 ] && [ "$LISTEN_EXPOSED" -eq 1 ] && [ "$FW_STATE" = none ]; then
            finding warn "$scope" "nofw:$proto:$port" \
                "no host firewall was detected and $proto/$port is held by a non-sensor process: it is reachable from anywhere the network allows" \
                "install and enable a host firewall, or move that service to 127.0.0.1" manual
        fi
    fi

    # 4. log
    local lp="${R_LOGPATH[$i]}" lstat lm ls age
    if [ -z "$lp" ]; then
        setcell "$i" log warn "relative default"
        finding warn "$scope" "logpath:$sensor" \
            "$sensor has no PROPOLIS_CATCHALL_LOG_PATH: its compiled default is a relative path the unit's sandbox cannot write" \
            "add PROPOLIS_CATCHALL_LOG_PATH=/var/log/propolis/catchall/events.jsonl to $ENV_DIR/catchall.env, then run: sudo systemctl restart $unit.service" manual
    elif lstat="$(stat -c '%Y %s' -- "$lp" 2>/dev/null)"; then
        lm="${lstat%% *}"
        ls="${lstat##* }"
        age=$((NOW - lm))
        local text
        text="$(human_age "$age") $(human_bytes "$ls")/$(human_bytes "$ROTATE_SIZE")"
        if [ "$ls" -ge $((ROTATE_SIZE * 3)) ]; then
            setcell "$i" log fail "$text"
            finding fail "$scope" "logsize-fail:$lp" \
                "$lp is $(human_bytes "$ls"), more than 3x the rotation size ($(human_bytes "$ROTATE_SIZE")): rotation is not keeping up. For a log the rotation refused, see docs/operations/retention.md, 'A log too large to rotate'" \
                "sudo systemctl start propolis-logrotate.service; sudo journalctl -u propolis-logrotate.service -n 30 --no-pager"
        elif [ "$ls" -ge $((ROTATE_SIZE * 2)) ]; then
            setcell "$i" log warn "$text"
            finding warn "$scope" "logsize-warn:$lp" \
                "$lp is $(human_bytes "$ls"), over 2x the rotation size ($(human_bytes "$ROTATE_SIZE"))" \
                "sudo systemctl start propolis-logrotate.service"
        elif [ "$listen_ok" -eq 1 ] && [ "$age" -gt $((STALE_HOURS * 3600)) ]; then
            setcell "$i" log warn "quiet $text"
            finding warn "$scope" "logquiet:$lp" \
                "$lp has not been written for $(human_age "$age") although $unit is bound and running: confirm traffic reaches the port (check the firewall and upstream filtering)" \
                "sudo journalctl -u $unit.service -n 50 --no-pager"
        else
            setcell "$i" log ok "$text"
        fi
    elif [ ! -x "$(dirname -- "$lp")" ] && [ -d "$(dirname -- "$lp")" ]; then
        setcell "$i" log unknown "?"
        limit "log files not traversable as this user (/var/log/propolis/* is owned by each sensor's account)"
    else
        setcell "$i" log warn "missing"
        if [ "$unit_down" -eq 0 ] && [ "$listen_ok" -eq 1 ]; then
            finding warn "$scope" "logmissing:$lp" \
                "$lp does not exist although $unit is running and bound: no event has been written, or the sensor writes elsewhere" \
                "sudo grep -H LOG_PATH $(q "$ENV_DIR")/*.env; sudo journalctl -u $unit.service -n 50 --no-pager"
        fi
    fi

    # 5. intake
    if [ "$INTAKE_STATE" = present ] && [ -n "$lp" ]; then
        local j found="" same_label=""
        local want_label
        want_label="$(label_of "$sensor")"
        for ((j = 0; j < ${#IN_PATH[@]}; j++)); do
            if [ "${IN_PATH[$j]}" = "$lp" ]; then
                found="${IN_LABEL[$j]}"
            fi
            if [ "${IN_LABEL[$j]}" = "$want_label" ]; then
                same_label="${IN_PATH[$j]}"
            fi
        done
        if [ -n "$found" ]; then
            setcell "$i" intake ok "$found"
        elif [ -n "$same_label" ]; then
            setcell "$i" intake fail "wrong path"
            finding fail "$scope" "intake-wrongpath:$lp" \
                "$INTAKE_VAR names '$want_label:$same_label' but $sensor writes $lp: intake tails a file the sensor never writes" \
                "in $INTAKE_FILE set the entry to $want_label:$lp, then run: $(intake_restart_watch)" manual
        else
            setcell "$i" intake fail "absent"
            finding fail "$scope" "intake-absent:$lp" \
                "$lp is not in $INTAKE_VAR: events from $sensor are never ingested" \
                "append ,$want_label:$lp to $INTAKE_VAR in $INTAKE_FILE, then run: $(intake_restart_watch)" manual
        fi
    elif [ "$INTAKE_STATE" = unreadable ]; then
        setcell "$i" intake unknown "?"
        limit "propolis.env / shipper.env not readable: PROPOLIS_SENSOR_LOGS cannot be checked (run as root)"
    elif [ -z "$lp" ]; then
        setcell "$i" intake skip "-"
    else
        setcell "$i" intake fail "no list"
    fi

    # 6. events
    if [ "$EV_STATE" = ok ]; then
        local age_s="${EV_AGE["$sensor"]:-}"
        if [ -z "$age_s" ]; then
            setcell "$i" events warn "none in 7d"
            finding warn "$scope" "events-none:$sensor" \
                "the ledger holds no event from sensor '$sensor' in the last 7 days: the first command shows its newest event ever; if the log is growing, the second shows whether intake is following it" \
                "$(ledger_query_fix "$sensor"); sudo journalctl -u propolis.service -n 50 --no-pager"
        elif [ "$age_s" -gt $((STALE_HOURS * 3600)) ]; then
            setcell "$i" events warn "$(human_age "$age_s") ago"
            finding warn "$scope" "events-old:$sensor" \
                "the newest '$sensor' event in the ledger is $(human_age "$age_s") old: check whether intake is following the log" \
                "sudo journalctl -u propolis.service -n 50 --no-pager"
        else
            setcell "$i" events ok "$(human_age "$age_s") ago"
        fi
    else
        setcell "$i" events skip "-"
    fi
}

# ---- host-wide checks ----------------------------------------------------------------------

check_rotation() {
    local e a mtime age parts=() worst=ok
    if [ "$SYSTEMCTL" -eq 1 ]; then
        e="$(sysq is-enabled propolis-logrotate.timer)"
        a="$(sysq is-active propolis-logrotate.timer)"
        if [ "$a" = active ]; then
            parts+=("timer active")
        else
            worst=fail
            parts+=("timer ${a:-not installed}")
            finding fail "logrotate" "timer" "propolis-logrotate.timer is ${a:-not installed}: nothing rotates the sensor logs (October 2026: a dead timer let one log reach 6.6 GB). If the timer unit is not installed at all, run the upgrade script instead: $(upgrade_fix)" \
                "sudo systemctl enable --now propolis-logrotate.timer"
        fi
        if [ "$a" = active ] && [ -n "$e" ] && ! { [ "$e" = enabled ] || [ "$e" = enabled-runtime ]; }; then
            if [ "$worst" = ok ]; then worst=warn; fi
            finding warn "logrotate" "timer-enabled" "propolis-logrotate.timer is active but $e, so it will not return after a reboot" \
                "sudo systemctl enable propolis-logrotate.timer"
        fi
        if [ "$(sysq is-failed propolis-logrotate.service)" = failed ]; then
            if [ "$worst" = ok ]; then worst=warn; fi
            parts+=("last run failed")
            finding warn "logrotate" "service-failed" "propolis-logrotate.service last exited non-zero (a log was refused by the free-space guard, or logrotate errored)" \
                "sudo journalctl -u propolis-logrotate.service -n 30 --no-pager"
        fi
    else
        worst=unknown
        parts+=("timer state unknown")
    fi
    if mtime="$(stat -c %Y -- "$ROTATE_STATE" 2>/dev/null)"; then
        age=$((NOW - mtime))
        parts+=("last run $(human_age "$age") ago")
        if [ "$age" -gt "$ROTATE_STALE_SECS" ]; then
            worst=fail
            finding fail "logrotate" "stale" "logrotate has not run for $(human_age "$age") (state file $ROTATE_STATE; the daemon's rotation-stale alert fires at 3h)" \
                "sudo systemctl start propolis-logrotate.service; sudo journalctl -u propolis-logrotate.service -n 30 --no-pager"
        fi
    else
        parts+=("never ran")
        if [ "$worst" = ok ]; then worst=warn; fi
        finding warn "logrotate" "never" "$ROTATE_STATE does not exist: logrotate has never run on this host's Propolis policy" \
            "sudo systemctl start propolis-logrotate.service"
    fi
    if [ ! -r "$ROTATE_POLICY" ]; then
        worst=fail
        parts+=("policy missing")
        finding fail "logrotate" "policy" "$ROTATE_POLICY is not installed" "$(checkout_install 0644 logrotate-sensors.conf "$ROTATE_POLICY")" "$(fix_kind_checkout)"
    fi
    if [ ! -x "$ROTATE_GUARD" ]; then
        worst=fail
        parts+=("guard missing")
        finding fail "logrotate" "guard" "$ROTATE_GUARD is not installed or not executable: every rotation fails closed" \
            "$(checkout_install 0755 logrotate-guard.sh "$ROTATE_GUARD")" "$(fix_kind_checkout)"
    fi
    local text="" p
    for p in "${parts[@]}"; do text="${text:+$text, }$p"; done
    global logrotate "$worst" "$text (rotation size: $ROTATE_SIZE_NOTE)"
}

# Whether the sets retention keeps can all sit beside the database without leaving the backup volume
# under the headroom deploy/backup.sh enforces (the ops monitor's low-disk threshold, and the
# logrotate guard's reserve). backup.sh refuses a run that would break it, so a node that fails this
# check stops backing up one night instead of filling the disk. Prints a finding and returns 1 when
# it cannot fit; prints nothing when it fits, or when the status predates the figures it needs or
# the retention is one backup.sh refuses to run with. A volume it cannot measure is reported with
# limit(), never as a pass.
backup_headroom() {
    local success="$1" unit_env dump archive set_bytes keep dir probe size avail pct keep_free
    local pct_bytes sets total tok used_sets other need
    dump="$(printf '%s' "$success" | sed -n 's/.*"dump_bytes":\([0-9]\{1,15\}\).*/\1/p')"
    archive="$(printf '%s' "$success" | sed -n 's/.*"archive_bytes":\([0-9]\{1,15\}\).*/\1/p')"
    # A status from before source_bytes was recorded predates the sizing this models.
    case "$success" in
        *'"source_bytes":'[0-9]*) ;;
        *) return 0 ;;
    esac
    if [ -z "$dump" ] || [ -z "$archive" ]; then
        return 0
    fi
    set_bytes=$((dump + archive))
    keep=7
    dir="${PROPOLIS_CC_BACKUP_DIR:-/var/backups/propolis}"
    if [ "$SYSTEMCTL" -eq 1 ]; then
        unit_env="$(sysq show --property=Environment --value propolis-backup.service)"
        for tok in $unit_env; do
            case "$tok" in
                PROPOLIS_BACKUP_KEEP=?*) keep="${tok#*=}" ;; # empty means backup.sh's default
                PROPOLIS_BACKUP_DIR=*) [ -n "${PROPOLIS_CC_BACKUP_DIR:-}" ] || dir="${tok#*=}" ;;
            esac
        done
    fi
    if ! [[ "$keep" =~ ^[0-9]{1,3}$ ]] || [ "$((10#$keep))" -lt 1 ] || [ "$((10#$keep))" -gt 365 ]; then
        return 0
    fi
    keep=$((10#$keep))
    if ! have df; then
        limit "df is not installed: the backup volume's headroom was not checked"
        return 0
    fi
    # The directory is root-only (0750), so a non-root run reads the volume's size from the nearest
    # ancestor it can reach; the sets themselves are measured below, and only as root.
    probe="$dir"
    while [ ! -d "$probe" ] || ! { read -r size avail < <(df --output=size,avail -B1 -- "$probe" 2>/dev/null | tail -n 1); [[ "$size" =~ ^[0-9]{1,18}$ && "$avail" =~ ^[0-9]{1,18}$ ]]; }; do
        [ "$probe" != / ] && [ "$probe" != . ] || { limit "the free space of $dir could not be read: the backup headroom was not checked"; return 0; }
        probe="$(dirname -- "$probe")"
    done
    pct="$(low_disk_pct "$ENV_DIR/propolis.env")"
    # The same arithmetic as backup.sh: the monitor fires strictly below the threshold.
    # shellcheck disable=SC2017 # dividing first is the overflow guard; the remainder is added back
    pct_bytes=$(( size / 100 * pct + (size % 100 * pct + 99) / 100 ))
    keep_free=$pct_bytes
    [ "$keep_free" -ge "$LOGROTATE_RESERVE_BYTES" ] || keep_free="$LOGROTATE_RESERVE_BYTES"
    # What else lives on the volume: everything that is not a set (the database, the logs, the
    # system) is the volume's used space minus the backup directory's. When the directory cannot be
    # measured (this user cannot read it, as for any non-root run of the real 0750 directory) the
    # answer is unknown, not zero: charging only the source size would drop the logs and the rest of
    # the system and stay silent where backup.sh refuses, so this is a limited check, never a pass.
    if used_sets="$(du -s -B1 -- "$dir" 2>/dev/null)" && [[ "${used_sets%%[[:space:]]*}" =~ ^[0-9]{1,18}$ ]]; then
        used_sets="${used_sets%%[[:space:]]*}"
        other=$((size - avail - used_sets))
        [ "$other" -ge 0 ] || other=0
    else
        limit "the backup directory $dir cannot be read as this user: the backup volume's headroom was not checked (run as root)"
        return 0
    fi
    # What backup.sh needs on the night it is tightest: it prunes the scheduled sets to KEEP-1, the
    # 3 pre-upgrade sets may all be present, and the new set is estimated at a fifth over the last.
    sets=$(( (keep > 1 ? keep - 1 : 1) + 3 ))
    need=$((set_bytes + set_bytes / 5))
    total=$((other + sets * set_bytes + need + keep_free))
    if [ "$total" -gt "$size" ]; then
        finding warn "backup" "backup-headroom" "retention cannot fit beside the rest of the volume: before a run of $keep scheduled backups the volume holds $(human_bytes "$other") of other data and $sets sets of about $(human_bytes "$set_bytes") ($(human_bytes $((sets * set_bytes)))), the next set needs $(human_bytes "$need") and the volume must keep $(human_bytes "$keep_free") free (the larger of the ${pct}% low-disk threshold and logrotate's $(human_bytes "$LOGROTATE_RESERVE_BYTES") reserve), which is $(human_bytes "$total") on $dir's $(human_bytes "$size") volume, short by $(human_bytes $((total - size))); backups will start refusing before the volume fills" \
            "lower PROPOLIS_BACKUP_KEEP for propolis-backup.service (sudo systemctl edit propolis-backup.service), or move the backup directory to a larger volume (PROPOLIS_BACKUP_DIR, and its ReadWritePaths in the same drop-in)" manual
        return 1
    fi
    return 0
}

# The nightly backup (deploy/backup.sh): the timer, the age of the last good set and whether sets
# are encrypted. Reads the script's own status files, so it agrees with the daemon's backup-stale.
check_backup() {
    local e a worst=ok parts=() success failure completed epoch age step
    if [ "$SYSTEMCTL" -eq 1 ]; then
        e="$(sysq is-enabled propolis-backup.timer)"
        a="$(sysq is-active propolis-backup.timer)"
        if [ "$a" = active ]; then
            parts+=("timer active")
        else
            worst=fail
            parts+=("timer ${a:-not installed}")
            finding fail "backup" "backup-timer" "propolis-backup.timer is ${a:-not installed}: nothing backs this node up. If the unit is not installed at all, run the upgrade script instead: $(upgrade_fix)" \
                "sudo systemctl enable --now propolis-backup.timer"
        fi
        if [ "$a" = active ] && [ -n "$e" ] && ! { [ "$e" = enabled ] || [ "$e" = enabled-runtime ]; }; then
            if [ "$worst" = ok ]; then worst=warn; fi
            finding warn "backup" "backup-timer-enabled" "propolis-backup.timer is active but $e, so it will not return after a reboot" \
                "sudo systemctl enable propolis-backup.timer"
        fi
    else
        worst=unknown
        parts+=("timer state unknown")
    fi
    success="$(cat -- "$BACKUP_STATUS/last-success" 2>/dev/null || true)"
    failure="$(cat -- "$BACKUP_STATUS/last-failure" 2>/dev/null || true)"
    step="$(printf '%s' "$failure" | sed -n 's/.*"step":"\([^"]*\)".*/\1/p')"
    completed="$(printf '%s' "$success" | sed -n 's/.*"completed_at":"\([^"]*\)".*/\1/p')"
    if [ -n "$completed" ] && epoch="$(date -u -d "$completed" +%s 2>/dev/null)"; then
        age=$((NOW - epoch))
        parts+=("last good backup $(human_age "$age") ago")
        local limit="$BACKUP_STALE_SECS" configured
        configured="$(read_env_var_in PROPOLIS_OPS_BACKUP_MAX_AGE_SECS "$ENV_DIR/propolis.env")"
        # The daemon refuses to start on a value it would not accept, so only an accepted one
        # (whole seconds, at least an hour) can be the limit it is alerting on.
        if [[ "$configured" =~ ^[0-9]{1,9}$ ]] && [ "$configured" -ge 3600 ]; then
            limit="$configured"
        fi
        if [ "$age" -gt "$limit" ]; then
            worst=fail
            finding fail "backup" "backup-stale" "the last good backup is $(human_age "$age") old (the daemon's backup-stale alert fires at $(human_age "$limit"))${step:+; the last run failed while $step}" \
                "sudo systemctl start propolis-backup.service; sudo journalctl -u propolis-backup.service -n 30 --no-pager"
        fi
        if ! backup_headroom "$success"; then
            if [ "$worst" = ok ]; then worst=warn; fi
            parts+=("retention too large for the volume")
        fi
        case "$success" in
            *'"encrypted":false'*)
                if [ "$worst" = ok ]; then worst=warn; fi
                parts+=("plaintext")
                finding warn "backup" "backup-plaintext" "backup sets are not encrypted, so they cannot safely leave this host" \
                    "install age (sudo apt install age) and put your age public key in $ENV_DIR/backup-recipients.txt; see docs/operations/backup-and-restore.md, \"The nightly backup\"" manual
                ;;
        esac
    else
        # A "not configured" record is a run from before DATABASE_URL existed, not a failed
        # backup: reported as never-ran, the same as the daemon's backup-stale reads it.
        if [ -n "$failure" ] && [[ "$step" != "not configured"* ]]; then
            worst=fail
            parts+=("never succeeded")
            finding fail "backup" "backup-failing" "no backup has ever completed${step:+; the last run failed while $step}" \
                "sudo journalctl -u propolis-backup.service -n 30 --no-pager"
        else
            if [ "$worst" = ok ]; then worst=warn; fi
            parts+=("never ran")
            finding warn "backup" "backup-never" "no backup has run on this host yet ($BACKUP_STATUS/last-success does not exist)" \
                "sudo systemctl start propolis-backup.service"
        fi
    fi
    if [ -s "$ENV_DIR/backup-recipients.txt" ] && ! command -v age >/dev/null 2>&1; then
        worst=fail
        finding fail "backup" "backup-age-missing" "$ENV_DIR/backup-recipients.txt names recipients but age is not installed, so every backup fails rather than write plaintext" \
            "install age with your package manager (sudo apt install age on Debian)" manual
    fi
    local text="" p
    for p in "${parts[@]}"; do text="${text:+$text, }$p"; done
    global backup "$worst" "$text"
}

# deploy/backup.sh dumps the database DATABASE_URL in propolis.env names, on whatever host it
# runs, and without one records `not configured` and exits 0. A host that runs no daemon has a
# propolis.env that names no database (propolis_env_configures_no_daemon), so there is no backup
# to judge.
backup_applies() {
    [ -z "$CC_DAEMONLESS" ]
}

# hook_target_shown URL: the scheme and host (with a port) of URL, or `the target` when it is not
# a plain http or https URL. A user name and password before the host, a path (a topic written
# into the URL) and a query (ntfy takes a token there) are never copied out of propolis.env into
# a report. The rule is the library's, so `propolis-status --setup` shows a URL the same way.
hook_target_shown() {
    pa_url_shown "$1"
}

# On a host that runs no daemon, what is left of the alerting check is the failure hook, which
# every unit there names in OnFailure=: the monitor and its heartbeat are settings the daemon
# reads, and their fix lines restart it. The hook (deploy/alert.sh) reads its push target from
# this host's own propolis.env and posts unit failures there whatever the role, so the row says
# where that is.
check_alerting_hook() {
    local file="$ENV_DIR/propolis.env" hook_url="" hook_topic="" where
    CC_LEFT_OUT+=("the daemon's alert monitor and heartbeat")
    if [ -r "$file" ]; then
        hook_url="$(alert_hook_value PROPOLIS_OPS_NTFY_URL "$file")"
        hook_topic="$(alert_hook_value PROPOLIS_OPS_NTFY_TOPIC "$file")"
    fi
    if [ -n "$hook_url" ] && [ -n "$hook_topic" ]; then
        where="it posts unit failures to $(hook_target_shown "$hook_url") (PROPOLIS_OPS_NTFY_* in $file)"
    else
        where="journal only"
    fi
    if [ -x "$ALERT_HOOK" ]; then
        if [ "$where" = "journal only" ]; then
            global alerting ok "failure hook installed (journal only); the daemon's monitor and heartbeat are checked on the control node"
        else
            global alerting ok "failure hook installed; $where; the daemon's monitor and heartbeat are checked on the control node"
        fi
        return 0
    fi
    global alerting fail "failure hook missing; the daemon's monitor and heartbeat are checked on the control node"
    hook_missing
}

# hook_missing: the finding for a missing failure hook, on either path of check_alerting.
hook_missing() {
    local fix kind what="a unit that dies (the daemon included) alerts nobody"
    fix="$(upgrade_fix)" kind="$(fix_kind_checkout)"
    if [ -n "$CC_DAEMONLESS" ]; then
        what="a unit that dies alerts nobody"
    fi
    # A collector has no upgrade script of its own: the written steps install the hook.
    if [ "$CC_DAEMONLESS" = collector ]; then
        fix="install the failure hook as in docs/operations/split-deployment.md, Upgrading" kind=manual
    fi
    finding fail "alerting" "ops-failure-hook" "$ALERT_HOOK is not installed: $what" "$fix" "$kind"
}

# Whether anything reaches the operator when something breaks: the daemon's monitor (off by
# default), a push target for it, the dead-man's switch that covers a dead host, and the
# OnFailure= hook that covers a dead daemon.
check_alerting() {
    local file="$ENV_DIR/propolis.env" enabled url topic heartbeat worst=ok parts=() on=0
    local have missing private hook_url hook_topic hook_push=0 hidden="" indented=1 extra="" v dv hv
    if [ -n "$CC_DAEMONLESS" ]; then
        check_alerting_hook
        return
    fi
    if [ ! -r "$file" ]; then
        global alerting unknown "$file is not readable"
        return
    fi
    enabled="$(read_env_var_in PROPOLIS_OPS_ENABLED "$file")"
    # The daemon gets the two values from systemd, which trims unquoted whitespace, and treats an
    # empty value as unset; `TOPIC=   ` looks set and is not.
    url="$(pa_env_get PROPOLIS_OPS_NTFY_URL "$file")"
    topic="$(pa_env_get PROPOLIS_OPS_NTFY_TOPIC "$file")"
    # The failure hook reads the file itself (deploy/alert.sh env_value), only from lines that
    # start with the name, strips quotes without trimming, and pushes when both raw values are
    # non-empty. It is judged on exactly that, untrimmed, or a quoted space would be taken for
    # a missing value the hook in fact posts with.
    hook_url="$(alert_hook_value PROPOLIS_OPS_NTFY_URL "$file")"
    hook_topic="$(alert_hook_value PROPOLIS_OPS_NTFY_TOPIC "$file")"
    if [ -n "$hook_url" ] && [ -n "$hook_topic" ]; then
        hook_push=1
    fi
    for v in PROPOLIS_OPS_NTFY_URL PROPOLIS_OPS_NTFY_TOPIC; do
        if [ "$v" = PROPOLIS_OPS_NTFY_URL ]; then
            dv="$url" hv="$hook_url"
        else
            dv="$topic" hv="$hook_topic"
        fi
        if [ -n "$url" ] && [ -n "$topic" ] && [ "$hook_push" -eq 0 ] && [ -z "$hv" ]; then
            # The daemon has a push target and the hook lacks this half of it. Indentation is
            # named as the cause only when the file holds the name on an indented line and on
            # no line the hook reads; any other cause gets the plain statement.
            hidden="${hidden:+$hidden and }$v"
            if grep -qE "^$v=" -- "$file" 2>/dev/null || ! grep -qE "^[[:space:]]+$v=" -- "$file" 2>/dev/null; then
                indented=0
            fi
        elif [ "$hook_push" -eq 1 ] && [ -z "$dv" ]; then
            # The hook posts with a value the daemon does not get (unquoted whitespace systemd
            # trims away, or a later indented line that only systemd reads).
            extra="${extra:+$extra and }$v"
        fi
    done
    heartbeat="$(read_env_var_in PROPOLIS_OPS_HEARTBEAT_URL "$file")"
    # The clause deploy/propolis.env.example gives beside the two lines: an open topic leaks the
    # alerts, which say when this host's pipeline is down.
    private="on a server where the topic's read access is restricted to you (where it is not, anyone who knows the topic name can read the alerts)"
    case "$(printf '%s' "$enabled" | tr '[:upper:]' '[:lower:]')" in
        true | 1 | yes | on)
            on=1
            parts+=("monitor on")
            ;;
        *)
            worst=warn
            parts+=("monitor off")
            finding warn "alerting" "ops-monitor-off" "PROPOLIS_OPS_ENABLED is not true in $file: nothing pages when a sensor dies, intake stalls or a backup goes stale (docs/operations/health-and-observability.md)" \
                "set PROPOLIS_OPS_ENABLED=true in $file, then run: sudo systemctl restart propolis" manual
            ;;
    esac
    # Both the daemon (parse_ops_alert) and the failure hook (deploy/alert.sh) push only with the
    # URL and the topic both set. With one of the two, the daemon refuses to start once the monitor
    # is on, and the hook, which needs no monitor, falls back to the journal.
    have=""
    missing=""
    if [ -n "$url" ] && [ -z "$topic" ]; then
        have=PROPOLIS_OPS_NTFY_URL
        missing=PROPOLIS_OPS_NTFY_TOPIC
    elif [ -z "$url" ] && [ -n "$topic" ]; then
        have=PROPOLIS_OPS_NTFY_TOPIC
        missing=PROPOLIS_OPS_NTFY_URL
    fi
    if [ "$hook_push" -eq 1 ] && [ -n "$url" ] && [ -n "$topic" ]; then
        parts+=("ntfy")
    elif [ -n "$missing" ] && [ "$on" -eq 1 ]; then
        worst=fail
        parts+=("push target half set, daemon will not start")
        finding fail "alerting" "ops-push-half" "PROPOLIS_OPS_ENABLED turns the monitor on and $have is set in $file, but $missing is empty: the daemon will not start with this file, because it refuses a push target with only one of the two set" \
            "set $missing in $file, $private, or empty $have to alert to the journal only, then run: sudo systemctl restart propolis" manual
    else
        if [ "$worst" = ok ]; then worst=warn; fi
        if [ -n "$extra" ]; then
            parts+=("ntfy for the failure hook only")
        elif [ -n "$hidden" ] && [ "$on" -eq 1 ]; then
            parts+=("ntfy for the daemon only, failure hook journal only")
        else
            parts+=("journal only")
        fi
        finding warn "alerting" "ops-no-push" "$(if [ -n "$hidden" ]; then
            if [ "$indented" -eq 1 ]; then
                printf 'the value of %s in %s is on an indented line, and the failure hook (deploy/alert.sh) reads only lines that start with the name' "$hidden" "$file"
            else
                printf 'the failure hook (deploy/alert.sh) does not see the value of %s in %s that the daemon gets from systemd (the hook reads the last line that starts with the name and removes up to one double and one single quote from each end of the value, without trimming it)' "$hidden" "$file"
            fi
            printf ': when a unit fails, its alert is written to the journal, where nobody sees it unless they look'
            if [ "$on" -eq 1 ]; then printf ' (the daemon gets the value from systemd and pushes its own alerts)'; fi
        elif [ -n "$extra" ]; then
            printf 'the failure hook (deploy/alert.sh) reads a value for %s in %s and posts its alerts with it when a unit fails, but the daemon, which gets the file from systemd, sees none (systemd trims unquoted whitespace, and takes the last assignment even from a line that does not start with the name)' "$extra" "$file"
            if [ -n "$missing" ]; then printf ': with the monitor turned on, the daemon would refuse to start with this file, because it gets only one of the two'; fi
        elif [ -n "$missing" ]; then
            printf '%s is set in %s, but %s is empty: the failure hook pushes only with both, so its alerts are written to the journal, where nobody sees them unless they look' "$have" "$file" "$missing"
        else
            printf 'no PROPOLIS_OPS_NTFY_URL in %s: alerts are written to the journal, where nobody sees them unless they look' "$file"
        fi)" \
            "$(if [ -n "$hidden" ] && [ "$indented" -eq 1 ]; then
                printf 'remove the whitespace before %s= in %s (the failure hook reads the file each time it runs)' "${hidden// and /= and }" "$file"
            elif [ -n "$hidden" ]; then
                printf 'write %s in %s on one line that starts with the name, with the value right after the =, %s (the failure hook reads the file each time it runs)' "$hidden" "$file" "$private"
            elif [ -n "$extra" ]; then
                printf 'write %s in %s on one line that starts with the name, with the value right after the = (or nothing after it, for alerts to the journal only), %s, then run: sudo systemctl restart propolis' "$extra" "$file" "$private"
            elif [ -n "$missing" ]; then
                printf 'set %s in %s, %s, then run: sudo systemctl restart propolis' "$missing" "$file" "$private"
            else
                printf 'set PROPOLIS_OPS_NTFY_URL and PROPOLIS_OPS_NTFY_TOPIC in %s, %s, then run: sudo systemctl restart propolis' "$file" "$private"
            fi)" manual
    fi
    if [ -n "$heartbeat" ]; then
        parts+=("heartbeat")
    else
        if [ "$worst" = ok ]; then worst=warn; fi
        parts+=("no heartbeat")
        finding warn "alerting" "ops-no-heartbeat" "no PROPOLIS_OPS_HEARTBEAT_URL in $file: if the whole host goes down, nothing tells you" \
            "create a dead-man's switch check (healthchecks.io or your own) and set PROPOLIS_OPS_HEARTBEAT_URL to its ping URL in $file, then run: sudo systemctl restart propolis" manual
    fi
    if [ ! -x "$ALERT_HOOK" ]; then
        worst=fail
        parts+=("failure hook missing")
        hook_missing
    fi
    local text="" p
    for p in "${parts[@]}"; do text="${text:+$text, }$p"; done
    global alerting "$worst" "$text"
}

# Every timestamp Propolis keeps (event times, feed TTLs, backup ages) assumes the clock is right.
check_clock() {
    local synced
    if ! command -v timedatectl >/dev/null 2>&1; then
        global clock unknown "timedatectl is not available"
        return
    fi
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    case "$synced" in
        yes) global clock ok "synchronized" ;;
        no)
            global clock warn "not synchronized"
            finding warn "clock" "clock-unsynced" "the system clock is not NTP-synchronized: event times, feed expiry and backup ages drift with it" \
                "sudo timedatectl set-ntp true"
            ;;
        *) global clock unknown "timedatectl did not report NTPSynchronized" ;;
    esac
}

# The rotation guard (deploy/logrotate-guard.sh) skips a log whose reader has not caught up by
# reading the reader's saved cursor, and rotates anyway when it cannot find one. Each log in the
# intake list therefore needs a cursor file the guard can see: one under the cursor directory, and
# that directory visible to propolis-logrotate.service.
check_cursors() {
    [ "$INTAKE_STATE" = present ] || return 0
    local default_dir var override cdir configured hash lp i checked=0 missing=() worst=ok text
    local reader why look ship=0
    if [ "$INTAKE_VAR" = PROPOLIS_SHIPPER_SENSOR_LOGS ]; then
        ship=1
        reader="the shipper (shipper.service)"
        # A collector: the shipper reads the sensor logs (crates/shipper/src/config.rs). Opening a
        # log saves nothing; a log's first cursor is saved when a ship cycle for it starts reading
        # (crates/shipper/src/client.rs ship_cycle, before any batch is sent), and a cycle runs
        # only after a connection to the gateway and returns at once while another log's batch is
        # in flight. Whether the log can be read or a batch accepted does not decide it. It logs
        # no line per log it opens, but every connect or cycle error carries the log's label as
        # sensor=.
        var=PROPOLIS_SHIPPER_CURSOR_DIR
        default_dir=/var/lib/propolis/shipper/cursors
        why="the shipper saves a log's first cursor when a ship cycle starts reading the log, before it sends anything, so this means no cycle has started for it yet: the shipper is not running, cannot reach the gateway, another log's batch is in flight and this log waits for it, the shipper cannot read or write its state directory or cannot write its cursor directory, or its ship loop has stopped; or it keeps its cursors elsewhere"
    else
        reader=intake
        var=PROPOLIS_CURSOR_DIR
        default_dir=/var/lib/propolis/cursors
        why="intake saves a cursor after its first batch, so this means intake has not read the log, or keeps its cursors elsewhere"
    fi
    configured="$(read_env_var_in "$var" "$INTAKE_FILE")"
    cdir="${PROPOLIS_CC_CURSOR_DIR:-${configured:-$default_dir}}"

    if [ -n "$configured" ] && [ "$configured" != "$default_dir" ]; then
        override="${PROPOLIS_CC_ROTATE_DROPIN_DIR:-/etc/systemd/system/propolis-logrotate.service.d}"
        if ! grep -qsF -- "$configured" "$override"/*.conf 2>/dev/null; then
            worst=warn
            finding warn "logrotate" "cursor-dir-unseen" \
                "$var is $configured in $INTAKE_FILE, but propolis-logrotate.service does not read that file, so the rotation guard looks in $default_dir and, finding no cursor, rotates without checking whether intake has read the log" \
                "create $override/cursor-dir.conf containing [Service] and Environment=$var=$configured, then run: sudo systemctl daemon-reload" manual
        fi
    fi

    if [ -d "$cdir" ]; then
        for ((i = 0; i < ${#IN_PATH[@]}; i++)); do
            lp="${IN_PATH[$i]}"
            case "$lp" in /*) ;; *) continue ;; esac
            # A log that does not exist, or is empty, has had nothing read from it yet.
            [ -s "$lp" ] || continue
            checked=$((checked + 1))
            hash="$(printf '%s' "$(readlink -f -- "$lp" 2>/dev/null || printf '%s' "$lp")" | sha256sum | cut -d' ' -f1)"
            if [ ! -e "$cdir/$hash.json" ]; then
                missing+=("${IN_LABEL[$i]}")
                worst=warn
                if [ "$ship" -eq 1 ]; then
                    look="check that shipper.service is running and shipping this log; its errors name the log as sensor=${IN_LABEL[$i]}: journalctl -u shipper.service -n 30 --no-pager"
                else
                    look="check that intake is running and reading this log: journalctl -u propolis.service -n 30 --no-pager"
                fi
                finding warn "logrotate" "cursor-missing:$lp" \
                    "no cursor file for $lp in $cdir: the rotation guard cannot see how far $reader has read it and rotates it without the unread-input check ($why)" \
                    "$look" manual
            fi
        done
    fi

    if [ "$checked" -eq 0 ] && [ "$worst" = ok ]; then
        global cursors skip "no intake log has content or $cdir does not exist yet"
        return 0
    fi
    text="$checked logs checked in $cdir"
    if [ "${#missing[@]}" -gt 0 ]; then
        text="$text; no cursor for: ${missing[*]}"
    fi
    global cursors "$worst" "$text"
}

INSTALL_BINS=()
load_install_bins() {
    local line list
    line="$(grep -E '^INSTALL_BINS=\(' "$INSTALL_BINS_SRC" 2>/dev/null | head -n 1)" || line=""
    list="${line#INSTALL_BINS=(}"
    list="${list%)}"
    # shellcheck disable=SC2206
    INSTALL_BINS=($list)
}

json_field() {
    local json="$1" key="$2"
    printf '%s' "$json" | sed -n "s/.*\"$key\": \"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

# read_why RC: what a pa_read_as status means, for a limit line.
read_why() {
    case "$1" in
        3) printf 'not a regular file' ;;
        4) printf 'larger than expected' ;;
        5) printf 'not read in time' ;;
        *) printf 'not readable' ;;
    esac
}

# build_differs NAME: whether the build of NAME differs from the installed binary. The checkout
# compares with cmp, as the operator who runs it there. The installed copy, which a root timer
# runs, reads the build as the checkout's owner (the build output is that account's to write) and
# compares digests. 0 differs, 1 same, 2 not compared (a limit line says why).
build_differs() {
    local b="$1" rc=0 build="" installed="" owner
    if [ "$CC_INSTALLED" -eq 0 ]; then
        cmp -s -- "$BUILD_DIR/$b" "$BIN_DIR/$b" && return 1
        return 0
    fi
    owner="$(stat -c %U -- "${REPO_DIR:-$BUILD_DIR}" 2>/dev/null)" || owner=""
    build="$(pa_read_as "$owner" "$BUILD_DIR/$b" 268435456 | sha256sum)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        limit "the build of $b in $BUILD_DIR was not compared with the installed binary: $(read_why "$rc") as ${owner:-its owner}"
        return 2
    fi
    installed="$(sha256sum <"$BIN_DIR/$b" 2>/dev/null)" || installed=""
    if [ -z "$installed" ]; then
        limit "the installed $BIN_DIR/$b could not be read, so it was not compared with the build"
        return 2
    fi
    [ "${build%% *}" != "${installed%% *}" ]
}

# cc_repo_head: sets CC_HEAD to the commit the checkout's HEAD names, read from the files under
# .git as the checkout's owner, and returns 0; or sets CC_HEAD_WHY and returns 1. It runs no git:
# a checkout's .git/config can name commands git runs (core.fsmonitor among them), so git run there
# from a root timer would run the owner's code as root, and run as the owner it would still run
# code the owner controls. Detached heads, loose refs and packed-refs are read; anything else (a
# .git file of a worktree, a link, a ref outside refs/heads) is not guessed at.
cc_repo_head() {
    local owner text="" rc=0 ref loose hex="" line
    local hexre='^([0-9a-f]{40}|[0-9a-f]{64})$' refre='^refs/heads/[A-Za-z0-9._/-]{1,200}$'
    CC_HEAD="" CC_HEAD_WHY=""
    if [ ! -d "$REPO_DIR" ]; then
        CC_HEAD_WHY="checkout not visible from this sandbox: $REPO_DIR"
        return 1
    fi
    # -d follows a link, so a .git that is one is caught by name first.
    if [ -L "$REPO_DIR/.git" ]; then
        CC_HEAD_WHY="$REPO_DIR/.git is a symbolic link"
        return 1
    fi
    if [ ! -d "$REPO_DIR/.git" ]; then
        if [ -e "$REPO_DIR/.git" ]; then
            CC_HEAD_WHY="$REPO_DIR/.git is not a directory, as in a worktree or a submodule"
        else
            CC_HEAD_WHY="$REPO_DIR has no .git directory"
        fi
        return 1
    fi
    owner="$(stat -c %U -- "$REPO_DIR" 2>/dev/null)" || owner=""
    text="$(pa_read_as "$owner" "$REPO_DIR/.git/HEAD" 4096)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        CC_HEAD_WHY=".git/HEAD $(read_why "$rc") as ${owner:-the owner of the checkout}"
        return 1
    fi
    if [[ "$text" =~ $hexre ]]; then
        CC_HEAD="$text"
        return 0
    fi
    ref="${text#ref: }"
    if [ "$ref" = "$text" ] || ! [[ "$ref" =~ $refre ]] || [[ "$ref" == *..* ]]; then
        CC_HEAD_WHY=".git/HEAD holds neither a commit id nor a branch under refs/heads"
        return 1
    fi
    loose="$REPO_DIR/.git/$ref"
    if [ -e "$loose" ] || [ -L "$loose" ]; then
        text="$(pa_read_as "$owner" "$loose" 128)" || rc=$?
        if [ "$rc" -ne 0 ]; then
            CC_HEAD_WHY=".git/$ref $(read_why "$rc") as $owner"
            return 1
        fi
        if [[ "$text" =~ $hexre ]]; then
            CC_HEAD="$text"
            return 0
        fi
        CC_HEAD_WHY=".git/$ref holds no commit id"
        return 1
    fi
    if [ -e "$REPO_DIR/.git/packed-refs" ] || [ -L "$REPO_DIR/.git/packed-refs" ]; then
        text="$(pa_read_as "$owner" "$REPO_DIR/.git/packed-refs" 1048576)" || rc=$?
        if [ "$rc" -ne 0 ]; then
            CC_HEAD_WHY=".git/packed-refs $(read_why "$rc") as $owner"
            return 1
        fi
        while IFS= read -r line; do
            if [ "$line" = "${line%% *} $ref" ] && [[ "${line%% *}" =~ $hexre ]]; then
                hex="${line%% *}"
            fi
        done <<<"$text"
        if [ -n "$hex" ]; then
            CC_HEAD="$hex"
            return 0
        fi
    fi
    CC_HEAD_WHY="the branch $ref is in neither .git/refs nor .git/packed-refs"
    return 1
}

check_binaries() {
    local b missing=() differ=() not_compared=() worst=ok text n=0 unit rc idle=()
    if [ "${#INSTALL_BINS[@]}" -eq 0 ]; then
        global binaries unknown "cannot read INSTALL_BINS from $INSTALL_BINS_SRC"
        limit "binary list unreadable: $INSTALL_BINS_SRC has no INSTALL_BINS line"
        return 0
    fi
    # A collector's hand upgrade builds and installs the binaries its units run and nothing
    # else, so on a host that runs no daemon a binary is compared only where an enabled unit of
    # its name runs it: the daemon's binary and propolis-watch belong to the control node.
    local bfix bkind bhow="the upgrade script builds and installs them"
    bfix="$(upgrade_fix)" bkind="$(fix_kind_checkout)"
    if [ "$CC_DAEMONLESS" = collector ]; then
        bfix="build and install them as in docs/operations/split-deployment.md, Upgrading" bkind=manual
        bhow="the collector's upgrade steps build and install them"
    fi
    for b in "${INSTALL_BINS[@]}"; do
        if [ -n "$CC_DAEMONLESS" ]; then
            probe_unit "$b"
            if ! unit_is_enabled "$b"; then
                idle+=("$b")
                continue
            fi
        fi
        if [ ! -x "$BIN_DIR/$b" ]; then
            case "$b" in
                gateway | shipper)
                    # Role-specific: installed only on the box that runs that role.
                    probe_unit "$b"
                    if [ -z "${U_ENABLED["$b"]}" ]; then
                        continue
                    fi
                    ;;
            esac
            missing+=("$b")
            continue
        fi
        n=$((n + 1))
        if [ -n "$BUILD_DIR" ] && [ -f "$BUILD_DIR/$b" ]; then
            rc=0
            build_differs "$b" || rc=$?
            if [ "$rc" -eq 0 ]; then
                differ+=("$b")
            elif [ "$rc" -eq 2 ]; then
                not_compared+=("$b")
            fi
        fi
    done
    text="$n installed"
    if [ "${#missing[@]}" -gt 0 ]; then
        worst=fail
        text="$text, MISSING: ${missing[*]}"
        finding fail "binaries" "bins-missing" "binaries missing from $BIN_DIR: ${missing[*]} (the units that run them fail to start); $bhow" \
            "$bfix" "$bkind"
    fi
    if [ "${#differ[@]}" -gt 0 ]; then
        if [ "$worst" = ok ]; then worst=warn; fi
        text="$text, differ from $BUILD_DIR: ${differ[*]}"
        finding warn "binaries" "bins-differ" "installed binaries differ from the build in $BUILD_DIR: ${differ[*]} (built but not installed, or the install did not replace them)" \
            "$bfix" "$bkind"
    fi
    # A build that could not be read is not known to match: build_differs gave its limit line.
    if [ "${#not_compared[@]}" -gt 0 ]; then
        if [ "$worst" = ok ]; then worst=unknown; fi
        text="$text, build not compared for: ${not_compared[*]}"
    fi
    # The installed copy that does not know its checkout compared no build at all, which is not a
    # match either. Its limit line says where the checkout was expected.
    if [ "$CC_INSTALLED" -eq 1 ] && [ -z "$BUILD_DIR" ] && [ "$n" -gt 0 ]; then
        if [ "$worst" = ok ]; then worst=unknown; fi
        text="$text, build not compared (checkout unknown)"
    fi
    if [ "${#idle[@]}" -gt 0 ]; then
        text="$text; not compared, as no unit here runs them: ${idle[*]}"
        CC_NOT_HERE+=("the binaries no unit here runs")
    fi
    global binaries "$worst" "$text"

    # The stamp records an install by install.sh or upgrade.sh and the daemon binary's revision.
    # A collector must not run upgrade.sh, and its hand upgrade writes no stamp, so there the
    # stamp only ever describes the first install.
    if [ "$CC_DAEMONLESS" = collector ]; then
        global deploy-stamp skip "not compared here (role collector): the collector's upgrade steps do not write the deploy stamp"
        CC_NOT_HERE+=("the deploy stamp, which the collector's upgrade steps do not write")
        return 0
    fi

    # The deploy stamp: what the last deploy recorded, against the checkout.
    local stamp head installed git_head
    if [ ! -r "$STAMP_FILE" ]; then
        global deploy-stamp warn "$STAMP_FILE not found: no deploy has recorded itself"
        finding warn "deploy-stamp" "stamp-missing" "$STAMP_FILE not found, so the installed version cannot be compared with the checkout" \
            "$(upgrade_fix)" "$(fix_kind_checkout)"
        return 0
    fi
    stamp="$(cat -- "$STAMP_FILE" 2>/dev/null)" || stamp=""
    head="$(json_field "$stamp" head_sha)"
    installed="$(printf '%s' "$stamp" | sed -n 's/.*"installed": {"propolis": "\([^"]*\)".*/\1/p' | head -n 1)"
    worst=ok
    text="deployed head ${head:0:12}"
    if [ -z "$head" ]; then
        worst=warn
        text="stamp has no head_sha"
        finding warn "deploy-stamp" "stamp-nohead" "$STAMP_FILE records no head_sha" "$(upgrade_fix)" "$(fix_kind_checkout)"
    elif [ -z "$installed" ]; then
        worst=warn
        text="$text, installed propolis version not recorded"
        finding warn "deploy-stamp" "stamp-noinstalled" "the stamp records no installed propolis revision (the binary did not answer --version at deploy time)" \
            "$(upgrade_fix)" "$(fix_kind_checkout)"
    else
        case "$head" in
            "${installed%+dirty}"*) text="$text, propolis binary ${installed:0:12}" ;;
            *)
                worst=fail
                text="$text, propolis binary ${installed:0:12} (MISMATCH)"
                finding fail "deploy-stamp" "stamp-mismatch" "the installed propolis binary reports ${installed:0:12} but the deploy built $head: the install did not replace the binary (a first run after a script change re-executes itself; run the upgrade twice if the binary is still old)" \
                    "$(upgrade_fix)" "$(fix_kind_checkout)"
                ;;
        esac
    fi
    if [ -n "$head" ] && [ -z "$REPO_DIR" ]; then
        # The installed copy that does not know its checkout: its limit line has said so, and a
        # stamp that was not compared with a checkout is not known to be current.
        if [ "$worst" = ok ]; then worst=unknown; fi
        text="$text, checkout unknown: stamp-behind not checked"
    elif [ -n "$head" ]; then
        if cc_repo_head; then
            git_head="$CC_HEAD"
            if [ "$git_head" != "$head" ]; then
                if [ "$worst" = ok ]; then worst=warn; fi
                text="$text, checkout is at ${git_head:0:12}"
                finding warn "deploy-stamp" "stamp-behind" "the checkout is at ${git_head:0:12} but the last deploy was ${head:0:12}" \
                    "$(upgrade_fix)" "$(fix_kind_checkout)"
            fi
        else
            if [ "$worst" = ok ]; then worst=unknown; fi
            text="$text, checkout HEAD not read"
            limit "checkout HEAD not readable ($CC_HEAD_WHY): stamp-behind not checked"
        fi
    fi
    global deploy-stamp "$worst" "$text"
}

check_intake_list() {
    local i j worst=ok text="" lp k gsdir="" gsdir_r="" gs_configured=""
    case "$INTAKE_STATE" in
        unreadable)
            global intake-list unknown "propolis.env / shipper.env not readable"
            return 0
            ;;
        missing)
            if [ "$ROW_COUNT" -gt 0 ]; then
                local nfile="$ENV_DIR/propolis.env" nvar=PROPOLIS_SENSOR_LOGS nmsg nfix
                nmsg="PROPOLIS_SENSOR_LOGS is not set in $nfile (nor PROPOLIS_SHIPPER_SENSOR_LOGS in shipper.env): the daemon refuses to start and no sensor log is ingested"
                nfix="set PROPOLIS_SENSOR_LOGS=<label>:<path>,... in $nfile (see deploy/propolis.env.example), then run: $(intake_restart "$nfile")"
                # A collector's list is the shipper's: the daemon's file and unit are not its to fix.
                if [ "$CC_DAEMONLESS" = collector ]; then
                    nfile="$ENV_DIR/shipper.env" nvar=PROPOLIS_SHIPPER_SENSOR_LOGS
                    nmsg="PROPOLIS_SHIPPER_SENSOR_LOGS is not set in $nfile: the shipper has no sensor log to ship"
                    nfix="set PROPOLIS_SHIPPER_SENSOR_LOGS=<label>:<path>,... in $nfile (docs/operations/split-deployment.md, Set up the collector), then run: $(intake_restart "$nfile")"
                fi
                global intake-list fail "no $nvar in $nfile"
                finding fail "intake-list" "intake-none" "$nmsg" "$nfix" manual
            fi
            ;;
        present)
            local n_entries=$(( ${#IN_PATH[@]} + ${#IN_BAD[@]} ))
            text="$INTAKE_VAR: $n_entries entries"
            for ((i = 0; i < ${#IN_BAD[@]}; i++)); do
                worst=fail
                local sug
                sug="$(suggest_entry "${IN_BAD[$i]}" "${IN_BAD_WHY[$i]}")"
                finding fail "intake-list" "intake-bad:${IN_BAD[$i]}" \
                    "$INTAKE_VAR entry '${IN_BAD[$i]}' is malformed (${IN_BAD_WHY[$i]}; expected label:path): the daemon refuses to start" \
                    "edit $INTAKE_FILE${sug:+ and change it to $sug}, then run: $(intake_restart)" manual
            done
            for ((i = 0; i < ${#IN_LABEL[@]}; i++)); do
                for ((j = i + 1; j < ${#IN_LABEL[@]}; j++)); do
                    if [ "${IN_LABEL[$i]}" = "${IN_LABEL[$j]}" ]; then
                        worst=fail
                        finding fail "intake-list" "intake-duplabel:${IN_LABEL[$i]}" \
                            "label '${IN_LABEL[$i]}' appears twice in $INTAKE_VAR (${IN_PATH[$i]} and ${IN_PATH[$j]}): per-log state is keyed by label" \
                            "give each entry a unique label in $INTAKE_FILE, then run: $(intake_restart)" manual
                    elif [ "${IN_PATH[$i]}" = "${IN_PATH[$j]}" ]; then
                        if [ "$worst" = ok ]; then worst=warn; fi
                        finding warn "intake-list" "intake-duppath:${IN_PATH[$i]}" \
                            "path ${IN_PATH[$i]} is listed twice in $INTAKE_VAR (labels ${IN_LABEL[$i]} and ${IN_LABEL[$j]}): every event is read twice" \
                            "remove one of the two entries from $INTAKE_FILE, then run: $(intake_restart)" manual
                    fi
                done
            done
            for ((i = 0; i < ${#IN_PATH[@]}; i++)); do
                lp="${IN_PATH[$i]}"
                case "$lp" in
                    /*) ;;
                    *)
                        if [ "$worst" = ok ]; then worst=warn; fi
                        finding warn "intake-list" "intake-rel:$lp" \
                            "$INTAKE_VAR entry '${IN_LABEL[$i]}:$lp' has a relative path, which resolves against the daemon's working directory" \
                            "use an absolute path in $INTAKE_FILE" manual
                        continue
                        ;;
                esac
                local known=0
                for ((k = 0; k < ROW_COUNT; k++)); do
                    if [ "${R_LOGPATH[$k]}" = "$lp" ]; then known=1; fi
                done
                # A collector's spool on a host that also runs the gateway: the gateway-spool row
                # judges it, and no local sensor writes it, so it is neither an orphan nor a typo.
                # Only where check_gateway_spool gives a row, that is where gateway.env names a
                # spool or the directory exists; elsewhere nothing would report the entry at all.
                # The trailing '/' is stripped as check_gateway_spool strips it, whose
                # spool-unlisted finding then names the slash.
                if [ "$known" -eq 0 ] && [ "$INTAKE_VAR" = PROPOLIS_SENSOR_LOGS ]; then
                    if [ -z "$gsdir" ]; then
                        [ ! -r "$ENV_DIR/gateway.env" ] || gs_configured="$(pa_env_get PROPOLIS_GATEWAY_SPOOL_DIR "$ENV_DIR/gateway.env")"
                        gsdir="${gs_configured:-$GATEWAY_SPOOL_DEFAULT}"
                        gsdir_r="$(readlink -m -- "$gsdir" 2>/dev/null)" || gsdir_r="$gsdir"
                    fi
                    if { [ -n "$gs_configured" ] || [ -d "$gsdir" ]; } \
                        && [ -n "$(spool_id_of "${lp%"${lp##*[!/]}"}" "$gsdir" "$gsdir_r")" ]; then
                        known=1
                    fi
                fi
                if [ "$known" -eq 0 ] && [ "$ROW_COUNT" -gt 0 ] && [ "${#UNREADABLE_ENV[@]}" -eq 0 ]; then
                    if [ ! -e "$lp" ] && [ ! -d "$(dirname -- "$lp")" ] && [ -x "$(dirname -- "$(dirname -- "$lp")")" ]; then
                        worst=fail
                        finding fail "intake-list" "intake-nodir:$lp" \
                            "$INTAKE_VAR entry '${IN_LABEL[$i]}:$lp' names a directory that does not exist, and no configured sensor writes to it (a typo?)" \
                            "correct the path in $INTAKE_FILE (sensors write under /var/log/propolis/<name>/), then run: $(intake_restart)" manual
                    else
                        if [ "$worst" = ok ]; then worst=warn; fi
                        finding warn "intake-list" "intake-orphan:$lp" \
                            "$INTAKE_VAR entry '${IN_LABEL[$i]}:$lp' matches no configured sensor's log path (a typo, or a sensor configured on another host)" \
                            "check the path against the sensor's *_LOG_PATH in $ENV_DIR, or remove the entry from $INTAKE_FILE" manual
                    fi
                fi
            done
            ;;
    esac

    # A variable-name typo: the real name never gets set, and the daemon reads the empty value.
    local hits line name tname file exact
    for file in "${ENV_FILES[@]}"; do
        [ -r "$file" ] || continue
        hits="$(grep -nE '^[[:space:]]*[A-Za-z_]*SENSOR[A-Za-z_]*LOG[A-Za-z_]*[[:space:]]*=' "$file" 2>/dev/null || true)"
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            name="${line#*:}"
            name="${name%%=*}"
            name="${name#"${name%%[![:space:]]*}"}"
            tname="${name%"${name##*[![:space:]]}"}"
            exact=0
            if [ "$name" = "$tname" ] && { [ "$tname" = PROPOLIS_SENSOR_LOGS ] || [ "$tname" = PROPOLIS_SHIPPER_SENSOR_LOGS ]; }; then
                exact=1
            fi
            if [ "$exact" -eq 0 ]; then
                worst=fail
                finding fail "intake-list" "intake-name:$file:$tname" \
                    "$file sets '$name', which is not a variable anything reads (expected PROPOLIS_SENSOR_LOGS, or PROPOLIS_SHIPPER_SENSOR_LOGS on a collector, with no space before '=')" \
                    "rename it to $(case "$file" in */shipper.env) printf PROPOLIS_SHIPPER_SENSOR_LOGS ;; *) printf PROPOLIS_SENSOR_LOGS ;; esac) in $file, then run: $(intake_restart "$file")" manual
            fi
        done <<<"$hits"
    done
    if [ "$INTAKE_STATE" = present ]; then
        global intake-list "$worst" "${text:-present}"
    fi
}

# ---- gateway spool -------------------------------------------------------------------------

# The labels intake binds to one sensor (crates/sensor-wire/src/origin.rs bound_sensor: the name of
# every SENSORS row, and CRED_LABELS). config_check_test.rs holds this list to that file.
SPOOL_BOUND_LABELS="ssh telnet adb redis http ftp smtp tftp mqtt dns catchall vnc mysql mssql postgresql mongodb cred-vnc cred-mysql cred-mssql cred-pg cred-mongo"
# The names the daemon gives its own subsystems (crates/propolis/src/ops_alert/condition.rs
# DAEMON_SUBSYSTEMS). A tailer under one of them shares that subsystem's name in the supervisor,
# and the sensor-down alert never watches it. config_check_test.rs holds this list to that file.
SPOOL_SUBSYSTEM_NAMES="review feed virustotal fetcher console ops-monitor sample-retention listener-probe campaigns"
# Where gateway.service spools when gateway.env leaves PROPOLIS_GATEWAY_SPOOL_DIR unset.
GATEWAY_SPOOL_DEFAULT="${PROPOLIS_CC_GATEWAY_SPOOL_DIR:-/var/spool/propolis/gateway}"
# The most unlisted collectors given a finding each; the rest are counted in the row.
SPOOL_MAX_REPORTED=20
# How long an unlisted spool must have gone unwritten before "read to its end" is taken to mean
# its collector is gone. A capturing sensor writes a stats line every minute, so a collector that
# is still shipping writes its spool far more often than this; a spool written more recently may
# belong to a collector whose entry was removed by mistake, which is the case this check is for.
SPOOL_QUIET_SECS=600

# A spool directory name fit to print: cleaned, and cut at 64 characters, the most a certificate
# CommonName may hold (RFC 5280 ub-common-name), so nothing longer is a collector id anyway.
spool_name() {
    local s
    s="$(clean "$1")"
    if [ "${#s}" -gt 64 ]; then
        s="${s:0:64}..."
    fi
    printf '%s' "$s"
}

# spool_id_of PATH DIR RESOLVED_DIR: the collector id when PATH is DIR/<id>/events.jsonl, else
# nothing. The path is tried as written and canonicalized, so `//`, `./` or a symlinked spool
# directory still match the directory the gateway writes into. A path ending in `/` names no file
# (the daemon's open of `events.jsonl/` fails with ENOTDIR) and readlink -m would drop the slash,
# so such a path lists nothing.
spool_id_of() {
    local path="$1" p base rest
    case "$path" in /*) ;; *) return 0 ;; esac
    case "$path" in */) return 0 ;; esac
    for p in "$(readlink -m -- "$path" 2>/dev/null || true)" "$path"; do
        for base in "$3" "$2"; do
            [ -n "$p" ] && [ -n "$base" ] || continue
            rest="${p#"${base%/}"/}"
            [ "$rest" != "$p" ] || continue
            case "$rest" in
                */*/*) ;;
                ?*/events.jsonl)
                    printf '%s' "${rest%/events.jsonl}"
                    return 0
                    ;;
            esac
        done
    done
}

# spool_bound LABEL: the sensor a log under LABEL is bound to, or nothing for an unbound label.
spool_bound() {
    local w
    for w in $SPOOL_BOUND_LABELS; do
        if [ "$w" = "$1" ]; then
            case "$w" in
                cred-pg) printf 'postgresql' ;;
                cred-mongo) printf 'mongodb' ;;
                cred-*) printf '%s' "${w#cred-}" ;;
                *) printf '%s' "$w" ;;
            esac
            return 0
        fi
    done
}

# spool_subsystem NAME: succeeds when NAME is one of the daemon's own subsystem names.
spool_subsystem() {
    local w
    for w in $SPOOL_SUBSYSTEM_NAMES; do
        [ "$w" != "$1" ] || return 0
    done
    return 1
}

# alert_hook_value NAME FILE: NAME as the failure hook reads it (deploy/alert.sh env_value): the
# last line that starts with NAME= (an indented one is not seen), with a leading and a trailing
# quote removed and no whitespace trimmed. The rule lives in the alert library
# (pa_hook_env_value), where the status command's VERIFIED compares it with the shell senders'
# reading, so the two checks see the same thing the hook does.
alert_hook_value() {
    pa_hook_env_value "$1" "$2"
}

# spool_read_state FILE CURSOR_DIR: how far intake read FILE, from the cursor the daemon keeps for
# it. The cursor is named by the SHA-256 of the file's resolved path, not by its label
# (crates/log-tailer/src/cursor.rs DurableCursor::cursor_file_path), so it outlives the entry that
# listed the file. Prints one of: `end` (read to its current size), `unread N` (N bytes written
# after the cursor), `none` (no cursor in that directory: not read, or the daemon keeps its
# cursors elsewhere), or `unknown REASON`.
#
# The gateway writes the spool and the daemon the cursor, so neither is trusted by this root run:
# the spool file's metadata is read without following a link (the gateway makes none), and the
# cursor is read as propolis, capped and under a timeout, so a FIFO or a link planted in its place
# can neither hang the run nor point it at another file.
spool_read_state() {
    local file="$1" cdir="$2" st rest inode size cur json c_inode c_offset rc=0 who="this user"
    # Tested by the shell, not by stat's %F: coreutils translates that word into the locale's
    # language, and systemd hands a service the host's LANG.
    if [ -L "$file" ]; then
        printf 'unknown %s is a symbolic link' "$file"
        return 0
    fi
    st="$(stat -c '%i %s' -- "$file" 2>/dev/null)" || st=""
    size="${st##* }"
    rest="${st% *}"
    inode="${rest##* }"
    if ! [[ "$inode" =~ ^[0-9]+$ ]] || ! [[ "$size" =~ ^[0-9]+$ ]]; then
        printf 'unknown %s could not be read with stat' "$file"
        return 0
    fi
    if [ ! -d "$cdir" ]; then
        printf 'none'
        return 0
    fi
    if [ ! -x "$cdir" ]; then
        printf 'unknown the cursor directory %s is not readable as this user' "$cdir"
        return 0
    fi
    cur="$cdir/$(printf '%s' "$(readlink -f -- "$file" 2>/dev/null || printf '%s' "$file")" | sha256sum | cut -d' ' -f1).json"
    if [ ! -e "$cur" ] && [ ! -L "$cur" ]; then
        printf 'none'
        return 0
    fi
    json="$(pa_read_as propolis "$cur" 4096)" || rc=$?
    # The account the read ran as, by the library's own rule (_pa_as): propolis under root, where a
    # missing account fails the same way, and the caller otherwise.
    local me="$UID"
    [ -z "${PA_ROOT:-}" ] || me="${PA_TEST_UID:-$UID}"
    if [ "$me" = 0 ] && [ "${PA_TEST_READ_AS_SELF:-}" != 1 ]; then
        who="propolis (or the propolis account is missing)"
    fi
    case "$rc" in
        0) ;;
        3) printf 'unknown its cursor %s is not a regular file' "$cur"; return 0 ;;
        4) printf 'unknown its cursor %s is larger than a cursor' "$cur"; return 0 ;;
        5) printf 'unknown its cursor %s could not be read in time' "$cur"; return 0 ;;
        *) printf 'unknown its cursor %s is not readable as %s' "$cur" "$who"; return 0 ;;
    esac
    c_inode="$(printf '%s' "$json" | sed -n 's/.*"inode":\([0-9][0-9]*\).*/\1/p')"
    c_offset="$(printf '%s' "$json" | sed -n 's/.*"offset":\([0-9][0-9]*\).*/\1/p')"
    if [ -z "$c_inode" ] || [ -z "$c_offset" ]; then
        printf 'unknown its cursor %s has no inode and offset' "$cur"
    elif [ "$c_inode" != "$inode" ]; then
        printf 'unknown its cursor %s is for inode %s, and the file is now inode %s' "$cur" "$c_inode" "$inode"
    elif [ "$c_offset" -gt "$size" ]; then
        printf 'unknown its cursor %s is at byte %s, past the file'"'"'s %s bytes, so the file was emptied after intake read it' "$cur" "$c_offset" "$size"
    elif [ "$c_offset" -eq "$size" ]; then
        printf 'end'
    else
        printf 'unread %s' "$((size - c_offset))"
    fi
}

# On a control plane the gateway accepts, acknowledges and spools every batch a collector ships,
# and the daemon ingests a spool only if PROPOLIS_SENSOR_LOGS lists it. A collector added, renamed
# or rebuilt without that entry has its evidence acknowledged and never ingested, and nothing else
# says so. Only a host with a gateway spool directory is checked; everywhere else this is silent.
check_gateway_spool() {
    local LC_ALL=C
    local genv="$ENV_DIR/gateway.env" penv="$ENV_DIR/propolis.env" configured="" sdir sdir_r
    if [ -e "$genv" ] && [ ! -r "$genv" ]; then
        global gateway-spool unknown "$genv not readable, so the spool directory is unknown"
        limit "gateway spool not checked: $genv is not readable as this user, so where the gateway spools is unknown; run as root"
        return 0
    fi
    if [ -r "$genv" ]; then
        configured="$(pa_env_get PROPOLIS_GATEWAY_SPOOL_DIR "$genv")"
    fi
    sdir="${configured:-$GATEWAY_SPOOL_DEFAULT}"
    if [ -n "$configured" ] && [ ! -d "$sdir" ]; then
        # gateway.env names a spool, so this is a control plane: say the spool was not checked
        # rather than look like a host that has none.
        global gateway-spool unknown "PROPOLIS_GATEWAY_SPOOL_DIR in $genv is $(clean "$sdir"), which is not a directory: no collector has delivered a batch yet, or the path is wrong; collector spools were not checked"
        return 0
    fi
    # No spool directory: a single host or a collector, with nothing here to check.
    [ -d "$sdir" ] || return 0
    if [ ! -r "$sdir" ] || [ ! -x "$sdir" ]; then
        global gateway-spool unknown "$sdir not readable as this user"
        limit "gateway spool not checked: $sdir is not readable as this user, so a collector whose spool PROPOLIS_SENSOR_LOGS does not list would go unseen; run as root"
        return 0
    fi
    if [ -e "$penv" ] && [ ! -r "$penv" ]; then
        global gateway-spool unknown "$penv not readable"
        limit "gateway spool not checked: $penv is not readable as this user, so the spool cannot be compared with PROPOLIS_SENSOR_LOGS; run as root"
        return 0
    fi
    sdir_r="$(readlink -m -- "$sdir" 2>/dev/null)" || sdir_r="$sdir"

    local i id lp label lab sid bound relabel worst=ok n=0 ignored=0 unreadable=0 mislabelled=0
    local d name file st mtime size detail why subsys badname=0 ownid entry rs read lead
    local -a unlisted=() retired=() order=() waiting=()
    local -A listed=() trailing=()
    local restart newid cdir
    restart="sudo systemctl restart propolis.service && $(checkout_cmd watch-env.sh)"
    newid="give this collector a new id (docs/operations/split-deployment.md, Rebuilding a collector) and list $sdir/<new id>/events.jsonl under that id in PROPOLIS_SENSOR_LOGS in $penv, then run: $restart"
    # The daemon's cursor directory, the one check_cursors reads: a spool no entry lists any more
    # still has its cursor there, which tells whether intake read it to its end.
    cdir="${PROPOLIS_CC_CURSOR_DIR:-}"
    if [ -z "$cdir" ]; then
        [ ! -r "$penv" ] || cdir="$(read_env_var_in PROPOLIS_CURSOR_DIR "$penv")"
        cdir="${cdir:-/var/lib/propolis/cursors}"
    fi
    # Only the daemon's own list counts: a shipper.env list is a collector's, not this host's intake.
    if [ "$INTAKE_VAR" = PROPOLIS_SENSOR_LOGS ]; then
        for ((i = 0; i < ${#IN_PATH[@]}; i++)); do
            lp="${IN_PATH[$i]}"
            id="$(spool_id_of "$lp" "$sdir" "$sdir_r")"
            if [ -z "$id" ]; then
                # A spool path written with a trailing '/' lists nothing; remember the entry so
                # the spool's finding can say what is wrong with it.
                case "$lp" in
                    */)
                        id="$(spool_id_of "${lp%"${lp##*[!/]}"}" "$sdir" "$sdir_r")"
                        [ -z "$id" ] || trailing["$id"]="$(clean "${IN_LABEL[$i]}:$lp")"
                        ;;
                esac
                continue
            fi
            [ -n "${listed["$id"]+x}" ] || order+=("$id")
            listed["$id"]=1
            label="${IN_LABEL[$i]}"
            bound="$(spool_bound "$label")"
            subsys=0
            if spool_subsystem "$label"; then subsys=1; fi
            # The collector id as the label is the convention, unless the id itself is a name
            # intake or the daemon treats specially: then relabelling cannot help, only a new id.
            ownid=0
            if [ "$label" = "$id" ]; then
                [ -n "$bound" ] || [ "$subsys" -eq 1 ] || continue
                ownid=1
                badname=$((badname + 1))
            else
                mislabelled=$((mislabelled + 1))
            fi
            lab="$(spool_name "$label")"
            sid="$(spool_name "$id")"
            if [ "$ownid" -eq 1 ] || [ -n "$(spool_bound "$id")" ] || spool_subsystem "$id"; then
                relabel="$newid"
            elif [[ "$id" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
                relabel="in $INTAKE_FILE change the entry to $id:$lp (intake keeps its read position by path, so the new label does not read the spool again), then run: $restart"
            else
                relabel="in $INTAKE_FILE label the entry with the collector id, the spool directory's name, then run: $restart"
            fi
            if [ -n "$bound" ]; then
                worst=fail
                finding fail "gateway-spool" "spool-label-sensor:$lp" \
                    "PROPOLIS_SENSOR_LOGS entry '$lab:$lp' reads collector $sid's spool under the label '$lab', which names a sensor: intake binds the log to $bound alone, so every line in this collector's stream from any other sensor is refused and skipped, and lines already refused are not read again$(if [ "$ownid" -eq 1 ]; then printf '. The label is the collector id, as it should be, so the id itself is the problem: any other label would break the rule that a spool is labelled with its collector id, which also keys the collector'"'"'s capture counters'; fi)" \
                    "$relabel" manual
            elif [ "$subsys" -eq 1 ]; then
                if [ "$worst" = ok ]; then worst=warn; fi
                finding warn "gateway-spool" "spool-label-subsystem:$lp" \
                    "PROPOLIS_SENSOR_LOGS entry '$lab:$lp' reads collector $sid's spool under '$lab', the name of one of the daemon's own subsystems: its events are ingested, but the daemon supervises this tailer under the same name as that subsystem, so the sensor-down alert never watches it and a stop of either can be reported as the other" \
                    "$relabel" manual
            else
                if [ "$worst" = ok ]; then worst=warn; fi
                finding warn "gateway-spool" "spool-label-other:$lp" \
                    "PROPOLIS_SENSOR_LOGS entry '$lab:$lp' reads collector $sid's spool under the label '$lab' instead of its id: its events are still ingested (a label that is not a sensor's name binds the log to no one sensor), but intake's log lines and the sensor-down and intake-stalled alerts for this spool carry '$lab', and the collector's capture counters are stored under '$lab' and published on /metrics as collector=\"$lab\", so they name the wrong collector or none" \
                    "$relabel" manual
            fi
        done
    fi

    for d in "$sdir"/* "$sdir"/.[!.]* "$sdir"/..?*; do
        name="${d##*/}"
        # The gateway makes a collector directory only under a name that is a safe path component
        # (crates/gateway/src/state.rs is_safe_path_component): no control character, no
        # backslash, and it makes no symlinks. Anything else was not made by it and is no id.
        if [ -L "$d" ] || [ ! -d "$d" ]; then
            [ -L "$d" ] && ignored=$((ignored + 1))
            continue
        fi
        if [[ "$name" == *\\* ]] || [[ "$name" =~ [[:cntrl:]] ]]; then
            ignored=$((ignored + 1))
            continue
        fi
        n=$((n + 1))
        [ -z "${listed["$name"]+x}" ] || continue
        if [ ! -x "$d" ]; then
            unreadable=$((unreadable + 1))
            continue
        fi
        file="$d/events.jsonl"
        # A directory with no events file yet holds no evidence to lose.
        [ -f "$file" ] || continue
        sid="$(spool_name "$name")"
        entry="${trailing["$name"]:-}"
        rs="$(spool_read_state "$file" "$cdir")"
        st="$(stat -c '%Y %s' -- "$file" 2>/dev/null)" || st=""
        mtime="${st%% *}"
        size="${st##* }"
        quiet=""
        if [[ "$mtime" =~ ^[0-9]+$ ]]; then quiet=$((NOW - mtime)); fi
        # Read to its end, no longer listed and not written for a while: a collector retired or
        # rebuilt under a new id, whose spool stays until it is moved away. Nothing is lost, so
        # it is only counted. One written a moment ago is not taken for retired: its collector
        # may still be shipping, and its next batch would be acknowledged and never ingested.
        if [ -z "$entry" ] && [ "$rs" = end ] && [ -n "$quiet" ] && [ "$quiet" -ge "$SPOOL_QUIET_SECS" ]; then
            retired+=("$sid (last written $(human_age "$quiet") ago)")
            continue
        fi
        unlisted+=("$sid")
        worst=fail
        [ "${#unlisted[@]}" -le "$SPOOL_MAX_REPORTED" ] || continue
        detail=""
        if [ -n "$quiet" ] && [[ "$size" =~ ^[0-9]+$ ]]; then
            detail=" ($(human_bytes "$size"), last written $(human_age "$quiet") ago)"
        fi
        why=""
        if ! [[ "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
            why="its name is not a plain collector id (letters, digits, '.', '_' and '-', at most 64), so no entry is suggested"
        elif [ -n "$(spool_bound "$name")" ]; then
            why="its name is a sensor's name, which as a label would bind the spool to that one sensor, so no entry is suggested"
        elif spool_subsystem "$name"; then
            why="its name is one the daemon gives one of its own subsystems, which as a label would hide the spool from the sensor-down alert, so no entry is suggested"
        fi
        lead="the gateway is accepting and acknowledging collector $sid's evidence into $sdir/$sid/events.jsonl$detail, but no PROPOLIS_SENSOR_LOGS entry in $penv points at that file, so the daemon is not ingesting it and the collector counts it as delivered."
        case "$rs" in
            none) read=" Intake has no cursor for this file in $cdir: it has not read it, or keeps its cursors elsewhere." ;;
            end)
                if [ -n "$entry" ]; then
                    read=" Intake's cursor shows it read the file to its end before the entry changed, so only what arrives from now on is missed."
                else
                    read=" Intake's cursor shows it read the file to its end, but the file was written within the last $(human_age "$SPOOL_QUIET_SECS"), so the collector may still be shipping and what it sends from now on is not ingested. If the collector was retired or rebuilt under a new id, this finding clears once the file has gone unwritten that long."
                fi
                ;;
            unread\ *)
                read=" Intake read this file before it stopped being listed, and $(human_bytes "${rs#unread }") written to it since are not ingested."
                lead="the gateway accepted and acknowledged collector $sid's evidence into $sdir/$sid/events.jsonl$detail, but no PROPOLIS_SENSOR_LOGS entry in $penv points at that file now, so the daemon is not ingesting what was written after it stopped reading and the collector counts it as delivered."
                ;;
            *) read=" Whether intake read it before it stopped being listed could not be determined: ${rs#unknown }." ;;
        esac
        if [ -n "$entry" ]; then
            read="$read The entry '$entry' ends in '/', which names a directory, so the daemon's open of it fails with 'Not a directory' and it reads nothing."
        fi
        finding fail "gateway-spool" "spool-unlisted:$name" \
            "$lead$read Intake reads a newly listed log from its start (from its saved read position if the path was listed before), so what the file holds is ingested once it is listed${why:+; $why}" \
            "$(if [ -n "$entry" ]; then
                printf "in %s remove the trailing '/' from the entry %s, then run: %s" "$penv" "$entry" "$restart"
            elif [ -z "$why" ]; then
                printf 'append ,%s:%s to PROPOLIS_SENSOR_LOGS in %s, then run: %s' "$name" "$file" "$penv" "$restart"
            else
                printf '%s' "$newid"
            fi)" manual
    done

    if [ "$unreadable" -gt 0 ]; then
        if [ "$worst" = ok ]; then worst=unknown; fi
        limit "gateway spool: $unreadable collector directories under $sdir are not readable as this user and were not checked; run as root"
    fi
    local text="$n collectors in $sdir" shown="" k
    if [ "${#unlisted[@]}" -gt 0 ]; then
        for ((k = 0; k < ${#unlisted[@]} && k < 5; k++)); do shown="${shown:+$shown, }${unlisted[$k]}"; done
        if [ "${#unlisted[@]}" -gt 5 ]; then shown="$shown and $((${#unlisted[@]} - 5)) more"; fi
        text="$text, not in PROPOLIS_SENSOR_LOGS: $shown"
    fi
    if [ "${#retired[@]}" -gt 0 ]; then
        shown=""
        for ((k = 0; k < ${#retired[@]} && k < 3; k++)); do shown="${shown:+$shown, }${retired[$k]}"; done
        if [ "${#retired[@]}" -gt 3 ]; then shown="$shown and $((${#retired[@]} - 3)) more"; fi
        text="$text, ${#retired[@]} read to the end and no longer listed: $shown"
    fi
    if [ "$mislabelled" -gt 0 ]; then
        text="$text, $mislabelled listed under a label that is not the collector id"
    fi
    if [ "$badname" -gt 0 ]; then
        text="$text, $badname listed under an id that is a sensor's or a daemon subsystem's name"
    fi
    if [ "$ignored" -gt 0 ]; then
        text="$text, $ignored entries that are not collector directories ignored"
    fi
    # A listed id with no directory yet is the documented way to add a collector ahead of its
    # first batch, so it is no finding; but a misspelled id looks exactly the same and its real
    # spool would then be reported unlisted, so the row names these ids for the operator to compare.
    for id in "${order[@]}"; do
        [ -e "$sdir/$id" ] || [ -L "$sdir/$id" ] || waiting+=("$(spool_name "$id")")
    done
    if [ "${#waiting[@]}" -gt 0 ]; then
        shown=""
        for ((k = 0; k < ${#waiting[@]} && k < 3; k++)); do shown="${shown:+$shown, }${waiting[$k]}"; done
        if [ "${#waiting[@]}" -gt 3 ]; then shown="$shown and $((${#waiting[@]} - 3)) more"; fi
        text="$text, listed but nothing delivered yet: $shown"
    fi
    global gateway-spool "$worst" "$text"
}

# Whether the watcher's own account can read $1, from the file's owner, group and mode. The
# check's own `-r` test answers for root in practice, and a watch.env at 0600 root:root passes
# it while propolis-watch cannot read the file (live, 2026-10-14).
watcher_can_read() {
    local owner group mode
    read -r owner group mode < <(stat -c '%U %G %a' -- "$1" 2>/dev/null) || return 0
    case "$mode" in '' | *[!0-7]*) return 0 ;; esac
    # The kernel picks ONE class (owner, else group, else other) and applies only its bits, so a
    # file the account owns at 0044 is unreadable to it although group and other can read it.
    if [ "$owner" = "$WATCH_ACCOUNT" ]; then
        [ $(( 8#$mode & 8#400 )) -ne 0 ]
    elif [ "$group" = "$WATCH_ACCOUNT" ]; then
        [ $(( 8#$mode & 8#040 )) -ne 0 ]
    else
        [ $(( 8#$mode & 8#004 )) -ne 0 ]
    fi
}

check_watcher() {
    local installed=0 worst=ok text parts=() src_line watch_line key_file
    # propolis-watch follows the daemon's intake list, which deploy/watch-env.sh copies out of
    # propolis.env into watch.env and does not write without one: on a host that runs no daemon
    # there is no list to watch, and the live watch is set up on the control node.
    if [ -n "$CC_DAEMONLESS" ]; then
        global watcher skip "not checked here (role $(role_word)): propolis-watch follows the daemon's intake list, on the control node"
        CC_LEFT_OUT+=("the live watch (propolis-watch)")
        return 0
    fi
    if [ -x "$BIN_DIR/propolis-watch" ] || id -u propolis-watch >/dev/null 2>&1; then
        installed=1
    fi
    if [ "$installed" -eq 0 ]; then
        global watcher skip "propolis-watch not installed on this host"
        return 0
    fi
    local wenv="$ENV_DIR/watch.env"
    if [ ! -e "$wenv" ]; then
        worst=fail
        parts+=("watch.env missing")
        finding fail "watcher" "watch-env-missing" "$wenv does not exist: propolis-watch has no log list and exits" \
            "$(checkout_fix watch-env.sh)" "$(fix_kind_checkout)"
    elif [ ! -r "$wenv" ]; then
        worst=unknown
        parts+=("watch.env unreadable")
        limit "watch.env not readable as this user"
    elif ! watcher_can_read "$wenv"; then
        worst=fail
        parts+=("watch.env not readable by $WATCH_ACCOUNT")
        finding fail "watcher" "watch-env-owner" "$wenv is not readable by the $WATCH_ACCOUNT account (it must be owned by root, group $WATCH_ACCOUNT, mode 0640): the watcher cannot read its log list and exits" \
            "$(checkout_fix watch-env.sh)" "$(fix_kind_checkout)"
    else
        watch_line="$(grep -E '^PROPOLIS_SENSOR_LOGS=' "$wenv" 2>/dev/null | tail -n 1 || true)"
        if [ -z "$watch_line" ]; then
            worst=fail
            parts+=("watch.env has no PROPOLIS_SENSOR_LOGS")
            finding fail "watcher" "watch-env-empty" "$wenv sets no PROPOLIS_SENSOR_LOGS" "$(checkout_fix watch-env.sh)" "$(fix_kind_checkout)"
        elif [ -r "$ENV_DIR/propolis.env" ]; then
            src_line="$(grep -E '^PROPOLIS_SENSOR_LOGS=' "$ENV_DIR/propolis.env" 2>/dev/null | tail -n 1 || true)"
            if [ "$src_line" = "$watch_line" ]; then
                parts+=("watch.env matches propolis.env")
            else
                worst=fail
                parts+=("watch.env differs from propolis.env")
                finding fail "watcher" "watch-env-drift" "$wenv differs from PROPOLIS_SENSOR_LOGS in propolis.env: the watcher follows a different list than the daemon" \
                    "$(checkout_fix watch-env.sh)" "$(fix_kind_checkout)"
            fi
        else
            parts+=("watch.env present (propolis.env unreadable, drift not checked)")
            worst=unknown
        fi
    fi
    key_file="$WATCH_HOME/.ssh/authorized_keys"
    if [ -s "$key_file" ]; then
        parts+=("authorized key present")
    elif [ -e "$key_file" ]; then
        if [ "$worst" = ok ]; then worst=warn; fi
        parts+=("authorized_keys empty")
        finding warn "watcher" "watch-key-empty" "$key_file is empty: nobody can start the watcher" \
            "install the forced-command key per docs/operations/live-watch.md (template: deploy/watch-authorized-keys.example)" manual
    elif [ -d "$WATCH_HOME" ] && [ ! -x "$WATCH_HOME" ]; then
        parts+=("authorized_keys not readable")
        worst=unknown
        limit "watcher home not traversable as this user"
    else
        if [ "$worst" = ok ]; then worst=warn; fi
        parts+=("no authorized key")
        finding warn "watcher" "watch-key-missing" "$key_file does not exist: nobody can start the watcher" \
            "install the forced-command key per docs/operations/live-watch.md (template: deploy/watch-authorized-keys.example)" manual
    fi
    local p
    text=""
    for p in "${parts[@]}"; do text="${text:+$text, }$p"; done
    global watcher "$worst" "$text"
}

# An enabled or running sensor unit with no bind configured is the fingerprint of a misspelled
# bind variable: the sensor starts, finds nothing to bind and exits or idles.
check_unconfigured_units() {
    local b k have_row worst=ok list=""
    if [ "${#UNREADABLE_ENV[@]}" -gt 0 ]; then
        # An unreadable env file may be exactly the one holding the missing bind: say nothing
        # rather than accuse a sensor of having none.
        global units unknown "cannot tell which units lack a bind: ${#UNREADABLE_ENV[@]} env files unreadable"
        return 0
    fi
    for b in "${INSTALL_BINS[@]}"; do
        case "$b" in sensor-*) ;; *) continue ;; esac
        have_row=0
        for ((k = 0; k < ROW_COUNT; k++)); do
            if [ "${R_UNIT[$k]}" = "$b" ]; then have_row=1; fi
        done
        if [ "$have_row" -eq 1 ]; then continue; fi
        probe_unit "$b"
        if [ "${U_ACTIVE["$b"]}" = unavailable ]; then continue; fi
        if unit_is_enabled "$b" || [ "${U_ACTIVE["$b"]}" = active ]; then
            worst=fail
            list="${list:+$list, }$b"
            finding fail "units" "noconfig:$b" \
                "$b.service is enabled or running but no bind variable is set for it in $ENV_DIR (the sensor has nothing to bind; a misspelled variable name looks like this). List the bind variables the env files do set, compare them with deploy/sensor.env.example, fix the name, then run: sudo systemctl restart $b.service" \
                "sudo grep -H BIND $(q "$ENV_DIR")/*.env"
        fi
    done
    if [ "$worst" = ok ]; then
        global units ok "every enabled or running sensor unit has a configured bind"
    else
        global units "$worst" "enabled with no bind configured: $list"
    fi
}

# The widest mode an env file may have. fleet-listeners.env is generated, secret-free and written
# 0644 (deploy/fleet-listeners.sh); watch.env is written root:propolis-watch 0640 so the watcher's
# account can read its one line (deploy/watch-env.sh); every other env file carries a secret and
# is 0600 (docs/operations/secret-management.md).
# A blanket chmod 0600 over *.env breaks the watcher, which is why the finding text names both
# exceptions: it is the only text an operator reads before running the fix.
env_mode_limit() {
    case "${1##*/}" in
        fleet-listeners.env) printf '644' ;;
        watch.env) printf '640' ;;
        *) printf '600' ;;
    esac
}

# A group or other bit beyond the limit lets another account on the host read a secret. The
# sensor units deny themselves the files by mount, but nothing covers a shell account or an
# unrelated service, and a file's mode can be read without root even where its content cannot.
# A mode stricter than the limit (0400, or 0000 for a file being rotated) is not a finding.
check_env_files() {
    local f mode limit extra loose=() filled=0
    for f in "${ENV_FILES[@]}"; do
        # A file env-files.sh created empty is not configuration, and the two generated files
        # (a copy of one propolis.env line, the listener inventory) are not the operator's. An
        # unreadable file is counted as filled: its content is unknown, and UNREADABLE_ENV
        # already reports that limit.
        case "${f##*/}" in
            watch.env | fleet-listeners.env) ;;
            *)
                if [ ! -r "$f" ] || grep -Eq '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=' -- "$f" 2>/dev/null; then
                    filled=$((filled + 1))
                fi
                ;;
        esac
        mode="$(stat -c %a -- "$f" 2>/dev/null)" || continue
        case "$mode" in '' | *[!0-7]*) continue ;; esac
        limit="$(env_mode_limit "$f")"
        extra=$(( 8#$mode & 8#077 & ~8#$limit ))
        if [ "$extra" -ne 0 ]; then
            loose+=("${f##*/}")
            finding fail "env-files" "env-mode:$f" \
                "$f is mode 0$mode, so accounts other than its owner can read or write it; it must be 0$limit (two files are meant to be wider and must NOT be chmod 0600: watch.env is 0640 root:propolis-watch so the watcher's account can read its one line, and the generated fleet-listeners.env is 0644; every other env file carries a secret: the database URL, the console password, vendor keys, a bind list another sensor need not see)" \
                "sudo chmod 0$limit $(q "$f")"
        fi
    done
    if [ "${#ENV_FILES[@]}" -eq 0 ]; then
        global env-files warn "no *.env files in $ENV_DIR"
        finding warn "env-files" "env-none" "no *.env files in $ENV_DIR: nothing is configured on this host" \
            "copy deploy/sensor.env.example and deploy/propolis.env.example to $ENV_DIR and fill them in (docs/operations/installation.md)" manual
    elif [ "${#loose[@]}" -gt 0 ]; then
        global env-files fail "${#ENV_FILES[@]} env files, readable or writable by other accounts: ${loose[*]}"
    elif [ "${#UNREADABLE_ENV[@]}" -gt 0 ]; then
        global env-files unknown "${#UNREADABLE_ENV[@]} of ${#ENV_FILES[@]} env files unreadable as this user"
    elif [ "$filled" -eq 0 ]; then
        global env-files warn "${#ENV_FILES[@]} env files, none sets anything"
        finding warn "env-files" "env-empty" "no env file in $ENV_DIR sets anything (provisioning creates them empty): nothing is configured on this host" \
            "copy deploy/sensor.env.example and deploy/propolis.env.example over the files in $ENV_DIR and fill them in (docs/operations/installation.md)" manual
    elif [ "$ROW_COUNT" -eq 0 ]; then
        global env-files ok "${#ENV_FILES[@]} env files, no sensor listener configured (a control-plane-only host)"
    else
        global env-files ok "${#ENV_FILES[@]} env files, $ROW_COUNT listeners configured"
    fi
}

# The line systemd's EnvironmentFile= uses for a Propolis setting, in a form the shell readers
# (deploy/alert.sh#env_value, migrate.sh, rollback.sh, backup.sh, listeners-lib.sh#read_env_var_in)
# read differently or not at all: blanks before the name or around '=' (the readers that match
# `^NAME=` miss the line), trailing blanks or a CR (they keep them in the value), a backslash or a
# quote the value does not close (systemd unescapes and joins lines, they do not). The daemon and
# a shell script then act on two different values, and nothing else says so. Only the line
# systemd uses (the last assignment) is judged, and the value is never printed: these files hold
# the database password.
check_env_syntax() {
    local f phys n line t key k v cr forms form msg re='^(DATABASE_URL|PROPOLIS_[A-Z0-9_]+)$'
    local ws=$' \t' found=0 g name before
    local -a order pieces
    local -A at text has_cr
    for f in "${ENV_FILES[@]}"; do
        if [ ! -f "$f" ] || [ ! -r "$f" ]; then
            continue
        fi
        order=()
        at=()
        text=()
        has_cr=()
        n=0
        while IFS= read -r phys || [ -n "$phys" ]; do
            n=$((n + 1))
            pieces=("$phys")
            cr=0
            case "$phys" in
                *$'\r'*)
                    cr=1
                    IFS=$'\r' read -r -a pieces <<<"$phys" || true
                    ;;
            esac
            for line in ${pieces[@]+"${pieces[@]}"}; do
                t="${line#"${line%%[!"$ws"]*}"}"
                case "$t" in
                    '#'* | ';'*) continue ;;
                    *=*) ;;
                    *) continue ;;
                esac
                key="${t%%=*}"
                key="${key%"${key##*[!"$ws"]}"}"
                [[ "$key" =~ $re ]] || continue
                [ -n "${at[$key]+x}" ] || order+=("$key")
                at[$key]="$n"
                text[$key]="$line"
                has_cr[$key]="$cr"
            done
        done <"$f"
        for key in ${order[@]+"${order[@]}"}; do
            pa_env_get "$key" "$f" >/dev/null || true
            line="${text[$key]}"
            t="${line#"${line%%[!"$ws"]*}"}"
            k="${t%%=*}"
            v="${t#*=}"
            forms=""
            if [ "$t" != "$line" ]; then
                forms="blanks before the name"
            fi
            case "$k" in *[$ws]) form=1 ;; *) form=0 ;; esac
            case "$v" in [$ws]*) form=1 ;; esac
            if [ "$form" -eq 1 ]; then
                forms="${forms:+$forms, }blanks around '='"
            fi
            case "$v" in
                *[$ws]) form=1 ;;
                *) form="${has_cr[$key]}" ;;
            esac
            if [ "$form" -eq 1 ]; then
                forms="${forms:+$forms, }trailing blanks or a CR"
            fi
            if [ "${PA_ENV_COMPLEX:-0}" = 1 ]; then
                case "$v" in
                    *[\\\"\']*) forms="${forms:+$forms, }a backslash or an unmatched quote" ;;
                    *) [ "${has_cr[$key]}" = 1 ] || forms="${forms:+$forms, }a line systemd reads as part of the line before it" ;;
                esac
            fi
            [ -n "$forms" ] || continue
            found=$((found + 1))
            msg="line ${at[$key]} of $f sets $key in a form systemd reads one way and the shell scripts read another way or not at all ($forms); the value is not shown"
            # A fix line never names DATABASE_URL (config_check_test.rs#assert_fix_contract).
            if [ "$key" = DATABASE_URL ]; then
                name=NAME before="the name"
            else
                name="$key" before="$key"
            fi
            finding warn "env-files" "env-systemd-only:$f:$key" "$msg" \
                "rewrite line ${at[$key]} of $f as $name=value, with nothing before $before, no blanks around '=', no trailing blanks, no backslash and no unmatched quote" manual
        done
    done
    # The env-files row says what its findings say, as every other row does.
    if [ "$found" -gt 0 ]; then
        for ((g = 0; g < ${#G_ID[@]}; g++)); do
            if [ "${G_ID[$g]}" = env-files ] && [ "${G_LEVEL[$g]}" = ok ]; then
                G_LEVEL[g]=warn
                G_TEXT[g]="${G_TEXT[$g]}; $found settings in a form systemd and the shell scripts read differently"
            fi
        done
    fi
}

# The root witness judges the failure hook's records, watches the units and runs this check on a
# timer. A host where it is missing, or its library is, records nothing and nobody hears about
# it: a collector that never got the witness looks healthy from everywhere else. Two timers run
# it, and either one stopped leaves half of it unrun. The library is the one this run loaded,
# the path its lookup resolved (CC_ALERT_LIB).
check_witness() {
    local b any=0 timers_off="" t e
    for b in "${INSTALL_BINS[@]}"; do
        probe_unit "$b"
        if unit_is_enabled "$b"; then any=1; fi
    done
    if [ "$SYSTEMCTL" -eq 0 ]; then
        global witness unknown "systemctl not found: whether the witness's timers are enabled is unknown"
        return 0
    fi
    if [ "$any" -eq 0 ]; then
        global witness ok "no Propolis unit enabled on this host"
        return 0
    fi
    if [ ! -x "$WITNESS_BIN" ] || [ ! -f "$CC_ALERT_LIB" ]; then
        local what="$WITNESS_BIN is not installed"
        [ -x "$WITNESS_BIN" ] || [ -f "$CC_ALERT_LIB" ] || what="$what, nor its library"
        [ ! -x "$WITNESS_BIN" ] || what="the witness's library $CC_ALERT_LIB is missing"
        global witness warn "$what"
        # A collector has no upgrade script of its own: the written steps install the witness.
        local fix kind
        fix="$(upgrade_fix)" kind="$(fix_kind_checkout)"
        if [ "$CC_ROLE" = collector ]; then
            fix="install the witness as in docs/operations/split-deployment.md, Upgrading" kind=manual
        fi
        finding warn "witness" "witness-missing" "$what, though Propolis units are enabled here: nothing on this host judges a failure, watches the units or runs this check on a timer" "$fix" "$kind"
        return 0
    fi
    for t in propolis-witness@light.timer propolis-witness@hourly.timer; do
        e="$(sysq is-enabled "$t")"
        [ "$e" = enabled ] || timers_off="${timers_off:+$timers_off, }$t ${e:-not installed}"
    done
    if [ -n "$timers_off" ]; then
        global witness warn "timers not enabled: $timers_off"
        finding warn "witness" "witness-timer" "the witness is installed but $timers_off: that pass does not run (the light pass every five minutes, the hourly pass config-check and the anonymous-read check)" \
            "sudo systemctl enable --now propolis-witness@light.timer propolis-witness@hourly.timer"
        return 0
    fi
    if [ ! -d "$PA_RUN" ]; then
        global witness warn "installed, both timers enabled, but $PA_RUN is missing (the tmpfiles entry was not applied; run: sudo systemd-tmpfiles --create /etc/tmpfiles.d/propolis.conf)"
        return 0
    fi
    global witness ok "installed, both timers enabled"
}

# alert_rule_words KEY: the validity rule of a shell sender's setting, in words.
alert_rule_words() {
    case "$1" in
        PROPOLIS_OPS_NTFY_URL) printf 'an http:// or https:// URL with a host and no blanks' ;;
        PROPOLIS_OPS_NTFY_TOPIC) printf '1 to 64 letters, digits, _ or -' ;;
        PROPOLIS_OPS_NTFY_TOKEN) printf '1 to 256 printable characters with no blank' ;;
        PROPOLIS_WITNESS_HEARTBEAT_URL) printf 'an https:// URL with no blanks' ;;
        *) printf 'a valid value' ;;
    esac
}

# The alert channel as the shell senders (the witness, the status command's test page) see it,
# from the alert library's own reading of the settings and the anonymous-read check it stored.
# Nothing here asks the alert server: the check is made by the witness every hour and by
# `propolis-status --setup`, and this script writes nothing, so a request here could not be kept.
# A setting the library ignores as invalid is named (the daemon and today's failure hook still
# use it: they read it their own way), and so is a topic the stored check did not find refusing
# anonymous reads: that is the topic the failure hook posts host and unit names to. A check never
# made for this target reads skip (not made yet, so it leaves the exit status alone); one that is
# stale, got no definite answer or cannot be read is unknown, never ok. On a host that runs no
# daemon the failure hook still posts to this host's target, so both still apply; only the
# daemon's part of the message goes.
check_alert_settings() {
    local file="$ENV_DIR/propolis.env" key src parts=() worst=ok b a cls gate who ac_text="" p text answer never hook_same
    # The library's clock follows this run's (PROPOLIS_CC_NOW), so the stored check's age is
    # counted from the same time as every other age in the report.
    if [[ "${PROPOLIS_CC_NOW:-}" =~ ^[0-9]{1,12}$ ]]; then
        # shellcheck disable=SC2034 # read by the library's pa_now, which this function calls
        local PA_TEST_WALL="$PROPOLIS_CC_NOW" PA_TEST_BOOT=- PA_TEST_UP=0
    fi
    pa_now
    if [ "$IS_ROOT" -eq 0 ]; then
        global alert-channel unknown "alert channel not checked: not root"
        limit "alert channel not checked: /var/lib/propolis/witness is not readable as this user; run as root"
        return 0
    fi
    if [ -e "$file" ] && [ ! -r "$file" ]; then
        global alert-channel unknown "$file is not readable"
        return 0
    fi
    PA_ROLE="$CC_ROLE"
    pa_settings_load
    local -a invalid=()
    read -r -a invalid <<<"${PA_INVALID:-}"
    case "${PA_HB_STATE:-unset}" in
        insecure | invalid) invalid+=(PROPOLIS_WITNESS_HEARTBEAT_URL) ;;
    esac
    for key in "${invalid[@]}"; do
        src="$file"
        # Who ignores the value and who does not: the shell senders read it through the library,
        # while today's failure hook and the daemon read propolis.env their own way and use it as
        # written. The heartbeat URL is the witness's alone, and is read from alert.env too, which
        # wins.
        who="the status command and the witness ignore it, while today's failure hook and the daemon still use it as written"
        [ -z "$CC_DAEMONLESS" ] || who="the status command and the witness ignore it, while today's failure hook still uses it as written"
        if [ "$key" = PROPOLIS_WITNESS_HEARTBEAT_URL ]; then
            pa_env_get "$key" "$file" "$ENV_DIR/$PA_ALERT_ENV_NAME" >/dev/null
            src="${PA_ENV_SRC:-$file}"
            who="the witness ignores it and pings no dead-man check"
        fi
        worst=warn
        parts+=("$key ignored")
        finding warn "alert-channel" "alert-setting-invalid:$key" "$key in $src is not valid ($(alert_rule_words "$key")): $who; see sudo propolis-status --setup" \
            "set $key in $src to $(alert_rule_words "$key"), written plainly on one line" manual
    done
    if [ "$PA_TARGET" != 1 ]; then
        # The hook reads propolis.env its own way: where it finds a URL and a topic it still
        # posts, which is no collector's quiet default.
        pa_hook_differs || true
        if [ -n "$PA_HOOK_URL" ] && [ "$PA_HOOK_TOPIC_SET" = 1 ]; then
            parts+=("no push target for the shell senders; today's failure hook still posts (see sudo propolis-status --setup)")
            for p in "${parts[@]}"; do ac_text="${ac_text:+$ac_text, }$p"; done
            global alert-channel warn "$ac_text"
            return 0
        fi
        if [ "$CC_DAEMONLESS" = collector ] && [ "$worst" = ok ]; then
            global alert-channel ok "no push target (a collector's default: its failure hook writes to the journal)"
            return 0
        fi
        parts+=("no push target")
        for p in "${parts[@]}"; do ac_text="${ac_text:+$ac_text, }$p"; done
        global alert-channel warn "$ac_text"
        return 0
    fi
    # The target the failure hook and the daemon post to (propolis.env), and its stored line.
    pa_state_read readcheck >/dev/null
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" readcheck "* ]]; then
        global alert-channel unknown "the stored anonymous-read check cannot be read"
        limit "anonymous read not checked yet: the stored check cannot be read; the witness checks within the hour, or run sudo propolis-status --setup"
        return 0
    fi
    b="$(pa_readcheck_binding "$PA_D_URL" "$PA_D_TOPIC")" || b=""
    if _pa_rc_line daemon && [ "$PA_RCL_BIND" = "$b" ] && [ "$PA_RCL_DCLASS" != - ] && [ "$PA_RCL_DCLASS" != refused ]; then
        cls="$PA_RCL_DCLASS"
        a="$(pa_age "$PA_RCL_DSTAMP")"
        a="$(if [ "$a" -ge 0 ]; then pa_dur "$a"; else printf 'an unknown time'; fi)"
        # Today's failure hook is named as sending there only where its own reader, which reads
        # propolis.env with a rule of its own, finds this URL and topic.
        hook_same=0
        pa_hook_differs || true
        if [ -n "$PA_HOOK_URL" ] && [ "$PA_HOOK_TOPIC_SET" = 1 ] \
            && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_URL "* ]] \
            && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_TOPIC "* ]]; then
            hook_same=1
        fi
        # Only a readable answer proves that anyone who knows the name reads the alerts; any
        # other answer that is not a refusal proves only that the topic is not proven private.
        if [ "$cls" = readable ]; then
            who="anyone who knows its name reads the alerts, the daemon's titles name this host's software, and today's failure hook sends this host's name and the failed unit (legacy)"
            [ -z "$CC_DAEMONLESS" ] || who="anyone who knows its name reads the alerts, and today's failure hook sends this host's name and the failed unit (legacy)"
            if [ "$hook_same" = 0 ]; then
                who="anyone who knows its name reads the alerts, and the daemon's titles name this host's software"
                [ -z "$CC_DAEMONLESS" ] || who="anyone who knows its name reads what this host pushes there"
            fi
            text="the alert topic answered an anonymous read ($cls, checked $a ago): $who"
            parts+=("topic readable by anyone ($cls)")
        else
            case "$cls" in
                redirect) answer="a redirect" ;;
                not_found) answer="not found (404)" ;;
                not_ntfy) answer="an answer that is not ntfy's" ;;
                *) answer="an answer this check does not know" ;;
            esac
            who="the daemon's titles name this host's software there, and today's failure hook sends this host's name and the failed unit (legacy)"
            [ -z "$CC_DAEMONLESS" ] || who="today's failure hook sends this host's name and the failed unit there (legacy)"
            if [ "$hook_same" = 0 ]; then
                who="the daemon's titles name this host's software there"
                [ -z "$CC_DAEMONLESS" ] || who=""
            fi
            text="the alert topic is not proven private: an anonymous read got $answer ($cls, checked $a ago)${who:+; $who}"
            parts+=("topic not proven private ($cls)")
        fi
        worst=warn
        finding warn "alert-channel" "alert-topic-readable" "$text" \
            "restrict read access to the topic, or move to a topic only you can read, then run: sudo propolis-status --setup" manual
    fi
    gate="$(pa_gate)"
    # Never checked for this target (no stored line, or only one for another target): right
    # after an install, an upgrade or a change of target, before the witness's first hourly pass
    # has stored a check. That is a check not yet made, so the row reads skip and the exit status
    # stays as it was before this row existed; a check that was made and could not answer (stale,
    # no definite answer) stays unknown.
    never=0
    if ! _pa_rc_line shell || [ "$PA_RCL_BIND" != "$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" ]; then
        never=1
    fi
    if [ "$worst" = warn ]; then
        for p in "${parts[@]}"; do ac_text="${ac_text:+$ac_text, }$p"; done
        global alert-channel warn "$ac_text"
    elif [ "$gate" = full ]; then
        global alert-channel ok "the topic refuses anonymous reads (the stored check)"
    elif [ "$never" = 1 ] && { [ "$gate" = pointer:never ] || [ "$gate" = pointer:unbound ]; }; then
        global alert-channel skip "anonymous read never checked for this target: the witness's hourly pass checks it within the hour; sudo propolis-status --setup checks it now"
    else
        case "$gate" in
            pointer:never | pointer:unbound | pointer:stale)
                global alert-channel unknown "anonymous read not checked for the current target (${gate#pointer:})"
                limit "anonymous read not checked yet: the witness checks within the hour, or run sudo propolis-status --setup"
                ;;
            *) global alert-channel warn "the topic is not proven private (${gate#pointer:})" ;;
        esac
    fi
}

# ---- run -----------------------------------------------------------------------------------

load_rotate_size
load_install_bins
detect_firewall
run_events
check_ledger_role

for ((idx = 0; idx < ROW_COUNT; idx++)); do
    check_listener "$idx"
done

check_env_files
check_rotation
if backup_applies; then
    check_backup
else
    global backup skip "not checked here (role $(role_word)): propolis.env names no database for the backup to dump; the control node backs up the daemon's"
    CC_LEFT_OUT+=("the backup of the daemon's database")
fi
check_alerting
check_alert_settings
check_clock
check_binaries
check_intake_list
check_gateway_spool
check_cursors
check_unconfigured_units
check_watcher
check_env_syntax
check_witness

# ---- totals --------------------------------------------------------------------------------

N_FAIL=0
N_WARN=0
for lvl in "${F_LEVEL[@]}"; do
    case "$lvl" in
        fail) N_FAIL=$((N_FAIL + 1)) ;;
        warn) N_WARN=$((N_WARN + 1)) ;;
    esac
done
STATUS=ok
EXIT_CODE=0
if [ "$N_FAIL" -gt 0 ]; then
    STATUS=fail
    EXIT_CODE=2
elif [ "$N_WARN" -gt 0 ] || [ "$UNKNOWN_COUNT" -gt 0 ]; then
    STATUS=warn
    EXIT_CODE=1
fi

row_status() {
    local i="$1" c lvl worst=ok
    for c in "${COLUMNS[@]}"; do
        lvl="$(cell_level "$i" "$c")"
        case "$lvl" in
            fail) worst=fail ;;
            warn) if [ "$worst" != fail ]; then worst=warn; fi ;;
            unknown) if [ "$worst" = ok ]; then worst=unknown; fi ;;
        esac
    done
    printf '%s' "$worst"
}

# ---- output --------------------------------------------------------------------------------

jstr() {
    local s
    s="$(clean "$1")"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '"%s"' "$s"
}

emit_json() {
    local i c sep first
    printf '{"schema":1,"generated_at_epoch":%s,"env_dir":%s,"root":%s,' \
        "$NOW" "$(jstr "$ENV_DIR")" "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)"
    printf '"status":"%s","exit_code":%s,"counts":{"fail":%s,"warn":%s,"unknown":%s},' \
        "$STATUS" "$EXIT_CODE" "$N_FAIL" "$N_WARN" "$UNKNOWN_COUNT"
    printf '"firewall":{"kind":"%s","note":%s},' "$FW_KIND" "$(jstr "$FW_NOTE")"
    printf '"limited":['
    sep=""
    for c in "${LIMITED[@]}"; do
        printf '%s%s' "$sep" "$(jstr "$c")"
        sep=","
    done
    printf '],"listeners":['
    sep=""
    for ((i = 0; i < ROW_COUNT; i++)); do
        printf '%s{"sensor":%s,"protocol":%s,"bind":%s,"port":%s,"unit":%s,"status":"%s","checks":{' \
            "$sep" "$(jstr "${R_SENSOR[$i]}")" "$(jstr "${R_PROTO[$i]}")" "$(jstr "${R_ADDR[$i]}")" \
            "$([ "${R_BADBIND[$i]}" -eq 0 ] && echo "${R_PORT[$i]}" || echo null)" \
            "$(jstr "${R_UNIT[$i]}")" "$(row_status "$i")"
        first=""
        for c in "${COLUMNS[@]}"; do
            printf '%s"%s":{"state":"%s","text":%s}' "$first" "$c" "$(cell_level "$i" "$c")" "$(jstr "$(cell_text "$i" "$c")")"
            first=","
        done
        printf '}}'
        sep=","
    done
    printf '],"global":['
    sep=""
    for ((i = 0; i < ${#G_ID[@]}; i++)); do
        printf '%s{"id":%s,"state":"%s","text":%s}' "$sep" "$(jstr "${G_ID[$i]}")" "${G_LEVEL[$i]}" "$(jstr "${G_TEXT[$i]}")"
        sep=","
    done
    printf '],"findings":['
    sep=""
    for ((i = 0; i < ${#F_LEVEL[@]}; i++)); do
        printf '%s{"level":"%s","id":%s,"scope":%s,"message":%s,"fix":%s,"fix_kind":%s}' \
            "$sep" "${F_LEVEL[$i]}" "$(jstr "${F_ID[$i]}")" "$(jstr "${F_SCOPE[$i]}")" "$(jstr "${F_MSG[$i]}")" \
            "$(jstr "${F_FIX[$i]}")" "$(jstr "${F_KIND[$i]}")"
        sep=","
    done
    printf ']}\n'
}

# tsv_field VALUE: VALUE as one TSV field. clean turns every byte outside space..~, the tab
# included, into '?', so no field can hold a tab or a newline; an empty field is written '-'.
tsv_field() {
    local s
    s="$(clean "$1")"
    printf '%s' "${s:--}"
}

# For the witness, when it comes (a later release): bash with no JSON parser, and a key per finding
# it can hash without the instance part that --json drops. The E line closes the document, so a
# cut-off run is detected.
emit_tsv() {
    local i c k12
    printf '#config-check tsv v1\n'
    printf 'S\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$STATUS" "$EXIT_CODE" "$N_FAIL" "$N_WARN" \
        "$UNKNOWN_COUNT" "$IS_ROOT" "$(tsv_field "$NOW")" "$CC_INSTALLED"
    for ((i = 0; i < ${#G_ID[@]}; i++)); do
        printf 'G\t%s\t%s\t%s\n' "$(tsv_field "${G_ID[$i]}")" "${G_LEVEL[$i]}" "$(tsv_field "${G_TEXT[$i]}")"
    done
    for ((i = 0; i < ROW_COUNT; i++)); do
        printf 'R\t%s\t%s\t%s' "$(tsv_field "${R_SENSOR[$i]}/${R_PROTO[$i]}")" "$(tsv_field "${R_UNIT[$i]}")" "$(row_status "$i")"
        for c in "${COLUMNS[@]}"; do
            printf '\t%s' "$(cell_level "$i" "$c")"
        done
        printf '\n'
    done
    for ((i = 0; i < ${#F_LEVEL[@]}; i++)); do
        k12="$(printf '%s' "${F_KEY[$i]}" | sha256sum 2>/dev/null)" || k12=""
        k12="${k12:0:12}"
        [[ "$k12" =~ ^[0-9a-f]{12}$ ]] || k12=-
        printf 'F\t%s\t%s\t%s\t%s\t%s\t%s\n' "${F_LEVEL[$i]}" "$(tsv_field "${F_ID[$i]}")" "$k12" \
            "$(tsv_field "${F_SCOPE[$i]}")" "${F_KIND[$i]:--}" "$(tsv_field "${F_MSG[$i]}")"
        if [ -n "${F_FIX[$i]}" ]; then
            printf 'X\t%s\n' "$(tsv_field "${F_FIX[$i]}")"
        fi
    done
    for c in "${LIMITED[@]}"; do
        printf 'L\t%s\n' "$(tsv_field "$c")"
    done
    printf 'E\t%s\n' "${#F_LEVEL[@]}"
}

mark() {
    case "$1" in
        ok) printf 'ok' ;;
        warn) printf 'WARN' ;;
        fail) printf 'FAIL' ;;
        unknown) printf '?' ;;
        *) printf '-' ;;
    esac
}

emit_text() {
    local i c w
    local -a widths=(14 4 4 6 8 3 6 6)
    local -a head=("LISTENER" "BIND" "UNIT" "LISTEN" "FIREWALL" "LOG" "INTAKE" "EVENTS")
    local -a vals
    local who="non-root"
    if [ "$IS_ROOT" -eq 1 ]; then who=root; fi
    printf 'Propolis configuration check (env %s, running as %s)\n\n' "$(clean "$ENV_DIR")" "$who"

    if [ "$ROW_COUNT" -gt 0 ]; then
        for ((i = 0; i < ROW_COUNT; i++)); do
            vals=("${R_SENSOR[$i]}/${R_PROTO[$i]}" "${R_ADDR[$i]}" "$(cell_text "$i" unit)" "$(cell_text "$i" listen)" \
                "$(cell_text "$i" firewall)" "$(cell_text "$i" log)" "$(cell_text "$i" intake)" "$(cell_text "$i" events)")
            for ((w = 0; w < 8; w++)); do
                if [ "${#vals[w]}" -gt "${widths[w]}" ]; then widths[w]="${#vals[w]}"; fi
            done
        done
        printf "%-${widths[0]}s  %-${widths[1]}s  %-${widths[2]}s  %-${widths[3]}s  %-${widths[4]}s  %-${widths[5]}s  %-${widths[6]}s  %-${widths[7]}s  %s\n" \
            "${head[@]}" "STATUS"
        for ((i = 0; i < ROW_COUNT; i++)); do
            vals=("${R_SENSOR[$i]}/${R_PROTO[$i]}" "${R_ADDR[$i]}" "$(cell_text "$i" unit)" "$(cell_text "$i" listen)" \
                "$(cell_text "$i" firewall)" "$(cell_text "$i" log)" "$(cell_text "$i" intake)" "$(cell_text "$i" events)")
            printf "%-${widths[0]}s  %-${widths[1]}s  %-${widths[2]}s  %-${widths[3]}s  %-${widths[4]}s  %-${widths[5]}s  %-${widths[6]}s  %-${widths[7]}s  %s\n" \
                "${vals[@]}" "$(mark "$(row_status "$i")")"
        done
        printf '\nfirewall: %s%s\n' "$FW_KIND" "${FW_NOTE:+ ($FW_NOTE)}"
        if [ "$EV_STATE" != ok ]; then
            printf 'events: skipped (%s)\n' "$EV_REASON"
        fi
    else
        printf 'No sensor listeners are configured in %s.\n' "$(clean "$ENV_DIR")"
    fi

    printf '\nHOST\n'
    for ((i = 0; i < ${#G_ID[@]}; i++)); do
        printf '  %-5s %-13s %s\n' "$(mark "${G_LEVEL[$i]}")" "${G_ID[$i]}" "${G_TEXT[$i]}"
    done
    # Said once in words, so a short report on a collector is not read as a clean bill for the
    # checks it did not run.
    # The two lists are kept apart because only the first is checked anywhere: no host compares
    # another's binaries or deploy stamp.
    if [ "${#CC_LEFT_OUT[@]}" -gt 0 ] || [ "${#CC_NOT_HERE[@]}" -gt 0 ]; then
        local left="" none="" part line
        for part in "${CC_LEFT_OUT[@]}"; do left="${left:+$left, }$part"; done
        for part in "${CC_NOT_HERE[@]}"; do none="${none:+$none, }$part"; done
        line="role: $(role_word)"
        if [ -n "$left" ]; then
            line="$line; checked by config-check on the host that runs propolis.service: $left"
        fi
        if [ -n "$none" ]; then
            line="$line; not checked here: $none"
        fi
        printf '\n%s\n' "$line"
    fi

    if [ "${#F_LEVEL[@]}" -gt 0 ]; then
        printf '\nFINDINGS (%s)\n' "${#F_LEVEL[@]}"
        for ((i = 0; i < ${#F_LEVEL[@]}; i++)); do
            printf '  %s  %s: %s\n' "$(mark "${F_LEVEL[$i]}")" "${F_SCOPE[$i]}" "${F_MSG[$i]}"
            if [ -n "${F_FIX[$i]}" ]; then
                if [ "${F_KIND[$i]}" = manual ]; then
                    printf '        do:  %s\n' "${F_FIX[$i]}"
                else
                    printf '        fix: %s\n' "${F_FIX[$i]}"
                fi
            fi
        done
    fi

    if [ "${#LIMITED[@]}" -gt 0 ]; then
        printf '\nLIMITED CHECKS (reported as ?, never as a pass)\n'
        for c in "${LIMITED[@]}"; do
            printf '  - %s\n' "$c"
        done
    fi

    printf '\nSUMMARY: %s failure(s), %s warning(s), %s unknown check(s): %s\n' "$N_FAIL" "$N_WARN" "$UNKNOWN_COUNT" "$STATUS"
}

if [ "$JSON" -eq 1 ]; then
    emit_json
elif [ "$TSV" -eq 1 ]; then
    emit_tsv
else
    emit_text
fi

if [ "$REPORT_ONLY" -eq 1 ]; then
    exit 0
fi
exit "$EXIT_CODE"
