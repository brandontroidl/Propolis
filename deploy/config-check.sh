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
# sensor units with no bind configured, and unreadable env files.
#
# NEVER MUTATES. It writes nothing outside a private temp directory it removes, restarts nothing,
# and changes no firewall rule. Every external tool is optional: a missing one makes its check
# "unknown" and is named under LIMITED CHECKS, never a crash. It does not execute any installed
# binary (an old binary that predates --version would START its service).
#
# WITHOUT ROOT it still runs, with these checks limited: sensor env files are 0600 and owned by
# each sensor's account, so the listener inventory itself may be unreadable; `ss` cannot name a
# socket's owner; ufw and nft cannot list rules; /var/log/propolis/* is not traversable; the
# database URL is unreadable. A check that cannot be answered is reported as unknown ("?"), counts
# as a warning in the exit status, and is listed under LIMITED CHECKS: it is never a pass.
#
# Usage: config-check.sh [--json] [--report-only] [--no-events] [--env-dir DIR] [--newest-event SENSOR]
#   --json         one JSON document on stdout instead of the table
#   --report-only  print the report but always exit 0 (upgrade.sh uses this)
#   --no-events    skip the ledger query
#   --newest-event SENSOR  print when the ledger last saw SENSOR (any age) and exit; the events
#                  findings' fix line, so the database URL never reaches a command line
#   --env-dir DIR  directory holding the env files   (default /etc/propolis)
# Exit status: 0 all ok, 1 warnings or unknown checks, 2 at least one failure, 64 bad usage.
#
# Test seams (all default to the production path; set only by tests): PROPOLIS_CC_NOW (epoch),
# PROPOLIS_CC_EUID, PROPOLIS_CC_BIN_DIR, PROPOLIS_CC_REPO_DIR, PROPOLIS_CC_BUILD_DIR,
# PROPOLIS_CC_STAMP, PROPOLIS_CC_LOGROTATE_STATE, PROPOLIS_CC_LOGROTATE_POLICY,
# PROPOLIS_CC_LOGROTATE_GUARD, PROPOLIS_CC_WATCH_HOME. PROPOLIS_CC_LOG_STALE_HOURS (default 24)
# is the age past which a log on a running sensor is reported as quiet.
#
# The output is plain ASCII: every value read from an env file is passed through `clean` first, so
# a hostile or corrupt file cannot inject terminal escapes or break the JSON.

set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${PROPOLIS_CC_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ENV_DIR=/etc/propolis
JSON=0
REPORT_ONLY=0
NO_EVENTS=0
NEWEST_EVENT=""

usage() {
    echo "usage: $0 [--json] [--report-only] [--no-events] [--env-dir DIR] [--newest-event SENSOR]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --json) JSON=1 ;;
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

# shellcheck source=deploy/listeners-lib.sh
. "$SCRIPT_DIR/listeners-lib.sh"

BIN_DIR="${PROPOLIS_CC_BIN_DIR:-/usr/local/bin}"
BUILD_DIR="${PROPOLIS_CC_BUILD_DIR:-$REPO_DIR/target/release}"
STAMP_FILE="${PROPOLIS_CC_STAMP:-/var/lib/propolis/deploy-stamp.json}"
ROTATE_STATE="${PROPOLIS_CC_LOGROTATE_STATE:-/var/lib/propolis/logrotate.state}"
ROTATE_POLICY="${PROPOLIS_CC_LOGROTATE_POLICY:-/etc/logrotate.d/propolis-sensors}"
ROTATE_GUARD="${PROPOLIS_CC_LOGROTATE_GUARD:-/usr/local/sbin/propolis-logrotate-guard}"
WATCH_HOME="${PROPOLIS_CC_WATCH_HOME:-/var/lib/propolis-watch}"
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
DEFAULT_ROTATE_SIZE=$((100 * 1024 * 1024))

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

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
        t=$((b * 10 / 1073741824))
        printf '%s%sG' $((t / 10)) "$([ $((t % 10)) -eq 0 ] || printf '.%s' $((t % 10)))"
    elif [ "$b" -ge 1048576 ]; then
        t=$((b * 10 / 1048576))
        printf '%s%sM' $((t / 10)) "$([ $((t % 10)) -eq 0 ] || printf '.%s' $((t % 10)))"
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
        return 0
    fi
    F_LEVEL+=("$level")
    F_SCOPE+=("$(clean "$scope")")
    F_MSG+=("$(clean "$msg")")
    F_FIX+=("$(clean "$fix")")
    F_KIND+=("$kind")
    F_ID+=("${key%%:*}")
}

# q VALUE: VALUE shell-quoted for a run line (a path with a space, or a quote, still pastes whole).
q() { printf '%q' "$1"; }

# The upgrade run, by absolute path so it works from any directory.
upgrade_fix() { printf 'sudo %s' "$(q "$SCRIPT_DIR/upgrade.sh")"; }

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

probe_unit() {
    local u="$1" e a
    if [ -n "${U_ACTIVE["$u"]+x}" ]; then
        return 0
    fi
    if [ "$SYSTEMCTL" -eq 0 ]; then
        U_ENABLED["$u"]=unavailable
        U_ACTIVE["$u"]=unavailable
        return 0
    fi
    e="$(sysq is-enabled "$u.service")"
    a="$(sysq is-active "$u.service")"
    # systemd 25x prints "not-found" for a unit with no file; older releases print nothing.
    if [ "$e" = not-found ]; then
        e=""
    fi
    U_ENABLED["$u"]="$e"
    U_ACTIVE["$u"]="${a:-inactive}"
}

unit_is_enabled() {
    case "${U_ENABLED["$1"]}" in
        enabled | enabled-runtime | alias | static | indirect | generated | linked | linked-runtime) return 0 ;;
        *) return 1 ;;
    esac
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
# bad entry makes the daemon refuse to start.
parse_intake() {
    local parts entry name path why
    IFS=',' read -r -a parts <<<"$INTAKE_RAW" || true
    for entry in "${parts[@]}"; do
        entry="$(trim "$entry")"
        [ -n "$entry" ] || continue
        why=""
        case "$entry" in
            *:*)
                name="${entry%%:*}"
                path="${entry#*:}"
                if [ -z "$name" ]; then
                    why="empty label"
                elif [ -z "$path" ]; then
                    why="label with no path"
                fi
                ;;
            *)
                name=""
                path=""
                why="no ':' separator"
                ;;
        esac
        if [ -n "$why" ]; then
            IN_BAD+=("$entry")
            IN_BAD_WHY+=("$why")
        else
            IN_LABEL+=("$name")
            IN_PATH+=("$path")
        fi
    done
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
        finding fail "$unit" "unit-missing:$unit" "$unit.service is not installed but $scope is configured (${R_VAR[$i]})" \
            "sudo install -m 0644 $(q "$ufile") /etc/systemd/system/$unit.service && sudo systemctl daemon-reload && sudo systemctl enable --now $unit.service"
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
                "in $INTAKE_FILE set the entry to $want_label:$lp, then run: sudo systemctl restart propolis.service && sudo $(q "$SCRIPT_DIR/watch-env.sh")" manual
        else
            setcell "$i" intake fail "absent"
            finding fail "$scope" "intake-absent:$lp" \
                "$lp is not in $INTAKE_VAR: events from $sensor are never ingested" \
                "append ,$want_label:$lp to $INTAKE_VAR in $INTAKE_FILE, then run: sudo systemctl restart propolis.service && sudo $(q "$SCRIPT_DIR/watch-env.sh")" manual
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
        finding fail "logrotate" "policy" "$ROTATE_POLICY is not installed" "sudo install -m 0644 $(q "$SCRIPT_DIR/logrotate-sensors.conf") $(q "$ROTATE_POLICY")"
    fi
    if [ ! -x "$ROTATE_GUARD" ]; then
        worst=fail
        parts+=("guard missing")
        finding fail "logrotate" "guard" "$ROTATE_GUARD is not installed or not executable: every rotation fails closed" \
            "sudo install -m 0755 $(q "$SCRIPT_DIR/logrotate-guard.sh") $(q "$ROTATE_GUARD")"
    fi
    local text="" p
    for p in "${parts[@]}"; do text="${text:+$text, }$p"; done
    global logrotate "$worst" "$text (rotation size: $ROTATE_SIZE_NOTE)"
}

# The rotation guard (deploy/logrotate-guard.sh) skips a log whose reader has not caught up by
# reading the reader's saved cursor, and rotates anyway when it cannot find one. Each log in the
# intake list therefore needs a cursor file the guard can see: one under the cursor directory, and
# that directory visible to propolis-logrotate.service.
check_cursors() {
    [ "$INTAKE_STATE" = present ] || return 0
    local default_dir var override cdir configured hash lp i checked=0 missing=() worst=ok text
    if [ "$INTAKE_VAR" = PROPOLIS_SHIPPER_SENSOR_LOGS ]; then
        var=PROPOLIS_SHIPPER_CURSOR_DIR
        default_dir=/var/lib/propolis/shipper/cursors
    else
        var=PROPOLIS_CURSOR_DIR
        default_dir=/var/lib/propolis/cursors
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
                finding warn "logrotate" "cursor-missing:$lp" \
                    "no cursor file for $lp in $cdir: the rotation guard cannot see how far intake has read it and rotates it without the unread-input check (intake saves a cursor after its first batch, so this means intake has not read the log, or keeps its cursors elsewhere)" \
                    "check that intake is running and reading this log: journalctl -u propolis.service -n 30 --no-pager" manual
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
    line="$(grep -E '^INSTALL_BINS=\(' "$SCRIPT_DIR/upgrade.sh" 2>/dev/null | head -n 1)" || line=""
    list="${line#INSTALL_BINS=(}"
    list="${list%)}"
    # shellcheck disable=SC2206
    INSTALL_BINS=($list)
}

json_field() {
    local json="$1" key="$2"
    printf '%s' "$json" | sed -n "s/.*\"$key\": \"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

check_binaries() {
    local b missing=() differ=() worst=ok text n=0 unit
    if [ "${#INSTALL_BINS[@]}" -eq 0 ]; then
        global binaries unknown "cannot read INSTALL_BINS from $SCRIPT_DIR/upgrade.sh"
        limit "binary list unreadable: $SCRIPT_DIR/upgrade.sh has no INSTALL_BINS line"
        return 0
    fi
    for b in "${INSTALL_BINS[@]}"; do
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
        if [ -f "$BUILD_DIR/$b" ] && ! cmp -s -- "$BUILD_DIR/$b" "$BIN_DIR/$b"; then
            differ+=("$b")
        fi
    done
    text="$n installed"
    if [ "${#missing[@]}" -gt 0 ]; then
        worst=fail
        text="$text, MISSING: ${missing[*]}"
        finding fail "binaries" "bins-missing" "binaries missing from $BIN_DIR: ${missing[*]} (the units that run them fail to start); the upgrade script builds and installs them" \
            "$(upgrade_fix)"
    fi
    if [ "${#differ[@]}" -gt 0 ]; then
        if [ "$worst" = ok ]; then worst=warn; fi
        text="$text, differ from $BUILD_DIR: ${differ[*]}"
        finding warn "binaries" "bins-differ" "installed binaries differ from the build in $BUILD_DIR: ${differ[*]} (built but not installed, or the install did not replace them)" \
            "$(upgrade_fix)"
    fi
    global binaries "$worst" "$text"

    # The deploy stamp: what the last deploy recorded, against the checkout.
    local stamp head installed git_head
    if [ ! -r "$STAMP_FILE" ]; then
        global deploy-stamp warn "$STAMP_FILE not found: no deploy has recorded itself"
        finding warn "deploy-stamp" "stamp-missing" "$STAMP_FILE not found, so the installed version cannot be compared with the checkout" \
            "$(upgrade_fix)"
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
        finding warn "deploy-stamp" "stamp-nohead" "$STAMP_FILE records no head_sha" "$(upgrade_fix)"
    elif [ -z "$installed" ]; then
        worst=warn
        text="$text, installed propolis version not recorded"
        finding warn "deploy-stamp" "stamp-noinstalled" "the stamp records no installed propolis revision (the binary did not answer --version at deploy time)" \
            "$(upgrade_fix)"
    else
        case "$head" in
            "${installed%+dirty}"*) text="$text, propolis binary ${installed:0:12}" ;;
            *)
                worst=fail
                text="$text, propolis binary ${installed:0:12} (MISMATCH)"
                finding fail "deploy-stamp" "stamp-mismatch" "the installed propolis binary reports ${installed:0:12} but the deploy built $head: the install did not replace the binary (a first run after a script change re-executes itself; run the upgrade twice if the binary is still old)" \
                    "$(upgrade_fix)"
                ;;
        esac
    fi
    if have git; then
        git_head="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)" || git_head=""
        if [ -n "$git_head" ] && [ -n "$head" ] && [ "$git_head" != "$head" ]; then
            if [ "$worst" = ok ]; then worst=warn; fi
            text="$text, checkout is at ${git_head:0:12}"
            finding warn "deploy-stamp" "stamp-behind" "the checkout is at ${git_head:0:12} but the last deploy was ${head:0:12}" \
                "$(upgrade_fix)"
        fi
    fi
    global deploy-stamp "$worst" "$text"
}

check_intake_list() {
    local i j worst=ok text="" lp k
    case "$INTAKE_STATE" in
        unreadable)
            global intake-list unknown "propolis.env / shipper.env not readable"
            return 0
            ;;
        missing)
            if [ "$ROW_COUNT" -gt 0 ]; then
                global intake-list fail "no PROPOLIS_SENSOR_LOGS in $ENV_DIR/propolis.env"
                finding fail "intake-list" "intake-none" "PROPOLIS_SENSOR_LOGS is not set in $ENV_DIR/propolis.env (nor PROPOLIS_SHIPPER_SENSOR_LOGS in shipper.env): the daemon refuses to start and no sensor log is ingested" \
                    "set PROPOLIS_SENSOR_LOGS=<label>:<path>,... in $ENV_DIR/propolis.env (see deploy/propolis.env.example), then run: sudo systemctl restart propolis.service" manual
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
                    "edit $INTAKE_FILE${sug:+ and change it to $sug}, then run: sudo systemctl restart propolis.service" manual
            done
            for ((i = 0; i < ${#IN_LABEL[@]}; i++)); do
                for ((j = i + 1; j < ${#IN_LABEL[@]}; j++)); do
                    if [ "${IN_LABEL[$i]}" = "${IN_LABEL[$j]}" ]; then
                        worst=fail
                        finding fail "intake-list" "intake-duplabel:${IN_LABEL[$i]}" \
                            "label '${IN_LABEL[$i]}' appears twice in $INTAKE_VAR (${IN_PATH[$i]} and ${IN_PATH[$j]}): per-log state is keyed by label" \
                            "give each entry a unique label in $INTAKE_FILE, then run: sudo systemctl restart propolis.service" manual
                    elif [ "${IN_PATH[$i]}" = "${IN_PATH[$j]}" ]; then
                        if [ "$worst" = ok ]; then worst=warn; fi
                        finding warn "intake-list" "intake-duppath:${IN_PATH[$i]}" \
                            "path ${IN_PATH[$i]} is listed twice in $INTAKE_VAR (labels ${IN_LABEL[$i]} and ${IN_LABEL[$j]}): every event is read twice" \
                            "remove one of the two entries from $INTAKE_FILE, then run: sudo systemctl restart propolis.service" manual
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
                if [ "$known" -eq 0 ] && [ "$ROW_COUNT" -gt 0 ] && [ "${#UNREADABLE_ENV[@]}" -eq 0 ]; then
                    if [ ! -e "$lp" ] && [ ! -d "$(dirname -- "$lp")" ] && [ -x "$(dirname -- "$(dirname -- "$lp")")" ]; then
                        worst=fail
                        finding fail "intake-list" "intake-nodir:$lp" \
                            "$INTAKE_VAR entry '${IN_LABEL[$i]}:$lp' names a directory that does not exist, and no configured sensor writes to it (a typo?)" \
                            "correct the path in $INTAKE_FILE (sensors write under /var/log/propolis/<name>/), then run: sudo systemctl restart propolis.service" manual
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
                    "rename it to PROPOLIS_SENSOR_LOGS in $file, then run: sudo systemctl restart propolis.service" manual
            fi
        done <<<"$hits"
    done
    if [ "$INTAKE_STATE" = present ]; then
        global intake-list "$worst" "${text:-present}"
    fi
}

check_watcher() {
    local installed=0 worst=ok text parts=() src_line watch_line key_file
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
            "sudo $(q "$SCRIPT_DIR/watch-env.sh")"
    elif [ ! -r "$wenv" ]; then
        worst=unknown
        parts+=("watch.env unreadable")
        limit "watch.env not readable as this user"
    else
        watch_line="$(grep -E '^PROPOLIS_SENSOR_LOGS=' "$wenv" 2>/dev/null | tail -n 1 || true)"
        if [ -z "$watch_line" ]; then
            worst=fail
            parts+=("watch.env has no PROPOLIS_SENSOR_LOGS")
            finding fail "watcher" "watch-env-empty" "$wenv sets no PROPOLIS_SENSOR_LOGS" "sudo $(q "$SCRIPT_DIR/watch-env.sh")"
        elif [ -r "$ENV_DIR/propolis.env" ]; then
            src_line="$(grep -E '^PROPOLIS_SENSOR_LOGS=' "$ENV_DIR/propolis.env" 2>/dev/null | tail -n 1 || true)"
            if [ "$src_line" = "$watch_line" ]; then
                parts+=("watch.env matches propolis.env")
            else
                worst=fail
                parts+=("watch.env differs from propolis.env")
                finding fail "watcher" "watch-env-drift" "$wenv differs from PROPOLIS_SENSOR_LOGS in propolis.env: the watcher follows a different list than the daemon" \
                    "sudo $(q "$SCRIPT_DIR/watch-env.sh")"
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

check_env_files() {
    if [ "${#ENV_FILES[@]}" -eq 0 ]; then
        global env-files warn "no *.env files in $ENV_DIR"
        finding warn "env-files" "env-none" "no *.env files in $ENV_DIR: nothing is configured on this host" \
            "copy deploy/sensor.env.example and deploy/propolis.env.example to $ENV_DIR and fill them in (docs/operations/installation.md)" manual
    elif [ "${#UNREADABLE_ENV[@]}" -gt 0 ]; then
        global env-files unknown "${#UNREADABLE_ENV[@]} of ${#ENV_FILES[@]} env files unreadable as this user"
    elif [ "$ROW_COUNT" -eq 0 ]; then
        global env-files ok "${#ENV_FILES[@]} env files, no sensor listener configured (a control-plane-only host)"
    else
        global env-files ok "${#ENV_FILES[@]} env files, $ROW_COUNT listeners configured"
    fi
}

# ---- run -----------------------------------------------------------------------------------

load_rotate_size
load_install_bins
detect_firewall
run_events

for ((idx = 0; idx < ROW_COUNT; idx++)); do
    check_listener "$idx"
done

check_env_files
check_rotation
check_binaries
check_intake_list
check_cursors
check_unconfigured_units
check_watcher

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
else
    emit_text
fi

if [ "$REPORT_ONLY" -eq 1 ]; then
    exit 0
fi
exit "$EXIT_CODE"
