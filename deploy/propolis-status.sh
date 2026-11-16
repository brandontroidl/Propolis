#!/usr/bin/env bash
#
# Where is the pipeline broken, and why: the walk an operator runs as root during an incident.
# Installed as /usr/local/sbin/propolis-status by deploy/install.sh and deploy/upgrade.sh.
#
#   propolis-status           every stage in order (listen, source, ship, gateway, intake, ledger,
#                             review, reports, feed, publish) with its last progress, the first one
#                             that stopped marked `>`, then the rails beside them (alert, backup,
#                             chain, host, monitor, witness, peers), the incidents the witness has
#                             open (or, on a host where no witness pass has run, the failures the
#                             failure hook recorded) with their causes and what today's hook did
#                             with each, the installed config-check's findings, and the next thing
#                             to look at
#   propolis-status STAGE     one stage or rail with everything behind its row
#   propolis-status --setup   what reaches the operator and why: this host's name on the channel,
#                             the push target (never its topic or token), the anonymous-read
#                             check run now and its answer in words, what the daemon and today's
#                             failure hook still reveal, the heartbeat URL, and VERIFIED
#   propolis-status --test-page
#                             one test page through the failure-alert unit (at most 3 in 24 h):
#                             it proves that unit, the network and the target as the library
#                             reads it; VERIFIED also needs today's hook to read the same values
#   propolis-status --ack-test CODE
#                             the code the test page carried, typed back: VERIFIED
#   propolis-status --banner  the login banner's text, as the witness would write it
#   propolis-status --maint MINUTES
#                             announce planned work: unit, collector and database kinds are held
#                             for MINUTES (1 to 120); 0 ends it, whoever started it
#   propolis-status -h        this text (any user)
#
# THE WALK IS READ-ONLY. It writes nothing: no state file, no lock, no temporary file except the
# header file that carries the console's metrics token to curl, which its one EXIT handler
# removes. --banner only prints. --setup, --test-page and --ack-test write only the readcheck,
# testpage and send-ledger files and the id salt, each under the state lock (10 s at most, else
# exit 75), then the banner; the anonymous-read check of --setup is made before the lock is
# taken, and the test page is sent by the failure-alert unit, never by this command, which only
# starts that unit. --maint writes the maintenance marker
# (/run/propolis-witness/maintenance) and then the banner, and nothing else; it takes no lock, so
# it works while a hung writer holds the state lock. The walk takes no lock either, so it shows
# the state files as the last writer left them. Every program it runs is
# bounded in time (systemctl, journalctl and timedatectl 10 s, each database probe 10 s,
# config-check 120 s, the console 5 s), so a broken host still gets an answer. The only network it
# touches is the console on loopback, asked only while the daemon runs, and the database
# DATABASE_URL names (local or remote) through `propolis pg-exec`.
#
# WHAT IT TRUSTS. It sources the alert library (/usr/local/sbin/propolis-alert-lib) and runs the
# daemon binary and the installed config-check only after checking that each, and every directory
# above it, is owned by root and writable by no one else. Env files are parsed, never sourced.
# Files another account can write (cursors, spool entries, the feed manifest, sensor logs) are
# read as that account with a size cap and a time limit through the library, or listed with
# `find -printf`, never followed. Names found there are printed only when they are plain ids, in
# braces; raw text (journal lines, psql errors) appears only in a stage view, cleaned of every
# byte outside printable ASCII and marked [untrusted]. It never prints the ntfy token or topic, a
# database URL or a password.
#
# WHAT IT CANNOT SEE. Only the witness judges the failure hook's records: until one of its passes
# has completed on the host (meta light_last), they are listed as recent failures and never
# change the exit status. The daemon's own causes, whether the ledger accepts writes, and the
# chain verdict live in daemon memory; the rows say so instead of guessing. A check it cannot make
# is `?` with the reason, never ok.
#
# Exit status of the walk and a stage view: 0 nothing stopped and nothing to look at; 1 a WARN or
# `?` anywhere, or an open ACT incident; 2 a stage is marked stopped, a rail is FAIL, or a PAGE
# incident is open. --banner: 0. --maint: 0 written or removed, 1 it could not be. --setup: 0 only
# when the gate is full, else 1. --test-page: 0 when the page went out (ok), else 1. --ack-test: 0
# when the code was the waiting one or was acknowledged already, else 1. Any form: 3 not root; 64 bad
# usage; 70 the alert library is missing, not trusted, or older than this script needs; 75 the
# state lock was not free within 10 s (the three verbs above).
#
# Test seams (honoured only with PROPOLIS_STATUS_ROOT set; tests only): PROPOLIS_STATUS_ROOT puts
# every path under that directory and keeps the caller's PATH, so stubs win; PROPOLIS_STATUS_EUID
# stands for the effective uid; PROPOLIS_STATUS_NOW is the time, as epoch seconds or as a
# WALL/BOOT/UP stamp; PROPOLIS_STATUS_CC is the config-check to run and PROPOLIS_STATUS_CC_LIMIT
# its time limit in seconds.
#
# The library version this script needs; deploy/rollback.sh reads the line below.
# needs-alert-lib: 9

umask 077
STATUS_SELF="${BASH_SOURCE[0]}"
STATUS_NEEDS_LIB=0
while IFS= read -r status_line; do
    case "$status_line" in
        '# needs-alert-lib: '*)
            STATUS_NEEDS_LIB="${status_line#'# needs-alert-lib: '}"
            break
            ;;
    esac
done < "$STATUS_SELF"
unset status_line
cd / || exit 70
export LC_ALL=C TZ=UTC
IFS=$' \t\n'
set -uo pipefail

STATUS_ROOT="${PROPOLIS_STATUS_ROOT:-}"
if [ -z "$STATUS_ROOT" ]; then
    # The system's directories first: a program put under /usr/local can then never stand in for
    # a system tool this script runs by name, on a host where /usr/local is writable by a group.
    PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
    export PATH
    # The library's own time and privilege seams must not reach a production run either.
    unset PA_TEST_WALL PA_TEST_BOOT PA_TEST_UP PA_TEST_READ_AS_SELF PA_TEST_UID PA_TEST_PROFILE
    unset PROPOLIS_STATUS_EUID PROPOLIS_STATUS_NOW PROPOLIS_STATUS_CC PROPOLIS_STATUS_CC_LIMIT
    # mktemp then uses /tmp: the curl config files of --setup hold the topic and the token, and a
    # caller's TMPDIR (sudo -E, a root shell with a user's environment) may be a directory another
    # account can write, where that account could swap a file for a link before it is written.
    unset TMPDIR
fi

STATUS_STAGES="listen source ship gateway intake ledger review reports feed publish"
STATUS_RAILS="alert backup chain host monitor witness peers"

usage() {
    cat << 'EOF'
usage: propolis-status                  the walk: every stage in order, the first stopped one marked >
       propolis-status STAGE            one stage or rail with everything behind its row
       propolis-status --setup          what reaches you and why; runs the anonymous-read check now
       propolis-status --test-page      send one test page through the failure-alert unit
       propolis-status --ack-test CODE  confirm the test page arrived (CODE is the one it carries)
       propolis-status --banner         print the login banner text
       propolis-status --maint MINUTES  hold unit, collector and database kinds for planned work
                                        (1 to 120 minutes; 0 ends it)
       propolis-status -h               this text
STAGE is one of: listen source ship gateway intake ledger review reports feed publish
                 alert backup chain host monitor witness peers
Run as root: sudo propolis-status
EOF
}

VIEW="" VERB="" MAINT_MINUTES="" ACK_CODE=""
if [ "$#" -eq 2 ] && [ "$1" = --ack-test ]; then
    # Checked here, before any file is read: the code reaches a comparison and nothing else.
    if [[ $2 =~ ^[0-9a-f]{6}$ ]]; then
        VERB=ack-test ACK_CODE="$2"
    else
        echo "propolis-status: --ack-test takes the 6-character code the test page carries (0-9, a-f)" >&2
        usage >&2
        exit 64
    fi
elif [ "$#" -eq 2 ] && [ "$1" = --maint ]; then
    # Digits only and read as decimal: `08` is eight minutes, and nothing else reaches the
    # arithmetic.
    if [[ $2 =~ ^[0-9]{1,3}$ ]] && [ "$((10#$2))" -le 120 ]; then
        VERB=maint MAINT_MINUTES="$((10#$2))"
    else
        echo "propolis-status: --maint takes the minutes to hold, 0 to 120" >&2
        usage >&2
        exit 64
    fi
elif [ "$#" -gt 1 ]; then
    echo "propolis-status: one form per call" >&2
    usage >&2
    exit 64
elif [ "$#" -eq 1 ]; then
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        --banner) VERB=banner ;;
        --setup) VERB=setup ;;
        --test-page) VERB=test-page ;;
        --maint)
            echo "propolis-status: --maint takes the minutes to hold, 0 to 120" >&2
            usage >&2
            exit 64
            ;;
        --ack-test)
            echo "propolis-status: --ack-test takes the 6-character code the test page carries (0-9, a-f)" >&2
            usage >&2
            exit 64
            ;;
    esac
fi
if [ "$#" -eq 1 ] && [ -z "$VERB" ]; then
    # One lowercase word first: a blank inside the argument would otherwise match across two names.
    [[ $1 =~ ^[a-z]{1,16}$ ]] && status_arg="$1" || status_arg="-"
    case " $STATUS_STAGES $STATUS_RAILS " in
        *" $status_arg "*) VIEW="$1" ;;
        *)
            echo "propolis-status: not a stage or rail: $(printf '%s' "$1" | tr -c ' -~' '?' | cut -b 1-40)" >&2
            usage >&2
            exit 64
            ;;
    esac
fi

if [ "${PROPOLIS_STATUS_EUID:-$EUID}" != 0 ]; then
    echo "propolis-status needs root: run sudo propolis-status" >&2
    exit 3
fi

# ---- the alert library ----------------------------------------------------------------------

status_no_library() {
    echo "propolis-status: $1" >&2
    exit 70
}

# status_trust_one PATH OWNER: PATH owned by OWNER and writable by no one else.
status_trust_one() {
    local u a o g
    if ! read -r u a o g < <(timeout 5 stat -c '%u %a %U %G' -- "$1" 2> /dev/null); then
        STATUS_UNTRUSTED="$1: cannot be checked"
        return 1
    fi
    if [ "$u" != "$2" ]; then
        STATUS_UNTRUSTED="$1: not owned by root ($o:$g $a)"
    elif ((8#$a & 8#020)); then
        STATUS_UNTRUSTED="$1: group-writable ($o:$g $a)"
    elif ((8#$a & 8#002)); then
        STATUS_UNTRUSTED="$1: world-writable ($o:$g $a)"
    else
        return 0
    fi
    return 1
}

# status_trust_dir DIR OWNER TOP: DIR passes status_trust_one; under a test root (TOP) the
# directories above that root are the test's surroundings and pass unchecked.
status_trust_dir() {
    local above="${1%/}"
    if [ -n "$3" ]; then
        case "$3" in "$above"/*) return 0 ;; esac
    fi
    status_trust_one "$1" "$2"
}

# status_trust FILE: the check the library's pa_trusted_exec makes, done here before the library
# itself is sourced, the same way: FILE is a regular file, not a link, and it and every directory
# passed through to reach it belong to root and are writable by no one else. FILE is resolved one
# component at a time, as the kernel resolves it, and a link among the directories is followed
# and checked where it leads, so the directory holding each link is checked too. Whoever can
# write one of them could replace what root is about to run. STATUS_MISSING is 1 when FILE is not
# there at all, which wants a reinstall, not a chmod.
status_trust() {
    local path="$1" owner=0 top="" cur=/ rest comp entry target hops=0
    STATUS_UNTRUSTED="" STATUS_MISSING=0
    if [ -n "$STATUS_ROOT" ]; then
        top="$(cd -P -- "$STATUS_ROOT" 2> /dev/null && pwd -P)" || {
            STATUS_UNTRUSTED="$STATUS_ROOT: missing"
            return 1
        }
        owner="$(timeout 5 stat -c %u -- "$top" 2> /dev/null)" || owner=0
    fi
    if [ -L "$path" ]; then
        STATUS_UNTRUSTED="$path: a symbolic link"
        return 1
    fi
    if [ ! -f "$path" ]; then
        [ -e "$path" ] || STATUS_MISSING=1
        STATUS_UNTRUSTED="$path: missing or not a regular file"
        return 1
    fi
    rest="${path#/}"
    if [ -n "$top" ]; then
        case "$path" in "${STATUS_ROOT%/}"/*) cur="$top" rest="${path#"${STATUS_ROOT%/}"/}" ;; esac
    fi
    status_trust_dir "$cur" "$owner" "$top" || return 1
    while [ -n "$rest" ]; do
        comp="${rest%%/*}"
        case "$rest" in
            */*) rest="${rest#*/}" ;;
            *) rest="" ;;
        esac
        case "$comp" in
            '' | .) continue ;;
            ..) cur="$(dirname -- "$cur")" ;;
            *)
                entry="${cur%/}/$comp"
                if [ -L "$entry" ]; then
                    hops=$((hops + 1))
                    if [ -z "$rest" ]; then
                        STATUS_UNTRUSTED="$entry: a symbolic link"
                        return 1
                    fi
                    if [ "$hops" -gt 40 ] || ! target="$(readlink -- "$entry")"; then
                        STATUS_UNTRUSTED="$entry: too many levels of symbolic links"
                        return 1
                    fi
                    case "$target" in /*) cur=/ ;; esac
                    rest="${target#/}/$rest"
                elif [ -d "$entry" ]; then
                    cur="$entry"
                elif [ -z "$rest" ] && [ -f "$entry" ]; then
                    status_trust_one "$entry" "$owner"
                    return
                else
                    STATUS_UNTRUSTED="$entry: not a regular file"
                    return 1
                fi
                ;;
        esac
        status_trust_dir "$cur" "$owner" "$top" || return 1
    done
    STATUS_UNTRUSTED="$path: not a regular file"
    return 1
}

STATUS_FIX="fix: sudo chmod g-w,o-w the directory named, for example sudo chmod g-w /usr/local/sbin /usr/local/bin /usr/local/lib/propolis (or remove /etc/staff-group-for-usr-local)"
STATUS_LIB="$STATUS_ROOT/usr/local/sbin/propolis-alert-lib"
STATUS_LIB_FAIL="alert library not found, failing to load, or older than version $STATUS_NEEDS_LIB at /usr/local/sbin/propolis-alert-lib; reinstall it from the checkout: sudo install -m 0644 deploy/alert-lib.sh /usr/local/sbin/propolis-alert-lib"
if ! status_trust "$STATUS_LIB"; then
    [ "$STATUS_MISSING" = 0 ] || status_no_library "$STATUS_LIB_FAIL"
    status_no_library "alert library not trusted: $STATUS_UNTRUSTED; $STATUS_FIX"
fi
# Whatever an older or foreign file leaves behind must not read as a version or a function.
PA_LIB_VERSION=""
STATUS_LIB_FUNCS="pa_init pa_env_get pa_settings_load pa_role pa_alias pa_id_table pa_plain_id
pa_ok_field pa_clean_untrusted pa_now pa_age pa_dur pa_hms pa_read_as pa_stat_as pa_trusted_exec
pa_state_read pa_maint_active pa_pg pa_push_scheduler pa_sensor_logs pa_unit_map pa_cleanup
pa_banner pa_banner_write pa_maint_write pa_gate pa_readcheck_binding pa_vol_project pa_vol_judge
pa_vol_stores pa_lock pa_unlock pa_salt_ensure pa_state_write pa_readcheck_run pa_readcheck_merge
pa_url_shown pa_token8 pa_budget_admit pa_ledger_add pa_testpage_write pa_verified pa_hook_env_value
pa_hook_differs pa_budget_next"
# shellcheck disable=SC2086 # the list is a fixed set of names
unset -f $STATUS_LIB_FUNCS
# Loaded once in a subshell first: under set -u an unbound variable at the library's top level
# ends the shell that sources it, and an exit there ends it with the library's status, so either
# would end this run with no word instead of the exit 70 promised for an unusable library.
# shellcheck source=deploy/alert-lib.sh
if [ "$(. "$STATUS_LIB" > /dev/null 2>&1 && echo loaded)" != loaded ]; then
    status_no_library "$STATUS_LIB_FAIL"
fi
set +u
# shellcheck source=deploy/alert-lib.sh
if ! . "$STATUS_LIB" 2> /dev/null; then
    set -u
    status_no_library "$STATUS_LIB_FAIL"
fi
set -u
# shellcheck disable=SC2086 # the list is a fixed set of names
if ! [[ $PA_LIB_VERSION =~ ^[0-9]{1,9}$ && $STATUS_NEEDS_LIB =~ ^[0-9]{1,9}$ ]] \
    || [ "$((10#$PA_LIB_VERSION))" -lt "$((10#$STATUS_NEEDS_LIB))" ] \
    || ! declare -F $STATUS_LIB_FUNCS > /dev/null; then
    status_no_library "$STATUS_LIB_FAIL"
fi
trap 'pa_cleanup' EXIT
pa_init "$STATUS_ROOT"
# The library's own check, which also resolves every link on the way, now that it is loaded.
if ! pa_trusted_exec "$STATUS_LIB"; then
    status_no_library "alert library not trusted: $PA_UNTRUSTED; $STATUS_FIX"
fi

if [ -n "$STATUS_ROOT" ] && [ -n "${PROPOLIS_STATUS_NOW:-}" ]; then
    if [[ $PROPOLIS_STATUS_NOW =~ ^([0-9]{1,12})/([0-9a-f]{8})/([0-9]{1,10})$ ]]; then
        export PA_TEST_WALL="${BASH_REMATCH[1]}" PA_TEST_BOOT="${BASH_REMATCH[2]}" PA_TEST_UP="${BASH_REMATCH[3]}"
    elif [[ $PROPOLIS_STATUS_NOW =~ ^[0-9]{1,12}$ ]]; then
        export PA_TEST_WALL="$PROPOLIS_STATUS_NOW" PA_TEST_BOOT=- PA_TEST_UP=0
    fi
fi
pa_now
PA_PG_APP=propolis-status

# Every program that asks the system something has a time limit, the library's calls included:
# these names shadow the programs for the library's functions too.
systemctl() { timeout 10 systemctl "$@"; }
journalctl() { timeout 10 journalctl "$@"; }
hostname() { timeout 5 hostname "$@"; }

# ---- small helpers --------------------------------------------------------------------------

# fmt_time WALL: HH:MM:SS on the current UTC date, MM-DD HH:MM before it, `-` when unknown.
fmt_time() {
    local w="${1:-}"
    if ! [[ $w =~ ^[0-9]{1,12}$ ]]; then
        printf -- '-'
        return 0
    fi
    if [ "$(date -u -d "@$w" +%F 2> /dev/null)" = "$(date -u -d "@$PA_WALL" +%F 2> /dev/null)" ]; then
        date -u -d "@$w" +%H:%M:%S 2> /dev/null || printf '?'
    else
        date -u -d "@$w" '+%m-%d %H:%M' 2> /dev/null || printf '?'
    fi
}

# fmt_age SECONDS: `6 s` under a minute, else pa_dur's words; `-` when unknown or in the future.
fmt_age() {
    local s="${1:-}"
    if ! [[ $s =~ ^[0-9]{1,12}$ ]]; then
        printf -- '-'
    elif [ "$s" -lt 60 ]; then
        printf '%s s' "$s"
    else
        pa_dur "$s"
    fi
}

# age_of WALL: seconds since WALL, `-` when unknown or in the future.
age_of() {
    if [[ ${1:-} =~ ^[0-9]{1,12}$ ]] && [ "$((PA_WALL - 10#$1))" -ge 0 ]; then
        printf '%s' "$((PA_WALL - 10#$1))"
    else
        printf -- '-'
    fi
}

# human_bytes N: 812 B, 3.4 KiB, 2.1 MiB, 1.0 GiB.
human_bytes() {
    local b="${1:-}" suffix t
    [[ $b =~ ^[0-9]{1,18}$ ]] || {
        printf '?'
        return 0
    }
    if [ "$b" -lt 1024 ]; then
        printf '%s B' "$b"
        return 0
    fi
    for suffix in KiB MiB GiB TiB; do
        t=$((b * 10 / 1024))
        b=$((b / 1024))
        if [ "$b" -lt 1024 ] || [ "$suffix" = TiB ]; then
            printf '%s.%s %s' "$((t / 10))" "$((t % 10))" "$suffix"
            return 0
        fi
    done
}

# braced NAME: {NAME} when it is a plain id, {?} otherwise (counted in WITHHELD).
WITHHELD=0
braced() {
    if pa_plain_id "${1:-}"; then
        printf '{%s}' "$1"
    else
        WITHHELD=$((WITHHELD + 1))
        printf '{?}'
    fi
}

# env_of KEY FILE...: sets ENV_V to KEY's value as systemd would load the files, and ENV_BAD to
# the first file that exists and cannot be read.
env_of() {
    pa_env_get "$@" > /dev/null
    ENV_V="$PA_ENV_VALUE" ENV_BAD="$PA_ENV_UNREADABLE"
}

# unit_show UNIT PROP...: sets U_<prop> for each, read through systemctl show with the time in
# UTC; 1 when systemctl did not answer. The properties any caller asks for:
U_ActiveState="" U_SubState="" U_Result="" U_NRestarts="" U_ActiveEnterTimestamp=""
U_UnitFileState="" U_InvocationID="" U_ExecMainStatus="" U_NextElapseUSecRealtime=""
U_LastTriggerUSec=""
unit_show() {
    local unit="$1" k v out
    shift
    for k in "$@"; do printf -v "U_$k" '%s' ""; done
    out="$(systemctl show "--property=$(
        IFS=,
        printf '%s' "$*"
    )" -- "$unit" 2> /dev/null)" || return 1
    while IFS='=' read -r k v; do
        case " $* " in *" $k "*) printf -v "U_$k" '%s' "$(printf '%s' "$v" | tr -c ' -~' '?')" ;; esac
    done <<< "$out"
    return 0
}

# unit_up: the last unit_show says the unit is running (starting counts; an automatic restart
# after a crash does not).
unit_up() {
    case "${U_ActiveState:-}" in
        active | reloading) return 0 ;;
        activating) [ "${U_SubState:-}" != auto-restart ] ;;
        *) return 1 ;;
    esac
}

# ts_epoch TEXT: epoch seconds of a systemd timestamp printed in UTC ("Thu 2026-11-12 08:02:11
# UTC"), nothing when it is not one.
ts_epoch() {
    local t="${1:-}"
    [[ $t =~ ([0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}) ]] || return 0
    date -u -d "${BASH_REMATCH[1]}" +%s 2> /dev/null || true
}

# json_int TEXT KEY: the integer after "KEY": in TEXT, nothing when there is none. Printed as a
# plain decimal: these files are written by less privileged accounts, and a number kept with its
# leading zeros (`08`) would be taken for a bad octal one by the arithmetic that uses it, an
# error that ends the script.
json_int() {
    [[ ${1:-} =~ \"$2\"[[:space:]]*:[[:space:]]*([0-9]{1,18}) ]] && printf '%s' "$((10#${BASH_REMATCH[1]}))"
    return 0
}

# json_str TEXT KEY: the plain string value of "KEY" in TEXT (no escapes), nothing otherwise.
json_str() {
    [[ ${1:-} =~ \"$2\"[[:space:]]*:[[:space:]]*\"([^\"\\]{0,200})\" ]] && printf '%s' "${BASH_REMATCH[1]}"
    return 0
}

# root_read FILE MAX: FILE's first MAX bytes when it is a regular file, not a link, in a
# directory only root writes; nothing and 1 otherwise.
root_read() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    timeout 5 head -c "$2" -- "$1" 2> /dev/null | tr -d '\000'
}

# file_facts PATH: sets F_TYPE (regular, missing, other or unknown), F_SIZE, F_MTIME and F_INODE
# from stat without following a link.
file_facts() {
    local out
    F_TYPE=unknown F_SIZE="" F_MTIME="" F_INODE=""
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        F_TYPE=missing
        return 0
    fi
    out="$(timeout 5 stat -c '%F|%s|%Y|%i' -- "$1" 2> /dev/null)" || return 0
    IFS='|' read -r F_TYPE F_SIZE F_MTIME F_INODE <<< "$out"
    case "$F_TYPE" in
        'regular file' | 'regular empty file') F_TYPE=regular ;;
        *) F_TYPE=other ;;
    esac
}

# cursor_name PATH: the cursor file name the log tailer uses for PATH, the SHA-256 of the path
# resolved as crates/log-tailer/src/cursor.rs canonical_key resolves it.
cursor_name() {
    local key h
    key="$(timeout 5 readlink -f -- "$1" 2> /dev/null)" || key=""
    [ -n "$key" ] || key="$1"
    h="$(printf '%s' "$key" | sha256sum)"
    printf '%s.json' "${h%% *}"
}

read_why() {
    case "${1:-}" in
        3) printf 'not a regular file' ;;
        4) printf 'too large' ;;
        5) printf 'timed out' ;;
        6) printf 'not readable' ;;
        *) printf 'cannot be read' ;;
    esac
}

# ---- what the host is -----------------------------------------------------------------------

PROPOLIS_ENV="$PA_ENV_DIR/propolis.env"
FLEET_ENV="$PA_ENV_DIR/fleet-listeners.env"
SHIPPER_ENV="$PA_ENV_DIR/shipper.env"
GATEWAY_ENV="$PA_ENV_DIR/gateway.env"

ROLE="$(pa_role)"
case "$ROLE" in
    single | control | collector | gateway) ;;
    *) ROLE=unknown ;;
esac
HAS_DAEMON=1
case "$ROLE" in collector | gateway) HAS_DAEMON=0 ;; esac
# The banner tells a collector, which has no push target by design.
PA_ROLE="$ROLE"

# ---- the verbs ------------------------------------------------------------------------------

# status_banner: --banner, the login banner's text from the state files, as the witness writes
# it. It only prints.
status_banner() {
    pa_banner
    exit 0
}

# status_maint MINUTES: --maint, planned work announced: the maintenance marker for MINUTES with
# reason manual (0 removes any marker), then the banner, which shows it. No lock: the marker is
# not a state file, and this must work while a hung writer holds the lock.
status_maint() {
    local rc=0
    pa_maint_write manual "$1" || rc=$?
    if [ "$rc" != 0 ]; then
        echo "propolis-status: the maintenance marker could not be written in /run/propolis-witness (is the directory there? sudo systemd-tmpfiles --create /etc/tmpfiles.d/propolis.conf)" >&2
        exit 1
    fi
    if [ "$1" = 0 ]; then
        printf 'maintenance ended\n'
    else
        printf 'maintenance until %s UTC: unit, collector and database kinds held on this host\n' "$(pa_hms "$PA_MAINT_UNTIL")"
    fi
    pa_banner_write || echo "propolis-status: the login banner was not rewritten (/run/motd.d is missing or refused the write)" >&2
    exit 0
}

# status_lock: the state lock within 10 s, or the verb ends: 75 when another writer holds it, 1
# when neither lock file can be opened.
status_lock() {
    local rc=0
    pa_lock 10 || rc=$?
    case "$rc" in
        0) return 0 ;;
        1)
            echo "propolis-status: the state lock is busy; try again" >&2
            exit 75
            ;;
        *)
            echo "propolis-status: the state lock cannot be opened (/var/lib/propolis/witness/state.lock or /run/propolis-witness/state.lock; provisioning makes them)" >&2
            exit 1
            ;;
    esac
}

# verified_words: what pa_verified says of the shell path, and `daemon not verified` where the
# daemon is enabled: no test page goes through the daemon's own sender, which read its settings
# when it started and may hold an older topic or token. The caller has loaded the settings.
verified_words() {
    local v
    v="$(pa_verified)"
    case "$v" in VERIFIED*) v+=" (shell)" ;; esac
    case "$ROLE" in single | control) v+="; daemon not verified" ;; esac
    printf '%s' "$v"
}

# hook_posts: whether today's failure hook posts while the shell senders have no target: its own
# reader (pa_hook_differs) finds a URL and a topic where the library finds none, whatever the
# reason (a value the library ignores as invalid, or a later line the hook never sees). Sets
# HOOK_POSTS (1 or 0) and the PA_HOOK_* facts. The caller has run pa_settings_load.
hook_posts() {
    HOOK_POSTS=0
    pa_hook_differs || true
    if [ "$PA_TARGET" != 1 ] && [ -n "$PA_HOOK_URL" ] && [ "$PA_HOOK_TOPIC_SET" = 1 ]; then
        HOOK_POSTS=1
    fi
}

# hook_diff_words: how the shell senders read the settings today's failure hook reads otherwise
# (PA_HOOK_DIFF, from hook_posts): `ignore KEY as invalid`, `read KEY otherwise`, or both.
hook_diff_words() {
    local k inv="" oth=""
    for k in $PA_HOOK_DIFF; do
        case " ${PA_INVALID:-} " in
            *" $k "*) inv+="${inv:+ and }$k" ;;
            *) oth+="${oth:+ and }$k" ;;
        esac
    done
    printf '%s%s%s' "${inv:+ignore $inv as invalid}" "${inv:+${oth:+ and }}" "${oth:+read $oth otherwise}"
}

# hook_fix: the fix while today's failure hook reads the push settings otherwise: the rule of the
# URL or topic the shell senders ignore as invalid, else to write the settings plainly, the one
# form both readings agree on, else the rule of the token they ignore as invalid: written plainly,
# a value that breaks its rule is still ignored.
hook_fix() {
    local k inv="" plain=0
    for k in $PA_HOOK_DIFF; do
        case " ${PA_INVALID:-} " in
            *" $k "*)
                case "$k" in
                    PROPOLIS_OPS_NTFY_URL | PROPOLIS_OPS_NTFY_TOPIC)
                        printf 'Set %s in /etc/propolis/propolis.env to %s, written plainly on one line' "$k" "$(setting_rule "$k")"
                        return 0
                        ;;
                    *) [ -n "$inv" ] || inv="$k" ;;
                esac
                ;;
            *) plain=1 ;;
        esac
    done
    if [ -n "$inv" ] && [ "$plain" = 0 ]; then
        printf 'Set %s in /etc/propolis/propolis.env to %s, written plainly on one line' "$inv" "$(setting_rule "$inv")"
        return 0
    fi
    printf 'Write each push setting in /etc/propolis/propolis.env as KEY=value at the start of its line, with no blank or comment'
}

# hook_diff_why: each setting of PA_HOOK_DIFF by why it differs, for --ack-test: `the shell
# senders ignore KEY as invalid; set KEY to <rule>` for one in PA_INVALID, and `today's failure
# hook reads KEY otherwise` for the rest, joined with `; `.
hook_diff_why() {
    local k out="" oth=""
    for k in $PA_HOOK_DIFF; do
        case " ${PA_INVALID:-} " in
            *" $k "*) out+="${out:+; }the shell senders ignore $k as invalid; set $k to $(setting_rule "$k")" ;;
            *) oth+="${oth:+ and }$k" ;;
        esac
    done
    [ -z "$oth" ] || out+="${out:+; }today's failure hook reads $oth otherwise"
    printf '%s' "$out"
}

# status_test_page: --test-page. Under the lock: the class test budget (3 in 24 h), a code from
# /dev/urandom, then the ledger line (counted before anything is sent) and the testpage record,
# which replaces any earlier one. Then the failure-alert unit is started for that code and sends
# the page, so its arrival proves that unit, the network and the target as the library reads it.
# This command sends nothing itself. It prints the code, as the unit's own name carries it (the
# code is not a secret, just what the operator types back once the page is on the phone), with
# `sent test page` only when the page left the host; otherwise one line says in words what became
# of it.
status_test_page() {
    local admit code bind k8 unit mode=pointer next
    pa_settings_load
    if [ "$PA_TARGET" != 1 ]; then
        hook_posts
        if [ "$HOOK_POSTS" = 1 ]; then
            printf "no target the shell senders accept: nothing sent; today's failure hook still posts to the setting they ignore (see sudo propolis-status --setup)\n"
        else
            printf 'no push target: nothing sent (the failure hook writes to the journal; see sudo propolis-status --setup)\n'
        fi
        exit 1
    fi
    [ "$(pa_gate)" != full ] || mode=full
    status_lock
    if ! pa_salt_ensure; then
        pa_unlock
        printf 'test page not sent: the id salt could not be written in /var/lib/propolis/witness\n'
        exit 1
    fi
    admit="$(pa_budget_admit test - open 1)"
    case "$admit" in
        admit) ;;
        withhold:test-cap)
            next="$(pa_budget_next test)" || next="?"
            pa_unlock
            printf 'test page budget spent (3 in 24 h): nothing sent; the next is allowed at %s UTC\n' "$next"
            exit 1
            ;;
        *)
            pa_unlock
            printf 'test page not sent: the send ledger cannot be read, so the budget cannot be counted\n'
            exit 1
            ;;
    esac
    code="$(od -An -N3 -tx1 /dev/urandom 2> /dev/null | tr -d ' \n')"
    bind="$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" || bind=""
    k8="$(pa_token8 "${PA_TOKEN:-}")" || k8=""
    if ! [[ $code =~ ^[0-9a-f]{6}$ ]] || [ -z "$bind" ] || [ -z "$k8" ]; then
        pa_unlock
        printf 'test page not sent: no code could be made (/dev/urandom, sha256sum)\n'
        exit 1
    fi
    if ! pa_ledger_add test - open "$mode" pending status \
        || ! pa_testpage_write "$code" "$PA_LEDGER_STAMP" "$bind" "$k8" pending - -; then
        pa_unlock
        printf 'test page not sent: the state could not be written (/var/lib/propolis/witness, /run/propolis-witness)\n'
        exit 1
    fi
    pa_unlock
    unit="propolis-alert@propolis-test-page-$code.service"
    # The unit is a oneshot, so start returns when the hook has finished; the hook's own limit is
    # 90 s. timeout runs the real systemctl, past the 10 s wrapper above.
    timeout 100 systemctl start -- "$unit" > /dev/null 2>&1 || true
    pa_banner_write || true
    if ! _pa_tp_line || [ "$PA_TP_CODE" != "$code" ]; then
        printf 'test page not confirmed: a newer test page replaced it before its result was written\n'
        exit 1
    fi
    case "$PA_TP_RESULT" in
        ok)
            printf 'sent test page %s: ok. When it arrives, type back the code it carries: sudo propolis-status --ack-test %s\n' "$code" "$code"
            exit 0
            ;;
        pending)
            # Also what a unit leaves that ran and could not write the record; its journal line
            # says which.
            printf "not sent: the failure-alert unit did not run, or could not write the page's record (see: journalctl -u %s)\n" "$unit"
            ;;
        sending)
            # The hook claimed the page and then could not write its result: it was sent, or was
            # being sent when the hook stopped.
            printf 'sent test page %s; the result could not be recorded (see: journalctl -u %s). If it arrives, type back the code it carries: sudo propolis-status --ack-test %s\n' \
                "$code" "$unit" "$code"
            ;;
        lockbusy)
            printf 'not sent: the failure-alert unit found the state lock busy; try again in a minute (see: journalctl -u %s)\n' "$unit"
            ;;
        noclaim)
            printf 'test page not sent: the failure-alert unit could not write its claim on the send ledger (/var/lib/propolis/witness, /run/propolis-witness); send another once there is room\n'
            ;;
        nocurl)
            printf "test page not sent: curl is not installed here; install it (today's failure hook cannot push without it either)\n"
            ;;
        notarget)
            printf 'test page not sent: the failure-alert unit found no push target; see sudo propolis-status --setup\n'
            ;;
        norender)
            printf 'test page not sent: it could not be put together (no alias yet, or a value that cannot be sent safely); see sudo propolis-status --setup\n'
            ;;
        nomatch)
            printf 'test page not sent: the failure-alert unit ran over 10 minutes after the page was asked for; send another\n'
            ;;
        perm:401 | perm:403)
            printf 'test page %s not accepted by the server (%s): check the token and that it may write to the topic; it counted toward the three a day (see: journalctl -u %s)\n' \
                "$code" "$PA_TP_RESULT" "$unit"
            ;;
        perm:*)
            printf 'test page %s not accepted by the server (%s): check PROPOLIS_OPS_NTFY_URL and the topic; it counted toward the three a day (see: journalctl -u %s)\n' \
                "$code" "$PA_TP_RESULT" "$unit"
            ;;
        transient:*)
            printf 'test page %s not accepted by the server (%s): try again later; it counted toward the three a day (see: journalctl -u %s)\n' \
                "$code" "$PA_TP_RESULT" "$unit"
            ;;
        *)
            printf 'test page %s: result %s (see: journalctl -u %s)\n' "$code" "$PA_TP_RESULT" "$unit"
            ;;
    esac
    exit 1
}

# status_ack_test CODE: --ack-test. Under the lock, the waiting test page is acknowledged only
# when CODE is its code, it went out (ok, or sending: the hook claimed it and could not write the
# result), it is at most a day old and it was not acknowledged before; anything else changes
# nothing. The same code typed again says when it was acknowledged and whether VERIFIED stands,
# without refreshing the 30 days: only a new page proves the path again. The account is
# SUDO_UID's when that is a number.
status_ack_test() {
    local a uid=0 v
    status_lock
    if _pa_tp_line && [ "$PA_TP_CODE" = "$1" ] && { [ "$PA_TP_RESULT" = ok ] || [ "$PA_TP_RESULT" = sending ]; } \
        && [ "$PA_TP_ACKED" != - ]; then
        pa_unlock
        pa_settings_load
        v="$(date -u -d "@${PA_TP_ACKED%%/*}" +%H:%M 2> /dev/null)" || v="?"
        if pa_verified > /dev/null; then
            printf 'already acknowledged at %s UTC: VERIFIED stands\n' "$v"
        else
            printf 'already acknowledged at %s UTC; now NOT VERIFIED (%s)\n' "$v" "$PA_VERIFIED_WORD"
        fi
        exit 0
    fi
    if _pa_tp_line && [ "$PA_TP_CODE" = "$1" ] && { [ "$PA_TP_RESULT" = ok ] || [ "$PA_TP_RESULT" = sending ]; } \
        && [ "$PA_TP_ACKED" = - ]; then
        a="$(pa_age "$PA_TP_SENT")"
        if [ "$a" -ge 0 ] && [ "$a" -le 86400 ]; then
            if [[ ${SUDO_UID:-} =~ ^[0-9]{1,10}$ ]]; then uid="$((10#$SUDO_UID))"; fi
            if pa_testpage_write "$PA_TP_CODE" "$PA_TP_SENT" "$PA_TP_BIND" "$PA_TP_TOKEN8" "$PA_TP_RESULT" "$PA_STAMP" "$uid"; then
                pa_unlock
                # The page proves the path the shell senders read; VERIFIED needs every other
                # rule too, today's failure hook reading the same target among them.
                pa_settings_load
                if pa_verified > /dev/null; then
                    printf 'VERIFIED: the test page reached you\n'
                else
                    v=""
                    if pa_hook_differs; then
                        v="$(printf ': %s: see sudo propolis-status --setup' "$(hook_diff_why)")"
                    fi
                    printf 'acknowledged; NOT VERIFIED (%s)%s\n' "$PA_VERIFIED_WORD" "$v"
                fi
                pa_banner_write || true
                exit 0
            fi
            pa_unlock
            printf 'not recorded: the state could not be written (/var/lib/propolis/witness, /run/propolis-witness)\n'
            exit 1
        fi
    fi
    pa_unlock
    printf 'wrong or expired code\n'
    exit 1
}

# gate_words GATE: the gate in words, for --setup, as what it governs: the test page and the
# shell messages a later release adds. Today's failure hook and the daemon are not gated, so no
# word here speaks of pushes in general (the failures line says what those carry).
gate_words() {
    local what="the test page (and the shell messages of a later release)"
    case "$1" in
        # pa_render builds the same test page in either mode, so only the later messages gain.
        full) printf 'full - the shell messages of a later release may carry detail: the topic refuses anonymous reads (the test page carries only the alias and the code in every mode)' ;;
        pointer:insecure) printf '%s  - %s carries no detail: over plain http a refusal proves nothing' "$1" "$what" ;;
        pointer:token-reads) printf '%s  - %s carries no detail: the token this host holds can read the topic' "$1" "$what" ;;
        pointer:*) printf '%s  - %s carries no detail until anonymous reads are refused' "$1" "$what" ;;
        *)
            # A target the shell senders ignore as invalid can still be today's hook's.
            if [ "${HOOK_POSTS:-0}" = 1 ]; then
                printf "%s  - the shell senders push nothing; today's failure hook still posts (see target)" "$1"
            else
                printf '%s  - nothing is pushed: no target' "$1"
            fi
            ;;
    esac
}

# setting_rule KEY: the rule a shell sender's push setting must meet, in config-check's words
# (alert_rule_words), for the fix --setup prints.
setting_rule() {
    case "$1" in
        PROPOLIS_OPS_NTFY_URL) printf 'an http:// or https:// URL with a host and no blanks' ;;
        PROPOLIS_OPS_NTFY_TOPIC) printf '1 to 64 letters, digits, _ or -' ;;
        PROPOLIS_OPS_NTFY_TOKEN) printf '1 to 256 printable characters with no blank' ;;
        *) printf 'a valid value' ;;
    esac
}

# next_step WORD: what to do about a NOT VERIFIED word, for --setup's verified line, from the
# word, the last test page's result (pa_verified left it in PA_TP_RESULT) and the role. Only no
# page, an expired one, a code past the day --ack-test takes it for, and a change today's failure
# hook reads the same way are told to send a page: after one that went out a new page would
# replace the code on the phone and spend one of the day's three, a change the hook reads
# otherwise needs the file fixed first, and without a target or a salt --test-page refuses and
# points back here.
next_step() {
    local send="Run: sudo propolis-status --test-page" a
    if [ "$PA_TARGET" != 1 ]; then
        # The hook still posting is a fix to make on any role, a collector's included.
        if [ "${HOOK_POSTS:-0}" = 1 ]; then
            hook_fix
        elif [ "$ROLE" = collector ]; then
            printf 'No push target is expected on a collector'
        else
            printf 'Set PROPOLIS_OPS_NTFY_URL and PROPOLIS_OPS_NTFY_TOPIC in /etc/propolis/propolis.env'
        fi
        return 0
    fi
    if ! _pa_salt > /dev/null; then
        printf 'The id salt must be written first (see the salt line)'
        return 0
    fi
    case "$1" in
        never | expired) printf '%s' "$send" ;;
        changed)
            # A new page cannot clear a change today's failure hook reads otherwise: it proves
            # only the shell senders' reading, and would spend one of the day's three.
            if pa_hook_differs; then
                hook_fix
            else
                printf '%s' "$send"
            fi
            ;;
        pending)
            case "$PA_TP_RESULT" in
                ok | sending)
                    # --ack-test takes a code for a day; after that only a new page helps.
                    a="$(pa_age "$PA_TP_SENT")"
                    if [ "$a" -ge 0 ] && [ "$a" -le 86400 ]; then
                        printf 'Type back the code from the page: sudo propolis-status --ack-test <code>'
                    else
                        printf "The last test page's code has expired (over a day old). %s" "$send"
                    fi
                    ;;
                pending) printf "The last test page was not sent: the failure-alert unit did not run, or could not write the page's record (see journalctl -u propolis-alert@propolis-test-page-%s.service)" "$PA_TP_CODE" ;;
                perm:401 | perm:403) printf 'The last test page was refused (%s): check the token and that it may write to the topic, then send another' "$PA_TP_RESULT" ;;
                perm:*) printf 'The last test page was refused (%s): check PROPOLIS_OPS_NTFY_URL and the topic, then send another' "$PA_TP_RESULT" ;;
                transient:*) printf 'The last test page got no answer that took it (%s): check the network and the server, then send another' "$PA_TP_RESULT" ;;
                nocurl) printf 'The last test page was not sent (nocurl): install curl, then send another' ;;
                lockbusy) printf 'The last test page was not sent (lockbusy): the state lock was busy; send another in a minute' ;;
                *) printf 'The last test page was not sent (%s): send another' "$PA_TP_RESULT" ;;
            esac
            ;;
        refused) printf 'A message was refused for good since the code was typed back: check the token and the topic, then send another test page' ;;
        path-failed | undelivered) printf 'A failure alert did not leave this host since: see sudo propolis-status alert' ;;
        *) printf 'A state file cannot be read: see sudo propolis-status' ;;
    esac
}

# status_setup: --setup. The anonymous-read check of the target runs first, without the lock (it
# can take a minute); then, under the lock, the id salt (the fallback alias comes from it) and the
# stored check, merged as the witness merges it. Then the report, one item a line: never the
# token, never the topic (only its length), and of the URL only its scheme and host.
status_setup() {
    local alias host role had_salt=0 salt=ok ran=0 b have body="" line t stored=1 gate token
    local hook_token hook_any hook_refused=0 hook_url
    pa_settings_load
    if [ "$PA_TARGET" = 1 ]; then
        pa_readcheck_run "$PA_URL" "$PA_TOPIC" "${PA_TOKEN:-}" || true
        ran=1
    fi
    status_lock
    if _pa_salt > /dev/null; then had_salt=1; fi
    if ! pa_salt_ensure; then
        salt="could not be written in /var/lib/propolis/witness: no alias yet"
    elif [ "$had_salt" = 0 ]; then
        salt="created now"
    fi
    if [ "$ran" = 1 ] && [ "$PA_RC_CAUSE" = - ]; then
        pa_now
        b="$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" || b=""
        have=0
        if _pa_rc_line shell; then have=1; fi
        # One target before alert.env is read: the shell's and the daemon's are the same, so its
        # line is the both line, and lines for either role alone are gone with it.
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            IFS=$'\t' read -r t _ <<< "$line"
            [ "$t" = R ] || body+="$line"$'\n'
        done < <(pa_state_read readcheck)
        body+="$(pa_readcheck_merge both "$b" "$have")"$'\n'
        pa_state_write readcheck < <(printf '%s' "$body") || stored=0
    fi
    pa_unlock
    PA_ROLE="$ROLE"
    gate="$(pa_gate)"
    # A definite answer other than a refusal that could not be stored must not leave the gate on
    # the refusal stored before it: the answer given now is the one that holds.
    if [ "$stored" = 0 ] && [ "$PA_RC_CLASS" != transient ] && [ "$PA_RC_CLASS" != refused ]; then
        gate="pointer:$PA_RC_CLASS"
    fi
    # What today's failure hook reads in propolis.env, by its own rule, against the shell senders.
    hook_posts
    hook_token="$(pa_hook_env_value PROPOLIS_OPS_NTFY_TOKEN)"
    # Whether today's failure hook posts at all: its own reader finds a URL and a topic.
    hook_any=0
    [ -z "$PA_HOOK_URL" ] || [ "$PA_HOOK_TOPIC_SET" != 1 ] || hook_any=1
    pa_alias > /dev/null 2>&1 || true
    alias="${PA_ALIAS:--}"
    host="$(hostname 2> /dev/null | tr -c 'A-Za-z0-9.\n-' '?' | head -n 1)"
    case "$ROLE" in
        single) role="single box" ;;
        control) role="control node" ;;
        collector) role=collector ;;
        gateway) role="gateway only" ;;
        *) role="unknown role" ;;
    esac
    printf 'setup on %s (%s, %s)\n' "$alias" "${host:-?}" "$role"
    # Only the test page carries the alias in this release; today's failure alerts name the host
    # by its host name. Where nothing posts, nothing names the host on a channel.
    t=""
    [ "$hook_any" = 0 ] || t="today's failure alerts name it by its host name, ${host:-?}"
    if [ "$PA_TARGET" != 1 ]; then
        if [ "$hook_any" = 1 ]; then
            printf "channel     today's failure alerts name this host by its host name, %s; no test page names it while the shell senders have no target\n" "${host:-?}"
        fi
    elif [ "$alias" = - ]; then
        printf 'channel     no alias yet: the id salt could not be written%s\n' "${t:+; $t}"
    elif [ "$ROLE" = single ]; then
        printf 'channel     test pages (and the shell messages of a later release) name this host by its alias, %s: record it%s\n' "$alias" "${t:+; $t}"
    else
        printf "channel     test pages (and the shell messages of a later release) name this host by its alias, %s: record it%s; warning: a fallback alias cannot be told from other hosts' on a phone, and this release has no setting to name it\n" "$alias" "${t:+; $t}"
    fi
    if [ "$HOOK_POSTS" = 1 ]; then
        # The hook posts the raw values: without a scheme curl falls back to plain http.
        case "$PA_HOOK_URL" in
            *://*) b="URL $(pa_url_shown "$PA_HOOK_URL")" ;;
            *) b="no scheme: curl uses plain http" ;;
        esac
        token=""
        [ -z "$hook_token" ] || token=" and the token"
        printf "target      none for the shell senders, which %s; today's failure hook still posts to it (%s), with the host and unit names, its journal lines%s\n" \
            "$(hook_diff_words)" "$b" "$token"
        for line in $PA_HOOK_DIFF; do
            case " $PA_INVALID " in
                *" $line "*)
                    case "$line" in
                        PROPOLIS_OPS_NTFY_URL | PROPOLIS_OPS_NTFY_TOPIC)
                            printf '            fix (config-check alert-setting-invalid): in /etc/propolis/propolis.env set %s to %s, written plainly on one line\n' \
                                "$line" "$(setting_rule "$line")"
                            ;;
                    esac
                    ;;
                *)
                    printf "            today's failure hook reads %s otherwise: write each push setting as KEY=value at the start of its line, with no blank or comment\n" "$line"
                    ;;
            esac
        done
    elif [ "$PA_TARGET" != 1 ]; then
        printf 'target      none: the failure hook writes its alerts to the journal%s\n' \
            "${PA_INVALID:+ (invalid value ignored: $PA_INVALID)}"
    else
        token="no token"
        [ -z "${PA_TOKEN:-}" ] || token="token set"
        printf 'target      ntfy from %s: URL %s, topic set (%s chars), %s%s\n' "$PA_TARGET_SRC" \
            "$(pa_url_shown "$PA_URL")" "${#PA_TOPIC}" "$token" "${PA_INVALID:+ (invalid value ignored: $PA_INVALID)}"
        # Names only: a page that went out through the library proves nothing for a hook that
        # would post elsewhere, or not at all.
        # A value the shell senders ignore as invalid is fixed by its rule; writing it plainly
        # would leave it ignored.
        b=""
        for line in $PA_HOOK_DIFF; do
            case " ${PA_INVALID:-} " in
                *" $line "*)
                    printf '            the shell senders ignore %s as invalid; set %s to %s\n' "$line" "$line" "$(setting_rule "$line")"
                    ;;
                *) b+="${b:+ and }$line" ;;
            esac
        done
        if [ -n "$b" ]; then
            printf "            today's failure hook reads %s otherwise: write each push setting as KEY=value at the start of its line, with no blank or comment\n" \
                "$b"
        fi
        if [ "$PA_RC_CAUSE" != - ]; then
            printf 'anon read   not checked: curl or a private temporary file was not to be had\n'
        else
            printf 'anon read   checked now: json %s (%s), raw %s (%s), sse %s (%s) -> %s\n' \
                "$PA_RC_JSON" "$PA_RC_JSON_CT" "$PA_RC_RAW" "$PA_RC_RAW_CT" "$PA_RC_SSE" "$PA_RC_SSE_CT" "$PA_RC_CLASS"
            [ "$PA_RC_CLASS" != transient ] || printf '            no definite answer: the one stored before stands\n'
            [ "$stored" = 1 ] || printf '            the answer could not be stored (/var/lib/propolis/witness, /run/propolis-witness)\n'
        fi
        if [[ $PA_URL != https://* ]]; then
            printf 'anon read   gate needs https: over http anyone on the path can fake this answer and read the pushes\n'
        fi
        case "$PA_RC_TOKEN" in
            reads) printf 'token       reads (this token can read the topic)\n' ;;
            noread) printf 'token       noread (this token cannot read the topic)\n' ;;
            unknown) printf 'token       unknown (its read got no answer that says)\n' ;;
            *)
                # A check that never ran says nothing about the token.
                if [ "$PA_RC_CAUSE" != - ] && [ -n "${PA_TOKEN:-}" ]; then
                    printf 'token       not checked\n'
                else
                    printf 'token       none\n'
                fi
                ;;
        esac
        if ! command -v curl > /dev/null 2>&1; then
            printf "            install curl: today's failure hook cannot push without it either\n"
        fi
        if [ "$ROLE" = collector ]; then
            printf "token       collectors should use their own topic: on ntfy.sh a token carries its user's read rights\n"
        fi
    fi
    printf 'gate        %s\n' "$(gate_words "$gate")"
    # Today's failure hook is not gated: it posts its host name, unit and journal lines wherever
    # it reads a URL and a topic. Its topic is proven private only by a refusal for the very target
    # it reads, stored now or before, and over plain http not even then.
    if [ "$hook_any" = 1 ]; then
        hook_url="$PA_HOOK_URL"
        if [ "$PA_TARGET" = 1 ] && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_URL "* ]] \
            && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_TOPIC "* ]]; then
            if [ "$stored" = 0 ] && [ "$PA_RC_CLASS" != transient ]; then
                [ "$PA_RC_CLASS" != refused ] || hook_refused=1
            elif _pa_rc_line daemon && [ "$PA_RCL_DCLASS" = refused ] \
                && [ "$PA_RCL_BIND" = "$(pa_readcheck_binding "$PA_D_URL" "$PA_D_TOPIC")" ]; then
                hook_refused=1
            fi
        fi
        if [[ $hook_url != https://* ]] || [ "$hook_refused" = 0 ]; then
            line="failures    the gate does not apply to today's failure alerts: each carries this host's name, the failed unit and its last journal lines"
            if [[ $hook_url != https://* ]]; then
                line+="; over plain http they travel in clear"
                [ -z "$hook_token" ] || line+=", the token too"
            fi
            [ "$hook_refused" = 1 ] || line+="; the topic is not proven to refuse anonymous reads"
            printf '%s\n' "$line"
        fi
    fi
    if [ "${PA_D_TARGET:-0}" = 1 ] && { ! _pa_rc_line daemon || [ "$PA_RCL_DCLASS" != refused ]; }; then
        # The hook posts to this topic only where its own reader finds this URL and topic.
        if [ "$hook_any" = 1 ] && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_URL "* ]] \
            && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_TOPIC "* ]]; then
            if [ "$HAS_DAEMON" = 1 ]; then
                printf "daemon      the daemon and today's failure hook post to this topic; their titles name this host's software and, for the hook, the host and unit (until step 3)\n"
            else
                printf "daemon      today's failure hook posts to this topic; its titles name the host and the unit that failed\n"
            fi
        elif [ "$HAS_DAEMON" = 1 ]; then
            printf "daemon      the daemon posts to this topic; its titles name this host's software (until step 3)\n"
        fi
    fi
    case "${PA_HB_STATE:-unset}" in
        set) printf 'heartbeat   set (the URL is not shown)\n' ;;
        insecure | invalid) printf 'heartbeat   refused (not an https URL): PROPOLIS_WITNESS_HEARTBEAT_URL is ignored\n' ;;
        *) printf 'heartbeat   not set. Recommended: a private dead-man check URL (no public status page) in PROPOLIS_WITNESS_HEARTBEAT_URL; it fires when this host stops\n' ;;
    esac
    # Run here as well, outside the $() of verified_words, so the word and the stored page's
    # result are set in this shell for the next step.
    pa_verified > /dev/null || true
    line="$(verified_words)"
    case "$line" in
        VERIFIED*) printf 'verified    %s\n' "$line" ;;
        *) printf 'verified    %s. %s\n' "$line" "$(next_step "$PA_VERIFIED_WORD")" ;;
    esac
    printf 'salt        %s\n' "$salt"
    pa_banner_write || echo "propolis-status: the login banner was not rewritten (/run/motd.d is missing or refused the write)" >&2
    [ "$gate" = full ] || exit 1
    exit 0
}

# daemon_config_older: the running daemon started before propolis.env last changed, so it may
# hold an older topic or token: a restart is what makes a changed target take effect. The
# file's own mtime, not a link's target. Run in a subshell, so the U_ values the rows read are
# left as they were.
daemon_config_older() {
    local m t
    case "$ROLE" in single | control) ;; *) return 1 ;; esac
    unit_show propolis.service ActiveState SubState ActiveEnterTimestamp || return 1
    unit_up || return 1
    t="$(ts_epoch "$U_ActiveEnterTimestamp")"
    m="$(timeout 5 stat -c %Y -- "$PROPOLIS_ENV" 2> /dev/null)" || return 1
    [[ $t =~ ^[0-9]{1,12}$ && $m =~ ^[0-9]{1,12}$ ]] && [ "$m" -gt "$t" ]
}

case "$VERB" in
    banner) status_banner ;;
    maint) status_maint "$MAINT_MINUTES" ;;
    setup) status_setup ;;
    test-page) status_test_page ;;
    ack-test) status_ack_test "$ACK_CODE" ;;
esac

env_of PROPOLIS_OPS_STALL_FOR_SECS "$PROPOLIS_ENV"
STALL=600
if [[ $ENV_V =~ ^[0-9]{1,9}$ ]] && [ "$((10#$ENV_V))" -gt 0 ]; then STALL=$((10#$ENV_V)); fi
env_of PROPOLIS_OPS_BACKUP_MAX_AGE_SECS "$PROPOLIS_ENV"
BACKUP_STALE=129600
if [[ $ENV_V =~ ^[0-9]{1,9}$ ]] && [ "$((10#$ENV_V))" -gt 0 ]; then BACKUP_STALE=$((10#$ENV_V)); fi
LOW_DISK=15

env_of PROPOLIS_GATEWAY_SPOOL_DIR "$GATEWAY_ENV"
SPOOL_DIR="${ENV_V:-$STATUS_ROOT/var/spool/propolis/gateway}"
SPOOL_ENV_BAD="$ENV_BAD"

# The state files, read once and without the lock: a reader that holds no lock never renames or
# logs (the library's rule), it only names what it could not read in PA_STATE_UNREADABLE.
declare -A META=()
while IFS=$'\t' read -r m_t m_k m_v _; do
    [ "$m_t" = M ] && [ -n "$m_k" ] && META[$m_k]="$m_v"
done < <(pa_state_read meta)
INCIDENTS_BODY="$(pa_state_read incidents)"
# Read again in this shell, output discarded: the reads above ran in subshells, and only a read
# in this one leaves the names of unreadable files in PA_STATE_UNREADABLE.
pa_state_read meta > /dev/null
pa_state_read incidents > /dev/null
INCIDENTS_FILE=0
if [ -e "$PA_STATE/incidents" ] || [ -e "$PA_RUN/fallback/incidents" ]; then INCIDENTS_FILE=1; fi
SALT=0
if [ -f "$PA_STATE/id-salt" ] && [[ $(root_read "$PA_STATE/id-salt" 64) =~ ^[0-9a-f]{32}$ ]]; then
    SALT=1
fi
UNKNOWN_EXTRA=0

# ---- config-check ---------------------------------------------------------------------------

CC_DONE=0 CC_WHY="" CC_SECS=0 CC_GEN="" CC_NFAIL=0 CC_NWARN=0 CC_NUNK=0
CCF_LEVEL=() CCF_ID=() CCF_SCOPE=() CCF_FIX=() CCR_ROWS=()
declare -A CCR_FW=()
CC_LIMIT=120
if [ -n "$STATUS_ROOT" ] && [[ ${PROPOLIS_STATUS_CC_LIMIT:-} =~ ^[1-9][0-9]{0,2}$ ]]; then
    CC_LIMIT="$PROPOLIS_STATUS_CC_LIMIT"
fi

# cc_word TEXT: a cell of config-check's TSV as one printable word of at most 64 bytes.
cc_word() {
    printf '%s' "${1:--}" | tr -c 'A-Za-z0-9._:@/+=,%-' '?' | cut -b 1-64
}

# run_config_check: the installed config-check, live (the walk is what the operator runs when
# something is wrong), in its machine format, without the ledger query, bounded at 120 s.
run_config_check() {
    local cc out rc start t level id k12 scope kind msg rest nf=0 e="" head
    cc="${PROPOLIS_STATUS_CC:-$STATUS_ROOT/usr/local/lib/propolis/config-check.sh}"
    if ! pa_trusted_exec "$cc"; then
        CC_WHY="not trusted: $PA_UNTRUSTED"
        return 0
    fi
    start="$SECONDS"
    out="$(timeout -k 5 "$CC_LIMIT" "$cc" --tsv --no-events --report-only < /dev/null 2> /dev/null | tr -d '\000')"
    rc=$?
    CC_SECS=$((SECONDS - start))
    if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
        CC_WHY="timed out after $CC_LIMIT s"
        return 0
    elif [ "$rc" -gt 2 ]; then
        CC_WHY="exit $rc"
        return 0
    fi
    head="${out%%$'\n'*}"
    if [ "$head" != '#config-check tsv v1' ]; then
        CC_WHY="no machine-readable output"
        return 0
    fi
    while IFS=$'\t' read -r t level id k12 scope kind msg rest; do
        case "$t" in
            S)
                # S status exit n_fail n_warn n_unknown root generated installed
                CC_NFAIL="$k12" CC_NWARN="$scope" CC_NUNK="$kind" CC_GEN="${rest%%$'\t'*}"
                ;;
            R)
                # R scope unit status unit-col listen-col firewall-col ...
                CCR_FW[$level]="${msg:-}"
                CCR_ROWS+=("$(cc_word "$level") ($(cc_word "$id")): unit $(cc_word "$scope"), listen $(cc_word "$kind"), firewall $(cc_word "$msg")")
                ;;
            F)
                CCF_LEVEL+=("$level") CCF_ID+=("$id") CCF_SCOPE+=("$scope") CCF_FIX+=("")
                nf=$((nf + 1))
                ;;
            X)
                [ "${#CCF_FIX[@]}" -eq 0 ] || CCF_FIX[${#CCF_FIX[@]} - 1]="$level"
                ;;
            E) e="$level" ;;
        esac
    done <<< "$out"
    if [ "$e" != "$nf" ]; then
        CC_WHY="output cut short"
        CCF_LEVEL=() CCF_ID=() CCF_SCOPE=() CCF_FIX=() CCR_ROWS=()
        return 0
    fi
    [[ $CC_NFAIL =~ ^[0-9]{1,6}$ ]] || CC_NFAIL=0
    [[ $CC_NWARN =~ ^[0-9]{1,6}$ ]] || CC_NWARN=0
    [[ $CC_NUNK =~ ^[0-9]{1,6}$ ]] || CC_NUNK=0
    CC_DONE=1
}

# cc_ids LEVEL ID...: the ids among the findings at LEVEL (any for `any`) that are in the list,
# each once, space separated.
cc_ids() {
    local level="$1" i out=" "
    shift
    for i in "${!CCF_ID[@]}"; do
        [ "$level" = any ] || [ "${CCF_LEVEL[$i]}" = "$level" ] || continue
        case " $* " in *" ${CCF_ID[$i]} "*) ;; *) continue ;; esac
        case "$out" in *" ${CCF_ID[$i]} "*) ;; *) out+="${CCF_ID[$i]} " ;; esac
    done
    out="${out# }"
    printf '%s' "${out% }"
}

# ---- the rows -------------------------------------------------------------------------------

R_NUM=() R_STAGE=() R_INST=() R_LAST=() R_AGE=() R_STATE=() R_NOTE=() R_WHY=() R_COND=() R_MARK=()

# add_row NUM STAGE INSTANCE LAST AGE STATE NOTE WHY COND: one row. NUM is empty for a rail. WHY
# is `direct` or `progress` for a FAIL (which rule made it), COND the STATUS_NEXT condition.
add_row() {
    R_NUM+=("$1") R_STAGE+=("$2") R_INST+=("$3") R_LAST+=("$4") R_AGE+=("$5") R_STATE+=("$6")
    R_NOTE+=("$7") R_WHY+=("${8:-}") R_COND+=("${9:-}") R_MARK+=("")
}

# not_here NUM STAGE NOTE: a stage this host does not run.
not_here() {
    add_row "$1" "$2" - - - - "$3"
}

# with_findings NOTE: NOTE with the rows' share of an unfinished config-check marked unknown.
with_findings() {
    if [ "$CC_DONE" = 1 ]; then
        printf '%s' "$1"
    else
        printf '%s' "${1:+$1; }findings ?"
    fi
}

SENSOR_UNITS=()
row_listen() {
    local list unit fstate e=0 a=0 restarts=0 oldest="" t down=() fails warns note state cond
    local scope u i
    local -a ids=()
    declare -gA UNIT_UP=()
    if [ "$ROLE" = control ]; then
        add_row 1 listen "collectors (remote)" - - remote "listeners on collectors: run status there"
    fi
    if [ "$ROLE" = gateway ]; then
        not_here 1 listen "no sensors on a gateway"
        return 0
    fi
    if ! list="$(systemctl list-unit-files 'sensor-*.service' --no-legend --no-pager 2> /dev/null)"; then
        add_row 1 listen - - - '?' "systemctl did not answer" "" ""
        return 0
    fi
    while read -r unit fstate _; do
        [[ $unit =~ ^sensor-[a-z0-9-]{1,40}\.service$ ]] || continue
        if ! unit_show "$unit" ActiveState SubState Result NRestarts ActiveEnterTimestamp UnitFileState; then
            add_row 1 listen - - - '?' "systemctl did not answer for $unit" "" ""
            return 0
        fi
        u=0
        if unit_up; then u=1; fi
        UNIT_UP[${unit%.service}]="$u"
        [ "${U_UnitFileState:-$fstate}" = enabled ] || [ "$u" = 1 ] || continue
        SENSOR_UNITS+=("$unit")
        if [ "${U_UnitFileState:-$fstate}" = enabled ]; then
            e=$((e + 1))
            [ "$u" = 1 ] || down+=("$unit")
        fi
        if [ "$u" = 1 ]; then
            a=$((a + 1))
            t="$(ts_epoch "$U_ActiveEnterTimestamp")"
            if [ -n "$t" ] && { [ -z "$oldest" ] || [ "$t" -lt "$oldest" ]; }; then oldest="$t"; fi
        fi
        if [[ ${U_NRestarts:-} =~ ^[0-9]{1,9}$ ]]; then restarts=$((restarts + 10#$U_NRestarts)); fi
    done <<< "$list"
    if [ "$ROLE" = control ] && [ "${#SENSOR_UNITS[@]}" -eq 0 ]; then
        return 0
    fi
    # A down unit and a page-eligible finding stop the stage; a finding of the daily tier (a
    # parked sensor among them: unit-disabled is today's only way to retire one) only warns, so
    # it never takes the marker from a real fault further down.
    fails="$(cc_ids any unit-missing listen-foreign listen-loopback listen-none danger)"
    for i in "${!CCF_ID[@]}"; do
        scope="${CCF_SCOPE[$i]}"
        case "${CCF_ID[$i]}" in
            unit-down)
                # Only while systemd still says the unit is not running.
                [ "${UNIT_UP[$scope]:-0}" = 1 ] || fails="${fails:+$fails }unit-down"
                ;;
            fw)
                [ "${CCR_FW[$scope]:-}" = unknown ] || fails="${fails:+$fails }fw"
                ;;
        esac
    done
    read -r -a ids <<< "$fails"
    fails=""
    [ "${#ids[@]}" -eq 0 ] || fails="$(printf '%s\n' "${ids[@]}" | sort -u | tr '\n' ' ')"
    fails="${fails% }"
    warns="$(cc_ids any unit-masked unit-disabled badbind noconfig listen-ownerless nofw)"
    note="$a of $e units active; restarts since start $restarts"
    state=ok cond=""
    if [ "$e" -eq 0 ] && [ "$a" -eq 0 ]; then
        state=WARN note="no sensor unit enabled" cond=listen-daily
    fi
    if [ -n "$warns" ]; then
        state=WARN cond=listen-daily
        case " $warns " in
            *" unit-disabled "*) note+="; $(cc_count unit-disabled) disabled on purpose (unit-disabled)" ;;
        esac
        note+="; findings: $warns"
    fi
    if [ "${#down[@]}" -gt 0 ] || [ -n "$fails" ]; then
        state=FAIL cond=listen-down
        [ "${#down[@]}" -eq 0 ] || note="${#down[@]} enabled and not active: ${down[*]}; $note"
        [ -z "$fails" ] || note+="; findings: $fails"
    fi
    add_row 1 listen "$e units" "$(fmt_time "$oldest")" - "$state" "$(with_findings "$note")" direct "$cond"
}

# cc_count ID: how many findings carry ID, as `1 unit` or `<n> units`.
cc_count() {
    local i n=0
    for i in "${!CCF_ID[@]}"; do [ "${CCF_ID[$i]}" != "$1" ] || n=$((n + 1)); done
    if [ "$n" = 1 ]; then printf '1 unit'; else printf '%s units' "$n"; fi
}

# The configured logs: LOG_LABEL, LOG_PATH, and the account that reads them; LOG_RC holds the
# readability test's status per log once row_source has run.
LOG_LABEL=() LOG_PATH=() LOG_RC=() LOG_READER="" LOG_ENV_BAD="" LOG_VAR=""
load_logs() {
    if [ "$ROLE" = collector ]; then
        env_of PROPOLIS_SHIPPER_SENSOR_LOGS "$SHIPPER_ENV"
        LOG_READER=propolis-shipper LOG_VAR=PROPOLIS_SHIPPER_SENSOR_LOGS
    else
        env_of PROPOLIS_SENSOR_LOGS "$FLEET_ENV" "$PROPOLIS_ENV"
        LOG_READER=propolis LOG_VAR=PROPOLIS_SENSOR_LOGS
    fi
    LOG_ENV_BAD="$ENV_BAD"
    pa_sensor_logs "$ENV_V"
    LOG_LABEL=("${PA_LOG_LABEL[@]}") LOG_PATH=("${PA_LOG_PATH[@]}")
}

# in_spool PATH: PATH lies under the gateway spool (a collector's log arriving on this node).
in_spool() {
    case "$1" in "${SPOOL_DIR%/}"/*) return 0 ;; esac
    return 1
}

row_source() {
    local i p n=0 newest="" oldest="" missing=0 refused=() unchecked=() other=0 rc fails warns note
    local state cond why=""
    if [ "$ROLE" = gateway ]; then
        not_here 2 source "no sensor logs on a gateway"
        return 0
    fi
    if [ -n "$LOG_ENV_BAD" ]; then
        add_row 2 source - - - '?' "${LOG_ENV_BAD##*/} cannot be read"
        return 0
    fi
    for i in "${!LOG_PATH[@]}"; do
        p="${LOG_PATH[$i]}"
        [ "$ROLE" != control ] || ! in_spool "$p" || continue
        n=$((n + 1))
        file_facts "$p"
        case "$F_TYPE" in
            missing)
                missing=$((missing + 1))
                continue
                ;;
            other)
                other=$((other + 1))
                continue
                ;;
            unknown)
                unchecked+=("$(braced "${LOG_LABEL[$i]}")")
                continue
                ;;
        esac
        if [ -z "$newest" ] || [ "$F_MTIME" -gt "$newest" ]; then newest="$F_MTIME"; fi
        if [ -z "$oldest" ] || [ "$F_MTIME" -lt "$oldest" ]; then oldest="$F_MTIME"; fi
        rc=0
        pa_read_as "$LOG_READER" "$p" 0 || rc=$?
        LOG_RC[i]="$rc"
        case "$rc" in
            0) ;;
            6) refused+=("$(braced "${LOG_LABEL[$i]}")") ;;
            *) unchecked+=("$(braced "${LOG_LABEL[$i]}") $(read_why "$rc")") ;;
        esac
    done
    fails="$(cc_ids fail logmissing logpath logquiet logsize-fail logsize-warn stale never policy guard service-failed cursor-missing cursor-dir-unseen)"
    warns="$(cc_ids warn logmissing logpath logquiet logsize-fail logsize-warn stale never policy guard service-failed cursor-missing cursor-dir-unseen)"
    note="newest $(fmt_age "$(age_of "$newest")"), oldest $(fmt_age "$(age_of "$oldest")")"
    [ "$n" -gt 0 ] || note="no log configured in $LOG_VAR"
    state=ok cond=""
    if [ "${#refused[@]}" -eq 0 ] && [ "${#unchecked[@]}" -eq 0 ] && [ "$n" -gt 0 ]; then
        note+="; all readable by $LOG_READER"
    fi
    [ "$missing" = 0 ] || note+="; $missing missing"
    [ "$other" = 0 ] || note+="; $other not a regular file"
    if [ -n "$warns" ]; then
        state=WARN cond=source-finding
        note+="; findings: $warns"
    fi
    if [ "${#unchecked[@]}" -gt 0 ]; then
        state='?' cond=""
        note+="; not checked: ${unchecked[*]}"
    fi
    if [ "${#refused[@]}" -gt 0 ] || [ -n "$fails" ]; then
        state=FAIL why=direct cond=source-finding
        [ "${#refused[@]}" -eq 0 ] || note="not readable by $LOG_READER: ${refused[*]}; $note"
        [ -z "$fails" ] || note+="; findings: $fails"
    fi
    case " $fails $warns " in
        *" stale "* | *" logsize-fail "* | *" guard "*) [ "$state" = '?' ] || cond=source-rotation ;;
    esac
    add_row 2 source "$n logs" "$(fmt_time "$newest")" "$(fmt_age "$(age_of "$newest")")" "$state" \
        "$(with_findings "$note")" "$why" "$cond"
}

# Spool listing on a control node or gateway: SPOOL_CN (plain names), SPOOL_SIZE, SPOOL_ACC (the
# gateway's state file for the collector, rewritten on every accepted batch), SPOOL_LAST (the
# newer of that and the spool file), SPOOL_EV (1 when the collector has a spool file, the names
# the witness's spool listing keys), and SPOOL_BAD, the collectors whose listing made no sense.
# The gateway account writes both directories, so every record is NUL-terminated (a file name
# may hold a newline) and every number is checked before it reaches arithmetic, where bash would
# evaluate an array subscript in it.
SPOOL_CN=() SPOOL_LAST=() SPOOL_ACC=() SPOOL_SIZE=() SPOOL_EV=() SPOOL_OK=1 SPOOL_WITHHELD=0 SPOOL_BAD=0
load_spool() {
    local y name cn_s cn_t acc bad f fs ft list gdir ev
    local -A gstate=()
    [ -d "$SPOOL_DIR" ] && [ ! -L "$SPOOL_DIR" ] || {
        SPOOL_OK=0
        return 0
    }
    list="$(timeout 10 find "$SPOOL_DIR" -mindepth 1 -maxdepth 1 -printf '%y %f\0' 2> /dev/null | tr '\0\n' '\n?')" || {
        SPOOL_OK=0
        return 0
    }
    env_of PROPOLIS_GATEWAY_STATE_DIR "$GATEWAY_ENV"
    gdir="${ENV_V:-$STATUS_ROOT/var/lib/propolis/gateway}"
    if [ -d "$gdir" ] && [ ! -L "$gdir" ]; then
        while IFS=' ' read -r -d '' ft f; do
            [[ $ft =~ ^[0-9]{1,12}(\.[0-9]+)?$ && $f == *.json ]] || continue
            pa_plain_id "${f%.json}" || continue
            gstate[${f%.json}]="${ft%%.*}"
        done < <(timeout 10 find "$gdir" -mindepth 1 -maxdepth 1 -type f -name '*.json' -printf '%T@ %f\0' 2> /dev/null)
    fi
    while read -r y name; do
        [ "$y" = d ] || continue
        if ! pa_plain_id "$name"; then
            SPOOL_WITHHELD=$((SPOOL_WITHHELD + 1))
            continue
        fi
        cn_s=0 cn_t="" bad=0 ev=0
        while IFS=' ' read -r -d '' fs ft f; do
            [ "$f" = events.jsonl ] || continue
            ev=1
            if [[ $fs =~ ^[0-9]{1,18}$ && $ft =~ ^[0-9]{1,12}(\.[0-9]+)?$ ]]; then
                cn_s="$fs" cn_t="${ft%%.*}"
            else
                bad=1
            fi
        done < <(timeout 10 find "$SPOOL_DIR/$name" -mindepth 1 -maxdepth 1 -type f -printf '%s %T@ %f\0' 2> /dev/null)
        [ "$bad" = 0 ] || SPOOL_BAD=$((SPOOL_BAD + 1))
        acc="${gstate[$name]:-}"
        if [ -n "$acc" ] && { [ -z "$cn_t" ] || [ "$acc" -gt "$cn_t" ]; }; then cn_t="$acc"; fi
        SPOOL_CN+=("$name") SPOOL_SIZE+=("$cn_s") SPOOL_LAST+=("$cn_t") SPOOL_ACC+=("$acc") SPOOL_EV+=("$ev")
    done <<< "$list"
}

# fresh WALL: WALL is a time no older than STALL (and not in the future).
fresh() {
    local a
    a="$(age_of "${1:-}")"
    [ "$a" != - ] && [ "$a" -le "$STALL" ]
}

SHIP_STATE=""
row_ship() {
    local i p cdir sdir cur text rc ino off mt age unread=0 behind=() unchecked=() newest_state="" t
    local note state why="" cond="" fresh_n=0 own any=0 cn line quiet id
    case "$ROLE" in
        single | unknown)
            not_here 3 ship "not split"
            return 0
            ;;
        control | gateway)
            if [ "$SPOOL_OK" = 0 ]; then
                add_row 3 ship - - - '?' "spool not readable"
                return 0
            fi
            for i in "${!SPOOL_CN[@]}"; do
                ! fresh "${SPOOL_LAST[$i]}" || fresh_n=$((fresh_n + 1))
            done
            # The collectors the witness's light pass holds quiet, by opaque id.
            quiet=$'\n'"$(open_insts spool-quiet)"$'\n'
            for i in "${!SPOOL_CN[@]}"; do
                cn="$(braced "${SPOOL_CN[$i]}")"
                t="${SPOOL_LAST[$i]}"
                # Only another collector's arrival says the path to this node works.
                own=0
                ! fresh "$t" || own=1
                line="collector side not visible from here"
                [ "$((fresh_n - own))" -le 0 ] || line+="; others arriving"
                id="${IDS[collector/${SPOOL_CN[$i]}]:-}"
                if [[ $id =~ ^c[0-9a-f]{5,8}$ ]] && [[ $quiet == *$'\n'"$id"$'\n'* ]]; then
                    add_row 3 ship "$cn" "$(fmt_time "$t")" "$(fmt_age "$(age_of "$t")")" FAIL \
                        "quiet for longer than twice its longest gap (witness); $line" direct spool-quiet
                else
                    add_row 3 ship "$cn" "$(fmt_time "$t")" "$(fmt_age "$(age_of "$t")")" info "$line"
                fi
                any=1
            done
            [ "$any" = 1 ] || add_row 3 ship - - - info "no collector in the spool"
            return 0
            ;;
    esac
    # A collector: what the shipper has not sent yet, from its cursors, read as the shipper.
    unit_show shipper.service ActiveState SubState UnitFileState || {
        add_row 3 ship - - - '?' "systemctl did not answer"
        return 0
    }
    env_of PROPOLIS_SHIPPER_CURSOR_DIR "$SHIPPER_ENV"
    cdir="${ENV_V:-$STATUS_ROOT/var/lib/propolis/shipper/cursors}"
    env_of PROPOLIS_SHIPPER_STATE_DIR "$SHIPPER_ENV"
    sdir="${ENV_V:-$STATUS_ROOT/var/lib/propolis/shipper/state}"
    newest_state="$(timeout 10 find "$sdir" -mindepth 1 -maxdepth 1 -type f -name '*.json' -printf '%T@\n' 2> /dev/null | sort -n | tail -n 1)"
    newest_state="${newest_state%%.*}"
    [[ $newest_state =~ ^[0-9]{1,12}$ ]] || newest_state=""
    SHIP_STATE="$newest_state"
    for i in "${!LOG_PATH[@]}"; do
        p="${LOG_PATH[$i]}"
        file_facts "$p"
        [ "$F_TYPE" = regular ] || continue
        cur="$cdir/$(cursor_name "$p")"
        rc=0
        text="$(pa_read_as propolis-shipper "$cur" 4096)" || rc=$?
        if [ "$rc" = 3 ] && [ ! -e "$cur" ] && [ ! -L "$cur" ]; then
            ino="" off=0
        elif [ "$rc" != 0 ]; then
            unchecked+=("$(braced "${LOG_LABEL[$i]}") cursor $(read_why "$rc")")
            continue
        else
            ino="$(json_int "$text" inode)" off="$(json_int "$text" offset)"
            if [ -z "$off" ]; then
                unchecked+=("$(braced "${LOG_LABEL[$i]}") cursor unparsed")
                continue
            fi
        fi
        if [ -n "$ino" ] && [ "$ino" != "$F_INODE" ]; then
            # The log was rotated under the cursor. The shipper starts the new file at offset 0
            # once it notices, so a cursor younger than STALL is in between; an older one has
            # stalled, and the whole new file is unread.
            rc=0
            mt="$(pa_stat_as propolis-shipper %Y "$cur")" || rc=$?
            if [ "$rc" != 0 ] || ! [[ $mt =~ ^[0-9]{1,12}$ ]]; then
                unchecked+=("$(braced "${LOG_LABEL[$i]}") cursor $(read_why "$rc")")
                continue
            fi
            age="$(age_of "$mt")"
            if [ "$age" = - ] || [ "$age" -le "$STALL" ]; then
                unchecked+=("$(braced "${LOG_LABEL[$i]}") rotated, not resumed yet")
                continue
            fi
            off=0
        fi
        if [ "$off" -lt "$F_SIZE" ]; then
            unread=$((unread + F_SIZE - off))
            behind+=("$(braced "${LOG_LABEL[$i]}")")
        fi
    done
    if [ "$unread" -gt 0 ]; then
        state=ok note="unread $(human_bytes "$unread") in ${behind[*]}"
    elif [ "${#unchecked[@]}" -eq 0 ]; then
        state=idle note="nothing unread"
    else
        state=ok note="unread 0 B in the logs checked"
    fi
    if [ "${#unchecked[@]}" -gt 0 ]; then
        state='?'
        note+="; not checked: ${unchecked[*]}"
    fi
    if [ "$unread" -gt 0 ]; then
        t="$(age_of "$newest_state")"
        if [ "$t" = - ] || [ "$t" -gt "$STALL" ]; then
            state=FAIL why=progress cond=ship-failing
            note+="; last accepted batch $(fmt_age "$t") ago"
        fi
    fi
    # What the witness's light pass read in the shipper's journal: errors on three passes in a
    # row, and lines it dropped (shown only with RUST_LOG set).
    if [ "$(open_count ship-failing)" != 0 ]; then
        state=FAIL why=direct cond=ship-failing
        note+="; shipper errors on three passes in a row (witness)"
    fi
    [ "$(open_count ship-dropped)" = 0 ] || note+="; the shipper dropped lines (witness)"
    if [ "${U_UnitFileState:-}" = enabled ] && ! unit_up; then
        state=FAIL why=direct cond=ship-down
        note="shipper.service ${U_ActiveState:-?}; $note"
    fi
    add_row 3 ship "${#LOG_PATH[@]} logs" "$(fmt_time "$newest_state")" "$(fmt_age "$(age_of "$newest_state")")" \
        "$state" "$note" "$why" "$cond"
}

row_gateway() {
    local total=0 newest="" i fails warns state note why="" cond="" id who key dup=""
    case "$ROLE" in
        control | gateway) ;;
        collector)
            not_here 4 gateway "on the control node: run sudo propolis-status there"
            return 0
            ;;
        *)
            not_here 4 gateway "not split"
            return 0
            ;;
    esac
    if [ -n "$SPOOL_ENV_BAD" ] || [ "$SPOOL_OK" = 0 ]; then
        add_row 4 gateway - - - '?' "spool or gateway.env not readable"
        return 0
    fi
    unit_show gateway.service ActiveState SubState UnitFileState || {
        add_row 4 gateway - - - '?' "systemctl did not answer"
        return 0
    }
    for i in "${!SPOOL_CN[@]}"; do
        total=$((total + 10#${SPOOL_SIZE[i]}))
        if [ -n "${SPOOL_LAST[$i]}" ] && { [ -z "$newest" ] || [ "${SPOOL_LAST[$i]}" -gt "$newest" ]; }; then
            newest="${SPOOL_LAST[$i]}"
        fi
    done
    note="${#SPOOL_CN[@]} collectors in spool, $(human_bytes "$total")"
    [ "$SPOOL_WITHHELD" = 0 ] || note+="; $SPOOL_WITHHELD name withheld: not a plain id"
    fails="$(cc_ids fail spool-unlisted spool-label-sensor)"
    warns="$(cc_ids any spool-label-subsystem spool-label-other)"
    state=ok
    if [ "$SPOOL_BAD" -gt 0 ]; then
        state='?'
        note+="; $SPOOL_BAD collector listing not read"
    fi
    if [ -n "$warns" ]; then
        state=WARN cond=gateway-finding
        note+="; findings: $warns"
    fi
    if [ -n "$fails" ]; then
        state=FAIL why=direct cond=gateway-finding
        note+="; findings: $fails"
    fi
    # The gateway's line that a rebuilt batch was not stored, as the witness's light pass read it.
    while IFS= read -r id; do
        case "$id" in
            -) who="a collector not listed" key=gwdup:unlisted ;;
            c[0-9a-f]*)
                [[ $id =~ ^c[0-9a-f]{5,8}$ ]] || continue
                who="$(collector_of "$id")" key="gwdup:$id"
                ;;
            *) continue ;;
        esac
        dup+="${dup:+; }rebuilt batch dropped from $who, $(seen_count "$key") records counted lost (witness)"
    done <<< "$(open_insts gateway-dup)"
    if [ -n "$dup" ]; then
        if [ "$state" != FAIL ]; then state=WARN cond=gateway-dup; fi
        note+="; $dup"
    fi
    if [ "${U_UnitFileState:-}" = enabled ] && ! unit_up; then
        state=FAIL why=direct cond=gateway-down
        note="gateway.service ${U_ActiveState:-?}; $note"
    fi
    add_row 4 gateway "spool" "$(fmt_time "$newest")" "$(fmt_age "$(age_of "$newest")")" "$state" \
        "$(with_findings "$note")" "$why" "$cond"
}

# The console on loopback: READY_CODE (000 when it did not answer), READY_GAVE_UP (checked names).
READY_CODE="" READY_GAVE_UP="" READY_BODY="" METRICS_BODY="" CONSOLE_URL=""
console_base() {
    local bind host port
    env_of PROPOLIS_CONSOLE_BIND "$FLEET_ENV" "$PROPOLIS_ENV"
    bind="${ENV_V:-127.0.0.1:8080}"
    case "$bind" in
        \[*\]:*)
            host="${bind%%]*}" host="${host#[}" port="${bind##*]:}"
            ;;
        *:*) host="${bind%:*}" port="${bind##*:}" ;;
        *) return 1 ;;
    esac
    [[ $port =~ ^[0-9]{1,5}$ ]] || return 1
    case "$host" in
        127.0.0.1 | 0.0.0.0 | localhost) CONSOLE_URL="http://127.0.0.1:$port" ;;
        ::1 | ::) CONSOLE_URL="http://[::1]:$port" ;;
        *) return 1 ;;
    esac
}

# console_get PATH [HEADER_FILE]: the body then a last line with the HTTP code.
console_get() {
    local -a h=()
    [ -z "${2:-}" ] || h=(-H "@$2")
    timeout 10 curl -sS --max-time 5 --max-filesize 1048576 --proto '=http' "${h[@]}" -o - \
        -w '\n%{http_code}' "$CONSOLE_URL$1" 2> /dev/null | tr -d '\000'
}

ask_console() {
    local out name hdr token names n=0 more=0
    local -a gave=()
    if ! console_base; then
        READY_CODE=skip
        return 0
    fi
    out="$(console_get /ready)" || true
    READY_CODE="${out##*$'\n'}"
    [[ $READY_CODE =~ ^[0-9]{3}$ ]] || READY_CODE=000
    READY_BODY="${out%$'\n'*}"
    [ "$READY_BODY" != "$out" ] || READY_BODY=""
    if [[ $READY_BODY =~ \"gave_up\"[[:space:]]*:[[:space:]]*\[([^]]{0,2000})\] ]]; then
        # Split on commas by read, never by an unquoted expansion: whoever answers on the port
        # writes these names, and a `*` among them would be expanded as a pattern, as root.
        names="${BASH_REMATCH[1]//\"/}"
        names="${names//[$'\n\r\t']/ }"
        IFS=, read -r -a gave <<< "$names"
        READY_GAVE_UP=""
        for name in "${gave[@]}"; do
            name="${name#"${name%%[! ]*}"}"
            name="${name%"${name##*[! ]}"}"
            [ -n "$name" ] || continue
            n=$((n + 1))
            if [ "$n" -gt 32 ]; then
                more=$((more + 1))
                continue
            fi
            READY_GAVE_UP+="$(braced "$name") "
        done
        [ "$more" = 0 ] || READY_GAVE_UP+="and $more more withheld "
        READY_GAVE_UP="${READY_GAVE_UP% }"
        [ -n "$READY_GAVE_UP" ] || READY_GAVE_UP="{?}"
    fi
    env_of PROPOLIS_CONSOLE_METRICS_TOKEN "$FLEET_ENV" "$PROPOLIS_ENV"
    token="$ENV_V"
    hdr=""
    if [ -n "$token" ]; then
        # The token reaches curl in a file only root can read, never on its command line.
        hdr="$(mktemp 2> /dev/null)" || hdr=""
        if [ -n "$hdr" ]; then
            PA_CLEANUP+=("$hdr")
            printf 'Authorization: Bearer %s\n' "$token" > "$hdr" || hdr=""
        fi
    fi
    if [ -z "$token" ] || [ -n "$hdr" ]; then
        out="$(console_get /metrics "$hdr")" || true
        [ "${out##*$'\n'}" != 200 ] || METRICS_BODY="${out%$'\n'*}"
    fi
    [ -z "$hdr" ] || rm -f -- "$hdr"
}

# ready_words: what the console said, as the intake row and the views print it.
ready_words() {
    case "$READY_CODE" in
        200) printf '/ready 200' ;;
        503)
            if [ -n "$READY_GAVE_UP" ]; then
                printf '/ready 503 (gave up: %s)' "$READY_GAVE_UP"
            else
                printf '/ready 503 (database)'
            fi
            ;;
        skip) printf '/ready not checked (console not on loopback)' ;;
        notasked)
            if [ "$P_OK" = 1 ]; then
                printf '/ready not asked (daemon not running)'
            else
                printf '/ready not asked (daemon state not read)'
            fi
            ;;
        000) printf '/ready no answer' ;;
        '') printf '/ready -' ;;
        *) printf '/ready %s' "$READY_CODE" ;;
    esac
}

# The daemon unit, read once: P_* from systemctl show.
P_OK=0 P_UP=0
load_daemon() {
    if unit_show propolis.service ActiveState SubState Result UnitFileState InvocationID; then
        P_OK=1
        P_ACTIVE="$U_ActiveState" P_RESULT="$U_Result" P_FILE="$U_UnitFileState"
        P_INV="$U_InvocationID"
        P_UP=0
        if unit_up; then P_UP=1; fi
    fi
}

INTAKE_DOWN=0
row_intake() {
    local i p cdir text rc ino off mt age unread=0 stale=0 unchecked=() nocur=0 oldest_age="" state
    local note why="" cond="" fails warns ready=""
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here 5 intake "on the control node: run sudo propolis-status there"
        return 0
    fi
    if [ -n "$LOG_ENV_BAD" ]; then
        add_row 5 intake - - - '?' "${LOG_ENV_BAD##*/} cannot be read"
        return 0
    fi
    env_of PROPOLIS_CURSOR_DIR "$FLEET_ENV" "$PROPOLIS_ENV"
    cdir="${ENV_V:-$STATUS_ROOT/var/lib/propolis/cursors}"
    for i in "${!LOG_PATH[@]}"; do
        p="${LOG_PATH[$i]}"
        file_facts "$p"
        [ "$F_TYPE" = regular ] || continue
        rc=0
        text="$(pa_read_as propolis "$cdir/$(cursor_name "$p")" 4096)" || rc=$?
        if [ "$rc" = 3 ] && [ ! -e "$cdir/$(cursor_name "$p")" ] && [ ! -L "$cdir/$(cursor_name "$p")" ]; then
            nocur=$((nocur + 1))
            continue
        elif [ "$rc" != 0 ]; then
            unchecked+=("$(braced "${LOG_LABEL[$i]}") cursor $(read_why "$rc")")
            continue
        fi
        ino="$(json_int "$text" inode)" off="$(json_int "$text" offset)"
        if [ -z "$off" ]; then
            unchecked+=("$(braced "${LOG_LABEL[$i]}") cursor unparsed")
            continue
        fi
        rc=0
        mt="$(pa_stat_as propolis %Y "$cdir/$(cursor_name "$p")")" || rc=$?
        if [ "$rc" != 0 ] || ! [[ $mt =~ ^[0-9]{1,12}$ ]]; then
            # A cursor whose age is unknown is not an old one.
            unchecked+=("$(braced "${LOG_LABEL[$i]}") cursor $(read_why "$rc")")
            continue
        fi
        age="$(age_of "$mt")"
        if [ "$age" != - ] && { [ -z "$oldest_age" ] || [ "$age" -gt "$oldest_age" ]; }; then oldest_age="$age"; fi
        if [ -n "$ino" ] && [ "$ino" != "$F_INODE" ]; then
            off=0
        fi
        # An offset past the size (a truncation the cursor has not caught up with) is behind too.
        if [ "$off" -ne "$F_SIZE" ]; then
            [ "$off" -gt "$F_SIZE" ] || unread=$((unread + F_SIZE - off))
            if [ "$age" = - ] || [ "$age" -gt "$STALL" ]; then stale=$((stale + 1)); fi
        fi
    done
    # With the daemon stopped any local account may hold the console port: it gets neither the
    # metrics token nor a say in this row.
    if [ "$P_OK" = 1 ] && [ "$P_UP" = 1 ]; then
        ask_console
    else
        READY_CODE=notasked
    fi
    ready="$(ready_words)"
    note="$(human_bytes "$unread") behind (cursor files); $ready"
    [ "$nocur" = 0 ] || note+="; $nocur without a cursor yet"
    state=ok
    fails="$(cc_ids any intake-none intake-bad)"
    warns="$(cc_ids any intake-name intake-rel intake-nodir intake-duplabel intake-duppath intake-orphan intake-absent intake-wrongpath)"
    if [ -n "$warns" ]; then
        state=WARN cond=intake-finding
        note+="; findings: $warns"
    fi
    if [ "${#unchecked[@]}" -gt 0 ]; then
        state='?' cond=""
        note+="; not checked: ${unchecked[*]}"
    fi
    if [ "$stale" -gt 0 ]; then
        state=FAIL why=progress cond=intake-finding
        note+="; $stale behind with a cursor older than $(pa_dur "$STALL")"
    fi
    if [ -n "$fails" ]; then
        state=FAIL why=direct cond=intake-finding
        note+="; findings: $fails"
    fi
    if [ "$READY_CODE" = 503 ] && [ -n "$READY_GAVE_UP" ]; then
        state=FAIL why=direct cond=intake-down
    fi
    if [ "$P_OK" = 0 ]; then
        state='?' note="systemctl did not answer; $note"
    elif [ "$P_FILE" = enabled ] && [ "$P_UP" = 0 ]; then
        state=FAIL why=direct cond=intake-down INTAKE_DOWN=1
        note="propolis.service $P_ACTIVE (Result=$P_RESULT); $note"
    fi
    local last=""
    [ -z "$oldest_age" ] || last=$((PA_WALL - oldest_age))
    add_row 5 intake "${#LOG_PATH[@]} logs" "$(fmt_time "$last")" "$(fmt_age "$oldest_age")" "$state" \
        "$(with_findings "$note")" "$why" "$cond"
}

LEDGER_OK=0 LEDGER_CAUSE=""
row_ledger() {
    local where id at note state cond words open
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here 6 ledger "on the control node: run sudo propolis-status there"
        return 0
    fi
    pa_pg 10 'SELECT 1' > /dev/null
    LEDGER_CAUSE="$PA_PG_CAUSE"
    where="${PA_PG_WHERE:-local} database"
    case "$PA_PG_CAUSE" in
        -) ;;
        db.unreachable | db.auth | db.timeout)
            add_row 6 ledger "$where" - - FAIL "select 1: $PA_PG_CAUSE" direct ledger-down
            return 0
            ;;
        *)
            note="$PA_PG_CAUSE"
            [ -z "$PA_PG_WHY" ] || note="$PA_PG_WHY"
            [ "$PA_PG_WHY" != "daemon binary predates pg-exec" ] || note="daemon binary predates pg-exec"
            case "$PA_PG_WHY" in 'not trusted:'*) note+="; $STATUS_FIX" ;; esac
            add_row 6 ledger "$where" - - '?' "select 1: $note"
            return 0
            ;;
    esac
    LEDGER_OK=1
    pa_pg 10 'SELECT id, extract(epoch FROM ingested_at)::bigint FROM event ORDER BY id DESC LIMIT 1' > /dev/null
    id="${PA_PG_OUT%%|*}" at="${PA_PG_OUT#*|}"
    [[ $id =~ ^[0-9]{1,19}$ ]] || id=""
    [[ $at =~ ^[0-9]{1,12}$ ]] || at=""
    note="reads answer"
    [ -z "$id" ] || note="last event #$id"
    [ "$PA_PG_CAUSE" = - ] || note="reads answer; last event not read ($PA_PG_CAUSE)"
    note+="; writes not visible from shell (step 3)"
    # The witness's hourly reading of the database's state, and what it holds open of it: an old
    # transaction id, slots nearly full or lock waits warn here; they stop no stage.
    state=ok cond=""
    words="$(pg_state_words)"
    [ -z "$words" ] || note+="; $words"
    open="$(dbstate_open)"
    if [ -n "$open" ]; then
        state=WARN cond=ledger-state note+="; open: $open"
    fi
    add_row 6 ledger "$where" "$(fmt_time "$at")" "$(fmt_age "$(age_of "$at")")" "$state" "$note" "" "$cond"
}

# ledger_unread: why rows 7 and 8 were not read. Only a connection-class cause is an outage
# someone observed; a probe that could not run says so instead.
ledger_unread() {
    case "$LEDGER_CAUSE" in
        db.unreachable | db.auth | db.timeout) printf 'database not answering' ;;
        *) printf 'ledger not read (%s)' "${LEDGER_CAUSE:-?}" ;;
    esac
}

row_review() {
    local at n
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here 7 review "on the control node: run sudo propolis-status there"
        return 0
    fi
    if [ "$LEDGER_OK" = 0 ]; then
        add_row 7 review - - - '?' "$(ledger_unread)"
        return 0
    fi
    if ! pa_pg 10 'SELECT extract(epoch FROM max(surfaced_at))::bigint, count(*) FILTER (WHERE decided_at IS NULL) FROM review_queue' > /dev/null; then
        add_row 7 review queue - - '?' "query failed ($PA_PG_CAUSE)"
        return 0
    fi
    at="${PA_PG_OUT%%|*}" n="${PA_PG_OUT#*|}"
    [[ $at =~ ^[0-9]{1,12}$ ]] || at=""
    [[ $n =~ ^[0-9]{1,12}$ ]] || n="?"
    add_row 7 review queue "$(fmt_time "$at")" "$(fmt_age "$(age_of "$at")")" info "$n pending"
}

REPORTS_SQL='SELECT vendor, extract(epoch FROM max(submitted_at))::bigint, extract(epoch FROM max(submitted_at) FILTER (WHERE success))::bigint, (array_agg(response_status ORDER BY id DESC))[1] FROM vendor_submission WHERE id > (SELECT coalesce(max(id),0) - 5000 FROM vendor_submission) GROUP BY vendor'
# What the server would impose on a session of the daemon: the read-only default set for this
# database or this role (ALTER DATABASE/ROLE ... SET), which the probe's own option does not show.
LEDGER_RO_SQL="SELECT coalesce(string_agg(s, ','), 'not set') FROM pg_db_role_setting, unnest(setconfig) s WHERE setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database())) AND setrole IN (0, (SELECT oid FROM pg_roles WHERE rolname = current_user)) AND s LIKE 'default_transaction_read_only=%'"
# The view's table adds, per vendor, the attempts since its last success within the same window.
REPORTS_VIEW_SQL='SELECT v.vendor, extract(epoch FROM max(v.submitted_at))::bigint, extract(epoch FROM max(v.submitted_at) FILTER (WHERE v.success))::bigint, (array_agg(v.response_status ORDER BY v.id DESC))[1], count(*) FILTER (WHERE v.id > coalesce(s.last_ok, 0)) FROM vendor_submission v LEFT JOIN (SELECT vendor, max(id) AS last_ok FROM vendor_submission WHERE success AND id > (SELECT coalesce(max(id),0) - 5000 FROM vendor_submission) GROUP BY vendor) s ON s.vendor = v.vendor WHERE v.id > (SELECT coalesce(max(id),0) - 5000 FROM vendor_submission) GROUP BY v.vendor, s.last_ok'
VENDORS=()
row_reports() {
    local v last code n=0 newest="" parts=() name
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here 8 reports "on the control node: run sudo propolis-status there"
        return 0
    fi
    if [ "$LEDGER_OK" = 0 ]; then
        add_row 8 reports - - - '?' "$(ledger_unread)"
        return 0
    fi
    if ! pa_pg 10 "$REPORTS_SQL" > /dev/null; then
        add_row 8 reports - - - '?' "query failed ($PA_PG_CAUSE)"
        return 0
    fi
    while IFS='|' read -r v last _ code; do
        [ -n "$v" ] || continue
        n=$((n + 1))
        name="$(braced "$v")"
        ! pa_plain_id "$v" || VENDORS+=("$v")
        [[ $last =~ ^[0-9]{1,12}$ ]] || last=""
        [[ $code =~ ^[0-9]{3}$ ]] || code="-"
        if [ -n "$last" ] && { [ -z "$newest" ] || [ "$last" -gt "$newest" ]; }; then newest="$last"; fi
        parts+=("$name $code $(fmt_time "$last")")
    done <<< "$PA_PG_OUT"
    add_row 8 reports "$n vendors" "$(fmt_time "$newest")" "$(fmt_age "$(age_of "$newest")")" info \
        "$(
            IFS='|'
            printf '%s' "${parts[*]}" | sed 's/|/ - /g'
        )${parts[*]:+; }first attempt per row"
}

FEED_DIR=""
row_feed() {
    local mt rc
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here 9 feed "on the control node: run sudo propolis-status there"
        return 0
    fi
    env_of PROPOLIS_FEED_ENABLED "$FLEET_ENV" "$PROPOLIS_ENV"
    if [ "${ENV_V,,}" = false ]; then
        not_here 9 feed "feed off (PROPOLIS_FEED_ENABLED=false)"
        return 0
    fi
    env_of PROPOLIS_FEED_OUTPUT_DIR "$FLEET_ENV" "$PROPOLIS_ENV"
    FEED_DIR="${ENV_V:-$STATUS_ROOT/var/lib/propolis/feed/current}"
    if [ ! -e "$FEED_DIR/manifest.json" ] && [ ! -L "$FEED_DIR/manifest.json" ]; then
        add_row 9 feed manifest - - info "no manifest yet"
        return 0
    fi
    rc=0
    mt="$(pa_stat_as propolis %Y "$FEED_DIR/manifest.json")" || rc=$?
    if [ "$rc" != 0 ] || ! [[ $mt =~ ^[0-9]{1,12}$ ]]; then
        add_row 9 feed manifest - - '?' "manifest $(read_why "$rc")"
        return 0
    fi
    add_row 9 feed manifest "$(fmt_time "$mt")" "$(fmt_age "$(age_of "$mt")")" info ""
}

PUB_MT="" PUB_EXPECTED=""
row_publish() {
    local marker out ty mt sched rc note expected wit state why cond
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here 10 publish "on the control node: run sudo propolis-status there"
        return 0
    fi
    marker="$STATUS_ROOT/var/lib/propolis/blocklist-status/last-pushed"
    mt=""
    if [ -e "$marker" ] || [ -L "$marker" ]; then
        out="$(timeout 5 stat -c '%F|%Y' -- "$marker" 2> /dev/null)" || out=""
        ty="${out%%|*}"
        case "$ty" in 'regular file' | 'regular empty file') mt="${out#*|}" ;; *) mt="?" ;; esac
    fi
    rc=0
    pa_push_scheduler > /dev/null || rc=$?
    sched="$PA_SCHED $PA_SCHED_N"
    env_of PROPOLIS_OPS_FEED_PUSH_EXPECTED "$PROPOLIS_ENV"
    expected="push not expected"
    case "${ENV_V,,}" in true | 1 | yes | on) expected="push expected" ;; esac
    PUB_MT="$mt" PUB_EXPECTED="$expected"
    # What the witness's hourly pass holds open on the push: a push over six hours behind the
    # feed fails the stage, whatever this walk could read itself.
    wit="" state=info why="" cond=""
    if [ "$(open_count push-failing)" != 0 ]; then
        wit="public push failing (witness); " state=FAIL why=direct cond=push-failing
    fi
    [ "$(open_count push-unscheduled)" = 0 ] || wit+="a push is expected and nothing runs it (witness); "
    if [ "$PA_SCHED" != none ]; then
        note="scheduler found ($PA_SCHED); $expected"
    elif [ "$rc" != 0 ]; then
        [ "$state" = FAIL ] || state='?'
        add_row 10 publish - - - "$state" "${wit}a crontab or unit file could not be read; $expected" "$why" "$cond"
        return 0
    else
        note="no scheduler; $expected"
    fi
    if [ "$mt" = "?" ]; then
        [ "$state" = FAIL ] || state='?'
        add_row 10 publish "${sched%% *}" - - "$state" "${wit}last-pushed is not a regular file; $note" "$why" "$cond"
        return 0
    fi
    [ -n "$mt" ] || note="never pushed; $note"
    add_row 10 publish "${sched%% *}" "$(fmt_time "$mt")" "$(fmt_age "$(age_of "$mt")")" "$state" \
        "$wit$note" "$why" "$cond"
}

# ---- the rails ------------------------------------------------------------------------------

# The ALERTS facts, shared by the header and the alert rail.
HOOK_POSTS=0
A_TARGET="" A_MONITOR="" A_QUEUE="" A_UNDELIVERED="" A_SINCE="" A_QUEUE_N=0 A_UNDELIVERED_N=0
A_QUEUE_OLDEST="" A_GATE="" A_GATE_CHECKED=- A_RC_NOTE="" A_DAEMON_PRIVATE=0 A_VERIFIED="" A_OLDCONF=0

# load_readcheck_facts: the gate (from the stored read check and the settings; no network), when
# the check was last attempted, one note per stored line (the shell's and the daemon's target, or
# one line for both), and whether the daemon's target (propolis.env, where the legacy hook and the
# daemon post) is proven private: a refusal for its current binding decided within 24 h, an
# attempt within 3 h, and the URL https.
load_readcheck_facts() {
    local role b a word
    pa_state_read readcheck > /dev/null
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" readcheck "* ]]; then
        A_GATE="?"
        A_RC_NOTE="readcheck unreadable"
        return 0
    fi
    PA_ROLE="$ROLE"
    pa_gate > /dev/null
    A_GATE="$PA_GATE" A_GATE_CHECKED="$PA_GATE_CHECKED"
    for role in shell daemon; do
        if [ "$role" = shell ]; then
            [ "$PA_TARGET" = 1 ] || continue
            b="$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" || b=""
        else
            [ "${PA_D_TARGET:-0}" = 1 ] || continue
            b="$(pa_readcheck_binding "$PA_D_URL" "$PA_D_TOPIC")" || b=""
        fi
        _pa_rc_line "$role" || continue
        # The gate's own terms, as pa_gate holds the shell target to them (a refusal decided within
        # a day, an attempt within three hours, over https): over plain HTTP a 403 proves nothing,
        # and a refusal no attempt has confirmed for three hours is no longer known.
        if [ "$role" = daemon ] && [ "$PA_RCL_BIND" = "$b" ] && [ "$PA_RCL_DCLASS" = refused ] \
            && [[ ${PA_D_URL:-} == https://* ]]; then
            a="$(pa_age "$PA_RCL_DSTAMP")"
            if [ "$a" -ge 0 ] && [ "$a" -le 86400 ]; then
                a="$(pa_age "$PA_RCL_ASTAMP")"
                [ "$a" -lt 0 ] || [ "$a" -gt 10800 ] || A_DAEMON_PRIVATE=1
            fi
        fi
        # A both line was named once, for the shell target.
        [ "$role" = shell ] || [ "$PA_RCL_ROLE" != both ] || continue
        if [ "$PA_RCL_BIND" != "$b" ]; then
            word="not checked for the current target"
        elif [ "$PA_RCL_DCLASS" = - ]; then
            word="no answer yet (last attempt $PA_RCL_ACLASS)"
        else
            word="$PA_RCL_DCLASS"
            [ "$PA_RCL_DCLASS" != readable ] || word="READABLE"
            word+=" (checked $(fmt_time "${PA_RCL_DSTAMP%%/*}"))"
            [ "$PA_RCL_TOKEN" = - ] || word+=", token $PA_RCL_TOKEN"
        fi
        A_RC_NOTE+="${A_RC_NOTE:+; }${PA_RCL_ROLE/both/shell and daemon} topic $word"
    done
}

load_alert_facts() {
    local f first text rc dir n=0 oldest="" list name
    pa_settings_load
    hook_posts
    load_readcheck_facts
    A_VERIFIED="$(verified_words)"
    if (daemon_config_older); then A_OLDCONF=1; fi
    if [ -e "$PROPOLIS_ENV" ] && { [ ! -f "$PROPOLIS_ENV" ] || [ ! -r "$PROPOLIS_ENV" ]; }; then
        A_TARGET="?"
    elif [ "$PA_TARGET" = 1 ]; then
        A_TARGET="ntfy from $PA_TARGET_SRC"
    elif [ "$HOOK_POSTS" = 1 ]; then
        A_TARGET="none for the shell senders; today's failure hook still posts"
    else
        A_TARGET="none"
    fi
    [ -z "$PA_INVALID" ] || A_TARGET+=" (invalid value ignored: $PA_INVALID)"
    if [ "$HAS_DAEMON" = 0 ]; then
        A_MONITOR=- A_QUEUE=-
    else
        env_of PROPOLIS_OPS_ENABLED "$PROPOLIS_ENV"
        OPS_ON=0
        case "${ENV_V,,}" in true | 1 | yes | on) OPS_ON=1 ;; esac
        if [ "$OPS_ON" = 0 ]; then
            A_MONITOR=off
        elif [ "$P_OK" = 0 ]; then
            A_MONITOR="?"
        elif [ "$P_UP" = 1 ]; then
            A_MONITOR=on
        else
            A_MONITOR=down
        fi
        env_of PROPOLIS_CURSOR_DIR "$FLEET_ENV" "$PROPOLIS_ENV"
        f="${ENV_V:-$STATUS_ROOT/var/lib/propolis/cursors}/ops-alert-undelivered.json"
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then
            A_QUEUE=empty
        else
            rc=0
            text="$(pa_read_as propolis "$f" 262144)" || rc=$?
            if [ "$rc" = 0 ]; then
                A_QUEUE_N="$(printf '%s' "$text" | grep -o '"first_failed_unix":' | wc -l)"
                A_QUEUE="$A_QUEUE_N"
                [ "$A_QUEUE_N" != 0 ] || A_QUEUE=empty
                A_QUEUE_OLDEST="$(printf '%s' "$text" | grep -o '"first_failed_unix":[[:space:]]*[0-9]\{1,12\}' \
                    | grep -o '[0-9]*$' | sort -n | sed -n 1p)"
            else
                A_QUEUE="? ($(read_why "$rc"))"
            fi
        fi
    fi
    # The legacy hook's own record of alerts that did not go out, one file per unit, written by
    # root (deploy/alert.sh undelivered): `<first epoch> <count> <logged epoch>`.
    dir="$STATUS_ROOT/run/propolis-alert/undelivered"
    if [ -d "$dir" ] && [ ! -L "$dir" ]; then
        if list="$(timeout 5 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' 2> /dev/null)"; then
            while IFS= read -r name; do
                [[ $name =~ ^[A-Za-z0-9@._:-]{1,200}$ ]] || continue
                n=$((n + 1))
                first=""
                read -r first _ < "$dir/$name" 2> /dev/null || true
                if [[ $first =~ ^[0-9]{1,12}$ ]] && { [ -z "$oldest" ] || [ "$first" -lt "$oldest" ]; }; then
                    oldest="$first"
                fi
            done <<< "$list"
            A_UNDELIVERED_N="$n" A_UNDELIVERED="$n" A_SINCE="$oldest"
        else
            A_UNDELIVERED="?"
        fi
    else
        A_UNDELIVERED=0
    fi
}

rail_alert() {
    local state=ok note="" cond="" inst=ntfy
    [ "$PA_TARGET" = 1 ] || [ "$HOOK_POSTS" = 1 ] || inst=journal
    if [ "$A_TARGET" = "?" ]; then
        state='?' note="propolis.env cannot be read"
    elif [ "$HOOK_POSTS" = 1 ]; then
        # The hook still posts, a collector's included: the journal is not where its alerts go.
        state=WARN cond=alert-target
        note="the shell senders $(hook_diff_words); today's failure hook still posts to it (see sudo propolis-status --setup)"
    elif [ "$PA_TARGET" != 1 ]; then
        if [ "$ROLE" = collector ]; then
            state=info note="no push path here (collector default)"
        else
            state=WARN cond=alert-target note="no push target: the failure hook writes its alerts to the journal"
        fi
    fi
    # On a collector alert.env is read only by the v2 senders: under legacy the operator who
    # wrote it is paged by nothing it says.
    if [ "$ROLE" = collector ] && { [ -e "$PA_ENV_DIR/alert.env" ] || [ -L "$PA_ENV_DIR/alert.env" ]; }; then
        [ "$state" != info ] || note=""
        [ "$state" = '?' ] || state=WARN
        cond=alert-target note="${note:+$note; }alert.env present, profile legacy: it acts only under v2"
    fi
    # The hook-posts note already names the settings it reads otherwise.
    [ -z "$PA_INVALID" ] || [ "$HOOK_POSTS" = 1 ] || {
        state=WARN cond=alert-target
        note="${note:+$note; }invalid value ignored: $PA_INVALID"
    }
    # The gate holds full detail back until a stored read check proves the topic refuses
    # anonymous reads; the daemon's own topic (propolis.env), where today's hook sends host and
    # unit names and the daemon its titles, is judged apart, so a private shell topic cannot hide
    # a readable daemon topic.
    if [ "$A_GATE" = "?" ]; then
        [ "$state" = WARN ] || state='?'
        note="${note:+$note; }readcheck cannot be read"
    else
        if [ "$PA_TARGET" = 1 ] && [ "$A_GATE" != full ]; then
            [ "$state" = '?' ] || state=WARN
            cond="${cond:-alert-target}" note="${note:+$note; }gate ${A_GATE}"
        fi
        if [ "${PA_D_TARGET:-0}" = 1 ] && [ "$A_DAEMON_PRIVATE" = 0 ]; then
            # The hook is named only where its own reader finds this URL and topic, the daemon
            # only where one runs.
            local hook_same=0 dnote=""
            if [ -n "$PA_HOOK_URL" ] && [ "$PA_HOOK_TOPIC_SET" = 1 ] \
                && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_URL "* ]] \
                && [[ " $PA_HOOK_DIFF " != *" PROPOLIS_OPS_NTFY_TOPIC "* ]]; then
                hook_same=1
            fi
            if [ "$hook_same" = 1 ] && [ "$HAS_DAEMON" = 0 ]; then
                dnote="legacy hook carries host and unit names"
            elif [ "$hook_same" = 1 ]; then
                dnote="legacy hook carries host and unit names; daemon titles name this host's software (until step 3)"
            elif [ "$HAS_DAEMON" = 1 ]; then
                dnote="daemon titles name this host's software (until step 3)"
            fi
            if [ -n "$dnote" ]; then
                [ "$state" = '?' ] || state=WARN
                cond="${cond:-alert-target}"
                note="${note:+$note; }$dnote"
            fi
        fi
    fi
    [ -z "$A_RC_NOTE" ] || note="${note:+$note; }$A_RC_NOTE"
    if [ "$A_UNDELIVERED" = "?" ]; then
        state='?' note="${note:+$note; }undelivered list cannot be read"
    elif [ "$A_UNDELIVERED_N" -gt 0 ]; then
        state=WARN cond=alert-path note="${note:+$note; }$A_UNDELIVERED_N units with an undelivered failure alert"
    fi
    if [ "$A_QUEUE_N" -gt 0 ]; then
        state=WARN cond=alert-path note="${note:+$note; }daemon queue $A_QUEUE_N"
    fi
    case "$A_QUEUE" in
        '?'*) [ "$state" = WARN ] || state='?' note="${note:+$note; }daemon queue $A_QUEUE" ;;
    esac
    # The witness opened alert-path: the legacy hook logged an alert it could not deliver, or a
    # failure hook itself failed.
    if open_record alert:shell; then
        state=FAIL cond=alert-path note="alert-path open: failure alerts are not leaving the host${note:+; $note}"
    fi
    [ -n "$note" ] || note="failure hook legacy; daemon queue $A_QUEUE"
    add_row "" alert "$inst" - - "$state" "$note" "" "$cond"
}

# open_record KEY: the witness's record of KEY is open or acknowledged.
open_record() {
    local t k st
    while IFS=$'\t' read -r t _ k _ _ _ _ st _; do
        [ "$t" = I ] && [ "$k" = "$1" ] || continue
        case "$st" in open | acked) return 0 ;; esac
    done <<< "$INCIDENTS_BODY"
    return 1
}

# open_tools: the checks whose tool-unusable record is open (tool:<check>, config-check aside:
# that is cc-stopped on the witness rail), space separated.
open_tools() {
    local t k kind st out=""
    while IFS=$'\t' read -r t _ k kind _ _ _ st _; do
        [ "$t" = I ] && [ "$kind" = tool-unusable ] && [[ $k == tool:* ]] || continue
        case "$st" in open | acked) ;; *) continue ;; esac
        pa_ok_field "$k" || continue
        out+="${out:+ }${k#tool:}"
    done <<< "$INCIDENTS_BODY"
    printf '%s' "$out"
}

# open_vols: the filesystems the witness's hourly pass records as filling or full soon, by their
# opaque mount id, `volume <id> filling` or `volume <id> full soon`, joined by `; `.
open_vols() {
    local t k kind inst st out=""
    while IFS=$'\t' read -r t _ k kind _ inst _ st _; do
        [ "$t" = I ] && [[ $k == vol:* ]] || continue
        case "$st" in open | acked) ;; *) continue ;; esac
        [[ $inst =~ ^m[0-9a-f]{5,8}$ ]] || inst="?"
        case "$kind" in
            volume-full-soon) out+="${out:+; }volume $inst full soon" ;;
            *) out+="${out:+; }volume $inst filling" ;;
        esac
    done <<< "$INCIDENTS_BODY"
    printf '%s' "$out"
}

# open_insts KIND: the instance of each open or acknowledged record of KIND, one a line (`-` for a
# record that names none).
open_insts() {
    local t kind inst st
    while IFS=$'\t' read -r t _ _ kind _ inst _ st _; do
        [ "$t" = I ] && [ "$kind" = "$1" ] || continue
        case "$st" in open | acked) printf '%s\n' "${inst:--}" ;; esac
    done <<< "$INCIDENTS_BODY"
}

# collector_of ID: the braced name of the collector in the spool whose opaque id is ID, else `a
# collector not in the spool`. Only here, on this host, does an id meet its name.
collector_of() {
    local k
    for k in "${!IDS[@]}"; do
        [[ $k == collector/* ]] && [ "${IDS[$k]}" = "$1" ] || continue
        braced "${k#collector/}"
        return 0
    done
    printf 'a collector not in the spool'
}

OBSERVE_BODY="" OBSERVE_READ=0

# seen_count KEY: what the witness's light pass counted against KEY's open record (the last field
# of its observe line seen:KEY: the records the gateway counted lost), 0 when none can be read.
seen_count() {
    local t name n out=0
    if [ "$OBSERVE_READ" = 0 ]; then
        OBSERVE_BODY="$(pa_state_read observe)"
        OBSERVE_READ=1
    fi
    while IFS=$'\t' read -r t name _ _ _ n _; do
        [ "$t" = P ] && [ "$name" = "seen:$1" ] && [[ ${n:-} =~ ^[0-9]{1,9}$ ]] || continue
        out=$((10#$n))
    done <<< "$OBSERVE_BODY"
    printf '%s' "$out"
}

# open_count KIND: how many of the witness's records of KIND are open or acknowledged.
open_count() {
    local t kind st n=0
    while IFS=$'\t' read -r t _ _ kind _ _ _ st _; do
        [ "$t" = I ] && [ "$kind" = "$1" ] || continue
        case "$st" in open | acked) n=$((n + 1)) ;; esac
    done <<< "$INCIDENTS_BODY"
    printf '%s' "$n"
}

# pg_state_words: the database's state as the witness's hourly pass last read it (meta pg_state),
# for the ledger row: transaction-id age, connections of the usable slots, lock waits over 120 s
# and the size; nothing when none was read.
pg_state_words() {
    local v="${META[pg_state]:-}"
    [[ $v =~ ^([0-9]{1,12})/[0-9a-f-]{1,8}/[0-9]{1,10}/([0-9]{1,18})/([0-9]{1,9})/([0-9]{1,9})/([0-9]{1,9})/([0-9]{1,18})$ ]] || return 0
    printf 'hourly %s: xid age %s, slots %s of %s, lock waits %s, size %s' "$(fmt_time "${BASH_REMATCH[1]}")" \
        "$((10#${BASH_REMATCH[2]}))" "$((10#${BASH_REMATCH[3]}))" "$((10#${BASH_REMATCH[4]}))" \
        "$((10#${BASH_REMATCH[5]}))" "$(human_bytes "$((10#${BASH_REMATCH[6]}))")"
}

# dbstate_open: the database states the hourly pass records as open: xid, slots, locks.
dbstate_open() {
    local t k st out=""
    while IFS=$'\t' read -r t _ k _ _ _ _ st _; do
        [ "$t" = I ] && [[ $k == dbstate:* ]] || continue
        case "$st" in open | acked) ;; *) continue ;; esac
        case "${k#dbstate:}" in xid | slots | locks) out+="${out:+ }${k#dbstate:}" ;; esac
    done <<< "$INCIDENTS_BODY"
    printf '%s' "$out"
}

B_SUCCESS="" B_FAILURE="" B_STEP="" B_SET=""
rail_backup() {
    local dir s f fails warns state=ok note="" cond="" t
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here "" backup "the backup runs on the control node"
        return 0
    fi
    dir="$STATUS_ROOT/var/lib/propolis/backup-status"
    s="$(root_read "$dir/last-success" 4096)" || s=""
    f="$(root_read "$dir/last-failure" 4096)" || f=""
    t="$(json_str "$s" completed_at)"
    [ -z "$t" ] || B_SUCCESS="$(date -u -d "$t" +%s 2> /dev/null)" || B_SUCCESS=""
    t="$(json_str "$f" failed_at)"
    [ -z "$t" ] || B_FAILURE="$(date -u -d "$t" +%s 2> /dev/null)" || B_FAILURE=""
    B_STEP="$(json_str "$f" step | tr -c ' -~' '?' | cut -b 1-80)"
    B_SET="$(json_str "$s" set)"
    pa_plain_id "$B_SET" || B_SET=""
    unit_show propolis-backup.timer UnitFileState NextElapseUSecRealtime || U_UnitFileState="?"
    note="${B_SET:+set $B_SET}"
    if [ -z "$B_SUCCESS" ]; then
        state=WARN cond=backup-failed note="no good backup recorded"
    elif [ "$(age_of "$B_SUCCESS")" = - ] || [ "$(age_of "$B_SUCCESS")" -gt "$BACKUP_STALE" ]; then
        state=WARN cond=backup-failed note="last good backup $(fmt_age "$(age_of "$B_SUCCESS")") ago${note:+; $note}"
    fi
    case "$U_UnitFileState" in
        enabled) ;;
        '?') [ "$state" = WARN ] || state='?' note="${note:+$note; }timer state not read" ;;
        *) state=WARN cond=backup-failed note="${note:+$note; }propolis-backup.timer ${U_UnitFileState:-not installed}" ;;
    esac
    warns="$(cc_ids warn backup-headroom backup-timer-enabled backup-plaintext backup-never)"
    [ -z "$warns" ] || {
        [ "$state" = FAIL ] || state=WARN
        cond=backup-failed note="${note:+$note; }findings: $warns"
    }
    fails="$(cc_ids fail backup-timer backup-stale backup-failing backup-age-missing)"
    if [ -n "$B_FAILURE" ] && { [ -z "$B_SUCCESS" ] || [ "$B_FAILURE" -gt "$B_SUCCESS" ]; }; then
        state=FAIL cond=backup-failed note="last run failed while ${B_STEP:-?}; ${note}"
    fi
    if [ -n "$fails" ]; then
        state=FAIL cond=backup-failed note="${note:+$note; }findings: $fails"
    fi
    # What the witness holds open on the backups: a run that has gone on past its limit, fewer
    # sets than kept, an off-host pull that stopped. The runbook explains all three under
    # backup-hung; a rail already warning for another reason keeps that reason's section.
    if [ "$(open_count backup-hung)" != 0 ]; then
        state=FAIL cond=backup-hung note="${note:+$note; }a backup run has not ended (witness)"
    fi
    if [ "$(open_count backup-retention)" != 0 ]; then
        t="fewer sets than kept"
        if [[ ${META[backup_sets]:-} =~ ^([0-9]{1,6})/([0-9]{1,3})$ ]]; then
            t="sets $((10#${BASH_REMATCH[1]})) of $((10#${BASH_REMATCH[2]}))"
        fi
        case "$state" in FAIL | WARN) ;; *) state=WARN cond=backup-hung ;; esac
        note="${note:+$note; }$t (witness)"
    fi
    if [ "$(open_count backup-offhost)" != 0 ]; then
        t="never seen"
        if [[ ${META[pull_last]:-} =~ ^([0-9]{1,12})/ ]]; then t="$(fmt_time "${BASH_REMATCH[1]}")"; fi
        case "$state" in FAIL | WARN) ;; *) state=WARN cond=backup-hung ;; esac
        note="${note:+$note; }a set has waited over 72 h for the off-host pull, last served $t (witness)"
    fi
    add_row "" backup nightly "$(fmt_time "$B_SUCCESS")" "$(fmt_age "$(age_of "$B_SUCCESS")")" "$state" \
        "$(with_findings "${note%; }")" direct "$cond"
}

rail_chain() {
    local note="verified by the daemon every 6 h (PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS); its verdict is in daemon memory until step 3"
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here "" chain "the ledger is on the control node"
        return 0
    fi
    if [ -n "$B_SUCCESS" ] && { [ -z "$B_FAILURE" ] || [ "$B_SUCCESS" -gt "$B_FAILURE" ]; }; then
        note+="; backup $(fmt_time "$B_SUCCESS") checked the ledger against earlier sets' chain heads"
    fi
    add_row "" chain - - - info "$note"
}

rail_host() {
    local state=ok note="" cond="" d use worst="" first="" sync out step lw k flag tools vols changes
    local -a dirs=() names=()
    for d in /var/lib/propolis /var/log/propolis /var/spool/propolis; do
        [ ! -d "$STATUS_ROOT$d" ] || dirs+=("$STATUS_ROOT$d") names+=("$d")
    done
    # df -P prints one line per directory asked about, in order, so the k-th line is the k-th
    # directory whatever filesystem holds it.
    for flag in -P -Pi; do
        [ "${#dirs[@]}" -gt 0 ] || break
        if ! out="$(timeout 10 df "$flag" -- "${dirs[@]}" 2> /dev/null)"; then
            [ "$flag" = -Pi ] || state='?' note="df did not answer; "
            continue
        fi
        k=0
        while read -r _ _ _ _ use _; do
            use="${use%\%}"
            d="${names[$k]:-?}"
            k=$((k + 1))
            [[ $use =~ ^[0-9]{1,3}$ ]] || continue
            if [ "$flag" = -P ]; then
                [ -n "$first" ] || first="$d ${use}% used; "
                [ "$((100 - use))" -ge "$LOW_DISK" ] || worst+="$d ${use}% used; "
            else
                [ "$((100 - use))" -ge "$LOW_DISK" ] || worst+="$d inodes ${use}% used; "
            fi
        done < <(printf '%s\n' "$out" | tail -n +2)
    done
    if [ -n "$worst" ]; then
        state=WARN cond=host-volume
    fi
    note+="${worst:-$first}"
    # timedatectl asks systemd-timedated over D-Bus, which can hang like any system call here.
    sync="$(timeout 10 timedatectl show -p NTPSynchronized 2> /dev/null)" || sync=""
    sync="${sync#NTPSynchronized=}"
    case "$sync" in
        yes)
            note+="clock synchronized"
            HOST_SYNC=synchronized
            ;;
        no)
            [ "$state" = WARN ] || cond='host-clock'
            state=WARN note+="clock not synchronized"
            HOST_SYNC="not synchronized"
            ;;
        *)
            [ "$state" = WARN ] || state='?'
            note+="clock sync not read"
            HOST_SYNC="sync not read"
            ;;
    esac
    step="${META[clock_step]:-}"
    if [[ $step =~ ^([0-9]{1,12})/[0-9a-f-]{1,8}/[0-9]{1,10}/([+-][0-9]{1,12})$ ]] \
        && [ "$(age_of "${BASH_REMATCH[1]}")" != - ] && [ "$(age_of "${BASH_REMATCH[1]}")" -le 86400 ]; then
        [ "$state" = WARN ] || cond='host-clock'
        HOST_STEP="stepped ${BASH_REMATCH[2]} s at $(fmt_time "${BASH_REMATCH[1]}")"
        state=WARN note+="; clock $HOST_STEP"
    fi
    salt_check
    case "${META[where]:-}" in
        run)
            [ "$state" = WARN ] || cond='host-state'
            state=WARN note+="; state written to /run only (the disk refused it)"
            ;;
        none)
            state=FAIL cond=host-state note+="; state not persisted anywhere"
            ;;
    esac
    lw="$(lockwait_count)"
    if [ "$lw" -gt 0 ]; then
        [ "$state" = WARN ] || [ "$state" = FAIL ] || cond='host-state'
        [ "$state" = FAIL ] || state=WARN
        note+="; state lock busy ($lw passes)"
    fi
    # A check the witness could not make on three passes in a row: what it watches through that
    # check is unseen until it can run again.
    tools="$(open_tools)"
    if [ -n "$tools" ]; then
        [ "$state" = WARN ] || [ "$state" = FAIL ] || cond='host-tool'
        [ "$state" = FAIL ] || state=WARN
        note+="; a check cannot run: $tools"
    fi
    # The witness's hourly pass judges every store, with a projection from a week of samples;
    # the opaque ids map to mount points in the host view.
    vols="$(open_vols)"
    if [ -n "$vols" ]; then
        [ "$state" = WARN ] || [ "$state" = FAIL ] || cond='host-volume'
        [ "$state" = FAIL ] || state=WARN
        note+="; $vols"
    fi
    # Recorded, not judged here: a NOTICE that a change waits for a restart or a reload.
    changes="$(open_count change-pending)"
    [ "$changes" = 0 ] || note+="; changed, not in force: $changes units (host view)"
    add_row "" host volumes - - "$state" "$note" direct "$cond"
}

HOST_SYNC="" HOST_STEP="" HOST_SALT=""

# salt_check: sets HOST_SALT, for the host view. A host cloned from another keeps the original's
# salt and so shares every opaque id with it, while its machine id is written anew. A salt older
# than /etc/machine-id is therefore worth saying, and only saying: it never changes the host row.
# The journal's oldest boot is no measure (it moves as the journal is trimmed, and would warn on
# every long-lived host), and a machine id can be rewritten on a host that was never cloned.
salt_check() {
    local salt_t="" id_t=""
    if [ "$SALT" = 0 ]; then
        HOST_SALT="none yet"
        return 0
    fi
    HOST_SALT="present"
    salt_t="$(timeout 5 stat -c %Y -- "$PA_STATE/id-salt" 2> /dev/null)" || salt_t=""
    [[ $salt_t =~ ^[0-9]{1,12}$ ]] || return 0
    id_t="$(timeout 5 stat -c %Y -- "$STATUS_ROOT/etc/machine-id" 2> /dev/null)" || id_t=""
    [[ $id_t =~ ^[0-9]{1,12}$ ]] || return 0
    [ "$salt_t" -ge "$id_t" ] || HOST_SALT="present, older than /etc/machine-id (a host cloned from another shares its ids)"
}

# lockwait_count: the largest count in /run/propolis-witness/lockwait, 0 when absent.
lockwait_count() {
    local f="$PA_RUN/lockwait" t c max=0
    [ -f "$f" ] && [ ! -L "$f" ] || {
        printf 0
        return 0
    }
    while read -r t c _; do
        [[ $t =~ ^[a-z]{1,16}$ && $c =~ ^[0-9]{1,9}$ ]] || continue
        [ "$((10#$c))" -le "$max" ] || max=$((10#$c))
    done < <(root_read "$f" 4096)
    printf '%s' "$max"
}

rail_monitor() {
    if [ "$HAS_DAEMON" = 0 ]; then
        not_here "" monitor "no daemon on this host"
        return 0
    fi
    if [ "$P_OK" = 0 ]; then
        add_row "" monitor daemon - - '?' "systemctl did not answer"
    elif [ "$P_FILE" = enabled ] && [ "$P_UP" = 0 ]; then
        add_row "" monitor daemon - - FAIL "down with the daemon: today's daemon conditions page nothing until it runs" direct monitor-down
    elif [ "$A_MONITOR" = off ]; then
        add_row "" monitor daemon - - WARN "monitor off (PROPOLIS_OPS_ENABLED is not true)" "" monitor-off
    elif [ "$P_UP" = 1 ]; then
        add_row "" monitor daemon - - ok "running; whether its conditions are answered is not visible from shell until step 3"
    else
        add_row "" monitor daemon - - info "propolis.service not enabled"
    fi
}

# rail_witness: the witness's light pass as seen from outside it. FAIL when its timer is not
# active, when no light pass has completed for 900 s (three periods; not judged in the first
# 1800 s of uptime, when every timer is just starting), or when the banner is missing or older
# than 900 s while the pass itself is fresh: the pass then runs but cannot tell anyone at login.
# WARN when a hook spool file has waited over 10 min, which the next pass should have taken in.
# The hourly pass: FAIL when its timer is not active or cc-stopped is open (config-check has not
# completed on two hourly passes, so every finding it reports goes unseen); WARN when the pass is
# over two hours and ten minutes old, when its timer fired over 15 minutes ago and no pass has
# ever completed, when the last config-check exited with a status above 2 or was not run at all,
# or when the last completed run printed lines out of form.
W_TIMER_ACTIVE="" W_TIMER_FILE="" W_TIMER_LAST=""
rail_witness() {
    local state=ok note="" cond="" fresh=0 last
    if ! unit_show propolis-witness@light.timer ActiveState UnitFileState LastTriggerUSec; then
        add_row "" witness timers - - '?' "systemctl did not answer"
        return 0
    fi
    W_TIMER_ACTIVE="$U_ActiveState" W_TIMER_FILE="$U_UnitFileState" W_TIMER_LAST="$U_LastTriggerUSec"
    if [ -n "$W_LIGHT_WALL" ] && [ "$W_LIGHT_AGE" -ge 0 ] && [ "$W_LIGHT_AGE" -le 900 ]; then
        fresh=1
        note="light pass $(fmt_age "$W_LIGHT_AGE") ago"
    fi
    if [ "$W_TIMER_ACTIVE" != active ]; then
        state=FAIL cond=witness note="propolis-witness@light.timer ${W_TIMER_ACTIVE:-not installed}"
    elif [ "$PA_UP" -lt 1800 ]; then
        [ -n "$note" ] || note="not judged in the first 30 min after a boot"
    elif [ -z "$W_LIGHT_WALL" ]; then
        last="$W_TIMER_LAST"
        if [ -z "$last" ] || [ "$last" = n/a ] || [ "$last" = 0 ]; then
            note="the light timer has not fired yet"
        else
            state=FAIL cond=witness note="no light pass has completed (the timer fired at $(fmt_time "$(ts_epoch "$last")"))"
        fi
    elif [ "$fresh" = 0 ]; then
        state=FAIL cond=witness note="light pass $(fmt_age "$W_LIGHT_AGE") old"
        [ "$W_LIGHT_AGE" -ge 0 ] || note="light pass time not known (clock)"
    fi
    if [ "$fresh" = 1 ] && { [ -z "$W_BANNER_MT" ] || [ "$(age_of "$W_BANNER_MT")" = - ] \
        || [ "$(age_of "$W_BANNER_MT")" -gt 900 ]; }; then
        state=FAIL cond=witness note="banner not written${W_BANNER_MT:+ since $(fmt_time "$W_BANNER_MT")}; $note"
    fi
    # The hourly pass: its timer, its age (two hours and ten minutes, since its timer adds up to
    # ten minutes of random delay to each hour), the last config-check's exit, and cc-stopped.
    if unit_show propolis-witness@hourly.timer ActiveState UnitFileState LastTriggerUSec; then
        last="$(ts_epoch "$U_LastTriggerUSec")"
        if [ "$U_ActiveState" != active ]; then
            state=FAIL cond=witness note="${note:+$note; }propolis-witness@hourly.timer ${U_ActiveState:-not installed}"
        elif [ "$PA_UP" -ge 1800 ] && [ -z "$W_HOURLY_WALL" ] && [ -n "$last" ] \
            && [ "$(age_of "$last")" != - ] && [ "$(age_of "$last")" -gt 900 ]; then
            # The timer fired more than the unit's 15 minutes ago and no pass ever completed:
            # each run is failing or being killed, which the light pass's view of the hourly
            # pass's age cannot show until one completes.
            [ "$state" = FAIL ] || { state=WARN cond=witness; }
            note="${note:+$note; }no hourly pass has completed (the timer fired at $(fmt_time "$last"))"
        elif [ "$PA_UP" -ge 1800 ] && [ -n "$W_HOURLY_WALL" ] && { [ "$W_HOURLY_AGE" -lt 0 ] || [ "$W_HOURLY_AGE" -gt 7800 ]; }; then
            [ "$state" = FAIL ] || { state=WARN cond=witness; }
            if [ "$W_HOURLY_AGE" -ge 0 ]; then
                note="${note:+$note; }hourly pass $(fmt_age "$W_HOURLY_AGE") old"
            else
                note="${note:+$note; }hourly pass time not known (clock)"
            fi
        elif [ -n "$W_HOURLY_WALL" ]; then
            note="${note:+$note; }hourly pass $(fmt_age "$W_HOURLY_AGE") ago"
        fi
    else
        [ "$state" = FAIL ] || state='?'
        note="${note:+$note; }hourly timer: systemctl did not answer"
    fi
    if [[ ${META[cc_last]:-} =~ /([0-9]{1,3})/([0-9]{1,6})$ ]] && [ "$((10#${BASH_REMATCH[1]}))" -gt 2 ]; then
        [ "$state" = FAIL ] || { state=WARN cond=witness; }
        note="${note:+$note; }last config-check exited ${BASH_REMATCH[1]}"
    elif [[ ${META[cc_last]:-} == */-/[0-9]* ]]; then
        [ "$state" = FAIL ] || { state=WARN cond=witness; }
        note="${note:+$note; }last config-check not run (missing or not trusted)"
    fi
    # A line config-check printed out of form cannot be tied to a finding, so none it could be
    # was taken as gone; the count says the check's output needs a look.
    if [[ ${META[cc_skipped]:-} =~ ^[0-9]{1,9}$ ]] && [ "$((10#${META[cc_skipped]}))" -gt 0 ]; then
        [ "$state" = FAIL ] || { state=WARN cond=witness; }
        note="${note:+$note; }config-check printed $((10#${META[cc_skipped]})) lines out of form"
    fi
    if [ "$(printf '%s\n' "$INCIDENTS_BODY" | grep -cE $'^I\t[^\t]*\ttool:config-check\t([^\t]*\t){4}(open|acked)\t')" -gt 0 ]; then
        state=FAIL cond=witness-tool note="${note:+$note; }cc-stopped: config-check has not completed on two hourly passes"
    fi
    # A journal class whose read could not finish twice in a row started again from the last 15
    # minutes, so the lines between are unread.
    if [[ ${META[jskip]:-} =~ ^([0-9]{1,12})/[0-9a-f-]{1,8}/[0-9]{1,10}/([a-z,]{1,64})$ ]] \
        && [ "$(age_of "$((10#${BASH_REMATCH[1]}))")" != - ] \
        && [ "$(age_of "$((10#${BASH_REMATCH[1]}))")" -le 86400 ]; then
        note="${note:+$note; }journal class ${BASH_REMATCH[2]//,/, }: lines may have been skipped ($(fmt_time "$((10#${BASH_REMATCH[1]}))"))"
    fi
    if [ "$W_SPOOL_OLD" -gt 0 ]; then
        [ "$state" = FAIL ] || { state=WARN cond=witness; }
        if [ "$W_SPOOL_OLD" = 1 ]; then
            note="${note:+$note; }1 hook spool file waiting over 10 min"
        else
            note="${note:+$note; }$W_SPOOL_OLD hook spool files waiting over 10 min"
        fi
    fi
    add_row "" witness timers "$(fmt_time "$W_LIGHT_WALL")" "$(fmt_age "$W_LIGHT_AGE")" "$state" "$note" direct "$cond"
}

rail_peers() {
    if [ "$ROLE" = collector ]; then
        not_here "" peers "the ledger is on the control node"
        return 0
    fi
    add_row "" peers - - - info "not visible from shell (step 3)"
}

# ---- the first stopped stage ----------------------------------------------------------------

# connect_failure_logged: the daemon's last run logged its failed connect to PostgreSQL, matched
# only by journal fields no other process can forge (the unit, the propolis uid and the run's
# invocation id).
connect_failure_logged() {
    local uid
    [[ ${P_INV:-} =~ ^[0-9a-f]{32}$ ]] || return 1
    uid="$(timeout 5 id -u -- propolis 2> /dev/null)" || return 1
    [[ $uid =~ ^[0-9]{1,10}$ ]] || return 1
    # grep -c reads to the end: a grep -q stopping at the first match would kill head and the
    # journal before it, and under pipefail a found line would read as none.
    [ "$(journalctl -q -o cat --no-pager _SYSTEMD_UNIT=propolis.service "_UID=$uid" "_SYSTEMD_INVOCATION_ID=$P_INV" \
        2> /dev/null | head -c 1048576 | grep -c -a -F 'propolis: failed to connect to PostgreSQL')" -gt 0 ]
}

# first_stopped: marks the first stage that stopped. The candidate is the lowest-numbered stage
# row that is FAIL. One override, from a trusted journal line: a daemon that is down because its
# connect to the database failed, with the ledger failing on a connection, puts the marker on the
# ledger and intake reads starved. A row after the mark that failed only for lack of progress is
# starved; one with a direct fault stays FAIL, marked (also). A row before the mark that could not
# be read is named on the marked row.
MARKED=-1
first_stopped() {
    local i cand=-1 i5=-1 i6=-1 unseen=""
    for i in "${!R_STAGE[@]}"; do
        [ -n "${R_NUM[$i]}" ] || continue
        [ "${R_NUM[$i]}" != 5 ] || [ "$i5" -ge 0 ] || i5="$i"
        [ "${R_NUM[$i]}" != 6 ] || [ "$i6" -ge 0 ] || i6="$i"
        if [ "${R_STATE[$i]}" = FAIL ] && [ "$cand" -lt 0 ]; then cand="$i"; fi
    done
    [ "$cand" -ge 0 ] || return 0
    if [ "$cand" = "$i5" ] && [ "$INTAKE_DOWN" = 1 ] && [ "$i6" -ge 0 ] && [ "${R_STATE[$i6]}" = FAIL ]; then
        case "$LEDGER_CAUSE" in
            db.unreachable | db.timeout | db.auth)
                if connect_failure_logged; then
                    R_STATE[i5]=starved R_NOTE[i5]="cannot start: database"
                    cand="$i6"
                else
                    R_NOTE[i5]+="; database also unreachable"
                fi
                ;;
        esac
    fi
    MARKED="$cand"
    R_MARK[cand]=">"
    for i in "${!R_STAGE[@]}"; do
        [ -n "${R_NUM[$i]}" ] || continue
        if [ "$i" -lt "$cand" ]; then
            [ "${R_STATE[$i]}" != '?' ] || unseen+="${unseen:+ }${R_STAGE[$i]}"
        elif [ "$i" -gt "$cand" ] && [ "${R_STATE[$i]}" = FAIL ]; then
            if [ "${R_WHY[$i]}" = progress ]; then
                R_STATE[i]=starved
            else
                R_NOTE[i]+=" (also)"
            fi
        fi
    done
    [ -z "$unseen" ] || R_NOTE[cand]+="; an earlier stage could not be read: $unseen"
}

# ---- what to look at next -------------------------------------------------------------------

# Each condition a row can end in, the view that expands it and the runbook key in
# docs/operations/health-and-observability.md (`-` when no section applies). Every key here has
# an anchor on that page; status_script_test.rs holds the two together.
STATUS_NEXT=(
    "listen-down listen listen-down"
    "listen-daily listen finding"
    "source-finding source finding"
    "source-rotation source rotation"
    "ship-down ship ship-down"
    "ship-failing ship ship-failing"
    "spool-quiet ship spool-quiet"
    "gateway-down gateway gateway-down"
    "gateway-finding gateway finding"
    "gateway-dup gateway gateway-dup"
    "intake-down intake daemon-down"
    "intake-finding intake finding"
    "ledger-down ledger db-unreachable"
    "ledger-state ledger db-state"
    "alert-path alert alert-path"
    "alert-target --setup -"
    "backup-failed backup backup-failed"
    "backup-hung backup backup-hung"
    "push-failing publish push-failing"
    "host-volume host volume"
    "host-state host state"
    "host-clock host -"
    "host-tool host tool"
    "monitor-down monitor daemon-down"
    "monitor-off monitor -"
    "witness witness witness"
    "witness-tool witness tool"
)

# next_line: the NEXT line, for the marked row, else the first FAIL rail, else the first WARN or
# `?` row in walk order.
next_line() {
    local i pick=-1 cond view="" key=- e repo page
    if [ "$MARKED" -ge 0 ]; then
        pick="$MARKED"
    else
        for i in "${!R_STAGE[@]}"; do
            if [ -z "${R_NUM[$i]}" ] && [ "${R_STATE[$i]}" = FAIL ]; then
                pick="$i"
                break
            fi
        done
        if [ "$pick" -lt 0 ]; then
            for i in "${!R_STAGE[@]}"; do
                case "${R_STATE[$i]}" in
                    WARN | '?')
                        pick="$i"
                        break
                        ;;
                esac
            done
        fi
    fi
    if [ "$pick" -lt 0 ]; then
        printf 'NEXT    nothing stopped and nothing to look at\n'
        return 0
    fi
    view="${R_STAGE[$pick]}"
    if [ "${R_STATE[$pick]}" != '?' ]; then
        cond="${R_COND[$pick]}"
        for e in "${STATUS_NEXT[@]}"; do
            read -r c v k <<< "$e"
            if [ "$c" = "$cond" ]; then
                view="$v" key="$k"
                break
            fi
        done
    fi
    repo="$(repo_dir)"
    if [ "$key" = - ]; then
        page="runbook -"
    elif [ -n "$repo" ]; then
        page="runbook $repo/docs/operations/health-and-observability.md#$key"
    else
        page="runbook docs/operations/health-and-observability.md#$key in the Propolis checkout"
    fi
    printf 'NEXT    sudo propolis-status %s  -  %s\n' "$view" "$page"
}

# repo_dir: the checkout the installer recorded, when the record is one line naming an absolute
# path with no control character.
repo_dir() {
    local f="$STATUS_ROOT/usr/local/lib/propolis/repo-dir" text="" re='^/[ -~]{1,4095}$'
    [ -f "$f" ] && [ ! -L "$f" ] || return 0
    text="$(root_read "$f" 4096)" || return 0
    text="${text%$'\n'}"
    [[ $text == *$'\n'* ]] && return 0
    [[ $text =~ $re ]] && printf '%s' "$text"
    return 0
}

# ---- ids ------------------------------------------------------------------------------------

declare -A IDS=()
IDS_LINE=""
# load_ids KIND: the opaque ids of the configured instances (pa_id_table, which widens two names
# of one kind whose ids collide). `local` takes the units, logs and collectors, known before
# anything slow runs, so the recent failures can name their units; `vendor` takes the vendors the
# reports query found. Collisions are widened within a kind, so the two calls agree with one. The
# collectors are the ones the witness keys too, every collector with a spool file and every one
# PROPOLIS_SENSOR_LOGS lists, so a widened id names the same collector in both.
load_ids() {
    local input="" u l i key id kind name list p
    [ "$SALT" = 1 ] || return 0
    if [ "$1" = local ]; then
        if list="$(systemctl list-unit-files 'sensor-*.service' --no-legend --no-pager 2> /dev/null)"; then
            while read -r u _; do
                [[ ! $u =~ ^sensor-[a-z0-9-]{1,40}\.service$ ]] || input+="unit"$'\t'"$u"$'\n'
            done <<< "$list"
        fi
        [ "$HAS_DAEMON" = 0 ] || input+="unit"$'\t'"propolis.service"$'\n'
        [ "$ROLE" != collector ] || input+="unit"$'\t'"shipper.service"$'\n'
        case "$ROLE" in control | gateway) input+="unit"$'\t'"gateway.service"$'\n' ;; esac
        while IFS=$'\t' read -r _ _ key _; do
            case "$key" in unit:*) input+="unit"$'\t'"${key#unit:}"$'\n' ;; esac
        done <<< "$INCIDENTS_BODY"
        for u in "${HOOK_UNITS[@]}"; do input+="unit"$'\t'"$u"$'\n'; done
        for l in "${LOG_LABEL[@]}"; do input+="source"$'\t'"$l"$'\n'; done
        for i in "${!SPOOL_CN[@]}"; do
            [ "${SPOOL_EV[$i]}" != 1 ] || input+="collector"$'\t'"${SPOOL_CN[$i]}"$'\n'
        done
        case "$ROLE" in
            control | gateway)
                for p in "${LOG_PATH[@]}"; do
                    case "$p" in "${SPOOL_DIR%/}"/*/events.jsonl) ;; *) continue ;; esac
                    i="${p#"${SPOOL_DIR%/}"/}"
                    i="${i%/events.jsonl}"
                    ! pa_plain_id "$i" || input+="collector"$'\t'"$i"$'\n'
                done
                ;;
        esac
    else
        for i in "${VENDORS[@]}"; do input+="vendor"$'\t'"$i"$'\n'; done
    fi
    while IFS=$'\t' read -r id kind name; do
        [ -n "$id" ] || continue
        IDS["$kind/$name"]="$id"
        if pa_ok_field "$name"; then IDS_LINE+="$id={$name} "; else IDS_LINE+="$id={?} "; fi
    done < <(printf '%s' "$input" | pa_id_table 2> /dev/null)
}

# ---- the recent failures --------------------------------------------------------------------

# cause_words CODE: a stored cause as a person reads it (`proc.exit:3` as `proc.exit 3`), `?`
# for anything outside the closed list.
cause_words() {
    local c="${1:-}" code num=""
    code="${c%%:*}"
    [ "$code" = "$c" ] || num="${c#*:}"
    case "$code" in
        proc.exit | proc.sandbox | proc.signal)
            [[ $num =~ ^[0-9]{1,3}$ ]] || {
                printf '?'
                return 0
            }
            printf '%s %s' "$code" "$num"
            return 0
            ;;
    esac
    [ -z "$num" ] || {
        printf '?'
        return 0
    }
    case "$code" in
        proc.sigsys | proc.oom | proc.timeout | proc.watchdog | proc.start_limit | proc.resources | proc.panic \
            | db.unreachable | db.auth | db.timeout | db.recovery | db.xid | db.slots | db.locks \
            | ready.db | ready.gave_up | ready.starting | tool.exec | http.auth | http.not_found \
            | http.client | http.rate | http.server | net.timeout | net.connect | nocurl | fs.no_space \
            | fs.readonly | guard.behind | guard.no_space | spool.quiet | gw.dup | ship.connect \
            | ship.rejected | ship.io | ship.dropped | backup.long | backup.keep | backup.pull \
            | push.stale | push.none | vol.low | vol.inodes | vol.projected | change.env | change.unit \
            | change.binary | journal.suppressed | witness.stale | cc.stopped | config.invalid \
            | config.finding | clock.step | unknown)
            printf '%s' "$code"
            ;;
        *) printf '?' ;;
    esac
}

stage_word() {
    case " $STATUS_STAGES $STATUS_RAILS witness " in
        *" ${1:-} "*) printf '%s' "$1" ;;
        *) printf '?' ;;
    esac
}

# legacy_tag OUT: what today's hook did with a firing, from its stored word.
legacy_tag() {
    case "${1:-}" in
        delivered | undelivered | cooldown | journal) printf '[legacy hook: %s]' "$1" ;;
        -) printf '[not pushed: legacy]' ;;
        *) printf '[legacy hook: ?]' ;;
    esac
}

# unit_shown UNIT: the unit as `<id>={<unit>}`, the name braced because a spool file name came
# from it.
unit_shown() {
    local shown="{?}"
    ! pa_ok_field "$1" || shown="{$1}"
    printf '%s=%s' "${IDS[unit/$1]:--}" "$shown"
}

# record_line LINE: one incident record as a recent failure, in REC_LINE. Also sets REC_KEY (the
# first failure, 0 when unknown, for sorting), REC_STATE and REC_RESOLVED (the resolve time). It
# never prints the tier or the state word: nothing has judged the record.
record_line() {
    local id key stage inst first w cause occ legacy res out
    local -a f
    IFS=$'\t' read -r -a f <<< "$1"
    id="${f[1]:-}" key="${f[2]:-}" stage="${f[4]:-}" REC_STATE="${f[7]:-}" first="${f[8]:-}"
    cause="${f[11]:-}" res="${f[21]:-}" occ="${f[31]:-}" legacy="${f[33]:--}"
    [[ $id =~ ^[wd]#[0-9]{1,9}$ ]] || id="?"
    w="${first%%/*}"
    [[ $w =~ ^[0-9]{1,12}$ ]] || w=""
    res="${res%%/*}"
    [[ $res =~ ^[0-9]{1,12}$ ]] || res=""
    REC_KEY="$((10#${w:-0}))" REC_RESOLVED="$res"
    inst=-
    case "$key" in unit:*) inst="$(unit_shown "${key#unit:}")" ;; esac
    out="$(printf '%-7s %-8s %-30s' "$id" "$(stage_word "$stage")" "$inst")"
    # The record keeps the first failure only: a later firing raises occ and replaces legacy_out.
    if [ -n "$w" ]; then out+=" first failed $(fmt_time "$w")"; else out+=" failed ?"; fi
    if [[ $occ =~ ^[0-9]{1,9}$ ]] && [ "$((10#$occ))" -gt 1 ]; then
        case "$legacy" in
            delivered | undelivered | cooldown | journal) out+=" ($((10#$occ)) firings, latest: legacy hook $legacy)" ;;
            *) out+=" ($((10#$occ)) firings)" ;;
        esac
    fi
    [ "$REC_STATE" != resolved ] || out+=", resolved $(fmt_time "$res")"
    out+="  cause $(cause_words "$cause")  $(legacy_tag "$legacy")"
    REC_LINE="$out"
}

# load_hook_spool: the firings the hook wrote to its spool instead of the record, because
# the lock was busy or its time nearly spent; nothing takes them in before the witness does. The
# checked fields of each go to HOOK_RAW and the unit to HOOK_UNITS; render_hook_spool makes the
# lines. Both directories are root's alone, so a plain read is enough; names and fields are still
# checked, since a unit name reaches the terminal.
HOOK_LINES=() HOOK_UNITS=() HOOK_RAW=()
load_hook_spool() {
    local dir name unit text t first last count result code status cause nr out w line
    for dir in "$PA_STATE/hook" "$PA_RUN/fallback"; do
        [ -d "$dir" ] && [ ! -L "$dir" ] || continue
        while IFS= read -r -d '' name; do
            unit="$name"
            # A file the witness claimed to take in (deploy/witness.sh#ingest_spool) holds the same
            # firings under `.ingest.<pid>.<name>` until its records are written.
            if [[ $unit =~ ^\.ingest\.[0-9]{1,10}\.(.+)$ ]]; then unit="${BASH_REMATCH[1]}"; fi
            if [ "$dir" = "$PA_RUN/fallback" ]; then
                [[ $unit == hook-* ]] || continue
                unit="${unit#hook-}"
            fi
            [[ $unit =~ ^[A-Za-z0-9@._:-]{1,200}$ ]] && [[ $unit != .* ]] || continue
            case "$unit" in *.tmp.*) continue ;; esac
            text="$(root_read "$dir/$name" 4096)" || continue
            [[ ${text%%$'\n'*} =~ ^#hook\ v1\ g=[0-9]{1,18}$ ]] || continue
            line="${text#*$'\n'}"
            line="${line%%$'\n'*}"
            IFS=$'\t' read -r t first last count result code status cause nr out _ <<< "$line"
            [ "$t" = H ] || continue
            for w in "$first" "$last" "$count" "$result" "$code" "$status" "$cause" "$nr" "$out"; do
                pa_ok_field "$w" || continue 2
            done
            w="${last%%/*}"
            [[ $w =~ ^[0-9]{1,12}$ ]] || w=-
            HOOK_RAW+=("$unit"$'\t'"$w"$'\t'"$count"$'\t'"$cause"$'\t'"$out")
            HOOK_UNITS+=("$unit")
        done < <(timeout 5 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\0' 2> /dev/null)
    done
}

# render_hook_spool: the spooled firings as lines in HOOK_LINES. Run after load_ids, which needs
# HOOK_UNITS first, so that each line names its unit by the opaque id the IDS line gives it.
render_hook_spool() {
    local raw unit w count cause out line
    HOOK_LINES=()
    for raw in "${HOOK_RAW[@]}"; do
        IFS=$'\t' read -r unit w count cause out <<< "$raw"
        [ "$w" != - ] || w=""
        pa_unit_map "$unit"
        line="$(printf '%-7s %-8s %-30s' - "$PA_UNIT_STAGE" "$(unit_shown "$unit")")"
        if [ -n "$w" ]; then line+=" failed $(fmt_time "$w")"; else line+=" failed ?"; fi
        [[ ! $count =~ ^[0-9]{1,9}$ ]] || [ "$((10#$count))" -le 1 ] || line+=" ($((10#$count)) firings)"
        line+="  cause $(cause_words "$cause")  $(legacy_tag "$out")  [spooled, not yet in the record]"
        HOOK_LINES+=("$(printf '%012d' "$((10#${w:-0}))")"$'\t'"$line")
    done
}

# open_line LINE: one incident record as the OPEN block lists it, in OPEN_TEXT, with OPEN_SORT
# (tier, then id number) and OPEN_TIER, OPEN_STATE. Every field is read with a default and
# checked before it is printed: a line cut short or damaged costs its words, never the walk.
open_line() {
    local id key tier stage inst state first opened cause next parent flags legacy rank num w a out
    local -a f
    IFS=$'\t' read -r -a f <<< "$1"
    id="${f[1]:-}" key="${f[2]:-}" stage="${f[4]:-}" tier="${f[6]:-}" state="${f[7]:-}"
    first="${f[8]:-}" opened="${f[9]:-}" cause="${f[11]:-}" parent="${f[13]:-}" next="${f[19]:-}"
    flags="${f[30]:--}" legacy="${f[33]:--}"
    if [[ $id =~ ^[wd]#([0-9]{1,9})$ ]]; then
        num="${BASH_REMATCH[1]}"
    else
        id="?" num=0
    fi
    case "$tier" in PAGE) rank=1 ;; ACT) rank=2 ;; NOTICE) rank=3 ;; *) rank=4 tier="?" ;; esac
    OPEN_TIER="$tier" OPEN_STATE="$state"
    OPEN_SORT="$rank$(printf '%010d' "$((10#$num))")"
    inst=-
    case "$key" in
        unit:*) inst="$(unit_shown "${key#unit:}")" ;;
        change:*) inst="$(unit_shown "${key#change:}")" ;;
        # A mount point is shown only in the host view, beside its id.
        vol:*) [[ ! ${f[5]:-} =~ ^m[0-9a-f]{5,8}$ ]] || inst="${f[5]}" ;;
    esac
    out="$(printf '%s %-6s %-8s %-30s' "$id" "$tier" "$(stage_word "$stage")" "$inst")"
    if [ "$state" = pending ]; then
        w="${first%%/*}"
        a="$(pa_age "$first")"
        if [[ $w =~ ^[0-9]{1,12}$ ]] && [ "$a" -ge 0 ]; then out+="  pending since $(fmt_time "$w")"; else out+="  pending, onset not known (clock)"; fi
    else
        w="${opened%%/*}"
        a="$(pa_age "$opened")"
        [ "$state" != acked ] || out+="  acked,"
        if [[ $w =~ ^[0-9]{1,12}$ ]] && [ "$a" -ge 0 ]; then
            out+="  open since $(fmt_time "$w") ($(fmt_age "$a"))"
        else
            out+="  open, onset not known (clock)"
        fi
    fi
    out+="  cause $(cause_words "$cause")"
    if [ "$state" = open ] && [[ ${next%%/*} =~ ^[0-9]{1,12}$ ]]; then
        out+="  would remind $(date -u -d "@${next%%/*}" +%H:%M 2> /dev/null || printf '?')"
    fi
    [[ ! $parent =~ ^[wd]#[0-9]{1,9}$ ]] || out+="  folded under $parent"
    if [ "$flags" != - ]; then
        if pa_ok_field "$flags"; then out+="  flags $flags"; else out+="  flags ?"; fi
    fi
    out+="  $(legacy_tag "$legacy")"
    OPEN_TEXT="$out"
}

# OPEN_CODE: what the open incidents add to the exit code once a witness pass has judged them:
# 2 for an open (or acked) PAGE, 1 for an open ACT; a pending record or a NOTICE adds nothing.
OPEN_CODE=0
load_open_code() {
    local t
    [ -n "${META[light_last]:-}" ] || return 0
    while IFS= read -r t; do
        [[ $t == I$'\t'* ]] || continue
        open_line "$t"
        case "$OPEN_STATE" in open | acked) ;; *) continue ;; esac
        case "$OPEN_TIER" in
            PAGE) OPEN_CODE=2 ;;
            ACT) [ "$OPEN_CODE" = 2 ] || OPEN_CODE=1 ;;
        esac
    done <<< "$INCIDENTS_BODY"
}

# print_open: the OPEN block, once a witness pass has completed on the host: the open, acked and
# pending records, PAGE first, then ACT, then NOTICE, then by id; then the firings still in the
# hook's spool, which the next pass takes in.
print_open() {
    local -a lines=()
    local t n=0
    while IFS= read -r t; do
        [[ $t == I$'\t'* ]] || continue
        open_line "$t"
        case "$OPEN_STATE" in open | acked | pending) ;; *) continue ;; esac
        lines+=("$OPEN_SORT"$'\t'"$OPEN_TEXT")
        n=$((n + 1))
    done <<< "$INCIDENTS_BODY"
    for t in "${HOOK_LINES[@]}"; do lines+=("9${t}"); done
    n=$((n + ${#HOOK_LINES[@]}))
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" incidents "* ]]; then
        printf 'OPEN    ? (incidents unreadable: see STATE)\n'
    elif [ "$n" -gt 0 ]; then
        printf '%s\n' "${lines[@]}" | sort | head -n 20 | cut -f 2- | sed '1s/^/OPEN    /; 2,$s/^/        /'
        [ "$n" -le 20 ] || printf '        ... and %s more: sudo propolis-status alert\n' "$((n - 20))"
    elif [ "$INCIDENTS_FILE" = 0 ]; then
        printf 'OPEN    no incident record yet\n'
    else
        printf 'OPEN    none recorded\n'
    fi
    case "$ROLE" in single | control) printf '        daemon incidents: not on disk before step 3\n' ;; esac
}

print_recent() {
    local -a lines=()
    local t age old=0 n=0 title
    if [ -n "${META[light_last]:-}" ]; then
        print_open
        return
    fi
    title="RECENT FAILURES (not judged: no witness pass has run on this host)"
    # Nothing resolves a record before the witness does, so an unresolved record is listed
    # however old its first failure: the unit may have failed again a minute ago. Only a resolved
    # record ages out, by its resolve time.
    while IFS= read -r t; do
        [[ $t == I$'\t'* ]] || continue
        record_line "$t"
        if [ "$REC_STATE" = resolved ]; then
            age="$(age_of "${REC_RESOLVED:-$REC_KEY}")"
            if [ "$age" != - ] && [ "$age" -gt 604800 ]; then
                old=$((old + 1))
                continue
            fi
        fi
        lines+=("$(printf '%012d' "$REC_KEY")"$'\t'"$REC_LINE")
        n=$((n + 1))
    done <<< "$INCIDENTS_BODY"
    lines+=("${HOOK_LINES[@]}")
    n=$((n + ${#HOOK_LINES[@]}))
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" incidents "* ]]; then
        printf 'RECENT FAILURES  ? (incidents unreadable: see STATE)\n'
    elif [ "$n" -gt 0 ]; then
        printf '%s\n' "$title"
    elif [ "$INCIDENTS_FILE" = 0 ]; then
        printf 'RECENT FAILURES  no incident record yet\n'
    else
        printf 'RECENT FAILURES  none recorded in the last 7 days\n'
    fi
    if [ "$n" -gt 0 ]; then
        printf '%s\n' "${lines[@]}" | sort -r | head -n 20 | cut -f 2- | sed 's/^/        /'
        [ "$n" -le 20 ] || printf '        ... and %s more: sudo propolis-status alert\n' "$((n - 20))"
    fi
    [ "$old" = 0 ] || printf '        %s resolved, older than 7 days, not listed\n' "$old"
    case "$ROLE" in single | control) printf '        daemon incidents: not on disk before step 3\n' ;; esac
}

# twenty_four: the 24 H line from the incident record. A line cut short has fewer fields than its
# type, so every field is asked for with a default: under `set -u` a missing one would end the walk.
twenty_four() {
    local t res=0 wd=0 quiet=0 w
    local -a f
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" incidents "* ]]; then
        printf '24 H    ? (incidents unreadable: see STATE)\n'
        return 0
    fi
    while IFS= read -r t; do
        IFS=$'\t' read -r -a f <<< "$t"
        case "${f[0]:-}" in
            I)
                [ "${f[7]:-}" = resolved ] || continue
                w="${f[21]:-}"
                w="${w%%/*}"
                [[ $w =~ ^[0-9]{1,12}$ ]] && [ "$(age_of "$w")" != - ] && [ "$(age_of "$w")" -le 86400 ] || continue
                res=$((res + 1))
                [ "${f[17]:-0}" != 0 ] || quiet=$((quiet + 1))
                ;;
            W)
                w="${f[1]:-}"
                w="${w%%/*}"
                [[ $w =~ ^[0-9]{1,12}$ ]] && [ "$(age_of "$w")" != - ] && [ "$(age_of "$w")" -le 86400 ] || continue
                wd=$((wd + 1))
                ;;
        esac
    done <<< "$INCIDENTS_BODY"
    printf '24 H    resolved %s - withheld by budget %s - opened and resolved without delivery %s\n' "$res" "$wd" "$quiet"
}

# ---- printing -------------------------------------------------------------------------------

print_row() {
    local i="$1" num="${R_NUM[$1]}"
    printf '%2s%1s %-9s %-24s %-16s %-7s %-8s %s\n' "$num" "${R_MARK[$i]}" "${R_STAGE[$i]}" \
        "${R_INST[$i]}" "${R_LAST[$i]}" "${R_AGE[$i]}" "${R_STATE[$i]}" "${R_NOTE[$i]}" \
        | sed 's/ *$//'
}

COLUMNS_LINE=' #  stage     instance                 last progress    age     state    note'

print_header() {
    local alias host role step lw
    if [ "$SALT" = 1 ]; then
        pa_alias > /dev/null 2>&1 || true
        alias="${PA_ALIAS:--}"
    else
        alias="- (no ids yet)"
    fi
    host="$(hostname 2> /dev/null | tr -c 'A-Za-z0-9.\n-' '?' | head -n 1)"
    case "$ROLE" in
        single) role="single box" ;;
        control) role="control node ($((${#SPOOL_CN[@]} + SPOOL_WITHHELD)) collectors in spool)" ;;
        collector) role=collector ;;
        gateway) role="gateway only" ;;
        *) role="unknown role" ;;
    esac
    printf '%s = %s - %s - %s UTC\n' "$alias" "${host:-?}" "$role" "$(date -u -d "@$PA_WALL" '+%F %T')"
    if pa_maint_active; then
        printf 'MAINT   %s until %s (%s left): unit kinds held' "$PA_MAINT_REASON" "$(pa_hms "$PA_MAINT_UNTIL")" \
            "$(fmt_age "$((PA_MAINT_UNTIL - PA_WALL))")"
        [ "$PA_MAINT_REASON" != manual ] || printf '; collector and database kinds held'
        printf '\n'
    fi
    step="${META[clock_step]:-}"
    if [[ $step =~ ^([0-9]{1,12})/[0-9a-f-]{1,8}/[0-9]{1,10}/([+-][0-9]{1,12})$ ]] \
        && [ "$(age_of "${BASH_REMATCH[1]}")" != - ] && [ "$(age_of "${BASH_REMATCH[1]}")" -le 86400 ]; then
        printf 'CLOCK   stepped %s s at %s: times in messages since then may be wrong\n' "${BASH_REMATCH[2]}" \
            "$(fmt_time "${BASH_REMATCH[1]}")"
    fi
    lw="$(lockwait_count)"
    [ "$lw" = 0 ] || printf 'LOCK    state lock busy for %s passes: the witness is not recording\n' "$lw"
    for step in ${PA_STATE_UNREADABLE:-}; do
        printf 'STATE   state file %s unreadable: shown as empty\n' "$step"
        UNKNOWN_EXTRA=1
    done
}

print_alerts() {
    local hook="failure hook legacy, $A_UNDELIVERED units undelivered" light state banner="" gate hourly
    [ -z "$A_SINCE" ] || hook+=" since $(fmt_time "$A_SINCE")"
    gate="gate $A_GATE"
    if _pa_stamp_split "$A_GATE_CHECKED"; then
        gate+=" (checked $(fmt_time "$_PA_W"), $(fmt_age "$(pa_age "$A_GATE_CHECKED")"))"
    fi
    printf 'ALERTS  target %s - %s - daemon monitor %s - daemon queue %s - %s - %s\n' "$A_TARGET" "$gate" \
        "$A_MONITOR" "$A_QUEUE" "$hook" "$A_VERIFIED"
    [ "$A_OLDCONF" = 0 ] || printf '        the daemon loaded an older configuration: restart propolis to apply it\n'
    if [ -n "$W_BANNER_MT" ]; then banner="$(fmt_time "$W_BANNER_MT")"; else banner="not written"; fi
    # An unreadable meta reads as empty, which must not pass for a host with nothing recorded.
    if [[ " ${PA_STATE_UNREADABLE:-} " == *" meta "* ]]; then
        printf '        witness light ? - hourly ? - state ? (meta unreadable) - banner %s\n' "$banner"
        return 0
    fi
    if [ -z "$W_LIGHT_WALL" ]; then
        light=never
    elif [ "$W_LIGHT_AGE" -ge 0 ]; then
        light="$(fmt_time "$W_LIGHT_WALL") ($(fmt_age "$W_LIGHT_AGE"))"
    else
        light="$(fmt_time "$W_LIGHT_WALL") (age not known: clock)"
    fi
    if [ -z "$W_HOURLY_WALL" ]; then
        hourly=never
    elif [ "$W_HOURLY_AGE" -ge 0 ]; then
        hourly="$(fmt_time "$W_HOURLY_WALL") ($(fmt_age "$W_HOURLY_AGE"))"
    else
        hourly="$(fmt_time "$W_HOURLY_WALL") (age not known: clock)"
    fi
    light+=" - hourly $hourly"
    case "${META[where]:-}" in
        persistent) state=persisted ;;
        run) state="not persisted (run)" ;;
        none) state="not persisted (none)" ;;
        *) state="nothing recorded yet" ;;
    esac
    printf '        witness light %s - state %s - banner %s%s\n' "$light" "$state" "$banner" "$(hb_words)"
}

# hb_words: the heartbeat URL field of ALERTS line 3, once a light pass has run (no pass asks it
# before): whether it is set (the URL itself is a secret and is never printed), refused because it
# is not https, and when it was last asked with what result, or last skipped and why. Skipping it
# is how the external dead-man check learns the host is not well.
hb_words() {
    local word last="" lres="" skip="" sres="" lw sw
    [ -n "$W_LIGHT_WALL" ] || return 0
    case "${PA_HB_STATE:-unset}" in
        set) word="set" ;;
        insecure | invalid) word="refused (not an https URL)" ;;
        *) word="not set" ;;
    esac
    if [ "$word" = set ]; then
        if [[ ${META[hb_last]:-} =~ ^([0-9]{1,12}/[0-9a-f-]{1,8}/[0-9]{1,10})/([a-z][a-z0-9._-]{0,31})$ ]]; then
            last="${BASH_REMATCH[1]}" lres="${BASH_REMATCH[2]}"
        fi
        if [[ ${META[hb_skip]:-} =~ ^([0-9]{1,12}/[0-9a-f-]{1,8}/[0-9]{1,10})/([a-z][a-z0-9._-]{0,31})$ ]]; then
            skip="${BASH_REMATCH[1]}" sres="${BASH_REMATCH[2]}"
        fi
        lw="${last%%/*}" sw="${skip%%/*}"
        if [ -n "$skip" ] && { [ -z "$last" ] || [ "$((10#$sw))" -gt "$((10#$lw))" ]; }; then
            word+=", skipped $(fmt_time "$((10#$sw))") ($sres)"
        elif [ -n "$last" ]; then
            word+=", asked $(fmt_time "$((10#$lw))") ($lres)"
        else
            word+=", not asked yet"
        fi
    fi
    printf ' - heartbeat URL %s' "$word"
}

# The witness's traces, for ALERTS, the witness rail and its view: W_LIGHT_WALL and W_LIGHT_AGE
# are the wall time and age (-1 when it cannot be read or lies in the future) of the newer of the
# light pass's heartbeat line (in /run, lost at reboot) and meta light_last (on disk);
# W_BANNER_MT the banner's modification time; W_SPOOL_OLD how many hook spool files have waited
# over 10 min, and W_SPOOL_N how many there are.
W_LIGHT_WALL="" W_LIGHT_AGE=-1 W_BANNER_MT="" W_SPOOL_OLD=0 W_SPOOL_N=0 W_HB_LINES=()
W_HOURLY_WALL="" W_HOURLY_AGE=-1
declare -A W_HB=()

# witness_pass_time INSTANCE META_STAMP: sets W_PASS_WALL and W_PASS_AGE to the newer of the
# instance's heartbeat line and its meta stamp (W_PASS_WALL empty when neither can be read).
witness_pass_time() {
    local best="${W_HB[$1]:-}" best_age=-1 s="$2" a
    W_PASS_WALL="" W_PASS_AGE=-1
    [ -z "$best" ] || best_age="$(pa_age "$best")"
    if [ -n "$s" ]; then
        a="$(pa_age "$s")"
        if [ -z "$best" ] || { [ "$a" -ge 0 ] && { [ "$best_age" -lt 0 ] || [ "$a" -lt "$best_age" ]; }; }; then
            best="$s" best_age="$a"
        fi
    fi
    if [ -n "$best" ] && [[ ${best%%/*} =~ ^[0-9]{1,12}$ ]]; then
        W_PASS_WALL="${best%%/*}" W_PASS_AGE="$best_age"
    fi
}

load_witness_facts() {
    local text head line t inst s mt
    text="$(root_read "$PA_RUN/heartbeat" 65536)" || text=""
    head="${text%%$'\n'*}"
    if [[ $head =~ ^#heartbeat\ v1\ g=[0-9]{1,18}$ ]]; then
        while IFS= read -r line; do
            IFS=$'\t' read -r t inst s _ <<< "$line"
            if [ "$t" != B ] || ! [[ $inst =~ ^[a-z]{1,16}$ ]] || ! pa_ok_field "${s:-}"; then continue; fi
            W_HB_LINES+=("$(printf '%s' "$line" | tr '\t' ' ' | tr -c ' -~' '?')")
            W_HB[$inst]="$s"
        done <<< "${text#*$'\n'}"
    fi
    witness_pass_time light "${META[light_last]:-}"
    W_LIGHT_WALL="$W_PASS_WALL" W_LIGHT_AGE="$W_PASS_AGE"
    witness_pass_time hourly "${META[hourly_last]:-}"
    W_HOURLY_WALL="$W_PASS_WALL" W_HOURLY_AGE="$W_PASS_AGE"
    if [ -f "$PA_MOTD/propolis" ] && [ ! -L "$PA_MOTD/propolis" ]; then
        mt="$(timeout 5 stat -c %Y -- "$PA_MOTD/propolis" 2> /dev/null)" || mt=""
        [[ $mt =~ ^[0-9]{1,12}$ ]] && W_BANNER_MT="$mt"
    fi
    # How long a spooled firing has waited, from the time the hook wrote into the file (the
    # spool's own clock, as load_hook_spool read it), not from the file's modification time.
    for line in "${HOOK_RAW[@]}"; do
        IFS=$'\t' read -r _ mt _ <<< "$line"
        W_SPOOL_N=$((W_SPOOL_N + 1))
        if [ "$(age_of "$mt")" != - ] && [ "$(age_of "$mt")" -gt 600 ]; then
            W_SPOOL_OLD=$((W_SPOOL_OLD + 1))
        fi
    done
}

print_check() {
    local ids=() i
    if [ "$CC_DONE" = 0 ]; then
        case "$CC_WHY" in
            'not trusted:'*)
                printf 'CHECK   config-check did not finish (%s; %s)\n' "$CC_WHY" "$STATUS_FIX"
                ;;
            *)
                printf 'CHECK   config-check did not finish (%s)  - fixes: sudo /usr/local/lib/propolis/config-check.sh\n' "$CC_WHY"
                ;;
        esac
        return 0
    fi
    for i in "${!CCF_ID[@]}"; do
        case " ${ids[*]} " in *" ${CCF_ID[$i]} "*) ;; *) ids+=("${CCF_ID[$i]}") ;; esac
    done
    printf 'CHECK   config-check %s (%s s): %s FAIL, %s WARN, %s ?' "$(fmt_time "$CC_GEN")" "$CC_SECS" \
        "$CC_NFAIL" "$CC_NWARN" "$CC_NUNK"
    [ "${#ids[@]}" -eq 0 ] || printf '  - ids: %s' "${ids[*]}"
    printf '  - fixes: sudo /usr/local/lib/propolis/config-check.sh; ledger role not checked here\n'
}

print_ids() {
    if [ "$SALT" = 0 ]; then
        printf 'IDS     no ids yet\n'
    elif [ -z "$IDS_LINE" ]; then
        printf 'IDS     none configured\n'
    else
        printf '%s\n' "${IDS_LINE% }" | fold -s -w 92 | sed '1s/^/IDS     /; 2,$s/^/        /'
    fi
    printf '        {...} = a name as found where another account writes, checked to be a plain id; [untrusted] = raw text, cleaned\n'
}

# exit_code: 2 when a stage is marked, a rail is FAIL or a PAGE incident is open, 1 for a WARN or
# `?` anywhere (the rows, an unreadable state file, config-check's own counts or a run that did
# not finish) or an open ACT incident, else 0. The recent failures listed before any witness pass
# never count: nothing has judged them.
exit_code() {
    local i code="$OPEN_CODE"
    [ "$MARKED" -lt 0 ] || code=2
    for i in "${!R_STAGE[@]}"; do
        case "${R_STATE[$i]}" in
            FAIL) code=2 ;;
            WARN | '?') [ "$code" = 2 ] || code=1 ;;
        esac
    done
    if [ "$code" = 0 ]; then
        if [ "$UNKNOWN_EXTRA" = 1 ] || [ "$CC_DONE" = 0 ] || [ "$((CC_NFAIL + CC_NWARN + CC_NUNK))" -gt 0 ]; then
            code=1
        fi
    fi
    return "$code"
}

# ---- the stage views ------------------------------------------------------------------------

view_untrusted() {
    pa_clean_untrusted 200 20 | sed 's/^/        /'
}

# view_volumes: for each filesystem the witness's hourly pass samples (observe Z lines), its last
# sample, how long its samples reach back and the projection from them (the library's
# pa_vol_project, the rule the witness opens by), with the mount point beside the opaque id where
# a store here maps to it. The stores are the library's pa_vol_stores, the witness's own list, each
# mapped by its own df: as root for root's stores, and for the data directory and a configured log
# directory as the account that owns it, since this walk runs as root with no sandbox and must not
# open a path that account could swap for a link to anything. An id no store maps to reads `mount
# point not known here` when a store's path could not be learnt or checked. Only this view, run by
# root, shows a mount point.
view_volumes() {
    local obs line t m s size avail it ia d out target input="" id kind name n first a hist w i as
    local benv="?" data="" known=1 remote=0 risk
    local -A mount_of=() last=() cnt=() oldest=()
    local -a mids=()
    obs="$(pa_state_read observe)"
    # Where the database is: a remote one's data volume is not on this host.
    pa_env_get DATABASE_URL "$FLEET_ENV" "$PROPOLIS_ENV" > /dev/null
    if [ -n "$PA_ENV_VALUE" ]; then
        case "$ROLE" in
            collector | gateway) ;;
            *)
                if [ "$(_pa_pg_where "$PA_ENV_VALUE")" = remote ]; then
                    remote=1
                else
                    data="${META[pg_datadir]:-}"
                    [ -n "$data" ] || known=0
                fi
                ;;
        esac
    elif [ -n "$PA_ENV_UNREADABLE" ]; then
        known=0
    fi
    PA_ENV_VALUE=""
    if out="$(systemctl show -p Environment -- propolis-backup.service 2> /dev/null)"; then
        benv="${out#Environment=}"
    fi
    pa_env_get PROPOLIS_SENSOR_LOGS "$FLEET_ENV" "$PROPOLIS_ENV" > /dev/null
    pa_sensor_logs "$PA_ENV_VALUE"
    PA_ENV_VALUE=""
    pa_vol_stores "$benv" "$data"
    [ "$PA_VOL_STORE_KNOWN" = 1 ] || known=0
    for i in "${!PA_VOL_STORE[@]}"; do
        d="$STATUS_ROOT${PA_VOL_STORE[$i]}" as="${PA_VOL_STORE_AS[$i]}"
        # A stat, which opens nothing; then df, which opens the path, as whoever owns it.
        [ -e "$d" ] || continue
        if [ -z "$as" ]; then
            out="$(timeout 10 df -P -- "$d" 2> /dev/null)"
        else
            out="$(_pa_as_t 10 "$as" df -P -- "$d")"
        fi
        # shellcheck disable=SC2181 # one status for the two branches above
        if [ "$?" != 0 ]; then
            known=0
            continue
        fi
        target="$(printf '%s\n' "$out" | sed -n 2p)"
        read -r _ _ _ _ _ target <<< "$target"
        [[ $target =~ ^/[\ -~]{0,255}$ ]] && input+="mount"$'\t'"$target"$'\n'
    done
    if [ -n "$input" ] && [ "$SALT" = 1 ]; then
        while IFS=$'\t' read -r id kind name; do
            [ "$kind" = mount ] && mount_of[$id]="$name"
        done < <(printf '%s' "$input" | pa_id_table 2> /dev/null)
    fi
    [ "$remote" = 0 ] || printf '    data volume: not readable here (remote database)\n'
    while IFS=$'\t' read -r t m s size avail it ia _; do
        [ "$t" = Z ] && [[ $m =~ ^m[0-9a-f]{5,8}$ ]] || continue
        [[ $size =~ ^[0-9]{1,18}$ && $avail =~ ^[0-9]{1,18}$ && $it =~ ^[0-9]{1,18}$ && $ia =~ ^[0-9]{1,18}$ ]] || continue
        _pa_stamp_split "$s" 2> /dev/null || continue
        [ -n "${cnt[$m]:-}" ] || mids+=("$m")
        cnt[$m]=$((${cnt[$m]:-0} + 1))
        [ -n "${oldest[$m]:-}" ] || oldest[$m]="$s"
        last[$m]="$s"$'\t'"$size"$'\t'"$avail"$'\t'"$it"$'\t'"$ia"
    done <<< "$obs"
    if [ "${#mids[@]}" = 0 ]; then
        printf '    volumes: no samples from the witness'"'"'s hourly pass yet\n'
        return 0
    fi
    for m in "${mids[@]}"; do
        IFS=$'\t' read -r s size avail it ia <<< "${last[$m]}"
        name="${mount_of[$m]:-}"
        if [ -z "$name" ]; then
            name="no store here is on it now"
            [ "$known" = 1 ] || name="mount point not known here"
        fi
        printf '    volume %s (%s): %s of %s free' "$m" "$(printf '%s' "$name" | tr -c ' -~' '?')" \
            "$(human_bytes "$avail")" "$(human_bytes "$size")"
        if [ "$((10#$it))" -gt 0 ]; then printf ', inodes %s of %s free' "$((10#$ia))" "$((10#$it))"; else printf ', no inode count'; fi
        n="${cnt[$m]}" first="${oldest[$m]}"
        a="$(pa_age "$first")"
        printf '; %s samples since %s\n' "$n" "$(fmt_time "${first%%/*}")"
        hist=""
        while IFS=$'\t' read -r t d w _ line _; do
            [ "$t" = Z ] && [ "$d" = "$m" ] && [ "$w" != "$s" ] && hist+="$w"$'\t'"$line"$'\n'
        done <<< "$obs"
        pa_vol_project "$s" "$avail" <<< "$hist"
        if [ "$PA_VOL_RATE" = - ]; then
            printf '      no projection: it needs 72 h of samples and a fall over them (%s now)\n' "$(fmt_age "$a")"
        else
            # fmt_time drops the year, which a date months off needs.
            w="${s%%/*}"
            if [ "$PA_VOL_HOURS" -gt 8760 ]; then
                risk="at risk in more than a year"
            else
                w=$((10#$w + PA_VOL_HOURS * 3600))
                if [ "$(date -u -d "@$w" +%Y 2> /dev/null)" = "$(date -u -d "@$PA_WALL" +%Y 2> /dev/null)" ]; then
                    risk="at risk by $(fmt_time "$w")"
                else
                    risk="at risk by $(date -u -d "@$w" '+%F %H:%M' 2> /dev/null || printf '?')"
                fi
            fi
            printf '      falling %s an hour; at that rate full of its last GiB in %s h, %s\n' \
                "$(human_bytes "$((PA_VOL_RATE * 1024))")" "$PA_VOL_HOURS" "$risk"
        fi
    done
}

# view_changes: the units the witness's hourly pass records as changed and not in force, and why.
view_changes() {
    local t k kind st cause u any=0 why
    while IFS=$'\t' read -r t _ k kind _ _ _ st _ _ _ cause _; do
        [ "$t" = I ] && [ "$kind" = change-pending ] && [[ $k == change:* ]] || continue
        case "$st" in open | acked | pending) ;; *) continue ;; esac
        u="${k#change:}"
        case "$cause" in
            change.env) why="an env file it loads changed after it started: restart it" ;;
            change.unit) why="its unit file changed: sudo systemctl daemon-reload" ;;
            change.binary) why="its binary was replaced while it runs: restart it" ;;
            *) why="?" ;;
        esac
        printf '    changed, not in force (%s): %s - %s\n' "$st" "$(unit_shown "$u")" "$why"
        any=1
    done <<< "$INCIDENTS_BODY"
    [ "$any" = 1 ] || printf '    changes: nothing recorded as waiting for a restart or a reload\n'
}

view_unit() {
    local unit="$1"
    if unit_show "$unit" ActiveState SubState Result NRestarts ActiveEnterTimestamp UnitFileState ExecMainStatus InvocationID; then
        printf '    %s: ActiveState=%s SubState=%s Result=%s NRestarts=%s UnitFileState=%s ExecMainStatus=%s since %s\n' \
            "$unit" "$U_ActiveState" "$U_SubState" "$U_Result" "$U_NRestarts" "$U_UnitFileState" "$U_ExecMainStatus" \
            "${U_ActiveEnterTimestamp:--}"
    else
        printf '    %s: systemctl did not answer\n' "$unit"
    fi
}

view_journal() {
    printf '    last journal lines of %s:\n' "$1"
    journalctl -q --no-pager -o short-iso -n 20 "_SYSTEMD_UNIT=$1" 2> /dev/null | head -c 65536 | view_untrusted
}

view_findings() {
    local i
    for i in "${!CCF_ID[@]}"; do
        case " $* " in *" ${CCF_ID[$i]} "*) ;; *) continue ;; esac
        printf '    finding %s %s (%s)\n' "${CCF_LEVEL[$i]}" "${CCF_ID[$i]}" "${CCF_SCOPE[$i]}"
        [ -z "${CCF_FIX[$i]}" ] || printf '      fix: %s\n' "${CCF_FIX[$i]}"
    done
}

view_logs_cursor() {
    local reader="$1" cdir="$2" i p text rc
    for i in "${!LOG_PATH[@]}"; do
        p="${LOG_PATH[$i]}"
        file_facts "$p"
        rc=0
        text="$(pa_read_as "$reader" "$cdir/$(cursor_name "$p")" 4096)" || rc=$?
        if [ "$rc" = 0 ]; then
            printf '    %s: file inode %s size %s; cursor inode %s offset %s\n' "$(braced "${LOG_LABEL[$i]}")" \
                "${F_INODE:--}" "${F_SIZE:--}" "$(json_int "$text" inode)" "$(json_int "$text" offset)"
        else
            printf '    %s: file inode %s size %s; cursor %s\n' "$(braced "${LOG_LABEL[$i]}")" "${F_INODE:--}" \
                "${F_SIZE:--}" "$(read_why "$rc")"
        fi
    done
}

stage_view() {
    local i u name st t
    print_header
    printf '%s\n' "$COLUMNS_LINE"
    for i in "${!R_STAGE[@]}"; do
        [ "${R_STAGE[$i]}" = "$VIEW" ] || continue
        print_row "$i"
    done
    case "$VIEW" in
        listen)
            for u in "${SENSOR_UNITS[@]}"; do view_unit "$u"; done
            for u in "${CCR_ROWS[@]}"; do printf '    listener %s\n' "$u"; done
            view_findings unit-missing unit-masked unit-down unit-disabled badbind noconfig listen-none \
                listen-foreign listen-loopback listen-ownerless danger fw nofw
            for u in "${SENSOR_UNITS[@]}"; do
                [ "${UNIT_UP[${u%.service}]:-0}" = 1 ] || view_journal "$u"
            done
            ;;
        source)
            # The paths come from root's own env files; they are still cleaned for the terminal.
            for i in "${!LOG_PATH[@]}"; do
                file_facts "${LOG_PATH[$i]}"
                case "${LOG_RC[$i]:-}" in
                    '') st="" ;;
                    0) st=", readable by $LOG_READER" ;;
                    6) st=", not readable by $LOG_READER" ;;
                    *) st=", readability not checked ($(read_why "${LOG_RC[$i]}"))" ;;
                esac
                printf '    %s %s: %s, %s bytes, modified %s%s\n' "$(braced "${LOG_LABEL[$i]}")" \
                    "$(printf '%s' "${LOG_PATH[$i]}" | tr -c ' -~' '?' | cut -b 1-200)" "$F_TYPE" "${F_SIZE:--}" \
                    "$(fmt_time "$F_MTIME")" "$st"
            done
            file_facts "$STATUS_ROOT/var/lib/propolis/logrotate.state"
            printf '    logrotate state file: %s, modified %s\n' "$F_TYPE" "$(fmt_time "$F_MTIME")"
            printf '    guard lines in 24 h: %s skipped, %s refused\n' \
                "$(journalctl -q -o cat --no-pager --since -24h _SYSTEMD_UNIT=propolis-logrotate.service _UID=0 2> /dev/null | grep -c -a -F 'propolis-logrotate-guard: skipping rotation of')" \
                "$(journalctl -q -o cat --no-pager --since -24h _SYSTEMD_UNIT=propolis-logrotate.service _UID=0 2> /dev/null | grep -c -a -F 'propolis-logrotate-guard: refusing to rotate')"
            view_findings logmissing logpath logquiet logsize-fail logsize-warn stale never policy guard \
                service-failed cursor-missing cursor-dir-unseen
            ;;
        ship)
            if [ "$ROLE" = collector ]; then
                env_of PROPOLIS_SHIPPER_CURSOR_DIR "$SHIPPER_ENV"
                view_logs_cursor propolis-shipper "${ENV_V:-$STATUS_ROOT/var/lib/propolis/shipper/cursors}"
                printf '    last accepted batch (newest state file): %s\n' "$(fmt_time "$SHIP_STATE")"
                view_unit shipper.service
                view_journal shipper.service
            fi
            ;;
        gateway)
            for i in "${!SPOOL_CN[@]}"; do
                st="not listed in $LOG_VAR"
                for u in "${LOG_PATH[@]}"; do
                    case "$u" in "${SPOOL_DIR%/}/${SPOOL_CN[$i]}"/*) st="listed in $LOG_VAR" ;; esac
                done
                printf '    %s: %s, last arrival %s, last accepted %s, %s\n' "$(braced "${SPOOL_CN[$i]}")" \
                    "$(human_bytes "${SPOOL_SIZE[$i]}")" "$(fmt_time "${SPOOL_LAST[$i]}")" \
                    "$(fmt_time "${SPOOL_ACC[$i]}")" "$st"
            done
            [ "$SPOOL_WITHHELD" = 0 ] || printf '    %s names withheld: not a plain id\n' "$SPOOL_WITHHELD"
            view_unit gateway.service
            printf '    gateway error lines in 24 h: %s\n' \
                "$(journalctl -q -o cat --no-pager --since -24h -p err _SYSTEMD_UNIT=gateway.service 2> /dev/null | wc -l)"
            for name in $(open_insts gateway-dup); do
                case "$name" in
                    -) printf '    witness: rebuilt batch dropped from a collector not listed, %s records counted lost\n' "$(seen_count gwdup:unlisted)" ;;
                    c[0-9a-f]*)
                        [[ $name =~ ^c[0-9a-f]{5,8}$ ]] || continue
                        printf '    witness: rebuilt batch dropped from %s, %s records counted lost\n' \
                            "$(collector_of "$name")" "$(seen_count "gwdup:$name")"
                        ;;
                esac
            done
            view_findings spool-unlisted spool-label-sensor spool-label-subsystem spool-label-other
            ;;
        intake)
            env_of PROPOLIS_CURSOR_DIR "$FLEET_ENV" "$PROPOLIS_ENV"
            view_logs_cursor propolis "${ENV_V:-$STATUS_ROOT/var/lib/propolis/cursors}"
            printf '    %s\n' "$(ready_words)"
            printf '%s\n' "$METRICS_BODY" | grep -E '^propolis_intake_(bytes_behind|oldest_unread_age_seconds|lines_quarantined_total)' \
                | head -n 100 | while read -r name st; do
                    if [[ $name =~ ^(propolis_intake_[a-z_]+)(\{sensor=\"([^\"]{0,80})\"\})?$ && $st =~ ^[0-9.e+]{1,30}$ ]]; then
                        printf '    %s%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]:+ $(braced "${BASH_REMATCH[3]}")}" "$st"
                    fi
                done
            view_unit propolis.service
            view_journal propolis.service
            ;;
        ledger)
            # Every session pa_pg opens is read-only by its own options, so SHOW
            # transaction_read_only would say `on` on any primary. What the server would impose
            # on the daemon is the database's and the role's own setting.
            if pa_pg 10 "$LEDGER_RO_SQL" > /dev/null; then
                printf '    default_transaction_read_only (database and role settings): %s\n' \
                    "$(printf '%s' "${PA_PG_OUT:-not set}" | tr -c 'A-Za-z0-9_=,. \n' '?' | head -n 1 | cut -b 1-120)"
            else
                printf '    default_transaction_read_only (database and role settings): %s %s\n' "$PA_PG_CAUSE" "$PA_PG_WHY"
            fi
            for i in 'SELECT pg_is_in_recovery()' \
                'SELECT count(*) FROM pg_locks WHERE NOT granted' \
                'SELECT age(datfrozenxid) FROM pg_database WHERE datname = current_database()' \
                'SELECT pg_database_size(current_database())'; do
                if pa_pg 10 "$i" > /dev/null; then
                    printf '    %s: %s\n' "$i" "$(printf '%s' "$PA_PG_OUT" | tr -c '0-9a-z\n' '?' | head -n 1)"
                else
                    printf '    %s: %s %s\n' "$i" "$PA_PG_CAUSE" "$PA_PG_WHY"
                    [ -z "$PA_PG_ERR" ] || printf '%s\n' "$PA_PG_ERR" | view_untrusted
                fi
            done
            ;;
        review)
            if [ "$LEDGER_OK" = 1 ] && pa_pg 10 'SELECT count(*) FILTER (WHERE decided_at IS NULL), extract(epoch FROM max(surfaced_at))::bigint, extract(epoch FROM max(decided_at))::bigint FROM review_queue' > /dev/null; then
                IFS='|' read -r i u name <<< "$PA_PG_OUT"
                printf '    pending %s; last surfaced %s; last decided %s\n' "$(printf '%s' "$i" | tr -c '0-9' '?')" \
                    "$(fmt_time "$u")" "$(fmt_time "$name")"
            fi
            ;;
        reports)
            if [ "$LEDGER_OK" = 1 ] && pa_pg 10 "$REPORTS_VIEW_SQL" > /dev/null; then
                while IFS='|' read -r name i u st t; do
                    [ -n "$name" ] || continue
                    [[ $t =~ ^[0-9]{1,12}$ ]] || t="?"
                    printf '    %s last attempt %s, last success %s, last status %s, %s attempts since the last success\n' \
                        "$(braced "$name")" "$(fmt_time "$i")" "$(fmt_time "$u")" \
                        "$(printf '%s' "${st:--}" | tr -c '0-9\n-' '?')" "$t"
                done <<< "$PA_PG_OUT"
            fi
            ;;
        feed)
            if [ -n "$FEED_DIR" ]; then
                u="$(pa_read_as propolis "$FEED_DIR/manifest.json" 65536)" || u=""
                if [[ $u =~ \"build_time\":\"([0-9T:.Z+-]{1,40})\" ]]; then
                    printf '    build_time %s\n' "${BASH_REMATCH[1]}"
                else
                    printf '    build_time not read\n'
                fi
            fi
            ;;
        publish)
            case "$PUB_MT" in
                '') t="never" ;;
                '?') t="not a regular file" ;;
                *) t="$(fmt_time "$PUB_MT")" ;;
            esac
            printf '    last pushed %s; %s\n' "$t" "${PUB_EXPECTED:--}"
            printf '    scheduler: %s (%s found)\n' "$(pa_push_scheduler 2> /dev/null)" "${PA_SCHED_N:-0}"
            t="${META[push_sched_since]:-}"
            [[ $t =~ ^([0-9]{1,12})/ ]] && printf '    witness: a scheduler seen since %s\n' "$(fmt_time "${BASH_REMATCH[1]}")"
            for name in push-failing push-unscheduled push-off; do
                [ "$(open_count "$name")" = 0 ] || printf '    witness: %s open\n' "$name"
            done
            ;;
        alert)
            for name in PROPOLIS_OPS_NTFY_URL PROPOLIS_OPS_NTFY_TOPIC PROPOLIS_OPS_NTFY_TOKEN; do
                env_of "$name" "$PROPOLIS_ENV"
                if [ -z "$ENV_V" ]; then
                    printf '    %s not set\n' "$name"
                else
                    case " $PA_INVALID " in
                        *" $name "*) printf '    %s set in %s, invalid (ignored)\n' "$name" "${PA_ENV_SRC##*/}" ;;
                        *) printf '    %s set in %s\n' "$name" "${PA_ENV_SRC##*/}" ;;
                    esac
                fi
            done
            printf '    undelivered failure alerts: %s%s\n' "$A_UNDELIVERED" "${A_SINCE:+ since $(fmt_time "$A_SINCE")}"
            printf '    failure hook lines in 24 h: %s not repeating, %s undelivered\n' \
                "$(journalctl -q -o cat --no-pager --since -24h SYSLOG_IDENTIFIER=propolis-alert _UID=0 2> /dev/null | grep -c -a -F 'not repeating')" \
                "$(journalctl -q -o cat --no-pager --since -24h SYSLOG_IDENTIFIER=propolis-alert _UID=0 2> /dev/null | grep -c -a -F 'undelivered')"
            printf '    daemon queue: %s%s\n' "$A_QUEUE" \
                "${A_QUEUE_OLDEST:+, oldest first_failed_unix $(fmt_time "$A_QUEUE_OLDEST")}"
            # The test page as recorded, without its code: --test-page prints it once, for the
            # operator to match against the phone, and a view kept on a screen has no need of it.
            printf '    %s\n' "$A_VERIFIED"
            if _pa_tp_line; then
                printf '    test page: asked %s, result %s, typed back %s\n' "$(fmt_time "${PA_TP_SENT%%/*}")" \
                    "$PA_TP_RESULT" "$(fmt_time "${PA_TP_ACKED%%/*}")"
            else
                printf '    test page: none recorded\n'
            fi
            # The newest ten lines of the send ledger, by key hash only.
            local l_s l_c l_k l_x l_m l_r l_w
            while IFS=$'\t' read -r t l_s l_c l_k l_x l_m l_r l_w _; do
                [ "$t" = L ] || continue
                printf '    ledger %s class %s key %s %s %s %s by %s\n' "$(fmt_time "${l_s%%/*}")" \
                    "$(view_field "${l_c:-}")" "$(view_field "${l_k:-}")" "$(view_field "${l_x:-}")" \
                    "$(view_field "${l_m:-}")" "$(view_field "${l_r:-}")" "$(view_field "${l_w:-}")"
            done < <(pa_state_read send-ledger | tail -n 10)
            # Each record as the walk lists it, then its fields by name. Tier, state and the
            # reminder fields stay out until a witness pass has judged the records.
            while IFS= read -r t; do
                [[ $t == I$'\t'* ]] || continue
                record_line "$t"
                printf '    %s\n' "$REC_LINE"
                IFS=$'\t' read -r -a name <<< "$t"
                printf '      key %s  kind %s  cause %s  cause_since %s  occ %s  nr_seen %s  legacy_out %s  flags %s\n' \
                    "$(view_field "${name[2]:-}")" "$(view_field "${name[3]:-}")" "$(view_field "${name[11]:-}")" \
                    "$(fmt_time "${name[12]%%/*}")" "$(view_field "${name[31]:-}")" "$(view_field "${name[32]:-}")" \
                    "$(view_field "${name[33]:-}")" "$(view_field "${name[30]:-}")"
                if [ -n "${META[light_last]:-}" ]; then
                    printf '      tier %s  state %s  opened %s  last_tx %s  reminders %s  next_due %s  resolved %s  proof %s  reopens %s  parent %s  would_push %s\n' \
                        "$(view_field "${name[6]:-}")" "$(view_field "${name[7]:-}")" "$(fmt_time "${name[9]%%/*}")" \
                        "$(view_field "${name[16]:-}")" "$(view_field "${name[18]:-}")" "$(fmt_time "${name[19]%%/*}")" \
                        "$(fmt_time "${name[21]%%/*}")" "$(view_field "${name[22]:-}")" "$(view_field "${name[23]:-}")" \
                        "$(view_field "${name[13]:-}")" "$(view_field "${name[29]:-}")"
                fi
            done <<< "$INCIDENTS_BODY"
            for t in "${HOOK_LINES[@]}"; do printf '    %s\n' "${t#*$'\t'}"; done
            ;;
        backup)
            printf '    last success: %s%s\n' "$(fmt_time "$B_SUCCESS")" "${B_SET:+ set $B_SET}"
            printf '    last failure: %s%s\n' "$(fmt_time "$B_FAILURE")" "${B_STEP:+ while $B_STEP}"
            unit_show propolis-backup.timer UnitFileState NextElapseUSecRealtime || true
            printf '    propolis-backup.timer %s, next %s\n' "${U_UnitFileState:-?}" "${U_NextElapseUSecRealtime:--}"
            # deploy/backup.sh's default; its unit loads no env file that could move it.
            u="$STATUS_ROOT/var/backups/propolis"
            if [ -d "$u" ] && [ ! -L "$u" ]; then
                t="$(timeout 10 df -P -- "$u" 2> /dev/null | tail -n +2 | head -n 1)"
                read -r _ _ _ name st _ <<< "$t"
                [[ $name =~ ^[0-9]{1,18}$ ]] || name=""
                printf '    backup directory /var/backups/propolis: %s free, %s used\n' \
                    "$(human_bytes "$((10#${name:-0} * 1024))")" "$(printf '%s' "${st:-?}" | tr -c '0-9%' '?')"
            else
                printf '    backup directory /var/backups/propolis: not present\n'
            fi
            t="${META[backup_sets]:-}"
            [[ $t =~ ^([0-9]{1,6})/([0-9]{1,3})$ ]] \
                && printf '    scheduled sets: %s of %s kept (witness, hourly)\n' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))"
            t="${META[pull_last]:-}"
            if [[ $t =~ ^([0-9]{1,12})/ ]]; then
                printf '    off-host pull last served: %s\n' "$(fmt_time "${BASH_REMATCH[1]}")"
            else
                printf '    off-host pull last served: never seen\n'
            fi
            for name in backup-hung backup-retention backup-offhost; do
                [ "$(open_count "$name")" = 0 ] || printf '    witness: %s open\n' "$name"
            done
            ;;
        host)
            timeout 10 df -P -- "$STATUS_ROOT/var/lib/propolis" "$STATUS_ROOT/var/log/propolis" "$STATUS_ROOT/var/spool/propolis" 2> /dev/null | sed 's/^/    /'
            timeout 10 df -Pi -- "$STATUS_ROOT/var/lib/propolis" "$STATUS_ROOT/var/log/propolis" "$STATUS_ROOT/var/spool/propolis" 2> /dev/null | sed 's/^/    /'
            journalctl --disk-usage 2> /dev/null | tr -c ' -~\n' '?' | head -n 2 | sed 's/^/    /'
            view_volumes
            view_changes
            printf '    clock: %s; %s\n' "${HOST_SYNC:-sync not read}" "${HOST_STEP:-no step in 24 h}"
            printf '    id salt: %s\n' "${HOST_SALT:-not checked}"
            if [[ " ${PA_STATE_UNREADABLE:-} " == *" meta "* ]]; then
                printf '    state written: ? (meta unreadable)\n'
            else
                printf '    state written: %s\n' "${META[where]:-nothing recorded yet}"
            fi
            ;;
        monitor)
            view_unit propolis.service
            printf '    ops monitor %s; %s; daemon queue %s\n' "$A_MONITOR" "$(ready_words)" "$A_QUEUE"
            ;;
        witness)
            printf '    propolis-witness@light.timer: ActiveState=%s UnitFileState=%s LastTriggerUSec=%s\n' \
                "${W_TIMER_ACTIVE:-?}" "${W_TIMER_FILE:-?}" "${W_TIMER_LAST:--}"
            view_unit propolis-witness@light.service
            for t in "${W_HB_LINES[@]}"; do printf '    heartbeat %s\n' "$t"; done
            [ "${#W_HB_LINES[@]}" -gt 0 ] || printf '    heartbeat: no line (/run is emptied by a reboot)\n'
            for name in "${!META[@]}"; do
                if pa_ok_field "$name" && pa_ok_field "${META[$name]}"; then
                    printf '    meta %s %s\n' "$name" "${META[$name]}"
                fi
            done | sort
            if [[ ${META[healed]:-} =~ ^([0-9]{1,9})/([0-9]{1,12})/ ]]; then
                printf '    restarts that healed (counted, never opened): %s, the latest %s\n' \
                    "${BASH_REMATCH[1]}" "$(fmt_time "${BASH_REMATCH[2]}")"
            fi
            printf '    hook spool files: %s (%s waiting over 10 min)\n' "$W_SPOOL_N" "$W_SPOOL_OLD"
            printf '    lockwait: %s consecutive passes without the lock\n' "$(lockwait_count)"
            if pa_maint_active; then
                printf '    maintenance marker: %s until %s\n' "$PA_MAINT_REASON" "$(pa_hms "$PA_MAINT_UNTIL")"
            else
                printf '    maintenance marker: none in force\n'
            fi
            printf '    banner: %s\n' "$(if [ -n "$W_BANNER_MT" ]; then fmt_time "$W_BANNER_MT"; else printf 'not written'; fi)"
            printf '    alert library version %s\n' "$PA_LIB_VERSION"
            ;;
        chain) printf '    the chain is verified inside the daemon, and its verdict is not written anywhere shell can read\n' ;;
        peers) printf '    other nodes on the same database cannot be seen from this host'"'"'s shell\n' ;;
    esac
    return 0
}

# view_field V: a record field as stored when it passes pa_ok_field, `?` otherwise.
view_field() {
    if pa_ok_field "${1:-}"; then printf '%s' "$1"; else printf '?'; fi
}

# ---- the walk -------------------------------------------------------------------------------

# status_walk: the header, ALERTS and the recent failures first, from state files and settings
# alone, so the operator sees them at once; then config-check, which can take a while, and the
# pipeline, rails, CHECK, 24 H, NEXT and IDS.
status_walk() {
    local i
    load_daemon
    load_alert_facts
    case "$ROLE" in control | gateway) load_spool ;; esac
    load_logs
    load_hook_spool
    load_ids local
    render_hook_spool
    load_witness_facts
    load_open_code
    if [ -z "$VIEW" ]; then
        print_header
        print_alerts
        print_recent
    fi
    run_config_check
    row_listen
    row_source
    row_ship
    row_gateway
    row_intake
    row_ledger
    row_review
    row_reports
    row_feed
    row_publish
    rail_alert
    rail_backup
    rail_chain
    rail_host
    rail_monitor
    rail_witness
    rail_peers
    first_stopped
    load_ids vendor
    if [ -n "$VIEW" ]; then
        # A view exits as the walk would: its row alone could hide a stage marked further up.
        stage_view
        exit_code
        return
    fi
    if [ "$MARKED" -ge 0 ]; then
        printf 'PIPELINE                                                   first stopped stage marked >\n'
    else
        printf 'PIPELINE  no stage stopped that shell can see; stages 7 to 10 are shown, not judged\n'
    fi
    printf '%s\n' "$COLUMNS_LINE"
    for i in "${!R_STAGE[@]}"; do
        [ -n "${R_NUM[$i]}" ] || continue
        print_row "$i"
    done
    printf 'RAILS\n'
    for i in "${!R_STAGE[@]}"; do
        [ -z "${R_NUM[$i]}" ] || continue
        print_row "$i"
    done
    print_check
    twenty_four
    next_line
    print_ids
    exit_code
}

status_walk
exit $?
