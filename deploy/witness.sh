#!/usr/bin/env bash
#
# The root witness: the part of the shell alerting code that runs on its own, on a timer.
# Installed as /usr/local/sbin/propolis-witness by deploy/install.sh and deploy/upgrade.sh;
# propolis-witness@light.service runs `propolis-witness light` every five minutes from
# propolis-witness@light.timer, and propolis-witness@hourly.service runs `propolis-witness hourly`
# once an hour from propolis-witness@hourly.timer.
#
# WHAT A LIGHT PASS DOES. It asks systemd once for the state of every Propolis unit (and reads
# the rotation guard's journal for a failed rotation run), then, under the state lock: takes in
# the failure hook's spool files (firings the hook could not record itself); judges the first
# sightings the hook left pending (one restart that healed is dropped and counted, a unit still
# down or restarting again is opened, a oneshot whose next run succeeded is dropped); opens a
# crash loop (NRestarts rising fast, or six times in six hours, on two passes in a row) and a
# unit left in the failed state on two passes; reminds open incidents on their schedule and
# resolves each with the proof of its kind; and writes its line in the heartbeat file and
# `meta light_last`. Last it writes the login banner, /run/motd.d/propolis, from the state files.
# When the alert target's URL or topic differs from the one the stored read check was made for,
# it runs the read check (below) before it takes the lock. It also judges the hourly pass from
# outside: its timer active and enabled, and a pass under three hours old.
#
# WHAT AN HOURLY PASS DOES. Without the lock: it runs the installed config-check
# (/usr/local/lib/propolis/config-check.sh --tsv --no-events --report-only) and reads its findings;
# it asks the ntfy server, without credentials, whether the topic can be read by anyone (three
# GETs, and one more with the token when a token is set; the anonymous-read check); and it asks
# systemd about the light pass's timer. Then, under the lock, it reads the state files afresh and
# changes only what is its own: a finding seen on two completed runs in a row is recorded with
# its tier from WITNESS_CC_TABLE, and resolved once absent from two that could check it (a run
# whose G row, listener cell or L line says its group was not checked says nothing of it, nor
# does one that printed a line out of form that could be it); a config-check that did not
# complete on two hourly passes opens cc-stopped; the read check's answer is stored for the gate
# and the banner; a light pass over twenty minutes old, or its timer stopped, opens witness-stale.
# What the light pass and the failure hook recorded in the meantime is kept as they wrote it.
#
# WHAT HOLDS AN OPEN. No unit kind opens in the first ten minutes of uptime, while a maintenance
# marker holds, or in the ten minutes after a marker was last seen (`meta maint_seen`): planned
# work is judged once its restarts have had time to settle, and restarts made under a marker or
# in those ten minutes do not count toward a slow loop afterwards. A first sighting held then
# stays pending. One held under a marker is flagged maint, by the hook or by a pass, and a
# record flagged maint is held for ten minutes from its sighting, since a short marker can come
# and go unseen between two passes. A sensor's loop in the first half hour of uptime waits,
# pending, for a config-check result, without which an unset bind cannot be told from a crash.
#
# RECORD ONLY. Nothing here sends, pages or posts. Each transition the v2 profile would push adds
# one to the record's would_push, which the status walk shows; that is all. Its only network
# requests are the read check's GETs, which carry no message; it runs no database probe.
#
# SAFE TO RUN FOREVER. An ordinary check error is recorded and the pass still exits 0, so it is
# never a failed unit for the failure hook to report; three in a row open the NOTICE
# tool-unusable. Every program it runs has a time limit, the light pass stops its optional reads
# after 200 s and its judgement after 240 s, the hourly pass its judgement after 720 s (marking
# itself partial), well inside the unit's 15 minutes, and nothing slow runs while it holds the
# state lock. When the lock is not free within 60 s (the hourly pass: 120 s) it writes no state,
# logs one line, counts the miss in /run/propolis-witness/lockwait
# (which the walk and the banner show), marks its heartbeat line partial and tries again on the
# next pass. No file it writes grows without bound: resolved records leave the incidents file
# after seven days, there is one spool file per unit and each is removed once taken in, and
# every pass removes temporary files a killed writer left behind.
# A missing directory, a full or read-only disk or a missing tool becomes a recorded note (state
# falls back to /run, then to the journal), never a crash loop.
#
# WHAT IT TRUSTS. It sources the alert library (/usr/local/sbin/propolis-alert-lib) only after
# checking that it, and every directory above it, is owned by root and writable by no one else.
# Unit names are checked against systemd's own form before they reach a file name or a command
# line, and every value systemctl prints is checked against its form before it is used. The
# installed config-check runs as root only after the same ownership check, of the script and of
# the libraries it sources beside itself, with a fixed argument list, a time limit and a cap on
# its output; every field of its output is checked before use, a line out of form is skipped and
# never taken as a finding gone, and a tier or a stage comes only from WITNESS_CC_TABLE, never
# from the output. The read check's
# topic and token reach curl only through files the library makes 0600, and the answer is judged
# by its status code and content type alone.
#
# Exit status: 0 after every pass that ran, whatever it found; 2 a bad argument; 3 the alert
# library is missing, not trusted, fails to load or is older than this script needs. Only those
# reach the failure hook, which records a witness unit's failure and never pages for it.
#
# Test seams (honoured only with PROPOLIS_ALERT_ROOT set; tests only): PROPOLIS_ALERT_ROOT puts
# every path under that directory (the installed config-check among them) and keeps the caller's
# PATH, so stubs win; PROPOLIS_WITNESS_NOW is the time as a WALL/BOOT/UP stamp;
# PROPOLIS_WITNESS_LOCK_WAIT replaces the wait for the state lock; PROPOLIS_WITNESS_DEADLINE
# replaces the 240 s (light) or 720 s (hourly) after which the pass judges nothing more.
#
# The library version this script needs; deploy/rollback.sh reads the line below.
# needs-alert-lib: 5

umask 077
WITNESS_SELF="${BASH_SOURCE[0]}"
WITNESS_NEEDS_LIB=0
while IFS= read -r witness_line; do
    case "$witness_line" in
        '# needs-alert-lib: '*)
            WITNESS_NEEDS_LIB="${witness_line#'# needs-alert-lib: '}"
            break
            ;;
    esac
done < "$WITNESS_SELF"
unset witness_line
cd / || exit 3
export LC_ALL=C TZ=UTC
IFS=$' \t\n'
set -uo pipefail

if [ "$#" -ne 1 ] || { [ "$1" != light ] && [ "$1" != hourly ]; }; then
    echo "usage: propolis-witness light|hourly   (light: the five-minute pass; hourly: config-check, the anonymous-read check and the light pass's health)" >&2
    exit 2
fi
INSTANCE="$1"

ROOT="${PROPOLIS_ALERT_ROOT:-}"
if [ -z "$ROOT" ]; then
    # The system's directories first: a program put under /usr/local can then never stand in for
    # a system tool this script runs by name, on a host where /usr/local is writable by a group.
    PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
    export PATH
    # The library's own time and privilege seams must not reach a production run either.
    unset PA_TEST_WALL PA_TEST_BOOT PA_TEST_UP PA_TEST_READ_AS_SELF PA_TEST_UID PA_TEST_PROFILE
    unset PROPOLIS_WITNESS_NOW PROPOLIS_WITNESS_LOCK_WAIT PROPOLIS_WITNESS_DEADLINE
fi

# ---- the alert library ----------------------------------------------------------------------

witness_no_library() {
    echo "propolis-witness: $1" >&2
    exit 3
}

# witness_trust_one PATH OWNER: PATH owned by OWNER and writable by no one else.
witness_trust_one() {
    local u a o g
    if ! read -r u a o g < <(timeout 5 stat -c '%u %a %U %G' -- "$1" 2> /dev/null); then
        WITNESS_UNTRUSTED="$1: cannot be checked"
        return 1
    fi
    if [ "$u" != "$2" ]; then
        WITNESS_UNTRUSTED="$1: not owned by root ($o:$g $a)"
    elif ((8#$a & 8#020)); then
        WITNESS_UNTRUSTED="$1: group-writable ($o:$g $a)"
    elif ((8#$a & 8#002)); then
        WITNESS_UNTRUSTED="$1: world-writable ($o:$g $a)"
    else
        return 0
    fi
    return 1
}

# witness_trust_dir DIR OWNER TOP: DIR passes witness_trust_one; under a test root (TOP) the
# directories above that root are the test's surroundings and pass unchecked.
witness_trust_dir() {
    local above="${1%/}"
    if [ -n "$3" ]; then
        case "$3" in "$above"/*) return 0 ;; esac
    fi
    witness_trust_one "$1" "$2"
}

# witness_trust FILE: the check the library's pa_trusted_exec makes, done here before the library
# itself is sourced, the way deploy/propolis-status.sh does it: FILE is a regular file, not a
# link, and it and every directory passed through to reach it (links among them followed and
# checked where they lead) belong to root and are writable by no one else. Whoever could write
# one of them could replace what a root timer sources every five minutes.
witness_trust() {
    local path="$1" owner=0 top="" cur=/ rest comp entry target hops=0
    WITNESS_UNTRUSTED=""
    if [ -n "$ROOT" ]; then
        top="$(cd -P -- "$ROOT" 2> /dev/null && pwd -P)" || {
            WITNESS_UNTRUSTED="$ROOT: missing"
            return 1
        }
        owner="$(timeout 5 stat -c %u -- "$top" 2> /dev/null)" || owner=0
    fi
    if [ -L "$path" ] || [ ! -f "$path" ]; then
        WITNESS_UNTRUSTED="$path: missing, a link or not a regular file"
        return 1
    fi
    rest="${path#/}"
    if [ -n "$top" ]; then
        case "$path" in "${ROOT%/}"/*) cur="$top" rest="${path#"${ROOT%/}"/}" ;; esac
    fi
    witness_trust_dir "$cur" "$owner" "$top" || return 1
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
                        WITNESS_UNTRUSTED="$entry: a symbolic link"
                        return 1
                    fi
                    if [ "$hops" -gt 40 ] || ! target="$(readlink -- "$entry")"; then
                        WITNESS_UNTRUSTED="$entry: too many levels of symbolic links"
                        return 1
                    fi
                    case "$target" in /*) cur=/ ;; esac
                    rest="${target#/}/$rest"
                elif [ -d "$entry" ]; then
                    cur="$entry"
                elif [ -z "$rest" ] && [ -f "$entry" ]; then
                    witness_trust_one "$entry" "$owner"
                    return
                else
                    WITNESS_UNTRUSTED="$entry: not a regular file"
                    return 1
                fi
                ;;
        esac
        witness_trust_dir "$cur" "$owner" "$top" || return 1
    done
    WITNESS_UNTRUSTED="$path: not a regular file"
    return 1
}

WITNESS_FIX="fix: sudo chmod g-w,o-w the directory named, for example sudo chmod g-w /usr/local/sbin (or remove /etc/staff-group-for-usr-local)"
WITNESS_LIB="$ROOT/usr/local/sbin/propolis-alert-lib"
WITNESS_LIB_FAIL="alert library not found, failing to load, or older than version $WITNESS_NEEDS_LIB at /usr/local/sbin/propolis-alert-lib; reinstall it from the checkout: sudo install -m 0644 deploy/alert-lib.sh /usr/local/sbin/propolis-alert-lib"
if ! witness_trust "$WITNESS_LIB"; then
    [ -e "$WITNESS_LIB" ] || witness_no_library "$WITNESS_LIB_FAIL"
    witness_no_library "alert library not trusted: $WITNESS_UNTRUSTED; $WITNESS_FIX"
fi
# Whatever an older or foreign file leaves behind must not read as a version or a function.
PA_LIB_VERSION=""
WITNESS_LIB_FUNCS="pa_init pa_settings_load pa_role pa_now pa_age pa_clock_check pa_salt_ensure
pa_id_table pa_ok_field pa_write pa_lock pa_unlock pa_state_read pa_state_write pa_maint_active
pa_cause pa_unit_map pa_incident_load pa_incident_get pa_incident_transition pa_incident_set
pa_incident_write pa_incident_prune pa_first_sighting pa_banner_write pa_trusted_exec pa_cleanup
pa_unit_name_ok pa_incident_fold pa_env_get pa_sensor_logs pa_readcheck_binding pa_readcheck_run
pa_readcheck_merge"
# shellcheck disable=SC2086 # the list is a fixed set of names
unset -f $WITNESS_LIB_FUNCS
# Loaded once in a subshell first: under set -u an unbound variable at the library's top level
# ends the shell that sources it, and an exit there ends it with the library's status, so either
# would end this pass with no word instead of the exit 3 that marks an unusable library.
# shellcheck source=deploy/alert-lib.sh
if [ "$(. "$WITNESS_LIB" > /dev/null 2>&1 && echo loaded)" != loaded ]; then
    witness_no_library "$WITNESS_LIB_FAIL"
fi
set +u
# shellcheck source=deploy/alert-lib.sh
if ! . "$WITNESS_LIB" 2> /dev/null; then
    set -u
    witness_no_library "$WITNESS_LIB_FAIL"
fi
set -u
# shellcheck disable=SC2086 # the list is a fixed set of names
if ! [[ $PA_LIB_VERSION =~ ^[0-9]{1,9}$ && $WITNESS_NEEDS_LIB =~ ^[0-9]{1,9}$ ]] \
    || [ "$((10#$PA_LIB_VERSION))" -lt "$((10#$WITNESS_NEEDS_LIB))" ] \
    || ! declare -F $WITNESS_LIB_FUNCS > /dev/null; then
    witness_no_library "$WITNESS_LIB_FAIL"
fi
trap 'pa_cleanup' EXIT
pa_init "$ROOT"
# The library's own check, which also resolves every link on the way, now that it is loaded.
if ! pa_trusted_exec "$WITNESS_LIB"; then
    witness_no_library "alert library not trusted: $PA_UNTRUSTED; $WITNESS_FIX"
fi

LOCK_WAIT=60
# The pass judges nothing more once this many seconds have gone: what
# it did is still written, and its heartbeat line says partial.
WITNESS_DEADLINE=240
if [ "$INSTANCE" = hourly ]; then
    # The programs an hourly pass runs on purpose each have their own limit: config-check 300 s;
    # the read check of two targets, four GETs each at 15 s, 120 s; systemctl 20 s for the timer
    # sample and 40 s for the role's two questions; about ten small reads of 5 s, 50 s; the state
    # lock 120 s. 650 s in all, inside 720 s. The local reads and writes of the state files have
    # no limit of their own: the library's `cat` and `stat` of each state file, pa_write's
    # `sync`, and the ownership checks' `stat` and `readlink` of each path. On a local disk they
    # take milliseconds; what bounds them on a disk that hangs is the unit's TimeoutStartSec of
    # 15 minutes.
    LOCK_WAIT=120
    WITNESS_DEADLINE=720
fi
if [ -n "$ROOT" ]; then
    if [[ ${PROPOLIS_WITNESS_NOW:-} =~ ^([0-9]{1,12})/([0-9a-f]{8})/([0-9]{1,10})$ ]]; then
        export PA_TEST_WALL="${BASH_REMATCH[1]}" PA_TEST_BOOT="${BASH_REMATCH[2]}" PA_TEST_UP="${BASH_REMATCH[3]}"
    fi
    if [[ ${PROPOLIS_WITNESS_LOCK_WAIT:-} =~ ^[1-9][0-9]{0,2}$ ]]; then LOCK_WAIT="$PROPOLIS_WITNESS_LOCK_WAIT"; fi
    if [[ ${PROPOLIS_WITNESS_DEADLINE:-} =~ ^[0-9]{1,3}$ ]]; then WITNESS_DEADLINE="$((10#$PROPOLIS_WITNESS_DEADLINE))"; fi
fi
pa_now

# Every program that asks the system something has a time limit, the library's calls included:
# these names shadow the programs for the library's functions too.
systemctl() { timeout 20 systemctl "$@"; }
logger() { timeout 5 logger "$@"; }

# note TEXT: one line in the journal under the witness's tag; a missing logger costs the line.
note() {
    logger -p daemon.notice -t propolis-witness "$1" 2> /dev/null || true
}

# The pass stops its optional reads (the rotation guard's journal) once this many seconds have
# gone, far inside the unit's TimeoutStartSec=15min.
WITNESS_SOFT_DEADLINE=200

# ---- what a pass looks at -------------------------------------------------------------------

# The units sampled: the daemon, the twelve sensors deploy/install.sh installs, the split
# deployment's two, the oneshots and the witness's own two instances, then their timers.
WITNESS_UNITS=(propolis.service sensor-catchall.service sensor-ssh.service sensor-telnet.service sensor-redis.service sensor-adb.service sensor-http.service sensor-ftp.service sensor-smtp.service sensor-tftp.service sensor-mqtt.service sensor-dns.service sensor-cred.service shipper.service gateway.service propolis-logrotate.service propolis-backup.service propolis-witness@light.service propolis-witness@hourly.service)
WITNESS_TIMERS=(propolis-logrotate.timer propolis-backup.timer propolis-witness@light.timer propolis-witness@hourly.timer)

# oneshot_timer UNIT: the timer that runs a oneshot, or nothing for a long-running unit.
oneshot_timer() {
    case "$1" in
        propolis-logrotate.service | propolis-backup.service) printf '%s' "${1%.service}.timer" ;;
        propolis-witness@*.service) printf '%s' "${1%.service}.timer" ;;
    esac
}

# spool_unit DIR NAME: sets SP_UNIT to the unit a hook spool file in DIR is for and SP_BASE to
# the hook's own name for it (UNIT, or hook-UNIT in the fallback directory), or fails. A file a
# pass claimed and did not finish, `.ingest.<pid>.<that name>`, counts as the hook's file: it
# holds firings nobody has taken in. A writer's temporary file does not.
spool_unit() {
    SP_BASE="$2" SP_UNIT=""
    if [[ $SP_BASE =~ ^\.ingest\.[0-9]{1,10}\.(.+)$ ]]; then SP_BASE="${BASH_REMATCH[1]}"; fi
    case "$SP_BASE" in *.tmp.*) return 1 ;; esac
    SP_UNIT="$SP_BASE"
    if [ "$1" = "$PA_RUN/fallback" ]; then
        [[ $SP_BASE == hook-* ]] || return 1
        SP_UNIT="${SP_BASE#hook-}"
    fi
    return 0
}

# ---- the systemd sample ---------------------------------------------------------------------

declare -A S_LOAD=() S_ACT=() S_SUB=() S_RES=() S_NR=() S_STATUS=() S_AEM=() S_IEM=() S_FILE=()
declare -A S_INV=() S_RESTART=() WANT=() _B=()
SAMPLE_OK=0 SAMPLE_CAUSE=""
SAMPLED=()
# The rotation guard's reading of a failed propolis-logrotate.service run, taken with the sample.
G_DONE=0 G_KIND="" G_TIER="" G_CAUSE=""

# sample_word VALUE PATTERN: VALUE when it matches PATTERN, else empty: systemctl's output is
# checked before any of it is used.
sample_word() {
    if [[ ${1:-} =~ $2 ]]; then printf '%s' "$1"; fi
}

# commit_block: the block of `key=value` lines just read, kept when it names a unit asked for.
commit_block() {
    local id="${_B[Id]:-}"
    if [ -n "$id" ] && [ -n "${WANT[$id]:-}" ]; then
        S_LOAD[$id]="$(sample_word "${_B[LoadState]:-}" '^[a-z-]{1,24}$')"
        S_ACT[$id]="$(sample_word "${_B[ActiveState]:-}" '^[a-z-]{1,24}$')"
        S_SUB[$id]="$(sample_word "${_B[SubState]:-}" '^[a-z-]{1,24}$')"
        S_RES[$id]="$(sample_word "${_B[Result]:-}" '^[a-z-]{1,32}$')"
        S_NR[$id]="$(sample_word "${_B[NRestarts]:-}" '^[0-9]{1,9}$')"
        S_STATUS[$id]="$(sample_word "${_B[ExecMainStatus]:-}" '^[0-9]{1,3}$')"
        S_AEM[$id]="$(sample_word "${_B[ActiveEnterTimestampMonotonic]:-}" '^[0-9]{1,18}$')"
        S_IEM[$id]="$(sample_word "${_B[InactiveEnterTimestampMonotonic]:-}" '^[0-9]{1,18}$')"
        S_FILE[$id]="$(sample_word "${_B[UnitFileState]:-}" '^[a-z-]{1,24}$')"
        S_INV[$id]="$(sample_word "${_B[InvocationID]:-}" '^[0-9a-f]{32}$')"
        S_RESTART[$id]="$(sample_word "${_B[Restart]:-}" '^[a-z-]{1,24}$')"
        [ -n "${S_LOAD[$id]}" ] || S_LOAD[$id]="?"
    fi
    _B=()
}

# parse_show TEXT: the blocks `systemctl show` printed, kept by commit_block for the units asked.
parse_show() {
    local line k
    _B=()
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            commit_block
            continue
        fi
        k="${line%%=*}"
        [ "$k" != "$line" ] || continue
        case "$k" in
            Id | LoadState | ActiveState | SubState | Result | NRestarts | ExecMainStatus \
                | ActiveEnterTimestampMonotonic | InactiveEnterTimestampMonotonic | UnitFileState \
                | InvocationID | Restart) _B[$k]="${line#*=}" ;;
        esac
    done <<< "$1"
    commit_block
}

# collect_sample: one `systemctl show` for every unit in scope, the units named by a record or a
# spool file among them (and the timer of each such oneshot), so a record is judged whatever
# unit it names. A word that is not a unit name is left out: systemd would answer for a unit of
# its own naming, or refuse the whole question and leave the pass with no sample. Sets SAMPLE_OK,
# or SAMPLE_CAUSE when systemd could not be asked. A failed
# rotation run's journal is read here too, before the pass takes the lock, as the hook reads it.
collect_sample() {
    local out rc t key u name dir timer
    local -a units=("${WITNESS_UNITS[@]}" "${WITNESS_TIMERS[@]}")
    for u in "${units[@]}"; do WANT[$u]=1; done
    while IFS=$'\t' read -r t _ key _; do
        [ "$t" = I ] || continue
        case "$key" in unit:*) u="${key#unit:}" ;; *) continue ;; esac
        pa_unit_name_ok "$u" && [ -z "${WANT[$u]:-}" ] || continue
        WANT[$u]=1
        units+=("$u")
    done < <(pa_state_read incidents)
    for dir in "$PA_STATE/hook" "$PA_RUN/fallback"; do
        [ -d "$dir" ] && [ ! -L "$dir" ] || continue
        while IFS= read -r -d '' name; do
            spool_unit "$dir" "$name" || continue
            u="$SP_UNIT"
            pa_unit_name_ok "$u" && [ -z "${WANT[$u]:-}" ] || continue
            WANT[$u]=1
            units+=("$u")
        done < <(timeout 10 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\0' 2> /dev/null)
    done
    for u in "${units[@]}"; do
        timer="$(oneshot_timer "$u")"
        [ -n "$timer" ] && [ -z "${WANT[$timer]:-}" ] || continue
        WANT[$timer]=1
        units+=("$timer")
    done
    out="$(systemctl show -p Id,LoadState,ActiveState,SubState,Result,NRestarts,ExecMainCode,ExecMainStatus,ActiveEnterTimestampMonotonic,InactiveEnterTimestampMonotonic,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,UnitFileState,MainPID,NeedDaemonReload,InvocationID,Restart -- "${units[@]}" 2> /dev/null)"
    rc=$?
    if [ "$rc" != 0 ]; then
        case "$rc" in 126 | 127) SAMPLE_CAUSE=tool.exec ;; *) SAMPLE_CAUSE=unknown ;; esac
        return 0
    fi
    parse_show "$out"
    if [ "${#S_LOAD[@]}" -eq 0 ]; then
        SAMPLE_CAUSE=unknown
        return 0
    fi
    for u in "${units[@]}"; do
        case "$u" in *.timer) continue ;; esac
        [ -n "${S_LOAD[$u]:-}" ] && SAMPLED+=("$u")
    done
    SAMPLE_OK=1
    # The guard's journal query is slow next to the rest of the pass, and the state lock is never
    # held across a slow read: sample_cause reuses what it found.
    u=propolis-logrotate.service
    if [ "${S_ACT[$u]:-}" = failed ] && [ -n "${S_INV[$u]:-}" ] && [ "$SECONDS" -lt "$WITNESS_SOFT_DEADLINE" ]; then
        pa_cause "${S_RES[$u]:-}" "${S_STATUS[$u]:-}" 0 > /dev/null
        PA_REC_KIND="" PA_REC_TIER="" PA_REC_CAUSE="$PA_CAUSE"
        _PA_HK_INV="${S_INV[$u]}"
        _pa_hook_guard
        G_DONE=1 G_KIND="$PA_REC_KIND" G_TIER="$PA_REC_TIER" G_CAUSE="$PA_REC_CAUSE"
    fi
}

# unit_facts UNIT: what the sample says about UNIT. F_ACTIVE is active, starting, restarting
# (waiting to be restarted after a crash), failed or inactive; F_UP the seconds it has been
# active (0 while starting, `-` when it is not up); F_NR NRestarts (empty when unknown);
# F_DISABLED 1 when it is off on purpose (disabled or masked and not running; for a oneshot, its
# timer disabled, masked or unknown to systemd) or no longer known to systemd; F_ONESHOT 1 for a
# unit run by a timer.
unit_facts() {
    local u="$1" timer aem
    F_NR="${S_NR[$u]:-}" F_AEM="${S_AEM[$u]:-}" F_DISABLED=0 F_ONESHOT=0 F_UP=-
    case "${S_ACT[$u]:-}" in
        active | reloading) F_ACTIVE=active ;;
        activating)
            if [ "${S_SUB[$u]:-}" = auto-restart ]; then F_ACTIVE=restarting; else F_ACTIVE=starting; fi
            ;;
        failed) F_ACTIVE=failed ;;
        *) F_ACTIVE=inactive ;;
    esac
    if [ "$F_ACTIVE" = active ]; then
        F_UP=0
        if [[ $F_AEM =~ ^[0-9]{1,18}$ ]]; then
            aem=$((10#$F_AEM / 1000000))
            [ "$aem" -gt "$((10#$PA_UP))" ] || F_UP=$((10#$PA_UP - aem))
        fi
    elif [ "$F_ACTIVE" = starting ]; then
        F_UP=0
    fi
    timer="$(oneshot_timer "$u")"
    if [ -n "$timer" ]; then
        F_ONESHOT=1
        case "${S_FILE[$timer]:-}" in
            disabled | masked) [ "$F_ACTIVE" = active ] || [ "$F_ACTIVE" = starting ] || F_DISABLED=1 ;;
        esac
        # A oneshot with no timer (a witness instance this release has none for, or a timer
        # removed) is never run again, so no next run could ever prove it fixed.
        if [ "${S_LOAD[$timer]:-}" = not-found ]; then
            [ "$F_ACTIVE" = active ] || [ "$F_ACTIVE" = starting ] || F_DISABLED=1
        fi
    else
        case "${S_FILE[$u]:-}" in
            disabled | masked) [ "$F_ACTIVE" != inactive ] && [ "$F_ACTIVE" != failed ] || F_DISABLED=1 ;;
        esac
    fi
    case "${S_LOAD[$u]:-}" in
        not-found) F_DISABLED=1 ;;
        masked) [ "$F_ACTIVE" = active ] || F_DISABLED=1 ;;
    esac
    return 0
}

# ---- observe: the samples kept between passes ------------------------------------------------
#
# The light pass owns the U, R and its own P lines of the observe file. A U line is the last
# sample of a unit: `U unit stamp nrestarts boot8`, and after those (appended under the minor
# revision rule, so a reader of the first four ignores them) the state word, the
# ActiveEnterTimestampMonotonic, whether the crash-loop condition held (1 or 0), and the stamp
# since which the unit has been up with the same NRestarts (`-` when it is not up). An R line is
# a unit's baseline for the slow rule, `R unit stamp nrestarts`, and a P line counts one check's
# results: `P check stamp result cause consecutive`.

#
# The hourly pass owns its own P lines: `config-check` (completed runs, ok, or not, error),
# `readcheck`, `witness-light` (the light pass fresh or stale, as it judged it) and one
# `clean:<key>` line per open finding, counting the completed runs in a row without it. The
# light pass's `witness-hourly` line is the same for the hourly pass. Every other line, the other
# instance's U and R lines among them, is kept exactly as read.

declare -A OBS_U=() OBS_R=() OBS_P=() NEW_U=() NEW_R=() JUDGED=()
OBS_KEEP=()
OBS_MINE_P=" units witness-hourly "
[ "$INSTANCE" != hourly ] || OBS_MINE_P=" config-check readcheck witness-light "

# obs_mine NAME: the P line NAME belongs to this instance.
obs_mine() {
    case "$OBS_MINE_P" in *" $1 "*) return 0 ;; esac
    [ "$INSTANCE" = hourly ] && [[ $1 == clean:* ]]
}

load_observe() {
    local line t name rest
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r t name rest <<< "$line"
        if [ "$INSTANCE" = hourly ] && { [ "$t" = U ] || [ "$t" = R ]; }; then
            OBS_KEEP+=("$line")
            continue
        fi
        case "$t" in
            U) pa_unit_name_ok "$name" && OBS_U[$name]="${rest:-}" ;;
            R) pa_unit_name_ok "$name" && OBS_R[$name]="${rest:-}" ;;
            P)
                if obs_mine "$name"; then
                    OBS_P[$name]="${rest:-}"
                else
                    OBS_KEEP+=("$line")
                fi
                ;;
            *) OBS_KEEP+=("$line") ;;
        esac
    done < <(pa_state_read observe)
}

# observe_body: the file's new body, every field checked as a state field is.
observe_body() {
    local u line f ok
    local -a fields
    if [ "$SAMPLE_OK" = 1 ]; then
        for u in "${!NEW_U[@]}"; do printf 'U\t%s\t%s\n' "$u" "${NEW_U[$u]}"; done
        for u in "${!NEW_R[@]}"; do printf 'R\t%s\t%s\n' "$u" "${NEW_R[$u]}"; done
        # A unit the deadline left unjudged keeps its last sample, so its two-pass rules carry on.
        for u in "${SAMPLED[@]}"; do
            [ -z "${JUDGED[$u]:-}" ] || continue
            [ -z "${OBS_U[$u]:-}" ] || printf 'U\t%s\t%s\n' "$u" "${OBS_U[$u]}"
            [ -z "${OBS_R[$u]:-}" ] || printf 'R\t%s\t%s\n' "$u" "${OBS_R[$u]}"
        done
    else
        for u in "${!OBS_U[@]}"; do printf 'U\t%s\t%s\n' "$u" "${OBS_U[$u]}"; done
        for u in "${!OBS_R[@]}"; do printf 'R\t%s\t%s\n' "$u" "${OBS_R[$u]}"; done
    fi | while IFS= read -r line; do
        IFS=$'\t' read -r -a fields <<< "$line"
        ok=1
        for f in "${fields[@]}"; do pa_ok_field "$f" || ok=0; done
        [ "$ok" = 0 ] || printf '%s\n' "$line"
    done
    for u in "${!OBS_P[@]}"; do printf 'P\t%s\t%s\n' "$u" "${OBS_P[$u]}"; done
    for line in "${OBS_KEEP[@]}"; do printf '%s\n' "$line"; done
}

# ---- small state helpers --------------------------------------------------------------------

WHERE=""
CHANGED=0
HEALED=0

# where_merge: folds PA_WHERE from the last write into WHERE, the worst of the pass: persistent,
# then run, then none.
where_merge() {
    case "$WHERE:${PA_WHERE:-}" in
        *:none | none:*) WHERE=none ;;
        *:run | run:*) WHERE=run ;;
        *:persistent) WHERE=persistent ;;
    esac
}

# lockwait_get: this instance's count of consecutive passes that missed the lock.
lockwait_get() {
    local f="$PA_RUN/lockwait" t c n=0
    [ -f "$f" ] && [ ! -L "$f" ] || {
        printf 0
        return 0
    }
    while read -r t c _; do
        [ "$t" = "$INSTANCE" ] && [[ $c =~ ^[0-9]{1,9}$ ]] && n=$((10#$c))
    done < <(timeout 5 head -c 4096 -- "$f" 2> /dev/null)
    printf '%s' "$n"
}

# lockwait_set N: this instance's line of the lockwait file, written without the lock (which is
# what it reports on), other instances' lines kept; 0 removes the line, and the file once empty.
lockwait_set() {
    local f="$PA_RUN/lockwait" t c body=""
    if [ -f "$f" ] && [ ! -L "$f" ]; then
        while read -r t c _; do
            [[ $t =~ ^[a-z]{1,16}$ && $c =~ ^[0-9]{1,9}$ ]] && [ "$t" != "$INSTANCE" ] || continue
            body+="$t"$'\t'"$c"$'\n'
        done < <(timeout 5 head -c 4096 -- "$f" 2> /dev/null)
    elif [ "$1" = 0 ]; then
        return 0
    fi
    [ "$1" = 0 ] || body+="$INSTANCE"$'\t'"$1"$'\n'
    if [ -z "$body" ]; then
        rm -f -- "$f" 2> /dev/null || true
    else
        pa_write "$f" < <(printf '%s' "$body") || true
    fi
}

# write_heartbeat STATUS: this instance's `B` line in the heartbeat file, other lines kept. A
# pass that wrote no state (it missed the lock) keeps the line's last word on where state lands.
write_heartbeat() {
    local f="$PA_RUN/heartbeat" g=0 head="" line t inst s w r body="" was=""
    if [ -f "$f" ] && [ ! -L "$f" ]; then
        {
            IFS= read -r head
            while IFS= read -r line; do
                IFS=$'\t' read -r t inst s w r _ <<< "$line"
                [ "$t" = B ] && [[ $inst =~ ^[a-z]{1,16}$ ]] || continue
                if [ "$inst" = "$INSTANCE" ]; then
                    case "${w:-}" in persistent | run | none) was="$w" ;; esac
                    continue
                fi
                if ! pa_ok_field "${s:-}" || ! pa_ok_field "${w:-}" || ! pa_ok_field "${r:-}"; then continue; fi
                body+="B"$'\t'"$inst"$'\t'"$s"$'\t'"$w"$'\t'"$r"$'\n'
            done
        } < <(timeout 5 head -c 65536 -- "$f" 2> /dev/null)
        [[ $head =~ ^#heartbeat\ v1\ g=([0-9]{1,18})$ ]] && g=$((10#${BASH_REMATCH[1]}))
    fi
    body+="B"$'\t'"$INSTANCE"$'\t'"$PA_STAMP"$'\t'"${WHERE:-${was:-none}}"$'\t'"$1"$'\n'
    pa_write "$f" < <(printf '#heartbeat v1 g=%s\n%s' "$((g + 1))" "$body") || true
}

# heartbeat_stamp INSTANCE: the stamp of INSTANCE's line in the heartbeat file, or nothing.
heartbeat_stamp() {
    local f="$PA_RUN/heartbeat" head="" line t inst s out=""
    [ -f "$f" ] && [ ! -L "$f" ] || return 0
    {
        IFS= read -r head
        [[ $head =~ ^#heartbeat\ v1\ g=[0-9]{1,18}$ ]] || return 0
        while IFS= read -r line; do
            IFS=$'\t' read -r t inst s _ <<< "$line"
            if [ "$t" = B ] && [ "$inst" = "$1" ] && _pa_stamp_split "${s:-}"; then out="$s"; fi
        done
    } < <(timeout 5 head -c 65536 -- "$f" 2> /dev/null)
    printf '%s' "$out"
}

# sweep_stale: the temporary files of writers killed between writing and renaming, older than
# ten minutes (no writer holds one that long), in both state directories and beside the banner.
sweep_stale() {
    local d
    for d in "$PA_STATE" "$PA_STATE/hook" "$PA_RUN" "$PA_RUN/fallback"; do
        [ -d "$d" ] && [ ! -L "$d" ] || continue
        timeout 10 find "$d" -mindepth 1 -maxdepth 1 -type f -name '*.tmp.*' -mmin +10 -delete 2> /dev/null || true
    done
    if [ -d "$PA_MOTD" ] && [ ! -L "$PA_MOTD" ]; then
        timeout 10 find "$PA_MOTD" -mindepth 1 -maxdepth 1 -type f -name '.propolis.tmp.*' -mmin +10 -delete 2> /dev/null || true
    fi
}

# ---- ids ------------------------------------------------------------------------------------

declare -A IDS=()
load_ids() {
    local input="" u id kind name
    for u in "${WITNESS_UNITS[@]}" "${SAMPLED[@]}"; do input+="unit"$'\t'"$u"$'\n'; done
    while IFS=$'\t' read -r id kind name; do
        [ "$kind" = unit ] && [ -n "$name" ] && IDS[$name]="$id"
    done < <(printf '%s' "$input" | pa_id_table 2> /dev/null)
}

# ---- applying transitions -------------------------------------------------------------------

# rec_set: puts the current record back in memory and marks the file for writing. Status 1 when
# it could not be kept, so a spool file behind it is not removed.
rec_set() {
    if pa_incident_set; then
        CHANGED=1
        return 0
    fi
    note "incident not recorded: the record of ${PA_INC[2]:-?} could not be kept (512 open, or a bad key)"
    return 1
}

# rec_open KEY KIND TIER STAGE CAUSE NR: opens KEY's record (a first sighting the hook left, or a
# new incident) with these attributes; an empty one keeps what the record has. What today's hook
# did and how often it fired stay the hook's: the witness only adds what it saw.
rec_open() {
    local key="$1" out="" occ="" had=0
    if pa_incident_get "$key" && [ "${PA_INC[7]}" != resolved ]; then
        had=1 out="${PA_INC[33]}" occ="${PA_INC[31]}"
    fi
    PA_REC_KIND="$2" PA_REC_TIER="$3" PA_REC_STAGE="$4" PA_REC_CAUSE="$5" PA_REC_NR="$6"
    PA_REC_INST="${IDS[${key#unit:}]:--}" PA_REC_OUT=- PA_REC_FLAG=""
    pa_incident_transition "$key" open || return 0
    if [ "$had" = 1 ]; then PA_INC[33]="$out" PA_INC[31]="$occ"; fi
    rec_set
}

# noconfig_open UNIT: config-check's `noconfig` finding for this sensor is open or pending: the
# unit restarts on an unset bind.
noconfig_open() {
    local k12
    k12="$(printf '%s' "noconfig:${1%.service}" | sha256sum 2> /dev/null)" || return 1
    pa_incident_get "finding:noconfig:${k12:0:12}" || return 1
    case "${PA_INC[7]}" in pending | open | acked) return 0 ;; esac
    return 1
}

# open_attrs UNIT KIND: sets O_KIND, O_TIER and O_STAGE for an open of KIND on UNIT from the unit
# map: the daemon's failures are its reserve kind, a sensor under an open noconfig finding is
# unit-nobind (ACT, never reminded).
open_attrs() {
    pa_unit_map "$1"
    O_KIND="$2" O_TIER="$PA_UNIT_TIER" O_STAGE="$PA_UNIT_STAGE"
    [ "$1" != propolis.service ] || O_KIND=daemon-down
    case "$1" in
        sensor-*.service)
            if noconfig_open "$1"; then O_KIND=unit-nobind O_TIER=ACT O_STAGE=listen; fi
            ;;
    esac
}

# sample_cause UNIT: the cause code of the unit's last run, from systemd's Result and status; the
# rotation guard's own causes for propolis-logrotate.service, as collect_sample read them.
sample_cause() {
    local u="$1"
    pa_cause "${S_RES[$u]:-}" "${S_STATUS[$u]:-}" 0 > /dev/null
    C_CAUSE="$PA_CAUSE" C_KIND="" C_TIER=""
    if [ "$u" = propolis-logrotate.service ] && [ "$G_DONE" = 1 ]; then
        C_CAUSE="$G_CAUSE" C_KIND="$G_KIND" C_TIER="$G_TIER"
    fi
}

# proof_for UNIT STEADY: the proof the record of UNIT has met on this sample, or nothing. Its
# kind decides: a oneshot's next run succeeded after the onset (nextrun); a crash loop or an
# unset bind has stayed up 30 min without a restart (quiet30); any other unit has stayed up
# 10 min without one (active10). Met on the first look after a reboot, it is `restart`.
proof_for() {
    local u="$1" steady="$2" kind="${PA_INC[3]:-}" onset="${PA_INC[10]:-}" iem met=""
    if [ "$F_ONESHOT" = 1 ] || [ "$kind" = rotation-skipped ]; then
        if [ "${S_RES[$u]:-}" = success ] && [[ ${S_IEM[$u]:-} =~ ^[0-9]{1,18}$ ]] && [ "${S_IEM[$u]}" != 0 ]; then
            iem=$((10#${S_IEM[$u]} / 1000000))
            if _pa_stamp_split "$onset" && [ "$_PA_B" = "$PA_BOOT" ] && [ "$PA_BOOT" != - ]; then
                [ "$iem" -le "$((10#$_PA_U))" ] || met=nextrun
            else
                met=nextrun
            fi
        fi
    elif [ "$steady" != - ]; then
        case "$kind" in
            unit-crashloop | unit-nobind) [ "$(pa_age "$steady")" -lt 1800 ] || met=quiet30 ;;
            *) [ "$(pa_age "$steady")" -lt 600 ] || met=active10 ;;
        esac
    fi
    [ -n "$met" ] || return 0
    if _pa_stamp_split "${PA_INC[9]:-}" && [ "$_PA_B" != "$PA_BOOT" ]; then met=restart; fi
    printf '%s' "$met"
}

# ---- the checks -----------------------------------------------------------------------------

MAINT=0
# judge_unit UNIT: crash loops (NRestarts rising fast or slowly, on two passes in a row), the
# failed state on two passes, the first sightings the hook left, and the proofs of what is open.
judge_unit() {
    local u="$1" key="unit:$1" pstamp pnr pboot pstate paem ploop psteady same=0 d age loop=0
    local bstamp="" bnr="" prevup="?" steady=- failed2=0 loop2=0 state="" judge hold="" proof k
    local nocc=0
    JUDGED[$u]=1
    unit_facts "$u"
    # A unit systemd no longer knows has nothing to sample: only a record of it is settled, as
    # for a unit retired on purpose.
    if [ "${S_LOAD[$u]:-}" = not-found ]; then
        pa_incident_get "$key" || return 0
        case "${PA_INC[7]}" in
            open | acked)
                PA_REC_PROOF=disabled
                pa_incident_transition "$key" resolve && rec_set
                ;;
            pending) pa_incident_transition "$key" drop && rec_set ;;
        esac
        return 0
    fi
    IFS=$'\t' read -r pstamp pnr pboot pstate paem ploop psteady _ <<< "${OBS_U[$u]:-}"
    pstamp="${pstamp:--}" pnr="${pnr:--}" pboot="${pboot:--}" pstate="${pstate:--}"
    paem="${paem:--}" ploop="${ploop:-0}" psteady="${psteady:--}"
    if [ "$PA_BOOT" != - ] && [ "$pboot" = "$PA_BOOT" ] && _pa_stamp_split "$pstamp"; then same=1; fi
    IFS=$'\t' read -r bstamp bnr _ <<< "${OBS_R[$u]:-}"
    # Up since when with the same NRestarts and the same start: a restart or a new start between
    # two passes starts the quiet time of a resolve again. So does a kept time that cannot be
    # read or is dated ahead of the clock, which would otherwise never reach its ten minutes.
    if [ "$F_ACTIVE" = active ]; then
        steady="$PA_STAMP"
        if [ "$same" = 1 ] && [ "$pstate" = active ] && [ "$pnr" = "${F_NR:--}" ] && [ "$paem" = "${F_AEM:--}" ] \
            && [ "$(pa_age "$psteady")" -ge 0 ]; then
            steady="$psteady"
        fi
    fi
    # Crash loops. A different boot, or a count that went down (a manual start resets it),
    # replaces the sample and judges nothing.
    if [ "$same" = 1 ] && [[ $F_NR =~ ^[0-9]{1,9}$ && $pnr =~ ^[0-9]{1,9}$ ]] && [ "$((10#$F_NR))" -ge "$((10#$pnr))" ]; then
        d=$((10#$F_NR - 10#$pnr))
        age="$(pa_age "$pstamp")"
        if [ "$d" -ge 3 ] && [ "$age" -ge 1 ] && [ "$age" -le 900 ]; then loop=1; fi
        if ! _pa_stamp_split "${bstamp:-}" || [ "$_PA_B" != "$PA_BOOT" ] || ! [[ ${bnr:-} =~ ^[0-9]{1,9}$ ]] \
            || [ "$((10#$bnr))" -gt "$((10#$F_NR))" ] || [ "$(pa_age "$bstamp")" -lt 0 ] \
            || [ "$(pa_age "$bstamp")" -gt 21600 ]; then
            bstamp="$PA_STAMP" bnr="$F_NR"
        fi
        # Quiet time alone never moves the baseline: a unit that crashes every 45 minutes is up
        # over half an hour between crashes, and six of them in six hours are still a loop. Only
        # a resolve does, for the restarts it answered (below).
        if [ "$((10#$F_NR - 10#$bnr))" -ge 6 ]; then loop=1; fi
    else
        bstamp="$PA_STAMP" bnr="${F_NR:--}"
    fi
    if [ "$loop" = 1 ] && [ "$ploop" = 1 ]; then loop2=1; fi
    if [ "$same" = 1 ]; then
        case "$pstate" in
            active)
                if [[ $paem =~ ^[0-9]{1,18}$ ]] && _pa_stamp_split "$pstamp"; then
                    prevup=$((10#$_PA_U - 10#$paem / 1000000))
                    [ "$prevup" -ge 0 ] || prevup=0
                fi
                ;;
            starting) prevup=0 ;;
            *) prevup=- ;;
        esac
        [ "$F_ACTIVE" != failed ] || [ "$pstate" != failed ] || failed2=1
    fi
    NEW_U[$u]="$PA_STAMP"$'\t'"${F_NR:--}"$'\t'"$PA_BOOT"$'\t'"$F_ACTIVE"$'\t'"${F_AEM:--}"$'\t'"$loop"$'\t'"$steady"
    NEW_R[$u]="$bstamp"$'\t'"${bnr:--}"

    # What holds every open: the boot grace, planned work announced by the marker, and the ten
    # minutes after the marker was last seen, so restarts the work caused have settled first. A
    # sensor's loop also waits for a first config-check result after a boot: without one an
    # unset bind cannot be told from a crash.
    [ "$PA_UP" -ge 600 ] || hold=grace
    if [ "$MAINT" = 1 ]; then
        hold=maint
    elif [ -z "$hold" ] && maint_recent; then
        hold="tail"
    fi
    # Restarts made while planned work holds were announced: the slow rule starts counting again
    # from here, so a unit that settled during the work is not a loop once the hold ends. A loop
    # still running then is caught by the fast rule, which compares two passes.
    case "$hold" in
        maint | tail)
            if [[ $F_NR =~ ^[0-9]{1,9}$ ]]; then NEW_R[$u]="$PA_STAMP"$'\t'"$F_NR"; fi
            ;;
    esac
    case "$u" in
        sensor-*.service)
            if [ "$PA_UP" -lt 1800 ] && ! cc_result_recent; then nocc=1; fi
            ;;
    esac

    if pa_incident_get "$key"; then state="${PA_INC[7]}"; fi
    if [ "$F_DISABLED" = 1 ]; then
        case "$state" in
            open | acked)
                PA_REC_PROOF=disabled
                pa_incident_transition "$key" resolve && rec_set
                ;;
            pending)
                pa_incident_transition "$key" drop && rec_set
                ;;
        esac
        return 0
    fi
    case "$state" in
        pending)
            # A sighting written after this pass took its sample would be judged against a
            # sample from before the failure: the next pass judges it.
            sighted_after_sample && return 0
            # The hook flagged it maint because a marker held when it fired, and an upgrade's
            # marker often comes and goes between two passes, unseen by any: the ten minutes
            # then count from the sighting itself.
            if [ -z "$hold" ] && flagged_maint_recent; then hold="tail"; fi
            if [ "$F_ONESHOT" = 1 ]; then
                # A oneshot does not restart itself: its next run is the answer. One that
                # succeeded after the sighting healed it; one still failed opens.
                proof="$(proof_for "$u" -)"
                if [ "$proof" = nextrun ] || [ "$proof" = restart ]; then
                    judge=ran
                elif [ "$F_ACTIVE" = failed ]; then
                    judge=open
                else
                    judge="wait"
                fi
            else
                judge="$(pa_first_sighting "${PA_INC[32]:--}" "$F_NR" "$F_UP" "$prevup")"
                if [ "$loop2" = 1 ] || [ "$failed2" = 1 ]; then judge=open; fi
            fi
            case "$judge" in
                open)
                    case "$hold" in
                        maint)
                            # Flagged only under a marker: the flag says planned work, and it is
                            # what holds the record for ten minutes from its sighting.
                            k="${PA_INC[30]:--}"
                            _pa_flag_add maint
                            [ "${PA_INC[30]}" = "$k" ] || rec_set
                            ;;
                        grace | tail) ;;
                        *)
                            [ "$nocc" = 0 ] || return 0
                            k=""
                            if [ "$loop2" = 1 ] && [ "${PA_INC[3]}" = unit-failed ]; then
                                open_attrs "$u" unit-crashloop
                                k="$O_KIND"
                            fi
                            rec_open "$key" "$k" "" "" "" "$F_NR"
                            ;;
                    esac
                    ;;
                drop)
                    # Counted whether the record goes or a kept resolve comes back: either way
                    # one restart healed.
                    HEALED=$((HEALED + 1))
                    pa_incident_transition "$key" drop && rec_set
                    ;;
                ran) pa_incident_transition "$key" drop && rec_set ;;
            esac
            ;;
        open | acked)
            if [ "$loop2" = 1 ] && [ "${PA_INC[3]}" = unit-failed ]; then
                open_attrs "$u" unit-crashloop
                PA_REC_KIND="$O_KIND" PA_REC_TIER="" PA_REC_CAUSE=""
                pa_incident_transition "$key" change && rec_set
            elif [ "$F_ACTIVE" = failed ]; then
                sample_cause "$u"
                if [ "$C_CAUSE" != unknown ] && [ "${PA_INC[11]}" != unknown ] \
                    && [ "${C_CAUSE%%.*}" != "${PA_INC[11]%%.*}" ]; then
                    PA_REC_KIND="" PA_REC_TIER="" PA_REC_CAUSE="$C_CAUSE"
                    pa_incident_transition "$key" change && rec_set
                fi
            else
                proof="$(proof_for "$u" "$steady")"
                if [ -n "$proof" ]; then
                    PA_REC_PROOF="$proof"
                    if pa_incident_transition "$key" resolve && rec_set; then
                        # What the resolve answered leaves the slow rule's baseline too.
                        if [[ $F_NR =~ ^[0-9]{1,9}$ ]]; then NEW_R[$u]="$PA_STAMP"$'\t'"$F_NR"; fi
                    fi
                fi
            fi
            ;;
        *)
            [ -z "$hold" ] || return 0
            if [ "$loop2" = 1 ]; then
                open_attrs "$u" unit-crashloop
                pa_cause "${S_RES[$u]:-}" "${S_STATUS[$u]:-}" 0 > /dev/null
                if [ "$nocc" = 1 ]; then
                    PA_REC_KIND="$O_KIND" PA_REC_TIER="$O_TIER" PA_REC_STAGE="$O_STAGE" PA_REC_CAUSE="$PA_CAUSE"
                    PA_REC_NR="$F_NR" PA_REC_INST="${IDS[$u]:--}" PA_REC_OUT=- PA_REC_FLAG=""
                    pa_incident_transition "$key" pending && rec_set
                    return 0
                fi
                rec_open "$key" "$O_KIND" "$O_TIER" "$O_STAGE" "$PA_CAUSE" "$F_NR"
            elif [ "$failed2" = 1 ]; then
                sample_cause "$u"
                open_attrs "$u" unit-failed
                [ -z "$C_KIND" ] || O_KIND="$C_KIND"
                [ -z "$C_TIER" ] || O_TIER="$C_TIER"
                rec_open "$key" "$O_KIND" "$O_TIER" "$O_STAGE" "$C_CAUSE" "$F_NR"
            fi
            ;;
    esac
    return 0
}

# cc_result_recent: a config-check run completed in this boot or in the last two hours (meta
# cc_last, written by the hourly pass for every run, and cc_fail 0: the last one completed).
cc_result_recent() {
    local v="${META_CC_LAST%%/*}"
    [ -n "$v" ] || return 1
    [ "$(_pa_num "${META_CC_FAIL:-0}")" = 0 ] || return 1
    v="${META_CC_LAST%/*/*}"
    _pa_stamp_split "$v" || return 1
    [ "$_PA_B" = "$PA_BOOT" ] && return 0
    [ "$(pa_age "$v")" -ge 0 ] && [ "$(pa_age "$v")" -le 7200 ]
}

# maint_recent: a maintenance marker was seen on a pass in the last ten minutes (meta
# maint_seen). What a marker held counts only if it still holds ten minutes after the marker
# ends, and this pass cannot see when an ended marker ended, only when one was last seen.
maint_recent() {
    local a
    _pa_stamp_split "$META_MAINT_SEEN" || return 1
    a="$(pa_age "$META_MAINT_SEEN")"
    [ "$a" -ge 0 ] && [ "$a" -lt 600 ]
}

# flagged_maint_recent: the current record carries the maint flag and its sighting (the onset,
# else first_seen) is under ten minutes old. A sighting dated ahead of the clock gives no hold:
# it could hold until the clock caught up.
flagged_maint_recent() {
    local s="${PA_INC[10]:-}" a
    case ",${PA_INC[30]:-}," in *,maint,*) ;; *) return 1 ;; esac
    _pa_stamp_split "$s" || s="${PA_INC[8]:-}"
    a="$(pa_age "$s")"
    [ "$a" -ge 0 ] && [ "$a" -lt 600 ]
}

# sighted_after_sample: the current record's first sighting (first_seen, or the onset of a
# sighting kept inside its reopen window) is dated at or after this pass's own stamp, which was
# taken before the sample: the hook wrote it while the pass was running. Only a stamp of this
# boot can be: one from another boot dated ahead of the clock (a host with no clock battery,
# before NTP) would otherwise keep the record from being judged until the clock caught up.
sighted_after_sample() {
    local s
    for s in "${PA_INC[8]:-}" "${PA_INC[10]:-}"; do
        _pa_stamp_split "$s" || continue
        if [ "$_PA_B" != - ] && [ "$_PA_B" = "$PA_BOOT" ]; then
            [ "$((10#$_PA_U))" -lt "$((10#$PA_UP))" ] || return 0
        elif [ "$_PA_B" = - ] && [ "$PA_BOOT" = - ]; then
            # With no boot id on either side the wall clock is all there is to go by.
            [ "$((10#$_PA_W))" -lt "$((10#$PA_WALL))" ] || return 0
        fi
    done
    return 1
}

# judge_records_without_sample: systemd could not be asked, so nothing is judged (unknown never
# resolves anything); after six hours of that an open unit incident is flagged cannotverify.
judge_records_without_sample() {
    local line key consec
    IFS=$'\t' read -r _ _ _ consec _ <<< "${OBS_P[units]:-}"
    [[ ${consec:-} =~ ^[0-9]{1,9}$ ]] && [ "$((10#$consec))" -ge 72 ] || return 0
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        case "$key" in unit:*) ;; *) continue ;; esac
        pa_incident_get "$key" || continue
        case "${PA_INC[7]}" in open | acked) ;; *) continue ;; esac
        case ",${PA_INC[30]}," in *,cannotverify,*) continue ;; esac
        _pa_flag_add cannotverify
        rec_set
    done
}

# check_counts CHECK RESULT CAUSE: one more result of a check in its P line; three failures in a
# row open the NOTICE tool-unusable on tool:CHECK, two clean results resolve it.
check_counts() {
    local check="$1" result="$2" cause="$3" prev consec=0
    IFS=$'\t' read -r _ prev _ consec _ <<< "${OBS_P[$check]:-}"
    if [ "${prev:-}" = "$result" ] && [[ ${consec:-} =~ ^[0-9]{1,9}$ ]]; then
        consec=$((10#$consec + 1))
    else
        consec=1
    fi
    [ "$consec" -le 999999 ] || consec=999999
    OBS_P[$check]="$PA_STAMP"$'\t'"$result"$'\t'"$cause"$'\t'"$consec"
    if [ "$result" != ok ] && [ "$consec" -ge 3 ]; then
        if ! pa_incident_get "tool:$check" || [ "${PA_INC[7]}" = resolved ]; then
            PA_REC_KIND=tool-unusable PA_REC_TIER=NOTICE PA_REC_STAGE=host PA_REC_CAUSE="$cause"
            PA_REC_INST=- PA_REC_NR=- PA_REC_OUT=- PA_REC_FLAG=""
            pa_incident_transition "tool:$check" open && rec_set
        fi
    elif [ "$result" = ok ] && [ "$consec" -ge 2 ] && pa_incident_get "tool:$check"; then
        case "${PA_INC[7]}" in
            open | acked)
                PA_REC_PROOF=clean2
                pa_incident_transition "tool:$check" resolve && rec_set
                ;;
        esac
    fi
}

# ingest_spool: the hook's spool files, each taken in under the lock as the hook would have
# recorded it (first sighting, or an open for a unit that does not restart itself), with its
# count of firings. A file that is not in the hook's format is removed with a note: it can never
# be taken in.
#
# The hook writes its file without the lock, rewriting the same path by rename with the count
# raised, so each file is first claimed: renamed to `.ingest.<pid>.<name>` and read from there. A
# firing the hook spools meanwhile starts a new file under the old name, for the next pass. The
# claimed copy is removed only once the records are written (spool_finish), and given back under
# its old name when they are not; one a killed pass left behind is taken in like the hook's own.
SPOOL_DONE=() SPOOL_BACK=()
ingest_spool() {
    local dir name unit f claim text head line t first count cause nr out tx
    local new was occ hold
    local -a names
    for dir in "$PA_STATE/hook" "$PA_RUN/fallback"; do
        [ -d "$dir" ] && [ ! -L "$dir" ] || continue
        # Listed whole before the first claim: a listing still running could show a claimed
        # file again under its new name.
        names=()
        while IFS= read -r -d '' name; do
            names+=("$name")
        done < <(timeout 10 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\0' 2> /dev/null)
        for name in "${names[@]}"; do
            spool_unit "$dir" "$name" || continue
            unit="$SP_UNIT"
            f="$dir/$name"
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            if ! pa_unit_name_ok "$unit"; then
                note "hook spool file ${dir##*/}/<unnamed> is not a unit's name; removed"
                rm -f -- "$f" 2> /dev/null || true
                continue
            fi
            claim="$dir/.ingest.$$.$SP_BASE"
            if [ "$f" != "$claim" ]; then
                # The same claim name left by an earlier pass is taken in as its own file.
                [ ! -e "$claim" ] && [ ! -L "$claim" ] || continue
                mv -f -T -- "$f" "$claim" 2> /dev/null || continue
            fi
            if ! text="$(timeout 5 head -c 4096 -- "$claim" 2> /dev/null)"; then
                spool_give_back "$claim" "$dir/$SP_BASE"
                continue
            fi
            head="${text%%$'\n'*}" line="${text#*$'\n'}"
            line="${line%%$'\n'*}"
            t="" first="" count="" cause="" nr="" out=""
            IFS=$'\t' read -r t first _ count _ _ _ cause nr out _ <<< "$line"
            if ! [[ $head =~ ^#hook\ v1\ g=[0-9]{1,18}$ ]] || [ "$t" != H ]; then
                note "hook spool file for $unit is not in the hook's format; removed"
                rm -f -- "$claim" 2> /dev/null || true
                continue
            fi
            pa_ok_field "$cause" || cause=unknown
            [[ $nr =~ ^[0-9]{1,9}$ ]] || nr=-
            case "$out" in delivered | undelivered | cooldown | journal) ;; *) out=- ;; esac
            count="$(_pa_num "$count")"
            [ "$count" -ge 1 ] || count=1
            pa_unit_map "$unit"
            PA_REC_KIND=unit-failed PA_REC_STAGE="$PA_UNIT_STAGE" PA_REC_TIER="$PA_UNIT_TIER"
            [ "$unit" != propolis.service ] || PA_REC_KIND=daemon-down
            PA_REC_CAUSE="$cause" PA_REC_NR="$nr" PA_REC_OUT="$out" PA_REC_FLAG=hookspool
            PA_REC_INST="${IDS[$unit]:--}"
            # What holds the witness's opens holds a spooled firing's too: a oneshot that failed
            # during the boot grace, under a marker (flagged maint then) or in the ten minutes
            # after one stays a first sighting, for the oneshot rule to judge once they are over.
            hold=0
            [ "$MAINT" = 0 ] || hold=1
            [ "$PA_UP" -ge 600 ] || hold=1
            tx=pending
            [ "${S_RESTART[$unit]:-}" != no ] || [ "$hold" = 1 ] || tx=open
            [ "$hold" = 1 ] || ! maint_recent || tx=pending
            new=1 was=""
            if pa_incident_get "unit:$unit"; then
                was="${PA_INC[7]}"
                [ "$was" = resolved ] || new=0
            fi
            if ! pa_incident_transition "unit:$unit" "$tx"; then
                spool_give_back "$claim" "$dir/$SP_BASE"
                continue
            fi
            # The flag says planned work: a firing held only by the boot grace does not carry it.
            [ "$MAINT" = 0 ] || _pa_flag_add maint
            occ=$(($(_pa_num "${PA_INC[31]:-}") + count - 1))
            [ "$occ" -le 999999999 ] || occ=999999999
            PA_INC[31]="$occ"
            if [ "$new" = 1 ] && _pa_stamp_split "$first"; then
                if [ "${PA_INC[8]}" = "$PA_STAMP" ]; then
                    # A new incident: it began when the hook first spooled it.
                    PA_INC[8]="$first" PA_INC[10]="$first" PA_INC[12]="$first"
                elif [ "$was" = resolved ] && [ "${PA_INC[7]}" = pending ]; then
                    # A sighting kept inside the reopen window: its onset is when the hook saw it.
                    PA_INC[10]="$first"
                fi
            fi
            if rec_set; then
                SPOOL_DONE+=("$claim") SPOOL_BACK+=("$dir/$SP_BASE")
            else
                spool_give_back "$claim" "$dir/$SP_BASE"
            fi
        done
    done
}

# spool_give_back CLAIM NAME: a claimed spool file not taken in goes back under the hook's name,
# unless the hook has started a new file there since: it then stays claimed, and the next pass
# takes both in.
spool_give_back() {
    mv -n -T -- "$1" "$2" 2> /dev/null || true
}

# spool_finish OK: the claimed spool files once the records are written (OK 1: removed) or not
# (OK 0: given back, to be taken in by a pass that can write).
spool_finish() {
    local i
    for i in "${!SPOOL_DONE[@]}"; do
        if [ "$1" = 1 ]; then
            rm -f -- "${SPOOL_DONE[$i]}" 2> /dev/null || true
        else
            spool_give_back "${SPOOL_DONE[$i]}" "${SPOOL_BACK[$i]}"
        fi
    done
    SPOOL_DONE=() SPOOL_BACK=()
}

# remind_all: every open record whose reminder is due gets it (record mode: one more would_push).
remind_all() {
    local line key
    local -a keys=()
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        keys+=("$key")
    done
    for key in "${keys[@]}"; do
        # A record opened by a release that kept no schedule (the hook's opens before the
        # witness existed) has none: it gets the one its tier and open time give. One that has
        # had a reminder and has none due has used its schedule, or had the rest skipped.
        if pa_incident_get "$key" && [ "${PA_INC[7]}" = open ] && [ "${PA_INC[19]:--}" = - ] \
            && [ "$(_pa_num "${PA_INC[18]:-}")" = 0 ]; then
            _pa_schedule
            [ "${PA_INC[19]}" = - ] || rec_set
        fi
        pa_incident_transition "$key" remind > /dev/null 2>&1 && rec_set
    done
    return 0
}

# ---- config-check's findings ----------------------------------------------------------------
#
# WITNESS_CC_TABLE: every finding id deploy/config-check.sh emits, and what the witness does with
# it. Fields, separated by `|`: the id; page (recorded at the tier shown, pushed under v2), daily
# (recorded as a NOTICE, seen in the walk and counted in the daily message) or never (not
# recorded); the tier; the stage or rail; the config-check row whose limitation makes a run say
# nothing about the finding (listener for the per-listener rows); how its instance is found (unit:
# the hash of `<id>:<unit>` for each configured sensor; scope: the listener row of its scope;
# logpath: the hash of `<id>:<path>` for each log of PROPOLIS_SENSOR_LOGS; fold: every name folds
# into one record; `-`: one per host); and the phrase a push will carry. A tier or a stage never
# comes from config-check's output, and an id with no row here is not recorded. A page row is
# there because nothing else sees its fault; the reason for each daily and never row is that
# another kind already pages the same fault, or that the condition is standing or deliberate.
WITNESS_CC_TABLE='
unit-missing|page|PAGE|listen|listener|unit|listener <inst> not installed
unit-down|page|PAGE|listen|listener|unit|listener <inst> stopped while enabled
listen-foreign|page|PAGE|listen|listener|scope|port of <inst> held by another process
listen-loopback|page|PAGE|listen|listener|scope|port of <inst> held on loopback
listen-none|page|PAGE|listen|listener|scope|listener <inst> up, nothing listening
fw|page|ACT|listen|listener|scope|firewall drops a port of <inst>
danger|page|PAGE|listen|listener|scope|real service exposed on a port of <inst>
spool-label-sensor|page|PAGE|gateway|gateway-spool|logpath|source <inst> refused at the gateway
spool-unlisted|page|ACT|gateway|gateway-spool|fold|collector <inst> not listed
intake-wrongpath|page|ACT|intake|listener|logpath|intake reads the wrong file for <inst>
intake-absent|page|ACT|intake|listener|logpath|source <inst> not ingested
logsize-fail|page|ACT|source|listener|logpath|log <inst> not rotated in time
stale|page|ACT|source|logrotate|-|rotation has not run for 3 h
backup-timer|page|ACT|backup|backup|-|no backup scheduled
backup-stale|page|ACT|backup|backup|-|last good backup too old
ops-failure-hook|page|ACT|alert|alerting|-|failure hook not installed
badbind|daily|NOTICE|listen|listener|-|-
unit-masked|daily|NOTICE|listen|listener|-|-
unit-disabled|daily|NOTICE|listen|listener|-|-
unit-notenabled|daily|NOTICE|listen|listener|-|-
listen-ownerless|daily|NOTICE|listen|listener|-|-
nofw|daily|NOTICE|listen|listener|-|-
logpath|daily|NOTICE|listen|listener|-|-
logquiet|daily|NOTICE|listen|listener|-|-
logmissing|daily|NOTICE|listen|listener|-|-
noconfig|daily|NOTICE|listen|units|-|-
logsize-warn|daily|NOTICE|source|listener|-|-
timer|daily|NOTICE|source|logrotate|-|-
timer-enabled|daily|NOTICE|source|logrotate|-|-
service-failed|never|-|source|logrotate|-|-
never|daily|NOTICE|source|logrotate|-|-
policy|daily|NOTICE|source|logrotate|-|-
guard|daily|NOTICE|source|logrotate|-|-
cursor-dir-unseen|daily|NOTICE|source|cursors|-|-
cursor-missing|daily|NOTICE|source|cursors|-|-
intake-none|daily|NOTICE|intake|intake-list|-|-
intake-bad|daily|NOTICE|intake|intake-list|-|-
intake-duplabel|daily|NOTICE|intake|intake-list|-|-
intake-duppath|daily|NOTICE|intake|intake-list|-|-
intake-rel|daily|NOTICE|intake|intake-list|-|-
intake-nodir|daily|NOTICE|intake|intake-list|-|-
intake-orphan|daily|NOTICE|intake|intake-list|-|-
intake-name|daily|NOTICE|intake|intake-list|-|-
events-none|never|-|intake|listener|-|-
events-old|never|-|intake|listener|-|-
spool-label-subsystem|daily|NOTICE|gateway|gateway-spool|-|-
spool-label-other|daily|NOTICE|gateway|gateway-spool|-|-
ledger-owner|never|-|ledger|ledger|-|-
ledger-database|never|-|ledger|ledger|-|-
ledger-grants|never|-|ledger|ledger|-|-
backup-headroom|daily|NOTICE|backup|backup|-|-
backup-timer-enabled|daily|NOTICE|backup|backup|-|-
backup-plaintext|daily|NOTICE|backup|backup|-|-
backup-failing|daily|NOTICE|backup|backup|-|-
backup-never|daily|NOTICE|backup|backup|-|-
backup-age-missing|daily|NOTICE|backup|backup|-|-
ops-monitor-off|daily|NOTICE|alert|alerting|-|-
ops-no-push|daily|NOTICE|alert|alerting|-|-
ops-no-heartbeat|daily|NOTICE|alert|alerting|-|-
ops-push-half|daily|NOTICE|alert|alerting|-|-
clock-unsynced|daily|NOTICE|host|clock|-|-
bins-missing|daily|NOTICE|host|binaries|-|-
bins-differ|never|-|host|binaries|-|-
stamp-missing|never|-|host|deploy-stamp|-|-
stamp-nohead|never|-|host|deploy-stamp|-|-
stamp-noinstalled|never|-|host|deploy-stamp|-|-
stamp-mismatch|daily|NOTICE|host|deploy-stamp|-|-
stamp-behind|never|-|host|deploy-stamp|-|-
watch-env-missing|daily|NOTICE|host|watcher|-|-
watch-env-owner|daily|NOTICE|host|watcher|-|-
watch-env-empty|daily|NOTICE|host|watcher|-|-
watch-env-drift|daily|NOTICE|host|watcher|-|-
watch-key-empty|daily|NOTICE|host|watcher|-|-
watch-key-missing|daily|NOTICE|host|watcher|-|-
env-mode|daily|NOTICE|host|env-files|-|-
env-none|daily|NOTICE|host|env-files|-|-
env-empty|daily|NOTICE|host|env-files|-|-
env-systemd-only|daily|NOTICE|host|env-files|-|-
witness-missing|daily|NOTICE|witness|witness|-|-
witness-timer|daily|NOTICE|witness|witness|-|-
'

declare -A T_ELIG=() T_TIER=() T_STAGE=() T_GROUP=() T_INST=()
load_table() {
    local id elig tier stage group inst
    while IFS='|' read -r id elig tier stage group inst _; do
        [ -n "$id" ] || continue
        T_ELIG[$id]="$elig" T_TIER[$id]="$tier" T_STAGE[$id]="$stage" T_GROUP[$id]="$group" T_INST[$id]="$inst"
    done <<< "$WITNESS_CC_TABLE"
}

CC_PATH="$ROOT/usr/local/lib/propolis/config-check.sh"
# What the installed config-check sources from its own directory, as root like the script itself:
# the listener library always, and an alert library there in preference to the installed one.
CC_SOURCED=("$ROOT/usr/local/lib/propolis/listeners-lib.sh" "$ROOT/usr/local/lib/propolis/alert-lib.sh")
# config-check prints at most this many spool-unlisted findings (deploy/config-check.sh
# SPOOL_MAX_REPORTED), so a run that prints this many may have found more.
WITNESS_SPOOL_REPORTED=20
CC_DONE=0 CC_RC=- CC_SECS=0 CC_WHY="" CC_BAD=0 CC_BAD_ALL=0 CC_LIMIT_ALL=0 CC_FOLD_N=0
declare -A CC_PRESENT=() CC_HELD=() CC_DAILY=() CC_LIMITED=() CC_INST=() CC_FW_UNKNOWN=() CC_DANGER=()
declare -A CC_DOWN_UNIT=() CC_BAD_ID=()
CF_ID=() CF_K12=() CF_SCOPE=()
PA_FI_UNITS=() PA_FI_SCOPE=() PA_FI_UNIT=()

# cc_limit TEXT: the groups an L line says the run could not check, from the fixed start of its
# text (deploy/config-check.sh#limit). A text with no group here limits every group, so a limit
# that a later config-check adds can never let a finding resolve unchecked.
cc_limit() {
    case "$1" in
        'ss unavailable'* | 'firewall rules unreadable'* | 'socket owners hidden'* \
            | 'log files not traversable'* | 'propolis.env / shipper.env not readable'*)
            CC_LIMITED[listener]=1
            ;;
        'df is not installed'* | 'the free space of '* | 'the backup directory '*) CC_LIMITED[backup]=1 ;;
        'gateway spool'*) CC_LIMITED[gateway-spool]=1 ;;
        'ledger query skipped'*) CC_LIMITED[ledger]=1 ;;
        'the build of '* | 'the installed '* | 'binary list unreadable'*) CC_LIMITED[binaries]=1 ;;
        'checkout HEAD not readable'*) CC_LIMITED[deploy-stamp]=1 ;;
        'checkout unknown'*) CC_LIMITED[deploy-stamp]=1 CC_LIMITED[binaries]=1 ;;
        'watch.env not readable'* | 'watcher home not traversable'*) CC_LIMITED[watcher]=1 ;;
        *) CC_LIMIT_ALL=1 ;;
    esac
}

# cc_run: the installed config-check, once, as root: only after the ownership check every program
# root runs passes, for the script and for what it sources beside itself, with the fixed argument
# list, under `timeout 300`, its output cut at 2 MiB and never shown. Sets CC_DONE (1 for a
# completed run: the header, S first, E last and E's count equal to the F lines), CC_RC (its exit
# status, `-` when it was not run), CC_SECS, CC_WHY, and from a completed run the findings (CF_*),
# the listener rows (PA_FI_SCOPE, PA_FI_UNIT), the rows that could not be checked (CC_LIMITED from
# G rows, listener cells and L lines; CC_LIMIT_ALL for an L line of no known group) and the scopes
# whose firewall cell is unknown. Every field is checked before use: an F line whose id fails
# pa_ok_field, or whose key hash is not 12 hex, is skipped and counted in CC_BAD (CC_BAD_ALL for a
# bad id, CC_BAD_ID[id] for a bad hash of a good id), since it cannot be tied to a key.
cc_run() {
    local out rc t0 line t a b c d n_f=0 n_e="" first=1 second=0 last="" i f
    local -a cells
    CC_DONE=0 CC_RC=- CC_SECS=0 CC_WHY="" CC_BAD=0 CC_BAD_ALL=0 CC_LIMIT_ALL=0
    if ! pa_trusted_exec "$CC_PATH"; then
        CC_WHY="not trusted: $PA_UNTRUSTED"
        [ -e "$CC_PATH" ] || [ -L "$CC_PATH" ] || CC_WHY="not installed"
        return 0
    fi
    for f in "${CC_SOURCED[@]}"; do
        # The alert library beside it is optional (config-check falls back to the installed one,
        # which this script already trusts); the listener library is not.
        [ "$f" != "${CC_SOURCED[1]}" ] || [ -e "$f" ] || [ -L "$f" ] || continue
        if ! pa_trusted_exec "$f"; then
            CC_WHY="not trusted: $PA_UNTRUSTED"
            return 0
        fi
    done
    t0="$SECONDS"
    out="$(
        timeout 300 "$CC_PATH" --tsv --no-events --report-only < /dev/null 2> /dev/null \
            | LC_ALL=C head -c 2097152 | LC_ALL=C tr -d '\000'
        exit "${PIPESTATUS[0]}"
    )"
    rc=$?
    CC_RC="$rc" CC_SECS=$((SECONDS - t0))
    if [ "$rc" = 124 ]; then
        CC_WHY="timed out after 300 s"
        return 0
    fi
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        last="$line"
        if [ "$first" = 1 ]; then
            first=0
            [ "$line" = "#config-check tsv v1" ] || {
                CC_WHY="not in the TSV form"
                return 0
            }
            second=1
            continue
        fi
        IFS=$'\t' read -r t a b c d _ <<< "$line"
        if [ "$second" = 1 ]; then
            second=0
            [ "$t" = S ] || {
                CC_WHY="not in the TSV form"
                return 0
            }
            continue
        fi
        case "$t" in
            G)
                if pa_ok_field "${a:-}" && [ "${b:-}" = unknown ]; then CC_LIMITED[$a]=1; fi
                ;;
            R)
                if ! pa_ok_field "${a:-}" || ! pa_ok_field "${b:-}"; then continue; fi
                PA_FI_SCOPE+=("$a") PA_FI_UNIT+=("$b")
                IFS=$'\t' read -r -a cells <<< "$line"
                for i in 4 5 6 7 8 9; do
                    [ "${cells[$i]:-}" != unknown ] || CC_LIMITED[listener]=1
                done
                [ "${cells[6]:-}" != unknown ] || CC_FW_UNKNOWN[$a]=1
                ;;
            F)
                n_f=$((n_f + 1))
                if ! pa_ok_field "${b:-}"; then
                    CC_BAD=$((CC_BAD + 1)) CC_BAD_ALL=1
                    continue
                fi
                if ! [[ ${c:-} =~ ^[0-9a-f]{12}$ ]]; then
                    CC_BAD=$((CC_BAD + 1))
                    CC_BAD_ID[$b]=1
                    continue
                fi
                pa_ok_field "${d:-}" || d=-
                CF_ID+=("$b") CF_K12+=("$c") CF_SCOPE+=("$d")
                ;;
            L) cc_limit "${a:-}" ;;
            E) n_e="${a:-}" ;;
        esac
    done <<< "$out"
    if [[ ${last%%$'\t'*} != E || ! $n_e =~ ^[0-9]{1,9}$ ]] || [ "$((10#$n_e))" -ne "$n_f" ]; then
        CC_WHY="output cut off or incomplete"
        CF_ID=() CF_K12=() CF_SCOPE=() PA_FI_SCOPE=() PA_FI_UNIT=() CC_LIMITED=() CC_FW_UNKNOWN=()
        CC_BAD_ID=() CC_BAD_ALL=0 CC_LIMIT_ALL=0
        return 0
    fi
    CC_DONE=1
}

# cc_findings: the findings of a completed run that the table records, by key, with their
# instances. Every spool-unlisted finding folds into finding:spool-unlisted:all (its names come
# from directories the gateway account writes, which must not be able to fill the record bound).
# A finding another kind pages on this run is daily for the run (CC_DAILY): a listen-foreign on a
# port a danger finding holds, and (judge_findings decides it, from systemd) a unit-down whose unit
# is failed, which unit-failed carries. A finding seen but not judged on this run is held
# (CC_HELD): a unit-down whose unit cannot be placed or is neither inactive nor failed, a fw
# finding whose firewall cell is unknown.
cc_findings() {
    local i id k12 scope key inst
    for i in "${!CF_ID[@]}"; do
        [ "${CF_ID[$i]}" != danger ] || CC_DANGER[${CF_SCOPE[$i]}]=1
    done
    for i in "${!CF_ID[@]}"; do
        id="${CF_ID[$i]}" k12="${CF_K12[$i]}" scope="${CF_SCOPE[$i]}"
        case "${T_ELIG[$id]:-}" in page | daily) ;; *) continue ;; esac
        if [ "$id" = spool-unlisted ]; then
            key=finding:spool-unlisted:all
            CC_FOLD_N=$((CC_FOLD_N + 1))
        else
            key="finding:$id:$k12"
        fi
        pa_ok_field "$key" || continue
        CC_PRESENT[$key]="$id"
        inst="$(pa_finding_inst "${T_INST[$id]}" "$id" "$k12" "$scope")"
        [ -z "$inst" ] || CC_INST[$key]="$inst"
        case "$id" in
            unit-down)
                if [ -n "$inst" ]; then CC_DOWN_UNIT[$key]="${inst#*$'\t'}"; else CC_HELD[$key]=1; fi
                ;;
            listen-foreign) [ -z "${CC_DANGER[$scope]:-}" ] || CC_DAILY[$key]=1 ;;
            fw) [ -z "${CC_FW_UNKNOWN[$scope]:-}" ] || CC_HELD[$key]=1 ;;
        esac
    done
}

# ---- the anonymous-read check ---------------------------------------------------------------

declare -A RC_CLASS=() RC_JSON=() RC_RAW=() RC_SSE=() RC_TOKEN=() RC_BIND=() RC_CAUSE=()
RC_ROLES=()

# rc_roles: the targets to check, by role: both when the shell target and the daemon's are the
# same one, else shell and daemon apiece (from a later release they can differ); none without a
# target. Sets RC_ROLES and RC_BIND.
rc_roles() {
    local sb="" db=""
    RC_ROLES=()
    [ "${PA_TARGET:-0}" != 1 ] || sb="$(pa_readcheck_binding "$PA_URL" "$PA_TOPIC")" || sb=""
    [ "${PA_D_TARGET:-0}" != 1 ] || db="$(pa_readcheck_binding "$PA_D_URL" "$PA_D_TOPIC")" || db=""
    if [ -n "$sb" ] && [ "$sb" = "$db" ]; then
        RC_ROLES=(both) RC_BIND[both]="$sb"
    else
        [ -z "$sb" ] || RC_ROLES+=(shell) RC_BIND[shell]="$sb"
        [ -z "$db" ] || RC_ROLES+=(daemon) RC_BIND[daemon]="$db"
    fi
}

# rc_collect ALL: the read check of each target role, without the lock: every role (ALL 1, the
# hourly pass), or only those whose stored line is bound to another target or missing (ALL 0, a
# light pass, so a changed URL or topic is checked within five minutes). The results wait in
# RC_* for rc_store.
rc_collect() {
    local role url topic token
    rc_roles
    for role in "${RC_ROLES[@]}"; do
        if [ "$1" = 0 ]; then
            if _pa_rc_line "${role/both/shell}" && [ "$PA_RCL_BIND" = "${RC_BIND[$role]}" ] \
                && { [ "$PA_RCL_ROLE" = "$role" ] || [ "$role" != both ]; }; then
                continue
            fi
        fi
        past_deadline && return 0
        if [ "$role" = daemon ]; then
            url="$PA_D_URL" topic="$PA_D_TOPIC" token=""
        else
            url="$PA_URL" topic="$PA_TOPIC" token="${PA_TOKEN:-}"
        fi
        pa_readcheck_run "$url" "$topic" "$token" || true
        RC_CLASS[$role]="$PA_RC_CLASS" RC_JSON[$role]="$PA_RC_JSON" RC_RAW[$role]="$PA_RC_RAW"
        RC_SSE[$role]="$PA_RC_SSE" RC_TOKEN[$role]="$PA_RC_TOKEN" RC_CAUSE[$role]="$PA_RC_CAUSE"
    done
}

# rc_store: under the lock, the readcheck file read afresh with this pass's answers merged in. A
# line of a role no target has now goes, except that a both line stands for the shell target
# when that has no line of its own; a line this pass did not check, and a line of a type this
# release does not know, are kept as read.
rc_store() {
    local line t role new="" old="" r keep b
    local -A have=()
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        old+="$line"$'\n'
        IFS=$'\t' read -r t _ _ _ _ _ _ _ _ role _ <<< "$line"
        if [ "$t" != R ]; then
            # A line of a type this release does not know belongs to one that does.
            new+="$line"$'\n'
            continue
        fi
        keep=""
        for r in "${RC_ROLES[@]}"; do
            [ -z "${RC_CLASS[$r]:-}" ] || continue
            if [ "$role" = "$r" ]; then
                keep="$line"
            elif [ "$role" = both ] && [ "$r" = shell ]; then
                keep="${line%$'\t'both$'\t'*}"$'\t'shell$'\t'"${line##*$'\t'both$'\t'}"
            fi
        done
        if [ -n "$keep" ] && [ -z "${have[$role]:-}" ]; then
            new+="$keep"$'\n'
            have[$role]=1
        fi
    done < <(pa_state_read readcheck)
    for r in "${RC_ROLES[@]}"; do
        [ -n "${RC_CLASS[$r]:-}" ] || continue
        b=0
        if _pa_rc_line "${r/both/shell}" && { [ "$PA_RCL_ROLE" = "$r" ] || [ "$PA_RCL_ROLE" = both ]; }; then b=1; fi
        PA_RC_CLASS="${RC_CLASS[$r]}" PA_RC_JSON="${RC_JSON[$r]}" PA_RC_RAW="${RC_RAW[$r]}"
        PA_RC_SSE="${RC_SSE[$r]}" PA_RC_TOKEN="${RC_TOKEN[$r]}"
        new+="$(pa_readcheck_merge "$r" "${RC_BIND[$r]}" "$b")"$'\n'
    done
    [ "$new" != "$old" ] || return 0
    pa_state_write readcheck < <(printf '%s' "$new")
    where_merge
}

# rc_result: the hourly pass's one result for the read check (ok, or unknown with a cause, for
# the P line and tool-unusable): unknown when an attempt could not be made or got no definite
# answer.
rc_result() {
    local r code
    RCR_RESULT=ok RCR_CAUSE=-
    for r in "${RC_ROLES[@]}"; do
        [ -n "${RC_CLASS[$r]:-}" ] || continue
        if [ "${RC_CAUSE[$r]}" != - ]; then
            RCR_RESULT=unknown RCR_CAUSE="${RC_CAUSE[$r]}"
        elif [ "${RC_CLASS[$r]}" = transient ]; then
            RCR_RESULT=unknown
            for code in "${RC_JSON[$r]}" "${RC_RAW[$r]}" "${RC_SSE[$r]}"; do
                case "$code" in
                    000) RCR_CAUSE=net.connect ;;
                    429) RCR_CAUSE=http.rate ;;
                    5[0-9][0-9]) RCR_CAUSE=http.server ;;
                    *) continue ;;
                esac
                break
            done
            [ "$RCR_CAUSE" != - ] || RCR_CAUSE=unknown
        fi
    done
}

# ---- the other pass's health ----------------------------------------------------------------

# streak NAME RESULT: one more result (ok or error) in this instance's P line NAME; sets STREAK_N
# to how many in a row it now has (a variable, since the line must change in this shell).
streak() {
    local prev consec=0
    IFS=$'\t' read -r _ prev _ consec _ <<< "${OBS_P[$1]:-}"
    if [ "${prev:-}" = "$2" ] && [[ ${consec:-} =~ ^[0-9]{1,9}$ ]]; then
        consec=$((10#$consec + 1))
    else
        consec=1
    fi
    [ "$consec" -le 999999 ] || consec=999999
    OBS_P[$1]="$PA_STAMP"$'\t'"$2"$'\t'-$'\t'"$consec"
    STREAK_N="$consec"
}

# pass_age OTHER META_STAMP: the age of the other instance's last completed pass, the newer of its
# heartbeat line in /run (emptied by a reboot) and its meta stamp (on disk), or -1 when neither can
# be read or both lie in the future.
pass_age() {
    local s a best=-1
    for s in "$(heartbeat_stamp "$1")" "$2"; do
        _pa_stamp_split "$s" || continue
        a="$(pa_age "$s")"
        [ "$a" -ge 0 ] || continue
        if [ "$best" -lt 0 ] || [ "$a" -lt "$best" ]; then best="$a"; fi
    done
    printf '%s' "$best"
}

# judge_other OTHER LIMIT META_STAMP: witness-stale on witness:OTHER, from this pass. OTHER is stale
# when its timer is not active and enabled, or its last pass is older than LIMIT seconds; a pass
# that has never completed counts from when its timer started in this boot, which is what keeps a
# host upgraded to a release with a new timer quiet until that timer's first run has had its time.
# Not judged in the first 1800 s of uptime (the hourly timer's first run after a boot can come 13
# minutes after the light pass's first), or when the timer's state or the pass's age cannot be
# read: unknown never opens or resolves anything, and drops a first sighting, since the next
# stale check is not the second in a row. Opened on two checks in a row, resolved fresh2 on two
# fresh checks in a row.
judge_other() {
    local other="$1" limit="$2" timer="propolis-witness@$1.timer" key="witness:$1" age verdict n aem
    local name="witness-$1"
    verdict=unknown
    if [ "$PA_UP" -ge 1800 ] && [ -n "${S_LOAD[$timer]:-}" ] && [ "${S_LOAD[$timer]}" != "?" ]; then
        if [ "${S_ACT[$timer]:-}" != active ] || [ "${S_FILE[$timer]:-}" != enabled ]; then
            verdict=stale
        else
            age="$(pass_age "$other" "$3")"
            if [ "$age" -lt 0 ] && [[ ${S_AEM[$timer]:-} =~ ^[0-9]{1,18}$ ]] && [ "${S_AEM[$timer]}" != 0 ]; then
                aem=$((10#${S_AEM[$timer]} / 1000000))
                [ "$aem" -gt "$((10#$PA_UP))" ] || age=$((10#$PA_UP - aem))
            fi
            if [ "$age" -ge 0 ]; then
                if [ "$age" -gt "$limit" ]; then verdict=stale; else verdict=fresh; fi
            fi
        fi
    fi
    pa_incident_get "$key" || PA_INC=()
    case "$verdict:${PA_INC[7]:-none}" in
        stale:none | stale:resolved)
            PA_REC_KIND=witness-stale PA_REC_TIER=ACT PA_REC_STAGE=witness PA_REC_CAUSE=witness.stale
            PA_REC_INST=- PA_REC_NR=- PA_REC_OUT=- PA_REC_FLAG=""
            pa_incident_transition "$key" pending && rec_set
            unset 'OBS_P[$name]'
            ;;
        stale:pending)
            PA_REC_KIND=witness-stale PA_REC_TIER=ACT PA_REC_STAGE=witness PA_REC_CAUSE=witness.stale
            PA_REC_INST=- PA_REC_NR=- PA_REC_OUT=- PA_REC_FLAG=""
            pa_incident_transition "$key" open && rec_set
            unset 'OBS_P[$name]'
            ;;
        stale:*) unset 'OBS_P[$name]' ;;
        fresh:pending)
            pa_incident_transition "$key" drop && rec_set
            unset 'OBS_P[$name]'
            ;;
        fresh:open | fresh:acked)
            streak "$name" ok
            n="$STREAK_N"
            if [ "$n" -ge 2 ]; then
                PA_REC_PROOF=fresh2
                pa_incident_transition "$key" resolve && rec_set
                unset 'OBS_P[$name]'
            fi
            ;;
        unknown:pending)
            # Two checks in a row means two that could judge: a stale check after one that could
            # not is a first sighting again.
            pa_incident_transition "$key" drop && rec_set
            unset 'OBS_P[$name]'
            ;;
        *) unset 'OBS_P[$name]' ;;
    esac
    return 0
}

# ---- the hourly pass's judgement ------------------------------------------------------------

# finding_attrs ID KEY: the record attributes of a finding, from the table alone.
finding_attrs() {
    local inst="${CC_INST[$2]:-}" kind name
    PA_REC_KIND=finding PA_REC_TIER="${T_TIER[$1]}" PA_REC_STAGE="${T_STAGE[$1]}"
    PA_REC_CAUSE=config.finding PA_REC_NR=- PA_REC_OUT=- PA_REC_FLAG="" PA_REC_INST=-
    if [ -n "$inst" ]; then
        kind="${inst%%$'\t'*}" name="${inst#*$'\t'}"
        PA_REC_INST="${FIDS[$kind/$name]:--}"
    fi
}

# cc_unknown_for ID: the run says nothing of ID's absence: its group could not be checked (a G row
# or a listener cell reading unknown, or an L line naming the group or none known), or a line out
# of form could have been one of ID's findings (a bad hash of ID, or a bad id).
cc_unknown_for() {
    [ "$CC_LIMIT_ALL" = 0 ] && [ "$CC_BAD_ALL" = 0 ] && [ -z "${CC_BAD_ID[$1]:-}" ] || return 0
    [ -n "${T_GROUP[$1]:-}" ] && [ -n "${CC_LIMITED[${T_GROUP[$1]}]:-}" ]
}

# judge_findings: the transitions of every finding record against a completed run. Present on
# this run: none becomes pending, pending opens, an open one counts nothing more but rises to the
# table's tier when it was recorded lower. Daily for this run (another kind pages the fault now):
# the same at NOTICE, a first sighting's tier lowered with it (it has pushed nothing), an open
# record's tier left as it is (a tier never falls while open). Absent from a run that could check
# it: pending is dropped, an open one resolves clean2 on the second such run in a row. A finding
# held on this run is present and changes nothing else; one the run says nothing of is unknown:
# an open one changes nothing and its clean count starts again, a pending one is dropped, since
# its next sighting would not be on the next run.
judge_findings() {
    local key id line state n parent daily
    local -a keys=()
    for key in "${!CC_PRESENT[@]}"; do
        past_deadline && return 1
        # Seen, held or not, is not absent: the run of clean checks starts again.
        unset 'OBS_P[clean:$key]'
        [ -z "${CC_HELD[$key]:-}" ] || continue
        id="${CC_PRESENT[$key]}"
        daily="${CC_DAILY[$key]:-}"
        if [ -n "${CC_DOWN_UNIT[$key]:-}" ]; then
            case "${DOWN_STATE[${CC_DOWN_UNIT[$key]}]:-}" in
                inactive) ;;
                failed) daily=1 ;;
                *)
                    CC_HELD[$key]=1
                    continue
                    ;;
            esac
        fi
        state=none
        if pa_incident_get "$key"; then state="${PA_INC[7]}"; fi
        finding_attrs "$id" "$key"
        if [ -n "$daily" ]; then
            PA_REC_TIER=NOTICE
            case "$state" in
                none | resolved) pa_incident_transition "$key" pending && rec_set ;;
                pending)
                    PA_INC[6]=NOTICE
                    rec_set
                    pa_incident_transition "$key" open && rec_set
                    ;;
            esac
        else
            case "$state" in
                none | resolved) pa_incident_transition "$key" pending && rec_set ;;
                pending) pa_incident_transition "$key" open && rec_set ;;
                open | acked)
                    if [ "$(_pa_tier_rank "$PA_REC_TIER")" -gt "$(_pa_tier_rank "${PA_INC[6]}")" ]; then
                        pa_incident_transition "$key" change && rec_set
                    fi
                    ;;
            esac
        fi
        if [ "$key" = finding:spool-unlisted:all ] && pa_incident_get "$key"; then
            n="$CC_FOLD_N"
            [ "$n" -lt "$WITNESS_SPOOL_REPORTED" ] || n="$WITNESS_SPOOL_REPORTED+"
            if [ "${PA_INC[34]}" != "$n" ]; then
                PA_INC[34]="$n"
                rec_set
            fi
        fi
    done
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        [[ $key == finding:* ]] && [ -z "${CC_PRESENT[$key]:-}" ] && keys+=("$key")
    done
    for key in "${keys[@]}"; do
        past_deadline && return 1
        id="${key#finding:}"
        id="${id%%:*}"
        pa_incident_get "$key" || continue
        state="${PA_INC[7]}"
        if cc_unknown_for "$id"; then
            unset 'OBS_P[clean:$key]'
            [ "$state" != pending ] || { pa_incident_transition "$key" drop && rec_set; }
            continue
        fi
        case "$state" in
            pending) pa_incident_transition "$key" drop && rec_set ;;
            open | acked)
                streak "clean:$key" ok
                n="$STREAK_N"
                if [ "$n" -ge 2 ]; then
                    PA_REC_PROOF=clean2
                    pa_incident_transition "$key" resolve && rec_set
                    unset 'OBS_P[clean:$key]'
                fi
                ;;
        esac
    done
    # A backup that is too old because the nightly run keeps failing is the failed run's to
    # report, which the hook already does: the finding folds under that open record.
    for key in "${!CC_PRESENT[@]}"; do
        [ "${CC_PRESENT[$key]}" = backup-stale ] || continue
        [ "$BACKUP_FAILED_LAST" = 1 ] || continue
        pa_incident_get unit:propolis-backup.service || continue
        case "${PA_INC[7]}" in open | acked) parent="${PA_INC[1]}" ;; *) continue ;; esac
        pa_incident_get "$key" || continue
        [ "${PA_INC[13]}" = - ] || continue
        if pa_incident_fold "$key" "$parent"; then rec_set; fi
    done
    # A clean count whose record is no longer open counts nothing.
    for key in "${!OBS_P[@]}"; do
        [[ $key == clean:* ]] || continue
        if pa_incident_get "${key#clean:}"; then
            case "${PA_INC[7]}" in open | acked) continue ;; esac
        fi
        unset 'OBS_P[$key]'
    done
    return 0
}

# judge_cc_run: a config-check that did not complete raises cc_fail; on the second hourly pass in
# a row it opens cc-stopped, an ACT on the witness rail, because every finding it would have
# reported is unseen while it cannot run. Two completed runs in a row resolve it.
judge_cc_run() {
    local n
    if [ "$CC_DONE" = 1 ]; then
        CC_FAIL=0
        streak config-check ok
        n="$STREAK_N"
        if [ "$n" -ge 2 ] && pa_incident_get tool:config-check; then
            case "${PA_INC[7]}" in
                open | acked)
                    PA_REC_PROOF=clean2
                    pa_incident_transition tool:config-check resolve && rec_set
                    ;;
            esac
        fi
        return 0
    fi
    CC_FAIL=$(($(_pa_num "$CC_FAIL") + 1))
    streak config-check error
    [ "$CC_FAIL" -ge 2 ] || return 0
    if ! pa_incident_get tool:config-check || [ "${PA_INC[7]}" = resolved ]; then
        PA_REC_KIND=cc-stopped PA_REC_TIER=ACT PA_REC_STAGE=witness PA_REC_CAUSE=cc.stopped
        PA_REC_INST=- PA_REC_NR=- PA_REC_OUT=- PA_REC_FLAG=""
        pa_incident_transition tool:config-check open && rec_set
    fi
}

declare -A FIDS=() DOWN_STATE=()
BACKUP_FAILED_LAST=0 CC_FAIL=0 STREAK_N=0

# hourly_ids: opaque ids for the instances a finding can name: every unit the light pass samples
# and every log label of PROPOLIS_SENSOR_LOGS.
hourly_ids() {
    local input="" u i id kind name
    for u in "${WITNESS_UNITS[@]}"; do input+="unit"$'\t'"$u"$'\n'; done
    for i in "${!PA_LOG_LABEL[@]}"; do
        pa_plain_id "${PA_LOG_LABEL[$i]}" && input+="source"$'\t'"${PA_LOG_LABEL[$i]}"$'\n'
    done
    while IFS=$'\t' read -r id kind name; do
        [ -n "$name" ] && FIDS[$kind/$name]="$id"
    done < <(printf '%s' "$input" | pa_id_table 2> /dev/null)
}

# hourly_sample: one `systemctl show` for the light pass's timer and the units of unit-down
# findings, without the lock.
hourly_sample() {
    local out u key
    local -a units=(propolis-witness@light.timer)
    for key in "${!CC_DOWN_UNIT[@]}"; do
        u="${CC_DOWN_UNIT[$key]}"
        pa_unit_name_ok "$u" && [ -z "${WANT[$u]:-}" ] || continue
        units+=("$u")
    done
    for u in "${units[@]}"; do WANT[$u]=1; done
    out="$(systemctl show -p Id,LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestampMonotonic -- "${units[@]}" 2> /dev/null)" || return 0
    parse_show "$out"
    for key in "${!CC_DOWN_UNIT[@]}"; do
        u="${CC_DOWN_UNIT[$key]}"
        DOWN_STATE[$u]="${S_ACT[$u]:-}"
    done
}

# backup_failed_last: the backup's last-failure is newer than its last-success (both written by
# root, deploy/backup.sh); an mtime that cannot be read says no.
backup_failed_last() {
    local d="$ROOT/var/lib/propolis/backup-status" f s
    BACKUP_FAILED_LAST=0
    [ -f "$d/last-failure" ] && [ ! -L "$d/last-failure" ] || return 0
    f="$(timeout 5 stat -c %Y -- "$d/last-failure" 2> /dev/null)" || return 0
    [[ $f =~ ^[0-9]{1,12}$ ]] || return 0
    if [ -f "$d/last-success" ] && [ ! -L "$d/last-success" ]; then
        s="$(timeout 5 stat -c %Y -- "$d/last-success" 2> /dev/null)" || return 0
        [[ $s =~ ^[0-9]{1,12}$ ]] || return 0
        [ "$((10#$f))" -gt "$((10#$s))" ] || return 0
    fi
    BACKUP_FAILED_LAST=1
}

# ---- one pass -------------------------------------------------------------------------------

META_CC_LAST="" META_MAINT_SEEN="" META_CC_FAIL=""

# past_deadline: the pass has used the time it may judge for (WITNESS_DEADLINE).
past_deadline() {
    [ "$SECONDS" -ge "$WITNESS_DEADLINE" ]
}

# light_pass: the light pass. See the header for what it does and in what order.
light_pass() {
    local rc u n status=ok healed="" hourly="" t k v ok
    local -a meta=()
    pa_settings_load
    PA_ROLE="$(pa_role)"
    if pa_maint_active; then MAINT=1; fi
    collect_sample
    rc_collect 0

    rc=0
    pa_lock "$LOCK_WAIT" || rc=$?
    if [ "$rc" != 0 ]; then
        if [ "$rc" = 1 ] && command -v flock > /dev/null 2>&1; then
            n="$(lockwait_get)"
            lockwait_set "$((n + 1))"
            note "state lock busy for $LOCK_WAIT s; pass skipped"
        else
            note "state lock cannot be taken (no lock file can be opened, or flock is missing); pass skipped"
            # Nothing this host writes can be kept while no lock can be had: the banner says so.
            WHERE=none PA_WHERE=none
        fi
        # The heartbeat is not a locked state file; pa_write keeps its rewrite whole.
        write_heartbeat partial
        pa_banner_write || note "banner not written: /run/motd.d is missing or refused the write"
        return 0
    fi
    [ "$(lockwait_get)" = 0 ] || lockwait_set 0

    pa_salt_ensure || true
    pa_clock_check || true
    where_merge
    while IFS=$'\t' read -r t k v _; do
        [ "$t" = M ] || continue
        case "$k" in
            cc_last) META_CC_LAST="$v" ;;
            cc_fail) META_CC_FAIL="$v" ;;
            hourly_last) hourly="$v" ;;
            healed) healed="$v" ;;
            maint_seen) META_MAINT_SEEN="$v" ;;
        esac
    done < <(pa_state_read meta)
    pa_incident_load
    load_observe
    sweep_stale
    load_ids
    ingest_spool
    rc_store

    if [ "$SAMPLE_OK" = 1 ]; then
        check_counts units ok -
        for u in "${SAMPLED[@]}"; do
            if past_deadline; then
                status=partial
                break
            fi
            judge_unit "$u"
        done
    else
        status=partial
        check_counts units unknown "$SAMPLE_CAUSE"
        judge_records_without_sample
    fi
    if past_deadline; then
        status=partial
    else
        [ "$SAMPLE_OK" = 0 ] || judge_other hourly 10800 "$hourly"
        remind_all
    fi
    if ! past_deadline; then
        n="${#_PA_INC_I[@]}/${#_PA_INC_REST[@]}"
        pa_incident_prune
        [ "$n" = "${#_PA_INC_I[@]}/${#_PA_INC_REST[@]}" ] || CHANGED=1
    fi

    if [ "$CHANGED" = 1 ]; then
        ok=0
        pa_incident_write && ok=1
        spool_finish "$ok"
        where_merge
    fi
    observe_body | pa_state_write observe
    where_merge
    # The restarts that healed are counted, never opened: the total and the latest.
    meta=(light_last "$PA_STAMP" where "${WHERE:-none}")
    if [ "$HEALED" -gt 0 ]; then
        n="$(_pa_num "${healed%%/*}")"
        meta+=(healed "$((n + HEALED))/$PA_STAMP")
    fi
    # When a maintenance marker was last seen, for the ten minutes it still holds (maint_recent).
    [ "$MAINT" = 0 ] || meta+=(maint_seen "$PA_STAMP")
    _pa_meta_set "${meta[@]}"
    where_merge
    [ "$WHERE" != none ] || status=partial
    write_heartbeat "$status"
    pa_unlock
    [ "$WHERE" != none ] || note "state not persisted: neither /var/lib/propolis/witness nor /run/propolis-witness took a write"

    PA_WHERE="$WHERE"
    pa_banner_write || note "banner not written: /run/motd.d is missing or refused the write"
    return 0
}

# hourly_pass: the hourly pass. See the header for what it does and in what order. Everything
# slow (config-check, the read check, systemd) happens before the lock; under it the state files
# are read afresh and only the hourly pass's own records, observe lines and meta keys change, so
# what the light pass or the hook wrote while this pass computed is kept.
hourly_pass() {
    local rc n status=ok t k v light="" judged=0
    pa_settings_load
    PA_ROLE="$(pa_role)"
    load_table
    for k in "${WITNESS_UNITS[@]}"; do
        case "$k" in sensor-*.service) PA_FI_UNITS+=("${k%.service}") ;; esac
    done
    pa_env_get PROPOLIS_SENSOR_LOGS "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    pa_sensor_logs "$PA_ENV_VALUE"
    cc_run
    [ "$CC_DONE" = 1 ] || status=partial
    if past_deadline; then
        status=partial
    else
        [ "$CC_DONE" = 0 ] || cc_findings
        rc_collect 1
        hourly_sample
        backup_failed_last
    fi
    past_deadline && status=partial

    rc=0
    pa_lock "$LOCK_WAIT" || rc=$?
    if [ "$rc" != 0 ]; then
        if [ "$rc" = 1 ] && command -v flock > /dev/null 2>&1; then
            n="$(lockwait_get)"
            lockwait_set "$((n + 1))"
            note "state lock busy for $LOCK_WAIT s; hourly pass skipped"
        else
            note "state lock cannot be taken (no lock file can be opened, or flock is missing); hourly pass skipped"
            WHERE=none PA_WHERE=none
        fi
        write_heartbeat partial
        return 0
    fi
    [ "$(lockwait_get)" = 0 ] || lockwait_set 0

    pa_salt_ensure || true
    pa_clock_check || true
    where_merge
    while IFS=$'\t' read -r t k v _; do
        [ "$t" = M ] || continue
        case "$k" in
            light_last) light="$v" ;;
            cc_fail) CC_FAIL="$v" ;;
        esac
    done < <(pa_state_read meta)
    pa_incident_load
    load_observe
    hourly_ids
    if ! past_deadline; then
        judged=1
        judge_cc_run
        if [ "$CC_DONE" = 1 ]; then
            judge_findings || status=partial
        fi
        if ! past_deadline; then
            rc_store
            rc_result
            [ "$RCR_RESULT" = ok ] || status=partial
            check_counts readcheck "$RCR_RESULT" "$RCR_CAUSE"
            judge_other light 1200 "$light"
        fi
    fi
    past_deadline && status=partial
    if [ "$CHANGED" = 1 ]; then
        pa_incident_write
        where_merge
    fi
    pa_state_write observe < <(observe_body)
    where_merge
    local -a meta=(hourly_last "$PA_STAMP" where "${WHERE:-none}")
    [ "$judged" = 0 ] || meta+=(cc_last "$PA_STAMP/$CC_RC/$CC_SECS" cc_fail "$(_pa_num "$CC_FAIL")")
    # How many lines the last completed run printed out of form, for the walk.
    [ "$judged" = 0 ] || [ "$CC_DONE" = 0 ] || meta+=(cc_skipped "$CC_BAD")
    _pa_meta_set "${meta[@]}"
    where_merge
    [ "$WHERE" != none ] || status=partial
    write_heartbeat "$status"
    pa_unlock
    [ "$CC_DONE" = 1 ] || note "config-check did not complete: ${CC_WHY:-exit $CC_RC}"
    [ "$CC_BAD" = 0 ] || note "config-check printed $CC_BAD finding lines that are not in its form; skipped, and no finding they could be is taken as gone"
    [ "$WHERE" != none ] || note "state not persisted: neither /var/lib/propolis/witness nor /run/propolis-witness took a write"
    return 0
}

if [ "$INSTANCE" = hourly ]; then
    hourly_pass
else
    light_pass
fi
exit 0
