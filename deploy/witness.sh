#!/usr/bin/env bash
#
# The root witness: the part of the shell alerting code that runs on its own, on a timer.
# Installed as /usr/local/sbin/propolis-witness by deploy/install.sh and deploy/upgrade.sh;
# propolis-witness@light.service runs `propolis-witness light` every five minutes from
# propolis-witness@light.timer.
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
# one to the record's would_push, which the status walk shows; that is all. It runs no curl, no
# config-check and no database probe.
#
# SAFE TO RUN FOREVER. An ordinary check error is recorded and the pass still exits 0, so it is
# never a failed unit for the failure hook to report; three in a row open the NOTICE
# tool-unusable. Every program it runs has a time limit, the pass stops its optional reads after
# 200 s and its judgement after 240 s (marking itself partial), well inside the unit's 15
# minutes, and nothing slow runs while it holds the state lock. When the lock is not free within
# 60 s it writes no state, logs one line, counts the miss in /run/propolis-witness/lockwait
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
# line, and every value systemctl prints is checked against its form before it is used.
#
# Exit status: 0 after every pass that ran, whatever it found; 2 a bad argument; 3 the alert
# library is missing, not trusted, fails to load or is older than this script needs. Only those
# reach the failure hook, which records a witness unit's failure and never pages for it.
#
# Test seams (honoured only with PROPOLIS_ALERT_ROOT set; tests only): PROPOLIS_ALERT_ROOT puts
# every path under that directory and keeps the caller's PATH, so stubs win;
# PROPOLIS_WITNESS_NOW is the time as a WALL/BOOT/UP stamp; PROPOLIS_WITNESS_LOCK_WAIT replaces
# the 60 s wait for the state lock; PROPOLIS_WITNESS_DEADLINE replaces the 240 s after which the
# pass judges nothing more.
#
# The library version this script needs; deploy/rollback.sh reads the line below.
# needs-alert-lib: 4

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

if [ "$#" -ne 1 ] || [ "$1" != light ]; then
    echo "usage: propolis-witness light   (the light pass; this release has no other)" >&2
    exit 2
fi

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
pa_unit_name_ok"
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

# collect_sample: one `systemctl show` for every unit in scope, the units named by a record or a
# spool file among them (and the timer of each such oneshot), so a record is judged whatever
# unit it names. A word that is not a unit name is left out: systemd would answer for a unit of
# its own naming, or refuse the whole question and leave the pass with no sample. Sets SAMPLE_OK,
# or SAMPLE_CAUSE when systemd could not be asked. A failed
# rotation run's journal is read here too, before the pass takes the lock, as the hook reads it.
collect_sample() {
    local out rc line k t key u name dir timer
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
    done <<< "$out"
    commit_block
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

declare -A OBS_U=() OBS_R=() OBS_P=() NEW_U=() NEW_R=() JUDGED=()
OBS_KEEP=()
OBS_MINE_P=" units "

load_observe() {
    local line t name rest
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=$'\t' read -r t name rest <<< "$line"
        case "$t" in
            U) pa_unit_name_ok "$name" && OBS_U[$name]="${rest:-}" ;;
            R) pa_unit_name_ok "$name" && OBS_R[$name]="${rest:-}" ;;
            P)
                case "$OBS_MINE_P" in
                    *" $name "*) OBS_P[$name]="${rest:-}" ;;
                    *) OBS_KEEP+=("$line") ;;
                esac
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
        [ "$t" = light ] && [[ $c =~ ^[0-9]{1,9}$ ]] && n=$((10#$c))
    done < <(timeout 5 head -c 4096 -- "$f" 2> /dev/null)
    printf '%s' "$n"
}

# lockwait_set N: this instance's line of the lockwait file, written without the lock (which is
# what it reports on), other instances' lines kept; 0 removes the line, and the file once empty.
lockwait_set() {
    local f="$PA_RUN/lockwait" t c body=""
    if [ -f "$f" ] && [ ! -L "$f" ]; then
        while read -r t c _; do
            [[ $t =~ ^[a-z]{1,16}$ && $c =~ ^[0-9]{1,9}$ ]] && [ "$t" != light ] || continue
            body+="$t"$'\t'"$c"$'\n'
        done < <(timeout 5 head -c 4096 -- "$f" 2> /dev/null)
    elif [ "$1" = 0 ]; then
        return 0
    fi
    [ "$1" = 0 ] || body+="light"$'\t'"$1"$'\n'
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
                if [ "$inst" = light ]; then
                    case "${w:-}" in persistent | run | none) was="$w" ;; esac
                    continue
                fi
                if ! pa_ok_field "${s:-}" || ! pa_ok_field "${w:-}" || ! pa_ok_field "${r:-}"; then continue; fi
                body+="B"$'\t'"$inst"$'\t'"$s"$'\t'"$w"$'\t'"$r"$'\n'
            done
        } < <(timeout 5 head -c 65536 -- "$f" 2> /dev/null)
        [[ $head =~ ^#heartbeat\ v1\ g=([0-9]{1,18})$ ]] && g=$((10#${BASH_REMATCH[1]}))
    fi
    body+="B"$'\t'"light"$'\t'"$PA_STAMP"$'\t'"${WHERE:-${was:-none}}"$'\t'"$1"$'\n'
    pa_write "$f" < <(printf '#heartbeat v1 g=%s\n%s' "$((g + 1))" "$body") || true
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
# cc_last, written by the hourly pass).
cc_result_recent() {
    local v="${META_CC_LAST%%/*}"
    [ -n "$v" ] || return 1
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

# ---- one pass -------------------------------------------------------------------------------

META_CC_LAST="" META_MAINT_SEEN=""

# past_deadline: the pass has used the time it may judge for (WITNESS_DEADLINE).
past_deadline() {
    [ "$SECONDS" -ge "$WITNESS_DEADLINE" ]
}

# light_pass: the light pass. See the header for what it does and in what order.
light_pass() {
    local rc u n status=ok healed="" t k v ok
    local -a meta=()
    pa_settings_load
    PA_ROLE="$(pa_role)"
    if pa_maint_active; then MAINT=1; fi
    collect_sample

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
            healed) healed="$v" ;;
            maint_seen) META_MAINT_SEEN="$v" ;;
        esac
    done < <(pa_state_read meta)
    pa_incident_load
    load_observe
    sweep_stale
    load_ids
    ingest_spool

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

light_pass
exit 0
