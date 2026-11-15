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
# THE LIGHT PASS'S PROBES, all read before the lock. First the database, as the daemon's own role
# through the daemon binary's pg-exec (read-only, `SELECT pg_is_in_recovery()`): one that does not
# answer on two passes opens db-unreachable, one that is a standby db-readonly. Then the daemon's
# readiness, one plain-HTTP GET of /ready on its console's loopback address, asked only of a
# listener the daemon itself holds: a daemon up for half an hour that does not answer is
# daemon-down, one that answers 503 while the database answers root is daemon-degraded, and
# daemon-down now resolves only on two ready answers five minutes apart (ten steady minutes where
# the console is not on loopback and cannot be asked). While the database is down and the daemon's
# last completed run logged that it could not connect, the daemon's own failure stays pending and
# folds under db-unreachable, so the outage is recorded once, under its cause; folded, it waits
# for that record to resolve. Then the journal lines nobody reads: the legacy hook's lines for an
# alert it could not deliver, and a failed failure hook, open alert-path, which resolves only on an
# alert delivered after it opened; journald's notice that it dropped a Propolis unit's lines opens
# journal-dropped; the rotation guard's lines are counted. A class's cursor moves on only once what
# it read was judged and kept. Last, after the pass, the optional heartbeat URL
# (PROPOLIS_WITNESS_HEARTBEAT_URL): one GET to an external dead-man check, made only after a pass
# that was complete and clean and 30 minutes after the last one that was not; skipping it is the
# signal.
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
# requests are the read check's GETs and the heartbeat URL's GET, which carry no message, the GET
# of the daemon's /ready on loopback, and the read-only database probe.
#
# SAFE TO RUN FOREVER. An ordinary check error is recorded and the pass still exits 0, so it is
# never a failed unit for the failure hook to report; three in a row open the NOTICE
# tool-unusable. Every program it runs has a time limit, the light pass starts no probe that
# could end past 160 s and stops its judgement after 240 s, the hourly pass its judgement after
# 720 s (marking
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
# by its status code and content type alone; so does the heartbeat URL, which is never written to
# a state file, a journal line or the banner. A journal line is matched only after the fields
# journald sets itself (the unit, the uid, the invocation id) have narrowed it to its writer, and
# then against fixed strings; no line, nor any part of one, is kept or shown, only counted. The
# daemon's /ready answer is taken only from a listener the kernel says the daemon holds, and is
# judged by its status code and one fixed token; the database URL stays in the one process that
# needs it.
#
# Exit status: 0 after every pass that ran, whatever it found; 2 a bad argument; 3 the alert
# library is missing, not trusted, fails to load or is older than this script needs. Only those
# reach the failure hook, which records a witness unit's failure and never pages for it.
#
# Test seams (honoured only with PROPOLIS_ALERT_ROOT set; tests only): PROPOLIS_ALERT_ROOT puts
# every path under that directory (the installed config-check among them) and keeps the caller's
# PATH, so stubs win; PROPOLIS_WITNESS_NOW is the time as a WALL/BOOT/UP stamp;
# PROPOLIS_WITNESS_LOCK_WAIT replaces the wait for the state lock; PROPOLIS_WITNESS_DEADLINE
# replaces the 240 s (light) or 720 s (hourly) after which the pass judges nothing more;
# PROPOLIS_WITNESS_SOFT_DEADLINE replaces the 160 s by which every optional probe must end.
#
# The library version this script needs; deploy/rollback.sh reads the line below.
# needs-alert-lib: 6

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
    unset PROPOLIS_WITNESS_NOW PROPOLIS_WITNESS_LOCK_WAIT PROPOLIS_WITNESS_DEADLINE PROPOLIS_WITNESS_SOFT_DEADLINE
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
pa_readcheck_merge pa_pg pa_heartbeat_get pa_journal_patterns pa_jcursor_ok"
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
#
# Before the lock a light pass may call, each under its own limit: systemd for the role, two
# questions at 20 s, 40 s; the spool listing, two finds at 10 s, 20 s; the unit sample, 20 s; the
# rotation guard's journal, 3 s; the database probe, 5 s to stat the daemon binary, 30 s to find
# its pg-exec guard when that is not known from an earlier pass and psql's 20 s with 2 s to be
# killed, 57 s; the daemon's last run in the journal, 5 s for the account and 30 s, 35 s; /ready,
# 5 s to ask who holds its port, 5 s for the account, 8 s for the GET and 5 s for its body, 23 s;
# three journal classes at 30 s, 90 s, and 5 s each for the cursor and the kept lines, 15 s; the
# failed alert units, two questions at 20 s, 40 s; the undelivered list and the delivered stamps,
# 5 s each, 10 s; a changed target's read check, two targets of four GETs at 15 s, 120 s. 503 s in
# all, more than the deadline, so only the role, the spool listing, the sample and the guard's
# journal (83 s) always run: every other probe starts only when its whole limit still ends by
# WITNESS_SOFT_DEADLINE (below, 160 s), and one that cannot is unknown for the pass, which is then
# partial. The ownership checks' `stat` and `readlink` of the daemon binary's path have no limit
# of their own, as the state files' reads have none (see the hourly pass below). With the lock's
# 60 s that is 220 s, inside 240 s.
# After the pass come the banner and the heartbeat URL's GET, 15 s, and 10 s for the lock to note
# its result, far inside the unit's 15 minutes.
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

# No optional read (the rotation guard's journal, each probe of the light pass) starts unless it
# ends by this many seconds, so the lock's wait still ends inside WITNESS_DEADLINE.
WITNESS_SOFT_DEADLINE=160
if [ -n "$ROOT" ] && [[ ${PROPOLIS_WITNESS_SOFT_DEADLINE:-} =~ ^[0-9]{1,3}$ ]]; then
    WITNESS_SOFT_DEADLINE="$((10#$PROPOLIS_WITNESS_SOFT_DEADLINE))"
fi

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
declare -A S_INV=() S_RESTART=() S_PID=() WANT=() _B=()
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
        S_PID[$id]="$(sample_word "${_B[MainPID]:-}" '^[1-9][0-9]{0,9}$')"
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
                | InvocationID | Restart | MainPID) _B[$k]="${line#*=}" ;;
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
    if [ "${S_ACT[$u]:-}" = failed ] && [ -n "${S_INV[$u]:-}" ] && fits 3; then
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
#
# The light pass's probes add their own: per check (`pg`, `ready`, `alertunit` and
# `journal:<class>`) the results in a row; `db` the database's last answer (ok, recovery or
# down), `ready-code` the last /ready status, and `daemon` what the daemon was seen to be (ok,
# down, activating, starting, degraded, dbcarried), each with how many passes in a row; and one
# `seen:journal:<unit>` line per open journal-dropped record, the last pass that saw its line.

declare -A OBS_U=() OBS_R=() OBS_P=() NEW_U=() NEW_R=() JUDGED=()
OBS_KEEP=()
OBS_MINE_P=" units witness-hourly pg ready alertunit db ready-code daemon "
[ "$INSTANCE" != hourly ] || OBS_MINE_P=" config-check readcheck witness-light "

# obs_mine NAME: the P line NAME belongs to this instance.
obs_mine() {
    case "$OBS_MINE_P" in *" $1 "*) return 0 ;; esac
    if [ "$INSTANCE" = hourly ]; then
        [[ $1 == clean:* ]]
    else
        [[ $1 == journal:* || $1 == seen:* ]]
    fi
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
    for d in "$PA_STATE" "$PA_STATE/hook" "$PA_STATE/jcursor" "$PA_RUN" "$PA_RUN/fallback" "$PA_RUN/jcursor"; do
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
# kind decides: a oneshot's next run succeeded after the onset (nextrun); the daemon answered
# /ready 200 on two passes at least five minutes apart (READY_GAP), up with the same start since
# the first of them (ready2: running is not ready, and a daemon that crashes between two answers
# has not recovered), or, where its console's address is not loopback and /ready cannot be asked
# at all (config.invalid), up 10 min without a restart (active10, which is what the proof field
# then says); a crash loop or an unset bind has stayed up 30 min without a restart (quiet30); any
# other unit has stayed up 10 min without one (active10). Met on the first look after a reboot,
# it is `restart`.
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
    elif [ "$steady" != - ] && [ "$u" = propolis.service ] && [ "$READY_CAUSE" = config.invalid ]; then
        [ "$(pa_age "$steady")" -lt 600 ] || met=active10
    elif [ "$steady" != - ] && [ "$u" = propolis.service ]; then
        [ "$READY2" != 1 ] || [ "$(pa_age "$steady")" -lt "$READY_GAP" ] || met=ready2
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
    local nocc=0 ddown2=0 dcause=""
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
    # The daemon is down too when it is stopped, waits to be restarted, or has been starting for
    # over half an hour, on two passes, and when it has been up half an hour and its console does
    # not answer (daemon_observe).
    if [ "$u" = propolis.service ]; then
        case "$DOBS" in
            down) [ "$DOBS_N" -lt 2 ] || ddown2=1 ;;
            activating) [ "$DOBS_N" -lt 8 ] || ddown2=1 ;;
        esac
        dcause="$DCAUSE"
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
            if [ "${PA_INC[13]:--}" != - ]; then
                folded_pending "$u" "$key" "$prevup" "$hold"
                return 0
            fi
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
                if [ "$loop2" = 1 ] || [ "$failed2" = 1 ] || [ "$ddown2" = 1 ]; then judge=open; fi
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
                            unit_open "$u" "$key" "$k" "" "" "" "$F_NR"
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
            if [ "$u" = propolis.service ] && ready_unverified; then
                flag_cannotverify "$key"
                pa_incident_get "$key" || return 0
            fi
            if [ "$u" = propolis.service ] && [ "$TIE_HOLD" = 1 ]; then
                # Opened before its parent existed: it takes db-unreachable as its parent once
                # that is open (the late-parent rule), and the database's cause with it. A daemon
                # in a fresh attempt is active and still failing, so its state is no test here.
                if tie_fold "$key" && [ "${PA_INC[11]}" != db.unreachable ]; then
                    PA_REC_KIND="" PA_REC_TIER="" PA_REC_CAUSE=db.unreachable
                    pa_incident_transition "$key" change && rec_set
                fi
            elif [ "$u" = propolis.service ] && { [ "$F_ACTIVE" != active ] || [ "$DOBS" = down ]; } \
                && [ "${PA_INC[13]}" != - ] && parent_gone "${PA_INC[13]}" 1800; then
                # Still down, not merely not ready: a daemon that runs and answers 503 is
                # daemon-degraded's to report, and one whose answer cannot be read is unknown.
                unfold_open
            elif [ "$loop2" = 1 ] && [ "${PA_INC[3]}" = unit-failed ]; then
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
                unit_open "$u" "$key" "$O_KIND" "$O_TIER" "$O_STAGE" "$PA_CAUSE" "$F_NR"
            elif [ "$failed2" = 1 ]; then
                sample_cause "$u"
                open_attrs "$u" unit-failed
                [ -z "$C_KIND" ] || O_KIND="$C_KIND"
                [ -z "$C_TIER" ] || O_TIER="$C_TIER"
                unit_open "$u" "$key" "$O_KIND" "$O_TIER" "$O_STAGE" "$C_CAUSE" "$F_NR"
            elif [ "$ddown2" = 1 ]; then
                # Stopped, waiting to restart, starting for over half an hour, or up without an
                # answer from its console: the cause is systemd's, or the console's for the last.
                sample_cause "$u"
                [ -z "$dcause" ] || C_CAUSE="$dcause"
                open_attrs "$u" unit-failed
                unit_open "$u" "$key" "$O_KIND" "$O_TIER" "$O_STAGE" "$C_CAUSE" "$F_NR"
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
        # A light pass starts a target's four GETs only when all of them end by its soft deadline;
        # the next pass checks what this one could not.
        [ "$INSTANCE" != light ] || fits 60 || return 0
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

# ---- the light pass's probes ----------------------------------------------------------------
#
# Each reads before the lock, which is never held across a slow call, and each starts only when
# its whole time limit still ends by WITNESS_SOFT_DEADLINE: one that cannot is unknown for the
# pass. Under the lock only what they found is judged. A check's result (ok, or unknown with a
# cause) goes to its P line, where three unknowns in a row open tool-unusable on tool:<check>.

declare -A CHK_RESULT=() CHK_CAUSE=()
CHECK_BAD=()

# fits SECONDS: a call that may take this long still ends by the soft deadline.
fits() {
    [ "$((SECONDS + $1))" -le "$WITNESS_SOFT_DEADLINE" ]
}

# check_result NAME RESULT CAUSE: what one check came to on this pass, for probe_counts.
check_result() {
    CHK_RESULT[$1]="$2" CHK_CAUSE[$1]="$3"
}

# account_uid NAME: the uid of a local account, or failure when there is none.
account_uid() {
    local u
    u="$(timeout 5 id -u -- "$1" 2> /dev/null)" || return 1
    [[ $u =~ ^[0-9]{1,10}$ ]] || return 1
    printf '%s' "$((10#$u))"
}

DB_RESULT=skip DB_CAUSE=- DB_WHERE=local DB_GUARD=- DB_BIN_ID=""

# db_probe: whether the daemon's database answers, asked as the daemon's own role through the
# daemon binary's pg-exec (pa_pg: read-only, 5 s to connect, 5 s per statement). DB_RESULT is f
# (it answers and takes writes), t (a standby: the daemon's writes fail), down (db.unreachable,
# db.auth or db.timeout, in DB_CAUSE), unknown (the probe could not tell: tool.exec,
# config.invalid, an answer out of form, or no time left) or skip (no DATABASE_URL, or a host that
# runs no daemon). psql's own words are another party's: they are dropped here, never kept.
db_probe() {
    local known="" need=57
    DB_RESULT=skip
    case "${PA_ROLE:-}" in collector | gateway) return 0 ;; esac
    pa_env_get DATABASE_URL "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    if [ -z "$PA_ENV_VALUE" ] && [ -z "$PA_ENV_UNREADABLE" ]; then return 0; fi
    PA_ENV_VALUE=""
    # Whether this very binary carried pg-exec's guard on an earlier pass, so 50 MB are not read
    # every five minutes; meta is read here without the lock, and only as a hint pa_pg checks
    # against the binary's inode, size and mtime.
    [ "$(_pa_meta_get pgexec_ok)" != 1 ] || known="$(_pa_meta_get pgexec_id)"
    [ -z "$known" ] || need=27
    if ! fits "$need"; then
        DB_RESULT=unknown DB_CAUSE=unknown
        check_result pg unknown unknown
        return 0
    fi
    PA_PG_GUARD_KNOWN="$known" PA_PG_APP=propolis-witness
    if pa_pg 20 'SELECT pg_is_in_recovery()' > /dev/null; then
        case "$PA_PG_OUT" in
            f) DB_RESULT=f DB_CAUSE=- ;;
            t) DB_RESULT=t DB_CAUSE=db.recovery ;;
            *) DB_RESULT=unknown DB_CAUSE=unknown ;;
        esac
    else
        DB_CAUSE="$PA_PG_CAUSE"
        case "$DB_CAUSE" in
            db.unreachable | db.auth | db.timeout) DB_RESULT=down ;;
            *) DB_RESULT=unknown ;;
        esac
    fi
    DB_WHERE="${PA_PG_WHERE:-local}" DB_GUARD="$PA_PG_GUARD" DB_BIN_ID="$PA_PG_BIN_ID"
    PA_PG_ERR="" PA_PG_OUT="" PA_PG_GUARD_KNOWN=""
    pa_ok_field "$DB_CAUSE" || DB_CAUSE=unknown
    if [ "$DB_RESULT" = unknown ]; then
        check_result pg unknown "$DB_CAUSE"
    else
        check_result pg ok -
    fi
}

TIE=0 PROPOLIS_UID=""

# daemon_tie: while the probe fails with a database cause, whether the daemon's last completed run
# logged that it could not connect to PostgreSQL. Its journal is narrowed by the fields journald
# sets (the unit and the daemon account's uid), then matched as fixed strings: the newest of the
# connect line and the start line the daemon logs once it has connected decides, and only the
# connect line ties the daemon's failure to the database. A run that failed or waits to be
# restarted is its own last run, read by its invocation id. A run in progress is not: the daemon
# logs the connect line only when its pool's acquire timeout (30 s) ends, so a fresh attempt has
# logged nothing yet, and its last completed run is read from the last 15 minutes instead. Without
# the account, or the id of a run that ended, there is no tie, and a read cut short says nothing.
daemon_tie() {
    local u=propolis.service inv="${S_INV[propolis.service]:-}" uid out st
    local -a pats=() m=()
    TIE=0
    [ "$DB_RESULT" = down ] || return 0
    # The account's 5 s and the journal's 30 s, both inside the soft deadline.
    if ! fits 35; then
        check_result journal:daemon unknown unknown
        return 0
    fi
    uid="$(account_uid propolis)" || return 0
    PROPOLIS_UID="$uid"
    mapfile -t pats < <(pa_journal_patterns daemon)
    [ "${#pats[@]}" -ge 2 ] || return 0
    case "${S_ACT[$u]:-}:${S_SUB[$u]:-}" in
        failed:* | activating:auto-restart)
            [ -n "$inv" ] || return 0
            m=("_SYSTEMD_INVOCATION_ID=$inv")
            ;;
        *) m=(--since=-15min) ;;
    esac
    out="$(
        timeout 30 journalctl -q --no-pager -o cat "_SYSTEMD_UNIT=propolis.service" "_UID=$uid" \
            "${m[@]}" 2> /dev/null | LC_ALL=C grep -a -F -e "${pats[0]}" -e "${pats[1]}" \
            | LC_ALL=C tail -n 1 | LC_ALL=C cut -b 1-400
        exit "${PIPESTATUS[0]}"
    )"
    st=$?
    if [ "$st" != 0 ]; then
        case "$st" in
            126 | 127) check_result journal:daemon unknown tool.exec ;;
            *) check_result journal:daemon unknown unknown ;;
        esac
        return 0
    fi
    check_result journal:daemon ok -
    case "$out" in *"${pats[0]}"*) TIE=1 ;; esac
    return 0
}

READY_RESULT=skip READY_CAUSE=- READY_ADDR="" READY_OWNER="" READY_OWNER_CAUSE=""

# console_addr: the daemon's console address from PROPOLIS_CONSOLE_BIND (the daemon's two env
# files, its default 127.0.0.1:8080) as READY_ADDR, with 0.0.0.0 asked as 127.0.0.1 and [::] as
# [::1]. Fails for any address that is not a loopback one: /ready is asked of the daemon on this
# host and of nothing reachable from elsewhere.
console_addr() {
    local bind host port o
    pa_env_get PROPOLIS_CONSOLE_BIND "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    [ "$PA_ENV_COMPLEX" = 0 ] && [ -z "$PA_ENV_UNREADABLE" ] || return 1
    bind="${PA_ENV_VALUE:-127.0.0.1:8080}"
    case "$bind" in
        \[*\]:*) host="${bind%%]*}" host="${host#[}" port="${bind##*]:}" ;;
        *:*) host="${bind%:*}" port="${bind##*:}" ;;
        *) return 1 ;;
    esac
    [[ $port =~ ^[0-9]{1,5}$ ]] && [ "$((10#$port))" -ge 1 ] && [ "$((10#$port))" -le 65535 ] || return 1
    port=$((10#$port))
    case "$host" in
        :: | ::1)
            READY_ADDR="[::1]:$port"
            return 0
            ;;
        0.0.0.0) host=127.0.0.1 ;;
    esac
    [[ $host =~ ^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do [ "$((10#$o))" -le 255 ] || return 1; done
    READY_ADDR="127.$((10#${BASH_REMATCH[1]})).$((10#${BASH_REMATCH[2]})).$((10#${BASH_REMATCH[3]})):$port"
}

# ready_owner PORT: who holds the TCP listeners that take a connection to READY_ADDR on PORT, from
# the kernel's socket table (ss over netlink, with the holding process and the socket's uid).
# READY_OWNER is daemon when every such listener is held by propolis.service's sampled MainPID or
# created by the propolis account, none when there is none, other for any other holder, and
# unknown (READY_OWNER_CAUSE) when ss could not tell.
ready_owner() {
    local port="$1" out rc=0 line rest p q uid ok any=0 re_pid='pid=([0-9]{1,10})' re_uid=' uid:([0-9]{1,10})'
    local main="${S_PID[propolis.service]:-}" want="${READY_ADDR%:*}" bound
    READY_OWNER=unknown READY_OWNER_CAUSE=unknown
    out="$(timeout 5 ss -Hltnpe "sport = :$port" 2> /dev/null)" || rc=$?
    if [ "$rc" != 0 ]; then
        case "$rc" in 126 | 127) READY_OWNER_CAUSE=tool.exec ;; esac
        return 0
    fi
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # Only a listener that can take a connection to the address asked counts: one bound to
        # that address, or to a wildcard of its family (`*` is both families). Another service
        # on the same port number at another address, a sensor on the public address say, holds
        # nothing of the console's.
        read -r _ _ _ bound _ <<< "$line"
        bound="${bound%:*}"
        bound="${bound%%%*}"
        case "$bound" in
            "$want" | '*') ;;
            0.0.0.0) [[ $want != \[* ]] || continue ;;
            '[::]') [[ $want == \[* ]] || continue ;;
            *) continue ;;
        esac
        any=1 ok=0 rest="$line" p=""
        while [[ $rest =~ $re_pid ]]; do
            p+=" $((10#${BASH_REMATCH[1]}))"
            rest="${rest#*"${BASH_REMATCH[0]}"}"
        done
        if [ -n "$p" ] && [ -n "$main" ]; then
            ok=1
            for q in $p; do [ "$q" = "$main" ] || ok=0; done
        fi
        if [ "$ok" = 0 ] && [[ $line =~ $re_uid ]]; then
            uid="$((10#${BASH_REMATCH[1]}))"
            # `-` once the account is known to be missing, so it is asked once a pass.
            [ -n "$PROPOLIS_UID" ] || PROPOLIS_UID="$(account_uid propolis)" || PROPOLIS_UID=-
            [ "$uid" != "$PROPOLIS_UID" ] || ok=1
        fi
        if [ "$ok" = 0 ]; then
            READY_OWNER=other
            return 0
        fi
    done <<< "$out"
    if [ "$any" = 0 ]; then READY_OWNER=none; else READY_OWNER=daemon; fi
}

# ready_probe: the daemon's readiness, one GET of /ready on its console's loopback address, over
# plain HTTP as the daemon serves it, with no credentials, no proxy, no redirect, a 64 KiB cap and
# time limits; asked only while propolis.service is enabled and up, and only of a listener the
# daemon holds (ready_owner). A daemon whose console failed to bind keeps running, and no sensor's
# sandbox keeps it from binding a loopback port, so while the daemon restarts, or after its bind
# failed, another local account could hold the port and answer for it. The body is the daemon's:
# only its status code is judged, and whether the one fixed token `"gave_up"` occurs.
# READY_RESULT: 200, 503 (the daemon's pool cannot reach its database), 503g (a subsystem gave
# up), 000 (no answer, or nothing listening; net.connect or net.timeout in READY_CAUSE), unknown
# (an address that is not loopback, config.invalid; a listener another holds or one ss cannot
# name; a status the daemon does not give; curl missing; no time left), notup or skip (not asked).
ready_probe() {
    local u=propolis.service body code rc n
    READY_RESULT=skip READY_CAUSE=-
    case "${PA_ROLE:-}" in collector | gateway) return 0 ;; esac
    [ "$SAMPLE_OK" = 1 ] && [ "${S_FILE[$u]:-}" = enabled ] || return 0
    case "${S_ACT[$u]:-}" in
        active | reloading) ;;
        *)
            READY_RESULT=notup
            return 0
            ;;
    esac
    if ! console_addr; then
        READY_RESULT=unknown READY_CAUSE=config.invalid
        check_result ready unknown config.invalid
        return 0
    fi
    body="$(umask 077 && mktemp 2> /dev/null)" || body=""
    if [ -z "$body" ] || ! fits 23; then
        READY_RESULT=unknown READY_CAUSE=unknown
        [ -n "$body" ] || READY_CAUSE=tool.exec
        check_result ready unknown "$READY_CAUSE"
        return 0
    fi
    PA_CLEANUP+=("$body")
    ready_owner "${READY_ADDR##*:}"
    case "$READY_OWNER" in
        daemon) ;;
        none)
            rm -f -- "$body" 2> /dev/null
            READY_RESULT=000 READY_CAUSE=net.connect
            check_result ready ok -
            return 0
            ;;
        *)
            rm -f -- "$body" 2> /dev/null
            READY_RESULT=unknown READY_CAUSE="$READY_OWNER_CAUSE"
            check_result ready unknown "$READY_CAUSE"
            return 0
            ;;
    esac
    code="$(timeout 8 curl -q -sS --noproxy '*' -o "$body" -w '%{http_code}' --max-time 5 \
        --max-filesize 65536 --max-redirs 0 --proto '=http' "http://$READY_ADDR/ready" 2> /dev/null)"
    rc=$?
    code="${code:0:3}"
    [[ $code =~ ^[0-9]{3}$ ]] || code=000
    case "$code" in
        200) READY_RESULT=200 ;;
        503)
            n="$(timeout 5 head -c 65536 -- "$body" 2> /dev/null | LC_ALL=C grep -c -a -F '"gave_up"')" || true
            if [[ $n =~ ^[0-9]{1,9}$ ]] && [ "$((10#$n))" -gt 0 ]; then READY_RESULT=503g; else READY_RESULT=503; fi
            ;;
        000)
            case "$rc" in
                126 | 127) READY_RESULT=unknown READY_CAUSE=tool.exec ;;
                28 | 124) READY_RESULT=000 READY_CAUSE=net.timeout ;;
                *) READY_RESULT=000 READY_CAUSE=net.connect ;;
            esac
            ;;
        4[0-9][0-9]) READY_RESULT=unknown READY_CAUSE=http.client ;;
        *) READY_RESULT=unknown READY_CAUSE=http.server ;;
    esac
    rm -f -- "$body" 2> /dev/null
    if [ "$READY_RESULT" = unknown ]; then
        check_result ready unknown "$READY_CAUSE"
    else
        check_result ready ok -
    fi
}

# The reason the legacy hook gives before `; alert follows` or before `; the alert ... is still
# undelivered since`, by its fixed start (deploy/alert.sh, the calls of undelivered), and the cause
# recorded for it; any other reason is unknown. `cause|start`, no start holding a `;`.
WITNESS_HOOK_REASONS='nocurl|curl is not installed;net.connect|could not post to ntfy;net.connect|the last attempt to deliver was less than'

# hook_records A B C: the legacy hook's lines, from journalctl's json output on stdin, as one word
# per kept entry: `A <cause>` (an alert it could not deliver, logged in full next), `B <cause>`
# (one still undelivered) or `C` (a failure alert, delivered or not). An entry counts only when
# its _SYSTEMD_UNIT, a field journald sets from the cgroup, names a propolis-alert@ instance, and
# then only the first line of its MESSAGE is matched: the full alert the hook logs carries the
# failed unit's last journal lines, which anyone who can reach a sensor writes. Inside a JSON
# string every quote is escaped, so no such text can pass for a field of the entry, and an entry
# whose MESSAGE journald gives in binary form (not a string) is not the hook's. journalctl before
# systemd 246 prints `{ "KEY" : "value", ... }`, with blanks around the colons and commas; such a
# line has its blanks outside strings taken out first, so it reads as the compact form.
hook_records() {
    LC_ALL=C awk -v a="$1" -v b="$2" -v c="$3" -v reasons="$WITNESS_HOOK_REASONS" '
        function squeeze(s,    out, i, n, ch, ins) {
            out = ""
            ins = 0
            n = length(s)
            for (i = 1; i <= n; i++) {
                ch = substr(s, i, 1)
                if (ins) {
                    out = out ch
                    if (ch == "\\") { i++; out = out substr(s, i, 1) }
                    else if (ch == "\"") ins = 0
                } else if (ch == "\"") { ins = 1; out = out ch }
                else if (ch != " " && ch != "\t") out = out ch
            }
            return out
        }
        BEGIN {
            nr = split(reasons, rs, ";")
            for (i = 1; i <= nr; i++) {
                k = index(rs[i], "|")
                rc[i] = substr(rs[i], 1, k - 1)
                rp[i] = substr(rs[i], k + 1)
            }
        }
        substr($0, 1, 1) != "{" { next }
        {
            line = $0
            if (substr(line, 2, 1) == " ") line = squeeze(line)
            if (index(line, ",\"_SYSTEMD_UNIT\":\"propolis-alert@") == 0 \
                && index(line, "{\"_SYSTEMD_UNIT\":\"propolis-alert@") != 1) next
            p = index(line, ",\"MESSAGE\":\"")
            if (p > 0) p += 12
            else if (index(line, "{\"MESSAGE\":\"") == 1) p = 13
            else next
            s = substr(line, p)
            gsub(/\\\\/, "\001", s)
            e = 0
            n = length(s)
            for (i = 1; i <= n; i++) {
                ch = substr(s, i, 1)
                if (ch == "\\") { i++; continue }
                if (ch == "\"") { e = i; break }
            }
            if (e == 0) next
            m = substr(s, 1, e - 1)
            k = index(m, "\\n")
            if (k > 0) m = substr(m, 1, k - 1)
            kind = ""
            if (length(m) >= length(a) && substr(m, length(m) - length(a) + 1) == a) kind = "A"
            else if (index(m, b) > 0) kind = "B"
            else {
                k = index(m, c)
                if (k > 1 && substr(m, 1, k - 1) ~ /^[A-Za-z0-9@._:-]+$/) { print "C"; next }
            }
            if (kind == "") next
            cause = "unknown"
            for (i = 1; i <= nr; i++) if (index(m, rp[i]) == 1) { cause = rc[i]; break }
            print kind " " cause
        }'
}

declare -A J_RESULT=() J_NEWCUR=() J_LINES=()
J_DROP=()

# jcursor_get CLASS: the stored cursor of CLASS when it has a cursor's form, else nothing. The
# copy in /run is newer whenever there is one: it is written only while the disk refuses writes,
# and removed once the disk takes one again. Neither the file nor its directory may be a link,
# which would let whatever it points at choose where the class starts reading.
jcursor_get() {
    local d f c
    for d in "$PA_RUN/jcursor" "$PA_STATE/jcursor"; do
        f="$d/$1"
        [ -d "$d" ] && [ ! -L "$d" ] && [ -f "$f" ] && [ ! -L "$f" ] || continue
        c="$(timeout 5 head -c 600 -- "$f" 2> /dev/null)" || continue
        c="${c%$'\n'}"
        if pa_jcursor_ok "$c"; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 0
}

# jclass_read CLASS MODE MATCH...: the entries of CLASS's journal (MATCH, fields journald sets)
# since its stored cursor, or the last 15 minutes without one, filtered first and only then cut:
# the fixed-string grep (MODE cat) or hook_records (MODE json) keeps only lines that carry a
# pattern, and those are cut to 1 MiB and 400 bytes a line into J_LINES. journalctl reads to the
# end of the entries either way, so a flood of other lines from the same unit costs read time,
# never a pattern line or the cursor's progress. journalctl writes its cursor into a private
# file, read back here only in a cursor's form, for jcursor_store to keep. A read that timed out
# or failed is unknown for the pass and its cursor is not taken.
jclass_read() {
    local class="$1" mode="$2" cur tmpc tmpo st0="" st1="" c p
    local -a pats=() gr=() cargs=()
    shift 2
    J_RESULT[$class]=unknown J_NEWCUR[$class]="" J_LINES[$class]=""
    if ! fits 45; then
        check_result "journal:$class" unknown unknown
        return 0
    fi
    tmpc="$(umask 077 && mktemp 2> /dev/null)" || tmpc=""
    tmpo="$(umask 077 && mktemp 2> /dev/null)" || tmpo=""
    PA_CLEANUP+=("$tmpc" "$tmpo")
    if [ -z "$tmpc" ] || [ -z "$tmpo" ]; then
        check_result "journal:$class" unknown tool.exec
        return 0
    fi
    mapfile -t pats < <(pa_journal_patterns "$class")
    for p in "${pats[@]}"; do gr+=(-e "$p"); done
    cur="$(jcursor_get "$class")"
    if [ -n "$cur" ]; then
        printf '%s\n' "$cur" > "$tmpc"
        cargs=("--cursor-file=$tmpc")
    else
        rm -f -- "$tmpc"
        cargs=("--cursor-file=$tmpc" --since=-15min)
    fi
    if [ "$mode" = json ]; then
        read -r st0 st1 < <(
            timeout 30 journalctl -q --no-pager -o json --output-fields=_SYSTEMD_UNIT,MESSAGE \
                "${cargs[@]}" "$@" 2> /dev/null | hook_records "${pats[@]}" > "$tmpo"
            printf '%s %s\n' "${PIPESTATUS[0]}" "${PIPESTATUS[1]}"
        )
    else
        read -r st0 st1 < <(
            timeout 30 journalctl -q --no-pager -o cat "${cargs[@]}" "$@" 2> /dev/null \
                | LC_ALL=C grep -a -F "${gr[@]}" > "$tmpo"
            printf '%s %s\n' "${PIPESTATUS[0]}" "${PIPESTATUS[1]}"
        )
    fi
    if [ "$st0" != 0 ] || ! [[ $st1 =~ ^[01]$ ]]; then
        case "$st0" in
            126 | 127) check_result "journal:$class" unknown tool.exec ;;
            *) check_result "journal:$class" unknown unknown ;;
        esac
        rm -f -- "$tmpc" "$tmpo" 2> /dev/null
        return 0
    fi
    J_LINES[$class]="$(timeout 5 head -c 1048576 -- "$tmpo" 2> /dev/null | LC_ALL=C cut -b 1-400)"
    c=""
    if [ -f "$tmpc" ] && [ ! -L "$tmpc" ]; then
        c="$(timeout 5 head -c 600 -- "$tmpc" 2> /dev/null)" || c=""
        c="${c%$'\n'}"
    fi
    if [ -n "$c" ] && [ "$c" != "$cur" ] && pa_jcursor_ok "$c"; then J_NEWCUR[$class]="$c"; fi
    rm -f -- "$tmpc" "$tmpo" 2> /dev/null
    J_RESULT[$class]=ok
    check_result "journal:$class" ok -
}

declare -A AU_IEM=() AU_CAUSE=()
AU_RESULT=skip

# alertunit_read: failure hooks that themselves failed or timed out: the failed propolis-alert@
# instances systemd lists, and for each when it failed (uptime) and its own proc.* cause. A failed
# instance stays failed until reset-failed, so the time is what tells a new failure from an old
# one. At most 32 instances, and only names in systemd's form.
alertunit_read() {
    local out u rc=0
    local -a units=()
    AU_RESULT=unknown
    if ! fits 40; then
        check_result alertunit unknown unknown
        return 0
    fi
    out="$(systemctl list-units --all --plain --no-legend --state=failed 'propolis-alert@*' 2> /dev/null)" || rc=$?
    if [ "$rc" != 0 ]; then
        case "$rc" in
            126 | 127) check_result alertunit unknown tool.exec ;;
            *) check_result alertunit unknown unknown ;;
        esac
        return 0
    fi
    while read -r u _; do
        if [[ $u != propolis-alert@* ]] || ! pa_unit_name_ok "$u"; then continue; fi
        [ "${#units[@]}" -lt 32 ] || break
        units+=("$u")
    done <<< "$out"
    if [ "${#units[@]}" -gt 0 ]; then
        for u in "${units[@]}"; do WANT[$u]=1; done
        if ! out="$(systemctl show -p Id,LoadState,ActiveState,Result,ExecMainStatus,InactiveEnterTimestampMonotonic -- "${units[@]}" 2> /dev/null)"; then
            check_result alertunit unknown unknown
            return 0
        fi
        parse_show "$out"
        for u in "${units[@]}"; do
            [ "${S_ACT[$u]:-}" = failed ] || continue
            # A failure whose time cannot be read cannot be told from an old one: it opens nothing.
            [[ ${S_IEM[$u]:-} =~ ^[0-9]{1,18}$ ]] && [ "${S_IEM[$u]}" != 0 ] || continue
            pa_cause "${S_RES[$u]:-}" "${S_STATUS[$u]:-}" 0 > /dev/null
            AU_IEM[$u]=$((10#${S_IEM[$u]} / 1000000)) AU_CAUSE[$u]="$PA_CAUSE"
        done
    fi
    AU_RESULT=ok
    check_result alertunit ok -
}

UNDELIV_N="" DELIV_LAST=""

# delivered_last: the newest of the legacy hook's delivered stamps, /run/propolis-alert/<unit>
# (deploy/alert.sh touches one each time an alert for that unit goes out, to the push target or,
# with none, to the journal), as wall-clock seconds in DELIV_LAST; 0 when there is none, nothing
# when the directory cannot be listed or there is no time left to list it.
delivered_last() {
    local dir="$ROOT/run/propolis-alert" t name best=0 st=1
    DELIV_LAST=""
    fits 5 || return 0
    if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
        DELIV_LAST=0
        return 0
    fi
    [ -d "$dir" ] && [ ! -L "$dir" ] || return 0
    # NUL-separated, so a name can never pass for a second entry with a time of its own choosing.
    while IFS= read -r -d '' name; do
        if [ "$name" = "status=0" ]; then
            st=0
            continue
        fi
        t="${name%% *}" name="${name#* }"
        [[ $name =~ ^[A-Za-z0-9@._:-]{1,200}$ && $t =~ ^([0-9]{1,12})(\.[0-9]*)?$ ]] || continue
        t="$((10#${BASH_REMATCH[1]}))"
        [ "$t" -le "$best" ] || best="$t"
    done < <(
        timeout 5 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%T@ %f\0' 2> /dev/null
        printf 'status=%s\0' "$?"
    )
    # A listing that failed or was cut off says nothing.
    [ "$st" = 0 ] || return 0
    DELIV_LAST="$best"
}

# undelivered_count: how many of the legacy hook's undelivered files /run/propolis-alert holds (one
# per unit, root-written by deploy/alert.sh, removed once that unit's alert goes out); nothing when
# the directory cannot be listed or there is no time left to list it.
undelivered_count() {
    local dir="$ROOT/run/propolis-alert/undelivered" name list n=0
    UNDELIV_N=""
    fits 5 || return 0
    if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
        UNDELIV_N=0
        return 0
    fi
    [ -d "$dir" ] && [ ! -L "$dir" ] || return 0
    list="$(timeout 5 find "$dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' 2> /dev/null)" || return 0
    while IFS= read -r name; do
        [[ $name =~ ^[A-Za-z0-9@._:-]{1,200}$ ]] && n=$((n + 1))
    done <<< "$list"
    UNDELIV_N="$n"
}

# light_probes: everything the light pass's checks read, before the lock, in order: the database
# first (light_pass runs it before the sample), then the daemon's last run while the database is
# down, /ready, the journal classes, the failed failure hooks, the undelivered list and the
# delivered stamps.
light_probes() {
    daemon_tie
    ready_probe
    jclass_read hook json _UID=0 SYSLOG_IDENTIFIER=propolis-alert
    jclass_read guard cat _SYSTEMD_UNIT=propolis-logrotate.service _UID=0
    jclass_read journald cat MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e _SYSTEMD_UNIT=systemd-journald.service _UID=0
    alertunit_read
    undelivered_count
    delivered_last
}

# ---- the light pass's judgement of its probes -------------------------------------------------

# rec_attrs KIND TIER STAGE CAUSE: the attributes of a kind the witness sees itself, with no unit.
rec_attrs() {
    PA_REC_KIND="$1" PA_REC_TIER="$2" PA_REC_STAGE="$3" PA_REC_CAUSE="$4"
    PA_REC_INST=- PA_REC_NR=- PA_REC_OUT=- PA_REC_FLAG=""
}

# two_pass KEY SEEN HOLD: the rule of two passes for a condition the witness sees, with the
# attributes in PA_REC_*. Seen (SEEN 1) with no record, or after a resolve, it is pending; seen on
# the next pass too it opens, unless HOLD (the boot grace, a marker) keeps it pending; seen while
# open it is a fresh reading (a change only when the cause's class moves). Not seen (SEEN 0, which
# an unknown is too) a pending record is dropped, since the next sighting would not be the second
# in a row, and an open one waits for its proof.
two_pass() {
    local key="$1" saw="$2" hold="$3" st=none
    if pa_incident_get "$key"; then st="${PA_INC[7]}"; fi
    if [ "$saw" = 1 ]; then
        case "$st" in
            none | resolved) pa_incident_transition "$key" pending && rec_set ;;
            pending) [ -n "$hold" ] || { pa_incident_transition "$key" open && rec_set; } ;;
            open | acked) pa_incident_transition "$key" change && rec_set ;;
        esac
    elif [ "$st" = pending ]; then
        pa_incident_transition "$key" drop && rec_set
    fi
    return 0
}

# resolve_if KEY MET PROOF: an open or acked record of KEY resolves with PROOF when MET is 1.
resolve_if() {
    [ "$2" = 1 ] && pa_incident_get "$1" || return 0
    case "${PA_INC[7]}" in
        open | acked)
            PA_REC_PROOF="$3"
            pa_incident_transition "$1" resolve && rec_set
            ;;
    esac
    return 0
}

# probe_counts: every check this pass ran, in its P line; three that could not tell in a row open
# tool-unusable. CHECK_BAD names this pass's.
probe_counts() {
    local c
    for c in "${!CHK_RESULT[@]}"; do
        check_counts "$c" "${CHK_RESULT[$c]}" "${CHK_CAUSE[$c]}"
        [ "${CHK_RESULT[$c]}" = ok ] || CHECK_BAD+=("$c")
    done
}

DB_PARENT="" TIE_HOLD=0 MAINT_REASON=""

# judge_db: db-unreachable (db:local or db:remote, PAGE) when the probe fails with a database cause
# on two passes in a row, db-readonly (db:recovery, PAGE) when the database is a standby on two;
# both resolve db2, two passes in a row on which it answered (writable, for db-readonly). Neither
# opens in the first 900 s of uptime, while a database is still recovering from the boot, nor under
# a maintenance marker of planned work (reason manual), which is how the operator says the database
# is being worked on. tool.exec and config.invalid say nothing of the database: they open nothing
# here, and count toward tool-unusable instead. Then, for the daemon's record: the open
# db-unreachable record a tie may fold it under (DB_PARENT), and whether the tie holds.
judge_db() {
    local prev="" hold="" key k answered2=0 f2=0
    DB_PARENT="" TIE_HOLD=0
    [ "$DB_RESULT" != skip ] || return 0
    IFS=$'\t' read -r _ prev _ <<< "${OBS_P[db]:-}"
    case "$DB_RESULT" in
        f) streak db ok ;;
        t) streak db recovery ;;
        down) streak db down ;;
        *) unset 'OBS_P[db]' ;;
    esac
    case "$DB_RESULT:${prev:-}" in
        f:ok | f:recovery | t:ok | t:recovery) answered2=1 ;;
    esac
    [ "$DB_RESULT:${prev:-}" != f:ok ] || f2=1
    [ "$PA_UP" -ge 900 ] || hold=grace
    if [ "$MAINT" = 1 ] && [ "$MAINT_REASON" = manual ]; then hold=maint; fi
    key="db:$DB_WHERE"
    for k in db:local db:remote; do
        rec_attrs db-unreachable PAGE ledger "$DB_CAUSE"
        if [ "$k" = "$key" ] && [ "$DB_RESULT" = down ]; then
            two_pass "$k" 1 "$hold"
        else
            two_pass "$k" 0 ""
            resolve_if "$k" "$answered2" db2
        fi
    done
    rec_attrs db-readonly PAGE ledger db.recovery
    if [ "$DB_RESULT" = t ]; then
        two_pass db:recovery 1 "$hold"
    else
        two_pass db:recovery 0 ""
        resolve_if db:recovery "$f2" db2
    fi
    # A probe that could not tell for six hours leaves every open database record unverifiable.
    if [ "$DB_RESULT" = unknown ] && unknown_for pg; then
        for k in db:local db:remote db:recovery; do flag_cannotverify "$k"; done
    fi
    if pa_incident_get "$key"; then
        case "${PA_INC[7]}" in open | acked) DB_PARENT="${PA_INC[1]}" ;; esac
    fi
    if [ "$DB_RESULT" = down ] && [ "$TIE" = 1 ]; then TIE_HOLD=1; fi
}

# unknown_for CHECK: CHECK's P line has said it could not tell on 72 passes in a row, six hours
# of light passes.
unknown_for() {
    local result consec
    IFS=$'\t' read -r _ result _ consec _ <<< "${OBS_P[$1]:-}"
    [ "${result:-ok}" != ok ] && [[ ${consec:-} =~ ^[0-9]{1,9}$ ]] && [ "$((10#$consec))" -ge 72 ]
}

# ready_unverified: /ready has been no proof input for six hours: it could not be asked or judged
# (P ready), or it timed out on 72 passes in a row and on this one.
ready_unverified() {
    local code consec
    unknown_for ready && return 0
    [ "$READY_RESULT:$READY_CAUSE" = 000:net.timeout ] || return 1
    IFS=$'\t' read -r _ code _ consec _ <<< "${OBS_P[ready-code]:-}"
    [ "${code:-}" = 000 ] && [[ ${consec:-} =~ ^[0-9]{1,9}$ ]] && [ "$((10#$consec))" -ge 72 ]
}

# flag_cannotverify KEY: an open or acked record of KEY is flagged cannotverify, once: its proof's
# input has been unknown for six hours. Unknown still resolves nothing.
flag_cannotverify() {
    pa_incident_get "$1" || return 0
    case "${PA_INC[7]}" in open | acked) ;; *) return 0 ;; esac
    case ",${PA_INC[30]}," in *,cannotverify,*) return 0 ;; esac
    _pa_flag_add cannotverify
    rec_set
}

# parent_gone ID SECONDS: the record with id ID resolved at least SECONDS ago, or is gone.
parent_gone() {
    local line id st rs a
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ id _ _ _ _ _ st _ _ _ _ _ _ _ _ _ _ _ _ _ rs _ <<< "$line"
        [ "$id" = "$1" ] || continue
        [ "$st" = resolved ] || return 1
        a="$(pa_age "${rs:-}")"
        [ "$a" -ge "$2" ]
        return
    done
    return 0
}

# tie_fold KEY: the daemon's record folds under the open db-unreachable record (DB_PARENT), now or
# already, and is the current record after. Status 1 while there is no open parent, or when it is
# folded under another.
tie_fold() {
    [ -n "$DB_PARENT" ] && pa_incident_get "$1" || return 1
    [ "${PA_INC[13]}" != "$DB_PARENT" ] || return 0
    [ "${PA_INC[13]}" = - ] || return 1
    pa_incident_fold "$1" "$DB_PARENT" || return 1
    rec_set
}

# unfold_open: the current record, folded under a parent that resolved half an hour ago while it
# is still failing, is its own incident again, and opens as one: what the parent's resolve said
# for it is no longer true.
unfold_open() {
    PA_INC[13]=-
    _pa_flag_drop folded
    PA_INC[9]="$PA_STAMP" PA_INC[16]=open PA_INC[18]=0
    _pa_counts && PA_INC[29]=$(($(_pa_num "${PA_INC[29]}") + 1))
    _pa_schedule
    rec_set
}

# daemon_up: the unit judged (unit_facts) is up and, for the daemon, ready: /ready answered 200,
# or, where it cannot be asked (config.invalid), it has been up ten minutes.
daemon_up() {
    [ "$F_ACTIVE" = active ] || return 1
    case "$READY_RESULT:$READY_CAUSE" in
        200:*) return 0 ;;
        *:config.invalid) [ "$F_UP" != - ] && [ "$F_UP" -ge 600 ] ;;
        *) return 1 ;;
    esac
}

# folded_pending UNIT KEY PREVUP HOLD: a first sighting folded under a parent (the daemon's under
# db-unreachable) sends nothing while that parent is open, whatever the tie says meanwhile: a
# journal read that lapses, or a database that answers once, does not make the outage two. Its
# NRestarts are kept current, so restarts during the outage are not taken for a new failure after
# it. Once the parent has resolved the child heals (dropped and counted) when it is up and ready
# or meets the first-sighting rule, and opens as its own incident only when it is still not up
# half an hour after the parent resolved (in v2 its message says it was folded under the parent).
folded_pending() {
    local u="$1" key="$2" prevup="$3" hold="$4" parent="${PA_INC[13]}" k judge
    if ! parent_gone "$parent" 0; then
        k="${PA_INC[30]:--}/${PA_INC[32]:--}"
        [[ ! $F_NR =~ ^[0-9]{1,9}$ ]] || PA_INC[32]="$F_NR"
        _pa_flag_add folded
        [ "${PA_INC[30]:--}/${PA_INC[32]:--}" = "$k" ] || rec_set
        return 0
    fi
    judge="$(pa_first_sighting "${PA_INC[32]:--}" "$F_NR" "$F_UP" "$prevup")"
    if { [ "$u" = propolis.service ] && daemon_up; } || [ "$judge" = drop ]; then
        HEALED=$((HEALED + 1))
        pa_incident_transition "$key" drop && rec_set
        return 0
    fi
    [ -z "$hold" ] && parent_gone "$parent" 1800 || return 0
    PA_INC[13]=-
    _pa_flag_drop folded
    if [ "${PA_INC[11]}" = db.unreachable ]; then
        sample_cause "$u"
        PA_INC[11]="$C_CAUSE" PA_INC[12]="$PA_STAMP"
    fi
    rec_set || return 0
    rec_open "$key" "" "" "" "" "$F_NR"
}

# unit_open UNIT KEY KIND TIER STAGE CAUSE NR: rec_open, except for the daemon while its failure is
# the database's: the probe fails with a database cause and its last run logged that it could not
# connect (TIE_HOLD). Its record then stays pending, with the database's cause, and folds under
# db-unreachable once that opens, so the first word of the outage names the database and the
# daemon's reserve slot is not spent on it. Not yet folded, it opens as usual the moment either
# stops holding, then as an incident of its own, with systemd's cause; once folded, only
# folded_pending decides, by its parent.
unit_open() {
    local u="$1" key="$2" out=- occ=1 had=0 cause="$6"
    shift 2
    if [ "$u" = propolis.service ] && [ "$TIE_HOLD" = 1 ]; then
        if pa_incident_get "$key" && [ "${PA_INC[7]}" != resolved ]; then
            had=1 out="${PA_INC[33]}" occ="${PA_INC[31]}"
        fi
        PA_REC_KIND=daemon-down PA_REC_TIER=PAGE PA_REC_STAGE=intake PA_REC_CAUSE=db.unreachable
        PA_REC_NR="$5" PA_REC_INST="${IDS[$u]:--}" PA_REC_OUT=- PA_REC_FLAG=""
        pa_incident_transition "$key" pending || return 0
        if [ "$had" = 1 ]; then PA_INC[33]="$out" PA_INC[31]="$occ"; fi
        rec_set || return 0
        tie_fold "$key" || true
        return 0
    fi
    if [ "$u" = propolis.service ] && pa_incident_get "$key" && [ "${PA_INC[7]}" != resolved ]; then
        [ "${PA_INC[13]}" = - ] || return 0
        if [ -z "$cause" ] && [ "${PA_INC[11]}" = db.unreachable ]; then
            sample_cause "$u"
            cause="$C_CAUSE"
        fi
    fi
    rec_open "$key" "$1" "$2" "$3" "$cause" "$5"
}

DOBS="" DOBS_N=0 DCAUSE="" READY2=0

# daemon_observe: what the daemon was seen to be on this pass, in its P line with how many passes
# in a row: down (stopped, failed or waiting to restart; or up for half an hour without an answer
# from its console, DCAUSE then the console's cause), activating (systemd still starting it),
# starting (up under half an hour without an answer: migrations can take that long, and calling
# it down invites a restart that makes things worse), degraded (503: its pool cannot reach a
# database root can reach, or a subsystem gave up, in DCAUSE), dbcarried (503 while the probe
# fails too: db-unreachable carries it), ok (200), off (disabled on purpose). READY2: /ready
# answered 200 on this pass and on the one before, at least five minutes earlier. The timer starts
# a pass five minutes after the last one started, and each stamp is whole seconds taken after a
# start whose length varies, so two passes five minutes apart can be stamped 299 s apart: five
# minutes is READY_GAP, ten seconds short of 300 and still far above any shorter gap.
READY_GAP=290
daemon_observe() {
    local u=propolis.service prevs="" prevr=""
    DOBS="" DOBS_N=0 DCAUSE="" READY2=0
    IFS=$'\t' read -r prevs prevr _ <<< "${OBS_P[ready-code]:-}"
    case "$READY_RESULT" in
        200 | 000 | 503 | 503g) streak ready-code "$READY_RESULT" ;;
        *) unset 'OBS_P[ready-code]' ;;
    esac
    if [ "$READY_RESULT" = 200 ] && [ "${prevr:-}" = 200 ] && _pa_stamp_split "${prevs:-}" \
        && [ "$(pa_age "$prevs")" -ge "$READY_GAP" ]; then
        READY2=1
    fi
    if [ "$SAMPLE_OK" != 1 ] || [ -z "${S_LOAD[$u]:-}" ] || [ "${S_LOAD[$u]}" = "?" ]; then
        unset 'OBS_P[daemon]'
        return 0
    fi
    case "${PA_ROLE:-}" in
        collector | gateway)
            unset 'OBS_P[daemon]'
            return 0
            ;;
    esac
    unit_facts "$u"
    if [ "$F_DISABLED" = 1 ]; then
        DOBS=off
        unset 'OBS_P[daemon]'
        return 0
    fi
    case "$F_ACTIVE" in
        failed | inactive | restarting) DOBS=down ;;
        starting) DOBS=activating ;;
        *)
            case "$READY_RESULT" in
                200) DOBS=ok ;;
                000)
                    if [ "$F_UP" != - ] && [ "$F_UP" -ge 1800 ]; then DOBS=down DCAUSE="$READY_CAUSE"; else DOBS=starting; fi
                    ;;
                503g) DOBS=degraded DCAUSE=ready.gave_up ;;
                503)
                    if [ "$DB_RESULT" = down ]; then DOBS=dbcarried; else DOBS=degraded DCAUSE=ready.db; fi
                    ;;
                *) DOBS="" ;;
            esac
            ;;
    esac
    if [ -z "$DOBS" ]; then
        unset 'OBS_P[daemon]'
        return 0
    fi
    streak daemon "$DOBS"
    DOBS_N="$STREAK_N"
}

# judge_degraded: daemon-degraded (ready:local, ACT) when the daemon is up and answers /ready 503
# on two passes, unless the probe fails too (db-unreachable carries that). A 503 while root's probe
# could not test the database (tool.exec, config.invalid, unknown) counts: the daemon's answer is
# then the only word on the database. Not opened in the first ten minutes after a boot or under a
# maintenance marker; resolved ready2, or disabled with the daemon.
judge_degraded() {
    local key=ready:local hold=""
    [ "$PA_UP" -ge 600 ] || hold=grace
    [ "$MAINT" = 0 ] || hold=maint
    rec_attrs daemon-degraded ACT intake "${DCAUSE:-ready.db}"
    case "$DOBS" in
        degraded) two_pass "$key" 1 "$hold" ;;
        ok)
            two_pass "$key" 0 ""
            resolve_if "$key" "$READY2" ready2
            ;;
        off)
            two_pass "$key" 0 ""
            resolve_if "$key" 1 disabled
            ;;
        *) two_pass "$key" 0 "" ;;
    esac
    if ready_unverified; then flag_cannotverify "$key"; fi
}

HOOK_A=0 HOOK_B=0 HOOK_C=0 HOOK_CAUSE=""

# hook_counts: the legacy hook's lines this pass, from J_LINES[hook].
hook_counts() {
    local w c
    HOOK_A=0 HOOK_B=0 HOOK_C=0 HOOK_CAUSE=""
    [ "${J_RESULT[hook]:-}" = ok ] || return 0
    while read -r w c _; do
        case "$w" in
            A) HOOK_A=$((HOOK_A + 1)) ;;
            B) HOOK_B=$((HOOK_B + 1)) ;;
            C) HOOK_C=$((HOOK_C + 1)) ;;
            *) continue ;;
        esac
        case "$w:${c:-}" in
            A:nocurl | A:net.connect | A:unknown | B:nocurl | B:net.connect | B:unknown) HOOK_CAUSE="$c" ;;
        esac
    done <<< "${J_LINES[hook]}"
}

# judge_alert_path: alert-path (alert:shell, PAGE) opens on first sight of a fact: the legacy hook
# logged that it could not deliver an alert (cause from its reason: nocurl, net.connect or
# unknown), or a failure hook failed (a failed propolis-alert@ instance whose failure is newer
# than this key's last open or resolve; its own proc.* cause). It resolves sent2xx on a pass
# whose reads all worked, on proof that an alert got through after the open (alert_delivered),
# with none of the legacy hook's undelivered files left (it removes its file once that unit's
# alert goes out) and no failure hook failed since the open. Nothing seen is never the proof: a
# hook killed by its time limit writes no undelivered file, and a reboot empties /run. Proof of a
# delivery holds across a reboot, and a failed hook listed now that failed before the open, in its
# boot, is the failure the record already holds.
judge_alert_path() {
    local key=alert:shell cause="" st=none ref="" u
    if pa_incident_get "$key"; then
        st="${PA_INC[7]}"
        case "$st" in
            open | acked | pending) ref="${PA_INC[9]}" ;;
            resolved) ref="${PA_INC[21]}" ;;
        esac
    fi
    if [ "$((HOOK_A + HOOK_B))" -gt 0 ]; then cause="${HOOK_CAUSE:-unknown}"; fi
    if [ "$AU_RESULT" = ok ]; then
        for u in "${!AU_IEM[@]}"; do
            # A failed state does not outlive a boot, so an instance failed in this one is newer
            # than an open or resolve of another; within one boot the uptimes tell. A time that
            # cannot be placed opens nothing.
            if [ -n "$ref" ]; then
                _pa_stamp_split "$ref" && [ "$_PA_B" != - ] && [ "$PA_BOOT" != - ] || continue
                if [ "$_PA_B" = "$PA_BOOT" ]; then
                    [ "${AU_IEM[$u]}" -gt "$((10#$_PA_U))" ] || continue
                fi
            fi
            cause="${AU_CAUSE[$u]}"
        done
    fi
    if [ -n "$cause" ]; then
        rec_attrs alert-path PAGE alert "$cause"
        case "$st" in
            open | acked) pa_incident_transition "$key" change && rec_set ;;
            *) pa_incident_transition "$key" open && rec_set ;;
        esac
        return 0
    fi
    case "$st" in open | acked) ;; *) return 0 ;; esac
    [ "${J_RESULT[hook]:-}" = ok ] && [ "$AU_RESULT" = ok ] && [ "$UNDELIV_N" = 0 ] || return 0
    ref="${PA_INC[9]}"
    _pa_stamp_split "$ref" || return 0
    for u in "${!AU_IEM[@]}"; do
        # Listed now, so failed in this boot: older than the open only when the open is of this
        # boot too and its uptime is later.
        [ "$_PA_B" != - ] && [ "$_PA_B" = "$PA_BOOT" ] && [ "${AU_IEM[$u]}" -le "$((10#$_PA_U))" ] || return 0
    done
    alert_delivered "$ref" || return 0
    pa_incident_get "$key" || return 0
    PA_REC_PROOF=sent2xx
    pa_incident_transition "$key" resolve && rec_set
    return 0
}

# alert_delivered OPENED: an alert went out after stamp OPENED, by one of: the legacy hook's
# delivered stamp for some unit (DELIV_LAST) dated after it on the wall clock; a failure hook's
# record of a unit (unit:*) whose firing said delivered, or journal on a host with no push target,
# and whose sighting (first seen, or a later onset) is after it; or, on a host with no push target,
# a failure alert logged on this pass with no undelivered line beside it.
alert_delivered() {
    local opened="$1" ow line s
    local -a f
    _pa_stamp_split "$opened" || return 1
    ow="$((10#$_PA_W))"
    if [[ $DELIV_LAST =~ ^[0-9]{1,12}$ ]] && [ "$((10#$DELIV_LAST))" -gt "$ow" ]; then return 0; fi
    if [ "${PA_TARGET:-0}" != 1 ] && [ "$HOOK_C" -gt 0 ] && [ "$((HOOK_A + HOOK_B))" = 0 ]; then return 0; fi
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r -a f <<< "$line"
        [[ ${f[2]:-} == unit:* ]] || continue
        case "${f[33]:-}" in delivered | journal) ;; *) continue ;; esac
        for s in "${f[8]:-}" "${f[10]:-}"; do
            _pa_stamp_split "$s" || continue
            s="$(_pa_stamp_span "$opened" "$s")" || continue
            [ "$s" -le 0 ] || return 0
        done
    done
    return 1
}

declare -A JD_N=()

# judge_journald: journal-dropped (journal:<unit>, NOTICE) on first sight of journald's notice that
# it suppressed lines of one of the units this witness watches, named exactly; resolved quiet24, a
# day with no such notice (the latest, OBS_P seen:<key>), judged only on passes whose read worked.
# journald names the unit itself (`Suppressed <n> messages from sensor-ssh.service`) since its
# client context rework in systemd 236, so on every supported host; older ones named the cgroup
# path, whose last part is the unit, and that form is taken too.
judge_journald() {
    local line n u key a s
    local re='^Suppressed ([0-9]{1,9}) messages from (/[A-Za-z0-9@._:/-]{0,300}/)?([A-Za-z0-9@._:-]{1,256})$'
    local -A watched=()
    [ "${J_RESULT[journald]:-}" = ok ] || return 0
    for u in "${WITNESS_UNITS[@]}"; do watched[$u]=1; done
    while IFS= read -r line; do
        [[ $line =~ $re ]] || continue
        n="${BASH_REMATCH[1]}" u="${BASH_REMATCH[3]}"
        [ -n "${watched[$u]:-}" ] || continue
        JD_N[$u]=$(($(_pa_num "${JD_N[$u]:-}") + 10#$n))
    done <<< "${J_LINES[journald]}"
    for u in "${!JD_N[@]}"; do
        key="journal:$u"
        rec_attrs journal-dropped NOTICE host journal.suppressed
        PA_REC_INST="${IDS[$u]:--}"
        pa_incident_transition "$key" open && rec_set
        OBS_P[seen:$key]="$PA_STAMP"$'\t'ok$'\t'-$'\t'1
    done
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        [[ $key == journal:* ]] && [ -z "${JD_N[${key#journal:}]:-}" ] || continue
        pa_incident_get "$key" || continue
        case "${PA_INC[7]}" in open | acked) ;; *) continue ;; esac
        IFS=$'\t' read -r s _ <<< "${OBS_P[seen:$key]:-}"
        _pa_stamp_split "${s:-}" || s="${PA_INC[9]}"
        a="$(pa_age "$s")"
        if [ "$a" -ge 86400 ]; then
            PA_REC_PROOF=quiet24
            pa_incident_transition "$key" resolve && rec_set
        fi
    done
    for key in "${!OBS_P[@]}"; do
        [[ $key == seen:journal:* ]] || continue
        if pa_incident_get "${key#seen:}"; then
            case "${PA_INC[7]}" in open | acked) continue ;; esac
        fi
        unset 'OBS_P[$key]'
    done
}

META_JLINES="" META_HB_SKIP=""
JLINES_NEW=""

# journal_tally: the counts the daily message and the walk read, added up in meta jlines:
# undelivered (the legacy hook's two undelivered lines), journal (failure alerts that went only to
# the journal: alerts logged with no undelivered line before them), guard (the rotation guard's
# refusals and skips) and suppressed (journald's lines dropped from watched units). Each a count of
# lines, never their text.
journal_tally() {
    local part k v line g=0 sup=0 jo
    local -a parts=()
    local -A t=([undelivered]=0 [journal]=0 [guard]=0 [suppressed]=0)
    IFS=, read -r -a parts <<< "$META_JLINES"
    for part in "${parts[@]}"; do
        k="${part%%:*}" v="${part#*:}"
        [ -n "${t[$k]+x}" ] || continue
        t[$k]="$(_pa_num "$v")"
    done
    jo=$((HOOK_C - HOOK_A))
    [ "$jo" -ge 0 ] || jo=0
    if [ "${J_RESULT[guard]:-}" = ok ]; then
        while IFS= read -r line; do [ -z "$line" ] || g=$((g + 1)); done <<< "${J_LINES[guard]}"
    fi
    for k in "${!JD_N[@]}"; do sup=$((sup + JD_N[$k])); done
    t[undelivered]=$((t[undelivered] + HOOK_A + HOOK_B)) t[journal]=$((t[journal] + jo))
    t[guard]=$((t[guard] + g)) t[suppressed]=$((t[suppressed] + sup))
    for k in "${!t[@]}"; do [ "${t[$k]}" -le 999999999 ] || t[$k]=999999999; done
    JLINES_NEW="undelivered:${t[undelivered]},journal:${t[journal]},guard:${t[guard]},suppressed:${t[suppressed]}"
}

# journal_restarts: a class whose read could not finish on two passes in a row starts again from
# the last 15 minutes without its cursor (J_DROP), since the cursor may stand before a stretch it
# can never get through; meta jskip says which, for the walk.
JSKIP_NEW=""
journal_restarts() {
    local c consec
    J_DROP=() JSKIP_NEW=""
    for c in hook guard journald; do
        [ "${J_RESULT[$c]:-}" = unknown ] || continue
        IFS=$'\t' read -r _ _ _ consec _ <<< "${OBS_P[journal:$c]:-}"
        [[ ${consec:-} =~ ^[0-9]{1,9}$ ]] && [ "$((10#$consec))" -ge 2 ] || continue
        J_DROP+=("$c")
        J_NEWCUR[$c]=""
        [ "$((10#$consec))" != 2 ] || JSKIP_NEW+="${JSKIP_NEW:+,}$c"
    done
    [ -z "$JSKIP_NEW" ] || JSKIP_NEW="$PA_STAMP/$JSKIP_NEW"
}

# jcursor_write DIR CLASS CURSOR: CURSOR as DIR/CLASS, 0600, by pa_write; DIR made 0700 if missing.
jcursor_write() {
    { [ -d "$1" ] || mkdir -m 0700 -- "$1"; } 2> /dev/null || return 1
    [ ! -L "$1" ] || return 1
    pa_write "$1/$2" < <(printf '%s\n' "$3")
}

# jcursor_store KEPT: under the lock, each class's new cursor in the state directory when this
# pass's state reached the disk, else in /run; the cursors of the classes that start again
# removed. KEPT 0 (the pass judged nothing, or what it judged was not written) moves no cursor:
# the next pass reads the same lines again, since a cursor past lines nobody judged loses them.
jcursor_store() {
    local c
    if [ "$1" != 1 ]; then
        J_NEWCUR=() J_DROP=()
        return 0
    fi
    for c in "${!J_NEWCUR[@]}"; do
        [ -n "${J_NEWCUR[$c]}" ] || continue
        if [ "$WHERE" = persistent ] && jcursor_write "$PA_STATE/jcursor" "$c" "${J_NEWCUR[$c]}"; then
            rm -f -- "$PA_RUN/jcursor/$c" 2> /dev/null || true
        else
            jcursor_write "$PA_RUN/jcursor" "$c" "${J_NEWCUR[$c]}" || true
        fi
    done
    for c in "${J_DROP[@]}"; do
        rm -f -- "$PA_STATE/jcursor/$c" "$PA_RUN/jcursor/$c" 2> /dev/null || true
    done
}

# judge_probes: the probes' transitions, before any unit is judged: the database first, so the
# daemon's record knows whether its failure is the database's.
judge_probes() {
    probe_counts
    judge_db
    daemon_observe
    judge_degraded
    hook_counts
    judge_alert_path
    judge_journald
    journal_tally
    journal_restarts
}

HB_GO=0 HB_WHY="" HB_SKIP_NEW="" HB_SKIP_FILE=""

# hbskip_get: the skip a pass that could not write meta kept (a missed lock, or no state written),
# `<stamp>/<reason>` in HB_SKIP_FILE: the newer of the copies in /run and in the state directory,
# a stamp dated ahead of the clock counting as newest. A file that is a link, or not in that form,
# is not read.
hbskip_get() {
    local f v
    HB_SKIP_FILE=""
    for f in "$PA_RUN/hbskip" "$PA_STATE/hbskip"; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        v="$(timeout 5 head -c 100 -- "$f" 2> /dev/null)" || continue
        v="${v%$'\n'}"
        [[ $v =~ ^[0-9]{1,12}/[0-9a-f-]{1,8}/[0-9]{1,10}/[a-z][a-z0-9._-]{0,31}$ ]] || continue
        HB_SKIP_FILE="$(hb_newer "$HB_SKIP_FILE" "$v")"
    done
    return 0
}

# hbskip_put VALUE: keeps a skip outside the locked state, 0600, in /run beside the heartbeat, or
# in the state directory when /run refuses it; only with a heartbeat URL to skip.
hbskip_put() {
    [ "${PA_HB_STATE:-unset}" = set ] || return 0
    pa_write "$PA_RUN/hbskip" < <(printf '%s\n' "$1") && return 0
    pa_write "$PA_STATE/hbskip" < <(printf '%s\n' "$1") || true
}

# hbskip_clear: the kept skip, once meta holds it.
hbskip_clear() {
    rm -f -- "$PA_RUN/hbskip" "$PA_STATE/hbskip" 2> /dev/null || true
}

# hb_newer A B: the newer of two `<stamp>/<reason>` values (either may be empty), one dated ahead
# of the clock counting as newest.
hb_newer() {
    local a b
    if [ -z "$1" ] || [ -z "$2" ]; then
        printf '%s' "${1:-$2}"
        return 0
    fi
    a="$(pa_age "${1%/*}")" b="$(pa_age "${2%/*}")"
    if [ "$a" -lt 0 ] || { [ "$b" -ge 0 ] && [ "$a" -le "$b" ]; }; then printf '%s' "$1"; else printf '%s' "$2"; fi
}

# hb_gate: whether the heartbeat URL is asked after this pass (HB_GO 1), else why not (HB_WHY,
# and in HB_SKIP_NEW the stamp and reason meta hb_skip keeps, from which 30 clean minutes count):
# insecure (not an https URL: refused, never requested), core (systemd could not be asked, or no
# state could be written; a pass that missed the lock is core too, and like one that wrote no
# state it keeps its skip with hbskip_put), alert-path (an alert path that is open: the dead-man
# check is then the one word that still gets out), pending (a transition waiting over 15
# minutes), check (a check that could not tell on this pass and has no open tool-unusable record,
# or a pass the deadline cut short) or clean30 (the last skip for any of those under 30 minutes
# ago). A standing limitation
# that is already recorded does not skip it, or the operator's dead-man check would fire every day
# until they deleted it. Skipping is the signal: nothing else is sent.
hb_gate() {
    HB_GO=0 HB_WHY="" HB_SKIP_NEW=""
    case "${PA_HB_STATE:-unset}" in
        set) hb_why ;;
        insecure | invalid) HB_WHY=insecure ;;
        *) return 0 ;;
    esac
    if [ -n "$HB_WHY" ]; then
        HB_SKIP_NEW="$PA_STAMP/$HB_WHY"
        return 0
    fi
    # The ping resumes only after 30 minutes clean, counted from the newer of meta's last skip and
    # the one a pass that could not write meta kept beside it. A last skip whose time cannot be
    # read, or lies ahead of the clock, is never in the past: the 30 minutes count from now.
    local last a
    last="$(hb_newer "$META_HB_SKIP" "$HB_SKIP_FILE")"
    if [ -n "$last" ]; then
        a="$(pa_age "${last%/*}")"
        if [ "$a" -lt 0 ]; then
            HB_WHY=clean30 HB_SKIP_NEW="$PA_STAMP/clean30"
            return 0
        fi
        if [ "$a" -lt 1800 ]; then
            HB_WHY=clean30
            return 0
        fi
    fi
    HB_GO=1
}

# hb_why: sets HB_WHY to the first rule of hb_gate this pass breaks, or leaves it empty.
hb_why() {
    local c line a ptx ps
    if [ "$SAMPLE_OK" != 1 ] || [ "$WHERE" = none ]; then
        HB_WHY=core
        return 0
    fi
    if pa_incident_get alert:shell; then
        case "${PA_INC[7]}" in
            open | acked)
                HB_WHY="alert-path"
                return 0
                ;;
        esac
    fi
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ptx ps _ <<< "$line"
        [ "${ptx:--}" != - ] || continue
        a="$(pa_age "${ps:-}")"
        if [ "$a" -lt 0 ] || [ "$a" -gt 900 ]; then
            HB_WHY=pending
            return 0
        fi
    done
    if [ "$DEADLINE_CUT" = 1 ]; then
        HB_WHY=check
        return 0
    fi
    for c in "${CHECK_BAD[@]}"; do
        if pa_incident_get "tool:$c"; then
            case "${PA_INC[7]}" in open | acked) continue ;; esac
        fi
        HB_WHY=check
        return 0
    done
}

# hb_send: the heartbeat URL's GET, after the pass and without the lock, then its result in meta
# hb_last (a stamp and a closed word, never the URL) under the lock for at most 10 s.
hb_send() {
    local rc=0
    pa_heartbeat_get || note "heartbeat URL request failed ($PA_HB_RESULT)"
    pa_lock 10 || rc=$?
    if [ "$rc" = 0 ]; then
        _pa_meta_set hb_last "$PA_STAMP/$PA_HB_RESULT" || true
        pa_unlock
    fi
    return 0
}

# ---- one pass -------------------------------------------------------------------------------

META_CC_LAST="" META_MAINT_SEEN="" META_CC_FAIL="" DEADLINE_CUT=0 PROBES_JUDGED=0

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
    if pa_maint_active; then MAINT=1 MAINT_REASON="$PA_MAINT_REASON"; fi
    # The database first: whether it answers decides how the daemon's failure is recorded.
    db_probe
    collect_sample
    light_probes
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
        # The heartbeat is not a locked state file; pa_write keeps its rewrite whole. Nor is the
        # kept skip: without it the next clean pass would ping at once, not 30 minutes on.
        write_heartbeat partial
        hbskip_put "$PA_STAMP/core"
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
            jlines) META_JLINES="$v" ;;
            hb_skip) META_HB_SKIP="$v" ;;
        esac
    done < <(pa_state_read meta)
    hbskip_get
    pa_incident_load
    load_observe
    sweep_stale
    load_ids
    ingest_spool
    rc_store
    if past_deadline; then
        status=partial
    else
        judge_probes
        PROBES_JUDGED=1
    fi
    [ "${#CHECK_BAD[@]}" = 0 ] || status=partial

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
    if past_deadline; then DEADLINE_CUT=1; fi

    ok=1
    if [ "$CHANGED" = 1 ]; then
        ok=0
        pa_incident_write && ok=1
        spool_finish "$ok"
        where_merge
    fi
    observe_body | pa_state_write observe
    where_merge
    # The cursors follow only lines that were judged and whose result was kept.
    if [ "$PROBES_JUDGED" = 1 ] && [ "$ok" = 1 ] && [ "$WHERE" != none ]; then
        jcursor_store 1
    else
        jcursor_store 0
    fi
    hb_gate
    # The restarts that healed are counted, never opened: the total and the latest.
    meta=(light_last "$PA_STAMP" where "${WHERE:-none}")
    if [ "$HEALED" -gt 0 ]; then
        n="$(_pa_num "${healed%%/*}")"
        meta+=(healed "$((n + HEALED))/$PA_STAMP")
    fi
    # When a maintenance marker was last seen, for the ten minutes it still holds (maint_recent).
    [ "$MAINT" = 0 ] || meta+=(maint_seen "$PA_STAMP")
    [ -z "$JLINES_NEW" ] || [ "$JLINES_NEW" = "$META_JLINES" ] || meta+=(jlines "$JLINES_NEW")
    [ -z "$JSKIP_NEW" ] || meta+=(jskip "$JSKIP_NEW")
    # A skip kept beside the state by a pass that could not write meta moves into meta here.
    v="$(hb_newer "${HB_SKIP_NEW:-$META_HB_SKIP}" "$HB_SKIP_FILE")"
    [ -z "$v" ] || [ "$v" = "$META_HB_SKIP" ] || meta+=(hb_skip "$v")
    # Whether this daemon binary carries pg-exec's guard, by its inode, size and mtime, so the
    # next pass need not read it again.
    case "$DB_GUARD" in
        0 | 1) [ -z "$DB_BIN_ID" ] || meta+=(pgexec_id "$DB_BIN_ID" pgexec_ok "$DB_GUARD") ;;
    esac
    _pa_meta_set "${meta[@]}"
    where_merge
    if [ "$WHERE" = none ]; then
        status=partial HB_GO=0
        hbskip_put "$PA_STAMP/core"
    elif [ -n "$HB_SKIP_FILE" ]; then
        hbskip_clear
    fi
    write_heartbeat "$status"
    pa_unlock
    [ "$WHERE" != none ] || note "state not persisted: neither /var/lib/propolis/witness nor /run/propolis-witness took a write"
    if [ "$HB_WHY" = insecure ] && [ "${META_HB_SKIP#*/*/*/}" != insecure ]; then
        note "heartbeat URL not requested: PROPOLIS_WITNESS_HEARTBEAT_URL is not a valid https:// URL"
    fi

    PA_WHERE="$WHERE"
    pa_banner_write || note "banner not written: /run/motd.d is missing or refused the write"
    [ "$HB_GO" = 0 ] || hb_send
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
