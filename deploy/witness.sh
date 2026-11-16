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
# `meta light_last`. Then, once a day, it posts the daily message (below), and last it writes the
# login banner, /run/motd.d/propolis, from the state files.
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
# it read was judged and kept. On a control node or gateway it lists the gateway spool, as the
# gateway account, and a collector PROPOLIS_SENSOR_LOGS lists whose spool has not been written for
# longer than twice the longest gap of its week (at least half an hour, the week a day old, the
# gateway up a quarter of an hour, no manual maintenance marker) opens spool-quiet, keyed by the
# collector's opaque id; the gateway's line that it dropped a rebuilt batch opens gateway-dup; on a
# collector the shipper's errors on three passes in a row open ship-failing and its dropped lines
# ship-dropped; the backup pull's served line is kept as meta pull_last; and a backup run past
# three times the last one's length (at least two hours) opens backup-hung. Last, after the pass,
# the optional heartbeat URL
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
# It also samples the free space and inodes of every store's filesystem with one df each and
# keeps a week of samples: a filesystem short of space or inodes, or that would fill within 72
# hours at the week's rate or the last day's, whichever is faster, opens volume-filling (at the
# lower tier of its two passes), rising to volume-full-soon within 12 hours
# or under 1.5 GiB free; a rotation refused for want of space folds under the record of the
# filesystem holding the sensor logs. Where the daemon has a database it reads its state in one
# read-only session (an old transaction id opens db-xid, slots nearly full db-slots, lock waits
# db-locks), and once a day the local data directory as the postgres account. It hashes the files
# that configure Propolis (of an env file only the whole content and its key names, never a
# value) and opens change-pending for a unit running with an env file changed since it started,
# needing a daemon reload, or running a binary since replaced. On a single box or control node it
# reads whether anything runs the public push and the push and publish markers: a push over six
# hours behind a feed that moved on opens push-failing, a push expected that nothing runs
# push-unscheduled, and the feed on with no push at all the NOTICE push-off. It counts the
# scheduled backup sets against PROPOLIS_BACKUP_KEEP (backup-retention), and with an off-host pull
# configured, a set that has waited over three days for it opens backup-offhost. A failed backup folds
# under db-unreachable or the backup volume's record by the step it failed in.
# What the light pass and the failure hook recorded in the meantime is kept as they wrote it.
# While the light pass is over 15 minutes stale, it posts the daily message in its place.
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
# RECORD ONLY, BUT FOR ONE DAILY MESSAGE. No incident is sent or paged: each transition the v2
# profile would push adds one to the record's would_push, which the status walk shows. The one
# message it posts is the daily message: once a local day, past PROPOLIS_OPS_DAILY_AT (08:41 by
# default; `off` turns it off) in the host's own zone, at least 20 hours after the last, priority
# 2, and only while the gate is full (a target over https whose topic a fresh read check proved
# to refuse anonymous reads). It carries the alias, counts, opaque incident ids, VERIFIED, the
# profile and whether the state was kept: never a name, a cause, a path or text read from the
# host. The light pass sends it, the hourly pass only while the light pass is over 15 minutes
# stale; both decide under the lock, and count it in meta and the send ledger before the post, so
# one that failed or was cut short is not sent again that day, and none goes where the state
# cannot be kept. Its other network requests are the read check's GETs and the heartbeat URL's
# GET, which carry no message, the GET of the daemon's /ready on loopback, and the read-only
# database probe and hourly state session.
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
# a state file, a journal line or the banner, and so do the daily message's, whose config file is
# removed as soon as curl returns. A journal line is matched only after the fields
# journald sets itself (the unit, the uid, the invocation id) have narrowed it to its writer, and
# then against fixed strings; no line, nor any part of one, is kept or shown, only counted. The
# daemon's /ready answer is taken only from a listener the kernel says the daemon holds, and is
# judged by its status code and one fixed token; the database URL stays in the one process that
# needs it. A gateway spool name is used only once it is a plain id of a listed collector, and
# then only through its opaque id; numbers read from files, programs and the journal are checked
# as digits first.
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
# PROPOLIS_WITNESS_SOFT_DEADLINE replaces the 160 s by which every optional probe must end;
# PROPOLIS_WITNESS_SPOOL_MAX replaces the 1024 entries one spool listing reads.
#
# The library version this script needs; deploy/rollback.sh reads the line below.
# needs-alert-lib: 10

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
# The zone this pass was started with is the host's: the daily message's time of day is read in
# it, and in nothing else, so every stamp, log line and comparison stays in UTC.
WITNESS_TZ_SET="${TZ+1}" WITNESS_TZ="${TZ-}"
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
    unset PROPOLIS_WITNESS_SPOOL_MAX
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
pa_readcheck_merge pa_pg pa_heartbeat_get pa_journal_patterns pa_jcursor_ok pa_vol_project pa_vol_judge
pa_vol_stores pa_gate pa_daily_due pa_budget_admit pa_render pa_ledger_add pa_ledger_result"
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
if [ "$WITNESS_TZ_SET" = 1 ]; then PA_HOST_TZ="$WITNESS_TZ"; else unset PA_HOST_TZ; fi
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
# 5 s each, 10 s; the collector spools, 5 s for the spool's owner, 5 s for the gateway account and
# 10 s for the listing, 20 s; the gateway's, the shipper's and the backup pull's journal classes,
# 5 s for the account and 45 s for the read each, 150 s; a changed target's read check, two
# targets of four GETs at 15 s, 120 s. 673 s in
# all, more than the deadline, so only the role, the spool listing, the sample and the guard's
# journal (83 s) always run: every other probe starts only when its whole limit still ends by
# WITNESS_SOFT_DEADLINE (below, 160 s), and one that cannot is unknown for the pass, which is then
# partial. The ownership checks' `stat` and `readlink` of the daemon binary's path have no limit
# of their own, as the state files' reads have none (see the hourly pass below). With the lock's
# 60 s that is 220 s, inside 240 s.
# After the pass come, once a day, the daily message's post, 40 s, and 30 s for the lock to note
# its result; then the banner and the heartbeat URL's GET, 15 s, and 10 s for the lock to note
# its result: 95 s at most, far inside the unit's 15 minutes. The hourly pass posts the daily
# message only while the light pass is stale, after its own 690 s, which ends by 760 s.
WITNESS_DEADLINE=240
if [ "$INSTANCE" = hourly ]; then
    # The programs an hourly pass always runs each have their own limit: config-check 300 s; the
    # read check of two targets, four GETs each at 15 s, 120 s; systemctl 20 s for the timer
    # sample and 40 s for the role's two questions; about ten small reads of 5 s, 50 s. 530 s.
    # The reads of the stores, the database, the watched files, the public push and the backups
    # come after them, and each
    # starts only when its whole limit still ends by WITNESS_SOFT_DEADLINE (570 s here; one that
    # cannot is unknown for the pass): systemctl 20 s for the units' properties and 5 s for each
    # running unit's binary; pa_pg's 30 s with 2 s to be killed, 5 s to stat the daemon binary
    # and 30 s to find its guard when no light pass has; 5 s for the postgres account and 15 s
    # for its psql; 5 s to place each store and 10 s for each filesystem's df; 10 s for each
    # listing of the watched directories, 30 s for their hashes, 5 s for each env file's key
    # names and 5 s for the binaries' stat; the push's scheduler, started only with 60 s left
    # (5 s for each crontab and unit file it reads, 10 s for each timer it asks about, so a host
    # with many files that each hang could pass it, as far as the unit's limit), 5 s for the
    # push marker and 10 s for the publish marker as the
    # daemon account; the backup sets' listing 10 s and their oldest date 5 s, 10 s for the pull
    # account and its authorized_keys, 5 s for the serve script's text; for one unlisted spool, 25 s for the spool's listing and
    # 5 s for each name's hash. With the state lock's 120 s the pass ends by 690 s,
    # inside 720 s. The local reads and writes of the state files have no limit of their own:
    # the library's `cat` and `stat` of each state file, pa_write's `sync`, and the ownership
    # checks' `stat` and `readlink` of each path. On a local disk they take milliseconds; what
    # bounds them on a disk that hangs is the unit's TimeoutStartSec of 15 minutes.
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

# No optional read (the rotation guard's journal, each probe of the light pass, each read of the
# hourly pass's stores, database and watched files) starts unless it ends by this many seconds, so
# the lock's wait still ends inside WITNESS_DEADLINE.
WITNESS_SOFT_DEADLINE=160
[ "$INSTANCE" != hourly ] || WITNESS_SOFT_DEADLINE=570
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
declare -A S_INV=() S_RESTART=() S_PID=() S_EMS=() S_EME=() WANT=() _B=()
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
        S_EMS[$id]="$(sample_word "${_B[ExecMainStartTimestampMonotonic]:-}" '^[0-9]{1,18}$')"
        S_EME[$id]="$(sample_word "${_B[ExecMainExitTimestampMonotonic]:-}" '^[0-9]{1,18}$')"
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
                | InvocationID | Restart | MainPID | ExecMainStartTimestampMonotonic \
                | ExecMainExitTimestampMonotonic) _B[$k]="${line#*=}" ;;
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
#
# For the collectors, the shipper and the gateway: `spool` the collector spools' listing and
# `shipfail` the light passes in a row whose shipper journal held an ERROR line (error) or none
# (ok); one `seen:gwdup:<id>` and `seen:shipdrop:local` line per open gateway-dup and
# ship-dropped record, the last pass that saw its line, with the records the gateway counted lost
# since the open in the place of the count. And one S line per listed collector:
# `S <collector id> <last mtime> <last advance stamp> <longest gap s> <window start stamp>
# <the window before's longest gap, or -> <advances in a row>`, the id the collector's opaque one.
#
# The hourly pass adds `push` and `backups`, its reads of the public push and of the backups.

declare -A OBS_U=() OBS_R=() OBS_P=() NEW_U=() NEW_R=() JUDGED=()
OBS_KEEP=()
OBS_MINE_P=" units witness-hourly pg ready alertunit db ready-code daemon spool shipfail "
[ "$INSTANCE" != hourly ] || OBS_MINE_P=" config-check readcheck witness-light volume pgstate changes push backups "

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
        if [ "$INSTANCE" = hourly ]; then
            case "$t" in
                U | R)
                    OBS_KEEP+=("$line")
                    continue
                    ;;
                Z)
                    OBS_Z+=("$line")
                    continue
                    ;;
                H)
                    if pa_ok_field "$name"; then OBS_H[$name]="${rest:-}"; fi
                    continue
                    ;;
            esac
        fi
        case "$t" in
            U) pa_unit_name_ok "$name" && OBS_U[$name]="${rest:-}" ;;
            R) pa_unit_name_ok "$name" && OBS_R[$name]="${rest:-}" ;;
            S)
                # The collectors' lines are the light pass's; the hourly pass keeps them as read.
                if [ "$INSTANCE" = light ]; then
                    [[ $name =~ ^c[0-9a-f]{5,8}$ ]] && OBS_S[$name]="${rest:-}"
                else
                    OBS_KEEP+=("$line")
                fi
                ;;
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
    # The collectors' lines: what this pass judged, or every line as read.
    if [ "$INSTANCE" = light ]; then
        if [ "$SPOOL_JUDGED" = 1 ]; then
            for u in "${!NEW_S[@]}"; do printf 'S\t%s\t%s\n' "$u" "${NEW_S[$u]}"; done
        else
            for u in "${!OBS_S[@]}"; do printf 'S\t%s\t%s\n' "$u" "${OBS_S[$u]}"; done
        fi | while IFS= read -r line; do
            IFS=$'\t' read -r -a fields <<< "$line"
            ok=1
            for f in "${fields[@]}"; do pa_ok_field "$f" || ok=0; done
            [ "$ok" = 0 ] || printf '%s\n' "$line"
        done
    fi
    # The hourly pass's samples of the stores and hashes of the watched files: what it judged, or,
    # when it judged nothing, every line as read.
    if [ "$INSTANCE" = hourly ]; then
        if [ "$VOL_JUDGED" = 1 ]; then
            for line in "${NEW_Z[@]}"; do printf '%s\n' "$line"; done
        else
            for line in "${OBS_Z[@]}"; do printf '%s\n' "$line"; done
        fi
        if [ "$H_JUDGED" = 1 ]; then
            for u in "${!NEW_H[@]}"; do printf 'H\t%s\t%s\n' "$u" "${NEW_H[$u]}"; done
        else
            for u in "${!OBS_H[@]}"; do printf 'H\t%s\t%s\n' "$u" "${OBS_H[$u]}"; done
        fi
    fi
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
alert-setting-invalid|daily|NOTICE|alert|alert-channel|-|-
alert-topic-readable|daily|NOTICE|alert|alert-channel|-|-
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
        'anonymous read not checked yet'* | 'alert channel not checked'*) CC_LIMITED[alert-channel]=1 ;;
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
            CC_FOLD_N=$((CC_FOLD_N + 1)) CC_FOLD_K12="$k12"
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
    local key id line state n parent daily inst
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
            # One unlisted collector is named by its opaque id; several, or one whose spool could
            # not be matched, by none.
            inst=-
            [ "$CC_FOLD_N" != 1 ] || [ -z "$UNLISTED_CID" ] || inst="$UNLISTED_CID"
            if [ "${PA_INC[34]}" != "$n" ] || [ "${PA_INC[5]}" != "$inst" ]; then
                PA_INC[34]="$n" PA_INC[5]="$inst"
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
BACKUP_FAILED_LAST=0 BACKUP_FAIL_MT="" CC_FAIL=0 STREAK_N=0

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
# root, deploy/backup.sh); an mtime that cannot be read says no. Sets BACKUP_STEP too, and
# BACKUP_FAIL_MT, when the failure was written, for the fold ties to place it against a parent.
backup_failed_last() {
    local d="$ROOT/var/lib/propolis/backup-status" f s
    BACKUP_FAILED_LAST=0 BACKUP_STEP="" BACKUP_FAIL_MT=""
    [ -f "$d/last-failure" ] && [ ! -L "$d/last-failure" ] || return 0
    # The step the run failed in, for the backup's fold ties: a plain JSON string, as the walk
    # reads it, and only ever compared with backup.sh's own fixed steps.
    s="$(timeout 5 head -c 4096 -- "$d/last-failure" 2> /dev/null | LC_ALL=C tr -d '\000')" || s=""
    if [[ $s =~ \"step\"[[:space:]]*:[[:space:]]*\"([^\"\\]{0,200})\" ]]; then BACKUP_STEP="${BASH_REMATCH[1]}"; fi
    f="$(timeout 5 stat -c %Y -- "$d/last-failure" 2> /dev/null)" || return 0
    [[ $f =~ ^[0-9]{1,12}$ ]] || return 0
    if [ -f "$d/last-success" ] && [ ! -L "$d/last-success" ]; then
        s="$(timeout 5 stat -c %Y -- "$d/last-success" 2> /dev/null)" || return 0
        [[ $s =~ ^[0-9]{1,12}$ ]] || return 0
        [ "$((10#$f))" -gt "$((10#$s))" ] || return 0
    fi
    BACKUP_FAILED_LAST=1 BACKUP_FAIL_MT=$((10#$f))
}

# ---- the hourly pass's stores, database and changes -------------------------------------------
#
# Each read runs before the lock, under its own time limit, and starts only when that limit still
# ends by WITNESS_SOFT_DEADLINE; one that cannot, or that times out, is unknown for the pass, never
# a value. Under the lock only what they found is judged. A path taken from an env file, a unit's
# properties or psql is used only once it passes path_ok, and what another account can write is
# read as that account.

# The binaries deploy/upgrade.sh installs in /usr/local/bin (its INSTALL_BINS), watched by inode,
# size and modification time: hashing some hundred megabytes every hour would show nothing a
# replaced file does not already show in those three.
WITNESS_BINS=(propolis sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred gateway shipper propolis-watch)

# path_ok PATH: an absolute path of the closed character set a path read from a file, a unit's
# properties or psql must keep to before it reaches a command line: no blank, quote or glob
# character, and no `..` component.
path_ok() {
    local LC_ALL=C
    [[ ${1:-} =~ ^/[A-Za-z0-9._/-]{1,200}$ ]] && [[ /$1/ != */../* ]]
}

# root_uid: the owner that stands for root: uid 0, or under a test root that root's owner, as the
# library's ownership check takes it.
root_uid() {
    local u=0
    if [ -n "$ROOT" ]; then
        u="$(timeout 5 stat -c %u -- "$ROOT" 2> /dev/null)" || u=0
        [[ $u =~ ^[0-9]{1,10}$ ]] || u=0
    fi
    printf '%s' "$((10#$u))"
}

declare -A CS_ACT=() CS_AEM=() CS_PID=() CS_NDR=() CS_ENVF=() CS_DEL=()
CS_OK=0 CS_BACKUP_ENV="" CS_EXE_BLIND=0

# change_sample: one `systemctl show` of every unit in scope for what change-pending judges: the
# state and start of each, its main process, whether systemd needs a daemon reload for it, and the
# env files it loads; and the backup unit's environment, where a drop-in may set
# PROPOLIS_BACKUP_DIR. Then, for each running unit, whether its main process runs a binary since
# replaced (its exe link ends in ` (deleted)`), read as root from /proc; a link that cannot be read
# is unknown (CS_DEL `?`), and when not one running unit's could be read CS_EXE_BLIND is 1: a
# replaced binary could not be seen anywhere. Sets CS_OK once systemd answered.
change_sample() {
    local out line k v u t running=0 linked=0
    local -a units=("${WITNESS_UNITS[@]}" "${WITNESS_TIMERS[@]}")
    fits 20 || return 0
    out="$(systemctl show -p Id,ActiveState,ActiveEnterTimestampMonotonic,MainPID,NeedDaemonReload,EnvironmentFiles,Environment -- "${units[@]}" 2> /dev/null)" || return 0
    _C=() _C_ENVF=""
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            cs_commit
            continue
        fi
        k="${line%%=*}" v="${line#*=}"
        [ "$k" != "$line" ] || continue
        case "$k" in
            # A unit may load several env files: systemctl prints one line for each.
            EnvironmentFiles)
                v="${v%% (*}"
                ! path_ok "$v" || _C_ENVF+=" $v"
                ;;
            Id | ActiveState | ActiveEnterTimestampMonotonic | MainPID | NeedDaemonReload | Environment) _C[$k]="$v" ;;
        esac
    done <<< "$out"
    cs_commit
    CS_OK=1
    for u in "${WITNESS_UNITS[@]}"; do
        [ "${CS_ACT[$u]:-}" = active ] && [ -n "${CS_PID[$u]:-}" ] || continue
        CS_DEL[$u]="?" running=$((running + 1))
        fits 5 || continue
        t="$(timeout 5 readlink -- "$ROOT/proc/${CS_PID[$u]}/exe" 2> /dev/null)" || continue
        linked=$((linked + 1))
        case "$t" in *' (deleted)') CS_DEL[$u]=1 ;; *) CS_DEL[$u]=0 ;; esac
    done
    if [ "$running" -gt 0 ] && [ "$linked" = 0 ]; then CS_EXE_BLIND=1; fi
}
declare -A WANT_C=() _C=()
_C_ENVF=""
for witness_u in "${WITNESS_UNITS[@]}" "${WITNESS_TIMERS[@]}"; do WANT_C[$witness_u]=1; done
unset witness_u

# cs_commit: the block of `key=value` lines just read (_C, and the env files in _C_ENVF), kept when
# it names a unit in scope; every value is checked against its form first.
cs_commit() {
    local u="${_C[Id]:-}"
    if [ -n "$u" ] && [ -n "${WANT_C[$u]:-}" ]; then
        CS_ACT[$u]="$(sample_word "${_C[ActiveState]:-}" '^[a-z-]{1,24}$')"
        CS_AEM[$u]="$(sample_word "${_C[ActiveEnterTimestampMonotonic]:-}" '^[0-9]{1,18}$')"
        CS_PID[$u]="$(sample_word "${_C[MainPID]:-}" '^[1-9][0-9]{0,9}$')"
        CS_NDR[$u]="$(sample_word "${_C[NeedDaemonReload]:-}" '^(yes|no)$')"
        CS_ENVF[$u]="$_C_ENVF"
        # Read for the backup directory alone, by pa_vol_stores; never stored or printed.
        [ "$u" != propolis-backup.service ] || CS_BACKUP_ENV="${_C[Environment]:-}"
    fi
    _C=() _C_ENVF=""
}

PG_RESULT=skip PG_CAUSE=- PG_WHERE="" PG_XID="" PG_CONN="" PG_USABLE="" PG_LOCKS="" PG_SIZE=""
PG_DATADIR="" PG_DATADIR_NEW=0 PG_DATADIR_KNOWN=1 PG_DATADIR_CAUSE=unknown
# The hourly state, readable by the daemon's own role: pg_database and pg_locks are public, other
# roles' rows of pg_stat_activity are counted with their columns nulled. Lock waits have a start
# time from server 14 (pg_locks.waitstart); before that, sessions waiting on a lock since their
# state changed. The column is read through to_jsonb, so the one statement parses on every server.
PG_SQL_XID='SELECT age(datfrozenxid) FROM pg_database WHERE datname = current_database()'
# Only client connections take a slot of max_connections; the server's own background processes
# (five or six on an idle server) are rows of pg_stat_activity too. backend_type came with server
# 10: read through to_jsonb so the statement parses on an older one, which then counts every row.
PG_SQL_SLOTS="SELECT count(*) FILTER (WHERE coalesce(to_jsonb(a)->>'backend_type', 'client backend') = 'client backend'), current_setting('max_connections'), current_setting('superuser_reserved_connections') FROM pg_stat_activity a"
PG_SQL_LOCKS="SELECT CASE WHEN current_setting('server_version_num')::int >= 140000 THEN (SELECT count(*) FROM pg_locks l WHERE NOT l.granted AND (to_jsonb(l)->>'waitstart')::timestamptz < now() - interval '120 seconds') ELSE (SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND state_change < now() - interval '120 seconds') END"
PG_SQL_SIZE='SELECT pg_database_size(current_database())'

# pg_state_read: the database's state in one pa_pg session of four statements (30 s): the age of
# its oldest unfrozen transaction id, connections against max_connections less the reserved
# slots, lock waits over 120 s, and its size, which is recorded only. Skipped where the light
# pass's probe is (no DATABASE_URL, a collector, a gateway-only host). PG_RESULT is ok, unknown
# (with PG_CAUSE) or skip; psql's own words are dropped here, never kept.
pg_state_read() {
    local known="" need=67 x c mx rs l z
    local -a lines=()
    PG_RESULT=skip
    case "${PA_ROLE:-}" in collector | gateway) return 0 ;; esac
    pa_env_get DATABASE_URL "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    if [ -z "$PA_ENV_VALUE" ] && [ -z "$PA_ENV_UNREADABLE" ]; then return 0; fi
    PA_ENV_VALUE=""
    PG_RESULT=unknown PG_CAUSE=unknown
    # The light pass keeps whether this binary carries pg-exec's guard; read here as a hint only.
    [ "$(_pa_meta_get pgexec_ok)" != 1 ] || known="$(_pa_meta_get pgexec_id)"
    [ -z "$known" ] || need=37
    fits "$need" || return 0
    PA_PG_GUARD_KNOWN="$known" PA_PG_APP=propolis-witness
    if pa_pg 30 "$PG_SQL_XID" "$PG_SQL_SLOTS" "$PG_SQL_LOCKS" "$PG_SQL_SIZE" > /dev/null; then
        mapfile -t lines <<< "$PA_PG_OUT"
        x="${lines[0]:-}" l="${lines[2]:-}" z="${lines[3]:-}"
        IFS='|' read -r c mx rs _ <<< "${lines[1]:-}"
        if [ "${#lines[@]}" = 4 ] && [[ $x =~ ^[0-9]{1,18}$ && $c =~ ^[0-9]{1,9}$ && $mx =~ ^[0-9]{1,9}$ \
            && $rs =~ ^[0-9]{1,9}$ && $l =~ ^[0-9]{1,9}$ && $z =~ ^[0-9]{1,18}$ ]]; then
            PG_RESULT=ok PG_CAUSE=-
            PG_XID=$((10#$x)) PG_CONN=$((10#$c)) PG_LOCKS=$((10#$l)) PG_SIZE=$((10#$z))
            PG_USABLE=$((10#$mx - 10#$rs))
            [ "$PG_USABLE" -ge 0 ] || PG_USABLE=0
        fi
    else
        PG_CAUSE="$PA_PG_CAUSE"
    fi
    PG_WHERE="${PA_PG_WHERE:-}"
    PA_PG_ERR="" PA_PG_OUT="" PA_PG_GUARD_KNOWN=""
    pa_ok_field "$PG_CAUSE" || PG_CAUSE=unknown
}

# pg_datadir_read: the local data directory, a store of its own, read once a day as the postgres
# account (`SHOW data_directory` needs pg_read_all_settings, which the daemon's role lacks), never
# as root, through setpriv, which runs no PAM session module, with a reset environment and none of
# this shell's descriptors, and kept in meta pg_datadir (with pg_datadir_stamp) in between. psql
# is looked for in /usr/bin and /bin only: --reset-env would put /usr/local/bin in its search, where
# a program put on a host whose /usr/local is writable by a group would run as postgres. A remote
# database has no data directory here. Only a path in path_ok's form is taken; psql's error text
# goes nowhere. PG_DATADIR_KNOWN is 0 when a local database's data directory, or where the
# database is, could not be learnt on this pass: the cached path, if any, is still sampled, but a
# filesystem missing from the stores then proves nothing.
pg_datadir_read() {
    local cached stamp a out rc
    PG_DATADIR="" PG_DATADIR_KNOWN=1 PG_DATADIR_CAUSE=unknown
    [ "$PG_RESULT" != skip ] || return 0
    cached="$(_pa_meta_get pg_datadir)" stamp="$(_pa_meta_get pg_datadir_stamp)"
    path_ok "$cached" || cached=""
    case "$PG_WHERE" in
        remote) return 0 ;;
        local) PG_DATADIR="$cached" ;;
        *)
            PG_DATADIR="$cached" PG_DATADIR_KNOWN=0
            return 0
            ;;
    esac
    # A stamp that cannot be read, or lies ahead of the clock, is no proof the cache is fresh.
    a="$(pa_age "$stamp")"
    if [ -n "$cached" ] && [ "$a" -ge 0 ] && [ "$a" -lt 86400 ]; then return 0; fi
    # With no postgres account the server runs elsewhere (a container on loopback): no data
    # directory here to place.
    account_uid postgres > /dev/null || return 0
    # A cache past its day still names where the data was; with none, the store is not known.
    [ -n "$cached" ] || PG_DATADIR_KNOWN=0
    fits 20 || return 0
    out="$(_pa_without_fds timeout 15 setpriv --reuid=postgres --regid=postgres --init-groups --reset-env -- \
        /usr/bin/env PATH=/usr/bin:/bin psql -X -A -t -c 'SHOW data_directory')"
    rc=$?
    if [ "$rc" != 0 ]; then
        # Why the store is not known, for the record of a check that stays unusable: psql that
        # cannot be run here, or a server that does not take the postgres account's connection.
        case "$rc" in
            126 | 127) PG_DATADIR_CAUSE=tool.exec ;;
            2) PG_DATADIR_CAUSE=db.unreachable ;;
        esac
        return 0
    fi
    out="${out%%$'\n'*}"
    path_ok "$out" || return 0
    PG_DATADIR="$out" PG_DATADIR_NEW=1 PG_DATADIR_KNOWN=1
}

VOL_DEV=() VOL_PATH=() VOL_AS=() VOL_TARGET=() VOL_SIZE=() VOL_AVAIL=() VOL_IT=() VOL_IA=() VOL_OK=() VOL_MID=()
VOL_ALL=1 VOL_CAUSE=unknown VOL_PCT=15 LOG_DEVS=" "

# What vol_stat runs, as root or as another account: stat with links followed, its words in the C
# locale, so a path that is not there (status 2) is told apart from one that could not be checked
# (status 1).
# shellcheck disable=SC2016 # the child bash expands these, with the path as $1
VOL_STAT_PROG='s="$(LC_ALL=C stat -L -c "%d %F" -- "$1" 2>&1)" && { printf "%s" "$s"; exit 0; }; case "$s" in *"No such file or directory"* | *"Not a directory"*) exit 2 ;; esac; exit 1'

# vol_stat PATH ACCOUNT: the filesystem and type of a store, `<dev> <type>`, links followed, as
# root or, when ACCOUNT is set, as that account, which could put a link on the path: root then
# never opens where it leads. Status 2 when the path is not there (a link to nothing included), 124
# when stat outlived its limit, 1 when it could not tell, a failed drop to ACCOUNT included.
vol_stat() {
    local out rc
    if [ -n "$2" ]; then
        out="$(_pa_as "$2" bash -c "$VOL_STAT_PROG" _ "$1")"
    else
        out="$(timeout 5 bash -c "$VOL_STAT_PROG" _ "$1" 2> /dev/null)"
    fi
    rc=$?
    case "$rc" in
        0) printf '%s' "$out" ;;
        2 | 124) return "$rc" ;;
        *) return 1 ;;
    esac
}

# vol_sample: the sizes of every store with one df sample per filesystem. The stores are
# pa_vol_stores', the list the walk maps mount ids back by: the state, cursors, feed and witness
# under /var/lib/propolis, the sensor logs, the spools, the gateway's spool, the journal, the
# backups, the local data directory and the configured log directories. Each is reduced to its
# filesystem with vol_stat, then `df -B1 --output=size,avail,itotal,iavail,target` runs once for
# each filesystem, 10 s at most, as the account that placed it; two stores df puts on one mount
# point (subvolumes without a mount of their own) are one. A store that is not there is skipped.
# VOL_ALL is 0 when this pass cannot tell that it found every store: a path that could not be
# learnt (systemd did not answer for the backup unit, gateway.env could not be read, where the
# database is was not learnt), a store that could not be checked, or a mount that hangs, which is
# unknown for that filesystem, never a value. LOG_DEVS holds the filesystems of the sensor logs,
# for the rotation guard's tie.
vol_sample() {
    local p benv="?" out rc dev type i j as line size avail it ia target
    local -A at=()
    VOL_ALL=1
    pa_env_get PROPOLIS_OPS_CAPACITY_FREE_PCT "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    # Out of the daemon's 1..100, it would refuse to start: the default is what it would use then.
    VOL_PCT=15
    if [[ $PA_ENV_VALUE =~ ^[0-9]{1,3}$ ]] && [ "$((10#$PA_ENV_VALUE))" -ge 1 ] && [ "$((10#$PA_ENV_VALUE))" -le 100 ]; then
        VOL_PCT=$((10#$PA_ENV_VALUE))
    fi
    [ "$CS_OK" != 1 ] || benv="$CS_BACKUP_ENV"
    pa_vol_stores "$benv" "$PG_DATADIR"
    [ "$PA_VOL_STORE_KNOWN" = 1 ] && [ "$PG_DATADIR_KNOWN" = 1 ] || VOL_ALL=0
    [ "$PG_DATADIR_KNOWN" = 1 ] || VOL_CAUSE="$PG_DATADIR_CAUSE"
    for i in "${!PA_VOL_STORE[@]}"; do
        p="${PA_VOL_STORE[$i]}" as="${PA_VOL_STORE_AS[$i]}"
        # With no propolis account no daemon reads or writes the configured logs here.
        if [ "$as" = propolis ] && ! account_uid propolis > /dev/null; then continue; fi
        if ! fits 5; then
            VOL_ALL=0
            continue
        fi
        out="$(vol_stat "$ROOT$p" "$as")"
        rc=$?
        [ "$rc" != 2 ] || continue
        if [ "$rc" != 0 ]; then
            VOL_ALL=0
            continue
        fi
        read -r dev type <<< "$out"
        # Not a directory: not a store on this host.
        [[ $dev =~ ^[0-9]{1,20}$ ]] && [ "$type" = directory ] || continue
        [ "${PA_VOL_STORE_LOG[$i]}" != 1 ] || LOG_DEVS+="$dev "
        # The backup directory's filesystem, for the fold of a backup refused for want of space.
        [ "$p" != "$BK_DIR" ] || BACKUP_DEV="$dev"
        [ -z "${at[$dev]:-}" ] || continue
        at[$dev]=1
        VOL_DEV+=("$dev") VOL_PATH+=("$p") VOL_AS+=("$as") VOL_OK+=(0) VOL_TARGET+=("") VOL_SIZE+=("")
        VOL_AVAIL+=("") VOL_IT+=("") VOL_IA+=("") VOL_MID+=("")
    done
    for i in "${!VOL_DEV[@]}"; do
        if ! fits 10; then
            VOL_ALL=0
            continue
        fi
        if [ -n "${VOL_AS[$i]}" ]; then
            out="$(_pa_as_t 10 "${VOL_AS[$i]}" df -B1 --output=size,avail,itotal,iavail,target -- "$ROOT${VOL_PATH[$i]}")"
        else
            out="$(timeout 10 df -B1 --output=size,avail,itotal,iavail,target -- "$ROOT${VOL_PATH[$i]}" 2> /dev/null)"
        fi
        rc=$?
        if [ "$rc" != 0 ]; then
            VOL_ALL=0
            case "$rc" in 126 | 127) VOL_CAUSE=tool.exec ;; esac
            continue
        fi
        line="$(printf '%s\n' "$out" | sed -n 2p)"
        size="" avail="" it="" ia="" target=""
        read -r size avail it ia target <<< "$line"
        if ! [[ $size =~ ^[0-9]{1,18}$ && $avail =~ ^[0-9]{1,18}$ && $it =~ ^[0-9]{1,18}$ && $ia =~ ^[0-9]{1,18}$ ]] \
            || ! [[ $target =~ ^/[\ -~]{0,255}$ ]]; then
            VOL_ALL=0
            continue
        fi
        VOL_OK[i]=1 VOL_SIZE[i]=$((10#$size)) VOL_AVAIL[i]=$((10#$avail)) VOL_IT[i]=$((10#$it))
        VOL_IA[i]=$((10#$ia)) VOL_TARGET[i]="$target"
    done
    # Records and samples are keyed by the mount point: a later filesystem df puts on the same one
    # adds neither, and holds the sensor logs for the first one's record.
    for i in "${!VOL_DEV[@]}"; do
        [ "${VOL_OK[$i]}" = 1 ] || continue
        for ((j = 0; j < i; j++)); do
            [ "${VOL_OK[$j]}" = 1 ] && [ "${VOL_TARGET[$j]}" = "${VOL_TARGET[$i]}" ] || continue
            VOL_OK[i]=0
            [[ $LOG_DEVS != *" ${VOL_DEV[$i]} "* ]] || LOG_DEVS+="${VOL_DEV[$j]} "
            break
        done
    done
}

declare -A CH_SHA=() CH_KEYS=() CH_FAILED=() CH_CTIME=()
CH_DONE=0

# The watched files, as `directory|depth`: each is listed with find (regular files of root's,
# never a link), and ch_watched picks the names that count.
WITNESS_WATCHED_DIRS=(/etc/propolis\|1 /etc/systemd/system\|2 /etc/logrotate.d\|1 /etc/tmpfiles.d\|1 /var/lib/propolis\|1 /usr/local/sbin\|1 /usr/local/lib/propolis\|1 /usr/local/bin\|1)

# The key names of an env file, one a line, by the rules pa_env_get reads systemd's
# EnvironmentFile= by: `KEY=value` and `KEY = value`, comments starting with # or ;, a value that
# runs on over lines inside a quote or past a trailing backslash, and a comment ending in a
# backslash that runs into the next line. Only a line that starts an entry gives its key, so no
# line of a value is ever printed, whatever it looks like. The states are _pa_env_scan's: k a line
# that starts afresh, c the line a comment runs into, v an unquoted value continued, s and d a
# single or double quote still open (e and f the character after a backslash).
# shellcheck disable=SC2016 # awk's own fields and strings, not the shell's
CH_KEYS_AWK='
function scan(m, t,   i, c, n) {
    if (m == "v" || (m == "p" && index(t, "\"") == 0 && index(t, "\047") == 0)) {
        n = 0
        if (match(t, /\\+$/)) n = RLENGTH
        return (n % 2) ? "v" : "k"
    }
    for (i = 1; i <= length(t); i++) {
        c = substr(t, i, 1)
        if (m == "p") {
            if (c == "\047") m = "s"
            else if (c == "\"") m = "d"
            else if (c == "\\") m = "e"
            else if (c != " " && c != "\t") m = "v"
        } else if (m == "v") {
            if (c == "\\") m = "e"
        } else if (m == "e") {
            m = "v"
        } else if (m == "s") {
            if (c == "\047") m = "p"
        } else if (m == "d") {
            if (c == "\"") m = "p"
            else if (c == "\\") m = "f"
        } else if (m == "f") {
            m = "d"
        }
    }
    if (m == "p" || m == "v") return "k"
    if (m == "e") return "v"
    return m
}
BEGIN { st = "k" }
{
    if (st == "c") { st = "k"; next }
    if (st != "k") { st = scan(st, $0); next }
    if ($0 ~ /^[ \t]*[#;]/) {
        if (match($0, /\\+$/) && RLENGTH % 2 == 1) st = "c"
        next
    }
    if (index($0, "=") == 0) next
    if ($0 ~ /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/) {
        k = $0
        sub(/^[ \t]*/, "", k)
        sub(/[ \t]*=.*$/, "", k)
        print k
    }
    v = $0
    sub(/^[^=]*=/, "", v)
    st = scan("p", v)
}'

# ch_watched DIR REL: how a listed file is watched: env (a hash of the content and of the sorted key
# names), file (a hash of the content), bin (inode, size and modification time), or not at all.
ch_watched() {
    local dir="$1" rel="$2" sub="" b
    case "$rel" in */*) sub="${rel%/*}" rel="${rel##*/}" ;; esac
    if [ -n "$sub" ]; then
        # Below a directory only a unit's drop-ins count: <unit>.d/<name>.conf.
        [ "$dir" = /etc/systemd/system ] && [[ $sub == *.d && $sub != */* && $rel == *.conf ]] \
            && ch_unit "${sub%.d}" && printf file
        return
    fi
    case "$dir|$rel" in
        "/etc/propolis|"*.env) printf env ;;
        "/etc/propolis|backup-recipients.txt" | "/etc/logrotate.d|propolis-sensors" \
            | "/etc/tmpfiles.d|propolis.conf" | "/var/lib/propolis|deploy-stamp.json" \
            | "/usr/local/sbin|propolis-"* | "/usr/local/lib/propolis|"*) printf file ;;
        "/etc/systemd/system|"*) ch_unit "$rel" && printf file ;;
        "/usr/local/bin|"*)
            for b in "${WITNESS_BINS[@]}"; do
                if [ "$rel" = "$b" ]; then
                    printf bin
                    return 0
                fi
            done
            return 1
            ;;
        *) return 1 ;;
    esac
}

# ch_unit NAME: NAME is one of the Propolis units deploy/install.sh puts in /etc/systemd/system.
ch_unit() {
    case "$1" in
        propolis.service | propolis-*.service | propolis-*.timer | sensor-*.service | gateway.service | shipper.service) return 0 ;;
    esac
    return 1
}

# change_read: a hash of each watched file, for its H line: sha256 of the content (env files and
# root's scripts, units and settings), of `inode/size/mtime` for the binaries, and for an env file
# the first 8 hex of sha256 of its sorted key names. No value of an env file is stored, hashed on
# its own or printed: the content reaches sha256sum and awk as a file they open, and awk passes on
# the key names alone. An env file's ctime is read too (CH_CTIME), for env_after_start. A
# directory whose listing failed keeps its files' last lines (CH_FAILED); a hash that timed out
# leaves CH_DONE 0, and every line is kept as read.
change_read() {
    local owner spec dir depth tmp rc s rel p kind h id out line
    local -a hashed=() theirs=() envs=() ctimes=() bins=() entries=()
    CH_DONE=0
    owner="$(root_uid)"
    tmp="$(mktemp 2> /dev/null)" || return 0
    PA_CLEANUP+=("$tmp")
    for spec in "${WITNESS_WATCHED_DIRS[@]}"; do
        dir="${spec%|*}" depth="${spec#*|}"
        if ! fits 10; then
            CH_FAILED[$dir]=1
            continue
        fi
        [ -d "$ROOT$dir" ] || continue
        timeout 10 find "$ROOT$dir" -mindepth 1 -maxdepth "$depth" -type f -user "$owner" -printf '%s\t%P\0' > "$tmp" 2> /dev/null
        rc=$?
        if [ "$rc" != 0 ]; then
            CH_FAILED[$dir]=1
            continue
        fi
        mapfile -d '' -t entries < "$tmp"
        for line in "${entries[@]}"; do
            s="${line%%$'\t'*}" rel="${line#*$'\t'}"
            p="$dir/$rel"
            pa_ok_field "$p" || continue
            kind="$(ch_watched "$dir" "$rel")" || continue
            case "$kind" in
                bin) bins+=("$p") ;;
                env)
                    # An env file over 1 MiB is no env file systemd would load whole: its keys are
                    # not read.
                    hashed+=("$p") ctimes+=("$p")
                    [[ $s =~ ^[0-9]{1,7}$ ]] && [ "$((10#$s))" -le 1048576 ] && envs+=("$p")
                    ;;
                *)
                    # /var/lib/propolis is the daemon account's own directory.
                    if [ "$dir" = /var/lib/propolis ]; then theirs+=("$p"); else hashed+=("$p"); fi
                    ;;
            esac
            [ "${#hashed[@]}" -le 400 ] || break
        done
    done
    if [ "${#hashed[@]}" -gt 0 ]; then
        fits 30 || return 0
        out="$(timeout 30 sha256sum -- "${hashed[@]/#/$ROOT}" 2> /dev/null)"
        rc=$?
        [ "$rc" != 124 ] || return 0
        while read -r h p; do
            [[ $h =~ ^[0-9a-f]{64}$ ]] || continue
            p="${p#"$ROOT"}"
            pa_ok_field "$p" || continue
            CH_SHA[$p]="${h:0:16}" CH_KEYS[$p]=-
        done <<< "$out"
    fi
    # A file in the daemon account's directory is hashed as that account. It can swap the name
    # for a link between the listing and the hash, and root would then open something else: a
    # file only root may read, or one that never ends.
    for p in "${theirs[@]}"; do
        fits 10 || return 0
        out="$(_pa_as_t 10 propolis sha256sum -- "$ROOT$p" 2> /dev/null)" || continue
        h="${out%% *}"
        [[ $h =~ ^[0-9a-f]{64}$ ]] || continue
        CH_SHA[$p]="${h:0:16}" CH_KEYS[$p]=-
    done
    for p in "${envs[@]}"; do
        if [ -z "${CH_SHA[$p]:-}" ] || ! fits 5; then continue; fi
        h="$(timeout 5 awk "$CH_KEYS_AWK" "$ROOT$p" 2> /dev/null | LC_ALL=C sort -u | sha256sum 2> /dev/null)" || continue
        [[ ${h:0:8} =~ ^[0-9a-f]{8}$ ]] && CH_KEYS[$p]="${h:0:8}"
    done
    for p in "${ctimes[@]}"; do
        if [ -z "${CH_SHA[$p]:-}" ] || ! fits 5; then continue; fi
        h="$(timeout 5 stat -c %Z -- "$ROOT$p" 2> /dev/null)" || continue
        [[ $h =~ ^[0-9]{1,12}$ ]] && CH_CTIME[$p]=$((10#$h))
    done
    if [ "${#bins[@]}" -gt 0 ] && fits 5; then
        out="$(timeout 5 stat -c '%i/%s/%Y %n' -- "${bins[@]/#/$ROOT}" 2> /dev/null)"
        while read -r id p; do
            [[ $id =~ ^[0-9]{1,20}/[0-9]{1,20}/[0-9]{1,12}$ ]] || continue
            p="${p#"$ROOT"}"
            pa_ok_field "$p" || continue
            h="$(printf '%s' "$id" | sha256sum 2> /dev/null)" || continue
            CH_SHA[$p]="${h:0:16}" CH_KEYS[$p]=-
        done <<< "$out"
    fi
    CH_DONE=1
}

# ---- the hourly pass's judgement of stores, the database and changes --------------------------

declare -A OBS_H=() NEW_H=()
OBS_Z=() NEW_Z=()
VOL_JUDGED=0 H_JUDGED=0

# absent_clean KEY: KEY's condition did not hold on a pass that could see it: a pending record is
# dropped (the next sighting would not be the second in a row), an open one counts one more clean
# pass and resolves with PROOF (in ABSENT_PROOF) on the second.
ABSENT_PROOF=clean2
absent_clean() {
    pa_incident_get "$1" || {
        unset 'OBS_P[clean:$1]'
        return 0
    }
    case "${PA_INC[7]}" in
        pending) pa_incident_transition "$1" drop && rec_set ;;
        open | acked)
            streak "clean:$1" ok
            if [ "$STREAK_N" -ge 2 ]; then
                PA_REC_PROOF="$ABSENT_PROOF"
                pa_incident_transition "$1" resolve && rec_set
                unset 'OBS_P[clean:$1]'
            fi
            ;;
        *) unset 'OBS_P[clean:$1]' ;;
    esac
    return 0
}

# absent_unknown KEY: KEY's condition could not be seen on this pass: unknown opens nothing and
# resolves nothing; a pending record is dropped, an open one's clean count starts again.
absent_unknown() {
    unset 'OBS_P[clean:$1]'
    pa_incident_get "$1" && [ "${PA_INC[7]}" = pending ] || return 0
    pa_incident_transition "$1" drop && rec_set
    return 0
}

# seen_hold KEY HOLD: KEY's condition holds on this pass (attributes in PA_REC_*): the rule of two
# passes, its clean count cleared.
seen_hold() {
    unset 'OBS_P[clean:$1]'
    two_pass "$1" 1 "$2"
}

# judge_volumes: volume-filling (ACT) and volume-full-soon (PAGE) on vol:<mount id>, one record per
# filesystem whatever it rises to, from this pass's samples and the history in the Z lines (the
# triggers and the projection are the library's pa_vol_judge and pa_vol_project). A rise from the
# first to the second is a change; a tier never falls while the record is open. Room again on two
# passes resolves it (room2). A filesystem whose df did not answer is unknown; one no store lives
# on any more, on a pass that sampled every store, is no longer filling. Then the Z lines: this
# pass's samples, the earlier ones under seven days old, at most one per filesystem in any 45
# minutes, and none of a filesystem that went.
judge_volumes() {
    local input="" i id kind name m key hist line t lm ls age trig
    local -A mid_of=() sampled=() count=()
    local -a keys=() kept=()
    for i in "${!VOL_DEV[@]}"; do
        [ "${VOL_OK[$i]}" = 1 ] && input+="mount"$'\t'"${VOL_TARGET[$i]}"$'\n'
    done
    if [ -n "$input" ]; then
        while IFS=$'\t' read -r id kind name; do
            [ "$kind" = mount ] && [ -n "$name" ] && mid_of[$name]="$id"
        done < <(printf '%s' "$input" | pa_id_table 2> /dev/null)
    fi
    for i in "${!VOL_DEV[@]}"; do
        [ "${VOL_OK[$i]}" = 1 ] || continue
        m="${mid_of[${VOL_TARGET[$i]}]:-}"
        if [ -z "$m" ]; then
            # No salt, no id: nothing can be keyed, so nothing is judged or dropped.
            VOL_ALL=0 VOL_OK[i]=0
            continue
        fi
        VOL_MID[i]="$m" sampled[$m]=1
        hist=""
        for line in "${OBS_Z[@]}"; do
            IFS=$'\t' read -r _ lm ls _ t _ <<< "$line"
            [ "$lm" = "$m" ] && hist+="$ls"$'\t'"$t"$'\n'
        done
        pa_vol_project "$PA_STAMP" "${VOL_AVAIL[$i]}" <<< "$hist"
        pa_vol_judge "${VOL_SIZE[$i]}" "${VOL_AVAIL[$i]}" "${VOL_IT[$i]}" "${VOL_IA[$i]}" "$VOL_PCT" "$PA_VOL_HOURS" || continue
        key="vol:$m"
        trig=$((PA_VOL_A | PA_VOL_B | PA_VOL_C | PA_VOL_SOON))
        if [ "$trig" = 1 ]; then
            if [ "$PA_VOL_SOON" = 1 ]; then
                rec_attrs volume-full-soon PAGE host "$PA_VOL_CAUSE"
            else
                rec_attrs volume-filling ACT host "$PA_VOL_CAUSE"
            fi
            if pa_incident_get "$key"; then
                case "${PA_INC[7]}" in
                    # Open at PAGE, the record stays volume-full-soon until it resolves.
                    open | acked) [ "$PA_VOL_SOON" = 1 ] || [ "${PA_INC[6]}" != PAGE ] || PA_REC_KIND="" ;;
                    # Two passes in a row open the record at the lower of their tiers: one reading
                    # of full soon alone pages nothing, and the next one raises it as a change.
                    pending)
                        if [ "$PA_VOL_SOON" = 1 ] && [ "${PA_INC[6]}" = ACT ]; then
                            rec_attrs volume-filling ACT host "$PA_VOL_CAUSE"
                        elif [ "$PA_VOL_SOON" = 0 ] && [ "${PA_INC[6]}" = PAGE ]; then
                            PA_INC[3]=volume-filling PA_INC[6]=ACT
                            rec_set
                        fi
                        ;;
                esac
            fi
            PA_REC_INST="$m"
            seen_hold "$key" ""
        else
            ABSENT_PROOF=room2 absent_clean "$key"
        fi
    done
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        [[ $key == vol:* ]] && [ -z "${sampled[${key#vol:}]:-}" ] && keys+=("$key")
    done
    for key in "${keys[@]}"; do
        if [ "$VOL_ALL" = 1 ]; then
            ABSENT_PROOF=room2 absent_clean "$key"
        else
            absent_unknown "$key"
        fi
    done
    for line in "${OBS_Z[@]}"; do
        IFS=$'\t' read -r _ lm ls _ <<< "$line"
        [[ $lm =~ ^m[0-9a-f]{5,8}$ ]] || continue
        age="$(pa_age "$ls")"
        [ "$age" -ge 0 ] && [ "$age" -le 604800 ] || continue
        if [ -n "${sampled[$lm]:-}" ]; then
            [ "$age" -ge 2700 ] || continue
        elif [ "$VOL_ALL" = 1 ]; then
            continue
        fi
        kept+=("$line")
    done
    for i in "${!VOL_DEV[@]}"; do
        [ "${VOL_OK[$i]}" = 1 ] || continue
        kept+=("Z"$'\t'"${VOL_MID[$i]}"$'\t'"$PA_STAMP"$'\t'"${VOL_SIZE[$i]}"$'\t'"${VOL_AVAIL[$i]}"$'\t'"${VOL_IT[$i]}"$'\t'"${VOL_IA[$i]}")
    done
    # The newest 224 of each filesystem at most, seven days of passes 45 minutes apart: lines are
    # kept in the order written, so the oldest go first.
    for line in "${kept[@]}"; do
        IFS=$'\t' read -r _ lm _ <<< "$line"
        count[$lm]=$((${count[$lm]:-0} + 1))
    done
    NEW_Z=()
    for line in "${kept[@]}"; do
        IFS=$'\t' read -r _ lm _ <<< "$line"
        if [ "${count[$lm]}" -gt 224 ]; then
            count[$lm]=$((${count[$lm]} - 1))
            continue
        fi
        NEW_Z+=("$line")
    done
    VOL_JUDGED=1
}

# judge_pgstate: db-xid (ACT) when the oldest unfrozen transaction id is over a thousand million
# old, half way to wraparound and far past autovacuum's own 200 million; db-slots (ACT) when the
# connections reach 90% of max_connections less the reserved slots; db-locks (NOTICE) for lock
# waits over 120 s; each on dbstate:<name>, on the second hourly pass, resolved clean2. Like the
# light pass's database kinds, none opens in the first 900 s of uptime or under a manual marker.
judge_pgstate() {
    local hold="" k xid=0 slots=0 locks=0
    [ "$PG_RESULT" != skip ] || return 0
    if [ "$PG_RESULT" != ok ]; then
        for k in xid slots locks; do absent_unknown "dbstate:$k"; done
        return 0
    fi
    [ "$PA_UP" -ge 900 ] || hold=grace
    if [ "$MAINT" = 1 ] && [ "$MAINT_REASON" = manual ]; then hold=maint; fi
    [ "$PG_XID" -le 1000000000 ] || xid=1
    if [ "$PG_USABLE" -gt 0 ] && [ "$((PG_CONN * 10))" -ge "$((PG_USABLE * 9))" ]; then slots=1; fi
    [ "$PG_LOCKS" = 0 ] || locks=1
    if [ "$xid" = 1 ]; then
        rec_attrs db-xid ACT ledger db.xid
        seen_hold dbstate:xid "$hold"
    else
        absent_clean dbstate:xid
    fi
    if [ "$slots" = 1 ]; then
        rec_attrs db-slots ACT ledger db.slots
        seen_hold dbstate:slots "$hold"
    else
        absent_clean dbstate:slots
    fi
    if [ "$locks" = 1 ]; then
        rec_attrs db-locks NOTICE ledger db.locks
        seen_hold dbstate:locks "$hold"
    else
        absent_clean dbstate:locks
    fi
}

# judge_hlines: this pass's H lines, `H path sha16 changed keys8 seen before`: the hash, the pass
# that first saw it (`-` for a file first seen, which is no change), the key-name hash of an env
# file, the last pass that saw it, and the last pass that saw the value before it. A file a pass
# could not list keeps its line as read; one no longer there drops out.
judge_hlines() {
    local p osha ochg oseen obef d keep
    NEW_H=()
    if [ "$CH_DONE" != 1 ]; then
        for p in "${!OBS_H[@]}"; do NEW_H[$p]="${OBS_H[$p]}"; done
        return 0
    fi
    for p in "${!CH_SHA[@]}"; do
        osha="" ochg="" oseen="" obef=""
        IFS=$'\t' read -r osha ochg _ oseen obef _ <<< "${OBS_H[$p]:-}"
        if [ -z "$osha" ]; then
            NEW_H[$p]="${CH_SHA[$p]}"$'\t'-$'\t'"${CH_KEYS[$p]}"$'\t'"$PA_STAMP"$'\t'-
        elif [ "$osha" = "${CH_SHA[$p]}" ]; then
            pa_ok_field "${ochg:-}" || ochg=-
            pa_ok_field "${obef:-}" || obef=-
            NEW_H[$p]="${CH_SHA[$p]}"$'\t'"$ochg"$'\t'"${CH_KEYS[$p]}"$'\t'"$PA_STAMP"$'\t'"$obef"
        else
            pa_ok_field "${oseen:-}" || oseen=-
            NEW_H[$p]="${CH_SHA[$p]}"$'\t'"$PA_STAMP"$'\t'"${CH_KEYS[$p]}"$'\t'"$PA_STAMP"$'\t'"$oseen"
        fi
    done
    for p in "${!OBS_H[@]}"; do
        [ -z "${NEW_H[$p]:-}" ] || continue
        keep=0
        for d in "${!CH_FAILED[@]}"; do
            case "$p" in "$d"/*) keep=1 ;; esac
        done
        [ "$keep" = 0 ] || NEW_H[$p]="${OBS_H[$p]}"
    done
    H_JUDGED=1
}

# env_after_start UNIT: an env file UNIT loads changed after UNIT started. The pass that first saw
# the new value must be in this boot and no earlier than the unit's start (uptime against uptime,
# which a clock step cannot move); across a boot the unit started after the boot, so only a change
# seen after that start counts. That pass alone would not do: a unit restarted between the edit
# and it already runs with the new value. So the change counts when the last pass that saw the
# earlier value is in this boot and no earlier than the start too; and when the start falls
# between those two passes, or the earlier pass was in another boot, the file's last change (its
# ctime, a root-owned file's) against the start on the wall clock decides. A clock stepped since
# the start makes that comparison worthless: then the first pass that saw the new value decides.
env_after_start() {
    local u="$1" f start chg bef ct step=0 cs=""
    [ "${CS_ACT[$u]:-}" = active ] && [ -n "${CS_AEM[$u]:-}" ] && [ "${CS_AEM[$u]}" != 0 ] || return 1
    [ "$PA_BOOT" != - ] || return 1
    start=$((10#${CS_AEM[$u]} / 1000000))
    cs="$(_pa_meta_get clock_step)"
    if _pa_stamp_split "${cs%/*}" && [ "$_PA_B" = "$PA_BOOT" ] && [ "$((10#$_PA_U))" -ge "$start" ]; then
        step=1
    fi
    for f in ${CS_ENVF[$u]:-}; do
        [[ $f == /etc/propolis/*.env ]] || continue
        chg="" bef=""
        IFS=$'\t' read -r _ chg _ _ bef _ <<< "${NEW_H[$f]:-}"
        _pa_stamp_split "${chg:-}" && [ "$_PA_B" = "$PA_BOOT" ] && [ "$((10#$_PA_U))" -ge "$start" ] || continue
        if _pa_stamp_split "${bef:-}" && [ "$_PA_B" = "$PA_BOOT" ] && [ "$((10#$_PA_U))" -ge "$start" ]; then
            return 0
        fi
        [ "$step" = 0 ] || return 0
        ct="${CH_CTIME[$f]:-}"
        [ -n "$ct" ] || continue
        [ "$ct" -le "$((10#$PA_WALL - 10#$PA_UP + start))" ] || return 0
    done
    return 1
}

# judge_changes: change-pending (NOTICE, host) on change:<unit>, on the second hourly pass: an env
# file edited after the unit that loads it started (change.env), a unit systemd needs a daemon
# reload for (change.unit), a unit whose running binary was replaced (change.binary). Clean on two
# passes resolves it. A binary that could not be checked is unknown for a record that says it was
# replaced.
judge_changes() {
    local u key cause
    if [ "$CS_OK" != 1 ]; then
        for u in "${WITNESS_UNITS[@]}" "${WITNESS_TIMERS[@]}"; do absent_unknown "change:$u"; done
        return 0
    fi
    for u in "${WITNESS_UNITS[@]}" "${WITNESS_TIMERS[@]}"; do
        key="change:$u" cause=""
        if [ "${CS_DEL[$u]:-}" = 1 ]; then
            cause=change.binary
        elif [ "${CS_NDR[$u]:-}" = yes ]; then
            cause=change.unit
        elif env_after_start "$u"; then
            cause=change.env
        fi
        if [ -n "$cause" ]; then
            rec_attrs change-pending NOTICE host "$cause"
            PA_REC_INST="${FIDS[unit/$u]:--}"
            seen_hold "$key" ""
        elif [ "${CS_DEL[$u]:-}" = "?" ] && pa_incident_get "$key" && [ "${PA_INC[11]}" = change.binary ]; then
            absent_unknown "$key"
        else
            absent_clean "$key"
        fi
    done
}

# tie_rotation: a propolis-logrotate failure the guard refused for want of space (guard.no_space)
# takes as its parent the open volume record of the filesystem that holds the sensor logs, by the
# late-parent rule: from then on it counts nothing, and the volume's record speaks for both.
tie_rotation() {
    local key=unit:propolis-logrotate.service parent="" i
    pa_incident_get "$key" || return 0
    case "${PA_INC[7]}" in pending | open | acked) ;; *) return 0 ;; esac
    [ "${PA_INC[11]}" = guard.no_space ] && [ "${PA_INC[13]}" = - ] || return 0
    for i in "${!VOL_DEV[@]}"; do
        [ -n "${VOL_MID[$i]:-}" ] && [[ $LOG_DEVS == *" ${VOL_DEV[$i]} "* ]] || continue
        pa_incident_get "vol:${VOL_MID[$i]}" || continue
        case "${PA_INC[7]}" in
            open | acked)
                parent="${PA_INC[1]}"
                break
                ;;
        esac
    done
    [ -n "$parent" ] || return 0
    if pa_incident_fold "$key" "$parent"; then rec_set; fi
}

# judge_stores: under the lock, the stores, the rotation guard's tie, the database's state and the
# changes, and each check's result in its P line (volume, pgstate, changes), where three unknowns
# in a row open tool-unusable. Status 1 when a check could not tell on this pass.
judge_stores() {
    local bad=0
    judge_volumes
    tie_rotation
    if [ "$VOL_ALL" = 1 ]; then
        check_counts volume ok -
    else
        check_counts volume unknown "$VOL_CAUSE"
        bad=1
    fi
    judge_pgstate
    case "$PG_RESULT" in
        ok) check_counts pgstate ok - ;;
        unknown)
            check_counts pgstate unknown "$PG_CAUSE"
            bad=1
            ;;
    esac
    judge_hlines
    judge_changes
    if [ "$CS_OK" = 1 ] && [ "$CS_EXE_BLIND" = 1 ]; then
        check_counts changes unknown tool.exec
        bad=1
    elif [ "$CS_OK" = 1 ] && [ "$CH_DONE" = 1 ] && [ "${#CH_FAILED[@]}" = 0 ]; then
        check_counts changes ok -
    else
        check_counts changes unknown unknown
        bad=1
    fi
    [ "$bad" = 0 ]
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

# account_uid NAME: the uid of a local account. Status 1 only when id says there is no such
# account (its own status 1); 2 when the lookup failed otherwise (cut off by its time limit, a
# name service that did not answer) or answered out of form, since not knowing is not "none".
account_uid() {
    local u rc=0
    u="$(timeout 5 id -u -- "$1" 2> /dev/null)" || rc=$?
    case "$rc" in
        0) ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
    [[ $u =~ ^[0-9]{1,10}$ ]] || return 2
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
# pattern, and those are cut to 400 bytes a line into J_LINES. journalctl reads to the end of the
# entries either way, so a flood of other lines from the same unit costs read time, never a
# pattern line or the cursor's progress. journalctl writes its cursor into a private file, read
# back here only in a cursor's form, for jcursor_store to keep. A read that timed out or failed,
# or whose kept lines pass 1 MiB (a flood of pattern lines), is unknown for the pass and its
# cursor is not taken.
jclass_read() {
    local class="$1" mode="$2" cur tmpc tmpo st0="" st1="" c p sz
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
    # Kept lines past the cap would be cut off unseen, a writer's ERROR line after a flood of its
    # WARN lines among them: such a read is not whole, so it is unknown and its cursor not taken.
    sz="$(timeout 5 stat -c %s -- "$tmpo" 2> /dev/null)" || sz=""
    if ! [[ $sz =~ ^[0-9]{1,15}$ ]] || [ "$sz" -gt 1048576 ]; then
        check_result "journal:$class" unknown unknown
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
# delivered stamps, then the collector spools and the classes of the gateway, the shipper and
# the backup pull.
light_probes() {
    daemon_tie
    ready_probe
    jclass_read hook json _UID=0 SYSLOG_IDENTIFIER=propolis-alert
    jclass_read guard cat _SYSTEMD_UNIT=propolis-logrotate.service _UID=0
    jclass_read journald cat MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e _SYSTEMD_UNIT=systemd-journald.service _UID=0
    alertunit_read
    undelivered_count
    delivered_last
    spool_probe
    gateway_probe
    shipper_probe
    pull_probe
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

# journal_tally: the counts the walk reads, added up in meta jlines: undelivered (the legacy hook's
# two undelivered lines), journal (failure alerts that went only to the journal: alerts logged
# with no undelivered line before them), guard (the rotation guard's refusals and skips) and
# suppressed (journald's lines dropped from watched units). Each a count of lines, never their
# text. The daily message does not carry them: they are running totals, not counts of its 24
# hours, and it would need a copy kept at each send to tell them apart.
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
    for c in hook guard journald gateway shipper pull; do
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
    # The spool listing's line of the pass before, which probe_counts is about to replace.
    SPOOL_PREV="${OBS_P[spool]:-}"
    probe_counts
    judge_db
    daemon_observe
    judge_degraded
    hook_counts
    judge_alert_path
    judge_journald
    judge_spools
    judge_gateway
    judge_shipper
    judge_pull
    judge_backup_run
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

# ---- the collectors, the shipper, the gateway and the backup run (light pass) ----------------
#
# What the gateway spool holds and what the gateway, the shipper and the backup pull's forced
# command log. The spool's directory names are collector ids a remote party chose when it
# enrolled, so a name is used only once pa_plain_id takes it and PROPOLIS_SENSOR_LOGS lists that
# collector's spool, and a record or an observe line names a collector by its opaque id alone. A
# directory nobody listed is config-check's spool-unlisted finding, never a record here.

# How many spool entries one listing reads: a gateway account that makes more cannot make a pass
# read without end, and a listed collector past them is unknown for the pass (the check `spool`
# says so), never quiet and never gone.
WITNESS_SPOOL_MAX=1024
if [ -n "$ROOT" ] && [[ ${PROPOLIS_WITNESS_SPOOL_MAX:-} =~ ^[0-9]{1,4}$ ]]; then
    WITNESS_SPOOL_MAX="$((10#$PROPOLIS_WITNESS_SPOOL_MAX))"
fi
GW_SPOOL=/var/spool/propolis/gateway
COLL_TRIED=0 COLL_OK=0
declare -A CN_ID=() CN_ALL=() SL_MT=() OBS_S=() NEW_S=() SEEN_NOW=()
SL_OK=0 SL_BOUND=0 SL_TRIED=0 SL_CAUSE=unknown SPOOL_RESULT=skip SPOOL_JUDGED=0 SPOOL_PREV=""

# gw_spool_dir: GW_SPOOL, the gateway's spool from PROPOLIS_GATEWAY_SPOOL_DIR in gateway.env, its
# default when unset or out of form, as pa_vol_stores takes it. Status 1 when gateway.env cannot
# be read: where the spool is is then unknown.
gw_spool_dir() {
    GW_SPOOL=/var/spool/propolis/gateway
    pa_env_get PROPOLIS_GATEWAY_SPOOL_DIR "$PA_ENV_DIR/gateway.env" > /dev/null
    if [ -n "$PA_ENV_UNREADABLE" ]; then
        PA_ENV_VALUE=""
        return 1
    fi
    if [ "$PA_ENV_COMPLEX" = 0 ] && path_ok "$PA_ENV_VALUE"; then GW_SPOOL="$PA_ENV_VALUE"; fi
    PA_ENV_VALUE=""
    return 0
}

# collectors_load: the collectors PROPOLIS_SENSOR_LOGS lists, the ones whose path is
# `<spool>/<id>/events.jsonl` (config-check's own test of a listed spool), each with its opaque id
# in CN_ID, and every collector of the spool listing (spool_list) with its id in CN_ALL. The ids
# come from one pa_id_table call over every listed name and every name in the spool, the input the
# walk gives it too: pa_id_table widens two colliding ids within its input, so a narrower one here
# would key a collector by an id the walk does not show. COLL_OK is 1 once every collector is
# keyed. Status 1 when an env file could not be read, the spool could not be listed, or there is
# no salt yet to key an id by (the first pass of a fresh host takes the salt under the lock, after
# this has run): a collector's line can then not be told from an unlisted one's, and no spool is
# judged.
collectors_load() {
    local p cn input="" id kind name
    local -a named=()
    local -A fed=()
    COLL_TRIED=1 COLL_OK=0 CN_ID=() CN_ALL=()
    gw_spool_dir || return 1
    pa_env_get PROPOLIS_SENSOR_LOGS "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    if [ -n "$PA_ENV_UNREADABLE" ]; then
        PA_ENV_VALUE=""
        return 1
    fi
    pa_sensor_logs "$PA_ENV_VALUE"
    PA_ENV_VALUE=""
    for p in "${PA_LOG_PATH[@]}"; do
        case "$p" in "$GW_SPOOL"/*/events.jsonl) ;; *) continue ;; esac
        cn="${p#"$GW_SPOOL"/}"
        cn="${cn%/events.jsonl}"
        pa_plain_id "$cn" || continue
        named+=("$cn")
    done
    spool_list
    [ "$SL_OK" = 1 ] || return 1
    for cn in "${named[@]}" "${!SL_MT[@]}"; do
        [ -z "${fed[$cn]:-}" ] || continue
        fed[$cn]=1
        input+="collector"$'\t'"$cn"$'\n'
    done
    if [ -n "$input" ]; then
        while IFS=$'\t' read -r id kind name; do
            [ "$kind" = collector ] && [[ $id =~ ^c[0-9a-f]{5,8}$ ]] && pa_plain_id "$name" && CN_ALL[$name]="$id"
        done < <(printf '%s' "$input" | pa_id_table 2> /dev/null)
        [ "${#CN_ALL[@]}" = "${#fed[@]}" ] || return 1
    fi
    for cn in "${named[@]}"; do CN_ID[$cn]="${CN_ALL[$cn]}"; done
    COLL_OK=1
    return 0
}

# spool_list: the spool file of each collector directory in GW_SPOOL, `<id>/events.jsonl`, with its
# modification time in whole seconds in SL_MT, by one find, NUL-separated, read as the gateway
# account when the spool is that account's (it can put a link or a FIFO where root would then
# look), at most WITNESS_SPOOL_MAX entries: a collector past them is missing from SL_MT, and
# SL_BOUND says so, so that a missing collector is unknown rather than one with no spool file.
# Only names pa_plain_id takes are kept. SL_OK is 1 when the listing completed, reached its bound
# or found no spool at all; SL_CAUSE says why not.
spool_list() {
    local dir="$ROOT$GW_SPOOL" as="" owner gw ent t rest cn n=0 st=""
    SL_OK=0 SL_BOUND=0 SL_TRIED=1 SL_CAUSE=unknown SL_MT=()
    if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
        SL_OK=1
        return 0
    fi
    [ -d "$dir" ] && [ ! -L "$dir" ] || return 0
    fits 25 || return 0
    owner="$(timeout 5 stat -c %u -- "$dir" 2> /dev/null)" || return 0
    [[ $owner =~ ^[0-9]{1,10}$ ]] || return 0
    if gw="$(account_uid propolis-gateway)" && [ "$((10#$owner))" = "$gw" ]; then as=propolis-gateway; fi
    while IFS= read -r -d '' ent; do
        # A name holds no slash: the status line can never be an entry's.
        case "$ent" in
            /status=*)
                st="${ent#/status=}"
                continue
                ;;
        esac
        n=$((n + 1))
        if [ "$n" -gt "$WITNESS_SPOOL_MAX" ]; then
            st=bound
            break
        fi
        t="${ent%% *}" rest="${ent#* }"
        [[ $t =~ ^([0-9]{1,12})(\.[0-9]*)?$ ]] || continue
        t="${BASH_REMATCH[1]}"
        cn="${rest%/events.jsonl}"
        if [ "$rest" = "$cn/events.jsonl" ] && pa_plain_id "$cn"; then SL_MT[$cn]=$((10#$t)); fi
    done < <(
        if [ -n "$as" ]; then
            _pa_as_t 10 "$as" find "$dir" -mindepth 2 -maxdepth 2 -name events.jsonl -type f -printf '%T@ %P\0'
        else
            timeout 10 find "$dir" -mindepth 2 -maxdepth 2 -name events.jsonl -type f -printf '%T@ %P\0' 2> /dev/null
        fi
        printf '/status=%s\0' "$?"
    )
    case "$st" in
        0) SL_OK=1 ;;
        bound) SL_OK=1 SL_BOUND=1 ;;
        126 | 127) SL_CAUSE=tool.exec ;;
    esac
    [ "$SL_OK" = 1 ] || SL_MT=()
}

# spool_probe: on a control node or a gateway, the listed collectors and their spool files, before
# the lock. The listing's result is the check `spool`: unknown too when it reached its bound
# before a listed collector, though the collectors it did reach are still judged.
spool_probe() {
    local cn
    SPOOL_RESULT=skip
    case "${PA_ROLE:-}" in control | gateway) ;; *) return 0 ;; esac
    SPOOL_RESULT=unknown
    if ! fits 25; then
        check_result spool unknown unknown
        return 0
    fi
    SL_TRIED=0
    if ! collectors_load; then
        if [ "$SL_TRIED" = 1 ] && [ "$SL_OK" != 1 ]; then
            check_result spool unknown "$SL_CAUSE"
        else
            check_result spool unknown unknown
        fi
        return 0
    fi
    SPOOL_RESULT=ok
    if [ "$SL_BOUND" = 1 ]; then
        for cn in "${!CN_ID[@]}"; do
            if [ -z "${SL_MT[$cn]:-}" ]; then
                check_result spool unknown unknown
                return 0
            fi
        done
    fi
    check_result spool ok -
}

# gateway_probe, shipper_probe, pull_probe: the journal classes of the gateway's duplicate line, the
# shipper's ERROR and WARN lines and the backup pull's served line, each read by the uid of its
# account (journald takes it from the socket's credentials, so no other account can write as
# that one) and its unit or the serve script's fixed identifier. Each runs only where its writer
# is: the gateway unit known to systemd; on a collector, the shipper unit; the serve script
# installed. An account that does not exist skips its class.
gateway_probe() {
    local u=gateway.service uid
    [ "$SAMPLE_OK" = 1 ] && [ -n "${S_LOAD[$u]:-}" ] && [ "${S_LOAD[$u]}" != not-found ] \
        && [ "${S_LOAD[$u]}" != "?" ] || return 0
    if ! fits 50; then
        check_result journal:gateway unknown unknown
        return 0
    fi
    uid="$(account_uid propolis-gateway)" || return 0
    [ "$COLL_TRIED" = 1 ] || collectors_load || true
    # Until the collectors are keyed a listed collector's line cannot be told from an unlisted
    # one's: the class waits, its cursor where it was, for a pass that can read it whole.
    if [ "$COLL_OK" != 1 ]; then
        check_result journal:gateway unknown unknown
        return 0
    fi
    jclass_read gateway cat _SYSTEMD_UNIT=gateway.service "_UID=$uid"
}

shipper_probe() {
    local u=shipper.service uid
    [ "${PA_ROLE:-}" = collector ] || return 0
    [ "$SAMPLE_OK" = 1 ] && [ -n "${S_LOAD[$u]:-}" ] && [ "${S_LOAD[$u]}" != not-found ] \
        && [ "${S_LOAD[$u]}" != "?" ] || return 0
    if ! fits 50; then
        check_result journal:shipper unknown unknown
        return 0
    fi
    uid="$(account_uid propolis-shipper)" || return 0
    jclass_read shipper cat _SYSTEMD_UNIT=shipper.service "_UID=$uid"
}

pull_probe() {
    local uid
    case "${PA_ROLE:-}" in collector | gateway) return 0 ;; esac
    [ -f "$ROOT/usr/local/sbin/propolis-backup-serve" ] || return 0
    if ! fits 50; then
        check_result journal:pull unknown unknown
        return 0
    fi
    uid="$(account_uid propolis-backup-pull)" || return 0
    jclass_read pull cat "_UID=$uid" SYSLOG_IDENTIFIER=propolis-backup-serve
}

# judge_spools: spool-quiet (ACT, the ship stage) on spool:<collector id> for a listed collector
# whose spool was last written longer ago than max(1800 s, twice the longest gap between two of
# its writes in the current week), on two passes in a row. The week must be at least a day old,
# or follow a week whose longest gap is known: one night of a quiet honeypot is not a fault. Not
# opened while the gateway has been up under fifteen minutes (it has not heard from a collector
# yet), nor under a maintenance marker whose reason is manual, which is how an operator says a
# collector is off on purpose; such a sighting waits, pending. The spool written on two passes in
# a row resolves it (spool2); a collector taken off the list resolves disabled. A listing that
# could not be made judges nothing, nor does one that reached its bound before a collector: a
# pending record is dropped and an open one stays. A collector whose spool file is gone (the
# gateway makes it again only on the next batch it accepts) is judged from the last write its S
# line holds; one never written has nothing to judge. A modification time ahead of the clock is
# no write this pass can place: neither quiet nor an advance, it leaves the S line as it was, so
# one bad time cannot widen the week's longest gap and blind the threshold. For the same reason
# the longest gap takes only a gap nobody was told of, seen from one pass to the next: the write
# that ends a quiet time whose record is pending or open is not learnt, nor is the first write
# seen after passes that did not list the spool.
judge_spools() {
    local cn cid key line lastm lastadv maxgap ws prevgap advn mt wsage quiet eff thr gap ok hold=""
    local watched=0 pst pres learn
    local -A listed=()
    local -a keys=()
    [ "$SPOOL_RESULT" != skip ] || return 0
    # Whether the pass before listed the spool too (its line of the check `spool`, as it was
    # before this pass counted its own): only then does the distance between two writes say how
    # long a collector was quiet, and not how long nobody looked.
    IFS=$'\t' read -r pst pres _ <<< "$SPOOL_PREV"
    if [ "${pres:-}" = ok ] && _pa_stamp_split "${pst:-}"; then
        gap="$(pa_age "$pst")"
        if [ "$gap" -ge 0 ] && [ "$gap" -le 900 ]; then watched=1; fi
    fi
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        [[ $key == spool:* ]] && keys+=("$key")
    done
    if [ "$SPOOL_RESULT" != ok ]; then
        for key in "${keys[@]}"; do absent_unknown "$key"; done
        return 0
    fi
    unit_facts gateway.service
    if [ "$F_ACTIVE" != active ] || [ "$F_UP" = - ] || [ "$F_UP" -lt 900 ]; then hold=gateway; fi
    if [ "$MAINT" = 1 ] && [ "$MAINT_REASON" = manual ]; then hold=maint; fi
    for cn in "${!CN_ID[@]}"; do
        cid="${CN_ID[$cn]}" key="spool:${CN_ID[$cn]}"
        listed[$cid]=1
        lastm="" lastadv="" maxgap="" ws="" prevgap="" advn=""
        IFS=$'\t' read -r lastm lastadv maxgap ws prevgap advn _ <<< "${OBS_S[$cid]:-}"
        mt="${SL_MT[$cn]:-}"
        # Past the listing's bound a collector is unknown, not gone, and one never written has
        # nothing to judge it by; one whose spool file is gone is quiet since the last write seen.
        if [ -z "$mt" ] && { [ "$SL_BOUND" = 1 ] || ! [[ $lastm =~ ^[0-9]{1,12}$ ]]; }; then
            [ -z "${OBS_S[$cid]:-}" ] || NEW_S[$cid]="${OBS_S[$cid]}"
            absent_unknown "$key"
            continue
        fi
        [ -n "$mt" ] || mt=$((10#$lastm))
        # A time ahead of the clock is no write this pass can place: neither quiet nor an advance.
        if [ "$mt" -gt "$((10#$PA_WALL + 300))" ]; then
            [ -z "${OBS_S[$cid]:-}" ] || NEW_S[$cid]="${OBS_S[$cid]}"
            two_pass "$key" 0 ""
            continue
        fi
        if [[ $lastm =~ ^[0-9]{1,12}$ ]]; then lastm=$((10#$lastm)); else lastm=""; fi
        if [[ $maxgap =~ ^[0-9]{1,12}$ ]]; then maxgap=$((10#$maxgap)); else maxgap=0; fi
        if [[ $prevgap =~ ^[0-9]{1,12}$ ]]; then prevgap=$((10#$prevgap)); else prevgap=-; fi
        if [[ $advn =~ ^[0-9]{1,9}$ ]]; then advn=$((10#$advn)); else advn=0; fi
        _pa_stamp_split "$lastadv" || lastadv=-
        # A window whose start cannot be read, or lies ahead of the clock, starts again now.
        if ! _pa_stamp_split "$ws" || [ "$(pa_age "$ws")" -lt 0 ]; then
            ws="$PA_STAMP" maxgap=0 prevgap=-
        fi
        wsage="$(pa_age "$ws")"
        if [ "$wsage" -gt 604800 ]; then
            prevgap="$maxgap" maxgap=0 ws="$PA_STAMP" wsage=0
        fi
        if [ -z "$lastm" ]; then
            lastm="$mt" lastadv="$PA_STAMP" advn=0
        elif [ "$mt" -gt "$lastm" ]; then
            gap=$((mt - lastm))
            # No gap is longer than the window it is kept for.
            [ "$gap" -le 604800 ] || gap=604800
            # A gap is learnt only as a quiet time nobody was told of: not one whose record is
            # pending or open (an outage would raise the threshold its successor is held to), and
            # not one that spans a time the spool was not listed.
            learn="$watched"
            if pa_incident_get "$key"; then
                case "${PA_INC[7]}" in pending | open | acked) learn=0 ;; esac
            fi
            [ "$learn" = 0 ] || [ "$gap" -le "$maxgap" ] || maxgap="$gap"
            lastm="$mt" lastadv="$PA_STAMP" advn=$((advn + 1))
            [ "$advn" -le 999999 ] || advn=999999
        else
            [ "$mt" -ge "$lastm" ] || lastm="$mt"
            advn=0
        fi
        NEW_S[$cid]="$lastm"$'\t'"$lastadv"$'\t'"$maxgap"$'\t'"$ws"$'\t'"$prevgap"$'\t'"$advn"
        ok=0 eff="$maxgap"
        [ "$wsage" -lt 86400 ] || ok=1
        if [ "$wsage" -lt 86400 ] && [ "$prevgap" != - ]; then
            ok=1
            [ "$prevgap" -le "$eff" ] || eff="$prevgap"
        fi
        # A modification time ahead of the clock is never quiet.
        quiet=$((10#$PA_WALL - mt))
        thr=$((2 * eff))
        [ "$thr" -ge 1800 ] || thr=1800
        rec_attrs spool-quiet ACT ship spool.quiet
        PA_REC_INST="$cid"
        if [ "$ok" = 1 ] && [ "$quiet" -gt "$thr" ]; then
            two_pass "$key" 1 "$hold"
        else
            two_pass "$key" 0 ""
            [ "$advn" -lt 2 ] || resolve_if "$key" 1 spool2
        fi
    done
    for key in "${keys[@]}"; do
        [ -z "${listed[${key#spool:}]:-}" ] || continue
        pa_incident_get "$key" || continue
        case "${PA_INC[7]}" in
            open | acked)
                PA_REC_PROOF=disabled
                pa_incident_transition "$key" resolve && rec_set
                ;;
            pending) pa_incident_transition "$key" drop && rec_set ;;
        esac
    done
    SPOOL_JUDGED=1
}

# quiet24_sweep PREFIX: the open records whose key starts with PREFIX and whose line was not seen
# on this pass resolve quiet24 once a day has passed since the last pass that saw it (OBS_P
# seen:<key>, else when it opened); a time that cannot be read is never a day ago. A seen line
# whose record is no longer open goes.
quiet24_sweep() {
    local prefix="$1" line key s a
    local -a keys=()
    for line in "${_PA_INC_I[@]}"; do
        IFS=$'\t' read -r _ _ key _ <<< "$line"
        [[ $key == "$prefix"* ]] && keys+=("$key")
    done
    for key in "${keys[@]}"; do
        [ -z "${SEEN_NOW[$key]:-}" ] || continue
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
        [[ $key == "seen:$prefix"* ]] || continue
        if pa_incident_get "${key#seen:}"; then
            case "${PA_INC[7]}" in open | acked) continue ;; esac
        fi
        unset 'OBS_P[$key]'
    done
}

# seen_count KEY N: KEY's line seen on this pass, with N more records counted lost since its open
# (the earlier count kept while the record stays open).
seen_count() {
    local prev=0 c
    if pa_incident_get "$1"; then
        case "${PA_INC[7]}" in
            open | acked)
                IFS=$'\t' read -r _ _ _ c _ <<< "${OBS_P[seen:$1]:-}"
                [[ ${c:-} =~ ^[0-9]{1,9}$ ]] && prev=$((10#$c))
                ;;
        esac
    fi
    prev=$((prev + $2))
    [ "$prev" -le 999999999 ] || prev=999999999
    SEEN_NOW[$1]=1
    OBS_P[seen:$1]="$PA_STAMP"$'\t'ok$'\t'-$'\t'"$prev"
}

# judge_gateway: gateway-dup (ACT, the gateway stage) on first sight of the gateway's line that a
# batch reused the last accepted sequence number with other content and was not stored. Its
# collector_id names the record only when it is a listed collector (gwdup:<opaque id>); any other
# is gwdup:unlisted. The two counts after the fixed keys records= and suppressed_records= are read
# as digits alone and summed for the walk, an upper bound of the evidence lost. A day without the
# line resolves it quiet24. No part of a line is kept.
judge_gateway() {
    local line rest cn r s key pat
    local -a pats=()
    local -A lost=() inst=()
    [ "${J_RESULT[gateway]:-}" = ok ] || return 0
    mapfile -t pats < <(pa_journal_patterns gateway)
    pat="${pats[0]:-}"
    [ -n "$pat" ] || return 0
    while IFS= read -r line; do
        [[ $line == *"$pat"* ]] || continue
        rest="${line#*"$pat"}"
        cn="" r=0 s=0
        if [[ $rest =~ (^|[[:space:]])collector_id=([^[:space:]]{1,64})([[:space:]]|$) ]]; then cn="${BASH_REMATCH[2]}"; fi
        if [[ $rest =~ [[:space:]]records=([0-9]{1,9})([[:space:]]|$) ]]; then r=$((10#${BASH_REMATCH[1]})); fi
        if [[ $rest =~ [[:space:]]suppressed_records=([0-9]{1,9})([[:space:]]|$) ]]; then s=$((10#${BASH_REMATCH[1]})); fi
        key=gwdup:unlisted
        if [ -n "$cn" ] && pa_plain_id "$cn" && [ -n "${CN_ID[$cn]:-}" ]; then
            key="gwdup:${CN_ID[$cn]}"
            inst[$key]="${CN_ID[$cn]}"
        fi
        lost[$key]=$((${lost[$key]:-0} + r + s))
        [ "${lost[$key]}" -le 999999999 ] || lost[$key]=999999999
    done <<< "${J_LINES[gateway]}"
    for key in "${!lost[@]}"; do
        rec_attrs gateway-dup ACT gateway gw.dup
        PA_REC_INST="${inst[$key]:--}"
        seen_count "$key" "${lost[$key]}"
        pa_incident_transition "$key" open && rec_set
    done
    quiet24_sweep gwdup:
}

# judge_shipper: on a collector, the shipper's ERROR lines on three light passes in a row open
# ship-failing (ACT, ship:local), its cause the worst of them (a rejected batch, a chain that
# diverged or the line before an exit on a permanent stop, ship.rejected; a failed cycle, a batch
# that cannot be recorded in the state directory or a gateway that keeps answering Retry, ship.io;
# a failed connection, ship.connect); two passes without one resolve it clean2. Its WARN lines (lines it dropped) open the NOTICE ship-dropped on
# first sight, resolved quiet24. An ERROR line whose message also says the shipper refuses to
# start is the unit kinds' to report, not counted. A read that could not tell counts toward
# neither.
#
# A line is classed by the head the log format writes before anything else (time, level,
# target) and by its message's own words, never by its fields: the policy line's error quotes the
# sensor name or protocol a refused line claimed, which whoever writes that sensor's log chooses.
# So an ERROR text counts only on an ERROR line and a WARN text only on a WARN line, and only
# where no `=` or double quote comes before it in the message: every field follows a `key=`
# (an apostrophe may: one of the messages has one before its matched words).
judge_shipper() {
    local line i e=0 w=0 c="" n st=none lvl msg idx re='^[^ ]+ +(ERROR|WARN) +[A-Za-z0-9_:]+: (.*)$'
    local -a pats=()
    case "${J_RESULT[shipper]:-}" in
        ok) ;;
        unknown)
            unset 'OBS_P[shipfail]'
            absent_unknown ship:local
            return 0
            ;;
        *) return 0 ;;
    esac
    mapfile -t pats < <(pa_journal_patterns shipper)
    [ "${#pats[@]}" -ge 10 ] || return 0
    while IFS= read -r line; do
        [[ $line =~ $re ]] || continue
        lvl="${BASH_REMATCH[1]}" msg="${BASH_REMATCH[2]}"
        if [ "$lvl" = ERROR ]; then
            [[ ${msg%%=*} != *'refusing to start'* ]] || continue
            idx="0 1 2 3 4 5 6"
        else
            idx="7 8 9"
        fi
        for i in $idx; do
            [[ $msg == *"${pats[$i]}"* ]] && [[ ${msg%%"${pats[$i]}"*} != *[=\"]* ]] || continue
            case "$i" in
                0)
                    e=$((e + 1))
                    [ -n "$c" ] || c=ship.connect
                    ;;
                1 | 2 | 3)
                    e=$((e + 1))
                    [ "$c" = ship.rejected ] || c=ship.io
                    ;;
                4 | 5 | 6) e=$((e + 1)) c=ship.rejected ;;
                *) w=$((w + 1)) ;;
            esac
            break
        done
    done <<< "${J_LINES[shipper]}"
    rec_attrs ship-failing ACT ship "${c:-ship.connect}"
    if pa_incident_get ship:local; then st="${PA_INC[7]}"; fi
    if [ "$e" -gt 0 ]; then
        streak shipfail error
        n="$STREAK_N"
        case "$st" in
            none | resolved | pending)
                if [ "$st" = pending ] && [ "$n" -ge 3 ]; then
                    pa_incident_transition ship:local open && rec_set
                else
                    pa_incident_transition ship:local pending && rec_set
                fi
                ;;
            open | acked) pa_incident_transition ship:local change && rec_set ;;
        esac
    else
        streak shipfail ok
        n="$STREAK_N"
        case "$st" in
            pending) pa_incident_transition ship:local drop && rec_set ;;
            open | acked) [ "$n" -lt 2 ] || resolve_if ship:local 1 clean2 ;;
        esac
    fi
    if [ "$w" -gt 0 ]; then
        rec_attrs ship-dropped NOTICE ship ship.dropped
        seen_count shipdrop:local 0
        pa_incident_transition shipdrop:local open && rec_set
    fi
    quiet24_sweep shipdrop:
}

PULL_NEW=""

# judge_pull: the backup pull's served line, in the exact form deploy/backup-serve.sh logs it, sets
# meta pull_last to this pass's stamp: the off-host copy was taken at most a pass ago.
judge_pull() {
    local line re='^served [0-9]{8}T[0-9]{6}Z-(scheduled|pre-upgrade) (propolis\.dump\.age|state\.tgz\.age|SHA256SUMS)$'
    [ "${J_RESULT[pull]:-}" = ok ] || return 0
    while IFS= read -r line; do
        if [[ $line =~ $re ]]; then
            PULL_NEW="$PA_STAMP"
            break
        fi
    done <<< "${J_LINES[pull]}"
}

META_BACKUP_DUR="" BACKUP_DUR_NEW=""

# judge_backup_run: backup-hung (ACT, the backup rail, backup:run) when propolis-backup.service has
# been activating for longer than max(7200 s, three times the last run's length) on two light
# passes in a row; resolved `ended` once it is no longer activating. The last run's length (meta
# backup_dur, BACKUP_DUR_NEW) is taken on each pass that sees the unit inactive with an exit after
# its start. The unit's TimeoutStartSec (six hours as shipped) still ends a run that never
# finishes; this says so earlier while the usual run is short, by four hours at most, and not at
# all once the usual run takes two hours, when three times its length is that timeout. A start
# time that cannot be read, lies ahead of the uptime, or belongs to a process that has already
# exited says nothing.
judge_backup_run() {
    local u=propolis-backup.service ems eme age lim=7200 dur
    [ "$SAMPLE_OK" = 1 ] && [ -n "${S_LOAD[$u]:-}" ] && [ "${S_LOAD[$u]}" != not-found ] \
        && [ "${S_LOAD[$u]}" != "?" ] || return 0
    ems="${S_EMS[$u]:-}" eme="${S_EME[$u]:-}"
    rec_attrs backup-hung ACT backup backup.long
    if [ "${S_ACT[$u]:-}" != activating ]; then
        if [ "${S_ACT[$u]:-}" = inactive ] && [[ $ems =~ ^[0-9]{1,18}$ && $eme =~ ^[0-9]{1,18}$ ]] \
            && [ "$((10#$ems))" -gt 0 ] && [ "$((10#$eme))" -gt "$((10#$ems))" ]; then
            BACKUP_DUR_NEW=$(((10#$eme - 10#$ems) / 1000000))
        fi
        two_pass backup:run 0 ""
        resolve_if backup:run 1 ended
        return 0
    fi
    if ! [[ $ems =~ ^[0-9]{1,18}$ ]] || [ "$((10#$ems))" = 0 ] || [ "$((10#$ems / 1000000))" -gt "$((10#$PA_UP))" ]; then
        two_pass backup:run 0 ""
        return 0
    fi
    # An exit later than the start with no main process: that process has ended, so the start is
    # not this run's main command's (it has not started, or has finished, and a command a drop-in
    # runs before or after it is still going). It says nothing of how long this run has taken.
    # With a main process running, the start is its own whatever the exit says.
    if [ -z "${S_PID[$u]:-}" ] && [[ $eme =~ ^[0-9]{1,18}$ ]] && [ "$((10#$eme))" -gt "$((10#$ems))" ]; then
        two_pass backup:run 0 ""
        return 0
    fi
    age=$((10#$PA_UP - 10#$ems / 1000000))
    if [[ $META_BACKUP_DUR =~ ^[0-9]{1,9}$ ]]; then
        dur=$((10#$META_BACKUP_DUR))
        [ "$((3 * dur))" -le "$lim" ] || lim=$((3 * dur))
    fi
    if [ "$age" -gt "$lim" ]; then
        two_pass backup:run 1 ""
    else
        two_pass backup:run 0 ""
    fi
}

# ---- the public push and the backups (hourly pass) -------------------------------------------
#
# Read before the lock, judged under it like the stores. The backup status files are root's own;
# the push marker belongs to the propolis-blocklist account (blocklist-sync.sh writes it), and
# root reads only its modification time, without following a link and only when it is a regular
# file. The feed's publish marker lies in the daemon account's directory and the pull account's
# authorized_keys in that account's, so each is read as its account.

PUSH_RESULT=skip PUSH_CAUSE=unknown PUSH_SCHED=none PUSH_MT="" PUB_MT="" PUSH_EXPECTED=0 FEED_ON=1
META_PUSH_SINCE="" PUSH_SINCE_NEW=""

# What push_read runs as the daemon account for the publish marker: stat without following a link,
# a path that is not there (status 2) told from one that could not be checked (status 1).
# shellcheck disable=SC2016 # the child bash expands these, with the path as $1
PUB_STAT_PROG='s="$(LC_ALL=C stat -c "%F|%Y" -- "$1" 2>&1)" && { printf "%s" "$s"; exit 0; }; case "$s" in *"No such file or directory"*) exit 2 ;; esac; exit 1'

# push_read: on a single box or a control node, whether anything runs the push (pa_push_scheduler,
# the rule the walk shows), the push marker's time (blocklist-status/last-pushed, the
# propolis-blocklist account's, its mtime alone read, not through a link), the
# feed's publish marker's time (`.<name>.last_published` beside PROPOLIS_FEED_OUTPUT_DIR, as the
# daemon writes it, read as the daemon account), PROPOLIS_FEED_ENABLED (default true, as the daemon
# reads it: true or false in any case, anything else the default) and
# PROPOLIS_OPS_FEED_PUSH_EXPECTED (default false; true, 1, yes or on). A marker that is missing is
# no time (PUSH_MT or PUB_MT empty); one that is not a regular file, or a read that failed, makes
# the check unknown for the pass.
push_read() {
    local f out rc dir name parent v
    PUSH_RESULT=skip
    # Only a host that runs the daemon publishes a feed to push.
    case "${PA_ROLE:-}" in single | control) ;; *) return 0 ;; esac
    PUSH_RESULT=unknown PUSH_CAUSE=unknown PUSH_MT="" PUB_MT=""
    pa_env_get PROPOLIS_FEED_ENABLED "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    [ -z "$PA_ENV_UNREADABLE" ] || return 0
    FEED_ON=1
    case "${PA_ENV_VALUE,,}" in false) FEED_ON=0 ;; esac
    pa_env_get PROPOLIS_OPS_FEED_PUSH_EXPECTED "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    v="${PA_ENV_VALUE,,}"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    PUSH_EXPECTED=0
    case "$v" in true | 1 | yes | on) PUSH_EXPECTED=1 ;; esac
    pa_env_get PROPOLIS_FEED_OUTPUT_DIR "$PA_ENV_DIR/fleet-listeners.env" "$PA_ENV_DIR/propolis.env" > /dev/null
    dir="${PA_ENV_VALUE:-/var/lib/propolis/feed/current}"
    PA_ENV_VALUE=""
    while [ "${#dir}" -gt 1 ] && [ "${dir%/}" != "$dir" ]; do dir="${dir%/}"; done
    path_ok "$dir" || return 0
    # The scheduler's reads have limits of their own, 5 s for each crontab or unit file and 10 s
    # for each timer: a minute covers a host's few files.
    fits 60 || return 0
    rc=0
    pa_push_scheduler > /dev/null || rc=$?
    PUSH_SCHED="$PA_SCHED"
    if [ "$rc" != 0 ] && [ "$PUSH_SCHED" = none ]; then return 0; fi
    f="$ROOT/var/lib/propolis/blocklist-status/last-pushed"
    if [ -e "$f" ] || [ -L "$f" ]; then
        [ -f "$f" ] && [ ! -L "$f" ] || return 0
        fits 5 || return 0
        out="$(timeout 5 stat -c %Y -- "$f" 2> /dev/null)" || return 0
        [[ $out =~ ^[0-9]{1,12}$ ]] || return 0
        PUSH_MT=$((10#$out))
    fi
    name="${dir##*/}" parent="${dir%/*}"
    [ -n "$parent" ] || parent=/
    [ -n "$name" ] || name=feed
    fits 10 || return 0
    out="$(_pa_as propolis bash -c "$PUB_STAT_PROG" _ "$ROOT${parent%/}/.$name.last_published")"
    rc=$?
    case "$rc" in
        0)
            [[ $out =~ ^regular(\ empty)?\ file\|([0-9]{1,12})$ ]] || return 0
            PUB_MT=$((10#${BASH_REMATCH[2]}))
            ;;
        2) ;;
        *) return 0 ;;
    esac
    PUSH_RESULT=ok PUSH_CAUSE=-
}

# judge_push: under the lock, the push's three kinds, each on the second hourly pass in a row.
# push-failing (ACT, the publish stage, push:<cron|timer>): a scheduler runs the push, the feed was
# published after the last push and that push is over six hours old; or there is no push marker,
# the scheduler has been seen for over six hours (meta push_sched_since) and a publish came after
# it was first seen. Six hours, not the daemon's half hour: the witness speaks where the daemon
# cannot, and a short outage of the remote is no page. A feed that did not change since the last
# push is not stale. Its onset is the push marker's time, and a push after that onset resolves it
# (pushed); a push moved to the other scheduler while it fails stays on the record already open,
# and one whose scheduler is gone resolves `disabled`, since no push can come to resolve it.
# push-unscheduled (ACT, push:none): the feed is on, a push is expected
# (PROPOLIS_OPS_FEED_PUSH_EXPECTED) and nothing runs it. push-off (NOTICE, push:off): the feed is on,
# nothing runs the push, and none is expected. Those two resolve clean2. Status 1 when the reads
# could not tell.
judge_push() {
    local fail=0 sched key k since sw carrier
    [ "$PUSH_RESULT" != skip ] || return 0
    if [ "$PUSH_RESULT" != ok ]; then
        for k in push:cron push:timer push:none push:off; do absent_unknown "$k"; done
        check_counts push unknown "$PUSH_CAUSE"
        return 1
    fi
    check_counts push ok -
    sched="$PUSH_SCHED"
    PUSH_SINCE_NEW=-
    if [ "$sched" != none ]; then
        since="$META_PUSH_SINCE"
        if ! _pa_stamp_split "$since" || [ "$(pa_age "$since")" -lt 0 ]; then since="$PA_STAMP"; fi
        PUSH_SINCE_NEW="$since"
        if [ -n "$PUSH_MT" ]; then
            if [ -n "$PUB_MT" ] && [ "$PUB_MT" -gt "$PUSH_MT" ] && [ "$((10#$PA_WALL - PUSH_MT))" -gt 21600 ]; then fail=1; fi
        else
            _pa_stamp_split "$since"
            sw="$((10#$_PA_W))"
            if [ "$(pa_age "$since")" -gt 21600 ] && [ -n "$PUB_MT" ] && [ "$PUB_MT" -gt "$sw" ]; then fail=1; fi
        fi
    fi
    # A push that keeps failing while the operator moves it from cron to a timer, or back, is one
    # fault: an open record on the other scheduler's key goes on carrying it.
    carrier=""
    if [ "$fail" = 1 ]; then
        carrier="$sched"
        if ! pa_incident_get "push:$sched" || [ "${PA_INC[7]}" = resolved ]; then
            for k in cron timer; do
                if [ "$k" != "$sched" ] && pa_incident_get "push:$k"; then
                    case "${PA_INC[7]}" in open | acked) carrier="$k" ;; esac
                fi
            done
        fi
    fi
    for k in cron timer; do
        key="push:$k"
        if [ "$k" = "$carrier" ]; then
            rec_attrs push-failing ACT publish push.stale
            seen_hold "$key" ""
            # A new sighting's onset is the last push: the time the public copy stopped moving.
            if [ -n "$PUSH_MT" ] && pa_incident_get "$key" && [ "${PA_INC[7]}" = pending ] \
                && [ "${PA_INC[10]}" = "$PA_STAMP" ]; then
                PA_INC[10]="$PUSH_MT/-/0"
                rec_set
            fi
            continue
        fi
        pa_incident_get "$key" || continue
        case "${PA_INC[7]}" in
            pending) pa_incident_transition "$key" drop && rec_set ;;
            open | acked)
                if [ -n "$PUSH_MT" ] && _pa_stamp_split "${PA_INC[10]}" && [ "$PUSH_MT" -gt "$((10#$_PA_W))" ]; then
                    PA_REC_PROOF=pushed
                    pa_incident_transition "$key" resolve && rec_set
                elif [ "$sched" = none ]; then
                    # Nothing runs the push any more, so no push can come to resolve this: that
                    # none is scheduled is the two kinds' below to say.
                    PA_REC_PROOF=disabled
                    pa_incident_transition "$key" resolve && rec_set
                fi
                ;;
        esac
    done
    if [ "$sched" = none ] && [ "$FEED_ON" = 1 ] && [ "$PUSH_EXPECTED" = 1 ]; then
        rec_attrs push-unscheduled ACT publish push.none
        seen_hold push:none ""
    else
        absent_clean push:none
    fi
    if [ "$sched" = none ] && [ "$FEED_ON" = 1 ] && [ "$PUSH_EXPECTED" = 0 ]; then
        rec_attrs push-off NOTICE publish push.none
        seen_hold push:off ""
    else
        absent_clean push:off
    fi
    return 0
}

BK_DIR=/var/backups/propolis BK_KEEP=7 BK_KNOWN=0 BACKUP_DEV="" BACKUP_STEP=""
BKS_RESULT=skip BKS_N=0 BKS_OLDEST="" PULL_CONF="" META_PULL_LAST=""
BKS_NAMES=() SERVE_OLD=0 META_PULL_SINCE="" PULL_SINCE_NEW=""

# backup_learn: the backup directory and the number of scheduled sets to keep, from the backup
# unit's Environment property (deploy/backup.sh takes both from its environment, so a drop-in is
# where an operator sets them): the last PROPOLIS_BACKUP_DIR in path_ok's form, else
# /var/backups/propolis, as pa_vol_stores takes it; the last PROPOLIS_BACKUP_KEEP from 1 to 365,
# else 7, as backup.sh would refuse anything else. BK_KNOWN is 0 when systemd did not answer.
backup_learn() {
    local w d="" k=""
    local -a words=()
    BK_DIR=/var/backups/propolis BK_KEEP=7 BK_KNOWN=0
    [ "$CS_OK" = 1 ] || return 0
    read -r -a words <<< "$CS_BACKUP_ENV" || true
    for w in "${words[@]}"; do
        case "$w" in
            PROPOLIS_BACKUP_DIR=*) d="${w#PROPOLIS_BACKUP_DIR=}" ;;
            PROPOLIS_BACKUP_KEEP=*) k="${w#PROPOLIS_BACKUP_KEEP=}" ;;
        esac
    done
    ! path_ok "$d" || BK_DIR="$d"
    if [[ $k =~ ^[0-9]{1,3}$ ]] && [ "$((10#$k))" -ge 1 ] && [ "$((10#$k))" -le 365 ]; then BK_KEEP=$((10#$k)); fi
    BK_KNOWN=1
}

# backup_read: on a single box or a control node, the scheduled sets in the backup directory, only
# names of the exact shape deploy/backup.sh prunes (`<YYYYMMDD>T<HHMMSS>Z-scheduled`), NUL-separated
# and at most 4096 entries, with the oldest one's date and each one's time as its name gives it
# (BKS_*); and whether an off-host pull is
# configured (PULL_CONF 1: a line that is not a comment in the pull account's authorized_keys, read
# as that account with a size cap; 0: no such account, file or line; empty: it could not be read).
# SERVE_OLD is 1 when a pull is configured and the installed serve script is one that does not log
# its served line: there is then nothing to count an unserved set from.
backup_read() {
    local dir ent n=0 sets=0 oldest="" st="" t f text rc line
    BKS_RESULT=skip PULL_CONF="" BKS_NAMES=() SERVE_OLD=0
    case "${PA_ROLE:-}" in collector | gateway) return 0 ;; esac
    BKS_RESULT=unknown
    dir="$ROOT$BK_DIR"
    if [ "$BK_KNOWN" != 1 ]; then
        :
    elif [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
        BKS_RESULT=ok BKS_N=0 BKS_OLDEST=""
    elif [ -d "$dir" ] && [ ! -L "$dir" ] && fits 15; then
        while IFS= read -r -d '' ent; do
            case "$ent" in
                /status=*)
                    st="${ent#/status=}"
                    continue
                    ;;
            esac
            n=$((n + 1))
            if [ "$n" -gt 4096 ]; then
                st=bound
                break
            fi
            [[ $ent =~ ^[0-9]{8}T[0-9]{6}Z-scheduled$ ]] || continue
            sets=$((sets + 1))
            BKS_NAMES+=("${ent%-scheduled}")
            if [ -z "$oldest" ] || [[ $ent < $oldest ]]; then oldest="$ent"; fi
        done < <(
            timeout 10 find "$dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\0' 2> /dev/null
            printf '/status=%s\0' "$?"
        )
        if [ "$st" = 0 ]; then
            BKS_RESULT=ok BKS_N="$sets" BKS_OLDEST=""
            if [[ $oldest =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z ]]; then
                t="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}"
                t="$(timeout 5 date -u -d "$t" +%s 2> /dev/null)" || t=""
                if [[ $t =~ ^[0-9]{1,12}$ ]]; then BKS_OLDEST=$((10#$t)); else BKS_RESULT=unknown; fi
            fi
        fi
    fi
    # The account's 5 s and the read's 5 s.
    fits 10 || return 0
    # Only an account id says is gone means no pull; a lookup that failed otherwise cannot tell.
    rc=0
    account_uid propolis-backup-pull > /dev/null || rc=$?
    case "$rc" in
        0) ;;
        1)
            PULL_CONF=0
            return 0
            ;;
        *) return 0 ;;
    esac
    f="$ROOT/var/lib/propolis-backup-pull/.ssh/authorized_keys"
    if [ ! -e "$f" ] && [ ! -L "$f" ]; then
        PULL_CONF=0
        return 0
    fi
    text="$(pa_read_as propolis-backup-pull "$f" 65536)"
    rc=$?
    [ "$rc" = 0 ] || return 0
    PULL_CONF=0
    while IFS= read -r line; do
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        PULL_CONF=1
        break
    done <<< "$text"
    # The serve script is root's own, installed beside this one. One that is there and does not
    # log its served line is an older one; a missing one serves nothing, which is a pull that
    # does not happen and is counted as one. One that could not be read is not taken for one
    # that logs: the pull is then unknown for the pass.
    f="$ROOT/usr/local/sbin/propolis-backup-serve"
    if [ "$PULL_CONF" = 1 ] && [ -f "$f" ] && [ ! -L "$f" ]; then
        if ! fits 5; then
            PULL_CONF=""
            return 0
        fi
        rc=0
        timeout 5 grep -q -F -- 'logger -t propolis-backup-serve' "$f" 2> /dev/null || rc=$?
        case "$rc" in
            0) ;;
            1) SERVE_OLD=1 ;;
            *) PULL_CONF="" ;;
        esac
    fi
}

BKS_NEW=""

# judge_backups: under the lock, backup-retention (NOTICE, backup:keep): fewer scheduled sets than
# KEEP while the oldest set's date is more than KEEP days ago, resolved clean2; and backup-offhost
# (NOTICE, backup:pull): a pull is configured and a scheduled set has waited over 72 hours for it,
# resolved by a newer served line (pulled), or `disabled` once no pull is configured. A set waits
# when it was made after the later of the last served line (meta pull_last, which the light pass
# writes) and the first hourly pass that saw the pull configured (meta pull_since). Sets, not the
# line's age alone: the pull fetches only the newest set and logs nothing when it already holds
# it, so a working pull is silent while no new set appears, and backups that stopped are their
# own records' to report. The first-seen time, so that a pull which never served anything is
# reported too; sets made before it are not counted, since whether they were pulled is not known.
# While the installed serve script is an older one that logs no served line there is nothing to
# count from, and nothing opens. Each on the second hourly pass in a row. Status 1 when a read
# could not tell.
judge_backups() {
    local bad=0 a floor="" since lo hi name waiting=0
    [ "$BKS_RESULT" != skip ] || return 0
    if [ "$BKS_RESULT" = ok ]; then
        BKS_NEW="$BKS_N/$BK_KEEP"
        if [ "$BKS_N" -lt "$BK_KEEP" ] && [ -n "$BKS_OLDEST" ] \
            && [ "$((10#$PA_WALL - BKS_OLDEST))" -gt "$((BK_KEEP * 86400))" ]; then
            rec_attrs backup-retention NOTICE backup backup.keep
            seen_hold backup:keep ""
        else
            absent_clean backup:keep
        fi
    else
        absent_unknown backup:keep
        bad=1
    fi
    case "$PULL_CONF" in
        1)
            since="$META_PULL_SINCE"
            if [ "$SERVE_OLD" = 1 ]; then
                since=-
            elif ! _pa_stamp_split "$since" || [ "$(pa_age "$since")" -lt 0 ]; then
                # Seen configured for the first time: since the last served line when there is
                # one (a pull that served was configured then), else since now. After a time
                # with no pull (`-`), since now: sets made meanwhile were never its to fetch.
                if [ -z "$since" ] && _pa_stamp_split "$META_PULL_LAST" && [ "$(pa_age "$META_PULL_LAST")" -ge 0 ]; then
                    since="$META_PULL_LAST"
                else
                    since="$PA_STAMP"
                fi
            fi
            PULL_SINCE_NEW="$since"
            # No floor while the serve script logs nothing: an earlier served line (another
            # script's) does not make this one's silence mean anything.
            if _pa_stamp_split "$since"; then floor=$((10#$_PA_W)); fi
            if [ -n "$floor" ] && _pa_stamp_split "$META_PULL_LAST" && [ "$((10#$_PA_W))" -gt "$floor" ]; then
                floor=$((10#$_PA_W))
            fi
            if [ "$BKS_RESULT" != ok ]; then
                # Which sets there are could not be read: whether one waits is not known.
                absent_unknown backup:pull
            else
                if [ -n "$floor" ]; then
                    # A set's name is its time, in the form and zone this prints (the script runs
                    # in UTC), so names compare as times do.
                    printf -v lo '%(%Y%m%dT%H%M%SZ)T' "$floor"
                    printf -v hi '%(%Y%m%dT%H%M%SZ)T' "$((10#$PA_WALL - 259200))"
                    for name in "${BKS_NAMES[@]}"; do
                        if [[ $name > $lo && $name < $hi ]]; then
                            waiting=1
                            break
                        fi
                    done
                fi
                if [ "$waiting" = 1 ]; then
                    rec_attrs backup-offhost NOTICE backup backup.pull
                    seen_hold backup:pull ""
                else
                    two_pass backup:pull 0 ""
                    if pa_incident_get backup:pull && _pa_stamp_split "$META_PULL_LAST" \
                        && a="$(_pa_stamp_span "${PA_INC[9]}" "$META_PULL_LAST")" && [ "$a" -gt 0 ]; then
                        resolve_if backup:pull 1 pulled
                    fi
                fi
            fi
            ;;
        0)
            PULL_SINCE_NEW=-
            two_pass backup:pull 0 ""
            resolve_if backup:pull 1 disabled
            ;;
        *)
            absent_unknown backup:pull
            bad=1
            ;;
    esac
    if [ "$bad" = 0 ]; then
        check_counts backups ok -
    else
        check_counts backups unknown unknown
    fi
    [ "$bad" = 0 ]
}

# tie_backup: fold ties 2 and 4, for a failed backup whose last-failure is newer than its
# last-success (both root's, deploy/backup.sh). One whose last step read the database (the
# ledger's chain head, the dump, the check against earlier sets' chain heads) takes an open
# db-unreachable as its parent; one that failed checking free space takes the open volume record
# of the backup directory's filesystem, and nothing else: that step queries the database too, so a
# database failure there cannot be told from a refusal for space. The late-parent rule: from then
# on it counts nothing and its parent speaks for both. A parent is taken only when the failure was
# written while its fault was there (at most 300 s before its first sighting, as a probe sees a
# fault a little after it starts): a failure hours before an outage is not tied to it.
tie_backup() {
    local key=unit:propolis-backup.service parent="" k i
    [ "$BACKUP_FAILED_LAST" = 1 ] && [[ $BACKUP_FAIL_MT =~ ^[0-9]{1,12}$ ]] || return 0
    pa_incident_get "$key" || return 0
    case "${PA_INC[7]}" in pending | open | acked) ;; *) return 0 ;; esac
    [ "${PA_INC[13]}" = - ] || return 0
    case "$BACKUP_STEP" in
        "reading the ledger's chain head" | "dumping the database" \
            | "checking the ledger against the chain heads earlier sets recorded")
            for k in db:local db:remote; do
                pa_incident_get "$k" || continue
                case "${PA_INC[7]}" in
                    open | acked)
                        backup_failed_during || continue
                        parent="${PA_INC[1]}"
                        break
                        ;;
                esac
            done
            ;;
        "checking free space")
            [ -n "$BACKUP_DEV" ] || return 0
            for i in "${!VOL_DEV[@]}"; do
                [ "${VOL_DEV[$i]}" = "$BACKUP_DEV" ] && [ -n "${VOL_MID[$i]:-}" ] || continue
                pa_incident_get "vol:${VOL_MID[$i]}" || continue
                case "${PA_INC[7]}" in
                    open | acked)
                        backup_failed_during || continue
                        parent="${PA_INC[1]}"
                        break
                        ;;
                esac
            done
            ;;
    esac
    [ -n "$parent" ] || return 0
    if pa_incident_fold "$key" "$parent"; then rec_set; fi
}

# backup_failed_during: the backup's failure (BACKUP_FAIL_MT) was written no earlier than 300 s
# before the first sighting of the record in PA_INC; a first sighting that cannot be read ties
# nothing.
backup_failed_during() {
    _pa_stamp_split "${PA_INC[8]}" || return 1
    [ "$BACKUP_FAIL_MT" -ge "$((10#$_PA_W - 300))" ]
}

CC_FOLD_K12="" UNLISTED_CID=""

# unlisted_inst_read: when a completed config-check run printed exactly one spool-unlisted
# finding, the opaque id of its collector, for the folded record's instance: the spool's plain
# names are listed and keyed with the listed ones (collectors_load, so the id is the one the walk
# shows) and the one whose key hash is the finding's (sha256 of `spool-unlisted:<name>`, as
# config-check makes it) is taken. The name reaches sha256sum and pa_id_table on their input,
# never a command line.
unlisted_inst_read() {
    local name h
    UNLISTED_CID=""
    [ "$CC_FOLD_N" = 1 ] && [[ $CC_FOLD_K12 =~ ^[0-9a-f]{12}$ ]] || return 0
    collectors_load || return 0
    for name in "${!SL_MT[@]}"; do
        fits 5 || return 0
        h="$(printf '%s' "spool-unlisted:$name" | timeout 5 sha256sum 2> /dev/null)" || continue
        [ "${h:0:12}" = "$CC_FOLD_K12" ] || continue
        UNLISTED_CID="${CN_ALL[$name]:-}"
        return 0
    done
}

# ---- the daily message ----------------------------------------------------------------------
#
# One message a day, priority 2, to the push target, only while the gate is full and only from
# the host that runs the daemon (a single box or control node): its absence
# then tells the operator to look. The light pass sends it; the hourly pass sends it only while
# the light pass is stale, and the two decide under the state lock, from meta and the send
# ledger, so only one of them can. It is counted before it goes (meta daily_last and
# daily_last_stamp, then a ledger line already claimed as sending), so a send that failed, timed
# out or was cut short by a killed pass is not tried again that day. The request is made with the
# lock released.

DAILY_GO=0 DAILY_STAMP="" DAILY_TITLE="" DAILY_PRIO="" DAILY_BODY=""

# light_stale LIGHT_LAST: the light pass's last pass (its heartbeat line or meta light_last, the
# newer) is over 15 minutes old, or none can be dated after the first half hour of uptime: what
# makes the hourly pass send what the light pass would.
light_stale() {
    local age
    age="$(pass_age light "$1")"
    if [ "$age" -lt 0 ]; then
        [ "$((10#$PA_UP))" -gt 1800 ]
    else
        [ "$age" -gt 900 ]
    fi
}

# daily_prepare: under the lock, after this pass's own writes, whether the daily message is due,
# and if so its rendering, its count in meta and its claimed ledger line. Not where the state
# cannot be kept (WHERE none): with nothing to remember it by, the next pass would send it again.
# What would send nothing whatever the server answered (no rendering, no curl) is settled here,
# before anything is counted. DAILY_GO is 1 when daily_send is to post it.
daily_prepare() {
    local t k v last_date="" last=""
    DAILY_GO=0
    [ "${WHERE:-none}" != none ] || return 0
    past_deadline && return 0
    # Under the legacy profile the message is the daemon host's alone: a split deployment gets
    # one a day, from its control node, and whether a credential kept on a collector can read
    # the topic never decides a send. A role that cannot be told sends none.
    case "${PA_ROLE:-}" in single | control) ;; *) return 0 ;; esac
    while IFS=$'\t' read -r t k v _; do
        [ "$t" = M ] || continue
        case "$k" in
            daily_last) last_date="$v" ;;
            daily_last_stamp) last="$v" ;;
        esac
    done < <(pa_state_read meta)
    pa_daily_due "$last_date" "$last" || return 0
    [ "$(pa_gate)" = full ] || return 0
    pa_budget_admit daily - daily 1 > /dev/null || return 0
    PA_WHERE="$WHERE"
    PA_DAILY_LISTED=""
    # The hourly pass loads the collectors only for an unlisted spool: standing in for the light
    # pass, it loads them here, or its message could not count them.
    case "${PA_ROLE:-}" in
        control | gateway) [ "$COLL_TRIED" = 1 ] || { fits 25 && collectors_load; } || true ;;
    esac
    [ "$COLL_OK" != 1 ] || PA_DAILY_LISTED="${#CN_ID[@]}"
    pa_render full daily - || return 0
    command -v curl > /dev/null 2>&1 || return 0
    # meta first: a ledger write that fails after it costs this day's message, never a second.
    _pa_meta_set daily_last "$PA_LOCAL_DATE" daily_last_stamp "$PA_STAMP" || return 0
    where_merge
    [ "$WHERE" != none ] || return 0
    pa_ledger_add daily - daily full sending "$INSTANCE" || return 0
    where_merge
    DAILY_STAMP="$PA_LEDGER_STAMP" DAILY_TITLE="$PA_TITLE" DAILY_PRIO="$PA_PRIO" DAILY_BODY="$PA_BODY"
    DAILY_GO=1
}

# daily_send: the post daily_prepare readied, made without the lock; then its result in its
# ledger line, under the lock. A lock not had within 30 s leaves the line claimed, which counts
# as sent: the count errs toward fewer messages, never more.
daily_send() {
    local result
    [ "$DAILY_GO" = 1 ] || return 0
    pa_send "$DAILY_TITLE" "$DAILY_PRIO" < <(printf '%s\n' "$DAILY_BODY") || true
    result="$PA_SEND_RESULT"
    if pa_lock 30; then
        pa_ledger_result "$DAILY_STAMP" daily "$result" "$INSTANCE" || true
        pa_unlock
    fi
    [ "$result" = ok ] || note "daily message not delivered ($result)"
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
            backup_dur) META_BACKUP_DUR="$v" ;;
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
    # The last backup run's length, for backup-hung's limit, and when the off-host pull was last
    # served, for the hourly pass's backup-offhost.
    [ -z "$BACKUP_DUR_NEW" ] || [ "$BACKUP_DUR_NEW" = "$META_BACKUP_DUR" ] || meta+=(backup_dur "$BACKUP_DUR_NEW")
    [ -z "$PULL_NEW" ] || meta+=(pull_last "$PULL_NEW")
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
    daily_prepare
    write_heartbeat "$status"
    pa_unlock
    [ "$WHERE" != none ] || note "state not persisted: neither /var/lib/propolis/witness nor /run/propolis-witness took a write"
    if [ "$HB_WHY" = insecure ] && [ "${META_HB_SKIP#*/*/*/}" != insecure ]; then
        note "heartbeat URL not requested: PROPOLIS_WITNESS_HEARTBEAT_URL is not a valid https:// URL"
    fi
    daily_send

    PA_WHERE="$WHERE"
    pa_banner_write || note "banner not written: /run/motd.d is missing or refused the write"
    [ "$HB_GO" = 0 ] || hb_send
    return 0
}

# hourly_pass: the hourly pass. See the header for what it does and in what order. Everything
# slow (config-check, the read check, systemd) happens before the lock; under it the state files
# are read afresh and only the hourly pass's own records, observe lines and meta keys change (and,
# while it stands in for a stale light pass, the daily message's meta keys and ledger line), so
# what the light pass or the hook wrote while this pass computed is kept.
hourly_pass() {
    local rc n status=ok t k v light="" judged=0
    pa_settings_load
    PA_ROLE="$(pa_role)"
    if pa_maint_active; then MAINT=1 MAINT_REASON="$PA_MAINT_REASON"; fi
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
        # The units' properties first: the backup unit's environment names a store.
        change_sample
        backup_learn
        pg_state_read
        pg_datadir_read
        vol_sample
        change_read
        push_read
        backup_read
        unlisted_inst_read
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
            push_sched_since) META_PUSH_SINCE="$v" ;;
            pull_last) META_PULL_LAST="$v" ;;
            pull_since) META_PULL_SINCE="$v" ;;
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
        if ! past_deadline; then
            judge_stores || status=partial
        fi
        if ! past_deadline; then
            judge_push || status=partial
            judge_backups || status=partial
            tie_backup
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
    # The database's last state, for the walk's ledger row, and the local data directory once read.
    if [ "$judged" = 1 ] && [ "$PG_RESULT" = ok ]; then
        meta+=(pg_state "$PA_STAMP/$PG_XID/$PG_CONN/$PG_USABLE/$PG_LOCKS/$PG_SIZE")
    fi
    [ "$PG_DATADIR_NEW" = 0 ] || meta+=(pg_datadir "$PG_DATADIR" pg_datadir_stamp "$PA_STAMP")
    # Since when a scheduler of the push has been seen (`-` while there is none), and the backup
    # sets against KEEP, for the walk.
    [ -z "$PUSH_SINCE_NEW" ] || [ "$PUSH_SINCE_NEW" = "$META_PUSH_SINCE" ] || meta+=(push_sched_since "$PUSH_SINCE_NEW")
    [ -z "$BKS_NEW" ] || meta+=(backup_sets "$BKS_NEW")
    # Since when an off-host pull has been seen configured (`-` while there is none, or none that
    # logs what it serves): what an unserved set is counted from before the first served line.
    [ -z "$PULL_SINCE_NEW" ] || [ "$PULL_SINCE_NEW" = "$META_PULL_SINCE" ] || meta+=(pull_since "$PULL_SINCE_NEW")
    _pa_meta_set "${meta[@]}"
    where_merge
    [ "$WHERE" != none ] || status=partial
    # The light pass sends the daily message; while it is stale, this pass stands in for it.
    if light_stale "$light"; then daily_prepare; fi
    write_heartbeat "$status"
    pa_unlock
    daily_send
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
