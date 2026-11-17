#!/usr/bin/env bash
#
# Tell the operator a Propolis unit failed. Installed as /usr/local/sbin/propolis-alert and run by
# propolis-alert@<unit>.service, which every Propolis unit names in OnFailure=. This is the alert
# that still goes out when the daemon itself is the thing that died: the daemon's own monitor
# cannot page about a process that is not running.
#
# Posts to the ntfy topic in /etc/propolis/propolis.env (PROPOLIS_OPS_NTFY_URL, _TOPIC and the
# optional _TOKEN, the same target the daemon's monitor uses); without one, writes the alert to the
# journal at err priority instead, and that journal line is the delivery.
#
# Rate-limited per unit (PROPOLIS_ALERT_COOLDOWN_SECS, default 1800): a unit with Restart= passes
# through the failed state on every crash, so a crash loop would otherwise page every few seconds.
# The cooldown is armed only by an alert that was delivered. An alert that was not (the post
# failed, or curl is not installed) would otherwise silence the unit for half an hour although
# nobody was told, so the next failure posts again once a short retry hold has passed
# (PROPOLIS_ALERT_RETRY_SECS, default 120), which still keeps a crash loop from hammering ntfy.
# While undelivered, the full alert goes to the journal at most once per cooldown and each failure
# in between writes one short err line saying since when the alert is undelivered; the alert that
# finally gets through also says how many earlier failures went undelivered and since when.
# A stamp dated after now (the clock was stepped back) counts as expired, never as recent.
#
# The journal lines quoted are the unit's own output, which can carry attacker-chosen text; they
# go only in the message body, never in a header, and the unit name is checked before it is used
# in one or in a state file name. The undelivered count is read back from a state file, so it is
# checked to be digits before it is used, and it goes only in the body. The token goes to curl in
# a header file, never on its command line.
#
# On today's path, whatever it did with the failure, unless the argument was refused, the failure
# is then recorded in the root alerting state (/var/lib/propolis/witness/incidents) with systemd's
# own cause and what this hook did with it. The record is made by the shared library
# (/usr/local/sbin/propolis-alert-lib), and none of its code runs in this shell: under
# `set -euo pipefail` an unbound variable or an arithmetic error inside a sourced file ends the
# shell even behind `|| true`, and this is the alert that must still go out when everything else
# is broken. So the record runs once the send is decided, from the EXIT handler, in a separate bash
# under `timeout` within the unit's 90 s, with its output discarded. A library that is missing,
# too old, broken or hung loses the record and writes one journal line under tag
# propolis-witness; what this hook sends, logs as propolis-alert, leaves in its own state files and
# returns stays exactly as it was. Under profile v2 (below) the v2 child records the failure
# instead, and one that fails late (after its marker but before its first write, or without its
# marker once too little time is left for today's message) may leave only that one line.
#
# One name takes another path: propolis-test-page-<6 hex>, which only `propolis-status
# --test-page` starts. That path sends the operator's test page through the library, in a child
# process, and exits 0 on every outcome (see the block after the argument check).
#
# Under a test root, before today's code, a child process asks the library which alerting profile
# is in force, and under profile v2 a second child handles the failure in the new message format
# instead (see the block after the test page). This release starts neither child without a test
# root, so on every host this hook is today's, whatever file sits at the library's path.
#
# Usage: propolis-alert <unit name>
# PROPOLIS_ALERT_ROOT reads every path under that directory instead of / (tests only).
#
# The two lines below are read by deploy/rollback.sh and the deploy tests, in exactly this form:
# this hook's contract number, which rollback compares before it puts an older hook back, and the
# version of the library the record step needs. The two children of profile v2 check the version
# they need themselves (V2_NEEDS).
#
# The decision child says v2 with status CHILD_DONE (20), never 0: a library file that ends the
# shell with status 0 at its top level (a stray `exit 0`, the wrong file at its path) would
# otherwise read as profile v2 in force, and the v2 child, ended the same way, as a failure
# handled. Such a library ends the record step's child with status 0 too, so the decision's 0 is
# named in one line of its own.
# hook-contract: 2
# needs-alert-lib: 2

set -euo pipefail
umask 077

UNIT="${1:-}"
if ! [[ "$UNIT" =~ ^[A-Za-z0-9@._:-]{1,200}$ ]]; then
    echo "usage: propolis-alert <unit name>" >&2
    exit 2
fi

# The test page. Decided by the name alone and before anything else, so every unit name that
# reaches the code below runs exactly as before. systemd hands this hook a failed unit's full
# name, which ends in its type (`.service`), so no real failure matches; only the status command
# starts propolis-alert@propolis-test-page-<CODE>.service. The page is sent by the library, which
# runs in a child bash under `timeout`, never in this shell: under `set -euo pipefail` a library
# with an unbound variable or an arithmetic error would end this shell with its own status, and
# this path exits 0 whatever happens. The child checks the library's version before it calls
# anything, logs its own line when it sends nothing, and this shell adds one only when the child
# itself failed. Nothing here posts, so a child that sent and then failed cannot cause a second
# message. A child that failed or was stopped by its time limit may already have sent (it returns
# 0 on every outcome it reaches), so that line says the outcome is unknown, not that nothing was
# sent. The child's limit counts down from the hook's own SECONDS, as the record step's does
# below, so the child always ends inside TimeoutStartSec=90s.
if [[ "$UNIT" =~ ^propolis-test-page-[0-9a-f]{6}$ ]]; then
    TP_ROOT="${PROPOLIS_ALERT_ROOT:-}"
    # The library version that has the test page (pa_hook_test_page).
    TP_NEEDS=9
    TP_BUDGET=$(( 85 - SECONDS ))
    [ "$TP_BUDGET" -ge 1 ] || TP_BUDGET=1
    # shellcheck source=deploy/alert-lib.sh
    # shellcheck disable=SC2016 # the child bash expands these, with the library as $1
    timeout --kill-after=2 "$TP_BUDGET" \
        bash -c 'trap "pa_cleanup 2>/dev/null" EXIT; . "$1" && [ "${PA_LIB_VERSION:-0}" -ge "$3" ] && pa_init "$2" && pa_hook_test_page "$4"' \
        _ "$TP_ROOT/usr/local/sbin/propolis-alert-lib" "$TP_ROOT" "$TP_NEEDS" "$UNIT" < /dev/null > /dev/null 2>&1 \
        || logger -p daemon.notice -t propolis-witness "test page outcome unknown for $UNIT (library missing, too old, failed or timed out)" 2>/dev/null \
        || true
    exit 0
fi

ROOT="${PROPOLIS_ALERT_ROOT:-}"
LIB="$ROOT/usr/local/sbin/propolis-alert-lib"
# The same number as the library version line above. The record step checks it before calling
# anything, so an older library is never asked for a function it does not have.
LIB_NEEDS=2
# The decision child's status for v2 in force (see the header).
CHILD_DONE=20
# What this hook did with the failure, for the record: set just before each exit below, and
# before the post. A plain assignment, so it sends and logs nothing.
PA_HOOK_OUT=-

# The record step, run once whatever path this hook took has ended. It keeps the status the hook
# was ending with: `set +e` first, so no step here can replace it, and `${headers:-}` because the
# cooldown and early paths end before the header file exists. The child gets the unit, the
# outcome and how far into its time the hook is, inherits systemd's MONITOR_* variables, and has
# whatever is left of 85 s (at least 1), plus 2 s before it is killed: inside TimeoutStartSec=90s.
# The child's own EXIT handler runs the library's pa_cleanup, so a child stopped by its time limit
# between writing a temporary state file and renaming it leaves no temporary file behind (bash
# runs an EXIT handler on the TERM that timeout sends). Before the library is sourced there is
# nothing to clean, and the handler's error is discarded.
# shellcheck disable=SC2317,SC2329 # run by the EXIT trap below; every path of this script ends in an explicit exit, and shellcheck does not follow those into the trap
record_on_exit() {
    local rc=$? budget
    set +e
    rm -f -- "${headers:-}"
    budget=$(( 85 - SECONDS ))
    [ "$budget" -ge 1 ] || budget=1
    # shellcheck source=deploy/alert-lib.sh
    # shellcheck disable=SC2016 # the child bash expands these, with the library as $1
    PA_HOOK_UNIT="$UNIT" PA_HOOK_OUT="$PA_HOOK_OUT" PA_HOOK_T0="$SECONDS" \
        timeout --kill-after=2 "$budget" \
        bash -c 'trap "pa_cleanup 2>/dev/null" EXIT; . "$1" && [ "${PA_LIB_VERSION:-0}" -ge "$3" ] && pa_init "$2" && pa_hook_record' \
        _ "$LIB" "$ROOT" "$LIB_NEEDS" < /dev/null > /dev/null 2>&1 \
        || logger -p daemon.notice -t propolis-witness "incident not recorded for $UNIT (library missing, too old or failed)" 2>/dev/null
    exit "$rc"
}

# Set before the decision below, so a hook stopped by a signal while the decision runs (the unit
# stopped, the host shutting down) still records the failure, as one stopped anywhere in today's
# code does. It is cleared while the v2 child runs, which records the failure itself (see below).
trap record_on_exit EXIT

# Profile v2, decided before any of today's code runs. Two children, each its own bash under
# timeout, so no library code runs in this shell (see the header): the decision asks the library
# which profile is in force (it ends CHILD_DONE once pa_hook_profile says v2, which it says by
# ending 0, and 10 for legacy), and only then the v2 child hands the failure to pa_hook_v2, which
# records it and sends at most one message in the new format. Any other status from the decision
# (10, a library that is missing, older than V2_NEEDS, broken or hung) leaves the failure to
# today's code below, unchanged. The decision gets no stdin and its output is discarded, as the
# record step's is.
#
# In this release the decision is asked only under a test root (PROPOLIS_ALERT_ROOT), which no
# unit passes: the library honours v2 only there, and a host must not depend on that alone, since
# a wrong file at the library's path that ended its shell with CHILD_DONE would read as v2 and,
# if it were slow, cost today's message its time. Without a test root neither child starts.
#
# The v2 child makes the marker file once it has the state lock, or has found it busy, and before
# it reads any state file under the lock, writes one or sends. The marker sits in a directory this
# hook makes for the one run (mktemp -d, so no other account can enter it or have prepared its
# name: the unit's /tmp is private, but a hook run by hand shares /tmp, and a link under a name
# that could be guessed would be followed when the marker is made). With no such directory the
# child is given no marker path, changes nothing and fails, and today's code runs. The
# marker is what this hook goes by: a child that left it may have sent, whatever its status, so
# this hook ends 0 here and adds nothing, no second message and no second record, since the
# record step's handler is cleared while the child runs. A child that left none wrote no record,
# no ledger line and no message, whatever its status (a library that ends the shell with status 0
# makes none), and today's code sends today's message, if enough of the unit's time is left for
# its worst case.
#
# The time budget, in seconds from the hook's start, inside TimeoutStartSec=90s:
# - today's code takes at most LEGACY_WORST = 65: the post's --retry-max-time 40 and its last
#   attempt's --max-time 20, and 5 for everything else; the record step then has what is left of
#   85 s, at least 1, and 2 more before it is killed.
# - legacy: the decision ends by 5 + 1 (DECIDE_LIMIT and its kill-after), today's code by
#   6 + 65 = 71, the record step by 85 + 2 = 87.
# - v2 handled: the v2 child ends by 75 + 2 (V2_LIMIT, counted from the hook's start, and its
#   kill-after) = 77; there is no record step.
# - v2 failed without the marker by 20 s (LEGACY_LAST_START = 85 - LEGACY_WORST; SECONDS counts
#   whole seconds, so up to a second later): today's code ends by 21 + 65 = 86, the record step
#   by 86 + 1 + 2 = 89.
# - v2 failed without the marker later: one journal line, by 77 and a moment. Without the marker
#   the child admitted nothing, and the witness's failed-state and crash-loop checks open the
#   incident.
# The decision's limit also shrinks to what is left of 85 s, so a hook started late keeps the
# record step's time.
DECIDE_LIMIT=5
V2_LIMIT=75
LEGACY_WORST=65
LEGACY_LAST_START=$(( 85 - LEGACY_WORST ))
# The library version that has pa_hook_profile and pa_hook_v2.
V2_NEEDS=12
decide_budget=$(( 85 - SECONDS ))
[ "$decide_budget" -le "$DECIDE_LIMIT" ] || decide_budget="$DECIDE_LIMIT"
[ "$decide_budget" -ge 1 ] || decide_budget=1
decide_rc=10
if [ -n "$ROOT" ]; then
    decide_rc=0
    # shellcheck source=deploy/alert-lib.sh
    # shellcheck disable=SC2016 # the child bash expands these, with the library as $1
    PA_HOOK_UNIT="$UNIT" timeout --kill-after=1 "$decide_budget" \
        bash -c 'trap "pa_cleanup 2>/dev/null" EXIT; . "$1" && [ "${PA_LIB_VERSION:-0}" -ge "$3" ] && pa_init "$2" && pa_hook_profile && exit "$4"' \
        _ "$LIB" "$ROOT" "$V2_NEEDS" "$CHILD_DONE" < /dev/null > /dev/null 2>&1 || decide_rc=$?
    if [ "$decide_rc" = 0 ]; then
        logger -p daemon.notice -t propolis-witness "the alert library ended before it said which profile is in force; today's code handles the failure of $UNIT, which may not be recorded" 2>/dev/null || true
    fi
fi
if [ "$decide_rc" = "$CHILD_DONE" ]; then
    v2_dir="$(mktemp -d 2>/dev/null)" || v2_dir=""
    v2_marker="${v2_dir:+$v2_dir/sent}"
    v2_budget=$(( V2_LIMIT - SECONDS ))
    [ "$v2_budget" -ge 1 ] || v2_budget=1
    v2_rc=0
    trap - EXIT
    # shellcheck source=deploy/alert-lib.sh
    # shellcheck disable=SC2016 # the child bash expands these, with the library as $1
    PA_HOOK_UNIT="$UNIT" PA_HOOK_MARKER="$v2_marker" timeout --kill-after=2 "$v2_budget" \
        bash -c 'trap "pa_cleanup 2>/dev/null" EXIT; . "$1" && [ "${PA_LIB_VERSION:-0}" -ge "$3" ] && pa_init "$2" && pa_hook_v2' \
        _ "$LIB" "$ROOT" "$V2_NEEDS" < /dev/null > /dev/null 2>&1 || v2_rc=$?
    v2_began=0
    if [ -n "$v2_dir" ]; then
        [ ! -e "$v2_marker" ] || v2_began=1
        rm -f -- "$v2_marker" 2>/dev/null || true
        rmdir -- "$v2_dir" 2>/dev/null || true
    fi
    if [ "$v2_began" = 1 ]; then
        if [ "$v2_rc" != 0 ]; then
            logger -p daemon.notice -t propolis-witness "new-format alert for $UNIT stopped after it began; a message may have gone" 2>/dev/null || true
        fi
        exit 0
    fi
    if [ "$SECONDS" -gt "$LEGACY_LAST_START" ]; then
        logger -p daemon.notice -t propolis-witness "alert for $UNIT not sent: the new-format path failed, and too little of the unit's time is left for today's message" 2>/dev/null || true
        exit 0
    fi
    trap record_on_exit EXIT
fi

# Units that did not exist before the record step are decided by name alone, before anything
# else: a failed witness pass is recorded, never paged, so no host is sent a page it was not sent
# before.
if [[ "$UNIT" =~ ^propolis-witness@[a-z]+\.service$ ]]; then
    exit 0
fi

ENV_FILE="$ROOT/etc/propolis/propolis.env"
STATE_DIR="${PROPOLIS_ALERT_STATE_DIR:-$ROOT/run/propolis-alert}"
COOLDOWN="${PROPOLIS_ALERT_COOLDOWN_SECS:-1800}"
[[ "$COOLDOWN" =~ ^[0-9]{1,7}$ ]] || COOLDOWN=1800
RETRY="${PROPOLIS_ALERT_RETRY_SECS:-120}"
[[ "$RETRY" =~ ^[0-9]{1,7}$ ]] || RETRY=120

env_value() {
    [ -r "$ENV_FILE" ] || return 0
    local v
    v="$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    printf '%s' "$v"
}

iso() {
    date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '@%s' "$1"
}

# Seconds since the file's mtime, or -1 when it is missing. A stamp dated after now comes out
# negative too, and expired() counts every negative age as expired: a clock stepped back would
# otherwise suppress alerts for as long as the step.
age_of() {
    local m
    m="$(stat -c %Y -- "$1" 2>/dev/null)" || { printf -- '-1'; return 0; }
    printf '%s' "$(( now - m ))"
}
expired() {
    [ "$1" -lt 0 ] || [ "$1" -ge "$2" ]
}

# State is best effort: an unwritable state directory must never stop the alert from going out
# or exit before the journal fallback is written.
mkdir -p "$STATE_DIR/undelivered" 2>/dev/null || true
stamp="$STATE_DIR/$UNIT"
# One file per unit, in a directory of its own so no unit name can collide with another's
# delivered stamp. Holds "<first undelivered epoch> <undelivered count> <epoch the full text was
# last journaled>"; its mtime is the last post attempt, which the retry hold runs from.
pending="$STATE_DIR/undelivered/$UNIT"
now="$(date +%s)"
if ! expired "$(age_of "$stamp")" "$COOLDOWN"; then
    logger -p daemon.notice -t propolis-alert "$UNIT failed again; alerted within the last $COOLDOWN s, not repeating"
    PA_HOOK_OUT=cooldown
    exit 0
fi

first="" count=0 logged=0
if [ -f "$pending" ]; then
    read -r first count logged < "$pending" 2>/dev/null || true
    # Anything but plain numbers is a damaged file: start over rather than trust it.
    if ! [[ "$first" =~ ^[0-9]{1,12}$ && "$count" =~ ^[0-9]{1,7}$ && "$logged" =~ ^[0-9]{1,12}$ ]]; then
        first="" count=0 logged=0
    fi
fi

host="$(hostname)"
late=""
if [ -n "$first" ]; then
    late="$(printf ' Also, %s earlier failures of this unit since %s went undelivered.' \
        "$(( 10#$count ))" "$(iso "$(( 10#$first ))")")"
fi
body="$(printf '%s entered the failed state on %s at %s.%s\n\nLast journal lines:\n%s\n' \
    "$UNIT" "$host" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$late" \
    "$(journalctl -u "$UNIT" -n 20 --no-pager -o short-iso 2>/dev/null | cut -c1-300 || true)")"

url="$(env_value PROPOLIS_OPS_NTFY_URL)"
topic="$(env_value PROPOLIS_OPS_NTFY_TOPIC)"
token="$(env_value PROPOLIS_OPS_NTFY_TOKEN)"

# $1, when given, is what the record calls this outcome (journal for the no-target path, whose
# journal line is the delivery).
delivered() {
    touch -- "$stamp" 2>/dev/null || true
    rm -f -- "$pending" 2>/dev/null || true
    PA_HOOK_OUT="${1:-delivered}"
    exit 0
}

# Records a failure whose alert did not go out, with $1 saying why and $2 the epoch to date the
# retry hold from. The full text goes to the journal at most once per cooldown and a short line in
# between, so a crash loop on a host that cannot reach ntfy does not flood the journal either.
undelivered() {
    [ -n "$first" ] || first="$now"
    count=$(( 10#$count + 1 ))
    [ "$count" -le 9999999 ] || count=9999999
    if expired "$(( now - 10#$logged ))" "$COOLDOWN"; then
        logger -p daemon.err -t propolis-alert "$1; alert follows" || true
        logger -p daemon.err -t propolis-alert "$body" || true
        logged="$now"
    else
        logger -p daemon.err -t propolis-alert "$1; the alert for $UNIT is still undelivered since $(iso "$(( 10#$first ))") ($count failures since then; the full text was logged at $(iso "$(( 10#$logged ))"))" || true
    fi
    { printf '%s %s %s\n' "$(( 10#$first ))" "$count" "$(( 10#$logged ))" > "$pending" \
        && touch -d "@$2" -- "$pending"; } 2>/dev/null || true
    PA_HOOK_OUT=undelivered
    exit 0
}

if [ -z "$url" ] || [ -z "$topic" ]; then
    # No push target: the journal line is the alert, so it counts as delivered.
    logger -p daemon.err -t propolis-alert "$body"
    delivered journal
fi

if [ -n "$first" ]; then
    attempt_age="$(age_of "$pending")"
    if ! expired "$attempt_age" "$RETRY"; then
        undelivered "the last attempt to deliver was less than $RETRY s ago, not retrying yet" "$(( now - attempt_age ))"
    fi
fi

if ! command -v curl > /dev/null 2>&1; then
    undelivered "curl is not installed, so this host cannot push alerts; install it" "$now"
fi

# The EXIT handler above removes it.
headers="$(mktemp 2>/dev/null)" || undelivered "could not create the ntfy header file in the temporary directory" "$now"
{
    printf 'Title: propolis: %s failed on %s\n' "$UNIT" "$host"
    printf 'Priority: 5\n'
    printf 'Tags: rotating_light\n'
    if [ -n "$token" ]; then
        printf 'Authorization: Bearer %s\n' "$token"
    fi
} > "$headers" || undelivered "could not write the ntfy header file in the temporary directory" "$now"
# --retry-max-time caps the whole retry period, which would otherwise wait out any Retry-After
# the server sends: its 40 s plus the last attempt's 20 s stay well under the unit's
# TimeoutStartSec=90s, so a slow ntfy still ends in undelivered below instead of systemd killing
# the hook before the failure is recorded.
# Once the post has started, a hook stopped by a signal must not be recorded as having handled
# nothing; delivered() overwrites this, and like today's hook an interrupted post leaves no stamp.
PA_HOOK_OUT=undelivered
if printf '%s' "$body" | curl -fsS --max-time 20 --retry 2 --retry-max-time 40 -H "@$headers" --data-binary @- \
    "${url%/}/$topic" > /dev/null; then
    delivered
fi
undelivered "could not post to ntfy" "$now"
