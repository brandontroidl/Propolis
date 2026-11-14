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
# Usage: propolis-alert <unit name>
# PROPOLIS_ALERT_ROOT reads every path under that directory instead of / (tests only).

set -euo pipefail
umask 077

UNIT="${1:-}"
if ! [[ "$UNIT" =~ ^[A-Za-z0-9@._:-]{1,200}$ ]]; then
    echo "usage: propolis-alert <unit name>" >&2
    exit 2
fi

ROOT="${PROPOLIS_ALERT_ROOT:-}"
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

delivered() {
    touch -- "$stamp" 2>/dev/null || true
    rm -f -- "$pending" 2>/dev/null || true
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
    exit 0
}

if [ -z "$url" ] || [ -z "$topic" ]; then
    # No push target: the journal line is the alert, so it counts as delivered.
    logger -p daemon.err -t propolis-alert "$body"
    delivered
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

headers="$(mktemp 2>/dev/null)" || undelivered "could not create the ntfy header file in the temporary directory" "$now"
trap 'rm -f -- "$headers"' EXIT
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
if printf '%s' "$body" | curl -fsS --max-time 20 --retry 2 --retry-max-time 40 -H "@$headers" --data-binary @- \
    "${url%/}/$topic" > /dev/null; then
    delivered
fi
undelivered "could not post to ntfy" "$now"
