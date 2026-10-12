#!/usr/bin/env bash
#
# Tell the operator a Propolis unit failed. Installed as /usr/local/sbin/propolis-alert and run by
# propolis-alert@<unit>.service, which every Propolis unit names in OnFailure=. This is the alert
# that still goes out when the daemon itself is the thing that died: the daemon's own monitor
# cannot page about a process that is not running.
#
# Posts to the ntfy topic in /etc/propolis/propolis.env (PROPOLIS_OPS_NTFY_URL, _TOPIC and the
# optional _TOKEN, the same target the daemon's monitor uses); without one, or when the post
# fails, writes the alert to the journal at err priority instead.
#
# Rate-limited per unit (PROPOLIS_ALERT_COOLDOWN_SECS, default 1800): a unit with Restart= passes
# through the failed state on every crash, so a crash loop would otherwise page every few seconds.
# The journal lines quoted are the unit's own output, which can carry attacker-chosen text; they
# go only in the message body, never in a header, and the unit name is checked before it is used
# in one. The token goes to curl in a header file, never on its command line.
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

env_value() {
    [ -r "$ENV_FILE" ] || return 0
    local v
    v="$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    printf '%s' "$v"
}

mkdir -p "$STATE_DIR"
stamp="$STATE_DIR/$UNIT"
now="$(date +%s)"
if [ -f "$stamp" ] && [ $(( now - $(stat -c %Y "$stamp") )) -lt "$COOLDOWN" ]; then
    logger -p daemon.notice -t propolis-alert "$UNIT failed again; alerted within the last $COOLDOWN s, not repeating"
    exit 0
fi
touch "$stamp"

host="$(hostname)"
body="$(printf '%s entered the failed state on %s at %s.\n\nLast journal lines:\n%s\n' \
    "$UNIT" "$host" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$(journalctl -u "$UNIT" -n 20 --no-pager -o short-iso 2>/dev/null | cut -c1-300 || true)")"

url="$(env_value PROPOLIS_OPS_NTFY_URL)"
topic="$(env_value PROPOLIS_OPS_NTFY_TOPIC)"
token="$(env_value PROPOLIS_OPS_NTFY_TOKEN)"

if [ -n "$url" ] && [ -n "$topic" ]; then
    headers="$(mktemp)"
    trap 'rm -f -- "$headers"' EXIT
    {
        printf 'Title: propolis: %s failed on %s\n' "$UNIT" "$host"
        printf 'Priority: 5\n'
        printf 'Tags: rotating_light\n'
        if [ -n "$token" ]; then
            printf 'Authorization: Bearer %s\n' "$token"
        fi
    } > "$headers"
    if printf '%s' "$body" | curl -fsS --max-time 20 --retry 2 -H "@$headers" --data-binary @- \
        "${url%/}/$topic" > /dev/null; then
        exit 0
    fi
    logger -p daemon.err -t propolis-alert "could not post to ntfy; alert follows"
fi
logger -p daemon.err -t propolis-alert "$body"
