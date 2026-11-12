#!/usr/bin/env bash
#
# Derives /etc/propolis/watch.env, the one value propolis-watch needs, from the daemon's env file.
#
# WHY THIS EXISTS. propolis-watch follows the event logs named in PROPOLIS_SENSOR_LOGS. That list
# lives in /etc/propolis/propolis.env, which the watcher's account must never read: the same file
# holds the database URL, the console password and vendor API keys. A hand-copied second list (in
# authorized_keys, say) would drift from the one the daemon uses, silently, which is the exact
# failure the watcher exists to catch. So the list keeps one source and this script writes a
# derived copy of that single line, the same arrangement as fleet-listeners.sh.
#
# WHAT IT WRITES. Exactly one line, `PROPOLIS_SENSOR_LOGS=<value>`, taken verbatim from the LAST
# uncommented assignment in the source (the one systemd's EnvironmentFile= ends up using), and
# nothing else from that file ever. The file is written to a temporary name in the same directory,
# checked to hold that one line and nothing more, made root:propolis-watch 0640, and renamed into
# place, so a reader never sees a partial file. The source file is only ever read with grep: it is
# never sourced, so nothing in it is executed or expanded.
#
# When the source is missing, or sets no PROPOLIS_SENSOR_LOGS (a fresh install before the operator
# has filled it in, or a collector-only box), it writes nothing, leaves any existing copy alone,
# and says so. Re-run it, or upgrade.sh, after changing PROPOLIS_SENSOR_LOGS in propolis.env.
#
# Usage: watch-env.sh [SOURCE] [OUT_FILE]
#   SOURCE     the daemon's env file   (default /etc/propolis/propolis.env)
#   OUT_FILE   file to write           (default /etc/propolis/watch.env)
# Environment:
#   DRY_RUN=1  print what would be done and touch nothing
#
# Ownership is set only when run as root (provision.sh, upgrade.sh); a non-root run, as in
# crates/sensor-framework/tests/deploy_test.rs, writes the same content with the caller's own.

set -euo pipefail

SOURCE="${1:-/etc/propolis/propolis.env}"
OUT_FILE="${2:-/etc/propolis/watch.env}"
DRY_RUN="${DRY_RUN:-0}"
KEY="PROPOLIS_SENSOR_LOGS"

if [ ! -r "$SOURCE" ]; then
    echo "==> watch-env: $SOURCE not readable; $OUT_FILE left as it is"
    exit 0
fi

line="$(grep -E "^${KEY}=" "$SOURCE" | tail -n 1 || true)"
if [ -z "$line" ]; then
    echo "==> watch-env: no $KEY in $SOURCE; $OUT_FILE left as it is"
    exit 0
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] would write $KEY from $SOURCE to $OUT_FILE (root:propolis-watch 0640)"
    exit 0
fi

TMP_FILE="$OUT_FILE.tmp.$$"
trap 'rm -f "$TMP_FILE"' EXIT
(umask 077 && printf '%s\n' "$line" >"$TMP_FILE")

# The guarantee this file exists to make, checked on what was actually written rather than assumed
# from the grep above: one line, and that line is the one key.
if [ "$(wc -l <"$TMP_FILE")" -ne 1 ] || ! grep -qE "^${KEY}=" "$TMP_FILE" \
    || grep -qvE "^${KEY}=" "$TMP_FILE"; then
    echo "error: watch-env: refusing to write $OUT_FILE: derived content is not exactly one $KEY line" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    chown root:propolis-watch "$TMP_FILE"
fi
chmod 0640 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUT_FILE"
trap - EXIT
echo "==> watch-env: wrote $OUT_FILE from $SOURCE"
