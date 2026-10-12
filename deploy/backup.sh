#!/usr/bin/env bash
#
# Back up a Propolis node: a pg_dump of the database plus an archive of the state the database does
# not hold (docs/operations/backup-and-restore.md, "What holds state"). Installed as
# /usr/local/sbin/propolis-backup; run nightly by propolis-backup.timer, and by upgrade.sh before it
# changes anything so the database can be put back if the new release's migrations must be undone.
#
# Each run writes one set, <dir>/<UTC time>-<reason>/:
#   propolis.dump  pg_dump --format=custom, restored with pg_restore as the page above describes
#   state.tgz      /etc/propolis, /var/spool/propolis and /var/lib/propolis/ssh, the page's archive
#   SHA256SUMS     the digest of each file as stored
# With /etc/propolis/backup-recipients.txt present (age public keys, one per line), both files are
# encrypted to those recipients (propolis.dump.age, state.tgz.age) and no plaintext copy is kept;
# the off-host pull only ever serves encrypted sets. Without it the set stays plaintext, root-only.
# A set is built under .partial-<name> and renamed into place last, so a set that exists is whole.
#
# Status, for the daemon's backup-stale alert and config-check.sh (both read it without root):
#   /var/lib/propolis/backup-status/last-success  JSON, rewritten after every good run
#   /var/lib/propolis/backup-status/last-failure  JSON, written by a failed run, removed by a good one
#
# The database password never reaches a command line: `propolis pg-exec` (crates/propolis/src/
# pg_exec.rs) parses DATABASE_URL with the daemon's own parser and runs pg_dump with libpq's PG*
# variables, so `ps` shows no secret while the dump runs.
#
# Usage: propolis-backup [--reason scheduled|pre-upgrade]
# Environment, all optional:
#   PROPOLIS_BACKUP_DIR   where sets are written (default /var/backups/propolis)
#   PROPOLIS_BACKUP_KEEP  scheduled sets to keep, 1-365 (default 7); pre-upgrade sets keep 3
#   PROPOLIS_BACKUP_ROOT  read every other path under this directory instead of / (tests only)
#   PROPOLIS_BIN          the propolis binary to run pg-exec with (default: propolis on PATH).
#                         upgrade.sh passes the one it just built: the installed one is still the
#                         previous release then, which may predate pg-exec, and a propolis binary
#                         without it would ignore the argument and start the daemon.

set -euo pipefail
set -o errtrace
umask 077

REASON=scheduled
case "${1:-}" in
    "") ;;
    --reason)
        REASON="${2:-}"
        [ "$#" -eq 2 ] || { echo "usage: $0 [--reason scheduled|pre-upgrade]" >&2; exit 2; }
        ;;
    *) echo "usage: $0 [--reason scheduled|pre-upgrade]" >&2; exit 2 ;;
esac
case "$REASON" in
    scheduled) KEEP="${PROPOLIS_BACKUP_KEEP:-7}" ;;
    pre-upgrade) KEEP=3 ;;
    *) echo "error: --reason must be scheduled or pre-upgrade, not '$REASON'" >&2; exit 2 ;;
esac
if ! [[ "$KEEP" =~ ^[0-9]+$ ]] || [ "$KEEP" -lt 1 ] || [ "$KEEP" -gt 365 ]; then
    echo "error: PROPOLIS_BACKUP_KEEP must be a whole number from 1 to 365, not '$KEEP'" >&2
    exit 2
fi

ROOT="${PROPOLIS_BACKUP_ROOT:-}"
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (it reads every service's spool and /etc/propolis)" >&2
    exit 1
fi
ENV_FILE="$ROOT/etc/propolis/propolis.env"
RECIPIENTS="$ROOT/etc/propolis/backup-recipients.txt"
STATUS_DIR="$ROOT/var/lib/propolis/backup-status"
BACKUP_DIR="${PROPOLIS_BACKUP_DIR:-$ROOT/var/backups/propolis}"
# Relative to $ROOT/, so the archive's member names are the same whatever the root: restoring
# with `tar -xpzf state.tgz -C /` puts each file back where it came from.
STATE_PATHS=(etc/propolis var/spool/propolis var/lib/propolis/ssh)

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Written by a temporary file and a rename, so a reader never sees half a file.
write_status() {
    local name="$1" body="$2"
    mkdir -p "$STATUS_DIR"
    chmod 0755 "$STATUS_DIR"
    printf '%s\n' "$body" > "$STATUS_DIR/.$name.tmp"
    chmod 0644 "$STATUS_DIR/.$name.tmp"
    mv -f "$STATUS_DIR/.$name.tmp" "$STATUS_DIR/$name"
}

STEP="starting"
PARTIAL=""
on_error() {
    local code=$?
    trap - ERR
    [ -n "$PARTIAL" ] && rm -rf -- "$PARTIAL"
    write_status last-failure "$(printf '{"failed_at":"%s","reason":"%s","step":"%s","exit_code":%d}' \
        "$(now_iso)" "$REASON" "$STEP" "$code")"
    echo "error: backup failed while $STEP (exit $code)" >&2
    exit 1
}
trap on_error ERR

mkdir -p "$STATUS_DIR"
exec 9> "$STATUS_DIR/lock"
STEP="waiting for another backup to finish"
flock -w 3600 9

STEP="reading DATABASE_URL"
DATABASE_URL=""
if [ -r "$ENV_FILE" ]; then
    DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' "$ENV_FILE" | tail -n 1)"
    DATABASE_URL="${DATABASE_URL%\"}"; DATABASE_URL="${DATABASE_URL#\"}"
    DATABASE_URL="${DATABASE_URL%\'}"; DATABASE_URL="${DATABASE_URL#\'}"
fi
if [ -z "$DATABASE_URL" ]; then
    # Not a failure to page about: the daemon cannot run without it either, so a node in this state
    # is still being installed. Recorded so config-check.sh can say why there is no backup.
    write_status last-failure "$(printf '{"failed_at":"%s","reason":"%s","step":"not configured: no DATABASE_URL in %s","exit_code":0}' \
        "$(now_iso)" "$REASON" "${ENV_FILE#"$ROOT"}")"
    echo "propolis-backup: no DATABASE_URL in $ENV_FILE yet; nothing to back up"
    exit 0
fi
export DATABASE_URL

STEP="finding the tools"
PROPOLIS_BIN="${PROPOLIS_BIN:-$(command -v propolis || echo /usr/local/bin/propolis)}"
for tool in "$PROPOLIS_BIN" pg_restore tar sha256sum flock df du; do
    command -v "$tool" >/dev/null || { echo "error: $tool is not installed" >&2; false; }
done
ENCRYPT=0
if [ -s "$RECIPIENTS" ]; then
    ENCRYPT=1
    command -v age >/dev/null || { echo "error: $RECIPIENTS names recipients but age is not installed (apt install age)" >&2; false; }
fi

existing=()
for path in "${STATE_PATHS[@]}"; do
    [ -e "$ROOT/$path" ] && existing+=("$path")
done

STEP="checking free space"
install -d -m 0750 "$BACKUP_DIR"
db_bytes="$("$PROPOLIS_BIN" pg-exec psql -X -A -t -c 'SELECT pg_database_size(current_database())')"
# At most 18 digits each, so the sum below cannot overflow bash's 64-bit arithmetic and wrap to a
# negative "need" that every disk satisfies.
[[ "$db_bytes" =~ ^[0-9]{1,18}$ ]] || { echo "error: could not read the database size: $db_bytes" >&2; false; }
state_bytes=0
if [ "${#existing[@]}" -gt 0 ]; then
    state_bytes="$(cd "$ROOT/" && du -s -B1 -- "${existing[@]}" | awk '{s += $1} END {printf "%d", s}')"
fi
[[ "$state_bytes" =~ ^[0-9]{1,18}$ ]] || { echo "error: could not size the state directories: $state_bytes" >&2; false; }
# A dump is usually far smaller than the database, but a mostly-text ledger does not compress to
# nothing; ask for the sum plus a fifth, so the run that would fill the disk is the one refused.
total=$(( db_bytes + state_bytes ))
need=$(( total + total / 5 ))
avail="$(df --output=avail -B1 "$BACKUP_DIR" | tail -n 1 | tr -d ' ')"
if [ "$avail" -lt "$need" ]; then
    echo "error: $BACKUP_DIR has $avail bytes free; this backup may need $need" >&2
    false
fi

SET="$(date -u +%Y%m%dT%H%M%SZ)-$REASON"
[ ! -e "$BACKUP_DIR/$SET" ] || { echo "error: $BACKUP_DIR/$SET already exists" >&2; false; }
PARTIAL="$BACKUP_DIR/.partial-$SET"
rm -rf -- "$PARTIAL"
mkdir -m 0700 "$PARTIAL"

STEP="dumping the database"
"$PROPOLIS_BIN" pg-exec pg_dump --format=custom --file="$PARTIAL/propolis.dump"
STEP="checking the dump reads back"
pg_restore --list "$PARTIAL/propolis.dump" > /dev/null

STEP="archiving the state directories"
if [ "${#existing[@]}" -gt 0 ]; then
    tar -C "$ROOT/" -czf "$PARTIAL/state.tgz" -- "${existing[@]}"
else
    tar -C "$ROOT/" -czf "$PARTIAL/state.tgz" --files-from /dev/null
fi

files=(propolis.dump state.tgz)
if [ "$ENCRYPT" -eq 1 ]; then
    STEP="encrypting to $RECIPIENTS"
    for f in propolis.dump state.tgz; do
        age -R "$RECIPIENTS" -o "$PARTIAL/$f.age" "$PARTIAL/$f"
        rm -f -- "$PARTIAL/$f"
    done
    files=(propolis.dump.age state.tgz.age)
fi

STEP="recording digests"
(cd "$PARTIAL" && sha256sum -- "${files[@]}" > SHA256SUMS)
mv -- "$PARTIAL" "$BACKUP_DIR/$SET"
PARTIAL=""

STEP="pruning old sets"
mapfile -t sets < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name "*-$REASON" -printf '%f\n' \
    | grep -E "^[0-9]{8}T[0-9]{6}Z-$REASON\$" | sort)
excess=$(( ${#sets[@]} - KEEP ))
for (( i = 0; i < excess; i++ )); do
    rm -rf -- "${BACKUP_DIR:?}/${sets[$i]}"
done

dump_size="$(stat -c %s "$BACKUP_DIR/$SET/${files[0]}")"
archive_size="$(stat -c %s "$BACKUP_DIR/$SET/${files[1]}")"
write_status last-success "$(printf '{"completed_at":"%s","reason":"%s","set":"%s","encrypted":%s,"dump_bytes":%d,"archive_bytes":%d}' \
    "$(now_iso)" "$REASON" "$SET" "$([ "$ENCRYPT" -eq 1 ] && echo true || echo false)" "$dump_size" "$archive_size")"
rm -f -- "$STATUS_DIR/last-failure"
echo "propolis-backup: wrote $BACKUP_DIR/$SET ($dump_size + $archive_size bytes$([ "$ENCRYPT" -eq 1 ] && echo ', encrypted'))"
