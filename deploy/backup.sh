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
# A run stopped from outside (its unit's timeout, `systemctl stop`, a shutdown) cleans up the same
# way: a half-written set holds a plaintext dump even when sets are encrypted.
on_signal() {
    trap - ERR TERM INT HUP
    STEP="interrupted while $STEP"
    false || on_error
}
trap on_signal TERM INT HUP

mkdir -p "$STATUS_DIR"
exec 9> "$STATUS_DIR/lock"
STEP="waiting for another backup to finish"
flock -w 3600 9
# Under the lock no other run is writing, so a .partial set left here was left by a run that was
# killed outright (SIGKILL, power loss) and never cleaned up after itself.
if [ -d "$BACKUP_DIR" ]; then
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '.partial-*' -exec rm -rf -- {} +
fi

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
# A propolis binary from before pg-exec would ignore the argument and start the daemon, as root,
# with DATABASE_URL in its environment. Look for pg-exec's own message in the binary instead of
# running it to find out.
grep -q -a -F 'propolis pg-exec: DATABASE_URL is not set' "$PROPOLIS_BIN" || {
    echo "error: $PROPOLIS_BIN has no pg-exec (it predates it); upgrade before backing up" >&2
    false
}
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
    # Sensors add and remove spool files while this runs; a file that vanishes mid-walk makes du
    # exit non-zero but its total is still the estimate this needs.
    state_bytes="$( (cd "$ROOT/" && du -s -B1 -- "${existing[@]}" 2>/dev/null || true) | awk '{s += $1} END {printf "%d", s}')"
fi
[[ "$state_bytes" =~ ^[0-9]{1,18}$ ]] || { echo "error: could not size the state directories: $state_bytes" >&2; false; }
# What a set will take is best known from the last one: scale its real size by how much the
# database and state have grown since (the source size each good run records), plus a fifth. The
# raw database size is the fallback, also plus a fifth, for a first run or a status from before the
# source size was recorded; it is several times what a compressed dump takes (a 5.9 GB source made
# a 1.07 GB set), so on its own it refused upgrades the disk had room for.
total=$(( db_bytes + state_bytes ))
need=$(( total + total / 5 ))
prev_success="$(cat -- "$STATUS_DIR/last-success" 2>/dev/null || true)"
prev_dump="$(printf '%s' "$prev_success" | sed -n 's/.*"dump_bytes":\([0-9]\{1,15\}\).*/\1/p')"
prev_archive="$(printf '%s' "$prev_success" | sed -n 's/.*"archive_bytes":\([0-9]\{1,15\}\).*/\1/p')"
prev_source="$(printf '%s' "$prev_success" | sed -n 's/.*"source_bytes":\([0-9]\{1,15\}\).*/\1/p')"
if [ -n "$prev_dump" ] && [ -n "$prev_archive" ]; then
    prev_set=$(( prev_dump + prev_archive ))
    if [ -n "$prev_source" ] && [ "$prev_source" -gt 0 ]; then
        # The product of two byte counts can pass bash's 64-bit range, so awk does the arithmetic.
        scaled="$(awk -v s="$prev_set" -v t="$total" -v p="$prev_source" 'BEGIN { printf "%.0f", (s * t / p) * 1.2 + 1 }')"
    else
        # A status written before source_bytes was recorded: the growth since is unknown, so allow
        # half again the last set, never more than the raw-size rule above.
        scaled=$(( prev_set + prev_set / 2 ))
        [ "$scaled" -le "$need" ] || scaled="$need"
    fi
    [[ "$scaled" =~ ^[0-9]{1,18}$ ]] || { echo "error: could not scale the last set's size: $scaled" >&2; false; }
    # Never ask for less than the last set really took.
    [ "$scaled" -ge "$prev_set" ] || scaled="$prev_set"
    need="$scaled"
fi
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
# The spools are live. A spool's .staging directory only holds a sample between its write and its
# rename into place, so it is left out; a file a sensor adds, removes or grows while tar reads is
# GNU tar's exit 1 ("some files differ"), which still leaves a complete archive of everything else.
# Exit 2 and above is a real failure.
tar_rc=0
if [ "${#existing[@]}" -gt 0 ]; then
    tar -C "$ROOT/" --exclude=.staging --warning=no-file-changed --warning=no-file-removed \
        --warning=no-file-shrank -czf "$PARTIAL/state.tgz" -- "${existing[@]}" || tar_rc=$?
else
    tar -C "$ROOT/" -czf "$PARTIAL/state.tgz" --files-from /dev/null || tar_rc=$?
fi
[ "$tar_rc" -le 1 ] || { echo "error: tar exited $tar_rc" >&2; false; }

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
# An encrypted set, and only an encrypted one, is readable by the off-host pull account
# (deploy/backup-serve.sh): ciphertext can leave the box, a plaintext dump never does.
if [ "$ENCRYPT" -eq 1 ] && getent group propolis-backup-pull >/dev/null 2>&1; then
    STEP="opening the encrypted set to the pull account"
    chgrp -R propolis-backup-pull "$PARTIAL"
    chmod 0750 "$PARTIAL"
    chmod 0640 "$PARTIAL"/*
fi
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
write_status last-success "$(printf '{"completed_at":"%s","reason":"%s","set":"%s","encrypted":%s,"dump_bytes":%d,"archive_bytes":%d,"source_bytes":%d}' \
    "$(now_iso)" "$REASON" "$SET" "$([ "$ENCRYPT" -eq 1 ] && echo true || echo false)" "$dump_size" "$archive_size" "$total")"
rm -f -- "$STATUS_DIR/last-failure"
echo "propolis-backup: wrote $BACKUP_DIR/$SET ($dump_size + $archive_size bytes$([ "$ENCRYPT" -eq 1 ] && echo ', encrypted'))"
