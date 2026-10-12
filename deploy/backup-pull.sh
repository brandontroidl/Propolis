#!/usr/bin/env bash
#
# Off-host copy of a Propolis node's backups, run on the machine that keeps them (not on the
# honeypot). Asks the node's propolis-backup-pull account (deploy/backup-serve.sh, behind a
# restricted SSH key) for its newest encrypted set, fetches each file, checks every digest in the
# set's SHA256SUMS and only then moves the set into place, so a set in DEST is always whole and
# verified. Keeps the newest KEEP sets. Never decrypts: the age identity stays wherever you keep
# it, and restoring is the manual procedure in docs/operations/backup-and-restore.md.
#
# Usage: backup-pull.sh --host HOST --port ADMIN_SSH_PORT --key ~/.ssh/propolis_backup
#                       --dest ~/propolis-backups [--keep 14]
#
# Exit status: 0 with the newest set present (fetched now or already here), non-zero otherwise,
# so a systemd --user timer's OnFailure= or a cron mail reports a pull that did not happen.

set -euo pipefail
umask 077

HOST="" PORT="" KEY="" DEST="" KEEP=14
usage() {
    echo "usage: $0 --host HOST --port ADMIN_SSH_PORT --key KEYFILE --dest DIR [--keep N]" >&2
    exit 2
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) HOST="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; shift 2 ;;
        --key) KEY="${2:-}"; shift 2 ;;
        --dest) DEST="${2:-}"; shift 2 ;;
        --keep) KEEP="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$HOST" ] && [ -n "$KEY" ] && [ -n "$DEST" ] || usage
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || usage
[[ "$KEEP" =~ ^[0-9]{1,4}$ ]] && [ "$KEEP" -ge 1 ] || usage
[[ "$HOST" =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "error: not a host name: $HOST" >&2; exit 2; }

SET_RE='^[0-9]{8}T[0-9]{6}Z-(scheduled|pre-upgrade)$'
FILE_RE='^(propolis\.dump\.age|state\.tgz\.age|SHA256SUMS)$'

remote() {
    ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEY" -p "$PORT" \
        "propolis-backup-pull@$HOST" "$@"
}

mkdir -p "$DEST"
listing="$(remote list)"
newest="$(printf '%s\n' "$listing" | awk 'NF == 3 {print $1; exit}')"
if [ -z "$newest" ]; then
    echo "error: $HOST serves no encrypted backup set (are age recipients configured there?)" >&2
    exit 1
fi
[[ "$newest" =~ $SET_RE ]] || { echo "error: the server named an unexpected set: ${newest:0:64}" >&2; exit 1; }

if [ -f "$DEST/$newest/SHA256SUMS" ]; then
    echo "propolis-backup-pull: $newest is already here"
else
    partial="$DEST/.partial-$newest"
    rm -rf -- "$partial"
    mkdir -p "$partial"
    mapfile -t files < <(printf '%s\n' "$listing" | awk -v s="$newest" '$1 == s {print $2}')
    for f in "${files[@]}"; do
        [[ "$f" =~ $FILE_RE ]] || { echo "error: the server named an unexpected file: ${f:0:64}" >&2; exit 1; }
        remote get "$newest" "$f" > "$partial/$f"
    done
    [ -f "$partial/SHA256SUMS" ] || { echo "error: $newest came without SHA256SUMS" >&2; exit 1; }
    if ! (cd "$partial" && sha256sum --check --quiet --strict SHA256SUMS); then
        echo "error: $newest does not match its digests; nothing was kept" >&2
        rm -rf -- "$partial"
        exit 1
    fi
    mv -- "$partial" "$DEST/$newest"
    echo "propolis-backup-pull: fetched and verified $newest"
fi

mapfile -t sets < <(find "$DEST" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | { grep -E "$SET_RE" || true; } | sort)
excess=$(( ${#sets[@]} - KEEP ))
for (( i = 0; i < excess; i++ )); do
    rm -rf -- "${DEST:?}/${sets[$i]}"
done
