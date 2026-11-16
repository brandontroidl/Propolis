#!/usr/bin/env bash
#
# The off-host backup pull's server side. Installed as /usr/local/sbin/propolis-backup-serve and
# run ONLY as the forced command of the propolis-backup-pull account
# (deploy/backup-pull-authorized-keys.example): sshd puts whatever the client asked to run in
# SSH_ORIGINAL_COMMAND, and this reads it as one of two requests and nothing else:
#
#   list                   one line per encrypted set, newest first:  <set> <file> <bytes>
#   get <set> <file>       that file's bytes on stdout
#
# Only encrypted sets are served (a set holding propolis.dump.age); a plaintext set is never
# listed or sent, so a stolen pull key yields ciphertext at most. Names are checked against the
# exact shapes deploy/backup.sh writes before they touch a path. The account reads the sets
# through group membership (backup.sh opens encrypted sets to it) and can write nothing. Each get
# that served its file logs one line, `served <set> <file>`, to the journal under the identifier
# propolis-backup-serve, which the root witness reads to see that the pull still happens.
#
# PROPOLIS_BACKUP_SERVE_DIR overrides /var/backups/propolis (tests only).

set -euo pipefail

DIR="${PROPOLIS_BACKUP_SERVE_DIR:-/var/backups/propolis}"
SET_RE='^[0-9]{8}T[0-9]{6}Z-(scheduled|pre-upgrade)$'
FILES=(propolis.dump.age state.tgz.age SHA256SUMS)

refuse() {
    echo "propolis-backup-serve: $1" >&2
    exit 2
}

encrypted_set() { [[ "$1" =~ $SET_RE ]] && [ -f "$DIR/$1/propolis.dump.age" ] && [ -f "$DIR/$1/SHA256SUMS" ]; }

read -r -a request <<<"${SSH_ORIGINAL_COMMAND:-}"
case "${request[0]:-}" in
    list)
        [ "${#request[@]}" -eq 1 ] || refuse "list takes no arguments"
        mapfile -t sets < <(find "$DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r)
        for set in "${sets[@]}"; do
            encrypted_set "$set" || continue
            for f in "${FILES[@]}"; do
                [ -f "$DIR/$set/$f" ] && printf '%s %s %s\n' "$set" "$f" "$(stat -c %s "$DIR/$set/$f")"
            done
        done
        ;;
    get)
        [ "${#request[@]}" -eq 3 ] || refuse "usage: get <set> <file>"
        set="${request[1]}" file="${request[2]}"
        encrypted_set "$set" || refuse "no encrypted set named ${set:0:64}"
        allowed=0
        for f in "${FILES[@]}"; do [ "$file" = "$f" ] && allowed=1; done
        [ "$allowed" -eq 1 ] || refuse "not a backup file: ${file:0:64}"
        cat -- "$DIR/$set/$file"
        # Only after the bytes went out (a failed cat has already ended the script with its own
        # status): the root witness reads this line, by this account's uid and this identifier,
        # to tell that the off-host copy is still being taken. Both names were checked against
        # the shapes above, so nothing else the client sent reaches the journal, and a logger
        # that is missing or fails changes neither what was served nor the exit status.
        timeout 5 logger -t propolis-backup-serve -p daemon.info "served $set $file" </dev/null >/dev/null 2>&1 || true
        ;;
    *) refuse "this key can only list and get encrypted backup sets" ;;
esac
