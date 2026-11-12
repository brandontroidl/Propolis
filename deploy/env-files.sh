#!/usr/bin/env bash
#
# Creates and tightens the secret-bearing /etc/propolis/*.env files so a fresh box never has one
# at 0644.
#
# WHY THIS EXISTS. Every unit's env file carries a secret (the database URL, the console password,
# vendor API keys) or a bind list another sensor need not see, and must be 0600
# (deploy/config-check.sh, `env-mode`). The operator creates them by copying the .env.example
# files, and `cp` and an editor's "new file" both leave 0644 under the usual umask, so a fresh box
# started with every file world-readable until config-check said so. `cp` onto an existing file
# keeps that file's mode, so creating the files here, empty and 0600, means the operator's copy
# and edits land in a file that is already closed.
#
# WHAT IT DOES.
#   - Creates each missing service env file (propolis.env and one per sensor) EMPTY, root:root,
#     0600. It writes no value: what goes in is the operator's. A unit started before the file is
#     filled in loads no variables, which config-check.sh reports as a missing bind or setting,
#     where a missing file would have stopped the unit at systemd's own check.
#   - Removes the group and other permission bits of every other existing *.env file in the
#     directory. It never loosens a mode (0400 stays 0400), never changes an owner, and does not
#     follow a symbolic link: a link is reported and left alone.
#   - Leaves the two files that are meant to be wider to the scripts that write them:
#     watch.env, root:propolis-watch 0640 (deploy/watch-env.sh), and fleet-listeners.env, 0644
#     and secret-free (deploy/fleet-listeners.sh). A blanket chmod 0600 over them broke the live
#     watcher on 2026-10-14, which is why this does not glob them in.
#
# Idempotent. Run by deploy/provision.sh, so by install.sh and upgrade.sh.
#
# Usage: env-files.sh [ENV_DIR]     (default /etc/propolis)
# Environment:
#   DRY_RUN=1  print what would be done and touch nothing
#
# Ownership of a created file is set only when run as root; a non-root run, as in
# crates/sensor-framework/tests/deploy_test.rs, creates it with the caller's own.

set -euo pipefail

ENV_DIR="${1:-/etc/propolis}"
DRY_RUN="${DRY_RUN:-0}"

# One per unit that names an EnvironmentFile= under /etc/propolis in deploy/*.service.
SERVICE_ENV_FILES=(propolis catchall ssh telnet redis adb http ftp smtp tftp mqtt dns cred)
# Written by their own scripts at the modes config-check.sh allows them.
OWN_MODE_FILES=(watch.env fleet-listeners.env)

log() { printf '==> env-files: %s\n' "$*"; }

if [ ! -d "$ENV_DIR" ]; then
    log "$ENV_DIR does not exist; nothing to do"
    exit 0
fi

is_exception() {
    local name="$1" other
    for other in "${OWN_MODE_FILES[@]}"; do
        [ "$name" = "$other" ] && return 0
    done
    return 1
}

for name in "${SERVICE_ENV_FILES[@]}"; do
    file="$ENV_DIR/$name.env"
    if [ -e "$file" ] || [ -L "$file" ]; then
        continue
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] would create empty $file (root:root 0600)"
        continue
    fi
    # noclobber: a file that appears between the test above and here is not truncated.
    (umask 077 && set -o noclobber && : >"$file")
    if [ "$(id -u)" -eq 0 ]; then
        chown root:root "$file"
    fi
    chmod 0600 "$file"
    log "created empty $file (0600)"
done

tightened=0
shopt -s nullglob
for file in "$ENV_DIR"/*.env; do
    name="${file##*/}"
    if is_exception "$name"; then
        continue
    fi
    if [ -L "$file" ]; then
        log "$file is a symbolic link; left alone"
        continue
    fi
    if [ ! -f "$file" ]; then
        log "$file is not a regular file; left alone"
        continue
    fi
    mode="$(stat -c %a -- "$file")"
    if [ $((8#$mode & 8#077)) -eq 0 ]; then
        continue
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] would remove group and other access from $file (mode $mode)"
    else
        chmod go-rwx -- "$file"
        log "$file was mode $mode; group and other access removed"
    fi
    tightened=$((tightened + 1))
done

if [ "$tightened" -eq 0 ]; then
    log "no env file under $ENV_DIR needed tightening"
fi
