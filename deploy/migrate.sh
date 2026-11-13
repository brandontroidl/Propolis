#!/usr/bin/env bash
#
# Apply the database migrations as the schema's OWNER role, then reset the grants of the role the
# daemon connects as. Installed as /usr/local/sbin/propolis-migrate; run by upgrade.sh between
# stopping and starting propolis, and by hand after `propolis migrate --init-roles`
# (docs/operations/database-roles.md).
#
# WHY THIS EXISTS. The ledger's append-only control is a revoke, and a revoke does not bind the
# role that owns the table. With one role the daemon is that owner. With two, the owner's
# credential must be somewhere the daemon cannot read it:
#   /etc/propolis/migrate.env   root:root 0600, one line: PROPOLIS_MIGRATE_DATABASE_URL=postgres://...
# No unit loads it; propolis.service and every sensor unit deny it by mount. This script, run as
# root, reads it; so does rollback.sh --with-database, also as root, to learn the owner role's
# name before a restore. The role the daemon connects as comes from DATABASE_URL in
# propolis.env, so the two files cannot name different runtime roles.
#
# Neither URL reaches a command line: both are handed to `propolis migrate` in its environment.
#
# Usage: propolis-migrate [--check | --configured]
#   (no flag)     migrate as the owner role and set the runtime role's grants
#   --check       report, as the daemon's role, whether the schema is current and the ledger
#                 protected; exit 0 only when both hold
#   --configured  exit 0 if migrate.env names an owner URL, 1 if not; prints nothing
# Without an owner URL (a deployment that has not split its roles) the no-flag form exits 3 and
# changes nothing: the daemon migrates at startup, as it always has.
#
# Environment, all optional:
#   PROPOLIS_MIGRATE_ROOT  read both env files under this directory instead of / (tests only)
#   PROPOLIS_BIN           the propolis binary to run (default: propolis on PATH). upgrade.sh
#                          passes the one it just built, as it does for the backup.

set -euo pipefail
umask 077

usage() {
    echo "usage: $0 [--check | --configured]" >&2
    exit 2
}

MODE=migrate
case "${1:-}" in
    "") ;;
    --check) MODE=check ;;
    --configured) MODE=configured ;;
    *) usage ;;
esac
[ "$#" -le 1 ] || usage

ROOT="${PROPOLIS_MIGRATE_ROOT:-}"
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (it reads /etc/propolis/migrate.env and propolis.env)" >&2
    exit 1
fi

MIGRATE_ENV="$ROOT/etc/propolis/migrate.env"
DAEMON_ENV="$ROOT/etc/propolis/propolis.env"

# env_value FILE KEY: the value systemd would load for KEY, as backup.sh reads DATABASE_URL: the
# last assignment wins and one pair of surrounding quotes is dropped.
env_value() {
    local v=""
    if [ -r "$1" ]; then
        v="$(sed -n "s/^$2=//p" "$1" | tail -n 1)"
        v="${v%\"}"; v="${v#\"}"
        v="${v%\'}"; v="${v#\'}"
    fi
    printf '%s' "$v"
}

OWNER_URL="$(env_value "$MIGRATE_ENV" PROPOLIS_MIGRATE_DATABASE_URL)"

if [ "$MODE" = configured ]; then
    [ -n "$OWNER_URL" ]
    exit
fi

PROPOLIS_BIN="${PROPOLIS_BIN:-$(command -v propolis || echo /usr/local/bin/propolis)}"
command -v "$PROPOLIS_BIN" >/dev/null || { echo "error: $PROPOLIS_BIN is not installed" >&2; exit 1; }
# A propolis binary from before `migrate` would ignore the argument and start the daemon, as root.
# Look for the subcommand's own usage text in the binary instead of running it to find out.
grep -q -a -F 'usage: propolis migrate' "$PROPOLIS_BIN" || {
    echo "error: $PROPOLIS_BIN has no migrate subcommand (it predates it); upgrade first" >&2
    exit 1
}

RUNTIME_URL="$(env_value "$DAEMON_ENV" DATABASE_URL)"

if [ "$MODE" = check ]; then
    [ -n "$RUNTIME_URL" ] || { echo "error: no DATABASE_URL in $DAEMON_ENV" >&2; exit 1; }
    DATABASE_URL="$RUNTIME_URL" exec "$PROPOLIS_BIN" migrate --check
fi

if [ -z "$OWNER_URL" ]; then
    echo "propolis-migrate: no PROPOLIS_MIGRATE_DATABASE_URL in $MIGRATE_ENV: the roles are not split, so the daemon migrates at startup and the ledger is not protected from its role (docs/operations/database-roles.md)" >&2
    exit 3
fi
# The owner's credential, readable by anyone but root, is the control undone.
mode="$(stat -c %a -- "$MIGRATE_ENV")"
if [ $((8#$mode & 8#077)) -ne 0 ]; then
    echo "error: $MIGRATE_ENV is mode $mode; it holds the schema owner's credential and must be 0600 (chmod 0600 $MIGRATE_ENV)" >&2
    exit 1
fi
[ -n "$RUNTIME_URL" ] || { echo "error: no DATABASE_URL in $DAEMON_ENV; the grants are set for the role it names" >&2; exit 1; }

PROPOLIS_MIGRATE_DATABASE_URL="$OWNER_URL" DATABASE_URL="$RUNTIME_URL" exec "$PROPOLIS_BIN" migrate
