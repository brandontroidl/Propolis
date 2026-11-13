#!/usr/bin/env bash
#
# Keep the running release before an upgrade replaces it, and put it back on request.
#
#   rollback.sh --save [--backup-set SET] BIN...
#                                upgrade.sh runs this before installing anything: copies the named
#                                binaries from /usr/local/bin, the Propolis unit files from
#                                /etc/systemd/system, the propolis-* helpers from /usr/local/sbin,
#                                and the deploy stamp into /var/lib/propolis/rollback/<release>/,
#                                recording SET, the pre-upgrade backup upgrade.sh just wrote (none
#                                when it took none). Keeps 3.
#   rollback.sh --list           lists the kept releases, newest first.
#   rollback.sh [--with-database] [--identity FILE] [--yes] [RELEASE]
#                                stops the services, puts RELEASE (default: the newest) back,
#                                reloads systemd and starts them again.
#
# Binaries alone are enough when the upgrade changed no schema. When it ran new migrations, the
# older daemon refuses the newer database at startup (sqlx reports a migration it does not know),
# and the database must go back too: --with-database restores the release's pre-upgrade dump. It
# never drops anything: the current database is RENAMED to <name>_before_rollback_<time>, a new
# empty one is created with the owner the current one has, and the dump is restored into it by the
# documented procedure (docs/operations/backup-and-restore.md, "Restore procedure"). Drop the
# renamed one yourself once you are satisfied. It needs PostgreSQL on this host (it runs psql and
# pg_restore as the postgres user); restore a remote database by hand with that page. An encrypted
# dump needs the age identity that decrypts it, by --identity or /etc/propolis/backup-identity.txt.
#
# The backup set is checked while everything still runs: its SHA256SUMS, that the dump decrypts and
# pg_restore can list it, and that the volume has room for a second copy of the database. Where
# the database roles are split (docs/operations/database-roles.md) the split is put back after the
# restore, before any service starts: a database the daemon's role had come to own is created for
# the owner role, a dump from before the split has its tables handed to the owner role
# (propolis migrate --init-roles), propolis-migrate and propolis-migrate --check run, and the
# script then asks the database itself whether the daemon's role is confined in it. If the restore
# fails, or the run is ended by a signal or a dropped terminal, the incomplete database is renamed
# to <name>_failed_restore_<time> and the renamed-aside one gets its name back; if that cannot be
# done, propolis.service is left stopped, because the name it connects to holds no ledger. What a
# failed run reports goes to the journal as well (tag propolis-rollback).
#
# PROPOLIS_ROLLBACK_ROOT reads and writes every path under that directory instead of / (tests).
# PROPOLIS_ROLLBACK_WAIT_SECS is how long to wait for propolis.service to stay up (default 30).

set -euo pipefail
umask 077

ROOT="${PROPOLIS_ROLLBACK_ROOT:-}"
STORE="$ROOT/var/lib/propolis/rollback"
KEEP=3
RELEASE_RE='^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4,40}$'
SET_RE='^[0-9]{8}T[0-9]{6}Z-pre-upgrade$'
SBIN_HELPERS=(propolis-backup propolis-logrotate-guard propolis-alert)
SENSORS=(sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred)

usage() {
    cat >&2 <<EOF
usage: $0 --save [--backup-set SET] BIN...
       $0 --list
       $0 [--with-database] [--identity FILE] [--yes] [RELEASE]
EOF
    exit 2
}

require_root() {
    if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
        echo "error: must run as root (try: sudo $0)" >&2
        exit 1
    fi
}

# The commit the installed propolis binary says it was built from, or "none".
installed_sha() {
    local bin="$ROOT/usr/local/bin/propolis" line
    [ -x "$bin" ] || { echo none; return; }
    line="$(timeout 10 "$bin" --version 2>/dev/null || true)"
    if [[ "$line" =~ \(([0-9a-f]{4,40}), ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo none
    fi
}

field() { sed -n "s/^$1=//p" "$2" | head -n 1; }

save() {
    require_root
    local set=""
    if [ "${1:-}" = --backup-set ]; then
        set="${2-}"
        shift 2 || usage
        if [ -n "$set" ] && ! [[ "$set" =~ $SET_RE ]]; then
            echo "error: not a pre-upgrade backup set name: $set" >&2
            exit 2
        fi
    fi
    [ "$#" -gt 0 ] || usage
    local sha name partial stamp
    sha="$(installed_sha)"
    if [ "$sha" = none ]; then
        echo "    nothing to keep: no installed propolis binary reports its commit"
        return
    fi
    name="$(date -u +%Y%m%dT%H%M%SZ)-${sha:0:12}"
    mkdir -p "$STORE"
    chmod 0700 "$STORE"
    partial="$STORE/.partial-$name"
    rm -rf -- "$partial"
    mkdir -p "$partial/bin" "$partial/sbin" "$partial/units"
    for bin in "$@"; do
        [[ "$bin" =~ ^[a-z0-9-]+$ ]] || { echo "error: not a binary name: $bin" >&2; exit 2; }
        [ -e "$ROOT/usr/local/bin/$bin" ] && cp -p -- "$ROOT/usr/local/bin/$bin" "$partial/bin/"
    done
    for helper in "${SBIN_HELPERS[@]}"; do
        [ -e "$ROOT/usr/local/sbin/$helper" ] && cp -p -- "$ROOT/usr/local/sbin/$helper" "$partial/sbin/"
    done
    shopt -s nullglob
    for unit in "$ROOT"/etc/systemd/system/{propolis.service,propolis-*.service,propolis-*.timer,sensor-*.service,gateway.service,shipper.service}; do
        [ -f "$unit" ] && cp -p -- "$unit" "$partial/units/"
    done
    shopt -u nullglob
    stamp="$ROOT/var/lib/propolis/deploy-stamp.json"
    [ -f "$stamp" ] && cp -p -- "$stamp" "$partial/deploy-stamp.json"
    # The set is the one upgrade.sh names: the backup it took moments ago, or none when it took
    # none. Never whatever backup happens to be newest, which could be from before an earlier
    # upgrade and would roll the database back past it.
    printf 'saved_at=%s\ncommit=%s\nbackup_set=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$sha" "$set" \
        > "$partial/manifest"
    mv -- "$partial" "$STORE/$name"
    echo "    kept the running release as $STORE/$name${set:+ (database: $set)}"

    mapfile -t releases < <(list_names)
    local excess=$(( ${#releases[@]} - KEEP ))
    for (( i = 0; i < excess; i++ )); do
        rm -rf -- "${STORE:?}/${releases[$i]}"
    done
}

# Kept release names, oldest first.
list_names() {
    [ -d "$STORE" ] || return 0
    find "$STORE" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | { grep -E "$RELEASE_RE" || true; } | sort
}

list() {
    local names
    mapfile -t names < <(list_names)
    if [ "${#names[@]}" -eq 0 ]; then
        echo "no kept releases in $STORE"
        return
    fi
    for (( i = ${#names[@]} - 1; i >= 0; i-- )); do
        local m="$STORE/${names[$i]}/manifest"
        printf '%s  commit %s  database %s\n' "${names[$i]}" "$(field commit "$m")" \
            "$(field backup_set "$m" | sed 's/^$/(none)/')"
    done
}

unit_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

# env_value KEY [FILE]: the value systemd would load for KEY from FILE (propolis.env unless given).
env_value() {
    local file="${2:-$ROOT/etc/propolis/propolis.env}" v
    [ -r "$file" ] || return 0
    v="$(sed -n "s/^$1=//p" "$file" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    printf '%s' "$v"
}

# Set once services are stopped: a failure from then on must say what state the box is in, and
# tries to bring the services back rather than leave a honeypot dark.
STOPPED=0
STEP=""
# The database's own name, the name it is renamed aside to, and whether the dump finished
# restoring into the new database of that name. Between the rename and that point the name the
# daemon connects to holds nothing, or half a ledger. ASIDE is set BEFORE the rename is asked for:
# a signal is acted on the moment a step returns, which is before the line after it runs, so a
# record made after the step can be missing for a step that happened. What was actually renamed
# is asked of PostgreSQL when it matters (put_database_back).
DB=""
ASIDE=""
RESTORED=0
# What put_database_back found and did: unmoved, back, stuck or unknown.
PUT_BACK=""
# Set while propolis-migrate and its --check have been asked for and have not both succeeded.
ROLES_UNCHECKED=0
# Set when the kept release cannot re-apply the role split of a node that has one.
ROLES_BY_HAND=0
# A node that splits its database roles: the role the daemon connects as and the role that owns
# the schema, both read before anything is stopped.
SPLIT=0
ROLE=""
OWNER_ROLE=""

# say TEXT: one line of a failed run's report, to stderr and to the journal. A rollback is often
# run over SSH and a session that drops is one of the ways it ends: the terminal is gone, a write
# to it fails, and what the operator finds on reconnecting is the journal. Never fails.
say() {
    echo "$1" >&2 2>/dev/null
    logger -t propolis-rollback -p daemon.err -- "$1" 2>/dev/null
    return 0
}

# The run ended between asking for the rename aside and recording a finished restore, so the name
# the daemon connects to may hold nothing, an empty database or part of a ledger. Asks PostgreSQL
# which it is and puts the real database back under its name; nothing is dropped. Sets PUT_BACK:
#   unmoved  the rename aside never happened: the real database never left its name
#   back     it had been renamed aside and has its name again
#   stuck    it is still renamed aside and could not be given its name back
#   unknown  PostgreSQL did not answer, so where it is cannot be said
# Returns 0 for the first two. Runs in the EXIT trap, so every step reports and none may end the
# script.
put_database_back() {
    local failed aside exists
    aside="$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 \
        -c "SELECT count(*) FROM pg_database WHERE datname = '$ASIDE'" 2>/dev/null)" || aside=""
    case "$aside" in
        0) PUT_BACK=unmoved; return 0 ;;
        1) ;;
        *) PUT_BACK=unknown; return 1 ;;
    esac
    PUT_BACK=stuck
    failed="${DB}_failed_restore_$(date -u +%Y%m%d%H%M%S)"
    exists="$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 \
        -c "SELECT count(*) FROM pg_database WHERE datname = '$DB'" 2>/dev/null)" || exists=""
    if [ "$exists" != 0 ]; then
        if runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
            -c "ALTER DATABASE \"$DB\" RENAME TO \"$failed\""; then
            # Not called incomplete: a run ended by a signal right after the restore returned has
            # a finished one here, and is undone all the same.
            say "The database the dump was being restored into was renamed to $failed; drop it once you have looked at it."
        else
            say "The database the dump was being restored into, $DB, could not be renamed out of the way."
        fi
    fi
    runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
        -c "ALTER DATABASE \"$ASIDE\" RENAME TO \"$DB\"" || return 1
    PUT_BACK=back
}

on_exit() {
    local daemon=1
    # Keyed on what was done, not on the exit status: ended by a signal, bash runs this with the
    # status of the last command that finished, which is usually 0.
    [ "$STOPPED" -eq 1 ] || return 0
    # From here to the last line nothing may end the script: not a step that fails, not a write
    # to a terminal that has gone away, not a second signal. The commands it runs inherit the
    # ignored signals, so the rename that puts the database back survives a hangup too.
    set +e
    trap '' HUP INT TERM PIPE
    say "error: the rollback failed while $STEP, after the services were stopped."
    if [ -n "$ASIDE" ] && [ "$RESTORED" -eq 0 ]; then
        put_database_back
        case "$PUT_BACK" in
            unmoved)
                say "The database was not renamed: $DB is as it was before the rollback, and nothing was dropped."
                ;;
            back)
                say "The database from before the rollback is back under its own name, $DB; nothing was dropped."
                ;;
            stuck)
                # Started on this name the daemon would find no ledger, or part of one, and on a
                # node with one database role would migrate and begin a new chain there while the
                # real one sits aside.
                daemon=0
                say "The database from before the rollback could NOT be put back under its name: the real data is in database $ASIDE, and nothing was dropped."
                say "propolis.service is left stopped, so that it cannot start a new ledger in an empty database; the sensors keep logging and nothing they record is lost. Once what stopped the rename (above) is out of the way, as the postgres user rename any database now named $DB aside, run ALTER DATABASE \"$ASIDE\" RENAME TO \"$DB\", then go forward again with deploy/upgrade.sh."
                ;;
            *)
                daemon=0
                say "PostgreSQL did not answer, so this script cannot tell whether the database is still under its name, $DB, or was renamed to $ASIDE. Nothing was dropped."
                say "propolis.service is left stopped, so that it cannot start a new ledger in an empty database; the sensors keep logging and nothing they record is lost. When PostgreSQL answers, list the databases as the postgres user (psql -l). If $ASIDE is there, rename any database now named $DB aside and run ALTER DATABASE \"$ASIDE\" RENAME TO \"$DB\". Then go forward again with deploy/upgrade.sh."
                ;;
        esac
        if [ "$daemon" -eq 1 ]; then
            say "The kept binaries are installed: propolis runs on that database if the upgrade changed no schema, and otherwise refuses it at startup and changes nothing. To go forward again, run deploy/upgrade.sh."
        fi
    elif [ -n "$ASIDE" ]; then
        say "The dump was restored into $DB; the database from before the rollback is kept as $ASIDE, and nothing was dropped."
    fi
    if [ "$ROLES_UNCHECKED" -eq 1 ]; then
        say "The database role split is NOT confirmed on the restored database: treat the ledger as not protected from the daemon's role, and expect propolis.service to refuse to start if the owner role's migration did not run. To put the split back: stop propolis, repeat the step that moves ownership (\`propolis migrate --init-roles\`, docs/operations/database-roles.md step 3; it is safe to repeat, and it is what a dump from before the split needs), then run \`propolis-migrate\` and \`propolis-migrate --check\`."
    fi
    if [ "$daemon" -eq 1 ]; then
        say "Trying to start the services again; check \`systemctl --failed\`."
    else
        say "Starting the sensors, the gateway and the shipper, not propolis.service; check \`systemctl --failed\`."
    fi
    for unit in "${SENSORS[@]}" gateway propolis shipper; do
        if [ "$unit" = propolis ] && [ "$daemon" -eq 0 ]; then
            continue
        fi
        unit_enabled "$unit.service" && systemctl start "$unit.service" 2>/dev/null || true
    done
    # Last, where it is read: on such a node this is why the daemon did not come back.
    if [ "$ROLES_BY_HAND" -eq 1 ]; then
        roles_caveat
    fi
    return 0
}
trap on_exit EXIT
# A signal ends the run the way a failed step does, through the EXIT trap, with a status that says
# so. Bash runs these once the command it is waiting for has ended: a hangup from a dropped
# terminal reaches that command too and ends it, and a signal sent to this script alone is acted
# on when the step in progress finishes.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# verify_set SETDIR DUMP IDENTITY: refuses unless the set is what the backup wrote and its dump can
# be read. Run while every service is still up: found at the restore step instead, a damaged set
# or a wrong identity leaves the services stopped and the live database already renamed aside.
verify_set() {
    local setdir="$1" dump="$2" identity="$3" name status
    name="${dump##*/}"
    if [ -f "$setdir/SHA256SUMS" ]; then
        # The digests are of the files as the backup stored them. A dump the file does not list is
        # not one of those (a plaintext copy decrypted next to the encrypted one, say), and a
        # check that passes without covering the file about to be restored proves nothing.
        awk -v name="$name" '$2 == name || $2 == "*" name { found = 1 } END { exit !found }' "$setdir/SHA256SUMS" || {
            echo "error: $setdir/SHA256SUMS does not list $name, so that file is not one the backup wrote there; move it out of the set, or restore by hand (docs/operations/backup-and-restore.md)" >&2
            exit 1
        }
        (cd "$setdir" && sha256sum --check --strict --quiet SHA256SUMS >&2) || {
            echo "error: $setdir does not match its SHA256SUMS (see above): the set is damaged or was changed after the backup wrote it" >&2
            exit 1
        }
    else
        echo "    $setdir has no SHA256SUMS (a set from before backups recorded one), so its files cannot be verified against their digests"
    fi
    if [[ "$dump" == *.age ]]; then
        # pg_restore stops reading where the table of contents ends. The rest is drained so that
        # age decrypts and authenticates the whole file and exits on its own verdict: cut off
        # mid-write it reports a failure for a good dump, and a truncated file would pass.
        status=(0 0)
        age --decrypt -i "$identity" "$dump" | {
            listed=0
            runuser -u postgres -- pg_restore --list > /dev/null || listed=$?
            cat > /dev/null
            [ "$listed" -eq 0 ]
        } || status=("${PIPESTATUS[@]}")
        [ "${status[0]}" -eq 0 ] || {
            echo "error: $identity does not decrypt $dump, or the file is damaged (age's own message is above)" >&2
            exit 1
        }
        [ "${status[1]}" -eq 0 ] || {
            echo "error: $dump decrypts, but pg_restore cannot list it: it is not a readable dump" >&2
            exit 1
        }
    else
        runuser -u postgres -- pg_restore --list < "$dump" > /dev/null || {
            echo "error: pg_restore cannot list $dump: it is not a readable dump" >&2
            exit 1
        }
    fi
}

# check_free_space DB BYTES: the restore loads a second copy of the database while the current one
# is kept aside, so the volume PostgreSQL stores its data on needs at least the current size free.
# The dump restores to about the size it was taken at, which the current size stands in for.
# Advisory: where either number cannot be read it says so and lets the rollback go on, because a
# server that will not tell its data directory is no reason to refuse a rollback that has room.
check_free_space() {
    local db="$1" size="$2" datadir avail=""
    datadir="$(runuser -u postgres -- psql -X -A -t -c 'SHOW data_directory' 2>/dev/null)" || datadir=""
    if [[ "$datadir" == /* ]]; then
        avail="$(df --output=avail -B1 -- "$datadir" 2>/dev/null | tail -n 1 | tr -d ' ')" || avail=""
    fi
    # At most 18 digits each, so the comparison stays inside bash's 64-bit arithmetic.
    if ! [[ "$size" =~ ^[0-9]{1,18}$ && "$avail" =~ ^[0-9]{1,18}$ ]]; then
        echo "    free space could not be checked (the size of database $db or the space free where PostgreSQL keeps its data could not be read); going on without that check"
        return 0
    fi
    if [ "$avail" -lt "$size" ]; then
        echo "error: the restore needs room for a second copy of database $db while the current one is kept aside: it is $size bytes and the volume holding $datadir has $avail bytes free. Free space there (a ${db}_before_rollback_* database from an earlier rollback that is no longer needed is one place to find it), or restore by hand (docs/operations/backup-and-restore.md)" >&2
        exit 1
    fi
}

# What a node with split database roles has to be told when the kept release is from before
# `propolis migrate`: that release cannot put the split back, and its daemon cannot run under it.
# Said when it is found and again as the last thing the run prints, whichever way the run ends.
roles_caveat() {
    say "WARNING: this node splits its database roles and the kept release is from before \`propolis migrate\`."
    say "    The split was NOT re-applied or checked. That release's daemon migrates as the role it connects"
    say "    as, which owns nothing in the database, so ownership has to be handed back by hand before it"
    say "    can start: docs/operations/database-roles.md, \"Going back to one role\"."
}

# After the restore, on a node that splits its database roles (migrate.env names an owner role):
# the dump brings table ownership and grants back, but not everything the split rests on, and
# nothing has yet asked the restored database whether the daemon's role is confined in it. Every
# step runs before any service starts and any of them failing fails the rollback.
#
# - A dump taken before the node split its roles has every table owned by the daemon's role. The
#   owner role cannot migrate that, and the daemon cannot either any more, because it does not own
#   the new database. The split's own first step (`propolis migrate --init-roles`, as the postgres
#   superuser) hands those tables to the owner role; it is one transaction and safe to repeat.
# - The owner role's migration run then sets the daemon role's grants again.
# - `propolis-migrate --check` asks, as the daemon's role, whether the schema is current.
# - Last, the script asks PostgreSQL itself whether that role controls the ledger table, owns the
#   database or may create in the ledger's schema. The check above is made by the kept release's
#   binary, and a release from before that binary learned to look at the database's owner calls a
#   database owned by the daemon's role protected.
restore_role_split() {
    local helper="$ROOT/usr/local/sbin/propolis-migrate" bin="$ROOT/usr/local/bin/propolis"
    local event_owner socket sockdir port confined
    [ "$SPLIT" -eq 1 ] || return 0
    # The same test propolis-migrate makes: a binary from before the subcommand would take
    # `migrate` for nothing and start the daemon, as root.
    if ! grep -q -a -F 'usage: propolis migrate' "$bin"; then
        ROLES_BY_HAND=1
        roles_caveat
        return 0
    fi
    echo "==> putting the database role split back and checking it"
    ROLES_UNCHECKED=1
    STEP="reading who owns the restored ledger"
    event_owner="$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 -d "$DB" \
        -c "SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = to_regclass('event')")"
    if [ "$event_owner" = "$ROLE" ]; then
        echo "    the dump is from before the roles were split (role $ROLE owns its tables): moving them to $OWNER_ROLE, as the split's first step does"
        STEP="moving the restored tables to the owner role (propolis migrate --init-roles)"
        # The superuser connects the way psql just did: over the server's own socket, which the
        # server names. The first directory it listens in and its port make the URL.
        socket="$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 \
            -c "SELECT current_setting('unix_socket_directories'), current_setting('port')")"
        sockdir="${socket%%|*}"
        sockdir="${sockdir%%,*}"
        port="${socket##*|}"
        [[ "$sockdir" =~ ^/[A-Za-z0-9_./-]+$ ]] && [[ "$port" =~ ^[0-9]{1,5}$ ]] || {
            echo "error: PostgreSQL's socket directory and port could not be read ('$socket'), so the step that moves ownership cannot be run from here" >&2
            exit 1
        }
        runuser -u postgres -- env "PROPOLIS_ADMIN_DATABASE_URL=postgres://postgres@${sockdir//\//%2F}:$port/$DB" \
            "$bin" migrate --init-roles --owner "$OWNER_ROLE" --runtime "$ROLE"
    fi
    STEP="re-applying the database role split (propolis-migrate)"
    PROPOLIS_MIGRATE_ROOT="$ROOT" PROPOLIS_BIN="$bin" "$helper"
    STEP="checking the database role split (propolis-migrate --check)"
    PROPOLIS_MIGRATE_ROOT="$ROOT" PROPOLIS_BIN="$bin" "$helper" --check
    STEP="checking that the daemon's role is confined in the restored database"
    confined="$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 -d "$DB" \
        -c "SELECT (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = '$ROLE') OR pg_has_role('$ROLE', c.relowner, 'USAGE'), (SELECT pg_has_role('$ROLE', d.datdba, 'USAGE') FROM pg_database d WHERE d.datname = current_database()), has_schema_privilege('$ROLE', c.relnamespace, 'CREATE') FROM pg_class c WHERE c.oid = to_regclass('event')")"
    if [ "$confined" != "f|f|f" ]; then
        echo "error: in the restored database the daemon's role $ROLE is not confined. Asked whether it controls the ledger table, owns the database, or may create in the ledger's schema, PostgreSQL answered '$confined' (each should be f), whatever the kept release's own check printed above." >&2
        exit 1
    fi
    ROLES_UNCHECKED=0
}

restore() {
    require_root
    local with_db=0 yes=0 identity="$ROOT/etc/propolis/backup-identity.txt" release=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --with-database) with_db=1 ;;
            --yes) yes=1 ;;
            --identity) identity="${2:-}"; [ -n "$identity" ] || usage; shift ;;
            --*) usage ;;
            *) [ -z "$release" ] || usage; release="$1" ;;
        esac
        shift
    done
    if [ -z "$release" ]; then
        release="$(list_names | tail -n 1)"
        [ -n "$release" ] || { echo "error: no kept releases in $STORE" >&2; exit 1; }
    fi
    [[ "$release" =~ $RELEASE_RE ]] || { echo "error: not a kept release name: $release" >&2; exit 2; }
    local dir="$STORE/$release"
    [ -d "$dir" ] || { echo "error: $dir does not exist (see $0 --list)" >&2; exit 1; }
    local commit set dump="" db="" owner="" size="" role="" owner_url="" owner_said="" name_re='^[a-z_][a-z0-9_]*$'
    commit="$(field commit "$dir/manifest")"
    set="$(field backup_set "$dir/manifest")"

    if [ "$with_db" -eq 1 ]; then
        [ -n "$set" ] || { echo "error: $release kept no pre-upgrade backup, so there is no database to restore" >&2; exit 1; }
        local setdir="$ROOT/var/backups/propolis/$set"
        if [ -f "$setdir/propolis.dump" ]; then
            dump="$setdir/propolis.dump"
        elif [ -f "$setdir/propolis.dump.age" ]; then
            dump="$setdir/propolis.dump.age"
            [ -r "$identity" ] || { echo "error: $dump is encrypted; give the age identity with --identity FILE" >&2; exit 1; }
            command -v age >/dev/null || { echo "error: age is not installed" >&2; exit 1; }
        else
            echo "error: the pre-upgrade backup $setdir is gone" >&2
            exit 1
        fi
        id -u postgres >/dev/null 2>&1 || { echo "error: no local postgres user; restore the database by hand (docs/operations/backup-and-restore.md)" >&2; exit 1; }
        # Asked of the database with the binary installed NOW (the release being rolled back
        # from, which has pg-exec), before anything is stopped, so a missing URL or an odd name
        # refuses while the box still runs.
        DATABASE_URL="$(env_value DATABASE_URL)"
        [ -n "$DATABASE_URL" ] || { echo "error: no DATABASE_URL in $ROOT/etc/propolis/propolis.env" >&2; exit 1; }
        export DATABASE_URL
        db="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_database()')"
        # The new database gets the owner this one has, not the role DATABASE_URL connects as.
        # Where the roles are split those differ: the daemon's role owning the database is the
        # split undone, and nothing in a dump puts a database's owner back.
        owner="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()')" || owner=""
        size="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT pg_database_size(current_database())' 2>/dev/null)" || size=""
        role="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_user' 2>/dev/null)" || role=""
        unset DATABASE_URL
        [ -n "$owner" ] || { echo "error: could not read which role owns database '$db', so the restored one cannot be given the same owner; restore by hand" >&2; exit 1; }
        [[ "$db" =~ $name_re ]] && [[ "$owner" =~ $name_re ]] || {
            echo "error: database '$db' or its owner '$owner' is not a plain name; restore by hand" >&2; exit 1; }
        # A node that splits its database roles. Putting the split back after the restore needs
        # both role names and an owner role that can connect, so both are read now, while a
        # wrong answer can still refuse with everything running. The owner's URL goes to the
        # binary in its environment, as propolis-migrate passes it, never on a command line.
        if PROPOLIS_MIGRATE_ROOT="$ROOT" "$ROOT/usr/local/sbin/propolis-migrate" --configured 2>/dev/null; then
            SPLIT=1
            ROLE="$role"
            owner_url="$(env_value PROPOLIS_MIGRATE_DATABASE_URL "$ROOT/etc/propolis/migrate.env")"
            # What psql said goes to a variable, not the screen, and is shown only in the refusal:
            # a URL psql cannot be handed (pg-exec takes fewer settings than the daemon's own
            # connection does) is a different thing to fix from a role that cannot log in.
            owner_said=""
            OWNER_ROLE="$(DATABASE_URL="$owner_url" "$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_user' 2>/dev/null)" || {
                OWNER_ROLE=""
                owner_said="$(DATABASE_URL="$owner_url" "$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_user' 2>&1 >/dev/null | head -n 3 | tr '\n' ' ')" || true
            }
            [[ "$ROLE" =~ $name_re ]] && [[ "$OWNER_ROLE" =~ $name_re ]] && [ "$ROLE" != "$OWNER_ROLE" ] || {
                echo "error: this node splits its database roles (migrate.env names an owner role), but the two roles could not be read as two different plain names: the daemon connects as '$ROLE' and the owner's URL as '$OWNER_ROLE'." >&2
                [ -z "$owner_said" ] || echo "Connecting with the owner's URL said: $owner_said" >&2
                echo "The split cannot be put back after a restore unless this script can connect as the owner role: check the URL in migrate.env (\`propolis-migrate --check\` shows the daemon's side; this script reads the role through psql, which takes fewer URL settings than propolis-migrate does), or restore by hand (docs/operations/backup-and-restore.md)" >&2
                exit 1
            }
            # The database belonging to the daemon's role is the split already undone, which is
            # what this script did on such a node before it kept the owner. Recreating it for
            # that role would keep it undone, and a kept release from before `propolis migrate
            # --check` looked at the database's owner would call the result protected.
            if [ "$owner" = "$ROLE" ] && grep -q -a -F 'usage: propolis migrate' "$dir/bin/propolis" 2>/dev/null; then
                echo "    database '$db' belongs to '$ROLE', the role the daemon connects as: the role split is undone on this node. The restored database is created for the owner role, '$OWNER_ROLE', instead."
                owner="$OWNER_ROLE"
            fi
        fi
        echo "==> checking the pre-upgrade backup $set and the room to restore it (nothing is stopped yet)"
        check_free_space "$db" "$size"
        verify_set "$setdir" "$dump" "$identity"
    fi

    echo "Rolling back to $release (commit $commit)."
    [ "$with_db" -eq 1 ] && echo "The database goes back to $set; the current one is renamed aside, not dropped."
    if [ "$yes" -ne 1 ]; then
        local answer
        read -r -p "Type the release name to continue: " answer
        [ "$answer" = "$release" ] || { echo "not confirmed; nothing changed"; exit 1; }
    fi

    echo "==> stopping services"
    STOPPED=1
    STEP="stopping services"
    # The backup too: a nightly dump holding a connection would make the rename below fail, and a
    # rolled-back release may have no backup helper at all.
    systemctl stop propolis-backup.timer propolis-backup.service 2>/dev/null || true
    for unit in shipper gateway propolis "${SENSORS[@]}"; do
        unit_enabled "$unit.service" && systemctl stop "$unit.service"
    done

    echo "==> putting the kept binaries, helpers and units back"
    STEP="putting the kept files back"
    shopt -s nullglob
    for f in "$dir"/bin/*; do install -m 0755 "$f" "$ROOT/usr/local/bin/$(basename "$f")"; done
    for f in "$dir"/sbin/*; do install -m 0755 "$f" "$ROOT/usr/local/sbin/$(basename "$f")"; done
    for f in "$dir"/units/*; do install -m 0644 "$f" "$ROOT/etc/systemd/system/$(basename "$f")"; done
    shopt -u nullglob
    [ -f "$dir/deploy-stamp.json" ] && install -m 0644 "$dir/deploy-stamp.json" "$ROOT/var/lib/propolis/deploy-stamp.json"
    systemctl daemon-reload

    if [ "$with_db" -eq 1 ]; then
        echo "==> restoring the database from $set"
        STEP="renaming the current database aside"
        local aside
        aside="${db}_before_rollback_$(date -u +%Y%m%d%H%M%S)"
        DB="$db"
        ASIDE="$aside"
        runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
            -c "ALTER DATABASE \"$db\" RENAME TO \"$aside\""
        STEP="creating the empty database"
        runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
            -c "CREATE DATABASE \"$db\" OWNER \"$owner\" TEMPLATE template0"
        STEP="restoring the dump"
        if [[ "$dump" == *.age ]]; then
            age --decrypt -i "$identity" "$dump" | runuser -u postgres -- pg_restore --exit-on-error --dbname="$db"
        else
            runuser -u postgres -- pg_restore --exit-on-error --dbname="$db" < "$dump"
        fi
        RESTORED=1
        restore_role_split
    fi

    # A release from before the nightly backup has no helper to run it, and its propolis binary no
    # pg-exec: the newer script would start that binary as the daemon. Off until upgraded again.
    STEP="setting the backup timer"
    if [ -e "$dir/sbin/propolis-backup" ]; then
        unit_enabled propolis-backup.timer && systemctl start propolis-backup.timer
    else
        systemctl disable --now propolis-backup.timer 2>/dev/null || true
        echo "    the kept release predates the nightly backup: propolis-backup.timer is disabled until the next upgrade"
    fi

    echo "==> starting services"
    STEP="starting services"
    for unit in "${SENSORS[@]}"; do
        unit_enabled "$unit.service" && systemctl start "$unit.service"
    done
    unit_enabled gateway.service && systemctl start gateway.service
    systemctl start propolis.service
    unit_enabled shipper.service && systemctl start shipper.service

    STEP="waiting for propolis.service"
    local up=0 wait="${PROPOLIS_ROLLBACK_WAIT_SECS:-30}"
    [[ "$wait" =~ ^[0-9]{1,4}$ ]] || wait=30
    for _ in $(seq 1 $(( (wait + 1) / 2 ))); do
        sleep 2
        if systemctl is-active --quiet propolis.service; then up=1; break; fi
    done
    if [ "$up" -eq 0 ]; then
        echo "error: propolis.service did not stay up after the rollback" >&2
        if [ "$with_db" -eq 0 ] && journalctl -u propolis.service --since "-5min" --no-pager 2>/dev/null \
            | grep -q -i 'migration'; then
            echo "The journal names a migration: the upgrade changed the schema. Run again with --with-database." >&2
        fi
        exit 1
    fi
    STOPPED=0
    echo "Rolled back to $release (commit $commit)."
    [ -n "$ASIDE" ] && echo "The database from before the rollback is kept as $ASIDE; drop it once you are satisfied."
    [ "$ROLES_BY_HAND" -eq 1 ] && roles_caveat
    return 0
}

case "${1:-}" in
    --save) shift; save "$@" ;;
    --list) list ;;
    *) restore "$@" ;;
esac
