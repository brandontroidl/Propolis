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
# empty one is created and the dump is restored into it by the documented procedure
# (docs/operations/backup-and-restore.md, "Restore procedure"). Drop the renamed one yourself once
# you are satisfied. It needs PostgreSQL on this host (it runs psql and pg_restore as the
# postgres user); restore a remote database by hand with that page. An encrypted dump needs the
# age identity that decrypts it, by --identity or /etc/propolis/backup-identity.txt.
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

env_value() {
    local file="$ROOT/etc/propolis/propolis.env" v
    [ -r "$file" ] || return 0
    v="$(sed -n "s/^$1=//p" "$file" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    printf '%s' "$v"
}

# Set once services are stopped: a failure from then on must say what state the box is in, and
# tries to bring the services back rather than leave a honeypot dark.
STOPPED=0
STEP=""
ASIDE=""
on_exit() {
    local code=$?
    [ "$code" -ne 0 ] && [ "$STOPPED" -eq 1 ] || return 0
    echo "error: the rollback failed while $STEP, after the services were stopped." >&2
    if [ -n "$ASIDE" ]; then
        echo "The database from before the rollback was renamed to $ASIDE; nothing was dropped." >&2
    fi
    echo "Trying to start the services again; check \`systemctl --failed\`." >&2
    for unit in "${SENSORS[@]}" gateway propolis shipper; do
        unit_enabled "$unit.service" && systemctl start "$unit.service" 2>/dev/null || true
    done
    return 0
}
trap on_exit EXIT

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
    local commit set dump="" db="" role=""
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
        role="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_user')"
        unset DATABASE_URL
        [[ "$db" =~ ^[a-z_][a-z0-9_]*$ ]] && [[ "$role" =~ ^[a-z_][a-z0-9_]*$ ]] || {
            echo "error: database '$db' or role '$role' is not a plain name; restore by hand" >&2; exit 1; }
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
        runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
            -c "ALTER DATABASE \"$db\" RENAME TO \"$aside\""
        ASIDE="$aside"
        STEP="creating the empty database"
        runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
            -c "CREATE DATABASE \"$db\" OWNER \"$role\" TEMPLATE template0"
        STEP="restoring the dump"
        if [[ "$dump" == *.age ]]; then
            age --decrypt -i "$identity" "$dump" | runuser -u postgres -- pg_restore --exit-on-error --dbname="$db"
        else
            runuser -u postgres -- pg_restore --exit-on-error --dbname="$db" < "$dump"
        fi
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
    return 0
}

case "${1:-}" in
    --save) shift; save "$@" ;;
    --list) list ;;
    *) restore "$@" ;;
esac
