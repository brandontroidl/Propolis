#!/usr/bin/env bash
#
# Keep the running release before an upgrade replaces it, and put it back on request.
#
#   rollback.sh --save BIN...    upgrade.sh runs this before installing anything: copies the named
#                                binaries from /usr/local/bin, the Propolis unit files from
#                                /etc/systemd/system, the propolis-* helpers from /usr/local/sbin,
#                                and the deploy stamp into /var/lib/propolis/rollback/<release>/,
#                                with the pre-upgrade backup set upgrade.sh just wrote. Keeps 3.
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
SBIN_HELPERS=(propolis-backup propolis-logrotate-guard)
SENSORS=(sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred)

usage() {
    cat >&2 <<EOF
usage: $0 --save BIN...
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
    [ "$#" -gt 0 ] || usage
    local sha name partial stamp set=""
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
    # The pre-upgrade backup upgrade.sh took moments ago, if it took one.
    local status="$ROOT/var/lib/propolis/backup-status/last-success"
    if [ -f "$status" ]; then
        set="$(sed -n 's/.*"set":"\([^"]*\)".*/\1/p' "$status")"
        [[ "$set" =~ $SET_RE ]] || set=""
    fi
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
    local commit set dump=""
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
    fi

    echo "Rolling back to $release (commit $commit)."
    [ "$with_db" -eq 1 ] && echo "The database goes back to $set; the current one is renamed aside, not dropped."
    if [ "$yes" -ne 1 ]; then
        local answer
        read -r -p "Type the release name to continue: " answer
        [ "$answer" = "$release" ] || { echo "not confirmed; nothing changed"; exit 1; }
    fi

    echo "==> stopping services"
    for unit in shipper gateway propolis "${SENSORS[@]}"; do
        unit_enabled "$unit.service" && systemctl stop "$unit.service"
    done

    echo "==> putting the kept binaries, helpers and units back"
    shopt -s nullglob
    for f in "$dir"/bin/*; do install -m 0755 "$f" "$ROOT/usr/local/bin/$(basename "$f")"; done
    for f in "$dir"/sbin/*; do install -m 0755 "$f" "$ROOT/usr/local/sbin/$(basename "$f")"; done
    for f in "$dir"/units/*; do install -m 0644 "$f" "$ROOT/etc/systemd/system/$(basename "$f")"; done
    shopt -u nullglob
    [ -f "$dir/deploy-stamp.json" ] && install -m 0644 "$dir/deploy-stamp.json" "$ROOT/var/lib/propolis/deploy-stamp.json"
    systemctl daemon-reload

    local aside=""
    if [ "$with_db" -eq 1 ]; then
        echo "==> restoring the database from $set"
        local db role
        db="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_database()')"
        role="$("$ROOT/usr/local/bin/propolis" pg-exec psql -X -A -t -c 'SELECT current_user')"
        [[ "$db" =~ ^[a-z_][a-z0-9_]*$ ]] && [[ "$role" =~ ^[a-z_][a-z0-9_]*$ ]] || {
            echo "error: database '$db' or role '$role' is not a plain name; restore by hand" >&2; exit 1; }
        aside="${db}_before_rollback_$(date -u +%Y%m%d%H%M%S)"
        runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 \
            -c "ALTER DATABASE \"$db\" RENAME TO \"$aside\"" \
            -c "CREATE DATABASE \"$db\" OWNER \"$role\" TEMPLATE template0"
        if [[ "$dump" == *.age ]]; then
            age --decrypt -i "$identity" "$dump" | runuser -u postgres -- pg_restore --exit-on-error --dbname="$db"
        else
            runuser -u postgres -- pg_restore --exit-on-error --dbname="$db" < "$dump"
        fi
    fi

    echo "==> starting services"
    for unit in "${SENSORS[@]}"; do
        unit_enabled "$unit.service" && systemctl start "$unit.service"
    done
    unit_enabled gateway.service && systemctl start gateway.service
    systemctl start propolis.service
    unit_enabled shipper.service && systemctl start shipper.service

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
    echo "Rolled back to $release (commit $commit)."
    [ -n "$aside" ] && echo "The database from before the rollback is kept as $aside; drop it once you are satisfied."
    return 0
}

case "${1:-}" in
    --save) shift; save "$@" ;;
    --list) list ;;
    *) restore "$@" ;;
esac
