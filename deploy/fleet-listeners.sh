#!/usr/bin/env bash
#
# Derives PROPOLIS_FLEET_LISTENERS from the sensors' own bind variables and writes it to a file
# the propolis and console units load.
#
# WHY THIS EXISTS. The fleet pane needs to know which listeners are supposed to exist, and nothing
# on the control plane can discover that: no sensor has a compiled-in port, the daemon binds none
# of them, and every bind lives in a per-sensor env file (one systemd unit, one OS user, one env
# file per sensor). A hand-maintained second copy of the list in propolis.env would be a copy that
# drifts from the sensors it claims to describe, and the drift would be invisible - a listener
# quietly missing from the pane looks exactly like a listener that was never configured. Deriving
# it at deploy time from the same files the sensors read leaves drift possible only BETWEEN
# deploys, and a sensor whose events arrive while it is absent from the inventory shows up on the
# pane as `undeclared listener` rather than not at all.
#
# WHY A SEPARATE FILE, not an edit to propolis.env. install.sh's own header states that it never
# creates or edits an /etc/propolis/*.env file: those carry secrets (the database URL, the console
# password, vendor API keys) no script has business rewriting in place. This writes only a file it
# owns, containing one derived, non-secret value. propolis.service and console.service load it
# BEFORE their operator-owned env file, so an explicit operator setting still wins.
#
# The listener NAME is the sensor's own self-reported name, which is what lands in `event.sensor` -
# not the PROPOLIS_SENSOR_LOGS label. sensor-cred reports its five protocols individually, so its
# names are vnc/mysql/mssql/postgresql/mongodb while its log labels are cred-vnc and so on. The
# mapping below mirrors crates/sensor-cred/src/main.rs's own table.
#
# Usage: fleet-listeners.sh [ENV_DIR] [OUT_FILE]
#   ENV_DIR    directory holding the sensor env files   (default /etc/propolis)
#   OUT_FILE   file to write                            (default $ENV_DIR/fleet-listeners.env)
# Environment:
#   PROPOLIS_FLEET_COLLECTOR_ID   collector id to stamp on each entry (default "local")
#
# Idempotent, and safe on a node where no sensor env file exists yet: it writes a header-only file
# and the pane then reports every check as unknown, which is the truth.

set -euo pipefail
shopt -s nullglob

ENV_DIR="${1:-/etc/propolis}"
OUT_FILE="${2:-$ENV_DIR/fleet-listeners.env}"
COLLECTOR_ID="${PROPOLIS_FLEET_COLLECTOR_ID:-local}"

# The last assignment of NAME across every *.env in ENV_DIR, ignoring commented-out lines and
# stripping one layer of surrounding quotes. Empty output means "not configured".
read_env_var() {
    local name="$1" files value
    files=("$ENV_DIR"/*.env)
    if [ "${#files[@]}" -eq 0 ]; then
        return 0
    fi
    value="$(grep -hE "^[[:space:]]*${name}=" "${files[@]}" 2>/dev/null | tail -n 1 || true)"
    value="${value#*=}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
    printf '%s' "$value"
}

# The port half of a bind address. Handles 0.0.0.0:22 and [::]:22 alike by taking everything after
# the last colon; a value with no colon is not an address and yields nothing.
port_of() {
    local addr="$1"
    case "$addr" in
        *:*) printf '%s' "${addr##*:}" ;;
        *) return 0 ;;
    esac
}

ENTRIES=()

add_entry() {
    local sensor="$1" proto="$2" port="$3"
    case "$port" in
        '' | *[!0-9]*) return 0 ;;
    esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 0
    fi
    ENTRIES+=("$COLLECTOR_ID/$sensor/$proto/$port")
}

# One TCP listener per variable: BIND_VAR:sensor-name.
for pair in \
    PROPOLIS_SSH_BIND:ssh \
    PROPOLIS_TELNET_BIND:telnet \
    PROPOLIS_REDIS_BIND:redis \
    PROPOLIS_ADB_BIND:adb \
    PROPOLIS_HTTP_BIND:http \
    PROPOLIS_FTP_BIND:ftp \
    PROPOLIS_SMTP_BIND:smtp \
    PROPOLIS_CRED_VNC_BIND:vnc \
    PROPOLIS_CRED_MYSQL_BIND:mysql \
    PROPOLIS_CRED_MSSQL_BIND:mssql \
    PROPOLIS_CRED_PG_BIND:postgresql \
    PROPOLIS_CRED_MONGO_BIND:mongodb; do
    var="${pair%%:*}"
    sensor="${pair##*:}"
    addr="$(read_env_var "$var")"
    [ -n "$addr" ] || continue
    add_entry "$sensor" tcp "$(port_of "$addr")"
done

# sensor-catchall takes a comma-separated list and binds BOTH TCP and UDP for every entry, so each
# port yields two listeners. It also still reads the deprecated bare spelling of its own variable
# (crates/sensor-catchall/src/main.rs's env_var fallback), and a box using that spelling must not
# silently produce an inventory with no catch-all in it.
catchall="$(read_env_var PROPOLIS_CATCHALL_BIND_ADDRS)"
if [ -z "$catchall" ]; then
    catchall="$(read_env_var CATCHALL_BIND_ADDRS)"
fi
if [ -n "$catchall" ]; then
    IFS=',' read -r -a catchall_addrs <<<"$catchall"
    for addr in "${catchall_addrs[@]}"; do
        addr="${addr#"${addr%%[![:space:]]*}"}"
        addr="${addr%"${addr##*[![:space:]]}"}"
        [ -n "$addr" ] || continue
        port="$(port_of "$addr")"
        add_entry catchall tcp "$port"
        add_entry catchall udp "$port"
    done
fi

TMP_FILE="$OUT_FILE.tmp.$$"
{
    echo "# Generated by deploy/fleet-listeners.sh - do not edit."
    echo "# Derived from the sensor bind variables in $ENV_DIR at deploy time. Re-run install.sh,"
    echo "# upgrade.sh, or this script after changing a sensor's bind, or the fleet pane will"
    echo "# describe the listeners of the previous deploy."
    if [ "${#ENTRIES[@]}" -gt 0 ]; then
        printf 'PROPOLIS_FLEET_LISTENERS='
        printf '%s' "${ENTRIES[0]}"
        for entry in "${ENTRIES[@]:1}"; do
            printf ',%s' "$entry"
        done
        printf '\n'
    else
        echo "# No sensor bind variables found, so no listener inventory is asserted here. The"
        echo "# fleet pane reports every check as unknown rather than reporting nothing at all."
    fi
} >"$TMP_FILE"
chmod 0644 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUT_FILE"

echo "==> wrote $OUT_FILE (${#ENTRIES[@]} listeners derived from $ENV_DIR)"
