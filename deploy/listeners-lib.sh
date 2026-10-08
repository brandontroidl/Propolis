#!/usr/bin/env bash
#
# Shared by fleet-listeners.sh and config-check.sh: the ONE derivation of which listeners the
# sensor env files configure. Sourced, never executed; it sets no shell options and defines
# functions only.
#
# WHY A LIBRARY. The fleet inventory and the deploy configuration check must agree on what is
# supposed to be listening. Two copies of the variable table would drift, and the drift would be
# silent: a sensor missing from one view and present in the other looks like a runtime fault, not
# a script bug. Both callers consume derive_listeners and apply their own validation to the result.
#
# The caller sets ENV_DIR (the directory holding the sensor env files) before calling anything, and
# runs with `shopt -s nullglob` so an ENV_DIR with no *.env file expands to nothing.

# The last assignment of NAME across the files given, ignoring commented-out lines and stripping
# one layer of surrounding quotes. Empty output means "not configured" (or no file readable).
read_env_var_in() {
    local name="$1" value
    shift
    if [ "$#" -eq 0 ]; then
        return 0
    fi
    value="$(grep -hE "^[[:space:]]*${name}=" "$@" 2>/dev/null | tail -n 1 || true)"
    value="${value#*=}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
    printf '%s' "$value"
}

# The same, across every *.env in ENV_DIR: how the sensors' binds are found.
read_env_var() {
    local files
    files=("$ENV_DIR"/*.env)
    read_env_var_in "$1" "${files[@]}"
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

# Prints one tab-separated line per configured listener:
#   sensor  proto  port  bind-address  variable
# in the order the fleet inventory has always listed them. `sensor` is the sensor's own
# self-reported name (what lands in event.sensor), which for sensor-cred is the protocol name, not
# the PROPOLIS_SENSOR_LOGS label; the mapping mirrors crates/sensor-cred/src/main.rs's own table.
# `port` is whatever followed the last colon and is NOT validated here: fleet-listeners.sh drops
# an unusable one, config-check.sh reports it.
derive_listeners() {
    local pair var sensor addr port catchall catchall_var
    local catchall_addrs=()

    # One TCP listener per variable: BIND_VAR:sensor-name.
    for pair in \
        PROPOLIS_SSH_BIND:ssh \
        PROPOLIS_TELNET_BIND:telnet \
        PROPOLIS_REDIS_BIND:redis \
        PROPOLIS_REDIS_TLS_BIND:redis \
        PROPOLIS_ADB_BIND:adb \
        PROPOLIS_HTTP_BIND:http \
        PROPOLIS_HTTP_TLS_BIND:http \
        PROPOLIS_FTP_BIND:ftp \
        PROPOLIS_FTP_TLS_BIND:ftp \
        PROPOLIS_SMTP_BIND:smtp \
        PROPOLIS_SMTP_SUBMISSION_BIND:smtp \
        PROPOLIS_SMTP_TLS_BIND:smtp \
        PROPOLIS_MQTT_BIND:mqtt \
        PROPOLIS_MQTT_TLS_BIND:mqtt \
        PROPOLIS_DNS_TLS_BIND:dns \
        PROPOLIS_CRED_VNC_BIND:vnc \
        PROPOLIS_CRED_MYSQL_BIND:mysql \
        PROPOLIS_CRED_MSSQL_BIND:mssql \
        PROPOLIS_CRED_PG_BIND:postgresql \
        PROPOLIS_CRED_MONGO_BIND:mongodb; do
        var="${pair%%:*}"
        sensor="${pair##*:}"
        addr="$(read_env_var "$var")"
        [ -n "$addr" ] || continue
        printf '%s\t%s\t%s\t%s\t%s\n' "$sensor" tcp "$(port_of "$addr")" "$addr" "$var"
    done

    # sensor-tftp is the one UDP-only listener: a single request socket, so one udp entry.
    addr="$(read_env_var PROPOLIS_TFTP_BIND)"
    if [ -n "$addr" ]; then
        printf '%s\t%s\t%s\t%s\t%s\n' tftp udp "$(port_of "$addr")" "$addr" PROPOLIS_TFTP_BIND
    fi

    # sensor-dns binds UDP and TCP on the same address (RFC 7766 makes TCP mandatory) and refuses
    # to start unless both bind, so one variable yields two listeners.
    addr="$(read_env_var PROPOLIS_DNS_BIND)"
    if [ -n "$addr" ]; then
        port="$(port_of "$addr")"
        printf '%s\t%s\t%s\t%s\t%s\n' dns udp "$port" "$addr" PROPOLIS_DNS_BIND
        printf '%s\t%s\t%s\t%s\t%s\n' dns tcp "$port" "$addr" PROPOLIS_DNS_BIND
    fi

    # sensor-catchall takes a comma-separated list and binds BOTH TCP and UDP for every entry, so
    # each port yields two listeners. It also still reads the deprecated bare spelling of its own
    # variable (crates/sensor-catchall/src/main.rs's env_var fallback), and a box using that
    # spelling must not silently produce an inventory with no catch-all in it.
    catchall_var=PROPOLIS_CATCHALL_BIND_ADDRS
    catchall="$(read_env_var "$catchall_var")"
    if [ -z "$catchall" ]; then
        catchall_var=CATCHALL_BIND_ADDRS
        catchall="$(read_env_var "$catchall_var")"
    fi
    if [ -n "$catchall" ]; then
        IFS=',' read -r -a catchall_addrs <<<"$catchall"
        for addr in "${catchall_addrs[@]}"; do
            addr="${addr#"${addr%%[![:space:]]*}"}"
            addr="${addr%"${addr##*[![:space:]]}"}"
            [ -n "$addr" ] || continue
            port="$(port_of "$addr")"
            printf '%s\t%s\t%s\t%s\t%s\n' catchall tcp "$port" "$addr" "$catchall_var"
            printf '%s\t%s\t%s\t%s\t%s\n' catchall udp "$port" "$addr" "$catchall_var"
        done
    fi
}
