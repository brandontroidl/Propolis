#!/usr/bin/env bash
#
# Mints one self-signed TLS pair per TLS-capable sensor into /etc/propolis/tls, then reasserts
# ownership and mode. Idempotent: provision-certs --sensor-tls skips a sensor whose cert AND key
# already exist, which is also how an operator-supplied real certificate survives a re-run.
#
# Separate from provision.sh because it needs the release binary, and install.sh provisions before
# it installs binaries while upgrade.sh installs first. The directory itself (0711 root:root) is
# created by provision.sh; run that first.
#
# The chown/chmod run on EVERY invocation, not only after a mint: provision-certs runs as root, so
# a pair minted by an interrupted earlier run is root-owned 0600 and the sensor could not read it,
# and a skip-if-exists run must still repair that.
#
# Usage: sudo ./provision-tls.sh                       (provisions for real)
#        DRY_RUN=1 ./provision-tls.sh                  (prints every action; no privilege or binary needed)
# Environment:
#   PROVISION_CERTS_BIN   provision-certs binary (default <repo>/target/release/provision-certs)

set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVISION_CERTS_BIN="${PROVISION_CERTS_BIN:-$SCRIPT_DIR/../target/release/provision-certs}"
TLS_DIR=/etc/propolis/tls
TLS_SENSORS=(http mqtt redis smtp ftp cred dns)

log() { printf '==> %s\n' "$*"; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run]'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (try: sudo $0)" >&2
    exit 1
fi

if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$PROVISION_CERTS_BIN" ]; then
    echo "error: $PROVISION_CERTS_BIN not found or not executable - run 'cargo build --release' first" >&2
    exit 1
fi

log "minting per-sensor TLS certificates into $TLS_DIR"
run "$PROVISION_CERTS_BIN" --sensor-tls "$TLS_DIR" "${TLS_SENSORS[@]}"

# Reassert ownership/mode on the minted regular files only. A path that is a SYMLINK is operator
# supplied (they pointed us at a real cert elsewhere): never chown/chmod through it, which would
# mutate the target outside $TLS_DIR. Skip it and leave the operator to manage its permissions.
for sensor in "${TLS_SENSORS[@]}"; do
    for spec in "$sensor.key:0600" "$sensor.crt:0644"; do
        path="$TLS_DIR/${spec%:*}"
        mode="${spec##*:}"
        if [ -L "$path" ]; then
            log "skipping $path: symlink (operator-managed); not following it to chown/chmod its target"
            continue
        fi
        run chown "propolis-$sensor:propolis-$sensor" "$path"
        run chmod "$mode" "$path"
    done
done
