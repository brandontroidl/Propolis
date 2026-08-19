#!/usr/bin/env bash
#
# In-place upgrade: pull, build, replace binaries, restart services.
# Safe to run on a live node - restarts are sequenced (propolis last so sensors
# can reconnect). Assumes install.sh has already run once.
#
# Usage: sudo ./deploy/upgrade.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (try: sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_DIR/target/release"

cd "$REPO_DIR"

echo "==> pulling latest"
sudo -u "$(stat -c '%U' "$REPO_DIR")" git pull

echo "==> building release"
sudo -u "$(stat -c '%U' "$REPO_DIR")" cargo build --release

echo "==> installing binaries"
for bin in propolis sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-cred; do
    install -m 0755 "$BUILD_DIR/$bin" "/usr/local/bin/$bin"
done

echo "==> restarting sensors"
for unit in sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-cred; do
    if systemctl is-enabled --quiet "$unit.service" 2>/dev/null; then
        systemctl restart "$unit.service"
    fi
done

echo "==> restarting propolis (runs migrations)"
systemctl restart propolis.service

echo "==> done. checking status"
sleep 2
systemctl --no-pager status propolis.service | head -5
