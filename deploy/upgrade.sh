#!/usr/bin/env bash
#
# In-place upgrade: pull, build, replace binaries, reinstall unit files + logrotate policy,
# daemon-reload, restart services.
# Safe to run on a live node - restarts are sequenced (propolis last so sensors
# can reconnect). Runs deploy/provision.sh itself before restarting anything, so a directory or
# user a change added since the last install/upgrade (e.g. a new sensor's spool dir) always exists
# before the unit that needs it restarts - no longer assumes install.sh already provisioned it.
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
# SP-A (collector/control-plane split): gateway and shipper are new binaries alongside the
# sensors and the unified daemon. A single-box migration installs and restarts every unit on this
# one host, so this list covers both topologies at once - a box running only the collector role
# (or only the control-plane role) simply has no unit file for the other side's binaries and the
# is-enabled guard below skips restarting what was never enabled.
for bin in propolis sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-cred gateway shipper; do
    install -m 0755 "$BUILD_DIR/$bin" "/usr/local/bin/$bin"
done

echo "==> ensuring dirs and users (provision.sh, idempotent)"
"$SCRIPT_DIR/provision.sh"

# Unit files and the logrotate policy are deliverables of a release just like the binaries: a
# hardening directive, a new ReadWritePaths grant, or a changed ExecStart merged to main never
# reached a box that was only ever upgraded, because this script used to reinstall binaries and
# restart units while systemd kept running the definitions from the last fresh install. The
# production list mirrors install.sh's step 5 (deploy_test.rs cross-checks the two). gateway and
# shipper units are operator-installed per role (split deployment), so they are refreshed only
# where they are already enabled, matching the is-enabled restart guards below.
echo "==> installing systemd units and logrotate config"
for unit in propolis.service sensor-catchall.service sensor-ssh.service sensor-telnet.service sensor-redis.service sensor-adb.service sensor-http.service sensor-ftp.service sensor-smtp.service sensor-cred.service; do
    install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
done
for unit in gateway.service shipper.service; do
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
    fi
done
install -m 0644 "$SCRIPT_DIR/logrotate-sensors.conf" /etc/logrotate.d/propolis-sensors

# Before any restart, or the restarts would start the OLD unit definitions.
echo "==> reloading systemd unit files"
systemctl daemon-reload

echo "==> restarting sensors"
for unit in sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-cred; do
    if systemctl is-enabled --quiet "$unit.service" 2>/dev/null; then
        systemctl restart "$unit.service"
    fi
done

# gateway is control-plane-side but must come up BEFORE shipper (collector-side, restarted last of
# all below): shipper dials the gateway on every batch send, so restarting shipper first would
# have it retry/backoff against a gateway that is mid-restart. On a single-box migration all of
# sensors/gateway/propolis/shipper run on the same host; on a split deployment each box only has
# the units relevant to its own role, so this ordering is a no-op there beyond what is-enabled
# already skips.
echo "==> restarting gateway"
if systemctl is-enabled --quiet gateway.service 2>/dev/null; then
    systemctl restart gateway.service
fi

echo "==> restarting propolis (runs migrations)"
systemctl restart propolis.service

echo "==> restarting shipper (after gateway, so it dials a gateway that is already up)"
if systemctl is-enabled --quiet shipper.service 2>/dev/null; then
    systemctl restart shipper.service
fi

echo "==> done. checking status"
sleep 2
systemctl --no-pager status propolis.service | head -5
