#!/usr/bin/env bash
#
# In-place upgrade: pull, build, replace binaries, reinstall unit files + logrotate policy,
# daemon-reload, restart services.
# Safe to run on a live node - restarts are sequenced: sensors, then gateway, propolis, and the
# shipper last. Not for a split deployment's collector, which must not run propolis: see
# docs/operations/split-deployment.md. Runs deploy/provision.sh itself before restarting
# anything, so a directory or user a change added since the last install/upgrade (e.g. a new
# sensor's spool dir) always exists before the unit that needs it restarts - no longer assumes
# install.sh already provisioned it.
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

# bash reads this file incrementally and the pull below can replace it on disk, so everything
# after the pull would otherwise run from the copy loaded BEFORE it: a release that changes this
# script (a new binary in the list below, a new step) would half-apply, building the new tree but
# installing from the old list. If the pull changed this file, run the new one instead. The guard
# variable makes that second run skip the pull (so it cannot loop, and cannot move the tree again
# mid-upgrade) and carries the pull timestamp across, so the deploy stamp still records when the
# pull happened rather than when the re-exec did. deploy_test.rs runs this block against stubs.
# BEGIN pull-and-reexec
echo "==> pulling latest"
if [ -n "${PROPOLIS_UPGRADE_REEXEC:-}" ]; then
    PULLED_AT="${PROPOLIS_UPGRADE_PULLED_AT:?PROPOLIS_UPGRADE_REEXEC is set without PROPOLIS_UPGRADE_PULLED_AT}"
    echo "    already pulled by the run that re-executed this script"
else
    PULLED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    SCRIPT_SUM_BEFORE="$(sha256sum < "$SCRIPT_DIR/upgrade.sh")"
    sudo -u "$(stat -c '%U' "$REPO_DIR")" git pull
    SCRIPT_SUM_AFTER="$(sha256sum < "$SCRIPT_DIR/upgrade.sh")"
    if [ "$SCRIPT_SUM_BEFORE" != "$SCRIPT_SUM_AFTER" ]; then
        echo "==> deploy/upgrade.sh changed in the pull, re-executing the new version"
        export PROPOLIS_UPGRADE_REEXEC=1 PROPOLIS_UPGRADE_PULLED_AT="$PULLED_AT"
        exec "$BASH" "$SCRIPT_DIR/upgrade.sh" "$@"
    fi
fi
# END pull-and-reexec

echo "==> building release"
sudo -u "$(stat -c '%U' "$REPO_DIR")" cargo build --release --workspace --locked

echo "==> installing binaries"
# SP-A (collector/control-plane split): gateway and shipper are new binaries alongside the
# sensors and the unified daemon. A single-box migration installs and restarts every unit on this
# one host, so this list covers both topologies at once - a box running only the collector role
# (or only the control-plane role) simply has no unit file for the other side's binaries and the
# is-enabled guard below skips restarting what was never enabled.
INSTALL_BINS=(propolis sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred gateway shipper propolis-watch)
for bin in "${INSTALL_BINS[@]}"; do
    if [ ! -x "$BUILD_DIR/$bin" ]; then
        echo "error: $BUILD_DIR/$bin was not built; the install list names a binary the workspace does not produce" >&2
        exit 1
    fi
    install -m 0755 "$BUILD_DIR/$bin" "/usr/local/bin/$bin"
done
# Re-read the destination rather than trust the loop: a binary missing from /usr/local/bin is a
# service that fails to start after the restarts below, which is too late to be the first notice.
for bin in "${INSTALL_BINS[@]}"; do
    if [ ! -x "/usr/local/bin/$bin" ]; then
        echo "error: /usr/local/bin/$bin is missing or not executable after the install" >&2
        exit 1
    fi
done

echo "==> ensuring dirs and users (provision.sh, idempotent)"
"$SCRIPT_DIR/provision.sh"

# After provision.sh (needs /etc/propolis/tls) and the binary install above, before the unit
# install and every restart, so a sensor restarted below with a *_TLS_BIND finds its pair.
echo "==> minting per-sensor TLS certificates (provision-tls.sh, idempotent)"
PROVISION_CERTS_BIN="$BUILD_DIR/provision-certs" "$SCRIPT_DIR/provision-tls.sh"

# Before the restarts, because the units read this file at start. Derived from the sensors' own
# bind variables rather than hand-maintained in propolis.env, so the fleet pane describes the
# listeners this box actually runs; see fleet-listeners.sh's header.
echo "==> deriving the fleet listener inventory"
"$SCRIPT_DIR/fleet-listeners.sh"

# Unit files and the logrotate policy are deliverables of a release just like the binaries: a
# hardening directive, a new ReadWritePaths grant, or a changed ExecStart merged to main never
# reached a box that was only ever upgraded, because this script used to reinstall binaries and
# restart units while systemd kept running the definitions from the last fresh install. The
# production list mirrors install.sh's step 5 (deploy_test.rs cross-checks the two). gateway and
# shipper units are operator-installed per role (split deployment), so they are refreshed only
# where they are already enabled, matching the is-enabled restart guards below.
echo "==> installing systemd units and logrotate config"
for unit in propolis.service sensor-catchall.service sensor-ssh.service sensor-telnet.service sensor-redis.service sensor-adb.service sensor-http.service sensor-ftp.service sensor-smtp.service sensor-tftp.service sensor-mqtt.service sensor-dns.service sensor-cred.service; do
    install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
done
for unit in gateway.service shipper.service; do
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
    fi
done
install -m 0644 "$SCRIPT_DIR/logrotate-sensors.conf" /etc/logrotate.d/propolis-sensors
# The policy's prerotate hook calls the guard, so it ships with the policy; a missing guard would
# fail every rotation closed.
install -m 0755 "$SCRIPT_DIR/logrotate-guard.sh" /usr/local/sbin/propolis-logrotate-guard
# Propolis rotates its own logs on its own timer rather than trusting the distro's logrotate.timer,
# which sat inactive for eleven days in October 2026 while a sensor log grew to 6.6 GB. Installed
# unconditionally (no env file or role decides it) and enabled after the reload below.
for unit in propolis-logrotate.service propolis-logrotate.timer; do
    install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
done

# After every step that can fail (the build, and every install above), and before the restarts, so
# the console reads it as soon as it comes back up. Recording it any earlier - this used to run
# right after the build, before the binaries were even copied - meant a failed or partial install
# loop still left a stamp claiming this checkout as deployed, which is worse than no stamp: it
# reports success for a deploy that did not finish. `deploy-stamp.sh` also reads each installed
# binary's own `--version` output here, which is the only source that describes the actual bytes
# now on disk rather than what this checkout merely intended to build - see that script's own
# `installed_sha` comment.
echo "==> recording the deploy stamp"
PROPOLIS_DEPLOY_PULLED_AT="$PULLED_AT" "$SCRIPT_DIR/deploy-stamp.sh" "$REPO_DIR"

# Before any restart, or the restarts would start the OLD unit definitions.
echo "==> reloading systemd unit files"
systemctl daemon-reload

# Idempotent: enabling an enabled timer is a no-op, and --now starts it if something stopped it.
# Before the restarts so a failure here (set -e) aborts before any service is bounced.
echo "==> enabling the log rotation timer"
systemctl enable --now propolis-logrotate.timer

echo "==> restarting sensors"
for unit in sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred; do
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

# Last, and report-only: the upgrade has finished by now, so a finding here is something to read
# and act on, not a reason to call the upgrade failed. config-check.sh compares what is configured
# with what is running; see docs/operations/service-lifecycle.md, "Configuration check".
echo "==> configuration check (report only; it cannot fail the upgrade)"
"$SCRIPT_DIR/config-check.sh" --report-only || echo "warning: config-check.sh itself failed to run; run it by hand: $SCRIPT_DIR/config-check.sh"
