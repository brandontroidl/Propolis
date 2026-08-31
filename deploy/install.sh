#!/usr/bin/env bash
#
# Propolis fresh-node install script.
#
# internal/design/07-runtime-coordination-deployment.md's "Install script": provisions OS users,
# directories, log paths, spool mount points, and systemd units for a fresh node. Idempotent (safe
# to re-run - every step below converges on the same end state whether the previous run left it
# half-done, fully done, or never started). Installs only the PRODUCTION deployment surface:
#
#   - deploy/propolis.service                        (the unified daemon)
#   - deploy/sensor-catchall.service, deploy/sensor-ssh.service   (unchanged from sub-project 2)
#   - deploy/sensor-{telnet,redis,adb,http,ftp,smtp,cred}.service (sub-project 8 sensors)
#
# deploy/intake.service, deploy/review.service, deploy/feed.service, and deploy/console.service are
# deliberately NOT installed here - internal/design/07-runtime-coordination-deployment.md's "What
# gets retired": those four standalone units are superseded by propolis.service in production and
# stay in the repo for development/testing only.
#
# This script does NOT:
#   - start or enable any service (`systemctl enable --now <unit>` is an operator action, taken
#     only after reviewing the populated env files).
#   - create, seed, or migrate the PostgreSQL database. The propolis binary runs its own migrations
#     (core-scoring + review) at startup once DATABASE_URL is reachable; provisioning the database
#     server itself is an independent operator/DBA action.
#   - create or edit any /etc/propolis/*.env file. Each one carries secrets (a database URL, the
#     console password, vendor API keys) this script has no business fabricating or touching -
#     internal/design/07-runtime-coordination-deployment.md's "Unified configuration" documents the
#     full variable set the operator must populate by hand.
#   - programmatically create the quarantine-spool noexec,nosuid,nodev mounts. Sizing and backing a
#     real mount (tmpfs budget vs. a dedicated partition) is a host-specific decision no generic
#     script can make safely - see step 3 below, which creates the directories and prints the
#     fstab lines the operator still needs to add.
#
# Usage: sudo ./install.sh [--dry-run]
#   --dry-run   Print every action this script would take without touching the system. Needs no
#               privilege and does not require the release binaries to already be built.
#               crates/sensor-framework/tests/deploy_test.rs runs this mode in CI to exercise the
#               script's full control flow without requiring root.

set -euo pipefail

# ---- args ----

DRY_RUN=0
if [ "$#" -gt 1 ]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
elif [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
elif [ -n "${1:-}" ]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/../target/release}"

log() { printf '==> %s\n' "$*"; }

# Executes "$@" for real, or prints it under --dry-run. Every mutating command in this script goes
# through this wrapper so the two modes can never drift apart.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run]'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

# ---- 0. privilege check ----

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (try: sudo $0)" >&2
    exit 1
fi

# ---- 1, 2 & 3. users, directories, and spool mountpoints (provisioning: see deploy/provision.sh) ----

# Shared with upgrade.sh so both entry points provision users/dirs through one idempotent routine
# - see provision.sh's own header for why. Prints its own "1/7 creating OS users" /
# "2/7 creating directories" / "3/7 creating spool directories" progress lines (verbatim from this
# script's former inline blocks), so nothing further is logged here.
run_provision() { DRY_RUN="$DRY_RUN" "$SCRIPT_DIR/provision.sh"; }
run_provision

cat <<'EOF'
    NOT DONE BY THIS SCRIPT - back each spool directory with a noexec,nosuid,nodev mount before
    production use, e.g. in /etc/fstab:

        tmpfs /var/spool/propolis/catchall tmpfs noexec,nosuid,nodev,size=256M 0 0
        tmpfs /var/spool/propolis/ssh      tmpfs noexec,nosuid,nodev,size=256M 0 0
        tmpfs /var/spool/propolis/adb      tmpfs noexec,nosuid,nodev,size=256M 0 0
        tmpfs /var/spool/propolis/ftp      tmpfs noexec,nosuid,nodev,size=256M 0 0
        tmpfs /var/spool/propolis/telnet   tmpfs noexec,nosuid,nodev,size=256M 0 0
        tmpfs /var/spool/propolis/fetched  tmpfs noexec,nosuid,nodev,size=1200M 0 0
        tmpfs /var/lib/propolis/spool      tmpfs noexec,nosuid,nodev,size=256M 0 0

    Size each mount for the expected upload/sample volume; a dedicated backing partition works
    identically (replace the tmpfs line with the partition's device and fstype). Run `mount -a`
    after editing fstab, then confirm with `findmnt <path>` that noexec,nosuid,nodev are actually
    in effect - a directory alone is one chmod away from being wrong.

    /var/spool/propolis/fetched needs its own sizing thought: its global byte budget
    (FETCH_SPOOL_GLOBAL_BUDGET in crates/propolis/src/main.rs) is 1 GB, so its mount must be sized
    at least that large or the OS hits ENOSPC before the daemon's own budget check reports a
    clean error - see INSTALL.md's "malware fetcher" section for the full sizing/retention
    tradeoff (tmpfs is RAM-backed and does not survive a reboot; use a persistent partition
    instead if fetched samples must survive one).
EOF

# ---- 4. binaries ----

log "4/7 installing binaries to /usr/local/bin"
for bin in propolis sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-cred; do
    src="$BUILD_DIR/$bin"
    dst="/usr/local/bin/$bin"
    if [ "$DRY_RUN" -eq 1 ]; then
        run install -m 0755 "$src" "$dst"
        continue
    fi
    if [ ! -x "$src" ]; then
        echo "error: $src not found or not executable - run 'cargo build --release' first" >&2
        exit 1
    fi
    install -m 0755 "$src" "$dst"
done

# ---- 5. systemd units ----

log "5/7 installing systemd units"
for unit in propolis.service sensor-catchall.service sensor-ssh.service sensor-telnet.service sensor-redis.service sensor-adb.service sensor-http.service sensor-ftp.service sensor-smtp.service sensor-cred.service; do
    run install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
done

# ---- 6. logrotate config ----

log "6/7 installing logrotate config"
run install -m 0644 "$SCRIPT_DIR/logrotate-sensors.conf" /etc/logrotate.d/propolis-sensors

# ---- 7. reload systemd ----

log "7/7 reloading systemd unit files"
run systemctl daemon-reload

if [ "$DRY_RUN" -eq 1 ]; then
    log "dry-run complete - no changes were made."
else
    log "done. Services are installed but NOT started or enabled, and the database is untouched."
    log "Next: populate /etc/propolis/*.env files, then 'systemctl enable --now <unit>' per service."
fi
