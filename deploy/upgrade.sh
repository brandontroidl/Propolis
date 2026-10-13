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
# Usage: sudo ./deploy/upgrade.sh [--accept-origin]
#   --accept-origin   deploy from the origin URL the checkout has NOW although it differs from the
#                     one the last deploy recorded; this run's deploy stamp records the new one.
#
# What gets built and installed as root is whatever the pull brings in, so the pull is held to the
# checks in the pull-and-reexec block below: a clean tree, the origin the last deploy recorded, a
# fast-forward of origin/main, and, when /etc/propolis/upgrade-signers exists, a commit signed by
# one of the SSH keys in it. The checks hold against the remote and against operator mistakes,
# not against the checkout's owner account: that account builds the binaries root installs
# unchanged, so it is trusted by construction. See docs/operations/upgrade-rollback-and-dr.md,
# "What the pull trusts".
#
# PROPOLIS_UPGRADE_ROOT reads the deploy stamp and the signers file under that directory instead
# of / (tests, like rollback.sh's PROPOLIS_ROLLBACK_ROOT).

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
ACCEPT_ORIGIN=0
for arg in "$@"; do
    case "$arg" in
        --accept-origin) ACCEPT_ORIGIN=1 ;;
        *) echo "usage: $0 [--accept-origin]" >&2; exit 2 ;;
    esac
done
ROOT="${PROPOLIS_UPGRADE_ROOT:-}"
STAMP_FILE="$ROOT/var/lib/propolis/deploy-stamp.json"
SIGNERS_FILE="$ROOT/etc/propolis/upgrade-signers"
REPO_OWNER="$(stat -c '%U' "$REPO_DIR")"
# Every git command runs as the checkout's owner, like the build: the fetch needs the owner's
# credentials, and git refuses root a directory someone else owns.
as_owner() { sudo -u "$REPO_OWNER" "$@"; }
stamp_field() {
    [ -r "$STAMP_FILE" ] || return 0
    sed -n "s/.*\"$1\": \"\\([^\"]*\\)\".*/\\1/p" "$STAMP_FILE" | head -n 1 || true
}
# A key that is present but empty means the last deploy could not read the value, which is not
# the same as a stamp written before the field existed; the origin check treats the two apart.
stamp_has_field() { [ -r "$STAMP_FILE" ] && grep -q "\"$1\":" "$STAMP_FILE"; }
# The userinfo part of an https URL can be a token; the stamp is world-readable, so it records
# and compares the URL without it. deploy-stamp.sh strips it the same way.
strip_userinfo() { sed 's#^\([a-z][a-z0-9+.-]*://\)[^/@]*@#\1#'; }
refuse() {
    echo "error: $1" >&2
    shift
    [ "$#" -eq 0 ] || printf '%s\n' "$@" >&2
    echo "the upgrade stops here: nothing was built or installed" >&2
    exit 1
}

echo "==> pulling latest"
if [ -n "${PROPOLIS_UPGRADE_REEXEC:-}" ]; then
    PULLED_AT="${PROPOLIS_UPGRADE_PULLED_AT:?PROPOLIS_UPGRADE_REEXEC is set without PROPOLIS_UPGRADE_PULLED_AT}"
    # The run that re-executed this one may predate the origin check (a box upgrading from a
    # release without it) and then carries no origin; reading it here is not a check, the pull
    # already happened, it only keeps the stamp this run writes complete.
    ORIGIN_URL="${PROPOLIS_UPGRADE_ORIGIN_URL:-}"
    if [ -z "$ORIGIN_URL" ]; then
        ORIGIN_URL="$(as_owner git remote get-url origin 2>/dev/null | strip_userinfo || true)"
    fi
    echo "    already pulled by the run that re-executed this script"
else
    PULLED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    SCRIPT_SUM_BEFORE="$(sha256sum < "$SCRIPT_DIR/upgrade.sh")"

    # An operator's uncommitted edit would otherwise be built and installed as root as though it
    # had been reviewed and merged. Untracked files count: a build can pick those up too. The
    # untracked mode is pinned so the owner's status.showUntrackedFiles cannot narrow the check;
    # ignored paths (target/, .env) are outside it either way.
    DIRTY="$(as_owner git status --porcelain --untracked-files=normal)"
    if [ -n "$DIRTY" ]; then
        refuse "the checkout has local changes, which a root-installed build must not include:" \
            "$DIRTY" "commit, stash or discard them, then run the upgrade again"
    fi

    # The remote is box-local git config, so a remote that moved since the last deploy is a
    # decision for the operator (a mistyped set-url, a mispointed clone), never something this
    # script discovers by building from it: the deploy stamp remembers where that deploy pulled
    # from. This holds against operator mistakes, not against the owner account, which can edit
    # the stamp's source of truth (the build) directly.
    if ! ORIGIN_URL="$(as_owner git remote get-url origin 2>/dev/null)"; then
        refuse "the checkout has no origin remote, so there is nothing to pull from" \
            "add one (git remote add origin <url>) and run again with --accept-origin"
    fi
    case "$ORIGIN_URL" in
        *'"'* | *\\*)
            refuse "the origin URL contains a quote or backslash, which the deploy stamp cannot record" ;;
    esac
    ORIGIN_URL="$(printf '%s' "$ORIGIN_URL" | strip_userinfo)"
    RECORDED_ORIGIN="$(stamp_field origin_url)"
    if [ "$ACCEPT_ORIGIN" -eq 1 ]; then
        echo "    --accept-origin: pulling from $ORIGIN_URL; this run's deploy stamp records it"
    elif ! stamp_has_field origin_url; then
        echo "    no deploy has recorded an origin yet; this run's deploy stamp records $ORIGIN_URL"
    elif [ -z "$RECORDED_ORIGIN" ]; then
        # The field is there and empty: the last deploy ran deploy-stamp.sh where git could not
        # read the checkout (root, with sudo's SUDO_UID naming an account other than the owner).
        # Proceeding would keep the check unarmed on every later upgrade without a word.
        refuse "the last deploy recorded an empty origin, so this upgrade cannot check the checkout's ($ORIGIN_URL) against it" \
            "run again with --accept-origin to record it; this script now records the origin it reads as the owner"
    elif [ "$ORIGIN_URL" != "$RECORDED_ORIGIN" ]; then
        refuse "the checkout's origin is $ORIGIN_URL but the last deploy pulled from $RECORDED_ORIGIN" \
            "if the move is deliberate, run again with --accept-origin (or re-run install.sh) to record the new origin"
    fi

    # Opt-in: the file's presence turns verification on, and from then on an origin/main without
    # an SSH signature by a listed key is refused. The file must be a regular file, root's and
    # writable by no one else, so that no other non-root account can list its own key (the owner
    # account needs no such route: it builds what root installs). Checked before the remote is
    # contacted, like the origin, so a broken policy file refuses without any network activity.
    if [ -e "$SIGNERS_FILE" ] || [ -L "$SIGNERS_FILE" ]; then
        if [ -L "$SIGNERS_FILE" ]; then
            refuse "$SIGNERS_FILE is a symbolic link; the signers file must be a regular file root owns"
        fi
        if [ -z "$ROOT" ] && [ "$(stat -c '%u' "$SIGNERS_FILE")" != 0 ]; then
            refuse "$SIGNERS_FILE is not owned by root"
        fi
        if [ -n "$(find "$SIGNERS_FILE" -maxdepth 0 -perm /022)" ]; then
            refuse "$SIGNERS_FILE is writable by its group or others (expected 0644)"
        fi
    fi

    as_owner git fetch origin

    # Resolved once, so the commit every check below looks at is the commit that gets merged: a
    # fetch from elsewhere (the owner's editor, a cron job, a second operator) between the checks
    # could otherwise move origin/main under them. A remote with no main branch is the usual
    # reason for a missing ref, and it must not be reported as a signature or ancestry failure.
    if ! TARGET="$(as_owner git rev-parse --verify --quiet 'refs/remotes/origin/main^{commit}')"; then
        refuse "the fetch from $ORIGIN_URL brought no origin/main, so there is nothing to upgrade to" \
            "the remote has no main branch, or the clone's fetch refspec does not include it"
    fi

    if [ -e "$SIGNERS_FILE" ]; then
        echo "    verifying origin/main ($TARGET) against the signers in $SIGNERS_FILE"
        # gpg.format picks the SIGNING format only; verification picks its backend from the
        # signature itself, so a PGP-signed commit would be handed to gpg with the owner's keyring,
        # which the signers file does not govern (any imported key, such as GitHub's web-flow key,
        # would then pass). Both other backends are pointed at /bin/false so only an SSH signature
        # can verify, and the SSH backend is pinned so the owner's gitconfig cannot replace it.
        if ! as_owner git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$SIGNERS_FILE" \
            -c gpg.ssh.program=ssh-keygen -c gpg.program=/bin/false -c gpg.x509.program=/bin/false \
            verify-commit "$TARGET"; then
            refuse "origin/main ($TARGET) is not SSH-signed by a key in $SIGNERS_FILE, so it will not be deployed" \
                "sign the commit with a listed SSH key, add the key to the file, or remove the file to deploy unsigned commits"
        fi
    fi

    # Only ever move forward onto what main has: a commit on this box that main lacks would be
    # merged into a root-installed build and would also never match the deploy stamp.
    if ! as_owner git merge-base --is-ancestor HEAD "$TARGET"; then
        refuse "this checkout is not an ancestor of origin/main ($TARGET), so the upgrade cannot fast-forward" \
            "commits here that origin/main does not have:" \
            "$(as_owner git log --oneline "$TARGET..HEAD")" \
            "reset the checkout to origin/main (or merge the commits into main) and run again"
    fi
    as_owner git merge --ff-only "$TARGET"
    SCRIPT_SUM_AFTER="$(sha256sum < "$SCRIPT_DIR/upgrade.sh")"
    if [ "$SCRIPT_SUM_BEFORE" != "$SCRIPT_SUM_AFTER" ]; then
        echo "==> deploy/upgrade.sh changed in the pull, re-executing the new version"
        export PROPOLIS_UPGRADE_REEXEC=1 PROPOLIS_UPGRADE_PULLED_AT="$PULLED_AT" \
            PROPOLIS_UPGRADE_ORIGIN_URL="$ORIGIN_URL"
        exec "$BASH" "$SCRIPT_DIR/upgrade.sh" "$@"
    fi
fi
# END pull-and-reexec

echo "==> building release"
as_owner cargo build --release --workspace --locked

# SP-A (collector/control-plane split): gateway and shipper are new binaries alongside the
# sensors and the unified daemon. A single-box migration installs and restarts every unit on this
# one host, so this list covers both topologies at once - a box running only the collector role
# (or only the control-plane role) simply has no unit file for the other side's binaries and the
# is-enabled guard below skips restarting what was never enabled.
INSTALL_BINS=(propolis sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred gateway shipper propolis-watch)

# Before anything is installed, so a failure here (set -e) leaves the box exactly as it was, and
# before propolis restarts, so the dump is of the schema the running release knows: migrations run
# only when the new daemon starts. This is the database deploy/rollback.sh --with-database puts
# back. The backup runs the binary just built (PROPOLIS_BIN): the installed one is the previous
# release, which may predate `propolis pg-exec`.
# BEGIN pre-upgrade
echo "==> backing up before the upgrade"
# The kept release records the set THIS run wrote, read back from the status file and accepted
# only when it is new: a run that wrote none (skipped, or nothing configured yet) records none,
# never an older set that would roll the database back past an earlier upgrade.
BACKUP_STATUS=/var/lib/propolis/backup-status/last-success
set_in_status() { sed -n 's/.*"set":"\([^"]*-pre-upgrade\)".*/\1/p' "$BACKUP_STATUS" 2>/dev/null || true; }
PRE_UPGRADE_SET=""
if [ "${PROPOLIS_UPGRADE_SKIP_BACKUP:-0}" = 1 ]; then
    echo "    skipped (PROPOLIS_UPGRADE_SKIP_BACKUP=1): this upgrade keeps no database to roll back to"
else
    before="$(set_in_status)"
    PROPOLIS_BIN="$BUILD_DIR/propolis" "$SCRIPT_DIR/backup.sh" --reason pre-upgrade
    after="$(set_in_status)"
    if [ -n "$after" ] && [ "$after" != "$before" ]; then
        PRE_UPGRADE_SET="$after"
    fi
fi
echo "==> keeping the running release for rollback (deploy/rollback.sh)"
"$SCRIPT_DIR/rollback.sh" --save --backup-set "$PRE_UPGRADE_SET" "${INSTALL_BINS[@]}"
# END pre-upgrade

echo "==> installing binaries"
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
# The nightly backup, installed and enabled the same way (after the reload below).
install -m 0755 "$SCRIPT_DIR/backup.sh" /usr/local/sbin/propolis-backup
for unit in propolis-backup.service propolis-backup.timer; do
    install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
done
# Every Propolis unit names this in OnFailure=; installed with them, nothing to enable.
install -m 0755 "$SCRIPT_DIR/alert.sh" /usr/local/sbin/propolis-alert
# The off-host pull's forced command; inert until the operator adds a key for propolis-backup-pull.
install -m 0755 "$SCRIPT_DIR/backup-serve.sh" /usr/local/sbin/propolis-backup-serve
install -m 0644 "$SCRIPT_DIR/propolis-alert@.service" /etc/systemd/system/propolis-alert@.service

# After every step that can fail (the build, and every install above), and before the restarts, so
# the console reads it as soon as it comes back up. Recording it any earlier - this used to run
# right after the build, before the binaries were even copied - meant a failed or partial install
# loop still left a stamp claiming this checkout as deployed, which is worse than no stamp: it
# reports success for a deploy that did not finish. `deploy-stamp.sh` also reads each installed
# binary's own `--version` output here, which is the only source that describes the actual bytes
# now on disk rather than what this checkout merely intended to build - see that script's own
# `installed_sha` comment. The origin is handed over rather than read again there: deploy-stamp.sh
# runs as root, which git refuses the owner's checkout unless sudo's SUDO_UID happens to name the
# owner, and an origin it could not read would be recorded as empty and refused next time.
echo "==> recording the deploy stamp"
PROPOLIS_DEPLOY_PULLED_AT="$PULLED_AT" PROPOLIS_DEPLOY_ORIGIN_URL="$ORIGIN_URL" \
    "$SCRIPT_DIR/deploy-stamp.sh" "$REPO_DIR" "$STAMP_FILE"

# Before any restart, or the restarts would start the OLD unit definitions.
echo "==> reloading systemd unit files"
systemctl daemon-reload

# Idempotent: enabling an enabled timer is a no-op, and --now starts it if something stopped it.
# Before the restarts so a failure here (set -e) aborts before any service is bounced.
echo "==> enabling the log rotation and backup timers"
systemctl enable --now propolis-logrotate.timer
systemctl enable --now propolis-backup.timer

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
