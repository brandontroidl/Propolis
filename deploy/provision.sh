#!/usr/bin/env bash
#
# Propolis idempotent provisioning: OS users + directories.
#
# Extracted verbatim from install.sh so both install.sh (fresh install) and upgrade.sh (in-place
# upgrade) run the identical provisioning routine. Before this script existed, a directory a change
# added (e.g. SP-B-1c's /var/spool/propolis/telnet) landed only in install.sh's inline block and
# was never created on an upgrade - a sensor whose unit file grants ReadWritePaths on that
# directory then crash-loops under ProtectSystem=strict on the next restart, because the bind-mount
# target does not exist. Now both entry points call this one script, so a new required directory
# only ever needs to be declared here once.
#
# Idempotent and safe to re-run on a live box: users are skip-if-exists; `install -d` reasserts
# mode/owner/group on directories that already exist (see ensure_dir below).
#
# This script does NOT start, enable, restart, or stop any service, and does NOT touch env files or
# binaries - provisioning only.
#
# Usage: sudo ./provision.sh          (provisions for real)
#        DRY_RUN=1 ./provision.sh     (prints every action without touching the system; no
#                                       privilege needed)

set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"

log() { printf '==> %s\n' "$*"; }

# Executes "$@" for real, or prints it under DRY_RUN=1. Every mutating command in this script goes
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

# ---- 1. users ----

ensure_user() {
    local name="$1"
    if id -u "$name" >/dev/null 2>&1; then
        log "user $name already exists"
    else
        run useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$name"
        [ "$DRY_RUN" -eq 1 ] || log "created user $name"
    fi
}

log "1/7 creating OS users"
ensure_user propolis
ensure_user propolis-catchall
ensure_user propolis-ssh
ensure_user propolis-telnet
ensure_user propolis-redis
ensure_user propolis-adb
ensure_user propolis-http
ensure_user propolis-ftp
ensure_user propolis-smtp
ensure_user propolis-cred

# propolis reads all sensors' logs (ReadOnlyPaths=/var/log/propolis in propolis.service). The
# files themselves are group-readable (UMask=0027 in sensor units), so propolis needs
# supplementary membership in each sensor's own group.
run usermod -aG propolis-catchall,propolis-ssh,propolis-telnet,propolis-redis,propolis-adb,propolis-http,propolis-ftp,propolis-smtp,propolis-cred propolis

# ---- 2. directories ----

ensure_dir() {
    local path="$1" mode="$2" owner="$3" group="$4"
    # install -d, unlike mkdir -p -m, reasserts mode/owner/group even when the directory already
    # exists - verified empirically (GNU coreutils 9.7: a 777 directory re-run through
    # `install -d -m 0750` comes back 0750; `mkdir -p -m 0750` on the same directory leaves it
    # untouched). That is what makes this idempotent and self-correcting rather than
    # create-once-and-hope.
    run install -d -m "$mode" -o "$owner" -g "$group" "$path"
}

log "2/7 creating directories"
ensure_dir /etc/propolis                  0755 root              root
ensure_dir /var/log/propolis              0755 root              root
ensure_dir /var/log/propolis/catchall     0750 propolis-catchall propolis-catchall
ensure_dir /var/log/propolis/ssh          0750 propolis-ssh      propolis-ssh
ensure_dir /var/log/propolis/telnet      0750 propolis-telnet   propolis-telnet
ensure_dir /var/log/propolis/redis       0750 propolis-redis    propolis-redis
ensure_dir /var/log/propolis/adb         0750 propolis-adb      propolis-adb
ensure_dir /var/log/propolis/http        0750 propolis-http     propolis-http
ensure_dir /var/log/propolis/ftp         0750 propolis-ftp      propolis-ftp
ensure_dir /var/log/propolis/smtp        0750 propolis-smtp     propolis-smtp
ensure_dir /var/log/propolis/cred        0750 propolis-cred     propolis-cred
# root-owned, NOT propolis: write permission on this directory would let a compromised propolis
# daemon unlink/rename any child regardless of the child's own owner - including the sibling
# /var/lib/propolis/ssh host-key dir (propolis-ssh), which it could swap for a symlink that
# sensor-ssh.service's ProtectSystem=strict bind-mount would then follow. propolis writes only into
# its own children below (cursors/, feed/, spool/), never this shared root, so it loses nothing.
ensure_dir /var/lib/propolis              0755 root              root
ensure_dir /var/lib/propolis/cursors      0750 propolis          propolis
# 0755, not cursors' 0750: this is feed's PUBLIC output tree (see deploy/propolis.service's own
# UMask=0022 comment) - the operator's out-of-band distribution mechanism, typically a different
# unrelated user, must be able to traverse in and read it.
ensure_dir /var/lib/propolis/feed         0755 propolis          propolis
# sensor-ssh stores its generated host key here (reused across restarts so the honeypot does not
# fingerprint itself as freshly minted). Listed in sensor-ssh.service's ReadWritePaths, so it
# must exist or ProtectSystem=strict's bind-mount setup fails with NAMESPACE.
ensure_dir /var/lib/propolis/ssh          0750 propolis-ssh      propolis-ssh

# ---- 3. spool directories (mount points only - see printed fstab guidance in install.sh) ----

# internal/design/02-sensor-framework.md's "Sample side channel": the spool MUST be backed by a
# noexec,nosuid,nodev mount, not merely a directory of non-executable files - deploy/sensor-
# catchall.service's and deploy/sensor-ssh.service's own ReadWritePaths comments already state this
# and defer enforcing it to "a deployment-time (fstab/provisioning) concern verified against the
# running system, not the unit file." This step creates the directories those two units' documented
# prerequisites require (matching their own ReadWritePaths grants) plus propolis.service's reserved
# /var/lib/propolis/spool - but, same as those unit files, cannot safely choose a backing device or
# tmpfs size budget on the operator's behalf, so it stops at the mountpoint; install.sh prints the
# fstab guidance for a fresh install, and an upgrade leaves an already-mounted tmpfs untouched
# (install -d on an existing mountpoint only reasserts mode/owner, never remounts).
log "3/7 creating spool directories (mountpoints only)"
ensure_dir /var/lib/propolis/spool        0750 propolis          propolis
ensure_dir /var/spool/propolis            0755 root              root
ensure_dir /var/spool/propolis/catchall   0750 propolis-catchall propolis-catchall
ensure_dir /var/spool/propolis/ssh        0750 propolis-ssh      propolis-ssh
ensure_dir /var/spool/propolis/adb       0750 propolis-adb      propolis-adb
ensure_dir /var/spool/propolis/ftp       0750 propolis-ftp      propolis-ftp
ensure_dir /var/spool/propolis/telnet     0750 propolis-telnet   propolis-telnet
# propolis-owned, not a dedicated sensor user: unlike catchall/ssh/adb/ftp/telnet above (each
# written by its own standalone sensor process), the malware fetcher runs inside propolis.service
# itself - see deploy/propolis.service's own ReadWritePaths grant for this exact path.
ensure_dir /var/spool/propolis/fetched   0750 propolis          propolis
