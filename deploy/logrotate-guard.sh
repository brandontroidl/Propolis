#!/bin/sh
#
# Free-space guard run by logrotate's `prerotate` hook (deploy/logrotate-sensors.conf), once per log
# that is about to be rotated, with the log's absolute path as $1. Installed as
# /usr/local/sbin/propolis-logrotate-guard by install.sh and upgrade.sh.
#
# Why it exists: `copytruncate` rotates by COPYING the live log to `<log>.1` before it truncates
# the original, so rotation needs free space equal to the log. A log that outgrew its filesystem
# (a stopped rotation timer let the telnet log reach 6.6 GB on a /var that had less than that
# free) cannot be rotated: the copy fills the volume that holds the database and every other
# sensor log, then fails, and the truncate never happens. This script refuses that rotation up
# front instead. A non-zero exit from `prerotate` skips ONLY the log it was called for (logrotate(8),
# "nosharedscripts"); every other log in the run is still rotated, and logrotate exits non-zero so
# propolis-logrotate.service shows as failed.
#
# Safe means: the free space available to an unprivileged writer on the log's filesystem covers the
# copy, a quarter of the log for the previous generation's compression, and a reserve (default
# 512 MiB, PROPOLIS_LOGROTATE_RESERVE_BYTES) that is left for everything else on the volume. A
# refused log is recovered by hand: docs/operations/retention.md, "A log too large to rotate".

set -eu

log="${1:?usage: propolis-logrotate-guard <log-path>}"
reserve="${PROPOLIS_LOGROTATE_RESERVE_BYTES:-536870912}"

size="$(stat -c %s -- "$log")"
# %a free blocks available to a non-root writer, %S the block size those counts are in.
# shellcheck disable=SC2046 # splitting the two integers stat prints into $1 and $2 is the point
set -- $(stat -f -c '%a %S' -- "$log")
avail=$(($1 * $2))
need=$((size + size / 4 + reserve))

if [ "$avail" -lt "$need" ]; then
    echo "propolis-logrotate-guard: refusing to rotate $log: ${size} bytes needs ${need} bytes free (copy + compression + ${reserve} reserve), ${avail} available. Archive and truncate it by hand: docs/operations/retention.md, 'A log too large to rotate'." >&2
    exit 1
fi
