#!/bin/sh
#
# Guard run by logrotate's `prerotate` hook (deploy/logrotate-sensors.conf), once per log that is
# about to be rotated, with the log's absolute path as $1. Installed as
# /usr/local/sbin/propolis-logrotate-guard by install.sh and upgrade.sh. A non-zero exit skips ONLY
# the log it was called for (logrotate(8), "nosharedscripts"); every other log in the run is still
# rotated, and logrotate exits non-zero so propolis-logrotate.service shows as failed.
#
# Two checks, in this order.
#
# 1. Free space. `copytruncate` rotates by COPYING the live log to `<log>.1` before it truncates
# the original, so rotation needs free space equal to the log. A log that outgrew its filesystem
# (a stopped rotation timer let the telnet log reach 6.6 GB on a /var that had less than that
# free) cannot be rotated: the copy fills the volume that holds the database and every other
# sensor log, then fails, and the truncate never happens. Safe means: the free space available to
# an unprivileged writer on the log's filesystem covers the copy, a quarter of the log for the
# previous generation's compression, and a reserve (default 512 MiB,
# PROPOLIS_LOGROTATE_RESERVE_BYTES) that is left for everything else on the volume. A refused log
# is recovered by hand: docs/operations/retention.md, "A log too large to rotate".
#
# 2. Unread input. `copytruncate` moves everything the reader has not read into `<log>.1`, and the
# reader (the tailer in crates/log-tailer) drains it from there. Two things lose data if rotation
# runs anyway, and both are decided from the reader's saved cursor
# (<cursor dir>/<sha256 of the log path>.json, written by DurableCursor::save), which this reads
# and never writes:
#   a. `<log>.1` has not been fully read. The next rotation would rename it to `.2` and compress
#      it, and the reader could no longer drain it. The tailer keeps its saved cursor inside the
#      old content (the old fingerprint, the position in `.1`) until that drain ends, so a cursor
#      whose fingerprint is `.1`'s first-256-bytes hash and whose offset is short of `.1`'s size
#      means `.1` is unread.
#   b. The live log holds more than MAX_UNREAD bytes (default 64 MiB,
#      PROPOLIS_LOGROTATE_MAX_UNREAD_BYTES) the reader has not read. Rotation would hand
#      all of it to a single drain that blocks the next rotation until it ends; skipping keeps it
#      in the file the reader is already following. The bound is a judgement, not a measurement:
#      64 MiB is two thirds of the shipped 100 MiB `size`, so a log is skipped only when its reader
#      has fallen most of a rotation behind, and it is far under the 300 MiB at which the daemon's
#      sensor-log-oversized alert pages. That alert is the backstop that keeps skipping from
#      becoming silent disk growth.
# A log is skipped (exit 1) when any reader's cursor says (a) or (b).
#
# When no cursor can be read (no cursor file under the intake or shipper cursor directory, an
# unreadable or malformed one, or one for a different inode of the log) the log is ROTATED, as it
# was before this check existed, and the reason is written to stderr and, at warning priority, to
# the journal through logger(1) (config-check.sh also flags a log with no cursor). The cursor file
# is named by the log path resolved with readlink -f, matching the daemon. The alternative, refusing,
# would turn a missing or misplaced cursor (intake never started, a cursor directory moved off the
# default and not visible to this unit) into a rotation that never runs: the exact disk-fill the
# 6.6 GB incident was. Rotating keeps five generations on disk and loses nothing the tailer's own
# recovery (a verified `.1`) cannot catch. The directories searched are PROPOLIS_CURSOR_DIR
# (default /var/lib/propolis/cursors) and PROPOLIS_SHIPPER_CURSOR_DIR (default
# /var/lib/propolis/shipper/cursors); set either in a drop-in for propolis-logrotate.service if the
# deployment moved them.

set -eu

log="${1:?usage: propolis-logrotate-guard <log-path>}"
reserve="${PROPOLIS_LOGROTATE_RESERVE_BYTES:-536870912}"
max_unread="${PROPOLIS_LOGROTATE_MAX_UNREAD_BYTES:-67108864}"
intake_dir="${PROPOLIS_CURSOR_DIR:-/var/lib/propolis/cursors}"
shipper_dir="${PROPOLIS_SHIPPER_CURSOR_DIR:-/var/lib/propolis/shipper/cursors}"

size="$(stat -c %s -- "$log")"
# %a free blocks available to a non-root writer, %S the block size those counts are in.
set -- $(stat -f -c '%a %S' -- "$log")
avail=$(($1 * $2))
need=$((size + size / 4 + reserve))

if [ "$avail" -lt "$need" ]; then
    echo "propolis-logrotate-guard: refusing to rotate $log: ${size} bytes needs ${need} bytes free (copy + compression + ${reserve} reserve), ${avail} available. Archive and truncate it by hand: docs/operations/retention.md, 'A log too large to rotate'." >&2
    exit 1
fi

note() {
    echo "propolis-logrotate-guard: $*" >&2
}

# A rotation that goes ahead because the guard could not see a cursor is a blind spot, not routine:
# it also goes to the journal at warning priority, where a filter on priority finds it.
warn() {
    note "$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t propolis-logrotate-guard -p daemon.warning -- "$*" 2>/dev/null || true
    fi
}

skip() {
    echo "propolis-logrotate-guard: skipping rotation of $log: $*. It is rotated on a later run once the reader has caught up; docs/operations/retention.md, 'Rotation while intake is behind'." >&2
    exit 1
}

copy="$log.1"
live_inode="$(stat -c %i -- "$log")"
# The daemon names the cursor file by the RESOLVED path (DurableCursor::cursor_file_path), so a
# log reached through a symlink or a `//` finds the same cursor; readlink -f resolves the same way.
resolved="$(readlink -f -- "$log" 2>/dev/null || true)"
path_hash="$(printf '%s' "${resolved:-$log}" | sha256sum | cut -d' ' -f1)"
if [ -z "$path_hash" ]; then
    warn "cannot derive the cursor file name for $log; rotating"
    exit 0
fi

copy2="$log.2"
copy2_hash=""
if [ -f "$copy2" ]; then
    copy2_hash="$(head -c 256 -- "$copy2" | sha256sum | cut -d' ' -f1)"
fi

copy_size=0
copy_hash=""
if [ -f "$copy" ]; then
    copy_size="$(stat -c %s -- "$copy")"
    copy_hash="$(head -c 256 -- "$copy" | sha256sum | cut -d' ' -f1)"
fi

usable=0
for dir in "$intake_dir" "$shipper_dir"; do
    file="$dir/$path_hash.json"
    [ -f "$file" ] || continue
    if ! json="$(cat -- "$file" 2>/dev/null)"; then
        note "cursor $file is unreadable"
        continue
    fi
    c_inode="$(printf '%s' "$json" | sed -n 's/.*"inode":\([0-9][0-9]*\).*/\1/p')"
    c_offset="$(printf '%s' "$json" | sed -n 's/.*"offset":\([0-9][0-9]*\).*/\1/p')"
    c_fp="$(printf '%s' "$json" | sed -n 's/.*"fingerprint":\[\([0-9][0-9,]*\)\].*/\1/p')"
    if [ -z "$c_inode" ] || [ -z "$c_offset" ] || [ -z "$c_fp" ]; then
        note "cursor $file is malformed"
        continue
    fi
    if [ "$c_inode" != "$live_inode" ]; then
        note "cursor $file is for inode $c_inode but $log is inode $live_inode"
        continue
    fi
    usable=$((usable + 1))
    c_hash="$(printf '%s' "$c_fp" | tr ',' ' ' | awk '{ for (i = 1; i <= NF; i++) printf "%02x", $i }')"

    if [ -n "$copy2_hash" ] && [ "$c_hash" = "$copy2_hash" ]; then
        # A second rotation already pushed the generation the cursor names back to `.2`, and `.1`
        # (rotated after it) has not been read at all. Rotating again would compress both.
        skip "the cursor in $file is still in $copy2, and $copy has not been read"
    fi
    if [ -n "$copy_hash" ] && [ "$c_hash" = "$copy_hash" ]; then
        # The cursor is still inside the old content: the reader has not finished with `.1`, or has
        # finished it and not yet seen the truncation. Its offset is a position in `.1`.
        if [ "$c_offset" -lt "$copy_size" ]; then
            skip "$copy is not fully read (the cursor in $file is at byte $c_offset of $copy_size)"
        fi
        # Read to the end of `.1`; the whole live file is what the reader will read next.
        unread="$(stat -c %s -- "$log")"
    else
        live_size="$(stat -c %s -- "$log")"
        if [ "$c_offset" -le "$live_size" ]; then
            unread=$((live_size - c_offset))
        else
            unread="$live_size"
        fi
    fi
    if [ "$unread" -gt "$max_unread" ]; then
        skip "the reader has ${unread} unread bytes in it, over the ${max_unread} bound (cursor $file)"
    fi
done

if [ "$usable" -eq 0 ]; then
    warn "no usable intake cursor for $log under $intake_dir or $shipper_dir; rotating without an unread-input check (docs/operations/retention.md, 'Rotation while intake is behind')"
fi
exit 0
