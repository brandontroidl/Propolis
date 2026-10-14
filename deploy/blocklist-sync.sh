#!/usr/bin/env bash
#
# blocklist-sync.sh - publish the built feed into the public blocklist repo, split into
#   tiers/       aggressive.* standard.*      (block-this-now)
#   retention/   all-<window>.*               (active-in-the-last-N)
# with manifest.json and this directory's blocklist-README.md at the repo root, then commit and push.
#
# Runs on the honeypot node from cron, after the feed publisher's atomic swap. The split lives HERE,
# at the push - the publisher's flat output, the manifest contract, and the console are unchanged by
# design.
#
# Idempotent: a run with no new build makes no commit. Fail-closed: a missing, malformed or tampered
# feed output aborts before the repo is touched, so nothing but a complete build is ever pushed.
#
# Privilege boundary. The feed directory is written by the daemon, the process that parses every
# attacker byte, and this script reads it from a cron job. So everything in that directory is
# treated as chosen by an attacker who controls the daemon: a symlink or hard link under a feed
# name would have this script copy a file the daemon cannot read (a host key, the deploy key) into
# a public repo, a FIFO would hang it, and a link planted where it writes would have it overwrite
# any file. Run it as the dedicated propolis-blocklist account deploy/provision.sh creates, which
# can read the feed and nothing of root's (docs/operations/routine-procedures.md); and whichever
# account runs it, it copies only single-link regular files with the publisher's own names, opens
# each without following a link or blocking, checks it again after reading, and writes nothing in
# the daemon's tree.
#
# Paths (override via environment; both feed and repo are auto-detected when unset):
#   PROPOLIS_FEED_OUTPUT_DIR      the publisher's flat output holding manifest.json
#   PROPOLIS_BLOCKLIST_REPO       the git checkout that is pushed        (default below)
#   PROPOLIS_BLOCKLIST_SSH_KEY    passphraseless deploy key used for the push (see below)
#   PROPOLIS_BLOCKLIST_STATUS_DIR where the last-pushed marker is written (default below)
set -euo pipefail
# stat's %F type names are translated under other locales.
export LC_ALL=C

# Where this script lives, so it can publish its sibling README alongside the feed.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The publisher's formats, one file per feed each (crates/feed/src/publisher.rs, write_tier); a
# test holds this list to the publisher's.
FORMATS=(txt json csv cidr ipset nft pf alias hosts rpz)
# The largest live file is about 1 MB (a 90-day JSON) and the whole build about 8 MB. 32 MiB a file
# stays under GitHub's 50 MB warning and 100 MB refusal; 256 MiB a build bounds what one run copies.
MAX_FILE_BYTES=$((32 * 1024 * 1024))
MAX_BUILD_BYTES=$((256 * 1024 * 1024))
# Retention windows are operator-configured (PROPOLIS_FEED_WINDOWS, five by default); this bounds
# how many file sets a tampered directory can make one run copy.
MAX_WINDOWS=16

# --- Push authentication ------------------------------------------------------------------------
# Cron has no ssh-agent, so a passphrase-protected key cannot be used non-interactively: the push
# hangs or fails while the same command run by hand succeeds against the operator's loaded agent.
# The historical fix was `git config core.sshCommand` inside the repo checkout, which is box-local
# state living outside version control - it has silently reverted more than once, each time turning
# the hourly publish back into a silent failure that only surfaced as a stale feed.
#
# So the key is named HERE, from the environment, and the script fails closed rather than letting
# ssh fall back to whatever identity happens to be available: a fallback that works interactively
# and fails under cron is the exact trap this is meant to remove.
KEY="${PROPOLIS_BLOCKLIST_SSH_KEY:-}"
if [ -n "$KEY" ]; then
  if [ ! -r "$KEY" ]; then
    echo "blocklist-sync: PROPOLIS_BLOCKLIST_SSH_KEY=$KEY is not readable - refusing to push with" \
         "an unintended identity (interactive runs would silently succeed via an agent that cron" \
         "does not have)" >&2
    exit 1
  fi
  export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes"
elif [ -z "${SSH_AUTH_SOCK:-}" ] && [ ! -t 0 ]; then
  # Non-interactive, no agent, no explicit key: the classic cron configuration in which the push is
  # about to fail. Say so up front so the cause is in the log next to the failure, not inferred.
  echo "blocklist-sync: WARNING no PROPOLIS_BLOCKLIST_SSH_KEY set and no ssh-agent in this" \
       "environment; the push will fail if the remote needs a passphrase-protected key" >&2
fi

# One header per run. The log is append-only and shared by cron and by-hand runs, and without
# this a failure could not be attributed to either: which identity pushed, and whether a terminal
# was attached (cron never has one), is exactly what a stale-feed investigation needs first.
if [ -t 0 ]; then tty_state="tty"; else tty_state="no-tty"; fi
echo "blocklist-sync: run $(date -Is) ${tty_state} identity=${KEY:-agent-or-default} uid=$(id -u)"

# Root can still run it (a crontab from before the dedicated account), and the checks below hold
# for root too; but as root, any gap in them reaches every file on the host.
if [ "$(id -u)" -eq 0 ]; then
  echo "blocklist-sync: WARNING running as root; run it as propolis-blocklist so the feed it" \
       "copies can never reach a file only root can read (docs/operations/routine-procedures.md)" >&2
fi

refuse() {
  echo "blocklist-sync: $* - refusing to push" >&2
  exit 1
}

# --- Resolve the feed source ------------------------------------------------------------------
# Prefer an explicit override; otherwise take whichever standard location actually holds a build.
# This tolerates both the documented `.../feed/current` and the older flat `.../feed` layout without
# guessing which this host uses.
SRC="${PROPOLIS_FEED_OUTPUT_DIR:-}"
if [ -z "$SRC" ]; then
  for cand in /var/lib/propolis/feed/current /var/lib/propolis/feed; do
    if [ -f "$cand/manifest.json" ]; then SRC="$cand"; break; fi
  done
fi
REPO="${PROPOLIS_BLOCKLIST_REPO:-/var/lib/propolis/blocklist-repo}"
STATUS_DIR="${PROPOLIS_BLOCKLIST_STATUS_DIR:-/var/lib/propolis/blocklist-status}"

# --- Validate (fail closed) -------------------------------------------------------------------
if [ -z "$SRC" ] || [ ! -f "$SRC/manifest.json" ]; then
  echo "blocklist-sync: no manifest.json under ${SRC:-<feed dir>} - feed not built, refusing to push" >&2
  exit 1
fi
if [ ! -d "$REPO/.git" ]; then
  echo "blocklist-sync: $REPO is not a git checkout" >&2
  exit 1
fi
# Absolute, since the work below runs from inside the feed directory.
absolute() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
SRC="$(absolute "$SRC")"
REPO="$(absolute "$REPO")"
STATUS_DIR="$(absolute "$STATUS_DIR")"
# stat resolves a trailing slash through a final symlink, which would blind the identity check below.
while [ "${#SRC}" -gt 1 ] && [ "${SRC%/}" != "$SRC" ]; do SRC="${SRC%/}"; done

# Enter the feed directory once and work only on names relative to it, so the daemon swapping the
# path for a link afterwards changes nothing. The directory entered must be the one the path names
# itself: a path that is a symlink, or was swapped while being entered, compares unequal.
cd -- "$SRC" || refuse "cannot enter $SRC"
[ "$(stat -c %d:%i .)" = "$(stat -c %d:%i -- "$SRC")" ] \
  || refuse "$SRC is a symbolic link or was replaced while being entered"

# --- Check every name against the publisher's output ------------------------------------------
# The directory is exactly one publisher build (it is swapped in whole), so any other name means
# something else wrote here: the build is refused rather than published without it.
shopt -s nullglob dotglob
entries=( * )
shopt -u nullglob dotglob

format_pattern="$(IFS='|'; printf '%s' "${FORMATS[*]}")"
name_pattern="^(aggressive|standard|all-[1-9][0-9]{0,4}[hd])\\.(${format_pattern})\$"
declare -A present=() feeds=([aggressive]=1 [standard]=1)
for name in "${entries[@]}"; do
  if [ "$name" = manifest.json ]; then
    present[$name]=1
  elif [[ "$name" =~ $name_pattern ]]; then
    present[$name]=1
    feeds[${BASH_REMATCH[1]}]=1
  else
    refuse "unexpected entry $(printf '%q' "$name") in $SRC"
  fi
done

# Two tiers plus the retention windows.
if [ $(( ${#feeds[@]} - 2 )) -gt "$MAX_WINDOWS" ]; then
  refuse "$(( ${#feeds[@]} - 2 )) retention windows in $SRC, more than the $MAX_WINDOWS allowed"
fi
# Every feed present carries every format, as the publisher writes them; manifest.json is required.
for feed in "${!feeds[@]}"; do
  for f in "${FORMATS[@]}"; do
    [ -n "${present[$feed.$f]:-}" ] || refuse "$feed.$f missing from $SRC - malformed feed output"
  done
done
[ -n "${present[manifest.json]:-}" ] || refuse "manifest.json missing from $SRC"

# --- Copy each file safely --------------------------------------------------------------------
# Copies one feed file to `dest`. The type and link count are checked on the name before opening
# it, so a FIFO or device is not opened in the ordinary case. The read is then bound to the file
# that was checked: perl (perl-base, Essential on Debian) opens the name ONCE with O_NOFOLLOW (a
# symlink swapped in is never opened, so nothing at its target sees an open) and O_NONBLOCK (a FIFO
# swapped in cannot hold the open), takes the device and inode of that same handle with fstat,
# refuses unless they equal the pre-open stat (perl's st_dev is the raw dev_t, the number GNU stat
# prints as %d) and the handle is a regular file, and only then copies at most `max` bytes from it.
# A hard link swapped in around the open is a different inode and is refused even if the name is
# restored before the next look. The timeout covers only a filesystem that stalls an open. After
# the read the name must still match its check, and the copy must be the size checked.
copy_feed_file() {
  local name="$1" dest="$2" max="$3" checked after type links size id
  checked="$(stat -c '%F|%h|%s|%d:%i' -- "$name")" || return 1
  IFS='|' read -r type links size id <<<"$checked"
  case "$type" in
    "regular file"|"regular empty file") ;;
    *) echo "blocklist-sync: $name is a $type, not a regular file" >&2; return 1 ;;
  esac
  if [ "$links" != 1 ]; then
    echo "blocklist-sync: $name has $links hard links; a feed file has exactly one" >&2
    return 1
  fi
  if [ "$size" -gt "$max" ]; then
    echo "blocklist-sync: $name is $size bytes, over the $max-byte limit" >&2
    return 1
  fi
  # shellcheck disable=SC2016 # perl, not the shell, expands $ARGV and the other $ names here
  timeout 10 perl -e '
    use Fcntl;
    my ($name, $id, $dest, $max) = @ARGV;
    sysopen(my $in, $name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or exit 1;
    my @st = stat($in);
    exit 3 unless @st && "$st[0]:$st[1]" eq $id && -f $in;
    sysopen(my $out, $dest, O_WRONLY | O_CREAT | O_EXCL, 0644) or exit 1;
    my ($left, $buf) = ($max, "");
    while ($left > 0) {
      my $n = sysread($in, $buf, $left < 1048576 ? $left : 1048576);
      exit 1 unless defined $n;
      last if $n == 0;
      for (my $off = 0; $off < $n; ) {
        my $w = syswrite($out, $buf, $n - $off, $off);
        exit 1 unless defined $w;
        $off += $w;
      }
      $left -= $n;
    }
    close($out) or exit 1;
  ' "$name" "$id" "$dest" "$max"
  local rc=$?
  case "$rc" in
    0) ;;
    3) echo "blocklist-sync: $name could not be opened as the file that was checked" >&2; return 1 ;;
    124) echo "blocklist-sync: opening $name did not finish within 10 s; refused" >&2; return 1 ;;
    127) echo "blocklist-sync: perl is not installed; it is required to copy feed files safely" >&2; return 1 ;;
    *) echo "blocklist-sync: $name could not be opened or copied (a link, a FIFO or an I/O error)" >&2; return 1 ;;
  esac
  after="$(stat -c '%F|%h|%s|%d:%i' -- "$name")" || return 1
  if [ "$after" != "$checked" ]; then
    echo "blocklist-sync: $name changed between its check and its copy" >&2
    return 1
  fi
  if [ "$(stat -c %s -- "$dest")" != "$size" ]; then
    echo "blocklist-sync: $name changed size while being copied" >&2
    return 1
  fi
}

# Copies land in a private directory inside the checkout's .git (same filesystem, never committed)
# and move into the work tree only once all of them passed, so a refusal leaves the repo untouched.
stage="$(mktemp -d "$REPO/.git/blocklist-sync.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/tiers" "$stage/retention"
total=0
for name in "${!present[@]}"; do
  case "$name" in
    manifest.json) dest="$stage/manifest.json" ;;
    all-*) dest="$stage/retention/$name" ;;
    *) dest="$stage/tiers/$name" ;;
  esac
  copy_feed_file "$name" "$dest" "$MAX_FILE_BYTES" || refuse "$name in $SRC failed its checks"
  total=$(( total + $(stat -c %s -- "$dest") ))
  [ "$total" -le "$MAX_BUILD_BYTES" ] || refuse "the build in $SRC is over $MAX_BUILD_BYTES bytes"
done

# --- Arrange the repo layout ------------------------------------------------------------------
cd -- "$REPO"
mkdir -p tiers retention
mv -f -- "$stage"/tiers/* tiers/
shopt -s nullglob
retention_files=( "$stage"/retention/* )
shopt -u nullglob
if [ "${#retention_files[@]}" -gt 0 ]; then
  mv -f -- "${retention_files[@]}" retention/
fi
mv -f -- "$stage/manifest.json" manifest.json

# Keep the repo's public README in sync with the packaged one, so the layout docs and raw-URL
# examples never drift from what this script actually publishes.
if [ -f "$SCRIPT_DIR/blocklist-README.md" ]; then
    cp -f "$SCRIPT_DIR/blocklist-README.md" README.md
fi

# Drop any stale FLAT feed files the pre-folder layout left at the repo root, so the repo converges
# on tiers/ + retention/ instead of carrying both copies. Matches only feed filenames; manifest.json,
# README, and LICENSE are untouched.
find . -maxdepth 1 -type f \( -name 'aggressive.*' -o -name 'standard.*' -o -name 'all-*.*' \) -delete

# --- Commit & push ----------------------------------------------------------------------------
git add -A
if git diff --cached --quiet; then
  echo "blocklist-sync: no new build to commit"
else
  build_time="$(sed -n 's/.*"build_time"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json | head -n1)"
  git commit -q -m "feed: ${build_time:-update}"
fi

# Records the push time for the daemon's `feed-push-stale` condition, which pages when the local
# feed has moved on from the last successful push - the one failure the daemon's own feed health
# cannot see, since this script runs outside it. The path is the one the condition reads
# (crates/propolis/src/ops_alert/conditions/feed.rs, PUSH_MARKER_PATH), in a directory only this
# account writes: never the daemon's tree, where a link it planted would redirect the write. A
# directory others can write is refused for the same reason. Written to a fresh temporary name and
# renamed over the marker, which replaces whatever entry is there rather than following it.
write_marker_files() {
  local dir="$1" tmp
  tmp="$(mktemp "$dir/.last-pushed.XXXXXX")" || return 1
  if printf 'blocklist-sync last-pushed marker\n' >"$tmp" && chmod 0644 -- "$tmp" \
     && mv -f -T -- "$tmp" "$dir/last-pushed"; then
    return 0
  fi
  rm -f -- "$tmp"
  return 1
}
export -f write_marker_files

# A root run (a crontab from before the dedicated account) cannot write the marker as itself: the
# directory belongs to propolis-blocklist and must stay that way, and root writing in a directory
# another account controls is the redirect this layout exists to prevent. So root drops to the
# directory's owner for the write, which then reaches nothing the owner could not already write.
write_push_marker() {
  local owner group mode me
  me="$(id -u)"
  [ -d "$STATUS_DIR" ] && [ ! -L "$STATUS_DIR" ] || return 1
  read -r owner group mode < <(stat -c '%u %g %a' -- "$STATUS_DIR") || return 1
  if (( 8#$mode & 8#022 )); then return 1; fi
  if [ "$owner" = "$me" ]; then
    write_marker_files "$STATUS_DIR"
  elif [ "$me" = 0 ]; then
    command -v setpriv >/dev/null 2>&1 || return 1
    # shellcheck disable=SC2016 # expanded by the child bash, which receives the directory as "$1"
    setpriv --reuid="$owner" --regid="$group" --clear-groups --no-new-privs -- \
      bash -c 'write_marker_files "$1"' write_marker_files "$STATUS_DIR"
  else
    return 1
  fi
}

# Always attempt the push, even when nothing new was committed: an earlier run may have committed
# locally but FAILED to push (the classic cause is cron having no SSH agent for the git remote), and
# a "no new changes -> skip push" flow would strand that commit forever. `git push` is a clean no-op
# when the branch is already up to date, and ships any stranded commit otherwise.
if git push -q origin HEAD; then
  echo "blocklist-sync: pushed (HEAD $(git rev-parse --short HEAD))"
  # A marker failure must not fail a successful push.
  if ! write_push_marker; then
    echo "blocklist-sync: WARNING could not update push marker $STATUS_DIR/last-pushed (the" \
         "directory must exist, be owned by this account (or by the account root can drop to, with" \
         "setpriv installed) and be writable by no one else);" \
         "the daemon's feed-push-stale condition will read this push as not having happened" >&2
  fi
else
  echo "blocklist-sync: git push FAILED - the local commit is not on the remote. Under cron this is" \
       "almost always missing SSH auth (no agent / passphrase key). See the deploy README." >&2
  exit 1
fi
