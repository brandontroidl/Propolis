#!/usr/bin/env bash
#
# blocklist-sync.sh - publish the built feed into the public blocklist repo, split into
#   tiers/       aggressive.* standard.*      (block-this-now)
#   retention/   all-<window>.*               (active-in-the-last-N)
# with manifest.json and this directory's blocklist-README.md at the repo root, then commit and push.
#
# Runs on the honeypot node from cron, after the feed publisher's atomic swap. The split lives HERE,
# at the push - the publisher's flat output, the manifest contract, and the console are unchanged by
# design. Replaces the earlier ad-hoc one-liner, which copied only the two tiers (never the retention
# feeds) as flat files at the repo root.
#
# Idempotent: a run with no new build makes no commit. Fail-closed: a missing or empty feed output
# aborts before the repo is touched, so a half-built or absent feed is never pushed.
#
# Paths (override via environment; both are auto-detected when unset):
#   PROPOLIS_FEED_OUTPUT_DIR   the publisher's flat output holding manifest.json
#   PROPOLIS_BLOCKLIST_REPO    the git checkout that is pushed        (default below)
#   PROPOLIS_BLOCKLIST_SSH_KEY passphraseless deploy key used for the push (see below)
set -euo pipefail

# Where this script lives, so it can publish its sibling README alongside the feed.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
echo "blocklist-sync: run $(date -Is) ${tty_state} identity=${KEY:-agent-or-default}"

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

# --- Validate (fail closed) -------------------------------------------------------------------
if [ -z "$SRC" ] || [ ! -f "$SRC/manifest.json" ]; then
  echo "blocklist-sync: no manifest.json under ${SRC:-<feed dir>} - feed not built, refusing to push" >&2
  exit 1
fi
if [ ! -d "$REPO/.git" ]; then
  echo "blocklist-sync: $REPO is not a git checkout" >&2
  exit 1
fi

# --- Gather the freshly published files -------------------------------------------------------
# nullglob so an empty match is a no-op rather than the literal glob string.
shopt -s nullglob
tier_files=( "$SRC"/aggressive.* "$SRC"/standard.* )
retention_files=( "$SRC"/all-*.* )
shopt -u nullglob

# The publisher writes every format even for an empty tier, so an empty tier set means the output is
# malformed, not a normal state - refuse rather than push a stripped repo.
if [ "${#tier_files[@]}" -eq 0 ]; then
  echo "blocklist-sync: no tier files under $SRC - malformed feed output, refusing to push" >&2
  exit 1
fi

# --- Arrange the repo layout ------------------------------------------------------------------
mkdir -p "$REPO/tiers" "$REPO/retention"
cp -f "${tier_files[@]}" "$REPO/tiers/"
if [ "${#retention_files[@]}" -gt 0 ]; then
  cp -f "${retention_files[@]}" "$REPO/retention/"
fi
cp -f "$SRC/manifest.json" "$REPO/manifest.json"

# Keep the repo's public README in sync with the packaged one, so the layout docs and raw-URL
# examples never drift from what this script actually publishes.
if [ -f "$SCRIPT_DIR/blocklist-README.md" ]; then
    cp -f "$SCRIPT_DIR/blocklist-README.md" "$REPO/README.md"
fi

# Drop any stale FLAT feed files the pre-folder layout left at the repo root, so the repo converges
# on tiers/ + retention/ instead of carrying both copies. Matches only feed filenames; manifest.json,
# README, and LICENSE are untouched.
find "$REPO" -maxdepth 1 -type f \( -name 'aggressive.*' -o -name 'standard.*' -o -name 'all-*.*' \) -delete

# --- Commit & push ----------------------------------------------------------------------------
cd "$REPO"
git add -A
if git diff --cached --quiet; then
  echo "blocklist-sync: no new build to commit"
else
  build_time="$(sed -n 's/.*"build_time"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json | head -n1)"
  git commit -q -m "feed: ${build_time:-update}"
fi

# Always attempt the push, even when nothing new was committed: an earlier run may have committed
# locally but FAILED to push (the classic cause is cron having no SSH agent for the git remote), and
# a "no new changes -> skip push" flow would strand that commit forever. `git push` is a clean no-op
# when the branch is already up to date, and ships any stranded commit otherwise.
if git push -q origin HEAD; then
  echo "blocklist-sync: pushed (HEAD $(git rev-parse --short HEAD))"
  # Record the push time for the daemon's `feed-push-stale` condition, which pages when the local
  # feed has moved on from the last successful push - the one failure the daemon's own feed
  # health cannot see, since this script runs outside it. A sibling dotfile of the feed directory
  # (never inside it, so it is not published), derived exactly as
  # crates/propolis/src/ops_alert/conditions/feed.rs's `push_marker_path` derives it; world-
  # readable so the propolis user can stat it. A marker failure must not fail a successful push.
  push_marker="$(dirname "$SRC")/.$(basename "$SRC").last_pushed"
  if ! { printf 'blocklist-sync last-pushed marker\n' > "$push_marker" && chmod 0644 "$push_marker"; }; then
    echo "blocklist-sync: WARNING could not update push marker $push_marker; the daemon's" \
         "feed-push-stale condition will read this push as not having happened" >&2
  fi
else
  echo "blocklist-sync: git push FAILED - the local commit is not on the remote. Under cron this is" \
       "almost always missing SSH auth (no agent / passphrase key). See the deploy README." >&2
  exit 1
fi
