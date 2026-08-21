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
set -euo pipefail

# Where this script lives, so it can publish its sibling README alongside the feed.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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

# --- Commit & push (clean no-op when nothing changed) -----------------------------------------
cd "$REPO"
git add -A
if git diff --cached --quiet; then
  echo "blocklist-sync: no changes since last build"
  exit 0
fi

build_time="$(sed -n 's/.*"build_time"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json | head -n1)"
git commit -q -m "feed: ${build_time:-update}"
git push -q origin HEAD
echo "blocklist-sync: pushed (${build_time:-unknown build time})"
