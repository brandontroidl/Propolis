#!/usr/bin/env bash
#
# Records which commit this box last deployed, so the console can tell a stale binary from a stale
# checkout.
#
# WHY THIS EXISTS. A build that produced new binaries and a service that was never restarted leave
# a box running code older than the code on disk, and nothing on the box could see that. The
# binaries now stamp themselves with the commit they were built from (crates/build-stamp.rs); this
# writes down what the DEPLOY did, and the console's fleet pane compares the two. Without this file
# the pane reads "not recorded", which is the honest answer, never "current".
#
# WHY NOT ASK GIT AT RENDER TIME. The console runs as its own user under ProtectSystem=strict and
# has no business reading the repository, the repository is private and the box must not beacon out
# to ask GitHub anything, and by the time the pane is rendered the checkout may have moved on from
# what was built. The deploy is the only moment that knows all three answers at once.
#
# origin_main_sha is whatever the last fetch saw, not a live query: no egress. It is therefore a
# lower bound on how far behind the box is, which is the safe direction.
#
# Usage: deploy-stamp.sh [REPO_DIR] [OUT_FILE]
#   REPO_DIR   the checkout that was built   (default: the parent of this script's directory)
#   OUT_FILE   file to write                 (default /var/lib/propolis/deploy-stamp.json)
# Environment:
#   PROPOLIS_DEPLOY_PULLED_AT   when the deploy pulled, RFC 3339 UTC (default: now)
#
# Written atomically (temp file in the same directory, then mv) and world-readable, because both
# the propolis daemon and the standalone console read it as their own unprivileged users. It holds
# nothing secret: two commit ids, a branch name and two timestamps.
#
# Idempotent, and safe to run where git cannot answer: an unavailable field is written as the empty
# string and the pane treats a stamp it cannot read as no stamp at all.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
OUT_FILE="${2:-/var/lib/propolis/deploy-stamp.json}"

# Every field is best-effort: a checkout with no .git, or a box with no git binary, must still
# leave a readable stamp rather than aborting a deploy over a monitoring detail.
git_field() {
    git -C "$REPO_DIR" "$@" 2>/dev/null || true
}

HEAD_SHA="$(git_field rev-parse HEAD)"
BRANCH="$(git_field rev-parse --abbrev-ref HEAD)"
# The last fetched origin/main, not a live lookup. Falls back to empty when there is no such ref,
# and the pane then says it cannot tell whether the box is behind rather than claiming it is not.
ORIGIN_MAIN_SHA="$(git_field rev-parse refs/remotes/origin/main)"
# This script runs immediately after the build, so now IS the build time. The pull happened
# earlier in the same deploy, so the caller passes it rather than letting the two fields carry the
# same number and pretend to be two facts.
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PULLED_AT="${PROPOLIS_DEPLOY_PULLED_AT:-$BUILT_AT}"

OUT_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$OUT_DIR"

# Same directory as the destination, so the mv is a rename within one filesystem and therefore
# atomic: a reader either sees the whole previous stamp or the whole new one, never a half-written
# file. The trap removes the temp file if anything below fails.
TMP_FILE="$(mktemp "$OUT_DIR/.deploy-stamp.json.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

printf '{"head_sha": "%s", "origin_main_sha": "%s", "branch": "%s", "pulled_at": "%s", "built_at": "%s"}\n' \
    "$HEAD_SHA" "$ORIGIN_MAIN_SHA" "$BRANCH" "$PULLED_AT" "$BUILT_AT" > "$TMP_FILE"

chmod 0644 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUT_FILE"
trap - EXIT

echo "wrote $OUT_FILE (head ${HEAD_SHA:-unknown}, origin/main ${ORIGIN_MAIN_SHA:-unknown})"
