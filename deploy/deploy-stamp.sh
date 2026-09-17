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
# Usage: deploy-stamp.sh [REPO_DIR] [OUT_FILE] [BIN_DIR]
#   REPO_DIR   the checkout that was built   (default: the parent of this script's directory)
#   OUT_FILE   file to write                 (default /var/lib/propolis/deploy-stamp.json)
#   BIN_DIR    where the binaries were installed (default /usr/local/bin)
# Environment:
#   PROPOLIS_DEPLOY_PULLED_AT   when the deploy pulled, RFC 3339 UTC (default: now)
#
# Run this AFTER the binaries are installed, never before: the `installed` field below is read back
# from the files that landed on disk, so a stamp written earlier would describe an install that had
# not happened yet. Both callers (install.sh, upgrade.sh) place it after their install step for
# that reason. See `installed_sha`'s own comment.
#
# Written atomically (temp file in the same directory, then mv) and world-readable, because both
# the propolis daemon and the standalone console read it as their own unprivileged users. It holds
# nothing secret: commit ids, a branch name and two timestamps.
#
# Idempotent, and safe to run where git cannot answer: an unavailable field is written as the empty
# string and the pane treats a stamp it cannot read as no stamp at all.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
OUT_FILE="${2:-/var/lib/propolis/deploy-stamp.json}"
BIN_DIR="${3:-/usr/local/bin}"

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

# `head_sha` above is what the CHECKOUT claimed at build time; it is not proof of what actually
# ended up installed - a partially-failed install loop, a stale cargo cache, or an install step
# that silently no-oped can all leave a different binary on disk than the one just built. Each
# binary is asked for its own identity through its offline `--version` output, which is the only
# source describing the bytes now sitting in BIN_DIR.
#
# BOTH binaries are recorded rather than one: the console is served by the unified `propolis`
# daemon on a single box and by the standalone `console` binary wherever the operator runs
# console.service, and the fleet pane compares the identity of the process RENDERING it. Reading
# one binary and presenting its revision as the other's would be a guess, which is the thing this
# field exists to replace.
#
# Best-effort like every other field: a binary that is absent (a collector-only box, an
# `install.sh --dry-run`), unreadable, or whose output is not the expected shape leaves its entry
# empty, and the pane reports that as not recorded rather than assuming anything.
#
# `timeout` and `</dev/null` are the guard for the one case this check exists to catch. If the
# install did NOT replace an old binary, that old binary predates `--version` and treats the flag
# as no argument at all, i.e. it starts the service. Bounded, with no stdin and its output
# discarded, it dies quickly and the field simply stays empty.
installed_sha() {
    local bin="$1" name line rest sha
    name="$(basename "$bin")"
    [ -x "$bin" ] || return 0
    line="$(timeout 10 "$bin" --version </dev/null 2>/dev/null)" || return 0
    # `<name> <version> (<sha>, built <timestamp>)`. A line that does not open with the binary's
    # own name is some other program sitting at that path, not this one's identity.
    case "$line" in
        "$name "*) ;;
        *) return 0 ;;
    esac
    rest="${line#*\(}"
    [ "$rest" != "$line" ] || return 0
    sha="${rest%%,*}"
    # Hex, with the build script's own dirty marker allowed. Anything else is not a revision and
    # must not be written into the stamp as though it were one.
    case "${sha%+dirty}" in
        "" | *[!0-9a-f]*) return 0 ;;
    esac
    printf '%s' "$sha"
}

PROPOLIS_INSTALLED_SHA="$(installed_sha "$BIN_DIR/propolis")"
CONSOLE_INSTALLED_SHA="$(installed_sha "$BIN_DIR/console")"

# A mismatch means the file on disk is not the commit this deploy just built - loud on stderr,
# where an operator running install.sh/upgrade.sh is already watching, rather than silent until
# someone happens to open the fleet pane. `+dirty` is stripped for the comparison only: a dirty
# build still names a real commit prefix, and this check is about WHICH commit.
warn_on_mismatch() {
    local bin="$1" sha="$2"
    { [ -n "$sha" ] && [ -n "$HEAD_SHA" ]; } || return 0
    case "$HEAD_SHA" in
        "${sha%+dirty}"*) return 0 ;;
    esac
    echo "warning: $bin reports ${sha}, which does not match this checkout's HEAD (${HEAD_SHA}) \
- the install may not have replaced the binary, or it was built from a stale cache" >&2
}
warn_on_mismatch "$BIN_DIR/propolis" "$PROPOLIS_INSTALLED_SHA"
warn_on_mismatch "$BIN_DIR/console" "$CONSOLE_INSTALLED_SHA"

OUT_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$OUT_DIR"

# Same directory as the destination, so the mv is a rename within one filesystem and therefore
# atomic: a reader either sees the whole previous stamp or the whole new one, never a half-written
# file. The trap removes the temp file if anything below fails.
TMP_FILE="$(mktemp "$OUT_DIR/.deploy-stamp.json.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

printf '{"head_sha": "%s", "origin_main_sha": "%s", "branch": "%s", "pulled_at": "%s", "built_at": "%s", "installed": {"propolis": "%s", "console": "%s"}}\n' \
    "$HEAD_SHA" "$ORIGIN_MAIN_SHA" "$BRANCH" "$PULLED_AT" "$BUILT_AT" \
    "$PROPOLIS_INSTALLED_SHA" "$CONSOLE_INSTALLED_SHA" > "$TMP_FILE"

chmod 0644 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUT_FILE"
trap - EXIT

echo "wrote $OUT_FILE (head ${HEAD_SHA:-unknown}, origin/main ${ORIGIN_MAIN_SHA:-unknown}, \
installed propolis ${PROPOLIS_INSTALLED_SHA:-unknown}, console ${CONSOLE_INSTALLED_SHA:-unknown})"
