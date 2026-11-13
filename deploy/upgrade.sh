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
# Usage: sudo ./deploy/upgrade.sh [--accept-origin] [--adopt-history=<commit>]
#   --accept-origin   deploy from the origin URL the checkout has NOW although it differs from the
#                     one the last deploy recorded; this run's deploy stamp records the new one.
#   --adopt-history=<commit>
#                     deploy origin/main although it does not descend from this checkout's commit
#                     (the repository's history was restarted, the checkout now points at a
#                     successor repository, main was rewritten, or main was moved back), provided
#                     origin/main is exactly <commit>, given as a full commit id. Naming the
#                     commit is the check: nothing in a history that does not contain this
#                     checkout ties it to what this box runs, so the operator states which commit
#                     they mean and anything else on origin/main is refused. The id is worth what
#                     the channel it came through is worth: it has to reach the operator some way
#                     that does not depend on the remote being checked.
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
ADOPT_COMMIT=""
for arg in "$@"; do
    case "$arg" in
        --accept-origin) ACCEPT_ORIGIN=1 ;;
        --adopt-history=*)
            # Twice is a mistake to stop on, not to resolve by taking the last: the two may differ.
            if [ -n "$ADOPT_COMMIT" ]; then
                echo "error: --adopt-history was given more than once" >&2
                exit 2
            fi
            ADOPT_COMMIT="${arg#--adopt-history=}"
            ADOPT_COMMIT="${ADOPT_COMMIT,,}"
            # The whole id and nothing git would have to resolve: an abbreviation names whichever
            # commit happens to match it in the repository that was fetched, and a ref name names
            # whatever the remote put there, which is the thing this argument exists to check.
            if ! [[ "$ADOPT_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
                echo "error: --adopt-history takes the full commit id of origin/main (40 hexadecimal characters), not '${ADOPT_COMMIT:0:80}'" >&2
                exit 2
            fi
            ;;
        *) echo "usage: $0 [--accept-origin] [--adopt-history=<commit>]" >&2; exit 2 ;;
    esac
done
ROOT="${PROPOLIS_UPGRADE_ROOT:-}"
STAMP_FILE="$ROOT/var/lib/propolis/deploy-stamp.json"
SIGNERS_FILE="$ROOT/etc/propolis/upgrade-signers"
REPO_OWNER="$(stat -c '%U' "$REPO_DIR")"
# Every git command runs as the checkout's owner, like the build: the fetch needs the owner's
# credentials, and git refuses root a directory someone else owns. Git is told not to warn about
# ambiguous ref names: every command here names a full ref or a commit id, so the warning can only
# fire for a ref that someone named like a commit id, and it prints that id in full.
as_owner() {
    if [ "$1" = git ]; then
        shift
        sudo -u "$REPO_OWNER" git -c core.warnAmbiguousRefs=false "$@"
    else
        sudo -u "$REPO_OWNER" "$@"
    fi
}
# Anything that reads as a commit id is taken out of text this run did not write itself (what git
# printed while it talked to the remote, a commit's subject line), wherever a refusal may follow.
without_ids() { sed -E 's/[0-9a-fA-F]{40,}/<a commit id, not shown>/g'; }
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

    # main and nothing else. Every other branch and every tag is a name the remote chooses, and
    # this script has no use for any of them: a tag named like a commit id is looked up as a ref
    # by some git commands that are handed the id, and a ref can be named to read as an argument
    # in the list git prints. Tags a clone already holds stay, so nothing below relies on this.
    #
    # Until this run has accepted origin/main, nothing it prints says which commit was fetched:
    # not a progress line, not a refusal. Where the operator is asked to name the commit
    # (--adopt-history), the id has to reach them some way that does not depend on the remote it
    # is checked against, and output that hands it over invites pasting it back. So the fetch is
    # quiet (git's summary line ends in the abbreviated id), and what it does print is held back
    # and shown without the part the remote wrote: a server can send any text it likes during a
    # fetch, and a ready-made "run upgrade.sh --adopt-history=<id>" above the refusal that asks
    # for the id is the obvious thing for a hostile one to send. A fetch that failed shows
    # everything, because that text is how an honest failure is diagnosed, with anything that
    # reads as a commit id taken out. This is a nudge, not a control: the id is in the clone,
    # one git command away.
    FETCH_FAILED=0
    FETCH_SAID="$(as_owner git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main' 2>&1)" || FETCH_FAILED=1
    if [ "$FETCH_FAILED" -eq 1 ]; then
        [ -z "$FETCH_SAID" ] || printf '%s\n' "$FETCH_SAID" | without_ids >&2
        refuse "the fetch from $ORIGIN_URL failed or brought no origin/main, so there is nothing to upgrade to" \
            "git's own message is above; a remote without a main branch is the usual reason for a missing ref"
    fi
    if [ -n "$FETCH_SAID" ]; then
        FETCH_LOCAL="$(printf '%s\n' "$FETCH_SAID" | grep -v '^remote:' || true)"
        [ -z "$FETCH_LOCAL" ] || printf '%s\n' "$FETCH_LOCAL" | without_ids >&2
        if [ "$FETCH_LOCAL" != "$FETCH_SAID" ]; then
            echo "    the remote sent text during the fetch, which is not shown: nothing a remote says is part of an upgrade" >&2
        fi
    fi

    # Resolved once, so the commit every check below looks at is the commit that gets merged: a
    # fetch from elsewhere (the owner's editor, a cron job, a second operator) between the checks
    # could otherwise move origin/main under them. A remote with no main branch is the usual
    # reason for a missing ref, and it must not be reported as a signature or ancestry failure.
    if ! TARGET="$(as_owner git rev-parse --verify --quiet 'refs/remotes/origin/main^{commit}')"; then
        refuse "the fetch from $ORIGIN_URL brought no origin/main, so there is nothing to upgrade to" \
            "the remote has no main branch, or the clone's fetch refspec does not include it"
    fi
    # And it has to be what THIS fetch brought. Git exits 0 from a fetch that updated nothing (a
    # shallow remote's main is rejected with a warning), and origin/main is then whatever an
    # earlier fetch left, possibly from another origin: deploying it would report an upgrade that
    # did not happen and, with --accept-origin, record an origin nothing came from.
    if [ "$(as_owner git rev-parse --verify --quiet 'FETCH_HEAD^{commit}' || true)" != "$TARGET" ]; then
        refuse "the fetch from $ORIGIN_URL did not deliver the origin/main this clone holds, so there is nothing new to check" \
            "git's own message, if any, is above; a shallow (depth-limited) remote is refused this way, and so is a second fetch that ran at the same moment" \
            "point the checkout at a full repository, or run the upgrade again"
    fi

    if [ -e "$SIGNERS_FILE" ]; then
        echo "    verifying origin/main against the signers in $SIGNERS_FILE"
        # gpg.format picks the SIGNING format only; verification picks its backend from the
        # signature itself, so a PGP-signed commit would be handed to gpg with the owner's keyring,
        # which the signers file does not govern (any imported key, such as GitHub's web-flow key,
        # would then pass). Both other backends are pointed at /bin/false so only an SSH signature
        # can verify, and the SSH backend is pinned so the owner's gitconfig cannot replace it.
        # What it prints is shown with commit ids taken out: on a malformed signature git quotes
        # the commit's own signature header, which is text whoever wrote the commit chose.
        VERIFIED=1
        VERIFY_SAID="$(as_owner git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$SIGNERS_FILE" \
            -c gpg.ssh.program=ssh-keygen -c gpg.program=/bin/false -c gpg.x509.program=/bin/false \
            verify-commit "$TARGET" 2>&1)" || VERIFIED=0
        [ -z "$VERIFY_SAID" ] || printf '%s\n' "$VERIFY_SAID" | without_ids >&2
        if [ "$VERIFIED" -eq 0 ]; then
            refuse "origin/main is not SSH-signed by a key in $SIGNERS_FILE, so it will not be deployed" \
                "sign the commit with a listed SSH key, add the key to the file, or remove the file to deploy unsigned commits"
        fi
    fi

    # A commit named with --adopt-history pins this run: origin/main must be that commit and no
    # other, whether or not its history turns out to need adopting. Checked before the ancestry
    # so the answer never depends on what the remote served.
    if [ -n "$ADOPT_COMMIT" ] && [ "$TARGET" != "$ADOPT_COMMIT" ]; then
        refuse "origin/main is not the commit --adopt-history names ($ADOPT_COMMIT)" \
            "either main has moved since you looked it up, or $ORIGIN_URL is not the repository you meant" \
            "look the commit up again at a source you trust and name that one, or drop the argument for an ordinary upgrade"
    fi

    # Where the operator finds the id. Not "the repository's page": for a hijacked hosting account
    # that page is the remote. The pin is worth what the channel it came through is worth.
    ADOPT_HINT="to deploy origin/main as it is, get the full commit id of its main branch through a channel that does not depend on this remote (the maintainer's announcement, a signed tag or release note, a clone made earlier on another machine) and run again with --adopt-history=<that commit id>"

    OLD_HEAD="$(as_owner git rev-parse --verify HEAD)"
    MOVED=1
    # The fetch took time, and the clean-tree check ran before it. Run again right before the
    # checkout moves, on either path. What it cannot see is a file created after it and before
    # the move, and that window is not closed here: the check after the move looks at tracked
    # files only, because an adopted tree may ignore different paths.
    still_clean() {
        local dirty
        dirty="$(as_owner git status --porcelain --untracked-files=normal)"
        if [ -n "$dirty" ]; then
            refuse "the checkout changed while this run was fetching, and a root-installed build must not include local changes:" \
                "$dirty" "commit, stash or discard them, then run the upgrade again"
        fi
    }
    # Only ever move forward onto what main has: a commit on this box that main lacks would be
    # merged into a root-installed build and would also never match the deploy stamp.
    if as_owner git merge-base --is-ancestor HEAD "$TARGET"; then
        if [ -n "$ADOPT_COMMIT" ]; then
            echo "    --adopt-history: origin/main already descends from this checkout, so this is an ordinary upgrade to the commit you named"
        fi
        still_clean
        # A merge git gives up on part-way has already rewritten some files: its failure goes to
        # the check after the move, which says where the checkout is, not out through `set -e`.
        as_owner git merge --ff-only "$TARGET" || MOVED=0
    elif [ -z "$ADOPT_COMMIT" ]; then
        if as_owner git merge-base --is-ancestor "$TARGET" HEAD; then
            # origin/main is an earlier commit of this checkout's own history: deploying it would
            # move the box backwards, which is what a remote that was rolled back looks like.
            refuse "origin/main is behind this checkout: it is an earlier commit of the same history, and this checkout is not an ancestor of origin/main" \
                "$(as_owner git rev-list --count "$TARGET..HEAD") commit(s) here are newer than origin/main, so deploying it would move this box backwards" \
                "$ADOPT_HINT"
        elif as_owner git merge-base HEAD "$TARGET" >/dev/null; then
            refuse "this checkout is not an ancestor of origin/main, so the upgrade cannot fast-forward" \
                "commits here that origin/main does not have:" \
                "$(as_owner git log --oneline -n 20 "$TARGET..HEAD" | without_ids)" \
                "if they were made on this box and should be kept, merge them into main and pull them back" \
                "$ADOPT_HINT; the commits listed above are then left behind"
        fi
        # No common commit at all. Listing "the commits origin/main does not have" would print
        # this checkout's whole history.
        refuse "this checkout shares no history with origin/main, so the upgrade cannot fast-forward" \
            "either the repository's history was restarted, or $ORIGIN_URL is a different repository" \
            "$ADOPT_HINT"
    else
        # Before the checkout moves: a main without this script is not a tree it can deploy, and
        # the lines after this block would be read from a file that is no longer there.
        if ! ADOPTED_SCRIPT="$(as_owner git cat-file blob "$TARGET:deploy/upgrade.sh" 2>/dev/null)"; then
            refuse "origin/main ($TARGET) has no deploy/upgrade.sh, so it is not a tree this script can deploy"
        fi
        # The rest of this run is handed to that script, on the understanding that it skips its
        # own pull when the guard variable is set. A fast-forward only ever reaches a script that
        # has the guard; an adoption can land on one from before it, which would pull again by
        # itself, with no pin, and deploy whatever main is by then.
        case "$ADOPTED_SCRIPT" in
            *PROPOLIS_UPGRADE_REEXEC*) ;;
            *) refuse "origin/main ($TARGET) carries a deploy/upgrade.sh from before the re-exec guard, so this run cannot hand over to it" \
                "run from that checkout it would pull a second time by itself, with none of the checks made here" ;;
        esac
        unset ADOPTED_SCRIPT
        echo "    --adopt-history: origin/main ($TARGET) does not contain this checkout's commit ($OLD_HEAD)"
        if as_owner git merge-base --is-ancestor "$TARGET" HEAD; then
            echo "    origin/main is BEHIND this checkout: adopting it moves this box backwards by $(as_owner git rev-list --count "$TARGET..HEAD") commit(s)"
        elif MERGE_BASE="$(as_owner git merge-base HEAD "$TARGET")"; then
            LEFT_BEHIND="$(as_owner git rev-list --count "$TARGET..HEAD")"
            echo "    the two share history up to $MERGE_BASE; $LEFT_BEHIND commit(s) here are not in origin/main and are left behind:"
            as_owner git log --oneline -n 20 "$TARGET..HEAD" | sed 's/^/      /'
            if [ "$LEFT_BEHIND" -gt 20 ]; then
                echo "      ... and $((LEFT_BEHIND - 20)) more"
            fi
        else
            echo "    the two share no history"
        fi
        # What the operator is agreeing to, in the one figure that matters: how much of what is
        # installed from here on differs from what this checkout held.
        if as_owner git diff --quiet "$OLD_HEAD" "$TARGET"; then
            echo "    every file is identical in both: adopting changes the history and no file"
        else
            # --no-renames: rename detection between two unrelated trees compares every pair of
            # files and adds nothing to a count.
            echo "    files differ between the two: $(as_owner git diff --no-renames --shortstat "$OLD_HEAD" "$TARGET" | sed 's/^ *//')"
        fi

        # The one thing an adoption can break that a fast-forward cannot: migrations only run
        # forward, so a daemon built from a tree that lacks a migration this database has already
        # run refuses to start. Git cannot see the database; it can see that the files are gone.
        mapfile -t LOST_MIGRATIONS < <(as_owner git diff --no-renames --name-only --diff-filter=D "$OLD_HEAD" "$TARGET" -- 'crates/*/migrations/*')
        if [ "${#LOST_MIGRATIONS[@]}" -gt 0 ]; then
            echo "    WARNING: origin/main lacks ${#LOST_MIGRATIONS[@]} database migration(s) this checkout has:"
            printf '      %s\n' "${LOST_MIGRATIONS[@]:0:10}"
            if [ "${#LOST_MIGRATIONS[@]}" -gt 10 ]; then
                echo "      ... and $((${#LOST_MIGRATIONS[@]} - 10)) more"
            fi
            echo "    a database that has run them is refused by the daemon this builds: propolis will not start until the database is"
            echo "    restored to a dump from before them (deploy/rollback.sh --with-database), which loses the events recorded since"
        fi

        still_clean

        # The commit being left is on no branch once the checkout moves, and a history that was
        # restarted cannot be fetched again: without a ref of its own git would expire it. Kept
        # under a name no fetch writes to, so the way back does not depend on the reflog.
        KEPT_REF="refs/propolis/before-adoption/$(date -u +%Y%m%dT%H%M%SZ)"
        if ! as_owner git update-ref "$KEPT_REF" "$OLD_HEAD"; then
            refuse "could not record this checkout's commit as $KEPT_REF, so the checkout was not moved"
        fi

        # A checkout, never a hard reset or a forced one: it refuses to overwrite a file edited
        # since the check above, and with --no-overwrite-ignore a box-local ignored file (.env, a
        # data directory) that the new tree has at the same path, where git's default is to
        # replace it without a word. The branch is named by stripping refs/heads/ from HEAD's own
        # target and the commit as <id>^{commit}: handed a short branch name or a bare id, git
        # looks either up as a ref first, and a tag of that name then decides where the branch
        # lands. Its exit status is not enough either (git reports a file it could not replace and
        # still exits 0), so what counts is the check after it.
        HEAD_REF="$(as_owner git symbolic-ref --quiet HEAD || true)"
        case "$HEAD_REF" in
            refs/heads/?*)
                as_owner git checkout --quiet --no-overwrite-ignore -B "${HEAD_REF#refs/heads/}" "$TARGET^{commit}" || MOVED=0 ;;
            *)
                as_owner git checkout --quiet --no-overwrite-ignore --detach "$TARGET^{commit}" || MOVED=0 ;;
        esac
    fi

    # The commit that was checked is the commit that is built, and nothing else is in the tree:
    # HEAD is that commit, every tracked file matches it, and no file the old commit had and
    # this one lacks is still on disk. This holds after a fast-forward as after an adoption, and
    # it is the guard that does not depend on how git resolved a name or on its exit status: git
    # reports a file it could not replace or remove and still exits 0, and a file it could not
    # remove is untracked from then on (cargo builds a stray build.rs or src/bin/*.rs without
    # being asked). Otherwise tracked files only: an adopted tree may ignore different paths, and
    # the box's own build output is not a change to what gets built.
    NOW_HEAD="$(as_owner git rev-parse --verify HEAD)"
    TREE_STATE="$(as_owner git status --porcelain --untracked-files=no)"
    LEFT_OVER=""
    # NUL-separated, so no file name needs unquoting. The last record is a marker written only
    # when git succeeded (a name git prints cannot start with that byte unquoted in practice,
    # and it would have to be the last one): without it the list cannot be trusted to be
    # complete, and a check that cannot be made is a refusal, not a pass.
    mapfile -d '' -t GONE < <(as_owner git diff --no-renames --name-only --diff-filter=D -z "$OLD_HEAD" "$TARGET" && printf '\001listed\0')
    if [ "${#GONE[@]}" -eq 0 ] || [ "${GONE[-1]}" != $'\001listed' ]; then
        MOVED=0
        LEFT_OVER="(could not list the files this move had to remove)"
    else
        unset 'GONE[-1]'
        for gone in ${GONE[@]+"${GONE[@]}"}; do
            # A regular file or a link. A directory here is the new commit's own: the path was a
            # file and is now a directory of tracked files.
            if [ -f "$REPO_DIR/$gone" ] || [ -L "$REPO_DIR/$gone" ]; then
                # Unless it is reached through a link: the new commit put a link where a
                # directory was, and the file found there belongs to the link's target.
                through_link=0
                parent="$gone"
                while [[ "$parent" == */* ]]; do
                    parent="${parent%/*}"
                    if [ -L "$REPO_DIR/$parent" ]; then
                        through_link=1
                        break
                    fi
                done
                if [ "$through_link" -eq 0 ]; then
                    LEFT_OVER+="${LEFT_OVER:+$'\n'}?? $gone"
                fi
            fi
        done
    fi
    if [ "$MOVED" -eq 0 ] || [ "$NOW_HEAD" != "$TARGET" ] || [ -n "$TREE_STATE" ] || [ -n "$LEFT_OVER" ]; then
        if [ "$NOW_HEAD" = "$OLD_HEAD" ]; then
            WHERE=("it has not moved from $OLD_HEAD")
        else
            WHERE=("it is at $NOW_HEAD and it was at $OLD_HEAD${KEPT_REF:+ (kept as $KEPT_REF)}")
        fi
        if [ -n "$TREE_STATE" ]; then
            WHERE+=("tracked files that do not match the commit it is at:" "$TREE_STATE")
        fi
        if [ -n "$LEFT_OVER" ]; then
            WHERE+=("files that commit does not have, still on disk:" "$LEFT_OVER")
        fi
        refuse "the checkout could not be moved cleanly onto the commit that was checked" \
            "${WHERE[@]}" \
            "the files listed are an edit made while this run was working, or what a move git could not finish left behind" \
            "git's own message, if any, is above. Fix what it names; then, as the checkout's owner, put back a file you did not edit with: git restore <file>" \
            "and remove a file listed with ??. Run the upgrade again when git status is clean: it carries on from the commit the checkout is on"
    fi
    if [ -n "${KEPT_REF:-}" ]; then
        echo "    this checkout is now at $TARGET; the commit it left ($OLD_HEAD) is kept as $KEPT_REF"
    fi

    SCRIPT_SUM_AFTER="$(sha256sum < "$SCRIPT_DIR/upgrade.sh")"
    if [ "$SCRIPT_SUM_BEFORE" != "$SCRIPT_SUM_AFTER" ]; then
        echo "==> deploy/upgrade.sh changed in the pull, re-executing the new version"
        export PROPOLIS_UPGRADE_REEXEC=1 PROPOLIS_UPGRADE_PULLED_AT="$PULLED_AT" \
            PROPOLIS_UPGRADE_ORIGIN_URL="$ORIGIN_URL"
        # --adopt-history is not handed on: the pull it governs is over, the re-executed run
        # skips this block, and an adopted tree whose script predates the argument would stop on
        # it with a usage error after the checkout had already moved.
        REEXEC_ARGS=()
        for arg in "$@"; do
            case "$arg" in
                --adopt-history=*) ;;
                *) REEXEC_ARGS+=("$arg") ;;
            esac
        done
        exec "$BASH" "$SCRIPT_DIR/upgrade.sh" ${REEXEC_ARGS[@]+"${REEXEC_ARGS[@]}"}
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
# The owner-role migration, run below between stopping and starting propolis where the roles are
# split; inert where /etc/propolis/migrate.env names no owner URL.
install -m 0755 "$SCRIPT_DIR/migrate.sh" /usr/local/sbin/propolis-migrate
# Every Propolis unit names this in OnFailure=; installed with them, nothing to enable.
install -m 0755 "$SCRIPT_DIR/alert.sh" /usr/local/sbin/propolis-alert
# The public-feed push runs from the operator's cron as propolis-blocklist out of a root-owned copy
# the account cannot edit; refreshed here so the copy never goes stale behind the checkout.
install -d -o root -g root -m 0755 /usr/local/lib/propolis
install -o root -g root -m 0755 "$SCRIPT_DIR/blocklist-sync.sh" /usr/local/lib/propolis/blocklist-sync.sh
install -o root -g root -m 0644 "$SCRIPT_DIR/blocklist-README.md" /usr/local/lib/propolis/blocklist-README.md
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

# Where the database roles are split (docs/operations/database-roles.md) the daemon's role cannot
# migrate, and refuses to start on a schema older than its binary. The owner role migrates here,
# with propolis stopped so the old release never runs against the new schema: the same order a
# restart gives a single-role node, whose daemon migrates as it starts.
if /usr/local/sbin/propolis-migrate --configured; then
    echo "==> stopping propolis, migrating as the owner role, starting propolis"
    systemctl stop propolis.service
    if ! /usr/local/sbin/propolis-migrate; then
        echo "error: the migration failed and propolis is stopped. Fix the cause and run 'propolis-migrate && systemctl start propolis', or put the previous release back with deploy/rollback.sh" >&2
        exit 1
    fi
    systemctl start propolis.service
else
    echo "==> restarting propolis (runs migrations)"
    systemctl restart propolis.service
fi

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
