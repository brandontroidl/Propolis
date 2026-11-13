<!--
title: Upgrade, rollback and disaster recovery
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-12
-->

# Upgrade, rollback and disaster recovery

## Upgrade model

Propolis is deployed from source. An upgrade is: pull the new source, rebuild
the release binaries, reinstall them, and restart the services. `deploy/upgrade.sh`
performs an in-place live upgrade on a node where `install.sh` has already run.

The script (run as root, `sudo ./deploy/upgrade.sh [--accept-origin] [--adopt-history=<commit>]`):

1. Fetches and fast-forwards the checkout to `origin/main`, then runs
   `cargo build --release --workspace --locked`, both **as the repo-owner user**, not as
   root, so build output keeps the owner's identity and dependency resolution cannot drift
   from the reviewed lockfile. The pull is held to the checks in
   [what the pull trusts](#what-the-pull-trusts) and stops before the build when one
   fails.
2. Takes a [backup](backup-and-restore.md#the-nightly-backup) of the database and state as a
   `-pre-upgrade` set, then keeps the running release (its binaries, the Propolis unit files,
   the `propolis-*` helpers in `/usr/local/sbin` and the deploy stamp) under
   `/var/lib/propolis/rollback/<time>-<commit>/` with the name of that backup, for
   [rollback](#rollback); the newest 3 are kept (`deploy/upgrade.sh#pre-upgrade`). Both happen
   before anything is installed, so a failure in either leaves the box as it was. The backup
   runs the binary just built, because the installed one may predate the `propolis pg-exec`
   it needs. `PROPOLIS_UPGRADE_SKIP_BACKUP=1` skips the backup (the release is still kept),
   leaving no database to roll back to. The backup refuses, and so stops the upgrade here
   with nothing installed, when the backup volume would not keep the ops monitor's low-disk
   threshold and logrotate's 512 MiB reserve free after the set is written
   ([free space](backup-and-restore.md#the-nightly-backup)). Free space on that volume, run
   a scheduled backup with a lower `PROPOLIS_BACKUP_KEEP` (`sudo systemctl edit
   propolis-backup.service`, then `sudo systemctl start propolis-backup.service`) to prune
   the old sets, move `PROPOLIS_BACKUP_DIR` to a larger volume, or skip the backup for this
   one upgrade with `PROPOLIS_UPGRADE_SKIP_BACKUP=1`. `config-check.sh` warns about a
   retention that cannot fit before an upgrade meets it.
3. Installs the built binaries (`propolis`, the 12 sensors, `gateway`, `shipper`)
   to `/usr/local/bin/` with `install -m 0755`.
4. Runs `deploy/provision.sh` (idempotent users + directories), then
   `deploy/provision-tls.sh`, which mints a self-signed TLS pair for each
   TLS-capable sensor that lacks one and leaves any existing pair, including an
   operator-supplied real certificate, untouched (`deploy/upgrade.sh#provision-tls.sh`;
   run by hand with `sudo deploy/provision-tls.sh`, `DRY_RUN=1` to preview, see
   [networking-tls.md](networking-tls.md#sensor-tls-attacker-facing-listeners)).
   It then reinstalls the production unit files and `logrotate-sensors.conf` (the same set `install.sh`
   installs; `gateway.service`/`shipper.service` only where already enabled), then
   runs `systemctl daemon-reload` so the restarts below pick up the new unit
   definitions.
5. Restarts each `sensor-*.service` **only if it is enabled**, then `gateway.service`
   if enabled.
6. Restarts `propolis.service`, so the daemon runs any new migrations after the
   binaries are in place. Where the [database roles are split](database-roles.md) the
   daemon cannot migrate: the script stops it, runs `propolis-migrate` as the owner role,
   and starts it, and a failed migration ends the upgrade with the daemon stopped. Then
   `shipper.service` if enabled (after the gateway it dials). `propolis.service` is restarted on every host, so the script must not be
   run on a collector of a [split deployment](split-deployment.md#upgrading).
   The "restarting propolis" step waits for the old process to stop before the new one
   starts, which takes at most 37 s (30 s subsystem grace, 2 s abort, 5 s pool close; see
   [service lifecycle](service-lifecycle.md#stop-and-graceful-shutdown)). The journal names
   any subsystem that had to be aborted. Ctrl-C there only stops `systemctl` waiting; the
   stop continues in the background.

The unified daemon is the production surface; the standalone `intake`/`review`/
`feed`/`console` units are superseded by it and are not part of the upgrade
path. See [deployment models](deployment-models.md) and
[service lifecycle](service-lifecycle.md).

### What the pull trusts

Whatever the pull brings in is built and installed as root, so `upgrade.sh` checks five things
before it builds (`deploy/upgrade.sh#pull-and-reexec`). Each refusal says what it found and
ends with "nothing was built or installed". The first four leave the checkout where it was. The
fifth is made after the checkout has moved, so a refusal there normally leaves it on the new
commit with the installed release still the old one; the message says where the checkout is
and how to put right what it lists.

1. **A clean tree.** `git status --porcelain --untracked-files=normal` must print nothing: an
   uncommitted edit on the box, tracked or untracked, would otherwise be built and installed
   as though it had been reviewed and merged. The refusal lists the files. Commit, stash or
   discard them. Ignored paths (`target/`, `.env`) are outside what `git status` reports, so
   the check does not see them; nothing in the build reads them today.
2. **The origin the last deploy pulled from.** The deploy stamp
   (`/var/lib/propolis/deploy-stamp.json`, `deploy/deploy-stamp.sh#origin_url`) records the
   `origin` URL of every install and upgrade, without any userinfo an https URL may carry.
   An upgrade whose `git remote get-url origin` differs from the record is refused before
   anything is fetched: the remote is box-local git configuration, and a remote that changed
   under root's feet is a decision for the operator, not something the script discovers by
   building from it. When the move is deliberate, run `sudo ./deploy/upgrade.sh --accept-origin`
   once (or re-run `install.sh`); that run's stamp records the new origin and later runs need
   no flag. The first upgrade after this check exists has no record to compare with: it records
   the origin and goes on. A stamp whose record is present but empty is different: the last
   deploy could not read the checkout's remote (see the note below) and the upgrade refuses
   until `--accept-origin` records one, rather than leaving the check unarmed silently.
3. **A signature, when you have opted in** (below). With `/etc/propolis/upgrade-signers`
   present, the fetched `origin/main` must carry an SSH signature by a key in that file. Only
   SSH signatures are accepted: a PGP or X.509 signature fails whatever keys the box holds.
4. **A fast-forward.** `HEAD` must be an ancestor of the fetched `origin/main`
   (`git merge-base --is-ancestor`) and the move is `git merge --ff-only`. Anything else is
   refused, and the refusal says which of three shapes it met: a `main` that shares no commit
   with the box, a `main` that lacks commits the box has (they are listed), or a `main` that
   is an earlier commit of the box's own history. None of the three is deployed without the
   operator naming the commit:
   [a restarted history](#a-restarted-history-or-a-successor-repository), below.
5. **The move itself.** The clean-tree check runs a second time right before the checkout
   moves, because the fetch took time. After the move the checkout must be at the commit that
   was checked, with no tracked file differing from it and no file left on disk that the new
   commit removed. Git reports a file it could not replace or remove and still exits 0, a
   file it could not remove is untracked from then on, and cargo builds a stray `build.rs` or
   `src/bin/*.rs` without being asked: a root-installed build must hold the commit and nothing
   else. A fast-forward git gave up on part-way ends here too, with the checkout not moved
   and some files already rewritten. When this check refuses, fix what git names, put the
   listed files right (`git restore <file>` for one you did not edit, remove one marked `??`)
   and run the upgrade again; it carries on from the commit the checkout is on. One window stays open: a new, untracked file
   created between the second clean-tree check and the move is not seen, because after the
   move only tracked files are compared (an adopted tree may ignore different paths).

`origin/main` is resolved to one commit right after the fetch, and the signature check, the
ancestry check and the merge all name that commit, so a fetch that lands in between (an
editor, a cron job, a second operator) cannot make the commit verified differ from the commit
merged. The fetch asks for the `main` branch and nothing else
(`deploy/upgrade.sh#--no-tags`): every other ref is a name the remote chooses, and a tag
named like a commit id or a branch whose name reads as an argument has no business in the
box's clone or on the operator's terminal. A remote without a `main` branch is refused as
that, not as a signature or ancestry failure. So is a fetch that exits 0 without delivering
`main` (git only warns when a shallow, depth-limited remote's `main` is rejected): the
`origin/main` the clone holds from an earlier fetch is never used in its place
(`deploy/upgrade.sh#FETCH_HEAD`).

The checks run only on the first pass: when the pull changed `upgrade.sh` itself, the
re-executed copy carries on from the pull it already did.

**Whom the checks hold against.** They hold against the remote and against operator mistakes
(a mistyped `set-url`, an edit left on the box, a push to `main` that should not have
happened). They do not hold against the account that owns the checkout: that account builds
`target/release/*`, which root installs unchanged, and owns `.git/hooks` and its own
`~/.gitconfig`, so it can already put anything it likes into a release. It is trusted by
construction, the same way the operator running `sudo` is. The signers file's `root 0644`
rule is about every other non-root account on the box, none of which may be able to list a
key of its own.

Every git command in the pull runs as the checkout's owner, because git refuses root a
directory someone else owns. The stamp is written by root after the install, so the origin
is handed over from the pull (`PROPOLIS_DEPLOY_ORIGIN_URL`) rather than read again as root:
git exempts root only for the uid in `SUDO_UID`, and an admin account upgrading a checkout a
deploy user owns would otherwise record an empty origin on every deploy and never arm the
check. `install.sh`'s stamp reads it as the owner for the same reason
(`deploy/deploy-stamp.sh#origin_url_as_owner`).

### A restarted history or a successor repository

Sometimes `origin/main` legitimately stops being a descendant of what a box runs: the
repository's history was squashed into a new first commit, the project moved to a successor
repository that starts from one, or `main` was rewritten or deliberately moved back. To the
fast-forward check each of these is indistinguishable from a mispointed or hijacked remote,
because nothing in a history that does not contain the box's commit ties it to the code on
the box. So the operator supplies the tie: the exact commit they expect `origin/main` to be.

```
# Example - run as root. The commit id reaches you some way that does not depend on this remote.
sudo ./deploy/upgrade.sh --adopt-history=<full commit id of the new main>
```

The argument exists from the release that added it. A box whose own `deploy/upgrade.sh` is
older answers it with a usage line and does nothing; such a box takes the
[steps by hand](#a-box-whose-upgradesh-predates-the-argument).

What the argument does (`deploy/upgrade.sh#ADOPT_COMMIT`):

- **It pins the run.** `origin/main` must be exactly the commit named, given as a full commit
  id; an abbreviation or a ref name is a usage error before anything is contacted, and so is
  the argument given twice. Any other commit on `origin/main` is refused, whether or not
  adopting turns out to be needed, so naming a commit never lets a different one through.
- **It widens one check, the fast-forward, and only for that commit.** The named commit is
  deployed whichever of the three shapes it has, including a `main` that is an earlier commit
  of the box's own history: the argument is the one thing that moves a box backwards, and the
  run says `BEHIND` in as many words before it does (see
  [moving backwards](#moving-backwards-and-the-database) first). The clean tree, the recorded origin and,
  with a signers file, the SSH signature are checked first and as before. An unsigned commit
  is not adopted on a box that requires signatures
  (`crates/sensor-framework/tests/deploy_test.rs#upgrade_adopt_history_with_signers_refuses_an_unsigned_commit_and_adopts_a_signed_one`).
- **It says what you are accepting.** Before the checkout moves, the run prints whether the
  two histories share any commit, the commits on the box that are left behind when they do,
  and how many files differ between the box's commit and the new one, or that every file is
  identical and only the history changed.
- **It never discards local content.** The clean-tree check runs a second time after the
  fetch. The move is a plain checkout, never forced and never a hard reset, so a file edited
  even later is left alone and the run stops; it also refuses to replace a file the box
  ignores (its own `.env`, a data directory) that the new tree happens to track. Afterwards
  check 5 applies as on any upgrade: the named commit, no tracked file differing from it, no
  removed file still on disk, or nothing is built
  (`crates/sensor-framework/tests/deploy_test.rs#upgrade_adopt_history_never_discards_or_builds_an_edit_made_during_the_run`).
- **It keeps the commit the box left.** That commit is on no branch afterwards, and on a
  restarted history it cannot be fetched again, so the run records it as
  `refs/propolis/before-adoption/<UTC time>` and prints the name. The ref does not expire.
  `git checkout -B main refs/propolis/before-adoption/<UTC time>`, as the checkout's owner,
  puts the checkout back on it (name the checkout's own branch if it is not `main`, or use
  `git checkout --detach` with the ref on a detached one); the installed release goes back
  with [`rollback.sh`](#rollback), as after any upgrade.
- **The rest of the run is the adopted tree's own `upgrade.sh`,** started without the
  argument: a tree from before the argument existed would stop on it after the checkout had
  already moved. The hand-over relies on that script skipping its own pull, so a `main` whose
  `upgrade.sh` is from before the re-exec guard is refused before anything moves: it would
  pull a second time by itself, with no pin. So is a `main` with no `deploy/upgrade.sh` at all
  (`crates/sensor-framework/tests/deploy_test.rs#upgrade_adopt_history_refuses_a_script_from_before_the_reexec_guard`).

**Where the commit id comes from.** The check is worth what the id's source is worth. It has
to reach you through a channel the remote being checked does not control: the maintainer's
announcement, a signed tag or release note you can verify, a clone made earlier on another
machine. The repository's own web page is the remote; when the worry is a hijacked
repository, it is not a second source.

Until a run has accepted `origin/main`, nothing it prints says which commit was fetched: not
the three refusals that ask for the argument, not the one that says the commit named is not
`origin/main`, not the signature refusal
(`crates/sensor-framework/tests/deploy_test.rs#upgrade_prints_the_fetched_commit_in_no_refusal_whichever_shape_the_remote_picks`).
The same goes for what the remote can make git print
(`crates/sensor-framework/tests/deploy_test.rs#upgrade_shows_nothing_the_remote_says_in_a_refused_run`).
Nothing a fetch printed is shown when the fetch worked: a server can send any text during
one, an ssh remote's text arrives with nothing to mark it as the remote's, and a
`Run: upgrade.sh --adopt-history=<id>` above the refusal that asks for an id is the obvious
thing for a hostile one to send. A fetch that failed, or delivered nothing, shows what was
printed, because that is how an honest failure is diagnosed, with anything that reads as a
commit id taken out; the same is taken out of git's signature messages and of the commit
subjects a refusal lists.

That is a nudge, not a control. The id is in the box's clone and one `git rev-parse` reads it
out; the script only declines to hand over a value that, pasted back, would check nothing.
What stands between a hostile remote and a root install is the operator taking the id from
somewhere else, and with signing on, the signature. Nothing a remote says during an upgrade
is an instruction.

#### Moving backwards, and the database

Migrations only run forward ([below](#migrations-are-additive-and-run-at-startup)). A tree
that lacks a migration this box's database has already run builds a daemon that refuses to
start, exactly as after a [rollback](#rollback) of the binaries alone. That is what adopting
a `main` moved back across a migration does, and what adopting a rewritten `main` or a
successor's snapshot does when it lacks migrations the box has. The run warns before it
moves, naming the migration files the adopted tree lacks
(`crates/sensor-framework/tests/deploy_test.rs#upgrade_adopt_history_warns_when_the_adopted_tree_lacks_migrations_the_box_has`),
and goes on, because git cannot see the database. Check before you run it:

```
# Example - as the checkout's owner; prints the migrations the commit you would adopt lacks.
git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main'
git diff --no-renames --name-only --diff-filter=D HEAD <full commit id> -- 'crates/*/migrations/*'
```

If it prints anything, the installed release and its database go back first, and the adoption
second:

1. `sudo ./deploy/rollback.sh --list`, then
   `sudo ./deploy/rollback.sh --with-database <release>` with a release from before those
   migrations. That puts back its binaries and the dump taken before the upgrade that ran
   them; the events recorded since stay in the renamed database, not the restored one.
2. `sudo ./deploy/upgrade.sh --adopt-history=<full commit id>`, so the checkout follows.

The other way round leaves `propolis` stopped, and a bare `rollback.sh --with-database` at
that point is no way out: it puts back the release the adoption just replaced, with the dump
that run took, which is the newer database again. Only the newest three releases are kept; a
release further back is a [restore by hand](backup-and-restore.md#restore-procedure). Or
wait until `main` has passed the box again.

**Moving a running box to a successor repository.** Three steps, in this order, because the
box's own copy of `upgrade.sh` has to know the argument before it can be given it:

1. Upgrade normally while the box still points at the old repository, so it takes the release
   whose `upgrade.sh` has `--adopt-history`.

   ```
   # Example - run as root.
   sudo ./deploy/upgrade.sh
   ```

2. Point the checkout at the new repository, as the account that owns the checkout.

   ```
   # Example - replace the URL with the successor repository's.
   git -C /path/to/checkout remote set-url origin https://example.invalid/owner/propolis.git
   ```

3. Upgrade once with both arguments: one accepts the new origin, the other names the commit.
   Neither stands in for the other
   (`crates/sensor-framework/tests/deploy_test.rs#upgrade_adopt_history_does_not_stand_in_for_accepting_a_changed_origin`).

   ```
   # Example - run as root.
   sudo ./deploy/upgrade.sh --accept-origin --adopt-history=<full commit id of the new main>
   ```

Later upgrades need neither argument: the box is on the new history and fast-forwards along
it. A split deployment's collectors do not run `upgrade.sh`; they follow by hand after the
control plane ([split deployment](split-deployment.md#following-a-restarted-history)).

#### A box whose upgrade.sh predates the argument

Step 1 is not available when the old repository is gone, or when the history was restarted
in place before the box took the release with the argument. The same checks can be made by
hand, and they keep the pin because every command after the fetch names the commit id and
none names the ref. As the account that owns the checkout, from the top of it:

```sh
# Example - ID is the full commit id of the new main, from a channel the remote does not control.
ID=<full commit id of the new main>
git remote get-url origin    # read it: the remote you mean (set-url first when moving)
# One command: each step runs only if the one before it succeeded.
[ "$(git symbolic-ref --quiet HEAD)" = refs/heads/main ] &&
[ -z "$(git status --porcelain --untracked-files=normal)" ] &&
OLD="$(git rev-parse --verify HEAD)" &&
git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main' &&
[ "$(git rev-parse --verify 'FETCH_HEAD^{commit}')" = "$ID" ] &&
[ "$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')" = "$ID" ] &&
{ [ ! -e /etc/propolis/upgrade-signers ] ||
  git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/etc/propolis/upgrade-signers \
      -c gpg.ssh.program=ssh-keygen -c gpg.program=/bin/false -c gpg.x509.program=/bin/false \
      verify-commit "$ID^{commit}"; } &&
git diff --shortstat "$OLD" "$ID^{commit}" &&
git update-ref "refs/propolis/before-adoption/$(date -u +%Y%m%dT%H%M%SZ)" "$OLD" &&
git checkout --quiet --no-overwrite-ignore -B main "$ID^{commit}" &&
[ -z "$(git status --porcelain --untracked-files=no)" ] &&
[ "$(git rev-parse HEAD)" = "$ID" ] &&
git diff --no-renames --name-only --diff-filter=D -z "$OLD" "$ID^{commit}" |
    xargs -0 -r sh -c 'for p; do d="$p"; while [ "$d" != "${d%/*}" ]; do d="${d%/*}"; [ -L "$d" ] && continue 2; done; if [ -f "$p" ] || [ -L "$p" ]; then echo "still on disk: $p"; exit 1; fi; done' sh &&
echo "OK: the checkout is on the commit named" ||
echo "STOPPED: a step failed and nothing after it ran"
```

In order: the checkout is on `main`; the tree is clean; `main` and nothing else is fetched,
and this fetch delivered it; `origin/main` is the commit named; with a signers file on the
box, that commit carries a listed key's SSH signature; the number of files that differ is
printed, which is what you are accepting; the commit being left is recorded, because it is on
no branch afterwards and cannot be fetched again from a restarted history; the branch moves,
without replacing ignored files; and the result is the named commit, with no tracked file
differing from it and no file the new commit removed still on disk (a file reached through
a link the new commit put where a directory was is the link target's, not a leftover). A step
that fails prints `STOPPED` and leaves the rest undone.

Three things the block does on purpose. `"$ID^{commit}"` rather than the bare id: handed a
bare id as the start point, `git checkout -B` looks it up as a ref name first, and a tag of
that name would decide where the branch lands. `ID` is set before anything is fetched:
whatever a remote prints during a fetch is the thing being checked, never a source for the
id. And it moves `main` only: on a checkout that is on another branch, put that branch's name
in the first line and in the `-B` line; on a detached one, drop the first line and use
`git checkout --quiet --no-overwrite-ignore --detach "$ID^{commit}"`. With signing on, the
signature is checked here, before the checkout: the next step runs the new tree's
`upgrade.sh` as root, and a signature checked only by the code it is meant to vouch for is
not a check. The [database](#moving-backwards-and-the-database) caution applies to this path
as to the script's.

The checkout now carries an `upgrade.sh` that has the argument, so the deploy itself is the
ordinary pinned run, as root (`--accept-origin` only when the remote changed):

```
# Example - run as root, with the same id.
sudo ./deploy/upgrade.sh --accept-origin --adopt-history=<full commit id of the new main>
```

It fetches again, refuses if `main` is no longer the commit named, finds the checkout already
on it and carries on to the build.

### Signed upgrades (recommended)

Fast-forward and origin pinning make the pull deploy exactly what `origin/main` is. Without
signing, that is the whole guarantee: a remote that is hostile or hijacked (a compromised
hosting account or push credential, a `core.sshCommand` or an https interception the owner's
CA store accepts) can serve any commit that descends from `HEAD`, and the box fetches it,
builds it and installs it as root; origin pinning and fast-forward-only stop a mispointed
remote and a rollback, not the remote itself. Signing makes the pull deploy only what a
holder of a listed key published: a compromised remote, a hijacked repository or a mistaken
push to `main` then fails verification on the box instead of being built as root. It is off
by default and turned on by one file on the box:

```
sudo install -m 0644 -o root -g root /dev/null /etc/propolis/upgrade-signers
```

`upgrade-signers` is an SSH allowed-signers file (`ssh-keygen -Y`, OpenSSH 8.2 or later; git
runs `ssh-keygen` as the repo owner). One line per key that may publish a release:

```
you@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

The first word is a label git reports; the key is the public half of the signing key. The
file must be a regular file (not a symbolic link), root's and writable by no one else
(`0644`), or another non-root account that can edit it could list its own key; the script
refuses a file that is not, before it contacts the remote.

On the machine you commit from, sign every commit with SSH:

```
ssh-keygen -t ed25519 -f ~/.ssh/propolis-signing -C "propolis signing"
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/propolis-signing.pub
git config --global commit.gpgsign true
```

(`user.signingkey` can name the public key when `ssh-agent` holds the private one, or the
private key file itself.) `cat ~/.ssh/propolis-signing.pub` is the rest of the signers line.

What this does and does not cover:

- Only the commit at `origin/main` is verified, every time, including when the checkout is
  already at it. The signature says who published the tip, not that every ancestor was
  signed.
- Only an SSH signature by a listed key passes. `git verify-commit` picks its backend from the
  signature, not from `gpg.format`, so the script points the PGP and X.509 backends at
  `/bin/false`: a PGP-signed commit is refused even when the owner's keyring holds the
  signer's key. A merge or squash commit made in the GitHub web interface is PGP-signed by
  GitHub's web-flow key and is therefore refused, so with signing on, land work on `main`
  from the command line (`git merge --ff-only`, or a rebase and push).
- The signature proves who published the commit, not that it was meant for `main`. The remote
  can present any commit a listed key signed that descends from `HEAD`, including a signed
  branch never meant to be released, and the box deploys it.
- The remote can withhold new commits indefinitely (a freeze); nothing on the box detects
  that `main` has moved elsewhere. The fleet pane's `origin_main_sha` is what the last fetch
  saw, not a live query.
- **CI does not verify signatures**, and nothing in the repository enforces them. The check
  happens on the box, against that box's file, at upgrade time only. A key is rotated by
  adding the new line, upgrading, then removing the old one.
- Removing the file turns verification off again; the next upgrade says nothing about it.

These are the residual risks of deploying from the repository; they are listed with the
others in [residual risks](../security/residual-risks.md#deploying-from-the-repository).

> **Rebuild after any dependency or vendoring change.** Run
> `cargo build --release --locked` and confirm it succeeds before restarting -
> a release build can fail where a debug/test build passed. Build/gate commands
> are owned by
> [development/build-and-test.md](../development/build-and-test.md).

### Migrations are additive and run at startup

On a node with one database role there is **no separate migrate step**. The daemon
embeds its migrations (`sqlx::migrate!`) and runs them at startup: on boot it connects
the pool, runs the core-scoring, review and fleet migration sets, and exits with a
non-zero status if one fails (a fail-fast, not a silent skip). On a node with
[split database roles](database-roles.md) the same sets are run by `propolis migrate` as
the owner role, and the daemon only checks that they are applied. The migration
inventory is owned by [reference/database.md](../reference/database.md).

Migrations are additive by design: new columns arrive with defaults or as
backfills over existing rows, so an older database restores cleanly and a newer
binary migrates it forward. Examples in the shipped set are the eligibility
backfill, the calendar-day count, and the TCP-only established-count column - all
add state to existing rows rather than requiring a destructive transform (see
[reference/database.md](../reference/database.md)).

The supported direction is **forward**: restore an older database, start a newer
binary, let it migrate. There is no shipped down-migration.

### Upgrade the intake side before the sensors

The sensor-to-intake log line gains optional fields over time, and an intake that predates one
ignores it rather than refusing the line. When sensors and intake run on different hosts
([split deployment](split-deployment.md#upgrading)), upgrade the control plane (intake) first and
the collectors after. The shell reply field is the current case: a reply recorded while a sensor
is newer than intake is dropped, the event is still ingested and the chain is unaffected, and the
console shows no reply for that command. The cred sensor's connection and login summaries are the
second case: an intake that predates them scores one as a single event, and a summary ingested
that way stays counted once (nothing re-projects it), while a rebuild of that address's projection
from the ledger (`rebuild_projection`) counts it as the events it stands for, so the rebuilt and
the stored score disagree until the address is rescored. On one host the daemon runs sensors'
intake and the sensors together, so the order only matters when the sensors are upgraded
separately.

## Rollback

Every upgrade keeps the release it replaces (step 2 above). `deploy/rollback.sh` puts one back:

```
sudo ./deploy/rollback.sh --list
sudo ./deploy/rollback.sh
sudo ./deploy/rollback.sh --with-database
```

`--list` shows the kept releases, newest first, with the commit each was built from and its
pre-upgrade backup. Without arguments it rolls back to the newest one; name another to pick
it. It shows what it is about to do and asks you to type the release name (`--yes` skips
that). Then it stops the enabled services, puts the kept binaries, helpers, unit files and
deploy stamp back, reloads systemd, starts the services again and waits for
`propolis.service` to stay up.

**When the upgrade changed the schema**, the binaries alone are not enough. Migrations only run
forward and no down-migration exists, so the older daemon refuses the newer database at
startup, and the script says so when it sees a migration error in the journal. Run it with
`--with-database` to also restore the release's pre-upgrade dump. It never drops anything: the
current database is renamed to `<name>_before_rollback_<time>`, a new empty one is created
with the owner the current one has (not the role `DATABASE_URL` connects as, which is a
different role where the [database roles are split](database-roles.md)), and the dump is
restored into it by the [documented procedure](backup-and-restore.md#restore-procedure).
Events recorded since the
upgrade are in the renamed database, not the restored one; drop it yourself once you no longer
need them. The restored ledger no longer holds the chain heads later backups recorded, so run one
backup with `PROPOLIS_BACKUP_ACCEPT_LEDGER_RESET=1` afterwards
([why](backup-and-restore.md#when-the-ledger-does-not-match-a-backup)).

On a node with split roles the script puts the split back and checks it after the restore,
before it starts any service (`deploy/rollback.sh#restore_role_split`):

1. While everything still runs it reads the role the daemon connects as and the owner role
   `migrate.env` names. If the owner role cannot connect, it refuses. If the database belongs
   to the daemon's role (which is what a `--with-database` rollback left on such a node before
   it kept the owner), it says so and creates the restored database for the owner role.
2. If the dump is from before the roles were split, every table in it belongs to the daemon's
   role. A freshly split node is in this position until its next upgrade, because the split
   starts with an upgrade and the kept dump was taken before it. The script runs the split's
   own first step on the restored database, `propolis migrate --init-roles` as the `postgres`
   user over the server's socket, with the binary it rolled back to.
3. It runs `propolis-migrate` and then `propolis-migrate --check`.
4. It asks PostgreSQL itself whether the daemon's role controls the `event` table, owns the
   database or may create objects in the ledger's schema. The check in step 3 is answered by
   the release that was rolled back to, and a release from before that check looked at the
   database's owner calls a database owned by the daemon's role protected.

If any of these fails the rollback fails, saying that the split is not confirmed on the restored
database, and the services are started all the same. Depending on the step, the daemon then
runs with the ledger not protected from its role, or refuses to start because the owner role's
migration did not run. The way out is the same either way and is printed: stop `propolis`,
repeat [the step that moves ownership](database-roles.md#splitting-the-roles-on-an-existing-node)
(it is safe to repeat), then `propolis-migrate` and `propolis-migrate --check`. Rolling back to
a release from before `propolis migrate` on a node with split roles also needs
[ownership handed back](database-roles.md#going-back-to-one-role); the script cannot do that for
you, says so, and goes on.

`--with-database` needs PostgreSQL on the same host (the script runs `psql` and
`pg_restore` as the `postgres` user); restore a remote database by hand with that page. An
encrypted dump needs the age identity that decrypts it: pass `--identity <file>`, or keep a
box-local key at
`/etc/propolis/backup-identity.txt` (root, 0600) whose public half is also in
`backup-recipients.txt`.

The kept release records only the pre-upgrade set that upgrade wrote. An upgrade run with
`PROPOLIS_UPGRADE_SKIP_BACKUP=1`, or before `DATABASE_URL` was set, records none, so
`--with-database` refuses it rather than restore an older set from before an earlier upgrade.

Before it stops anything, `--with-database` checks the set it is about to restore
(`deploy/rollback.sh#verify_set`): the files against the set's `SHA256SUMS`, that the dump
decrypts with the identity, and that `pg_restore --list` can read it. A set from before backups
wrote `SHA256SUMS` is restored with a note that it could not be verified. It also compares the
current database's size with the space free on the volume that holds PostgreSQL's data
directory, because the restore loads a second copy while the current database is kept aside; if
either figure cannot be read it says the check was not made and goes on.

Every refusal (no kept release, a release with no backup, a missing identity, no local
PostgreSQL, no `DATABASE_URL`, a database or owner name that is not a plain identifier, an
owner that cannot be read, on a node with split roles an owner role that cannot connect, a set
that does not match its `SHA256SUMS` or whose `SHA256SUMS`
does not list the dump, a dump the identity does not decrypt or `pg_restore --list` cannot
read, less free space than the current database's size, an unconfirmed prompt) happens before
any service is stopped. The script also stops `propolis-backup.timer` while it works, so a
nightly dump cannot hold the database open during the rename. If a step fails after the
services are stopped, it says which step and starts the services again; check
`systemctl --failed` afterwards. When the failure comes after the database was renamed aside
and before the dump is fully restored, the script first puts the
real database back (`deploy/rollback.sh#put_database_back`): the incomplete one is renamed to
`<name>_failed_restore_<time>` and the renamed-aside one gets its name back, so the daemon
starts on the database it had. With the kept binaries it then either runs or refuses a newer
schema at startup; go forward again with `deploy/upgrade.sh`. If the real database cannot be
put back, the sensors, the gateway and the shipper are started and `propolis.service` is left
stopped, so that it cannot begin a new ledger in an empty database, and the message names the
database that holds the real data. The script does not go by its own record of what it had
done: it asks PostgreSQL which names exist, so a database that was never renamed is left alone
and said to be where it was, and if PostgreSQL cannot be asked the daemon is likewise left
stopped and the message names both places the data can be. Nothing is dropped in any case.
Wherever the daemon is left stopped it is also disabled, because a stopped unit that is still
enabled starts at the next boot, on whatever database holds the name by then; the message
gives the `systemctl enable --now propolis.service` to run once the database is back. The
nightly backup's timer, which the script stops while it works, is started again when a run
fails with the database in place, and stays off while the daemon is held back.

A signal ends the run the same way a failed step does (`deploy/rollback.sh#on_exit`). The
restore is the long step and a rollback is usually run over SSH: if the session drops, the
restore is killed with it, the real database is put back and the services are started. A signal
sent to the script alone is acted on once the step in progress has finished. What a failed run
reports is also written to the journal, because the terminal may be gone:
`journalctl -t propolis-rollback`. To keep a long restore going through a dropped session, run
the rollback inside `tmux` or `screen`.

Rolling back to a release from before the nightly backup disables `propolis-backup.timer` until
the next upgrade, because that release's binary has no `pg-exec`.

## Disaster recovery

### Single-node blast radius

The default deployment is a single node: one daemon, its sensors, and one
PostgreSQL instance, typically on one host. That host is a single failure domain.
Loss of the host loses the running platform **and**, if the database and spool
live on the same host, the canonical datastore and the custody evidence with it.
Redundancy inside one host (a second disk, a co-located replica) is not disaster
recovery - it shares the failure domain.

What is irreplaceable if the host is lost and nothing left it:

- The `event` ledger and `ip_score` state (the datastore itself).
- Captured sample bodies and quarantined fetched malware under
  `/var/spool/propolis` (custody evidence; the database keeps only references).

What is not lost with a database backup: the feed output regenerates from
`ip_score`, and log cursors rebuild by re-reading logs.

### Off-host backup

Real disaster recovery for a single-node deployment needs an off-host anchor that a full host
loss cannot touch. The node backs itself up nightly and a machine on independent hardware,
power and network pulls each encrypted set over a restricted SSH key
([off-host copies](backup-and-restore.md#off-host-copies)); until that pull is set up, every
backup is on the same disk as what it protects.

### Recovery is a claim to test

Possessing backups is not the ability to recover. Rehearse the full DR path -
provision a fresh host, restore config, restore the database, restore spool,
start, and verify per [backup and restore](backup-and-restore.md) - at least once,
and record the result. A recovery runbook that has never been executed against
real state is unverified. The database and spool part of that path has a
repeatable rehearsal against populated scratch clusters; its scope and last
result are in [backup and restore](backup-and-restore.md#restore-rehearsal). It
does not cover provisioning a host, service-user ownership, or configuration.

### Multi-node note

A multi-node cluster shares one PostgreSQL database; the nodes are stateless
relative to that shared datastore, so DR still centres on the database and the
per-node spool. The shared database is the single failure domain the cluster does
not remove. See [deployment models](deployment-models.md).
