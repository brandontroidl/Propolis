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

The script (run as root, `sudo ./deploy/upgrade.sh [--accept-origin]`):

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
   leaving no database to roll back to.
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
   binaries are in place, then `shipper.service` if enabled (after the gateway it
   dials). `propolis.service` is restarted on every host, so the script must not be
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

Whatever the pull brings in is built and installed as root, so `upgrade.sh` checks four things
before it builds (`deploy/upgrade.sh#pull-and-reexec`). Each refusal says what it found and
ends with "nothing was built or installed"; the checkout is left where it was.

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
   (`git merge-base --is-ancestor`) and the move is `git merge --ff-only`. A commit on the box
   that `main` does not have is listed and refused: reset the checkout to `origin/main`, or
   merge the commits into `main` and pull them back.

`origin/main` is resolved to one commit right after the fetch, and the signature check, the
ancestry check and the merge all name that commit, so a fetch that lands in between (an
editor, a cron job, a second operator) cannot make the commit verified differ from the commit
merged. A fetch that brings no `origin/main` at all (a remote without a `main` branch, a
narrowed fetch refspec) is refused as that, not as a signature or ancestry failure.

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

There is **no separate migrate step**. The daemon embeds its migrations
(`sqlx::migrate!`) and runs them at startup: on boot it connects the pool, runs
the core-scoring migration set then the review migration set, and exits with a
non-zero status if either fails (a fail-fast, not a silent skip). The migration
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
that way stays counted once (nothing re-projects it). On one host the daemon runs sensors' intake and the
sensors together, so the order only matters when the sensors are upgraded separately.

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
owned by the same role, and the dump is restored into it by the
[documented procedure](backup-and-restore.md#restore-procedure). Events recorded since the
upgrade are in the renamed database, not the restored one; drop it yourself once you no longer
need them. This needs PostgreSQL on the same host (the script runs `psql` and `pg_restore` as
the `postgres` user); restore a remote database by hand with that page. An encrypted dump needs
the age identity that decrypts it: pass `--identity <file>`, or keep a box-local key at
`/etc/propolis/backup-identity.txt` (root, 0600) whose public half is also in
`backup-recipients.txt`.

The kept release records only the pre-upgrade set that upgrade wrote. An upgrade run with
`PROPOLIS_UPGRADE_SKIP_BACKUP=1`, or before `DATABASE_URL` was set, records none, so
`--with-database` refuses it rather than restore an older set from before an earlier upgrade.

Every refusal (no kept release, a release with no backup, a missing identity, no local
PostgreSQL, no `DATABASE_URL`, a database or role name that is not a plain identifier, an
unconfirmed prompt) happens before any service is stopped. The script also stops
`propolis-backup.timer` while it works, so a nightly dump cannot hold the database open
during the rename. If a step fails after the services are stopped, it says which step, names
the renamed-aside database if there is one, and starts the services again; check
`systemctl --failed` afterwards. Rolling back to a release from before the nightly backup
disables `propolis-backup.timer` until the next upgrade, because that release's binary has no
`pg-exec`.

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
