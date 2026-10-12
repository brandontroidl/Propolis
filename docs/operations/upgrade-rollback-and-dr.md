<!--
title: Upgrade, rollback and disaster recovery
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Upgrade, rollback and disaster recovery

## Upgrade model

Propolis is deployed from source. An upgrade is: pull the new source, rebuild
the release binaries, reinstall them, and restart the services. `deploy/upgrade.sh`
performs an in-place live upgrade on a node where `install.sh` has already run.

The script (run as root, `sudo ./deploy/upgrade.sh`):

1. Runs `git pull` and `cargo build --release --workspace --locked` **as the
   repo-owner user**, not as root, so build output keeps the owner's identity and
   dependency resolution cannot drift from the reviewed lockfile.
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
console shows no reply for that command. On one host the daemon runs sensors' intake and the
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
