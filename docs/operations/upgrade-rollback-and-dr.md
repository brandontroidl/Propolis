<!--
title: Upgrade, rollback and disaster recovery
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Upgrade, rollback and disaster recovery

## Upgrade model

Propolis is deployed from source. An upgrade is: pull the new source, rebuild
the release binaries, reinstall them, and restart the services. `deploy/upgrade.sh`
performs an in-place live upgrade on a node where `install.sh` has already run.

The script (run as root, `sudo ./deploy/upgrade.sh`):

1. Runs `git pull` and `cargo build --release` **as the repo-owner user**, not as
   root, so build output keeps the owner's identity.
2. Installs the built binaries (`propolis`, the 9 sensors, `gateway`, `shipper`)
   to `/usr/local/bin/` with `install -m 0755`.
3. Runs `deploy/provision.sh` (idempotent users + directories), reinstalls the
   production unit files and `logrotate-sensors.conf` (the same set `install.sh`
   installs; `gateway.service`/`shipper.service` only where already enabled), then
   runs `systemctl daemon-reload` so the restarts below pick up the new unit
   definitions.
4. Restarts each `sensor-*.service` **only if it is enabled**, then `gateway.service`
   if enabled.
5. Restarts `propolis.service`, so sensors reconnect and the daemon runs any new
   migrations after the binaries are in place, then `shipper.service` if enabled
   (after the gateway it dials).

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

## Rollback

Rollback of the **binaries** is straightforward: reinstall the previous release
binaries (rebuild from the prior source revision, or keep the prior
`/usr/local/bin/propolis` and sensor binaries aside before an upgrade) and
restart the services.

Rollback of the **database schema** is not shipped. Because migrations only run
forward and no down-migration exists, a schema that a newer binary has already
migrated cannot be automatically reverted to the older shape. If you must return
to an older binary after its migrations have applied, restore the pre-upgrade
database backup rather than trying to reverse the schema. This is the operational
reason to take a database backup immediately before every upgrade - see
[backup and restore](backup-and-restore.md).

> **Take a database backup before upgrading.** The forward-only migration model
> means an in-place schema change is not automatically reversible. Your rollback
> path for the database is the pre-upgrade dump, nothing else.

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

### Off-host backup is the missing piece

There is currently **no off-host backup mechanism shipped** with Propolis. Real
disaster recovery for a single-node deployment requires an off-host anchor that a
full host loss cannot touch: ship the database dump and the spool/config archives
(see [backup and restore](backup-and-restore.md)) to storage on independent
hardware, power, and network. Off-host replication of evidence is a recommended
operator responsibility and a planned platform capability, not a delivered
feature. `[planned]`

### Recovery is a claim to test

Possessing backups is not the ability to recover. Rehearse the full DR path -
provision a fresh host, restore config, restore the database, restore spool,
start, and verify per [backup and restore](backup-and-restore.md) - at least once,
and record the result. A recovery runbook that has never been executed against
real state is unverified.

### Multi-node note

A multi-node cluster shares one PostgreSQL database; the nodes are stateless
relative to that shared datastore, so DR still centres on the database and the
per-node spool. The shared database is the single failure domain the cluster does
not remove. See [deployment models](deployment-models.md).
