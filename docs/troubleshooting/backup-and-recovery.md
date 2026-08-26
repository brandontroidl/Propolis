<!--
title: Troubleshooting — backup and recovery
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Backup and recovery

Backup/restore procedure is owned by
[Backup and restore](../operations/backup-and-restore.md); upgrade/rollback and
disaster recovery by
[Upgrade, rollback and DR](../operations/upgrade-rollback-and-dr.md). This page
covers recovery problems and, above all, **verifying the restore path actually
works** before you need it.

> Propolis does not ship a backup tool or a scheduled backup timer in `deploy/`.
> What follows is guidance on what state matters and how to confirm a restore,
> not a shipped automation. `[inferred]` where noted.

## What state actually needs protecting

| State | Where | Regenerable? |
|---|---|---|
| Event ledger + scores | PostgreSQL (`event`, `ip_score`, `review_queue`, `vendor_submission`, `sample_analysis`, …) | ledger: **no**; projections rebuild from ledger |
| Secrets / config | `/etc/propolis/*.env` (0600, operator-authored) | no — not in the repo |
| SSH host key | `/var/lib/propolis/ssh/host_key` | technically yes, but regenerating changes the honeypot's fingerprint |
| Cursor state | `/var/lib/propolis/cursors` | yes — reingest re-derives, may reprocess logs |
| Published feed | `PROPOLIS_FEED_OUTPUT_DIR` (default `/var/lib/propolis/feed/current`) | yes — rebuilt each interval from the DB |
| Captured samples | `/var/spool/propolis/*` | no — live malware evidence, not reproducible |

The **database is the primary backup target.** The `event` ledger is append-only
and hash-chained; everything else in the DB is a projection that can be rebuilt
from it. Paths: [Filesystem paths](../reference/filesystem-paths.md); tables:
[Database reference](../reference/database.md).

> **Warning — sensitive contents.** `/etc/propolis/*.env` files carry secrets
> (DB password, console password, vendor keys) and the spool holds live malware.
> Encrypt these backups at rest and restrict access; do not copy the spool onto a
> general-purpose host. See
> [Secret management](../operations/secret-management.md) and
> [Malware custody](../security/malware-custody.md).

## Testing the restore path (do this before you rely on it)

A backup you have never restored is unverified. Exercise it end to end against a
scratch environment, not production:

1. Restore the database dump into a fresh PostgreSQL instance.
2. Point a non-production `propolis` at it with a throwaway
   `DATABASE_URL`/console password. Startup will run migrations against the
   restored schema — a **migration failure here** means the dump and the binary
   version disagree; reconcile before trusting the backup (see
   [Database](database.md)).
3. Verify the hash chain: open the console integrity page and run
   `POST /integrity/verify`, or wait for the ops monitor's periodic verify if
   enabled. A **broken chain** after restore means the dump captured the ledger
   inconsistently (mixed points in time) or was altered — the restore is not
   trustworthy. An intact chain is the go/no-go signal.
4. Confirm projections rebuild: scores, queue, and feed should populate from the
   restored ledger on the normal loops.

If any step fails, fix the backup process — do not assume "reversible."

## Common recovery problems

- **Migrations fail on the restored DB** — version skew between the dump's schema
  and the running binary. Restore with the matching code version, or migrate
  forward deliberately. Never edit an already-applied migration to force it.
- **Integrity reports broken after restore** — the ledger rows are inconsistent.
  Re-take the dump with a consistent snapshot (e.g. a single transaction /
  `pg_dump` point-in-time), not a piecemeal copy.
- **Sessions gone after restore/restart** — expected. Console sessions are
  in-memory and never persisted; you re-log-in. Not a recovery failure.
- **Feed empty immediately after restore** — expected; the publisher rebuilds it
  on the next `PROPOLIS_FEED_BUILD_INTERVAL_SECS` cycle from the restored DB.
- **SSH fingerprint changed** — if you did not restore
  `/var/lib/propolis/ssh/host_key`, the sensor generates a new key and the
  honeypot presents as freshly minted. Restore the key to preserve continuity.
- **Reingesting duplicates events** — cursor state under
  `/var/lib/propolis/cursors` tracks how far each sensor log was consumed;
  restoring stale cursors (or none) against retained logs can reprocess events.
  The ledger's dedup and hash chain bound the damage, but restore cursors
  alongside the logs they pair with `[inferred]`.

## Multi-node note

A cluster shares one PostgreSQL database, so the DB backup covers all nodes'
scoring state. Per-node state to protect separately is each node's
`/etc/propolis/*.env`, its SSH host key, and its captured spool. Deployment
models: [Deployment models](../operations/deployment-models.md).
