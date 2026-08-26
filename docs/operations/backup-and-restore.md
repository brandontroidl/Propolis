<!--
title: Backup and restore
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Backup and restore

Propolis ships **no backup or restore tool**. This page describes what state
exists, where it lives, and a recommended procedure built from standard tools.
Treat everything here as operator guidance, not a shipped capability.

> **Recovery is unverified until you test it.** A backup you have never restored
> is a hypothesis. Rehearse the restore end to end against a scratch environment
> before you depend on it. See
> [upgrade, rollback and DR](upgrade-rollback-and-dr.md) for the single-node
> blast-radius context that makes this matter.

## What holds state

Three categories of durable state, in descending order of importance.

### 1. PostgreSQL - the canonical datastore

Everything scored, queued, reviewed, and published derives from the database.
It is the one component whose loss is not recoverable from anything else on the
node. It holds the append-only `event` ledger (with its tamper-evident hash
chain), the `ip_score` aggregates, the review queue, vendor-submission records,
fetch-attempt records, and sample verdicts. Tables and migrations are owned by
[reference/database.md](../reference/database.md).

The daemon connects via `DATABASE_URL` and manages its own schema; the database
itself is created and administered by the operator, never by `install.sh`. See
[secret management](secret-management.md) for where `DATABASE_URL` lives and
[installation](installation.md) for the database-provisioning step.

### 2. Spool directories

On-disk working state under `/var/spool/propolis` and `/var/lib/propolis`. The
canonical owner of these paths is
[reference/filesystem-paths.md](../reference/filesystem-paths.md); the queue and
spool lifecycle is described in [queue-and-spool](queue-and-spool.md). The parts
worth backing up:

| Path | Contents | Recoverable elsewhere? |
|---|---|---|
| `/var/spool/propolis/<sensor>` | Per-sensor capture spool | No (raw capture) |
| `/var/spool/propolis/fetched` | Fetched malware samples (quarantine, 1 GB global budget) | No (custody evidence) |
| `/var/lib/propolis/cursors` | Per-sensor log-read cursors | Rebuilds by re-reading logs |
| `/var/lib/propolis/ssh` | Persistent SSH host key | Regenerates, but changes the honeypot fingerprint |
| `/var/lib/propolis/feed/current` | Published feed output | Rebuilds from the database on the next feed cycle |

The captured sample bodies and quarantined fetched malware are custody evidence
and are **not** reconstructable from the database (the database stores only the
SHA-256 reference and verdict, per
[reference/database.md](../reference/database.md)). Losing the SSH host key does
not lose data but re-mints the honeypot's identity, which attackers can
fingerprint.

The feed output directory rebuilds itself: the in-process publisher regenerates
`/var/lib/propolis/feed/current` on each build cycle from `ip_score`, so it does
not strictly need backup - a database backup implies it.

### 3. Configuration and secrets

Per-service environment files under `/etc/propolis/*.env` (mode `0600`, owned by
each service user), created by hand by the operator. They carry the database
password (inline in `DATABASE_URL`), the console password, the optional session
secret, and any vendor / VirusTotal / ntfy keys. The full inventory and handling
rules are owned by [secret management](secret-management.md).

> **These files contain live secrets.** Back them up to encrypted storage only,
> with access controls at least as strict as the `0600` originals. Never place
> them in a repository, a shared drive, or any backup that is not encrypted at
> rest.

## Recommended backup procedure

This is an example built from standard tooling; adapt it to your environment.

### Database

Use PostgreSQL's own dump tool. A logical dump is portable across minor versions
and simple to verify:

```
# Example - run as a role with read access to the propolis database.
pg_dump --format=custom --file=propolis-$(date +%F).dump "$DATABASE_URL"
```

The `event` ledger is append-only and the hash chain is self-verifying, so a
consistent point-in-time dump preserves tamper-evidence: a restored ledger
re-verifies against the same golden encoding (see the hash-chain description in
[reference/database.md](../reference/database.md)). For a large or busy node,
prefer physical base backups plus WAL archiving (`pg_basebackup` +
`archive_command`) so you can restore to a point in time; that is standard
PostgreSQL practice and outside the scope of this project.

### Spool and configuration

Archive the durable directories and the config tree. Preserve ownership and
modes - the `0600` env files and per-sensor `0750` spool dirs are load-bearing.

```
# Example. Run as root to preserve per-service ownership.
tar --numeric-owner -czf propolis-state-$(date +%F).tgz \
  /etc/propolis \
  /var/spool/propolis/fetched \
  /var/spool/propolis \
  /var/lib/propolis/ssh
```

Store the config/secrets archive encrypted and separately from the data archive
if you can, so a data-restore workflow never needs to touch the secret material.

## Restore procedure

> **Restore overwrites live state.** Every step below replaces or reconstructs
> production data. Run it against a fresh node or a scratch database first, and
> stop the daemon before restoring anything it might be writing.

1. **Stop the platform.** `systemctl stop propolis.service` and each
   `sensor-*.service` (see [service lifecycle](service-lifecycle.md)) so nothing
   writes while you restore.
2. **Restore configuration.** Unpack `/etc/propolis` (or recreate the `*.env`
   files by hand per [secret management](secret-management.md)). Confirm modes
   are `0600` and ownership matches each service user.
3. **Restore the database.** Create an empty database, then load the dump
   (`pg_restore` for a custom-format dump). Because the daemon runs its own
   migrations at startup and migrations are additive (see
   [upgrade, rollback and DR](upgrade-rollback-and-dr.md)), restore into a schema
   the current binary can migrate forward - restoring an older dump and starting
   a newer binary is the supported direction.
4. **Restore spool and host key.** Unpack the state archive, preserving owners
   and modes. The SSH host key under `/var/lib/propolis/ssh` restores the prior
   fingerprint; omit it only if you intend a fresh identity.
5. **Start the platform** and verify. On startup the daemon connects, runs
   migrations, and spawns subsystems; confirm liveness/readiness per
   [health and observability](health-and-observability.md) and confirm the feed
   rebuilds. The publisher will regenerate `/var/lib/propolis/feed/current` on
   its next cycle even if you did not restore it.

## Verification

A restore is not "done" until you have confirmed:

- `/ready` returns 200 (database reachable) - see
  [health and observability](health-and-observability.md).
- Recent events are present and the hash chain re-verifies (the daemon's
  chain-verify pass; DB-layer linkage is enforced on insert per
  [reference/database.md](../reference/database.md)).
- The console loads and the review queue shows the expected pending set.
- The feed directory is regenerating on schedule.

Record the date and result of each restore rehearsal. An untested backup is a
residual risk, not a control.
