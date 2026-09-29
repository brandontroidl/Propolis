<!--
title: Backup and restore
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-28
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
tar -czf propolis-state-$(date +%F).tgz \
  /etc/propolis \
  /var/spool/propolis \
  /var/lib/propolis/ssh
```

Name each tree once. `tar` recurses into every directory it is given, and
`/var/spool/propolis` already contains each per-sensor spool and the `fetched`
quarantine, so listing a subdirectory beside its parent stores every file under
it twice. `crates/propolis/tests/docs_agreement.rs` fails the build if a `tar`
command in the docs names a path inside another one it also names.

Do not add `--numeric-owner`. Without it the archive records each file's owner by
user and group name as well as number, and a root extraction maps the names onto
the target host's accounts. `deploy/provision.sh` creates the service users with
`useradd --system`, which assigns their UIDs dynamically, so the same user can have
a different number on a rebuilt host; an archive holding only numbers would hand
each restored file to whichever local account holds the old number, possibly a
different service.

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
3. **Restore the database.** `pg_dump` records object ownership and grants but
   not roles, so on a new PostgreSQL server create the daemon's `propolis` role
   first, then an empty database it owns, then load the dump:

   ```
   # Example - run as a PostgreSQL superuser on the new server.
   psql -c 'CREATE ROLE propolis LOGIN'
   psql -c 'CREATE DATABASE propolis OWNER propolis TEMPLATE template0'
   pg_restore --exit-on-error --dbname=propolis propolis-2026-09-28.dump
   ```

   Then give the role the password your `DATABASE_URL` carries (`\password
   propolis` in `psql`). Without the role the restore fails with `role
   "propolis" does not exist`; `--exit-on-error` makes it stop there instead of
   continuing past errors, which is `pg_restore`'s default. Do not add
   `--no-owner` or `--no-privileges`. With `--no-owner` the restoring superuser
   owns every table and the daemon's startup migrations fail with `permission
   denied for table _sqlx_migrations`. With `--no-privileges` the `event`
   ledger's append-only revoke (see
   [reference/database.md](../reference/database.md)), which travels in the dump
   as a privilege statement, is dropped and the `propolis` role can update,
   delete and truncate the ledger again. `template0` keeps anything added to
   `template1` on the new server out of the restored database. Because the
   daemon runs its own migrations at startup and migrations are additive (see
   [upgrade, rollback and DR](upgrade-rollback-and-dr.md)), restore into a schema
   the current binary can migrate forward - restoring an older dump and starting
   a newer binary is the supported direction.
4. **Restore spool and host key.** On a rebuilt host, run `deploy/provision.sh`
   first so the service users exist, then unpack the state archive as root, which
   keeps modes and maps each file's recorded owner name onto the local account:

   ```
   # Example - run as root on the rebuilt host.
   tar -xpzf propolis-state-2026-09-28.tgz -C /
   ```

   The SSH host key under
   `/var/lib/propolis/ssh` restores the prior fingerprint; omit it only if you
   intend a fresh identity.
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

## Restore rehearsal

`crates/propolis/tests/restore_rehearsal.rs` runs this page's backup and restore
end to end against populated data. It supplies its own paths, cluster and
database, so it runs its own `pg_dump`, `pg_restore` and `tar` commands rather
than these verbatim, with the same options: a test that needs no PostgreSQL, and
so runs in CI, fails if a command on this page and the rehearsal's version of it
pass different options, in either direction. The rehearsal itself is `#[ignore]`d
in the normal suite because it needs the PostgreSQL server binaries plus a
`pg_dump` and `pg_restore` of the same major version, which CI does not install. Point it at that `bin` directory:

```
RESTORE_REHEARSAL_PG_BIN=/usr/lib/postgresql/18/bin \
  cargo test -p propolis --locked --test restore_rehearsal -- --ignored --nocapture
```

It needs no `DATABASE_URL` and touches no existing server: it creates two
throwaway clusters with `initdb` under `target/tmp`, listening only on 127.0.0.1
in ports 56001-56999, and stops both and deletes its scratch directory whether it
passes or fails. `--nocapture` prints the figures recorded below. An unset or
incomplete `RESTORE_REHEARSAL_PG_BIN` fails the test rather than skipping it.

What it does:

1. **Builds a node's state** in a fresh cluster: the `propolis` role and
   database, the daemon's migrations in startup order, a few hundred hash-chained
   events from 16 addresses across 7 sensors and 13 signal types (session-end
   telemetry included), and review, vendor-submission, fetch, verdict and
   fleet-probe rows. Events and projections, the review queue, fetch attempts and
   probe results go through the crates' own write paths. Vendor submissions and
   verdicts are inserted directly in the shape those paths write, because the real
   paths need a vendor or VirusTotal on the other end. Sample bodies go into the
   `ssh`, `telnet` and `fetched` spools through the quarantine spool, so every file
   name is the digest the database references.
2. **Backs it up** with `pg_dump --format=custom` and the `tar` inputs read from
   the archive command on this page (re-rooted under a scratch directory), checks
   the archive holds no member twice, then stops the source cluster and deletes its
   data directory and spool tree.
3. **Restores** into a second, freshly `initdb`'d cluster by the procedure above
   (role, empty database from `template0`, `pg_restore --exit-on-error`) and
   unpacks the archive into a new root.
4. **Compares and verifies**, failing on any difference:
   - every table's row count and an md5 over the text of every row; named
     aggregates (event max id, chain head hash, weight sum, per-signal counts;
     `ip_score` raw-score sum, event and established-event sums, eligibility, tier
     and active-day figures; review, fetch and vendor breakdowns); sequence
     positions; index, constraint, enum, trigger and function definitions; and the
     `propolis` role's privileges on `event`;
   - the daemon's migrations run against the restored database and change nothing;
   - `verify_chain` returns `Intact` over the whole restored ledger, and every
     `ip_score` row equals the projection replayed from the restored events;
   - an event appended after the restore takes the next id, chains onto the
     restored head and still verifies; a new `vendor_submission` id does not
     collide; every sequence sits at or above its column's maximum;
   - the linkage trigger still refuses a forged `prev_hash`, and the `propolis`
     role still cannot `UPDATE` the ledger;
   - the restored spool matches the source file for file (size and `0640` mode),
     and every sample an event, a `fetch_attempt` or a `sample_analysis` row
     references is read back through the spool's verified reader and re-hashes to
     its name.

What it proves: a logical `pg_dump`/`pg_restore` of a populated database into a new
cluster of the same PostgreSQL major version reproduces every row, sequence
position, grant and schema object; the restored hash chain verifies and accepts new
events; and the documented archive carries every sample body the database
references, unaltered.

What it does not prove: physical base backups, WAL archiving or point-in-time
recovery; file ownership after extraction (it runs unprivileged, so the root-only
mapping of recorded owner names onto a host whose service users have different
UIDs is GNU tar's behaviour as documented, not exercised here); restoring
across PostgreSQL major versions; a dump taken while the daemon is writing; volumes
beyond a few hundred rows; or recovery of `/etc/propolis` and the SSH host key,
which placeholders stand in for.

### Rehearsal record

**2026-09-28 - pass.** PostgreSQL 18.0 server, `pg_dump` and `pg_restore` 18.0,
GNU tar 1.35; restored into a fresh cluster (`initdb`), not only a fresh database.
Re-run at 2026-09-29 00:03 UTC on the tree that adds the documented-option check,
with the same result; the review migration count below is from that run, as the
first record predated review migration `0007`.

| Table | Rows, source = restored |
|---|---|
| `event` | 340 (51 session-end telemetry) |
| `ip_score` | 16 |
| `review_queue` | 13 (10 pending, 1 approved, 1 rejected, 1 snoozed) |
| `vendor_submission` | 3 (1 succeeded) |
| `fetch_attempt` | 7 (2 success, 2 rejected, 1 timeout, 2 pending, 1 still claimed) |
| `fetch_daily_usage` | 1 |
| `sample_analysis` | 4 (1 pending verdict) |
| `listener_probe` | 3 |
| `_sqlx_migrations`, `_sqlx_migrations_review`, `_sqlx_migrations_fleet` | 12, 7, 1 |

- Every table's row digest, every named aggregate and every schema-object digest
  matched. Chain head `f6699ed522fc7f4633dc0a358a8f1b52006e1215fae1c4adf3a4bb899e90d994`
  at id 340; event weight sum 11563.
- `ip_score`: raw-score sum `1483.287754040193170329669452938`, event-count sum 289,
  established-event sum 248, active-day sum 42, 16 eligible, 13 recommended for
  vendor and tiered `aggressive`; all 16 projections replay from the restored ledger.
- `verify_chain`: `Intact` over 340 restored events, and over 341 after a
  post-restore append (id 341, `prev_hash` = the restored head).
- Sequences: `event_id_seq` 340 and `vendor_submission_id_seq` 3, each equal to its
  column maximum.
- `event` privileges for `propolis`: of SELECT, INSERT, UPDATE, DELETE and
  TRUNCATE, only SELECT and INSERT, before and after.
- Samples: 20 spool files restored identical to the source, at `0640`; 40 event references (9
  distinct bodies), 2 `fetch_attempt` references and 4 `sample_analysis` rows
  re-hash to their names. Archive: 28 members, none repeated.
- Checked the same day that the rehearsal fails when it should: restoring with
  `--no-privileges` (the revoke is lost), with `--no-owner` (startup migrations are
  refused), into a server without the `propolis` role, with one restored sample
  altered, with `fetched` left out of the archive, and with the archive command
  naming `fetched` beside its parent.
