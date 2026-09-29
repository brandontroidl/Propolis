<!--
title: Troubleshooting - database
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Database problems

Every Propolis binary that stores or reads state connects to one PostgreSQL
database via `DATABASE_URL` and runs its migrations at startup. Schema, tables,
enums, and migration list are owned by
[Database reference](../reference/database.md); this page covers symptoms.

## Connection failures at startup

Phase 2 of daemon startup connects the pool; on failure it logs
`propolis: failed to connect to PostgreSQL` and exits 1
(`crates/propolis/src/main.rs#main`). Check, in order:

1. `DATABASE_URL` is correct and reachable - host, port, database name, and the
   inline password. Test independently: `psql "$DATABASE_URL" -c 'SELECT 1'` as
   the service user's environment.
2. PostgreSQL is up and accepting connections (`systemctl status postgresql`).
   The unit orders after `postgresql.service` but does not wait for readiness
   beyond TCP connect.
3. `pg_hba.conf` permits the connection. For a containerized Postgres, do **not**
   rely on `host all all all trust` - that is called out as unsafe in the
   install notes. Use a scoped rule with password auth.
4. If the DB is remote, the daemon needs outbound to its port (default 5432) and
   the firewall must allow it.
5. Pool sizing: `PROPOLIS_DB_MAX_CONNECTIONS` (default 10) caps connections per
   binary. Running the unified daemon plus standalone services, or multiple
   nodes against one DB, multiplies demand on `max_connections` server-side.

## Migration failures at startup

Phase 3 runs three independent migration histories against the same database:
core-scoring migrations, then review, then fleet
(`crates/propolis/src/main.rs#main`). The review and fleet histories are each
tracked in their own table (`_sqlx_migrations_review`,
`crates/review/src/lib.rs#migrator`; `_sqlx_migrations_fleet`, `crates/fleet/src/lib.rs#migrator`)
so the three do not collide. Failure logs `core-scoring migrations
failed`, `review migrations failed`, or `fleet migrations failed` and exits 1.

Common causes:

- **Schema drift** - the database was previously migrated by a different code
  version, or a migration was applied then its `.sql` edited. Never edit an
  already-applied migration in place; it corrupts recorded state. Rebuild the
  environment from a known-good source instead.
- **Insufficient privilege** - the connecting role cannot create/alter tables.
  The role needs DDL rights on the target database.
- **Partial prior run** - a migration interrupted mid-way. Inspect the `_sqlx_*`
  migration tables and the referenced objects; reconcile against the migration
  list in [Database reference](../reference/database.md).

Migrations run automatically at every start - there is no separate migrate step
to invoke.

## `/ready` returns 503

`GET /ready` is fail-closed: it runs `SELECT 1` against the pool, then checks
whether any supervised subsystem has given up, and returns
`200 {"status":"ok"}` only when both pass
(`crates/console/src/routes/health.rs#ready`). Any DB error - closed
pool, network error, timeout - returns `503 {"status":"unavailable"}`
(`crates/console/src/routes/health.rs#ready`). A subsystem that has exhausted its restarts returns
`503 {"status":"unavailable","gave_up":[...]}` (`crates/console/src/routes/health.rs#ready`). A 503
therefore means the console process is alive but either cannot reach the
database or has a dead subsystem; a `gave_up` field in the body tells the two
apart. Distinguish from liveness:

```
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/health   # 200 = process serving
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/ready    # 503 = DB unreachable
```

A persistent 503 with a healthy `/health` and no `gave_up` field points at the
database or the pool, not the web layer. The daemon logs `readiness check: database ping failed` with the
error. See [Health and observability](../operations/health-and-observability.md).

## Hash-chain / integrity page reports "broken"

The `event` ledger is append-only and hash-chained. The console integrity page
(`GET /integrity`, `POST /integrity/verify`) runs `core_scoring::verify_chain`
over the ledger and reports intact or broken
(`crates/console/src/routes/integrity.rs#run_verify`). The POST changes no
state, but it still requires the session's CSRF token like every other console POST
(`crates/console/src/routes/integrity.rs#run_verify`).

A **broken** result means a stored event's hash does not chain to its
predecessor. This indicates the `event` table was modified out of band - direct `UPDATE`/`DELETE` on `event`, a restore that mixed rows from different
points in time, or storage corruption. Investigate before trusting downstream
scores. Note that the console's own delete actions (`delist`,
`crates/console/src/routes/queue.rs#delist`; `delete_ip`, `crates/console/src/routes/queue.rs#delete_ip`)
**never touch the `event` ledger** - they only touch projection rows
(`delist` deletes the `review_queue` row and latches `ip_score` as delisted;
`delete_ip` deletes the `review_queue`, `vendor_submission` and `ip_score` rows),
which can be rebuilt from the ledger. So operator deletes are
not a cause of chain breakage.

If ops-alerting is enabled, the monitor periodically re-verifies the chain on the
`PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS` interval (default 6h) and pages on a
break; see [Integrations and feed](integrations-and-feed.md).

## Restoring or rebuilding projection state

Because scores/queue/submissions are a projection of the immutable ledger, a
corrupted projection (not the ledger) can be discarded and rebuilt. Ledger
integrity is the thing to protect; see
[Backup and recovery](backup-and-recovery.md) for verifying a restore end to end.
