<!--
title: Storage and database model
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Storage and database model

Propolis uses **PostgreSQL as its single datastore**. There is no second database,
no message broker, and no external queue: sensors write local NDJSON logs, intake
tails those logs and appends to Postgres, and every downstream reader (scoring,
review, feed, console) reads the same database. Captured file bodies are the one
thing that lives outside Postgres — they sit in an on-disk quarantine spool and are
referenced from the database by SHA-256 (see
[event and sample lifecycle](./event-and-sample-lifecycle.md)).

Exact table columns, enum variants, and the migration list are owned by
[reference/database.md](../reference/database.md). This page describes the
model — the append-only ledger, its enforcement, and the projections derived from
it — and links there for the values.

## Two schema-owning crates

Schema is split across two migration sets:

- **`core-scoring`** owns `event`, `ip_score`, `sample_analysis`, and all five enum
  types (11 migrations).
- **`review`** owns `review_queue`, `vendor_submission`, `fetch_attempt` (3
  migrations). It depends on the `review_state_enum` created by core-scoring's first
  migration — a deliberate cross-crate schema dependency so the schema is complete.

Migrations are **additive and applied-once**. A migration that has run is never
edited in place; the current canonical shape is what the runtime reads, and legacy
shapes are normalized only inside explicit migration code.

## The append-only event ledger

`event` is the system of record: an **append-only, hash-chained ledger** of every
observation. Two independent mechanisms make it append-only, one at the application
layer and one at the database layer.

### Hash chain (tamper-evidence)

Every event carries a SHA-256 `hash` over a **frozen canonical byte encoding** of its
own content, chained to the prior event's hash:

```
hash = SHA256( prev_hash_or_empty || canonical_bytes(event) )
```

`canonical_bytes` (`crates/core-scoring/src/hashing.rs`) writes a fixed set of fields
in a fixed order, each variable-length field length-prefixed with a `u64`
little-endian length so adjacent fields cannot blur into one another. It deliberately
does **not** serialize the whole struct as JSON (JSON key order is incidental and
fragile). The exact field order and framing are owned by
[reference/database.md](../reference/database.md) and are pinned by a **golden test
vector** — if that vector changes, the frozen encoding changed and every historical
hash would be invalidated.

Fields that are **not** hashed: the row `id`, `ingested_at`, `session_id`,
`prev_hash`, and `hash` itself. `session_id` in particular was added later precisely
so it could correlate a sensor session's events **without** altering the chain (it is
absent from `canonical_bytes`), and pre-existing rows degrade gracefully.

What the chain guarantees: **tamper-evidence**. Any change to a hashed field of any
event, or any reordering or insertion, breaks the linkage from that event forward.
What it does **not** provide: confidentiality, or protection against deletion by a
database superuser — append-only enforcement is a separate control (below).

### Database-layer enforcement

Two migrations back the chain at the database, not just in Rust:

- **Chain-linkage trigger** — a `BEFORE INSERT FOR EACH ROW` trigger
  (`enforce_chain_linkage()`) reads the current chain head (the `hash` of the
  max-`id` row) and rejects any insert whose `prev_hash` does not match it (or, for
  the first event, is not `NULL`). It raises an exception before the row lands, so a
  fabricated or missing `prev_hash` is **fail-closed**. The DB enforces linkage only;
  the hash value itself is still computed application-side.
- **Privilege revoke** — in the production database only (recognized by the database
  name `propolis` and the presence of the `propolis` role), the hardening migration
  runs `REVOKE UPDATE, DELETE, TRUNCATE ON event FROM propolis`. The application role
  keeps `INSERT` for intake but **cannot mutate, delete, or truncate** the ledger.
  Test databases skip the revoke. The same migration also adds CHECK constraints
  (32-byte hash, non-empty sensor, confidence in [0,1], non-negative weight) after
  deleting any rogue rows.

### Serialized single-writer append

All appends serialize against **one transaction-scoped Postgres advisory lock**
(`pg_advisory_xact_lock`, `crates/core-scoring/src/repository/events.rs`). The
transaction pins `READ COMMITTED` isolation, then acquires the lock before the
chain-head read, so the chain-head read, event INSERT, projection read, and
`ip_score` UPSERT all run as **one serialized critical section**. This guarantees,
under any number of concurrent callers, that the chain cannot fork (no two appends
read the same `prev_hash` and both insert against it) and the projection UPSERT
cannot lose an update. The lock auto-releases at transaction end, so a rolled-back
append never leaves it held. See
[concurrency and failure](./concurrency-and-failure.md).

All event inserts are fully parameterized (`$n` bound values via the runtime
`sqlx::query*` API); no SQL query text is built with string formatting anywhere in
non-test source.

## Projections derived from the ledger

`ip_score` is a **per-IP projection** of the ledger: an aggregate keyed on
`source_ip`, advanced by the same transaction that appends the event. It holds the
running score inputs (raw score, decay anchor, max confidence, event and category
counts, distinct WAN/sensor counts, first/last seen) and the derived feed flags
(`eligible`, `recommended_for_vendor`, `recommended_for_blocklist`, `tier`,
`delisted`). Because it is a projection, it can be **rebuilt from the ledger** — which
is exactly why the console's `delete_ip` action purges the `ip_score` and review rows
but deliberately never touches the `event` ledger.

Two projection columns are worth calling out for their integrity intent (values and
formulas owned by [reference/scoring-and-feed.md](../reference/scoring-and-feed.md)):

- `active_days` — an unbounded, non-decaying count of distinct UTC calendar days an
  IP was seen, so a slow attacker the time-decay would otherwise erase can still earn
  a tier.
- `established_event_count` — counts only non-spoofable completed-TCP-connection
  events, so a spoofed UDP/ICMP flood cannot get an innocent third party published to
  the feed.

`sample_analysis` is a per-sample verdict table (detected/total engine hits, keyed by
SHA-256) linking a captured sample to its VirusTotal-style result.

The scoring formula lives in Rust, not SQL. Exactly one migration embeds a scoring
formula in SQL (a one-time eligibility backfill); a later migration explicitly refuses
to duplicate tier logic in SQL, keeping Rust the single source of truth.

## The `review` crate tables

- `review_queue` (PK `source_ip`) — snapshots score and categories at the moment an
  IP is surfaced for operator review; carries the review `state`
  (pending/approved/rejected/snoozed) and decision timestamps.
- `vendor_submission` (PK `id`) — one row per abuse-report submission, with a
  **UNIQUE `idempotency_key`** that dedupes retries and the recorded vendor response.
- `fetch_attempt` (PK `url_hash`) — the malware fetcher's record of each
  attacker-supplied URL it considered, including the pinned IP actually dialed, the
  status, and the guard's reject reason. Its `status` value set is documented in a SQL
  comment (not a CHECK or enum); the values are set by review-crate code.

## Captured file bodies (outside Postgres)

Sample bodies are **not** stored in the database. They are written to an on-disk
quarantine spool, named by SHA-256 (never the attacker's filename), size-bounded per
file and by a global byte budget, written `0640`, and re-hashed on read (fail-closed
on mismatch). The database holds only the reference. See
[malware custody](../security/malware-custody.md) and
[event and sample lifecycle](./event-and-sample-lifecycle.md).

## Related

- [reference/database.md](../reference/database.md) — every table, column, enum, and
  migration (the canonical owner of these values).
- [reference/scoring-and-feed.md](../reference/scoring-and-feed.md) — scoring
  constants, tiers, and the feed gate.
- [architecture/concurrency-and-failure.md](./concurrency-and-failure.md) — the
  serialized append path and failure modes.
- [security/filesystem-and-db-protections.md](../security/filesystem-and-db-protections.md) —
  the DB privilege model.
