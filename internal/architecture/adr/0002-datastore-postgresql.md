# ADR 0002: PostgreSQL is the single canonical datastore

Status: Accepted 2026-07-16

## Context

The central new requirement is cross-sensor breadth: an attacker seen across
several of the operator's WAN IPs must have that breadth counted in the single
weight that drives reporting. That forces every WAN-IP collector, whether it is
one multi-homed node or several collector nodes, to write into one shared,
concurrent, transactional attacker score. The review queue and the background
schedulers also need real row-level coordination across writers.

The old system used SQLite in WAL mode. SQLite is single-writer and file-local:
it cannot be the shared brain that multiple collectors on different hosts
aggregate into.

## Decision

Use PostgreSQL as the single canonical store for the whole platform.

Rationale:

- Concurrent aggregation: many collectors append signal and update one shared
  score under proper transaction isolation.
- Row locking for the review queue (one open item per IP) and for scheduler and
  coordination work.
- A real replication and failover path, which is a secondary benefit rather than
  the primary goal.
- Mature Rust tooling (sqlx, tokio-postgres) gives typed, async access.

## Alternatives considered

- SQLite: single-node, single-writer, file-local. Rejected because it
  structurally cannot serve cross-node breadth aggregation, which is the reason
  for the rebuild's topology.
- Maintaining both SQLite and PostgreSQL backends: rejected. It doubles the
  persistence surface and its test matrix, and the single-node case is served by
  running one PostgreSQL instance rather than a second engine.

## Consequences

Postgres is a required dependency even for a single-node deployment; there is
one persistence path, not two. The datastore becomes the coordination point for
the cluster. Schema changes follow the additive migration discipline defined for
the persistence layer, and the event-sourced write model in ADR 0003 is built on
this store.
