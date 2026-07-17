# ADR 0003: Event-sourced scoring with a derived projection

Status: Accepted 2026-07-16

## Context

Multiple WAN-IP collectors feed one shared attacker score (ADR 0002). If every
collector mutates a single per-IP score row, each hot IP becomes a contention
point where concurrent writers serialize and race on the same row. The platform
also needs forensically defensible evidence: any reporting decision must be
explainable and reproducible after the fact.

## Decision

Model scoring as an append-only event ledger plus a derived `ip_score`
projection.

- Collectors only append events. They never contend on a shared mutable score
  row, because appends do not race the way an in-place update does.
- The append-only ledger is the tamper-evident evidence (see ADR 0008). Each
  IP's current score and its ELIGIBLE / WEIGHT / RECOMMENDED decision are
  reproducible by replaying that IP's events through the scoring rules.
- Cross-WAN breadth falls out of the ledger directly, because every WAN-IP
  observation for an attacker is already recorded as events against that IP.

The `ip_score` projection is a derived, rebuildable read model, resolved from
the ledger rather than being an independent source of truth.

## Alternatives considered

- A mutable per-IP score row updated in place under row locks. Rejected: it
  creates a write-contention hot spot per active IP and, more importantly, it
  discards the immutable-evidence property. A mutated row cannot be replayed and
  cannot prove it was not edited.

## Consequences

The ledger is the source of truth; the projection is a cache of it and may be
rebuilt. Writes stay append-only on the hot path, which suits many concurrent
collectors. Replay is the reference implementation of scoring, which keeps the
decision auditable. Storage grows with event volume and is bounded by the
retention policy, and the projection must be kept consistent with the ledger it
derives from.
