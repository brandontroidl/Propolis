# ADR 0005: Clean-room rewrite, old system as behavioral reference only

Status: Accepted 2026-07-16

## Context

Propolis already exists as a working Python system whose behavior is well
understood and documented. The rebuild changes the language to Rust (ADR 0001),
the datastore to PostgreSQL (ADR 0002), the write model to event sourcing
(ADR 0003), and the topology to single-node-or-cluster (ADR 0006). Those changes
touch nearly every layer, and a language change alone already means no source
carries over.

The temptation in any rewrite is to preserve old decisions by default and frame
new design questions as keep-or-change. That imports assumptions that were made
for a different language, datastore, and single-node boundary.

## Decision

Perform a clean-room rewrite.

- No old code is kept or ported.
- The old codebase is a behavioral reference only: it documents what detection
  logic works and where the sharp edges are.
- No old decision is preserved by default. Each choice is re-justified forward on
  the new goals' merits.
- Design questions are not framed as keep-versus-change-the-old.

The old system remains the behavioral specification for what the platform must
do, not the architectural specification for how it must do it.

## Alternatives considered

- Incremental port of the Python system. Not viable: the language change removes
  the source, and the datastore and topology changes invalidate the persistence
  and coordination design regardless.
- Preserve old decisions unless a reason to change is found. Rejected: it
  smuggles single-node, SQLite-era assumptions into a clustered, event-sourced
  design.

## Consequences

The work is a full ground-up build across all sub-projects. Every architectural
choice is stated and justified fresh, which is what the ADRs in this directory
record. The behavioral reference is consulted for correctness of detection and
scoring behavior, not for structure.
