# ADR 0008: Append-only, hash-chained evidence ledger

Status: Accepted 2026-07-16

## Context

Every abuse report and every published feed entry is a claim about a third party,
made under a legitimate-interest lawful basis and gated by explicit operator
approval. If that claim is challenged, the platform must be able to show the
evidence behind a score and prove the evidence was not altered after the fact.
The event ledger (ADR 0003) already holds every observation; it needs to be
demonstrably tamper-evident. At the same time, data-minimization law requires
that the evidence not itself become a store of attacker-controlled secrets or
personal payloads.

## Decision

Make the event ledger and the audit trail append-only and hash-chained.

- Each row hashes its own content together with the previous row's hash, forming
  a chain. Any later edit or deletion breaks the chain from that point forward
  and is therefore detectable.
- Content stays minimized. Passwords and payloads are dropped at the sensor at
  capture time and never reach the ledger, so the hash chain protects derived
  indicators and evidence, not raw secrets.

This gives a forensically defensible record: an IP's score and decision are
reproducible by replaying its events (ADR 0003), and the chain proves those
events were not rewritten.

## Alternatives considered

- A mutable audit table with row-level timestamps. Rejected: timestamps do not
  prevent or reveal an in-place edit, so the record is not tamper-evident.
- Storing full captured payloads for richer evidence. Rejected: it conflicts
  with data-minimization obligations and turns the evidence store into a secrets
  liability.

## Consequences

The ledger is write-once; corrections are new appended events, never edits.
Verification is a chain walk that recomputes each row's hash. The minimization
rule constrains what evidence can be retained, which is an accepted trade against
completeness. Sensors, which drop secrets at capture, are the enforcement point
for the content that never enters the chain.
