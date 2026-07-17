# ADR 0001: Implementation language is Rust

Status: Accepted 2026-07-16

## Context

Propolis is an internet-facing defensive platform. Its sensors sit on the open
WAN and parse attacker-controlled bytes, so the language choice is a security
decision before it is a productivity one. The old system was Python, chosen for
convenience, and the rebuild is an explicit move off it toward a more efficient,
lower-footprint runtime. The scoring spine and multi-node aggregation also need
predictable latency and a strong way to keep the system's invariants from being
violated at runtime.

## Decision

Write the whole platform in Rust.

Rationale:

- Memory safety on the sensor attack surface. A memory-unsafe honeypot exposed
  to hostile input is a liability; Rust removes the classic overflow and
  use-after-free classes at compile time.
- The type system encodes the domain invariants. Illegal states (an unratified
  report, a naive timestamp, an out-of-domain metric label) are made
  unrepresentable so they do not compile rather than failing in production.
- No garbage collector, a small static binary, low memory footprint, and
  predictable latency suit a long-running host process and lightweight
  collector nodes.

## Alternatives considered

- Go: easier HA and clustering ecosystem and a shallower learning curve, but
  weaker compile-time safety guarantees. Rejected: safety on the exposed surface
  outweighs ecosystem convenience.
- Elixir / BEAM: the best fit for a no-single-point-of-failure supervision
  model, but not CPU-efficient for the parsing and scoring workload. Rejected on
  efficiency.
- Python: the old language. Rejected as not efficient enough and an
  over-defaulted choice for this domain.

## Consequences

The rebuild is a full ground-up rewrite; no old code carries over. The team
takes on Rust's steeper build and borrow-checker cost in exchange for the safety
and footprint gains. Datastore tooling must be mature in Rust, which ADR 0002
depends on.
