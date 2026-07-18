# ADR 0007: Foundation-first build sequencing

Status: Accepted 2026-07-16

## Context

The rebuild is a full ground-up effort across sensors, intake, scoring,
reporting, feed, console, and multi-node runtime. The layers have a clear
dependency order: sensors produce events that intake aggregates, aggregation
feeds scoring, scoring feeds review and reporting, and everything else observes
or deploys that layer. Building breadth-first or end-to-end-first would mean
standing work on top of an unproven core.

## Decision

Build each layer complete before starting the next, in this order:

1. Core scoring layer: domain model, PostgreSQL persistence, scoring, and the breadth
   model.
2. Native sensor framework, the catch-all sensor, and one TCP-auth sensor.
3. Event intake and multi-node aggregation.
4. Review, gatekeeper, and reporting.
5. Feed.
6. Console and observability.
7. Runtime, multi-node coordination, and deployment.
8. Remaining native sensors.

Each sub-project gets its own spec, plan, and build cycle rather than being
designed all at once up front.

## Alternatives considered

- Walking skeleton: a thin end-to-end slice first, then thickening. Considered
  and set aside: the value of the platform is in the correctness of the scoring
  and eligibility layer, which a thin slice does not exercise, and the core scoring layer is
  the part that must be right first.
- Hybrid of skeleton and foundation-first. Considered; foundation-first was
  chosen for a cleaner dependency order and per-layer verification.

## Consequences

Each layer is verified complete before the next depends on it, which limits
rework from building on unproven foundations. End-to-end behavior is not
demonstrable until the upper layers land, so early progress is measured by
completed layers rather than a running pipeline. Per-sub-project specs keep each
build cycle scoped and reviewable.
