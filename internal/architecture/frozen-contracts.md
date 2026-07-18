# Frozen cross-cutting interface contracts

**Status:** frozen 2026-07-17. Changing anything listed here requires an explicit superseding
decision (a new ADR or a recorded amendment), not a silent edit — every later sub-project imports
these and a shift forces rework upward (ADR-0007).

The point of this file is the *freeze declaration and policy*. It does not re-paste the definitions —
that would create a drift-prone clone. Each frozen item points to its single canonical source.

## Freeze policy

- **Additive only.** New columns are optional so existing rows still validate; a schema version is
  bumped only when stored data must be actively transformed. The runtime reads only the current
  canonical shape; any legacy shape is normalized in explicit migration code, never a runtime shim
  (`01-core-scoring-layer.md` (§ PostgreSQL schema)).
- **One source of truth.** These shapes are resolved from their canonical definition, never cloned.

## Frozen now (canonical: `design/01-core-scoring-layer.md`)

1. **Domain vocabulary — the 5 enums** (`01-core-scoring-layer.md` § Enums): `protocol_enum`, `category_enum`,
   `feed_tier_enum`, the 16-value `signal_type_enum`, and `review_state_enum`. Every sub-project
   imports this vocabulary and never redefines it. `signal_type_enum` completeness (every value has
   exactly one weight row) is test-asserted (`01-core-scoring-layer.md` § Signal weights).
2. **`event` ledger shape** (`01-core-scoring-layer.md` § Event ledger): append-only, hash-chained. INSERT-only in the
   normal path; `metadata` holds only sanitized PII-free content; `prev_hash` NULL only for the first
   row of a chain. Sub-project 2 sensors target this; sub-project 3 intake writes it.
3. **`ip_score` projection shape** (`01-core-scoring-layer.md` § Score projection): derived, rebuildable from the ledger.
   Read by sub-project 4 (review/reporting), 5 (feed), 6 (console).
   - **Amendment 2026-07-17 (operator-ratified):** the single `recommended BOOLEAN` is split into
     `recommended_for_vendor` + `recommended_for_blocklist` (panel resolution of sub-project 1's open
     questions — see `design/01-core-scoring-layer-open-questions.md`). Pre-implementation, no live data, so
     this is a clean spec amendment, not a data migration. `distinct_wan_count` keeps its shape but its
     *derivation* hardens (authenticated-vantage filter + `/24`/ASN dedupe) — logic, not shape.

**Not frozen by this file** (deliberately): the *scoring constants and gate logic* — breadth
constants, which score feeds the tier gate, the recommendation threshold, the half-life. Those 4 open questions are now resolved and folded into the spec (see
`design/01-core-scoring-layer-open-questions.md`); they are logic/values, not shapes, and migrations
are additive, so the schema freezes independently of them.

## Deferred — the highest-risk interface, NOT yet freezable

- **Sensor → intake signed-event wire format.** Flagged open in both `design/02-sensor-framework.md:19`
  and `design/03-event-intake-aggregation.md:19`. It belongs to sub-project 2's design (not yet done).
  It is **not** the same as the `event` *storage* shape above — it is the on-the-wire, signed format a
  sensor emits to intake. This MUST be settled at sub-project 2 design time, before 02 and 03 fork,
  because 03 consumes it. Recorded here so it is not lost.
