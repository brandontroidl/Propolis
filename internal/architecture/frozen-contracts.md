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

## Frozen now (canonical: `design/02-sensor-framework.md`)

4. **Sensor → intake wire contract** (`02-sensor-framework.md` § The sensor to intake wire contract).
   Settled and frozen 2026-07-20, closing the deferred item below. It is **not** the `event` *storage*
   shape above — it is the on-the-wire format a sensor emits to intake, which sub-project 3 consumes.
   Three parts: (a) the **event record** — one NDJSON line carrying exactly the facts
   `EventInput::from_signal` needs (`v`, `source_ip`, `wan_ip`, `sensor`, `signal_type`, `protocol`,
   `authenticated`, `observed_at` at µs, `metadata`, optional `sample`); the sensor never emits
   weight/confidence/category (intake derives them from `signal_type`). (b) the **sample side channel**
   — captured file bodies in an isolated quarantine spool named by SHA-256, referenced from the event,
   never inline. (c) the **integrity model** — the amendment below. The one canonical type lives in
   `crates/sensor-wire`, imported by both the sensors and intake so it cannot drift.
   - Two properties of the record are frozen with it, not left to the implementation. `metadata`
     carries a mandatory **`protocol_label`** on every event from a protocol-speaking sensor: the
     exact lowercase L7 label (`ssh`, `telnet`, `ftp`), distinct from the L4 `protocol` enum, which
     sub-project 4 reads to derive a protocol-specific vendor report category. And every
     attacker-controlled value in `metadata` has passed the **capture sanitization contract** before
     it reaches the record, which is what stops an attacker-supplied newline from forging an event
     line in a newline-delimited transport. Both are canonical in `02-sensor-framework.md`.
   - **Amendment 2026-07-20 (ADR-0010):** the wording "signed events" is replaced by "structured,
     channel-isolated events." Sensor-side cryptographic signing is impossible under the no-secrets
     posture (a key is a secret) and pointless against sensor compromise. Integrity is the OS
     one-directional channel (trust boundary) plus the ledger hash chain applied at intake
     (tamper-evidence). See ADR-0010.

## Deferred — resolved, retained for history

- **Sensor → intake signed-event wire format** — RESOLVED 2026-07-20 and moved to "Frozen now" (item 4
  above). Was flagged open in `design/02-sensor-framework.md` and `design/03-event-intake-aggregation.md`.
  The "signed" framing was amended per ADR-0010.
