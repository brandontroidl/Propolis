# ADR-0009: Accepted limitations of the core scoring layer

Status: accepted (2026-07-18)

## Context

The post-merge adversarial audit (`internal/audit/2026-07-18-core-scoring-audit.md`) surfaced three
properties of the shipped core scoring layer that are real but were deliberately NOT changed in the
hardening pass. Recording them here so they are explicit design decisions, not accidental gaps, and so
a future reader or sub-project does not "fix" a non-bug or rely on a guarantee that does not hold.

## Decision

1. **The event hash chain is unsigned; tail truncation is undetectable.** `verify_chain` detects
   content mutation, reordering, and head/middle deletion, but deleting the newest event(s) leaves a
   shorter, internally self-consistent prefix that reads `Intact`. Closing this requires a signed,
   externally anchored chain tip (e.g. a periodically signed head hash published out of band).
   Deferred: it is a larger mechanism than sub-project 1's scope and belongs with the
   runtime/coordination layer (sub-project 7) or a dedicated integrity-anchoring effort.

2. **`ingested_at` is stored but not covered by the content hash.** It is set by a Postgres
   `DEFAULT now()` at INSERT time — after the chain hash is computed — so it cannot enter the
   pre-insert content hash without a second write pass. It is unused by scoring/eligibility, so an
   attacker with DB write access altering it changes no score or report; only the forensic ingestion
   timeline is affected. Accepted as-is; revisit only if forensic ingestion-time integrity becomes a
   requirement.

3. **Per-category `category_breakdown` weight is uncapped.** Only the aggregate `raw_score` is capped
   at 100; a category's accumulated decayed weight can exceed 100 under a burst of distinct high-weight
   signals. This affects no scoring decision — the 0.5 live floor, eligibility, tier, and
   recommendations do not depend on a per-category cap — so it is a display/consumer concern only.
   Accepted; a consumer rendering per-category weight on a 0-100 scale must clamp for display.

## Consequences

- Downstream sub-projects treat these as known, documented behavior: tamper-evidence covers mutation
  but not tail truncation; `ingested_at` is outside the integrity envelope; per-category weight is
  uncapped.
- If any becomes a real requirement, it is a deliberate new decision (a superseding ADR), not a bugfix.

## Rejected alternatives

- **Sign the chain / add a length anchor in sub-project 1** — rejected: integrity anchoring is a
  runtime/coordination concern, not the pure scoring core; premature here.
- **Add `ingested_at` to the content hash via a post-insert update** — rejected: it would make the
  append path a two-write, non-atomic operation for a field with no scoring impact.
- **Cap per-category weight at 100** — rejected: the cap is an aggregate-score concept; capping the
  per-category accumulation would discard information with no scoring benefit and could mask a
  genuinely dominant category.
