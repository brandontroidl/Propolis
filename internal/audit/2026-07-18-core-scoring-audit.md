# Core scoring layer — post-merge adversarial audit (2026-07-18)

**Method:** 8 independent discipline-grounded auditors read the merged `crates/core-scoring` source
(commit `fb6bd7f`). Two lenses (anti-spoof, fail-closed) returned **no** findings. The adversarial
verify phase did **not** complete (session usage limit), so these are **auditor leads, not
panel-verified** — except the two marked [SOURCE-VERIFIED], which the orchestrator personally confirmed
against source. Everything else needs source-verification before a fix lands.

Status (updated 2026-07-18): fixes in progress on branch `hardening/core-scoring-audit-fixes` (off
`main`; `main`/`origin` still at `fb6bd7f`). Full serial suite green after each fix (48 tests).

FIXED + committed:
- #1 confidence `rescale(3)` (was incomplete `round_dp`) — commit `82b520d`.
- #2 `validate()` enforces signal_type coupling → blocks the confirmed-real forge — commit `e5e4366`.
- #3 unbounded weight → SUBSUMED by #2 (weight must equal the small table value).
- #4 symmetric dedup window (out-of-order events keep their weight) — commit `c9a8a93`.
- #6 pin READ COMMITTED so the append advisory lock serializes correctly — commit `a864767`.
- #7 CORRECTION: no panic existed (empty source was already guarded — an earlier grep-without-reading
  claim was wrong). Converted to the real minor fix: `rebuild_projection` returns `Ok(None)` for an
  empty source (was `Err(Corrupt)`), matching `read_score` — commit `4310282`.

ALSO FIXED + committed:
- #5 `read_score` re-derives gate flags at read time (shared `derive_projection` extracted from
  `apply_event`; pure, never persisted) — commit `7e0fd20`.
- #11 Corrupt fail-closed test + #12 per-field tamper detection (all 11 canonical fields) — `fb16d00`.
- #13 IPv6 `/64` dedupe test + #15 `effective_score` cap test + #16 exact tier-floor boundaries — `209edad`.
- #14 real-DB breadth test (tcp AND auth required on the same event) — `f7cb2d9`.
- #18 `verify_chain` tail-truncation limitation documented in code.

DEFERRED (deliberately):
- #8-10 public-API completeness -> to sub-project 4 (finalize the surface there; making
  `read_stored_score` `pub(crate)` now would break the integration test that legitimately uses it).
- #17 `ingested_at` not in the content hash -> accepted (set by DB DEFAULT at insert, after the hash
  is computed; unused by scoring).
- #19 per-category weight uncapped -> accepted (scoring unaffected: the 0.5 floor and gates do not
  depend on the cap).

NEXT: full serial re-audit + suite, then merge `hardening/core-scoring-audit-fixes` -> `main`.

## A. Real defects — fix (code)

1. **[SOURCE-VERIFIED] Confidence hash normalization is incomplete → `verify_chain` false-breaks.**
   `repository/events.rs:120` uses `confidence.round_dp(3)`, which trims excess scale but does not PAD;
   `dec!(0.9)` stays `"0.9"`, but the `NUMERIC(4,3)` column stores `"0.900"`, so reconstruction re-hashes
   a different string and `verify_chain` returns `Broken` on an UNTAMPERED chain for any confidence not
   authored at scale-3. Existing tests pass only because `from_signal` uses scale-3 literals. **Fix:**
   `.rescale(3)`. (This is an incomplete part of the earlier hash-storage-stability fix.)

2. **[SOURCE-VERIFIED] `EventInput` lets `category`/`weight`/`confidence` desync from `signal_type` →
   forges the confirmed-real latch.** `types.rs:54-62` `validate()` checks only confidence-range +
   non-empty sensor; `is_confirmed_real` (`enums.rs`) gates on `(protocol, authenticated, category)` and
   never consults `signal_type`. A caller building `EventInput` directly (all fields `pub`) can set
   `category: Honeypot` on a non-honeypot `signal_type` and pass the anti-spoof gate. The gate rests on
   `from_signal` convention, not enforcement. **Fix:** `validate()` enforces `category`/`weight`/
   `confidence == signal_weight(signal_type).*`, rejecting a desynced event. This one fix also closes #3
   (weight is then always the small table value, never wraps). Design choice to confirm: enforce in
   `validate()` vs. make the fields un-settable (derive-only).

3. **Unvalidated `weight: u32` wraps to negative on `i32` INSERT.** `events.rs:161` binds
   `event.weight as i32`; `validate()` never bounds `weight`, so `weight > i32::MAX` persists negative in
   the ledger. Reachable via the public `EventInput` (pub fields). **Subsumed by #2** if `validate()`
   enforces `weight == signal_weight().weight`; otherwise add an explicit bound.

4. **Dedup window is one-sided → out-of-order events always dedupe (false-negative).**
   `events.rs:187-190` (and mirrored `replay.rs:139-142`): `deduped = (observed_at - prior).num_seconds()
   <= 60`. A negative elapsed (event arrives with an EARLIER `observed_at` than the prior recorded one —
   ordinary under buffered sensors / multi-collector clock skew) is trivially `<= 60`, so the event is
   deduped and its full weight is dropped from `raw_score`, suppressing a genuinely severe confirmed-real
   attacker below the tier/blocklist floors. **Fix:** symmetric window `elapsed.abs() <= 60` in both
   `events.rs` and `replay.rs` (keep replay==incremental).

5. **`read_score` returns a live-projected `raw_score` alongside stale write-time gate flags.**
   `events.rs:284-291` decays only `raw_score`; `eligible`/`tier`/`recommended_*`/`max_confidence`/
   `distinct_categories` are returned as computed at the last write. A quiet-since-write IP reads back
   `raw_score ~= 0` yet `tier: Aggressive, recommended_for_vendor: true` — the exact false-tier the design
   guards against at write time. **Fix:** `read_score` re-derives the gate flags at now (decay the
   breakdown + rerun the gates), OR is restricted to not return misleading flags. Design choice to confirm.

6. **Append serialization is silently conditional on READ COMMITTED isolation.** `events.rs:124`
   `pool.begin()` inherits the server default; under REPEATABLE READ / SERIALIZABLE the tx snapshot
   freezes at the advisory-lock `SELECT` before it blocks, so the post-lock chain-head read can miss a
   just-committed append → the chain can still fork, though the module doc claims it cannot. **Fix:** pin
   `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` at tx start and document the dependency.

7. **`rebuild_projection` panics on an empty-source IP** (the already-known one). `replay.rs:~179`
   `acc.expect(...)`; a public-API call for an IP with zero events panics instead of returning
   `None`/error. **Fix:** return `Ok(None)` (or a typed error) for an empty source.

## B. Public-API completeness (fix)

8. **`effective_score` (WEIGHT) + `breadth_factor` + `BREADTH_PER_WAN`/`BREADTH_CAP` are crate-private.**
   `scoring` is `mod` not `pub mod` (`lib.rs:17`); the design names WEIGHT as a core derived fact used for
   sorting/display. A later sub-project would have to re-hardcode `0.15`/`0.60` (violating "import, never
   redefine"). **Fix:** re-export them (and/or add `effective_score` to `IpScore`).

9. **`IpScore.category_breakdown` is opaque `serde_json::Value`** though a typed `CategoryStat { weight,
   max_confidence }` exists internally (`engine.rs`), unreachable outside the crate. **Fix:** export
   `CategoryStat` (or a typed accessor).

10. **`read_stored_score` is public but is a test-only comparison helper** (`repository/mod.rs:13`); a
    consumer could call it instead of `read_score` and get an un-decayed score. **Fix:** `pub(crate)`.

## C. Missing tests (add — these guard load-bearing invariants)

11. **`RepoError::Corrupt` fail-closed path has zero test coverage** — no test writes malformed
    `category_breakdown` via SQL and asserts `Err(Corrupt)` (not panic). A future refactor could reintroduce
    the panic silently.
12. **Tamper detection tests only mutate the `weight` column** — 8 of 11 canonical fields untested,
    including `authenticated`/`category`/`protocol` (the anti-spoof-critical ones). Add per-field tamper
    tests via real SQL + `verify_chain`.
13. **IPv6 `/64` dedupe branch untested** (`breadth.rs:35-41`).
14. **Anti-spoof breadth proptest bypasses the real vantage/dedupe machinery** (`engine.rs:303-318` feeds
    arbitrary `wan: i32` straight into `apply_event`; never calls `distinct_wan_count`). Add a test that
    drives the real breadth path with adversarial vantage shapes.
15. **`effective_score` SCORE_CAP clamp never tested** (raw*factor > 100).
16. **Exact-floor boundary tests missing** — STANDARD floor (raw 75 / conf 0.70) and the 0.5 live-floor
    exactly, per the spec's own testing-strategy section.

## D. Document / defer (design-level, minor)

17. **`ingested_at` is stored but not in the content hash.** Largely unavoidable (set by DB `DEFAULT
    now()` at insert, after the hash is computed) and unused by scoring; document as out of the
    content-hash envelope, or move ingestion time into the hashed payload if forensic integrity is required.
18. **`verify_chain` has no head/length anchor** — tail-truncation of the newest events leaves a valid
    prefix that reads `Intact`. Inherent to an unsigned chain; needs a signed head/tip anchor to close.
    Document as a known limitation.
19. **Per-category `category_breakdown` weight is uncapped** while `raw_score` caps at 100; a consumer
    assuming a 0-100 scale sees larger values. Scoring logic is unaffected (the 0.5 floor doesn't care).
    Design choice: cap for consistency, or document the difference.
