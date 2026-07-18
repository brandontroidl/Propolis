# Sub-project 1 — resolution of the 4 open questions

**Status: RATIFIED by operator 2026-07-17.** Resolves the open questions in `01-core-scoring-layer.md`.
Produced by a 4-seat evidence-judged panel (threat-intel/Fable, anti-spoof-sec/Opus,
statistician/Sonnet, dba-systems/Haiku) with full peer review + pairwise judging. The settled
decisions are now folded into `01-core-scoring-layer.md`; the frozen-contract amendment is recorded in
`architecture/frozen-contracts.md`. This file is the durable rationale + dissent record.

The four are coupled: **Q1→Q2→Q3 form one interlocking package**; Q4 stands alone.

## Q1 — Breadth constants  (confidence: medium)
- **Keep `BREADTH_PER_WAN=0.15`, `BREADTH_CAP=0.60`** (linear-with-saturation, max 1.60x). **WAN-breadth
  only — reject `distinct_sensor_count`** from the multiplier (it measures the operator's own
  instrumentation density and couples tiers to deployment).
- **Harden the WAN denominator with BOTH** (they defeat different attacks; neither subsumes the other):
  - **(a) authenticated-vantage filter:** a WAN counts toward `distinct_wan_count` only if it observed a
    `protocol=tcp AND authenticated=true` event from that source. Defeats *spoofed* breadth.
  - **(b) `/24` (+ upstream-ASN where a lookup exists) dedupe** on the counted WAN set. Defeats *genuine
    but correlated* breadth (one contiguous sweep across the operator's own clustered WANs ≠ N
    independent sightings).
- **Dissent:** the `/24`+ASN dedupe adds complexity (ASN needs a GeoIP/BGP lookup) for a possibly-rare
  case; authenticated-only is simpler and carries the whole anti-spoof load. And `0.15/0.60` are
  **empirically unanchored guesses** (old system had no breadth) — must be revalidated against real
  multi-WAN traces once collected. Generous constants are acceptable **only if Q2 = raw-only**.

## Q2 — Which score feeds the tier gate  (confidence: high)
- **Tier gate runs on the RAW decayed score, both tiers:** AGGRESSIVE `raw>=90 AND max_conf>=0.95`;
  STANDARD `raw>=75 AND max_conf>=0.70`. `effective_score` (breadth-boosted) is used **only** for
  weight/sorting/display and the Q3 blocklist gate — **structurally excluded from vendor-report
  severity**, so breadth can never inflate a vendor claim. (The 75/90 floors were calibrated on the raw
  distribution; feeding them a 1.6x-boosted score silently drops the true floor to raw ~47/~56.)
- **Unanimous cross-cutting fix (load-bearing):** `max_confidence` in the tier gate is computed over the
  currently-**decayed live** breakdown (only events whose decayed weight is still > 0), **never a sticky
  lifetime maximum**.
- **Dissent:** raw-gating permanently withholds a *vendor* report on the confirmed-real cross-WAN
  slow-brute-forcer (raw 60-74, high breadth) — the class multi-WAN exists to catch. Acceptable **only
  if the Q3 blocklist split ships** as the mitigation (it still gets blocklisted + surfaced for manual
  escalation).

## Q3 — Recommendation threshold  (confidence: medium)
- **Split-surface model — two eligibility-gated booleans** matching the two real downstream actions:
  - `recommended_for_vendor = eligible AND tier(raw_score) is not None` (no independent third threshold;
    report-worthiness stays in the raw tier gate).
  - `recommended_for_blocklist = eligible AND effective_score >= BLOCKLIST_FLOOR` (proposed **50**).
- Vendor floors **and** `BLOCKLIST_FLOOR` are **fixed source constants**; `half_life` stays the only
  operator-tunable knob. **Ratify Q2 and Q3 together.**
- **Dissent:** the blocklist is **published publicly**, so `BLOCKLIST_FLOOR=50` set too low harms
  third-party consumers, not just the operator — set it conservatively and instrument over/under-
  inclusion. Keep any "report to vendor" affordance **structurally absent** from the blocklist path so
  the independent threshold can't leak into the vendor surface.

## Q4 — Half-life  (confidence: high)
- **Keep `half_life_seconds = 21600` (6h).** Do **not** shorten to 3h; do **not** make it a function of
  WAN count. It stays the sole tunable knob. (Decay is the wrong lever for multi-WAN fan-in: the
  steady-state `S = w/(1-0.5^(T/HL))` is monotonic in inter-arrival T, so no half-life neutralizes
  fan-in; and 3h permanently suppresses a confirmed-real slow-sprayer — peak 59.3 < 75, never tiers.)
- **Rider (enforce as a merge gate):** any new high-frequency signal type must justify its confidence
  value against the consolidation math before merge — a careless high confidence on a high-volume signal
  is the one path that turns consolidation into a false-tier vector at any half-life.
- **Dissent:** if real traces are far denser than modeled, many IPs pin at cap 100 and weight stops
  discriminating; the fix is tuning weights/breadth/confidence, **never** the decay knob — instrument
  real inflow and re-check.

## Consequences if ratified (beyond tuning knobs)
The panel went past the 4 knobs into structural refinements the build must absorb:
1. `distinct_wan_count` **derivation changes** (auth-filter + `/24`/ASN dedupe) — logic, not schema shape;
   raw data already exists in `event.wan_ip` / `event.authenticated`.
2. `max_confidence` semantics change to live-decayed — logic. **Refinement ratified 2026-07-17
   (during build):** the ratified rule ("only events whose decayed weight is still > 0 contribute") is
   asymptotically vacuous (decay never reaches 0) and the projection stores no per-event confidences, so
   it is defined concretely as: `category_breakdown` stores per category `{weight, max_confidence}`, and
   the top-level `max_confidence` is the max over categories whose decayed weight exceeds the 0.5 live
   floor (same floor as `distinct_categories`) of that category's stored max confidence. Category-
   granularity, JSONB-content only (no SQL schema change). Folded into `01-core-scoring-layer.md`.
3. **`ip_score` frozen shape amends additively:** the single `recommended BOOLEAN` splits into
   `recommended_for_vendor` + `recommended_for_blocklist`; add `BLOCKLIST_FLOOR` as a fixed constant.
   This is an additive amendment to `internal/architecture/frozen-contracts.md` and needs sign-off.
