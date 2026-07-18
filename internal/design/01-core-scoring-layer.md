# Sub-project 1: core scoring layer

Detailed design spec for the Propolis-new core scoring layer (Rust + PostgreSQL). This is the
foundation layer, built complete and tested in isolation before any sensor, intake, review,
reporting, feed, console, or runtime layer is started.

## Purpose and scope

The core scoring layer owns four things and nothing else:

1. Domain types: the Rust vocabulary (enums, signal table, event and score value types)
   every later sub-project imports and never redefines.
2. The PostgreSQL schema and the repositories that read and write it.
3. The scoring engine: decay math, weight accumulation, and the eligibility and tier gates.
4. The cross-WAN breadth model: how signal seen across multiple of the operator's WAN IPs
   raises an attacker's weight and recommendation.

The core scoring layer has no network listeners, no vendor clients, no web surface, and no scheduler. It
is a library plus a schema plus a scoring function. It is testable in isolation by feeding it
synthetic events and asserting the resulting projection, with no sensor and no live traffic.

Deployment context the core scoring layer must serve: every WAN-IP collector, whether one multi-homed node
or several collector nodes, feeds ONE shared PostgreSQL store so cross-WAN breadth counts
toward a single attacker score. That shared, concurrent, transactional store is the reason the
datastore is PostgreSQL and not a file-local single-writer database.

## The three-level report model

The core scoring layer computes three derived facts per source IP. They are distinct and must not be
collapsed into one another.

- ELIGIBLE. An IP may be reported at all only when all three legs hold:

  ```
  eligible  =  has_confirmed_real
               AND event_count >= 2
               AND distinct_categories >= 2
  ```

  `has_confirmed_real` is a sticky latch. It is set true the first time an event with
  `protocol = tcp AND authenticated = true AND category = honeypot` is recorded (a completed
  handshake to a honeypot proves the source IP is real, not spoofed). Once true it is never
  unset. `distinct_categories` counts categories whose decayed breakdown weight exceeds 0.5
  (strict). Because a faded second category can drop below the floor, eligibility can flip from
  true to false through passage of time alone; `has_confirmed_real` and `event_count` are
  historical facts and never decay.

- WEIGHT. The decayed accumulated signal weight, capped at 100, multiplied by the breadth
  factor. This is the magnitude of corroborated malice, boosted by how broadly the IP was seen.

- RECOMMENDED. Two eligibility-gated flags, one per downstream action:

  ```
  recommended_for_vendor     =  eligible AND tier is not None
  recommended_for_blocklist  =  eligible AND effective_score >= BLOCKLIST_FLOOR
  ```

  `tier` is computed on the RAW decayed score (see Tier gate), so breadth can never raise a
  vendor report's severity. The blocklist gate uses the breadth-boosted `effective_score`, so a
  confirmed-real but broad-and-low attacker is still surfaced to the operator's own reversible
  blocklist. `BLOCKLIST_FLOOR` (50) is a fixed source constant. A recommended IP is actively
  surfaced and queued for operator approval by a later sub-project. The core scoring layer only computes the
  flags; it never reports or publishes.

INVARIANT (load-bearing, enforced by test): breadth affects the effective score (weight) and the
blocklist recommendation only. It never feeds the tier gate or the vendor recommendation, it can never
set `has_confirmed_real`, and it can never make an ineligible IP eligible. Only a confirmed-real event
does that. Rationale: reports built on spoofable UDP or a lone SYN get a
vendor reporter account penalized; a completed TCP handshake to a honeypot is the one signal
that proves the source address is real, so it, and only it, opens the eligibility gate. A
breadth boost that could manufacture eligibility would reintroduce exactly the spoof risk the
gate exists to remove.

## Architecture: event-sourced

The core scoring layer is event-sourced. Collectors append immutable events to a hash-chained ledger. The
per-IP score is a derived projection, never a source of truth.

- The `event` table is an append-only, hash-chained ledger. Each row's `hash` covers its
  canonical content and the `prev_hash` of the chain, making the ledger tamper-evident.
- The `ip_score` table is a projection: the current decayed score and the derived flags for
  one source IP. It is decayed to "now" on read and is fully rebuildable by replaying that IP's
  events from the ledger in observed order. A replay-built projection must equal the
  incrementally maintained projection (see Testing strategy).
- Advancing the projection is a write path. In single-node mode the process advances it
  directly. In cluster mode a single leader-elected scorer advances it, so there is one writer
  of record for the projection even though many collectors append events. The leader-election
  mechanism itself belongs to sub-project 7 (runtime and coordination); the core scoring layer only assumes
  that projection advancement is serialized per source IP.
- Deduplication lives in the append path. The same `source_ip` plus `signal_type` within a
  short dedup window adds no weight, but it still records the sighting: it decays the stored
  score to now, refreshes `last_seen`, unions the new protocol into the record, and recomputes
  the derived flags. It never fabricates additional weight for a repeated identical signal.

## PostgreSQL schema

DDL below is the canonical shape the runtime reads. Migrations are additive: new columns are
optional so existing rows still validate, and a version is bumped only when stored data must be
actively transformed. The runtime reads only this current shape; any legacy shape is normalized
solely in explicit migration code, never through a silent runtime shim.

### Enums

```sql
CREATE TYPE protocol_enum AS ENUM ('tcp', 'udp', 'icmp');

CREATE TYPE category_enum AS ENUM ('honeypot', 'ids', 'network', 'waf', 'auth');

CREATE TYPE feed_tier_enum AS ENUM ('aggressive', 'standard');

CREATE TYPE signal_type_enum AS ENUM (
    'honeypot_connection',
    'honeypot_login_attempt',
    'honeypot_command_exec',
    'honeypot_malware_upload',
    'honeypot_file_download',
    'suricata_sev1',
    'suricata_sev2',
    'suricata_sev3',
    'port_scan',
    'syn_flood',
    'blocked_connection',
    'waf_sqli_xss',
    'waf_generic_block',
    'ssh_brute_force',
    'catchall_probe',
    'remote_auth_failure'
);

-- Used by the review sub-project (sub-project 4), defined here so the schema is complete.
CREATE TYPE review_state_enum AS ENUM ('pending', 'approved', 'rejected', 'snoozed');
```

### Event ledger

```sql
CREATE TABLE event (
    id            BIGSERIAL       PRIMARY KEY,
    source_ip     INET            NOT NULL,
    wan_ip        INET,           -- null for corroborating sensors with no bindable WAN IP
    sensor        TEXT            NOT NULL,
    signal_type   signal_type_enum NOT NULL,
    protocol      protocol_enum   NOT NULL,
    authenticated BOOLEAN         NOT NULL,
    category      category_enum   NOT NULL,
    weight        INTEGER         NOT NULL,
    confidence    NUMERIC(4,3)    NOT NULL,
    observed_at   TIMESTAMPTZ     NOT NULL,
    ingested_at   TIMESTAMPTZ     NOT NULL DEFAULT now(),
    metadata      JSONB           NOT NULL DEFAULT '{}'::jsonb,  -- sanitized at capture
    prev_hash     BYTEA,
    hash          BYTEA           NOT NULL
);

CREATE INDEX event_source_ip_idx   ON event (source_ip);
CREATE INDEX event_observed_at_idx ON event (observed_at);
```

The `event` table is append-only: the repository issues INSERT only, never UPDATE or DELETE
against it in the normal path. `metadata` holds only sanitized, PII-free content; passwords and
raw payloads are dropped at capture time by the sensor, upstream of the core scoring layer, and never reach
this column. `prev_hash` is NULL only for the first row of a chain.

### Score projection

```sql
CREATE TABLE ip_score (
    source_ip            INET          PRIMARY KEY,
    raw_score            NUMERIC       NOT NULL,
    decay_anchor         TIMESTAMPTZ   NOT NULL,
    max_confidence       NUMERIC       NOT NULL,
    event_count          INTEGER       NOT NULL,
    distinct_categories  INTEGER       NOT NULL,
    category_breakdown   JSONB         NOT NULL DEFAULT '{}'::jsonb,
    has_confirmed_real   BOOLEAN       NOT NULL DEFAULT false,
    distinct_wan_count   INTEGER       NOT NULL DEFAULT 0,
    distinct_sensor_count INTEGER      NOT NULL DEFAULT 0,
    first_seen           TIMESTAMPTZ   NOT NULL,
    last_seen            TIMESTAMPTZ   NOT NULL,
    eligible                  BOOLEAN  NOT NULL DEFAULT false,
    recommended_for_vendor    BOOLEAN  NOT NULL DEFAULT false,
    recommended_for_blocklist BOOLEAN  NOT NULL DEFAULT false,
    tier                      feed_tier_enum
);
```

`ip_score` is a derived projection, rebuildable from the ledger. `raw_score` is the stored,
un-projected value anchored at `decay_anchor`; readers project it to now (see Scoring math).
`category_breakdown` maps each category to its decayed accumulated weight and is the source of
the `distinct_categories` count. `tier` is nullable: NULL means "not tiered" and is distinct
from `aggressive`/`standard`.

## Scoring math (recommended, tunable)

Constants marked recommended are proposals for the operator to tune. They are listed in Open
questions. Every constant here is a source-level default, not a value the reporting gate can be
weakened from at runtime by an untrusted input.

### Signal weights

Recommended starting values for each signal type (weight / confidence / category). These are
tunable defaults, not frozen law:

```
honeypot_connection      40  / 0.90 / honeypot
honeypot_login_attempt   50  / 0.92 / honeypot
honeypot_command_exec    60  / 0.95 / honeypot
honeypot_malware_upload  80  / 0.98 / honeypot
honeypot_file_download   70  / 0.96 / honeypot
suricata_sev1            30  / 0.70 / ids
suricata_sev2            15  / 0.50 / ids
suricata_sev3             5  / 0.30 / ids
port_scan                20  / 0.60 / network
syn_flood                25  / 0.70 / network
blocked_connection        3  / 0.15 / network
waf_sqli_xss             35  / 0.85 / waf
waf_generic_block        15  / 0.50 / waf
ssh_brute_force          20  / 0.60 / auth
catchall_probe           15  / 0.40 / network
remote_auth_failure      12  / 0.40 / auth
```

The 16-entry table is complete: every `signal_type_enum` value has exactly one weight row, and
that completeness is asserted by test. `syn_flood` and `ssh_brute_force` may have no emitting
sensor in the first sensor sub-project; their rows are retained as reserved and carry no runtime
cost.

### Decay

```
decayed = prev * 0.5 ^ (elapsed_seconds / half_life_seconds)
```

- `half_life_seconds` default 21600 (6 hours) — ratified as the SOLE operator-tunable scoring knob;
  every other threshold is a fixed source constant. Do NOT shorten it for multi-WAN and do NOT tie it
  to WAN count: decay is monotonic in inter-arrival time, so no half-life value neutralizes multi-WAN
  fan-in, and shortening permanently suppresses a confirmed-real slow attacker. Rider (enforce as a
  merge gate): any new high-frequency signal type must justify its confidence value against the
  consolidation math before merge — a careless high confidence on a high-volume signal is the one path
  that turns consolidation into a false-tier vector at any half-life.
- Score is capped at 100 after accumulation.
- Clock-skew clamp: if `elapsed_seconds <= 0`, return `prev` unchanged. Decay only ever
  shrinks a score; it never inflates one, even when a later event carries an earlier or skewed
  timestamp.

Decay is applied in exactly two places:

1. On write (accumulate). The engine reads the un-projected stored `raw_score` (anchored at
   `decay_anchor`), decays it to the new event's `observed_at`, adds this event's weight, caps
   at 100, and rewrites `raw_score` with a fresh `decay_anchor`. Every per-category breakdown
   weight decays by the same factor before this event's category weight is added.
2. On read (project to now). Readers decay the stored `raw_score` from `decay_anchor` to the
   read instant as a pure projection and never write the result back.

The write path MUST read the un-projected stored value, not a read-projected one. Reading a
value that was already decayed on read and decaying it again on write double-decays a returning
attacker's score. This is a real seam: a repository test double where the un-projected read and
the projected read return the same value hides it. It is caught only by a real-engine plus
real-repository integration test that spans at least one half-life.

### Breadth factor

Breadth is a bounded multiplier applied to `raw_score` to produce the effective score. It
rewards an IP seen across more of the operator's WAN IPs:

```
factor = 1 + min(BREADTH_CAP, BREADTH_PER_WAN * max(0, distinct_wan_count - 1))
effective_score = min(100, raw_score * factor)
```

Settled values (ratified; magnitude is provisional — revalidate against real multi-WAN traces once
collected, and expect to tune down):

- `BREADTH_PER_WAN = 0.15`
- `BREADTH_CAP = 0.60`

With these, one WAN IP gives factor 1.00, and five or more WAN IPs give factor 1.60.

`distinct_wan_count` is WAN-breadth ONLY. Sensor-breadth (`distinct_sensor_count`) is deliberately NOT
a multiplier input: it measures the operator's own instrumentation density and would couple tiers to
deployment scale. The WAN count is hardened by two load-bearing rules, which defeat different attacks
and neither of which subsumes the other:

1. Authenticated-vantage filter: a WAN IP counts toward `distinct_wan_count` only if it observed a
   `protocol = tcp AND authenticated = true` event from that source. A spoofed source cannot complete a
   handshake, so spoofed breadth contributes zero. (Defeats spoofed breadth.)
2. `/24` (and shared upstream-ASN where a lookup is available) dedupe on the counted WAN set: WAN IPs
   in the same `/24` or ASN count once. One contiguous sweep across the operator's clustered WANs is
   one sighting, not N. `/24` dedupe is mandatory; ASN dedupe is best-effort (needs a GeoIP/BGP
   lookup). (Defeats genuine-but-correlated breadth.)

The breadth factor feeds the effective score (weight, sorting, display) and the blocklist
recommendation only. It does NOT feed the tier gate, which runs on the raw score (see Tier gate), and
it is structurally incapable of touching `has_confirmed_real` or the eligibility legs.

### Eligibility gate

As defined in The three-level report model:

```
eligible = has_confirmed_real
           AND event_count >= 2
           AND distinct_categories >= 2
```

`distinct_categories` counts categories whose decayed breakdown weight is strictly greater than
0.5.

### Tier gate

Tier is computed on the RAW decayed score (ratified), NOT the breadth-boosted effective score:
breadth must never raise a vendor report's severity, and the 90/75 floors are calibrated on the raw
distribution (feeding them a score boosted up to 1.6x would silently lower the true floors to raw
~56/~47). Both axes of a band must clear their floor:

```
AGGRESSIVE  if  raw_score >= 90  AND  max_confidence >= 0.95
STANDARD    if  raw_score >= 75  AND  max_confidence >= 0.70   (tested after AGGRESSIVE)
otherwise   ->  None
```

`max_confidence` here is computed over the currently-DECAYED live breakdown (only events whose decayed
weight is still > 0 contribute), never a sticky lifetime maximum, so a faded high-confidence event
stops holding a tier open. A score of 92 with confidence 0.80 is STANDARD, not AGGRESSIVE: the
confidence floor is not met. `tier` and `eligible` are independent facts; an IP can be eligible with
`tier = None`.

### Recommendation

Two eligibility-gated flags, one per real downstream action (see The three-level report model):

```
recommended_for_vendor     = eligible AND tier is not None          (tier on raw score)
recommended_for_blocklist  = eligible AND effective_score >= BLOCKLIST_FLOOR
```

`BLOCKLIST_FLOOR = 50` is a fixed source constant (provisional — the blocklist is published publicly,
so a floor set too low degrades the list for third-party consumers, not just the operator; validate
against real data and instrument over/under-inclusion). Any "report to vendor" action is structurally
absent from the blocklist path, so the blocklist floor can never leak into the vendor surface.

## Error handling

- A malformed event is dropped and never crashes the pipeline. The append path validates the
  event (parseable source IP, known signal type, in-range fields) and rejects a bad one by
  returning an error, not by panicking.
- The append is transactional: the projection upsert and the ledger insert commit together, so
  a partial write cannot leave the projection ahead of or behind the ledger.
- The `hash` covers the event's canonical content plus the chain's `prev_hash`. On read the
  chain is verified by recomputing each hash and checking linkage; a mismatch is surfaced as a
  tamper indication, not silently ignored.
- A database error fails closed. On any error path an IP is never marked eligible or
  recommended. An unknown, missing, or malformed value denies rather than admits. A guard whose
  input is absent or unreadable must deny, never proceed.

## Testing strategy

The core scoring layer is verified with property-based tests and boundary example tests, exercising the real
scoring path rather than mocks.

- Decay is monotonic non-increasing: for any non-negative elapsed time, the decayed value is
  less than or equal to the input.
- Decay never inflates on negative or zero elapsed time: the clock-skew clamp returns `prev`
  unchanged.
- Decay halves at exactly one half-life: input decayed over exactly `half_life_seconds` equals
  input times 0.5, within numeric tolerance.
- Replay determinism: for any event stream, the projection rebuilt by replaying the full ledger
  in observed order equals the projection maintained incrementally by the write path.
- Breadth never flips eligibility: for any event stream that contains no confirmed-real event,
  `eligible` stays false for every value of `distinct_wan_count` and every breadth constant.
  This is the anti-spoof invariant and is a required test.
- Hash-chain tamper detection: mutating any recorded event's content or reordering the chain
  makes verification fail.
- Gate truth tables: eligibility, tier, and recommendation are asserted across boundary inputs
  (score and confidence exactly on each floor, `distinct_categories` at 1 and 2, breakdown
  weight at exactly 0.5, `event_count` at 1 and 2), confirming strict versus non-strict
  comparisons behave as specified.
- Double-decay guard: a real-engine plus real-repository integration test across at least one
  half-life confirms the write path reads the un-projected value, so a returning attacker is
  not decayed twice.
- Breadth denominator hardening: a WAN that saw only non-`tcp`/unauthenticated events from a source
  does not increment `distinct_wan_count` (authenticated-vantage filter); two WAN IPs in the same
  `/24` count once (dedupe). A spoofed multi-WAN burst yields `distinct_wan_count` of at most 1.
- Tier runs on raw, not effective: an eligible IP with `raw_score = 60` and `effective_score = 96`
  (high breadth) tiers `None` — breadth cannot promote it to a vendor tier.
- Live-decayed confidence: an IP whose only high-confidence event has decayed to zero weight no longer
  meets the tier confidence floor, even if its lifetime maximum confidence was high.
- Split recommendation: `recommended_for_vendor` is true only when the raw tier is not None;
  `recommended_for_blocklist` is true only when `effective_score >= BLOCKLIST_FLOOR`; each requires
  `eligible`. A broad-but-low confirmed-real IP can be blocklist-recommended while vendor-None.

## Open questions — RESOLVED

All four were resolved by an evidence-judged panel and ratified by the operator on 2026-07-17. The
settled decisions are folded into the sections above; full rationale and surviving dissent live in
`01-core-scoring-layer-open-questions.md`. Summary:

1. Breadth constants: `0.15` / `0.60`, WAN-breadth only (sensor-breadth rejected), with a hardened
   `distinct_wan_count` denominator (authenticated-vantage filter + `/24`/ASN dedupe). Magnitude is
   provisional — revalidate on real multi-WAN traces.
2. Which score feeds the tier gate: the RAW decayed score, not the breadth-boosted score. Plus:
   `max_confidence` in the tier gate is the live-decayed value, not a sticky lifetime maximum.
3. Recommendation: split into `recommended_for_vendor` (raw tier) and `recommended_for_blocklist`
   (`effective_score >= BLOCKLIST_FLOOR`, 50). Both floors are fixed source constants.
4. Half-life: stays 21600s (6h), the sole operator-tunable knob.
