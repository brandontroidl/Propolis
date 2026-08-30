<!--
title: Evidence provenance and artifact custody
audience: developer
status: draft
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-30
-->

# Evidence provenance and artifact custody (SP-B)

Status: **Draft** (design; not yet implemented). The canonical specification for how Propolis makes
captured evidence durable, independently attributable, and content-addressed across the collector /
control-plane split (SP-A). Adversarial review findings, agent execution plans, and task briefs live
under the private `docs/superpowers/` tree; this document is the versioned, code-facing contract.

Only SP-B-1 (the additive `SampleRef.capture_id` wire field, merged) is implemented. This is design v4;
v1-v3 were rejected by successive adversarial reviews (see the private findings). Implementation waits
for this document to pass its own review.

## The product question

*Which source IPs are attached to this captured artifact, and on what evidence?* The v2 model could not
answer it for URL-fetched artifacts: a single observation row carried occurrence + SHA + one parent, but
a URL reference has no SHA, and one URL deduplicated across many referrers collapses to one fetch. v4
answers it with a many-to-many provenance **graph** whose edges carry an explicit evidence basis, an
**atomic** intake transaction that never advances past an unpersisted observation, and a three-stage
**custody** protocol under which a collector deletes a body only after its attribution is durable.

**Terminology (load-bearing):** a **captured artifact** is a body Propolis stored, identified by SHA-256.
It is **not "malware"** until an `analysis_result` verdict classifies it; a **retrieved endpoint** is an
IP Propolis contacted, never automatically "C2". Observed fact and analytical inference are kept in
separate relations and separate UI roles throughout.

## Authenticated transport: the enveloped gateway-spool record

SP-A's gateway wrote raw NDJSON to a per-collector spool (`crates/gateway/src/spool.rs`, byte-transparent,
`flush` not `fsync`). SP-B replaces that spool record with **one crash-consistent enveloped record** per
event, so the authenticated collector identity and the raw event bytes cannot drift apart across a crash:

```
enveloped spool record:
  collector_id       -- derived EXCLUSIVELY from the verified client-cert identity (never collector-provided)
  gateway_sequence    -- the per-collector monotonic sequence the gateway already tracks
  record_index        -- index within the batch
  batch_hash          -- the batch's rolling hash (already computed on the wire)
  raw_event_bytes     -- the sensor event's exact serialized NDJSON bytes, unchanged
```

The gateway writes this record with **fsync before it acknowledges the batch** (gateway `fsync` is a
mandatory SP-B dependency, not a separate hardening task). Intake consumes the envelope: it takes
`collector_id` authoritatively from it (never trusting any collector-authored field), parses
`raw_event_bytes` unchanged (preserving the hash chain), and gains stable transport coordinates
`(collector_id, gateway_sequence, record_index)` that serve as a fallback identity for legacy events
predating `occurrence_id`.

## Stable identities

- **`occurrence_id`** - a UUIDv7 minted at the sensor **per event** (additive `sensor-wire` field on
  `SensorEvent`; optional + skip, no `WIRE_VERSION` bump). A replayed event carries the same
  `occurrence_id`, so intake dedups exactly (below). Legacy events without it fall back to
  `(collector_id, gateway_sequence, record_index)`.
- **`capture_id`** - merged on `SampleRef` (SP-B-1); one per captured body; the receipt identity.
- **`collector_id`** - from the enveloped record only (verified cert identity).

## The evidence graph (schema)

Append-only relations, with **two** explicitly-derived mutable projections - `artifact_current`
(rebuilt from `artifact_state_event`) and `analysis_submission` (rebuilt from `analysis_submission_event`)
- each rebuildable and neither a source of truth. Every evidence-bearing row also emits an
`evidence_commitment` in its own insert transaction (P0-1, below). Every append-only relation has
UPDATE/DELETE/TRUNCATE revoked (Security).
`sha256` is BYTEA; the wire and
display edges hex-encode. Hosted in `crates/core-scoring/migrations`.

```sql
-- One immutable row per event occurrence. NO sha; artifacts link via observation_artifact.
CREATE TABLE observation (
    collector_id          TEXT NOT NULL,
    occurrence_id         UUID NOT NULL,
    role                  TEXT NOT NULL,   -- direct_upload | url_reference | fetch | recursive_fetch
    source_ip             INET,
    sensor                TEXT,
    session_id            UUID,
    url                   TEXT,
    url_hash              BYTEA,
    retrieved_endpoint_ip INET,            -- endpoint contacted; never labelled "C2"
    event_id              BIGINT,
    event_hash            BYTEA,
    observed_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (collector_id, occurrence_id),
    CONSTRAINT observation_role_ck CHECK (role IN ('direct_upload','url_reference','fetch','recursive_fetch'))
);
CREATE INDEX observation_url_hash_idx  ON observation (url_hash);
CREATE INDEX observation_source_ip_idx ON observation (source_ip);

-- FACTS ONLY: directly-observed / causal edges (P0 correction: facts and inferences are not mixed).
-- Only `caused_retrieval` (the exact reference a fetch acted on) and `recursive_fetch_discovery` (a
-- structural fact: the fetcher observed URL X inside retrieved body Y) live here. The graph may cycle.
CREATE TABLE observation_edge (
    edge_id               BIGSERIAL UNIQUE,  -- surrogate so provenance_assertion_support can reference a fact edge by one column
    parent_collector_id   TEXT NOT NULL,
    parent_occurrence_id  UUID NOT NULL,
    child_collector_id    TEXT NOT NULL,
    child_occurrence_id   UUID NOT NULL,
    relation              TEXT NOT NULL,
    observed_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (parent_collector_id, parent_occurrence_id, child_collector_id, child_occurrence_id, relation),
    FOREIGN KEY (parent_collector_id, parent_occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    FOREIGN KEY (child_collector_id, child_occurrence_id)   REFERENCES observation (collector_id, occurrence_id),
    CONSTRAINT edge_relation_ck CHECK (relation IN ('caused_retrieval','recursive_fetch_discovery'))
);
CREATE INDEX observation_edge_child_idx  ON observation_edge (child_collector_id, child_occurrence_id);
CREATE INDEX observation_edge_parent_idx ON observation_edge (parent_collector_id, parent_occurrence_id);

-- INFERENCES/ASSOCIATIONS, kept OUT of the fact tables (P0 correction). A temporal same-URL association
-- or a backfill inference, each with its derivation method + confidence + supporting evidence.
CREATE TABLE provenance_assertion (
    id                    BIGSERIAL PRIMARY KEY,
    parent_collector_id   TEXT NOT NULL,
    parent_occurrence_id  UUID NOT NULL,
    child_collector_id    TEXT NOT NULL,
    child_occurrence_id   UUID NOT NULL,
    basis                 TEXT NOT NULL,   -- observed_before_retrieval | same_url_after_retrieval | historical_url_inference
    method                TEXT NOT NULL,   -- url_hash_temporal | url_hash_backfill
    method_version        TEXT NOT NULL,
    confidence            NUMERIC(4,3) NOT NULL,   -- 0..1
    derived_at            TIMESTAMPTZ NOT NULL,     -- supporting evidence is typed + FK'd in provenance_assertion_support (P0: no untyped JSONB)
    FOREIGN KEY (parent_collector_id, parent_occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    FOREIGN KEY (child_collector_id, child_occurrence_id)   REFERENCES observation (collector_id, occurrence_id),
    CONSTRAINT assertion_basis_ck CHECK (basis IN ('observed_before_retrieval','same_url_after_retrieval','historical_url_inference')),
    CONSTRAINT assertion_conf_ck CHECK (confidence BETWEEN 0 AND 1)
);
CREATE INDEX provenance_assertion_child_idx ON provenance_assertion (child_collector_id, child_occurrence_id);

-- P0 correction: an assertion's supporting evidence is TYPED and referentially enforced, never untyped
-- JSON ids (that recreates the dangling-reference class SP-B exists to remove). One append-only row per
-- (assertion, supporting item); exactly one typed target group is set, matching support_kind, each FK'd.
CREATE TABLE provenance_assertion_support (
    id                   BIGSERIAL PRIMARY KEY,
    assertion_id         BIGINT NOT NULL REFERENCES provenance_assertion (id),
    support_kind         TEXT NOT NULL,    -- observation | retrieval_attempt | fact_edge | analysis_run | assertion
    obs_collector_id     TEXT,
    obs_occurrence_id    UUID,
    attempt_id           UUID    REFERENCES retrieval_attempt (attempt_id),
    edge_id              BIGINT  REFERENCES observation_edge  (edge_id),
    support_run_id       UUID    REFERENCES analysis_run      (run_id),
    support_assertion_id BIGINT  REFERENCES provenance_assertion (id),
    FOREIGN KEY (obs_collector_id, obs_occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    CONSTRAINT pas_kind_ck CHECK (support_kind IN ('observation','retrieval_attempt','fact_edge','analysis_run','assertion')),
    -- exactly the group matching support_kind is populated, all others NULL (fail-closed against mislabelled links)
    CONSTRAINT pas_exactly_one CHECK (
        (support_kind = 'observation'      AND obs_collector_id IS NOT NULL AND obs_occurrence_id IS NOT NULL
             AND attempt_id IS NULL AND edge_id IS NULL AND support_run_id IS NULL AND support_assertion_id IS NULL)
     OR (support_kind = 'retrieval_attempt' AND attempt_id IS NOT NULL
             AND obs_collector_id IS NULL AND obs_occurrence_id IS NULL AND edge_id IS NULL AND support_run_id IS NULL AND support_assertion_id IS NULL)
     OR (support_kind = 'fact_edge'        AND edge_id IS NOT NULL
             AND obs_collector_id IS NULL AND obs_occurrence_id IS NULL AND attempt_id IS NULL AND support_run_id IS NULL AND support_assertion_id IS NULL)
     OR (support_kind = 'analysis_run'     AND support_run_id IS NOT NULL
             AND obs_collector_id IS NULL AND obs_occurrence_id IS NULL AND attempt_id IS NULL AND edge_id IS NULL AND support_assertion_id IS NULL)
     OR (support_kind = 'assertion'        AND support_assertion_id IS NOT NULL
             AND obs_collector_id IS NULL AND obs_occurrence_id IS NULL AND attempt_id IS NULL AND edge_id IS NULL AND support_run_id IS NULL)),
    UNIQUE (assertion_id, support_kind, obs_collector_id, obs_occurrence_id, attempt_id, edge_id, support_run_id, support_assertion_id)
);
CREATE INDEX provenance_assertion_support_aid_idx ON provenance_assertion_support (assertion_id);

-- Many-to-many occurrence -> content (which occurrence produced/uploaded which body).
CREATE TABLE observation_artifact (
    collector_id   TEXT NOT NULL,
    occurrence_id  UUID NOT NULL,
    sha256         BYTEA NOT NULL,
    relation       TEXT NOT NULL,          -- captured
    PRIMARY KEY (collector_id, occurrence_id, sha256, relation),
    FOREIGN KEY (collector_id, occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    CONSTRAINT obs_artifact_sha_len CHECK (octet_length(sha256) = 32)
);
CREATE INDEX observation_artifact_sha_idx ON observation_artifact (sha256);

-- The capture <-> observation join (finding 2). A collector can capture the same body repeatedly,
-- so SHA cannot substitute; this binds a body-capture occurrence to its receipt-bearing capture_id.
CREATE TABLE capture_observation (
    collector_id   TEXT NOT NULL,
    capture_id     UUID NOT NULL,
    occurrence_id  UUID NOT NULL,
    sha256         BYTEA NOT NULL,
    PRIMARY KEY (collector_id, capture_id),
    FOREIGN KEY (collector_id, occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    CONSTRAINT capture_obs_sha_len CHECK (octet_length(sha256) = 32)
);

-- Content lifecycle as an APPEND-ONLY event log (finding 4); the mutable current state is a projection.
CREATE TABLE artifact_state_event (
    id            BIGSERIAL PRIMARY KEY,
    sha256        BYTEA NOT NULL,
    state         TEXT NOT NULL,           -- observed | received | verified | quarantined_orphan | absent
    verified_size BIGINT,                  -- NULL until 'verified' (finding 4: cannot be truthful at placeholder time)
    reason        TEXT,
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT artifact_state_ck CHECK (state IN ('observed','received','verified','quarantined_orphan','absent'))
);
CREATE INDEX artifact_state_event_sha_idx ON artifact_state_event (sha256, id);

-- Rebuildable projection of the latest state per sha (built from artifact_state_event; not a source of truth).
CREATE TABLE artifact_current (
    sha256            BYTEA PRIMARY KEY,
    current_presence  TEXT NOT NULL,        -- present | quarantined_orphan | absent
    integrity_status  TEXT NOT NULL,        -- verified | unverified
    verified_size     BIGINT,               -- NULL until verified
    first_observed_at TIMESTAMPTZ NOT NULL,
    verified_at       TIMESTAMPTZ           -- NULL until verified
);

-- Custody (finding 2/5): which collector delivered which capture, and the content it committed to.
CREATE TABLE artifact_receipt (
    collector_id   TEXT NOT NULL,
    capture_id     UUID NOT NULL,
    occurrence_id  UUID NOT NULL,           -- binds the receipt to the observation (finding 2)
    sha256         BYTEA NOT NULL,
    size           BIGINT NOT NULL,
    committed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (collector_id, capture_id)
);

-- Ledger-level replay guard (finding 3): dedup an occurrence BEFORE appending to the hash chain / scoring.
CREATE TABLE event_occurrence (
    collector_id   TEXT NOT NULL,
    occurrence_id  UUID NOT NULL,
    event_id       BIGINT NOT NULL,
    PRIMARY KEY (collector_id, occurrence_id)
);

-- Immutable analyzer RUN. Created BEFORE analysis_result in the migration (it is the FK target; finding 4
-- - the SQL order now matches the comment). run_id is the identity; reruns (even same version) are new
-- runs, never blocked. Carries the analyzer binary/ruleset/config digests, the raw-result CAS reference AND
-- its digest, and a reproducible SIGNATURE (finding 4: a key id + status is not a signature). The SHA
-- lives HERE only; analysis_result derives it through run_id (finding 5 - no duplicate SHA to disagree).
CREATE TABLE analysis_run (
    run_id                 UUID PRIMARY KEY,
    sha256                 BYTEA NOT NULL,   -- the analyzed artifact; the sole SHA for the run+its results
    analyzer               TEXT NOT NULL,
    analyzer_version       TEXT NOT NULL,
    analyzer_binary_digest BYTEA,
    ruleset_digest         BYTEA,
    config_digest          BYTEA,
    raw_cas_ref            TEXT NOT NULL,    -- where the raw analyzer payload is stored (CAS)
    raw_digest             BYTEA NOT NULL,   -- SHA-256 of that raw payload
    signed_manifest_digest BYTEA,           -- SHA-256 of the canonical manifest that was signed
    signature              BYTEA,            -- the actual signature bytes over signed_manifest_digest
    signature_algorithm    TEXT,             -- e.g. ed25519 | ecdsa-p256-sha256 (needed to reproduce)
    signer_key_id          TEXT,             -- identifies the signing key
    verification_status    TEXT NOT NULL DEFAULT 'unverified',  -- unverified | signature_valid | signature_invalid
    started_at             TIMESTAMPTZ NOT NULL,
    finished_at            TIMESTAMPTZ,
    CONSTRAINT analysis_run_sha_len CHECK (octet_length(sha256) = 32),
    CONSTRAINT analysis_run_sig_complete CHECK (          -- a signature is all-or-nothing
        (signature IS NULL AND signature_algorithm IS NULL AND signed_manifest_digest IS NULL)
        OR (signature IS NOT NULL AND signature_algorithm IS NOT NULL AND signed_manifest_digest IS NOT NULL))
);
CREATE INDEX analysis_run_sha_idx ON analysis_run (sha256);

-- Inference, isolated from fact (finding 5). Append-only terminal verdicts, each bound by FK to the
-- immutable analysis_run that produced it. The artifact SHA is reached THROUGH run_id (no local sha256
-- column - finding 5: a duplicated SHA could disagree with the run's). Reruns allowed; NO unique-per-sha.
CREATE TABLE analysis_result (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES analysis_run (run_id),
    verdict         TEXT NOT NULL,          -- analyzer-native summary
    is_malware      BOOLEAN NOT NULL,       -- the classification that makes it "malware" in the UI
    detected        INTEGER,
    total           INTEGER,
    vt_link         TEXT,
    source_sensor   TEXT,
    analyzed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX analysis_result_run_idx ON analysis_result (run_id);
-- SHA-keyed result lookup goes through the run: WHERE run_id IN (SELECT run_id FROM analysis_run WHERE sha256=$1).

-- Submission lifecycle as an APPEND-ONLY event log (cleanup: analysis_submission was called rebuildable
-- but had no event source). pending/submitted/analyzed/failed transitions are appended here.
CREATE TABLE analysis_submission_event (
    id            BIGSERIAL PRIMARY KEY,
    sha256        BYTEA NOT NULL,
    analyzer      TEXT NOT NULL,
    state         TEXT NOT NULL,            -- pending | submitted | analyzed | failed
    reason        TEXT,
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT submission_state_ck CHECK (state IN ('pending','submitted','analyzed','failed')),
    CONSTRAINT submission_ev_sha_len CHECK (octet_length(sha256) = 32)
);
CREATE INDEX analysis_submission_event_idx ON analysis_submission_event (sha256, analyzer, id);

-- Rebuildable projection of the latest submission state per (sha, analyzer) - built from the event log
-- above; not a source of truth (mirrors artifact_current / artifact_state_event).
CREATE TABLE analysis_submission (
    sha256        BYTEA NOT NULL,
    analyzer      TEXT NOT NULL,
    state         TEXT NOT NULL,            -- pending | submitted | analyzed | failed
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sha256, analyzer)
);
```

### Migration order (executable, finding 4 generalized)

The blocks above are grouped by concern, not file order. The migration creates tables in **dependency
order** - identity tables (`observation`), then `retrieval_attempt`, `analysis_run`, `observation_edge`,
`observation_artifact`, `capture_observation`, then `provenance_assertion`, then
`provenance_assertion_support`, then the projections and event logs. Any FK whose target is defined in a
later concern-group (`provenance_assertion_support.attempt_id` -> `retrieval_attempt`;
`.support_run_id` -> `analysis_run`) is realized with `ALTER TABLE ... ADD CONSTRAINT` **after** both ends
exist. A state-independent parse/compile guard runs the whole migration set against a scratch database in
the gate, so an ordering regression fails the build, not production.

### Per-row evidence commitment, in the same transaction (P0-1)

The Merkle layer must not open a deletion-before-provability window: **every evidence-bearing row emits its
commitment in the same database transaction that inserts the row.** The per-row commitment is part of SP-B
core (SP-B-2), not deferred to SP-B-6; only *epoch closure* (root, signature, anchor) is asynchronous, and
it runs over rows that are already immutable and already committed.

```sql
-- One immutable commitment per evidence-bearing row, appended in the row's own transaction.
CREATE TABLE evidence_commitment (
    commitment_id   BIGSERIAL PRIMARY KEY,
    relation        TEXT   NOT NULL,       -- 'observation' | 'observation_edge' | 'provenance_assertion' | ...
    row_pk_digest   BYTEA  NOT NULL,       -- SHA-256 of the row's canonical primary key (locates the row)
    row_digest      BYTEA  NOT NULL,       -- SHA-256 over the row's FROZEN canonical encoding (SP-B-6 pins it)
    global_sequence BIGINT NOT NULL,       -- dense global order, assigned in-tx from one sequence
    committed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ec_rowdig_len CHECK (octet_length(row_digest) = 32),
    CONSTRAINT ec_pkdig_len  CHECK (octet_length(row_pk_digest) = 32),
    UNIQUE (relation, row_pk_digest),      -- one commitment per row
    UNIQUE (global_sequence)
);
CREATE INDEX evidence_commitment_seq_idx ON evidence_commitment (global_sequence);

-- Epoch closure is SP-B-6 and asynchronous. Membership is by global_sequence RANGE, so a commitment row is
-- NEVER mutated to point at an epoch (it stays append-only). Signature fields mirror analysis_run's.
CREATE TABLE evidence_epoch (
    epoch_id               BIGINT PRIMARY KEY,
    seq_lo                 BIGINT NOT NULL,   -- inclusive; the epoch covers [seq_lo, seq_hi]
    seq_hi                 BIGINT NOT NULL,
    merkle_root            BYTEA  NOT NULL,
    prev_root              BYTEA,             -- commits the prior epoch's root (chains epochs); NULL for epoch 0
    signed_manifest_digest BYTEA  NOT NULL,
    signature              BYTEA  NOT NULL,
    signature_algorithm    TEXT   NOT NULL,
    signer_key_id          TEXT   NOT NULL,
    anchor_receipt         JSONB,             -- trusted-timestamp / transparency-log inclusion, committed off-host
    closed_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT epoch_range_ck CHECK (seq_hi >= seq_lo)
);
```

**Enforcement (fail-closed, both mechanisms):**
- The **only** grantee of INSERT on every evidence relation is a single repository function that inserts the
  row and its `evidence_commitment` together (one interface, per the reviewer's "one repository interface").
- A **deferred constraint trigger** (`DEFERRABLE INITIALLY DEFERRED`) on each evidence relation fails the
  transaction at commit if the row has no matching `evidence_commitment(relation, row_pk_digest)`. So even a
  future writer that bypasses the repository cannot commit an uncommitted evidence row - the digest is not
  optional. `global_sequence` comes from one dedicated sequence; epoch membership is by sequence **range**
  (`evidence_epoch.seq_lo..seq_hi`), so a commitment row is never mutated to point at an epoch.

### Cross-table SHA agreement (P0-2)

Redundant SHA columns were removed where a value is FK-derivable (`observation_retrieval.result_sha256` and
`analysis_result.sha256` are gone - each reaches the SHA through its FK). The remaining cross-table
equalities are enforced by **deferred constraint triggers** so a writer bug cannot commit a
cryptographically-committed but false relationship:
- `retrieval_attempt.result_sha256` **=** the `observation_artifact('captured').sha256` of the `fetch`
  observation bound to it through `observation_retrieval` (the attempt's bytes are the fetch's bytes).
- `capture_observation.sha256` **=** the `observation_artifact.sha256` for the same `(collector_id,
  occurrence_id)` (the capture's bytes are the occurrence's captured bytes).

Both are `DEFERRABLE INITIALLY DEFERRED`, checked at commit, so the two rows may be inserted in either order
within the one intake/fetcher transaction and still be proven equal before commit.

### Facts vs. inferences (finding 3, enforced at the schema level)

A URL can serve SHA-A today and SHA-B tomorrow, so sharing a `url_hash` with a fetch does not prove an IP
referenced the retrieved bytes. Directly-observed/causal links and derived associations live in **separate
tables**, not one `basis` column:
- **`observation_edge` = facts only.** `caused_retrieval` (the exact reference the fetcher selected and
  acted on for a specific `retrieval_attempt`, also bound in `observation_retrieval`) and
  `recursive_fetch_discovery` (the fetcher directly observed URL X inside retrieved body Y). These are the
  only edges presented as direct provenance.
- **`provenance_assertion` = associations + inferences**, each with `method`, `method_version`,
  `confidence`, `derived_at`, and typed `provenance_assertion_support` rows: `observed_before_retrieval` (same `url_hash`,
  earlier - temporally consistent, not causal), `same_url_after_retrieval`, and `historical_url_inference`
  (backfill from `url_hash` alone). Never presented as retrieval provenance.

The console renders each contributing link with its fact-vs-assertion source, basis, method, and
confidence, and never flattens them into "attached".

## Atomic intake (finding 3, one transaction - LOCKED, no alternative)

Per accepted enveloped record, intake runs **one** database transaction via
`core_scoring::append_ingested_record(tx, IngestedRecord) -> Result<AppendOutcome, RepoError>`:
1. Look up `event_occurrence(collector_id, occurrence_id)`. If present with identical immutable content,
   the whole record is an **exact replay -> no-op** (return the existing outcome; do not append to the
   hash chain, do not touch scoring). If present with **conflicting** content -> **roll back and alert**.
2. Otherwise append the ledger event (hash chain), upsert the score projection, insert
   `event_occurrence`, insert the `observation` row(s), any `observation_edge`s, `observation_artifact`
   link + `capture_observation` for a body-bearing event, an `artifact_state_event('observed')`, and the
   `evidence_commitment` for every evidence-bearing row written (P0-1; the deferred trigger fails the commit
   if any is missing).
All in the one `tx`. The tailer cursor advances **only** after the transaction commits. A crash mid-tx
rolls back; the enveloped record is re-read; step 1 makes it a no-op. There is **no** best-effort write
and **no** projection-outbox fallback in this specification.

## Collector outbox + three-stage custody

### Durable outbox manifest (collector side, finding 2)

Written fsync-atomically with body publication (directory scanning cannot recover which `capture_id`
produced a SHA-named file):

```
manifest row (fsynced with the body):
  collector_id
  capture_id
  occurrence_id        -- REQUIRED (finding 2): the outbox carries the observation identity
  sha256
  size
  body_key
  gateway_spool_state  -- pending | durable   (the enveloped event is fsynced in the gateway spool)
  cas_state            -- pending | durable    (the body has a CAS receipt)
  custody_state        -- pending | complete   (CustodyComplete received)
```

The artifact-shipper consumes manifest rows, not files.

### Three-stage custody (LOCKED; only the third authorizes deletion)

1. **Gateway-spool receipt** - the enveloped event record is fsynced durable in the gateway spool (the
   event channel's ack now means fsynced, not flushed).
2. **CAS body receipt** - the body is hash-verified and durable in the CAS.
3. **`CustodyComplete` receipt** - proves that, in Postgres, the `observation`, the `capture_observation`
   link, the verified body (`artifact_receipt` + `artifact_state_event('verified')`), **and the
   `evidence_commitment` row of each of those** are **all committed** (P0-1: the relationships are not just
   durable, they are provable - inside a Merkle-committable sequence). It binds `collector_id + capture_id +
   occurrence_id + sha256 + size` and carries the `commitment_id`s (or their `global_sequence`s) it requires.

A collector may delete its only copy of a body **only on `CustodyComplete`**. Stages 1 and 2 are
prerequisites; neither alone authorizes deletion. This closes both the "durable body, lost attribution"
hole (if the observation never committed, `CustodyComplete` is never issued) **and** the
"durable body, unprovable attribution" hole (if the commitments are missing, `CustodyComplete` is withheld,
so a body is never deleted before its relationships can enter an epoch). Epoch *closure* may lag; the
committed, immutable commitment rows are what the receipt requires, and they are enough - the next epoch
will include them.

## Artifact channel + CAS

Dedicated ingest-only mTLS channel off a **separate artifact CA** (SP-A event gateway unchanged besides
its new fsync). `Offer{capture_id, occurrence_id, sha256, size} -> Need | Present -> chunk stream ->
committed DurableReceipt{disposition: stored | already_present}`. **`collector_id` is NOT on the wire**
(P0 correction): the ingress derives collector identity solely from the verified artifact client
certificate and keys **ownership, quota namespace, and receipts** from it - a collector-supplied
`collector_id` is never trusted (same rule as the enveloped gateway record). The **CAS content path is
global**, `cas_root + shard + hex(computed_sha)`, collector-INDEPENDENT (finding 6): identical bytes from
two collectors dedup to one path; only ownership/quota/receipts are per-certificate, never the content
path. No pre-commit `AlreadyDurable`:
even when the CAS holds the SHA, the ingress first commits an `artifact_receipt` for this
`(collector_id, capture_id, occurrence_id)` and confirms the body is present on disk (`stat`/re-hash),
then returns `already_present`. Receipt identity `(collector_id, capture_id)`; exact re-offer is a no-op
re-ack; a conflicting `sha`/`size` for the same identity is rejected + alerted.

CAS write: per-attempt-random temp on the **same filesystem** as the sharded tree -> re-read-verify
size+SHA from disk -> fsync -> atomic rename to `<cas_root>/<shard>/<hex>` from the **computed** digest
and a **configured** `cas_root` (never a stored absolute path) -> fsync leaf shard (+ `cas_root` on
create) -> commit `artifact_state_event('verified')` + projection + `artifact_receipt`. Over-quota
**rejects new Offers** (received evidence never evicted). An orphan (fs-success/db-crash) is
`quarantined_orphan`, adopted or held, never auto-deleted.

## Producers

- **Intake** - `direct_upload` (body event: observation + `observation_artifact` + `capture_observation`
  + `artifact_state_event('observed')`) and `url_reference` (every `honeypot_file_download` event; SHA
  NULL; `url_hash` set) - all in the atomic transaction.
- **Fetcher** (in-plane for SP-B; SP-C relocates execution) - on a retrieval: a `fetch` observation
  (`url_hash`, `retrieved_endpoint_ip`, `observation_artifact` -> produced SHA), a `retrieval_attempt` +
  `observation_retrieval` row, and then the reference links split by kind (fact vs. inference): a
  **`caused_retrieval` `observation_edge`** (fact) for the exact reference it acted on, and a
  **`provenance_assertion`** for every *other* `url_reference` sharing the `url_hash` -
  `observed_before_retrieval` for earlier same-URL references, `same_url_after_retrieval` for later ones -
  each with its `method`, `confidence`, and typed `provenance_assertion_support` rows. Recursive child
  discovery writes a `recursive_fetch_discovery` `observation_edge` (fact) on **both** first-discovery and
  rediscovery paths. `fetch_attempt.parent_hash` -> `parent_url_hash`; causal lineage lives in
  `observation_edge`, associations in `provenance_assertion`.
- **VirusTotal** (finding 8) - read and write move to `analysis_result`/`analysis_submission` **together**;
  `already_analyzed` reads the new tables so a new sample is never resubmitted; scanner iterates
  `artifact_current` by `current_presence='present'` reading the CAS; `sample_analysis` backfilled lossless
  then dropped (sequenced with the console rebuild).

## The SHA -> all-associated-source-IPs traversal (finding 5/8, P1)

**The authoritative traversal is application-side breadth-first (BFS)** over `observation_edge` (facts) and
`provenance_assertion` (assertions), unioned per hop and tagged by source. It is the *single* algorithm
that produces a source-IP list; the recursive CTE below is **illustrative only** and non-authoritative,
kept because it reads clearly and its representative traversal is verified - maintaining two authoritative
algorithms would risk the exact disagreement the review warns of, so acceptance test (l) reconciles the CTE
against BFS on a fixed corpus and BFS wins any divergence.

The BFS contract (decision-complete):
- **Node identity** is the composite `(collector_id, occurrence_id)`; a visited-set on that key is the
  cycle guard (a bare `occurrence_id` false-cycles across collectors).
- **Per-node fanout cap** `F`: fetch `F + 1` parent edges per node; if `F + 1` come back, emit the node but
  set **`fanout_truncated`** (P1: the cap firing is never silent - the old lateral `LIMIT $4` discarded
  parents with no signal).
- **Total-node budget** `B`: stop expanding when `B` distinct nodes are visited and set **`budget_truncated`**
  (a single CTE cannot bound total nodes; BFS can).
- **Depth bound** `D`: stop past depth `D` and set **`depth_truncated`**.
- Each result row carries `source_ip`, `role`, `depth`, the full `node_path`, and the full `basis_path`
  (`src:basis` per hop). Real pagination is a **keyset cursor** over the ordered result, never a `LIMIT+1`.
- The three truncation flags are returned to the console, which shows *why* a list may be incomplete.

```sql
-- ILLUSTRATIVE ONLY (non-authoritative; BFS above is authoritative). Verified for syntax + one
-- representative traversal. caller: SET LOCAL statement_timeout.
WITH RECURSIVE
prov_link AS (
    SELECT parent_collector_id, parent_occurrence_id, child_collector_id, child_occurrence_id,
           relation AS basis, 'fact'::text AS src FROM observation_edge
    UNION ALL
    SELECT parent_collector_id, parent_occurrence_id, child_collector_id, child_occurrence_id,
           basis, 'assertion'::text AS src FROM provenance_assertion
),
seed AS (
    SELECT o.collector_id, o.occurrence_id, 0 AS depth,
           ARRAY[o.collector_id||':'||o.occurrence_id::text] AS node_path, ARRAY[]::text[] AS basis_path
    FROM observation_artifact oa JOIN observation o USING (collector_id, occurrence_id)
    WHERE oa.sha256 = $1
),
walk AS (
    SELECT collector_id, occurrence_id, depth, node_path, basis_path FROM seed
    UNION ALL
    SELECT e.parent_collector_id, e.parent_occurrence_id, w.depth+1,
           w.node_path || (e.parent_collector_id||':'||e.parent_occurrence_id::text),
           w.basis_path || (e.src||':'||e.basis)
    FROM walk w
    JOIN LATERAL (
        SELECT pl.* FROM prov_link pl
        WHERE pl.child_collector_id = w.collector_id AND pl.child_occurrence_id = w.occurrence_id
          AND (pl.parent_collector_id||':'||pl.parent_occurrence_id::text) <> ALL (w.node_path)  -- composite cycle guard
        ORDER BY pl.parent_collector_id, pl.parent_occurrence_id, pl.basis
        LIMIT $4                                                                                 -- per-node fanout cap
    ) e ON true
    WHERE w.depth < $2                                                                           -- depth bound
)
SELECT DISTINCT o.collector_id, o.occurrence_id, host(o.source_ip) AS source_ip, o.role, o.url,
       o.sensor, o.session_id, w.depth, w.node_path, w.basis_path, o.observed_at
FROM walk w JOIN observation o USING (collector_id, occurrence_id)
WHERE o.source_ip IS NOT NULL
ORDER BY o.source_ip, o.role, w.depth, o.collector_id, o.occurrence_id, w.node_path                -- total order
LIMIT $3 + 1;                                                                                     -- truncation flag
```

The console filters/labels by the `basis_path` (only `caused_retrieval` is direct retrieval provenance;
everything else is association or inference), shows the node path, paginates via the keyset cursor, and
surfaces the `fanout_truncated` / `budget_truncated` / `depth_truncated` flags; it never presents an
association as retrieval provenance, and never presents a truncated list as complete.

## Historical backfill (finding 9: SQL + an operator tool)

Two parts, because filesystem adoption is not a SQL migration:
- **SQL migration** - derive `direct_upload` observations + links from events carrying `sample_sha256`;
  a `url_reference` per `honeypot_file_download` event; `fetch` observations + links from `fetch_attempt`
  rows with a `sha256`; `provenance_assertion`s joining references to fetches by `url_hash` with basis
  `historical_url_inference`, `method='backfill_url_join'`, low `confidence` (no timing evidence survives,
  so these are inferences, never facts). `occurrence_id`s derived deterministically
  from the source row (stable hash of `event.id`) so re-runs are idempotent.
- **Operator migration tool** (`propolis-cas-adopt`) - resumable, journaled: rehash each spool body,
  reconcile against `artifact_current` (append `artifact_state_event` rows, never mutate), adopt into
  the CAS or flag, dry-run report, and label irrecoverable
  recursive lineage **incomplete**. Not a normal migration.

## Cryptographic coverage (P0 correction)

The event hash chain covers only `event` rows over a **frozen canonical encoding that excludes
`session_id`**, and the new relations - `observation`, `observation_edge`, `observation_artifact`,
`capture_observation`, `artifact_receipt`, `artifact_state_event`, `analysis_result`, and analyst
decisions - sit entirely outside it. Signing the event-chain tip proves none of these relationships. So:

Coverage is split so there is **no deletion-before-provability window** (P0-1). The **per-row commitment
is SP-B core, not SP-B-6**: `evidence_commitment` (schema above) is inserted in the *same transaction* as
each evidence-bearing row (observation, edge, assertion, `provenance_assertion_support`,
observation_artifact, capture_observation, artifact_receipt, artifact_state_event, analysis_run,
analysis_result, observation_retrieval, retrieval_attempt), enforced by the single writer interface and the
deferred completeness trigger, and `CustodyComplete` requires those commitment rows. So a relationship is
provable the instant it is durable.

**SP-B-6 (epoch closure + anchoring)** is the *asynchronous* remainder, run over rows that are already
immutable and already committed. It defines, decision-complete (not prose):
- A **frozen canonical encoding** per relation (field order + types fixed) over which each row's
  `row_digest` is taken - the encoding SP-B core computes against.
- **Epoch closure** over a `global_sequence` range (`evidence_epoch`, schema above): a Merkle root, its
  signature (`signature` + `signature_algorithm` + `signed_manifest_digest`), the `signer_key_id`, a key
  **rotation** record, **previous-root linkage** (`prev_root` chains epochs), and an off-host
  **anchor receipt** (trusted timestamp / transparency-log inclusion). Membership is by sequence range, so
  no commitment row is ever mutated.
- **Session coverage LOCKED**: the frozen `event` chain is NOT changed; instead a covered `observation`
  row's `row_digest` binds `event_hash + session_id`, so `session_id` is committed via the graph, not by
  re-encoding the event.
- An exported case package (roadmap phase 4) carries the signed epoch root(s), inclusion proofs for every
  cited row, and a standalone verifier, so a third party can prove the relationship path.

SP-B core lands the relations **and their per-row commitments**; SP-B-6 lands the epochs, signing,
rotation, and anchor receipts. Anchoring is **in scope for SP-B (as SP-B-6)** - not a non-goal.

## Retrieval context (P1 correction: a URL is not a fetch)

URL-level dedup plus one fetch result cannot model a URL whose content, DNS, redirect chain, certificate,
or endpoint changes over time. Every retrieval attempt persists its full response context as its own
immutable row, and the `fetch` observation references the attempt that produced its SHA:

```sql
CREATE TABLE retrieval_attempt (
    attempt_id       UUID PRIMARY KEY,
    url_raw          TEXT NOT NULL,
    url_normalized   TEXT NOT NULL,
    url_hash         BYTEA NOT NULL,
    -- redirect_chain is an ORDERED array of per-hop objects, each carrying that hop's own context (cleanup:
    -- DNS/endpoint/TLS/response are per hop, not one flat set): {url_hash, pinned_endpoint, dns_answers,
    -- tls_fingerprint, http_status, content_type}. Attacker-controlled; see the bounds below.
    redirect_chain   JSONB,
    final_endpoint   INET,                -- the IP dialed on the final hop (convenience; also the last redirect_chain hop)
    final_tls        TEXT,                -- final-hop server cert / JA3S where available
    final_status     INTEGER,             -- final HTTP status (never trusted for classification)
    started_at       TIMESTAMPTZ NOT NULL,
    finished_at      TIMESTAMPTZ,
    result_sha256    BYTEA,               -- the body this attempt produced, NULL on failure
    CONSTRAINT ra_url_raw_len   CHECK (octet_length(url_raw)   <= 8192),
    CONSTRAINT ra_url_norm_len  CHECK (octet_length(url_normalized) <= 8192),
    CONSTRAINT ra_url_hash_len  CHECK (octet_length(url_hash)  = 32),
    CONSTRAINT ra_result_len    CHECK (result_sha256 IS NULL OR octet_length(result_sha256) = 32),
    CONSTRAINT ra_chain_bound   CHECK (redirect_chain IS NULL          -- cap hop count; per-field caps enforced by the writer
                                       OR jsonb_array_length(redirect_chain) <= 32)
);
CREATE INDEX retrieval_attempt_url_hash_idx ON retrieval_attempt (url_hash);
CREATE INDEX retrieval_attempt_sha_idx      ON retrieval_attempt (result_sha256);

-- The causal binding the prose alone did not establish (P0 correction): an immutable row tying the
-- retrieval attempt to the fetch observation it produced AND (for attacker-driven fetches) the exact
-- reference observation that caused it. The SHA is NOT duplicated here (finding 5): it is reached through
-- attempt_id -> retrieval_attempt.result_sha256. `trigger_kind` (cleanup) lets a scheduled/manual refetch,
-- which has no attacker reference, still be represented; causal_ref is required only for attacker_reference.
CREATE TABLE observation_retrieval (
    attempt_id                    UUID NOT NULL REFERENCES retrieval_attempt (attempt_id),
    fetch_collector_id            TEXT NOT NULL,
    fetch_occurrence_id           UUID NOT NULL,   -- the `fetch` observation
    trigger_kind                  TEXT NOT NULL,   -- attacker_reference | scheduled_refetch | manual
    causal_ref_collector_id       TEXT,            -- the reference observation the fetcher selected (NULL for non-attacker triggers)
    causal_ref_occurrence_id      UUID,
    PRIMARY KEY (attempt_id),
    FOREIGN KEY (fetch_collector_id, fetch_occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    FOREIGN KEY (causal_ref_collector_id, causal_ref_occurrence_id) REFERENCES observation (collector_id, occurrence_id),
    CONSTRAINT obs_retrieval_trigger_ck CHECK (trigger_kind IN ('attacker_reference','scheduled_refetch','manual')),
    CONSTRAINT obs_retrieval_causal_ck CHECK (           -- attacker fetches MUST name the causing reference; others must NOT
        (trigger_kind = 'attacker_reference' AND causal_ref_collector_id IS NOT NULL AND causal_ref_occurrence_id IS NOT NULL)
        OR (trigger_kind <> 'attacker_reference' AND causal_ref_collector_id IS NULL AND causal_ref_occurrence_id IS NULL))
);
```

For an attacker-driven fetch the `caused_retrieval` `observation_edge` (reference -> fetch) and this
`observation_retrieval` row are written together in the fetcher's transaction, so "this IP caused the
retrieval of these bytes" is provable to the fetch observation, the attempt, its endpoint, and its time -
not merely to a shared `url_hash`. A deferred trigger (P0-2) proves the attempt's `result_sha256` equals
the fetch's captured `observation_artifact.sha256`, so the two SHAs cannot silently disagree.

## Security (real, not prose)

Distinct DB roles (ingest-writer, fetcher/analysis-writer, console read-only), each granted only what it
needs, UPDATE/DELETE/TRUNCATE revoked on all append-only relations; enum/length/size/FK CHECKs (above);
CAS paths = configured `cas_root` + validated hex; collector identity from the enveloped record;
orphans quarantined.

## Console (roles distinct)

**Observed source** (IP that issued the instruction), **Uploaded via** (protocol), **Referenced URL**,
**Retrieved endpoint** (contacted IP; not "C2"), **Analysis verdict** (malware only with an
`analysis_result`, provider + timestamp). Sample -> every associated source IP with its path + basis; IP
-> associated samples; presence-honest Download/VT; URL userinfo masked. Built after the `sample_analysis`
drop is sequenced.

## Locked decisions (recorded in decisions.md)

1. **Collector identity** from the authenticated **enveloped gateway-spool record** only (verified cert
   identity + gateway_sequence/record_index/batch_hash/raw_event_bytes, crash-consistent). No loose
   sidecar. Never a collector-provided `collector_id`.
2. **One atomic intake transaction** - no projection-outbox alternative.
3. **Append-only `artifact_state_event` + rebuildable `artifact_current` projection** - not a mutable row.
4. **Three-stage custody**; only `CustodyComplete` (binding collector_id+capture_id+occurrence_id+sha256+size
   **and the required `evidence_commitment` rows**) authorizes deletion.
5. Gateway spool **fsync-before-ack** is a mandatory SP-B dependency, not a separate task.
6. **Facts vs. inferences are separate relations**: `observation_edge` (facts) vs. `provenance_assertion`
   (inferences, with method + confidence), and assertion support is a **typed, FK-enforced**
   `provenance_assertion_support`, never untyped JSONB.
7. **Per-row evidence commitment is SP-B core, emitted in the same transaction as each evidence row**
   (single writer interface + deferred completeness trigger); epoch closure/signing/anchoring is the
   asynchronous SP-B-6 remainder over already-immutable rows. No deletion-before-provability window.
8. **No duplicated SHA**: a SHA is reached through its FK (`analysis_result`->`analysis_run`,
   `observation_retrieval`->`retrieval_attempt`); the remaining cross-table equalities are enforced by
   **deferred constraint triggers**, so a committed-but-false relationship cannot be written.
9. **Analysis**: an immutable `analysis_run` holds the sole SHA and a **reproducible signature**
   (signature bytes + algorithm + signed-manifest digest, not just a key id); `analysis_result` derives the
   SHA via `run_id`; the submission lifecycle is an append-only `analysis_submission_event` log + projection.
10. **Traversal**: application-side **BFS is authoritative** (composite node identity, per-node fanout cap,
    total-node budget, depth bound, three explicit truncation flags, keyset pagination); the recursive CTE
    is illustrative only and reconciled to BFS by test.
11. **CAS content path is global** (`cas_root/shard/hex(computed_sha)`); ownership, quota, and receipts are
    per-certificate.
12. **Retrieval**: `retrieval_attempt` + `observation_retrieval`; `trigger_kind` represents scheduled/manual
    refetches (nullable `causal_ref`); per-redirect-hop context; attacker JSON is bounded.

## Deliverables required before implementation

Revised schema (above); transaction boundaries (`append_ingested_record`, above); collector outbox +
three receipt state machines (above); historical migration (SQL + operator tool); the exact SHA->IPs
query (above), whose **syntax and one representative traversal are verified** against the supported
Postgres (the full acceptance suite below is a deliverable, not yet run); acceptance tests proving:
(a) two IPs reference one URL and **both** resolve to the resulting SHA; (b) one URL, multiple parents,
one fetch, one SHA, all reachable; (c) recursive cycles A->B->A terminate within the depth bound;
(d) event/body arrival order (either channel first) never loses attribution; (e) crash replay produces no
duplicate observations/receipts/ledger events (the `event_occurrence` guard); (f) conflicting-identity
reuse is rejected + alerted; (g) historical samples gain every recoverable association, with inferred
edges labelled; (h) **`CustodyComplete` is withheld when any required `evidence_commitment` row is
missing** (the deferred trigger + the receipt condition), and a body is not deleted; (i) a transaction that
would create a **cross-table SHA disagreement** (attempt vs. captured artifact, or capture vs. occurrence)
is rejected at commit by the deferred equality triggers; (j) an **invalid analysis signature** yields
`verification_status='signature_invalid'` and is surfaced, never silently trusted; (k)
**`provenance_assertion_support` referential integrity** - a support row with a dangling or
kind-mismatched target is rejected; (l) **fanout truncation is flagged** - a node exceeding `F` parents
sets `fanout_truncated`, and BFS and the illustrative CTE agree on a fixed corpus; (m) a
**scheduled/manual refetch** (no attacker reference) is representable via `trigger_kind` with a NULL
`causal_ref`. Plus: the graph traversal's fanout behaviour under a dense attacker-controlled graph
(fanout cap + total-node budget + depth cap all hold and flag).

## Non-goals

Scoring (out of scope; separate risk-posture review); SP-C fetcher relocation + detonation; the WORM tier
that makes body eviction reachable; the collector-rebuild epoch (SP-A F1 residual). (Evidence-commitment
anchoring is **in** scope as SP-B-6 - not a non-goal; the earlier v4 draft's listing it here was the
contradiction the review flagged.)

## Sub-plan sequencing

SP-B-1 (`capture_id`) merged. SP-B-1b: additive `occurrence_id` + the enveloped gateway-spool record +
gateway fsync + the collector outbox manifest. SP-B-2 (rewritten): the graph relations + roles/constraints
+ `append_ingested_record` + backfill SQL + VT move + the SHA->IPs query + tests (a)-(g). SP-B-3:
the artifact-ingress channel + CAS + three-stage custody, grounded in **fresh reads** of the SP-A
collector-wire/gateway/shipper/state/provision-certs code, not memory. SP-B-4: fetcher graph edges (basis)
+ VT CAS-walk. SP-B-5: console. SP-B-6: evidence commitment - the `evidence_commitment` epoch chain,
per-row digest binding, signer identity + key rotation, and the off-host anchor receipt (the dependent
contract in the cryptographic-coverage section). Each SP-B-2..6 plan is written only after this document
passes review.
