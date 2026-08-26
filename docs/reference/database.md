<!--
title: Database reference
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Database reference

Canonical owner of the PostgreSQL schema: tables, columns, enum types, migrations,
and the append-only ledger's hash chain. Signal semantics and the signal weight
table live in [events-and-signals.md](events-and-signals.md); scoring thresholds,
tiers, and eligibility live in [scoring-and-feed.md](scoring-and-feed.md).

Two crates own schema through two independent migration sets:

- **core-scoring** (`crates/core-scoring/migrations/*.sql`, 11 migrations) owns
  `event`, `ip_score`, `sample_analysis`, and all five enum types.
- **review** (`crates/review/migrations/*.sql`, 3 migrations) owns `review_queue`,
  `vendor_submission`, `fetch_attempt`.

review depends on `review_state_enum`, which is created by core-scoring migration
`0001` (a deliberate cross-crate schema dependency; the enum is defined in `0001` so
the shared schema is complete, `0001_enums.sql:26`).

## Enum types

Created by `0001_enums.sql` with `CREATE TYPE ... AS ENUM`. Each is mirrored by a
Rust `sqlx::Type` enum in `crates/core-scoring/src/domain/enums.rs`.

| Postgres type | Variants (wire/DB values) | Rust enum |
|---|---|---|
| `protocol_enum` | `tcp`, `udp`, `icmp` | `Protocol` (`enums.rs:16`) |
| `category_enum` | `honeypot`, `ids`, `network`, `waf`, `auth` | `Category` (`enums.rs:36`; derives `PartialOrd, Ord`) |
| `feed_tier_enum` | `aggressive`, `standard` | `FeedTier` (`enums.rs:48`) |
| `signal_type_enum` | 16 variants (see below) | `SignalType` (`enums.rs:65`) |
| `review_state_enum` | `pending`, `approved`, `rejected`, `snoozed` | `ReviewState` (`enums.rs:108`) |

`signal_type_enum` variants (`0001_enums.sql:7-24`): `honeypot_connection`,
`honeypot_login_attempt`, `honeypot_command_exec`, `honeypot_malware_upload`,
`honeypot_file_download`, `suricata_sev1`, `suricata_sev2`, `suricata_sev3`,
`port_scan`, `syn_flood`, `blocked_connection`, `waf_sqli_xss`, `waf_generic_block`,
`ssh_brute_force`, `catchall_probe`, `remote_auth_failure`. The Rust side pins the
count with `SignalType::ALL: [SignalType; 16]` (`enums.rs:84`), guarded by test
`signal_type_all_has_16_distinct_variants` (`enums.rs:123`). Per-signal meaning and
weight: [events-and-signals.md](events-and-signals.md).

### Serde casing asymmetry (hash-chain critical)

`SignalType`, `Protocol`, and `Category` carry `#[serde(rename_all(deserialize =
...))]` - a **Deserialize-only** rename (`enums.rs:5-15, 57-64`). Serialize
deliberately stays at the bare Rust identifier (`"CatchallProbe"`, `"Tcp"`), NOT the
snake_case/lowercase wire form. The reason is the frozen hash chain: `canonical_bytes`
hashes `serde_json::to_vec(&enum)` verbatim, so flipping Serialize casing would change
every chain hash. Deserialize accepts the snake_case/lowercase wire strings so intake
can parse sensor-wire records. Locked by tests
`signal_type_serialize_is_unchanged_bare_rust_identifier` (`enums.rs:174`) and
`protocol_serialize_is_unchanged_bare_rust_identifier` (`enums.rs:204`).

## Table: `event` (append-only ledger)

Base `0002_event.sql`; hardened by `0004`; `session_id` added by `0007`.

| column | type | constraint / default | source |
|---|---|---|---|
| `id` | BIGSERIAL | PRIMARY KEY | `0002:2` |
| `source_ip` | INET | NOT NULL | `0002:3` |
| `wan_ip` | INET | nullable (NULL = corroborating sensor with no bindable WAN IP) | `0002:4` |
| `sensor` | TEXT | NOT NULL; CHECK `sensor <> ''` | `0002:5`, `0004:14` |
| `signal_type` | signal_type_enum | NOT NULL | `0002:6` |
| `protocol` | protocol_enum | NOT NULL | `0002:7` |
| `authenticated` | BOOLEAN | NOT NULL | `0002:8` |
| `category` | category_enum | NOT NULL | `0002:9` |
| `weight` | INTEGER | NOT NULL; CHECK `>= 0` | `0002:10`, `0004:17` |
| `confidence` | NUMERIC(4,3) | NOT NULL; CHECK `BETWEEN 0 AND 1` | `0002:11`, `0004:16` |
| `observed_at` | TIMESTAMPTZ | NOT NULL | `0002:12` |
| `ingested_at` | TIMESTAMPTZ | NOT NULL DEFAULT `now()` | `0002:13` |
| `metadata` | JSONB | NOT NULL DEFAULT `'{}'` (sanitized at capture) | `0002:14` |
| `prev_hash` | BYTEA | nullable (NULL only for the first event) | `0002:15` |
| `hash` | BYTEA | NOT NULL; CHECK `octet_length(hash) = 32` (SHA-256) | `0002:16`, `0004:15` |
| `session_id` | UUID | nullable; correlates one sensor session | `0007:6` |

Indexes: `event_source_ip_idx (source_ip)` (`0002:19`), `event_observed_at_idx
(observed_at)` (`0002:20`), `event_session_idx (source_ip, session_id)` (`0007:7`).

The `metadata` column is documented "sanitized at capture" (`0002_event.sql:14`); the
sanitizer path itself lives outside the schema. The DB does **not** enforce the
`signal_type` -> `category` coupling; a mismatched `category` on a direct SQL INSERT
passes all CHECK constraints. That coupling is enforced application-side only, in
`EventInput::validate` (`types.rs:70-74`).

### Immutability hardening (`0004_harden_event_table.sql`)

Cleanup first DELETEs rogue rows (hash not 32 bytes, empty sensor, confidence outside
[0,1], negative weight), then adds the four CHECK constraints above (`0004:11-17`).
In the production database only - `current_database() = 'propolis'` AND the `propolis`
role exists - it runs `REVOKE UPDATE, DELETE, TRUNCATE ON event FROM propolis`
(`0004:22-27`). The `propolis` role keeps INSERT (intake needs it) but cannot mutate,
delete, or truncate the ledger. Test databases (name `test`, or missing role) skip the
REVOKE so the cleanup DELETEs above can still run.

### `session_id` (`0007_session_id.sql`)

Nullable UUID correlating one sensor session's events (e.g. one SSH connection's
logins, execs, and transfers). It is **not** part of the hash chain - `session_id` is
absent from `canonical_bytes`, so adding it did not alter any existing hash.
Pre-existing rows keep NULL and degrade gracefully (no grouping).

## Hash chain (`crates/core-scoring/src/hashing.rs`)

The canonical byte encoding is **FROZEN** (`hashing.rs:1-47`). Every previously
computed hash was computed against this exact layout; any change to field order,
framing, or a field's encoding would silently change all future hashes and break
verification of every persisted event. A shape change that must affect hashing is to
be introduced as a new, explicitly versioned encoding function, not an edit to this
one.

`canonical_bytes(&EventInput)` (`hashing.rs:72-123`) writes fields in fixed order.
Every variable-length field is length-prefixed with a **`u64` little-endian** length
(`push_len_prefixed`, `hashing.rs:62-65`) so no field can blur into the next and a
field at or beyond 4 GiB cannot wrap and collide.

| # | field | encoding |
|---|---|---|
| 1 | `source_ip` | `to_string()` bytes, len-prefixed (`:76`) |
| 2 | `wan_ip` | presence byte (`0`=None, `1`=Some), then if Some `to_string()` len-prefixed (`:79-85`) |
| 3 | `sensor` | UTF-8 bytes, len-prefixed (`:88`) |
| 4 | `signal_type` | `serde_json::to_vec` (quoted bare identifier, e.g. `"HoneypotCommandExec"`), len-prefixed (`:91-93`) |
| 5 | `protocol` | `serde_json::to_vec`, len-prefixed (`:96-98`) |
| 6 | `authenticated` | single byte `0`/`1`, no prefix (`:101`) |
| 7 | `category` | `serde_json::to_vec`, len-prefixed (`:104-106`) |
| 8 | `weight` | `u32` little-endian, 4 bytes, no prefix (`:109`) |
| 9 | `confidence` | `Decimal::to_string()` bytes, len-prefixed (`:112`) |
| 10 | `observed_at` | RFC 3339 string bytes, len-prefixed (`:115`) |
| 11 | `metadata` | `serde_json::to_vec(&metadata)` bytes, len-prefixed (`:118-120`) |

`serde_json` is built without the `preserve_order` feature, so JSON object keys
serialize sorted (deterministic) rather than insertion-ordered (`hashing.rs:40-43`).

**Not hashed** (absent from `canonical_bytes`): `id`, `ingested_at`, `session_id`,
`prev_hash`, and `hash` itself.

`chain_hash(prev, event)` = `SHA256( prev.unwrap_or(&[]) || canonical_bytes(event) )`
(`hashing.rs:131-136`). The first event uses `prev = None` (empty prefix). Each hash
binds the event's own content and the prior event's hash. A golden vector,
`golden_chain_hash_is_stable` (`hashing.rs`), pins the encoding to a fixed 32-byte
result for a known event.

**What it guarantees:** tamper-evidence of the append-only ledger. Any change to a
hashed field, or any reorder/insertion, breaks the linkage from that event forward,
because each hash is re-derivable only from the exact original bytes plus the prior
hash. It does **not** provide confidentiality, and it does **not** by itself prevent
deletion by a database superuser - append-only enforcement comes separately from the
`0004` REVOKE and the `0005` trigger below.

### Chain-linkage trigger (`0005_chain_enforcement_trigger.sql`)

`enforce_chain_linkage()` runs BEFORE INSERT FOR EACH ROW on `event` (`0005:33-36`).
It reads the current chain head (the `hash` of the row with max `id`, `0005:17`) and
enforces (`0005:19-27`):

- empty table: `NEW.prev_hash` must be NULL, else `RAISE EXCEPTION 'first event must
  have NULL prev_hash'`;
- otherwise: `NEW.prev_hash` must equal the head hash, else `RAISE EXCEPTION
  'prev_hash does not match chain head'`.

The hash itself is still computed application-side in Rust; the trigger enforces only
**linkage**, not hash correctness (`0005:6-10`). It is fail-closed: a fabricated or
missing `prev_hash` is rejected before the row lands.

## Table: `ip_score` (per-IP aggregate)

Base `0003_ip_score.sql`; extended by `0008`, `0010`, `0011`. PK `source_ip`. Rust
read model `IpScore` (`types.rs:89-119`). The formulas that produce these values are
owned by [scoring-and-feed.md](scoring-and-feed.md); this table is the persisted
result.

| column | type | default | source |
|---|---|---|---|
| `source_ip` | INET | PRIMARY KEY | `0003:2` |
| `raw_score` | NUMERIC | NOT NULL | `0003:3` |
| `decay_anchor` | TIMESTAMPTZ | NOT NULL | `0003:4` |
| `max_confidence` | NUMERIC | NOT NULL | `0003:5` |
| `event_count` | INTEGER | NOT NULL | `0003:6` |
| `distinct_categories` | INTEGER | NOT NULL | `0003:7` |
| `category_breakdown` | JSONB | NOT NULL DEFAULT `'{}'` | `0003:8` |
| `has_confirmed_real` | BOOLEAN | NOT NULL DEFAULT false | `0003:9` |
| `distinct_wan_count` | INTEGER | NOT NULL DEFAULT 0 | `0003:10` |
| `distinct_sensor_count` | INTEGER | NOT NULL DEFAULT 0 | `0003:11` |
| `first_seen` | TIMESTAMPTZ | NOT NULL | `0003:12` |
| `last_seen` | TIMESTAMPTZ | NOT NULL | `0003:13` |
| `eligible` | BOOLEAN | NOT NULL DEFAULT false | `0003:14` |
| `recommended_for_vendor` | BOOLEAN | NOT NULL DEFAULT false | `0003:15` |
| `recommended_for_blocklist` | BOOLEAN | NOT NULL DEFAULT false | `0003:16` |
| `tier` | feed_tier_enum | nullable | `0003:17` |
| `delisted` | BOOLEAN | NOT NULL DEFAULT false | `0008:1` |
| `active_days` | INTEGER | NOT NULL DEFAULT 1 | `0010:7` |
| `last_active_day` | DATE | nullable | `0010:8` |
| `established_event_count` | INTEGER | NOT NULL DEFAULT 0 | `0011:12` |

No indexes are defined beyond the `source_ip` PRIMARY KEY.

`has_confirmed_real` latches true only for an authenticated TCP honeypot event:
`is_confirmed_real(p, authenticated, c) = p==Tcp && authenticated && c==Honeypot`
(`enums.rs:115-117`).

`active_days` (`0010`): an unbounded, non-decaying count of distinct UTC calendar days
the IP was seen. It feeds a persistence bonus at the tier gate so a slow attacker that
the 6-hour decay would otherwise erase still earns a tier. `last_active_day` records
the last UTC day counted, telling the next event whether it opens a new day. The
migration backfills `active_days` from the distinct-UTC-date count in the `event`
ledger (`0010:17-25`); rows whose events were already pruned keep DEFAULT 1.

`established_event_count` (`0011`): counts only non-spoofable completed-TCP-connection
events. The by-volume recommendation gates on this instead of raw `event_count`, so a
spoofed UDP/ICMP flood cannot publish an innocent third party. Backfill = `count(*)
WHERE protocol='tcp'` per `source_ip` (`0011:14-22`); no-TCP rows keep 0.

`0006_relax_eligibility.sql` is a **data-only** backfill (no schema change). It relaxed
the eligibility gate from `(has_confirmed_real AND event_count>=2 AND
distinct_categories>=2)` to `(has_confirmed_real AND event_count>=2)`, then recomputed
`eligible`, `recommended_for_vendor = (tier IS NOT NULL)`, and
`recommended_for_blocklist` for newly qualifying rows (`0006:7-14`). It is the one
migration that embeds a scoring formula in SQL; `0010` explicitly refuses to duplicate
tier logic in SQL (`0010:14-16`). The authoritative formulas are in
[scoring-and-feed.md](scoring-and-feed.md).

## Table: `sample_analysis` (`0009_sample_analysis.sql`)

VirusTotal-style verdict per captured sample, keyed by SHA-256; links to a
[SampleRef](events-and-signals.md#sampleref). PK `sha256`.

| column | type | default |
|---|---|---|
| `sha256` | TEXT | PRIMARY KEY |
| `detected` | INTEGER | NOT NULL |
| `total` | INTEGER | NOT NULL |
| `vt_link` | TEXT | NOT NULL DEFAULT `''` |
| `source_sensor` | TEXT | NOT NULL DEFAULT `''` |
| `analyzed_at` | TIMESTAMPTZ | NOT NULL DEFAULT `now()` |

`detected` / `total` are the engine-hit counts.

## review crate tables

### `review_queue` (`review/migrations/0001_review_queue.sql`)

PK `source_ip INET`. Snapshots the score and categories at surface time.

| column | type | default |
|---|---|---|
| `source_ip` | INET | PRIMARY KEY |
| `state` | review_state_enum | NOT NULL DEFAULT `'pending'` |
| `score_at_surface` | NUMERIC(10,3) | NOT NULL |
| `categories_at_surface` | JSONB | NOT NULL |
| `surfaced_at` | TIMESTAMPTZ | NOT NULL DEFAULT `now()` |
| `decided_at` | TIMESTAMPTZ | nullable |
| `notes` | TEXT | nullable |

### `vendor_submission` (`0002_vendor_submission.sql`)

PK `id BIGSERIAL`. The `UNIQUE idempotency_key` dedupes retries.

| column | type | default |
|---|---|---|
| `id` | BIGSERIAL | PRIMARY KEY |
| `source_ip` | INET | NOT NULL |
| `vendor` | TEXT | NOT NULL |
| `idempotency_key` | TEXT | NOT NULL UNIQUE |
| `categories` | TEXT[] | NOT NULL |
| `comment` | TEXT | NOT NULL |
| `submitted_at` | TIMESTAMPTZ | NOT NULL DEFAULT `now()` |
| `response_status` | INTEGER | nullable |
| `response_body` | TEXT | nullable |
| `success` | BOOLEAN | NOT NULL DEFAULT FALSE |

Index: `idx_vendor_submission_ip_vendor (source_ip, vendor, submitted_at DESC)`.

### `fetch_attempt` (`0003_fetch_attempt.sql`)

PK `url_hash BYTEA` = `sha256(normalized url)`. Records attempts to fetch attacker-cited
payload URLs.

| column | type | notes |
|---|---|---|
| `url_hash` | BYTEA | PRIMARY KEY = sha256(normalized url) |
| `url` | TEXT | NOT NULL |
| `host` | TEXT | NOT NULL |
| `scheme` | TEXT | NOT NULL |
| `pinned_ip` | TEXT | IP actually dialed (IOC) |
| `port` | INTEGER | |
| `source_ip` | INET | attacker src from the event |
| `parent_hash` | BYTEA | NULL, or the script this URL was extracted from (recursion) |
| `depth` | INTEGER | NOT NULL DEFAULT 0 |
| `status` | TEXT | NOT NULL; free TEXT, not an enum (see below) |
| `reject_reason` | TEXT | guard reason when `status='rejected'` |
| `sha256` | BYTEA | NULL unless the body was captured |
| `bytes` | INTEGER | |
| `content_type` | TEXT | server-declared; recorded, never trusted |
| `attempts` | INTEGER | NOT NULL DEFAULT 0 |
| `next_attempt` | TIMESTAMPTZ | backoff schedule |
| `first_seen` | TIMESTAMPTZ | NOT NULL DEFAULT `now()` |
| `last_attempt` | TIMESTAMPTZ | NOT NULL |

Indexes: `(host, last_attempt)`, `(status, next_attempt)`.

`status` is a free TEXT column, **not** an enum or CHECK. The documented value set -
`pending`, `success`, `dead`, `rejected`, `too_big`, `timeout`, `empty` - lives only
in a SQL comment (`0003:11`); the actual values written are set by review-crate code.

## Migration change map

**core-scoring** (`crates/core-scoring/migrations/`):

| migration | adds |
|---|---|
| `0001` | all 5 enum types (protocol / category / feed_tier / signal_type / review_state) |
| `0002` | `event` table + `source_ip` and `observed_at` indexes |
| `0003` | `ip_score` table |
| `0004` | hardens `event`: DELETE rogue rows, add 4 CHECK constraints, REVOKE UPDATE/DELETE/TRUNCATE from `propolis` role (prod only) |
| `0005` | `enforce_chain_linkage()` BEFORE INSERT trigger on `event` |
| `0006` | data backfill after relaxing the eligibility gate (drops `distinct_categories>=2`); recomputes flags |
| `0007` | `event.session_id UUID` + index `(source_ip, session_id)` |
| `0008` | `ip_score.delisted BOOLEAN DEFAULT false` |
| `0009` | `sample_analysis` table |
| `0010` | `ip_score.active_days INTEGER DEFAULT 1` + `last_active_day DATE`; backfills day counts |
| `0011` | `ip_score.established_event_count INTEGER DEFAULT 0`; backfills TCP-only counts |

**review** (`crates/review/migrations/`):

| migration | adds |
|---|---|
| `0001` | `review_queue` (uses core-scoring's `review_state_enum`) |
| `0002` | `vendor_submission` + index |
| `0003` | `fetch_attempt` + 2 indexes |

Migration workflow and conventions: [../development/schema-and-migrations.md](../development/schema-and-migrations.md).
