<!--
title: Database reference
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Database reference

Canonical owner of the PostgreSQL schema: tables, columns, enum types, migrations,
and the append-only ledger's hash chain. Signal semantics and the signal weight
table live in [events-and-signals.md](events-and-signals.md); scoring thresholds,
tiers, and eligibility live in [scoring-and-feed.md](scoring-and-feed.md).

Three crates own schema through three independent migration sets:

- **core-scoring** (`crates/core-scoring/migrations/*.sql`) owns `event`, `ip_score`,
  `ip_vantage`, `ip_sensor`, `sample_analysis`, the campaign and indicator tables, and all five
  enum types.
- **review** (`crates/review/migrations/*.sql`) owns `review_queue`,
  `vendor_submission`, `fetch_attempt`, `fetch_daily_usage`.
- **fleet** (`crates/fleet/migrations/*.sql`) owns `listener_probe` and `sensor_stats`.

The change maps at the end of this page list every migration in each set.

review depends on `review_state_enum`, which is created by core-scoring migration
`0001` (a deliberate cross-crate schema dependency; the enum is defined in `0001` so
the shared schema is complete, `crates/core-scoring/migrations/0001_enums.sql#review_state_enum`).

## Enum types

Created by `0001_enums.sql` with `CREATE TYPE ... AS ENUM`. Each is mirrored by a
Rust `sqlx::Type` enum in `crates/core-scoring/src/domain/enums.rs`.

| Postgres type | Variants (wire/DB values) | Rust enum |
|---|---|---|
| `protocol_enum` | `tcp`, `udp`, `icmp` | `Protocol` (`crates/core-scoring/src/domain/enums.rs#Protocol`) |
| `category_enum` | `honeypot`, `ids`, `network`, `waf`, `auth` | `Category` (`crates/core-scoring/src/domain/enums.rs#Category`; derives `PartialOrd, Ord`) |
| `feed_tier_enum` | `aggressive`, `standard` | `FeedTier` (`crates/core-scoring/src/domain/enums.rs#FeedTier`) |
| `signal_type_enum` | 17 variants (see below) | `SignalType` (`crates/core-scoring/src/domain/enums.rs#SignalType`) |
| `review_state_enum` | `pending`, `approved`, `rejected`, `snoozed` | `ReviewState` (`crates/core-scoring/src/domain/enums.rs#ReviewState`) |

`signal_type_enum` variants (`crates/core-scoring/migrations/0001_enums.sql#signal_type_enum`, `crates/core-scoring/migrations/0012_session_end_signal.sql#honeypot_session_end`):
`honeypot_connection`, `honeypot_login_attempt`, `honeypot_command_exec`,
`honeypot_malware_upload`, `honeypot_file_download`, `suricata_sev1`,
`suricata_sev2`, `suricata_sev3`, `port_scan`, `syn_flood`, `blocked_connection`,
`waf_sqli_xss`, `waf_generic_block`, `ssh_brute_force`, `catchall_probe`,
`remote_auth_failure`, `honeypot_session_end` (telemetry only, never scored - see
`SignalType::TELEMETRY`). The Rust side pins the count with
`SignalType::ALL: [SignalType; 17]` (`crates/core-scoring/src/domain/enums.rs#ALL`), guarded by test
`crates/core-scoring/src/domain/enums.rs#signal_type_all_has_17_distinct_variants`. Per-signal meaning and
weight: [events-and-signals.md](events-and-signals.md).

### Serde casing asymmetry (hash-chain critical)

`SignalType` and `Protocol` carry `#[serde(rename_all(deserialize =
...))]` - a **Deserialize-only** rename (`crates/core-scoring/src/domain/enums.rs#Protocol`, `crates/core-scoring/src/domain/enums.rs#SignalType`); `Category` carries
no such override. Serialize
deliberately stays at the bare Rust identifier (`"CatchallProbe"`, `"Tcp"`), NOT the
snake_case/lowercase wire form. The reason is the frozen hash chain: `canonical_bytes`
hashes `serde_json::to_vec(&enum)` verbatim, so flipping Serialize casing would change
every chain hash. Deserialize accepts the snake_case/lowercase wire strings so intake
can parse sensor-wire records. Locked by tests
`crates/core-scoring/src/domain/enums.rs#signal_type_serialize_is_unchanged_bare_rust_identifier` and
`crates/core-scoring/src/domain/enums.rs#protocol_serialize_is_unchanged_bare_rust_identifier`.

## Table: `event` (append-only ledger)

Base `0002_event.sql`; hardened by `0004`; `session_id` added by `0007`.

| column | type | constraint / default | source |
|---|---|---|---|
| `id` | BIGSERIAL | PRIMARY KEY | `crates/core-scoring/migrations/0002_event.sql#id` |
| `source_ip` | INET | NOT NULL | `crates/core-scoring/migrations/0002_event.sql#source_ip` |
| `wan_ip` | INET | nullable (NULL = corroborating sensor with no bindable WAN IP) | `crates/core-scoring/migrations/0002_event.sql#wan_ip` |
| `sensor` | TEXT | NOT NULL; CHECK `sensor <> ''` | `crates/core-scoring/migrations/0002_event.sql#sensor`, `crates/core-scoring/migrations/0004_harden_event_table.sql#event_sensor_nonempty` |
| `signal_type` | signal_type_enum | NOT NULL | `crates/core-scoring/migrations/0002_event.sql#signal_type` |
| `protocol` | protocol_enum | NOT NULL | `crates/core-scoring/migrations/0002_event.sql#protocol` |
| `authenticated` | BOOLEAN | NOT NULL | `crates/core-scoring/migrations/0002_event.sql#authenticated` |
| `category` | category_enum | NOT NULL | `crates/core-scoring/migrations/0002_event.sql#category` |
| `weight` | INTEGER | NOT NULL; CHECK `>= 0` | `crates/core-scoring/migrations/0002_event.sql#weight`, `crates/core-scoring/migrations/0004_harden_event_table.sql#event_weight_nonnegative` |
| `confidence` | NUMERIC(4,3) | NOT NULL; CHECK `BETWEEN 0 AND 1` | `crates/core-scoring/migrations/0002_event.sql#confidence`, `crates/core-scoring/migrations/0004_harden_event_table.sql#event_confidence_range` |
| `observed_at` | TIMESTAMPTZ | NOT NULL | `crates/core-scoring/migrations/0002_event.sql#observed_at` |
| `ingested_at` | TIMESTAMPTZ | NOT NULL DEFAULT `now()` | `crates/core-scoring/migrations/0002_event.sql#ingested_at` |
| `metadata` | JSONB | NOT NULL DEFAULT `'{}'` (sanitized at capture) | `crates/core-scoring/migrations/0002_event.sql#metadata` |
| `prev_hash` | BYTEA | nullable (NULL only for the first event) | `crates/core-scoring/migrations/0002_event.sql#prev_hash` |
| `hash` | BYTEA | NOT NULL; CHECK `octet_length(hash) = 32` (SHA-256) | `crates/core-scoring/migrations/0002_event.sql#hash`, `crates/core-scoring/migrations/0004_harden_event_table.sql#event_hash_length` |
| `session_id` | UUID | nullable; correlates one sensor session | `crates/core-scoring/migrations/0007_session_id.sql#session_id` |

Indexes: `event_source_ip_idx (source_ip)` (`crates/core-scoring/migrations/0002_event.sql#event_source_ip_idx`), `event_observed_at_idx
(observed_at)` (`crates/core-scoring/migrations/0002_event.sql#event_observed_at_idx`), `event_session_idx (source_ip, session_id)` (`crates/core-scoring/migrations/0007_session_id.sql#event_session_idx`), `event_dedup_idx (source_ip, signal_type, observed_at)` (`crates/core-scoring/migrations/0013_event_dedup_index.sql#event_dedup_idx`).

`event_dedup_idx` serves the dedup read every scored append makes inside the append lock
(`crates/core-scoring/src/repository/events.rs#DEDUP_PRIOR_SQL`). That statement hides the
source address from the planner, so a bot loop that holds a large share of the ledger is costed
as an average source and read through this index, rather than by walking
`event_observed_at_idx` down from the newest row. The walk costs one row per event newer than
the source's last sighting, which grows while intake is behind. The plan is held by
`crates/core-scoring/src/repository/events.rs#dedup_read_plan_uses_the_dedup_index_on_an_incident_shaped_ledger`
and `crates/core-scoring/src/repository/events.rs#dedup_read_plan_generic_form_uses_the_dedup_index`.

The `metadata` column is documented "sanitized at capture" (`crates/core-scoring/migrations/0002_event.sql#metadata`); the
sanitizer path itself lives outside the schema. The DB does **not** enforce the
`signal_type` -> `category` coupling; a mismatched `category` on a direct SQL INSERT
passes all CHECK constraints. That coupling is enforced application-side only, in
`EventInput::validate` (`crates/core-scoring/src/domain/types.rs#validate`).

### Immutability hardening (`0004_harden_event_table.sql`)

Cleanup first DELETEs rogue rows (hash not 32 bytes, empty sensor, confidence outside
[0,1], negative weight), then adds the four CHECK constraints above
(`crates/core-scoring/migrations/0004_harden_event_table.sql#DELETE FROM event WHERE`,
`crates/core-scoring/migrations/0004_harden_event_table.sql#ALTER TABLE event`).
In the production database only - `current_database() = 'propolis'` AND the `propolis`
role exists - it runs `REVOKE UPDATE, DELETE, TRUNCATE ON event FROM propolis`
(`crates/core-scoring/migrations/0004_harden_event_table.sql#REVOKE UPDATE, DELETE, TRUNCATE ON event FROM propolis`). The `propolis` role keeps INSERT (intake needs it) but cannot mutate,
delete, or truncate the ledger. Test databases (name `test`, or missing role) skip the
REVOKE so the cleanup DELETEs above can still run.

### `session_id` (`0007_session_id.sql`)

Nullable UUID correlating one sensor session's events (e.g. one SSH connection's
logins, execs, and transfers). It is **not** part of the hash chain - `session_id` is
absent from `canonical_bytes`, so adding it did not alter any existing hash.
Pre-existing rows keep NULL and degrade gracefully (no grouping).

## Hash chain (`crates/core-scoring/src/hashing.rs`)

The canonical byte encoding is **FROZEN** (`crates/core-scoring/src/hashing.rs`). Every previously
computed hash was computed against this exact layout; any change to field order,
framing, or a field's encoding would silently change all future hashes and break
verification of every persisted event. A shape change that must affect hashing is to
be introduced as a new, explicitly versioned encoding function, not an edit to this
one.

`canonical_bytes(&EventInput)` (`crates/core-scoring/src/hashing.rs#canonical_bytes`) writes fields in fixed order.
Every variable-length field is length-prefixed with a **`u64` little-endian** length
(`crates/core-scoring/src/hashing.rs#push_len_prefixed`) so no field can blur into the next and a
field at or beyond 4 GiB cannot wrap and collide.

| # | field | encoding |
|---|---|---|
| 1 | `source_ip` | `to_string()` bytes, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 2 | `wan_ip` | presence byte (`0`=None, `1`=Some), then if Some `to_string()` len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 3 | `sensor` | UTF-8 bytes, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 4 | `signal_type` | `serde_json::to_vec` (quoted bare identifier, e.g. `"HoneypotCommandExec"`), len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 5 | `protocol` | `serde_json::to_vec`, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 6 | `authenticated` | single byte `0`/`1`, no prefix (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 7 | `category` | `serde_json::to_vec`, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 8 | `weight` | `u32` little-endian, 4 bytes, no prefix (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 9 | `confidence` | `Decimal::to_string()` bytes, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 10 | `observed_at` | RFC 3339 string bytes, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |
| 11 | `metadata` | `serde_json::to_vec(&metadata)` bytes, len-prefixed (`crates/core-scoring/src/hashing.rs#canonical_bytes`) |

`serde_json` is built without the `preserve_order` feature, so JSON object keys
serialize sorted (deterministic) rather than insertion-ordered (`crates/core-scoring/src/hashing.rs`).

**Not hashed** (absent from `canonical_bytes`): `id`, `ingested_at`, `session_id`,
`prev_hash`, and `hash` itself.

`chain_hash(prev, event)` = `SHA256( prev.unwrap_or(&[]) || canonical_bytes(event) )`
(`crates/core-scoring/src/hashing.rs#chain_hash`). The first event uses `prev = None` (empty prefix). Each hash
binds the event's own content and the prior event's hash. A golden vector,
`golden_chain_hash_is_stable` (`crates/core-scoring/src/hashing.rs#golden_chain_hash_is_stable`), pins the encoding to a fixed 32-byte
result for a known event.

**What it guarantees:** tamper-evidence of the append-only ledger. Any change to a
hashed field, or any reorder/insertion, breaks the linkage from that event forward,
because each hash is re-derivable only from the exact original bytes plus the prior
hash. It does **not** provide confidentiality, and it does **not** by itself prevent
deletion by a database superuser - append-only enforcement comes separately from the
`0004` REVOKE and the `0005` trigger below.

### Chain-linkage trigger (`0005_chain_enforcement_trigger.sql`)

`enforce_chain_linkage()` runs BEFORE INSERT FOR EACH ROW on `event`
(`crates/core-scoring/migrations/0005_chain_enforcement_trigger.sql#trg_enforce_chain_linkage`).
It reads the current chain head (the `hash` of the row with max `id`,
`crates/core-scoring/migrations/0005_chain_enforcement_trigger.sql#SELECT hash INTO head_hash`) and
enforces (`crates/core-scoring/migrations/0005_chain_enforcement_trigger.sql#enforce_chain_linkage`):

- empty table: `NEW.prev_hash` must be NULL, else `RAISE EXCEPTION 'first event must
  have NULL prev_hash'`;
- otherwise: `NEW.prev_hash` must equal the head hash, else `RAISE EXCEPTION
  'prev_hash does not match chain head'`.

The hash itself is still computed application-side in Rust; the trigger enforces only
**linkage**, not hash correctness (`crates/core-scoring/migrations/0005_chain_enforcement_trigger.sql`). It is fail-closed: a fabricated or
missing `prev_hash` is rejected before the row lands.

## Table: `ip_score` (per-IP aggregate)

Base `0003_ip_score.sql`; extended by `0008`, `0010`, `0011`. PK `source_ip`. Rust
read model `IpScore` (`crates/core-scoring/src/domain/types.rs#IpScore`). The formulas that produce these values are
owned by [scoring-and-feed.md](scoring-and-feed.md); this table is the persisted
result.

| column | type | default | source |
|---|---|---|---|
| `source_ip` | INET | PRIMARY KEY | `crates/core-scoring/migrations/0003_ip_score.sql#source_ip` |
| `raw_score` | NUMERIC | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#raw_score` |
| `decay_anchor` | TIMESTAMPTZ | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#decay_anchor` |
| `max_confidence` | NUMERIC | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#max_confidence` |
| `event_count` | INTEGER | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#event_count` |
| `distinct_categories` | INTEGER | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#distinct_categories` |
| `category_breakdown` | JSONB | NOT NULL DEFAULT `'{}'` | `crates/core-scoring/migrations/0003_ip_score.sql#category_breakdown` |
| `has_confirmed_real` | BOOLEAN | NOT NULL DEFAULT false | `crates/core-scoring/migrations/0003_ip_score.sql#has_confirmed_real` |
| `distinct_wan_count` | INTEGER | NOT NULL DEFAULT 0 | `crates/core-scoring/migrations/0003_ip_score.sql#distinct_wan_count` |
| `distinct_sensor_count` | INTEGER | NOT NULL DEFAULT 0 | `crates/core-scoring/migrations/0003_ip_score.sql#distinct_sensor_count` |
| `first_seen` | TIMESTAMPTZ | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#first_seen` |
| `last_seen` | TIMESTAMPTZ | NOT NULL | `crates/core-scoring/migrations/0003_ip_score.sql#last_seen` |
| `eligible` | BOOLEAN | NOT NULL DEFAULT false | `crates/core-scoring/migrations/0003_ip_score.sql#eligible` |
| `recommended_for_vendor` | BOOLEAN | NOT NULL DEFAULT false | `crates/core-scoring/migrations/0003_ip_score.sql#recommended_for_vendor` |
| `recommended_for_blocklist` | BOOLEAN | NOT NULL DEFAULT false | `crates/core-scoring/migrations/0003_ip_score.sql#recommended_for_blocklist` |
| `tier` | feed_tier_enum | nullable | `crates/core-scoring/migrations/0003_ip_score.sql#tier` |
| `delisted` | BOOLEAN | NOT NULL DEFAULT false | `crates/core-scoring/migrations/0008_delisted.sql#delisted` |
| `active_days` | INTEGER | NOT NULL DEFAULT 1 | `crates/core-scoring/migrations/0010_active_days.sql#active_days` |
| `last_active_day` | DATE | nullable | `crates/core-scoring/migrations/0010_active_days.sql#last_active_day` |
| `established_event_count` | INTEGER | NOT NULL DEFAULT 0 | `crates/core-scoring/migrations/0011_established_event_count.sql#established_event_count` |

No indexes are defined beyond the `source_ip` PRIMARY KEY.

`has_confirmed_real` latches true only for an authenticated TCP honeypot event:
`is_confirmed_real(p, authenticated, c) = p==Tcp && authenticated && c==Honeypot`
(`crates/core-scoring/src/domain/enums.rs#is_confirmed_real`).

`active_days` (`0010`): an unbounded, non-decaying count of distinct UTC calendar days
the IP was seen. It feeds a persistence bonus at the tier gate so a slow attacker that
the 6-hour decay would otherwise erase still earns a tier. `last_active_day` records
the last UTC day counted, telling the next event whether it opens a new day. The
migration backfills `active_days` from the distinct-UTC-date count in the `event`
ledger (`crates/core-scoring/migrations/0010_active_days.sql#UPDATE ip_score s SET`); rows whose events were already pruned keep DEFAULT 1.

`established_event_count` (`0011`): counts only non-spoofable completed-TCP-connection
events. The by-volume recommendation gates on this instead of raw `event_count`, so a
spoofed UDP/ICMP flood cannot publish an innocent third party. Backfill = `count(*)
WHERE protocol='tcp'` per `source_ip` (`crates/core-scoring/migrations/0011_established_event_count.sql#WHERE protocol = 'tcp'`); no-TCP rows keep 0.

`0006_relax_eligibility.sql` is a **data-only** backfill (no schema change). It relaxed
the eligibility gate from `(has_confirmed_real AND event_count>=2 AND
distinct_categories>=2)` to `(has_confirmed_real AND event_count>=2)`, then recomputed
`eligible`, `recommended_for_vendor = (tier IS NOT NULL)`, and
`recommended_for_blocklist` for newly qualifying rows
(`crates/core-scoring/migrations/0006_relax_eligibility.sql#UPDATE ip_score SET`). It is the one
migration that embeds a scoring formula in SQL; `0010` explicitly refuses to duplicate
tier logic in SQL (`crates/core-scoring/migrations/0010_active_days.sql#it does not re-derive the tier/recommendation flags in SQL`). The authoritative formulas are in
[scoring-and-feed.md](scoring-and-feed.md).

<a id="breadth-sets"></a>
## Tables: `ip_vantage` and `ip_sensor` (breadth sets, `0014_breadth_sets.sql`)

The two per-source sets `distinct_wan_count` and `distinct_sensor_count` are counted from.
Like `ip_score` they are projections of the ledger: no foreign key ties them to `ip_score`, and
the console's `delete_ip`, which removes a score row but keeps the ledger, leaves them in place,
so a later event from that address still counts its whole history.

| table | column | type | constraint | source |
|---|---|---|---|---|
| `ip_vantage` | `source_ip` | INET | NOT NULL; PK with `wan_ip` | `crates/core-scoring/migrations/0014_breadth_sets.sql#ip_vantage` |
| `ip_vantage` | `wan_ip` | INET | NOT NULL | `crates/core-scoring/migrations/0014_breadth_sets.sql#wan_ip` |
| `ip_vantage` | `saw_authenticated_tcp` | BOOLEAN | NOT NULL | `crates/core-scoring/migrations/0014_breadth_sets.sql#saw_authenticated_tcp` |
| `ip_sensor` | `source_ip` | INET | NOT NULL; PK with `sensor` | `crates/core-scoring/migrations/0014_breadth_sets.sql#ip_sensor` |
| `ip_sensor` | `sensor` | TEXT | NOT NULL | `crates/core-scoring/migrations/0014_breadth_sets.sql#sensor` |

`ip_vantage` has one row per source and non-null WAN address the source was seen on, and
`saw_authenticated_tcp` is true once any scored event on that WAN was authenticated TCP.
`ip_sensor` has one row per source and sensor. Each scored append folds its event into both
inside the append lock and reads them back by primary key
(`crates/core-scoring/src/repository/events.rs#fold_breadth_sets`); `distinct_wan_count`
applies the breadth rule (authenticated vantages only, one per /24 or /64) to the vantage rows,
and `distinct_sensor_count` is the sensor row count. Telemetry never writes either table:
`append_telemetry_event` does not touch them.

The migration creates both tables and fills them from the ledger with a `GROUP BY` over every
scored row (telemetry excluded), holding `SHARE` on `event` so no append slips between the read
and the commit ([schema-and-migrations](../development/schema-and-migrations.md#index-builds)).

The tables summarize the ledger as the append path wrote it. A row that reaches `event` any
other way, or a pruning job that deletes events (see [retention](../operations/retention.md#event-and-score-retention)),
leaves them out of step with it. To rebuild them from the ledger, empty both and run the
migration's two `INSERT ... SELECT` statements again with the daemon stopped.
`rebuild_projection` does not read them: it counts from the ledger rows, so a replay is an
independent check (`crates/core-scoring/src/repository/breadth_sets_tests.rs#breadth_sets_match_the_whole_history_aggregates_after_every_append`).

<a id="campaign-tables"></a>
## Campaign and indicator tables (`0015_campaigns.sql`, `0016_campaign_fingerprint.sql`)

Derived from the ledger by the campaign indexer, a bounded background job, never by the append
path; [campaigns](../operations/campaigns.md) explains the grouping rules. Like `ip_score` they
can be rebuilt: empty them, set `campaign_cursor.last_event_id` to 0, and the indexer works
through the ledger again. Migration 0016 adds `campaign_cursor.fingerprint_version` (existing
rows are version 1) and `rebuild_until`, with which the indexer rebuilds only the
command-sequence state when the fingerprint changes
(`crates/core-scoring/migrations/0016_campaign_fingerprint.sql#fingerprint_version`),
`campaign.min_shapes` and `max_shapes`, the fewest and most commands a command-sequence
campaign's runs held (`crates/core-scoring/migrations/0016_campaign_fingerprint.sql#min_shapes`),
and `campaign_session.payload`, the shapes folded into a run's key
(`crates/core-scoring/migrations/0016_campaign_fingerprint.sql#payload`).

| table | holds | key | source |
|---|---|---|---|
| `campaign_cursor` | the last event id indexed | single row | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_cursor` |
| `campaign` | one row per campaign: `kind` (`sample`, `command_sequence`, `scanner`), `key`, `label`, `representative` (JSONB), `rep_event_id`, `first_seen`, `last_seen`, `member_count`, `sightings`, `self_propagating` | `id`; UNIQUE `(kind, key)` | `crates/core-scoring/migrations/0015_campaigns.sql#CREATE TABLE campaign (` |
| `campaign_member` | one row per campaign and source address: first and last seen, sightings, `uploaded` | `(campaign_id, source_ip)`; index on `source_ip` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_member` |
| `campaign_member_day` | the UTC days each member was seen | `(campaign_id, day, source_ip)` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_member_day` |
| `campaign_sensor` | sightings per sensor | `(campaign_id, sensor)` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_sensor` |
| `campaign_sample` | samples linked to a campaign | `(campaign_id, sha256)`; index on `sha256` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_sample` |
| `campaign_session` | indexer state: one shell session's current run (running digest, shape count, campaign once grouped) | `session_id` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_session` |
| `campaign_watermark` | indexer state: newest `observed_at` read per sensor | `sensor` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_watermark` |
| `campaign_scan_window` | indexer state: distinct sensors per source per window | `(source_ip, window_start)` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_scan_window` |
| `campaign_pending_fetch` | downloads waiting for a fetch outcome | `(url_hash, source_ip)` | `crates/core-scoring/migrations/0015_campaigns.sql#campaign_pending_fetch` |
| `ioc` | indicators: `kind`, `value`, `detail`, and either `artifact_sha256` or `event_id` with `source_ip` | `id`; partial UNIQUE `(artifact_sha256, kind, value)` and `(source_ip, kind, value)` | `crates/core-scoring/migrations/0015_campaigns.sql#ioc_artifact_uq` |
| `ioc_artifact_scan` | captured artifacts queued for indicator extraction, and the outcome | `sha256` | `crates/core-scoring/migrations/0015_campaigns.sql#ioc_artifact_scan` |

`ioc.kind` is one of `url`, `endpoint`, `ssh_key`, `rsa_key`, `password_hash`, `irc_server`,
`irc_channel`, `hosts_entry`, `persistence`, `proxy` and `credentials`. `ioc.value` is at most
256 characters and `ioc.detail` 128, both sanitized and stripped of URL user information and
`Authorization` values before they are written. A password hash is stored only as a marker
(`sha512-crypt sha256:<16 hex>`), never the crypt string (`crates/review/src/ioc.rs#password_hashes`),
and a `credentials` row names only how a credential was carried, never its value. The working-state tables are pruned two
days behind their sensor's clock (`crates/review/src/campaign/mod.rs#prune`).

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
| `claim_expires` | TIMESTAMPTZ | NULL = unclaimed; set when a fetch cycle claims the row, cleared when its outcome is recorded (`0006`) |
| `transport_auth` | TEXT | NOT NULL DEFAULT `'unknown'`; CHECK in `verified`, `unverified`, `plaintext`, `unknown`: how the captured body's transport was authenticated over every hop, `unknown` when no body was captured or the row predates `0007` ([meanings](../security/malware-custody.md#transport-authentication-of-fetched-samples)) |
| `tls_verify_error` | TEXT | the first certificate-validation error; CHECK: non-NULL exactly when `transport_auth = 'unverified'` (`0007`) |

Indexes: `(host, last_attempt)`, `(status, next_attempt)`, `(first_seen DESC)` (`0005`),
and a partial `(host, claim_expires) WHERE claim_expires IS NOT NULL` (`0006`).

### `fetch_daily_usage` (`0006_fetch_coordination.sql`)

One row per UTC day: `day DATE` PRIMARY KEY, `used INTEGER NOT NULL DEFAULT 0 CHECK
(used >= 0)`. The fetcher's daily cap is charged here when rows are claimed, shared by
every node on the database. See
[rate limits and budgets](rate-limits-and-budgets.md#per-cycle-and-per-host).

`status` is a free TEXT column, **not** an enum or CHECK. The documented value set -
`pending`, `success`, `dead`, `rejected`, `too_big`, `timeout`, `empty` - lives only
in a SQL comment (`crates/review/migrations/0003_fetch_attempt.sql#pending|success|dead|rejected|too_big|timeout|empty`); the actual values written are set by review-crate code.
`transport_auth` is the exception on this table: its value set, and its pairing with
`tls_verify_error`, are enforced by CHECK constraints (`0007`).

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
| `0012` | `signal_type_enum` value `honeypot_session_end` (unscored interaction telemetry) |
| `0013` | index `event_dedup_idx (source_ip, signal_type, observed_at)` for the append path's dedup read; built inside the migration transaction, so writes to `event` wait for the build ([schema-and-migrations](../development/schema-and-migrations.md#index-builds)) |
| `0014` | tables `ip_vantage (source_ip, wan_ip, saw_authenticated_tcp)` and `ip_sensor (source_ip, sensor)`, the [breadth sets](#breadth-sets) the append path counts from; backfilled from the ledger under a `SHARE` lock on `event` |
| `0015` | the [campaign and indicator tables](#campaign-tables) and the indexer's cursor (starting at 0, no backfill: the indexer reads the ledger in batches after startup) |
| `0016` | `campaign_cursor.fingerprint_version` and `rebuild_until`, `campaign.min_shapes` and `max_shapes`, `campaign_session.payload` (see [campaign tables](#campaign-tables)); no data is rewritten, the indexer rebuilds the command-sequence campaigns itself on its next batch |

**review** (`crates/review/migrations/`):

| migration | adds |
|---|---|
| `0001` | `review_queue` (uses core-scoring's `review_state_enum`) |
| `0002` | `vendor_submission` + index |
| `0003` | `fetch_attempt` + 2 indexes |
| `0004` | data backfill of `fetch_attempt.source_ip` (NULL before the `host()` read fix) |
| `0005` | `fetch_attempt (first_seen DESC)` index for newest-first selection |
| `0006` | `fetch_attempt.claim_expires` + partial index; `fetch_daily_usage` table |
| `0007` | `fetch_attempt.transport_auth` (existing rows `'unknown'`) + `tls_verify_error`, with their CHECK constraints |

**fleet** (`crates/fleet/migrations/`, tracked in `_sqlx_migrations_fleet`):

| migration | adds |
|---|---|
| `0001` | `listener_probe` + `(sensor, attempted_at DESC)` index |
| `0002` | `sensor_stats`: the latest `sensor_stats` line per sensor (capture counters and budget), outside the ledger |

Migration workflow and conventions: [../development/schema-and-migrations.md](../development/schema-and-migrations.md).
