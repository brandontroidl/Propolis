<!--
title: Schema and migrations
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Schema and migrations

This page covers the migration workflow, the additive-change rule, the frozen wire
contract, and the vendoring rebuild step. The exact tables, columns, enums, and the
migration → change map are owned by [`reference/database`](../reference/database.md).

## Two migration histories, one database

Migration SQL lives in **two crates**, applied against **one** physical database:

- `crates/core-scoring/migrations/` - 11 files, `0001_enums.sql` …
  `0011_established_event_count.sql`. Owns `event`, `ip_score`, `sample_analysis`,
  and all five enum types.
- `crates/review/migrations/` - 3 files: `0001_review_queue.sql`,
  `0002_vendor_submission.sql`, `0003_fetch_attempt.sql`.

Both histories number from `0001`. sqlx's default `_sqlx_migrations` bookkeeping
table is keyed by version only (no namespacing), so sharing it would raise
`VersionMissing` / `VersionMismatch`. The review crate works around this with its own
`migrator()` that renames the bookkeeping table to `_sqlx_migrations_review` via
`dangerous_set_table_name` (`crates/review/src/lib.rs:25-49`). `review` also has a
cross-crate schema dependency: it uses `review_state_enum`, which is created by
core-scoring migration `0001` (`0001_enums.sql:26`).

At runtime the daemon applies core-scoring migrations first, then `review::migrator()`,
each `exit(1)` on failure (`crates/propolis/src/main.rs:555-566`).

In tests, migrations are applied one of two ways
([build-and-test](build-and-test.md#test-styles-by-layer)):
`#[sqlx::test(migrations = "./migrations")]` for a single crate's history, or
`#[sqlx::test(migrations = false)]` + manual `sqlx::migrate!(...).run(pool)` then
`review::migrator().run(pool)` where both histories are needed.

## Additive-change rule

Migrations are **additive and forward-only**:

- New columns are added with a default or as nullable so existing rows still validate;
  new tables are created, not mutated in place.
- **Never edit an already-applied migration in place** - it corrupts persisted state.
  Add a new numbered migration instead; rebuild a dev database from scratch when a
  history changes.
- Bump nothing in the wire/hash encoding for a schema change (see below). Columns not
  part of the hash chain (`session_id`, `ingested_at`, `id`, `prev_hash`, `hash`) can
  be added freely; `session_id` was added this way (`0007`) without touching the chain.

Two migrations in the current history embed data-only backfills rather than schema
change: `0006_relax_eligibility.sql` (recomputes eligibility flags - the one migration
that embeds a scoring formula in SQL) and the `0010`/`0011` backfills for `active_days`
and `established_event_count`. `0010` explicitly refuses to duplicate tier logic in SQL
(`0010:14-16`) - scoring stays in Rust. Keep new scoring logic out of migrations.

## The frozen wire contract

The sensor → intake NDJSON format (`crates/sensor-wire/src/lib.rs`, `WIRE_VERSION = 1`)
and the append-only ledger's canonical hash encoding
(`crates/core-scoring/src/hashing.rs`) are **frozen**. They are coupled:

- `canonical_bytes` writes event fields in a fixed order with length-prefixed framing
  and hashes them; a golden vector pins the encoding
  (`hashing.rs:192-214`, `golden_chain_hash_is_stable`).
- The enum Serialize casing is deliberately the bare Rust identifier (e.g.
  `"CatchallProbe"`, `"Tcp"`), **not** snake/lowercase - changing it would change every
  chain hash. Locked by
  `signal_type_serialize_is_unchanged_bare_rust_identifier` and
  `protocol_serialize_is_unchanged...` (`domain/enums.rs:174,204`). Deserialize accepts
  the wire strings so intake can parse sensor records.
- `observed_at` serializes as RFC 3339 via chrono's default serde and **must** match
  `hashing.rs` - do not switch to `ts_microseconds` or the chain breaks
  (`sensor-wire/src/lib.rs:45-48`).

Any change touching these is a chain-compatibility break, not an additive migration.
Full mechanism in [`architecture/storage`](../architecture/storage.md); frozen field
order and guarantees in [`reference/events-and-signals`](../reference/events-and-signals.md).

## sqlx

`sqlx` `0.9.0` with the `postgres, runtime-tokio, macros, rust_decimal, chrono, uuid,
json` feature set (`crates/core-scoring/Cargo.toml:14`; console omits `uuid`,
`crates/console/Cargo.toml:24`). Migrations are plain SQL files applied via the
`sqlx::migrate!` macro and the review `migrator()`. The test database provisioning is
in [toolchain-and-environment](toolchain-and-environment.md#test-postgresql).

<a id="vendoring"></a>
## Vendoring and rebuild-after-vendor

All dependencies are vendored in-tree under `vendor/`; `.cargo/config.toml` redirects
crates-io to it. Workflow (`CONTRIBUTING.md:13-14`): run `cargo vendor` after adding
or updating a dependency, then commit the vendor changes. `Cargo.lock` is committed and
frozen in CI via `--locked`.

> **Rebuild in release after re-vendoring.** `.gitattributes` marks `vendor/** -text`
> so EOL normalization cannot mangle vendored files' `.cargo-checksum.json`. A checksum
> mismatch surfaces only in a **release** build - a debug/test build can pass. After any
> `cargo vendor`, run `cargo build --release --locked`, not just `cargo test`.

The dependency/vendoring model is owned by
[`reference/dependencies`](../reference/dependencies.md); supply-chain posture is in
[`security/supply-chain`](../security/supply-chain.md).
