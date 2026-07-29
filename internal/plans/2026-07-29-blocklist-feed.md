# Blocklist Feed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 5 - a single Rust crate (`crates/feed`) that builds a two-tier public blocklist from approved ip_score projections, exports to multiple formats with anti-deanonymization coarsening, and publishes atomically to a local directory.

**Architecture:** The feed builder queries ip_score for recommended-for-blocklist IPs, applies exclusions (RFC1918/5737, operator allowlist, delist), coarsens timestamps to hourly granularity, and groups by tier. Exporters produce plain text, JSON, CSV, and CIDR formats. The publisher writes atomically with fail-closed re-validation. Canonical spec: `internal/design/05-blocklist-feed.md`.

**Tech Stack:** Rust (2024 edition), `core-scoring` (IpScore, read_score, FeedTier), `sqlx` (PostgreSQL), `tokio` (async runtime, fs), `serde`/`serde_json`, `chrono`, `tracing`, `ipnet` (CIDR handling), `sha2` (manifest checksums).

## Global Constraints

- **Rust 2024 edition.** New crate at `crates/feed`.
- **Database:** read-only access to ip_score (from core-scoring's tables). No new migrations.
- **Fail closed.** Exclusion check failure -> reject entire build. Publisher re-validates every entry. Reserved/private/allowlisted IP in output -> build rejected.
- **No raw score, no confidence in exports.** Anti-deanonymization. Timestamps coarsened to hour.
- **Collateral safety.** Host routes only (/32). No aggregation in initial implementation.
- **Tests require PostgreSQL.** Same propolis-pg container.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: Crate scaffold + exclusion engine + feed builder

**Files:**
- Create: `crates/feed/Cargo.toml`, `crates/feed/src/lib.rs`, `crates/feed/src/builder.rs`, `crates/feed/src/exclusion.rs`
- Modify: `Cargo.toml` (add `feed` to workspace members)
- Test: `crates/feed/tests/builder_test.rs`, `crates/feed/tests/exclusion_test.rs`

**Interfaces:**
- Consumes: `core_scoring::{IpScore, FeedTier, read_score}`, `sqlx::PgPool`.
- Produces: `FeedSnapshot`, `FeedEntry`, `ExclusionEngine::new(allowlist, delist)`, `ExclusionEngine::is_excluded(ip) -> bool`, `FeedBuilder::build(pool, exclusions, config) -> Result<FeedSnapshot>`, `coarsen_to_hour(dt) -> DateTime<Utc>`.

Tests:
- Exclusion: RFC1918 excluded, RFC5737 excluded, loopback excluded, public IP passes, allowlisted IP excluded, delisted IP excluded, empty allowlist passes all public IPs.
- Builder: seed real ip_score data via append_event (need IPs with recommended_for_blocklist=true), build the feed, verify entries match expected IPs, verify tier assignment, verify coarsened timestamps, verify no excluded IPs in output.
- Coarsening: verify all timestamps are truncated to hour boundaries.

---

### Task 2: Exporters (plain text, JSON, CSV, CIDR)

**Files:**
- Create: `crates/feed/src/export/mod.rs`, `crates/feed/src/export/plaintext.rs`, `crates/feed/src/export/json.rs`, `crates/feed/src/export/csv.rs`, `crates/feed/src/export/cidr.rs`
- Test: `crates/feed/tests/export_test.rs`

**Interfaces:**
- Consumes: `FeedSnapshot`, `FeedEntry` (Task 1).
- Produces: `export_plaintext(tier_name, entries, valid_until) -> String`, `export_json(tier_name, snapshot) -> String`, `export_csv(entries) -> String`, `export_cidr(entries) -> String`.

Tests:
- Plain text: correct header, one IP per line, no raw score or confidence.
- JSON: parses as valid JSON, has meta + entries, no score/confidence fields.
- CSV: parseable, correct columns, no score/confidence.
- CIDR: all entries are /32 host routes.
- Anti-deanonymization: no field in any format reveals raw_score, max_confidence, or sub-hour timestamps.

---

### Task 3: Publisher + binary + deployment

**Files:**
- Create: `crates/feed/src/publisher.rs`, `crates/feed/src/main.rs`, `deploy/feed.service`
- Modify: `crates/sensor-framework/tests/deploy_test.rs` (add feed unit test)
- Test: `crates/feed/tests/publisher_test.rs`

**Interfaces:**
- Consumes: `FeedSnapshot`, exporters (Task 2), `ExclusionEngine` (Task 1).
- Produces: `Publisher::publish(snapshot, output_dir, exclusions) -> Result<()>` (re-validates, writes atomically), manifest.json with checksums.

The binary runs a periodic build loop: build snapshot, export all formats, publish. Config from environment variables (DATABASE_URL, PROPOLIS_FEED_OUTPUT_DIR, PROPOLIS_FEED_BUILD_INTERVAL_SECS, PROPOLIS_FEED_ALLOWLIST, PROPOLIS_FEED_DELIST).

Tests:
- Publisher fail-closed: inject a reserved IP, verify entire build rejected.
- Atomic publish: verify output directory updated atomically.
- Manifest: correct checksums, coarsened build_time.
- Deploy test: hardened systemd unit directives present.

Re-vendor after adding dependencies. Commit vendor changes separately.
