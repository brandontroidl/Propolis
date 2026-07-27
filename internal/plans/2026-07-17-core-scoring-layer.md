# Core Scoring Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 1 - the Rust + PostgreSQL library that owns the domain vocabulary, the append-only hash-chained event ledger, the derived per-IP score projection, and the scoring/eligibility/tier/recommendation logic - testable in isolation with no sensors and no live traffic.

**Architecture:** Event-sourced. Collectors append immutable events to a hash-chained `event` ledger; the per-IP `ip_score` row is a derived projection, decayed-to-now on read and rebuildable by replay. The crate has no network listeners, no vendor clients, no scheduler - it is a library, a schema, and a scoring function. Canonical spec: `internal/design/01-core-scoring-layer.md`; ratified parameter decisions: `internal/design/01-core-scoring-layer-open-questions.md`; frozen interface contracts: `internal/architecture/frozen-contracts.md`.

**Tech Stack:** Rust (2024 edition), `sqlx` (raw SQL + compile-time checking + migrations, async/tokio), `rust_decimal` (exact NUMERIC), `sha2` (SHA-256 chain), `proptest` (property tests), `thiserror` (typed errors), `serde`/`serde_json` (canonical encoding + JSONB).

## Global Constraints

- **Language:** Rust 2024 edition; toolchain pinned via `rust-toolchain.toml`. Workspace root at repo root; this crate is `crates/core-scoring`.
- **Dependency vetting:** frozen-lockfile installs; review the `Cargo.lock` diff; pin versions; confirm each crate's current API against its docs before use (do not code crate APIs from memory). No install scripts run.
- **No float for scores.** All stored and accumulated values - `raw_score`, `confidence`, `max_confidence`, breakdown weights, the breadth factor - are `rust_decimal::Decimal`, never `f64`. The ONE permitted `f64` touchpoint is the decay factor's transcendental exponent `0.5^(elapsed/half_life)` (no exact decimal form exists): compute it in `f64`, convert to `Decimal`, multiply into the `Decimal` score. Scores are never accumulated or stored through `f64`. Task 7 documents this as the single sanctioned touchpoint.
- **Fail closed.** Any error path - DB error, unreadable value, malformed event - leaves an IP NOT eligible and NOT recommended. A guard whose input is absent or unreadable denies.
- **Append-only ledger.** The `event` repository issues INSERT only; never UPDATE/DELETE in the normal path. Corrections are new appended events.
- **Data minimization.** `metadata` JSONB holds only sanitized, PII-free content. Passwords/payloads are dropped upstream (at the sensor) and are out of scope here; the repository must not add a code path that could persist them.
- **Constants are fixed source values, not runtime-tunable** - except `half_life_seconds` (the sole operator-tunable knob). Ratified values: `BREADTH_PER_WAN = 0.15`, `BREADTH_CAP = 0.60`, `SCORE_CAP = 100`, `HALF_LIFE_SECONDS = 21600`, `BLOCKLIST_FLOOR = 50`, `DISTINCT_CATEGORY_FLOOR = 0.5` (strict), tier floors AGGRESSIVE `raw>=90 & conf>=0.95` / STANDARD `raw>=75 & conf>=0.70`.
- **Load-bearing invariant (test-asserted):** breadth affects the effective score and the blocklist recommendation only. It never feeds the tier gate or the vendor recommendation, never sets `has_confirmed_real`, and never makes an ineligible IP eligible. Only a confirmed-real event (`protocol=tcp AND authenticated=true AND category=honeypot`) opens eligibility.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: Workspace + crate scaffold

**Files:**
- Create: `Cargo.toml` (workspace root), `rust-toolchain.toml`, `crates/core-scoring/Cargo.toml`, `crates/core-scoring/src/lib.rs`, `.gitignore` (add `/target`)
- Test: `crates/core-scoring/tests/smoke.rs`

**Interfaces:**
- Produces: the `core_scoring` crate compiles and its test target runs.

- [ ] **Step 1: Write the failing test**

```rust
// crates/core-scoring/tests/smoke.rs
#[test]
fn crate_builds_and_links() {
    assert_eq!(core_scoring::VERSION_MARKER, "core-scoring");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p core-scoring --test smoke`
Expected: FAIL - `VERSION_MARKER` not found / crate does not build.

- [ ] **Step 3: Write minimal scaffold**

Workspace root `Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/core-scoring"]
```
`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
```
`crates/core-scoring/Cargo.toml` (versions to be pinned + lockfile-reviewed; confirm current majors before adding):
```toml
[package]
name = "core-scoring"
version = "0.1.0"
edition = "2024"

[dependencies]
sqlx = { version = "*", features = ["postgres", "runtime-tokio", "macros", "rust_decimal", "chrono", "uuid", "json"] }
rust_decimal = { version = "*", features = ["serde"] }
rust_decimal_macros = "*"
sha2 = "*"
serde = { version = "*", features = ["derive"] }
serde_json = "*"
thiserror = "*"
chrono = { version = "*", features = ["serde"] }
tokio = { version = "*", features = ["rt-multi-thread", "macros"] }

[dev-dependencies]
proptest = "*"
```
`crates/core-scoring/src/lib.rs`:
```rust
pub const VERSION_MARKER: &str = "core-scoring";
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p core-scoring --test smoke`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml crates/core-scoring .gitignore
git commit -m "feat(core-scoring): scaffold workspace and crate"
```

---

### Task 2: Domain enums

**Files:**
- Create: `crates/core-scoring/src/domain/mod.rs`, `crates/core-scoring/src/domain/enums.rs`
- Modify: `crates/core-scoring/src/lib.rs` (add `pub mod domain;`)
- Test: `crates/core-scoring/src/domain/enums.rs` (unit tests inline)

**Interfaces:**
- Produces: `Protocol`, `Category`, `FeedTier`, `SignalType`, `ReviewState` enums with `sqlx::Type` derives mapping to the SQL enums; `SignalType::ALL: [SignalType; 16]`.

- [ ] **Step 1: Write the failing test**

```rust
// in enums.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signal_type_all_has_16_distinct_variants() {
        assert_eq!(SignalType::ALL.len(), 16);
        let mut seen = std::collections::HashSet::new();
        for s in SignalType::ALL { assert!(seen.insert(s), "duplicate {s:?}"); }
    }
    #[test]
    fn confirmed_real_predicate_only_tcp_auth_honeypot() {
        assert!(is_confirmed_real(Protocol::Tcp, true, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Udp, true, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Tcp, false, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Tcp, true, Category::Ids));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p core-scoring domain::enums`
Expected: FAIL - types not defined.

- [ ] **Step 3: Write minimal implementation**

```rust
// enums.rs
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "protocol_enum", rename_all = "lowercase")]
pub enum Protocol { Tcp, Udp, Icmp }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "category_enum", rename_all = "lowercase")]
pub enum Category { Honeypot, Ids, Network, Waf, Auth }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "feed_tier_enum", rename_all = "lowercase")]
pub enum FeedTier { Aggressive, Standard }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "signal_type_enum", rename_all = "snake_case")]
pub enum SignalType {
    HoneypotConnection, HoneypotLoginAttempt, HoneypotCommandExec, HoneypotMalwareUpload,
    HoneypotFileDownload, SuricataSev1, SuricataSev2, SuricataSev3, PortScan, SynFlood,
    BlockedConnection, WafSqliXss, WafGenericBlock, SshBruteForce, CatchallProbe, RemoteAuthFailure,
}
impl SignalType {
    pub const ALL: [SignalType; 16] = [
        SignalType::HoneypotConnection, SignalType::HoneypotLoginAttempt, SignalType::HoneypotCommandExec,
        SignalType::HoneypotMalwareUpload, SignalType::HoneypotFileDownload, SignalType::SuricataSev1,
        SignalType::SuricataSev2, SignalType::SuricataSev3, SignalType::PortScan, SignalType::SynFlood,
        SignalType::BlockedConnection, SignalType::WafSqliXss, SignalType::WafGenericBlock,
        SignalType::SshBruteForce, SignalType::CatchallProbe, SignalType::RemoteAuthFailure,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "review_state_enum", rename_all = "lowercase")]
pub enum ReviewState { Pending, Approved, Rejected, Snoozed }

pub fn is_confirmed_real(p: Protocol, authenticated: bool, c: Category) -> bool {
    p == Protocol::Tcp && authenticated && c == Category::Honeypot
}
```
Confirm the `sqlx::Type` `rename_all` values match the SQL enum labels exactly (Task 5). `snake_case` must render `honeypot_login_attempt` etc.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p core-scoring domain::enums`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src
git commit -m "feat(core-scoring): domain enums and confirmed-real predicate"
```

---

### Task 3: Signal weight table

**Files:**
- Create: `crates/core-scoring/src/domain/weights.rs`
- Modify: `crates/core-scoring/src/domain/mod.rs`
- Test: inline in `weights.rs`

**Interfaces:**
- Consumes: `SignalType`, `Category` (Task 2).
- Produces: `pub struct SignalWeight { pub weight: u32, pub confidence: Decimal, pub category: Category }` and `pub fn signal_weight(SignalType) -> SignalWeight` (total - every variant has exactly one row).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::enums::{SignalType, Category};
    #[test]
    fn every_signal_type_has_exactly_one_weight_row() {
        for s in SignalType::ALL { let _ = signal_weight(s); } // total: no panic, no default arm
    }
    #[test]
    fn spot_check_known_rows() {
        let w = signal_weight(SignalType::HoneypotMalwareUpload);
        assert_eq!(w.weight, 80);
        assert_eq!(w.confidence, dec!(0.980));
        assert_eq!(w.category, Category::Honeypot);
        assert_eq!(signal_weight(SignalType::BlockedConnection).weight, 3);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p core-scoring domain::weights`
Expected: FAIL - `signal_weight` not defined.

- [ ] **Step 3: Write minimal implementation**

```rust
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use crate::domain::enums::{SignalType, Category};

pub struct SignalWeight { pub weight: u32, pub confidence: Decimal, pub category: Category }

pub fn signal_weight(s: SignalType) -> SignalWeight {
    use SignalType::*; use Category::*;
    let (weight, confidence, category) = match s {
        HoneypotConnection   => (40, dec!(0.900), Honeypot),
        HoneypotLoginAttempt => (50, dec!(0.920), Honeypot),
        HoneypotCommandExec  => (60, dec!(0.950), Honeypot),
        HoneypotMalwareUpload=> (80, dec!(0.980), Honeypot),
        HoneypotFileDownload => (70, dec!(0.960), Honeypot),
        SuricataSev1         => (30, dec!(0.700), Ids),
        SuricataSev2         => (15, dec!(0.500), Ids),
        SuricataSev3         => ( 5, dec!(0.300), Ids),
        PortScan             => (20, dec!(0.600), Network),
        SynFlood             => (25, dec!(0.700), Network),
        BlockedConnection    => ( 3, dec!(0.150), Network),
        WafSqliXss           => (35, dec!(0.850), Waf),
        WafGenericBlock      => (15, dec!(0.500), Waf),
        SshBruteForce        => (20, dec!(0.600), Auth),
        CatchallProbe        => (15, dec!(0.400), Network),
        RemoteAuthFailure    => (12, dec!(0.400), Auth),
    };
    SignalWeight { weight, confidence, category }
}
```
The exhaustive `match` with no `_` arm is the compile-time completeness guarantee; the test is the belt to the compiler's braces.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p core-scoring domain::weights`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src
git commit -m "feat(core-scoring): 16-row signal weight table"
```

---

### Task 4: Event and score value types

**Files:**
- Create: `crates/core-scoring/src/domain/types.rs`
- Modify: `crates/core-scoring/src/domain/mod.rs`
- Test: inline

**Interfaces:**
- Consumes: enums (Task 2).
- Produces:
  - `pub struct EventInput { source_ip: IpAddr, wan_ip: Option<IpAddr>, sensor: String, signal_type: SignalType, protocol: Protocol, authenticated: bool, category: Category, weight: u32, confidence: Decimal, observed_at: DateTime<Utc>, metadata: serde_json::Value }`
  - `pub struct IpScore { ... all ip_score columns ... }` (read model).
  - `EventInput::from_signal(source_ip, wan_ip, sensor, signal_type, protocol, authenticated, observed_at, metadata) -> EventInput` that fills `weight`/`confidence`/`category` from `signal_weight` so a caller cannot desync them.
  - `EventInput::validate(&self) -> Result<(), ValidationError>` and `pub enum ValidationError { ConfidenceOutOfRange, SensorEmpty }` - the spec's append-path validation. Confidence must be in `[0, 1]`; `sensor` non-empty. (Most invalidity is already unrepresentable: `source_ip`/`wan_ip` are typed `IpAddr`, `signal_type`/`protocol`/`category` are typed enums, so a malformed IP or unknown signal type cannot be constructed here - those are rejected at the intake boundary in sub-project 3.)

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn from_signal_fills_weight_confidence_category_from_table() {
        let e = EventInput::from_signal(
            "203.0.113.7".parse().unwrap(), None, "sensor-a".into(),
            SignalType::HoneypotCommandExec, Protocol::Tcp, true,
            "2026-07-17T00:00:00Z".parse().unwrap(), serde_json::json!({}));
        assert_eq!(e.weight, 60);
        assert_eq!(e.confidence, dec!(0.950));
        assert_eq!(e.category, Category::Honeypot);
        assert!(e.validate().is_ok());
    }
    #[test]
    fn validate_rejects_out_of_range_confidence() {
        let mut e = sample_event();
        e.confidence = dec!(1.5);
        assert!(matches!(e.validate(), Err(ValidationError::ConfidenceOutOfRange)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p core-scoring domain::types`
Expected: FAIL - types not defined.

- [ ] **Step 3: Write minimal implementation**

Define `EventInput` and `IpScore` structs with the fields above (types matching the schema: `IpAddr`, `Option<IpAddr>`, `Decimal`, `DateTime<Utc>`, `serde_json::Value`, counts as `i32`/`u32`, `Option<FeedTier>`). Implement `from_signal` pulling `weight/confidence/category` from `signal_weight(signal_type)` (Task 3). Use RFC5737 `203.0.113.0/24` addresses in tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p core-scoring domain::types`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src
git commit -m "feat(core-scoring): event and score value types"
```

---

### Task 5: Database migrations (enums + tables)

**Files:**
- Create: `crates/core-scoring/migrations/0001_enums.sql`, `0002_event.sql`, `0003_ip_score.sql`
- Test: `crates/core-scoring/tests/migrations.rs`

**Interfaces:**
- Produces: a migrated schema exactly matching `frozen-contracts.md` (§ Enums, § Event ledger, § Score projection), including the ratified `recommended_for_vendor` + `recommended_for_blocklist` split.

- [ ] **Step 1: Write the failing test**

```rust
// tests/migrations.rs
#[sqlx::test(migrations = "./migrations")]
async fn migrations_apply_and_expose_expected_columns(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'ip_score' ORDER BY column_name")
        .fetch_all(&pool).await?;
    assert!(cols.contains(&"recommended_for_vendor".to_string()));
    assert!(cols.contains(&"recommended_for_blocklist".to_string()));
    assert!(!cols.contains(&"recommended".to_string()));
    Ok(())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p core-scoring --test migrations` (needs a reachable Postgres; `sqlx::test` provisions a disposable DB - confirm `DATABASE_URL` and the `sqlx::test` setup against current sqlx docs).
Expected: FAIL - no migrations.

- [ ] **Step 3: Write the migrations**

`0001_enums.sql`: the five `CREATE TYPE ... AS ENUM` statements from `frozen-contracts.md` § Enums (labels exactly `honeypot_login_attempt`, etc.).
`0002_event.sql`: the `event` table + `event_source_ip_idx`, `event_observed_at_idx` from § Event ledger.
`0003_ip_score.sql`: the `ip_score` table from § Score projection, with `recommended_for_vendor BOOLEAN NOT NULL DEFAULT false` and `recommended_for_blocklist BOOLEAN NOT NULL DEFAULT false` (NOT a single `recommended`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p core-scoring --test migrations`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/migrations crates/core-scoring/tests/migrations.rs
git commit -m "feat(core-scoring): postgres schema migrations"
```

---

### Task 6: Canonical encoding + hash chain

**Files:**
- Create: `crates/core-scoring/src/hashing.rs`
- Test: inline + `proptest`

**Interfaces:**
- Consumes: `EventInput` (Task 4).
- Produces: `pub fn canonical_bytes(&EventInput) -> Vec<u8>` (deterministic, field-order-fixed) and `pub fn chain_hash(prev: Option<&[u8]>, event: &EventInput) -> [u8; 32]` (SHA-256 over `prev || canonical_bytes(event)`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn hash_is_deterministic_for_same_event() {
    let e = sample_event();
    assert_eq!(chain_hash(None, &e), chain_hash(None, &e));
}
#[test]
fn mutating_any_field_changes_the_hash() {
    let e = sample_event();
    let mut e2 = e.clone(); e2.weight += 1;
    assert_ne!(chain_hash(None, &e), chain_hash(None, &e2));
}
#[test]
fn prev_hash_is_bound_into_the_chain() {
    let e = sample_event();
    assert_ne!(chain_hash(None, &e), chain_hash(Some(&[9u8;32]), &e));
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p core-scoring hashing`
Expected: FAIL - not defined.

- [ ] **Step 3: Implement**

`canonical_bytes` serializes fields in a FIXED order with length-prefixed encoding (not `serde_json`, whose key order is not guaranteed): e.g. write each field as `len(u32 LE) || bytes` for strings/IPs/metadata (metadata via `serde_json::to_vec` of a `BTreeMap`-sorted value), fixed-width for numerics (`confidence` as its `Decimal` string bytes, `weight` as `u32 LE`, timestamps as RFC3339 bytes). `chain_hash` feeds `prev.unwrap_or(&[])` then `canonical_bytes` into `sha2::Sha256`. Document that the encoding is frozen - changing it breaks all existing chains.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p core-scoring hashing`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/hashing.rs
git commit -m "feat(core-scoring): canonical event encoding and sha-256 chain"
```

---

### Task 7: Decay math

**Files:**
- Create: `crates/core-scoring/src/scoring/mod.rs`, `crates/core-scoring/src/scoring/decay.rs`, `crates/core-scoring/src/scoring/constants.rs`
- Test: inline example tests + `proptest`

**Interfaces:**
- Produces: `pub fn decay(prev: Decimal, elapsed_seconds: i64, half_life_seconds: i64) -> Decimal` and constants (`HALF_LIFE_SECONDS: i64 = 21600`, `SCORE_CAP: Decimal = 100`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn clamps_nonpositive_elapsed() {
    assert_eq!(decay(dec!(50), 0, 21600), dec!(50));
    assert_eq!(decay(dec!(50), -100, 21600), dec!(50));
}
#[test]
fn halves_at_exactly_one_half_life() {
    let out = decay(dec!(80), 21600, 21600);
    assert!((out - dec!(40)).abs() < dec!(0.0001));
}
proptest! {
    #[test]
    fn monotonic_non_increasing(prev in 0i64..100, elapsed in 0i64..1_000_000) {
        let p = Decimal::from(prev);
        prop_assert!(decay(p, elapsed, 21600) <= p);
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p core-scoring scoring::decay`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
pub fn decay(prev: Decimal, elapsed_seconds: i64, half_life_seconds: i64) -> Decimal {
    if elapsed_seconds <= 0 { return prev; }               // clock-skew clamp: only ever shrinks
    // factor = 0.5 ^ (elapsed / half_life), computed in f64 for the exponent only,
    // then applied to the Decimal score; result re-quantized. Never store/accumulate via f64.
    let exp = elapsed_seconds as f64 / half_life_seconds as f64;
    let factor = Decimal::from_f64_retain(0.5f64.powf(exp)).unwrap_or(Decimal::ZERO);
    prev * factor
}
```
Note: the exponent uses `f64` for `powf` only; the score itself stays `Decimal`. If stricter exactness is required later, replace with a `Decimal`-native pow. Document this as the single sanctioned `f64` touchpoint.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p core-scoring scoring::decay`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/scoring
git commit -m "feat(core-scoring): decay math with clock-skew clamp"
```

---

### Task 8: Breadth factor + hardened WAN count

**Files:**
- Create: `crates/core-scoring/src/scoring/breadth.rs`
- Test: inline

**Interfaces:**
- Consumes: constants (Task 7).
- Produces:
  - `pub fn distinct_wan_count(vantages: &[WanVantage]) -> u32` where `WanVantage { wan_ip: IpAddr, saw_authenticated_tcp: bool }` - counts a WAN only if `saw_authenticated_tcp`, deduped by `/24` (IPv4) / `/64` (IPv6).
  - `pub fn breadth_factor(distinct_wan_count: u32) -> Decimal` = `1 + min(BREADTH_CAP, BREADTH_PER_WAN * max(0, n-1))`.
  - `pub fn effective_score(raw_score: Decimal, distinct_wan_count: u32) -> Decimal` = `min(100, raw_score * factor)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn one_wan_gives_factor_one() { assert_eq!(breadth_factor(1), dec!(1.00)); }
#[test]
fn five_or_more_wans_saturate_at_1_60() {
    assert_eq!(breadth_factor(5), dec!(1.60));
    assert_eq!(breadth_factor(9), dec!(1.60));
}
#[test]
fn spoofed_wan_without_authenticated_tcp_is_not_counted() {
    let v = vec![
        WanVantage { wan_ip: "198.51.100.1".parse().unwrap(), saw_authenticated_tcp: true },
        WanVantage { wan_ip: "203.0.113.9".parse().unwrap(), saw_authenticated_tcp: false },
    ];
    assert_eq!(distinct_wan_count(&v), 1);
}
#[test]
fn same_24_counts_once() {
    let v = vec![
        WanVantage { wan_ip: "198.51.100.1".parse().unwrap(), saw_authenticated_tcp: true },
        WanVantage { wan_ip: "198.51.100.9".parse().unwrap(), saw_authenticated_tcp: true },
    ];
    assert_eq!(distinct_wan_count(&v), 1);
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p core-scoring scoring::breadth`
Expected: FAIL.

- [ ] **Step 3: Implement** the three functions. For `/24` dedupe, mask IPv4 to the high 24 bits (IPv6 to /64) and collect authenticated vantages into a `HashSet` of masked prefixes; count the set size. (ASN dedupe is deferred/best-effort per the ratified decision and is out of scope for this task - leave a documented extension point, no stub code.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p core-scoring scoring::breadth`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/scoring/breadth.rs
git commit -m "feat(core-scoring): breadth factor with authenticated + /24-deduped wan count"
```

---

### Task 9: Eligibility gate

**Files:**
- Create: `crates/core-scoring/src/scoring/eligibility.rs`
- Test: inline

**Interfaces:**
- Produces: `pub fn distinct_categories(breakdown: &CategoryBreakdown) -> u32` (count categories whose decayed weight `> 0.5` strict) and `pub fn eligible(has_confirmed_real: bool, event_count: u32, distinct_categories: u32) -> bool`, where `CategoryBreakdown` is a `BTreeMap<Category, Decimal>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn eligibility_requires_all_three_legs() {
    assert!(eligible(true, 2, 2));
    assert!(!eligible(false, 5, 5));      // no confirmed-real
    assert!(!eligible(true, 1, 2));       // too few events
    assert!(!eligible(true, 2, 1));       // too few categories
}
#[test]
fn distinct_categories_floor_is_strict_at_half() {
    let mut b = CategoryBreakdown::new();
    b.insert(Category::Honeypot, dec!(0.50));   // exactly 0.5 does NOT count
    b.insert(Category::Ids, dec!(0.51));
    assert_eq!(distinct_categories(&b), 1);
}
```

- [ ] **Step 2: Run to verify fail** - `cargo test -p core-scoring scoring::eligibility`; FAIL.

- [ ] **Step 3: Implement** both functions (`> dec!(0.5)` strict; `eligible = has_confirmed_real && event_count >= 2 && distinct_categories >= 2`).

- [ ] **Step 4: Run to verify pass** - PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/scoring/eligibility.rs
git commit -m "feat(core-scoring): eligibility gate with strict category floor"
```

---

### Task 10: Tier gate + recommendation split

**Files:**
- Create: `crates/core-scoring/src/scoring/tier.rs`
- Test: inline

**Interfaces:**
- Consumes: `FeedTier`, constants, `effective_score` (Task 8).
- Produces:
  - `pub fn tier(raw_score: Decimal, max_confidence: Decimal) -> Option<FeedTier>` - on RAW score, AGGRESSIVE tested first.
  - `pub fn recommended_for_vendor(eligible: bool, tier: Option<FeedTier>) -> bool`.
  - `pub fn recommended_for_blocklist(eligible: bool, effective_score: Decimal) -> bool` (`effective_score >= 50`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn tier_runs_on_raw_not_effective() {
    // raw 60, high breadth -> effective 96, but tier must be None (raw < 75)
    assert_eq!(tier(dec!(60), dec!(0.90)), None);
}
#[test]
fn tier_floors_require_both_axes() {
    assert_eq!(tier(dec!(92), dec!(0.80)), Some(FeedTier::Standard)); // conf fails AGGRESSIVE
    assert_eq!(tier(dec!(90), dec!(0.95)), Some(FeedTier::Aggressive));
    assert_eq!(tier(dec!(74), dec!(0.99)), None);
}
#[test]
fn recommendation_split() {
    assert!(!recommended_for_vendor(true, None));
    assert!(recommended_for_vendor(true, Some(FeedTier::Standard)));
    assert!(recommended_for_blocklist(true, dec!(50)));
    assert!(!recommended_for_blocklist(true, dec!(49)));
    assert!(!recommended_for_blocklist(false, dec!(90))); // eligibility-gated
}
```

- [ ] **Step 2: Run to verify fail** - FAIL.

- [ ] **Step 3: Implement** - AGGRESSIVE `raw>=90 && conf>=0.95`, else STANDARD `raw>=75 && conf>=0.70`, else None; the two recommendation functions.

- [ ] **Step 4: Run to verify pass** - PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/scoring/tier.rs
git commit -m "feat(core-scoring): raw-score tier gate and split recommendation"
```

---

### Task 11: Projection engine (pure state transition)

**Files:**
- Create: `crates/core-scoring/src/scoring/engine.rs`
- Test: inline + `proptest`

**Interfaces:**
- Consumes: everything in `scoring/`, `EventInput`, `IpScore`, `is_confirmed_real`.
- Produces: `pub fn apply_event(prev: Option<IpScore>, event: &EventInput, half_life_seconds: i64) -> IpScore` - the pure accumulate step: decays the stored `raw_score` from `prev.decay_anchor` to `event.observed_at`, decays each category breakdown weight by the same factor, adds this event's weight (capped 100), sets a fresh `decay_anchor = event.observed_at`, updates `max_confidence` over the live-decayed breakdown, `event_count += 1`, `has_confirmed_real |= is_confirmed_real(...)`, recomputes `distinct_categories`, `eligible`, `tier`, `recommended_for_vendor`, `recommended_for_blocklist`. Dedup handling (same source+signal within window: no weight added, but decay-to-now, refresh `last_seen`, union protocol, recompute flags) lives here behind a `deduped: bool` parameter.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn confirmed_real_latch_sticks_and_never_unsets() {
    let e1 = auth_honeypot_event("2026-07-17T00:00:00Z");
    let s1 = apply_event(None, &e1, 21600);
    assert!(s1.has_confirmed_real);
    let e2 = udp_probe_event("2026-07-20T00:00:00Z");   // days later, decayed
    let s2 = apply_event(Some(s1), &e2, 21600);
    assert!(s2.has_confirmed_real);                      // still true
}
proptest! {
    #[test]
    fn breadth_never_flips_eligibility_without_confirmed_real(seq in event_seq_no_confirmed_real()) {
        let mut s = None;
        for e in seq { s = Some(apply_event(s.take(), &e, 21600)); }
        prop_assert!(!s.unwrap().eligible);              // anti-spoof invariant
    }
}
```

- [ ] **Step 2: Run to verify fail** - FAIL.

- [ ] **Step 3: Implement** `apply_event` composing Tasks 7-10. Breadth (`distinct_wan_count`/`effective_score`) is threaded from the repository layer's vantage set (Task 12); in the pure engine, accept the current `distinct_wan_count` on `prev`/passed in and compute `effective_score` for the blocklist flag only. The engine must read the UN-projected stored `raw_score` (the caller passes the stored value, never a read-projected one) - see Task 12's double-decay guard.

- [ ] **Step 4: Run to verify pass** - PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/scoring/engine.rs
git commit -m "feat(core-scoring): pure projection accumulate step"
```

---

### Task 12: Repository - append path + projection (real Postgres)

**Files:**
- Create: `crates/core-scoring/src/repository/mod.rs`, `crates/core-scoring/src/repository/events.rs`
- Test: `crates/core-scoring/tests/repository.rs` (`sqlx::test`, real DB)

**Interfaces:**
- Consumes: engine (Task 11), hashing (Task 6), migrations (Task 5).
- Produces:
  - `pub enum RepoError { Db(sqlx::Error), Invalid(ValidationError), Chain(String) }` (via `thiserror`; `From<sqlx::Error>` and `From<ValidationError>`). Fail-closed: any variant means the caller gets an error and NO projection was committed (the transaction rolls back).
  - `append_event(&PgPool, EventInput) -> Result<IpScore, RepoError>` - calls `event.validate()?` FIRST (a malformed event is rejected by error, never a panic, and nothing is written), then in ONE transaction: read the current chain head hash, compute `chain_hash`, INSERT the event, read the UN-PROJECTED stored `ip_score` row, call `apply_event`, UPSERT the projection, commit. Dedup window checked on `(source_ip, signal_type)`.
  - `read_score(&PgPool, IpAddr) -> Result<Option<IpScore>, RepoError>` - reads the stored row and projects `raw_score` to now as a pure read (never writes back).

- [ ] **Step 1: Write the failing tests**

```rust
#[sqlx::test(migrations = "./migrations")]
async fn append_updates_projection_atomically(pool: PgPool) -> Result<(), RepoError> {
    let s = append_event(&pool, auth_honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z")).await?;
    assert_eq!(s.event_count, 1);
    assert!(s.has_confirmed_real);
    Ok(())
}
#[sqlx::test(migrations = "./migrations")]
async fn malformed_event_is_rejected_without_writing(pool: PgPool) {
    let mut bad = auth_honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z");
    bad.confidence = dec!(9);                                  // out of range
    assert!(matches!(append_event(&pool, bad).await, Err(RepoError::Invalid(_))));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM event").fetch_one(&pool).await.unwrap();
    assert_eq!(n, 0);                                          // nothing written on the error path
}
#[sqlx::test(migrations = "./migrations")]
async fn double_decay_guard_across_one_half_life(pool: PgPool) -> Result<(), RepoError> {
    // event A at t0; READ at t0+6h (projects raw to ~half); event B at t0+6h.
    // The write path for B must read the UN-projected stored raw, not the read-projected one.
    let a = append_event(&pool, honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z", 40)).await?;
    let _ = read_score(&pool, "203.0.113.7".parse().unwrap()).await?; // a read in between
    let b = append_event(&pool, honeypot_input("203.0.113.7", "2026-07-17T06:00:00Z", 40)).await?;
    // stored raw at B = decay(40, 6h) + 40 = 20 + 40 = 60 (NOT decay(decay(40)) + 40)
    assert!((b.raw_score - dec!(60)).abs() < dec!(0.01));
    Ok(())
}
```

- [ ] **Step 2: Run to verify fail** - FAIL.

- [ ] **Step 3: Implement** the transactional append (INSERT-only on `event`; `INSERT ... ON CONFLICT (source_ip) DO UPDATE` on `ip_score`) and the read-projection. Confirm `sqlx` transaction + `query!`/`query_as!` macro usage against current sqlx docs. The stored `raw_score`/`decay_anchor` are read WITHIN the transaction before `apply_event`.

- [ ] **Step 4: Run to verify pass** - PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/repository crates/core-scoring/tests/repository.rs
git commit -m "feat(core-scoring): transactional append path and read projection"
```

---

### Task 13: Replay rebuild + chain verification

**Files:**
- Create: `crates/core-scoring/src/repository/replay.rs`
- Test: `crates/core-scoring/tests/replay.rs` (`sqlx::test`) + `proptest`

**Interfaces:**
- Produces:
  - `rebuild_projection(&PgPool, IpAddr) -> Result<IpScore, RepoError>` - replays that IP's events in observed order via `apply_event` from empty.
  - `verify_chain(&PgPool) -> Result<ChainStatus, RepoError>` - recomputes each row's hash + linkage; returns `Intact` or `Broken { first_bad_id }`.

- [ ] **Step 1: Write the failing tests**

```rust
#[sqlx::test(migrations = "./migrations")]
async fn replay_equals_incremental(pool: PgPool) -> Result<(), RepoError> {
    for e in sample_stream() { append_event(&pool, e).await?; }
    let incremental = read_score(&pool, IP).await?.unwrap();
    let replayed = rebuild_projection(&pool, IP).await?;
    assert_eq!(replayed.raw_score, incremental.raw_score);   // extend to full struct equality
    Ok(())
}
#[sqlx::test(migrations = "./migrations")]
async fn tampering_breaks_the_chain(pool: PgPool) -> Result<(), RepoError> {
    append_event(&pool, sample()).await?;
    sqlx::query("UPDATE event SET weight = weight + 1 WHERE id = 1").execute(&pool).await?;
    assert!(matches!(verify_chain(&pool).await?, ChainStatus::Broken { .. }));
    Ok(())
}
```

- [ ] **Step 2: Run to verify fail** - FAIL.

- [ ] **Step 3: Implement** replay (compare projected-to-same-instant to avoid decay-anchor drift in the equality) and chain verification. For replay equality, project both to a common instant before comparing.

- [ ] **Step 4: Run to verify pass** - PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/repository/replay.rs crates/core-scoring/tests/replay.rs
git commit -m "feat(core-scoring): replay rebuild and hash-chain verification"
```

---

### Task 14: Public API surface + end-to-end test

**Files:**
- Modify: `crates/core-scoring/src/lib.rs` (re-export the public API; remove `VERSION_MARKER`)
- Test: `crates/core-scoring/tests/end_to_end.rs`

**Interfaces:**
- Produces: the crate's public surface - `append_event`, `read_score`, `rebuild_projection`, `verify_chain`, `EventInput`, `IpScore`, the enums, and `signal_weight`. Nothing else is `pub`.

- [ ] **Step 1: Write the failing test** - an end-to-end scenario against a real DB: a spoofable multi-WAN UDP sweep (no confirmed-real) never becomes `eligible`; a confirmed-real honeypot session plus a second category crosses into `eligible` and the correct tier/recommendation; breadth raises `recommended_for_blocklist` but never the vendor tier.

- [ ] **Step 2: Run to verify fail** - FAIL (API not re-exported).

- [ ] **Step 3: Implement** the re-exports; delete the smoke marker (update Task 1's `smoke.rs` if it still references it).

- [ ] **Step 4: Run to verify pass** - `cargo test -p core-scoring` (full suite, serial: `--test-threads=1` for the DB tests if they contend).

- [ ] **Step 5: Commit**

```bash
git add crates/core-scoring/src/lib.rs crates/core-scoring/tests/end_to_end.rs
git commit -m "feat(core-scoring): public api surface and end-to-end scenario"
```

---

## Notes for the implementer

- **Verify crate APIs against current docs before coding** each `sqlx`/`rust_decimal`/`proptest` step - these evolve; the snippets here are the shape, not a pinned API.
- **The double-decay guard (Task 12) is the subtle one.** A repository test double where the un-projected read and the projected read return the same value hides the bug; it is caught only by the real-engine + real-repository integration test spanning at least one half-life.
- **Run the full suite serially before any merge** (`cargo test -p core-scoring -- --test-threads=1`); the `sqlx::test` DB tests can contend otherwise.
- **Every constant traces to** `internal/design/01-core-scoring-layer-open-questions.md` (ratified) or `01-core-scoring-layer.md`. Do not introduce a new tunable; `half_life_seconds` is the only one.
