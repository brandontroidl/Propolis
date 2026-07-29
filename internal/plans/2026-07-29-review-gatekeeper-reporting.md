# Review Queue + Gatekeeper + Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 4 - a single Rust crate (`crates/review`) implementing the operator review queue, per-vendor submission gatekeeper, and vendor abuse-reporting adapters (AbuseIPDB, DShield, OTX) - testable end-to-end against a real PostgreSQL database with mocked vendor APIs.

**Architecture:** The review crate reads ip_score projections from core-scoring's database tables, surfaces recommended IPs in a review_queue table, and submits operator-approved reports through a gatekeeper that enforces per-vendor cooldown, rate limits, and category filters. Each vendor adapter implements a common trait. The binary runs as a submission daemon + CLI. Canonical spec: `internal/design/04-review-gatekeeper-reporting.md`.

**Tech Stack:** Rust (2024 edition), `core-scoring` (ip_score projection, domain types), `sqlx` (PostgreSQL + migrations), `reqwest` (vendor API calls, with rustls-tls), `tokio` (async runtime), `serde`/`serde_json`, `tracing`, `clap` (CLI argument parsing).

## File Structure

```
crates/review/
  Cargo.toml
  migrations/
    0001_review_queue.sql
    0002_vendor_submission.sql
  src/
    lib.rs              # public API re-exports
    queue.rs            # ReviewQueue - state machine, population, withdrawal, decisions
    gatekeeper.rs       # Gatekeeper - per-vendor check sequence
    submit.rs           # SubmissionRunner - poll approved, submit through gatekeeper
    vendor/
      mod.rs            # VendorAdapter trait, VendorReport, category mapping
      abuseipdb.rs      # AbuseIPDB REST adapter
      dshield.rs        # DShield HTTP adapter
      otx.rs            # OTX pulse adapter
    cli.rs              # CLI for operator decisions (approve/reject/snooze/list)
    main.rs             # binary entry point (daemon mode + CLI dispatch)
  tests/
    queue_test.rs       # state machine, population, withdrawal
    gatekeeper_test.rs  # check sequence, cooldown, rate limit, fail-closed
    submit_test.rs      # end-to-end with mock vendor
    vendor_test.rs      # category mapping, payload construction
```

## Global Constraints

- **Language:** Rust 2024 edition. New crate at `crates/review`.
- **Dependencies:** pin versions, review Cargo.lock diff. `reqwest` with `rustls-tls` feature (no OpenSSL dependency). Re-vendor after adding the crate.
- **Database:** this crate reads ip_score (from core-scoring's tables) and writes review_queue + vendor_submission (its own migrations). Same PostgreSQL database.
- **Human-approval gate:** NOTHING auto-fires. The submission daemon processes ONLY Approved entries. No auto-approve, no timeout-to-approve, no bulk-approve-by-score.
- **Fail closed:** gatekeeper checks deny on missing config, DB error, or unreadable input.
- **API keys:** read from environment variables, NEVER logged, NEVER stored in any database field or event.
- **Tests require PostgreSQL.** Same `propolis-pg` container as SP1/SP3.
- **Vendor API calls are mocked in tests.** No real vendor API calls from the test suite.
- **IP addresses in tests:** RFC5737/RFC1918.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: Crate scaffold + migrations + review queue

**Files:**
- Create: `crates/review/Cargo.toml`, `crates/review/src/lib.rs`, `crates/review/src/queue.rs`, `crates/review/migrations/0001_review_queue.sql`, `crates/review/migrations/0002_vendor_submission.sql`
- Modify: `Cargo.toml` (add `review` to workspace members)
- Test: `crates/review/tests/queue_test.rs`

**Interfaces:**
- Consumes: `core_scoring::{IpScore, ReviewState}`, `sqlx::PgPool`.
- Produces: `ReviewQueue::populate(&self, pool) -> Result<usize>` (scans ip_score, inserts Pending entries), `ReviewQueue::withdraw(&self, pool) -> Result<usize>` (removes Pending entries for IPs no longer recommended/eligible), `ReviewQueue::approve(pool, ip, notes) -> Result<()>`, `ReviewQueue::reject(pool, ip, notes) -> Result<()>`, `ReviewQueue::snooze(pool, ip, notes) -> Result<()>`, `ReviewQueue::list_pending(pool) -> Result<Vec<QueueEntry>>`, `QueueEntry` struct.

- [ ] **Step 1: Write the failing test**

```rust
// crates/review/tests/queue_test.rs
use review::queue::*;
use sqlx::PgPool;
use std::net::IpAddr;

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    // Run core-scoring migrations first (ip_score table must exist).
    sqlx::migrate!("../core-scoring/migrations").run(&pool).await.unwrap();
    // Then review migrations.
    sqlx::migrate!().run(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn populate_surfaces_recommended_ip() {
    let pool = setup_pool().await;
    // Insert a recommended ip_score (use core_scoring::append_event or direct SQL).
    // ... (build an IP with recommended_for_vendor = true, eligible = true)
    let queue = ReviewQueue::new();
    let count = queue.populate(&pool).await.unwrap();
    assert!(count >= 1);
    let entries = queue.list_pending(&pool).await.unwrap();
    assert!(entries.iter().any(|e| e.source_ip == test_ip));
}

#[tokio::test]
async fn withdraw_removes_ineligible_pending_entry() {
    let pool = setup_pool().await;
    // Surface an IP, then update ip_score to eligible = false.
    // Run withdraw, verify the Pending entry is removed.
}

#[tokio::test]
async fn approve_sets_state_and_decided_at() {
    let pool = setup_pool().await;
    // Surface an IP, then approve it.
    queue.approve(&pool, test_ip, Some("looks malicious")).await.unwrap();
    // Verify state = Approved, decided_at is set.
}

#[tokio::test]
async fn reject_prevents_resurfacing() {
    let pool = setup_pool().await;
    // Surface, reject, run populate again. Verify no new Pending entry.
}

#[tokio::test]
async fn duplicate_populate_is_idempotent() {
    let pool = setup_pool().await;
    // Populate twice. Verify only one entry per IP.
}
```

Note: the exact test code depends on how ip_score rows are seeded. The implementer should use `core_scoring::append_event` to build real scores, or direct SQL INSERT into ip_score with the required fields. Use unique source IPs per test. Run with `--test-threads=1`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p review --test queue_test -- --test-threads=1`
Expected: FAIL - crate does not exist.

- [ ] **Step 3: Write minimal implementation**

Add `"crates/review"` to workspace `Cargo.toml` members.

`Cargo.toml` dependencies: `core-scoring` (path), `sqlx` (with postgres + runtime-tokio + macros + chrono), `tokio`, `serde`/`serde_json`, `tracing`, `rust_decimal`, `chrono`, `thiserror`. Dev: `tempfile`.

Write both migration SQL files per the spec. `queue.rs`: implement the populate scan (INSERT ... SELECT from ip_score WHERE recommended_for_vendor AND eligible AND NOT IN review_queue), withdraw scan (DELETE FROM review_queue WHERE state = 'pending' AND source_ip NOT IN eligible+recommended), and the three operator actions (UPDATE state, decided_at).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p review --test queue_test -- --test-threads=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/review
git commit -m "feat(review): scaffold crate with migrations and review queue state machine"
```

---

### Task 2: Gatekeeper

**Files:**
- Create: `crates/review/src/gatekeeper.rs`
- Modify: `crates/review/src/lib.rs`
- Test: `crates/review/tests/gatekeeper_test.rs`

**Interfaces:**
- Consumes: `sqlx::PgPool`, `VendorConfig`.
- Produces: `Gatekeeper::check(pool, ip, vendor_config, current_score) -> Result<GateResult>`, `GateResult::Pass | GateResult::Held(reason)`, `GateReason` enum (Disabled, Cooldown, RateLimit, ScoreFloor, CategoryFilter, DbError).

- [ ] **Step 1-5:** Follow the same TDD pattern. Test each check individually:
- Vendor disabled -> Held(Disabled)
- Within cooldown -> Held(Cooldown)
- Rate limit exceeded -> Held(RateLimit)
- Score below floor -> Held(ScoreFloor)
- No matching category -> Held(CategoryFilter)
- All checks pass -> Pass
- DB error during check -> Held(DbError) (fail-closed)

---

### Task 3: Vendor adapters + category mapping

**Files:**
- Create: `crates/review/src/vendor/mod.rs`, `crates/review/src/vendor/abuseipdb.rs`, `crates/review/src/vendor/dshield.rs`, `crates/review/src/vendor/otx.rs`
- Modify: `crates/review/src/lib.rs`
- Test: `crates/review/tests/vendor_test.rs`

**Interfaces:**
- Consumes: `reqwest::Client`, `VendorConfig`.
- Produces: `VendorAdapter` trait (`name() -> &str`, `submit(report) -> Result<VendorResponse>`), `VendorReport` struct, `build_categories(protocol_label, category) -> Vec<String>`, `AbuseIpDb`, `DShield`, `OtxAdapter` structs implementing the trait.

- [ ] **Step 1-5:** TDD. Tests use a mock HTTP server (e.g., `wiremock` or a simple tokio TCP listener that returns canned responses) to verify:
- AbuseIPDB payload contains correct categories, IP, comment
- DShield payload contains IP, port, protocol
- OTX payload creates a pulse with correct indicators
- Category mapping: ssh -> 22, telnet -> 23, ftp -> 5, generic -> 14
- "Already reported" response treated as success
- Transient error (5xx) returns Err (retried by caller)
- Permanent error (4xx) returns Err with permanent flag

Add `reqwest` (with `rustls-tls`) and a mock HTTP dependency (e.g., `wiremock`) to Cargo.toml.

---

### Task 4: Submission runner

**Files:**
- Create: `crates/review/src/submit.rs`
- Modify: `crates/review/src/lib.rs`
- Test: `crates/review/tests/submit_test.rs`

**Interfaces:**
- Consumes: `ReviewQueue` (Task 1), `Gatekeeper` (Task 2), `VendorAdapter` (Task 3), `sqlx::PgPool`.
- Produces: `SubmissionRunner::new(pool, vendors, gatekeeper_config) -> Self`, `SubmissionRunner::run_once(&self) -> Result<SubmitResult>`, `SubmitResult { submitted: usize, held: usize, failed: usize }`.

- [ ] **Step 1-5:** TDD. The submission runner:
- Reads Approved entries from review_queue
- For each, reads current ip_score (decayed to now)
- Runs gatekeeper checks for each configured vendor
- If all checks pass, builds VendorReport and calls adapter.submit()
- Records result in vendor_submission table with idempotency key
- Tests: end-to-end with real DB + mock vendor. Verify idempotency (same key no double-submit). Verify held entries are not submitted. Verify failed submissions are recorded.

---

### Task 5: CLI + binary composition

**Files:**
- Create: `crates/review/src/cli.rs`, `crates/review/src/main.rs`
- Test: CLI is tested via the binary with `--help` and integration tests

**Interfaces:**
- Consumes: all previous tasks.
- Produces: `review` binary with subcommands: `daemon` (run submission loop), `approve <ip>`, `reject <ip>`, `snooze <ip>`, `list` (show pending queue), `history <ip>` (show submission history).

- [ ] **Step 1-5:** TDD. Add `clap` dependency. The main.rs dispatches to daemon mode or CLI subcommand. CLI operations are thin wrappers around ReviewQueue methods. The daemon mode runs a loop: populate queue, withdraw ineligible, submit approved, sleep.

---

### Task 6: Deployment + re-vendor

**Files:**
- Create: `deploy/review.service`
- Modify: `crates/sensor-framework/tests/deploy_test.rs` (add review unit test)
- Re-vendor: `cargo vendor`

- [ ] **Step 1-5:** Create the hardened systemd unit (same pattern as intake.service). The review service needs:
- Database access (EnvironmentFile with DATABASE_URL + API keys)
- Outbound HTTPS (for vendor API calls) - `RestrictAddressFamilies=AF_INET AF_INET6`
- No inbound ports
- No sensor log access (reads only from the database)
- MemoryDenyWriteExecute=yes (correct spelling)

Re-vendor after all dependencies are added. Commit vendor changes separately.
