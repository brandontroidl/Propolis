# Runtime Composition + Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 7 - a unified daemon crate (`crates/propolis`) that composes intake, review, feed, and console into one process with shared PgPool, per-subsystem restart-on-panic, graceful shutdown, and unified config. Plus a hardened systemd unit and an install script for fresh-node provisioning.

**Architecture:** The daemon imports the four backend crates as libraries and runs their core loops as concurrent tokio tasks. Sensors stay as separate processes/services. One EnvironmentFile configures everything. A CancellationToken coordinates graceful shutdown. A supervisor wrapper restarts panicked subsystems with exponential backoff. Canonical spec: `internal/design/07-runtime-coordination-deployment.md`.

**Tech Stack:** Rust (2024 edition), `intake` (library), `review` (library), `feed` (library), `console` (library), `core-scoring` (library), `sqlx` (PgPool), `tokio` (tasks, signal, time), `tokio-util` (CancellationToken), `tracing`+`tracing-subscriber`.

## File Structure

```
crates/propolis/
  Cargo.toml
  src/
    main.rs             # entry point: config, PgPool, spawn subsystems, signal handler
    config.rs           # PropolisConfig parsed from env, validated fail-fast
    supervisor.rs       # spawn_supervised() - restart-on-panic with exponential backoff
  tests/
    smoke_test.rs       # start daemon, verify /health + /ready + cursor files

deploy/
  propolis.service      # hardened unified systemd unit
  install.sh            # idempotent fresh-node provisioning script
```

## Global Constraints

- **Rust 2024 edition.** New crate at `crates/propolis`.
- **No new library functionality.** This crate composes existing APIs. If an existing crate's library API is insufficient (e.g., missing a public function the daemon needs), extend that crate's `lib.rs` - do not reimplement the logic in propolis.
- **Fail fast on config error.** Missing required env vars, invalid values, and DB connection failure at startup all produce a diagnostic message and exit code 1. No retry-forever on a missing database.
- **Graceful shutdown.** SIGTERM/SIGINT -> CancellationToken -> all subsystems drain and stop.
- **Sensors stay separate.** The daemon does not start or manage sensor processes. Those are independent systemd services.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: Unified daemon + config + supervisor

**Files:**
- Create: `crates/propolis/Cargo.toml`, `crates/propolis/src/main.rs`, `crates/propolis/src/config.rs`, `crates/propolis/src/supervisor.rs`
- Modify: `Cargo.toml` (add `propolis` to workspace members)
- Possibly modify: library crates (intake, review, feed, console) if their APIs need minor extensions to be callable from the daemon
- Test: `crates/propolis/tests/smoke_test.rs`

**Interfaces:**
- Consumes: `intake::{LogTailer, IntakeRunner}`, `review::{ReviewQueue, SubmissionRunner, vendor::*}`, `feed::{FeedBuilder, ExclusionEngine, Publisher}`, `console::routes::*` + `console::auth::*`, `core_scoring`, `sqlx::PgPool`.
- Produces: `PropolisConfig` (parsed from env, all fields validated), `spawn_supervised(name, future, cancel_token) -> JoinHandle` (restart-on-panic with backoff), the `propolis` binary.

**Config (PropolisConfig):**
```rust
pub struct PropolisConfig {
    // Database
    pub database_url: String,
    pub db_max_connections: u32,        // default 10
    // Intake
    pub sensor_logs: Vec<SensorLogConfig>,
    pub cursor_dir: PathBuf,
    pub poll_interval: Duration,
    // Review
    pub review_enabled: bool,           // default true
    pub queue_scan_interval: Duration,
    pub submit_poll_interval: Duration,
    pub vendors: Vec<FullVendorConfig>,
    // Feed
    pub feed_enabled: bool,             // default true
    pub feed_output_dir: PathBuf,
    pub feed_build_interval: Duration,
    pub feed_aggressive_ttl: Duration,
    pub feed_standard_ttl: Duration,
    pub feed_allowlist: Vec<IpNet>,
    pub feed_delist: Vec<IpAddr>,
    // Console
    pub console_bind: SocketAddr,       // default 127.0.0.1:8080
    pub console_password: String,
    pub console_session_secret: Option<[u8; 32]>,
}
```

**Supervisor (spawn_supervised):**
```rust
pub fn spawn_supervised<F, Fut>(
    name: &'static str,
    cancel: CancellationToken,
    factory: F,
) -> JoinHandle<()>
where
    F: Fn(CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
```

The supervisor spawns `factory(cancel.child_token())` as a tokio task. If the task panics, it logs the panic, waits `backoff` (1s, 2s, 4s, 8s, 16s, cap 60s), and respawns. After 3 consecutive panics within 60 seconds, it stops restarting and logs an alert. The failure counter resets after 5 minutes of healthy operation.

**main.rs orchestration:**
1. Initialize tracing (JSON in production, human-readable if `RUST_LOG` is set)
2. Parse and validate PropolisConfig from env (fail fast)
3. Connect PgPool (fail fast on connection error)
4. Run database migrations (core-scoring + review)
5. Spawn all four subsystems via spawn_supervised
6. Wait for shutdown signal (SIGTERM/SIGINT)
7. Cancel the CancellationToken
8. Await all subsystem JoinHandles with a timeout (30s)
9. Exit

**Smoke test:**
- Start the daemon against the test database
- Verify `/health` returns 200
- Verify `/ready` returns 200
- Verify cursor directory was created
- Send SIGTERM, verify clean exit

**Important:** each existing crate's library API may need small extensions:
- `intake`: the `IntakeRunner` currently has a synchronous `run_batch()`. The daemon needs a loop wrapper that polls and respects the CancellationToken.
- `review`: the standalone binary's daemon loop (populate + withdraw + submit) needs to be extractable as a library function.
- `feed`: the standalone binary's build loop needs to be extractable.
- `console`: the router builder needs to be callable from outside the crate's own main.rs.

Read each crate's `main.rs` and `lib.rs` to understand what's already public and what needs exposing. Make minimal extensions - add `pub` to existing functions or extract a loop body into a library function. Do not restructure.

- [ ] **Step 1: Write the failing test**

The smoke test starts the daemon and checks endpoints. Write it first, then implement config + supervisor + main.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p propolis --test smoke_test -- --test-threads=1`
Expected: FAIL - crate does not exist.

- [ ] **Step 3: Write implementation**

Create the crate, implement config parsing, supervisor, and main.rs orchestration. Extend library crates as needed (minimal changes).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p propolis --test smoke_test -- --test-threads=1`
Expected: PASS.

Also run the full workspace gate: `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked -- --test-threads=1`

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(propolis): unified daemon composing intake, review, feed, and console"
```

---

### Task 2: Deployment unit + install script

**Files:**
- Create: `deploy/propolis.service`, `deploy/install.sh`
- Modify: `crates/sensor-framework/tests/deploy_test.rs` (add propolis unit test)
- Test: deploy test assertions + install script dry-run test

**Interfaces:**
- Produces: hardened systemd unit, idempotent install script.

**propolis.service:** per the spec - User=propolis, EnvironmentFile, ReadOnlyPaths for sensor logs, ReadWritePaths for cursors/feed/spool, MemoryMax=1G, TasksMax=256, MemoryDenyWriteExecute=yes, SystemCallFilter placeholder.

**install.sh:**
1. Create users (propolis, propolis-catchall, propolis-ssh)
2. Create directories (/var/log/propolis/{catchall,ssh}/, /var/lib/propolis/{cursors,feed,spool}/, /etc/propolis/)
3. Set ownership and permissions
4. Set up spool as noexec mount (or document how to)
5. Install binaries to /usr/local/bin/
6. Install systemd units
7. Install logrotate config
8. systemctl daemon-reload

The script is idempotent. It does NOT start services or create the database.

**Deploy test:** assert the propolis.service unit has all required hardening directives (same pattern as existing deploy_test.rs).

- [ ] **Step 1-5:** TDD. Write deploy test first, then create the unit and install script.

```bash
git commit -m "feat(deploy): unified propolis service unit and install script"
```

---

### Task 3: Re-vendor + integration verification

**Files:**
- Modify: `Cargo.lock`, `vendor/` (via cargo vendor)

**This task:**
1. Re-vendor after the new crate is added: `cargo vendor`
2. Run the full workspace gate one final time
3. Verify the `propolis` binary compiles and starts
4. Commit vendor changes separately

- [ ] **Step 1-5:**

```bash
# Re-vendor
cargo vendor

# Verify
cargo build -p propolis
cargo test --workspace --locked -- --test-threads=1

# Commit
git commit -m "build: re-vendor after adding propolis unified daemon"
```
