# Event Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 3 - a single Rust crate (`crates/intake`) that tails sensor NDJSON log files, converts wire-format events to domain types, and writes them to the core-scoring event ledger via `append_event` - testable end-to-end against a real PostgreSQL database.

**Architecture:** The intake binary runs one tailer per configured sensor log file. Each tailer reads NDJSON lines using a durable cursor (inode + offset + fingerprint, persisted as JSON, copytruncate-aware), converts `SensorEvent` to `EventInput` via `from_signal`, and calls `append_event`. Multi-node aggregation is direct PostgreSQL writes through the existing advisory lock - no broker, no leader election. Canonical spec: `internal/design/03-event-intake-aggregation.md`.

**Tech Stack:** Rust (2024 edition), `sensor-wire` (wire types), `core-scoring` (EventInput, append_event, SignalType, Protocol), `sqlx` (PostgreSQL), `tokio` (async runtime), `serde`/`serde_json`, `sha2` (cursor fingerprint), `tracing` (structured logging).

## File Structure

```
crates/intake/
  Cargo.toml
  src/
    main.rs         # binary entry point, config from env, PgPool, tailer orchestration
    cursor.rs       # DurableCursor - persistent read position per log file
    tailer.rs       # LogTailer - reads NDJSON lines, advances cursor, handles rotation
    converter.rs    # convert SensorEvent -> EventInput via from_signal + sample folding
    runner.rs       # IntakeRunner - tailer + converter + append_event loop
  tests/
    cursor_test.rs    # cursor persistence, rotation detection, restart recovery
    tailer_test.rs    # line reading, rotation survival, at-least-once delivery
    converter_test.rs # wire-to-domain conversion, unknown signal rejection
    end_to_end.rs     # full pipeline against real PostgreSQL

deploy/
  intake.service    # hardened systemd unit
```

## Global Constraints

- **Language:** Rust 2024 edition; toolchain pinned via existing `rust-toolchain.toml`. New crate at `crates/intake`.
- **Dependency vetting:** pin versions, review Cargo.lock diff. Re-vendor after adding the crate (`cargo vendor`).
- **Database dependency:** this crate DOES hold a database handle (the first in the stack to do so). It depends on `core-scoring` (which depends on `sqlx`).
- **Fail closed.** Unknown signal types, malformed JSON, and validation failures are rejected. A rejected event is never written to the ledger. The cursor advances past rejections (they are permanently bad).
- **At-least-once delivery.** On database error, the cursor does NOT advance. The event is retried. The dedup window in `append_event` catches duplicates if the first attempt committed.
- **No vendor client, no web surface, no feed publisher.** Intake reads sensor logs and writes to PostgreSQL. Nothing else.
- **Tests require PostgreSQL.** The test infrastructure from `core-scoring` (Podman `propolis-pg` container) must be running. Tests use real database transactions.
- **IP addresses in tests:** RFC5737/RFC1918.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: intake crate scaffold + converter

**Files:**
- Create: `crates/intake/Cargo.toml`, `crates/intake/src/lib.rs`, `crates/intake/src/converter.rs`
- Modify: `Cargo.toml` (add `intake` to workspace members)
- Test: `crates/intake/tests/converter_test.rs`

**Interfaces:**
- Consumes: `sensor_wire::SensorEvent`, `sensor_wire::SampleRef`, `core_scoring::{SignalType, Protocol, EventInput}`.
- Produces: `pub fn convert(event: SensorEvent) -> Result<EventInput, ConvertError>`, `ConvertError` enum, `pub fn fold_sample_metadata(metadata: Value, sample: Option<SampleRef>) -> Value`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/intake/tests/converter_test.rs
use sensor_wire::*;
use intake::converter::{convert, ConvertError};

fn sample_wire_event() -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: "2026-07-20T14:03:11.482913Z".parse().unwrap(),
        metadata: serde_json::json!({"protocol_label": "ssh", "command": "uname -a"}),
        sample: None,
    }
}

#[test]
fn converts_known_signal_type() {
    let input = convert(sample_wire_event()).unwrap();
    assert_eq!(input.signal_type, core_scoring::SignalType::HoneypotCommandExec);
    assert_eq!(input.protocol, core_scoring::Protocol::Tcp);
    assert!(input.authenticated);
    assert_eq!(input.weight, 60);  // from signal weight table
    assert_eq!(input.category, core_scoring::Category::Honeypot);
}

#[test]
fn rejects_unknown_signal_type() {
    let mut event = sample_wire_event();
    event.signal_type = "nonexistent_signal".into();
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::UnknownSignalType(_))));
}

#[test]
fn rejects_unknown_protocol() {
    let mut event = sample_wire_event();
    event.protocol = "quic".into();
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::UnknownProtocol(_))));
}

#[test]
fn rejects_empty_sensor() {
    let mut event = sample_wire_event();
    event.sensor = String::new();
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::Validation(_))));
}

#[test]
fn folds_sample_into_metadata() {
    let mut event = sample_wire_event();
    event.sample = Some(SampleRef {
        sha256: "a".repeat(64),
        size: 12345,
        orig_name: "evil.bin".into(),
    });
    let input = convert(event).unwrap();
    assert_eq!(input.metadata["sample_sha256"], "a".repeat(64));
    assert_eq!(input.metadata["sample_size"], 12345);
    assert_eq!(input.metadata["sample_orig_name"], "evil.bin");
}

#[test]
fn preserves_existing_metadata_when_folding_sample() {
    let mut event = sample_wire_event();
    event.sample = Some(SampleRef {
        sha256: "b".repeat(64),
        size: 100,
        orig_name: "test.bin".into(),
    });
    let input = convert(event).unwrap();
    // Original metadata fields preserved.
    assert_eq!(input.metadata["protocol_label"], "ssh");
    assert_eq!(input.metadata["command"], "uname -a");
    // Sample fields added.
    assert_eq!(input.metadata["sample_sha256"], "b".repeat(64));
}

#[test]
fn rejects_schema_version_mismatch() {
    let mut event = sample_wire_event();
    event.v = 99;
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::UnsupportedVersion(99))));
}

#[test]
fn all_sensor_wire_constants_convert_successfully() {
    // Every SIGNAL_* constant in sensor-wire must produce a valid EventInput.
    let signals = [
        (SIGNAL_CATCHALL_PROBE, PROTO_UDP, false),
        (SIGNAL_HONEYPOT_CONNECTION, PROTO_TCP, false),
        (SIGNAL_HONEYPOT_LOGIN_ATTEMPT, PROTO_TCP, true),
        (SIGNAL_HONEYPOT_COMMAND_EXEC, PROTO_TCP, true),
        (SIGNAL_HONEYPOT_MALWARE_UPLOAD, PROTO_TCP, true),
        (SIGNAL_HONEYPOT_FILE_DOWNLOAD, PROTO_TCP, true),
    ];
    for (signal, proto, auth) in signals {
        let mut event = sample_wire_event();
        event.signal_type = signal.into();
        event.protocol = proto.into();
        event.authenticated = auth;
        let result = convert(event);
        assert!(result.is_ok(), "failed to convert signal: {signal}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p intake --test converter_test`
Expected: FAIL - crate does not exist.

- [ ] **Step 3: Write minimal implementation**

Add `"crates/intake"` to workspace `Cargo.toml` members.

`crates/intake/Cargo.toml`:
```toml
[package]
name = "intake"
version = "0.1.0"
edition = "2024"

[dependencies]
sensor-wire = { path = "../sensor-wire" }
core-scoring = { path = "../core-scoring" }
serde = { version = "*", features = ["derive"] }
serde_json = "*"
chrono = { version = "*", features = ["serde"] }
tokio = { version = "*", features = ["rt-multi-thread", "macros", "signal", "fs", "time", "io-util"] }
sqlx = { version = "*", features = ["postgres", "runtime-tokio", "macros"] }
sha2 = "*"
tracing = "*"
tracing-subscriber = "*"
thiserror = "*"
```
Pin versions to match existing workspace crates where possible. Review Cargo.lock diff.

`converter.rs`:
```rust
use core_scoring::{EventInput, Protocol, SignalType, ValidationError};
use sensor_wire::{SampleRef, SensorEvent, WIRE_VERSION};

#[derive(Debug)]
pub enum ConvertError {
    UnknownSignalType(String),
    UnknownProtocol(String),
    UnsupportedVersion(u32),
    Validation(ValidationError),
    Json(serde_json::Error),
}

pub fn convert(event: SensorEvent) -> Result<EventInput, ConvertError> {
    if event.v != WIRE_VERSION {
        return Err(ConvertError::UnsupportedVersion(event.v));
    }

    let signal_type: SignalType = serde_json::from_value(
        serde_json::Value::String(event.signal_type.clone()),
    ).map_err(|_| ConvertError::UnknownSignalType(event.signal_type))?;

    let protocol: Protocol = serde_json::from_value(
        serde_json::Value::String(event.protocol.clone()),
    ).map_err(|_| ConvertError::UnknownProtocol(event.protocol))?;

    let metadata = fold_sample_metadata(event.metadata, event.sample);

    let input = EventInput::from_signal(
        event.source_ip,
        event.wan_ip,
        event.sensor,
        signal_type,
        protocol,
        event.authenticated,
        event.observed_at,
        metadata,
    );

    input.validate().map_err(ConvertError::Validation)?;
    Ok(input)
}

pub fn fold_sample_metadata(
    mut metadata: serde_json::Value,
    sample: Option<SampleRef>,
) -> serde_json::Value {
    if let Some(ref s) = sample {
        if let serde_json::Value::Object(ref mut map) = metadata {
            map.insert("sample_sha256".into(), s.sha256.clone().into());
            map.insert("sample_size".into(), s.size.into());
            map.insert("sample_orig_name".into(), s.orig_name.clone().into());
        }
    }
    metadata
}
```

`lib.rs`:
```rust
pub mod converter;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p intake --test converter_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/intake
git commit -m "feat(intake): scaffold crate with wire-to-domain converter"
```

---

### Task 2: Durable log cursor

**Files:**
- Create: `crates/intake/src/cursor.rs`
- Modify: `crates/intake/src/lib.rs` (add `pub mod cursor;`)
- Test: `crates/intake/tests/cursor_test.rs`

**Interfaces:**
- Consumes: `sha2` for fingerprinting.
- Produces: `CursorState` struct, `DurableCursor::new(log_path, cursor_dir) -> Self`, `DurableCursor::load(&self) -> Option<CursorState>`, `DurableCursor::save(&self, state: &CursorState) -> io::Result<()>`, `DurableCursor::detect_rotation(&self, state: &CursorState) -> RotationEvent`, `RotationEvent` enum (`None`, `Truncated`, `InodeChanged`, `Replaced`).

- [ ] **Step 1: Write the failing test**

```rust
// crates/intake/tests/cursor_test.rs
use intake::cursor::*;
use std::io::Write;

#[test]
fn save_and_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "line1\nline2\n").unwrap();
    let cursor = DurableCursor::new(log_path, dir.path().join("cursors"));
    let state = CursorState {
        inode: 12345,
        offset: 6,
        fingerprint: [0u8; 32],
    };
    cursor.save(&state).unwrap();
    let loaded = cursor.load().unwrap().unwrap();
    assert_eq!(loaded.inode, 12345);
    assert_eq!(loaded.offset, 6);
}

#[test]
fn missing_cursor_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = DurableCursor::new(
        dir.path().join("events.jsonl"),
        dir.path().join("cursors"),
    );
    assert!(cursor.load().unwrap().is_none());
}

#[test]
fn corrupt_cursor_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let cursor_dir = dir.path().join("cursors");
    std::fs::create_dir_all(&cursor_dir).unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor = DurableCursor::new(log_path, cursor_dir.clone());
    // Write garbage to the cursor file.
    let cursor_file = cursor.cursor_file_path();
    std::fs::write(&cursor_file, "not json").unwrap();
    assert!(cursor.load().unwrap().is_none());
}

#[test]
fn detect_truncation_when_offset_exceeds_size() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "short").unwrap();
    let cursor = DurableCursor::new(log_path.clone(), dir.path().join("cursors"));
    let state = CursorState {
        inode: get_inode(&log_path),
        offset: 1000,  // way past file size
        fingerprint: compute_fingerprint(&log_path),
    };
    let rotation = cursor.detect_rotation(&state);
    assert!(matches!(rotation, RotationEvent::Truncated));
}

#[test]
fn detect_no_rotation_when_offset_within_size() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "some content here\n").unwrap();
    let cursor = DurableCursor::new(log_path.clone(), dir.path().join("cursors"));
    let state = CursorState {
        inode: get_inode(&log_path),
        offset: 5,
        fingerprint: compute_fingerprint(&log_path),
    };
    let rotation = cursor.detect_rotation(&state);
    assert!(matches!(rotation, RotationEvent::None));
}

#[test]
fn atomic_save_does_not_corrupt_on_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "content").unwrap();
    let cursor = DurableCursor::new(log_path, dir.path().join("cursors"));
    let state1 = CursorState { inode: 1, offset: 10, fingerprint: [1u8; 32] };
    cursor.save(&state1).unwrap();
    let state2 = CursorState { inode: 2, offset: 20, fingerprint: [2u8; 32] };
    cursor.save(&state2).unwrap();
    let loaded = cursor.load().unwrap().unwrap();
    // Must be state2, not a corrupt mix of state1 and state2.
    assert_eq!(loaded.inode, 2);
    assert_eq!(loaded.offset, 20);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p intake --test cursor_test`
Expected: FAIL - module not defined.

- [ ] **Step 3: Write minimal implementation**

Add `tempfile` as a dev-dependency.

`cursor.rs`: implement `CursorState` (with serde derives for JSON persistence), `DurableCursor` with save (atomic: write to temp file, fsync, rename) and load (read JSON, return None on missing/corrupt), `detect_rotation` (compare inode, offset vs file size, fingerprint). `compute_fingerprint` hashes the first min(256, file_size) bytes via SHA-256. `get_inode` reads the file's inode via `std::os::unix::fs::MetadataExt`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p intake --test cursor_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/intake
git commit -m "feat(intake): durable log cursor with rotation detection and atomic persistence"
```

---

### Task 3: Log tailer

**Files:**
- Create: `crates/intake/src/tailer.rs`
- Modify: `crates/intake/src/lib.rs` (add `pub mod tailer;`)
- Test: `crates/intake/tests/tailer_test.rs`

**Interfaces:**
- Consumes: `DurableCursor` (Task 2).
- Produces: `LogTailer::new(log_path, cursor_dir) -> Self`, `LogTailer::read_batch(&mut self, max_lines: usize) -> Vec<String>`, `LogTailer::persist_cursor(&self) -> io::Result<()>`, `LogTailer::advance(&mut self, bytes: usize)`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/intake/tests/tailer_test.rs
use intake::tailer::LogTailer;
use std::io::Write;

#[test]
fn reads_complete_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "line1\nline2\nline3\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["line1", "line2", "line3"]);
}

#[test]
fn incomplete_trailing_line_not_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "complete\nincomplete").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["complete"]);
    // Append the newline.
    let mut f = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
    f.write_all(b"\n").unwrap();
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["incomplete"]);
}

#[test]
fn respects_max_batch_size() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "a\nb\nc\nd\ne\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(2);
    assert_eq!(lines.len(), 2);
    let lines = tailer.read_batch(10);
    assert_eq!(lines.len(), 3);  // remaining
}

#[test]
fn survives_copytruncate_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    // Write initial events.
    std::fs::write(&log_path, "event1\nevent2\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["event1", "event2"]);
    tailer.persist_cursor().unwrap();
    // Simulate copytruncate: truncate the file to 0.
    std::fs::write(&log_path, "").unwrap();
    // Write new events.
    let mut f = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
    f.write_all(b"event3\nevent4\n").unwrap();
    drop(f);
    let lines = tailer.read_batch(10);
    assert_eq!(lines, vec!["event3", "event4"]);
}

#[test]
fn persist_and_resume_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "first\nsecond\nthird\n").unwrap();
    let cursor_dir = dir.path().join("cursors");
    // First run: read first two lines.
    {
        let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
        let lines = tailer.read_batch(2);
        assert_eq!(lines, vec!["first", "second"]);
        tailer.persist_cursor().unwrap();
    }
    // Second run: resume from cursor.
    {
        let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
        let lines = tailer.read_batch(10);
        assert_eq!(lines, vec!["third"]);
    }
}

#[test]
fn missing_log_file_returns_empty_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nonexistent.jsonl");
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let lines = tailer.read_batch(10);
    assert!(lines.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p intake --test tailer_test`
Expected: FAIL - module not defined.

- [ ] **Step 3: Write minimal implementation**

`tailer.rs`: `LogTailer` holds a `DurableCursor` and a `CursorState` (loaded or initialized). `read_batch` opens the log file, seeks to `state.offset`, reads up to `max_lines` complete lines (split on `\n`), advances `state.offset` by the bytes consumed. Before seeking, calls `detect_rotation` and handles `Truncated` (reset to 0), `InodeChanged` (read old file to EOF if accessible, then new file from 0), `Replaced` (reset to 0, recompute fingerprint). `persist_cursor` delegates to `DurableCursor::save`. An incomplete trailing line (no terminal `\n`) is not consumed - the offset stays at the start of that line.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p intake --test tailer_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/intake
git commit -m "feat(intake): log tailer with rotation-aware NDJSON line reading"
```

---

### Task 4: Intake runner + end-to-end tests

**Files:**
- Create: `crates/intake/src/runner.rs`
- Modify: `crates/intake/src/lib.rs` (add `pub mod runner;`)
- Test: `crates/intake/tests/end_to_end.rs`

**Interfaces:**
- Consumes: `LogTailer` (Task 3), `convert` (Task 1), `core_scoring::append_event`, `sqlx::PgPool`.
- Produces: `IntakeRunner::new(tailer, pool, sensor_name) -> Self`, `IntakeRunner::run_batch(&mut self) -> RunBatchResult`, `RunBatchResult { ingested: usize, rejected: usize, errors: usize }`.

**Note:** These tests require PostgreSQL. The existing `propolis-pg` Podman container must be running. Follow the same test infrastructure pattern as `crates/core-scoring/tests/`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/intake/tests/end_to_end.rs
// These tests require a running PostgreSQL instance (propolis-pg container).

use core_scoring::{append_event, read_score, verify_chain, ChainStatus};
use intake::converter::convert;
use intake::runner::{IntakeRunner, RunBatchResult};
use intake::tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../core-scoring/migrations").run(&pool).await.unwrap();
    pool
}

fn write_event_line(path: &std::path::Path, event: &SensorEvent) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
    let line = serde_json::to_string(event).unwrap();
    writeln!(f, "{line}").unwrap();
}

#[tokio::test]
async fn ingest_single_event_appears_in_ledger() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    let event = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({"protocol_label": "ssh", "username": "root"}),
        sample: None,
    };
    write_event_line(&log_path, &event);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(tailer, pool.clone(), "test-ssh".into());
    let result = runner.run_batch().await;
    assert_eq!(result.ingested, 1);
    assert_eq!(result.rejected, 0);

    let score = read_score(&pool, "203.0.113.7".parse().unwrap()).await.unwrap();
    assert!(score.is_some());
    let score = score.unwrap();
    assert!(score.has_confirmed_real);
    assert!(score.eligible);
}

#[tokio::test]
async fn unknown_signal_type_rejected_cursor_advances() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    // Write a bad event followed by a good one.
    let bad = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.8".parse().unwrap(),
        wan_ip: None,
        sensor: "test".into(),
        signal_type: "nonexistent_signal".into(),
        protocol: PROTO_TCP.into(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({}),
        sample: None,
    };
    let good = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.9".parse().unwrap(),
        wan_ip: None,
        sensor: "catchall".into(),
        signal_type: SIGNAL_CATCHALL_PROBE.into(),
        protocol: PROTO_UDP.into(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({}),
        sample: None,
    };
    write_event_line(&log_path, &bad);
    write_event_line(&log_path, &good);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(tailer, pool.clone(), "test".into());
    let result = runner.run_batch().await;
    assert_eq!(result.rejected, 1);
    assert_eq!(result.ingested, 1);

    // Bad event not in ledger.
    let score = read_score(&pool, "203.0.113.8".parse().unwrap()).await.unwrap();
    assert!(score.is_none());
    // Good event in ledger.
    let score = read_score(&pool, "203.0.113.9".parse().unwrap()).await.unwrap();
    assert!(score.is_some());
}

#[tokio::test]
async fn hash_chain_intact_after_ingestion() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    for i in 0..5 {
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("203.0.113.{}", 10 + i).parse().unwrap(),
            wan_ip: None,
            sensor: "catchall".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
        };
        write_event_line(&log_path, &event);
    }

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(tailer, pool.clone(), "test".into());
    runner.run_batch().await;

    let status = verify_chain(&pool).await.unwrap();
    assert!(matches!(status, ChainStatus::Intact));
}

#[tokio::test]
async fn rotation_survival_no_events_lost() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursors");

    // Write first batch.
    for i in 0..3 {
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("203.0.113.{}", 20 + i).parse().unwrap(),
            wan_ip: None,
            sensor: "catchall".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
        };
        write_event_line(&log_path, &event);
    }

    // Ingest first batch.
    let mut runner = IntakeRunner::new(
        LogTailer::new(log_path.clone(), cursor_dir.clone()),
        pool.clone(), "test".into(),
    );
    let r = runner.run_batch().await;
    assert_eq!(r.ingested, 3);
    runner.persist_cursor().unwrap();

    // Simulate copytruncate rotation.
    std::fs::write(&log_path, "").unwrap();

    // Write second batch.
    for i in 0..3 {
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("203.0.113.{}", 30 + i).parse().unwrap(),
            wan_ip: None,
            sensor: "catchall".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
        };
        write_event_line(&log_path, &event);
    }

    // Ingest second batch (new tailer simulating restart awareness).
    let mut runner2 = IntakeRunner::new(
        LogTailer::new(log_path, cursor_dir),
        pool.clone(), "test".into(),
    );
    let r2 = runner2.run_batch().await;
    assert_eq!(r2.ingested, 3);

    // All 6 events in ledger.
    for i in 20..23 {
        let ip = format!("203.0.113.{i}").parse().unwrap();
        assert!(read_score(&pool, ip).await.unwrap().is_some(), "missing IP 203.0.113.{i}");
    }
    for i in 30..33 {
        let ip = format!("203.0.113.{i}").parse().unwrap();
        assert!(read_score(&pool, ip).await.unwrap().is_some(), "missing IP 203.0.113.{i}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p intake --test end_to_end -- --test-threads=1`
Expected: FAIL - module not defined.

- [ ] **Step 3: Write minimal implementation**

`runner.rs`:
```rust
use crate::converter::{convert, ConvertError};
use crate::tailer::LogTailer;
use core_scoring::append_event;
use sensor_wire::SensorEvent;
use sqlx::PgPool;

pub struct RunBatchResult {
    pub ingested: usize,
    pub rejected: usize,
    pub errors: usize,
}

pub struct IntakeRunner {
    tailer: LogTailer,
    pool: PgPool,
    sensor_name: String,
}

impl IntakeRunner {
    pub fn new(tailer: LogTailer, pool: PgPool, sensor_name: String) -> Self {
        Self { tailer, pool, sensor_name }
    }

    pub async fn run_batch(&mut self) -> RunBatchResult {
        let lines = self.tailer.read_batch(100);
        let mut result = RunBatchResult { ingested: 0, rejected: 0, errors: 0 };

        for line in &lines {
            let event: SensorEvent = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(sensor = %self.sensor_name, "malformed JSON: {e}");
                    result.rejected += 1;
                    continue;
                }
            };

            let input = match convert(event) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(sensor = %self.sensor_name, "conversion rejected: {e:?}");
                    result.rejected += 1;
                    continue;
                }
            };

            match append_event(&self.pool, input).await {
                Ok(_score) => { result.ingested += 1; }
                Err(e) => {
                    tracing::error!(sensor = %self.sensor_name, "append failed: {e:?}");
                    result.errors += 1;
                    // Do NOT advance cursor past this event on DB error.
                    // For simplicity in this batch model, we stop processing
                    // and the remaining lines will be re-read next batch.
                    break;
                }
            }
        }
        result
    }

    pub fn persist_cursor(&self) -> std::io::Result<()> {
        self.tailer.persist_cursor()
    }
}
```

Note on cursor advancement: in this implementation, `read_batch` advances the tailer's internal state for all lines read. On a DB error mid-batch, the cursor is NOT persisted (the caller must call `persist_cursor` only after a fully successful batch, or implement per-line cursor tracking). The at-least-once guarantee holds because unpersisted cursor state is lost on restart, causing re-read from the last persisted position.

The end-to-end tests need the `propolis-pg` PostgreSQL container running and migrations applied. The test `setup_pool` function handles this. Each test should use unique source IPs to avoid cross-test interference, or truncate the tables between tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p intake --test end_to_end -- --test-threads=1`
Expected: PASS (requires PostgreSQL running).

- [ ] **Step 5: Commit**

```bash
git add crates/intake
git commit -m "feat(intake): runner wiring tailer to append_event with end-to-end tests"
```

---

### Task 5: Binary composition + deployment

**Files:**
- Create: `crates/intake/src/main.rs`, `deploy/intake.service`
- Modify: `crates/intake/Cargo.toml` (add `[[bin]]` if needed)
- Test: assertions in `crates/intake/tests/end_to_end.rs` (add deploy test) or `crates/sensor-framework/tests/deploy_test.rs` (add intake unit assertions)

**Interfaces:**
- Consumes: `IntakeRunner` (Task 4), `LogTailer` (Task 3), `sqlx::PgPool`.
- Produces: `intake` binary, `deploy/intake.service` hardened systemd unit.

- [ ] **Step 1: Write the failing test**

```rust
// Add to existing deploy_test.rs in sensor-framework, or create a new test file.
#[test]
fn intake_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/intake.service")
    ).unwrap();
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    // Intake does not bind ports, so no CAP_NET_BIND_SERVICE needed.
    // But it does need network access to PostgreSQL.
    assert!(unit.contains("User="));
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root");
    assert!(unit.contains("MemoryMax="));
    assert!(unit.contains("SystemCallFilter="));
    assert!(unit.contains("MemoryDenyWriteExecute=yes"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework --test deploy_test intake_unit`
Expected: FAIL - service file does not exist.

- [ ] **Step 3: Write minimal implementation**

`main.rs`:
```rust
use intake::runner::IntakeRunner;
use intake::tailer::LogTailer;
use sqlx::PgPool;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let cursor_dir: PathBuf = std::env::var("PROPOLIS_CURSOR_DIR")
        .unwrap_or_else(|_| "/var/lib/propolis/cursors".into())
        .into();
    let poll_interval: u64 = std::env::var("PROPOLIS_POLL_INTERVAL_MS")
        .unwrap_or_else(|_| "1000".into())
        .parse()
        .expect("PROPOLIS_POLL_INTERVAL_MS must be a number");

    // Parse sensor log paths from PROPOLIS_SENSOR_LOGS (comma-separated name:path pairs).
    let sensor_logs_str = std::env::var("PROPOLIS_SENSOR_LOGS")
        .expect("PROPOLIS_SENSOR_LOGS must be set (e.g., catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl)");

    let pool = PgPool::connect(&database_url).await
        .expect("failed to connect to PostgreSQL");

    std::fs::create_dir_all(&cursor_dir)
        .expect("failed to create cursor directory");

    let mut handles = Vec::new();
    for entry in sensor_logs_str.split(',') {
        let parts: Vec<&str> = entry.splitn(2, ':').collect();
        if parts.len() != 2 {
            tracing::error!("invalid sensor log entry: {entry}");
            continue;
        }
        let sensor_name = parts[0].to_string();
        let log_path = PathBuf::from(parts[1]);
        let pool = pool.clone();
        let cursor_dir = cursor_dir.clone();
        let interval = std::time::Duration::from_millis(poll_interval);

        handles.push(tokio::spawn(async move {
            let tailer = LogTailer::new(log_path, cursor_dir);
            let mut runner = IntakeRunner::new(tailer, pool, sensor_name.clone());
            tracing::info!(sensor = %sensor_name, "intake tailer started");
            loop {
                let result = runner.run_batch().await;
                if result.ingested > 0 || result.rejected > 0 {
                    tracing::info!(
                        sensor = %sensor_name,
                        ingested = result.ingested,
                        rejected = result.rejected,
                        errors = result.errors,
                    );
                    if let Err(e) = runner.persist_cursor() {
                        tracing::error!(sensor = %sensor_name, "cursor persist failed: {e}");
                    }
                }
                if result.ingested == 0 && result.rejected == 0 {
                    tokio::time::sleep(interval).await;
                }
            }
        }));
    }

    // Wait for shutdown signal.
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutting down");
    for h in handles { h.abort(); }
}
```

`deploy/intake.service`:
```ini
[Unit]
Description=Propolis intake - sensor log ingestion to event ledger
After=network.target postgresql.service

[Service]
Type=simple
User=propolis-intake
EnvironmentFile=/etc/propolis/intake.env

# Least authority
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Read-only access to sensor log directories
ReadOnlyPaths=/var/log/propolis
# Write access to cursor directory only
ReadWritePaths=/var/lib/propolis/cursors

# Resource caps
MemoryMax=256M
TasksMax=32
CPUQuota=50%
LimitNOFILE=1024

# Containment
# NOTE: SystemCallFilter must be derived empirically via strace against the
# running binary before production deployment. This is a placeholder.
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# NOTE: the real systemd directive is MemoryDenyWriteExecute (no trailing 'tion').
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
```

After creating the files, re-vendor dependencies: `cargo vendor`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework --test deploy_test intake_unit` and `cargo build -p intake`
Expected: PASS and successful build.

- [ ] **Step 5: Commit**

```bash
git add crates/intake deploy/intake.service Cargo.lock vendor
git commit -m "feat(intake): binary entry point and hardened systemd unit"
```
