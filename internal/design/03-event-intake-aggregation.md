# Sub-project 3: event intake + multi-node aggregation

Detailed design spec for the Propolis-new intake layer (Rust). This layer sits between the sensor
framework (sub-project 2) and the review/reporting layers (sub-project 4): it reads raw sensor events
from disk, validates and converts them, and writes them to the core scoring layer's event ledger.

## Purpose and scope

This layer owns three things and nothing else:

1. A durable log cursor that tails each sensor's NDJSON log file, survives process restart and log
   rotation, and delivers events at-least-once.
2. A converter that parses the wire-format `SensorEvent` into `core-scoring`'s `EventInput` via
   `from_signal`, rejecting unknown or malformed events fail-closed.
3. A runner that feeds converted events to `append_event`, which serializes writes, hash-chains the
   ledger, computes dedup/breadth/scoring, and upserts the ip_score projection - all inside a single
   PostgreSQL transaction per event.

This layer has no vendor client, no web surface, no feed publisher, and no sensor. It reads sensor
logs (read-only filesystem access to the sensor's log directory) and writes to PostgreSQL. It is the
first layer in the stack that holds a database handle.

The single cross-cutting question this layer must settle is the multi-node aggregation transport,
deferred by sub-project 2's spec. It is settled here (see Multi-node aggregation).

## Inherited invariants (from the roadmap and earlier specs)

These are established at the foundation and not relitigated here; this layer realizes them.

- **Append-only, hash-chained ledger.** `append_event` is INSERT-only with a per-chain advisory lock,
  a SHA-256 chain hash linking each event to its predecessor, and a dedup window on
  `(source_ip, signal_type)`. This layer calls it; it does not reimplement any part of it.
- **Single source of truth for scoring.** `from_signal` derives `weight`, `confidence`, and `category`
  from `signal_type` via the signal weight table. A sensor never emits these fields; intake never
  overrides them. `validate()` rejects any event whose derived values do not match the table.
- **Human-approval gate.** Intake surfaces and queues; it never auto-reports or auto-publishes.
  Writing an event to the ledger and updating the projection is the end of intake's responsibility.
- **One-directional log flow.** A sensor has write-only access to its own log; intake has read-only
  access. Enforced by filesystem permissions and service-manager mounts, not convention. Intake never
  writes to a sensor's log directory.

## Architecture

One crate, added to the workspace:

- `crates/intake` - the intake binary. Depends on `sensor-wire` (wire types), `core-scoring`
  (EventInput, append_event, SignalType, Protocol), `tokio`, `sqlx`, `serde_json`, `sha2`, `tracing`.

The binary runs one tailer per configured sensor log file. Each tailer reads NDJSON lines from its
sensor's log, parses them into `SensorEvent`, converts to `EventInput`, and calls `append_event`.
All tailers share one `PgPool` and one configuration. The advisory lock inside `append_event`
serializes writes across tailers and across nodes.

### Crate structure

```
crates/intake/
  Cargo.toml
  src/
    main.rs           # binary entry point, config loading, tailer orchestration
    cursor.rs         # DurableCursor - persistent read position per log file
    tailer.rs         # LogTailer - reads NDJSON lines, advances cursor, handles rotation
    converter.rs      # convert SensorEvent -> EventInput via from_signal
    runner.rs         # IntakeRunner - tailer + converter + append_event loop
  tests/
    cursor_test.rs    # cursor persistence, rotation detection, restart recovery
    tailer_test.rs    # line reading, rotation survival, at-least-once delivery
    converter_test.rs # wire-to-domain conversion, unknown signal rejection
    end_to_end.rs     # full pipeline: write events -> rotate -> ingest -> verify ledger
```

## The durable log cursor

The cursor tracks the read position in one sensor's log file. It must survive three events without
losing or double-counting events:

1. **Normal read.** The cursor advances byte-by-byte as complete lines are read. An incomplete
   trailing line (no terminal newline) is not consumed; the cursor stays at the start of that line
   and re-reads it on the next poll.
2. **Process restart.** The cursor is persisted to a JSON file after each batch of events is
   successfully written to the ledger (not after each line - that would be one fsync per event).
   On startup, the cursor resumes from the persisted position.
3. **Log rotation (copytruncate).** The deployed logrotate config uses `copytruncate`, which copies
   the log content to a rotated file and then truncates the original to zero length. The sensor's
   open file descriptor continues writing to the same inode at offset 0. The cursor detects this
   by comparing its recorded offset against the file's current size: if `offset > size`, the file
   was truncated. The cursor resets to offset 0 and re-reads from the beginning. Events written
   between the copy and the truncate appear in both the rotated file and the truncated file's new
   content; the ledger's dedup window catches the overlap, so at-least-once delivery is
   maintained without at-most-once complexity.

### Cursor state

```rust
pub struct CursorState {
    pub inode: u64,
    pub offset: u64,
    pub fingerprint: [u8; 32],  // SHA-256 of the first min(256, file_size) bytes at offset 0
}
```

- `inode` identifies the file. If the file's inode changes (rotation by rename rather than
  copytruncate), the cursor reads the old inode's file to EOF (if still accessible), then switches
  to the new inode at offset 0.
- `offset` is the byte position of the next unread byte.
- `fingerprint` detects file replacement: if the first 256 bytes of the current file don't match
  the stored fingerprint and the inode is the same, the file was replaced (not truncated). The
  cursor resets to offset 0 and recomputes the fingerprint.

The cursor is persisted as a JSON file in a configurable cursor directory (one file per sensor log,
named by a stable hash of the log file's absolute path). Persistence is atomic: write to a temp file,
fsync, rename.

### Failure modes

- **Cursor ahead of file (copytruncate detected).** Reset to 0, re-read. Dedup catches overlap.
- **Cursor file missing (first run or lost state).** Start from offset 0. All existing events are
  ingested; dedup catches any that are already in the ledger.
- **Cursor file corrupt (unreadable JSON).** Treat as missing. Start from 0. Log the corruption.
- **Log file missing (sensor not yet started).** Poll until the file appears. Not an error.
- **Log file inode changed (rotation by rename).** Read old file to EOF if accessible, then new file
  from 0.
- **Events lost to rotation (cursor so far behind that rotated generations were deleted before the
  cursor reached them).** Detected by fingerprint mismatch on the current file. Log the gap as a
  metric (events_lost_to_rotation counter). This is the only data-loss path, and it is bounded by
  the rotation retention count (5 generations at 100M = 500M of headroom).

## The converter

The converter maps `sensor_wire::SensorEvent` to `core_scoring::EventInput`. This is the boundary
between the sensor's string-typed wire format and the domain's enum-typed model.

```rust
pub fn convert(event: SensorEvent) -> Result<EventInput, ConvertError> {
    let signal_type: SignalType = serde_json::from_value(
        serde_json::Value::String(event.signal_type)
    )?;
    let protocol: Protocol = serde_json::from_value(
        serde_json::Value::String(event.protocol)
    )?;

    let input = EventInput::from_signal(
        event.source_ip,
        event.wan_ip,
        event.sensor,
        signal_type,
        protocol,
        event.authenticated,
        event.observed_at,
        fold_sample_metadata(event.metadata, event.sample),
    );

    input.validate()?;
    Ok(input)
}
```

The string-to-enum conversion uses serde deserialization, which leverages the asymmetric
`rename_all(deserialize = "snake_case")` on `SignalType` and `Protocol` (added in SP2). An unknown
string fails deserialization and the event is rejected.

### Sample metadata folding

When `event.sample` is `Some(ref)`, the converter folds the sample reference into `metadata` so
downstream layers can access it:

```json
{
  "protocol_label": "ssh",
  "command": "scp -t /tmp/evil.bin",
  "sample_sha256": "abcd1234...",
  "sample_size": 12345,
  "sample_orig_name": "evil.bin"
}
```

The quarantine spool body itself stays on disk; only the reference travels in the event. Downstream
layers (SP4/SP8) use `sample_sha256` to locate the body in the spool for VirusTotal submission.

### Rejection policy

- Unknown `signal_type` or `protocol` string: rejected, logged with the raw string value.
- `validate()` failure (signal-type desync, empty sensor, out-of-range confidence): rejected, logged.
- Malformed JSON (unparseable NDJSON line): rejected, logged with the raw line (truncated to 1024
  bytes for log safety). The cursor advances past the bad line.
- Schema version mismatch (`v != 1`): rejected, logged. Future versions bump `v` and require a
  converter update.

Rejection is fail-closed: a rejected event is never written to the ledger. The rejection is logged
as a structured warning with enough context to diagnose (sensor name, signal type, error) but never
the full raw line (which may contain attacker-controlled content). The cursor advances past rejected
events so they do not block the pipeline.

## The runner

The runner is the intake loop. One `IntakeRunner` per sensor log file, each running as a tokio task.

```
loop {
    let lines = tailer.read_batch(max_batch_size);
    if lines.is_empty() {
        sleep(poll_interval);
        continue;
    }
    for line in lines {
        match convert(parse_ndjson(&line)) {
            Ok(event_input) => {
                match append_event(&pool, event_input).await {
                    Ok(score) => { /* optionally log score changes */ }
                    Err(e) => { /* log, but do NOT advance cursor past this event */ }
                }
            }
            Err(e) => { /* log rejection, advance cursor */ }
        }
    }
    tailer.persist_cursor();
}
```

### Cursor advancement rules

- **Successful append:** cursor advances past the event's line.
- **Conversion rejection:** cursor advances past the line (the event is permanently bad; re-reading
  it on restart would reject it again).
- **Database error:** cursor does NOT advance. The event is retried on the next loop iteration. This
  is the at-least-once guarantee: a transient database error (connection lost, timeout) causes the
  same event to be re-appended. The dedup window in `append_event` catches the duplicate if the
  first attempt actually committed.

### Batching and persistence

The cursor is persisted after each batch, not after each line. A batch is up to `max_batch_size`
lines (configurable, default 100). This amortizes the fsync cost of cursor persistence. On crash
mid-batch, up to `max_batch_size` events may be re-read and re-appended; the dedup window catches
the overlap.

## Multi-node aggregation

The aggregation question deferred from sub-project 2 is settled here.

### Decision: direct PostgreSQL write per collector, no broker

Each collector node runs its own intake process. Each intake process tails the local sensors' log
files and writes directly to the shared PostgreSQL database using `append_event`. The advisory lock
inside `append_event` serializes all writes from all nodes into a single total order per source IP.

**Why no broker.** A message broker (Kafka, NATS, Redis Streams) between collectors and the scorer
adds a component, a failure mode, and a delivery-guarantee concern (exactly-once across a broker
boundary is hard; at-least-once with dedup is what we already have). For a system designed for
single-digit collector count (the deployment model is 1-4 WAN IPs per node, a handful of nodes),
direct database writes through an advisory lock are simpler, correct, and sufficient. The database
is already the canonical store; making it the aggregation point too eliminates a hop.

**Why this works at scale.** The advisory lock serializes writes per source IP chain, not globally.
Different source IPs can be appended concurrently from different nodes (the lock key is derived from
the source IP). The contention point is a single IP being appended to from multiple nodes
simultaneously, which is the normal case when an attacker scans multiple WAN IPs. The lock hold
time is one INSERT + one UPSERT + breadth queries per transaction, on the order of single-digit
milliseconds. At the expected event rate (hundreds to low thousands of events per second across all
collectors), this is well within PostgreSQL's capacity.

**Backpressure.** There is none, by design. The sensor-to-log path is fire-and-forget (the sensor
never blocks on intake). The log-to-ledger path reads as fast as it can. If intake falls behind
(database slowdown, network partition to a remote DB), events accumulate on disk in the sensor's
log files. The rotation retention (5 generations * 100M = 500M per sensor) is the buffer. If the
gap exceeds the retention, events are lost to rotation - the only data-loss path, bounded and
metered.

**Cross-node dedup.** Already handled. `append_event` applies a dedup window on
`(source_ip, signal_type)` within `DEDUP_WINDOW_SECONDS`. If the same attacker hits two WAN IPs on
different collectors within the window, both events are ingested (they have different `wan_ip`
values, so they are distinct evidence and contribute to breadth). If the same event is somehow
ingested twice from the same sensor (cursor restart), the dedup window catches it.

**Scorer leader election.** Not needed. Every `append_event` call atomically computes the scoring
projection inside its own transaction. There is no separate scorer process. The projection is
always consistent with the ledger because it is derived inside the same transaction that appends
the event.

## Configuration

```rust
pub struct IntakeConfig {
    pub database_url: String,
    pub sensor_logs: Vec<SensorLogConfig>,
    pub cursor_dir: PathBuf,
    pub poll_interval: Duration,
    pub max_batch_size: usize,
}

pub struct SensorLogConfig {
    pub name: String,       // sensor name for logging/metrics
    pub log_path: PathBuf,  // absolute path to the sensor's NDJSON log file
}
```

Loaded from environment variables, matching the project's existing pattern (sensor-catchall and
sensor-ssh both use environment-based config).

## Isolation and deployment

The intake binary ships a hardened service-manager unit, following the same pattern as the sensor
units from sub-project 2. Key differences from sensor units:

- **Has a database handle.** The unit must have access to the PostgreSQL connection string (via
  `EnvironmentFile`). This is the first binary in the stack that holds database credentials.
- **Read-only filesystem access to sensor logs.** The unit mounts each sensor's log directory
  read-only. It never writes to a sensor's log directory.
- **Write access to cursor directory.** The cursor directory is the only writable path besides
  `/tmp`.
- **No network listener.** Intake does not bind any port. It is a consumer, not a server.
  `RestrictAddressFamilies` can be tighter than the sensor units (only `AF_INET`/`AF_INET6` for
  the PostgreSQL connection, or `AF_UNIX` if using a local socket).

## Error handling

- A malformed or unparseable NDJSON line is rejected and the cursor advances past it. The pipeline
  does not stall on bad input.
- An unknown signal type or protocol string is rejected. The event is logged with the raw string
  value for operator diagnosis.
- A database error (connection lost, timeout, constraint violation) causes the cursor to NOT advance.
  The event is retried on the next poll. Persistent database unavailability causes the intake process
  to poll indefinitely, logging periodic warnings, accumulating events on disk.
- A cursor file that cannot be written (disk full, permission denied) is logged as an error. The
  intake process continues with the in-memory cursor and retries persistence on the next batch. On
  process restart without a persisted cursor, events are re-read from offset 0; dedup catches
  overlap.

## Testing strategy

Verified against the real database and real file I/O, not mocks.

- **Cursor persistence and restart.** Write events, persist cursor, simulate restart (reload cursor
  from file), write more events. Verify no events lost or double-counted in the ledger.
- **Rotation survival (the SP2 deferred test).** Write events to a log file, rotate it (copytruncate:
  copy + truncate to 0), write more events. Ingest through the full pipeline. Verify every event
  appears in the ledger exactly once (dedup catches the overlap window).
- **Unknown signal type rejected.** An event with `signal_type: "nonexistent_signal"` is rejected
  and logged. The cursor advances past it. The ledger has no record of it.
- **Malformed JSON rejected.** A line that is not valid JSON is rejected. The cursor advances. The
  pipeline continues with the next line.
- **Database error retry.** Simulate a transient database error (drop the connection mid-append).
  Verify the cursor does not advance and the event is retried successfully on the next poll.
- **Wire record round-trip.** A `SensorEvent` emitted by a real sensor (catch-all or SSH) is
  ingested, and the resulting `EventInput` in the ledger matches the expected signal type, protocol,
  authenticated flag, WAN IP, and metadata.
- **Sample metadata folding.** An event with a `sample` reference produces an `EventInput` whose
  metadata contains `sample_sha256`, `sample_size`, and `sample_orig_name`.
- **Multi-tailer independence.** Two tailers reading different log files ingest concurrently without
  interference. Events from both appear in the ledger with correct attribution.
- **Cursor ahead of file (copytruncate detection).** Set cursor offset beyond file size. Verify
  cursor resets to 0 and re-reads without error.
- **Hash chain integrity after ingestion.** After ingesting a batch, `verify_chain()` returns
  `Intact`.

## Decisions closed by this spec

1. Multi-node aggregation transport: **direct PostgreSQL write per collector, no broker.** Each
   collector runs its own intake process writing to the shared database. Advisory lock serializes.
2. Backpressure model: **none.** Sensor logs are the buffer. Rotation retention bounds the loss.
3. Cross-node dedup: **handled by `append_event`'s existing dedup window.** No additional mechanism.
4. Scorer leader election: **not needed.** Every writer computes the projection atomically.
5. Cursor model: **inode + offset + fingerprint, persisted as JSON, copytruncate-aware.**

## Open questions - deferred to their owning layer (not open for this spec)

- The quarantine store retention, cleanup, and the operator-approved VirusTotal forward - sub-projects
  4 and 8. Intake folds the sample reference into metadata but does not manage the spool.
- The review queue that reads `ip_score` projections - sub-project 4.
- The feed builder that reads `ip_score` projections - sub-project 5.
- The web console - sub-project 6.
- Runtime composition of intake + sensors into a single managed process - sub-project 7.

## Provenance of this spec

The scope, the aggregation decisions, and the cursor model were settled on 2026-07-29 with the
operator. The four open questions deferred from sub-project 2's spec (multi-node transport,
backpressure, cross-node dedup, scorer leader election) are all resolved here with the simplest
correct answer: direct database writes, no broker, no leader, existing dedup. The design leverages
core-scoring's existing advisory-lock serialization and dedup window rather than introducing new
coordination mechanisms.
