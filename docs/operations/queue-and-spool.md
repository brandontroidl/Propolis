<!--
title: Queue and spool behavior
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
-->

# Queue and spool behavior

What happens between a captured malware body and a stored sample, and what an operator sees
when either stage is overloaded. This is the operational companion to [capacity
planning](./capacity-planning.md) (the numbers) and [event and sample
lifecycle](../architecture/event-and-sample-lifecycle.md) (the design). Only the
`sensor-ssh`, `sensor-adb`, `sensor-ftp`, `sensor-telnet`, `sensor-tftp`, and `sensor-mqtt`
sensors spool bodies (the set is `crates/review/src/spool.rs#BODY_SPOOLERS`); the rest capture
metadata only.

## The hand-off path

A sensor never writes a captured body on the connection's response path. Doing so would make
the reply latency reveal whether a capture happened, so capture is pushed onto a bounded queue
drained by a single background worker, off the response path
(`crates/sensor-framework/src/handoff.rs`).

```mermaid
flowchart LR
  conn["Connection handler<br/>(reply returns immediately)"] -->|submit, try_send| q["Bounded queue<br/>capacity 64"]
  q --> w["Single worker<br/>(sequential drain)"]
  w --> s["QuarantineSpool<br/>per-file + global budget"]
  s --> ev["NDJSON event<br/>appended to log"]
  q -.->|queue full| d["dropped_count++<br/>no spool, no event"]
  s -.->|refused| r["spool_refused_count++<br/>no event"]
```

Key properties:

- **Bounded queue, capacity 64.** `submit` is backed by `mpsc::try_send` and **never blocks**:
  if the queue is full the job is dropped immediately (`crates/sensor-framework/src/handoff.rs#submit`,
  `crates/sensor-ftp/src/lib.rs#CAPTURE_QUEUE_SIZE`, `crates/sensor-adb/src/lib.rs#CAPTURE_QUEUE_SIZE`,
  `crates/sensor-ssh/src/server.rs#serve`).
- **Exactly one worker.** The worker drains the queue strictly sequentially, so
  `spool.store` is never called concurrently; a second `start_worker` call panics
  (`crates/sensor-framework/src/handoff.rs#start_worker`).
- **Panic isolation.** A panicking event builder is caught (`catch_unwind`) and the worker
  continues (`crates/sensor-framework/src/handoff.rs#process_job`).

## What an operator sees under overload

Two counters and two WARN patterns distinguish the two ways a capture can be lost, both visible
in `journalctl`. (The ops-alert monitor watches spool disk free space rather than these
counters; see [health and observability](./health-and-observability.md).)

### Queue-full drops (`dropped_count`)

When an attacker floods uploads faster than the single worker drains, the queue fills and
`submit` drops jobs. Each drop increments `dropped_count` and logs a WARN **only at power-of-two
totals** (drop 1, 2, 4, 8, 16, ...), so the first drop is loud and a sustained flood degrades to
logarithmic noise instead of filling the log partition it shares
(`crates/sensor-framework/src/handoff.rs#submit`). A dropped job produces no stored sample and no event. This is a
deliberate trade of completeness for covertness under load, not an error.

Log line (example): `capture hand-off: queue full, sample dropped (no spool, no event)` with
`dropped_total=<N>`.

### Spool refusals (`spool_refused_count`)

A body that reaches the worker but the spool rejects increments `spool_refused_count` and logs
a WARN **per refusal** (`crates/sensor-framework/src/handoff.rs#process_job`). The spool refuses in two cases
(`crates/sensor-framework/src/spool.rs#store`, `crates/sensor-framework/src/spool.rs#reserve_budget`):

- **`FileSizeExceeded`** - the body is larger than the per-file cap (10 MB for the spooling
  sensors) (`sensor-framework/src/spool.rs#store`).
- **`BudgetExhausted`** - the global byte budget (100 MB per spooling sensor) is already
  reserved. Reservation is atomic (`compare_exchange`), so the budget is a hard ceiling
  (`sensor-framework/src/spool.rs#reserve_budget`).

Unlike a queue drop, a spool refusal is the only in-process record that a capture was lost at
that stage, which is why every refusal logs (not just powers of two).

## Spool storage properties

The quarantine spool is content-addressed and fail-closed by construction (the module
doc of `crates/sensor-framework/src/spool.rs`):

- files are named by the SHA-256 of their content, never by an attacker-supplied filename, so
  path traversal is structurally impossible (`sensor-framework/src/spool.rs#store`);
- each body is written to a file in the spool's `.staging/` directory with `0640`
  permissions and synced, then given its digest name with a hard link, which never replaces
  an existing name, so a digest name never holds a partial body and two stores of the same
  bytes at once both succeed (`sensor-framework/src/spool.rs#publish`, `sensor-framework/src/spool.rs#write_and_seal`);
- reads re-hash and refuse on mismatch (`HashMismatch` -> corrupt, refused). Every reader
  outside the writing sensor - the console download, the VirusTotal upload - goes through
  `sensor_framework::spool::read_verified` (`sensor-framework/src/spool.rs#read_verified`): the entry is opened without following a symlink,
  must be a regular file no larger than any producer can write (500 MB), and is hashed from the
  opened descriptor. A link, FIFO or swapped body under a digest name is refused and logged,
  never read through; the samples list and spool metrics skip such entries;
- duplicate content dedups on the existing hash and consumes no extra budget (`sensor-framework/src/spool.rs#store`);
- on restart, `new()` re-scans the directory to recover used bytes, so a restart does not reset
  the budget ceiling (`sensor-framework/src/spool.rs#scan_existing_usage`), and removes staged files older than an
  hour that a stopped process left behind (`sensor-framework/src/spool.rs#remove_stale_staging`).

Sample files are trimmed at 30 days; see [retention](./retention.md). Spool paths and budgets
are owned by [filesystem paths](../reference/filesystem-paths.md) and
[capacity planning](./capacity-planning.md). For symptom-based help see
[troubleshooting: queue and spool](../troubleshooting/queue-and-spool.md).
