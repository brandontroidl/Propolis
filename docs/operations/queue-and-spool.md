<!--
title: Queue and spool behavior
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Queue and spool behavior

What happens between a captured malware body and a stored sample, and what an operator sees
when either stage is overloaded. This is the operational companion to [capacity
planning](./capacity-planning.md) (the numbers) and [event and sample
lifecycle](../architecture/event-and-sample-lifecycle.md) (the design). Only the
`sensor-ssh`, `sensor-ftp`, `sensor-adb`, and `sensor-telnet` sensors spool bodies; the rest
capture metadata only.

## The hand-off path

A sensor never writes a captured body on the connection's response path. Doing so would make
the reply latency reveal whether a capture happened, so capture is pushed onto a bounded queue
drained by a single background worker, off the response path
(`crates/sensor-framework/src/handoff.rs:1-14`).

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
  if the queue is full the job is dropped immediately (`handoff.rs:221-241`).
- **Exactly one worker.** The worker drains the queue strictly sequentially, so
  `spool.store` is never called concurrently; a second `start_worker` call panics
  (`handoff.rs:259-298`).
- **Panic isolation.** A panicking event builder is caught (`catch_unwind`) and the worker
  continues (`process_job`, `handoff.rs:323-347`).

## What an operator sees under overload

Two counters and two WARN patterns distinguish the two ways a capture can be lost, both visible
in `journalctl`. (The ops-alert monitor watches spool disk free space rather than these
counters; see [health and observability](./health-and-observability.md).)

### Queue-full drops (`dropped_count`)

When an attacker floods uploads faster than the single worker drains, the queue fills and
`submit` drops jobs. Each drop increments `dropped_count` and logs a WARN **only at power-of-two
totals** (drop 1, 2, 4, 8, 16, ...), so the first drop is loud and a sustained flood degrades to
logarithmic noise instead of filling the log partition it shares
(`handoff.rs:225-241`). A dropped job produces no stored sample and no event. This is a
deliberate trade of completeness for covertness under load, not an error.

Log line (example): `capture hand-off: queue full, sample dropped (no spool, no event)` with
`dropped_total=<N>`.

### Spool refusals (`spool_refused_count`)

A body that reaches the worker but the spool rejects increments `spool_refused_count` and logs
a WARN **per refusal** (`process_job`, `handoff.rs:330-340`). The spool refuses in two cases
(`crates/sensor-framework/src/spool.rs:139-209,235-256`):

- **`FileSizeExceeded`** - the body is larger than the per-file cap (10 MB for the spooling
  sensors) (`spool.rs:146-151`).
- **`BudgetExhausted`** - the global byte budget (100 MB per spooling sensor) is already
  reserved. Reservation is atomic (`compare_exchange`), so the budget is a hard ceiling
  (`reserve_budget`, `spool.rs:235-256`).

Unlike a queue drop, a spool refusal is the only in-process record that a capture was lost at
that stage, which is why every refusal logs (not just powers of two).

## Spool storage properties

The quarantine spool is content-addressed and fail-closed by construction
(`spool.rs:1-9`):

- files are named by the SHA-256 of their content, never by an attacker-supplied filename, so
  path traversal is structurally impossible (`store`, `spool.rs:139-209`);
- files are written `create_new` with `0640` permissions (`spool.rs:171-175`, `write_and_seal` `spool.rs:348-364`);
- reads re-hash and refuse on mismatch (`HashMismatch` -> corrupt, refused). Every reader
  outside the writing sensor - the console download, the VirusTotal upload - goes through
  `sensor_framework::spool::read_verified` (`spool.rs:282-337`): the entry is opened without following a symlink,
  must be a regular file no larger than any producer can write (500 MB), and is hashed from the
  opened descriptor. A link, FIFO or swapped body under a digest name is refused and logged,
  never read through; the samples list and spool metrics skip such entries;
- duplicate content dedups on the existing hash and consumes no extra budget (`spool.rs:156-167`);
- on restart, `new()` re-scans the directory to recover used bytes, so a restart does not reset
  the budget ceiling (`scan_existing_usage`, `spool.rs:119-127,366-382`).

Sample files are trimmed at 30 days; see [retention](./retention.md). Spool paths and budgets
are owned by [filesystem paths](../reference/filesystem-paths.md) and
[capacity planning](./capacity-planning.md). For symptom-based help see
[troubleshooting: queue and spool](../troubleshooting/queue-and-spool.md).
