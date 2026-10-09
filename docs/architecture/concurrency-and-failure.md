<!--
title: Concurrency and failure modes
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
-->

# Concurrency and failure modes

Propolis is built to stay bounded and to fail in a defined direction under exactly the
saturation an attacker can induce on purpose. This page describes the concurrency
model - per-connection tasks, bounded queues, and the single serialized append writer - and the failure modes at each stage, with the fail-open vs fail-closed posture stated
explicitly.

## Concurrency model

### Per-connection tasks with a hard concurrency cap

Each sensor's listener runs an accept loop and spawns **one task per connection** (or
per UDP datagram). Three framework-enforced bounds apply without the handler's
cooperation (`crates/sensor-framework/src/listener.rs`, `bounds.rs`, `admission.rs`):

- **Per-source cap** - `PerSourceLimiter` (`crates/sensor-framework/src/admission.rs#PerSourceLimiter`)
  counts live connections per source IP (IPv4-mapped IPv6 normalized) and refuses a
  source already at its cap, so one host cannot take every `max_concurrent` permit and
  blind the sensor to everyone else. It is checked **before** the global permit, so a
  refused source burns no global permit; the guard moves into the connection task and
  frees its slot on any exit (finish, panic, timeout, abort). Sensors pass
  `default_per_source_cap(max_concurrent)`, a quarter of `max_concurrent`, floor 2,
  never above `max_concurrent`. The gateway passes `None` (no cap): its one trusted
  shipper opens many connections from a single IP. The TFTP and DNS sensors, which run their
  own UDP receive loops, apply the same limiter and derivation. Refusals are logged at
  power-of-two totals.
- **`max_concurrent`** - a `tokio::sync::Semaphore` seeded with that many permits. A
  connection accepted while every permit is held is **refused immediately** (the socket
  is closed, not queued). An accepted-but-waiting connection would itself be the
  unbounded resource the cap exists to prevent.
- **`max_duration`** - the handler future runs inside `tokio::time::timeout`; once it
  elapses, the future and everything it owns (the connection included) is dropped in
  place.

Three further bounds - `read_timeout`, `idle_timeout`, and `max_captured_bytes` - are
enforced by the handler's own read loop rather than the listener (the listener hands
off the raw stream so the handler can resolve WAN attribution), but their **values**
come from the same single `ConnectionBounds` definition, not numbers each sensor
invents.

Panic isolation sits at the connection boundary: each handler runs in its own task and
its poll is wrapped in `catch_unwind`, so a panic on one connection cannot take down the
listener or another connection.

A transient accept/recv error backs off ~20ms rather than spinning a CPU at 100%, so a
persistent condition (for example, running out of file descriptors) degrades to a slow
retry loop.

### Off-response-path capture hand-off (a bounded queue + single worker)

Capturing a file body - hashing it, writing it to the spool, appending the event - must
never make the connection's reply path wait, because an attacker measuring response
latency would be measuring exactly the work that only happens when something is worth
capturing. So the sensor handler does no more than build a `CaptureJob` and `submit` it
(`crates/sensor-framework/src/handoff.rs`):

- **`submit` is backed by `mpsc::Sender::try_send`** and returns immediately either
  way. There is no path by which enqueuing can stall a connection's response, even under
  deliberate saturation.
- **A full queue DROPS the job and increments a counter** - it never blocks. The drop
  count is logged at power-of-two totals.
- **Exactly one worker drains the queue, strictly sequentially.** `mpsc::channel` hands
  out one `Receiver`; `start_worker` moves it out of a `Mutex<Option<_>>` on its first
  call and **panics on any later call**. That single task processes one job to
  completion - including its synchronous `spool.store` - before it `recv()`s again, so
  `store` is never invoked concurrently with itself.
- A panicking sensor `event_builder` is caught, logged, and dropped; **the worker
  survives**.

### Serialized single-writer append

All appends to the event ledger serialize against **one transaction-scoped Postgres
advisory lock** (`pg_advisory_xact_lock`, `crates/core-scoring/src/repository/events.rs`).
The transaction pins `READ COMMITTED`, acquires the lock, then does the chain-head read,
event INSERT, projection read, the upserts and reads of the source's WAN and sensor sets
(`ip_vantage`, `ip_sensor`), and the `ip_score` UPSERT as one critical section. Under any
number of concurrent callers this guarantees the hash chain cannot fork, the projection
UPSERT cannot lose an update, the breadth sets hold every scored event committed before the
append that reads them, and the dedup-window read cannot be bypassed by an interleaved
insert. The lock auto-releases at transaction end, so a rolled-back append
never leaves it held. See [storage](./storage.md).

Intake takes the lock once per **batch**, not once per line: `append_events`
(`crates/core-scoring/src/repository/batch.rs#append_events`) runs the same critical section for
up to 1000 events in one transaction and leaves exactly the state the per-event path would
([storage](./storage.md#batched-append)). A batch that fails rolls back whole. If one event
caused the failure (an invalid event, a stored projection that will not decode, a data
exception or constraint violation), the batch is retried in halves so the events before it
commit. Intake then counts one error and moves its read position past exactly the lines that
committed (and any rejected or probe lines among them), computed from the line lengths recorded
when they were read, and the loop persists the cursor there. The next poll starts at the failed
line: committed events are not appended a second time, and nothing after the failing event is
written. If the log file changed under the failed batch (a `copytruncate` or an in-place
replacement landed while the append was in flight) the position cannot be trusted, so the whole
batch is read again from its start: replayed, never skipped. A failure at the first line of a
batch reports nothing ingested, so the intake loop sleeps its poll interval instead of retrying at
once. An event the database always refuses therefore holds that sensor's intake at that line
until it is removed from the log, as it did one event at a time; the third consecutive poll
refusing the same line logs `intake wedged at <sensor>` with the event's `observed_at` and the
SQLSTATE, and `intake-stalled` quotes the same text when it fires. Nothing skips or quarantines
the line: that is the operator's decision. An error that is not about one event (a lost
connection, a lock timeout) is returned without splitting the batch and is retried on the next
poll; it neither counts toward the three polls nor resets them.

An event can enter the ledger twice in three cases, the price of at-least-once delivery: the
connection drops after Postgres committed a batch but before the acknowledgement arrives (the
batch is reported as failed and read again); the process stops between a commit and the cursor
being persisted; or the log file changed under a failed batch, as above. The dedup window absorbs
the replayed events' score weight but not the extra ledger rows or the source's event counters.

Concurrent NDJSON log appends (multiple connections through one `EventEmitter` behind an
`Arc`) are serialized by the OS: one `O_APPEND` `write_all` of the whole line is atomic
on a local filesystem, so lines are never interleaved or overwritten. This guarantee
**does not extend to NFS** (the client kernel simulates `O_APPEND` and can race) - the
log directory must be local storage.

### Log rotation under a reader that is behind

Logs rotate by `copytruncate`: logrotate copies the log to `events.jsonl.1`, then empties the
original in place, so the sensor's open descriptor never needs to reopen
(`deploy/logrotate-sensors.conf`). Two things can lose lines, and they are different in kind.

- **The copy-to-truncate gap.** A line the sensor appends after the copy and before the truncate
  is in neither file. This is the only loss when the reader is caught up (48 to 570 lines per
  rotation in the intake soak), it is not bounded by anything the reader does, and it is the
  accepted trade for a sensor with no rotation code.
- **The unread part of the old file.** Everything the reader had not read when the log was emptied
  exists only in `.1`. The tailer reads it from there: on a truncation (the read offset past the
  new size) or an in-place replacement it opens `<log>.1`, checks that it is the old content (its
  first 256 bytes hash to the fingerprint stored for the old file, and it is at least as long as
  the read offset), reads it from the offset to its end through the same drain that follows a
  rename rotation, then continues the new file from 0 (`crates/log-tailer/src/tailer.rs#LogTailer`).
  Until that drain ends, the saved cursor stays in the old content, so a restart resumes it and the
  rotation guard can see `.1` is unread. Before this, a reader that was behind at rotation time
  restarted at offset 0 of the new file and the rest of the old one was never read: the intake
  soak lost 71,150, 442,378 and 822,979 telnet lines in three runs with no error.
- **Each generation queued while draining keeps its own resume point.** The saved cursor always
  describes the generation at the front of the drain queue. If a second rotation lands while the
  first copy is still being read and the process then restarts, the cursor names the first
  generation, now `.2` or, under the shipped `compress` + `delaycompress` policy, `.2.gz`: the
  restart finds it there by fingerprint (for the gzip, the hash of the first 256 decompressed
  bytes), reads it from the saved offset, then `.1` (rotated after it, so unread) from 0, then the
  live file. A gzip is expanded, streaming, into an unlinked scratch file (in the cursor
  directory) so the saved position stays a plain decompressed offset; expansion is capped at
  512 MiB, past which the generation is reported lost. If the generation cannot be found at all
  (a truncated or corrupt `.2.gz`, or a copy pushed deeper), the first poll after a start reads
  the newer uncompressed copies from 0 rather than skipping them, accepting a repeat of anything a
  stale `.1` holds over losing it, and reports the loss. A running tailer never does this: its
  state follows the live file, so a non-matching copy is an older generation. The guard exists to
  prevent a second rotation while a copy is unread.
- **A committed prefix across a rotation is placed, not replayed.** When a copytruncate lands while
  a batch is being appended and the append fails partway, the runner accepts the lines that
  committed. With a verifiable `.1` the read position moves forward over them, so the next read
  continues `.1` after them and nothing is appended twice.

When `.1` cannot be trusted (it is missing, only `.1.gz` exists, or it is another generation's
content) it is not read, since reading it would ingest lines the ledger already has. The unread
bytes are then lost; the tailer logs `a copytruncate rotation discarded input that was never read`
with the path, offset and an estimate, and the `intake-rotation-loss` alert pages
([health and observability](../operations/health-and-observability.md)). The guard that runs
before each rotation keeps this from happening in normal operation
([retention](../operations/retention.md#rotation-while-intake-is-behind)).

## Failure modes and posture

| Stage | Failure | Behavior | Posture |
|---|---|---|---|
| Sensor accept loop | Concurrency cap reached | Connection refused immediately (socket closed, not queued) | Bounded - sheds load |
| Sensor accept loop | Transient accept/recv error | ~20ms backoff, retry | Degrade slowly |
| Sensor handler | Panic on one connection | Caught at the task boundary; listener and other connections unaffected | Isolated |
| Sensor bind | One configured port fails to bind | Non-fatal: the sensor logs it and keeps the other ports (the caller loops and does not propagate) | Degrade partially |
| Capture queue | Queue full | Job dropped, counter incremented; reply path never blocks | **Fail-open on capture** (covertness over completeness) |
| Capture worker | `event_builder` panics | Caught, logged, dropped; worker survives | Isolated |
| Spool | Per-file cap or global budget exceeded | `store` refuses the write (`FileSizeExceeded` / budget rejection) | **Fail-closed on storage** |
| Spool | Re-hash on read mismatches | `HashMismatch`; the corrupted body is never passed downstream | **Fail-closed** |
| Event append | DB-layer chain trigger sees a bad `prev_hash` | Insert rejected before it lands (`RAISE EXCEPTION`) | **Fail-closed** |
| Event emit | Serialization or IO error | No partial event line is ever written; the framework guarantees a whole line or nothing | **Fail-closed (all-or-nothing)** |
| Console `/ready` | `SELECT 1` fails (DB unavailable) | `503 {"status":"unavailable"}` | **Fail-closed** |
| Console startup | No `PROPOLIS_CONSOLE_PASSWORD` | Refuses to start (`MissingPassword`) | **Fail-closed** |
| Console login | `ConnectInfo` peer unavailable | Login extraction fails closed | **Fail-closed** |
| Ops-alert | Enabled but URL/topic missing | Refuses to start: "a monitor that cannot page must not start silently" | **Fail-closed** |
| Fetcher | `own_ips` empty | Refuses to run (cannot compute self-target guard) | **Fail-closed** |

### Where the system deliberately fails open

The one deliberate fail-open is **capture completeness under queue saturation**: a full
capture queue drops the job rather than blocking. This is a covertness decision, not an
oversight - blocking the reply path to guarantee a capture would announce, by latency,
that a capture happened. The drop is counted and logged so the operator can see it.

Everything on the **integrity, storage, and control-plane** paths fails closed: the hash
chain, the spool budget and verify, event emission, readiness, console auth, ops-alert
startup, and the fetcher's self-target guard all deny or refuse rather than proceed on a
missing or malformed input.

## Backpressure and capacity

- **Sensors** shed load by refusing connections past `max_concurrent`, and past a
  per-source cap (a quarter of `max_concurrent` by default) for any single source IP -
  they do not queue.
- **Capture** sheds load by dropping jobs past the bounded queue - it does not block.
- **Intake** reads each sensor log 100 lines a batch, growing to 1000 while the log keeps
  filling a whole batch, advancing a per-sensor cursor, and
  reads again at once while lines remain; it sleeps for the poll interval only when a batch
  comes back empty (`crates/propolis/src/main.rs#run_intake_sensor`). Its rate is set by the
  serialized append lock: one batch at a time across every sensor, so a slow batch for one
  source holds up all of them. No read inside the lock grows with a source's history or with
  intake lag, and a batch holds the lock for tens of milliseconds
  ([storage](./storage.md#batched-append)). Intake does not shed load; when a sensor writes faster than
  intake appends, the backlog stays in the log, and the `intake-lagging` alert and the fleet
  pane's behind badge report it ([intake backlog](../troubleshooting/intake-backlog.md)).
- The **console** binds loopback-only by default and derives metrics from live DB
  queries per scrape (not pre-aggregated).

Capacity-planning guidance and the exact bound values are owned by
[operations/capacity-planning.md](../operations/capacity-planning.md),
[operations/queue-and-spool.md](../operations/queue-and-spool.md), and
[reference/environment-variables.md](../reference/environment-variables.md).

## Related

- [architecture/storage.md](./storage.md) - the serialized append path.
- [architecture/sensors.md](./sensors.md) - the sensor framework these bounds live in.
- [operations/queue-and-spool.md](../operations/queue-and-spool.md) - operating the
  capture queue and spool.
- [operations/health-and-observability.md](../operations/health-and-observability.md) - readiness and the drop/rejection counters.
