<!--
title: Concurrency and failure modes
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Concurrency and failure modes

Propolis is built to stay bounded and to fail in a defined direction under exactly the
saturation an attacker can induce on purpose. This page describes the concurrency
model — per-connection tasks, bounded queues, and the single serialized append writer —
and the failure modes at each stage, with the fail-open vs fail-closed posture stated
explicitly.

## Concurrency model

### Per-connection tasks with a hard concurrency cap

Each sensor's listener runs an accept loop and spawns **one task per connection** (or
per UDP datagram). Two framework-enforced bounds apply without the handler's
cooperation (`crates/sensor-framework/src/listener.rs`, `bounds.rs`):

- **`max_concurrent`** — a `tokio::sync::Semaphore` seeded with that many permits. A
  connection accepted while every permit is held is **refused immediately** (the socket
  is closed, not queued). An accepted-but-waiting connection would itself be the
  unbounded resource the cap exists to prevent.
- **`max_duration`** — the handler future runs inside `tokio::time::timeout`; once it
  elapses, the future and everything it owns (the connection included) is dropped in
  place.

Three further bounds — `read_timeout`, `idle_timeout`, and `max_captured_bytes` — are
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

Capturing a file body — hashing it, writing it to the spool, appending the event — must
never make the connection's reply path wait, because an attacker measuring response
latency would be measuring exactly the work that only happens when something is worth
capturing. So the sensor handler does no more than build a `CaptureJob` and `submit` it
(`crates/sensor-framework/src/handoff.rs`):

- **`submit` is backed by `mpsc::Sender::try_send`** and returns immediately either
  way. There is no path by which enqueuing can stall a connection's response, even under
  deliberate saturation.
- **A full queue DROPS the job and increments a counter** — it never blocks. The drop
  count is logged at power-of-two totals.
- **Exactly one worker drains the queue, strictly sequentially.** `mpsc::channel` hands
  out one `Receiver`; `start_worker` moves it out of a `Mutex<Option<_>>` on its first
  call and **panics on any later call**. That single task processes one job to
  completion — including its synchronous `spool.store` — before it `recv()`s again, so
  `store` is never invoked concurrently with itself.
- A panicking sensor `event_builder` is caught, logged, and dropped; **the worker
  survives**.

### Serialized single-writer append

All appends to the event ledger serialize against **one transaction-scoped Postgres
advisory lock** (`pg_advisory_xact_lock`, `crates/core-scoring/src/repository/events.rs`).
The transaction pins `READ COMMITTED`, acquires the lock, then does the chain-head read,
event INSERT, projection read, and `ip_score` UPSERT as one critical section. Under any
number of concurrent callers this guarantees the hash chain cannot fork, the projection
UPSERT cannot lose an update, and the dedup-window read cannot be bypassed by an
interleaved insert. The lock auto-releases at transaction end, so a rolled-back append
never leaves it held. See [storage](./storage.md).

Concurrent NDJSON log appends (multiple connections through one `EventEmitter` behind an
`Arc`) are serialized by the OS: one `O_APPEND` `write_all` of the whole line is atomic
on a local filesystem, so lines are never interleaved or overwritten. This guarantee
**does not extend to NFS** (the client kernel simulates `O_APPEND` and can race) — the
log directory must be local storage.

## Failure modes and posture

| Stage | Failure | Behavior | Posture |
|---|---|---|---|
| Sensor accept loop | Concurrency cap reached | Connection refused immediately (socket closed, not queued) | Bounded — sheds load |
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
oversight — blocking the reply path to guarantee a capture would announce, by latency,
that a capture happened. The drop is counted and logged so the operator can see it.

Everything on the **integrity, storage, and control-plane** paths fails closed: the hash
chain, the spool budget and verify, event emission, readiness, console auth, ops-alert
startup, and the fetcher's self-target guard all deny or refuse rather than proceed on a
missing or malformed input.

## Backpressure and capacity

- **Sensors** shed load by refusing connections past `max_concurrent` — they do not
  queue.
- **Capture** sheds load by dropping jobs past the bounded queue — it does not block.
- **Intake** polls the sensor logs on an interval; it advances a per-sensor cursor and
  is naturally rate-limited by its poll interval and the serialized append lock.
- The **console** binds loopback-only by default and derives metrics from live DB
  queries per scrape (not pre-aggregated).

Capacity-planning guidance and the exact bound values are owned by
[operations/capacity-planning.md](../operations/capacity-planning.md),
[operations/queue-and-spool.md](../operations/queue-and-spool.md), and
[reference/environment-variables.md](../reference/environment-variables.md).

## Related

- [architecture/storage.md](./storage.md) — the serialized append path.
- [architecture/sensors.md](./sensors.md) — the sensor framework these bounds live in.
- [operations/queue-and-spool.md](../operations/queue-and-spool.md) — operating the
  capture queue and spool.
- [operations/health-and-observability.md](../operations/health-and-observability.md) —
  readiness and the drop/rejection counters.
