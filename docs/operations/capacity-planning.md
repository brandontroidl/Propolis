<!--
title: Capacity planning
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-10
-->

# Capacity planning

The bounded resources an operator sizes: database connections, the capture queue, spool
budgets, per-unit memory and task caps, and what drives database growth. Exact env-var
defaults and bounds are owned by [environment
variables](../reference/environment-variables.md) and
[rate limits and budgets](../reference/rate-limits-and-budgets.md); this page explains how to
size them.

## Database connections

The daemon opens one PgPool sized by `PROPOLIS_DB_MAX_CONNECTIONS` (default **10**, must be
`> 0`; `parse_positive_u64`, `crates/propolis/src/config.rs#DEFAULT_DB_MAX_CONNECTIONS`,
`crates/propolis/src/config.rs#load_config`). Every subsystem (intake, review, feed,
console, metrics) shares this one pool. In a multi-node cluster each node opens its own pool
against the shared database, so size the PostgreSQL `max_connections` for the **sum** across
all nodes plus headroom, not a single node. Under-sizing the pool serializes subsystem DB work;
over-sizing it can exhaust the server's connection slots.

## Capture queue

Each spooling sensor hands captured bodies to a single background worker through a bounded
in-process channel of **64** jobs, hard-coded per sensor rather than sourced from the unused
`SensorConfig::capture_queue_size` field: SSH `crates/sensor-ssh/src/server.rs#serve`,
FTP `CAPTURE_QUEUE_SIZE` (`crates/sensor-ftp/src/lib.rs#CAPTURE_QUEUE_SIZE`), ADB
`crates/sensor-adb/src/lib.rs#CAPTURE_QUEUE_SIZE`. The queue is deliberately small and drops rather than blocks
when full, so it bounds memory, not throughput. Operational behavior under overload is
described in [queue and spool](./queue-and-spool.md); it is not operator-tunable via env in the
shipped config.

## Spool budgets

Captured malware bodies are written to disk under per-sensor and fetcher spool directories,
each with a hard global byte budget and a per-file cap. Reservation is atomic and the spool
refuses (fail-closed) once the budget is reached (`crates/sensor-framework/src/spool.rs`).

| Spool | Per-file cap | Global budget | Cite |
|---|---|---|---|
| `sensor-ssh`, `sensor-ftp`, `sensor-adb`, `sensor-telnet`, `sensor-tftp` capture | 10 MB | 100 MB | SSH `crates/sensor-ssh/src/server.rs#serve`, TFTP `crates/sensor-tftp/src/lib.rs#start_test_server`, FTP `crates/sensor-ftp/src/lib.rs#SPOOL_MAX_FILE_SIZE`/`crates/sensor-ftp/src/lib.rs#SPOOL_GLOBAL_BUDGET`, ADB `crates/sensor-adb/src/lib.rs#SPOOL_MAX_FILE_SIZE`/`crates/sensor-adb/src/lib.rs#SPOOL_GLOBAL_BUDGET`, telnet `crates/sensor-telnet/src/lib.rs#start_test_server` |
| `sensor-mqtt` capture (binary PUBLISH payloads) | 256 KiB (one PUBLISH packet, `crates/sensor-mqtt/src/handler.rs#MAX_PACKET_BYTES`) | 100 MB | `crates/sensor-mqtt/src/lib.rs#SPOOL_MAX_FILE_SIZE`/`crates/sensor-mqtt/src/lib.rs#SPOOL_GLOBAL_BUDGET` |
| Fetcher (`/var/spool/propolis/fetched`) | `PROPOLIS_FETCH_MAX_BYTES` (default 10 MB) | **1 GB** (`FETCH_SPOOL_GLOBAL_BUDGET`) | `crates/propolis/src/main.rs#FETCH_SPOOL_GLOBAL_BUDGET`, `crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_BYTES` |

Redis, HTTP, SMTP, cred, DNS, and catchall sensors never write a body to a spool (they capture
metadata only), so they consume no spool budget. Telnet only spools when the shell phase sees a
binary payload (a Mirai/Gafgyt dropper), never the login/password phase - but when it does, it
draws from the same 10 MB/100 MB budget as ssh/ftp/adb/tftp. MQTT spools only a PUBLISH payload
that passes the binary gate, from its own 100 MB budget. The fetcher spool is a growing malware
corpus with a much larger budget than the incidental per-connection upload spools; its per-file
cap is the same `PROPOLIS_FETCH_MAX_BYTES` the HTTP fetch enforces, so the two cannot drift.
The global budgets are compile-time constants, not env vars; plan disk so
`/var/spool/propolis` can hold the sum (roughly 1 GB fetcher + 100 MB per spooling sensor)
plus rotated logs under `/var/log/propolis`. Sample retention trims the spool; see
[retention](./retention.md).

## Connection concurrency (per sensor)

Each sensor caps concurrent connections with `max_concurrent`; a connection accepted over the
cap is closed immediately, never queued (`crates/sensor-framework/src/bounds.rs#ConnectionBounds`).
Defaults (all operator-overridable via each sensor's `_MAX_CONCURRENT` env var, owned by
[environment variables](../reference/environment-variables.md)):

- most internet-facing sensors: **256**;
- `sensor-http`: **512** (`crates/sensor-http/src/main.rs#DEFAULT_MAX_CONCURRENT`);
- `sensor-catchall`: 256, but with much tighter timeouts and a 4 KB capture cap
  (`crates/sensor-catchall/src/main.rs#DEFAULT_READ_TIMEOUT_MS`/
  `crates/sensor-catchall/src/main.rs#DEFAULT_IDLE_TIMEOUT_MS`/
  `crates/sensor-catchall/src/main.rs#DEFAULT_MAX_CAPTURED_BYTES`).

A zero or unparseable bound is rejected at startup ("zero never means unlimited") for every
sensor except SMTP and cred, which fall back to the default on invalid input
(`crates/sensor-smtp/src/main.rs#parse_positive_u64`/`crates/sensor-smtp/src/main.rs#parse_positive_u32`,
`crates/sensor-cred/src/main.rs#parse_positive_u64`/`crates/sensor-cred/src/main.rs#parse_positive_u32`). Raising
`max_concurrent` raises peak memory and file-descriptor use; keep it under each unit's
`LimitNOFILE`.

## Capture memory budget (body-capturing sensors)

`max_concurrent` times a per-connection body cap does not bound a sensor's memory on its own:
many connections can each buffer an upload at once. The five sensors that buffer bodies (ssh,
ftp, adb, telnet, tftp) therefore share one process-wide ceiling,
`sensor_framework::capture_budget::CaptureMemoryBudget`, charged in 64 KiB chunks as a body grows
and refunded as soon as the hand-off worker has spooled it. The ceiling is
`PROPOLIS_<SENSOR>_CAPTURE_MEMORY_BYTES`, defaulting to 40% of the unit's `MemoryMax`: 107374182
bytes (about 102 MiB) for the 256 M sensors, 214748364 bytes (about 205 MiB) for `sensor-ssh`.
The 40% share is an unmeasured choice; the other 60% is headroom for the runtime, protocol
parsers, shell and fake-filesystem state, queued events and allocator overhead, none of which
the budget charges. A capture that hits the ceiling is stored as a truncated prefix
(`end_reason: "capture_memory_budget"`), and one that cannot buffer a single byte produces no
sample; see [environment variables](../reference/environment-variables.md) for the variables and
the exact behavior. Raise the variable only together with the unit's `MemoryMax`. The per-unit
counts (current, high-water, refused reservations, truncated and refused captures) are exposed by
`CaptureHandoff` getters for diagnostics; no endpoint publishes them yet.

## SSH sensor worst-case memory

`sensor-ssh` keeps a payload streamed over the shell or an exec's standard input up to 10 MB
(`PROPOLIS_SSH_MAX_CAPTURED_BYTES`, default `10_000_000`, the spool's per-file cap
`crates/sensor-ssh/src/server.rs#SPOOL_MAX_FILE_BYTES`; it was `1_000_000`). The limit decides how
many uploads fill the capture budget, not how much the budget holds, so the worst case is the
sum of the places that hold bytes, each bounded where it is allocated and released:

| Term | Bound | Where it is enforced |
|---|---|---|
| Capture bodies (uploads, shell payloads, held stdin) | 214,748,364 (40% of `MemoryMax`) | `crates/sensor-framework/src/capture_budget.rs#try_reserve` admits a 64 KiB chunk only by compare-exchange under the ceiling; `CaptureBody` and `Reservation` refund on drop, panic unwind included; `crates/sensor-ssh/src/server.rs#DEFAULT_CAPTURE_BUDGET_BYTES` |
| Output queued for peers, and input waiting behind it | 67,108,864 (64 MiB) | `crates/sensor-ssh/src/server.rs#OUTPUT_BUDGET_BYTES`; a unit of work reserves `crates/sensor-ssh/src/server.rs#OUTPUT_UNIT_BYTES` before it runs and `ChannelFlow::queue` hands out only that |
| Per-connection shell and filesystem state | 256 x 466,944 = 119,537,664 | `crates/sensor-framework/src/budget.rs#max_resident_bytes` at `crates/sensor-ssh/src/main.rs#DEFAULT_MAX_CONCURRENT` |
| A shell line's working copies | 2 workers x 22,020,096 = 44,040,192 | `crates/sensor-framework/src/budget.rs#LINE_WORKING_SET_BYTES` (five times the line work allowance, 4,194,304, plus 1 MiB); `#[tokio::main(worker_threads = 2)]` in `crates/sensor-ssh/src/main.rs` |
| Sum | 445,435,084 | |
| Runtime allowance (estimate) | 67,108,864 | code, stacks, packet buffers, the hand-off queue, socket memory |
| Total against `MemoryMax=512M` (536,870,912) | 512,543,948, 24,326,964 to spare | `crates/sensor-ssh/tests/memory_budget_test.rs` |

Why each term holds:

- **Capture bodies.** Every body is a `CaptureBody` of the one budget (`ShellCapture`, `HeldInput`,
  `ScpReceiver`, the SFTP handler), so ten-megabyte uploads from all 256 connections still cannot
  pass the ceiling. A body that cannot grow keeps its prefix and the event says `truncated`. The
  budget fits 21 bodies of 10 MB; the rest of a burst is cut short and flagged
  (`end_reason: "capture_memory_budget"`), as at any limit.
- **Held input.** A command waiting for its input is run on the capture buffer itself, moved into
  the shell and back (`crates/sensor-framework/src/held_input.rs#HeldInput`), so the input is
  never copied while it runs, and the buffer stays charged until the capture is recorded. Before
  this, a 10 MB input cost about 31 MB more than the input per line (3.1 times; 15 MB at the old
  limit); it is now at most 21 MB at any input size, which `crates/sensor-framework/tests/finish_line_overhead.rs`
  measures at 10 MB and 40 MB.
- **Output.** A peer that never reads used to leave every line's output (up to 4 MiB a line, 10
  channels, 256 connections) queued with no bound. Now a line runs only while its channel holds
  less than one line of unsent output (`CHANNEL_QUEUED_MAX_BYTES`, 8,388,608: the line cap doubled
  for a pty's CR-LF) and its connection less than two (`CONNECTION_QUEUED_MAX_BYTES`), and only with
  an allowance of the output budget in hand. Input that cannot run waits in order, charged
  (payload plus 128 bytes) to the same budget and capped at twice the window per channel
  (`DEFERRED_CHANNEL_MAX_BYTES`), and runs when the peer reads. When the budget or the cap cannot
  hold what is waiting, the session ends; nothing is dropped or cut silently. A connection
  that does this is closed at `max_duration` like any other.
- **Worker threads.** A line runs synchronously, so only a worker can be inside one. Two is
  enough for a unit that `CPUQuota=75%` limits to under one core, and it makes the line term
  independent of the host's core count. With a worker per core it would be cores x 22 MB.

Residuals, stated plainly. The 64 MiB runtime allowance and the 40% and 12.5% shares are
estimates, not measurements; the margin above is 4.5% of `MemoryMax`, and a measured
high-water of a loaded sensor is the check that would tighten it. One peer that holds output
unread can use up to 16,777,216 bytes of the output budget, so a handful of such connections
stall the shell replies of the others until they time out or are closed; the capture budget and
the sample hand-off are separate and keep working.

## Per-unit resource caps (systemd)

The deploy units cap memory, tasks, CPU, and file descriptors. These are the hard ceilings a
process cannot exceed; size sensor `max_concurrent` and capture load to stay within them.

| Unit | MemoryMax | TasksMax | CPUQuota | LimitNOFILE | Cite |
|---|---|---|---|---|---|
| `propolis` | 1 G | 256 | 100% | 4096 | `deploy/propolis.service#MemoryMax`/`deploy/propolis.service#TasksMax`/`deploy/propolis.service#CPUQuota`/`deploy/propolis.service#LimitNOFILE` |
| `sensor-ssh` | 512 M | 128 | 75% | 4096 | `deploy/sensor-ssh.service#MemoryMax`/`deploy/sensor-ssh.service#TasksMax`/`deploy/sensor-ssh.service#CPUQuota`/`deploy/sensor-ssh.service#LimitNOFILE` |
| `sensor-catchall` | 256 M | 64 | 50% | 4096 | `deploy/sensor-catchall.service#MemoryMax`/`deploy/sensor-catchall.service#TasksMax`/`deploy/sensor-catchall.service#CPUQuota`/`deploy/sensor-catchall.service#LimitNOFILE` |
| other sensors | 256 M | 128 | 50% | 4096 | `deploy/sensor-*.service` |

The daemon holds all four subsystems in one process, hence the highest caps in the set. If a
unit is being OOM-killed, `journalctl -u <unit>` shows the `MemoryMax` hit; reduce load or
raise the cap deliberately rather than removing it. See [concurrency and
failure](../architecture/concurrency-and-failure.md).

## Database growth

The `event` table grows with every captured event and never self-truncates; `ip_score` holds
one row per source IP, and `ip_vantage` and `ip_sensor` one row per source and WAN address or
sensor it was seen on (on a 7.5M-row, 3.9 GB test ledger with 300k sources, 47 MB and 93 MB).
Scoring uses time-decay on read, so old events keep contributing to
storage even after their scoring weight has decayed away. Growth is driven by attack volume and
sensor exposure, not by a fixed schedule. There is **no built-in event-table pruning**; plan
database storage for sustained ingest and prune with your own retention job if needed. Sample
files (not DB rows) are trimmed at 30 days by the always-on `sample-retention` subsystem; feed membership is
bounded by retention windows. Both are covered in [retention](./retention.md). Table and column
definitions are owned by [database reference](../reference/database.md).
