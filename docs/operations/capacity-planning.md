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

A zero or unparseable bound is rejected at startup ("zero never means unlimited") by every
sensor, all twelve reading their bounds through one set of typed readers
(`crates/sensor-framework/src/env.rs#Env`). Raising
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

## Session memory (`sensor-ssh`, `sensor-telnet`, `sensor-adb`)

The shell sensors count what each client session really holds on the heap instead of estimating
it. Their binaries install `AccountingAlloc`
(`crates/sensor-framework/src/session_memory.rs#AccountingAlloc`), which tags every allocation with
the session it was made in; each connection's future runs in its own accounted scope
(`crates/sensor-framework/src/session_memory.rs#scope`). Capture bodies grow outside the session,
since the capture memory budget above already charges them. Every allocation carries a header of
16 bytes (more for alignments above 16), counted in the session's figure. `sensor-http` charges
its connections to a pool of its own the same way; its sizing is in
[HTTP sensor worst-case memory](#http-sensor-worst-case-memory).

- A session may keep at most 8 MiB between lines
  (`crates/sensor-framework/src/session_memory.rs#RETAINED_LIMIT_BYTES`), and hold at most that
  plus one line's working set, about 29 MiB, while a line runs
  (`crates/sensor-framework/src/session_memory.rs#PEAK_LIMIT_BYTES`). Past the peak the shell stops
  the running line at its next step (the line's work budget runs out, recorded as a memory hit)
  and the sensor then ends the session; past the retained limit after a line it ends the session
  too.
- One sensor's sessions share a pool of 30% of `MemoryMax`
  (`crates/sensor-framework/src/session_memory.rs#pool_bytes`): 161,061,273 bytes for SSH,
  80,530,635 for telnet and ADB. A session reserves it in 64 KiB chunks. Its fair share is the
  pool, less what ended sessions left allocated, divided among the sessions running (a newcomer
  included), and never under the pool divided by `max_concurrent` (629,145 bytes for SSH, 314,572
  for telnet and ADB at the default 256). When the pool has no room:
  - a session within its floor still takes what it asked for, and the pool counts it past its
    ceiling; floors add up to the pool, so this is at most the pool again;
  - a session past its floor gets no more: its running line stops, and after the line (for SSH
    and ADB, after the packet or message) it is ended unless it is back within what it had
    reserved or its share;
  - the session holding the most above its share is asked to let go and ended, and while what
    the sessions hold stays over the ceiling the next one over its share is asked every 200 ms,
    whether or not anyone allocates. A session at or under its share is never asked.

  A sensor whose share would be under 64 KiB refuses to start.
- A session that is ended this way marks any capture in flight `end_reason` `memory_limit`. A
  watchdog task wakes sessions asked to let go every 200 ms, so one waiting for its peer's next
  line, message or packet (telnet's held input included) ends then, not at its idle timeout. A
  session blocked writing to a peer that does not read ends through the output limits instead
  (the stall limit, the write timeout), and its memory counts against the pool until then. While
  one asked session is still giving its room back, the pool asks no other. SSH also refuses a new
  shell or exec (`SSH_MSG_CHANNEL_FAILURE`) while the session is over or the pool has under 512 KiB
  left, and its queued output is charged to the output budget, not to the session.

The pool, the capture budget (40%) and, for SSH, the 64 MiB output budget leave the rest of
`MemoryMax` to the runtime, the allocation headers and the worker threads' line working sets.
Sessions can hold more than the pool for as long as the asked sessions take to end: what the
sessions within their floors took past it, at most the pool again, and what a session past its
floor allocated before its line stopped.

## SSH sensor worst-case memory

`sensor-ssh` keeps a payload streamed over the shell or an exec's standard input up to 10 MB
(`PROPOLIS_SSH_MAX_CAPTURED_BYTES`, default `10_000_000`, the spool's per-file cap
`crates/sensor-ssh/src/server.rs#SPOOL_MAX_FILE_BYTES`; it was `1_000_000`). The limit decides how
many uploads fill the capture budget, not how much the budget holds, so the worst case is the
sum of the places that hold bytes, each bounded where it is allocated and released:

| Term | Bound | Where it is enforced |
|---|---|---|
| Capture bodies (uploads, shell payloads, held stdin) | 214,748,364 (40% of `MemoryMax`) | `crates/sensor-framework/src/capture_budget.rs#try_reserve` admits a 64 KiB chunk only by compare-exchange under the ceiling; `CaptureBody` and `Reservation` refund on drop, panic unwind included; `crates/sensor-ssh/src/server.rs#DEFAULT_CAPTURE_BUDGET_BYTES` |
| What client sessions hold, shell lines included | 161,061,273 (30% of `MemoryMax`) | the session pool [above](#session-memory-sensor-ssh-sensor-telnet-sensor-adb); a line runs inside its connection's accounted scope, so its working set is charged to the session (`crates/sensor-framework/src/session_memory.rs#PEAK_LIMIT_BYTES`) |
| Output queued for peers, and input waiting behind it | 67,108,864 (64 MiB) | `crates/sensor-ssh/src/server.rs#OUTPUT_BUDGET_BYTES`; a unit of work reserves `crates/sensor-ssh/src/server.rs#OUTPUT_UNIT_BYTES` before it runs and `ChannelFlow::queue` hands out only that |
| Sum | 442,918,501 | |
| Runtime allowance (estimate) | 67,108,864 | code, stacks, packet buffers, the hand-off queue, allocation headers, socket memory |
| Total against `MemoryMax=512M` (536,870,912) | 510,027,365, 26,843,547 to spare | `crates/sensor-ssh/tests/memory_budget_test.rs` |

Why each term holds:

- **Capture bodies.** Every body is a `CaptureBody` of the one budget (`ShellCapture`, `HeldInput`,
  `ScpReceiver`, the SFTP handler), so ten-megabyte uploads from all 256 connections still cannot
  pass the ceiling. A body that cannot grow keeps its prefix and the event says `truncated`. The
  budget fits 21 bodies of 10 MB; the rest of a burst is cut short and flagged
  (`end_reason: "capture_memory_budget"`), as at any limit.
- **Held input.** A command waiting for its input is run on the capture buffer itself, moved into
  the shell and back (`crates/sensor-framework/src/held_input.rs#HeldInput`), so the input is
  never copied while it runs, and the buffer stays charged to the capture budget until the
  capture is recorded. What the line adds is at most one line's working set at any input size,
  which `crates/sensor-framework/tests/finish_line_overhead.rs` measures at 1, 10 and 40 MB.
- **Sessions.** The capture limit does not change this term: capture bodies grow outside the
  session, and the pool bounds the rest.

Residuals, stated plainly. The 64 MiB runtime allowance and the 40% and 30% shares are
estimates, not measurements, and the margin above is 5% of `MemoryMax`. Sessions can hold more
than the pool for as long as the asked sessions take to end (see the session memory section);
a measured high-water of a loaded sensor is the check that would tighten both.

## HTTP sensor worst-case memory

`sensor-http` admits 512 connections on each listener (`crates/sensor-http/src/main.rs#DEFAULT_MAX_CONCURRENT`),
so 1,024 at once with HTTPS bound, against `MemoryMax=256M` (268,435,456 bytes). Its binary
installs `AccountingAlloc` and runs each connection, on either listener, in its own accounted
scope (`crates/sensor-http/src/lib.rs#start_test_server`), so what a connection holds is charged
to its session as on the shell sensors [above](#session-memory-sensor-ssh-sensor-telnet-sensor-adb).
HTTP spools nothing and has no capture budget, so its session pool takes that 40% as well: 70%
of `MemoryMax`, 187,904,815 bytes (`crates/sensor-http/src/lib.rs#SESSION_MEMORY_POOL_BYTES`),
shared by both listeners and configured for all 1,024 sessions, which gives each a floor of
183,500 bytes. The slot table holds 2,047 sessions
(`crates/sensor-framework/src/session_memory.rs#SLOT_COUNT`).

What one connection holds, from where each buffer is allocated and released
(`crates/sensor-http/src/handler.rs#BoundedReader`), and measured as the session's live bytes
(allocation headers included) at each read under the accounting allocator:

| Phase | Held | Bound | Measured |
|---|---|---|---|
| Header block | the header buffer | 16,384 bytes: each read asks for at most the room left, and the buffer doubles but never past the cap | 17,172 at 12 KiB read |
| Body drain, plain | the header block, kept once as bytes; the body capture, sized once to what is kept; the header buffer is freed first | 16,380 + 65,536 | 82,720 |
| Body drain, HTTPS | the same, plus rustls's record buffers, which grow inside the session | | 132,035 |
| Event written, reply sent | the event; the request is dropped first | | 11,687 |

The largest measured, 132,035 bytes, is under the 183,500-byte floor, so 1,024 sessions all at that
size would hold 135,203,840 bytes, inside the pool (only the 512 HTTPS ones can reach it); no session at or under its floor is ever asked to let
go. A session past its share while the pool is short is ended at its next read, or at once while
it waits for its peer (`crates/sensor-http/tests/session_memory_limit.rs`, which also holds the
flood and largest requests, plain and over TLS, within that floor). A header block of empty `:`
lines costs its bytes: before, each line was a 48-byte table entry, and 5,400 of them held about
390 KiB through the body drain.

Outside the pool: each connection's task (the handler future measures 6,568 bytes, plus the
listener's two task cells), the runtime, and socket memory, which the kernel bounds per socket
and the handler keeps drained while it reads. And the TLS handshake, which runs in the
framework (`crates/sensor-framework/src/tls.rs`) before the handler, so before the session
starts: rustls joins a fragmented handshake message in a buffer of up to 65,535 bytes, held for
up to the read timeout (30 s). Measured on a release build, 512 connections each holding a
60 KiB partial ClientHello cost about 110 KB each, 56 MB together. A connection is either in its
handshake or in its session, and a session costs more, so the worst mix is 512 handshaking
HTTPS connections (about 56 MB, outside the pool) beside 512 plaintext sessions in the pool; it
measured 117.6 MB of anonymous memory, 136 MB at its peak, against the 256 MiB unit. Once the
handshake ends the buffer is released and the connection joins the pool. Past the handshake a
client can still fragment a handshake message and grow rustls's buffer toward 64 KiB inside the
session [unverified, from the vendored source]; the pool then ends that session if it is over
its share while the pool is short. A body capture is sized at the declared Content-Length (up to
64 KiB) as soon as the header block ends, so an idle connection that declared a large body holds
about 82.7 KB at once, not as bytes arrive. The sum outside the pool is therefore bounded by
the 80,530,641 bytes the pool leaves. Building the request event is
the one larger moment: a 64 KiB body of invalid UTF-8 expands when it is decoded and redacted,
and measured 350,000 bytes, charged to the session, for the length of one poll; at most one runs
per worker thread at a time.

How long a connection holds these is bounded too: the header block must arrive within the idle
timeout of its first byte and the body within the idle timeout of the header's end, so a request
holds its buffers for at most the read timeout plus twice the idle timeout (150 s at the
defaults), not the 600 s `max_duration` a byte a minute used to keep them for.

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
