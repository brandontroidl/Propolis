<!--
title: Capacity planning
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
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
`> 0`; `crates/propolis/src/config.rs:16,432`). Every subsystem (intake, review, feed,
console, metrics) shares this one pool. In a multi-node cluster each node opens its own pool
against the shared database, so size the PostgreSQL `max_connections` for the **sum** across
all nodes plus headroom, not a single node. Under-sizing the pool serializes subsystem DB work;
over-sizing it can exhaust the server's connection slots.

## Capture queue

Each spooling sensor hands captured bodies to a single background worker through a bounded
in-process channel of **64** jobs (`SensorConfig::capture_queue_size`; SSH `server.rs:110`,
FTP `lib.rs:14`, ADB `lib.rs`). The queue is deliberately small and drops rather than blocks
when full, so it bounds memory, not throughput. Operational behavior under overload is
described in [queue and spool](./queue-and-spool.md); it is not operator-tunable via env in the
shipped config.

## Spool budgets

Captured malware bodies are written to disk under per-sensor and fetcher spool directories,
each with a hard global byte budget and a per-file cap. Reservation is atomic and the spool
refuses (fail-closed) once the budget is reached (`crates/sensor-framework/src/spool.rs`).

| Spool | Per-file cap | Global budget | Cite |
|---|---|---|---|
| `sensor-ssh`, `sensor-ftp`, `sensor-adb`, `sensor-telnet` capture | 10 MB | 100 MB | `spool.rs:156`, SSH `server.rs:107-111`, telnet `lib.rs:42` |
| Fetcher (`/var/spool/propolis/fetched`) | `PROPOLIS_FETCH_MAX_BYTES` (default 10 MB) | **1 GB** (`FETCH_SPOOL_GLOBAL_BUDGET`) | `crates/propolis/src/main.rs:41,55` |

Redis, HTTP, SMTP, cred, and catchall sensors never write a body to a spool (they capture
metadata only), so they consume no spool budget. Telnet only spools when the shell phase sees a
binary payload (a Mirai/Gafgyt dropper), never the login/password phase - but when it does, it
draws from the same 10 MB/100 MB budget as ssh/ftp/adb. The fetcher spool is a growing malware
corpus with a much larger budget than the incidental per-connection upload spools; its per-file
cap is the same `PROPOLIS_FETCH_MAX_BYTES` the HTTP fetch enforces, so the two cannot drift.
The global budgets are compile-time constants, not env vars; plan disk so
`/var/spool/propolis` can hold the sum (roughly 1 GB fetcher + 100 MB per spooling sensor)
plus rotated logs under `/var/log/propolis`. Sample retention trims the spool; see
[retention](./retention.md).

## Connection concurrency (per sensor)

Each sensor caps concurrent connections with `max_concurrent`; a connection accepted over the
cap is closed immediately, never queued (`crates/sensor-framework/src/bounds.rs:29-33`).
Defaults (all operator-overridable via each sensor's `_MAX_CONCURRENT` env var, owned by
[environment variables](../reference/environment-variables.md)):

- most internet-facing sensors: **256**;
- `sensor-http`: **512** (`crates/sensor-http/src/main.rs:20-24`);
- `sensor-catchall`: 256, but with much tighter timeouts and a 4 KB capture cap
  (`crates/sensor-catchall/src/main.rs:39-43`).

A zero or unparseable bound is rejected at startup ("zero never means unlimited") for every
sensor except SMTP and cred, which fall back to the default on invalid input
(`crates/sensor-smtp/src/main.rs:28-38`, `crates/sensor-cred/src/main.rs:29-38`). Raising
`max_concurrent` raises peak memory and file-descriptor use; keep it under each unit's
`LimitNOFILE`.

## Per-unit resource caps (systemd)

The deploy units cap memory, tasks, CPU, and file descriptors. These are the hard ceilings a
process cannot exceed; size sensor `max_concurrent` and capture load to stay within them.

| Unit | MemoryMax | TasksMax | CPUQuota | LimitNOFILE | Cite |
|---|---|---|---|---|---|
| `propolis` | 1 G | 256 | 100% | 4096 | `deploy/propolis.service:170-173` |
| `sensor-ssh` | 512 M | 128 | 75% | (default) | `deploy/sensor-ssh.service:34-78` |
| `sensor-catchall` | 256 M | 64 | 50% | (default) | `deploy/sensor-catchall.service:33-73` |
| other sensors | 256 M | 128 | 50% | (default) | `deploy/sensor-*.service` |

The daemon holds all four subsystems in one process, hence the highest caps in the set. If a
unit is being OOM-killed, `journalctl -u <unit>` shows the `MemoryMax` hit; reduce load or
raise the cap deliberately rather than removing it. See [concurrency and
failure](../architecture/concurrency-and-failure.md).

## Database growth

The `event` table grows with every captured event and never self-truncates; `ip_score` holds
one row per source IP. Scoring uses time-decay on read, so old events keep contributing to
storage even after their scoring weight has decayed away. Growth is driven by attack volume and
sensor exposure, not by a fixed schedule. There is **no built-in event-table pruning**; plan
database storage for sustained ingest and prune with your own retention job if needed. Sample
files (not DB rows) are trimmed at 30 days by the VT scanner's cleanup pass; feed membership is
bounded by retention windows. Both are covered in [retention](./retention.md). Table and column
definitions are owned by [database reference](../reference/database.md).
