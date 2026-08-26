<!--
title: Architecture decisions (code-evidenced)
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Architecture decisions

The authoritative Architecture Decision Records (ADRs) are **private** and are not part
of the published corpus. This page summarizes the load-bearing architecture decisions
that are **observable in the code** — each one is inferable from source, tests, and
migrations without reference to the private records. Where a decision's *rationale* is
only asserted in a private ADR, that rationale is marked **[inferred]** from the
code-visible mechanism.

For the historical index of decisions, see
[history/decisions-index.md](../history/decisions-index.md).

## 1. PostgreSQL is the single datastore

There is no second database, broker, or external queue. Sensors write local NDJSON
logs; intake tails them and appends to Postgres; scoring, review, feed, and the console
all read the same database. Captured file bodies are the only state outside Postgres
(the on-disk quarantine spool, referenced by SHA-256).

**Code evidence:** two migration sets over one database; the console, feed, review, and
scoring crates all connect via a shared `sqlx` `PgPool`; no broker/queue dependency in
`Cargo.lock`. See [storage](./storage.md).

## 2. The event ledger is append-only and hash-chained, enforced at the DB layer

Integrity is not left to application discipline. Every event carries a SHA-256 hash over
a **frozen canonical byte encoding**, chained to the prior event. The chain is enforced
in two independent places:

- a `BEFORE INSERT` trigger rejects any row whose `prev_hash` does not match the current
  chain head (fail-closed);
- in the production database, `UPDATE`/`DELETE`/`TRUNCATE` on `event` are **revoked**
  from the application role, which keeps only `INSERT`.

The canonical encoding is pinned by a golden test vector; changing it would invalidate
every historical hash.

**Code evidence:** `crates/core-scoring/src/hashing.rs` (frozen encoding + golden
vector), the chain-enforcement trigger migration, the privilege-revoke migration. See
[storage](./storage.md) and
[security/filesystem-and-db-protections.md](../security/filesystem-and-db-protections.md).

**[inferred]** rationale: tamper-evidence of the observation record without relying on
the application being uncompromised.

## 3. Per-sensor process isolation

Each sensor is its own crate and its own binary, deployed as its own systemd service
under a **dedicated unprivileged user** (never root), with `ProtectSystem=strict`,
`MemoryDenyWriteExecute=yes`, per-service `ReadWritePaths` scoped to that sensor's own
dirs, and resource caps. A sensor can write only to its own log and spool; it has no
database credentials and no path to another sensor.

**Code evidence:** one crate per sensor; per-unit systemd files asserted by
`crates/sensor-framework/tests/deploy_test.rs` (which fails if a hardening directive is
dropped); the one-directional NDJSON channel (sensors never connect to intake). See
[architecture/process-topology.md](./process-topology.md) and
[security/filesystem-and-db-protections.md](../security/filesystem-and-db-protections.md).

Note: the systemd `SystemCallFilter` shipped in the units is a **placeholder** (a broad
`@system-service` allowlist minus `@privileged @resources`), explicitly a development
allowlist the unit header says to tighten before production — not a delivered hardened
syscall filter. See [security/residual-risks.md](../security/residual-risks.md).

## 4. Never-execute: the honeypot captures, it never runs what it captures

No Propolis code spawns a subprocess or execs. A whole-workspace grep for
`Command::new` / `process::Command` / `libc::exec` / `.spawn()` across non-test source
returns zero matches, and no crate enables tokio's `process` feature. Per-sensor
static-check tests walk each crate's source tree and fail if a process-spawn construct
ever appears. Captured samples are written no-execute (`0640`, on a `noexec` mount) and
are never run at any point — custody is store → hash → verify → human-approve → report.

**Code evidence:** the eight `never_exec_static_check` tests (one gap: `sensor-catchall`
lacks its own regression test but is clean under the workspace grep);
`MemoryDenyWriteExecute=yes` on every unit; the spool permissions and mount requirement.
See [security/never-execute.md](../security/never-execute.md) and
[malware custody](../security/malware-custody.md).

## 5. Sensors are egress-free by construction; outbound is confined and gated

Each attacker-facing sensor has **no HTTP client in its own dependency closure**
(enforced for `sensor-ssh` by an explicit banned-dependency test). The workspace as a
whole is **not** egress-free — `Cargo.lock` contains `reqwest`/`hyper`, used by the
platform tier. All outbound network access is confined to **five paths, every one
opt-in and defaulting off**, and the one path that dials an attacker-supplied URL (the
malware fetcher) runs through a fail-closed SSRF vetter on every hop.

**Code evidence:** the `sensor-ssh` no-HTTP-client test; the five gated paths with their
default-off flags; the fetcher's `guard.rs` vetter. See
[security/outbound-controls.md](../security/outbound-controls.md) and
[trust boundaries](./trust-boundaries-and-data-flows.md).

## 6. Sanitize attacker text at one shared chokepoint

Every attacker-controlled string routes through a single `sanitize_value` function
before it can enter an event record, with a load-bearing order of operations
(line-breaking whitespace collapsed before control-stripping, then bidi/zero-width/tag-
block removal, NFC-normalize, UTF-8-boundary truncation). Byte-derived fields are
hex-encoded rather than decoded. This is enforced structurally for captures: the single
capture worker sanitizes `orig_name`, not each sensor.

**Code evidence:** `crates/sensor-framework/src/sanitize.rs` applied in 18 source files;
the framework routing `spool.store` through one worker. See
[security/input-handling.md](../security/input-handling.md).

## 7. All DB access is parameterized

No SQL query text is built with string formatting anywhere in non-test source; every
query uses bound `$n` parameters via the runtime `sqlx::query*` API (chosen so the build
does not require a live database). This removes the SQL-injection surface even though
sensors feed attacker-controlled data into the pipeline.

**Code evidence:** the whole-src grep for `format!(...)` around SQL keywords returns
zero; the event insert and feed/review queries are all parameterized. See
[security/filesystem-and-db-protections.md](../security/filesystem-and-db-protections.md).

## 8. Server-rendered console, no client build step, self-hosted assets

The console is server-rendered minijinja with HTMX fragment swaps and Chart.js; there is
**no SPA and no JavaScript build pipeline**. Every template, font, and JS library is
embedded in the binary at compile time and served locally — the deployed box makes no
CDN request. The console serves plain HTTP on a loopback bind with no in-process TLS.

**Code evidence:** templates via `include_str!`, `base.html` assembled at compile time
from vendored Chart.js and htmx, fonts embedded and served from a fixed allowlist. See
[console architecture](./console.md).

## 9. Dependencies are vendored and the build is pinned

The build uses vendored dependencies and a frozen lockfile; cargo-vendored files are
protected from end-of-line mangling (`vendor/** -text` in `.gitattributes`) after a
CRLF→LF normalization once broke `.cargo-checksum.json` and release builds.

**Code evidence:** the `vendor/` tree and the gitattributes rule; the recorded regression
that a release build (`cargo build --release --locked`) must be run after any re-vendor.
See [reference/dependencies.md](../reference/dependencies.md) and
[security/supply-chain.md](../security/supply-chain.md).

## 10. Foundation-first, bounded-by-construction

Recurring decisions visible across the code: single-source-of-truth definitions (the
signal-weight table, `ConnectionBounds`, the frozen wire format shared by every
producer and consumer), bounds enforced by the framework rather than each handler
(concurrency, duration, per-file and global spool budgets), and fail-closed defaults on
integrity and control paths with a single deliberate fail-open (capture drop under
saturation, for covertness). See
[concurrency and failure](./concurrency-and-failure.md).

## Related

- [history/decisions-index.md](../history/decisions-index.md) — historical decision index.
- [architecture/index.md](./index.md) — how to read the architecture section.
- [security/threat-model.md](../security/threat-model.md) — the threat model these
  decisions answer to.
