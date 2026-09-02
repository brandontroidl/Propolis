<!--
title: Sensor architecture
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Sensor architecture

Propolis captures attacker activity through **nine sensor crates covering twelve
emulated protocols**, plus one protocol-agnostic passive listener. Every sensor is
a thin protocol front-end built on one shared crate, `sensor-framework`, which owns
the parts that must behave identically everywhere: the listener, connection bounds,
event emission, capture hand-off, the quarantine spool, the fake shell, and the
single fictional host persona.

This page explains how a sensor is structured and how a connection travels from
accept to emitted event. Exact per-protocol behavior (banners, verbs, response
codes, caps) is owned by [`reference/sensor-behavior.md`](../reference/sensor-behavior.md);
event fields and signal types by
[`reference/events-and-signals.md`](../reference/events-and-signals.md); ports and
binds by [`reference/ports-and-protocols.md`](../reference/ports-and-protocols.md).

## The two invariants sensors exist to hold

Every sensor crate is engineered so that two properties hold **by construction**,
not by careful coding:

- **Egress-free.** No attacker-facing sensor crate has an HTTP or network-fetch
  client anywhere in its own dependency tree. Per-sensor tests ban
  `reqwest/hyper/ureq/curl/isahc/surf/attohttpc`; the shell's `wget`/`curl` return
  canned transcripts with zero network I/O
  (`crates/sensor-framework/src/shell.rs:17-25`). A sensor cannot fetch or serve
  attacker-directed content because nothing capable of it is present. (The *platform*
  as a whole has a few operator-gated, default-off egress paths for enrichment and
  reporting; see [`security/outbound-controls.md`](../security/outbound-controls.md).
  Those live in other crates, never in a sensor.)
- **Never-execute.** No sensor imports a process-spawning facility. There is no code
  path from an attacker-typed byte to a real shell, syscall, or interpreter. The fake
  shell returns hand-written strings; a source-level test
  (`never_exec_static_check` in `crates/sensor-ssh/tests/shell_test.rs`) asserts this
  across every file in the shell and SSH crates. See
  [`security/never-execute.md`](../security/never-execute.md).

## The shared framework (`sensor-framework`)

A sensor crate supplies protocol logic; the framework supplies everything else.

### Listener and per-connection isolation

`run_tcp_listener(addr, bounds, handler)` binds one TCP address, runs an accept loop,
and hands each accepted connection to the protocol handler with a raw `TcpStream`,
the peer `SocketAddr`, and a fresh `Uuid::now_v7()` session id
(`crates/sensor-framework/src/listener.rs:72-140`). Each connection:

- runs in its own `tokio::spawn`, so a panicking handler is caught by tokio's task
  harness, logged, and never crashes the accept loop
  (`listener.rs:62-71, 124-130`);
- is bounded by `max_concurrent` via a `tokio::sync::Semaphore` - a connection over
  the limit is refused immediately (socket closed, never queued)
  (`bounds.rs:29-33`);
- is time-bounded by running the handler future inside
  `tokio::time::timeout(max_duration, fut)` (`listener.rs:118`).

`run_udp_listener` mirrors this for datagrams, but **never hands the socket to the
handler**, so a UDP sensor cannot answer a probe by construction
(`listener.rs:147-161, 162-221`). `normalize_dual_stack` maps IPv4-mapped IPv6 peers
(`::ffff:a.b.c.d`) down to plain IPv4 before WAN resolution, so a plain-IPv4 WAN map
matches a dual-stack listener (`listener.rs:272-280`).

### Connection bounds

`ConnectionBounds` (`bounds.rs:16-34`) defines *shape only* - `read_timeout`, `idle_timeout`, `max_duration`, `max_captured_bytes`,
`max_concurrent`. Concrete values are set per sensor and read from environment
variables validated at startup; a present-but-zero or unparseable bound makes the
process refuse to start on most sensors ("zero never means unlimited"). Exact
defaults, and the two sensors that fall back to defaults instead of refusing
(SMTP and cred), are owned by
[`reference/environment-variables.md`](../reference/environment-variables.md).

### WAN resolution

`WanResolver` maps the local bound address a connection landed on to the operator's
WAN IP, so an event records which vantage saw the attacker
(`wan.rs:25-33`). An unmapped local address yields `None` → the event's `wan_ip` is
null, a documented case rather than an error. No-NAT deployments carry an identity
entry (local == WAN).

### Persona, fake filesystem, fake shell

One coherent fictional host - **Ubuntu 22.04.4 LTS "Jammy", hostname `server01` by
default** - is resolved from `persona.rs` so no two sensors contradict each other
(`persona.rs:21-51`). Banners, `uname` output, and `/etc/os-release` all derive from
it.

`fakefs.rs` is an in-memory static snapshot, fresh per session, with no real
filesystem underneath - path traversal is structurally impossible
(`fakefs.rs:1-14`). `shell.rs` is the interactive fake shell presented post-auth,
shared by SSH, Telnet, and ADB. It emits one `honeypot_command_exec` per non-blank
line (recording the raw line, sanitized and capped), decodes single-byte-XOR
obfuscated probes, recognizes fetch verbs (emitting `honeypot_file_download` with the
target URL, never fetching it), and answers a curated command set including a
BusyBox applet dispatcher and a Gafgyt/BASHLITE echo handshake. The per-command
behavior is owned by
[`reference/sensor-behavior.md`](../reference/sensor-behavior.md).

### Capture sanitization

`sanitize_value(input, max_len)` is the single chokepoint every attacker string
clears before entering an event (`sanitize.rs:1-27`): it collapses CR/LF/tab runs to
one space, strips ANSI/C0/C1 controls and bidi/zero-width characters, NFC-normalizes,
and UTF-8-boundary-safe truncates to a byte cap - closing CR/LF/ANSI log injection.
See [`security/input-handling.md`](../security/input-handling.md).

## The capture path

Only three sensors write captured file *bodies* to disk - **SSH, FTP, and ADB**.
Redis, Telnet, HTTP, SMTP, cred, and catchall capture metadata only and never spool a
body (confirmed by the absence of `QuarantineSpool`/`CaptureHandoff` in those crates).

For the spooling sensors the path is deliberately **off the connection's reply
path**, for covertness - response latency must not leak whether a capture happened:

1. The handler reads enough to answer the protocol, builds a `CaptureJob`, and
   `submit`s it. `submit` is backed by `mpsc::try_send` and **never blocks**; a full
   queue drops the job, returns `CaptureDropped`, and increments a counter
   (`handoff.rs:109-148`). Queue size is 64 on every spooling sensor.
2. A **single worker** drains the queue strictly sequentially (`start_worker` panics
   on a second call), so the spool is never written concurrently
   (`handoff.rs:159-188`). It hashes the body, stores it, and appends the event; a
   panicking event builder is isolated by `catch_unwind` and the worker continues
   (`handoff.rs:194-233`).

### Quarantine spool

`QuarantineSpool` stores every captured body under its **SHA-256 as the filename**
(never the attacker-supplied name → traversal impossible), with `0640` permissions
and re-hash-on-read fail-closed (`spool.rs:1-9, 114-122`). It enforces a per-file
size cap and a global byte budget via an atomic `compare_exchange` reservation, dedups
on existing hash, and recovers its used-byte count by scanning the directory on
startup so a restart does not reset the ceiling. SSH/FTP/ADB use a 10 MB per-file cap
and a 100 MB global budget. See
[`security/malware-custody.md`](../security/malware-custody.md) and
[`reference/filesystem-paths.md`](../reference/filesystem-paths.md).

### Event emission

`EventEmitter::append` serializes an event to one NDJSON line, opens the log with
`O_APPEND` (atomic concurrent appends on local storage), and `write_all` + `flush`; a
serialize or append failure never partially writes a line
(`emit.rs:40-53`). The log directory must be local storage - NFS `O_APPEND` can race
(`emit.rs:26-39`). These NDJSON files are what the intake tailer consumes; see
[`event-and-sample-lifecycle.md`](event-and-sample-lifecycle.md).

## The wire record

Every sensor emits the same frozen record, `SensorEvent`
(`crates/sensor-wire/src/lib.rs:36-53`, `WIRE_VERSION = 1`). A sensor emits **raw
facts only** - `source_ip`, `wan_ip`, `sensor`, `signal_type` (a plain string),
`protocol`, `authenticated`, `observed_at`, `metadata`, an optional `sample`
reference, and an optional `session_id`. Weight, confidence, and category are **not**
on the wire; they are derived downstream so a sensor never computes a score. Field
types and the signal vocabulary are owned by
[`reference/events-and-signals.md`](../reference/events-and-signals.md).

## The catch-all and multi-protocol sensors

- **`sensor-catchall`** emulates no protocol and never writes a byte back
  (`crates/sensor-catchall/src/handler.rs:1-9`). It binds every configured address
  on **both TCP and UDP**, reads up to a small byte cap, and emits one
  `catchall_probe` carrying a hex payload sample. Its bounds are deliberately tighter
  than the interactive sensors.
- **`sensor-cred`** is one binary with one listener per configured database/remote
  protocol - **VNC, MySQL, MSSQL, PostgreSQL, MongoDB**. Each speaks just enough of
  its handshake to elicit a credential attempt, drops the credential, and emits a
  login attempt. This is why nine crates cover twelve protocols.

## Never-serve-outbound

No sensor fetches or serves attacker-directed content: FTP `RETR`→550 and
`PORT/EPRT`→502, ADB sync `RECV`→FAIL, SSH `direct-tcpip` refused, catchall and all
UDP never respond, and shell `wget`/`curl` are canned
(`sensor-wire`/handler evidence, cross-cutting). This invariant is part of the trust
boundary; see
[`security/attack-surfaces.md`](../security/attack-surfaces.md) and
[`architecture/trust-boundaries-and-data-flows.md`](trust-boundaries-and-data-flows.md).

## Adding a sensor

The developer procedure for building a new sensor on this framework lives in
[`development/adding-a-sensor.md`](../development/adding-a-sensor.md).
