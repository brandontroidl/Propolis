<!--
title: Process and service topology
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Process and service topology

Propolis runs as two coexisting process models on one node, resolved by
`deploy/install.sh`: the attacker-facing **sensors**, one OS process each, and the
**unified `propolis` daemon**, which runs the entire data plane as supervised tokio
tasks in a single process sharing one `PgPool`.

The crate/binary inventory behind these processes is in
[components.md](components.md). Exact env-var defaults and bounds are owned by
[../reference/environment-variables.md](../reference/environment-variables.md);
filesystem paths by
[../reference/filesystem-paths.md](../reference/filesystem-paths.md). The default
values named below are repeated only where they clarify the process model.

## Sensors - one OS process each

Each sensor binary runs as its own systemd service (nine units:
`deploy/sensor-{catchall,ssh,telnet,redis,adb,http,ftp,smtp,cred}.service`). Isolating
sensors as separate processes keeps a sensor crash or compromise off the data plane.

Each unit runs `ExecStart=/usr/local/bin/sensor-<x>` with
`EnvironmentFile=/etc/propolis/<x>.env`, `Restart=always`, and `MemoryMax=512M`.
Configuration is environment variables only, validated at startup: the process refuses
to start (`exit`) on a malformed value. Each sensor binds its TCP/UDP addresses and
writes NDJSON event logs that intake later tails.

Source: `deploy/sensor-ssh.service` (ExecStart/Restart/MemoryMax);
`sensor-catchall/src/main.rs:6-13`, `sensor-ssh/src/main.rs:8-10`.

## Data plane - the unified `propolis` daemon

`deploy/propolis.service` runs `ExecStart=/usr/local/bin/propolis` with
`EnvironmentFile=/etc/propolis/propolis.env`, `After=network.target
postgresql.service`, `Restart=on-failure`, `MemoryMax=1G`, `TasksMax=256`,
`CPUQuota=100%`, `LimitNOFILE=4096`.

`Restart=on-failure` (not `always`) is deliberate: the daemon supervises its own
subsystems internally (see [Supervision](#supervision)), so systemd only restarts it on
an actual process failure.

This one unit **supersedes** the development-only `deploy/intake.service`,
`review.service`, `feed.service`, and `console.service`. In production, one `propolis`
process runs all four subsystems as concurrent tokio tasks over a single shared
`PgPool`; `install.sh` installs exactly `propolis.service` plus the nine sensor units
and does not install the four standalone data-plane units.

Source: `deploy/propolis.service` header and directives; `deploy/install.sh` unit list.

> **Note on the placeholder syscall filter.** The systemd `SystemCallFilter` shipped in
> the units is a broad development allowlist (`@system-service` minus `@privileged
> @resources`) that the unit header explicitly flags for tightening. It is a residual
> risk, not a delivered hardened syscall filter. See
> [../security/hardening-checklist.md](../security/hardening-checklist.md).

### Subsystems inside the daemon

After startup, the daemon spawns each subsystem via `spawn_supervised` under a single
`CancellationToken` tree (`crates/propolis/src/main.rs` `main`):

1. **Intake tailers** - one supervised task per configured sensor log; each runs a poll
   loop (read batch -> append to ledger -> persist cursor -> sleep on idle,
   `poll_interval` default 1000 ms). (`main.rs:593-630, 172-251`)
2. **Review** - if `review_enabled`: builds the vendor adapters (AbuseIPDB/DShield/OTX)
   and runs a queue-scan loop (default 60 s) plus a submission loop (default 30 s).
   (`main.rs:633-667, 255-303`)
3. **Feed** - if `feed_enabled`: builds a snapshot and atomically publishes it (default
   900 s), touching the ops-monitor freshness marker. (`main.rs:670-742, 305-350`)
4. **VirusTotal scanner** - if `vt_enabled`: scans the spool directories under
   `/var/spool/propolis`, sharing one daily budget across cycles and cleaning samples
   older than 30 days. (`main.rs:744-791`)
5. **Malware fetcher** - if `fetch_enabled`: an SSRF-guarded staging-server fetcher that
   is **fail-closed on an empty `own_ips`**, reserves/refunds a daily budget across
   cycles, and writes to `/var/spool/propolis/fetched`. (`main.rs:41-158, 793-946`)
6. **Console web server** - always spawned: axum on `config.console_bind` (default
   `127.0.0.1:8080`), graceful shutdown wired to the cancel token. (`main.rs:370-431,
   948-997`)
7. **Ops self-alert monitor** - if `ops_alert.enabled`: reads the shared supervisor and
   intake liveness handles, watches disk/DB/feed/vendor health, and pages ntfy on
   degradation. (`main.rs:999-1061`)

Subsystems 2-5 and 7 are opt-in and default off; the console is the only data-plane
subsystem always spawned. The exact enabling env vars and their defaults are owned by
[../reference/environment-variables.md](../reference/environment-variables.md); the
gated egress subsystems (VirusTotal, vendor submitters, ops-alert) are covered in
[../security/outbound-controls.md](../security/outbound-controls.md).

The console listens as plain HTTP on a loopback `TcpListener` (`axum::serve`); there is
no in-process TLS. Any TLS termination is operator-provided (for example a reverse
proxy) and out of the daemon. See
[../operations/networking-tls.md](../operations/networking-tls.md).

### Startup sequence

`main` runs fail-fast, in order (`main.rs:511-577`):

1. Initialize tracing (`RUST_LOG`, else `info`) plus an in-memory `LogBuffer`
   (capacity 1000) feeding the console's live `/logs` viewer.
2. Parse and validate config; `exit(1)` on error.
3. Connect the `PgPool` with `db_max_connections` (default 10); `exit(1)` on failure.
4. Run the core-scoring migrations, then the review migrations, against the one DB;
   `exit(1)` on failure.
5. Create the cursor directory; `exit(1)` on failure.

Only then are the subsystems spawned.

### Supervision

`spawn_supervised(name, cancel, state, factory)` wraps each subsystem in a tokio task
that catches panics and restarts with exponential backoff `1s -> 2s -> 4s -> 8s ->
16s`, capped at `60s`. After `MAX_CONSECUTIVE_PANICS = 3` panics within a `PANIC_WINDOW`
of 60 s it stops restarting that subsystem and alerts; the panic counter resets after
`HEALTHY_RESET = 300s` of healthy operation. A clean return (the future completes
without panicking) is treated as intentional shutdown - no restart. Each subsystem's
state is published into a shared map the ops-monitor reads.

Source: `crates/propolis/src/supervisor.rs:16-33`.

### Shared state

One `PgPool` is cloned into every subsystem. A single `CancellationToken` tree issues a
`.child_token()` per subsystem. `events_ingested` and `events_rejected` `AtomicU64`
counters are shared intake -> console; the `SupervisorHandle` map and `IntakeProgress`
handle are shared into the ops-monitor; the `LogBuffer` is shared tracing -> console.
(`main.rs:582-591`)

### Shutdown

`shutdown_signal()` fires on SIGINT/SIGTERM, calls `cancel.cancel()`, awaits all handles
with a `SHUTDOWN_TIMEOUT` of 30 s, then closes the pool. (`main.rs:160, 480-507,
1064-1087`)

## Feed publishing

The daemon's feed subsystem builds and publishes the blocklist snapshot locally. The
downstream **blocklist-sync / publish cron is an operator setup step**
(`deploy/blocklist-sync.sh`, referenced by comment) and is **not** wired into any
shipped systemd timer or cron in `deploy/`. See
[../operations/service-lifecycle.md](../operations/service-lifecycle.md).
