<!--
title: Process and service topology
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
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

Each sensor binary runs as its own systemd service (twelve units:
`deploy/sensor-{catchall,ssh,telnet,redis,adb,http,ftp,smtp,tftp,mqtt,dns,cred}.service`). Isolating
sensors as separate processes keeps a sensor crash or compromise off the data plane.

Each unit runs `ExecStart=/usr/local/bin/sensor-<x>` with
`EnvironmentFile=/etc/propolis/<x>.env`, `Restart=always`, and `MemoryMax=512M`.
Configuration is environment variables only, validated at startup: the process refuses
to start (`exit`) on a malformed value. Each sensor binds its TCP/UDP addresses and
writes NDJSON event logs that intake later tails.

Source: `deploy/sensor-ssh.service` (ExecStart/Restart/MemoryMax);
`crates/sensor-catchall/src/main.rs`, `crates/sensor-ssh/src/main.rs`.

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
`PgPool`; `install.sh` installs exactly `propolis.service` plus the twelve sensor units
and does not install the four standalone data-plane units.

Source: `deploy/propolis.service` header and directives; `deploy/install.sh` unit list.

> **Note on the placeholder syscall filter.** The systemd `SystemCallFilter` shipped in
> the units is a broad development allowlist (`@system-service` minus `@privileged
> @resources`) that the unit header explicitly flags for tightening. It is a residual
> risk, not a delivered hardened syscall filter. See
> [../security/hardening-checklist.md](../security/hardening-checklist.md).

### Subsystems inside the daemon

After startup, the daemon spawns each subsystem via `spawn_supervised` under a single
`CancellationToken` tree (`crates/propolis/src/main.rs#main`):

1. **Intake tailers** - one supervised task per configured sensor log; each runs a poll
   loop (read batch -> append to ledger -> persist cursor -> sleep on idle,
   `poll_interval` default 1000 ms). (`crates/propolis/src/main.rs#run_intake_sensor`)
2. **Review** - if `review_enabled`: builds the vendor adapters (AbuseIPDB/DShield/OTX)
   and runs a queue-scan loop (default 60 s) plus a submission loop (default 30 s).
   (`crates/propolis/src/main.rs#build_adapters`, `crates/propolis/src/main.rs#run_queue_scan_loop`,
   `crates/propolis/src/main.rs#run_submission_loop`)
3. **Feed** - if `feed_enabled`: builds a snapshot and atomically publishes it (default
   900 s), touching the ops-monitor freshness marker. (`crates/propolis/src/main.rs#run_feed_loop`)
4. **VirusTotal scanner** - if `vt_enabled`: scans the spool directories under
   `/var/spool/propolis`, sharing one daily budget across cycles. (`crates/propolis/src/main.rs#main`,
   `crates/review/src/virustotal.rs#DailyBudget`, `crates/review/src/virustotal.rs#scan_spool`)
   **Sample retention** - always spawned (`sample-retention`): hourly, deletes spooled
   bodies older than 30 days from every body directory, independent of VirusTotal
   (`crates/propolis/src/main.rs#SAMPLE_RETENTION_DAYS`).
5. **Malware fetcher** - if `fetch_enabled`: an SSRF-guarded staging-server fetcher that
   is **fail-closed on an empty `own_ips`**, enforces its per-host and daily caps in the
   database when a cycle claims rows, so they hold across restarts and across nodes
   sharing the database, and writes to `/var/spool/propolis/fetched`. (`crates/propolis/src/main.rs#local_interface_ips`,
   `crates/propolis/src/main.rs#main`, `crates/propolis/src/main.rs#fetch_spool_dir`; the claim is `store::claim_candidates` in
   `crates/review/src/fetcher/store.rs`, called from `run_cycle_with`)
6. **Console web server** - always spawned: axum on `config.console_bind` (default
   `127.0.0.1:8080`), graceful shutdown wired to the cancel token. (`crates/propolis/src/main.rs#run_console`)
7. **Ops self-alert monitor** - if `ops_alert.enabled`: reads the shared supervisor and
   intake liveness handles, watches disk/DB/feed/vendor health, and pages ntfy on
   degradation. (`crates/propolis/src/main.rs#main`, `crates/propolis/src/ops_alert/monitor.rs#Monitor::run`)

Subsystems 2-5 and 7 are opt-in and default off; the console and sample retention are
the only subsystems always spawned. The exact enabling env vars and their defaults are owned by
[../reference/environment-variables.md](../reference/environment-variables.md); the
gated egress subsystems (VirusTotal, vendor submitters, ops-alert) are covered in
[../security/outbound-controls.md](../security/outbound-controls.md).

The console listens as plain HTTP on a loopback `TcpListener` (`console::server::serve`, HTTP/1.1); there is
no in-process TLS. Any TLS termination is operator-provided (for example a reverse
proxy) and out of the daemon. See
[../operations/networking-tls.md](../operations/networking-tls.md).

### Startup sequence

`main` runs fail-fast, in order (`crates/propolis/src/main.rs#main`):

1. Initialize tracing (`RUST_LOG`, else `info`) plus an in-memory `LogBuffer`
   (capacity 1000) feeding the console's live `/logs` viewer.
2. Parse and validate config; `exit(1)` on error.
3. Connect the `PgPool` with `db_max_connections` (default 10); `exit(1)` on failure.
4. Run the core-scoring migrations, then the review migrations, then the fleet
   migrations, against the one DB; `exit(1)` on failure.
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

Source: `crates/propolis/src/supervisor.rs#spawn_supervised`, with its limits in
`crates/propolis/src/supervisor.rs#INITIAL_BACKOFF`, `crates/propolis/src/supervisor.rs#MAX_BACKOFF`,
`crates/propolis/src/supervisor.rs#MAX_CONSECUTIVE_PANICS`, `crates/propolis/src/supervisor.rs#PANIC_WINDOW` and
`crates/propolis/src/supervisor.rs#HEALTHY_RESET`.

### Shared state

One `PgPool` is cloned into every subsystem. A single `CancellationToken` tree issues a
`.child_token()` per subsystem. `events_ingested` and `events_rejected` `AtomicU64`
counters are shared intake -> console; the `SupervisorHandle` map and `IntakeProgress`
handle are shared into the ops-monitor; the `LogBuffer` is shared tracing -> console.
(`crates/propolis/src/main.rs#main`)

### Shutdown

When `shutdown_signal()` (`crates/propolis/src/main.rs#shutdown_signal`) resolves on SIGINT/SIGTERM, `main` calls
`cancel.cancel()` and awaits all named handles with a `SHUTDOWN_TIMEOUT` of 30 s. Any
subsystem still running is aborted, named in a warning, and given 2 s to unwind; the pool
close is then bounded at 5 s, so a stop takes at most 37 s. See
[service lifecycle](../operations/service-lifecycle.md#stop-and-graceful-shutdown).
(`crates/propolis/src/main.rs#main`, `crates/propolis/src/main.rs#drain_subsystems`,
`crates/propolis/src/main.rs#SHUTDOWN_TIMEOUT`)

## Feed publishing

The daemon's feed subsystem builds and publishes the blocklist snapshot locally. The
downstream **blocklist-sync / publish cron is an operator setup step**
(`deploy/blocklist-sync.sh`, referenced by comment) and is **not** wired into any
shipped systemd timer or cron in `deploy/`. See
[../operations/service-lifecycle.md](../operations/service-lifecycle.md).
