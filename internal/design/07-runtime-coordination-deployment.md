# Sub-project 7: runtime composition + deployment

Detailed design spec for the Propolis-new unified daemon and deployment model (Rust). This layer
composes the four database-connected subsystems (intake, review, feed, console) into one process,
provides a hardened deployment unit, and ships an install script for fresh-node provisioning.

## Purpose and scope

This layer owns three things and nothing else:

1. The unified daemon (`crates/propolis`): one process that runs intake tailers, the review
   submission cycle, the feed builder, and the console web server as concurrent tokio tasks sharing
   a single PgPool. Per-subsystem restart-on-panic with backoff.
2. The production deployment unit (`deploy/propolis.service`): one hardened systemd service
   replacing the four separate backend service units. Sensor units stay unchanged.
3. An install script (`deploy/install.sh`): provisions OS users, directories, log paths, spool
   mounts, and systemd units for a fresh node.

This layer does not build new functionality. It composes existing library APIs from intake, review,
feed, and console into one binary with unified configuration and lifecycle management.

## Deployment model

Each Propolis node serves one WAN IP. The operator runs 1-5 nodes, each with its own sensors and
its own intake process, all writing to one shared PostgreSQL database. The multi-WAN breadth model
(SP1) and the direct-PostgreSQL aggregation transport (SP3) were designed for exactly this topology.

Per node, three processes:
- `propolis.service` - the unified daemon (intake + review + feed + console)
- `sensor-catchall.service` - the catch-all sensor (unchanged from SP2)
- `sensor-ssh.service` - the SSH honeypot (unchanged from SP2)

The sensors stay as separate processes because they run unprivileged with no database handle and
no secrets (the security posture from SP2). The four backend services share a database connection
and the same failure mode (DB unavailable = all four stop), so merging them into one process is
simpler to operate without losing meaningful isolation.

## Architecture

One crate, added to the workspace:

- `crates/propolis` - the unified daemon binary. Depends on `intake` (library), `review` (library),
  `feed` (library), `console` (library), `core-scoring` (library), `sqlx`, `tokio`, `tracing`.

### Crate structure

```
crates/propolis/
  Cargo.toml
  src/
    main.rs             # entry point, config loading, PgPool, subsystem orchestration
    config.rs           # unified config from one EnvironmentFile
    supervisor.rs       # per-subsystem task spawning with restart-on-panic + backoff
  tests/
    smoke_test.rs       # start daemon, verify all four subsystems respond
```

### What gets retired

`deploy/intake.service`, `deploy/review.service`, `deploy/feed.service`, `deploy/console.service`
are superseded by `deploy/propolis.service` for production. The standalone binaries and their unit
files stay in the repo for development and testing but are not the production deployment path.

## Daemon internals

### Subsystem tasks

The daemon starts four subsystem groups as tokio tasks from one `main()`:

1. **Intake tailers** - one task per configured sensor log file. Continuous poll loop tailing
   NDJSON logs and calling `append_event`. Uses `intake::tailer::LogTailer` and
   `intake::runner::IntakeRunner`.

2. **Review submission** - one task running the periodic cycle: populate the review queue from
   ip_score, withdraw ineligible Pending entries, submit Approved entries through the gatekeeper
   to vendor adapters. Uses `review::queue::ReviewQueue`, `review::submit::SubmissionRunner`,
   and the vendor adapters from `review::vendor`.

3. **Feed builder** - one task running periodic builds: query ip_score for recommended-for-blocklist
   IPs, build FeedSnapshot with exclusions, export to all formats, publish atomically. Uses
   `feed::builder::FeedBuilder`, `feed::export::*`, `feed::publisher::Publisher`.

4. **Console web server** - one task running the axum server on the configured bind address
   (default 127.0.0.1:8080). Uses `console::routes::*` and `console::auth::*`.

All four share one `sqlx::PgPool` configured once at startup.

### Graceful shutdown

On SIGTERM or SIGINT:
1. The console stops accepting new connections and drains in-flight requests.
2. Intake tailers persist their cursors and stop polling.
3. The review submission task finishes its current cycle (if mid-cycle) and stops.
4. The feed builder finishes its current build (if mid-build) and stops.
5. The daemon exits cleanly.

Implemented via a shared `tokio_util::sync::CancellationToken` passed to all subsystems.

### Per-subsystem restart on panic

Each subsystem task is wrapped in a supervisor that catches panics and restarts the task with
exponential backoff (1s, 2s, 4s, 8s, 16s, capped at 60s). A persistent failure (3 consecutive
panics within 60 seconds) stops restarting that subsystem and logs an alert, but the daemon stays
up for the other three. The supervisor resets the failure counter after 5 minutes of healthy
operation.

A subsystem that fails to start on the first attempt (e.g., config error, missing directory) logs
the error and does not retry - the daemon exits with a non-zero status so systemd can report the
failure.

### Shared PgPool

One `PgPool` with configurable `max_connections` (default 10). Shared across all four subsystems
via `Arc<PgPool>`. Connection health is checked at startup via the console's existing `/ready`
logic (a DB ping). If the initial connection fails, the daemon exits immediately (fail-fast, not
retry-forever on a missing database).

## Unified configuration

One environment file: `/etc/propolis/propolis.env`. Consolidates all env vars from the four
separate services:

```bash
# Database
DATABASE_URL=postgres://propolis:...@localhost:5432/propolis
PROPOLIS_DB_MAX_CONNECTIONS=10

# Intake
PROPOLIS_SENSOR_LOGS=catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl
PROPOLIS_CURSOR_DIR=/var/lib/propolis/cursors
PROPOLIS_POLL_INTERVAL_MS=1000

# Review
PROPOLIS_QUEUE_SCAN_INTERVAL_SECS=60
PROPOLIS_SUBMIT_POLL_INTERVAL_SECS=30
PROPOLIS_VENDOR_ABUSEIPDB_ENABLED=true
PROPOLIS_VENDOR_ABUSEIPDB_KEY=...
# (other vendor config)

# Feed
PROPOLIS_FEED_OUTPUT_DIR=/var/lib/propolis/feed
PROPOLIS_FEED_BUILD_INTERVAL_SECS=900
PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS=24
PROPOLIS_FEED_STANDARD_TTL_HOURS=48

# Console
PROPOLIS_CONSOLE_BIND=127.0.0.1:8080
PROPOLIS_CONSOLE_PASSWORD=...
PROPOLIS_CONSOLE_SESSION_SECRET=...
```

The daemon validates all config at startup and fails fast on missing required values.

## Install script

`deploy/install.sh` provisions a fresh node:

1. Creates OS users: `propolis-catchall`, `propolis-ssh`, `propolis` (for the daemon).
2. Creates directories:
   - `/var/log/propolis/{catchall,ssh}/` (sensor log dirs, owned by respective sensor users)
   - `/var/lib/propolis/{cursors,feed,spool}/` (daemon writable paths)
   - `/etc/propolis/` (config dir)
3. Sets up the quarantine spool as a `noexec,nosuid,nodev` mount (or tmpfs with those options).
4. Installs the compiled binaries to `/usr/local/bin/`.
5. Installs systemd units from `deploy/` to `/etc/systemd/system/`.
6. Installs the logrotate config.
7. Runs `systemctl daemon-reload`.

The script is idempotent (safe to re-run). It does NOT start the services or create the database -
those are operator actions after reviewing the config.

## Deployment unit

`deploy/propolis.service`:

```ini
[Unit]
Description=Propolis unified daemon (intake + review + feed + console)
After=network.target postgresql.service

[Service]
Type=simple
User=propolis
EnvironmentFile=/etc/propolis/propolis.env
ExecStart=/usr/local/bin/propolis

# Least authority
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Readable: sensor logs (for intake tailer)
ReadOnlyPaths=/var/log/propolis

# Writable: cursors, feed output, spool
ReadWritePaths=/var/lib/propolis

# Resource caps
MemoryMax=1G
TasksMax=256
CPUQuota=100%
LimitNOFILE=4096

# Containment
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
MemoryDenyWriteExecute=yes

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Higher resource caps than the individual services (it runs four subsystems). The console binds a
loopback port (needs AF_INET). The review daemon makes outbound HTTPS calls to vendor APIs (needs
AF_INET). Intake reads sensor logs (ReadOnlyPaths). Feed writes to output dir (ReadWritePaths).

## No cluster coordination

Each node is independent. There is no leader election, no cross-node coordination, and no shared
state beyond the PostgreSQL database. The database's own advisory locks serialize concurrent writes
from multiple nodes. Scheduled work (review submission, feed builds) runs on every node, but this
is safe:
- Review submission is idempotent (same idempotency key per IP per vendor per day).
- Feed builds are idempotent (same snapshot produces same output).
- Intake dedup catches cross-node duplicate events.

If the operator wants a single node to run review submission or feed builds (to avoid duplicate
vendor API calls), they can disable those subsystems per-node via config
(`PROPOLIS_REVIEW_ENABLED=false`, `PROPOLIS_FEED_ENABLED=false`). This is a deployment decision,
not a coordination mechanism.

## Error handling

- Database unavailable at startup: daemon exits immediately (fail-fast).
- Database unavailable during operation: subsystems retry on their own poll loops. The daemon stays
  up. The `/ready` endpoint returns 503.
- Subsystem panic: supervisor restarts with backoff. Other subsystems unaffected.
- Config error: daemon exits immediately with a diagnostic message.
- Signal (SIGTERM/SIGINT): graceful shutdown of all subsystems.

## Testing strategy

- **Smoke test.** Start the daemon against a real PostgreSQL database, verify:
  - `/health` returns 200
  - `/ready` returns 200
  - `/metrics` returns valid Prometheus format
  - Intake tailers are running (cursor files created)
  - Console serves the login page at the configured bind address
- **Subsystem restart.** Simulate a panic in one subsystem (via a test hook), verify the other
  three continue running and the panicked one restarts.
- **Graceful shutdown.** Send SIGTERM, verify cursors are persisted, no partial state.
- **Config validation.** Missing required env vars produce a clear error message and exit code 1.
- **Install script.** Run on a clean system, verify directories, users, and unit files are created.

## Decisions closed by this spec

1. Process model: **one unified daemon for the four DB-connected services, sensors stay separate.**
2. Cluster coordination: **none.** Each node is independent. Idempotency handles duplicates.
3. Per-subsystem restart: **exponential backoff, 3 consecutive panics in 60s = stop restarting.**
4. Config model: **one EnvironmentFile, validated at startup, fail-fast on missing values.**
5. Install path: **idempotent shell script provisioning users, directories, units.**

## Open questions - deferred

- TLS termination for the console (reverse proxy is the operator's deployment concern).
- Database migration management (currently via sqlx migrate, could be wired into the daemon's
  startup).
- Log aggregation across nodes (operator's observability stack).
