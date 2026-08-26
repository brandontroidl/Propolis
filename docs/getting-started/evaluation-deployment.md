<!--
title: Evaluation Deployment
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Evaluation deployment (non-production)

A minimal local bring-up: build, provision a throwaway database, run the unified daemon
plus one sensor on loopback, and reach the console. This is for **evaluation only**.

> [!WARNING]
> This is not a production deployment. It skips the systemd sandboxing, per-service
> secret files, real syscall hardening, TLS proxy, and backups that a real deployment
> requires. Do **not** expose these listeners to untrusted networks. When you are ready
> to deploy for real, follow [installation](../operations/installation.md) and the
> [production-readiness checklist](production-readiness-checklist.md).

Egress note: in this minimal configuration Propolis makes no outbound requests beyond
PostgreSQL. Every enrichment/reporting egress path (VirusTotal, vendor abuse submitters,
console rDNS, ops-alert ntfy, malware fetcher) defaults **off** and is left off here. See
[outbound controls](../security/outbound-controls.md).

## 1. Build

```bash
cargo build --release
```

Produces `target/release/propolis` plus the sensor binaries (`sensor-ssh`, `sensor-telnet`,
`sensor-cred`, ...) (`deploy/install.sh:198`). Requires the pinned toolchain - see
[prerequisites](prerequisites.md).

## 2. Provision a disposable PostgreSQL

Example (podman), a localhost-only trust-auth container matching the dev/CI image
(`postgres:18`, `.env`):

```bash
# EXAMPLE - throwaway eval database, no password, loopback only
podman run -d --name propolis-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 \
  docker.io/library/postgres:18
```

The daemon creates its schema by running embedded migrations at startup
(`crates/propolis/src/main.rs:554-565`); no manual migrate step.

> [!WARNING]
> `trust` auth with no password is acceptable only for a loopback-bound throwaway
> container. Never use it for a database reachable off-host. See the pg_hba caution in
> [networking and TLS](../operations/networking-tls.md).

## 3. Minimal configuration

The daemon reads all config from environment variables and is fail-fast on any missing
required or malformed value (`crates/propolis/src/config.rs:1-3`). For an evaluation, the
minimum required set is:

```bash
# EXAMPLE - eval env, loopback only
export DATABASE_URL='postgres://postgres@127.0.0.1:5432/postgres'
export PROPOLIS_CONSOLE_PASSWORD='choose-a-strong-value'   # required; refuses to start if empty
export PROPOLIS_SENSOR_LOGS='ssh:/tmp/propolis-eval/ssh/events.jsonl'
export PROPOLIS_CURSOR_DIR='/tmp/propolis-eval/cursors'
mkdir -p /tmp/propolis-eval/ssh /tmp/propolis-eval/cursors
```

- `DATABASE_URL`, `PROPOLIS_CONSOLE_PASSWORD`, and `PROPOLIS_SENSOR_LOGS` are **required**
  (`config.rs:430,517,437`). `PROPOLIS_SENSOR_LOGS` is a `name:path,...` map of each
  sensor to the events file the daemon tails; it needs at least one entry
  (`config.rs:236-262`).
- `PROPOLIS_CONSOLE_BIND` defaults to `127.0.0.1:8080` (`config.rs:30`).
- `PROPOLIS_CONSOLE_SESSION_SECRET` is optional; if unset a fresh key is generated each
  start, so sessions do not survive a restart (`config.rs:371-389`) - fine for eval.

Every env var, its default, bounds, and fail-behavior are owned by
[reference/environment-variables.md](../reference/environment-variables.md); the paths
above are examples, not defaults.

## 4. Run the daemon

```bash
./target/release/propolis
```

Startup sequence (`crates/propolis/src/main.rs:511-577`): init logging -> load+validate
config (exit 1 on bad config) -> connect the PgPool (exit 1 on failure) -> run
core-scoring then review migrations (exit 1 on failure) -> create the cursor dir ->
spawn the intake/review/feed/console subsystems as concurrent tasks on one pool.

The unified daemon holds all four subsystems in one process; a panicked subsystem is
restarted internally with backoff, and a process exit means a fatal config/DB/migration
failure or a clean operator shutdown - see
[process topology](../architecture/process-topology.md).

## 5. Run one sensor locally

Bind the SSH sensor to a high unprivileged port (avoids needing `CAP_NET_BIND_SERVICE`)
and point its log at the same file named in `PROPOLIS_SENSOR_LOGS` above:

```bash
# EXAMPLE - eval SSH sensor on loopback high port
export PROPOLIS_SSH_BIND='127.0.0.1:2222'
export PROPOLIS_SSH_LOG_PATH='/tmp/propolis-eval/ssh/events.jsonl'
./target/release/sensor-ssh
```

`PROPOLIS_SSH_BIND` is required with no default; a zero or unparseable bound is rejected,
not defaulted (`crates/sensor-ssh/src/main.rs:23,70-79`). `PROPOLIS_SSH_LOG_PATH` defaults
to `/var/log/propolis/ssh/events.jsonl` (`sensor-ssh/src/main.rs:46`); the eval override
above keeps everything under a writable temp dir. Per-protocol capture behavior is owned
by [reference/sensor-behavior.md](../reference/sensor-behavior.md).

## 6. Reach the console

Open `http://127.0.0.1:8080/` and log in with `PROPOLIS_CONSOLE_PASSWORD`. The console is
plain HTTP on loopback - there is **no in-process TLS** (`crates/propolis/src/main.rs:413-424`).
Next: [produce your first capture](first-capture.md) and take the
[console tour](console-tour.md).

## Teardown

When done, stop both processes (Ctrl-C; the daemon does a graceful shutdown with a 30s
timeout) and remove the eval database container:

```bash
podman rm -f propolis-pg
rm -rf /tmp/propolis-eval
```

Full teardown guidance is in [safe teardown](safe-teardown.md).
