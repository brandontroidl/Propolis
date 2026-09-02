<!--
title: Deployment models
audience: deployer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Deployment models

Propolis runs on Linux with systemd. It supports a single-node deployment (the
primary, documented model) and a multi-node cluster sharing one PostgreSQL
database.

## Single node (primary)

One host runs everything:

- The **unified daemon** `propolis` (one process) runs intake, review, feed, and
  the operator console as concurrent tokio tasks over a single PgPool
  (`crates/propolis/src/main.rs`, `deploy/propolis.service`).
- The **sensor binaries** (`sensor-ssh`, `sensor-telnet`, `sensor-http`,
  `sensor-ftp`, `sensor-smtp`, `sensor-redis`, `sensor-adb`, `sensor-catchall`,
  `sensor-cred`) each run as their own systemd service and their own OS user.
  Sensors are always separate processes; they are never embedded in the unified
  daemon.

The daemon consumes each sensor's JSONL event log from disk (via
`PROPOLIS_SENSOR_LOGS`); it does not connect to the sensors over the network.
This is the configuration installed by `deploy/install.sh` and the one the rest
of the operations docs assume. See [installation.md](installation.md).

There is a second, dev/testing-only way to run the platform: the four standalone
service binaries `intake`, `review`, `feed`, and `console` as separate units
(`deploy/intake.service`, `deploy/review.service`, `deploy/feed.service`,
`deploy/console.service`). These are **superseded by `propolis.service` in
production and are not installed by `install.sh`** (`deploy/install.sh:14-17`).
They remain in the repo for development only; do not deploy them as the
production surface.

## Multi-node cluster

Multiple nodes can share one PostgreSQL database: scoring aggregates in the
shared DB, and review/feed are designed to be idempotent so more than one node
can run them against the same data (`INSTALL.md:364-376`). [inferred] - this is
an `INSTALL.md` claim; no cluster-coordination code was read to confirm the
idempotency guarantee, and the single-node model is the one exercised in
practice. Treat cluster deployment as an advanced, less-travelled path and
validate review/feed idempotency in your own environment before relying on it.

## Hardware and OS assumptions

- **OS:** Linux with systemd. The unit files use systemd `>= 244` directives
  (`NoExecPaths=`, `deploy/propolis.service:157-159`); every currently-supported
  distro ships well past that.
- **PostgreSQL:** version 15+ is the `INSTALL.md` claim (`INSTALL.md:9`). The
  binary connects via `DATABASE_URL` and runs its own migrations at startup; no
  DB-version check exists in the code [inferred from the absence of a version
  gate], so "15+" is an operator requirement, not an enforced one.
- **Rust toolchain** (build host only): pinned to `1.96.1`
  (`rust-toolchain.toml`). See
  [../development/toolchain-and-environment.md](../development/toolchain-and-environment.md).
- **Resource envelope:** the unified daemon unit caps at `MemoryMax=1G`,
  `TasksMax=256`, `CPUQuota=100%`, `LimitNOFILE=4096`
  (`deploy/propolis.service:170-173`) - the highest in the deploy set, since one
  process holds all four subsystems. Per-sensor caps are lower (256M–512M). See
  [capacity-planning.md](capacity-planning.md).

## Maturity

Source-available and actively developed, with one tagged release (`v0.1.0`); the
current tree is `0.3.0` and untagged. This is not a production-certified or
production-blessed build - see
[../overview/maturity-and-status.md](../overview/maturity-and-status.md) and
[../getting-started/production-readiness-checklist.md](../getting-started/production-readiness-checklist.md).

## Related

- [installation.md](installation.md) - build, install, and unit layout
- [configuration.md](configuration.md) - configuration model
- [../architecture/process-topology.md](../architecture/process-topology.md) - process/task topology
- [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md) - ports and binds
