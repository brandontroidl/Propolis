<!--
title: Deployment models
audience: deployer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
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
production and are not installed by `install.sh`**
(`deploy/install.sh#deliberately NOT installed here`).
They remain in the repo for development only; do not deploy them as the
production surface.

## Multi-node cluster

Multiple nodes can share one PostgreSQL database: scoring aggregates in the
shared DB, and review/feed are designed to be idempotent so more than one node
can run them against the same data
(`docs/archive/2026-08-26/root/INSTALL.md#Multi-node deployment`).

What is enforced in code and tested with two independent connection pools:

- **Malware fetcher.** Each cycle claims its rows in one transaction, so no two
  nodes fetch the same URL, and the per-host hourly and daily caps are shared
  budgets in the database rather than one budget per node. See
  [rate limits and budgets](../reference/rate-limits-and-budgets.md#per-cycle-and-per-host).
- **Vendor submissions.** A unique `{ip}:{vendor}:{date}` idempotency key is
  claimed in the database before the external call, so concurrent nodes do not
  submit the same IP to the same vendor twice in a day.

Feed publication across nodes remains [inferred] from the `INSTALL.md` claim; no
cross-node test covers it. The single-node model is the one exercised in
practice, so treat cluster deployment as an advanced, less-travelled path and
validate feed behaviour in your own environment before relying on it.

## Hardware and OS assumptions

- **OS:** Linux with systemd. The unit files use systemd `>= 244` directives
  (`NoExecPaths=`, `deploy/propolis.service#NoExecPaths=`); every currently-supported
  distro ships well past that.
- **PostgreSQL:** version 15+ is the `INSTALL.md` claim
  (`docs/archive/2026-08-26/root/INSTALL.md#Prerequisites`; the live `INSTALL.md` is now a redirect stub). The
  binary connects via `DATABASE_URL` and runs its own migrations at startup; no
  DB-version check exists in the code [inferred from the absence of a version
  gate], so "15+" is an operator requirement, not an enforced one.
- **Rust toolchain** (build host only): pinned to `1.96.1`
  (`rust-toolchain.toml`). See
  [../development/toolchain-and-environment.md](../development/toolchain-and-environment.md).
- **Resource envelope:** the unified daemon unit caps at `MemoryMax=1G`,
  `TasksMax=256`, `CPUQuota=100%`, `LimitNOFILE=4096`
  (`deploy/propolis.service#MemoryMax=1G`, `deploy/propolis.service#TasksMax=256`,
  `deploy/propolis.service#CPUQuota=100%`, `deploy/propolis.service#LimitNOFILE=4096`) - the highest
  in the deploy set, since one
  process holds all four subsystems. Per-sensor caps are lower (256M–512M). See
  [capacity-planning.md](capacity-planning.md).

## Maturity

Source-available and actively developed, with one tagged release (`v0.1.0`); the
current tree is `0.4.0` and untagged. This is not a production-certified or
production-blessed build - see
[../overview/maturity-and-status.md](../overview/maturity-and-status.md) and
[../getting-started/production-readiness-checklist.md](../getting-started/production-readiness-checklist.md).

## Related

- [installation.md](installation.md) - build, install, and unit layout
- [configuration.md](configuration.md) - configuration model
- [../architecture/process-topology.md](../architecture/process-topology.md) - process/task topology
- [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md) - ports and binds
