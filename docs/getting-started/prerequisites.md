<!--
title: Prerequisites
audience: deployer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Prerequisites

What you need before building or running Propolis. This page lists requirements; exact
values (ports, paths, env vars) live in the [reference section](../reference/) and are
linked, not restated.

## Operating system

- Linux with systemd. Tested on Fedora 43; any systemd-based distribution works
  (`INSTALL.md:3-7`).
- The production units rely on systemd sandboxing directives, some requiring systemd
  >= 244 (`NoExecPaths`) - see [service lifecycle](../operations/service-lifecycle.md).
- Non-Linux hosts are unsupported.

## Rust toolchain (building from source)

- Pinned to the exact version `1.96.1` via `rust-toolchain.toml` (`channel = "1.96.1"`,
  `rust-toolchain.toml:6`). Not "stable" - the pin is deliberate for reproducible builds.
- Required components: `clippy`, `rustfmt` (`rust-toolchain.toml:7`). Install with
  `rustup`, which provides matched `rustc`/`clippy`/`rustfmt` for the pinned version.
- Edition 2024 across the workspace.
- Build command: `cargo build --release` (`README.md:65`, `INSTALL.md:15`). See
  [build and test](../development/build-and-test.md) for the full gate.

## PostgreSQL

- PostgreSQL 15 or newer, one database shared by all nodes (`INSTALL.md:8-9`).
  The "15+" figure is an INSTALL.md requirement; the binary does **not** enforce a
  version check in code [not-evidenced - `crates/propolis/src/main.rs:542-565` connects
  and migrates without a version gate].
- The daemon connects via `DATABASE_URL` and runs its own embedded migrations at
  startup - there is no separate migrate step (`crates/propolis/src/main.rs:554-565`).
- For a disposable evaluation database, see
  [evaluation deployment](evaluation-deployment.md).
- Table/enum/migration details are owned by [reference/database.md](../reference/database.md).

## Network ports

Sensors have **no compiled-in default port** - each sensor's bind address is a required
config value with no default, set per host in its `.env` file (GLOBAL: ports come from
`deploy/`, not code). The console binds loopback `127.0.0.1:8080` by default
(`crates/propolis/src/config.rs:30`).

You need the ports you intend to expose to be free on the host. The canonical port/bind
mapping (what `deploy/` configures) is owned by
[reference/ports-and-protocols.md](../reference/ports-and-protocols.md). Binding sensors
to privileged ports (< 1024, e.g. SSH 22) requires `CAP_NET_BIND_SERVICE`, granted by the
sensor units; a local non-root evaluation should use high ports instead.

## Privilege

- Building and evaluating locally need no root.
- `deploy/install.sh` requires root (creates system users, installs units and binaries);
  it does **not** start services, create the database, or write any secret `.env` file -
  those are operator steps (`deploy/install.sh:19-32`). See
  [installation](../operations/installation.md).

## Before internet exposure

Prerequisites for a lab bring-up are not the bar for production. Before exposing any
listener to untrusted traffic, work through the
[production-readiness checklist](production-readiness-checklist.md).
