<!--
title: Prerequisites
audience: deployer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Prerequisites

## Operating system

Linux with systemd. Development and the production box run Fedora and Debian; any
systemd distribution should work. The shipped units use sandboxing directives that need
a reasonably current systemd; one of them (`NoExecPaths`) arrived in systemd 244.
Nothing else is supported.

## Rust toolchain

The toolchain is pinned to an exact version in `rust-toolchain.toml`, including `clippy`
and `rustfmt`. Install `rustup` and the pin is applied automatically when you build in
the checkout. The workspace uses the 2024 edition. Building needs no root.

```bash
cargo build --release
```

## PostgreSQL

PostgreSQL 15 or newer. The project's own tests and CI run against 18. The daemon
connects with `DATABASE_URL` and applies its own migrations at startup; there is no
separate migrate step and the binary does not check the server version.

For a throwaway evaluation database, the [quickstart](../manuals/quickstart.md) starts
one in a container.

## Network ports

Sensors have no compiled-in default port; each one's bind address is a required setting,
and the shipped unit files put them on the standard ports (SSH on 22 and so on). Binding
below 1024 needs `CAP_NET_BIND_SERVICE`, which the sensor units grant; a local
evaluation as an ordinary user should use high ports instead. The console listens on
`127.0.0.1:8080` unless told otherwise. The full port list is in
[ports and protocols](../reference/ports-and-protocols.md).

## Privilege

Building and running an evaluation need no root. `deploy/install.sh` needs root to create
the service users, directories and unit files. It does not start any service, create the
database, or write any secret file; those are yours to do, following
[installation](../operations/installation.md).

## Before exposing anything

A lab bring-up and an internet-facing deployment have different bars. Before any
listener accepts untrusted traffic, work through the
[production-readiness checklist](production-readiness-checklist.md).
