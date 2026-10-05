<!--
title: Compatibility and versioning
audience: all
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Compatibility and versioning

## Version scheme

Propolis uses semantic-versioning-shaped version numbers (`MAJOR.MINOR.PATCH`).
Every workspace crate pins its own `version` independently; there is no shared
`[workspace.package]` version key. Eighteen crates have moved together (currently
`0.4.0`); the six added since `0.3.0` are at `0.1.0` and have not been bumped yet.
Pre-1.0, treat minor bumps as potentially breaking.

## Current version/tag state

- **Crate version: `0.4.0`** for nineteen of the 25 workspace crates; `0.1.0` for
  `collector-wire`, `fleet`, `gateway`, `log-tailer`, `provision-certs` and `shipper`.
- **Only release tag: `v0.1.0`** (points at commit `e0bfd513`,
  2026-08-02). There is no `v0.2.0`, `v0.3.0` or `v0.4.0` tag.
- The `0.4.0` tree is therefore **unreleased/untagged** - roughly three minor
  bumps of work sit ahead of the tagged release.
- No `rust-version` / MSRV is declared in any crate.

The single source of truth for maturity, implemented-vs-partial status, and the
version/tag divergence is
[../overview/maturity-and-status.md](../overview/maturity-and-status.md).

## Compatibility surfaces

### Sensor wire contract - frozen

The `sensor-wire` crate defines the event contract between sensors and the
platform and is treated as a **frozen contract** (guarded by its own tests).
Changes to it are compatibility-sensitive and are not made casually.

### Database schema - additive

Schema evolution is **additive**: new columns/fields are optional so existing
rows still validate, and stored data is transformed only through explicit
migration code, never silent runtime shims. The database schema, tables, enums,
and migration list are owned by
[../reference/database.md](../reference/database.md); the migration workflow is
in [../development/schema-and-migrations.md](../development/schema-and-migrations.md).

### Collector-to-gateway wire - lock-step

Every frame a `shipper` sends carries a version byte, and there is no negotiation: a `gateway`
rejects any other version, and a shipper stops on a rejection
(`crates/collector-wire/src/frame.rs#VERSION`, `crates/collector-wire/src/frame.rs#decode_frame`).
A change to the wire therefore has to reach the control plane and every collector together; see
[split deployment](../operations/split-deployment.md#upgrading).

### Configuration - additive

New configuration is introduced with safe defaults so an existing deployment
keeps working without changes. Exact env-var names, defaults, and bounds are
owned by
[../reference/environment-variables.md](../reference/environment-variables.md).

## Upgrade and rollback

Operational upgrade, rollback, and disaster-recovery procedure is documented in
[../operations/upgrade-rollback-and-dr.md](../operations/upgrade-rollback-and-dr.md).
