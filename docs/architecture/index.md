<!--
title: Architecture overview
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Architecture

Propolis is a defensive single-node honeypot and threat-intelligence platform: a set
of attacker-facing sensors that capture unsolicited traffic, a scoring engine that
turns captured events into an IP reputation ledger, and a review/enrichment/feed
pipeline plus an operator console built on top of that ledger. It is a Rust workspace
of 18 crates producing 15 binaries.

For what Propolis is at the product level, its use cases, and its non-goals, see
[../overview/index.md](../overview/index.md). For maturity and version/tag state, see
[../overview/maturity-and-status.md](../overview/maturity-and-status.md).

## The one-node model

Propolis is designed to run as a single node. All state lives in one PostgreSQL
database, and the data-plane subsystems (intake, review, feed, console, plus the
VirusTotal scanner, malware fetcher, and ops-alert monitor) run inside **one
supervised daemon process** (`propolis`) sharing a single `PgPool`. The attacker-facing
sensors run as **separate OS processes**, one per sensor binary, so a crash or
compromise in a sensor cannot take down the data plane.

This split - a unified data-plane daemon alongside isolated per-sensor services - is
the defining structural decision of the deployment. It is detailed in
[process-topology.md](process-topology.md).

### What crosses the network boundary

Attacker-facing sensor crates are egress-free by construction: each has no HTTP client
in its own dependency tree, enforced by per-sensor tests. The platform as a whole is
**not** egress-free - it has a small number of enrichment and reporting egress paths
(VirusTotal, vendor abuse submitters, forward-confirmed rDNS, the ops-alert POST), and
each is operator-gated and defaults **off**. Offline GeoLite2 enrichment is local file
reads, not network. The full picture is in
[trust-boundaries-and-data-flows.md](trust-boundaries-and-data-flows.md) and
[../security/outbound-controls.md](../security/outbound-controls.md).

## How to read this section

- [components.md](components.md) - the workspace and component inventory: every crate,
  which are libraries vs. binaries, and how they depend on each other.
- [process-topology.md](process-topology.md) - the process/service model: the unified
  `propolis` daemon and its supervised tokio tasks vs. the per-sensor services;
  startup, supervision, and shutdown.
- [sensors.md](sensors.md) - sensor architecture and the shared sensor framework.
- [event-and-sample-lifecycle.md](event-and-sample-lifecycle.md) - capture to ledger to
  score; sample spool and hand-off.
- [pipeline.md](pipeline.md) - scoring, review, enrichment, and the feed pipeline.
- [console.md](console.md) - operator console architecture.
- [storage.md](storage.md) - the database model and the event hash chain.
- [evidence-provenance-and-artifact-custody.md](evidence-provenance-and-artifact-custody.md) - **Draft**: the SP-B evidence provenance graph, artifact custody protocol, and IP-to-captured-artifact attribution (not yet implemented).
- [concurrency-and-failure.md](concurrency-and-failure.md) - concurrency, backpressure,
  and failure modes.
- [decisions.md](decisions.md) - code-evidenced architecture decisions.

Reference pages own the exact values these narratives cite: environment variables in
[../reference/environment-variables.md](../reference/environment-variables.md), ports in
[../reference/ports-and-protocols.md](../reference/ports-and-protocols.md), filesystem
paths in [../reference/filesystem-paths.md](../reference/filesystem-paths.md), and the
database schema in [../reference/database.md](../reference/database.md).
