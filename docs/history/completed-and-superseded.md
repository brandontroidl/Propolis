<!--
title: Completed and superseded work
audience: all
status: historical
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Completed and superseded work

A record of build milestones that are complete and of designs that have been
replaced. Exact current behavior lives in the reference and architecture sections;
this page is history, not a source of current values.

## Completed build (SP1-SP8)

The original build shipped as eight sub-projects, all present in the tree and listed
in the root [`CHANGELOG.md`](../../CHANGELOG.md) `Added` section. Each maps to one or
more crates under `crates/`.

| Sub-project | Delivered | Now documented in |
|---|---|---|
| **SP1: core scoring** | Domain model, PostgreSQL schema, append-only hash-chained event ledger, time-decayed scoring, eligibility/weight/recommendation gates, multi-WAN breadth model | [architecture/pipeline](../architecture/pipeline.md), [reference/scoring-and-feed](../reference/scoring-and-feed.md), [architecture/storage](../architecture/storage.md) |
| **SP2: sensor framework + SSH** | Shared sensor harness (listener, event emitter, capture handoff, quarantine spool, WAN resolver, fake filesystem/shell), catch-all port-scan sensor, SSH honeypot with vendored crypto; wire contract frozen | [architecture/sensors](../architecture/sensors.md), [reference/sensor-behavior](../reference/sensor-behavior.md) |
| **SP3: event intake** | Rotation-aware sensor-log tailer with a durable cursor, direct-PostgreSQL aggregation | [architecture/event-and-sample-lifecycle](../architecture/event-and-sample-lifecycle.md) |
| **SP4: review queue and reporting** | Human-approval gate, per-vendor submission gatekeeper, AbuseIPDB/DShield/OTX adapters | [architecture/pipeline](../architecture/pipeline.md), [reference/integrations](../reference/integrations.md) |
| **SP5: blocklist feed** | Two-tier export (aggressive/standard) with anti-deanonymization coarsening, fail-closed publisher | [reference/scoring-and-feed](../reference/scoring-and-feed.md) |
| **SP6: web console** | Operator dashboard: review queue, IP detail, feed status, metrics, rate-limited login | [architecture/console](../architecture/console.md), [reference/console-routes](../reference/console-routes.md) |
| **SP7: unified daemon** | `propolis` binary composing intake/review/feed/console as supervised tokio tasks over one PgPool; hardened systemd unit and idempotent install script | [architecture/process-topology](../architecture/process-topology.md) |
| **SP8: seven added sensors** | telnet, redis, adb, http, ftp, smtp, and a credential multi-protocol sensor (VNC/MySQL/MSSQL/PostgreSQL/MongoDB), each a dedicated hardened service | [reference/sensor-behavior](../reference/sensor-behavior.md), [reference/ports-and-protocols](../reference/ports-and-protocols.md) |

Together these give **9 sensor crates covering 12 protocols** (the credential sensor
serves five). The exact protocol/port mapping is owned by
[reference/ports-and-protocols](../reference/ports-and-protocols.md).

### Post-tag feature work

Beyond SP1-SP8, several features merged after the `v0.1.0` tag: forward-confirmed
reverse DNS, trusted-org ASN suppression, the IP-detail network-profile panel with
offline GeoLite2 enrichment, telnet XOR de-obfuscation, operational self-alerting,
and the V12 operator-console interface. These are covered in
[changelog](changelog.md) and, for the console, below.

## Superseded designs

### Earlier console direction -> V12 operator-console interface

The earlier operator-console visual/interaction direction was **superseded by the
V12 operator-console interface**, merged post-tag at commit `dbf8c053`. V12 is the
current console UI: a theme system (default `graphite`, plus `cream`, `system`, and
a `hacker` theme) with an in-page theme switcher, an evidence drawer that renders the
IP dossier via an HTMX request, and self-hosted fonts.

Two consequences worth recording:

- The earlier direction is **no longer current**; the current console is documented
  in [architecture/console](../architecture/console.md) and
  [reference/console-routes](../reference/console-routes.md).
- V12 is **not yet reflected in the root changelog** - see
  [changelog](changelog.md#not-yet-in-the-changelog). The README's console section
  also predates V12 and does not describe the theme system or evidence drawer.

The verbatim pre-rewrite public documents are preserved immutably under
[`docs/archive/2026-08-26/`](../archive/2026-08-26/MANIFEST.md); see
[archive-map](archive-map.md).
