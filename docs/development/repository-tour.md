<!--
title: Repository tour
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Repository tour

Where each concern lives and how to find it. This page maps the tree; exact
tables, ports, routes, and constants are owned by the
[reference section](../reference/) and linked from here rather than restated.

## Top level

| Path | What it holds |
|---|---|
| `Cargo.toml` | Workspace root: `resolver = "2"`, 18 members, no `[workspace.dependencies]` and no `[workspace.package]` (every crate declares its own version and deps). |
| `Cargo.lock` | Committed, frozen in CI via `--locked`. |
| `rust-toolchain.toml` | Pins the exact toolchain (`1.96.1`) + `clippy`, `rustfmt`. See [toolchain-and-environment](toolchain-and-environment.md). |
| `.cargo/config.toml` | Redirects crates-io to the vendored source tree. |
| `vendor/` | All dependencies vendored in-tree. Do not edit. See [schema-and-migrations](schema-and-migrations.md#vendoring) and [`reference/dependencies`](../reference/dependencies.md). |
| `crates/` | The 18 workspace members (below). |
| `deploy/` | systemd units + `install.sh`. Owns real bind ports/paths at deploy time. See [`reference/ports-and-protocols`](../reference/ports-and-protocols.md). |
| `.github/workflows/ci.yml` | The authoritative build/test gate. See [build-and-test](build-and-test.md). |
| `.env` | Gitignored local dev config (test `DATABASE_URL`, podman recipe). Not committed. |
| `CONTRIBUTING.md`, `CHANGELOG.md`, `INSTALL.md`, `README.md`, `SECURITY.md`, `LICENSE.md` | Root docs. |

`internal/`, `docs/superpowers/`, `.superpowers/` are gitignored private material - not part of the source tour.

## Crates

18 workspace members (`Cargo.toml:3-21`). Full component inventory with binaries and dependency edges lives in [`architecture/components`](../architecture/components.md); the summary by concern:

**Foundation libraries (no internal deps):**
- `core-scoring` - event ledger, chain-hashing, scoring, blocklist eligibility; owns the core DB migrations (`crates/core-scoring/migrations/`).
- `sensor-wire` - the frozen sensor→intake NDJSON wire format (`WIRE_VERSION = 1`); imported by every sensor and by intake.
- `geoip` - offline MaxMind GeoLite2 City + ASN reader (local file reads only, no network).

**Sensor layer:**
- `sensor-framework` - the shared harness (listener lifecycle, WAN attribution, sanitize, emit, quarantine spool, capture hand-off, fake shell/fs, persona, bounds). Depends only on `sensor-wire`.
- `sensor-{catchall,ssh,telnet,redis,adb,http,ftp,smtp,cred}` - the 9 sensor binaries covering 12 protocols (`cred` alone serves VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Each depends only on `sensor-wire` + `sensor-framework` + `tokio`. See [adding-a-sensor](adding-a-sensor.md) and [`architecture/sensors`](../architecture/sensors.md).

**Data plane:**
- `intake` - tails sensor NDJSON logs, converts wire events to domain events, appends to the ledger.
- `review` - review-queue state machine, gatekeeper, vendor adapters (AbuseIPDB/DShield/OTX), VirusTotal scanner, malware fetcher, operator CLI; owns its own migrations (`crates/review/migrations/`).
- `feed` - blocklist snapshot builder + atomic publish (text/JSON/CSV/CIDR) with checksummed manifest.
- `console` - the operator web console (axum): auth, dashboard, review queue, IP detail, feed status, `/metrics`, `/logs`. See [`architecture/console`](../architecture/console.md).
- `propolis` - the unified daemon (binary only). Composes intake + review + feed + console + VirusTotal + fetcher + ops-monitor as concurrent tokio tasks on one `PgPool`. See [`architecture/process-topology`](../architecture/process-topology.md).

## Finding things

| Looking for… | Go to |
|---|---|
| A DB table, column, enum, or migration | `crates/core-scoring/migrations/`, `crates/review/migrations/`; documented in [`reference/database`](../reference/database.md). |
| The wire event format | `crates/sensor-wire/src/lib.rs`; documented in [`reference/events-and-signals`](../reference/events-and-signals.md). |
| Scoring weights / thresholds | `crates/core-scoring/src/domain/`; documented in [`reference/scoring-and-feed`](../reference/scoring-and-feed.md). |
| An env var's default / bound | source per crate (e.g. `crates/propolis/src/config.rs`, each sensor's `main.rs`); documented in [`reference/environment-variables`](../reference/environment-variables.md). |
| A console route | `crates/console/src/routes/`; documented in [`reference/console-routes`](../reference/console-routes.md). |
| How the daemon wires subsystems | `crates/propolis/src/main.rs`, `crates/propolis/src/supervisor.rs`. |
| Deploy units / install steps | `deploy/`; documented in [`operations/service-lifecycle`](../operations/service-lifecycle.md). |

There is no `Makefile` or `justfile` - build and test are plain `cargo` (verified absent).
