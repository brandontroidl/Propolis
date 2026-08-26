# Propolis

Self-hosted honeypot and threat-intelligence platform. Native protocol sensors capture
hostile traffic on your own infrastructure, an append-only hash-chained ledger scores
each source by corroborated evidence, and - only after you approve each case - Propolis
publishes a firewall blocklist and files vendor abuse reports.

Single Rust workspace, PostgreSQL as the one datastore, a loopback operator console, and
hardened per-sensor systemd services. Every sensor is passive: it captures, it never runs
what it captures.

> **This is the front door.** Full documentation lives under [`docs/`](docs/README.md);
> start with **[DOCUMENTATION.md](DOCUMENTATION.md)** for the map, or jump to a
> [manual for your role](docs/README.md#manuals).

## What it is

- **9 sensor crates covering 12 protocols** in one deployment (SSH, Telnet, HTTP, FTP,
  SMTP, Redis, ADB, a catch-all port-scan sensor, and a multi-protocol credential sensor
  for VNC/MySQL/MSSQL/PostgreSQL/MongoDB), each a dedicated hardened service.
- **Evidence-based scoring** with a *confirmed-real* gate: an IP earns a feed tier or a
  vendor report only after a completed TCP handshake authenticates against a honeypot
  sensor - spoofable UDP or lone-SYN traffic never latches it.
- **Human-approved output**: nothing is published to the blocklist feed or reported to a
  vendor without explicit operator approval in the console.
- **An append-only, hash-chained PostgreSQL ledger**: every score is reproducible by
  replaying the evidence; the chain is enforced by a database trigger.

See [capabilities](docs/overview/capabilities.md) and the
[architecture overview](docs/architecture/index.md).

## Who it is for

Defenders running a honeypot on infrastructure they own and are authorized to monitor:
home labs, researchers, educators, nonprofit / public-safety / government operators, and
contributors. See [intended audiences](docs/overview/audiences.md) and
[ethical-use boundaries](docs/overview/ethical-use.md).

## What it does NOT do

Not a network IDS, not a multi-tenant SaaS, not an exploit or offensive tool, not a
managed service. It ships **no in-process TLS** (put a reverse proxy in front of the
console) and the systemd `SystemCallFilter` in the shipped units is a **placeholder** you
are expected to tighten. See [non-goals](docs/overview/non-goals.md) and
[limitations](docs/overview/limitations.md).

## Maturity

Source-available and actively developed. The only release **tag is `v0.1.0`**; the
current tree is `0.3.0` (untagged) and carries roughly two minor bumps of unreleased
work, including the V12 operator console. It is **not** certified or blessed for
production - read [maturity and status](docs/overview/maturity-and-status.md) and the
[production-readiness checklist](docs/getting-started/production-readiness-checklist.md)
before internet exposure.

## Security cautions

Propolis is designed to sit on the public internet receiving hostile traffic.

- It **captures live malware** into a sterile, `noexec` spool and never executes it -
  handle the spool accordingly ([malware custody](docs/security/malware-custody.md)).
- It makes **no outbound requests except five operator-gated paths that all default off**
  (VirusTotal, the AbuseIPDB/DShield/OTX submitters, console reverse-DNS, and ops-alert
  ntfy); the sensors themselves are egress-free by construction
  ([outbound controls](docs/security/outbound-controls.md)).
- Single node = single blast radius; keep off-host backups.

Full picture: [threat model](docs/security/threat-model.md),
[hardening checklist](docs/security/hardening-checklist.md),
[residual risks](docs/security/residual-risks.md). Report a vulnerability privately via
[SECURITY.md](SECURITY.md).

## Minimal quickstart (evaluation only)

> **Warning:** this brings up listeners that accept hostile traffic. Do it on an isolated
> host you control, not on a production network, until you have read the
> [production-readiness checklist](docs/getting-started/production-readiness-checklist.md).

```
cargo build --release            # pinned toolchain in rust-toolchain.toml
# provide DATABASE_URL + PROPOLIS_CONSOLE_PASSWORD, then run a local evaluation:
```

The full, verified evaluation path is in
[getting-started/evaluation-deployment](docs/getting-started/evaluation-deployment.md);
production installation is in [operations/installation](docs/operations/installation.md).

## Documentation

- **[DOCUMENTATION.md](DOCUMENTATION.md)** - the corpus map and where to start by role.
- **[docs/](docs/README.md)** - the full layered corpus (overview, getting-started,
  architecture, operations, security, development, reference, governance, troubleshooting,
  history).
- **[docs/binder/HANDOFF-BINDER.md](docs/binder/HANDOFF-BINDER.md)** - the complete linear
  handoff binder (offline reading, transfer, audit, AI ingestion).
- **[Reference](docs/reference/environment-variables.md)** - every environment variable,
  port, path, table, route, and signal.

## Build and architecture

Rust (2024 edition), all dependencies vendored in-tree; PostgreSQL as the single
datastore; hardened systemd units (`ProtectSystem=strict`, `NoNewPrivileges`,
`MemoryDenyWriteExecute`, dedicated per-sensor users). No third-party honeypot code -
every sensor is self-authored. See the [architecture section](docs/architecture/index.md)
and [supply chain](docs/security/supply-chain.md).

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE.md) - **not**
open source. Free for personal, home-lab, research, educational, nonprofit, and government
use; commercial use requires a separate license. See
[governance/licensing](docs/governance/licensing.md).
