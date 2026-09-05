# Propolis

Propolis is a self-hosted honeypot for collecting and reviewing hostile network traffic.
It includes native sensors for SSH, Telnet, HTTP, FTP, SMTP, Redis, ADB, VNC, MySQL,
MSSQL, PostgreSQL, and MongoDB, plus a silent catch-all listener that records probes on
whatever other TCP and UDP ports you point it at.

Events are stored in PostgreSQL, scored by source IP, and shown in a local operator
console. Operator approval is required for vendor reports and score-based blocklist
entries. A separate connection-volume rule can add high-volume TCP sources to retention
feeds automatically. Captured payloads are stored for analysis but are never executed.

## How it works

Each sensor is its own hardened systemd service running as its own user. Sensors accept
connections, impersonate the real service closely enough to keep an attacker talking, and
write what they see to an append-only event log. The unified daemon tails those logs into
a hash-chained PostgreSQL ledger, scores each source IP from the evidence, and serves the
console on loopback.

An IP only earns a feed tier or a vendor report after a completed TCP handshake has
authenticated against a sensor. Spoofable UDP traffic and lone SYNs do not count toward
that gate. The one automatic path is volume: a source with a thousand or more completed
connections on record and activity in the last day is added to the retention feeds
without review, so a flood is blocked even when no login was attempted. Score-based tiers
and vendor reports still wait for a decision in the console.

Captured files (SCP, SFTP, ADB pushes, FTP uploads, downloaded droppers) go to a spool
mounted `noexec`. VirusTotal lookups, abuse reports to AbuseIPDB, DShield and OTX, reverse
DNS in the console, and push alerts are the only outbound paths, and all of them are off
until configured.

## Building and trying it

The toolchain is pinned in `rust-toolchain.toml`.

```
cargo build --release
```

Building does not start anything. Running Propolis needs a PostgreSQL database, a
`DATABASE_URL`, a console password, and the sensor listeners, which by design accept
hostile traffic. Do a first run on an isolated host you control, not on a network you
care about, following
[getting-started/evaluation-deployment](docs/getting-started/evaluation-deployment.md).
Production installs use `deploy/install.sh` and are described in
[operations/installation](docs/operations/installation.md).

## Risks to know before exposing it

- The spool holds live malware. Treat the host and its backups accordingly.
- The console has no built-in TLS. Keep it on loopback or behind a reverse proxy.
- The shipped systemd `SystemCallFilter` is a placeholder to tighten for your kernel.
- One node is one blast radius. Keep an off-host copy of the database and spool.
- The last tagged release is `v0.1.0`; the tree is at `0.3.0` with unreleased work. Read
  the production-readiness checklist before internet exposure.

## Scope

Propolis is not an IDS, not multi-tenant, and not an offensive tool. It runs on
infrastructure you own and are authorized to monitor: home labs, research, teaching,
nonprofit and public-sector operations.

## Documentation

Everything else, including the architecture, threat model, operations runbooks, and the
reference for every variable, port, table and route, is under
[docs/](docs/README.md). Report a vulnerability privately via [SECURITY.md](SECURITY.md).

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md). Free for personal, research, educational,
nonprofit, and government use; commercial use needs a separate license.
