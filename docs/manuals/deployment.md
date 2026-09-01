<!--
title: Deployment manual
audience: deployer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Deployment manual

An ordered path for deploying Propolis to real infrastructure. Each step links
to the canonical page that owns its exact commands and values; this manual is the
sequence and the gates, not a re-listing.

> [!IMPORTANT]
> Propolis is source-available and actively developed, with one tagged release
> (`v0.1.0`) and a current tree at `0.3.0` (untagged). It carries **no**
> production, security, legal, or regulatory certification. The steps below
> reduce risk, not assurance - residual risks remain even when every item is
> done: see
> [`../security/residual-risks.md`](../security/residual-risks.md).

> [!WARNING]
> The sensors are **live, internet-facing attacker listeners**. Do not enable
> them until the host is positioned as intended (isolated VLAN, firewalled,
> out-of-band administration - the honeypot's port 22 is the *fake* SSH sensor,
> not a real admin channel). Deploy only on infrastructure you own or are
> authorized to monitor: [`../overview/ethical-use.md`](../overview/ethical-use.md).

## 0. Choose the deployment model

Single node is the primary, documented model: one host runs the unified daemon
plus the nine sensor processes, each its own systemd unit and OS user. A
multi-node cluster sharing one PostgreSQL is an advanced, less-travelled path
whose idempotency you must validate yourself.

- [`../operations/deployment-models.md`](../operations/deployment-models.md)

## 1. Prerequisites

Linux with systemd (units use directives requiring systemd >= 244), the pinned
Rust toolchain `1.96.1` on the build host, and PostgreSQL 15+ reachable via
`DATABASE_URL` (the daemon runs its own embedded migrations at startup - no
separate migrate step).

- [`../getting-started/prerequisites.md`](../getting-started/prerequisites.md)

## 2. Install

Build (`cargo build --release`), then `sudo ./deploy/install.sh` (root
required). The installer is idempotent and creates users, directories, binaries,
10 systemd units, and logrotate. It deliberately does **not** start any service,
**does not create or migrate the database**, and **does not write any
`/etc/propolis/*.env` file** - those are your steps.

- [`../operations/installation.md`](../operations/installation.md)

## 3. Configuration

Propolis is configured entirely through environment variables in
operator-authored per-service files under `/etc/propolis/` (`0600`, owned by the
service user). Startup is fail-fast on any missing-required or present-but-zero
numeric bound - a misconfiguration cannot silently disable a guard (the `cred`
and `smtp` sensors are the two lenient exceptions on non-bind bounds).

- Model and which file configures what:
  [`../operations/configuration.md`](../operations/configuration.md)
- Every variable, default, bound, and fail behavior (canonical):
  [`../reference/environment-variables.md`](../reference/environment-variables.md)

## 4. Secrets

Author the `.env` files by hand; no secret is created by the installer, read
from argv, or written back to disk. At minimum set `DATABASE_URL` (carries the
DB password inline - use a least-privilege role, not `trust` auth) and
`PROPOLIS_CONSOLE_PASSWORD` (Argon2id-hashed at startup, plaintext dropped).
Set `PROPOLIS_CONSOLE_SESSION_SECRET` (exactly 64 hex chars) if you want session
stability across restarts. Set vendor / VirusTotal / ntfy keys **only** for
egress paths you deliberately enable (all default off).

- [`../operations/secret-management.md`](../operations/secret-management.md)

## 5. Networking and TLS

Three exposure classes: attacker-facing sensors (operator-chosen `ip:port`, no
code default), the operator-facing console (loopback `127.0.0.1:8080` by
default), and no-listener subsystems.

> [!WARNING]
> **No in-process TLS.** The console is plain HTTP on a loopback `TcpListener`
> (`axum::serve`, no rustls). Any TLS is **operator-provided** - keep the console
> on loopback and front it with your own reverse proxy. `/health`, `/ready`, and
> `/metrics` are unauthenticated and share the console bind; they are acceptable
> only because it is loopback-only. Before any firewall change that could sever
> access, confirm out-of-band administration first.

- [`../operations/networking-tls.md`](../operations/networking-tls.md)
- Ports/binds (canonical):
  [`../reference/ports-and-protocols.md`](../reference/ports-and-protocols.md)

## 6. Hardening

Work the security-owned sequence before exposing anything to hostile traffic.
The single largest item: **derive the real `SystemCallFilter`** - every shipped
unit carries a placeholder (`@system-service` minus `@privileged @resources`),
a broad dev allowlist you must replace with a `strace`-derived per-binary set.
Also enforce the `noexec,nosuid,nodev` spool mounts (the installer prints fstab
guidance but does not create them) and confirm the other sandbox directives are
in effect.

- [`../security/hardening-checklist.md`](../security/hardening-checklist.md)
- What remains unmitigated regardless:
  [`../security/residual-risks.md`](../security/residual-risks.md)
- Egress paths, all default off:
  [`../security/outbound-controls.md`](../security/outbound-controls.md)

## 7. First start

After the `.env` files exist and the database is reachable, enable and start the
unified daemon and each sensor unit, then verify with `systemctl status` and
`journalctl`. Startup, health/readiness, and shutdown behavior:

- [`../operations/service-lifecycle.md`](../operations/service-lifecycle.md)
- [`../operations/health-and-observability.md`](../operations/health-and-observability.md)

## 8. Production-readiness gate

Do not treat first start as done. Work the full checklist - secrets, TLS/network
exposure, host/process hardening, backups verified by an actual restore,
retention, feed-repo privacy, opt-in egress, and ops alerting - before exposing
any listener to untrusted traffic.

- [`../getting-started/production-readiness-checklist.md`](../getting-started/production-readiness-checklist.md)

Backups are not a recovery path until restored end-to-end at least once:
[`../operations/backup-and-restore.md`](../operations/backup-and-restore.md) and
[`../operations/upgrade-rollback-and-dr.md`](../operations/upgrade-rollback-and-dr.md).

## After deployment

- Day-to-day operation: [operations manual](operations.md) and
  [`../operations/routine-procedures.md`](../operations/routine-procedures.md).
- Security posture assessment: [security manual](security.md).
- Decommissioning:
  [`../getting-started/safe-teardown.md`](../getting-started/safe-teardown.md).
