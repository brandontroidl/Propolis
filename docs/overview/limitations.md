<!--
title: Limitations
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-01
-->

# Limitations

Known limitations and residual risks that are in scope but not fully mitigated.
Scope decisions (what Propolis deliberately does not do) are in
[Non-goals](non-goals.md); the security-owned treatment is in
[`../security/residual-risks.md`](../security/residual-risks.md).

## Single-node blast radius

Propolis is a single-node platform. Sensors, the unified daemon, and PostgreSQL run
on one host; a compromise or failure of that host affects everything. There is no
built-in high availability, failover, or off-host redundancy. Backup and recovery
are operator responsibilities - see
[`../operations/backup-and-restore.md`](../operations/backup-and-restore.md).

## No in-process TLS

The console serves **plain HTTP on a loopback `TcpListener`** (`axum::serve`, no
rustls). There is no built-in transport encryption. Exposing the console beyond
loopback requires an operator-provided reverse proxy or tunnel to add TLS
`[inferred]`. See [`../operations/networking-tls.md`](../operations/networking-tls.md).

## Placeholder syscall filter

The systemd `SystemCallFilter` shipped in `deploy/` is a **placeholder** - a broad
development allowlist (`@system-service` minus `@privileged @resources`) that the
unit header itself says to tighten. It is **not a shipped hardened syscall filter**
and should be treated as a residual risk, not a delivered control. See
[`../security/hardening-checklist.md`](../security/hardening-checklist.md).

## Honeypot detectability

Sensors emulate real services but are not indistinguishable from them. A determined
adversary can fingerprint a honeypot (protocol quirks, timing, banners). Detection
degrades intelligence yield rather than causing direct harm, but it is an inherent
limitation of the approach. IP rotation is the practical lever when a deployment is
burned. See [`../security/attack-surfaces.md`](../security/attack-surfaces.md).

## Feed-repository exposure risk

Publishing the blocklist to a remote (e.g. a public repository) exposes which
addresses you list and, by inference, that you run a honeypot. Weigh this before
publishing. The publish step is operator-configured, giving you control over what is
exposed and where - see the manual-publish limitation below.

## Manual feed publish

Feed publishing / blocklist sync is an **operator setup step**
(`deploy/blocklist-sync.sh`, referenced by comment) and is **not wired into any
shipped systemd timer or cron**. Without operator configuration, the feed is built
locally but not pushed anywhere. See
[`../operations/routine-procedures.md`](../operations/routine-procedures.md).

## Egress paths exist and must be understood

Sensors are egress-free, but the platform has a small number of enrichment/reporting
egress paths (VirusTotal, vendor abuse submitters, reverse DNS, ntfy alerts). All
default off, but an operator enabling them takes on the associated outbound exposure.
Operational self-alerting is the one exception worth stating plainly: it can be
enabled with **no egress at all**, delivering alerts to the local log instead of
ntfy, so monitoring the node does not require accepting an outbound path.
See [`../security/outbound-controls.md`](../security/outbound-controls.md).
