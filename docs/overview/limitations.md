<!--
title: Limitations
audience: evaluator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
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

## No in-process TLS on the console

The console serves **plain HTTP on a loopback `TcpListener`** (`console::server::serve`, HTTP/1.1, no
rustls). There is no built-in transport encryption for it (seven sensors do terminate TLS on their
attacker-facing ports, which does not protect operator traffic). Exposing the console beyond
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

## Intake append cost grows with a source's history

Open item, partly fixed. Intake appends one event per transaction under a single lock that keeps
the hash chain in order, so the slowest append sets the pace for every sensor
(`crates/core-scoring/src/repository/events.rs#append_event`). Migration `0013` removed the cost
that grew with intake lag (the dedup read; see [intake backlog](../troubleshooting/intake-backlog.md)).
Two remain:

- **Per-event history reads.** Each scored append reads every earlier event of its source to
  count distinct WAN vantages and sensors. That is linear in the source's history: on a 7.5M-row
  test ledger an append for a source with 100k events took about 0.7 s, and for one with 1.5M
  events about 7 s. A long-running bot loop on one address therefore still caps intake for its
  sensor, and through the lock slows the others. Keeping those per-source sets in the projection,
  so each append reads a handful of rows, is the next change `[planned]`.
- **One transaction and one lock acquisition per event.** Each append pays its own round trips
  and commit. Appending a batch of lines in one transaction, still one event at a time in order,
  is planned after the history reads `[planned]`.

The `intake-lagging` alert and the fleet pane's behind badge make the resulting backlog visible;
they do not remove it. While intake is behind, a `copytruncate` rotation of the log drops the
unread part from ingest (it stays in the rotated copy), and the lag readings fall back with it.

## Tailer misreads a small rotated log as growth

Open item, not yet fixed. The log tailer that intake, the shipper and `propolis-watch` share
detects a `copytruncate` rotation by the read offset passing the file's size, or by the first 256
bytes changing. Below 256 bytes those bytes change with ordinary appends too, so a file that was
under 256 bytes and has only grown is trusted as growth
(`crates/log-tailer/src/tailer.rs#LogTailer::maybe_false_positive_replaced`). If such a small log
is rotated and refilled past the old read offset before the next poll (one second for intake, a
quarter second for the watcher), the tailer keeps reading from the old offset and the start of the
new content is skipped. A production log is rotated at 100 MB (`deploy/logrotate-sensors.conf`),
so the window is narrow: it needs a rotation of an almost empty log, forced by hand, followed by
a burst. A fix needs a rotation signal that does not depend on the size of the leading window.

## Egress paths exist and must be understood

Sensors are egress-free, but the platform has a small number of enrichment/reporting
egress paths (VirusTotal, vendor abuse submitters, reverse DNS, ntfy alerts). All
default off, but an operator enabling them takes on the associated outbound exposure.
Operational self-alerting is the one exception worth stating plainly: it can be
enabled with **no egress at all**, delivering alerts to the local log instead of
ntfy, so monitoring the node does not require accepting an outbound path.
See [`../security/outbound-controls.md`](../security/outbound-controls.md).
