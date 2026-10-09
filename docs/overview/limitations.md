<!--
title: Limitations
audience: evaluator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
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

## One lock orders every append

The hash chain is one sequence, so every append, from every sensor, takes a single lock and
waits its turn; a faster writer would not change that. What bounds the rate is how long each
turn lasts. A turn used to be one event, and the cost of an event grew with intake lag
(migration `0013`, the dedup read; see [intake backlog](../troubleshooting/intake-backlog.md))
and with a source's history (migration `0014`, the breadth sets; see
[database reference](../reference/database.md#breadth-sets)). Neither grows now, and a turn is
a batch of up to 1000 lines in one transaction
(`crates/core-scoring/src/repository/batch.rs#append_events`). On a 1M-row test ledger with a
200k-event source on a RAM-backed server, intake appended 11,000 to 13,600 events a second in
batches of 1000, against 350 to 470 one at a time; where each commit waits on a disk flush the
one-at-a-time figure is lower and the batched one barely moves `[inferred]`. While a batch
commits, other sensors' writers wait: about 70 to 90 ms at 1000 lines. An event the database
refuses on every attempt (a NUL character in a command, which `jsonb` cannot store) still holds
that sensor's intake at its line, as it did before batching
([concurrency and failure](../architecture/concurrency-and-failure.md#serialized-single-writer-append)).

The `intake-lagging` alert and the fleet pane's behind badge make a backlog visible;
they do not remove it. While intake is behind, a `copytruncate` rotation moves the unread part
into `events.jsonl.1`, which the tailer reads before the new file, so nothing is dropped and the
lag readings include it. The rotation guard skips a log that is too far behind or whose `.1` is
unread ([retention](../operations/retention.md#rotation-while-intake-is-behind)); a log that
skips for long grows until `sensor-log-oversized` pages. If `.1` cannot be used, the unread part
is lost and `intake-rotation-loss` pages.

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
