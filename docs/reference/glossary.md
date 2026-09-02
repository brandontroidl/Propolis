<!--
title: Glossary
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Glossary

Canonical definitions of Propolis terminology. Exact numeric values (weights,
thresholds, tier cutoffs, retention windows, ports) are owned by the reference
pages linked from each term, not restated here.

### Honeypot

A deliberately exposed decoy service that has no legitimate users, so every
connection to it is unsolicited and presumptively hostile. Propolis is a
single-node honeypot platform: its sensors present decoy services and record
what connects to them.

### Sensor

An attacker-facing decoy service. There are 9 sensor crates covering 12
protocols (the `cred` sensor alone serves VNC/MySQL/MSSQL/PostgreSQL/MongoDB).
Each sensor runs as its own OS process, binds a configured address, and writes
NDJSON event logs; it holds no HTTP client and makes no outbound requests (see
*egress-free*). Per-protocol capture behavior is documented in
[`sensor-behavior.md`](sensor-behavior.md).

### Persona

A sensor's presented identity - banners, negotiated options, and canned
responses chosen so the decoy resembles a real service rather than a honeypot.
Personas live in the shared sensor framework
(`crates/sensor-framework/src/lib.rs`).

### Fake shell / fake filesystem

The simulated interactive shell and directory tree that SSH, Telnet, and ADB
sensors present to an attacker who reaches a command prompt. Provided by the
sensor framework; commands are logged, never executed. See
[`../security/never-execute.md`](../security/never-execute.md).

### Signal type

The classification of an observed event (16 distinct variants,
`crates/core-scoring/src/domain/enums.rs`). Signal types, event fields, and the
weight each contributes are owned by
[`events-and-signals.md`](events-and-signals.md).

### Category / protocol / authenticated

The three event attributes that decide whether a sighting *confirms* an
attacker rather than merely records traffic. Only a TCP event that is
authenticated and categorized `Honeypot` sets the confirmed-real latch
(`is_confirmed_real`, `crates/core-scoring/src/domain/enums.rs:115`).

### Confirmed-real latch

A sticky per-IP flag meaning "this IP completed a full authenticated honeypot
interaction at least once." It is set the first time an event satisfies the
confirmed-real predicate (TCP + authenticated + `Honeypot` category) and never
clears thereafter (`crates/core-scoring/src/scoring/engine.rs:144-146`). A
spoofed source cannot forge it, because it requires a completed authenticated
TCP handshake from an address the sender actually controls. It gates
*eligibility*.

### Eligibility

Whether an IP may be published to the blocklist feed. An IP is eligible only
when it is not delisted, has the confirmed-real latch, and has at least two
recorded events (`crates/core-scoring/src/scoring/eligibility.rs:1-8`). Raw
score alone never makes an IP eligible. Thresholds are owned by
[`scoring-and-feed.md`](scoring-and-feed.md).

### Score / breadth / effective score

The raw score is the accumulated weight of an IP's events; *breadth* is a bonus
for being seen from multiple independent WAN vantage points; the *effective
score* is the breadth-adjusted total (`effective_score`,
`crates/core-scoring/src/scoring/breadth.rs`). Breadth only counts a vantage
that saw authenticated TCP, and collapses vantages sharing a /24 (IPv4) or /64
(IPv6) prefix to a single entry. Constants and the formula are owned by
[`scoring-and-feed.md`](scoring-and-feed.md).

### WAN vantage

One outward-facing IP address from which the honeypot was reached - a single
observation point on the attacker's network reach. Multiple distinct vantages
observing the same source IP is the evidence *breadth* rewards
(`WanVantage`, `crates/core-scoring/src/scoring/breadth.rs`).

### Tier

A published-severity band an eligible IP falls into based on its effective
score, used by the blocklist feed. Tier boundaries are owned by
[`scoring-and-feed.md`](scoring-and-feed.md).

### Retention window

The bounded time span over which events are retained and count toward scoring;
older data ages out. The exact window is owned by
[`scoring-and-feed.md`](scoring-and-feed.md) /
[`../operations/retention.md`](../operations/retention.md).

### Hash chain

The tamper-evidence mechanism of the event ledger: each appended event is
chain-hashed against its predecessor so that after-the-fact modification of a
recorded event is detectable (`crates/core-scoring`, ledger append path). See
[`../architecture/storage.md`](../architecture/storage.md).

### Spool / quarantine spool

An on-disk staging area for captured samples (uploaded files, fetched malware),
rooted at `/var/spool/propolis`. In production each spool directory must be a
`noexec,nosuid,nodev` mount so a captured payload can never be executed from it.
Paths are owned by [`filesystem-paths.md`](filesystem-paths.md); custody rules
in [`../security/malware-custody.md`](../security/malware-custody.md).

### Handoff (capture hand-off)

The controlled transfer of a captured artifact from a sensor process to the
spool for later analysis. The sensor writes the capture to its quarantine spool;
nothing is forwarded off-host automatically.

### Ledger / intake

The append-only event store is the *ledger* (owned by `core-scoring`).
*Intake* is the subsystem that tails sensor NDJSON logs, converts wire events to
domain events, and appends them to the ledger. See
[`../architecture/event-and-sample-lifecycle.md`](../architecture/event-and-sample-lifecycle.md).

### Review queue / gatekeeper

The operator-facing pipeline that surfaces candidate IPs for a human decision
(approve / reject / snooze) before any vendor report is sent. The *gatekeeper*
applies the rules that decide what enters the queue. Operator commands are in
[`commands.md`](commands.md).

### Feed / blocklist feed

The published output: eligible IPs exported as text/JSON/CSV/CIDR with an
atomic, checksummed manifest (`crates/feed`). Distribution off-host is an
operator step, not wired into a shipped timer. See
[`scoring-and-feed.md`](scoring-and-feed.md).

### Egress-free (scoped)

A precise claim: **the sensor crates** are egress-free by construction - each
has no HTTP client in its dependency tree, enforced by per-sensor tests. The
**platform** is not egress-free: it has a small number of enrichment/reporting
outbound paths (VirusTotal, vendor abuse submitters, console rDNS, ops-alert
ntfy), every one opt-in and defaulting off, plus offline GeoLite2 enrichment
that is local file reads, not network. Never state that the whole system makes
no outbound requests. The enumerated paths are owned by
[`../security/outbound-controls.md`](../security/outbound-controls.md).

### Unified daemon

The `propolis` binary, which runs intake, review, feed, console, VirusTotal,
the malware fetcher, and the ops-monitor as concurrent supervised tokio tasks
sharing one PostgreSQL connection pool. In production it supersedes the
separate intake/review/feed/console dev units. See
[`../architecture/process-topology.md`](../architecture/process-topology.md).

### Delisted

An IP explicitly removed from feed eligibility regardless of its score; a
delisted IP is never eligible (`crates/core-scoring/src/scoring/eligibility.rs`).
