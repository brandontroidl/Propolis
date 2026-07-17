# Propolis

Propolis is a single-operator defensive honeypot and threat-intelligence platform. It runs self-authored sensors that capture hostile network traffic, attributes each observation to an attacker source IP, scores that IP with time-decayed corroborated signals, and, only after explicit human approval, files abuse reports with reputation vendors and publishes a tiered public blocklist feed. The problem it solves: turning noisy, attacker-controlled sensor telemetry into high-confidence, corroborated, human-ratified abuse intelligence without ever auto-reporting spoofable or single-sourced traffic, and without leaking secrets, passwords, or the operator's own infrastructure addresses.

This is a clean-room rebuild. Three things make it different from the prior system:

- **Native sensors.** Every honeypot and sensor is self-authored rather than assembled from third-party projects. This means one license, no bundling of external honeypot licenses, and no dependency on upstream projects that break or get abandoned. Native sensors are themselves attack surface, so they are built safe-by-construction: passive, unprivileged, no database handle, no secrets.
- **Multi-WAN breadth.** Propolis binds multiple WAN IPs and records which WAN IP each hit arrived on. An attacker seen across several of the operator's WAN IPs has that breadth folded into the weight that drives reporting: breadth raises an IP's weight and its reporting recommendation. Breadth never manufactures eligibility (see principles below).
- **Single-node or cluster on one shared score.** Propolis runs as a single multi-homed node or as several collector nodes. The purpose of the cluster is signal aggregation: every WAN-IP collector feeds one shared attacker score so cross-WAN breadth counts toward a single weight. PostgreSQL is the shared brain that makes that possible; replication and failover are a secondary benefit, not the goal.

## Tech stack

- **Language:** Rust.
- **Datastore:** PostgreSQL, the single canonical store.
- **Architecture:** event-sourced. Evidence is an append-only, hash-chained event ledger; each IP's score and decision are reproducible by replaying its events.

## Core principles

- **Human-approval gate.** Nothing is reported to a vendor or published to the feed without explicit operator approval. The pipeline only ever queues candidates.
- **Confirmed-real before we report.** An IP becomes eligible for reporting only after at least one confirmed-real event: a completed TCP handshake or authenticated honeypot event. A completed handshake proves the source IP is real; reports built on spoofable UDP or lone-SYN traffic get vendor reporter accounts penalized.
- **Breadth raises weight, never manufactures eligibility.** Breadth and accumulated signal raise an IP's weight and its reporting recommendation, but they can never make an ineligible IP eligible. Only a confirmed-real event does that. This anti-spoof floor is an invariant.
- **Passive-only sensors.** Sensors capture and log. They never respond, never hack back, run unprivileged, hold no database handle and no secrets.
- **Secrets never in config.** Credentials, keys, and tokens reach the process only through the environment at the trust boundary, never through config files.
- **PII dropped at the sensor.** Passwords and payloads are dropped at capture time, never stored. The operator's own destination addresses stay on the box and never reach a feed, vendor report, or the console.
- **Tamper-evident evidence.** The event ledger is append-only and hash-chained, so the record of what was seen and why an IP was scored cannot be silently altered.

## Report model

An IP moves through three levels:

- **Eligible.** Reportable at all only after at least one confirmed-real event, plus variety of at least 2 events across at least 2 distinct signal categories.
- **Weight.** The decayed accumulated signal score, capped at 100, multiplied up by cross-WAN breadth.
- **Recommended.** An eligible IP whose weight crosses a threshold is actively surfaced and queued for operator approval.

Breadth acts on weight and recommendation only. It can never cross the eligibility floor.

## Status

In design. The build is foundation-first: sub-project 1 is the core spine (domain, PostgreSQL, scoring, breadth model), followed by 2 sensors, 3 intake and aggregation, 4 review, gatekeeper, and reporting, 5 feed, 6 console and observability, 7 runtime, coordination, and deployment, and 8 the remaining sensors. The core-spine specification is the first written spec.

Source-available; software license to be decided.

## Documentation

- Architecture overview: [docs/architecture/overview.md](docs/architecture/overview.md)
- Architecture decision records: [docs/architecture/adr/](docs/architecture/adr/)
- Design specs: [docs/design/](docs/design/)
- Security posture: [docs/security/posture.md](docs/security/posture.md)
- Roadmap: [docs/roadmap.md](docs/roadmap.md)
