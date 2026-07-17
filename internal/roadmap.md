# Propolis-new Build Roadmap

Propolis-new is a clean-room Rust rebuild of a single-operator defensive honeypot and threat-intelligence platform. The datastore is PostgreSQL as the single canonical store, and the architecture is event-sourced: evidence is an append-only, hash-chained event ledger, and each IP's score and reporting decision are reproducible by replaying that IP's events.

This document defines how the system is built. It does not restate the full system design; it defines the sequencing, the unit of work, and the scope of each sub-project.

## Foundation-first sequencing

The build is foundation-first. Each layer is built complete before the next begins. A layer is not "in progress" across three sub-projects at once; the core spine is finished, verified, and stable before the sensor framework is written on top of it, and so on up the stack. The rationale is that every layer above rests on the invariants of the layer below, and a shifting foundation forces rework in everything built on it. Building each layer to completion first means the layer's contracts are settled before anything depends on them.

Each sub-project is a self-contained unit of work with its own three-stage cycle:

1. **Spec** - the design is settled and written down before any code. The spec names the scope, the invariants the layer must hold, the data shapes and interfaces it owns, and the decisions it closes. Specs live in `docs/superpowers/specs/`.
2. **Plan** - the spec is decomposed into an ordered, verifiable implementation plan.
3. **Build** - the plan is executed in small, independently verified increments.

A sub-project is done only when its whole loop is wired end to end and verified, not when the happy path compiles. The next sub-project's spec begins only after the prior sub-project's build is complete.

Several invariants are established at the foundation and are load-bearing for every layer above. They are stated here so each later spec inherits them rather than relitigating them:

- **Human-approval gate.** Nothing is reported to a vendor or published to the feed without explicit operator approval. The intake and scoring layers only ever surface and queue; they never auto-report or auto-publish.
- **Three-level report model.** ELIGIBLE gates on evidence quality: an IP may be reported at all only after at least one confirmed-real event (a completed TCP handshake or authenticated honeypot event) plus variety of at least two events across at least two distinct signal categories. WEIGHT is the decayed accumulated signal score, capped at 100, multiplied up by breadth. RECOMMENDED means an eligible IP whose weight crosses a threshold is actively surfaced and queued for operator approval.
- **Breadth invariant.** Multi-WAN and cross-sensor breadth raises weight and raises the recommendation, but breadth can never make an ineligible IP eligible. Only a confirmed-real event moves an IP across the eligibility floor. This is the anti-spoof guarantee: spoofable UDP or lone-SYN traffic across many WAN IPs must never manufacture a report, because a report of such traffic gets vendor reporter accounts penalized, whereas a completed TCP handshake proves the source IP is real.
- **Passive, isolated sensors.** Sensors are passive only, with no active response and no hack-back. They are unprivileged, hold no database handle and no secrets, and drop passwords and payloads at capture time.
- **Event-sourced evidence.** The event ledger is append-only and hash-chained, so it is tamper-evident and every decision is replayable from its events.

## Sub-projects

Eight sub-projects, built in order. Only sub-project 1 has a full written spec so far; sub-projects 2 through 8 are scope stubs that receive their own spec at the start of their own cycle.

| # | Sub-project | Scope | Status |
|---|---|---|---|
| 1 | Core spine | Domain model, PostgreSQL schema and event ledger, scoring and decay, the eligibility/weight/recommendation model, and the multi-WAN breadth model. The foundation every later layer imports and depends on. | In design, spec written |
| 2 | Native sensor framework + catch-all + one TCP-auth sensor | The framework for self-authored, safe-by-construction passive sensors, plus the catch-all listener and one honeypot that produces authenticated TCP-handshake events (the confirmed-real signal the eligibility floor requires). | Design pending |
| 3 | Event intake + multi-node aggregation | Ingest of sensor output into the event ledger with per-hit WAN attribution, and aggregation of all WAN-IP collectors into one shared attacker score so cross-sensor and cross-WAN breadth counts. | Design pending |
| 4 | Review queue + gatekeeper + reporting | The operator review queue, the per-vendor submission gatekeeper, and the vendor reporting path. The mandatory human-approval gate lives here. | Design pending |
| 5 | Feed builder + exporters + publisher | Build of the tiered public blocklist from approved IPs, the export formats, and out-of-band publication, with fail-closed validation before publish. | Design pending |
| 6 | Web console + observability | The loopback operator console for review and inspection, plus logging, metrics, and health. | Design pending |
| 7 | Runtime composition + multi-node coordination + deployment | The composition root that wires the process, coordination across nodes in a cluster deployment, and the deployment and hardening artifacts. | Design pending |
| 8 | Remaining native sensors | The remaining self-authored sensors: Redis, ADB, malware-capture, and credential. | Design pending |

Sub-project 1, the core spine, is the only sub-project with a full spec. Sub-projects 2 through 8 are scope stubs: the one-to-two-sentence scope above fixes their boundary, but each earns its full spec, plan, and build when its cycle begins, on the current goals' merits.
