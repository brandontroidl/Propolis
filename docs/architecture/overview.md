# Propolis Architecture Overview

Status: design spec for the clean-room Rust rebuild. This document describes the system-level
design. It does not describe the old Python system, which serves only as a behavioral reference.
Component-level decisions and their rationale live in the ADRs under `docs/architecture/adr/`.

## Purpose and intended boundaries

Propolis is a single-operator defensive honeypot and threat-intelligence platform. It runs
self-authored passive sensors that capture unsolicited attack traffic, attributes each observation
to a source IP, scores that IP from time-decayed corroborated signal, and, only after an operator
explicitly approves each case, files abuse reports with reputation vendors and publishes a public
blocklist feed.

The platform solves one problem: turning noisy, attacker-controlled sensor telemetry into
high-confidence, corroborated, human-ratified abuse intelligence, without ever auto-reporting a
spoofable or single-sourced observation, and without leaking secrets, captured passwords, or the
operator's own infrastructure addresses.

In scope:

- Native, self-authored sensors only. No third-party honeypots, so the deployment carries one
  software license and no dependency on upstream projects that break or are abandoned.
- Passive capture only. Sensors never respond to, engage, or attack a source. There is no hack-back.
- A single canonical PostgreSQL datastore, event-sourced, shared by every collector.
- A mandatory human-approval gate on every outbound report and every feed publication.
- Multi-WAN attribution: for every hit the platform records which of the operator's WAN IPs it
  arrived on, and cross-WAN breadth raises an attacker's weight.

Out of scope by design:

- Real-time blocking. The approval gate makes the feed non-real-time. The cost of a false vendor
  report, a reputation penalty against the operator's reporter accounts, is judged worse than latency.
- Active defense of any kind.
- A general system of record. Propolis is authoritative for its own evidence ledger and nothing else.

## End-to-end pipeline

The pipeline is a single forward flow from capture to a human decision, after which two independent
downstream branches may fire. The branches share no state beyond the derived per-IP score they both
read.

```
native sensors (passive capture)
  -> append to the event ledger (append-only, hash-chained)
  -> derived per-IP score + breadth (projection, decayed to now)
  -> eligibility gate (confirmed-real event required) + recommendation gate (weight threshold)
  -> human review queue (operator approves / rejects / snoozes)
  -> [branch A] vendor abuse report      (per-vendor submission gate, on approval)
  -> [branch B] public blocklist feed     (scheduled rebuild from approved IPs)
```

Stage responsibilities:

- Sensors capture attack traffic and emit structured observations. They are unprivileged, hold no
  database handle and no secrets, and drop captured passwords and payloads at capture time.
- Intake attributes each observation to a source IP, classifies its signal category, stamps a
  timezone-aware UTC observation time, and appends it to the ledger. Malformed, non-attributable, or
  non-qualifying input is dropped at this boundary and never scored.
- The scoring projection derives each IP's current weight, breadth, and corroboration facts from its
  ledger events.
- The eligibility and recommendation gates decide whether an IP may be reported at all and whether it
  is actively surfaced to the operator.
- The review queue holds one open item per IP. Nothing advances to a downstream branch without an
  explicit operator decision.
- Branch A submits an approved case to reputation vendors, subject to a per-vendor submission gate
  (cooldown, rate limit, and per-vendor policy).
- Branch B rebuilds the tiered public blocklist from currently approved IPs on a schedule, validates
  it fail-closed, and optionally publishes it.

Both branches read the derived score; neither writes the other's state. An approved IP that has since
decayed below the gates silently drops out of the feed on the next rebuild rather than being actively
removed.

## The event-sourced core

The ledger is the evidence of record. Every captured observation is appended as an immutable event.
The ledger is append-only and hash-chained: each event carries a hash over its own content and the
prior event's hash, so any insertion, deletion, or edit of a past event breaks the chain and is
detectable. This makes the evidence tamper-evident and makes each IP's score and each reporting
decision reproducible by replaying that IP's events.

Per-IP score is a derived projection, not a source of truth:

- The projection (`ip_score`) holds each IP's accumulated weight, per-category breakdown, breadth
  counts, and corroboration facts.
- Weight decays continuously. The projection is decayed to the current time on read, so a stored row
  is never rewritten purely to reflect elapsed time.
- The projection is rebuildable at any time by replaying the ledger. If the projection is lost or
  suspected inconsistent, it is reconstructed from the append-only events, which remain authoritative.

Decay direction and half-life are scoring parameters. A half-life on the order of hours is
recommended and tunable; the exact value is fixed in the scoring configuration and is the primary
scoring knob. The corroboration and eligibility predicates below are not operator-tunable: they are
fixed in code so the reporting floor cannot be weakened from configuration.

## Multi-node breadth aggregation

Breadth is the reason the datastore is shared. An attacker seen across several of the operator's WAN
IPs and across several sensors is more likely to be a real, broadly-scanning adversary than one seen
on a single address, and that breadth must be reflected in a single score rather than fragmented
across per-node stores.

Model:

- Breadth is the distinct count of WAN IPs and the distinct count of sensors an attacker touches.
- N WAN-IP collectors append their events to one shared PostgreSQL store. Every collector's signal
  lands in one attacker score, so cross-WAN and cross-sensor breadth accumulates into a single weight.
- Collectors append to the shared ledger without contending on a shared score row. Ingest is an
  append to the event ledger; the derived projection is advanced separately, so concurrent collectors
  do not serialize on one hot row.
- Projection advancement is single-writer per deployment. In cluster mode one leader-elected scorer
  advances the projection from the shared ledger. On a single node that same node advances the
  projection directly, with no election.

The destination WAN IP each hit arrived on is recorded for operator-facing attribution and breadth
scoring. It is never placed on the external feed or in a vendor report. Breadth counts, not the
operator's own addresses, are what cross the trust boundary outward.

## The three-level report model

Reporting eligibility is separated into three distinct levels. They are evaluated in order, and the
first is a hard floor the others cannot bypass.

1. ELIGIBLE. An IP may be reported at all only after at least one confirmed-real event, plus variety.
   A confirmed-real event is a completed TCP handshake or an authenticated honeypot event, which
   proves the source IP is not spoofed. Variety requires at least 2 events across at least 2 distinct
   signal categories. An IP with no confirmed-real event is never eligible, regardless of how much
   other signal it accumulates.

2. WEIGHT. The decayed, accumulated signal score, capped at 100, then multiplied up by breadth. Weight
   measures how much corroborated signal an eligible IP carries and how broadly it was observed.

3. RECOMMENDED. An eligible IP whose weight crosses a threshold is actively surfaced and queued for
   operator approval. The recommendation threshold is a configured value; a starting threshold is
   recommended and tunable.

Invariant: breadth raises weight and raises the recommendation, but breadth can never make an
ineligible IP eligible. Only a confirmed-real event moves an IP across the eligibility floor. This is
the anti-spoof guarantee. Reports built on spoofable UDP or lone-SYN traffic get a vendor reporter
account penalized; requiring a completed TCP handshake before eligibility ensures every reported
source IP is real. Widening the observed breadth of an unproven IP must not manufacture a report.

The human-approval gate sits after RECOMMENDED and is mandatory. A recommended IP is surfaced to the
operator; nothing is reported to a vendor or published to the feed without explicit operator approval.

## Deployment modes

Single-node. One host binds one or more WAN IPs, runs the sensors, and runs the intake, scoring,
review, and downstream services against a local or co-located PostgreSQL instance. The node advances
the projection directly.

Cluster. Several collector nodes, each bound to one or more WAN IPs, append to one shared PostgreSQL
store. The purpose of the cluster is signal aggregation: every WAN-IP collector feeds the one shared
score so breadth counts across the whole deployment. One leader-elected scorer advances the projection.

Choosing PostgreSQL as a shared, concurrent, transactional store is what makes aggregation possible;
a file-local single-writer store cannot be the shared brain that every collector aggregates into.
Replication and failover high availability are a secondary benefit of running PostgreSQL, not the
goal of the cluster. The cluster exists for breadth first; resilience follows from the datastore
choice.

## Build sequencing

The system is built foundation-first, each layer complete before the next:

1. Core spine: domain model, PostgreSQL schema, event ledger, scoring projection, and breadth model.
2. Native sensor framework, the catch-all sensor, and one TCP-auth sensor.
3. Event intake and multi-node aggregation.
4. Review queue, submission gatekeeper, and vendor reporting.
5. Public blocklist feed.
6. Operator console and observability.
7. Runtime, multi-node coordination, and deployment.
8. Remaining native sensors.

## Architecture decision records

Component-level decisions, their rationale, and rejected alternatives are recorded as ADRs under
`docs/architecture/adr/`. This overview states the system-level shape; the ADRs are authoritative for
per-component choices.
