<!--
title: Researcher manual
audience: researcher
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Researcher manual

A guided path for someone using Propolis as a **data source**: what it produces,
how the data is structured, how each source is scored, the boundaries on using it,
and why the record is reproducible. Exact fields, weights, and constants live in
the reference pages this links; this manual explains what they mean for analysis.

Propolis is defensive tooling for infrastructure you own or are authorized to
monitor. Read [ethical use](#ethical-use-boundaries) before collecting or
publishing anything derived from captured data.

## What Propolis produces

From attacker traffic against decoy services on your own WAN addresses, three
kinds of artifact:

1. **Events** - an append-only, hash-chained ledger of every observation
   (connection, login attempt, command, upload, download). This is the system of
   record.
2. **Samples** - captured file bodies (attacker uploads over SSH/SCP/SFTP, FTP
   `STOR`, ADB push, and payloads the malware fetcher retrieved), held in a
   sterile on-disk quarantine spool and referenced from the database by SHA-256.
3. **Scores** - a per-IP projection derived from the events: a time-decayed
   score, a confirmed-real latch, feed tier, and recommendation flags.

The capture surface is nine sensor crates over twelve protocols; the full
inventory is [`overview/capabilities`](../overview/capabilities.md), and per-
protocol capture behavior is
[`reference/sensor-behavior`](../reference/sensor-behavior.md).

## The data model

### Events and the wire format

A sensor emits raw facts only, as a frozen NDJSON `SensorEvent` (one line per
event, `WIRE_VERSION = 1`). It carries `source_ip`, `wan_ip`, `sensor`,
`signal_type`, `protocol`, `authenticated`, `observed_at`, free-form `metadata`,
an optional `sample` reference, and an optional `session_id`. A sensor never
computes `weight`, `confidence`, or `category` - those are derived
downstream by intake from a single-source-of-truth table. The exact field list,
the sample side-channel, and the signal taxonomy are owned by
[`reference/events-and-signals`](../reference/events-and-signals.md).

`session_id` correlates one sensor session's events (one SSH connection's logins,
execs, and transfers) and is deliberately **not** part of the hash chain, so it
can be used for correlation without disturbing the ledger's integrity.

### Signal taxonomy

There are 16 signal types across categories `honeypot`, `ids`, `network`, `waf`,
and `auth`. A sensor can emit only the honeypot subset plus `catchall_probe`; the
rest originate from other layers. Each type maps to a fixed `weight`,
`confidence`, and `category` in the weight table (the single source of truth):
honeypot signals carry the highest weight and confidence (e.g.
`honeypot_malware_upload` = 80 / 0.980), a firewall-blocked connection the lowest
(3 / 0.150). The table and the per-signal meanings are owned by
[`reference/events-and-signals`](../reference/events-and-signals.md#signal-weight-table).

### Where events land

Events become rows in the append-only `event` ledger; the per-IP aggregate lives
in `ip_score`; captured-sample verdicts live in `sample_analysis`. The full
schema - tables, columns, enums, and the migration list - is owned by
[`reference/database`](../reference/database.md); the architectural model is
[`architecture/storage`](../architecture/storage.md), and the end-to-end flow from
connection to score is
[`architecture/event-and-sample-lifecycle`](../architecture/event-and-sample-lifecycle.md).

## Scoring methodology

A source IP's score is a **decaying, capped accumulation** of signal weights,
computed as a pure fold: decay prior state to the new event's timestamp, add the
event's weight (unless deduped within a 60 s window), recompute derived flags. The
raw score decays with a 6-hour half-life and is clamped at 100. On top of the base
accumulation, two integrity-minded adjustments matter for interpreting a score:

- **Cross-WAN breadth** multiplies the effective score by how many distinct WAN
  vantages saw the source - but only vantages that completed an **authenticated
  TCP** handshake count, and same-prefix vantages (/24 IPv4, /64 IPv6) dedup to
  one. A spoofed source cannot inflate breadth.
- **Persistence** adds a bonus for distinct active calendar days beyond a grace
  window, so a slow attacker that time-decay would otherwise erase can still earn
  a tier. It is applied to a gate-facing score only, never the stored raw, so it
  cannot double-count.

Every constant, tier threshold, and the exact formulas are owned by
[`reference/scoring-and-feed`](../reference/scoring-and-feed.md). How scoring,
review, and feed connect is [`architecture/pipeline`](../architecture/pipeline.md).

### The confirmed-real gate

This is the critical distinction for anyone treating the data as intelligence.
An IP earns a feed tier or a vendor report only after it latches
`has_confirmed_real`, which requires **an authenticated TCP honeypot event**
(`protocol == Tcp && authenticated && category == Honeypot`). UDP/ICMP,
unauthenticated, or non-honeypot traffic never latches it. Weight and confidence
alone do not set it. The latch is sticky until an explicit delist. Combined with
the eligibility rule (confirmed-real plus at least two recorded events), this
means a listed IP is corroborated by traffic a spoofed source could not produce.
An independent **volume path** can list a high-volume source on completed-TCP
event counts alone, but it never triggers vendor reporting and never applies to
spoofable UDP/ICMP floods. Details:
[`reference/scoring-and-feed`](../reference/scoring-and-feed.md#confirmed-real-gate).

## Samples and their verdicts

A sample is a captured file body, stored under the **sterile spool** custody
model: named by SHA-256 (never the attacker's filename, so path traversal is
structurally impossible), size-bounded per file and by a global byte budget,
written `0640`, and re-hashed on read (fail-closed on mismatch). The `sha256` is
the key into the `sample_analysis` verdict table. VirusTotal enrichment does a
**hash lookup** by default (sending only the hash); uploading an unknown sample
**body** off-box is opt-in and default off. Custody, integrity, and the disk-fill
controls are owned by [`security/malware-custody`](../security/malware-custody.md).

> **Captured samples are live, hostile code.** You are responsible for storing,
> handling, and disposing of them safely. Keep the spool on a
> `noexec,nosuid,nodev` mount, never browse it with a tool that auto-opens files,
> and never execute captured content. See
> [`security/malware-custody`](../security/malware-custody.md).

## Ethical-use boundaries

Owned by [`overview/ethical-use`](../overview/ethical-use.md). The boundaries that
govern research use:

- **Authorized infrastructure only.** Deploy only on addresses you own or are
  explicitly authorized to monitor. Sensors are passive: they observe traffic that
  reaches them and never probe or connect back to the sources they observe, so the
  intelligence comes from attackers choosing to engage your decoys.
- **Not for offensive use.** Repurposing captured data or credentials to act
  against third parties is outside both the intent and the license.
- **Outbound actions are operator-gated.** No IP is listed and no vendor abuse
  report is filed without explicit per-case operator approval; enabling any
  enrichment/reporting egress (VirusTotal, AbuseIPDB/DShield/OTX, ntfy, reverse
  DNS) is an operator decision with associated exposure. See
  [`security/outbound-controls`](../security/outbound-controls.md). When you file a
  report, ensure it is accurate and made in good faith.
- **Privacy invariants.** Submitted passwords are read only far enough to advance
  the protocol and then dropped - never stored, logged, or placed on any event.
  The honeypot's own WAN vantage address is internal-only and never appears in the
  public feed or a vendor report. See
  [`security/sample-and-credential-privacy`](../security/sample-and-credential-privacy.md).
- **License.** Source-available under PolyForm Noncommercial 1.0.0: personal use,
  home labs, research, teaching, and nonprofit/public-safety/government use are
  free; commercial use requires a separate license. See
  [`governance/licensing`](../governance/licensing.md) and
  [`LICENSE.md`](../../LICENSE.md).

## Reproducibility

The event ledger is built for a defensible, reproducible record:

- **Tamper-evident hash chain.** Every event carries a SHA-256 hash over a
  **frozen canonical byte encoding** of its content, chained to the prior event's
  hash. The encoding writes a fixed field order with length-prefixed framing (not
  whole-struct JSON, whose key order is fragile) and is pinned by a golden test
  vector. Any change to a hashed field, or any reorder or insertion, breaks the
  linkage from that event forward. This gives tamper-**evidence**, not
  confidentiality.
- **Database-layer enforcement.** A `BEFORE INSERT` trigger independently rejects
  any row whose `prev_hash` does not match the current chain head (fail-closed),
  and in the production database the application role is `REVOKE`d `UPDATE`,
  `DELETE`, `TRUNCATE` on the ledger - it can only append.
- **Serialized single-writer append** under one advisory lock guarantees the
  chain cannot fork under concurrent callers.
- **Replayable projection.** `ip_score` is a projection of the ledger and can be
  **rebuilt from the events** - which is why the console's delete-IP action purges
  the projection and review rows but deliberately never touches the `event`
  ledger. The scoring fold is deterministic given the ordered events.

Mechanism detail is owned by [`architecture/storage`](../architecture/storage.md)
(the hash chain, the enforcement, the projections) and
[`reference/database`](../reference/database.md) (the canonical encoding and
schema). A replay integration test exercises the rebuild path (see
[build and test](../development/build-and-test.md#test-taxonomy), core-scoring
`replay`).

## Where to go next

- Signal taxonomy and event fields:
  [`reference/events-and-signals`](../reference/events-and-signals.md).
- Scoring constants, tiers, and gates:
  [`reference/scoring-and-feed`](../reference/scoring-and-feed.md).
- The data model in the architecture:
  [`architecture/storage`](../architecture/storage.md),
  [`architecture/event-and-sample-lifecycle`](../architecture/event-and-sample-lifecycle.md).
- What Propolis is and is not: [`overview/index`](../overview/index.md).
