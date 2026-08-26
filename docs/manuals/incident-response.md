<!--
title: Incident-responder manual
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Incident-responder manual

A curated path for reading captured evidence off a Propolis node, proving it was not
altered, handling captured malware safely, reconstructing what (if anything) left the
box, and containing the node. It orders the canonical pages and links to them; each
linked page owns its facts.

Scope note: Propolis is a honeypot. Nothing an attacker sent was ever executed (see
[never-execute](../security/never-execute.md)), so an "incident" here is almost always
*evidence review and custody* of what was captured, not host compromise recovery. If you
suspect the host itself, treat the single-node blast radius as total (see
[residual risks](../security/residual-risks.md)) and contain first (below).

## 1. Contain first if the node is live and suspect

If you need the node to stop taking traffic before you investigate, stop the listeners
before the daemon so no new events arrive mid-teardown, and use `disable` (not just
`stop`) because sensors are `Restart=always`. The full procedure - graceful shutdown, the
30s shutdown timeout, and the preserve-vs-wipe decision - is owned by
[safe teardown](../getting-started/safe-teardown.md) and
[service lifecycle](../operations/service-lifecycle.md).

> **Preserve before you wipe.** Captured evidence cannot be recovered once wiped unless
> you took a verified backup first. Take and verify a backup
> ([backup and restore](../operations/backup-and-restore.md)) before touching anything you
> intend to keep.

## 2. Where the evidence lives

| Evidence | Location | Recoverable elsewhere? |
|---|---|---|
| Event ledger + per-IP score projection | PostgreSQL (`event`, `ip_score`, `review_queue`, `vendor_submission`, `fetch_attempt`, `sample_analysis`) | The ledger is canonical; `ip_score` rebuilds from it |
| Captured sample bodies (possible live malware) | On-disk quarantine spool under `/var/spool/propolis/<sensor>` and `/var/spool/propolis/fetched` | No - custody evidence, referenced from the DB only by SHA-256 |
| Sensor NDJSON logs | `/var/log/propolis/<sensor>/` (logrotate, size-based) | The DB is authoritative; logs are a rotated convenience copy |

Paths are owned by [filesystem paths](../reference/filesystem-paths.md); tables, columns,
and enums by [database reference](../reference/database.md); the storage model by
[storage](../architecture/storage.md).

## 3. Read the evidence in the console

The console is the intended reading surface (loopback bind by default; session-gated).
Routes are owned by [console routes](../reference/console-routes.md).

- **Per-IP detail** - `GET /ip/{ip}`: the score, category breakdown, distinct WAN
  vantages and sensors, and the evidence view. Drawer mode is `?drawer=1` with an
  `HX-Request` header; a missing IP returns 404.
- **Event history** - `GET /ip/{ip}/events`: the attacker's captured events for that IP,
  keyset-paginated.
- **Search** - `GET /search/events` and `/search/ips` to pivot across the corpus;
  `GET /ips` lists scored IPs (capped 500 rows).
- **Samples** - `GET /samples` lists captured samples; `GET /samples/download/{sha256}`
  streams the raw body as `application/octet-stream` with `Content-Disposition: attachment`
  and `Content-Security-Policy: default-src 'none'` (a hardened download - see custody below
  before you open anything).
- **Live logs** - `GET /logs` is a 1000-event in-memory ring, a convenience tail only; the
  journal and the NDJSON files are authoritative
  ([health and observability](../operations/health-and-observability.md)).

Every attacker-controlled string in these views has already passed the shared
`sanitize_value` chokepoint (CR/LF, ANSI, bidi, zero-width, length cap) before it entered
an event, so a forged log line cannot corrupt your terminal or the page. See
[input handling](../security/input-handling.md).

## 4. Prove the evidence was not altered

The `event` ledger is append-only and hash-chained: each event carries a SHA-256 over a
frozen length-prefixed canonical encoding, chained to the prior event's hash. Any change
to a hashed field, or any reordering or insertion, breaks the linkage from that event
forward.

Verify it before you rely on captured evidence in a report:

- **Console** - the `GET /integrity` page, `POST /integrity/verify` (a read-only chain
  verification; deliberately no CSRF because it mutates nothing).
- **In code** - `core_scoring::verify_chain`.

Database-layer backing (independent of the Rust check): a `BEFORE INSERT` trigger rejects
any insert whose `prev_hash` does not match the chain head, and the production application
role has `UPDATE/DELETE/TRUNCATE` on `event` revoked. The chain guarantees
**tamper-evidence**, not confidentiality and not protection against a DB superuser deleting
rows. Detail owned by [storage](../architecture/storage.md) and
[database reference](../reference/database.md). Note that any deletion (for example a manual
prune) breaks chain continuity from that point forward - expected, but record it so a later
verifier does not read the break as tampering.

## 5. Handle captured malware safely

Custody is **store -> hash -> verify -> human-approve -> report**, and a sample is **never
executed or opened** by Propolis at any point. Bodies are named by their SHA-256 (never the
attacker's filename, so path traversal is structurally impossible), written `0640`,
size-bounded per file and by a global byte budget, and re-hashed on read (fail-closed on
mismatch). The full custody model is owned by
[malware custody](../security/malware-custody.md).

> **Live malware at rest.** The spool holds real captured samples. Treat it as hostile
> content: keep it on a `noexec,nosuid,nodev` mount, never browse it with a tool that
> auto-opens or previews files, and move samples to an isolated analysis environment rather
> than opening them on the honeypot host. Whether the noexec mount is actually in force on a
> given box is not verifiable from source and is a residual risk
> ([residual risks](../security/residual-risks.md)).

The `sample_analysis` table records VirusTotal-style verdicts (detected/total engine hits)
keyed by SHA-256, when VirusTotal is enabled. The `fetch_attempt` table records each
attacker-supplied URL the fetcher considered, including the pinned IP actually dialed, the
status, and the guard's reject reason - useful for reconstructing what the box was asked to
retrieve.

## 6. Reconstruct what egress may have occurred

Sensors are egress-free by construction; only the platform's five opt-in paths can leave the
box, and all default off. To determine what actually left this node, check which were
enabled (their env vars, owned by
[environment variables](../reference/environment-variables.md)) and read the corresponding
records. Full behavior and guards are owned by
[outbound controls](../security/outbound-controls.md):

- **Vendor abuse submitters** (AbuseIPDB/DShield/OTX) - only ever send review-queue rows the
  operator **Approved**; each submission is one `vendor_submission` row with a unique
  idempotency key and the recorded vendor response. That table is the authoritative record of
  what IPs were reported outward.
- **VirusTotal** - sample-hash lookups (and, only if `PROPOLIS_VT_UPLOAD` was on, uploads of
  unknown samples). Verdicts land in `sample_analysis`.
- **Malware fetcher** - the one path that dials an attacker-supplied URL. `fetch_attempt` rows
  show each URL considered and whether the SSRF guard allowed or rejected it (and why).
- **Console reverse DNS** - one PTR query per address when enabled; display-only, never a
  suppression signal.
- **Ops-alert ntfy** - POSTs alert text (sanitized before send) to the operator's own ntfy
  server.

The public **feed** carries only attacker `source_ip` plus tier/first-seen/last-seen/
categories and **zero** `wan_ip` references by construction, so publishing it does not leak
the honeypot's vantage ([attack surfaces](../security/attack-surfaces.md)).

## 7. Teardown

When the investigation is done, preserve or deliberately wipe the three evidence stores per
[safe teardown](../getting-started/safe-teardown.md), and reverse `install.sh` manually if you
are fully decommissioning the box. Decide separately whether to leave or retract any published
blocklist feed - that is a change to the external repository, independent of tearing down the node.

## Related

- [Threat model](../security/threat-model.md) and the [security reviewer manual](./security.md)
- [Malware custody](../security/malware-custody.md) and [never-execute](../security/never-execute.md)
- [Outbound controls](../security/outbound-controls.md)
- [Backup and restore](../operations/backup-and-restore.md) and [safe teardown](../getting-started/safe-teardown.md)
