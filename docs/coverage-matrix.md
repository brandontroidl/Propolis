<!--
title: Documentation coverage matrix
audience: maintainer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Documentation coverage matrix

Maps every major component, pipeline stage, security invariant, and operational
procedure to the canonical doc page(s) that document it, with a coverage verdict.
Built by reading the corpus against the extracted source evidence.

**Verdict vocabulary.** `documented` — a canonical page covers the item and owns or
correctly links its facts. `partial` — covered, but with a stated caveat: an
`[inferred]`/`[not-evidenced]` claim, a residual risk the corpus flags as
unmitigated, or a facet not fully traced to source. `gap` — no canonical page
covers it. A `partial` here is a documentation-honesty marker, not a defect in the
docs; several rows are `partial` precisely *because* the corpus documents a residual
risk plainly (per the GLOBAL CORRECTIONS) rather than papering over it.

Result: **no coverage gaps.** Every component, stage, invariant, and procedure has a
canonical owner. The `partial` rows carry a documented caveat, noted in the last
column.

## Component crates (18 crates / 15 binaries)

Inventory and dependency graph owned by
[architecture/components.md](architecture/components.md). Per-crate behavior lives in
the architecture and reference pages below.

| Crate | Primary doc page(s) | Coverage | Note |
|---|---|---|---|
| `sensor-wire` | [components.md](architecture/components.md), [reference/events-and-signals.md](reference/events-and-signals.md) | documented | Frozen NDJSON wire format (`WIRE_VERSION=1`); event fields owned by events-and-signals. |
| `core-scoring` | [pipeline.md](architecture/pipeline.md), [storage.md](architecture/storage.md), [reference/scoring-and-feed.md](reference/scoring-and-feed.md), [reference/database.md](reference/database.md) | documented | Ledger, chain-hash, scoring engine, gates; constants owned by scoring-and-feed. |
| `geoip` | [reference/integrations.md](reference/integrations.md), [architecture/pipeline.md](architecture/pipeline.md) | documented | Offline GeoLite2 City+ASN; local file reads, egress-free (GLOBAL CORRECTION 1). |
| `sensor-framework` | [architecture/sensors.md](architecture/sensors.md), [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | Shared harness: listener lifecycle, sanitize, emit, spool, hand-off, fake shell/fs, persona, bounds. |
| `sensor-catchall` | [architecture/sensors.md](architecture/sensors.md), [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | Passive catch-all; `catchall_probe`. Uses unprefixed `CATCHALL_*` env vars (env-vars ref). |
| `sensor-ssh` | [reference/sensor-behavior.md](reference/sensor-behavior.md), [architecture/sensors.md](architecture/sensors.md) | documented | Full handshake, fake shell, SCP/SFTP capture; password-drop invariant in privacy page. |
| `sensor-telnet` | [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | Option negotiation, accepts any credential, shared fake shell. |
| `sensor-redis` | [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | RESP parse, canned replies, cred/command capture. |
| `sensor-adb` | [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | `CNXN` handshake, `shell:` via fake shell, `sync:` push capture. |
| `sensor-http` | [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | Per-connection HTTP honeypot handler. |
| `sensor-ftp` | [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | Capture hand-off + quarantine spool for uploads; PASV data-peer validation. |
| `sensor-smtp` | [reference/sensor-behavior.md](reference/sensor-behavior.md) | documented | Per-connection SMTP honeypot handler. |
| `sensor-cred` | [reference/sensor-behavior.md](reference/sensor-behavior.md), [reference/ports-and-protocols.md](reference/ports-and-protocols.md) | documented | One binary, 5 protocols (VNC/MySQL/MSSQL/PostgreSQL/MongoDB) = the "9 crates / 12 protocols" count. |
| `intake` | [event-and-sample-lifecycle.md](architecture/event-and-sample-lifecycle.md), [architecture/pipeline.md](architecture/pipeline.md) | partial | Tailer + wire→domain conversion documented; intake's own INSERT path not traced line-by-line in evidence (no-`format!`-SQL grep covers it). |
| `review` | [architecture/pipeline.md](architecture/pipeline.md), [reference/integrations.md](reference/integrations.md), [security/malware-custody.md](security/malware-custody.md) | documented | Review queue, gatekeeper, vendor adapters, VT scanner, fetcher, operator CLI. |
| `feed` | [architecture/pipeline.md](architecture/pipeline.md), [reference/scoring-and-feed.md](reference/scoring-and-feed.md) | documented | Snapshot→export→atomic publish; 10 formats per tier/window; checksummed manifest. |
| `console` | [architecture/console.md](architecture/console.md), [reference/console-routes.md](reference/console-routes.md), [security/authn-authz.md](security/authn-authz.md) | documented | axum operator console; 30 routes (7 public, 23 session-gated); no global CSP (GLOBAL CORRECTION 6). |
| `propolis` | [process-topology.md](architecture/process-topology.md), [concurrency-and-failure.md](architecture/concurrency-and-failure.md) | documented | Unified daemon: intake+review+feed+console+VT+fetcher+ops-monitor as supervised tokio tasks on one PgPool. |

The 4 retired dev units (`intake`/`review`/`feed`/`console.service`) are documented as
superseded by `propolis.service` in
[operations/deployment-models.md](operations/deployment-models.md); their full
hardening blocks are not transcribed (not the production surface) — a deliberate
scope choice, not a gap.

## Pipeline stages and data flows

Narrative owned by [architecture/pipeline.md](architecture/pipeline.md) and
[architecture/event-and-sample-lifecycle.md](architecture/event-and-sample-lifecycle.md);
exact constants by [reference/scoring-and-feed.md](reference/scoring-and-feed.md).

| Stage / flow | Doc page(s) | Coverage | Note |
|---|---|---|---|
| Capture → sanitize → emit (event flow) | [event-and-sample-lifecycle.md](architecture/event-and-sample-lifecycle.md), [architecture/sensors.md](architecture/sensors.md) | documented | Reply-blocking path; one NDJSON line per event, `O_APPEND`. |
| Sample hand-off → quarantine spool (sample flow) | [event-and-sample-lifecycle.md](architecture/event-and-sample-lifecycle.md), [security/malware-custody.md](security/malware-custody.md), [operations/queue-and-spool.md](operations/queue-and-spool.md) | documented | Off-response-path mpsc; single worker; SHA-256 naming; per-file cap + global budget. |
| Intake tail → ledger append (hash chain) | [event-and-sample-lifecycle.md](architecture/event-and-sample-lifecycle.md), [architecture/storage.md](architecture/storage.md) | documented | SHA-256 chain over frozen canonical encoding; advisory-lock serialized. |
| Scoring: decay + accumulate + gates | [architecture/pipeline.md](architecture/pipeline.md), [reference/scoring-and-feed.md](reference/scoring-and-feed.md) | documented | 6h half-life, dedup window, breadth multiplier, persistence bonus, tier, eligibility. |
| Review queue populate / operator decision | [architecture/pipeline.md](architecture/pipeline.md), [operations/routine-procedures.md](operations/routine-procedures.md), [reference/database.md](reference/database.md) | documented | Populate/withdraw, approve/reject/snooze; human gate before any publication. |
| Enrichment: VirusTotal scan | [reference/integrations.md](reference/integrations.md), [security/outbound-controls.md](security/outbound-controls.md) | documented | Opt-in; per-UTC-day budget; scans spool dirs; gated by key. |
| Enrichment: malware fetcher (attacker URL) | [security/malware-custody.md](security/malware-custody.md), [reference/rate-limits-and-budgets.md](reference/rate-limits-and-budgets.md) | documented | Opt-in; SSRF-vetted every hop; per-host + daily budgets; recursion-capped. |
| Enrichment: GeoLite2 / ASN | [reference/integrations.md](reference/integrations.md) | documented | Local file reads only; ASN suppression opt-in. |
| Feed build → export → atomic publish | [architecture/pipeline.md](architecture/pipeline.md), [reference/scoring-and-feed.md](reference/scoring-and-feed.md), [operations/queue-and-spool.md](operations/queue-and-spool.md) | documented | Retention-window membership; 10 formats; staging + two-rename swap; checksum self-check. |
| Feed → public repo sync (cron) | [operations/deployment-models.md](operations/deployment-models.md), [reference/commands.md](reference/commands.md) | partial | `deploy/blocklist-sync.sh` is an operator setup step (GLOBAL CORRECTION 4); NOT wired into any shipped systemd timer/cron — documented as such. |
| Vendor submission (AbuseIPDB/DShield/OTX) | [reference/integrations.md](reference/integrations.md), [security/outbound-controls.md](security/outbound-controls.md) | partial | AbuseIPDB/OTX wire contracts verified live; DShield attribution flagged provisional/unverified — documented with caveat. |
| Cluster / multi-node aggregation | [operations/deployment-models.md](operations/deployment-models.md), [operations/capacity-planning.md](operations/capacity-planning.md) | partial | Shared-DB multi-node is an INSTALL.md claim `[inferred]`; no cluster-coordination code verified — documented as inferred. |

## Security invariants

The 12 invariants from the security-invariants evidence, each with its canonical
narrative owner. Reference values (ports, routes, constants) are owned by the
`reference/` pages the security pages link to.

| Invariant | Doc page(s) | Coverage | Note |
|---|---|---|---|
| 1. Never-execute (no spawn/exec) | [security/never-execute.md](security/never-execute.md) | documented | Whole-workspace grep clean; 8 per-sensor static-check tests; W^X at deploy. The one flagged item (`sensor-catchall` lacks a `never_exec_static_check` regression test) is documented in never-execute.md. |
| 2. Sensors egress-free by construction | [security/outbound-controls.md](security/outbound-controls.md), [security/supply-chain.md](security/supply-chain.md) | documented | Scoped to sensor crates (GLOBAL CORRECTION 1); the workspace is NOT egress-free — stated plainly. |
| 3. Five gated outbound paths (all default OFF) | [security/outbound-controls.md](security/outbound-controls.md), [reference/environment-variables.md](reference/environment-variables.md) | documented | VT, vendor submitters, console rDNS, GeoLite2 (local, not network), ops-alert ntfy; each opt-in, several fail-closed. |
| 4. Fetcher SSRF guard | [security/malware-custody.md](security/malware-custody.md), [security/input-handling.md](security/input-handling.md) | documented | Scheme allowlist, userinfo reject, DNS-rebinding defense, address pinning, forbidden-target check, tftp port lock. |
| 5. `sanitize_value` at event boundaries | [security/input-handling.md](security/input-handling.md) | documented | Order-of-operations chokepoint; applied in 18 src files; structurally enforced for captures. |
| 6. Event hash chain (tamper-evidence) | [architecture/storage.md](architecture/storage.md), [security/input-handling.md](security/input-handling.md) | documented | Frozen canonical encoding, golden vector, advisory-lock serialization. |
| 7. Malware custody (sterile spool, human-gated) | [security/malware-custody.md](security/malware-custody.md) | documented | Store→hash→verify→human-approve→report; never executed; SHA-256 naming; `0640`, noexec mount. |
| 8. Credential / password privacy | [security/sample-and-credential-privacy.md](security/sample-and-credential-privacy.md) | documented | Password read only to advance the parser, then dropped; never in any event field; no wire field. |
| 9. WAN attribution internal-only | [security/sample-and-credential-privacy.md](security/sample-and-credential-privacy.md), [security/threat-model.md](security/threat-model.md) | documented | `wan_ip` on internal/auth-gated views only; ZERO references in the public feed or vendor reports. |
| 10. DB writes parameterized (no SQLi) | [security/input-handling.md](security/input-handling.md), [security/filesystem-and-db-protections.md](security/filesystem-and-db-protections.md) | documented | No `format!`-built SQL in non-test src; bound params throughout. |
| 11. Session / CSRF auth boundary | [security/authn-authz.md](security/authn-authz.md), [reference/console-routes.md](reference/console-routes.md) | documented | Argon2id password, HMAC session cookie, constant-time CSRF, rate limiter, fail-closed on missing password. |
| 12. Filesystem / permission protections | [security/filesystem-and-db-protections.md](security/filesystem-and-db-protections.md), [security/hardening-checklist.md](security/hardening-checklist.md), [operations/installation.md](operations/installation.md) | partial | systemd least-authority + install.sh perms documented and test-asserted. Two residual risks flagged plainly: `SystemCallFilter` is a PLACEHOLDER, not a shipped hardened filter (GLOBAL CORRECTION 2); the `noexec,nosuid,nodev` spool mounts are operator-provisioned, unverifiable from source. |

Residual-risk cross-cut for invariants 2 and 12 is consolidated in
[security/residual-risks.md](security/residual-risks.md). No in-process TLS
(GLOBAL CORRECTION 3) is owned by
[operations/networking-tls.md](operations/networking-tls.md) and cross-referenced
from residual-risks and authn-authz.

## Operational procedures

Owned by the `operations/` section, with symptom-based recovery in `troubleshooting/`.

| Procedure | Doc page(s) | Coverage | Note |
|---|---|---|---|
| Install (users, dirs, spool, units) | [operations/installation.md](operations/installation.md), [reference/commands.md](reference/commands.md) | documented | `install.sh` is idempotent, dry-run capable; does NOT start services, touch the DB, or write `.env`. |
| Deployment models (single-node / cluster / dev units) | [operations/deployment-models.md](operations/deployment-models.md) | partial | Single-node fully documented; multi-node aggregation `[inferred]` (see pipeline table). |
| Configuration (env vars, defaults, bounds) | [operations/configuration.md](operations/configuration.md), [reference/environment-variables.md](reference/environment-variables.md) | documented | Every `PROPOLIS_*` var, default, bound, and fail behavior owned by the env-vars reference. |
| Secret management | [operations/secret-management.md](operations/secret-management.md) | documented | Per-service `/etc/propolis/*.env`, mode `0600`, operator-created; no secret from argv. |
| Networking / TLS | [operations/networking-tls.md](operations/networking-tls.md) | partial | Loopback-default console; TLS is an `[inferred]` reverse-proxy concern, no in-process TLS (GLOBAL CORRECTION 3). |
| Service lifecycle (start/stop/status/upgrade) | [operations/service-lifecycle.md](operations/service-lifecycle.md), [reference/commands.md](reference/commands.md) | documented | `systemctl enable --now`; graceful 30s shutdown; `upgrade.sh` in-place; migrations at startup. |
| Health / readiness / metrics / alerts | [operations/health-and-observability.md](operations/health-and-observability.md), [reference/console-routes.md](reference/console-routes.md) | documented | `/health`, `/ready` (503 fail-closed), `/metrics` Prometheus, `/logs` ring; opt-in ntfy ops-alerting. |
| Capacity planning | [operations/capacity-planning.md](operations/capacity-planning.md) | documented | Resource caps per unit; PgPool sizing; single-daemon footprint. |
| Queue & spool management | [operations/queue-and-spool.md](operations/queue-and-spool.md) | documented | Review queue, quarantine spool, fetcher spool, budgets, drop behavior. |
| Retention & logrotate | [operations/retention.md](operations/retention.md) | documented | Feed retention windows; `logrotate-sensors.conf` (`size 100M`, `copytruncate`, size-based DoS bound). |
| Backup & restore | [operations/backup-and-restore.md](operations/backup-and-restore.md), [troubleshooting/backup-and-recovery.md](troubleshooting/backup-and-recovery.md) | documented | DB is the tamper-evident system of record; recovery procedure documented. |
| Upgrade / rollback / DR | [operations/upgrade-rollback-and-dr.md](operations/upgrade-rollback-and-dr.md) | documented | In-place upgrade order (sensors then daemon); rollback and DR guidance. |
| Routine day-to-day procedures | [operations/routine-procedures.md](operations/routine-procedures.md) | documented | Reviewing the queue, publication gate, sample triage. |
| Feed publish → public repo | [operations/deployment-models.md](operations/deployment-models.md), [reference/commands.md](reference/commands.md) | partial | `blocklist-sync.sh` is an operator cron step, not a shipped timer (GLOBAL CORRECTION 4). |
| Host-compromise monitoring (Guardian) | [operations/health-and-observability.md](operations/health-and-observability.md), [security/residual-risks.md](security/residual-risks.md) | partial | Referenced as a separate external monitor distinct from the in-process ops-alerter; not part of this workspace, so documented by reference only. |

## Corpus-control pages (self-coverage)

| Item | Doc page | Coverage |
|---|---|---|
| Current/historical/superseded policy | [documentation-policy.md](documentation-policy.md) | documented |
| Claim → source traceability | [claim-to-source-ledger.md](claim-to-source-ledger.md) | partial | Canonical path reserved; page assembled alongside this one (verify present before relying on the link). |
| Complete linear reading experience | [binder/HANDOFF-BINDER.md](binder/HANDOFF-BINDER.md) | partial | Canonical path reserved; binder assembled alongside this one (verify present before relying on the link). |
</content>
</invoke>
