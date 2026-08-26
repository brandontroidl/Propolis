<!--
title: Handoff binder
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Propolis handoff binder

A single linear document that assembles the whole Propolis picture in reading
order: what it is, how it is built, how it is secured, deployed, operated, and
maintained, and where it came from. It is meant to be read top to bottom - for
offline reading, project transfer, audit, or ingestion by a downstream tool.

This binder is a **synthesis and index, not a second source of truth.** Every
section summarizes the canonical pages that own its facts and links to them for
full depth. Exact values (env vars, ports, paths, schema, scoring constants,
routes) are owned by the [`reference/`](../reference/environment-variables.md)
pages and are not restated here. Where this binder and a canonical page ever
disagree, the canonical page wins. See [How this binder is assembled](README.md).

## Contents

1. [Executive handoff](#1-executive-handoff)
2. [Project identity and scope](#2-project-identity-and-scope)
3. [Current implementation status](#3-current-implementation-status)
4. [System architecture](#4-system-architecture)
5. [Security and trust model](#5-security-and-trust-model)
6. [Deployment](#6-deployment)
7. [Configuration](#7-configuration)
8. [Operations](#8-operations)
9. [Data and evidence lifecycle](#9-data-and-evidence-lifecycle)
10. [Incident response](#10-incident-response)
11. [Development and testing](#11-development-and-testing)
12. [Maintenance and releases](#12-maintenance-and-releases)
13. [Troubleshooting](#13-troubleshooting)
14. [Governance and roadmap](#14-governance-and-roadmap)
15. [Known limitations and technical debt](#15-known-limitations-and-technical-debt)
16. [Reference appendices](#16-reference-appendices)
17. [Historical provenance and archive map](#17-historical-provenance-and-archive-map)

---

## 1. Executive handoff

Propolis is a **self-hosted, single-node honeypot and threat-intelligence
platform**. It runs native protocol sensors that impersonate common services,
records what attackers do against WAN addresses you own, scores each source by
corroborated evidence, and - only after an operator approves each case -
publishes a firewall blocklist and files vendor abuse reports. It is defensive
tooling for infrastructure you own or are authorized to monitor
([overview](../overview/index.md), [ethical use](../overview/ethical-use.md)).

The essentials a new owner needs on day one:

- **What runs:** one unified `propolis` daemon (intake + review + feed + console
  + VirusTotal + malware fetcher + ops-monitor, as supervised tokio tasks over
  one PostgreSQL pool) plus nine attacker-facing sensor processes, each its own
  systemd service and OS user. See [§4](#4-system-architecture).
- **State of the code:** source-available and actively developed. Crate version
  is `0.3.0` across all 18 crates, but the **only release tag is `v0.1.0`**; the
  current tree is untagged. Not certified or production-blessed. See
  [§3](#3-current-implementation-status).
- **The safety posture in one line:** *sensors are egress-free by construction;
  the platform's five enrichment/reporting egress paths are operator-gated and
  default off.* The honeypot never executes what it captures. See
  [§5](#5-security-and-trust-model).
- **What the operator owns:** authoring the `/etc/propolis/*.env` secret files
  (the installer never writes them), keeping the console loopback-only or behind
  their own TLS proxy, tightening the placeholder syscall filter, creating the
  `noexec` spool mounts, testing backups, and installing the feed-publish cron.
  See [§6](#6-deployment), [§7](#7-configuration), [§8](#8-operations).
- **The single largest risk:** it is a single node - one host holds the sensors,
  the daemon, PostgreSQL, and the malware spool. A host loss loses everything not
  backed up off-host, and there is no off-host backup shipped. See
  [§15](#15-known-limitations-and-technical-debt).

Pick your entry path by role in [Audiences](../overview/audiences.md); the corpus
map is [`DOCUMENTATION.md`](../../DOCUMENTATION.md).

---

## 2. Project identity and scope

**What it is** ([overview](../overview/index.md),
[capabilities](../overview/capabilities.md)):

- A **honeypot layer** - nine sensor crates presenting twelve protocol listeners
  (SSH, Telnet, HTTP, FTP, SMTP, Redis, ADB, plus VNC/MySQL/MSSQL/PostgreSQL/
  MongoDB from the credential sensor), each a separate OS process.
- A **scoring and review pipeline** - a hash-chained event ledger, a time-decayed
  per-IP score behind a confirmed-real gate, an operator review queue, and a
  two-tier blocklist feed.
- An **operator console** - a loopback web dashboard for triage, review, and feed
  status.
- A **single Rust workspace** deployed as one unified daemon plus the sensor
  processes.

**What it does NOT do** ([non-goals](../overview/non-goals.md)) - these are scope
decisions, not gaps:

- Not a network IDS/IPS; it observes traffic delivered to its own decoy
  listeners and does not block inline.
- Not multi-tenant, SaaS, or a managed service; you operate one node yourself.
- Not an offensive or exploitation tool.
- Ships **no built-in TLS** (the console is plain HTTP on loopback).
- **Not "egress-free" as a whole** - sensors are egress-free by construction, but
  the platform has a few operator-gated, default-off egress paths.
- No automatic public action, and no bundled third-party threat-intel data.

**Ethical-use boundary** ([ethical use](../overview/ethical-use.md)): deploy only
on infrastructure you own or are explicitly authorized to monitor; captured
malware is live hostile code and its custody and any onward transmission are the
operator's responsibility.

**Audiences and entry points** ([audiences](../overview/audiences.md)): evaluators
start at [capabilities](../overview/capabilities.md) /
[maturity](../overview/maturity-and-status.md); deployers at
[deployment models](../operations/deployment-models.md); operators at
[routine procedures](../operations/routine-procedures.md); security reviewers at
the [threat model](../security/threat-model.md); contributors at the
[repository tour](../development/repository-tour.md).

---

## 3. Current implementation status

Read the version signals together, not in isolation
([maturity and status](../overview/maturity-and-status.md),
[release procedure](../development/release-procedure.md)):

| Fact | Value |
|---|---|
| Crate version (all 18 crates, no `[workspace.package]` key) | `0.3.0` |
| Only release tag | `v0.1.0` (annotated, commit `e0bfd513`, 2026-08-02) |
| `v0.2.0` / `v0.3.0` tags | do not exist - the `0.3.0` tree is **untagged** |
| `CHANGELOG.md` | a single, undated `## Unreleased` section, not version-partitioned |
| Current `main` HEAD (this pass) | `2ed77827` |
| Rust edition / MSRV | edition 2024; no `rust-version`/MSRV declared |

So the working tree is roughly **two unpublished minor bumps ahead of the tagged
release**. Describe maturity as *source-available, actively developed, one tagged
release (`v0.1.0`), current tree `0.3.0` untagged* - never certified or
production-blessed.

**The V12 operator-console interface** (the theme system, evidence drawer, and
self-hosted fonts) merged **after** the `v0.1.0` tag, at commit `dbf8c053`
(2026-08-25), and is **not mentioned in `CHANGELOG.md`**. It is present in the
current tree. See [console architecture](../architecture/console.md).

**Implemented and substantial** (declared-test counts, not a verified green run
in this pass): core scoring, intake, review/reporting with AbuseIPDB/DShield/OTX
adapters, the two-tier feed with a fail-closed publisher, the console, the
12-protocol sensor surface, and the unified daemon with ops self-alerting.

**Partial / opt-in / conditional** (off-by-default, not absent): reverse DNS
enrichment, ASN suppression, MaxMind GeoLite2 geo/ASN (requires an operator-
supplied database directory; nothing is bundled), and ops self-alerting.

**A claim not verified from source:** the `v0.1.0` tag message and README cite a
*"172-test authorized pentest, all findings remediated."* No pentest harness is
located under `crates/`, so this is recorded as an unverified maintainer claim;
the tag's test-count figures ("770+", "172") predate ~180 commits of later work
and are stale. A separate 2026-08-25/26 sensor adversarial audit did land
(remediations merged at `2ed77827`) - see [§17](#17-historical-provenance-and-archive-map)
and [audits](../history/audits.md).

---

## 4. System architecture

Full section: [architecture index](../architecture/index.md). Propolis is a Rust
workspace of **18 crates producing 15 binaries**
([components](../architecture/components.md)).

**The one-node model** ([process topology](../architecture/process-topology.md)).
All state lives in one PostgreSQL database. The data plane (intake, review, feed,
console, plus the VirusTotal scanner, malware fetcher, and ops-alert monitor)
runs inside **one supervised daemon process** (`propolis`) sharing a single
`PgPool`. The attacker-facing **sensors run as separate OS processes**, one per
sensor binary, so a crash or compromise in a sensor cannot take down the data
plane. In production one `propolis.service` supersedes the dev-only standalone
`intake`/`review`/`feed`/`console` units.

**Sensors** ([sensor architecture](../architecture/sensors.md)). **Nine sensor
crates cover twelve protocols** (the `sensor-cred` crate serves five:
VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Every sensor is a thin protocol front-end on
one shared `sensor-framework` that owns the listener, per-connection bounds
(concurrency semaphore, timeouts), WAN attribution, the single `sanitize_value`
chokepoint, the capture hand-off, the quarantine spool, the fake shell/filesystem,
and one coherent persona. Two invariants hold **by construction**: egress-free
(no HTTP client in a sensor's dependency tree) and never-execute (no process-spawn
facility anywhere in a sensor). **Sensors have no compiled-in default port** - the
listen addresses come entirely from the deploy units' config, not from source.

**Storage** ([storage](../architecture/storage.md)). PostgreSQL is the single
datastore - no second DB, broker, or queue. The `event` table is an
**append-only, hash-chained ledger**: each row carries `SHA-256(prev_hash ‖
canonical_bytes(event))` over a frozen, length-prefixed field encoding pinned by a
golden test vector. Append-only is enforced in three ways - a `BEFORE INSERT`
chain-linkage trigger (fail-closed), a production-only `REVOKE UPDATE/DELETE/
TRUNCATE` on the app role, and a single serialized advisory-lock critical section
for every append. `ip_score` is a rebuildable per-IP projection of the ledger.

**Pipeline** ([pipeline](../architecture/pipeline.md)). Events fold into a
decayed per-IP score (6h half-life), gated by a sticky confirmed-real latch
(TCP + authenticated + honeypot category), a breadth multiplier over distinct WAN
vantages, and a non-decaying persistence bonus. Tiers (Aggressive / Standard) and
recommendations feed a **review queue** that is the human gate before any outward
action, then a **feed builder** and an **operator-approved vendor submission**
path.

**Console** ([console](../architecture/console.md)). Server-rendered axum +
minijinja + HTMX + self-hosted Chart.js. It serves **plain HTTP on a loopback
`TcpListener` - there is no in-process TLS**. It exposes **30 routes (7 public,
23 session-gated)**, sets `X-Frame-Options: DENY` and `nosniff` globally, and sets
**no global CSP** (only `/samples/download` sets `default-src 'none'`).

**Concurrency and failure** ([concurrency and failure](../architecture/concurrency-and-failure.md)).
Bounded by construction: per-connection tasks with a hard concurrency cap that
sheds load by refusing (never queuing); a bounded capture queue drained by one
sequential worker; the serialized single-writer append. The one deliberate
**fail-open** is capture completeness under queue saturation (a covertness choice -
a dropped capture is counted, not silently lost); everything on the integrity,
storage, and control paths **fails closed**.

**Trust boundaries and egress** ([trust boundaries](../architecture/trust-boundaries-and-data-flows.md)).
Attacker → sensors (low-trust, exposed) → local NDJSON logs + spool (one-
directional; sensors never talk to intake or the DB directly) → PostgreSQL →
platform → console (operator, loopback). **The platform is not egress-free** - the
lockfile contains `reqwest`/`hyper` for the platform tier - but every outbound
path is opt-in and default off (see [§5](#5-security-and-trust-model)).

Code-evidenced architecture decisions (the private ADRs are out of scope) are
catalogued in [decisions](../architecture/decisions.md).

---

## 5. Security and trust model

Full section starts at the [threat model](../security/threat-model.md).

**Adversary and assets.** The primary adversary is an unauthenticated internet
attacker controlling every byte on a sensor connection, the source-address
framing, and content designed to attack downstream consumers (forged log lines,
traversal filenames, SSRF-shaped URLs, oversized inputs). Protected assets: the
host (no attacker code ever runs), evidence integrity (tamper-evident ledger),
the database (no injection/unbounded growth), malware custody, credential/sample
privacy, the operator, and third parties (the box must not become an attack
proxy). Out of scope as adversaries: a malicious operator, a compromised kernel,
toolchain supply-chain compromise.

**The egress posture (global correction).** *Sensors are egress-free by
construction; the platform's few enrichment/reporting egress paths are
operator-gated and default off.* Never say the whole system makes no outbound
requests - `Cargo.lock` contains `reqwest` and `hyper` for the platform tier. The
canonical owner is [outbound controls](../security/outbound-controls.md). There
are exactly **five outbound paths, every one opt-in and defaulting off**, several
fail-closed if their credential/topic is missing:

| # | Path | Component | Gate (default off) |
|---|---|---|---|
| 1 | VirusTotal sample lookup/upload | `review` | `PROPOLIS_VT_ENABLED` + non-empty key; upload a separate flag |
| 2 | Abuse-vendor submitters (AbuseIPDB/DShield/OTX) | `review` | `PROPOLIS_VENDOR_<NAME>_ENABLED`; fail-closed with no key |
| 3 | Malware fetcher (attacker-supplied URL) | `review::fetcher` | `PROPOLIS_FETCH_ENABLED`; SSRF-guarded |
| 4 | Forward-confirmed reverse DNS | `console` | `PROPOLIS_CONSOLE_RDNS_ENABLED`; display-only, never a suppression signal |
| 5 | Ops-alert ntfy POST | `propolis` daemon | ops `enabled`; URL+topic then required |

Offline GeoLite2 enrichment is **local file reads, not network**. Path 3 is the
only one that dials an attacker-controlled URL; it runs through a load-bearing
SSRF vetter (scheme allowlist http/https/tftp, `user:pass@host` rejected,
DNS-rebinding defense, pinned-address connect, IPv6 canonicalization, forbidden
own-host/reserved-target check) on the initial URL **and every redirect hop**,
fail-closed at each step, and the fetcher refuses to run at all if `own_ips` is
empty.

**Never-execute and malware custody**
([never-execute](../security/never-execute.md),
[malware custody](../security/malware-custody.md)). No Propolis code spawns a
subprocess or execs - a whole-workspace grep for process-spawn constructs returns
zero, per-sensor static-check tests enforce it, and units set
`MemoryDenyWriteExecute=yes`. Custody is **store → hash → verify → human-approve →
report**: bodies are named by their SHA-256 (traversal structurally impossible),
written `0640`, re-hashed on read (fail-closed on mismatch), bounded by a per-file
cap and a global byte budget, and forwarded to a vendor only after an operator
**approves** the review-queue entry. Samples are never executed or opened.

**Input handling and DB protections**
([input handling](../security/input-handling.md),
[filesystem/DB protections](../security/filesystem-and-db-protections.md)). Every
attacker string routes through the shared `sanitize_value` chokepoint (order-
sensitive: collapse line-breaking whitespace, strip control/bidi/zero-width, NFC-
normalize, UTF-8-safe truncate) before it can enter an event. All SQL is
parameterized (`$n` bound values; no query text built by string formatting).

**Console auth** ([authn/authz](../security/authn-authz.md)). Single-operator,
coarse binary authorization. Argon2id password hashed at startup (plaintext
dropped; refuses to start with no `PROPOLIS_CONSOLE_PASSWORD`), HMAC-signed
in-memory sessions (no session table - a restart drops all sessions), per-session
CSRF on mutating routes (constant-time compare; login and read-only integrity-
verify deliberately exempt), and a sliding-window login rate limiter keyed on the
real TCP peer, memory-bounded and fail-closed.

**No in-process TLS (global correction).** The console is plain HTTP on a loopback
`TcpListener`; any TLS is operator-provided (e.g. a reverse proxy) and
`[inferred]`. `/health`, `/ready`, `/metrics` are unauthenticated - acceptable
*only* because the default bind is loopback.

**Supply chain** ([supply chain](../security/supply-chain.md),
[dependencies](../reference/dependencies.md)). Dependencies are vendored in-tree
with a frozen lockfile; `vendor/** -text` protects vendored checksums from EOL
mangling. Run `cargo build --release --locked` after any re-vendor.

Vulnerability reports go through [vulnerability disclosure](../security/vulnerability-disclosure.md)
(private report, 72h acknowledgment). The full accepted-risk list is
[residual risks](../security/residual-risks.md); the operator's pre-exposure
sequence is the [hardening checklist](../security/hardening-checklist.md).

---

## 6. Deployment

Full section: [deployment models](../operations/deployment-models.md),
[installation](../operations/installation.md).

**Models.** Linux + systemd. The primary, documented model is **single-node**: one
host runs the unified `propolis` daemon plus the nine sensor services. A
multi-node cluster sharing one PostgreSQL database is possible but `[inferred]`
from `INSTALL.md` (review/feed designed idempotent); treat it as an advanced,
less-travelled path and validate idempotency yourself. Requirements: systemd
≥ 244, PostgreSQL 15+ (an operator requirement, not code-enforced), and the pinned
Rust `1.96.1` on the build host only.

**Install** (`sudo ./deploy/install.sh`, root; `--dry-run` needs no privilege).
Build first (`cargo build --release`); the script errors if a binary is missing.
It creates 10 system users, config/log/state directories with specific
owners/modes, spool mountpoints, installs the 10 binaries to `/usr/local/bin`, the
10 production units, and a logrotate config, then `daemon-reload`. Notable:
`/var/lib/propolis` is 0755 root-owned deliberately so a compromised daemon cannot
swap the sibling SSH host-key dir.

**What `install.sh` deliberately does NOT do:** it does not start or enable any
service, does not create or migrate the database, and **does not create or edit
any `/etc/propolis/*.env` file** - those carry secrets the script "has no business
fabricating." You author them by hand before starting anything.

**Units.** `propolis.service` is `Restart=on-failure` (its in-process supervisor
restarts panicked subsystems, so a process exit only means fail-fast or an
operator stop); the nine `sensor-*.service` units are `Restart=always`. All units
apply a least-authority sandbox (`NoNewPrivileges`, `ProtectSystem=strict`,
`PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`, per-sensor capability
sets - only privileged-port sensors get `CAP_NET_BIND_SERVICE`).

**Two operator-owned deployment gaps (global corrections):**

- **The `SystemCallFilter` in every shipped unit is a PLACEHOLDER**
  (`@system-service` minus `@privileged @resources`) - a broad development
  allowlist the unit header itself says to tighten with `strace -c -f` before
  production. Treat the syscall sandbox as effectively absent until you derive the
  real per-binary allowlist.
- The **`noexec,nosuid,nodev` spool mounts** are printed as fstab guidance by
  `install.sh`, not created. Add and verify them (`findmnt`).

**Networking/TLS** ([networking and TLS](../operations/networking-tls.md)). Three
exposure classes: attacker-facing sensors (operator-chosen `ip:port`, no default),
operator-facing console (`127.0.0.1:8080` loopback), and no-listener components.
There is **no in-process TLS** - keep the console loopback and terminate TLS at
your own reverse proxy if it must be reachable off-host. Before any firewall
change that could sever access, confirm out-of-band admin (the honeypot's port 22
is the *fake* SSH sensor, not a real admin channel).

Before exposing any listener, work the
[production-readiness checklist](../getting-started/production-readiness-checklist.md).
For a non-production local bring-up, see
[evaluation deployment](../getting-started/evaluation-deployment.md).

---

## 7. Configuration

Full section: [configuration model](../operations/configuration.md). Every exact
default/bound is owned by
[environment variables](../reference/environment-variables.md).

Propolis is configured **entirely through environment variables** in per-service
files under `/etc/propolis/` - no config-file format, no runtime CLI flags, no
config in the database. Each systemd unit reads one `EnvironmentFile`:
`propolis.service` → `/etc/propolis/propolis.env` (the whole data plane), each
`sensor-<name>.service` → `/etc/propolis/<name>.env`. These files are
operator-authored, mode `0600`, owned by the service user; `install.sh` never
creates them.

Grouped by subsystem: database (`DATABASE_URL` required,
`PROPOLIS_DB_MAX_CONNECTIONS`), intake (`PROPOLIS_SENSOR_LOGS` required,
`PROPOLIS_CURSOR_DIR`, poll cadence), review/feed cadence and vendor/feed tuning,
console (`PROPOLIS_CONSOLE_BIND`, `PROPOLIS_CONSOLE_PASSWORD` required,
`PROPOLIS_CONSOLE_SESSION_SECRET`, `PROPOLIS_GEOIP_DIR`), the four egress-capable
subsystems (all default off), and per-sensor binds/bounds.

**Fail-fast validation.** Most binaries **abort startup** on a missing required
variable or a present-but-invalid / present-but-zero numeric bound - "zero never
means unlimited," so a misconfiguration cannot silently disable a guard. Two
exceptions: the `cred` and `smtp` sensors fall back to defaults on an invalid
bound (their bind vars still fail-close). Fail-closed pairings worth knowing: a
vendor/VT `*_ENABLED=true` with an empty key is forced disabled;
`PROPOLIS_OPS_ENABLED=true` makes the ntfy URL and topic required;
`PROPOLIS_FEED_WINDOWS` fails closed on any malformed entry; the ASN allowlist is
inert unless a GeoLite2-ASN database loads.

**Secrets** ([secret management](../operations/secret-management.md)). No secret is
created by the installer, read from argv (all via `env::var`, so none appear in
process listings), or written back to disk. `DATABASE_URL` carries the DB password
inline; `PROPOLIS_CONSOLE_PASSWORD` is Argon2id-hashed at startup and the
plaintext dropped (the `.env` file's `0600` mode is the real control);
`PROPOLIS_CONSOLE_SESSION_SECRET` must be exactly 64 hex chars if set, else a fresh
key each start; vendor / VirusTotal / ntfy keys are opt-in. Back these files up to
encrypted storage only, never to a repository.

**Sensor binds and WAN attribution.** Every sensor requires its `<PREFIX>_BIND`
and refuses to start without it - there is **no compiled-in default port**, so the
"standard" SSH-22/Telnet-23 mapping is whatever the operator writes.
`<PREFIX>_WAN_MAP` maps a local bind to its public WAN IP for breadth scoring; an
unmapped address yields a null `wan_ip`, a valid non-fatal state.

---

## 8. Operations

Full section: [routine procedures](../operations/routine-procedures.md),
[service lifecycle](../operations/service-lifecycle.md).

**Lifecycle.** Configuration and secrets must exist first. Start with
`systemctl enable --now propolis.service` and each sensor unit; ordering between
sensors and the daemon does not matter for correctness (sensors append to local
logs, the daemon tails them). Daemon startup fails fast in order: init tracing →
load/validate config → connect the pool → run embedded migrations (core-scoring
then review) → create the cursor dir → spawn subsystems. There is **no separate
migrate step**. A clean stop (SIGTERM/SIGINT) cancels subsystems and awaits them
under a 30s timeout.

**Reviewing the queue.** IPs that clear the eligibility gate surface into the
review queue for a human decision. Publication of any IP requires **all** of: an
authenticated console session, the IP seen more than once, above the score floor,
and an explicit approval. There is no auto-publish path. States: pending /
approved / rejected / snoozed; a decision records `decided_at` and notes.

**Publishing the feed - two stages, only the first automated (global
correction):**

- **Stage 1 (automated):** the daemon's feed subsystem builds a snapshot from
  `ip_score` and writes it atomically to `/var/lib/propolis/feed/current` every
  build interval (default 900s). A failed build leaves the previous feed in place.
- **Stage 2 (operator cron):** shipping the built feed to a public repository is
  done by `deploy/blocklist-sync.sh`, **referenced by comment only and not wired
  into any shipped systemd timer or cron**. You install the crontab; confirm the
  push credential is a headless deploy key. This step is egress (a `git push`
  exposing the listed IPs) - see [outbound controls](../security/outbound-controls.md).

**Health and observability**
([health and observability](../operations/health-and-observability.md)). `GET
/health` (liveness, always 200, no DB), `GET /ready` (200 if `SELECT 1`, else
**503 fail-closed**), `GET /metrics` (Prometheus, derived live per scrape;
unauthenticated, so keep loopback). Watch `propolis_feed_last_build_timestamp`
(feed still publishing), the review-queue depth, and two capture-loss counters:
`dropped_count` (queue full - WARNs at powers of two) and `spool_refused_count`
(per-file cap or budget - WARN per refusal). The daemon and sensors log via
`tracing` to the journal; a session-gated `/logs` viewer tails a 1000-event ring
buffer.

**Ops self-alerting (opt-in).** An internal monitor pages via ntfy on degradation
(spool free space, intake/feed stall, feed staleness, vendor failure rate, review
backlog, periodic hash-chain verify). Off by default; when enabled the ntfy URL
and topic are required or the daemon refuses to start.

**Retention** ([retention](../operations/retention.md)). Feed membership is bound
by tier TTLs (Aggressive 24h, Standard 48h) and retention windows (default
`24h,7d,30d,60d,90d`). Captured sample files are trimmed at 30 days - **but only
by the VirusTotal scanner's cleanup pass, which runs only when VirusTotal is
enabled**; without VT, spooled files are bounded only by the global byte budget,
so run your own prune if you need age-based expiry. There is **no built-in pruning
of the `event` table** - plan storage for sustained ingest. Sensor logs rotate at
`size 100M`, 5 generations.

**Capacity** ([capacity planning](../operations/capacity-planning.md)). One shared
PgPool (default 10 connections); capture queue depth 64; spool budgets 100 MB per
spooling sensor (SSH/FTP/ADB) and 1 GB for the fetcher; per-unit systemd caps
(daemon 1G/256 tasks; sensors 256-512M). Queue/spool operational behavior is in
[queue and spool](../operations/queue-and-spool.md).

---

## 9. Data and evidence lifecycle

Full section: [event and sample lifecycle](../architecture/event-and-sample-lifecycle.md).
Two flows share an origin at the sensor and then diverge - the event goes down the
reply-blocking path, the sample body goes off it.

**Event flow.** A sensor handler sanitizes every attacker string, builds a
`SensorEvent` (raw facts only, no score), and writes exactly one NDJSON line to
its local log via one atomic `O_APPEND` `write_all` - an event exists once and
only once the whole line lands (local storage required; NFS `O_APPEND` can race).
Intake tails each log, validates `signal_type`/`protocol` against the known set,
derives weight/confidence/category from the single-source-of-truth weight table (a
sensor never computes a score), and appends to the hash-chained ledger. The
scoring fold decays prior per-IP state, adds the event's weight, and recomputes
the gate flags into `ip_score`. `session_id` correlates one sensor session's
events and is deliberately outside the hash chain.

**Sample flow** (only SSH, FTP, ADB spool bodies; the fetcher spools what it
pulls). The handler `submit`s a `CaptureJob` over an mpsc `try_send` that never
blocks the reply - a full queue drops the job and counts it (covertness over
completeness). A single sequential worker stores each body under its SHA-256 name
(0640, budgeted), and the event carries only a `SampleRef { sha256, size,
orig_name }` where `orig_name` is a sanitized indicator, never a path.

**Enrichment.** VirusTotal hash-lookup writes a `detected/total` verdict to
`sample_analysis` (a hash lookup sends only the hash; uploading a body is opt-in
`PROPOLIS_VT_UPLOAD`, default off). The optional malware fetcher retrieves a
dropper-referenced payload through the SSRF guard. Offline GeoLite2 ASN suppression
is local file reads.

**What leaves in a report.** A vendor report carries only `{source_ip, categories,
comment, evidence_window}` - never the WAN vantage, raw score, confidence, or a
sample body. Captured passwords are dropped at the sensor and are structurally
absent from every report and log
([sample and credential privacy](../security/sample-and-credential-privacy.md)).

**Backup** ([backup and restore](../operations/backup-and-restore.md)). Three
durable state categories, in descending importance: (1) **PostgreSQL** - the
canonical datastore, the one thing not recoverable from anything else on the node;
(2) **spool directories** - captured sample bodies and fetched malware are custody
evidence and are **not** reconstructable from the DB (which holds only the SHA-256
reference); cursors rebuild by re-reading logs and the feed dir regenerates from
`ip_score`; (3) **config/secrets** under `/etc/propolis/*.env` (back up to
encrypted storage only). Propolis ships **no backup or restore tool** - use
`pg_dump` plus a `tar` of the durable dirs, preserving owners/modes. **A backup is
a hypothesis until you have restored it end-to-end** against a scratch environment.

---

## 10. Incident response

There is no single incident-response owner page in the reference corpus; the
material is assembled from the security and operations sections. The role manual
is [`manuals/incident-response.md`](../manuals/incident-response.md).

**If the honeypot captured live malware you must handle**
([malware custody](../security/malware-custody.md)). The spool holds real captured
samples - treat it as hostile content. Keep it on a `noexec,nosuid,nodev` mount,
never browse it with a tool that auto-opens or previews files, and rely on the
custody chain (SHA-256-named, `0640`, re-hash-verified). Forwarding a sample or
IP to a vendor requires an explicit **approve** in the console review queue; there
is no automatic-forward path. Propolis never executes a captured body.

**If you suspect ledger tampering.** The `event` chain is tamper-evident: any
change to a hashed field, or any reorder/insertion, breaks the linkage from that
point forward. The console's integrity page runs a read-only chain verification;
the DB-layer trigger enforces linkage on every insert (fail-closed), and in the
production database `UPDATE/DELETE/TRUNCATE` are revoked from the app role. A
broken chain reported on the integrity page is the signal to investigate - see
[troubleshooting: database](../troubleshooting/database.md).

**If the host is lost or compromised**
([upgrade/rollback/DR](../operations/upgrade-rollback-and-dr.md),
[residual risks](../security/residual-risks.md)). Single-node blast radius: a host
loss takes the datastore and the custody evidence with it unless they were shipped
off-host. Recover by provisioning a fresh host and running the restore path in
[backup and restore](../operations/backup-and-restore.md) - restore config, restore
the database (forward-migration direction only), restore spool and the SSH host
key, start, and verify `/ready`, the chain, the console, and the feed. There is no
shipped down-migration; the rollback path for the schema is the pre-upgrade dump.

**If you found a vulnerability in Propolis itself.** Report it privately per
[vulnerability disclosure](../security/vulnerability-disclosure.md) (72h
acknowledgment; fixes committed and tagged before public disclosure). Do not open
a public issue.

**If a source has fingerprinted the honeypot.** Detection degrades intelligence
yield rather than causing direct harm; **IP rotation** is the practical lever for
recovering interaction. Symptom-first help is the
[troubleshooting index](../troubleshooting/index.md).

---

## 11. Development and testing

Full section: [build and test](../development/build-and-test.md),
[repository tour](../development/repository-tour.md).

**Toolchain** ([toolchain and environment](../development/toolchain-and-environment.md)).
Rust pinned to `1.96.1` (`rust-toolchain.toml`); dependencies vendored in-tree
(`.cargo/config.toml` redirects crates-io to `vendor/`); build/test are plain
`cargo` (no Makefile/justfile). The DB-backed tests need a local test PostgreSQL.

**The gate.** CI runs **three independent jobs**, deliberately not one chained job
(a single chained job once let an unformatted tree hide clippy and the whole suite
for 30+ commits):

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1     # under set -o pipefail
```

Load-bearing details: `--all-targets` compiles test targets so a broken test file
fails clippy rather than silently vanishing; `--test-threads=1` runs serially;
`set -o pipefail` stops a piped `cargo test | tee` from reporting a red suite as
green; `--locked` freezes `Cargo.lock`. `CONTRIBUTING.md` gives a looser one-liner
- use the CI commands.

**Test corpus.** 1165 test functions (681 unit + 484 integration; 116 DB-backed
via `sqlx::test`; exactly 1 `#[ignore]`d live rDNS test). These are static
attribute counts, not a verified passing run in this pass; the old "~946 tests"
and the tag's "770+" are stale. Sensor crates test with real TCP against ephemeral
listeners plus static-check tests that enforce the sensor contract (never-execute,
no-HTTP-client). A `docs_agreement` test fails CI if any `PROPOLIS_*`/`CATCHALL_*`
env var in source is missing from `INSTALL.md`.

**Adding a sensor** ([adding a sensor](../development/adding-a-sensor.md)) and
**schema changes** ([schema and migrations](../development/schema-and-migrations.md)):
migrations are additive and applied-once; never edit an applied migration in
place; run `cargo build --release --locked` after any `cargo vendor`.

---

## 12. Maintenance and releases

**Maintenance model** ([maintenance and support](../governance/maintenance-and-support.md)).
Single-maintainer, source-available, **best-effort**: no SLA, no warranty, no
support desk. Security handling is best-effort on the same basis. Help starts at
[`DOCUMENTATION.md`](../../DOCUMENTATION.md); defects go to the project's GitHub.

**Release model** ([release policy](../governance/release-policy.md),
[release procedure](../development/release-procedure.md)). A release is an
**annotated git tag `vMAJOR.MINOR.PATCH`** on a `main` commit - tagging is the
release act; there is no published package. No release is cut on a red gate. The
procedure (partly `[inferred]` - there is no CI release job and no `RELEASING.md`):
bump every crate's version (no `[workspace.package]` key; kept in lockstep),
rename `## Unreleased` to the version/date and open a fresh one, run the full gate
**and** `cargo build --release --locked`, then create and push an annotated tag.
Pushing a tag is an outward, effectively-irreversible publish - confirm it points
at the intended fully-gated commit.

**Compatibility and versioning**
([compatibility and versioning](../governance/compatibility-and-versioning.md)).
SemVer-shaped; pre-1.0, treat minor bumps as potentially breaking. The
`sensor-wire` contract is frozen; schema and configuration evolution is additive
(new fields optional, safe defaults, transforms only in explicit migration code).

**Upgrade path** ([upgrade/rollback/DR](../operations/upgrade-rollback-and-dr.md)).
`sudo ./deploy/upgrade.sh` rebuilds as the repo-owner, reinstalls binaries,
restarts enabled sensors, then restarts `propolis.service` last so migrations run.
Take a database backup first - the forward-only migration model means an in-place
schema change is not automatically reversible.

---

## 13. Troubleshooting

Full section: [troubleshooting index](../troubleshooting/index.md) (symptom-first).

Because most config is **fail-closed**, the single most common failure class is a
service that exits immediately at boot with a logged reason - so
`journalctl -u <unit>` is the first check every time. Cross-cutting first checks:
`systemctl status <unit>`; `curl -s localhost:8080/ready` (process up vs DB
reachable); `curl -s localhost:8080/health` (liveness only); confirm whether the
unified daemon or the dev-only standalone set is deployed.

Symptom areas map to dedicated pages:

- Startup exits, bad env var, bind conflicts → [startup and config](../troubleshooting/startup-and-config.md)
- DB connect/migration failures, `/ready` 503, broken integrity chain → [database](../troubleshooting/database.md)
- Dropped events, spool filling → [queue and spool](../troubleshooting/queue-and-spool.md)
- Nothing captured, port not listening, `wan_ip` null → [sensors and networking](../troubleshooting/sensors-and-networking.md)
- Can't reach/login to the console, logged out after restart, CSRF 403, offline fonts → [console](../troubleshooting/console.md)
- VirusTotal / vendors / fetcher / feed / blocklist repo / ops alerts → [integrations and feed](../troubleshooting/integrations-and-feed.md)
- Restore/backup verification → [backup and recovery](../troubleshooting/backup-and-recovery.md)

---

## 14. Governance and roadmap

**Roadmap policy** ([roadmap](../governance/roadmap.md)). The detailed plan lives
in private internal material; the public page states only *how* direction is
decided: the maintainer sets priorities (no committed schedule), evidence over
intent (planned work is never presented as delivered), and additive/reversible-
first (safe defaults, additive schema, opt-in default-off egress). For what exists
today versus what is partial, use the code-evidenced
[maturity and status](../overview/maturity-and-status.md), not a roadmap.

**Licensing** ([licensing](../governance/licensing.md),
[`LICENSE.md`](../../LICENSE.md)). **Source-available, not open source**, under the
**PolyForm Noncommercial License 1.0.0**. Noncommercial use (personal, home lab,
research, teaching, nonprofit/public-safety/government) is free; commercial use
requires a separate license from the maintainer. No warranty.

**Contribution** ([contribution](../governance/contribution.md)). Noncommercial
contributions welcome under the same license; contributions are made under it and
must pass the merge gate.

---

## 15. Known limitations and technical debt

Consolidated from [limitations](../overview/limitations.md) and
[residual risks](../security/residual-risks.md) - these are limits of the shipped
code and deployment model, stated plainly, not defects to be discovered later.

- **Single-node blast radius.** Sensors, daemon, and PostgreSQL run on one host;
  a host loss or compromise reaches everything. No built-in HA/failover/off-host
  redundancy, and **no off-host backup mechanism is shipped** (`[planned]`).
  Off-host evidence replication is an operator responsibility.
- **Placeholder syscall filter** (global correction). Every unit's
  `SystemCallFilter` is a broad development allowlist, not a tightened seccomp
  filter, and whether one was derived on a given host is not verifiable from
  source. Treat the syscall sandbox as absent until narrowed.
- **No in-process TLS** (global correction). Plain HTTP on loopback; console
  confidentiality/integrity beyond loopback depends entirely on an
  operator-provided reverse proxy.
- **Quarantine mount options are operator-applied.** `install.sh` prints the
  `noexec,nosuid,nodev` fstab guidance but cannot enforce it; if the mounts are
  missing, the `0640` mode and `NoExecPaths` are the remaining defenses.
- **Manual feed publish** (global correction). The blocklist-sync/publish cron is
  an operator setup step, not a shipped timer; without it the feed builds locally
  but is pushed nowhere.
- **Egress paths, once enabled, are real egress.** All five default off, but
  enabling one accepts its outbound exposure - most sharply the fetcher, which
  dials attacker-supplied URLs (SSRF-guarded, but still a deliberate risk).
- **Honeypot-detection tells.** No emulation is indistinguishable to a determined
  adversary; IP rotation is the recovery lever. Specific tells are deliberately
  not enumerated.
- **Unauthenticated console metrics/health/ready.** Safe *only* because the
  console defaults to loopback; rebinding off-loopback without a fronting proxy
  exposes them.
- **No built-in `event`-table pruning**, and the 30-day sample cleanup runs only
  when VirusTotal is enabled - plan storage and prune accordingly.
- **Coverage-test gap.** The explicit no-HTTP-client dependency assertion exists
  only for `sensor-ssh`; extending it to the other sensors would make the
  "sensors are egress-free" claim machine-checked for all of them. `sensor-catchall`
  lacks its own never-execute regression test (clean under the workspace grep).
- **Unverified pentest claim.** The "172-test authorized pentest" cited by the
  README and tag has no locatable harness under `crates/`; corroborate before
  relying on it (see [audits](../history/audits.md)).

---

## 16. Reference appendices

The [`reference/`](../reference/environment-variables.md) pages are the single
canonical owners of exact values. This binder cites them rather than restating -
consult each for the authoritative table:

| Reference page | Owns |
|---|---|
| [environment-variables](../reference/environment-variables.md) | every env var: name, default, bounds, fail-on-invalid behavior |
| [ports-and-protocols](../reference/ports-and-protocols.md) | ports and binds (sensors have no code default; the deploy units configure them) |
| [filesystem-paths](../reference/filesystem-paths.md) | all filesystem paths, owners, and modes |
| [database](../reference/database.md) | tables, columns, enums, migrations, the hash-chain canonical encoding |
| [events-and-signals](../reference/events-and-signals.md) | signal types, event fields, weights |
| [sensor-behavior](../reference/sensor-behavior.md) | per-protocol capture behavior (banners, verbs, caps) |
| [console-routes](../reference/console-routes.md) | the 30 routes (7 public, 23 session-gated) and per-route auth/CSRF |
| [scoring-and-feed](../reference/scoring-and-feed.md) | scoring constants, thresholds, tiers, TTLs, retention windows |
| [integrations](../reference/integrations.md) | VirusTotal, vendor submitters, ntfy, GeoLite2 wire contracts |
| [rate-limits-and-budgets](../reference/rate-limits-and-budgets.md) | fetcher/vendor/VT budgets and spool byte limits |
| [commands](../reference/commands.md) | runnable build/test/deploy/ops commands |
| [dependencies](../reference/dependencies.md) | dependency and vendoring model |
| [glossary](../reference/glossary.md) | terminology |

**Quick facts to anchor the numbers** (each owned by a page above): 18 crates /
15 binaries; 9 sensor crates / 12 protocols; 30 console routes (7 public, 23
session-gated); scoring half-life 6h; tiers Aggressive (score ≥ 90, confidence ≥
0.95) and Standard (≥ 75, ≥ 0.70); tier TTLs 24h/48h; retention windows
`24h,7d,30d,60d,90d`; feed build interval 900s; spool budgets 100 MB per spooling
sensor and 1 GB fetcher; sample cleanup at 30 days (VT-enabled only); capture
queue depth 64; default pool 10 connections; console default bind
`127.0.0.1:8080`.

---

## 17. Historical provenance and archive map

Full section: [`history/`](../history/changelog.md).

**Build history** ([completed and superseded](../history/completed-and-superseded.md)).
The original build shipped as eight sub-projects, SP1-SP8: core scoring; sensor
framework + SSH; event intake; review queue and reporting; blocklist feed; web
console; unified daemon; and seven added sensors (telnet, redis, adb, http, ftp,
smtp, and the credential multi-protocol sensor) - together the 9 crates / 12
protocols. Post-tag feature work added reverse DNS, ASN suppression, the network-
profile panel with offline GeoLite2, telnet XOR de-obfuscation, ops self-alerting,
and the **V12 operator-console interface** (which superseded the earlier console
direction, merged at `dbf8c053`, still absent from the changelog).

**Changelog state** ([changelog](../history/changelog.md)). The root
[`CHANGELOG.md`](../../CHANGELOG.md) is a single undated `## Unreleased` section,
not version-partitioned - entries cannot be mapped to `v0.1.0` versus later work
from the changelog alone, and the SP-era test subtotals in it are stale.

**Decisions** ([decisions-index](../history/decisions-index.md)). The
authoritative ADRs are private and gitignored; the public corpus documents only
the **code-observable** decisions in [architecture decisions](../architecture/decisions.md).

**Audits** ([audits](../history/audits.md)). A read-only sensor adversarial audit
(2026-08-25/26) merged its fidelity and observability hardening into `main` at
`2ed77827` (the current HEAD); it reported the dangerous vulnerability classes
(memory-safety, RCE, sandbox-escape, injection) clean. Specific detection tells
are deliberately not published. The separate "172-test pentest" claim remains
unverified from the public tree.

**Old-to-new map and archive**
([old-to-new-map](../history/old-to-new-map.md),
[archive-map](../history/archive-map.md)). The 2026-08-26 documentation rewrite
replaced a small root-level doc set (`README`, `INSTALL`, `SECURITY`, `CHANGELOG`,
`CONTRIBUTING`) with this layered corpus, using explicit compatibility stubs for
obsolete root paths (Markdown cannot redirect). The verbatim pre-rewrite public
documents are preserved byte-exact and immutable under
[`docs/archive/2026-08-26/`](../archive/2026-08-26/MANIFEST.md) with a
`CHECKSUMS.sha256` manifest. The private blueprint (`internal/**`,
`docs/superpowers/**`, `.superpowers/**`) and the live `.env` were deliberately
**not** archived - publishing the detection/logging blueprint would hand an
attacker the honeypot's fingerprinting playbook, and the `.env` is a secret.

---

*End of binder. For the corpus map and per-role entry points, see
[`DOCUMENTATION.md`](../../DOCUMENTATION.md) and
[Audiences](../overview/audiences.md).*
