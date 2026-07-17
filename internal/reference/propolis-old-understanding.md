# Propolis - System Understanding for a Fresh Rebuild

> Target audience: an engineer rebuilding Propolis from scratch in `~/Propolis-new`.
> Source: reverse-engineered subsystem summaries of `~/Propolis-old`.
> Everything below is grounded in those summaries. Exact numbers, gate predicates,
> env var names, and file paths are load-bearing - reproduce them verbatim.
> Where the old code and old docs disagreed, the summaries record it; **the CODE is
> authoritative** in every such case and the rebuild must follow the code behavior.

---

## 1. What Propolis is

Propolis is a **single-node, single-operator, IPv4-only defensive honeypot + threat-intelligence
platform** written in Python (>=3.11, package version 0.1.0). It ingests logs from honeypots
(Cowrie, Heralding, Dionaea, ADBHoney, RedisHoneypot, a bundled catch-all sensor), IDS/WAF
sensors (Suricata, ModSecurity, nginx, Wazuh), and firewalls (netfilter, pfSense/OPNsense
filterlog), attributes each observation to an attacker source IP, scores that IP with
time-decayed weighted signals, and - **only after a human operator explicitly approves each one** -
files abuse reports with reputation vendors (AbuseIPDB, DShield, OTX; opt-in SniffCat) and
publishes a tiered public blocklist feed to a GitHub repo. The problem it solves: turning noisy,
attacker-controlled sensor telemetry into **high-confidence, corroborated, human-ratified,
GDPR-defensible** abuse intelligence without ever auto-reporting a spoofable or single-sourced
observation, and without leaking secrets, passwords, or the operator's own infrastructure
addresses. It is deliberately **not** a system of record, not highly available, not clustered,
not multi-writer, not multi-host - a deployment that outgrows one box is a different system.

---

## 2. End-to-end pipeline (stage by stage → concrete modules)

The analysis loop (`runtime.AnalysisLoop.tick`, one daemon thread) drives ingest→enqueue.
Reporting and feed publication are **two independent downstream branches**, both fired *outside*
the analysis loop; their only coupling is that both read `ip_scores`.

| Stage | Module(s) | What happens |
|---|---|---|
| **0. Sensors** | `src/sensors/catchall/catchall_honeypot.py`; external Cowrie/Heralding/etc. | Capture attack traffic, append NDJSON/CSV log lines. Catch-all is a hardened, non-root, secret-free asyncio listener on ~50 ports. |
| **1. Ingest / tail** | `ingest/tailer.py` (`Tailer.read_new`), `persistence/.../offset_store.py` | Crash-safe, bounded, rotation/truncation/copytruncate-aware tail from a durable `(offset, inode, fingerprint)` cursor. At-least-once delivery. |
| **2. Parse** | `parsers/registry.py` (`PARSER_REGISTRY`, 13 keys) + one module per source | Pure total function `parse(line)->LogEvent|None`, never raises. Drops malformed/non-attributable/non-qualifying lines. Attributes source IP, classifies `SignalType`, stamps tz-aware UTC `observed_at`. |
| **2b. Suricata SID suppression** | `runtime.AnalysisLoop` + `config.detection.suricata_ignored_sids` | Drops suricata events whose `metadata['signature_id']` ∈ the ignored set, pre-scoring. |
| **3. Sanitize** | `sanitize/cleaners.py` | At parse time every attacker-controlled metadata string passes `clean_for_log`. Passwords are **dropped at parse**, never stored. |
| **4. Score** | `scoring/engine.py` (`ScoringEngine.process`), `scoring/decay.py`, `scoring/gates.py` | IP-shape validate → allowlist → signal lookup → dedup → half-life decay + weight accumulate → recompute corroboration fields → tier → reportability → atomic upsert `ip_scores` + append `events`. |
| **5. Gate (corroboration + tier)** | `scoring/gates.py` (`is_reportable`, `tier`) | Freezes `reportable` and `tier` onto the row. `AnalysisLoop` enqueues to review **only when `snapshot.reportable` is True**. |
| **6. Review (human gate)** | `review_queue/queue.py`, `persistence/.../review_repository.py`, `web/app.py` | State-guarded `PENDING`/`SNOOZED`/`APPROVED`/`REJECTED` queue, one open item per IP. Operator approves/rejects/snoozes in the loopback web UI. |
| **7a. Report → vendors** | `reporting/dispatcher.py`, `reporting/*` adapters, `gatekeeper/keeper.py` | On approve (or scheduled retry): emission-seam guards → per-vendor gatekeeper (cooldown/rate-limit/policy) → bounded-retry HTTP submit → audit + cooldown-on-success. |
| **7b. Feed publish** | `blocklist/*` (builder/writer/exporters/validate/publisher/feed_cli) | Scheduled (12h) rebuild of the two-tier blocklist from approved IPs → validate fail-closed → optional git push. |

Cross-cutting: `observability/*` (structlog JSON, Prometheus, health, scheduler); `config/*`
(frozen Pydantic `AppConfig`); `persistence/*` (SQLite/WAL, SQLAlchemy Core, Alembic);
`runtime.py`/`cli.py` (composition root + entrypoint).

---

## 3. Core design principles & invariants (MUST survive the rebuild)

These are the identity of the system. Exact numbers are load-bearing.

### 3.1 Human-approval gate (architecturally mandatory)
- The analysis loop only enqueues `state=PENDING`. It **never** auto-reports or auto-publishes.
- Vendor reporting fires only from `POST /review/{id}/approve` (or the retry runner re-submitting an
  already-`APPROVED` item). The dispatcher **re-asserts `state is APPROVED`** before any submission.
- The feed lists only IPs with an `APPROVED` review item.
- Trade-off (intended): a non-real-time feed. Cost of a false vendor report (reputation penalty) is
  judged worse than latency.

### 3.2 Corroboration gate - exact predicate (`is_reportable`)
```
reportable  ⇔  event_count >= 2  AND  distinct_categories >= 2  AND  has_tcp_auth is True
```
- Reads **no score and no confidence**. Three separate legs; a single noisy sensor can never make an
  IP reportable. (A breadth-boosted confidence therefore cannot flip a 1-event/1-category IP.)
- `has_tcp_auth` is set **only** by an event with `protocol == TCP AND authenticated == True AND
  category == HONEYPOT` (`_is_tcp_auth`). It is a **sticky latch** (`prev.has_tcp_auth OR _is_tcp_auth`):
  once True, stays True.
- `distinct_categories` = count of categories whose **decayed** breakdown weight is **> 0.5** (strict).
  A faded second category drops the count - the only way passage of time flips `reportable` True→False.
- `event_count` and `has_tcp_auth` are historical facts and **never decay**.
- Consequence: a **catch-all-only** (or non-honeypot-only) deployment produces an **empty feed by
  design** - nothing ever earns the `has_tcp_auth` latch.

### 3.3 Tier gate - exact predicate (`tier`)
```
AGGRESSIVE  ⇔  raw_score >= 90.0  AND  max_confidence >= 0.95
STANDARD    ⇔  raw_score >= 75.0  AND  max_confidence >= 0.70   (tested after AGGRESSIVE)
else        →  None   (below STANDARD threshold, "not tiered"; tier is FeedTier | None)
```
- **Both axes** must clear a band's floor (score 92 / conf 0.80 → STANDARD, not AGGRESSIVE).
- `reportable` and `tier` are **independent** (an IP can be `reportable=True` with `tier=None`).

### 3.4 Decay math - exact constants & formula
- `HALF_LIFE_SECONDS = 21600` (6h). Config knob `scoring.decay_half_life_s` (default 21600, `gt=0`) -
  the **only** operator-tunable scoring parameter. Every other threshold is a fixed source constant so
  the reporting gate cannot be weakened from YAML.
- `SCORE_CAP = 100.0` (fixed). `LAMBDA = ln(2)/21600` (computed in `decay.py` but **unused** - the
  decay path uses the base-0.5 form; open question whether to remove it).
- Formula: `decay_score = prev_score * 0.5 ** (elapsed_seconds / half_life_seconds)`.
  `elapsed_seconds <= 0.0` short-circuits and returns `prev` unchanged (clock-skew clamp: decay only
  ever shrinks, never inflates).
- Applied in **exactly two places**: the engine on **write** (mutates the stored row; reads prev via
  `get_raw`, the un-projected value), and `ScoreRepository` on **read** (pure projection, never
  rewritten). Using `get_raw` on write is what prevents **double-decay** of a returning attacker.
- Accumulation: `raw_score = min(100, decay_score(prev.raw_score, elapsed) + weight)`; every per-category
  breakdown weight decays by the **same factor**, then this event's category `+= weight`; per-category
  bucket also capped at 100.

### 3.5 Dedup
- `DEDUP_WINDOW = 300` seconds (config `ingest.dedup_window_s`, default 300, `gt=0`).
- Key = `f"{source_ip}:{signal_type.value}"` (protocol **not** in the key).
- A dedup hit adds **no weight** but IS a fresh sighting: it decays the stored score to now, refreshes
  `last_seen=now`, **unions** the new protocol into `source_protocols`, recomputes
  `distinct_categories`/`tier`, and **recomputes `reportable` via `is_reportable`** (never copies
  `prev.reportable`). Returns `None` (no event appended).
  *(NOTE: the old `scoring-engine.md` step 5 wrongly said a dedup hit performs no decay/no recompute.
  Follow the CODE: decay + recompute on dedup refresh.)*

### 3.6 Feed collateral rule - /32 default + /24 collapse
- Entries are **/32 host routes by default** (`DEFAULT_CIDR_PREFIX = 32`).
- A `/24` collapses to one entry **only when all 256 hosts are independently listed**
  (`feed.cidr_floor` Literal[24,32]; 24 collapses, 32 emits host routes only; floor never crossed
  below /24, `AGGREGATION_FLOOR_PREFIX = 24`). A partially-malicious /24 stays as /32s so aggregation
  never blocks an unlisted address.
- **AGGRESSIVE is always a literal-string SUBSET of STANDARD** - derived from the *capped* standard set,
  not an independent slice, so the subset invariant survives cap truncation and /24 collapse.
- Exclusions (at build AND re-validated at publish): RFC1918 (10/8, 172.16/12, 192.168/16, 127/8) +
  reserved/bogons (CGNAT 100.64/10, link-local 169.254, 240/4, 0/8, multicast 224/4), allowlist CIDRs,
  operator IPs, **any UDP taint**, `top_signal ∈ {syn_flood, port_scan}` (`EXCLUDED_SIGNAL_TYPES`),
  no-tcp-auth, delisted IPs, per-tier expiry. RFC5737 doc ranges (192.0.2/198.51.100/203.0.113) are
  **exempted** so tests/examples publish as stand-in attackers.
- Two size caps: per-tier `feed.max_entries` (default 50000, `Field(gt=0, le=FEED_SIZE_CAP)`) is the
  operative runtime publish gate; absolute ceiling `FEED_SIZE_CAP = 250000`
  (`blocklist/constants.py`) is the CI-asserted limit.
- Tier auto-expiry FROZEN (`TIER_EXPIRY_DAYS`): AGGRESSIVE **90 days**, STANDARD **30 days**, anchored
  on each IP's `last_seen`. Not tunable.

### 3.7 Secrets never in YAML
- Four secret classes reach the process **env-only**:
  1. Vendor keys/ids via `_ENV_SECRET_MAP` (below).
  2. Web session secret via `PROPOLIS_WEB_SESSION_SECRET` (+ runtime `HPINTEL_SESSION_SECRET` fallback).
  3. Web credential via `PROPOLIS_WEB_USERNAME` / `PROPOLIS_WEB_PASSWORD_HASH`.
  4. Feed push token `PROPOLIS_FEED_PUSH_TOKEN` (never an `AppConfig` field).
- The loader **strips** vendor secret fields (`api_key`, `user_id`) from every YAML vendor block
  *before* merge, then re-injects from env. An inlined secret in YAML is **silently discarded**.
- No `${ENV}` interpolation. Env values are `.strip()`ped on injection (both web and vendor - the code
  strips vendor too, to avoid a trailing newline from `KEY=$(cat keyfile)` corrupting an Authorization
  header; the old doc wrongly said vendor values are stored as-is).

### 3.8 Loopback-only bind
- `web.bind` default `127.0.0.1:8000`. **Two guards, config validator fires first**:
  - `WebCfg._reject_wildcard`: rejects `*`, requires a parseable IP literal (so `localhost` fails at
    load), rejects `0.0.0.0`/`::`/unspecified.
  - `web/bind.py assert_loopback_or_lan_bind` (fail-fast, first statement of `build_app`): rejects
    wildcards `{"", "0.0.0.0", "::", "*"}`, requires `is_loopback OR is_private` for IP literals.
  - **Effective contract: a loopback or RFC1918-private IP literal.**
- Plain HTTP by design (SameSite=Strict cookie, `https_only=False`) for loopback/LAN; front with a TLS
  reverse proxy to expose beyond the host.

### 3.9 PII / password drop at parse
- Passwords are **never stored or sanitized** - dropped at parse. Cowrie never reads a password field;
  Heralding reads the CSV password column only to parse the row and discards it; Dionaea scrubs FTP
  `PASS`/`ACCT` args to `[redacted]` (keeps `USER` as an indicator); RedisHoneypot stores only the
  command verb, never args. Enforced downstream by `ScoreRepository._EVIDENCE_KEYS` allowlist
  (`command, username, uri, url, signature, user_agent, rules`) which **excludes** password.
- `dst_ip` (the operator's own WAN VIP) is stored **only** as an aggregate `distinct_dst_count` for
  scanner-breadth scoring - **destination addresses never appear** in any snapshot, feed, vendor
  report, or UI (rendered only as "swept N VIPs").

### 3.10 Privilege separation
- Two OS users (`propolis`, `catchall`), two committed systemd units. The catch-all sensor is
  **secret-free, DB-free, non-root**, holding only `CAP_NET_BIND_SERVICE`. A compromise of the
  internet-facing listener yields no credentials and no database handle.

### 3.11 Single-node / single-operator / IPv4-only boundaries
- One `propolis run` process is the sole composition root and **sole DB-writer process** (SQLite WAL,
  one writer). No HA, no clustering, no multi-writer, no message broker, no multi-host log shipping.
  The feed is IPv4-only. Exactly one operator credential per deployment (no user store/registration).

### 3.12 IP-shape validation (single upstream chokepoint)
- `ipaddress.ip_address()` inside `try/except ValueError` in the scoring engine drops
  garbage/hostnames/spoofed-header tokens **before** scoring/review/report/feed. Fail-closed: unparseable
  → `None`. The feed builder re-validates independently.

### 3.13 Submission gate (`GateKeeper.check`) - exact ordered sequence
The second gate (distinct from `is_reportable`), enforced per-vendor at submission time inside
`ReportDispatcher`. Short-circuits on the FIRST failure; every rejection is `GateResult(allowed=False,
reason=...)`, success is `GateResult(allowed=True, reason=None)`. Order (reproduce verbatim):
1. unknown target (no registered policy) -> `unknown_target` (fail-closed).
2. `_protocol_excluded(snapshot)` -> `protocol_excluded`. True when EITHER `Protocol.UDP in
   source_protocols` (UDP is spoofable, disqualifies regardless of score) OR (no above-0.5 category
   other than `network` AND `has_tcp_auth is False`). A TCP-auth signal keeps an all-network IP eligible.
3. `raw_score < policy.min_score` -> `score_too_low` (STRICT `<`; equal passes).
4. `max_confidence < policy.min_confidence` -> `confidence_too_low` (STRICT `<`; equal passes).
5. `require_categories` non-empty AND none present (present = breakdown keys with weight > 0.5) ->
   `missing_category` (any-of match).
6. `distinct_categories < policy.min_distinct_categories` -> `needs_corroboration`.
7. `cooldowns.on_cooldown(target, ip)` -> `cooldown`.
8. `rate_limits.allow(target, policy.max_per_hour)` False -> `rate_limited`.
- Side-effect ordering matters: cooldown/rate-limit are LAST, so a policy/score/category rejection never
  touches those stores. Check 8 is a check-and-increment: an ALLOWED candidate consumes a `(vendor,hour)`
  slot even if the later submit fails; a rejected one does not.
- `TargetPolicy` fields: `name`, `is_reputation_vendor` (metadata, not read by check), `min_score`,
  `min_confidence`, `require_categories: tuple[str,...]`, `min_distinct_categories`, `cooldown_hours`
  (used only by `commit_cooldown`), `max_per_hour`. Config (VendorCfg) defaults: `min_score=75.0`,
  `min_confidence=0.70`, `require_categories=()`, `min_distinct_categories=1`, `cooldown_hours=24`,
  `max_per_hour=40`.
- Cooldown asymmetry: `check` only READS cooldown; the window is started by a separate
  `commit_cooldown(target, ip)` that `ReportDispatcher` calls ONLY when `submit` returns
  `status == "success"`. A transient failure leaves NO cooldown (retry-eligible next cycle) but the
  rate-limit slot was already consumed at check time.

### 3.14 Review queue - one-open-per-IP + state-guarded transitions
- Open states `PENDING`/`SNOOZED` are decidable; `_TERMINAL_STATES = {APPROVED, REJECTED}` are
  irreversible (re-approving would re-fire vendor reports). `_ensure_open` raises on a terminal item.
- `enqueue`: `find_open_by_ip`; if an open item exists, refresh weight fields only (not
  `ip`/`state`/`created_at`) via `update_if_open` (a state-guarded write that NO-OPs if a web operator
  moved the item terminal between read and write - the background loop never resurrects a decided item to
  PENDING); else `add` a new `PENDING` item (`created_at = snapshot.last_seen`).
- `approve`/`reject`/`snooze`: load -> `_ensure_open` -> `replace(state=...)` -> `update_if_open`. If it
  returns `None` the caller LOST the race to a concurrent decision and raises; the web seam returns 409
  and does NOT dispatch, so only the single winning transition fires reports. Audit is written only after
  the winning write, never on the lost-race path.
- `list_pending`: PENDING plus SNOOZED whose `snoozed_until <= now` (None -> always surface; naive
  datetime coerced to UTC to never raise in render). Weight sort key `(raw_score, max_confidence,
  event_count)` descending.

---

## 4. Architecture & tech stack (and WHY - ADRs + rejected alternatives)

| Choice | Where | Why / ADR | Rejected alternative |
|---|---|---|---|
| **SQLite + WAL** | `persistence/engine.py` | ADR-0001. Single-node, single-writer process; PRAGMAs `foreign_keys=ON` + `busy_timeout=5000` (all conns), `journal_mode=WAL` + `synchronous=NORMAL` (file DBs only, skipped for `:memory:`). `CHECK` constraints enforce domain bounds. Repository behind a `typing.Protocol` seam. | PostgreSQL/network DB daemon - rejected for a single box; portability is *qualified*, NOT a connection-string change (SQLite-specific `on_conflict_do_update`, `json_extract`, partial unique index, PRAGMA listener). `synchronous=NORMAL` accepts loss of not-yet-checkpointed txns on **power loss** (safe against app crashes) - accepted; Propolis is not a system of record. STRICT mode NOT used. |
| **SQLAlchemy Core (not ORM)** | `persistence/models.py` | Domain/application layers are SQLAlchemy-free; only persistence knows SQL. | ORM declarative - the `events.metadata` column would collide with `Table.metadata`. |
| **Alembic (only DDL path)** | `persistence/migrate.py`, `migrations/` | ADR-0002. Additive-only, `render_as_batch=True` for SQLite ALTER, linear chain 0001→0002→0003, each ALTER `_has_column`-guarded (idempotent vs fresh `create_all`). `is_at_head` gate at 3 sites (startup SystemExit, `/readyz` 503, `db migrate --check` exit 0/1). No auto-migrate on startup. **No CI drift gate.** | Backfill-as-migration - rejected; `import-legacy` is a CLI concern (re-runnable, testable), not a migration. |
| **FastAPI (narrow mode)** | `web/app.py` | ADR-0003. `docs_url=None, redoc_url=None` (no OpenAPI), plain `dict` request bodies (not Pydantic models), signed session cookie + per-session CSRF, **synchronous** handlers. | Full OpenAPI/Pydantic web models, bearer/API-key/Basic auth - rejected for a single-operator loopback UI. |
| **HTMX + Jinja** | `web/rendering.py`, `templates/` | ADR-0004. Autoescape on; single `clean_for_html` output-encoding chokepoint (escapes `& < > " '` and **colon → `&#58;`** to neutralize `javascript:`/`data:` schemes). Strict CSP, no JS build pipeline, self-hosted **SRI-pinned** HTMX 1.9.12. | CDN scripts, inline styles/scripts - forbidden by CSP; data-driven presentation resolved to CSS classes (`bar-w-0..100`, `bar-h-0..10`, `sev-*`). |
| **Pydantic config** | `config/models.py` | Frozen (`ConfigDict(frozen=True, extra="forbid")`) whole tree; fail-fast validation, no partial start; secrets `SecretStr`. | `${ENV}` YAML interpolation - rejected; secrets come only through env maps at the trust boundary. |
| **structlog (JSON)** | `observability/logging.py` | Single stdout JSON stream (journald captures); **by-key** secret redaction (13-key set) before serialization; UTC ISO timestamps. | Value-pattern scrubbing - not done; redaction is key-name based (a secret under a non-listed key leaks by design - bind creds only under listed keys). |
| **Prometheus** | `observability/metrics.py` | 5 collectors behind a **closed label enum** (tier/vendor/outcome/component) so no attacker string/IP becomes a label (cardinality + egress defense). `/metrics` only when `metrics_enabled`. | Free-string labels - rejected (CWE-778); `record_submission` raises on out-of-domain labels. |
| **systemd (hardened)** | `deploy/systemd/`, ADR-0005/0006 | Two units, two users, one-directional log flow, web served in-process. Kernel-enforced `NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies=AF_INET AF_INET6`, cap split. | Web as a separate privilege-separated unit - explicitly **not** done in v1 (accepted risk, §6). |
| **GitHub-published feed** | `blocklist/publisher.py`, ADR-0007 | Out-of-band git push + CI validate-only (no DB on runner), branch protection, actions SHA-pinned. Token via `GIT_ASKPASS`, never in argv/`.git/config`. | Pushing from CI with DB access - rejected; the node builds+pushes, CI only validates the committed bytes at `--size-cap 250000`. |
| **Scanner-breadth boost** | `ScoreRepository` (read-time), ADR-0008 | `+0.04` confidence per extra swept VIP, cap `+0.12`, only when `has_tcp_auth`; feeds **tier only**, never `is_reportable`; `dst_ip` stays on box (aggregate count). Frozen constants, no YAML. | Storing/exporting dst addresses - rejected (PII). |

Package is `propolis` 0.1.0, Python >=3.11.

---

## 5. Subsystem-by-subsystem map

**Domain model (`propolis.domain`)** - Dependency-free type vocabulary every subsystem imports and
never redefines. Files: `enums.py` (Protocol, Category, FeedTier, ReviewState), `signals.py`
(`SignalType` 16 members, `SignalWeight` NamedTuple, `SIGNAL_WEIGHTS` table), `events.py` (LogEvent),
`snapshot.py` (ScoreSnapshot), `review.py` (ReviewItem), `results.py` (SubmissionResult, GateResult).
Public: `__all__` of exactly 12 names. All five dataclasses `frozen=True, slots=True`; `LogEvent` and
`ScoreSnapshot` set `__hash__=None` (unhashable - carry mutable dict/frozenset). Owns: enum string
encodings, the 16-entry `SIGNAL_WEIGHTS` completeness invariant, and tz-aware-UTC construction guards
(`__post_init__` raises `ValueError` on naive datetimes). No I/O, no logic.

**Config (`propolis.config`)** - One YAML file + env → frozen `AppConfig`. Files: `models.py`
(`_Frozen` base + `AppConfig` + 13 sub-configs), `loader.py` (`load_config`, `load_yaml_layer`,
`build_env_layer`, `deep_merge`, secret maps). Public: `load_config(path, env) -> AppConfig`. Owns:
secrets-never-in-YAML (strip+reinject), fail-fast validation, `RetentionCfg` cross-field invariant
(`scores_days >= events_days`, else CASCADE-deletes in-window events), frozen scoring/feed thresholds,
loopback bind validator, fail-closed web defaults (`auth=None` → `/login` rejects all;
`session_secret=""` → ephemeral + WARN). `deep_merge` **replaces** lists wholesale (setting
`allowlist.cidrs` drops the RFC1918 defaults - operator must re-list).

**Ingest tailer (`propolis.ingest`)** - Crash-safe bounded tailer. File: `tailer.py`. Public:
`Tailer(offset_store).read_new(source, filepath) -> Iterator[str]`; `OffsetStore` Protocol
(`get -> (offset, inode, fingerprint)`, `set(source, offset, inode, fingerprint='')`). Owns:
rotation/truncation/copytruncate resets (inode-change → size-shrink → head-fingerprint blake2b of first
256B), TOCTOU-safe `os.fstat(fh.fileno())`, at-least-once commit-last-on-clean-read,
`MAX_LINE_BYTES=64KiB`, `MAX_LINES_PER_TICK=10_000`, `_READLINE_CAP = MAX_LINE_BYTES+1`.
*(The 3-tuple cursor + fingerprint feature exists in code but the old docs described a 2-tuple -
follow code; needs a `fingerprint` column.)*

**Sanitize (`propolis.sanitize`)** - Three one-way sink-specific cleaners. File: `cleaners.py`.
`clean_for_log` (ANSI + newline→space **before** control strip + NFC + invisible/bidi/zero-width strip,
cap 2000); `clean_for_html` (cap 2000 then entity-escape 6 chars incl. colon); `clean_for_vendor_comment`
(`clean_for_log` then redact email→`[email]`, IPv6 then IPv4 →`[ip]`, cap 1024). Pure/stateless/total,
never raise. Owns: log-injection, XSS/scheme, and outbound third-party-PII defenses. IPv4 regex anchors
on digit/dot edges (redacts glued/trailing-dot forms); IPv6 handles mixed/mapped forms as one token.

**Parsers (`propolis.parsers`)** - 13-key `PARSER_REGISTRY`, one total `parse(line)->LogEvent|None`
per source. Files: `registry.py` + `cowrie/heralding/adbhoney/dionaea/redishoneypot/catchall/suricata/
modsecurity/nginx/netfilter/filterlog(+pfsense/opnsense wrappers)/wazuh/_syslog`. Owns: never-raise
contract, tz-aware `observed_at`, never-persist-a-secret, source-IP attribution, XFF rejection in nginx
(CWE-348), direction gates in netfilter/filterlog (avoid scoring the local host), non-TCP drop in
dionaea. `filterlog`/`_syslog` are helpers, not registry keys.

**Scoring (`propolis.scoring`)** - Sole write-path scorer. Files: `engine.py` (`ScoringEngine.process`),
`decay.py` (`decay_score`), `gates.py` (`is_reportable`, `tier`). Public: `process(event)->ScoreSnapshot|
None`. Owns: decay-once-on-write (via `get_raw`), SCORE_CAP=100, corroboration + tier gates, the
`has_tcp_auth` sticky latch, dedup semantics, atomic `record()` (upsert `ip_scores` before append
`events`, FK ON DELETE CASCADE). Read-time decay + breadth boost live in `ScoreRepository`, not here.

**Reporting (`propolis.reporting`)** - Approved item → vendor abuse reports. Files: `base.py`
(`VendorAdapter` ABC, retry loop, `DEFAULT_TIMEOUT_S=15.0`, `DEFAULT_MAX_RETRIES=3`), `dispatcher.py`
(emission-seam guards), `registry.py` (4-tier registry), `evidence.py` (PII-free comment + signal
summary), `abuseipdb/dshield/otx/sniffcat.py`, `experimental/*` (inert `DisabledAdapter`). Public:
`ReportDispatcher.dispatch(item, snapshot, evidence) -> dict[str,SubmissionResult]`. Owns: approved-only
(`PermissionError` otherwise), delist + UDP-taint fail-closed skips, cooldown-commit-only-on-success,
CONNECT-only retry idempotency (read/write timeouts terminal - non-idempotent POST may have landed),
audit-every-outcome, category-code derivation, secret redaction in audit bodies.

**Persistence (`propolis.persistence`)** - Durable datastore + GDPR + migrations + `propolis db` CLI.
Files: `engine.py`, `models.py` (11-12 tables), `unit_of_work.py`, `repositories/*` (score/review/audit
/dedup/cooldown/rate_limit/offset + in-memory doubles), `purge.py`, `cli.py`, `import_legacy.py`,
`migrate.py`, `migrations/`. Owns: decay-on-read vs `get_raw` split, breadth boost, `observed_at`
UTC-normalize + future-clamp (protects lexicographic-ISO purge), atomic `record()`, atomic rate-limit
`check_and_increment`, `update_if_open` state-guarded transition, partial-unique one-open-per-IP index,
report-retry producer (`find_approved_unreported` with grace-window / post-approval-success-scoping /
give-up-cap guards), GDPR erase/export/delist, `PurgeService`. Timestamps are TEXT ISO strings
everywhere; booleans are Integer 0/1.

**Web console (`propolis.web`)** - Loopback FastAPI + HTMX/Jinja operator UI; the only web-layer DB
writer. Files: `app.py` (`build_app`, routes, write guard, login DoS backstops), `auth.py`, `passwords.py`
(scrypt), `csrf.py`, `bind.py`, `login_throttle.py`, `security.py` (CSP middleware), `rendering.py`
(`_encoded` chokepoint), `read_model.py`. Owns: 4 layered controls (scrypt verify, signed session cookie,
viewer/reviewer role gate, per-session synchronizer CSRF), login throttle (5/300s) + `BoundedSemaphore(4)`
on scrypt, strict CSP, single HTML output-encoding chokepoint, DB-contention→503, vendor-dispatch bridge
(fires only after durable approve), fail-fast bind + empty-session-secret guards.

**Observability (`propolis.observability`)** - 4 primitives. Files: `logging.py` (by-key redaction, 13
keys, sentinel `***REDACTED***`), `metrics.py` (5 collectors, bounded-label enum), `health.py`
(liveness always ok; readiness = DB-at-Alembic-head dead-man's-switch), `scheduler.py` (`PurgeScheduler`
monotonic run-once-per-interval, gate advanced **before** run to prevent retry storm). One scheduler
class drives all three background jobs.

**Composition root (`propolis.runtime` + `propolis.cli`)** - Sole DI wiring point. Files: `runtime.py`
(`build_runtime -> Runtime`, `run`, 6 port adapters, `AnalysisLoop`, secret resolvers), `cli.py`
(argv[0] dispatch to run/db/feed/web). Owns: 3 shared singletons (Metrics/Engine/SystemClock), 7
repos/stores, gatekeeper policies (enabled ∧ dispatchable vendors only), env-only secret resolution,
4 daemon threads (all polled at `poll_interval_s=5`; schedulers self-rate-limit), fail-fast `is_at_head`
before threads start, poison-line redaction (logs source only, never line text).

**Catch-all sensor (`src/sensors/catchall`)** - Hardened non-root secret-free asyncio honeypot on ~50
TCP/UDP ports. File: `catchall_honeypot.py`. Emits one NDJSON probe line per connection (hard contract
with `parsers/catchall`). Owns: secret-free/DB-free threat model, `CAP_NET_BIND_SERVICE`-only privilege,
bounded payload capture (first 512B hex, `data_len` full), latin-1 banner bytes, UDP-is-log-only
(never answers - no reflection/amplification), bind-failure-non-fatal, `dst_ip` never leaves the box.

---

## 6. Security, privacy & compliance posture

**STRIDE / trust boundaries (5 TBs).** TB1/TB2 (sensor→reporter) is the boundary that carries
weight - a separate hardened OS user (`catchall`) with no DB handle and no secrets, kernel-enforced by
systemd. TB4 (web) is **inside** the reporter process and is **not** privilege-separated in v1 -
defended by session auth + per-session CSRF + loopback/LAN bind + the corroboration gate, **not** by a
separate process or read-only DB role. Explicitly accepted for v1: a compromised reviewer session /
auth-or-CSRF bypass / FastAPI RCE yields queue writes (firing gated vendor reports) AND in-memory API
keys. Host compromise and stolen operator credentials are **out of scope**.

**GDPR / DPIA / RoPA.** Lawful basis Art. 6(1)(f) legitimate interest + Recital 49 (network security).
**All IP addresses treated as personal data** (CJEU *Breyer* + Recital 30). Compliance artifacts
(`docs/compliance/{feed-policy,dpia,ropa,art14-5b-memo}.md`) are all **DRAFT** pending DPO/controller
ratification; the DPIA's dominant unresolved question is whether feed publication is Art. 10
criminal-offence data. `feed-policy.md` doubles as the Art. 13/14 privacy notice (the Art. 14(5)(b)
disproportionate-effort substitute measure). Data-subject rights via CLI: `db export-ip` (Art. 15),
`db delist` (Art. 21 suppression, idempotent `ON CONFLICT(ip) DO UPDATE SET reason`), `db erase`
(Art. 17: delete events/ip_scores/review_item/feed_entry/cooldowns/dedup(`LIKE '{ip}:%'`)/delist rows +
insert fresh suppression; **audit_log deliberately retained** as the lawful record). Retention windows
(LIA-ratified): events 180d, scores 365d, audit 365d; feed AGGRESSIVE 90d / STANDARD 30d. Delist/erase
write the DB only; suppression reaches the feed on the next scheduled build (≤12h) or manual publish -
no per-entry live revocation.

**Data minimization.** Firewall feeds carry IP/CIDR only; machine-readable per-IP feeds add derived
metadata (score, first/last-seen, count, tier, expiry) but **never** attack content (no
usernames/passwords/commands/payloads/geo/WHOIS/ASN). `dst_ip` never leaves the host. Passwords dropped
at parse. Outbound vendor comments redacted (`clean_for_vendor_comment`) and date-only (no colons, so
the IPv6 redactor cannot eat timestamps).

**Fail-closed guards (Section-4-floor, never scaled down).** Locked SQLite → HTTP 503 (never a false
approve); corroboration/tier thresholds are code constants (not config); UDP-anywhere taint at
gatekeeper + feed + emission seam; delist/allowlist/RFC1918 exclusion at feed build **and** publish-time
validate (twice, CI branch-protected); `is_at_head` SystemExit before any thread starts; auth
credential `None` → `/login` rejects all (locked, not open); readiness fail-closed on any DB-check
exception.

**Secret scanning.** `.gitleaks.toml` (`useDefault=true` + custom `public-ipv4-literal` rule over
`config/|deploy/|src/`, allowlisting RFC1918/loopback/CGNAT/RFC5737) fails the build on any routable
public IPv4 in those trees. *(Note: `templates/` is not scanned.)* `secrets` CI job needs
`GITLEAKS_LICENSE`.

**Malicious-fixture test properties** (`tests/fixtures/malicious/*.json`, ~5 fixtures + sanitizer/parser
tests): (1) **log_injection** - CRLF+ANSI in username neutralized by `clean_for_log`. (2) **oversized**
(>100KB input) - bounded by tailer caps and field truncation. (3) **truncated** (invalid JSON) - parser
returns `None`, never raises; offset still advances (poison line skipped). (4) **udp_spoof** (catchall
SNMP UDP) - UDP taint fail-closes at gatekeeper + feed + emission. (5) **xss** (`<script>`/`onerror` in
cowrie command) - `clean_for_html` + Jinja autoescape render inert; `Markup()` prevents double-encoding.
Property-style: every `PARSER_REGISTRY` parser returns `None|LogEvent` and never raises on
adversarial/fixture/truncated input.

---

## 7. Deployment & process model

**Single-process runtime composition.** `propolis run` is the sole composition root and sole
DB-writer process. `build_runtime(config)` wires 3 shared singletons (`Metrics(CollectorRegistry())`,
`Engine(create_engine_for_url(db_url))`, `SystemClock()`), 7 repositories/stores, 6 port adapters, the
scoring path, gatekeeper, `ReportDispatcher` (one `httpx.Client(timeout=10.0)` for process lifetime),
review queue, health registry, 3 `PurgeScheduler`-driven jobs, `AnalysisLoop`, and the FastAPI app
(built last so it receives constructed refs), returning a frozen `Runtime` dataclass (the test seam -
call `tick()` without threads/socket). `run()` stays thin: `configure_logging` → fail-fast
`is_at_head(db_url)` (else `SystemExit` with the migrate remediation) → `build_runtime` → start **4
daemon threads** (`propolis-analysis` @ `poll_interval_s=5`; `propolis-purge` @ `max(poll_interval_s,
3600)`; `propolis-feed-publish` @ `publish_interval_s=43200`/12h; `propolis-report-retry` @
`retry_interval_s=3600`/1h - all polled every 5s, the 3 schedulers self-rate-limit internally) →
`uvicorn.run(app, host=web.bind, port=web.port)`. Each thread body is wrapped in try/except (one bad
pass can't kill it); no explicit signal handler - daemon threads die with the process. **There is NO
`propolis-analysis` or `propolis-web` unit** - everything is one process.

**systemd hardening (both units).** `Type=simple`, `Restart=always`/`RestartSec=10`,
`NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
`ProtectKernelTunables=true`, `ProtectControlGroups=true`, `RestrictAddressFamilies=AF_INET AF_INET6`,
`After=network.target`, `WantedBy=multi-user.target`. **Reporter** (`propolis.service`, user
`propolis`): empty `CapabilityBoundingSet`/`AmbientCapabilities`, `ReadOnlyPaths=/var/log/propolis/
sensors /opt/cowrie /opt/heralding`, `ReadWritePaths=/var/lib/propolis`, must NOT bind `0.0.0.0` and
must NOT grant `CAP_NET_BIND_SERVICE` (unprivileged loopback port). **Not set on either** (open TODO):
`IPAddressDeny`, `PrivateDevices`, `PrivateNetwork`, and no resource limits
(`MemoryMax`/`CPUQuota`/`TasksMax`/`LimitNOFILE`) - egress is firewall-enforced (pfSense default-deny),
`RestrictAddressFamilies` is defense-in-depth only.

**Separate catchall user/unit.** `propolis-sensor-catchall.service`, user `catchall`, non-root,
secret-free, DB-free; `Ambient`+`Bounding = CAP_NET_BIND_SERVICE` (privileged ports without root),
`Environment=CATCHALL_LOG_DIR=/var/log/propolis/sensors`, `ReadWritePaths=/var/log/propolis/sensors`.
Shared sensor-log root: sensor RW, analysis RO - one-directional flow. Secrets injected via an
operator-defined `EnvironmentFile` (canonical: `/etc/propolis/propolis.env` mode 0600, referenced by
drop-in `10-secrets.conf`) - **not shipped in the repo**.

**Env vars.** Vendor secrets: `PROPOLIS_ABUSEIPDB_API_KEY`, `PROPOLIS_DSHIELD_API_KEY`,
`PROPOLIS_DSHIELD_USER_ID`, `PROPOLIS_OTX_API_KEY`, `SNIFFCAT_API_TOKEN` (note: breaks the `PROPOLIS_*`
convention, still maps to `sniffcat.api_key`). Web: `PROPOLIS_WEB_SESSION_SECRET`,
`PROPOLIS_WEB_USERNAME`, `PROPOLIS_WEB_PASSWORD_HASH`. Feed: `PROPOLIS_FEED_PUSH_TOKEN` (read at the
publish call site, never an `AppConfig` field). Legacy `HPINTEL_SESSION_SECRET` consulted only in
`runtime._resolve_session_secret` (not in the loader).

---

## 8. Open questions / risks / sharp edges the rebuild must decide

**Reserved-but-unreachable signals.** `SYN_FLOOD` (25/0.70/NETWORK) and `SSH_BRUTE_FORCE`
(20/0.60/AUTH) have `SIGNAL_WEIGHTS` entries but **no shipped parser emits them**. Keep the weights but
decide: reserved-for-future, emitted out-of-tree, or removable. (`PORT_SCAN` is now reachable via the
Wazuh parser; `REMOTE_AUTH_FAILURE` too - so AUTH is reachable on the write path, but being
non-honeypot it can never set `has_tcp_auth`.)

**`feed_entry` table is never written.** Created, read by export, deleted by purge/erase, but **no code
path inserts into it** - always empty; `FeedWriter.write` records only a `feed_publication` row.
Decide: add the provenance writer (bug) or drop the table (vestigial). Same for
`feed_publication.git_commit` (column exists, never populated).

**Feed exporter count doc mismatch.** The authoritative view (ADR-0007 + c4-component) is **5 exporters
/ 10 tier files** (plain `.txt`, ipset `.ipset`, nft `.nft`, JSON `.json`, STIX `.stix.json`, each over
AGGRESSIVE+STANDARD) + `manifest.json` + `delisted.txt`. System-level views undercount to 3/6. Rebuild
must implement **all five** exporters (including `JsonExporter` per-IP and `StixExporter` STIX 2.1),
not just the three CIDR formats. STIX indicator id = deterministic `uuid5(NAMESPACE, ip)`, spec_version
2.1, labels `['malicious-activity']`.

**Two bind validators disagree** (config-model vs `web/bind.py`). Config validator fires first and
rejects hostnames, so `web/bind.py`'s hostname-acceptance branch is effectively dead. Effective
contract = loopback/private IP literal. Decide the single supported contract.

**`HPINTEL_SESSION_SECRET` legacy fallback.** Present only in runtime, not the loader. Decide: keep for
in-place upgrades or remove as residual debt. (Rename any lingering `HPINTEL_*`/`hpintel` per the
no-cross-project-naming rule - Propolis is the project.)

**Storage-encoding asymmetry.** The **same** category appears as `HONEYPOT` (`events.category`, stored
by `.name`) and `honeypot` (`ip_scores.category_breakdown` keys, stored by `.value`) in one DB.
`review_item.state` stores `.name`, `ip_scores.tier` stores `.name`, `source_protocols` a `.name` CSV.
CHECK constraints enumerate uppercase. The legacy importer normalizes breakdown keys to uppercase
(divergent from the live engine). Preserve exactly which column uses which casing, or unify
deliberately.

**Two approve-label spellings.** Production `ReviewQueue.approve` stamps action `'approve'`; the legacy
`ReviewRepository.approve` helper stamps `'APPROVED'`. The retry producer case-folds and matches both
(`_APPROVE_LABELS`). The rebuild's retry path must match the **production** spelling.

**Double-decay seam.** The engine must read prev via an **un-projected `get_raw`** distinct from the
decay-on-read `get`, both wired to the **same** repository instance. A test double where `get()==get_raw()`
hides this; only a real-engine + real-repo integration test across one half-life catches it.

**Retry-loop tunables.** `RETRY_GRACE_SECONDS = len(DISPATCHABLE_REGISTRY) * DEFAULT_MAX_RETRIES * (3 *
int(DEFAULT_TIMEOUT_S)) + 30` (the `3x` because httpx applies the timeout per phase); v1 = 4×3×45+30 =
570s. `MAX_REPORT_RETRY_ATTEMPTS = 5` before dead-letter. `_FAILED_STATUSES = ('failed','error')`
(`skipped`/`success` excluded). Persistence has a **build-time dependency** on reporting's constants -
changing `DEFAULT_MAX_RETRIES`/`DEFAULT_TIMEOUT_S` silently changes the grace window; keep them in sync.

**AbuseIPDB classification by status, not header.** 200 → success (commits cooldown, even when
`X-RateLimit-Remaining==0`); 429 → skipped (retry-eligible, non-cooldown, not counted toward give-up
cap); other non-200 → failed (counts toward cap). Do not reintroduce the old rate-limit-header heuristic.

**`make migrate` is broken.** A bare `alembic upgrade head` reads `sqlalchemy.url` from `alembic.ini`
which is intentionally unset (`env.py` raises). The supported command is `propolis db migrate --url
<url>` (sets URL programmatically). `propolis-validate-feed` console script exists in code but is
**absent from `pyproject [project.scripts]`** - use in-tree `propolis feed validate` instead.

**Ambiguities the summaries left open:** the canonical public feed repo URL (`feed.publish_repo_url`
default `""`) is undocumented; the authoritative Heralding log path disagrees between
`config.example.yaml` (`/opt/heralding/log/activity.csv`) and `generate_config.sh`
(`/var/log/propolis/sensors/heralding.csv`); Cowrie/Heralding systemd units are **not committed** (only
generated by install scripts, with weaker hardening); the "SLSA provenance" CI step is actually a plain
`sha256sum` over 3 files (not real SLSA); `config.example.yaml` ships 11 of the 13 parser source blocks
(omits `nginx`, `modsecurity`; the registry - not the config - is authoritative). Backup cadence /
off-box destination are undocumented operator decisions. `ipset restore` is additive (needs temp-set +
atomic swap to prune); `nft -f` replaces atomically.

**`SIGNAL_WEIGHTS` - reproduce verbatim** (weight / confidence / category):
`HONEYPOT_CONNECTION 40/0.90/HONEYPOT`, `HONEYPOT_LOGIN_ATTEMPT 50/0.92/HONEYPOT`,
`HONEYPOT_COMMAND_EXEC 60/0.95/HONEYPOT`, `HONEYPOT_MALWARE_UPLOAD 80/0.98/HONEYPOT`,
`HONEYPOT_FILE_DOWNLOAD 70/0.96/HONEYPOT`, `SURICATA_SEV1 30/0.70/IDS`, `SURICATA_SEV2 15/0.50/IDS`,
`SURICATA_SEV3 5/0.30/IDS`, `PORT_SCAN 20/0.60/NETWORK`, `SYN_FLOOD 25/0.70/NETWORK`,
`BLOCKED_CONNECTION 3/0.15/NETWORK`, `WAF_SQLI_XSS 35/0.85/WAF`, `WAF_GENERIC_BLOCK 15/0.50/WAF`,
`SSH_BRUTE_FORCE 20/0.60/AUTH`, `CATCHALL_PROBE 15/0.40/NETWORK`, `REMOTE_AUTH_FAILURE 12/0.40/AUTH`.
Pinned by `tests/unit/domain/test_signal_weights.py`.

---

## 9. Verified feed + deploy specifics (first-hand recovered reads)

### 9.1 Feed build + validate (verified against source)
- Source of truth: `SELECT DISTINCT ip FROM review_item WHERE state='APPROVED'`, each resolved via
  `ScoreRepository.get` (decay-on-read). Kept only if `snapshot is not None and reportable and tier is
  not None`. An approved IP that has since decayed below the gate SILENTLY drops (no explicit removal).
  An IP with no `events` rows is skipped (guards a stale aggregate outliving its purged events: events
  180d < scores 365d).
- Aggregation (`aggregate_cidrs`): `/32` default; a `/24` collapses to one entry ONLY when all 256 hosts
  are present AND none is pinned. 255/256 stays 255 `/32`s; one delist/pin decomposes the whole `/24`
  back to 256 `/32`s. Floor never below `/24`. IPv6 is silently dropped (IPv4-only contract).
- Subset invariant: STANDARD built and capped FIRST, then AGGRESSIVE is DERIVED from the capped standard
  tokens (a `/32` is aggressive iff its host is aggressive; a `/24` iff all 256 are) so aggressive is
  byte-for-byte a subset even after cap truncation and `/24` collapse. Re-asserted at publish.
- Build-time exclusion order (first failure wins): tier None -> `EXCLUDED_SIGNAL_TYPES
  {syn_flood, port_scan}` -> protocol (UDP anywhere OR not has_tcp_auth) -> allowlist (default cidrs
  10/8, 172.16/12, 192.168/16, 127/8) -> delisted -> expired; plus `is_bogon` (`not is_global or
  is_multicast`) with the RFC5737 doc-range exemption (192.0.2/198.51.100/203.0.113).
- Publish-time `validate_feed_dir` (fail-closed, runs BEFORE any git push and in CI): size cap; every
  token must parse as `IPv4Network` (the PII / non-IP / IPv6 guard); reject private nets; reject bogons;
  reject delisted by OVERLAP (a collapsed `/24` containing a delisted host is rejected); assert
  `set(aggressive).issubset(standard)`; per-IP `*.json` backstop must be covered-by-standard.
- Exporters: FIVE (`Plain, Ipset, Nft, Stix, Json`) x two tiers = 10 files + `manifest.json` +
  `delisted.txt` = 12 published files. CIDR exporters: `.txt`/`.ipset`/`.nft`; per-IP: `.json`/`.stix.json`.
  STIX 2.1, `NAMESPACE=8f9d1c2e-6b3a-5e47-9a21-0c7d4e2f1b80`, indicator id `uuid5(NAMESPACE, ip)` (stable
  per IP -> dedupable). manifest carries `sha256_files` over the 10 exporter files.
- Caps: `feed.max_entries` default 50000 (operative runtime gate, sliced on standard once);
  `FEED_SIZE_CAP=250000` (CI ceiling). Expiry anchored on `last_seen`: AGGRESSIVE 90d, STANDARD 30d.
- Publisher: token from `PROPOLIS_FEED_PUSH_TOKEN` only, injected via `GIT_ASKPASS` env (never argv,
  `.git/config`, or error text); https remote carries only the username. Build-only no-op when repo url
  empty OR token None, but validation still runs first. Empty `git status` -> no commit. `feed_entry`
  table is never written (the wired suppression is `delist_registry`); `feed_publication.git_commit` is
  never populated.

### 9.2 Deploy / isolation model (verified) and do-not-repeat notes
- `propolis.service`: `User=propolis`, `ExecStart=/opt/propolis/venv/bin/propolis run --config
  /etc/propolis/config.yaml`; empty `CapabilityBoundingSet`/`AmbientCapabilities`; `ProtectSystem=strict`,
  `NoNewPrivileges`, `RestrictAddressFamilies=AF_INET AF_INET6`; `ReadOnlyPaths` = sensor logs +
  `/opt/cowrie` `/opt/heralding`; `ReadWritePaths=/var/lib/propolis` (sole writable path). NOT set (gaps):
  `IPAddressDeny`, `PrivateNetwork`, `PrivateDevices`, `SystemCallFilter`, resource limits. The
  feed-publish thread writes a relative `./feed` with no `WorkingDirectory` set (needs a writable CWD).
- `propolis-sensor-catchall.service`: `User=catchall`, `ExecStart=... python -m
  sensors.catchall.catchall_honeypot`, Ambient/Bounding = `CAP_NET_BIND_SERVICE` only, writes
  `/var/log/propolis/sensors` only, no DB, no secrets. One-directional log flow enforced by mount, not
  convention.
- Secret injection: nothing baked in. `EnvironmentFile=/etc/propolis/propolis.env` (mode 0600, owner
  propolis), referenced by drop-in `/etc/systemd/system/propolis.service.d/10-secrets.conf`. Feed push
  token read out-of-band, never in `AppConfig`.
- DO-NOT-REPEAT for the native-sensor rebuild: the third-party honeypot install scripts generate units
  with WEAK or NO hardening (Cowrie unit has ZERO hardening; Heralding has an UNBOUNDED capability set;
  Dionaea only partial). The rebuild's first-party sensors MUST carry the committed catch-all unit's
  hardening (`NoNewPrivileges`, `ProtectSystem=strict`, minimal single capability), never the weak
  generated shape.
- Other verified sharp edges: `config.example.yaml` omits `nginx` + `modsecurity` source blocks
  (registry is authoritative); Heralding log path diverges between example and `generate_config.sh`;
  `make migrate` is broken (bare `alembic upgrade head`, no url) - real path is `propolis db migrate
  --url <url>`.
