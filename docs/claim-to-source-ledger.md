<!--
title: Claim-to-source ledger
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Claim-to-source ledger

> **Generated audit artifact.** This ledger was produced during the 2026-08-26
> documentation review against HEAD `2ed77827` and is not maintained with every commit.
> Line numbers and commit IDs in it are that snapshot's; resolve by symbol or test name
> against the current tree. It is review evidence, not reader documentation.

The audit trail behind the documentation. Every material claim the corpus makes -
above all the security and anti-abuse ones, and the six framing corrections that
distinguish what Propolis actually does from what an earlier README implied - is
listed here against the source that proves it: a `file:line` in `crates/`, a
migration, a deploy unit, or a regression test.

## How to read this

- **Source** cites the code, test, migration, or deploy file that carries the
  behavior. Line numbers are from the tree state read 2026-08-26 (HEAD
  `2ed77827`); prefer resolving by the named symbol/test, since line numbers rot on
  the next edit. Off-limits blueprint material (`internal/`, `docs/superpowers/`)
  was never used as a source.
- **Status** is one of:
  - **IMPLEMENTED** - present in code and, where noted, guarded by a named test.
  - **[inferred]** - concluded from the absence of a field/path or from design
    rationale, not from a positive assertion in code (e.g. "no WAN IP reaches a
    vendor report" is proven by reading every adapter payload struct and finding no
    such field).
  - **[planned]** / **PLACEHOLDER** - documented as a pre-production step or residual
    risk, not a shipped control (e.g. the seccomp `SystemCallFilter`).
- Reference pages own the exact values; this ledger cites the source and links the
  canonical owner rather than restating tables. See
  [documentation-policy.md](documentation-policy.md) for the status vocabulary.

---

## 1. The six framing corrections

These are the claims most easily gotten wrong. Each is stated in its corrected form.

| # | Corrected claim | Source | Status |
|---|---|---|---|
| 1 | The platform is **not** egress-free; only each attacker-facing *sensor* crate is, by dependency construction. `Cargo.lock` contains `reqwest` (`Cargo.lock:3203`) and `hyper` (`Cargo.lock:1796`), used by `review`/fetcher/VT/ntfy. | `crates/sensor-ssh/tests/shell_test.rs:364` `sensor_ssh_has_no_http_client_dependency` (bans `reqwest,hyper,ureq,curl,isahc,surf,attohttpc`) | IMPLEMENTED |
| 1 | Five outbound paths exist, **every one opt-in and default OFF**: VirusTotal, vendor abuse submitters, console rDNS, ops-alert ntfy, and the malware fetcher. GeoLite2 enrichment is local file reads, not network. | See §5 (outbound paths) below; GeoLite2 `crates/geoip/src/lib.rs:1-30` | IMPLEMENTED |
| 2 | systemd `SystemCallFilter` is a **PLACEHOLDER** (`@system-service` minus `@privileged @resources`), a broad dev allowlist the unit header says to tighten via `strace` before production - not a shipped hardened filter. | `deploy/propolis.service:176-187`, `deploy/sensor-ssh.service:80-99` | PLACEHOLDER / [planned] |
| 3 | **No in-process TLS.** Console is plain HTTP on a loopback `TcpListener` (`axum::serve`, no rustls). Any TLS is operator-provided (reverse proxy). | `crates/propolis/src/main.rs:413-424`; `crates/console/src/main.rs` bind | [inferred] (operator-provided) |
| 4 | The feed publish / blocklist-sync cron is an **operator setup step** (`deploy/blocklist-sync.sh`, referenced by comment), not wired into any shipped systemd timer/cron in `deploy/`. | `deploy/blocklist-sync.sh:1-13,9`; no timer unit in `deploy/` | IMPLEMENTED (script) / [not-evidenced] (cron wiring) |
| 5 | Crate version is `0.3.0` but the only release **tag is `v0.1.0`**; `CHANGELOG.md` is a single undated `## Unreleased` section and does not mention the V12 console (merged post-tag at `dbf8c053`). | `grep ^version crates/*/Cargo.toml` (all `0.3.0`); `git tag` (only `v0.1.0` -> `e0bfd513`); `CHANGELOG.md:3`; V12 merge `dbf8c053` | IMPLEMENTED |
| 6 | **9 sensor crates cover 12 protocols** (the `cred` sensor serves VNC/MySQL/MSSQL/PostgreSQL/MongoDB). No sensor has a compiled-in default port; ports come from operator env. Console sets **no global CSP** (only `/samples/download` sets `default-src 'none'`) and exposes **30 routes (7 public, 23 session-gated)**. | Sensor crates `Cargo.toml:1-21`; cred modules `crates/sensor-cred/src/{vnc,mysql,mssql,postgresql,mongodb}.rs`; CSP `crates/console/src/routes/samples.rs:156-159`; routes `crates/console/src/routes/mod.rs:33-57` | IMPLEMENTED |

Canonical owners: [overview/maturity-and-status.md](overview/maturity-and-status.md),
[security/outbound-controls.md](security/outbound-controls.md),
[security/residual-risks.md](security/residual-risks.md),
[reference/console-routes.md](reference/console-routes.md).

---

## 2. Never-execute (capture, never run)

Owner: [security/never-execute.md](security/never-execute.md).

| Claim | Source | Status |
|---|---|---|
| No Propolis code spawns a subprocess or execs. Whole-workspace grep for `Command::new`/`process::Command`/`libc::exec`/`.spawn()` over non-test `src` returns zero; the only `std::process` use is `exit(1)`. | `crates/review/src/main.rs:414,422,432` (exit only) | IMPLEMENTED |
| No crate enables tokio's `"process"` feature. | asserted `crates/sensor-cred/tests/integration.rs:485-486` | IMPLEMENTED |
| Per-sensor static-check tests fail the build if any `.rs` gains an exec call (8 tests; ssh test also covers `sensor-framework/src`). | `crates/sensor-ssh/tests/shell_test.rs:121,145-160`; cred `:488`, adb `:356`, ftp `:255`, http `:198`, redis `:270`, smtp `:358`, telnet `:181` | IMPLEMENTED |
| Deployment-layer W^X: every unit sets `MemoryDenyWriteExecute=yes` (correct spelling). | `deploy/sensor-ssh.service:104-112`; asserted `crates/sensor-framework/tests/deploy_test.rs:100-102` | IMPLEMENTED |
| Fake shell's `wget`/`curl` return canned transcripts with zero network I/O; no process-spawn or HTTP client in the crate. | `crates/sensor-framework/src/shell.rs:9-29` | IMPLEMENTED |
| Gap: `sensor-catchall` has no `never_exec_static_check` regression guard (covered only by the whole-workspace grep). | absence in `crates/sensor-catchall/tests/` | [inferred] (coverage gap) |

---

## 3. Input sanitization at event boundaries

Owner: [security/input-handling.md](security/input-handling.md).

| Claim | Source | Status |
|---|---|---|
| `sanitize_value(input, max_len)` is the single shared chokepoint; order is load-bearing: collapse CR/LF/tab/VT/FF runs first, then strip ANSI CSI + C0/C1 + separators + bidi + zero-width + Unicode tag block, then NFC-normalize, then char-boundary-safe truncate. | `crates/sensor-framework/src/sanitize.rs:15-27,42,97,118` | IMPLEMENTED |
| CSI parser is bounded (a truncated escape cannot hang). | `sanitize.rs:79`; test `malformed_csi_does_not_panic_or_hang:265` | IMPLEMENTED |
| Byte-derived fields are hex-encoded ("safe by alphabet"), never decoded text. | `sanitize.rs:33` `to_hex_bounded` | IMPLEMENTED |
| Applied structurally: the capture worker sanitizes `orig_name`; `spool.store` always returns empty `orig_name`, so no sensor can smuggle a filename into an event. | `crates/sensor-framework/src/handoff.rs:202`; `spool.rs:126-128,151-155`; test `orig_name_is_sanitized_before_reaching_the_event handoff.rs:358` | IMPLEMENTED |
| `metadata` column documented "sanitized at capture". | `crates/core-scoring/migrations/0002_event.sql:14` | IMPLEMENTED |

---

## 4. Event hash chain (tamper-evidence)

Owners: [architecture/storage.md](architecture/storage.md),
[reference/database.md](reference/database.md).

| Claim | Source | Status |
|---|---|---|
| SHA-256 chain over a FROZEN canonical byte encoding: 11 fields, fixed order, each variable field `u64`-LE length-prefixed; deliberately not `serde_json` of the whole struct. | `crates/core-scoring/src/hashing.rs:56,69,72-123` | IMPLEMENTED |
| `chain_hash(prev, event) = SHA256(prev.unwrap_or(&[]) || canonical_bytes(event))`; `prev=None` at head. | `hashing.rs:122,131-136` | IMPLEMENTED |
| Enum serialization is pinned to the bare Rust identifier (`"CatchallProbe"`, `"Tcp"`); changing casing would change every chain hash. | `crates/core-scoring/src/domain/enums.rs:5-15,57-64`; tests `enums.rs:174,204` | IMPLEMENTED |
| Golden vector pins the exact 32-byte hash; any field mutation, reorder, or insert breaks linkage forward. | tests `hashing.rs:157,163,171,178,196` | IMPLEMENTED |
| Insert is serialized under `pg_advisory_xact_lock` in one transaction so concurrent inserts cannot fork the chain on the same `prev_hash`. | `crates/core-scoring/src/repository/events.rs:142,151,167-171` | IMPLEMENTED |
| DB trigger `enforce_chain_linkage()` (BEFORE INSERT) rejects a `prev_hash` that does not match the current chain head; head hash still computed application-side. | `crates/core-scoring/migrations/0005_chain_enforcement_trigger.sql:17-27,33-36` | IMPLEMENTED |
| Append-only enforced in prod DB: migration `REVOKE UPDATE, DELETE, TRUNCATE ON event FROM propolis` (skipped for test DBs). | `crates/core-scoring/migrations/0004_harden_event_table.sql:22-27` | IMPLEMENTED |
| `session_id` is nullable and NOT hashed (absent from `canonical_bytes`); pre-existing rows degrade gracefully. | `0007_session_id.sql`; `hashing.rs:105` | IMPLEMENTED |

---

## 5. Outbound-network controls (the five gated paths)

Owners: [security/outbound-controls.md](security/outbound-controls.md),
[reference/integrations.md](reference/integrations.md),
[reference/environment-variables.md](reference/environment-variables.md).

| Path | Gate (default OFF) + fail-closed behavior | Source | Status |
|---|---|---|---|
| VirusTotal | `PROPOLIS_VT_ENABLED && !vt_api_key.is_empty()`; upload gated by `PROPOLIS_VT_UPLOAD` (default false); per-UTC-day cap. | `crates/propolis/src/config.rs:521-522`; `crates/review/src/virustotal.rs:22,102` | IMPLEMENTED |
| Vendor abuse submitters (AbuseIPDB/DShield/OTX) | `PROPOLIS_VENDOR_<NAME>_ENABLED` default false; enabled-but-no-key forced disabled; only operator-**Approved** rows submitted. | `crates/review/src/main.rs:149,150-155`; `crates/review/src/submit.rs:6-20` | IMPLEMENTED |
| Malware fetcher | `PROPOLIS_FETCH_ENABLED` default false; daemon spawns only `if config.fetch_enabled`; refuses to run if `own_ips` empty. | `config.rs:527`; `crates/propolis/src/main.rs:794,828-835` | IMPLEMENTED |
| Console reverse DNS | `PROPOLIS_CONSOLE_RDNS_ENABLED` default disabled; one PTR query, display-only, never a suppression signal. | `crates/console/src/rdns.rs:1-7,34` | IMPLEMENTED |
| Ops-alert ntfy | `enabled` default false; when enabled, `ntfy_url`+`ntfy_topic` become REQUIRED (fail-closed); body sanitized; 30s per-attempt timeout. | `crates/propolis/src/ops_alert/config.rs:10-15`; `dispatch.rs:4,22` | IMPLEMENTED |
| Console/sensors/intake/feed/core-scoring make no outbound requests beyond PostgreSQL (and opt-in rDNS). | evidence 08 §3 roll-up | [inferred] (from per-crate deps + grep) |
| GeoLite2 enrichment is local `.mmdb` file reads, egress-free; disabled when `PROPOLIS_GEOIP_DIR` unset. | `crates/geoip/src/lib.rs:1-30,61-62`; `crates/console/src/main.rs:131-134` | IMPLEMENTED |

### 5a. Fetcher SSRF guard (`vet`, fail-closed at every hop)

| Claim | Source | Status |
|---|---|---|
| Scheme allowlist http/https/tftp; tftp only on the initial fetch, never a redirect. | `crates/review/src/fetcher/guard.rs:159-164`; test `vet_redirect_context_forbids_tftp:365` | IMPLEMENTED |
| `user:pass@host` rejected outright. | `guard.rs:152-157` | IMPLEMENTED |
| DNS-rebinding defense: a mixed public+internal resolve set rejects the whole host. | `guard.rs:189-195`; test `vet_rejects_internal_and_mixed_sets:319` | IMPLEMENTED |
| Connect pins the vetted IP, never re-resolves the host. | `guard.rs:94-101`; `crates/review/src/fetcher/http.rs:114-142` | IMPLEMENTED |
| Forbidden-target check rejects own-host, reserved IPs, `0.0.0.0/8`, CGNAT `100.64/10`, `::`; canonicalizes v4-mapped/6to4/NAT64/Teredo first. | `guard.rs:14-83`; test `base_is_reserved_ip_misses_v4_mapped:279` | IMPLEMENTED |
| tftp forces port 69; explicit non-69 port rejected. | `guard.rs:206-210`; test `:402` | IMPLEMENTED |
| Empty resolve set fails closed. | `guard.rs:185-187`; test `:425` | IMPLEMENTED |
| Byte cap enforced mid-stream (aborts to `TooBig`, never buffers oversized body); certs deliberately not validated because bytes never execute. | `http.rs:73-96,170-176` | IMPLEMENTED |
| Dropper-URL extraction bounded: 64 KiB body scan, max 256 URLs, `$`-unresolved tokens dropped. | `crates/review/src/fetcher/extract.rs:36,42,60-77` | IMPLEMENTED |

---

## 6. Malware custody (sterile spool, human-gated forward)

Owner: [security/malware-custody.md](security/malware-custody.md).

| Claim | Source | Status |
|---|---|---|
| Capture hand-off is off the response path: `mpsc::try_send` never blocks the reply; a full queue drops the job and counts it. | `crates/sensor-framework/src/handoff.rs:125-141` | IMPLEMENTED |
| Exactly one worker drains the queue; a second `start_worker` panics, so `spool.store` is never concurrent. | `handoff.rs:172`; test `start_worker_called_twice_panics:402` | IMPLEMENTED |
| Samples named by SHA-256, never the attacker filename - path traversal structurally impossible. | `crates/sensor-framework/src/spool.rs:134`; test `sha256_naming:328` | IMPLEMENTED |
| `verify()` re-hashes on read, fail-closed on mismatch; hash arg validated as 64-hex before any path join. | `spool.rs:205,216,304`; tests `verify_fails_on_corrupted_body:366`, `verify_rejects_path_traversal_attempt:430` | IMPLEMENTED |
| Per-file cap + global byte budget with atomic check-and-reserve; budget recovered from disk on restart. | `spool.rs:136-141,232,288` | IMPLEMENTED |
| Sample files written `0640`; spool directory required to be a `noexec,nosuid,nodev` mount. | `spool.rs:271-279` (test `file_permissions:386`); unit comment `deploy/sensor-ssh.service:53-59` | IMPLEMENTED (perms) / [not-evidenced] (runtime mount) |
| Forwarded to a vendor only after the operator APPROVES the review-queue entry; never executed at any point. | `crates/review/src/submit.rs:6-20` | IMPLEMENTED |

---

## 7. Credential / password privacy

Owner: [security/sample-and-credential-privacy.md](security/sample-and-credential-privacy.md).

| Claim | Source | Status |
|---|---|---|
| A submitted password is read only far enough to advance the parser, then dropped; never placed in any `SensorEvent` field. | `crates/sensor-ssh/src/auth.rs:1-16,138-146`; test `password_never_in_event auth_test.rs:49` | IMPLEMENTED |
| Every login-capturing sensor drops the password (telnet, ftp, redis, smtp, cred); tests assert absence at serialized-JSON level. | telnet `handler.rs:105-114`, ftp `handler.rs:104-111`, redis `handler.rs:334-348`, smtp `handler.rs:101-131`; cred VNC/MySQL/MSSQL/PG/Mongo handlers | IMPLEMENTED |
| No sensor logs a password value (grep of tracing lines mentioning `password` over ssh/cred `src` returns zero). | evidence 08 §8 | [inferred] (grep-negative) |
| The `SensorEvent` wire type has no password field. | `crates/sensor-wire/src/lib.rs:36-53` | IMPLEMENTED |

---

## 8. WAN attribution is internal-only

Owners: [reference/scoring-and-feed.md](reference/scoring-and-feed.md),
[architecture/trust-boundaries-and-data-flows.md](architecture/trust-boundaries-and-data-flows.md).

| Claim | Source | Status |
|---|---|---|
| `wan_ip` (the honeypot's own ingress address) is carried on events and stored, but never in the public feed - the feed selects only `host(source_ip)` + tier/first_seen/last_seen/categories. | `crates/feed/src/builder.rs:169-172,226`; grep of `crates/feed/src/**` returns zero `wan_ip` | IMPLEMENTED |
| No `VendorReport` (or adapter payload) has a field that could carry a WAN vantage; multi-WAN data feeds only the internal breadth multiplier. | `crates/review/src/vendor/mod.rs:29-35`; `abuseipdb.rs:43-49`, `dshield.rs:103-113`, `otx.rs:38-53` | [inferred] (from absence, all three payloads read) |
| In the console, `wan_ip` appears only in detail/search views behind `require_session`. | `crates/console/src/routes/{detail,search}.rs` | IMPLEMENTED |

---

## 9. SQL injection resistance

Owner: [security/filesystem-and-db-protections.md](security/filesystem-and-db-protections.md).

| Claim | Source | Status |
|---|---|---|
| No SQL string is built with `format!` in non-test src (grep for `format!` containing SELECT/INSERT/UPDATE/DELETE/WHERE returns zero). | evidence 08 §10 | [inferred] (grep-negative over all src) |
| Event insert and advisory lock fully parameterized. | `crates/core-scoring/src/repository/events.rs:151,167-171` | IMPLEMENTED |
| Feed builder, review CLI, and VirusTotal use `$`-placeholders / static SQL. | `feed/src/builder.rs:169-176,226`; `review/src/cli.rs:165-166`; `virustotal.rs:278-280` | IMPLEMENTED |
| Console sort/filter columns chosen from fixed literal matches, not interpolated; search `q` LIKE-metachars escaped. | `crates/console/src/routes/ips.rs:44-53`; `search.rs:100-104,469-522` | IMPLEMENTED |

---

## 10. Console authentication, sessions, CSRF

Owners: [security/authn-authz.md](security/authn-authz.md),
[reference/console-routes.md](reference/console-routes.md).

| Claim | Source | Status |
|---|---|---|
| Operator password hashed with Argon2id at startup, plaintext discarded, hash never written to disk. | `crates/console/src/auth.rs:35-52`; `deploy/console.service:38-41` | IMPLEMENTED |
| Console refuses to start with no password (`MissingPassword`, fail-closed). | `crates/console/src/main.rs:61-63,123-126` | IMPLEMENTED |
| Session cookie value = `{id}.{HMAC-SHA256(id, secret)}`; HMAC verified before store lookup; store in-memory only, cleared on restart. | `auth.rs:78-83,134,138-155,191` | IMPLEMENTED |
| Cookie flags: `HttpOnly` always, `SameSite=Strict` always, `Secure` unless peer is loopback, `Max-Age` = TTL; logout destroys the session server-side. | `crates/console/src/routes/login.rs:111-119,93-105` | IMPLEMENTED |
| `require_session` middleware redirects any unauthenticated protected request to `/login` (302); `/health`,`/ready`,`/metrics`,`/login`,`/logout`,`/assets/fonts` mounted outside the layer. | `auth.rs:262-279`; `routes/mod.rs:33-57` | IMPLEMENTED |
| CSRF: per-session token, constant-time compare via `subtle::ConstantTimeEq`; checked on approve/reject/snooze/delist/delete. | `auth.rs:160-180`; `routes/queue.rs:11-14,379-382` | IMPLEMENTED |
| `POST /login` deliberately has no CSRF check (no pre-auth session to bind); defense is the rate limiter. | `login.rs:6-17` | IMPLEMENTED (documented rationale) |
| Login rate limiter: sliding window default 5 attempts / 60s per source IP, reset on success; map capped 10k prune / 50k reject; keyed on real TCP peer via `ConnectInfo` (fails closed if server not built with `into_make_service_with_connect_info`). | `auth.rs:200-256`; `login.rs:19-26,58-69` | IMPLEMENTED |
| Console binds `127.0.0.1:8080` loopback-only by default. | `crates/console/src/main.rs:35-38`; `crates/propolis/src/config.rs:508-513` | IMPLEMENTED |
| No global CSP; only `/samples/download` sets `default-src 'none'`. Global headers are `X-Frame-Options: DENY` + `X-Content-Type-Options: nosniff`. XSS defense is minijinja auto-escaping. | `routes/mod.rs:59-71`; `routes/samples.rs:156-159`; `templates.rs:3-7` | IMPLEMENTED |
| `/samples/download` serves raw malware as `application/octet-stream` attachment with the hardened CSP; `delete_ip` never touches the append-only `event` ledger. | `routes/samples.rs:147-159`; `routes/queue.rs:435-468` | IMPLEMENTED |

---

## 11. Filesystem and systemd hardening

Owners: [security/filesystem-and-db-protections.md](security/filesystem-and-db-protections.md),
[reference/filesystem-paths.md](reference/filesystem-paths.md),
[security/residual-risks.md](security/residual-risks.md).

| Claim | Source | Status |
|---|---|---|
| Every unit runs as a dedicated unprivileged user, never root, with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6`, and `MemoryDenyWriteExecute=yes` - asserted by test, not just documented. | `deploy/sensor-ssh.service`; `crates/sensor-framework/tests/deploy_test.rs:84,100-102,178,212` | IMPLEMENTED |
| `SystemCallFilter` is a documented PLACEHOLDER; the tight allowlist must be derived empirically before production. | `deploy/sensor-ssh.service:80-99`; `deploy/propolis.service:176-187` | PLACEHOLDER / [planned] |
| Whether the `noexec,nosuid,nodev` spool mounts are actually mounted on the production box - install.sh only PRINTS the fstab guidance. | `deploy/install.sh:172-182` | [not-evidenced] (runtime) |
| `/var/lib/propolis` is root-owned `0755` so an unprivileged sensor cannot swap the host-key dir for a symlink. | `deploy/install.sh:132-137` | IMPLEMENTED |
| install.sh creates `--system --no-create-home --shell /usr/sbin/nologin` users; does NOT start services, create/migrate the DB, or write any `/etc/propolis/*.env`. | `deploy/install.sh:86-101,19-32,232-233` | IMPLEMENTED |
| Secrets live only in per-service `/etc/propolis/*.env` (mode 0600, service-owned); no secret is read from argv. | unit headers e.g. `deploy/console.service:36-37`; `crates/propolis/src/config.rs` env reads | IMPLEMENTED |
| The daemon supervises its own subsystems (panic restart with backoff, `MAX_CONSECUTIVE_PANICS=3`), which is why `propolis.service` uses `Restart=on-failure` not `always`. | `crates/propolis/src/supervisor.rs:16-25`; `deploy/propolis.service:123-124` | IMPLEMENTED |

---

## 12. Scoring, eligibility, and anti-abuse gates

Owner: [reference/scoring-and-feed.md](reference/scoring-and-feed.md) (owns exact
constants); [reference/events-and-signals.md](reference/events-and-signals.md) (owns
weights).

| Claim | Source | Status |
|---|---|---|
| 16 signal types map to fixed `(weight, confidence, category)` via a total match with no default arm; five categories. | `crates/core-scoring/src/domain/weights.rs:11-37`; test `every_signal_type_has_exactly_one_weight_row:44` | IMPLEMENTED |
| Raw score decays with a 6h half-life; non-positive elapsed returns prior unchanged (clock-skew clamp - decay only shrinks). | `crates/core-scoring/src/scoring/constants.rs:5`; `decay.rs:13-20` | IMPLEMENTED |
| `confirmed_real` requires TCP + authenticated + Honeypot; sticky latch, never unset; UDP/ICMP/unauth never latch it. | `crates/core-scoring/src/domain/enums.rs:115-117`; `engine.rs:145-146`; test `confirmed_real_latch_sticks_and_never_unsets:346` | IMPLEMENTED |
| Breadth multiplier counts only vantages with `saw_authenticated_tcp==true`, deduped by /24 (v4) or /64 (v6) - a spoofed source cannot complete an authenticated TCP handshake. | `crates/core-scoring/src/scoring/breadth.rs:29-57,66-69` | IMPLEMENTED |
| Persistence bonus applies to a gate-facing score only, never the stored raw, so the next decay cannot double-count it. | `engine.rs:212-220`; `persistence.rs:21-24` | IMPLEMENTED |
| Tier runs on the GATED raw (base + persistence), not the breadth-multiplied effective score; `max_confidence` is live-decayed and fails closed to 0. | `crates/core-scoring/src/scoring/tier.rs:9-19`; `engine.rs:196-204,222`; test `tier_runs_on_raw_not_effective:48` | IMPLEMENTED |
| Eligibility = `!delisted && has_confirmed_real && event_count>=2`; takes no score input, so decay can never revoke it (sticky until explicit delist). The two-category gate was dropped 2026-08-19 (migration 0006). | `crates/core-scoring/src/scoring/eligibility.rs:1-8`; `crates/core-scoring/migrations/0006_relax_eligibility.sql` | IMPLEMENTED |
| Volume-list path counts only `established_event_count` (completed-TCP events), so a spoofed UDP/ICMP flood cannot volume-list an innocent third party; vendor reporting still gates on confirmed-real. | `engine.rs:152-153,231-236`; tests `a_udp_only_flood_is_not_volume_listed:513`, `a_high_volume_tcp_flood_is_blocklisted:480` | IMPLEMENTED |

---

## 13. Blocklist feed, review queue, vendor submission

Owner: [reference/scoring-and-feed.md](reference/scoring-and-feed.md),
[reference/integrations.md](reference/integrations.md).

| Claim | Source | Status |
|---|---|---|
| Feed membership is decided by RETENTION windows against stored (last-event) fields, not a live-decayed score, so tier cannot slide between builds. | `crates/feed/src/builder.rs:110-128,135-153` | IMPLEMENTED |
| Merit-tiered entries require operator approval (`q.state='approved'`); volume entries auto-publish into retention windows only, never the tier files. | `builder.rs:168-179,225-234` | IMPLEMENTED |
| Exported timestamps coarsened to the hour boundary (anti-deanonymization). | `builder.rs:330-340`; `export/mod.rs:39-41` | IMPLEMENTED |
| One `is_reserved_ip` list guards BOTH outbound paths (feed publish + vendor submit); previously feed-only. | `crates/core-scoring/src/net.rs:1-9,57-59`; `crates/feed/src/exclusion.rs:19-22` | IMPLEMENTED |
| ASN suppression is opt-in and empty by default; an empty allowlist short-circuits before any DB lookup; ASN ownership is RIR-registered, not per-IP spoofable. | `exclusion.rs:8-11,53-61`; `crates/propolis/src/config.rs:498` | IMPLEMENTED |
| Publisher re-validates every entry against exclusions (first violation rejects the whole build), stages + fsyncs + atomic two-rename swap, self-checks the staged `.txt` SHA-256. | `crates/feed/src/publisher.rs:95-101,111-168,278-286` | IMPLEMENTED |
| Review queue: only `recommended_for_vendor && eligible` rows surface as Pending; Rejected/Snoozed persist so they never re-surface; operator decision errors `NotFound`, never a silent no-op. | `crates/review/src/queue.rs:74-91,119-171` | IMPLEMENTED |
| Gatekeeper runs an ordered fail-closed sequence (Reserved -> Disabled -> Stale -> Cooldown -> RateLimit -> ScoreFloor -> CategoryFilter); Reserved is first and not operator-overridable; DB error -> DbError (fail-closed). | `crates/review/src/gatekeeper.rs:85-138,143-165` | IMPLEMENTED |
| Submission idempotency key `{ip}:{vendor}:{UTC-date}`; row claimed `success=false` before the HTTP call, updated after; only an attempted submission writes a row. | `crates/review/src/submit.rs:14-19,257-283,300-305` | IMPLEMENTED |
| Vendor API key lives only on the adapter struct, never on report/response/error, never logged. | `crates/review/src/vendor/mod.rs:60-70` | IMPLEMENTED |
| AbuseIPDB 429 treated as success (duplicate within cooldown); DShield `password` field always empty (honeypot drops passwords); OTX pulses forced public. | `abuseipdb.rs:73-84`; `dshield.rs:132-144`; `otx.rs:61-82` | IMPLEMENTED |
| DShield wire contract is provisional (endpoint 403'd during implementation); less certain than AbuseIPDB/OTX (both verified live 2026-08-19). | `crates/review/src/main.rs:220-236`; `vendor/dshield.rs` header | [inferred] (unverified upstream) |

---

## 14. VirusTotal daily-cap enforcement

Owner: [reference/integrations.md](reference/integrations.md),
[reference/rate-limits-and-budgets.md](reference/rate-limits-and-budgets.md).

| Claim | Source | Status |
|---|---|---|
| One `DailyBudget` owned across all scan cycles caps calls per UTC day (resets on date rollover); a per-cycle counter would reset every cycle and never enforce the cap. | `crates/review/src/virustotal.rs:22-58`; `crates/propolis/src/main.rs:771-774` | IMPLEMENTED |
| Runtime hard-codes `request_delay_ms=15000`, `daily_limit=450`; scans `/var/spool/propolis/{ssh,adb,ftp,catchall,fetched}`; cleans samples >30 days. | `main.rs:751-752,763-769,781` | IMPLEMENTED |

---

## 15. Data model and schema evolution

Owner: [reference/database.md](reference/database.md).

| Claim | Source | Status |
|---|---|---|
| Two migration histories against one physical DB; `review` renames its bookkeeping table to `_sqlx_migrations_review` to avoid version collisions with core-scoring (both number from 0001). | `crates/review/src/lib.rs:25-49` | IMPLEMENTED |
| `event` is append-only with CHECK constraints (32-byte hash, nonempty sensor, confidence in [0,1], weight>=0) added in migration 0004. | `crates/core-scoring/migrations/0004_harden_event_table.sql:11-17` | IMPLEMENTED |
| Schema changes are additive; `SensorEvent.session_id` omitted from JSON when None so older records still deserialize. | `crates/sensor-wire/src/lib.rs:36-53`; test `deserialize_without_session_id:134` | IMPLEMENTED |
| `fetch_attempt.status` value set is documented only in a SQL comment, not a CHECK/enum; free TEXT column. | `crates/review/migrations/0003_fetch_attempt.sql:11` | IMPLEMENTED (as designed) |
| DB does not enforce the signal_type<->category coupling; enforced application-side in `EventInput::validate`. | `crates/core-scoring/src/domain/types.rs:70-74` | [inferred] (app-only enforcement) |

---

## 16. Status and maturity

Owner: [overview/maturity-and-status.md](overview/maturity-and-status.md).

| Claim | Source | Status |
|---|---|---|
| Source-available, one tagged release (`v0.1.0` at `e0bfd513`, 2026-08-02), current tree `0.3.0` untagged; HEAD 180 commits ahead of the tag. | `git tag`; `git rev-list --count v0.1.0..HEAD` = 180 | IMPLEMENTED |
| The V12 operator-console interface (theme system graphite/cream/system/hacker, evidence drawer, self-hosted fonts) merged post-tag at `dbf8c053`; the task brief's `2ed77827` is a later merge that contains it transitively, not the V12 merge. | `crates/console/src/templates/base_head.html:2,44-149`; `drawer_shell.html:1-3`; git history | IMPLEMENTED |
| Fonts are embedded in the binary and served from a fixed 4-name allowlist; the deployed box makes no CDN font request. | `crates/console/src/routes/assets.rs:22-25,34-50` | IMPLEMENTED |
| Test-count claims elsewhere are stale (tag says "770+"; CHANGELOG cites SP-era subtotals). Declared attribute count at HEAD is ~1054-1165 by grep - not a verified green run. | evidence 10/11 grep counts | [inferred] (attribute count, not executed) |
| The "172-test authorized pentest, all findings remediated" claim (README/tag) has no harness in `crates/`. | README.md:81 | [not-evidenced] (outside code) |
| License = PolyForm Noncommercial 1.0.0. | README.md:83-85; LICENSE.md | IMPLEMENTED |

---

## Known coverage gaps in this ledger

- Runtime-only facts that source cannot prove: the tightened seccomp filter, the
  `noexec` spool mounts actually being mounted, and the blocklist-sync crontab are
  all `[not-evidenced]` in the repo (deploy-time / operator responsibilities). See
  [security/residual-risks.md](security/residual-risks.md).
- Absence-based claims ("no `format!` SQL", "no password in logs", "no WAN field on
  any vendor payload") are grep- or read-negative over the source and marked
  `[inferred]`; they are only as strong as the search population, which was the full
  non-test `src` tree in each case.
- `sensor-catchall` lacks a `never_exec_static_check` regression guard; the exec-free
  guarantee for it rests on the whole-workspace grep, not a per-crate test.
