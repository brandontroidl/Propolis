<!--
title: Attack surfaces
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Attack surfaces

Every boundary where untrusted or externally reachable data enters or leaves Propolis,
what it exposes, and the control that contains it. Exact values (ports, routes, env
defaults, tables) live in the reference pages this page links to.

For the trust model behind these boundaries see [threat-model.md](threat-model.md).

## Summary

| Surface | Direction | Reachable by | Primary controls |
|---|---|---|---|
| Sensor listeners | inbound | internet attacker | never-execute, boundary sanitization, no HTTP client in sensor closure |
| Malware fetcher | outbound | attacker-chosen URL (opt-in) | SSRF vetter, forbidden-egress guard, default off |
| Console (HTTP) | inbound | operator (loopback default) | Argon2id auth, session/CSRF gate, security headers |
| Database | internal | intake/scoring/console | parameterized SQL only, dedicated backend |
| Quarantine spool | internal file store | worker writes, console reads | SHA-256 naming, `0640`, `noexec` mount, byte budget |
| Feed publish | outbound (files) | anyone consuming the public feed | field selection excludes internal fields; operator-run sync |
| Enrichment / reporting egress | outbound | operator-configured services | all opt-in, default off, fail-closed |

## Sensor listeners

The attacker-facing surface: **9 sensor crates covering 12 protocols** (the `cred`
sensor serves VNC / MySQL / MSSQL / PostgreSQL / MongoDB). Sensors have **no compiled-in
default port** - ports come from the config/env the deploy units set; see
[../reference/ports-and-protocols.md](../reference/ports-and-protocols.md) and
[../reference/sensor-behavior.md](../reference/sensor-behavior.md).

Exposes: raw attacker-chosen bytes on each protocol - banners, commands, credentials,
uploaded sample bytes.

Controls:

- **Never-execute.** No sensor spawns a subprocess or execs; the honeypot captures, it
  never runs what it captures. Enforced by per-sensor static-check regression tests and
  deployment W^X. See [never-execute.md](never-execute.md).
- **Boundary sanitization.** Every attacker-controlled string passes through
  `sanitize_value` before entering an event record (CR/LF, ANSI, bidi, zero-width, length
  cap). See [input-handling.md](input-handling.md).
- **No HTTP client in the sensor dependency closure** (sensors are egress-free by
  construction). Note the per-crate dependency assertion is enforced by test only for
  `sensor-ssh`; the workspace lockfile does contain HTTP clients used by the non-sensor
  paths below. See [never-execute.md](never-execute.md) and
  [outbound-controls.md](outbound-controls.md).
- **Credential privacy.** A submitted password is read only far enough to advance the
  parser, then dropped; it is never placed in any event field. See
  [sample-and-credential-privacy.md](sample-and-credential-privacy.md).

## Malware fetcher (attacker-directed outbound)

The one path that fetches an **attacker-supplied URL**. It is opt-in
(`PROPOLIS_FETCH_ENABLED`, default off) and the daemon only spawns it when enabled.

Exposes: an SSRF / internal-scan risk - an attacker who gets the box to fetch a URL of
their choosing.

Control: a fail-closed URL vetter run on the initial URL **and every redirect hop** - scheme allowlist (http/https/tftp), `user:pass@host` rejected, DNS-rebinding defense
(a mixed public+internal resolve set rejects the whole host), the connect address pinned
to the vetted IP (never re-resolved), and a forbidden-target check rejecting own-host and
reserved IP ranges (with IPv6 canonicalization first). See
[outbound-controls.md](outbound-controls.md).

## Console (HTTP)

Axum + minijinja server-rendered HTML. **30 routes: 7 public, 23 session-gated**
(canonical table: [../reference/console-routes.md](../reference/console-routes.md)).
Default bind is loopback-only (`127.0.0.1:8080`); the operator opts into a wider bind.

Exposes: the public group - `/health`, `/ready`, `/metrics`, `/login` (GET+POST),
`/logout`, `/assets/fonts/{file}` - reachable without a session. Everything else is behind
the session gate. `/metrics` is Prometheus text and is public because Prometheus cannot
log in; that is acceptable *because* the default bind is loopback.

Controls:

- **Authentication and session/CSRF boundary** - Argon2id password, HMAC-tagged session
  cookie, per-session CSRF on mutating routes, login rate limiting. See
  [authn-authz.md](authn-authz.md).
- **Security headers on every response:** `X-Frame-Options: DENY` and
  `X-Content-Type-Options: nosniff`. There is **no global Content-Security-Policy**; the
  only route that sets a CSP is `/samples/download/{sha256}`
  (`default-src 'none'`, served `application/octet-stream` as an attachment). XSS defense
  is minijinja auto-escaping (`.html` templates) plus `nosniff`/`DENY` plus that hardened
  download path, not a CSP.
- **Path/traversal-safe route params.** Font names match a fixed four-name allowlist;
  sample downloads validate a 64-hex SHA-256; feed downloads validate the tier as a shape
  check that admits no `.`/`/`/`\`. See [../reference/console-routes.md](../reference/console-routes.md).
- **External-lookup links** on the detail page are followed by the *operator's* browser;
  the box never leaks a captured IP to a third-party lookup service.

> No in-process TLS. The console listener is plain HTTP; TLS, if any, is operator-provided
> (e.g. a reverse proxy) `[inferred]`. See
> [../operations/networking-tls.md](../operations/networking-tls.md).

## Database

Internal surface. All writes are parameterized - no SQL string is built with `format!` in
non-test source; the event insert and all query paths bind values, never interpolate. See
[input-handling.md](input-handling.md) and, for tables/enums, [../reference/database.md](../reference/database.md).

## Quarantine spool

Internal file store for captured samples. Files are **named by their SHA-256** (never the
attacker's filename), written `0640`, size-capped per file and under a global byte budget,
and `verify()` re-hashes on read and fails closed on mismatch. The spool directory is
required to be a `noexec,nosuid,nodev` mount (deployment concern). See
[malware-custody.md](malware-custody.md) and [filesystem-and-db-protections.md](filesystem-and-db-protections.md).

## Feed publish

The public blocklist feed is the outward-facing data product. It selects only attacker
`source_ip` plus tier / first-seen / last-seen / categories; it carries **zero** references
to the honeypot's own `wan_ip` (internal-only) - verified across every feed export path.
See [sample-and-credential-privacy.md](sample-and-credential-privacy.md) and
[../reference/scoring-and-feed.md](../reference/scoring-and-feed.md).

The feed publish / blocklist-sync cron is an **operator setup step**
(`deploy/blocklist-sync.sh`, referenced by comment), **not** wired into any shipped
systemd timer or cron unit. See [../operations/deployment-models.md](../operations/deployment-models.md).

## Enrichment and reporting egress

Five platform-level outbound paths - VirusTotal, vendor abuse submitters
(AbuseIPDB / DShield / OTX), console forward-confirmed rDNS, offline GeoLite2 (local file
reads, **not** network), and ops-alert ntfy. **Every one is opt-in and defaults off**;
several fail closed if their credential or topic is missing, and vendor submission only
ever sends operator-**approved** review-queue rows. Full list, gating flags, and the
forbidden-egress guard: [outbound-controls.md](outbound-controls.md) and
[../reference/integrations.md](../reference/integrations.md).
