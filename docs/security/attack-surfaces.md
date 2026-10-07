<!--
title: Attack surfaces
audience: security
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-06
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

The attacker-facing surface: **11 sensor crates covering 14 protocols** (the `cred`
sensor serves VNC / MySQL / MSSQL / PostgreSQL / MongoDB). Sensors have **no compiled-in
default port** - ports come from the config/env the deploy units set; see
[../reference/ports-and-protocols.md](../reference/ports-and-protocols.md) and
[../reference/sensor-behavior.md](../reference/sensor-behavior.md).

Exposes: raw attacker-chosen bytes on each protocol - banners, commands, credentials,
uploaded sample bytes.

`sensor-http` can also expose an implicit-TLS HTTPS listener (conventionally 443). It exists only
when `PROPOLIS_HTTP_TLS_BIND` is set, so an operator who sets only the cert and key opens no new
port. It adds a TLS handshake to the reachable surface: a failed or stalled handshake is cut at the
read timeout and recorded nowhere but a debug log, no client certificate is requested, and the
certificate is the deploy-minted self-signed one whose only name is `localhost`. A half-configured
or unusable cert and key pair makes the sensor refuse to start rather than serve plaintext. See
[../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).

`sensor-redis` can likewise expose an implicit-TLS listener (conventionally 6380, `rediss://`). It
exists only when `PROPOLIS_REDIS_TLS_BIND` is set, so cert and key alone open no new port. The
surface and its limits match the HTTPS listener: a handshake that fails or stalls is cut at the
read timeout and logged only at debug level, no client certificate is requested, there is no
STARTTLS, and the certificate is the deploy-minted self-signed one named `localhost`. The AUTH
password is never captured over TLS, as on the plain listener. A half-configured or unusable pair
makes the sensor refuse to start rather than serve plaintext.

`sensor-mqtt` can also expose an implicit-TLS listener (conventionally 8883, MQTTS). It exists only
when `PROPOLIS_MQTT_TLS_BIND` is set, so cert and key alone open no new port. The surface and its
limits match the HTTPS listener: a handshake that fails or stalls is cut at the read timeout and
logged only at debug level, no client certificate is requested, there is no STARTTLS, and the
certificate is the deploy-minted self-signed one named `localhost`. The MQTT password is never
captured over TLS, as on the plain listener. Binary PUBLISH payloads sent over TLS are quarantined
by the same hand-off, byte budget and shutdown drain as the plain listener, and never run. A
half-configured or unusable pair makes the sensor refuse to start rather than serve plaintext.

`sensor-smtp` can expose up to two more ports and a protocol upgrade. An implicit-TLS listener
(conventionally 465, SMTPS) and a submission listener (conventionally 587, plain with STARTTLS)
each exist only when `PROPOLIS_SMTP_TLS_BIND` or `PROPOLIS_SMTP_SUBMISSION_BIND` is set, so cert
and key alone open no new port. They do enable STARTTLS on the plain listeners (25, and 587 when
set), which adds a handshake to those sessions: a failed or stalled handshake ends the session,
and the same limits as the HTTPS listener apply (no client certificate, a deploy-minted
self-signed certificate named `localhost`, handshake failures logged only at debug level). The
STARTTLS upgrade refuses plaintext pipelined behind the command (the injection class of
CVE-2011-0411): the bytes are counted in one `honeypot_command_exec` event, never captured or
interpreted, and the connection is closed with a `554` before any handshake begins. Session state
is reset after the upgrade. AUTH passwords are never captured over TLS, as on the plain
listener. A half-configured or unusable pair makes the sensor refuse to start rather than serve
plaintext. See
[../operations/networking-tls.md](../operations/networking-tls.md#live-smtps-and-starttls-on-sensor-smtp).

`sensor-ftp` can expose one more port and a protocol upgrade. An implicit-TLS listener
(conventionally 990, FTPS) exists only when `PROPOLIS_FTP_TLS_BIND` is set, so cert and key alone
open no new port. They do enable AUTH TLS on the plain listener (21), which adds a handshake to
those sessions: a failed or stalled handshake ends the session, and the same limits as the HTTPS
listener apply (no client certificate, a deploy-minted self-signed certificate named `localhost`,
handshake failures logged only at debug level). The AUTH TLS upgrade refuses plaintext pipelined
behind the command (the injection class of CVE-2011-0411): the bytes are counted in one
`honeypot_command_exec` event, never captured or interpreted, and the connection is closed with a
`504` before any handshake begins. Session state, including login, is reset after the upgrade.
After `PROT P` a passive data connection also carries a TLS handshake, but only once its source IP
matched the control connection, and uploads over it are quarantined by the same hand-off, byte
budget and shutdown drain as plaintext uploads, and never run. Passwords are never captured over
TLS, as on the plain listener. A half-configured or unusable pair makes the sensor refuse to
start rather than serve plaintext. See
[../operations/networking-tls.md](../operations/networking-tls.md#live-ftps-and-auth-tls-on-sensor-ftp).

`sensor-cred` opens no new port for TLS: with `PROPOLIS_CRED_TLS_CERT` and
`PROPOLIS_CRED_TLS_KEY` set, the existing PostgreSQL, MySQL, MSSQL and MongoDB ports also accept a
TLS handshake, in-band after an SSLRequest, a `CLIENT_SSL` SSLRequest or a PRELOGIN asking for
encryption, or on MongoDB when the first two bytes are a TLS record header. Each handshake is cut
at the read timeout, no client certificate is requested, the certificate is the deploy-minted
self-signed one named `localhost`, and a failed handshake ends the session with no plaintext
fallback. PostgreSQL and MySQL read the pre-upgrade request with exact-length reads and no
user-space buffer, so plaintext sent behind the request reaches the handshake as garbage and is
never read as protocol (the CVE-2021-23222 shape). The MSSQL handshake runs inside TDS packets
through a sensor-specific framing adapter (`crates/sensor-cred/src/tds_tls.rs`), which is parser
code reachable by any client that offers encryption; it buffers at most one 8-byte TDS header in
fixed-size storage, passes payload bytes straight to rustls, and frames each handshake write as one
TDS packet of at most 4096 bytes. Plaintext clients are still served on every port, including
an MSSQL client that offers `ENCRYPT_OFF`. Passwords, DES and MD5 responses are never captured over
TLS, as in plaintext. A half-configured or unusable pair makes the sensor refuse to start rather
than serve plaintext. See
[../operations/networking-tls.md](../operations/networking-tls.md#live-in-band-tls-on-sensor-cred).

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

Axum + minijinja server-rendered HTML. **34 routes: 8 public, 26 session-gated**
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
  `X-Content-Type-Options: nosniff`, and a Content-Security-Policy allowing script, style,
  fonts and requests from this origin only, with nothing inline (no template carries inline
  script, style or handlers). `/samples/download/{sha256}` keeps a stricter
  `default-src 'none'` (served `application/octet-stream` as an attachment). XSS defense
  is minijinja auto-escaping (`.html` templates); the policy is the second line.
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
