<!--
title: Troubleshooting - console
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Console access

The operator console is an Axum server-rendered web app that binds
**loopback-only by default** (`127.0.0.1:8080`) over plain HTTP - there is no
in-process TLS. Routes and APIs are owned by
[Console routes](../reference/console-routes.md).

## Cannot reach the console

- **Loopback bind** - by default the console only accepts connections from the
  box itself (`PROPOLIS_CONSOLE_BIND` default `127.0.0.1:8080`). From your
  workstation you will get connection-refused. Reach it over an SSH tunnel
  (`ssh -L 8080:127.0.0.1:8080 <box>`) or put an operator-provided reverse proxy
  in front. Changing the bind to a non-loopback address exposes an unauthed
  `/metrics` endpoint and a plain-HTTP login; do not do so without a proxy
  terminating TLS. See [Networking and TLS](../operations/networking-tls.md).
- **Process not serving** - `curl -s localhost:8080/health` on the box should
  return `200 {"status":"ok"}`. If it fails, the console task is not up; check
  the daemon log.

> **Warning.** Binding the console to a public interface serves the login page
> and `/metrics` over unencrypted HTTP and exposes them beyond the host. Keep it
> loopback-only unless a TLS-terminating reverse proxy sits in front.

## Login fails

Login runs three checks in order (`crates/console/src/routes/login.rs:58-83`):

1. **Rate limit** → `429 Too Many Requests`. The limiter is per source IP,
   default **5 attempts / 60 seconds** (`crates/console/src/auth.rs:251-255`). A
   rejected attempt is not itself counted, so failed retries do not extend the
   window; a **successful** login resets it. If you are locked out, wait out the
   60-second window. Values:
   [Rate limits and budgets](../reference/rate-limits-and-budgets.md).
2. **Password** → `401 Unauthorized`. The password comes from
   `PROPOLIS_CONSOLE_PASSWORD`, hashed with Argon2id at startup; the plaintext is
   dropped and only the hash kept in memory. There is no password reset flow - change the env var and restart. An empty/absent password means the console
   refuses to start in the first place (see
   [Startup and config](startup-and-config.md)).
3. **Success** → session cookie set, redirect to `/`.

### Login redirect loop / cookie not sticking

- **`ConnectInfo` requirement** - the server must run with
  `into_make_service_with_connect_info::<SocketAddr>()` or peer-IP extraction
  fails closed on every login (`crates/console/src/main.rs:262`,
  `login.rs:19-26`). This is wired in the shipped binaries; if you run a custom
  harness that omits it, every login fails.
- **`Secure` cookie over plain HTTP** - the session cookie is set `Secure` unless
  the client is loopback (`login.rs:115`). If you reach the console through a
  proxy that presents as a non-loopback client but serves plain HTTP to the
  browser, the browser drops the `Secure` cookie and you bounce back to
  `/login`. Terminate TLS at the proxy (so the browser sees HTTPS), or reach the
  console via a loopback tunnel.
- **`SameSite=Strict`** - the cookie is `SameSite=Strict`; a cross-site
  navigation into the console will not send it. Navigate directly.

## Logged out after every restart

Expected. Sessions live in an in-memory `HashMap` with **no session table**;
every session is lost on restart by design
(`crates/console/src/auth.rs:87-91`). Likewise, if
`PROPOLIS_CONSOLE_SESSION_SECRET` is unset a fresh signing key is generated each
start, invalidating any surviving cookies. Set a fixed 64-hex-char secret only if
you want the signing key stable across restarts - sessions themselves still do
not survive one. Default TTL is 24h.

## "invalid or missing csrf token" (403)

The queue mutation actions (approve/reject/snooze/delist/delete) require a
per-session CSRF token; a missing or wrong token returns `403 Forbidden`
(`crates/console/src/routes/queue.rs:379-382`). Causes:

- The page was loaded before a restart and its embedded token no longer matches
  any session. Reload the page to get a fresh token, then retry.
- A custom client is POSTing without the `csrf_token` form field. The token is
  surfaced to templates and embedded as `<meta name="csrf-token">`.

`POST /integrity/verify` and the `/samples` routes are session-gated but have
**no** CSRF check - `integrity/verify` is a read-only chain verification with no
state mutation, so a 403 there is not expected.

## Fonts or styling look wrong

Fonts are **self-hosted**: four faces are embedded in the console binary and
served from `/assets/fonts/{file}` against a fixed allowlist; the deployed box
makes no third-party/CDN font request (`crates/console/src/routes/assets.rs`).
Chart.js and htmx are likewise vendored and self-hosted. If styling breaks:

- **A reverse proxy stripping or misrouting `/assets/fonts/*`** - that route is
  public (so the pre-auth login page can load fonts). Ensure the proxy passes it
  through un-rewritten. An unknown font name returns 404 by design (allowlist).
- **No global Content-Security-Policy** - the console sets only `X-Frame-Options:
  DENY` and `X-Content-Type-Options: nosniff` globally; the only route emitting a
  CSP is `/samples/download`. So a broken page is not a CSP blocking assets - look at the proxy or the network path instead.

## Pages show empty states

Empty panels are usually "no data yet", not an error:

- **No events captured** - dashboard, attackers, and search are empty until
  sensors capture and the daemon ingests. Confirm capture first (see
  [Sensors and networking](sensors-and-networking.md)).
- **Feed tab empty** - the feed page reads back published files from
  `PROPOLIS_FEED_OUTPUT_DIR`; a missing/malformed `manifest.json` renders an
  empty state rather than erroring, and `feed_disabled` shows when no output dir
  is set. See [Integrations and feed](integrations-and-feed.md).
- **Dashboard supplementary cards blank** - three supplementary cards
  (`events_last_hour`, `feed_entries`, `top_attacker`) soft-fail to placeholders,
  while the three core cards hard-fail; a blank supplementary card means that one
  query failed but the page still renders (`crates/console/src/routes/dashboard.rs`).
- **A source never enters the review queue** - it never became eligible; see
  [Queue and spool](queue-and-spool.md).
