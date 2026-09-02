<!--
title: Console architecture
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Console architecture

The operator console (`crates/console`) is a server-rendered web application: an
[axum](https://github.com/tokio-rs/axum) HTTP service that renders HTML with
[minijinja](https://github.com/mitsuhiko/minijinja), swaps page fragments with
[htmx](https://htmx.org/), and draws charts with a self-hosted Chart.js. It reads
PostgreSQL through `sqlx` and issues **no other outbound requests** beyond the
database (and one opt-in reverse-DNS lookup, default off - see
[trust boundaries](./trust-boundaries-and-data-flows.md)).

The full route table, request/response shapes, and per-route auth are owned by
[reference/console-routes.md](../reference/console-routes.md); env vars and their
defaults by [reference/environment-variables.md](../reference/environment-variables.md).
This page describes the architecture, not the exact values.

## Composition

Two binaries construct the same `AppState`: the standalone `console` binary
(`crates/console/src/main.rs`) and the unified `propolis` daemon
(`propolis::run_console`, `crates/console/src/lib.rs:56-58`). The standalone
`main.rs` is the fully verified construction path; the unified daemon wires the
same router.

`router(state)` (`routes/mod.rs:33-57`) builds two route groups:

- **Public group** - `health`, `ready`, `metrics`, `login`, `logout`, and the
  fonts asset route, mounted **outside** the session layer.
- **Protected group** - everything else (dashboard, queue, IP detail, feed,
  search, IPs, integrity, samples, logs), wrapped with a
  `require_session` middleware via `.route_layer(...)` so every route in it is
  session-gated.

There are **30 routes: 7 public, 23 session-gated**. See
[reference/console-routes.md](../reference/console-routes.md) for the table.

## No in-process TLS

The console serves **plain HTTP** on a loopback `TcpListener` via `axum::serve`.
There is **no built-in TLS** (no `rustls` in the console's serving path). Any TLS
termination is operator-provided in front of the console (for example, a reverse
proxy) and is **[inferred]** - the console itself never negotiates TLS. The default
bind is loopback-only; see
[reference/ports-and-protocols.md](../reference/ports-and-protocols.md) and
[operations/networking-tls.md](../operations/networking-tls.md).

The binary MUST serve with `into_make_service_with_connect_info::<SocketAddr>()`
(`main.rs:262`), because the login rate limiter keys on the real TCP peer via
`ConnectInfo`; without it, `ConnectInfo` extraction fails closed on every login.

## Session, CSRF, and login

Full detail is owned by [security/authn-authz.md](../security/authn-authz.md); the
architecture in brief:

- **Password** - the operator password is hashed with **Argon2id** at startup and
  the plaintext dropped; only the PHC hash is held in memory, never written to disk
  or the database. The console **refuses to start** with no `PROPOLIS_CONSOLE_PASSWORD`
  (fail-closed).
- **Session cookie** - value is `{session_id}.{HMAC-SHA256(session_id, secret)}`;
  `validate` verifies the HMAC tag *before* any store lookup. The store is an
  in-memory `RwLock<HashMap>` - **no session table**, so every session is lost on
  restart, by design. Cookie flags: `HttpOnly` and `SameSite=Strict` always;
  `Secure` unless the peer is loopback; `Max-Age` tracks the store TTL.
- **CSRF** - a per-session token, generated on first use and reused, compared in
  constant time (`subtle::ConstantTimeEq`), surfaced to templates as a
  `<meta name="csrf-token">`. It gates the mutating queue actions
  (approve/reject/snooze/delist/delete). `POST /login` deliberately carries **no
  CSRF check** (no pre-auth session to bind a token to; the rate limiter is its
  defense), and `POST /integrity/verify` carries none because it is a read-only
  chain verification with no state mutation.
- **Login rate limiting** - sliding-window per source IP with memory-bound caps.

## Security headers

`security_headers` middleware is applied globally (`routes/mod.rs:55`) and sets two
headers on **every** response, public and protected alike:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`

**There is no global Content-Security-Policy.** The only route that emits a CSP is
`GET /samples/download/{sha256}`, which serves the raw malware sample as an
`application/octet-stream` attachment under `Content-Security-Policy: default-src
'none'` plus its own `nosniff`. XSS defense for the HTML pages is therefore
minijinja auto-escaping (below) plus `nosniff`/`DENY` and the hardened download
path - **not a CSP**.

## Templates and fragments

- All templates are embedded in the binary via `include_str!` (`templates.rs`);
  there is no runtime template directory. The environment is built once at startup
  and shared behind an `Arc`.
- **Auto-escaping** is minijinja's XSS guarantee: any template whose registered name
  ends in `.html` auto-escapes every `{{ }}` value unless it opts out with `|safe`.
  `|safe` is used deliberately only for `serde_json`-serialized Chart.js data arrays
  injected into inline `<script>` blocks.
- `base.html` is assembled at **compile time** from five pieces via
  `concat!(include_str!(..))`: the head, the vendored Chart.js UMD bundle, chart
  defaults, the vendored htmx bundle, and the tail. Both JS libraries are unmodified
  upstream, **self-hosted, no CDN at runtime**.
- **HTMX fragment model** - several routes return partials rather than full pages:
  the dashboard and IP-detail charts, the IP-detail event timeline (keyset
  pagination), the queue-row partials after an action, and search "load more". A
  request carrying `HX-Request` receives the fragment; the same handler renders the
  full page otherwise. IP detail additionally renders into a `drawer_shell.html`
  layout when `?drawer=1` and `HX-Request` are both present (the **evidence drawer**).
- **Logs** stream over Server-Sent Events (`/logs/stream`, `text/event-stream`) from
  an in-memory ring buffer; a lagged receiver is skipped, not fatal.

## Theme system (V12) and fonts

The V12 operator-console interface - the theme system, evidence drawer, and
self-hosted fonts - merged **after** the `v0.1.0` tag (at commit `dbf8c053`); it is
present in the current `0.3.0` tree but not in any tagged release, and `CHANGELOG.md`
does not yet mention it (see
[overview/maturity-and-status.md](../overview/maturity-and-status.md)).

- **Four themes**, driven by CSS custom properties and switched via
  `<html data-theme=...>`: **graphite** (dark, the designed default), **cream**
  (light), **system** (follows the OS - light by default, graphite under a dark OS),
  and **hacker** (a green-phosphor mono theme). The server default is `graphite`,
  whose palette sits on bare `:root` so a no-JS page still renders it.
- **Persistence** - the selected theme is stored in `localStorage` under
  `propolis-theme`; a tiny pre-paint inline script applies it before first paint to
  avoid a flash, guarded in try/catch for private-mode throws. The top-nav
  `<select>` syncs, persists, and re-colors the charts on change.
- **Top navigation** is server-rendered: wordmark, main nav (Dashboard, Review with
  a pending badge, Attackers, Feed, Search, an Operations dropdown to
  Logs/Samples/Integrity), a quick-search form, the theme selector, uptime, version,
  and Sign out. An `active_nav` context variable drives the active/`aria-current`
  state.
- **Fonts** are embedded in the binary and served from a public `/assets/fonts/{file}`
  route against a fixed four-name allowlist (unknown name → 404; no filesystem path is
  built, so no traversal). The deployed box makes **no third-party or CDN font
  request**; the login page is public specifically so it can load the same fonts and
  theme pre-auth.

## Health, readiness, and metrics

`/health`, `/ready`, and `/metrics` are public (Prometheus cannot log in), which is
acceptable because the console binds loopback-only by default. `/health` is a
liveness-only constant `200`; `/ready` pings `SELECT 1` and returns `200`/`503`
fail-closed; `/metrics` derives Prometheus gauges and counters from live DB queries
per scrape. See [operations/health-and-observability.md](../operations/health-and-observability.md).

## Related

- [reference/console-routes.md](../reference/console-routes.md) - every route and API.
- [architecture/storage.md](./storage.md) - the database this console reads.
- [architecture/trust-boundaries-and-data-flows.md](./trust-boundaries-and-data-flows.md) - where the console sits in the trust model.
- [security/authn-authz.md](../security/authn-authz.md) - full auth model.
