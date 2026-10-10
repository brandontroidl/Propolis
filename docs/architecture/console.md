<!--
title: Console architecture
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-10
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
(`propolis::run_console`, `crates/propolis/src/main.rs#run_console`). The standalone
`main.rs` is the fully verified construction path; the unified daemon wires the
same router.

`router(state)` (`crates/console/src/routes/mod.rs#router`) builds two route groups:

- **Public group** - `health`, `ready`, `metrics`, `login`, `logout`, and the two
  asset routes (`/assets/fonts/{file}`, `/assets/{file}`), mounted **outside** the
  session layer.
- **Protected group** - everything else (dashboard, queue, IP detail, feed, fleet,
  search, IPs, integrity, samples, logs), wrapped with a
  `require_session` middleware via `.route_layer(...)` so every route in it is
  session-gated.

There are **39 routes: 8 public, 31 session-gated**. See
[reference/console-routes.md](../reference/console-routes.md) for the table.

## No in-process TLS

The console serves **plain HTTP/1.1** on a loopback `TcpListener` via
`console::server::serve` (hyper's HTTP/1 connection builder driven by the console's own
accept loop). There is **no built-in TLS** (no `rustls` in the console's serving path). Any TLS
termination is operator-provided in front of the console (for example, a reverse
proxy) and is **[inferred]** - the console itself never negotiates TLS. The default
bind is loopback-only; see
[reference/ports-and-protocols.md](../reference/ports-and-protocols.md) and
[operations/networking-tls.md](../operations/networking-tls.md).

`console::server::serve` bounds the connection itself, so the console does not depend
on a proxy for it: at most 64 connections at once (one accepted past that is closed
immediately), 10 seconds to deliver a request's headers (re-armed while a kept-alive
connection waits, so idle connections close too), and 10 seconds and 2 MiB for the body,
read before the handler runs (`408` or `413` otherwise). It serves HTTP/1.1 only: hyper's
auto-detecting builder waits for the HTTP/2 preface with no timeout of its own. It also
inserts `ConnectInfo<SocketAddr>` on every request, which the login rate limiter keys on;
without it, `ConnectInfo` extraction fails closed on every login.

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
  (approve/reject/snooze/unsnooze/delist/relist/delete) and `POST /integrity/verify`,
  which changes no state but scans the whole ledger (and runs one at a time).
  `POST /login` deliberately carries **no CSRF check** (no pre-auth session to bind a
  token to; the rate limiter is its defense).
- **Login rate limiting** - sliding-window per source IP plus a budget across all
  sources, with memory-bound caps. Argon2 verification runs on the blocking pool, at most
  two at a time, so a login spray cannot occupy the async workers.

## Security headers

`security_headers` middleware is applied globally (`crates/console/src/routes/mod.rs#router`) and sets three
headers on **every** response, public and protected alike:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- a Content-Security-Policy allowing script, style, fonts and requests from this origin
  only and nothing inline (exact text in
  [console routes](../reference/console-routes.md#content-security-policy)), unless the route
  set a stricter one: `GET /samples/download/{sha256}` keeps `default-src 'none'`.

No template carries inline script, inline style or an event handler; every script and
stylesheet is a static file under `src/assets/`, served by `routes::assets`. XSS defense for
the HTML pages is minijinja auto-escaping (below); the policy stops an escaping mistake from
becoming script execution.

## Templates and fragments

- All templates are embedded in the binary via `include_str!` (`templates.rs`);
  there is no runtime template directory. The environment is built once at startup
  and shared behind an `Arc`.
- **Auto-escaping** is minijinja's XSS guarantee: any template whose registered name
  ends in `.html` auto-escapes every `{{ }}` value unless it opts out with `|safe`.
  `|safe` is used deliberately only for `serde_json`-serialized Chart.js data arrays
  injected into inline `<script>` blocks.
- `base.html` is assembled at **compile time** from two pieces via
  `concat!(include_str!(..))` (`crates/console/src/templates.rs#BASE_HTML`): `base_head.html`
  and `base_tail.html`. The head links the stylesheet and loads the vendored Chart.js UMD
  bundle, the chart defaults (`assets/charts.js`) and the vendored htmx bundle as static
  files under `src/assets/`; the tail carries the navigation, the evidence drawer and
  `console.js`. Both JS libraries are unmodified upstream, **self-hosted, no CDN at
  runtime**.
- **Visual system** - one stylesheet (`assets/console.css`) and a set of shared macros
  (`templates/macros.html`) hold every token and component; the
  [console design system](../reference/console-design-system.md) lists them and the rules a
  change follows, and a rendered-page test enforces the structural ones.
- **Review queue layout** - the pending tab groups by campaign without any script: a native
  `<details>` row per campaign that has two or more listed pending members, whose member rows sit
  in a nested table sharing the page's `<colgroup>` widths (`macros.html#queue_cols`). An address
  in several campaigns is listed under the one with the most pending members, then the most hosts,
  then the lowest id (`routes/queue.rs#group_home`); its other campaigns appear on its IP page.
  Scores are plain numbers (the page carries no score bar, to keep each row quiet), "Active" is one cell
  (`routes/format.rs#format_active`: a clock range within one UTC day, a length plus recency
  across days, exact timestamps in the `title`), and below 640 px each entry stacks as a card,
  as every table of addresses does (all rules in `console.css`, no inline style). Group counts are rendered with the page and are not updated when a member is decided in
  place; the approve confirmation lists the live pending set.
- **HTMX fragment model** - several routes return partials rather than full pages:
  the dashboard and IP-detail charts, the IP-detail event timeline (keyset
  pagination), the queue-row partials after an action, and search "load more". A
  request carrying `HX-Request` receives the fragment; the same handler renders the
  full page otherwise. IP detail additionally renders into a `drawer_shell.html`
  layout when `?drawer=1` and `HX-Request` are both present (the **evidence drawer**).
- **Logs** stream over Server-Sent Events (`/logs/stream`, `text/event-stream`) from
  an in-memory ring buffer held to an entry count and a byte budget; a lagged receiver is
  skipped, not fatal. Entries carry their structured fields; the page folds adjacent
  identical INFO entries server-side for the first render (`routes/logs.rs#fold_entries`)
  and `assets/logs.js` folds live lines by the same rule.

## Theme system (V12) and fonts

The V12 operator-console interface - the theme system, evidence drawer, and
self-hosted fonts - merged **after** the `v0.1.0` tag (at commit `dbf8c053`); it is
present in the current `0.4.0` tree but not in any tagged release, and `CHANGELOG.md`
does not yet mention it (see
[overview/maturity-and-status.md](../overview/maturity-and-status.md)).

- **Four themes**, driven by CSS custom properties and switched via
  `<html data-theme=...>`: **graphite** (dark, the designed default), **cream**
  (light), **system** (follows the OS - light by default, graphite under a dark OS),
  and **hacker** (a green-phosphor mono theme). The server default is `graphite`,
  whose palette sits on bare `:root` so a no-JS page still renders it.
- **Persistence** - the selected theme is stored in `localStorage` under
  `propolis-theme`; a tiny pre-paint script (`assets/theme-init.js`, loaded first in the head, never inline) applies it before first paint to
  avoid a flash, guarded in try/catch for private-mode throws. The top-nav
  `<select>` syncs, persists, and re-colors the charts on change.
- **Top navigation** is server-rendered: wordmark, main nav (Dashboard, Review with
  a pending badge, Attackers, Campaigns, Feed, Search, an Operations dropdown to
  Fleet/Logs/Samples/Integrity), a quick-search form, the theme selector, uptime, version,
  and Sign out. An `active_nav` context variable drives the active/`aria-current`
  state.
- **Fonts** are embedded in the binary and served from a public `/assets/fonts/{file}`
  route against a fixed four-name allowlist (unknown name → 404; no filesystem path is
  built, so no traversal). The deployed box makes **no third-party or CDN font
  request**; the login page is public specifically so it can load the same fonts and
  theme pre-auth.

## Health, readiness, and metrics

Supplementary panels (charts, the most-active table, sample links and verdicts, the
integrity page's event count, the nav's pending badge) soft-fail: a query error renders a
placeholder rather than a 503. Every such failure goes through `routes::degraded`, which
logs the error and names the panel in an amber banner at the top of the page ("Some
panels could not be loaded and show placeholders: ..."), so a zero or an empty table is
never mistaken for a quiet node. A page's core content still fails closed to a 503.

`/health`, `/ready`, and `/metrics` are public (Prometheus cannot log in), which is
acceptable because the console binds loopback-only by default. `/health` is a
liveness-only constant `200`; `/ready` pings `SELECT 1`, then asks the daemon's
supervisor whether any subsystem has given up, and returns `200`/`503` fail-closed
(the dead names in the body); `/metrics` derives Prometheus gauges and counters from live DB queries
per scrape. See [operations/health-and-observability.md](../operations/health-and-observability.md).

## Related

- [reference/console-routes.md](../reference/console-routes.md) - every route and API.
- [architecture/storage.md](./storage.md) - the database this console reads.
- [architecture/trust-boundaries-and-data-flows.md](./trust-boundaries-and-data-flows.md) - where the console sits in the trust model.
- [security/authn-authz.md](../security/authn-authz.md) - full auth model.
