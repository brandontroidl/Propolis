<!--
title: Console Tour
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Console tour

A guided walkthrough of the operator console. The console is a server-rendered
(minijinja + HTMX) web UI backed by PostgreSQL, served over plain HTTP on loopback
`127.0.0.1:8080` by default (`crates/console/src/routes/mod.rs`,
`crates/propolis/src/config.rs:30`). The complete route/API table is owned by
[reference/console-routes.md](../reference/console-routes.md) - this page explains the
pages, not the endpoint list.

> [!NOTE]
> There is no in-process TLS; the console is plain HTTP. Reaching it from anything other
> than loopback requires an operator-provided TLS reverse proxy - see
> [networking and TLS](../operations/networking-tls.md).

## Login

`GET /login` presents the form. Authentication is a single shared password from
`PROPOLIS_CONSOLE_PASSWORD` (Argon2id-hashed at startup, held only in memory)
(`crates/console/src/auth.rs:35-65`). On success you get a signed `propolis_session`
cookie (HttpOnly, SameSite=Strict, Secure unless the client is loopback) with a 24h TTL
(`auth.rs:76`, `login.rs:111-119`). Sessions are in-memory only and are lost on daemon
restart, by design (`auth.rs:2-5`).

Login is rate-limited per source IP (default 5 attempts / 60s; a blocked attempt returns
`429` and is not itself counted) (`auth.rs:200-256`). A wrong password returns `401`.
Authn/authz details are owned by [authn-authz](../security/authn-authz.md).

Everything except `/health`, `/ready`, `/metrics`, `/login`, `/logout`, and
`/assets/fonts/*` is session-gated; an unauthenticated hit on a protected page redirects
(302) to `/login` (`routes/mod.rs:33-57`, `auth.rs:262-279`).

## Dashboard (`/`)

Six stat cards: three core (total scored IPs, pending reviews, approved today) that hard-
fail if their query errors, and three supplementary (events last hour, feed entries, top
attacker) that soft-fail to placeholders (`crates/console/src/routes/dashboard.rs:101-213`).
Two Chart.js charts (events timeline, protocol distribution) and a "most active" table
with 24h activity strips. The timeline range switches via `/dashboard/chart?range=`
(`1h`/`24h`/`7d`/`30d`, malformed falls back to `24h`) (`dashboard.rs:414-459`).

## Review queue (`/queue`)

IPs that cross the review threshold await a human decision here. Each row offers
approve / reject / snooze; IP-level actions delist or delete. Every mutating action is a
POST carrying a required per-session CSRF token; a missing/invalid token returns `403`
(`crates/console/src/routes/queue.rs:372-406`).

- **Delist** removes the queue row and flags the IP off the feed
  (`delisted=TRUE, eligible=FALSE, ...`) (`queue.rs:408-433`).
- **Delete** purges the `review_queue`, `vendor_submission`, and `ip_score` rows but
  deliberately does **not** touch the append-only `event` ledger - the projection can be
  rebuilt from it (`queue.rs:435-473`).

The publication gate (why an IP is eligible at all: authenticated session + seen more than
once + above the score/confidence floor + human-approved) and its thresholds are owned by
[reference/scoring-and-feed.md](../reference/scoring-and-feed.md).

## IP detail + evidence drawer (`/ip/{ip}`)

Read-only view of one address: the evidence timeline (keyset-paginated by
`(observed_at, id)` via `/ip/{ip}/events`), sessions grouped by `session_id`, a per-WAN
breakdown, categories, vendor submissions, a services-probed panel, and external-lookup
links (`crates/console/src/routes/detail.rs:198-401`).

- **Evidence drawer.** Append `?drawer=1` with an `HX-Request` header (the console does
  this when you open detail from a list) to render the same data into a slide-in drawer
  (`drawer_shell.html`) instead of a full page (`detail.rs:205-215`).
- **External lookups** are links your browser follows - the honeypot never makes the
  request, so it never leaks a captured IP to a third party (`detail.rs:732-753`).
- Enrichment shown here is offline GeoIP plus opt-in forward-confirmed rDNS
  (`detail.rs:305-325`); rDNS is the only egress and is off by default
  (`PROPOLIS_CONSOLE_RDNS_ENABLED`). See [outbound controls](../security/outbound-controls.md).

A missing IP returns a direct `404`, not an error page (`detail.rs:217-219`).

## Feed status (`/feed`)

Two tabs (`?tab=status|entries`):

- **Status** (default) reads the published `manifest.json` and surfaces tier counts
  (aggressive/standard), retention windows, and exclusion counts (allowlist/delist/ASN).
  A missing or malformed manifest shows an empty state, never a hard error
  (`crates/console/src/routes/feed.rs:136-218`).
- **Entries** lists the addresses actually in the published feed by reading the exported
  `{feed}.json` files back off disk (not re-querying the DB), so the page cannot drift
  from what the builder published (`feed.rs:160-179`). No live score column, because feed
  membership is fixed at observation time.

Downloads are served from `/feed/download/{tier}/{format}` in 10 formats
(`json`, `csv`, `txt`, `cidr`, `ipset`, `nft`, `pf`, `alias`, `hosts`, `rpz`), with both
path segments shape-validated before any filesystem access (`feed.rs:294-357`). Tiers,
windows, and thresholds are owned by
[reference/scoring-and-feed.md](../reference/scoring-and-feed.md).

## Other pages

- **Attackers** `/ips` - scored `ip_score` list, sortable, capped at 500 rows
  (`crates/console/src/routes/ips.rs:37-119`).
- **Integrity** `/integrity` - runs a hash-chain verification over the `event` ledger and
  reports intact/broken (`crates/console/src/routes/integrity.rs:36-66`).
- **Samples** `/samples` - captured malware samples by sha256, joined with VirusTotal
  results where available (`crates/console/src/routes/samples.rs:81-135`). See the malware
  warning in [first capture](first-capture.md).
- **Search** `/search/events`, `/search/ips` - filtered search (free text, sensor, signal
  type, IP, date range); at least one filter is required (`crates/console/src/routes/search.rs`).
- **Logs** `/logs` - terminal-style live viewer over the daemon's tracing ring buffer
  (SSE) (`crates/console/src/routes/logs.rs`).

## Themes

Four themes, selectable from the top-nav switcher and persisted in `localStorage`
(`propolis-theme`): **graphite** (dark, the designed default), **cream** (light),
**system** (follows the OS), and **hacker** (green phosphor)
(`crates/console/src/templates/base_head.html:44-149`, `base_tail.html:80-138`). A tiny
pre-paint script applies the stored theme before first paint to avoid a flash; the server
default is graphite (`base_head.html:2-16`). Fonts are self-hosted from
`/assets/fonts/*` - the deployed box makes no CDN request
(`crates/console/src/routes/assets.rs:8-9`).

## Health and metrics (unauthenticated)

`/health` (liveness, always 200), `/ready` (pings the DB; 200/503 fail-closed), and
`/metrics` (Prometheus text) are public because they cannot log in and the console is
loopback-only (`crates/console/src/routes/health.rs`, `metrics.rs:8-11`). See
[health and observability](../operations/health-and-observability.md).
