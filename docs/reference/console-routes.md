<!--
title: Console routes and APIs
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Console routes and APIs

Canonical owner of console route facts: paths, methods, auth boundary, CSRF model,
feed download formats, queue mutations, and the security-headers middleware. The
console is an Axum + minijinja server-rendered app (HTMX partial swaps, self-hosted
Chart.js); it serves plain HTTP on a loopback `TcpListener` with no in-process TLS
(any TLS is operator-provided via a reverse proxy `[inferred]` - see
[networking and TLS](../operations/networking-tls.md)). Configuration env vars are
owned by [environment variables](environment-variables.md); the default bind is
`127.0.0.1:8080` (loopback only).

Source: `crates/console/src/routes/`, `crates/console/src/auth.rs`.

## Auth boundary

`router()` (`crates/console/src/routes/mod.rs#router`) builds two groups:

- **Protected group** (`crates/console/src/routes/mod.rs#router`): merged, then wrapped with
  `require_session` via `route_layer`. Every route is session-gated.
- **Public group** (`crates/console/src/routes/mod.rs#router`): `health`, `metrics`, `login`, `assets`
  merged **outside** `require_session` - no session required.

Both groups then receive `security_headers` globally (`crates/console/src/routes/mod.rs#router`).

`require_session` (`crates/console/src/auth.rs#require_session`) reads the `propolis_session` cookie and calls
`sessions.validate`. On a valid session it continues; on an invalid/absent session it
returns `Redirect::to("/login")` (**303**) for an ordinary request, or **401** with an
`HX-Redirect: /login` header for an HTMX request (`hx-request` header present, no
swappable body). An unauthenticated hit on a protected route is therefore always
redirected to the login page, by whichever mechanism the requester understands.

Session and password internals (cookie signing, Argon2id, TTL, CSRF token generation,
login rate limiting) are owned by [authentication and authorization](../security/authn-authz.md).

## Route table

**8 public + 26 session-gated = 34 routes** (one row per method and path; `/login` serves GET and POST).

### Public (no session)

| Method | Path | Handler | Notes | Source |
|---|---|---|---|---|
| GET | `/health` | `health` | always `200 {"status":"ok"}` (liveness only) | `crates/console/src/routes/health.rs#health` |
| GET | `/ready` | `ready` | pings `SELECT 1`, then any supervised subsystem that gave up; `200`/`503` (`gave_up` names in the body), fail-closed | `routes/health.rs` `ready` |
| GET | `/metrics` | `metrics` | Prometheus text (`text/plain; version=0.0.4`) | `crates/console/src/routes/metrics.rs#metrics` |
| GET | `/login` | `login_form` | | `crates/console/src/routes/login.rs#login_form` |
| POST | `/login` | `login_submit` | no CSRF (no pre-auth session to bind) | `crates/console/src/routes/login.rs#login_submit` |
| GET | `/logout` | `logout` | idempotent; destroys session + clears cookie | `crates/console/src/routes/login.rs#logout` |
| GET | `/assets/fonts/{file}` | `font` | fixed 4-name allowlist; public so login page loads fonts | `routes/assets.rs` |
| GET | `/assets/{file}` | `static_asset` | the pages' scripts and stylesheets, fixed allowlist; ETag + `no-cache`, `304` on a match | `routes/assets.rs` |

### Session-gated (protected)

| Method | Path | Handler | Notes | Source |
|---|---|---|---|---|
| GET | `/` | `dashboard` | 6 stat cards, 2 Chart.js charts | `crates/console/src/routes/dashboard.rs#dashboard` |
| GET | `/dashboard/chart` | `dashboard_chart_fragment` | HTMX; `?range=1h\|24h\|7d\|30d`, malformed -> `24h` | `crates/console/src/routes/dashboard.rs#dashboard_chart_fragment` |
| GET | `/queue` | `queue_page` | review queue | `crates/console/src/routes/queue.rs#queue_page` |
| POST | `/queue/{ip}/approve` | `approve` | CSRF required | `crates/console/src/routes/queue.rs#approve` |
| POST | `/queue/{ip}/reject` | `reject` | CSRF required | `crates/console/src/routes/queue.rs#reject` |
| POST | `/queue/{ip}/snooze` | `snooze` | CSRF required | `crates/console/src/routes/queue.rs#snooze` |
| POST | `/queue/{ip}/unsnooze` | `unsnooze` | CSRF required | `routes/queue.rs` |
| POST | `/ip/{ip}/delist` | `delist` | CSRF required | `routes/queue.rs` |
| POST | `/ip/{ip}/relist` | `relist` | CSRF required | `routes/queue.rs` |
| POST | `/ip/{ip}/delete` | `delete_ip` | CSRF required | `routes/queue.rs` |
| GET | `/ip/{ip}` | `detail` | drawer mode via `?drawer=1` + `HX-Request`; missing IP -> `404` | `crates/console/src/routes/detail.rs#detail` |
| GET | `/ip/{ip}/events` | `events_fragment` | HTMX keyset pagination | `crates/console/src/routes/detail.rs#events_fragment` |
| GET | `/ip/{ip}/chart` | `chart_fragment` | HTMX | `crates/console/src/routes/detail.rs#chart_fragment` |
| GET | `/feed` | `feed_page` | `?tab=status\|entries` | `crates/console/src/routes/feed.rs#feed_page` |
| GET | `/feed/download/{tier}/{format}` | `download_feed` | see feed downloads below | `crates/console/src/routes/feed.rs#download_feed` |
| GET | `/fleet` | `fleet_page` | listener reachability, capture completeness, running version | `routes/fleet.rs` |
| GET | `/fleet/status` | `fleet_status_fragment` | HTMX, polled every 30 s; stale handling in `assets/live-panels.js` | `routes/fleet.rs` |
| GET | `/search/events` | `search_events` | doubles as HTMX load-more when `HX-Request` present; `400` on a control character or an over-512-byte query param | `crates/console/src/routes/search.rs#search_events` |
| GET | `/search/ips` | `search_ips` | `400` on a control character or an over-512-byte query param | `crates/console/src/routes/search.rs#search_ips` |
| GET | `/ips` | `ip_list` | `ip_score` list, capped 500 rows | `crates/console/src/routes/ips.rs#ip_list`, `crates/console/src/routes/ips.rs#fetch_ips_ordered` |
| GET | `/integrity` | `integrity_page` | | `crates/console/src/routes/integrity.rs#integrity_page` |
| POST | `/integrity/verify` | `run_verify` | CSRF (403); one verification at a time (409 while one runs) | `routes/integrity.rs` |
| GET | `/samples` | `samples_page` | | `crates/console/src/routes/samples.rs#samples_page` |
| GET | `/samples/download/{sha256}` | `download_sample` | hardened download; sets a per-route CSP | `crates/console/src/routes/samples.rs#download_sample`, `crates/console/src/routes/samples.rs#serve_sample` |
| GET | `/logs` | `logs_page` | in-memory ring-buffer snapshot | `crates/console/src/routes/logs.rs#logs_page` |
| GET | `/logs/stream` | `logs_stream` | SSE (`text/event-stream`) | `crates/console/src/routes/logs.rs#logs_stream` |

## CSRF model

- **Per-session token**, generated on first use and reused thereafter so multiple open
  forms stay valid (`generate_csrf`, `crates/console/src/auth.rs#generate_csrf`). Surfaced to templates as `csrf_token` and
  embedded in `crates/console/src/templates/base_head.html#csrf-token` as `<meta name="csrf-token" content="...">`.
- `validate_csrf` uses a constant-time compare (`subtle::ConstantTimeEq`) and returns
  `false` if the session is absent or no token has been generated yet (fail-closed)
  (`crates/console/src/auth.rs#validate_csrf`).
- **Every session-gated POST requires CSRF**, the queue mutations and
  `POST /integrity/verify` alike. The verification changes no state, but it scans the
  whole ledger, so it is an operator action with a real cost that another page must not
  be able to trigger; it also runs one at a time (`409` while one is in progress).
- **`POST /login` deliberately does not check CSRF.** No pre-auth session exists to bind
  a token to; a forged login still needs the correct password, and the rate limiter is
  the real defense (`login.rs`).

## Queue mutation actions

All under the protected group (`crates/console/src/routes/queue.rs#router`). Each POST takes an `ActionForm`
with a required `csrf_token` field and optional `notes` (`crates/console/src/routes/queue.rs#ActionForm`). CSRF is
validated first; on failure the handler returns **`403 FORBIDDEN`** "invalid or missing
csrf token" (`crates/console/src/routes/queue.rs#unsnooze` unsnooze, `crates/console/src/routes/queue.rs#act` act, `crates/console/src/routes/queue.rs#delist` delist, `crates/console/src/routes/queue.rs#relist` relist,
`crates/console/src/routes/queue.rs#delete_ip` delete_ip).

| Action | Method + path | Effect | Response |
|---|---|---|---|
| Approve | `POST /queue/{ip}/approve` | `ReviewQueue::approve` | HTMX `queue_row.html` partial |
| Reject | `POST /queue/{ip}/reject` | `ReviewQueue::reject` | HTMX row partial |
| Snooze | `POST /queue/{ip}/snooze` | `ReviewQueue::snooze` | HTMX row partial |
| Delist | `POST /ip/{ip}/delist` | delete `review_queue` row; set `ip_score.delisted=TRUE, eligible=FALSE, recommended_for_vendor=FALSE, recommended_for_blocklist=FALSE` | `303` → `/ip/{ip}` |
| Delete | `POST /ip/{ip}/delete` | purge `review_queue` + `vendor_submission` + `ip_score` rows | `303` → `/queue` |

Approve/reject/snooze converge in `act` (`crates/console/src/routes/queue.rs#act`), then re-read the score and
render the `queue_row.html` partial (`queue_moved_row.html` when the decision came from a history tab,
`crates/console/src/routes/queue.rs#response_row_template`). `delete_ip` deliberately does **not** touch the
append-only hash-chained `event` ledger (`crates/console/src/routes/queue.rs#delete_ip`) - the projection can be
rebuilt from the ledger. Table and column facts are owned by
[database reference](database.md); scoring flags by [scoring and feed](scoring-and-feed.md).

## Feed downloads

`GET /feed/download/{tier}/{format}` (`crates/console/src/routes/feed.rs#download_feed`) streams one export file off
disk. Both path segments are validated **before** touching the filesystem.

- `tier` (feed name) is validated by `is_known_feed_name` (`crates/console/src/routes/feed.rs#is_known_feed_name`): accepts
  literal `aggressive` / `standard`, or `all-{digits}{h|d}` retention-window names. This
  is a **shape check** that admits no `.`, `/`, or `\`, so no accepted value can traverse
  out of the feed directory.
- `format` is matched against a fixed set → (extension, content-type)
  (`crates/console/src/routes/feed.rs#download_feed`). **10 formats:**

  | Format | Extension | Content-Type |
  |---|---|---|
  | `json` | `.json` | `application/json` |
  | `csv` | `.csv` | `text/csv` |
  | `txt` | `.txt` | `text/plain` |
  | `cidr` | `.cidr` | `text/plain` |
  | `ipset` | `.ipset` | `text/plain` |
  | `nft` | `.nft` | `text/plain` |
  | `pf` | `.pf` | `text/plain` |
  | `alias` | `.alias` | `text/plain` |
  | `hosts` | `.hosts` | `text/plain` |
  | `rpz` | `.rpz` | `text/plain` |

- The path is built as `{tier}.{extension}` under the feed directory
  (`PROPOLIS_FEED_OUTPUT_DIR`, see [environment variables](environment-variables.md)) and
  served with `Content-Disposition: attachment; filename="{tier}.{extension}"`
  (`crates/console/src/routes/feed.rs#download_feed`).
- Every "nothing to serve" case (feed dir unset, unknown tier/format, file absent) ->
  **`404`** with a small HTML body, not a generic 503 (`crates/console/src/routes/feed.rs#download_feed`, `crates/console/src/routes/feed.rs#download_not_found`).

The `/feed` page itself has two tabs (`?tab=status|entries`): the status tab reads
`manifest.json` from the feed dir and the entries tab reads back the published `{feed}.json`
export files rather than re-querying the DB (`feed_page`, `crates/console/src/routes/feed.rs#feed_page`).

## Security-headers middleware

`security_headers` (`crates/console/src/routes/mod.rs#security_headers`) is applied globally at `crates/console/src/routes/mod.rs#router`, so it
runs on **every** response, public and protected alike. It sets:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy`, unless the route already set a stricter one (below)

### Content-Security-Policy

Every response carries
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
(`routes::CONTENT_SECURITY_POLICY`). No page carries an inline `<script>`, an inline
style or an event-handler attribute: every script and stylesheet is a static file under
`crates/console/src/assets/`, served at `/assets/{name}` from a fixed allowlist with an ETag
and `Cache-Control: no-cache`, so a browser revalidates and never runs a stale script against
new markup. Data-driven widths use generated classes (`pct-0` to `pct-100`, `h-2` to `h-26`)
rather than style attributes. `templates.rs` tests scan every template for inline script,
style and handlers, and for references to assets that are not served.

`GET /samples/download/{sha256}` keeps a stricter policy of its own. It serves the raw malware
sample with `Content-Security-Policy: default-src 'none'` alongside its own
`X-Content-Type-Options: nosniff`, `Content-Type: application/octet-stream`, and
`Content-Disposition: attachment` (`serve_sample` in `samples.rs`). That download also
validates the `{sha256}` segment as exactly 64 hex characters and returns `400` for a malformed
value. It serves only a body that passes `review::spool::read_sample` (a regular file, not a
link, whose content hashes to the requested digest); an entry that exists but fails that check
returns `409` and is logged, and an absent one returns `404`.

XSS defense across the HTML pages is **minijinja auto-escaping** (every template whose name
ends in `.html` is auto-escaped). The policy is the second line: an escaping mistake that let
markup through still could not run script or apply inline style.
