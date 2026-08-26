<!--
title: Console routes and APIs
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
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

`router()` (`routes/mod.rs:33-57`) builds two groups:

- **Protected group** (`routes/mod.rs:34-47`): merged, then wrapped with
  `require_session` via `route_layer`. Every route is session-gated.
- **Public group** (`routes/mod.rs:49-54`): `health`, `metrics`, `login`, `assets`
  merged **outside** `require_session` - no session required.

Both groups then receive `security_headers` globally (`routes/mod.rs:55`).

`require_session` (`auth.rs:262-279`) reads the `propolis_session` cookie and calls
`sessions.validate`. On a valid session it continues; on an invalid/absent session it
returns `Redirect::to("/login")` (**302**, not 401). An unauthenticated hit on a
protected route is therefore a redirect to the login page.

Session and password internals (cookie signing, Argon2id, TTL, CSRF token generation,
login rate limiting) are owned by [authentication and authorization](../security/authn-authz.md).

## Route table

**7 public + 23 session-gated = 30 routes.**

### Public (no session)

| Method | Path | Handler | Notes | Source |
|---|---|---|---|---|
| GET | `/health` | `health` | always `200 {"status":"ok"}` (liveness only) | `routes/health.rs:16,22-24` |
| GET | `/ready` | `ready` | pings `SELECT 1`; `200`/`503`, fail-closed | `routes/health.rs:17,28-40` |
| GET | `/metrics` | `metrics` | Prometheus text (`text/plain; version=0.0.4`) | `routes/metrics.rs:40,190-198` |
| GET | `/login` | `login_form` | | `routes/login.rs:45` |
| POST | `/login` | `login_submit` | no CSRF (no pre-auth session to bind) | `routes/login.rs:45` |
| GET | `/logout` | `logout` | idempotent; destroys session + clears cookie | `routes/login.rs:46` |
| GET | `/assets/fonts/{file}` | `font` | fixed 4-name allowlist; public so login page loads fonts | `routes/assets.rs:28` |

### Session-gated (protected)

| Method | Path | Handler | Notes | Source |
|---|---|---|---|---|
| GET | `/` | `dashboard` | 6 stat cards, 2 Chart.js charts | `routes/dashboard.rs:49` |
| GET | `/dashboard/chart` | `dashboard_chart_fragment` | HTMX; `?range=1h\|24h\|7d\|30d`, malformed → `24h` | `routes/dashboard.rs:50` |
| GET | `/queue` | `queue_page` | review queue | `routes/queue.rs:41` |
| POST | `/queue/{ip}/approve` | `approve` | CSRF required | `routes/queue.rs:42` |
| POST | `/queue/{ip}/reject` | `reject` | CSRF required | `routes/queue.rs:43` |
| POST | `/queue/{ip}/snooze` | `snooze` | CSRF required | `routes/queue.rs:44` |
| POST | `/ip/{ip}/delist` | `delist` | CSRF required | `routes/queue.rs:45` |
| POST | `/ip/{ip}/delete` | `delete_ip` | CSRF required | `routes/queue.rs:46` |
| GET | `/ip/{ip}` | `detail` | drawer mode via `?drawer=1` + `HX-Request`; missing IP → `404` | `routes/detail.rs:76` |
| GET | `/ip/{ip}/events` | `events_fragment` | HTMX keyset pagination | `routes/detail.rs:77` |
| GET | `/ip/{ip}/chart` | `chart_fragment` | HTMX | `routes/detail.rs:78` |
| GET | `/feed` | `feed_page` | `?tab=status\|entries` | `routes/feed.rs:59` |
| GET | `/feed/download/{tier}/{format}` | `download_feed` | see feed downloads below | `routes/feed.rs:60` |
| GET | `/search/events` | `search_events` | doubles as HTMX load-more when `HX-Request` present | `routes/search.rs:58` |
| GET | `/search/ips` | `search_ips` | | `routes/search.rs:59` |
| GET | `/ips` | `ip_list` | `ip_score` list, capped 500 rows | `routes/ips.rs:14` |
| GET | `/integrity` | `integrity_page` | | `routes/integrity.rs:13` |
| POST | `/integrity/verify` | `run_verify` | **no CSRF** (read-only chain verify) | `routes/integrity.rs:14` |
| GET | `/samples` | `samples_page` | | `routes/samples.rs:17` |
| GET | `/samples/download/{sha256}` | `download_sample` | hardened download; sets a per-route CSP | `routes/samples.rs:18` |
| GET | `/logs` | `logs_page` | in-memory ring-buffer snapshot | `routes/logs.rs:35` |
| GET | `/logs/stream` | `logs_stream` | SSE (`text/event-stream`) | `routes/logs.rs:37` |

## CSRF model

- **Per-session token**, generated on first use and reused thereafter so multiple open
  forms stay valid (`auth.rs:157-180`). Surfaced to templates as `csrf_token` and
  embedded in `base_head.html:19` as `<meta name="csrf-token" content="...">`.
- `validate_csrf` uses a constant-time compare (`subtle::ConstantTimeEq`) and returns
  `false` if the session is absent or no token has been generated yet (fail-closed)
  (`auth.rs:171-180`).
- **Only the five queue mutations require CSRF.** Two session-gated POSTs deliberately
  do **not** check CSRF:
  - `POST /login` - no pre-auth session exists to bind a token to; a forged login still
    needs the correct password, and the rate limiter is the real defense
    (`login.rs:6-17`).
  - `POST /integrity/verify` - a read-only hash-chain verification with no state
    mutation (`integrity.rs:14,36`).

## Queue mutation actions

All under the protected group (`routes/queue.rs:39-47`). Each POST takes an `ActionForm`
with a required `csrf_token` field and optional `notes` (`queue.rs:136-141`). CSRF is
validated first; on failure the handler returns **`403 FORBIDDEN`** "invalid or missing
csrf token" (`queue.rs:379-382,414-416,450-452`).

| Action | Method + path | Effect | Response |
|---|---|---|---|
| Approve | `POST /queue/{ip}/approve` | `ReviewQueue::approve` | HTMX `queue_row.html` partial |
| Reject | `POST /queue/{ip}/reject` | `ReviewQueue::reject` | HTMX row partial |
| Snooze | `POST /queue/{ip}/snooze` | `ReviewQueue::snooze` | HTMX row partial |
| Delist | `POST /ip/{ip}/delist` | delete `review_queue` row; set `ip_score.delisted=TRUE, eligible=FALSE, recommended_for_vendor=FALSE, recommended_for_blocklist=FALSE` | `303` → `/ip/{ip}` |
| Delete | `POST /ip/{ip}/delete` | purge `review_queue` + `vendor_submission` + `ip_score` rows | `303` → `/queue` |

Approve/reject/snooze converge in `act` (`queue.rs:372-406`), then re-read the score and
render the `queue_row.html` partial. `delete_ip` deliberately does **not** touch the
append-only hash-chained `event` ledger (`queue.rs:435-473`) - the projection can be
rebuilt from the ledger. Table and column facts are owned by
[database reference](database.md); scoring flags by [scoring and feed](scoring-and-feed.md).

## Feed downloads

`GET /feed/download/{tier}/{format}` (`feed.rs:60,294-336`) streams one export file off
disk. Both path segments are validated **before** touching the filesystem.

- `tier` (feed name) is validated by `is_known_feed_name` (`feed.rs:346-357`): accepts
  literal `aggressive` / `standard`, or `all-{digits}{h|d}` retention-window names. This
  is a **shape check** that admits no `.`, `/`, or `\`, so no accepted value can traverse
  out of the feed directory.
- `format` is matched against a fixed set → (extension, content-type)
  (`feed.rs:304-316`). **10 formats:**

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
  (`feed.rs:318-330`).
- Every "nothing to serve" case (feed dir unset, unknown tier/format, file absent) →
  **`404`** with a small HTML body, not a generic 503 (`feed.rs:298-303,315,331-334,359-363`).

The `/feed` page itself has two tabs (`?tab=status|entries`): the status tab reads
`manifest.json` from the feed dir and the entries tab reads back the published `{feed}.json`
export files rather than re-querying the DB (`feed.rs:59-179`).

## Security-headers middleware

`security_headers` (`routes/mod.rs:59-71`) is applied globally at `routes/mod.rs:55`, so it
runs on **every** response, public and protected alike. It sets exactly two headers:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`

### No global Content-Security-Policy

There is **no global CSP header**. The only route that emits a CSP is
`GET /samples/download/{sha256}`, which serves the raw malware sample with
`Content-Security-Policy: default-src 'none'` alongside its own
`X-Content-Type-Options: nosniff`, `Content-Type: application/octet-stream`, and
`Content-Disposition: attachment` (`samples.rs:145-160`). That download also validates the
`{sha256}` segment as exactly 64 hex characters and returns `400` for a malformed value
(`samples.rs:138-139`).

XSS defense across the HTML pages is therefore **minijinja auto-escaping** (every template
whose name ends in `.html` is auto-escaped) plus `nosniff` / `DENY` and the hardened
download path - not a CSP.
