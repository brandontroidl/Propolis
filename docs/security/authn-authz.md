<!--
title: Console authentication and authorization
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Console authentication and authorization

The operator console is a single-operator web application: one password, sessions held
in memory, and a hard split between a small public route group and a large session-gated
group. This page owns the authentication mechanism; the canonical route table (method,
path, handler, auth, CSRF) lives in
[../reference/console-routes.md](../reference/console-routes.md), and env-var exact
defaults live in [../reference/environment-variables.md](../reference/environment-variables.md).

> No in-process TLS. The console listens as plain HTTP on a loopback `TcpListener`
> (`console::server::serve`, HTTP/1.1, no rustls). Any TLS is operator-provided (for example a reverse proxy)
> and `[inferred]`. See [../operations/networking-tls.md](../operations/networking-tls.md).

## Public versus gated routes

The router builds two groups. The **protected** group (dashboard, queue, detail, feed,
search, ips, integrity, samples, logs) is wrapped with the `require_session` middleware
via `route_layer`. The **public** group (health, ready, metrics, login, logout, fonts) is
mounted outside that layer. In total **30 routes: 7 public, 23 session-gated**.

`require_session` reads the `propolis_session` cookie and calls `sessions.validate`; on a
valid session it continues, and on any missing/invalid session it returns a **302 redirect
to `/login`** (never a 401). Full table: [../reference/console-routes.md](../reference/console-routes.md).

`/metrics` is public because Prometheus cannot authenticate; this is acceptable only
*because* the default bind is loopback-only.

## Password: Argon2id

The operator password (`PROPOLIS_CONSOLE_PASSWORD`) is hashed at startup with **Argon2id
(default params)** and the plaintext is discarded; only the PHC hash string is kept in
memory, never written to disk or the database (`crates/console/src/auth.rs:45-52`).
Verification fails closed: an unparseable stored hash returns `false` rather than panicking
(`auth.rs:57-64`).

The console **refuses to start** with no password - an empty or absent
`PROPOLIS_CONSOLE_PASSWORD` is a fail-closed `MissingPassword` startup error
(`crates/console/src/main.rs:123-126`).

## Session cookie

- **Cookie name:** `propolis_session`.
- **Value format:** `{session_id}.{hmac_tag}`, where the tag is HMAC-SHA256 of the session
  id under a 32-byte server secret (`auth.rs:78-83`, `sign` at `auth.rs:191-197`). The HMAC
  tag is verified **before** any session-map lookup, so a guessed or forged id is rejected
  without a lookup (`auth.rs:138-155`).
- **Session id:** 32 random bytes, hex-encoded (`auth.rs:123`).
- **Store:** in-memory `RwLock<HashMap>` only - there is **no session table**, so every
  session is lost on restart, by design (`auth.rs:87-91`).
- **TTL:** default 24h; configurable via `with_ttl` (`auth.rs:76,103-109`).
- **Secret:** `PROPOLIS_CONSOLE_SESSION_SECRET` (64 hex chars / 32 bytes) if set, else a
  freshly generated secret at startup - which, combined with the in-memory store, means a
  restart invalidates all existing cookies.

Cookie attributes (`crates/console/src/routes/login.rs:111-119`):

| Attribute | Value |
|---|---|
| `HttpOnly` | always |
| `SameSite` | `Strict`, always |
| `Secure` | set **unless** the peer is loopback (`!peer_ip.is_loopback()`) |
| `Path` | `/` |
| `Max-Age` | tracks the store TTL |

## Login flow

`login_submit` (`routes/login.rs`), in order:

1. Extract the peer IP from `ConnectInfo<SocketAddr>`, which `console::server::serve`
   inserts on every request. Served any other way, `ConnectInfo` extraction **fails
   closed** on every login.
2. **Rate-limit check first** (per source and global, below) - on block,
   `429 Too Many Requests` with the form re-rendered.
3. **Password verify**, bounded: Argon2id runs on the blocking pool, at most two
   verifications at once (`MAX_CONCURRENT_VERIFICATIONS`). An attempt that cannot get a
   slot within 5 seconds is not checked at all and gets `503` ("Login is busy"); a wrong
   password gets `401 Unauthorized`.
4. On success - reset the rate limiter for that IP, create the session, set the cookie,
   redirect to `/`.

Logout (`GET /logout`) validates the cookie, **destroys the session server-side** via
`sessions.destroy`, then clears the client cookie. It is idempotent: it works with no
cookie, an expired session, or a tampered cookie (`login.rs:88-105`, `auth.rs:187-189`).
Destroying server-side matters - clearing only the client cookie would leave a captured
cookie value valid until its TTL elapsed.

## CSRF

- **Per-session token**, generated on first use and reused thereafter so multiple
  concurrently-open forms stay valid (`generate_csrf`, `auth.rs:160-167`): 32 random bytes,
  hex, stored on the `Session`.
- **Validated in constant time** via `subtle::ConstantTimeEq::ct_eq` (`validate_csrf`,
  `auth.rs:171-180`). Returns `false` if the session is absent or has no token generated
  yet (fail-closed).
- The token is surfaced to templates and embedded as `<meta name="csrf-token">` in
  `base_head.html`.
- **Enforced on every session-gated POST** - approve / reject / snooze / delist / delete
  and `POST /integrity/verify`. Each validates CSRF first and returns **403 Forbidden**
  ("invalid or missing csrf token") on failure. The chain verification mutates no state,
  but it scans the whole ledger, so another page must not be able to set it off; it also
  runs one at a time (`409` while one is in progress). The exact per-route CSRF column is
  in [../reference/console-routes.md](../reference/console-routes.md).

One deliberate CSRF omission, documented in source:

- **`POST /login` has no CSRF check.** No session exists pre-auth to bind a token to, and a
  forged login still needs the Argon2id-verified password, so it gains nothing; the login
  rate limiter is its defense (`login.rs`).

## Login rate limiting

A sliding-window limiter keyed by source IP, default **5 attempts / 60s**, plus a budget
of **30 attempts / 60s across all sources** (`RateLimiter::default`,
`DEFAULT_GLOBAL_LOGIN_ATTEMPTS` in `auth.rs`), per-IP history reset on successful login.
Load-bearing properties:

- **The global budget bounds distributed guessing.** Per-IP limits alone allow five guesses
  a minute from every address an attacker controls. The cost is deliberate: a sustained
  spray can keep the operator from logging in until it stops, which for a single-password
  console is preferable to an unbounded guessing rate.
- A **refused attempt is not recorded** in either window, so rejected retries cannot extend
  them, and a refused address never gains an entry in the per-IP map.
- **Memory-bound, fail-closed:** new per-IP entries are admitted only within the global
  budget; the map is also pruned of stale entries past 10,000 and refuses all attempts past
  50,000 as a backstop.
- **Counted:** `propolis_console_login_refused_per_ip_total`,
  `propolis_console_login_refused_global_total` and
  `propolis_console_login_verify_busy_total` on `/metrics` make a spray visible.
- **Keyed on the real TCP peer** via `ConnectInfo`; if that extraction fails, login fails
  closed.

## Authorization model

Authorization is coarse and binary: a request is either an authenticated operator session
(full access to the protected group) or it is not (redirected to login). There are no
roles or per-object permissions - the console serves a single trusted operator
([threat-model.md](threat-model.md)). The bind model backstops this: default
`127.0.0.1:8080` loopback-only, with the operator opting into a wider bind via
`PROPOLIS_CONSOLE_BIND` (`main.rs:118-121`). A wider bind without operator-provided TLS
and a network-layer restriction is a residual risk - see
[residual-risks.md](residual-risks.md).
