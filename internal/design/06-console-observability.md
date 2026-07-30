# Sub-project 6: web console + observability

Detailed design spec for the Propolis-new operator console and observability layer (Rust). The
console is a single-operator, loopback-bound web interface for reviewing recommended IPs, acting on
the approval gate, and inspecting evidence. The observability layer provides structured logging,
metrics, and health/readiness endpoints.

## Purpose and scope

This layer owns four things and nothing else:

1. The operator web console: a server-rendered HTML interface (axum + minijinja + HTMX) for
   reviewing recommended IPs, approving/rejecting/snoozing, inspecting per-IP evidence and per-WAN
   breadth, and monitoring feed status. Binds loopback only by default.
2. Authentication and CSRF: a single-operator password-based session with Argon2 hashing, HMAC
   session cookies, and CSRF tokens on all mutating forms.
3. Observability endpoints: /health (liveness), /ready (readiness - DB connectivity, fail-closed),
   /metrics (Prometheus text format).
4. Structured logging integration: tracing-based logging with secret and PII redaction for all
   crates in the workspace.

This layer has no sensor, no intake, no vendor client, and no feed publisher. It reads ip_score
projections and review_queue entries from the database (read-only for scoring data, read-write for
review queue state transitions via the review crate's API).

## Architecture

One crate, added to the workspace:

- `crates/console` - the web console binary. Depends on `core-scoring` (IpScore, read_score),
  `review` (ReviewQueue, approve/reject/snooze), `axum`, `minijinja`, `tokio`, `sqlx`, `tracing`,
  `argon2`, `hmac`+`sha2`, `metrics`+`metrics-exporter-prometheus`.

### Crate structure

```
crates/console/
  Cargo.toml
  src/
    lib.rs              # public API (for tests)
    main.rs             # binary entry point
    auth.rs             # password verification, session management, CSRF
    routes/
      mod.rs            # axum Router composition
      dashboard.rs      # GET / - summary stats
      queue.rs          # GET /queue, POST /queue/:ip/approve|reject|snooze
      detail.rs         # GET /ip/:ip - evidence, breadth, submissions
      feed.rs           # GET /feed - feed status
      health.rs         # GET /health, /ready, /metrics
    templates/
      base.html         # base layout with nav, HTMX script
      dashboard.html    # dashboard template
      queue.html        # review queue table
      queue_row.html    # HTMX partial for single row update
      detail.html       # IP detail page
      feed.html         # feed status page
      login.html        # login form
  tests/
    auth_test.rs        # session creation, CSRF validation
    routes_test.rs      # HTTP request/response testing via axum::test
```

## Pages

### Dashboard (GET /)

Summary cards:
- Total scored IPs (count of ip_score rows)
- Pending reviews (count of review_queue WHERE state = 'pending')
- Approved today (count WHERE state = 'approved' AND decided_at >= today)
- Active feed entries per tier (count from last feed build, read from manifest.json)
- Recent submissions (last 10 vendor_submission rows)

### Review queue (GET /queue)

Table of pending review entries with columns: IP, raw score (decayed to now), tier, categories,
event count, first seen, last seen, actions (Approve/Reject/Snooze buttons).

Each action button uses HTMX to POST to `/queue/:ip/approve|reject|snooze` and replaces the row
with an updated version (showing the new state) without a full page reload.

Optional notes field on approve/reject (textarea, submitted with the action).

Sorting by score (descending, default), first seen, last seen, event count.

### IP detail (GET /ip/:ip)

- Score summary: raw score, effective score, tier, eligibility status, recommendation status
- Evidence timeline: recent events from the event ledger for this IP, with signal type, sensor,
  WAN IP, timestamp, and sanitized metadata
- Per-WAN breadth: breakdown of events by WAN IP (the internal attribution the operator sees but
  that never reaches the feed or vendor reports)
- Category breakdown: events per category with weight contribution
- Submission history: vendor_submission rows for this IP

Per-WAN attribution is internal-only. The detail page shows it; the feed and vendor reports do not.

### Feed status (GET /feed)

- Last build time (from manifest.json if present)
- Entry counts per tier
- Next scheduled build (based on build interval)
- Links to download current feed files

### Login (GET /login, POST /login)

Simple password form. On success, sets a session cookie and redirects to /. On failure, re-renders
the form with an error message. No username field (single operator).

## Authentication

### Password storage

The operator sets the password via the `PROPOLIS_CONSOLE_PASSWORD` environment variable. On startup,
the console hashes it with Argon2id and discards the plaintext. The hash is held in memory only,
never written to disk or database.

### Sessions

On successful login, the console creates a session with:
- A random session ID (32 bytes, from OsRng)
- An HMAC-SHA256 tag over the session ID using a server-side secret key
- Stored in an in-memory HashMap (no database session table - single operator, restart clears sessions)

The session cookie is HttpOnly, Secure (when not on localhost), SameSite=Strict, with a configurable
TTL (default 24h).

### CSRF

Every form includes a hidden CSRF token. The token is a random value stored in the session. On
form submission, the token is validated against the session. Requests without a valid CSRF token
are rejected with 403.

### Rate limiting

Login attempts are rate-limited to 5 per minute per source IP (in-memory counter, reset on success).
This prevents brute-force attacks against the operator password.

## Observability

### Health (GET /health)

Returns HTTP 200 with body `{"status":"ok"}`. Always succeeds if the process is running. Used as a
liveness probe.

### Readiness (GET /ready)

Pings the PostgreSQL database. Returns HTTP 200 if the ping succeeds, HTTP 503 if it fails.
Fail-closed: any error during the ping returns 503. Used as a readiness probe.

### Metrics (GET /metrics)

Prometheus text format. Key metrics:
- `propolis_events_ingested_total` (counter, by sensor)
- `propolis_events_rejected_total` (counter, by reason)
- `propolis_ips_scored` (gauge)
- `propolis_ips_eligible` (gauge)
- `propolis_ips_recommended_vendor` (gauge)
- `propolis_ips_recommended_blocklist` (gauge)
- `propolis_review_queue_pending` (gauge)
- `propolis_vendor_submissions_total` (counter, by vendor, by status)
- `propolis_feed_entries` (gauge, by tier)
- `propolis_feed_last_build_timestamp` (gauge, unix seconds)

Metrics are derived from database queries on each /metrics scrape (not pre-computed). This is
acceptable at the expected scrape interval (15-60 seconds) and avoids stale counters.

### Structured logging

All crates already use `tracing` for structured logging. The console binary initializes
`tracing-subscriber` with a JSON formatter for production and a human-readable formatter for
development. Secret and PII redaction is handled by the existing `sanitize_value` function in
sensor-framework (attacker-controlled content is already sanitized at capture time).

## Configuration

```rust
pub struct ConsoleConfig {
    pub database_url: String,
    pub bind_addr: SocketAddr,          // default 127.0.0.1:8080
    pub password: String,               // from env, hashed on startup, plaintext discarded
    pub session_secret: [u8; 32],       // from env or generated on startup
    pub session_ttl: Duration,          // default 24h
    pub feed_output_dir: Option<PathBuf>,  // to read manifest.json for feed status
}
```

Loaded from environment variables.

## Error handling

- Database errors on page loads render an error page (not a raw 500). The error message is generic
  ("Service unavailable") - no internal details exposed.
- Authentication failures return to the login page with a generic "Invalid password" message.
- CSRF failures return 403 with a generic message.
- Missing IP (detail page for an IP not in the database) returns 404.

## Testing strategy

- **Auth tests:** password verification, session creation/validation, CSRF token generation/
  validation, expired session rejection, rate limiting.
- **Route tests:** use axum's built-in test utilities to make HTTP requests and verify responses
  without starting a real server. Verify: dashboard returns 200 with stats, queue returns pending
  entries, approve/reject/snooze change state, detail page shows evidence, unauthenticated requests
  redirect to login.
- **Observability tests:** /health returns 200, /ready returns 200 when DB is up and 503 when
  down, /metrics returns valid Prometheus text format.

## Decisions closed by this spec

1. Web framework: **axum** (tokio-native).
2. Rendering: **server-side HTML with minijinja + HTMX** (no JS build step).
3. Authentication: **single-operator password, Argon2id hash, HMAC session cookie**.
4. Bind model: **loopback only by default** (127.0.0.1:8080).
5. Metrics format: **Prometheus text format** via /metrics endpoint.
6. Session storage: **in-memory** (single operator, restart clears).

## Open questions - deferred

- Cluster bind model (which node serves the console, reverse proxy config) - sub-project 7.
- WebSocket for live event streaming - future enhancement.
- Multi-user support with roles - not needed for single operator.
