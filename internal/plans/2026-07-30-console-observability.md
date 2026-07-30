# Web Console + Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 6 - a single Rust crate (`crates/console`) providing a loopback-bound operator web console (axum + minijinja + HTMX), password authentication with CSRF, and observability endpoints (health, readiness, Prometheus metrics).

**Architecture:** Server-rendered HTML with HTMX for dynamic updates. The console reads ip_score projections and review_queue entries, and drives the review queue's approve/reject/snooze API. Templates are embedded in the binary. Auth is single-operator password with Argon2 + HMAC sessions. Canonical spec: `internal/design/06-console-observability.md`.

**Tech Stack:** Rust (2024 edition), `axum` (web framework), `minijinja` (templates), `tokio`, `sqlx`, `core-scoring`, `review`, `argon2` (password hashing), `hmac`+`sha2` (session cookies), `metrics`+`metrics-exporter-prometheus`, `tracing`+`tracing-subscriber`.

## Global Constraints

- **Rust 2024 edition.** New crate at `crates/console`.
- **Loopback only.** Default bind to 127.0.0.1:8080. Never bind a public address without explicit config.
- **Auth required.** All pages except /health, /ready, /metrics, and /login require authentication.
- **CSRF on all mutating forms.** Every POST has a CSRF token validated against the session.
- **No PII in error pages.** Generic error messages, no internal details.
- **Per-WAN attribution is internal-only.** Shown on the IP detail page, never in feed or vendor reports.
- **Tests require PostgreSQL** for DB-backed routes. Auth tests are pure (no DB).
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: Crate scaffold + auth + session management

**Files:**
- Create: `crates/console/Cargo.toml`, `crates/console/src/lib.rs`, `crates/console/src/auth.rs`, `crates/console/src/routes/mod.rs`, `crates/console/src/routes/health.rs`
- Modify: `Cargo.toml` (add `console` to workspace members)
- Test: `crates/console/tests/auth_test.rs`

**Interfaces:**
- Produces: `PasswordStore::new(plaintext) -> Self` (hashes with Argon2, discards plaintext), `PasswordStore::verify(attempt) -> bool`, `SessionStore` (in-memory HashMap), `create_session() -> (session_id, cookie_value)`, `validate_session(cookie) -> Option<Session>`, `generate_csrf() -> String`, `validate_csrf(session, token) -> bool`, `login_rate_limiter`.
- Also: `/health` returns 200, `/ready` pings DB (200 or 503).

Tests: password hash/verify, session create/validate/expire, CSRF generate/validate, rate limiter blocks after 5 attempts, /health returns 200.

---

### Task 2: Dashboard + review queue pages

**Files:**
- Create: `crates/console/src/routes/dashboard.rs`, `crates/console/src/routes/queue.rs`, `crates/console/src/templates/` (base.html, dashboard.html, queue.html, queue_row.html, login.html)
- Test: `crates/console/tests/routes_test.rs`

**Interfaces:**
- Consumes: `core_scoring::read_score`, `review::queue::ReviewQueue`, `sqlx::PgPool`, session/auth from Task 1.
- Produces: GET / (dashboard with stats), GET /queue (pending entries table), POST /queue/:ip/approve|reject|snooze (HTMX partial row update), GET /login, POST /login.

Templates use minijinja with auto-escaping. HTMX loaded from a CDN-free inline script (no external dependencies). Base template includes nav, CSRF meta tag, HTMX script.

Tests: dashboard returns 200 with stats, queue lists pending entries, approve changes state (verified via DB), unauthenticated request redirects to /login, CSRF-less POST returns 403.

---

### Task 3: IP detail page + feed status

**Files:**
- Create: `crates/console/src/routes/detail.rs`, `crates/console/src/routes/feed.rs`, `crates/console/src/templates/detail.html`, `crates/console/src/templates/feed.html`
- Test: added to `routes_test.rs`

**Interfaces:**
- Consumes: event ledger (for evidence timeline), ip_score, review_queue, vendor_submission, feed manifest.json.
- Produces: GET /ip/:ip (evidence timeline, per-WAN breakdown, category chart, submission history), GET /feed (last build, entry counts, next build).

The evidence timeline queries the event table directly for the given IP (last N events, ordered by observed_at DESC). Per-WAN breakdown is a GROUP BY wan_ip query. Both are read-only.

Tests: detail page shows events for a seeded IP, 404 for unknown IP, feed page reads manifest.json correctly.

---

### Task 4: Metrics endpoint + binary + deployment

**Files:**
- Create: `crates/console/src/main.rs`, `deploy/console.service`
- Modify: `crates/console/src/routes/health.rs` (add /metrics)
- Modify: `crates/sensor-framework/tests/deploy_test.rs` (add console unit test)
- Test: metrics format test

**Interfaces:**
- Produces: GET /metrics (Prometheus text format with propolis_* metrics), the `console` binary, hardened systemd unit.

The binary initializes tracing, connects to the DB, hashes the password, builds the axum router, and serves. The systemd unit binds loopback only, with MemoryDenyWriteExecute=yes.

After adding dependencies, re-vendor. Commit vendor changes separately.

Tests: /metrics returns valid Prometheus format, deploy test verifies unit hardening directives.
