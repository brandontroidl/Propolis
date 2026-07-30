//! Public API surface for `console`: the operator web console's library half (`src/main.rs`, the
//! binary entry point, lands in a later task). Sub-project 6 task 1 wires the crate scaffold,
//! password/session/CSRF/rate-limit auth (`auth`), and the health/readiness endpoints (`routes`).
//! Dashboard, review queue, IP detail, feed status, and `/metrics` land in later tasks - see
//! `internal/plans/2026-07-30-console-observability.md` and the canonical spec,
//! `internal/design/06-console-observability.md`.

pub mod auth;
pub mod routes;

use std::sync::Arc;

use sqlx::PgPool;

use auth::{PasswordStore, RateLimiter, SessionStore};

/// Shared state handed to every route and to the auth middleware. `PgPool` clones cheaply (it is
/// already reference-counted internally); the other fields wrap an `RwLock` internally, which is
/// not itself `Clone`, so they are `Arc`-wrapped to make `AppState` cheaply cloneable per-request.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub sessions: Arc<SessionStore>,
    pub passwords: Arc<PasswordStore>,
    pub login_rate_limiter: Arc<RateLimiter>,
}
