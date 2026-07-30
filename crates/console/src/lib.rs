//! Public API surface for `console`: the operator web console's library half (`src/main.rs`, the
//! binary entry point, is the thin env-config + wiring shell around this). Sub-project 6 task 1
//! wired the crate scaffold, password/session/CSRF/rate-limit auth (`auth`), and the
//! health/readiness endpoints (`routes`). Task 2 added the dashboard, review queue, and login
//! pages (`routes::dashboard`, `routes::queue`, `routes::login`) and the `templates` module that
//! renders them. Task 3 adds IP detail and feed status (`routes::detail`, `routes::feed`); task 4
//! adds `/metrics` (`routes::metrics`) and the binary itself. See
//! `internal/plans/2026-07-30-console-observability.md` and the canonical spec,
//! `internal/design/06-console-observability.md`.

pub mod auth;
pub mod routes;
pub mod templates;

use std::path::PathBuf;
use std::sync::Arc;

use minijinja::Environment;
use sqlx::PgPool;

use auth::{PasswordStore, RateLimiter, SessionStore};

/// Shared state handed to every route and to the auth middleware. `PgPool` clones cheaply (it is
/// already reference-counted internally); the other fields wrap an `RwLock` internally, which is
/// not itself `Clone`, so they are `Arc`-wrapped to make `AppState` cheaply cloneable per-request.
/// `templates` is built once at startup (`templates::environment`) rather than per-request: the
/// templates are static (embedded via `include_str!`), so re-parsing them on every request would
/// be pure waste.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub sessions: Arc<SessionStore>,
    pub passwords: Arc<PasswordStore>,
    pub login_rate_limiter: Arc<RateLimiter>,
    pub templates: Arc<Environment<'static>>,
    /// The feed publisher's output directory (`PROPOLIS_FEED_OUTPUT_DIR`), read by
    /// `routes::feed` and `routes::metrics` for `manifest.json`. `None` when unconfigured - the
    /// console and the `feed` binary are independently deployed services that share this
    /// directory by convention, not a required dependency (`routes::feed`'s own doc comment).
    pub feed_output_dir: Option<PathBuf>,
}
