//! Axum router composition. `/health` and `/ready` are public - no session required. Task 2 adds
//! the first session-gated routes (dashboard, queue) and, alongside them, a `protected` group
//! wrapped in [`crate::auth::require_session`] via `Router::route_layer`; that wiring is deferred
//! until there is at least one protected route because `route_layer` panics on a router with no
//! routes yet attached (axum's own documented behavior - see `vendor/axum/src/docs/routing/route_layer.md`).
//! Until then, [`crate::auth::require_session`] is exercised directly against a purpose-built test
//! router (`tests/auth_test.rs`), not through this composition.

pub mod health;

use axum::Router;

use crate::AppState;

/// Builds the full console router for the given state.
pub fn router(state: AppState) -> Router {
    Router::new().merge(health::router()).with_state(state)
}
