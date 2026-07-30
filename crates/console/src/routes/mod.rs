//! Axum router composition. `/health`, `/ready`, and `/login` are public - no session required.
//! Every other route (dashboard, queue) is mounted in a `protected` group wrapped in
//! [`crate::auth::require_session`] via `Router::route_layer`, so a new page added in a later task
//! only needs to `.merge()` into `protected` below to be session-gated automatically.

pub mod dashboard;
pub mod error;
pub mod health;
pub mod login;
pub mod queue;

use axum::Router;
use axum::middleware;

use crate::AppState;
use crate::auth::require_session;

/// Builds the full console router for the given state.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .merge(dashboard::router())
        .merge(queue::router())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    Router::new()
        .merge(health::router())
        .merge(login::router())
        .merge(protected)
        .with_state(state)
}
