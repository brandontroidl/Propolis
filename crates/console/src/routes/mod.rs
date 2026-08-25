//! Axum router composition. `/health`, `/ready`, `/metrics`, `/login`, and `/assets/fonts/*` are
//! public - no session required (a monitoring probe or a Prometheus scraper carries no session; the
//! login page must load its fonts before a session exists; see `health`'s, `metrics`'s, and
//! `assets`'s own doc comments). Every other route (dashboard, queue, detail, feed) is mounted in
//! a `protected` group wrapped in [`crate::auth::require_session`] via `Router::route_layer`, so a
//! new page added in a later task only needs to `.merge()` into `protected` below to be
//! session-gated automatically.

pub mod assets;
pub(crate) mod context;
pub mod dashboard;
pub mod detail;
pub mod error;
pub mod feed;
mod format;
pub mod health;
pub mod integrity;
pub mod ips;
pub mod login;
pub mod logs;
pub mod metrics;
pub mod queue;
pub mod samples;
pub mod search;

use axum::Router;
use axum::middleware;

use crate::AppState;
use crate::auth::require_session;

/// Builds the full console router for the given state.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .merge(dashboard::router())
        .merge(queue::router())
        .merge(detail::router())
        .merge(feed::router())
        .merge(search::router())
        .merge(ips::router())
        .merge(integrity::router())
        .merge(samples::router())
        .merge(logs::router())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    Router::new()
        .merge(health::router())
        .merge(metrics::router())
        .merge(login::router())
        .merge(assets::router())
        .merge(protected)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(axum::http::header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    resp
}
