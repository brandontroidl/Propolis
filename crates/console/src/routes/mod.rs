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
pub(crate) mod degraded;
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

/// The live effective threat score, expressed in SQL, for ordering and displaying IPs by their
/// score AS OF NOW rather than by the stored `raw_score` - which is anchored at each IP's last
/// event via `decay_anchor`, so ordering by it ranks every IP at its own last-event moment and a
/// long-idle high score outranks an actively-attacking one.
///
/// This reproduces exactly what `routes::detail` displays and what `core_scoring::read_score`
/// projects: the stored `raw_score` decayed to now over the 6h half-life, then scaled by the
/// breadth factor and clamped to the score cap. Persistence is deliberately NOT folded in - the
/// detail page's effective score is `effective_score(read_score().raw_score, wan)`, which excludes
/// it (persistence lifts only the gate-facing score, never the displayed effective one), and these
/// ranking/display surfaces must agree with that page.
///
/// The literals mirror `core-scoring/src/scoring/constants.rs` (`HALF_LIFE_SECONDS` = 21600,
/// `BREADTH_PER_WAN` = 0.15, `BREADTH_CAP` = 0.60, `SCORE_CAP` = 100); the
/// `live_effective_score_sql_matches_core_scoring` test in `tests/routes_test.rs` guards them
/// against drift by comparing this expression to `core_scoring::effective_score` over real rows.
pub const LIVE_EFFECTIVE_SCORE_SQL: &str = "LEAST(100, raw_score * power(0.5, EXTRACT(EPOCH FROM (now() - decay_anchor)) / 21600.0) * (1.0 + LEAST(0.60, 0.15 * GREATEST(0, distinct_wan_count - 1))))";

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
