//! `GET /health` (liveness) and `GET /ready` (readiness). Both are mounted outside the auth
//! middleware (`internal/design/06-console-observability.md`, "Observability") - a monitoring
//! probe carries no session.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// Always 200: liveness only asks "is the process running and serving requests", never anything
/// about the database or other dependencies.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Pings Postgres, then asks the supervisor whether any subsystem has given up, and reports
/// 200/503 accordingly. Fail-closed: any DB error - a closed pool, a network error, a timeout -
/// reports not-ready rather than assuming health. A dead subsystem also reports not-ready: a
/// daemon whose intake or a sensor tailer has exhausted its restarts is serving pages against a
/// live database while collecting nothing, and a probe that only pinged the database called
/// that ready. The dead names are in the body so the probe's log says which.
async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(error) = sqlx::query("SELECT 1").execute(&state.db).await {
        tracing::warn!(%error, "readiness check: database ping failed");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "unavailable"})),
        )
            .into_response();
    }
    let gave_up = (state.gave_up_subsystems)();
    if !gave_up.is_empty() {
        tracing::warn!(
            ?gave_up,
            "readiness check: supervised subsystems have given up"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "unavailable", "gave_up": gave_up})),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({"status": "ok"}))).into_response()
}
