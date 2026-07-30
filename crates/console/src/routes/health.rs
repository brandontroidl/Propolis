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

/// Pings Postgres and reports 200/503 accordingly. Fail-closed: any error - a closed pool, a
/// network error, a timeout - reports not-ready rather than assuming health.
async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Err(error) => {
            tracing::warn!(%error, "readiness check: database ping failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "unavailable"})),
            )
                .into_response()
        }
    }
}
