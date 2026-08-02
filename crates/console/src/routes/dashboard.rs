//! `GET /` - the dashboard's summary stats (`internal/design/06-console-observability.md`,
//! "Pages" > "Dashboard"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Feed-tier entry counts (from the feed publisher's `manifest.json`) are deferred to Task 3
//! (`routes::feed`), which owns the feed-output-directory config this crate does not have yet -
//! see `internal/plans/2026-07-30-console-observability.md`.

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Extension, Router};
use minijinja::context;
use serde::Serialize;
use sqlx::Row;

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(dashboard))
}

#[derive(Debug, Serialize)]
struct RecentSubmission {
    source_ip: String,
    vendor: String,
    submitted_at: String,
    success: bool,
}

async fn dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Html<String>, AppError> {
    let total_scored_ips: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_score")
        .fetch_one(&state.db)
        .await?;

    let pending_reviews: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM review_queue WHERE state = 'pending'")
            .fetch_one(&state.db)
            .await?;

    // `current_date` is a DATE; Postgres implicitly casts it to a TIMESTAMPTZ at local-midnight
    // for the `>=` comparison against `decided_at` (matches the design spec's own query text).
    let approved_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM review_queue \
         WHERE state = 'approved' AND decided_at >= current_date",
    )
    .fetch_one(&state.db)
    .await?;

    let recent_rows = sqlx::query(
        "SELECT host(source_ip) AS source_ip, vendor, submitted_at, success \
         FROM vendor_submission ORDER BY submitted_at DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await?;

    let mut recent_submissions = Vec::with_capacity(recent_rows.len());
    for row in recent_rows {
        let submitted_at: chrono::DateTime<chrono::Utc> = row.try_get("submitted_at")?;
        recent_submissions.push(RecentSubmission {
            source_ip: row.try_get("source_ip")?,
            vendor: row.try_get("vendor")?,
            submitted_at: submitted_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            success: row.try_get("success")?,
        });
    }

    // A session is guaranteed here (this route sits behind `require_session`), so the page always
    // has a real CSRF token to display in `base.html`'s meta tag, matching every other
    // authenticated page - this route itself has no form that needs one.
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
    } = base_context(&state.db, state.startup_time, state.version).await;

    let tmpl = state.templates.get_template("dashboard.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "dashboard",
        total_scored_ips,
        pending_reviews,
        approved_today,
        recent_submissions,
        pending_count,
        uptime,
        version,
    })?;
    Ok(Html(html))
}
