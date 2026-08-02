//! `GET /` - the dashboard's summary stats (`internal/design/06-console-observability.md`,
//! "Pages" > "Dashboard"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Six stat cards: three "core" numbers (`total_scored_ips`, `pending_reviews`, `approved_today`)
//! that fail the whole page closed via `AppError`/`?` on a query error, matching this page's
//! pre-existing behavior; and three supplementary ones (`events_last_hour`, `feed_entries`,
//! `top_attacker`) that soft-fail to their placeholder value instead - same reasoning as
//! `base_context`'s own doc comment: a transient hiccup on a nice-to-have widget should not take
//! down an otherwise-fine page render. `feed_entries` reads the feed publisher's `manifest.json`
//! tier counts via `routes::feed::read_manifest` (the same helper `routes::feed`/`routes::metrics`
//! already use), rather than re-parsing the file - see that function's doc comment for the on-disk
//! shape.

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
use crate::routes::feed::read_manifest;
use crate::routes::format::format_relative_time;

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

#[derive(Debug, Serialize)]
struct RecentEvent {
    relative_time: String,
    sensor: String,
    signal_type: String,
    source_ip: String,
}

#[derive(Debug, Serialize)]
struct ProtocolCount {
    sensor: String,
    count: i64,
}

async fn dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Html<String>, AppError> {
    let total_scored_ips: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_score")
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

    // Supplementary stats below: each soft-fails to its own placeholder rather than propagating,
    // per the module doc comment.
    let events_last_hour: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event WHERE observed_at >= now() - interval '1 hour'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let top_attacker: Option<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT host(source_ip), raw_score::text FROM ip_score ORDER BY raw_score DESC LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);
    let top_attacker_ip = top_attacker.as_ref().map(|t| t.0.as_str()).unwrap_or("--");
    let top_attacker_score = top_attacker.as_ref().map(|t| t.1.as_str()).unwrap_or("");

    let recent_event_rows = sqlx::query(
        "SELECT observed_at, sensor, signal_type::text, host(source_ip) AS source_ip \
         FROM event ORDER BY observed_at DESC LIMIT 20",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut recent_events = Vec::with_capacity(recent_event_rows.len());
    for row in recent_event_rows {
        let observed_at: chrono::DateTime<chrono::Utc> = row.try_get("observed_at")?;
        recent_events.push(RecentEvent {
            relative_time: format_relative_time(observed_at),
            sensor: row.try_get("sensor")?,
            signal_type: row.try_get("signal_type")?,
            source_ip: row.try_get("source_ip")?,
        });
    }

    let protocol_rows = sqlx::query(
        "SELECT sensor, COUNT(*) AS cnt FROM event \
         WHERE observed_at >= now() - interval '24 hours' \
         GROUP BY sensor ORDER BY cnt DESC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut protocol_dist = Vec::with_capacity(protocol_rows.len());
    for row in protocol_rows {
        protocol_dist.push(ProtocolCount {
            sensor: row.try_get("sensor")?,
            count: row.try_get("cnt")?,
        });
    }

    // -1 signals "no data" (unconfigured, missing, or unparsable manifest) -> the template
    // displays "--"; `read_manifest` already collapses every one of those cases to `None`.
    let feed_entries: i64 = state
        .feed_output_dir
        .as_deref()
        .and_then(read_manifest)
        .map(|m| (m.tiers.aggressive.count + m.tiers.standard.count) as i64)
        .unwrap_or(-1);

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
        pending_reviews => pending_count,
        approved_today,
        events_last_hour,
        feed_entries,
        top_attacker_ip,
        top_attacker_score,
        recent_events,
        protocol_dist,
        recent_submissions,
        pending_count,
        uptime,
        version,
    })?;
    Ok(Html(html))
}
