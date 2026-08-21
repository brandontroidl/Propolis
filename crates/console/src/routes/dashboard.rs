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
//!
//! Charts and sparklines (sub-project 6, console-charts): three Chart.js charts (events timeline,
//! protocol distribution, top attackers) and two SVG sparklines (`routes::sparkline::render`, in
//! the "Events / hour" and "Total scored IPs" stat cards), all fed by supplementary,
//! soft-failing queries per the same policy as above - a slow or errored chart query degrades to
//! an empty chart/flat sparkline, never a 503. Chart.js needs its datasets as JS array literals
//! inside an inline `<script>`, so each array is serialized with `serde_json::to_string` into a
//! `String` *before* it reaches the template, then injected with the `|safe` filter - `templates`'s
//! doc comment establishes that minijinja auto-escapes every `.html` template, so without `|safe`
//! the JSON's own quotes would be HTML-entity-escaped and produce a JS syntax error rather than an
//! array literal. `protocol_dist` (a `Vec`, already in context for its own truthiness check) stays
//! as-is; `proto_labels`/`proto_data` are new, separately-named JSON-string siblings derived from
//! it. The events timeline always renders (24 buckets, zero-filled by the query's own
//! `generate_series`/`COALESCE`) even with no events; the protocol-distribution and top-attackers
//! charts instead hide their `<canvas>` and show the same "waiting for sensor events" copy the
//! page already uses elsewhere when their source list is empty (`protocol_dist` and the new
//! `has_attackers` respectively) - an empty Chart.js canvas has nothing worth looking at.

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::{Extension, Router};
use minijinja::context;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;
use crate::routes::feed::read_manifest;
use crate::routes::format::{format_activity, format_relative_time, format_sensor_label};
use crate::routes::sparkline;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard/chart", get(dashboard_chart_fragment))
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
    activity: String,
    source_ip: String,
}

#[derive(Debug, Serialize)]
struct ProtocolCount {
    label: String,
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
        let sensor: String = row.try_get("sensor")?;
        let signal_type: String = row.try_get("signal_type")?;
        recent_events.push(RecentEvent {
            relative_time: format_relative_time(observed_at),
            activity: format_activity(&sensor, &signal_type),
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
        let sensor: String = row.try_get("sensor")?;
        protocol_dist.push(ProtocolCount {
            label: format_sensor_label(&sensor),
            count: row.try_get("cnt")?,
        });
    }
    let proto_labels: Vec<String> = protocol_dist.iter().map(|p| p.label.clone()).collect();
    let proto_data: Vec<i64> = protocol_dist.iter().map(|p| p.count).collect();

    // Default range: 24 hourly buckets, oldest to newest, zero-filled where an hour had no events
    // - always exactly 24 rows (the `generate_series` bound is unconditional), so the timeline
    // chart and the events sparkline below always have real (possibly all-zero) data, never an
    // empty array. `dashboard_chart_fragment` (below) reuses the same helper for the
    // adjustable-range HTMX endpoint the "1h/24h/7d/30d" buttons hit.
    let (timeline_labels, timeline_data) = hourly_series(&state.db).await;
    // The status band's "Events / 24h" cell: the 24 hourly buckets are already computed and
    // zero-filled, so their sum is the day's total at no extra query cost.
    let events_24h: i64 = timeline_data.iter().sum();
    let current_range = "24h";

    let attacker_rows = sqlx::query(
        "SELECT host(source_ip) AS ip, raw_score::float8 AS score, event_count \
         FROM ip_score ORDER BY raw_score DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut attacker_labels: Vec<String> = Vec::with_capacity(attacker_rows.len());
    let mut attacker_data: Vec<f64> = Vec::with_capacity(attacker_rows.len());
    for row in &attacker_rows {
        let ip: String = row.try_get("ip")?;
        let count: i32 = row.try_get("event_count")?;
        attacker_labels.push(format!("{ip} ({count})"));
        attacker_data.push(row.try_get("score")?);
    }
    // Drives the top-attackers chart's empty-state gate in the template: `attacker_labels` is
    // JSON-stringified below, and a non-empty JSON string (even `"[]"`) is truthy in minijinja, so
    // the template cannot tell "no rows" from "some rows" by checking that string directly.
    let has_attackers = !attacker_labels.is_empty();

    // 7-day cumulative trend for the "Total scored IPs" sparkline: a running total (not a daily
    // delta), so its rightmost point matches the stat card's own displayed value - the same
    // reasoning the stat-tile convention in the dataviz skill gives for a sparkline's trend arm.
    // `ip_score` has no index on `first_seen`, so each of the 7 correlated-subquery evaluations
    // below is a sequential scan; fine at this project's single-node scale (a dashboard an
    // operator loads occasionally, not a hot path) - a single-pass running-sum rewrite is not
    // worth the added complexity here.
    let scored_trend_rows = sqlx::query(
        "SELECT bucket::date, (SELECT COUNT(*) FROM ip_score WHERE first_seen <= bucket + interval '1 day') AS cnt \
         FROM generate_series(current_date - interval '6 days', current_date, interval '1 day') AS bucket \
         ORDER BY bucket",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut scored_trend_data: Vec<i64> = Vec::with_capacity(scored_trend_rows.len());
    for row in scored_trend_rows {
        scored_trend_data.push(row.try_get("cnt")?);
    }

    let events_sparkline = sparkline::render(&timeline_data, 120, 24, "#3987e5");
    let scored_sparkline = sparkline::render(&scored_trend_data, 120, 24, "#3987e5");

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

    // Shadowed into their JSON-string form right before the template needs them - see the module
    // doc comment for why a string (rendered with `|safe`) rather than a native minijinja list.
    let timeline_labels = serde_json::to_string(&timeline_labels).unwrap_or_else(|_| "[]".into());
    let timeline_data = serde_json::to_string(&timeline_data).unwrap_or_else(|_| "[]".into());
    let proto_labels = serde_json::to_string(&proto_labels).unwrap_or_else(|_| "[]".into());
    let proto_data = serde_json::to_string(&proto_data).unwrap_or_else(|_| "[]".into());
    let attacker_labels = serde_json::to_string(&attacker_labels).unwrap_or_else(|_| "[]".into());
    let attacker_data = serde_json::to_string(&attacker_data).unwrap_or_else(|_| "[]".into());

    let tmpl = state.templates.get_template("dashboard.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "dashboard",
        total_scored_ips,
        pending_reviews => pending_count,
        approved_today,
        events_last_hour,
        events_24h,
        feed_entries,
        top_attacker_ip,
        top_attacker_score,
        recent_events,
        protocol_dist,
        recent_submissions,
        timeline_labels,
        timeline_data,
        proto_labels,
        proto_data,
        attacker_labels,
        attacker_data,
        has_attackers,
        events_sparkline,
        scored_sparkline,
        pending_count,
        uptime,
        version,
        current_range,
    })?;
    Ok(Html(html))
}

/// `GET /dashboard/chart?range=<1h|24h|7d|30d>` - the range-selector HTMX endpoint for the
/// dashboard's events timeline chart. Renders the same fragment template `dashboard`'s initial
/// page load includes, so the two never drift into two different chart markups.
async fn dashboard_chart_fragment(
    State(state): State<AppState>,
    Query(params): Query<ChartRangeQuery>,
) -> Result<Html<String>, AppError> {
    let current_range = normalize_dashboard_range(params.range.as_deref());
    let (labels, data) = match current_range {
        "1h" => five_minute_series(&state.db).await,
        "7d" => daily_series(&state.db, 6).await,
        "30d" => daily_series(&state.db, 29).await,
        _ => hourly_series(&state.db).await,
    };
    let timeline_labels = serde_json::to_string(&labels).unwrap_or_else(|_| "[]".into());
    let timeline_data = serde_json::to_string(&data).unwrap_or_else(|_| "[]".into());

    let tmpl = state
        .templates
        .get_template("dashboard_chart_fragment.html")?;
    let html = tmpl.render(context! {
        current_range,
        timeline_labels,
        timeline_data,
        // Emits the out-of-band range-selector swap; unset on the full-page render, which
        // includes this template inline and draws the selector itself.
        is_fragment => true,
    })?;
    Ok(Html(html))
}

#[derive(Debug, Deserialize)]
struct ChartRangeQuery {
    #[serde(default)]
    range: Option<String>,
}

/// Normalizes the `?range=` query param to one of the four range-selector buttons
/// (`templates/dashboard.html`'s `dashboard-chart-range` selector); anything else - missing,
/// malformed, or a value from a future/removed button - falls back to the same "24h" default
/// `dashboard`'s own initial render uses, rather than erroring on an operator-editable query string.
fn normalize_dashboard_range(raw: Option<&str>) -> &'static str {
    match raw {
        Some("1h") => "1h",
        Some("7d") => "7d",
        Some("30d") => "30d",
        _ => "24h",
    }
}

/// 24 hourly buckets (oldest to newest, zero-filled), site-wide - the dashboard timeline's default
/// range and the "24h" range-selector button. Soft-fails to two empty vectors on a query error,
/// per the module doc comment's chart policy.
async fn hourly_series(db: &PgPool) -> (Vec<String>, Vec<i64>) {
    let rows = sqlx::query(
        "SELECT bucket, COALESCE(cnt, 0) AS cnt \
         FROM generate_series( \
             date_trunc('hour', now()) - interval '23 hours', \
             date_trunc('hour', now()), \
             interval '1 hour' \
         ) AS bucket \
         LEFT JOIN ( \
             SELECT date_trunc('hour', observed_at) AS hour, COUNT(*) AS cnt \
             FROM event \
             WHERE observed_at >= now() - interval '24 hours' \
             GROUP BY hour \
         ) sub ON sub.hour = bucket \
         ORDER BY bucket",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut labels = Vec::with_capacity(rows.len());
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let (Ok(bucket), Ok(cnt)) = (
            row.try_get::<chrono::DateTime<chrono::Utc>, _>("bucket"),
            row.try_get::<i64, _>("cnt"),
        ) else {
            continue;
        };
        labels.push(bucket.format("%H:00").to_string());
        data.push(cnt);
    }
    (labels, data)
}

/// `days + 1` daily buckets (oldest to newest, zero-filled), site-wide - the "7d"/"30d"
/// range-selector buttons.
async fn daily_series(db: &PgPool, days: i32) -> (Vec<String>, Vec<i64>) {
    let rows = sqlx::query(
        "SELECT bucket::date AS bucket, COALESCE(cnt, 0) AS cnt \
         FROM generate_series(current_date - ($1::int * interval '1 day'), current_date, interval '1 day') AS bucket \
         LEFT JOIN ( \
             SELECT date_trunc('day', observed_at)::date AS day, COUNT(*) AS cnt \
             FROM event \
             WHERE observed_at >= current_date - ($1::int * interval '1 day') \
             GROUP BY day \
         ) sub ON sub.day = bucket::date \
         ORDER BY bucket",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut labels = Vec::with_capacity(rows.len());
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let (Ok(bucket), Ok(cnt)) = (
            row.try_get::<chrono::NaiveDate, _>("bucket"),
            row.try_get::<i64, _>("cnt"),
        ) else {
            continue;
        };
        labels.push(bucket.format("%b %-d").to_string());
        data.push(cnt);
    }
    (labels, data)
}

/// 12 five-minute buckets (oldest to newest, zero-filled), site-wide - the "1h" range-selector
/// button, the one range finer than an hourly bucket. `date_bin` (PostgreSQL 14+; this project
/// targets current PostgreSQL - see `.github/workflows/ci.yml`'s `postgres:18` service image)
/// aligns each bucket to a fixed 5-minute grid from an arbitrary UTC origin, the same way
/// `date_trunc('hour', ..)` aligns the other ranges to the hour - without a shared origin, "now"
/// rounded down to the nearest 5 minutes would drift by up to 4 minutes between the
/// `generate_series` bound and each row's own bucket, silently misaligning some events into the
/// wrong bucket.
async fn five_minute_series(db: &PgPool) -> (Vec<String>, Vec<i64>) {
    let rows = sqlx::query(
        "SELECT bucket, COALESCE(cnt, 0) AS cnt \
         FROM generate_series( \
             date_bin('5 minutes', now(), TIMESTAMPTZ '2000-01-01 00:00:00+00') - interval '55 minutes', \
             date_bin('5 minutes', now(), TIMESTAMPTZ '2000-01-01 00:00:00+00'), \
             interval '5 minutes' \
         ) AS bucket \
         LEFT JOIN ( \
             SELECT date_bin('5 minutes', observed_at, TIMESTAMPTZ '2000-01-01 00:00:00+00') AS slot, COUNT(*) AS cnt \
             FROM event \
             WHERE observed_at >= now() - interval '1 hour' \
             GROUP BY slot \
         ) sub ON sub.slot = bucket \
         ORDER BY bucket",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut labels = Vec::with_capacity(rows.len());
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let (Ok(bucket), Ok(cnt)) = (
            row.try_get::<chrono::DateTime<chrono::Utc>, _>("bucket"),
            row.try_get::<i64, _>("cnt"),
        ) else {
            continue;
        };
        labels.push(bucket.format("%H:%M").to_string());
        data.push(cnt);
    }
    (labels, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dashboard_range_accepts_known_values_and_defaults_to_24h() {
        assert_eq!(normalize_dashboard_range(Some("1h")), "1h");
        assert_eq!(normalize_dashboard_range(Some("24h")), "24h");
        assert_eq!(normalize_dashboard_range(Some("7d")), "7d");
        assert_eq!(normalize_dashboard_range(Some("30d")), "30d");
        assert_eq!(normalize_dashboard_range(Some("bogus")), "24h");
        assert_eq!(normalize_dashboard_range(None), "24h");
    }
}
