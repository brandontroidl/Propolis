//! `GET /ip/:ip` - the IP detail page (`internal/design/06-console-observability.md`, "Pages" >
//! "IP detail"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Four read-only queries, all scoped to the one path-param IP:
//! - the score summary via `core_scoring::read_score` (decayed to now, same as `routes::queue`)
//!   plus `core_scoring::effective_score` for the breadth-adjusted number the blocklist
//!   recommendation gate actually uses;
//! - the evidence timeline: the last 50 `event` rows for this IP, newest first;
//! - the per-WAN breakdown: `event` rows GROUP BY `wan_ip` - internal-only attribution the
//!   operator sees here but that never reaches the feed or a vendor report (this design's own
//!   "Per-WAN attribution is internal-only");
//! - the category breakdown, derived from the already-fetched `IpScore.category_breakdown` (no
//!   extra query - it is the same JSON `routes::queue`'s `live_categories` reads, just kept as
//!   weight/confidence values here instead of collapsed to a category list);
//! - the submission history: `vendor_submission` rows for this IP.
//!
//! An IP with no `ip_score` row renders 404, matching the design's "Error handling": "Missing IP
//! ... returns 404." That is a normal, expected outcome (an operator following a stale link, or
//! guessing an IP), not a database/template failure, so it is handled directly rather than
//! through `AppError` (whose every variant renders a generic 503 - see that module's doc
//! comment): a 404 here says something true and specific, a 503 would not.

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{DateTime, Utc};
use core_scoring::{Category, Protocol, SignalType, effective_score, read_score};
use minijinja::context;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::AppState;
use crate::auth::Session;
use crate::routes::error::AppError;
use crate::routes::format::{format_timestamp, tier_label};

pub fn router() -> Router<AppState> {
    Router::new().route("/ip/{ip}", get(detail))
}

#[derive(Debug, Serialize)]
struct EvidenceRow {
    observed_at: String,
    sensor: String,
    signal_type: String,
    protocol: String,
    authenticated: bool,
    wan_ip: String,
}

#[derive(Debug, Serialize)]
struct WanRow {
    wan_ip: String,
    event_count: i64,
    has_authenticated: bool,
}

#[derive(Debug, Serialize)]
struct CategoryRow {
    category: String,
    weight: String,
    max_confidence: String,
}

#[derive(Debug, Serialize)]
struct SubmissionRow {
    submitted_at: String,
    vendor: String,
    categories: String,
    response_status: String,
    success: bool,
}

/// Mirrors the JSON shape of `core_scoring::scoring::engine::CategoryStat` (crate-private there -
/// see `queue.rs`'s `live_categories` for the same deserialize-a-local-shape approach applied to
/// just the category keys).
#[derive(Debug, Deserialize)]
struct CategoryStatView {
    weight: Decimal,
    max_confidence: Decimal,
}

async fn detail(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
) -> Result<Response, AppError> {
    let Some(score) = read_score(&state.db, ip).await? else {
        return Ok((StatusCode::NOT_FOUND, not_found_body(ip)).into_response());
    };

    let effective = effective_score(score.raw_score, score.distinct_wan_count as u32);
    let raw_f64 = score.raw_score.to_f64().unwrap_or(0.0);
    let effective_f64 = effective.to_f64().unwrap_or(0.0);

    let evidence_rows = sqlx::query(
        "SELECT host(wan_ip) AS wan_ip, sensor, signal_type, protocol, authenticated, observed_at \
         FROM event WHERE source_ip = $1::inet ORDER BY observed_at DESC LIMIT 50",
    )
    .bind(ip.to_string())
    .fetch_all(&state.db)
    .await?;
    let mut evidence = Vec::with_capacity(evidence_rows.len());
    for row in evidence_rows {
        let signal_type: SignalType = row.try_get("signal_type")?;
        let protocol: Protocol = row.try_get("protocol")?;
        let observed_at: DateTime<Utc> = row.try_get("observed_at")?;
        evidence.push(EvidenceRow {
            observed_at: format_timestamp(observed_at),
            sensor: row.try_get("sensor")?,
            signal_type: format!("{signal_type:?}"),
            protocol: format!("{protocol:?}"),
            authenticated: row.try_get("authenticated")?,
            wan_ip: row
                .try_get::<Option<String>, _>("wan_ip")?
                .unwrap_or_else(|| "-".to_string()),
        });
    }

    let wan_rows = sqlx::query(
        "SELECT host(wan_ip) AS wan_ip, COUNT(*) AS event_count, \
                bool_or(protocol = 'tcp' AND authenticated) AS has_authenticated \
         FROM event WHERE source_ip = $1::inet AND wan_ip IS NOT NULL \
         GROUP BY wan_ip ORDER BY event_count DESC",
    )
    .bind(ip.to_string())
    .fetch_all(&state.db)
    .await?;
    let mut per_wan = Vec::with_capacity(wan_rows.len());
    for row in wan_rows {
        per_wan.push(WanRow {
            wan_ip: row.try_get("wan_ip")?,
            event_count: row.try_get("event_count")?,
            has_authenticated: row
                .try_get::<Option<bool>, _>("has_authenticated")?
                .unwrap_or(false),
        });
    }

    let categories = category_rows(&score.category_breakdown);

    let submission_rows = sqlx::query(
        "SELECT vendor, categories, submitted_at, response_status, success \
         FROM vendor_submission WHERE source_ip = $1::inet ORDER BY submitted_at DESC",
    )
    .bind(ip.to_string())
    .fetch_all(&state.db)
    .await?;
    let mut submissions = Vec::with_capacity(submission_rows.len());
    for row in submission_rows {
        let submitted_at: DateTime<Utc> = row.try_get("submitted_at")?;
        let categories: Vec<String> = row.try_get("categories")?;
        let response_status: Option<i32> = row.try_get("response_status")?;
        submissions.push(SubmissionRow {
            submitted_at: format_timestamp(submitted_at),
            vendor: row.try_get("vendor")?,
            categories: categories.join(", "),
            response_status: response_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
            success: row.try_get("success")?,
        });
    }

    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();

    let tmpl = state.templates.get_template("detail.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "detail",
        ip => ip.to_string(),
        raw_score => format!("{:.1}", score.raw_score),
        raw_score_pct => raw_f64.clamp(0.0, 100.0).round() as u32,
        effective_score => format!("{:.1}", effective),
        effective_score_pct => effective_f64.clamp(0.0, 100.0).round() as u32,
        tier => score.tier.map(tier_label).unwrap_or("-"),
        eligible => score.eligible,
        recommended_for_vendor => score.recommended_for_vendor,
        recommended_for_blocklist => score.recommended_for_blocklist,
        has_confirmed_real => score.has_confirmed_real,
        event_count => score.event_count,
        distinct_categories => score.distinct_categories,
        distinct_wan_count => score.distinct_wan_count,
        distinct_sensor_count => score.distinct_sensor_count,
        max_confidence => format!("{:.3}", score.max_confidence),
        first_seen => format_timestamp(score.first_seen),
        last_seen => format_timestamp(score.last_seen),
        evidence,
        per_wan,
        categories,
        submissions,
    })?;
    Ok(Html(html).into_response())
}

/// Every category ever contributed for this IP, with its CURRENT (live-decayed) weight - not
/// filtered to only those still above the eligibility engine's 0.5 live floor. A category that
/// has since decayed away is still real evidence history; hiding it here would make the detail
/// page (the one place meant to show the full picture) less complete than the queue's own
/// category summary.
fn category_rows(breakdown: &serde_json::Value) -> Vec<CategoryRow> {
    let Ok(map) = serde_json::from_value::<BTreeMap<Category, CategoryStatView>>(breakdown.clone())
    else {
        return Vec::new();
    };
    map.into_iter()
        .map(|(category, stat)| CategoryRow {
            category: format!("{category:?}").to_lowercase(),
            weight: format!("{:.1}", stat.weight),
            max_confidence: format!("{:.3}", stat.max_confidence),
        })
        .collect()
}

/// `IpAddr::to_string()`/`Display` can only ever produce digits, `.`, and `:` - never an HTML
/// metacharacter - so interpolating it directly into a literal string here is safe by
/// construction, the same reasoning `routes::error`'s static `GENERIC_BODY` relies on for having
/// no interpolation at all.
fn not_found_body(ip: IpAddr) -> Html<String> {
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>IP not found</title>\
         <p style=\"font-family:sans-serif;padding:2rem\">No score projection found for {ip}. \
         It may not have been scored yet, or the IP was mistyped.</p>"
    ))
}
