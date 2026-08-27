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
//! Charts + the most-active strip (sub-project 6, console-charts): two Chart.js charts (events
//! timeline, protocol distribution) and the "most active" table, whose per-IP 24-hour activity
//! strips (`most_active_rows`) replaced the old top-attackers bar chart - the chart duplicated
//! information the strip table shows better. All are fed by supplementary, soft-failing queries: a
//! slow or errored query degrades to an empty chart / the "waiting for sensor events" copy, never a
//! 503. Chart.js needs its datasets as JS array literals inside an inline `<script>`, so each array
//! is serialized with `serde_json::to_string` into a `String` *before* it reaches the template, then
//! injected with the `|safe` filter - `templates`'s doc comment establishes that minijinja
//! auto-escapes every `.html` template, so without `|safe` the JSON's own quotes would be
//! HTML-entity-escaped and produce a JS syntax error rather than an array literal. The events
//! timeline always renders (25 buckets, zero-filled by the query's own `generate_series`/`COALESCE`)
//! even with no events; the protocol-distribution chart instead hides its `<canvas>` and shows the
//! "waiting for sensor events" copy when `protocol_dist` is empty - an empty Chart.js canvas has
//! nothing worth looking at.

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
use crate::routes::format::{
    format_activity, format_relative_time, format_sensor_label, severity_rank, signal_severity,
    signal_tag_label,
};

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

/// One hourly cell of an IP's 24-hour activity strip. `height` is a pixel height derived from the
/// hour's event volume (sqrt-scaled so small-but-real hours stay visible); `class` is the strip
/// severity class (`s1`..`s4`, or empty for an idle hour) from the worst signal that hour.
#[derive(Debug, Serialize)]
struct StripCell {
    height: u32,
    class: &'static str,
}

/// A "what it did" severity tag for the most-active table.
#[derive(Debug, Serialize)]
struct SigTag {
    label: &'static str,
    sev: &'static str,
}

/// One row of the dashboard's "most active" table: an attacker IP with its 24-hour activity strip
/// and the worst signals it triggered.
#[derive(Debug, Serialize)]
struct MostActiveRow {
    ip: String,
    event_count: i64,
    last_seen: String,
    strip: Vec<StripCell>,
    tags: Vec<SigTag>,
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

    // Honest pipeline-health signal: the age of the most recent event. This is a real, verifiable
    // fact (intake wrote something this recently), never a hardcoded "OK" that could disagree with
    // reality. Fresh (< 1h) reads green; stale reads amber ("check sensors"). No events yet -> not
    // fresh, so a brand-new node does not claim health it cannot show.
    let last_event: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT max(observed_at) FROM event")
            .fetch_one(&state.db)
            .await
            .unwrap_or(None);
    let (last_event_ago, pipeline_fresh) = match last_event {
        Some(t) => (
            format_relative_time(t),
            (chrono::Utc::now() - t).num_minutes() < 60,
        ),
        None => ("none".to_string(), false),
    };

    // Rank by the live effective score (decayed to now), not the stored `raw_score` anchored at the
    // IP's last event - otherwise a long-idle high score outranks an active attacker. Matches the
    // detail page and the Attackers table (`LIVE_EFFECTIVE_SCORE_SQL`).
    // Audited: interpolates only the constant `LIVE_EFFECTIVE_SCORE_SQL`, never user input.
    let top_attacker: Option<(String, String)> =
        sqlx::query_as::<_, (String, String)>(sqlx::AssertSqlSafe(format!(
            "SELECT host(source_ip), round(({frag})::numeric, 1)::text \
             FROM ip_score ORDER BY ({frag}) DESC LIMIT 1",
            frag = crate::routes::LIVE_EFFECTIVE_SCORE_SQL,
        )))
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

    // Default range: 25 hourly buckets covering the rolling 24h window (oldest and newest are
    // partial hours), oldest to newest, zero-filled where an hour had no events - always exactly 25
    // rows (the `generate_series` bound is unconditional), so the timeline chart and the events
    // sparkline below always have real (possibly all-zero) data, never an empty array.
    // `dashboard_chart_fragment` (below) reuses the same helper for the adjustable-range HTMX
    // endpoint the "1h/24h/7d/30d" buttons hit.
    let (timeline_labels, timeline_data) = hourly_series(&state.db).await;
    // The status band's "Events / 24h" cell: the buckets and the event filter now share the same
    // `now() - 24h` lower bound, so their sum is the EXACT rolling-24h total (no in-window event
    // falls outside a bucket) at no extra query cost.
    let events_24h: i64 = timeline_data.iter().sum();
    let current_range = "24h";

    // The "most active" table with its 24-hour activity strips - the signature dashboard element.
    // Soft-fails to empty (shows the waiting-for-events copy) rather than 503 on a query error.
    let most_active = most_active_rows(&state.db).await;

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

    let tmpl = state.templates.get_template("dashboard.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "dashboard",
        total_scored_ips,
        pending_reviews => pending_count,
        approved_today,
        events_last_hour,
        events_24h,
        last_event_ago,
        pipeline_fresh,
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
        most_active,
        pending_count,
        uptime,
        version,
        current_range,
    })?;
    Ok(Html(html))
}

/// The top attacker IPs of the last 24 hours, each with a 24-cell hourly activity strip (worst
/// signal per hour drives the cell colour, event volume its height) and its worst signals as
/// severity tags. Soft-fails to an empty vec on any query error, per the module's chart policy.
async fn most_active_rows(db: &PgPool) -> Vec<MostActiveRow> {
    use std::collections::{BTreeSet, HashMap};

    // One pass: the busiest few source IPs in the window, joined back to their own events grouped by
    // hour, with the distinct signal types seen in each hour so the strip can colour each cell by
    // the worst signal that hour rather than only the IP's overall worst.
    let rows = sqlx::query(
        "WITH top AS ( \
             SELECT source_ip, COUNT(*) AS cnt, MAX(observed_at) AS last_seen \
             FROM event WHERE observed_at >= now() - interval '24 hours' \
             GROUP BY source_ip ORDER BY cnt DESC, MAX(observed_at) DESC LIMIT 6 \
         ) \
         SELECT host(t.source_ip) AS ip, t.cnt, t.last_seen, \
                (EXTRACT(EPOCH FROM (date_trunc('hour', now()) - date_trunc('hour', e.observed_at))) / 3600)::int AS hours_ago, \
                COUNT(*) AS hr_cnt, \
                array_agg(DISTINCT e.signal_type::text) AS hr_sigs \
         FROM top t \
         JOIN event e ON e.source_ip = t.source_ip AND e.observed_at >= now() - interval '24 hours' \
         GROUP BY t.source_ip, t.cnt, t.last_seen, date_trunc('hour', e.observed_at) \
         ORDER BY t.cnt DESC, hours_ago",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    struct Acc {
        cnt: i64,
        last_seen: chrono::DateTime<chrono::Utc>,
        hours: HashMap<i32, (i64, u8)>, // hours_ago -> (event count, worst severity rank)
        sigs: BTreeSet<String>,
        order: usize,
    }
    let mut accs: HashMap<String, Acc> = HashMap::new();
    let mut next_order = 0usize;
    for row in &rows {
        let Ok(ip) = row.try_get::<String, _>("ip") else {
            continue;
        };
        let Ok(last_seen) = row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_seen") else {
            continue;
        };
        let cnt: i64 = row.try_get("cnt").unwrap_or(0);
        let hours_ago: i32 = row.try_get("hours_ago").unwrap_or(-1);
        let hr_cnt: i64 = row.try_get("hr_cnt").unwrap_or(0);
        let hr_sigs: Vec<String> = row.try_get("hr_sigs").unwrap_or_default();
        let worst = hr_sigs
            .iter()
            .map(|s| severity_rank(signal_severity(s)))
            .max()
            .unwrap_or(0);
        let acc = accs.entry(ip).or_insert_with(|| {
            let o = next_order;
            next_order += 1;
            Acc {
                cnt,
                last_seen,
                hours: HashMap::new(),
                sigs: BTreeSet::new(),
                order: o,
            }
        });
        if (0..24).contains(&hours_ago) {
            acc.hours.insert(hours_ago, (hr_cnt, worst));
        }
        acc.sigs.extend(hr_sigs);
    }

    let mut result: Vec<(usize, MostActiveRow)> = accs
        .into_iter()
        .map(|(ip, acc)| {
            let max_hr = acc
                .hours
                .values()
                .map(|(c, _)| *c)
                .max()
                .unwrap_or(1)
                .max(1);
            // 24 cells, oldest (left) to newest (right): cell h is the hour (23 - h) hours ago.
            let strip = (0..24)
                .map(|h| match acc.hours.get(&(23 - h)) {
                    Some((c, sev)) if *c > 0 => {
                        let frac = (*c as f64).sqrt() / (max_hr as f64).sqrt();
                        StripCell {
                            height: (2.0 + 24.0 * frac).round() as u32,
                            class: match *sev {
                                4 => "s4",
                                3 => "s3",
                                2 => "s2",
                                1 => "s1",
                                _ => "",
                            },
                        }
                    }
                    _ => StripCell {
                        height: 2,
                        class: "",
                    },
                })
                .collect();
            let mut tags: Vec<SigTag> = acc
                .sigs
                .iter()
                .map(|s| SigTag {
                    label: signal_tag_label(s),
                    sev: signal_severity(s),
                })
                .collect();
            tags.sort_by_key(|t| std::cmp::Reverse(severity_rank(t.sev)));
            tags.truncate(3);
            (
                acc.order,
                MostActiveRow {
                    ip,
                    event_count: acc.cnt,
                    last_seen: format_relative_time(acc.last_seen),
                    strip,
                    tags,
                },
            )
        })
        .collect();
    result.sort_by_key(|(o, _)| *o);
    result.into_iter().map(|(_, r)| r).collect()
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

/// 25 hourly buckets covering the rolling 24h window (oldest to newest, zero-filled), site-wide -
/// the dashboard timeline's default range and the "24h" range-selector button. The bucket series
/// and the event filter share one `now() - 24h` lower bound, so the oldest and newest buckets are
/// partial hours and every event within the rolling 24h lands in exactly one bucket (the previous
/// hour-aligned `date_trunc('hour', now()) - 23h` series dropped a whole hour of in-window events at
/// each hour boundary). Soft-fails to two empty vectors on a query error, per the module doc
/// comment's chart policy.
async fn hourly_series(db: &PgPool) -> (Vec<String>, Vec<i64>) {
    let rows = sqlx::query(
        "SELECT bucket, COALESCE(cnt, 0) AS cnt \
         FROM generate_series( \
             date_trunc('hour', now() - interval '24 hours'), \
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
