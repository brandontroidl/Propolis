//! `GET /search/events` and `GET /search/ips` - event-level and IP-level search across all
//! captured evidence (`internal/design/11-console-forensics.md`, section 3 "Search"). Session-gated:
//! mounted under the `protected` group in `routes::mod`.
//!
//! Both handlers share one filter set ([`Filters`]): free-text `q` (`metadata::text ILIKE`),
//! exact-match `sensor`/`signal_type`, `ip`, and a `from`/`to` `observed_at` range, all combined
//! with AND via the spec's `($n::type IS NULL OR ...)` SQL pattern - one prepared query handles
//! every filter combination without building the WHERE clause dynamically. At least one filter is
//! required: an entirely empty query is rejected (rendered as a "provide a filter" empty state,
//! never run against the database) to avoid an unbounded full-table scan - the same reasoning
//! `fetch_evidence_rows`'s page-size cap and `routes::queue`'s scoped queries apply elsewhere in
//! this crate.
//!
//! Event search reuses `routes::detail`'s cursor encoding (`format_cursor`/`parse_cursor`) for
//! its own `(observed_at, id)`-shaped `?cursor=` value, even though - per the design's literal
//! "Query pattern" for event search - only the `id` half is actually bound into the `id < $7`
//! predicate here; reusing the same encode/decode functions keeps every cursor in the console in
//! one format rather than inventing a second one for this one query. IP search does not paginate:
//! it is already capped at 50 aggregated rows (the design's own "sufficient for an aggregated
//! view").
//!
//! `search_events` doubles as the "Load more" HTMX endpoint: a request carrying the `HX-Request`
//! header gets back just the next batch of `<tr>`s plus an out-of-band replacement for the
//! load-more button (`search_events_fragment.html`, mirroring `events_fragment.html`'s own
//! two-swap split - see `routes::detail`'s module doc comment). A normal browser navigation (no
//! `HX-Request` header, including a bookmarked or manually-edited `?cursor=...` URL) always gets
//! the full page. The load-more button carries the current filters forward via `hx-include` on the
//! filter form rather than a hand-built query string, since the button lives on the same page as
//! that form; the Events/By IP mode-switch tabs are plain `<a href>` navigations instead (a bigger
//! structural change than an in-place swap), so those DO need a hand-built, percent-encoded query
//! string ([`Filters::query_string`]) - the workspace has no `url`/`form_urlencoded` crate
//! dependency to reach for and the task's constraints forbid adding one, hence the small
//! self-contained [`percent_encode`] rather than pulling one in.

use std::net::IpAddr;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Html;
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use core_scoring::{SignalType, read_score};
use minijinja::context;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::detail::{extract_detail, format_cursor, parse_cursor, signal_type_snake};
use crate::routes::error::AppError;
use crate::routes::format::{format_activity, format_relative_time, format_timestamp, tier_label};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/search/events", get(search_events))
        .route("/search/ips", get(search_ips))
}

/// Event search page size; the fetch queries ask for one more than this to detect a next page
/// (`fetch_search_events`'s doc comment), matching `EVIDENCE_PAGE_SIZE`'s 51-fetch-display-50
/// convention in `routes::detail`.
const SEARCH_PAGE_SIZE: i64 = 50;

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
    pub sensor: Option<String>,
    pub signal_type: Option<String>,
    pub ip: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cursor: Option<String>,
    pub mode: Option<String>,
}

/// The six filter values, normalized once from [`SearchParams`] (trimmed, empty-string treated as
/// absent). Kept as `Option<String>` rather than pre-parsed into `IpAddr`/`DateTime` because the
/// raw, normalized string is also what the filter form and the mode-switch tabs redisplay - a
/// filter that fails to parse (a malformed IP, an unparsable date) simply drops out of the WHERE
/// clause via [`Filters::parsed_ip`]/[`Filters::parsed_from`]/[`Filters::parsed_to`] returning
/// `None` rather than rejecting the whole request, the same fail-open-to-unfiltered posture
/// `normalize_detail_range` in `routes::detail` takes on a malformed `?range=` value - this is an
/// operator's own internal-only filter input, not an untrusted boundary.
#[derive(Debug, Default, Clone)]
struct Filters {
    q: Option<String>,
    sensor: Option<String>,
    signal_type: Option<String>,
    ip: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

impl Filters {
    fn from_params(p: &SearchParams) -> Self {
        Filters {
            q: normalize(&p.q),
            sensor: normalize(&p.sensor),
            signal_type: normalize(&p.signal_type),
            ip: normalize(&p.ip),
            from: normalize(&p.from),
            to: normalize(&p.to),
        }
    }

    /// At least one filter present - the gate that decides whether the handlers run a query at
    /// all (module doc comment).
    fn any_provided(&self) -> bool {
        self.q.is_some()
            || self.sensor.is_some()
            || self.signal_type.is_some()
            || self.ip.is_some()
            || self.from.is_some()
            || self.to.is_some()
    }

    fn parsed_ip(&self) -> Option<IpAddr> {
        self.ip.as_deref().and_then(|s| s.parse().ok())
    }

    fn parsed_from(&self) -> Option<DateTime<Utc>> {
        self.from.as_deref().and_then(parse_date_bound_start)
    }

    fn parsed_to(&self) -> Option<DateTime<Utc>> {
        self.to.as_deref().and_then(parse_date_bound_end)
    }

    /// Builds the `q=..&sensor=..&...` query string the Events/By IP mode-switch tabs append to
    /// their target href, carrying every currently-set filter forward (module doc comment). Never
    /// includes `cursor` - switching modes always starts that mode's own result set from the top.
    fn query_string(&self) -> String {
        [
            ("q", &self.q),
            ("sensor", &self.sensor),
            ("signal_type", &self.signal_type),
            ("ip", &self.ip),
            ("from", &self.from),
            ("to", &self.to),
        ]
        .into_iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .map(|v| format!("{name}={}", percent_encode(v)))
        })
        .collect::<Vec<_>>()
        .join("&")
    }
}

/// Trims a query param and turns an empty string into `None` - an unfilled `<input>` submits as
/// `""`, not an absent key, so without this an empty text field would thread the SQL
/// `... IS NULL OR ...` branch through a nonsensical empty-string comparison instead of taking the
/// "no filter" branch.
fn normalize(raw: &Option<String>) -> Option<String> {
    raw.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parses a `from`/`to` filter value as either a full RFC 3339 timestamp or a bare `YYYY-MM-DD`
/// date (what an `<input type="date">` submits) - the start-of-day form, used for `from`.
fn parse_date_bound_start(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|naive| Utc.from_utc_datetime(&naive))
}

/// The end-of-day form of [`parse_date_bound_start`], used for `to` so a bare date filter includes
/// the whole day rather than cutting off at midnight.
fn parse_date_bound_end(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(23, 59, 59))
        .map(|naive| Utc.from_utc_datetime(&naive))
}

/// Minimal RFC 3986 percent-encoding (unreserved set kept literal, everything else escaped) - see
/// the module doc comment for why this exists instead of a crate dependency.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The filter values as plain (never `None`) strings for redisplay in the filter form - built once
/// per render rather than leaning on minijinja's `default` filter, which only replaces an
/// `undefined` value, not a serialized `None`/`null` (`Filters`'s own doc comment explains why
/// `None` is the normal, expected state for an unfilled field).
#[derive(Debug, Serialize)]
struct FormValues {
    q: String,
    sensor: String,
    signal_type: String,
    ip: String,
    from: String,
    to: String,
}

impl From<&Filters> for FormValues {
    fn from(f: &Filters) -> Self {
        FormValues {
            q: f.q.clone().unwrap_or_default(),
            sensor: f.sensor.clone().unwrap_or_default(),
            signal_type: f.signal_type.clone().unwrap_or_default(),
            ip: f.ip.clone().unwrap_or_default(),
            from: f.from.clone().unwrap_or_default(),
            to: f.to.clone().unwrap_or_default(),
        }
    }
}

/// One event search result row. Trims the SELECT list from the design's literal query
/// (`protocol`/`authenticated`/`wan_ip` also appear there) down to the columns the results table
/// actually renders - `internal/design/11-console-forensics.md`'s "Result row" display spec lists
/// only `observed_at`/`source_ip`/`sensor`/`signal_type`/detail/`session_id`, and the WHERE clause
/// (the part correctness depends on) is otherwise unchanged from the spec.
#[derive(Debug, Serialize)]
struct SearchEventRow {
    id: i64,
    observed_at: String,
    relative_time: String,
    source_ip: String,
    /// Combined sensor + signal-type label via `format_activity`, matching the "Activity" column
    /// convention every other events table in this console uses (the dashboard's recent-activity
    /// table, the detail page's evidence timeline) rather than two separate raw columns.
    activity: String,
    detail: String,
    session_id: Option<String>,
    /// First 8 characters of `session_id`, shown as the visible link text (the full UUID is
    /// verbose for a results table); `None` renders as a plain "-" in the template.
    session_short: Option<String>,
    #[serde(skip)]
    raw_observed_at: DateTime<Utc>,
}

/// One IP search result row: an aggregated match count plus the IP's current (decayed-to-now)
/// score/tier, joined in from `core_scoring::read_score` per IP (design's "The result page joins
/// each row with `ip_score`"). Score/tier degrade to "-" rather than dropping the row when an IP
/// has events but no `ip_score` projection yet (a race with the scoring pipeline, not corruption) -
/// the row is still real evidence a search should surface.
#[derive(Debug, Serialize)]
struct SearchIpRow {
    ip: String,
    match_count: i64,
    first_seen: String,
    last_seen: String,
    score: String,
    score_pct: u32,
    tier: &'static str,
}

async fn search_events(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
) -> Result<Html<String>, AppError> {
    let filters = Filters::from_params(&params);
    let is_htmx = headers.get("HX-Request").is_some();
    let searched = filters.any_provided();

    if !searched {
        // A "Load more" click always carries its page's original filters forward via
        // `hx-include`, so an htmx request with no filters at all should not be reachable in
        // practice; fail closed to an empty fragment rather than running an unbounded query.
        if is_htmx {
            tracing::warn!(
                "htmx search-events request arrived with no filters; returning empty fragment"
            );
            return Ok(Html(String::new()));
        }
        return render_search_page(
            &state,
            &session,
            &filters,
            "events",
            Vec::new(),
            false,
            None,
            Vec::new(),
            false,
        )
        .await;
    }

    let cursor = params.cursor.as_deref().and_then(parse_cursor);
    let mut rows = fetch_search_events(&state.db, &filters, cursor).await?;
    let has_more = rows.len() as i64 > SEARCH_PAGE_SIZE;
    rows.truncate(SEARCH_PAGE_SIZE as usize);
    let next_cursor = rows.last().map(|r| format_cursor(r.raw_observed_at, r.id));

    if is_htmx {
        let tmpl = state
            .templates
            .get_template("search_events_fragment.html")?;
        let html = tmpl.render(context! { rows, has_more, next_cursor })?;
        return Ok(Html(html));
    }

    render_search_page(
        &state,
        &session,
        &filters,
        "events",
        rows,
        has_more,
        next_cursor,
        Vec::new(),
        true,
    )
    .await
}

async fn search_ips(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Query(params): Query<SearchParams>,
) -> Result<Html<String>, AppError> {
    let filters = Filters::from_params(&params);
    let searched = filters.any_provided();
    let ip_rows = if searched {
        fetch_search_ips(&state.db, &filters).await?
    } else {
        Vec::new()
    };

    render_search_page(
        &state,
        &session,
        &filters,
        "ips",
        Vec::new(),
        false,
        None,
        ip_rows,
        searched,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn render_search_page(
    state: &AppState,
    session: &Session,
    filters: &Filters,
    mode: &'static str,
    event_rows: Vec<SearchEventRow>,
    has_more: bool,
    next_cursor: Option<String>,
    ip_rows: Vec<SearchIpRow>,
    searched: bool,
) -> Result<Html<String>, AppError> {
    let (sensors, signal_types) = filter_options(&state.db).await;
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
    } = base_context(&state.db, state.startup_time, state.version).await;
    let form = FormValues::from(filters);
    let query_string = filters.query_string();

    let tmpl = state.templates.get_template("search.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "search",
        pending_count,
        uptime,
        version,
        mode,
        form,
        sensors,
        signal_types,
        searched,
        rows => event_rows,
        has_more,
        next_cursor,
        ip_rows,
        query_string,
    })?;
    Ok(Html(html))
}

/// Populates the filter form's sensor/signal-type dropdowns (design's "Filter dropdowns"). Soft-
/// fails to an empty list on a query error rather than propagating: the dropdowns are supplementary
/// form chrome, not the search itself, matching `routes::context::base_context`'s own
/// supplementary-chrome soft-fail policy.
async fn filter_options(db: &PgPool) -> (Vec<String>, Vec<String>) {
    let sensors =
        sqlx::query_scalar::<_, String>("SELECT DISTINCT sensor FROM event ORDER BY sensor")
            .fetch_all(db)
            .await
            .unwrap_or_default();
    let signal_types = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT signal_type::text FROM event ORDER BY signal_type",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    (sensors, signal_types)
}

/// Fetches up to `SEARCH_PAGE_SIZE + 1` matching `event` rows, newest first, per the design's
/// "Event search query" pattern - the `SELECT` list is trimmed (`SearchEventRow`'s doc comment);
/// the `WHERE` clause carries one correction over the design's literal SQL, verified live against
/// a real Postgres rather than assumed from the spec text: `source_ip = $4` needs its own `::inet`
/// cast, not just the earlier `$4::inet IS NULL` in the same `OR`. `sqlx::query` (the dynamic,
/// non-macro form used here) declares each bound parameter's wire type from the Rust value alone -
/// `filters.parsed_ip().map(|ip| ip.to_string())` is a `String`, so $4 is declared `text` - and
/// Postgres does not implicitly cast `text` to `inet` at a second, uncast usage site even though an
/// earlier cast in the same statement fixed the parameter's type for ITS OWN clause; the result is
/// `operator does not exist: inet = text`, reproduced with `sensor=catchall` (a query where $4 is
/// NULL) confirming this is a static type-resolution error, not a data-dependent one. `sensor`/
/// `signal_type` need no such fix (both compare `text` to `text`); `observed_at`/`id` need none
/// either (`DateTime<Utc>`/`i64` already declare `timestamptz`/`bigint` directly, matching their
/// columns). Returning one extra row is the same fetch-51-display-50 "is there a next page" signal
/// `fetch_evidence_rows` uses in `routes::detail`.
async fn fetch_search_events(
    db: &PgPool,
    filters: &Filters,
    cursor: Option<(DateTime<Utc>, i64)>,
) -> Result<Vec<SearchEventRow>, AppError> {
    let cursor_id = cursor.map(|(_, id)| id);
    let rows = sqlx::query(
        "SELECT id, host(source_ip) AS source_ip, sensor, signal_type, observed_at, metadata, \
                session_id::text AS session_id \
         FROM event \
         WHERE ($1::text IS NULL OR metadata::text ILIKE '%' || $1 || '%') \
           AND ($2::text IS NULL OR sensor = $2) \
           AND ($3::text IS NULL OR signal_type::text = $3) \
           AND ($4::inet IS NULL OR source_ip = $4::inet) \
           AND ($5::timestamptz IS NULL OR observed_at >= $5) \
           AND ($6::timestamptz IS NULL OR observed_at <= $6) \
           AND ($7::bigint IS NULL OR id < $7) \
         ORDER BY observed_at DESC, id DESC \
         LIMIT $8",
    )
    .bind(filters.q.as_deref())
    .bind(filters.sensor.as_deref())
    .bind(filters.signal_type.as_deref())
    .bind(filters.parsed_ip().map(|ip| ip.to_string()))
    .bind(filters.parsed_from())
    .bind(filters.parsed_to())
    .bind(cursor_id)
    .bind(SEARCH_PAGE_SIZE + 1)
    .fetch_all(db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let sensor: String = row.try_get("sensor")?;
        let signal_type: SignalType = row.try_get("signal_type")?;
        let observed_at: DateTime<Utc> = row.try_get("observed_at")?;
        let metadata: serde_json::Value = row.try_get("metadata")?;
        let signal_snake = signal_type_snake(signal_type);
        let session_id: Option<String> = row.try_get("session_id")?;
        let session_short = session_id.as_ref().map(|s| s.chars().take(8).collect());
        out.push(SearchEventRow {
            id: row.try_get("id")?,
            observed_at: format_timestamp(observed_at),
            relative_time: format_relative_time(observed_at),
            source_ip: row.try_get("source_ip")?,
            activity: format_activity(&sensor, &signal_snake),
            detail: extract_detail(&signal_snake, &metadata),
            session_id,
            session_short,
            raw_observed_at: observed_at,
        });
    }
    Ok(out)
}

/// Fetches up to 50 aggregated IP rows per the design's "IP search" query pattern, then joins each
/// one with `core_scoring::read_score` for its current score/tier (`SearchIpRow`'s doc comment) -
/// the same per-row read-after-list pattern `routes::queue`'s `queue_page` already uses for pending
/// entries, not batched into a single SQL join because the decay projection lives in the scoring
/// engine, not in a column this query can read directly.
async fn fetch_search_ips(db: &PgPool, filters: &Filters) -> Result<Vec<SearchIpRow>, AppError> {
    let rows = sqlx::query(
        "SELECT host(source_ip) AS source_ip, COUNT(*) AS match_count, \
                MIN(observed_at) AS first_seen, MAX(observed_at) AS last_seen \
         FROM event \
         WHERE ($1::text IS NULL OR metadata::text ILIKE '%' || $1 || '%') \
           AND ($2::text IS NULL OR sensor = $2) \
           AND ($3::text IS NULL OR signal_type::text = $3) \
           AND ($4::timestamptz IS NULL OR observed_at >= $4) \
           AND ($5::timestamptz IS NULL OR observed_at <= $5) \
         GROUP BY source_ip \
         ORDER BY match_count DESC \
         LIMIT 50",
    )
    .bind(filters.q.as_deref())
    .bind(filters.sensor.as_deref())
    .bind(filters.signal_type.as_deref())
    .bind(filters.parsed_from())
    .bind(filters.parsed_to())
    .fetch_all(db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let ip_str: String = row.try_get("source_ip")?;
        let match_count: i64 = row.try_get("match_count")?;
        let first_seen: DateTime<Utc> = row.try_get("first_seen")?;
        let last_seen: DateTime<Utc> = row.try_get("last_seen")?;

        let (score, score_pct, tier) = match ip_str.parse::<IpAddr>() {
            Ok(ip) => match read_score(db, ip).await {
                Ok(Some(s)) => {
                    let f = s.raw_score.to_f64().unwrap_or(0.0);
                    (
                        format!("{:.1}", s.raw_score),
                        f.clamp(0.0, 100.0).round() as u32,
                        s.tier.map(tier_label).unwrap_or("-"),
                    )
                }
                // No projection yet, or the read itself failed - either way this is
                // supplementary context on top of a real match, not a reason to hide the row.
                _ => ("-".to_string(), 0, "-"),
            },
            // `host(source_ip)` always yields a parseable address; this arm exists only so a
            // future storage-format surprise degrades to a dash rather than panicking.
            Err(_) => ("-".to_string(), 0, "-"),
        };

        out.push(SearchIpRow {
            ip: ip_str,
            match_count,
            first_seen: format_timestamp(first_seen),
            last_seen: format_timestamp(last_seen),
            score,
            score_pct,
            tier,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(q: Option<&str>) -> SearchParams {
        SearchParams {
            q: q.map(str::to_string),
            sensor: None,
            signal_type: None,
            ip: None,
            from: None,
            to: None,
            cursor: None,
            mode: None,
        }
    }

    #[test]
    fn normalize_trims_and_drops_empty_strings() {
        assert_eq!(
            normalize(&Some("  root  ".to_string())),
            Some("root".to_string())
        );
        assert_eq!(normalize(&Some("   ".to_string())), None);
        assert_eq!(normalize(&None), None);
    }

    #[test]
    fn filters_any_provided_is_false_with_no_filters() {
        let filters = Filters::from_params(&params(None));
        assert!(!filters.any_provided());
    }

    #[test]
    fn filters_any_provided_is_true_with_a_blank_query_but_a_real_sensor() {
        let mut p = params(Some("   "));
        p.sensor = Some("ssh".to_string());
        let filters = Filters::from_params(&p);
        assert!(filters.any_provided());
        assert_eq!(filters.q, None);
        assert_eq!(filters.sensor, Some("ssh".to_string()));
    }

    #[test]
    fn parsed_ip_accepts_a_valid_address_and_drops_a_malformed_one() {
        let mut p = params(None);
        p.ip = Some("203.0.113.7".to_string());
        assert_eq!(
            Filters::from_params(&p).parsed_ip(),
            Some("203.0.113.7".parse().unwrap())
        );

        let mut p = params(None);
        p.ip = Some("not-an-ip".to_string());
        assert_eq!(Filters::from_params(&p).parsed_ip(), None);
    }

    #[test]
    fn parse_date_bound_start_accepts_bare_date_at_midnight() {
        let dt = parse_date_bound_start("2026-08-01").unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-08-01T00:00:00+00:00");
    }

    #[test]
    fn parse_date_bound_end_accepts_bare_date_at_end_of_day() {
        let dt = parse_date_bound_end("2026-08-01").unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-08-01T23:59:59+00:00");
    }

    #[test]
    fn parse_date_bound_accepts_full_rfc3339() {
        let dt = parse_date_bound_start("2026-08-01T12:30:00Z").unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-08-01T12:30:00+00:00");
    }

    #[test]
    fn parse_date_bound_rejects_garbage() {
        assert_eq!(parse_date_bound_start("not-a-date"), None);
        assert_eq!(parse_date_bound_end(""), None);
    }

    #[test]
    fn percent_encode_keeps_unreserved_and_escapes_the_rest() {
        assert_eq!(percent_encode("abc123-_.~"), "abc123-_.~");
        assert_eq!(percent_encode("a b&c"), "a%20b%26c");
        assert_eq!(percent_encode("root@host"), "root%40host");
    }

    #[test]
    fn query_string_omits_unset_filters_and_encodes_set_ones() {
        let mut p = params(Some("cat /etc/passwd"));
        p.sensor = Some("ssh".to_string());
        let filters = Filters::from_params(&p);
        assert_eq!(filters.query_string(), "q=cat%20%2Fetc%2Fpasswd&sensor=ssh");
    }

    #[test]
    fn query_string_is_empty_with_no_filters() {
        let filters = Filters::from_params(&params(None));
        assert_eq!(filters.query_string(), "");
    }

    #[test]
    fn form_values_defaults_unset_filters_to_empty_strings() {
        let filters = Filters::from_params(&params(None));
        let form = FormValues::from(&filters);
        assert_eq!(form.q, "");
        assert_eq!(form.sensor, "");
    }
}
