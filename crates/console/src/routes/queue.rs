//! `GET /queue` (pending review entries, decayed-to-now score) and
//! `POST /queue/{ip}/approve|reject|snooze` (HTMX row-partial mutation), per
//! `internal/design/06-console-observability.md`'s "Pages" > "Review queue". Session-gated:
//! mounted under the `protected` group in `routes::mod`.
//!
//! `review_queue` stores each entry's score/categories only as a snapshot taken at surface time
//! (`score_at_surface`/`categories_at_surface`); the queue page must show the CURRENT decayed
//! state instead, so every displayed field besides `state`/`notes` comes from a fresh
//! `core_scoring::read_score` call per pending IP, never from those snapshot columns.
//!
//! CSRF is checked on the three mutating routes here: the operator's own authenticated session
//! (guaranteed present by `require_session`) issues these, which is exactly the session-riding
//! forgery `SessionStore`'s per-session CSRF token exists to stop. `routes::login`'s POST
//! deliberately has no CSRF check - see that module's doc comment for why that is a considered
//! omission, not a gap.

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use chrono::{DateTime, Utc};
use core_scoring::{Category, IpScore, ReviewState, read_score};
use minijinja::context;
use review::queue::ReviewQueue;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;
use crate::routes::format::{format_timestamp, tier_label};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/queue", get(queue_page))
        .route("/queue/{ip}/approve", post(approve))
        .route("/queue/{ip}/reject", post(reject))
        .route("/queue/{ip}/snooze", post(snooze))
        .route("/ip/{ip}/delist", post(delist))
        .route("/ip/{ip}/delete", post(delete_ip))
}

/// The three operator decisions a pending entry can receive. A dedicated enum (rather than
/// reusing `core_scoring::ReviewState` directly for dispatch) keeps the three route handlers from
/// having to guard against the fourth, impossible-here `Pending` variant.
#[derive(Debug, Clone, Copy)]
enum Action {
    Approve,
    Reject,
    Snooze,
}

impl Action {
    fn review_state(self) -> ReviewState {
        match self {
            Action::Approve => ReviewState::Approved,
            Action::Reject => ReviewState::Rejected,
            Action::Snooze => ReviewState::Snoozed,
        }
    }
}

/// Sort key accepted via `?sort=`, matching the spec's "Sorting by score (descending, default),
/// first seen, last seen, event count."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SortKey {
    #[default]
    Score,
    FirstSeen,
    LastSeen,
    EventCount,
}

impl SortKey {
    fn as_str(self) -> &'static str {
        match self {
            SortKey::Score => "score",
            SortKey::FirstSeen => "first_seen",
            SortKey::LastSeen => "last_seen",
            SortKey::EventCount => "event_count",
        }
    }
}

/// Tab accepted via `?tab=`, matching this task's "pending/approved/rejected/snoozed" review
/// queue history tabs. `Pending` is the default (unchanged page behavior for a bare `/queue`
/// hit); the other three list historical decisions straight from `review_queue` since
/// `ReviewQueue` exposes no per-state listing beyond `list_pending`/`list_approved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Tab {
    #[default]
    Pending,
    Approved,
    Rejected,
    Snoozed,
}

impl Tab {
    fn as_str(self) -> &'static str {
        match self {
            Tab::Pending => "pending",
            Tab::Approved => "approved",
            Tab::Rejected => "rejected",
            Tab::Snoozed => "snoozed",
        }
    }

    /// The `review_queue.state` value this tab lists, or `None` for `Pending` (handled by the
    /// existing `ReviewQueue::list_pending` path, which additionally sorts by the `?sort=` key).
    fn review_state(self) -> Option<ReviewState> {
        match self {
            Tab::Pending => None,
            Tab::Approved => Some(ReviewState::Approved),
            Tab::Rejected => Some(ReviewState::Rejected),
            Tab::Snoozed => Some(ReviewState::Snoozed),
        }
    }
}

#[derive(Debug, Deserialize)]
struct QueueQuery {
    #[serde(default)]
    sort: SortKey,
    #[serde(default)]
    tab: Tab,
}

#[derive(Debug, Deserialize)]
struct ActionForm {
    csrf_token: String,
    #[serde(default)]
    notes: String,
}

/// One row's display data: every numeric/timestamp field is pre-formatted in Rust rather than in
/// the template, keeping the template free of `Decimal`/`DateTime` formatting logic.
///
/// Shared by the pending tab (rendered via `queue_row.html`, `is_pending: true`, `decided_at`/
/// `submissions` empty) and the approved/rejected/snoozed history tabs (rendered via
/// `queue_history_row.html`, `is_pending: false`, `decided_at` populated, `submissions` populated
/// only on the approved tab).
#[derive(Debug, Serialize)]
struct QueueRowView {
    ip: String,
    state: &'static str,
    is_pending: bool,
    score: String,
    score_pct: u32,
    tier: &'static str,
    categories: String,
    event_count: i32,
    first_seen: String,
    last_seen: String,
    decided_at: String,
    submissions: String,
    notes: String,
    csrf_token: String,
}

async fn queue_page(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Query(query): Query<QueueQuery>,
) -> Result<Html<String>, AppError> {
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();

    let rows: Vec<QueueRowView> = match query.tab.review_state() {
        None => pending_rows(&state.db, query.sort, &csrf_token).await?,
        Some(review_state) => history_rows(&state.db, review_state).await?,
    };

    // `pending_count` is the shared sitewide count from `base_context` (the same query the
    // nav/footer badge uses on every page) rather than `rows.len()`: the two are equal in normal
    // operation, but `pending_rows` below silently omits any entry missing its `ip_score`
    // projection, so sourcing the heading from the same canonical count keeps this page's own "N
    // pending" consistent with what the rest of the console shows for the same number.
    let BaseContext {
        pending_count,
        uptime,
        version,
        degraded,
    } = base_context(&state.db, state.startup_time, state.version).await;

    let tmpl = state.templates.get_template("queue.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "queue",
        pending_count,
        uptime,
        version,
        degraded => degraded.names(),
        rows,
        sort => query.sort.as_str(),
        tab => query.tab.as_str(),
    })?;
    Ok(Html(html))
}

fn sort_pending(rows: &mut [(IpAddr, Option<String>, IpScore)], key: SortKey) {
    use std::cmp::Reverse;
    match key {
        // Highest severity first - the spec's default.
        SortKey::Score => rows.sort_by_key(|r| Reverse(r.2.raw_score)),
        // Oldest-pending-first: the natural order to clear a backlog.
        SortKey::FirstSeen => rows.sort_by_key(|r| r.2.first_seen),
        // Most recently active first - the freshest signal.
        SortKey::LastSeen => rows.sort_by_key(|r| Reverse(r.2.last_seen)),
        SortKey::EventCount => rows.sort_by_key(|r| Reverse(r.2.event_count)),
    }
}

/// The pending tab: every open `review_queue` entry, sorted by `sort`, each joined against its
/// live (decayed-to-now) `ip_score` projection. Unchanged behavior from before tab support -
/// factored out of `queue_page` so it sits alongside its `history_rows` sibling below.
async fn pending_rows(
    pool: &PgPool,
    sort: SortKey,
    csrf_token: &str,
) -> Result<Vec<QueueRowView>, AppError> {
    let entries = ReviewQueue::new().list_pending(pool).await?;

    let mut pending = Vec::with_capacity(entries.len());
    for entry in entries {
        let ip = entry.source_ip;
        match read_score(pool, ip).await? {
            Some(score) => pending.push((ip, entry.notes, score)),
            None => {
                // Cannot happen via the normal populate path (see `review::queue`'s doc comment),
                // but the pending row is unusable without a projection - skip it, don't crash the
                // whole page over one stale/corrupt entry.
                tracing::warn!(
                    %ip,
                    "pending review entry has no ip_score projection; omitting from queue page"
                );
            }
        }
    }
    sort_pending(&mut pending, sort);

    Ok(pending
        .into_iter()
        .map(|(ip, notes, score)| {
            row_view(
                ip,
                ReviewState::Pending,
                notes.as_deref(),
                &score,
                csrf_token,
            )
        })
        .collect())
}

/// The approved/rejected/snoozed tabs: `review_queue` exposes no `list_pending`-style method for
/// these states (only `list_pending` and `list_approved` exist, and the latter sorts by
/// `decided_at ASC` for the submission runner's FIFO, not the newest-first order an operator
/// browsing history wants), so query directly here rather than adding narrow one-off methods to
/// `ReviewQueue` for a console-only display need. Newest-decided first, capped at 100 rows - a
/// history browse, not a paginated audit log.
async fn history_rows(
    pool: &PgPool,
    review_state: ReviewState,
) -> Result<Vec<QueueRowView>, AppError> {
    let db_rows = sqlx::query(
        "SELECT host(source_ip) AS ip, decided_at, notes \
         FROM review_queue WHERE state = $1 ORDER BY decided_at DESC LIMIT 100",
    )
    .bind(review_state)
    .fetch_all(pool)
    .await?;

    let mut rows = Vec::with_capacity(db_rows.len());
    for db_row in db_rows {
        let ip_text: String = db_row.try_get("ip")?;
        let Ok(ip) = ip_text.parse::<IpAddr>() else {
            // Cannot happen via any write path here (`source_ip` is a stored `inet`, and
            // `host()` always renders a valid address text) - fail closed on the one row rather
            // than the whole tab if it ever does.
            tracing::warn!(
                ip = %ip_text,
                ?review_state,
                "review_queue row has unparseable source_ip; omitting from history tab"
            );
            continue;
        };
        let decided_at: Option<DateTime<Utc>> = db_row.try_get("decided_at")?;
        let notes: Option<String> = db_row.try_get("notes")?;

        let Some(score) = read_score(pool, ip).await? else {
            tracing::warn!(
                %ip,
                ?review_state,
                "history review entry has no ip_score projection; omitting from queue page"
            );
            continue;
        };

        // Submission counts are only meaningful once a decision has actually been forwarded to
        // vendors, so only the approved tab pays for the extra per-row query.
        let submissions = match review_state {
            ReviewState::Approved => submission_summary(pool, ip).await?,
            _ => String::new(),
        };

        rows.push(history_row_view(
            ip,
            review_state,
            decided_at,
            notes.as_deref(),
            &score,
            submissions,
        ));
    }
    Ok(rows)
}

/// "N/M vendors" for `ip`'s `vendor_submission` rows, or "-" when none exist yet (an approved IP
/// the submission runner has not picked up yet).
async fn submission_summary(pool: &PgPool, ip: IpAddr) -> Result<String, AppError> {
    let row = sqlx::query(
        "SELECT COUNT(*) FILTER (WHERE success) AS succeeded, COUNT(*) AS total \
         FROM vendor_submission WHERE source_ip = $1::inet",
    )
    .bind(ip.to_string())
    .fetch_one(pool)
    .await?;
    let succeeded: i64 = row.try_get("succeeded")?;
    let total: i64 = row.try_get("total")?;
    if total == 0 {
        Ok("-".to_string())
    } else {
        Ok(format!("{succeeded}/{total} vendors"))
    }
}

async fn approve(
    state: State<AppState>,
    session: Extension<Session>,
    path: Path<IpAddr>,
    form: Form<ActionForm>,
) -> Result<Response, AppError> {
    act(state, session, path, form, Action::Approve).await
}

async fn reject(
    state: State<AppState>,
    session: Extension<Session>,
    path: Path<IpAddr>,
    form: Form<ActionForm>,
) -> Result<Response, AppError> {
    act(state, session, path, form, Action::Reject).await
}

async fn snooze(
    state: State<AppState>,
    session: Extension<Session>,
    path: Path<IpAddr>,
    form: Form<ActionForm>,
) -> Result<Response, AppError> {
    act(state, session, path, form, Action::Snooze).await
}

async fn act(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
    Form(form): Form<ActionForm>,
    action: Action,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        tracing::warn!(%ip, "queue action rejected: missing or invalid csrf token");
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    let notes = form.notes.trim();
    let notes = if notes.is_empty() { None } else { Some(notes) };

    let queue = ReviewQueue::new();
    match action {
        Action::Approve => queue.approve(&state.db, ip, notes).await,
        Action::Reject => queue.reject(&state.db, ip, notes).await,
        Action::Snooze => queue.snooze(&state.db, ip, notes).await,
    }?;

    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let Some(score) = read_score(&state.db, ip).await? else {
        return Err(AppError::missing_projection(ip));
    };
    let row = row_view(ip, action.review_state(), notes, &score, &csrf_token);

    let tmpl = state.templates.get_template("queue_row.html")?;
    let html = tmpl.render(context! { row })?;
    Ok(Html(html).into_response())
}

async fn delist(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
    Form(form): Form<ActionForm>,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    sqlx::query("DELETE FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip.to_string())
        .execute(&state.db)
        .await?;

    sqlx::query(
        "UPDATE ip_score SET delisted = TRUE, eligible = FALSE, recommended_for_vendor = FALSE, \
         recommended_for_blocklist = FALSE WHERE source_ip = $1::inet",
    )
    .bind(ip.to_string())
    .execute(&state.db)
    .await?;

    tracing::info!(%ip, "ip delisted from feed and queue");
    Ok(Redirect::to(&format!("/ip/{ip}")).into_response())
}

/// `POST /ip/{ip}/delete` - purge an address's derived state (scoring projection, review-queue
/// entry, and vendor-submission history), for a false positive or a test address an operator wants
/// gone rather than merely delisted.
///
/// The append-only, hash-chained `event` ledger is deliberately NOT touched: deleting a link would
/// break `verify_chain` for the whole ledger, and the projection deleted here can always be rebuilt
/// from it. So this is "forget the scoring/review state", not a ledger edit - if the same address
/// sends another event, or the projection is replayed, it reappears (which is correct: the ledger
/// is the source of truth). Same CSRF gate as `delist`.
async fn delete_ip(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
    Form(form): Form<ActionForm>,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    // Literal statements (sqlx requires a static SQL string, and it is the right guard here): the
    // ONLY dynamic value is the bound `$1` IP, never the table name.
    let ip_str = ip.to_string();
    sqlx::query("DELETE FROM review_queue WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM vendor_submission WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM ip_score WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&state.db)
        .await?;

    tracing::info!(%ip, "ip purged from scoring/review/vendor state (event ledger retained)");
    // The ip_score row is gone, so /ip/{ip} would 404 - send the operator back to the queue.
    Ok(Redirect::to("/queue").into_response())
}

fn row_view(
    ip: IpAddr,
    review_state: ReviewState,
    notes: Option<&str>,
    score: &IpScore,
    csrf_token: &str,
) -> QueueRowView {
    let score_f64 = score.raw_score.to_f64().unwrap_or(0.0);
    QueueRowView {
        ip: ip.to_string(),
        state: review_state_label(review_state),
        is_pending: review_state == ReviewState::Pending,
        score: format!("{:.1}", score.raw_score),
        score_pct: score_f64.clamp(0.0, 100.0).round() as u32,
        tier: score.tier.map(tier_label).unwrap_or("-"),
        categories: live_categories(&score.category_breakdown),
        event_count: score.event_count,
        first_seen: format_timestamp(score.first_seen),
        last_seen: format_timestamp(score.last_seen),
        decided_at: String::new(),
        submissions: String::new(),
        notes: notes.unwrap_or_default().to_string(),
        csrf_token: csrf_token.to_string(),
    }
}

/// A history-tab row (approved/rejected/snoozed): no action buttons, so no `csrf_token` needed;
/// `decided_at` and `submissions` are populated instead of left blank as they are for a pending
/// row.
fn history_row_view(
    ip: IpAddr,
    review_state: ReviewState,
    decided_at: Option<DateTime<Utc>>,
    notes: Option<&str>,
    score: &IpScore,
    submissions: String,
) -> QueueRowView {
    let mut row = row_view(ip, review_state, notes, score, "");
    row.decided_at = decided_at.map(format_timestamp).unwrap_or_default();
    row.submissions = submissions;
    row
}

fn review_state_label(s: ReviewState) -> &'static str {
    match s {
        ReviewState::Pending => "pending",
        ReviewState::Approved => "approved",
        ReviewState::Rejected => "rejected",
        ReviewState::Snoozed => "snoozed",
    }
}

/// The comma-joined, lowercased set of categories with currently-live weight, derived from
/// `IpScore.category_breakdown` (a JSON object keyed by `Category`'s default - i.e. bare
/// PascalCase-identifier - `Serialize` output; matches how `review::submit` parses the same
/// column). `BTreeMap<Category, _>` iterates in `Category`'s declared (and derived-`Ord`) order,
/// so the joined string is deterministic.
fn live_categories(breakdown: &serde_json::Value) -> String {
    let Ok(map) =
        serde_json::from_value::<BTreeMap<Category, serde_json::Value>>(breakdown.clone())
    else {
        return String::new();
    };
    map.keys()
        .map(|c| format!("{c:?}").to_lowercase())
        .collect::<Vec<_>>()
        .join(", ")
}
