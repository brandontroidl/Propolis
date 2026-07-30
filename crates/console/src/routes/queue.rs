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
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use core_scoring::{Category, IpScore, ReviewState, read_score};
use minijinja::context;
use review::queue::ReviewQueue;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Session;
use crate::routes::error::AppError;
use crate::routes::format::{format_timestamp, tier_label};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/queue", get(queue_page))
        .route("/queue/{ip}/approve", post(approve))
        .route("/queue/{ip}/reject", post(reject))
        .route("/queue/{ip}/snooze", post(snooze))
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

#[derive(Debug, Deserialize)]
struct QueueQuery {
    #[serde(default)]
    sort: SortKey,
}

#[derive(Debug, Deserialize)]
struct ActionForm {
    csrf_token: String,
    #[serde(default)]
    notes: String,
}

/// One row's display data: every numeric/timestamp field is pre-formatted in Rust rather than in
/// the template, keeping the template free of `Decimal`/`DateTime` formatting logic.
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
    notes: String,
    csrf_token: String,
}

async fn queue_page(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Query(query): Query<QueueQuery>,
) -> Result<Html<String>, AppError> {
    let entries = ReviewQueue::new().list_pending(&state.db).await?;

    let mut pending = Vec::with_capacity(entries.len());
    for entry in entries {
        let ip = entry.source_ip;
        match read_score(&state.db, ip).await? {
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
    sort_pending(&mut pending, query.sort);

    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let rows: Vec<QueueRowView> = pending
        .into_iter()
        .map(|(ip, notes, score)| {
            row_view(
                ip,
                ReviewState::Pending,
                notes.as_deref(),
                &score,
                &csrf_token,
            )
        })
        .collect();

    let tmpl = state.templates.get_template("queue.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "queue",
        pending_count => rows.len(),
        rows,
        sort => query.sort.as_str(),
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
        notes: notes.unwrap_or_default().to_string(),
        csrf_token: csrf_token.to_string(),
    }
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
