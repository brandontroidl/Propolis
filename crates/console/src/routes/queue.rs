//! `GET /queue` (pending review entries, decayed-to-now score) and
//! `POST /queue/{ip}/approve|reject|snooze|unsnooze` (HTMX row-partial mutation), per
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
//!
//! The page's `volume` tab and `POST /volume/{ip}/approve|reject|reopen` are the same thing for
//! the other queue, `volume_review`: addresses the connection-volume rule would list in the
//! retention feeds, which are published only once approved here (`review::volume`). They are
//! separate routes on a separate table because the two approvals differ: approving a pending
//! review entry lets the submission runner report the address to vendors, approving a volume
//! candidate publishes it and reports nothing. Same session gate, same CSRF check.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use chrono::{DateTime, Utc};
use core_scoring::{FeedTier, IpScore, ReviewState, begin_exclusive, read_score};
use minijinja::context;
use review::queue::ReviewQueue;
use review::volume::{VolumeEntry, VolumeQueue};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::campaigns::{CampaignRef, campaigns_by_ip};
use crate::routes::context::{BaseContext, base_context};
use crate::routes::detail::extract_detail;
use crate::routes::error::AppError;
use crate::routes::format::{
    format_active, format_sensor_label, format_timestamp, group_digits, signal_severity,
    signal_tag_label, tier_label,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/queue", get(queue_page))
        .route("/queue/{ip}/approve", post(approve))
        .route("/queue/{ip}/reject", post(reject))
        .route("/queue/{ip}/snooze", post(snooze))
        .route("/ip/{ip}/delist", post(delist))
        // The way back. `populate` never re-surfaces a decided entry, so without these an entry
        // an operator chose to defer can only be reached from the Snoozed tab, and a delisted
        // address could not be relisted at all - see each handler's own doc comment.
        .route("/queue/{ip}/unsnooze", post(unsnooze))
        .route("/ip/{ip}/relist", post(relist))
        .route("/ip/{ip}/delete", post(delete_ip))
        // Decisions on volume candidates. Under `/volume`, not `/queue`, so no client can reach
        // one by mistyping the other: `/queue/{ip}/approve` approves for vendor reporting.
        .route("/volume/{ip}/approve", post(volume_approve))
        .route("/volume/{ip}/reject", post(volume_reject))
        .route("/volume/{ip}/reopen", post(volume_reopen))
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
/// `ReviewQueue` exposes no per-state listing beyond `list_pending`/`list_approved`. `Volume` is
/// the other queue: the volume candidates waiting for a decision and the ones already decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Tab {
    #[default]
    Pending,
    Approved,
    Rejected,
    Snoozed,
    Volume,
}

impl Tab {
    fn as_str(self) -> &'static str {
        match self {
            Tab::Pending => "pending",
            Tab::Approved => "approved",
            Tab::Rejected => "rejected",
            Tab::Snoozed => "snoozed",
            Tab::Volume => "volume",
        }
    }

    /// The `review_queue.state` value this tab lists, or `None` for `Pending` (handled by the
    /// existing `ReviewQueue::list_pending` path, which additionally sorts by the `?sort=` key)
    /// and for `Volume`, which lists `volume_review` and no `review_queue` row at all.
    fn review_state(self) -> Option<ReviewState> {
        match self {
            Tab::Pending | Tab::Volume => None,
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
    /// Which tab the row was acted on from, sent by the history tabs' own hidden field. Empty for
    /// the pending tab and for any non-browser caller. It decides only what the response renders:
    /// a decision made from a history tab moves the row to a DIFFERENT tab, so re-rendering it in
    /// this table's columns would put the wrong headers over the cells - see
    /// `queue_moved_row.html`.
    #[serde(default)]
    from_tab: String,
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
    /// The tier the address last earned ([`earned_tier`]), which is what the queue offers it on
    /// and what a listing runs from, and when it earned it, for the cell's `title`.
    tier: &'static str,
    tier_title: String,
    event_count: i32,
    /// The pending tab's "Active" cell ([`format_active`]): from the first sighting to the last
    /// completed connection, and its exact-timestamps `title`.
    active: String,
    active_title: String,
    decided_at: String,
    submissions: String,
    notes: String,
    csrf_token: String,
    /// What the address did, for the pending tab's context line ([`row_context`]). `None` on the
    /// history tabs and on a decision's re-rendered row, which renders without the line.
    context: Option<RowContext>,
}

/// The pending tab's per-row context: enough to decide most entries without opening them.
#[derive(Debug, Serialize)]
struct RowContext {
    /// Display labels of the sensors the address reached, most events first.
    sensors: Vec<String>,
    /// Distinct sessions (connections with a session id).
    sessions: i64,
    /// The most frequent signal types, most frequent first, at most [`CONTEXT_SIGNALS`].
    signals: Vec<SignalCount>,
    /// The first upload or download it made, else its first command past a shell-entry preamble.
    notable: Option<Notable>,
    /// Set when the address has more events than [`CONTEXT_SAMPLE`]: the counts above then
    /// describe that many of its events, and this says so ("5,000 of 7,845").
    sampled: Option<String>,
    /// The largest campaign the address belongs to, with its pending member count, so a row from
    /// a fifty-host campaign says so and links to approving them together.
    campaign: Option<CampaignRef>,
}

#[derive(Debug, Serialize)]
struct SignalCount {
    label: &'static str,
    sev: &'static str,
    count: i64,
}

#[derive(Debug, Clone, Serialize)]
struct Notable {
    /// `upload`, `fetch` or `command`.
    kind: &'static str,
    /// Cut to [`CONTEXT_TEXT_CHARS`] for the line itself.
    text: String,
    /// Longer form for the `title` attribute, cut to [`CONTEXT_TITLE_CHARS`].
    full: String,
}

/// One volume candidate on the volume tab, pending or decided. The counts stay numbers so the
/// template's `count` filter groups them like every other count on the page.
#[derive(Debug, Serialize)]
struct VolumeRowView {
    ip: String,
    state: &'static str,
    is_pending: bool,
    /// `ip_score.established_event_count` now: what the volume rule counts.
    established_now: i32,
    /// The same count when the scan offered the address.
    established_at_surface: i32,
    /// Every event, spoofable ones included, for comparison with the two above.
    event_count: i32,
    /// Exact, not relative: a last-seen stamp dated ahead of the clock is something the operator
    /// should be able to see before approving.
    last_seen: String,
    decided_at: String,
    notes: String,
    csrf_token: String,
    /// Sensors reached and top signal types, as on the pending tab. Only on a pending row.
    context: Option<RowContext>,
}

/// The volume tab's two lists.
#[derive(Debug, Serialize)]
struct VolumeView {
    pending: Vec<VolumeRowView>,
    /// Approved and rejected candidates, most recently decided first, at most
    /// [`VOLUME_DECIDED_SHOWN`].
    decided: Vec<VolumeRowView>,
}

/// Decided volume candidates listed under the pending ones: a history browse, like the 100 rows
/// each review-queue history tab shows.
const VOLUME_DECIDED_SHOWN: usize = 100;

/// A campaign with two or more pending members on the page, shown as one expandable row.
#[derive(Debug, Serialize)]
struct QueueGroup {
    id: i64,
    label: String,
    kind: &'static str,
    /// Hosts in the campaign.
    members: i32,
    /// Pending members in the campaign overall: what the approve confirmation will list.
    pending: i64,
    /// Members listed under this group (a member whose home is another campaign is listed there).
    shown: usize,
    infected: bool,
    /// What the first member that did something notable did.
    what: Option<Notable>,
    /// The group's top member, which also fixes its position under the current sort.
    top_score: String,
    rows: Vec<QueueRowView>,
}

/// One entry of the pending list: a campaign group or a single row.
#[derive(Debug, Serialize)]
struct QueueItem {
    group: Option<QueueGroup>,
    row: Option<QueueRowView>,
}

/// Events read per row for the context line's counts. Most addresses have fewer, and the line is
/// exact for them; a flood is described from this many and labelled as such.
const CONTEXT_SAMPLE: i64 = 5000;

/// Signal types named on the context line.
const CONTEXT_SIGNALS: usize = 3;

/// Commands read, oldest first, looking for the first one past the preamble.
const CONTEXT_COMMANDS: i64 = 64;

/// Longest command or URL shown on the context line, in characters.
const CONTEXT_TEXT_CHARS: usize = 96;

/// Longest command or URL carried in the line's `title` attribute, in characters.
const CONTEXT_TITLE_CHARS: usize = 600;

/// The lines Mirai-family telnet loaders send to reach a shell before doing anything (see
/// `crates/sensor-telnet/tests/echo_loader.rs`). Every such session starts with them, so the
/// first of them says nothing about what the address came to do.
const SHELL_ENTRY_PREAMBLE: &[&str] = &[
    "start",
    "enable",
    "config terminal",
    "system",
    "linuxshell",
    "su",
    "shell",
    "sh",
];

/// Builds [`RowContext`] for `ip` from at most [`CONTEXT_SAMPLE`] events, its first upload or
/// download (indexed on `(source_ip, signal_type, observed_at)`), and at most
/// [`CONTEXT_COMMANDS`] of its earliest commands.
async fn row_context(pool: &PgPool, ip: IpAddr, event_count: i32) -> Result<RowContext, AppError> {
    let ip_text = ip.to_string();
    let rows = sqlx::query(
        "WITH s AS MATERIALIZED ( \
             SELECT sensor, signal_type, session_id FROM event \
             WHERE source_ip = $1::inet LIMIT $2) \
         SELECT sensor, signal_type::text AS signal_type, count(*) AS n, \
                (SELECT count(DISTINCT session_id) FROM s) AS sessions, \
                (SELECT count(*) FROM s) AS sampled \
         FROM s GROUP BY sensor, signal_type",
    )
    .bind(&ip_text)
    .bind(CONTEXT_SAMPLE)
    .fetch_all(pool)
    .await?;

    let mut sessions = 0;
    let mut sampled = 0;
    let mut by_sensor: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_signal: BTreeMap<String, i64> = BTreeMap::new();
    for row in &rows {
        let n: i64 = row.try_get("n")?;
        sessions = row.try_get("sessions")?;
        sampled = row.try_get("sampled")?;
        *by_sensor.entry(row.try_get("sensor")?).or_default() += n;
        *by_signal.entry(row.try_get("signal_type")?).or_default() += n;
    }
    let mut sensors: Vec<(String, i64)> = by_sensor.into_iter().collect();
    sensors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut signals: Vec<(String, i64)> = by_signal.into_iter().collect();
    signals.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    Ok(RowContext {
        sensors: sensors
            .iter()
            .map(|(s, _)| format_sensor_label(s))
            .collect(),
        sessions,
        signals: signals
            .iter()
            .take(CONTEXT_SIGNALS)
            .map(|(s, count)| SignalCount {
                label: signal_tag_label(s),
                sev: signal_severity(s),
                count: *count,
            })
            .collect(),
        notable: notable_action(pool, &ip_text).await?,
        sampled: (sampled >= CONTEXT_SAMPLE).then(|| {
            format!(
                "{} of {}",
                group_digits(sampled),
                group_digits(i64::from(event_count).max(sampled))
            )
        }),
        campaign: None,
    })
}

/// The address's first upload or download, else its first command that is not part of the
/// shell-entry preamble.
async fn notable_action(pool: &PgPool, ip: &str) -> Result<Option<Notable>, AppError> {
    let transfer = sqlx::query(
        "SELECT signal_type::text AS signal_type, metadata FROM event \
         WHERE source_ip = $1::inet \
           AND signal_type IN ('honeypot_malware_upload', 'honeypot_file_download') \
         ORDER BY observed_at, id LIMIT 1",
    )
    .bind(ip)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = transfer {
        let signal: String = row.try_get("signal_type")?;
        let metadata: serde_json::Value = row.try_get("metadata")?;
        return Ok(Some(notable(
            if signal == "honeypot_malware_upload" {
                "upload"
            } else {
                "fetch"
            },
            &extract_detail(&signal, &metadata),
        )));
    }

    let commands: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT metadata FROM event \
         WHERE source_ip = $1::inet AND signal_type = 'honeypot_command_exec' \
         ORDER BY observed_at, id LIMIT $2",
    )
    .bind(ip)
    .bind(CONTEXT_COMMANDS)
    .fetch_all(pool)
    .await?;
    Ok(commands
        .iter()
        .map(|m| extract_detail("honeypot_command_exec", m))
        .find(|c| {
            let c = c.trim().to_ascii_lowercase();
            c != "-" && !c.is_empty() && !SHELL_ENTRY_PREAMBLE.contains(&c.as_str())
        })
        .map(|c| notable("command", c.trim())))
}

fn notable(kind: &'static str, text: &str) -> Notable {
    Notable {
        kind,
        text: clip(text, CONTEXT_TEXT_CHARS),
        full: clip(text, CONTEXT_TITLE_CHARS),
    }
}

/// `text` cut to `max` characters, with an ellipsis when cut.
fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((at, _)) => format!("{}...", &text[..at]),
        None => text.to_string(),
    }
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

    let mut rows: Vec<QueueRowView> = match (query.tab, query.tab.review_state()) {
        // The volume tab lists the other queue and no review-queue row.
        (Tab::Volume, _) => Vec::new(),
        (_, None) => pending_rows(&state.db, query.sort, &csrf_token).await?,
        // The token goes to the history tabs too: the Snoozed tab carries real decision controls
        // (it is the only route back out of a snooze), and those POST like any other.
        (_, Some(review_state)) => history_rows(&state.db, review_state, &csrf_token).await?,
    };
    let volume = if query.tab == Tab::Volume {
        Some(volume_view(&state.db, &csrf_token).await?)
    } else {
        None
    };

    // `pending_count` is the shared sitewide count from `base_context` (the same query the
    // nav/footer badge uses on every page) rather than `rows.len()`: the two are equal in normal
    // operation, but `pending_rows` below silently omits any entry missing its `ip_score`
    // projection, so sourcing the heading from the same canonical count keeps this page's own "N
    // pending" consistent with what the rest of the console shows for the same number. It counts
    // both queues, so the heading also says how many of them are volume candidates.
    let BaseContext {
        pending_count,
        volume_pending_count,
        uptime,
        version,
        mut degraded,
    } = base_context(&state.db, state.startup_time, state.version).await;

    // Campaign membership for every row with a context line, in one query.
    let ips: Vec<String> = rows
        .iter()
        .filter(|r| r.context.is_some())
        .map(|r| r.ip.clone())
        .collect();
    let mut campaigns = degraded.soft(
        "campaign membership",
        campaigns_by_ip(&state.db, &ips).await,
    );
    // Only the pending tab groups; the history tabs carry no context line.
    let items = if query.tab == Tab::Pending {
        group_pending(std::mem::take(&mut rows), &mut campaigns)
    } else {
        Vec::new()
    };

    let tmpl = state.templates.get_template("queue.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "queue",
        pending_count,
        volume_pending_count,
        review_pending_count => pending_count - volume_pending_count,
        uptime,
        version,
        degraded => degraded.names(),
        rows,
        items,
        volume,
        sort => query.sort.as_str(),
        tab => query.tab.as_str(),
    })?;
    Ok(Html(html))
}

/// The campaign a pending address is listed under, when it is in any with two or more pending
/// members: the one with the most pending members, then the most hosts, then the lowest id. The
/// rule depends only on the campaigns' own counts, so the same address lands in the same group on
/// every render and under every sort. Its other campaigns are shown on its IP page only.
fn group_home(campaigns: &[CampaignRef]) -> Option<&CampaignRef> {
    campaigns
        .iter()
        .filter(|c| c.pending >= 2)
        .max_by_key(|c| (c.pending, c.members, std::cmp::Reverse(c.id)))
}

/// Turns the sorted pending rows into list items. Rows sharing a home campaign
/// ([`group_home`]) become one [`QueueGroup`] at the position of the first of them, so the current
/// sort applies to a group through its top member; a campaign with only one row on the page, and
/// an address in no such campaign, stay single rows (which keep their campaign link, the largest
/// campaign by hosts, and its "approve all" link on the context line).
fn group_pending(
    rows: Vec<QueueRowView>,
    campaigns: &mut HashMap<String, Vec<CampaignRef>>,
) -> Vec<QueueItem> {
    let homes: Vec<Option<CampaignRef>> = rows
        .iter()
        .map(|r| {
            campaigns
                .get(&r.ip)
                .and_then(|list| group_home(list))
                .cloned()
        })
        .collect();
    let mut on_page: HashMap<i64, usize> = HashMap::new();
    for home in homes.iter().flatten() {
        *on_page.entry(home.id).or_default() += 1;
    }

    let mut items: Vec<QueueItem> = Vec::new();
    let mut group_at: HashMap<i64, usize> = HashMap::new();
    for (mut row, home) in rows.into_iter().zip(homes) {
        let grouped = home.filter(|h| on_page.get(&h.id).copied().unwrap_or(0) >= 2);
        let Some(home) = grouped else {
            if let Some(context) = row.context.as_mut() {
                context.campaign = campaigns
                    .remove(&row.ip)
                    .and_then(|list| list.into_iter().next());
            }
            items.push(QueueItem {
                group: None,
                row: Some(row),
            });
            continue;
        };
        let at = *group_at.entry(home.id).or_insert_with(|| {
            items.push(QueueItem {
                group: Some(QueueGroup {
                    id: home.id,
                    label: home.label.clone(),
                    kind: home.kind,
                    members: home.members,
                    pending: home.pending,
                    shown: 0,
                    infected: home.role == "infected host",
                    what: None,
                    top_score: row.score.clone(),
                    rows: Vec::new(),
                }),
                row: None,
            });
            items.len() - 1
        });
        let group = items[at].group.as_mut().expect("index names a group");
        if group.what.is_none() {
            group.what = row.context.as_ref().and_then(|c| c.notable.clone());
        }
        // The header already says what the group did; a member that did exactly that does not
        // repeat it, so what remains on its line is what sets it apart.
        if let (Some(what), Some(context)) = (&group.what, row.context.as_mut())
            && context
                .notable
                .as_ref()
                .is_some_and(|n| n.kind == what.kind && n.text == what.text)
        {
            context.notable = None;
        }
        group.shown += 1;
        group.rows.push(row);
    }
    items
}

fn sort_pending(rows: &mut [(IpAddr, Option<String>, IpScore)], key: SortKey) {
    use std::cmp::Reverse;
    match key {
        // Highest severity first - the spec's default.
        SortKey::Score => rows.sort_by_key(|r| Reverse(r.2.raw_score)),
        // Oldest-pending-first: the natural order to clear a backlog.
        SortKey::FirstSeen => rows.sort_by_key(|r| r.2.first_seen),
        // Most recently active first - the freshest signal. By the last completed connection:
        // `last_seen` also moves on a datagram, whose sender chose the address it names, so
        // sorted on it anyone could lift a candidate to the top of the operator's list.
        SortKey::LastSeen => rows.sort_by_key(|r| Reverse(last_connection(&r.2))),
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

    let mut rows = Vec::with_capacity(pending.len());
    for (ip, notes, score) in pending {
        let mut row = row_view(
            ip,
            ReviewState::Pending,
            notes.as_deref(),
            &score,
            csrf_token,
        );
        row.context = Some(row_context(pool, ip, score.event_count).await?);
        rows.push(row);
    }
    Ok(rows)
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
    csrf_token: &str,
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
            csrf_token,
        ));
    }
    Ok(rows)
}

/// The volume tab: every pending volume candidate, oldest-surfaced first, each with its live
/// projection and the pending tab's context line; then the latest decided ones.
///
/// A pending row whose address has no projection is omitted, as on the pending tab; the next
/// queue scan withdraws it. Decided rows are shown from `volume_review` alone, so a decision
/// stays visible, and reversible, whatever has happened to the address since.
async fn volume_view(pool: &PgPool, csrf_token: &str) -> Result<VolumeView, AppError> {
    let queue = VolumeQueue::new();

    let mut pending = Vec::new();
    for entry in queue.list_pending(pool).await? {
        let ip = entry.source_ip;
        let Some(score) = read_score(pool, ip).await? else {
            tracing::warn!(
                %ip,
                "pending volume candidate has no ip_score projection; omitting from queue page"
            );
            continue;
        };
        let mut row = volume_row_view(&entry, Some(&score), csrf_token);
        row.context = Some(row_context(pool, ip, score.event_count).await?);
        pending.push(row);
    }

    // Each state is read newest-first and bounded, so the merge below holds the newest
    // `VOLUME_DECIDED_SHOWN` decisions overall without reading the whole history.
    let limit = Some(VOLUME_DECIDED_SHOWN as i64);
    let mut decided = queue
        .list_by_state(pool, ReviewState::Approved, limit)
        .await?;
    decided.extend(
        queue
            .list_by_state(pool, ReviewState::Rejected, limit)
            .await?,
    );
    decided.sort_by_key(|e| std::cmp::Reverse(e.decided_at));
    decided.truncate(VOLUME_DECIDED_SHOWN);

    Ok(VolumeView {
        pending,
        decided: decided
            .iter()
            .map(|entry| volume_row_view(entry, None, csrf_token))
            .collect(),
    })
}

fn volume_row_view(
    entry: &VolumeEntry,
    score: Option<&IpScore>,
    csrf_token: &str,
) -> VolumeRowView {
    VolumeRowView {
        ip: entry.source_ip.to_string(),
        state: review_state_label(entry.state),
        is_pending: entry.state == ReviewState::Pending,
        established_now: score.map_or(0, |s| s.established_event_count),
        established_at_surface: entry.established_events_at_surface,
        event_count: score.map_or(0, |s| s.event_count),
        // The last completed connection, which is the clock a volume listing and its approval's
        // lapse run on. Not `last_seen`: that moves on any datagram naming the address, and an
        // operator shown it would read a stopped flood as a live one.
        last_seen: score
            .and_then(|s| s.established_last_seen)
            .map(format_timestamp)
            .unwrap_or_default(),
        decided_at: entry.decided_at.map(format_timestamp).unwrap_or_default(),
        notes: entry.notes.clone().unwrap_or_default(),
        csrf_token: csrf_token.to_string(),
        context: None,
    }
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

/// `POST /queue/{ip}/unsnooze` - put a decided entry back in the pending queue.
///
/// Snoozing promises a later decision, and `ReviewQueue::populate` deliberately never re-surfaces
/// a decided row, so this is the route that keeps the promise. It answers with the row re-rendered
/// as a PENDING row, which is what the Snoozed tab needs: the entry now carries the three ordinary
/// decision controls in place.
async fn unsnooze(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
    Form(form): Form<ActionForm>,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        tracing::warn!(%ip, "queue unsnooze rejected: missing or invalid csrf token");
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    ReviewQueue::new().unsnooze(&state.db, ip).await?;

    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let Some(score) = read_score(&state.db, ip).await? else {
        return Err(AppError::missing_projection(ip));
    };
    let row = row_view(ip, ReviewState::Pending, None, &score, &csrf_token);
    let tmpl = state
        .templates
        .get_template(response_row_template(&form.from_tab))?;
    Ok(Html(tmpl.render(context! { row })?).into_response())
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

    let tmpl = state
        .templates
        .get_template(response_row_template(&form.from_tab))?;
    let html = tmpl.render(context! { row })?;
    Ok(Html(html).into_response())
}

/// The three things an operator can do to a volume candidate.
#[derive(Debug, Clone, Copy)]
enum VolumeAction {
    Approve,
    Reject,
    Reopen,
}

/// `POST /volume/{ip}/approve` - publish a volume candidate in the retention feeds. It is not
/// reported to abuse vendors: that is what `POST /queue/{ip}/approve` does, on the other queue.
async fn volume_approve(
    state: State<AppState>,
    session: Extension<Session>,
    path: Path<IpAddr>,
    form: Form<ActionForm>,
) -> Result<Response, AppError> {
    volume_act(state, session, path, form, VolumeAction::Approve).await
}

/// `POST /volume/{ip}/reject` - keep a volume candidate out of the retention feeds. The row
/// stays, so the scan does not offer the address again.
async fn volume_reject(
    state: State<AppState>,
    session: Extension<Session>,
    path: Path<IpAddr>,
    form: Form<ActionForm>,
) -> Result<Response, AppError> {
    volume_act(state, session, path, form, VolumeAction::Reject).await
}

/// `POST /volume/{ip}/reopen` - return a decided volume candidate to pending. The way to undo an
/// approval (the address leaves the retention feeds at the next build) or a rejection.
async fn volume_reopen(
    state: State<AppState>,
    session: Extension<Session>,
    path: Path<IpAddr>,
    form: Form<ActionForm>,
) -> Result<Response, AppError> {
    volume_act(state, session, path, form, VolumeAction::Reopen).await
}

/// The volume decisions, built like [`act`]: CSRF first, then the one state change, then the row
/// re-rendered for the HTMX swap.
///
/// A decision made in the pending list answers with that row carrying its new state. A reopen is
/// made from the decided list, whose row no longer belongs there, so it answers with the
/// acknowledgement that says where the candidate went.
async fn volume_act(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
    Form(form): Form<ActionForm>,
    action: VolumeAction,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        tracing::warn!(%ip, "volume queue action rejected: missing or invalid csrf token");
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    let notes = form.notes.trim();
    let notes = if notes.is_empty() { None } else { Some(notes) };

    let queue = VolumeQueue::new();
    match action {
        VolumeAction::Approve => queue.approve(&state.db, ip, notes).await,
        VolumeAction::Reject => queue.reject(&state.db, ip, notes).await,
        VolumeAction::Reopen => queue.reopen(&state.db, ip).await,
    }?;

    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    // Read back rather than assembled from the request, so the row shows what was stored.
    let Some(entry) = queue.get(&state.db, ip).await? else {
        // Decided a moment ago and gone already: a delist or delete landed in between.
        return Err(review::ReviewError::VolumeNotFound(ip).into());
    };
    let (template, score) = match action {
        VolumeAction::Reopen => ("queue_volume_decided_row.html", None),
        VolumeAction::Approve | VolumeAction::Reject => {
            let Some(score) = read_score(&state.db, ip).await? else {
                return Err(AppError::missing_projection(ip));
            };
            ("queue_volume_row.html", Some(score))
        }
    };
    let row = volume_row_view(&entry, score.as_ref(), &csrf_token);
    let tmpl = state.templates.get_template(template)?;
    Ok(Html(tmpl.render(context! { row })?).into_response())
}

/// Which row template answers a decision made from `from_tab`.
///
/// The pending tab keeps its existing behaviour: the decided row is re-rendered in place with a
/// state pill, which fits the pending table's columns exactly. A history tab's columns are
/// different and the row no longer belongs to that tab at all, so it gets the acknowledgement row
/// instead.
fn response_row_template(from_tab: &str) -> &'static str {
    if from_tab.is_empty() || from_tab == Tab::Pending.as_str() {
        "queue_row.html"
    } else {
        "queue_moved_row.html"
    }
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

    // Under the append lock: an append in flight reads this address's projection and writes it
    // back, and would overwrite the flags set here (see `begin_exclusive`).
    let mut tx = begin_exclusive(&state.db).await?;
    sqlx::query("DELETE FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip.to_string())
        .execute(&mut *tx)
        .await?;
    // The volume decision goes with it, approved or not: a delist takes the address out of every
    // feed, and a relist must not bring an old volume approval back into force unasked.
    sqlx::query("DELETE FROM volume_review WHERE source_ip = $1::inet")
        .bind(ip.to_string())
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "UPDATE ip_score SET delisted = TRUE, eligible = FALSE, recommended_for_vendor = FALSE, \
         recommended_for_blocklist = FALSE WHERE source_ip = $1::inet",
    )
    .bind(ip.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    tracing::info!(%ip, "ip delisted from feed and queue");
    Ok(Redirect::to(&format!("/ip/{ip}")).into_response())
}

/// `POST /ip/{ip}/relist` - undo a delist.
///
/// The console tour says a delist "keeps it out of the feed until you say otherwise"; this is how
/// the operator says otherwise. Without it, `delist` is a one-way door wearing the word "until".
///
/// It clears the `delisted` latch and then re-derives the gate flags rather than assigning them:
/// `delist` wrote `eligible`/`recommended_for_vendor`/`recommended_for_blocklist` as FALSE
/// directly, and setting them back to TRUE here would claim gates this address may no longer pass
/// (its score decays while delisted, and the category weights with it). Clearing the latch first
/// and reading the projection back gives the same answer `core_scoring` would give for any other
/// address.
///
/// The times the address earned its tiers (`aggressive_earned_at`, `standard_earned_at`) are not
/// touched by `delist` or by this: delisting holds a listing, it does not erase what was earned.
/// So a relisted address resumes what is left of its listing once it is approved again, and one
/// whose listing ran out while it was delisted stays out until it earns a tier again.
///
/// It does NOT restore the review-queue entry `delist` deleted: that entry was a recommendation,
/// and the population scan re-creates one on its next pass iff the address still qualifies (it
/// is eligible again and has earned a tier). The
/// same holds for a volume candidate: `delist` deleted its `volume_review` row, decision
/// included, and the volume scan offers the address again, pending, iff it still qualifies. Same
/// CSRF gate as `delist`.
async fn relist(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(ip): Path<IpAddr>,
    Form(form): Form<ActionForm>,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    // Under the append lock, so the re-derived flags are not overwritten by an append in flight.
    let mut tx = begin_exclusive(&state.db).await?;
    let cleared = sqlx::query("UPDATE ip_score SET delisted = FALSE WHERE source_ip = $1::inet")
        .bind(ip.to_string())
        .execute(&mut *tx)
        .await?;
    if cleared.rows_affected() == 0 {
        return Err(AppError::missing_projection(ip));
    }

    // Read the projection back with the latch cleared: `read_score` re-derives every gate from the
    // stored row through the same `core_scoring` rules the append path uses, so this cannot drift
    // from what an ordinary event would have computed.
    let Some(score) = read_score(&mut *tx, ip).await? else {
        return Err(AppError::missing_projection(ip));
    };
    sqlx::query(
        "UPDATE ip_score SET eligible = $1, recommended_for_vendor = $2, \
         recommended_for_blocklist = $3 WHERE source_ip = $4::inet",
    )
    .bind(score.eligible)
    .bind(score.recommended_for_vendor)
    .bind(score.recommended_for_blocklist)
    .bind(ip.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    tracing::info!(
        %ip,
        eligible = score.eligible,
        recommended_for_vendor = score.recommended_for_vendor,
        recommended_for_blocklist = score.recommended_for_blocklist,
        "ip relisted; gates re-derived from the current projection"
    );
    Ok(Redirect::to(&format!("/ip/{ip}")).into_response())
}

/// `POST /ip/{ip}/delete` - purge an address's derived state (scoring projection, review-queue
/// entry, volume-review entry, and vendor-submission history), for a false positive or a test
/// address an operator wants gone rather than merely delisted.
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
    // Under the append lock, so an append in flight cannot write the purged row back.
    let mut tx = begin_exclusive(&state.db).await?;
    sqlx::query("DELETE FROM review_queue WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&mut *tx)
        .await?;
    // An approved volume row left behind would publish the address again the moment it sent
    // another thousand connections, on a decision made about state this purge just discarded.
    sqlx::query("DELETE FROM volume_review WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM vendor_submission WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM ip_score WHERE source_ip = $1::inet")
        .bind(&ip_str)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    tracing::info!(%ip, "ip purged from scoring/review/vendor state (event ledger retained)");
    // The ip_score row is gone, so /ip/{ip} would 404 - send the operator back to the queue.
    Ok(Redirect::to("/queue").into_response())
}

/// The address's last completed connection. `last_seen` stands in only for a row with none on
/// record, which the queue does not offer.
fn last_connection(score: &IpScore) -> DateTime<Utc> {
    score.established_last_seen.unwrap_or(score.last_seen)
}

/// The tier the address last earned, by the later of its two earned times. The queue offers an
/// address because it earned a tier, and a listing runs from that time. `score.tier` is the
/// tier its score holds at this moment (the projection is decayed to now when it is read), which
/// is none once the score has decayed, or after one later low-weight connection. A row with no
/// earned time on record shows that live tier.
fn earned_tier(score: &IpScore) -> Option<FeedTier> {
    match (score.aggressive_earned_at, score.standard_earned_at) {
        (Some(aggressive), Some(standard)) if standard > aggressive => Some(FeedTier::Standard),
        (Some(_), _) => Some(FeedTier::Aggressive),
        (None, Some(_)) => Some(FeedTier::Standard),
        (None, None) => score.tier,
    }
}

fn row_view(
    ip: IpAddr,
    review_state: ReviewState,
    notes: Option<&str>,
    score: &IpScore,
    csrf_token: &str,
) -> QueueRowView {
    let (active, active_title) =
        format_active(score.first_seen, last_connection(score), Utc::now());
    QueueRowView {
        ip: ip.to_string(),
        state: review_state_label(review_state),
        is_pending: review_state == ReviewState::Pending,
        score: format!("{:.1}", score.raw_score),
        tier: earned_tier(score).map(tier_label).unwrap_or("-"),
        tier_title: score
            .tier_earned_at()
            .map(|at| format!("earned {}", format_timestamp(at)))
            .unwrap_or_default(),
        event_count: score.event_count,
        active,
        active_title,
        decided_at: String::new(),
        submissions: String::new(),
        notes: notes.unwrap_or_default().to_string(),
        csrf_token: csrf_token.to_string(),
        context: None,
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
    csrf_token: &str,
) -> QueueRowView {
    let mut row = row_view(ip, review_state, notes, score, csrf_token);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn campaign(id: i64, members: i32, pending: i64) -> CampaignRef {
        CampaignRef {
            id,
            kind: "same commands",
            label: format!("campaign {id}"),
            members,
            role: "attacker",
            pending,
        }
    }

    fn home(list: &[CampaignRef]) -> Option<i64> {
        group_home(list).map(|c| c.id)
    }

    #[test]
    fn home_is_the_campaign_with_the_most_pending_members_not_the_most_hosts() {
        let list = [campaign(1, 50, 3), campaign(2, 5, 5)];
        assert_eq!(home(&list), Some(2));
    }

    #[test]
    fn home_ties_on_pending_go_to_more_hosts_then_the_lower_id() {
        assert_eq!(home(&[campaign(1, 5, 4), campaign(2, 9, 4)]), Some(2));
        assert_eq!(home(&[campaign(7, 9, 4), campaign(3, 9, 4)]), Some(3));
    }

    #[test]
    fn a_campaign_with_one_pending_member_is_never_a_home() {
        assert_eq!(home(&[campaign(1, 50, 1), campaign(2, 5, 1)]), None);
        assert_eq!(home(&[]), None);
    }
}
