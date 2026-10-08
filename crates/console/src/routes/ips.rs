//! `GET /ips` - the Attackers table: every scored address, 500 to a page.
//!
//! Paging is keyset, not `OFFSET`: a page link carries the address of the row it continues from
//! (`after=` for the next page, `before=` for the previous), and the query resumes strictly past
//! that row's `(sort key, source_ip)` - looked up by `ip_score`'s primary key - so a page never
//! repeats or skips a row because addresses were scored while the operator paged, and its cost
//! does not grow with depth. `ip_score` has no index on any sort column, so each page is one
//! bounded scan of the projection table with a top-500 sort (the table holds one row per address,
//! never the event ledger).
//!
//! The score sort orders by a TIME-INVARIANT key rather than the live score itself. Every row's
//! live score decays with the same half-life, so `ln(raw * breadth) + ln 2 * anchor / half_life`
//! orders rows as their live scores do at any instant (both sides of a comparison decay by the
//! same factor) and does not change between two page loads. The live score itself is clamped at
//! 100, and clamped rows tie: broken by address, they leave the tie in a different order as they
//! decay below the cap, so rows could trade places between the request for page one and the
//! request for page two, and a keyset cursor over a moving order repeats and drops rows. The
//! displayed score is still the live one (`LIVE_EFFECTIVE_SCORE_SQL`); the visible difference is
//! that rows showing 100.0 are ordered among themselves by how far past the cap they are.
//!
//! The heading says which rows are shown out of how many: counts are exact up to
//! [`COUNT_CAP`] and past it read from the planner's row estimate, labelled as an estimate.

use std::net::IpAddr;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use minijinja::context;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::AppState;
use crate::routes::context::base_context;
use crate::routes::error::AppError;
use crate::routes::format::{format_relative_time, format_timestamp, group_digits};

pub fn router() -> Router<AppState> {
    Router::new().route("/ips", get(ip_list))
}

/// Rows per page.
const PAGE_SIZE: usize = 500;

/// The most rows a count reads before it stops and falls back to an estimate.
const COUNT_CAP: i64 = 100_000;

/// The score sort's order key: equal in order to the live effective score at every instant, but
/// constant over time (module doc comment). The literals are `LIVE_EFFECTIVE_SCORE_SQL`'s: the
/// 21600 s half-life and the 0.15-per-WAN breadth factor capped at 0.60. A zero score has no
/// logarithm and sorts last.
const SCORE_ORDER_KEY: &str = "(CASE WHEN raw_score > 0 \
    THEN ln(raw_score::float8 * (1.0 + LEAST(0.60, 0.15 * GREATEST(0, distinct_wan_count - 1)))) \
         + EXTRACT(EPOCH FROM decay_anchor)::float8 * ln(2.0) / 21600.0 \
    ELSE '-Infinity'::float8 END)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Score,
    Events,
    First,
    Last,
}

impl SortKey {
    fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("events") => SortKey::Events,
            Some("first") => SortKey::First,
            Some("last") => SortKey::Last,
            _ => SortKey::Score,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            SortKey::Score => "score",
            SortKey::Events => "events",
            SortKey::First => "first",
            SortKey::Last => "last",
        }
    }

    /// The SQL the page orders and pages by. One of four literals, never user input.
    fn order_key(self) -> &'static str {
        match self {
            SortKey::Score => SCORE_ORDER_KEY,
            SortKey::Events => "event_count",
            SortKey::First => "first_seen",
            SortKey::Last => "last_seen",
        }
    }
}

#[derive(Debug, Deserialize)]
struct IpListParams {
    sort: Option<String>,
    dir: Option<String>,
    /// Continue after this address (the next page).
    after: Option<String>,
    /// Continue before this address (the previous page).
    before: Option<String>,
}

/// Where a page starts.
#[derive(Debug, Clone, Copy)]
enum Cursor {
    First,
    After(IpAddr),
    Before(IpAddr),
}

#[derive(Debug, Serialize)]
struct IpRow {
    ip: String,
    raw_score: String,
    tier: String,
    event_count: i32,
    distinct_categories: i32,
    distinct_wan_count: i32,
    first_seen: String,
    last_seen: String,
    last_seen_relative: String,
    eligible: bool,
}

/// A row count that is exact up to [`COUNT_CAP`] and an estimate past it.
#[derive(Debug, Clone, Copy)]
struct Count {
    value: i64,
    exact: bool,
}

async fn ip_list(
    State(state): State<AppState>,
    Query(params): Query<IpListParams>,
) -> Result<Html<String>, AppError> {
    let sort = SortKey::parse(params.sort.as_deref());
    let desc = params.dir.as_deref() != Some("asc");

    // A cursor that does not parse, or names an address no longer scored (deleted since the link
    // was rendered), cannot say where to resume: start over from the first page and say so,
    // rather than showing an empty page.
    let requested = match (params.after.as_deref(), params.before.as_deref()) {
        (Some(raw), _) => raw.parse().ok().map(Cursor::After),
        (None, Some(raw)) => raw.parse().ok().map(Cursor::Before),
        (None, None) => Some(Cursor::First),
    };
    let cursor = match requested {
        Some(Cursor::After(ip) | Cursor::Before(ip)) if !is_scored(&state.db, ip).await? => None,
        other => other,
    };
    let cursor_lost = cursor.is_none();
    let cursor = cursor.unwrap_or(Cursor::First);

    let page = fetch_page(&state.db, sort, desc, cursor).await?;
    let position = match (cursor, page.rows.first()) {
        (Cursor::First, _) | (_, None) => Count {
            value: 0,
            exact: true,
        },
        (_, Some(first)) => rows_ahead(&state.db, sort, desc, &first.ip).await?,
    };
    let total = total_count(&state.db).await?;

    let next_after = page
        .rows
        .last()
        .map(|r| r.ip.clone())
        .filter(|_| page.has_next);
    let prev_before = page
        .rows
        .first()
        .map(|r| r.ip.clone())
        .filter(|_| page.has_prev);
    let shown = page.rows.len() as i64;
    let rows: Vec<IpRow> = page
        .rows
        .into_iter()
        .map(|r| IpRow {
            ip: r.ip,
            raw_score: format!("{:.1}", r.score),
            tier: if r.tier.is_empty() {
                "-".into()
            } else {
                r.tier
            },
            event_count: r.event_count,
            distinct_categories: r.distinct_categories,
            distinct_wan_count: r.distinct_wan_count,
            first_seen: format_timestamp(r.first_seen),
            last_seen: format_timestamp(r.last_seen),
            last_seen_relative: format_relative_time(r.last_seen),
            eligible: r.eligible,
        })
        .collect();

    let base = base_context(&state.db, state.startup_time, state.version).await;
    let tmpl = state.templates.get_template("ips.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "ips",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        ips => rows,
        shown,
        shown_from => group_digits(position.value + 1),
        shown_to => group_digits(position.value + shown),
        position_exact => position.exact,
        total => group_digits(total.value),
        total_exact => total.exact,
        next_after,
        prev_before,
        cursor_lost,
        sort => sort.as_str(),
        dir => if desc { "desc" } else { "asc" },
    })?))
}

/// One page of rows in display order, and whether pages exist on either side of it.
struct Page {
    rows: Vec<IpRowRaw>,
    has_prev: bool,
    has_next: bool,
}

async fn is_scored(db: &PgPool, ip: IpAddr) -> Result<bool, AppError> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ip_score WHERE source_ip = $1::inet)")
            .bind(ip.to_string())
            .fetch_one(db)
            .await?,
    )
}

/// Fetches the page `cursor` names, one row past [`PAGE_SIZE`] so the far side's existence is
/// known without a count. A `Before` page is read in reverse order from its cursor and flipped.
async fn fetch_page(
    db: &PgPool,
    sort: SortKey,
    desc: bool,
    cursor: Cursor,
) -> Result<Page, AppError> {
    let key = sort.order_key();
    // Reading toward the end of the listing in its own direction, or back toward its start.
    let forward = !matches!(cursor, Cursor::Before(_));
    let read_desc = desc == forward;
    let (dir, past) = if read_desc {
        ("DESC", "<")
    } else {
        ("ASC", ">")
    };
    let resume = match cursor {
        Cursor::First => String::new(),
        Cursor::After(_) | Cursor::Before(_) => format!(
            "WHERE ({key}, source_ip) {past} \
             (SELECT {key}, source_ip FROM ip_score WHERE source_ip = $1::inet)"
        ),
    };
    let sql = format!(
        "SELECT host(source_ip) AS ip, ({live})::float8 AS score, \
         COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, \
         first_seen, last_seen, eligible FROM ip_score {resume} \
         ORDER BY {key} {dir}, source_ip {dir} LIMIT {limit}",
        live = crate::routes::LIVE_EFFECTIVE_SCORE_SQL,
        limit = PAGE_SIZE + 1,
    );
    // Audited: `sql` interpolates only `LIVE_EFFECTIVE_SCORE_SQL`, one of `SortKey::order_key`'s
    // four literals, fixed direction words and the page-size constant. The cursor address is a
    // bound parameter.
    let query = sqlx::query_as::<_, IpRowRaw>(sqlx::AssertSqlSafe(sql));
    let mut rows = match cursor {
        Cursor::First => query.fetch_all(db).await?,
        Cursor::After(ip) | Cursor::Before(ip) => query.bind(ip.to_string()).fetch_all(db).await?,
    };
    let more = rows.len() > PAGE_SIZE;
    rows.truncate(PAGE_SIZE);
    if forward {
        Ok(Page {
            rows,
            has_prev: matches!(cursor, Cursor::After(_)),
            has_next: more,
        })
    } else {
        rows.reverse();
        Ok(Page {
            rows,
            has_prev: more,
            has_next: true,
        })
    }
}

/// How many rows sort ahead of `ip` in this listing: the zero-based position of the page's first
/// row. Stops counting at [`COUNT_CAP`] and says so.
async fn rows_ahead(db: &PgPool, sort: SortKey, desc: bool, ip: &str) -> Result<Count, AppError> {
    let key = sort.order_key();
    let ahead = if desc { ">" } else { "<" };
    let sql = format!(
        "SELECT count(*) FROM (SELECT 1 FROM ip_score WHERE ({key}, source_ip) {ahead} \
         (SELECT {key}, source_ip FROM ip_score WHERE source_ip = $1::inet) LIMIT {COUNT_CAP}) s"
    );
    // Audited: interpolates one of `SortKey::order_key`'s literals, a fixed operator and a
    // constant; the address is bound.
    let value: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(ip)
        .fetch_one(db)
        .await?;
    Ok(Count {
        value,
        exact: value < COUNT_CAP,
    })
}

/// Scored addresses in total: an exact count up to [`COUNT_CAP`], past it the planner's estimate
/// (`pg_class.reltuples`, refreshed by autovacuum), which costs nothing to read.
async fn total_count(db: &PgPool) -> Result<Count, AppError> {
    let counted: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM (SELECT 1 FROM ip_score LIMIT {}) s",
        COUNT_CAP + 1
    )))
    .fetch_one(db)
    .await?;
    if counted <= COUNT_CAP {
        return Ok(Count {
            value: counted,
            exact: true,
        });
    }
    let estimate: f32 =
        sqlx::query_scalar("SELECT reltuples FROM pg_class WHERE oid = 'ip_score'::regclass")
            .fetch_one(db)
            .await?;
    Ok(Count {
        value: (estimate as i64).max(counted),
        exact: false,
    })
}

#[derive(sqlx::FromRow)]
struct IpRowRaw {
    ip: String,
    score: f64,
    tier: String,
    event_count: i32,
    distinct_categories: i32,
    distinct_wan_count: i32,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
    eligible: bool,
}
