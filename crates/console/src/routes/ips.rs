//! `GET /ips` - the Attackers table: every scored address, 500 at a time. `GET /ips/rows` is the
//! console's "Load more" for it (the same control as the IP page's timeline and Search): it
//! appends the next 500 below the rows already shown.
//!
//! Loading more is keyset, not `OFFSET`: the button carries the address of the last row shown
//! (`after=`), and the query resumes strictly past that row's `(sort key, source_ip)` - looked up
//! by `ip_score`'s primary key - so the list never repeats or skips a row because addresses were
//! scored while the operator read it, and its cost does not grow with depth. `ip_score` has no
//! index on any sort column, so each load is one bounded scan of the projection table with a
//! top-500 sort (the table holds one row per address, never the event ledger).
//!
//! The score sort orders by a TIME-INVARIANT key rather than the live score itself. Every row's
//! live score decays with the same half-life, so `ln(raw * breadth) + ln 2 * anchor / half_life`
//! orders rows as their live scores do at any instant (both sides of a comparison decay by the
//! same factor) and does not change between two loads. The live score itself is clamped at 100,
//! and clamped rows tie: broken by address, they leave the tie in a different order as they decay
//! below the cap, so rows could trade places between the first load and the next, and a keyset
//! cursor over a moving order repeats and drops rows. The displayed score is still the live one
//! (`LIVE_EFFECTIVE_SCORE_SQL`); the visible difference is that rows showing 100.0 are ordered
//! among themselves by how far past the cap they are.
//!
//! The heading says how many addresses are scored: exact up to
//! [`crate::routes::rowcount::COUNT_CAP`] and past it read from the planner's row estimate,
//! labelled as an estimate.

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
use crate::routes::format::{format_relative_time, format_timestamp, score_pct};
use crate::routes::rowcount::{Count, capped_total};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ips", get(ip_list))
        .route("/ips/rows", get(ip_rows))
}

/// Rows per load.
const PAGE_SIZE: usize = 500;

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

    /// The SQL the list orders and resumes by. One of four literals, never user input.
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
    /// The last address already shown (`/ips/rows` only).
    after: Option<String>,
}

#[derive(Debug, Serialize)]
struct IpRow {
    ip: String,
    raw_score: String,
    score_pct: u32,
    tier: String,
    event_count: i32,
    distinct_categories: i32,
    distinct_wan_count: i32,
    first_seen: String,
    last_seen: String,
    last_seen_relative: String,
    eligible: bool,
}

/// One load's rows in display order, and the cursor for the next load if there is more.
struct Batch {
    rows: Vec<IpRow>,
    next_after: Option<String>,
}

async fn ip_list(
    State(state): State<AppState>,
    Query(params): Query<IpListParams>,
) -> Result<Html<String>, AppError> {
    let sort = SortKey::parse(params.sort.as_deref());
    let desc = params.dir.as_deref() != Some("asc");
    let batch = fetch_batch(&state.db, sort, desc, None).await?;
    let total = total_count(&state.db).await?;

    let base = base_context(&state.db, state.startup_time, state.version).await;
    let tmpl = state.templates.get_template("ips.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "ips",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        ips => batch.rows,
        next_after => batch.next_after,
        cursor_lost => false,
        total => total.value,
        total_exact => total.exact,
        sort => sort.as_str(),
        dir => if desc { "desc" } else { "asc" },
    })?))
}

/// The next batch after `after`. A cursor that does not parse, or names an address no longer
/// scored (deleted since the button was rendered), cannot say where to resume: the fragment adds
/// no rows and says so, rather than starting over and repeating rows already on the page.
async fn ip_rows(
    State(state): State<AppState>,
    Query(params): Query<IpListParams>,
) -> Result<Html<String>, AppError> {
    let sort = SortKey::parse(params.sort.as_deref());
    let desc = params.dir.as_deref() != Some("asc");
    let after = params
        .after
        .as_deref()
        .and_then(|raw| raw.parse::<IpAddr>().ok());
    let after = match after {
        Some(ip) if is_scored(&state.db, ip).await? => Some(ip),
        _ => None,
    };
    let batch = match after {
        Some(ip) => fetch_batch(&state.db, sort, desc, Some(ip)).await?,
        None => Batch {
            rows: Vec::new(),
            next_after: None,
        },
    };
    let tmpl = state.templates.get_template("ips_rows_fragment.html")?;
    Ok(Html(tmpl.render(context! {
        ips => batch.rows,
        next_after => batch.next_after,
        cursor_lost => after.is_none(),
        sort => sort.as_str(),
        dir => if desc { "desc" } else { "asc" },
    })?))
}

async fn is_scored(db: &PgPool, ip: IpAddr) -> Result<bool, AppError> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ip_score WHERE source_ip = $1::inet)")
            .bind(ip.to_string())
            .fetch_one(db)
            .await?,
    )
}

/// The batch after `after` (the first one when `None`), read one row past [`PAGE_SIZE`] so
/// whether more follow is known without a count.
async fn fetch_batch(
    db: &PgPool,
    sort: SortKey,
    desc: bool,
    after: Option<IpAddr>,
) -> Result<Batch, AppError> {
    let key = sort.order_key();
    let (dir, past) = if desc { ("DESC", "<") } else { ("ASC", ">") };
    let resume = match after {
        None => String::new(),
        Some(_) => format!(
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
    let mut raw = match after {
        None => query.fetch_all(db).await?,
        Some(ip) => query.bind(ip.to_string()).fetch_all(db).await?,
    };
    let more = raw.len() > PAGE_SIZE;
    raw.truncate(PAGE_SIZE);
    let next_after = raw.last().map(|r| r.ip.clone()).filter(|_| more);
    let rows = raw
        .into_iter()
        .map(|r| IpRow {
            ip: r.ip,
            raw_score: format!("{:.1}", r.score),
            score_pct: score_pct(r.score),
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
    Ok(Batch { rows, next_after })
}

/// Scored addresses in total: exact up to the counting cap, past it the planner's estimate.
async fn total_count(db: &PgPool) -> Result<Count, AppError> {
    Ok(capped_total(db, "ip_score").await?)
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
