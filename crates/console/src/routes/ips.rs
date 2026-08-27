use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use minijinja::context;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::routes::context::base_context;
use crate::routes::error::AppError;
use crate::routes::format::{format_relative_time, format_timestamp};

pub fn router() -> Router<AppState> {
    Router::new().route("/ips", get(ip_list))
}

#[derive(Debug, Deserialize)]
struct IpListParams {
    sort: Option<String>,
    dir: Option<String>,
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

async fn ip_list(
    State(state): State<AppState>,
    Query(params): Query<IpListParams>,
) -> Result<Html<String>, AppError> {
    let sort_col = params.sort.as_deref().unwrap_or("score");
    let sort_dir = params.dir.as_deref().unwrap_or("desc");

    let raw_rows = match (sort_col, sort_dir) {
        ("events", "asc") => fetch_ips_ordered(&state, "event_count ASC").await?,
        ("events", _) => fetch_ips_ordered(&state, "event_count DESC").await?,
        ("first", "asc") => fetch_ips_ordered(&state, "first_seen ASC").await?,
        ("first", _) => fetch_ips_ordered(&state, "first_seen DESC").await?,
        ("last", "asc") => fetch_ips_ordered(&state, "last_seen ASC").await?,
        ("last", _) => fetch_ips_ordered(&state, "last_seen DESC").await?,
        (_, "asc") => fetch_ips_ordered(&state, "raw_score ASC").await?,
        _ => fetch_ips_ordered(&state, "raw_score DESC").await?,
    };

    let rows: Vec<IpRow> = raw_rows
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

    let total = rows.len();
    let base = base_context(&state.db, state.startup_time, state.version).await;

    let tmpl = state.templates.get_template("ips.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "ips",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        ips => rows,
        total,
        sort => sort_col,
        dir => sort_dir,
    })?))
}

async fn fetch_ips_ordered(state: &AppState, order: &str) -> Result<Vec<IpRowRaw>, AppError> {
    // `order` is one of a fixed set of literals chosen by the caller's match below (never user
    // input), so interpolating it is injection-safe. The score sort and the displayed `score` both
    // use the live projection (`LIVE_EFFECTIVE_SCORE_SQL`, matching the detail page and
    // `core_scoring::read_score`), not the stored `raw_score` anchored at each IP's last event.
    let order_by = match order {
        "raw_score ASC" => format!("{} ASC", crate::routes::LIVE_EFFECTIVE_SCORE_SQL),
        "raw_score DESC" => format!("{} DESC", crate::routes::LIVE_EFFECTIVE_SCORE_SQL),
        other => other.to_string(),
    };
    let sql = format!(
        "SELECT host(source_ip) AS ip, ({frag})::float8 AS score, \
         COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, \
         first_seen, last_seen, eligible FROM ip_score ORDER BY {order_by} LIMIT 500",
        frag = crate::routes::LIVE_EFFECTIVE_SCORE_SQL,
    );
    // Audited: `sql` interpolates only `LIVE_EFFECTIVE_SCORE_SQL` and a fixed `order_by` literal,
    // never user input, so it is injection-safe (see the match above).
    Ok(sqlx::query_as::<_, IpRowRaw>(sqlx::AssertSqlSafe(sql))
        .fetch_all(&state.db)
        .await?)
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
