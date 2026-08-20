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
    let rows = match order {
        "event_count ASC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY event_count ASC LIMIT 500"
        ).fetch_all(&state.db).await?,
        "event_count DESC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY event_count DESC LIMIT 500"
        ).fetch_all(&state.db).await?,
        "first_seen ASC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY first_seen ASC LIMIT 500"
        ).fetch_all(&state.db).await?,
        "first_seen DESC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY first_seen DESC LIMIT 500"
        ).fetch_all(&state.db).await?,
        "last_seen ASC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY last_seen ASC LIMIT 500"
        ).fetch_all(&state.db).await?,
        "last_seen DESC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY last_seen DESC LIMIT 500"
        ).fetch_all(&state.db).await?,
        "raw_score ASC" => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY raw_score ASC LIMIT 500"
        ).fetch_all(&state.db).await?,
        _ => sqlx::query_as::<_, IpRowRaw>(
            "SELECT host(source_ip) AS ip, raw_score::float8 AS score, COALESCE(tier::text, '') AS tier, event_count, distinct_categories, distinct_wan_count, first_seen, last_seen, eligible FROM ip_score ORDER BY raw_score DESC LIMIT 500"
        ).fetch_all(&state.db).await?,
    };
    Ok(rows)
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
