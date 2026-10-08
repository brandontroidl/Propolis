//! `GET /campaigns` (every campaign, newest activity first), `GET /campaigns/{id}` (members, the
//! representative session or sample, linked samples and indicators) and the two-step
//! `GET`/`POST /campaigns/{id}/approve`. Session-gated like every page in `routes::mod`'s
//! protected group. The tables are the campaign indexer's (`review::campaign`); this module only
//! reads them, apart from the approve action, which writes review decisions.
//!
//! Approving a campaign is never one click. The GET lists exactly the pending members it would
//! approve and carries that list in its form; the POST approves the addresses in the form that are
//! still pending members of the campaign, and nothing else, so a member that joined after the page
//! was rendered is not approved behind the operator's back. Each approval goes through
//! `ReviewQueue::approve`, the same call the per-row Approve button makes.
//!
//! Everything shown here came from attacker traffic: labels, command shapes, URLs, keys. It is
//! rendered as auto-escaped text, and no indicator is ever a link.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Form, Router};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use minijinja::context;
use review::campaign::Kind;
use review::ioc::{self, IocKind};
use review::queue::ReviewQueue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::base_context;
use crate::routes::error::AppError;
use crate::routes::format::{format_sensor_label, format_timestamp, group_digits};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/campaigns", get(list_page))
        .route("/campaigns/{id}", get(detail_page))
        .route(
            "/campaigns/{id}/approve",
            get(approve_confirm).post(approve_members),
        )
}

/// Campaigns listed on one page.
const LIST_LIMIT: i64 = 200;
/// Members listed on a campaign page.
const MEMBER_LIMIT: i64 = 500;
/// Pending members one confirmation can approve.
pub(crate) const MAX_APPROVE: i64 = 1000;
/// Indicators listed per section of a campaign or sample page.
const IOC_LIMIT: i64 = 200;
/// Most recent members whose command indicators a campaign page reads.
const IOC_MEMBER_SCAN: i64 = 2000;
/// Days in the list page's sparkline, and in the detail page's.
const LIST_SPARK_DAYS: i64 = 14;
const DETAIL_SPARK_DAYS: i64 = 30;

/// What a campaign's members are called. A sample campaign whose script scans for and copies
/// itself to new hosts is a worm, and the hosts that uploaded it are most likely its victims. This
/// is campaign metadata for the operator; vendor submissions do not use it yet.
pub(crate) fn member_role(kind: &str, self_propagating: bool) -> &'static str {
    if kind == Kind::Sample.as_str() && self_propagating {
        "infected host"
    } else {
        "attacker"
    }
}

fn kind_label(kind: &str) -> &'static str {
    Kind::parse(kind).map_or("unknown", Kind::label)
}

/// A link to a campaign, as other pages show it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CampaignRef {
    pub id: i64,
    pub kind: &'static str,
    pub label: String,
    pub members: i32,
    pub role: &'static str,
    /// Members still pending review; filled only where a page shows it.
    pub pending: i64,
}

/// The campaigns each of `ips` belongs to, largest first, at most three per address.
pub(crate) async fn campaigns_by_ip(
    pool: &PgPool,
    ips: &[String],
) -> Result<HashMap<String, Vec<CampaignRef>>, sqlx::Error> {
    if ips.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT ip, id, kind, label, member_count, self_propagating, pending FROM ( \
           SELECT host(m.source_ip) AS ip, c.id, c.kind, c.label, c.member_count, \
                  c.self_propagating, \
                  (SELECT count(*) FROM campaign_member p \
                     JOIN review_queue q ON q.source_ip = p.source_ip AND q.state = 'pending' \
                    WHERE p.campaign_id = c.id) AS pending, \
                  row_number() OVER (PARTITION BY m.source_ip \
                                     ORDER BY c.member_count DESC, c.id) AS rank \
           FROM campaign_member m JOIN campaign c ON c.id = m.campaign_id \
           WHERE m.source_ip = ANY($1::inet[])) ranked \
         WHERE rank <= 3 ORDER BY ip, rank",
    )
    .bind(ips)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<String, Vec<CampaignRef>> = HashMap::new();
    for r in rows {
        let kind: String = r.try_get("kind")?;
        out.entry(r.try_get("ip")?).or_default().push(CampaignRef {
            id: r.try_get("id")?,
            kind: kind_label(&kind),
            label: r.try_get("label")?,
            members: r.try_get("member_count")?,
            role: member_role(&kind, r.try_get("self_propagating")?),
            pending: r.try_get("pending")?,
        });
    }
    Ok(out)
}

/// The sample campaign of each of `shas` that has one.
pub(crate) async fn campaigns_by_sample(
    pool: &PgPool,
    shas: &[String],
) -> Result<HashMap<String, CampaignRef>, sqlx::Error> {
    if shas.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT key, id, label, member_count, self_propagating FROM campaign \
         WHERE kind = 'sample' AND key = ANY($1)",
    )
    .bind(shas)
    .fetch_all(pool)
    .await?;
    let mut out = HashMap::new();
    for r in rows {
        out.insert(
            r.try_get("key")?,
            CampaignRef {
                id: r.try_get("id")?,
                kind: Kind::Sample.label(),
                label: r.try_get("label")?,
                members: r.try_get("member_count")?,
                role: member_role("sample", r.try_get("self_propagating")?),
                pending: 0,
            },
        );
    }
    Ok(out)
}

/// Every campaign linked to the sample `sha256`: its own, and the command sequences whose
/// sessions uploaded it, largest first.
pub(crate) async fn campaigns_linking_sample(
    pool: &PgPool,
    sha256: &str,
) -> Result<Vec<CampaignRef>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT c.id, c.kind, c.label, c.member_count, c.self_propagating \
         FROM campaign_sample s JOIN campaign c ON c.id = s.campaign_id \
         WHERE s.sha256 = $1 ORDER BY c.member_count DESC, c.id LIMIT 50",
    )
    .bind(sha256)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let kind: String = r.try_get("kind")?;
        out.push(CampaignRef {
            id: r.try_get("id")?,
            kind: kind_label(&kind),
            label: r.try_get("label")?,
            members: r.try_get("member_count")?,
            role: member_role(&kind, r.try_get("self_propagating")?),
            pending: 0,
        });
    }
    Ok(out)
}

/// One bar of a distinct-addresses-per-day sparkline, laid out in Rust so the template only places
/// numbers into SVG attributes.
#[derive(Debug, Serialize)]
struct Bar {
    x: i64,
    y: i64,
    h: i64,
    day: String,
    hosts: i64,
}

const SPARK_HEIGHT: i64 = 20;
const SPARK_STEP: i64 = 5;

fn sparkline(counts: &BTreeMap<NaiveDate, i64>, today: NaiveDate, days: i64) -> Vec<Bar> {
    let max = counts.values().copied().max().unwrap_or(0).max(1);
    (0..days)
        .map(|i| {
            let day = today - Duration::days(days - 1 - i);
            let hosts = counts.get(&day).copied().unwrap_or(0);
            let h = if hosts == 0 {
                0
            } else {
                (hosts * SPARK_HEIGHT / max).max(1)
            };
            Bar {
                x: i * SPARK_STEP,
                y: SPARK_HEIGHT - h,
                h,
                day: day.to_string(),
                hosts,
            }
        })
        .collect()
}

async fn day_counts(
    pool: &PgPool,
    ids: &[i64],
    since: NaiveDate,
) -> Result<HashMap<i64, BTreeMap<NaiveDate, i64>>, sqlx::Error> {
    let rows: Vec<(i64, NaiveDate, i64)> = sqlx::query_as(
        "SELECT campaign_id, day, count(*) FROM campaign_member_day \
         WHERE campaign_id = ANY($1) AND day >= $2 GROUP BY 1, 2",
    )
    .bind(ids)
    .bind(since)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<i64, BTreeMap<NaiveDate, i64>> = HashMap::new();
    for (id, day, n) in rows {
        out.entry(id).or_default().insert(day, n);
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
struct SensorCount {
    label: String,
    sightings: i64,
}

async fn sensor_counts(
    pool: &PgPool,
    ids: &[i64],
) -> Result<HashMap<i64, Vec<SensorCount>>, sqlx::Error> {
    let rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT campaign_id, sensor, sightings FROM campaign_sensor WHERE campaign_id = ANY($1) \
         ORDER BY campaign_id, sightings DESC, sensor",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<i64, Vec<SensorCount>> = HashMap::new();
    for (id, sensor, sightings) in rows {
        out.entry(id).or_default().push(SensorCount {
            label: format_sensor_label(&sensor),
            sightings,
        });
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
struct SampleLink {
    sha256: String,
    short: String,
}

async fn linked_samples(
    pool: &PgPool,
    ids: &[i64],
    per_campaign: usize,
) -> Result<HashMap<i64, (Vec<SampleLink>, usize)>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT campaign_id, sha256 FROM campaign_sample WHERE campaign_id = ANY($1) \
         ORDER BY campaign_id, sha256",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<i64, (Vec<SampleLink>, usize)> = HashMap::new();
    for (id, sha) in rows {
        let entry = out.entry(id).or_default();
        if entry.0.len() < per_campaign {
            entry.0.push(SampleLink {
                short: sha.chars().take(12).collect(),
                sha256: sha,
            });
        } else {
            entry.1 += 1;
        }
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    kind: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListRow {
    id: i64,
    kind: &'static str,
    label: String,
    members: i32,
    sightings: String,
    first_seen: String,
    last_seen: String,
    role: &'static str,
    spark: Vec<Bar>,
    sensors: Vec<SensorCount>,
    samples: Vec<SampleLink>,
    more_samples: usize,
}

#[derive(Debug, Serialize)]
struct KindTab {
    value: &'static str,
    label: &'static str,
}

/// How far the indexer has read: the cursor against the newest ledger id. Both are primary-key
/// reads, so this costs nothing however large the ledger is.
pub(crate) async fn indexer_progress(pool: &PgPool) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT (SELECT last_event_id FROM campaign_cursor WHERE singleton), \
                (SELECT coalesce(max(id), 0) FROM event)",
    )
    .fetch_one(pool)
    .await
}

async fn list_page(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Html<String>, AppError> {
    let kind = query.kind.as_deref().and_then(Kind::parse);
    let kind_text = kind.map(Kind::as_str);
    let rows = sqlx::query(
        "SELECT id, kind, label, member_count, sightings, first_seen, last_seen, self_propagating \
         FROM campaign WHERE ($1::text IS NULL OR kind = $1) \
         ORDER BY last_seen DESC, id DESC LIMIT $2",
    )
    .bind(kind_text)
    .bind(LIST_LIMIT)
    .fetch_all(&state.db)
    .await?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM campaign WHERE ($1::text IS NULL OR kind = $1)")
            .bind(kind_text)
            .fetch_one(&state.db)
            .await?;
    let ids: Vec<i64> = rows
        .iter()
        .map(|r| r.try_get("id"))
        .collect::<Result<_, _>>()?;

    let base = base_context(&state.db, state.startup_time, state.version).await;
    let mut degraded = base.degraded;
    let today = Utc::now().date_naive();
    let days = degraded.soft(
        "activity sparklines",
        day_counts(&state.db, &ids, today - Duration::days(LIST_SPARK_DAYS - 1)).await,
    );
    let mut sensors = degraded.soft("campaign sensors", sensor_counts(&state.db, &ids).await);
    let mut samples = degraded.soft("linked samples", linked_samples(&state.db, &ids, 3).await);
    let (indexed, newest) = degraded.soft("indexer progress", indexer_progress(&state.db).await);

    let mut campaigns = Vec::with_capacity(rows.len());
    for r in rows {
        let id: i64 = r.try_get("id")?;
        let kind: String = r.try_get("kind")?;
        let (sample_links, more_samples) = samples.remove(&id).unwrap_or_default();
        let mut top = sensors.remove(&id).unwrap_or_default();
        top.truncate(3);
        campaigns.push(ListRow {
            id,
            kind: kind_label(&kind),
            label: r.try_get("label")?,
            members: r.try_get("member_count")?,
            sightings: group_digits(r.try_get("sightings")?),
            first_seen: format_timestamp(r.try_get("first_seen")?),
            last_seen: format_timestamp(r.try_get("last_seen")?),
            role: member_role(&kind, r.try_get("self_propagating")?),
            spark: sparkline(
                &days.get(&id).cloned().unwrap_or_default(),
                today,
                LIST_SPARK_DAYS,
            ),
            sensors: top,
            samples: sample_links,
            more_samples,
        });
    }

    let tabs: Vec<KindTab> = Kind::ALL
        .iter()
        .map(|k| KindTab {
            value: k.as_str(),
            label: k.label(),
        })
        .collect();
    let tmpl = state.templates.get_template("campaigns.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "campaigns",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        campaigns,
        total,
        shown_limit => LIST_LIMIT,
        kind => kind_text.unwrap_or(""),
        tabs,
        indexed,
        newest,
        indexer_behind => newest.saturating_sub(indexed),
        spark_days => LIST_SPARK_DAYS,
        spark_width => LIST_SPARK_DAYS * SPARK_STEP,
        spark_height => SPARK_HEIGHT,
    })?))
}

#[derive(Debug, Serialize)]
struct MemberRow {
    ip: String,
    first_seen: String,
    last_seen: String,
    sightings: i64,
    uploaded: bool,
    review: Option<String>,
}

/// One indicator as a page lists it.
#[derive(Debug, Serialize)]
pub(crate) struct IocRow {
    pub kind: &'static str,
    /// As stored: offered only through the explicit "copy original" action.
    pub value: String,
    /// What the page shows and the plain copy action copies (`review::ioc::defang`).
    pub defanged: String,
    pub detail: String,
    /// The artifact it came from (a sample digest), or the address and event of the first
    /// command that carried it.
    pub sample: Option<String>,
    pub source_ip: Option<String>,
    pub event_id: Option<i64>,
    pub sightings: i64,
    /// Members whose commands carried it; a campaign of two hundred hosts running one script
    /// lists each of its indicators once, not two hundred times.
    pub hosts: i64,
}

fn ioc_row(r: &sqlx::postgres::PgRow) -> Result<IocRow, sqlx::Error> {
    let kind: String = r.try_get("kind")?;
    let value: String = r.try_get("value")?;
    let detail: String = r.try_get("detail")?;
    Ok(IocRow {
        kind: IocKind::parse(&kind).map_or("indicator", IocKind::label),
        defanged: ioc::defang(&value),
        value,
        detail: ioc::defang(&detail),
        sample: r.try_get("artifact_sha256")?,
        source_ip: r.try_get("source_ip")?,
        event_id: r.try_get("event_id")?,
        sightings: r.try_get("sightings")?,
        hosts: r.try_get("hosts")?,
    })
}

/// Indicators extracted from the artifact `sha256`.
pub(crate) async fn artifact_iocs(pool: &PgPool, sha256: &str) -> Result<Vec<IocRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT kind, value, detail, artifact_sha256, NULL::text AS source_ip, \
                NULL::bigint AS event_id, sightings, 1::bigint AS hosts \
         FROM ioc WHERE artifact_sha256 = $1 ORDER BY kind, value LIMIT $2",
    )
    .bind(sha256)
    .bind(IOC_LIMIT)
    .fetch_all(pool)
    .await?;
    rows.iter().map(ioc_row).collect()
}

/// What the representative of a campaign shows: a command sequence's shapes, a sample's origin,
/// or a scanner's sensor set. Every string is attacker-derived and rendered escaped.
#[derive(Debug, Default, Serialize)]
struct Representative {
    source_ip: Option<String>,
    session_id: Option<String>,
    shapes: Vec<String>,
    sha256: Option<String>,
    origin: Option<String>,
    orig_name: Option<String>,
    url: Option<String>,
    sensors: Vec<String>,
}

fn representative(value: &Value) -> Representative {
    let text = |k: &str| {
        value
            .get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let list = |k: &str| -> Vec<String> {
        value
            .get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Representative {
        source_ip: text("source_ip"),
        session_id: text("session_id"),
        shapes: list("shapes"),
        sha256: text("sha256"),
        origin: text("origin"),
        orig_name: text("orig_name"),
        url: text("url").map(|u| ioc::defang(&u)),
        sensors: list("sensors"),
    }
}

/// The campaign's pending members, at most [`MAX_APPROVE`], in address order.
async fn pending_members(pool: &PgPool, id: i64) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT host(m.source_ip) FROM campaign_member m \
         JOIN review_queue q ON q.source_ip = m.source_ip AND q.state = 'pending' \
         WHERE m.campaign_id = $1 ORDER BY m.source_ip LIMIT $2",
    )
    .bind(id)
    .bind(MAX_APPROVE)
    .fetch_all(pool)
    .await
}

fn not_found(id: i64) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Campaign not found</title>\
             <link rel=\"stylesheet\" href=\"/assets/console.css\">\
             <p class=\"message-page\">No campaign {id}. <a href=\"/campaigns\">All campaigns</a></p>"
        )),
    )
        .into_response()
}

async fn detail_page(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let Some(c) = sqlx::query(
        "SELECT kind, key, label, representative, first_seen, last_seen, member_count, sightings, \
                self_propagating FROM campaign WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    else {
        return Ok(not_found(id));
    };
    let kind: String = c.try_get("kind")?;
    let key: String = c.try_get("key")?;

    let member_rows = sqlx::query(
        "SELECT host(m.source_ip) AS ip, m.first_seen, m.last_seen, m.sightings, m.uploaded, \
                q.state::text AS review \
         FROM campaign_member m LEFT JOIN review_queue q ON q.source_ip = m.source_ip \
         WHERE m.campaign_id = $1 ORDER BY m.last_seen DESC, m.source_ip LIMIT $2",
    )
    .bind(id)
    .bind(MEMBER_LIMIT)
    .fetch_all(&state.db)
    .await?;
    let mut members = Vec::with_capacity(member_rows.len());
    for r in &member_rows {
        members.push(MemberRow {
            ip: r.try_get("ip")?,
            first_seen: format_timestamp(r.try_get("first_seen")?),
            last_seen: format_timestamp(r.try_get("last_seen")?),
            sightings: r.try_get("sightings")?,
            uploaded: r.try_get("uploaded")?,
            review: r.try_get("review")?,
        });
    }

    let base = base_context(&state.db, state.startup_time, state.version).await;
    let mut degraded = base.degraded;
    let pending = degraded.soft("pending members", pending_members(&state.db, id).await);
    let today = Utc::now().date_naive();
    let days = degraded.soft(
        "activity sparkline",
        day_counts(
            &state.db,
            &[id],
            today - Duration::days(DETAIL_SPARK_DAYS - 1),
        )
        .await,
    );
    let sensors = degraded
        .soft("campaign sensors", sensor_counts(&state.db, &[id]).await)
        .remove(&id)
        .unwrap_or_default();
    let (samples, more_samples) = degraded
        .soft("linked samples", linked_samples(&state.db, &[id], 50).await)
        .remove(&id)
        .unwrap_or_default();

    let artifact_iocs = degraded.soft(
        "artifact indicators",
        async {
            let rows = sqlx::query(
                "SELECT kind, value, detail, artifact_sha256, NULL::text AS source_ip, \
                        NULL::bigint AS event_id, sightings, 1::bigint AS hosts \
                 FROM ioc WHERE artifact_sha256 IN \
                     (SELECT sha256 FROM campaign_sample WHERE campaign_id = $1) \
                 ORDER BY kind, value LIMIT $2",
            )
            .bind(id)
            .bind(IOC_LIMIT)
            .fetch_all(&state.db)
            .await?;
            rows.iter().map(ioc_row).collect::<Result<Vec<_>, _>>()
        }
        .await,
    );
    let command_iocs = degraded.soft(
        "command indicators",
        async {
            // One row per indicator, with how many members carried it and the earliest event
            // that did, read from the most recent members so a huge campaign stays bounded.
            let rows = sqlx::query(
                "SELECT i.kind, i.value, (array_agg(i.detail ORDER BY i.event_id))[1] AS detail, \
                        NULL::text AS artifact_sha256, \
                        (array_agg(host(i.source_ip) ORDER BY i.event_id))[1] AS source_ip, \
                        min(i.event_id) AS event_id, sum(i.sightings)::bigint AS sightings, \
                        count(DISTINCT i.source_ip) AS hosts \
                 FROM ioc i JOIN ( \
                     SELECT source_ip FROM campaign_member WHERE campaign_id = $1 \
                     ORDER BY last_seen DESC LIMIT $3) m ON m.source_ip = i.source_ip \
                 WHERE i.artifact_sha256 IS NULL \
                 GROUP BY i.kind, i.value \
                 ORDER BY hosts DESC, sightings DESC, i.kind, i.value LIMIT $2",
            )
            .bind(id)
            .bind(IOC_LIMIT)
            .bind(IOC_MEMBER_SCAN)
            .fetch_all(&state.db)
            .await?;
            rows.iter().map(ioc_row).collect::<Result<Vec<_>, _>>()
        }
        .await,
    );

    let self_propagating: bool = c.try_get("self_propagating")?;
    let tmpl = state.templates.get_template("campaign_detail.html")?;
    let html = tmpl.render(context! {
        active_nav => "campaigns",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        id,
        kind => kind_label(&kind),
        kind_value => kind,
        key,
        label => c.try_get::<String, _>("label")?,
        representative => representative(&c.try_get::<Value, _>("representative")?),
        first_seen => format_timestamp(c.try_get::<DateTime<Utc>, _>("first_seen")?),
        last_seen => format_timestamp(c.try_get::<DateTime<Utc>, _>("last_seen")?),
        member_count => c.try_get::<i32, _>("member_count")?,
        sightings => group_digits(c.try_get("sightings")?),
        role => member_role(&kind, self_propagating),
        self_propagating,
        members,
        member_limit => MEMBER_LIMIT,
        pending_members => pending.len(),
        spark => sparkline(&days.get(&id).cloned().unwrap_or_default(), today, DETAIL_SPARK_DAYS),
        spark_width => DETAIL_SPARK_DAYS * SPARK_STEP,
        spark_height => SPARK_HEIGHT,
        spark_days => DETAIL_SPARK_DAYS,
        sensors,
        samples,
        more_samples,
        artifact_iocs,
        command_iocs,
    })?;
    Ok(Html(html).into_response())
}

async fn approve_confirm(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let Some(label) = sqlx::query_scalar::<_, String>("SELECT label FROM campaign WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
    else {
        return Ok(not_found(id));
    };
    let pending = pending_members(&state.db, id).await?;
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let tmpl = state.templates.get_template("campaign_approve.html")?;
    let html = tmpl.render(context! {
        active_nav => "campaigns",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => base.degraded.names(),
        csrf_token,
        id,
        label,
        confirming => true,
        ips => pending.join(","),
        pending,
        max_approve => MAX_APPROVE,
    })?;
    Ok(Html(html).into_response())
}

#[derive(Debug, Deserialize)]
struct ApproveForm {
    csrf_token: String,
    /// The addresses the confirmation page listed, comma-separated.
    #[serde(default)]
    ips: String,
    #[serde(default)]
    notes: String,
}

/// The addresses in a confirmation form, or `None` when one is not an address or there are more
/// than [`MAX_APPROVE`].
fn parse_confirmed(ips: &str) -> Option<Vec<IpAddr>> {
    let parsed: Vec<IpAddr> = ips
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    (parsed.len() as i64 <= MAX_APPROVE).then_some(parsed)
}

async fn approve_members(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
    Form(form): Form<ApproveForm>,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        tracing::warn!(
            campaign = id,
            "campaign approve rejected: missing or invalid csrf token"
        );
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }
    let Some(confirmed) = parse_confirmed(&form.ips) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "the confirmed address list is malformed",
        )
            .into_response());
    };
    let Some(label) = sqlx::query_scalar::<_, String>("SELECT label FROM campaign WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
    else {
        return Ok(not_found(id));
    };
    let confirmed_text: Vec<String> = confirmed.iter().map(IpAddr::to_string).collect();
    // Only what the operator confirmed AND is still a pending member right now.
    let eligible: Vec<String> = sqlx::query_scalar(
        "SELECT host(m.source_ip) FROM campaign_member m \
         JOIN review_queue q ON q.source_ip = m.source_ip AND q.state = 'pending' \
         WHERE m.campaign_id = $1 AND m.source_ip = ANY($2::inet[]) ORDER BY m.source_ip",
    )
    .bind(id)
    .bind(&confirmed_text)
    .fetch_all(&state.db)
    .await?;

    let notes = form.notes.trim();
    let notes = if notes.is_empty() {
        format!("approved with campaign {id}")
    } else {
        notes.chars().take(2000).collect()
    };
    let queue = ReviewQueue::new();
    let mut approved = Vec::with_capacity(eligible.len());
    for ip_text in &eligible {
        let Ok(ip) = ip_text.parse::<IpAddr>() else {
            continue;
        };
        queue.approve(&state.db, ip, Some(&notes)).await?;
        approved.push(ip_text.clone());
    }
    let skipped: Vec<String> = confirmed_text
        .into_iter()
        .filter(|ip| !eligible.iter().any(|e| e == ip))
        .collect();
    tracing::info!(
        campaign = id,
        approved = approved.len(),
        skipped = skipped.len(),
        "campaign members approved by the operator"
    );

    let base = base_context(&state.db, state.startup_time, state.version).await;
    let tmpl = state.templates.get_template("campaign_approve.html")?;
    let html = tmpl.render(context! {
        active_nav => "campaigns",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => base.degraded.names(),
        id,
        label,
        confirming => false,
        approved,
        skipped,
    })?;
    Ok(Html(html).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sparkline_scales_to_the_busiest_day_and_keeps_quiet_days_empty() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 7).unwrap();
        let counts: BTreeMap<NaiveDate, i64> = [(today, 4), (today - Duration::days(2), 1)]
            .into_iter()
            .collect();
        let bars = sparkline(&counts, today, 4);
        assert_eq!(bars.len(), 4);
        assert_eq!(bars[3].h, SPARK_HEIGHT);
        assert_eq!(bars[3].y, 0);
        assert_eq!(bars[1].h, SPARK_HEIGHT / 4);
        assert_eq!(bars[0].h, 0);
        assert_eq!(bars[2].h, 0);
        assert_eq!(bars[0].day, "2026-10-04");
        assert_eq!(bars[3].x, 3 * SPARK_STEP);
    }

    #[test]
    fn only_a_self_propagating_sample_makes_its_members_infected_hosts() {
        assert_eq!(member_role("sample", true), "infected host");
        assert_eq!(member_role("sample", false), "attacker");
        assert_eq!(member_role("command_sequence", true), "attacker");
    }

    #[test]
    fn the_confirmed_list_must_be_addresses_and_bounded() {
        assert_eq!(
            parse_confirmed("192.0.2.1, 2001:db8::1,").unwrap(),
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert_eq!(parse_confirmed("").unwrap(), Vec::<IpAddr>::new());
        assert!(parse_confirmed("192.0.2.1,'; DROP TABLE review_queue").is_none());
        let too_many: Vec<String> = (0..=MAX_APPROVE)
            .map(|i| format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256))
            .collect();
        assert!(parse_confirmed(&too_many.join(",")).is_none());
    }
}
