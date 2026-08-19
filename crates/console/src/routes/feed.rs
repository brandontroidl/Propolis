//! `GET /feed` - feed status (`internal/design/06-console-observability.md`, "Pages" > "Feed
//! status"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Reads `manifest.json` from the configured feed output directory
//! (`AppState::feed_output_dir`, from `PROPOLIS_FEED_OUTPUT_DIR`). A missing file or malformed
//! JSON both collapse to `None` via [`read_manifest`] - never a hard error: a feed build that has
//! not run yet is normal, expected state, not a failure. The empty state's copy then distinguishes
//! *why* there is no build, via `feed_disabled` (`true` when `feed_output_dir` itself is `None`,
//! i.e. this node has no feed builder configured at all): "feed builder is disabled on this node"
//! vs. "feed enabled - awaiting first build" for a configured directory with no manifest yet.
//! `routes::metrics` reuses [`read_manifest`] for `propolis_feed_entries`.
//!
//! [`Manifest`] mirrors the JSON SHAPE `feed::publisher::Manifest` writes
//! (`crates/feed/src/publisher.rs`), deliberately as its own Deserialize-only type rather than a
//! dependency on the `feed` crate: `console` and `feed` are independently deployed services
//! (`deploy/console.service`, `deploy/feed.service`) that communicate only through this on-disk
//! file, so the file's JSON shape is the contract between them, not a shared Rust struct - and
//! `feed::publisher::Manifest` is crate-private there too (no consumer needed it publicly before
//! this).
//!
//! Entries tab (console-forensics task 8): `?tab=entries` lists the IPs actually recommended for
//! the blocklist, grouped by tier - a live query over `review_queue`/`ip_score`, not a parse of
//! the published feed files themselves (those are plain-text/CSV/JSON export formats, not a
//! convenient read-back source, and the DB is the current live truth the next build will publish
//! from). This can drift slightly from the last published `manifest.json` snapshot (a decision
//! made after the last build, or score decay since) - an accepted, momentary skew, the same kind
//! `routes::queue`'s live-decayed re-read already accepts for the review queue itself.
//!
//! Download endpoint (console-forensics task 8): `GET /feed/download/{tier}/{format}` streams one
//! of the four export files `feed::publisher::write_tier` writes per tier
//! (`{tier}.{txt,json,csv,cidr}`) straight off disk. `tier` and `format` are both matched against
//! a fixed allow-list before ever touching the filesystem - never interpolated into the path
//! unchecked - so this cannot become a traversal primitive over an operator-editable URL segment.
//! 404 (not the generic `AppError` 503) on every "nothing to serve" case alike: feed disabled,
//! unknown tier/format, or the build simply hasn't produced that file yet - all normal, expected
//! states rather than a database/template failure, mirroring `routes::detail`'s own direct-404
//! treatment of "no such IP" rather than routing through `AppError`.

use std::path::Path;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use core_scoring::FeedTier;
use minijinja::context;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;
use crate::routes::format::format_timestamp;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/feed", get(feed_page))
        .route("/feed/download/{tier}/{format}", get(download_feed))
}

/// Tab accepted via `?tab=` - `Status` (the original manifest summary, unchanged default) or
/// `Entries` (this task's live IP listing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Tab {
    #[default]
    Status,
    Entries,
}

impl Tab {
    fn as_str(self) -> &'static str {
        match self {
            Tab::Status => "status",
            Tab::Entries => "entries",
        }
    }
}

#[derive(Debug, Deserialize)]
struct FeedQuery {
    #[serde(default)]
    tab: Tab,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) build_time: String,
    pub(crate) tiers: ManifestTiers,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ManifestTiers {
    pub(crate) aggressive: TierManifest,
    pub(crate) standard: TierManifest,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TierManifest {
    pub(crate) count: usize,
    pub(crate) valid_until: String,
}

/// Reads and parses `manifest.json` from `dir`. `None` covers every "not available" case alike -
/// a missing file, a read error, or malformed JSON - matching the brief's "if configured and
/// exists" and the design's "If manifest missing: 'No feed builds yet'."
pub(crate) fn read_manifest(dir: &Path) -> Option<Manifest> {
    let bytes = std::fs::read(dir.join("manifest.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn feed_page(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Query(query): Query<FeedQuery>,
) -> Result<Html<String>, AppError> {
    let manifest = state.feed_output_dir.as_deref().and_then(read_manifest);
    let feed_disabled = state.feed_output_dir.is_none();
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
    } = base_context(&state.db, state.startup_time, state.version).await;

    // Only the entries tab needs the join - the status tab's context below is unchanged from
    // before this task, so there is no reason to pay for the query on every `/feed` hit.
    let (aggressive_entries, standard_entries) = match query.tab {
        Tab::Entries => fetch_feed_entries(&state.db).await?,
        Tab::Status => (Vec::new(), Vec::new()),
    };
    let tab = query.tab.as_str();

    let tmpl = state.templates.get_template("feed.html")?;
    let html = match manifest {
        Some(m) => tmpl.render(context! {
            csrf_token,
            active_nav => "feed",
            pending_count,
            uptime,
            version,
            feed_disabled,
            has_build => true,
            build_time => m.build_time,
            aggressive_count => m.tiers.aggressive.count,
            aggressive_valid_until => m.tiers.aggressive.valid_until,
            standard_count => m.tiers.standard.count,
            standard_valid_until => m.tiers.standard.valid_until,
            tab,
            aggressive_entries,
            standard_entries,
        })?,
        None => tmpl.render(context! {
            csrf_token,
            active_nav => "feed",
            pending_count,
            uptime,
            version,
            feed_disabled,
            has_build => false,
            tab,
            aggressive_entries,
            standard_entries,
        })?,
    };
    Ok(Html(html))
}

/// One IP recommended for the blocklist, as rendered in the entries tab's per-tier table. Every
/// numeric/timestamp field is pre-formatted in Rust, matching `routes::detail`/`routes::queue`'s
/// own convention of keeping the template free of `Decimal`/`DateTime` formatting logic.
#[derive(Debug, Serialize)]
struct FeedEntryRow {
    ip: String,
    score: String,
    score_pct: u32,
    event_count: i32,
    first_seen: String,
    last_seen: String,
}

/// The entries tab's query (module doc comment): every IP with an *approved* `review_queue`
/// decision whose live `ip_score` still recommends it for the blocklist, split into the
/// aggressive/standard buckets the template renders as two panels.
///
/// A row whose `tier` is `NULL` is dropped with a warning rather than guessed into a bucket: per
/// `core-scoring`'s own schema, `tier` is only ever set alongside `recommended_for_blocklist`, so
/// this should not occur in practice (the same "should not happen but fail closed, not panic"
/// posture `routes::error::AppError::missing_projection` documents for the analogous case on the
/// detail page).
async fn fetch_feed_entries(
    db: &PgPool,
) -> Result<(Vec<FeedEntryRow>, Vec<FeedEntryRow>), AppError> {
    let rows = sqlx::query(
        "SELECT host(rq.source_ip) AS ip, isc.raw_score, isc.event_count, \
                isc.first_seen, isc.last_seen, isc.tier \
         FROM review_queue rq \
         JOIN ip_score isc ON rq.source_ip = isc.source_ip \
         WHERE rq.state = 'approved' AND isc.recommended_for_blocklist = TRUE \
         ORDER BY isc.tier, isc.raw_score DESC",
    )
    .fetch_all(db)
    .await?;

    let mut aggressive = Vec::new();
    let mut standard = Vec::new();
    for row in rows {
        let ip: String = row.try_get("ip")?;
        let tier: Option<FeedTier> = row.try_get("tier")?;
        let Some(tier) = tier else {
            tracing::warn!(
                %ip,
                "feed entries: approved + recommended_for_blocklist row has no tier; omitting"
            );
            continue;
        };
        let raw_score: Decimal = row.try_get("raw_score")?;
        let score_f64 = raw_score.to_f64().unwrap_or(0.0);
        let entry = FeedEntryRow {
            ip,
            score: format!("{raw_score:.1}"),
            score_pct: score_f64.clamp(0.0, 100.0).round() as u32,
            event_count: row.try_get("event_count")?,
            first_seen: format_timestamp(row.try_get("first_seen")?),
            last_seen: format_timestamp(row.try_get("last_seen")?),
        };
        match tier {
            FeedTier::Aggressive => aggressive.push(entry),
            FeedTier::Standard => standard.push(entry),
        }
    }
    Ok((aggressive, standard))
}

/// `GET /feed/download/{tier}/{format}` - streams one export file straight off disk (module doc
/// comment). Both path segments are matched against a fixed allow-list before being used to build
/// the filesystem path, never interpolated unchecked, so an operator-editable URL segment cannot
/// escape `feed_output_dir`.
async fn download_feed(
    State(state): State<AppState>,
    AxumPath((tier, format)): AxumPath<(String, String)>,
) -> Response {
    let Some(dir) = state.feed_output_dir.as_deref() else {
        return download_not_found();
    };
    if !matches!(tier.as_str(), "aggressive" | "standard") {
        return download_not_found();
    }
    let (extension, content_type) = match format.as_str() {
        "json" => ("json", "application/json"),
        "csv" => ("csv", "text/csv"),
        "txt" => ("txt", "text/plain"),
        "cidr" => ("cidr", "text/plain"),
        _ => return download_not_found(),
    };

    let path = dir.join(format!("{tier}.{extension}"));
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, content_type.to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{tier}.{extension}\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, %tier, %format, "feed download: file not found or unreadable");
            download_not_found()
        }
    }
}

fn download_not_found() -> Response {
    const BODY: &str = "<!doctype html><meta charset=\"utf-8\"><title>Not found</title>\
        <p style=\"font-family:sans-serif;padding:2rem\">No feed file available for that tier/format.</p>";
    (StatusCode::NOT_FOUND, Html(BODY)).into_response()
}
