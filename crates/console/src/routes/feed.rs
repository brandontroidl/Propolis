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
//! Entries tab: `?tab=entries` lists the addresses actually IN the published feed, read back from
//! the `{feed}.json` export files rather than re-queried from the database.
//!
//! It used to be a live query that re-derived each address's score decayed to the moment of the
//! request, and decided tier and membership from that. Since the builder decided the same things
//! from its own re-derivation at a different moment, the two disagreed constantly and visibly: the
//! Status tab reported 8 entries in a tier while Entries listed 7, and both were "correct" for the
//! instant they ran. Reading the published files removes the disagreement by construction - there
//! is no second derivation left to drift. The page now describes the feed as published, which is
//! what an operator is actually asking when they open it, and it agrees with `manifest.json`
//! because both come from the same build.
//!
//! Download endpoint: `GET /feed/download/{feed}/{format}` streams one export file straight off
//! disk. `feed` and `format` are both matched against a fixed pattern before ever touching the
//! filesystem - never interpolated into the path unchecked - so this cannot become a traversal
//! primitive over an operator-editable URL segment. 404 (not the generic `AppError` 503) on every
//! "nothing to serve" case alike: feed disabled, unknown feed/format, or the build simply hasn't
//! produced that file yet - all normal, expected states rather than a database/template failure,
//! mirroring `routes::detail`'s own direct-404 treatment of "no such IP".

use std::path::Path;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use minijinja::context;
use serde::{Deserialize, Serialize};

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
    /// Retention feeds. `default` rather than required so a `manifest.json` written by a build
    /// from before retention feeds existed still parses instead of collapsing the whole page to
    /// the "no builds yet" empty state.
    #[serde(default)]
    pub(crate) windows: Vec<WindowManifest>,
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

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WindowManifest {
    pub(crate) label: String,
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

    // Only the entries tab reads the export files back; the status tab needs only the manifest.
    let dir = state.feed_output_dir.as_deref();
    let (aggressive_entries, standard_entries, window_entries) = match query.tab {
        Tab::Entries => {
            let windows: Vec<(String, Vec<FeedEntryRow>)> = manifest
                .as_ref()
                .map(|m| m.windows.as_slice())
                .unwrap_or_default()
                .iter()
                .filter_map(|w| {
                    read_published_feed(dir, &format!("all-{}", w.label))
                        .map(|rows| (w.label.clone(), rows))
                })
                .collect();
            (
                read_published_feed(dir, "aggressive").unwrap_or_default(),
                read_published_feed(dir, "standard").unwrap_or_default(),
                windows,
            )
        }
        Tab::Status => (Vec::new(), Vec::new(), Vec::new()),
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
            windows => m.windows,
            tab,
            aggressive_entries,
            standard_entries,
            window_entries,
        })?,
        None => tmpl.render(context! {
            csrf_token,
            active_nav => "feed",
            pending_count,
            uptime,
            version,
            feed_disabled,
            has_build => false,
            windows => Vec::<WindowManifest>::new(),
            tab,
            aggressive_entries,
            standard_entries,
            window_entries,
        })?,
    };
    Ok(Html(html))
}

/// One address as it appears in a published feed file, ready to render.
///
/// There is deliberately no score column. The score is what the page used to lead with, and it was
/// actively misleading: it is a live-decaying value, while feed membership is now fixed at
/// observation time, so an operator watching a score tick down below a tier threshold reasonably
/// expected the entry to move and it did not. The per-address score still lives on the detail page,
/// one click away, where it is not standing next to a membership claim it does not govern.
#[derive(Debug, Serialize)]
struct FeedEntryRow {
    ip: String,
    event_count: i32,
    first_seen: String,
    last_seen: String,
    /// The activity labels this address triggered, joined for display.
    signals: String,
}

/// One published feed file's parsed contents.
#[derive(Debug, Deserialize)]
struct PublishedFeed {
    entries: Vec<PublishedEntry>,
}

#[derive(Debug, Deserialize)]
struct PublishedEntry {
    ip: String,
    first_seen: String,
    last_seen: String,
    events: i32,
    /// Absent in files written before activity labels existed, so defaulted rather than required:
    /// an older file must still render, not blank the tab.
    #[serde(default)]
    signals: Vec<String>,
}

/// Reads `{name}.json` from the feed output directory and renders its entries.
///
/// `None` for every "not available" case alike - no feed directory configured, the file absent
/// because the build has not produced it, or unparseable - matching [`read_manifest`]'s posture.
/// A feed that exists but is empty returns `Some(vec![])`, which the template distinguishes from
/// `None`: "nothing in this feed" is a different statement from "no build yet".
fn read_published_feed(dir: Option<&Path>, name: &str) -> Option<Vec<FeedEntryRow>> {
    let bytes = std::fs::read(dir?.join(format!("{name}.json"))).ok()?;
    let parsed: PublishedFeed = serde_json::from_slice(&bytes).ok()?;
    Some(
        parsed
            .entries
            .into_iter()
            .map(|e| FeedEntryRow {
                ip: e.ip,
                event_count: e.events,
                first_seen: display_timestamp(&e.first_seen),
                last_seen: display_timestamp(&e.last_seen),
                signals: e.signals.join(", "),
            })
            .collect(),
    )
}

/// Re-formats an exported RFC 3339 timestamp into the console's own display format, so these rows
/// read the same as every other timestamp in the UI. Falls back to the raw string rather than
/// blanking the cell if it does not parse - a display concern is never worth losing the row over.
fn display_timestamp(raw: &str) -> String {
    raw.parse::<chrono::DateTime<chrono::Utc>>()
        .map(format_timestamp)
        .unwrap_or_else(|_| raw.to_string())
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
    if !is_known_feed_name(&tier) {
        return download_not_found();
    }
    let (extension, content_type) = match format.as_str() {
        "json" => ("json", "application/json"),
        "csv" => ("csv", "text/csv"),
        "txt" => ("txt", "text/plain"),
        "cidr" => ("cidr", "text/plain"),
        "ipset" => ("ipset", "text/plain"),
        "nft" => ("nft", "text/plain"),
        "pf" => ("pf", "text/plain"),
        "alias" => ("alias", "text/plain"),
        "hosts" => ("hosts", "text/plain"),
        "rpz" => ("rpz", "text/plain"),
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

/// The set of feed names this endpoint will build a path from: the two fixed tiers, plus
/// `all-{count}{h|d}` for the operator-configured retention feeds.
///
/// The retention set is configurable, so it cannot be a literal list here - but it is still an
/// exact pattern, not a sanitisation pass. Every accepted name is `[a-z]+` or `all-` followed by
/// digits and a single unit character, which admits no `.`, `/`, or `\`, so no accepted value can
/// traverse out of the feed directory. Validating the shape rather than stripping bad characters
/// is what keeps that true: a stripper has to anticipate every encoding, a shape check does not.
fn is_known_feed_name(name: &str) -> bool {
    if matches!(name, "aggressive" | "standard") {
        return true;
    }
    let Some(window) = name.strip_prefix("all-") else {
        return false;
    };
    let Some((count, unit)) = window.split_at_checked(window.len().saturating_sub(1)) else {
        return false;
    };
    matches!(unit, "h" | "d") && !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit())
}

fn download_not_found() -> Response {
    const BODY: &str = "<!doctype html><meta charset=\"utf-8\"><title>Not found</title>\
        <p style=\"font-family:sans-serif;padding:2rem\">No feed file available for that tier/format.</p>";
    (StatusCode::NOT_FOUND, Html(BODY)).into_response()
}
