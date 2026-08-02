//! `GET /feed` - feed status (`internal/design/06-console-observability.md`, "Pages" > "Feed
//! status"). Session-gated: mounted under the `protected` group in `routes::mod`.
//!
//! Reads `manifest.json` from the configured feed output directory
//! (`AppState::feed_output_dir`, from `PROPOLIS_FEED_OUTPUT_DIR`). Absent config, a missing file,
//! or malformed JSON all render the same "No feed builds yet" state - never a hard error: a feed
//! build that has not run yet (or is not deployed on this host at all) is normal, expected state,
//! not a failure. `routes::metrics` reuses [`read_manifest`] for `propolis_feed_entries`.
//!
//! [`Manifest`] mirrors the JSON SHAPE `feed::publisher::Manifest` writes
//! (`crates/feed/src/publisher.rs`), deliberately as its own Deserialize-only type rather than a
//! dependency on the `feed` crate: `console` and `feed` are independently deployed services
//! (`deploy/console.service`, `deploy/feed.service`) that communicate only through this on-disk
//! file, so the file's JSON shape is the contract between them, not a shared Rust struct - and
//! `feed::publisher::Manifest` is crate-private there too (no consumer needed it publicly before
//! this).

use std::path::Path;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Extension, Router};
use minijinja::context;
use serde::Deserialize;

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new().route("/feed", get(feed_page))
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
) -> Result<Html<String>, AppError> {
    let manifest = state.feed_output_dir.as_deref().and_then(read_manifest);
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
    } = base_context(&state.db, state.startup_time, state.version).await;

    let tmpl = state.templates.get_template("feed.html")?;
    let html = match manifest {
        Some(m) => tmpl.render(context! {
            csrf_token,
            active_nav => "feed",
            pending_count,
            uptime,
            version,
            has_build => true,
            build_time => m.build_time,
            aggressive_count => m.tiers.aggressive.count,
            aggressive_valid_until => m.tiers.aggressive.valid_until,
            standard_count => m.tiers.standard.count,
            standard_valid_until => m.tiers.standard.valid_until,
        })?,
        None => tmpl.render(context! {
            csrf_token,
            active_nav => "feed",
            pending_count,
            uptime,
            version,
            has_build => false,
        })?,
    };
    Ok(Html(html))
}
