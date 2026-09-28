//! Public static assets, embedded into the binary via `include_bytes!` so there is no runtime asset
//! directory to ship: the self-hosted web fonts, and every stylesheet and script the pages load
//! (`src/assets/`). Mounted OUTSIDE the session gate - like `/login` - so the unauthenticated login
//! page can load them; the files contain no secrets.
//!
//! Self-hosting is a hard deployment requirement: the console must make NO third-party request
//! (no Google Fonts / CDN egress from the honeypot box), and the Content-Security-Policy
//! (`routes::mod`) permits scripts, styles and fonts from this origin only. Fonts are Hanken
//! Grotesk (variable weight axis, SIL OFL) and IBM Plex Mono 400/500/600 (SIL OFL), Latin-subset
//! woff2. The OFL license texts live beside the woff2 files in `src/fonts/`.
//!
//! Every filename is matched against a fixed allowlist (never used to build a filesystem path), so
//! it is not a path-traversal vector; an unknown name is a plain 404.

use std::sync::LazyLock;

use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest, Sha256};

use crate::AppState;

const HANKEN_VAR: &[u8] = include_bytes!("../fonts/hanken-grotesk-var.woff2");
const PLEX_400: &[u8] = include_bytes!("../fonts/ibm-plex-mono-400.woff2");
const PLEX_500: &[u8] = include_bytes!("../fonts/ibm-plex-mono-500.woff2");
const PLEX_600: &[u8] = include_bytes!("../fonts/ibm-plex-mono-600.woff2");

const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";

/// Every stylesheet and script a page may reference, by the name it is served under.
const STATIC_ASSETS: [(&str, &str, &[u8]); 10] = [
    ("console.css", CSS, include_bytes!("../assets/console.css")),
    (
        "theme-init.js",
        JS,
        include_bytes!("../assets/theme-init.js"),
    ),
    ("chart.min.js", JS, include_bytes!("../assets/chart.min.js")),
    ("charts.js", JS, include_bytes!("../assets/charts.js")),
    ("htmx.min.js", JS, include_bytes!("../assets/htmx.min.js")),
    ("console.js", JS, include_bytes!("../assets/console.js")),
    (
        "live-panels.js",
        JS,
        include_bytes!("../assets/live-panels.js"),
    ),
    ("dashboard.js", JS, include_bytes!("../assets/dashboard.js")),
    ("feed.js", JS, include_bytes!("../assets/feed.js")),
    ("logs.js", JS, include_bytes!("../assets/logs.js")),
];

/// One strong validator per entry of [`STATIC_ASSETS`], from its content. These files change with
/// the binary, not per request, so a browser revalidates each load (`no-cache`) and gets a 304 until
/// an upgrade actually changes the file - a page can never run a stale script against new markup.
static ETAGS: LazyLock<Vec<String>> = LazyLock::new(|| {
    STATIC_ASSETS
        .iter()
        .map(|(_, _, bytes)| format!("\"{}\"", &hex::encode(Sha256::digest(bytes))[..32]))
        .collect()
});

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/assets/fonts/{file}", get(font))
        .route("/assets/{file}", get(static_asset))
}

/// Whether `/assets/{name}` is served. The template tests check every reference against this, so
/// a page cannot link a stylesheet or script that would 404.
#[cfg(test)]
pub(crate) fn is_static_asset(name: &str) -> bool {
    STATIC_ASSETS.iter().any(|(served, _, _)| *served == name)
}

async fn static_asset(Path(file): Path<String>, headers: HeaderMap) -> Response {
    let Some(index) = STATIC_ASSETS.iter().position(|(name, _, _)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (_, content_type, bytes) = STATIC_ASSETS[index];
    let etag = ETAGS[index].as_str();
    let cached = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|tag| tag.trim() == etag));
    let validators = [(header::ETAG, etag), (header::CACHE_CONTROL, "no-cache")];
    if cached {
        return (StatusCode::NOT_MODIFIED, validators).into_response();
    }
    (validators, [(header::CONTENT_TYPE, content_type)], bytes).into_response()
}

/// Serves one embedded woff2 by its exact name. Content is immutable (the bytes are baked into the
/// binary), so a one-year immutable cache is safe and keeps the fonts off every subsequent page
/// load.
async fn font(Path(file): Path<String>) -> Response {
    let bytes: &'static [u8] = match file.as_str() {
        "hanken-grotesk-var.woff2" => HANKEN_VAR,
        "ibm-plex-mono-400.woff2" => PLEX_400,
        "ibm-plex-mono-500.woff2" => PLEX_500,
        "ibm-plex-mono-600.woff2" => PLEX_600,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
        .into_response()
}
