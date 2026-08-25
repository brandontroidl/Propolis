//! Public, cacheable static assets: the self-hosted web fonts, embedded into the binary via
//! `include_bytes!` (same "no runtime asset directory to ship" model as the vendored `chart.min.js`
//! and `htmx.min.js`). Mounted OUTSIDE the session gate - like `/login` - so the unauthenticated
//! login page can load them; the files contain no secrets.
//!
//! Self-hosting is a hard deployment requirement: the console must make NO third-party font request
//! (no Google Fonts / CDN egress from the honeypot box). Fonts are Hanken Grotesk (variable weight
//! axis, SIL OFL) and IBM Plex Mono 400/500/600 (SIL OFL), Latin-subset woff2. The OFL license texts
//! live beside the woff2 files in `src/fonts/`.
//!
//! The filename is matched against a fixed allowlist (never used to build a filesystem path), so it
//! is not a path-traversal vector; an unknown name is a plain 404.

use axum::Router;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::AppState;

const HANKEN_VAR: &[u8] = include_bytes!("../fonts/hanken-grotesk-var.woff2");
const PLEX_400: &[u8] = include_bytes!("../fonts/ibm-plex-mono-400.woff2");
const PLEX_500: &[u8] = include_bytes!("../fonts/ibm-plex-mono-500.woff2");
const PLEX_600: &[u8] = include_bytes!("../fonts/ibm-plex-mono-600.woff2");

pub fn router() -> Router<AppState> {
    Router::new().route("/assets/fonts/{file}", get(font))
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
