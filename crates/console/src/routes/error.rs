//! Shared error -> HTTP response mapping for the operator-facing pages (dashboard, queue):
//! `internal/design/06-console-observability.md`'s "Error handling" requires that a database (or
//! template) failure never reaches the browser as a raw framework 500 or with internal detail -
//! only a generic "Service unavailable" message, with the real cause logged server-side. Every
//! variant here maps to that same response; the variants exist only so the server-side log line
//! (via each `From` impl) says which layer actually failed, not to expose that distinction to the
//! client.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

const GENERIC_BODY: &str = "<!doctype html><meta charset=\"utf-8\"><title>Service unavailable</title>\
<p style=\"font-family:sans-serif;padding:2rem\">Service unavailable. Please try again shortly.</p>";

/// A page-load failure, always rendered as a generic 503 - see the module doc comment.
#[derive(Debug)]
pub enum AppError {
    Database,
    ReviewQueue,
    Template,
    /// A review decision (approve/reject/snooze) committed successfully, but the IP's `ip_score`
    /// projection was gone by the time the handler tried to re-read it for the response partial.
    /// Should not occur in practice (nothing deletes `ip_score` rows; see `review::queue`'s doc
    /// comment), but the read path fails closed rather than panicking if it ever does.
    MissingProjection,
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error serving a console page");
        AppError::Database
    }
}

impl From<core_scoring::RepoError> for AppError {
    fn from(e: core_scoring::RepoError) -> Self {
        tracing::error!(error = %e, "core-scoring read failed serving a console page");
        AppError::Database
    }
}

impl From<review::ReviewError> for AppError {
    fn from(e: review::ReviewError) -> Self {
        tracing::error!(error = %e, "review queue operation failed serving a console page");
        AppError::ReviewQueue
    }
}

impl From<minijinja::Error> for AppError {
    fn from(e: minijinja::Error) -> Self {
        tracing::error!(error = %e, "template render failed");
        AppError::Template
    }
}

impl AppError {
    pub fn missing_projection(ip: std::net::IpAddr) -> Self {
        tracing::error!(%ip, "ip_score projection missing immediately after a review decision");
        AppError::MissingProjection
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::SERVICE_UNAVAILABLE, Html(GENERIC_BODY)).into_response()
    }
}
