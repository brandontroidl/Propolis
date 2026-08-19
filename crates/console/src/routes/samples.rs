use std::path::PathBuf;

use axum::extract::{Path as AxumPath, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use minijinja::context;
use serde::Serialize;

use crate::AppState;
use crate::routes::context::base_context;
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/samples", get(samples_page))
        .route("/samples/download/{sha256}", get(download_sample))
}

#[derive(Debug, Serialize)]
struct SampleRow {
    sha256: String,
    sha256_short: String,
    size: String,
    sensor: String,
}

async fn samples_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;

    let mut samples = Vec::new();
    for (sensor, dir) in spool_dirs() {
        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                        samples.push(SampleRow {
                            sha256_short: name[..12].to_string(),
                            sha256: name,
                            size: format_bytes(meta.len()),
                            sensor: sensor.to_string(),
                        });
                    }
                }
            }
        }
    }

    samples.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    let total = samples.len();

    let tmpl = state.templates.get_template("samples.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "samples",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        samples,
        total,
    })?))
}

async fn download_sample(AxumPath(sha256): AxumPath<String>) -> Response {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid sha256").into_response();
    }

    for (_sensor, dir) in spool_dirs() {
        let path = dir.join(&sha256);
        if let Ok(bytes) = tokio::fs::read(&path).await {
            return (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{sha256}\""),
                    ),
                ],
                bytes,
            )
                .into_response();
        }
    }

    (axum::http::StatusCode::NOT_FOUND, "sample not found").into_response()
}

fn spool_dirs() -> Vec<(&'static str, PathBuf)> {
    vec![
        ("ssh", PathBuf::from("/var/spool/propolis/ssh")),
        ("adb", PathBuf::from("/var/spool/propolis/adb")),
        ("ftp", PathBuf::from("/var/spool/propolis/ftp")),
        ("catchall", PathBuf::from("/var/spool/propolis/catchall")),
    ]
}

fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}
