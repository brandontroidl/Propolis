use std::path::PathBuf;

use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
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
    vt_detected: Option<i32>,
    vt_total: Option<i32>,
    vt_link: String,
    /// Source IPs this sample is attributable to, newest first, and whether more exist than are
    /// shown. Empty for a sample nothing links to yet - see `sample_source_ips`.
    source_ips: Vec<String>,
    more_source_ips: usize,
}

#[derive(Debug, Serialize)]
struct FetchStatusCount {
    label: &'static str,
    count: i64,
    /// Appended as `stat-card--{variant}` (see `base_head.html`'s `.stat-card--*` rules); empty
    /// means the plain, uncolored `.stat-card`.
    variant: &'static str,
}

/// Display order + labels + color variant for each `fetch_attempt.status` value
/// (`review::fetcher::FetchStatus::as_str()` - pending/success/dead/rejected/too_big/timeout/
/// empty). Success first (the outcome an operator scans for), then the retryable failure classes,
/// then the two terminal/in-progress states. Only `dead` (permanently failed after the retry cap)
/// gets the alert color; `timeout`/`too_big` are still-retrying failures (attention); `rejected`/
/// `empty` are expected, benign outcomes (the SSRF guard and empty-body responses are routine, not
/// alarming) so they stay uncolored; `pending` is neutral in-progress work (info).
const FETCH_STATUS_DISPLAY: [(&str, &str, &str); 7] = [
    ("success", "Success", "good"),
    ("rejected", "Rejected", ""),
    ("timeout", "Timeout", "attention"),
    ("too_big", "Too big", "attention"),
    ("empty", "Empty", ""),
    ("dead", "Dead", "alert"),
    ("pending", "Pending", "info"),
];

/// `GROUP BY status` on `fetch_attempt` - parameterless, so there is no injection surface. Missing
/// statuses (no attempts recorded yet, or none of that particular outcome) default to a count of
/// 0 rather than being absent from the strip, so the operator always sees the full status set.
async fn fetch_status_counts(pool: &sqlx::PgPool) -> Vec<FetchStatusCount> {
    let counts: std::collections::HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, count(*) FROM fetch_attempt GROUP BY status",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    FETCH_STATUS_DISPLAY
        .iter()
        .map(|(key, label, variant)| FetchStatusCount {
            label,
            count: *counts.get(*key).unwrap_or(&0),
            variant,
        })
        .collect()
}

/// How many source IPs to show inline per sample before collapsing to a "+N more" count.
/// Overridable with `PROPOLIS_CONSOLE_MAX_SOURCE_IPS` for an operator whose feed has many
/// attackers per sample; a blank, zero, or unparseable value falls back to the default rather than
/// rendering an empty column (zero never means unlimited).
const DEFAULT_MAX_SOURCE_IPS_SHOWN: usize = 3;
const ENV_MAX_SOURCE_IPS: &str = "PROPOLIS_CONSOLE_MAX_SOURCE_IPS";

fn max_source_ips_shown() -> usize {
    std::env::var(ENV_MAX_SOURCE_IPS)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_SOURCE_IPS_SHOWN)
}

/// sha256 (lowercase hex) -> the source IPs that sample is attributable to, newest attempt first.
///
/// The link is `fetch_attempt`: the fetcher records the attacker IP whose event reported the URL it
/// retrieved, alongside the sha256 of what came back. `fetch_attempt.sha256` is BYTEA while the
/// spool filenames (and `sample_analysis.sha256`) are lowercase hex, hence `encode(...)`.
///
/// Two honest limits, both surfaced in the UI rather than papered over:
/// - `fetch_attempt` is keyed by `url_hash` and inserted `ON CONFLICT DO NOTHING`, so `source_ip`
///   is the FIRST attacker that reported each URL, not every one that referenced it.
/// - It covers FETCHED samples only. A body uploaded directly to a sensor has no `fetch_attempt`
///   row, so it shows no source here until the capture/observation link lands.
///   Rows whose `source_ip` was never recorded (NULL) are simply absent.
async fn sample_source_ips(pool: &sqlx::PgPool) -> std::collections::HashMap<String, Vec<String>> {
    // Unions the two ways a sample is attributable: an address that UPLOADED it to a sensor (the
    // event carries the sha - a first-party observation, and the only link an FTP/SCP upload has,
    // since it never goes through the fetcher), and an address whose reported url the fetcher
    // retrieved. Uploads sort first so the stronger attribution is what gets shown when the
    // per-sample display cap truncates.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT sha, ip FROM ( \
           SELECT e.metadata->>'sample_sha256' AS sha, host(e.source_ip) AS ip, \
                  0 AS rank, max(e.observed_at) AS at \
           FROM event e \
           WHERE e.metadata->>'sample_sha256' IS NOT NULL \
           GROUP BY 1, 2 \
           UNION ALL \
           SELECT encode(fa.sha256, 'hex') AS sha, host(fa.source_ip) AS ip, \
                  1 AS rank, max(fa.last_attempt) AS at \
           FROM fetch_attempt fa \
           WHERE fa.sha256 IS NOT NULL AND fa.source_ip IS NOT NULL \
           GROUP BY 1, 2 \
         ) linked \
         ORDER BY rank, at DESC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    group_source_ips(rows)
}

/// Groups `(sha, ip)` pairs by sha, preserving input order (the query's newest-attempt-first) and
/// dropping repeats: one attacker can appear on several URLs that resolved to the same body, and it
/// should be listed once. Split from the query so the grouping is testable without a database.
fn group_source_ips(rows: Vec<(String, String)>) -> std::collections::HashMap<String, Vec<String>> {
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (sha, ip) in rows {
        let ips = map.entry(sha).or_default();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    map
}

async fn samples_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let source_ips_by_sha = sample_source_ips(&state.db).await;

    let vt_results: std::collections::HashMap<String, (i32, i32, String)> =
        sqlx::query_as::<_, (String, i32, i32, String)>(
            "SELECT sha256, detected, total, vt_link FROM sample_analysis",
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(sha, d, t, l)| (sha, (d, t, l)))
        .collect();

    let max_source_ips = max_source_ips_shown();
    let mut samples = Vec::new();
    for (sensor, dir) in spool_dirs() {
        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                        let vt = vt_results.get(&name);
                        let all_ips = source_ips_by_sha.get(&name);
                        let source_ips: Vec<String> = all_ips
                            .map(|v| v.iter().take(max_source_ips).cloned().collect())
                            .unwrap_or_default();
                        let more_source_ips =
                            all_ips.map_or(0, |v| v.len().saturating_sub(max_source_ips));
                        samples.push(SampleRow {
                            sha256_short: name[..12].to_string(),
                            sha256: name,
                            size: format_bytes(meta.len()),
                            sensor: sensor.to_string(),
                            vt_detected: vt.map(|(d, _, _)| *d),
                            vt_total: vt.map(|(_, t, _)| *t),
                            vt_link: vt.map(|(_, _, l)| l.clone()).unwrap_or_default(),
                            source_ips,
                            more_source_ips,
                        });
                    }
                }
            }
        }
    }

    samples.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    let total = samples.len();

    let status_counts = fetch_status_counts(&state.db).await;
    let fetch_attempts_total: i64 = status_counts.iter().map(|c| c.count).sum();

    let tmpl = state.templates.get_template("samples.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "samples",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        samples,
        total,
        status_counts,
        fetch_attempts_total,
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
                    (
                        header::HeaderName::from_static("x-content-type-options"),
                        "nosniff".to_string(),
                    ),
                    (
                        header::HeaderName::from_static("content-security-policy"),
                        "default-src 'none'".to_string(),
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
    // The one canonical list (sensor spools + the fetcher's bucket), shared with the VT scan and
    // sample retention so this view never walks a different set than they do.
    review::spool::all_body_dirs()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ips_group_by_sha_dedup_and_keep_query_order() {
        let map = group_source_ips(vec![
            ("aa".to_string(), "203.0.113.1".to_string()),
            ("aa".to_string(), "203.0.113.2".to_string()),
            // Same attacker on a second URL that resolved to the same body: listed once.
            ("aa".to_string(), "203.0.113.1".to_string()),
            ("bb".to_string(), "203.0.113.9".to_string()),
        ]);

        assert_eq!(
            map.get("aa").unwrap(),
            &vec!["203.0.113.1".to_string(), "203.0.113.2".to_string()],
            "dedup must keep the first occurrence and the query's newest-first order"
        );
        assert_eq!(map.get("bb").unwrap(), &vec!["203.0.113.9".to_string()]);
        assert!(
            !map.contains_key("cc"),
            "a sample nothing links to must have no entry, so the row renders 'not linked'"
        );
    }
}
