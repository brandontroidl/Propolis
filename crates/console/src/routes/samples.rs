use std::path::PathBuf;

use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use minijinja::context;
use serde::Serialize;

use crate::AppState;
use chrono::{Duration, Utc};

use crate::routes::campaigns::{
    Bar, CampaignRef, LIST_SPARK_DAYS, SPARK_HEIGHT, SPARK_STEP, artifact_iocs,
    campaigns_by_sample, campaigns_linking_sample, day_counts, delivering_campaigns,
    sample_activity, sparkline,
};
use crate::routes::context::base_context;
use crate::routes::error::AppError;
use crate::routes::format::format_active;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/samples", get(samples_page))
        .route("/samples/{sha256}", get(sample_page))
        .route("/samples/download/{sha256}", get(download_sample))
}

/// The fetcher's bucket among `review::spool::all_body_dirs`; every other entry is a sensor's spool.
const FETCHED_BUCKET: &str = "fetched";

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
    /// How the fetcher's transport was authenticated for each URL that returned this body; empty
    /// for a body no fetch produced (a sensor upload). See `sample_transport`.
    transport: Vec<TransportTag>,
    /// The body sits in a sensor's spool rather than the fetcher's bucket, so a sensor took it from
    /// the address that sent it and the Transport column has nothing to say about it.
    uploaded: bool,
    /// The sample's own campaign: every address that uploaded it or reported a URL serving it.
    campaign: Option<CampaignRef>,
    /// When the sample's hosts were active, from the same campaign; empty when no address is
    /// linked to the sample.
    active: String,
    active_title: String,
    spark: Vec<Bar>,
    /// The behaviour (command-sequence campaign) whose sessions uploaded it, as `(id, hosts)`.
    delivered_by: Option<DeliveredBy>,
}

#[derive(Debug, Serialize)]
struct DeliveredBy {
    id: i64,
    members: i32,
}

/// One distinct transport-authentication state among the fetches that returned a sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct TransportTag {
    label: &'static str,
    /// Appended as `sev--{sev}`; empty renders as plain dim text.
    sev: &'static str,
    /// The certificate-validation error for an unverified fetch, shown on hover. It can carry
    /// names from the attacker's certificate, so it is length-capped here and auto-escaped by the
    /// template like every other value.
    detail: Option<String>,
}

/// The longest certificate error shown on hover; the full text stays in `fetch_attempt`.
const TRANSPORT_DETAIL_MAX_CHARS: usize = 160;

fn transport_tag(state: &str, error: Option<String>) -> TransportTag {
    let detail = error.map(|e| e.chars().take(TRANSPORT_DETAIL_MAX_CHARS).collect());
    match state {
        "verified" => TransportTag {
            label: "TLS verified",
            sev: "low",
            detail: None,
        },
        "unverified" => TransportTag {
            label: "TLS unverified",
            sev: "watch",
            detail,
        },
        "plaintext" => TransportTag {
            label: "plaintext",
            sev: "low",
            detail: None,
        },
        // 'unknown': fetched before transport authentication was recorded. Never shown as verified.
        _ => TransportTag {
            label: "not recorded",
            sev: "",
            detail: None,
        },
    }
}

/// sha256 (lowercase hex) -> each distinct transport state among the successful fetches that
/// returned that body. Several URLs can serve the same bytes over different transports, so the
/// states are listed side by side rather than collapsed to the best one: a verified copy does not
/// make an unverified one authenticated.
async fn sample_transport(
    pool: &sqlx::PgPool,
) -> Result<std::collections::HashMap<String, Vec<TransportTag>>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT DISTINCT ON (encode(sha256, 'hex'), transport_auth) \
                encode(sha256, 'hex'), transport_auth, tls_verify_error \
         FROM fetch_attempt \
         WHERE status = 'success' AND sha256 IS NOT NULL \
         ORDER BY encode(sha256, 'hex'), transport_auth, last_attempt DESC",
    )
    .fetch_all(pool)
    .await?;
    let mut map: std::collections::HashMap<String, Vec<TransportTag>> =
        std::collections::HashMap::new();
    for (sha, state, error) in rows {
        map.entry(sha)
            .or_default()
            .push(transport_tag(&state, error));
    }
    Ok(map)
}

#[derive(Debug, Serialize)]
struct FetchStatusCount {
    label: &'static str,
    count: i64,
}

/// Display order + labels for each `fetch_attempt.status` value
/// (`review::fetcher::FetchStatus::as_str()` - pending/success/dead/rejected/too_big/timeout/
/// empty). Success first (the outcome an operator scans for), then the retryable failure classes,
/// then the two terminal/in-progress states. The counts are inventory, so none is coloured: the
/// console spends colour only on things that want the operator.
const FETCH_STATUS_DISPLAY: [(&str, &str); 7] = [
    ("success", "Success"),
    ("rejected", "Rejected"),
    ("timeout", "Timeout"),
    ("too_big", "Too big"),
    ("empty", "Empty"),
    ("dead", "Dead"),
    ("pending", "Pending"),
];

/// `GROUP BY status` on `fetch_attempt` - parameterless, so there is no injection surface. Missing
/// statuses (no attempts recorded yet, or none of that particular outcome) default to a count of
/// 0 rather than being absent from the strip, so the operator always sees the full status set.
async fn fetch_status_counts(pool: &sqlx::PgPool) -> Result<Vec<FetchStatusCount>, sqlx::Error> {
    let counts: std::collections::HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, count(*) FROM fetch_attempt GROUP BY status",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    Ok(FETCH_STATUS_DISPLAY
        .iter()
        .map(|(key, label)| FetchStatusCount {
            label,
            count: *counts.get(*key).unwrap_or(&0),
        })
        .collect())
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
async fn sample_source_ips(
    pool: &sqlx::PgPool,
) -> Result<std::collections::HashMap<String, Vec<String>>, sqlx::Error> {
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
    .await?;

    Ok(group_source_ips(rows))
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
    // Each DB read soft-fails through `degraded` so the page names the placeholder: an empty
    // source-IP map renders "not linked" and an empty verdict map "not yet scanned", both of
    // which are also what a healthy node with nothing to show renders.
    let mut degraded = base.degraded;
    let source_ips_by_sha = degraded.soft("sample source IPs", sample_source_ips(&state.db).await);
    let transport_by_sha = degraded.soft("fetch transport", sample_transport(&state.db).await);

    let vt_results: std::collections::HashMap<String, (i32, i32, String)> = degraded
        .soft(
            "VirusTotal verdicts",
            sqlx::query_as::<_, (String, i32, i32, String)>(
                "SELECT sha256, detected, total, vt_link FROM sample_analysis",
            )
            .fetch_all(&state.db)
            .await,
        )
        .into_iter()
        .map(|(sha, d, t, l)| (sha, (d, t, l)))
        .collect();

    let max_source_ips = max_source_ips_shown();
    let mut files = Vec::new();
    for (sensor, dir) in spool_dirs() {
        for file in review::spool::list_samples(&dir).await.unwrap_or_default() {
            files.push((sensor, file));
        }
    }
    let shas: Vec<String> = files.iter().map(|(_, f)| f.sha256.clone()).collect();
    let campaigns = degraded.soft(
        "sample campaigns",
        campaigns_by_sample(&state.db, &shas).await,
    );
    let activity = degraded.soft("sample activity", sample_activity(&state.db, &shas).await);
    let delivering = degraded.soft(
        "delivering campaigns",
        delivering_campaigns(&state.db, &shas).await,
    );
    let today = Utc::now().date_naive();
    let ids: Vec<i64> = campaigns.values().map(|c| c.id).collect();
    let days = degraded.soft(
        "activity sparklines",
        day_counts(&state.db, &ids, today - Duration::days(LIST_SPARK_DAYS - 1)).await,
    );
    let now = Utc::now();
    let mut samples = Vec::new();
    {
        for (sensor, file) in files {
            let vt = vt_results.get(&file.sha256);
            let all_ips = source_ips_by_sha.get(&file.sha256);
            let source_ips: Vec<String> = all_ips
                .map(|v| v.iter().take(max_source_ips).cloned().collect())
                .unwrap_or_default();
            let more_source_ips = all_ips.map_or(0, |v| v.len().saturating_sub(max_source_ips));
            let transport = transport_by_sha
                .get(&file.sha256)
                .cloned()
                .unwrap_or_default();
            let campaign = campaigns.get(&file.sha256).cloned();
            let (active, active_title) = activity
                .get(&file.sha256)
                .map(|(first, last)| format_active(*first, *last, now))
                .unwrap_or_default();
            let spark = campaign.as_ref().map_or_else(Vec::new, |c| {
                sparkline(
                    &days.get(&c.id).cloned().unwrap_or_default(),
                    today,
                    LIST_SPARK_DAYS,
                )
            });
            samples.push(SampleRow {
                sha256_short: file.sha256[..12].to_string(),
                size: format_bytes(file.size),
                delivered_by: delivering
                    .get(&file.sha256)
                    .map(|&(id, members)| DeliveredBy { id, members }),
                active,
                active_title,
                spark,
                campaign,
                sha256: file.sha256,
                sensor: sensor.to_string(),
                vt_detected: vt.map(|(d, _, _)| *d),
                vt_total: vt.map(|(_, t, _)| *t),
                vt_link: vt.map(|(_, _, l)| l.clone()).unwrap_or_default(),
                source_ips,
                more_source_ips,
                transport,
                uploaded: sensor != FETCHED_BUCKET,
            });
        }
    }

    // The most widely delivered files first, then by digest so the order is stable.
    samples.sort_by(|a, b| {
        let hosts = |s: &SampleRow| s.campaign.as_ref().map_or(0, |c| c.members);
        hosts(b)
            .cmp(&hosts(a))
            .then_with(|| a.sha256.cmp(&b.sha256))
    });
    let total = samples.len();

    let status_counts = degraded.soft("fetch status counts", fetch_status_counts(&state.db).await);
    let fetch_attempts_total: i64 = status_counts.iter().map(|c| c.count).sum();

    let tmpl = state.templates.get_template("samples.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "samples",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        samples,
        total,
        status_counts,
        fetch_attempts_total,
        spark_days => LIST_SPARK_DAYS,
        spark_width => LIST_SPARK_DAYS * SPARK_STEP,
        spark_height => SPARK_HEIGHT,
    })?))
}

/// `GET /samples/{sha256}` - one sample: where it is spooled, the campaigns it belongs to, and the
/// indicators extracted from it. The digest is validated before it touches a query or a path.
async fn sample_page(
    State(state): State<AppState>,
    AxumPath(sha256): AxumPath<String>,
) -> Result<Response, AppError> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok((axum::http::StatusCode::BAD_REQUEST, "invalid sha256").into_response());
    }
    let sha256 = sha256.to_ascii_lowercase();
    let mut spooled = None;
    for (bucket, dir) in spool_dirs() {
        // Not following a link: a planted symlink under a digest name is not a sample.
        if let Ok(meta) = std::fs::symlink_metadata(dir.join(&sha256))
            && meta.is_file()
        {
            spooled = Some((bucket, meta.len()));
            break;
        }
    }

    let base = base_context(&state.db, state.startup_time, state.version).await;
    let mut degraded = base.degraded;
    let campaigns: Vec<CampaignRef> = degraded.soft(
        "sample campaigns",
        campaigns_linking_sample(&state.db, &sha256).await,
    );
    let scan_state: Option<String> = degraded.soft(
        "indicator scan state",
        sqlx::query_scalar("SELECT state FROM ioc_artifact_scan WHERE sha256 = $1")
            .bind(&sha256)
            .fetch_optional(&state.db)
            .await,
    );
    let iocs = degraded.soft("indicators", artifact_iocs(&state.db, &sha256).await);

    let tmpl = state.templates.get_template("sample_detail.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "samples",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        spooled => spooled.is_some(),
        bucket => spooled.map(|(b, _)| b).unwrap_or_default(),
        size => spooled.map(|(_, s)| format_bytes(s)).unwrap_or_default(),
        sha256,
        campaigns,
        scan_state => scan_state.unwrap_or_default(),
        iocs,
    })?)
    .into_response())
}

async fn download_sample(AxumPath(sha256): AxumPath<String>) -> Response {
    serve_sample(&spool_dirs(), &sha256).await
}

async fn serve_sample(dirs: &[(&'static str, PathBuf)], sha256: &str) -> Response {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid sha256").into_response();
    }
    // Spool names are lowercase; accept a pasted uppercase digest for the same body.
    let sha256 = sha256.to_ascii_lowercase();

    // A body that exists but fails verification is reported as such rather than as "not found":
    // a link, a non-regular file or content that does not hash to its name in a spool means
    // something other than the sensor wrote there, which the operator needs to see.
    let mut refused = false;
    for (sensor, dir) in dirs {
        let bytes = match review::spool::read_sample(dir, &sha256).await {
            Ok(bytes) => bytes,
            Err(review::spool::SpoolError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(e) => {
                tracing::warn!(sensor, sha256 = %sha256, error = %e, "samples: refused to serve a spool entry that failed verification");
                refused = true;
                continue;
            }
        };
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

    if refused {
        return (
            axum::http::StatusCode::CONFLICT,
            "sample failed integrity verification and was not served",
        )
            .into_response();
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
    fn only_a_verified_fetch_reads_as_verified_and_errors_are_capped() {
        assert_eq!(transport_tag("verified", None).label, "TLS verified");
        assert_eq!(transport_tag("plaintext", None).label, "plaintext");
        let unknown = transport_tag("unknown", None);
        assert_eq!(unknown.label, "not recorded");
        assert_eq!(
            unknown.sev, "",
            "a state nobody recorded must not look like a verdict"
        );
        assert_eq!(transport_tag("anything-else", None).label, "not recorded");

        let long = "x".repeat(TRANSPORT_DETAIL_MAX_CHARS + 50);
        let unverified = transport_tag("unverified", Some(long));
        assert_eq!(unverified.label, "TLS unverified");
        assert_eq!(unverified.sev, "watch");
        assert_eq!(
            unverified.detail.unwrap().chars().count(),
            TRANSPORT_DETAIL_MAX_CHARS
        );
    }

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

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    async fn body_of(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn serve_sample_returns_a_verified_body_from_whichever_spool_holds_it() {
        let empty = tempfile::tempdir().unwrap();
        let holding = tempfile::tempdir().unwrap();
        let body = b"dropper bytes";
        let sha = sha256_hex(body);
        std::fs::write(holding.path().join(&sha), body).unwrap();
        let dirs = [
            ("ssh", empty.path().to_path_buf()),
            ("fetched", holding.path().to_path_buf()),
        ];

        let response = serve_sample(&dirs, &sha.to_ascii_uppercase()).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(body_of(response).await, body);
    }

    /// The audit's reproduction: a digest-named symlink in a sensor spool pointing at a local file
    /// served that file's bytes to the operator. It must be refused, and the target's bytes must
    /// not appear in the response - including when the link's name is the target's real digest,
    /// which a name-only check would accept.
    #[cfg(unix)]
    #[tokio::test]
    async fn serve_sample_refuses_a_symlink_and_never_returns_its_target() {
        let spool = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("hostname");
        std::fs::write(&target, b"host-secret-contents").unwrap();

        for name in ["a".repeat(64), sha256_hex(b"host-secret-contents")] {
            let link = spool.path().join(&name);
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let response = serve_sample(&[("ssh", spool.path().to_path_buf())], &name).await;
            assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
            let served = body_of(response).await;
            assert!(
                !served
                    .windows(b"host-secret-contents".len())
                    .any(|w| w == b"host-secret-contents"),
                "target bytes leaked through the download route"
            );
            std::fs::remove_file(&link).unwrap();
        }
    }

    #[tokio::test]
    async fn serve_sample_refuses_content_that_does_not_match_its_name() {
        let spool = tempfile::tempdir().unwrap();
        let name = sha256_hex(b"what the name claims");
        std::fs::write(spool.path().join(&name), b"what is actually there").unwrap();

        let response = serve_sample(&[("ftp", spool.path().to_path_buf())], &name).await;
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn serve_sample_distinguishes_missing_from_malformed() {
        let spool = tempfile::tempdir().unwrap();
        let dirs = [("adb", spool.path().to_path_buf())];
        assert_eq!(
            serve_sample(&dirs, &"e".repeat(64)).await.status(),
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            serve_sample(&dirs, "../../etc/passwd").await.status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }
}
