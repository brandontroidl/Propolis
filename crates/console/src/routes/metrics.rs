//! `GET /metrics` - Prometheus text-format metrics (`internal/design/06-console-observability.md`,
//! "Observability" > "Metrics"), derived from live DB queries (and the feed publisher's
//! `manifest.json`, via `routes::feed::read_manifest`, when configured) on every scrape rather
//! than pre-aggregated counters: "Metrics are derived from database queries on each /metrics
//! scrape (not pre-computed)... avoids stale counters."
//!
//! Mounted OUTSIDE the auth middleware alongside `/health`/`/ready` (see `routes::health`'s own
//! doc comment): a Prometheus scraper cannot complete an interactive password login, so this
//! endpoint carries no session gate. Unauthenticated exposure of operational counts (IP counts,
//! queue depth) is acceptable here because the whole console binds loopback-only by default
//! (this design's own closed decision #4, "Bind model").
//!
//! Two metrics named in the design's list are deliberately NOT emitted here:
//! `propolis_events_ingested_total` and `propolis_events_rejected_total`. Both are per-process,
//! in-memory batch counters inside the `intake` binary (`crates/intake/src/main.rs`'s
//! `run_sensor_loop`, logged via `tracing::info!` but never persisted to Postgres) - there is no
//! durable store this crate could read them from without inventing a new cross-process counter
//! channel, which is out of scope for this task. Every metric below is one this crate can derive
//! honestly from data it actually has: `ip_score`, `review_queue`, `vendor_submission`, and the
//! feed publisher's `manifest.json`. The three gauges below that go beyond the task brief's own
//! explicit list (`propolis_ips_recommended_vendor`/`_blocklist`, `propolis_feed_last_build_timestamp`)
//! ARE named in the design doc's "Metrics" list and are one cheap extra query / one extra
//! manifest field away, using data already being read for the brief's own metrics.

use std::fmt::Write as _;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::DateTime;
use sqlx::Row;

use crate::AppState;
use crate::routes::error::AppError;
use crate::routes::feed::read_manifest;

pub fn router() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}

async fn metrics(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    // Optional bearer gate (`PROPOLIS_CONSOLE_METRICS_TOKEN`). When configured, `/metrics` requires
    // a matching `Authorization: Bearer <token>` even though it is mounted outside session auth -
    // defense in depth for a non-loopback bind. Unconfigured leaves it open (see
    // `console::warn_if_console_exposed`).
    if let Some(token) = &state.metrics_token {
        let authorized = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), token.as_bytes()));
        if !authorized {
            return Ok((axum::http::StatusCode::UNAUTHORIZED, "unauthorized\n").into_response());
        }
    }

    let mut out = String::new();

    let ips_scored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_score")
        .fetch_one(&state.db)
        .await?;
    push_gauge(
        &mut out,
        "propolis_ips_scored",
        "Total IPs with an ip_score projection.",
        ips_scored,
    );

    let ips_eligible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ip_score WHERE eligible = true")
            .fetch_one(&state.db)
            .await?;
    push_gauge(
        &mut out,
        "propolis_ips_eligible",
        "IPs currently eligible for review.",
        ips_eligible,
    );

    let ips_recommended_vendor: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ip_score WHERE recommended_for_vendor = true")
            .fetch_one(&state.db)
            .await?;
    push_gauge(
        &mut out,
        "propolis_ips_recommended_vendor",
        "IPs currently recommended for vendor reporting.",
        ips_recommended_vendor,
    );

    let ips_recommended_blocklist: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ip_score WHERE recommended_for_blocklist = true")
            .fetch_one(&state.db)
            .await?;
    push_gauge(
        &mut out,
        "propolis_ips_recommended_blocklist",
        "IPs currently recommended for the blocklist feed.",
        ips_recommended_blocklist,
    );

    let review_queue_pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM review_queue WHERE state = 'pending'")
            .fetch_one(&state.db)
            .await?;
    push_gauge(
        &mut out,
        "propolis_review_queue_pending",
        "review_queue entries awaiting an operator decision.",
        review_queue_pending,
    );

    let submission_rows = sqlx::query(
        "SELECT vendor, success, COUNT(*) AS count FROM vendor_submission \
         GROUP BY vendor, success ORDER BY vendor, success",
    )
    .fetch_all(&state.db)
    .await?;
    writeln!(
        out,
        "# HELP propolis_vendor_submissions_total Total vendor submission attempts by vendor and outcome."
    )
    .unwrap();
    writeln!(out, "# TYPE propolis_vendor_submissions_total counter").unwrap();
    for row in submission_rows {
        let vendor: String = row.try_get("vendor")?;
        let success: bool = row.try_get("success")?;
        let count: i64 = row.try_get("count")?;
        let status = if success { "success" } else { "failure" };
        writeln!(
            out,
            "propolis_vendor_submissions_total{{vendor=\"{}\",status=\"{status}\"}} {count}",
            escape_label(&vendor)
        )
        .unwrap();
    }

    // Malware pipeline: the WORK, not the process. A live scanner or fetcher that has stopped
    // verdicting or retiring urls is invisible to a liveness probe; queue depth by stage plus the
    // age of the oldest waiting item is what shows it. The ops-monitor's `scan-stale` and
    // `fetch-stale` conditions page on the same signals.
    let fetch_rows = sqlx::query(
        "SELECT status, COUNT(*) AS count FROM fetch_attempt GROUP BY status ORDER BY status",
    )
    .fetch_all(&state.db)
    .await?;
    writeln!(
        out,
        "# HELP propolis_fetch_attempts Malware fetcher urls by current status."
    )
    .unwrap();
    writeln!(out, "# TYPE propolis_fetch_attempts gauge").unwrap();
    for row in fetch_rows {
        let status: String = row.try_get("status")?;
        let count: i64 = row.try_get("count")?;
        writeln!(
            out,
            "propolis_fetch_attempts{{status=\"{}\"}} {count}",
            escape_label(&status)
        )
        .unwrap();
    }
    let fetch_pending_oldest: Option<f64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM now() - min(first_seen))::float8 \
         FROM fetch_attempt WHERE status = 'pending'",
    )
    .fetch_one(&state.db)
    .await?;
    push_gauge(
        &mut out,
        "propolis_fetch_pending_oldest_age_seconds",
        "Age of the oldest fetch url still pending; 0 when none is pending.",
        age_seconds(fetch_pending_oldest),
    );

    let (analysis_pending, analysis_scanned): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE detected < 0), count(*) FILTER (WHERE detected >= 0) \
         FROM sample_analysis",
    )
    .fetch_one(&state.db)
    .await?;
    writeln!(
        out,
        "# HELP propolis_sample_analysis Captured samples by analysis state: scanned (a verdict recorded) or pending (uploaded, no verdict yet)."
    )
    .unwrap();
    writeln!(out, "# TYPE propolis_sample_analysis gauge").unwrap();
    writeln!(
        out,
        "propolis_sample_analysis{{state=\"pending\"}} {analysis_pending}"
    )
    .unwrap();
    writeln!(
        out,
        "propolis_sample_analysis{{state=\"scanned\"}} {analysis_scanned}"
    )
    .unwrap();
    let analysis_pending_oldest: Option<f64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM now() - min(analyzed_at))::float8 \
         FROM sample_analysis WHERE detected < 0",
    )
    .fetch_one(&state.db)
    .await?;
    push_gauge(
        &mut out,
        "propolis_sample_analysis_pending_oldest_age_seconds",
        "Age of the oldest VirusTotal upload still awaiting a verdict; 0 when none.",
        age_seconds(analysis_pending_oldest),
    );

    // Spool occupancy from the filesystem: sample count and oldest body per spool. A spool this
    // process cannot read yields no series (absent, not zero) - the standalone console binary has
    // no spool grant, and an absent series is honest where a zero would claim an empty spool.
    let spools: Vec<(&str, u64, u64)> = review::spool::all_body_dirs()
        .iter()
        .filter_map(|(name, dir)| spool_occupancy(dir).map(|(n, age)| (*name, n, age)))
        .collect();
    if !spools.is_empty() {
        writeln!(
            out,
            "# HELP propolis_spool_samples Captured sample bodies on disk, per spool."
        )
        .unwrap();
        writeln!(out, "# TYPE propolis_spool_samples gauge").unwrap();
        for (name, count, _) in &spools {
            writeln!(out, "propolis_spool_samples{{spool=\"{name}\"}} {count}").unwrap();
        }
        writeln!(
            out,
            "# HELP propolis_spool_oldest_sample_age_seconds Age of the oldest sample body on disk, per spool; 0 when empty."
        )
        .unwrap();
        writeln!(out, "# TYPE propolis_spool_oldest_sample_age_seconds gauge").unwrap();
        for (name, _, age) in &spools {
            writeln!(
                out,
                "propolis_spool_oldest_sample_age_seconds{{spool=\"{name}\"}} {age}"
            )
            .unwrap();
        }
    }

    if let Some(manifest) = state.feed_output_dir.as_deref().and_then(read_manifest) {
        writeln!(
            out,
            "# HELP propolis_feed_entries Entry count in the last published feed build, by tier."
        )
        .unwrap();
        writeln!(out, "# TYPE propolis_feed_entries gauge").unwrap();
        writeln!(
            out,
            "propolis_feed_entries{{tier=\"aggressive\"}} {}",
            manifest.tiers.aggressive.count
        )
        .unwrap();
        writeln!(
            out,
            "propolis_feed_entries{{tier=\"standard\"}} {}",
            manifest.tiers.standard.count
        )
        .unwrap();

        // Retention feeds get their own metric rather than another `propolis_feed_entries` series:
        // that metric's label is `tier`, and a retention window is not a tier - reusing it would
        // make `sum(propolis_feed_entries)` double-count, since every tiered entry also appears in
        // the windows it falls inside. Emitted even when empty, so a window that has silently
        // stopped publishing is visible as a zero rather than as an absent series.
        if !manifest.windows.is_empty() {
            writeln!(
                out,
                "# HELP propolis_feed_window_entries Entry count per retention feed in the last published build."
            )
            .unwrap();
            writeln!(out, "# TYPE propolis_feed_window_entries gauge").unwrap();
            for window in &manifest.windows {
                writeln!(
                    out,
                    "propolis_feed_window_entries{{window=\"{}\"}} {}",
                    window.label, window.count
                )
                .unwrap();
            }
        }

        if let Ok(build_time) = DateTime::parse_from_rfc3339(&manifest.build_time) {
            push_gauge(
                &mut out,
                "propolis_feed_last_build_timestamp",
                "Unix timestamp of the last successful feed build.",
                build_time.timestamp(),
            );
        }
    }

    let ingested = state
        .events_ingested
        .load(std::sync::atomic::Ordering::Relaxed);
    let rejected = state
        .events_rejected
        .load(std::sync::atomic::Ordering::Relaxed);
    writeln!(out, "# HELP propolis_events_ingested_total Total events successfully ingested since process start.").unwrap();
    writeln!(out, "# TYPE propolis_events_ingested_total counter").unwrap();
    writeln!(out, "propolis_events_ingested_total {ingested}").unwrap();
    writeln!(out, "# HELP propolis_events_rejected_total Total events rejected (parse/validation failure) since process start.").unwrap();
    writeln!(out, "# TYPE propolis_events_rejected_total counter").unwrap();
    writeln!(out, "propolis_events_rejected_total {rejected}").unwrap();

    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response())
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: i64) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} gauge").unwrap();
    writeln!(out, "{name} {value}").unwrap();
}

/// Prometheus text-format label-value escaping: backslash, double quote, and newline. Vendor
/// names are config-driven, trusted identifiers today (`"abuseipdb"`/`"dshield"`/`"otx"` -
/// `crates/review/src/vendor/*.rs`'s `VendorAdapter::name`), not attacker-controlled, but escaping
/// is cheap and this keeps the exposition format well-formed regardless.
/// Constant-time byte comparison for the metrics bearer token, so a wrong token cannot be recovered
/// by response-timing. The length may leak (a token's length is not the secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// `EXTRACT(EPOCH FROM now() - min(...))` as whole seconds for a gauge: NULL (nothing waiting)
/// and a negative value (clock skew) both read as 0, never as a stale age.
fn age_seconds(epoch_secs: Option<f64>) -> i64 {
    epoch_secs.map_or(0, |s| s.max(0.0) as i64)
}

/// `(sample count, oldest sample age in seconds)` for one spool directory, counting only the
/// sha256-named bodies the spool writes (never its tmp files). `None` when the directory cannot
/// be read at all, so the caller emits no series rather than a false zero.
fn spool_occupancy(dir: &std::path::Path) -> Option<(u64, u64)> {
    let entries = std::fs::read_dir(dir).ok()?;
    let now = std::time::SystemTime::now();
    let mut count = 0u64;
    let mut oldest = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        count += 1;
        if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
            let age = now.duration_since(mtime).map_or(0, |d| d.as_secs());
            oldest = oldest.max(age);
        }
    }
    Some((count, oldest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_seconds_treats_null_and_skew_as_zero() {
        assert_eq!(age_seconds(None), 0);
        assert_eq!(age_seconds(Some(-12.0)), 0);
        assert_eq!(age_seconds(Some(90.9)), 90);
    }

    #[test]
    fn spool_occupancy_counts_only_sha_named_bodies_and_reports_the_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("a".repeat(64));
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(tmp.path().join("b".repeat(64)), b"y").unwrap();
        std::fs::write(tmp.path().join("staging.tmp"), b"z").unwrap();
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        let (count, oldest) = spool_occupancy(tmp.path()).unwrap();
        assert_eq!(count, 2, "the tmp file is not a sample");
        assert!((3599..=3601).contains(&oldest), "oldest age {oldest}");
        assert_eq!(
            spool_occupancy(&tmp.path().join("missing")),
            None,
            "an unreadable spool yields no series, never a zero"
        );
    }

    #[test]
    fn escape_label_escapes_backslash_quote_and_newline() {
        assert_eq!(escape_label(r#"a\b"c\nd"#), r#"a\\b\"c\\nd"#);
        assert_eq!(escape_label("plain"), "plain");
    }

    #[test]
    fn push_gauge_emits_help_type_and_value_lines() {
        let mut out = String::new();
        push_gauge(&mut out, "propolis_ips_scored", "help text", 42);
        assert_eq!(
            out,
            "# HELP propolis_ips_scored help text\n# TYPE propolis_ips_scored gauge\npropolis_ips_scored 42\n"
        );
    }
}
