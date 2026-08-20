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

async fn metrics(State(state): State<AppState>) -> Result<Response, AppError> {
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
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

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
