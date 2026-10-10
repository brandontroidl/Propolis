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

    // Planner estimate and on-disk size, not a count over the table: a scrape must not read it.
    // `reltuples` is -1 on a table never analysed, which reads as 0 rows here.
    let (shell_output_rows, shell_output_bytes): (i64, i64) = sqlx::query_as(
        "SELECT GREATEST(reltuples, 0)::bigint, pg_total_relation_size(oid)::bigint \
         FROM pg_class WHERE oid = 'shell_output'::regclass",
    )
    .fetch_one(&state.db)
    .await?;
    push_gauge(
        &mut out,
        "propolis_shell_output_rows",
        "Stored shell reply texts (planner estimate).",
        shell_output_rows,
    );
    push_gauge(
        &mut out,
        "propolis_shell_output_bytes",
        "On-disk size of the shell reply table with its indexes.",
        shell_output_bytes,
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

    // -1 is "uploaded, no verdict yet" and -2 is "kept local, not uploaded for its type"
    // (`review::virustotal`); neither is a verdict, and only -1 is waiting on anything.
    let (analysis_pending, analysis_scanned, analysis_not_uploaded): (i64, i64, i64) =
        sqlx::query_as(
            "SELECT count(*) FILTER (WHERE detected = -1), count(*) FILTER (WHERE detected >= 0), \
             count(*) FILTER (WHERE detected = -2) \
             FROM sample_analysis",
        )
        .fetch_one(&state.db)
        .await?;
    writeln!(
        out,
        "# HELP propolis_sample_analysis Captured samples by analysis state: scanned (a verdict recorded), pending (uploaded, no verdict yet) or not_uploaded (kept local because the content is not executable or script content)."
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
    writeln!(
        out,
        "propolis_sample_analysis{{state=\"not_uploaded\"}} {analysis_not_uploaded}"
    )
    .unwrap();
    let analysis_pending_oldest: Option<f64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM now() - min(analyzed_at))::float8 \
         FROM sample_analysis WHERE detected = -1",
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
    let mut spools: Vec<(&str, u64, u64)> = Vec::new();
    for (name, dir) in review::spool::all_body_dirs() {
        if let Some((count, age)) = spool_occupancy(&dir).await {
            spools.push((name, count, age));
        }
    }
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

    push_intake_lag(&mut out, (state.intake_lag)());
    match fleet::stats::read_all(&state.db).await {
        Ok(rows) => push_sensor_stats(&mut out, &rows, chrono::Utc::now()),
        // Logged and left out, never a failed scrape: an absent series says nobody measured.
        Err(e) => tracing::warn!(error = %e, "sensor_stats could not be read for /metrics"),
    }
    push_counter(
        &mut out,
        "propolis_intake_lines_quarantined_total",
        "Log lines the database kept refusing that intake set aside in the quarantine directory and skipped, since process start.",
        crate::intake_lag::LINES_QUARANTINED.load(std::sync::atomic::Ordering::Relaxed),
    );

    // Console saturation: each of these moves only when a bound refused work, so a non-zero rate
    // is a login spray or a connection flood, not ordinary use.
    push_counter(
        &mut out,
        "propolis_console_login_refused_per_ip_total",
        "Login attempts refused by the per-address rate limit since process start.",
        state.login_rate_limiter.refused_per_ip(),
    );
    push_counter(
        &mut out,
        "propolis_console_login_refused_global_total",
        "Login attempts refused by the all-addresses login budget since process start.",
        state.login_rate_limiter.refused_global(),
    );
    push_counter(
        &mut out,
        "propolis_console_login_verify_busy_total",
        "Login attempts answered busy because every password-verification slot was taken.",
        state.passwords.busy_count(),
    );
    push_counter(
        &mut out,
        "propolis_console_connections_shed_total",
        "Connections closed on accept because the console's connection limit was reached.",
        crate::server::STATS
            .connections_shed
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push_counter(
        &mut out,
        "propolis_console_body_timeouts_total",
        "Requests answered 408 because the body did not arrive within the read timeout.",
        crate::server::STATS
            .body_timeouts
            .load(std::sync::atomic::Ordering::Relaxed),
    );

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

/// The per-log intake backlog, labelled with the log's `PROPOLIS_SENSOR_LOGS` name. A process that
/// tails nothing reports no logs and emits neither metric: an absent series says nobody measured,
/// where a zero would say caught up. A log with lines waiting but no event appended since start
/// has no age to report, so it gets a bytes sample and no age sample.
fn push_intake_lag(out: &mut String, mut logs: Vec<crate::intake_lag::IntakeLag>) {
    if logs.is_empty() {
        return;
    }
    logs.sort_by(|a, b| a.log.cmp(&b.log));
    writeln!(
        out,
        "# HELP propolis_intake_bytes_behind Unread bytes of each intake log after its latest poll, rotated-out files still being drained included."
    )
    .unwrap();
    writeln!(out, "# TYPE propolis_intake_bytes_behind gauge").unwrap();
    for lag in &logs {
        writeln!(
            out,
            "propolis_intake_bytes_behind{{sensor=\"{}\"}} {}",
            escape_label(&lag.log),
            lag.bytes_behind
        )
        .unwrap();
    }
    writeln!(
        out,
        "# HELP propolis_intake_oldest_unread_age_seconds How long the oldest unread line of each intake log has waited: 0 when the latest poll read every complete line, otherwise now minus the observed_at of the last event appended from it."
    )
    .unwrap();
    writeln!(
        out,
        "# TYPE propolis_intake_oldest_unread_age_seconds gauge"
    )
    .unwrap();
    for lag in &logs {
        if let Some(age) = lag.oldest_unread_age {
            writeln!(
                out,
                "propolis_intake_oldest_unread_age_seconds{{sensor=\"{}\"}} {}",
                escape_label(&lag.log),
                age.as_secs()
            )
            .unwrap();
        }
    }
}

/// Each capturing sensor's latest `sensor_stats` line, labelled by sensor, with how old that line
/// is. The values are the last ones reported and stay put when a sensor goes quiet; what changes
/// is `propolis_sensor_stats_age_seconds` (and `_stale`), so a dead sensor reads as stale rather
/// than as zeros. A sensor that never reported has no series at all.
fn push_sensor_stats(
    out: &mut String,
    rows: &[fleet::stats::SensorStatsRow],
    now: chrono::DateTime<chrono::Utc>,
) {
    if rows.is_empty() {
        return;
    }
    type Value = fn(&fleet::stats::SensorStatsRow) -> i64;
    let series: [(&str, &str, &str, Value); 8] = [
        (
            "propolis_sensor_capture_queue_dropped_total",
            "counter",
            "Captures dropped because the sensor's hand-off queue was full, since the sensor started.",
            |r| r.dropped,
        ),
        (
            "propolis_sensor_capture_spool_refused_total",
            "counter",
            "Captures the sensor's spool refused (per-file cap or exhausted budget), since the sensor started.",
            |r| r.spool_refused,
        ),
        (
            "propolis_sensor_capture_truncated_total",
            "counter",
            "Captures kept as a prefix because the capture memory budget ran out, since the sensor started.",
            |r| r.truncated,
        ),
        (
            "propolis_sensor_capture_refused_total",
            "counter",
            "Captures refused with no bytes because the capture memory budget was full, since the sensor started.",
            |r| r.refused,
        ),
        (
            "propolis_sensor_capture_budget_bytes",
            "gauge",
            "Capture bytes the sensor held in memory at its last report.",
            |r| r.budget_current,
        ),
        (
            "propolis_sensor_capture_budget_high_water_bytes",
            "gauge",
            "Most capture bytes the sensor has held in memory at once since it started.",
            |r| r.budget_high_water,
        ),
        (
            "propolis_sensor_capture_budget_refused_total",
            "counter",
            "Capture memory reservations the budget refused, since the sensor started.",
            |r| r.budget_refused,
        ),
        (
            "propolis_sensor_uptime_seconds",
            "gauge",
            "Sensor uptime at its last report.",
            |r| r.uptime_secs,
        ),
    ];
    for (name, kind, help, value) in series {
        writeln!(out, "# HELP {name} {help}").unwrap();
        writeln!(out, "# TYPE {name} {kind}").unwrap();
        for row in rows {
            writeln!(
                out,
                "{name}{{sensor=\"{}\"}} {}",
                escape_label(&row.sensor),
                value(row)
            )
            .unwrap();
        }
    }
    type Derived = fn(&fleet::stats::SensorStatsRow, chrono::DateTime<chrono::Utc>) -> i64;
    let derived: [(&str, &str, Derived); 3] = [
        (
            "propolis_sensor_stats_age_seconds",
            "Seconds since the sensor's last stats line, by the sensor's own clock.",
            |r, now| r.age_seconds(now),
        ),
        (
            "propolis_sensor_stats_stale",
            "1 when the sensor's last stats line is older than three reporting intervals: the values above are then history, not current.",
            |r, now| i64::from(r.is_stale(now)),
        ),
        (
            "propolis_sensor_stats_final",
            "1 when the sensor's last line was its shutdown line: a clean stop, as opposed to silence.",
            |r, _| i64::from(r.is_final),
        ),
    ];
    for (name, help, value) in derived {
        writeln!(out, "# HELP {name} {help}").unwrap();
        writeln!(out, "# TYPE {name} gauge").unwrap();
        for row in rows {
            writeln!(
                out,
                "{name}{{sensor=\"{}\"}} {}",
                escape_label(&row.sensor),
                value(row, now)
            )
            .unwrap();
        }
    }
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} counter").unwrap();
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

/// `(sample count, oldest sample age in seconds)` for one spool directory, counting exactly what
/// the samples page lists (`review::spool::list_samples`: sha256-named regular files, never tmp
/// files or links). `None` when the directory cannot be read at all, so the caller emits no
/// series rather than a false zero.
async fn spool_occupancy(dir: &std::path::Path) -> Option<(u64, u64)> {
    let samples = review::spool::list_samples(dir).await?;
    let now = std::time::SystemTime::now();
    let oldest = samples
        .iter()
        .filter_map(|s| s.modified)
        .map(|mtime| now.duration_since(mtime).map_or(0, |d| d.as_secs()))
        .max()
        .unwrap_or(0);
    Some((samples.len() as u64, oldest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_row(sensor: &str, reported: &str, is_final: bool) -> fleet::stats::SensorStatsRow {
        fleet::stats::SensorStatsRow {
            sensor: sensor.into(),
            reported_at: reported.parse().unwrap(),
            received_at: reported.parse().unwrap(),
            uptime_secs: 3600,
            is_final,
            dropped: 11,
            spool_refused: 12,
            truncated: 13,
            refused: 14,
            budget_current: 15,
            budget_high_water: 16,
            budget_refused: 17,
        }
    }

    #[test]
    fn sensor_stats_are_published_by_sensor_with_their_age_and_staleness() {
        let now: chrono::DateTime<chrono::Utc> = "2026-10-09T12:10:00Z".parse().unwrap();
        let rows = [
            stats_row("ssh", "2026-10-09T12:09:30Z", false),
            // Silent for 6 minutes with no shutdown line: stale, and not a clean stop.
            stats_row("telnet", "2026-10-09T12:04:00Z", false),
            // A shutdown line 10 s ago: a clean stop that is not yet stale. The two rows differ in
            // BOTH flags, so a swap of stale and final cannot pass.
            stats_row("ftp", "2026-10-09T12:09:50Z", true),
        ];
        let mut out = String::new();
        push_sensor_stats(&mut out, &rows, now);
        for line in [
            "propolis_sensor_capture_queue_dropped_total{sensor=\"ssh\"} 11",
            "propolis_sensor_capture_spool_refused_total{sensor=\"ssh\"} 12",
            "propolis_sensor_capture_truncated_total{sensor=\"ssh\"} 13",
            "propolis_sensor_capture_refused_total{sensor=\"ssh\"} 14",
            "propolis_sensor_capture_budget_bytes{sensor=\"ssh\"} 15",
            "propolis_sensor_capture_budget_high_water_bytes{sensor=\"ssh\"} 16",
            "propolis_sensor_capture_budget_refused_total{sensor=\"ssh\"} 17",
            "propolis_sensor_uptime_seconds{sensor=\"ssh\"} 3600",
            "propolis_sensor_stats_age_seconds{sensor=\"ssh\"} 30",
            "propolis_sensor_stats_stale{sensor=\"ssh\"} 0",
            "propolis_sensor_stats_final{sensor=\"ssh\"} 0",
            "propolis_sensor_stats_age_seconds{sensor=\"telnet\"} 360",
            "propolis_sensor_stats_stale{sensor=\"telnet\"} 1",
            "propolis_sensor_stats_final{sensor=\"telnet\"} 0",
            "propolis_sensor_stats_age_seconds{sensor=\"ftp\"} 10",
            "propolis_sensor_stats_stale{sensor=\"ftp\"} 0",
            "propolis_sensor_stats_final{sensor=\"ftp\"} 1",
            // A stale sensor keeps its last values; staleness is what says they are history.
            "propolis_sensor_capture_queue_dropped_total{sensor=\"telnet\"} 11",
        ] {
            assert!(
                out.lines().any(|l| l == line),
                "missing `{line}` in:\n{out}"
            );
        }
        assert!(out.contains("# TYPE propolis_sensor_capture_queue_dropped_total counter"));
        assert!(out.contains("# TYPE propolis_sensor_capture_budget_bytes gauge"));
    }

    #[test]
    fn no_sensor_stats_means_no_series_not_zeros() {
        let mut out = String::new();
        push_sensor_stats(
            &mut out,
            &[],
            "2026-10-09T12:10:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn a_sensor_name_cannot_break_the_exposition_format() {
        let mut out = String::new();
        push_sensor_stats(
            &mut out,
            &[stats_row("a\"b\nc", "2026-10-09T12:09:30Z", false)],
            "2026-10-09T12:10:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
        );
        // Every series line, of every metric, carries the escaped name on one line; a raw newline
        // or quote in any one of them would leave a line that is neither a comment nor a series.
        let series: Vec<&str> = out.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(series.len(), 11, "one series per metric:\n{out}");
        for line in series {
            assert!(
                line.starts_with("propolis_sensor_") && line.contains("{sensor=\"a\\\"b\\nc\"} "),
                "malformed series line `{line}`"
            );
        }
    }

    #[sqlx::test(migrations = false)]
    async fn stats_stored_by_intake_are_what_the_scrape_renders(pool: sqlx::PgPool) {
        fleet::migrator().run(&pool).await.unwrap();
        fleet::stats::upsert(&pool, &stats_row("tftp", "2026-10-09T12:09:00Z", false))
            .await
            .unwrap();
        let rows = fleet::stats::read_all(&pool).await.unwrap();
        let mut out = String::new();
        push_sensor_stats(
            &mut out,
            &rows,
            "2026-10-09T12:09:10Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
        );
        assert!(out.contains("propolis_sensor_capture_truncated_total{sensor=\"tftp\"} 13"));
        assert!(out.contains("propolis_sensor_stats_age_seconds{sensor=\"tftp\"} 10"));
    }

    #[test]
    fn age_seconds_treats_null_and_skew_as_zero() {
        assert_eq!(age_seconds(None), 0);
        assert_eq!(age_seconds(Some(-12.0)), 0);
        assert_eq!(age_seconds(Some(90.9)), 90);
    }

    #[tokio::test]
    async fn spool_occupancy_counts_only_sha_named_bodies_and_reports_the_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("a".repeat(64));
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(tmp.path().join("b".repeat(64)), b"y").unwrap();
        std::fs::write(tmp.path().join("staging.tmp"), b"z").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&old, tmp.path().join("c".repeat(64))).unwrap();
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        let (count, oldest) = spool_occupancy(tmp.path()).await.unwrap();
        assert_eq!(count, 2, "neither the tmp file nor a link is a sample");
        assert!((3599..=3601).contains(&oldest), "oldest age {oldest}");
        assert_eq!(
            spool_occupancy(&tmp.path().join("missing")).await,
            None,
            "an unreadable spool yields no series, never a zero"
        );
    }

    #[test]
    fn escape_label_escapes_backslash_quote_and_newline() {
        assert_eq!(escape_label(r#"a\b"c\nd"#), r#"a\\b\"c\\nd"#);
        assert_eq!(escape_label("plain"), "plain");
    }

    fn lag(log: &str, bytes: u64, age: Option<u64>) -> crate::intake_lag::IntakeLag {
        crate::intake_lag::IntakeLag {
            log: log.into(),
            sensors: vec![log.into()],
            bytes_behind: bytes,
            oldest_unread_age: age.map(std::time::Duration::from_secs),
            behind: false,
        }
    }

    #[test]
    fn intake_lag_is_one_series_per_log_and_an_unknown_age_is_absent_not_zero() {
        let mut out = String::new();
        push_intake_lag(
            &mut out,
            vec![
                lag("telnet", 6_600_000_000, Some(950_400)),
                lag("cred-vnc", 0, Some(0)),
                lag("ssh", 4_096, None),
            ],
        );
        assert!(out.contains("# TYPE propolis_intake_bytes_behind gauge\n"));
        assert!(out.contains("propolis_intake_bytes_behind{sensor=\"telnet\"} 6600000000\n"));
        assert!(out.contains("propolis_intake_bytes_behind{sensor=\"cred-vnc\"} 0\n"));
        assert!(out.contains("propolis_intake_bytes_behind{sensor=\"ssh\"} 4096\n"));
        assert!(
            out.contains("propolis_intake_oldest_unread_age_seconds{sensor=\"telnet\"} 950400\n")
        );
        assert!(out.contains("propolis_intake_oldest_unread_age_seconds{sensor=\"cred-vnc\"} 0\n"));
        assert!(
            !out.contains("propolis_intake_oldest_unread_age_seconds{sensor=\"ssh\"}"),
            "no appended event to measure from must leave the age absent: {out}"
        );
        let cred = out.find("{sensor=\"cred-vnc\"}").unwrap();
        let telnet = out.find("{sensor=\"telnet\"}").unwrap();
        assert!(cred < telnet, "series are ordered by log name: {out}");
    }

    #[test]
    fn a_process_tailing_nothing_emits_no_intake_lag_series() {
        let mut out = String::new();
        push_intake_lag(&mut out, Vec::new());
        assert_eq!(out, "");
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
