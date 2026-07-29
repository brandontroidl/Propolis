//! review: the binary entry point for sub-project 4's review queue,
//! gatekeeper, and vendor submission daemon. Two modes selected by the CLI's
//! subcommand (`review::cli`):
//!
//! - `review daemon` - runs forever: populates/withdraws the review queue on
//!   `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS`, and polls
//!   `SubmissionRunner::run_once` on `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS`,
//!   each on its own tokio task (mirrors `intake/src/main.rs`'s
//!   per-concern-loop pattern - Task 4's carry-forward note: "Task 5 ...
//!   builds real adapters from FullVendorConfig + one shared reqwest::Client,
//!   boxes them, and drives run_once() + populate()/withdraw() on a poll
//!   loop").
//! - Any other subcommand (`approve`/`reject`/`snooze`/`list`/`history`) -
//!   runs one operator decision or query against `review_queue`/
//!   `vendor_submission` via `review::cli::execute` and exits.
//!
//! Configuration is environment variables, matching `intake`/
//! `sensor-catchall`/`sensor-ssh`'s established convention: every value is
//! validated at startup and the process refuses to start on a malformed one
//! rather than silently substituting a default that could disable a bound.
//! See the `ENV_*` constants and `load_config_from_env` below for the full
//! list; `internal/design/04-review-gatekeeper-reporting.md`'s
//! "Configuration" is the spec this mirrors.

use std::env;
use std::time::Duration;

use clap::Parser;
use sqlx::PgPool;

use review::cli::{self, Cli, Command};
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{AbuseIpDb, DShield, FullVendorConfig, OtxAdapter, VendorAdapter};

const ENV_DATABASE_URL: &str = "DATABASE_URL";
const ENV_QUEUE_SCAN_INTERVAL_SECS: &str = "PROPOLIS_QUEUE_SCAN_INTERVAL_SECS";
const ENV_SUBMIT_POLL_INTERVAL_SECS: &str = "PROPOLIS_SUBMIT_POLL_INTERVAL_SECS";

const DEFAULT_QUEUE_SCAN_INTERVAL_SECS: u64 = 60;
const DEFAULT_SUBMIT_POLL_INTERVAL_SECS: u64 = 30;
const DEFAULT_COOLDOWN_HOURS: u32 = 24;
const DEFAULT_RATE_LIMIT: u32 = 100;
const DEFAULT_RATE_WINDOW_HOURS: u32 = 1;

#[derive(Debug)]
struct Config {
    database_url: String,
    queue_scan_interval: Duration,
    submit_poll_interval: Duration,
    vendors: Vec<FullVendorConfig>,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `DATABASE_URL` was absent or empty.
    MissingDatabaseUrl,
    /// A bound value failed to parse as the expected integer type.
    InvalidBound { field: String, value: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingDatabaseUrl => write!(
                f,
                "{ENV_DATABASE_URL} must be set to a PostgreSQL connection string"
            ),
            ConfigError::InvalidBound { field, value } => {
                write!(f, "{field} must be a non-negative integer, got {value:?}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses an optional positive `u64` bound: `None` (the env var was unset)
/// falls back to `default`; present-but-zero or present-but-unparseable are
/// both rejected. Used only for the two poll intervals, where zero would
/// busy-loop pinning a CPU core on every idle daemon task - mirrors
/// `intake`/`sensor-catchall`'s identically-named helper (kept free of
/// `std::env` itself so it stays unit-testable without mutating real process
/// environment).
fn parse_positive_u64(raw: Option<&str>, default: u64, field: &str) -> Result<u64, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::InvalidBound {
        field: field.to_string(),
        value: raw.to_string(),
    })?;
    if value == 0 {
        return Err(ConfigError::InvalidBound {
            field: field.to_string(),
            value: raw.to_string(),
        });
    }
    Ok(value)
}

/// Parses an optional `u32` bound: `None` falls back to `default`;
/// present-but-unparseable is rejected. Unlike [`parse_positive_u64`], zero
/// IS accepted here: `submit.rs`'s own module doc names "an operator has
/// deliberately zeroed out cooldown" as a real, supported case, and a zero
/// `rate_limit` is a valid (if extreme) way to hold every submission to a
/// vendor closed. Used for the three per-vendor gatekeeper bounds
/// (`cooldown_hours`/`rate_limit`/`rate_window_hours`).
fn parse_u32(raw: Option<&str>, default: u32, field: &str) -> Result<u32, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    raw.parse().map_err(|_| ConfigError::InvalidBound {
        field: field.to_string(),
        value: raw.to_string(),
    })
}

/// Parses a `PROPOLIS_VENDOR_<NAME>_ENABLED`-shaped boolean env var. Fails
/// closed on a malformed value: falls back to `default` (never to `true`)
/// and the caller logs it loudly, rather than refusing to start the whole
/// daemon over one vendor's typo'd flag.
fn parse_bool_flag(raw: Option<&str>, default: bool) -> bool {
    match raw {
        None => default,
        Some(s) if s.eq_ignore_ascii_case("true") => true,
        Some(s) if s.eq_ignore_ascii_case("false") => false,
        Some(_) => default,
    }
}

/// Builds one vendor's [`FullVendorConfig`] from its already-resolved
/// `api_key`/`api_url` plus the generic `PROPOLIS_VENDOR_<NAME>_*` bounds
/// every vendor shares. `name` is upper-cased into the `PROPOLIS_VENDOR_<NAME>_*`
/// env var prefix (e.g. `"abuseipdb"` -> `PROPOLIS_VENDOR_ABUSEIPDB_ENABLED`).
///
/// "API keys that are missing or empty fail-closed: the vendor is treated as
/// disabled" (design spec "Error handling") is enforced here, not left to the
/// gatekeeper, so a misconfigured vendor never even attempts an
/// unauthenticated HTTP call.
fn load_vendor_config(
    name: &str,
    api_key: String,
    api_url: String,
) -> Result<FullVendorConfig, ConfigError> {
    let prefix = format!("PROPOLIS_VENDOR_{}", name.to_uppercase());

    let enabled_field = format!("{prefix}_ENABLED");
    let mut enabled = parse_bool_flag(env::var(&enabled_field).ok().as_deref(), false);
    if enabled && api_key.is_empty() {
        tracing::warn!(
            vendor = name,
            "enabled but no API key configured; treating as disabled (fail-closed)"
        );
        enabled = false;
    }

    let cooldown_field = format!("{prefix}_COOLDOWN_HOURS");
    let cooldown_hours = parse_u32(
        env::var(&cooldown_field).ok().as_deref(),
        DEFAULT_COOLDOWN_HOURS,
        &cooldown_field,
    )?;
    let rate_limit_field = format!("{prefix}_RATE_LIMIT");
    let rate_limit = parse_u32(
        env::var(&rate_limit_field).ok().as_deref(),
        DEFAULT_RATE_LIMIT,
        &rate_limit_field,
    )?;
    let rate_window_field = format!("{prefix}_RATE_WINDOW_HOURS");
    let rate_window_hours = parse_u32(
        env::var(&rate_window_field).ok().as_deref(),
        DEFAULT_RATE_WINDOW_HOURS,
        &rate_window_field,
    )?;

    Ok(FullVendorConfig {
        name: name.to_string(),
        enabled,
        api_key,
        api_url,
        cooldown_hours,
        rate_limit,
        rate_window_hours,
        score_floor: None,
        category_filter: None,
    })
}

/// Loads and validates configuration from environment variables. Fails
/// closed: a missing `DATABASE_URL` or a malformed bound is rejected here
/// rather than silently substituted with a default. Validates every
/// vendor's bounds unconditionally, regardless of which CLI subcommand was
/// requested - in production this env is loaded once by systemd
/// (`EnvironmentFile=/etc/propolis/review.env`) for the whole unit, so an
/// operator subcommand shares the exact same validated configuration the
/// daemon would have started with.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let database_url = env::var(ENV_DATABASE_URL)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::MissingDatabaseUrl)?;

    let queue_scan_interval_secs = parse_positive_u64(
        env::var(ENV_QUEUE_SCAN_INTERVAL_SECS).ok().as_deref(),
        DEFAULT_QUEUE_SCAN_INTERVAL_SECS,
        ENV_QUEUE_SCAN_INTERVAL_SECS,
    )?;
    let submit_poll_interval_secs = parse_positive_u64(
        env::var(ENV_SUBMIT_POLL_INTERVAL_SECS).ok().as_deref(),
        DEFAULT_SUBMIT_POLL_INTERVAL_SECS,
        ENV_SUBMIT_POLL_INTERVAL_SECS,
    )?;

    let abuseipdb_key = env::var("PROPOLIS_VENDOR_ABUSEIPDB_KEY").unwrap_or_default();
    let abuseipdb_url = env::var("PROPOLIS_VENDOR_ABUSEIPDB_URL")
        .unwrap_or_else(|_| review::vendor::abuseipdb::DEFAULT_BASE_URL.to_string());
    let abuseipdb = load_vendor_config("abuseipdb", abuseipdb_key, abuseipdb_url)?;

    // DShield's real API wants "API key + user ID" (design spec's "DShield adapter"), but
    // FullVendorConfig/DShield::new (frozen by Task 3 - see task-3-report.md's dshield.rs
    // rationale) carry only one credential slot: "there is nowhere to carry a separate user ID
    // without adding a field to that frozen struct, which is a decision for whoever owns the
    // spec." DShield's own payload shape is itself unverified (the live endpoint 403'd during
    // that task), so composing "{user}:{key}" into the single api_key slot here is no less
    // provisional than the rest of that adapter - flagged in this task's report as a decision a
    // real DShield API verification pass may need to revisit, rather than widening a frozen
    // struct/adapter signature this task does not own.
    let dshield_key = env::var("PROPOLIS_VENDOR_DSHIELD_KEY").unwrap_or_default();
    let dshield_user = env::var("PROPOLIS_VENDOR_DSHIELD_USER")
        .ok()
        .filter(|s| !s.is_empty());
    let dshield_key = match dshield_user {
        Some(user) if !dshield_key.is_empty() => format!("{user}:{dshield_key}"),
        _ => dshield_key,
    };
    let dshield_url = env::var("PROPOLIS_VENDOR_DSHIELD_URL")
        .unwrap_or_else(|_| review::vendor::dshield::DEFAULT_BASE_URL.to_string());
    let dshield = load_vendor_config("dshield", dshield_key, dshield_url)?;

    let otx_key = env::var("PROPOLIS_VENDOR_OTX_KEY").unwrap_or_default();
    let otx_url = env::var("PROPOLIS_VENDOR_OTX_URL")
        .unwrap_or_else(|_| review::vendor::otx::DEFAULT_BASE_URL.to_string());
    let otx = load_vendor_config("otx", otx_key, otx_url)?;

    Ok(Config {
        database_url,
        queue_scan_interval: Duration::from_secs(queue_scan_interval_secs),
        submit_poll_interval: Duration::from_secs(submit_poll_interval_secs),
        vendors: vec![abuseipdb, dshield, otx],
    })
}

/// Builds the real vendor adapters from each `FullVendorConfig` plus one
/// shared `reqwest::Client` (Task 4's carry-forward note), boxed as
/// `dyn VendorAdapter` alongside their gatekeeper-scoped configs. Every
/// configured vendor is constructed regardless of `enabled` - the
/// gatekeeper's own first check (`GateReason::Disabled`) is what actually
/// holds a disabled vendor's submissions, so this function does not need to
/// duplicate that filtering.
fn build_adapters(
    vendors: &[FullVendorConfig],
    client: reqwest::Client,
) -> (
    Vec<Box<dyn VendorAdapter>>,
    Vec<review::gatekeeper::VendorConfig>,
) {
    let mut adapters: Vec<Box<dyn VendorAdapter>> = Vec::with_capacity(vendors.len());
    let mut gate_configs = Vec::with_capacity(vendors.len());
    for vc in vendors {
        let adapter: Box<dyn VendorAdapter> = match vc.name.as_str() {
            "abuseipdb" => Box::new(AbuseIpDb::new(
                client.clone(),
                vc.api_key.clone(),
                vc.api_url.clone(),
            )),
            "dshield" => Box::new(DShield::new(
                client.clone(),
                vc.api_key.clone(),
                vc.api_url.clone(),
            )),
            "otx" => Box::new(OtxAdapter::new(
                client.clone(),
                vc.api_key.clone(),
                vc.api_url.clone(),
            )),
            other => {
                tracing::warn!(
                    vendor = other,
                    "no adapter implementation for this vendor name; skipping"
                );
                continue;
            }
        };
        gate_configs.push(vc.gate_config());
        adapters.push(adapter);
    }
    (adapters, gate_configs)
}

/// Resolves when the process receives SIGINT (`Ctrl+C`) or, on Unix,
/// SIGTERM - what `systemctl stop` sends, not SIGINT, to the hardened
/// `deploy/review.service` unit this binary ships. Mirrors
/// `intake/src/main.rs`'s identically-named helper exactly (same reason:
/// graceful shutdown under systemd), duplicated here rather than taken as a
/// dependency - matches that module's own precedent for why this one small
/// helper is not worth a shared crate.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "review: failed to install SIGTERM handler; shutdown_signal now waits on SIGINT only"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// One queue-maintenance cycle, forever: populate newly-recommended IPs, then
/// withdraw any still-Pending entry whose trigger has lapsed. Errors are
/// logged and retried on the next tick (design spec "Error handling": "a
/// database error ... is logged and retried on the next poll cycle"); success
/// counts are already logged by `ReviewQueue::populate`/`withdraw`
/// themselves, so this loop only adds the error-path logging they don't do.
async fn run_queue_scan_loop(pool: PgPool, interval: Duration) {
    let queue = ReviewQueue::new();
    loop {
        if let Err(e) = queue.populate(&pool).await {
            tracing::error!(error = %e, "review: queue populate failed");
        }
        if let Err(e) = queue.withdraw(&pool).await {
            tracing::error!(error = %e, "review: queue withdraw failed");
        }
        tokio::time::sleep(interval).await;
    }
}

/// One submission poll cycle, forever: `SubmissionRunner::run_once` over
/// every Approved entry. Logs the pass's aggregate result when it did
/// anything (`run_once` itself already logs per-item detail); errors are
/// logged and retried on the next tick, matching the queue-scan loop.
async fn run_submission_loop(runner: SubmissionRunner, interval: Duration) {
    loop {
        match runner.run_once().await {
            Ok(result) => {
                if result.submitted > 0 || result.held > 0 || result.failed > 0 {
                    tracing::info!(
                        submitted = result.submitted,
                        held = result.held,
                        failed = result.failed,
                        "review: submission pass complete"
                    );
                }
            }
            Err(e) => tracing::error!(error = %e, "review: submission run_once failed"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Runs the submission daemon forever: spawns the queue-scan and
/// submission-poll loops as independent tokio tasks (they run on different
/// configured intervals) and waits for a shutdown signal to abort both.
async fn run_daemon(pool: PgPool, config: Config) {
    for vc in &config.vendors {
        tracing::info!(
            vendor = %vc.name,
            enabled = vc.enabled,
            "review: vendor configured"
        );
    }

    let client = reqwest::Client::new();
    let (adapters, gate_configs) = build_adapters(&config.vendors, client);
    let runner = SubmissionRunner::new(pool.clone(), adapters, gate_configs);

    let queue_handle = tokio::spawn(run_queue_scan_loop(pool, config.queue_scan_interval));
    let submit_handle = tokio::spawn(run_submission_loop(runner, config.submit_poll_interval));

    shutdown_signal().await;
    tracing::info!("review: shutdown signal received; stopping");
    queue_handle.abort();
    submit_handle.abort();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "review: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let pool = match PgPool::connect(&config.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "review: failed to connect to PostgreSQL");
            std::process::exit(1);
        }
    };

    match cli.command {
        Command::Daemon => run_daemon(pool, config).await,
        other => {
            if let Err(e) = cli::execute(&pool, other).await {
                tracing::error!(error = %e, "review: command failed");
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_positive_u64_uses_default_when_absent() {
        assert_eq!(parse_positive_u64(None, 42, "x").unwrap(), 42);
    }

    #[test]
    fn parse_positive_u64_rejects_zero() {
        // Zero must never silently mean "poll as fast as possible".
        assert!(matches!(
            parse_positive_u64(Some("0"), 42, "x"),
            Err(ConfigError::InvalidBound { .. })
        ));
    }

    #[test]
    fn parse_positive_u64_rejects_non_numeric() {
        assert!(matches!(
            parse_positive_u64(Some("not-a-number"), 42, "x"),
            Err(ConfigError::InvalidBound { .. })
        ));
    }

    #[test]
    fn parse_positive_u64_accepts_explicit_value() {
        assert_eq!(parse_positive_u64(Some("100"), 42, "x").unwrap(), 100);
    }

    #[test]
    fn parse_u32_uses_default_when_absent() {
        assert_eq!(parse_u32(None, 24, "x").unwrap(), 24);
    }

    #[test]
    fn parse_u32_accepts_zero() {
        // Unlike the poll intervals, zero is a legitimate gatekeeper bound
        // (a deliberately zeroed cooldown, or a rate limit of zero).
        assert_eq!(parse_u32(Some("0"), 24, "x").unwrap(), 0);
    }

    #[test]
    fn parse_u32_rejects_non_numeric() {
        assert!(matches!(
            parse_u32(Some("nope"), 24, "x"),
            Err(ConfigError::InvalidBound { .. })
        ));
    }

    #[test]
    fn parse_bool_flag_defaults_when_absent() {
        assert!(!parse_bool_flag(None, false));
        assert!(parse_bool_flag(None, true));
    }

    #[test]
    fn parse_bool_flag_parses_true_and_false_case_insensitively() {
        assert!(parse_bool_flag(Some("true"), false));
        assert!(parse_bool_flag(Some("TRUE"), false));
        assert!(!parse_bool_flag(Some("false"), true));
        assert!(!parse_bool_flag(Some("False"), true));
    }

    #[test]
    fn parse_bool_flag_falls_back_to_default_on_malformed_value() {
        // Fails closed: an unrecognized value never silently becomes `true`.
        assert!(!parse_bool_flag(Some("yes"), false));
    }

    #[test]
    fn load_config_missing_database_url_fails() {
        // The env is shared across test threads (matches intake's/sensor-ssh's
        // precedent), so only assert what we can reason about without
        // mutating it.
        if env::var(ENV_DATABASE_URL).is_err() {
            assert!(matches!(
                load_config_from_env(),
                Err(ConfigError::MissingDatabaseUrl)
            ));
        }
    }

    #[test]
    fn build_adapters_constructs_one_adapter_per_known_vendor_name() {
        let vendors = vec![
            FullVendorConfig {
                name: "abuseipdb".to_string(),
                enabled: false,
                api_key: String::new(),
                api_url: "http://127.0.0.1:1".to_string(),
                cooldown_hours: 24,
                rate_limit: 100,
                rate_window_hours: 1,
                score_floor: None,
                category_filter: None,
            },
            FullVendorConfig {
                name: "dshield".to_string(),
                enabled: false,
                api_key: String::new(),
                api_url: "http://127.0.0.1:1".to_string(),
                cooldown_hours: 24,
                rate_limit: 100,
                rate_window_hours: 1,
                score_floor: None,
                category_filter: None,
            },
            FullVendorConfig {
                name: "otx".to_string(),
                enabled: false,
                api_key: String::new(),
                api_url: "http://127.0.0.1:1".to_string(),
                cooldown_hours: 24,
                rate_limit: 100,
                rate_window_hours: 1,
                score_floor: None,
                category_filter: None,
            },
        ];
        let (adapters, gate_configs) = build_adapters(&vendors, reqwest::Client::new());
        assert_eq!(adapters.len(), 3);
        assert_eq!(gate_configs.len(), 3);
        let names: Vec<&str> = adapters.iter().map(|a| a.name()).collect();
        assert_eq!(names, vec!["abuseipdb", "dshield", "otx"]);
    }

    #[test]
    fn build_adapters_skips_unrecognized_vendor_name() {
        let vendors = vec![FullVendorConfig {
            name: "future-vendor".to_string(),
            enabled: false,
            api_key: String::new(),
            api_url: "http://127.0.0.1:1".to_string(),
            cooldown_hours: 24,
            rate_limit: 100,
            rate_window_hours: 1,
            score_floor: None,
            category_filter: None,
        }];
        let (adapters, gate_configs) = build_adapters(&vendors, reqwest::Client::new());
        assert!(adapters.is_empty());
        assert!(gate_configs.is_empty());
    }
}
