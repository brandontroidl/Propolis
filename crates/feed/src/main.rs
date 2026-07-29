//! feed: the binary entry point for sub-project 5's blocklist feed. Runs a periodic build loop -
//! build a `FeedSnapshot` from `ip_score`, publish it - on `PROPOLIS_FEED_BUILD_INTERVAL_SECS`,
//! matching the per-concern poll-loop pattern `intake`/`review`'s own `main.rs` already establish.
//! See `internal/design/05-blocklist-feed.md`'s "Configuration".
//!
//! Configuration is environment variables, matching `intake`/`review`/`sensor-catchall`/
//! `sensor-ssh`'s established convention: every value is validated at startup and the process
//! refuses to start on a malformed one rather than silently substituting a default that could
//! disable a bound. See the `ENV_*` constants and `load_config_from_env` below.

use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use sqlx::PgPool;

use feed::{ExclusionEngine, FeedBuilder, FeedConfig, Publisher};

const ENV_DATABASE_URL: &str = "DATABASE_URL";
const ENV_OUTPUT_DIR: &str = "PROPOLIS_FEED_OUTPUT_DIR";
const ENV_BUILD_INTERVAL_SECS: &str = "PROPOLIS_FEED_BUILD_INTERVAL_SECS";
const ENV_AGGRESSIVE_TTL_HOURS: &str = "PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS";
const ENV_STANDARD_TTL_HOURS: &str = "PROPOLIS_FEED_STANDARD_TTL_HOURS";
const ENV_ALLOWLIST: &str = "PROPOLIS_FEED_ALLOWLIST";
const ENV_DELIST: &str = "PROPOLIS_FEED_DELIST";

// `/var/lib/propolis/feed` is this service's own dedicated writable root (granted via
// `ReadWritePaths` in `deploy/feed.service`, never the shared `/var/lib/propolis`); `current` is
// the actual published directory `Publisher::publish` atomically swaps. See
// `crates/feed/src/publisher.rs`'s module doc comment for why the parent of the published
// directory - not just the directory itself - must be writable.
const DEFAULT_OUTPUT_DIR: &str = "/var/lib/propolis/feed/current";
const DEFAULT_BUILD_INTERVAL_SECS: u64 = 900;
const DEFAULT_AGGRESSIVE_TTL_HOURS: u64 = 24;
const DEFAULT_STANDARD_TTL_HOURS: u64 = 48;

#[derive(Debug)]
struct Config {
    database_url: String,
    output_dir: PathBuf,
    build_interval: Duration,
    aggressive_ttl_hours: u64,
    standard_ttl_hours: u64,
    allowlist: Vec<IpNet>,
    delist: Vec<IpAddr>,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `DATABASE_URL` was absent or empty.
    MissingDatabaseUrl,
    /// A bound value failed to parse as a positive integer, or parsed to 0. Zero is always
    /// rejected rather than silently treated as "build as fast as possible" / "never expires".
    InvalidBound { field: &'static str, value: String },
    /// A `PROPOLIS_FEED_ALLOWLIST` entry was not a valid CIDR.
    InvalidCidr { field: &'static str, value: String },
    /// A `PROPOLIS_FEED_DELIST` entry was not a valid IP address.
    InvalidIp { field: &'static str, value: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingDatabaseUrl => write!(
                f,
                "{ENV_DATABASE_URL} must be set to a PostgreSQL connection string"
            ),
            ConfigError::InvalidBound { field, value } => write!(
                f,
                "{field} must be a positive integer, got {value:?} (zero never means \"as fast \
                 as possible\")"
            ),
            ConfigError::InvalidCidr { field, value } => write!(
                f,
                "{field} entry {value:?} is not a valid CIDR (e.g. \"203.0.113.0/24\" or \
                 \"9.9.9.9/32\" - a bare address without a prefix length is rejected)"
            ),
            ConfigError::InvalidIp { field, value } => {
                write!(f, "{field} entry {value:?} is not a valid IP address")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses an optional positive `u64` bound: `None` (the env var was unset) falls back to
/// `default`; present-but-zero or present-but-unparseable are both rejected. Mirrors
/// `intake`/`review`'s own `parse_positive_u64`.
fn parse_positive_u64(
    raw: Option<&str>,
    default: u64,
    field: &'static str,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::InvalidBound {
        field,
        value: raw.to_string(),
    })?;
    if value == 0 {
        return Err(ConfigError::InvalidBound {
            field,
            value: raw.to_string(),
        });
    }
    Ok(value)
}

/// Parses a comma-separated CIDR list (`PROPOLIS_FEED_ALLOWLIST`). An absent or blank-only env
/// var yields an empty list - no operator exemptions beyond the hardcoded reserved ranges, the
/// safe default. Each entry must carry an explicit prefix length: `ExclusionEngine` takes `IpNet`,
/// never a bare `IpAddr`, matching this crate's own test fixtures
/// (`crates/feed/tests/exclusion_test.rs` writes a single host as `"9.9.9.9/32"`, never bare).
fn parse_cidr_list(raw: &str, field: &'static str) -> Result<Vec<IpNet>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>().map_err(|_| ConfigError::InvalidCidr {
                field,
                value: s.to_string(),
            })
        })
        .collect()
}

/// Parses a comma-separated IP list (`PROPOLIS_FEED_DELIST`). An absent or blank-only env var
/// yields an empty list - nothing explicitly delisted, the safe default.
fn parse_ip_list(raw: &str, field: &'static str) -> Result<Vec<IpAddr>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpAddr>().map_err(|_| ConfigError::InvalidIp {
                field,
                value: s.to_string(),
            })
        })
        .collect()
}

/// Loads and validates configuration from environment variables. Fails closed: a missing
/// `DATABASE_URL`, a zero-valued bound, or a malformed allowlist/delist entry is rejected here
/// rather than silently substituted or dropped.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let database_url = env::var(ENV_DATABASE_URL)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::MissingDatabaseUrl)?;
    let output_dir = env::var(ENV_OUTPUT_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_OUTPUT_DIR));
    let build_interval_secs = parse_positive_u64(
        env::var(ENV_BUILD_INTERVAL_SECS).ok().as_deref(),
        DEFAULT_BUILD_INTERVAL_SECS,
        ENV_BUILD_INTERVAL_SECS,
    )?;
    let aggressive_ttl_hours = parse_positive_u64(
        env::var(ENV_AGGRESSIVE_TTL_HOURS).ok().as_deref(),
        DEFAULT_AGGRESSIVE_TTL_HOURS,
        ENV_AGGRESSIVE_TTL_HOURS,
    )?;
    let standard_ttl_hours = parse_positive_u64(
        env::var(ENV_STANDARD_TTL_HOURS).ok().as_deref(),
        DEFAULT_STANDARD_TTL_HOURS,
        ENV_STANDARD_TTL_HOURS,
    )?;
    let allowlist = parse_cidr_list(&env::var(ENV_ALLOWLIST).unwrap_or_default(), ENV_ALLOWLIST)?;
    let delist = parse_ip_list(&env::var(ENV_DELIST).unwrap_or_default(), ENV_DELIST)?;

    Ok(Config {
        database_url,
        output_dir,
        build_interval: Duration::from_secs(build_interval_secs),
        aggressive_ttl_hours,
        standard_ttl_hours,
        allowlist,
        delist,
    })
}

/// Resolves when the process receives SIGINT (`Ctrl+C`) or, on Unix, SIGTERM - what `systemctl
/// stop` sends to the hardened `deploy/feed.service` unit this binary ships. Duplicated from
/// `intake`/`review`'s own `shutdown_signal` rather than shared, for the same reason `intake`'s own
/// doc comment gives: pulling in a whole other crate for one signal-handling helper is out of
/// proportion.
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
                    "feed: failed to install SIGTERM handler; shutdown_signal now waits on SIGINT only"
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

/// One build-and-publish cycle. Errors at either stage are logged and swallowed here, never
/// propagated to crash the loop: a failed build or publish this cycle leaves the previously
/// published feed in place and simply tries again next interval, matching the design's "Error
/// handling" - "A database error during the build query fails the entire build. No partial feed is
/// published" / "A file write error fails the entire publish. The previous feed version stays in
/// place."
async fn run_build_cycle(
    pool: &PgPool,
    exclusions: &ExclusionEngine,
    feed_config: &FeedConfig,
    output_dir: &Path,
) {
    let snapshot = match FeedBuilder::build(pool, exclusions, feed_config).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            tracing::error!(error = %e, "feed: build failed; no feed published this cycle");
            return;
        }
    };

    let aggressive = snapshot.aggressive.len();
    let standard = snapshot.standard.len();

    match Publisher::publish(&snapshot, output_dir, exclusions, feed_config) {
        Ok(()) => {
            tracing::info!(aggressive, standard, "feed: build published");
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "feed: publish failed; the previous feed version stays in place"
            );
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "feed: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let pool = match PgPool::connect(&config.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "feed: failed to connect to PostgreSQL");
            std::process::exit(1);
        }
    };

    let exclusions = ExclusionEngine::new(config.allowlist.clone(), config.delist.clone());
    let feed_config = FeedConfig {
        aggressive_ttl: chrono::Duration::hours(config.aggressive_ttl_hours as i64),
        standard_ttl: chrono::Duration::hours(config.standard_ttl_hours as i64),
    };

    tracing::info!(
        output_dir = %config.output_dir.display(),
        build_interval_secs = config.build_interval.as_secs(),
        aggressive_ttl_hours = config.aggressive_ttl_hours,
        standard_ttl_hours = config.standard_ttl_hours,
        allowlist_entries = config.allowlist.len(),
        delist_entries = config.delist.len(),
        "feed: starting periodic build loop"
    );

    let build_loop = async {
        loop {
            run_build_cycle(&pool, &exclusions, &feed_config, &config.output_dir).await;
            tokio::time::sleep(config.build_interval).await;
        }
    };

    tokio::select! {
        _ = build_loop => {}
        _ = shutdown_signal() => {
            tracing::info!("feed: shutdown signal received; stopping");
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
    fn parse_cidr_list_empty_string_yields_empty_vec() {
        assert_eq!(parse_cidr_list("", "x").unwrap(), Vec::new());
        assert_eq!(parse_cidr_list("   ", "x").unwrap(), Vec::new());
    }

    #[test]
    fn parse_cidr_list_accepts_comma_separated_cidrs_and_trims_whitespace() {
        let list = parse_cidr_list(" 10.0.0.0/8 , 9.9.9.9/32 ", "x").unwrap();
        assert_eq!(
            list,
            vec![
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
                "9.9.9.9/32".parse::<IpNet>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_cidr_list_rejects_a_bare_ip_without_prefix_length() {
        assert!(matches!(
            parse_cidr_list("9.9.9.9", "x"),
            Err(ConfigError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn parse_ip_list_empty_string_yields_empty_vec() {
        assert_eq!(parse_ip_list("", "x").unwrap(), Vec::<IpAddr>::new());
    }

    #[test]
    fn parse_ip_list_accepts_comma_separated_ips() {
        let list = parse_ip_list("1.2.3.4,5.6.7.8", "x").unwrap();
        assert_eq!(
            list,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn parse_ip_list_rejects_a_cidr_entry() {
        // Delist is host addresses only - a "/32" suffix is not a valid IpAddr.
        assert!(matches!(
            parse_ip_list("9.9.9.9/32", "x"),
            Err(ConfigError::InvalidIp { .. })
        ));
    }

    #[test]
    fn load_config_missing_database_url_fails() {
        // The env is shared across test threads (matches intake's/sensor-ssh's own precedent for
        // this exact test), so only assert what we can reason about without mutating it.
        if env::var(ENV_DATABASE_URL).is_err() {
            assert!(matches!(
                load_config_from_env(),
                Err(ConfigError::MissingDatabaseUrl)
            ));
        }
    }
}
