//! Unified configuration for the Propolis daemon: one `PropolisConfig` parsed from environment
//! variables at startup. Fails fast on any missing required value or malformed bound rather than
//! silently substituting a default that could disable a guard.

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;

use review::vendor::{FullVendorConfig, abuseipdb, dshield, otx};

// ---- defaults ----

const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_CURSOR_DIR: &str = "/var/lib/propolis/cursors";
const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_QUEUE_SCAN_INTERVAL_SECS: u64 = 60;
const DEFAULT_SUBMIT_POLL_INTERVAL_SECS: u64 = 30;
const DEFAULT_FEED_OUTPUT_DIR: &str = "/var/lib/propolis/feed/current";
const DEFAULT_FEED_BUILD_INTERVAL_SECS: u64 = 900;
const DEFAULT_AGGRESSIVE_TTL_HOURS: u64 = 24;
const DEFAULT_STANDARD_TTL_HOURS: u64 = 48;
const DEFAULT_CONSOLE_BIND: &str = "127.0.0.1:8080";
const DEFAULT_COOLDOWN_HOURS: u32 = 24;
const DEFAULT_RATE_LIMIT: u32 = 100;
const DEFAULT_RATE_WINDOW_HOURS: u32 = 1;

/// One sensor log entry: a sensor's name (for logging/metrics) and the absolute path to its
/// NDJSON log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorLogConfig {
    pub name: String,
    pub log_path: PathBuf,
}

/// Consolidated configuration for every Propolis subsystem.
#[derive(Debug)]
pub struct PropolisConfig {
    // Database
    pub database_url: String,
    pub db_max_connections: u32,
    // Intake
    pub sensor_logs: Vec<SensorLogConfig>,
    pub cursor_dir: PathBuf,
    pub poll_interval: Duration,
    // Review
    pub review_enabled: bool,
    pub queue_scan_interval: Duration,
    pub submit_poll_interval: Duration,
    pub vendors: Vec<FullVendorConfig>,
    // Feed
    pub feed_enabled: bool,
    pub feed_output_dir: PathBuf,
    pub feed_build_interval: Duration,
    pub feed_aggressive_ttl: Duration,
    pub feed_standard_ttl: Duration,
    pub feed_allowlist: Vec<IpNet>,
    pub feed_delist: Vec<IpAddr>,
    // Console
    pub console_bind: SocketAddr,
    pub console_password: String,
    pub console_session_secret: [u8; 32],
    // VirusTotal
    pub vt_enabled: bool,
    pub vt_api_key: String,
    pub vt_upload_unknown: bool,
    pub vt_scan_interval_secs: u64,
}

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing(field) => write!(f, "{field} must be set"),
            ConfigError::Invalid {
                field,
                value,
                reason,
            } => {
                write!(f, "{field}: {reason}, got {value:?}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn require_env(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_positive_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(default),
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::Invalid {
        field: name,
        value: raw.clone(),
        reason: "must be a positive integer",
    })?;
    if value == 0 {
        return Err(ConfigError::Invalid {
            field: name,
            value: raw,
            reason: "must be a positive integer (zero never means unlimited)",
        });
    }
    Ok(value)
}

fn parse_u32(name: &str, default: u32) -> Result<u32, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(default),
    };
    raw.parse().map_err(|_| ConfigError::Invalid {
        field: "vendor bound",
        value: raw,
        reason: "must be a non-negative integer",
    })
}

fn parse_bool_flag(name: &str, default: bool) -> bool {
    match env::var(name).ok().as_deref() {
        None => default,
        Some(s) if s.eq_ignore_ascii_case("true") => true,
        Some(s) if s.eq_ignore_ascii_case("false") => false,
        Some(_) => default,
    }
}

fn parse_sensor_logs(raw: &str) -> Result<Vec<SensorLogConfig>, ConfigError> {
    let logs: Vec<SensorLogConfig> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let mut parts = entry.splitn(2, ':');
            let name = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            if name.is_empty() || path.is_empty() {
                return Err(ConfigError::Invalid {
                    field: "PROPOLIS_SENSOR_LOGS",
                    value: entry.to_string(),
                    reason: "expected name:path",
                });
            }
            Ok(SensorLogConfig {
                name: name.to_string(),
                log_path: PathBuf::from(path),
            })
        })
        .collect::<Result<_, _>>()?;
    if logs.is_empty() {
        return Err(ConfigError::Missing("PROPOLIS_SENSOR_LOGS"));
    }
    Ok(logs)
}

fn parse_cidr_list(raw: &str) -> Result<Vec<IpNet>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>().map_err(|_| ConfigError::Invalid {
                field: "PROPOLIS_FEED_ALLOWLIST",
                value: s.to_string(),
                reason: "not a valid CIDR",
            })
        })
        .collect()
}

fn parse_ip_list(raw: &str) -> Result<Vec<IpAddr>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpAddr>().map_err(|_| ConfigError::Invalid {
                field: "PROPOLIS_FEED_DELIST",
                value: s.to_string(),
                reason: "not a valid IP address",
            })
        })
        .collect()
}

fn load_session_secret() -> Result<[u8; 32], ConfigError> {
    let raw = match env::var("PROPOLIS_CONSOLE_SESSION_SECRET") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            use rand::RngExt;
            return Ok(rand::rng().random::<[u8; 32]>());
        }
    };
    let bytes = hex::decode(&raw).map_err(|_| ConfigError::Invalid {
        field: "PROPOLIS_CONSOLE_SESSION_SECRET",
        value: raw.clone(),
        reason: "must be exactly 64 hex characters (32 bytes)",
    })?;
    bytes.try_into().map_err(|_| ConfigError::Invalid {
        field: "PROPOLIS_CONSOLE_SESSION_SECRET",
        value: raw,
        reason: "must be exactly 64 hex characters (32 bytes)",
    })
}

fn load_vendor_config(
    name: &str,
    api_key: String,
    api_url: String,
) -> Result<FullVendorConfig, ConfigError> {
    let prefix = format!("PROPOLIS_VENDOR_{}", name.to_uppercase());
    let enabled_field = format!("{prefix}_ENABLED");
    let mut enabled = parse_bool_flag(&enabled_field, false);
    if enabled && api_key.is_empty() {
        tracing::warn!(
            vendor = name,
            "enabled but no API key configured; treating as disabled (fail-closed)"
        );
        enabled = false;
    }

    let cooldown_field = format!("{prefix}_COOLDOWN_HOURS");
    let cooldown_hours = parse_u32(&cooldown_field, DEFAULT_COOLDOWN_HOURS)?;
    let rate_limit_field = format!("{prefix}_RATE_LIMIT");
    let rate_limit = parse_u32(&rate_limit_field, DEFAULT_RATE_LIMIT)?;
    let rate_window_field = format!("{prefix}_RATE_WINDOW_HOURS");
    let rate_window_hours = parse_u32(&rate_window_field, DEFAULT_RATE_WINDOW_HOURS)?;

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

/// Loads and validates the unified configuration from environment variables. Fails fast on any
/// missing required value or malformed bound.
pub fn load_config() -> Result<PropolisConfig, ConfigError> {
    let database_url = require_env("DATABASE_URL")?;

    let db_max_connections = parse_positive_u64(
        "PROPOLIS_DB_MAX_CONNECTIONS",
        DEFAULT_DB_MAX_CONNECTIONS as u64,
    )? as u32;

    let sensor_logs = parse_sensor_logs(&env::var("PROPOLIS_SENSOR_LOGS").unwrap_or_default())?;
    let cursor_dir = env::var("PROPOLIS_CURSOR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CURSOR_DIR));
    let poll_interval_ms =
        parse_positive_u64("PROPOLIS_POLL_INTERVAL_MS", DEFAULT_POLL_INTERVAL_MS)?;

    let review_enabled = parse_bool_flag("PROPOLIS_REVIEW_ENABLED", true);
    let queue_scan_interval_secs = parse_positive_u64(
        "PROPOLIS_QUEUE_SCAN_INTERVAL_SECS",
        DEFAULT_QUEUE_SCAN_INTERVAL_SECS,
    )?;
    let submit_poll_interval_secs = parse_positive_u64(
        "PROPOLIS_SUBMIT_POLL_INTERVAL_SECS",
        DEFAULT_SUBMIT_POLL_INTERVAL_SECS,
    )?;

    let abuseipdb_key = env::var("PROPOLIS_VENDOR_ABUSEIPDB_KEY").unwrap_or_default();
    let abuseipdb_url = env::var("PROPOLIS_VENDOR_ABUSEIPDB_URL")
        .unwrap_or_else(|_| abuseipdb::DEFAULT_BASE_URL.to_string());
    let abuseipdb = load_vendor_config("abuseipdb", abuseipdb_key, abuseipdb_url)?;

    let dshield_key = env::var("PROPOLIS_VENDOR_DSHIELD_KEY").unwrap_or_default();
    let dshield_user = env::var("PROPOLIS_VENDOR_DSHIELD_USER")
        .ok()
        .filter(|s| !s.is_empty());
    let dshield_key = match dshield_user {
        Some(user) if !dshield_key.is_empty() => format!("{user}:{dshield_key}"),
        _ => dshield_key,
    };
    let dshield_url = env::var("PROPOLIS_VENDOR_DSHIELD_URL")
        .unwrap_or_else(|_| dshield::DEFAULT_BASE_URL.to_string());
    let dshield = load_vendor_config("dshield", dshield_key, dshield_url)?;

    let otx_key = env::var("PROPOLIS_VENDOR_OTX_KEY").unwrap_or_default();
    let otx_url =
        env::var("PROPOLIS_VENDOR_OTX_URL").unwrap_or_else(|_| otx::DEFAULT_BASE_URL.to_string());
    let otx = load_vendor_config("otx", otx_key, otx_url)?;

    let feed_enabled = parse_bool_flag("PROPOLIS_FEED_ENABLED", true);
    let feed_output_dir = env::var("PROPOLIS_FEED_OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_FEED_OUTPUT_DIR));
    let feed_build_interval_secs = parse_positive_u64(
        "PROPOLIS_FEED_BUILD_INTERVAL_SECS",
        DEFAULT_FEED_BUILD_INTERVAL_SECS,
    )?;
    let feed_aggressive_ttl_hours = parse_positive_u64(
        "PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS",
        DEFAULT_AGGRESSIVE_TTL_HOURS,
    )?;
    let feed_standard_ttl_hours = parse_positive_u64(
        "PROPOLIS_FEED_STANDARD_TTL_HOURS",
        DEFAULT_STANDARD_TTL_HOURS,
    )?;
    let feed_allowlist = parse_cidr_list(&env::var("PROPOLIS_FEED_ALLOWLIST").unwrap_or_default())?;
    let feed_delist = parse_ip_list(&env::var("PROPOLIS_FEED_DELIST").unwrap_or_default())?;

    let bind_raw =
        env::var("PROPOLIS_CONSOLE_BIND").unwrap_or_else(|_| DEFAULT_CONSOLE_BIND.to_string());
    let console_bind = bind_raw
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::Invalid {
            field: "PROPOLIS_CONSOLE_BIND",
            value: bind_raw,
            reason: "not a valid ip:port address",
        })?;
    let console_password = require_env("PROPOLIS_CONSOLE_PASSWORD")?;
    let console_session_secret = load_session_secret()?;

    let vt_api_key = env::var("PROPOLIS_VT_KEY").unwrap_or_default();
    let vt_enabled = parse_bool_flag("PROPOLIS_VT_ENABLED", false) && !vt_api_key.is_empty();
    let vt_upload_unknown = parse_bool_flag("PROPOLIS_VT_UPLOAD", false);
    let vt_scan_interval_secs = parse_u32("PROPOLIS_VT_SCAN_INTERVAL_SECS", 300)? as u64;

    Ok(PropolisConfig {
        database_url,
        db_max_connections,
        sensor_logs,
        cursor_dir,
        poll_interval: Duration::from_millis(poll_interval_ms),
        review_enabled,
        queue_scan_interval: Duration::from_secs(queue_scan_interval_secs),
        submit_poll_interval: Duration::from_secs(submit_poll_interval_secs),
        vendors: vec![abuseipdb, dshield, otx],
        feed_enabled,
        feed_output_dir,
        feed_build_interval: Duration::from_secs(feed_build_interval_secs),
        feed_aggressive_ttl: Duration::from_secs(feed_aggressive_ttl_hours * 3600),
        feed_standard_ttl: Duration::from_secs(feed_standard_ttl_hours * 3600),
        feed_allowlist,
        feed_delist,
        console_bind,
        console_password,
        console_session_secret,
        vt_enabled,
        vt_api_key,
        vt_upload_unknown,
        vt_scan_interval_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sensor_logs_accepts_comma_separated_pairs() {
        let logs = parse_sensor_logs(
            "catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl",
        )
        .unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].name, "catchall");
        assert_eq!(logs[1].name, "ssh");
    }

    #[test]
    fn parse_sensor_logs_rejects_empty() {
        assert!(parse_sensor_logs("").is_err());
        assert!(parse_sensor_logs("   ").is_err());
    }

    #[test]
    fn parse_sensor_logs_rejects_entry_without_colon() {
        assert!(parse_sensor_logs("not-a-pair").is_err());
    }
}
