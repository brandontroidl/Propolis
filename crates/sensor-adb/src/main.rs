//! sensor-adb: the ADB (Android Debug Bridge) honeypot sensor binary. Binds one TCP address
//! (conventionally 5555), completes the `CNXN` handshake with a fake device banner, then serves
//! `shell:`/`shell:<command>` via the shared fake shell and captures `sync:` pushes to the
//! quarantine spool - see `internal/design/08-remaining-sensors.md`'s "sensor-adb" section for
//! the protocol flow this binary composes and `handler.rs` for the session logic.
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! convention established by `sensor-telnet`/`sensor-redis`/`sensor-ssh`'s own `main.rs`. Every
//! value is validated at startup and the process refuses to start on a malformed one rather than
//! silently substituting a default that could disable the bound it names.

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver, shutdown_signal};

const ENV_BIND: &str = "PROPOLIS_ADB_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_ADB_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_ADB_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_ADB_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_ADB_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_ADB_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_ADB_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_ADB_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_ADB_MAX_CONCURRENT";
/// Unprefixed and shared across every sensor binary on this collector (see sensor-ssh's own
/// `main.rs` for why): must match the shipper's `PROPOLIS_SHIPPER_COLLECTOR_ID` cert CommonName.
const ENV_COLLECTOR_ID: &str = "COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_ADB_OUTBOX_DIR";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/adb/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/adb";
const DEFAULT_COLLECTOR_ID: &str = "local";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `PROPOLIS_ADB_BIND` was absent or unparseable.
    NoBind,
    InvalidBind(String),
    InvalidWanMapEntry(String),
    /// A bound value failed to parse, or parsed to 0. Zero is always rejected rather than
    /// silently treated as "unlimited" - matches `sensor-telnet`/`sensor-catchall`'s convention.
    InvalidBound {
        field: &'static str,
        value: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NoBind => {
                write!(f, "{ENV_BIND} must be set to a single ip:port bind address")
            }
            ConfigError::InvalidBind(s) => write!(f, "invalid {ENV_BIND} address {s:?}"),
            ConfigError::InvalidWanMapEntry(s) => write!(
                f,
                "invalid {ENV_WAN_MAP} entry {s:?}, expected local_ip=wan_ip"
            ),
            ConfigError::InvalidBound { field, value } => write!(
                f,
                "{field} must be a positive integer, got {value:?} (zero never means unlimited)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse a comma-separated `local_ip=wan_ip` list. An empty or absent input is a valid, empty
/// map - the no-WAN-binding case documented in the wire contract.
fn parse_wan_map(raw: &str) -> Result<HashMap<IpAddr, IpAddr>, ConfigError> {
    let mut map = HashMap::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (local, wan) = entry
            .split_once('=')
            .ok_or_else(|| ConfigError::InvalidWanMapEntry(entry.to_string()))?;
        let local: IpAddr = local
            .trim()
            .parse()
            .map_err(|_| ConfigError::InvalidWanMapEntry(entry.to_string()))?;
        let wan: IpAddr = wan
            .trim()
            .parse()
            .map_err(|_| ConfigError::InvalidWanMapEntry(entry.to_string()))?;
        map.insert(local, wan);
    }
    Ok(map)
}

/// Parse an optional positive `u64` bound: `None` (the env var was unset) falls back to
/// `default`; present-but-zero or present-but-unparseable are both rejected.
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

/// `u32` counterpart of [`parse_positive_u64`] (for `max_concurrent`), same rules.
fn parse_positive_u32(
    raw: Option<&str>,
    default: u32,
    field: &'static str,
) -> Result<u32, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let value: u32 = raw.parse().map_err(|_| ConfigError::InvalidBound {
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

/// Resolve the outbox directory: the explicit `PROPOLIS_ADB_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_ADB_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
}

/// Load and validate configuration from environment variables. Fails closed: any missing bind
/// address, malformed entry, or zero-valued bound is rejected here rather than silently
/// substituted with a default that could disable the bound it names.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let bind_raw = env::var(ENV_BIND).map_err(|_| ConfigError::NoBind)?;
    let bind_addr: SocketAddr = bind_raw
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;

    let wan_map = parse_wan_map(&env::var(ENV_WAN_MAP).unwrap_or_default())?;
    let log_path = env::var(ENV_LOG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_PATH));
    let spool_dir = env::var(ENV_SPOOL_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SPOOL_DIR));
    let collector_id =
        env::var(ENV_COLLECTOR_ID).unwrap_or_else(|_| DEFAULT_COLLECTOR_ID.to_string());
    let outbox_dir = resolve_outbox_dir(&spool_dir, env::var(ENV_OUTBOX_DIR).ok());

    let read_timeout_ms = parse_positive_u64(
        env::var(ENV_READ_TIMEOUT_MS).ok().as_deref(),
        DEFAULT_READ_TIMEOUT_MS,
        ENV_READ_TIMEOUT_MS,
    )?;
    let idle_timeout_ms = parse_positive_u64(
        env::var(ENV_IDLE_TIMEOUT_MS).ok().as_deref(),
        DEFAULT_IDLE_TIMEOUT_MS,
        ENV_IDLE_TIMEOUT_MS,
    )?;
    let max_duration_secs = parse_positive_u64(
        env::var(ENV_MAX_DURATION_SECS).ok().as_deref(),
        DEFAULT_MAX_DURATION_SECS,
        ENV_MAX_DURATION_SECS,
    )?;
    let max_captured_bytes = parse_positive_u64(
        env::var(ENV_MAX_CAPTURED_BYTES).ok().as_deref(),
        DEFAULT_MAX_CAPTURED_BYTES,
        ENV_MAX_CAPTURED_BYTES,
    )?;
    let max_concurrent = parse_positive_u32(
        env::var(ENV_MAX_CONCURRENT).ok().as_deref(),
        DEFAULT_MAX_CONCURRENT,
        ENV_MAX_CONCURRENT,
    )?;

    Ok(Config {
        bind_addr,
        wan_map,
        log_path,
        spool_dir,
        collector_id,
        outbox_dir,
        bounds: ConnectionBounds {
            read_timeout: Duration::from_millis(read_timeout_ms),
            idle_timeout: Duration::from_millis(idle_timeout_ms),
            max_duration: Duration::from_secs(max_duration_secs),
            max_captured_bytes,
            max_concurrent,
        },
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-adb: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    let (bound, handle) = match sensor_adb::start_test_server(
        config.bind_addr,
        config.log_path,
        config.spool_dir,
        wan_resolver,
        config.bounds,
        config.collector_id,
        config.outbox_dir,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(
                addr = %config.bind_addr,
                error = %e,
                "sensor-adb: failed to start server"
            );
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "sensor-adb: listening");

    shutdown_signal().await;
    tracing::info!("sensor-adb: shutdown signal received; stopping");
    handle.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wan_map_accepts_entries() {
        let map = parse_wan_map("10.0.0.1=198.51.100.4,10.0.0.2=198.51.100.5").unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            Some(&"198.51.100.4".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn parse_wan_map_empty_is_valid() {
        assert!(parse_wan_map("").unwrap().is_empty());
    }

    #[test]
    fn parse_wan_map_rejects_malformed() {
        assert!(matches!(
            parse_wan_map("not-valid"),
            Err(ConfigError::InvalidWanMapEntry(_))
        ));
    }

    #[test]
    fn load_config_missing_bind_fails() {
        // The env is shared across test threads, so only test what we can reason about without
        // mutating it: the error variant for a missing bind address.
        let result = load_config_from_env();
        if env::var(ENV_BIND).is_err() {
            assert!(matches!(result, Err(ConfigError::NoBind)));
        }
    }

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
    fn parse_positive_u32_rejects_zero() {
        assert!(matches!(
            parse_positive_u32(Some("0"), 1, "x"),
            Err(ConfigError::InvalidBound { .. })
        ));
    }

    #[test]
    fn parse_positive_u32_accepts_explicit_value() {
        assert_eq!(parse_positive_u32(Some("7"), 1, "x").unwrap(), 7);
    }

    #[test]
    fn outbox_defaults_under_the_spool_root() {
        // With no PROPOLIS_ADB_OUTBOX_DIR override, the outbox must sit under the resolved
        // spool dir, which is inside the sensor's systemd ReadWritePaths (unlike the old
        // shared /var/lib/propolis/outbox default).
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, None);
        assert_eq!(outbox_dir, PathBuf::from("/custom/spool/outbox"));
    }

    #[test]
    fn explicit_outbox_override_still_wins() {
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, Some("/explicit/outbox".to_string()));
        assert_eq!(outbox_dir, PathBuf::from("/explicit/outbox"));
    }
}
