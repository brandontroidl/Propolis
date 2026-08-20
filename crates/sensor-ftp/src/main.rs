use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver, shutdown_signal};

const ENV_BIND: &str = "PROPOLIS_FTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_FTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_FTP_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_FTP_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_FTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_FTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_FTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_FTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_FTP_MAX_CONCURRENT";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/ftp/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/ftp";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

#[derive(Debug)]
enum ConfigError {
    NoBind,
    InvalidBind(String),
    InvalidWanMapEntry(String),
    InvalidBound { field: &'static str, value: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NoBind => write!(f, "{ENV_BIND} must be set"),
            ConfigError::InvalidBind(s) => write!(f, "invalid {ENV_BIND}: {s:?}"),
            ConfigError::InvalidWanMapEntry(s) => write!(f, "invalid {ENV_WAN_MAP} entry: {s:?}"),
            ConfigError::InvalidBound { field, value } => {
                write!(f, "{field} must be positive, got {value:?}")
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
}

impl std::error::Error for ConfigError {}

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

    Ok(Config {
        bind_addr,
        wan_map,
        log_path,
        spool_dir,
        bounds: ConnectionBounds {
            read_timeout: Duration::from_millis(parse_positive_u64(
                env::var(ENV_READ_TIMEOUT_MS).ok().as_deref(),
                DEFAULT_READ_TIMEOUT_MS,
                ENV_READ_TIMEOUT_MS,
            )?),
            idle_timeout: Duration::from_millis(parse_positive_u64(
                env::var(ENV_IDLE_TIMEOUT_MS).ok().as_deref(),
                DEFAULT_IDLE_TIMEOUT_MS,
                ENV_IDLE_TIMEOUT_MS,
            )?),
            max_duration: Duration::from_secs(parse_positive_u64(
                env::var(ENV_MAX_DURATION_SECS).ok().as_deref(),
                DEFAULT_MAX_DURATION_SECS,
                ENV_MAX_DURATION_SECS,
            )?),
            max_captured_bytes: parse_positive_u64(
                env::var(ENV_MAX_CAPTURED_BYTES).ok().as_deref(),
                DEFAULT_MAX_CAPTURED_BYTES,
                ENV_MAX_CAPTURED_BYTES,
            )?,
            max_concurrent: parse_positive_u32(
                env::var(ENV_MAX_CONCURRENT).ok().as_deref(),
                DEFAULT_MAX_CONCURRENT,
                ENV_MAX_CONCURRENT,
            )?,
        },
    })
}

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

fn parse_positive_u64(
    raw: Option<&str>,
    default: u64,
    field: &'static str,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else { return Ok(default) };
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

fn parse_positive_u32(
    raw: Option<&str>,
    default: u32,
    field: &'static str,
) -> Result<u32, ConfigError> {
    let Some(raw) = raw else { return Ok(default) };
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-ftp: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let bind_addr = config.bind_addr;
    let wan_map = config.wan_map;
    let log_path = config.log_path;
    let spool_dir = config.spool_dir;
    let bounds = config.bounds;

    let wan_resolver = Arc::new(WanResolver::new(wan_map));
    let (bound, handle) =
        match sensor_ftp::start_test_server(bind_addr, log_path, spool_dir, wan_resolver, bounds)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(addr = %bind_addr, error = %e, "sensor-ftp: failed to start");
                std::process::exit(1);
            }
        };

    tracing::info!(local = %bound, "sensor-ftp: listening");
    shutdown_signal().await;
    tracing::info!("sensor-ftp: shutdown signal received; stopping");
    handle.abort();
}
