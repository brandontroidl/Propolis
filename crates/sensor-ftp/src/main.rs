use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M,
    SHUTDOWN_DRAIN_TIMEOUT, TlsServer, WanResolver, load_server_config, shutdown_signal,
};

const ENV_BIND: &str = "PROPOLIS_FTP_BIND";
/// Optional implicit-FTPS listener (990). Needs both `_TLS_CERT` and `_TLS_KEY`.
const ENV_TLS_BIND: &str = "PROPOLIS_FTP_TLS_BIND";
/// Cert and key paths. TLS is enabled iff BOTH are set; AUTH TLS on `PROPOLIS_FTP_BIND` is honoured
/// only then.
const ENV_TLS_CERT: &str = "PROPOLIS_FTP_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_FTP_TLS_KEY";
const ENV_WAN_MAP: &str = "PROPOLIS_FTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_FTP_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_FTP_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_FTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_FTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_FTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_FTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_FTP_MAX_CONCURRENT";
/// Shared across every sensor binary AND `shipper` on this collector (see sensor-ssh's own
/// `main.rs` for why): must match the shipper's client certificate CommonName.
const ENV_COLLECTOR_ID: &str = "PROPOLIS_COLLECTOR_ID";
/// Pre-rename bare spelling, still read via [`sensor_framework::env_with_legacy`] when
/// `PROPOLIS_COLLECTOR_ID` is unset (see sensor-ssh's own `main.rs` for why).
const ENV_COLLECTOR_ID_LEGACY: &str = "COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_FTP_OUTBOX_DIR";
/// Ceiling, in bytes, on capture bodies buffered in memory across every connection. Defaults to
/// 40% of the unit's 256M `MemoryMax` (see `deploy/sensor-ftp.service`).
const ENV_CAPTURE_MEMORY_BYTES: &str = "PROPOLIS_FTP_CAPTURE_MEMORY_BYTES";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/ftp/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/ftp";
const DEFAULT_COLLECTOR_ID: &str = "local";
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
    InvalidBound {
        field: &'static str,
        value: String,
    },
    InvalidTlsBind(String),
    /// Exactly one of cert/key set, or a TLS bind without both. Names the variables only.
    TlsIncomplete(&'static str),
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
            ConfigError::InvalidTlsBind(s) => write!(f, "invalid {ENV_TLS_BIND}: {s:?}"),
            ConfigError::TlsIncomplete(why) => write!(f, "{why}"),
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    tls_bind: Option<SocketAddr>,
    /// Cert and key paths, present iff TLS is enabled.
    tls_paths: Option<(PathBuf, PathBuf)>,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_memory_bytes: u64,
}

impl std::error::Error for ConfigError {}

/// Resolve the outbox directory: the explicit `PROPOLIS_FTP_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_FTP_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
}

/// Unset or empty counts as not set. Both set enables TLS; exactly one set, or a TLS bind without
/// both, is an error so a half-configured sensor never starts (and never binds a plaintext port
/// the operator believed was protected).
fn tls_paths(
    cert: Option<String>,
    key: Option<String>,
    tls_bind_set: bool,
) -> Result<Option<(PathBuf, PathBuf)>, ConfigError> {
    let set = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    match (set(cert), set(key)) {
        (Some(c), Some(k)) => Ok(Some((PathBuf::from(c), PathBuf::from(k)))),
        (None, None) if tls_bind_set => Err(ConfigError::TlsIncomplete(
            "PROPOLIS_FTP_TLS_BIND is set but PROPOLIS_FTP_TLS_CERT and PROPOLIS_FTP_TLS_KEY are not",
        )),
        (None, None) => Ok(None),
        _ => Err(ConfigError::TlsIncomplete(
            "PROPOLIS_FTP_TLS_CERT and PROPOLIS_FTP_TLS_KEY must be set together",
        )),
    }
}

fn load_config_from_env() -> Result<Config, ConfigError> {
    let bind_raw = env::var(ENV_BIND).map_err(|_| ConfigError::NoBind)?;
    let bind_addr: SocketAddr = bind_raw
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;
    let tls_bind = match env::var(ENV_TLS_BIND) {
        Ok(raw) if !raw.trim().is_empty() => Some(
            raw.trim()
                .parse()
                .map_err(|_| ConfigError::InvalidTlsBind(raw.clone()))?,
        ),
        _ => None,
    };
    let tls_paths = tls_paths(
        env::var(ENV_TLS_CERT).ok(),
        env::var(ENV_TLS_KEY).ok(),
        tls_bind.is_some(),
    )?;
    let wan_map = parse_wan_map(&env::var(ENV_WAN_MAP).unwrap_or_default())?;
    let log_path = env::var(ENV_LOG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_PATH));
    let spool_dir = env::var(ENV_SPOOL_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SPOOL_DIR));
    let collector_id = sensor_framework::env_with_legacy(ENV_COLLECTOR_ID, ENV_COLLECTOR_ID_LEGACY)
        .unwrap_or_else(|| DEFAULT_COLLECTOR_ID.to_string());
    let outbox_dir = resolve_outbox_dir(&spool_dir, env::var(ENV_OUTBOX_DIR).ok());

    Ok(Config {
        bind_addr,
        tls_bind,
        tls_paths,
        wan_map,
        log_path,
        spool_dir,
        collector_id,
        outbox_dir,
        capture_memory_bytes: parse_positive_u64(
            env::var(ENV_CAPTURE_MEMORY_BYTES).ok().as_deref(),
            DEFAULT_CAPTURE_BUDGET_BYTES_256M,
            ENV_CAPTURE_MEMORY_BYTES,
        )?,
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
    let tls_bind = config.tls_bind;
    let wan_map = config.wan_map;
    let log_path = config.log_path;
    let spool_dir = config.spool_dir;
    let bounds = config.bounds;
    let collector_id = config.collector_id;
    let outbox_dir = config.outbox_dir;
    let capture_memory_bytes = config.capture_memory_bytes;

    // Validated and loaded BEFORE any socket is bound, so a bad TLS config never leaves a
    // plaintext listener running.
    let tls = match config.tls_paths {
        None => None,
        Some((cert, key)) => match load_server_config(&cert, &key) {
            Ok(server_config) => Some(TlsServer::from_config(server_config)),
            Err(e) => {
                tracing::error!(error = %e, "sensor-ftp: invalid TLS configuration; refusing to start");
                std::process::exit(1);
            }
        },
    };
    let listeners = match sensor_ftp::plan_listeners(bind_addr, tls_bind, tls) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("sensor-ftp: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    let wan_resolver = Arc::new(WanResolver::new(wan_map));
    let (started, handoff) = match sensor_ftp::start_listeners(
        listeners,
        log_path,
        spool_dir,
        wan_resolver,
        bounds,
        collector_id,
        outbox_dir,
        Arc::new(CaptureMemoryBudget::new(capture_memory_bytes)),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "sensor-ftp: failed to start");
            std::process::exit(1);
        }
    };

    for (bound, _) in &started {
        tracing::info!(local = %bound, "sensor-ftp: listening");
    }
    shutdown_signal().await;
    tracing::info!("sensor-ftp: shutdown signal received; stopping");
    for (_, handle) in &started {
        handle.abort();
    }
    // Queued captures only; a connection cancelled mid-capture never submits (see handoff.rs).
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_defaults_under_the_spool_root() {
        // With no PROPOLIS_FTP_OUTBOX_DIR override, the outbox must sit under the resolved
        // spool dir, which is inside the sensor's systemd ReadWritePaths (unlike the old
        // shared /var/lib/propolis/outbox default).
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, None);
        assert_eq!(outbox_dir, PathBuf::from("/custom/spool/outbox"));
    }

    #[test]
    fn capture_memory_ceiling_defaults_and_rejects_zero_or_garbage() {
        let parse = |raw: Option<&str>| {
            parse_positive_u64(
                raw,
                DEFAULT_CAPTURE_BUDGET_BYTES_256M,
                ENV_CAPTURE_MEMORY_BYTES,
            )
        };
        assert_eq!(parse(None).unwrap(), 107_374_182);
        assert_eq!(parse(Some("5000000")).unwrap(), 5_000_000);
        assert!(parse(Some("0")).is_err());
        assert!(parse(Some("lots")).is_err());
        assert!(parse(Some("-1")).is_err());
    }

    #[test]
    fn tls_is_enabled_only_by_a_complete_pair_and_fails_closed() {
        let some = |s: &str| Some(s.to_string());
        assert!(tls_paths(None, None, false).unwrap().is_none());
        assert!(tls_paths(some(""), some("  "), false).unwrap().is_none());
        assert!(tls_paths(some("/c"), some("/k"), false).unwrap().is_some());
        assert!(tls_paths(some("/c"), some("/k"), true).unwrap().is_some());
        assert!(tls_paths(some("/c"), None, false).is_err());
        assert!(tls_paths(None, some("/k"), false).is_err());
        assert!(tls_paths(some("/c"), some(""), false).is_err());
        assert!(tls_paths(None, None, true).is_err());
    }

    #[test]
    fn explicit_outbox_override_still_wins() {
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, Some("/explicit/outbox".to_string()));
        assert_eq!(outbox_dir, PathBuf::from("/explicit/outbox"));
    }
}
