//! sensor-redis: the Redis honeypot sensor binary. Binds one TCP address, parses RESP commands
//! (both inline and multi-bulk array forms), and responds with canned data while capturing
//! credentials and suspicious commands as indicators - see
//! `internal/design/08-remaining-sensors.md`'s "sensor-redis" section for the protocol flow this
//! binary composes and `handler.rs` for the session logic.
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! convention established by `sensor-telnet`/`sensor-ssh`/`sensor-catchall`'s own `main.rs`. Every
//! value is validated at startup and the process refuses to start on a malformed one rather than
//! silently substituting a default that could disable the bound it names.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, EnvError, WanResolver, shutdown_signal, strict_env_var};

const ENV_BIND: &str = "PROPOLIS_REDIS_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_REDIS_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_REDIS_LOG_PATH";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_REDIS_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_REDIS_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_REDIS_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_REDIS_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_REDIS_MAX_CONCURRENT";
const ENV_TLS_BIND: &str = "PROPOLIS_REDIS_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_REDIS_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_REDIS_TLS_KEY";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/redis/events.jsonl";
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
    bounds: ConnectionBounds,
    tls: Option<TlsConfig>,
}

/// A second, implicit-TLS listener (`rediss://`) beside the plaintext one.
#[derive(Debug, Clone, PartialEq)]
struct TlsConfig {
    /// `None` when a cert and key are configured without a TLS bind: validated, never listened on.
    bind_addr: Option<SocketAddr>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    InvalidTlsBind(String),
    /// The named cert or key env var was unset or blank while the other half of the TLS
    /// configuration was present.
    TlsPathMissing(&'static str),
    /// An env var held bytes that are not valid UTF-8; never read as unset.
    Env(EnvError),
    /// `PROPOLIS_REDIS_BIND` was absent or unparseable.
    NoBind,
    InvalidBind(String),
    InvalidWanMapEntry(String),
    /// A bound value failed to parse, or parsed to 0. Zero is always rejected rather than
    /// silently treated as "unlimited" - matches `sensor-catchall`'s own convention.
    InvalidBound {
        field: &'static str,
        value: String,
    },
}

impl From<EnvError> for ConfigError {
    fn from(e: EnvError) -> Self {
        ConfigError::Env(e)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::InvalidTlsBind(s) => write!(f, "invalid {ENV_TLS_BIND} address {s:?}"),
            ConfigError::TlsPathMissing(var) => write!(
                f,
                "{var} must be set to a PEM file path (TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY})"
            ),
            ConfigError::Env(e) => write!(f, "{e}"),
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

/// TLS is enabled iff both the cert and key paths are set. `None` only when nothing TLS-related
/// is configured; a bind without the pair, or exactly one of the pair, is an error so the caller
/// refuses to start rather than serve plaintext where TLS was asked for. A pair without a bind
/// parses (the caller still validates the files) but yields no listener. Inputs come from
/// `sensor_framework::tls_env_var`, already trimmed with blank read as unset.
fn parse_tls(
    bind: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    let (cert_path, key_path) = (cert.map(PathBuf::from), key.map(PathBuf::from));
    if bind.is_none() && cert_path.is_none() && key_path.is_none() {
        return Ok(None);
    }
    // TLS is enabled iff both paths are set; a half-configured pair is reported as the missing half.
    let cert_path = cert_path.ok_or(ConfigError::TlsPathMissing(ENV_TLS_CERT))?;
    let key_path = key_path.ok_or(ConfigError::TlsPathMissing(ENV_TLS_KEY))?;
    // The bind is never defaulted: the fleet inventory derives from the *_BIND vars.
    let bind_addr = bind
        .map(|raw| {
            raw.parse::<SocketAddr>()
                .map_err(|_| ConfigError::InvalidTlsBind(raw.to_string()))
        })
        .transpose()?;
    Ok(Some(TlsConfig {
        bind_addr,
        cert_path,
        key_path,
    }))
}

/// Load and validate configuration from environment variables. Fails closed: any missing bind
/// address, malformed entry, or zero-valued bound is rejected here rather than silently
/// substituted with a default that could disable the bound it names.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let bind_raw = strict_env_var(ENV_BIND)?.ok_or(ConfigError::NoBind)?;
    let bind_addr: SocketAddr = bind_raw
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;

    let wan_map = parse_wan_map(&strict_env_var(ENV_WAN_MAP)?.unwrap_or_default())?;
    let log_path = strict_env_var(ENV_LOG_PATH)?
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_PATH));

    let read_timeout_ms = parse_positive_u64(
        strict_env_var(ENV_READ_TIMEOUT_MS)?.as_deref(),
        DEFAULT_READ_TIMEOUT_MS,
        ENV_READ_TIMEOUT_MS,
    )?;
    let idle_timeout_ms = parse_positive_u64(
        strict_env_var(ENV_IDLE_TIMEOUT_MS)?.as_deref(),
        DEFAULT_IDLE_TIMEOUT_MS,
        ENV_IDLE_TIMEOUT_MS,
    )?;
    let max_duration_secs = parse_positive_u64(
        strict_env_var(ENV_MAX_DURATION_SECS)?.as_deref(),
        DEFAULT_MAX_DURATION_SECS,
        ENV_MAX_DURATION_SECS,
    )?;
    let max_captured_bytes = parse_positive_u64(
        strict_env_var(ENV_MAX_CAPTURED_BYTES)?.as_deref(),
        DEFAULT_MAX_CAPTURED_BYTES,
        ENV_MAX_CAPTURED_BYTES,
    )?;
    let max_concurrent = parse_positive_u32(
        strict_env_var(ENV_MAX_CONCURRENT)?.as_deref(),
        DEFAULT_MAX_CONCURRENT,
        ENV_MAX_CONCURRENT,
    )?;

    let tls = parse_tls(
        strict_env_var(ENV_TLS_BIND)?.as_deref(),
        strict_env_var(ENV_TLS_CERT)?.as_deref(),
        strict_env_var(ENV_TLS_KEY)?.as_deref(),
    )?;

    Ok(Config {
        bind_addr,
        wan_map,
        log_path,
        tls,
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
    sensor_framework::init_logging();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-redis: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Load the cert and key before binding anything, plaintext included: a TLS misconfiguration
    // must not leave a plaintext listener up.
    let tls_server = match &config.tls {
        Some(t) => match sensor_framework::load_server_config(&t.cert_path, &t.key_path) {
            Ok(server_config) => {
                let server = sensor_framework::TlsServer::from_config(server_config);
                match t.bind_addr {
                    Some(addr) => Some((addr, server)),
                    None => {
                        tracing::warn!(
                            "sensor-redis: {ENV_TLS_CERT} and {ENV_TLS_KEY} are valid but \
                             {ENV_TLS_BIND} is not set; no TLS listener started"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    cert = %t.cert_path.display(), key = %t.key_path.display(), error = %e,
                    "sensor-redis: TLS configured but cert/key unusable; refusing to start"
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    let (bound, handle) = match sensor_redis::start_test_server(
        config.bind_addr,
        config.log_path.clone(),
        wan_resolver.clone(),
        config.bounds.clone(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let e = sensor_framework::listener_start_error(config.bind_addr, e);
            tracing::error!("sensor-redis: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "sensor-redis: listening");

    let tls_handle = match tls_server {
        Some((addr, server)) => {
            match sensor_redis::start_test_server_tls(
                addr,
                config.log_path,
                wan_resolver,
                config.bounds,
                server,
            )
            .await
            {
                Ok((bound, handle)) => {
                    tracing::info!(local = %bound, "sensor-redis: listening (tls)");
                    Some(handle)
                }
                Err(e) => {
                    handle.abort();
                    let e = sensor_framework::listener_start_error(addr, e);
                    tracing::error!("sensor-redis: {e}; refusing to start");
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    shutdown_signal().await;
    tracing::info!("sensor-redis: shutdown signal received; stopping");
    handle.abort();
    if let Some(h) = tls_handle {
        h.abort();
    }
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
        if std::env::var(ENV_BIND).is_err() {
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

    const CERT: &str = "/etc/propolis/tls/redis.crt";
    const KEY: &str = "/etc/propolis/tls/redis.key";

    #[test]
    fn parse_tls_nothing_configured_is_none() {
        // Blank values never reach here: tls_env_var reads them as unset.
        assert_eq!(parse_tls(None, None, None), Ok(None));
    }

    #[test]
    fn parse_tls_full_is_some() {
        assert_eq!(
            parse_tls(Some("0.0.0.0:6380"), Some(CERT), Some(KEY)),
            Ok(Some(TlsConfig {
                bind_addr: Some("0.0.0.0:6380".parse().unwrap()),
                cert_path: CERT.into(),
                key_path: KEY.into(),
            }))
        );
    }

    #[test]
    fn parse_tls_bind_without_cert_is_refused() {
        assert_eq!(
            parse_tls(Some("0.0.0.0:6380"), None, Some(KEY)),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
        assert_eq!(
            parse_tls(Some("0.0.0.0:6380"), None, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }

    #[test]
    fn parse_tls_bind_without_key_is_refused() {
        assert_eq!(
            parse_tls(Some("0.0.0.0:6380"), Some(CERT), None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
    }

    #[test]
    fn parse_tls_exactly_one_of_cert_and_key_without_bind_is_refused() {
        assert_eq!(
            parse_tls(None, Some(CERT), None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
        assert_eq!(
            parse_tls(None, None, Some(KEY)),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }

    #[test]
    fn parse_tls_pair_without_bind_has_no_listener() {
        assert_eq!(
            parse_tls(None, Some(CERT), Some(KEY)),
            Ok(Some(TlsConfig {
                bind_addr: None,
                cert_path: CERT.into(),
                key_path: KEY.into(),
            }))
        );
    }

    #[test]
    fn parse_tls_rejects_a_bad_bind() {
        assert!(matches!(
            parse_tls(Some("nonsense"), Some(CERT), Some(KEY)),
            Err(ConfigError::InvalidTlsBind(_))
        ));
    }
}
