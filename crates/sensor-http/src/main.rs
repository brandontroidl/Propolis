use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, shutdown_signal};

const ENV_BIND: &str = "PROPOLIS_HTTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_HTTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_HTTP_LOG_PATH";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_HTTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_HTTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_HTTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_HTTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_HTTP_MAX_CONCURRENT";

const ENV_TLS_BIND: &str = "PROPOLIS_HTTP_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_HTTP_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_HTTP_TLS_KEY";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/http/events.jsonl";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
const DEFAULT_MAX_CONCURRENT: u32 = 512;

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    bounds: ConnectionBounds,
    tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, PartialEq)]
struct TlsConfig {
    /// `None` when only the cert and key are set: the pair is still loaded and validated, but no
    /// TLS listener starts, because the fleet inventory derives from explicit `*_BIND` vars.
    bind_addr: Option<SocketAddr>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    NoBind,
    InvalidBind(String),
    InvalidTlsBind(String),
    /// The named cert or key env var was unset or blank while TLS was asked for by the other
    /// path var or by `PROPOLIS_HTTP_TLS_BIND`.
    TlsPathMissing(&'static str),
    InvalidWanMapEntry(String),
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
            ConfigError::InvalidTlsBind(s) => write!(f, "invalid {ENV_TLS_BIND} address {s:?}"),
            ConfigError::TlsPathMissing(var) => write!(
                f,
                "{var} must be set to a PEM file path (TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY})"
            ),
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

/// TLS is enabled iff both the cert and key paths are set (blank counts as unset). Anything
/// less than that while TLS was asked for, by one path var or by a bind, is a refusal: the
/// caller exits rather than serving plaintext where TLS was intended. With no TLS var set at
/// all the sensor behaves exactly as before. The TLS bind has no compiled default.
fn parse_tls(
    bind: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    let path = |raw: Option<&str>| {
        raw.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    let (cert_path, key_path) = (path(cert), path(key));
    let bind_addr = match bind {
        Some(raw) => Some(
            raw.trim()
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::InvalidTlsBind(raw.to_string()))?,
        ),
        None => None,
    };
    match (bind_addr, cert_path, key_path) {
        (None, None, None) => Ok(None),
        (_, None, _) => Err(ConfigError::TlsPathMissing(ENV_TLS_CERT)),
        (_, _, None) => Err(ConfigError::TlsPathMissing(ENV_TLS_KEY)),
        (bind_addr, Some(cert_path), Some(key_path)) => Ok(Some(TlsConfig {
            bind_addr,
            cert_path,
            key_path,
        })),
    }
}

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

    // var_os + lossy: a non-UTF-8 value must fail parsing (refuse), not read as unset and
    // silently disable TLS the way `env::var(..).ok()` would.
    let env_str = |name: &str| env::var_os(name).map(|v| v.to_string_lossy().into_owned());
    let tls = parse_tls(
        env_str(ENV_TLS_BIND).as_deref(),
        env_str(ENV_TLS_CERT).as_deref(),
        env_str(ENV_TLS_KEY).as_deref(),
    )?;

    Ok(Config {
        bind_addr,
        wan_map,
        log_path,
        tls,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-http: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Load the cert and key before binding anything (plaintext included): a misconfigured TLS
    // pair must not leave a half-configured sensor serving.
    let tls_server = match &config.tls {
        Some(t) => match sensor_framework::load_server_config(&t.cert_path, &t.key_path) {
            Ok(server_config) => match t.bind_addr {
                Some(addr) => Some((addr, TlsServer::from_config(server_config))),
                None => {
                    tracing::warn!(
                        "sensor-http: {ENV_TLS_CERT} and {ENV_TLS_KEY} loaded but {ENV_TLS_BIND} is unset; no TLS listener started"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::error!(
                    cert = %t.cert_path.display(), key = %t.key_path.display(), error = %e,
                    "sensor-http: TLS configured but cert/key unusable; refusing to start"
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    let (bound, handle) = match sensor_http::start_test_server(
        config.bind_addr,
        config.log_path.clone(),
        wan_resolver.clone(),
        config.bounds.clone(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(addr = %config.bind_addr, error = %e, "sensor-http: failed to start server");
            std::process::exit(1);
        }
    };
    tracing::info!(local = %bound, "sensor-http: listening");

    let tls_handle = match tls_server {
        Some((addr, server)) => {
            match sensor_http::start_test_server_tls(
                addr,
                config.log_path,
                wan_resolver,
                config.bounds,
                server,
            )
            .await
            {
                Ok((bound, tls_handle)) => {
                    tracing::info!(local = %bound, "sensor-http: listening (tls)");
                    Some(tls_handle)
                }
                Err(e) => {
                    handle.abort();
                    tracing::error!(addr = %addr, error = %e, "sensor-http: failed to start tls server");
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    shutdown_signal().await;
    tracing::info!("sensor-http: shutdown signal received; stopping");
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
        let map = parse_wan_map("10.0.0.1=198.51.100.4").unwrap();
        assert_eq!(map.len(), 1);
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
        let result = load_config_from_env();
        if env::var(ENV_BIND).is_err() {
            assert!(matches!(result, Err(ConfigError::NoBind)));
        }
    }

    fn tls_cfg(bind: Option<&str>) -> TlsConfig {
        TlsConfig {
            bind_addr: bind.map(|b| b.parse().unwrap()),
            cert_path: "/etc/propolis/tls/http.crt".into(),
            key_path: "/etc/propolis/tls/http.key".into(),
        }
    }

    const CRT: Option<&str> = Some("/etc/propolis/tls/http.crt");
    const KEY: Option<&str> = Some("/etc/propolis/tls/http.key");

    #[test]
    fn parse_tls_unset_is_none() {
        assert_eq!(parse_tls(None, None, None), Ok(None));
        assert_eq!(parse_tls(None, Some("  "), Some("")), Ok(None));
    }

    #[test]
    fn parse_tls_full_is_some() {
        assert_eq!(
            parse_tls(Some("127.0.0.1:8443"), CRT, KEY),
            Ok(Some(tls_cfg(Some("127.0.0.1:8443"))))
        );
    }

    #[test]
    fn parse_tls_both_paths_without_a_bind_has_no_listener_address() {
        assert_eq!(parse_tls(None, CRT, KEY), Ok(Some(tls_cfg(None))));
    }

    #[test]
    fn parse_tls_exactly_one_path_is_refused() {
        assert_eq!(
            parse_tls(None, None, KEY),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
        assert_eq!(
            parse_tls(None, CRT, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
        assert_eq!(
            parse_tls(Some("0.0.0.0:443"), CRT, Some("   ")),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
    }

    #[test]
    fn parse_tls_bind_without_both_paths_is_refused() {
        assert_eq!(
            parse_tls(Some("0.0.0.0:443"), None, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }

    #[test]
    fn parse_tls_rejects_bad_or_empty_bind() {
        assert!(matches!(
            parse_tls(Some("nonsense"), CRT, KEY),
            Err(ConfigError::InvalidTlsBind(_))
        ));
        assert!(matches!(
            parse_tls(Some(""), CRT, KEY),
            Err(ConfigError::InvalidTlsBind(_))
        ));
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
}
