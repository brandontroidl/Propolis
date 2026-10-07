use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M,
    SHUTDOWN_DRAIN_TIMEOUT, TlsServer, WanResolver, shutdown_signal,
};

const ENV_BIND: &str = "PROPOLIS_MQTT_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_MQTT_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_MQTT_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_MQTT_SPOOL_DIR";
/// Shared across every sensor binary AND `shipper` on this collector (see sensor-ssh's own
/// `main.rs` for why): must match the shipper's client certificate CommonName.
const ENV_COLLECTOR_ID: &str = "PROPOLIS_COLLECTOR_ID";
/// Pre-rename bare spelling, still read via [`sensor_framework::env_with_legacy`] when
/// `PROPOLIS_COLLECTOR_ID` is unset (see sensor-ssh's own `main.rs` for why).
const ENV_COLLECTOR_ID_LEGACY: &str = "COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_MQTT_OUTBOX_DIR";
/// Ceiling, in bytes, on capture bodies buffered in memory across every connection. Defaults to
/// 40% of the unit's 256M `MemoryMax` (see `deploy/sensor-mqtt.service`).
const ENV_CAPTURE_MEMORY_BYTES: &str = "PROPOLIS_MQTT_CAPTURE_MEMORY_BYTES";
/// MQTTS listener address. TLS is enabled iff BOTH `PROPOLIS_MQTT_TLS_CERT` and
/// `PROPOLIS_MQTT_TLS_KEY` are set; the deploy env file supplies `0.0.0.0:8883` for the bind.
const ENV_TLS_BIND: &str = "PROPOLIS_MQTT_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_MQTT_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_MQTT_TLS_KEY";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_MQTT_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_MQTT_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_MQTT_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_MQTT_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_MQTT_MAX_CONCURRENT";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/mqtt/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/mqtt";
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
    /// A TLS env var was unset or blank while the TLS pair is incomplete or a TLS bind is set.
    TlsVarMissing(&'static str),
    /// The named TLS env var was set to a value that is not valid UTF-8.
    TlsVarNotUtf8(&'static str),
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
            ConfigError::TlsVarMissing(var) => write!(
                f,
                "{var} must be set: TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY}, and {ENV_TLS_BIND} requires them"
            ),
            ConfigError::TlsVarNotUtf8(var) => write!(f, "{var} is set but is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The TLS pair (both paths always present) and the MQTTS bind, if one is configured.
#[derive(Debug, Clone, PartialEq)]
struct TlsConfig {
    bind_addr: Option<SocketAddr>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

/// `None` only when no TLS variable is set at all. Anything else must be a complete, parseable
/// configuration: exactly one of cert/key, or a bind without the pair, is an error so the caller
/// refuses to start rather than serving plaintext where TLS was asked for. Inputs come from
/// `sensor_framework::tls_env_var`, already trimmed with blank read as unset, so an empty
/// `PROPOLIS_MQTT_TLS_BIND=` is "off", as `deploy/fleet-listeners.sh` reads it.
fn parse_tls(
    bind: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    let (cert_path, key_path) = (cert.map(PathBuf::from), key.map(PathBuf::from));
    let bind_addr = bind
        .map(|raw| {
            raw.parse::<SocketAddr>()
                .map_err(|_| ConfigError::InvalidTlsBind(raw.to_string()))
        })
        .transpose()?;
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Ok(Some(TlsConfig {
            bind_addr,
            cert_path,
            key_path,
        })),
        (Some(_), None) => Err(ConfigError::TlsVarMissing(ENV_TLS_KEY)),
        (None, Some(_)) => Err(ConfigError::TlsVarMissing(ENV_TLS_CERT)),
        (None, None) if bind.is_some() => Err(ConfigError::TlsVarMissing(ENV_TLS_CERT)),
        (None, None) => Ok(None),
    }
}

#[derive(Debug, Clone)]
struct Config {
    tls: Option<TlsConfig>,
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_memory_bytes: u64,
}

/// Resolve the outbox directory: the explicit `PROPOLIS_MQTT_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_MQTT_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
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
    let spool_dir = env::var(ENV_SPOOL_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SPOOL_DIR));
    let collector_id = sensor_framework::env_with_legacy(ENV_COLLECTOR_ID, ENV_COLLECTOR_ID_LEGACY)
        .unwrap_or_else(|| DEFAULT_COLLECTOR_ID.to_string());
    let outbox_dir = resolve_outbox_dir(&spool_dir, env::var(ENV_OUTBOX_DIR).ok());
    let tls_var = |name: &'static str| {
        sensor_framework::tls_env_var(name).map_err(|_| ConfigError::TlsVarNotUtf8(name))
    };
    let tls = parse_tls(
        tls_var(ENV_TLS_BIND)?.as_deref(),
        tls_var(ENV_TLS_CERT)?.as_deref(),
        tls_var(ENV_TLS_KEY)?.as_deref(),
    )?;

    Ok(Config {
        tls,
        bind_addr,
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
    sensor_framework::init_logging();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-mqtt: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let bind_addr = config.bind_addr;

    // Before ANY listener binds (plaintext included): an unusable cert/key pair must not leave a
    // plaintext sensor running where the operator asked for TLS.
    let tls_server = match &config.tls {
        Some(t) => match sensor_framework::load_server_config(&t.cert_path, &t.key_path) {
            Ok(server_config) => Some((t.bind_addr, TlsServer::from_config(server_config))),
            Err(e) => {
                tracing::error!(
                    cert = %t.cert_path.display(), key = %t.key_path.display(), error = %e,
                    "sensor-mqtt: TLS configured but cert/key unusable; refusing to start"
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));
    let handoff = match sensor_mqtt::new_capture_handoff(
        config.log_path.clone(),
        config.spool_dir,
        config.collector_id,
        config.outbox_dir,
        Arc::new(CaptureMemoryBudget::new(config.capture_memory_bytes)),
    ) {
        Ok(handoff) => handoff,
        Err(e) => {
            tracing::error!(error = %e, "sensor-mqtt: failed to start");
            std::process::exit(1);
        }
    };
    let (bound, handle) = match sensor_mqtt::start_plain_listener(
        bind_addr,
        config.log_path.clone(),
        wan_resolver.clone(),
        config.bounds.clone(),
        handoff.clone(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let e = sensor_framework::listener_start_error(bind_addr, e);
            tracing::error!("sensor-mqtt: {e}; refusing to start");
            std::process::exit(1);
        }
    };
    tracing::info!(local = %bound, "sensor-mqtt: listening");

    let tls_handle = match tls_server {
        Some((Some(tls_addr), server)) => {
            match sensor_mqtt::start_tls_listener(
                tls_addr,
                config.log_path,
                wan_resolver,
                config.bounds,
                handoff.clone(),
                server,
            )
            .await
            {
                Ok((tls_bound, tls_handle)) => {
                    tracing::info!(local = %tls_bound, "sensor-mqtt: listening (tls)");
                    Some(tls_handle)
                }
                Err(e) => {
                    handle.abort();
                    let e = sensor_framework::listener_start_error(tls_addr, e);
                    tracing::error!("sensor-mqtt: {e}; refusing to start");
                    std::process::exit(1);
                }
            }
        }
        Some((None, _)) => {
            tracing::warn!(
                "sensor-mqtt: TLS cert is configured but no TLS bind uses it ({ENV_TLS_BIND} is unset); no TLS listener started"
            );
            None
        }
        None => None,
    };

    shutdown_signal().await;
    tracing::info!("sensor-mqtt: shutdown signal received; stopping");
    handle.abort();
    if let Some(tls_handle) = tls_handle {
        tls_handle.abort();
    }
    // Queued captures only; a connection cancelled mid-packet never submits (see handoff.rs).
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_default_and_reject_zero_or_garbage() {
        assert_eq!(parse_positive_u64(None, 7, "f").unwrap(), 7);
        assert_eq!(parse_positive_u64(Some("42"), 7, "f").unwrap(), 42);
        assert!(parse_positive_u64(Some("0"), 7, "f").is_err());
        assert!(parse_positive_u64(Some("lots"), 7, "f").is_err());
        assert!(parse_positive_u64(Some("-1"), 7, "f").is_err());
        assert_eq!(parse_positive_u32(None, 9, "f").unwrap(), 9);
        assert!(parse_positive_u32(Some("0"), 9, "f").is_err());
        assert!(parse_positive_u32(Some("4294967296"), 9, "f").is_err());
    }

    #[test]
    fn outbox_defaults_under_the_spool_root_and_an_explicit_override_wins() {
        let spool_dir = PathBuf::from("/custom/spool");
        assert_eq!(
            resolve_outbox_dir(&spool_dir, None),
            PathBuf::from("/custom/spool/outbox")
        );
        assert_eq!(
            resolve_outbox_dir(&spool_dir, Some("/explicit/outbox".to_string())),
            PathBuf::from("/explicit/outbox")
        );
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
    fn parse_tls_absent_is_none() {
        // Blank values never reach here: tls_env_var reads them as unset.
        assert_eq!(parse_tls(None, None, None).unwrap(), None);
    }

    #[test]
    fn parse_tls_full_is_some() {
        let got = parse_tls(
            Some("0.0.0.0:8883"),
            Some("/etc/propolis/tls/mqtt.crt"),
            Some("/etc/propolis/tls/mqtt.key"),
        )
        .unwrap();
        assert_eq!(
            got,
            Some(TlsConfig {
                bind_addr: Some("0.0.0.0:8883".parse().unwrap()),
                cert_path: "/etc/propolis/tls/mqtt.crt".into(),
                key_path: "/etc/propolis/tls/mqtt.key".into(),
            })
        );
    }

    #[test]
    fn parse_tls_pair_without_bind_keeps_the_pair_for_validation() {
        let got = parse_tls(None, Some("/c"), Some("/k")).unwrap().unwrap();
        assert_eq!(got.bind_addr, None);
    }

    #[test]
    fn parse_tls_exactly_one_of_cert_and_key_is_refused() {
        for bind in [None, Some("0.0.0.0:8883")] {
            assert!(matches!(
                parse_tls(bind, Some("/c"), None),
                Err(ConfigError::TlsVarMissing(ENV_TLS_KEY))
            ));
            assert!(matches!(
                parse_tls(bind, None, Some("/k")),
                Err(ConfigError::TlsVarMissing(ENV_TLS_CERT))
            ));
        }
    }

    #[test]
    fn parse_tls_bind_without_the_pair_is_refused() {
        assert!(matches!(
            parse_tls(Some("0.0.0.0:8883"), None, None),
            Err(ConfigError::TlsVarMissing(_))
        ));
    }

    #[test]
    fn parse_tls_rejects_a_bad_bind() {
        assert!(matches!(
            parse_tls(Some("nonsense"), Some("/c"), Some("/k")),
            Err(ConfigError::InvalidTlsBind(_))
        ));
    }

    #[test]
    fn wan_map_is_strict() {
        let map = parse_wan_map("10.0.0.5=203.0.113.9, 10.0.0.6=203.0.113.10").unwrap();
        assert_eq!(map.len(), 2);
        assert!(parse_wan_map("").unwrap().is_empty());
        assert!(parse_wan_map("10.0.0.5").is_err());
        assert!(parse_wan_map("10.0.0.5=nope").is_err());
        assert!(parse_wan_map("nope=203.0.113.9").is_err());
    }
}
