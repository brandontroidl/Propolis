use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sensor_framework::session_memory::{self, AccountingAlloc, DEFAULT_POOL_BYTES_256M};
use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, Env, EnvError,
    SHUTDOWN_DRAIN_TIMEOUT, TlsServer, WanResolver, shutdown_signal,
};

/// Every allocation is charged to the session it was made in (`session_memory`), so a PUBLISH
/// body waiting for the rest of its packet counts against the session pool.
#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

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

#[derive(Debug, PartialEq)]
enum ConfigError {
    NoBind,
    /// A TLS env var was unset or blank while the TLS pair is incomplete or a TLS bind is set.
    TlsVarMissing(&'static str),
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses (a malformed
    /// address, a zero or unparseable bound, a bad WAN map entry); never read as unset.
    Env(EnvError),
}

impl From<EnvError> for ConfigError {
    fn from(e: EnvError) -> Self {
        ConfigError::Env(e)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NoBind => write!(f, "{ENV_BIND} must be set"),
            ConfigError::TlsVarMissing(var) => write!(
                f,
                "{var} must be set: TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY}, and {ENV_TLS_BIND} requires them"
            ),
            ConfigError::Env(e) => write!(f, "{e}"),
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

/// `None` only when no TLS variable is set at all. Anything else must be a complete configuration:
/// exactly one of cert/key, or a bind without the pair, is an error so the caller refuses to start
/// rather than serving plaintext where TLS was asked for. Inputs come from `sensor_framework::Env`,
/// already trimmed with blank read as unset and the bind already parsed, so an empty
/// `PROPOLIS_MQTT_TLS_BIND=` is "off", as `deploy/fleet-listeners.sh` reads it.
fn parse_tls(
    bind_addr: Option<SocketAddr>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    let (cert_path, key_path) = (cert.map(PathBuf::from), key.map(PathBuf::from));
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Ok(Some(TlsConfig {
            bind_addr,
            cert_path,
            key_path,
        })),
        (Some(_), None) => Err(ConfigError::TlsVarMissing(ENV_TLS_KEY)),
        (None, Some(_)) => Err(ConfigError::TlsVarMissing(ENV_TLS_CERT)),
        (None, None) if bind_addr.is_some() => Err(ConfigError::TlsVarMissing(ENV_TLS_CERT)),
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

fn load_config(env: &Env) -> Result<Config, ConfigError> {
    let spool_dir = env.path(ENV_SPOOL_DIR, DEFAULT_SPOOL_DIR)?;
    let outbox_dir = resolve_outbox_dir(&spool_dir, env.string(ENV_OUTBOX_DIR)?);
    Ok(Config {
        tls: parse_tls(
            env.socket_addr(ENV_TLS_BIND)?,
            env.string(ENV_TLS_CERT)?.as_deref(),
            env.string(ENV_TLS_KEY)?.as_deref(),
        )?,
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
        spool_dir,
        collector_id: sensor_framework::env_with_legacy(ENV_COLLECTOR_ID, ENV_COLLECTOR_ID_LEGACY)?
            .unwrap_or_else(|| DEFAULT_COLLECTOR_ID.to_string()),
        outbox_dir,
        capture_memory_bytes: env
            .positive_u64(ENV_CAPTURE_MEMORY_BYTES, DEFAULT_CAPTURE_BUDGET_BYTES_256M)?,
        bounds: ConnectionBounds {
            read_timeout: env.duration_ms(ENV_READ_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS)?,
            idle_timeout: env.duration_ms(ENV_IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS)?,
            max_duration: env.duration_secs(ENV_MAX_DURATION_SECS, DEFAULT_MAX_DURATION_SECS)?,
            max_captured_bytes: env
                .positive_u64(ENV_MAX_CAPTURED_BYTES, DEFAULT_MAX_CAPTURED_BYTES)?,
            max_concurrent: env
                .positive_u32(ENV_MAX_CONCURRENT, DEFAULT_MAX_CONCURRENT)?
                .get(),
        },
    })
}

#[tokio::main]
async fn main() {
    sensor_framework::init_logging();

    let config = match load_config(&Env::process()) {
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

    // Every session either listener admits must fit in the session memory pool at its floor; each
    // listener has its own `max_concurrent` permits.
    let listeners = if matches!(tls_server, Some((Some(_), _))) {
        2
    } else {
        1
    };
    let sessions = config.bounds.max_concurrent.saturating_mul(listeners);
    if let Err(e) = session_memory::configure(DEFAULT_POOL_BYTES_256M, sessions) {
        tracing::error!(
            error = %e,
            max_concurrent = config.bounds.max_concurrent,
            listeners,
            "sensor-mqtt: {ENV_MAX_CONCURRENT} times the listener count does not fit the session \
             memory pool; refusing to start"
        );
        std::process::exit(1);
    }
    tokio::spawn(session_memory::watchdog());

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
    handoff.start_stats("mqtt");

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
    // Cuts live connections (their captures are recorded as truncated), then drains the queue.
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:1883");
    const TLS_BIND: Option<SocketAddr> = Some(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        8883,
    ));

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "1883")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:1883".parse().unwrap());
        assert_eq!(c.tls, None);
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.spool_dir, PathBuf::from(DEFAULT_SPOOL_DIR));
        assert_eq!(
            c.outbox_dir,
            PathBuf::from("/var/spool/propolis/mqtt/outbox")
        );
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(600));
        assert_eq!(c.bounds.max_captured_bytes, 1_000_000);
        assert_eq!(c.bounds.max_concurrent, 256);
        // 40% of the unit's 256M MemoryMax.
        assert_eq!(c.capture_memory_bytes, 107_374_182);
    }

    #[test]
    fn a_zero_or_garbage_bound_is_an_error_not_a_disabled_guard() {
        for var in [
            ENV_READ_TIMEOUT_MS,
            ENV_IDLE_TIMEOUT_MS,
            ENV_MAX_DURATION_SECS,
            ENV_MAX_CAPTURED_BYTES,
            ENV_MAX_CONCURRENT,
            ENV_CAPTURE_MEMORY_BYTES,
        ] {
            for bad in ["0", "-1", "ten"] {
                match load_config(&Env::from_table(&[BIND, (var, bad)])) {
                    Err(ConfigError::Env(EnvError::Invalid { var: v, value, .. })) => {
                        assert_eq!((v.as_str(), value.as_str()), (var, bad));
                    }
                    other => panic!("{var}={bad}: {other:?}"),
                }
            }
        }
        assert!(matches!(
            load_config(&Env::from_table(&[
                BIND,
                (ENV_MAX_CONCURRENT, "4294967296")
            ])),
            Err(ConfigError::Env(EnvError::TooLarge { .. }))
        ));
        for (var, bad) in [
            (ENV_WAN_MAP, "10.0.0.5"),
            (ENV_WAN_MAP, "10.0.0.5=nope"),
            (ENV_WAN_MAP, "nope=203.0.113.9"),
            (ENV_TLS_BIND, "nonsense"),
        ] {
            assert!(
                matches!(
                    load_config(&Env::from_table(&[BIND, (var, bad)])),
                    Err(ConfigError::Env(EnvError::Invalid { .. }))
                ),
                "{var}={bad}"
            );
        }
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
    fn parse_tls_absent_is_none() {
        // Blank values never reach here: the env reader reads them as unset.
        assert_eq!(parse_tls(None, None, None).unwrap(), None);
    }

    #[test]
    fn parse_tls_full_is_some() {
        let got = parse_tls(
            TLS_BIND,
            Some("/etc/propolis/tls/mqtt.crt"),
            Some("/etc/propolis/tls/mqtt.key"),
        )
        .unwrap();
        assert_eq!(
            got,
            Some(TlsConfig {
                bind_addr: TLS_BIND,
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
        for bind in [None, TLS_BIND] {
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
            parse_tls(TLS_BIND, None, None),
            Err(ConfigError::TlsVarMissing(_))
        ));
    }
}
