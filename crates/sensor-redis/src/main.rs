//! sensor-redis: the Redis honeypot sensor binary. Binds one TCP address, parses RESP commands
//! (both inline and multi-bulk array forms), and responds with canned data while capturing
//! credentials and suspicious commands as indicators - see
//! `internal/design/08-remaining-sensors.md`'s "sensor-redis" section for the protocol flow this
//! binary composes and `handler.rs` for the session logic.
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! convention established by `sensor-telnet`/`sensor-ssh`/`sensor-catchall`'s own `main.rs`. Every
//! value is read through `sensor_framework::Env`, validated at startup, and the process refuses to
//! start on a malformed one rather than silently substituting a default that could disable the
//! bound it names.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, Env, EnvError, WanResolver, shutdown_signal,
};

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
    /// The named cert or key env var was unset or blank while the other half of the TLS
    /// configuration was present.
    TlsPathMissing(&'static str),
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses (a malformed
    /// address, a zero or unparseable bound, a bad WAN map entry); never read as unset.
    Env(EnvError),
    /// `PROPOLIS_REDIS_BIND` was absent.
    NoBind,
}

impl From<EnvError> for ConfigError {
    fn from(e: EnvError) -> Self {
        ConfigError::Env(e)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::TlsPathMissing(var) => write!(
                f,
                "{var} must be set to a PEM file path (TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY})"
            ),
            ConfigError::Env(e) => write!(f, "{e}"),
            ConfigError::NoBind => {
                write!(f, "{ENV_BIND} must be set to a single ip:port bind address")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// TLS is enabled iff both the cert and key paths are set. `None` only when nothing TLS-related
/// is configured; a bind without the pair, or exactly one of the pair, is an error so the caller
/// refuses to start rather than serve plaintext where TLS was asked for. A pair without a bind
/// parses (the caller still validates the files) but yields no listener. Inputs come from
/// `sensor_framework::Env`, already trimmed with blank read as unset and the bind already parsed.
fn parse_tls(
    bind_addr: Option<SocketAddr>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    let (cert_path, key_path) = (cert.map(PathBuf::from), key.map(PathBuf::from));
    if bind_addr.is_none() && cert_path.is_none() && key_path.is_none() {
        return Ok(None);
    }
    // TLS is enabled iff both paths are set; a half-configured pair is reported as the missing half.
    let cert_path = cert_path.ok_or(ConfigError::TlsPathMissing(ENV_TLS_CERT))?;
    let key_path = key_path.ok_or(ConfigError::TlsPathMissing(ENV_TLS_KEY))?;
    // The bind is never defaulted: the fleet inventory derives from the *_BIND vars.
    Ok(Some(TlsConfig {
        bind_addr,
        cert_path,
        key_path,
    }))
}

/// Load and validate configuration. Fails closed: any missing bind address, malformed entry, or
/// zero-valued bound is rejected here rather than silently substituted with a default that could
/// disable the bound it names.
fn load_config(env: &Env) -> Result<Config, ConfigError> {
    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
        tls: parse_tls(
            env.socket_addr(ENV_TLS_BIND)?,
            env.string(ENV_TLS_CERT)?.as_deref(),
            env.string(ENV_TLS_KEY)?.as_deref(),
        )?,
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
    // One pool for both listeners: their sessions share the one process's MemoryMax.
    let pool = Arc::new(CaptureMemoryBudget::new(sensor_redis::memory::POOL_BYTES));

    let (bound, handle) = match sensor_redis::start_test_server(
        config.bind_addr,
        config.log_path.clone(),
        wan_resolver.clone(),
        config.bounds.clone(),
        pool.clone(),
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
                pool,
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
    use std::time::Duration;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:6379");

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "6379")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:6379".parse().unwrap());
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.tls, None);
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(600));
        assert_eq!(c.bounds.max_captured_bytes, 1_000_000);
        assert_eq!(c.bounds.max_concurrent, 256);
    }

    #[test]
    fn a_zero_or_garbage_bound_is_an_error_not_a_disabled_guard() {
        for var in [
            ENV_READ_TIMEOUT_MS,
            ENV_IDLE_TIMEOUT_MS,
            ENV_MAX_DURATION_SECS,
            ENV_MAX_CAPTURED_BYTES,
            ENV_MAX_CONCURRENT,
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
        for (var, bad) in [(ENV_WAN_MAP, "not-valid"), (ENV_TLS_BIND, "nonsense")] {
            assert!(
                matches!(
                    load_config(&Env::from_table(&[BIND, (var, bad)])),
                    Err(ConfigError::Env(EnvError::Invalid { .. }))
                ),
                "{var}={bad}"
            );
        }
    }

    const CERT: &str = "/etc/propolis/tls/redis.crt";
    const KEY: &str = "/etc/propolis/tls/redis.key";
    const TLS_BIND: Option<SocketAddr> = Some(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        6380,
    ));

    #[test]
    fn parse_tls_nothing_configured_is_none() {
        // Blank values never reach here: the env reader reads them as unset.
        assert_eq!(parse_tls(None, None, None), Ok(None));
    }

    #[test]
    fn parse_tls_full_is_some() {
        assert_eq!(
            parse_tls(TLS_BIND, Some(CERT), Some(KEY)),
            Ok(Some(TlsConfig {
                bind_addr: TLS_BIND,
                cert_path: CERT.into(),
                key_path: KEY.into(),
            }))
        );
    }

    #[test]
    fn parse_tls_bind_without_cert_is_refused() {
        assert_eq!(
            parse_tls(TLS_BIND, None, Some(KEY)),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
        assert_eq!(
            parse_tls(TLS_BIND, None, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }

    #[test]
    fn parse_tls_bind_without_key_is_refused() {
        assert_eq!(
            parse_tls(TLS_BIND, Some(CERT), None),
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
}
