use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{ConnectionBounds, Env, EnvError, WanResolver, shutdown_signal};

const ENV_BIND: &str = "PROPOLIS_SMTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_SMTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_SMTP_LOG_PATH";
const ENV_SUBMISSION_BIND: &str = "PROPOLIS_SMTP_SUBMISSION_BIND";
const ENV_TLS_BIND: &str = "PROPOLIS_SMTP_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_SMTP_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_SMTP_TLS_KEY";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_SMTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_SMTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_SMTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_SMTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_SMTP_MAX_CONCURRENT";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/smtp/events.jsonl";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    /// The 587 listener; unset or blank means "not configured", a typo refuses to start: it must
    /// not silently drop a listener the derived fleet inventory will claim exists.
    submission_bind: Option<SocketAddr>,
    /// The 465 implicit-TLS listener, same rule.
    tls_bind: Option<SocketAddr>,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    bounds: ConnectionBounds,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    NoBind,
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses: a bad bound is
    /// never replaced by its default.
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
            ConfigError::NoBind => {
                write!(f, "{ENV_BIND} must be set to a single ip:port bind address")
            }
            ConfigError::Env(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn load_config(env: &Env) -> Result<Config, ConfigError> {
    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        submission_bind: env.socket_addr(ENV_SUBMISSION_BIND)?,
        tls_bind: env.socket_addr(ENV_TLS_BIND)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
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
            tracing::error!(error = %e, "sensor-smtp: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // All configuration is validated before the first socket is bound, so a bad TLS setup never
    // leaves a plaintext listener running.
    let tls = match sensor_smtp::tls_from_env(
        ENV_TLS_CERT,
        ENV_TLS_KEY,
        config.tls_bind.is_some(),
        sensor_framework::strict_env_var,
    ) {
        Ok(tls) => tls,
        Err(e) => {
            tracing::error!(error = %e, "sensor-smtp: invalid TLS configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let listeners = match sensor_smtp::plan_listeners(
        config.bind_addr,
        config.submission_bind,
        config.tls_bind,
        tls,
    ) {
        Ok(listeners) => listeners,
        Err(e) => {
            tracing::error!("sensor-smtp: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));
    let started =
        match sensor_smtp::start_listeners(listeners, config.log_path, wan_resolver, config.bounds)
            .await
        {
            Ok(started) => started,
            Err(e) => {
                tracing::error!("sensor-smtp: {e}; refusing to start");
                std::process::exit(1);
            }
        };

    for (bound, _) in &started {
        tracing::info!(local = %bound, "sensor-smtp: listening");
    }
    shutdown_signal().await;
    tracing::info!("sensor-smtp: shutdown signal received; stopping");
    for (_, handle) in &started {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:25");

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "25")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:25".parse().unwrap());
        assert_eq!(c.submission_bind, None);
        assert_eq!(c.tls_bind, None);
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(600));
        assert_eq!(c.bounds.max_captured_bytes, 1_000_000);
        assert_eq!(c.bounds.max_concurrent, 256);
    }

    /// The failure this sensor used to have: a bound it could not parse ran with the default.
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
    }

    #[test]
    fn extra_listeners_and_the_wan_map_are_strict() {
        let c = load_config(&Env::from_table(&[
            BIND,
            (ENV_SUBMISSION_BIND, "203.0.113.7:587"),
            (ENV_TLS_BIND, "203.0.113.7:465"),
            (ENV_WAN_MAP, "10.0.0.1=198.51.100.4"),
        ]))
        .unwrap();
        assert_eq!(c.submission_bind, Some("203.0.113.7:587".parse().unwrap()));
        assert_eq!(c.tls_bind, Some("203.0.113.7:465".parse().unwrap()));
        assert_eq!(c.wan_map.len(), 1);
        for (var, bad) in [
            (ENV_SUBMISSION_BIND, "587"),
            (ENV_TLS_BIND, "nonsense"),
            (ENV_WAN_MAP, "10.0.0.1"),
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
}
