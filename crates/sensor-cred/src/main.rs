use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{ConnectionBounds, Env, EnvError, WanResolver, shutdown_signal};

const ENV_WAN_MAP: &str = "PROPOLIS_CRED_WAN_MAP";
const ENV_LOG_DIR: &str = "PROPOLIS_CRED_LOG_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_CRED_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_CRED_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_CRED_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_CRED_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_CRED_MAX_CONCURRENT";
const ENV_TLS_CERT: &str = "PROPOLIS_CRED_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_CRED_TLS_KEY";
/// One bind variable per protocol; at least one must be set.
const BIND_VARS: [(&str, &str); 5] = [
    ("PROPOLIS_CRED_VNC_BIND", "vnc"),
    ("PROPOLIS_CRED_MYSQL_BIND", "mysql"),
    ("PROPOLIS_CRED_MSSQL_BIND", "mssql"),
    ("PROPOLIS_CRED_PG_BIND", "postgresql"),
    ("PROPOLIS_CRED_MONGO_BIND", "mongodb"),
];
/// The protocols `start_listener` hands the TLS config to; vnc ignores it.
const TLS_CAPABLE: [&str; 4] = ["postgresql", "mysql", "mssql", "mongodb"];

const DEFAULT_LOG_DIR: &str = "/var/log/propolis/cred";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
/// Shorter than the other sensors' 600: a credential probe is over in seconds.
const DEFAULT_MAX_DURATION_SECS: u64 = 60;
/// Smaller than the other sensors' 1_000_000: a login exchange carries no file body.
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 100_000;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

#[derive(Debug, Clone, PartialEq)]
struct PortConfig {
    protocol: &'static str,
    bind: SocketAddr,
}

#[derive(Debug, Clone)]
struct Config {
    ports: Vec<PortConfig>,
    /// Cert and key paths; both or neither, so a half-configured pair never binds plaintext where
    /// TLS was intended.
    tls_paths: Option<(PathBuf, PathBuf)>,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_dir: PathBuf,
    bounds: ConnectionBounds,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// No `PROPOLIS_CRED_*_BIND` was set.
    NoBind,
    /// Exactly one of the TLS pair was set.
    TlsIncomplete,
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses: a bad bound is
    /// never replaced by its default, and a bad bind never silently drops a listener the fleet
    /// inventory still claims.
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
                write!(
                    f,
                    "no bind addresses configured; set at least one PROPOLIS_CRED_*_BIND"
                )
            }
            ConfigError::TlsIncomplete => write!(
                f,
                "TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY}, but only one is set"
            ),
            ConfigError::Env(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn load_config(env: &Env) -> Result<Config, ConfigError> {
    let mut ports = Vec::new();
    for (var, protocol) in BIND_VARS {
        if let Some(bind) = env.socket_addr(var)? {
            ports.push(PortConfig { protocol, bind });
        }
    }
    let tls_paths = match (env.string(ENV_TLS_CERT)?, env.string(ENV_TLS_KEY)?) {
        (None, None) => None,
        (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
        _ => return Err(ConfigError::TlsIncomplete),
    };
    if ports.is_empty() {
        return Err(ConfigError::NoBind);
    }
    Ok(Config {
        ports,
        tls_paths,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_dir: env.path(ENV_LOG_DIR, DEFAULT_LOG_DIR)?,
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
            tracing::error!(error = %e, "sensor-cred: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Fail closed: a configured pair must load, before anything binds.
    let tls = match &config.tls_paths {
        None => None,
        Some((cert, key)) => match sensor_cred::CredTls::from_files(cert, key) {
            Ok(tls) => {
                let capable: Vec<&str> = config
                    .ports
                    .iter()
                    .map(|pc| pc.protocol)
                    .filter(|protocol| TLS_CAPABLE.contains(protocol))
                    .collect();
                if capable.is_empty() {
                    tracing::warn!(
                        "sensor-cred: TLS is configured but no TLS-capable protocol is bound ({})",
                        TLS_CAPABLE.join(", ")
                    );
                } else {
                    tracing::info!("sensor-cred: TLS enabled for {}", capable.join(", "));
                }
                Some(tls)
            }
            Err(e) => {
                tracing::error!(error = %e, "sensor-cred: TLS is configured but the certificate or key cannot be loaded; refusing to start");
                std::process::exit(1);
            }
        },
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    // Unlike sensors whose TLS adds a listener, a bind failure here skips that one protocol: the
    // five are independent traps and TLS adds no listener whose loss could hide behind the others.
    let mut handles = Vec::new();
    for pc in &config.ports {
        let log_path = config.log_dir.join(format!("{}.jsonl", pc.protocol));
        match sensor_cred::start_listener(
            pc.bind,
            log_path,
            wan_resolver.clone(),
            config.bounds.clone(),
            pc.protocol,
            tls.clone(),
        )
        .await
        {
            Ok((bound, handle)) => {
                tracing::info!(protocol = pc.protocol, local = %bound, "sensor-cred: listening");
                handles.push(handle);
            }
            Err(e) => {
                let e = sensor_framework::listener_start_error(pc.bind, e);
                tracing::error!("sensor-cred: {e}; skipping protocol {}", pc.protocol);
            }
        }
    }

    if handles.is_empty() {
        tracing::error!(
            "sensor-cred: no listener started on any configured address; refusing to start"
        );
        std::process::exit(1);
    }

    shutdown_signal().await;
    tracing::info!("sensor-cred: shutdown signal received; stopping");
    for handle in handles {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PG: (&str, &str) = ("PROPOLIS_CRED_PG_BIND", "203.0.113.7:5432");

    #[test]
    fn at_least_one_bind_is_required_and_each_must_parse() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert_eq!(
            load_config(&Env::from_table(&[(ENV_LOG_DIR, "/tmp/x")])).unwrap_err(),
            ConfigError::NoBind
        );
        for (var, _) in BIND_VARS {
            assert!(
                matches!(
                    load_config(&Env::from_table(&[PG, (var, "5432")])),
                    Err(ConfigError::Env(EnvError::Invalid { .. }))
                ),
                "{var}"
            );
        }
    }

    #[test]
    fn every_set_bind_becomes_a_port_in_declaration_order() {
        let c = load_config(&Env::from_table(&[
            ("PROPOLIS_CRED_MONGO_BIND", "203.0.113.7:27017"),
            ("PROPOLIS_CRED_VNC_BIND", "203.0.113.7:5900"),
            ("PROPOLIS_CRED_MYSQL_BIND", " "),
        ]))
        .unwrap();
        assert_eq!(
            c.ports,
            vec![
                PortConfig {
                    protocol: "vnc",
                    bind: "203.0.113.7:5900".parse().unwrap()
                },
                PortConfig {
                    protocol: "mongodb",
                    bind: "203.0.113.7:27017".parse().unwrap()
                },
            ]
        );
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[PG])).unwrap();
        assert_eq!(c.tls_paths, None);
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_dir, PathBuf::from(DEFAULT_LOG_DIR));
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(60));
        assert_eq!(c.bounds.max_captured_bytes, 100_000);
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
                match load_config(&Env::from_table(&[PG, (var, bad)])) {
                    Err(ConfigError::Env(EnvError::Invalid { var: v, value, .. })) => {
                        assert_eq!((v.as_str(), value.as_str()), (var, bad));
                    }
                    other => panic!("{var}={bad}: {other:?}"),
                }
            }
        }
        assert!(matches!(
            load_config(&Env::from_table(&[PG, (ENV_WAN_MAP, "10.0.0.1")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn tls_is_both_paths_or_neither() {
        let c = load_config(&Env::from_table(&[
            PG,
            (ENV_TLS_CERT, "/etc/propolis/tls/cred.crt"),
            (ENV_TLS_KEY, "/etc/propolis/tls/cred.key"),
        ]))
        .unwrap();
        assert_eq!(
            c.tls_paths,
            Some((
                PathBuf::from("/etc/propolis/tls/cred.crt"),
                PathBuf::from("/etc/propolis/tls/cred.key")
            ))
        );
        for var in [ENV_TLS_CERT, ENV_TLS_KEY] {
            assert_eq!(
                load_config(&Env::from_table(&[PG, (var, "/x")])).unwrap_err(),
                ConfigError::TlsIncomplete,
                "{var}"
            );
        }
    }
}
