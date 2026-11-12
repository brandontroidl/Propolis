//! `gateway` binary configuration: environment variables (see the `ENV_*` constants below),
//! matching the fail-closed pattern established by `sensor-ssh/src/main.rs` - every value is
//! validated at startup and the process refuses to start on a malformed one. The gateway holds
//! no `DATABASE_URL` and no vendor keys; it only needs a bind address, the three mTLS PEM
//! paths, its spool/state directories, and the connection bounds `sensor_framework` enforces.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sensor_framework::ConnectionBounds;

const ENV_BIND: &str = "PROPOLIS_GATEWAY_BIND";
const ENV_CA_CERT_PATH: &str = "PROPOLIS_GATEWAY_CA_CERT_PATH";
const ENV_SERVER_CERT_PATH: &str = "PROPOLIS_GATEWAY_SERVER_CERT_PATH";
const ENV_SERVER_KEY_PATH: &str = "PROPOLIS_GATEWAY_SERVER_KEY_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_GATEWAY_SPOOL_DIR";
const ENV_STATE_DIR: &str = "PROPOLIS_GATEWAY_STATE_DIR";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_GATEWAY_MAX_CONCURRENT";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_GATEWAY_MAX_DURATION_SECS";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_GATEWAY_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_GATEWAY_IDLE_TIMEOUT_MS";

const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/gateway";
const DEFAULT_STATE_DIR: &str = "/var/lib/propolis/gateway";

// Deliberately identical to sensor-ssh's defaults (see that crate's main.rs): both are
// TCP listeners governed by the same `sensor_framework::ConnectionBounds`, so there is no
// reason for the gateway to pick different numbers.
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 120;
const DEFAULT_MAX_CONCURRENT: u32 = 64;

/// The gateway's own read loop (`server.rs::handle_connection`) already bounds every frame at
/// `collector_wire::frame::MAX_FRAME_LEN` before allocating, so `ConnectionBounds`'s
/// `max_captured_bytes` field (a per-connection cumulative cap the listener does not enforce
/// itself - see that struct's doc) is not independently useful here and is not exposed as a
/// separate env var; it is set to the same frame ceiling so the field still carries a
/// meaningful, fail-closed value rather than an arbitrary one.
const MAX_CAPTURED_BYTES: u64 = collector_wire::frame::MAX_FRAME_LEN as u64;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub spool_dir: PathBuf,
    pub state_dir: PathBuf,
    pub bounds: ConnectionBounds,
}

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    /// `PROPOLIS_GATEWAY_BIND` was absent.
    NoBind,
    InvalidBind(String),
    /// A required PEM path env var was absent.
    MissingPath(&'static str),
    /// A bound was present but zero or unparseable. Rejected rather than defaulted: silently
    /// substituting a default for a misconfigured bound is how a guard gets disabled without
    /// anyone noticing.
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
            ConfigError::MissingPath(field) => write!(f, "{field} must be set to a file path"),
            ConfigError::InvalidBound { field, value } => {
                write!(
                    f,
                    "invalid {field} value {value:?}, expected a positive integer"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn required_path(field: &'static str) -> Result<PathBuf, ConfigError> {
    env::var(field)
        .map(PathBuf::from)
        .map_err(|_| ConfigError::MissingPath(field))
}

pub fn load_config_from_env() -> Result<Config, ConfigError> {
    let bind_raw = env::var(ENV_BIND).map_err(|_| ConfigError::NoBind)?;
    let bind_addr: SocketAddr = bind_raw
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;

    let ca_cert_path = required_path(ENV_CA_CERT_PATH)?;
    let server_cert_path = required_path(ENV_SERVER_CERT_PATH)?;
    let server_key_path = required_path(ENV_SERVER_KEY_PATH)?;

    let spool_dir = env::var(ENV_SPOOL_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SPOOL_DIR));
    let state_dir = env::var(ENV_STATE_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STATE_DIR));

    let bounds = ConnectionBounds {
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
        max_captured_bytes: MAX_CAPTURED_BYTES,
        max_concurrent: parse_positive_u32(
            env::var(ENV_MAX_CONCURRENT).ok().as_deref(),
            DEFAULT_MAX_CONCURRENT,
            ENV_MAX_CONCURRENT,
        )?,
    };

    Ok(Config {
        bind_addr,
        ca_cert_path,
        server_cert_path,
        server_key_path,
        spool_dir,
        state_dir,
        bounds,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The env is process-global and tests run on multiple threads; serialize any test that
    // sets/removes these vars so they cannot interleave with each other or with unrelated
    // tests that happen to read them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        keys: Vec<&'static str>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut keys = Vec::new();
            for (k, v) in vars {
                // SAFETY: serialized by ENV_LOCK above; no other thread touches these vars.
                unsafe { env::set_var(k, v) };
                keys.push(*k);
            }
            EnvGuard { _lock: lock, keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                // SAFETY: serialized by ENV_LOCK held for the guard's lifetime.
                unsafe { env::remove_var(k) };
            }
        }
    }

    fn valid_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            (ENV_BIND, "127.0.0.1:9443"),
            (ENV_CA_CERT_PATH, "/tmp/ca.pem"),
            (ENV_SERVER_CERT_PATH, "/tmp/server.pem"),
            (ENV_SERVER_KEY_PATH, "/tmp/server.key"),
        ]
    }

    #[test]
    fn load_config_from_valid_env_succeeds() {
        let _guard = EnvGuard::set(&valid_vars());
        let config = load_config_from_env().expect("valid env must parse");
        assert_eq!(config.bind_addr, "127.0.0.1:9443".parse().unwrap());
        assert_eq!(config.ca_cert_path, PathBuf::from("/tmp/ca.pem"));
        assert_eq!(config.server_cert_path, PathBuf::from("/tmp/server.pem"));
        assert_eq!(config.server_key_path, PathBuf::from("/tmp/server.key"));
        assert_eq!(config.spool_dir, PathBuf::from(DEFAULT_SPOOL_DIR));
        assert_eq!(config.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
        assert_eq!(config.bounds.max_concurrent, DEFAULT_MAX_CONCURRENT);
    }

    #[test]
    fn load_config_missing_bind_fails() {
        let mut vars = valid_vars();
        vars.retain(|(k, _)| *k != ENV_BIND);
        let _guard = EnvGuard::set(&vars);
        // The guard above never set ENV_BIND; make sure a leftover from another process/test
        // run is not the reason this passes.
        unsafe { env::remove_var(ENV_BIND) };
        assert_eq!(load_config_from_env().unwrap_err(), ConfigError::NoBind);
    }

    #[test]
    fn load_config_unparseable_bind_fails() {
        let mut vars = valid_vars();
        vars[0] = (ENV_BIND, "not-a-socket-addr");
        let _guard = EnvGuard::set(&vars);
        assert!(matches!(
            load_config_from_env(),
            Err(ConfigError::InvalidBind(_))
        ));
    }

    #[test]
    fn load_config_zero_max_concurrent_fails() {
        let mut vars = valid_vars();
        vars.push((ENV_MAX_CONCURRENT, "0"));
        let _guard = EnvGuard::set(&vars);
        assert_eq!(
            load_config_from_env().unwrap_err(),
            ConfigError::InvalidBound {
                field: ENV_MAX_CONCURRENT,
                value: "0".to_string(),
            }
        );
    }

    #[test]
    fn load_config_missing_ca_cert_path_fails() {
        let mut vars = valid_vars();
        vars.retain(|(k, _)| *k != ENV_CA_CERT_PATH);
        let _guard = EnvGuard::set(&vars);
        unsafe { env::remove_var(ENV_CA_CERT_PATH) };
        assert_eq!(
            load_config_from_env().unwrap_err(),
            ConfigError::MissingPath(ENV_CA_CERT_PATH)
        );
    }
}
