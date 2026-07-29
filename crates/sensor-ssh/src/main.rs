//! sensor-ssh: the SSH honeypot sensor binary. Binds one TCP address, runs a full SSH
//! handshake (transport, key exchange, authentication) using this crate's own primitives
//! (ADR-0011), then presents a fake shell and captures SCP/SFTP uploads - see
//! `internal/design/02-sensor-framework.md`'s "SSH sensor" and `server.rs` for the session
//! logic this binary composes.
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! `EnvironmentFile` in `deploy/sensor-ssh.service` and the convention established by
//! `sensor-catchall/src/main.rs`. Every value is validated at startup and the process
//! refuses to start on a malformed one.

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{WanResolver, shutdown_signal};
use sensor_ssh::hostkey::HostKey;

const ENV_BIND: &str = "PROPOLIS_SSH_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_SSH_WAN_MAP";
const ENV_HOST_KEY_PATH: &str = "PROPOLIS_SSH_HOST_KEY_PATH";
const ENV_LOG_PATH: &str = "PROPOLIS_SSH_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_SSH_SPOOL_DIR";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/ssh/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/ssh";
const DEFAULT_HOST_KEY_PATH: &str = "/var/lib/propolis/ssh/host_key";

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    host_key_path: PathBuf,
    log_path: PathBuf,
    spool_dir: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `PROPOLIS_SSH_BIND` was absent or unparseable.
    NoBind,
    InvalidBind(String),
    InvalidWanMapEntry(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NoBind => {
                write!(f, "{ENV_BIND} must be set to a single ip:port bind address")
            }
            ConfigError::InvalidBind(s) => write!(f, "invalid {ENV_BIND} address {s:?}"),
            ConfigError::InvalidWanMapEntry(s) => write!(
                f,
                "invalid {ENV_WAN_MAP} entry {s:?}, expected local_ip=wan_ip"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse a comma-separated `local_ip=wan_ip` list. An empty or absent input is a valid,
/// empty map - the no-WAN-binding case documented in the wire contract.
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

fn load_config_from_env() -> Result<Config, ConfigError> {
    let bind_raw = env::var(ENV_BIND).map_err(|_| ConfigError::NoBind)?;
    let bind_addr: SocketAddr = bind_raw
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;

    let wan_map = parse_wan_map(&env::var(ENV_WAN_MAP).unwrap_or_default())?;

    let host_key_path = env::var(ENV_HOST_KEY_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_HOST_KEY_PATH));
    let log_path = env::var(ENV_LOG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_PATH));
    let spool_dir = env::var(ENV_SPOOL_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SPOOL_DIR));

    Ok(Config {
        bind_addr,
        wan_map,
        host_key_path,
        log_path,
        spool_dir,
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-ssh: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Load or generate the host key so the honeypot does not fingerprint itself as freshly
    // minted on every restart (design doc's "Host key").
    let host_key = if config.host_key_path.exists() {
        match HostKey::load(&config.host_key_path) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(
                    path = %config.host_key_path.display(),
                    error = %e,
                    "sensor-ssh: failed to load host key"
                );
                std::process::exit(1);
            }
        }
    } else {
        let key = HostKey::generate();
        if let Some(parent) = config.host_key_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::error!(
                path = %parent.display(),
                error = %e,
                "sensor-ssh: failed to create host key directory"
            );
            std::process::exit(1);
        }
        if let Err(e) = key.save(&config.host_key_path) {
            tracing::error!(
                path = %config.host_key_path.display(),
                error = %e,
                "sensor-ssh: failed to save generated host key"
            );
            std::process::exit(1);
        }
        tracing::info!(
            path = %config.host_key_path.display(),
            "sensor-ssh: generated new host key"
        );
        key
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    let (bound, handle) = match sensor_ssh::start_test_server(
        config.bind_addr,
        config.log_path,
        config.spool_dir,
        config.host_key_path,
        wan_resolver,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(
                addr = %config.bind_addr,
                error = %e,
                "sensor-ssh: failed to start server"
            );
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "sensor-ssh: listening");

    // Host key is already loaded/generated and passed to start_test_server above; drop the
    // local clone so only the server tasks hold it.
    drop(host_key);

    shutdown_signal().await;
    tracing::info!("sensor-ssh: shutdown signal received; stopping");
    handle.abort();
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
        // The env is shared across test threads, so only test what we can reason about
        // without mutating it: the error variant for a missing bind address.
        let result = load_config_from_env();
        // This test runs in an environment where PROPOLIS_SSH_BIND is not set.
        if env::var(ENV_BIND).is_err() {
            assert!(matches!(result, Err(ConfigError::NoBind)));
        }
    }
}
