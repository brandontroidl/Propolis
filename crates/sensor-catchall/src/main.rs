//! sensor-catchall: the passive, protocol-agnostic catch-all listener. Binds every configured
//! TCP/UDP address and emits a `catchall_probe` event for whatever a scanner or bot sends -
//! `internal/design/02-sensor-framework.md`'s "Catch-all listener": it emulates no protocol at
//! all, so what it captures is exactly what arrived unprompted.
//!
//! Configuration is environment variables (see the `ENV_*` constants below): this crate's brief
//! deliberately carries no TOML/CLI-arg-parsing dependency, and a handful of env vars is enough
//! surface for a single-purpose catch-all binary. Every value is validated at startup and the
//! process refuses to start on a malformed one rather than silently substituting a default that
//! could disable the bound it names - `internal/design/02-sensor-framework.md`'s "Catch-all
//! listener": "a validated, bounded config", and "Config values are validated and bounded":
//! "zero does not mean unlimited".

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_catchall::handler;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    ConnectionBounds, EventEmitter, WanResolver, run_tcp_listener, run_udp_listener,
    shutdown_signal,
};
use tokio::task::JoinHandle;

const ENV_BIND_ADDRS: &str = "CATCHALL_BIND_ADDRS";
const ENV_LOG_PATH: &str = "CATCHALL_LOG_PATH";
const ENV_WAN_MAP: &str = "CATCHALL_WAN_MAP";
const ENV_READ_TIMEOUT_MS: &str = "CATCHALL_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "CATCHALL_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "CATCHALL_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "CATCHALL_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "CATCHALL_MAX_CONCURRENT";

const DEFAULT_LOG_PATH: &str = "catchall-events.jsonl";
const DEFAULT_READ_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 30;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 4_096;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

/// Catch-all process configuration: every TCP/UDP address to bind, the local-to-WAN IP table, the
/// per-connection bounds, and the event log path. Unlike `sensor_framework::SensorConfig`, this
/// carries no spool/hand-off fields - the catch-all never spools a file body (see `handler.rs`'s
/// module doc), so requiring an operator to configure a spool directory it would never use would
/// be dead, misleading config surface.
#[derive(Debug, Clone)]
struct Config {
    bind_addrs: Vec<SocketAddr>,
    wan_map: HashMap<IpAddr, IpAddr>,
    bounds: ConnectionBounds,
    log_path: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `CATCHALL_BIND_ADDRS` was absent, empty, or held only blank entries.
    NoBindAddrs,
    InvalidBindAddr(String),
    InvalidWanMapEntry(String),
    /// A bound value failed to parse, or parsed to 0. Zero is always rejected rather than
    /// silently treated as "unlimited" - see this file's module doc.
    InvalidBound {
        field: &'static str,
        value: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NoBindAddrs => write!(
                f,
                "{ENV_BIND_ADDRS} must name at least one bind address (comma-separated ip:port)"
            ),
            ConfigError::InvalidBindAddr(s) => write!(f, "invalid bind address {s:?}"),
            ConfigError::InvalidWanMapEntry(s) => {
                write!(
                    f,
                    "invalid {ENV_WAN_MAP} entry {s:?}, expected local_ip=wan_ip"
                )
            }
            ConfigError::InvalidBound { field, value } => write!(
                f,
                "{field} must be a positive integer, got {value:?} (zero never means unlimited)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse a comma-separated list of `ip:port` bind addresses. Rejects an empty list outright - the
/// design doc's "a validated, bounded config" requires at least one real address to serve.
fn parse_bind_addrs(raw: &str) -> Result<Vec<SocketAddr>, ConfigError> {
    let addrs: Vec<SocketAddr> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<SocketAddr>()
                .map_err(|_| ConfigError::InvalidBindAddr(s.to_string()))
        })
        .collect::<Result<_, _>>()?;
    if addrs.is_empty() {
        return Err(ConfigError::NoBindAddrs);
    }
    Ok(addrs)
}

/// Parse a comma-separated `local_ip=wan_ip` list. An empty (or absent) input is a valid, empty
/// map - the wire contract's documented "no WAN binding" case, not an error.
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

/// Parse an optional positive `u64` bound: `None` (the env var was unset) falls back to `default`;
/// present-but-zero or present-but-unparseable are both rejected. Pure (takes the already-read
/// value rather than touching `std::env` itself) so it is unit-testable without mutating real
/// process environment - env var mutation is global, mutable, cross-thread state that would race
/// against Rust's default parallel test execution.
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

/// Load and validate configuration from environment variables. Fails closed: any missing bind
/// address, malformed entry, or zero-valued bound is rejected here rather than silently
/// substituted with a default that could disable the bound it names.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let bind_addrs = parse_bind_addrs(&env::var(ENV_BIND_ADDRS).unwrap_or_default())?;
    let wan_map = parse_wan_map(&env::var(ENV_WAN_MAP).unwrap_or_default())?;
    let log_path = env::var(ENV_LOG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_PATH));

    let read_timeout_ms = parse_positive_u64(
        env::var(ENV_READ_TIMEOUT_MS).ok().as_deref(),
        DEFAULT_READ_TIMEOUT_MS,
        ENV_READ_TIMEOUT_MS,
    )?;
    let idle_timeout_ms = parse_positive_u64(
        env::var(ENV_IDLE_TIMEOUT_MS).ok().as_deref(),
        DEFAULT_IDLE_TIMEOUT_MS,
        ENV_IDLE_TIMEOUT_MS,
    )?;
    let max_duration_secs = parse_positive_u64(
        env::var(ENV_MAX_DURATION_SECS).ok().as_deref(),
        DEFAULT_MAX_DURATION_SECS,
        ENV_MAX_DURATION_SECS,
    )?;
    let max_captured_bytes = parse_positive_u64(
        env::var(ENV_MAX_CAPTURED_BYTES).ok().as_deref(),
        DEFAULT_MAX_CAPTURED_BYTES,
        ENV_MAX_CAPTURED_BYTES,
    )?;
    let max_concurrent = parse_positive_u32(
        env::var(ENV_MAX_CONCURRENT).ok().as_deref(),
        DEFAULT_MAX_CONCURRENT,
        ENV_MAX_CONCURRENT,
    )?;

    Ok(Config {
        bind_addrs,
        wan_map,
        bounds: ConnectionBounds {
            read_timeout: Duration::from_millis(read_timeout_ms),
            idle_timeout: Duration::from_millis(idle_timeout_ms),
            max_duration: Duration::from_secs(max_duration_secs),
            max_captured_bytes,
            max_concurrent,
        },
        log_path,
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "catchall: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let emitter = Arc::new(EventEmitter::new(config.log_path.clone()));
    let wan_resolver = Arc::new(WanResolver::new(config.wan_map.clone()));

    // A per-port bind failure is non-fatal (design doc's "Listener lifecycle": "one unavailable
    // port never takes the sensor down") - each bind is attempted independently and only logged
    // on failure, never propagated to stop the loop over the rest of the configured addresses.
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for addr in &config.bind_addrs {
        let bounds = config.bounds.clone();
        let tcp_emitter = emitter.clone();
        let tcp_wan_resolver = wan_resolver.clone();
        match run_tcp_listener(*addr, bounds.clone(), move |stream, peer, session_id| {
            let emitter = tcp_emitter.clone();
            let wan_resolver = tcp_wan_resolver.clone();
            let bounds = bounds.clone();
            async move {
                handler::handle_tcp(stream, peer, session_id, &wan_resolver, &emitter, &bounds)
                    .await;
            }
        })
        .await
        {
            Ok((bound, handle)) => {
                tracing::info!(local = %bound, "catchall: tcp listener bound");
                handles.push(handle);
            }
            Err(e) => {
                tracing::warn!(%addr, error = %e, "catchall: tcp bind failed; skipping this port");
            }
        }

        let local_ip = normalize_dual_stack(*addr).ip();
        let udp_emitter = emitter.clone();
        let udp_wan_resolver = wan_resolver.clone();
        match run_udp_listener(*addr, move |data, peer| {
            let emitter = udp_emitter.clone();
            let wan_resolver = udp_wan_resolver.clone();
            async move {
                handler::handle_udp(data, peer, local_ip, &wan_resolver, &emitter).await;
            }
        })
        .await
        {
            Ok((bound, handle)) => {
                tracing::info!(local = %bound, "catchall: udp listener bound");
                handles.push(handle);
            }
            Err(e) => {
                tracing::warn!(%addr, error = %e, "catchall: udp bind failed; skipping this port");
            }
        }
    }

    if handles.is_empty() {
        tracing::error!("catchall: no listener bound on any configured address; exiting");
        std::process::exit(1);
    }

    shutdown_signal().await;
    tracing::info!("catchall: shutdown signal received; stopping listeners");
    for handle in handles {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bind_addrs_accepts_comma_separated_list() {
        let addrs = parse_bind_addrs("0.0.0.0:2222, 0.0.0.0:8080").unwrap();
        assert_eq!(
            addrs,
            vec![
                "0.0.0.0:2222".parse().unwrap(),
                "0.0.0.0:8080".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parse_bind_addrs_rejects_empty() {
        assert_eq!(parse_bind_addrs(""), Err(ConfigError::NoBindAddrs));
        assert_eq!(parse_bind_addrs("   "), Err(ConfigError::NoBindAddrs));
    }

    #[test]
    fn parse_bind_addrs_rejects_malformed_entry() {
        assert!(matches!(
            parse_bind_addrs("not-an-addr"),
            Err(ConfigError::InvalidBindAddr(_))
        ));
    }

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
    fn parse_wan_map_empty_string_is_empty_map_not_an_error() {
        assert!(parse_wan_map("").unwrap().is_empty());
    }

    #[test]
    fn parse_wan_map_rejects_malformed_entry() {
        assert!(matches!(
            parse_wan_map("not-valid"),
            Err(ConfigError::InvalidWanMapEntry(_))
        ));
        assert!(matches!(
            parse_wan_map("also=not=valid=at=all"),
            Err(ConfigError::InvalidWanMapEntry(_))
        ));
    }

    #[test]
    fn parse_positive_u64_uses_default_when_absent() {
        assert_eq!(parse_positive_u64(None, 42, "x").unwrap(), 42);
    }

    #[test]
    fn parse_positive_u64_rejects_zero() {
        // Zero must never silently mean "unlimited".
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
    fn parse_positive_u64_accepts_explicit_value() {
        assert_eq!(parse_positive_u64(Some("100"), 42, "x").unwrap(), 100);
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
}
