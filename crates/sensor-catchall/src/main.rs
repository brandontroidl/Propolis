//! sensor-catchall: the passive, protocol-agnostic catch-all listener. Binds every configured
//! TCP/UDP address and emits a `catchall_probe` event for whatever a scanner or bot sends -
//! `internal/design/02-sensor-framework.md`'s "Catch-all listener": it emulates no protocol at
//! all, so what it captures is exactly what arrived unprompted.
//!
//! Configuration is environment variables (see the `ENV_*` constants below): this crate's brief
//! deliberately carries no TOML/CLI-arg-parsing dependency, and a handful of env vars is enough
//! surface for a single-purpose catch-all binary. Every value is read through
//! `sensor_framework::Env`, validated at startup, and the process refuses to start on a malformed
//! one rather than silently substituting a default that could disable the bound it names -
//! `internal/design/02-sensor-framework.md`'s "Catch-all listener": "a validated, bounded
//! config", and "Config values are validated and bounded": "zero does not mean unlimited".

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sensor_catchall::handler;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    ConnectionBounds, Env, EnvError, EventEmitter, WanResolver, run_tcp_listener, run_udp_listener,
    shutdown_signal,
};
use tokio::task::JoinHandle;

// Canonical `PROPOLIS_CATCHALL_*` names, matching every other sensor (`PROPOLIS_SSH_BIND`,
// `PROPOLIS_FTP_SPOOL_DIR`, ...). This sensor originally shipped with bare `CATCHALL_*` names, the
// lone exception in the fleet, and that inconsistency cost a real deployment: the operator wrote
// `/etc/propolis/catchall.env` to the majority convention, nothing read it, the fail-closed config
// check rejected the empty bind list, and the catch-all sensor sat dead through ~4000 restarts
// without anyone noticing. `env_var` below still honours the bare names so existing configs keep
// working; it warns so they can be migrated rather than silently depended on.
const ENV_BIND_ADDRS: &str = "PROPOLIS_CATCHALL_BIND_ADDRS";
const ENV_LOG_PATH: &str = "PROPOLIS_CATCHALL_LOG_PATH";
const ENV_WAN_MAP: &str = "PROPOLIS_CATCHALL_WAN_MAP";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_CATCHALL_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_CATCHALL_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_CATCHALL_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_CATCHALL_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_CATCHALL_MAX_CONCURRENT";

/// Reads `name`, falling back to the pre-rename bare spelling (`PROPOLIS_CATCHALL_X` -> `CATCHALL_X`)
/// so a config written against the old names still starts the sensor. A legacy hit is warned about
/// once per variable, naming the canonical replacement, so the fallback is a migration path rather
/// than a second permanent spelling.
fn legacy_name(canonical: &str) -> &str {
    canonical.strip_prefix("PROPOLIS_").unwrap_or(canonical)
}

fn env_var(name: &str) -> Result<Option<String>, EnvError> {
    sensor_framework::env_with_legacy(name, legacy_name(name))
}

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
    /// [`ENV_BIND_ADDRS`] (and its legacy bare spelling) was absent, empty, or held only blank
    /// entries.
    NoBindAddrs,
    InvalidBindAddr(String),
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses. Zero is always
    /// rejected rather than silently treated as "unlimited" - see this file's module doc.
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
            ConfigError::Env(e) => write!(f, "{e}"),
            ConfigError::NoBindAddrs => write!(
                f,
                "{ENV_BIND_ADDRS} must name at least one bind address (comma-separated ip:port)"
            ),
            ConfigError::InvalidBindAddr(s) => write!(f, "invalid bind address {s:?}"),
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

/// Load and validate configuration. Fails closed: any missing bind address, malformed entry, or
/// zero-valued bound is rejected here rather than silently substituted with a default that could
/// disable the bound it names.
fn load_config(env: &Env) -> Result<Config, ConfigError> {
    Ok(Config {
        bind_addrs: parse_bind_addrs(&env.string(ENV_BIND_ADDRS)?.unwrap_or_default())?,
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

    let config = match load_config(&Env::from_lookup(env_var)) {
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
        let per_source_cap = Some(sensor_framework::default_per_source_cap(
            bounds.max_concurrent,
        ));
        match run_tcp_listener(
            *addr,
            bounds.clone(),
            per_source_cap,
            move |stream, peer, session_id| {
                let emitter = tcp_emitter.clone();
                let wan_resolver = tcp_wan_resolver.clone();
                let bounds = bounds.clone();
                async move {
                    handler::handle_tcp(stream, peer, session_id, &wan_resolver, &emitter, &bounds)
                        .await;
                }
            },
        )
        .await
        {
            Ok((bound, handle)) => {
                tracing::info!(local = %bound, "catchall: tcp listener bound");
                handles.push(handle);
            }
            Err(e) => {
                let e = sensor_framework::listener_start_error(*addr, e);
                tracing::warn!("catchall: tcp {e}; skipping this port");
            }
        }

        let local_ip = normalize_dual_stack(*addr).ip();
        let udp_emitter = emitter.clone();
        let udp_wan_resolver = wan_resolver.clone();
        match run_udp_listener(
            *addr,
            config.bounds.clone(),
            per_source_cap,
            move |data, peer| {
                let emitter = udp_emitter.clone();
                let wan_resolver = udp_wan_resolver.clone();
                async move {
                    handler::handle_udp(data, peer, local_ip, &wan_resolver, &emitter).await;
                }
            },
        )
        .await
        {
            Ok((bound, handle)) => {
                tracing::info!(local = %bound, "catchall: udp listener bound");
                handles.push(handle);
            }
            Err(e) => {
                let e = sensor_framework::listener_start_error(*addr, e);
                tracing::warn!("catchall: udp {e}; skipping this port");
            }
        }
    }

    if handles.is_empty() {
        tracing::error!(
            "catchall: no listener started on any configured address; refusing to start"
        );
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
    use std::time::Duration;

    const BINDS: (&str, &str) = (ENV_BIND_ADDRS, "0.0.0.0:2222, 0.0.0.0:8080");

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
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBindAddrs
        );
    }

    #[test]
    fn parse_bind_addrs_rejects_malformed_entry() {
        assert!(matches!(
            parse_bind_addrs("not-an-addr"),
            Err(ConfigError::InvalidBindAddr(_))
        ));
    }

    #[test]
    fn a_valid_bind_list_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BINDS])).unwrap();
        assert_eq!(c.bind_addrs.len(), 2);
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(5_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(5_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(30));
        assert_eq!(c.bounds.max_captured_bytes, 4_096);
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
                match load_config(&Env::from_table(&[BINDS, (var, bad)])) {
                    Err(ConfigError::Env(EnvError::Invalid { var: v, value, .. })) => {
                        assert_eq!((v.as_str(), value.as_str()), (var, bad));
                    }
                    other => panic!("{var}={bad}: {other:?}"),
                }
            }
        }
        for bad in ["not-valid", "also=not=valid=at=all"] {
            assert!(
                matches!(
                    load_config(&Env::from_table(&[BINDS, (ENV_WAN_MAP, bad)])),
                    Err(ConfigError::Env(EnvError::Invalid { .. }))
                ),
                "{bad}"
            );
        }
    }

    // The legacy spelling is derived by stripping the PROPOLIS_ prefix, so a config written against
    // the old bare names still resolves instead of leaving the sensor unconfigured - the failure
    // that left the catch-all sensor dead across ~4000 restarts because nothing read its env file.
    // Tested as a pure derivation rather than by mutating process-global env vars, which would race
    // every other test in this binary.
    #[test]
    fn the_legacy_bare_name_is_the_canonical_one_without_the_propolis_prefix() {
        assert_eq!(legacy_name(ENV_BIND_ADDRS), "CATCHALL_BIND_ADDRS");
        assert_eq!(legacy_name(ENV_MAX_CONCURRENT), "CATCHALL_MAX_CONCURRENT");
        // A name that is already unprefixed is returned unchanged, never truncated further.
        assert_eq!(legacy_name("CATCHALL_BIND_ADDRS"), "CATCHALL_BIND_ADDRS");
    }
}
