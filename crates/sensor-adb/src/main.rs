//! sensor-adb: the ADB (Android Debug Bridge) honeypot sensor binary. Binds one TCP address
//! (conventionally 5555), completes the `CNXN` handshake with a fake device banner, then serves
//! `shell:`/`shell:<command>` via the shared fake shell and captures `sync:` pushes to the
//! quarantine spool - see `internal/design/08-remaining-sensors.md`'s "sensor-adb" section for
//! the protocol flow this binary composes and `handler.rs` for the session logic.
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! convention established by `sensor-telnet`/`sensor-redis`/`sensor-ssh`'s own `main.rs`. Every
//! value is read through `sensor_framework::Env`, validated at startup, and the process refuses
//! to start on a malformed one rather than silently substituting a default that could disable the
//! bound it names.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::session_memory::{self, AccountingAlloc, DEFAULT_POOL_BYTES_256M};
use sensor_framework::{
    Arrival, CaptureMemoryBudget, CommandEventConfig, CommandEventGate, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, Env, EnvError, EventEmitter, SHUTDOWN_DRAIN_TIMEOUT,
    WanResolver, shutdown_signal,
};

/// Every allocation is charged to the session it was made in (`session_memory`).
#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

const ENV_BIND: &str = "PROPOLIS_ADB_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_ADB_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_ADB_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_ADB_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_ADB_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_ADB_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_ADB_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_ADB_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_ADB_MAX_CONCURRENT";
/// Shared across every sensor binary AND `shipper` on this collector (see sensor-ssh's own
/// `main.rs` for why): must match the shipper's client certificate CommonName.
const ENV_COLLECTOR_ID: &str = "PROPOLIS_COLLECTOR_ID";
/// Pre-rename bare spelling, still read via [`sensor_framework::env_with_legacy`] when
/// `PROPOLIS_COLLECTOR_ID` is unset (see sensor-ssh's own `main.rs` for why).
const ENV_COLLECTOR_ID_LEGACY: &str = "COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_ADB_OUTBOX_DIR";
/// Ceiling, in bytes, on capture bodies buffered in memory across every connection. Defaults to
/// 40% of the unit's 256M `MemoryMax` (see `deploy/sensor-adb.service`).
const ENV_CAPTURE_MEMORY_BYTES: &str = "PROPOLIS_ADB_CAPTURE_MEMORY_BYTES";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/adb/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/adb";
const DEFAULT_COLLECTOR_ID: &str = "local";
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
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_memory_bytes: u64,
    command_events: CommandEventConfig,
}

/// The sensor name in `PROPOLIS_ADB_COMMAND_EVENT_RATE_PER_MIN` and `..._BURST`.
const COMMAND_EVENT_SENSOR: &str = "adb";
/// How long shutdown waits for the command summaries still accumulating to be written.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `PROPOLIS_ADB_BIND` was absent.
    NoBind,
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses. Zero is always
    /// rejected rather than silently treated as "unlimited".
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
            ConfigError::NoBind => {
                write!(f, "{ENV_BIND} must be set to a single ip:port bind address")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Resolve the outbox directory: the explicit `PROPOLIS_ADB_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_ADB_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
}

/// Load and validate configuration. Fails closed: any missing bind address, malformed entry, or
/// zero-valued bound is rejected here rather than silently substituted with a default that could
/// disable the bound it names.
fn load_config(env: &Env) -> Result<Config, ConfigError> {
    let spool_dir = env.path(ENV_SPOOL_DIR, DEFAULT_SPOOL_DIR)?;
    let outbox_dir = resolve_outbox_dir(&spool_dir, env.string(ENV_OUTBOX_DIR)?);
    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
        spool_dir,
        collector_id: sensor_framework::env_with_legacy(ENV_COLLECTOR_ID, ENV_COLLECTOR_ID_LEGACY)?
            .unwrap_or_else(|| DEFAULT_COLLECTOR_ID.to_string()),
        outbox_dir,
        capture_memory_bytes: env
            .positive_u64(ENV_CAPTURE_MEMORY_BYTES, DEFAULT_CAPTURE_BUDGET_BYTES_256M)?,
        command_events: CommandEventConfig::from_env(COMMAND_EVENT_SENSOR, env)?,
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
            tracing::error!(error = %e, "sensor-adb: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Every admitted session must fit in the session memory pool at its floor.
    if let Err(e) = session_memory::configure(DEFAULT_POOL_BYTES_256M, config.bounds.max_concurrent)
    {
        tracing::error!(error = %e, "sensor-adb: invalid configuration; refusing to start");
        std::process::exit(1);
    }
    tokio::spawn(session_memory::watchdog());

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));
    let command_events = Arc::new(CommandEventGate::new(config.command_events));
    let summary_emitter = EventEmitter::new(config.log_path.clone());

    let (bound, handle, handoff) = match sensor_adb::start_test_server_with_handoff(
        config.bind_addr,
        config.log_path,
        config.spool_dir,
        wan_resolver,
        config.bounds,
        config.collector_id,
        config.outbox_dir,
        Arc::new(CaptureMemoryBudget::new(config.capture_memory_bytes)),
        command_events.clone(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let e = sensor_framework::listener_start_error(config.bind_addr, e);
            tracing::error!("sensor-adb: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "sensor-adb: listening");
    handoff.start_stats("adb");

    shutdown_signal().await;
    tracing::info!("sensor-adb: shutdown signal received; stopping");
    handle.abort();
    // The listener is stopped, so no new command reaches the gate: write the summaries still
    // accumulating, bounded by the window table's capacity and by this timeout.
    if tokio::time::timeout(
        SHUTDOWN_FLUSH_TIMEOUT,
        command_events.flush(&summary_emitter, Arrival::new(bound.port())),
    )
    .await
    .is_err()
    {
        tracing::warn!("sensor-adb: command summaries not all written before shutdown");
    }
    // Cuts live connections (their captures are recorded as truncated), then drains the queue.
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:5555");

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "5555")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:5555".parse().unwrap());
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.spool_dir, PathBuf::from(DEFAULT_SPOOL_DIR));
        assert_eq!(
            c.outbox_dir,
            PathBuf::from("/var/spool/propolis/adb/outbox")
        );
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(600));
        assert_eq!(c.bounds.max_captured_bytes, 1_000_000);
        assert_eq!(c.bounds.max_concurrent, 256);
        // 40% of the unit's 256M MemoryMax.
        assert_eq!(c.capture_memory_bytes, 107_374_182);
        assert_eq!(c.command_events, CommandEventConfig::default());
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
            load_config(&Env::from_table(&[BIND, (ENV_WAN_MAP, "not-valid")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn outbox_defaults_under_the_spool_root() {
        // With no PROPOLIS_ADB_OUTBOX_DIR override, the outbox must sit under the resolved
        // spool dir, which is inside the sensor's systemd ReadWritePaths (unlike the old
        // shared /var/lib/propolis/outbox default).
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, None);
        assert_eq!(outbox_dir, PathBuf::from("/custom/spool/outbox"));
    }

    #[test]
    fn explicit_outbox_override_still_wins() {
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, Some("/explicit/outbox".to_string()));
        assert_eq!(outbox_dir, PathBuf::from("/explicit/outbox"));
    }
}
