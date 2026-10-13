use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, Env, EnvError,
    SHUTDOWN_DRAIN_TIMEOUT, TlsServer, WanResolver, load_server_config, shutdown_signal,
};

const ENV_BIND: &str = "PROPOLIS_FTP_BIND";
/// Optional implicit-FTPS listener (990). Needs both `_TLS_CERT` and `_TLS_KEY`.
const ENV_TLS_BIND: &str = "PROPOLIS_FTP_TLS_BIND";
/// Cert and key paths. TLS is enabled iff BOTH are set; AUTH TLS on `PROPOLIS_FTP_BIND` is honoured
/// only then.
const ENV_TLS_CERT: &str = "PROPOLIS_FTP_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_FTP_TLS_KEY";
const ENV_WAN_MAP: &str = "PROPOLIS_FTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_FTP_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_FTP_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_FTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_FTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_FTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_FTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_FTP_MAX_CONCURRENT";
/// Shared across every sensor binary AND `shipper` on this collector (see sensor-ssh's own
/// `main.rs` for why): must match the shipper's client certificate CommonName.
const ENV_COLLECTOR_ID: &str = "PROPOLIS_COLLECTOR_ID";
/// Pre-rename bare spelling, still read via [`sensor_framework::env_with_legacy`] when
/// `PROPOLIS_COLLECTOR_ID` is unset (see sensor-ssh's own `main.rs` for why).
const ENV_COLLECTOR_ID_LEGACY: &str = "COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_FTP_OUTBOX_DIR";
/// Ceiling, in bytes, on capture bodies buffered in memory across every connection. Defaults to
/// 40% of the unit's 256M `MemoryMax` (see `deploy/sensor-ftp.service`).
const ENV_CAPTURE_MEMORY_BYTES: &str = "PROPOLIS_FTP_CAPTURE_MEMORY_BYTES";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/ftp/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/ftp";
const DEFAULT_COLLECTOR_ID: &str = "local";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

#[derive(Debug, PartialEq)]
enum ConfigError {
    NoBind,
    /// Exactly one of cert/key set, or a TLS bind without both. Names the variables only.
    TlsIncomplete(&'static str),
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
            ConfigError::TlsIncomplete(why) => write!(f, "{why}"),
            ConfigError::Env(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    tls_bind: Option<SocketAddr>,
    /// Cert and key paths, present iff TLS is enabled.
    tls_paths: Option<(PathBuf, PathBuf)>,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_memory_bytes: u64,
}

impl std::error::Error for ConfigError {}

/// Resolve the outbox directory: the explicit `PROPOLIS_FTP_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_FTP_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
}

/// Inputs come from `sensor_framework::Env`, already trimmed with blank read as unset. Both set
/// enables TLS; exactly one set, or a TLS bind without both, is an error so a half-configured
/// sensor never starts (and never binds a plaintext port the operator believed was protected).
fn tls_paths(
    cert: Option<String>,
    key: Option<String>,
    tls_bind_set: bool,
) -> Result<Option<(PathBuf, PathBuf)>, ConfigError> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((PathBuf::from(c), PathBuf::from(k)))),
        (None, None) if tls_bind_set => Err(ConfigError::TlsIncomplete(
            "PROPOLIS_FTP_TLS_BIND is set but PROPOLIS_FTP_TLS_CERT and PROPOLIS_FTP_TLS_KEY are not",
        )),
        (None, None) => Ok(None),
        _ => Err(ConfigError::TlsIncomplete(
            "PROPOLIS_FTP_TLS_CERT and PROPOLIS_FTP_TLS_KEY must be set together",
        )),
    }
}

fn load_config(env: &Env) -> Result<Config, ConfigError> {
    // A non-UTF-8 or malformed value is invalid, never unset: reading it as unset would silently
    // skip the 990 listener or turn TLS off.
    let tls_bind = env.socket_addr(ENV_TLS_BIND)?;
    let tls_paths = tls_paths(
        env.string(ENV_TLS_CERT)?,
        env.string(ENV_TLS_KEY)?,
        tls_bind.is_some(),
    )?;
    let spool_dir = env.path(ENV_SPOOL_DIR, DEFAULT_SPOOL_DIR)?;
    let outbox_dir = resolve_outbox_dir(&spool_dir, env.string(ENV_OUTBOX_DIR)?);

    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        tls_bind,
        tls_paths,
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
            tracing::error!(error = %e, "sensor-ftp: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let bind_addr = config.bind_addr;
    let tls_bind = config.tls_bind;
    let wan_map = config.wan_map;
    let log_path = config.log_path;
    let spool_dir = config.spool_dir;
    let bounds = config.bounds;
    let collector_id = config.collector_id;
    let outbox_dir = config.outbox_dir;
    let capture_memory_bytes = config.capture_memory_bytes;

    // Validated and loaded BEFORE any socket is bound, so a bad TLS config never leaves a
    // plaintext listener running.
    let tls = match config.tls_paths {
        None => None,
        Some((cert, key)) => match load_server_config(&cert, &key) {
            Ok(server_config) => Some(TlsServer::from_config(server_config)),
            Err(e) => {
                tracing::error!(error = %e, "sensor-ftp: invalid TLS configuration; refusing to start");
                std::process::exit(1);
            }
        },
    };
    let listeners = match sensor_ftp::plan_listeners(bind_addr, tls_bind, tls) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("sensor-ftp: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    let wan_resolver = Arc::new(WanResolver::new(wan_map));
    let (started, handoff) = match sensor_ftp::start_listeners(
        listeners,
        log_path,
        spool_dir,
        wan_resolver,
        bounds,
        collector_id,
        outbox_dir,
        Arc::new(CaptureMemoryBudget::new(capture_memory_bytes)),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!("sensor-ftp: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    for (bound, _) in &started {
        tracing::info!(local = %bound, "sensor-ftp: listening");
    }
    handoff.start_stats("ftp");
    shutdown_signal().await;
    tracing::info!("sensor-ftp: shutdown signal received; stopping");
    for (_, handle) in &started {
        handle.abort();
    }
    // Cuts live connections (their captures are recorded as truncated), then drains the queue.
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:21");

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "21")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:21".parse().unwrap());
        assert_eq!(c.tls_bind, None);
        assert_eq!(c.tls_paths, None);
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.spool_dir, PathBuf::from(DEFAULT_SPOOL_DIR));
        assert_eq!(
            c.outbox_dir,
            PathBuf::from("/var/spool/propolis/ftp/outbox")
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

    #[test]
    fn outbox_defaults_under_the_spool_root() {
        // With no PROPOLIS_FTP_OUTBOX_DIR override, the outbox must sit under the resolved
        // spool dir, which is inside the sensor's systemd ReadWritePaths (unlike the old
        // shared /var/lib/propolis/outbox default).
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, None);
        assert_eq!(outbox_dir, PathBuf::from("/custom/spool/outbox"));
    }

    #[test]
    fn tls_is_enabled_only_by_a_complete_pair_and_fails_closed() {
        // Blank values never reach here: the env reader reads them as unset.
        let some = |s: &str| Some(s.to_string());
        assert!(tls_paths(None, None, false).unwrap().is_none());
        assert!(tls_paths(some("/c"), some("/k"), false).unwrap().is_some());
        assert!(tls_paths(some("/c"), some("/k"), true).unwrap().is_some());
        assert!(tls_paths(some("/c"), None, false).is_err());
        assert!(tls_paths(None, some("/k"), false).is_err());
        assert!(tls_paths(some("/c"), None, true).is_err());
        assert!(tls_paths(None, None, true).is_err());
    }

    #[test]
    fn explicit_outbox_override_still_wins() {
        let spool_dir = PathBuf::from("/custom/spool");
        let outbox_dir = resolve_outbox_dir(&spool_dir, Some("/explicit/outbox".to_string()));
        assert_eq!(outbox_dir, PathBuf::from("/explicit/outbox"));
    }
}
