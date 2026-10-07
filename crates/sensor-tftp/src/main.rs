use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, EnvError,
    SHUTDOWN_DRAIN_TIMEOUT, WanResolver, shutdown_signal, strict_env_var,
};
use sensor_tftp::handler::MAX_BODY_HARD_CAP;

/// Required, with no default: the sensor is off until an operator names a bind address. TFTP lets
/// anyone on the network make the host send UDP, so a sensor that listened on a built-in address
/// would be exposed by installing the package.
const ENV_BIND: &str = "PROPOLIS_TFTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_TFTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_TFTP_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_TFTP_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_TFTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_TFTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_TFTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_TFTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_TFTP_MAX_CONCURRENT";
/// Shared across every sensor binary AND `shipper` on this collector (see sensor-ssh's own
/// `main.rs` for why): must match the shipper's client certificate CommonName. No legacy bare
/// spelling is read: this sensor never shipped under one.
const ENV_COLLECTOR_ID: &str = "PROPOLIS_COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_TFTP_OUTBOX_DIR";
/// Ceiling, in bytes, on capture bodies buffered in memory across every transfer. Defaults to 40%
/// of the unit's 256M `MemoryMax` (see `deploy/sensor-tftp.service`).
const ENV_CAPTURE_MEMORY_BYTES: &str = "PROPOLIS_TFTP_CAPTURE_MEMORY_BYTES";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/tftp/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/tftp";
const DEFAULT_COLLECTOR_ID: &str = "local";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
/// Sized against `MemoryMax=256M` in `deploy/sensor-tftp.service`. Worst case in flight is every
/// concurrent WRQ holding a full-cap body, plus a full capture queue of full-cap bodies, plus the
/// process baseline: 128 * 1 MB + 64 * 1 MB + ~15 MB = ~207 MB, under the 268 MB limit with room
/// for Vec growth slack. Raising this, or `PROPOLIS_TFTP_MAX_CAPTURED_BYTES`, without lowering
/// the other lets a single-host WRQ flood OOM the unit (`default_memory_budget_fits_memory_max`).
const DEFAULT_MAX_CONCURRENT: u32 = 128;

#[derive(Debug)]
enum ConfigError {
    NoBind,
    InvalidBind(String),
    InvalidWanMapEntry(String),
    InvalidBound {
        field: &'static str,
        value: String,
    },
    BoundTooLarge {
        field: &'static str,
        max: u64,
    },
    /// An env var held bytes that are not valid UTF-8; never read as unset.
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
                write!(f, "{ENV_BIND} must be set (the sensor is off by default)")
            }
            ConfigError::InvalidBind(s) => write!(f, "invalid {ENV_BIND}: {s:?}"),
            ConfigError::InvalidWanMapEntry(s) => write!(f, "invalid {ENV_WAN_MAP} entry: {s:?}"),
            ConfigError::InvalidBound { field, value } => {
                write!(f, "{field} must be positive, got {value:?}")
            }
            ConfigError::BoundTooLarge { field, max } => {
                write!(f, "{field} must be at most {max}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

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
}

/// Resolve the outbox directory: the explicit `PROPOLIS_TFTP_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_TFTP_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
}

/// Build the configuration from a variable lookup (the process environment in `main`, a map in the
/// tests). A missing bind, a malformed value, or a zero or oversized bound is an error: the caller
/// exits without binding anything, and no default ever stands in for a bad value.
fn load_config_from(
    get: impl Fn(&str) -> Result<Option<String>, EnvError>,
) -> Result<Config, ConfigError> {
    let bind_raw = get(ENV_BIND)?.ok_or(ConfigError::NoBind)?;
    let bind_addr: SocketAddr = bind_raw
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;
    let wan_map = parse_wan_map(&get(ENV_WAN_MAP)?.unwrap_or_default())?;
    let log_path = get(ENV_LOG_PATH)?
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_PATH));
    let spool_dir = get(ENV_SPOOL_DIR)?
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SPOOL_DIR));
    let outbox_dir = resolve_outbox_dir(&spool_dir, get(ENV_OUTBOX_DIR)?);
    let collector_id = get(ENV_COLLECTOR_ID)?.unwrap_or_else(|| DEFAULT_COLLECTOR_ID.to_string());

    let max_captured_bytes = parse_positive_u64(
        get(ENV_MAX_CAPTURED_BYTES)?.as_deref(),
        DEFAULT_MAX_CAPTURED_BYTES,
        ENV_MAX_CAPTURED_BYTES,
    )?;
    if max_captured_bytes > MAX_BODY_HARD_CAP {
        return Err(ConfigError::BoundTooLarge {
            field: ENV_MAX_CAPTURED_BYTES,
            max: MAX_BODY_HARD_CAP,
        });
    }

    Ok(Config {
        bind_addr,
        wan_map,
        log_path,
        spool_dir,
        collector_id,
        outbox_dir,
        capture_memory_bytes: parse_positive_u64(
            get(ENV_CAPTURE_MEMORY_BYTES)?.as_deref(),
            DEFAULT_CAPTURE_BUDGET_BYTES_256M,
            ENV_CAPTURE_MEMORY_BYTES,
        )?,
        bounds: ConnectionBounds {
            read_timeout: Duration::from_millis(parse_positive_u64(
                get(ENV_READ_TIMEOUT_MS)?.as_deref(),
                DEFAULT_READ_TIMEOUT_MS,
                ENV_READ_TIMEOUT_MS,
            )?),
            idle_timeout: Duration::from_millis(parse_positive_u64(
                get(ENV_IDLE_TIMEOUT_MS)?.as_deref(),
                DEFAULT_IDLE_TIMEOUT_MS,
                ENV_IDLE_TIMEOUT_MS,
            )?),
            max_duration: Duration::from_secs(parse_positive_u64(
                get(ENV_MAX_DURATION_SECS)?.as_deref(),
                DEFAULT_MAX_DURATION_SECS,
                ENV_MAX_DURATION_SECS,
            )?),
            max_captured_bytes,
            max_concurrent: parse_positive_u32(
                get(ENV_MAX_CONCURRENT)?.as_deref(),
                DEFAULT_MAX_CONCURRENT,
                ENV_MAX_CONCURRENT,
            )?,
        },
    })
}

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

fn parse_positive_u64(
    raw: Option<&str>,
    default: u64,
    field: &'static str,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else { return Ok(default) };
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

fn parse_positive_u32(
    raw: Option<&str>,
    default: u32,
    field: &'static str,
) -> Result<u32, ConfigError> {
    let Some(raw) = raw else { return Ok(default) };
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

#[tokio::main]
async fn main() {
    sensor_framework::init_logging();

    let config = match load_config_from(strict_env_var) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-tftp: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let bind_addr = config.bind_addr;

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));
    let (bound, handle, handoff) = match sensor_tftp::start_test_server_with_handoff(
        bind_addr,
        config.log_path,
        config.spool_dir,
        wan_resolver,
        config.bounds,
        config.collector_id,
        config.outbox_dir,
        Arc::new(CaptureMemoryBudget::new(config.capture_memory_bytes)),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let e = sensor_framework::listener_start_error(bind_addr, e);
            tracing::error!("sensor-tftp: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "sensor-tftp: listening");
    shutdown_signal().await;
    tracing::info!("sensor-tftp: shutdown signal received; stopping");
    handle.abort();
    // Queued captures only; a transfer cancelled mid-capture never submits (see handoff.rs).
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<Option<String>, EnvError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| Ok(map.get(name).cloned())
    }

    fn load(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        load_config_from(vars(pairs))
    }

    #[test]
    fn a_non_utf8_variable_is_a_config_error_never_a_default() {
        let get = |name: &str| {
            if name == ENV_MAX_CONCURRENT {
                Err(EnvError::NotUnicode {
                    var: name.to_string(),
                })
            } else if name == ENV_BIND {
                Ok(Some("203.0.113.7:69".to_string()))
            } else {
                Ok(None)
            }
        };
        let err = load_config_from(get).expect_err("must not fall back to the default");
        assert!(matches!(err, ConfigError::Env(_)), "{err}");
        assert!(err.to_string().contains(ENV_MAX_CONCURRENT));
    }

    /// Default-off: with nothing configured the sensor refuses to start, so it can never bind a
    /// built-in address.
    #[test]
    fn no_bind_configured_is_an_error_and_binds_nothing() {
        assert!(matches!(load(&[]), Err(ConfigError::NoBind)));
        assert!(matches!(
            load(&[(ENV_LOG_PATH, "/tmp/x"), (ENV_MAX_CONCURRENT, "4")]),
            Err(ConfigError::NoBind)
        ));
    }

    #[test]
    fn malformed_bind_is_an_error() {
        for bad in ["", "69", "0.0.0.0", "not-an-addr:69", "203.0.113.7:99999"] {
            assert!(
                matches!(load(&[(ENV_BIND, bad)]), Err(ConfigError::InvalidBind(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let cfg = load(&[(ENV_BIND, "203.0.113.7:69")]).unwrap();
        assert_eq!(cfg.bind_addr, "203.0.113.7:69".parse().unwrap());
        assert_eq!(cfg.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(cfg.spool_dir, PathBuf::from(DEFAULT_SPOOL_DIR));
        assert_eq!(
            cfg.outbox_dir,
            PathBuf::from("/var/spool/propolis/tftp/outbox")
        );
        assert_eq!(cfg.bounds.max_captured_bytes, 1_000_000);
        assert_eq!(cfg.bounds.max_concurrent, 128);
        assert_eq!(cfg.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(cfg.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(cfg.bounds.max_duration, Duration::from_secs(600));
    }

    /// `MemoryMax=256M` in `deploy/sensor-tftp.service`. The defaults' worst case (every slot and
    /// every queue entry holding a full-cap body, plus baseline) must stay within 80% of it, so a
    /// WRQ flood from one host cannot OOM the unit.
    #[test]
    fn default_memory_budget_fits_memory_max() {
        const MEMORY_MAX: u64 = 256 * 1024 * 1024;
        const BASELINE: u64 = 15_000_000;
        let bodies = u64::from(DEFAULT_MAX_CONCURRENT) + sensor_tftp::CAPTURE_QUEUE_SIZE as u64;
        let worst = bodies * DEFAULT_MAX_CAPTURED_BYTES + BASELINE;
        assert!(
            worst <= MEMORY_MAX / 5 * 4,
            "default worst case {worst} bytes exceeds 80% of MemoryMax {MEMORY_MAX}"
        );
        let cfg = load(&[(ENV_BIND, "203.0.113.7:69")]).unwrap();
        assert_eq!(cfg.bounds.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(cfg.bounds.max_captured_bytes, DEFAULT_MAX_CAPTURED_BYTES);
    }

    #[test]
    fn a_zero_or_non_numeric_bound_is_an_error_not_a_disabled_guard() {
        for field in [
            ENV_READ_TIMEOUT_MS,
            ENV_IDLE_TIMEOUT_MS,
            ENV_MAX_DURATION_SECS,
            ENV_MAX_CAPTURED_BYTES,
            ENV_MAX_CONCURRENT,
            ENV_CAPTURE_MEMORY_BYTES,
        ] {
            for bad in ["0", "-1", "ten", ""] {
                let result = load(&[(ENV_BIND, "203.0.113.7:69"), (field, bad)]);
                assert!(
                    matches!(result, Err(ConfigError::InvalidBound { .. })),
                    "{field}={bad:?} must be rejected"
                );
            }
        }
    }

    #[test]
    fn capture_memory_ceiling_defaults_to_forty_percent_of_memory_max_and_is_overridable() {
        let cfg = load(&[(ENV_BIND, "203.0.113.7:69")]).unwrap();
        assert_eq!(cfg.capture_memory_bytes, 107_374_182);
        let cfg = load(&[
            (ENV_BIND, "203.0.113.7:69"),
            (ENV_CAPTURE_MEMORY_BYTES, "5000000"),
        ])
        .unwrap();
        assert_eq!(cfg.capture_memory_bytes, 5_000_000);
    }

    #[test]
    fn the_body_cap_cannot_exceed_the_spool_file_limit() {
        let at = MAX_BODY_HARD_CAP.to_string();
        assert!(load(&[(ENV_BIND, "203.0.113.7:69"), (ENV_MAX_CAPTURED_BYTES, &at)]).is_ok());
        let over = (MAX_BODY_HARD_CAP + 1).to_string();
        assert!(matches!(
            load(&[
                (ENV_BIND, "203.0.113.7:69"),
                (ENV_MAX_CAPTURED_BYTES, &over)
            ]),
            Err(ConfigError::BoundTooLarge { .. })
        ));
    }

    #[test]
    fn wan_map_parses_and_rejects_garbage() {
        let cfg = load(&[
            (ENV_BIND, "10.0.0.5:69"),
            (ENV_WAN_MAP, "10.0.0.5=198.51.100.4"),
        ])
        .unwrap();
        assert_eq!(
            cfg.wan_map.get(&"10.0.0.5".parse().unwrap()),
            Some(&"198.51.100.4".parse().unwrap())
        );
        assert!(matches!(
            load(&[(ENV_BIND, "10.0.0.5:69"), (ENV_WAN_MAP, "10.0.0.5")]),
            Err(ConfigError::InvalidWanMapEntry(_))
        ));
    }

    #[test]
    fn outbox_defaults_under_the_spool_root() {
        // With no PROPOLIS_TFTP_OUTBOX_DIR override, the outbox must sit under the resolved
        // spool dir, which is inside the sensor's systemd ReadWritePaths.
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
