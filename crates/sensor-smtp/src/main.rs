use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver, shutdown_signal};

const ENV_BIND: &str = "PROPOLIS_SMTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_SMTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_SMTP_LOG_PATH";
const ENV_SUBMISSION_BIND: &str = "PROPOLIS_SMTP_SUBMISSION_BIND";
const ENV_TLS_BIND: &str = "PROPOLIS_SMTP_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_SMTP_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_SMTP_TLS_KEY";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/smtp/events.jsonl";

fn parse_wan_map(raw: &str) -> HashMap<IpAddr, IpAddr> {
    let mut map = HashMap::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((local, wan)) = entry.split_once('=')
            && let (Ok(l), Ok(w)) = (local.trim().parse::<IpAddr>(), wan.trim().parse::<IpAddr>())
        {
            map.insert(l, w);
        }
    }
    map
}

fn parse_positive_u64(raw: Option<&str>, default: u64) -> u64 {
    raw.and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn parse_positive_u32(raw: Option<&str>, default: u32) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

/// Read through `sensor_framework::strict_env_var`: unset or blank is `None`, and a non-UTF-8
/// value refuses to start, so no variable is ever silently read as unset or defaulted.
fn env_or_exit(var: &str) -> Option<String> {
    match sensor_framework::strict_env_var(var) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(error = %e, "sensor-smtp: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    }
}

/// Unset or blank means "not configured". Anything else must parse or the sensor refuses to
/// start: a typo must not silently drop a listener the derived fleet inventory will claim exists.
fn optional_bind(var: &str) -> Option<SocketAddr> {
    let raw = env_or_exit(var)?;
    match raw.parse() {
        Ok(addr) => Some(addr),
        Err(_) => {
            tracing::error!("sensor-smtp: invalid {var}: {raw:?}; refusing to start");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    sensor_framework::init_logging();

    let Some(bind_raw) = env_or_exit(ENV_BIND) else {
        tracing::error!("{ENV_BIND} must be set");
        std::process::exit(1);
    };
    let bind_addr: SocketAddr = match bind_raw.trim().parse() {
        Ok(a) => a,
        Err(_) => {
            tracing::error!("invalid {ENV_BIND}: {bind_raw:?}");
            std::process::exit(1);
        }
    };

    let wan_map = parse_wan_map(&env_or_exit(ENV_WAN_MAP).unwrap_or_default());
    let log_path = env_or_exit(ENV_LOG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_PATH));

    let bounds = ConnectionBounds {
        read_timeout: Duration::from_millis(parse_positive_u64(
            env_or_exit("PROPOLIS_SMTP_READ_TIMEOUT_MS").as_deref(),
            30_000,
        )),
        idle_timeout: Duration::from_millis(parse_positive_u64(
            env_or_exit("PROPOLIS_SMTP_IDLE_TIMEOUT_MS").as_deref(),
            60_000,
        )),
        max_duration: Duration::from_secs(parse_positive_u64(
            env_or_exit("PROPOLIS_SMTP_MAX_DURATION_SECS").as_deref(),
            600,
        )),
        max_captured_bytes: parse_positive_u64(
            env_or_exit("PROPOLIS_SMTP_MAX_CAPTURED_BYTES").as_deref(),
            1_000_000,
        ),
        max_concurrent: parse_positive_u32(
            env_or_exit("PROPOLIS_SMTP_MAX_CONCURRENT").as_deref(),
            256,
        ),
    };

    // All configuration is validated before the first socket is bound, so a bad TLS setup never
    // leaves a plaintext listener running.
    let submission_bind = optional_bind(ENV_SUBMISSION_BIND);
    let tls_bind = optional_bind(ENV_TLS_BIND);
    let tls = match sensor_smtp::tls_from_env(
        ENV_TLS_CERT,
        ENV_TLS_KEY,
        tls_bind.is_some(),
        sensor_framework::strict_env_var,
    ) {
        Ok(tls) => tls,
        Err(e) => {
            tracing::error!(error = %e, "sensor-smtp: invalid TLS configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let listeners = match sensor_smtp::plan_listeners(bind_addr, submission_bind, tls_bind, tls) {
        Ok(listeners) => listeners,
        Err(e) => {
            tracing::error!("sensor-smtp: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    let wan_resolver = Arc::new(WanResolver::new(wan_map));
    let started =
        match sensor_smtp::start_listeners(listeners, log_path, wan_resolver, bounds).await {
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
