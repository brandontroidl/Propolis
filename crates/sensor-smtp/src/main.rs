use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver, shutdown_signal};

const ENV_BIND: &str = "PROPOLIS_SMTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_SMTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_SMTP_LOG_PATH";

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
    raw.and_then(|s| s.parse::<u64>().ok()).filter(|&v| v > 0).unwrap_or(default)
}

fn parse_positive_u32(raw: Option<&str>, default: u32) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok()).filter(|&v| v > 0).unwrap_or(default)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let bind_raw = match env::var(ENV_BIND) {
        Ok(v) => v,
        Err(_) => { tracing::error!("{ENV_BIND} must be set"); std::process::exit(1); }
    };
    let bind_addr: SocketAddr = match bind_raw.trim().parse() {
        Ok(a) => a,
        Err(_) => { tracing::error!("invalid {ENV_BIND}: {bind_raw:?}"); std::process::exit(1); }
    };

    let wan_map = parse_wan_map(&env::var(ENV_WAN_MAP).unwrap_or_default());
    let log_path = env::var(ENV_LOG_PATH).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_PATH));

    let bounds = ConnectionBounds {
        read_timeout: Duration::from_millis(parse_positive_u64(env::var("PROPOLIS_SMTP_READ_TIMEOUT_MS").ok().as_deref(), 30_000)),
        idle_timeout: Duration::from_millis(parse_positive_u64(env::var("PROPOLIS_SMTP_IDLE_TIMEOUT_MS").ok().as_deref(), 60_000)),
        max_duration: Duration::from_secs(parse_positive_u64(env::var("PROPOLIS_SMTP_MAX_DURATION_SECS").ok().as_deref(), 600)),
        max_captured_bytes: parse_positive_u64(env::var("PROPOLIS_SMTP_MAX_CAPTURED_BYTES").ok().as_deref(), 1_000_000),
        max_concurrent: parse_positive_u32(env::var("PROPOLIS_SMTP_MAX_CONCURRENT").ok().as_deref(), 256),
    };

    let wan_resolver = Arc::new(WanResolver::new(wan_map));
    let (bound, handle) = match sensor_smtp::start_test_server(bind_addr, log_path, wan_resolver, bounds).await {
        Ok(pair) => pair,
        Err(e) => { tracing::error!(addr = %bind_addr, error = %e, "sensor-smtp: failed to start"); std::process::exit(1); }
    };

    tracing::info!(local = %bound, "sensor-smtp: listening");
    shutdown_signal().await;
    tracing::info!("sensor-smtp: shutdown signal received; stopping");
    handle.abort();
}
