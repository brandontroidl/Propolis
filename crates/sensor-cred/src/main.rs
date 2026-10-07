use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver, shutdown_signal};

const DEFAULT_LOG_DIR: &str = "/var/log/propolis/cred";
const TLS_CERT_VAR: &str = "PROPOLIS_CRED_TLS_CERT";
const TLS_KEY_VAR: &str = "PROPOLIS_CRED_TLS_KEY";

struct PortConfig {
    protocol: &'static str,
    bind: SocketAddr,
}

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

#[tokio::main]
async fn main() {
    sensor_framework::init_logging();

    let wan_map = parse_wan_map(&env::var("PROPOLIS_CRED_WAN_MAP").unwrap_or_default());
    let wan_resolver = Arc::new(WanResolver::new(wan_map));
    let log_dir = env::var("PROPOLIS_CRED_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_DIR));

    let bounds = ConnectionBounds {
        read_timeout: Duration::from_millis(parse_positive_u64(
            env::var("PROPOLIS_CRED_READ_TIMEOUT_MS").ok().as_deref(),
            30_000,
        )),
        idle_timeout: Duration::from_millis(parse_positive_u64(
            env::var("PROPOLIS_CRED_IDLE_TIMEOUT_MS").ok().as_deref(),
            60_000,
        )),
        max_duration: Duration::from_secs(parse_positive_u64(
            env::var("PROPOLIS_CRED_MAX_DURATION_SECS").ok().as_deref(),
            60,
        )),
        max_captured_bytes: parse_positive_u64(
            env::var("PROPOLIS_CRED_MAX_CAPTURED_BYTES").ok().as_deref(),
            100_000,
        ),
        max_concurrent: parse_positive_u32(
            env::var("PROPOLIS_CRED_MAX_CONCURRENT").ok().as_deref(),
            256,
        ),
    };

    // Parse per-protocol bind addresses from env
    let mut ports = Vec::new();
    for (env_key, protocol) in [
        ("PROPOLIS_CRED_VNC_BIND", "vnc"),
        ("PROPOLIS_CRED_MYSQL_BIND", "mysql"),
        ("PROPOLIS_CRED_MSSQL_BIND", "mssql"),
        ("PROPOLIS_CRED_PG_BIND", "postgresql"),
        ("PROPOLIS_CRED_MONGO_BIND", "mongodb"),
    ] {
        if let Ok(bind_str) = env::var(env_key) {
            if let Ok(bind) = bind_str.trim().parse::<SocketAddr>() {
                ports.push(PortConfig { protocol, bind });
            } else {
                tracing::error!(env = env_key, value = %bind_str, "invalid bind address");
                std::process::exit(1);
            }
        }
    }

    // Fail closed: either TLS var set means the pair must load, or nothing binds at all. Read
    // through tls_env_var, so a blank value is unset and a non-UTF-8 one is an error.
    let tls_var = |var: &str| match sensor_framework::tls_env_var(var) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(error = %e, "sensor-cred: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };
    let tls = match (tls_var(TLS_CERT_VAR), tls_var(TLS_KEY_VAR)) {
        (None, None) => None,
        (Some(cert), Some(key)) => {
            match sensor_cred::CredTls::from_files(Path::new(&cert), Path::new(&key)) {
                Ok(tls) => {
                    tracing::info!(
                        "sensor-cred: TLS enabled for postgresql, mysql, mssql and mongodb"
                    );
                    Some(tls)
                }
                Err(e) => {
                    tracing::error!(error = %e, "sensor-cred: TLS is configured but the certificate or key cannot be loaded; refusing to start");
                    std::process::exit(1);
                }
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            tracing::error!(
                "sensor-cred: TLS needs both {TLS_CERT_VAR} and {TLS_KEY_VAR}, but only one is set; refusing to start"
            );
            std::process::exit(1);
        }
    };

    if ports.is_empty() {
        tracing::error!(
            "sensor-cred: no bind addresses configured; set at least one PROPOLIS_CRED_*_BIND"
        );
        std::process::exit(1);
    }

    // Unlike sensors whose TLS adds a listener, a bind failure here skips that one protocol: the
    // five are independent traps and TLS adds no listener whose loss could hide behind the others.
    let mut handles = Vec::new();
    for pc in &ports {
        let log_path = log_dir.join(format!("{}.jsonl", pc.protocol));
        match sensor_cred::start_listener(
            pc.bind,
            log_path,
            wan_resolver.clone(),
            bounds.clone(),
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
