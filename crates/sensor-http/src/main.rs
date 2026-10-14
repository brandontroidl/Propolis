use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{
    ConnectionBounds, Env, EnvError, TlsServer, WanResolver, listener_start_error, shutdown_signal,
};

/// Every allocation is charged to the session it was made in (`session_memory`).
#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

const ENV_BIND: &str = "PROPOLIS_HTTP_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_HTTP_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_HTTP_LOG_PATH";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_HTTP_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_HTTP_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_HTTP_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_HTTP_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_HTTP_MAX_CONCURRENT";

const ENV_TLS_BIND: &str = "PROPOLIS_HTTP_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_HTTP_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_HTTP_TLS_KEY";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/http/events.jsonl";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
const DEFAULT_MAX_CAPTURED_BYTES: u64 = 1_000_000;
const DEFAULT_MAX_CONCURRENT: u32 = 512;

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    bounds: ConnectionBounds,
    tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, PartialEq)]
struct TlsConfig {
    /// `None` when only the cert and key are set: the pair is still loaded and validated, but no
    /// TLS listener starts, because the fleet inventory derives from explicit `*_BIND` vars.
    bind_addr: Option<SocketAddr>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    NoBind,
    /// The named cert or key env var was unset or blank while TLS was asked for by the other
    /// path var or by `PROPOLIS_HTTP_TLS_BIND`.
    TlsPathMissing(&'static str),
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
            ConfigError::NoBind => {
                write!(f, "{ENV_BIND} must be set to a single ip:port bind address")
            }
            ConfigError::TlsPathMissing(var) => write!(
                f,
                "{var} must be set to a PEM file path (TLS needs both {ENV_TLS_CERT} and {ENV_TLS_KEY})"
            ),
            ConfigError::Env(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// TLS is enabled iff both the cert and key paths are set. Inputs come from `sensor_framework::Env`,
/// already trimmed with blank read as unset and the bind already parsed. Anything less than a pair
/// while TLS was asked for, by one path var or by a bind, is a refusal: the caller exits rather
/// than serving plaintext where TLS was intended. With no TLS var set at all the sensor behaves
/// exactly as before. The TLS bind has no compiled default.
fn parse_tls(
    bind_addr: Option<SocketAddr>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    let (cert_path, key_path) = (cert.map(PathBuf::from), key.map(PathBuf::from));
    match (bind_addr, cert_path, key_path) {
        (None, None, None) => Ok(None),
        (_, None, _) => Err(ConfigError::TlsPathMissing(ENV_TLS_CERT)),
        (_, _, None) => Err(ConfigError::TlsPathMissing(ENV_TLS_KEY)),
        (bind_addr, Some(cert_path), Some(key_path)) => Ok(Some(TlsConfig {
            bind_addr,
            cert_path,
            key_path,
        })),
    }
}

fn load_config(env: &Env) -> Result<Config, ConfigError> {
    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
        tls: parse_tls(
            env.socket_addr(ENV_TLS_BIND)?,
            env.string(ENV_TLS_CERT)?.as_deref(),
            env.string(ENV_TLS_KEY)?.as_deref(),
        )?,
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
            tracing::error!(error = %e, "sensor-http: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Load the cert and key before binding anything (plaintext included): a misconfigured TLS
    // pair must not leave a half-configured sensor serving.
    let tls_server = match &config.tls {
        Some(t) => match sensor_framework::load_server_config(&t.cert_path, &t.key_path) {
            Ok(server_config) => match t.bind_addr {
                Some(addr) => Some((addr, TlsServer::from_config(server_config))),
                None => {
                    tracing::warn!(
                        "sensor-http: {ENV_TLS_CERT} and {ENV_TLS_KEY} loaded but {ENV_TLS_BIND} is unset; no TLS listener started"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::error!(
                    cert = %t.cert_path.display(), key = %t.key_path.display(), error = %e,
                    "sensor-http: TLS configured but cert/key unusable; refusing to start"
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    // Both listeners' sessions share one pool, so it is sized for both at once; every admitted
    // session must fit in it at its floor.
    let listeners = if tls_server.is_some() { 2 } else { 1 };
    if let Err(e) = session_memory::configure(
        sensor_http::SESSION_MEMORY_POOL_BYTES,
        config.bounds.max_concurrent.saturating_mul(listeners),
    ) {
        tracing::error!(error = %e, "sensor-http: invalid configuration; refusing to start");
        std::process::exit(1);
    }
    tokio::spawn(session_memory::watchdog());

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    let (bound, handle) = match sensor_http::start_test_server(
        config.bind_addr,
        config.log_path.clone(),
        wan_resolver.clone(),
        config.bounds.clone(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let e = listener_start_error(config.bind_addr, e);
            tracing::error!("sensor-http: {e}; refusing to start");
            std::process::exit(1);
        }
    };
    tracing::info!(local = %bound, "sensor-http: listening");

    let tls_handle = match tls_server {
        Some((addr, server)) => {
            match sensor_http::start_test_server_tls(
                addr,
                config.log_path,
                wan_resolver,
                config.bounds,
                server,
            )
            .await
            {
                Ok((bound, tls_handle)) => {
                    tracing::info!(local = %bound, "sensor-http: listening (tls)");
                    Some(tls_handle)
                }
                Err(e) => {
                    handle.abort();
                    let e = listener_start_error(addr, e);
                    tracing::error!("sensor-http: {e}; refusing to start");
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    shutdown_signal().await;
    tracing::info!("sensor-http: shutdown signal received; stopping");
    handle.abort();
    if let Some(h) = tls_handle {
        h.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:80");

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "80")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:80".parse().unwrap());
        assert!(c.wan_map.is_empty());
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.tls, None);
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(600));
        assert_eq!(c.bounds.max_captured_bytes, 1_000_000);
        // 512, not the other sensors' 256.
        assert_eq!(c.bounds.max_concurrent, 512);
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
    fn the_default_bounds_on_both_listeners_fit_the_session_memory_pool() {
        // Both listeners at the default, as the binary configures it with TLS bound.
        session_memory::configure(
            sensor_http::SESSION_MEMORY_POOL_BYTES,
            DEFAULT_MAX_CONCURRENT * 2,
        )
        .expect("1,024 sessions have slots and a usable share");
    }

    fn tls_cfg(bind: Option<&str>) -> TlsConfig {
        TlsConfig {
            bind_addr: bind.map(|b| b.parse().unwrap()),
            cert_path: "/etc/propolis/tls/http.crt".into(),
            key_path: "/etc/propolis/tls/http.key".into(),
        }
    }

    const CRT: Option<&str> = Some("/etc/propolis/tls/http.crt");
    const KEY: Option<&str> = Some("/etc/propolis/tls/http.key");
    const TLS_BIND: Option<SocketAddr> = Some(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        443,
    ));

    #[test]
    fn parse_tls_unset_is_none() {
        // Blank values never reach here: the env reader reads them as unset.
        assert_eq!(parse_tls(None, None, None), Ok(None));
    }

    #[test]
    fn parse_tls_full_is_some() {
        assert_eq!(
            parse_tls(TLS_BIND, CRT, KEY),
            Ok(Some(tls_cfg(Some("0.0.0.0:443"))))
        );
    }

    #[test]
    fn parse_tls_both_paths_without_a_bind_has_no_listener_address() {
        assert_eq!(parse_tls(None, CRT, KEY), Ok(Some(tls_cfg(None))));
    }

    #[test]
    fn parse_tls_exactly_one_path_is_refused() {
        assert_eq!(
            parse_tls(None, None, KEY),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
        assert_eq!(
            parse_tls(None, CRT, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
        assert_eq!(
            parse_tls(TLS_BIND, CRT, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
    }

    #[test]
    fn parse_tls_bind_without_both_paths_is_refused() {
        assert_eq!(
            parse_tls(TLS_BIND, None, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }
}
