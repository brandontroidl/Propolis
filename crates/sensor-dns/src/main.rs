//! sensor-dns: the DNS honeypot sensor binary. Serves UDP and TCP on `PROPOLIS_DNS_BIND` (both,
//! or it refuses to start) and, when `PROPOLIS_DNS_TLS_BIND` is set, DNS over TLS. See `lib.rs`
//! for the surfaces and the reply invariant.
//!
//! Configuration is environment variables only (the `ENV_*` constants below), every one read
//! through `sensor_framework::Env`. The sensor is off by default: with no bind it binds nothing
//! and exits. Every value is validated at startup and a malformed one refuses to start rather
//! than falling back to a default that could disable the bound it names.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    ConnectionBounds, Env, EnvError, Rate, RateLimitConfig, WanResolver, shutdown_signal,
};

const ENV_BIND: &str = "PROPOLIS_DNS_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_DNS_WAN_MAP";
const ENV_LOG_PATH: &str = "PROPOLIS_DNS_LOG_PATH";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_DNS_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_DNS_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_DNS_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_DNS_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_DNS_MAX_CONCURRENT";
const ENV_TLS_BIND: &str = "PROPOLIS_DNS_TLS_BIND";
const ENV_TLS_CERT: &str = "PROPOLIS_DNS_TLS_CERT";
const ENV_TLS_KEY: &str = "PROPOLIS_DNS_TLS_KEY";
const ENV_REPLY_RATE_PER_SOURCE: &str = "PROPOLIS_DNS_REPLY_RATE_PER_SOURCE";
const ENV_REPLY_BURST_PER_SOURCE: &str = "PROPOLIS_DNS_REPLY_BURST_PER_SOURCE";
const ENV_REPLY_RATE_GLOBAL: &str = "PROPOLIS_DNS_REPLY_RATE_GLOBAL";
const ENV_REPLY_BURST_GLOBAL: &str = "PROPOLIS_DNS_REPLY_BURST_GLOBAL";

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/dns/events.jsonl";
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 120;
/// The TCP/DoT bytes read per connection. Every message charges its 2-byte length prefix too, so
/// this is exactly enough for a connection's 64 queries at the 4096-byte maximum: 262_272.
const DEFAULT_MAX_CAPTURED_BYTES: u64 = (sensor_dns::stream::MAX_QUERIES_PER_CONNECTION
    * (2 + sensor_dns::stream::MAX_TCP_MESSAGE_BYTES))
    as u64;
/// Applied separately to the UDP handler pool, the TCP listener and the DoT listener.
const DEFAULT_MAX_CONCURRENT: u32 = 256;
/// UDP datagrams answered (and logged one by one) per second per source /24 or /56.
const DEFAULT_REPLY_RATE_PER_SOURCE: u32 = 5;
const DEFAULT_REPLY_BURST_PER_SOURCE: u32 = 10;
/// UDP datagrams answered per second across every source.
const DEFAULT_REPLY_RATE_GLOBAL: u32 = 1000;
const DEFAULT_REPLY_BURST_GLOBAL: u32 = 2000;
/// How long shutdown waits to write the rate-limited summaries still accumulating.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    log_path: PathBuf,
    bounds: ConnectionBounds,
    rate: RateLimitConfig,
    tls: Option<TlsConfig>,
}

/// The DoT listener beside the plaintext pair.
#[derive(Debug, Clone, PartialEq)]
struct TlsConfig {
    /// `None` when a cert and key are configured without a TLS bind: validated, never listened on.
    bind_addr: Option<SocketAddr>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    NoBind,
    /// The named cert or key variable was unset or blank while the rest of the TLS configuration
    /// was present.
    TlsPathMissing(&'static str),
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses (a malformed
    /// address, a zero or unparseable bound or rate, a bad WAN map entry); never read as unset.
    /// Zero never means unlimited, and a rate can never be configured off.
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
                write!(f, "{ENV_BIND} must be set (the sensor is off by default)")
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

/// `None` only when nothing TLS-related is configured. A bind without the pair, or exactly one of
/// the pair, is an error so the sensor refuses to start rather than run without the TLS that was
/// asked for. A pair without a bind parses (the caller still validates the files) but yields no
/// listener: the fleet inventory derives from the `*_BIND` variables.
fn parse_tls(
    bind_addr: Option<SocketAddr>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsConfig>, ConfigError> {
    if bind_addr.is_none() && cert.is_none() && key.is_none() {
        return Ok(None);
    }
    let cert_path = cert
        .map(PathBuf::from)
        .ok_or(ConfigError::TlsPathMissing(ENV_TLS_CERT))?;
    let key_path = key
        .map(PathBuf::from)
        .ok_or(ConfigError::TlsPathMissing(ENV_TLS_KEY))?;
    Ok(Some(TlsConfig {
        bind_addr,
        cert_path,
        key_path,
    }))
}

/// Load the configuration through `env` (in production the process environment), so the rules
/// are testable without touching the process environment.
fn load_config(env: &Env) -> Result<Config, ConfigError> {
    let per_source = Rate::new(
        env.positive_u32(ENV_REPLY_RATE_PER_SOURCE, DEFAULT_REPLY_RATE_PER_SOURCE)?,
        env.positive_u32(ENV_REPLY_BURST_PER_SOURCE, DEFAULT_REPLY_BURST_PER_SOURCE)?,
    );
    let global = Rate::new(
        env.positive_u32(ENV_REPLY_RATE_GLOBAL, DEFAULT_REPLY_RATE_GLOBAL)?,
        env.positive_u32(ENV_REPLY_BURST_GLOBAL, DEFAULT_REPLY_BURST_GLOBAL)?,
    );

    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
        rate: RateLimitConfig::new(per_source, global),
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
            tracing::error!(error = %e, "sensor-dns: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Load the cert and key before binding anything: a TLS misconfiguration must not leave the
    // plaintext listeners up.
    let tls_server = match &config.tls {
        Some(t) => match sensor_framework::load_server_config(&t.cert_path, &t.key_path) {
            Ok(server_config) => {
                let server = sensor_framework::TlsServer::from_config(server_config);
                match t.bind_addr {
                    Some(addr) => Some((addr, server)),
                    None => {
                        tracing::warn!(
                            "sensor-dns: {ENV_TLS_CERT} and {ENV_TLS_KEY} are valid but \
                             {ENV_TLS_BIND} is not set; no TLS listener started"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    cert = %t.cert_path.display(), key = %t.key_path.display(), error = %e,
                    "sensor-dns: TLS configured but cert/key unusable; refusing to start"
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));

    let plain = match sensor_dns::start_test_server(
        config.bind_addr,
        config.log_path.clone(),
        wan_resolver.clone(),
        config.bounds.clone(),
        config.rate,
    )
    .await
    {
        Ok(listeners) => listeners,
        Err(e) => {
            // `e` already names the transport and the address that failed.
            tracing::error!("sensor-dns: {e}; refusing to start");
            std::process::exit(1);
        }
    };
    tracing::info!(udp = %plain.udp, tcp = %plain.tcp, "sensor-dns: listening");

    let tls_handle = match tls_server {
        Some((addr, server)) => {
            match sensor_dns::start_test_server_tls(
                addr,
                config.log_path,
                wan_resolver,
                config.bounds,
                server,
            )
            .await
            {
                Ok((bound, handle)) => {
                    tracing::info!(local = %bound, "sensor-dns: listening (tls)");
                    Some(handle)
                }
                Err(e) => {
                    plain.abort();
                    tracing::error!("sensor-dns: {e}; refusing to start");
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    shutdown_signal().await;
    tracing::info!("sensor-dns: shutdown signal received; stopping");
    plain.abort();
    if let Some(h) = tls_handle {
        h.abort();
    }
    // The listeners are stopped, so the ledger can only shrink: write what it holds, bounded by
    // its fixed capacity and by this timeout.
    if tokio::time::timeout(SHUTDOWN_FLUSH_TIMEOUT, plain.flush_rate_limited())
        .await
        .is_err()
    {
        tracing::warn!("sensor-dns: rate-limited summaries not all written before shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_table(pairs)
    }

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:53");
    const CERT: &str = "/etc/propolis/tls/dns.crt";
    const KEY: &str = "/etc/propolis/tls/dns.key";
    const TLS_BIND: Option<SocketAddr> = Some(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        853,
    ));
    const BOUNDS: [&str; 5] = [
        ENV_READ_TIMEOUT_MS,
        ENV_IDLE_TIMEOUT_MS,
        ENV_MAX_DURATION_SECS,
        ENV_MAX_CAPTURED_BYTES,
        ENV_MAX_CONCURRENT,
    ];

    #[test]
    fn no_bind_is_an_error() {
        assert_eq!(load_config(&env(&[])).unwrap_err(), ConfigError::NoBind);
    }

    #[test]
    fn blank_bind_is_no_bind() {
        for blank in [" ", "\t\n"] {
            assert_eq!(
                load_config(&env(&[(ENV_BIND, blank)])).unwrap_err(),
                ConfigError::NoBind
            );
        }
    }

    #[test]
    fn malformed_bind_is_an_error() {
        for bad in ["53", "0.0.0.0", "x:53", "203.0.113.7:99999"] {
            match load_config(&env(&[(ENV_BIND, bad)])) {
                Err(ConfigError::Env(EnvError::Invalid { var, value, .. })) => {
                    assert_eq!((var.as_str(), value.as_str()), (ENV_BIND, bad));
                }
                other => panic!("{bad}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&env(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:53".parse().unwrap());
        assert!(c.wan_map.is_empty());
        assert_eq!(
            c.log_path,
            PathBuf::from("/var/log/propolis/dns/events.jsonl")
        );
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(120));
        assert_eq!(c.bounds.max_captured_bytes, 262_272);
        assert_eq!(c.bounds.max_concurrent, 256);
        assert_eq!(
            (c.rate.per_source.per_second(), c.rate.per_source.burst()),
            (5, 10)
        );
        assert_eq!(
            (c.rate.global.per_second(), c.rate.global.burst()),
            (1000, 2000)
        );
        assert_eq!(c.tls, None);
    }

    const RATES: [&str; 4] = [
        ENV_REPLY_RATE_PER_SOURCE,
        ENV_REPLY_BURST_PER_SOURCE,
        ENV_REPLY_RATE_GLOBAL,
        ENV_REPLY_BURST_GLOBAL,
    ];

    #[test]
    fn a_zero_or_non_numeric_reply_rate_is_an_error_not_a_disabled_limit() {
        for field in RATES {
            for bad in ["0", "-5", "fast", "4294967296"] {
                match load_config(&env(&[BIND, (field, bad)])) {
                    Err(ConfigError::Env(
                        EnvError::Invalid { var, value, .. }
                        | EnvError::TooLarge { var, value, .. },
                    )) => {
                        assert_eq!((var.as_str(), value.as_str()), (field, bad));
                    }
                    other => panic!("{field}={bad}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn reply_rates_load_each_from_its_own_variable_and_blank_takes_the_default() {
        let c = load_config(&env(&[
            BIND,
            (ENV_REPLY_RATE_PER_SOURCE, "7"),
            (ENV_REPLY_BURST_PER_SOURCE, "11"),
            (ENV_REPLY_RATE_GLOBAL, "300"),
            (ENV_REPLY_BURST_GLOBAL, "450"),
        ]))
        .unwrap();
        assert_eq!(
            (c.rate.per_source.per_second(), c.rate.per_source.burst()),
            (7, 11)
        );
        assert_eq!(
            (c.rate.global.per_second(), c.rate.global.burst()),
            (300, 450)
        );
        let mut pairs = vec![BIND];
        pairs.extend(RATES.iter().map(|f| (*f, " ")));
        let blank = load_config(&env(&pairs)).unwrap();
        let defaults = load_config(&env(&[BIND])).unwrap();
        assert_eq!(blank.rate, defaults.rate);
    }

    #[test]
    fn a_zero_or_non_numeric_bound_is_an_error_not_a_disabled_guard() {
        for field in BOUNDS {
            for bad in ["0", "-1", "ten"] {
                match load_config(&env(&[BIND, (field, bad)])) {
                    Err(ConfigError::Env(EnvError::Invalid { var, value, .. })) => {
                        assert_eq!((var.as_str(), value.as_str()), (field, bad));
                    }
                    other => panic!("{field}={bad}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_blank_bound_takes_its_default() {
        let defaults = load_config(&env(&[BIND])).unwrap().bounds;
        let mut pairs = vec![BIND];
        pairs.extend(BOUNDS.iter().map(|f| (*f, "  ")));
        let blank = load_config(&env(&pairs)).unwrap().bounds;
        assert_eq!(blank.read_timeout, defaults.read_timeout);
        assert_eq!(blank.idle_timeout, defaults.idle_timeout);
        assert_eq!(blank.max_duration, defaults.max_duration);
        assert_eq!(blank.max_captured_bytes, defaults.max_captured_bytes);
        assert_eq!(blank.max_concurrent, defaults.max_concurrent);
    }

    #[test]
    fn wan_map_parses_and_rejects_garbage() {
        let c = load_config(&env(&[
            BIND,
            (ENV_WAN_MAP, "10.0.0.1=198.51.100.4, 10.0.0.2=198.51.100.5"),
        ]))
        .unwrap();
        assert_eq!(c.wan_map.len(), 2);
        assert_eq!(
            c.wan_map.get(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            Some(&"198.51.100.4".parse::<IpAddr>().unwrap())
        );
        for bad in ["not-valid", "10.0.0.1=", "x=198.51.100.4"] {
            assert!(
                matches!(
                    load_config(&env(&[BIND, (ENV_WAN_MAP, bad)])),
                    Err(ConfigError::Env(EnvError::Invalid { .. }))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn parse_tls_nothing_configured_is_none() {
        assert_eq!(parse_tls(None, None, None), Ok(None));
    }

    #[test]
    fn parse_tls_full_is_some() {
        assert_eq!(
            parse_tls(TLS_BIND, Some(CERT), Some(KEY)),
            Ok(Some(TlsConfig {
                bind_addr: TLS_BIND,
                cert_path: CERT.into(),
                key_path: KEY.into(),
            }))
        );
    }

    #[test]
    fn parse_tls_bind_without_cert_is_refused() {
        assert_eq!(
            parse_tls(TLS_BIND, None, Some(KEY)),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
        assert_eq!(
            parse_tls(TLS_BIND, None, None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }

    #[test]
    fn parse_tls_bind_without_key_is_refused() {
        assert_eq!(
            parse_tls(TLS_BIND, Some(CERT), None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
    }

    #[test]
    fn parse_tls_exactly_one_of_cert_and_key_without_bind_is_refused() {
        assert_eq!(
            parse_tls(None, Some(CERT), None),
            Err(ConfigError::TlsPathMissing(ENV_TLS_KEY))
        );
        assert_eq!(
            parse_tls(None, None, Some(KEY)),
            Err(ConfigError::TlsPathMissing(ENV_TLS_CERT))
        );
    }

    #[test]
    fn parse_tls_pair_without_bind_has_no_listener() {
        assert_eq!(
            parse_tls(None, Some(CERT), Some(KEY)),
            Ok(Some(TlsConfig {
                bind_addr: None,
                cert_path: CERT.into(),
                key_path: KEY.into(),
            }))
        );
    }

    #[test]
    fn a_bad_tls_bind_is_an_error() {
        assert!(matches!(
            load_config(&env(&[
                BIND,
                (ENV_TLS_BIND, "nonsense"),
                (ENV_TLS_CERT, CERT),
                (ENV_TLS_KEY, KEY)
            ])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_non_utf8_value_is_an_env_error() {
        let get = Env::from_lookup(|var: &str| {
            if var == ENV_TLS_KEY {
                Err(EnvError::NotUnicode {
                    var: var.to_string(),
                })
            } else if var == ENV_BIND {
                Ok(Some(BIND.1.to_string()))
            } else {
                Ok(None)
            }
        });
        let err = load_config(&get).unwrap_err();
        assert_eq!(
            err,
            ConfigError::Env(EnvError::NotUnicode {
                var: ENV_TLS_KEY.to_string()
            })
        );
        let text = err.to_string();
        assert!(
            text.contains(ENV_TLS_KEY) && text.contains("UTF-8"),
            "{text}"
        );
    }
}
