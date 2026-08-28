//! `shipper` binary configuration: environment variables (see the `ENV_*` constants below),
//! matching the fail-closed pattern established by `sensor-ssh/src/main.rs` and
//! `gateway/src/config.rs` - every value is validated at startup and the process refuses to
//! start on a malformed one. The collector holds no `DATABASE_URL` and no vendor keys: it only
//! needs the gateway address, the three mTLS PEM paths, the sensor logs to tail, and the
//! cursor/state directories.
//!
//! `SENSOR_LOGS` uses the same `name:path,name:path` grammar as
//! `propolis::config::PROPOLIS_SENSOR_LOGS` (`crates/propolis/src/config.rs`). There is
//! deliberately no per-log state key here: per the corrected Task 12 design, every sensor log
//! on this collector ships through ONE seq/hash chain keyed by `COLLECTOR_ID` (see
//! `validate_collector_id` and `main.rs`'s ship loop), because the gateway keys its chain by the
//! client certificate's CommonName - not by anything the collector sends per log.

use std::env;
use std::io::BufReader;
use std::path::PathBuf;

use tokio_rustls::rustls::pki_types::CertificateDer;

const ENV_GATEWAY_ADDR: &str = "PROPOLIS_SHIPPER_GATEWAY_ADDR";
const ENV_GATEWAY_DNS: &str = "PROPOLIS_SHIPPER_GATEWAY_DNS";
const ENV_CA_CERT_PATH: &str = "PROPOLIS_SHIPPER_CA_CERT_PATH";
const ENV_CLIENT_CERT_PATH: &str = "PROPOLIS_SHIPPER_CLIENT_CERT_PATH";
const ENV_CLIENT_KEY_PATH: &str = "PROPOLIS_SHIPPER_CLIENT_KEY_PATH";
const ENV_COLLECTOR_ID: &str = "PROPOLIS_SHIPPER_COLLECTOR_ID";
const ENV_SENSOR_LOGS: &str = "PROPOLIS_SHIPPER_SENSOR_LOGS";
const ENV_CURSOR_DIR: &str = "PROPOLIS_SHIPPER_CURSOR_DIR";
const ENV_STATE_DIR: &str = "PROPOLIS_SHIPPER_STATE_DIR";
const ENV_POLL_INTERVAL_MS: &str = "PROPOLIS_SHIPPER_POLL_INTERVAL_MS";
const ENV_MAX_RECORDS_PER_BATCH: &str = "PROPOLIS_SHIPPER_MAX_RECORDS_PER_BATCH";
const ENV_RETRY_BACKOFF_MS: &str = "PROPOLIS_SHIPPER_RETRY_BACKOFF_MS";

const DEFAULT_CURSOR_DIR: &str = "/var/lib/propolis/shipper/cursors";
const DEFAULT_STATE_DIR: &str = "/var/lib/propolis/shipper/state";
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 2000;

/// One sensor log this collector tails, parsed from one `name:path` entry of `SENSOR_LOGS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorLogConfig {
    pub name: String,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub gateway_addr: std::net::SocketAddr,
    pub gateway_dns: String,
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub collector_id: String,
    pub sensor_logs: Vec<SensorLogConfig>,
    pub cursor_dir: PathBuf,
    pub state_dir: PathBuf,
    pub poll_interval_ms: u64,
    pub max_records_per_batch: usize,
    pub retry_backoff_ms: u64,
}

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    /// A required env var was absent.
    Missing(&'static str),
    /// A present value failed to parse or was otherwise invalid (includes a present-but-zero
    /// numeric bound: rejected rather than defaulted, since silently substituting a default for
    /// a misconfigured bound is how a guard gets disabled without anyone noticing).
    Invalid {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    /// `COLLECTOR_ID` does not match the CommonName of the configured client certificate.
    CollectorIdMismatch {
        configured: String,
        cert_cn: Option<String>,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing(field) => write!(f, "{field} must be set"),
            ConfigError::Invalid {
                field,
                value,
                reason,
            } => write!(f, "{field}: {reason}, got {value:?}"),
            ConfigError::CollectorIdMismatch {
                configured,
                cert_cn,
            } => write!(
                f,
                "{ENV_COLLECTOR_ID} {configured:?} does not match the client certificate's \
                 CommonName {cert_cn:?}"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

fn required_var(field: &'static str) -> Result<String, ConfigError> {
    env::var(field).map_err(|_| ConfigError::Missing(field))
}

fn required_path(field: &'static str) -> Result<PathBuf, ConfigError> {
    required_var(field).map(PathBuf::from)
}

/// Parse a comma-separated `name:path,name:path` list, same grammar as
/// `propolis::config`'s `PROPOLIS_SENSOR_LOGS` parser (`splitn(2, ':')`, both sides required
/// non-empty). At least one entry is required: an empty `SENSOR_LOGS` leaves this collector
/// with nothing to ship, which is a misconfiguration, not a valid idle state.
fn parse_sensor_logs(raw: &str) -> Result<Vec<SensorLogConfig>, ConfigError> {
    let logs: Vec<SensorLogConfig> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let mut parts = entry.splitn(2, ':');
            let name = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            if name.is_empty() || path.is_empty() {
                return Err(ConfigError::Invalid {
                    field: ENV_SENSOR_LOGS,
                    value: entry.to_string(),
                    reason: "expected name:path",
                });
            }
            Ok(SensorLogConfig {
                name: name.to_string(),
                log_path: PathBuf::from(path),
            })
        })
        .collect::<Result<_, _>>()?;
    if logs.is_empty() {
        return Err(ConfigError::Missing(ENV_SENSOR_LOGS));
    }
    Ok(logs)
}

/// Parse an optional positive `u64` bound: `None` (the env var was unset) falls back to
/// `default`; present-but-zero or present-but-unparseable are both rejected.
fn parse_positive_u64(
    raw: Option<&str>,
    default: u64,
    field: &'static str,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::Invalid {
        field,
        value: raw.to_string(),
        reason: "expected a positive integer",
    })?;
    if value == 0 {
        return Err(ConfigError::Invalid {
            field,
            value: raw.to_string(),
            reason: "expected a positive integer",
        });
    }
    Ok(value)
}

pub fn load_config_from_env() -> Result<Config, ConfigError> {
    let gateway_addr_raw = required_var(ENV_GATEWAY_ADDR)?;
    let gateway_addr: std::net::SocketAddr =
        gateway_addr_raw
            .trim()
            .parse()
            .map_err(|_| ConfigError::Invalid {
                field: ENV_GATEWAY_ADDR,
                value: gateway_addr_raw.clone(),
                reason: "expected a host:port socket address",
            })?;

    let gateway_dns = required_var(ENV_GATEWAY_DNS)?;
    let ca_cert_path = required_path(ENV_CA_CERT_PATH)?;
    let client_cert_path = required_path(ENV_CLIENT_CERT_PATH)?;
    let client_key_path = required_path(ENV_CLIENT_KEY_PATH)?;
    let collector_id = required_var(ENV_COLLECTOR_ID)?;

    let sensor_logs_raw = required_var(ENV_SENSOR_LOGS)?;
    let sensor_logs = parse_sensor_logs(&sensor_logs_raw)?;

    let cursor_dir = env::var(ENV_CURSOR_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CURSOR_DIR));
    let state_dir = env::var(ENV_STATE_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STATE_DIR));

    let poll_interval_ms = parse_positive_u64(
        env::var(ENV_POLL_INTERVAL_MS).ok().as_deref(),
        DEFAULT_POLL_INTERVAL_MS,
        ENV_POLL_INTERVAL_MS,
    )?;
    let max_records_per_batch = parse_positive_u64(
        env::var(ENV_MAX_RECORDS_PER_BATCH).ok().as_deref(),
        crate::batcher::DEFAULT_MAX_RECORDS as u64,
        ENV_MAX_RECORDS_PER_BATCH,
    )? as usize;
    let retry_backoff_ms = parse_positive_u64(
        env::var(ENV_RETRY_BACKOFF_MS).ok().as_deref(),
        DEFAULT_RETRY_BACKOFF_MS,
        ENV_RETRY_BACKOFF_MS,
    )?;

    Ok(Config {
        gateway_addr,
        gateway_dns,
        ca_cert_path,
        client_cert_path,
        client_key_path,
        collector_id,
        sensor_logs,
        cursor_dir,
        state_dir,
        poll_interval_ms,
        max_records_per_batch,
        retry_backoff_ms,
    })
}

fn parse_cert_chain(pem: &[u8]) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem);
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()
}

/// Validates that `collector_id` matches the CommonName of the leaf certificate in
/// `client_cert_pem`, fail-closed: an unparseable cert, a cert with no CommonName, or a CN that
/// disagrees with `collector_id` are all rejected before the collector ever dials the gateway.
///
/// The gateway trusts the collector id it reads from this exact certificate's verified CN
/// (`collector_wire::tls::peer_common_name`, used identically on its side, not from anything the
/// collector sends in the payload). If this collector's configured `COLLECTOR_ID` disagreed with
/// what its own certificate presents, every batch it ships would silently land under a
/// different collector id than the operator configured - a shared-chain confusion of exactly
/// the kind the corrected Task 12 design exists to prevent, just one level up (identity instead
/// of sequence).
pub fn validate_collector_id(
    client_cert_pem: &[u8],
    collector_id: &str,
) -> Result<(), ConfigError> {
    let certs = parse_cert_chain(client_cert_pem).map_err(|e| ConfigError::Invalid {
        field: ENV_CLIENT_CERT_PATH,
        value: e.to_string(),
        reason: "failed to parse client certificate PEM",
    })?;
    match collector_wire::tls::peer_common_name(&certs) {
        Some(cn) if cn == collector_id => Ok(()),
        Some(cn) => Err(ConfigError::CollectorIdMismatch {
            configured: collector_id.to_string(),
            cert_cn: Some(cn),
        }),
        None => Err(ConfigError::CollectorIdMismatch {
            configured: collector_id.to_string(),
            cert_cn: None,
        }),
    }
}
