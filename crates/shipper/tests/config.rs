//! `shipper::config` behavior: valid env parses to a `Config`, a required var missing or a
//! numeric bound present-but-zero both fail closed, and a `COLLECTOR_ID` that disagrees with the
//! client certificate's CommonName is rejected before the collector ever dials the gateway.

use std::env;
use std::path::PathBuf;
use std::sync::Mutex;

use shipper::config::{ConfigError, load_config_from_env, validate_collector_id};

// The env is process-global and tests run on multiple threads; serialize any test that
// sets/removes these vars so they cannot interleave with each other or with unrelated tests
// that happen to read them (same discipline as gateway::config's tests).
static ENV_LOCK: Mutex<()> = Mutex::new(());

const ENV_GATEWAY_ADDR: &str = "PROPOLIS_SHIPPER_GATEWAY_ADDR";
const ENV_GATEWAY_DNS: &str = "PROPOLIS_SHIPPER_GATEWAY_DNS";
const ENV_CA_CERT_PATH: &str = "PROPOLIS_SHIPPER_CA_CERT_PATH";
const ENV_CLIENT_CERT_PATH: &str = "PROPOLIS_SHIPPER_CLIENT_CERT_PATH";
const ENV_CLIENT_KEY_PATH: &str = "PROPOLIS_SHIPPER_CLIENT_KEY_PATH";
const ENV_COLLECTOR_ID: &str = "PROPOLIS_SHIPPER_COLLECTOR_ID";
const ENV_SENSOR_LOGS: &str = "PROPOLIS_SHIPPER_SENSOR_LOGS";
const ENV_POLL_INTERVAL_MS: &str = "PROPOLIS_SHIPPER_POLL_INTERVAL_MS";

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    keys: Vec<&'static str>,
}

impl EnvGuard {
    fn set(vars: &[(&'static str, &str)]) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut keys = Vec::new();
        for (k, v) in vars {
            // SAFETY: serialized by ENV_LOCK above; no other thread touches these vars.
            unsafe { env::set_var(k, v) };
            keys.push(*k);
        }
        EnvGuard { _lock: lock, keys }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for k in &self.keys {
            // SAFETY: serialized by ENV_LOCK held for the guard's lifetime.
            unsafe { env::remove_var(k) };
        }
    }
}

fn valid_vars() -> Vec<(&'static str, &'static str)> {
    vec![
        (ENV_GATEWAY_ADDR, "127.0.0.1:9443"),
        (ENV_GATEWAY_DNS, "gateway.local"),
        (ENV_CA_CERT_PATH, "/tmp/ca.pem"),
        (ENV_CLIENT_CERT_PATH, "/tmp/client.pem"),
        (ENV_CLIENT_KEY_PATH, "/tmp/client.key"),
        (ENV_COLLECTOR_ID, "collector-1"),
        (ENV_SENSOR_LOGS, "ssh:/var/log/propolis/ssh/events.jsonl"),
    ]
}

#[test]
fn load_config_from_valid_env_succeeds() {
    let _guard = EnvGuard::set(&valid_vars());
    let config = load_config_from_env().expect("valid env must parse");

    assert_eq!(config.gateway_addr, "127.0.0.1:9443".parse().unwrap());
    assert_eq!(config.gateway_dns, "gateway.local");
    assert_eq!(config.ca_cert_path, PathBuf::from("/tmp/ca.pem"));
    assert_eq!(config.client_cert_path, PathBuf::from("/tmp/client.pem"));
    assert_eq!(config.client_key_path, PathBuf::from("/tmp/client.key"));
    assert_eq!(config.collector_id, "collector-1");
    assert_eq!(config.sensor_logs.len(), 1);
    assert_eq!(config.sensor_logs[0].name, "ssh");
    assert_eq!(
        config.sensor_logs[0].log_path,
        PathBuf::from("/var/log/propolis/ssh/events.jsonl")
    );
    // Defaults not overridden by valid_vars().
    assert_eq!(
        config.cursor_dir,
        PathBuf::from("/var/lib/propolis/shipper/cursors")
    );
    assert_eq!(
        config.state_dir,
        PathBuf::from("/var/lib/propolis/shipper/state")
    );
    assert_eq!(config.poll_interval_ms, 1000);
    assert_eq!(
        config.max_records_per_batch,
        shipper::batcher::DEFAULT_MAX_RECORDS
    );
    assert_eq!(config.retry_backoff_ms, 2000);
}

#[test]
fn load_config_missing_gateway_addr_fails() {
    let mut vars = valid_vars();
    vars.retain(|(k, _)| *k != ENV_GATEWAY_ADDR);
    let _guard = EnvGuard::set(&vars);
    // The guard above never sets ENV_GATEWAY_ADDR; make sure a leftover from another
    // process/test run is not the reason this passes.
    unsafe { env::remove_var(ENV_GATEWAY_ADDR) };
    assert_eq!(
        load_config_from_env().unwrap_err(),
        ConfigError::Missing(ENV_GATEWAY_ADDR)
    );
}

#[test]
fn load_config_zero_poll_interval_fails() {
    let mut vars = valid_vars();
    vars.push((ENV_POLL_INTERVAL_MS, "0"));
    let _guard = EnvGuard::set(&vars);
    assert_eq!(
        load_config_from_env().unwrap_err(),
        ConfigError::Invalid {
            field: ENV_POLL_INTERVAL_MS,
            value: "0".to_string(),
            reason: "expected a positive integer",
        }
    );
}

#[test]
fn collector_id_matching_the_cert_cn_validates() {
    let dir = tempfile::tempdir().expect("tempdir");
    provision_certs::provision(dir.path(), "gateway.local", "collector-a").expect("provision");
    let cert_pem = std::fs::read(dir.path().join("collector-a.crt")).expect("read cert");

    assert!(validate_collector_id(&cert_pem, "collector-a").is_ok());
}

#[test]
fn collector_id_not_matching_the_cert_cn_is_a_startup_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    provision_certs::provision(dir.path(), "gateway.local", "collector-a").expect("provision");
    let cert_pem = std::fs::read(dir.path().join("collector-a.crt")).expect("read cert");

    let err = validate_collector_id(&cert_pem, "collector-b").unwrap_err();
    assert_eq!(
        err,
        ConfigError::CollectorIdMismatch {
            configured: "collector-b".to_string(),
            cert_cn: Some("collector-a".to_string()),
        }
    );
}
