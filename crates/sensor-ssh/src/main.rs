//! sensor-ssh: the SSH honeypot sensor binary. Binds one TCP address, runs a full SSH
//! handshake (transport, key exchange, authentication) using this crate's own primitives
//! (ADR-0011), then presents a fake shell and captures SCP/SFTP uploads - see
//! `internal/design/02-sensor-framework.md`'s "SSH sensor" and `server.rs` for the session
//! logic this binary composes.
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! `EnvironmentFile` in `deploy/sensor-ssh.service` and the convention established by
//! `sensor-catchall/src/main.rs`. Every value is read through `sensor_framework::Env`, validated
//! at startup, and the process refuses to start on a malformed one.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::time::Duration;

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{
    Arrival, CaptureMemoryBudget, CommandEventConfig, CommandEventGate, ConnectionBounds, Env,
    EnvError, EventEmitter, SHUTDOWN_DRAIN_TIMEOUT, WanResolver, shutdown_signal,
};
use sensor_ssh::hostkey::HostKey;
use sensor_ssh::server::{DEFAULT_CAPTURE_BUDGET_BYTES, SESSION_MEMORY_POOL_BYTES};

/// Every allocation is charged to the session it was made in (`session_memory`).
#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

const ENV_BIND: &str = "PROPOLIS_SSH_BIND";
const ENV_WAN_MAP: &str = "PROPOLIS_SSH_WAN_MAP";
const ENV_HOST_KEY_PATH: &str = "PROPOLIS_SSH_HOST_KEY_PATH";
const ENV_LOG_PATH: &str = "PROPOLIS_SSH_LOG_PATH";
const ENV_SPOOL_DIR: &str = "PROPOLIS_SSH_SPOOL_DIR";
const ENV_READ_TIMEOUT_MS: &str = "PROPOLIS_SSH_READ_TIMEOUT_MS";
const ENV_IDLE_TIMEOUT_MS: &str = "PROPOLIS_SSH_IDLE_TIMEOUT_MS";
const ENV_MAX_DURATION_SECS: &str = "PROPOLIS_SSH_MAX_DURATION_SECS";
const ENV_MAX_CAPTURED_BYTES: &str = "PROPOLIS_SSH_MAX_CAPTURED_BYTES";
const ENV_MAX_CONCURRENT: &str = "PROPOLIS_SSH_MAX_CONCURRENT";
const ENV_BANNER: &str = "PROPOLIS_SSH_BANNER";
/// Shared across every sensor binary AND `shipper` on this collector - not `PROPOLIS_SSH_*` -
/// because the value must be the SAME physical identity every sensor stamps onto its outbox
/// manifest rows (SP-B-1b), matching the CommonName of the mTLS client certificate `shipper` on
/// this box presents to the gateway (`shipper::config::ENV_COLLECTOR_ID` /
/// `validate_collector_id`). A per-sensor-prefixed name here would invite the exact divergence
/// this identity exists to prevent.
const ENV_COLLECTOR_ID: &str = "PROPOLIS_COLLECTOR_ID";
/// Pre-rename bare spelling every sensor originally shipped with, still read via
/// [`sensor_framework::env_with_legacy`] when `PROPOLIS_COLLECTOR_ID` is unset - the same
/// divergence risk `sensor-catchall`'s bare `CATCHALL_*` names once caused, generalized because
/// this identity is shared across five binaries, not just this one.
const ENV_COLLECTOR_ID_LEGACY: &str = "COLLECTOR_ID";
/// Defaults to `<spool_dir>/outbox` (see [`resolve_outbox_dir`]), not a fixed path: the outbox
/// must land inside this sensor's own writable spool root, which is already granted in its
/// systemd `ReadWritePaths`.
const ENV_OUTBOX_DIR: &str = "PROPOLIS_SSH_OUTBOX_DIR";
/// Ceiling, in bytes, on capture bodies buffered in memory across every session. Defaults to 40%
/// of the unit's 512M `MemoryMax` (`sensor_ssh::server::DEFAULT_CAPTURE_BUDGET_BYTES`; see
/// `deploy/sensor-ssh.service`).
const ENV_CAPTURE_MEMORY_BYTES: &str = "PROPOLIS_SSH_CAPTURE_MEMORY_BYTES";

/// The software-version sent in `SSH-2.0-<this>`. Defaults to the OpenSSH build the shared persona
/// claims (an Ubuntu 22.04 host -> OpenSSH 8.9p1), so the banner blends into the internet's largest
/// SSH population AND does not contradict the handshake. The previous default claimed 9.6p1, whose
/// real KEXINIT always advertises the kex-strict / ext-info Terrapin mitigation that this server
/// does not emit, so a Terrapin scanner flagged the mismatch; 8.9p1 predates those, so omitting them
/// is consistent. Operators SHOULD still set `PROPOLIS_SSH_BANNER` per host so the fleet does not
/// share one value. Residual: the KEXINIT algorithm set is a minimal fixed offer (ADR-0011), so a
/// HASSHServer probe can still distinguish this from a real OpenSSH; aligning the KEXINIT needs more
/// crypto than the ADR currently permits and is tracked as a separate follow-up.
const DEFAULT_BANNER: &str = sensor_framework::persona::OPENSSH_VERSION;

const DEFAULT_LOG_PATH: &str = "/var/log/propolis/ssh/events.jsonl";
const DEFAULT_SPOOL_DIR: &str = "/var/spool/propolis/ssh";
const DEFAULT_HOST_KEY_PATH: &str = "/var/lib/propolis/ssh/host_key";
/// Single-node deployments run no shipper, so there is no collector identity to match; `"local"`
/// keeps the outbox manifest well-formed anyway.
const DEFAULT_COLLECTOR_ID: &str = "local";

// Identical to sensor-telnet's defaults except the capture limit. Both are unauthenticated,
// internet-facing TCP honeypots with the same exposure, so two different sets of numbers would be a
// difference with no reason behind it - and the reason each bound exists is the same for both.
const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 600;
/// The per-upload capture limit is the spool's per-file cap, 16 MiB, not a number of its own: a
/// payload streamed over the shell or an exec's stdin is cut at exactly the point the spool would
/// refuse it. At 1,000,000 a 6.6 MB Go worm was cut at a hash no reputation service knew, and at
/// 10,000,000 a 10,027,008-byte miner was. What the larger default costs in memory is bounded by
/// the capture and output budgets, not by this number (docs/operations/capacity-planning.md).
const DEFAULT_MAX_CAPTURED_BYTES: u64 = sensor_ssh::server::SPOOL_MAX_FILE_BYTES;
const DEFAULT_MAX_CONCURRENT: u32 = 256;

#[derive(Debug, Clone)]
struct Config {
    bind_addr: SocketAddr,
    wan_map: HashMap<IpAddr, IpAddr>,
    host_key_path: PathBuf,
    log_path: PathBuf,
    spool_dir: PathBuf,
    bounds: ConnectionBounds,
    banner: String,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_memory_bytes: u64,
    command_events: CommandEventConfig,
}

/// The sensor name in `PROPOLIS_SSH_COMMAND_EVENT_RATE_PER_MIN` and `..._BURST`.
const COMMAND_EVENT_SENSOR: &str = "ssh";
/// How long shutdown waits for the command summaries still accumulating to be written.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `PROPOLIS_SSH_BIND` was absent.
    NoBind,
    /// A variable was not valid UTF-8, or was set to a value the sensor refuses (a malformed
    /// address, a zero or unparseable bound, a bad WAN map entry). Rejected rather than defaulted:
    /// silently substituting a default for a misconfigured bound is how a guard gets disabled
    /// without anyone noticing.
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

/// Resolve the outbox directory: the explicit `PROPOLIS_SSH_OUTBOX_DIR` override if set, else a
/// subdirectory of the sensor's own resolved spool root. The default must derive from
/// `spool_dir` (not a fixed constant) so it also follows a `PROPOLIS_SSH_SPOOL_DIR` override,
/// and so it always lands inside the writable root the sensor's systemd unit already grants.
fn resolve_outbox_dir(spool_dir: &Path, env_override: Option<String>) -> PathBuf {
    env_override
        .map(PathBuf::from)
        .unwrap_or_else(|| spool_dir.join("outbox"))
}

fn load_config(env: &Env) -> Result<Config, ConfigError> {
    let spool_dir = env.path(ENV_SPOOL_DIR, DEFAULT_SPOOL_DIR)?;
    let outbox_dir = resolve_outbox_dir(&spool_dir, env.string(ENV_OUTBOX_DIR)?);
    Ok(Config {
        bind_addr: env.socket_addr(ENV_BIND)?.ok_or(ConfigError::NoBind)?,
        wan_map: env.wan_map(ENV_WAN_MAP)?,
        host_key_path: env.path(ENV_HOST_KEY_PATH, DEFAULT_HOST_KEY_PATH)?,
        log_path: env.path(ENV_LOG_PATH, DEFAULT_LOG_PATH)?,
        spool_dir,
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
        banner: env
            .string(ENV_BANNER)?
            .unwrap_or_else(|| DEFAULT_BANNER.to_string()),
        collector_id: sensor_framework::env_with_legacy(ENV_COLLECTOR_ID, ENV_COLLECTOR_ID_LEGACY)?
            .unwrap_or_else(|| DEFAULT_COLLECTOR_ID.to_string()),
        outbox_dir,
        capture_memory_bytes: env
            .positive_u64(ENV_CAPTURE_MEMORY_BYTES, DEFAULT_CAPTURE_BUDGET_BYTES)?,
        command_events: CommandEventConfig::from_env(COMMAND_EVENT_SENSOR, env)?,
    })
}

// Two workers, not one per core: the unit runs under `CPUQuota=75%`, so more threads add no
// throughput, and every worker can be inside a shell line at once, each with a line's working
// copies (about 21 MB) outside any budget. The worst-case sum in
// docs/operations/capacity-planning.md and `tests/budget_product_test.rs` counts exactly this
// many.
#[tokio::main(worker_threads = 2)]
async fn main() {
    sensor_framework::init_logging();
    // Before the first capture: otherwise freed capture bodies stay resident outside every budget.
    if !session_memory::pin_mmap_threshold() {
        tracing::warn!(
            "sensor-ssh: the allocator did not take the mmap threshold; freed capture buffers may \
             stay resident outside the capture budget"
        );
    }

    let config = match load_config(&Env::process()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sensor-ssh: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // Every admitted session must fit in the session memory pool at its floor.
    if let Err(e) =
        session_memory::configure(SESSION_MEMORY_POOL_BYTES, config.bounds.max_concurrent)
    {
        tracing::error!(error = %e, "sensor-ssh: invalid configuration; refusing to start");
        std::process::exit(1);
    }
    tokio::spawn(session_memory::watchdog());

    // Load or generate the host key so the honeypot does not fingerprint itself as freshly
    // minted on every restart (design doc's "Host key").
    let host_key = if config.host_key_path.exists() {
        match HostKey::load(&config.host_key_path) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(
                    path = %config.host_key_path.display(),
                    error = %e,
                    "sensor-ssh: failed to load host key"
                );
                std::process::exit(1);
            }
        }
    } else {
        let key = HostKey::generate();
        if let Some(parent) = config.host_key_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::error!(
                path = %parent.display(),
                error = %e,
                "sensor-ssh: failed to create host key directory"
            );
            std::process::exit(1);
        }
        if let Err(e) = key.save(&config.host_key_path) {
            tracing::error!(
                path = %config.host_key_path.display(),
                error = %e,
                "sensor-ssh: failed to save generated host key"
            );
            std::process::exit(1);
        }
        tracing::info!(
            path = %config.host_key_path.display(),
            "sensor-ssh: generated new host key"
        );
        key
    };

    let wan_resolver = Arc::new(WanResolver::new(config.wan_map));
    let command_events = Arc::new(CommandEventGate::new(config.command_events));
    let summary_emitter = EventEmitter::new(config.log_path.clone());

    let (bound, handle, handoff) = match sensor_ssh::serve_with_handoff(
        config.bind_addr,
        config.log_path,
        config.spool_dir,
        config.host_key_path,
        wan_resolver,
        config.bounds,
        config.banner,
        config.collector_id,
        config.outbox_dir,
        Arc::new(CaptureMemoryBudget::new(config.capture_memory_bytes)),
        command_events.clone(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let e =
                sensor_framework::listener_start_error(config.bind_addr, std::io::Error::other(e));
            tracing::error!("sensor-ssh: {e}; refusing to start");
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "sensor-ssh: listening");
    handoff.start_stats("ssh");

    // Host key is already loaded/generated and passed to start_test_server above; drop the
    // local clone so only the server tasks hold it.
    drop(host_key);

    shutdown_signal().await;
    tracing::info!("sensor-ssh: shutdown signal received; stopping");
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
        tracing::warn!("sensor-ssh: command summaries not all written before shutdown");
    }
    // Cuts live connections (their captures are recorded as truncated), then drains the queue.
    handoff.drain(SHUTDOWN_DRAIN_TIMEOUT).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIND: (&str, &str) = (ENV_BIND, "203.0.113.7:22");

    #[test]
    fn no_or_malformed_bind_is_an_error() {
        assert_eq!(
            load_config(&Env::from_table(&[])).unwrap_err(),
            ConfigError::NoBind
        );
        assert!(matches!(
            load_config(&Env::from_table(&[(ENV_BIND, "22")])),
            Err(ConfigError::Env(EnvError::Invalid { .. }))
        ));
    }

    #[test]
    fn a_valid_bind_loads_with_the_documented_defaults() {
        let c = load_config(&Env::from_table(&[BIND])).unwrap();
        assert_eq!(c.bind_addr, "203.0.113.7:22".parse().unwrap());
        assert!(c.wan_map.is_empty());
        assert_eq!(c.host_key_path, PathBuf::from(DEFAULT_HOST_KEY_PATH));
        assert_eq!(c.log_path, PathBuf::from(DEFAULT_LOG_PATH));
        assert_eq!(c.spool_dir, PathBuf::from(DEFAULT_SPOOL_DIR));
        assert_eq!(
            c.outbox_dir,
            PathBuf::from("/var/spool/propolis/ssh/outbox")
        );
        assert_eq!(c.bounds.read_timeout, Duration::from_millis(30_000));
        assert_eq!(c.bounds.idle_timeout, Duration::from_millis(60_000));
        assert_eq!(c.bounds.max_duration, Duration::from_secs(600));
        // The spool's per-file cap, 16 MiB, not 1_000_000 like the other sensors.
        assert_eq!(c.bounds.max_captured_bytes, 16_777_216);
        assert_eq!(c.bounds.max_concurrent, 256);
        assert_eq!(c.banner, DEFAULT_BANNER);
        // 40% of the unit's 512M MemoryMax.
        assert_eq!(c.capture_memory_bytes, 214_748_364);
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
        // With no PROPOLIS_SSH_OUTBOX_DIR override, the outbox must sit under the resolved
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
