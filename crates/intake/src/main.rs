//! intake: the binary entry point for sub-project 3's event intake pipeline. Runs one
//! `IntakeRunner` (tailer + converter + `append_event`, wired in Tasks 1-4) per configured sensor
//! log file, each polling on its own tokio task against a shared `PgPool` - see
//! `internal/design/03-event-intake-aggregation.md`'s "The runner" and "Configuration".
//!
//! Configuration is environment variables (see the `ENV_*` constants below), matching the
//! convention established by `sensor-catchall/src/main.rs` and `sensor-ssh/src/main.rs`: every
//! value is validated at startup and the process refuses to start on a malformed one rather than
//! silently substituting a default that could disable the bound it names.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use intake::runner::IntakeRunner;
use intake::tailer::LogTailer;
use sqlx::PgPool;

const ENV_DATABASE_URL: &str = "DATABASE_URL";
const ENV_CURSOR_DIR: &str = "PROPOLIS_CURSOR_DIR";
const ENV_POLL_INTERVAL_MS: &str = "PROPOLIS_POLL_INTERVAL_MS";
const ENV_SENSOR_LOGS: &str = "PROPOLIS_SENSOR_LOGS";

const DEFAULT_CURSOR_DIR: &str = "/var/lib/propolis/cursors";
const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;

/// One entry of `PROPOLIS_SENSOR_LOGS`: a sensor's name (for logging/metrics) and the absolute
/// path to its NDJSON log file. Mirrors the design doc's `SensorLogConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SensorLogConfig {
    name: String,
    log_path: PathBuf,
}

#[derive(Debug)]
struct Config {
    database_url: String,
    cursor_dir: PathBuf,
    poll_interval: Duration,
    sensor_logs: Vec<SensorLogConfig>,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `DATABASE_URL` was absent or empty.
    MissingDatabaseUrl,
    /// `PROPOLIS_SENSOR_LOGS` was absent, empty, or held only blank entries.
    NoSensorLogs,
    InvalidSensorLogEntry(String),
    /// A bound value failed to parse, or parsed to 0. Zero is always rejected rather than
    /// silently treated as "poll as fast as possible" - a busy-poll loop pinning a CPU core on
    /// every idle tailer, the same "zero never means unlimited" convention `sensor-catchall`'s
    /// `parse_positive_u64` establishes for its own bounds.
    InvalidBound {
        field: &'static str,
        value: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingDatabaseUrl => write!(
                f,
                "{ENV_DATABASE_URL} must be set to a PostgreSQL connection string"
            ),
            ConfigError::NoSensorLogs => write!(
                f,
                "{ENV_SENSOR_LOGS} must name at least one sensor (comma-separated name:path pairs)"
            ),
            ConfigError::InvalidSensorLogEntry(s) => {
                write!(
                    f,
                    "invalid {ENV_SENSOR_LOGS} entry {s:?}, expected name:path"
                )
            }
            ConfigError::InvalidBound { field, value } => write!(
                f,
                "{field} must be a positive integer, got {value:?} (zero never means \"as fast as possible\")"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses `PROPOLIS_SENSOR_LOGS`'s comma-separated `name:path` entries (e.g.
/// `catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl`).
/// Splits each entry on the FIRST colon only (`splitn(2, ':')`): a sensor name never contains
/// one, but a log path could in principle (an unusual but legal POSIX filename). Rejects an
/// empty list outright, matching `sensor-catchall`'s `parse_bind_addrs` - at least one real
/// sensor is required.
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
                return Err(ConfigError::InvalidSensorLogEntry(entry.to_string()));
            }
            Ok(SensorLogConfig {
                name: name.to_string(),
                log_path: PathBuf::from(path),
            })
        })
        .collect::<Result<_, _>>()?;
    if logs.is_empty() {
        return Err(ConfigError::NoSensorLogs);
    }
    Ok(logs)
}

/// Parses an optional positive `u64` bound: `None` (the env var was unset) falls back to
/// `default`; present-but-zero or present-but-unparseable are both rejected. Mirrors
/// `sensor-catchall`'s `parse_positive_u64` (kept free of `std::env` itself so it stays
/// unit-testable without mutating real process environment).
fn parse_positive_u64(
    raw: Option<&str>,
    default: u64,
    field: &'static str,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
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

/// Loads and validates configuration from environment variables. Fails closed: a missing
/// `DATABASE_URL`, an empty or malformed sensor log list, or a zero-valued poll interval is
/// rejected here rather than silently substituted with a default.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let database_url = env::var(ENV_DATABASE_URL)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::MissingDatabaseUrl)?;
    let cursor_dir = env::var(ENV_CURSOR_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CURSOR_DIR));
    let poll_interval_ms = parse_positive_u64(
        env::var(ENV_POLL_INTERVAL_MS).ok().as_deref(),
        DEFAULT_POLL_INTERVAL_MS,
        ENV_POLL_INTERVAL_MS,
    )?;
    let sensor_logs = parse_sensor_logs(&env::var(ENV_SENSOR_LOGS).unwrap_or_default())?;

    Ok(Config {
        database_url,
        cursor_dir,
        poll_interval: Duration::from_millis(poll_interval_ms),
        sensor_logs,
    })
}

/// Resolves when the process receives SIGINT (`Ctrl+C`) or, on Unix, SIGTERM - what `systemctl
/// stop` sends, not SIGINT, to the hardened `deploy/intake.service` unit this binary ships.
/// Mirrors `sensor_framework::listener::shutdown_signal` exactly (same reason: graceful shutdown
/// under systemd), duplicated here rather than taken as a dependency: `intake` is architecturally
/// distinct from the sensor layer (`internal/design/03-event-intake-aggregation.md`: "no vendor
/// client, no web surface, no feed publisher, and no sensor"), and pulling in the whole
/// listener/spool/WAN-resolution surface of `sensor-framework` for one signal-handling helper is
/// out of proportion to what it buys.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "intake: failed to install SIGTERM handler; shutdown_signal now waits on SIGINT only"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// One sensor's poll loop: read a batch, append what converts, and persist the cursor only when
/// the whole batch appended cleanly. Guarding on `result.errors == 0` before persisting is the
/// at-least-once guarantee (`IntakeRunner::persist_cursor`'s own doc comment and
/// `internal/design/03-event-intake-aggregation.md`'s "Cursor advancement rules": "Database
/// error: cursor does NOT advance"): persisting past a batch that hit a database error partway
/// through would durably skip the failed line - and everything the tailer already read after it
/// in that batch - instead of retrying it on the next poll.
async fn run_sensor_loop(
    sensor: SensorLogConfig,
    pool: PgPool,
    cursor_dir: PathBuf,
    poll_interval: Duration,
) {
    let SensorLogConfig { name, log_path } = sensor;
    let tailer = LogTailer::new(log_path, cursor_dir);
    let mut runner = IntakeRunner::new(tailer, pool, name.clone());
    tracing::info!(sensor = %name, "intake: tailer started");

    loop {
        let result = runner.run_batch().await;

        if result.ingested > 0 || result.rejected > 0 || result.errors > 0 {
            tracing::info!(
                sensor = %name,
                ingested = result.ingested,
                rejected = result.rejected,
                errors = result.errors,
                "intake: batch processed"
            );
        }

        if result.errors == 0
            && let Err(e) = runner.persist_cursor()
        {
            tracing::error!(sensor = %name, error = %e, "intake: cursor persist failed");
        }

        if result.ingested == 0 && result.rejected == 0 {
            tokio::time::sleep(poll_interval).await;
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "intake: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let pool = match PgPool::connect(&config.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "intake: failed to connect to PostgreSQL");
            std::process::exit(1);
        }
    };

    if let Err(e) = std::fs::create_dir_all(&config.cursor_dir) {
        tracing::error!(
            path = %config.cursor_dir.display(),
            error = %e,
            "intake: failed to create cursor directory"
        );
        std::process::exit(1);
    }

    let mut handles = Vec::new();
    for sensor in config.sensor_logs {
        let pool = pool.clone();
        let cursor_dir = config.cursor_dir.clone();
        let poll_interval = config.poll_interval;
        handles.push(tokio::spawn(async move {
            run_sensor_loop(sensor, pool, cursor_dir, poll_interval).await;
        }));
    }

    shutdown_signal().await;
    tracing::info!("intake: shutdown signal received; stopping");
    for handle in handles {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sensor_logs_accepts_comma_separated_pairs() {
        let logs = parse_sensor_logs(
            "catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl",
        )
        .unwrap();
        assert_eq!(
            logs,
            vec![
                SensorLogConfig {
                    name: "catchall".into(),
                    log_path: "/var/log/propolis/catchall/events.jsonl".into(),
                },
                SensorLogConfig {
                    name: "ssh".into(),
                    log_path: "/var/log/propolis/ssh/events.jsonl".into(),
                },
            ]
        );
    }

    #[test]
    fn parse_sensor_logs_trims_whitespace_around_entries() {
        let logs = parse_sensor_logs(" catchall:/var/log/a.jsonl , ssh:/var/log/b.jsonl ").unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].name, "catchall");
        assert_eq!(logs[1].name, "ssh");
    }

    #[test]
    fn parse_sensor_logs_rejects_empty() {
        assert_eq!(parse_sensor_logs(""), Err(ConfigError::NoSensorLogs));
        assert_eq!(parse_sensor_logs("   "), Err(ConfigError::NoSensorLogs));
    }

    #[test]
    fn parse_sensor_logs_rejects_entry_without_colon() {
        assert!(matches!(
            parse_sensor_logs("not-a-pair"),
            Err(ConfigError::InvalidSensorLogEntry(_))
        ));
    }

    #[test]
    fn parse_sensor_logs_rejects_empty_name_or_path() {
        assert!(matches!(
            parse_sensor_logs(":/var/log/x.jsonl"),
            Err(ConfigError::InvalidSensorLogEntry(_))
        ));
        assert!(matches!(
            parse_sensor_logs("catchall:"),
            Err(ConfigError::InvalidSensorLogEntry(_))
        ));
    }

    #[test]
    fn parse_sensor_logs_path_may_contain_colon() {
        // splitn(2, ':') splits only at the first colon, so a path segment after it is kept
        // intact rather than truncated or rejected.
        let logs = parse_sensor_logs("weird:/var/log/a:b.jsonl").unwrap();
        assert_eq!(logs[0].log_path, PathBuf::from("/var/log/a:b.jsonl"));
    }

    #[test]
    fn parse_positive_u64_uses_default_when_absent() {
        assert_eq!(parse_positive_u64(None, 42, "x").unwrap(), 42);
    }

    #[test]
    fn parse_positive_u64_rejects_zero() {
        // Zero must never silently mean "poll as fast as possible".
        assert!(matches!(
            parse_positive_u64(Some("0"), 42, "x"),
            Err(ConfigError::InvalidBound { .. })
        ));
    }

    #[test]
    fn parse_positive_u64_rejects_non_numeric() {
        assert!(matches!(
            parse_positive_u64(Some("not-a-number"), 42, "x"),
            Err(ConfigError::InvalidBound { .. })
        ));
    }

    #[test]
    fn parse_positive_u64_accepts_explicit_value() {
        assert_eq!(parse_positive_u64(Some("100"), 42, "x").unwrap(), 100);
    }

    #[test]
    fn load_config_missing_database_url_fails() {
        // The env is shared across test threads (matches sensor-ssh's
        // load_config_missing_bind_fails precedent), so only assert what we can reason about
        // without mutating it.
        if env::var(ENV_DATABASE_URL).is_err() {
            assert!(matches!(
                load_config_from_env(),
                Err(ConfigError::MissingDatabaseUrl)
            ));
        }
    }
}
