//! console: the binary entry point for sub-project 6's operator web console. Initializes
//! tracing, connects to PostgreSQL, hashes the operator password, builds the axum router, and
//! serves it - see `internal/design/06-console-observability.md`'s "Configuration".
//!
//! Configuration is environment variables, matching every other Propolis binary's convention
//! (`crates/feed/src/main.rs`, `crates/intake/src/main.rs`, `crates/review/src/main.rs`): every
//! value is validated at startup and the process refuses to start on a malformed one rather than
//! silently substituting a default that could disable a bound.
//!
//! MUST serve via `Router::into_make_service_with_connect_info::<SocketAddr>()` - Task 2's
//! carry-forward, documented on `console::routes::login`'s module doc comment: the login route's
//! rate limiter and the session cookie's `Secure` decision both key on the TCP peer address via
//! `axum::extract::ConnectInfo<SocketAddr>`, which that extractor only populates when the router
//! is served this way (falling back to a test-only `MockConnectInfo` layer otherwise).

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use console::auth::{PasswordStore, RateLimiter, SessionStore};
use console::log_buffer::{LogBuffer, LogBufferLayer};
use console::{AppState, routes};
use rand::RngExt;
use sqlx::PgPool;

const ENV_DATABASE_URL: &str = "DATABASE_URL";
const ENV_BIND: &str = "PROPOLIS_CONSOLE_BIND";
const ENV_PASSWORD: &str = "PROPOLIS_CONSOLE_PASSWORD";
const ENV_SESSION_SECRET: &str = "PROPOLIS_CONSOLE_SESSION_SECRET";
const ENV_FEED_OUTPUT_DIR: &str = "PROPOLIS_FEED_OUTPUT_DIR";
const ENV_GEOIP_DIR: &str = "PROPOLIS_GEOIP_DIR";
const ENV_RDNS_ENABLED: &str = "PROPOLIS_CONSOLE_RDNS_ENABLED";
const ENV_TRUSTED_PROXY: &str = "PROPOLIS_CONSOLE_TRUSTED_PROXY";
const ENV_METRICS_TOKEN: &str = "PROPOLIS_CONSOLE_METRICS_TOKEN";

/// Loopback only, matching the design's closed decision #4 ("Bind model: loopback only by
/// default") - an operator who wants the console reachable elsewhere binds it explicitly via
/// `PROPOLIS_CONSOLE_BIND`, e.g. behind their own reverse proxy.
const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// How many recent tracing events `routes::logs`'s viewer keeps in memory for a freshly loaded
/// page - see `log_buffer::LogBuffer::new`'s own doc comment. Matches `propolis::main`'s own
/// constant for the unified daemon binary.
const LOG_BUFFER_CAPACITY: usize = 1000;

struct Config {
    database_url: String,
    bind_addr: SocketAddr,
    password: String,
    session_secret: [u8; 32],
    feed_output_dir: Option<PathBuf>,
    geoip_dir: Option<PathBuf>,
    rdns_enabled: bool,
    trusted_proxy: bool,
    metrics_token: Option<String>,
}

#[derive(Debug, PartialEq)]
enum ConfigError {
    /// `DATABASE_URL` was absent or empty.
    MissingDatabaseUrl,
    /// `PROPOLIS_CONSOLE_BIND` was set but is not a valid `ip:port` address.
    InvalidBind(String),
    /// `PROPOLIS_CONSOLE_PASSWORD` was absent or empty - the console cannot start with no
    /// operator password to hash and gate every session behind.
    MissingPassword,
    /// `PROPOLIS_CONSOLE_SESSION_SECRET` was set but is not exactly 64 hex characters (32
    /// bytes), matching `auth::SessionStore`'s HMAC key size.
    InvalidSessionSecret,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingDatabaseUrl => write!(
                f,
                "{ENV_DATABASE_URL} must be set to a PostgreSQL connection string"
            ),
            ConfigError::InvalidBind(value) => {
                write!(f, "{ENV_BIND} {value:?} is not a valid ip:port address")
            }
            ConfigError::MissingPassword => write!(
                f,
                "{ENV_PASSWORD} must be set to the operator's console password"
            ),
            ConfigError::InvalidSessionSecret => write!(
                f,
                "{ENV_SESSION_SECRET} must be exactly 64 hex characters (32 bytes) when set"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses `PROPOLIS_CONSOLE_SESSION_SECRET` if set (64 hex chars = 32 bytes). Generates a fresh
/// random secret via `OsRng`-backed `rand::rng()` when unset - the spec's own `ConsoleConfig`:
/// "`session_secret`: from env or generated on startup." A generated secret invalidating any
/// session across a restart changes nothing in practice: `SessionStore` is in-memory only, so a
/// restart already drops every session regardless of the secret (`auth::SessionStore`'s own doc
/// comment: "a restart clears every session by design").
fn load_session_secret(raw: Option<&str>) -> Result<[u8; 32], ConfigError> {
    let Some(hex_str) = raw else {
        return Ok(rand::rng().random::<[u8; 32]>());
    };
    let bytes = hex::decode(hex_str).map_err(|_| ConfigError::InvalidSessionSecret)?;
    bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidSessionSecret)
}

/// Loads and validates configuration from environment variables. Fails closed: a missing
/// `DATABASE_URL`/`PROPOLIS_CONSOLE_PASSWORD`, a malformed `PROPOLIS_CONSOLE_BIND`, or a
/// malformed `PROPOLIS_CONSOLE_SESSION_SECRET` is rejected here rather than silently substituted.
fn load_config_from_env() -> Result<Config, ConfigError> {
    let database_url = env::var(ENV_DATABASE_URL)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::MissingDatabaseUrl)?;

    let bind_raw = env::var(ENV_BIND).unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let bind_addr = bind_raw
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::InvalidBind(bind_raw.clone()))?;

    let password = env::var(ENV_PASSWORD)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::MissingPassword)?;

    let session_secret = load_session_secret(env::var(ENV_SESSION_SECRET).ok().as_deref())?;

    let feed_output_dir = env::var(ENV_FEED_OUTPUT_DIR).ok().map(PathBuf::from);
    let geoip_dir = env::var(ENV_GEOIP_DIR)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let rdns_enabled = env::var(ENV_RDNS_ENABLED)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    let trusted_proxy = env::var(ENV_TRUSTED_PROXY)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    let metrics_token = env::var(ENV_METRICS_TOKEN).ok().filter(|s| !s.is_empty());

    Ok(Config {
        database_url,
        bind_addr,
        password,
        session_secret,
        feed_output_dir,
        geoip_dir,
        rdns_enabled,
        trusted_proxy,
        metrics_token,
    })
}

/// Resolves when the process receives SIGINT (`Ctrl+C`) or, on Unix, SIGTERM - what `systemctl
/// stop` sends to the hardened `deploy/console.service` unit this binary ships. Duplicated from
/// `feed`/`intake`/`review`'s own `shutdown_signal` rather than shared - each of those crates
/// duplicates it too, for the same reason: pulling in a shared crate for one signal-handling
/// helper is out of proportion to what it buys.
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
                    "console: failed to install SIGTERM handler; shutdown_signal now waits on SIGINT only"
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

#[tokio::main]
async fn main() {
    // The live `/logs` viewer (`routes::logs`) needs a copy of every event this process logs, so
    // `LogBufferLayer` is layered onto the subscriber alongside the default `fmt` output rather
    // than filtered separately - see that layer's own doc comment (`console::log_buffer`).
    let log_buffer = Arc::new(LogBuffer::new(LOG_BUFFER_CAPACITY));
    {
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with(tracing_subscriber::fmt::layer())
            .with(LogBufferLayer::new(log_buffer.clone()))
            .init();
    }

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "console: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let pool = match PgPool::connect(&config.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "console: failed to connect to PostgreSQL");
            std::process::exit(1);
        }
    };

    // The operator password is hashed here and the plaintext is never held beyond this call -
    // `PasswordStore::new`'s own doc comment. `config` (including the now-redundant plaintext
    // field) is dropped at the end of `main`, well before the server starts accepting requests.
    let passwords = Arc::new(PasswordStore::new(&config.password));

    let bind_addr = config.bind_addr;
    console::warn_if_console_exposed(bind_addr);
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(bind = %bind_addr, error = %e, "console: failed to bind");
            std::process::exit(1);
        }
    };

    // Load the GeoLite2 databases (a synchronous, potentially large file read) on a blocking-pool
    // thread so it never parks an async worker at startup.
    let geoip = Arc::new(match config.geoip_dir.clone() {
        Some(dir) => tokio::task::spawn_blocking(move || geoip::GeoIp::load(&dir))
            .await
            .unwrap_or_else(|_| geoip::GeoIp::disabled()),
        None => geoip::GeoIp::disabled(),
    });
    if geoip.is_enabled() {
        tracing::info!("console: GeoLite2 enrichment enabled");
    }

    let state = AppState {
        db: pool,
        sessions: Arc::new(SessionStore::new(config.session_secret)),
        passwords,
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip,
        rdns: Arc::new(console::rdns::RdnsResolver::new(config.rdns_enabled)),
        feed_output_dir: config.feed_output_dir,
        startup_time: chrono::Utc::now(),
        version: env!("CARGO_PKG_VERSION"),
        log_buffer,
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: config.trusted_proxy,
        metrics_token: config.metrics_token.map(Arc::from),
    };

    tracing::info!(bind = %bind_addr, "console: starting");

    let app = routes::router(state).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!(error = %e, "console: server error");
    }
    tracing::info!("console: shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_session_secret_generates_when_absent() {
        let a = load_session_secret(None).unwrap();
        let b = load_session_secret(None).unwrap();
        assert_ne!(a, b, "each generated secret should be freshly random");
    }

    #[test]
    fn load_session_secret_accepts_64_hex_chars() {
        let hex_secret = "11".repeat(32);
        let secret = load_session_secret(Some(&hex_secret)).unwrap();
        assert_eq!(secret, [0x11u8; 32]);
    }

    #[test]
    fn load_session_secret_rejects_wrong_length() {
        assert_eq!(
            load_session_secret(Some("aabb")),
            Err(ConfigError::InvalidSessionSecret)
        );
    }

    #[test]
    fn load_session_secret_rejects_non_hex() {
        let not_hex = "zz".repeat(32);
        assert_eq!(
            load_session_secret(Some(&not_hex)),
            Err(ConfigError::InvalidSessionSecret)
        );
    }

    #[test]
    fn load_config_missing_database_url_fails() {
        // The env is shared across test threads (matches every sibling binary's own precedent
        // for this exact test - e.g. feed/intake's `load_config_missing_database_url_fails`), so
        // only assert what we can reason about without mutating it.
        if env::var(ENV_DATABASE_URL).is_err() {
            assert!(matches!(
                load_config_from_env(),
                Err(ConfigError::MissingDatabaseUrl)
            ));
        }
    }
}
