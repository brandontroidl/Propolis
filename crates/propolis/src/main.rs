//! Propolis unified daemon: composes intake, review, feed, and console as concurrent tokio tasks
//! sharing one PgPool. See `internal/design/07-runtime-coordination-deployment.md`.
//!
//! Startup sequence: parse config, connect PgPool, run migrations, spawn all four subsystems via
//! `spawn_supervised`, wait for shutdown signal, cancel all subsystems, await with timeout.

mod config;
mod supervisor;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

use config::SensorLogConfig;
use supervisor::spawn_supervised;

use console::AppState;
use console::auth::{PasswordStore, RateLimiter, SessionStore};
use console::log_buffer::LogBuffer;
use feed::{ExclusionEngine, FeedBuilder, FeedConfig, Publisher};
use intake::runner::IntakeRunner;
use intake::tailer::LogTailer;
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{AbuseIpDb, DShield, FullVendorConfig, OtxAdapter, VendorAdapter};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// How many recent tracing events `console::routes::logs`'s viewer keeps in memory for a
/// freshly loaded page (`console::log_buffer::LogBuffer::new`'s own doc comment - live-streamed
/// entries after that are unbounded by this, only by the browser tab's own cap).
const LOG_BUFFER_CAPACITY: usize = 1000;

// ---- subsystem loops ----

/// One intake sensor's poll loop - reads batches, appends to ledger, persists cursor, sleeps on
/// idle. Mirrors `intake/src/main.rs`'s `run_sensor_loop`.
async fn run_intake_sensor(
    sensor: SensorLogConfig,
    pool: PgPool,
    cursor_dir: PathBuf,
    poll_interval: Duration,
    cancel: CancellationToken,
    ingested_counter: Arc<std::sync::atomic::AtomicU64>,
    rejected_counter: Arc<std::sync::atomic::AtomicU64>,
) {
    let SensorLogConfig { name, log_path } = sensor;
    let tailer = LogTailer::new(log_path, cursor_dir);
    let mut runner = IntakeRunner::new(tailer, pool, name.clone());
    tracing::info!(sensor = %name, "intake: tailer started");

    loop {
        if cancel.is_cancelled() {
            if let Err(e) = runner.persist_cursor() {
                tracing::error!(sensor = %name, error = %e, "intake: cursor persist on shutdown failed");
            }
            tracing::info!(sensor = %name, "intake: tailer stopped");
            return;
        }

        let result = runner.run_batch().await;

        if result.ingested > 0 || result.rejected > 0 || result.errors > 0 {
            ingested_counter.fetch_add(result.ingested as u64, std::sync::atomic::Ordering::Relaxed);
            rejected_counter.fetch_add(result.rejected as u64, std::sync::atomic::Ordering::Relaxed);
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
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {}
                _ = cancel.cancelled() => {}
            }
        }
    }
}

/// Queue-maintenance loop: populate newly-recommended IPs, withdraw lapsed entries. Mirrors
/// `review/src/main.rs`'s `run_queue_scan_loop`.
async fn run_queue_scan_loop(pool: PgPool, interval: Duration, cancel: CancellationToken) {
    let queue = ReviewQueue::new();
    loop {
        if cancel.is_cancelled() {
            return;
        }
        if let Err(e) = queue.populate(&pool).await {
            tracing::error!(error = %e, "review: queue populate failed");
        }
        if let Err(e) = queue.withdraw(&pool).await {
            tracing::error!(error = %e, "review: queue withdraw failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => { return; }
        }
    }
}

/// Submission poll loop: submit approved entries through the gatekeeper to vendor adapters.
/// Mirrors `review/src/main.rs`'s `run_submission_loop`.
async fn run_submission_loop(
    runner: SubmissionRunner,
    interval: Duration,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match runner.run_once().await {
            Ok(result) => {
                if result.submitted > 0 || result.held > 0 || result.failed > 0 {
                    tracing::info!(
                        submitted = result.submitted,
                        held = result.held,
                        failed = result.failed,
                        "review: submission pass complete"
                    );
                }
            }
            Err(e) => tracing::error!(error = %e, "review: submission run_once failed"),
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => { return; }
        }
    }
}

/// Feed build loop: build snapshot, publish atomically. Mirrors `feed/src/main.rs`'s loop.
async fn run_feed_loop(
    pool: PgPool,
    exclusions: ExclusionEngine,
    feed_config: FeedConfig,
    output_dir: PathBuf,
    interval: Duration,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }

        match FeedBuilder::build(&pool, &exclusions, &feed_config).await {
            Ok(snapshot) => {
                let aggressive = snapshot.aggressive.len();
                let standard = snapshot.standard.len();
                match Publisher::publish(&snapshot, &output_dir, &exclusions, &feed_config) {
                    Ok(()) => {
                        tracing::info!(aggressive, standard, "feed: build published");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "feed: publish failed; previous feed stays in place"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "feed: build failed; no feed published this cycle");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => { return; }
        }
    }
}

/// Console web server. Mirrors `console/src/main.rs`.
async fn run_console(
    pool: PgPool,
    bind_addr: SocketAddr,
    password: String,
    session_secret: [u8; 32],
    feed_output_dir: Option<PathBuf>,
    log_buffer: Arc<LogBuffer>,
    events_ingested: Arc<std::sync::atomic::AtomicU64>,
    events_rejected: Arc<std::sync::atomic::AtomicU64>,
    cancel: CancellationToken,
) {
    let passwords = Arc::new(PasswordStore::new(&password));
    let state = AppState {
        db: pool,
        sessions: Arc::new(SessionStore::new(session_secret)),
        passwords,
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        feed_output_dir,
        startup_time: chrono::Utc::now(),
        version: env!("CARGO_PKG_VERSION"),
        log_buffer,
        events_ingested,
        events_rejected,
    };

    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(bind = %bind_addr, error = %e, "console: failed to bind");
            return;
        }
    };

    tracing::info!(bind = %bind_addr, "console: starting");

    let app = console::routes::router(state).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
    {
        tracing::error!(error = %e, "console: server error");
    }
    tracing::info!("console: shutdown complete");
}

// ---- vendor adapter construction ----

/// Builds boxed vendor adapters + gatekeeper configs from `FullVendorConfig`s. Mirrors
/// `review/src/main.rs`'s `build_adapters`.
fn build_adapters(
    vendors: &[FullVendorConfig],
    client: reqwest::Client,
) -> (
    Vec<Box<dyn VendorAdapter>>,
    Vec<review::gatekeeper::VendorConfig>,
) {
    let mut adapters: Vec<Box<dyn VendorAdapter>> = Vec::with_capacity(vendors.len());
    let mut gate_configs = Vec::with_capacity(vendors.len());
    for vc in vendors {
        let adapter: Box<dyn VendorAdapter> = match vc.name.as_str() {
            "abuseipdb" => Box::new(AbuseIpDb::new(
                client.clone(),
                vc.api_key.clone(),
                vc.api_url.clone(),
            )),
            "dshield" => Box::new(DShield::new(
                client.clone(),
                vc.api_key.clone(),
                vc.api_url.clone(),
            )),
            "otx" => Box::new(OtxAdapter::new(
                client.clone(),
                vc.api_key.clone(),
                vc.api_url.clone(),
            )),
            other => {
                tracing::warn!(
                    vendor = other,
                    "no adapter implementation for this vendor name; skipping"
                );
                continue;
            }
        };
        gate_configs.push(vc.gate_config());
        adapters.push(adapter);
    }
    (adapters, gate_configs)
}

// ---- shutdown signal ----

/// Resolves on SIGINT or SIGTERM.
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
                    "propolis: failed to install SIGTERM handler; waiting on SIGINT only"
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

// ---- entry point ----

#[tokio::main]
async fn main() {
    // Tracing: honor RUST_LOG if set, otherwise default to info. The console's live `/logs`
    // viewer (`console::routes::logs`) needs a copy of every event this process logs, so
    // `LogBufferLayer` is layered onto the same subscriber stack as the existing `fmt` output
    // rather than given a separate filter of its own - see that layer's own doc comment for why
    // adding the `EnvFilter` via `.with()` here is what makes it see exactly what `fmt` prints,
    // no more.
    let log_buffer = Arc::new(LogBuffer::new(LOG_BUFFER_CAPACITY));
    {
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with(tracing_subscriber::fmt::layer())
            .with(console::log_buffer::LogBufferLayer::new(log_buffer.clone()))
            .init();
    }

    // 1. Parse and validate config (fail fast).
    let config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "propolis: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    // 2. Connect PgPool (fail fast).
    let pool = match PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "propolis: failed to connect to PostgreSQL");
            std::process::exit(1);
        }
    };

    // 3. Run migrations (core-scoring + review).
    if let Err(e) = sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
    {
        tracing::error!(error = %e, "propolis: core-scoring migrations failed");
        std::process::exit(1);
    }
    if let Err(e) = review::migrator().run(&pool).await {
        tracing::error!(error = %e, "propolis: review migrations failed");
        std::process::exit(1);
    }

    // 4. Create cursor directory (fail fast).
    if let Err(e) = std::fs::create_dir_all(&config.cursor_dir) {
        tracing::error!(
            path = %config.cursor_dir.display(),
            error = %e,
            "propolis: failed to create cursor directory"
        );
        std::process::exit(1);
    }

    tracing::info!("propolis: starting unified daemon");

    let cancel = CancellationToken::new();
    let mut handles = Vec::new();

    let events_ingested = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let events_rejected = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 5. Spawn intake tailers - one supervised task per sensor log.
    for sensor in config.sensor_logs {
        let pool = pool.clone();
        let cursor_dir = config.cursor_dir.clone();
        let poll_interval = config.poll_interval;
        let cancel = cancel.clone();
        let sensor_name: &'static str = Box::leak(sensor.name.clone().into_boxed_str());
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();

        handles.push(spawn_supervised(
            sensor_name,
            cancel.clone(),
            move |token| {
                let sensor = sensor.clone();
                let pool = pool.clone();
                let cursor_dir = cursor_dir.clone();
                let ing = ing.clone();
                let rej = rej.clone();
                async move {
                    run_intake_sensor(sensor, pool, cursor_dir, poll_interval, token, ing, rej).await;
                }
            },
        ));
    }

    // 6. Spawn review subsystem (queue scan + submission) if enabled.
    if config.review_enabled {
        let pool_r = pool.clone();
        let queue_interval = config.queue_scan_interval;
        let submit_interval = config.submit_poll_interval;
        let vendors = config.vendors.clone();

        handles.push(spawn_supervised("review", cancel.clone(), move |token| {
            let pool = pool_r.clone();
            let vendors = vendors.clone();
            async move {
                let client = reqwest::Client::new();
                let (adapters, gate_configs) = build_adapters(&vendors, client);
                let runner = SubmissionRunner::new(pool.clone(), adapters, gate_configs);

                let queue_token = token.child_token();
                let submit_token = token.child_token();

                let queue_handle =
                    tokio::spawn(run_queue_scan_loop(pool, queue_interval, queue_token));
                let submit_handle =
                    tokio::spawn(run_submission_loop(runner, submit_interval, submit_token));

                token.cancelled().await;
                queue_handle.abort();
                submit_handle.abort();
            }
        }));
    } else {
        tracing::info!("propolis: review subsystem disabled");
    }

    // 7. Spawn feed builder if enabled.
    if config.feed_enabled {
        let pool_f = pool.clone();
        let exclusions =
            ExclusionEngine::new(config.feed_allowlist.clone(), config.feed_delist.clone());
        let feed_config = FeedConfig {
            aggressive_ttl: chrono::Duration::seconds(config.feed_aggressive_ttl.as_secs() as i64),
            standard_ttl: chrono::Duration::seconds(config.feed_standard_ttl.as_secs() as i64),
        };
        let output_dir = config.feed_output_dir.clone();
        let build_interval = config.feed_build_interval;

        handles.push(spawn_supervised("feed", cancel.clone(), move |token| {
            let pool = pool_f.clone();
            let exclusions = exclusions.clone();
            let feed_config = feed_config.clone();
            let output_dir = output_dir.clone();
            async move {
                run_feed_loop(
                    pool,
                    exclusions,
                    feed_config,
                    output_dir,
                    build_interval,
                    token,
                )
                .await;
            }
        }));
    } else {
        tracing::info!("propolis: feed subsystem disabled");
    }

    // 8. Spawn VirusTotal scanner if enabled.
    if config.vt_enabled {
        let pool_vt = pool.clone();
        let vt_config = review::virustotal::VtConfig {
            api_key: config.vt_api_key.clone(),
            upload_unknown: config.vt_upload_unknown,
            scan_interval_secs: config.vt_scan_interval_secs,
            request_delay_ms: 15_000,
        };

        handles.push(spawn_supervised("virustotal", cancel.clone(), move |token| {
            let pool = pool_vt.clone();
            let vt_config = vt_config.clone();
            async move {
                let spool_dirs: Vec<(&str, std::path::PathBuf)> = vec![
                    ("ssh", std::path::PathBuf::from("/var/spool/propolis/ssh")),
                    ("adb", std::path::PathBuf::from("/var/spool/propolis/adb")),
                    ("ftp", std::path::PathBuf::from("/var/spool/propolis/ftp")),
                    ("catchall", std::path::PathBuf::from("/var/spool/propolis/catchall")),
                ];
                loop {
                    if token.is_cancelled() {
                        tracing::info!("virustotal: scanner stopped");
                        return;
                    }
                    review::virustotal::scan_spool(&pool, &vt_config, &spool_dirs).await;
                    review::virustotal::cleanup_old_samples(&spool_dirs, 30).await;
                    tokio::select! {
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(vt_config.scan_interval_secs)) => {}
                        _ = token.cancelled() => {}
                    }
                }
            }
        }));
    } else {
        tracing::info!("propolis: virustotal scanner disabled");
    }

    // 9. Spawn console web server.
    {
        let pool_c = pool.clone();
        let bind = config.console_bind;
        let password = config.console_password.clone();
        let session_secret = config.console_session_secret;
        let feed_output_dir = if config.feed_enabled {
            Some(config.feed_output_dir.clone())
        } else {
            None
        };
        let log_buffer = log_buffer.clone();
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();

        handles.push(spawn_supervised("console", cancel.clone(), move |token| {
            let pool = pool_c.clone();
            let password = password.clone();
            let feed_dir = feed_output_dir.clone();
            let log_buffer = log_buffer.clone();
            let ing = ing.clone();
            let rej = rej.clone();
            async move {
                run_console(
                    pool,
                    bind,
                    password,
                    session_secret,
                    feed_dir,
                    log_buffer,
                    ing,
                    rej,
                    token,
                )
                .await;
            }
        }));
    }

    // 9. Wait for shutdown signal.
    shutdown_signal().await;
    tracing::info!("propolis: shutdown signal received");

    // 10. Cancel all subsystems.
    cancel.cancel();

    // 11. Await all handles with timeout.
    let shutdown = async {
        for handle in handles {
            let _ = handle.await;
        }
    };

    if tokio::time::timeout(SHUTDOWN_TIMEOUT, shutdown)
        .await
        .is_err()
    {
        tracing::warn!(
            timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
            "propolis: shutdown timed out; exiting"
        );
    }

    pool.close().await;
    tracing::info!("propolis: shutdown complete");
}
