//! Propolis unified daemon: composes intake, review, feed, and console as concurrent tokio tasks
//! sharing one PgPool. See `internal/design/07-runtime-coordination-deployment.md`.
//!
//! Startup sequence: parse config, connect PgPool, run migrations, spawn all four subsystems via
//! `spawn_supervised`, wait for shutdown signal, cancel all subsystems, await with timeout.

mod config;
mod ops_alert;
mod supervisor;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

use config::SensorLogConfig;
use ops_alert::condition::{IntakeProgress, SensorIntake, SupervisorHandle};
use ops_alert::conditions::intake::progress_from_batch;
use supervisor::spawn_supervised;

use console::AppState;
use console::auth::{PasswordStore, RateLimiter, SessionStore};
use console::log_buffer::LogBuffer;
use feed::{ExclusionEngine, FeedBuilder, FeedConfig, Publisher};
use intake::runner::IntakeRunner;
use intake::tailer::LogTailer;
use review::fetcher::{self, FetchDeps, guard::SystemResolver, http::FetchLimits};
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{AbuseIpDb, DShield, FullVendorConfig, OtxAdapter, VendorAdapter};

/// Absolute path the malware fetcher writes captured samples to. Hardcoded, matching the VT
/// scanner's own `spool_dirs` below and `console/src/routes/samples.rs`'s identical list - not an
/// operator env var, same convention as every other sensor's `SPOOL_MAX_FILE_SIZE`/
/// `SPOOL_GLOBAL_BUDGET` constants.
const FETCH_SPOOL_DIR: &str = "/var/spool/propolis/fetched";

/// Root of the capture spool the ops-monitor's capacity condition watches for free space. The
/// per-sensor and fetched subdirectories all live under it, so it is the volume that fills as
/// captured samples accumulate.
const OPS_SPOOL_ROOT: &str = "/var/spool/propolis";

/// Global byte budget for the fetched-malware spool. Matches `review::fetcher`'s own orchestration
/// tests' convention (10 MB/file, 1 GB total) rather than the smaller 100 MB the upload-capture
/// sensors use (`sensor-ftp`/`sensor-adb`) - this spool is a dedicated malware corpus growing over
/// time from internet-wide staging servers, not an incidental per-connection upload side channel.
/// The per-file cap is NOT a second constant here: it is `config.fetch_max_bytes`, the same
/// operator-tunable byte guard the streaming HTTP fetch itself enforces, so the two can never
/// drift apart into two independently-set byte ceilings for what is really one property.
const FETCH_SPOOL_GLOBAL_BUDGET: u64 = 1_000_000_000;

/// Enumerates every unicast IPv4/IPv6 address bound to a live local interface, via
/// `nix::ifaddrs::getifaddrs` (the OS `getifaddrs(3)` call). Loopback and link-local addresses are
/// included deliberately: this set only needs to contain every address the OS considers "us" - a
/// separate, independent check (`review::fetcher::guard::is_forbidden_egress_target`, backed by
/// `core_scoring::is_reserved_ip`) already rejects those ranges as fetch targets regardless of
/// `own_ips`, so redundancy here costs nothing.
///
/// Returns an empty set (never panics) on enumeration failure - the caller is responsible for
/// treating that as fail-closed, since an empty `own_ips` means the SSRF guard cannot exclude this
/// node's own addresses as fetch targets.
fn local_interface_ips() -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    match nix::ifaddrs::getifaddrs() {
        Ok(addrs) => {
            for ifaddr in addrs {
                let Some(sockaddr) = ifaddr.address else {
                    continue;
                };
                if let Some(v4) = sockaddr.as_sockaddr_in() {
                    ips.insert(IpAddr::V4(v4.ip()));
                } else if let Some(v6) = sockaddr.as_sockaddr_in6() {
                    ips.insert(IpAddr::V6(v6.ip()));
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "fetcher: failed to enumerate local interface addresses");
        }
    }
    ips
}

/// True when NOT ONE address in `own_ips` is a real public address - i.e. every entry is
/// loopback/private/link-local/reserved. On a NAT'd/DNAT'd node this is the common case: this
/// node's own public WAN IP is never bound to any local interface, so `local_interface_ips()`
/// alone cannot see it and `own_ips` ends up non-empty (loopback, the private LAN address) but
/// still missing the one address that actually matters for self-targeting protection. Reuses
/// `guard::is_forbidden_egress_target`'s own canonicalization/reserved-range logic (an empty
/// `own` set here, since this asks "is this address itself public", not "is it in some set") so
/// this stays in lockstep with what the SSRF guard itself treats as forbidden.
fn own_ips_lack_a_public_address(own_ips: &HashSet<IpAddr>) -> bool {
    own_ips
        .iter()
        .all(|ip| fetcher::guard::is_forbidden_egress_target(*ip, &HashSet::new()).is_some())
}

/// A per-UTC-day cap on how many fetch attempts the malware fetcher may start, mirroring
/// `review::virustotal::DailyBudget`'s pattern - own ONE instance outside the per-cycle loop body,
/// reset only on a day rollover, never re-initialized per cycle (that exact mistake was already
/// shipped once for the VT scanner's daily cap and had to be fixed - see
/// `internal/roadmap.md`/the VT daily-cap-reset fix this project already shipped). Not the same
/// type as `review::virustotal::DailyBudget`: that one is consumed one unit per item inside its
/// own loop; this one instead grants a whole cycle's `batch` size up front (via `reserve`), since
/// `run_cycle`'s internal selection and concurrency are opaque from this call site - the cap must
/// be enforced by bounding `batch` before the cycle runs, not by counting after the fact.
///
/// `reserve` alone is NOT the whole protocol: it is a pessimistic upper bound (never grant past
/// what remains), but a cycle typically uses only a fraction of its grant - an idle honeypot (the
/// common case; file-download events are rare) selects zero or few candidates most cycles. The
/// caller MUST call `refund` once the cycle's actual work is known, giving back
/// `grant - actually_fetched`, or the daily cap silently counts requested batch size instead of
/// real fetch attempts and drains itself on pure no-op cycles (fixed after this was shipped once
/// with `reserve`'s effect baked directly into a since-removed `consume_up_to` that never
/// reconciled).
struct DailyFetchBudget {
    limit: u32,
    used: u32,
    day: chrono::NaiveDate,
}

impl DailyFetchBudget {
    fn new(limit: u32, today: chrono::NaiveDate) -> Self {
        Self {
            limit,
            used: 0,
            day: today,
        }
    }

    /// Resets `used` first if the UTC day has rolled over, then grants up to `want` against
    /// whatever remains of today's cap - never more, so a single cycle can never exceed the daily
    /// limit even though `run_cycle` only ever sees the granted amount as its own `batch` size.
    /// The grant is provisional: the caller reconciles it with `refund` once real usage is known.
    fn reserve(&mut self, now: chrono::DateTime<chrono::Utc>, want: u32) -> u32 {
        let today = now.date_naive();
        if today != self.day {
            self.day = today;
            self.used = 0;
        }
        let remaining = self.limit.saturating_sub(self.used);
        let grant = remaining.min(want);
        self.used += grant;
        grant
    }

    /// Give back `unused` slots from a previous `reserve` grant once the cycle's actual fetch
    /// count is known. Saturating: the counter that gates this guard must never wrap silently
    /// even if called out of balance with `reserve` (e.g. a day rollover landed between the two).
    fn refund(&mut self, unused: u32) {
        self.used = self.used.saturating_sub(unused);
    }
}

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// How many recent tracing events `console::routes::logs`'s viewer keeps in memory for a
/// freshly loaded page (`console::log_buffer::LogBuffer::new`'s own doc comment - live-streamed
/// entries after that are unbounded by this, only by the browser tab's own cap).
const LOG_BUFFER_CAPACITY: usize = 1000;

// ---- subsystem loops ----

/// One intake sensor's poll loop - reads batches, appends to ledger, persists cursor, sleeps on
/// idle. Mirrors `intake/src/main.rs`'s `run_sensor_loop`.
#[allow(clippy::too_many_arguments)]
async fn run_intake_sensor(
    sensor: SensorLogConfig,
    intake_key: &'static str,
    pool: PgPool,
    cursor_dir: PathBuf,
    poll_interval: Duration,
    cancel: CancellationToken,
    ingested_counter: Arc<std::sync::atomic::AtomicU64>,
    rejected_counter: Arc<std::sync::atomic::AtomicU64>,
    intake_progress: IntakeProgress,
) {
    let SensorLogConfig { name, log_path } = sensor;
    let tailer = LogTailer::new(log_path, cursor_dir);
    let mut runner = IntakeRunner::new(tailer, pool, name.clone());
    tracing::info!(sensor = %name, "intake: tailer started");

    // Seed the liveness entry so a sensor that never ingests still reads as "recently alive" until
    // its first real stall, rather than looking stalled from t=0.
    {
        let mut map = intake_progress.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(intake_key).or_insert(SensorIntake {
            last_advanced_at: Instant::now(),
            backlog: false,
        });
    }

    loop {
        if cancel.is_cancelled() {
            if let Err(e) = runner.persist_cursor() {
                tracing::error!(sensor = %name, error = %e, "intake: cursor persist on shutdown failed");
            }
            tracing::info!(sensor = %name, "intake: tailer stopped");
            return;
        }

        let result = runner.run_batch().await;

        // Publish intake liveness for the ops-monitor's intake-stalled condition.
        let (advanced, backlog) =
            progress_from_batch(result.ingested, result.rejected, result.errors);
        {
            let mut map = intake_progress.lock().unwrap_or_else(|p| p.into_inner());
            let entry = map.entry(intake_key).or_insert(SensorIntake {
                last_advanced_at: Instant::now(),
                backlog: false,
            });
            if advanced {
                entry.last_advanced_at = Instant::now();
            }
            entry.backlog = backlog;
        }

        if result.ingested > 0 || result.rejected > 0 || result.errors > 0 {
            ingested_counter
                .fetch_add(result.ingested as u64, std::sync::atomic::Ordering::Relaxed);
            rejected_counter
                .fetch_add(result.rejected as u64, std::sync::atomic::Ordering::Relaxed);
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
                        // Record the publish time for the ops-monitor's feed-stale condition. A
                        // marker failure must not disturb a successful publish - log and continue.
                        if let Err(e) = ops_alert::conditions::feed::touch_marker(&output_dir) {
                            tracing::warn!(error = %e, "feed: last-published marker update failed");
                        }
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

/// What the console subsystem needs from the daemon at startup.
///
/// Grouped rather than passed as a long parameter list: this had grown to nine positional
/// arguments, four of them `Arc`s of similar shape, which is exactly the arrangement where a
/// caller silently swaps two and nothing complains. Named fields make the call site checkable.
struct ConsoleRuntime {
    pool: PgPool,
    bind_addr: SocketAddr,
    password: String,
    session_secret: [u8; 32],
    feed_output_dir: Option<PathBuf>,
    geoip_dir: Option<PathBuf>,
    log_buffer: Arc<LogBuffer>,
    events_ingested: Arc<std::sync::atomic::AtomicU64>,
    events_rejected: Arc<std::sync::atomic::AtomicU64>,
}

/// Console web server. Mirrors `console/src/main.rs`.
async fn run_console(rt: ConsoleRuntime, cancel: CancellationToken) {
    let ConsoleRuntime {
        pool,
        bind_addr,
        password,
        session_secret,
        feed_output_dir,
        geoip_dir,
        log_buffer,
        events_ingested,
        events_rejected,
    } = rt;
    let passwords = Arc::new(PasswordStore::new(&password));
    let geoip = Arc::new(match geoip_dir {
        Some(ref dir) => console::geoip::GeoIp::load(dir),
        None => console::geoip::GeoIp::disabled(),
    });
    if geoip.is_enabled() {
        tracing::info!("console: GeoLite2 enrichment enabled");
    }
    let state = AppState {
        db: pool,
        sessions: Arc::new(SessionStore::new(session_secret)),
        passwords,
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip,
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
    // Shared supervised-state map: the supervisor writes each subsystem's state, the ops-monitor
    // reads it (subsystem-gaveup and sensor-down conditions).
    let supervisor_state: SupervisorHandle = Arc::new(Mutex::new(HashMap::new()));
    // Shared per-sensor intake liveness: each sensor loop writes its own entry, the ops-monitor
    // reads it (intake-stalled condition).
    let intake_progress: IntakeProgress = Arc::new(Mutex::new(HashMap::new()));

    for sensor in config.sensor_logs {
        let pool = pool.clone();
        let cursor_dir = config.cursor_dir.clone();
        let poll_interval = config.poll_interval;
        let cancel = cancel.clone();
        let sensor_name: &'static str = Box::leak(sensor.name.clone().into_boxed_str());
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();
        let progress = intake_progress.clone();

        handles.push(spawn_supervised(
            sensor_name,
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
                let sensor = sensor.clone();
                let pool = pool.clone();
                let cursor_dir = cursor_dir.clone();
                let ing = ing.clone();
                let rej = rej.clone();
                let progress = progress.clone();
                async move {
                    run_intake_sensor(
                        sensor,
                        sensor_name,
                        pool,
                        cursor_dir,
                        poll_interval,
                        token,
                        ing,
                        rej,
                        progress,
                    )
                    .await;
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

        handles.push(spawn_supervised(
            "review",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
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
            },
        ));
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
            windows: config
                .feed_windows
                .iter()
                .map(|(label, dur)| {
                    (
                        label.clone(),
                        chrono::Duration::seconds(dur.as_secs() as i64),
                    )
                })
                .collect(),
        };
        let output_dir = config.feed_output_dir.clone();
        let build_interval = config.feed_build_interval;

        handles.push(spawn_supervised(
            "feed",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
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
            },
        ));
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
            daily_limit: 450,
        };

        handles.push(spawn_supervised(
            "virustotal",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
            let pool = pool_vt.clone();
            let vt_config = vt_config.clone();
            async move {
                let spool_dirs: Vec<(&str, std::path::PathBuf)> = vec![
                    ("ssh", std::path::PathBuf::from("/var/spool/propolis/ssh")),
                    ("adb", std::path::PathBuf::from("/var/spool/propolis/adb")),
                    ("ftp", std::path::PathBuf::from("/var/spool/propolis/ftp")),
                    ("catchall", std::path::PathBuf::from("/var/spool/propolis/catchall")),
                    ("fetched", std::path::PathBuf::from(FETCH_SPOOL_DIR)),
                ];
                // One budget owned across every scan cycle so the cap is per DAY, not per cycle.
                let mut budget = review::virustotal::DailyBudget::new(
                    vt_config.daily_limit,
                    chrono::Utc::now().date_naive(),
                );
                loop {
                    if token.is_cancelled() {
                        tracing::info!("virustotal: scanner stopped");
                        return;
                    }
                    review::virustotal::scan_spool(&pool, &vt_config, &spool_dirs, &mut budget).await;
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

    // 9. Spawn malware fetcher if enabled.
    if config.fetch_enabled {
        let pool_fetch = pool.clone();
        let fetch_own_ips_configured = config.fetch_own_ips.clone();
        let fetch_user_agent = config.fetch_user_agent.clone();
        let fetch_interval = config.fetch_interval;
        let fetch_max_bytes = config.fetch_max_bytes;
        let fetch_max_per_host_hour = config.fetch_max_per_host_hour;
        let fetch_max_hops = config.fetch_max_hops;
        let fetch_max_depth = config.fetch_max_depth;
        let fetch_daily_cap = config.fetch_daily_cap;
        let fetch_batch_size = config.fetch_batch_size;
        let fetch_connect_timeout = config.fetch_connect_timeout;
        let fetch_read_timeout = config.fetch_read_timeout;
        let fetch_total_timeout = config.fetch_total_timeout;

        handles.push(spawn_supervised(
            "fetcher",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
                let pool = pool_fetch.clone();
                let own_ips_extra = fetch_own_ips_configured.clone();
                let user_agent = fetch_user_agent.clone();
                async move {
                    // Fail-closed only against the DEGENERATE case: if own_ips ends up completely
                    // empty (interface enumeration failed outright and no PROPOLIS_FETCH_OWN_IPS is
                    // configured), the SSRF guard has nothing at all to exclude, so refuse to run
                    // rather than run unsafe. This does NOT mean self-targeting protection is
                    // complete otherwise - see the warning below for the gap this does not close.
                    // Computed once at startup, like every other field of `deps` below - not
                    // re-checked per cycle, matching how the VT loop builds its own
                    // `spool_dirs`/`vt_config` once outside the loop and reuses them for every call.
                    let mut own_ips: HashSet<IpAddr> = local_interface_ips();
                    own_ips.extend(own_ips_extra);
                    if own_ips.is_empty() {
                        tracing::error!(
                            "fetcher: own_ips is empty (local interface enumeration failed and no \
                         PROPOLIS_FETCH_OWN_IPS configured); refusing to run - an empty own_ips \
                         set cannot vet a fetch against this node's own addresses"
                        );
                        return;
                    }

                    // Cannot auto-detect a NAT'd/DNAT'd node's public WAN IP - nothing visible on
                    // this host reveals it, so this is a best-effort operator reminder, not a
                    // guarantee. If every address in own_ips is reserved/private/link-local, this is
                    // very likely a NAT'd node whose PROPOLIS_FETCH_OWN_IPS was never set: this
                    // node's own public IP is not bound to any local interface, so a URL an attacker
                    // stages pointing back at it would NOT be excluded as a fetch target.
                    if own_ips_lack_a_public_address(&own_ips) {
                        tracing::warn!(
                            "fetcher: own_ips contains no public address (only loopback/private/\
                         link-local addresses found) - if this node is behind NAT, its public WAN \
                         IP is not on any local interface and will NOT be excluded as a fetch \
                         target unless PROPOLIS_FETCH_OWN_IPS names it explicitly; set \
                         PROPOLIS_FETCH_OWN_IPS to this node's public egress IP(s) before relying \
                         on self-targeting protection - see INSTALL.md's malware fetcher section"
                        );
                    }

                    let spool_dir = std::path::PathBuf::from(FETCH_SPOOL_DIR);
                    if let Err(e) = std::fs::create_dir_all(&spool_dir) {
                        tracing::error!(
                            error = %e,
                            path = FETCH_SPOOL_DIR,
                            "fetcher: failed to create spool directory, refusing to run"
                        );
                        return;
                    }

                    let deps = FetchDeps {
                        pool,
                        spool: sensor_framework::QuarantineSpool::new(
                            spool_dir,
                            fetch_max_bytes as u64,
                            FETCH_SPOOL_GLOBAL_BUDGET,
                        ),
                        own_ips,
                        limits: FetchLimits {
                            max_bytes: fetch_max_bytes,
                            connect_timeout: fetch_connect_timeout,
                            read_timeout: fetch_read_timeout,
                            total_timeout: fetch_total_timeout,
                            user_agent,
                        },
                        resolver: Box::new(SystemResolver),
                        max_hops: fetch_max_hops,
                        max_depth: fetch_max_depth,
                        per_host_hour: fetch_max_per_host_hour,
                    };

                    // One budget owned across every cycle, never re-initialized inside the loop below
                    // - see `DailyFetchBudget`'s own doc comment for why that would reintroduce the
                    // daily-cap-reset bug already fixed once for the VT scanner.
                    let mut budget =
                        DailyFetchBudget::new(fetch_daily_cap, chrono::Utc::now().date_naive());

                    loop {
                        if token.is_cancelled() {
                            tracing::info!("fetcher: scanner stopped");
                            return;
                        }

                        let grant = budget.reserve(chrono::Utc::now(), fetch_batch_size as u32);
                        if grant > 0 {
                            // Awaited to completion before the next cycle can start or the sleep
                            // below begins: `run_cycle`'s own `select_candidates` does not claim rows
                            // (no FOR UPDATE SKIP LOCKED), so two overlapping calls would double-fetch
                            // and double the effective per-host cap.
                            let stats = fetcher::run_cycle(&deps, grant as usize).await;

                            // Reconcile the daily budget against ACTUAL fetch attempts, not the
                            // requested grant: `skipped_bucket` candidates never reached the network
                            // (the per-host-hour bucket gated them before any fetch), and an idle
                            // honeypot selects few or zero candidates most cycles. Charging the full
                            // grant regardless would drain `daily_cap` in `daily_cap / batch_size`
                            // idle cycles and then sit paused for the rest of the day.
                            let actually_fetched =
                                stats.selected.saturating_sub(stats.skipped_bucket);
                            budget.refund(grant.saturating_sub(actually_fetched as u32));

                            if stats.selected > 0 {
                                tracing::info!(
                                    selected = stats.selected,
                                    succeeded = stats.succeeded,
                                    rejected = stats.rejected,
                                    too_big = stats.too_big,
                                    timeout = stats.timeout,
                                    empty = stats.empty,
                                    dead = stats.dead,
                                    skipped_bucket = stats.skipped_bucket,
                                    enqueued_children = stats.enqueued_children,
                                    errors = stats.errors,
                                    "fetcher: cycle complete"
                                );
                            }
                        } else {
                            tracing::debug!(
                                "fetcher: daily cap reached, pausing until the UTC day rolls over"
                            );
                        }

                        tokio::select! {
                            _ = tokio::time::sleep(fetch_interval) => {}
                            _ = token.cancelled() => {}
                        }
                    }
                }
            },
        ));
    } else {
        tracing::info!("propolis: malware fetcher disabled");
    }

    // 10. Spawn console web server.
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
        let geoip_dir = config.geoip_dir.clone();
        let log_buffer = log_buffer.clone();
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();

        handles.push(spawn_supervised(
            "console",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
                let pool = pool_c.clone();
                let password = password.clone();
                let feed_dir = feed_output_dir.clone();
                let geoip_dir = geoip_dir.clone();
                let log_buffer = log_buffer.clone();
                let ing = ing.clone();
                let rej = rej.clone();
                async move {
                    run_console(
                        ConsoleRuntime {
                            pool,
                            bind_addr: bind,
                            password,
                            session_secret,
                            feed_output_dir: feed_dir,
                            geoip_dir,
                            log_buffer,
                            events_ingested: ing,
                            events_rejected: rej,
                        },
                        token,
                    )
                    .await;
                }
            },
        ));
    }

    // 10.5. Spawn the operational self-alerting monitor if enabled. It reads the shared supervisor
    // and intake handles the other subsystems publish into, plus disk/DB/feed/vendor signals, and
    // pages ntfy on degradation. It is itself supervised - a panic restarts it - but if it gives up
    // entirely, nothing pages about the monitor being down (the who-watches-the-watcher limit,
    // accepted in the design). Capacity watches the daemon's own always-present data directories:
    // the cursor/data volume and the capture spool volume; a DB on a volume distinct from the data
    // volume is Postgres's own concern (documented capacity limitation).
    if config.ops_alert.enabled {
        let pool_ops = pool.clone();
        let ops_cfg = config.ops_alert.clone();
        let ops_supervisor = supervisor_state.clone();
        let ops_intake = intake_progress.clone();
        let pg_data_volume = config.cursor_dir.clone();
        let spool_dir = PathBuf::from(OPS_SPOOL_ROOT);
        let feed_marker = ops_alert::conditions::feed::marker_path(&config.feed_output_dir);
        let feed_build_interval = config.feed_build_interval;

        handles.push(spawn_supervised(
            "ops-monitor",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
                let pool = pool_ops.clone();
                let ops_cfg = ops_cfg.clone();
                let supervisor = ops_supervisor.clone();
                let intake_progress = ops_intake.clone();
                let pg_data_volume = pg_data_volume.clone();
                let spool_dir = spool_dir.clone();
                let feed_marker_path = feed_marker.clone();
                async move {
                    let dispatcher = match ops_alert::dispatch::Dispatcher::new(&ops_cfg) {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "ops-monitor: dispatcher build failed; not starting (fix config)"
                            );
                            return;
                        }
                    };
                    let ctx = ops_alert::condition::MonitorCtx {
                        pool,
                        pg_data_volume,
                        spool_dir,
                        supervisor,
                        intake_progress,
                        feed_marker_path,
                        feed_build_interval,
                        cfg: ops_cfg,
                    };
                    ops_alert::monitor::Monitor::new(
                        ops_alert::monitor::default_conditions(),
                        ctx,
                        dispatcher,
                    )
                    .run(token)
                    .await;
                }
            },
        ));
    } else {
        tracing::info!("propolis: operational self-alerting disabled");
    }

    // 11. Wait for shutdown signal.
    shutdown_signal().await;
    tracing::info!("propolis: shutdown signal received");

    // 12. Cancel all subsystems.
    cancel.cancel();

    // 13. Await all handles with timeout.
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

#[cfg(test)]
mod daily_fetch_budget_tests {
    use super::*;

    fn at(ts: &str) -> chrono::DateTime<chrono::Utc> {
        ts.parse().unwrap()
    }

    // Fix round 1, #1 (important): a cycle that selects nothing (or nothing past the per-host
    // bucket) must cost the daily budget zero, or an idle honeypot - the common case - drains
    // daily_cap in daily_cap/batch_size cycles on pure no-op cycles and then sits paused for the
    // rest of the day.
    #[test]
    fn idle_cycles_with_zero_actual_work_do_not_drain_the_daily_budget() {
        let day = at("2026-08-22T00:00:00Z");
        let mut budget = DailyFetchBudget::new(10, day.date_naive());
        for _ in 0..50 {
            let grant = budget.reserve(day, 20);
            assert_eq!(
                grant, 10,
                "a burst must still be bounded by the full remaining budget"
            );
            budget.refund(grant); // idle cycle: nothing was actually fetched
        }
        // Fully available still - none of the 50 idle cycles above cost anything real.
        assert_eq!(budget.reserve(day, 10), 10);
    }

    #[test]
    fn a_cycle_that_actually_fetches_k_consumes_exactly_k() {
        let day = at("2026-08-22T00:00:00Z");
        let mut budget = DailyFetchBudget::new(10, day.date_naive());
        let grant = budget.reserve(day, 8);
        assert_eq!(grant, 8);
        budget.refund(grant - 3); // only 3 of the 8 granted slots were actually fetched

        // 3 consumed, 7 of the original 10 remain.
        assert_eq!(budget.reserve(day, 20), 7);
    }

    #[test]
    fn reserve_still_hard_bounds_a_single_burst_to_remaining_budget() {
        let day = at("2026-08-22T00:00:00Z");
        let mut budget = DailyFetchBudget::new(5, day.date_naive());
        assert_eq!(
            budget.reserve(day, 100),
            5,
            "a single cycle must never be granted more than the daily cap regardless of batch size"
        );
    }

    #[test]
    fn resets_on_a_new_utc_day_and_is_not_re_initialized_mid_run() {
        let day1 = at("2026-08-21T23:00:00Z");
        let mut budget = DailyFetchBudget::new(10, day1.date_naive());
        let grant = budget.reserve(day1, 10);
        budget.refund(0); // all 10 were actually fetched
        assert_eq!(budget.reserve(day1, 1), 0, "exhausted for the rest of day1");
        assert_eq!(grant, 10);

        let day2 = at("2026-08-22T00:05:00Z");
        assert_eq!(
            budget.reserve(day2, 10),
            10,
            "must reset on the new UTC day rather than staying exhausted"
        );
    }
}

// Fix round 1, #2 (important): the empty-own_ips fail-closed check almost never fires in
// practice (getifaddrs always returns loopback), and on a NAT'd node the public WAN IP is never
// on any local interface - own_ips_lack_a_public_address is the runtime signal that closes that
// visibility gap with a warning (never auto-detection, which is impossible from inside the NAT).
#[cfg(test)]
mod own_ips_public_address_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_and_private_only_is_flagged() {
        let own_ips: HashSet<IpAddr> = [ip("127.0.0.1"), ip("10.20.30.109"), ip("::1")]
            .into_iter()
            .collect();
        assert!(
            own_ips_lack_a_public_address(&own_ips),
            "a NAT'd node's local-interface-only own_ips must be flagged as missing a public \
             address"
        );
    }

    #[test]
    fn a_single_public_address_clears_the_warning() {
        // One real public address (e.g. from PROPOLIS_FETCH_OWN_IPS) alongside the usual
        // loopback/private noise is enough - the node has a public address covered. 8.8.8.8 is
        // the same canonical "definitely public" fixture `guard.rs`'s own tests use (not
        // 203.0.113.x - RFC5737 documentation space is itself in the reserved ranges).
        let own_ips: HashSet<IpAddr> = [ip("127.0.0.1"), ip("10.20.30.109"), ip("8.8.8.8")]
            .into_iter()
            .collect();
        assert!(
            !own_ips_lack_a_public_address(&own_ips),
            "a real public address in own_ips must clear the warning"
        );
    }
}
