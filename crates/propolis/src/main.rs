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
use log_tailer::LogTailer;
use review::fetcher::{self, FetchDeps, guard::SystemResolver, http::FetchLimits};
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{AbuseIpDb, DShield, FullVendorConfig, OtxAdapter, VendorAdapter};

/// Path the malware fetcher writes captured samples to - the same `fetched` bucket
/// `review::spool::all_body_dirs` hands the VT scan, sample retention and the console samples
/// view, so the writer and every reader agree by construction. Not an operator env var, same
/// convention as every other sensor's `SPOOL_MAX_FILE_SIZE`/`SPOOL_GLOBAL_BUDGET` constants.
/// Resolved from the shared spool root, never hardcoded, so it follows `PROPOLIS_SPOOL_ROOT` like
/// every other directory under the tree and a deployment that relocates the spool does not leave the
/// fetcher writing somewhere the scanner and console do not look.
fn fetch_spool_dir() -> std::path::PathBuf {
    review::spool::spool_subdir("fetched")
}

/// Age past which a spooled sample body is deleted by the `sample-retention` subsystem, and how
/// often that pass runs. Compile-time like the spool byte caps, not an env var: retention is a
/// property of the evidence model (`docs/operations/retention.md`), and the DB row recording a
/// sample's analysis outlives the bytes. The pass is a directory walk, so hourly is cheap and
/// keeps a spool from sitting full for a whole day after its oldest bodies expire.
const SAMPLE_RETENTION_DAYS: u64 = 30;
const SAMPLE_RETENTION_INTERVAL: Duration = Duration::from_secs(3600);

/// Root of the capture spool the ops-monitor's capacity condition watches for free space. The
/// per-sensor and fetched subdirectories all live under it, so it is the volume that fills as
/// captured samples accumulate.
fn ops_spool_root() -> std::path::PathBuf {
    review::spool::spool_root()
}

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
                if result.submitted > 0
                    || result.held > 0
                    || result.failed > 0
                    || result.unresolved > 0
                {
                    tracing::info!(
                        submitted = result.submitted,
                        held = result.held,
                        failed = result.failed,
                        unresolved = result.unresolved,
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

/// Checks that the feed publisher will actually be able to write, by exercising the same directory
/// the publisher's staging step uses: the PARENT of `output_dir`, since staging is created as a
/// sibling (`feed::publisher::create_staging_dir`) so the atomic rename stays same-filesystem.
///
/// Creates and removes a probe directory rather than inspecting permission bits, which is the only
/// way to account for ownership, ACLs, a read-only mount, and the systemd sandbox's ReadWritePaths
/// all at once - the last of which is exactly what a bit-check would have missed.
fn preflight_output_dir(output_dir: &std::path::Path) -> std::io::Result<()> {
    let parent = output_dir.parent().filter(|p| !p.as_os_str().is_empty());
    let Some(parent) = parent else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", output_dir.display()),
        ));
    };
    std::fs::create_dir_all(parent)?;
    let probe = parent.join(format!(
        ".{}.preflight",
        output_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "feed".to_string())
    ));
    // A leftover from a killed run must not make the probe fail; create_dir_all is idempotent.
    std::fs::create_dir_all(&probe)?;
    let _ = std::fs::remove_dir(&probe);
    Ok(())
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
    // Preflight: prove the publish destination is writable BEFORE the first build, so a
    // misconfigured path is one loud line at startup instead of an identical error every interval
    // forever. A real deployment pointed PROPOLIS_FEED_OUTPUT_DIR one level too high, which put the
    // staging directory (a sibling of the output dir) inside a root-owned directory the daemon
    // could not write; it failed every 15 minutes for hours, unnoticed.
    //
    // Logged, not fatal: the feed is one subsystem, and aborting the whole daemon would also stop
    // intake and the console, which are unaffected. The ops-monitor's feed-stale condition is what
    // escalates if it stays broken.
    if let Err(e) = preflight_output_dir(&output_dir) {
        tracing::error!(
            output_dir = %output_dir.display(),
            error = %e,
            "feed: output directory is not writable; every publish will fail until this is fixed. \
             Staging is created as a SIBLING of the output directory, so the publishing user needs \
             write permission on its PARENT, not just on the output directory itself."
        );
    }

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
    rdns_enabled: bool,
    trusted_proxy: bool,
    metrics_token: Option<String>,
    log_buffer: Arc<LogBuffer>,
    events_ingested: Arc<std::sync::atomic::AtomicU64>,
    events_rejected: Arc<std::sync::atomic::AtomicU64>,
    /// The supervisor map, so `/ready` can report a subsystem that has given up.
    supervisor: SupervisorHandle,
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
        rdns_enabled,
        trusted_proxy,
        metrics_token,
        log_buffer,
        events_ingested,
        events_rejected,
        supervisor,
    } = rt;
    // Sorted so the readiness body is stable across polls; a poisoned lock reads as "nothing
    // known", never as a crash inside the probe.
    let gave_up_subsystems: console::SubsystemHealth = Arc::new(move || {
        let mut names: Vec<&'static str> = supervisor
            .lock()
            .map(|map| {
                map.iter()
                    .filter(|(_, s)| s.is_down())
                    .map(|(name, _)| *name)
                    .collect()
            })
            .unwrap_or_default();
        names.sort_unstable();
        names
    });
    let passwords = Arc::new(PasswordStore::new(&password));
    // Load the GeoLite2 databases (a synchronous, potentially large file read) on a blocking-pool
    // thread so it never parks a shared runtime worker at startup - run_console is a supervised task
    // co-located with the sensors and other subsystems on the same tokio runtime.
    let geoip = Arc::new(match geoip_dir {
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
        sessions: Arc::new(SessionStore::new(session_secret)),
        passwords,
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip,
        rdns: Arc::new(console::rdns::RdnsResolver::new(rdns_enabled)),
        feed_output_dir,
        startup_time: chrono::Utc::now(),
        version: env!("CARGO_PKG_VERSION"),
        log_buffer,
        events_ingested,
        events_rejected,
        trusted_proxy,
        metrics_token: metrics_token.map(Arc::from),
        gave_up_subsystems,
    };

    console::warn_if_console_exposed(bind_addr);
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

                    // A dead child restarts the whole review group under the supervisor's
                    // policy; merely awaiting cancellation here left the parent Running over a
                    // panicked loop, invisible to /ready and the ops-monitor.
                    supervisor::watch_children(
                        token,
                        vec![
                            ("review queue scan", queue_handle),
                            ("review submission", submit_handle),
                        ],
                    )
                    .await;
                }
            },
        ));
    } else {
        tracing::info!("propolis: review subsystem disabled");
    }

    // 7. Spawn feed builder if enabled.
    if config.feed_enabled {
        let pool_f = pool.clone();
        let base_exclusions =
            ExclusionEngine::new(config.feed_allowlist.clone(), config.feed_delist.clone());
        let exclusions = if config.feed_asn_allowlist.is_empty() {
            base_exclusions
        } else {
            // ASN suppression configured: load the ASN database off the async worker (a synchronous
            // file read) and layer it on. A missing dir/DB warns and leaves suppression inert (fail
            // open - the CIDR allowlist and reserved checks are untouched), never blocks startup.
            let geoip = match config.geoip_dir.clone() {
                Some(dir) => tokio::task::spawn_blocking(move || geoip::GeoIp::load_asn_only(&dir))
                    .await
                    .unwrap_or_else(|_| geoip::GeoIp::disabled()),
                None => {
                    tracing::warn!(
                        "PROPOLIS_FEED_ASN_ALLOWLIST is set but PROPOLIS_GEOIP_DIR is not; ASN suppression is inert"
                    );
                    geoip::GeoIp::disabled()
                }
            };
            if !geoip.is_enabled() {
                tracing::warn!(
                    "PROPOLIS_FEED_ASN_ALLOWLIST is set but the GeoLite2-ASN database did not load; ASN suppression is inert"
                );
            }
            base_exclusions.with_asn_allowlist(
                config.feed_asn_allowlist.clone(),
                std::sync::Arc::new(geoip),
            )
        };
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
            pending_recheck_secs: config.vt_pending_recheck_secs,
        };

        handles.push(spawn_supervised(
            "virustotal",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
            let pool = pool_vt.clone();
            let vt_config = vt_config.clone();
            async move {
                let spool_dirs = review::spool::all_body_dirs();
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

    // 8b. Sample retention: age out spooled bodies on every deployment. This used to be a step
    // of the VirusTotal scan cycle, so a box without a VT key never evicted a sample by age and
    // its spools were bounded only by the byte budgets, which then refused NEW evidence once old
    // samples had filled them. Retention is not a scanning concern; it runs whether or not any
    // analysis is configured.
    handles.push(spawn_supervised(
        "sample-retention",
        cancel.clone(),
        supervisor_state.clone(),
        move |token| async move {
            let spool_dirs = review::spool::all_body_dirs();
            loop {
                if token.is_cancelled() {
                    return;
                }
                review::virustotal::cleanup_old_samples(&spool_dirs, SAMPLE_RETENTION_DAYS).await;
                tokio::select! {
                    _ = tokio::time::sleep(SAMPLE_RETENTION_INTERVAL) => {}
                    _ = token.cancelled() => {}
                }
            }
        },
    ));

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

                    let spool_dir = fetch_spool_dir();
                    if let Err(e) = std::fs::create_dir_all(&spool_dir) {
                        tracing::error!(
                            error = %e,
                            path = %fetch_spool_dir().display(),
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
                            dns_timeout: fetch_connect_timeout,
                        },
                        resolver: Arc::new(SystemResolver),
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
        let rdns_enabled = config.console_rdns_enabled;
        let console_trusted_proxy = config.console_trusted_proxy;
        let console_metrics_token = config.console_metrics_token.clone();
        let log_buffer = log_buffer.clone();
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();
        let console_supervisor = supervisor_state.clone();

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
                let console_metrics_token = console_metrics_token.clone();
                let supervisor = console_supervisor.clone();
                async move {
                    run_console(
                        ConsoleRuntime {
                            pool,
                            bind_addr: bind,
                            password,
                            session_secret,
                            feed_output_dir: feed_dir,
                            geoip_dir,
                            rdns_enabled,
                            trusted_proxy: console_trusted_proxy,
                            metrics_token: console_metrics_token,
                            log_buffer,
                            events_ingested: ing,
                            events_rejected: rej,
                            supervisor,
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
        let spool_dir = ops_spool_root();
        let ops_spool_dirs = review::spool::all_body_dirs();
        let (vt_enabled, fetch_enabled) = (config.vt_enabled, config.fetch_enabled);
        let feed_marker = ops_alert::conditions::feed::marker_path(&config.feed_output_dir);
        let feed_push_marker =
            ops_alert::conditions::feed::push_marker_path(&config.feed_output_dir);
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
                let spool_dirs = ops_spool_dirs.clone();
                let feed_marker_path = feed_marker.clone();
                let feed_push_marker_path = feed_push_marker.clone();
                async move {
                    // No ntfy target configured: deliver alerts to the local log sink rather than
                    // not alerting at all. Same conditions, same cooldown/dedup policy, different
                    // transport - see `dispatch::LogPoster`.
                    let local_only = ops_cfg.ntfy_url.is_empty();
                    let ctx = ops_alert::condition::MonitorCtx {
                        pool,
                        pg_data_volume,
                        spool_dir,
                        spool_dirs,
                        vt_enabled,
                        fetch_enabled,
                        supervisor,
                        intake_progress,
                        feed_marker_path,
                        feed_push_marker_path,
                        feed_build_interval,
                        cfg: ops_cfg.clone(),
                    };
                    if local_only {
                        tracing::warn!(
                            "ops-monitor: no PROPOLIS_OPS_NTFY_URL configured; alerts go to the \
                             local log at ERROR level only (journalctl -p err). Set the ntfy url \
                             and topic for push delivery."
                        );
                        let dispatcher = ops_alert::dispatch::Dispatcher::with_poster(
                            ops_alert::dispatch::LogPoster,
                            &ops_cfg.ntfy_url,
                            &ops_cfg.ntfy_topic,
                            ops_cfg.ntfy_token.clone(),
                            ops_cfg.repage_cooldown,
                        );
                        ops_alert::monitor::Monitor::new(
                            ops_alert::monitor::default_conditions(),
                            ctx,
                            dispatcher,
                        )
                        .run(token)
                        .await;
                    } else {
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
                        ops_alert::monitor::Monitor::new(
                            ops_alert::monitor::default_conditions(),
                            ctx,
                            dispatcher,
                        )
                        .run(token)
                        .await;
                    }
                }
            },
        ));
    } else {
        // WARN, not INFO: running with no self-monitoring is a risk posture, and at INFO it scrolled
        // past unnoticed while a feed-publish failure repeated for hours and a sensor sat dead.
        tracing::warn!(
            "propolis: operational self-alerting is DISABLED (PROPOLIS_OPS_ENABLED); no feed-stale, \
             sensor-down, intake-stalled or backlog condition will page. Set PROPOLIS_OPS_ENABLED=true \
             (ntfy optional - alerts fall back to the local log)."
        );
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

    // Reproduces the production misconfiguration: the output dir was set one level too high, so the
    // publisher's staging sibling landed in a directory the daemon could not write, and every
    // publish failed silently for hours. The preflight must catch that at startup - and must NOT
    // fire for a correctly writable path, or it would just be noise operators learn to ignore.
    #[test]
    #[cfg(unix)]
    fn preflight_detects_an_unwritable_parent_and_passes_a_writable_one() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");

        // Writable parent: <tmp>/feed/current - the intended layout. Must pass.
        let ok_parent = tmp.path().join("feed");
        std::fs::create_dir(&ok_parent).expect("create writable parent");
        assert!(
            preflight_output_dir(&ok_parent.join("current")).is_ok(),
            "a writable parent must not warn"
        );

        // Unwritable parent, mirroring a root-owned dir the publishing user cannot write.
        let bad_parent = tmp.path().join("locked");
        std::fs::create_dir(&bad_parent).expect("create parent");
        std::fs::set_permissions(&bad_parent, std::fs::Permissions::from_mode(0o555))
            .expect("chmod");
        assert!(
            preflight_output_dir(&bad_parent.join("feed")).is_err(),
            "an unwritable parent must be caught before the first publish"
        );

        std::fs::set_permissions(&bad_parent, std::fs::Permissions::from_mode(0o755)).ok();
    }
}
