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
use supervisor::spawn_supervised_named;

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

/// How often the campaign indexer looks for new ledger rows once it has caught up.
const CAMPAIGN_TICK_INTERVAL: Duration = Duration::from_secs(15);
/// The pause between ticks while it works through a backlog, so a large catch-up shares the
/// database with intake instead of running back to back.
const CAMPAIGN_CATCHUP_PAUSE: Duration = Duration::from_millis(500);

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

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an aborted subsystem gets to unwind (drop its pooled connection) before shutdown moves on.
const ABORT_WAIT: Duration = Duration::from_secs(2);

/// Bound on `pool.close()`, which otherwise waits for every checked-out connection to come back.
const POOL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// systemd's default `TimeoutStopSec` (`DefaultTimeoutStopSec`); the unit sets none. Past it the
/// manager SIGKILLs the daemon, so the whole stop path must finish well inside it.
const SYSTEMD_DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(90);

/// Worst-case stop: subsystem grace, abort unwind, pool close.
const WORST_CASE_STOP: Duration = SHUTDOWN_TIMEOUT
    .saturating_add(ABORT_WAIT)
    .saturating_add(POOL_CLOSE_TIMEOUT);
const _: () = assert!(WORST_CASE_STOP.as_secs() * 2 <= SYSTEMD_DEFAULT_STOP_TIMEOUT.as_secs());

/// How long the console waits for open connections to finish on shutdown. Must stay below
/// `SHUTDOWN_TIMEOUT`: the live log stream never ends on its own, so an unbounded wait for it
/// would always run the daemon's whole shutdown budget out.
const CONSOLE_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

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
    probe_sources: Arc<HashSet<IpAddr>>,
    probe_grace: Duration,
) {
    let SensorLogConfig { name, log_path } = sensor;
    let tailer = LogTailer::new(log_path, cursor_dir);
    let mut runner = IntakeRunner::new(tailer, pool, name.clone(), probe_sources, probe_grace);
    tracing::info!(sensor = %name, "intake: tailer started");

    // Seed the liveness entry so a sensor that never ingests still reads as "recently alive" until
    // its first real stall, rather than looking stalled from t=0.
    {
        let mut map = intake_progress.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(intake_key)
            .or_insert_with(|| SensorIntake::started(Instant::now()));
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

        // Publish intake liveness and lag for the ops-monitor's intake-stalled and intake-lagging
        // conditions, `/metrics` and the fleet pane.
        let (advanced, backlog) = progress_from_batch(
            result.ingested,
            result.rejected,
            result.probe_confirmations,
            result.errors,
        );
        let bytes_behind = runner.backlog_bytes();
        {
            let mut map = intake_progress.lock().unwrap_or_else(|p| p.into_inner());
            let entry = map
                .entry(intake_key)
                .or_insert_with(|| SensorIntake::started(Instant::now()));
            if advanced {
                entry.last_advanced_at = Instant::now();
            }
            entry.backlog = backlog;
            entry.bytes_behind = Some(bytes_behind);
            entry.last_ingested_observed_at = runner.last_ingested_observed_at();
            entry.wedge = runner.wedged();
            // The set only grows, so an unchanged length is an unchanged set.
            if entry.reported_sensors.len() != runner.reported_sensors().len() {
                entry.reported_sensors = runner.reported_sensors().iter().cloned().collect();
            }
        }

        // The probe confirmations are logged but deliberately left out of the two counters
        // `/metrics` publishes as ingest volume: they are this node's own synthetic traffic, and
        // folding them in would inflate the number an operator reads as attacker activity.
        if result.ingested > 0
            || result.rejected > 0
            || result.probe_confirmations > 0
            || result.errors > 0
        {
            ingested_counter
                .fetch_add(result.ingested as u64, std::sync::atomic::Ordering::Relaxed);
            rejected_counter
                .fetch_add(result.rejected as u64, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                sensor = %name,
                ingested = result.ingested,
                rejected = result.rejected,
                probe_confirmations = result.probe_confirmations,
                errors = result.errors,
                "intake: batch processed"
            );
        }

        if result.cursor_moved()
            && let Err(e) = runner.persist_cursor()
        {
            tracing::error!(sensor = %name, error = %e, "intake: cursor persist failed");
        }

        // A batch of nothing but probe lines still consumed input, so there may be more waiting:
        // sleeping here would halve the drain rate of a log the probe is writing into.
        if result.ingested == 0 && result.rejected == 0 && result.probe_confirmations == 0 {
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

    // A publish interrupted between its two renames leaves the public path absent with the last
    // valid build parked beside it. Restore it now rather than waiting for a build to succeed: the
    // feed is fetched by other people's blocklists, and the next build is an interval away at best
    // - and never, if whatever killed the last publish also stops the builds.
    match feed::recover_interrupted_publish(&output_dir) {
        Ok(true) => {
            tracing::info!("feed: restored the last valid feed after an interrupted publish")
        }
        Ok(false) => {}
        Err(e) => tracing::error!(
            output_dir = %output_dir.display(),
            error = %e,
            "feed: the published feed directory is missing and the parked previous build could \
             not be moved back into place"
        ),
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
    fleet_listeners: Arc<Vec<fleet::Listener>>,
    fleet_probe_interval: Duration,
    deploy_stamp_path: Option<PathBuf>,
    log_buffer: Arc<LogBuffer>,
    events_ingested: Arc<std::sync::atomic::AtomicU64>,
    events_rejected: Arc<std::sync::atomic::AtomicU64>,
    /// The supervisor map, so `/ready` can report a subsystem that has given up.
    supervisor: SupervisorHandle,
    /// Each intake log's backlog, for `/metrics` and the fleet pane.
    intake_lag: console::intake_lag::IntakeLagSource,
}

/// The console's view of the intake loops' backlog: one entry per log that has finished a poll,
/// judged behind by the same rule as the `intake-lagging` condition's age branch.
fn intake_lag_source(
    progress: IntakeProgress,
    poll_interval: Duration,
) -> console::intake_lag::IntakeLagSource {
    use ops_alert::conditions::intake_lag::{age_threshold, is_behind, oldest_unread_age};
    let threshold = age_threshold(poll_interval);
    Arc::new(move || {
        let now = chrono::Utc::now();
        let map = progress.lock().unwrap_or_else(|p| p.into_inner());
        map.iter()
            .filter_map(|(log, intake)| {
                let bytes_behind = intake.bytes_behind?;
                let age = oldest_unread_age(intake, now);
                Some(console::intake_lag::IntakeLag {
                    log: (*log).to_string(),
                    sensors: intake.reported_sensors.clone(),
                    bytes_behind,
                    oldest_unread_age: age,
                    behind: is_behind(age, threshold),
                })
            })
            .collect()
    })
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
        fleet_listeners,
        fleet_probe_interval,
        deploy_stamp_path,
        log_buffer,
        events_ingested,
        events_rejected,
        supervisor,
        intake_lag,
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
        fleet_listeners,
        fleet_probe_interval,
        deploy_stamp_path,
        startup_time: chrono::Utc::now(),
        // This daemon serves the console itself, so the fleet pane's version panel is reporting on
        // THIS binary: the installed file name it was started from, which is also the name its own
        // `--version` line above opens with and the key `deploy/deploy-stamp.sh` records it under.
        binary_name: "propolis",
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("PROPOLIS_GIT_SHA"),
        built_at: env!("PROPOLIS_BUILD_TIMESTAMP"),
        log_buffer,
        events_ingested,
        events_rejected,
        trusted_proxy,
        metrics_token: metrics_token.map(Arc::from),
        gave_up_subsystems,
        intake_lag,
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

    // Bounded connections, header reads and body reads; see `console::server`. The grace period
    // sits inside the daemon's own SHUTDOWN_TIMEOUT so the console never holds shutdown past it.
    console::server::serve(
        listener,
        console::routes::router(state),
        console::server::ServeLimits::default(),
        cancel.cancelled_owned(),
        CONSOLE_SHUTDOWN_GRACE,
    )
    .await;
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

/// `propolis shell explain <fixture.session>`: replays a sanitized session fixture through the
/// fake shell and prints the engine's decision trace per line (see
/// `sensor_framework::replay::explain`). The file's bytes are the only input and stdout/stderr
/// the only output; no listener, database, tracing subscriber or network is touched. Returns the
/// process exit code.
fn run_shell_explain(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("usage: propolis shell explain <fixture.session>");
        return 2;
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("propolis shell explain: cannot read {path}: {e}");
            return 1;
        }
    };
    let fixture = match sensor_framework::replay::parse(&text) {
        Ok(fixture) => fixture,
        Err(e) => {
            eprintln!("propolis shell explain: {path}: {e}");
            return 1;
        }
    };
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let result = sensor_framework::replay::explain(&fixture, &mut out);
    let flushed = std::io::Write::flush(&mut out);
    match result.and(flushed) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("propolis shell explain: {e}");
            1
        }
    }
}

const SHADOW_DIFF_USAGE: &str = "usage: propolis shell shadow-diff <fixture.session|dir> [--json]";

/// The `*.session` files `path` names: itself when a file, else every one directly inside it.
fn shadow_diff_files(path: &std::path::Path) -> Result<Vec<PathBuf>, String> {
    let meta =
        std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !meta.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let entries =
        std::fs::read_dir(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "session"))
        .collect();
    if files.is_empty() {
        return Err(format!("{}: no .session fixtures", path.display()));
    }
    files.sort();
    Ok(files)
}

/// `propolis shell shadow-diff <path> [--json]`: replays each fixture (one file, or every
/// `*.session` in a directory) through the current emulator and reports where its reply or
/// `@class` differs from the committed expectation, for review before a behavior change is
/// accepted. Offline like `shell explain`: fixture bytes in, stdout/stderr out. Exit code: 0 when
/// no step diverges, 1 when any does, 2 on a usage, read or parse error.
fn run_shadow_diff(path: Option<&str>, json: bool) -> i32 {
    let Some(path) = path else {
        eprintln!("{SHADOW_DIFF_USAGE}");
        return 2;
    };
    let files = match shadow_diff_files(std::path::Path::new(path)) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("propolis shell shadow-diff: {e}");
            return 2;
        }
    };
    let mut results = Vec::new();
    let mut errored = false;
    for file in &files {
        let name = file.display().to_string();
        let parsed = std::fs::read_to_string(file)
            .map_err(|e| format!("cannot read {name}: {e}"))
            .and_then(|text| {
                sensor_framework::replay::parse(&text).map_err(|e| format!("{name}: {e}"))
            });
        match parsed {
            Ok(fixture) => results.push((name, sensor_framework::replay::diff(&fixture))),
            Err(e) => {
                eprintln!("propolis shell shadow-diff: {e}");
                errored = true;
            }
        }
    }
    let steps: usize = results.iter().map(|(_, d)| d.len()).sum();
    let diverged: usize = results
        .iter()
        .map(|(_, d)| d.iter().filter(|s| !s.matched).count())
        .sum();
    let text = if json {
        format!("{}\n", sensor_framework::replay::files_to_json(&results))
    } else {
        let mut text = String::new();
        for (name, diffs) in &results {
            for s in diffs.iter().filter(|s| !s.matched) {
                text.push_str(&format!("{name}:{}: $ {}\n", s.line_no, s.input));
                text.push_str(&format!("  reply expected: {}\n", s.reply_expected));
                text.push_str(&format!("  reply actual:   {}\n", s.reply_actual));
                if let Some(c) = &s.class_expected {
                    text.push_str(&format!(
                        "  class expected: {c}\n  class actual:   {}\n",
                        s.class_actual
                    ));
                } else {
                    text.push_str(&format!(
                        "  class actual:   {} (not pinned)\n",
                        s.class_actual
                    ));
                }
            }
        }
        text.push_str(&format!("{steps} steps, {diverged} diffs\n"));
        text
    };
    let mut out = std::io::stdout().lock();
    if let Err(e) = std::io::Write::write_all(&mut out, text.as_bytes())
        .and_then(|()| std::io::Write::flush(&mut out))
    {
        eprintln!("propolis shell shadow-diff: {e}");
        return 2;
    }
    if errored { 2 } else { i32::from(diverged > 0) }
}

const COVERAGE_USAGE: &str =
    "usage: propolis coverage [--since <rfc3339>] [--until <rfc3339>] [--json] [--examples]";

#[derive(Debug, Default, PartialEq, Eq)]
struct CoverageArgs {
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    json: bool,
    /// Include one raw (sanitized) example command per family; normalized shapes only otherwise.
    examples: bool,
}

fn parse_coverage_args(args: &[String]) -> Result<CoverageArgs, String> {
    fn instant(
        flag: &str,
        value: Option<&String>,
    ) -> Result<chrono::DateTime<chrono::Utc>, String> {
        let value = value.ok_or_else(|| format!("{flag} needs an RFC 3339 timestamp"))?;
        chrono::DateTime::parse_from_rfc3339(value)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| format!("{flag} {value}: {e}"))
    }
    let mut parsed = CoverageArgs::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--since" => parsed.since = Some(instant("--since", it.next())?),
            "--until" => parsed.until = Some(instant("--until", it.next())?),
            "--json" => parsed.json = true,
            "--examples" => parsed.examples = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(parsed)
}

/// Map ledger rows into the analysis input. A command event without a recognized classification
/// predates the emulator's per-line classification and carries nothing coverage can bucket, so it
/// is left out; the count of those is returned.
fn coverage_input(
    rows: Vec<core_scoring::CoverageEventRow>,
) -> (Vec<sensor_framework::coverage::CoverageEvent>, usize) {
    use core_scoring::SignalType;
    use sensor_framework::coverage::{CoverageEvent, CoverageSignal};
    use sensor_framework::shell::CommandClass;

    let mut events = Vec::with_capacity(rows.len());
    let mut skipped = 0;
    for row in rows {
        let signal = match row.signal_type {
            SignalType::HoneypotCommandExec => {
                let class = match row.classification.as_deref() {
                    Some("supported") => CommandClass::Supported,
                    Some("partial") => CommandClass::Partial,
                    Some("unknown") => CommandClass::Unknown,
                    Some("parse_limit") => CommandClass::ParseLimit,
                    _ => {
                        skipped += 1;
                        continue;
                    }
                };
                CoverageSignal::CommandExec {
                    basename: row.command_basename,
                    class,
                    command: row.command,
                }
            }
            SignalType::HoneypotFileDownload => CoverageSignal::FileDownload,
            SignalType::HoneypotMalwareUpload => CoverageSignal::MalwareUpload,
            SignalType::HoneypotLoginAttempt => CoverageSignal::LoginAttempt,
            _ => continue,
        };
        events.push(CoverageEvent {
            session_id: row.session_id,
            order_key: (row.observed_at.timestamp_micros(), row.id),
            signal,
        });
    }
    (events, skipped)
}

/// Read the coverage events from `pool`, build the report and write it to `out`. Read-only: it
/// issues one SELECT and starts nothing. Errors are operator-facing text.
async fn run_coverage(
    pool: &PgPool,
    args: &CoverageArgs,
    out: &mut impl std::io::Write,
) -> Result<(), String> {
    let read = core_scoring::coverage_events(
        pool,
        args.since,
        args.until,
        core_scoring::MAX_COVERAGE_ROWS,
    )
    .await
    .map_err(|e| format!("cannot read events: {e}"))?;
    if read.truncated {
        return Err(format!(
            "more than {} matching events; narrow the range with --since/--until",
            core_scoring::MAX_COVERAGE_ROWS
        ));
    }
    let (events, skipped) = coverage_input(read.rows);
    if skipped > 0 {
        eprintln!("propolis coverage: skipped {skipped} command event(s) with no classification");
    }
    let window = (args.since.is_some() || args.until.is_some()).then(|| {
        let rfc =
            |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        sensor_framework::coverage::ReportWindow {
            from: args.since.map(rfc),
            to: args.until.map(rfc),
        }
    });
    let mut report = sensor_framework::coverage::build_report(&events, window);
    report.generated_at =
        Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    if !args.examples {
        report.strip_examples();
    }
    let text = if args.json {
        format!("{}\n", report.to_json())
    } else {
        report.render_text()
    };
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| format!("cannot write report: {e}"))
}

/// `propolis coverage`: an operator query. It reads only `DATABASE_URL` (not the daemon's full
/// configuration), opens a small read-only pool and runs [`run_coverage`]; no migrations, tracing
/// subscriber, listener, intake, review, feed, console, fleet or supervisor is started. Returns
/// the process exit code.
async fn run_coverage_cli(args: &[String]) -> i32 {
    let args = match parse_coverage_args(args) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("propolis coverage: {e}\n{COVERAGE_USAGE}");
            return 2;
        }
    };
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("propolis coverage: DATABASE_URL is not set");
        return 1;
    };
    let pool = match PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("propolis coverage: cannot connect to PostgreSQL: {e}");
            return 1;
        }
    };
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let result = run_coverage(&pool, &args, &mut out).await;
    drop(out);
    pool.close().await;
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("propolis coverage: {e}");
            1
        }
    }
}

// ---- entry point ----

#[tokio::main]
async fn main() {
    // Offline identity check, ahead of every other line in this function on purpose: config
    // loading, the PgPool connect, and migrations all fail loudly when the environment is not yet
    // fully populated (a fresh install, an operator diagnosing a stuck deploy), and this must
    // answer "what commit is this BINARY actually built from" regardless. It is the only way to
    // confirm what a deploy actually installed - `deploy/deploy-stamp.json` records what the
    // CHECKOUT was at build time, which a partially-failed install loop or a stale cargo cache can
    // both make untrue of the binary that landed in `/usr/local/bin`. See
    // `crates/build-stamp.rs`'s own header for why these two env vars exist at all.
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!(
            "propolis {} ({}, built {})",
            env!("CARGO_PKG_VERSION"),
            env!("PROPOLIS_GIT_SHA"),
            env!("PROPOLIS_BUILD_TIMESTAMP")
        );
        return;
    }

    // Offline operator command, ahead of config, the PgPool, tracing and every listener for the
    // same reason as `--version`: it reads one fixture file and prints, so it must work on a
    // machine with no database or environment, and must never reach a sensor connection.
    {
        let args: Vec<String> = std::env::args().skip(1).take(3).collect();
        if args.first().map(String::as_str) == Some("shell")
            && args.get(1).map(String::as_str) == Some("explain")
        {
            std::process::exit(run_shell_explain(args.get(2).map(String::as_str)));
        }
    }

    // Offline fixture review, same reasoning as `shell explain`: no config, database or listener.
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("shell")
            && args.get(1).map(String::as_str) == Some("shadow-diff")
        {
            let json = args[2..].iter().any(|a| a == "--json");
            let path = args[2..].iter().find(|a| a.as_str() != "--json");
            std::process::exit(run_shadow_diff(path.map(String::as_str), json));
        }
    }

    // Operator query over the event database. Still ahead of tracing, migrations and every
    // listener: it needs only DATABASE_URL and must never start the daemon.
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("coverage") {
            std::process::exit(run_coverage_cli(&args[1..]).await);
        }
    }

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

    // 3. Run migrations (core-scoring + review + fleet), each under its own bookkeeping table.
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
    if let Err(e) = fleet::migrator().run(&pool).await {
        tracing::error!(error = %e, "propolis: fleet migrations failed");
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
    let mut handles: Vec<(&'static str, tokio::task::JoinHandle<()>)> = Vec::new();

    let events_ingested = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let events_rejected = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 5. Spawn intake tailers - one supervised task per sensor log.
    // Shared supervised-state map: the supervisor writes each subsystem's state, the ops-monitor
    // reads it (subsystem-gaveup and sensor-down conditions).
    let supervisor_state: SupervisorHandle = Arc::new(Mutex::new(HashMap::new()));
    // Shared per-sensor intake liveness: each sensor loop writes its own entry, the ops-monitor
    // reads it (intake-stalled condition).
    let intake_progress: IntakeProgress = Arc::new(Mutex::new(HashMap::new()));

    // Shared by every intake tailer. The grace window is twice the sweep interval, the same
    // multiple `fleet::health::reach_level` calls fresh, so the window intake confirms in and the
    // window the console trusts a confirmation in cannot drift apart.
    let probe_sources = Arc::new(config.fleet_probe_sources.clone());
    let probe_grace = config.fleet_probe_interval.saturating_mul(2);

    // Taken before the loop below consumes the list: the ops-monitor's log-rotation conditions
    // measure the same files the tailers read.
    let rotation_logs = config.sensor_logs.clone();
    for sensor in config.sensor_logs {
        let pool = pool.clone();
        let cursor_dir = config.cursor_dir.clone();
        let poll_interval = config.poll_interval;
        let cancel = cancel.clone();
        let sensor_name: &'static str = Box::leak(sensor.name.clone().into_boxed_str());
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();
        let progress = intake_progress.clone();
        let sensor_probe_sources = probe_sources.clone();

        handles.push(spawn_supervised_named(
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
                let probe_sources = sensor_probe_sources.clone();
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
                        probe_sources,
                        probe_grace,
                    )
                    .await;
                }
            },
        ));
    }

    // 5b. Spawn the listener reachability probe, if enabled. Supervised like every other daemon
    // subsystem, so a panicking sweep restarts under backoff and a give-up shows in /ready and
    // pages through subsystem-gaveup rather than leaving the pane quietly unmeasured.
    //
    // Config already refused to start if this is enabled without the source addresses intake needs
    // to drop the probe's own connections (`ConfigError::ProbeEnabledWithoutSources`), so by the
    // time the sweep runs the contamination guard is known to be armed.
    if config.fleet_probe_enabled {
        if config.fleet_listeners.is_empty() {
            tracing::warn!(
                "listener-probe: enabled but PROPOLIS_FLEET_LISTENERS names no listeners; the \
                 sweep has nothing to dial and the fleet pane will report every check as unknown"
            );
        }
        let probe_pool = pool.clone();
        let probe_listeners = Arc::new(config.fleet_listeners.clone());
        let probe_endpoints = Arc::new(config.fleet_endpoints.clone());
        let probe_cfg = fleet::ProbeConfig {
            interval: config.fleet_probe_interval,
            timeout: config.fleet_probe_timeout,
        };
        handles.push(spawn_supervised_named(
            "listener-probe",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
                let pool = probe_pool.clone();
                let listeners = probe_listeners.clone();
                let endpoints = probe_endpoints.clone();
                async move {
                    fleet::run_probe_loop(pool, listeners, endpoints, probe_cfg, token).await;
                }
            },
        ));
    } else {
        tracing::info!("propolis: listener reachability probe disabled");
    }

    // 6. Spawn review subsystem (queue scan + submission) if enabled.
    if config.review_enabled {
        let pool_r = pool.clone();
        let queue_interval = config.queue_scan_interval;
        let submit_interval = config.submit_poll_interval;
        let vendors = config.vendors.clone();

        handles.push(spawn_supervised_named(
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

        handles.push(spawn_supervised_named(
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

        handles.push(spawn_supervised_named(
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
    handles.push(spawn_supervised_named(
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

    // 8c. Campaign indexer (docs/operations/campaigns.md): groups sources into campaigns and
    // extracts indicators, off the append path, a bounded batch of ledger rows per step. Local work
    // only: it reads the database and the spools and makes no outbound connection, so it runs on
    // every deployment.
    {
        let pool_campaigns = pool.clone();
        handles.push(spawn_supervised_named(
            "campaigns",
            cancel.clone(),
            supervisor_state.clone(),
            move |token| {
                let pool = pool_campaigns.clone();
                async move {
                    let spool_dirs = review::spool::all_body_dirs();
                    loop {
                        if token.is_cancelled() {
                            return;
                        }
                        let stop = || token.is_cancelled();
                        let stats = review::campaign::run_tick(&pool, &spool_dirs, &stop).await;
                        if stats.events > 0 || stats.fetch_links > 0 || stats.artifacts_scanned > 0
                        {
                            tracing::info!(
                                events = stats.events,
                                batches = stats.batches,
                                caught_up = stats.caught_up,
                                fetch_links = stats.fetch_links,
                                artifacts_scanned = stats.artifacts_scanned,
                                "campaigns: indexed"
                            );
                        }
                        let backlog = stats.batches > 0 && !stats.caught_up;
                        let pause = if backlog {
                            CAMPAIGN_CATCHUP_PAUSE
                        } else {
                            CAMPAIGN_TICK_INTERVAL
                        };
                        tokio::select! {
                            _ = tokio::time::sleep(pause) => {}
                            _ = token.cancelled() => {}
                        }
                    }
                }
            },
        ));
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

        handles.push(spawn_supervised_named(
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
                        daily_cap: fetch_daily_cap,
                    };

                    loop {
                        if token.is_cancelled() {
                            tracing::info!("fetcher: scanner stopped");
                            return;
                        }

                        // The per-host and daily caps are enforced when the cycle claims its rows,
                        // in the database, so they hold across restarts and across every node
                        // sharing it; a cycle that claims nothing costs nothing.
                        let stats = fetcher::run_cycle(&deps, fetch_batch_size).await;
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
                                skipped_daily = stats.skipped_daily,
                                enqueued_children = stats.enqueued_children,
                                errors = stats.errors,
                                "fetcher: cycle complete"
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
        let console_fleet_listeners = Arc::new(config.fleet_listeners.clone());
        let console_fleet_probe_interval = config.fleet_probe_interval;
        let console_deploy_stamp = config.fleet_deploy_stamp.clone();
        let log_buffer = log_buffer.clone();
        let ing = events_ingested.clone();
        let rej = events_rejected.clone();
        let console_supervisor = supervisor_state.clone();
        let console_intake_lag = intake_lag_source(intake_progress.clone(), config.poll_interval);

        handles.push(spawn_supervised_named(
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
                let fleet_listeners = console_fleet_listeners.clone();
                let deploy_stamp_path = console_deploy_stamp.clone();
                let supervisor = console_supervisor.clone();
                let intake_lag = console_intake_lag.clone();
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
                            fleet_listeners,
                            fleet_probe_interval: console_fleet_probe_interval,
                            deploy_stamp_path,
                            log_buffer,
                            events_ingested: ing,
                            events_rejected: rej,
                            supervisor,
                            intake_lag,
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
        let intake_poll_interval = config.poll_interval;
        let ops_rotation = ops_alert::condition::RotationCtx::production(rotation_logs);

        handles.push(spawn_supervised_named(
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
                let rotation = ops_rotation.clone();
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
                        intake_poll_interval,
                        feed_marker_path,
                        feed_push_marker_path,
                        feed_build_interval,
                        rotation,
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

    // 13. Drain the subsystems within the budget; abort and name any that did not stop.
    drain_subsystems(handles, SHUTDOWN_TIMEOUT).await;

    // Aborted tasks have released their connections, so this normally returns at once; the bound
    // is for a task stuck in synchronous code, which an abort cannot interrupt.
    if tokio::time::timeout(POOL_CLOSE_TIMEOUT, pool.close())
        .await
        .is_err()
    {
        tracing::warn!(
            timeout_secs = POOL_CLOSE_TIMEOUT.as_secs(),
            "propolis: database pool did not close in time; exiting with connections open"
        );
    }
    tracing::info!("propolis: shutdown complete");
}

/// Awaits every subsystem handle concurrently for up to `budget`. Any still running after that is
/// aborted (a task that ignores cancellation would otherwise keep its pooled connection and wedge
/// `pool.close()`), given `ABORT_WAIT` to unwind, and its name returned.
async fn drain_subsystems(
    handles: Vec<(&'static str, tokio::task::JoinHandle<()>)>,
    budget: Duration,
) -> Vec<&'static str> {
    let names: Vec<&'static str> = handles.iter().map(|(name, _)| *name).collect();
    let aborts: Vec<_> = handles.iter().map(|(_, h)| h.abort_handle()).collect();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    for (index, (_, handle)) in handles.into_iter().enumerate() {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = handle.await;
            let _ = tx.send(index);
        });
    }
    drop(tx);

    let mut running = vec![true; names.len()];
    collect_stopped(&mut rx, &mut running, &names, budget).await;

    let stragglers: Vec<usize> = (0..names.len()).filter(|i| running[*i]).collect();
    if stragglers.is_empty() {
        return Vec::new();
    }
    let straggler_names: Vec<&'static str> = stragglers.iter().map(|i| names[*i]).collect();
    tracing::warn!(
        timeout_secs = budget.as_secs(),
        "propolis: shutdown timed out waiting for: {}; aborted",
        straggler_names.join(", ")
    );
    for &i in &stragglers {
        aborts[i].abort();
    }
    collect_stopped(&mut rx, &mut running, &names, ABORT_WAIT).await;
    straggler_names
}

/// Marks subsystems stopped as their completion indices arrive, until all are done, the channel
/// closes, or `wait` elapses.
async fn collect_stopped(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<usize>,
    running: &mut [bool],
    names: &[&'static str],
    wait: Duration,
) {
    let _ = tokio::time::timeout(wait, async {
        while running.iter().any(|r| *r) {
            let Some(index) = rx.recv().await else { break };
            running[index] = false;
            tracing::debug!(subsystem = names[index], "propolis: subsystem stopped");
        }
    })
    .await;
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::task::JoinHandle;

    fn obeys(token: &CancellationToken) -> JoinHandle<()> {
        let token = token.clone();
        tokio::spawn(async move { token.cancelled().await })
    }

    /// Ignores cancellation; flips `dropped` when its future is dropped (the abort).
    fn ignores_cancellation(dropped: Arc<AtomicBool>) -> JoinHandle<()> {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        tokio::spawn(async move {
            let _flag = Flag(dropped);
            std::future::pending::<()>().await;
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_subsystem_that_ignores_cancellation_is_aborted_and_named() {
        let token = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let handles = vec![
            ("good-a", obeys(&token)),
            ("stuck", ignores_cancellation(dropped.clone())),
            ("good-b", obeys(&token)),
        ];
        token.cancel();
        // A regression that waits forever fails here instead of hanging the suite.
        let stragglers =
            tokio::time::timeout(WORST_CASE_STOP, drain_subsystems(handles, SHUTDOWN_TIMEOUT))
                .await
                .expect("drain must finish within the stop budget");
        assert_eq!(stragglers, vec!["stuck"]);
        assert!(
            dropped.load(Ordering::SeqCst),
            "the straggler was aborted, not left running"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn well_behaved_subsystems_are_all_awaited_and_not_reported() {
        let token = CancellationToken::new();
        let finished = Arc::new(AtomicBool::new(false));
        let slow_done = finished.clone();
        let slow_token = token.clone();
        let slow = tokio::spawn(async move {
            slow_token.cancelled().await;
            // Slower than the others but inside the budget: must be awaited, not aborted.
            tokio::time::sleep(Duration::from_secs(20)).await;
            slow_done.store(true, Ordering::SeqCst);
        });
        let handles = vec![("a", obeys(&token)), ("slow", slow), ("b", obeys(&token))];
        token.cancel();
        let stragglers = drain_subsystems(handles, SHUTDOWN_TIMEOUT).await;
        assert!(stragglers.is_empty(), "{stragglers:?}");
        assert!(
            finished.load(Ordering::SeqCst),
            "the slow subsystem ran to completion"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_returns_promptly_when_everything_finishes_early() {
        let token = CancellationToken::new();
        let handles = vec![("a", obeys(&token)), ("b", obeys(&token))];
        token.cancel();
        let started = tokio::time::Instant::now();
        let stragglers = drain_subsystems(handles, SHUTDOWN_TIMEOUT).await;
        assert!(stragglers.is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "drain waited {:?} for subsystems that had already stopped",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_set_drains_immediately() {
        assert!(
            drain_subsystems(Vec::new(), SHUTDOWN_TIMEOUT)
                .await
                .is_empty()
        );
    }

    /// The end-to-end stop budget must leave room under systemd's default stop timeout. The const
    /// assertion next to `WORST_CASE_STOP` enforces it at build time; this pins the intent and the
    /// console grace ordering.
    #[test]
    fn worst_case_stop_fits_inside_the_systemd_default() {
        assert_eq!(WORST_CASE_STOP, Duration::from_secs(37));
        assert!(WORST_CASE_STOP < SYSTEMD_DEFAULT_STOP_TIMEOUT);
        assert!(CONSOLE_SHUTDOWN_GRACE < SHUTDOWN_TIMEOUT);
    }
}

#[cfg(test)]
mod coverage_cli_tests {
    use super::*;
    use core_scoring::{CoverageEventRow, SignalType};
    use sensor_framework::coverage::CoverageSignal;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_parse_and_bad_ones_are_rejected() {
        assert_eq!(parse_coverage_args(&[]).unwrap(), CoverageArgs::default());
        let parsed = parse_coverage_args(&argv(&[
            "--since",
            "2026-10-01T00:00:00Z",
            "--until",
            "2026-10-02T00:00:00+02:00",
            "--json",
            "--examples",
        ]))
        .unwrap();
        assert!(parsed.json && parsed.examples);
        assert_eq!(
            parsed.since.unwrap().to_rfc3339(),
            "2026-10-01T00:00:00+00:00"
        );
        assert_eq!(
            parsed.until.unwrap().to_rfc3339(),
            "2026-10-01T22:00:00+00:00"
        );

        for bad in [
            argv(&["--since"]),
            argv(&["--since", "yesterday"]),
            argv(&["--bogus"]),
        ] {
            assert!(parse_coverage_args(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rows_map_to_signals_and_unclassified_commands_are_skipped() {
        let at = "2026-10-01T10:00:00Z".parse().unwrap();
        let row = |signal_type, classification: Option<&str>| CoverageEventRow {
            session_id: sensor_framework::Uuid::from_u128(1),
            signal_type,
            observed_at: at,
            id: 7,
            classification: classification.map(str::to_string),
            command_basename: Some("wget".to_string()),
            command: Some("wget x".to_string()),
        };
        let (events, skipped) = coverage_input(vec![
            row(SignalType::HoneypotCommandExec, Some("parse_limit")),
            row(SignalType::HoneypotCommandExec, None),
            row(SignalType::HoneypotCommandExec, Some("mystery")),
            row(SignalType::HoneypotFileDownload, None),
            row(SignalType::HoneypotMalwareUpload, None),
            row(SignalType::HoneypotLoginAttempt, None),
            row(SignalType::HoneypotConnection, None),
        ]);
        assert_eq!(skipped, 2);
        assert_eq!(events.len(), 4);
        assert!(matches!(
            events[0].signal,
            CoverageSignal::CommandExec {
                class: sensor_framework::shell::CommandClass::ParseLimit,
                ..
            }
        ));
        assert_eq!(events[0].order_key, (at.timestamp_micros(), 7));
        assert_eq!(events[3].signal, CoverageSignal::LoginAttempt);
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

#[cfg(test)]
mod intake_lag_source_tests {
    use super::*;

    /// What the console receives from the intake map: a log that has not finished a poll is left
    /// out (unmeasured, not caught up), a log read to the end is not behind, and a log whose lines
    /// have waited 11 days is behind with its own sensor names attached.
    #[test]
    fn the_console_sees_measured_logs_only_and_the_age_rule_decides_behind() {
        let progress: IntakeProgress = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut map = progress.lock().unwrap();
            map.insert("ssh", SensorIntake::started(Instant::now()));
            let mut vnc = SensorIntake::started(Instant::now());
            vnc.bytes_behind = Some(120);
            vnc.last_ingested_observed_at = Some(chrono::Utc::now());
            map.insert("cred-vnc", vnc);
            let mut telnet = SensorIntake::started(Instant::now());
            telnet.backlog = true;
            telnet.bytes_behind = Some(6_600_000_000);
            telnet.last_ingested_observed_at =
                Some(chrono::Utc::now() - chrono::Duration::days(11));
            telnet.reported_sensors = vec!["telnet".into()];
            map.insert("telnet", telnet);
        }

        let mut logs = intake_lag_source(progress, Duration::from_secs(1))();
        logs.sort_by(|a, b| a.log.cmp(&b.log));
        assert_eq!(
            logs.iter().map(|l| l.log.as_str()).collect::<Vec<_>>(),
            vec!["cred-vnc", "telnet"]
        );
        assert!(!logs[0].behind);
        assert_eq!(logs[0].oldest_unread_age, Some(Duration::ZERO));
        assert!(logs[1].behind);
        assert_eq!(logs[1].bytes_behind, 6_600_000_000);
        assert_eq!(logs[1].sensors, vec!["telnet".to_string()]);
        assert!(logs[1].oldest_unread_age >= Some(Duration::from_secs(11 * 86_400)));
    }

    /// The intake loop itself publishes the backlog reading, from `None` before its first poll to
    /// the bytes left after it. Lines that fail to parse are consumed without a database, which
    /// is what lets the real loop run here on a pool that never connects.
    #[tokio::test]
    async fn the_intake_loop_publishes_its_backlog_after_each_poll() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        std::fs::write(&log_path, "not json\n".repeat(150)).unwrap();
        let progress: IntakeProgress = Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused/unused")
            .unwrap();
        let task = tokio::spawn(run_intake_sensor(
            SensorLogConfig {
                name: "telnet".into(),
                log_path,
            },
            "telnet",
            pool,
            dir.path().join("cursors"),
            Duration::from_millis(10),
            cancel.clone(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            progress.clone(),
            Arc::new(HashSet::new()),
            Duration::from_secs(600),
        ));

        let drained = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let bytes = progress
                    .lock()
                    .unwrap()
                    .get("telnet")
                    .and_then(|s| s.bytes_behind);
                if bytes == Some(0) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        cancel.cancel();
        task.await.unwrap();
        assert!(
            drained.is_ok(),
            "the loop never published a drained backlog: {:?}",
            progress.lock().unwrap().get("telnet")
        );
    }
}
