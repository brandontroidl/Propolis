//! sensor-adb library surface: the per-connection session handler (`handler` module) and the
//! ADB wire protocol parsing/building it drives (`adb_proto` module), plus `start_test_server`,
//! the composition that wires them to `sensor_framework`'s shared TCP listener, quarantine spool,
//! and off-response-path capture hand-off. `main.rs` (the production entry point) and
//! `tests/integration.rs` both build on this same `start_test_server`, so the test suite
//! exercises exactly the capture logic the binary runs in production.

pub mod adb_proto;
pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    Arrival, CaptureHandoff, CaptureMemoryBudget, CommandEventConfig, CommandEventGate,
    ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, EventEmitter, OutboxManifest,
    QuarantineSpool, WanResolver, command_flood, run_tcp_listener_tracked,
};
use tokio::task::JoinHandle;

/// Per-file and store-wide quarantine spool caps, matching `sensor-ssh`'s
/// `server::start_test_server` constants: 10 MB per captured file, 100 MB total. ADB pushes are
/// typically small (IoT botnet binaries, cryptominers), so this is generous headroom, not a
/// tight fit.
const SPOOL_MAX_FILE_SIZE: u64 = 10_000_000;
const SPOOL_GLOBAL_BUDGET: u64 = 100_000_000;

/// Capacity of the in-process capture hand-off queue, matching `sensor-ssh`'s convention.
const CAPTURE_QUEUE_SIZE: usize = 64;

/// Start the ADB honeypot server on `addr` (use `:0` for an ephemeral port - every test in
/// `tests/integration.rs` relies on this), appending events to `log_path` and spooling captured
/// `sync:` push bodies under `spool_dir` (created if it does not already exist). `wan_resolver`
/// maps the listener's local address to the operator's WAN IP (see
/// `sensor_framework::WanResolver`); `bounds` governs the per-connection resource limits
/// `handler::MessageReader`'s own read loop enforces plus the concurrency/duration caps
/// `run_tcp_listener` enforces directly. `main.rs` calls this with operator-configured values;
/// tests build their own fixed `ConnectionBounds`.
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let (bound, handle, _handoff) = start_test_server_with_handoff(
        addr,
        log_path,
        spool_dir,
        wan_resolver,
        bounds,
        collector_id,
        outbox_dir,
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        Arc::new(CommandEventGate::new(CommandEventConfig::default())),
    )
    .await?;
    Ok((bound, handle))
}

/// `start_test_server` plus the capture hand-off, so `main` can `drain` it on shutdown, the
/// process-wide capture memory budget `main` built from its configured ceiling, and the sensor's
/// per-source command-event budget, which `main` flushes on shutdown. A separate function rather
/// than a wider return type so the many callers that never shut down (every integration test) are
/// unchanged. The returned handle stops the listener and the command-summary writer together.
#[allow(clippy::too_many_arguments)]
pub async fn start_test_server_with_handoff(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
    command_events: Arc<CommandEventGate>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>, Arc<CaptureHandoff>)> {
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let summary_emitter = emitter.clone();
    let summary_gate = command_events.clone();
    let spool = QuarantineSpool::new(spool_dir, SPOOL_MAX_FILE_SIZE, SPOOL_GLOBAL_BUDGET);
    // The hand-off's own emitter writes to the same log file; EventEmitter opens with O_APPEND
    // on each write, so a second independent instance targeting the same path is safe - same
    // reasoning as sensor-ssh's server::start_test_server.
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        CAPTURE_QUEUE_SIZE,
        collector_id,
        OutboxManifest::new(outbox_dir),
        capture_budget,
    ));
    handoff.start_worker();

    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    let drain_handle = handoff.clone();
    let tracker = handoff.connections().clone();
    let (bound, handle) = run_tcp_listener_tracked(
        addr,
        bounds.clone(),
        per_source_cap,
        Some(tracker),
        move |stream, peer, session_id| {
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            let handoff = handoff.clone();
            let command_events = command_events.clone();
            async move {
                handler::handle_connection(
                    stream,
                    peer,
                    session_id,
                    emitter,
                    wan_resolver,
                    bounds,
                    handoff,
                    command_events,
                )
                .await;
            }
        },
    )
    .await?;
    let writer = summary_gate.spawn_writer(summary_emitter, Arrival::new(bound.port()));
    Ok((
        bound,
        command_flood::with_writer(handle, writer),
        drain_handle,
    ))
}
