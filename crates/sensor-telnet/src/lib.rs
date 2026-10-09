//! sensor-telnet library surface: the per-connection session handler (`handler` module) and the
//! IAC negotiation helpers it drives (`telnet` module), plus `start_test_server`, the composition
//! that wires them to `sensor_framework`'s shared TCP listener. `main.rs` (the production entry
//! point) and `tests/integration.rs` both build on this same `start_test_server`, so the test
//! suite exercises exactly the capture logic the binary runs in production.

pub mod handler;
pub mod infected_hold;
pub mod telnet;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    Arrival, CaptureHandoff, CaptureMemoryBudget, CommandEventConfig, CommandEventGate,
    ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, EventEmitter, OutboxManifest,
    QuarantineSpool, WanResolver, command_flood, run_tcp_listener_tracked,
};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use infected_hold::InfectedHold;

/// Close `stream` so the peer sees a reset: `SO_LINGER` of zero makes the close send an RST
/// instead of a FIN, as a closed port's answer does.
fn reset(stream: TcpStream) {
    // A socket that already failed has nothing left to reset.
    let _ = stream.set_zero_linger();
    drop(stream);
}

/// Start the Telnet honeypot server on `addr` (use `:0` for an ephemeral port - every test in
/// `tests/integration.rs` relies on this), appending events to `log_path`. `spool_dir` is the
/// quarantine directory a binary shell-phase payload (a Mirai/Gafgyt dropper) is captured to -
/// see `handler::handle_connection`'s use of `CaptureHandoff`. `wan_resolver` maps the listener's
/// local address to the operator's WAN IP (see `sensor_framework::WanResolver`); `bounds` governs
/// the per-connection resource limits `handler::handle_connection`'s own read loop enforces plus
/// the concurrency/duration caps `run_tcp_listener` enforces directly. `main.rs` calls this with
/// operator-configured values; tests build their own fixed `ConnectionBounds`.
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
        Arc::new(InfectedHold::disabled()),
    )
    .await?;
    Ok((bound, handle))
}

/// `start_test_server` plus the capture hand-off, so `main` can `drain` it on shutdown, the
/// process-wide capture memory budget `main` built from its configured ceiling, and the sensor's
/// per-source command-event budget, which `main` flushes on shutdown. A separate function rather
/// than a wider return type so the many callers that never shut down (every integration test) are
/// unchanged. The returned handle stops the listener and the command-summary writer together.
/// `infected_hold` refuses the sources whose infection a session finished (see `infected_hold`);
/// `start_test_server` passes a disabled one so a test may open as many sessions as it likes.
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
    infected_hold: Arc<InfectedHold>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>, Arc<CaptureHandoff>)> {
    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let summary_emitter = emitter.clone();
    let summary_gate = command_events.clone();
    let hold_for_sessions = infected_hold.clone();

    // Ensure the spool directory exists.
    std::fs::create_dir_all(&spool_dir)?;

    let spool = QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000);
    // The handoff's emitter writes to the same log file. EventEmitter opens with O_APPEND on
    // each write so concurrent emitters to the same path are safe - mirrors sensor-ssh's
    // `server::serve`.
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        64,
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
            let local_addr = stream.local_addr().ok();
            let emitter = emitter.clone();
            let handoff = handoff.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            let command_events = command_events.clone();
            let infected_hold = hold_for_sessions.clone();
            async move {
                // Before anything is written or logged: a held source sees a closed door, not a
                // login prompt, and the refusal is counted by the hold.
                if infected_hold.refuses(normalize_dual_stack(peer).ip()) {
                    reset(stream);
                    return;
                }
                handler::handle_connection(
                    stream,
                    peer,
                    local_addr,
                    session_id,
                    emitter,
                    wan_resolver,
                    bounds,
                    handoff,
                    command_events,
                    infected_hold,
                )
                .await;
            }
        },
    )
    .await?;
    let writer = summary_gate.spawn_writer(summary_emitter, Arrival::new(bound.port()));
    let refusal_writer =
        infected_hold::spawn_summary_writer(infected_hold, infected_hold::SUMMARY_INTERVAL);
    Ok((
        bound,
        command_flood::with_writer(command_flood::with_writer(handle, writer), refusal_writer),
        drain_handle,
    ))
}
