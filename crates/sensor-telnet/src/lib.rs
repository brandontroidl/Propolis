//! sensor-telnet library surface: the per-connection session handler (`handler` module) and the
//! IAC negotiation helpers it drives (`telnet` module), plus `start_test_server`, the composition
//! that wires them to `sensor_framework`'s shared TCP listener. `main.rs` (the production entry
//! point) and `tests/integration.rs` both build on this same `start_test_server`, so the test
//! suite exercises exactly the capture logic the binary runs in production.

pub mod handler;
pub mod telnet;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    CaptureHandoff, ConnectionBounds, EventEmitter, OutboxManifest, QuarantineSpool, WanResolver,
    run_tcp_listener,
};
use tokio::task::JoinHandle;

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
    let emitter = Arc::new(EventEmitter::new(log_path.clone()));

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
    ));
    let _worker = handoff.start_worker();

    run_tcp_listener(addr, bounds.clone(), move |stream, peer, session_id| {
        let emitter = emitter.clone();
        let handoff = handoff.clone();
        let wan_resolver = wan_resolver.clone();
        let bounds = bounds.clone();
        async move {
            handler::handle_connection(
                stream,
                peer,
                session_id,
                emitter,
                wan_resolver,
                bounds,
                handoff,
            )
            .await;
        }
    })
    .await
}
