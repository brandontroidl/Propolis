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
    CaptureHandoff, ConnectionBounds, EventEmitter, QuarantineSpool, WanResolver, run_tcp_listener,
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
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let spool = QuarantineSpool::new(spool_dir, SPOOL_MAX_FILE_SIZE, SPOOL_GLOBAL_BUDGET);
    // The hand-off's own emitter writes to the same log file; EventEmitter opens with O_APPEND
    // on each write, so a second independent instance targeting the same path is safe - same
    // reasoning as sensor-ssh's server::start_test_server.
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        CAPTURE_QUEUE_SIZE,
    ));
    let _worker = handoff.start_worker();

    run_tcp_listener(addr, bounds.clone(), move |stream, peer| {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let bounds = bounds.clone();
        let handoff = handoff.clone();
        async move {
            handler::handle_connection(stream, peer, emitter, wan_resolver, bounds, handoff).await;
        }
    })
    .await
}
