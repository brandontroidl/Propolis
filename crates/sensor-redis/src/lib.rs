//! sensor-redis library surface: the per-connection session handler (`handler` module) and the
//! RESP protocol parsing/encoding it drives (`resp` module), plus `start_test_server`, the
//! composition that wires them to `sensor_framework`'s shared TCP listener. `main.rs` (the
//! production entry point) and `tests/integration.rs` both build on this same `start_test_server`,
//! so the test suite exercises exactly the capture logic the binary runs in production.

pub mod handler;
pub mod resp;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver, run_tcp_listener};
use tokio::task::JoinHandle;

/// Start the Redis honeypot server on `addr` (use `:0` for an ephemeral port - every test in
/// `tests/integration.rs` relies on this), appending events to `log_path`. `wan_resolver` maps the
/// listener's local address to the operator's WAN IP (see `sensor_framework::WanResolver`);
/// `bounds` governs the per-connection resource limits `handler::RespReader`'s own read loop
/// enforces plus the concurrency/duration caps `run_tcp_listener` enforces directly. `main.rs`
/// calls this with operator-configured values; tests build their own fixed `ConnectionBounds`.
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));

    run_tcp_listener(addr, bounds.clone(), move |stream, peer, session_id| {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let bounds = bounds.clone();
        async move {
            handler::handle_connection(stream, peer, session_id, emitter, wan_resolver, bounds)
                .await;
        }
    })
    .await
}
