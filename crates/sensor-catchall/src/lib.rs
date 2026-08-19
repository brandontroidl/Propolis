//! sensor-catchall library surface: the catch-all's per-hit handler logic (`handler` module) plus
//! the small composition helpers that wire it to `sensor_framework`'s listener. `main.rs` (the
//! production entry point) and `tests/integration.rs` both build on this same module rather than
//! on two separate code paths, so the test suite exercises exactly the capture logic the binary
//! runs in production - see `tests/integration.rs`'s own comment: "uses the handler module
//! directly rather than starting the full binary, so it can control ports and read the log file."
//! There is no library API meant for use outside this crate (the interface list this task was
//! built from: "No library API - the catch-all is a standalone binary"); `pub` here exists only so
//! `tests/integration.rs`, a separate compilation unit that links against this crate's lib target,
//! can reach it.

pub mod handler;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    ConnectionBounds, EventEmitter, WanResolver, run_tcp_listener, run_udp_listener,
};
use tokio::task::JoinHandle;

/// Bounds used by the two `start_test_*` helpers below: generous enough that no test in
/// `tests/integration.rs` times out on a slow runner, while still exercising the real
/// `read_timeout`/`idle_timeout`/`max_captured_bytes` enforcement path `handler::handle_tcp`
/// applies. Production bounds come from the operator's own configuration in `main.rs`, not these
/// fixed test values.
fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_millis(300),
        max_duration: Duration::from_secs(5),
        max_captured_bytes: 4096,
        max_concurrent: 100,
    }
}

/// Start the catch-all TCP listener on `addr`, appending events to `log_path`, with no WAN
/// mapping configured (`wan_ip` always resolves to `None`). Exposed so integration tests can drive
/// the real capture path end to end on an ephemeral port; `main.rs` composes `handler::handle_tcp`
/// the same way, against operator configuration instead of these fixed test bounds/empty WAN map.
pub async fn start_test_listener(
    addr: SocketAddr,
    log_path: PathBuf,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let bounds = test_bounds();
    run_tcp_listener(addr, bounds.clone(), move |stream, peer, session_id| {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let bounds = bounds.clone();
        async move {
            handler::handle_tcp(stream, peer, session_id, &wan_resolver, &emitter, &bounds).await;
        }
    })
    .await
}

/// Start the catch-all UDP listener on `addr`, mirroring `start_test_listener` for datagrams.
///
/// `run_udp_listener`'s handler is only ever given the datagram bytes and the sender's address
/// (see `sensor_framework::listener`'s module doc: this is deliberate, part of what makes a UDP
/// response structurally impossible) - it has no way to report which local address the datagram
/// arrived on. `addr` is therefore normalized and captured directly from this function's own
/// argument as the "local address" `handler::handle_udp` resolves WAN attribution against: correct
/// for any concrete (non-wildcard) bind address, which is the deployment shape WAN attribution
/// already assumes (one bind address per WAN-facing interface, matching `WanResolver`'s map keys).
/// It is only approximate for a wildcard bind (`0.0.0.0`/`::`), where "the" local address is
/// inherently ambiguous for UDP without OS-level `IP_PKTINFO` support that `tokio::net::UdpSocket`
/// does not expose - a narrower limitation than TCP's (see `handler::handle_tcp`, which instead
/// reads the actual per-connection `local_addr()`).
pub async fn start_test_udp_listener(
    addr: SocketAddr,
    log_path: PathBuf,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let local_ip = normalize_dual_stack(addr).ip();
    run_udp_listener(addr, move |data, peer| {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        async move {
            handler::handle_udp(data, peer, local_ip, &wan_resolver, &emitter).await;
        }
    })
    .await
}
