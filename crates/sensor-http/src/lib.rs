pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    ConnectionBounds, EventEmitter, TlsServer, WanResolver, run_tcp_listener, run_tls_listener,
};
use tokio::task::JoinHandle;

pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));

    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    run_tcp_listener(
        addr,
        bounds.clone(),
        per_source_cap,
        move |stream, peer, session_id| {
            let local_addr = stream.local_addr().ok();
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            async move {
                handler::handle_connection(
                    stream,
                    peer,
                    local_addr,
                    false,
                    session_id,
                    emitter,
                    wan_resolver,
                    bounds,
                )
                .await;
            }
        },
    )
    .await
}

/// The HTTPS twin of [`start_test_server`]: the same handler, bounds and per-source cap behind an
/// implicit-TLS handshake (no client auth). A failed handshake never reaches the handler, so it
/// emits no event. Events from this listener carry `"tls": true`.
pub async fn start_test_server_tls(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    tls: TlsServer,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));

    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    run_tls_listener(
        addr,
        bounds.clone(),
        per_source_cap,
        tls,
        move |stream, peer, local_addr, session_id| {
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            async move {
                handler::handle_connection(
                    stream,
                    peer,
                    local_addr,
                    true,
                    session_id,
                    emitter,
                    wan_resolver,
                    bounds,
                )
                .await;
            }
        },
    )
    .await
}
