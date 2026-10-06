pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver, run_tcp_listener};
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
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            async move {
                handler::handle_connection(stream, peer, session_id, emitter, wan_resolver, bounds)
                    .await;
            }
        },
    )
    .await
}
