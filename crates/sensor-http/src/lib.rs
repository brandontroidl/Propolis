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

    run_tcp_listener(addr, bounds.clone(), move |stream, peer| {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let bounds = bounds.clone();
        async move {
            handler::handle_connection(stream, peer, emitter, wan_resolver, bounds).await;
        }
    })
    .await
}
