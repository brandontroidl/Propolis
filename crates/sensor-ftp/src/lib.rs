pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    CaptureHandoff, ConnectionBounds, EventEmitter, QuarantineSpool, WanResolver, run_tcp_listener,
};
use tokio::task::JoinHandle;

const SPOOL_MAX_FILE_SIZE: u64 = 10_000_000;
const SPOOL_GLOBAL_BUDGET: u64 = 100_000_000;
const CAPTURE_QUEUE_SIZE: usize = 64;

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
