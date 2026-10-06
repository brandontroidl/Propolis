pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    CaptureHandoff, CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M,
    EventEmitter, OutboxManifest, QuarantineSpool, WanResolver, run_tcp_listener,
};
use tokio::task::JoinHandle;

/// A PUBLISH payload is at most `handler::MAX_PACKET_BYTES`, so no spooled body can exceed it.
const SPOOL_MAX_FILE_SIZE: u64 = handler::MAX_PACKET_BYTES as u64;
const SPOOL_GLOBAL_BUDGET: u64 = 100_000_000;
const CAPTURE_QUEUE_SIZE: usize = 64;

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
    )
    .await?;
    Ok((bound, handle))
}

/// `start_test_server` plus the capture hand-off, so `main` can `drain` it on shutdown, and the
/// process-wide capture memory budget `main` built from its configured ceiling. A separate
/// function rather than a wider return type so the many callers that never shut down (every
/// integration test) are unchanged.
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
) -> std::io::Result<(SocketAddr, JoinHandle<()>, Arc<CaptureHandoff>)> {
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let spool = QuarantineSpool::new(spool_dir, SPOOL_MAX_FILE_SIZE, SPOOL_GLOBAL_BUDGET);
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
    let (bound, handle) = run_tcp_listener(
        addr,
        bounds.clone(),
        per_source_cap,
        move |stream, peer, session_id| {
            let local_addr = stream.local_addr().ok();
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            let handoff = handoff.clone();
            async move {
                handler::handle_connection(
                    stream,
                    peer,
                    local_addr,
                    session_id,
                    emitter,
                    wan_resolver,
                    bounds,
                    handoff,
                )
                .await;
            }
        },
    )
    .await?;
    Ok((bound, handle, drain_handle))
}
