pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    CaptureHandoff, CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M,
    EventEmitter, OutboxManifest, QuarantineSpool, TlsServer, WanResolver,
    run_tcp_listener_tracked, run_tls_listener_tracked,
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

/// Build the capture hand-off (spool, worker, outbox) once. The plaintext and TLS listeners of one
/// sensor share it, so the spool budget and the process-wide capture memory budget are charged
/// once and `main` drains a single queue on shutdown.
pub fn new_capture_handoff(
    log_path: PathBuf,
    spool_dir: PathBuf,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
) -> std::io::Result<Arc<CaptureHandoff>> {
    std::fs::create_dir_all(&spool_dir)?;
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
    Ok(handoff)
}

/// Plaintext MQTT listener over an existing hand-off.
pub async fn start_plain_listener(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));
    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    let tracker = handoff.connections().clone();
    run_tcp_listener_tracked(
        addr,
        bounds.clone(),
        per_source_cap,
        Some(tracker),
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
                    false,
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
    .await
}

/// Implicit-TLS MQTT listener (MQTTS) over an existing hand-off. A failed or stalled handshake is
/// dropped by `run_tls_listener` before the handler runs, so it emits no event. Every event of an
/// accepted session carries `"tls": true`.
pub async fn start_tls_listener(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
    tls: TlsServer,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));
    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    let tracker = handoff.connections().clone();
    run_tls_listener_tracked(
        addr,
        bounds.clone(),
        per_source_cap,
        Some(tracker),
        tls,
        move |stream, peer, local_addr, session_id| {
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            let handoff = handoff.clone();
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
                    handoff,
                )
                .await;
            }
        },
    )
    .await
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
    let handoff = new_capture_handoff(
        log_path.clone(),
        spool_dir,
        collector_id,
        outbox_dir,
        capture_budget,
    )?;
    let (bound, handle) =
        start_plain_listener(addr, log_path, wan_resolver, bounds, handoff.clone()).await?;
    Ok((bound, handle, handoff))
}

/// The MQTTS twin of [`start_test_server_with_handoff`]: its own hand-off, a TLS-only listener.
#[allow(clippy::too_many_arguments)]
pub async fn start_test_server_tls_with_handoff(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
    tls: TlsServer,
) -> std::io::Result<(SocketAddr, JoinHandle<()>, Arc<CaptureHandoff>)> {
    let handoff = new_capture_handoff(
        log_path.clone(),
        spool_dir,
        collector_id,
        outbox_dir,
        capture_budget,
    )?;
    let (bound, handle) =
        start_tls_listener(addr, log_path, wan_resolver, bounds, handoff.clone(), tls).await?;
    Ok((bound, handle, handoff))
}
