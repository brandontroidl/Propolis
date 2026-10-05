//! sensor-tftp: a TFTP (UDP/69) honeypot that records read and write probes and captures uploaded
//! payloads. It is the one sensor that replies over UDP, so its reply surface is bounded by
//! construction: see [`guarded`] for the byte-budget guarantee and [`handler`] for the state
//! machine. It never serves file content, never retransmits, and never opens an outbound
//! connection.

pub mod guarded;
pub mod handler;
pub mod protocol;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureHandoff, ConnectionBounds, EventEmitter, OutboxManifest, PerSourceLimiter,
    QuarantineSpool, WanResolver, default_per_source_cap,
};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use handler::{MAX_BODY_HARD_CAP, RECV_BUFFER, Sensor};

const SPOOL_GLOBAL_BUDGET: u64 = 100_000_000;
/// `pub` so the default-memory-budget test in `main.rs` counts the same queue the sensor builds.
pub const CAPTURE_QUEUE_SIZE: usize = 64;
/// Backoff after a failed receive, so a persistent error (descriptor exhaustion) degrades to a
/// slow retry instead of a hot loop.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// Bind the request socket on `addr` and serve it. `main` and the tests both come through here, so
/// the tests exercise the code the binary runs. Returns the bound address (useful for a `:0` bind)
/// and the serve task.
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let spool = QuarantineSpool::new(spool_dir, MAX_BODY_HARD_CAP, SPOOL_GLOBAL_BUDGET);
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        CAPTURE_QUEUE_SIZE,
        collector_id,
        OutboxManifest::new(outbox_dir),
    ));
    let _worker = handoff.start_worker();

    let socket = UdpSocket::bind(addr).await?;
    let bound = socket.local_addr()?;
    let semaphore = Arc::new(Semaphore::new(bounds.max_concurrent as usize));
    let limiter = PerSourceLimiter::new(default_per_source_cap(bounds.max_concurrent));
    let sensor = Arc::new(Sensor {
        emitter,
        wan_resolver,
        bounds,
        handoff,
        local_ip: bound.ip(),
    });

    let handle = tokio::spawn(serve(socket, sensor, semaphore, limiter));
    Ok((bound, handle))
}

/// The request loop. This socket only ever receives: replies leave from a per-transfer socket
/// (`guarded::Transfer`), as RFC 1350 specifies. A request that cannot get a concurrency permit
/// is dropped unanswered, like any other lost datagram, and the loop keeps draining the socket.
async fn serve(
    socket: UdpSocket,
    sensor: Arc<Sensor>,
    semaphore: Arc<Semaphore>,
    limiter: PerSourceLimiter,
) {
    let max_duration = sensor.bounds.max_duration;
    let mut buf = vec![0u8; RECV_BUFFER];
    let mut refused: u64 = 0;
    let mut source_refused: u64 = 0;
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                tracing::warn!(error = %e, "tftp: recv error; retrying");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        let Some(request) = handler::classify(&buf[..n]) else {
            continue;
        };
        // Per-source first so a refused source never burns a global permit.
        let Some(source_guard) = limiter.try_admit(peer) else {
            source_refused += 1;
            if source_refused.is_power_of_two() {
                tracing::warn!(refused_total = source_refused, %peer, "tftp: per-source cap reached; request dropped");
            }
            continue;
        };
        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            refused += 1;
            // Logged at power-of-two totals: a flood must not fill the log it is probing.
            if refused.is_power_of_two() {
                tracing::warn!(refused_total = refused, %peer, "tftp: max_concurrent reached; request dropped");
            }
            continue;
        };
        let sensor = sensor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _source_guard = source_guard;
            let handled = tokio::time::timeout(max_duration, sensor.handle_request(peer, request));
            if handled.await.is_err() {
                tracing::warn!(%peer, "tftp: transfer exceeded max_duration; dropped");
            }
        });
    }
}
