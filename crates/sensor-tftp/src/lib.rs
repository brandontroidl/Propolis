//! sensor-tftp: a TFTP (UDP/69) honeypot that records read and write probes and captures uploaded
//! payloads. It is one of two sensors that reply over UDP (sensor-dns is the other), so its reply
//! surface is bounded by construction: see [`guarded`] for the byte-budget guarantee and the
//! source check, and [`handler`] for the state machine. Every datagram on the request socket is
//! also rate limited per source network and in total (`sensor_framework::rate_limit`): one over
//! its budget gets no reply and no event of its own, only a share of one bounded summary event per
//! source network per window. It never serves file content, never retransmits, and never opens an
//! outbound connection.

pub mod guarded;
pub mod handler;
pub mod protocol;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    Arrival, CaptureHandoff, CaptureMemoryBudget, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, EventEmitter, FloodLedger, OutboxManifest, PerSourceLimiter,
    QuarantineSpool, RateDecision, RateLimitConfig, ReplyRateLimiter, WanResolver, arrival,
    default_per_source_cap,
};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use handler::{MAX_BODY_HARD_CAP, RECV_BUFFER, Sensor, flood_sample};

const SPOOL_GLOBAL_BUDGET: u64 = 100_000_000;
/// `pub` so the default-memory-budget test in `main.rs` counts the same queue the sensor builds.
pub const CAPTURE_QUEUE_SIZE: usize = 64;
/// Backoff after a failed receive, so a persistent error (descriptor exhaustion) degrades to a
/// slow retry instead of a hot loop.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// The request socket's rate limiter and the ledger of what it refused.
struct RequestFlood {
    limiter: ReplyRateLimiter,
    ledger: FloodLedger,
}

/// A running sensor: the bound request address, the capture hand-off `main` drains on shutdown,
/// and the tasks behind them.
pub struct TftpServer {
    pub addr: SocketAddr,
    pub handoff: Arc<CaptureHandoff>,
    serve_handle: JoinHandle<()>,
    summary_handle: JoinHandle<()>,
    sensor: Arc<Sensor>,
    flood: Arc<RequestFlood>,
}

impl TftpServer {
    /// Stop taking requests and stop the summary timer. Transfers already running finish on
    /// their own bounds.
    pub fn abort(&self) {
        self.serve_handle.abort();
        self.summary_handle.abort();
    }

    /// Emit every rate-limited summary still accumulating, due or not. Bounded by the summary
    /// table's fixed capacity; called at shutdown after [`TftpServer::abort`].
    pub async fn flush_rate_limited(&self) {
        self.sensor
            .emit_summaries(self.flood.ledger.drain(), self.flood.ledger.window())
            .await;
    }
}

/// Bind the request socket on `addr` and serve it, with the default capture memory budget. `main`
/// and the tests both come through here or [`start_test_server_with_capture_budget`], so the tests
/// exercise the code the binary runs.
#[allow(clippy::too_many_arguments)]
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    rate: RateLimitConfig,
) -> std::io::Result<TftpServer> {
    start_test_server_with_capture_budget(
        addr,
        log_path,
        spool_dir,
        wan_resolver,
        bounds,
        collector_id,
        outbox_dir,
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        rate,
    )
    .await
}

/// [`start_test_server`] with the process-wide capture memory budget `main` built from its
/// configured ceiling.
#[allow(clippy::too_many_arguments)]
pub async fn start_test_server_with_capture_budget(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
    rate: RateLimitConfig,
) -> std::io::Result<TftpServer> {
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let spool = QuarantineSpool::new(spool_dir, MAX_BODY_HARD_CAP, SPOOL_GLOBAL_BUDGET);
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        CAPTURE_QUEUE_SIZE,
        collector_id,
        OutboxManifest::new(outbox_dir),
        capture_budget,
    ));
    handoff.start_worker();

    let socket = UdpSocket::bind(addr).await?;
    let bound = socket.local_addr()?;
    let semaphore = Arc::new(Semaphore::new(bounds.max_concurrent as usize));
    let limiter = PerSourceLimiter::new(default_per_source_cap(bounds.max_concurrent));
    let sensor = Arc::new(Sensor {
        emitter,
        wan_resolver,
        bounds,
        handoff: handoff.clone(),
        local_ip: bound.ip(),
        #[cfg(test)]
        transfers_bound: Default::default(),
    });
    let flood = Arc::new(RequestFlood {
        limiter: ReplyRateLimiter::new(&rate),
        ledger: FloodLedger::new(&rate),
    });

    let arrival = Arrival::new(bound.port());
    let serve_handle = tokio::spawn(serve(
        socket,
        arrival,
        sensor.clone(),
        semaphore,
        limiter,
        flood.clone(),
    ));
    let summary_handle = tokio::spawn(emit_due_summaries(sensor.clone(), flood.clone()));
    Ok(TftpServer {
        addr: bound,
        handoff,
        serve_handle,
        summary_handle,
        sensor,
        flood,
    })
}

/// The request loop. This socket only ever receives: replies leave from a per-transfer socket
/// (`guarded::Transfer`), as RFC 1350 specifies. Every datagram first takes a rate token, before
/// it is parsed: one that gets none goes to the flood ledger unanswered. Only the request is
/// charged; the DATA and ACK packets of a running transfer arrive on its own socket, already
/// pinned to one peer. A request that cannot get a per-source slot or a concurrency permit is
/// dropped unanswered, like any other lost datagram, and the loop keeps draining the socket.
///
/// `arrival` is this socket's bound port. Every event of a request, its upload's included, is
/// stamped with it: the request arrived here even though its transfer runs on its own ephemeral
/// socket.
async fn serve(
    socket: UdpSocket,
    arrival: Arrival,
    sensor: Arc<Sensor>,
    semaphore: Arc<Semaphore>,
    limiter: PerSourceLimiter,
    flood: Arc<RequestFlood>,
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
        let datagram = &buf[..n];
        let decision = flood.limiter.check(peer);
        if decision != RateDecision::Allow {
            flood
                .ledger
                .record(peer, decision, n, Instant::now(), || flood_sample(datagram));
            continue;
        }
        let Some(request) = handler::classify(datagram) else {
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
            let handled = tokio::time::timeout(
                max_duration,
                arrival::scope(arrival, sensor.handle_request(peer, request)),
            );
            if handled.await.is_err() {
                tracing::warn!(%peer, "tftp: transfer exceeded max_duration; dropped");
            }
        });
    }
}

/// Emit each summary whose window has ended, forever. Holds no lock across the appends: the
/// ledger hands over the due summaries and forgets them first.
async fn emit_due_summaries(sensor: Arc<Sensor>, flood: Arc<RequestFlood>) {
    let window = flood.ledger.window();
    let mut ticker = tokio::time::interval(flood.ledger.emit_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let due = flood.ledger.take_due(Instant::now());
        sensor.emit_summaries(due, window).await;
    }
}
