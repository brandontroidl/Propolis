//! sensor-dns: a DNS honeypot with three surfaces: UDP 53 and TCP 53 on one bind address, and
//! optional DNS over TLS (RFC 7858) on 853. It serves no records: every query that parses gets
//! the same REFUSED reply, the query's header rewritten and its question echoed, nothing appended
//! (see [`protocol::refused_reply`]). A UDP reply is therefore never larger than the query that
//! caused it, and [`guarded`] holds the crate's single UDP send site behind a byte budget and a
//! source-address gate. UDP datagrams are also rate limited per source network and in total
//! (`sensor_framework::rate_limit`): one over its budget gets no reply and no event of its own,
//! only a share of one bounded summary event per source network per window. The sensor never
//! opens an outbound connection.
//!
//! `main.rs` and the tests both start the sensor through [`start_test_server`] and
//! [`start_test_server_tls`], so the tests exercise the code the binary runs.

pub mod events;
pub mod guarded;
pub mod protocol;
pub mod stream;
mod udp;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    ConnectionBounds, EventEmitter, FloodLedger, PerSourceLimiter, RateLimitConfig,
    ReplyRateLimiter, TlsServer, WanResolver, default_per_source_cap, listener_start_error,
    run_tcp_listener, run_tls_listener,
};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use guarded::ReplySocket;
use udp::{UdpFlood, UdpSensor};

/// A bind failure naming the transport (`udp`, `tcp` or `dot`) as well as the address, since
/// one `PROPOLIS_DNS_BIND` starts two listeners and a resolver can hold either. Keeps the
/// error's kind.
fn start_error(transport: &str, addr: SocketAddr, error: std::io::Error) -> std::io::Error {
    let error = listener_start_error(addr, error);
    std::io::Error::new(error.kind(), format!("{transport}: {error}"))
}

/// Shared per-listener state handed to every handler.
#[derive(Clone)]
pub struct Ctx {
    pub emitter: Arc<EventEmitter>,
    pub wan_resolver: Arc<WanResolver>,
    pub bounds: ConnectionBounds,
}

/// The plaintext surfaces: UDP and TCP on the same ip:port.
pub struct PlainListeners {
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    pub udp_handle: JoinHandle<()>,
    pub tcp_handle: JoinHandle<()>,
    /// Emits rate-limited summaries as their windows end.
    pub summary_handle: JoinHandle<()>,
    sensor: Arc<UdpSensor>,
    flood: Arc<UdpFlood>,
}

impl PlainListeners {
    /// Stop serving: no datagram or connection is taken after this returns.
    pub fn abort(&self) {
        self.udp_handle.abort();
        self.tcp_handle.abort();
        self.summary_handle.abort();
    }

    /// Emit every rate-limited summary still accumulating, due or not. Bounded by the summary
    /// table's fixed capacity; called at shutdown after [`PlainListeners::abort`].
    pub async fn flush_rate_limited(&self) {
        self.sensor
            .emit_summaries(self.flood.ledger.drain(), self.flood.ledger.window())
            .await;
    }
}

/// Bind UDP and TCP on the same ip:port and serve both. UDP is bound first but not served until
/// TCP binds too, so a failed TCP bind drops the UDP socket before returning: nothing is left
/// listening on a half-started sensor. With port 0 the TCP bind on the port UDP drew may collide
/// with another process, so the pair is retried a few times. `rate` bounds UDP only: a TCP or
/// DoT source is proven by its handshake and cannot aim the sensor at a third party.
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    rate: RateLimitConfig,
) -> std::io::Result<PlainListeners> {
    let ctx = Ctx {
        emitter: Arc::new(EventEmitter::new(log_path)),
        wan_resolver,
        bounds: bounds.clone(),
    };
    let per_source_cap = default_per_source_cap(bounds.max_concurrent);
    let attempts = if addr.port() == 0 { 8 } else { 1 };
    for attempt in 1..=attempts {
        let udp = UdpSocket::bind(addr)
            .await
            .map_err(|e| start_error("udp", addr, e))?;
        let udp_bound = udp.local_addr()?;
        let tcp_addr = SocketAddr::new(addr.ip(), udp_bound.port());
        let tcp_ctx = ctx.clone();
        let started = run_tcp_listener(
            tcp_addr,
            bounds.clone(),
            Some(per_source_cap),
            move |stream, peer, session_id| {
                let local = stream.local_addr().ok();
                stream::handle_connection(stream, peer, local, false, session_id, tcp_ctx.clone())
            },
        )
        .await;
        match started {
            Ok((tcp_bound, tcp_handle)) => {
                let socket = Arc::new(udp);
                let sensor = Arc::new(UdpSensor {
                    ctx: ctx.clone(),
                    reply: ReplySocket::new(socket.clone()),
                    local_ip: udp_bound.ip(),
                });
                let semaphore = Arc::new(Semaphore::new(bounds.max_concurrent as usize));
                let limiter = PerSourceLimiter::new(per_source_cap);
                let flood = Arc::new(UdpFlood {
                    limiter: ReplyRateLimiter::new(&rate),
                    ledger: FloodLedger::new(&rate),
                });
                let udp_handle = tokio::spawn(udp::serve(
                    socket,
                    sensor.clone(),
                    semaphore,
                    limiter,
                    flood.clone(),
                ));
                let summary_handle =
                    tokio::spawn(udp::emit_due_summaries(sensor.clone(), flood.clone()));
                return Ok(PlainListeners {
                    udp: udp_bound,
                    tcp: tcp_bound,
                    udp_handle,
                    tcp_handle,
                    summary_handle,
                    sensor,
                    flood,
                });
            }
            Err(e)
                if addr.port() == 0
                    && e.kind() == std::io::ErrorKind::AddrInUse
                    && attempt < attempts =>
            {
                drop(udp);
            }
            Err(e) => {
                drop(udp);
                return Err(start_error("tcp", tcp_addr, e));
            }
        }
    }
    unreachable!("the last attempt returns from the loop")
}

/// DoT: an implicit-TLS listener in front of the same stream handler, with every event tagged
/// `"tls": true`. A failed or stalled handshake is dropped without an event.
pub async fn start_test_server_tls(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    tls: TlsServer,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let ctx = Ctx {
        emitter: Arc::new(EventEmitter::new(log_path)),
        wan_resolver,
        bounds: bounds.clone(),
    };
    let per_source_cap = default_per_source_cap(bounds.max_concurrent);
    run_tls_listener(
        addr,
        bounds,
        Some(per_source_cap),
        tls,
        move |stream, peer, local, session_id| {
            stream::handle_connection(stream, peer, local, true, session_id, ctx.clone())
        },
    )
    .await
    .map_err(|e| start_error("dot", addr, e))
}
