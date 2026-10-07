//! sensor-dns: a DNS honeypot with three surfaces: UDP 53 and TCP 53 on one bind address, and
//! optional DNS over TLS (RFC 7858) on 853. It serves no records: every query that parses gets
//! the same REFUSED reply, the query's header rewritten and its question echoed, nothing appended
//! (see [`protocol::refused_reply`]). A UDP reply is therefore never larger than the query that
//! caused it, and [`guarded`] holds the crate's single UDP send site behind a byte budget and a
//! source-address gate. The sensor never opens an outbound connection.
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
    ConnectionBounds, EventEmitter, PerSourceLimiter, TlsServer, WanResolver,
    default_per_source_cap, run_tcp_listener, run_tls_listener,
};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use guarded::ReplySocket;
use udp::UdpSensor;

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
}

/// Bind UDP and TCP on the same ip:port and serve both. UDP is bound first but not served until
/// TCP binds too, so a failed TCP bind drops the UDP socket before returning: nothing is left
/// listening on a half-started sensor. With port 0 the TCP bind on the port UDP drew may collide
/// with another process, so the pair is retried a few times.
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) -> std::io::Result<PlainListeners> {
    let ctx = Ctx {
        emitter: Arc::new(EventEmitter::new(log_path)),
        wan_resolver,
        bounds: bounds.clone(),
    };
    let per_source_cap = default_per_source_cap(bounds.max_concurrent);
    let attempts = if addr.port() == 0 { 8 } else { 1 };
    for attempt in 1..=attempts {
        let udp = UdpSocket::bind(addr).await?;
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
                let udp_handle = tokio::spawn(udp::serve(socket, sensor, semaphore, limiter));
                return Ok(PlainListeners {
                    udp: udp_bound,
                    tcp: tcp_bound,
                    udp_handle,
                    tcp_handle,
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
                return Err(e);
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
}
