//! The UDP serve loop and the per-datagram handler. The socket is shared with
//! [`crate::guarded::ReplySocket`], which holds the only send path.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{PerSourceLimiter, Uuid};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

use crate::Ctx;
use crate::events::{QueryRecord, QueryStatus, udp_query_event};
use crate::guarded::{ReplySocket, Sent, reply_gate};
use crate::protocol::{HEADER_LEN, Transport, parse_query, refused_reply};

/// The largest UDP payload, so nothing is clipped to look shorter than it was.
pub(crate) const RECV_BUFFER: usize = 65536;
/// Backoff after a failed receive, so a persistent error (descriptor exhaustion) degrades to a
/// slow retry instead of a hot loop.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);

pub(crate) struct UdpSensor {
    pub ctx: Ctx,
    pub reply: ReplySocket,
    /// The address the socket is bound to. UDP offers no per-datagram local address, so WAN
    /// attribution resolves against the bind address (under a wildcard bind, the wildcard).
    pub local_ip: IpAddr,
}

/// Receive datagrams forever. A datagram shorter than a header is dropped without an event; a
/// datagram that cannot get a per-source slot or a concurrency permit is dropped like any other
/// lost datagram, and the loop keeps draining the socket.
pub(crate) async fn serve(
    socket: Arc<UdpSocket>,
    sensor: Arc<UdpSensor>,
    semaphore: Arc<Semaphore>,
    limiter: PerSourceLimiter,
) {
    let mut buf = vec![0u8; RECV_BUFFER];
    let mut refused: u64 = 0;
    let mut source_refused: u64 = 0;
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                tracing::warn!(error = %e, "dns: recv error; retrying");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        if n < HEADER_LEN {
            continue;
        }
        // Per-source first so a refused source never burns a global permit.
        let Some(source_guard) = limiter.try_admit(peer) else {
            source_refused += 1;
            // Power-of-two totals: a flood must not fill the log it is probing.
            if source_refused.is_power_of_two() {
                tracing::warn!(refused_total = source_refused, %peer, "dns: per-source cap reached; datagram dropped");
            }
            continue;
        };
        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            refused += 1;
            if refused.is_power_of_two() {
                tracing::warn!(refused_total = refused, %peer, "dns: max_concurrent reached; datagram dropped");
            }
            continue;
        };
        let datagram = buf[..n].to_vec();
        let sensor = sensor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _source_guard = source_guard;
            let read_timeout = sensor.ctx.bounds.read_timeout;
            let handled =
                tokio::time::timeout(read_timeout, sensor.handle_datagram(peer, datagram));
            if handled.await.is_err() {
                tracing::warn!(%peer, "dns: datagram handling exceeded read_timeout; dropped");
            }
        });
    }
}

impl UdpSensor {
    /// Record one datagram, then answer it if it parsed and the reply gate allows. The event is
    /// appended before the reply is sent and records the decision that governed the send.
    pub(crate) async fn handle_datagram(&self, peer: SocketAddr, datagram: Vec<u8>) {
        let source_ip = normalize_dual_stack(peer).ip();
        let wan_ip = self
            .ctx
            .wan_resolver
            .resolve(normalize_dual_stack(SocketAddr::new(self.local_ip, 0)).ip());
        let session_id = Uuid::now_v7();

        let parsed = parse_query(&datagram, Transport::Udp);
        let (record, reply) = match &parsed {
            Ok(q) => {
                let reply = refused_reply(&datagram, q);
                let status = match reply_gate(peer, datagram.len(), reply.len()) {
                    Ok(()) => QueryStatus::Answered,
                    Err(reason) => QueryStatus::Suppressed(reason),
                };
                let record = QueryRecord {
                    transport: Transport::Udp,
                    tls: false,
                    status,
                    query_len: datagram.len(),
                    declared_len: None,
                    msg_index: None,
                    header: Some(&q.header),
                    question: Some(&q.question),
                    edns: Some(&q.edns),
                    reply_len: (status == QueryStatus::Answered).then_some(reply.len()),
                };
                (record, (status == QueryStatus::Answered).then_some(reply))
            }
            Err(rejected) => (
                QueryRecord {
                    transport: Transport::Udp,
                    tls: false,
                    status: QueryStatus::Rejected(rejected.reason),
                    query_len: datagram.len(),
                    declared_len: None,
                    msg_index: None,
                    header: rejected.header.as_ref(),
                    question: rejected.question.as_ref(),
                    edns: None,
                    reply_len: None,
                },
                None,
            ),
        };

        let event = udp_query_event(&record, source_ip, wan_ip, session_id);
        if let Err(e) = self.ctx.emitter.append(&event).await {
            tracing::error!(error = %e, "dns: failed to append event");
        }

        let Some(reply) = reply else {
            return;
        };
        match self.reply.send_reply(peer, datagram.len(), &reply).await {
            Sent::Ok => {}
            Sent::Failed(e) => tracing::debug!(%peer, error = %e, "dns: reply send failed"),
            Sent::Refused(reason) => {
                // Unreachable: the same pure gate already passed above.
                tracing::warn!(%peer, reason = reason.as_str(), "dns: reply refused at send");
            }
        }
    }
}
