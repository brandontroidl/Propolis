//! The UDP serve loop and the per-datagram handler. The socket is shared with
//! [`crate::guarded::ReplySocket`], which holds the only send path.
//!
//! Every datagram long enough to carry a header first takes a token from the reply rate limiter
//! (per source network and global). One that gets none is not answered and not logged on its
//! own: it is counted into its source network's summary in the flood ledger, and
//! [`emit_due_summaries`] writes one `rate_limited` event per network per window. A flood
//! therefore costs the log a bounded number of events, and allocates nothing per datagram beyond
//! the limiter's and ledger's fixed tables.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    Arrival, FloodLedger, FloodSummary, PerSourceLimiter, RateDecision, ReplyRateLimiter, Uuid,
    arrival,
};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::Ctx;
use crate::events::{QueryRecord, QueryStatus, rate_limited_event, udp_query_event};
use crate::guarded::{ReplySocket, Sent, reply_gate};
use crate::protocol::{HEADER_LEN, Transport, parse_query, qtype_name, refused_reply};

/// The largest UDP payload, so nothing is clipped to look shorter than it was.
pub(crate) const RECV_BUFFER: usize = 65536;
/// Backoff after a failed receive, so a persistent error (descriptor exhaustion) degrades to a
/// slow retry instead of a hot loop.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);
/// Bounds on how often due summaries are looked for: a tenth of the window, clamped.
const MIN_SUMMARY_TICK: Duration = Duration::from_millis(10);
const MAX_SUMMARY_TICK: Duration = Duration::from_secs(1);

pub(crate) struct UdpSensor {
    pub ctx: Ctx,
    pub reply: ReplySocket,
    /// The address the socket is bound to. UDP offers no per-datagram local address, so WAN
    /// attribution resolves against the bind address (under a wildcard bind, the wildcard).
    pub local_ip: IpAddr,
    /// The bound port, stamped on every event this surface emits. This socket is not run by
    /// `run_udp_listener` and its events leave from per-datagram and summary tasks, so the scope
    /// that listener would have entered is entered here, at each append.
    pub arrival: Arrival,
}

/// The UDP surface's rate limiter and the ledger of what it refused.
pub(crate) struct UdpFlood {
    pub limiter: ReplyRateLimiter,
    pub ledger: FloodLedger,
}

/// Receive datagrams forever. A datagram shorter than a header is dropped without an event; one
/// over its rate budget goes to the flood ledger; one that cannot get a per-source slot or a
/// concurrency permit is dropped like any other lost datagram, and the loop keeps draining the
/// socket.
pub(crate) async fn serve(
    socket: Arc<UdpSocket>,
    sensor: Arc<UdpSensor>,
    semaphore: Arc<Semaphore>,
    limiter: PerSourceLimiter,
    flood: Arc<UdpFlood>,
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
        let decision = flood.limiter.check(peer);
        if decision != RateDecision::Allow {
            let datagram = &buf[..n];
            flood
                .ledger
                .record(peer, decision, n, Instant::now(), || flood_sample(datagram));
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

/// `"<QTYPE> <qname>"` for a summary sample, or `"malformed"` when no question parsed. Runs only
/// while the summary has room for another sample.
fn flood_sample(datagram: &[u8]) -> String {
    let question = match parse_query(datagram, Transport::Udp) {
        Ok(q) => Some(q.question),
        Err(rejected) => rejected.question,
    };
    match question {
        Some(q) => format!("{} {}", qtype_name(q.qtype), q.qname),
        None => "malformed".to_string(),
    }
}

/// Emit each summary whose window has ended, forever. Holds no lock across the appends: the
/// ledger hands over the due summaries and forgets them first.
pub(crate) async fn emit_due_summaries(sensor: Arc<UdpSensor>, flood: Arc<UdpFlood>) {
    let window = flood.ledger.window();
    let tick = (window / 10).clamp(MIN_SUMMARY_TICK, MAX_SUMMARY_TICK);
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let due = flood.ledger.take_due(Instant::now());
        sensor.emit_summaries(due, window).await;
    }
}

impl UdpSensor {
    fn wan_ip(&self) -> Option<IpAddr> {
        self.ctx
            .wan_resolver
            .resolve(normalize_dual_stack(SocketAddr::new(self.local_ip, 0)).ip())
    }

    pub(crate) async fn emit_summaries(&self, summaries: Vec<FloodSummary>, window: Duration) {
        if summaries.is_empty() {
            return;
        }
        let wan_ip = self.wan_ip();
        let (now, now_utc) = (Instant::now(), Utc::now());
        for summary in &summaries {
            let event = rate_limited_event(summary, wan_ip, window, now, now_utc);
            if let Err(e) = arrival::scope(self.arrival, self.ctx.emitter.append(&event)).await {
                tracing::error!(error = %e, "dns: failed to append event");
            }
        }
    }

    /// Record one datagram, then answer it if it parsed and the reply gate allows. The event is
    /// appended before the reply is sent and records the decision that governed the send.
    pub(crate) async fn handle_datagram(&self, peer: SocketAddr, datagram: Vec<u8>) {
        let source_ip = normalize_dual_stack(peer).ip();
        let wan_ip = self.wan_ip();
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
        if let Err(e) = arrival::scope(self.arrival, self.ctx.emitter.append(&event)).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver};
    use sensor_wire::SensorEvent;

    fn query() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([7]);
        m.extend(b"example");
        m.extend([3]);
        m.extend(b"com");
        m.extend([0, 0, 1, 0, 1]);
        m
    }

    async fn sensor(log: &Path) -> UdpSensor {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        UdpSensor {
            ctx: Ctx {
                emitter: Arc::new(EventEmitter::new(log.to_path_buf())),
                wan_resolver: Arc::new(WanResolver::new(HashMap::new())),
                bounds: ConnectionBounds {
                    read_timeout: Duration::from_secs(5),
                    idle_timeout: Duration::from_secs(5),
                    max_duration: Duration::from_secs(30),
                    max_captured_bytes: 262_272,
                    max_concurrent: 16,
                },
            },
            local_ip: socket.local_addr().unwrap().ip(),
            arrival: Arrival::new(socket.local_addr().unwrap().port()),
            reply: ReplySocket::new(socket),
        }
    }

    fn last_event(log: &Path) -> SensorEvent {
        let text = std::fs::read_to_string(log).unwrap();
        serde_json::from_str(text.lines().last().unwrap()).unwrap()
    }

    /// The handler, not only the pure gate, refuses every suppressed source: the event says so
    /// and nothing reaches the socket.
    #[tokio::test]
    async fn the_handler_suppresses_reflective_ports_and_unroutable_sources() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let sensor = sensor(&log).await;
        for (peer, reason) in [
            ("198.51.100.9:7", "reflective_source_port"),
            ("198.51.100.9:19", "reflective_source_port"),
            ("198.51.100.9:0", "reflective_source_port"),
            ("255.255.255.255:5353", "unroutable_source"),
            ("[::ffff:224.0.0.1]:5353", "unroutable_source"),
            ("[ff02::1]:5353", "unroutable_source"),
        ] {
            sensor.handle_datagram(peer.parse().unwrap(), query()).await;
            let e = last_event(&log);
            assert_eq!(e.metadata["query_status"], "suppressed", "{peer}");
            assert_eq!(e.metadata["suppress_reason"], reason, "{peer}");
            assert!(e.metadata.get("reply_len").is_none(), "{peer}");
            assert!(e.metadata.get("rcode").is_none(), "{peer}");
            assert_eq!(sensor.reply.sends(), 0, "{peer}: a send was attempted");
        }

        // The counter does count: an ordinary client is answered through the same path.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sensor
            .handle_datagram(client.local_addr().unwrap(), query())
            .await;
        assert_eq!(last_event(&log).metadata["query_status"], "answered");
        assert_eq!(sensor.reply.sends(), 1);
    }

    #[test]
    fn flood_samples_name_the_question_or_say_malformed() {
        assert_eq!(flood_sample(&query()), "A example.com.");
        let mut answer_present = query();
        answer_present[7] = 1;
        assert_eq!(flood_sample(&answer_present), "A example.com.");
        let mut pointer = query();
        pointer[12] = 0xC0;
        assert_eq!(flood_sample(&pointer), "malformed");
    }
}
