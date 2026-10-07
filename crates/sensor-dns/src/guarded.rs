//! The only code in this crate that can put a UDP packet on the wire.
//!
//! A UDP reply is the raw material of a reflection attack: the source address of a datagram is
//! whatever the sender wrote, so every reply this sensor emits can be aimed at a victim by a
//! spoofer. The construction removes the amplification, not just the attack: the one reply shape
//! (`protocol::refused_reply`) is the query's own header and question with nothing appended, so it
//! is never larger than the query, and this module re-checks that with a [`ByteBudget`] before the
//! crate's single `send_to`. A reflected spoofed query therefore returns no more bytes than the
//! spoofer sent, and there is no retransmission path.
//!
//! [`reply_gate`] also refuses to answer a source that cannot be a real client (unspecified,
//! broadcast, multicast) or a source port that belongs to a legacy UDP service (echo, daytime,
//! qotd, chargen, time, and port 0): a query spoofed "from" one of those would make the sensor
//! start a loop with a third party's service.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use sensor_framework::listener::normalize_dual_stack;
use tokio::net::UdpSocket;

pub const REFLECTIVE_SOURCE_PORTS: [u16; 6] = [0, 7, 13, 17, 19, 37];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressReason {
    ReflectiveSourcePort,
    UnroutableSource,
    ByteBudget,
}

impl SuppressReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SuppressReason::ReflectiveSourcePort => "reflective_source_port",
            SuppressReason::UnroutableSource => "unroutable_source",
            SuppressReason::ByteBudget => "byte_budget",
        }
    }
}

/// Running totals for one exchange. `received` is bytes accepted from the peer; `sent` is bytes
/// the sensor has put on the wire to it. A copy of `sensor-tftp`'s budget, with the spend method
/// named `try_spend`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudget {
    received: u64,
    sent: u64,
}

impl ByteBudget {
    pub fn record_received(&mut self, len: usize) {
        self.received = self.received.saturating_add(len as u64);
    }

    /// Bytes the sensor may still send without exceeding what it has received.
    pub fn remaining(&self) -> usize {
        usize::try_from(self.received.saturating_sub(self.sent)).unwrap_or(usize::MAX)
    }

    /// Reserve `len` bytes of the budget. `false` (and nothing reserved) when the packet would
    /// make `sent` exceed `received`.
    pub fn try_spend(&mut self, len: usize) -> bool {
        let Some(total) = self.sent.checked_add(len as u64) else {
            return false;
        };
        if total > self.received {
            return false;
        }
        self.sent = total;
        true
    }

    pub fn received(&self) -> u64 {
        self.received
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }
}

/// Whether a reply of `reply_len` bytes to `peer`, for a query of `query_len` bytes, may be sent.
/// Pure: the decision depends only on its arguments.
pub fn reply_gate(
    peer: SocketAddr,
    query_len: usize,
    reply_len: usize,
) -> Result<(), SuppressReason> {
    let ip = normalize_dual_stack(peer).ip();
    let broadcast = ip == IpAddr::V4(Ipv4Addr::BROADCAST);
    if ip.is_unspecified() || broadcast || ip.is_multicast() {
        return Err(SuppressReason::UnroutableSource);
    }
    if REFLECTIVE_SOURCE_PORTS.contains(&peer.port()) {
        return Err(SuppressReason::ReflectiveSourcePort);
    }
    let mut budget = ByteBudget::default();
    budget.record_received(query_len);
    if !budget.try_spend(reply_len) {
        return Err(SuppressReason::ByteBudget);
    }
    Ok(())
}

#[derive(Debug)]
pub enum Sent {
    Ok,
    /// Refused by [`reply_gate`]; nothing was sent.
    Refused(SuppressReason),
    Failed(io::Error),
}

/// The listening socket's reply side.
pub struct ReplySocket {
    socket: Arc<UdpSocket>,
}

impl ReplySocket {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    /// Re-runs [`reply_gate`], then the crate's single `send_to`, to exactly `peer` as
    /// `recv_from` reported it (not normalized). `never_amplifies_static_check` in
    /// `tests/integration.rs` keeps it the only one.
    pub async fn send_reply(&self, peer: SocketAddr, query_len: usize, reply: &[u8]) -> Sent {
        if let Err(reason) = reply_gate(peer, query_len, reply.len()) {
            return Sent::Refused(reason);
        }
        match self.socket.send_to(reply, peer).await {
            Ok(_) => Sent::Ok,
            Err(e) => Sent::Failed(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn budget_refuses_to_spend_more_than_it_received() {
        let mut b = ByteBudget::default();
        assert!(!b.try_spend(1), "nothing received, nothing may be sent");
        b.record_received(9);
        assert!(b.try_spend(4));
        assert!(b.try_spend(4));
        assert!(
            !b.try_spend(2),
            "10 sent against 9 received must be refused"
        );
        assert_eq!((b.received(), b.sent()), (9, 8));
        assert_eq!(b.remaining(), 1);
        assert!(b.try_spend(1));
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn a_refused_spend_reserves_nothing() {
        let mut b = ByteBudget::default();
        b.record_received(5);
        assert!(!b.try_spend(6));
        assert_eq!(b.sent(), 0);
        assert!(b.try_spend(5));
    }

    #[test]
    fn budget_arithmetic_does_not_overflow() {
        let mut b = ByteBudget::default();
        b.record_received(usize::MAX);
        b.record_received(usize::MAX);
        assert!(b.try_spend(usize::MAX));
        assert!(!b.try_spend(usize::MAX), "overflow refuses, never wraps");
        assert!(!b.try_spend(1));
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn reply_gate_refuses_reflective_ports_and_unroutable_sources() {
        for port in REFLECTIVE_SOURCE_PORTS {
            assert_eq!(
                reply_gate(
                    SocketAddr::new("203.0.113.7".parse().unwrap(), port),
                    30,
                    30
                ),
                Err(SuppressReason::ReflectiveSourcePort),
                "port {port}"
            );
        }
        for port in [1024, 53] {
            assert_eq!(
                reply_gate(
                    SocketAddr::new("203.0.113.7".parse().unwrap(), port),
                    30,
                    30
                ),
                Ok(())
            );
        }
        for peer in [
            "0.0.0.0:5353",
            "255.255.255.255:5353",
            "224.0.0.1:5353",
            "[ff02::1]:5353",
            "[::]:5353",
            "[::ffff:255.255.255.255]:5353",
        ] {
            assert_eq!(
                reply_gate(addr(peer), 30, 30),
                Err(SuppressReason::UnroutableSource),
                "{peer}"
            );
        }
        assert_eq!(reply_gate(addr("[2001:db8::1]:5353"), 30, 30), Ok(()));
    }

    #[test]
    fn reply_gate_refuses_a_reply_larger_than_the_query() {
        let peer = addr("198.51.100.9:40000");
        assert_eq!(reply_gate(peer, 20, 21), Err(SuppressReason::ByteBudget));
        assert_eq!(reply_gate(peer, 20, 20), Ok(()));
    }

    #[tokio::test]
    async fn send_reply_reaches_only_the_peer_and_never_over_budget() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply = ReplySocket::new(server.clone());
        let peer_addr = peer.local_addr().unwrap();

        assert!(matches!(
            reply.send_reply(peer_addr, 29, &[7u8; 29]).await,
            Sent::Ok
        ));
        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!((n, from), (29, server.local_addr().unwrap()));

        assert!(matches!(
            reply.send_reply(peer_addr, 29, &[7u8; 30]).await,
            Sent::Refused(SuppressReason::ByteBudget)
        ));
        let got = tokio::time::timeout(Duration::from_millis(150), peer.recv_from(&mut buf)).await;
        assert!(got.is_err(), "an over-budget reply must not reach the wire");
    }
}
