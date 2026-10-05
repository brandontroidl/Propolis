//! The only code in this crate that can put a UDP packet on the wire.
//!
//! TFTP is the one sensor that answers over UDP, and a UDP reply is the raw material of a
//! reflection attack: the source address of a datagram is whatever the sender wrote, so every
//! packet this sensor emits can be aimed at a victim by a spoofer. The construction here removes
//! the amplification, not just the attack: a [`Transfer`] owns the transfer socket privately and
//! its single `send_to` call sits behind [`ByteBudget`], which refuses any packet that would take
//! the bytes sent past the bytes received from the peer. Reflection of a spoofed request therefore
//! returns no more bytes than the spoofer sent (the reply can equal the request in size, never
//! exceed it), and there is no retransmission path, because a retransmission is a send with
//! nothing new received.
//!
//! The same type pins the peer: it records the exact (ip, port) the request came from, sends only
//! there, and reports any datagram from another source as [`Received::Foreign`] without counting
//! it toward the budget.

use std::io;
use std::net::{IpAddr, SocketAddr};

use sensor_framework::listener::normalize_dual_stack;
use tokio::net::UdpSocket;

/// Running totals for one transfer. `received` is bytes accepted from the pinned peer (the request
/// datagram included); `sent` is bytes the sensor has put on the wire to it.
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
    pub fn try_send(&mut self, len: usize) -> bool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// A datagram of this many bytes from the pinned peer, now counted in the budget.
    FromPeer(usize),
    /// A datagram from any other source: dropped, not counted, never answered.
    Foreign,
}

#[derive(Debug)]
pub enum Sent {
    Ok,
    /// Refused by the byte budget; nothing was sent.
    OverBudget,
    Failed(io::Error),
}

/// One transfer's socket: ephemeral, bound to the interface the request arrived on, pinned to the
/// requesting (ip, port).
pub struct Transfer {
    socket: UdpSocket,
    peer: SocketAddr,
    budget: ByteBudget,
}

impl Transfer {
    /// Bind a fresh ephemeral socket on `local_ip` for a transfer with `peer`, whose request
    /// datagram was `request_len` bytes (the first credit in the budget).
    pub async fn bind(local_ip: IpAddr, peer: SocketAddr, request_len: usize) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        let mut budget = ByteBudget::default();
        budget.record_received(request_len);
        Ok(Self {
            socket,
            peer,
            budget,
        })
    }

    pub fn budget(&self) -> &ByteBudget {
        &self.budget
    }

    /// The local address of the transfer socket, for tests that need to talk to it.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<Received> {
        let (n, from) = self.socket.recv_from(buf).await?;
        if !same_endpoint(from, self.peer) {
            return Ok(Received::Foreign);
        }
        self.budget.record_received(n);
        Ok(Received::FromPeer(n))
    }

    /// Send `packet` to the pinned peer if the byte budget allows it. This is the only `send_to`
    /// in the crate; `never_amplifies_static_check` in `tests/integration.rs` keeps it that way.
    pub async fn send(&mut self, packet: &[u8]) -> Sent {
        if !self.budget.try_send(packet.len()) {
            return Sent::OverBudget;
        }
        match self.socket.send_to(packet, self.peer).await {
            Ok(_) => Sent::Ok,
            Err(e) => Sent::Failed(e),
        }
    }
}

/// Whether two socket addresses name the same (ip, port), treating an IPv4-mapped IPv6 address and
/// the plain IPv4 it maps as the same host: a dual-stack socket reports an IPv4 peer in mapped
/// form. The port is compared too, since the TFTP transfer ID is the source port.
pub fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    normalize_dual_stack(a) == normalize_dual_stack(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_refuses_to_send_more_than_it_received() {
        let mut b = ByteBudget::default();
        assert!(!b.try_send(1), "nothing received, nothing may be sent");
        b.record_received(9);
        assert!(b.try_send(4));
        assert!(b.try_send(4));
        assert!(!b.try_send(2), "10 sent against 9 received must be refused");
        assert_eq!((b.received(), b.sent()), (9, 8));
        assert_eq!(b.remaining(), 1);
        assert!(b.try_send(1));
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn a_refused_send_reserves_nothing() {
        let mut b = ByteBudget::default();
        b.record_received(5);
        assert!(!b.try_send(6));
        assert_eq!(b.sent(), 0);
        assert!(b.try_send(5));
    }

    #[test]
    fn budget_arithmetic_does_not_overflow() {
        let mut b = ByteBudget::default();
        b.record_received(usize::MAX);
        b.record_received(usize::MAX);
        assert!(b.try_send(usize::MAX));
        assert!(!b.try_send(usize::MAX), "overflow refuses, never wraps");
        assert!(!b.try_send(1));
    }

    #[test]
    fn endpoints_match_on_ip_and_port_across_mapped_forms() {
        let plain: SocketAddr = "203.0.113.7:4000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:4000".parse().unwrap();
        assert!(same_endpoint(plain, mapped));
        assert!(!same_endpoint(plain, "203.0.113.7:4001".parse().unwrap()));
        assert!(!same_endpoint(plain, "203.0.113.8:4000".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_datagram_from_another_source_is_foreign_and_uncounted() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut transfer =
            Transfer::bind("127.0.0.1".parse().unwrap(), peer.local_addr().unwrap(), 9)
                .await
                .unwrap();
        let target = transfer.local_addr().unwrap();
        let mut buf = [0u8; 64];

        other.send_to(b"spoof", target).await.unwrap();
        assert_eq!(transfer.recv(&mut buf).await.unwrap(), Received::Foreign);
        assert_eq!(
            transfer.budget().received(),
            9,
            "foreign bytes earn no budget"
        );

        peer.send_to(b"real", target).await.unwrap();
        assert_eq!(
            transfer.recv(&mut buf).await.unwrap(),
            Received::FromPeer(4)
        );
        assert_eq!(transfer.budget().received(), 13);
    }

    #[tokio::test]
    async fn send_goes_only_to_the_pinned_peer_and_only_within_budget() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut transfer =
            Transfer::bind("127.0.0.1".parse().unwrap(), peer.local_addr().unwrap(), 6)
                .await
                .unwrap();
        assert!(matches!(transfer.send(&[1, 2, 3, 4]).await, Sent::Ok));
        let mut buf = [0u8; 16];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3, 4]);
        assert_eq!(from, transfer.local_addr().unwrap());
        // 4 of 6 used; a further 4 would exceed the credit.
        assert!(matches!(
            transfer.send(&[1, 2, 3, 4]).await,
            Sent::OverBudget
        ));
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            peer.recv_from(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "an over-budget packet must not reach the wire"
        );
    }
}
