//! Peer-pinned TFTP RRQ fetch (RFC 1350). Malware loaders (Mirai/Gafgyt variants) commonly pull a
//! payload via `tftp -g <host> -r <file>`, so this is a real capture path alongside HTTP.
//!
//! TFTP runs over UDP with no built-in peer authentication, so every defense here is enforced in
//! application code rather than left to the OS:
//!
//! - The socket is bound but never `connect()`-ed to the well-known port 69. A `connect()`-ed UDP
//!   socket only ever delivers datagrams from the exact peer address it was connected to
//!   (verified empirically against tokio's `UdpSocket` before writing this: a client connected to
//!   `ip:69` never observes a reply from a different source port). A real TFTP server replies to
//!   data requests from a freshly allocated ephemeral port - the TID - almost never port 69, so
//!   connecting up front would make the legitimate reply itself unreceivable. [`recv_from_locked_peer`]
//!   does the equivalent check by hand: it accepts the first reply from `pinned.ip` on any port
//!   (that port becomes the locked TID) and rejects every later packet whose source is not
//!   exactly `(pinned.ip, locked TID)`.
//! - The caller has already run `guard::vet(..., allow_tftp: true)` to produce `pinned`, so
//!   `pinned.ip` is the SSRF-vetted target; nothing here ever dials or accepts a reply from any
//!   other host.
//! - An `OACK` (option negotiation, opcode 6) as the first reply aborts the fetch outright rather
//!   than negotiating `blksize`/`tsize` - a negotiated oversized block is a cheap amplification
//!   vector, and this client has no need for it.
//! - A running byte cap is enforced per block, so an oversized transfer aborts mid-stream instead
//!   of buffering the whole thing.
//! - Every wait for a reply is bounded by a fixed per-block timeout with a capped retry count, and
//!   the whole transfer is additionally wrapped in `limits.total_timeout`: worst case, a
//!   many-block transfer that stalls on every single block could otherwise run unbounded
//!   (retries x per-block timeout x block count), so `total_timeout` is the hard outer cap that
//!   actually bounds it.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::guard::Pinned;
use super::http::FetchLimits;

const OP_RRQ: u16 = 1;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const OP_OACK: u16 = 6;

/// TFTP's fixed data-block size (RFC 1350); a block shorter than this marks end of transfer.
const BLOCK_SIZE: usize = 512;
/// How long to wait for a reply before retransmitting the last packet sent.
const PER_BLOCK_TIMEOUT: Duration = Duration::from_secs(2);
/// Retransmit attempts per wait, on top of the initial send - not a global budget for the whole
/// transfer (see the module doc: `limits.total_timeout` is what bounds the many-block worst case).
const MAX_RETRIES: u32 = 5;

/// The outcome of one [`fetch_tftp`] call.
#[derive(Debug, Clone, PartialEq)]
pub enum TftpOutcome {
    Captured(Vec<u8>),
    Empty,
    TooBig,
    Oack,
    Timeout,
}

#[derive(Debug, thiserror::Error)]
pub enum TftpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetch `path` from `pinned` via a TFTP RRQ in octet mode. Connects to nothing but `pinned.ip`
/// (the caller's already-vetted, SSRF-safe target) and enforces the TID lock, OACK abort, byte
/// cap, and timeout invariants described in the module doc.
pub async fn fetch_tftp(
    pinned: &Pinned,
    path: &str,
    limits: &FetchLimits,
) -> Result<TftpOutcome, TftpError> {
    match tokio::time::timeout(limits.total_timeout, fetch_tftp_inner(pinned, path, limits)).await {
        Ok(result) => result,
        Err(_) => Ok(TftpOutcome::Timeout),
    }
}

async fn fetch_tftp_inner(
    pinned: &Pinned,
    path: &str,
    limits: &FetchLimits,
) -> Result<TftpOutcome, TftpError> {
    let local_addr = match pinned.ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(local_addr).await?;

    let mut buf = vec![0u8; 4 + BLOCK_SIZE];
    let mut locked_tid: Option<SocketAddr> = None;
    let mut captured = Vec::new();
    let mut expected_block: u16 = 1;
    let mut pending = rrq_packet(path);
    let mut pending_dest = SocketAddr::new(pinned.ip, pinned.port);

    loop {
        let Some(n) = recv_with_retries(
            &socket,
            &mut buf,
            pinned.ip,
            &mut locked_tid,
            &pending,
            pending_dest,
        )
        .await?
        else {
            return Ok(TftpOutcome::Timeout);
        };

        if n < 2 {
            continue; // too short to carry an opcode - noise from the locked peer, ignore it
        }
        let opcode = u16::from_be_bytes([buf[0], buf[1]]);

        match opcode {
            OP_OACK => return Ok(TftpOutcome::Oack),
            OP_ERROR => return Ok(terminal(captured)),
            OP_DATA if n >= 4 => {
                let block = u16::from_be_bytes([buf[2], buf[3]]);
                if block != expected_block {
                    // Duplicate or out-of-order block (e.g. our ACK was lost and the server
                    // retransmitted the previous block): ignore it and keep waiting - the
                    // resend/retry loop above will re-ACK and prompt the real next block.
                    continue;
                }

                let data = &buf[4..n];
                if captured.len() + data.len() > limits.max_bytes {
                    return Ok(TftpOutcome::TooBig);
                }
                captured.extend_from_slice(data);
                let short = data.len() < BLOCK_SIZE;

                let tid = locked_tid.expect("recv_with_retries locks the TID before returning");
                let ack = ack_packet(block);
                if short {
                    // Final block: no further reply is expected, so ACK once directly rather
                    // than handing it to the wait/retry loop.
                    socket.send_to(&ack, tid).await?;
                    return Ok(terminal(captured));
                }
                pending = ack;
                pending_dest = tid;
                expected_block = expected_block.wrapping_add(1);
            }
            _ => continue, // unexpected opcode from the locked peer - ignore and keep waiting
        }
    }
}

fn terminal(captured: Vec<u8>) -> TftpOutcome {
    if captured.is_empty() {
        TftpOutcome::Empty
    } else {
        TftpOutcome::Captured(captured)
    }
}

/// Waits for a reply to `send_buf` (sent to `dest`) that passes the peer/TID lock, retransmitting
/// `send_buf` on every timeout up to [`MAX_RETRIES`] additional attempts. A packet from the wrong
/// peer is dropped *within* the current wait window by [`recv_from_locked_peer`] and never
/// consumes a retry - only a window that elapses with no validly-sourced reply at all does.
/// Returns `Ok(None)` once retries are exhausted with nothing valid received.
async fn recv_with_retries(
    socket: &UdpSocket,
    buf: &mut [u8],
    pinned_ip: IpAddr,
    locked_tid: &mut Option<SocketAddr>,
    send_buf: &[u8],
    dest: SocketAddr,
) -> Result<Option<usize>, TftpError> {
    for _ in 0..=MAX_RETRIES {
        socket.send_to(send_buf, dest).await?;
        match tokio::time::timeout(
            PER_BLOCK_TIMEOUT,
            recv_from_locked_peer(socket, buf, pinned_ip, locked_tid),
        )
        .await
        {
            Ok(Ok(n)) => return Ok(Some(n)),
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => continue,
        }
    }
    Ok(None)
}

/// Receives datagrams until one passes the peer lock, silently dropping everything else - the
/// TID-lock anti-injection defense. Before a TID is locked, only `pinned_ip` is checked (any port
/// establishes the lock, since the real TID is not known yet); once locked, the source must match
/// `locked_tid` exactly (IP and port). An off-path attacker's packet - wrong IP, wrong port, or
/// both - is dropped here and never accepted, never ACKed, and never mistaken for the real reply.
async fn recv_from_locked_peer(
    socket: &UdpSocket,
    buf: &mut [u8],
    pinned_ip: IpAddr,
    locked_tid: &mut Option<SocketAddr>,
) -> Result<usize, TftpError> {
    loop {
        let (n, from) = socket.recv_from(buf).await?;
        match *locked_tid {
            None => {
                if from.ip() != pinned_ip {
                    continue;
                }
                *locked_tid = Some(from);
                return Ok(n);
            }
            Some(tid) if from == tid => return Ok(n),
            Some(_) => continue, // TID mismatch: off-path/injected packet, drop
        }
    }
}

/// `\x00\x01<path>\x00octet\x00` - RRQ in octet (binary) mode; no options negotiated.
fn rrq_packet(path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + path.len() + 1 + 5 + 1);
    buf.extend_from_slice(&OP_RRQ.to_be_bytes());
    buf.extend_from_slice(path.as_bytes());
    buf.push(0);
    buf.extend_from_slice(b"octet");
    buf.push(0);
    buf
}

/// `\x00\x04<block>` - ACK for `block`.
fn ack_packet(block: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&OP_ACK.to_be_bytes());
    buf.extend_from_slice(&block.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::super::guard::{Pinned, Scheme};
    use super::super::http::FetchLimits;
    use super::*;

    fn pinned(ip: IpAddr, port: u16) -> Pinned {
        Pinned {
            host: ip.to_string(),
            ip,
            port,
            scheme: Scheme::Tftp,
        }
    }

    fn limits(max_bytes: usize) -> FetchLimits {
        FetchLimits {
            max_bytes,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(5),
            user_agent: "propolis-fetch-test".to_string(),
        }
    }

    fn data_packet(block: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0, 3];
        pkt.extend_from_slice(&block.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[tokio::test]
    async fn rrq_happy_path_streams_blocks_to_captured() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut buf = [0u8; 600];
            let (_, client) = server.recv_from(&mut buf).await.unwrap(); // RRQ

            server
                .send_to(&data_packet(1, &[0xAAu8; 512]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // ACK 1

            server
                .send_to(&data_packet(2, &[0xBBu8; 10]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // ACK 2 (final, short block)
        });

        let result = fetch_tftp(
            &pinned(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            "loader.bin",
            &limits(1024 * 1024),
        )
        .await
        .unwrap();

        match result {
            TftpOutcome::Captured(bytes) => {
                assert_eq!(bytes.len(), 522);
                assert!(bytes[..512].iter().all(|&b| b == 0xAA));
                assert!(bytes[512..].iter().all(|&b| b == 0xBB));
            }
            other => panic!("expected Captured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn data_from_wrong_source_ip_is_dropped_real_block_captured() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        // A genuinely different source IP (not just a different port), to prove the lock checks
        // the address, not merely the TID's port. 127.0.0.0/8 is all loopback, so binding a
        // second address on it needs no elevated privilege.
        let attacker = UdpSocket::bind("127.0.0.2:0").await.unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 600];
            let (_, client) = server.recv_from(&mut buf).await.unwrap(); // RRQ

            // Block 1 from the real server establishes the TID lock.
            server
                .send_to(&data_packet(1, &[0x11u8; 512]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // ACK 1

            // Off-path attacker races an injected block 2 - same block number the client now
            // expects - from a different source IP than the just-locked TID. It must be dropped,
            // never accepted or ACKed, even though the block number matches.
            attacker
                .send_to(&data_packet(2, &[0xEEu8; 512]), client)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;

            // The real, short final block from the locked peer.
            server
                .send_to(&data_packet(2, &[0x22u8; 5]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // final ACK
        });

        let result = fetch_tftp(
            &pinned(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            "loader.bin",
            &limits(1024 * 1024),
        )
        .await
        .unwrap();

        match result {
            TftpOutcome::Captured(bytes) => {
                let mut expected = vec![0x11u8; 512];
                expected.extend_from_slice(&[0x22u8; 5]);
                assert_eq!(
                    bytes, expected,
                    "expected only the locked peer's blocks; the injected off-path block 2 must be dropped"
                );
            }
            other => panic!("expected Captured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_source_ip_packet_arriving_first_never_hijacks_the_lock() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        // A genuinely different source IP, not just a different port - this exercises the
        // pre-lock guard (`from.ip() != pinned_ip`, checked before `locked_tid` is ever set),
        // distinct from the post-lock TID check the test above exercises. 127.0.0.0/8 is all
        // loopback, so a second bound address needs no elevated privilege.
        let attacker = UdpSocket::bind("127.0.0.2:0").await.unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 600];
            let (_, client) = server.recv_from(&mut buf).await.unwrap(); // RRQ

            // Off-path attacker fires an injected block 1 immediately, racing to arrive before
            // the real server's reply. This must never establish the TID lock, no matter how
            // early it arrives - the lock may only ever be taken from `pinned.ip`.
            attacker
                .send_to(&data_packet(1, &[0xEEu8; 512]), client)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;

            // The real server's block 1 arrives after the injected packet.
            server
                .send_to(&data_packet(1, &[0x11u8; 5]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // final ACK
        });

        let result = fetch_tftp(
            &pinned(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            "loader.bin",
            &limits(1024 * 1024),
        )
        .await
        .unwrap();

        match result {
            TftpOutcome::Captured(bytes) => assert_eq!(
                bytes,
                vec![0x11u8; 5],
                "the injected off-path packet must never establish the lock; only the real \
                 peer's block may be captured"
            ),
            other => panic!("expected Captured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn first_reply_oack_aborts() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut buf = [0u8; 600];
            let (_, client) = server.recv_from(&mut buf).await.unwrap(); // RRQ
            server.send_to(&[0, 6], client).await.unwrap(); // OACK, no options
        });

        let result = fetch_tftp(
            &pinned(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            "loader.bin",
            &limits(1024),
        )
        .await
        .unwrap();

        assert_eq!(result, TftpOutcome::Oack);
    }

    #[tokio::test]
    async fn oversize_transfer_hits_byte_cap() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut buf = [0u8; 600];
            let (_, client) = server.recv_from(&mut buf).await.unwrap(); // RRQ

            server
                .send_to(&data_packet(1, &[0x77u8; 512]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // ACK 1

            server
                .send_to(&data_packet(2, &[0x77u8; 512]), client)
                .await
                .unwrap();
            server.recv_from(&mut buf).await.unwrap(); // ACK 2 (total now exactly at cap)

            // Pushes the running total over the cap; the client must bail before ACKing this one.
            server
                .send_to(&data_packet(3, &[0x77u8; 512]), client)
                .await
                .unwrap();
        });

        let result = fetch_tftp(
            &pinned(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            "loader.bin",
            &limits(1024), // exactly 2 full blocks; a 3rd must exceed it
        )
        .await
        .unwrap();

        assert_eq!(result, TftpOutcome::TooBig);
    }
}
