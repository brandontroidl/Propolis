//! A client that never reads its replies. Each SUBSCRIBE is answered with one SUBACK byte per
//! filter, and a filter can be empty, so a peer that sends SUBSCRIBEs and never reads blocks the
//! sensor in a reply write; while it is blocked the sensor does not read, and whatever the peer
//! sends waits in the kernel, charged to the unit's cgroup and seen by no budget. These drive a
//! real client into that state over plaintext and MQTTS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, TlsServer,
    WanResolver, server_config_from_pem,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// The flood stops here whatever happens: far past what a backpressured connection takes.
const FLOOD_CAP: usize = 12 * 1024 * 1024;

/// What a never-reading peer may push in SUBSCRIBEs before the sensor stops taking its bytes: the
/// SUBSCRIBE whose SUBACK blocks, then only the sensor's clamped receive queue and the client's
/// own buffers. Clamped, that measured about 306 KB over plaintext and 390 KB over MQTTS (the
/// client's TLS layer buffers some); unclamped, the sensor's send buffer took over a megabyte of
/// SUBACKs and its autotuned receive buffer the rest, about 6.3 MB (all on loopback).
const BACKPRESSURE_LIMIT: usize = 1024 * 1024;

/// One SUBSCRIBE body: packet id, then empty filters with QoS 0 (three bytes each), just under the
/// sensor's packet limit; its SUBACK is a third of its size.
const FILTERS_PER_SUBSCRIBE: usize = 87_000;

struct Server {
    plain: SocketAddr,
    tls: SocketAddr,
    connector: TlsConnector,
    handles: Vec<JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

async fn start(bounds: ConnectionBounds) -> Server {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let tls = TlsServer::from_config(
        server_config_from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert.der().to_vec()))
        .unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let handoff = sensor_mqtt::new_capture_handoff(
        log_path.clone(),
        dir.path().join("spool"),
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .unwrap();
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (plain, plain_handle) = sensor_mqtt::start_plain_listener(
        loopback,
        log_path.clone(),
        wan.clone(),
        bounds.clone(),
        handoff.clone(),
    )
    .await
    .unwrap();
    let (tls_addr, tls_handle) =
        sensor_mqtt::start_tls_listener(loopback, log_path, wan, bounds, handoff, tls)
            .await
            .unwrap();
    Server {
        plain,
        tls: tls_addr,
        connector: TlsConnector::from(Arc::new(client)),
        handles: vec![plain_handle, tls_handle],
        _dir: dir,
    }
}

fn varint(mut v: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            return out;
        }
    }
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![first];
    p.extend(varint(body.len()));
    p.extend_from_slice(body);
    p
}

fn connect_packet() -> Vec<u8> {
    let mut body = vec![0x00, 0x04];
    body.extend_from_slice(b"MQTT");
    // Level 4, clean session, keepalive 0 (the idle bound stays the configured one).
    body.extend_from_slice(&[0x04, 0x02, 0x00, 0x00]);
    body.extend_from_slice(&[0x00, 0x02]);
    body.extend_from_slice(b"t1");
    packet(0x10, &body)
}

fn subscribe_packet(packet_id: u16) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    for _ in 0..FILTERS_PER_SUBSCRIBE {
        body.extend_from_slice(&[0x00, 0x00, 0x00]);
    }
    packet(0x82, &body)
}

/// A client socket with small kernel buffers, so its own share of what it pushes is small and its
/// receive window shuts as soon as the replies it never reads pile up.
async fn small_buffer_client(addr: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(4096).unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.connect(addr).await.unwrap()
}

/// CONNECT, read the CONNACK (the last thing this client reads), then 600 KB of QoS 0 text
/// PUBLISH the sensor reads and answers with nothing, which is what grew the receive buffer in
/// the reported attack.
async fn connect_and_warm_up<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(&connect_packet()).await.unwrap();
    let mut connack = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut connack))
        .await
        .expect("a CONNACK arrives")
        .unwrap();
    assert_eq!(connack, [0x20, 0x02, 0x00, 0x00]);
    let mut publish = vec![0x00, 0x01, b'w'];
    publish.extend(std::iter::repeat_n(b'a', 100_000));
    let publish = packet(0x30, &publish);
    for _ in 0..6 {
        stream.write_all(&publish).await.unwrap();
    }
    stream.flush().await.unwrap();
}

/// Send SUBSCRIBEs, never reading, until the stream stops taking bytes for half a second; how
/// many bytes it took in all.
async fn subscribe_until_backpressured<S: AsyncWrite + Unpin>(stream: &mut S) -> usize {
    let mut pushed = 0;
    let mut packet_id = 1u16;
    let mut pending = subscribe_packet(packet_id);
    let mut offset = 0;
    while pushed < FLOOD_CAP {
        match tokio::time::timeout(Duration::from_millis(500), stream.write(&pending[offset..]))
            .await
        {
            Ok(Ok(n)) if n > 0 => {
                pushed += n;
                offset += n;
                if offset == pending.len() {
                    packet_id = packet_id.wrapping_add(1).max(1);
                    pending = subscribe_packet(packet_id);
                    offset = 0;
                }
            }
            Ok(_) => panic!("the sensor closed the connection before it stopped reading"),
            Err(_) => return pushed,
        }
    }
    pushed
}

fn bounds(max_concurrent: u32) -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(30),
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 16_000_000,
        max_concurrent,
    }
}

#[tokio::test]
async fn a_peer_that_never_reads_is_held_to_a_clamped_buffer_over_plaintext() {
    let server = start(bounds(8)).await;
    let mut stream = small_buffer_client(server.plain).await;
    connect_and_warm_up(&mut stream).await;
    let pushed = subscribe_until_backpressured(&mut stream).await;
    assert!(
        pushed < BACKPRESSURE_LIMIT,
        "a plaintext peer that never reads pushed {pushed} bytes before the sensor stopped taking them"
    );
}

#[tokio::test]
async fn a_peer_that_never_reads_is_held_to_a_clamped_buffer_over_mqtts() {
    let server = start(bounds(8)).await;
    let tcp = small_buffer_client(server.tls).await;
    let mut stream = server
        .connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("client handshake");
    connect_and_warm_up(&mut stream).await;
    let pushed = subscribe_until_backpressured(&mut stream).await;
    assert!(
        pushed < BACKPRESSURE_LIMIT,
        "an MQTTS peer that never reads pushed {pushed} bytes before the sensor stopped taking them"
    );
}

/// The reply write gives up well before the idle timeout and ends the session, freeing its slot:
/// with one slot, a second client is served once the first is gone. It used to wait out the whole
/// idle timeout, its socket unread all the while.
#[tokio::test]
async fn a_reply_the_peer_never_reads_ends_the_session_before_the_idle_timeout() {
    let server = start(bounds(1)).await;
    let mut stalled = small_buffer_client(server.plain).await;
    connect_and_warm_up(&mut stalled).await;
    subscribe_until_backpressured(&mut stalled).await;

    let waited = Duration::from_secs(8);
    tokio::time::sleep(waited).await;
    let mut second = TcpStream::connect(server.plain).await.unwrap();
    second.write_all(&connect_packet()).await.unwrap();
    let mut connack = [0u8; 4];
    let served = tokio::time::timeout(Duration::from_secs(3), second.read_exact(&mut connack))
        .await
        .is_ok_and(|read| read.is_ok());
    assert!(
        served && connack == [0x20, 0x02, 0x00, 0x00],
        "the stalled session still held the only slot {waited:?} after its reply blocked (idle timeout 30 s)"
    );
    drop(stalled);
}
