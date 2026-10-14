//! The control channel while the sensor is not reading it. A LIST or STOR waits for its data
//! connection without reading the control socket, and a reply the peer never reads blocks the
//! handler in its write; what the peer sends meanwhile waits in the kernel receive queue, charged
//! to the unit's cgroup and seen by no budget. These drive a real client through both and measure
//! what it can park, over plaintext and implicit TLS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, TlsServer,
    WanResolver, server_config_from_pem,
};
use sensor_ftp::ListenerKind;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// The flood is stopped here: on an unclamped socket the kernel would take far more, and this is
/// already several times what a clamped one holds.
const FLOOD_CAP: usize = 4 * 1024 * 1024;

/// What one parked connection may push: the sensor's receive queue plus the client's own small send
/// buffer. Clamped, the sensor's queue is 32 KiB and the flood measured 36,864 bytes; unclamped,
/// the default 128 KiB receive buffer let it push 155,136 to 896,388 depending on the listener and
/// the run (loopback, `tcp_rmem` default 131072). The limit sits between with room on both sides.
const PARKED_LIMIT: usize = 96 * 1024;

struct Server {
    plain: SocketAddr,
    implicit: SocketAddr,
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
    let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (started, _handoff) = sensor_ftp::start_listeners(
        vec![
            (loopback, ListenerKind::Plain { tls: None }),
            (loopback, ListenerKind::Implicit { tls }),
        ],
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .await
    .unwrap();
    Server {
        plain: started[0].0,
        implicit: started[1].0,
        connector: TlsConnector::from(Arc::new(client)),
        handles: started.into_iter().map(|(_, h)| h).collect(),
        _dir: dir,
    }
}

/// A client socket whose own send buffer is small, so what a flood pushes is mostly what the
/// server's receive queue took.
async fn small_send_buffer_client(addr: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(4096).unwrap();
    socket.connect(addr).await.unwrap()
}

async fn read_reply<S: AsyncRead + Unpin>(reader: &mut BufReader<S>) -> String {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .expect("a reply arrives")
        .expect("read error");
    line
}

/// Grow the server's receive buffer the way the reported attack did (pipelined long lines the
/// sensor reads and answers at once, which receive autotuning rewards), then ask for a passive
/// listing and leave its data connection unopened, so the sensor waits in accept and stops
/// reading the control socket.
async fn park_in_list<S: AsyncRead + AsyncWrite + Unpin>(reader: &mut BufReader<S>) {
    let banner = read_reply(reader).await;
    assert!(banner.starts_with("220"), "banner: {banner}");
    let mut junk = vec![b'A'; 8000];
    junk.extend_from_slice(b"\r\n");
    let lines = 100;
    let mut pipelined = Vec::with_capacity(junk.len() * lines);
    for _ in 0..lines {
        pipelined.extend_from_slice(&junk);
    }
    reader.get_mut().write_all(&pipelined).await.unwrap();
    reader.get_mut().flush().await.unwrap();
    for _ in 0..lines {
        let reply = read_reply(reader).await;
        assert!(reply.starts_with("500"), "junk reply: {reply}");
    }
    reader.get_mut().write_all(b"PASV\r\n").await.unwrap();
    reader.get_mut().flush().await.unwrap();
    let reply = read_reply(reader).await;
    assert!(reply.starts_with("227"), "PASV reply: {reply}");
    reader.get_mut().write_all(b"LIST\r\n").await.unwrap();
    reader.get_mut().flush().await.unwrap();
    let reply = read_reply(reader).await;
    assert!(reply.starts_with("150"), "LIST reply: {reply}");
}

/// Write raw bytes until the socket stops taking them for half a second; what it took.
async fn flood(tcp: &mut TcpStream) -> usize {
    let chunk = [b'x'; 4096];
    let mut pushed = 0;
    while pushed < FLOOD_CAP {
        match tokio::time::timeout(Duration::from_millis(500), tcp.write(&chunk)).await {
            Ok(Ok(n)) if n > 0 => pushed += n,
            _ => break,
        }
    }
    pushed
}

fn parked_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(10),
        // The LIST waits this long for its data connection: long enough to measure the flood.
        idle_timeout: Duration::from_secs(20),
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 5_000_000,
        max_concurrent: 8,
    }
}

#[tokio::test]
async fn a_peer_parks_only_a_clamped_buffer_while_a_plain_list_waits() {
    let server = start(parked_bounds()).await;
    let mut reader = BufReader::new(small_send_buffer_client(server.plain).await);
    park_in_list(&mut reader).await;
    let pushed = flood(reader.get_mut()).await;
    assert!(
        pushed < PARKED_LIMIT,
        "a plain control connection parked {pushed} bytes while its LIST waited"
    );
}

#[tokio::test]
async fn a_peer_parks_only_a_clamped_buffer_while_an_implicit_tls_list_waits() {
    let server = start(parked_bounds()).await;
    let tcp = small_send_buffer_client(server.implicit).await;
    let tls = server
        .connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("client handshake");
    let mut reader = BufReader::new(tls);
    park_in_list(&mut reader).await;
    // The sensor is not reading, so whether the bytes are valid records does not matter; raw
    // bytes on the socket measure the kernel queue without the client's TLS buffering.
    let (mut tcp, _) = reader.into_inner().into_inner();
    let pushed = flood(&mut tcp).await;
    assert!(
        pushed < PARKED_LIMIT,
        "an implicit-TLS control connection parked {pushed} bytes while its LIST waited"
    );
}

/// A peer that never reads its replies blocks the sensor's write. The session must end at the
/// idle timeout, freeing its slot, instead of holding the slot and its parked buffers until
/// `max_duration`. With one slot, a second client is served only once the first has ended.
#[tokio::test]
async fn a_reply_the_peer_never_reads_ends_the_session_at_the_idle_timeout() {
    let idle = Duration::from_secs(2);
    let server = start(ConnectionBounds {
        read_timeout: idle,
        idle_timeout: idle,
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 5_000_000,
        max_concurrent: 1,
    })
    .await;

    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stalled = socket.connect(server.plain).await.unwrap();
    // Each three-byte line is answered with a 22-byte 500 the client never reads, until the
    // sensor's write blocks and it stops reading too, which is when this write stops completing.
    let lines = b"X\r\n".repeat(1024);
    let mut sent = 0;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), stalled.write(&lines)).await {
            Ok(Ok(n)) if n > 0 => sent += n,
            Ok(_) => panic!("the sensor closed the connection before its write blocked"),
            Err(_) => break,
        }
        assert!(
            sent < 4_000_000,
            "the sensor kept reading; its write never blocked"
        );
    }

    tokio::time::sleep(idle + Duration::from_millis(1500)).await;
    let mut second = TcpStream::connect(server.plain).await.unwrap();
    let mut banner = [0u8; 3];
    let served = tokio::time::timeout(Duration::from_secs(3), second.read_exact(&mut banner))
        .await
        .is_ok_and(|read| read.is_ok());
    assert!(
        served && &banner == b"220",
        "the stalled session still held the only slot {:?} after its write blocked",
        idle + Duration::from_millis(1500)
    );
    drop(stalled);
}
