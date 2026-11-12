//! The HTTP sensor under the session accounting allocator, as its binary runs: what a connection
//! holds is charged to its session and stays within the share the default pool gives every
//! session at once, a header block of empty lines included, and a session the pool asks to let
//! go is ended while it waits for its peer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, server_config_from_pem};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

/// What each session may hold when every one the binary admits by default holds it at once:
/// the pool over 1,024 sessions (`DEFAULT_MAX_CONCURRENT` 512 on each of the two listeners).
const DEFAULT_FLOOR: u64 = sensor_http::SESSION_MEMORY_POOL_BYTES / 1024;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration: Duration::from_secs(120),
        max_captured_bytes: 5_000_000,
        max_concurrent: 64,
    }
}

/// The audit's request: a declared megabyte, 5,400 lone `:` lines, then one body byte, so the
/// connection is held in the body drain with its header block read.
fn flood() -> Vec<u8> {
    let mut request = b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n".to_vec();
    request.extend(b":\r\n".repeat(5400));
    request.extend_from_slice(b"\r\nA");
    request
}

/// The most a request can make a connection hold: a header block filled to its cap by one
/// cookie, and a body past the capture cap, still being drained.
fn largest() -> Vec<u8> {
    let mut request =
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\nCookie: c=".to_vec();
    request.resize(16 * 1024 - 4, b'c');
    request.extend_from_slice(b"\r\n\r\n");
    request.extend(std::iter::repeat_n(b'A', 70_000));
    request
}

/// Whether the server closes the connection within `within` while the client sends nothing.
async fn closes_while_idle<S: AsyncRead + Unpin>(conn: &mut S, within: Duration) -> bool {
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(Ok(0) | Err(_)) =
            tokio::time::timeout(Duration::from_millis(100), conn.read(&mut chunk)).await
        {
            return true;
        }
    }
    false
}

const CHUNK: u64 = 64 * 1024;

/// Wait until the sessions that ended have given their room back, so the next one is alone. A
/// few hundred bytes that ended sessions left to the runtime stay counted; a session still
/// running holds at least a chunk.
async fn pool_drained() {
    let deadline = Instant::now() + Duration::from_secs(5);
    while session_memory::pool_used() >= CHUNK {
        assert!(
            Instant::now() < deadline,
            "the pool keeps {} bytes",
            session_memory::pool_used()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Send `request` on a connection opened after the pool drained, and hold it: the pool, sized so
/// this one session has the default share and no more, must not ask it to let go.
async fn held_within_the_default_share<S>(mut conn: S, request: &[u8], what: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    session_memory::configure(DEFAULT_FLOOR, 1).unwrap();
    conn.write_all(request).await.unwrap();
    assert!(
        !closes_while_idle(&mut conn, Duration::from_secs(1)).await,
        "{what}: a session holding it was asked to let go, so it holds more than {DEFAULT_FLOOR}"
    );
    assert!(
        session_memory::pool_used() > 0,
        "{what}: the connection's memory is charged to its session"
    );
    drop(conn);
}

fn tls_pair() -> (TlsServer, TlsConnector) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server = TlsServer::from_config(
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
    let client = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    (server, client)
}

/// A session over its share while the pool is short is asked to let go, and one waiting in the
/// body drain for its peer's next byte is ended then, not at its idle timeout. It holds the most
/// of a pool shrunk to what it holds plus two chunks, with the smallest floor the pool allows,
/// so small newcomers run the pool out and it is the one over its share.
async fn quiet_holder_is_ended(addr: SocketAddr) {
    pool_drained().await;
    session_memory::configure(u64::MAX / 2, 16).unwrap();
    let mut holder = TcpStream::connect(addr).await.unwrap();
    holder.write_all(&largest()).await.unwrap();
    assert!(!closes_while_idle(&mut holder, Duration::from_millis(500)).await);
    let ceiling = session_memory::pool_used() + 2 * CHUNK;
    session_memory::configure(ceiling, (ceiling / CHUNK) as u32).unwrap();
    let mut newcomers = Vec::new();
    let mut ended = false;
    for _ in 0..8 {
        let mut newcomer = TcpStream::connect(addr).await.unwrap();
        newcomer
            .write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nA")
            .await
            .unwrap();
        newcomers.push(newcomer);
        if closes_while_idle(&mut holder, Duration::from_millis(400)).await {
            ended = true;
            break;
        }
    }
    assert!(ended, "the quiet holder was ended for the newcomers");
    drop((holder, newcomers));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_holds_its_buffers_on_its_session_within_the_default_share() {
    tokio::spawn(session_memory::watchdog());
    let dir = tempfile::tempdir().unwrap();
    let (addr, plain) = sensor_http::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
    )
    .await
    .unwrap();
    let (server, client) = tls_pair();
    let (tls_addr, tls) = sensor_http::start_test_server_tls(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        server,
    )
    .await
    .unwrap();
    let name = ServerName::try_from("localhost").unwrap();

    // The order matters: the wiring is proven first, so the share checks after it cannot pass
    // only because nothing is charged.
    quiet_holder_is_ended(addr).await;

    // Before the fix the flood held one 48-byte entry per line, about 390 KiB, past the share.
    for (what, request) in [("flood", flood()), ("largest", largest())] {
        pool_drained().await;
        let conn = TcpStream::connect(addr).await.unwrap();
        held_within_the_default_share(conn, &request, what).await;
        pool_drained().await;
        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let conn = client.connect(name.clone(), tcp).await.unwrap();
        held_within_the_default_share(conn, &request, &format!("{what} over TLS")).await;
    }

    plain.abort();
    tls.abort();
}
