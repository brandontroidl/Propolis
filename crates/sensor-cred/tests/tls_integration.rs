//! TLS on the cred sensor's existing plaintext ports: postgresql SSLRequest, mysql CLIENT_SSL,
//! mssql TLS-inside-TDS PRELOGIN, and the mongodb ClientHello sniff. Plus the process-level
//! fail-closed rule for PROPOLIS_CRED_TLS_CERT / PROPOLIS_CRED_TLS_KEY.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_cred::CredTls;
use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::{SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore};

const WAIT: Duration = Duration::from_secs(5);

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

/// An ephemeral server identity and a client config that trusts exactly it.
struct Pki {
    tls: CredTls,
    client: Arc<ClientConfig>,
    roots: RootCertStore,
}

fn pki() -> Pki {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let tls = CredTls::from_pem(
        cert.pem().as_bytes(),
        signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert.der().to_vec()))
        .unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    Pki {
        tls,
        client: Arc::new(client),
        roots,
    }
}

fn tls12_client(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

struct TestServer {
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(protocol: &'static str, tls: Option<CredTls>) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_cred::start_listener(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            wan_resolver,
            test_bounds(),
            protocol,
            tls,
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
            handle,
            _dir: dir,
        }
    }

    async fn events(&self) -> Vec<SensorEvent> {
        let content = tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }

    /// The first event of `signal`, polling up to 2s for the emitter to land it.
    async fn wait_event(&self, signal: &str) -> SensorEvent {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(e) = self
                .events()
                .await
                .into_iter()
                .find(|e| e.signal_type == signal)
            {
                return e;
            }
            assert!(Instant::now() < deadline, "no {signal} event");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn connection_event(&self) -> SensorEvent {
        self.wait_event(sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
            .await
    }
}

fn tls_tag(event: &SensorEvent) -> Option<&serde_json::Value> {
    event.metadata.get("tls")
}

fn username(event: &SensorEvent) -> Option<&str> {
    event.metadata.get("username").and_then(|v| v.as_str())
}

async fn send<S: AsyncWrite + Unpin>(conn: &mut S, bytes: &[u8]) {
    conn.write_all(bytes).await.unwrap();
    conn.flush().await.unwrap();
}

async fn read_exact<S: AsyncRead + Unpin>(conn: &mut S, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(WAIT, conn.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    buf
}

/// The server closes: read to EOF (or error) within the wait.
async fn assert_closed<S: AsyncRead + Unpin>(conn: &mut S) {
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(WAIT, conn.read_to_end(&mut sink))
        .await
        .expect("server did not close the connection");
}

// ---- PostgreSQL ----

const PG_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

fn pg_startup(user: &str) -> Vec<u8> {
    let mut body = 0x0003_0000i32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.extend_from_slice(b"\0\0");
    let mut msg = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    msg
}

fn pg_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![kind];
    msg.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    msg.extend_from_slice(body);
    msg
}

async fn pg_read<S: AsyncRead + Unpin>(conn: &mut S) -> (u8, Vec<u8>) {
    let head = read_exact(conn, 5).await;
    let len = i32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    (head[0], read_exact(conn, len - 4).await)
}

/// Startup, md5 password, then one simple query refused with 42501.
async fn pg_login_and_query<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut S, user: &str) {
    send(conn, &pg_startup(user)).await;
    let (kind, body) = pg_read(conn).await;
    assert_eq!(kind, b'R');
    assert_eq!(&body[..4], &5i32.to_be_bytes(), "md5 challenge");
    send(
        conn,
        &pg_message(b'p', b"md5aaaaaaaabbbbbbbbccccccccdddddddd\0"),
    )
    .await;
    loop {
        if pg_read(conn).await.0 == b'Z' {
            break;
        }
    }
    send(conn, &pg_message(b'Q', b"SELECT 1\0")).await;
    let (kind, body) = pg_read(conn).await;
    assert_eq!(kind, b'E');
    assert!(String::from_utf8_lossy(&body).contains("42501"));
    assert_eq!(pg_read(conn).await.0, b'Z');
}

#[tokio::test]
async fn pg_sslrequest_upgrades_and_login_and_query_are_tagged_tls() {
    let pki = pki();
    let srv = TestServer::start("postgresql", Some(pki.tls.clone())).await;
    let mut tcp = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut tcp, &PG_SSL_REQUEST).await;
    assert_eq!(read_exact(&mut tcp, 1).await, b"S");
    let mut conn = TlsConnector::from(pki.client.clone())
        .connect(server_name(), tcp)
        .await
        .unwrap();
    pg_login_and_query(&mut conn, "tlsuser").await;

    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("tlsuser"));
    assert_eq!(tls_tag(&login), Some(&serde_json::Value::Bool(true)));
    let command = srv.wait_event(SIGNAL_HONEYPOT_COMMAND_EXEC).await;
    assert_eq!(tls_tag(&command), Some(&serde_json::Value::Bool(true)));
    // Emitted before negotiation, so it is not claimed as TLS.
    assert_eq!(tls_tag(&srv.connection_event().await), None);
    srv.handle.abort();
}

#[tokio::test]
async fn pg_without_tls_config_answers_n_and_stays_plain() {
    let srv = TestServer::start("postgresql", None).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut conn, &PG_SSL_REQUEST).await;
    assert_eq!(read_exact(&mut conn, 1).await, b"N");
    pg_login_and_query(&mut conn, "plainuser").await;
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("plainuser"));
    assert_eq!(tls_tag(&login), None);
    srv.handle.abort();
}

#[tokio::test]
async fn pg_plaintext_after_s_is_dropped() {
    let pki = pki();
    let srv = TestServer::start("postgresql", Some(pki.tls.clone())).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut conn, &PG_SSL_REQUEST).await;
    assert_eq!(read_exact(&mut conn, 1).await, b"S");
    // A plaintext StartupMessage where the ClientHello belongs: no fallback.
    send(&mut conn, &pg_startup("sneaky")).await;
    assert_closed(&mut conn).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        srv.events()
            .await
            .iter()
            .all(|e| e.signal_type != SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
    );
    // The listener is unharmed.
    let mut again = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut again, &PG_SSL_REQUEST).await;
    assert_eq!(read_exact(&mut again, 1).await, b"S");
    srv.handle.abort();
}

// ---- MySQL ----

async fn mysql_read<S: AsyncRead + Unpin>(conn: &mut S) -> (u8, Vec<u8>) {
    let head = read_exact(conn, 4).await;
    let len = u32::from_le_bytes([head[0], head[1], head[2], 0]) as usize;
    (head[3], read_exact(conn, len).await)
}

fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = (payload.len() as u32).to_le_bytes()[..3].to_vec();
    pkt.push(seq);
    pkt.extend_from_slice(payload);
    pkt
}

/// caps(4) max_packet(4) charset(1) reserved(23): the SSLRequest, and the HandshakeResponse41
/// prefix.
fn mysql_prefix(caps: u32) -> Vec<u8> {
    let mut p = caps.to_le_bytes().to_vec();
    p.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    p.push(0x21);
    p.extend_from_slice(&[0u8; 23]);
    p
}

fn mysql_handshake_response(caps: u32, user: &str) -> Vec<u8> {
    let mut p = mysql_prefix(caps);
    p.extend_from_slice(user.as_bytes());
    p.extend_from_slice(&[0, 0]);
    p
}

/// PROTOCOL_41 | SECURE_CONNECTION, with and without CLIENT_SSL.
const MYSQL_CLIENT_CAPS: u32 = 0x0000_8200;
const MYSQL_CLIENT_SSL: u32 = 0x0000_0800;

fn greeting_caps_low(greeting: &[u8]) -> u16 {
    u16::from_le_bytes([greeting[21], greeting[22]])
}

#[tokio::test]
async fn mysql_greeting_flag_follows_config() {
    let pki = pki();
    let with = TestServer::start("mysql", Some(pki.tls.clone())).await;
    let without = TestServer::start("mysql", None).await;
    let mut a = TcpStream::connect(with.addr).await.unwrap();
    let mut b = TcpStream::connect(without.addr).await.unwrap();
    let (_, on) = mysql_read(&mut a).await;
    let (_, off) = mysql_read(&mut b).await;
    assert_ne!(greeting_caps_low(&on) & 0x0800, 0);
    assert_eq!(greeting_caps_low(&off) & 0x0800, 0);
    with.handle.abort();
    without.handle.abort();
}

#[tokio::test]
async fn mysql_ssl_request_upgrades_then_login_captured() {
    let pki = pki();
    let srv = TestServer::start("mysql", Some(pki.tls.clone())).await;
    let mut tcp = TcpStream::connect(srv.addr).await.unwrap();
    let (seq, _) = mysql_read(&mut tcp).await;
    assert_eq!(seq, 0);
    let caps = MYSQL_CLIENT_CAPS | MYSQL_CLIENT_SSL;
    send(&mut tcp, &mysql_packet(1, &mysql_prefix(caps))).await;
    let mut conn = TlsConnector::from(pki.client.clone())
        .connect(server_name(), tcp)
        .await
        .unwrap();
    send(
        &mut conn,
        &mysql_packet(2, &mysql_handshake_response(caps, "tlsuser")),
    )
    .await;
    let (seq, ok) = mysql_read(&mut conn).await;
    assert_eq!(seq, 3);
    assert_eq!(ok[0], 0x00);

    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("tlsuser"));
    assert_eq!(tls_tag(&login), Some(&serde_json::Value::Bool(true)));
    assert_eq!(tls_tag(&srv.connection_event().await), None);
    srv.handle.abort();
}

#[tokio::test]
async fn mysql_client_ignoring_ssl_still_works_plain() {
    let pki = pki();
    let srv = TestServer::start("mysql", Some(pki.tls.clone())).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    let _ = mysql_read(&mut conn).await;
    send(
        &mut conn,
        &mysql_packet(1, &mysql_handshake_response(MYSQL_CLIENT_CAPS, "plainuser")),
    )
    .await;
    let (seq, ok) = mysql_read(&mut conn).await;
    assert_eq!(seq, 2);
    assert_eq!(ok[0], 0x00);
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("plainuser"));
    assert_eq!(tls_tag(&login), None);
    srv.handle.abort();
}

// ---- MSSQL ----
//
// The client side is a sans-IO rustls ClientConnection framed by hand, independent of the
// server's TdsTlsAdapter, so the adapter is checked against a separate implementation.

fn tds_packet(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![kind, 0x01];
    pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 1, 0]);
    pkt.extend_from_slice(payload);
    pkt
}

async fn read_tds(conn: &mut TcpStream) -> (u8, Vec<u8>) {
    let head = read_exact(conn, 8).await;
    let total = u16::from_be_bytes([head[2], head[3]]) as usize;
    (head[0], read_exact(conn, total - 8).await)
}

/// Client PRELOGIN with VERSION and ENCRYPTION options.
fn tds_prelogin(encryption: u8) -> Vec<u8> {
    let mut p = vec![0x00, 0x00, 0x0B, 0x00, 0x06];
    p.extend_from_slice(&[0x01, 0x00, 0x11, 0x00, 0x01]);
    p.push(0xFF);
    p.extend_from_slice(&[15, 0, 0, 1, 0, 0]);
    p.push(encryption);
    tds_packet(0x12, &p)
}

/// The ENCRYPTION byte of a server PRELOGIN response payload, walked here rather than imported.
fn reply_encryption(payload: &[u8]) -> Option<u8> {
    let mut i = 0;
    while *payload.get(i)? != 0xFF {
        let h = payload.get(i..i + 5)?;
        if h[0] == 0x01 {
            return payload
                .get(u16::from_be_bytes([h[1], h[2]]) as usize)
                .copied();
        }
        i += 5;
    }
    None
}

/// Login7 with `user` at offset 94 (UTF-16LE).
fn login7(user: &str) -> Vec<u8> {
    let mut l = vec![0u8; 200];
    l[0..4].copy_from_slice(&200u32.to_le_bytes());
    l[4..8].copy_from_slice(&0x7400_0004u32.to_le_bytes());
    l[48..50].copy_from_slice(&94u16.to_le_bytes());
    let units: Vec<u16> = user.encode_utf16().collect();
    l[50..52].copy_from_slice(&(units.len() as u16).to_le_bytes());
    for (i, u) in units.iter().enumerate() {
        l[94 + 2 * i..96 + 2 * i].copy_from_slice(&u.to_le_bytes());
    }
    l
}

async fn mssql_prelogin(srv: &TestServer, encryption: u8) -> (TcpStream, Option<u8>) {
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut conn, &tds_prelogin(encryption)).await;
    let (kind, payload) = read_tds(&mut conn).await;
    assert_eq!(kind, 0x04);
    (conn, reply_encryption(&payload))
}

/// Run the client handshake with every TLS flight carried as TDS PRELOGIN packet data.
async fn tls_over_tds(conn: &mut TcpStream, config: Arc<ClientConfig>) -> ClientConnection {
    let mut tls = ClientConnection::new(config, server_name()).unwrap();
    loop {
        // Drain writes before checking is_handshaking, so the TLS 1.3 client Finished leaves
        // framed.
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out).unwrap();
            send(conn, &tds_packet(0x12, &out)).await;
        }
        if !tls.is_handshaking() {
            return tls;
        }
        let (kind, payload) = read_tds(conn).await;
        assert_eq!(
            kind, 0x12,
            "handshake flight must arrive in a PRELOGIN packet"
        );
        let mut rest = &payload[..];
        while !rest.is_empty() {
            tls.read_tls(&mut rest).unwrap();
            tls.process_new_packets().unwrap();
        }
    }
}

/// After the handshake, TLS records flow raw: send Login7 inside TLS, return the decrypted
/// response packet.
async fn login_over_tls(conn: &mut TcpStream, tls: &mut ClientConnection, user: &str) -> Vec<u8> {
    tls.writer()
        .write_all(&tds_packet(0x10, &login7(user)))
        .unwrap();
    let mut out = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut out).unwrap();
    }
    send(conn, &out).await;

    let mut plain = Vec::new();
    let deadline = Instant::now() + WAIT;
    loop {
        if plain.len() >= 8 {
            let total = u16::from_be_bytes([plain[2], plain[3]]) as usize;
            if plain.len() >= total {
                return plain;
            }
        }
        assert!(Instant::now() < deadline, "no LOGINACK over tls");
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(WAIT, conn.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(n, 0, "server closed before LOGINACK");
        let mut rest = &chunk[..n];
        while !rest.is_empty() {
            tls.read_tls(&mut rest).unwrap();
            tls.process_new_packets().unwrap();
        }
        let mut buf = [0u8; 4096];
        loop {
            match tls.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plain.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("tls read: {e}"),
            }
        }
    }
}

#[tokio::test]
async fn mssql_prelogin_reply_follows_the_table() {
    let pki = pki();
    let srv = TestServer::start("mssql", Some(pki.tls.clone())).await;
    for (client, expected) in [
        (0x00, None),
        (0x01, Some(0x01)),
        (0x03, Some(0x01)),
        (0x02, Some(0x02)),
    ] {
        let (_conn, reply) = mssql_prelogin(&srv, client).await;
        assert_eq!(reply, expected, "client ENCRYPTION {client:#04x}");
    }
    srv.handle.abort();
}

/// The PRELOGIN response the sensor sent before TLS existed: VERSION only, no ENCRYPTION option.
const PRE_TLS_PRELOGIN_RESPONSE: [u8; 20] = [
    0x04, 0x01, 0x00, 0x14, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0xFF, 15, 0, 16,
    57, 0, 0,
];

/// A client offering ENCRYPT_OFF to a TLS-enabled node gets the pre-TLS reply byte for byte and
/// a plaintext session, so a scanner that cannot do TLS still hands over its Login7.
#[tokio::test]
async fn mssql_encrypt_off_client_gets_the_pre_tls_reply_and_stays_plain() {
    let pki = pki();
    let srv = TestServer::start("mssql", Some(pki.tls.clone())).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut conn, &tds_prelogin(0x00)).await;
    let reply = read_exact(&mut conn, PRE_TLS_PRELOGIN_RESPONSE.len()).await;
    assert_eq!(reply, PRE_TLS_PRELOGIN_RESPONSE);
    mssql_plain_login(&mut conn, "offuser").await;
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("offuser"));
    assert_eq!(tls_tag(&login), None);
    srv.handle.abort();
}

async fn mssql_login_over_tls(client: Arc<ClientConfig>, tls: CredTls) {
    let srv = TestServer::start("mssql", Some(tls)).await;
    let (mut conn, reply) = mssql_prelogin(&srv, 0x01).await;
    assert_eq!(reply, Some(0x01));
    let mut tls = tls_over_tds(&mut conn, client).await;
    let response = login_over_tls(&mut conn, &mut tls, "tlsuser").await;
    assert_eq!(response[0], 0x04);
    assert_eq!(response[8], 0xAD, "LOGINACK token");

    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("tlsuser"));
    assert_eq!(tls_tag(&login), Some(&serde_json::Value::Bool(true)));
    assert_eq!(tls_tag(&srv.connection_event().await), None);
    srv.handle.abort();
}

#[tokio::test]
async fn mssql_login_over_tls13_through_tds_framing() {
    let pki = pki();
    mssql_login_over_tls(pki.client.clone(), pki.tls.clone()).await;
}

#[tokio::test]
async fn mssql_login_over_tls12_through_tds_framing() {
    let pki = pki();
    mssql_login_over_tls(tls12_client(pki.roots.clone()), pki.tls.clone()).await;
}

async fn mssql_plain_login(conn: &mut TcpStream, user: &str) {
    send(conn, &tds_packet(0x10, &login7(user))).await;
    let (kind, payload) = read_tds(conn).await;
    assert_eq!(kind, 0x04);
    assert_eq!(payload[0], 0xAD, "LOGINACK token");
}

#[tokio::test]
async fn mssql_not_sup_client_stays_plain() {
    let pki = pki();
    let srv = TestServer::start("mssql", Some(pki.tls.clone())).await;
    let (mut conn, reply) = mssql_prelogin(&srv, 0x02).await;
    assert_eq!(reply, Some(0x02));
    mssql_plain_login(&mut conn, "plainuser").await;
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("plainuser"));
    assert_eq!(tls_tag(&login), None);
    srv.handle.abort();
}

#[tokio::test]
async fn mssql_plain_login_unchanged_when_tls_disabled() {
    let srv = TestServer::start("mssql", None).await;
    let (mut conn, reply) = mssql_prelogin(&srv, 0x01).await;
    assert_eq!(reply, None, "no ENCRYPTION option without a TLS config");
    mssql_plain_login(&mut conn, "plainuser").await;
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("plainuser"));
    assert_eq!(tls_tag(&login), None);
    srv.handle.abort();
}

// ---- MongoDB: ClientHello sniff on the plaintext port ----

fn op_msg(request_id: i32, bson: &[u8]) -> Vec<u8> {
    let mut body = 0u32.to_le_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(bson);
    let mut msg = ((16 + body.len()) as i32).to_le_bytes().to_vec();
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&2013u32.to_le_bytes());
    msg.extend_from_slice(&body);
    msg
}

fn bson_doc(elements: &[u8]) -> Vec<u8> {
    let mut doc = ((elements.len() + 5) as i32).to_le_bytes().to_vec();
    doc.extend_from_slice(elements);
    doc.push(0);
    doc
}

fn bson_string(key: &str, value: &str) -> Vec<u8> {
    let mut e = vec![0x02];
    e.extend_from_slice(key.as_bytes());
    e.push(0);
    e.extend_from_slice(&((value.len() + 1) as i32).to_le_bytes());
    e.extend_from_slice(value.as_bytes());
    e.push(0);
    e
}

fn sasl_start(user: &str) -> Vec<u8> {
    let mut e = vec![0x10];
    e.extend_from_slice(b"saslStart\0");
    e.extend_from_slice(&1i32.to_le_bytes());
    e.extend_from_slice(&bson_string("mechanism", "SCRAM-SHA-1"));
    let payload = format!("n,,n={user},r=somerandomnonce");
    e.push(0x05);
    e.extend_from_slice(b"payload\0");
    e.extend_from_slice(&(payload.len() as i32).to_le_bytes());
    e.push(0);
    e.extend_from_slice(payload.as_bytes());
    e.extend_from_slice(&bson_string("$db", "admin"));
    bson_doc(&e)
}

async fn mongo_read<S: AsyncRead + Unpin>(conn: &mut S) -> Vec<u8> {
    let head = read_exact(conn, 16).await;
    let len = i32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    read_exact(conn, len - 16).await
}

async fn mongo_hello_and_auth<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut S, user: &str) {
    let hello = bson_doc(&[bson_string("isMaster", "1"), bson_string("$db", "admin")].concat());
    send(conn, &op_msg(1, &hello)).await;
    let _ = mongo_read(conn).await;
    send(conn, &op_msg(2, &sasl_start(user))).await;
    let _ = mongo_read(conn).await;
}

#[tokio::test]
async fn mongodb_tls_client_on_plain_port_is_served_over_tls() {
    let pki = pki();
    let srv = TestServer::start("mongodb", Some(pki.tls.clone())).await;
    let tcp = TcpStream::connect(srv.addr).await.unwrap();
    let mut conn = TlsConnector::from(pki.client.clone())
        .connect(server_name(), tcp)
        .await
        .unwrap();
    mongo_hello_and_auth(&mut conn, "tlsuser").await;

    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("tlsuser"));
    assert_eq!(tls_tag(&login), Some(&serde_json::Value::Bool(true)));
    // TLS is known before the session starts, so the connection event is tagged too.
    assert_eq!(
        tls_tag(&srv.connection_event().await),
        Some(&serde_json::Value::Bool(true))
    );
    srv.handle.abort();
}

#[tokio::test]
async fn mongodb_plaintext_client_still_works_when_tls_configured() {
    let pki = pki();
    let srv = TestServer::start("mongodb", Some(pki.tls.clone())).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    mongo_hello_and_auth(&mut conn, "plainuser").await;
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("plainuser"));
    assert_eq!(tls_tag(&login), None);
    assert_eq!(tls_tag(&srv.connection_event().await), None);
    srv.handle.abort();
}

/// A plaintext first message whose length's low byte is 0x16 (278 = 0x0116, so it starts
/// `16 01`) looks like a TLS record to a one-byte sniff. With TLS configured it must still be
/// served in plaintext.
#[tokio::test]
async fn mongodb_plaintext_first_message_starting_0x16_stays_plain_with_tls_configured() {
    const LEN: usize = 278;
    let hello_with_pad = |pad: usize| {
        let elements = [
            bson_string("isMaster", "1"),
            bson_string("pad", &"x".repeat(pad)),
            bson_string("$db", "admin"),
        ]
        .concat();
        op_msg(1, &bson_doc(&elements))
    };
    let pad = LEN - hello_with_pad(0).len();
    let hello = hello_with_pad(pad);
    assert_eq!(hello.len(), LEN);
    assert_eq!(&hello[..2], &[0x16, 0x01]);

    let pki = pki();
    let srv = TestServer::start("mongodb", Some(pki.tls.clone())).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    send(&mut conn, &hello).await;
    let reply = mongo_read(&mut conn).await;
    assert!(
        reply.windows(9).any(|w| w == b"ismaster\0"),
        "hello answered in plaintext"
    );
    send(&mut conn, &op_msg(2, &sasl_start("lenuser"))).await;
    let _ = mongo_read(&mut conn).await;
    let login = srv.wait_event(SIGNAL_HONEYPOT_LOGIN_ATTEMPT).await;
    assert_eq!(username(&login), Some("lenuser"));
    assert_eq!(tls_tag(&login), None);
    assert_eq!(tls_tag(&srv.connection_event().await), None);
    srv.handle.abort();
}

#[tokio::test]
async fn mongodb_tls_client_without_config_is_not_upgraded() {
    let pki = pki();
    let srv = TestServer::start("mongodb", None).await;
    let tcp = TcpStream::connect(srv.addr).await.unwrap();
    let handshake = tokio::time::timeout(
        WAIT,
        TlsConnector::from(pki.client.clone()).connect(server_name(), tcp),
    )
    .await
    .expect("plaintext path must close, not hang");
    assert!(handshake.is_err(), "no TLS without a config");
    // The ClientHello went down the plaintext path: an untagged connection event, no login.
    assert_eq!(tls_tag(&srv.connection_event().await), None);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        srv.events()
            .await
            .iter()
            .all(|e| e.signal_type != SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
    );
    srv.handle.abort();
}

// ---- Process-level: fail-closed config ----

const CERT_VAR: &str = "PROPOLIS_CRED_TLS_CERT";
const KEY_VAR: &str = "PROPOLIS_CRED_TLS_KEY";

fn sensor(log_dir: &std::path::Path, pg_bind: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sensor-cred"));
    cmd.env_clear()
        .env("PROPOLIS_CRED_PG_BIND", pg_bind)
        .env("PROPOLIS_CRED_LOG_DIR", log_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd
}

/// Exit status within 5s; a child still running is killed and reported as `None`.
fn exit_code(mut cmd: std::process::Command) -> Option<i32> {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn cred_refuses_to_start_when_cert_and_key_are_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = sensor(dir.path(), "127.0.0.1:0");
    cmd.env(CERT_VAR, dir.path().join("missing.crt"))
        .env(KEY_VAR, dir.path().join("missing.key"));
    assert_eq!(exit_code(cmd), Some(1));
}

#[test]
fn cred_refuses_to_start_with_only_one_tls_var() {
    let pki_dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = pki_dir.path().join("cred.crt");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    let mut cmd = sensor(pki_dir.path(), "127.0.0.1:0");
    cmd.env(CERT_VAR, &cert_path);
    assert_eq!(exit_code(cmd), Some(1));
    // A blank partner is unset, so it does not complete the pair.
    let mut cmd = sensor(pki_dir.path(), "127.0.0.1:0");
    cmd.env(CERT_VAR, &cert_path).env(KEY_VAR, " ");
    assert_eq!(exit_code(cmd), Some(1));
}

/// Blank or whitespace-only cert and key vars read as unset (the rule every TLS sensor shares):
/// the plaintext sensor starts and keeps running.
#[test]
fn cred_starts_in_plaintext_when_both_tls_vars_are_blank() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = sensor(dir.path(), "127.0.0.1:0");
    cmd.env(CERT_VAR, "").env(KEY_VAR, " \t");
    let mut child = cmd.spawn().unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let still_running = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        still_running,
        "blank TLS vars must read as unset, not refuse"
    );
}

/// A cert or key variable that is set but not UTF-8 is a configuration error, not "unset": with
/// the other variable absent, treating it as unset would start the sensor in plaintext.
#[test]
fn cred_refuses_to_start_when_a_tls_var_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;

    for var in [CERT_VAR, KEY_VAR] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = sensor(dir.path(), "127.0.0.1:0");
        cmd.env(
            var,
            std::ffi::OsStr::from_bytes(b"/etc/propolis/tls/\xff.pem"),
        );
        assert_eq!(exit_code(cmd), Some(1), "{var} not UTF-8");
    }
}

/// The pass branch through the binary: a valid pair loads, the plaintext port binds, and main
/// hands the config to the listener (an SSLRequest is answered `S`).
#[test]
fn cred_starts_with_a_valid_pair_and_answers_s() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("cred.crt"), dir.path().join("cred.key"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let mut cmd = sensor(dir.path(), &addr);
    cmd.env(CERT_VAR, &cert_path).env(KEY_VAR, &key_path);
    let mut child = cmd.spawn().unwrap();

    let deadline = Instant::now() + WAIT;
    let answer = loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("sensor exited: {status}");
        }
        if let Ok(mut conn) = std::net::TcpStream::connect(&addr) {
            conn.set_read_timeout(Some(WAIT)).unwrap();
            conn.write_all(&PG_SSL_REQUEST).unwrap();
            let mut answer = [0u8; 1];
            conn.read_exact(&mut answer).unwrap();
            break answer;
        }
        assert!(Instant::now() < deadline, "sensor never listened");
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(&answer, b"S");
}
