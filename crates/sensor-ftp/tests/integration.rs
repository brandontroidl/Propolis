use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CAPTURE_CHUNK_BYTES, CaptureHandoff, CaptureMemoryBudget, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, TlsServer, WanResolver, server_config_from_pem,
};
use sensor_ftp::ListenerKind;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    handle: JoinHandle<()>,
    handoff: Arc<CaptureHandoff>,
    budget: Arc<CaptureMemoryBudget>,
    /// Plain control listener WITH AUTH TLS honoured (only set by `start_tls`).
    tls_addr: Option<std::net::SocketAddr>,
    /// Implicit FTPS listener (only set by `start_tls`).
    implicit_addr: Option<std::net::SocketAddr>,
    connector: Option<TlsConnector>,
    extra_handles: Vec<JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

/// A fresh in-memory self-signed cert: the server side and a client that trusts exactly it. The
/// key never touches disk.
fn ephemeral_tls() -> (TlsServer, TlsConnector) {
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
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, TlsConnector::from(Arc::new(client)))
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

impl TestServer {
    async fn start() -> TestServer {
        Self::start_with_capture_budget(DEFAULT_CAPTURE_BUDGET_BYTES_256M).await
    }

    async fn start_with_capture_budget(ceiling: u64) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let budget = Arc::new(CaptureMemoryBudget::new(ceiling));
        let (addr, handle, handoff) = sensor_ftp::start_test_server_with_handoff(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            wan_resolver,
            test_bounds(),
            "test".to_string(),
            dir.path().join("outbox"),
            budget.clone(),
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
            spool_dir,
            handle,
            handoff,
            budget,
            tls_addr: None,
            implicit_addr: None,
            connector: None,
            extra_handles: Vec::new(),
            _dir: dir,
        }
    }

    /// A plain listener that honours AUTH TLS plus an implicit-FTPS listener, one cert, one
    /// shared hand-off and budget.
    async fn start_tls() -> TestServer {
        Self::start_tls_with_bounds(test_bounds()).await
    }

    async fn start_tls_with_bounds(bounds: ConnectionBounds) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let budget = Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M));
        let (server, connector) = ephemeral_tls();
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (mut started, handoff) = sensor_ftp::start_listeners(
            vec![
                (
                    loopback,
                    ListenerKind::Plain {
                        tls: Some(server.clone()),
                    },
                ),
                (loopback, ListenerKind::Implicit { tls: server }),
            ],
            log_path.clone(),
            spool_dir.clone(),
            wan_resolver,
            bounds,
            "test".to_string(),
            dir.path().join("outbox"),
            budget.clone(),
        )
        .await
        .unwrap();
        let (implicit_addr, implicit_handle) = started.remove(1);
        let (addr, handle) = started.remove(0);
        TestServer {
            addr,
            log_path,
            spool_dir,
            handle,
            handoff,
            budget,
            tls_addr: Some(addr),
            implicit_addr: Some(implicit_addr),
            connector: Some(connector),
            extra_handles: vec![implicit_handle],
            _dir: dir,
        }
    }

    fn stop(self) {
        self.handle.abort();
        for h in &self.extra_handles {
            h.abort();
        }
    }

    /// Waits for `n` `honeypot_malware_upload` lines (see `wait_for_upload_event`).
    async fn wait_for_upload_events(&self, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let seen = self
                .events()
                .await
                .iter()
                .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
                .count();
            if seen >= n {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {n} upload event(s), saw {seen}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn uploads(&self) -> Vec<sensor_wire::SensorEvent> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .collect()
    }

    async fn events(&self) -> Vec<sensor_wire::SensorEvent> {
        let content = tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }

    /// Poll the event log for the capture's own `honeypot_malware_upload` line. The hand-off
    /// worker writes the spooled body first and appends the event only after the outbox manifest
    /// row is fsynced (`handoff::process_job`), and it runs off the connection's response path, so
    /// the 226/426 reply the caller has already read says nothing about whether the event exists
    /// yet. A fixed sleep only guesses at that gap; this waits for the artifact the caller is
    /// about to assert on. Callers asserting the event is ABSENT must keep a fixed wait instead,
    /// since no artifact ever arrives to poll for.
    async fn wait_for_upload_event(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let content = tokio::fs::read_to_string(&self.log_path)
                .await
                .unwrap_or_default();
            let recorded = content.lines().any(|line| {
                serde_json::from_str::<sensor_wire::SensorEvent>(line)
                    .is_ok_and(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            });
            if recorded {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for a honeypot_malware_upload event in {:?}",
                self.log_path
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

struct FtpClient<S> {
    reader: BufReader<S>,
}

impl FtpClient<TcpStream> {
    async fn connect(addr: std::net::SocketAddr) -> FtpClient<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut client = FtpClient {
            reader: BufReader::new(stream),
        };
        let banner = client.read_reply().await;
        assert!(banner.starts_with("220"), "banner: {banner}");
        client
    }

    /// Handshake over the plain control socket after a 234. `into_inner` is safe here: the
    /// server sends nothing between its 234 and our ClientHello.
    async fn into_tls(self, connector: &TlsConnector) -> FtpClient<TlsStream<TcpStream>> {
        let tcp = self.reader.into_inner();
        let tls = connector
            .connect(localhost(), tcp)
            .await
            .expect("client handshake");
        FtpClient {
            reader: BufReader::new(tls),
        }
    }

    async fn connect_implicit(
        addr: std::net::SocketAddr,
        connector: &TlsConnector,
    ) -> FtpClient<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(localhost(), tcp)
            .await
            .expect("client handshake");
        let mut client = FtpClient {
            reader: BufReader::new(tls),
        };
        let banner = client.read_reply().await;
        assert!(banner.starts_with("220"), "banner: {banner}");
        client
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> FtpClient<S> {
    async fn read_reply(&mut self) -> String {
        self.read_reply_within(Duration::from_secs(3)).await
    }

    async fn read_reply_within(&mut self, wait: Duration) -> String {
        let mut line = String::new();
        tokio::time::timeout(wait, self.reader.read_line(&mut line))
            .await
            .expect("timeout reading reply")
            .expect("read error");
        line
    }

    async fn send(&mut self, cmd: &str) -> String {
        self.reader
            .get_mut()
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        self.reader.get_mut().flush().await.unwrap();
        self.read_reply().await
    }

    async fn login(&mut self, user: &str, pass: &str) {
        let r = self.send(&format!("USER {user}")).await;
        assert!(r.starts_with("331"), "USER reply: {r}");
        let r = self.send(&format!("PASS {pass}")).await;
        assert!(r.starts_with("230"), "PASS reply: {r}");
    }

    async fn pasv(&mut self) -> std::net::SocketAddr {
        let r = self.send("PASV").await;
        assert!(r.starts_with("227"), "PASV reply: {r}");
        parse_pasv_addr(&r)
    }
}

fn parse_pasv_addr(reply: &str) -> std::net::SocketAddr {
    let start = reply.find('(').unwrap() + 1;
    let end = reply.find(')').unwrap();
    let nums: Vec<u8> = reply[start..end]
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    let ip = std::net::Ipv4Addr::new(nums[0], nums[1], nums[2], nums[3]);
    let port = (nums[4] as u16) << 8 | nums[5] as u16;
    std::net::SocketAddr::new(ip.into(), port)
}

#[tokio::test]
async fn login_and_credential_capture() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("admin", "secret123").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert!(login.authenticated);
    assert_eq!(
        login.metadata.get("username").and_then(|v| v.as_str()),
        Some("admin")
    );
    assert!(
        login.metadata.get("password").is_none(),
        "password must never appear in events"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn lowercase_and_mixed_case_commands_are_accepted_like_vsftpd() {
    // RFC 959 commands are case-insensitive and real vsftpd uppercases the verb internally. Before
    // the fix a lowercase `syst`/`user` fell through to "500 Unknown command" - a one-command
    // honeypot tell distinguishing this from the vsftpd it advertises.
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    assert!(
        client.send("syst").await.starts_with("215"),
        "lowercase syst must return 215 like vsftpd"
    );
    assert!(
        client.send("user anonymous").await.starts_with("331"),
        "lowercase user must be accepted"
    );
    assert!(
        client.send("FeAt").await.starts_with("211"),
        "mixed-case feat must be accepted"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn stor_upload_captured_in_spool() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let data_addr = client.pasv().await;
    client
        .reader
        .get_mut()
        .write_all(b"STOR /tmp/evil.bin\r\n")
        .await
        .unwrap();
    let r = client.read_reply().await;
    assert!(r.starts_with("150"), "STOR 150: {r}");

    let body = b"MZ-fake-malware-payload-bytes";
    let mut data = TcpStream::connect(data_addr).await.unwrap();
    data.write_all(body).await.unwrap();
    drop(data);

    let r = client.read_reply().await;
    assert!(r.starts_with("226"), "STOR 226: {r}");

    srv.wait_for_upload_event().await;
    let events = srv.events().await;
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .unwrap();
    let sample = upload.sample.as_ref().unwrap();
    assert_eq!(sample.size, body.len() as u64);
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(upload.metadata["wire_size"], body.len() as u64);
    assert_eq!(upload.metadata["complete"], true);
    assert_eq!(upload.metadata["end_reason"], "transfer_complete");

    use sha2::{Digest, Sha256};
    let expected_hash = sensor_framework::to_hex_bounded(&Sha256::digest(body), 32);
    assert_eq!(sample.sha256, expected_hash);

    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, body);
    srv.handle.abort();
}

/// A STOR past the 10 MB cap keeps only the prefix. The event must say so - `truncated` plus the
/// real `wire_size` - or a scan of the prefix reads as a verdict on the whole upload.
#[tokio::test]
async fn stor_upload_past_the_cap_is_marked_truncated() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let data_addr = client.pasv().await;
    client
        .reader
        .get_mut()
        .write_all(b"STOR /tmp/huge.bin\r\n")
        .await
        .unwrap();
    let r = client.read_reply().await;
    assert!(r.starts_with("150"), "STOR 150: {r}");

    const CAP: usize = 10_000_000;
    let sent = CAP + 4096;
    let mut data = TcpStream::connect(data_addr).await.unwrap();
    data.write_all(&vec![0xABu8; sent]).await.unwrap();
    drop(data);

    let r = client.read_reply().await;
    assert!(r.starts_with("226"), "STOR 226: {r}");

    srv.wait_for_upload_event().await;
    let events = srv.events().await;
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("the capped upload must still be captured and emitted");
    let sample = upload.sample.as_ref().unwrap();
    assert_eq!(sample.size, CAP as u64, "only the prefix is retained");
    assert_eq!(upload.metadata["truncated"], true);
    assert_eq!(upload.metadata["wire_size"], sent as u64);
    srv.handle.abort();
}

/// Opens a passive data connection and issues STOR, returning the live data stream once the 150
/// has been read. The caller decides when (and whether) to close it.
async fn begin_stor(client: &mut FtpClient<TcpStream>, name: &str) -> TcpStream {
    let data_addr = client.pasv().await;
    let r = client.send(&format!("STOR {name}")).await;
    assert!(r.starts_with("150"), "STOR 150: {r}");
    TcpStream::connect(data_addr).await.unwrap()
}

/// A whole upload on a fresh connection. The write result is ignored: once the sensor stops
/// reading (budget exhausted) it closes the data connection under the sender.
async fn stor_whole(srv: &TestServer, name: &str, body: &[u8]) -> String {
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let mut data = begin_stor(&mut client, name).await;
    let _ = data.write_all(body).await;
    drop(data);
    client.read_reply().await
}

async fn wait_for_budget_current(srv: &TestServer, bytes: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while srv.budget.current_bytes() != bytes {
        assert!(
            std::time::Instant::now() < deadline,
            "budget current stayed at {} (wanted {bytes})",
            srv.budget.current_bytes()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn capture_within_budget_is_complete_and_the_budget_returns_to_zero_after_spooling() {
    let srv = TestServer::start_with_capture_budget(4 * CAPTURE_CHUNK_BYTES).await;
    let body = vec![0x5Au8; 100_000];
    let r = stor_whole(&srv, "/tmp/ok.bin", &body).await;
    assert!(r.starts_with("226"), "{r}");
    srv.wait_for_upload_event().await;

    let uploads = srv.uploads().await;
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0].sample.as_ref().unwrap().size, body.len() as u64);
    assert_eq!(uploads[0].metadata["complete"], true);
    assert_eq!(uploads[0].metadata["truncated"], false);
    assert_eq!(uploads[0].metadata["end_reason"], "transfer_complete");
    // 100_000 bytes held two 64 KiB chunks while buffered; the worker refunded them once spooled.
    assert_eq!(srv.budget.high_water_bytes(), 2 * CAPTURE_CHUNK_BYTES);
    assert_eq!(srv.budget.current_bytes(), 0);
    assert_eq!(srv.handoff.truncated_capture_count(), 0);
    srv.handle.abort();
}

#[tokio::test]
async fn capture_that_exhausts_the_budget_keeps_its_prefix_and_later_uploads_still_work() {
    let srv = TestServer::start_with_capture_budget(2 * CAPTURE_CHUNK_BYTES).await;
    let kept = 2 * CAPTURE_CHUNK_BYTES as usize;
    let body: Vec<u8> = (0..300_000usize).map(|i| (i % 251) as u8).collect();
    let r = stor_whole(&srv, "/tmp/big.bin", &body).await;
    assert!(
        r.starts_with("451"),
        "budget exhaustion ends the STOR like a full disk: {r}"
    );
    srv.wait_for_upload_event().await;

    let uploads = srv.uploads().await;
    let sample = uploads[0].sample.as_ref().unwrap();
    assert_eq!(sample.size, kept as u64, "the prefix that fit is retained");
    assert_eq!(uploads[0].metadata["truncated"], true);
    assert_eq!(uploads[0].metadata["complete"], false);
    assert_eq!(uploads[0].metadata["end_reason"], "capture_memory_budget");
    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(
        on_disk,
        body[..kept],
        "the stored bytes are exactly the leading prefix"
    );
    assert_eq!(srv.handoff.truncated_capture_count(), 1);
    wait_for_budget_current(&srv, 0).await;

    // The room freed by spooling the first capture serves the next one in full.
    let r = stor_whole(&srv, "/tmp/small.bin", b"MZ-small").await;
    assert!(r.starts_with("226"), "{r}");
    srv.wait_for_upload_events(2).await;
    let second = &srv.uploads().await[1];
    assert_eq!(second.sample.as_ref().unwrap().size, 8);
    assert_eq!(second.metadata["complete"], true);
    srv.handle.abort();
}

#[tokio::test]
async fn concurrent_captures_share_one_ceiling() {
    let ceiling = 3 * CAPTURE_CHUNK_BYTES;
    let srv = TestServer::start_with_capture_budget(ceiling).await;

    // Capture A takes one chunk and stays open.
    let mut a_ctl = FtpClient::connect(srv.addr).await;
    a_ctl.login("root", "toor").await;
    let mut a_data = begin_stor(&mut a_ctl, "/tmp/a.bin").await;
    a_data.write_all(&[1u8; 60_000]).await.unwrap();
    wait_for_budget_current(&srv, CAPTURE_CHUNK_BYTES).await;

    // Capture B wants three chunks but only two remain.
    let mut b_ctl = FtpClient::connect(srv.addr).await;
    b_ctl.login("root", "toor").await;
    let mut b_data = begin_stor(&mut b_ctl, "/tmp/b.bin").await;
    let _ = b_data.write_all(&vec![2u8; 150_000]).await;
    let r = b_ctl.read_reply().await;
    assert!(r.starts_with("451"), "{r}");
    drop(b_data);
    assert_eq!(
        srv.budget.high_water_bytes(),
        ceiling,
        "reached, never past, the ceiling"
    );

    drop(a_data);
    let r = a_ctl.read_reply().await;
    assert!(r.starts_with("226"), "{r}");
    srv.wait_for_upload_events(2).await;

    let uploads = srv.uploads().await;
    let mut sizes: Vec<u64> = uploads
        .iter()
        .map(|u| u.sample.as_ref().unwrap().size)
        .collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![60_000, 2 * CAPTURE_CHUNK_BYTES]);
    assert!(srv.budget.high_water_bytes() <= ceiling);
    wait_for_budget_current(&srv, 0).await;
    srv.handle.abort();
}

#[tokio::test]
async fn capture_that_gets_zero_bytes_submits_no_sample_and_counts_a_refusal() {
    let srv = TestServer::start_with_capture_budget(CAPTURE_CHUNK_BYTES).await;

    let mut a_ctl = FtpClient::connect(srv.addr).await;
    a_ctl.login("root", "toor").await;
    let mut a_data = begin_stor(&mut a_ctl, "/tmp/a.bin").await;
    a_data.write_all(b"MZ-holder").await.unwrap();
    wait_for_budget_current(&srv, CAPTURE_CHUNK_BYTES).await;

    // The budget is full: B's first byte cannot be buffered at all.
    let r = stor_whole(&srv, "/tmp/starved.bin", b"never kept").await;
    assert!(r.starts_with("451"), "{r}");
    assert_eq!(srv.handoff.refused_capture_count(), 1);
    assert_eq!(srv.handoff.truncated_capture_count(), 0);

    drop(a_data);
    let r = a_ctl.read_reply().await;
    assert!(r.starts_with("226"), "{r}");
    srv.wait_for_upload_events(1).await;
    // No artifact exists to poll for an absent event, so give a stray second one time to appear.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let uploads = srv.uploads().await;
    assert_eq!(
        uploads.len(),
        1,
        "only the holder's capture exists: {uploads:?}"
    );
    assert_eq!(uploads[0].sample.as_ref().unwrap().size, 9);
    // The starved connection still produced its ordinary connection event (holder + starved).
    assert_eq!(
        srv.events()
            .await
            .iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
            .count(),
        2
    );
    srv.handle.abort();
}

/// A STOR whose data connection never arrives has transferred nothing. vsftpd answers 425; the
/// sensor used to answer "226 Transfer complete." after its accept timed out.
#[tokio::test]
async fn stor_without_a_data_connection_is_425_not_transfer_complete() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let _ = client.pasv().await;
    let r = client.send("STOR /tmp/never.bin").await;
    assert!(r.starts_with("150"), "{r}");
    // The accept wait is the idle timeout (5 s in these bounds).
    let r = client.read_reply_within(Duration::from_secs(8)).await;
    assert!(r.starts_with("425 Failed to establish connection."), "{r}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        !events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD),
        "nothing was uploaded: {events:?}"
    );
    srv.handle.abort();
}

/// A data connection that goes quiet mid-file is a fragment, not a file: the reply is vsftpd's
/// 426 and the event says the upload is incomplete, while the fragment is still kept as evidence.
#[tokio::test]
async fn stor_that_stalls_mid_transfer_is_426_and_recorded_as_incomplete() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let data_addr = client.pasv().await;
    let r = client.send("STOR /tmp/partial.bin").await;
    assert!(r.starts_with("150"), "{r}");
    let fragment = b"MZ-first-half-of-a-payload";
    let mut data = TcpStream::connect(data_addr).await.unwrap();
    data.write_all(fragment).await.unwrap();
    // Keep the data connection open and silent past the idle timeout.
    let r = client.read_reply_within(Duration::from_secs(8)).await;
    assert!(r.starts_with("426 Failure reading network stream."), "{r}");
    drop(data);

    srv.wait_for_upload_event().await;
    let events = srv.events().await;
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("the fragment is still captured");
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "idle_timeout");
    assert_eq!(upload.metadata["wire_size"], fragment.len() as u64);
    assert_eq!(upload.sample.as_ref().unwrap().size, fragment.len() as u64);
    srv.handle.abort();
}

/// The listener's `max_duration` drops the handler mid-STOR; only the capture's destructor runs,
/// and it must say the session was cancelled rather than borrow an ending nothing observed.
#[tokio::test]
async fn stor_cut_off_by_max_duration_is_recorded_as_session_cancelled() {
    let srv = TestServer::start_tls_with_bounds(ConnectionBounds {
        idle_timeout: Duration::from_secs(20),
        max_duration: Duration::from_millis(1500),
        ..test_bounds()
    })
    .await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let data_addr = client.pasv().await;
    let r = client.send("STOR /tmp/slow.bin").await;
    assert!(r.starts_with("150"), "{r}");
    let fragment = b"MZ-a-dropper-still-arriving";
    let mut data = TcpStream::connect(data_addr).await.unwrap();
    data.write_all(fragment).await.unwrap();

    srv.wait_for_upload_event().await;
    let upload = srv.uploads().await.remove(0);
    drop(data);
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "session_cancelled");
    assert_eq!(upload.metadata["wire_size"], fragment.len() as u64);
    srv.stop();
}

/// LIST with no data connection sent nothing; "Directory send OK" claimed otherwise.
#[tokio::test]
async fn list_without_a_data_connection_is_425() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "toor").await;
    let _ = client.pasv().await;
    let r = client.send("LIST").await;
    assert!(r.starts_with("150"), "{r}");
    let r = client.read_reply_within(Duration::from_secs(8)).await;
    assert!(r.starts_with("425 Failed to establish connection."), "{r}");
    srv.handle.abort();
}

#[tokio::test]
async fn retr_refused() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "x").await;
    let r = client.send("RETR /etc/passwd").await;
    assert!(r.starts_with("550"), "RETR must be refused: {r}");
    srv.handle.abort();
}

#[tokio::test]
async fn port_refused() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "x").await;
    let r = client.send("PORT 10,0,0,1,4,1").await;
    assert!(r.starts_with("502"), "PORT must be refused: {r}");
    let r = client.send("EPRT |1|10.0.0.1|1025|").await;
    assert!(r.starts_with("502"), "EPRT must be refused: {r}");
    srv.handle.abort();
}

#[tokio::test]
async fn protocol_label_ftp_on_all_events() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("user", "pass").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    for event in &events {
        assert_eq!(event.sensor, "ftp");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("ftp")
        );
    }
    srv.handle.abort();
}

#[test]
fn never_exec_static_check() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for entry in walk_rs(&src_dir) {
        let content = std::fs::read_to_string(&entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found.push(entry.display().to_string());
        }
    }
    assert!(
        found.is_empty(),
        "sensor-ftp must not spawn processes: {found:?}"
    );
}

#[tokio::test]
async fn malformed_input_does_not_crash_listener() {
    let srv = TestServer::start().await;
    for seed in 0..5u8 {
        if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
            let garbage: Vec<u8> = (0..2048u32)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                .collect();
            let _ = conn.write_all(&garbage).await;
            drop(conn);
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut probe = FtpClient::connect(srv.addr).await;
    probe.login("test", "test").await;
    srv.handle.abort();
}

#[tokio::test]
async fn no_outbound_connections() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let c = count.clone();
    let task = tokio::spawn(async move {
        loop {
            if target.accept().await.is_ok() {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "x").await;
    let r = client
        .send(&format!(
            "PORT 127,0,0,1,{},{}",
            target_addr.port() >> 8,
            target_addr.port() & 0xFF
        ))
        .await;
    assert!(r.starts_with("502"));
    let r = client.send("RETR /etc/passwd").await;
    assert!(r.starts_with("550"));

    tokio::time::sleep(Duration::from_millis(300)).await;
    srv.handle.abort();
    task.abort();
    assert_eq!(
        count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor-ftp must open zero outbound connections"
    );
}

#[tokio::test]
async fn list_returns_canned_directory() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "x").await;
    let data_addr = client.pasv().await;

    client
        .reader
        .get_mut()
        .write_all(b"LIST\r\n")
        .await
        .unwrap();
    let r = client.read_reply().await;
    assert!(r.starts_with("150"), "LIST 150: {r}");

    let mut data = TcpStream::connect(data_addr).await.unwrap();
    let mut listing = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), data.read_to_string(&mut listing)).await;
    assert!(listing.contains("readme.txt"), "listing: {listing}");

    let r = client.read_reply().await;
    assert!(r.starts_with("226"), "LIST 226: {r}");
    srv.handle.abort();
}

async fn tls_data(addr: std::net::SocketAddr, connector: &TlsConnector) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    connector
        .connect(localhost(), tcp)
        .await
        .expect("data handshake")
}

/// Reads a multi-line reply (`211-` ... `211 `) into one string.
async fn read_feat<S: AsyncRead + AsyncWrite + Unpin>(client: &mut FtpClient<S>) -> String {
    client
        .reader
        .get_mut()
        .write_all(b"FEAT\r\n")
        .await
        .unwrap();
    client.reader.get_mut().flush().await.unwrap();
    let mut all = String::new();
    loop {
        let line = client.read_reply().await;
        assert!(!line.is_empty(), "connection closed mid-FEAT: {all}");
        let last = line.starts_with("211 ");
        all.push_str(&line);
        if last {
            return all;
        }
    }
}

/// Upgrades a fresh connection to the plain+AUTH TLS listener to TLS.
async fn auth_tls(srv: &TestServer) -> FtpClient<TlsStream<TcpStream>> {
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    assert_eq!(
        client.send("AUTH TLS").await,
        "234 Proceed with negotiation.\r\n"
    );
    client.into_tls(srv.connector.as_ref().unwrap()).await
}

/// TLS control channel with PBSZ 0 and PROT P done.
async fn private_session(srv: &TestServer) -> FtpClient<TlsStream<TcpStream>> {
    let mut client = auth_tls(srv).await;
    client.login("root", "x").await;
    assert!(client.send("PBSZ 0").await.starts_with("200"));
    assert!(client.send("PROT P").await.starts_with("200"));
    client
}

async fn send_only<S: AsyncRead + AsyncWrite + Unpin>(client: &mut FtpClient<S>, cmd: &str) {
    client
        .reader
        .get_mut()
        .write_all(format!("{cmd}\r\n").as_bytes())
        .await
        .unwrap();
    client.reader.get_mut().flush().await.unwrap();
}

#[tokio::test]
async fn feat_lists_tls_verbs_only_when_tls_is_configured() {
    let plain = TestServer::start().await;
    let mut client = FtpClient::connect(plain.addr).await;
    let feat = read_feat(&mut client).await;
    for verb in ["AUTH", "PBSZ", "PROT"] {
        assert!(!feat.contains(verb), "{feat}");
    }
    plain.stop();

    let srv = TestServer::start_tls().await;
    let mut client = FtpClient::connect(srv.addr).await;
    let feat = read_feat(&mut client).await;
    for verb in [" AUTH TLS\r\n", " PBSZ\r\n", " PROT\r\n"] {
        assert!(feat.contains(verb), "{feat}");
    }
    srv.stop();
}

#[tokio::test]
async fn auth_tls_without_configured_tls_is_500_unknown_command() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    for cmd in ["AUTH TLS", "PBSZ 0", "PROT P"] {
        assert_eq!(client.send(cmd).await, "500 Unknown command.\r\n", "{cmd}");
    }
    srv.stop();
}

#[tokio::test]
async fn auth_tls_upgrades_resets_login_state_and_tags_events() {
    let srv = TestServer::start_tls().await;
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    assert!(client.send("USER pre").await.starts_with("331"));
    assert_eq!(
        client.send("AUTH TLS").await,
        "234 Proceed with negotiation.\r\n"
    );
    let mut client = client.into_tls(srv.connector.as_ref().unwrap()).await;
    assert!(client.send("PASS x").await.starts_with("230"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let events = srv.events().await;
    assert!(
        events[0].metadata.get("tls").is_none(),
        "the plaintext-phase connection event carries no tls tag"
    );
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login.metadata["username"], "",
        "USER sent in cleartext is discarded"
    );
    assert_eq!(login.metadata["tls"], true);
    srv.stop();
}

#[tokio::test]
async fn auth_tls_with_pipelined_plaintext_is_refused_and_recorded() {
    let srv = TestServer::start_tls().await;
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    // ONE write, so the injected commands are buffered behind AUTH TLS. USER/PASS is chosen
    // because PASS is a command that emits a login event if it is ever interpreted: a command
    // that emits nothing would make the "never ran" assertion below vacuous.
    let injected = "USER x\r\nPASS y\r\n";
    client
        .reader
        .get_mut()
        .write_all(format!("AUTH TLS\r\n{injected}").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        client.read_reply().await,
        "504 Pipelined commands after AUTH TLS refused.\r\n"
    );
    assert_eq!(client.read_reply().await, "", "the connection is closed");

    // A late login event from a wrongly interpreted injection would land after the reply.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = srv.events().await;
    let refusal = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("refusal event");
    assert_eq!(refusal.metadata["command"], "AUTH");
    assert_eq!(refusal.metadata["starttls_refused"], "pipelined_plaintext");
    assert_eq!(refusal.metadata["pipelined_bytes"], injected.len());
    assert!(refusal.metadata.get("tls").is_none());
    assert!(
        events
            .iter()
            .all(|e| e.signal_type != sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT),
        "the injected PASS must never produce a login event"
    );
    srv.stop();
}

#[tokio::test]
async fn auth_tls_variants_and_errors() {
    let srv = TestServer::start_tls().await;
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    assert!(client.send("AUTH GSSAPI").await.starts_with("504"));
    assert!(client.send("PBSZ 0").await.starts_with("503"));
    assert!(client.send("PROT P").await.starts_with("503"));
    assert_eq!(
        client.send("AUTH TLS").await,
        "234 Proceed with negotiation.\r\n"
    );
    let mut client = client.into_tls(srv.connector.as_ref().unwrap()).await;
    assert!(
        client.send("PROT P").await.starts_with("503"),
        "PROT before PBSZ"
    );
    assert_eq!(client.send("PBSZ 0").await, "200 PBSZ set to 0.\r\n");
    assert_eq!(client.send("PROT P").await, "200 PROT now Private.\r\n");
    assert_eq!(client.send("PROT C").await, "200 PROT now Clear.\r\n");
    assert!(client.send("PROT S").await.starts_with("536"));
    assert!(client.send("PROT Z").await.starts_with("504"));
    assert!(client.send("AUTH TLS").await.starts_with("503"));

    let mut fresh = FtpClient::connect(srv.tls_addr.unwrap()).await;
    assert!(fresh.send("AUTH ssl").await.starts_with("234"));
    srv.stop();
}

#[tokio::test]
async fn implicit_ftps_990_login_and_tls_tag() {
    let srv = TestServer::start_tls().await;
    let mut client =
        FtpClient::connect_implicit(srv.implicit_addr.unwrap(), srv.connector.as_ref().unwrap())
            .await;
    client.login("root", "x").await;
    assert!(client.send("AUTH TLS").await.starts_with("503"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(login.metadata["tls"], true);
    assert!(login.metadata.get("password").is_none());
    for e in &events {
        assert_eq!(
            e.metadata["tls"], true,
            "every implicit-session event is tagged"
        );
    }
    srv.stop();
}

#[tokio::test]
async fn implicit_ftps_handshake_failure_is_silent_and_listener_survives() {
    let srv = TestServer::start_tls().await;
    let mut raw = TcpStream::connect(srv.implicit_addr.unwrap())
        .await
        .unwrap();
    raw.write_all(&[0x41u8; 2048]).await.unwrap();
    let mut buf = [0u8; 256];
    let mut banner = Vec::new();
    // rustls may send a fatal alert before closing; a "220" banner must never arrive.
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match raw.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => banner.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "connection must close");
    assert!(!banner.starts_with(b"220"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        srv.events().await.is_empty(),
        "no event for a failed handshake"
    );

    let mut client =
        FtpClient::connect_implicit(srv.implicit_addr.unwrap(), srv.connector.as_ref().unwrap())
            .await;
    client.login("root", "x").await;
    srv.stop();
}

const LIST_BODY: &str = "-rw-r--r--    1 0        0            4096 Jan 16  2024 readme.txt\r\ndrwxr-xr-x    2 0        0            4096 Jan 16  2024 pub\r\n";

#[tokio::test]
async fn prot_p_list_is_tls_on_the_data_channel() {
    let srv = TestServer::start_tls().await;
    let mut client = private_session(&srv).await;
    let data_addr = client.pasv().await;
    send_only(&mut client, "LIST").await;
    assert!(client.read_reply().await.starts_with("150"));
    let mut data = tls_data(data_addr, srv.connector.as_ref().unwrap()).await;
    let mut listing = String::new();
    data.read_to_string(&mut listing).await.unwrap();
    assert_eq!(listing, LIST_BODY);
    assert!(client.read_reply().await.starts_with("226"));
    srv.stop();
}

#[tokio::test]
async fn prot_c_list_stays_cleartext_on_a_tls_control_channel() {
    let srv = TestServer::start_tls().await;
    let mut client = auth_tls(&srv).await;
    client.login("root", "x").await;
    assert!(client.send("PBSZ 0").await.starts_with("200"));
    assert!(client.send("PROT C").await.starts_with("200"));
    let data_addr = client.pasv().await;
    send_only(&mut client, "LIST").await;
    assert!(client.read_reply().await.starts_with("150"));
    let mut data = TcpStream::connect(data_addr).await.unwrap();
    let mut listing = String::new();
    data.read_to_string(&mut listing).await.unwrap();
    assert_eq!(listing, LIST_BODY);
    assert!(client.read_reply().await.starts_with("226"));
    srv.stop();
}

#[tokio::test]
async fn prot_p_stor_is_captured_and_close_without_close_notify_is_complete() {
    let srv = TestServer::start_tls().await;
    let mut client = private_session(&srv).await;
    let data_addr = client.pasv().await;
    send_only(&mut client, "STOR evil.bin").await;
    assert!(client.read_reply().await.starts_with("150"));

    let body = b"MZ-tls-body";
    let mut data = tls_data(data_addr, srv.connector.as_ref().unwrap()).await;
    data.write_all(body).await.unwrap();
    data.flush().await.unwrap();
    // Dropped without shutdown(): no close_notify, the way FTPS clients commonly finish.
    drop(data);

    let r = client.read_reply().await;
    assert!(r.starts_with("226"), "STOR reply: {r}");
    srv.wait_for_upload_event().await;
    let upload = srv.uploads().await.remove(0);
    let sample = upload.sample.as_ref().unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(upload.metadata["complete"], true);
    assert_eq!(upload.metadata["wire_size"], body.len() as u64);
    assert_eq!(upload.metadata["tls"], true);
    assert_eq!(sample.size, body.len() as u64);
    assert_eq!(
        sample.sha256,
        sensor_framework::to_hex_bounded(&Sha256::digest(body), 32)
    );
    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, body);
    srv.stop();
}

#[tokio::test]
async fn prot_p_data_handshake_failure_is_425() {
    let srv = TestServer::start_tls().await;
    let mut client = private_session(&srv).await;
    let data_addr = client.pasv().await;
    send_only(&mut client, "LIST").await;
    assert!(client.read_reply().await.starts_with("150"));
    let mut raw = TcpStream::connect(data_addr).await.unwrap();
    raw.write_all(&[0x41u8; 512]).await.unwrap();
    let r = client.read_reply().await;
    assert!(r.starts_with("425 Failed to establish connection."), "{r}");
    assert!(client.send("NOOP").await.starts_with("200"));
    srv.stop();
}

/// A data connection that reaches the passive port from 127.0.0.2 while the control connection
/// came from 127.0.0.1: the shape of an off-path host racing the port. Linux routes all of
/// 127.0.0.0/8 to loopback, so no extra interface is needed.
async fn connect_from_other_ip(addr: std::net::SocketAddr) -> TcpStream {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    socket.connect(addr).await.unwrap()
}

/// STOR on an already-armed passive port from the control peer's own address, to completion.
async fn stor_on<S: AsyncRead + AsyncWrite + Unpin>(
    srv: &TestServer,
    client: &mut FtpClient<S>,
    data_addr: std::net::SocketAddr,
    name: &str,
    body: &[u8],
    prot_p: bool,
) {
    send_only(client, &format!("STOR {name}")).await;
    let r = client.read_reply().await;
    assert!(r.starts_with("150"), "STOR 150: {r}");
    if prot_p {
        let mut data = tls_data(data_addr, srv.connector.as_ref().unwrap()).await;
        data.write_all(body).await.unwrap();
        data.flush().await.unwrap();
        drop(data);
    } else {
        let mut data = TcpStream::connect(data_addr).await.unwrap();
        data.write_all(body).await.unwrap();
        drop(data);
    }
    let r = client.read_reply().await;
    assert!(r.starts_with("226"), "STOR 226: {r}");
}

/// LIST on an already-armed passive port from the control peer's own address, to completion.
async fn list_on<S: AsyncRead + AsyncWrite + Unpin>(
    srv: &TestServer,
    client: &mut FtpClient<S>,
    data_addr: std::net::SocketAddr,
    prot_p: bool,
) -> String {
    send_only(client, "LIST").await;
    let r = client.read_reply().await;
    assert!(r.starts_with("150"), "LIST 150: {r}");
    let mut listing = String::new();
    if prot_p {
        let mut data = tls_data(data_addr, srv.connector.as_ref().unwrap()).await;
        data.read_to_string(&mut listing).await.unwrap();
    } else {
        let mut data = TcpStream::connect(data_addr).await.unwrap();
        data.read_to_string(&mut listing).await.unwrap();
    }
    let r = client.read_reply().await;
    assert!(r.starts_with("226"), "LIST 226: {r}");
    listing
}

/// One hijack attempt on `verb` (`STOR` or `LIST`): a data connection from another source IP is
/// refused with vsftpd's reply and nothing is captured, then the same armed port still serves its
/// real owner, which proves the refusal was the peer check and not a broken session.
async fn hijack_attempt<S: AsyncRead + AsyncWrite + Unpin>(
    srv: &TestServer,
    client: &mut FtpClient<S>,
    verb: &str,
    prot_p: bool,
    label: &str,
) {
    let data_addr = client.pasv().await;
    send_only(
        client,
        if verb == "STOR" {
            "STOR evil.bin"
        } else {
            "LIST"
        },
    )
    .await;
    let r = client.read_reply().await;
    assert!(r.starts_with("150"), "{label}: {verb} 150: {r}");

    let mut hijacker = connect_from_other_ip(data_addr).await;
    let _ = hijacker.write_all(b"MZ-hijacked").await;
    drop(hijacker);

    let r = client.read_reply().await;
    assert_eq!(r, "425 Security: bad IP connecting.\r\n", "{label}: {verb}");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        srv.uploads().await.is_empty(),
        "{label}: the hijacker's bytes were captured"
    );

    // The port is still armed for the control peer.
    if verb == "STOR" {
        let body = b"MZ-from-the-real-peer";
        stor_on(srv, client, data_addr, "real.bin", body, prot_p).await;
        srv.wait_for_upload_events(1).await;
        let uploads = srv.uploads().await;
        assert_eq!(uploads.len(), 1, "{label}");
        assert_eq!(
            uploads[0].sample.as_ref().unwrap().size,
            body.len() as u64,
            "{label}"
        );
        assert_eq!(
            uploads[0].metadata["wire_size"],
            body.len() as u64,
            "{label}"
        );
    } else {
        assert_eq!(
            list_on(srv, client, data_addr, prot_p).await,
            LIST_BODY,
            "{label}"
        );
    }
}

async fn assert_hijack_refused_in_every_channel_mode(verb: &str) {
    for mode in [
        "plain control",
        "tls control, PROT C",
        "tls control, PROT P",
    ] {
        // A fresh server per mode so each starts with an empty event log.
        let srv = TestServer::start_tls().await;
        match mode {
            "plain control" => {
                let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
                client.login("root", "x").await;
                hijack_attempt(&srv, &mut client, verb, false, mode).await;
            }
            "tls control, PROT C" => {
                let mut client = auth_tls(&srv).await;
                client.login("root", "x").await;
                assert!(client.send("PBSZ 0").await.starts_with("200"));
                assert!(client.send("PROT C").await.starts_with("200"));
                hijack_attempt(&srv, &mut client, verb, false, mode).await;
            }
            _ => {
                let mut client = private_session(&srv).await;
                hijack_attempt(&srv, &mut client, verb, true, mode).await;
            }
        }
        srv.stop();
    }
}

#[tokio::test]
async fn stor_data_connection_from_another_ip_is_refused_and_captures_nothing() {
    assert_hijack_refused_in_every_channel_mode("STOR").await;
}

#[tokio::test]
async fn list_data_connection_from_another_ip_is_refused() {
    assert_hijack_refused_in_every_channel_mode("LIST").await;
}

#[tokio::test]
async fn auth_tls_discards_the_plaintext_login_so_a_later_upload_is_unauthenticated() {
    let srv = TestServer::start_tls().await;
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    client.login("root", "toor").await;
    assert_eq!(
        client.send("AUTH TLS").await,
        "234 Proceed with negotiation.\r\n"
    );
    let mut client = client.into_tls(srv.connector.as_ref().unwrap()).await;

    // No login inside the TLS session: the cleartext one must not carry over.
    let data_addr = client.pasv().await;
    stor_on(
        &srv,
        &mut client,
        data_addr,
        "a.bin",
        b"MZ-before-login",
        false,
    )
    .await;
    srv.wait_for_upload_events(1).await;
    assert!(
        !srv.uploads().await[0].authenticated,
        "an upload after AUTH TLS with no new login was recorded as authenticated"
    );

    // The field is live: a login inside the TLS session flips it.
    client.login("root", "toor").await;
    let data_addr = client.pasv().await;
    stor_on(
        &srv,
        &mut client,
        data_addr,
        "b.bin",
        b"MZ-after-login",
        false,
    )
    .await;
    srv.wait_for_upload_events(2).await;
    assert!(srv.uploads().await[1].authenticated);
    srv.stop();
}

#[tokio::test]
async fn auth_tls_discards_a_passive_listener_opened_in_cleartext() {
    let srv = TestServer::start_tls().await;
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    let _old_port = client.pasv().await;
    assert_eq!(
        client.send("AUTH TLS").await,
        "234 Proceed with negotiation.\r\n"
    );
    let mut client = client.into_tls(srv.connector.as_ref().unwrap()).await;

    // Only the NOT-armed replies are acceptable: a 150 would mean the cleartext listener is
    // still serving transfers inside the protected session.
    assert_eq!(client.send("LIST").await, "425 Use PORT or PASV first.\r\n");
    assert_eq!(
        client.send("STOR a.bin").await,
        "425 Use PORT or PASV first.\r\n"
    );
    srv.stop();
}

#[tokio::test]
async fn pasv_and_nlst_are_case_insensitive_like_the_other_verbs() {
    let srv = TestServer::start().await;
    let mut client = FtpClient::connect(srv.addr).await;
    client.login("root", "x").await;

    let r = client.send("pasv").await;
    assert!(r.starts_with("227 Entering Passive Mode ("), "{r}");
    let data_addr = parse_pasv_addr(&r);
    send_only(&mut client, "nlst").await;
    assert!(client.read_reply().await.starts_with("150"));
    let mut data = TcpStream::connect(data_addr).await.unwrap();
    let mut names = String::new();
    data.read_to_string(&mut names).await.unwrap();
    assert_eq!(
        names, "readme.txt\r\npub\r\n",
        "lowercase nlst is bare names"
    );
    assert!(client.read_reply().await.starts_with("226"));

    let r = client.send("EpSv").await;
    assert!(
        r.starts_with("229 Entering Extended Passive Mode (|||"),
        "{r}"
    );
    let r = client.send("pAsV").await;
    assert!(r.starts_with("227 "), "{r}");
    srv.stop();
}

fn stall_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(1),
        ..test_bounds()
    }
}

#[tokio::test]
async fn a_stalled_auth_tls_handshake_is_cut_at_the_read_timeout() {
    let srv = TestServer::start_tls_with_bounds(stall_bounds()).await;
    let mut client = FtpClient::connect(srv.tls_addr.unwrap()).await;
    assert_eq!(
        client.send("AUTH TLS").await,
        "234 Proceed with negotiation.\r\n"
    );
    // The ClientHello never comes. Without the handshake bound the session would live until
    // max_duration (30 s) and the 4 s window below would expire.
    let started = std::time::Instant::now();
    let closed = tokio::time::timeout(
        Duration::from_secs(4),
        client.reader.get_mut().read(&mut [0u8; 16]),
    )
    .await
    .expect("the stalled handshake held the session past the read timeout");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "closed before the read timeout: {:?}",
        started.elapsed()
    );

    // The listener is unaffected.
    let mut fresh = FtpClient::connect(srv.tls_addr.unwrap()).await;
    assert!(fresh.send("NOOP").await.starts_with("200"));
    srv.stop();
}

#[tokio::test]
async fn a_stalled_prot_p_data_handshake_is_cut_at_the_read_timeout() {
    let srv = TestServer::start_tls_with_bounds(stall_bounds()).await;
    let mut client = private_session(&srv).await;
    let data_addr = client.pasv().await;
    send_only(&mut client, "LIST").await;
    assert!(client.read_reply().await.starts_with("150"));

    // Connect from the control peer's own address and then say nothing. The accept wait is the
    // 5 s idle timeout; the handshake bound is 1 s, so a 4 s window separates them.
    let _stalled = TcpStream::connect(data_addr).await.unwrap();
    let started = std::time::Instant::now();
    let r = client.read_reply_within(Duration::from_secs(4)).await;
    assert!(r.starts_with("425 Failed to establish connection."), "{r}");
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "refused before the read timeout: {:?}",
        started.elapsed()
    );
    assert!(client.send("NOOP").await.starts_with("200"));
    srv.stop();
}

fn walk_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, files);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
    }
    walk(dir, &mut files);
    files
}
