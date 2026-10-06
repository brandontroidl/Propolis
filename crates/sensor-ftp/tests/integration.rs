use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CAPTURE_CHUNK_BYTES, CaptureHandoff, CaptureMemoryBudget, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, WanResolver,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

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
    _dir: tempfile::TempDir,
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
            _dir: dir,
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

struct FtpClient {
    reader: BufReader<TcpStream>,
}

impl FtpClient {
    async fn connect(addr: std::net::SocketAddr) -> FtpClient {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut client = FtpClient {
            reader: BufReader::new(stream),
        };
        let banner = client.read_reply().await;
        assert!(banner.starts_with("220"), "banner: {banner}");
        client
    }

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
async fn begin_stor(client: &mut FtpClient, name: &str) -> TcpStream {
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
    assert!(uploads[0].metadata.get("end_reason").is_none());
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
    assert_eq!(upload.metadata["wire_size"], fragment.len() as u64);
    assert_eq!(upload.sample.as_ref().unwrap().size, fragment.len() as u64);
    srv.handle.abort();
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
