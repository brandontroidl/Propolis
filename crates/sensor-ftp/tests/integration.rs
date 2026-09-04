use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
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
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_ftp::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            wan_resolver,
            test_bounds(),
            "test".to_string(),
            dir.path().join("outbox"),
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
            spool_dir,
            handle,
            _dir: dir,
        }
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
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
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

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = srv.events().await;
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .unwrap();
    let sample = upload.sample.as_ref().unwrap();
    assert_eq!(sample.size, body.len() as u64);
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(upload.metadata["wire_size"], body.len() as u64);

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

    tokio::time::sleep(Duration::from_millis(500)).await;
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
