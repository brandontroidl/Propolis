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
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_smtp::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            wan_resolver,
            test_bounds(),
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

struct SmtpClient {
    reader: BufReader<TcpStream>,
}

impl SmtpClient {
    async fn connect(addr: std::net::SocketAddr) -> SmtpClient {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut client = SmtpClient {
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
            .expect("timeout")
            .expect("read error");
        line
    }

    async fn read_multiline_reply(&mut self) -> String {
        let mut result = String::new();
        loop {
            let line = self.read_reply().await;
            let done = line.len() >= 4 && line.as_bytes()[3] == b' ';
            result.push_str(&line);
            if done {
                break;
            }
        }
        result
    }

    async fn send(&mut self, cmd: &str) -> String {
        self.reader
            .get_mut()
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        self.read_reply().await
    }

    async fn send_multiline(&mut self, cmd: &str) -> String {
        self.reader
            .get_mut()
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        self.read_multiline_reply().await
    }

    async fn ehlo(&mut self) {
        let r = self.send_multiline("EHLO test.local").await;
        assert!(r.contains("250"), "EHLO: {r}");
    }
}

#[tokio::test]
async fn ehlo_advertises_auth() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    let r = client.send_multiline("EHLO test").await;
    assert!(
        r.contains("AUTH PLAIN LOGIN"),
        "EHLO must advertise AUTH: {r}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn banner_and_ehlo_impersonate_ubuntu_postfix() {
    let srv = TestServer::start().await;
    let stream = TcpStream::connect(srv.addr).await.unwrap();
    let mut reader = BufReader::new(stream);

    // Banner: persona hostname + Postfix (Ubuntu), never the RFC2606 placeholder mail.example.com.
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();
    assert!(banner.contains("server01"), "banner host: {banner}");
    assert!(
        banner.contains("ESMTP Postfix (Ubuntu)"),
        "banner: {banner}"
    );
    assert!(
        !banner.contains("example.com"),
        "banner leaks placeholder: {banner}"
    );

    // EHLO: real Postfix caps, no "Hello" token, terminating on a capability not a bare "250 OK".
    reader.write_all(b"EHLO probe\r\n").await.unwrap();
    let mut ehlo = String::new();
    loop {
        let mut l = String::new();
        reader.read_line(&mut l).await.unwrap();
        ehlo.push_str(&l);
        if l.starts_with("250 ") {
            break;
        }
    }
    assert!(
        !ehlo.contains("Hello"),
        "EHLO carries the non-Postfix 'Hello' token: {ehlo}"
    );
    assert!(
        ehlo.contains("250-STARTTLS"),
        "EHLO missing STARTTLS: {ehlo}"
    );
    assert!(
        ehlo.contains("250-PIPELINING"),
        "EHLO missing PIPELINING: {ehlo}"
    );
    assert!(
        ehlo.trim_end().ends_with("250 CHUNKING"),
        "EHLO must terminate on a real capability: {ehlo}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn unterminated_over_long_line_is_chopped_and_answered() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    // A blob well over MAX_LINE_LEN (8192) with NO newline. The old read_line blocked waiting for a
    // newline while buffering the whole thing (unbounded -> OOM); the bounded reader returns after
    // the cap and the server answers. If this hung, read_reply's timeout would panic the test.
    let blob = "A".repeat(20_000);
    client
        .reader
        .get_mut()
        .write_all(blob.as_bytes())
        .await
        .unwrap();
    let r = client.read_reply().await;
    assert!(
        r.starts_with("50"),
        "an unterminated over-long line must be chopped and answered, not buffered whole: {r}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn auth_plain_credential_capture() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    // AUTH PLAIN: base64("\0admin\0secret")
    let r = client.send("AUTH PLAIN AGFkbWluAHNlY3JldA==").await;
    assert!(r.starts_with("235"), "AUTH PLAIN reply: {r}");

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
    assert!(login.metadata.get("password").is_none());
    srv.handle.abort();
}

#[tokio::test]
async fn auth_login_credential_capture() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let r = client.send("AUTH LOGIN").await;
    assert!(r.starts_with("334"), "AUTH LOGIN prompt: {r}");
    // "root" base64 = "cm9vdA=="
    let r = client.send("cm9vdA==").await;
    assert!(r.starts_with("334"), "password prompt: {r}");
    // "toor" base64 = "dG9vcg=="
    let r = client.send("dG9vcg==").await;
    assert!(r.starts_with("235"), "AUTH LOGIN success: {r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login.metadata.get("username").and_then(|v| v.as_str()),
        Some("root")
    );
    srv.handle.abort();
}

/// EHLO advertises CHUNKING, so a client may deliver by BDAT instead of DATA. It used to get
/// "502 command not recognized", contradicting the advertisement and losing the message.
#[tokio::test]
async fn bdat_last_delivers_the_message_and_is_captured() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<attacker@evil.com>").await;
    let _ = client.send("RCPT TO:<victim@example.com>").await;
    let body = b"Subject: Chunked\r\n\r\nvia BDAT\r\n";
    client
        .reader
        .get_mut()
        .write_all(format!("BDAT {} LAST\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    client.reader.get_mut().write_all(body).await.unwrap();
    let r = client.read_reply().await;
    assert!(
        r.starts_with("250 2.0.0 Ok: queued as"),
        "BDAT LAST must be accepted like DATA: {r}"
    );
    // The session is still usable afterwards.
    let r = client.send("NOOP").await;
    assert!(r.starts_with("250"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let data_event = events
        .iter()
        .find(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
        .expect("a BDAT delivery must produce the same message event as DATA");
    assert_eq!(
        data_event.metadata.get("subject").and_then(|v| v.as_str()),
        Some("Chunked")
    );
    assert_eq!(
        data_event
            .metadata
            .get("body_size")
            .and_then(|v| v.as_u64()),
        Some(body.len() as u64)
    );
    assert_eq!(
        data_event
            .metadata
            .get("chunking")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    srv.handle.abort();
}

/// A client that declares a chunk and hangs up part way through has not delivered a message.
/// The sensor used to answer "queued" and record a body of zero bytes.
#[tokio::test]
async fn bdat_short_chunk_is_neither_acknowledged_nor_recorded() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.com>").await;
    let _ = client.send("RCPT TO:<b@example.com>").await;
    client
        .reader
        .get_mut()
        .write_all(b"BDAT 100 LAST\r\nabc")
        .await
        .unwrap();
    // Close our sending side; the server sees EOF inside the chunk.
    client.reader.get_mut().shutdown().await.unwrap();
    let mut rest = String::new();
    let got = tokio::time::timeout(
        Duration::from_secs(3),
        client.reader.read_to_string(&mut rest),
    )
    .await;
    assert!(
        got.is_ok() && !rest.contains("250"),
        "no acknowledgement for a chunk that never fully arrived: {rest:?}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        !events
            .iter()
            .any(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA")),
        "no message event for an incomplete chunk: {events:?}"
    );
    srv.handle.abort();
}

/// A body exactly at the cap is kept whole; one past the cap is kept up to the cap and the
/// event records the real size with `truncated`, instead of a body of zero bytes.
#[tokio::test]
async fn bdat_body_at_and_past_the_cap_is_recorded_honestly() {
    for (size, expect_truncated) in [(65_536usize, false), (70_000usize, true)] {
        let srv = TestServer::start().await;
        let mut client = SmtpClient::connect(srv.addr).await;
        client.ehlo().await;
        let _ = client.send("MAIL FROM:<a@evil.com>").await;
        let _ = client.send("RCPT TO:<b@example.com>").await;
        let body = vec![b'x'; size];
        client
            .reader
            .get_mut()
            .write_all(format!("BDAT {size} LAST\r\n").as_bytes())
            .await
            .unwrap();
        client.reader.get_mut().write_all(&body).await.unwrap();
        let r = client.read_reply().await;
        assert!(r.contains("queued as"), "{r}");

        tokio::time::sleep(Duration::from_millis(200)).await;
        let events = srv.events().await;
        let data_event = events
            .iter()
            .find(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
            .unwrap();
        assert_eq!(
            data_event
                .metadata
                .get("body_size")
                .and_then(|v| v.as_u64()),
            Some(size as u64),
            "body_size is what the client sent"
        );
        assert_eq!(
            data_event
                .metadata
                .get("truncated")
                .and_then(|v| v.as_bool()),
            Some(expect_truncated),
            "size {size}"
        );
        srv.handle.abort();
    }
}

#[tokio::test]
async fn bdat_chunks_accumulate_until_last() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.com>").await;
    let _ = client.send("RCPT TO:<b@example.com>").await;
    let first = b"Subject: Two\r\n\r\n";
    let second = b"parts\r\n";
    client
        .reader
        .get_mut()
        .write_all(format!("BDAT {}\r\n", first.len()).as_bytes())
        .await
        .unwrap();
    client.reader.get_mut().write_all(first).await.unwrap();
    let r = client.read_reply().await;
    assert!(
        r.starts_with("250 2.0.0 Ok:") && !r.contains("queued"),
        "an intermediate chunk is acknowledged but not queued: {r}"
    );
    client
        .reader
        .get_mut()
        .write_all(format!("BDAT {} LAST\r\n", second.len()).as_bytes())
        .await
        .unwrap();
    client.reader.get_mut().write_all(second).await.unwrap();
    let r = client.read_reply().await;
    assert!(r.contains("queued as"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let data_event = events
        .iter()
        .find(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
        .unwrap();
    assert_eq!(
        data_event
            .metadata
            .get("body_size")
            .and_then(|v| v.as_u64()),
        Some((first.len() + second.len()) as u64),
        "both chunks belong to one message"
    );
    assert_eq!(
        data_event.metadata.get("subject").and_then(|v| v.as_str()),
        Some("Two")
    );
    srv.handle.abort();
}

#[tokio::test]
async fn data_capture_with_sender_and_recipient() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<attacker@evil.com>").await;
    let _ = client.send("RCPT TO:<victim@example.com>").await;
    let _ = client.send("DATA").await;
    client.reader.get_mut().write_all(
        b"From: attacker@evil.com\r\nTo: victim@example.com\r\nSubject: Phishing Test\r\n\r\nClick this link.\r\n.\r\n"
    ).await.unwrap();
    let r = client.read_reply().await;
    assert!(r.starts_with("250"), "DATA completion: {r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let data_event = events
        .iter()
        .find(|e| {
            e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC
                && e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA")
        })
        .unwrap();
    assert_eq!(
        data_event
            .metadata
            .get("mail_from")
            .and_then(|v| v.as_str()),
        Some("attacker@evil.com")
    );
    assert_eq!(
        data_event.metadata.get("subject").and_then(|v| v.as_str()),
        Some("Phishing Test")
    );
    let rcpt = data_event
        .metadata
        .get("rcpt_to")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(rcpt[0].as_str(), Some("victim@example.com"));
    srv.handle.abort();
}

#[tokio::test]
async fn never_relays_no_outbound_smtp() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@b>").await;
    let _ = client.send("RCPT TO:<c@d>").await;
    let _ = client.send("DATA").await;
    client
        .reader
        .get_mut()
        .write_all(b"Subject: test\r\n\r\nbody\r\n.\r\n")
        .await
        .unwrap();
    let _ = client.read_reply().await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    srv.handle.abort();
    task.abort();
    assert_eq!(
        count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor-smtp must never relay"
    );
}

#[tokio::test]
async fn protocol_label_smtp_on_all_events() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("AUTH PLAIN AGFkbWluAHNlY3JldA==").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    for event in &events {
        assert_eq!(event.sensor, "smtp");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("smtp")
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
        {
            found.push(entry.display().to_string());
        }
    }
    assert!(
        found.is_empty(),
        "sensor-smtp must not spawn processes: {found:?}"
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
    let mut probe = SmtpClient::connect(srv.addr).await;
    probe.ehlo().await;
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
