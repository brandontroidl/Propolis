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
        Self::start_with_bounds(test_bounds()).await
    }

    async fn start_with_bounds(bounds: ConnectionBounds) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_smtp::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            wan_resolver,
            bounds,
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

/// Every event the server wrote, serialized whole, so a test can assert a secret appears in no
/// field at all rather than only in the field it expects.
fn all_event_text(events: &[sensor_wire::SensorEvent]) -> String {
    events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Python's smtplib (and other clients) send the username as the RFC 4954 initial response:
/// `AUTH LOGIN <base64 user>`. The sensor used to ignore it, prompt "Username:", and record the
/// next line - the password - as the username.
#[tokio::test]
async fn auth_login_initial_response_is_the_username_and_the_password_is_never_recorded() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    // "probeuser" / "S3cretPassw0rd"
    let r = client.send("AUTH LOGIN cHJvYmV1c2Vy").await;
    assert_eq!(
        r, "334 UGFzc3dvcmQ6\r\n",
        "with an initial response only the password is prompted for"
    );
    let r = client.send("UzNjcmV0UGFzc3cwcmQ=").await;
    assert!(r.starts_with("235 2.7.0"), "{r}");
    let r = client.send("QUIT").await;
    assert!(r.starts_with("221"), "the dialogue stays in step: {r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let logins: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .collect();
    assert_eq!(logins.len(), 1, "{events:?}");
    assert_eq!(logins[0].metadata["username"], "probeuser");
    let text = all_event_text(&events);
    for secret in ["S3cretPassw0rd", "UzNjcmV0UGFzc3cwcmQ"] {
        assert!(!text.contains(secret), "password in an event: {text}");
    }
    srv.handle.abort();
}

/// RFC 4954: an initial response of "=" is a present but empty response, so the username is
/// empty and the server goes straight to the password.
#[tokio::test]
async fn auth_login_empty_initial_response_prompts_only_for_the_password() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let r = client.send("AUTH LOGIN =").await;
    assert_eq!(r, "334 UGFzc3dvcmQ6\r\n");
    // "hunter2xyz"
    let r = client.send("aHVudGVyMnh5eg==").await;
    assert!(r.starts_with("235"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .expect("a login attempt");
    assert_eq!(login.metadata["username"], "");
    assert!(!all_event_text(&events).contains("hunter2xyz"));
    srv.handle.abort();
}

/// `AUTH PLAIN` without an initial response is answered `334 ` and the credential is read from
/// the next line, as Postfix does. The sensor used to answer 502 to an advertised mechanism.
#[tokio::test]
async fn auth_plain_without_initial_response_is_answered_334_and_captured() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let r = client.send("AUTH PLAIN").await;
    assert_eq!(r, "334 \r\n");
    // base64("\0probeuser\0S3cretPassw0rd")
    let r = client.send("AHByb2JldXNlcgBTM2NyZXRQYXNzdzByZA==").await;
    assert!(r.starts_with("235 2.7.0"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .expect("a login attempt");
    assert_eq!(login.metadata["username"], "probeuser");
    assert!(!all_event_text(&events).contains("S3cretPassw0rd"));
    srv.handle.abort();
}

/// A PLAIN blob with one NUL (`user\0pass`, no authzid) is malformed; its second field is the
/// password, which must not be recorded as the username.
#[tokio::test]
async fn auth_plain_malformed_blob_never_records_its_password() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    // base64("probeuser\0S3cretPassw0rd")
    let r = client
        .send("AUTH PLAIN cHJvYmV1c2VyAFMzY3JldFBhc3N3MHJk")
        .await;
    assert!(r.starts_with("235"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
    );
    assert!(
        !all_event_text(&events).contains("S3cretPassw0rd"),
        "{events:?}"
    );
    srv.handle.abort();
}

/// A `*` answering a 334 cancels the exchange (RFC 4954) with Postfix's reply; nothing is
/// recorded and the session continues.
#[tokio::test]
async fn auth_cancelled_with_star_is_aborted_and_not_recorded() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let r = client.send("auth login").await;
    assert!(r.starts_with("334 VXNlcm5hbWU6"), "{r}");
    let r = client.send("*").await;
    assert_eq!(r, "501 5.7.0 Authentication aborted\r\n");
    let r = client.send("AUTH PLAIN").await;
    assert_eq!(r, "334 \r\n");
    let r = client.send("*").await;
    assert_eq!(r, "501 5.7.0 Authentication aborted\r\n");
    let r = client.send("NOOP").await;
    assert!(r.starts_with("250"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        !events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT),
        "{events:?}"
    );
    srv.handle.abort();
}

/// EHLO advertises ETRN, which used to get `502 command not recognized`, contradicting the
/// advertisement. The replies are Postfix's `etrn_cmd` (smtpd.c); a stock install has no
/// fast-flush domains, so a well-formed request is refused with 459.
#[tokio::test]
async fn etrn_is_answered_like_postfix() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    for (cmd, want) in [
        ("ETRN", "500 Syntax: ETRN domain\r\n"),
        ("ETRN a.test b.test", "500 Syntax: ETRN domain\r\n"),
        (
            "ETRN example.com",
            "459 <example.com>: service unavailable\r\n",
        ),
        (
            "etrn #example.com",
            "459 <example.com>: service unavailable\r\n",
        ),
        (
            "ETRN @mail.example.com",
            "459 <mail.example.com>: service unavailable\r\n",
        ),
        (
            "ETRN [192.0.2.7]",
            "459 <[192.0.2.7]>: service unavailable\r\n",
        ),
        ("ETRN bad..name", "501 Error: invalid parameter syntax\r\n"),
        ("ETRN -x.test", "501 Error: invalid parameter syntax\r\n"),
    ] {
        assert_eq!(client.send(cmd).await, want, "{cmd}");
    }
    let _ = client.send("MAIL FROM:<>").await;
    assert_eq!(
        client.send("ETRN example.com").await,
        "503 Error: MAIL transaction in progress\r\n"
    );
    let _ = client.send("RSET").await;
    assert_eq!(
        client.send("ETRN example.com").await,
        "459 <example.com>: service unavailable\r\n"
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

/// A chunk larger than what is left of the session budget cannot arrive whole, so it is never
/// acknowledged: the sensor used to read the remainder and answer "queued" for part of a chunk.
#[tokio::test]
async fn bdat_past_the_session_budget_is_neither_acknowledged_nor_recorded() {
    let bounds = ConnectionBounds {
        max_captured_bytes: 256,
        ..test_bounds()
    };
    let srv = TestServer::start_with_bounds(bounds).await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.com>").await;
    let _ = client.send("RCPT TO:<b@example.com>").await;
    let chunk = vec![b'x'; 512];
    client
        .reader
        .get_mut()
        .write_all(b"BDAT 512 LAST\r\n")
        .await
        .unwrap();
    let _ = client.reader.get_mut().write_all(&chunk).await;
    let mut rest = String::new();
    let got = tokio::time::timeout(
        Duration::from_secs(3),
        client.reader.read_to_string(&mut rest),
    )
    .await;
    assert!(
        got.is_ok() && !rest.contains("250"),
        "a chunk past the budget is not acknowledged: {rest:?}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        !events
            .iter()
            .any(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA")),
        "no message event for a chunk that never fully arrived: {events:?}"
    );
    srv.handle.abort();
}

/// RFC 3030 allows the final chunk to be empty; `BDAT 0 LAST` ends the message rather than the
/// connection, which a zero-length chunk used to do.
#[tokio::test]
async fn bdat_zero_length_last_chunk_completes_the_message() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.com>").await;
    let _ = client.send("RCPT TO:<b@example.com>").await;
    let body = b"Subject: Empty tail\r\n\r\nbody\r\n";
    client
        .reader
        .get_mut()
        .write_all(format!("BDAT {}\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    client.reader.get_mut().write_all(body).await.unwrap();
    let r = client.read_reply().await;
    assert!(r.starts_with("250"), "{r}");
    let r = client.send("BDAT 0 LAST").await;
    assert!(r.contains("queued as"), "an empty LAST chunk queues: {r}");
    let r = client.send("NOOP").await;
    assert!(r.starts_with("250"), "session stays open: {r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let data_event = events
        .iter()
        .find(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
        .expect("the message is recorded");
    assert_eq!(
        data_event
            .metadata
            .get("body_size")
            .and_then(|v| v.as_u64()),
        Some(body.len() as u64)
    );
    assert_eq!(
        data_event.metadata.get("subject").and_then(|v| v.as_str()),
        Some("Empty tail")
    );
    srv.handle.abort();
}

/// A multi-byte character split between two chunks is one character in the message; decoding
/// each chunk on its own turned it into two replacement characters and miscounted the bytes.
#[tokio::test]
async fn bdat_multibyte_character_split_across_chunks_is_decoded_whole() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.com>").await;
    let _ = client.send("RCPT TO:<b@example.com>").await;
    let body = "Subject: café\r\n\r\nx\r\n".as_bytes();
    let split = body.iter().position(|&b| b == 0xC3).unwrap() + 1;
    let (first, second) = body.split_at(split);
    for (chunk, last) in [(first, ""), (second, " LAST")] {
        client
            .reader
            .get_mut()
            .write_all(format!("BDAT {}{last}\r\n", chunk.len()).as_bytes())
            .await
            .unwrap();
        client.reader.get_mut().write_all(chunk).await.unwrap();
        let r = client.read_reply().await;
        assert!(r.starts_with("250"), "{r}");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let data_event = events
        .iter()
        .find(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
        .unwrap();
    assert_eq!(
        data_event.metadata.get("subject").and_then(|v| v.as_str()),
        Some("café")
    );
    assert_eq!(
        data_event
            .metadata
            .get("body_size")
            .and_then(|v| v.as_u64()),
        Some(body.len() as u64)
    );
    srv.handle.abort();
}

/// DATA is complete only at the `.` line. A client that hangs up before it has not sent a
/// message, and the sensor used to answer "queued" for whatever had arrived.
#[tokio::test]
async fn data_without_terminating_dot_is_neither_acknowledged_nor_recorded() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.com>").await;
    let _ = client.send("RCPT TO:<b@example.com>").await;
    let r = client.send("DATA").await;
    assert!(r.starts_with("354"), "{r}");
    client
        .reader
        .get_mut()
        .write_all(b"Subject: Cut\r\n\r\nno terminator\r\n")
        .await
        .unwrap();
    client.reader.get_mut().shutdown().await.unwrap();
    let mut rest = String::new();
    let got = tokio::time::timeout(
        Duration::from_secs(3),
        client.reader.read_to_string(&mut rest),
    )
    .await;
    assert!(
        got.is_ok() && !rest.contains("250"),
        "no acknowledgement without the terminating dot: {rest:?}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        !events
            .iter()
            .any(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA")),
        "no message event for an unterminated DATA: {events:?}"
    );
    srv.handle.abort();
}

/// A body line longer than the 8192-byte read cap used to end the session silently after 354:
/// no reply, no event, and the pipelined QUIT unanswered. Postfix accepts the message. The
/// sensor now keeps the first 8192 bytes of the line, counts the rest in `body_size`, flags
/// the message `truncated`, and answers 250. A line that ends exactly at the cap is whole.
#[tokio::test]
async fn data_line_past_the_read_cap_keeps_the_message_and_flags_it_truncated() {
    // (line length without its CRLF, expect truncated)
    for (len, expect_truncated) in [(8191usize, false), (9000, true), (30_000, true)] {
        let srv = TestServer::start().await;
        let mut client = SmtpClient::connect(srv.addr).await;
        let r = client.send("DATA").await;
        assert!(r.starts_with("354"), "{r}");
        let mut body = b"Subject: long\r\n\r\n".to_vec();
        body.extend(std::iter::repeat_n(b'X', len));
        body.extend_from_slice(b"\r\nafter\r\n.\r\nQUIT\r\n");
        client.reader.get_mut().write_all(&body).await.unwrap();
        let r = client.read_reply().await;
        assert!(r.starts_with("250 2.0.0 Ok: queued as"), "len {len}: {r}");
        let r = client.read_reply().await;
        assert!(r.starts_with("221"), "len {len}: the QUIT is answered: {r}");

        tokio::time::sleep(Duration::from_millis(200)).await;
        let events = srv.events().await;
        let msg = events
            .iter()
            .find(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
            .unwrap_or_else(|| panic!("len {len}: a message event: {events:?}"));
        assert_eq!(msg.metadata["subject"], "long", "len {len}");
        // Each line counts its bytes plus one for the line break.
        let expected_size = "Subject: long".len() + 1 + 1 + len + 1 + "after".len() + 1;
        assert_eq!(msg.metadata["body_size"], expected_size, "len {len}");
        assert_eq!(msg.metadata["truncated"], expect_truncated, "len {len}");
        srv.handle.abort();
    }
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

/// Postfix's `smtpd_recipient_limit` (default 1000): the 1001st RCPT of a transaction gets
/// `452 4.5.3 Error: too many recipients`. The event keeps the first 100 addresses and the
/// accepted count, and the envelope resets after the message as Postfix's does, so the next
/// transaction neither inherits nor re-emits the old recipients.
#[tokio::test]
async fn rcpt_list_is_capped_like_postfix_and_reset_after_each_message() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.addr).await;
    client.ehlo().await;
    let _ = client.send("MAIL FROM:<a@evil.test>").await;
    let mut batch = String::new();
    for i in 0..1000 {
        batch.push_str(&format!("RCPT TO:<r{i}@example.com>\r\n"));
    }
    client
        .reader
        .get_mut()
        .write_all(batch.as_bytes())
        .await
        .unwrap();
    for i in 0..1000 {
        let r = client.read_reply().await;
        assert_eq!(r, "250 2.1.5 Ok\r\n", "recipient {i}");
    }
    let r = client.send("RCPT TO:<one-too-many@example.com>").await;
    assert_eq!(r, "452 4.5.3 Error: too many recipients\r\n");
    let r = client.send("DATA").await;
    assert!(r.starts_with("354"), "{r}");
    let r = client.send("Subject: many\r\n\r\nx\r\n.").await;
    assert!(r.contains("queued as"), "{r}");

    // A second transaction on the same connection starts from an empty envelope.
    let _ = client.send("MAIL FROM:<b@evil.test>").await;
    let r = client.send("RCPT TO:<second@example.com>").await;
    assert!(r.starts_with("250"), "the cap is per transaction: {r}");
    let _ = client.send("DATA").await;
    let r = client.send("Subject: one\r\n\r\ny\r\n.").await;
    assert!(r.contains("queued as"), "{r}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let messages: Vec<_> = events
        .iter()
        .filter(|e| e.metadata.get("command").and_then(|v| v.as_str()) == Some("DATA"))
        .collect();
    assert_eq!(messages.len(), 2, "{events:?}");
    let first = &messages[0].metadata;
    assert_eq!(first["rcpt_count"], 1000);
    let kept = first["rcpt_to"].as_array().unwrap();
    assert_eq!(kept.len(), 100);
    assert_eq!(kept[0], "r0@example.com");
    assert_eq!(kept[99], "r99@example.com");
    let second = &messages[1].metadata;
    assert_eq!(second["mail_from"], "b@evil.test");
    assert_eq!(second["rcpt_to"], serde_json::json!(["second@example.com"]));
    assert_eq!(second["rcpt_count"], 1);
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
