use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        TestServer::start_with(test_bounds()).await
    }

    async fn start_with(bounds: ConnectionBounds) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_http::start_test_server(
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
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event line: {e}: {l}")))
            .collect()
    }
}

async fn send_request(addr: std::net::SocketAddr, request: &str) -> String {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    conn.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn get_root_returns_200_html() {
    let srv = TestServer::start().await;
    let resp = send_request(srv.addr, "GET / HTTP/1.1\r\nHost: test\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "response: {resp}");
    assert!(resp.contains("Content-Type: text/html"));
    assert!(resp.contains("Welcome to nginx!"), "response: {resp}");
    // The two headers whose absence fingerprinted this sensor must now be present.
    assert!(
        resp.contains("Server: nginx/1.18.0 (Ubuntu)"),
        "missing Server header: {resp}"
    );
    assert!(resp.contains("\r\nDate: "), "missing Date header: {resp}");
    srv.handle.abort();
}

#[tokio::test]
async fn head_sends_headers_without_a_body() {
    let srv = TestServer::start().await;
    let resp = send_request(srv.addr, "HEAD / HTTP/1.1\r\nHost: test\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "response: {resp}");
    assert!(
        resp.contains("Content-Length: "),
        "HEAD must still advertise Content-Length: {resp}"
    );
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(body.is_empty(), "HEAD returned a body: {body:?}");
    srv.handle.abort();
}

#[tokio::test]
async fn disallowed_method_returns_405() {
    let srv = TestServer::start().await;
    let resp = send_request(
        srv.addr,
        "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 405"), "response: {resp}");
    assert!(resp.contains("405 Not Allowed"), "response: {resp}");
    srv.handle.abort();
}

#[tokio::test]
async fn get_nonexistent_returns_404() {
    let srv = TestServer::start().await;
    let resp = send_request(srv.addr, "GET /nonexistent HTTP/1.1\r\nHost: test\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 404"), "response: {resp}");
    assert!(resp.contains("Not Found"));
    srv.handle.abort();
}

#[tokio::test]
async fn get_robots_txt_returns_200() {
    let srv = TestServer::start().await;
    let resp = send_request(srv.addr, "GET /robots.txt HTTP/1.1\r\nHost: test\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 200"));
    assert!(resp.contains("Disallow"));
    srv.handle.abort();
}

#[tokio::test]
async fn path_traversal_attempt_logged() {
    let srv = TestServer::start().await;
    let _ = send_request(
        srv.addr,
        "GET /../../../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    let path = cmd.metadata.get("path").and_then(|v| v.as_str()).unwrap();
    assert!(
        path.contains("etc/passwd"),
        "path traversal must be captured: {path}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn post_body_captured() {
    let srv = TestServer::start().await;
    let body = "username=admin&password=secret";
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = send_request(srv.addr, &req).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert!(cmd.metadata.get("body_preview").is_some());
    assert_eq!(
        cmd.metadata.get("body_size").and_then(|v| v.as_u64()),
        Some(body.len() as u64)
    );
    srv.handle.abort();
}

/// A declared body over nginx's default `client_max_body_size` (1 MB) is refused with 413 before
/// any of it is read; the old handler read 64 KB of it and answered 405 for the method.
#[tokio::test]
async fn post_body_over_one_megabyte_is_refused_with_413_before_it_is_sent() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    conn.write_all(b"POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: 2000000\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut response)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 413 Request Entity Too Large\r\n"),
        "{response}"
    );
    assert!(response.contains("<title>413 Request Entity Too Large</title>"));

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert_eq!(
        cmd.metadata.get("body_declared").and_then(|v| v.as_u64()),
        Some(2_000_000)
    );
    assert_eq!(
        cmd.metadata.get("body_size").and_then(|v| v.as_u64()),
        Some(0)
    );
    srv.handle.abort();
}

/// A header block that has not ended within 16 KiB is answered as nginx answers a header past its
/// buffers, `400` with its "Request Header Or Cookie Too Large" page: the old reader kept reading
/// one chunk past the cap and then hung up without a word. Empty `:` lines count like any other
/// bytes.
#[tokio::test]
async fn a_header_block_past_16_kib_gets_nginx_400() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    let mut request = b"GET / HTTP/1.1\r\nHost: test\r\n".to_vec();
    request.extend(b":\r\n".repeat(6000));
    // Exactly 16 KiB with no blank line yet, so the server has read everything that was sent
    // when it answers and closes (bytes it left unread would turn its close into a reset).
    request.truncate(16 * 1024);
    conn.write_all(&request).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut response)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(response.contains("Server: nginx/1.18.0 (Ubuntu)\r\n"));
    assert!(response.contains("<title>400 Request Header Or Cookie Too Large</title>"));
    assert!(response.contains("<center>Request Header Or Cookie Too Large</center>"));
    srv.handle.abort();
}

/// Bounds where a whole request part must arrive within one second, while each read alone may
/// wait as long, and the connection may last half a minute.
fn one_second_parts() -> ConnectionBounds {
    ConnectionBounds {
        idle_timeout: Duration::from_secs(1),
        ..test_bounds()
    }
}

/// Send `first`, then one byte of `drip` every 300 ms, under the per-read timeout each time, and
/// return how long after the first send the server closed the connection, if it did within 5 s.
async fn closed_while_dripping(
    addr: std::net::SocketAddr,
    first: &[u8],
    drip: &[u8],
) -> Option<Duration> {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    let start = std::time::Instant::now();
    conn.write_all(first).await.unwrap();
    let mut drip = drip.iter().cycle();
    let mut chunk = [0u8; 1024];
    while start.elapsed() < Duration::from_secs(5) {
        match tokio::time::timeout(Duration::from_millis(300), conn.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => return Some(start.elapsed()),
            Ok(Ok(_)) => panic!("no reply is owed to an unfinished request"),
            Err(_) => {
                if conn.write_all(&[*drip.next().unwrap()]).await.is_err() {
                    return Some(start.elapsed());
                }
            }
        }
    }
    None
}

/// A header block sent a byte at a time, each within the per-read timeout, is cut once it has
/// taken `idle_timeout` from its first byte, as nginx's `client_header_timeout` cuts a whole
/// header; the old reader kept it, and its buffer, until `max_duration`.
#[tokio::test]
async fn a_header_block_dripped_past_its_deadline_is_dropped() {
    let srv = TestServer::start_with(one_second_parts()).await;
    let closed = closed_while_dripping(srv.addr, b"GET / HTTP/1.1\r\n", b"X-Drip: y\r\n").await;
    assert!(
        closed.is_some_and(|after| after < Duration::from_millis(2500)),
        "closed after {closed:?}"
    );
    srv.handle.abort();
}

/// A body sent a byte at a time is cut once it has taken `idle_timeout` from the header's end;
/// the event records what had arrived and that the body is incomplete, and nothing is answered.
#[tokio::test]
async fn a_body_dripped_past_its_deadline_is_dropped_and_recorded_incomplete() {
    let srv = TestServer::start_with(one_second_parts()).await;
    let closed = closed_while_dripping(
        srv.addr,
        b"POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\n",
        b"A",
    )
    .await;
    assert!(
        closed.is_some_and(|after| after < Duration::from_millis(2500)),
        "closed after {closed:?}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("the attempt is still evidence");
    assert_eq!(
        cmd.metadata.get("body_complete").and_then(|v| v.as_bool()),
        Some(false)
    );
    let received = cmd.metadata.get("body_size").and_then(|v| v.as_u64());
    assert!(received.is_some_and(|n| n < 100), "{received:?}");
    srv.handle.abort();
}

/// Thousands of empty `:` lines inside 16 KiB are still a request nginx serves (it skips each as
/// an invalid header line): the reply and the event come as for any other GET, and no header
/// value is taken from them.
#[tokio::test]
async fn thousands_of_empty_header_lines_within_16_kib_are_served() {
    let srv = TestServer::start().await;
    let mut request = "GET / HTTP/1.1\r\nHost: test\r\n".to_string();
    request.push_str(&":\r\n".repeat(5400));
    request.push_str("User-Agent: after-the-flood\r\n\r\n");
    let response = send_request(srv.addr, &request).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert_eq!(
        cmd.metadata.get("user_agent").and_then(|v| v.as_str()),
        Some("after-the-flood")
    );
    assert_eq!(
        cmd.metadata.get("host").and_then(|v| v.as_str()),
        Some("test")
    );
    srv.handle.abort();
}

/// A body larger than the capture cap but within what nginx accepts is read to the end before
/// the reply, so the client sees a clean response after its upload instead of a reset part way;
/// the event records the real size and that the kept copy is a prefix.
#[tokio::test]
async fn post_body_past_the_capture_cap_is_drained_and_recorded_honestly() {
    let srv = TestServer::start().await;
    let body = vec![b'A'; 70_000];
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    conn.write_all(b"POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: 70000\r\n\r\n")
        .await
        .unwrap();
    conn.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut response)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 405 Not Allowed\r\n"),
        "{response}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert_eq!(
        cmd.metadata.get("body_size").and_then(|v| v.as_u64()),
        Some(70_000)
    );
    assert_eq!(
        cmd.metadata.get("body_complete").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        cmd.metadata.get("truncated").and_then(|v| v.as_bool()),
        Some(true)
    );
    srv.handle.abort();
}

/// A client that declares a body and hangs up before sending it all has not made a request.
/// nginx logs the premature close and answers nothing; the old handler answered as if the
/// fragment were the whole body.
#[tokio::test]
async fn post_body_cut_short_gets_no_response_and_is_recorded_as_incomplete() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    conn.write_all(
        b"POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\nuser=admin&pass=",
    )
    .await
    .unwrap();
    conn.shutdown().await.unwrap();
    let mut response = Vec::new();
    let got = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut response)).await;
    assert!(
        got.is_ok() && response.is_empty(),
        "no reply to a body that never arrived: {:?}",
        String::from_utf8_lossy(&response)
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("the attempt is still evidence");
    assert_eq!(
        cmd.metadata.get("body_size").and_then(|v| v.as_u64()),
        Some(16)
    );
    assert_eq!(
        cmd.metadata.get("body_complete").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        cmd.metadata.get("body_preview").and_then(|v| v.as_str()),
        Some("user=admin&pass=")
    );
    srv.handle.abort();
}

#[tokio::test]
async fn protocol_label_http_on_all_events() {
    let srv = TestServer::start().await;
    let _ = send_request(srv.addr, "GET / HTTP/1.1\r\nHost: test\r\n\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(events.len() >= 2, "expected connection+command events");
    for event in &events {
        assert_eq!(event.sensor, "http");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        assert!(!event.authenticated);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("http")
        );
    }
    srv.handle.abort();
}

#[test]
fn never_exec_static_check() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = walk_rs(&src_dir);
    assert!(!files.is_empty());
    let mut found = Vec::new();
    for entry in &files {
        let content = std::fs::read_to_string(entry).unwrap_or_default();
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
        "sensor-http must not contain process-spawning code: {found:?}"
    );
}

#[tokio::test]
async fn malformed_request_drops_connection_without_crashing_listener() {
    let srv = TestServer::start().await;
    for seed in 0..5u8 {
        if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
            let garbage: Vec<u8> = (0..2048u32)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
                .collect();
            let _ = conn.write_all(&garbage).await;
            drop(conn);
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = send_request(srv.addr, "GET / HTTP/1.1\r\nHost: test\r\n\r\n").await;
    assert!(resp.contains("200 OK"), "listener must survive garbage");
    srv.handle.abort();
}

#[tokio::test]
async fn connection_event_emitted_even_without_request() {
    let srv = TestServer::start().await;
    {
        let _conn = TcpStream::connect(srv.addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    assert!(
        events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
    );
    srv.handle.abort();
}

#[tokio::test]
async fn user_agent_captured_in_metadata() {
    let srv = TestServer::start().await;
    let _ = send_request(
        srv.addr,
        "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 Bot\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    let ua = cmd
        .metadata
        .get("user_agent")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(ua.contains("Mozilla"), "user-agent: {ua}");
    assert!(
        cmd.metadata.get("claimed_crawler").is_none(),
        "an ordinary User-Agent carries no crawler label"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn a_claimed_crawler_is_labelled_but_still_recorded_as_the_same_signal() {
    let srv = TestServer::start().await;
    let _ = send_request(
        srv.addr,
        "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 (compatible; ClaudeBot/1.0)\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("a claimed crawler's request is still recorded as the ordinary request signal");
    assert_eq!(
        cmd.metadata.get("claimed_crawler").and_then(|v| v.as_str()),
        Some("ClaudeBot")
    );
    srv.handle.abort();
}

#[tokio::test]
async fn query_string_captured() {
    let srv = TestServer::start().await;
    let _ = send_request(
        srv.addr,
        "GET /search?q=test&lang=en HTTP/1.1\r\nHost: test\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert_eq!(
        cmd.metadata.get("path").and_then(|v| v.as_str()),
        Some("/search")
    );
    let query = cmd.metadata.get("query").and_then(|v| v.as_str()).unwrap();
    assert!(query.contains("q=test"));
    srv.handle.abort();
}

// ---------------------------------------------------------------------------------------------
// Credential privacy (docs/security/sample-and-credential-privacy.md). Modelled on sensor-ssh's
// `password_never_in_event`: each secret is asserted absent from the SERIALIZED request event as
// written to the log, not from the typed struct, so a future field cannot reintroduce it silently.
// ---------------------------------------------------------------------------------------------

/// Sends `request`, returns the request event and the exact JSON line the sensor wrote for it.
async fn request_event(request: &str) -> (sensor_wire::SensorEvent, String) {
    let srv = TestServer::start().await;
    let _ = send_request(srv.addr, request).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let content = tokio::fs::read_to_string(&srv.log_path).await.unwrap();
    let line = content
        .lines()
        .find(|l| l.contains(sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC))
        .expect("a request event line")
        .to_string();
    srv.handle.abort();
    (serde_json::from_str(&line).unwrap(), line)
}

fn post(path: &str, content_type: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn form_login_password_never_in_event() {
    let body = "username=admin&password=s3cret_p%40ssw0rd!&remember=1";
    let (event, line) =
        request_event(&post("/login", "application/x-www-form-urlencoded", body)).await;
    assert!(
        !line.contains("s3cret_p"),
        "password must NEVER appear in event: {line}"
    );
    assert_eq!(
        event.metadata["body_preview"],
        "username=admin&password=<redacted>&remember=1"
    );
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn json_login_password_never_in_event_at_any_depth() {
    let body = r#"{"user":"admin","password":"hunter2","session":{"creds":{"token":"tok_9f8e"}}}"#;
    let (event, line) = request_event(&post("/api/login", "application/json", body)).await;
    assert!(
        !line.contains("hunter2"),
        "password must NEVER appear in event: {line}"
    );
    assert!(
        !line.contains("tok_9f8e"),
        "token must NEVER appear in event: {line}"
    );
    assert_eq!(
        event.metadata["body_preview"],
        r#"{"user":"admin","password":"<redacted>","session":{"creds":{"token":"<redacted>"}}}"#
    );
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn basic_auth_keeps_the_username_and_never_the_password() {
    // admin:hunter2
    let (event, line) = request_event(
        "GET /admin HTTP/1.1\r\nHost: test\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n",
    )
    .await;
    assert!(
        !line.contains("hunter2"),
        "password must NEVER appear in event: {line}"
    );
    assert!(
        !line.contains("YWRtaW46aHVudGVyMg"),
        "nor its encoding: {line}"
    );
    assert_eq!(event.metadata["auth_scheme"], "Basic");
    assert_eq!(event.metadata["auth_username"], "admin");
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn bearer_token_never_in_event() {
    let (event, line) = request_event(
        "GET /api HTTP/1.1\r\nHost: test\r\nProxy-Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\r\n\r\n",
    )
    .await;
    assert!(
        !line.contains("eyJhbGci"),
        "token must NEVER appear in event: {line}"
    );
    assert_eq!(event.metadata["auth_scheme"], "Bearer");
    assert_eq!(event.metadata["proxy_auth_scheme"], "Bearer");
    assert!(event.metadata.get("auth_username").is_none());
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn cookie_values_never_in_event() {
    let (event, line) = request_event(
        "GET / HTTP/1.1\r\nHost: test\r\nCookie: PHPSESSID=9a1b2c3d4e; remember_token=rt_55aa; lang=en\r\n\r\n",
    )
    .await;
    for secret in ["9a1b2c3d4e", "rt_55aa", "=en"] {
        assert!(
            !line.contains(secret),
            "cookie value must NEVER appear in event: {line}"
        );
    }
    assert_eq!(
        event.metadata["cookie"],
        "PHPSESSID=<redacted>; remember_token=<redacted>; lang=<redacted>"
    );
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn multipart_login_password_never_in_event() {
    let body = "--b0undary\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n--b0undary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--b0undary--\r\n";
    let (event, line) = request_event(&post(
        "/login",
        "multipart/form-data; boundary=b0undary",
        body,
    ))
    .await;
    assert!(
        !line.contains("hunter2"),
        "password must NEVER appear in event: {line}"
    );
    let preview = event.metadata["body_preview"].as_str().unwrap();
    assert!(preview.contains("name=\"username\""), "{preview}");
    assert!(preview.contains("admin"), "{preview}");
    assert!(preview.contains("name=\"password\""), "{preview}");
    assert!(preview.contains("<redacted>"), "{preview}");
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn query_string_password_never_in_event() {
    let (event, line) = request_event(
        "GET /login?user=root&passwd=toor123&next=%2F HTTP/1.1\r\nHost: test\r\n\r\n",
    )
    .await;
    assert!(
        !line.contains("toor123"),
        "password must NEVER appear in event: {line}"
    );
    assert_eq!(
        event.metadata["query"],
        "user=root&passwd=<redacted>&next=%2F"
    );
    assert_eq!(event.metadata["credentials_redacted"], true);
}

/// The common case is behaviour-preserving: a request that carries no credential produces
/// exactly the fields it produced before redaction existed, with no flag and nothing rewritten.
#[tokio::test]
async fn request_without_credentials_serializes_exactly_as_before() {
    let body = "q=nginx&lang=en";
    let (mut event, _) = request_event(&format!(
        "POST /search?page=2&sort=asc HTTP/1.1\r\nHost: test\r\nUser-Agent: curl/8.5.0\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ))
    .await;
    // The emitter stamps the ephemeral listener port on every event; it is not the handler's.
    event.metadata.as_object_mut().unwrap().remove("local_port");
    assert_eq!(
        event.metadata,
        serde_json::json!({
            "protocol_label": "http",
            "method": "POST",
            "path": "/search",
            "query": "page=2&sort=asc",
            "user_agent": "curl/8.5.0",
            "host": "test",
            "body_size": 15,
            "body_declared": 15,
            "body_complete": true,
            "truncated": false,
            "body_preview": "q=nginx&lang=en",
        })
    );
}

/// Redaction runs on the captured body before the preview cap, so a secret anywhere in the
/// captured bytes is gone and the preview is still no longer than the cap.
#[tokio::test]
async fn redacted_body_preview_still_respects_the_cap() {
    let filler = "a".repeat(4_500);
    let body = format!("password=first_secret&note={filler}&pin=last_secret");
    let (event, line) =
        request_event(&post("/login", "application/x-www-form-urlencoded", &body)).await;
    assert!(!line.contains("first_secret"), "{line}");
    assert!(!line.contains("last_secret"), "{line}");
    let preview = event.metadata["body_preview"].as_str().unwrap();
    assert!(preview.len() <= 4096, "preview is {} bytes", preview.len());
    assert!(
        preview.starts_with("password=<redacted>&note=aaaa"),
        "{preview}"
    );
    assert_eq!(event.metadata["truncated"], false);
    assert_eq!(event.metadata["credentials_redacted"], true);
}

// Bypasses a review found in the first cut, each with the request that leaked. The secret is
// `ZZSECRETZZ` (or `WlpTRUNSRVRaWjp4`, its Basic encoding with `:x`) so one substring check
// covers the line.

#[tokio::test]
async fn authorization_without_a_scheme_word_never_in_event() {
    let (event, line) =
        request_event("GET / HTTP/1.1\r\nHost: t\r\nAuthorization: WlpTRUNSRVRaWjp4\r\n\r\n").await;
    assert!(!line.contains("WlpTRUNSRVRaWjp4"), "{line}");
    assert_eq!(event.metadata["auth_scheme"], "<redacted>");
    assert_eq!(event.metadata["credentials_redacted"], true);

    let (event, line) =
        request_event("GET / HTTP/1.1\r\nHost: t\r\nAuthorization: ZZSECRETZZ\r\n\r\n").await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(event.metadata["auth_scheme"], "<redacted>");

    // A scheme word alone dropped nothing, so the flag stays absent.
    let (event, _) =
        request_event("GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Basic\r\n\r\n").await;
    assert_eq!(event.metadata["auth_scheme"], "Basic");
    assert!(event.metadata.get("credentials_redacted").is_none());
}

#[tokio::test]
async fn xmlrpc_and_xml_login_password_never_in_event() {
    let call = "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>ZZSECRETZZ</string></value></param></params></methodCall>";
    let (event, line) = request_event(&post("/xmlrpc.php", "text/xml", call)).await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    let preview = event.metadata["body_preview"].as_str().unwrap();
    assert!(preview.contains("wp.getUsersBlogs"), "{preview}");
    assert!(preview.contains("<string>admin</string>"), "{preview}");
    assert!(preview.contains("<string><redacted></string>"), "{preview}");
    assert_eq!(event.metadata["credentials_redacted"], true);

    let soap = "<login><username>admin</username><password>ZZSECRETZZ</password></login>";
    let (event, line) = request_event(&post("/api", "application/xml", soap)).await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(
        event.metadata["body_preview"],
        "<login><username>admin</username><password><redacted></password></login>"
    );
}

#[tokio::test]
async fn password_like_names_outside_the_first_list_never_in_event() {
    let (event, line) = request_event(
        "GET /?userpass=ZZ1&passcode=ZZ2&credentials=admin:ZZ3&api-key=ZZ4&pw=ZZ5&psw=ZZ6&pswd=ZZ7&senha=ZZ8&mot_de_passe=ZZ9&loginpass=ZZa&pass1=ZZb&access-key=ZZc HTTP/1.1\r\nHost: t\r\n\r\n",
    )
    .await;
    for secret in [
        "ZZ1", "ZZ2", "ZZ3", "ZZ4", "ZZ5", "ZZ6", "ZZ7", "ZZ8", "ZZ9", "ZZa", "ZZb", "ZZc",
    ] {
        assert!(!line.contains(secret), "{secret} leaked: {line}");
    }
    assert_eq!(
        event.metadata["query"],
        "userpass=<redacted>&passcode=<redacted>&credentials=<redacted>&api-key=<redacted>&pw=<redacted>&psw=<redacted>&pswd=<redacted>&senha=<redacted>&mot_de_passe=<redacted>&loginpass=<redacted>&pass1=<redacted>&access-key=<redacted>"
    );
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn json_secret_inside_a_container_never_in_event() {
    let (event, line) = request_event(&post(
        "/api",
        "application/json",
        r#"{"password":["ZZSECRETZZ"]}"#,
    ))
    .await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(
        event.metadata["body_preview"],
        r#"{"password":"<redacted>"}"#
    );
    assert_eq!(event.metadata["credentials_redacted"], true);

    let (event, line) = request_event(&post(
        "/api",
        "application/json",
        r#"{"password":{"value":"ZZSECRETZZ"}}"#,
    ))
    .await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(
        event.metadata["body_preview"],
        r#"{"password":"<redacted>"}"#
    );
}

#[tokio::test]
async fn multipart_as_real_senders_write_it_never_in_event() {
    for body in [
        "--bb\nContent-Disposition: form-data; name=\"password\"\n\nZZSECRETZZ\n--bb--\n",
        "--bb\r\nContent-Disposition: form-data; filename=\"x\"; name=\"password\"\r\n\r\nZZSECRETZZ\r\n--bb--\r\n",
        "--bb\r\nContent-Disposition: form-data; name=password\r\n\r\nZZSECRETZZ\r\n--bb--\r\n",
    ] {
        let (event, line) =
            request_event(&post("/login", "multipart/form-data; boundary=bb", body)).await;
        assert!(!line.contains("ZZSECRETZZ"), "{body:?}: {line}");
        let preview = event.metadata["body_preview"].as_str().unwrap();
        assert!(preview.contains("<redacted>"), "{preview}");
        assert_eq!(event.metadata["credentials_redacted"], true, "{body:?}");
    }
}

#[tokio::test]
async fn cookie_token_without_a_name_never_in_event() {
    let (event, line) =
        request_event("GET / HTTP/1.1\r\nHost: t\r\nCookie: ZZSECRETZZ\r\n\r\n").await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(event.metadata["cookie"], "<redacted>");
    assert_eq!(event.metadata["credentials_redacted"], true);
}

#[tokio::test]
async fn semicolon_query_and_target_secrets_never_in_event() {
    let (event, line) =
        request_event("GET /?user=a;password=ZZSECRETZZ HTTP/1.1\r\nHost: t\r\n\r\n").await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(event.metadata["query"], "user=a;password=<redacted>");
    assert_eq!(event.metadata["credentials_redacted"], true);

    let (event, line) = request_event(
        "GET http://admin:ZZSECRETZZ@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(
        event.metadata["path"],
        "http://admin:<redacted>@example.com/"
    );
    assert_eq!(event.metadata["credentials_redacted"], true);

    let (event, line) =
        request_event("GET /login%3Fpassword=ZZSECRETZZ HTTP/1.1\r\nHost: t\r\n\r\n").await;
    assert!(!line.contains("ZZSECRETZZ"), "{line}");
    assert_eq!(event.metadata["path"], "/login%3Fpassword=<redacted>");
    assert_eq!(event.metadata["credentials_redacted"], true);
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
