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
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_http::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            wan_resolver,
            test_bounds(),
        )
        .await
        .unwrap();
        TestServer { addr, log_path, handle, _dir: dir }
    }

    async fn events(&self) -> Vec<sensor_wire::SensorEvent> {
        let content = tokio::fs::read_to_string(&self.log_path).await.unwrap_or_default();
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
    assert!(resp.contains("It works!"));
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
    let _ = send_request(srv.addr, "GET /../../../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events.iter().find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC).unwrap();
    let path = cmd.metadata.get("path").and_then(|v| v.as_str()).unwrap();
    assert!(path.contains("etc/passwd"), "path traversal must be captured: {path}");
    srv.handle.abort();
}

#[tokio::test]
async fn post_body_captured() {
    let srv = TestServer::start().await;
    let body = "username=admin&password=secret";
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{}",
        body.len(), body
    );
    let _ = send_request(srv.addr, &req).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events.iter().find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC).unwrap();
    assert!(cmd.metadata.get("body_preview").is_some());
    assert_eq!(cmd.metadata.get("body_size").and_then(|v| v.as_u64()), Some(body.len() as u64));
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
        assert_eq!(event.metadata.get("protocol_label").and_then(|v| v.as_str()), Some("http"));
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
    assert!(found.is_empty(), "sensor-http must not contain process-spawning code: {found:?}");
}

#[tokio::test]
async fn malformed_request_drops_connection_without_crashing_listener() {
    let srv = TestServer::start().await;
    for seed in 0..5u8 {
        if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
            let garbage: Vec<u8> = (0..2048u32).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
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
    assert!(events.iter().any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION));
    srv.handle.abort();
}

#[tokio::test]
async fn user_agent_captured_in_metadata() {
    let srv = TestServer::start().await;
    let _ = send_request(srv.addr, "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 Bot\r\n\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events.iter().find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC).unwrap();
    let ua = cmd.metadata.get("user_agent").and_then(|v| v.as_str()).unwrap();
    assert!(ua.contains("Mozilla"), "user-agent: {ua}");
    srv.handle.abort();
}

#[tokio::test]
async fn query_string_captured() {
    let srv = TestServer::start().await;
    let _ = send_request(srv.addr, "GET /search?q=test&lang=en HTTP/1.1\r\nHost: test\r\n\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd = events.iter().find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC).unwrap();
    assert_eq!(cmd.metadata.get("path").and_then(|v| v.as_str()), Some("/search"));
    let query = cmd.metadata.get("query").and_then(|v| v.as_str()).unwrap();
    assert!(query.contains("q=test"));
    srv.handle.abort();
}

fn walk_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() { walk(&path, files); }
                else if path.extension().is_some_and(|e| e == "rs") { files.push(path); }
            }
        }
    }
    walk(dir, &mut files);
    files
}
