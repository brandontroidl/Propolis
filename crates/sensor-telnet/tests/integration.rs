//! Real-client integration tests: connects a plain `tokio::net::TcpStream` to this crate's own
//! honeypot and verifies events, protocol_label, and the password-never-captured invariant end to
//! end. Telnet has no cryptography or handshake beyond IAC negotiation, so a raw TCP client (as
//! the task brief specifies) is a faithful enough stand-in for a real telnet client.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

/// Read from `stream` until the accumulated bytes contain `needle`, or panic after 3s. Telnet
/// negotiation/prompt bytes can arrive split across multiple TCP segments, so this cannot assume
/// one `read` call is enough.
async fn read_until_contains(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let n = stream.read(&mut chunk).await.expect("read failed");
            assert!(n > 0, "connection closed before {needle:?} was seen");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(needle.len()).any(|w| w == needle) {
                return;
            }
        }
    })
    .await;
    result.unwrap_or_else(|_| panic!("timed out waiting for {needle:?}, got {buf:?}"));
    buf
}

async fn login(conn: &mut TcpStream, username: &[u8], password: &[u8]) {
    read_until_contains(conn, b"login: ").await;
    conn.write_all(username).await.unwrap();
    conn.write_all(b"\r\n").await.unwrap();
    read_until_contains(conn, b"Password: ").await;
    conn.write_all(password).await.unwrap();
    conn.write_all(b"\r\n").await.unwrap();
    read_until_contains(conn, b"# ").await;
}

// -------------------------------------------------------------------------------------------
// given suite (task brief)
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn login_and_command_capture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"attacker", b"hunter2").await;
    conn.write_all(b"uname -a\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    conn.write_all(b"exit\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    let signal_types: Vec<&str> = events.iter().map(|e| e.signal_type.as_str()).collect();
    assert!(
        signal_types.contains(&sensor_wire::SIGNAL_HONEYPOT_CONNECTION),
        "missing honeypot_connection event; got: {signal_types:?}"
    );
    assert!(
        signal_types.contains(&sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT),
        "missing honeypot_login_attempt event; got: {signal_types:?}"
    );
    assert!(
        signal_types.contains(&sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC),
        "missing honeypot_command_exec event; got: {signal_types:?}"
    );

    let cmd_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert_eq!(
        cmd_event.metadata.get("command").and_then(|v| v.as_str()),
        Some("uname -a")
    );
}

#[tokio::test]
async fn password_never_appears_in_any_event() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"SuperSecretPassword123").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(
        !content.contains("SuperSecretPassword123"),
        "password must never appear in any event"
    );
}

#[tokio::test]
async fn protocol_label_is_telnet_on_all_events() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;
    conn.write_all(b"whoami\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!events.is_empty());
    for event in &events {
        assert_eq!(event.sensor, "telnet");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        let label = event
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str());
        assert_eq!(label, Some("telnet"), "protocol_label must be 'telnet'");
    }
}

#[test]
fn never_exec_static_check() {
    // Mirrors sensor-ssh's tests/shell_test.rs::never_exec_static_check, scoped to
    // sensor-telnet's own source. sensor-framework (where FakeFs/FakeShell actually live, the two
    // highest-priority security surfaces per shell.rs's own module doc) is already covered by
    // sensor-ssh's copy of this same check, so it is deliberately not re-scanned here.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = walkdir_or_manual(&src_dir);
    assert!(
        !files.is_empty(),
        "expected to find sensor-telnet source files at {}",
        src_dir.display()
    );

    let mut found_exec = Vec::new();
    for entry in &files {
        let content = std::fs::read_to_string(entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found_exec.push(entry.display().to_string());
        }
    }
    assert!(
        found_exec.is_empty(),
        "sensor-telnet must not contain process-spawning code: {found_exec:?}"
    );
}

#[tokio::test]
async fn malformed_random_bytes_drop_connection_without_crashing_listener() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    // A pseudo-random byte stream, heavy on 0xFF (IAC) to specifically stress the negotiation
    // parser, written then immediately dropped - repeated several times with different seeds.
    for seed in 0..5u8 {
        if let Ok(mut conn) = TcpStream::connect(addr).await {
            let garbage: Vec<u8> = (0..2048u32)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
                .collect();
            let _ = conn.write_all(&garbage).await;
            drop(conn);
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The listener must still be accepting new connections.
    let conn = TcpStream::connect(addr).await;
    assert!(conn.is_ok(), "accept loop must survive malformed input");
    handle.abort();
}

// -------------------------------------------------------------------------------------------
// additional coverage, not in the brief's given suite.
//
// None of the five tests above can distinguish this implementation from one that (a) hardcodes
// `authenticated`/`source_ip`/`wan_ip` rather than reading real connection state, (b) accepts only
// specific credentials instead of all of them, (c) leaks a stray IAC byte into the captured
// username when a client sends option negotiation mid-line, or (d) lets the shared FakeShell's
// outbound-fetch simulation actually dial out. Mirrors sensor-ssh's own rationale for the same
// reason: the given fixtures are necessary, not sufficient.
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn connection_event_unauthenticated_login_event_authenticated_with_username() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    let conn_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
        .unwrap();
    assert!(!conn_event.authenticated);

    let login_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert!(login_event.authenticated);
    assert_eq!(
        login_event
            .metadata
            .get("username")
            .and_then(|v| v.as_str()),
        Some("root")
    );
}

#[tokio::test]
async fn accepts_all_credentials() {
    // The design spec's "Accept all credentials, emit honeypot_login_attempt
    // (authenticated=true)" - any username/password combination succeeds; there is no real
    // authentication check. Reaching the shell prompt at all proves the login was accepted.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(
        &mut conn,
        b"totally-made-up-user",
        b"totally-made-up-password",
    )
    .await;
    handle.abort();
}

#[tokio::test]
async fn iac_bytes_in_username_do_not_corrupt_the_line_buffer() {
    // "Don't crash on IAC sequences embedded in data" - an IAC negotiation sequence arriving
    // mid-line must be stripped without leaving stray bytes in the captured username.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    read_until_contains(&mut conn, b"login: ").await;
    // "ro" + IAC WILL <terminal-type opt 24> (a client spontaneously offering an option mid-line,
    // which real telnet clients do) + "ot" + CRLF.
    let mut line = b"ro".to_vec();
    line.extend_from_slice(&[255, 251, 24]);
    line.extend_from_slice(b"ot\r\n");
    conn.write_all(&line).await.unwrap();
    read_until_contains(&mut conn, b"Password: ").await;
    conn.write_all(b"pass\r\n").await.unwrap();
    read_until_contains(&mut conn, b"# ").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let login_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login_event
            .metadata
            .get("username")
            .and_then(|v| v.as_str()),
        Some("root"),
        "IAC bytes embedded mid-line must be stripped, not leak into the captured username"
    );
}

#[tokio::test]
async fn multiple_commands_each_captured_as_separate_events() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;
    conn.write_all(b"whoami\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.write_all(b"id\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.write_all(b"pwd\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let commands: Vec<&str> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .filter_map(|e| e.metadata.get("command").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(commands, vec!["whoami", "id", "pwd"]);
}

#[tokio::test]
async fn no_outbound_connections_from_wget_in_shell() {
    // Mirrors sensor-ssh's own `no_outbound_connections` test: the shared FakeShell's wget/curl
    // handlers must perform zero real network I/O regardless of which sensor drives them.
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = connection_count.clone();
    let target_task = tokio::spawn(async move {
        loop {
            if let Ok((_stream, _addr)) = target_listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;
    let cmd = format!(
        "wget http://127.0.0.1:{}/malware.bin\r\n",
        target_addr.port()
    );
    conn.write_all(cmd.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(conn);
    handle.abort();
    target_task.abort();

    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor-telnet must open ZERO outbound connections"
    );
}

fn walkdir_or_manual(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
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
