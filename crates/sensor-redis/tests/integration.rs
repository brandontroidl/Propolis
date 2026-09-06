//! Real-client integration tests: connects a plain `tokio::net::TcpStream` speaking raw RESP to
//! this crate's own honeypot and verifies events, protocol_label, and the credential-never-
//! captured invariant end to end. Redis has no cryptography or handshake beyond the RESP framing
//! itself, so a hand-rolled RESP client (as the task brief specifies) is a faithful enough
//! stand-in for `redis-cli`/a client library - and, unlike a unit test, this is the only layer
//! that actually exercises `handler::handle_connection`'s and `handler::RespReader`'s socket I/O
//! loop rather than the pure dispatch logic `src/handler.rs`'s own tests already cover.

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

async fn start_server() -> (
    std::net::SocketAddr,
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_redis::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        wan_resolver,
        test_bounds(),
    )
    .await
    .unwrap();
    (addr, log_path, handle, dir)
}

async fn read_events(log_path: &std::path::Path) -> Vec<sensor_wire::SensorEvent> {
    let content = tokio::fs::read_to_string(log_path).await.unwrap();
    content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Encode and send one command as a RESP multi-bulk array - what a real `redis-cli`/client
/// library sends.
async fn send_multibulk(conn: &mut TcpStream, parts: &[&str]) {
    let mut buf = format!("*{}\r\n", parts.len()).into_bytes();
    for p in parts {
        buf.extend_from_slice(format!("${}\r\n", p.len()).as_bytes());
        buf.extend_from_slice(p.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    conn.write_all(&buf).await.unwrap();
}

/// Send one command as an inline request - what a plain `nc`/telnet-style probe sends.
async fn send_inline(conn: &mut TcpStream, line: &str) {
    conn.write_all(line.as_bytes()).await.unwrap();
    conn.write_all(b"\r\n").await.unwrap();
}

/// Read from `stream` until the accumulated bytes contain `needle`, or panic after 3s. A RESP
/// reply can arrive split across multiple TCP segments, so this cannot assume one `read` call is
/// enough - mirrors sensor-telnet's own `tests/integration.rs` helper of the same name.
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

// -------------------------------------------------------------------------------------------
// given suite (task brief)
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn ping_pong_round_trip_inline() {
    let (addr, _log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_inline(&mut conn, "PING").await;
    let reply = read_until_contains(&mut conn, b"+PONG\r\n").await;
    assert_eq!(reply, b"+PONG\r\n");
    handle.abort();
}

#[tokio::test]
async fn ping_pong_round_trip_multibulk() {
    let (addr, _log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(&mut conn, &["PING"]).await;
    let reply = read_until_contains(&mut conn, b"+PONG\r\n").await;
    assert_eq!(reply, b"+PONG\r\n");
    handle.abort();
}

#[tokio::test]
async fn auth_credential_capture_password_not_in_events() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(&mut conn, &["AUTH", "SuperSecretPassword123"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    let login_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .expect("missing honeypot_login_attempt event");
    assert!(login_event.authenticated);

    let raw_content = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(
        !raw_content.contains("SuperSecretPassword123"),
        "password must never appear in the event log"
    );
}

#[tokio::test]
async fn set_get_responses_correct() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();

    send_multibulk(&mut conn, &["SET", "foo", "bar"]).await;
    let set_reply = read_until_contains(&mut conn, b"+OK\r\n").await;
    assert_eq!(set_reply, b"+OK\r\n");

    send_multibulk(&mut conn, &["GET", "foo"]).await;
    let get_reply = read_until_contains(&mut conn, b"$3\r\nbar\r\n").await;
    assert_eq!(
        get_reply, b"$3\r\nbar\r\n",
        "GET must return what this session SET; nil here contradicted the +OK"
    );

    send_multibulk(&mut conn, &["GET", "never-set"]).await;
    let get_reply = read_until_contains(&mut conn, b"$-1\r\n").await;
    assert_eq!(get_reply, b"$-1\r\n", "an unset key is nil");

    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    let set_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("missing honeypot_command_exec event for SET");
    assert_eq!(
        set_event.metadata.get("key").and_then(|v| v.as_str()),
        Some("foo")
    );
    assert_eq!(
        set_event.metadata.get("value").and_then(|v| v.as_str()),
        Some("bar")
    );
}

#[tokio::test]
async fn config_set_dir_logged_as_indicator() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(&mut conn, &["CONFIG", "SET", "dir", "/etc/cron.d"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    let event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("missing honeypot_command_exec event for CONFIG SET dir");
    assert_eq!(
        event.metadata.get("command").and_then(|v| v.as_str()),
        Some("CONFIG SET")
    );
    assert_eq!(
        event.metadata.get("param").and_then(|v| v.as_str()),
        Some("dir")
    );
    assert_eq!(
        event.metadata.get("value").and_then(|v| v.as_str()),
        Some("/etc/cron.d")
    );
}

#[tokio::test]
async fn slaveof_logged_as_indicator() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(&mut conn, &["SLAVEOF", "198.51.100.50", "6379"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    let event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("missing honeypot_command_exec event for SLAVEOF");
    assert_eq!(
        event.metadata.get("command").and_then(|v| v.as_str()),
        Some("SLAVEOF")
    );
}

#[tokio::test]
async fn protocol_label_is_redis_on_all_events() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();

    send_multibulk(&mut conn, &["AUTH", "pw"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["SET", "k", "v"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["CONFIG", "SET", "dbfilename", "shell.php"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["SLAVEOF", "198.51.100.50", "6379"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["EVAL", "return 1", "0"]).await;
    read_until_contains(&mut conn, b"\r\n").await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    assert!(
        events.len() >= 6,
        "expected connection + 5 command events, got {events:?}"
    );
    for event in &events {
        assert_eq!(event.sensor, "redis");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        let label = event
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str());
        assert_eq!(
            label,
            Some("redis"),
            "protocol_label must be 'redis' on {event:?}"
        );
    }
}

#[test]
fn never_exec_static_check() {
    // Mirrors sensor-telnet's tests/integration.rs::never_exec_static_check, scoped to
    // sensor-redis's own source. sensor-framework is covered by sensor-ssh's copy of this same
    // check.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = walkdir_or_manual(&src_dir);
    assert!(
        !files.is_empty(),
        "expected to find sensor-redis source files at {}",
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
        "sensor-redis must not contain process-spawning code: {found_exec:?}"
    );
}

#[tokio::test]
async fn malformed_resp_does_not_crash_listener() {
    let (addr, _log_path, handle, _dir) = start_server().await;

    // A pseudo-random byte stream heavy on '*' and '$' (the RESP framing bytes) to specifically
    // stress the multibulk parser, written then immediately dropped - repeated with different
    // seeds, mirroring sensor-telnet's own malformed-input resilience test.
    for seed in 0..5u8 {
        if let Ok(mut conn) = TcpStream::connect(addr).await {
            let garbage: Vec<u8> = (0..2048u32)
                .map(|i| match i % 7 {
                    0 => b'*',
                    1 => b'$',
                    _ => (i as u8).wrapping_mul(31).wrapping_add(seed),
                })
                .collect();
            let _ = conn.write_all(&garbage).await;
            drop(conn);
        }
    }

    // A handful of structurally-specific malformed RESP payloads: a huge non-terminated
    // multibulk count claim, a negative bulk length, and a bulk marker with no length at all.
    for payload in [
        &b"*999999999999\r\n"[..],
        &b"*1\r\n$-999\r\n"[..],
        &b"*1\r\n$\r\n"[..],
        &b"*abc123!!!\r\n"[..],
    ] {
        if let Ok(mut conn) = TcpStream::connect(addr).await {
            let _ = conn.write_all(payload).await;
            drop(conn);
        }
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The listener must still be accepting new connections and speaking RESP correctly.
    let mut conn = TcpStream::connect(addr)
        .await
        .expect("accept loop must survive malformed input");
    send_inline(&mut conn, "PING").await;
    let reply = read_until_contains(&mut conn, b"+PONG\r\n").await;
    assert_eq!(reply, b"+PONG\r\n");
    handle.abort();
}

// -------------------------------------------------------------------------------------------
// additional coverage, not in the brief's given suite.
//
// None of the tests above can distinguish this implementation from one that (a) hardcodes
// `authenticated`/`source_ip`/`wan_ip` rather than reading real connection state, (b) leaks a
// stray connection event when none should fire, (c) forgets to gate GET on the deliberate
// stateless simplification, or (d) lets EVAL/SLAVEOF actually attempt a real network action.
// Mirrors sensor-telnet's own rationale for the same reason: the given fixtures are necessary,
// not sufficient.
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn connection_event_emitted_before_any_command() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let conn = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    assert_eq!(
        events.len(),
        1,
        "a bare connect/disconnect must emit exactly one event"
    );
    assert_eq!(
        events[0].signal_type,
        sensor_wire::SIGNAL_HONEYPOT_CONNECTION
    );
    assert!(!events[0].authenticated);
}

#[tokio::test]
async fn unknown_command_returns_error_reply_with_no_event() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_inline(&mut conn, "FOOBARBAZ").await;
    let reply = read_until_contains(&mut conn, b"\r\n").await;
    assert!(reply.starts_with(b"-ERR"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    assert!(
        events
            .iter()
            .all(|e| e.signal_type != sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC),
        "an unknown command must never emit honeypot_command_exec"
    );
}

#[tokio::test]
async fn eval_returns_error_and_logs_indicator() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(
        &mut conn,
        &["EVAL", "return redis.call('set','x','1')", "0"],
    )
    .await;
    let reply = read_until_contains(&mut conn, b"\r\n").await;
    assert!(reply.starts_with(b"-"), "EVAL must reply an error");
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    let event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("missing honeypot_command_exec event for EVAL");
    assert_eq!(
        event.metadata.get("command").and_then(|v| v.as_str()),
        Some("EVAL")
    );
}

#[tokio::test]
async fn info_contains_redis_version_and_linux() {
    let (addr, _log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(&mut conn, &["INFO"]).await;
    let reply = read_until_contains(&mut conn, b"redis_version").await;
    let text = String::from_utf8_lossy(&reply);
    assert!(text.starts_with('$'), "INFO must reply a bulk string");
    assert!(text.contains("Linux"));
    handle.abort();
}

#[tokio::test]
async fn config_get_returns_array_reply() {
    let (addr, _log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();
    send_multibulk(&mut conn, &["CONFIG", "GET", "*"]).await;
    let mut chunk = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
    assert!(
        chunk[..n].starts_with(b"*"),
        "CONFIG GET must reply an array"
    );
    handle.abort();
}

#[tokio::test]
async fn auth_then_set_authenticated_field_true_over_real_connection() {
    let (addr, log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();

    send_multibulk(&mut conn, &["SET", "k1", "v1"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["AUTH", "pw"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["SET", "k2", "v2"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let events = read_events(&log_path).await;
    let set_events: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .collect();
    assert_eq!(set_events.len(), 2);
    assert!(
        !set_events[0].authenticated,
        "SET before AUTH must be authenticated=false"
    );
    assert!(
        set_events[1].authenticated,
        "SET after AUTH must be authenticated=true"
    );
}

#[tokio::test]
async fn multiple_pipelined_commands_in_one_write_are_each_dispatched() {
    let (addr, _log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();

    let mut pipeline = Vec::new();
    pipeline.extend_from_slice(b"*1\r\n$4\r\nPING\r\n");
    pipeline.extend_from_slice(b"*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n");
    pipeline.extend_from_slice(b"*1\r\n$4\r\nPING\r\n");
    conn.write_all(&pipeline).await.unwrap();

    // Three replies expected back to back: +PONG, +OK, +PONG.
    let expected = b"+PONG\r\n+OK\r\n+PONG\r\n";
    let reply = read_until_contains(&mut conn, expected).await;
    assert_eq!(reply, expected);
    handle.abort();
}

#[tokio::test]
async fn no_outbound_connections_during_full_command_sequence() {
    // Mirrors sensor-telnet's own `no_outbound_connections_from_wget_in_shell` test: every
    // command this sensor recognizes - including the ones a real attacker would use to try to
    // make it reach out (SLAVEOF, EVAL) - must never open a real network connection anywhere.
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

    let (addr, _log_path, handle, _dir) = start_server().await;
    let mut conn = TcpStream::connect(addr).await.unwrap();

    send_multibulk(&mut conn, &["AUTH", "pw"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(
        &mut conn,
        &["SLAVEOF", "127.0.0.1", &target_addr.port().to_string()],
    )
    .await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(
        &mut conn,
        &["EVAL", "return redis.call('slaveof','127.0.0.1','1')", "0"],
    )
    .await;
    read_until_contains(&mut conn, b"\r\n").await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(conn);
    handle.abort();
    target_task.abort();

    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor-redis must open ZERO outbound connections, even when told to SLAVEOF itself"
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
