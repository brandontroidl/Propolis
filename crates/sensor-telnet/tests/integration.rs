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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
async fn nested_shell_exit_restores_the_login_prompt_before_final_logout() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"password").await;

    conn.write_all(b"sh\r\n").await.unwrap();
    read_until_contains(&mut conn, b"# ").await;
    conn.write_all(b"exit\r\n").await.unwrap();
    read_until_contains(&mut conn, b"root@server01:~# ").await;

    conn.write_all(b"cd /tmp\r\n").await.unwrap();
    read_until_contains(&mut conn, b"root@server01:/tmp# ").await;
    conn.write_all(b"exit\r\n").await.unwrap();
    let logout = read_until_contains(&mut conn, b"logout\r\n").await;
    assert!(
        !logout
            .windows(b"root@server01:/tmp# ".len())
            .any(|w| w == b"root@server01:/tmp# "),
        "a closed login shell must not print another prompt: {logout:?}"
    );

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut byte))
        .await
        .expect("server did not close after login-shell exit")
        .unwrap();
    assert_eq!(read, 0, "login-shell exit must close the Telnet session");
    handle.abort();
}

/// Read a shell reply: bytes until one ends in a prompt, or the server closes. Only the tail is
/// checked, so a megabyte of output is not rescanned on every read.
async fn read_reply(conn: &mut TcpStream) -> (usize, bool) {
    let mut total = 0;
    let mut tail = Vec::new();
    let mut chunk = vec![0u8; 65_536];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut chunk))
            .await
            .expect("timed out waiting for the reply")
            .unwrap_or(0);
        if n == 0 {
            return (total, true);
        }
        total += n;
        tail.extend_from_slice(&chunk[..n]);
        tail.drain(..tail.len().saturating_sub(2));
        if tail == b"# " {
            return (total, false);
        }
    }
}

#[tokio::test]
async fn a_connection_that_has_spent_its_egress_allowance_is_dropped_after_that_reply() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"attacker", b"pw").await;

    // Each `cat /dev/zero` answers with one MiB and a prompt; the connection may write 16 MiB.
    let mut answered = 0;
    let mut wire = 0;
    loop {
        assert!(answered < 20, "the connection was never dropped");
        conn.write_all(b"cat /dev/zero\r\n").await.unwrap();
        let (bytes, closed) = read_reply(&mut conn).await;
        wire += bytes;
        if closed {
            break;
        }
        answered += 1;
    }
    // The 16th reply is the one that reaches the cap: it arrives whole, prompt included (the reply
    // loop only counts it as answered by seeing that prompt), and nothing follows it.
    assert_eq!(answered, 16);
    assert!(
        wire >= 16 << 20,
        "the drop came before the allowance was spent: {wire}"
    );
    handle.abort();
}

#[tokio::test]
async fn password_never_appears_in_any_event() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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
async fn a_telnet_connection_keeps_its_own_files_and_a_new_one_starts_clean() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut first = TcpStream::connect(addr).await.unwrap();
    login(&mut first, b"root", b"pass").await;
    first
        .write_all(b"echo telnet-marker-8864 > /tmp/telnet_x\r\n")
        .await
        .unwrap();
    read_until_contains(&mut first, b"# ").await;
    first.write_all(b"cat /tmp/telnet_x\r\n").await.unwrap();
    let seen = read_until_contains(&mut first, b"telnet-marker-8864\r\n").await;
    assert!(!seen.is_empty());

    let mut second = TcpStream::connect(addr).await.unwrap();
    login(&mut second, b"root", b"pass").await;
    second.write_all(b"cat /tmp/telnet_x\r\n").await.unwrap();
    let reply = read_until_contains(&mut second, b"# ").await;
    assert!(
        !String::from_utf8_lossy(&reply).contains("telnet-marker-8864"),
        "a new connection saw the previous connection's file"
    );

    drop(first);
    drop(second);
    handle.abort();
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
        dir.path().join("spool"),
        wan_resolver,
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
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

// -------------------------------------------------------------------------------------------
// evidence capture: raw shell-phase input is spooled when the shared FakeShell flags a binary
// payload (a Mirai/Gafgyt dropper today collapses to a "flood": "binary" marker with the raw
// bytes discarded); a plaintext-only session, and the login/password phase of every session,
// must never be captured.
// -------------------------------------------------------------------------------------------

/// A dropper streaming its payload with no newline yet, cut off when the listener hits
/// `max_duration`. Nothing in this test tells the sensor the bytes are binary: no line is ever
/// completed, so the per-line flood flag is never raised, and the session is ended by the
/// listener rather than by the client. Both of those are the production boundary the unit tests
/// bypass by calling the flag directly, and both were broken - the capture was discarded for
/// want of a flag, and a cancelled capture reported itself complete.
#[tokio::test]
async fn a_payload_cut_off_mid_line_is_still_captured_and_marked_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let bounds = ConnectionBounds {
        // Short enough that the listener cancels this session while the payload is still
        // mid-line, which is the path under test.
        max_duration: Duration::from_secs(2),
        ..test_bounds()
    };
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        wan_resolver,
        bounds,
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;

    // Mostly non-ASCII, and deliberately NO trailing newline: the reader buffers it, the shell
    // never sees a line, and the flood flag is never raised.
    let payload = vec![0xAAu8; 256];
    conn.write_all(&payload).await.unwrap();

    // Hold the connection open and let the listener's max_duration cancel the handler.
    wait_for_upload_event(&log_path).await;
    drop(conn);
    handle.abort();

    let spooled = spooled_files(&spool_dir);
    assert_eq!(spooled.len(), 1, "the cut-off payload must be spooled");
    let stored = std::fs::read(&spooled[0]).unwrap();
    assert_eq!(stored, payload, "the stored bytes are what the client sent");

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("a cancelled session's binary capture must still be recorded");
    assert_eq!(
        upload.metadata["capture_reason"], "binary_shell_payload",
        "{:?}",
        upload.metadata
    );
    // `Cancelled` is the one ending no code inside the handler can record, because the listener
    // drops the whole future: it survives only as the initial value. Without this assertion a
    // cancelled capture could carry any other reason and still pass on `complete` alone.
    assert_eq!(
        upload.metadata["end_reason"], "session_cancelled",
        "{:?}",
        upload.metadata
    );
    assert_eq!(
        upload.metadata["complete"], false,
        "a capture handed over by a cancelled handler is a fragment: {:?}",
        upload.metadata
    );
    assert_eq!(upload.metadata["size"], payload.len() as u64);
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(
        upload.sample.as_ref().unwrap().size,
        payload.len() as u64,
        "the sample the console reads points at the stored bytes"
    );
}

/// How the client ends the session, which is the only thing that can say whether a shell capture
/// holds the whole payload: the sensor has no protocol-defined end of file to go by.
enum Ending {
    /// Stop sending and let `idle_timeout` elapse with the connection still open.
    GoQuiet,
    /// Close the connection cleanly. The peer finished sending.
    CloseCleanly,
    /// Abort with an RST (`SO_LINGER` 0), so the server's next read fails rather than reporting
    /// end-of-file.
    ResetConnection,
    /// Terminate the payload's line and then type `exit`, the way a client that is done says so.
    /// The second ending that must read as complete, and the only one that reaches the handler's
    /// own `ClientLogout` arm rather than a read result inside `read_line`.
    Logout,
}

/// Drive one binary-payload session to `ending` and return the upload event's metadata with the
/// bytes that reached the spool. Every caller sends a payload that is binary and unterminated -
/// only the ending differs, so a difference in the recorded outcome can come from nothing else.
async fn payload_session(bounds: ConnectionBounds, payload: &[u8], ending: Ending) -> Metadata {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        wan_resolver,
        bounds,
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;
    conn.write_all(payload).await.unwrap();

    match ending {
        Ending::GoQuiet => {
            wait_for_upload_event(&log_path).await;
            drop(conn);
        }
        Ending::CloseCleanly => {
            drop(conn);
            wait_for_upload_event(&log_path).await;
        }
        Ending::ResetConnection => {
            // A zero linger makes close send RST instead of FIN, so the server sees a read error
            // rather than end-of-file. Without it this case is indistinguishable from a clean
            // close, and a clean close is the one ending that means the payload was finished.
            //
            // Deprecated because a NON-zero linger blocks the closing thread until the kernel
            // finishes draining. Zero is the opposite case: close returns at once and sends the
            // reset, which is the whole point here. The alternative is a raw `setsockopt` behind
            // `unsafe`, which buys nothing for a test that wants exactly this behavior.
            #[allow(deprecated)]
            conn.set_linger(Some(Duration::ZERO)).unwrap();
            drop(conn);
            wait_for_upload_event(&log_path).await;
        }
        Ending::Logout => {
            // Close the binary line first, so the shell actually sees it and raises the flood
            // flag through the production path, then ask to end the session. The capture
            // therefore holds the payload plus these bytes - what matters here is the ending.
            conn.write_all(b"\r\nexit\r\n").await.unwrap();
            wait_for_upload_event(&log_path).await;
            drop(conn);
        }
    }
    handle.abort();

    let stored_dir = spooled_files(&spool_dir);
    assert_eq!(stored_dir.len(), 1, "exactly one capture per session");
    let stored = std::fs::read(&stored_dir[0]).unwrap();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let upload = content
        .lines()
        .map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).unwrap())
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("the binary capture must be recorded whatever ended the session");
    Metadata {
        json: upload.metadata,
        stored,
    }
}

struct Metadata {
    json: serde_json::Value,
    stored: Vec<u8>,
}

/// An idle session is not a finished one. The payload stops arriving and the reader's
/// `idle_timeout` elapses with the transfer still open, so the bytes are a fragment - but every
/// one of these endings used to run the same "the loop returned, so it is complete" line.
#[tokio::test]
async fn a_payload_abandoned_mid_transfer_is_recorded_as_cut_short_by_the_idle_timeout() {
    let bounds = ConnectionBounds {
        idle_timeout: Duration::from_millis(600),
        max_duration: Duration::from_secs(30),
        ..test_bounds()
    };
    let payload = vec![0xAAu8; 256];
    let m = payload_session(bounds, &payload, Ending::GoQuiet).await;

    assert_eq!(m.stored, payload, "the stored bytes are what was sent");
    assert_eq!(m.json["end_reason"], "idle_timeout", "{:?}", m.json);
    assert_eq!(
        m.json["complete"], false,
        "an idle timeout cut the transfer short: {:?}",
        m.json
    );
}

/// A socket that fails mid-session is also not a finished one, and an RST is the case a clean
/// close is easiest to confuse it with: both end the loop, one after the peer finished sending
/// and one not.
#[tokio::test]
async fn a_payload_ended_by_a_connection_reset_is_recorded_as_a_transport_failure() {
    let payload = vec![0xAAu8; 256];
    let m = payload_session(test_bounds(), &payload, Ending::ResetConnection).await;

    assert_eq!(m.json["end_reason"], "transport_error", "{:?}", m.json);
    assert_eq!(
        m.json["complete"], false,
        "a reset connection left the transfer open: {:?}",
        m.json
    );
}

/// The other side of the same distinction: the peer closed the connection itself, so whatever it
/// sent is whatever it meant to send. This is the ONLY ending in this file that is complete, and
/// it is what stops the fix above from being "label everything incomplete".
#[tokio::test]
async fn a_payload_the_client_finished_sending_before_closing_is_recorded_as_complete() {
    let payload = vec![0xAAu8; 256];
    let m = payload_session(test_bounds(), &payload, Ending::CloseCleanly).await;

    assert_eq!(m.stored, payload);
    assert_eq!(m.json["end_reason"], "peer_closed", "{:?}", m.json);
    assert_eq!(
        m.json["complete"], true,
        "the peer closed the connection itself: {:?}",
        m.json
    );
}

/// The handler's own `exit` arm, which is a different exit path from the peer closing the socket:
/// it is reached from the command loop rather than from a read result inside `read_line`, and it
/// was the one remaining `complete: true` path with no capture test behind it. Without this, the
/// line that records it could be deleted and only the RST/idle/budget tests would notice - all of
/// which expect `false`, so "label everything incomplete" would still pass.
#[tokio::test]
async fn a_payload_followed_by_an_exit_command_is_recorded_as_a_client_logout() {
    let payload = vec![0xAAu8; 256];
    let m = payload_session(test_bounds(), &payload, Ending::Logout).await;

    assert_eq!(m.json["end_reason"], "client_logout", "{:?}", m.json);
    assert_eq!(
        m.json["complete"], true,
        "the client asked to end the session: {:?}",
        m.json
    );
    assert!(
        m.stored.starts_with(&payload),
        "the payload the client sent is still the head of the capture"
    );
}

/// Hitting `max_captured_bytes` stops the sensor reading, so the rest of the payload was never
/// seen: the capture is both a prefix (`truncated`) and unfinished (`complete: false`). The two
/// are different facts - a whole small file is truncated: false, complete: true - and the panel
/// shows them differently.
#[tokio::test]
async fn a_payload_that_exhausts_the_capture_budget_is_recorded_as_a_prefix_and_unfinished() {
    let bounds = ConnectionBounds {
        max_captured_bytes: 512,
        idle_timeout: Duration::from_millis(600),
        ..test_bounds()
    };
    // Comfortably past the budget even after the login phase has spent part of it.
    let payload = vec![0xAAu8; 4096];
    let m = payload_session(bounds, &payload, Ending::GoQuiet).await;

    assert_eq!(m.json["end_reason"], "capture_budget", "{:?}", m.json);
    assert_eq!(
        m.json["complete"], false,
        "the rest of the payload was never read: {:?}",
        m.json
    );
    assert_eq!(
        m.json["truncated"], true,
        "the stored bytes are a prefix: {:?}",
        m.json
    );
    assert!(
        m.stored.len() < payload.len(),
        "stored {} of {} bytes",
        m.stored.len(),
        payload.len()
    );
}

/// Poll the event log for the capture's own `honeypot_malware_upload` line, rather than a fixed
/// sleep - the capture hand-off's worker runs off the connection's response path (see
/// `sensor_framework::handoff`'s module doc), so there is no synchronous point at which "the
/// worker is done" is directly observable.
///
/// Wait on the event line specifically, not on the spooled body: `handoff::process_job` writes the
/// body first and appends the event only after the outbox manifest row is fsynced, so a wait that
/// stops at the spooled file can return before the line every caller here goes on to assert on
/// exists. That window never opens on an idle machine and opened three times at once on a loaded
/// shared CI runner. The body is covered either way, being written strictly earlier.
async fn wait_for_upload_event(log_path: &std::path::Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let content = tokio::fs::read_to_string(log_path)
            .await
            .unwrap_or_default();
        let recorded = content.lines().any(|line| {
            serde_json::from_str::<sensor_wire::SensorEvent>(line)
                .is_ok_and(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        });
        if recorded {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for a honeypot_malware_upload event in {log_path:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn binary_shell_payload_is_captured_as_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
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

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"pass").await;

    // A Mirai/Gafgyt-style binary dropper streamed over the "shell": mostly non-ASCII bytes,
    // which is_binary_line (shell.rs) flags as a binary flood once its lossy-UTF-8-decoded form
    // is >30% non-printable. Every byte here is >= 0x20 so LineReader::feed buffers it into the
    // line rather than discarding it as an ignored control byte.
    let mut binary = vec![0xAAu8; 128];
    binary.extend_from_slice(b"\r\n");
    conn.write_all(&binary).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(conn);

    wait_for_upload_event(&log_path).await;
    handle.abort();

    let spooled = spooled_files(&spool_dir);
    assert_eq!(spooled.len(), 1, "exactly one sample should be spooled");

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("expected a honeypot_malware_upload event for the binary shell payload");
    assert_eq!(upload.sensor, "telnet");
    assert!(upload.authenticated);
    let sample = upload
        .sample
        .as_ref()
        .expect("malware_upload event must carry a sample");
    assert!(
        !sample.sha256.is_empty(),
        "sample must have a non-empty sha256"
    );
    assert!(sample.size > 0, "sample must have a non-zero size");
}

#[tokio::test]
async fn plaintext_session_is_never_captured_and_password_never_reaches_the_spool() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_telnet::start_test_server(
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

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"SuperSecretPassword123").await;
    conn.write_all(b"whoami\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    conn.write_all(b"exit\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    let spooled_count = spooled_files(&spool_dir).len();
    assert_eq!(
        spooled_count, 0,
        "a plaintext-only session must never produce a spooled capture"
    );

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(
        !content.contains("SuperSecretPassword123"),
        "password must never appear anywhere in the event log, spooled capture or otherwise"
    );
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        !events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD),
        "no malware_upload event for a plaintext-only session; got: {:?}",
        events.iter().map(|e| &e.signal_type).collect::<Vec<_>>()
    );
}

/// The captures stored in `dir`: files named by the SHA-256 of their content. The spool also holds a
/// `.staging/` directory, where a body is written before it is published under that name.
fn spooled_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    sensor_framework::spool::is_canonical_sha256_hex(
                        &e.file_name().to_string_lossy(),
                    )
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
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

/// Telnet runs the same terminal as the SSH shell: `cat > f` takes the lines typed after it until
/// Ctrl-D, the file holds them, and the input is captured once as `shell_stdin`. The text is not a
/// binary flood, so the shell's own capture stays empty: each byte goes to one capture.
#[tokio::test]
async fn cat_at_the_telnet_shell_takes_typed_lines_until_ctrl_d_and_captures_them() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"password").await;
    // The command, its input and the Ctrl-D in one write, as a script sends them, CR-NUL Enters
    // included.
    conn.write_all(b"cat > /tmp/typed\r\0#!/bin/sh\r\0echo telnet-dropper\r\0\x04")
        .await
        .unwrap();
    let echoed = read_until_contains(&mut conn, b"root@server01:~# ").await;
    let echoed = String::from_utf8_lossy(&echoed);
    assert!(
        echoed.contains("#!/bin/sh\r\necho telnet-dropper\r\n"),
        "{echoed:?}"
    );
    conn.write_all(b"cat /tmp/typed\r\n").await.unwrap();
    let read_back = read_until_contains(&mut conn, b"telnet-dropper\r\nroot@server01").await;
    assert!(String::from_utf8_lossy(&read_back).contains("#!/bin/sh\r\n"));
    conn.write_all(b"exit\r\n").await.unwrap();
    wait_for_upload_event(&log_path).await;
    drop(conn);
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let uploads: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).unwrap())
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .collect();
    assert_eq!(uploads.len(), 1, "{uploads:?}");
    let metadata = &uploads[0].metadata;
    assert_eq!(metadata["capture_reason"], "shell_stdin");
    assert_eq!(metadata["end_reason"], "transfer_complete");
    assert_eq!(metadata["destination"], "/tmp/typed");
    assert_eq!(metadata["command"], "cat > /tmp/typed");
    assert_eq!(metadata["size"], "#!/bin/sh\necho telnet-dropper\n".len());
    let stored = spooled_files(&dir.path().join("spool"));
    assert_eq!(stored.len(), 1);
    assert_eq!(
        std::fs::read(&stored[0]).unwrap(),
        b"#!/bin/sh\necho telnet-dropper\n"
    );
}

/// A `read` at the telnet shell answers when Enter hands it its line, as a terminal's does, and
/// what was typed after that Enter, in the same write, is the next command.
#[tokio::test]
async fn a_read_at_the_telnet_shell_answers_on_its_line() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();
    let mut conn = TcpStream::connect(addr).await.unwrap();
    login(&mut conn, b"root", b"password").await;
    conn.write_all(b"read x; echo got=$x\r\0hello\r\0echo after\r\0")
        .await
        .unwrap();
    let reply = read_until_contains(&mut conn, b"after\r\nroot@server01:~# ").await;
    let reply = String::from_utf8_lossy(&reply);
    assert!(reply.contains("hello\r\ngot=hello\r\n"), "{reply:?}");
    conn.write_all(b"exit\r\n").await.unwrap();
    drop(conn);
    handle.abort();
}
