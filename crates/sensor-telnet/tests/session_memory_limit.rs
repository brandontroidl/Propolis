//! The telnet sensor under the session accounting allocator, as its binary runs: a session that
//! grows its shell past what a session may hold is ended, and gives back what it held.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

async fn read_until_contains(stream: &mut TcpStream, needle: &[u8]) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(5), async {
        while !buf.windows(needle.len()).any(|w| w == needle) {
            let n = stream.read(&mut chunk).await.expect("read failed");
            assert!(n > 0, "closed before {needle:?}");
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("the prompt arrives");
}

/// A connection past login, at its first prompt.
async fn logged_in(addr: std::net::SocketAddr) -> TcpStream {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    read_until_contains(&mut conn, b"login: ").await;
    conn.write_all(b"root\r\n").await.unwrap();
    read_until_contains(&mut conn, b"Password: ").await;
    conn.write_all(b"root\r\n").await.unwrap();
    read_until_contains(&mut conn, b"# ").await;
    conn
}

/// Send one line and wait for the next prompt. False once the server has closed the connection.
async fn send_line(conn: &mut TcpStream, text: &str) -> bool {
    if conn
        .write_all(format!("{text}\r\n").as_bytes())
        .await
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), conn.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => return false,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.ends_with(b"# ") {
                    return true;
                }
            }
            Err(_) => panic!("no prompt and no close after {text:?}"),
        }
    }
}

/// Whether the server closes the connection within `within` while the client sends nothing.
async fn closes_while_idle(conn: &mut TcpStream, within: Duration) -> bool {
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(Ok(0) | Err(_)) =
            tokio::time::timeout(Duration::from_millis(100), conn.read(&mut chunk)).await
        {
            return true;
        }
    }
    false
}

/// With every session slot taken, a new connection could not be accounted: the sensor closes it
/// at once rather than serve it unbounded.
async fn refused_without_a_slot(addr: std::net::SocketAddr) {
    use tokio::io::AsyncReadExt;
    let held: Vec<_> = (0..session_memory::SLOT_COUNT)
        .map(|_| session_memory::scope(std::future::ready(())))
        .collect();
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    let closed = loop {
        match tokio::time::timeout_at(deadline.into(), conn.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => break true,
            Ok(Ok(_)) => {}
            Err(_) => break false,
        }
    };
    drop(held);
    assert!(closed, "a session with no slot was closed, not served");
}

/// Asked to let go while it waits for its next line, or with `waiting` running and waiting for
/// its input: a quiet session holding the most of a pool that newcomers need is ended at once,
/// not at its idle timeout. It grows with room to spare; then the pool shrinks to what it keeps
/// plus 1.5 MiB, for four sessions, so the newcomers run it out and it is the one over its share.
async fn quiet_holder_is_ended(addr: std::net::SocketAddr, waiting: Option<&str>) {
    session_memory::set_retained_limit(64 * 1024 * 1024);
    let mut holder = logged_in(addr).await;
    assert!(send_line(&mut holder, "set -- '' ''").await);
    for _ in 0..15 {
        assert!(send_line(&mut holder, "set -- \"$@\" \"$@\"").await);
    }
    if let Some(command) = waiting {
        holder
            .write_all(format!("{command}\r\nhalf a file\r\n").as_bytes())
            .await
            .unwrap();
    }
    assert!(!closes_while_idle(&mut holder, Duration::from_millis(500)).await);
    session_memory::configure(session_memory::pool_used() + 1536 * 1024, 4).unwrap();
    let mut newcomers = Vec::new();
    let mut ended = false;
    for _ in 0..12 {
        newcomers.push(logged_in(addr).await);
        if closes_while_idle(&mut holder, Duration::from_millis(400)).await {
            ended = true;
            break;
        }
    }
    assert!(
        ended,
        "the quiet holder ({waiting:?}) was ended for the newcomers"
    );
    drop((holder, newcomers));
    session_memory::configure(u64::MAX / 2, 16).unwrap();
    session_memory::set_retained_limit(session_memory::RETAINED_LIMIT_BYTES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_past_its_memory_is_ended_and_gives_it_back() {
    tokio::spawn(session_memory::watchdog());
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            max_duration: Duration::from_secs(120),
            max_captured_bytes: 1_000_000,
            // A per-source cap of 16, so one test client can open enough sessions to run a small
            // pool out.
            max_concurrent: 64,
        },
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // Over the retained limit and far under the peak, then quiet: only the check between lines
    // can end this session, and it does, without waiting for another line.
    session_memory::set_retained_limit(1024 * 1024);
    let mut conn = logged_in(addr).await;
    // A binary payload streamed at the shell first, so a capture is in flight when the session is
    // ended and records why.
    let mut binary = vec![0xAAu8; 128];
    binary.extend_from_slice(b"\r\n");
    conn.write_all(&binary).await.unwrap();
    read_until_contains(&mut conn, b"# ").await;
    let mut open = send_line(&mut conn, "set -- '' ''").await;
    for _ in 0..16 {
        if !open {
            break;
        }
        open = send_line(&mut conn, "set -- \"$@\" \"$@\"").await;
    }
    assert!(
        !open || closes_while_idle(&mut conn, Duration::from_secs(5)).await,
        "a session holding past its retained limit was ended"
    );
    drop(conn);
    session_memory::set_retained_limit(session_memory::RETAINED_LIMIT_BYTES);
    // The capture it had in flight says the session was ended for its memory.
    let log = dir.path().join("events.jsonl");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let content = tokio::fs::read_to_string(&log).await.unwrap_or_default();
        let ended_for_memory = content
            .lines()
            .filter_map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).ok())
            .any(|e| {
                e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD
                    && e.metadata.get("end_reason").and_then(|v| v.as_str()) == Some("memory_limit")
            });
        if ended_for_memory {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no capture recorded end_reason memory_limit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quiet_holder_is_ended(addr, None).await;
    quiet_holder_is_ended(addr, Some("cat > /tmp/held")).await;

    let mut conn = logged_in(addr).await;
    conn.write_all(b"set -- '' ''\r\n").await.unwrap();

    // Doubling the positional parameters until the session is over what it may hold: the sensor
    // closes the connection rather than following it.
    let started = Instant::now();
    let mut chunk = [0u8; 4096];
    let mut closed = false;
    while started.elapsed() < Duration::from_secs(60) {
        if conn.write_all(b"set -- \"$@\" \"$@\"\r\n").await.is_err() {
            closed = true;
            break;
        }
        if let Ok(Ok(0) | Err(_)) =
            tokio::time::timeout(Duration::from_millis(200), conn.read(&mut chunk)).await
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "the session was ended, not followed for a minute");

    let deadline = Instant::now() + Duration::from_secs(10);
    while session_memory::pool_used() > 256 * 1024 {
        assert!(
            Instant::now() < deadline,
            "the pool still holds {}",
            session_memory::pool_used()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    refused_without_a_slot(addr).await;
    drop(logged_in(addr).await);
    handle.abort();
}
