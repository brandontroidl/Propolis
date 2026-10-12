//! The ADB sensor under the session accounting allocator, as its binary runs: a session that grows
//! its shell past what a session may hold is ended, and gives back what it held.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_adb::adb_proto::{self, Header};
use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

/// One message, or `None` once the server has closed the connection.
async fn read_message(stream: &mut TcpStream) -> Option<(Header, Vec<u8>)> {
    let mut header_buf = [0u8; adb_proto::HEADER_LEN];
    stream.read_exact(&mut header_buf).await.ok()?;
    let header = Header::parse(&header_buf).expect("well-formed header");
    let mut data = vec![0u8; header.data_length as usize];
    if header.data_length > 0 {
        stream.read_exact(&mut data).await.ok()?;
    }
    Some((header, data))
}

/// A connection with an interactive shell stream open; the server's stream id.
async fn shell(addr: std::net::SocketAddr) -> (TcpStream, u32) {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    conn.write_all(&adb_proto::build_cnxn(&adb_proto::host_banner()))
        .await
        .unwrap();
    let (cnxn, _) = read_message(&mut conn).await.expect("CNXN");
    assert_eq!(cnxn.command, adb_proto::A_CNXN);
    conn.write_all(&adb_proto::build_open(7, "shell:"))
        .await
        .unwrap();
    let (okay, _) = read_message(&mut conn).await.expect("OKAY");
    assert_eq!(okay.command, adb_proto::A_OKAY);
    let server_id = okay.arg0;
    // The shell's first prompt.
    let (prompt, _) = read_message(&mut conn).await.expect("prompt");
    conn.write_all(&adb_proto::build_okay(prompt.arg1, prompt.arg0))
        .await
        .unwrap();
    (conn, server_id)
}

/// Send one line to the shell stream and wait for its prompt, acknowledging what it writes.
/// False once the server has closed the connection.
async fn send_line(conn: &mut TcpStream, server_id: u32, text: &str) -> bool {
    send_bytes(conn, server_id, format!("{text}\n").as_bytes()).await
}

/// [`send_line`] for raw bytes, which must end the line themselves.
async fn send_bytes(conn: &mut TcpStream, server_id: u32, bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).into_owned();
    if conn
        .write_all(&adb_proto::build_wrte(7, server_id, bytes))
        .await
        .is_err()
    {
        return false;
    }
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), read_message(conn)).await {
            Ok(None) => return false,
            Ok(Some((header, data))) if header.command == adb_proto::A_WRTE => {
                out.extend_from_slice(&data);
                let _ = conn
                    .write_all(&adb_proto::build_okay(header.arg1, header.arg0))
                    .await;
                if out.ends_with(b"# ") || out.ends_with(b"$ ") {
                    return true;
                }
            }
            Ok(Some(_)) => {}
            Err(_) => panic!("no prompt and no close after {text:?}"),
        }
    }
}

/// Whether the server closes the connection within `within` while the client sends nothing.
async fn closes_while_idle(conn: &mut TcpStream, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(None) = tokio::time::timeout(Duration::from_millis(100), read_message(conn)).await
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_past_its_memory_is_ended_and_gives_it_back() {
    tokio::spawn(session_memory::watchdog());
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_adb::start_test_server(
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

    // Over the retained limit and far under the peak, then quiet: only the check between messages
    // can end this session, and it does, without waiting for another message.
    session_memory::set_retained_limit(1024 * 1024);
    let (mut conn, server_id) = shell(addr).await;
    // A binary payload streamed at the shell first, so a capture is in flight when the session is
    // ended and records why.
    let mut binary = vec![0xAAu8; 128];
    binary.push(b'\n');
    assert!(send_bytes(&mut conn, server_id, &binary).await);
    let mut open = send_line(&mut conn, server_id, "set -- '' ''").await;
    for _ in 0..16 {
        if !open {
            break;
        }
        open = send_line(&mut conn, server_id, "set -- \"$@\" \"$@\"").await;
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

    // Asked to let go while it waits for its next message: a quiet session holding the most of a
    // pool that newcomers need is ended at once, not at its idle timeout. It grows with room to
    // spare; then the pool shrinks to what it keeps plus 512 KiB (an Android shell is small), for
    // four sessions, so the newcomers run it out and it is the one over its share.
    session_memory::set_retained_limit(64 * 1024 * 1024);
    let (mut holder, holder_id) = shell(addr).await;
    assert!(send_line(&mut holder, holder_id, "set -- '' ''").await);
    for _ in 0..15 {
        assert!(send_line(&mut holder, holder_id, "set -- \"$@\" \"$@\"").await);
    }
    assert!(!closes_while_idle(&mut holder, Duration::from_millis(500)).await);
    session_memory::configure(session_memory::pool_used() + 512 * 1024, 4).unwrap();
    let mut newcomers = Vec::new();
    let mut ended = false;
    for _ in 0..12 {
        newcomers.push(shell(addr).await);
        if closes_while_idle(&mut holder, Duration::from_millis(400)).await {
            ended = true;
            break;
        }
    }
    assert!(ended, "the quiet holder was ended for the newcomers");
    drop((holder, newcomers));
    session_memory::configure(u64::MAX / 2, 16).unwrap();
    session_memory::set_retained_limit(session_memory::RETAINED_LIMIT_BYTES);

    let (mut conn, server_id) = shell(addr).await;

    // Doubling the positional parameters until the session is over what it may hold: the sensor
    // closes the connection rather than following it.
    let started = Instant::now();
    let mut closed = false;
    let mut line = b"set -- '' ''\n".to_vec();
    while started.elapsed() < Duration::from_secs(60) {
        if conn
            .write_all(&adb_proto::build_wrte(7, server_id, &line))
            .await
            .is_err()
        {
            closed = true;
            break;
        }
        line = b"set -- \"$@\" \"$@\"\n".to_vec();
        // Acknowledge whatever the shell writes back until it goes quiet or the server closes.
        loop {
            match tokio::time::timeout(Duration::from_millis(200), read_message(&mut conn)).await {
                Ok(None) => {
                    closed = true;
                    break;
                }
                Ok(Some((header, _))) if header.command == adb_proto::A_WRTE => {
                    let _ = conn
                        .write_all(&adb_proto::build_okay(header.arg1, header.arg0))
                        .await;
                }
                Ok(Some(_)) => {}
                Err(_) => break,
            }
        }
        if closed {
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
    drop(shell(addr).await);
    handle.abort();
}
