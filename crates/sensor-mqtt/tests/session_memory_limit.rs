//! The MQTT sensor under the session accounting allocator, as its binary runs. A PUBLISH body is
//! buffered whole before it is parsed, so a client that declares 256 KiB and sends most of it
//! holds that much of the sensor's heap until its idle timeout; hundreds of them, next to the
//! capture budget, pushed the unit past `MemoryMax`. Pending bodies are charged to the session pool
//! instead, and the sessions the pool cannot hold are ended.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, WanResolver,
};
use sensor_wire::{SIGNAL_HONEYPOT_SESSION_END, SensorEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

const CONNACK: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
const DECLARED: usize = 262_143;
const SENT: usize = 200_000;

fn connect_packet() -> Vec<u8> {
    let mut packet = vec![0x10, 14, 0x00, 0x04];
    packet.extend_from_slice(b"MQTT");
    packet.extend_from_slice(&[0x04, 0x02, 0x00, 0x00, 0x00, 0x02]);
    packet.extend_from_slice(b"m1");
    packet
}

/// A QoS 0 PUBLISH header declaring `DECLARED` bytes, then the first `SENT` of them.
fn partial_publish() -> Vec<u8> {
    let mut packet = vec![0x30];
    let mut v = DECLARED;
    loop {
        let mut b = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            b |= 0x80;
        }
        packet.push(b);
        if v == 0 {
            break;
        }
    }
    packet.extend_from_slice(&[0x00, 0x01, b'p']);
    packet.resize(packet.len() + SENT - 3, b'a');
    packet
}

/// Whether the server has closed the connection: a read sees the end (or a reset) within `within`.
async fn closed_within(conn: &mut TcpStream, within: Duration) -> bool {
    let mut chunk = [0u8; 64];
    matches!(
        tokio::time::timeout(within, conn.read(&mut chunk)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn events(path: &std::path::Path) -> Vec<SensorEvent> {
    tokio::fs::read_to_string(path)
        .await
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// With every slot taken, a new connection could not be accounted: the sensor closes it before
/// answering anything rather than serve it unbounded.
async fn refused_without_a_slot(addr: std::net::SocketAddr) {
    let held: Vec<_> = (0..session_memory::SLOT_COUNT)
        .map(|_| session_memory::scope(std::future::ready(())))
        .collect();
    let mut conn = TcpStream::connect(addr).await.unwrap();
    conn.write_all(&connect_packet()).await.unwrap();
    let mut reply = Vec::new();
    // A reset counts as closed: the sensor drops the socket with the CONNECT still unread.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut reply))
        .await
        .is_ok();
    drop(held);
    assert!(
        closed && reply.is_empty(),
        "a session with no slot was closed unanswered, not served (got {reply:?})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_publish_bodies_are_charged_to_the_session_pool_and_the_excess_is_ended() {
    tokio::spawn(session_memory::watchdog());
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (addr, handle, _handoff) = sensor_mqtt::start_test_server_with_handoff(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(5),
            // A pending body would otherwise be held this long.
            idle_timeout: Duration::from_secs(30),
            max_duration: Duration::from_secs(60),
            max_captured_bytes: 1_000_000,
            // A per-source cap of 8, so all eight test clients from one address are admitted.
            max_concurrent: 32,
        },
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .await
    .unwrap();

    // 1 MiB for eight sessions: 128 KiB each at the floor, so eight 200 KB bodies cannot all fit.
    let pool = 1024 * 1024;
    session_memory::configure(pool, 8).unwrap();
    let mut clients = Vec::new();
    for _ in 0..8 {
        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(&connect_packet()).await.unwrap();
        let mut connack = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut connack))
            .await
            .expect("a CONNACK arrives")
            .unwrap();
        assert_eq!(connack, CONNACK);
        // The rest of the packet never comes; the sensor waits for it with the body buffered.
        conn.write_all(&partial_publish()).await.unwrap();
        clients.push(conn);
    }

    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut open = 0;
    for conn in &mut clients {
        if !closed_within(conn, Duration::from_millis(200)).await {
            open += 1;
        }
    }
    let ended = clients.len() - open;
    assert!(
        open * SENT <= pool as usize,
        "{open} sessions still hold a {SENT}-byte pending body against a {pool}-byte pool"
    );
    assert!(ended >= 3, "only {ended} of the sessions were ended");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let memory_ends = events(&log_path)
            .await
            .iter()
            .filter(|e| {
                e.signal_type == SIGNAL_HONEYPOT_SESSION_END
                    && e.metadata["end_reason"] == "memory_limit"
            })
            .count();
        if memory_ends >= ended {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{ended} sessions ended but {memory_ends} session-end events say memory_limit"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    drop(clients);
    session_memory::configure(u64::MAX / 2, 16).unwrap();
    refused_without_a_slot(addr).await;
    handle.abort();
}
