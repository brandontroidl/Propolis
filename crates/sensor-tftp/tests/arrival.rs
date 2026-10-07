//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. TFTP owns its request socket rather than using
//! `run_udp_listener`, moves each transfer to an ephemeral socket, and emits the upload from the
//! capture hand-off's worker: three ways for the stamp to be lost or to name the wrong port.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, WanResolver,
};
use sensor_wire::{SIGNAL_HONEYPOT_MALWARE_UPLOAD, SensorEvent};
use tokio::net::UdpSocket;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

fn request(op: u8, name: &[u8]) -> Vec<u8> {
    let mut v = vec![0, op];
    v.extend_from_slice(name);
    v.push(0);
    v.extend_from_slice(b"octet");
    v.push(0);
    v
}

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn recv(sock: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .expect("timed out waiting for a TFTP reply")
        .unwrap();
    buf.truncate(n);
    (buf, from)
}

#[tokio::test]
async fn probe_and_upload_events_carry_the_request_sockets_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let (server, handle, _handoff) = sensor_tftp::start_test_server_with_handoff(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "test".into(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .await
    .unwrap();

    // A write: ACK 0 comes from the transfer's own ephemeral socket, then one short block ends it.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&request(2, b"/tmp/evil.bin"), server)
        .await
        .unwrap();
    let (ack0, transfer) = recv(&client).await;
    assert_eq!(ack0, [0, 4, 0, 0]);
    assert_ne!(transfer.port(), server.port());
    let mut block = vec![0, 3, 0, 1];
    block.extend_from_slice(b"MZ-fake-payload");
    client.send_to(&block, transfer).await.unwrap();
    recv(&client).await;
    // And a read probe, which the sensor answers with an error.
    client
        .send_to(&request(1, b"/etc/passwd"), server)
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let seen = events(&log);
        let uploads = seen
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .count();
        if uploads == 1 && seen.len() >= 3 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{seen:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for e in events(&log) {
        assert_eq!(e.protocol, "udp", "{e:?}");
        assert_eq!(e.metadata["local_port"], server.port(), "{e:?}");
    }
    handle.abort();
}
