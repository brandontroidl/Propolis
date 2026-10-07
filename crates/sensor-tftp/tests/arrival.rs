//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. TFTP owns its request socket rather than using
//! `run_udp_listener`, moves each transfer to an ephemeral socket, emits the upload from the
//! capture hand-off's worker, and writes rate-limit summaries from a timer task and from the
//! shutdown flush: every one of those is a way for the stamp to be lost or to name the wrong port.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, Rate,
    RateLimitConfig, WanResolver,
};
use sensor_tftp::TftpServer;
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

/// `per_source` requests per second (and burst) from one network, summarized over `window`.
fn rate(per_source: u32, window: Duration) -> RateLimitConfig {
    let nz = |n| NonZeroU32::new(n).unwrap();
    let mut config = RateLimitConfig::new(
        Rate::new(nz(per_source), nz(per_source)),
        Rate::new(nz(1_000_000), nz(1_000_000)),
    );
    config.summary_window = window;
    config
}

async fn start(log: &Path, dir: &Path, rate: RateLimitConfig) -> TftpServer {
    sensor_tftp::start_test_server_with_capture_budget(
        "127.0.0.1:0".parse().unwrap(),
        log.to_path_buf(),
        dir.join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "test".into(),
        dir.join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        rate,
    )
    .await
    .unwrap()
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

fn rate_limited(e: &SensorEvent) -> bool {
    e.metadata["query_status"] == "rate_limited"
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

async fn wait_for(log: &Path, done: impl Fn(&[SensorEvent]) -> bool) -> Vec<SensorEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !done(&events(log)) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out; events so far: {:?}",
            events(log)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    events(log)
}

/// Read probes back to back from one source: with a budget of one per second, all but the first
/// go to the flood ledger. Each send yields so the server drains its socket as it goes.
async fn flood(to: SocketAddr, n: u16) {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..n {
        client
            .send_to(&request(1, format!("/f{i}").as_bytes()), to)
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn probe_and_upload_events_carry_the_request_sockets_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let server = start(&log, dir.path(), rate(1_000_000, Duration::from_secs(10))).await;
    let addr = server.addr;

    // A write: ACK 0 comes from the transfer's own ephemeral socket, then one short block ends it.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&request(2, b"/tmp/evil.bin"), addr)
        .await
        .unwrap();
    let (ack0, transfer) = recv(&client).await;
    assert_eq!(ack0, [0, 4, 0, 0]);
    assert_ne!(transfer.port(), addr.port());
    let mut block = vec![0, 3, 0, 1];
    block.extend_from_slice(b"MZ-fake-payload");
    client.send_to(&block, transfer).await.unwrap();
    recv(&client).await;
    // And a read probe, which the sensor answers with an error.
    client
        .send_to(&request(1, b"/etc/passwd"), addr)
        .await
        .unwrap();

    let seen = wait_for(&log, |seen| {
        seen.iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .count()
            == 1
            && seen.len() >= 3
    })
    .await;
    for e in &seen {
        assert_eq!(e.protocol, "udp", "{e:?}");
        assert_eq!(e.metadata["local_port"], addr.port(), "{e:?}");
    }
    server.abort();
}

/// The summary timer runs on its own task, outside every request's scope.
#[tokio::test]
async fn a_rate_limit_summary_from_the_timer_carries_the_request_sockets_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let server = start(&log, dir.path(), rate(1, Duration::from_millis(200))).await;
    flood(server.addr, 10).await;

    let seen = wait_for(&log, |seen| seen.iter().any(rate_limited)).await;
    for e in seen.iter().filter(|e| rate_limited(e)) {
        assert_eq!(e.protocol, "udp", "{e:?}");
        assert_eq!(e.metadata["local_port"], server.addr.port(), "{e:?}");
    }
    server.abort();
}

/// The shutdown flush runs on `main`'s task, after the request loop and the timer are stopped.
#[tokio::test]
async fn a_summary_flushed_at_shutdown_carries_the_request_sockets_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let server = start(&log, dir.path(), rate(1, Duration::from_secs(3600))).await;
    flood(server.addr, 10).await;
    // The one request inside the budget is logged; the rest wait in the ledger.
    wait_for(&log, |seen| !seen.is_empty()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.abort();
    assert!(
        !events(&log).iter().any(rate_limited),
        "the window has not ended, so only the flush may write the summary"
    );
    server.flush_rate_limited().await;

    let summaries: Vec<SensorEvent> = events(&log).into_iter().filter(rate_limited).collect();
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0].protocol, "udp");
    assert_eq!(summaries[0].metadata["local_port"], server.addr.port());
}
