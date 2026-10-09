//! The listener registers every connection in the hand-off's tracker, so a shutdown `drain` can cut
//! a connection still holding an in-flight capture instead of losing it. A listener started
//! without the tracker would pass every other test and still drop that capture at SIGTERM.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, CommandEventConfig, CommandEventGate, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, QuiesceOutcome, WanResolver,
};
use tokio::net::TcpStream;

#[tokio::test]
async fn an_open_connection_is_tracked_and_cut_by_drain() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle, handoff) = sensor_ssh::serve_with_handoff(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            max_duration: Duration::from_secs(60),
            max_captured_bytes: 1_000_000,
            max_concurrent: 64,
        },
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        Arc::new(CommandEventGate::new(CommandEventConfig::default())),
    )
    .await
    .unwrap();

    let _client = TcpStream::connect(addr).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while handoff.connections().live() != 1 {
        assert!(std::time::Instant::now() < deadline, "connection untracked");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    handle.abort();
    let report = handoff.drain(Duration::from_secs(2)).await;
    assert_eq!(report.connections, QuiesceOutcome::Cancelled(1));
    assert_eq!(handoff.connections().live(), 0);
}
