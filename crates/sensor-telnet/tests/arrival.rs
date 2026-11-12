//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. Two listeners write one log here (a deployment
//! binding telnet on 23 and 2323 would), so each event's port must be its own listener's.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::{SIGNAL_HONEYPOT_CONNECTION, SensorEvent};
use tokio::net::TcpStream;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn connections_by_port(events: &[SensorEvent]) -> HashMap<u16, usize> {
    let mut out = HashMap::new();
    for e in events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
    {
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        *out.entry(port).or_insert(0) += 1;
    }
    out
}

#[tokio::test]
async fn each_listener_stamps_its_own_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut listeners = Vec::new();
    for n in 1..=2 {
        let (addr, handle) = sensor_telnet::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log.clone(),
            dir.path().join(format!("spool{n}")),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds(),
            "test".into(),
            dir.path().join(format!("outbox{n}")),
        )
        .await
        .unwrap();
        for _ in 0..n {
            let _conn = TcpStream::connect(addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        listeners.push((addr, handle));
    }

    let want = HashMap::from([(listeners[0].0.port(), 1), (listeners[1].0.port(), 2)]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while connections_by_port(&events(&log)) != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "connection events per port {:?}, want {want:?}",
            connections_by_port(&events(&log))
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for e in events(&log) {
        assert_eq!(e.protocol, "tcp", "{e:?}");
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        assert!(want.contains_key(&port), "{e:?}");
    }
    for (_, handle) in listeners {
        handle.abort();
    }
}
