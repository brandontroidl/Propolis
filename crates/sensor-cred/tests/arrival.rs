//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. `sensor-cred` runs one listener per protocol,
//! each reporting its own sensor name; with all five writing one log, every event's port must be
//! the port of the listener its sensor name says it came from.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::{SIGNAL_HONEYPOT_CONNECTION, SensorEvent};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const PROTOCOLS: [&str; 5] = ["vnc", "mysql", "mssql", "postgresql", "mongodb"];

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
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

#[tokio::test]
async fn each_protocol_listener_stamps_its_own_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let mut ports = HashMap::new();
    let mut handles = Vec::new();
    for protocol in PROTOCOLS {
        let (addr, handle) = sensor_cred::start_listener(
            "127.0.0.1:0".parse().unwrap(),
            log.clone(),
            wan.clone(),
            bounds(),
            protocol,
            None,
        )
        .await
        .unwrap();
        ports.insert(protocol.to_string(), addr.port());
        handles.push(handle);
        // A few bytes, for the protocols that wait for the client before deciding what it is.
        let mut conn = TcpStream::connect(addr).await.unwrap();
        let _ = conn.write_all(&[0u8; 16]).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let seen = events(&log);
        let connected: std::collections::HashSet<&str> = seen
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
            .map(|e| e.sensor.as_str())
            .collect();
        if PROTOCOLS.iter().all(|p| connected.contains(p)) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "connection events seen for {connected:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for e in events(&log) {
        assert_eq!(e.protocol, "tcp", "{e:?}");
        assert_eq!(e.metadata["local_port"], ports[&e.sensor], "{e:?}");
    }
    for handle in handles {
        handle.abort();
    }
}
