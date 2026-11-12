//! Regression cover for the 2026-09-17 audit finding "the shipper can lose unacknowledged
//! records after exhausting retries", over the real transport: a real `gateway::serve` accepting
//! real mutual TLS, a real `ShipperClient`/`ship_cycle`, and a real filesystem spool - no stubs
//! on either side of the wire.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use collector_wire::ack::{AckReason, AckStatus};
use collector_wire::frame::Batch;
use collector_wire::tls::{client_config, server_config};
use gateway::{BatchSink, GatewaySink, SpoolWriter, serve};
use log_tailer::LogTailer;
use sensor_framework::ConnectionBounds;
use shipper::client::{RetryPolicy, ShipperClient, StopReason, ship_cycle};
use tokio_rustls::rustls::ClientConfig;

const GATEWAY_DNS: &str = "gateway.local";
const COLLECTOR_ID: &str = "collector-test";

struct Certs {
    ca: Vec<u8>,
    gateway_cert: Vec<u8>,
    gateway_key: Vec<u8>,
    collector_cert: Vec<u8>,
    collector_key: Vec<u8>,
}

fn mint_certs(dir: &Path) -> Certs {
    provision_certs::provision(dir, GATEWAY_DNS, COLLECTOR_ID).expect("provision");
    let read = |name: &str| std::fs::read(dir.join(name)).expect("read cert file");
    Certs {
        ca: read("ca.crt"),
        gateway_cert: read("gateway.crt"),
        gateway_key: read("gateway.key"),
        collector_cert: read(&format!("{COLLECTOR_ID}.crt")),
        collector_key: read(&format!("{COLLECTOR_ID}.key")),
    }
}

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 1 << 20,
        max_concurrent: 10,
    }
}

fn client_tls(certs: &Certs) -> Arc<ClientConfig> {
    client_config(&certs.ca, &certs.collector_cert, &certs.collector_key).expect("client_config")
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy::new(Duration::from_millis(20), 3)
}

struct RetryOnce {
    inner: GatewaySink<SpoolWriter>,
    first: std::sync::atomic::AtomicBool,
}
impl BatchSink for RetryOnce {
    fn accept(&self, id: &str, batch: &Batch) -> collector_wire::ack::Ack {
        if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
            collector_wire::ack::Ack {
                status: AckStatus::Retry,
                reason: AckReason::SpoolWriteFailed,
                next_expected_seq: 1,
            }
        } else {
            self.inner.accept(id, batch)
        }
    }
}
#[tokio::test]
async fn audit_retry_exhaustion_must_not_skip_unacknowledged_records() {
    let dir = tempfile::tempdir().unwrap();
    let certs = mint_certs(dir.path());
    let spool = dir.path().join("spool");
    let sink: Arc<dyn BatchSink> = Arc::new(RetryOnce {
        inner: GatewaySink::new(
            dir.path().join("gateway-state"),
            SpoolWriter::new(spool.clone()),
        ),
        first: std::sync::atomic::AtomicBool::new(true),
    });
    let tls = server_config(&certs.ca, &certs.gateway_cert, &certs.gateway_key).unwrap();
    let (addr, _handle) = serve("127.0.0.1:0".parse().unwrap(), tls, test_bounds(), sink)
        .await
        .unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, "first\nsecond\n").unwrap();
    let mut tailer = LogTailer::new(path, dir.path().join("cursor"));
    let state = dir.path().join("state");
    let mut stream = ShipperClient::connect(addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .unwrap();
    let first = ship_cycle(
        &mut stream,
        &mut tailer,
        &state,
        COLLECTOR_ID,
        1,
        RetryPolicy::new(Duration::from_millis(1), 0),
    )
    .await
    .unwrap();
    assert!(matches!(first.stopped, Some(StopReason::RetriesExhausted)));
    let mut stream = ShipperClient::connect(addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .unwrap();
    ship_cycle(
        &mut stream,
        &mut tailer,
        &state,
        COLLECTOR_ID,
        1,
        retry_policy(),
    )
    .await
    .unwrap();
    let actual = std::fs::read_to_string(spool.join(COLLECTOR_ID).join("events.jsonl")).unwrap();
    assert_eq!(
        actual, "first\nsecond\n",
        "retry resumed beyond an unacknowledged batch"
    );
}
