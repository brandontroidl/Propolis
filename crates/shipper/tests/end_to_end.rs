//! End-to-end proof of collector -> gateway -> spool: a real `gateway::serve` accepting real
//! mutual TLS, a real `ShipperClient`/`ship_cycle`, and a real filesystem spool - no stubs on
//! either side of the wire.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use collector_wire::ack::{AckReason, AckStatus};
use collector_wire::frame::{Batch, encode_frame};
use collector_wire::hash::ZERO_HASH;
use collector_wire::tls::{client_config, server_config};
use gateway::{BatchSink, GatewaySink, SpoolWriter, serve};
use log_tailer::LogTailer;
use sensor_framework::ConnectionBounds;
use shipper::client::{RetryPolicy, ShipperClient, ship_cycle};
use tokio_rustls::rustls::ClientConfig;

const GATEWAY_DNS: &str = "gateway.local";
const COLLECTOR_ID: &str = "collector-test";
const STATE_KEY: &str = "collector-test-sensor1";

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

/// Starts a real gateway wired to a real, on-disk `GatewaySink`/`SpoolWriter` pair - the same
/// verification + spool chain the box runs - and returns its bound ephemeral address.
async fn start_gateway(certs: &Certs, state_dir: PathBuf, spool_dir: PathBuf) -> SocketAddr {
    let tls =
        server_config(&certs.ca, &certs.gateway_cert, &certs.gateway_key).expect("server_config");
    let sink: Arc<dyn BatchSink> =
        Arc::new(GatewaySink::new(state_dir, SpoolWriter::new(spool_dir)));
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, _handle) = serve(addr, tls, test_bounds(), sink)
        .await
        .expect("serve binds");
    bound_addr
}

fn client_tls(certs: &Certs) -> Arc<ClientConfig> {
    client_config(&certs.ca, &certs.collector_cert, &certs.collector_key).expect("client_config")
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy::new(Duration::from_millis(20), 3)
}

#[tokio::test]
async fn ships_two_lines_byte_exact_and_a_re_run_after_confirmation_ships_nothing_new() {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path());

    let gateway_state_dir = tempfile::tempdir().expect("gateway state tempdir");
    let spool_dir = tempfile::tempdir().expect("spool tempdir");
    let bound_addr = start_gateway(
        &certs,
        gateway_state_dir.path().to_path_buf(),
        spool_dir.path().to_path_buf(),
    )
    .await;

    let sensor_dir = tempfile::tempdir().expect("sensor tempdir");
    let log_path = sensor_dir.path().join("events.jsonl");
    std::fs::write(&log_path, "{\"a\":1}\n{\"b\":2}\n").expect("write sensor log");
    let cursor_dir = sensor_dir.path().join("cursors");

    let shipper_state_dir = tempfile::tempdir().expect("shipper state tempdir");

    // Cycle 1: a fresh tailer, a fresh connection, a fresh confirmed-state - two whole lines are
    // available and must ship as one batch.
    let mut tailer = LogTailer::new(log_path.clone(), cursor_dir.clone());
    let mut stream = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("connect");
    let report = ship_cycle(
        &mut stream,
        &mut tailer,
        shipper_state_dir.path(),
        STATE_KEY,
        16,
        retry_policy(),
    )
    .await
    .expect("ship cycle 1");
    assert_eq!(report.batches_shipped, 1);
    assert!(report.stopped.is_none());

    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    let content = std::fs::read(&spool_path).expect("read spool");
    assert_eq!(content, b"{\"a\":1}\n{\"b\":2}\n".to_vec());

    // Cycle 2: a brand-new LogTailer (reloading the cursor from disk) and a brand-new
    // connection prove the cursor and confirmed-seq state were actually PERSISTED, not merely
    // held in the process's memory - re-running after confirmation ships nothing new.
    let mut tailer2 = LogTailer::new(log_path.clone(), cursor_dir.clone());
    let mut stream2 = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("reconnect");
    let report2 = ship_cycle(
        &mut stream2,
        &mut tailer2,
        shipper_state_dir.path(),
        STATE_KEY,
        16,
        retry_policy(),
    )
    .await
    .expect("ship cycle 2");
    assert_eq!(
        report2.batches_shipped, 0,
        "nothing new to ship after confirmation"
    );
    assert!(report2.stopped.is_none());

    let content_after = std::fs::read(&spool_path).expect("read spool again");
    assert_eq!(
        content_after, content,
        "re-running the ship cycle after confirmation must not append anything new"
    );
}

#[tokio::test]
async fn a_batch_with_a_tampered_hash_chain_is_rejected_and_never_reaches_the_spool() {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path());

    let gateway_state_dir = tempfile::tempdir().expect("gateway state tempdir");
    let spool_dir = tempfile::tempdir().expect("spool tempdir");
    let bound_addr = start_gateway(
        &certs,
        gateway_state_dir.path().to_path_buf(),
        spool_dir.path().to_path_buf(),
    )
    .await;

    let mut stream = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("connect");

    // A raw post-encode byte flip breaks `decode_frame`'s own internal checksum instead (it
    // recomputes the trailing hash over the frame bytes and finds it no longer matches), and
    // `gateway::server::handle_connection` maps EVERY `decode_frame` error uniformly to
    // `Reject{Malformed}` - never `HashMismatch` - regardless of which specific `FrameError` it
    // was. `AckReason::HashMismatch` is produced by exactly one site instead:
    // `GatewaySink::accept`'s own chain check, comparing `batch.prev_batch_hash` against the
    // gateway's tracked `last_batch_hash` for this collector. So "a tampered hash" that must
    // reach the gateway as `HashMismatch` has to be a self-consistent, cleanly-decoding frame
    // whose CHAIN hash is wrong, not a frame whose own wire checksum is wrong. Build exactly
    // that: a batch tampered to chain from a hash the gateway (a never-seen collector) does not
    // expect, encoded normally so it decodes fine and is rejected only on the chain check.
    let mut tampered_prev_hash = ZERO_HASH;
    tampered_prev_hash[0] ^= 0xFF;
    let batch = Batch::new(1, tampered_prev_hash, vec![b"{\"x\":1}".to_vec()]);
    let frame = encode_frame(&batch);

    let ack = ShipperClient::send_batch(&mut stream, &frame)
        .await
        .expect("send tampered batch");
    assert_eq!(ack.status, AckStatus::Reject);
    assert_eq!(ack.reason, AckReason::HashMismatch);

    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    assert!(
        !spool_path.exists(),
        "a hash-chain-tampered batch must never reach the spool"
    );
}
