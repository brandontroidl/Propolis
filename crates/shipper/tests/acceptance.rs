//! SP-A end-to-end acceptance test: proves the collector/control-plane split's spec-level
//! acceptance criteria in one place. Real `sensor_wire::SensorEvent` records survive
//! byte-exact through mTLS shipping and reconstitute for intake off the spool, and each of the
//! spec's "compromise yields nothing" properties (a foreign-CA client, a replay, a sequence
//! gap, a one-byte tamper) is independently rejected, with the gateway returning only its
//! fixed 14-byte ack and no other channel.
//!
//! Each test provisions its own certs, its own gateway instance, and its own tempdir spool - no
//! state is shared between arms, so a rejection in one test can never be explained by leftover
//! state from another.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use collector_wire::ack::{ACK_LEN, AckReason, AckStatus};
use collector_wire::frame::{Batch, encode_frame};
use collector_wire::hash::ZERO_HASH;
use collector_wire::tls::{client_config, server_config};
use gateway::{BatchSink, GatewaySink, SpoolWriter, serve};
use log_tailer::LogTailer;
use sensor_framework::ConnectionBounds;
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};
use shipper::client::{RetryPolicy, ShipperClient, ship_cycle};
use tokio::io::AsyncReadExt;
use tokio_rustls::rustls::ClientConfig;

const GATEWAY_DNS: &str = "gateway.local";
const COLLECTOR_ID: &str = "collector-acceptance";
const STATE_KEY: &str = "collector-acceptance-sensor1";

struct Certs {
    ca: Vec<u8>,
    gateway_cert: Vec<u8>,
    gateway_key: Vec<u8>,
    collector_cert: Vec<u8>,
    collector_key: Vec<u8>,
}

fn mint_certs(dir: &Path, gateway_dns: &str, collector_id: &str) -> Certs {
    provision_certs::provision(dir, gateway_dns, collector_id).expect("provision");
    let read = |name: &str| std::fs::read(dir.join(name)).expect("read cert file");
    Certs {
        ca: read("ca.crt"),
        gateway_cert: read("gateway.crt"),
        gateway_key: read("gateway.key"),
        collector_cert: read(&format!("{collector_id}.crt")),
        collector_key: read(&format!("{collector_id}.key")),
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

/// Three real `SensorEvent` records, each exercising a different optional-field combination (a
/// sample ref, a session id, a null wan_ip) so the byte-exact and reconstitution checks below
/// cover more than the all-fields-populated happy path. IPs are RFC 5737 documentation
/// addresses (TEST-NET-3), never real ones.
fn build_events() -> Vec<SensorEvent> {
    vec![
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: Some("198.51.100.4".parse().unwrap()),
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: "2026-08-27T10:15:00Z".parse().unwrap(),
            metadata: serde_json::json!({ "protocol_label": "ssh", "command": "uname -a" }),
            sample: None,
            session_id: Some(uuid::Uuid::now_v7()),
        },
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.9".parse().unwrap(),
            wan_ip: None,
            sensor: "telnet".into(),
            signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: "2026-08-27T10:15:03Z".parse().unwrap(),
            metadata: serde_json::json!({ "protocol_label": "telnet", "username": "admin" }),
            sample: None,
            session_id: None,
        },
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.11".parse().unwrap(),
            wan_ip: Some("198.51.100.4".parse().unwrap()),
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: "2026-08-27T10:15:07Z".parse().unwrap(),
            metadata: serde_json::json!({ "protocol_label": "ssh" }),
            sample: Some(SampleRef {
                sha256: "a".repeat(64),
                size: 4096,
                orig_name: "dropper.bin".into(),
                capture_id: None,
            }),
            session_id: Some(uuid::Uuid::now_v7()),
        },
    ]
}

/// The full loopback pipeline: real `SensorEvent`s -> tailer -> shipper -> mTLS -> gateway ->
/// spool -> a fresh tailer reconstituting them for intake. Proves records survive byte-exact
/// end to end.
#[tokio::test]
async fn real_sensor_events_survive_shipping_byte_exact_and_reconstitute_for_intake() {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path(), GATEWAY_DNS, COLLECTOR_ID);

    let gateway_state_dir = tempfile::tempdir().expect("gateway state tempdir");
    let spool_dir = tempfile::tempdir().expect("spool tempdir");
    let bound_addr = start_gateway(
        &certs,
        gateway_state_dir.path().to_path_buf(),
        spool_dir.path().to_path_buf(),
    )
    .await;

    let events = build_events();
    let mut ndjson = String::new();
    for event in &events {
        ndjson.push_str(&serde_json::to_string(event).expect("serialize SensorEvent"));
        ndjson.push('\n');
    }

    let sensor_dir = tempfile::tempdir().expect("sensor tempdir");
    let log_path = sensor_dir.path().join("ssh-events.jsonl");
    std::fs::write(&log_path, &ndjson).expect("write sensor log");
    let cursor_dir = sensor_dir.path().join("cursors");

    let shipper_state_dir = tempfile::tempdir().expect("shipper state tempdir");
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
    .expect("ship cycle");
    assert_eq!(
        report.batches_shipped, 1,
        "all three events must fit into one batch"
    );
    assert!(report.stopped.is_none());

    // Step 5: assert every event appears byte-exact in the per-collector spool.
    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    let spool_bytes = std::fs::read(&spool_path).expect("read spool");
    assert_eq!(
        spool_bytes,
        ndjson.clone().into_bytes(),
        "the spooled bytes must match the shipped NDJSON exactly, byte for byte"
    );

    // Step 6: feed the spool file into a fresh LogTailer and parse each line back into a
    // SensorEvent - the same reconstitution path intake performs downstream of the gateway.
    // A separate cursor dir proves this is reading the spool from a cold start, not reusing
    // any cursor state the shipper's own tailer left behind.
    let intake_cursor_dir = sensor_dir.path().join("intake-cursors");
    let mut intake_tailer = LogTailer::new(spool_path.clone(), intake_cursor_dir);
    let reconstituted_lines = intake_tailer.read_batch(events.len());
    assert_eq!(
        reconstituted_lines.len(),
        events.len(),
        "every shipped record must be readable back off the spool"
    );
    let reconstituted: Vec<SensorEvent> = reconstituted_lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("parse SensorEvent back off the spool"))
        .collect();
    assert_eq!(
        reconstituted, events,
        "records reconstituted from the spool must equal the originals exactly - proof the \
         bytes survived intact for the downstream hash chain"
    );
}

/// A client cert signed by a CA the gateway never trusted must fail the mTLS handshake and
/// leave no trace on the spool - the collector-compromise-yields-nothing property with no
/// shared CA.
#[tokio::test]
async fn a_client_certificate_signed_by_a_foreign_ca_cannot_complete_the_handshake_and_writes_nothing()
 {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path(), GATEWAY_DNS, COLLECTOR_ID);

    let gateway_state_dir = tempfile::tempdir().expect("gateway state tempdir");
    let spool_dir = tempfile::tempdir().expect("spool tempdir");
    let bound_addr = start_gateway(
        &certs,
        gateway_state_dir.path().to_path_buf(),
        spool_dir.path().to_path_buf(),
    )
    .await;

    // `provision_certs::provision` mints a fresh, independent CA every call, so this second
    // collector's cert chains to a CA the gateway (rooted only at `certs.ca`) has never trusted
    // - a completely disjoint trust root, not merely a different leaf.
    let foreign_dir = tempfile::tempdir().expect("foreign cert tempdir");
    let foreign_collector_id = "foreign-collector";
    provision_certs::provision(foreign_dir.path(), GATEWAY_DNS, foreign_collector_id)
        .expect("provision foreign certs");
    let foreign_cert = std::fs::read(
        foreign_dir
            .path()
            .join(format!("{foreign_collector_id}.crt")),
    )
    .expect("read foreign cert");
    let foreign_key = std::fs::read(
        foreign_dir
            .path()
            .join(format!("{foreign_collector_id}.key")),
    )
    .expect("read foreign key");

    // Trust the REAL gateway's server cert (rooted at the real CA) but present the foreign
    // collector's client cert/key - the shape of an attacker who knows the gateway address but
    // holds no certificate signed by its CA.
    let foreign_client_tls =
        client_config(&certs.ca, &foreign_cert, &foreign_key).expect("client_config");

    // TLS 1.3's client-auth flow lets the CLIENT side of the handshake complete (it sends its
    // own Certificate/CertificateVerify/Finished as its last flight and does not wait for a
    // reply) before it learns the SERVER rejected that certificate - the rejection can surface
    // either as an immediate handshake error here, or only on the next read/write once the
    // gateway's own verification tears the connection down. Cover both: if `connect` itself
    // did not error, the connection must still be provably unusable for shipping anything.
    match ShipperClient::connect(bound_addr, foreign_client_tls, GATEWAY_DNS).await {
        Err(_) => {}
        Ok(mut stream) => {
            let batch = Batch::new(1, ZERO_HASH, vec![b"{\"n\":1}".to_vec()]);
            let frame = encode_frame(&batch);
            let send_result = ShipperClient::send_batch(&mut stream, &frame).await;
            assert!(
                send_result.is_err(),
                "a connection presenting a foreign-CA client cert must never successfully \
                 exchange a batch, even if the client's own handshake step appeared to complete"
            );
        }
    }

    assert!(
        !spool_dir.path().join(foreign_collector_id).exists(),
        "a rejected handshake must never reach the spool"
    );
    assert!(
        !spool_dir.path().join(COLLECTOR_ID).exists(),
        "no collector's spool directory should exist - nothing was ever accepted"
    );
}

/// A replayed batch (same seq, resent on the same connection - the shape of a shipper's
/// crash-retry) must be an idempotent `Duplicate` and must never append to the spool twice.
#[tokio::test]
async fn a_replayed_batch_is_deduped_as_duplicate_and_never_double_writes_the_spool() {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path(), GATEWAY_DNS, COLLECTOR_ID);

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

    let batch = Batch::new(1, ZERO_HASH, vec![b"{\"n\":1}".to_vec()]);
    let frame = encode_frame(&batch);

    let first = ShipperClient::send_batch(&mut stream, &frame)
        .await
        .expect("send first");
    assert_eq!(first.status, AckStatus::Accepted);

    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    let content_after_first = std::fs::read(&spool_path).expect("read spool after first send");

    // Resend the exact same frame, pipelined on the same connection.
    let second = ShipperClient::send_batch(&mut stream, &frame)
        .await
        .expect("send replay");
    assert_eq!(second.status, AckStatus::Duplicate);
    assert_eq!(second.reason, AckReason::None);

    let content_after_second = std::fs::read(&spool_path).expect("read spool after replay");
    assert_eq!(
        content_after_first, content_after_second,
        "a duplicate batch must never append to the spool a second time"
    );
}

/// A batch that skips ahead of the expected next seq (a gap, from message loss or reordering)
/// must be rejected with `SeqGap` and never reach the spool.
#[tokio::test]
async fn a_sequence_gap_is_rejected_and_never_reaches_the_spool() {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path(), GATEWAY_DNS, COLLECTOR_ID);

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

    // A never-seen collector expects seq 1; jump straight to seq 2 to open a gap.
    let batch = Batch::new(2, ZERO_HASH, vec![b"{\"n\":1}".to_vec()]);
    let frame = encode_frame(&batch);

    let ack = ShipperClient::send_batch(&mut stream, &frame)
        .await
        .expect("send gapped batch");
    assert_eq!(ack.status, AckStatus::Reject);
    assert_eq!(ack.reason, AckReason::SeqGap);

    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    assert!(
        !spool_path.exists(),
        "a sequence-gapped batch must never reach the spool"
    );
}

/// A single flipped byte inside the frame's own trailing hash breaks `decode_frame`'s wire
/// checksum before the batch ever reaches `GatewaySink::accept`'s chain check; the gateway maps
/// that decode-time `FrameError::HashMismatch` to `Reject{HashMismatch}`. Same reason code as the
/// chain-history `HashMismatch` `end_to_end.rs` (Task 11) covers with a self-consistent but
/// wrongly-chained frame, but a distinct mechanism: this one is wire-corruption caught at decode,
/// that one is a valid frame failing the rolling-chain check at verification.
#[tokio::test]
async fn a_single_flipped_byte_in_the_frame_is_rejected_as_hash_mismatch_and_never_reaches_the_spool()
 {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path(), GATEWAY_DNS, COLLECTOR_ID);

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

    let batch = Batch::new(1, ZERO_HASH, vec![b"{\"n\":1}".to_vec()]);
    let mut frame = encode_frame(&batch);
    // The last byte of the frame is inside the trailing 32-byte batch_hash: flipping it leaves
    // the header/records fully decodable and only breaks the trailer checksum.
    let last = frame.len() - 1;
    frame[last] ^= 0xFF;

    let ack = ShipperClient::send_batch(&mut stream, &frame)
        .await
        .expect("send tampered frame");
    assert_eq!(ack.status, AckStatus::Reject);
    assert_eq!(ack.reason, AckReason::HashMismatch);

    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    assert!(
        !spool_path.exists(),
        "a wire-corrupted frame must never reach the spool"
    );
}

/// The gateway exposes no path that returns anything other than the fixed 14-byte ack: after a
/// successful batch, probing the same connection for more data must never turn up extra bytes.
#[tokio::test]
async fn the_gateway_returns_only_the_fixed_ack_and_no_other_channel() {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let certs = mint_certs(cert_dir.path(), GATEWAY_DNS, COLLECTOR_ID);

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

    let batch = Batch::new(1, ZERO_HASH, vec![b"{\"n\":1}".to_vec()]);
    let frame = encode_frame(&batch);
    // `ShipperClient::send_batch` already `read_exact`s exactly ACK_LEN bytes; getting an Ack
    // back at all proves that much arrived. The probe below proves nothing MORE ever does.
    let ack = ShipperClient::send_batch(&mut stream, &frame)
        .await
        .expect("send batch");
    assert_eq!(ack.status, AckStatus::Accepted);

    let mut probe = [0u8; 8];
    match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut probe)).await {
        Err(_) => {}    // timed out waiting for more bytes: no other channel is exposed
        Ok(Ok(0)) => {} // connection closed with nothing further buffered: also no extra channel
        Ok(Ok(n)) => panic!(
            "gateway sent {n} bytes beyond the fixed {ACK_LEN}-byte ack - a second channel exists"
        ),
        Ok(Err(error)) => panic!("unexpected read error while probing for extra data: {error}"),
    }
}
