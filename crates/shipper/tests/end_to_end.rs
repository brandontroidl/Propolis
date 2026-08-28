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
use shipper::client::{RetryPolicy, ShipperClient, StopReason, ship_cycle};
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

/// Regression proof for the corrected Task 12 design: two sensor logs on ONE collector must
/// share a single seq/hash chain (one `ConfirmedState` keyed by `COLLECTOR_ID`), never one chain
/// per log. Drives two independent `LogTailer`s through `ship_cycle` in the same serial order
/// `main.rs`'s ship loop uses, both keyed by `COLLECTOR_ID`, and asserts: the shared chain's seq
/// strictly increases across the two calls (2, not two independent 1s), exactly one
/// `ConfirmedState` file exists for this collector, and both logs' lines land in the ONE spool
/// file - proof neither batch was silently `Duplicate`-dropped, since `GatewaySink::accept`
/// (verify.rs) never writes the spool on a `Duplicate` ack.
#[tokio::test]
async fn two_sensor_logs_ship_through_one_shared_multiplexed_chain_with_no_duplicate_drop() {
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
    let cursor_dir = sensor_dir.path().join("cursors");

    let ssh_log_path = sensor_dir.path().join("ssh-events.jsonl");
    std::fs::write(&ssh_log_path, "{\"sensor\":\"ssh\",\"n\":1}\n").expect("write ssh log");
    let telnet_log_path = sensor_dir.path().join("telnet-events.jsonl");
    std::fs::write(&telnet_log_path, "{\"sensor\":\"telnet\",\"n\":1}\n")
        .expect("write telnet log");

    let shipper_state_dir = tempfile::tempdir().expect("shipper state tempdir");

    let mut ssh_tailer = LogTailer::new(ssh_log_path.clone(), cursor_dir.clone());
    let mut telnet_tailer = LogTailer::new(telnet_log_path.clone(), cursor_dir.clone());

    // Pass order mirrors main.rs's ship loop: iterate the tailers in order, one dial per
    // tailer, both against the SAME shared collector-id key - never a per-log key.
    let mut stream = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("connect for ssh");
    let ssh_report = ship_cycle(
        &mut stream,
        &mut ssh_tailer,
        shipper_state_dir.path(),
        COLLECTOR_ID,
        16,
        retry_policy(),
    )
    .await
    .expect("ship ssh log");
    assert_eq!(ssh_report.batches_shipped, 1);
    assert!(ssh_report.stopped.is_none());

    let state_after_ssh =
        shipper::state::ConfirmedState::load(shipper_state_dir.path(), COLLECTOR_ID)
            .expect("load state")
            .expect("state present after first ship");
    assert_eq!(
        state_after_ssh.last_seq, 1,
        "the ssh log's batch must be seq 1 on the shared chain"
    );

    let mut stream2 = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("connect for telnet");
    let telnet_report = ship_cycle(
        &mut stream2,
        &mut telnet_tailer,
        shipper_state_dir.path(),
        COLLECTOR_ID,
        16,
        retry_policy(),
    )
    .await
    .expect("ship telnet log");
    assert_eq!(telnet_report.batches_shipped, 1);
    assert!(telnet_report.stopped.is_none());

    let state_after_telnet =
        shipper::state::ConfirmedState::load(shipper_state_dir.path(), COLLECTOR_ID)
            .expect("load state")
            .expect("state present after second ship");
    assert_eq!(
        state_after_telnet.last_seq, 2,
        "the telnet log's batch must continue the SAME shared chain as seq 2, not restart at \
         seq 1 on an independent per-log chain"
    );
    assert_ne!(
        state_after_telnet.last_batch_hash, state_after_ssh.last_batch_hash,
        "the telnet batch must chain from the ssh batch's confirmed hash"
    );

    // Both logs' lines must land in the ONE collector spool file. GatewaySink::accept
    // (gateway/src/verify.rs) never touches the spool on a Duplicate ack, so both lines being
    // present, with no extra lines, is direct proof the gateway Accepted both batches.
    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    let content = std::fs::read_to_string(&spool_path).expect("read spool");
    assert!(
        content.contains("\"sensor\":\"ssh\""),
        "the ssh log's line is missing from the shared spool"
    );
    assert!(
        content.contains("\"sensor\":\"telnet\""),
        "the telnet log's line is missing from the shared spool"
    );
    assert_eq!(
        content.lines().count(),
        2,
        "exactly one line per log must reach the spool - a Duplicate-dropped or re-written \
         batch would produce a different count"
    );

    // Exactly one ConfirmedState file for this collector - not one per sensor log. A per-log
    // key (the bug the corrected design fixes) would have produced two files here, each ship
    // starting its own chain at seq 1, and the gateway would have silently Duplicate-dropped
    // the second log's records instead of accepting them.
    let state_files: Vec<_> = std::fs::read_dir(shipper_state_dir.path())
        .expect("read shipper state dir")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        state_files.len(),
        1,
        "all sensor logs on one collector must share exactly one ConfirmedState file"
    );
}

/// F1 regression proof: the gateway keeps a per-collector `CollectorState` (seq/hash chain) on
/// the CONTROL PLANE, independent of anything on the collector box. If a collector is rebuilt
/// reusing the same collector id (client cert CN) with its LOCAL shipper state reset to fresh
/// (e.g. a wiped `STATE_DIR`), the naive behavior - treating every `Duplicate` ack identically to
/// `Accepted` - would silently drop the rebuilt collector's new events: they'd ship as seq
/// 1, 2, 3... which the gateway (already ahead) echoes back as `Duplicate`, and the old code
/// advanced the confirmed state AND persisted the tailer cursor past them anyway. `ship_cycle`
/// must instead recognize `next_expected_seq > our_seq + 1` as chain divergence, not a benign
/// crash-retry, and stop loudly without losing anything.
#[tokio::test]
async fn a_rebuilt_collector_reusing_an_identity_with_reset_shipper_state_diverges_loudly_instead_of_silently_dropping_evidence()
 {
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

    // Phase 1: the "original" collector ships 3 batches (forced one record at a time via
    // max_records=1) so the gateway's CollectorState for COLLECTOR_ID advances to last_seq=3.
    // This state lives entirely on the gateway (control-plane) side.
    let original_sensor_dir = tempfile::tempdir().expect("original sensor tempdir");
    let original_log_path = original_sensor_dir.path().join("events.jsonl");
    std::fs::write(&original_log_path, "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n")
        .expect("write original sensor log");
    let original_cursor_dir = original_sensor_dir.path().join("cursors");

    let original_shipper_state_dir = tempfile::tempdir().expect("original shipper state tempdir");
    let mut original_tailer = LogTailer::new(original_log_path, original_cursor_dir);
    let mut stream = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("connect for original collector");
    let original_report = ship_cycle(
        &mut stream,
        &mut original_tailer,
        original_shipper_state_dir.path(),
        COLLECTOR_ID,
        1, // one record per batch, forcing 3 separate confirmed batches (seq 1, 2, 3)
        retry_policy(),
    )
    .await
    .expect("ship original collector's batches");
    assert_eq!(original_report.batches_shipped, 3);
    assert!(original_report.stopped.is_none());

    let spool_path = spool_dir.path().join(COLLECTOR_ID).join("events.jsonl");
    let spool_content_before_rebuild =
        std::fs::read(&spool_path).expect("read spool before rebuild");
    assert_eq!(
        spool_content_before_rebuild,
        b"{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n".to_vec()
    );

    // Phase 2: simulate a rebuild. A brand-new sensor log holding a brand-new event, a brand-new
    // tailer/cursor dir, and a FRESH ConfirmedState (a never-used state_dir) - but the SAME
    // collector id (same certs, same COLLECTOR_ID), exactly what a rebuilt collector box reusing
    // its old cert/CN with wiped local state would present. The gateway's CollectorState for
    // COLLECTOR_ID, untouched by the rebuild, still remembers last_seq=3.
    let rebuilt_sensor_dir = tempfile::tempdir().expect("rebuilt sensor tempdir");
    let rebuilt_log_path = rebuilt_sensor_dir.path().join("events.jsonl");
    std::fs::write(&rebuilt_log_path, "{\"new\":1}\n").expect("write rebuilt sensor log");
    let rebuilt_cursor_dir = rebuilt_sensor_dir.path().join("cursors");

    let rebuilt_shipper_state_dir = tempfile::tempdir().expect("rebuilt shipper state tempdir");
    let mut rebuilt_tailer = LogTailer::new(rebuilt_log_path.clone(), rebuilt_cursor_dir.clone());
    let mut stream2 = ShipperClient::connect(bound_addr, client_tls(&certs), GATEWAY_DNS)
        .await
        .expect("connect for rebuilt collector");
    let rebuilt_report = ship_cycle(
        &mut stream2,
        &mut rebuilt_tailer,
        rebuilt_shipper_state_dir.path(),
        COLLECTOR_ID,
        16,
        retry_policy(),
    )
    .await
    .expect("ship cycle for rebuilt collector");

    // (a) The cycle must STOP loudly with ChainDiverged, not silently succeed as if the batch
    // had been accepted or was an ordinary duplicate.
    assert_eq!(
        rebuilt_report.stopped,
        Some(StopReason::ChainDiverged {
            our_seq: 1,
            gateway_next_expected: 4,
        }),
        "a rebuilt collector reusing an identity with a fresh shipper state must diverge loudly, \
         not silently succeed"
    );
    assert_eq!(
        rebuilt_report.batches_shipped, 0,
        "the diverged batch must never be counted as shipped"
    );

    // (b) The new event must NOT be in the gateway spool - the gateway correctly refused it as a
    // duplicate of an already-confirmed seq rather than appending it.
    let spool_content_after_rebuild =
        std::fs::read(&spool_path).expect("read spool after rebuild attempt");
    assert_eq!(
        spool_content_after_rebuild, spool_content_before_rebuild,
        "the rebuilt collector's new event must never reach the spool"
    );

    // (c) The fresh tailer's cursor must NOT have been advanced past the unshipped line: a
    // brand-new LogTailer instance over the SAME log path and cursor dir must still see it from
    // the beginning, proving a later resync (a fresh collector id, or a gateway-state reset)
    // could still ship it rather than having silently lost it.
    let mut recheck_tailer = LogTailer::new(rebuilt_log_path, rebuilt_cursor_dir);
    let unshipped_lines = recheck_tailer.read_batch(10);
    assert_eq!(
        unshipped_lines,
        vec!["{\"new\":1}".to_string()],
        "the tailer cursor must not have advanced past the diverged, unshipped line"
    );
}
