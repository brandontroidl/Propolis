use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CAPTURE_CHUNK_BYTES, CaptureHandoff, CaptureMemoryBudget, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, Rate, RateLimitConfig, WanResolver,
};
use sensor_tftp::TftpServer;
use sensor_wire::{
    PROTO_UDP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SensorEvent,
};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;

const BLOCK: usize = 512;

fn rate(per_second: u32, burst: u32, global: u32, global_burst: u32) -> RateLimitConfig {
    let nz = |n| NonZeroU32::new(n).unwrap();
    RateLimitConfig::new(
        Rate::new(nz(per_second), nz(burst)),
        Rate::new(nz(global), nz(global_burst)),
    )
}

/// Limits no ordinary test comes near, so only the flood tests see rate limiting.
fn unlimited() -> RateLimitConfig {
    rate(1_000_000, 1_000_000, 1_000_000, 1_000_000)
}

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

struct TestServer {
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    server: TftpServer,
    handoff: Arc<CaptureHandoff>,
    budget: Arc<CaptureMemoryBudget>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        Self::start_with(test_bounds(), HashMap::new()).await
    }

    async fn start_with(
        bounds: ConnectionBounds,
        wan_map: HashMap<std::net::IpAddr, std::net::IpAddr>,
    ) -> TestServer {
        Self::start_full(
            bounds,
            wan_map,
            DEFAULT_CAPTURE_BUDGET_BYTES_256M,
            unlimited(),
        )
        .await
    }

    async fn start_with_capture_budget(ceiling: u64) -> TestServer {
        Self::start_full(test_bounds(), HashMap::new(), ceiling, unlimited()).await
    }

    async fn start_rated(rate: RateLimitConfig) -> TestServer {
        Self::start_full(
            test_bounds(),
            HashMap::new(),
            DEFAULT_CAPTURE_BUDGET_BYTES_256M,
            rate,
        )
        .await
    }

    async fn start_full(
        bounds: ConnectionBounds,
        wan_map: HashMap<std::net::IpAddr, std::net::IpAddr>,
        capture_ceiling: u64,
        rate: RateLimitConfig,
    ) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let budget = Arc::new(CaptureMemoryBudget::new(capture_ceiling));
        let server = sensor_tftp::start_test_server_with_capture_budget(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            Arc::new(WanResolver::new(wan_map)),
            bounds,
            "test".to_string(),
            dir.path().join("outbox"),
            budget.clone(),
            rate,
        )
        .await
        .unwrap();
        TestServer {
            addr: server.addr,
            log_path,
            spool_dir,
            handoff: server.handoff.clone(),
            server,
            budget,
            _dir: dir,
        }
    }

    async fn wait_for_budget_current(&self, bytes: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while self.budget.current_bytes() != bytes {
            assert!(
                std::time::Instant::now() < deadline,
                "budget current stayed at {} (wanted {bytes})",
                self.budget.current_bytes()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn events(&self) -> Vec<SensorEvent> {
        let content = tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }

    /// Poll the event log until an event matching `pred` appears. The hand-off worker stores the
    /// body and appends the upload event off the reply path, so a reply the client has already read
    /// says nothing about whether the event exists yet. Callers asserting an event is ABSENT must
    /// use a fixed wait instead.
    async fn wait_for(&self, what: &str, pred: impl Fn(&SensorEvent) -> bool) -> SensorEvent {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(event) = self.events().await.into_iter().find(|e| pred(e)) {
                return event;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what} in {:?}",
                self.log_path
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_upload(&self) -> SensorEvent {
        self.wait_for("a honeypot_malware_upload event", |e| {
            e.signal_type == SIGNAL_HONEYPOT_MALWARE_UPLOAD
        })
        .await
    }

    async fn uploads(&self) -> Vec<SensorEvent> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .collect()
    }

    fn spool_files(&self) -> Vec<String> {
        std::fs::read_dir(&self.spool_dir)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.path().is_file())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A TFTP client over one UDP socket that counts every byte it sends and receives, so a test can
/// state the anti-amplification property directly: bytes back never exceed bytes out.
struct Client {
    sock: UdpSocket,
    sent: usize,
    received: usize,
}

impl Client {
    async fn new() -> Client {
        Client::bound("127.0.0.1:0").await
    }

    async fn bound(addr: &str) -> Client {
        Client {
            sock: UdpSocket::bind(addr).await.unwrap(),
            sent: 0,
            received: 0,
        }
    }

    async fn send(&mut self, to: SocketAddr, packet: &[u8]) {
        self.sock.send_to(packet, to).await.unwrap();
        self.sent += packet.len();
    }

    async fn recv_within(&mut self, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(wait, self.sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                self.received += n;
                buf.truncate(n);
                Some((buf, from))
            }
            _ => None,
        }
    }

    async fn recv(&mut self) -> (Vec<u8>, SocketAddr) {
        self.recv_within(Duration::from_secs(3))
            .await
            .expect("timed out waiting for a TFTP reply")
    }

    async fn assert_silent(&mut self, wait: Duration) {
        if let Some((packet, from)) = self.recv_within(wait).await {
            panic!("expected silence, got {packet:?} from {from}");
        }
    }

    /// Start a write and return the transfer address the ACK 0 came from.
    async fn begin_write(&mut self, server: SocketAddr, name: &str, mode: &str) -> SocketAddr {
        self.send(server, &wrq(name.as_bytes(), mode.as_bytes()))
            .await;
        let (reply, from) = self.recv().await;
        assert_eq!(reply, ack(0), "ACK 0 expected");
        assert_ne!(from, server, "the transfer must move to its own socket");
        from
    }

    async fn send_block(&mut self, to: SocketAddr, block: u16, payload: &[u8]) {
        self.send(to, &data(block, payload)).await;
    }

    async fn expect_ack(&mut self, from: SocketAddr, block: u16) {
        let (reply, source) = self.recv().await;
        assert_eq!(source, from, "ACK must come from the transfer socket");
        assert_eq!(reply, ack(block));
    }
}

fn request(op: u8, name: &[u8], mode: &[u8]) -> Vec<u8> {
    let mut v = vec![0, op];
    v.extend_from_slice(name);
    v.push(0);
    v.extend_from_slice(mode);
    v.push(0);
    v
}

fn rrq(name: &[u8], mode: &[u8]) -> Vec<u8> {
    request(1, name, mode)
}

fn wrq(name: &[u8], mode: &[u8]) -> Vec<u8> {
    request(2, name, mode)
}

fn data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 3];
    v.extend_from_slice(&block.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ack(block: u16) -> Vec<u8> {
    let mut v = vec![0, 4];
    v.extend_from_slice(&block.to_be_bytes());
    v
}

fn error_code(packet: &[u8]) -> u16 {
    assert!(packet.len() >= 5, "not an ERROR packet: {packet:?}");
    assert_eq!(&packet[..2], &[0, 5], "not an ERROR packet: {packet:?}");
    u16::from_be_bytes([packet[2], packet[3]])
}

fn sha_hex(body: &[u8]) -> String {
    sensor_framework::to_hex_bounded(&Sha256::digest(body), 32)
}

#[tokio::test]
async fn wrq_upload_is_captured_in_the_spool_and_emits_both_events() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "/tmp/evil.bin", "octet").await;

    let mut body = vec![0xAB; BLOCK];
    body.extend_from_slice(b"MZ-fake-payload-tail");
    client.send_block(transfer, 1, &body[..BLOCK]).await;
    client.expect_ack(transfer, 1).await;
    client.send_block(transfer, 2, &body[BLOCK..]).await;
    client.expect_ack(transfer, 2).await;

    let upload = srv.wait_for_upload().await;
    let sample = upload.sample.as_ref().unwrap();
    assert_eq!(sample.size, body.len() as u64);
    assert_eq!(sample.sha256, sha_hex(&body));
    assert_eq!(sample.orig_name, "/tmp/evil.bin");
    assert_eq!(upload.sensor, "tftp");
    assert_eq!(upload.protocol, PROTO_UDP);
    assert!(!upload.authenticated);
    assert_eq!(upload.metadata["protocol_label"], "tftp");
    assert_eq!(upload.metadata["sha256"], sha_hex(&body));
    assert_eq!(upload.metadata["size"], body.len() as u64);
    assert_eq!(upload.metadata["wire_size"], body.len() as u64);
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(upload.metadata["complete"], true);
    assert_eq!(upload.metadata["end_reason"], "transfer_complete");
    assert_eq!(upload.metadata["orig_name"], "/tmp/evil.bin");

    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, body);

    let events = srv.events().await;
    let probe = events
        .iter()
        .find(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
        .expect("a probe event for the WRQ");
    assert_eq!(probe.sensor, "tftp");
    assert_eq!(probe.protocol, PROTO_UDP);
    assert!(!probe.authenticated);
    assert_eq!(
        probe.source_ip,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(probe.metadata["protocol_label"], "tftp");
    assert_eq!(probe.metadata["filename"], "/tmp/evil.bin");
    assert_eq!(probe.metadata["mode"], "octet");
    assert_eq!(probe.metadata["direction"], "wrq");
    assert!(probe.session_id.is_some());
    assert_eq!(
        probe.session_id, upload.session_id,
        "one session id spans the probe and the upload"
    );
    srv.server.abort();
}

/// Sends `blocks` full blocks of `fill` and returns the transfer address plus how many were ACKed
/// before the sensor answered with an ERROR (or all of them if it never did).
async fn send_full_blocks(
    client: &mut Client,
    transfer: SocketAddr,
    blocks: u16,
    fill: u8,
) -> (u16, Option<Vec<u8>>) {
    let mut acked = 0;
    for block in 1..=blocks {
        client.send_block(transfer, block, &[fill; BLOCK]).await;
        let (reply, _) = client.recv().await;
        if reply == ack(block) {
            acked = block;
        } else {
            return (acked, Some(reply));
        }
    }
    (acked, None)
}

#[tokio::test]
async fn capture_within_budget_is_complete_and_the_budget_returns_to_zero_after_spooling() {
    let srv = TestServer::start_with_capture_budget(4 * CAPTURE_CHUNK_BYTES).await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "ok.bin", "octet").await;
    let (acked, error) = send_full_blocks(&mut client, transfer, 3, 0x11).await;
    assert_eq!((acked, error), (3, None));
    client.send_block(transfer, 4, b"tail").await;
    client.expect_ack(transfer, 4).await;

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.sample.as_ref().unwrap().size, (3 * BLOCK + 4) as u64);
    assert_eq!(upload.metadata["complete"], true);
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(upload.metadata["end_reason"], "transfer_complete");
    assert_eq!(srv.budget.high_water_bytes(), CAPTURE_CHUNK_BYTES);
    srv.wait_for_budget_current(0).await;
    assert_eq!(srv.handoff.truncated_capture_count(), 0);
    srv.server.abort();
}

#[tokio::test]
async fn capture_that_exhausts_the_budget_keeps_its_prefix_and_later_uploads_still_work() {
    // One 64 KiB chunk = exactly 128 blocks of 512 bytes; block 129 needs a chunk that is not there.
    let srv = TestServer::start_with_capture_budget(CAPTURE_CHUNK_BYTES).await;
    let kept_blocks = (CAPTURE_CHUNK_BYTES as usize / BLOCK) as u16;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "big.bin", "octet").await;
    let (acked, error) = send_full_blocks(&mut client, transfer, kept_blocks + 1, 0x22).await;
    assert_eq!(acked, kept_blocks, "every block that fit was acknowledged");
    assert_eq!(
        error_code(&error.expect("block past the budget is refused with an ERROR")),
        3,
        "disk full"
    );

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.sample.as_ref().unwrap().size, CAPTURE_CHUNK_BYTES);
    assert_eq!(upload.metadata["truncated"], true);
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "capture_memory_budget");
    assert_eq!(srv.handoff.truncated_capture_count(), 1);
    srv.wait_for_budget_current(0).await;

    // The room freed by spooling the first capture serves the next one in full.
    let mut second = Client::new().await;
    let transfer = second.begin_write(srv.addr, "small.bin", "octet").await;
    second.send_block(transfer, 1, b"MZ-small").await;
    second.expect_ack(transfer, 1).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while srv.uploads().await.len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "second upload never landed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let second_upload = &srv.uploads().await[1];
    assert_eq!(second_upload.sample.as_ref().unwrap().size, 8);
    assert_eq!(second_upload.metadata["complete"], true);
    srv.server.abort();
}

#[tokio::test]
async fn concurrent_transfers_share_one_ceiling_and_a_zero_byte_capture_submits_no_sample() {
    let ceiling = CAPTURE_CHUNK_BYTES;
    let srv = TestServer::start_with_capture_budget(ceiling).await;

    // A holds the only chunk (one short of finishing: a full block keeps the transfer open).
    let mut a = Client::new().await;
    let a_transfer = a.begin_write(srv.addr, "a.bin", "octet").await;
    a.send_block(a_transfer, 1, &[1u8; BLOCK]).await;
    a.expect_ack(a_transfer, 1).await;
    srv.wait_for_budget_current(CAPTURE_CHUNK_BYTES).await;

    // B's first block cannot be buffered at all: refused, no sample, refusal counted.
    let mut b = Client::new().await;
    let b_transfer = b.begin_write(srv.addr, "b.bin", "octet").await;
    b.send_block(b_transfer, 1, &[2u8; BLOCK]).await;
    let (reply, _) = b.recv().await;
    assert_eq!(error_code(&reply), 3);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while srv.handoff.refused_capture_count() < 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "refusal never counted"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(srv.handoff.truncated_capture_count(), 0);
    assert!(srv.budget.high_water_bytes() <= ceiling);

    // A finishes: its capture is the only sample, and B's probe event still exists.
    a.send_block(a_transfer, 2, b"end").await;
    a.expect_ack(a_transfer, 2).await;
    srv.wait_for_upload().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let uploads = srv.uploads().await;
    assert_eq!(uploads.len(), 1, "no empty sample for the starved capture");
    assert_eq!(uploads[0].sample.as_ref().unwrap().size, (BLOCK + 3) as u64);
    let probes = srv
        .events()
        .await
        .into_iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
        .count();
    assert_eq!(probes, 2);
    srv.wait_for_budget_current(0).await;
    srv.server.abort();
}

#[tokio::test]
async fn shutdown_drain_leaves_the_captured_body_in_the_spool_and_its_event_in_the_log() {
    // What main does on SIGTERM: stop the listener, then drain the hand-off. The assertions read
    // the spool and log with no polling, so they hold only if `drain` itself waited for the worker.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let server = sensor_tftp::start_test_server_with_capture_budget(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        unlimited(),
    )
    .await
    .unwrap();

    let mut client = Client::new().await;
    let transfer = client.begin_write(server.addr, "drain.bin", "octet").await;
    let body = b"drained-on-shutdown".to_vec();
    client.send_block(transfer, 1, &body).await;
    client.expect_ack(transfer, 1).await;
    // The handler submits right after it sends the final ACK; give that task a moment to run.
    tokio::time::sleep(Duration::from_millis(200)).await;

    server.abort();
    let outcome = server.handoff.drain(Duration::from_secs(10)).await;
    assert_eq!(outcome, sensor_framework::DrainOutcome::Drained);

    let on_disk = std::fs::read(spool_dir.join(sha_hex(&body))).expect("body is in the spool");
    assert_eq!(on_disk, body);
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        log.contains(SIGNAL_HONEYPOT_MALWARE_UPLOAD),
        "the upload event is in the log"
    );
}

#[tokio::test]
async fn an_upload_that_ends_on_a_full_block_boundary_needs_the_zero_length_final_block() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "aligned", "octet").await;

    client.send_block(transfer, 1, &[7u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;
    // A full block does not end the transfer: nothing is captured until the short block arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(srv.uploads().await.is_empty());
    client.send_block(transfer, 2, &[]).await;
    client.expect_ack(transfer, 2).await;

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.sample.as_ref().unwrap().size, BLOCK as u64);
    assert_eq!(upload.metadata["complete"], true);
    srv.server.abort();
}

#[tokio::test]
async fn rrq_gets_one_tiny_error_and_no_content() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let req = rrq(b"/etc/passwd", b"octet");
    client.send(srv.addr, &req).await;

    let (reply, from) = client.recv().await;
    assert_ne!(from, srv.addr, "the reply moves to a transfer socket");
    assert_eq!(error_code(&reply), 1, "File not found");
    assert!(
        reply.len() <= 19,
        "a fixed, tiny reply: {} bytes",
        reply.len()
    );
    assert!(reply.len() <= req.len());
    assert_eq!(&reply[4..reply.len() - 1], b"File not found");
    assert_eq!(*reply.last().unwrap(), 0);

    // One packet, then silence: no DATA, no retransmission, even if the client ACKs.
    client.assert_silent(Duration::from_millis(400)).await;
    client.send(from, &ack(1)).await;
    client.send(from, &ack(0)).await;
    client.assert_silent(Duration::from_millis(300)).await;

    assert!(srv.spool_files().is_empty());
    assert!(srv.uploads().await.is_empty());
    let events = srv.events().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["direction"], "rrq");
    assert_eq!(events[0].metadata["filename"], "/etc/passwd");
    srv.server.abort();
}

/// The reply to any exchange never carries more bytes than the peer sent. Discriminating cases:
/// the smallest legal RRQs (8 and 9 bytes), where a fixed 19-byte "File not found" would exceed the
/// request, and a mixed flood from one client.
#[tokio::test]
async fn replies_never_exceed_what_the_peer_sent() {
    let srv = TestServer::start().await;

    // An 8-byte request (empty filename, mode "mail"): the reply must fit in 8 bytes.
    let mut tiny = Client::new().await;
    let req = rrq(b"", b"mail");
    assert_eq!(req.len(), 8);
    tiny.send(srv.addr, &req).await;
    let (reply, _) = tiny.recv().await;
    assert_eq!(error_code(&reply), 1);
    assert!(
        reply.len() <= req.len(),
        "{}-byte reply to an {}-byte request",
        reply.len(),
        req.len()
    );
    tiny.assert_silent(Duration::from_millis(300)).await;

    // A 4-byte request (empty filename, empty mode) cannot be answered within budget: no reply.
    let mut empty = Client::new().await;
    assert_eq!(rrq(b"", b"").len(), 4);
    empty.send(srv.addr, &rrq(b"", b"")).await;
    empty.assert_silent(Duration::from_millis(400)).await;

    // A flood of minimal requests from one socket: total bytes back <= total bytes out.
    let mut flood = Client::new().await;
    for i in 0..150u32 {
        let name = if i % 3 == 0 {
            b"".to_vec()
        } else {
            format!("f{i}").into_bytes()
        };
        let mode: &[u8] = if i % 2 == 0 { b"mail" } else { b"octet" };
        let packet = if i % 5 == 0 {
            wrq(&name, mode)
        } else {
            rrq(&name, mode)
        };
        flood.send(srv.addr, &packet).await;
    }
    while flood
        .recv_within(Duration::from_millis(500))
        .await
        .is_some()
    {}
    assert!(
        flood.received > 0,
        "the flood must have been answered at all"
    );
    assert!(
        flood.received <= flood.sent,
        "reflected {} bytes for {} sent",
        flood.received,
        flood.sent
    );
    srv.server.abort();
}

#[tokio::test]
async fn a_full_upload_with_retransmits_and_noise_never_amplifies() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "big.bin", "octet").await;

    let block = [0x41u8; BLOCK];
    for n in 1..=20u16 {
        client.send_block(transfer, n, &block).await;
        client.expect_ack(transfer, n).await;
        // Duplicate every third block and inject out-of-order junk: only the duplicate is answered.
        if n % 3 == 0 {
            client.send_block(transfer, n, &block).await;
            client.expect_ack(transfer, n).await;
        }
        client.send_block(transfer, n + 100, &block).await;
        client.send(transfer, &ack(n)).await;
        client.send(transfer, &[1, 2, 3]).await;
        client.assert_silent(Duration::from_millis(10)).await;
    }
    client.send_block(transfer, 21, b"end").await;
    client.expect_ack(transfer, 21).await;

    assert!(
        client.received * 10 < client.sent,
        "an upload must de-amplify heavily: {} received for {} sent",
        client.received,
        client.sent
    );
    let upload = srv.wait_for_upload().await;
    assert_eq!(
        upload.sample.as_ref().unwrap().size,
        (20 * BLOCK + 3) as u64
    );
    assert_eq!(upload.metadata["truncated"], false);
    srv.server.abort();
}

#[tokio::test]
async fn duplicate_data_is_re_acked_and_not_stored_twice() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "dup.bin", "octet").await;

    let first = [b'A'; BLOCK];
    client.send_block(transfer, 1, &first).await;
    client.expect_ack(transfer, 1).await;
    client.send_block(transfer, 1, &first).await;
    client.expect_ack(transfer, 1).await;
    client.send_block(transfer, 1, &first).await;
    client.expect_ack(transfer, 1).await;
    client.send_block(transfer, 2, b"tail").await;
    client.expect_ack(transfer, 2).await;

    let upload = srv.wait_for_upload().await;
    let mut expected = first.to_vec();
    expected.extend_from_slice(b"tail");
    let sample = upload.sample.as_ref().unwrap();
    assert_eq!(sample.sha256, sha_hex(&expected));
    assert_eq!(sample.size, expected.len() as u64);
    assert_eq!(upload.metadata["wire_size"], expected.len() as u64);
    srv.server.abort();
}

#[tokio::test]
async fn out_of_order_blocks_and_block_zero_get_no_reply() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "ooo.bin", "octet").await;

    client.send_block(transfer, 3, b"skipped ahead").await;
    client.send_block(transfer, 0, b"block zero").await;
    client.assert_silent(Duration::from_millis(300)).await;
    client.send_block(transfer, 1, b"real").await;
    client.expect_ack(transfer, 1).await;

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.sample.as_ref().unwrap().sha256, sha_hex(b"real"));
    srv.server.abort();
}

/// A packet from any source other than the requester's exact (ip, port) is dropped: no reply, no
/// body, no budget. If the check were absent the spoofed block 1 would win and the genuine one
/// would be read as a duplicate, so the captured hash would be the attacker's.
#[tokio::test]
async fn a_packet_from_another_source_is_dropped() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "owned.bin", "octet").await;

    let mut same_ip_other_port = Client::new().await;
    same_ip_other_port
        .send_block(transfer, 1, b"EVIL-same-ip")
        .await;
    same_ip_other_port
        .assert_silent(Duration::from_millis(300))
        .await;

    let mut other_ip = Client::bound("127.0.0.2:0").await;
    other_ip.send_block(transfer, 1, b"EVIL-other-ip").await;
    other_ip.send(transfer, &data(2, b"EVIL")).await;
    other_ip.assert_silent(Duration::from_millis(300)).await;

    client.send_block(transfer, 1, b"GOOD").await;
    client.expect_ack(transfer, 1).await;

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.sample.as_ref().unwrap().sha256, sha_hex(b"GOOD"));
    assert_eq!(upload.metadata["wire_size"], 4);
    assert_eq!(srv.uploads().await.len(), 1);
    srv.server.abort();
}

#[tokio::test]
async fn foreign_packets_do_not_keep_a_transfer_alive() {
    let mut bounds = test_bounds();
    bounds.read_timeout = Duration::from_millis(400);
    bounds.idle_timeout = Duration::from_millis(400);
    let srv = TestServer::start_with(bounds, HashMap::new()).await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "stall.bin", "octet").await;
    client.send_block(transfer, 1, &[1u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;

    // Spoofed traffic for well past the idle timeout must not reset the peer's idle clock.
    let mut other = Client::new().await;
    for _ in 0..12 {
        other.send_block(transfer, 2, b"keepalive").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "idle_timeout");
    assert_eq!(upload.sample.as_ref().unwrap().size, BLOCK as u64);
    srv.server.abort();
}

#[tokio::test]
async fn the_body_cap_truncates_still_captures_and_stops_the_transfer() {
    let mut bounds = test_bounds();
    bounds.max_captured_bytes = 1000;
    let srv = TestServer::start_with(bounds, HashMap::new()).await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "huge.bin", "octet").await;

    client.send_block(transfer, 1, &[9u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;
    client.send_block(transfer, 2, &[9u8; BLOCK]).await;
    let (reply, from) = client.recv().await;
    assert_eq!(from, transfer);
    assert_eq!(error_code(&reply), 3, "disk full ends the transfer");
    assert!(reply.len() <= 19);

    let upload = srv.wait_for_upload().await;
    let sample = upload.sample.as_ref().unwrap();
    assert_eq!(sample.size, 1000, "only the capped prefix is retained");
    assert_eq!(sample.sha256, sha_hex(&[9u8; 1000]));
    assert_eq!(upload.metadata["wire_size"], 1024);
    assert_eq!(upload.metadata["truncated"], true);
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "capture_budget");

    // The transfer is over: further blocks get nothing.
    client.send_block(transfer, 3, &[9u8; BLOCK]).await;
    client.assert_silent(Duration::from_millis(300)).await;
    assert_eq!(srv.uploads().await.len(), 1);
    srv.server.abort();
}

/// A cap that is a multiple of the block size cuts exactly on a block boundary, so the retained
/// bytes equal the wire bytes and the framework's `wire_size > size` derivation reads false. The
/// transfer was still aborted mid-upload, so the sensor must report it truncated.
#[tokio::test]
async fn a_block_aligned_body_cap_still_reports_truncated() {
    let mut bounds = test_bounds();
    bounds.max_captured_bytes = 1024;
    let srv = TestServer::start_with(bounds, HashMap::new()).await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "aligned.bin", "octet").await;

    client.send_block(transfer, 1, &[7u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;
    client.send_block(transfer, 2, &[7u8; BLOCK]).await;
    let (reply, _) = client.recv().await;
    assert_eq!(error_code(&reply), 3, "disk full ends the transfer");

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.sample.as_ref().unwrap().size, 1024);
    assert_eq!(upload.metadata["wire_size"], 1024);
    assert_eq!(upload.metadata["truncated"], true);
    assert_eq!(upload.metadata["complete"], false);
    srv.server.abort();
}

#[tokio::test]
async fn an_idle_transfer_is_captured_as_incomplete() {
    let mut bounds = test_bounds();
    bounds.read_timeout = Duration::from_millis(400);
    bounds.idle_timeout = Duration::from_millis(400);
    let srv = TestServer::start_with(bounds, HashMap::new()).await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "stalled.bin", "octet").await;
    client.send_block(transfer, 1, &[5u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "idle_timeout");
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(upload.sample.as_ref().unwrap().size, BLOCK as u64);
    srv.server.abort();
}

#[tokio::test]
async fn a_wrq_that_never_sends_data_is_only_a_probe() {
    let mut bounds = test_bounds();
    bounds.read_timeout = Duration::from_millis(300);
    let srv = TestServer::start_with(bounds, HashMap::new()).await;
    let mut client = Client::new().await;
    let _ = client.begin_write(srv.addr, "nothing", "octet").await;

    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(srv.uploads().await.is_empty());
    assert!(srv.spool_files().is_empty());
    let events = srv.events().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["direction"], "wrq");
    srv.server.abort();
}

#[tokio::test]
async fn max_duration_cancels_a_transfer_and_keeps_what_arrived() {
    let mut bounds = test_bounds();
    bounds.max_duration = Duration::from_millis(600);
    let srv = TestServer::start_with(bounds, HashMap::new()).await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "slowloris.bin", "octet").await;
    client.send_block(transfer, 1, &[3u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;

    // The idle timeout is 5 s, so only max_duration can end this.
    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "session_cancelled");
    assert_eq!(upload.sample.as_ref().unwrap().size, BLOCK as u64);
    srv.server.abort();
}

#[tokio::test]
async fn max_concurrent_drops_requests_beyond_the_limit() {
    let mut bounds = test_bounds();
    bounds.max_concurrent = 1;
    let srv = TestServer::start_with(bounds, HashMap::new()).await;

    let mut first = Client::new().await;
    let transfer = first.begin_write(srv.addr, "holder.bin", "octet").await;

    // The only permit is held by the open transfer: a second request is dropped unanswered. It
    // comes from a different source IP so the per-source cap cannot be what drops it.
    let mut second = Client::bound("127.0.0.2:0").await;
    second.send(srv.addr, &wrq(b"refused.bin", b"octet")).await;
    second.send(srv.addr, &rrq(b"refused.bin", b"octet")).await;
    second.assert_silent(Duration::from_millis(500)).await;
    let wrq_probes = |events: &[SensorEvent]| {
        events
            .iter()
            .filter(|e| e.metadata["filename"] == "refused.bin")
            .count()
    };
    assert_eq!(
        wrq_probes(&srv.events().await),
        0,
        "a dropped request leaves no event"
    );

    // Finishing the first transfer frees the permit.
    first.send_block(transfer, 1, b"done").await;
    first.expect_ack(transfer, 1).await;
    let mut third = Client::bound("127.0.0.3:0").await;
    let mut answered = false;
    for _ in 0..20 {
        third.send(srv.addr, &rrq(b"after.bin", b"octet")).await;
        if third
            .recv_within(Duration::from_millis(250))
            .await
            .is_some()
        {
            answered = true;
            break;
        }
    }
    assert!(
        answered,
        "the permit must be released when the transfer ends"
    );
    srv.server.abort();
}

#[tokio::test]
async fn per_source_cap_drops_one_source_but_still_serves_another() {
    // max_concurrent 8 derives a per-source cap of 2.
    let mut bounds = test_bounds();
    bounds.max_concurrent = 8;
    let srv = TestServer::start_with(bounds, HashMap::new()).await;

    let mut hog = Client::bound("127.0.0.2:0").await;
    let _t1 = hog.begin_write(srv.addr, "hog1.bin", "octet").await;
    let _t2 = hog.begin_write(srv.addr, "hog2.bin", "octet").await;

    // The same source is now at its cap: the next request is dropped unanswered, with no event.
    hog.send(srv.addr, &wrq(b"hog3.bin", b"octet")).await;
    hog.assert_silent(Duration::from_millis(500)).await;
    assert!(
        srv.events()
            .await
            .iter()
            .all(|e| e.metadata["filename"] != "hog3.bin"),
        "a request dropped by the per-source cap leaves no event"
    );

    // A different source is unaffected even though the global limit has plenty of room.
    let mut other = Client::bound("127.0.0.3:0").await;
    other.begin_write(srv.addr, "other.bin", "octet").await;
    srv.server.abort();
}

#[tokio::test]
async fn filename_and_mode_are_sanitized_before_they_reach_an_event() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let hostile = "a\r\n{\"forged\":1}\x1b[31m\u{202e}evil\x07.bin";
    let transfer = client.begin_write(srv.addr, hostile, "OcTeT").await;
    client.send_block(transfer, 1, b"payload").await;
    client.expect_ack(transfer, 1).await;
    let upload = srv.wait_for_upload().await;

    let raw = tokio::fs::read_to_string(&srv.log_path).await.unwrap();
    assert_eq!(
        raw.lines().count(),
        2,
        "one probe and one upload, no forged line"
    );
    for line in raw.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("every line is one JSON object");
    }
    assert!(!raw.contains('\u{202e}'));
    assert!(!raw.contains("\\u001b"), "no escape sequence survives");
    assert!(!raw.contains("\\r") && !raw.contains("\\n\\n"));
    assert!(!raw.contains("\\u0007"));

    let probe = srv
        .events()
        .await
        .into_iter()
        .find(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
        .unwrap();
    let filename = probe.metadata["filename"].as_str().unwrap();
    assert!(
        !filename.contains(['\r', '\n', '\x1b', '\x07', '\u{202e}']),
        "{filename:?}"
    );
    assert!(filename.contains("evil"));
    assert_eq!(upload.metadata["orig_name"].as_str().unwrap(), filename);
    assert_eq!(upload.sample.unwrap().orig_name, filename);
    srv.server.abort();
}

#[tokio::test]
async fn an_unsupported_mode_gets_error_4_and_no_transfer() {
    let srv = TestServer::start().await;
    for (name, mode) in [("a.bin", "binary\r\nINJECT"), ("m.bin", "mail")] {
        let mut client = Client::new().await;
        let req = wrq(name.as_bytes(), mode.as_bytes());
        client.send(srv.addr, &req).await;
        let (reply, _) = client.recv().await;
        assert_eq!(error_code(&reply), 4);
        assert!(reply.len() <= req.len().min(19));
        client.assert_silent(Duration::from_millis(200)).await;
    }
    let events = srv.events().await;
    assert_eq!(events.len(), 2, "both are still recorded as probes");
    assert!(
        events[0].metadata["mode"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| !c.is_control())
    );
    assert!(srv.uploads().await.is_empty());
    srv.server.abort();
}

#[tokio::test]
async fn a_peer_error_ends_the_transfer_and_keeps_the_fragment() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "aborted.bin", "octet").await;
    client.send_block(transfer, 1, &[8u8; BLOCK]).await;
    client.expect_ack(transfer, 1).await;
    client.send(transfer, b"\x00\x05\x00\x00abort\x00").await;

    let upload = srv.wait_for_upload().await;
    assert_eq!(upload.metadata["complete"], false);
    assert_eq!(upload.metadata["end_reason"], "peer_aborted");
    assert_eq!(upload.sample.as_ref().unwrap().size, BLOCK as u64);
    client.assert_silent(Duration::from_millis(200)).await;
    srv.server.abort();
}

#[tokio::test]
async fn an_oversized_data_packet_is_refused_and_not_stored() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let transfer = client.begin_write(srv.addr, "jumbo.bin", "octet").await;
    client.send_block(transfer, 1, &[1u8; BLOCK + 88]).await;
    let (reply, _) = client.recv().await;
    assert_eq!(error_code(&reply), 4);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(srv.uploads().await.is_empty());
    srv.server.abort();
}

/// Garbage on the request socket must neither crash the listener nor draw a reply or an event.
#[tokio::test]
async fn malformed_datagrams_are_ignored_and_the_listener_survives() {
    let srv = TestServer::start().await;
    let mut client = Client::new().await;
    let mut junk: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0, 1],
        b"\x00\x01noterminator".to_vec(),
        b"\x00\x02name\x00octet".to_vec(),
        vec![0, 3, 0, 1, 2, 3],
        vec![0, 4, 0, 1],
        vec![0, 5, 0, 1, 0],
        vec![0, 6, 1, 2],
        vec![0xFF; 1500],
    ];
    for seed in 0..40u32 {
        junk.push(
            (0..(seed * 13 % 700))
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed as u8))
                .collect(),
        );
    }
    for packet in &junk {
        client.send(srv.addr, packet).await;
    }
    client.assert_silent(Duration::from_millis(500)).await;
    assert!(srv.events().await.is_empty(), "noise is not a probe");

    // Still alive and serving.
    let transfer = client.begin_write(srv.addr, "after-junk", "octet").await;
    client.send_block(transfer, 1, b"ok").await;
    client.expect_ack(transfer, 1).await;
    srv.wait_for_upload().await;
    srv.server.abort();
}

#[tokio::test]
async fn wan_ip_is_attributed_from_the_bind_address() {
    let mut map = HashMap::new();
    map.insert(
        "127.0.0.1".parse().unwrap(),
        "198.51.100.4".parse().unwrap(),
    );
    let srv = TestServer::start_with(test_bounds(), map).await;
    let mut client = Client::new().await;
    client.send(srv.addr, &rrq(b"x", b"octet")).await;
    let _ = client.recv().await;
    let events = srv.events().await;
    assert_eq!(
        events[0].wan_ip,
        Some("198.51.100.4".parse::<std::net::IpAddr>().unwrap())
    );
    srv.server.abort();
}

#[tokio::test]
async fn a_bind_that_cannot_be_taken_fails_instead_of_starting() {
    let taken = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = sensor_tftp::start_test_server(
        taken.local_addr().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
        unlimited(),
    )
    .await;
    assert!(result.is_err());
}

// Request-socket rate limiting.

fn md<'a>(e: &'a SensorEvent, key: &str) -> &'a serde_json::Value {
    &e.metadata[key]
}

fn rate_limited(events: &[SensorEvent]) -> Vec<&SensorEvent> {
    events
        .iter()
        .filter(|e| md(e, "query_status") == "rate_limited")
        .collect()
}

fn suppressed_total(events: &[SensorEvent]) -> u64 {
    rate_limited(events)
        .iter()
        .map(|e| md(e, "suppressed_count").as_u64().unwrap())
        .sum()
}

fn probes(events: &[SensorEvent]) -> usize {
    events
        .iter()
        .filter(|e| e.metadata.get("direction").is_some())
        .count()
}

/// Send `n` RRQs back to back and count every reply that arrives within `settle` of the last
/// one. Returns the replies and the time from the first send to the end of collection. Each send
/// yields so the server drains its socket as it goes: a test runtime has one thread, and the
/// kernel would otherwise drop what overflows the socket's receive buffer.
async fn flood(client: &mut Client, to: SocketAddr, n: u16, settle: Duration) -> (usize, Duration) {
    let started = std::time::Instant::now();
    for i in 0..n {
        client
            .send(to, &rrq(format!("f{i}").as_bytes(), b"octet"))
            .await;
        tokio::task::yield_now().await;
    }
    let mut replies = 0;
    while client.recv_within(settle).await.is_some() {
        replies += 1;
    }
    (replies, started.elapsed())
}

#[tokio::test]
async fn a_request_flood_gets_at_most_burst_plus_rate_replies_and_summary_events_not_one_each() {
    let mut limits = rate(5, 10, 100_000, 100_000);
    limits.summary_window = Duration::from_millis(400);
    let srv = TestServer::start_rated(limits).await;
    let mut client = Client::new().await;
    let sent = 300u16;
    let (replies, elapsed) = flood(&mut client, srv.addr, sent, Duration::from_millis(300)).await;
    let ceiling = 10 + (5.0 * elapsed.as_secs_f64()).ceil() as usize;
    assert!(
        (10..=ceiling).contains(&replies),
        "{replies} replies in {elapsed:?}; at most {ceiling} allowed"
    );

    // Every datagram is accounted for: handled ones one probe event each, the rest in summaries.
    let expected_suppressed = u64::from(sent) - replies as u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while suppressed_total(&srv.events().await) < expected_suppressed {
        assert!(
            std::time::Instant::now() < deadline,
            "summaries cover {} of {expected_suppressed}",
            suppressed_total(&srv.events().await)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let events = srv.events().await;
    assert_eq!(suppressed_total(&events), expected_suppressed);
    assert_eq!(probes(&events), replies);
    let summaries = rate_limited(&events);
    // One summary per window the flood touched, never one per datagram.
    assert!(
        !summaries.is_empty() && summaries.len() <= 4,
        "{} summaries",
        summaries.len()
    );
    assert_eq!(events.len(), replies + summaries.len(), "no other events");
    let s = summaries[0];
    assert_eq!(s.sensor, "tftp");
    assert_eq!(s.signal_type, SIGNAL_HONEYPOT_CONNECTION);
    assert_eq!(s.protocol, PROTO_UDP);
    assert!(!s.authenticated);
    assert_eq!(md(s, "protocol_label"), "tftp");
    assert_eq!(md(s, "transport"), "udp");
    assert_eq!(md(s, "source_prefix"), "127.0.0.0/24");
    assert_eq!(s.source_ip, client.sock.local_addr().unwrap().ip());
    assert_eq!(md(s, "distinct_sources"), 1);
    let samples = md(s, "samples").as_array().unwrap();
    assert!(!samples.is_empty() && samples.len() <= 8, "{samples:?}");
    assert!(
        samples[0].as_str().unwrap().starts_with("rrq f"),
        "{samples:?}"
    );
    // The shortest request sent, "f0", is 11 bytes.
    assert!(
        md(s, "suppressed_bytes").as_u64().unwrap()
            >= md(s, "suppressed_count").as_u64().unwrap() * 11
    );
    srv.server.abort();
}

#[tokio::test]
async fn a_second_network_is_answered_while_the_first_is_limited() {
    let srv = TestServer::start_rated(rate(1, 2, 100_000, 100_000)).await;
    let mut flooder = Client::new().await;
    let (replies, _) = flood(&mut flooder, srv.addr, 50, Duration::from_millis(200)).await;
    assert!((2..=3).contains(&replies), "{replies}");
    // 127.0.1.0/24 is a different source network on the same loopback interface.
    let mut other = Client::bound("127.0.1.1:0").await;
    for name in [&b"a.bin"[..], b"b.bin"] {
        other.send(srv.addr, &rrq(name, b"octet")).await;
        let (reply, _) = other.recv().await;
        assert_eq!(error_code(&reply), 1);
    }
    // The flooder is still limited.
    flooder.send(srv.addr, &rrq(b"again", b"octet")).await;
    flooder.assert_silent(Duration::from_millis(200)).await;
    srv.server.abort();
}

/// Every datagram on the request socket is charged before it is parsed, so junk over the limit is
/// counted (as `malformed`) in the same summary as requests, and shutdown writes the summaries
/// whose window has not ended.
#[tokio::test]
async fn shutdown_flushes_the_summaries_still_accumulating_and_junk_is_charged_too() {
    let mut limits = rate(1, 1, 100_000, 100_000);
    limits.summary_window = Duration::from_secs(3600);
    let srv = TestServer::start_rated(limits).await;
    let mut client = Client::new().await;
    client.send(srv.addr, &rrq(b"first", b"octet")).await;
    let (reply, _) = client.recv().await;
    assert_eq!(error_code(&reply), 1, "the burst of one is answered");
    for _ in 0..3 {
        client.send(srv.addr, &[0, 9, 1, 2, 3]).await;
        tokio::task::yield_now().await;
    }
    for i in 0..15 {
        client
            .send(srv.addr, &rrq(format!("g{i}").as_bytes(), b"octet"))
            .await;
        tokio::task::yield_now().await;
    }
    client.assert_silent(Duration::from_millis(300)).await;
    assert!(
        rate_limited(&srv.events().await).is_empty(),
        "the window has not ended"
    );

    srv.server.abort();
    srv.server.flush_rate_limited().await;
    let events = srv.events().await;
    let summaries = rate_limited(&events);
    assert_eq!(summaries.len(), 1);
    let s = summaries[0];
    assert_eq!(md(s, "suppressed_count"), 18);
    assert_eq!(md(s, "per_source_limited"), 18);
    assert_eq!(md(s, "global_limited"), 0);
    // Three 5-byte junk datagrams, ten 11-byte RRQs (g0..g9) and five 12-byte ones (g10..g14).
    assert_eq!(md(s, "suppressed_bytes"), 3 * 5 + 10 * 11 + 5 * 12);
    let samples: Vec<&str> = md(s, "samples")
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        samples,
        [
            "malformed",
            "malformed",
            "malformed",
            "rrq g0",
            "rrq g1",
            "rrq g2",
            "rrq g3",
            "rrq g4"
        ]
    );
    assert_eq!(
        probes(&events),
        1,
        "only the answered request has its own event"
    );
}

/// The source up to its test module. Only the `#[cfg(test)] mod tests` block is cut: a
/// `#[cfg(test)]` item elsewhere (the transfer counter in handler.rs) stays in the scanned text.
fn non_test_source(path: &std::path::Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    match text.find("#[cfg(test)]\nmod tests") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

fn src_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn never_exec_static_check() {
    let mut found = Vec::new();
    for entry in src_files() {
        let content = std::fs::read_to_string(&entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found.push(entry.display().to_string());
        }
    }
    assert!(
        found.is_empty(),
        "sensor-tftp must not spawn processes: {found:?}"
    );
}

/// The reply surface is one `send_to`, behind the byte budget, and nothing dials out: no TCP, no
/// `connect`, and no second place that can write to a UDP socket.
#[test]
fn never_amplifies_static_check() {
    let mut send_sites = Vec::new();
    for entry in src_files() {
        let src = non_test_source(&entry);
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        for banned in [
            "TcpStream",
            "TcpListener",
            ".connect(",
            "UdpSocket::connect",
        ] {
            assert!(
                !src.contains(banned),
                "{name} must not use {banned}: sensor-tftp opens no outbound connection"
            );
        }
        for needle in [".send_to(", ".send(", ".try_send_to(", ".poll_send_to("] {
            let in_guard_wrapper = name == "guarded.rs";
            for (offset, _) in src.match_indices(needle) {
                // `Transfer::send` is the budgeted wrapper; callers elsewhere call it, not the socket.
                let line = src[..offset].lines().last().unwrap_or("");
                let is_socket_call = needle != ".send(" || line.contains("socket");
                if is_socket_call {
                    send_sites.push(format!("{name}: {needle}"));
                    assert!(
                        in_guard_wrapper,
                        "{name} writes to a socket outside the budgeted Transfer: {needle}"
                    );
                }
            }
        }
        if name != "guarded.rs" && name != "lib.rs" {
            assert!(
                !src.contains("UdpSocket::bind"),
                "{name} must not bind its own socket; transfers go through guarded::Transfer"
            );
        }
    }
    assert_eq!(
        send_sites,
        vec!["guarded.rs: .send_to(".to_string()],
        "exactly one UDP send site is allowed, and it is in guarded.rs"
    );
}

fn manifest() -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .unwrap()
}

#[test]
fn sensor_tftp_has_no_http_client_dependency() {
    let manifest = manifest();
    for banned in [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
    ] {
        assert!(
            !manifest.contains(banned),
            "sensor-tftp must not depend on an HTTP client: {banned}"
        );
    }
}

#[test]
fn tokio_dependency_lacks_process_feature() {
    let manifest = manifest();
    let tokio_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("tokio"))
        .expect("tokio dependency");
    assert!(
        !tokio_line.contains("\"process\""),
        "tokio's process feature must stay off: {tokio_line}"
    );
}
