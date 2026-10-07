//! One TFTP request, start to finish.
//!
//! State machine per request datagram (every state ends the transfer; none loops back to the
//! request socket):
//!
//! ```text
//! RRQ, valid mode   -> ERROR 1 "File not found" (<= 19 bytes, <= request size) -> done
//! RRQ, other mode   -> ERROR 4                                                  -> done
//! WRQ, bad mode     -> ERROR 4                                                  -> done
//! WRQ netascii/octet-> ACK 0 -> [DATA n -> ACK n]* -> short block               -> Complete
//!                      duplicate DATA n-1 -> re-ACK, body untouched
//!                      other DATA / stray packets -> ignored, no reply
//!                      body cap hit -> ERROR 3                                  -> BodyCap
//!                      capture memory budget full -> ERROR 3                    -> CaptureBudget
//!                      idle / packet cap / peer ERROR / oversized DATA          -> ends, incomplete
//! ```
//!
//! The sensor never serves content, never retransmits, and replies to a packet only with a packet
//! no larger than the budget the peer's own traffic earned (see [`crate::guarded`]). A request
//! from a source nothing may be sent to (`sensor_framework::check_reply_source`) is recorded with
//! its `suppress_reason` and gets no transfer socket at all. Uploaded bytes are written to the
//! quarantine spool and never interpreted.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    CaptureBody, CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, FloodSummary,
    SourceRefusal, Uuid, WanResolver, check_reply_source, rate_limited_event, sanitize_value,
    upload_metadata,
};
use sensor_wire::{
    PROTO_UDP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent,
    WIRE_VERSION,
};
use tokio::time::Instant;

use crate::guarded::{Received, Sent, Transfer};
use crate::protocol::{
    self, BLOCK_SIZE, ERR_DISK_FULL, ERR_FILE_NOT_FOUND, ERR_ILLEGAL_OPERATION, MSG_DISK_FULL,
    MSG_FILE_NOT_FOUND, MSG_ILLEGAL_OPERATION, Mode, Packet,
};

pub const PROTOCOL_LABEL: &str = "tftp";
const MAX_FILENAME_LEN: usize = 255;
const MAX_MODE_LEN: usize = 32;

/// Ceiling on a retained upload, whatever `PROPOLIS_TFTP_MAX_CAPTURED_BYTES` says: the spool's own
/// per-file limit (`SPOOL_MAX_FILE_SIZE` in `lib.rs`), so a larger value could only produce a body
/// the spool refuses.
pub const MAX_BODY_HARD_CAP: u64 = 10_000_000;

/// Packets from the peer tolerated beyond the number a transfer of `max_captured_bytes` needs, for
/// duplicates and stray frames. Bounds a peer that streams junk or replays one block forever.
const PACKET_ALLOWANCE: usize = 16;

/// Datagrams are read into a buffer this size. A legal DATA packet is 516 bytes; the slack lets an
/// oversized one be recognised as oversized instead of being silently clipped to look legal.
pub const RECV_BUFFER: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Rrq,
    Wrq,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::Rrq => "rrq",
            Direction::Wrq => "wrq",
        }
    }
}

/// An RRQ or WRQ lifted out of its datagram so it can outlive the receive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRequest {
    pub direction: Direction,
    pub filename: Vec<u8>,
    pub mode: Vec<u8>,
    pub datagram_len: usize,
}

/// `Some` only for a well-formed RRQ or WRQ. Everything else arriving on the request socket (a
/// stray DATA, ACK or ERROR, a malformed request, noise) is dropped without a reply or an event.
pub fn classify(datagram: &[u8]) -> Option<OwnedRequest> {
    let (direction, request) = match protocol::parse(datagram).ok()? {
        Packet::Rrq(r) => (Direction::Rrq, r),
        Packet::Wrq(r) => (Direction::Wrq, r),
        _ => return None,
    };
    Some(OwnedRequest {
        direction,
        filename: request.filename.to_vec(),
        mode: request.mode.to_vec(),
        datagram_len: datagram.len(),
    })
}

/// How a WRQ transfer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The final short block arrived: the whole file.
    Complete,
    /// The retained-body cap was reached with the peer still sending.
    BodyCap,
    /// No valid packet from the peer within the read/idle timeout.
    Idle,
    /// More packets than a transfer of this size can legitimately need.
    PacketCap,
    /// The peer aborted with an ERROR packet.
    PeerError,
    /// The peer sent a DATA packet larger than a block.
    Malformed,
    /// The socket failed, or a reply could not be sent.
    Transport,
    /// The process-wide capture memory budget had no room for more of the file; the prefix already
    /// buffered is kept. Answered with the same ERROR a full disk gets.
    CaptureBudget,
}

pub struct Sensor {
    pub emitter: Arc<EventEmitter>,
    pub wan_resolver: Arc<WanResolver>,
    pub bounds: ConnectionBounds,
    pub handoff: Arc<CaptureHandoff>,
    /// The address the request socket is bound to. Transfer sockets bind here too, so replies leave
    /// from the interface the request arrived on, and WAN attribution resolves against it (UDP
    /// offers no per-datagram local address; under a wildcard bind this is the wildcard, the same
    /// limit `sensor-catchall` documents).
    pub local_ip: IpAddr,
    /// Transfer sockets bound, so in-crate tests can prove a suppressed request never got one.
    #[cfg(test)]
    pub(crate) transfers_bound: std::sync::atomic::AtomicUsize,
}

impl Sensor {
    fn wan_ip(&self) -> Option<IpAddr> {
        self.wan_resolver
            .resolve(normalize_dual_stack(SocketAddr::new(self.local_ip, 0)).ip())
    }

    /// Append one `rate_limited` event per summary.
    pub(crate) async fn emit_summaries(&self, summaries: Vec<FloodSummary>, window: Duration) {
        if summaries.is_empty() {
            return;
        }
        let wan_ip = self.wan_ip();
        let (now, now_utc) = (Instant::now(), Utc::now());
        for summary in &summaries {
            let event = rate_limited_event(
                PROTOCOL_LABEL,
                PROTOCOL_LABEL,
                summary,
                wan_ip,
                window,
                now,
                now_utc,
            );
            if let Err(e) = self.emitter.append(&event).await {
                tracing::error!(error = %e, "tftp: failed to append event");
            }
        }
    }

    /// Handle one request. The caller bounds the whole call with `max_duration`; dropping the
    /// future mid-transfer submits whatever was received as an incomplete capture.
    pub async fn handle_request(&self, peer: SocketAddr, request: OwnedRequest) {
        let source_ip = normalize_dual_stack(peer).ip();
        let wan_ip = self.wan_ip();
        let session_id = Uuid::now_v7();
        let refusal = check_reply_source(peer).err();
        let filename = sanitize_value(
            &String::from_utf8_lossy(&request.filename),
            MAX_FILENAME_LEN,
        );
        let mode_text = sanitize_value(&String::from_utf8_lossy(&request.mode), MAX_MODE_LEN);

        let event = connection_event(
            source_ip,
            wan_ip,
            session_id,
            &filename,
            &mode_text,
            request.direction,
            refusal,
        );
        if let Err(e) = self.emitter.append(&event).await {
            tracing::error!(%peer, error = %e, "tftp: failed to append probe event");
        }
        if refusal.is_some() {
            return;
        }

        let mut transfer = match Transfer::bind(self.local_ip, peer, request.datagram_len).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(%peer, error = %e, "tftp: transfer socket bind failed; no reply");
                return;
            }
        };
        #[cfg(test)]
        self.transfers_bound
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mode = Mode::from_bytes(&request.mode);
        let writable = matches!(mode, Some(Mode::Netascii | Mode::Octet));
        match request.direction {
            Direction::Rrq => {
                // A read is never served. The one reply is a fixed, tiny ERROR.
                let (code, message) = if mode.is_some() {
                    (ERR_FILE_NOT_FOUND, MSG_FILE_NOT_FOUND)
                } else {
                    (ERR_ILLEGAL_OPERATION, MSG_ILLEGAL_OPERATION)
                };
                reply_error(&mut transfer, code, message).await;
            }
            Direction::Wrq if !writable => {
                reply_error(&mut transfer, ERR_ILLEGAL_OPERATION, MSG_ILLEGAL_OPERATION).await;
            }
            Direction::Wrq => {
                let mut capture = UploadCapture {
                    body: self.handoff.new_capture_body(),
                    wire_bytes: 0,
                    submitted: false,
                    cap_hit: false,
                    orig_name: filename,
                    source_ip,
                    wan_ip,
                    session_id,
                    handoff: self.handoff.clone(),
                };
                let outcome = capture.receive(&mut transfer, &self.bounds).await;
                tracing::debug!(
                    %peer,
                    ?outcome,
                    received = transfer.budget().received(),
                    sent = transfer.budget().sent(),
                    "tftp: upload ended"
                );
                capture.finish(outcome == Outcome::Complete);
            }
        }
    }
}

/// Send one ERROR, cut to whatever the byte budget allows (nothing at all if even the shortest
/// form does not fit).
async fn reply_error(transfer: &mut Transfer, code: u16, message: &str) {
    if let Some(packet) = protocol::error(code, message, transfer.budget().remaining()) {
        let _ = transfer.send(&packet).await;
    }
}

/// A WRQ upload being received: the retained body (at most the cap), the payload bytes the peer
/// sent whether retained or not, and what the event needs. Submitted through `finish`, or from
/// `Drop` as incomplete if the handler is cancelled mid-transfer (the `max_duration` timeout drops
/// the whole future, so no code after the receive loop would run).
struct UploadCapture {
    body: CaptureBody,
    wire_bytes: u64,
    submitted: bool,
    /// The body cap aborted the transfer. Recorded explicitly because the framework derives
    /// `truncated` from `wire_size > size`, which is false when the cap is block-aligned and the
    /// cut lands exactly on a block boundary.
    cap_hit: bool,
    orig_name: String,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    handoff: Arc<CaptureHandoff>,
}

impl UploadCapture {
    async fn receive(&mut self, transfer: &mut Transfer, bounds: &ConnectionBounds) -> Outcome {
        let cap = bounds.max_captured_bytes.min(MAX_BODY_HARD_CAP) as usize;
        // Enough packets for a full-cap transfer plus its final short block, plus slack. Because
        // the cap is at most 10 MB, `expected` below never reaches the 16-bit block-number limit.
        let max_packets = cap / BLOCK_SIZE + 2 + PACKET_ALLOWANCE;

        if !matches!(transfer.send(&protocol::ack(0)).await, Sent::Ok) {
            return Outcome::Transport;
        }

        let mut expected: u16 = 1;
        let mut packets = 0usize;
        let mut buf = [0u8; RECV_BUFFER];
        // The deadline moves only on a packet from the peer, so a stream of spoofed datagrams from
        // elsewhere cannot keep a transfer alive.
        let mut deadline = Instant::now() + bounds.read_timeout;
        loop {
            let received = match tokio::time::timeout_at(deadline, transfer.recv(&mut buf)).await {
                Err(_) => return Outcome::Idle,
                Ok(Err(_)) => return Outcome::Transport,
                Ok(Ok(received)) => received,
            };
            let Received::FromPeer(n) = received else {
                continue;
            };
            deadline = Instant::now() + bounds.idle_timeout;
            packets += 1;
            if packets > max_packets {
                return Outcome::PacketCap;
            }

            match protocol::parse(&buf[..n]) {
                Ok(Packet::Data { block, payload }) if block == expected => {
                    if payload.len() > BLOCK_SIZE {
                        reply_error(transfer, ERR_ILLEGAL_OPERATION, MSG_ILLEGAL_OPERATION).await;
                        return Outcome::Malformed;
                    }
                    let take = cap.saturating_sub(self.body.len()).min(payload.len());
                    let kept = self.body.extend_from_slice(&payload[..take]);
                    self.wire_bytes += payload.len() as u64;
                    if kept.is_err() {
                        reply_error(transfer, ERR_DISK_FULL, MSG_DISK_FULL).await;
                        return Outcome::CaptureBudget;
                    }

                    if payload.len() < BLOCK_SIZE {
                        let _ = transfer.send(&protocol::ack(block)).await;
                        return Outcome::Complete;
                    }
                    if self.body.len() >= cap {
                        self.cap_hit = true;
                        reply_error(transfer, ERR_DISK_FULL, MSG_DISK_FULL).await;
                        return Outcome::BodyCap;
                    }
                    if !matches!(transfer.send(&protocol::ack(block)).await, Sent::Ok) {
                        return Outcome::Transport;
                    }
                    let Some(next) = expected.checked_add(1) else {
                        return Outcome::PacketCap;
                    };
                    expected = next;
                }
                // The peer missed our ACK and resent the previous block: acknowledge again, keep
                // nothing. Block 0 is never a duplicate of anything.
                Ok(Packet::Data { block, .. }) if block != 0 && block == expected - 1 => {
                    if !matches!(transfer.send(&protocol::ack(block)).await, Sent::Ok) {
                        return Outcome::Transport;
                    }
                }
                Ok(Packet::Error { .. }) => return Outcome::PeerError,
                // Out-of-order DATA, a stray ACK/RRQ/WRQ/OACK, or garbage: no reply, so a peer
                // cannot make the sensor talk by sending nonsense.
                _ => {}
            }
        }
    }

    fn finish(&mut self, complete: bool) {
        if self.submitted {
            return;
        }
        self.submitted = true;
        // A WRQ that never delivered a byte is a probe, already recorded as such; an empty
        // malware_upload would only add noise. A completed empty file (DATA 1 with no payload) is a
        // real, if odd, upload.
        if self.wire_bytes == 0 && !complete {
            return;
        }
        let body = std::mem::replace(&mut self.body, self.handoff.new_capture_body());
        let orig_name = self.orig_name.clone();
        let (source_ip, wan_ip, session_id, wire_bytes, cap_hit) = (
            self.source_ip,
            self.wan_ip,
            self.session_id,
            self.wire_bytes,
            self.cap_hit,
        );
        let job = CaptureJob {
            body,
            orig_name,
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: PROTOCOL_LABEL.to_string(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.to_string(),
                protocol: PROTO_UDP.to_string(),
                // TFTP has no authentication, so no exchange can count as authenticated.
                authenticated: false,
                observed_at: chrono::Utc::now(),
                metadata: upload_metadata_with_cap(
                    PROTOCOL_LABEL,
                    &sample,
                    wire_bytes,
                    complete,
                    cap_hit,
                ),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        };
        let _ = self.handoff.submit(job);
    }
}

impl Drop for UploadCapture {
    fn drop(&mut self) {
        self.finish(false);
    }
}

/// The shared upload metadata, with `truncated` forced true when the body cap cut the transfer.
fn upload_metadata_with_cap(
    protocol_label: &str,
    sample: &SampleRef,
    wire_bytes: u64,
    complete: bool,
    cap_hit: bool,
) -> serde_json::Value {
    let mut metadata = upload_metadata(protocol_label, sample, wire_bytes, complete);
    if cap_hit {
        metadata["truncated"] = serde_json::Value::Bool(true);
    }
    metadata
}

/// `"<rrq|wrq> <filename>"` for a rate-limited summary's sample, or `"malformed"` for anything
/// that is not a request. The ledger sanitizes and caps it, and runs this only while the summary
/// has room for another sample.
pub(crate) fn flood_sample(datagram: &[u8]) -> String {
    match classify(datagram) {
        Some(r) => format!(
            "{} {}",
            r.direction.label(),
            String::from_utf8_lossy(&r.filename)
        ),
        None => "malformed".to_string(),
    }
}

fn connection_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    filename: &str,
    mode: &str,
    direction: Direction,
    refusal: Option<SourceRefusal>,
) -> SensorEvent {
    let mut metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "filename": filename,
        "mode": mode,
        "direction": direction.label(),
    });
    if let Some(refusal) = refusal {
        metadata["suppress_reason"] = serde_json::json!(refusal.as_str());
    }
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_UDP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata,
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-off with one queue slot and no worker: a second `submit` is refused, which is how a
    /// test proves the first happened.
    fn one_slot_handoff() -> Arc<CaptureHandoff> {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let outbox_dir = dir.path().join("outbox");
        let spool =
            sensor_framework::QuarantineSpool::new(spool_dir, MAX_BODY_HARD_CAP, 100_000_000);
        let emitter = EventEmitter::new(dir.path().join("events.jsonl"));
        std::mem::forget(dir);
        Arc::new(CaptureHandoff::new(
            spool,
            emitter,
            1,
            "test".to_string(),
            sensor_framework::OutboxManifest::new(outbox_dir),
            Arc::new(sensor_framework::CaptureMemoryBudget::new(u64::MAX)),
        ))
    }

    fn probe_job() -> CaptureJob {
        let mut body = CaptureBody::unbudgeted();
        body.extend_from_slice(&[1]).unwrap();
        CaptureJob {
            body,
            orig_name: "probe".into(),
            event_builder: Box::new(|_sample| unreachable!("never built")),
        }
    }

    fn capture(wire_bytes: u64, handoff: &Arc<CaptureHandoff>) -> UploadCapture {
        let mut body = CaptureBody::unbudgeted();
        body.extend_from_slice(&vec![0xAA; wire_bytes as usize])
            .unwrap();
        UploadCapture {
            body,
            wire_bytes,
            submitted: false,
            cap_hit: false,
            orig_name: "x.bin".into(),
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            session_id: Uuid::now_v7(),
            handoff: handoff.clone(),
        }
    }

    /// The `max_duration` timeout cancels a handler by dropping its future mid-transfer; the bytes
    /// already received must still reach the hand-off as an incomplete capture, and a finished
    /// capture must not be submitted a second time by the same mechanism.
    #[tokio::test]
    async fn upload_capture_is_submitted_when_the_handler_is_cancelled() {
        let handoff = one_slot_handoff();
        let held = capture(7, &handoff);
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            let _keep = &held;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(cancelled.is_err());
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the one slot holds the abandoned upload fragment"
        );

        let handoff = one_slot_handoff();
        let mut finished = capture(5, &handoff);
        finished.finish(true);
        drop(finished);
        assert!(
            handoff.submit(probe_job()).is_err(),
            "exactly one submission: finish, not finish plus drop"
        );
    }

    #[test]
    fn a_wrq_that_delivered_nothing_submits_no_capture() {
        let handoff = one_slot_handoff();
        let mut empty = capture(0, &handoff);
        empty.finish(false);
        drop(empty);
        assert!(
            handoff.submit(probe_job()).is_ok(),
            "nothing received, nothing submitted"
        );
    }

    #[test]
    fn a_completed_empty_upload_is_still_a_capture() {
        let handoff = one_slot_handoff();
        let mut empty = capture(0, &handoff);
        empty.finish(true);
        assert!(handoff.submit(probe_job()).is_err());
    }

    fn sensor(log: &std::path::Path) -> Sensor {
        Sensor {
            emitter: Arc::new(EventEmitter::new(log.to_path_buf())),
            wan_resolver: Arc::new(WanResolver::new(std::collections::HashMap::new())),
            bounds: ConnectionBounds {
                read_timeout: std::time::Duration::from_millis(200),
                idle_timeout: std::time::Duration::from_millis(200),
                max_duration: std::time::Duration::from_secs(5),
                max_captured_bytes: 1_000_000,
                max_concurrent: 16,
            },
            handoff: one_slot_handoff(),
            local_ip: "127.0.0.1".parse().unwrap(),
            transfers_bound: Default::default(),
        }
    }

    fn last_event(log: &std::path::Path) -> SensorEvent {
        let text = std::fs::read_to_string(log).unwrap();
        serde_json::from_str(text.lines().last().unwrap()).unwrap()
    }

    fn bound(sensor: &Sensor) -> usize {
        sensor
            .transfers_bound
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The handler, not only the transfer's send, refuses every suppressed source: the probe event
    /// records why, and no transfer socket is bound, so not even the first reply can leave. Both
    /// directions are covered, since a WRQ's first reply is ACK 0 rather than an ERROR.
    #[tokio::test]
    async fn the_handler_suppresses_reflective_ports_and_unroutable_sources() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let sensor = sensor(&log);
        for (peer, reason) in [
            ("198.51.100.9:7", "reflective_source_port"),
            ("198.51.100.9:13", "reflective_source_port"),
            ("198.51.100.9:17", "reflective_source_port"),
            ("198.51.100.9:19", "reflective_source_port"),
            ("198.51.100.9:37", "reflective_source_port"),
            ("198.51.100.9:0", "reflective_source_port"),
            ("255.255.255.255:4000", "unroutable_source"),
            ("0.0.0.0:4000", "unroutable_source"),
            ("224.0.0.1:4000", "unroutable_source"),
            ("[::ffff:224.0.0.1]:4000", "unroutable_source"),
            ("[::ffff:255.255.255.255]:4000", "unroutable_source"),
            ("[ff02::1]:4000", "unroutable_source"),
            ("[::]:4000", "unroutable_source"),
        ] {
            for datagram in [
                &b"\x00\x01boot.bin\x00octet\x00"[..],
                b"\x00\x02up.bin\x00octet\x00",
            ] {
                let request = classify(datagram).unwrap();
                let direction = request.direction.label();
                sensor.handle_request(peer.parse().unwrap(), request).await;
                let e = last_event(&log);
                assert_eq!(e.metadata["direction"], direction, "{peer}");
                assert_eq!(e.metadata["suppress_reason"], reason, "{peer} {direction}");
                assert_eq!(
                    bound(&sensor),
                    0,
                    "{peer} {direction}: a transfer was bound"
                );
            }
        }

        // The counter does count: an ordinary client gets a transfer and its one ERROR.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = classify(b"\x00\x01boot.bin\x00octet\x00").unwrap();
        sensor
            .handle_request(client.local_addr().unwrap(), request)
            .await;
        assert!(last_event(&log).metadata.get("suppress_reason").is_none());
        assert_eq!(bound(&sensor), 1);
        let mut buf = [0u8; 64];
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..4], &[0, 5, 0, 1], "{:?}", &buf[..n]);
    }

    #[test]
    fn flood_samples_name_the_request_or_say_malformed() {
        assert_eq!(
            flood_sample(b"\x00\x01boot.bin\x00octet\x00"),
            "rrq boot.bin"
        );
        assert_eq!(flood_sample(b"\x00\x02a b\x00netascii\x00"), "wrq a b");
        assert_eq!(flood_sample(b"\x00\x01noterminator"), "malformed");
        assert_eq!(
            flood_sample(&[0, 4, 0, 1]),
            "malformed",
            "ACK is not a request"
        );
        assert_eq!(flood_sample(&[]), "malformed");
    }

    #[test]
    fn classify_accepts_only_well_formed_requests() {
        let rrq = classify(b"\x00\x01a.bin\x00octet\x00").unwrap();
        assert_eq!(rrq.direction, Direction::Rrq);
        assert_eq!(rrq.filename, b"a.bin");
        assert_eq!(rrq.mode, b"octet");
        assert_eq!(rrq.datagram_len, 14);
        assert_eq!(
            classify(b"\x00\x02a\x00netascii\x00").unwrap().direction,
            Direction::Wrq
        );
        assert!(classify(b"\x00\x01noterminator").is_none());
        assert!(
            classify(&[0, 3, 0, 1, 9]).is_none(),
            "DATA is not a request"
        );
        assert!(classify(&[0, 4, 0, 0]).is_none(), "ACK is not a request");
        assert!(
            classify(&[0, 5, 0, 1, 0]).is_none(),
            "ERROR is not a request"
        );
        assert!(classify(&[]).is_none());
    }

    #[test]
    fn connection_event_is_unauthenticated_udp_with_the_request_fields() {
        let event = connection_event(
            "203.0.113.7".parse().unwrap(),
            None,
            Uuid::now_v7(),
            "boot.bin",
            "octet",
            Direction::Wrq,
            None,
        );
        assert!(event.metadata.get("suppress_reason").is_none());
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "tftp");
        assert_eq!(event.protocol, PROTO_UDP);
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(event.metadata["protocol_label"], "tftp");
        assert_eq!(event.metadata["filename"], "boot.bin");
        assert_eq!(event.metadata["mode"], "octet");
        assert_eq!(event.metadata["direction"], "wrq");
    }
}
