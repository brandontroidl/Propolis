//! SCP and SFTP inbound file capture (Task 14). Captures file uploads over the SCP and SFTP
//! protocols and submits them to `CaptureHandoff` for quarantine spool storage and event
//! emission. See "No attacker-directed fetch" in `internal/design/02-sensor-framework.md`:
//! this module only captures INBOUND writes (files the attacker pushes TO the honeypot);
//! outbound reads are never served.
//!
//! **SCP** (`scp -t <path>`): the client opens an exec channel with `scp -t <path>`. The
//! protocol is a simple handshake: the server acknowledges with `\0`, the client sends a
//! `C<mode> <size> <filename>\n` header, the server acknowledges again, the client streams
//! exactly `<size>` bytes of file data followed by a `\0` trailer, and the server sends a
//! final `\0`. The handler reads the file data, submits it to `CaptureHandoff`, and emits
//! `honeypot_malware_upload`.
//!
//! **SFTP** (subsystem `sftp`): a binary protocol with its own framing (4-byte length +
//! type + request-id + payload). This handler implements the minimum viable subset for
//! inbound write capture: `SSH_FXP_INIT`/`VERSION` negotiation, `OPEN` (write-mode only),
//! `WRITE` (accumulates body per handle), and `CLOSE` (submits to `CaptureHandoff`). Every
//! other verb responds with `SSH_FX_OP_UNSUPPORTED` - no directory listing, no stat, no
//! read-back.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use sensor_framework::{CaptureHandoff, CaptureJob, Uuid};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

// ---- SCP receiver ----

/// Hard ceiling on the in-memory body the SCP receiver will accumulate. Matches
/// `start_test_server`'s spool `max_file_size` (10 MB). Without this cap the attacker-declared
/// size field (a `u64`) would grow the buffer to the declared value before the spool's own
/// per-file check ever fires - an unbounded in-memory allocation on an internet-facing parser.
/// Once the cap is reached, bytes are still consumed (to keep the protocol state machine
/// aligned) but not stored.
const MAX_CAPTURE_BODY: usize = 10_000_000;

enum ScpState {
    /// Waiting for `C<mode> <size> <filename>\n` from the client.
    WaitHeader,
    /// Reading exactly `expected` bytes of file body. `consumed` tracks how many body bytes
    /// have been read from the wire (for protocol framing), which may exceed
    /// `MAX_CAPTURE_BODY` - the body itself stops growing at that cap.
    ReadingBody { expected: u64, consumed: usize },
    /// Waiting for the trailing `\0` from the client.
    WaitTrailer,
    /// Transfer complete (or failed); no more processing.
    Done,
}

/// SCP server-mode receiver (`scp -t <path>`). Constructed when the session orchestrator
/// sees an exec request starting with `scp -t`. Accumulates the transferred file body and
/// submits it to `CaptureHandoff` when the transfer completes.
pub struct ScpReceiver {
    state: ScpState,
    line_buf: Vec<u8>,
    filename: String,
    body: Vec<u8>,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    handoff: Arc<CaptureHandoff>,
}

impl ScpReceiver {
    /// Construct a new SCP receiver and return the initial `\0` acknowledge the SCP protocol
    /// requires the server to send before the client begins.
    pub fn new(
        source_ip: IpAddr,
        wan_ip: Option<IpAddr>,
        session_id: Uuid,
        handoff: Arc<CaptureHandoff>,
    ) -> (Self, Vec<u8>) {
        (
            Self {
                state: ScpState::WaitHeader,
                line_buf: Vec::new(),
                filename: String::new(),
                body: Vec::new(),
                source_ip,
                wan_ip,
                session_id,
                handoff,
            },
            vec![0u8], // initial ready-acknowledge
        )
    }

    /// Feed incoming channel data bytes. Returns response bytes to send back to the client.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            match self.state {
                ScpState::WaitHeader => {
                    while offset < data.len() {
                        let byte = data[offset];
                        offset += 1;
                        if byte == b'\n' {
                            if let Some((size, name)) = parse_scp_header(&self.line_buf) {
                                self.filename = name;
                                self.body.clear();
                                let capped = (size as usize).min(MAX_CAPTURE_BODY);
                                self.body.reserve(capped);
                                self.state = ScpState::ReadingBody {
                                    expected: size,
                                    consumed: 0,
                                };
                                response.push(0); // acknowledge header
                            } else {
                                self.state = ScpState::Done;
                            }
                            self.line_buf.clear();
                            break;
                        }
                        self.line_buf.push(byte);
                        if self.line_buf.len() > 4096 {
                            self.state = ScpState::Done;
                            break;
                        }
                    }
                }
                ScpState::ReadingBody {
                    expected,
                    ref mut consumed,
                } => {
                    let wire_remaining = (expected as usize).saturating_sub(*consumed);
                    let available = data.len() - offset;
                    let take = wire_remaining.min(available);

                    // Only store bytes up to the memory cap; the rest is drained to keep
                    // the protocol state machine aligned with the wire.
                    let storable = MAX_CAPTURE_BODY.saturating_sub(self.body.len()).min(take);
                    if storable > 0 {
                        self.body
                            .extend_from_slice(&data[offset..offset + storable]);
                    }

                    *consumed += take;
                    offset += take;
                    if *consumed >= expected as usize {
                        self.state = ScpState::WaitTrailer;
                    }
                }
                ScpState::WaitTrailer => {
                    // The client sends a single \0 byte after the file body.
                    offset += 1;
                    self.submit_capture();
                    response.push(0); // final ack
                    self.state = ScpState::Done;
                }
                ScpState::Done => break,
            }
        }

        response
    }

    fn submit_capture(&self) {
        let body = self.body.clone();
        let orig_name = self.filename.clone();
        let source_ip = self.source_ip;
        let wan_ip = self.wan_ip;
        let session_id = self.session_id;

        let _ = self.handoff.submit(CaptureJob {
            body,
            orig_name,
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: "ssh".into(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
                protocol: PROTO_TCP.into(),
                authenticated: true,
                observed_at: chrono::Utc::now(),
                metadata: serde_json::json!({
                    "protocol_label": "ssh",
                    "sha256": sample.sha256,
                    "size": sample.size,
                    "orig_name": sample.orig_name,
                }),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        });
    }
}

/// Parse an SCP C-line: `C<mode> <size> <filename>`. Returns `(size, filename)` on success.
fn parse_scp_header(line: &[u8]) -> Option<(u64, String)> {
    let line = std::str::from_utf8(line).ok()?;
    if !line.starts_with('C') {
        return None;
    }
    let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
    if parts.len() < 3 {
        return None;
    }
    let size: u64 = parts[1].parse().ok()?;
    let filename = parts[2].to_string();
    Some((size, filename))
}

// ---- SFTP handler ----

// SFTP v3 message types (draft-ietf-secsh-filexfer-02).
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;

// SFTP status codes.
const SSH_FX_OK: u32 = 0;
const SSH_FX_FAILURE: u32 = 4;
const SSH_FX_OP_UNSUPPORTED: u32 = 8;

// SFTP open pflags.
const SSH_FXF_WRITE: u32 = 0x0000_0002;
const SSH_FXF_CREAT: u32 = 0x0000_0008;

/// Cap on accumulated file body per SFTP handle, matching `ScpReceiver`'s `MAX_CAPTURE_BODY`.
const SFTP_MAX_FILE_BODY: usize = 10_000_000;

/// Max concurrently-open SFTP handles per session, and a ceiling on the TOTAL body bytes resident
/// across ALL open handles. The per-file cap alone does not bound memory: a client can open many
/// handles and write the per-file max to each without ever closing. These bound the count and the
/// sum so one SFTP session cannot OOM the process.
const SFTP_MAX_OPEN_HANDLES: usize = 64;
const SFTP_MAX_SESSION_BYTES: usize = 20_000_000;

/// Maximum SFTP packet length the handler will reassemble. A single SFTP packet larger than
/// this is rejected at framing time rather than accumulated in memory. 256 KB is generous for
/// any legitimate SFTP operation (data chunks are typically <= 64 KB, bounded further by the
/// SSH channel's own max-packet-size of 32 KB) while preventing the attacker-controlled u32
/// length field from growing the reassembly buffer to ~4 GB.
const SFTP_MAX_PACKET_SIZE: usize = 262_144;

/// Per-handle state for an open SFTP file.
struct SftpOpenFile {
    orig_name: String,
    body: Vec<u8>,
}

/// SFTP subsystem handler. Constructed when the session sees a `subsystem sftp` request.
/// Accumulates incoming bytes, parses SFTP packets, and dispatches them.
pub struct SftpHandler {
    buf: Vec<u8>,
    handles: HashMap<String, SftpOpenFile>,
    /// Running sum of body bytes across all currently-open handles, bounded by
    /// `SFTP_MAX_SESSION_BYTES`; decremented when a handle closes.
    resident_body: usize,
    next_handle: u32,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    handoff: Arc<CaptureHandoff>,
}

impl SftpHandler {
    pub fn new(
        source_ip: IpAddr,
        wan_ip: Option<IpAddr>,
        session_id: Uuid,
        handoff: Arc<CaptureHandoff>,
    ) -> Self {
        Self {
            buf: Vec::new(),
            handles: HashMap::new(),
            resident_body: 0,
            next_handle: 0,
            source_ip,
            wan_ip,
            session_id,
            handoff,
        }
    }

    /// Feed incoming channel data and return SFTP response bytes to send back.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        let mut response = Vec::new();

        loop {
            // SFTP framing: uint32 length (of the body after this field) + body.
            if self.buf.len() < 4 {
                break;
            }
            let pkt_len = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
            if pkt_len > SFTP_MAX_PACKET_SIZE {
                // An attacker-declared length this large would grow the reassembly buffer
                // to gigabytes before the packet is ever parsed. Reject it by clearing the
                // buffer - the framing is irrecoverable at this point anyway.
                self.buf.clear();
                break;
            }
            if self.buf.len() < 4 + pkt_len {
                break; // incomplete packet
            }
            if pkt_len == 0 {
                self.buf.drain(..4);
                continue;
            }
            let pkt_body: Vec<u8> = self.buf[4..4 + pkt_len].to_vec();
            self.buf.drain(..4 + pkt_len);

            let msg_type = pkt_body[0];
            let body = &pkt_body[1..];

            match msg_type {
                SSH_FXP_INIT => {
                    response.extend_from_slice(&self.build_version());
                }
                SSH_FXP_OPEN => {
                    response.extend_from_slice(&self.handle_open(body));
                }
                SSH_FXP_WRITE => {
                    response.extend_from_slice(&self.handle_write(body));
                }
                SSH_FXP_CLOSE => {
                    response.extend_from_slice(&self.handle_close(body));
                }
                _ => {
                    // For any other message type, extract the request id if possible
                    // and return OP_UNSUPPORTED.
                    if body.len() >= 4 {
                        let id = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
                        response.extend_from_slice(&build_status(id, SSH_FX_OP_UNSUPPORTED));
                    }
                }
            }
        }

        response
    }

    fn build_version(&self) -> Vec<u8> {
        // SSH_FXP_VERSION: byte(2) + uint32(version=3)
        let body_len: u32 = 1 + 4;
        let mut pkt = Vec::with_capacity(4 + body_len as usize);
        pkt.extend_from_slice(&body_len.to_be_bytes());
        pkt.push(SSH_FXP_VERSION);
        pkt.extend_from_slice(&3u32.to_be_bytes()); // version 3
        pkt
    }

    fn handle_open(&mut self, body: &[u8]) -> Vec<u8> {
        let mut cursor = 0usize;
        let Some(id) = read_u32(body, &mut cursor) else {
            return Vec::new();
        };
        let Some(filename) = read_string(body, &mut cursor) else {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        };
        let Some(pflags) = read_u32(body, &mut cursor) else {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        };

        // Only honor opens with write intent.
        if pflags & (SSH_FXF_WRITE | SSH_FXF_CREAT) == 0 {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        }

        // Bound the number of concurrently-open handles: an attacker can OPEN without CLOSE to grow
        // the handles map (and its bodies) without limit.
        if self.handles.len() >= SFTP_MAX_OPEN_HANDLES {
            return build_status(id, SSH_FX_FAILURE);
        }

        let handle_str = format!("h{}", self.next_handle);
        self.next_handle += 1;

        self.handles.insert(
            handle_str.clone(),
            SftpOpenFile {
                orig_name: String::from_utf8_lossy(&filename).into_owned(),
                body: Vec::new(),
            },
        );

        build_handle(id, &handle_str)
    }

    fn handle_write(&mut self, body: &[u8]) -> Vec<u8> {
        let mut cursor = 0usize;
        let Some(id) = read_u32(body, &mut cursor) else {
            return Vec::new();
        };
        let Some(handle) = read_string(body, &mut cursor) else {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        };
        // Skip uint64 offset.
        if cursor + 8 > body.len() {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        }
        cursor += 8;
        let Some(data) = read_string(body, &mut cursor) else {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        };

        let handle_str = String::from_utf8_lossy(&handle);
        // Store only up to the smaller of the per-file and per-SESSION remaining room, so many open
        // handles cannot sum past SFTP_MAX_SESSION_BYTES. Excess is acknowledged but dropped.
        let session_room = SFTP_MAX_SESSION_BYTES.saturating_sub(self.resident_body);
        let stored = if let Some(file) = self.handles.get_mut(handle_str.as_ref()) {
            let file_room = SFTP_MAX_FILE_BODY.saturating_sub(file.body.len());
            let storable = data.len().min(file_room).min(session_room);
            if storable > 0 {
                file.body.extend_from_slice(&data[..storable]);
            }
            Some(storable)
        } else {
            None
        };
        match stored {
            Some(storable) => {
                self.resident_body += storable;
                build_status(id, SSH_FX_OK)
            }
            None => build_status(id, SSH_FX_OP_UNSUPPORTED),
        }
    }

    fn handle_close(&mut self, body: &[u8]) -> Vec<u8> {
        let mut cursor = 0usize;
        let Some(id) = read_u32(body, &mut cursor) else {
            return Vec::new();
        };
        let Some(handle) = read_string(body, &mut cursor) else {
            return build_status(id, SSH_FX_OP_UNSUPPORTED);
        };

        let handle_str = String::from_utf8_lossy(&handle);
        if let Some(file) = self.handles.remove(handle_str.as_ref()) {
            self.resident_body = self.resident_body.saturating_sub(file.body.len());
            if !file.body.is_empty() {
                self.submit_capture(file);
            }
            build_status(id, SSH_FX_OK)
        } else {
            build_status(id, SSH_FX_OK)
        }
    }

    fn submit_capture(&self, file: SftpOpenFile) {
        let source_ip = self.source_ip;
        let wan_ip = self.wan_ip;
        let session_id = self.session_id;

        let _ = self.handoff.submit(CaptureJob {
            body: file.body,
            orig_name: file.orig_name,
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: "ssh".into(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
                protocol: PROTO_TCP.into(),
                authenticated: true,
                observed_at: chrono::Utc::now(),
                metadata: serde_json::json!({
                    "protocol_label": "ssh",
                    "sha256": sample.sha256,
                    "size": sample.size,
                    "orig_name": sample.orig_name,
                }),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        });
    }
}

// ---- SFTP packet builders ----

/// Build an `SSH_FXP_STATUS` response packet.
fn build_status(id: u32, status_code: u32) -> Vec<u8> {
    // body: byte(101) + uint32(id) + uint32(status) + string("") + string("")
    let body_len: u32 = 1 + 4 + 4 + 4 + 4;
    let mut pkt = Vec::with_capacity(4 + body_len as usize);
    pkt.extend_from_slice(&body_len.to_be_bytes());
    pkt.push(SSH_FXP_STATUS);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&status_code.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes()); // error message (empty)
    pkt.extend_from_slice(&0u32.to_be_bytes()); // language tag (empty)
    pkt
}

/// Build an `SSH_FXP_HANDLE` response packet.
fn build_handle(id: u32, handle: &str) -> Vec<u8> {
    let handle_bytes = handle.as_bytes();
    let body_len: u32 = 1 + 4 + 4 + handle_bytes.len() as u32;
    let mut pkt = Vec::with_capacity(4 + body_len as usize);
    pkt.extend_from_slice(&body_len.to_be_bytes());
    pkt.push(SSH_FXP_HANDLE);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&(handle_bytes.len() as u32).to_be_bytes());
    pkt.extend_from_slice(handle_bytes);
    pkt
}

// ---- Small binary reader helpers ----

fn read_u32(data: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let bytes = data.get(*cursor..end)?;
    let value = u32::from_be_bytes(bytes.try_into().expect("4 bytes"));
    *cursor = end;
    Some(value)
}

fn read_string(data: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    let len = read_u32(data, cursor)? as usize;
    let end = cursor.checked_add(len)?;
    let bytes = data.get(*cursor..end)?.to_vec();
    *cursor = end;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scp_header_valid() {
        let header = b"C0644 1234 evil.bin";
        let (size, name) = parse_scp_header(header).unwrap();
        assert_eq!(size, 1234);
        assert_eq!(name, "evil.bin");
    }

    #[test]
    fn parse_scp_header_rejects_non_c_prefix() {
        assert!(parse_scp_header(b"D0755 0 subdir").is_none());
    }

    #[test]
    fn parse_scp_header_rejects_truncated() {
        assert!(parse_scp_header(b"C0644").is_none());
    }

    #[test]
    fn sftp_build_status_layout() {
        let pkt = build_status(42, SSH_FX_OK);
        let len = u32::from_be_bytes(pkt[..4].try_into().unwrap()) as usize;
        assert_eq!(pkt.len(), 4 + len);
        assert_eq!(pkt[4], SSH_FXP_STATUS);
        let id = u32::from_be_bytes(pkt[5..9].try_into().unwrap());
        assert_eq!(id, 42);
        let code = u32::from_be_bytes(pkt[9..13].try_into().unwrap());
        assert_eq!(code, SSH_FX_OK);
    }

    #[test]
    fn sftp_build_handle_layout() {
        let pkt = build_handle(7, "h0");
        let len = u32::from_be_bytes(pkt[..4].try_into().unwrap()) as usize;
        assert_eq!(pkt.len(), 4 + len);
        assert_eq!(pkt[4], SSH_FXP_HANDLE);
        let id = u32::from_be_bytes(pkt[5..9].try_into().unwrap());
        assert_eq!(id, 7);
    }

    // ---- Memory-cap tests (review finding: unbounded growth is a DoS vector) ----

    /// Helper: build a minimal CaptureHandoff backed by a tempdir. The handoff's worker is
    /// never started (no events emitted), but `submit` succeeds without blocking.
    fn test_handoff() -> Arc<CaptureHandoff> {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool =
            sensor_framework::QuarantineSpool::new(spool_dir, MAX_CAPTURE_BODY as u64, 100_000_000);
        let emitter = sensor_framework::EventEmitter::new(dir.path().join("events.jsonl"));
        // Leak the tempdir so it outlives the handoff (the test is short-lived anyway).
        std::mem::forget(dir);
        Arc::new(CaptureHandoff::new(spool, emitter, 16))
    }

    #[test]
    fn scp_body_capped_at_max_capture_body() {
        // An attacker declares a body larger than MAX_CAPTURE_BODY. The receiver must not
        // grow self.body beyond the cap, but must still advance through the declared byte
        // count to keep the protocol state machine aligned with the wire (so the trailing
        // \0 and final ack still land correctly).
        let handoff = test_handoff();
        let (mut scp, _initial) =
            ScpReceiver::new("127.0.0.1".parse().unwrap(), None, Uuid::now_v7(), handoff);

        // Header declaring 12 MB (above the 10 MB cap).
        let declared: usize = 12_000_000;
        let header = format!("C0644 {declared} huge.bin\n");
        scp.feed(header.as_bytes());

        // Feed the full declared body in 1 MB chunks.
        let chunk = vec![0xAA; 1_000_000];
        for _ in 0..12 {
            scp.feed(&chunk);
        }
        // The body must be capped; the wire must be fully consumed.
        assert!(
            scp.body.len() <= MAX_CAPTURE_BODY,
            "body grew to {} bytes, cap is {MAX_CAPTURE_BODY}",
            scp.body.len()
        );
        assert_eq!(scp.body.len(), MAX_CAPTURE_BODY);

        // Send trailing \0 - the state machine must still be aligned.
        let response = scp.feed(&[0x00]);
        assert_eq!(response, vec![0x00], "final ack must still arrive");
    }

    #[test]
    fn sftp_rejects_oversized_packet() {
        // An attacker sends a 4-byte SFTP length field declaring a packet larger than
        // SFTP_MAX_PACKET_SIZE. The handler must clear its buffer rather than accumulating
        // data toward that length.
        let handoff = test_handoff();
        let mut sftp =
            SftpHandler::new("127.0.0.1".parse().unwrap(), None, Uuid::now_v7(), handoff);

        // Forge a length header claiming 1 GB.
        let huge_len: u32 = 1_000_000_000;
        let mut bad_data = Vec::new();
        bad_data.extend_from_slice(&huge_len.to_be_bytes());
        // Follow with some junk bytes (far less than the declared length).
        bad_data.extend_from_slice(&[0xFF; 1024]);

        let response = sftp.feed(&bad_data);

        // The handler must have cleared its buffer rather than waiting to reassemble 1 GB.
        assert!(
            sftp.buf.is_empty(),
            "buffer should be cleared on oversized packet, has {} bytes",
            sftp.buf.len()
        );
        // No valid SFTP response is produced for the rejected packet.
        assert!(response.is_empty());
    }

    #[test]
    fn sftp_open_handles_are_capped() {
        fn open_pkt(id: u32, filename: &str) -> Vec<u8> {
            let mut body = vec![SSH_FXP_OPEN];
            body.extend_from_slice(&id.to_be_bytes());
            body.extend_from_slice(&(filename.len() as u32).to_be_bytes());
            body.extend_from_slice(filename.as_bytes());
            body.extend_from_slice(&SSH_FXF_WRITE.to_be_bytes());
            let mut pkt = (body.len() as u32).to_be_bytes().to_vec();
            pkt.extend_from_slice(&body);
            pkt
        }

        let handoff = test_handoff();
        let mut sftp =
            SftpHandler::new("127.0.0.1".parse().unwrap(), None, Uuid::now_v7(), handoff);

        // INIT (version 3), then open the cap's worth of write handles without ever closing:
        // each must return a HANDLE.
        let mut init = vec![SSH_FXP_INIT];
        init.extend_from_slice(&3u32.to_be_bytes());
        let mut init_pkt = (init.len() as u32).to_be_bytes().to_vec();
        init_pkt.extend_from_slice(&init);
        let _ = sftp.feed(&init_pkt);

        for i in 0..SFTP_MAX_OPEN_HANDLES as u32 {
            let resp = sftp.feed(&open_pkt(i, &format!("f{i}")));
            assert_eq!(resp[4], SSH_FXP_HANDLE, "open {i} should return a handle");
        }
        // The next OPEN must be refused with a STATUS carrying SSH_FX_FAILURE, not another handle -
        // the guard against an OPEN-without-CLOSE flood OOM.
        let resp = sftp.feed(&open_pkt(999, "overflow"));
        assert_eq!(resp[4], SSH_FXP_STATUS, "over-cap open must be a STATUS");
        let code = u32::from_be_bytes([resp[9], resp[10], resp[11], resp[12]]);
        assert_eq!(code, SSH_FX_FAILURE, "over-cap open must be SSH_FX_FAILURE");
    }

    #[test]
    fn sftp_oversized_length_rejected_as_soon_as_header_readable() {
        // The attacker sends just the 4-byte length in one feed. The cap must fire
        // immediately once the 4 bytes are present - it must not wait for body bytes
        // to arrive before checking.
        let handoff = test_handoff();
        let mut sftp =
            SftpHandler::new("127.0.0.1".parse().unwrap(), None, Uuid::now_v7(), handoff);

        let huge_len: u32 = 500_000;
        let response = sftp.feed(&huge_len.to_be_bytes());

        assert!(
            sftp.buf.is_empty(),
            "buffer should be cleared as soon as the oversized length header is readable"
        );
        assert!(response.is_empty());

        // Subsequent feeds must not accumulate either.
        let response = sftp.feed(&[0xBB; 1024]);
        // The 1024 bytes are a new (incomplete) packet with no valid length yet.
        assert!(sftp.buf.len() <= 1024);
        assert!(response.is_empty());
    }

    #[test]
    fn sftp_oversized_length_split_across_feeds() {
        // The attacker trickles the 4-byte length header across two feeds: the first
        // delivers only 2 bytes (not enough to read the length), the second delivers the
        // remaining 2 bytes. The check must fire on the second feed.
        let handoff = test_handoff();
        let mut sftp =
            SftpHandler::new("127.0.0.1".parse().unwrap(), None, Uuid::now_v7(), handoff);

        let huge_len: u32 = 1_000_000;
        let header = huge_len.to_be_bytes();

        // First feed: only 2 of the 4 length bytes.
        sftp.feed(&header[..2]);
        assert_eq!(sftp.buf.len(), 2, "not enough bytes to read length yet");

        // Second feed: remaining 2 bytes complete the length.
        let response = sftp.feed(&header[2..]);
        assert!(
            sftp.buf.is_empty(),
            "buffer should be cleared once the oversized length is fully readable"
        );
        assert!(response.is_empty());
    }
}
