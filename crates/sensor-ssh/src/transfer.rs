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

use sensor_framework::fakefs::FakeFs;
use sensor_framework::{CaptureHandoff, CaptureJob, Uuid, upload_metadata};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

/// Where a relative upload path lands: the login home the fake shell starts in.
const UPLOAD_HOME: &str = "/root";

/// The permission bits an upload gets when the client sent none (or a malformed value).
const DEFAULT_UPLOAD_PERM: u32 = 0o644;

/// The fake-tree path an upload named `raw` is written to, or `None` when it must not be.
///
/// The path is attacker-supplied, so it is refused outright when it carries a NUL or other control
/// character or any `..` component, rather than normalized: an upload that climbs is hostile, and
/// landing it somewhere it did not name would only mislead. A relative path is taken from
/// [`UPLOAD_HOME`]. The overlay has no host filesystem underneath, so the result is only ever a key
/// into the in-memory tree.
fn upload_destination(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return None;
    }
    if raw.split('/').any(|component| component == "..") {
        return None;
    }
    Some(if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("{UPLOAD_HOME}/{raw}")
    })
}

/// The target path of an `scp -t` exec command: what follows the options, quotes stripped.
fn scp_target(cmd: &str) -> Option<String> {
    let rest = cmd.strip_prefix("scp -t")?;
    let target: Vec<&str> = rest
        .split_whitespace()
        .skip_while(|token| token.starts_with('-'))
        .collect();
    let target = target.join(" ");
    let target = target.trim_matches(|c| c == '\'' || c == '"');
    (!target.is_empty()).then(|| target.to_string())
}

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
    /// Permission bits from the C-line, applied when the file lands in the fake tree.
    perm: u32,
    body: Vec<u8>,
    /// Body bytes consumed off the wire for the current file, capped or not - what the client
    /// actually sent, as opposed to `body.len()`, what was retained.
    wire_bytes: u64,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    handoff: Arc<CaptureHandoff>,
    /// A share of the connection's filesystem: a completed upload is also written into it, so a
    /// later command on the connection can read the file back.
    fs: FakeFs,
    /// The `scp -t` target as typed, `None` when the command named none.
    target: Option<String>,
}

impl ScpReceiver {
    /// Construct a new SCP receiver for the exec command `cmd` (`scp -t <target>`) and return the
    /// initial `\0` acknowledge the SCP protocol requires the server to send before the client
    /// begins. `fs` is a share of the connection's filesystem.
    pub fn new(
        source_ip: IpAddr,
        wan_ip: Option<IpAddr>,
        session_id: Uuid,
        handoff: Arc<CaptureHandoff>,
        fs: FakeFs,
        cmd: &str,
    ) -> (Self, Vec<u8>) {
        (
            Self {
                state: ScpState::WaitHeader,
                line_buf: Vec::new(),
                filename: String::new(),
                perm: DEFAULT_UPLOAD_PERM,
                body: Vec::new(),
                wire_bytes: 0,
                source_ip,
                wan_ip,
                session_id,
                handoff,
                fs,
                target: scp_target(cmd),
            },
            vec![0u8], // initial ready-acknowledge
        )
    }

    /// Where a completed upload lands in the fake tree: the target itself, or the sent file's
    /// name inside it when the target is a directory (or ends in `/`), as `scp` does. Only the last
    /// component of the wire filename is used, so it cannot steer the write out of the target.
    fn fs_destination(&self) -> Option<String> {
        let raw = self.target.as_deref()?;
        let target = upload_destination(raw)?;
        if !raw.ends_with('/') && !self.fs.is_dir(&target) {
            return Some(target);
        }
        let name = self.filename.rsplit('/').next().unwrap_or_default();
        if matches!(name, "" | "." | "..") {
            return None;
        }
        upload_destination(&format!("{}/{name}", target.trim_end_matches('/')))
    }

    /// Best effort and additive: the quarantine spool is the record of the upload, this only gives
    /// the attacker's next command something to find. A refused write (budget, read-only mount,
    /// bad name) is dropped. A body that hit the capture cap is not written, because a truncated
    /// payload that "ran" would be a worse tell than a missing one.
    fn land_in_fake_fs(&mut self) {
        if self.wire_bytes != self.body.len() as u64 {
            return;
        }
        if let Some(dest) = self.fs_destination() {
            let _ = self.fs.write_file_mode(&dest, &self.body, self.perm);
        }
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
                            if let Some((perm, size, name)) = parse_scp_header(&self.line_buf) {
                                self.filename = name;
                                self.perm = perm;
                                self.body.clear();
                                self.wire_bytes = 0;
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
                    self.wire_bytes += take as u64;
                    offset += take;
                    if *consumed >= expected as usize {
                        self.state = ScpState::WaitTrailer;
                    }
                }
                ScpState::WaitTrailer => {
                    // The client sends a single \0 byte after the file body.
                    offset += 1;
                    let _ = self.handoff.submit(self.capture_job(true));
                    self.land_in_fake_fs();
                    response.push(0); // final ack
                    self.state = ScpState::Done;
                }
                ScpState::Done => break,
            }
        }

        response
    }

    /// The session is ending with the transfer unfinished: a body still in flight, or the whole
    /// body received but the trailing `\0` never sent. What arrived is returned as a capture
    /// marked incomplete, for the caller to submit: a dropper cut off before the trailer used to
    /// leave no event and no bytes, as if it had never been sent. One-shot: the state moves to
    /// `Done`, so `Drop` below cannot submit a second copy.
    pub fn abandon(&mut self) -> Option<CaptureJob> {
        let unfinished = matches!(
            self.state,
            ScpState::ReadingBody { .. } | ScpState::WaitTrailer
        ) && self.wire_bytes > 0;
        self.state = ScpState::Done;
        unfinished.then(|| self.capture_job(false))
    }

    fn capture_job(&self, complete: bool) -> CaptureJob {
        let body = self.body.clone();
        let orig_name = self.filename.clone();
        let source_ip = self.source_ip;
        let wan_ip = self.wan_ip;
        let session_id = self.session_id;
        let wire_size = self.wire_bytes;

        CaptureJob {
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
                metadata: upload_metadata("ssh", &sample, wire_size, complete),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        }
    }
}

/// The receiver is dropped however the session ends, including the listener's `max_duration`
/// timeout, which cancels the whole handler future and never reaches any cleanup written after
/// the packet loop. Submitting from `Drop` is what makes an unfinished transfer survive every
/// exit path with one mechanism; `submit` never blocks, so this is safe in a destructor.
impl Drop for ScpReceiver {
    fn drop(&mut self) {
        if let Some(job) = self.abandon() {
            let _ = self.handoff.submit(job);
        }
    }
}

/// Parse an SCP C-line: `C<mode> <size> <filename>`. Returns `(permission bits, size, filename)`
/// on success; a mode that is not octal falls back to [`DEFAULT_UPLOAD_PERM`].
fn parse_scp_header(line: &[u8]) -> Option<(u32, u64, String)> {
    let line = std::str::from_utf8(line).ok()?;
    if !line.starts_with('C') {
        return None;
    }
    let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
    if parts.len() < 3 {
        return None;
    }
    let perm = u32::from_str_radix(parts[0], 8)
        .map(|mode| mode & 0o777)
        .unwrap_or(DEFAULT_UPLOAD_PERM);
    let size: u64 = parts[1].parse().ok()?;
    let filename = parts[2].to_string();
    Some((perm, size, filename))
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
    /// Permission bits from the OPEN attrs, applied when the file lands in the fake tree.
    perm: u32,
    body: Vec<u8>,
    /// Bytes the client wrote to this handle, including any dropped past the per-file or
    /// per-session cap; `body.len()` is what was retained.
    wire_bytes: u64,
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
    /// A share of the connection's filesystem; a closed upload is also written into it.
    fs: FakeFs,
}

impl SftpHandler {
    pub fn new(
        source_ip: IpAddr,
        wan_ip: Option<IpAddr>,
        session_id: Uuid,
        handoff: Arc<CaptureHandoff>,
        fs: FakeFs,
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
            fs,
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

        let perm = read_open_perm(body, &mut cursor);

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
                perm,
                body: Vec::new(),
                wire_bytes: 0,
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
            file.wire_bytes += data.len() as u64;
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
                self.land_in_fake_fs(&file);
                let _ = self.handoff.submit(self.capture_job(file, true));
            }
            build_status(id, SSH_FX_OK)
        } else {
            build_status(id, SSH_FX_OK)
        }
    }

    /// Best effort and additive, as for SCP: write a closed upload that arrived whole into the
    /// fake tree at the path it was opened under. Only a handle that received bytes reaches here,
    /// so an open-and-close never truncates an existing file; a body cut by a cap is not written.
    /// WRITE offsets are not tracked, so the body is the bytes in arrival order.
    fn land_in_fake_fs(&mut self, file: &SftpOpenFile) {
        if file.wire_bytes != file.body.len() as u64 {
            return;
        }
        if let Some(dest) = upload_destination(&file.orig_name) {
            let _ = self.fs.write_file_mode(&dest, &file.body, file.perm);
        }
    }

    /// The session is ending with handles still open. Every one that received bytes is returned
    /// as a capture marked incomplete, for the caller to submit; a file the client never CLOSEd
    /// used to vanish with the session.
    pub fn abandon(&mut self) -> Vec<CaptureJob> {
        self.resident_body = 0;
        let mut open: Vec<SftpOpenFile> = self.handles.drain().map(|(_, f)| f).collect();
        open.retain(|f| f.wire_bytes > 0);
        open.sort_by(|a, b| a.orig_name.cmp(&b.orig_name));
        open.into_iter()
            .map(|file| self.capture_job(file, false))
            .collect()
    }

    fn capture_job(&self, file: SftpOpenFile, complete: bool) -> CaptureJob {
        let source_ip = self.source_ip;
        let wan_ip = self.wan_ip;
        let session_id = self.session_id;
        let wire_size = file.wire_bytes;

        CaptureJob {
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
                metadata: upload_metadata("ssh", &sample, wire_size, complete),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        }
    }
}

/// See `ScpReceiver`'s `Drop`: the same one mechanism for every exit path, the listener's
/// `max_duration` cancellation included.
impl Drop for SftpHandler {
    fn drop(&mut self) {
        for job in self.abandon() {
            let _ = self.handoff.submit(job);
        }
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

/// The permission bits in the ATTRS that follow an OPEN's pflags (SFTP v3: a flags word, then
/// size, uid/gid and permissions in that order when their bits are set). A missing, truncated
/// or permission-less ATTRS yields [`DEFAULT_UPLOAD_PERM`].
fn read_open_perm(body: &[u8], cursor: &mut usize) -> u32 {
    const ATTR_SIZE: u32 = 0x1;
    const ATTR_UIDGID: u32 = 0x2;
    const ATTR_PERMISSIONS: u32 = 0x4;
    let Some(flags) = read_u32(body, cursor) else {
        return DEFAULT_UPLOAD_PERM;
    };
    if flags & ATTR_SIZE != 0 {
        *cursor = cursor.saturating_add(8);
    }
    if flags & ATTR_UIDGID != 0 {
        *cursor = cursor.saturating_add(8);
    }
    if flags & ATTR_PERMISSIONS == 0 {
        return DEFAULT_UPLOAD_PERM;
    }
    read_u32(body, cursor).map_or(DEFAULT_UPLOAD_PERM, |mode| mode & 0o777)
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
        let (perm, size, name) = parse_scp_header(header).unwrap();
        assert_eq!(perm, 0o644);
        assert_eq!(size, 1234);
        assert_eq!(name, "evil.bin");
    }

    #[test]
    fn parse_scp_header_reads_the_octal_mode_and_defaults_a_bad_one() {
        assert_eq!(parse_scp_header(b"C0755 1 x").unwrap().0, 0o755);
        assert_eq!(
            parse_scp_header(b"C4755 1 x").unwrap().0,
            0o755,
            "setuid masked"
        );
        assert_eq!(parse_scp_header(b"C0600 1 x").unwrap().0, 0o600);
        assert_eq!(
            parse_scp_header(b"Cxyz 1 x").unwrap().0,
            DEFAULT_UPLOAD_PERM
        );
        assert_eq!(parse_scp_header(b"C 1 x").unwrap().0, DEFAULT_UPLOAD_PERM);
    }

    #[test]
    fn read_open_perm_walks_the_attrs_in_wire_order() {
        let perm_of = |bytes: &[u8]| read_open_perm(bytes, &mut 0);
        assert_eq!(perm_of(&[]), DEFAULT_UPLOAD_PERM, "no attrs at all");
        assert_eq!(perm_of(&0u32.to_be_bytes()), DEFAULT_UPLOAD_PERM);
        assert_eq!(
            perm_of(&0x4u32.to_be_bytes()),
            DEFAULT_UPLOAD_PERM,
            "truncated"
        );
        // SIZE and UIDGID come before PERMISSIONS and must be skipped.
        let mut attrs = 0x7u32.to_be_bytes().to_vec();
        attrs.extend_from_slice(&99u64.to_be_bytes());
        attrs.extend_from_slice(&[0; 8]);
        attrs.extend_from_slice(&0o100_755u32.to_be_bytes());
        assert_eq!(perm_of(&attrs), 0o755);
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
        let outbox_dir = dir.path().join("outbox");
        let spool =
            sensor_framework::QuarantineSpool::new(spool_dir, MAX_CAPTURE_BODY as u64, 100_000_000);
        let emitter = sensor_framework::EventEmitter::new(dir.path().join("events.jsonl"));
        // Leak the tempdir so it outlives the handoff (the test is short-lived anyway).
        std::mem::forget(dir);
        Arc::new(CaptureHandoff::new(
            spool,
            emitter,
            16,
            "test".to_string(),
            sensor_framework::OutboxManifest::new(outbox_dir),
        ))
    }

    #[test]
    fn scp_body_capped_at_max_capture_body() {
        // An attacker declares a body larger than MAX_CAPTURE_BODY. The receiver must not
        // grow self.body beyond the cap, but must still advance through the declared byte
        // count to keep the protocol state machine aligned with the wire (so the trailing
        // \0 and final ack still land correctly).
        let handoff = test_handoff();
        let (mut scp, _initial) = ScpReceiver::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
            "scp -t /tmp",
        );

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
        // The emitted event must describe the prefix AS a prefix: the full declared size was
        // consumed off the wire, and `upload_metadata` turns wire_bytes > size into `truncated`.
        assert_eq!(scp.wire_bytes, declared as u64);

        // Send trailing \0 - the state machine must still be aligned.
        let response = scp.feed(&[0x00]);
        assert_eq!(response, vec![0x00], "final ack must still arrive");
    }

    fn sample_for(job: &CaptureJob) -> SampleRef {
        SampleRef {
            sha256: "cd".repeat(32),
            size: job.body.len() as u64,
            orig_name: job.orig_name.clone(),
            capture_id: None,
        }
    }

    /// A session that dies with the SCP body half received keeps the half, marked incomplete;
    /// it used to leave nothing.
    #[test]
    fn scp_abandoned_mid_body_yields_an_incomplete_capture() {
        let handoff = test_handoff();
        let (mut scp, _initial) = ScpReceiver::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
            "scp -t /tmp",
        );
        scp.feed(b"C0644 100 dropper.bin\n");
        scp.feed(b"MZ-first-forty-bytes-of-a-hundred-byte-f");
        let job = scp.abandon().expect("bytes arrived, so a capture");
        assert_eq!(job.body, b"MZ-first-forty-bytes-of-a-hundred-byte-f");
        assert_eq!(job.orig_name, "dropper.bin");
        let sample = sample_for(&job);
        let event = (job.event_builder)(sample);
        assert_eq!(event.metadata["complete"], false);
        assert_eq!(event.metadata["wire_size"], 40u64);
        assert_eq!(event.metadata["truncated"], false);
        assert!(scp.abandon().is_none(), "abandon is one-shot");

        // The whole body arrived but the trailing NUL never did: the file is all there, the
        // protocol never finished, and the receiver used to keep nothing because its state was
        // WaitTrailer rather than ReadingBody.
        let (mut trailerless, _) = ScpReceiver::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            test_handoff(),
            FakeFs::new(),
            "scp -t /tmp",
        );
        trailerless.feed(b"C0644 3 x\n");
        trailerless.feed(b"ABC");
        let job = trailerless
            .abandon()
            .expect("a complete body without its trailer is still a capture");
        assert_eq!(job.body, b"ABC");
        let sample = sample_for(&job);
        let event = (job.event_builder)(sample);
        assert_eq!(event.metadata["complete"], false);

        // Nothing arrived after the header: nothing to keep.
        let (mut empty, _) = ScpReceiver::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            test_handoff(),
            FakeFs::new(),
            "scp -t /tmp",
        );
        empty.feed(b"C0644 100 dropper.bin\n");
        assert!(empty.abandon().is_none());
    }

    /// A hand-off with room for exactly one job, so a test can prove a submission happened
    /// without a worker: the next `submit` is refused.
    fn one_slot_handoff() -> Arc<CaptureHandoff> {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let outbox_dir = dir.path().join("outbox");
        let spool =
            sensor_framework::QuarantineSpool::new(spool_dir, MAX_CAPTURE_BODY as u64, 100_000_000);
        let emitter = sensor_framework::EventEmitter::new(dir.path().join("events.jsonl"));
        std::mem::forget(dir);
        Arc::new(CaptureHandoff::new(
            spool,
            emitter,
            1,
            "test".to_string(),
            sensor_framework::OutboxManifest::new(outbox_dir),
        ))
    }

    fn probe_job() -> CaptureJob {
        CaptureJob {
            body: vec![1],
            orig_name: "probe".into(),
            event_builder: Box::new(|_sample| unreachable!("never built")),
        }
    }

    /// The listener cancels a handler at `max_duration` by dropping its future, which never
    /// reaches cleanup code after the packet loop. The receiver's `Drop` is the only thing that
    /// runs on that path, and it must submit the unfinished transfer.
    #[tokio::test]
    async fn scp_and_sftp_submit_the_unfinished_transfer_when_cancelled_by_timeout() {
        let handoff = one_slot_handoff();
        let (mut scp, _) = ScpReceiver::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff.clone(),
            FakeFs::new(),
            "scp -t /tmp",
        );
        scp.feed(b"C0644 100 dropper.bin\n");
        scp.feed(b"MZ-partial");
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            let _keep = &scp;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(
            cancelled.is_err(),
            "the future was cancelled, not completed"
        );
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the one slot holds the abandoned SCP capture"
        );

        let handoff = one_slot_handoff();
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff.clone(),
            FakeFs::new(),
        );
        let mut init = vec![SSH_FXP_INIT];
        init.extend_from_slice(&3u32.to_be_bytes());
        let mut init_pkt = (init.len() as u32).to_be_bytes().to_vec();
        init_pkt.extend_from_slice(&init);
        let _ = sftp.feed(&init_pkt);
        let mut open = vec![SSH_FXP_OPEN];
        open.extend_from_slice(&1u32.to_be_bytes());
        open.extend_from_slice(&1u32.to_be_bytes());
        open.extend_from_slice(b"f");
        open.extend_from_slice(&SSH_FXF_WRITE.to_be_bytes());
        let mut open_pkt = (open.len() as u32).to_be_bytes().to_vec();
        open_pkt.extend_from_slice(&open);
        let resp = sftp.feed(&open_pkt);
        let handle_len = u32::from_be_bytes([resp[9], resp[10], resp[11], resp[12]]) as usize;
        let handle = resp[13..13 + handle_len].to_vec();
        let mut write = vec![SSH_FXP_WRITE];
        write.extend_from_slice(&2u32.to_be_bytes());
        write.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        write.extend_from_slice(&handle);
        write.extend_from_slice(&0u64.to_be_bytes());
        write.extend_from_slice(&3u32.to_be_bytes());
        write.extend_from_slice(b"ELF");
        let mut write_pkt = (write.len() as u32).to_be_bytes().to_vec();
        write_pkt.extend_from_slice(&write);
        let _ = sftp.feed(&write_pkt);
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            let _keep = &sftp;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(cancelled.is_err());
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the one slot holds the abandoned SFTP capture"
        );
    }

    /// SFTP handles still open at session end are captured as incomplete files.
    #[test]
    fn sftp_abandoned_open_handles_yield_incomplete_captures() {
        let handoff = test_handoff();
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
        );
        let mut init = vec![SSH_FXP_INIT];
        init.extend_from_slice(&3u32.to_be_bytes());
        let mut init_pkt = (init.len() as u32).to_be_bytes().to_vec();
        init_pkt.extend_from_slice(&init);
        let _ = sftp.feed(&init_pkt);

        let mut open = vec![SSH_FXP_OPEN];
        open.extend_from_slice(&1u32.to_be_bytes());
        open.extend_from_slice(&11u32.to_be_bytes());
        open.extend_from_slice(b"dropper.elf");
        open.extend_from_slice(&SSH_FXF_WRITE.to_be_bytes());
        let mut open_pkt = (open.len() as u32).to_be_bytes().to_vec();
        open_pkt.extend_from_slice(&open);
        let resp = sftp.feed(&open_pkt);
        assert_eq!(resp[4], SSH_FXP_HANDLE);
        let handle_len = u32::from_be_bytes([resp[9], resp[10], resp[11], resp[12]]) as usize;
        let handle = resp[13..13 + handle_len].to_vec();

        let mut write = vec![SSH_FXP_WRITE];
        write.extend_from_slice(&2u32.to_be_bytes());
        write.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        write.extend_from_slice(&handle);
        write.extend_from_slice(&0u64.to_be_bytes());
        write.extend_from_slice(&7u32.to_be_bytes());
        write.extend_from_slice(b"\x7fELF-fr");
        let mut write_pkt = (write.len() as u32).to_be_bytes().to_vec();
        write_pkt.extend_from_slice(&write);
        let _ = sftp.feed(&write_pkt);

        let mut jobs = sftp.abandon();
        assert_eq!(jobs.len(), 1);
        let job = jobs.remove(0);
        assert_eq!(job.body, b"\x7fELF-fr");
        assert_eq!(job.orig_name, "dropper.elf");
        let sample = sample_for(&job);
        let event = (job.event_builder)(sample);
        assert_eq!(event.metadata["complete"], false);
        assert!(sftp.abandon().is_empty(), "handles are drained");
        assert_eq!(sftp.resident_body, 0);
    }

    #[test]
    fn sftp_rejects_oversized_packet() {
        // An attacker sends a 4-byte SFTP length field declaring a packet larger than
        // SFTP_MAX_PACKET_SIZE. The handler must clear its buffer rather than accumulating
        // data toward that length.
        let handoff = test_handoff();
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
        );

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
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
        );

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
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
        );

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
    fn upload_destination_denies_traversal_and_control_characters() {
        assert_eq!(upload_destination("/tmp/p"), Some("/tmp/p".into()));
        assert_eq!(upload_destination("p"), Some("/root/p".into()));
        assert_eq!(upload_destination(""), None);
        assert_eq!(upload_destination("/tmp/../etc/passwd"), None);
        assert_eq!(upload_destination("../x"), None);
        assert_eq!(upload_destination("/tmp/a\0b"), None);
        assert_eq!(upload_destination("/tmp/a\nb"), None);
        // A dotted name is not a `..` component.
        assert_eq!(upload_destination("/tmp/..x"), Some("/tmp/..x".into()));
    }

    #[test]
    fn scp_target_skips_options_and_quotes() {
        assert_eq!(scp_target("scp -t /tmp/x"), Some("/tmp/x".into()));
        assert_eq!(scp_target("scp -t -d /tmp/"), Some("/tmp/".into()));
        assert_eq!(scp_target("scp -t -- '/tmp/a b'"), Some("/tmp/a b".into()));
        assert_eq!(scp_target("scp -t"), None);
        assert_eq!(scp_target("scp -f /etc/passwd"), None);
    }

    fn scp_upload(fs: FakeFs, cmd: &str, name: &str, body: &[u8]) -> Arc<CaptureHandoff> {
        let handoff = one_slot_handoff();
        let (mut scp, _) = ScpReceiver::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff.clone(),
            fs,
            cmd,
        );
        scp.feed(format!("C0644 {} {name}\n", body.len()).as_bytes());
        scp.feed(body);
        let ack = scp.feed(&[0]);
        assert_eq!(ack, vec![0], "final ack");
        handoff
    }

    #[test]
    fn scp_upload_lands_in_the_shared_fs_and_still_submits_the_capture() {
        let base = FakeFs::new();
        let handoff = scp_upload(
            base.share(),
            "scp -t /tmp/payload",
            "ignored",
            b"MZ-scp-4471",
        );
        assert_eq!(
            base.read_all("/tmp/payload", 64).unwrap(),
            b"MZ-scp-4471",
            "a share of the same connection sees the body at the target"
        );
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the evidence submit happened"
        );
        assert!(
            !FakeFs::new().file_exists("/tmp/payload"),
            "another connection's filesystem is untouched"
        );
    }

    #[test]
    fn scp_into_a_directory_uses_only_the_last_component_of_the_wire_name() {
        let base = FakeFs::new();
        scp_upload(
            base.share(),
            "scp -t /tmp",
            "../../etc/dropped.sh",
            b"#!/bin/sh-9913",
        );
        assert_eq!(
            base.read_all("/tmp/dropped.sh", 64).unwrap(),
            b"#!/bin/sh-9913"
        );
        assert!(!base.file_exists("/etc/dropped.sh"));

        scp_upload(base.share(), "scp -t /tmp/", "..", b"x");
        assert!(
            !base.file_exists("/tmp/.."),
            "a `..` name is refused, not written"
        );
    }

    #[test]
    fn scp_target_that_climbs_is_not_written_but_is_still_captured() {
        let base = FakeFs::new();
        let before = base.read_all("/etc/hostname", 64).unwrap();
        let handoff = scp_upload(
            base.share(),
            "scp -t /tmp/../etc/hostname",
            "h",
            b"pwned-0001",
        );
        assert_eq!(base.read_all("/etc/hostname", 64).unwrap(), before);
        assert!(
            handoff.submit(probe_job()).is_err(),
            "evidence still submitted"
        );
    }

    #[test]
    fn an_upload_over_the_connection_budget_is_not_stored_but_is_still_captured() {
        use sensor_framework::{BudgetLimits, ConnectionBudget};
        let budget = ConnectionBudget::new(BudgetLimits {
            owned_bytes: 1024,
            ..BudgetLimits::standard()
        });
        let base = FakeFs::new().with_budget(budget);
        let body = vec![0xAB; 4096];
        let handoff = scp_upload(base.share(), "scp -t /tmp/big", "big", &body);
        assert!(!base.file_exists("/tmp/big"), "the fs refused the write");
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the capture does not depend on the fs write"
        );
    }

    #[test]
    fn sftp_close_lands_the_body_and_an_open_without_writes_changes_nothing() {
        fn pkt(msg: u8, parts: &[&[u8]]) -> Vec<u8> {
            let mut body = vec![msg];
            for p in parts {
                body.extend_from_slice(p);
            }
            let mut out = (body.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(&body);
            out
        }
        fn s(b: &[u8]) -> Vec<u8> {
            let mut v = (b.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(b);
            v
        }
        let base = FakeFs::new();
        let before = base.read_all("/etc/hostname", 64).unwrap();
        let handoff = one_slot_handoff();
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff.clone(),
            base.share(),
        );
        let open = |sftp: &mut SftpHandler, id: u32, path: &[u8]| {
            let resp = sftp.feed(&pkt(
                SSH_FXP_OPEN,
                &[
                    &id.to_be_bytes(),
                    &s(path),
                    &SSH_FXF_WRITE.to_be_bytes(),
                    &0u32.to_be_bytes(),
                ],
            ));
            let len = u32::from_be_bytes([resp[9], resp[10], resp[11], resp[12]]) as usize;
            resp[13..13 + len].to_vec()
        };
        // Open an existing file and close it with no WRITE: untouched.
        let h = open(&mut sftp, 1, b"/etc/hostname");
        sftp.feed(&pkt(SSH_FXP_CLOSE, &[&2u32.to_be_bytes(), &s(&h)]));
        assert_eq!(base.read_all("/etc/hostname", 64).unwrap(), before);

        let h = open(&mut sftp, 3, b"/var/tmp/sftp_payload");
        sftp.feed(&pkt(
            SSH_FXP_WRITE,
            &[
                &4u32.to_be_bytes(),
                &s(&h),
                &0u64.to_be_bytes(),
                &s(b"ELF-sftp-2288"),
            ],
        ));
        sftp.feed(&pkt(SSH_FXP_CLOSE, &[&5u32.to_be_bytes(), &s(&h)]));
        assert_eq!(
            base.read_all("/var/tmp/sftp_payload", 64).unwrap(),
            b"ELF-sftp-2288"
        );
        assert!(
            handoff.submit(probe_job()).is_err(),
            "evidence submitted on CLOSE"
        );
    }

    #[test]
    fn sftp_oversized_length_split_across_feeds() {
        // The attacker trickles the 4-byte length header across two feeds: the first
        // delivers only 2 bytes (not enough to read the length), the second delivers the
        // remaining 2 bytes. The check must fire on the second feed.
        let handoff = test_handoff();
        let mut sftp = SftpHandler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            Uuid::now_v7(),
            handoff,
            FakeFs::new(),
        );

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
