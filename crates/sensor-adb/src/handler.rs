//! Per-connection ADB session handler: the 24-byte-header read loop, per-stream dispatch (fake
//! shell for `shell:`/`shell:<command>`, sync `SEND`/`RECV`/`STAT` capture for `sync:`), and the
//! `TcpStream` I/O this crate's only stateful, non-pure module owns. See `adb_proto.rs` for the
//! pure message framing this drives and `internal/design/08-remaining-sensors.md`'s "sensor-adb"
//! section for the protocol flow.
//!
//! **Every event this module builds carries `authenticated: false`, with no exception.** ADB has
//! no authentication step at all (see `adb_proto`'s module doc); the task's own wire contract
//! states this plainly enough to repeat here: `is_confirmed_real` requires `authenticated = true
//! AND category = Honeypot`, so ADB signal alone can never manufacture eligibility on its own -
//! that is correct, not a gap this handler should try to work around. Unlike every sibling
//! sensor (SSH/Telnet/Redis), there is no login step here that could ever flip this to `true`.
//!
//! **Stream multiplexing.** Real adb multiplexes many logical streams (a shell session, a sync
//! transfer, ...) over one TCP connection, each identified by a per-side, per-stream id: `OPEN`
//! carries the opener's own id as `local-id`; every later message about that stream carries
//! `(sender's own id, recipient's id)` as `(arg0, arg1)` (confirmed against AOSP's protocol
//! docs: `READY(local-id, remote-id, '')`, `WRITE(...)`/`CLOSE(...)` follow the same shape). This
//! handler mints its own id per accepted `OPEN` and tracks it in a small table keyed by that
//! minted id, so a client that concurrently opens a shell and a sync transfer on one connection
//! (both a real `adb` client and some bots do this) is handled correctly rather than assuming one
//! stream per connection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::fakefs::FakeFs;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::shell::{EmitContext, FakeShell};
use sensor_framework::upload_metadata;
use sensor_framework::{
    CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, Uuid, WanResolver,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent,
    WIRE_VERSION,
};

use crate::adb_proto::{self, Destination, Header, SyncHeader};

/// This sensor's identity on both the wire `sensor` field and every event's
/// `metadata.protocol_label` - see the design spec's "protocol_label: adb" / "sensor name: adb".
const PROTOCOL_LABEL: &str = "adb";

/// Cap on the interactive shell's partial-line buffer, matching sensor-telnet/sensor-ssh's own
/// `MAX_LINE_LEN` convention: if an attacker streams continuous non-newline bytes on a `shell:`
/// stream, the buffer is flushed as a partial line once it hits this limit so memory stays
/// bounded while the input is still captured.
const MAX_SHELL_LINE_LEN: usize = 8192;

/// Cap on accumulated `SEND` file body, matching `sensor-ssh`'s `transfer::MAX_CAPTURE_BODY`
/// convention: bytes beyond this are still drained off the wire (to keep the sync sub-protocol's
/// state machine aligned with what the client believes it sent) but not retained in memory.
const MAX_SYNC_BODY: usize = 10_000_000;

const SHELL_PROMPT: &[u8] = b"root@server01:~# ";

fn connection_event(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

// ---- per-stream state ----

/// One open ADB stream: the client's own id for it (needed on every reply so the client can
/// route the response back to the right stream) plus its protocol-specific state.
struct Stream {
    client_local_id: u32,
    kind: StreamKind,
}

enum StreamKind {
    /// Interactive `shell:` session: `FakeShell` plus a partial-line buffer for incremental
    /// input. A one-shot `shell:<command>` never reaches this table at all - see
    /// `handle_open`'s doc.
    Shell(FakeShell, Vec<u8>),
    /// `sync:` file-transfer sub-protocol session.
    Sync(SyncState),
}

/// Which sync sub-message a `sync:` stream is midway through parsing, plus the reassembly
/// buffer it is fed from. Mirrors `sensor-ssh`'s `transfer::SftpHandler` shape: an accumulating
/// byte buffer, complete sub-messages drained out of it in a loop, one call to `feed` per
/// inbound `WRTE`.
struct SyncState {
    buf: Vec<u8>,
    /// Set while accumulating a `SEND` transfer's body across possibly many `DATA` chunks.
    pending_send: Option<PendingSend>,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
}

struct PendingSend {
    orig_name: String,
    body: Vec<u8>,
    /// DATA payload bytes the client sent, including any drained past `MAX_SYNC_BODY`;
    /// `body.len()` is what was retained.
    wire_bytes: u64,
}

impl SyncState {
    fn new(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> Self {
        Self {
            buf: Vec::new(),
            pending_send: None,
            source_ip,
            wan_ip,
            session_id,
        }
    }

    /// Feed newly arrived `WRTE` payload bytes, draining as many complete sync sub-messages as
    /// are available. Returns the response bytes to send back (a `STAT`/`FAIL`/`OKAY` reply, or
    /// empty if the sub-message consumed produced no immediate reply - e.g. a bare `SEND`
    /// header, which only replies once the matching `DONE` arrives) and, if a `SEND` transfer
    /// just completed, the capture job to hand off.
    ///
    /// Never panics on any input, including a length field that does not match what actually
    /// follows, a `DATA`/`DONE` with no preceding `SEND`, or a completely unrecognized sync id:
    /// every such case is treated as "this sync sub-stream cannot make forward progress" and
    /// resets defensively (clears `buf`, drops any `pending_send`) rather than guessing.
    fn feed(&mut self, data: &[u8]) -> (Vec<u8>, Option<CaptureJob>) {
        self.buf.extend_from_slice(data);
        let mut response = Vec::new();
        let mut upload = None;

        while let Some(sync_header) = SyncHeader::parse(&self.buf) {
            match sync_header.id {
                adb_proto::SYNC_SEND if self.pending_send.is_none() => {
                    if sync_header.length > adb_proto::MAX_SYNC_PATH_LEN {
                        self.reset();
                        break;
                    }
                    let Some(payload) = self.take_payload(sync_header.length) else {
                        break; // wait for more bytes
                    };
                    let path_mode = String::from_utf8_lossy(&payload).into_owned();
                    let orig_name = adb_proto::parse_send_path(&path_mode)
                        .map(|(path, _mode)| path)
                        .unwrap_or_default();
                    self.pending_send = Some(PendingSend {
                        orig_name,
                        body: Vec::new(),
                        wire_bytes: 0,
                    });
                }
                adb_proto::SYNC_DATA if self.pending_send.is_some() => {
                    if sync_header.length > adb_proto::SYNC_MAX_CHUNK {
                        self.reset();
                        break;
                    }
                    let Some(chunk) = self.take_payload(sync_header.length) else {
                        break;
                    };
                    if let Some(pending) = self.pending_send.as_mut() {
                        let storable = MAX_SYNC_BODY.saturating_sub(pending.body.len());
                        let take = storable.min(chunk.len());
                        pending.body.extend_from_slice(&chunk[..take]);
                        pending.wire_bytes += chunk.len() as u64;
                    }
                }
                adb_proto::SYNC_DONE if self.pending_send.is_some() => {
                    // DONE's length field IS the mtime - no further payload bytes to consume.
                    self.buf.drain(..adb_proto::SYNC_HEADER_LEN);
                    if let Some(pending) = self.pending_send.take() {
                        upload = Some(self.build_capture_job(pending, true));
                    }
                    response.extend_from_slice(&adb_proto::build_sync_message(
                        adb_proto::SYNC_OKAY,
                        &[],
                    ));
                }
                adb_proto::SYNC_STAT => {
                    if sync_header.length > adb_proto::MAX_SYNC_PATH_LEN {
                        self.reset();
                        break;
                    }
                    if self.take_payload(sync_header.length).is_none() {
                        break;
                    }
                    response.extend_from_slice(&adb_proto::build_sync_message(
                        adb_proto::SYNC_STAT,
                        &adb_proto::stat_not_found_body(),
                    ));
                }
                adb_proto::SYNC_RECV => {
                    if sync_header.length > adb_proto::MAX_SYNC_PATH_LEN {
                        self.reset();
                        break;
                    }
                    let Some(payload) = self.take_payload(sync_header.length) else {
                        break;
                    };
                    let path = String::from_utf8_lossy(&payload).into_owned();
                    tracing::info!(
                        path = %sanitize_value(&path, 255),
                        "adb: refusing sync RECV (pull); no outbound file data is ever served"
                    );
                    response.extend_from_slice(&adb_proto::build_sync_message(
                        adb_proto::SYNC_FAIL,
                        b"Permission denied",
                    ));
                }
                _ => {
                    // Unrecognized id (LIST/QUIT/DENT/a stray OKAY), or a DATA/DONE/SEND arriving
                    // out of the order this state machine expects: nothing here can make forward
                    // progress, so the sync sub-stream resets defensively. The outer OPEN stream
                    // itself is untouched - a well-behaved client can still CLSE it normally.
                    self.reset();
                    break;
                }
            }
        }

        (response, upload)
    }

    /// If `self.buf` holds at least `SYNC_HEADER_LEN + len` bytes, drain and return the `len`
    /// payload bytes following the sub-header (the sub-header itself is drained too). Otherwise
    /// leaves `buf` untouched and returns `None` - the caller waits for a later `feed` call to
    /// supply the rest.
    fn take_payload(&mut self, len: u32) -> Option<Vec<u8>> {
        let total_needed = adb_proto::SYNC_HEADER_LEN + len as usize;
        if self.buf.len() < total_needed {
            return None;
        }
        let payload = self.buf[adb_proto::SYNC_HEADER_LEN..total_needed].to_vec();
        self.buf.drain(..total_needed);
        Some(payload)
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.pending_send = None;
    }

    /// The stream or session is ending with a `SEND` still open (no `DONE` arrived). The bytes
    /// that did are returned as a capture marked incomplete; they used to be dropped with the
    /// stream.
    fn abandon(&mut self) -> Option<CaptureJob> {
        self.buf.clear();
        let pending = self.pending_send.take()?;
        (pending.wire_bytes > 0).then(|| self.build_capture_job(pending, false))
    }

    fn build_capture_job(&self, pending: PendingSend, complete: bool) -> CaptureJob {
        let source_ip = self.source_ip;
        let wan_ip = self.wan_ip;
        let session_id = self.session_id;
        let wire_size = pending.wire_bytes;
        CaptureJob {
            body: pending.body,
            orig_name: pending.orig_name,
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: PROTOCOL_LABEL.to_string(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.to_string(),
                protocol: PROTO_TCP.to_string(),
                authenticated: false,
                observed_at: chrono::Utc::now(),
                metadata: upload_metadata(PROTOCOL_LABEL, &sample, wire_size, complete),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        }
    }
}

// ---- bounded outer-message reader ----

/// Reads whole ADB messages (24-byte header + `data_length` payload) off the socket, applying
/// `bounds` the same way `sensor-telnet`'s `LineReader` / `sensor-redis`'s `RespReader` do:
/// `read_timeout` bounds the wait for the very first bytes of the whole session, `idle_timeout`
/// bounds every read after that, and a running total checked against `max_captured_bytes` bounds
/// the whole session's captured input regardless of how many messages it spans.
struct MessageReader {
    bounds: ConnectionBounds,
    first_read: bool,
    total_captured: u64,
}

impl MessageReader {
    fn new(bounds: ConnectionBounds) -> Self {
        Self {
            bounds,
            first_read: true,
            total_captured: 0,
        }
    }

    /// Read exactly `n` bytes, or `None` on EOF, a read error, a timeout, or the session's
    /// `max_captured_bytes` budget being exhausted.
    async fn read_exact_bounded(&mut self, stream: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
        if self.total_captured.saturating_add(n as u64) > self.bounds.max_captured_bytes {
            return None;
        }
        let timeout = if self.first_read {
            self.bounds.read_timeout
        } else {
            self.bounds.idle_timeout
        };
        self.first_read = false;

        let mut buf = vec![0u8; n];
        match tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await {
            Ok(Ok(_bytes_read)) => {
                self.total_captured += n as u64;
                Some(buf)
            }
            _ => None,
        }
    }

    /// Read one full ADB message (header + payload). `None` covers every failure mode uniformly
    /// (EOF, timeout, budget exhaustion, a malformed header with a bad magic, or a `data_length`
    /// beyond `adb_proto::MAX_MESSAGE_DATA_LEN`), so the caller has exactly one thing to do on
    /// `None`: end the session.
    async fn read_message(&mut self, stream: &mut TcpStream) -> Option<(Header, Vec<u8>)> {
        let header_bytes = self
            .read_exact_bounded(stream, adb_proto::HEADER_LEN)
            .await?;
        let header = Header::parse(&header_bytes)?;
        if header.data_length > adb_proto::MAX_MESSAGE_DATA_LEN {
            return None;
        }
        let data = if header.data_length == 0 {
            Vec::new()
        } else {
            self.read_exact_bounded(stream, header.data_length as usize)
                .await?
        };
        Some((header, data))
    }
}

// ---- connection handler ----

/// Handle one accepted ADB connection end to end: the `CNXN` handshake, then a loop dispatching
/// `OPEN`/`WRTE`/`OKAY`/`CLSE` across however many concurrent streams the client opens. Never
/// panics and never propagates an I/O error to the caller - any read/write failure or malformed
/// input simply ends the session early, matching `sensor_framework::run_tcp_listener`'s
/// per-connection isolation contract.
pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
) {
    // Normalize dual-stack mapped addresses before resolving WAN - mirrors sensor-telnet/
    // sensor-ssh's own handling of the same listener module doc requirement.
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    // Emit honeypot_connection (authenticated=false) before anything else - the TCP handshake
    // itself is the observation, independent of whether a CNXN ever arrives.
    let conn_event = connection_event(source_ip, wan_ip, session_id);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "adb: failed to append connection event");
    }

    let mut reader = MessageReader::new(bounds);

    // ---- CNXN handshake ----
    let Some((header, _data)) = reader.read_message(&mut stream).await else {
        return;
    };
    if header.command != adb_proto::A_CNXN {
        return; // not a well-formed ADB session opener
    }
    if stream
        .write_all(&adb_proto::build_cnxn(&adb_proto::device_banner()))
        .await
        .is_err()
    {
        return;
    }

    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let mut next_stream_id: u32 = 1;

    // The message loop runs as a block so that however it ends, every sync stream still holding
    // a half-received SEND is flushed below as an incomplete capture instead of dropped.
    async {
        loop {
            let Some((header, data)) = reader.read_message(&mut stream).await else {
                return;
            };

            match header.command {
                adb_proto::A_OPEN => {
                    if handle_open(
                        &mut stream,
                        &header,
                        &data,
                        &mut streams,
                        &mut next_stream_id,
                        source_ip,
                        wan_ip,
                        session_id,
                        &emitter,
                        peer_addr,
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
                adb_proto::A_WRTE => {
                    if handle_wrte(
                        &mut stream,
                        &header,
                        &data,
                        &mut streams,
                        &emitter,
                        &handoff,
                        peer_addr,
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
                adb_proto::A_OKAY => {
                    // Flow-control ack for one of our own WRTEs; this handler never has more than
                    // one outstanding write per stream in flight, so there is nothing to unblock.
                }
                adb_proto::A_CLSE => {
                    let server_id = header.arg1;
                    if let Some(mut s) = streams.remove(&server_id) {
                        // A sync stream closed mid-SEND: keep what arrived, marked incomplete.
                        if let StreamKind::Sync(sync) = &mut s.kind
                            && let Some(job) = sync.abandon()
                        {
                            let _ = handoff.submit(job);
                        }
                        let _ = stream
                            .write_all(&adb_proto::build_clse(server_id, s.client_local_id))
                            .await;
                    }
                    // Unknown stream id (already closed, or never opened): no reply, so garbage
                    // input can never trigger a CLSE reply storm.
                }
                _ => {
                    // A second CNXN mid-session, or any other/unknown command: not well-formed ADB
                    // from this point on. Ending the session is simpler and safer than guessing.
                    return;
                }
            }
        }
    }
    .await;

    for s in streams.values_mut() {
        if let StreamKind::Sync(sync) = &mut s.kind
            && let Some(job) = sync.abandon()
        {
            let _ = handoff.submit(job);
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Max concurrently-open ADB streams per connection. Each accepted interactive/sync OPEN pins a
/// `Stream` (a FakeShell plus its fake filesystem) in the streams map; a real device also bounds
/// concurrent streams, and this stops an OPEN flood from amplifying wire bytes into unbounded heap.
const MAX_STREAMS_PER_CONN: usize = 32;

#[allow(clippy::too_many_arguments)]
async fn handle_open(
    stream: &mut TcpStream,
    header: &Header,
    data: &[u8],
    streams: &mut HashMap<u32, Stream>,
    next_stream_id: &mut u32,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    emitter: &Arc<EventEmitter>,
    peer_addr: SocketAddr,
) -> Result<(), ()> {
    let client_local_id = header.arg0;
    if client_local_id == 0 {
        // OPEN's local-id "may not be zero" per the protocol; not worth trying to recover a
        // session that violates this from the very first stream it opens.
        return Err(());
    }

    // Cap concurrently-open streams. Without this, a client that floods OPEN with a fresh id and
    // never CLSEs pins a FakeShell + FakeFs per stream (~30 wire bytes amplified to KBs of resident
    // heap each), OOM-killing the sensor. Once the cap is hit, refuse further opens with a CLSE
    // (arg0=0 marks a failed open) instead of allocating another stream.
    if streams.len() >= MAX_STREAMS_PER_CONN {
        write_or_err(stream, &adb_proto::build_clse(0, client_local_id)).await?;
        return Ok(());
    }

    let dest = String::from_utf8_lossy(data).into_owned();

    match adb_proto::classify_destination(&dest) {
        Destination::Shell(cmd) => {
            let server_id = *next_stream_id;
            *next_stream_id += 1;
            let ctx = EmitContext {
                source_ip,
                wan_ip,
                authenticated: false,
                protocol_label: PROTOCOL_LABEL.to_string(),
                session_id: Some(session_id),
            };
            let mut shell = FakeShell::new(FakeFs::new(), ctx);

            write_or_err(stream, &adb_proto::build_okay(server_id, client_local_id)).await?;

            match cmd {
                Some(cmd) => {
                    // One-shot exec: run once, write output (if any), then close - mirrors real
                    // adb's `shell:<command>` semantics (the stream closes when the command
                    // exits) and sensor-ssh's `ChannelAction::Exec` one-shot pattern.
                    let (output, events) = shell.handle_input(&cmd);
                    for event in &events {
                        if emitter.append(event).await.is_err() {
                            tracing::error!(%peer_addr, "adb: failed to append command event");
                        }
                    }
                    if !output.is_empty() {
                        write_or_err(
                            stream,
                            &adb_proto::build_wrte(server_id, client_local_id, output.as_bytes()),
                        )
                        .await?;
                    }
                    write_or_err(stream, &adb_proto::build_clse(server_id, client_local_id))
                        .await?;
                    // Never inserted into `streams`: already fully closed.
                }
                None => {
                    write_or_err(
                        stream,
                        &adb_proto::build_wrte(server_id, client_local_id, SHELL_PROMPT),
                    )
                    .await?;
                    streams.insert(
                        server_id,
                        Stream {
                            client_local_id,
                            kind: StreamKind::Shell(shell, Vec::new()),
                        },
                    );
                }
            }
        }
        Destination::Sync => {
            let server_id = *next_stream_id;
            *next_stream_id += 1;
            write_or_err(stream, &adb_proto::build_okay(server_id, client_local_id)).await?;
            streams.insert(
                server_id,
                Stream {
                    client_local_id,
                    kind: StreamKind::Sync(SyncState::new(source_ip, wan_ip, session_id)),
                },
            );
        }
        Destination::Unsupported => {
            tracing::debug!(
                %peer_addr,
                destination = %sanitize_value(&dest, 255),
                "adb: refusing unsupported OPEN destination"
            );
            // arg0=0: this CLOSE indicates a failed OPEN, so no stream id was ever minted for
            // it - exactly the documented "local-id MAY be zero" case.
            write_or_err(stream, &adb_proto::build_clse(0, client_local_id)).await?;
        }
    }
    Ok(())
}

async fn handle_wrte(
    stream: &mut TcpStream,
    header: &Header,
    data: &[u8],
    streams: &mut HashMap<u32, Stream>,
    emitter: &Arc<EventEmitter>,
    handoff: &Arc<CaptureHandoff>,
    peer_addr: SocketAddr,
) -> Result<(), ()> {
    // Routing: arg1 is the recipient's (our) id for the stream - see the module doc's
    // local-id/remote-id convention.
    let server_id = header.arg1;
    let Some(entry) = streams.get_mut(&server_id) else {
        return Ok(()); // unknown stream (already closed, or never opened): ignore, do not reply
    };
    let client_local_id = entry.client_local_id;

    match &mut entry.kind {
        StreamKind::Shell(shell, line_buf) => {
            let mut responses = Vec::new();
            for &byte in data {
                if byte == b'\n' || byte == b'\r' {
                    if !line_buf.is_empty() {
                        let line = String::from_utf8_lossy(line_buf).into_owned();
                        line_buf.clear();
                        let (output, events) = shell.handle_input(&line);
                        for event in &events {
                            if emitter.append(event).await.is_err() {
                                tracing::error!(%peer_addr, "adb: failed to append command event");
                            }
                        }
                        responses.extend_from_slice(output.as_bytes());
                        responses.extend_from_slice(SHELL_PROMPT);
                    }
                } else {
                    line_buf.push(byte);
                    if line_buf.len() >= MAX_SHELL_LINE_LEN {
                        let line = String::from_utf8_lossy(line_buf).into_owned();
                        line_buf.clear();
                        let (_output, events) = shell.handle_input(&line);
                        for event in &events {
                            if emitter.append(event).await.is_err() {
                                tracing::error!(%peer_addr, "adb: failed to append command event");
                            }
                        }
                    }
                }
            }
            write_or_err(stream, &adb_proto::build_okay(server_id, client_local_id)).await?;
            if !responses.is_empty() {
                write_or_err(
                    stream,
                    &adb_proto::build_wrte(server_id, client_local_id, &responses),
                )
                .await?;
            }
        }
        StreamKind::Sync(sync) => {
            let (response, upload) = sync.feed(data);
            write_or_err(stream, &adb_proto::build_okay(server_id, client_local_id)).await?;
            if let Some(job) = upload {
                // Off-response-path: never awaited, never blocks this reply - see
                // sensor_framework::handoff's module doc. A full queue drops the job and is
                // counted, not retried on this hot path.
                let _ = handoff.submit(job);
            }
            if !response.is_empty() {
                write_or_err(
                    stream,
                    &adb_proto::build_wrte(server_id, client_local_id, &response),
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn write_or_err(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), ()> {
    stream.write_all(bytes).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_is_unauthenticated_with_adb_label() {
        let session_id = Uuid::now_v7();
        let event = connection_event("203.0.113.7".parse().unwrap(), None, session_id);
        assert!(!event.authenticated);
        assert_eq!(event.session_id, Some(session_id));
        assert_eq!(event.sensor, "adb");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(event.protocol, PROTO_TCP);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("adb")
        );
        assert_eq!(event.sample, None);
    }

    fn test_sync_state() -> SyncState {
        SyncState::new("203.0.113.7".parse().unwrap(), None, Uuid::now_v7())
    }

    #[test]
    fn sync_send_data_done_produces_capture_job() {
        let mut sync = test_sync_state();
        let mut wire = Vec::new();
        wire.extend_from_slice(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/data/local/tmp/evil.bin,33188",
        ));
        wire.extend_from_slice(&adb_proto::build_sync_message(
            adb_proto::SYNC_DATA,
            b"hello",
        ));
        wire.extend_from_slice(&adb_proto::build_sync_done(1_700_000_000));

        let (response, upload) = sync.feed(&wire);
        let sync_reply = SyncHeader::parse(&response).unwrap();
        assert_eq!(sync_reply.id, adb_proto::SYNC_OKAY);
        let job = upload.expect("SEND+DATA+DONE must produce a capture job");
        assert_eq!(job.body, b"hello");
        assert_eq!(job.orig_name, "/data/local/tmp/evil.bin");
    }

    #[test]
    fn sync_send_split_across_multiple_feed_calls() {
        // The reassembly buffer must persist state across separate WRTE-driven `feed` calls,
        // exactly as a real client trickling SEND/DATA/DONE across separate writes would drive
        // it (see tests/integration.rs's own `sync_push` helper, which does exactly this).
        let mut sync = test_sync_state();
        let (r1, u1) = sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/tmp/x,420",
        ));
        assert!(r1.is_empty());
        assert!(u1.is_none());

        let (r2, u2) = sync.feed(&adb_proto::build_sync_message(adb_proto::SYNC_DATA, b"AB"));
        assert!(r2.is_empty());
        assert!(u2.is_none());

        let (r3, u3) = sync.feed(&adb_proto::build_sync_done(0));
        assert_eq!(SyncHeader::parse(&r3).unwrap().id, adb_proto::SYNC_OKAY);
        assert_eq!(u3.unwrap().body, b"AB");
    }

    /// A SEND whose DONE never arrives (stream closed, session dropped) keeps the DATA that did,
    /// marked incomplete; a completed SEND is marked complete.
    #[test]
    fn sync_abandoned_mid_send_yields_an_incomplete_capture() {
        let sample = |job: &CaptureJob| SampleRef {
            sha256: "ef".repeat(32),
            size: job.body.len() as u64,
            orig_name: job.orig_name.clone(),
            capture_id: None,
        };
        let mut sync = test_sync_state();
        sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/data/local/tmp/x,33188",
        ));
        sync.feed(&adb_proto::build_sync_message(adb_proto::SYNC_DATA, b"AB"));
        let job = sync.abandon().expect("DATA arrived, so a capture");
        assert_eq!(job.body, b"AB");
        let sample_ref = sample(&job);
        let event = (job.event_builder)(sample_ref);
        assert_eq!(event.metadata["complete"], false);
        assert!(sync.abandon().is_none());

        // A SEND with no DATA yet has nothing to keep.
        let mut bare = test_sync_state();
        bare.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/tmp/y,420",
        ));
        assert!(bare.abandon().is_none());

        let mut done = test_sync_state();
        let (_, upload) = done.feed(
            &[
                adb_proto::build_sync_message(adb_proto::SYNC_SEND, b"/tmp/z,420"),
                adb_proto::build_sync_message(adb_proto::SYNC_DATA, b"CD"),
                adb_proto::build_sync_done(0),
            ]
            .concat(),
        );
        let job = upload.unwrap();
        let sample_ref = sample(&job);
        let event = (job.event_builder)(sample_ref);
        assert_eq!(event.metadata["complete"], true);
    }

    #[test]
    fn sync_recv_is_refused_with_fail_and_no_upload() {
        let mut sync = test_sync_state();
        let (response, upload) = sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_RECV,
            b"/data/secrets.txt",
        ));
        assert!(upload.is_none());
        let reply = SyncHeader::parse(&response).unwrap();
        assert_eq!(reply.id, adb_proto::SYNC_FAIL);
        assert!(!response[adb_proto::SYNC_HEADER_LEN..].is_empty());
    }

    #[test]
    fn sync_stat_reports_not_found_and_does_not_upload() {
        let mut sync = test_sync_state();
        let (response, upload) = sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_STAT,
            b"/tmp/probe",
        ));
        assert!(upload.is_none());
        let reply = SyncHeader::parse(&response).unwrap();
        assert_eq!(reply.id, adb_proto::SYNC_STAT);
        assert_eq!(
            &response[adb_proto::SYNC_HEADER_LEN..],
            &adb_proto::stat_not_found_body()
        );
    }

    #[test]
    fn sync_data_body_capped_at_max_sync_body() {
        // An attacker declares (and sends) a body larger than MAX_SYNC_BODY across multiple
        // DATA chunks. The accumulated body must stop growing at the cap - mirrors
        // sensor-ssh's `transfer::scp_body_capped_at_max_capture_body`.
        let mut sync = test_sync_state();
        sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/tmp/huge,420",
        ));
        let chunk = vec![0xAAu8; 100_000];
        for _ in 0..(MAX_SYNC_BODY / chunk.len() + 5) {
            sync.feed(&adb_proto::build_sync_message(adb_proto::SYNC_DATA, &chunk));
        }
        let (_response, upload) = sync.feed(&adb_proto::build_sync_done(0));
        let job = upload.unwrap();
        assert!(
            job.body.len() <= MAX_SYNC_BODY,
            "body grew to {} bytes, cap is {MAX_SYNC_BODY}",
            job.body.len()
        );
        assert_eq!(job.body.len(), MAX_SYNC_BODY);

        // The emitted event must not present the retained prefix as the whole file.
        let sent = (chunk.len() * (MAX_SYNC_BODY / chunk.len() + 5)) as u64;
        let event = (job.event_builder)(SampleRef {
            sha256: "ab".repeat(32),
            size: job.body.len() as u64,
            orig_name: "huge".into(),
            capture_id: None,
        });
        assert_eq!(event.metadata["truncated"], true);
        assert_eq!(event.metadata["wire_size"], sent);
        assert_eq!(event.metadata["size"], MAX_SYNC_BODY as u64);
    }

    #[test]
    fn sync_body_within_cap_is_not_marked_truncated() {
        let mut sync = test_sync_state();
        sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/tmp/small,420",
        ));
        let chunk = vec![0x55u8; 4096];
        sync.feed(&adb_proto::build_sync_message(adb_proto::SYNC_DATA, &chunk));
        let (_response, upload) = sync.feed(&adb_proto::build_sync_done(0));
        let job = upload.unwrap();
        let event = (job.event_builder)(SampleRef {
            sha256: "ab".repeat(32),
            size: job.body.len() as u64,
            orig_name: "small".into(),
            capture_id: None,
        });
        assert_eq!(event.metadata["truncated"], false);
        assert_eq!(event.metadata["wire_size"], 4096u64);
    }

    #[test]
    fn sync_oversized_data_chunk_length_resets_state_without_panicking() {
        let mut sync = test_sync_state();
        sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_SEND,
            b"/tmp/x,420",
        ));
        // Forge a DATA sub-header claiming far more than SYNC_MAX_CHUNK, followed by only a
        // little real data - the declared length alone must trigger the reset, not require
        // actually accumulating toward it.
        let mut forged = adb_proto::SyncHeader {
            id: adb_proto::SYNC_DATA,
            length: adb_proto::SYNC_MAX_CHUNK + 1,
        }
        .encode()
        .to_vec();
        forged.extend_from_slice(&[0xFF; 16]);
        let (response, upload) = sync.feed(&forged);
        assert!(response.is_empty());
        assert!(upload.is_none());
        assert!(
            sync.buf.is_empty(),
            "buffer must be cleared, not accumulated toward"
        );
        assert!(sync.pending_send.is_none());
    }

    #[test]
    fn sync_data_or_done_without_preceding_send_is_ignored_without_panicking() {
        let mut sync = test_sync_state();
        let (response, upload) = sync.feed(&adb_proto::build_sync_message(
            adb_proto::SYNC_DATA,
            b"stray",
        ));
        assert!(response.is_empty());
        assert!(upload.is_none());
    }

    #[test]
    fn sync_feed_never_panics_on_arbitrary_bytes() {
        // Fuzz-lite guard mirroring sensor-telnet's IacFilter convention: `feed` parses fully
        // attacker-controlled, pre-any-check bytes on a stream ADB has no authentication for at
        // all, so arbitrary (including malformed or truncated) input must never panic.
        for seed in 0..20u8 {
            let mut sync = test_sync_state();
            let garbage: Vec<u8> = (0..512u32)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                .collect();
            let _ = sync.feed(&garbage);
        }
    }
}
