//! Per-connection Telnet session handler: negotiates basic options, captures a username/password
//! login (dropping the password immediately), then hands off to the shared `FakeShell` for
//! command capture. See `internal/design/08-remaining-sensors.md`'s "sensor-telnet" section for
//! the protocol flow this composes and `telnet.rs` for the IAC parsing it drives.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use sensor_framework::fakefs::FakeFs;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::persona;
use sensor_framework::sanitize_value;
use sensor_framework::shell::{EmitContext, FakeShell, LineStep, onlcr};
use sensor_framework::{
    CAPTURE_REASON_SHELL_STDIN, CaptureBody, CaptureEnd, CaptureHandoff, CaptureJob, CaptureSource,
    CommandEventGate, ConnectionBounds, ConnectionBudget, EgressState, EventEmitter, HeldEnd,
    HeldInput, InputMode, StdinCaptures, UploadEnd, Uuid, WanResolver, limits_from,
    upload_metadata,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

use crate::telnet::{IacFilter, negotiation_preamble};

/// This sensor's identity on both the wire `sensor` field and every event's
/// `metadata.protocol_label` - see the design spec's "protocol_label: telnet" / "sensor name:
/// telnet".
const PROTOCOL_LABEL: &str = "telnet";

/// Cap on the line buffer, mirroring sensor-ssh's `server::MAX_LINE_LEN`: if an attacker streams
/// continuous non-newline bytes, the buffer is flushed as a partial line once it hits this limit
/// so memory stays bounded while the input is still captured.
const MAX_LINE_LEN: usize = 8192;

/// Cap applied to the sanitized username captured in `honeypot_login_attempt`'s metadata,
/// matching sensor-ssh's `auth::MAX_METADATA_STRING_LEN` convention.
const MAX_USERNAME_LEN: usize = 255;

/// Size of each individual raw socket read. Deliberately small and fixed (unrelated to
/// `bounds.max_captured_bytes`, which bounds the whole session): a large single read would let
/// one `stream.read()` call pull in far more than a typical line before this handler gets a
/// chance to apply `MAX_LINE_LEN`/the total-captured cap.
const READ_CHUNK_SIZE: usize = 1024;

const PROMPT_PASSWORD: &[u8] = b"Password: ";

/// Handle one accepted Telnet connection end to end: negotiation, login, then the fake shell.
/// Never panics and never propagates an I/O error to the caller - any read/write failure or
/// malformed input simply ends the session early, matching `sensor_framework::run_tcp_listener`'s
/// per-connection isolation contract (a dropped connection here never affects the accept loop or
/// any other in-flight session).
///
/// `handoff` captures the raw shell-phase input as evidence when the shared `FakeShell` flags a
/// binary payload (the "flood": "binary" marker `is_binary_line` sets in `shell.rs`) - a
/// Mirai/Gafgyt loader's binary dropper, which `FakeShell` otherwise suppresses to a one-line
/// marker and would be lost. Capture starts only after login (`LineReader::start_capture`, called
/// just before the shell loop below), so the attacker's password is never in the captured bytes.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
    command_events: Arc<CommandEventGate>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Normalize dual-stack mapped addresses before resolving WAN, so an IPv4-mapped IPv6 address
    // (::ffff:a.b.c.d from a dual-stack listener) matches the operator's plain-IPv4 WAN map entry
    // - mirrors sensor-ssh's `server::handle_session` handling of the same listener module doc
    // requirement.
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = local_addr
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    // Emit honeypot_connection (authenticated=false) before anything else - the TCP handshake
    // itself is the observation, independent of whatever happens (or fails to happen) next.
    let conn_event = connection_event(source_ip, wan_ip, session_id);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "telnet: failed to append connection event");
    }

    let write_timeout = bounds.idle_timeout;

    if write_raw(&mut stream, write_timeout, &negotiation_preamble())
        .await
        .is_err()
    {
        return;
    }

    // A real telnetd prints the network issue banner then a hostname-qualified login prompt. Both
    // come from the shared persona so the hostname matches uname / the shell prompt / the other
    // sensors, instead of a bare "login:" with no host and a cross-instance-constant shell prompt.
    let host = persona::hostname();
    let issue = format!("{}\n", persona::OS_PRETTY);
    if write_telnet_data(&mut stream, write_timeout, issue.as_bytes(), None)
        .await
        .is_err()
    {
        return;
    }

    // Built before `bounds` moves into the reader: the connection's one budget, which also carries
    // the sensor's per-source command-event budget to the shell.
    let budget = ConnectionBudget::with_command_gate(limits_from(&bounds), command_events);
    let mut reader = LineReader::new(bounds, handoff.clone());

    let login_prompt = format!("{host} login: ");
    if write_telnet_data(&mut stream, write_timeout, login_prompt.as_bytes(), None)
        .await
        .is_err()
    {
        return;
    }
    let Some(username_raw) = reader.read_line(&mut stream, true).await else {
        return;
    };
    let username = sanitize_value(&username_raw, MAX_USERNAME_LEN);

    if write_telnet_data(&mut stream, write_timeout, PROMPT_PASSWORD, None)
        .await
        .is_err()
    {
        return;
    }
    // The password is read only far enough to advance past the login prompt - mirrors
    // sensor-ssh's `auth.rs` password invariant. It is never stored beyond this local binding,
    // never logged, and never placed in any event field; it is dropped the moment this
    // connection's stack frame moves past this point.
    let Some(_password) = reader.read_line(&mut stream, false).await else {
        return;
    };

    // Accept all credentials unconditionally - see the design spec's "Accept all credentials,
    // emit honeypot_login_attempt (authenticated=true)". There is nothing behind this honeypot
    // worth gatekeeping; the goal is to let the attacker reach the shell and reveal intent.
    let login_event = login_event(source_ip, wan_ip, &username, session_id);
    if emitter.append(&login_event).await.is_err() {
        tracing::error!(%peer_addr, "telnet: failed to append login event");
    }

    let ctx = EmitContext {
        source_ip,
        wan_ip,
        authenticated: true,
        protocol_label: PROTOCOL_LABEL.to_string(),
        session_id: Some(session_id),
    };
    let shell = FakeShell::new(FakeFs::new(), ctx).with_budget(budget.clone());

    if write_telnet_data(
        &mut stream,
        write_timeout,
        shell.prompt().as_bytes(),
        Some(&shell),
    )
    .await
    .is_err()
    {
        return;
    }

    // Capture is shell-phase only: it starts here, after the password has already been read and
    // dropped above, and never before - so a captured sample can never contain the login
    // credentials. See the crate-level design note above `handle_connection`.
    reader.start_capture();
    // Arm the reader to submit its capture from `Drop`. The listener enforces `max_duration` by
    // dropping this whole future, so a submit written after the loop below never runs for a
    // session that hits the bound - and a dropper streaming a large payload is exactly the
    // session that does. `Drop` is the only code that runs on every exit path.
    reader.arm_capture_submit(source_ip, wan_ip, session_id);

    // What commands read from the terminal (`cat > f` takes the lines after it until Ctrl-D),
    // captured once per distinct body and submitted when this session's future goes, cancelled
    // or not.
    let stdin_captures = StdinCaptures::new(
        handoff.clone(),
        CaptureSource {
            sensor: PROTOCOL_LABEL,
            source_ip,
            wan_ip,
            session_id,
            authenticated: true,
        },
    );
    let max_stdin_bytes = reader.bounds.max_captured_bytes;
    // A file the shell sees assembled from typed `echo` chunks is captured through the same set.
    let mut shell = shell.with_captures(stdin_captures.clone());

    loop {
        let Some(line) = reader.read_line(&mut stream, true).await else {
            break;
        };
        let (step, events) = shell.start_line(&line);
        for event in &events {
            if event.metadata.get("flood").and_then(|v| v.as_str()) == Some("binary") {
                reader.flag_binary();
            }
            if emitter.append(event).await.is_err() {
                tracing::error!(%peer_addr, "telnet: failed to append command event");
            }
        }
        let output = match step {
            LineStep::Ran(output) => output,
            LineStep::AwaitingInput => {
                // The bytes after the line are the command's input until it ends, as on the
                // terminal a real telnetd hands the shell; they never reach the line reader.
                let mut input = HeldInput::new(
                    &shell,
                    InputMode::Terminal,
                    &stdin_captures,
                    CAPTURE_REASON_SHELL_STDIN,
                    max_stdin_bytes,
                );
                // Each Enter hands the command its line: `read x` finishes on the first.
                input.per_line();
                match reader.read_held(&mut stream, &mut input, &mut shell).await {
                    Some(HeldOutcome::Ended(end)) => input.finish(&mut shell, end),
                    Some(HeldOutcome::Resumed(output)) => output,
                    None => {
                        let _ = input.finish(&mut shell, HeldEnd::Cut(reader.session_end));
                        break;
                    }
                }
            }
        };
        let close_session = output.close_session;

        if close_session {
            // Not charged: the session ends with this write, so there is no later write for the
            // count to refuse.
            let _ =
                write_telnet_data(&mut stream, write_timeout, output.bytes(), Some(&shell)).await;
            reader.mark_session_end(CaptureEnd::ClientLogout);
            break;
        }

        let mut response = output.bytes().to_vec();
        response.extend_from_slice(shell.prompt().as_bytes());
        let encoded = encode_telnet_data(&response, Some(&shell));
        if write_raw(&mut stream, write_timeout, &encoded)
            .await
            .is_err()
        {
            reader.mark_session_end(CaptureEnd::TransportError);
            break;
        }
        // Charged as written, after ONLCR and the codec. A connection with no egress left is
        // dropped once this reply, prompt included, is out.
        if budget.charge_egress(encoded.len() as u64) == EgressState::Spent {
            reader.mark_session_end(CaptureEnd::TransportError);
            break;
        }
    }
    // A file assembled and never run is captured as the session leaves it, ended this way.
    stdin_captures.end_session(reader.session_end);

    // Nothing else is recorded here. Every exit above - and every one inside `read_line` - names the
    // ending that produced it, because they do not mean the same thing: a logout leaves a whole
    // capture, an idle timeout or a failed write leaves a fragment. This line used to set
    // "complete" for all of them alike. The capture itself is submitted by `LineReader`'s `Drop`
    // (see `arm_capture_submit`), the only code that also runs when the listener cancels this
    // future at `max_duration`.
}

/// Encode application data in the one order a Telnet client observes it: terminal newlines,
/// optional per-session XOR, then RFC 854 escaping of literal IAC bytes. Negotiation commands do
/// not pass through this function because their 0xff bytes are protocol markers, not data.
fn encode_telnet_data(bytes: &[u8], shell: Option<&FakeShell>) -> Vec<u8> {
    let terminal = onlcr(bytes);
    let coded = match shell {
        Some(shell) => shell.encode_output(&terminal),
        None => terminal,
    };
    escape_iac(&coded)
}

/// RFC 854 escaping: a literal 0xff data byte is sent doubled so it is not read as IAC.
fn escape_iac(bytes: &[u8]) -> Vec<u8> {
    let iac_count = bytes.iter().filter(|&&byte| byte == 0xff).count();
    let mut escaped = Vec::with_capacity(bytes.len().saturating_add(iac_count));
    for &byte in bytes {
        escaped.push(byte);
        if byte == 0xff {
            escaped.push(0xff);
        }
    }
    escaped
}

async fn write_raw<S: AsyncWrite + Unpin>(
    stream: &mut S,
    write_timeout: Duration,
    bytes: &[u8],
) -> Result<(), ()> {
    tokio::time::timeout(write_timeout, stream.write_all(bytes))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

async fn write_telnet_data<S: AsyncWrite + Unpin>(
    stream: &mut S,
    write_timeout: Duration,
    bytes: &[u8],
    shell: Option<&FakeShell>,
) -> Result<(), ()> {
    write_raw(stream, write_timeout, &encode_telnet_data(bytes, shell)).await
}

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

fn login_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    username: &str,
    session_id: Uuid,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "username": username,
        }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

/// How the input of a held line came to an end.
enum HeldOutcome {
    /// The input ended (Ctrl-D, Ctrl-C, the capture ceiling): run the line on it.
    Ended(HeldEnd),
    /// The command finished on the lines typed so far; this is what it printed.
    Resumed(sensor_framework::shell::CommandResult),
}

/// Buffered, IAC-stripping line reader. One instance per connection; `bounds` governs every
/// individual socket read the same way `sensor_catchall::handler::read_bounded` does:
/// `read_timeout` bounds the wait for the very first byte of the whole session, `idle_timeout`
/// bounds every read after that, and a running total checked against `max_captured_bytes` bounds
/// the whole session's captured input regardless of how many lines it spans.
struct LineReader {
    filter: IacFilter,
    /// IAC-stripped bytes read off the socket and not yet consumed. An attacker script can write
    /// several lines in one write, faster than they are consumed one at a time, and a line that
    /// reads its input (`cat > f`) takes the bytes after it raw, so lines are cut from here only
    /// as they are wanted.
    unread: VecDeque<u8>,
    /// Bytes accumulated for the line currently being assembled.
    current: Vec<u8>,
    bounds: ConnectionBounds,
    first_read: bool,
    total_captured: u64,
    /// True if the previous byte was a CR, so a following LF (the second half of a CR-LF Enter) is
    /// swallowed rather than treated as a second, empty line. Spans reads, hence a field.
    prev_cr: bool,
    /// Raw, already-IAC-stripped bytes accumulated while `capturing` is true - the evidence
    /// capture buffer `take_capture` drains. Distinct from `total_captured`/`current`: those track
    /// line assembly and the whole-session byte budget, this tracks only the shell-phase bytes a
    /// caller has opted into preserving.
    capture: CaptureBody,
    /// Where `capture` bodies are allocated from (its process-wide memory budget) and submitted
    /// to, so a drained capture is replaced by a fresh budgeted one.
    handoff: Arc<CaptureHandoff>,
    /// Shell-phase bytes that arrived after `capture` hit `bounds.max_captured_bytes` and were
    /// dropped, so the emitted event can say the capture is a prefix and how big the whole was.
    capture_overflow: u64,
    /// Set by `start_capture`; gates whether `read_line` accumulates into `capture`. Starts false
    /// so the login/password phase is never captured.
    capturing: bool,
    /// Set when the shared shell flags a binary flood: without it, and without the raw bytes
    /// themselves looking binary, the capture is an ordinary typed session and is never spooled.
    binary_seen: bool,
    /// How the session ended, set at the exact exit path that ended it. Starts `Cancelled`
    /// because that is the one ending no code can record: the listener drops this whole future at
    /// `max_duration`. Only a peer-chosen end makes the capture complete - see `CaptureEnd`.
    session_end: CaptureEnd,
    /// What `Drop` needs to hand the capture off. `None` until `arm_capture_submit`, so a reader
    /// built by a unit test submits nothing.
    submit: Option<CaptureSubmit>,
}

/// The connection facts `LineReader::drop` stamps onto the capture it submits.
struct CaptureSubmit {
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
}

/// Submitting from `Drop` is what makes the capture survive every exit path, the listener's
/// `max_duration` cancellation included - it drops this future in place, so nothing written
/// after the session loop runs. `CaptureHandoff::submit` never blocks, so it is safe here.
impl Drop for LineReader {
    fn drop(&mut self) {
        // An empty body that was starved by the budget still goes to `submit`, which counts it as
        // a refusal; a merely empty one has nothing to report.
        if self.capture.is_empty() && !self.capture.is_exhausted() {
            return;
        }
        // The per-line flag is only raised once a complete line reached the shell. A payload
        // still mid-line when the session was cancelled never got one, so the bytes themselves
        // are the fallback test - otherwise a dropper's buffer reads as ordinary typing and is
        // thrown away, which is the loss this destructor exists to prevent.
        if !self.binary_seen && !sensor_framework::shell::looks_binary(self.capture.as_slice()) {
            return;
        }
        let Some(ctx) = self.submit.take() else {
            return;
        };
        // Order matters: `capture_wire_bytes` counts the retained half, which `take_capture`
        // drains.
        let wire_size = self.capture_wire_bytes();
        let body = self.take_capture();
        // Only an ending the PEER chose means the bytes are whole. A handler cancelled at
        // `max_duration`, an idle timeout, a socket error and an exhausted capture budget all
        // leave a fragment of whatever was still arriving, and the console shows it as
        // incomplete rather than as a whole sample.
        let end = self.session_end;
        let (source_ip, wan_ip, session_id) = (ctx.source_ip, ctx.wan_ip, ctx.session_id);
        let _ = self.handoff.submit(CaptureJob {
            body,
            orig_name: format!("telnet-session-{session_id}"),
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: PROTOCOL_LABEL.to_string(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.to_string(),
                protocol: PROTO_TCP.to_string(),
                authenticated: true,
                observed_at: chrono::Utc::now(),
                metadata: {
                    let mut m = upload_metadata(
                        PROTOCOL_LABEL,
                        &sample,
                        wire_size,
                        UploadEnd::Session(end),
                    );
                    m["capture_reason"] = serde_json::json!("binary_shell_payload");
                    m
                },
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        });
    }
}

impl LineReader {
    fn new(bounds: ConnectionBounds, handoff: Arc<CaptureHandoff>) -> Self {
        Self {
            filter: IacFilter::new(),
            unread: VecDeque::new(),
            current: Vec::new(),
            bounds,
            first_read: true,
            total_captured: 0,
            prev_cr: false,
            capture: handoff.new_capture_body(),
            handoff,
            capture_overflow: 0,
            capturing: false,
            binary_seen: false,
            session_end: CaptureEnd::Cancelled,
            submit: None,
        }
    }

    /// Let this reader hand its capture off when it is dropped. Called once, alongside
    /// `start_capture`.
    fn arm_capture_submit(&mut self, source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) {
        self.submit = Some(CaptureSubmit {
            source_ip,
            wan_ip,
            session_id,
        });
    }

    /// The shared shell saw a binary flood on this session, so the captured bytes are evidence.
    fn flag_binary(&mut self) {
        self.binary_seen = true;
    }

    /// Record how the session ended. Called at the exit path that ended it, never after the loop:
    /// "the loop returned" is true of a clean logout and of an idle timeout alike, and the whole
    /// point of the distinction is that those two produce different evidence.
    fn mark_session_end(&mut self, end: CaptureEnd) {
        self.session_end = end;
    }

    /// Begin accumulating raw input into the capture buffer. Callers invoke this only once the
    /// login phase is over, so the password never reaches `capture`.
    fn start_capture(&mut self) {
        self.capturing = true;
    }

    /// Drain and return everything accumulated in the capture buffer so far.
    fn take_capture(&mut self) -> CaptureBody {
        std::mem::replace(&mut self.capture, self.handoff.new_capture_body())
    }

    /// Shell-phase bytes the client sent while capturing, retained or dropped past the ceiling.
    /// Read BEFORE `take_capture`, which drains the retained half.
    fn capture_wire_bytes(&self) -> u64 {
        self.capture.len() as u64 + self.capture_overflow
    }

    /// Accumulate already-IAC-stripped `data` into the capture buffer, a no-op unless
    /// `start_capture` has been called, and bounded so a captured session can never grow past
    /// `bounds.max_captured_bytes` - the same ceiling the whole session's `total_captured` is
    /// checked against, applied here to the narrower capture buffer.
    fn capture_bytes(&mut self, data: &[u8]) {
        if !self.capturing {
            return;
        }
        let room = self
            .bounds
            .max_captured_bytes
            .saturating_sub(self.capture.len() as u64) as usize;
        let take = data.len().min(room);
        let before = self.capture.len();
        // A budget refusal keeps the prefix already held and marks the body exhausted for the
        // hand-off; what was not kept counts toward the overflow like bytes past the ceiling.
        let _ = self.capture.extend_from_slice(&data[..take]);
        let kept = self.capture.len() - before;
        self.capture_overflow += (data.len() - kept) as u64;
    }

    /// Read one line (terminated by `\n` or `\r`) of already IAC-stripped, lossily-decoded text.
    /// Returns `None` on EOF, a read timeout, a read error, or the session's `max_captured_bytes`
    /// budget being exhausted - any of which end the session in `handle_connection`, never panic
    /// it.
    ///
    /// A line-ending byte seen while `current` is still empty is silently ignored rather than
    /// emitted as a blank line - the same convention sensor-ssh's own channel data loop uses,
    /// which is what makes a `\r\n` (or `\n\r`) pair collapse into a single line ending instead of
    /// producing a spurious empty second line.
    /// Read one line of already-IAC-stripped, lossily-decoded text. When `echo` is true, each typed
    /// character is echoed back (backspace erases on screen); the Enter's CR-LF is echoed either way,
    /// so a password (echo=false) is hidden but its Enter still advances the line. Returns `None` on
    /// EOF, a read timeout/error, or the session's `max_captured_bytes` budget being exhausted.
    async fn read_line<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        echo: bool,
    ) -> Option<String> {
        loop {
            let mut echo_out = Vec::new();
            let line = self.next_line(echo, &mut echo_out);
            if !echo_out.is_empty()
                && write_telnet_data(stream, self.bounds.idle_timeout, &echo_out, None)
                    .await
                    .is_err()
            {
                self.session_end = CaptureEnd::TransportError;
                return None;
            }
            if line.is_some() {
                return line;
            }
            if !self.fill(stream).await {
                return None;
            }
        }
    }

    /// Hand the bytes after a line that reads its input to `input` until the input ends (Ctrl-D,
    /// Ctrl-C, the capture ceiling) or the command has read all it wanted from the lines typed
    /// so far, echoing them as the terminal does. `None` when the session ended first;
    /// `session_end` says how. The bytes after the end are left for the next line.
    async fn read_held<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        input: &mut HeldInput,
        shell: &mut FakeShell,
    ) -> Option<HeldOutcome> {
        if std::mem::take(&mut self.prev_cr) {
            input.follow_cr();
        }
        loop {
            if !self.unread.is_empty() {
                let fed = input.feed(self.unread.make_contiguous());
                self.unread.drain(..fed.taken);
                // The terminal's echo already carries CR-LF, so it skips the newline translation
                // shell output gets.
                if !fed.echo.is_empty()
                    && write_raw(stream, self.bounds.idle_timeout, &escape_iac(&fed.echo))
                        .await
                        .is_err()
                {
                    self.session_end = CaptureEnd::TransportError;
                    return None;
                }
                if let Some(end) = fed.ended {
                    return Some(HeldOutcome::Ended(end));
                }
                if fed.line
                    && let Some(output) = input.resume(shell)
                {
                    self.prev_cr = input.ended_on_cr();
                    return Some(HeldOutcome::Resumed(output));
                }
                continue;
            }
            if !self.fill(stream).await {
                return None;
            }
        }
    }

    /// Read once from the socket into `unread`, answering any option negotiation it carried.
    /// False when the session ended instead (EOF, a timeout, an error, the session's
    /// `max_captured_bytes`), with `session_end` saying which.
    async fn fill<S: AsyncRead + AsyncWrite + Unpin>(&mut self, stream: &mut S) -> bool {
        if self.total_captured >= self.bounds.max_captured_bytes {
            self.session_end = CaptureEnd::CaptureBudget;
            return false;
        }

        let per_read_timeout = if self.first_read {
            self.bounds.read_timeout
        } else {
            self.bounds.idle_timeout
        };

        let mut raw = [0u8; READ_CHUNK_SIZE];
        let n = match tokio::time::timeout(per_read_timeout, stream.read(&mut raw)).await {
            // Three different endings, and a capture can only say whether its bytes are whole
            // if they stay apart: the peer closing is the one that means "it finished
            // sending".
            Ok(Ok(0)) => {
                self.session_end = CaptureEnd::PeerClosed;
                return false;
            }
            Ok(Err(_)) => {
                self.session_end = CaptureEnd::TransportError;
                return false;
            }
            Err(_) => {
                self.session_end = CaptureEnd::IdleTimeout;
                return false;
            }
            Ok(Ok(n)) => n,
        };
        self.first_read = false;
        self.total_captured += n as u64;

        let mut data = Vec::new();
        let mut response = Vec::new();
        self.filter.process(&raw[..n], &mut data, &mut response);
        if !response.is_empty()
            && write_raw(stream, self.bounds.idle_timeout, &response)
                .await
                .is_err()
        {
            self.session_end = CaptureEnd::TransportError;
            return false;
        }
        self.unread.extend(data);
        true
    }

    /// Cut the next line from `unread`, and, since the sensor offers `WILL ECHO`, produce the
    /// server-side echo of the bytes it consumed into `echo_out`. `None` once `unread` runs out
    /// before a line ends; the partial line stays in `current`. The bytes it consumes are the
    /// shell's, so they are what the binary-payload capture keeps.
    ///
    /// - A bare Enter arrives as CR, CR-LF, or (RFC 854 s.4.3) **CR-NUL**; `prev_cr` collapses the
    ///   pair and NUL bytes are dropped, so a stray NUL never orphans onto the next line as a leading
    ///   `\0` (which used to make every command after the first fail to match and defeat the
    ///   exit/logout check).
    /// - Each Enter submits the current line - **including an empty one**, so a lone Enter reprints
    ///   the prompt like a real shell - and echoes CR-LF regardless of `echo` (so a password's Enter
    ///   still advances the cursor).
    /// - Printable bytes are buffered and, when `echo`, echoed; backspace/DEL erases one buffered
    ///   byte and, when `echo`, rubs it out on screen (`\b \b`). Other control bytes are ignored.
    fn next_line(&mut self, echo: bool, echo_out: &mut Vec<u8>) -> Option<String> {
        let mut consumed = Vec::new();
        let mut line = None;
        while let Some(byte) = self.unread.pop_front() {
            consumed.push(byte);
            // Swallow the LF of a CR-LF Enter (the CR already submitted the line).
            if self.prev_cr {
                self.prev_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' | b'\n' => {
                    self.prev_cr = byte == b'\r';
                    // The rest of a CR-LF or CR-NUL Enter, when it is already here, belongs to
                    // this line: the password's would otherwise be read in the shell phase.
                    if self.prev_cr && matches!(self.unread.front(), Some(b'\n' | 0)) {
                        consumed.extend(self.unread.pop_front());
                        self.prev_cr = false;
                    }
                    echo_out.push(b'\n');
                    line = Some(String::from_utf8_lossy(&self.current).into_owned());
                    self.current.clear();
                }
                0 => {} // CR-NUL padding: drop.
                0x08 | 0x7f => {
                    if self.current.pop().is_some() && echo {
                        echo_out.extend_from_slice(b"\x08 \x08");
                    }
                }
                b if b >= 0x20 => {
                    self.current.push(b);
                    if echo {
                        echo_out.push(b);
                    }
                    if self.current.len() >= MAX_LINE_LEN {
                        line = Some(String::from_utf8_lossy(&self.current).into_owned());
                        self.current.clear();
                    }
                }
                _ => {} // other control bytes: ignore.
            }
            if line.is_some() {
                break;
            }
        }
        self.capture_bytes(&consumed);
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bounds() -> ConnectionBounds {
        ConnectionBounds {
            read_timeout: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(30),
            max_duration: std::time::Duration::from_secs(600),
            max_captured_bytes: 65_536,
            max_concurrent: 256,
        }
    }

    /// A hand-off with one queue slot and no worker: a second `submit` is refused, which is how
    /// these tests prove the first one happened.
    fn one_slot_handoff() -> Arc<CaptureHandoff> {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let outbox_dir = dir.path().join("outbox");
        let spool = sensor_framework::QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000);
        let emitter = sensor_framework::EventEmitter::new(dir.path().join("events.jsonl"));
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

    fn armed_reader(handoff: Arc<CaptureHandoff>) -> LineReader {
        let mut reader = LineReader::new(test_bounds(), handoff);
        reader.start_capture();
        reader.arm_capture_submit("203.0.113.7".parse().unwrap(), None, Uuid::now_v7());
        reader
    }

    /// The listener enforces `max_duration` by dropping the session future, so the submit that
    /// used to sit after the session loop never ran for a session that hit the bound - and a
    /// dropper streaming a payload is exactly the long session that does. The capture is
    /// submitted from `Drop` now, which runs on that path too.
    #[tokio::test]
    async fn the_binary_shell_capture_survives_a_cancelled_session() {
        let handoff = one_slot_handoff();
        let mut reader = armed_reader(handoff.clone());
        reader
            .capture
            .extend_from_slice(b"\x7fELF-payload-bytes")
            .unwrap();
        reader.flag_binary();

        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            let _held = &reader;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(
            cancelled.is_err(),
            "the future was cancelled, not completed"
        );
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the one slot holds the capture the cancelled session had accumulated"
        );
    }

    /// An ordinary typed session is never spooled, cancelled or not: only a binary flood makes
    /// the captured bytes evidence.
    #[tokio::test]
    async fn a_plaintext_session_submits_nothing_when_cancelled() {
        let handoff = one_slot_handoff();
        let mut reader = armed_reader(handoff.clone());
        reader
            .capture
            .extend_from_slice(b"cat /proc/mounts\n")
            .unwrap();

        drop(reader);
        assert!(
            handoff.submit(probe_job()).is_ok(),
            "no binary flood, so nothing was submitted"
        );
    }

    #[test]
    fn capture_is_a_noop_until_start_capture_is_called() {
        // Mirrors the login phase: bytes flow through the reader before start_capture is ever
        // called, and must never land in the capture buffer - this is the mechanism that keeps
        // the password out of any spooled evidence.
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        reader.capture_bytes(b"root\r\nhunter2\r\n");
        assert!(
            reader.take_capture().is_empty(),
            "bytes seen before start_capture must never be captured"
        );
    }

    #[test]
    fn capture_accumulates_post_iac_bytes_once_capturing() {
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        reader.start_capture();
        reader.capture_bytes(b"echo hi\r\n");
        reader.capture_bytes(&[0x7f, 0xe1, 0x08, 0xff]);
        assert_eq!(
            reader.take_capture().as_slice(),
            b"echo hi\r\n\x7f\xe1\x08\xff"
        );
        // take_capture drains: a second call returns nothing more until fed again.
        assert!(reader.take_capture().is_empty());
    }

    #[test]
    fn capture_is_bounded_by_max_captured_bytes() {
        let mut bounds = test_bounds();
        bounds.max_captured_bytes = 10;
        let mut reader = LineReader::new(bounds, one_slot_handoff());
        reader.start_capture();
        reader.capture_bytes(b"0123456789ABCDEF"); // 16 bytes offered, cap is 10
        // The whole offered size is still known, so the event can say the capture is a prefix.
        assert_eq!(reader.capture_wire_bytes(), 16);
        assert_eq!(
            reader.capture.len(),
            10,
            "a capture must never exceed the bound"
        );

        // Further bytes past the bound are dropped, not appended once the cap is already full.
        reader.capture_bytes(b"more");
        assert_eq!(
            reader.capture.len(),
            10,
            "no more bytes accumulate once the bound is reached"
        );

        let captured = reader.take_capture();
        assert_eq!(captured.as_slice(), b"0123456789");
    }

    #[test]
    fn crnul_enter_does_not_orphan_nul_into_the_next_command() {
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        let mut echo = Vec::new();
        // A real telnet client transmits a bare Enter as CR-NUL (RFC 854 s.4.3). Two commands, each
        // terminated that way: the NUL after the first must not corrupt the second command.
        reader.unread.extend(b"echo one\r\x00echo two\r\x00");
        assert_eq!(
            reader.next_line(false, &mut echo).as_deref(),
            Some("echo one")
        );
        assert_eq!(
            reader.next_line(false, &mut echo).as_deref(),
            Some("echo two"),
            "the NUL from the first CR-NUL Enter must not orphan onto the next command"
        );
        assert_eq!(reader.next_line(false, &mut echo), None);
        assert!(
            reader.current.is_empty(),
            "no orphaned NUL left dangling in the line buffer"
        );
    }

    #[test]
    fn typed_chars_are_echoed_and_backspace_erases() {
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        let mut echo = Vec::new();
        // Type "ab", backspace (DEL), "c", Enter as CR-NUL.
        reader.unread.extend(b"ab\x7fc\r\x00");
        assert_eq!(reader.next_line(true, &mut echo).as_deref(), Some("ac"));
        assert_eq!(echo, b"ab\x08 \x08c\n");
    }

    #[test]
    fn password_read_hides_chars_but_still_echoes_the_enter() {
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        let mut echo = Vec::new();
        reader.unread.extend(b"secret\r\x00");
        assert_eq!(
            reader.next_line(false, &mut echo).as_deref(),
            Some("secret")
        );
        // Password characters are not echoed; only the Enter's CR-LF advances the cursor.
        assert_eq!(echo, b"\n");
    }

    #[test]
    fn empty_enter_submits_an_empty_line_so_the_prompt_reprints() {
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        let mut echo = Vec::new();
        reader.unread.extend(b"\r\x00");
        assert_eq!(reader.next_line(true, &mut echo).as_deref(), Some(""));
        assert_eq!(echo, b"\n");
    }

    /// The shell's binary-payload capture keeps the bytes the line reader consumed, and only
    /// those: what is still unread when a line ends belongs to whoever reads it next (a held
    /// command's input is captured as that, never twice).
    #[test]
    fn only_the_bytes_a_line_consumed_reach_the_shell_capture() {
        let mut reader = LineReader::new(test_bounds(), one_slot_handoff());
        reader.start_capture();
        reader.unread.extend(b"cat > f\r\npayload-for-cat");
        let mut echo = Vec::new();
        assert_eq!(
            reader.next_line(true, &mut echo).as_deref(),
            Some("cat > f")
        );
        assert_eq!(reader.take_capture().as_slice(), b"cat > f\r\n");
        assert_eq!(
            reader.unread.iter().copied().collect::<Vec<u8>>(),
            b"payload-for-cat"
        );
    }

    #[test]
    fn data_encoding_applies_onlcr_then_xor_then_iac_escaping() {
        let ctx = EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "telnet".to_string(),
            session_id: Some(Uuid::now_v7()),
        };
        let mut shell = FakeShell::new(FakeFs::new(), ctx);
        let obfuscated_enable: String = b"enable"
            .iter()
            .map(|byte| char::from(byte ^ 0x09))
            .collect();
        shell.handle_input(&obfuscated_enable);

        // ONLCR inserts CR before LF. XOR turns 0xf6 into 0xff, and only then does Telnet double
        // the IAC data byte. Reordering either transform changes these exact bytes.
        assert_eq!(
            encode_telnet_data(&[b'\n', 0xf6], Some(&shell)),
            vec![b'\r' ^ 0x09, b'\n' ^ 0x09, 0xff, 0xff]
        );
    }

    #[test]
    fn connection_event_is_unauthenticated_with_telnet_label() {
        let session_id = Uuid::now_v7();
        let event = connection_event("203.0.113.7".parse().unwrap(), None, session_id);
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "telnet");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(event.protocol, PROTO_TCP);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("telnet")
        );
        assert_eq!(event.sample, None);
        assert_eq!(event.session_id, Some(session_id));
    }

    #[test]
    fn login_event_is_authenticated_and_carries_username() {
        let session_id = Uuid::now_v7();
        let event = login_event("203.0.113.7".parse().unwrap(), None, "root", session_id);
        assert!(event.authenticated);
        assert_eq!(event.session_id, Some(session_id));
        assert_eq!(event.sensor, "telnet");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
        assert_eq!(
            event.metadata.get("username").and_then(|v| v.as_str()),
            Some("root")
        );
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("telnet")
        );
    }

    #[test]
    fn login_event_metadata_never_has_a_password_key() {
        // There is no `password` argument to `login_event` at all - this test documents that
        // guarantee at the type level: the function cannot leak what it is never given.
        let event = login_event("203.0.113.7".parse().unwrap(), None, "root", Uuid::now_v7());
        assert!(event.metadata.get("password").is_none());
    }
}
