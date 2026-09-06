//! Per-connection Telnet session handler: negotiates basic options, captures a username/password
//! login (dropping the password immediately), then hands off to the shared `FakeShell` for
//! command capture. See `internal/design/08-remaining-sensors.md`'s "sensor-telnet" section for
//! the protocol flow this composes and `telnet.rs` for the IAC parsing it drives.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::fakefs::FakeFs;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::persona;
use sensor_framework::sanitize_value;
use sensor_framework::shell::{EmitContext, FakeShell};
use sensor_framework::{
    CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, Uuid, WanResolver, upload_metadata,
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
pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
) {
    // Normalize dual-stack mapped addresses before resolving WAN, so an IPv4-mapped IPv6 address
    // (::ffff:a.b.c.d from a dual-stack listener) matches the operator's plain-IPv4 WAN map entry
    // - mirrors sensor-ssh's `server::handle_session` handling of the same listener module doc
    // requirement.
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    // Emit honeypot_connection (authenticated=false) before anything else - the TCP handshake
    // itself is the observation, independent of whatever happens (or fails to happen) next.
    let conn_event = connection_event(source_ip, wan_ip, session_id);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "telnet: failed to append connection event");
    }

    if stream.write_all(&negotiation_preamble()).await.is_err() {
        return;
    }

    // A real telnetd prints the network issue banner then a hostname-qualified login prompt. Both
    // come from the shared persona so the hostname matches uname / the shell prompt / the other
    // sensors, instead of a bare "login:" with no host and a cross-instance-constant shell prompt.
    let host = persona::hostname();
    let shell_prompt = persona::root_prompt(&host);

    let issue = format!("{}\r\n", persona::OS_PRETTY);
    if stream.write_all(issue.as_bytes()).await.is_err() {
        return;
    }

    let mut reader = LineReader::new(bounds);

    let login_prompt = format!("{host} login: ");
    if stream.write_all(login_prompt.as_bytes()).await.is_err() {
        return;
    }
    let Some(username_raw) = reader.read_line(&mut stream, true).await else {
        return;
    };
    let username = sanitize_value(&username_raw, MAX_USERNAME_LEN);

    if stream.write_all(PROMPT_PASSWORD).await.is_err() {
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
    let mut shell = FakeShell::new(FakeFs::new(), ctx);

    if stream.write_all(shell_prompt.as_bytes()).await.is_err() {
        return;
    }

    // Capture is shell-phase only: it starts here, after the password has already been read and
    // dropped above, and never before - so a captured sample can never contain the login
    // credentials. See the crate-level design note above `handle_connection`.
    reader.start_capture();
    let mut binary_seen = false;

    loop {
        let Some(line) = reader.read_line(&mut stream, true).await else {
            break;
        };
        let is_exit = matches!(line.trim(), "exit" | "logout");

        let (output, events) = shell.handle_input(&line);
        for event in &events {
            if event.metadata.get("flood").and_then(|v| v.as_str()) == Some("binary") {
                binary_seen = true;
            }
            if emitter.append(event).await.is_err() {
                tracing::error!(%peer_addr, "telnet: failed to append command event");
            }
        }

        // The shared shell emits bare LF line endings; a telnet NVT terminal needs CR-LF or the
        // cursor never returns to column 0 (each new line renders indented - a visible tell). The
        // banner/prompts above already use \r\n; translate the command output to match.
        let output = output.replace('\n', "\r\n");

        if is_exit {
            let _ = stream
                .write_all(&shell.encode_output(output.as_bytes()))
                .await;
            break;
        }

        let mut response = output.into_bytes();
        response.extend_from_slice(shell_prompt.as_bytes());
        // Mirror any XOR obfuscation onto the response so a symmetric-codec bot reads plaintext after
        // de-obfuscating (identity for a plaintext session, so normal bots are unaffected).
        let response = shell.encode_output(&response);
        if stream.write_all(&response).await.is_err() {
            break;
        }
    }

    // A binary payload was seen somewhere in the shell phase (a Mirai/Gafgyt dropper streamed
    // over the "shell" - never a real interactive command): preserve the raw bytes as evidence.
    // Plaintext-only sessions never reach this branch, so an ordinary attacker's typed commands
    // are never spooled.
    if binary_seen {
        let wire_size = reader.capture_wire_bytes();
        let raw = reader.take_capture();
        if !raw.is_empty() {
            let orig_name = format!("telnet-session-{session_id}");
            let _ = handoff.submit(CaptureJob {
                body: raw,
                orig_name,
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
                        let mut m = upload_metadata(PROTOCOL_LABEL, &sample, wire_size, true);
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

/// Buffered, IAC-stripping line reader. One instance per connection; `bounds` governs every
/// individual socket read the same way `sensor_catchall::handler::read_bounded` does:
/// `read_timeout` bounds the wait for the very first byte of the whole session, `idle_timeout`
/// bounds every read after that, and a running total checked against `max_captured_bytes` bounds
/// the whole session's captured input regardless of how many lines it spans.
struct LineReader {
    filter: IacFilter,
    /// Complete lines already extracted from a read that produced more than one (an attacker
    /// script can write several `\n`-terminated lines in a single write, faster than this reader
    /// consumes them one at a time).
    pending: VecDeque<String>,
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
    capture: Vec<u8>,
    /// Shell-phase bytes that arrived after `capture` hit `bounds.max_captured_bytes` and were
    /// dropped, so the emitted event can say the capture is a prefix and how big the whole was.
    capture_overflow: u64,
    /// Set by `start_capture`; gates whether `read_line` accumulates into `capture`. Starts false
    /// so the login/password phase is never captured.
    capturing: bool,
}

impl LineReader {
    fn new(bounds: ConnectionBounds) -> Self {
        Self {
            filter: IacFilter::new(),
            pending: VecDeque::new(),
            current: Vec::new(),
            bounds,
            first_read: true,
            total_captured: 0,
            prev_cr: false,
            capture: Vec::new(),
            capture_overflow: 0,
            capturing: false,
        }
    }

    /// Begin accumulating raw input into the capture buffer. Callers invoke this only once the
    /// login phase is over, so the password never reaches `capture`.
    fn start_capture(&mut self) {
        self.capturing = true;
    }

    /// Drain and return everything accumulated in the capture buffer so far.
    fn take_capture(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.capture)
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
        self.capture.extend_from_slice(&data[..take]);
        self.capture_overflow += (data.len() - take) as u64;
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
    async fn read_line(&mut self, stream: &mut TcpStream, echo: bool) -> Option<String> {
        loop {
            if let Some(line) = self.pending.pop_front() {
                return Some(line);
            }

            if self.total_captured >= self.bounds.max_captured_bytes {
                return None;
            }

            let per_read_timeout = if self.first_read {
                self.bounds.read_timeout
            } else {
                self.bounds.idle_timeout
            };

            let mut raw = [0u8; READ_CHUNK_SIZE];
            let n = match tokio::time::timeout(per_read_timeout, stream.read(&mut raw)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None, // EOF, read error, or timeout
                Ok(Ok(n)) => n,
            };
            self.first_read = false;
            self.total_captured += n as u64;

            let mut data = Vec::new();
            let mut response = Vec::new();
            self.filter.process(&raw[..n], &mut data, &mut response);
            self.capture_bytes(&data);
            if !response.is_empty() && stream.write_all(&response).await.is_err() {
                return None;
            }

            let mut echo_out = Vec::new();
            self.feed(&data, echo, &mut echo_out);
            if !echo_out.is_empty() && stream.write_all(&echo_out).await.is_err() {
                return None;
            }
        }
    }

    /// Extract complete lines from already-IAC-filtered `data` into `pending`, and, since the sensor
    /// now offers `WILL ECHO`, produce the server-side echo into `echo_out`.
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
    fn feed(&mut self, data: &[u8], echo: bool, echo_out: &mut Vec<u8>) {
        for &byte in data {
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
                    echo_out.extend_from_slice(b"\r\n");
                    self.pending
                        .push_back(String::from_utf8_lossy(&self.current).into_owned());
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
                        self.pending
                            .push_back(String::from_utf8_lossy(&self.current).into_owned());
                        self.current.clear();
                    }
                }
                _ => {} // other control bytes: ignore.
            }
        }
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

    #[test]
    fn capture_is_a_noop_until_start_capture_is_called() {
        // Mirrors the login phase: bytes flow through the reader before start_capture is ever
        // called, and must never land in the capture buffer - this is the mechanism that keeps
        // the password out of any spooled evidence.
        let mut reader = LineReader::new(test_bounds());
        reader.capture_bytes(b"root\r\nhunter2\r\n");
        assert!(
            reader.take_capture().is_empty(),
            "bytes seen before start_capture must never be captured"
        );
    }

    #[test]
    fn capture_accumulates_post_iac_bytes_once_capturing() {
        let mut reader = LineReader::new(test_bounds());
        reader.start_capture();
        reader.capture_bytes(b"echo hi\r\n");
        reader.capture_bytes(&[0x7f, 0xe1, 0x08, 0xff]);
        assert_eq!(reader.take_capture(), b"echo hi\r\n\x7f\xe1\x08\xff");
        // take_capture drains: a second call returns nothing more until fed again.
        assert!(reader.take_capture().is_empty());
    }

    #[test]
    fn capture_is_bounded_by_max_captured_bytes() {
        let mut bounds = test_bounds();
        bounds.max_captured_bytes = 10;
        let mut reader = LineReader::new(bounds);
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
        assert_eq!(captured, b"0123456789");
    }

    #[test]
    fn crnul_enter_does_not_orphan_nul_into_the_next_command() {
        let mut reader = LineReader::new(test_bounds());
        let mut echo = Vec::new();
        // A real telnet client transmits a bare Enter as CR-NUL (RFC 854 s.4.3). Two commands, each
        // terminated that way: the NUL after the first must not corrupt the second command.
        reader.feed(b"echo one\r\x00echo two\r\x00", false, &mut echo);
        assert_eq!(reader.pending.pop_front().as_deref(), Some("echo one"));
        assert_eq!(
            reader.pending.pop_front().as_deref(),
            Some("echo two"),
            "the NUL from the first CR-NUL Enter must not orphan onto the next command"
        );
        assert!(reader.pending.is_empty());
        assert!(
            reader.current.is_empty(),
            "no orphaned NUL left dangling in the line buffer"
        );
    }

    #[test]
    fn typed_chars_are_echoed_and_backspace_erases() {
        let mut reader = LineReader::new(test_bounds());
        let mut echo = Vec::new();
        // Type "ab", backspace (DEL), "c", Enter as CR-NUL.
        reader.feed(b"ab\x7fc\r\x00", true, &mut echo);
        assert_eq!(reader.pending.pop_front().as_deref(), Some("ac"));
        assert_eq!(echo, b"ab\x08 \x08c\r\n");
    }

    #[test]
    fn password_read_hides_chars_but_still_echoes_the_enter() {
        let mut reader = LineReader::new(test_bounds());
        let mut echo = Vec::new();
        reader.feed(b"secret\r\x00", false, &mut echo);
        assert_eq!(reader.pending.pop_front().as_deref(), Some("secret"));
        // Password characters are not echoed; only the Enter's CR-LF advances the cursor.
        assert_eq!(echo, b"\r\n");
    }

    #[test]
    fn empty_enter_submits_an_empty_line_so_the_prompt_reprints() {
        let mut reader = LineReader::new(test_bounds());
        let mut echo = Vec::new();
        reader.feed(b"\r\x00", true, &mut echo);
        assert_eq!(reader.pending.pop_front().as_deref(), Some(""));
        assert_eq!(echo, b"\r\n");
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
