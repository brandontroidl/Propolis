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
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
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
pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
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
    let Some(username_raw) = reader.read_line(&mut stream).await else {
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
    let Some(_password) = reader.read_line(&mut stream).await else {
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

    loop {
        let Some(line) = reader.read_line(&mut stream).await else {
            return;
        };
        let is_exit = matches!(line.trim(), "exit" | "logout");

        let (output, events) = shell.handle_input(&line);
        for event in &events {
            if emitter.append(event).await.is_err() {
                tracing::error!(%peer_addr, "telnet: failed to append command event");
            }
        }

        if is_exit {
            let _ = stream.write_all(output.as_bytes()).await;
            return;
        }

        let mut response = output.into_bytes();
        response.extend_from_slice(shell_prompt.as_bytes());
        if stream.write_all(&response).await.is_err() {
            return;
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
        }
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
    async fn read_line(&mut self, stream: &mut TcpStream) -> Option<String> {
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
            if !response.is_empty() && stream.write_all(&response).await.is_err() {
                return None;
            }

            for byte in data {
                if byte == b'\n' || byte == b'\r' {
                    if !self.current.is_empty() {
                        self.pending
                            .push_back(String::from_utf8_lossy(&self.current).into_owned());
                        self.current.clear();
                    }
                } else {
                    self.current.push(byte);
                    if self.current.len() >= MAX_LINE_LEN {
                        self.pending
                            .push_back(String::from_utf8_lossy(&self.current).into_owned());
                        self.current.clear();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
