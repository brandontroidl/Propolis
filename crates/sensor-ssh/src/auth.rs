//! SSH user authentication (RFC 4252): the state machine that captures a session's offered
//! username, drops the password immediately after the parser has advanced past it, and latches
//! `authenticated` true on the first user-authentication request. See "Protocol and
//! authentication" in `internal/design/02-sensor-framework.md`: this server performs the real SSH
//! transport up through key exchange, so reaching user-authentication is itself a multi-round-
//! trip cryptographic proof that the peer is real - that is what the confirmed-real semantics key
//! off, not the specific credential offered. Every user-auth attempt is therefore accepted,
//! whatever the method or the credential: the goal is to let the attacker reach the shell and
//! reveal intent, not to gatekeep a honeypot that has nothing behind it worth protecting.
//!
//! **The password invariant.** A submitted password is read only far enough to advance the
//! parser past it - the wire format is length-prefixed, so skipping it without reading its bytes
//! is not possible - and the returned value is never stored on `AuthState`, never logged, and
//! never placed in any field of any `SensorEvent`. `password_never_in_event` in
//! `tests/auth_test.rs` asserts this at the serialized-JSON level, not just against the typed
//! struct, so a future field addition cannot reintroduce it silently.
//!
//! The `method` name is exactly as attacker-controlled as `username` (an SSH client may claim any
//! string as its auth method) and is embedded in the same event, so it clears the same
//! `sanitize_value` chokepoint before it does - `method_with_injection_is_sanitized` in
//! `tests/auth_test.rs` covers this.

use std::net::IpAddr;

use sensor_framework::{Uuid, sanitize_value};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

use crate::transport::{SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS};

/// Cap applied to every attacker-controlled string this module embeds in an event (`username`,
/// `method`): generous for any real value, bounded so a client cannot inflate an event record by
/// padding either field. Matches `transport::MAX_VERSION_LINE_LEN`, this crate's existing
/// convention for "a generously bounded protocol string."
const MAX_METADATA_STRING_LEN: usize = 255;

/// Per-connection user-authentication state. Constructed once, immediately after transport
/// establishment (key exchange + `SSH_MSG_NEWKEYS`), with the connection's real parameters -
/// never a placeholder address - since `emit_connection_event` and every login-attempt event
/// carry `source_ip`/`wan_ip` straight from here for the lifetime of the session.
pub struct AuthState {
    authenticated: bool,
    username: Option<String>,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
}

/// Errors this module's parsing can produce. Every variant is constructed from a checked
/// condition on attacker-controlled bytes (a truncated field, a length prefix past the end of the
/// payload) - never a caught panic - matching `transport::TransportError`'s own construction
/// discipline: this parses bytes from a peer that is not yet authenticated.
#[derive(Debug)]
pub enum AuthError {
    /// The payload's own fields are structurally inconsistent: wrong message type, a truncated
    /// string, or a length prefix that claims more bytes than the payload holds.
    MalformedPacket,
    Io(std::io::Error),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MalformedPacket => write!(f, "malformed SSH_MSG_USERAUTH_REQUEST"),
            AuthError::Io(e) => write!(f, "SSH auth i/o error: {e}"),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuthError::Io(e) => Some(e),
            AuthError::MalformedPacket => None,
        }
    }
}

impl From<std::io::Error> for AuthError {
    fn from(e: std::io::Error) -> Self {
        AuthError::Io(e)
    }
}

impl AuthState {
    /// `source_ip`/`wan_ip` are this connection's real attributes; there is no default or
    /// placeholder address, because every event this type ever emits carries them verbatim.
    pub fn new(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> Self {
        Self {
            authenticated: false,
            username: None,
            source_ip,
            wan_ip,
            session_id,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// The username captured by `handle_userauth` - already sanitized, since it is stored from
    /// the same `username` binding placed in that event's metadata - or `None` before the first
    /// user-authentication request. Added for the fake shell (Task 13): the session orchestrator
    /// wires `AuthState` and `FakeShell` together and may want the shell's persona to reflect the
    /// identity the attacker actually claimed, rather than a hardcoded name.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The `honeypot_connection` event: emitted once, immediately after transport establishment
    /// and before the service-request/userauth flow even starts, so `authenticated = false`
    /// unconditionally here regardless of what happens later in the session.
    pub fn emit_connection_event(&self) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.source_ip,
            wan_ip: self.wan_ip,
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_CONNECTION.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({ "protocol_label": "ssh" }),
            sample: None,
            session_id: Some(self.session_id),
        }
    }

    /// Handle one `SSH_MSG_USERAUTH_REQUEST`: capture the username (sanitized), latch
    /// `authenticated`, and always accept - see the module doc for why every method and every
    /// credential is accepted unconditionally. Returns the raw `SSH_MSG_USERAUTH_SUCCESS`
    /// response payload and the `honeypot_login_attempt` event to emit.
    ///
    /// The password (present only when `method == "password"`) is read by
    /// `parse_userauth_request` solely to advance the parser past it in the wire format; the
    /// local binding below (`_password`) is never read again and is dropped when this call
    /// returns. It is never stored on `self`, never logged, and never reaches `metadata`.
    pub fn handle_userauth(
        &mut self,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<SensorEvent>), AuthError> {
        let (username_raw, _service, method_raw, _password) = parse_userauth_request(payload)?;

        let username = sanitize_value(
            &String::from_utf8_lossy(&username_raw),
            MAX_METADATA_STRING_LEN,
        );
        let method = sanitize_value(
            &String::from_utf8_lossy(&method_raw),
            MAX_METADATA_STRING_LEN,
        );

        self.username = Some(username.clone());
        self.authenticated = true;

        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.source_ip,
            wan_ip: self.wan_ip,
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({
                "protocol_label": "ssh",
                "username": username,
                "method": method,
            }),
            sample: None,
            session_id: Some(self.session_id),
        };

        // Always accept: see the module doc for why.
        let response = vec![SSH_MSG_USERAUTH_SUCCESS];
        Ok((response, vec![event]))
    }
}

/// `(username, service_name, method, password)`, as parsed by `parse_userauth_request`.
/// Factored into a named alias rather than a bare 4-tuple per `clippy::type_complexity`.
type UserAuthFields = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Parse an `SSH_MSG_USERAUTH_REQUEST` payload (RFC 4252 section 5):
/// `byte SSH_MSG_USERAUTH_REQUEST || string user name || string service name || string method
/// name || method-specific fields`. Returns `(username, service_name, method, password)`, where
/// `password` is non-empty only when `method == b"password"` (RFC 4252 section 8's
/// `boolean FALSE || string plaintext password`); every other method's trailing fields are left
/// unparsed since nothing here needs them. Every offset is derived from a length field read out of
/// `payload` itself and checked before use, so a truncated or hostile payload returns `Err` rather
/// than panicking - this parses bytes from an unauthenticated peer.
fn parse_userauth_request(payload: &[u8]) -> Result<UserAuthFields, AuthError> {
    let mut cursor = 0usize;

    let msg_type = read_u8(payload, &mut cursor)?;
    if msg_type != SSH_MSG_USERAUTH_REQUEST {
        return Err(AuthError::MalformedPacket);
    }

    let username = read_string(payload, &mut cursor)?;
    let service = read_string(payload, &mut cursor)?;
    let method = read_string(payload, &mut cursor)?;

    let password = if method == b"password" {
        let _old_password_flag = read_u8(payload, &mut cursor)?;
        read_string(payload, &mut cursor)?
    } else {
        Vec::new()
    };

    Ok((username, service, method, password))
}

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, AuthError> {
    let byte = *data.get(*cursor).ok_or(AuthError::MalformedPacket)?;
    *cursor += 1;
    Ok(byte)
}

/// Read an SSH `string` (RFC 4251 section 5: uint32 big-endian length prefix + raw bytes).
fn read_string(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, AuthError> {
    let len = read_u32(data, cursor)? as usize;
    let end = cursor.checked_add(len).ok_or(AuthError::MalformedPacket)?;
    let bytes = data
        .get(*cursor..end)
        .ok_or(AuthError::MalformedPacket)?
        .to_vec();
    *cursor = end;
    Ok(bytes)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, AuthError> {
    let end = cursor.checked_add(4).ok_or(AuthError::MalformedPacket)?;
    let bytes = data.get(*cursor..end).ok_or(AuthError::MalformedPacket)?;
    let value = u32::from_be_bytes(bytes.try_into().expect("slice is exactly 4 bytes"));
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn push_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    #[test]
    fn parse_userauth_request_rejects_wrong_message_type() {
        let mut buf = vec![SSH_MSG_USERAUTH_REQUEST + 1];
        push_ssh_string(&mut buf, b"root");
        let result = parse_userauth_request(&buf);
        assert!(matches!(result, Err(AuthError::MalformedPacket)));
    }

    #[test]
    fn parse_userauth_request_rejects_truncated_username_length() {
        // Message type + a length prefix claiming more bytes than actually follow.
        let mut buf = vec![SSH_MSG_USERAUTH_REQUEST];
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"short");
        let result = parse_userauth_request(&buf);
        assert!(matches!(result, Err(AuthError::MalformedPacket)));
    }

    #[test]
    fn parse_userauth_request_non_password_method_leaves_password_empty() {
        let mut buf = vec![SSH_MSG_USERAUTH_REQUEST];
        push_ssh_string(&mut buf, b"root");
        push_ssh_string(&mut buf, b"ssh-connection");
        push_ssh_string(&mut buf, b"publickey");
        // No further fields parsed for a non-password method.
        let (username, service, method, password) = parse_userauth_request(&buf).unwrap();
        assert_eq!(username, b"root");
        assert_eq!(service, b"ssh-connection");
        assert_eq!(method, b"publickey");
        assert!(password.is_empty());
    }

    proptest! {
        /// Fuzz-lite guard: this parses attacker-controlled bytes pre-authentication, so no
        /// arbitrary, possibly-truncated input may ever panic - it must always resolve to `Ok`
        /// or `Err`. Mirrors `transport::tests::parse_kexinit_never_panics_on_arbitrary_bytes`.
        #[test]
        fn parse_userauth_request_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..=512)
        ) {
            let _ = parse_userauth_request(&bytes);
        }
    }
}
