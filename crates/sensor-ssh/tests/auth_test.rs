//! Integration tests for `sensor_ssh::auth` (user-authentication state machine) and
//! `sensor_ssh::channel` (channel open/request dispatch). Both modules are pure parsers with no
//! I/O of their own, so every test here drives them directly with hand-built wire bytes - no
//! socket, no live server.

use proptest::prelude::*;
use sensor_ssh::auth::{AuthError, AuthState};
use sensor_ssh::channel::{
    ChannelAction, ChannelError, handle_channel_open, handle_channel_request,
};
use sensor_ssh::transport;

// ---------------------------------------------------------------------------------------------
// auth.rs - given suite (task brief)
// ---------------------------------------------------------------------------------------------

#[test]
fn authenticated_false_before_userauth() {
    let state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    assert!(!state.is_authenticated());
}

#[test]
fn authenticated_true_after_userauth_success() {
    let mut state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    let userauth_request = build_password_userauth(b"attacker", b"password123");
    let (response, events) = state.handle_userauth(&userauth_request).unwrap();
    assert!(state.is_authenticated());
    assert_eq!(response[0], transport::SSH_MSG_USERAUTH_SUCCESS);
    // Verify events emitted.
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].signal_type,
        sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT
    );
    assert!(events[0].authenticated);
}

#[test]
fn password_never_in_event() {
    let mut state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    let password = b"s3cret_p@ssw0rd!";
    let userauth = build_password_userauth(b"root", password);
    let (_response, events) = state.handle_userauth(&userauth).unwrap();
    let event_json = serde_json::to_string(&events[0]).unwrap();
    assert!(
        !event_json.contains("s3cret_p@ssw0rd!"),
        "password must NEVER appear in event: {event_json}"
    );
}

#[test]
fn username_captured_in_metadata() {
    let mut state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    let userauth = build_password_userauth(b"admin", b"pass");
    let (_response, events) = state.handle_userauth(&userauth).unwrap();
    let username = events[0].metadata.get("username").and_then(|v| v.as_str());
    assert_eq!(username, Some("admin"));
}

#[test]
fn username_with_injection_is_sanitized() {
    let mut state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    let evil_name = b"root\r\n{\"v\":1,\"signal_type\":\"evil\"}";
    let userauth = build_password_userauth(evil_name, b"pass");
    let (_response, events) = state.handle_userauth(&userauth).unwrap();
    let username = events[0]
        .metadata
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(!username.contains('\n'));
    assert!(!username.contains('\r'));
}

#[test]
fn authenticated_latch_stays_true() {
    let mut state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    let userauth = build_password_userauth(b"root", b"pass");
    state.handle_userauth(&userauth).unwrap();
    assert!(state.is_authenticated());
    // authenticated stays true for the rest of the session.
    assert!(state.is_authenticated());
}

// ---------------------------------------------------------------------------------------------
// auth.rs - additional coverage, not in the brief's given suite.
//
// None of the six tests above can distinguish this implementation from one that (a) forgets to
// sanitize the "method" field before embedding it (the given suite never builds a non-trivial
// method name), (b) panics or wrongly latches on a malformed packet, or (c) hardcodes a
// "password"-shaped parse that breaks on any other auth method. `sensor_framework::sanitize`'s
// own test module documents the same reasoning for the same reason: the given fixtures are
// necessary, not sufficient.
// ---------------------------------------------------------------------------------------------

#[test]
fn emit_connection_event_is_unauthenticated_ssh_connection() {
    let state = AuthState::new(
        "203.0.113.7".parse().unwrap(),
        Some("198.51.100.4".parse().unwrap()),
    );
    let event = state.emit_connection_event();
    assert_eq!(event.signal_type, sensor_wire::SIGNAL_HONEYPOT_CONNECTION);
    assert!(!event.authenticated);
    assert_eq!(event.sensor, "ssh");
    assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
    assert_eq!(
        event.source_ip,
        "203.0.113.7".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        event.wan_ip,
        Some("198.51.100.4".parse::<std::net::IpAddr>().unwrap())
    );
    assert_eq!(
        event
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("ssh")
    );
}

#[test]
fn handle_userauth_rejects_empty_payload() {
    let mut state = AuthState::new("203.0.113.7".parse().unwrap(), None);
    let result = state.handle_userauth(&[]);
    assert!(matches!(result, Err(AuthError::MalformedPacket)));
    // A rejected parse must never latch authenticated.
    assert!(!state.is_authenticated());
}

#[test]
fn handle_userauth_rejects_truncated_password_field() {
    let mut state = AuthState::new("203.0.113.7".parse().unwrap(), None);
    // Well-formed username/service/"password"-method prefix, then cut off before the FALSE
    // byte and password string RFC 4252 section 8 requires.
    let mut buf = vec![transport::SSH_MSG_USERAUTH_REQUEST];
    push_ssh_string(&mut buf, b"root");
    push_ssh_string(&mut buf, b"ssh-connection");
    push_ssh_string(&mut buf, b"password");
    // Missing: boolean + password string.
    let result = state.handle_userauth(&buf);
    assert!(matches!(result, Err(AuthError::MalformedPacket)));
    assert!(!state.is_authenticated());
}

#[test]
fn non_password_method_is_accepted_with_no_password_key_in_metadata() {
    let mut state = AuthState::new("203.0.113.7".parse().unwrap(), None);
    let mut buf = vec![transport::SSH_MSG_USERAUTH_REQUEST];
    push_ssh_string(&mut buf, b"probe");
    push_ssh_string(&mut buf, b"ssh-connection");
    push_ssh_string(&mut buf, b"none");
    // "none" (RFC 4252 section 5.2) carries no method-specific fields at all.
    let (response, events) = state.handle_userauth(&buf).unwrap();
    assert!(state.is_authenticated());
    assert_eq!(response[0], transport::SSH_MSG_USERAUTH_SUCCESS);
    assert_eq!(
        events[0].metadata.get("method").and_then(|v| v.as_str()),
        Some("none")
    );
    // The structural guarantee, not just "the password value is absent": a method that never
    // carried a password must leave no "password" key in metadata at all.
    assert!(events[0].metadata.get("password").is_none());
}

#[test]
fn method_with_injection_is_sanitized() {
    // The method name is exactly as attacker-controlled as the username (a client may claim any
    // string here) and it is embedded directly in `metadata.method`; it must clear the same
    // `sanitize_value` chokepoint before it does.
    let mut state = AuthState::new("203.0.113.7".parse().unwrap(), None);
    let mut buf = vec![transport::SSH_MSG_USERAUTH_REQUEST];
    push_ssh_string(&mut buf, b"root");
    push_ssh_string(&mut buf, b"ssh-connection");
    push_ssh_string(&mut buf, b"evil\r\n{\"signal_type\":\"forged\"}");
    let (_response, events) = state.handle_userauth(&buf).unwrap();
    let method = events[0]
        .metadata
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(!method.contains('\n'));
    assert!(!method.contains('\r'));
    let event_json = serde_json::to_string(&events[0]).unwrap();
    assert!(!event_json.contains("\"signal_type\":\"forged\""));
}

// ---------------------------------------------------------------------------------------------
// channel.rs
// ---------------------------------------------------------------------------------------------

#[test]
fn channel_open_session_is_confirmed() {
    let packet = build_channel_open(b"session", 7);
    let (channel_id, response) = handle_channel_open(&packet).unwrap();
    assert_eq!(channel_id, 7);
    assert_eq!(response[0], transport::SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    let recipient_channel = u32::from_be_bytes(response[1..5].try_into().unwrap());
    let sender_channel = u32::from_be_bytes(response[5..9].try_into().unwrap());
    assert_eq!(recipient_channel, 7);
    assert_eq!(sender_channel, 7);
}

#[test]
fn channel_open_rejects_direct_tcpip() {
    // direct-tcpip is SSH-level local port forwarding: a request for the server to relay bytes
    // to a third address the client names. Confirming it would be the SSH-layer twin of the FTP
    // PORT-bounce / attacker-directed-fetch primitive the design doc forbids for every other
    // protocol ("No attacker-directed fetch", internal/design/02-sensor-framework.md). It must
    // never be confirmed.
    let packet = build_channel_open(b"direct-tcpip", 3);
    let (_channel_id, response) = handle_channel_open(&packet).unwrap();
    assert_eq!(response[0], transport::SSH_MSG_CHANNEL_OPEN_FAILURE);
    assert_ne!(response[0], transport::SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
}

#[test]
fn channel_open_rejects_malformed_packet() {
    let result = handle_channel_open(&[]);
    assert!(matches!(result, Err(ChannelError::MalformedPacket)));
}

#[test]
fn channel_request_pty_req_is_recognized() {
    let packet = build_channel_request(5, b"pty-req", true, b"");
    let action = handle_channel_request(&packet, 5).unwrap();
    assert_eq!(action, ChannelAction::PtyReq);
}

#[test]
fn channel_request_shell_is_recognized() {
    let packet = build_channel_request(5, b"shell", true, b"");
    let action = handle_channel_request(&packet, 5).unwrap();
    assert_eq!(action, ChannelAction::Shell);
}

#[test]
fn channel_request_exec_captures_raw_command() {
    let mut extra = Vec::new();
    push_ssh_string(&mut extra, b"cat /etc/passwd");
    let packet = build_channel_request(5, b"exec", true, &extra);
    let action = handle_channel_request(&packet, 5).unwrap();
    assert_eq!(action, ChannelAction::Exec("cat /etc/passwd".to_string()));
}

#[test]
fn channel_request_subsystem_captures_name() {
    let mut extra = Vec::new();
    push_ssh_string(&mut extra, b"sftp");
    let packet = build_channel_request(5, b"subsystem", true, &extra);
    let action = handle_channel_request(&packet, 5).unwrap();
    assert_eq!(action, ChannelAction::Subsystem("sftp".to_string()));
}

#[test]
fn channel_request_unknown_type_is_other() {
    let packet = build_channel_request(5, b"env", false, b"");
    let action = handle_channel_request(&packet, 5).unwrap();
    assert_eq!(action, ChannelAction::Other);
}

#[test]
fn channel_request_rejects_channel_id_mismatch() {
    let packet = build_channel_request(5, b"shell", true, b"");
    let result = handle_channel_request(&packet, 99);
    assert!(matches!(result, Err(ChannelError::ChannelMismatch)));
}

#[test]
fn channel_request_rejects_malformed_packet() {
    let result = handle_channel_request(&[], 0);
    assert!(matches!(result, Err(ChannelError::MalformedPacket)));
}

// ---------------------------------------------------------------------------------------------
// Fuzz-lite guards: every function above parses bytes from an unauthenticated (auth.rs) or
// freshly-authenticated-but-still-hostile (channel.rs) peer, so arbitrary, possibly-truncated
// input must always resolve to `Ok`/`Err`, never panic. Mirrors
// `transport::tests::parse_kexinit_never_panics_on_arbitrary_bytes`.
// ---------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn handle_userauth_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=512)
    ) {
        let mut state = AuthState::new("203.0.113.7".parse().unwrap(), None);
        let _ = state.handle_userauth(&bytes);
    }

    #[test]
    fn handle_channel_open_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=512)
    ) {
        let _ = handle_channel_open(&bytes);
    }

    #[test]
    fn handle_channel_request_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=512),
        channel_id in any::<u32>()
    ) {
        let _ = handle_channel_request(&bytes, channel_id);
    }
}

// ---------------------------------------------------------------------------------------------
// Wire-building helpers
// ---------------------------------------------------------------------------------------------

fn build_password_userauth(username: &[u8], password: &[u8]) -> Vec<u8> {
    // SSH_MSG_USERAUTH_REQUEST format:
    // byte      SSH_MSG_USERAUTH_REQUEST (50)
    // string    user name
    // string    service name ("ssh-connection")
    // string    method name ("password")
    // boolean   FALSE (no old password)
    // string    plaintext password
    let mut buf = vec![transport::SSH_MSG_USERAUTH_REQUEST];
    push_ssh_string(&mut buf, username);
    push_ssh_string(&mut buf, b"ssh-connection");
    push_ssh_string(&mut buf, b"password");
    buf.push(0); // FALSE
    push_ssh_string(&mut buf, password);
    buf
}

fn push_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn build_channel_open(channel_type: &[u8], sender_channel: u32) -> Vec<u8> {
    let mut buf = vec![transport::SSH_MSG_CHANNEL_OPEN];
    push_ssh_string(&mut buf, channel_type);
    buf.extend_from_slice(&sender_channel.to_be_bytes());
    buf.extend_from_slice(&2_097_152u32.to_be_bytes()); // initial window size
    buf.extend_from_slice(&32_768u32.to_be_bytes()); // maximum packet size
    buf
}

fn build_channel_request(
    channel_id: u32,
    request_type: &[u8],
    want_reply: bool,
    extra: &[u8],
) -> Vec<u8> {
    let mut buf = vec![transport::SSH_MSG_CHANNEL_REQUEST];
    buf.extend_from_slice(&channel_id.to_be_bytes());
    push_ssh_string(&mut buf, request_type);
    buf.push(want_reply as u8);
    buf.extend_from_slice(extra);
    buf
}
