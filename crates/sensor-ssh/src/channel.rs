//! SSH channel and session-request dispatch (RFC 4254 sections 5-6): parses
//! `SSH_MSG_CHANNEL_OPEN` and `SSH_MSG_CHANNEL_REQUEST` payloads into plain data (a channel id, a
//! response packet, or a `ChannelAction`) for the session orchestrator to act on and push through
//! the encrypted packet I/O (Task 11). Like `auth`, this module performs no I/O of its own, so it
//! is deterministic and testable without a live socket.
//!
//! **Only `session` channels are ever confirmed.** `direct-tcpip` (SSH local port forwarding) and
//! every other non-`session` channel type ask the server to relay bytes to or from a third address
//! the *client* names - exactly the request-forgery shape
//! `internal/design/02-sensor-framework.md`'s "No attacker-directed fetch" forbids for every other
//! protocol verb shaped like "the server goes and gets something" (FTP `RETR`/`PORT`, TFTP `RRQ`),
//! a guarantee the design doc gates at the same review priority as never-exec. Refusing every
//! channel type but `session` at open time closes this off by construction: no later task can wire
//! up a proxy by forgetting to check the type, because the type is checked once, here, before a
//! channel exists at all.
//!
//! **Sanitization is deferred to the event builder.** `ChannelAction::Exec`/`Subsystem` carry the
//! raw, unsanitized command/subsystem-name string - this module never constructs a `SensorEvent`,
//! so there is nothing here for `sanitize_value` to protect yet. The caller must sanitize at the
//! point it embeds the value in an event, the same convention
//! `transport::do_version_exchange_server_with_version` documents for the version banner it
//! returns.

use crate::transport::{
    SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE,
    SSH_MSG_CHANNEL_REQUEST,
};

/// RFC 4254 section 5.1's reason code for a channel type this server does not service.
const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;

/// Initial window size and maximum packet size this server advertises for every confirmed
/// channel. This server never rate-limits attacker traffic through SSH flow control - that is
/// `sensor_framework::ConnectionBounds`' job - so these are simply generous, protocol-plausible
/// defaults (in OpenSSH's own neighborhood), not a tuned capacity plan.
const INITIAL_WINDOW_SIZE: u32 = 2_097_152; // 2 MiB
const CHANNEL_MAX_PACKET_SIZE: u32 = 32_768; // 32 KiB

/// What the caller should do next after a `SSH_MSG_CHANNEL_REQUEST`. See the module doc for why
/// `Exec`/`Subsystem` carry their string raw, unsanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelAction {
    /// `pty-req`: a pseudo-terminal was requested. Acknowledged unconditionally; the requested
    /// terminal type and dimensions are parsed to keep the wire cursor aligned but not retained.
    PtyReq,
    /// `shell`: start the interactive fake shell (Task 13).
    Shell,
    /// `exec <command>`: run one command non-interactively. Carries the raw command string.
    Exec(String),
    /// `subsystem <name>`: e.g. `sftp`. Carries the raw subsystem name.
    Subsystem(String),
    /// Any other request type (`env`, `window-change`, `signal`, `exit-status`, ...externally
    /// this server never has anything to do with them).
    Other,
}

/// Errors this module's parsing can produce. Every variant is constructed from a checked
/// condition on attacker-controlled bytes, matching `auth::AuthError`'s and
/// `transport::TransportError`'s own construction discipline: never a caught panic.
#[derive(Debug)]
pub enum ChannelError {
    /// The payload's own fields are structurally inconsistent: wrong message type, a truncated
    /// string, or a length prefix past the end of the payload.
    MalformedPacket,
    /// The packet's own `recipient channel` field did not match the `channel_id` the caller
    /// already associated with this exchange.
    ChannelMismatch,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::MalformedPacket => write!(f, "malformed SSH channel message"),
            ChannelError::ChannelMismatch => {
                write!(f, "recipient channel did not match the expected channel id")
            }
        }
    }
}

impl std::error::Error for ChannelError {}

/// Handle one `SSH_MSG_CHANNEL_OPEN` (RFC 4254 section 5.1). Returns the channel number this
/// exchange concerns - the client's own `sender channel`, echoed back - and the response packet to
/// send.
///
/// **The caller must check the response's message type (byte 0) before treating the returned id
/// as an open channel.** For a `session` channel - the only type this server ever services - the
/// response is `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` and the id is reused as this server's own
/// channel id (mirroring the client's own number is sufficient to keep ids unique per connection
/// with no allocator state at all: RFC 4254 already requires a correct client to give each of its
/// own concurrently open channels a distinct sender-channel number, so reusing that same number as
/// our side's id inherits that same uniqueness for free). For anything else the response is
/// `SSH_MSG_CHANNEL_OPEN_FAILURE` (see the module doc for why) - no channel exists, and the
/// returned id is only the client's number for bookkeeping/logging, never one to register as open.
pub fn handle_channel_open(packet: &[u8]) -> Result<(u32, Vec<u8>), ChannelError> {
    let mut cursor = 0usize;

    let msg_type = read_u8(packet, &mut cursor)?;
    if msg_type != SSH_MSG_CHANNEL_OPEN {
        return Err(ChannelError::MalformedPacket);
    }

    let channel_type = read_string(packet, &mut cursor)?;
    let sender_channel = read_u32(packet, &mut cursor)?;
    let _initial_window_size = read_u32(packet, &mut cursor)?;
    let _max_packet_size = read_u32(packet, &mut cursor)?;

    if channel_type != b"session" {
        return Ok((sender_channel, build_channel_open_failure(sender_channel)));
    }

    Ok((
        sender_channel,
        build_channel_open_confirmation(sender_channel),
    ))
}

/// Handle one `SSH_MSG_CHANNEL_REQUEST` (RFC 4254 section 5.4). `channel_id` is the id the caller
/// already associated with this channel (from `handle_channel_open`'s return); it is checked
/// against the packet's own `recipient channel` field rather than trusted blindly, so a confused
/// or malicious peer addressing the wrong channel is rejected rather than silently misrouted.
pub fn handle_channel_request(
    packet: &[u8],
    channel_id: u32,
) -> Result<ChannelAction, ChannelError> {
    let mut cursor = 0usize;

    let msg_type = read_u8(packet, &mut cursor)?;
    if msg_type != SSH_MSG_CHANNEL_REQUEST {
        return Err(ChannelError::MalformedPacket);
    }

    let recipient_channel = read_u32(packet, &mut cursor)?;
    if recipient_channel != channel_id {
        return Err(ChannelError::ChannelMismatch);
    }

    let request_type = read_string(packet, &mut cursor)?;
    let _want_reply = read_u8(packet, &mut cursor)?;

    let action = match request_type.as_slice() {
        b"pty-req" => ChannelAction::PtyReq,
        b"shell" => ChannelAction::Shell,
        b"exec" => {
            let command = read_string(packet, &mut cursor)?;
            ChannelAction::Exec(String::from_utf8_lossy(&command).into_owned())
        }
        b"subsystem" => {
            let name = read_string(packet, &mut cursor)?;
            ChannelAction::Subsystem(String::from_utf8_lossy(&name).into_owned())
        }
        _ => ChannelAction::Other,
    };

    Ok(action)
}

/// Build `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (RFC 4254 section 5.1): recipient channel (the
/// client's own number for this channel) + sender channel (this server's id, mirrored from the
/// same number - see `handle_channel_open`'s doc) + the window/packet-size limits above.
fn build_channel_open_confirmation(channel: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    out.extend_from_slice(&channel.to_be_bytes()); // recipient channel
    out.extend_from_slice(&channel.to_be_bytes()); // sender channel (mirrored)
    out.extend_from_slice(&INITIAL_WINDOW_SIZE.to_be_bytes());
    out.extend_from_slice(&CHANNEL_MAX_PACKET_SIZE.to_be_bytes());
    out
}

/// Build `SSH_MSG_CHANNEL_OPEN_FAILURE` (RFC 4254 section 5.1) for a channel type this server
/// refuses to service. No channel is created, so there is no server-side id to report.
fn build_channel_open_failure(recipient_channel: u32) -> Vec<u8> {
    let description = b"unsupported channel type";
    let mut out = Vec::with_capacity(1 + 4 + 4 + 4 + description.len() + 4);
    out.push(SSH_MSG_CHANNEL_OPEN_FAILURE);
    out.extend_from_slice(&recipient_channel.to_be_bytes());
    out.extend_from_slice(&SSH_OPEN_UNKNOWN_CHANNEL_TYPE.to_be_bytes());
    out.extend_from_slice(&(description.len() as u32).to_be_bytes());
    out.extend_from_slice(description);
    out.extend_from_slice(&0u32.to_be_bytes()); // language tag, empty
    out
}

// ---- Small bounds-checked binary reader, mirroring transport::mod's own parsing discipline:
// every offset is derived from a length field read out of `data` itself and checked with
// `checked_add`/`.get(..)` before use, so a truncated or hostile packet returns `Err` rather than
// panicking. ----

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, ChannelError> {
    let byte = *data.get(*cursor).ok_or(ChannelError::MalformedPacket)?;
    *cursor += 1;
    Ok(byte)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, ChannelError> {
    let end = cursor.checked_add(4).ok_or(ChannelError::MalformedPacket)?;
    let bytes = data
        .get(*cursor..end)
        .ok_or(ChannelError::MalformedPacket)?;
    let value = u32::from_be_bytes(bytes.try_into().expect("slice is exactly 4 bytes"));
    *cursor = end;
    Ok(value)
}

fn read_string(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ChannelError> {
    let len = read_u32(data, cursor)? as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(ChannelError::MalformedPacket)?;
    let bytes = data
        .get(*cursor..end)
        .ok_or(ChannelError::MalformedPacket)?
        .to_vec();
    *cursor = end;
    Ok(bytes)
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
    fn build_channel_open_confirmation_has_expected_layout() {
        let bytes = build_channel_open_confirmation(42);
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[0], SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        assert_eq!(u32::from_be_bytes(bytes[1..5].try_into().unwrap()), 42);
        assert_eq!(u32::from_be_bytes(bytes[5..9].try_into().unwrap()), 42);
    }

    #[test]
    fn handle_channel_open_rejects_wrong_message_type() {
        let mut buf = vec![SSH_MSG_CHANNEL_OPEN + 1];
        push_ssh_string(&mut buf, b"session");
        let result = handle_channel_open(&buf);
        assert!(matches!(result, Err(ChannelError::MalformedPacket)));
    }

    #[test]
    fn handle_channel_request_rejects_truncated_exec_command() {
        // "exec" promises a trailing command string but the packet is cut off before it.
        let mut buf = vec![SSH_MSG_CHANNEL_REQUEST];
        buf.extend_from_slice(&5u32.to_be_bytes());
        push_ssh_string(&mut buf, b"exec");
        buf.push(1); // want_reply = true
        // Missing: the command string.
        let result = handle_channel_request(&buf, 5);
        assert!(matches!(result, Err(ChannelError::MalformedPacket)));
    }

    proptest! {
        /// Fuzz-lite guard: mirrors
        /// `transport::tests::parse_kexinit_never_panics_on_arbitrary_bytes` for this module's
        /// own pre-authorization binary parsing.
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
}
