use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, TlsServer, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

use crate::tds_tls::TdsTlsAdapter;
use crate::{with_tls, write_flush};

const PROTOCOL_LABEL: &str = "mssql";
const MAX_TDS_PACKET: usize = 65536;

// TDS packet types
const TDS_PRELOGIN: u8 = 0x12;
const TDS_LOGIN7: u8 = 0x10;
const TDS_RESPONSE: u8 = 0x04;

// PRELOGIN ENCRYPTION option values (MS-TDS 2.2.6.5); the 0x80 bit marks client-cert variants.
const ENCRYPT_OFF: u8 = 0x00;
const ENCRYPT_ON: u8 = 0x01;
const ENCRYPT_NOT_SUP: u8 = 0x02;
const ENCRYPT_REQ: u8 = 0x03;
const PL_VERSION: u8 = 0x00;
const PL_ENCRYPTION: u8 = 0x01;
const PL_TERMINATOR: u8 = 0xFF;
/// 15.0.4153.0, SQL Server 2019.
const SERVER_VERSION: [u8; 6] = [15, 0, 16, 57, 0, 0];

/// `starttls` set: PRELOGIN is answered per `negotiate_encryption` and, when that negotiates TLS,
/// the handshake runs inside TDS PRELOGIN packets and Login7 arrives over TLS, unless the client
/// sends a plaintext Login7 instead, which is captured untagged. `None`: the
/// PRELOGIN response carries no ENCRYPTION option, as before.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    starttls: Option<TlsServer>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = local_addr
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let _ = emitter
        .append(&connection_event(source_ip, wan_ip, session_id))
        .await;

    let timeout = bounds.read_timeout;

    // 1. Read client PreLogin
    let Some((pkt_type, prelogin)) = read_tds_packet(&mut stream, None, timeout).await else {
        return;
    };
    if pkt_type != TDS_PRELOGIN {
        return;
    }

    // 2. Send PreLogin response
    let negotiated = starttls
        .as_ref()
        .map(|_| negotiate_encryption(client_encryption(&prelogin)));
    let prelogin_resp = build_prelogin_response(negotiated.as_ref().and_then(|n| n.reply));
    if write_flush(&mut stream, &prelogin_resp).await.is_err() {
        return;
    }

    match (starttls, negotiated) {
        (Some(tls), Some(Negotiated { tls: true, .. })) => {
            // Read (not peek: `S` is any stream) the first byte after PRELOGIN to choose the path.
            let mut first = [0u8; 1];
            match tokio::time::timeout(timeout, stream.read_exact(&mut first)).await {
                Ok(Ok(_)) => {}
                _ => return,
            }
            // Capture first: a client that asked for encryption but then sends a plaintext
            // Login7 still has its credential recorded, as an ENCRYPT_OFF client would.
            if first[0] == TDS_LOGIN7 {
                tracing::debug!(peer = %peer_addr, "mssql client asked for encryption but sent a plaintext login7");
                return finish_login(
                    &mut stream,
                    Some(first[0]),
                    source_ip,
                    wan_ip,
                    session_id,
                    &emitter,
                    timeout,
                    false,
                )
                .await;
            }
            let framed = TdsTlsAdapter::starting_with(stream, first[0]);
            let mut secure = match tokio::time::timeout(timeout, tls.accept(framed)).await {
                Ok(Ok(secure)) => secure,
                Ok(Err(error)) => {
                    tracing::debug!(peer = %peer_addr, %error, "mssql tls handshake failed; dropping connection");
                    return;
                }
                Err(_elapsed) => {
                    tracing::debug!(peer = %peer_addr, "mssql tls handshake timed out; dropping connection");
                    return;
                }
            };
            // A handshake tail still queued in rustls (the TLS 1.2 server CCS + Finished) must
            // leave through the still-framing adapter. tokio-rustls 0.26.4 already flushes at the
            // end of `accept`; this flush keeps the invariant local rather than relying on that.
            if secure.flush().await.is_err() {
                return;
            }
            secure.get_mut().0.finish_handshake();
            finish_login(
                &mut secure,
                None,
                source_ip,
                wan_ip,
                session_id,
                &emitter,
                timeout,
                true,
            )
            .await;
        }
        _ => {
            finish_login(
                &mut stream,
                None,
                source_ip,
                wan_ip,
                session_id,
                &emitter,
                timeout,
                false,
            )
            .await
        }
    }
}

/// Read Login7, record the username, answer LOGINACK. `first` is the packet's first byte when
/// the caller has already consumed it.
#[allow(clippy::too_many_arguments)]
async fn finish_login<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    first: Option<u8>,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    emitter: &EventEmitter,
    timeout: std::time::Duration,
    tls: bool,
) {
    let Some((pkt_type, login7)) = read_tds_packet(stream, first, timeout).await else {
        return;
    };
    if pkt_type != TDS_LOGIN7 {
        return;
    }

    let username = parse_login7_username(&login7);
    let username = sanitize_value(&username, 255);

    let _ = emitter
        .append(&with_tls(
            login_event(source_ip, wan_ip, &username, session_id),
            tls,
        ))
        .await;

    let _ = write_flush(stream, &build_loginack()).await;
}

/// The ENCRYPTION option byte of a client PRELOGIN payload; `None` if absent or malformed.
fn client_encryption(prelogin: &[u8]) -> Option<u8> {
    let mut i = 0;
    loop {
        let token = *prelogin.get(i)?;
        if token == PL_TERMINATOR {
            return None;
        }
        let h = prelogin.get(i + 1..i + 5)?;
        let offset = u16::from_be_bytes([h[0], h[1]]) as usize;
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        if token == PL_ENCRYPTION {
            return if len >= 1 {
                prelogin.get(offset).copied()
            } else {
                None
            };
        }
        i += 5;
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Negotiated {
    /// The ENCRYPTION option of the PRELOGIN response; `None` sends the pre-TLS response, which
    /// has no ENCRYPTION option at all.
    reply: Option<u8>,
    tls: bool,
}

/// Not the MS-TDS server table, on purpose: capture over fidelity. A client that asks for
/// encryption (ON or REQ) is answered ON and gets TLS. A client that offers OFF gets the pre-TLS
/// response byte for byte and a plaintext session; a real ENCRYPT_ON server would answer REQ and
/// force TLS, which loses the Login7 of every scanner that cannot do TLS. A NOT_SUP (or silent)
/// client is answered NOT_SUP and kept in plaintext rather than terminated. Login-only encryption
/// (a reply of OFF) is never offered: it would need a TLS-to-plaintext downgrade after Login7.
/// Client-cert variants are masked to their base value; the handshake never asks for a client
/// certificate.
fn negotiate_encryption(client: Option<u8>) -> Negotiated {
    match client.map(|v| v & 0x03) {
        Some(ENCRYPT_OFF) => Negotiated {
            reply: None,
            tls: false,
        },
        Some(ENCRYPT_ON) | Some(ENCRYPT_REQ) => Negotiated {
            reply: Some(ENCRYPT_ON),
            tls: true,
        },
        _ => Negotiated {
            reply: Some(ENCRYPT_NOT_SUP),
            tls: false,
        },
    }
}

fn build_prelogin_response(encryption: Option<u8>) -> Vec<u8> {
    let mut payload = Vec::new();
    match encryption {
        // Minimal PreLogin: VERSION option only (offset 6, length 6).
        None => {
            payload.push(PL_VERSION);
            payload.extend_from_slice(&6u16.to_be_bytes());
            payload.extend_from_slice(&6u16.to_be_bytes());
            payload.push(PL_TERMINATOR);
            payload.extend_from_slice(&SERVER_VERSION);
        }
        // VERSION (offset 11, length 6) then ENCRYPTION (offset 17, length 1).
        Some(enc) => {
            payload.push(PL_VERSION);
            payload.extend_from_slice(&11u16.to_be_bytes());
            payload.extend_from_slice(&6u16.to_be_bytes());
            payload.push(PL_ENCRYPTION);
            payload.extend_from_slice(&17u16.to_be_bytes());
            payload.extend_from_slice(&1u16.to_be_bytes());
            payload.push(PL_TERMINATOR);
            payload.extend_from_slice(&SERVER_VERSION);
            payload.push(enc);
        }
    }
    wrap_tds_packet(TDS_RESPONSE, &payload)
}

fn build_loginack() -> Vec<u8> {
    let mut payload = Vec::new();
    // Token type LOGINACK (0xAD)
    payload.push(0xAD);
    // Length (2 bytes)
    let ack_body: Vec<u8> = {
        let mut b = Vec::new();
        b.push(0x01); // interface: SQL_DFLT
        b.extend_from_slice(&[0x74, 0x00, 0x00, 0x00]); // TDS version 7.4
        // LOGINACK ProgName (the server program name) as UTF-16LE. Real SQL Server sends the
        // literal product name here, NOT the instance/host and NEVER the honeypot's own name - a
        // banner that names the honeypot lets a scanner enumerate every node by searching for it.
        let name = "Microsoft SQL Server";
        b.push(name.len() as u8);
        for c in name.encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b.extend_from_slice(&[15, 0, 16, 57]); // server version
        b
    };
    payload.extend_from_slice(&(ack_body.len() as u16).to_le_bytes());
    payload.extend_from_slice(&ack_body);

    // DONE token (0xFD) to signal end of response
    payload.push(0xFD);
    payload.extend_from_slice(&[0x00, 0x00]); // status
    payload.extend_from_slice(&[0x00, 0x00]); // curcmd
    payload.extend_from_slice(&0u64.to_le_bytes()); // done row count

    wrap_tds_packet(TDS_RESPONSE, &payload)
}

/// Parse username from a TDS Login7 packet. The Login7 body has fixed offsets at known positions
/// for the client name, username, password, etc. Username is at OffsetIbUserName (offset 48-49)
/// and CchUserName (offset 50-51), stored as UTF-16LE.
fn parse_login7_username(data: &[u8]) -> String {
    if data.len() < 94 {
        return String::new();
    }
    // Login7 layout: first 4 bytes are total length, then fixed fields
    // Username offset is at byte 48 (relative to start of Login7 body)
    // Username length (in chars) at byte 50
    let offset = u16::from_le_bytes([data[48], data[49]]) as usize;
    let length = u16::from_le_bytes([data[50], data[51]]) as usize;

    if length == 0 || offset + length * 2 > data.len() {
        return String::new();
    }

    let utf16_bytes = &data[offset..offset + length * 2];
    let utf16: Vec<u16> = utf16_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    String::from_utf16_lossy(&utf16)
}

fn wrap_tds_packet(pkt_type: u8, payload: &[u8]) -> Vec<u8> {
    let total = 8 + payload.len();
    let mut packet = Vec::with_capacity(total);
    packet.push(pkt_type);
    packet.push(0x01); // status: EOM
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // SPID
    packet.push(0x01); // packet ID
    packet.push(0x00); // window
    packet.extend_from_slice(payload);
    packet
}

/// One TDS packet. `first`: the header's first byte, already consumed by the caller.
async fn read_tds_packet<S: AsyncRead + Unpin>(
    stream: &mut S,
    first: Option<u8>,
    timeout: std::time::Duration,
) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 8];
    let start = match first {
        Some(byte) => {
            header[0] = byte;
            1
        }
        None => 0,
    };
    tokio::time::timeout(timeout, stream.read_exact(&mut header[start..]))
        .await
        .ok()?
        .ok()?;

    let pkt_type = header[0];
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(8..=MAX_TDS_PACKET).contains(&length) {
        return None;
    }

    let payload_len = length - 8;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        tokio::time::timeout(timeout, stream.read_exact(&mut payload))
            .await
            .ok()?
            .ok()?;
    }

    Some((pkt_type, payload))
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
        reply: None,
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
        reply: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_login7_username_extracts_utf16le() {
        // Build a minimal Login7-shaped buffer with username "sa" at offset 94
        let mut data = vec![0u8; 200];
        // Total length
        data[0..4].copy_from_slice(&200u32.to_le_bytes());
        // Username offset at byte 48-49: point to byte 94
        data[48..50].copy_from_slice(&94u16.to_le_bytes());
        // Username length (in chars) at byte 50-51: 2 chars
        data[50..52].copy_from_slice(&2u16.to_le_bytes());
        // Write "sa" as UTF-16LE at offset 94
        data[94] = b's';
        data[95] = 0;
        data[96] = b'a';
        data[97] = 0;
        assert_eq!(parse_login7_username(&data), "sa");
    }

    #[test]
    fn parse_login7_username_returns_empty_on_short_data() {
        assert_eq!(parse_login7_username(&[0u8; 10]), "");
    }

    #[test]
    fn tds_packet_wrapping() {
        let pkt = wrap_tds_packet(TDS_RESPONSE, &[0xAA, 0xBB]);
        assert_eq!(pkt[0], TDS_RESPONSE);
        assert_eq!(pkt[1], 0x01); // EOM
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 10); // 8 header + 2 payload
        assert_eq!(pkt[8], 0xAA);
        assert_eq!(pkt[9], 0xBB);
    }

    /// A client PRELOGIN payload: option table, terminator, then the option data in order.
    fn prelogin(opts: &[(u8, &[u8])]) -> Vec<u8> {
        let table_len = opts.len() * 5 + 1;
        let mut table = Vec::new();
        let mut data = Vec::new();
        for (token, value) in opts {
            table.push(*token);
            table.extend_from_slice(&((table_len + data.len()) as u16).to_be_bytes());
            table.extend_from_slice(&(value.len() as u16).to_be_bytes());
            data.extend_from_slice(value);
        }
        table.push(PL_TERMINATOR);
        [table, data].concat()
    }

    #[test]
    fn client_encryption_parses_the_option() {
        let version: &[u8] = &[15, 0, 0, 1, 0, 0];
        let both = prelogin(&[(PL_VERSION, version), (PL_ENCRYPTION, &[0x01])]);
        assert_eq!(client_encryption(&both), Some(0x01));
        // A different value at the option's offset proves the offset is followed, not guessed.
        let off = prelogin(&[(PL_VERSION, version), (PL_ENCRYPTION, &[0x00])]);
        assert_eq!(client_encryption(&off), Some(0x00));
        assert_eq!(client_encryption(&prelogin(&[(PL_VERSION, version)])), None);
        assert_eq!(
            client_encryption(&both[..7]),
            None,
            "truncated option table"
        );
        let mut past_end = prelogin(&[(PL_ENCRYPTION, &[0x01])]);
        past_end[1..3].copy_from_slice(&500u16.to_be_bytes());
        assert_eq!(client_encryption(&past_end), None);
        assert_eq!(client_encryption(&[]), None);
    }

    #[test]
    fn negotiation_follows_the_capture_first_table() {
        let n = |reply, tls| Negotiated { reply, tls };
        // OFF keeps the pre-TLS reply (no ENCRYPTION option) and a plaintext session, where a
        // real ENCRYPT_ON server would answer REQ.
        assert_eq!(negotiate_encryption(Some(0x00)), n(None, false));
        assert_eq!(negotiate_encryption(Some(0x80)), n(None, false));
        assert_eq!(negotiate_encryption(Some(0x01)), n(Some(ENCRYPT_ON), true));
        assert_eq!(negotiate_encryption(Some(0x03)), n(Some(ENCRYPT_ON), true));
        assert_eq!(
            negotiate_encryption(Some(0x02)),
            n(Some(ENCRYPT_NOT_SUP), false)
        );
        assert_eq!(negotiate_encryption(None), n(Some(ENCRYPT_NOT_SUP), false));
        assert_eq!(negotiate_encryption(Some(0x81)), n(Some(ENCRYPT_ON), true));
    }

    #[test]
    fn prelogin_response_without_tls_is_byte_identical_to_before() {
        // Golden bytes from the pre-TLS build_prelogin_response.
        assert_eq!(
            build_prelogin_response(None),
            [
                0x04, 0x01, 0x00, 0x14, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0xFF,
                15, 0, 16, 57, 0, 0
            ]
        );
    }

    #[test]
    fn prelogin_response_with_encryption_layout() {
        let pkt = build_prelogin_response(Some(ENCRYPT_ON));
        assert_eq!(
            pkt,
            [
                0x04, 0x01, 0x00, 0x1A, 0, 0, 1, 0, 0x00, 0x00, 0x0B, 0x00, 0x06, 0x01, 0x00, 0x11,
                0x00, 0x01, 0xFF, 15, 0, 16, 57, 0, 0, 0x01
            ]
        );
        assert_eq!(client_encryption(&pkt[8..]), Some(ENCRYPT_ON));
        assert_eq!(
            client_encryption(&build_prelogin_response(Some(ENCRYPT_REQ))[8..]),
            Some(ENCRYPT_REQ)
        );
    }
}
