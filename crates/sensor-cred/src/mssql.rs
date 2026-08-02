use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "mssql";
const MAX_TDS_PACKET: usize = 65536;

// TDS packet types
const TDS_PRELOGIN: u8 = 0x12;
const TDS_LOGIN7: u8 = 0x10;
const TDS_RESPONSE: u8 = 0x04;

pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) {
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let _ = emitter.append(&connection_event(source_ip, wan_ip)).await;

    let timeout = bounds.read_timeout;

    // 1. Read client PreLogin
    let Some((pkt_type, _prelogin)) = read_tds_packet(&mut stream, timeout).await else {
        return;
    };
    if pkt_type != TDS_PRELOGIN {
        return;
    }

    // 2. Send PreLogin response
    let prelogin_resp = build_prelogin_response();
    if stream.write_all(&prelogin_resp).await.is_err() {
        return;
    }

    // 3. Read Login7
    let Some((pkt_type, login7)) = read_tds_packet(&mut stream, timeout).await else {
        return;
    };
    if pkt_type != TDS_LOGIN7 {
        return;
    }

    // 4. Parse username from Login7 packet
    let username = parse_login7_username(&login7);
    let username = sanitize_value(&username, 255);

    let _ = emitter
        .append(&login_event(source_ip, wan_ip, &username))
        .await;

    // 5. Send LOGINACK response
    let loginack = build_loginack();
    let _ = stream.write_all(&loginack).await;
}

fn build_prelogin_response() -> Vec<u8> {
    // Minimal PreLogin: VERSION token only
    let mut payload = Vec::new();
    // Option token: VERSION (0x00), offset=6, length=6
    payload.push(0x00); // token
    payload.extend_from_slice(&6u16.to_be_bytes()); // offset
    payload.extend_from_slice(&6u16.to_be_bytes()); // length
    payload.push(0xFF); // terminator
    // VERSION value: 15.0.4153.1 (SQL Server 2019)
    payload.extend_from_slice(&[15, 0, 16, 57]); // major.minor.build
    payload.extend_from_slice(&[0, 0]); // sub-build

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
        // Server name as UTF-16LE
        let name = "Propolis";
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

async fn read_tds_packet(
    stream: &mut TcpStream,
    timeout: std::time::Duration,
) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 8];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
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

fn connection_event(source_ip: IpAddr, wan_ip: Option<IpAddr>) -> SensorEvent {
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
    }
}

fn login_event(source_ip: IpAddr, wan_ip: Option<IpAddr>, username: &str) -> SensorEvent {
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
}
