use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "mysql";
const MAX_PACKET_SIZE: usize = 65536;

pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
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

    let _ = emitter
        .append(&connection_event(source_ip, wan_ip, session_id))
        .await;

    let timeout = bounds.read_timeout;

    // Send MySQL greeting packet
    let greeting = build_greeting();
    if stream.write_all(&greeting).await.is_err() {
        return;
    }

    // Read client HandshakeResponse
    let Some(response) = read_mysql_packet(&mut stream, timeout).await else {
        return;
    };

    // Parse username from HandshakeResponse41
    // Layout after 4-byte header: cap_flags(4) + max_packet(4) + charset(1) + reserved(23) + username(NUL)
    if response.len() < 36 {
        return;
    }
    let username_start = 32; // 4 + 4 + 1 + 23
    let username = extract_nul_string(&response[username_start..]);
    let username = sanitize_value(&username, 255);

    let _ = emitter
        .append(&login_event(source_ip, wan_ip, &username, session_id))
        .await;

    // Send OK packet
    let ok_packet = build_ok_packet(2);
    let _ = stream.write_all(&ok_packet).await;
}

fn build_greeting() -> Vec<u8> {
    // Per-connection random thread id and scramble. A real MySQL server varies both on every
    // connection; the old constants (id 1, an all-0x42 scramble) were a one-packet honeypot tell
    // and made the challenge-response replayable.
    let conn_id: u32 = (rand::random::<u32>() % 50_000) + 1000;
    let scramble: [u8; 20] = rand::random();

    let mut payload = Vec::new();
    payload.push(0x0a); // protocol version 10
    payload.extend_from_slice(b"5.7.42\0"); // server version (never embed the project name here - a
    // banner that names the honeypot lets a scanner find every node by searching for it)
    payload.extend_from_slice(&conn_id.to_le_bytes()); // connection id
    payload.extend_from_slice(&scramble[..8]); // auth-plugin-data part 1
    payload.push(0x00); // filler
    // capability flags lower: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
    payload.extend_from_slice(&0x0200_f7ffu32.to_le_bytes()[..2]);
    payload.push(0x21); // character set (utf8_general_ci)
    payload.extend_from_slice(&0x0002u16.to_le_bytes()); // status flags
    // capability flags upper
    payload.extend_from_slice(&0x0200_f7ffu32.to_le_bytes()[2..4]);
    payload.push(21); // auth-plugin-data length
    payload.extend_from_slice(&[0x00; 10]); // reserved
    payload.extend_from_slice(&scramble[8..20]); // auth-plugin-data part 2 (12 bytes)
    payload.push(0x00); // NUL terminator for auth-plugin-data
    payload.extend_from_slice(b"mysql_native_password\0");

    wrap_packet(0, &payload)
}

fn build_ok_packet(seq: u8) -> Vec<u8> {
    let payload = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]; // OK, 0 affected, 0 insert_id, status, 0 warnings
    wrap_packet(seq, &payload)
}

fn wrap_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len.to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(payload);
    packet
}

async fn read_mysql_packet(
    stream: &mut TcpStream,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;

    let length = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    if length > MAX_PACKET_SIZE {
        return None;
    }

    let mut payload = vec![0u8; length];
    tokio::time::timeout(timeout, stream.read_exact(&mut payload))
        .await
        .ok()?
        .ok()?;

    Some(payload)
}

fn extract_nul_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_packet_has_valid_structure() {
        let pkt = build_greeting();
        assert!(pkt.len() > 4);
        let payload_len = (pkt[0] as usize) | ((pkt[1] as usize) << 8) | ((pkt[2] as usize) << 16);
        assert_eq!(payload_len, pkt.len() - 4);
        assert_eq!(pkt[3], 0); // seq 0
        assert_eq!(pkt[4], 0x0a); // protocol version 10
    }

    #[test]
    fn extract_nul_string_works() {
        assert_eq!(extract_nul_string(b"root\0extra"), "root");
        assert_eq!(extract_nul_string(b"admin"), "admin");
        assert_eq!(extract_nul_string(b"\0"), "");
    }

    #[test]
    fn greeting_randomizes_per_connection() {
        // With the old constant thread id and all-0x42 scramble every greeting was byte-identical,
        // a one-packet honeypot tell and a replayable auth challenge. Two greetings must now differ.
        assert_ne!(
            build_greeting(),
            build_greeting(),
            "greeting must vary per connection (random thread id + scramble)"
        );
    }
}
