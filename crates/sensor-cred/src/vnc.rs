use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "vnc";

// RFB 3.8 - the version all modern VNC clients support
const RFB_VERSION: &[u8] = b"RFB 003.008\n";
const RFB_VERSION_LEN: usize = 12;

// SecurityType 2 = VNC Authentication (DES challenge-response)
const SECURITY_TYPES: &[u8] = &[1, 2]; // count=1, type=2
const VNC_AUTH_CHALLENGE_LEN: usize = 16;
const VNC_AUTH_RESPONSE_LEN: usize = 16;
const SECURITY_RESULT_OK: &[u8] = &[0, 0, 0, 0];

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

    // 1. Server -> Client: protocol version
    if stream.write_all(RFB_VERSION).await.is_err() {
        return;
    }

    // 2. Client -> Server: protocol version
    let mut client_version = [0u8; RFB_VERSION_LEN];
    if timed_read_exact(&mut stream, &mut client_version, timeout)
        .await
        .is_err()
    {
        return;
    }

    // 3. Server -> Client: security types (VNC Auth only)
    if stream.write_all(SECURITY_TYPES).await.is_err() {
        return;
    }

    // 4. Client -> Server: selected security type
    let mut selected = [0u8; 1];
    if timed_read_exact(&mut stream, &mut selected, timeout)
        .await
        .is_err()
    {
        return;
    }

    if selected[0] != 2 {
        return; // only VNC Auth supported
    }

    // 5. Server -> Client: 16-byte challenge. Per-connection random: a real RFB server sends a
    // fresh random challenge, and a constant one is both a fingerprint and a replayable DES auth.
    let challenge: [u8; VNC_AUTH_CHALLENGE_LEN] = rand::random();
    if stream.write_all(&challenge).await.is_err() {
        return;
    }

    // 6. Client -> Server: 16-byte DES-encrypted response
    let mut response = [0u8; VNC_AUTH_RESPONSE_LEN];
    if timed_read_exact(&mut stream, &mut response, timeout)
        .await
        .is_err()
    {
        return;
    }

    // Can't extract plaintext from DES challenge-response, but the attempt itself is the signal
    let _ = emitter
        .append(&login_event(source_ip, wan_ip, session_id))
        .await;

    // 7. Server -> Client: SecurityResult OK
    let _ = stream.write_all(SECURITY_RESULT_OK).await;
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

fn login_event(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

async fn timed_read_exact(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> Result<(), ()> {
    tokio::time::timeout(timeout, stream.read_exact(buf))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    Ok(())
}
