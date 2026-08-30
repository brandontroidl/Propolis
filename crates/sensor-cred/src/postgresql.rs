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

const PROTOCOL_LABEL: &str = "postgresql";
const MAX_STARTUP_MSG: usize = 65536;

// PostgreSQL message types (server -> client)
const AUTH_MD5_PASSWORD: i32 = 5;
const AUTH_OK: i32 = 0;

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

    // 1. Read StartupMessage (no message type byte - just length + protocol + params)
    let mut len_buf = [0u8; 4];
    if timed_read_exact(&mut stream, &mut len_buf, timeout)
        .await
        .is_err()
    {
        return;
    }
    let msg_len = i32::from_be_bytes(len_buf) as usize;
    if !(8..=MAX_STARTUP_MSG).contains(&msg_len) {
        return;
    }

    let mut body = vec![0u8; msg_len - 4];
    if timed_read_exact(&mut stream, &mut body, timeout)
        .await
        .is_err()
    {
        return;
    }

    // Check protocol version (3.0 = 196608)
    if body.len() < 4 {
        return;
    }
    let protocol = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);

    // Handle SSL request (protocol = 80877103)
    if protocol == 80877103 {
        // Decline SSL with 'N'
        if stream.write_all(b"N").await.is_err() {
            return;
        }
        // Client will resend StartupMessage without SSL
        let mut len_buf2 = [0u8; 4];
        if timed_read_exact(&mut stream, &mut len_buf2, timeout)
            .await
            .is_err()
        {
            return;
        }
        let msg_len2 = i32::from_be_bytes(len_buf2) as usize;
        if !(8..=MAX_STARTUP_MSG).contains(&msg_len2) {
            return;
        }
        body = vec![0u8; msg_len2 - 4];
        if timed_read_exact(&mut stream, &mut body, timeout)
            .await
            .is_err()
        {
            return;
        }
    }

    // Parse key=value pairs from startup message (after 4-byte protocol version)
    let username = parse_startup_params(&body[4..], "user");
    let username = sanitize_value(&username, 255);

    // 2. Send AuthenticationMD5Password challenge
    let salt: [u8; 4] = rand::random(); // per-connection random MD5 salt (a constant salt is a
    // one-packet tell and lets the challenge-response be replayed)
    let mut auth_msg = Vec::new();
    auth_msg.push(b'R'); // Authentication message type
    let body_len: i32 = 4 + 4 + 4; // length + auth_type + salt
    auth_msg.extend_from_slice(&body_len.to_be_bytes());
    auth_msg.extend_from_slice(&AUTH_MD5_PASSWORD.to_be_bytes());
    auth_msg.extend_from_slice(&salt);
    if stream.write_all(&auth_msg).await.is_err() {
        return;
    }

    // 3. Read PasswordMessage ('p' + length + md5hash)
    let mut type_buf = [0u8; 1];
    if timed_read_exact(&mut stream, &mut type_buf, timeout)
        .await
        .is_err()
    {
        return;
    }
    if type_buf[0] != b'p' {
        return;
    }

    let mut pw_len = [0u8; 4];
    if timed_read_exact(&mut stream, &mut pw_len, timeout)
        .await
        .is_err()
    {
        return;
    }
    let pw_body_len = i32::from_be_bytes(pw_len) as usize;
    if !(4..=1024).contains(&pw_body_len) {
        return;
    }
    let mut _pw_body = vec![0u8; pw_body_len - 4];
    if timed_read_exact(&mut stream, &mut _pw_body, timeout)
        .await
        .is_err()
    {
        return;
    }
    // Password hash is read only to advance the protocol; discarded.

    let _ = emitter
        .append(&login_event(source_ip, wan_ip, &username, session_id))
        .await;

    // 4. Send AuthenticationOk
    let mut ok_msg = Vec::new();
    ok_msg.push(b'R');
    ok_msg.extend_from_slice(&8i32.to_be_bytes()); // length
    ok_msg.extend_from_slice(&AUTH_OK.to_be_bytes());
    let _ = stream.write_all(&ok_msg).await;
}

fn parse_startup_params(data: &[u8], key: &str) -> String {
    let mut i = 0;
    while i < data.len() {
        let k_start = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        if i >= data.len() {
            break;
        }
        let k = &data[k_start..i];
        i += 1; // skip NUL

        let v_start = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        let v = &data[v_start..i];
        if i < data.len() {
            i += 1; // skip NUL
        }

        if k == key.as_bytes() {
            return String::from_utf8_lossy(v).into_owned();
        }

        // Empty key signals end of params
        if k.is_empty() {
            break;
        }
    }
    String::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_startup_params_extracts_user() {
        let mut data = Vec::new();
        data.extend_from_slice(b"user\0postgres\0database\0mydb\0\0");
        assert_eq!(parse_startup_params(&data, "user"), "postgres");
        assert_eq!(parse_startup_params(&data, "database"), "mydb");
        assert_eq!(parse_startup_params(&data, "missing"), "");
    }

    #[test]
    fn parse_startup_params_empty() {
        assert_eq!(parse_startup_params(&[], "user"), "");
        assert_eq!(parse_startup_params(&[0], "user"), "");
    }
}
