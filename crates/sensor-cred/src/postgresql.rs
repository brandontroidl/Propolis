use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION,
    SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
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

    // 4. Send AuthenticationOk, then what a real server sends before it will take a query:
    // its ParameterStatus set, BackendKeyData, and ReadyForQuery. Closing right after
    // AuthenticationOk, as this handler used to, ended the session before the client could send
    // anything, so whatever the attacker intended to run was never observed.
    let mut ok_msg = Vec::new();
    ok_msg.push(b'R');
    ok_msg.extend_from_slice(&8i32.to_be_bytes()); // length
    ok_msg.extend_from_slice(&AUTH_OK.to_be_bytes());
    for (name, value) in SERVER_PARAMETERS {
        ok_msg.extend_from_slice(&parameter_status(name, value));
    }
    ok_msg.extend_from_slice(&backend_key_data());
    ok_msg.extend_from_slice(&READY_FOR_QUERY_IDLE);
    if stream.write_all(&ok_msg).await.is_err() {
        return;
    }

    // 5. Query loop: record every simple query as a command event and refuse it the way a
    // server refuses a role without the privilege, then go back to ReadyForQuery. That keeps the
    // session open for the next statement instead of hanging up on the first.
    let mut total_read: u64 = 0;
    let mut messages = 0usize;
    // Extended-protocol error state: after a refused Execute a real server discards everything
    // until the client's Sync, then answers ReadyForQuery.
    let mut skip_until_sync = false;
    loop {
        let mut type_buf = [0u8; 1];
        if timed_read_exact(&mut stream, &mut type_buf, bounds.idle_timeout)
            .await
            .is_err()
        {
            return;
        }
        let mut len_buf = [0u8; 4];
        if timed_read_exact(&mut stream, &mut len_buf, bounds.idle_timeout)
            .await
            .is_err()
        {
            return;
        }
        let msg_len = i32::from_be_bytes(len_buf);
        if !(4..=MAX_QUERY_MSG).contains(&msg_len) {
            return;
        }
        let mut body = vec![0u8; msg_len as usize - 4];
        if timed_read_exact(&mut stream, &mut body, bounds.idle_timeout)
            .await
            .is_err()
        {
            return;
        }
        total_read += 5 + body.len() as u64;
        messages += 1;
        if total_read >= bounds.max_captured_bytes || messages > MAX_QUERY_MESSAGES {
            return;
        }
        match type_buf[0] {
            // Simple query: the statement text, NUL-terminated.
            b'Q' => {
                let sql = String::from_utf8_lossy(body.strip_suffix(&[0]).unwrap_or(&body));
                let _ = emitter
                    .append(&query_event(source_ip, wan_ip, &sql, session_id))
                    .await;
                let mut reply = error_response("42501", "permission denied");
                reply.extend_from_slice(&READY_FOR_QUERY_IDLE);
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
            }
            // Terminate.
            b'X' => return,
            // Extended-protocol Sync ends the error state and the client waits for ReadyForQuery.
            b'S' => {
                skip_until_sync = false;
                if stream.write_all(&READY_FOR_QUERY_IDLE).await.is_err() {
                    return;
                }
            }
            // The extended protocol. A client library (psycopg, JDBC, Go's pq) sends Parse /
            // Bind / Describe / Execute / Sync rather than a simple Query, and each step expects
            // its completion message before the next; ignoring them, as this handler first did,
            // stalled such clients on Flush and never recorded their SQL. The statement text is in
            // Parse, so that is where it is recorded; Execute is refused the way the simple path
            // is, and everything after a refusal is discarded until Sync, as a real server does.
            _ if skip_until_sync => {}
            b'P' => {
                // statement name NUL, query NUL, i16 parameter-type count, ...
                let mut parts = body.split(|&b| b == 0);
                let _name = parts.next();
                let sql = String::from_utf8_lossy(parts.next().unwrap_or(&[]));
                let _ = emitter
                    .append(&query_event(source_ip, wan_ip, &sql, session_id))
                    .await;
                if stream.write_all(&PARSE_COMPLETE).await.is_err() {
                    return;
                }
            }
            b'B' => {
                if stream.write_all(&BIND_COMPLETE).await.is_err() {
                    return;
                }
            }
            b'D' => {
                if stream.write_all(&NO_DATA).await.is_err() {
                    return;
                }
            }
            b'C' => {
                if stream.write_all(&CLOSE_COMPLETE).await.is_err() {
                    return;
                }
            }
            b'E' => {
                skip_until_sync = true;
                let reply = error_response("42501", "permission denied");
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
            }
            // Flush: every reply above was written as it happened, so nothing is pending.
            b'H' => {}
            _ => {}
        }
    }
}

const PARSE_COMPLETE: [u8; 5] = [b'1', 0, 0, 0, 4];
const BIND_COMPLETE: [u8; 5] = [b'2', 0, 0, 0, 4];
const CLOSE_COMPLETE: [u8; 5] = [b'3', 0, 0, 0, 4];
const NO_DATA: [u8; 5] = [b'n', 0, 0, 0, 4];

/// Largest message accepted in the query phase; a statement is text, not a bulk transfer.
const MAX_QUERY_MSG: i32 = 65536;
/// Statements one session may send before it is closed; enough for any tool, a bound on a loop.
const MAX_QUERY_MESSAGES: usize = 200;
/// ReadyForQuery with the transaction status `I` (idle).
const READY_FOR_QUERY_IDLE: [u8; 6] = [b'Z', 0, 0, 0, 5, b'I'];
/// The ParameterStatus set a stock PostgreSQL 14 on Ubuntu 22.04 reports after AuthenticationOk.
/// A client library reads several of these before it will send anything.
const SERVER_PARAMETERS: [(&str, &str); 9] = [
    ("in_hot_standby", "off"),
    ("integer_datetimes", "on"),
    ("TimeZone", "Etc/UTC"),
    ("IntervalStyle", "postgres"),
    ("is_superuser", "off"),
    ("client_encoding", "UTF8"),
    ("server_encoding", "UTF8"),
    ("server_version", "14.13 (Ubuntu 14.13-0ubuntu0.22.04.1)"),
    ("standard_conforming_strings", "on"),
];

fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut msg = vec![b'S'];
    let len = 4 + name.len() + 1 + value.len() + 1;
    msg.extend_from_slice(&(len as i32).to_be_bytes());
    msg.extend_from_slice(name.as_bytes());
    msg.push(0);
    msg.extend_from_slice(value.as_bytes());
    msg.push(0);
    msg
}

/// BackendKeyData with a random process id and cancel key; a fixed pair would be a tell.
fn backend_key_data() -> Vec<u8> {
    let pid: u32 = 1000 + (rand::random::<u32>() % 60000);
    let key: u32 = rand::random();
    let mut msg = vec![b'K'];
    msg.extend_from_slice(&12i32.to_be_bytes());
    msg.extend_from_slice(&pid.to_be_bytes());
    msg.extend_from_slice(&key.to_be_bytes());
    msg
}

/// ErrorResponse with the fields a client displays: severity, SQLSTATE and message.
fn error_response(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut fields = Vec::new();
    for (tag, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        fields.push(tag);
        fields.extend_from_slice(value.as_bytes());
        fields.push(0);
    }
    fields.push(0);
    let mut msg = vec![b'E'];
    msg.extend_from_slice(&((4 + fields.len()) as i32).to_be_bytes());
    msg.extend_from_slice(&fields);
    msg
}

fn query_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    sql: &str,
    session_id: Uuid,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "command": sanitize_value(sql, MAX_QUERY_LEN),
        }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

/// Statement text kept in the event; a longer one is cut, the whole of it never was evidence.
const MAX_QUERY_LEN: usize = 4096;

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
