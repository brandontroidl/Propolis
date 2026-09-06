use std::collections::HashMap;
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
    // Parameter types per prepared statement, so Describe can answer for the statement the
    // client actually parsed.
    let mut statements: HashMap<Vec<u8>, Vec<u32>> = HashMap::new();
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
            // Terminate.
            b'X' => return,
            // Extended-protocol Sync ends the error state and the client waits for ReadyForQuery.
            b'S' => {
                skip_until_sync = false;
                if stream.write_all(&READY_FOR_QUERY_IDLE).await.is_err() {
                    return;
                }
            }
            // After a refused Execute a real server discards everything, a simple Query
            // included, until Sync; this guard therefore sits ahead of every other arm.
            _ if skip_until_sync => {}
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
            // The extended protocol. A client library (psycopg, JDBC, Go's pq) sends Parse /
            // Bind / Describe / Execute / Sync rather than a simple Query, and each step expects
            // its completion message before the next; ignoring them, as this handler first did,
            // stalled such clients on Flush and never recorded their SQL. The statement text is in
            // Parse, so that is where it is recorded; Execute is refused the way the simple path
            // is, and everything after a refusal is discarded until Sync, as a real server does.
            b'P' => {
                // statement name NUL, query NUL, i16 parameter-type count, i32 OIDs...
                let mut parts = body.split(|&b| b == 0);
                let name = parts.next().unwrap_or(&[]).to_vec();
                let sql_bytes = parts.next().unwrap_or(&[]);
                let sql = String::from_utf8_lossy(sql_bytes);
                let types_at = name.len() + 1 + sql_bytes.len() + 1;
                let params = parameter_types(&sql, body.get(types_at..).unwrap_or(&[]));
                if statements.len() >= MAX_STATEMENTS {
                    statements.clear();
                }
                statements.insert(name, params);
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
            // Describe: a statement ('S') is answered with its parameter list before the row
            // description; a portal ('P') with the row description alone. A client that
            // described a statement and got only NoData had a malformed exchange, and one whose
            // `SELECT $1::integer` came back as zero parameters was told its own placeholders
            // do not exist.
            b'D' => {
                let mut reply = Vec::new();
                if body.first() == Some(&b'S') {
                    let name = body.get(1..).unwrap_or(&[]);
                    let name = name.strip_suffix(&[0]).unwrap_or(name);
                    let params = statements.get(name).cloned().unwrap_or_default();
                    reply.extend_from_slice(&parameter_description(&params));
                }
                reply.extend_from_slice(&NO_DATA);
                if stream.write_all(&reply).await.is_err() {
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
/// Prepared statements one session may hold; the map is cleared past this, as a bound.
const MAX_STATEMENTS: usize = 64;
/// Placeholders one statement may declare; a real server allows 65535.
const MAX_PARAMETERS: usize = 256;

/// ParameterDescription: i16 count then one i32 type OID per parameter.
fn parameter_description(oids: &[u32]) -> Vec<u8> {
    let mut msg = vec![b't'];
    msg.extend_from_slice(&((4 + 2 + 4 * oids.len()) as i32).to_be_bytes());
    msg.extend_from_slice(&(oids.len() as i16).to_be_bytes());
    for oid in oids {
        msg.extend_from_slice(&oid.to_be_bytes());
    }
    msg
}

/// The parameter types a statement resolves to. Parse may declare them; an undeclared (OID 0)
/// or undeclared-by-count placeholder is resolved from an explicit `$n::type` cast in the SQL,
/// else to `text`, the type a real server gives an otherwise unconstrained literal. A real
/// server infers from column types too; this box has no columns, so `text` is its answer.
fn parameter_types(sql: &str, declared: &[u8]) -> Vec<u32> {
    let count = declared
        .get(..2)
        .map(|b| i16::from_be_bytes([b[0], b[1]]).max(0) as usize)
        .unwrap_or(0);
    let mut oids: Vec<u32> = (0..count)
        .map(|i| {
            declared
                .get(2 + 4 * i..6 + 4 * i)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0)
        })
        .collect();
    let placeholders = placeholder_count(sql).min(MAX_PARAMETERS);
    if oids.len() < placeholders {
        oids.resize(placeholders, 0);
    }
    oids.truncate(MAX_PARAMETERS);
    for (i, oid) in oids.iter_mut().enumerate() {
        if *oid == 0 {
            *oid = cast_type(sql, i + 1).unwrap_or(OID_TEXT);
        }
    }
    oids
}

const OID_TEXT: u32 = 25;

/// The highest `$n` in the statement.
fn placeholder_count(sql: &str) -> usize {
    let mut max = 0usize;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && end - start < 5 && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start
                && let Ok(n) = sql[start..end].parse::<usize>()
            {
                max = max.max(n);
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
    max
}

/// The type OID of an explicit `$n::type` cast in the statement, for the common names.
fn cast_type(sql: &str, n: usize) -> Option<u32> {
    let marker = format!("${n}::");
    let rest = &sql[sql.find(&marker)? + marker.len()..];
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_lowercase();
    Some(match name.as_str() {
        "bool" | "boolean" => 16,
        "bytea" => 17,
        "int8" | "bigint" => 20,
        "int2" | "smallint" => 21,
        "int4" | "int" | "integer" => 23,
        "text" => OID_TEXT,
        "oid" => 26,
        "json" => 114,
        "float4" | "real" => 700,
        "float8" | "double" => 701,
        "inet" => 869,
        "varchar" => 1043,
        "date" => 1082,
        "timestamp" => 1114,
        "timestamptz" => 1184,
        "numeric" | "decimal" => 1700,
        "uuid" => 2950,
        "jsonb" => 3802,
        _ => return None,
    })
}

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
    fn parameter_types_come_from_declaration_cast_or_default_to_text() {
        // Declared int4 for $1, nothing for $2: $2 is resolved from its cast.
        let mut declared = 1i16.to_be_bytes().to_vec();
        declared.extend_from_slice(&23u32.to_be_bytes());
        assert_eq!(
            parameter_types("SELECT $1, $2::bigint", &declared),
            vec![23, 20]
        );
        // Undeclared and uncast: text.
        assert_eq!(parameter_types("SELECT $1", &[]), vec![25]);
        // Declared as unspecified (0) with a cast: the cast wins.
        let mut unspecified = 1i16.to_be_bytes().to_vec();
        unspecified.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            parameter_types("SELECT $1::integer", &unspecified),
            vec![23]
        );
        assert_eq!(parameter_types("SELECT 1", &[]), Vec::<u32>::new());
        let msg = parameter_description(&[23, 20]);
        assert_eq!(&msg[..7], &[b't', 0, 0, 0, 14, 0, 2]);
        assert_eq!(&msg[7..11], &23u32.to_be_bytes());
    }

    #[test]
    fn parse_startup_params_empty() {
        assert_eq!(parse_startup_params(&[], "user"), "");
        assert_eq!(parse_startup_params(&[0], "user"), "");
    }
}
