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

const PROTOCOL_LABEL: &str = "mongodb";
const MAX_MSG_SIZE: usize = 65536;

// MongoDB wire protocol opcodes
const OP_MSG: u32 = 2013;

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

    // Read messages until we see an authenticate command or the connection drops
    loop {
        let Some(msg) = read_mongo_msg(&mut stream, timeout).await else {
            return;
        };

        // Check if this is an OP_MSG (opcode 2013)
        if msg.opcode != OP_MSG {
            // Send a generic error for legacy opcodes
            let _ = send_op_msg_reply(
                &mut stream,
                msg.request_id,
                r#"{"ok":0,"errmsg":"unsupported"}"#,
            )
            .await;
            continue;
        }

        // OP_MSG body: flagBits(4) + sections
        // Section kind 0: body BSON document
        if msg.body.len() < 5 {
            return;
        }

        // Try to extract command name and username from the BSON-ish payload
        let payload_str = String::from_utf8_lossy(&msg.body[4..]);

        if payload_str.contains("isMaster")
            || payload_str.contains("ismaster")
            || payload_str.contains("hello")
        {
            let _ = send_op_msg_reply(
                &mut stream,
                msg.request_id,
                r#"{"ismaster":true,"maxBsonObjectSize":16777216,"maxMessageSizeBytes":48000000,"maxWriteBatchSize":100000,"ok":1}"#,
            ).await;
        } else if payload_str.contains("saslStart") || payload_str.contains("authenticate") {
            // Extract username from SCRAM-SHA payload or authenticate command
            let username = extract_scram_username(&msg.body[4..])
                .or_else(|| extract_bson_string(&msg.body[4..], "user"));
            let username = sanitize_value(&username.unwrap_or_default(), 255);

            let _ = emitter
                .append(&login_event(source_ip, wan_ip, &username, session_id))
                .await;

            // Send a saslContinue-style response (the auth will fail, but we got the credential)
            let _ = send_op_msg_reply(
                &mut stream,
                msg.request_id,
                r#"{"ok":1,"conversationId":1,"done":false,"payload":{"$binary":{"base64":"","subType":"0"}}}"#,
            ).await;
            return;
        } else {
            let _ = send_op_msg_reply(&mut stream, msg.request_id, r#"{"ok":1}"#).await;
        }
    }
}

struct MongoMsg {
    request_id: i32,
    opcode: u32,
    body: Vec<u8>,
}

async fn read_mongo_msg(stream: &mut TcpStream, timeout: std::time::Duration) -> Option<MongoMsg> {
    // Standard header: messageLength(4) + requestID(4) + responseTo(4) + opCode(4)
    let mut header = [0u8; 16];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;

    let msg_length = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let request_id = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let opcode = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);

    if !(16..=MAX_MSG_SIZE).contains(&msg_length) {
        return None;
    }

    let body_len = msg_length - 16;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        tokio::time::timeout(timeout, stream.read_exact(&mut body))
            .await
            .ok()?
            .ok()?;
    }

    Some(MongoMsg {
        request_id,
        opcode,
        body,
    })
}

async fn send_op_msg_reply(stream: &mut TcpStream, request_id: i32, json: &str) -> Result<(), ()> {
    // Build a minimal BSON document from JSON-ish content
    // For simplicity, we'll build a raw BSON document with just enough to look right
    let bson_doc = build_minimal_bson(json);

    // OP_MSG: flagBits(4) + section kind 0 (1 byte) + BSON body
    let mut op_msg_body = Vec::new();
    op_msg_body.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    op_msg_body.push(0); // section kind 0 (body)
    op_msg_body.extend_from_slice(&bson_doc);

    let msg_length = (16 + op_msg_body.len()) as i32;
    let mut packet = Vec::with_capacity(msg_length as usize);
    packet.extend_from_slice(&msg_length.to_le_bytes());
    packet.extend_from_slice(&1i32.to_le_bytes()); // our requestID
    packet.extend_from_slice(&request_id.to_le_bytes()); // responseTo
    packet.extend_from_slice(&OP_MSG.to_le_bytes());
    packet.extend_from_slice(&op_msg_body);

    stream.write_all(&packet).await.map_err(|_| ())
}

/// Build a minimal valid BSON document from a flat key-value shape. This is deliberately simple -
/// a honeypot response only needs to parse in MongoDB drivers, not represent arbitrary data.
fn build_minimal_bson(json: &str) -> Vec<u8> {
    // For the honeypot's canned responses we embed the JSON as a raw string.
    // Real BSON encoding would be needed for a full implementation, but for a credential-capture
    // honeypot that sends only ~3 different canned responses, we use pre-built BSON.

    // Use a minimal approach: build BSON with just {"ok": 1} or similar
    let mut doc = Vec::new();
    let placeholder_len = 4; // will be overwritten
    doc.extend_from_slice(&[0u8; 4]); // document length placeholder

    if json.contains("\"ismaster\":true") || json.contains("\"ok\":1") {
        // BSON double type (0x01) for "ok" = 1.0
        doc.push(0x01); // type: double
        doc.extend_from_slice(b"ok\0");
        doc.extend_from_slice(&1.0f64.to_le_bytes());

        if json.contains("ismaster") {
            doc.push(0x08); // type: boolean
            doc.extend_from_slice(b"ismaster\0");
            doc.push(0x01); // true

            doc.push(0x10); // type: int32
            doc.extend_from_slice(b"maxBsonObjectSize\0");
            doc.extend_from_slice(&16777216i32.to_le_bytes());

            doc.push(0x10);
            doc.extend_from_slice(b"maxMessageSizeBytes\0");
            doc.extend_from_slice(&48000000i32.to_le_bytes());
        }

        if json.contains("conversationId") {
            doc.push(0x10); // int32
            doc.extend_from_slice(b"conversationId\0");
            doc.extend_from_slice(&1i32.to_le_bytes());

            doc.push(0x08); // boolean
            doc.extend_from_slice(b"done\0");
            doc.push(0x00); // false
        }
    } else {
        // error response
        doc.push(0x01);
        doc.extend_from_slice(b"ok\0");
        doc.extend_from_slice(&0.0f64.to_le_bytes());
    }

    doc.push(0x00); // document terminator

    let total_len = doc.len() as i32;
    doc[..placeholder_len].copy_from_slice(&total_len.to_le_bytes());
    doc
}

/// Extract username from a SCRAM-SHA-1/256 saslStart payload. The client's first message contains
/// `n,,n=<username>,r=<nonce>` base64-encoded in the BSON payload field.
fn extract_scram_username(data: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(data);
    // Look for the SCRAM pattern in the binary data
    // The username appears as n=<user>, in the saslStart payload
    if let Some(pos) = s.find("n=") {
        let after = &s[pos + 2..];
        let end = after.find(',').unwrap_or(after.len());
        let user = &after[..end];
        if !user.is_empty() && !user.contains('\0') {
            return Some(user.to_string());
        }
    }
    None
}

/// Extract a string value for a given key from BSON-ish binary data. This is a best-effort
/// search, not a full BSON parser - sufficient for extracting "user" from authenticate commands.
fn extract_bson_string(data: &[u8], key: &str) -> Option<String> {
    let key_with_nul = format!("{key}\0");
    let key_bytes = key_with_nul.as_bytes();

    for (i, window) in data.windows(key_bytes.len()).enumerate() {
        if window == key_bytes {
            // Check if preceded by type 0x02 (string)
            if i > 0 && data[i - 1] == 0x02 {
                let value_start = i + key_bytes.len();
                if value_start + 4 <= data.len() {
                    let str_len = i32::from_le_bytes([
                        data[value_start],
                        data[value_start + 1],
                        data[value_start + 2],
                        data[value_start + 3],
                    ]) as usize;
                    let str_start = value_start + 4;
                    if str_len > 0 && str_start + str_len <= data.len() {
                        let s = String::from_utf8_lossy(&data[str_start..str_start + str_len - 1]);
                        return Some(s.into_owned());
                    }
                }
            }
        }
    }
    None
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
    fn extract_scram_username_from_payload() {
        assert_eq!(
            extract_scram_username(b"n,,n=admin,r=some_nonce_value"),
            Some("admin".to_string())
        );
    }

    #[test]
    fn extract_scram_username_returns_none_on_garbage() {
        assert_eq!(extract_scram_username(b"garbage"), None);
    }

    #[test]
    fn build_minimal_bson_produces_valid_length() {
        let doc = build_minimal_bson(r#"{"ok":1}"#);
        let declared_len = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
        assert_eq!(declared_len, doc.len());
        assert_eq!(*doc.last().unwrap(), 0x00); // terminator
    }
}
