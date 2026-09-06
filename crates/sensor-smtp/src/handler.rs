use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::persona;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION,
    SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "smtp";
const MAX_LINE_LEN: usize = 8192;
const MAX_DATA_BODY: usize = 65536;
const MAX_USERNAME_LEN: usize = 255;

/// A Postfix-style short queue id (uppercase base36-ish), minted per accepted message so the DATA
/// reply reads `... queued as <ID>` like a real Postfix instead of a bare "250 OK".
fn queue_id() -> String {
    const ALPHA: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let raw: [u8; 11] = rand::random();
    raw.iter()
        .map(|b| ALPHA[*b as usize % ALPHA.len()] as char)
        .collect()
}

pub async fn handle_connection(
    stream: TcpStream,
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

    // The advertised identity comes from the shared persona so the SMTP hostname matches uname /
    // the other sensors, never the RFC2606 placeholder mail.example.com. The banner and EHLO
    // capability set impersonate a stock Ubuntu Postfix; every advertised capability has a matching
    // handler/reply below, since advertising one the server does not honor is itself a tell.
    let host = persona::hostname();
    let banner = format!("220 {host} ESMTP Postfix (Ubuntu)\r\n");
    let ehlo_reply = format!(
        "250-{host}\r\n\
         250-PIPELINING\r\n\
         250-SIZE 10240000\r\n\
         250-ETRN\r\n\
         250-STARTTLS\r\n\
         250-AUTH PLAIN LOGIN\r\n\
         250-ENHANCEDSTATUSCODES\r\n\
         250-8BITMIME\r\n\
         250-DSN\r\n\
         250-SMTPUTF8\r\n\
         250 CHUNKING\r\n"
    );
    let helo_reply = format!("250 {host}\r\n");

    let mut reader = BufReader::new(stream);
    if write_reply(&mut reader, banner.as_bytes()).await.is_err() {
        return;
    }

    let mut mail_from = String::new();
    let mut rcpt_to = Vec::new();
    let mut total_read: u64 = 0;
    // Message body accumulated across BDAT chunks until the LAST one arrives.
    let mut bdat_body = String::new();

    loop {
        let Some(line) = read_line_bounded(&mut reader, &bounds, &mut total_read).await else {
            return;
        };
        let upper = line.to_ascii_uppercase();

        if upper.starts_with("EHLO") {
            let _ = write_reply(&mut reader, ehlo_reply.as_bytes()).await;
        } else if upper.starts_with("HELO") {
            // HELO gets a single-line greeting; only EHLO returns the multiline extension list.
            let _ = write_reply(&mut reader, helo_reply.as_bytes()).await;
        } else if upper.starts_with("STARTTLS") {
            // Advertised in EHLO, so it must be answered - but this low-interaction sensor has no
            // TLS. Postfix's own "TLS temporarily unavailable" reply is realistic and needs no
            // handshake, unlike a 502 that would contradict the advertised STARTTLS capability.
            let _ = write_reply(
                &mut reader,
                b"454 4.7.0 TLS not available due to local problem\r\n",
            )
            .await;
        } else if upper.starts_with("AUTH PLAIN ") {
            // AUTH PLAIN <base64(NUL user NUL pass)> - decode username, drop password
            let encoded = line[11..].trim();
            let username = decode_auth_plain(encoded).unwrap_or_default();
            let _ = emitter
                .append(&login_event(source_ip, wan_ip, &username, session_id))
                .await;
            let _ = write_reply(&mut reader, b"235 2.7.0 Authentication successful\r\n").await;
        } else if upper.starts_with("AUTH LOGIN") {
            // AUTH LOGIN: server prompts for username then password base64
            let _ = write_reply(&mut reader, b"334 VXNlcm5hbWU6\r\n").await; // "Username:"
            let Some(user_b64) = read_line_bounded(&mut reader, &bounds, &mut total_read).await
            else {
                return;
            };
            let username = base64_decode_lossy(user_b64.trim());
            let _ = write_reply(&mut reader, b"334 UGFzc3dvcmQ6\r\n").await; // "Password:"
            let Some(_pass_b64) = read_line_bounded(&mut reader, &bounds, &mut total_read).await
            else {
                return;
            };
            // Password decoded only to advance the protocol, then dropped.
            let _ = emitter
                .append(&login_event(
                    source_ip,
                    wan_ip,
                    &sanitize_value(&username, MAX_USERNAME_LEN),
                    session_id,
                ))
                .await;
            let _ = write_reply(&mut reader, b"235 2.7.0 Authentication successful\r\n").await;
        } else if upper.starts_with("MAIL FROM:") {
            mail_from = extract_angle_bracket(&line[10..]);
            rcpt_to.clear();
            let _ = write_reply(&mut reader, b"250 2.1.0 Ok\r\n").await;
        } else if upper.starts_with("RCPT TO:") {
            rcpt_to.push(extract_angle_bracket(&line[8..]));
            let _ = write_reply(&mut reader, b"250 2.1.5 Ok\r\n").await;
        } else if upper == "DATA" {
            let _ = write_reply(&mut reader, b"354 End data with <CR><LF>.<CR><LF>\r\n").await;
            let body = read_data_body(&mut reader, &bounds, &mut total_read).await;
            let subject = extract_header(&body, "Subject");
            let msg = ReceivedMessage {
                mail_from: &mail_from,
                rcpt_to: &rcpt_to,
                subject: &subject,
                body_size: body.len(),
                chunking: false,
            };
            let _ = emitter
                .append(&data_event(source_ip, wan_ip, &msg, session_id))
                .await;
            // Postfix acknowledges an accepted message with a queue id, not a bare "250 OK".
            let reply = format!("250 2.0.0 Ok: queued as {}\r\n", queue_id());
            let _ = write_reply(&mut reader, reply.as_bytes()).await;
        } else if upper.starts_with("BDAT") {
            // CHUNKING (RFC 3030) is advertised in EHLO, so a client may send the message as
            // `BDAT <size> [LAST]` followed by exactly <size> raw octets: no dot-stuffing and no
            // terminator line. Answering 502 here contradicted the advertisement and lost every
            // message from a client that chose BDAT over DATA.
            let mut words = line.split_whitespace().skip(1);
            let size: Option<u64> = words.next().and_then(|s| s.parse().ok());
            let last = words.next().is_some_and(|w| w.eq_ignore_ascii_case("LAST"));
            match size {
                None => {
                    let _ = write_reply(
                        &mut reader,
                        b"501 5.5.4 Error: BDAT requires a chunk size\r\n",
                    )
                    .await;
                }
                Some(size) => {
                    let chunk = read_raw_chunk(&mut reader, size, &bounds, &mut total_read).await;
                    if bdat_body.len() + chunk.len() < MAX_DATA_BODY {
                        bdat_body.push_str(&chunk);
                    }
                    if last {
                        let subject = extract_header(&bdat_body, "Subject");
                        let msg = ReceivedMessage {
                            mail_from: &mail_from,
                            rcpt_to: &rcpt_to,
                            subject: &subject,
                            body_size: bdat_body.len(),
                            chunking: true,
                        };
                        let _ = emitter
                            .append(&data_event(source_ip, wan_ip, &msg, session_id))
                            .await;
                        bdat_body.clear();
                        let reply = format!("250 2.0.0 Ok: queued as {}\r\n", queue_id());
                        let _ = write_reply(&mut reader, reply.as_bytes()).await;
                    } else {
                        let reply = format!("250 2.0.0 Ok: {size} bytes\r\n");
                        let _ = write_reply(&mut reader, reply.as_bytes()).await;
                    }
                }
            }
        } else if upper.starts_with("RSET") {
            mail_from.clear();
            rcpt_to.clear();
            bdat_body.clear();
            let _ = write_reply(&mut reader, b"250 2.0.0 Ok\r\n").await;
        } else if upper.starts_with("NOOP") {
            let _ = write_reply(&mut reader, b"250 2.0.0 Ok\r\n").await;
        } else if upper.starts_with("QUIT") {
            let _ = write_reply(&mut reader, b"221 2.0.0 Bye\r\n").await;
            return;
        } else if upper.starts_with("VRFY") {
            let _ = write_reply(
                &mut reader,
                b"252 2.0.0 Cannot VRFY user, but will accept message and attempt delivery\r\n",
            )
            .await;
        } else if upper.starts_with("EXPN") {
            let _ = write_reply(&mut reader, b"502 5.5.1 Command not implemented\r\n").await;
        } else {
            let _ = write_reply(&mut reader, b"502 5.5.2 Error: command not recognized\r\n").await;
        }
    }
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

/// One received message, however it was transferred, as the event records it.
struct ReceivedMessage<'a> {
    mail_from: &'a str,
    rcpt_to: &'a [String],
    subject: &'a str,
    body_size: usize,
    /// Delivered with BDAT (CHUNKING) rather than DATA.
    chunking: bool,
}

fn data_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    msg: &ReceivedMessage<'_>,
    session_id: Uuid,
) -> SensorEvent {
    let ReceivedMessage {
        mail_from,
        rcpt_to,
        subject,
        body_size,
        chunking,
    } = *msg;
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        // `command` stays "DATA" for a message delivered by BDAT too: it is the same "a message
        // body was received" observation for everything downstream; `chunking` says which
        // transfer the client chose.
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "command": "DATA",
            "mail_from": sanitize_value(mail_from, 255),
            "rcpt_to": rcpt_to.iter().map(|r| sanitize_value(r, 255)).collect::<Vec<_>>(),
            "subject": sanitize_value(subject, 512),
            "body_size": body_size,
            "chunking": chunking,
        }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

fn extract_angle_bracket(s: &str) -> String {
    let trimmed = s.trim();
    if let (Some(start), Some(end)) = (trimmed.find('<'), trimmed.find('>'))
        && start < end
    {
        return trimmed[start + 1..end].to_string();
    }
    trimmed.to_string()
}

/// Decode AUTH PLAIN: base64 of `\0username\0password`. Returns the username; password is dropped.
fn decode_auth_plain(encoded: &str) -> Option<String> {
    let decoded = base64_decode_bytes(encoded)?;
    // Format: \0user\0pass - split on NUL bytes
    let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
    if parts.len() >= 2 {
        Some(String::from_utf8_lossy(parts[1]).into_owned())
    } else {
        None
    }
}

fn base64_decode_lossy(encoded: &str) -> String {
    base64_decode_bytes(encoded)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn base64_decode_bytes(encoded: &str) -> Option<Vec<u8>> {
    let clean: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let mut result = Vec::new();
    let chars: Vec<u8> = clean.bytes().collect();
    for chunk in chars.chunks(4) {
        let mut buf = [0u8; 4];
        let mut count = 0;
        for &b in chunk {
            if b == b'=' {
                break;
            }
            buf[count] = b64_val(b)?;
            count += 1;
        }
        if count >= 2 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if count >= 3 {
            result.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if count >= 4 {
            result.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(result)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn extract_header(body: &str, name: &str) -> String {
    for line in body.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case(name)
        {
            return value.trim().to_string();
        }
    }
    String::new()
}

async fn write_reply(reader: &mut BufReader<TcpStream>, data: &[u8]) -> Result<(), ()> {
    reader.get_mut().write_all(data).await.map_err(|_| ())
}

async fn read_line_bounded(
    reader: &mut BufReader<TcpStream>,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Option<String> {
    if *total >= bounds.max_captured_bytes {
        return None;
    }
    let timeout = if *total == 0 {
        bounds.read_timeout
    } else {
        bounds.idle_timeout
    };
    // Bound the bytes buffered for ONE line: a client that never sends a newline would otherwise
    // make `read_line` grow the buffer to the whole line before any cap applied (unbounded
    // allocation -> OOM). Read through a `take` limited to MAX_LINE_LEN and never past the remaining
    // capture budget, so an over-long line is chopped, not buffered whole. Decoding the bounded byte
    // buffer with `from_utf8_lossy` also removes the old `String::truncate` char-boundary panic on a
    // multibyte character straddling the limit.
    let remaining = bounds.max_captured_bytes.saturating_sub(*total);
    let cap = (MAX_LINE_LEN as u64).min(remaining).max(1);
    let mut buf = Vec::new();
    let mut limited = (&mut *reader).take(cap);
    match tokio::time::timeout(timeout, limited.read_until(b'\n', &mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
        Ok(Ok(n)) => {
            *total += n as u64;
            Some(
                String::from_utf8_lossy(&buf)
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            )
        }
    }
}

/// Read exactly `size` raw octets of a BDAT chunk, never more than the session's remaining
/// capture budget. A chunk larger than the budget is cut at the budget; the unread remainder then
/// reads as garbage commands and the budget check ends the session, the same end an oversized
/// DATA body meets.
async fn read_raw_chunk(
    reader: &mut BufReader<TcpStream>,
    size: u64,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> String {
    let remaining = bounds.max_captured_bytes.saturating_sub(*total);
    let want = size.min(remaining) as usize;
    if want == 0 {
        return String::new();
    }
    let mut buf = vec![0u8; want];
    match tokio::time::timeout(bounds.idle_timeout, reader.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            *total += want as u64;
            String::from_utf8_lossy(&buf).into_owned()
        }
        _ => {
            *total = bounds.max_captured_bytes;
            String::new()
        }
    }
}

async fn read_data_body(
    reader: &mut BufReader<TcpStream>,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> String {
    let mut body = String::new();
    loop {
        let Some(line) = read_line_bounded(reader, bounds, total).await else {
            break;
        };
        if line == "." {
            break;
        }
        // Dot-stuffing: a line starting with "." has the leading dot removed
        let actual = line.strip_prefix('.').unwrap_or(&line);
        if body.len() + actual.len() < MAX_DATA_BODY {
            body.push_str(actual);
            body.push('\n');
        }
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_fields() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7());
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "smtp");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
    }

    #[test]
    fn login_event_fields() {
        let event = login_event(
            "203.0.113.7".parse().unwrap(),
            None,
            "admin",
            Uuid::now_v7(),
        );
        assert!(event.authenticated);
        assert_eq!(
            event.metadata.get("username").and_then(|v| v.as_str()),
            Some("admin")
        );
        assert!(event.metadata.get("password").is_none());
    }

    #[test]
    fn extract_angle_bracket_works() {
        assert_eq!(
            extract_angle_bracket("<user@example.com>"),
            "user@example.com"
        );
        assert_eq!(extract_angle_bracket("  <a@b>  "), "a@b");
        assert_eq!(extract_angle_bracket("plain"), "plain");
    }

    #[test]
    fn decode_auth_plain_extracts_username() {
        // base64 of "\0admin\0secret"
        let encoded = "AGFkbWluAHNlY3JldA==";
        assert_eq!(decode_auth_plain(encoded), Some("admin".to_string()));
    }

    #[test]
    fn base64_decode_lossy_works() {
        // "admin" -> "YWRtaW4="
        assert_eq!(base64_decode_lossy("YWRtaW4="), "admin");
        assert_eq!(base64_decode_lossy(""), "");
    }

    #[test]
    fn extract_header_finds_subject() {
        let body = "From: a@b\r\nSubject: Test Subject\r\nTo: c@d\r\n\r\nBody here";
        assert_eq!(extract_header(body, "Subject"), "Test Subject");
        assert_eq!(extract_header(body, "Missing"), "");
    }
}
