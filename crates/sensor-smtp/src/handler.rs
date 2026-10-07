use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::persona;
use sensor_framework::sanitize_value;
use sensor_framework::{
    ConnectionBounds, EventEmitter, MaybeTlsStream, TlsServer, Uuid, WanResolver, upgrade_buffered,
};
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

/// Serves one SMTP session. `stream` is `Tls` for an implicit-TLS (465) connection and `Plain`
/// otherwise; `tls` is `Some` iff a certificate is configured, which is what lets STARTTLS upgrade
/// a plain session instead of getting the `454` reply.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connection(
    stream: MaybeTlsStream,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    tls: Option<TlsServer>,
) {
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = local_addr
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let _ = emitter
        .append(&connection_event(
            source_ip,
            wan_ip,
            session_id,
            stream.is_tls(),
        ))
        .await;

    // The advertised identity comes from the shared persona so the SMTP hostname matches uname /
    // the other sensors, never the RFC2606 placeholder mail.example.com. The banner and EHLO
    // capability set impersonate a stock Ubuntu Postfix; every advertised capability has a matching
    // handler/reply below, since advertising one the server does not honor is itself a tell.
    let host = persona::hostname();
    let banner = format!("220 {host} ESMTP Postfix (Ubuntu)\r\n");
    let helo_reply = format!("250 {host}\r\n");

    let mut reader = BufReader::new(stream);
    if write_reply(&mut reader, banner.as_bytes()).await.is_err() {
        return;
    }

    let mut mail_from = String::new();
    let mut rcpt_to = Vec::new();
    let mut total_read: u64 = 0;
    // Message body accumulated across BDAT chunks until the LAST one arrives, and the bytes the
    // client sent for it (the body stops growing at MAX_DATA_BODY; the count does not).
    let mut bdat_body: Vec<u8> = Vec::new();
    let mut bdat_received: usize = 0;

    loop {
        let Some(line) = read_line_bounded(&mut reader, &bounds, &mut total_read).await else {
            return;
        };
        let upper = line.to_ascii_uppercase();

        if upper.starts_with("EHLO") {
            // Postfix never offers STARTTLS on a session that already has TLS. On a plain session it
            // is offered even with no certificate configured (the 454 below answers it), so every
            // advertised capability still has a matching reply.
            let reply = ehlo_reply(&host, !reader.get_ref().is_tls());
            let _ = write_reply(&mut reader, reply.as_bytes()).await;
        } else if upper.starts_with("HELO") {
            // HELO gets a single-line greeting; only EHLO returns the multiline extension list.
            let _ = write_reply(&mut reader, helo_reply.as_bytes()).await;
        } else if upper.starts_with("STARTTLS") {
            if reader.get_ref().is_tls() {
                let _ = write_reply(&mut reader, b"503 5.5.1 Error: TLS already active\r\n").await;
            } else if upper.trim_end() != "STARTTLS" && tls.is_some() {
                // RFC 3207 section 4: the STARTTLS verb takes no parameters. Only with TLS
                // configured; without it the unchanged 454 below answers every STARTTLS line.
                let _ = write_reply(
                    &mut reader,
                    b"501 5.5.4 Syntax error (no parameters allowed)\r\n",
                )
                .await;
            } else if let Some(tls) = tls.as_ref() {
                // CVE-2011-0411 shape: bytes the client pipelined behind STARTTLS were sent in
                // plaintext and must never be read as commands inside the TLS session. Refuse
                // before the 220 so the client never believes a handshake is coming, and record
                // the attempt.
                let pipelined = reader.buffer().len();
                if pipelined > 0 {
                    let _ = emitter
                        .append(&starttls_refused_event(
                            source_ip, wan_ip, session_id, pipelined,
                        ))
                        .await;
                    let _ = write_reply(
                        &mut reader,
                        b"554 5.5.1 Error: command pipelining after STARTTLS\r\n",
                    )
                    .await;
                    let _ = reader.get_mut().shutdown().await;
                    return;
                }
                if write_reply(&mut reader, b"220 2.0.0 Ready to start TLS\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                // The only upgrade path: upgrade_buffered re-checks for buffered plaintext and
                // builds a fresh BufReader. Any failure ends the session; there is no plaintext
                // fallback after the 220.
                let Ok(upgraded) = upgrade_buffered(reader, tls, bounds.read_timeout).await else {
                    return;
                };
                reader = upgraded;
                // RFC 3207 section 4.2: the server discards what it learned before the upgrade and
                // the client must EHLO again. `total_read` is deliberately kept: the capture cap is
                // per connection.
                mail_from.clear();
                rcpt_to.clear();
                bdat_body.clear();
                bdat_received = 0;
            } else {
                // No cert/key configured: Postfix's own "TLS temporarily unavailable" reply needs
                // no handshake and does not contradict the advertised STARTTLS capability.
                let _ = write_reply(
                    &mut reader,
                    b"454 4.7.0 TLS not available due to local problem\r\n",
                )
                .await;
            }
        } else if upper.starts_with("AUTH PLAIN ") {
            // AUTH PLAIN <base64(NUL user NUL pass)> - decode username, drop password
            let encoded = line[11..].trim();
            let username = decode_auth_plain(encoded).unwrap_or_default();
            let _ = emitter
                .append(&login_event(
                    source_ip,
                    wan_ip,
                    &username,
                    session_id,
                    reader.get_ref().is_tls(),
                ))
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
                    reader.get_ref().is_tls(),
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
            // No terminating `.` line means no message: the session ends without a "queued".
            let Some((body, received)) =
                read_data_body(&mut reader, &bounds, &mut total_read).await
            else {
                return;
            };
            let text = String::from_utf8_lossy(&body);
            let subject = extract_header(&text, "Subject");
            let msg = ReceivedMessage {
                mail_from: &mail_from,
                rcpt_to: &rcpt_to,
                subject: &subject,
                body_size: received,
                truncated: received > body.len(),
                chunking: false,
                tls: reader.get_ref().is_tls(),
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
                    // A chunk that never fully arrived is neither acknowledged nor recorded:
                    // the client hung up mid-transfer, and the session ends as a real one would.
                    let Some(chunk) =
                        read_raw_chunk(&mut reader, size, &bounds, &mut total_read).await
                    else {
                        return;
                    };
                    bdat_received += chunk.len();
                    append_bounded(&mut bdat_body, &chunk);
                    if last {
                        let text = String::from_utf8_lossy(&bdat_body);
                        let subject = extract_header(&text, "Subject");
                        let msg = ReceivedMessage {
                            mail_from: &mail_from,
                            rcpt_to: &rcpt_to,
                            subject: &subject,
                            body_size: bdat_received,
                            truncated: bdat_received > bdat_body.len(),
                            chunking: true,
                            tls: reader.get_ref().is_tls(),
                        };
                        let _ = emitter
                            .append(&data_event(source_ip, wan_ip, &msg, session_id))
                            .await;
                        bdat_body.clear();
                        bdat_received = 0;
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
            bdat_received = 0;
            let _ = write_reply(&mut reader, b"250 2.0.0 Ok\r\n").await;
        } else if upper.starts_with("NOOP") {
            let _ = write_reply(&mut reader, b"250 2.0.0 Ok\r\n").await;
        } else if upper.starts_with("QUIT") {
            let _ = write_reply(&mut reader, b"221 2.0.0 Bye\r\n").await;
            // On a TLS session this sends close_notify instead of a bare TCP close.
            let _ = reader.get_mut().shutdown().await;
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

fn ehlo_reply(host: &str, offer_starttls: bool) -> String {
    let starttls = if offer_starttls {
        "250-STARTTLS\r\n"
    } else {
        ""
    };
    format!(
        "250-{host}\r\n\
         250-PIPELINING\r\n\
         250-SIZE 10240000\r\n\
         250-ETRN\r\n\
         {starttls}\
         250-AUTH PLAIN LOGIN\r\n\
         250-ENHANCEDSTATUSCODES\r\n\
         250-8BITMIME\r\n\
         250-DSN\r\n\
         250-SMTPUTF8\r\n\
         250 CHUNKING\r\n"
    )
}

/// Adds `"tls": true` to event metadata. The key is absent on plaintext events, so a consumer
/// reads "has the key" as "was TLS" and existing plaintext events are unchanged.
fn tag_tls(metadata: &mut serde_json::Value, tls: bool) {
    if tls && let Some(map) = metadata.as_object_mut() {
        map.insert("tls".to_string(), serde_json::Value::Bool(true));
    }
}

fn connection_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    tls: bool,
) -> SensorEvent {
    let mut metadata = serde_json::json!({ "protocol_label": PROTOCOL_LABEL });
    tag_tls(&mut metadata, tls);
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata,
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
    tls: bool,
) -> SensorEvent {
    let mut metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "username": username,
    });
    tag_tls(&mut metadata, tls);
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata,
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
    /// Bytes the client sent as the body, whether or not all of it was kept.
    body_size: usize,
    /// The kept body is shorter than `body_size`: the message ran past `MAX_DATA_BODY`.
    truncated: bool,
    /// Delivered with BDAT (CHUNKING) rather than DATA.
    chunking: bool,
    /// The session was TLS when the message arrived.
    tls: bool,
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
        truncated,
        chunking,
        tls,
    } = *msg;
    // `command` stays "DATA" for a message delivered by BDAT too: it is the same "a message
    // body was received" observation for everything downstream; `chunking` says which
    // transfer the client chose.
    let mut metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "command": "DATA",
        "mail_from": sanitize_value(mail_from, 255),
        "rcpt_to": rcpt_to.iter().map(|r| sanitize_value(r, 255)).collect::<Vec<_>>(),
        "subject": sanitize_value(subject, 512),
        "body_size": body_size,
        "truncated": truncated,
        "chunking": chunking,
    });
    tag_tls(&mut metadata, tls);
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata,
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

/// A STARTTLS that arrived with plaintext already buffered behind it. The pipelined bytes are
/// counted, not captured: they are the injection payload and are never interpreted.
fn starttls_refused_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    pipelined_bytes: usize,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "command": "STARTTLS",
            "starttls_refused": "pipelined_plaintext",
            "pipelined_bytes": pipelined_bytes,
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

async fn write_reply<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    data: &[u8],
) -> Result<(), ()> {
    let inner = reader.get_mut();
    inner.write_all(data).await.map_err(|_| ())?;
    // tokio-rustls can leave a written record unsent until flushed; a no-op on plain TCP.
    inner.flush().await.map_err(|_| ())
}

async fn read_line_bounded<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
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

/// `read_line_bounded` for the message body: the raw line bytes with the terminator stripped,
/// and whether a terminator was actually seen. Decoding per line would count a replacement
/// character's three bytes where the wire carried one, and the body's own decoding happens once
/// over the whole message.
async fn read_body_line<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Option<Vec<u8>> {
    if *total >= bounds.max_captured_bytes {
        return None;
    }
    let remaining = bounds.max_captured_bytes.saturating_sub(*total);
    let cap = (MAX_LINE_LEN as u64).min(remaining).max(1);
    let mut buf = Vec::new();
    let mut limited = (&mut *reader).take(cap);
    match tokio::time::timeout(bounds.idle_timeout, limited.read_until(b'\n', &mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
        Ok(Ok(n)) => {
            *total += n as u64;
            if buf.last() != Some(&b'\n') {
                // Cut by the cap or the budget, not a line the client finished.
                return None;
            }
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            Some(buf)
        }
    }
}

/// Read exactly the `size` raw octets of a BDAT chunk. `Some` only when the whole declared chunk
/// arrived: a client that declared more than the session's remaining capture budget, hung up,
/// or went quiet past the idle timeout has not delivered the chunk, and `None` ends the session
/// without an acknowledgement. Reading what fit in the budget and calling that the chunk was
/// how a 512-byte declaration became a "queued" 156-byte message. A declared size of zero is a
/// valid, complete, empty chunk (RFC 3030 allows `BDAT 0 LAST`), not exhausted capacity.
async fn read_raw_chunk<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    size: u64,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Option<Vec<u8>> {
    let remaining = bounds.max_captured_bytes.saturating_sub(*total);
    if size > remaining {
        *total = bounds.max_captured_bytes;
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    match tokio::time::timeout(bounds.idle_timeout, reader.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            *total += size;
            Some(buf)
        }
        _ => {
            *total = bounds.max_captured_bytes;
            None
        }
    }
}

/// Append `bytes` to `body` up to `MAX_DATA_BODY` bytes. The body is kept as bytes and decoded
/// once, at the end, so a multibyte character split across two BDAT chunks or cut by the cap
/// is decoded from the whole, never from each fragment.
fn append_bounded(body: &mut Vec<u8>, bytes: &[u8]) {
    let room = MAX_DATA_BODY.saturating_sub(body.len());
    body.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

/// The message body up to `MAX_DATA_BODY` bytes, and the number of body bytes the client sent,
/// which keeps counting after the body stops growing so the event can say the body was cut.
/// `None` when the client never sent the terminating `.` line (it hung up, went quiet, or ran
/// out of budget): that is an unfinished transfer, not a message, and it gets no "queued".
async fn read_data_body<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Option<(Vec<u8>, usize)> {
    let mut body = Vec::new();
    let mut received = 0usize;
    loop {
        let line = read_body_line(reader, bounds, total).await?;
        if line == b"." {
            return Some((body, received));
        }
        // Dot-stuffing: a line starting with "." has the leading dot removed
        let actual = line.strip_prefix(b".").unwrap_or(&line);
        received += actual.len() + 1;
        append_bounded(&mut body, actual);
        append_bounded(&mut body, b"\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_fields() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7(), false);
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "smtp");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert!(event.metadata.get("tls").is_none());
    }

    #[test]
    fn login_event_fields() {
        let event = login_event(
            "203.0.113.7".parse().unwrap(),
            None,
            "admin",
            Uuid::now_v7(),
            false,
        );
        assert!(event.authenticated);
        assert_eq!(
            event.metadata.get("username").and_then(|v| v.as_str()),
            Some("admin")
        );
        assert!(event.metadata.get("password").is_none());
        assert!(event.metadata.get("tls").is_none());
    }

    fn message(tls: bool) -> ReceivedMessage<'static> {
        ReceivedMessage {
            mail_from: "a@b.test",
            rcpt_to: &[],
            subject: "s",
            body_size: 1,
            truncated: false,
            chunking: false,
            tls,
        }
    }

    #[test]
    fn tls_tag_is_present_only_when_true() {
        let ip = "203.0.113.7".parse().unwrap();
        let id = Uuid::now_v7();
        for tls in [true, false] {
            let events = [
                connection_event(ip, None, id, tls),
                login_event(ip, None, "u", id, tls),
                data_event(ip, None, &message(tls), id),
            ];
            for event in events {
                if tls {
                    assert_eq!(event.metadata.get("tls"), Some(&serde_json::json!(true)));
                } else {
                    assert!(event.metadata.get("tls").is_none(), "{:?}", event.metadata);
                }
            }
        }
    }

    #[test]
    fn starttls_refused_event_records_the_count_and_never_the_bytes() {
        let event =
            starttls_refused_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7(), 31);
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(event.metadata["command"], "STARTTLS");
        assert_eq!(event.metadata["starttls_refused"], "pipelined_plaintext");
        assert_eq!(event.metadata["pipelined_bytes"], 31);
        assert!(event.metadata.get("tls").is_none());
        assert!(event.sample.is_none());
    }

    #[test]
    fn ehlo_reply_offers_starttls_only_when_asked() {
        let with = ehlo_reply("h", true);
        let without = ehlo_reply("h", false);
        assert!(with.contains("250-STARTTLS\r\n"));
        assert!(!without.contains("STARTTLS"));
        for reply in [&with, &without] {
            assert!(reply.starts_with("250-h\r\n"));
            assert!(reply.contains("250-AUTH PLAIN LOGIN\r\n"));
            assert!(reply.ends_with("250 CHUNKING\r\n"));
        }
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
