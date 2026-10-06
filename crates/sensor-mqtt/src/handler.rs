//! Per-connection MQTT session handler: a metadata-only recon trap for TCP/1883.
//!
//! It records who connects (CONNECT credentials, client id, will topic), what they subscribe to,
//! and what they publish (topic plus bounded payload metadata), and answers just enough of MQTT
//! 3.1/3.1.1 that a scanner or client library carries on and reveals intent. It serves nothing:
//! a PUBLISH is never delivered to any subscriber, retained, or forwarded; there is no broker
//! state; no outbound socket is ever opened; nothing is executed. The CONNECT password is read
//! only to advance the parser and is dropped, never stored or logged.
//!
//! MQTT 5.0 is a known first-cut limitation: a level-5 CONNECT is logged (properties blocks are
//! skipped without being interpreted) and then declined with CONNACK reason 0x84, so a 5.0 session
//! is captured at CONNECT and goes no further.
//!
//! [`read_packet`] and [`Session::on_packet`] are pure of any `TcpStream` so the parser and state
//! machine are unit-tested (and fuzzed) directly; [`handle_connection`] only wires them to a socket.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{
    ConnectionBounds, EventEmitter, Uuid, WanResolver, sanitize_value, to_hex_bounded,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION,
    SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

pub const PROTOCOL_LABEL: &str = "mqtt";

/// Largest remaining-length (variable header + payload) a packet may declare. The spec allows up
/// to ~256 MiB; a declaration above this closes the connection without buffering anything.
pub const MAX_PACKET_BYTES: usize = 262_144;
/// Packets processed per connection before the session is ended.
pub const MAX_PACKETS: usize = 1024;
/// The remaining-length varint is at most four bytes; a fifth continuation byte is malformed.
const MAX_VARINT_BYTES: usize = 4;
const MAX_FIELD_LEN: usize = 255;
/// Subscribe filters listed in one event (the SUBACK still answers every filter).
const MAX_LOGGED_TOPICS: usize = 32;
const PAYLOAD_PREVIEW_BYTES: usize = 256;

const TYPE_CONNECT: u8 = 1;
const TYPE_PUBLISH: u8 = 3;
const TYPE_PUBREL: u8 = 6;
const TYPE_SUBSCRIBE: u8 = 8;
const TYPE_UNSUBSCRIBE: u8 = 10;
const TYPE_PINGREQ: u8 = 12;
const TYPE_DISCONNECT: u8 = 14;

const CONNACK_ACCEPTED: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
/// MQTT 5.0 CONNACK: ack flags 0, reason 0x84 (unsupported protocol version), no properties.
const CONNACK_V5_UNSUPPORTED_VERSION: [u8; 5] = [0x20, 0x03, 0x00, 0x84, 0x00];
const PINGRESP: [u8; 2] = [0xD0, 0x00];

// ---------------------------------------------------------------------------------------------
// Wire parsing
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Varint {
    Value {
        value: usize,
        len: usize,
    },
    /// A continuation bit is set on the last byte given and fewer than four bytes were given.
    Incomplete,
    /// Four bytes were given and the fourth still carries a continuation bit.
    Malformed,
}

pub fn decode_varint(bytes: &[u8]) -> Varint {
    let mut value = 0usize;
    for (i, &b) in bytes.iter().enumerate().take(MAX_VARINT_BYTES) {
        value |= usize::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Varint::Value { value, len: i + 1 };
        }
    }
    if bytes.len() >= MAX_VARINT_BYTES {
        Varint::Malformed
    } else {
        Varint::Incomplete
    }
}

fn encode_varint(mut value: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_VARINT_BYTES);
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    pub ptype: u8,
    pub flags: u8,
    pub body: Vec<u8>,
}

/// Why a packet could not be read; every variant ends the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    Closed,
    Timeout,
    Malformed,
    TooLarge,
    Budget,
}

async fn read_exact_within<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    within: Duration,
) -> Result<(), ReadError> {
    match tokio::time::timeout(within, reader.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Err(ReadError::Closed),
        Err(_) => Err(ReadError::Timeout),
    }
}

/// Read one control packet. The body is read through a `take` limited to the declared length
/// (already capped at `MAX_PACKET_BYTES` and the remaining capture budget), so memory grows only
/// with bytes the peer actually sends, never with what it merely declares.
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Result<Packet, ReadError> {
    if *total >= bounds.max_captured_bytes {
        return Err(ReadError::Budget);
    }
    let first_wait = if *total == 0 {
        bounds.read_timeout
    } else {
        bounds.idle_timeout
    };
    let mut header = [0u8; 1];
    read_exact_within(reader, &mut header, first_wait).await?;
    *total += 1;

    let mut raw = [0u8; MAX_VARINT_BYTES];
    let mut n = 0;
    let remaining = loop {
        read_exact_within(reader, &mut raw[n..=n], bounds.idle_timeout).await?;
        n += 1;
        *total += 1;
        match decode_varint(&raw[..n]) {
            Varint::Value { value, .. } => break value,
            Varint::Incomplete => continue,
            Varint::Malformed => return Err(ReadError::Malformed),
        }
    };
    if remaining > MAX_PACKET_BYTES {
        return Err(ReadError::TooLarge);
    }
    if total.saturating_add(remaining as u64) > bounds.max_captured_bytes {
        return Err(ReadError::Budget);
    }

    let mut body = Vec::new();
    let read = tokio::time::timeout(
        bounds.idle_timeout,
        (&mut *reader).take(remaining as u64).read_to_end(&mut body),
    )
    .await;
    match read {
        Ok(Ok(got)) if got == remaining => {}
        Ok(_) => return Err(ReadError::Closed),
        Err(_) => return Err(ReadError::Timeout),
    }
    *total += remaining as u64;
    Ok(Packet {
        ptype: header[0] >> 4,
        flags: header[0] & 0x0F,
        body,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// An MQTT length-prefixed field (a UTF-8 string or binary data): 2-byte length, then bytes.
    fn field(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }

    /// Step over an MQTT 5.0 properties block (varint length, then that many bytes) without
    /// interpreting it.
    fn skip_properties(&mut self) -> Option<()> {
        match decode_varint(&self.buf[self.pos..]) {
            Varint::Value { value, len } => {
                self.pos += len;
                self.take(value).map(|_| ())
            }
            _ => None,
        }
    }
}

/// Attacker bytes as bounded, sanitized display text: lossy decode (never a panicking
/// `from_utf8`), pre-cut so a 64 KiB field is not fully decoded for a 255-char log value.
fn text(bytes: &[u8], max: usize) -> String {
    let cut = &bytes[..bytes.len().min(max.saturating_mul(4))];
    sanitize_value(&String::from_utf8_lossy(cut), max)
}

#[derive(Debug)]
pub struct Connect {
    pub level: u8,
    pub keepalive: u16,
    pub clean_session: bool,
    pub client_id: String,
    pub username: Option<String>,
    pub will_topic: Option<String>,
    pub will_payload_len: Option<usize>,
}

/// Parse a CONNECT body. `None` means malformed (the caller closes). The password is read only to
/// reach the end of the payload and is never kept.
pub fn parse_connect(body: &[u8]) -> Option<Connect> {
    let mut c = Cursor::new(body);
    let name = c.field()?;
    let level = c.u8()?;
    // 3.1 is "MQIsdp" level 3; 3.1.1 and 5.0 are "MQTT" levels 4 and 5. Any other pairing is not
    // a protocol this sensor speaks.
    if !matches!((name, level), (b"MQTT", 4 | 5) | (b"MQIsdp", 3)) {
        return None;
    }
    let flags = c.u8()?;
    if flags & 0x01 != 0 {
        return None;
    }
    let keepalive = c.u16()?;
    if level == 5 {
        c.skip_properties()?;
    }

    let has_username = flags & 0x80 != 0;
    let has_password = flags & 0x40 != 0;
    let will_retain = flags & 0x20 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let has_will = flags & 0x04 != 0;
    if will_qos == 3 || (!has_will && (will_qos != 0 || will_retain)) {
        return None;
    }
    if level < 5 && has_password && !has_username {
        return None;
    }

    let client_id = text(c.field()?, MAX_FIELD_LEN);
    let (mut will_topic, mut will_payload_len) = (None, None);
    if has_will {
        if level == 5 {
            c.skip_properties()?;
        }
        will_topic = Some(text(c.field()?, MAX_FIELD_LEN));
        will_payload_len = Some(c.field()?.len());
    }
    let username = if has_username {
        Some(text(c.field()?, MAX_FIELD_LEN))
    } else {
        None
    };
    if has_password {
        // Read to advance the parser, then dropped: a password never reaches an event.
        c.field()?;
    }
    Some(Connect {
        level,
        keepalive,
        clean_session: flags & 0x02 != 0,
        client_id,
        username,
        will_topic,
        will_payload_len,
    })
}

#[derive(Debug)]
pub struct Publish<'a> {
    pub topic: &'a [u8],
    pub qos: u8,
    pub retain: bool,
    pub dup: bool,
    pub packet_id: Option<u16>,
    pub payload: &'a [u8],
}

pub fn parse_publish(flags: u8, body: &[u8]) -> Option<Publish<'_>> {
    let qos = (flags >> 1) & 0x03;
    if qos == 3 {
        return None;
    }
    let mut c = Cursor::new(body);
    let topic = c.field()?;
    let packet_id = if qos > 0 { Some(c.u16()?) } else { None };
    Some(Publish {
        topic,
        qos,
        retain: flags & 0x01 != 0,
        dup: flags & 0x08 != 0,
        packet_id,
        payload: c.rest(),
    })
}

/// A subscription filter is valid when non-empty, NUL-free, `#` only as the whole last level and
/// `+` only as a whole level.
fn valid_filter(filter: &[u8]) -> bool {
    if filter.is_empty() || filter.contains(&0) {
        return false;
    }
    let levels: Vec<&[u8]> = filter.split(|&b| b == b'/').collect();
    let last = levels.len() - 1;
    levels.iter().enumerate().all(|(i, level)| {
        if level.contains(&b'#') {
            *level == b"#" && i == last
        } else if level.contains(&b'+') {
            *level == b"+"
        } else {
            true
        }
    })
}

struct Subscribe<'a> {
    packet_id: u16,
    filters: Vec<(&'a [u8], u8)>,
}

fn parse_subscribe(body: &[u8]) -> Option<Subscribe<'_>> {
    let mut c = Cursor::new(body);
    let packet_id = c.u16()?;
    let mut filters = Vec::new();
    while c.pos < body.len() {
        let filter = c.field()?;
        let requested = c.u8()?;
        if requested > 2 {
            return None;
        }
        filters.push((filter, requested));
    }
    if filters.is_empty() {
        return None;
    }
    Some(Subscribe { packet_id, filters })
}

/// UNSUBSCRIBE carries a packet id and at least one well-formed filter; the filters themselves are
/// not needed because nothing is subscribed.
fn parse_unsubscribe(body: &[u8]) -> Option<u16> {
    let mut c = Cursor::new(body);
    let packet_id = c.u16()?;
    if c.pos >= body.len() {
        return None;
    }
    while c.pos < body.len() {
        c.field()?;
    }
    Some(packet_id)
}

/// Fixed-header flag bits a packet type must carry (MQTT 3.1.1 table 2.2). PUBLISH carries
/// DUP/QoS/RETAIN and is validated by [`parse_publish`]. `None` is a type this sensor does not
/// accept from a client at all.
fn required_flags(ptype: u8) -> Option<Option<u8>> {
    match ptype {
        TYPE_CONNECT | TYPE_PINGREQ | TYPE_DISCONNECT => Some(Some(0)),
        TYPE_PUBLISH => Some(None),
        TYPE_PUBREL | TYPE_SUBSCRIBE | TYPE_UNSUBSCRIBE => Some(Some(0b0010)),
        _ => None,
    }
}

fn payload_preview(payload: &[u8]) -> (String, &'static str) {
    let prefix = &payload[..payload.len().min(PAYLOAD_PREVIEW_BYTES)];
    let cut = prefix.len() < payload.len();
    let decoded = match std::str::from_utf8(prefix) {
        Ok(t) => Some(t),
        // A multibyte character split by OUR cut is fine; one that is invalid in the payload is not.
        Err(e) if cut && e.error_len().is_none() => {
            std::str::from_utf8(&prefix[..e.valid_up_to()]).ok()
        }
        Err(_) => None,
    };
    match decoded {
        Some(t)
            if !t
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')) =>
        {
            (sanitize_value(t, PAYLOAD_PREVIEW_BYTES), "text")
        }
        _ => (to_hex_bounded(prefix, PAYLOAD_PREVIEW_BYTES), "hex"),
    }
}

// ---------------------------------------------------------------------------------------------
// Session state machine
// ---------------------------------------------------------------------------------------------

/// One thing worth recording, before the per-connection identity fields are attached.
#[derive(Debug)]
pub struct Observation {
    pub signal_type: &'static str,
    pub authenticated: bool,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub reply: Vec<u8>,
    pub events: Vec<Observation>,
    pub close: bool,
}

impl Outcome {
    fn close() -> Self {
        Outcome {
            close: true,
            ..Outcome::default()
        }
    }

    fn reply(bytes: &[u8]) -> Self {
        Outcome {
            reply: bytes.to_vec(),
            ..Outcome::default()
        }
    }
}

fn ack(first: u8, packet_id: u16) -> [u8; 4] {
    let id = packet_id.to_be_bytes();
    [first, 0x02, id[0], id[1]]
}

#[derive(Debug, Default)]
pub struct Session {
    connected: bool,
}

impl Session {
    pub fn on_packet(&mut self, pkt: &Packet) -> Outcome {
        let Some(expected) = required_flags(pkt.ptype) else {
            return Outcome::close();
        };
        if expected.is_some_and(|flags| flags != pkt.flags) {
            return Outcome::close();
        }
        // The first packet must be CONNECT, and CONNECT may be sent only once.
        if self.connected == (pkt.ptype == TYPE_CONNECT) {
            return Outcome::close();
        }
        match pkt.ptype {
            TYPE_CONNECT => self.on_connect(&pkt.body),
            TYPE_PUBLISH => on_publish(pkt),
            TYPE_PUBREL => match <[u8; 2]>::try_from(pkt.body.as_slice()) {
                Ok(id) => Outcome::reply(&ack(0x70, u16::from_be_bytes(id))),
                Err(_) => Outcome::close(),
            },
            TYPE_SUBSCRIBE => on_subscribe(&pkt.body),
            TYPE_UNSUBSCRIBE => match parse_unsubscribe(&pkt.body) {
                Some(id) => Outcome::reply(&ack(0xB0, id)),
                None => Outcome::close(),
            },
            TYPE_PINGREQ if pkt.body.is_empty() => Outcome::reply(&PINGRESP),
            _ => Outcome::close(),
        }
    }

    fn on_connect(&mut self, body: &[u8]) -> Outcome {
        let Some(connect) = parse_connect(body) else {
            return Outcome::close();
        };
        let mut metadata = serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "client_id": connect.client_id,
            "username": connect.username.as_deref().unwrap_or(""),
            "protocol_level": connect.level,
            "keepalive": connect.keepalive,
            "clean_session": connect.clean_session,
        });
        if let Some(topic) = &connect.will_topic {
            metadata["will_topic"] = serde_json::Value::String(topic.clone());
        }
        if let Some(len) = connect.will_payload_len {
            metadata["will_payload_len"] = serde_json::Value::from(len);
        }
        let events = vec![Observation {
            signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            authenticated: true,
            metadata,
        }];
        if connect.level == 5 {
            return Outcome {
                reply: CONNACK_V5_UNSUPPORTED_VERSION.to_vec(),
                events,
                close: true,
            };
        }
        self.connected = true;
        Outcome {
            reply: CONNACK_ACCEPTED.to_vec(),
            events,
            close: false,
        }
    }
}

fn on_publish(pkt: &Packet) -> Outcome {
    let Some(publish) = parse_publish(pkt.flags, &pkt.body) else {
        return Outcome::close();
    };
    let (preview, encoding) = payload_preview(publish.payload);
    let digest = Sha256::digest(publish.payload);
    let metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "command": "PUBLISH",
        "topic": text(publish.topic, MAX_FIELD_LEN),
        "qos": publish.qos,
        "retain": publish.retain,
        "dup": publish.dup,
        "payload_len": publish.payload.len(),
        "payload_preview": preview,
        "payload_preview_encoding": encoding,
        "payload_sha256": to_hex_bounded(&digest, digest.len()),
    });
    let reply = match (publish.qos, publish.packet_id) {
        (1, Some(id)) => ack(0x40, id).to_vec(),
        (2, Some(id)) => ack(0x50, id).to_vec(),
        _ => Vec::new(),
    };
    Outcome {
        reply,
        events: vec![Observation {
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC,
            authenticated: false,
            metadata,
        }],
        close: false,
    }
}

fn on_subscribe(body: &[u8]) -> Outcome {
    let Some(sub) = parse_subscribe(body) else {
        return Outcome::close();
    };
    let mut granted = Vec::with_capacity(sub.filters.len());
    let mut topics = Vec::new();
    let mut qos = Vec::new();
    for (i, (filter, requested)) in sub.filters.iter().enumerate() {
        granted.push(if valid_filter(filter) {
            (*requested).min(1)
        } else {
            0x80
        });
        if i < MAX_LOGGED_TOPICS {
            topics.push(text(filter, MAX_FIELD_LEN));
            qos.push(*requested);
        }
    }
    let id = sub.packet_id.to_be_bytes();
    let mut reply = vec![0x90];
    reply.extend(encode_varint(2 + granted.len()));
    reply.extend_from_slice(&id);
    reply.extend_from_slice(&granted);
    Outcome {
        reply,
        events: vec![Observation {
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC,
            authenticated: false,
            metadata: serde_json::json!({
                "protocol_label": PROTOCOL_LABEL,
                "command": "SUBSCRIBE",
                "topics": topics,
                "qos": qos,
                "topic_count": sub.filters.len(),
            }),
        }],
        close: false,
    }
}

// ---------------------------------------------------------------------------------------------
// Socket loop
// ---------------------------------------------------------------------------------------------

pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) {
    let source_ip: IpAddr = normalize_dual_stack(peer_addr).ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let identify =
        |signal_type: &str, authenticated: bool, metadata: serde_json::Value| SensorEvent {
            v: WIRE_VERSION,
            source_ip,
            wan_ip,
            sensor: PROTOCOL_LABEL.to_string(),
            signal_type: signal_type.to_string(),
            protocol: PROTO_TCP.to_string(),
            authenticated,
            observed_at: chrono::Utc::now(),
            metadata,
            sample: None,
            session_id: Some(session_id),
            occurrence_id: None,
        };

    let _ = emitter
        .append(&identify(
            SIGNAL_HONEYPOT_CONNECTION,
            false,
            serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
        ))
        .await;

    let mut session = Session::default();
    let mut total_read: u64 = 0;
    for _ in 0..MAX_PACKETS {
        let Ok(packet) = read_packet(&mut stream, &bounds, &mut total_read).await else {
            return;
        };
        let outcome = session.on_packet(&packet);
        for obs in outcome.events {
            let _ = emitter
                .append(&identify(obs.signal_type, obs.authenticated, obs.metadata))
                .await;
        }
        if !outcome.reply.is_empty() {
            let write =
                tokio::time::timeout(bounds.idle_timeout, stream.write_all(&outcome.reply)).await;
            if !matches!(write, Ok(Ok(()))) {
                return;
            }
        }
        if outcome.close {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lenp(s: &[u8]) -> Vec<u8> {
        let mut v = (s.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(s);
        v
    }

    fn connect_body(level: u8, flags: u8, rest: &[u8]) -> Vec<u8> {
        let mut b = if level == 3 {
            lenp(b"MQIsdp")
        } else {
            lenp(b"MQTT")
        };
        b.push(level);
        b.push(flags);
        b.extend_from_slice(&60u16.to_be_bytes());
        if level == 5 {
            b.push(0); // empty properties
        }
        b.extend_from_slice(rest);
        b
    }

    fn pkt(ptype: u8, flags: u8, body: Vec<u8>) -> Packet {
        Packet { ptype, flags, body }
    }

    fn connected() -> Session {
        let mut s = Session::default();
        let out = s.on_packet(&pkt(1, 0, connect_body(4, 0x02, &lenp(b"cid"))));
        assert!(!out.close);
        s
    }

    #[test]
    fn varint_decodes_spec_boundaries() {
        assert_eq!(decode_varint(&[0x00]), Varint::Value { value: 0, len: 1 });
        assert_eq!(decode_varint(&[0x7F]), Varint::Value { value: 127, len: 1 });
        assert_eq!(
            decode_varint(&[0x80, 0x01]),
            Varint::Value { value: 128, len: 2 }
        );
        assert_eq!(
            decode_varint(&[0xFF, 0xFF, 0xFF, 0x7F]),
            Varint::Value {
                value: 268_435_455,
                len: 4
            }
        );
        assert_eq!(decode_varint(&[0x80]), Varint::Incomplete);
        assert_eq!(decode_varint(&[0x80, 0x80, 0x80, 0x80]), Varint::Malformed);
        assert_eq!(decode_varint(&[]), Varint::Incomplete);
    }

    #[test]
    fn varint_round_trips() {
        for v in [0usize, 1, 127, 128, 16_383, 16_384, 2_097_151, 268_435_455] {
            let enc = encode_varint(v);
            assert_eq!(
                decode_varint(&enc),
                Varint::Value {
                    value: v,
                    len: enc.len()
                }
            );
        }
    }

    #[test]
    fn connect_311_logs_identity_and_never_the_password() {
        let mut rest = lenp(b"client-1");
        rest.extend(lenp(b"admin"));
        rest.extend(lenp(b"hunter2-secret"));
        let body = connect_body(4, 0xC2, &rest);
        let c = parse_connect(&body).unwrap();
        assert_eq!(c.client_id, "client-1");
        assert_eq!(c.username.as_deref(), Some("admin"));
        assert!(c.clean_session);
        assert_eq!(c.keepalive, 60);

        let out = Session::default().on_packet(&pkt(1, 0, body));
        assert_eq!(out.reply, CONNACK_ACCEPTED);
        let dump = serde_json::to_string(&out.events[0].metadata).unwrap();
        assert!(!dump.contains("hunter2"), "password leaked: {dump}");
        assert!(out.events[0].metadata.get("password").is_none());
        assert!(out.events[0].authenticated);
    }

    #[test]
    fn connect_with_will_records_topic_and_payload_length_only() {
        let mut rest = lenp(b"c");
        rest.extend(lenp(b"will/topic"));
        rest.extend(lenp(b"last words"));
        let c = parse_connect(&connect_body(4, 0x06, &rest)).unwrap();
        assert_eq!(c.will_topic.as_deref(), Some("will/topic"));
        assert_eq!(c.will_payload_len, Some(10));
    }

    #[test]
    fn connect_level5_is_logged_then_declined() {
        let out =
            Session::default().on_packet(&pkt(1, 0, connect_body(5, 0x02, &lenp(b"v5client"))));
        assert_eq!(out.reply, CONNACK_V5_UNSUPPORTED_VERSION);
        assert!(out.close);
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].metadata["protocol_level"], 5);
        assert_eq!(out.events[0].metadata["client_id"], "v5client");
    }

    #[test]
    fn connect_rejects_reserved_bit_bad_protocol_and_inconsistent_flags() {
        let id = lenp(b"c");
        assert!(
            parse_connect(&connect_body(4, 0x03, &id)).is_none(),
            "reserved bit"
        );
        assert!(
            parse_connect(&connect_body(6, 0x02, &id)).is_none(),
            "level 6"
        );
        let mut wrong = lenp(b"MQTT");
        wrong.push(3);
        wrong.push(0x02);
        wrong.extend_from_slice(&[0, 60]);
        wrong.extend(&id);
        assert!(parse_connect(&wrong).is_none(), "MQTT/level 3");
        assert!(
            parse_connect(&connect_body(4, 0x20, &id)).is_none(),
            "will-retain without will"
        );
        assert!(
            parse_connect(&connect_body(4, 0x10, &id)).is_none(),
            "will-qos without will"
        );
        assert!(
            parse_connect(&connect_body(4, 0x1C, &id)).is_none(),
            "will-qos 3"
        );
        let mut pw = id.clone();
        pw.extend(lenp(b"p"));
        assert!(
            parse_connect(&connect_body(4, 0x42, &pw)).is_none(),
            "password without username"
        );
    }

    #[test]
    fn connect_truncated_anywhere_is_none_not_panic() {
        for level in [3u8, 4, 5] {
            let mut rest = lenp(b"client");
            if level == 5 {
                rest.push(0); // empty will properties
            }
            rest.extend(lenp(b"will/t"));
            rest.extend(lenp(b"wp"));
            rest.extend(lenp(b"user"));
            rest.extend(lenp(b"pass"));
            let full = connect_body(level, 0xC6, &rest);
            assert!(parse_connect(&full).is_some(), "level {level} full body");
            for cut in 0..full.len() {
                assert!(
                    parse_connect(&full[..cut]).is_none(),
                    "level {level} truncated at {cut} must be rejected"
                );
            }
        }
    }

    #[test]
    fn non_connect_first_and_double_connect_close() {
        let mut s = Session::default();
        assert!(
            s.on_packet(&pkt(12, 0, vec![])).close,
            "PINGREQ pre-CONNECT"
        );
        assert!(
            s.on_packet(&pkt(3, 0, lenp(b"t"))).close,
            "PUBLISH pre-CONNECT"
        );
        let mut s = connected();
        assert!(
            s.on_packet(&pkt(1, 0, connect_body(4, 0x02, &lenp(b"x"))))
                .close
        );
    }

    #[test]
    fn reserved_flags_and_unknown_types_close() {
        let mut s = connected();
        assert!(
            s.on_packet(&pkt(8, 0, vec![0, 1, 0, 1, b't', 0])).close,
            "SUBSCRIBE flags 0"
        );
        assert!(s.on_packet(&pkt(12, 1, vec![])).close, "PINGREQ flags 1");
        assert!(s.on_packet(&pkt(0, 0, vec![])).close, "type 0");
        assert!(
            s.on_packet(&pkt(2, 0, vec![0, 0])).close,
            "CONNACK from a client"
        );
        assert!(s.on_packet(&pkt(15, 0, vec![])).close, "AUTH");
        assert!(s.on_packet(&pkt(14, 0, vec![])).close, "DISCONNECT closes");
        assert!(
            s.on_packet(&pkt(12, 0, vec![1])).close,
            "PINGREQ with a body"
        );
    }

    #[test]
    fn subscribe_grants_min_qos_1_and_rejects_bad_filters() {
        let mut s = connected();
        let mut body = vec![0x00, 0x2A];
        body.extend(lenp(b"sensors/#"));
        body.push(2);
        body.extend(lenp(b"a/+/b"));
        body.push(0);
        body.extend(lenp(b"bad#filter"));
        body.push(1);
        body.extend(lenp(b""));
        body.push(1);
        let out = s.on_packet(&pkt(8, 2, body));
        assert_eq!(out.reply, vec![0x90, 6, 0x00, 0x2A, 1, 0, 0x80, 0x80]);
        let m = &out.events[0].metadata;
        assert_eq!(m["command"], "SUBSCRIBE");
        assert_eq!(m["topics"][0], "sensors/#");
        assert_eq!(m["qos"][0], 2);
        assert_eq!(m["topic_count"], 4);
    }

    #[test]
    fn subscribe_logs_at_most_the_first_32_filters_but_answers_all() {
        let mut s = connected();
        let mut body = vec![0, 1];
        for i in 0..40 {
            body.extend(lenp(format!("t/{i}").as_bytes()));
            body.push(0);
        }
        let out = s.on_packet(&pkt(8, 2, body));
        assert_eq!(
            out.events[0].metadata["topics"].as_array().unwrap().len(),
            32
        );
        assert_eq!(out.events[0].metadata["topic_count"], 40);
        assert_eq!(out.reply.len(), 2 + 2 + 40);
    }

    #[test]
    fn malformed_subscribe_closes() {
        let mut s = connected();
        assert!(s.on_packet(&pkt(8, 2, vec![0, 1])).close, "no filters");
        assert!(
            s.on_packet(&pkt(8, 2, vec![0, 1, 0, 5, b'a'])).close,
            "truncated filter"
        );
        let mut bad_qos = vec![0, 1];
        bad_qos.extend(lenp(b"t"));
        bad_qos.push(3);
        assert!(s.on_packet(&pkt(8, 2, bad_qos)).close, "requested qos 3");
    }

    #[test]
    fn publish_qos0_qos1_qos2_replies_and_metadata() {
        let mut s = connected();
        let q0 = s.on_packet(&pkt(3, 0, [lenp(b"a/b"), b"hello".to_vec()].concat()));
        assert!(q0.reply.is_empty());
        let m = &q0.events[0].metadata;
        assert_eq!(m["topic"], "a/b");
        assert_eq!(m["payload_len"], 5);
        assert_eq!(m["payload_preview"], "hello");
        assert_eq!(m["payload_preview_encoding"], "text");
        assert_eq!(
            m["payload_sha256"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        let q1 = s.on_packet(&pkt(
            3,
            0x02,
            [lenp(b"a/b"), vec![0x12, 0x34], b"x".to_vec()].concat(),
        ));
        assert_eq!(q1.reply, vec![0x40, 2, 0x12, 0x34]);
        assert_eq!(q1.events[0].metadata["qos"], 1);

        let q2 = s.on_packet(&pkt(
            3,
            0x0D,
            [lenp(b"a/b"), vec![0, 9], b"x".to_vec()].concat(),
        ));
        assert_eq!(q2.reply, vec![0x50, 2, 0, 9]);
        assert_eq!(q2.events[0].metadata["qos"], 2);
        assert_eq!(q2.events[0].metadata["dup"], true);
        assert_eq!(q2.events[0].metadata["retain"], true);

        let rel = s.on_packet(&pkt(6, 2, vec![0, 9]));
        assert_eq!(rel.reply, vec![0x70, 2, 0, 9]);
        assert!(rel.events.is_empty());
    }

    #[test]
    fn publish_binary_payload_is_hex_and_never_republished() {
        let mut s = connected();
        let out = s.on_packet(&pkt(3, 0, [lenp(b"t"), vec![0xFF, 0x00, 0x1B]].concat()));
        let m = &out.events[0].metadata;
        assert_eq!(m["payload_preview"], "ff001b");
        assert_eq!(m["payload_preview_encoding"], "hex");
        assert!(
            out.reply.is_empty(),
            "a PUBLISH never produces a forwarded PUBLISH"
        );
    }

    #[test]
    fn publish_text_with_control_bytes_is_hex_and_long_payload_preview_is_bounded() {
        let (p, enc) = payload_preview(b"hi\x1b[31mred");
        assert_eq!(enc, "hex");
        assert!(p.starts_with("6869"));
        let big = vec![b'a'; 100_000];
        let (p, enc) = payload_preview(&big);
        assert_eq!(enc, "text");
        assert_eq!(p.len(), PAYLOAD_PREVIEW_BYTES);
        // A multibyte character split by the preview cut stays text.
        let mut split = vec![b'a'; PAYLOAD_PREVIEW_BYTES - 1];
        split.extend_from_slice("é".as_bytes());
        let (_, enc) = payload_preview(&split);
        assert_eq!(enc, "text");
    }

    #[test]
    fn malformed_publish_closes() {
        let mut s = connected();
        assert!(s.on_packet(&pkt(3, 0x06, lenp(b"t"))).close, "qos 3");
        assert!(
            s.on_packet(&pkt(3, 0x02, lenp(b"t"))).close,
            "qos1 without packet id"
        );
        assert!(
            s.on_packet(&pkt(3, 0, vec![0, 9, b'a'])).close,
            "truncated topic"
        );
    }

    #[test]
    fn ping_and_unsubscribe_are_answered() {
        let mut s = connected();
        assert_eq!(s.on_packet(&pkt(12, 0, vec![])).reply, PINGRESP);
        let mut body = vec![0, 7];
        body.extend(lenp(b"a/b"));
        let out = s.on_packet(&pkt(10, 2, body));
        assert_eq!(out.reply, vec![0xB0, 2, 0, 7]);
        assert!(s.on_packet(&pkt(10, 2, vec![0, 7])).close, "no filters");
    }

    #[test]
    fn attacker_text_is_sanitized_and_bounded() {
        let mut s = connected();
        let long = vec![b'z'; 5000];
        let topic = [b"x\r\ny\x1b[2J".as_slice(), &[0xC3, 0x28], &long].concat();
        let out = s.on_packet(&pkt(3, 0, lenp(&topic)));
        let t = out.events[0].metadata["topic"].as_str().unwrap();
        assert!(t.chars().count() <= MAX_FIELD_LEN);
        assert!(!t.contains('\n') && !t.contains('\x1b'));
    }

    #[test]
    fn valid_filter_rules() {
        for ok in ["a", "a/b", "#", "+", "a/#", "+/+/x", "/", "a//b"] {
            assert!(valid_filter(ok.as_bytes()), "{ok}");
        }
        for bad in ["", "a#", "#/a", "a/#/b", "a+", "a/b+/c", "a\0b"] {
            assert!(!valid_filter(bad.as_bytes()), "{bad}");
        }
    }

    fn test_bounds() -> ConnectionBounds {
        ConnectionBounds {
            read_timeout: Duration::from_millis(200),
            idle_timeout: Duration::from_millis(200),
            max_duration: Duration::from_secs(5),
            max_captured_bytes: 1_000_000,
            max_concurrent: 4,
        }
    }

    #[tokio::test]
    async fn read_packet_enforces_varint_cap_size_cap_and_budget() {
        let b = test_bounds();
        let mut total = 0;
        let ok = read_packet(&mut &[0xC0u8, 0x00][..], &b, &mut total)
            .await
            .unwrap();
        assert_eq!((ok.ptype, ok.flags, ok.body.len()), (12, 0, 0));

        let five = [0x30u8, 0x80, 0x80, 0x80, 0x80, 0x01];
        assert_eq!(
            read_packet(&mut &five[..], &b, &mut 0).await.unwrap_err(),
            ReadError::Malformed
        );

        // Declares 268_435_455 bytes and supplies none: refused on the declaration alone.
        let huge = [0x30u8, 0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(
            read_packet(&mut &huge[..], &b, &mut 0).await.unwrap_err(),
            ReadError::TooLarge
        );
        // One past the cap.
        let mut over = vec![0x30u8];
        over.extend(encode_varint(MAX_PACKET_BYTES + 1));
        assert_eq!(
            read_packet(&mut &over[..], &b, &mut 0).await.unwrap_err(),
            ReadError::TooLarge
        );
        // Exactly the cap is accepted when the bytes arrive.
        let mut at_cap = vec![0x30u8];
        at_cap.extend(encode_varint(MAX_PACKET_BYTES));
        at_cap.extend(vec![0u8; MAX_PACKET_BYTES]);
        assert_eq!(
            read_packet(&mut &at_cap[..], &b, &mut 0)
                .await
                .unwrap()
                .body
                .len(),
            MAX_PACKET_BYTES
        );

        let tight = ConnectionBounds {
            max_captured_bytes: 100,
            ..test_bounds()
        };
        let mut budgeted = vec![0x30u8, 0x64];
        budgeted.extend(vec![0u8; 100]);
        assert_eq!(
            read_packet(&mut &budgeted[..], &tight, &mut 0)
                .await
                .unwrap_err(),
            ReadError::Budget
        );
    }

    #[tokio::test]
    async fn read_packet_short_body_is_closed_not_a_packet() {
        let b = test_bounds();
        let short = [0x30u8, 0x05, 1, 2];
        assert_eq!(
            read_packet(&mut &short[..], &b, &mut 0).await.unwrap_err(),
            ReadError::Closed
        );
    }

    #[tokio::test]
    async fn arbitrary_bytes_never_panic_and_stay_bounded() {
        // Deterministic xorshift stream: many shapes of garbage, truncated at every length class.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let b = test_bounds();
        for round in 0..400 {
            let len = (next() % 600) as usize;
            let mut data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 2 == 0 && !data.is_empty() {
                // Bias half the rounds toward a plausible first packet so the parsers are reached.
                data[0] = 0x10;
            }
            let mut session = Session::default();
            let mut total = 0u64;
            let mut input = &data[..];
            for _ in 0..MAX_PACKETS {
                let Ok(p) = read_packet(&mut input, &b, &mut total).await else {
                    break;
                };
                assert!(p.body.len() <= data.len());
                let out = session.on_packet(&p);
                assert!(out.reply.len() <= 4 + 2 + p.body.len());
                if out.close {
                    break;
                }
            }
            assert!(total <= data.len() as u64);
        }
    }
}
