//! Per-connection MQTT session handler: a recon trap for TCP/1883 that spools binary payloads.
//!
//! It records who connects (CONNECT credentials, client id, will topic), what they subscribe to,
//! and what they publish (topic plus bounded payload metadata), and answers MQTT 3.1, 3.1.1 and
//! 5.0 so a scanner or client library carries on and reveals intent. It serves nothing: a PUBLISH
//! is never delivered to any subscriber, retained, or forwarded; there is no broker state; no
//! outbound socket is ever opened; nothing is executed. Any credential is accepted (the deliberate
//! low-interaction choice: it is what lets the post-CONNECT SUBSCRIBE and PUBLISH recon through).
//!
//! A PUBLISH payload that passes [`looks_binary`] is additionally handed to the capture hand-off
//! and spooled as a potential malware sample (`honeypot_malware_upload`), bounded by the
//! process-wide capture-memory budget; a text or control payload stays metadata-only.
//!
//! The CONNECT password and the 5.0 Authentication-Data property are credentials: each is read
//! only to advance the parser and is dropped, never stored or logged.
//!
//! MQTT 5.0 is handled in full. A 5.0 packet's properties block is parsed strictly inside its
//! declared length by [`parse_properties`] (checked indexing, at most [`MAX_PROPERTIES`]
//! properties, never past the block), so a malformed property sets `properties_parse_error` but
//! can neither corrupt the packet boundary nor fail the packet. Levels 3 and 4 have no properties
//! blocks and take the 3.1.1 path unchanged.
//!
//! Every connection ends with one session-end summary event, and a connection whose first
//! packet is malformed (or not a CONNECT) emits a `malformed` connection event so the scanner's
//! fingerprint is not lost. After CONNECT the per-read idle bound follows the client's keepalive
//! (1.5x, as a real broker does), see [`keepalive_idle`].
//!
//! [`read_packet`] and [`Session::on_packet`] are pure of any `TcpStream` so the parser and state
//! machine are unit-tested (and fuzzed) directly; [`handle_connection`] only wires them to a socket.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::shell::looks_binary;
use sensor_framework::{
    CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, Uuid, WanResolver, sanitize_value,
    to_hex_bounded, upload_metadata,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION,
    SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SIGNAL_HONEYPOT_SESSION_END,
    SampleRef, SensorEvent, WIRE_VERSION,
};

pub const PROTOCOL_LABEL: &str = "mqtt";

/// Largest remaining-length (variable header + payload) a packet may declare. The spec allows up
/// to ~256 MiB; a declaration above this closes the connection without buffering anything.
pub const MAX_PACKET_BYTES: usize = 262_144;
/// Packets processed per connection before the session is ended.
pub const MAX_PACKETS: usize = 1024;
/// Properties read from one 5.0 properties block; the next one marks `parse_error` and stops.
pub const MAX_PROPERTIES: usize = 64;
/// User properties kept (and logged) from one block; `user_property_count` still counts them all.
pub const MAX_LOGGED_USER_PROPERTIES: usize = 16;
/// The remaining-length varint is at most four bytes; a fifth continuation byte is malformed.
const MAX_VARINT_BYTES: usize = 4;
const MAX_FIELD_LEN: usize = 255;
/// Subscribe filters listed in one event (the SUBACK still answers every filter).
const MAX_LOGGED_TOPICS: usize = 32;
const PAYLOAD_PREVIEW_BYTES: usize = 256;
/// The `capture_reason` stamped on a spooled PUBLISH payload: it passed the same `looks_binary`
/// gate telnet, ssh and adb use before a shell-phase buffer is treated as a sample.
const CAPTURE_REASON_BINARY_PUBLISH: &str = "binary_publish_payload";
/// Wire bytes of a rejected first packet kept as hex in a malformed-connection event.
const MALFORMED_SNIPPET_BYTES: usize = 32;

const TYPE_CONNECT: u8 = 1;
const TYPE_PUBLISH: u8 = 3;
const TYPE_PUBACK: u8 = 4;
const TYPE_PUBREC: u8 = 5;
const TYPE_PUBREL: u8 = 6;
const TYPE_PUBCOMP: u8 = 7;
const TYPE_SUBSCRIBE: u8 = 8;
const TYPE_UNSUBSCRIBE: u8 = 10;
const TYPE_PINGREQ: u8 = 12;
const TYPE_DISCONNECT: u8 = 14;
const TYPE_AUTH: u8 = 15;

const CONNACK_ACCEPTED: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
/// MQTT 5.0 CONNACK: ack flags 0, reason 0x00 (success), empty properties block.
const CONNACK_V5_ACCEPTED: [u8; 5] = [0x20, 0x03, 0x00, 0x00, 0x00];
/// MQTT 5.0 AUTH: reason 0x00 (success), empty properties block.
const AUTH_V5_SUCCESS: [u8; 4] = [0xF0, 0x02, 0x00, 0x00];
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

impl ReadError {
    fn reason(&self) -> &'static str {
        match self {
            ReadError::Closed => "truncated",
            ReadError::Timeout => "timeout",
            ReadError::Malformed => "bad_remaining_length",
            ReadError::TooLarge => "oversize_declaration",
            ReadError::Budget => "capture_budget",
        }
    }
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

/// Read one control packet, waiting at most `bounds.idle_timeout` between reads.
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Result<Packet, ReadError> {
    read_packet_within(reader, bounds, total, bounds.idle_timeout, &mut Vec::new()).await
}

/// Read one control packet. The body is read through a `take` limited to the declared length
/// (already capped at `MAX_PACKET_BYTES` and the remaining capture budget), so memory grows only
/// with bytes the peer actually sends, never with what it merely declares.
///
/// `idle` is the per-read wait after the first packet (the keepalive-derived bound once a client
/// has connected). `head` receives the header byte and remaining-length bytes as they arrive, so a
/// malformed first packet can still be fingerprinted when no [`Packet`] is produced.
async fn read_packet_within<R: AsyncRead + Unpin>(
    reader: &mut R,
    bounds: &ConnectionBounds,
    total: &mut u64,
    idle: Duration,
    head: &mut Vec<u8>,
) -> Result<Packet, ReadError> {
    if *total >= bounds.max_captured_bytes {
        return Err(ReadError::Budget);
    }
    let first_wait = if *total == 0 {
        bounds.read_timeout
    } else {
        idle
    };
    let mut header = [0u8; 1];
    read_exact_within(reader, &mut header, first_wait).await?;
    *total += 1;
    head.push(header[0]);

    let mut raw = [0u8; MAX_VARINT_BYTES];
    let mut n = 0;
    let remaining = loop {
        read_exact_within(reader, &mut raw[n..=n], idle).await?;
        head.push(raw[n]);
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
        idle,
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

/// The per-read idle bound once a client has connected: a real broker drops a client that is
/// silent for 1.5x its keepalive, so the sensor does too, but never waits longer than the
/// configured `idle_timeout`. A keepalive of 0 turns the client's own bound off.
pub fn keepalive_idle(idle_timeout: Duration, keepalive_secs: u16) -> Duration {
    if keepalive_secs == 0 {
        return idle_timeout;
    }
    idle_timeout.min(Duration::from_millis(u64::from(keepalive_secs) * 1500))
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

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A variable byte integer (a properties length or a property identifier).
    fn varint(&mut self) -> Option<usize> {
        match decode_varint(self.buf.get(self.pos..)?) {
            Varint::Value { value, len } => {
                self.pos += len;
                Some(value)
            }
            _ => None,
        }
    }

    /// An MQTT length-prefixed field (a UTF-8 string or binary data): 2-byte length, then bytes.
    fn field(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = self.buf.get(self.pos..).unwrap_or_default();
        self.pos = self.buf.len();
        rest
    }

    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// An MQTT 5.0 properties block: a varint byte length, then that many bytes, interpreted by
    /// [`parse_properties`]. `None` only when the declared length does not fit in what is left
    /// (the packet boundary is unknowable); a bad property inside a block that does fit is
    /// `parse_error`, and the cursor still lands exactly at the block end.
    fn properties(&mut self) -> Option<Properties> {
        let len = self.varint()?;
        Some(parse_properties(self.take(len)?))
    }
}

/// Attacker bytes as bounded, sanitized display text: lossy decode (never a panicking
/// `from_utf8`), pre-cut so a 64 KiB field is not fully decoded for a 255-char log value.
fn text(bytes: &[u8], max: usize) -> String {
    let cut = &bytes[..bytes.len().min(max.saturating_mul(4))];
    sanitize_value(&String::from_utf8_lossy(cut), max)
}

/// The recon-relevant contents of one MQTT 5.0 properties block. Authentication-Data is
/// deliberately not a field: it is a credential and is dropped while parsing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Properties {
    pub session_expiry: Option<u32>,
    pub receive_max: Option<u16>,
    pub max_packet_size: Option<u32>,
    pub topic_alias_max: Option<u16>,
    pub topic_alias: Option<u16>,
    pub request_response_info: Option<u8>,
    pub auth_method: Option<String>,
    /// The first [`MAX_LOGGED_USER_PROPERTIES`] user properties, sanitized and bounded.
    pub user_properties: Vec<(String, String)>,
    /// Every user property seen, including those past the kept limit.
    pub user_property_count: usize,
    /// A property was malformed, unknown, or past [`MAX_PROPERTIES`]; parsing stopped there and
    /// whatever was read before it is still reported.
    pub parse_error: bool,
}

/// Interpret a properties block (the bytes after its length varint). Never reads outside `block`
/// and never panics on any input; the work is bounded by the block length (itself bounded by
/// `MAX_PACKET_BYTES`) and [`MAX_PROPERTIES`].
pub fn parse_properties(block: &[u8]) -> Properties {
    let mut props = Properties::default();
    let mut c = Cursor::new(block);
    let mut seen = 0usize;
    while !c.at_end() {
        if seen == MAX_PROPERTIES || read_property(&mut c, &mut props).is_none() {
            props.parse_error = true;
            break;
        }
        seen += 1;
    }
    props
}

/// One property: an identifier, then a value whose wire type the identifier fixes. An identifier
/// outside the 5.0 table cannot be skipped (its value width is unknown), so it is an error.
fn read_property(c: &mut Cursor<'_>, props: &mut Properties) -> Option<()> {
    match c.varint()? {
        // Byte: payload format, request problem info, maximum QoS, retain / wildcard /
        // subscription-id / shared-subscription available.
        0x01 | 0x17 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2A => {
            c.u8()?;
        }
        0x19 => props.request_response_info = Some(c.u8()?),
        // Two-byte integer: server keep alive.
        0x13 => {
            c.u16()?;
        }
        0x21 => props.receive_max = Some(c.u16()?),
        0x22 => props.topic_alias_max = Some(c.u16()?),
        0x23 => props.topic_alias = Some(c.u16()?),
        // Four-byte integer: message expiry, will delay.
        0x02 | 0x18 => {
            c.u32()?;
        }
        0x11 => props.session_expiry = Some(c.u32()?),
        0x27 => props.max_packet_size = Some(c.u32()?),
        // Variable byte integer: subscription identifier.
        0x0B => {
            c.varint()?;
        }
        // UTF-8 string: content type, response topic, assigned client id, response information,
        // server reference, reason string.
        0x03 | 0x08 | 0x12 | 0x1A | 0x1C | 0x1F => {
            c.field()?;
        }
        0x15 => props.auth_method = Some(text(c.field()?, MAX_FIELD_LEN)),
        // Binary data: correlation data, and Authentication-Data, which is a credential and is
        // read only to advance the cursor.
        0x09 | 0x16 => {
            c.field()?;
        }
        0x26 => {
            let name = c.field()?;
            let value = c.field()?;
            props.user_property_count += 1;
            if props.user_properties.len() < MAX_LOGGED_USER_PROPERTIES {
                props
                    .user_properties
                    .push((text(name, MAX_FIELD_LEN), text(value, MAX_FIELD_LEN)));
            }
        }
        _ => return None,
    }
    Some(())
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
    /// The CONNECT properties block (default for levels 3 and 4).
    pub properties: Properties,
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
    let properties = if level == 5 {
        c.properties()?
    } else {
        Properties::default()
    };

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
            // Will properties (delay, expiry, content type, ...) are not recon-relevant.
            c.properties()?;
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
        properties,
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
    pub properties: Properties,
}

/// Parse a PUBLISH body. For level 5 a properties block sits between the packet id and the
/// payload, so the payload is whatever follows that block; for 3.1/3.1.1 it follows the packet id.
pub fn parse_publish(level: u8, flags: u8, body: &[u8]) -> Option<Publish<'_>> {
    let qos = (flags >> 1) & 0x03;
    if qos == 3 {
        return None;
    }
    let mut c = Cursor::new(body);
    let topic = c.field()?;
    let packet_id = if qos > 0 { Some(c.u16()?) } else { None };
    let properties = if level == 5 {
        c.properties()?
    } else {
        Properties::default()
    };
    Some(Publish {
        topic,
        qos,
        retain: flags & 0x01 != 0,
        dup: flags & 0x08 != 0,
        packet_id,
        payload: c.rest(),
        properties,
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
    properties: Properties,
}

fn parse_subscribe(level: u8, body: &[u8]) -> Option<Subscribe<'_>> {
    let mut c = Cursor::new(body);
    let packet_id = c.u16()?;
    let properties = if level == 5 {
        c.properties()?
    } else {
        Properties::default()
    };
    let mut filters = Vec::new();
    while !c.at_end() {
        let filter = c.field()?;
        let options = c.u8()?;
        let requested = if level == 5 {
            // Bits 0-1 maximum QoS, 2 no-local, 3 retain-as-published, 4-5 retain handling
            // (3 is reserved), 6-7 reserved.
            if options & 0xC0 != 0 || (options >> 4) & 0x03 == 3 || options & 0x03 == 3 {
                return None;
            }
            options & 0x03
        } else {
            if options > 2 {
                return None;
            }
            options
        };
        filters.push((filter, requested));
    }
    if filters.is_empty() {
        return None;
    }
    Some(Subscribe {
        packet_id,
        filters,
        properties,
    })
}

/// UNSUBSCRIBE carries a packet id (and, for level 5, a properties block) and at least one
/// well-formed filter; the filters themselves are not needed because nothing is subscribed, only
/// their count (the 5.0 UNSUBACK answers each one).
fn parse_unsubscribe(level: u8, body: &[u8]) -> Option<(u16, usize)> {
    let mut c = Cursor::new(body);
    let packet_id = c.u16()?;
    if level == 5 {
        c.properties()?;
    }
    if c.at_end() {
        return None;
    }
    let mut count = 0;
    while !c.at_end() {
        c.field()?;
        count += 1;
    }
    Some((packet_id, count))
}

/// The 5.0 reason-code-plus-properties tail, as parsed by PUBACK/PUBREC/PUBREL/PUBCOMP (after the
/// packet id) and AUTH: an optional reason code, then an optional properties block, nothing after.
/// Absent means reason 0x00 and no properties. (DISCONNECT closes the connection without parsing
/// its own tail, so it does not call this.)
fn reason_and_properties(c: &mut Cursor<'_>) -> Option<(u8, Properties)> {
    if c.at_end() {
        return Some((0, Properties::default()));
    }
    let reason = c.u8()?;
    let properties = if c.at_end() {
        Properties::default()
    } else {
        c.properties()?
    };
    c.at_end().then_some((reason, properties))
}

/// A 5.0 PUBACK/PUBREC/PUBREL/PUBCOMP body: packet id, then [`reason_and_properties`].
fn parse_ack_v5(body: &[u8]) -> Option<u16> {
    let mut c = Cursor::new(body);
    let packet_id = c.u16()?;
    reason_and_properties(&mut c)?;
    Some(packet_id)
}

/// Fixed-header flag bits a packet type must carry (MQTT 3.1.1 table 2.2, 5.0 table 2.2). PUBLISH
/// carries DUP/QoS/RETAIN and is validated by [`parse_publish`]. `None` is a type this sensor does
/// not accept from a client at this protocol level: AUTH exists only in 5.0, and PUBACK, PUBREC and
/// PUBCOMP answer a server PUBLISH that the sensor never sends, so before 5.0 they are refused as
/// they always were.
fn required_flags(ptype: u8, level: u8) -> Option<Option<u8>> {
    match ptype {
        TYPE_CONNECT | TYPE_PINGREQ | TYPE_DISCONNECT => Some(Some(0)),
        TYPE_PUBLISH => Some(None),
        TYPE_PUBREL | TYPE_SUBSCRIBE | TYPE_UNSUBSCRIBE => Some(Some(0b0010)),
        TYPE_PUBACK | TYPE_PUBREC | TYPE_PUBCOMP | TYPE_AUTH if level == 5 => Some(Some(0)),
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

/// A PUBLISH whose payload passed the [`looks_binary`] gate and so is to be spooled as a potential
/// sample. It names the payload by length only: the payload is the tail of the packet body (see
/// [`parse_publish`]), so [`handle_connection`] slices it out of the packet it already holds
/// instead of the session copying up to `MAX_PACKET_BYTES` outside the capture-memory budget.
#[derive(Debug)]
pub struct CaptureRequest {
    pub payload_len: usize,
    /// The sanitized, bounded topic, or `None` when it is empty (the caller then names the sample
    /// after the session).
    pub orig_name: Option<String>,
    /// The mqtt-specific fields merged into the `honeypot_malware_upload` metadata.
    pub fields: serde_json::Value,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub reply: Vec<u8>,
    pub events: Vec<Observation>,
    pub capture: Option<CaptureRequest>,
    pub close: bool,
    /// Why the packet was refused, when it was (the connection closes). A clean DISCONNECT closes
    /// with no reason.
    pub reject: Option<&'static str>,
}

impl Outcome {
    fn close() -> Self {
        Outcome {
            close: true,
            ..Outcome::default()
        }
    }

    fn reject(reason: &'static str) -> Self {
        Outcome {
            close: true,
            reject: Some(reason),
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

/// Add the recon-relevant CONNECT properties to a login event. Authentication-Data is not in
/// [`Properties`], so it cannot reach here.
fn add_connect_properties(metadata: &mut serde_json::Value, p: &Properties) {
    if let Some(method) = &p.auth_method {
        metadata["auth_method"] = serde_json::Value::String(method.clone());
    }
    if let Some(v) = p.session_expiry {
        metadata["session_expiry"] = v.into();
    }
    if let Some(v) = p.receive_max {
        metadata["receive_max"] = v.into();
    }
    if let Some(v) = p.max_packet_size {
        metadata["max_packet_size"] = v.into();
    }
    if let Some(v) = p.topic_alias_max {
        metadata["topic_alias_max"] = v.into();
    }
    if let Some(v) = p.request_response_info {
        metadata["request_response_info"] = v.into();
    }
    if p.user_property_count > 0 {
        metadata["user_properties"] = p
            .user_properties
            .iter()
            .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
            .collect();
        metadata["user_property_count"] = p.user_property_count.into();
    }
    flag_parse_error(metadata, p);
}

fn flag_parse_error(metadata: &mut serde_json::Value, p: &Properties) {
    if p.parse_error {
        metadata["properties_parse_error"] = true.into();
    }
}

/// The event for a connection whose first packet was malformed or not a CONNECT: the reason, how
/// many bytes the peer sent, and a bounded hex snippet of the wire bytes (never raw text).
pub fn malformed_observation(reason: &str, bytes_seen: u64, first_bytes: &[u8]) -> Observation {
    Observation {
        signal_type: SIGNAL_HONEYPOT_CONNECTION,
        authenticated: false,
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "malformed": true,
            "reason": reason,
            "bytes_seen": bytes_seen,
            "first_bytes_hex": to_hex_bounded(first_bytes, MALFORMED_SNIPPET_BYTES),
        }),
    }
}

/// The leading wire bytes of a packet (header byte, remaining length, body) for a fingerprint,
/// copying at most [`MALFORMED_SNIPPET_BYTES`] of the body.
fn packet_head(pkt: &Packet) -> Vec<u8> {
    let mut head = vec![(pkt.ptype << 4) | pkt.flags];
    head.extend(encode_varint(pkt.body.len()));
    head.extend_from_slice(&pkt.body[..pkt.body.len().min(MALFORMED_SNIPPET_BYTES)]);
    head
}

#[derive(Debug, Default)]
pub struct Session {
    connected: bool,
    level: u8,
    keepalive: u16,
    client_id: Option<String>,
    packets: u64,
    publishes: u64,
    subscribes: u64,
}

impl Session {
    pub fn connected(&self) -> bool {
        self.connected
    }

    pub fn on_packet(&mut self, pkt: &Packet) -> Outcome {
        self.packets += 1;
        let outcome = self.dispatch(pkt);
        if !outcome.close {
            match pkt.ptype {
                TYPE_PUBLISH => self.publishes += 1,
                TYPE_SUBSCRIBE => self.subscribes += 1,
                _ => {}
            }
        }
        outcome
    }

    fn dispatch(&mut self, pkt: &Packet) -> Outcome {
        // The first packet must be CONNECT, and CONNECT may be sent only once.
        if !self.connected && pkt.ptype != TYPE_CONNECT {
            return Outcome::reject("first_packet_not_connect");
        }
        if self.connected && pkt.ptype == TYPE_CONNECT {
            return Outcome::reject("duplicate_connect");
        }
        let Some(expected) = required_flags(pkt.ptype, self.level) else {
            return Outcome::reject("unsupported_packet_type");
        };
        if expected.is_some_and(|flags| flags != pkt.flags) {
            return Outcome::reject("bad_fixed_header_flags");
        }
        let level = self.level;
        match pkt.ptype {
            TYPE_CONNECT => self.on_connect(&pkt.body),
            TYPE_PUBLISH => on_publish(level, pkt),
            TYPE_PUBACK | TYPE_PUBREC | TYPE_PUBCOMP => {
                // Reaches here only at level 5. These answer a server PUBLISH the sensor never
                // sent, so a well-formed one is accepted and ignored.
                match parse_ack_v5(&pkt.body) {
                    Some(_) => Outcome::default(),
                    None => Outcome::reject("malformed_ack"),
                }
            }
            TYPE_PUBREL => {
                let id = if level == 5 {
                    parse_ack_v5(&pkt.body)
                } else {
                    <[u8; 2]>::try_from(pkt.body.as_slice())
                        .ok()
                        .map(u16::from_be_bytes)
                };
                match id {
                    Some(id) => Outcome::reply(&ack(0x70, id)),
                    None => Outcome::reject("malformed_pubrel"),
                }
            }
            TYPE_SUBSCRIBE => on_subscribe(level, &pkt.body),
            TYPE_UNSUBSCRIBE => match parse_unsubscribe(level, &pkt.body) {
                Some((id, count)) if level == 5 => {
                    // UNSUBACK: packet id, empty properties, one reason code (0x00 success) per
                    // filter.
                    let mut reply = vec![0xB0];
                    reply.extend(encode_varint(3 + count));
                    reply.extend_from_slice(&id.to_be_bytes());
                    reply.push(0x00);
                    reply.extend(std::iter::repeat_n(0x00, count));
                    Outcome::reply(&reply)
                }
                Some((id, _)) => Outcome::reply(&ack(0xB0, id)),
                None => Outcome::reject("malformed_unsubscribe"),
            },
            TYPE_PINGREQ if pkt.body.is_empty() => Outcome::reply(&PINGRESP),
            TYPE_AUTH => on_auth(&pkt.body),
            TYPE_DISCONNECT => Outcome::close(),
            _ => Outcome::reject("malformed_packet"),
        }
    }

    fn on_connect(&mut self, body: &[u8]) -> Outcome {
        let Some(connect) = parse_connect(body) else {
            return Outcome::reject("malformed_connect");
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
        if connect.level == 5 {
            add_connect_properties(&mut metadata, &connect.properties);
        }
        self.connected = true;
        self.level = connect.level;
        self.keepalive = connect.keepalive;
        self.client_id = Some(connect.client_id);
        // Every CONNECT is accepted and logged as a login attempt, so credential brute-forcing
        // across connections is captured.
        Outcome {
            reply: if connect.level == 5 {
                CONNACK_V5_ACCEPTED.to_vec()
            } else {
                CONNACK_ACCEPTED.to_vec()
            },
            events: vec![Observation {
                signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
                authenticated: true,
                metadata,
            }],
            ..Outcome::default()
        }
    }

    /// The session-end summary: counts only, no attacker-controlled text beyond the sanitized
    /// client id already logged at CONNECT.
    pub fn end_observation(&self, bytes_in: u64, duration: Duration) -> Observation {
        let mut metadata = serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "packets": self.packets,
            "publishes": self.publishes,
            "subscribes": self.subscribes,
            "bytes_in": bytes_in,
            "duration_ms": u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        });
        if let Some(id) = &self.client_id {
            metadata["client_id"] = serde_json::Value::String(id.clone());
        }
        Observation {
            signal_type: SIGNAL_HONEYPOT_SESSION_END,
            authenticated: false,
            metadata,
        }
    }
}

/// A 5.0 AUTH (re-authentication or an enhanced-auth step). The sensor completes it: reply AUTH
/// with reason 0x00 (success) and no properties, and record the reason and method name. The
/// Authentication-Data is a credential and is never kept.
fn on_auth(body: &[u8]) -> Outcome {
    let mut c = Cursor::new(body);
    let Some((reason, props)) = reason_and_properties(&mut c) else {
        return Outcome::reject("malformed_auth");
    };
    // 0x00 success, 0x18 continue authentication, 0x19 re-authenticate.
    if !matches!(reason, 0x00 | 0x18 | 0x19) {
        return Outcome::reject("malformed_auth");
    }
    let mut metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "command": "AUTH",
        "reason_code": reason,
    });
    if let Some(method) = &props.auth_method {
        metadata["auth_method"] = serde_json::Value::String(method.clone());
    }
    flag_parse_error(&mut metadata, &props);
    Outcome {
        reply: AUTH_V5_SUCCESS.to_vec(),
        events: vec![Observation {
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC,
            authenticated: false,
            metadata,
        }],
        ..Outcome::default()
    }
}

fn on_publish(level: u8, pkt: &Packet) -> Outcome {
    let Some(publish) = parse_publish(level, pkt.flags, &pkt.body) else {
        return Outcome::reject("malformed_publish");
    };
    let (preview, encoding) = payload_preview(publish.payload);
    let digest = Sha256::digest(publish.payload);
    let mut metadata = serde_json::json!({
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
    // Topic aliasing is recorded, never resolved: nothing is delivered, so no alias table exists.
    if let Some(alias) = publish.properties.topic_alias {
        metadata["topic_alias"] = alias.into();
    }
    flag_parse_error(&mut metadata, &publish.properties);
    let reply = match (publish.qos, publish.packet_id) {
        (1, Some(id)) => ack(0x40, id).to_vec(),
        (2, Some(id)) => ack(0x50, id).to_vec(),
        _ => Vec::new(),
    };
    // The metadata event above is always emitted (so the topic and preview survive a refused or
    // dropped capture). A payload that looks binary is additionally spooled as a potential sample;
    // text and control payloads stay metadata-only.
    let capture = looks_binary(publish.payload).then(|| {
        let topic = text(publish.topic, MAX_FIELD_LEN);
        let mut fields = serde_json::json!({
            "topic": topic,
            "qos": publish.qos,
            "retain": publish.retain,
            "dup": publish.dup,
            "capture_reason": CAPTURE_REASON_BINARY_PUBLISH,
        });
        if let Some(alias) = publish.properties.topic_alias {
            fields["topic_alias"] = alias.into();
        }
        CaptureRequest {
            payload_len: publish.payload.len(),
            orig_name: (!topic.is_empty()).then_some(topic),
            fields,
        }
    });
    Outcome {
        reply,
        events: vec![Observation {
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC,
            authenticated: false,
            metadata,
        }],
        capture,
        ..Outcome::default()
    }
}

fn on_subscribe(level: u8, body: &[u8]) -> Outcome {
    let Some(sub) = parse_subscribe(level, body) else {
        return Outcome::reject("malformed_subscribe");
    };
    // SUBACK failure code for an invalid filter: 0x80 in 3.1.1, 0x8F (topic filter invalid) in 5.0.
    let invalid = if level == 5 { 0x8F } else { 0x80 };
    let mut granted = Vec::with_capacity(sub.filters.len());
    let mut topics = Vec::new();
    let mut qos = Vec::new();
    for (i, (filter, requested)) in sub.filters.iter().enumerate() {
        granted.push(if valid_filter(filter) {
            (*requested).min(1)
        } else {
            invalid
        });
        if i < MAX_LOGGED_TOPICS {
            topics.push(text(filter, MAX_FIELD_LEN));
            qos.push(*requested);
        }
    }
    let props_len = usize::from(level == 5);
    let mut reply = vec![0x90];
    reply.extend(encode_varint(2 + props_len + granted.len()));
    reply.extend_from_slice(&sub.packet_id.to_be_bytes());
    if level == 5 {
        reply.push(0x00);
    }
    reply.extend_from_slice(&granted);
    let mut metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "command": "SUBSCRIBE",
        "topics": topics,
        "qos": qos,
        "topic_count": sub.filters.len(),
    });
    flag_parse_error(&mut metadata, &sub.properties);
    Outcome {
        reply,
        events: vec![Observation {
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC,
            authenticated: false,
            metadata,
        }],
        ..Outcome::default()
    }
}

// ---------------------------------------------------------------------------------------------
// Socket loop
// ---------------------------------------------------------------------------------------------

/// Mark an event as having arrived over TLS. The key is absent (not `false`) on a plaintext
/// connection so plaintext events stay byte-identical to a sensor with no TLS configured.
fn stamp_tls(metadata: &mut serde_json::Value, tls: bool) {
    if tls {
        metadata["tls"] = serde_json::Value::Bool(true);
    }
}

/// Build the hand-off job for a spooled PUBLISH payload. The payload is charged to the
/// capture-memory budget as it is copied in: a budget that cannot hold all of it leaves a prefix
/// (`complete` false here, and the hand-off stamps `truncated` / `end_reason` itself), and one that
/// holds none of it makes `submit` refuse the job. The packet was read whole, so a payload the
/// budget did not cut is complete.
fn capture_job(
    handoff: &CaptureHandoff,
    request: CaptureRequest,
    payload: &[u8],
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    tls: bool,
) -> CaptureJob {
    let mut body = handoff.new_capture_body();
    let complete = body.extend_from_slice(payload).is_ok();
    let wire_size = payload.len() as u64;
    let CaptureRequest {
        orig_name, fields, ..
    } = request;
    CaptureJob {
        body,
        orig_name: orig_name.unwrap_or_else(|| format!("mqtt-publish-{session_id}")),
        event_builder: Box::new(move |sample: SampleRef| {
            let mut metadata = upload_metadata(PROTOCOL_LABEL, &sample, wire_size, complete);
            if let (Some(map), Some(extra)) = (metadata.as_object_mut(), fields.as_object()) {
                map.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
            stamp_tls(&mut metadata, tls);
            SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: PROTOCOL_LABEL.to_string(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.to_string(),
                protocol: PROTO_TCP.to_string(),
                // Every CONNECT is accepted, and a PUBLISH is only reachable after one.
                authenticated: true,
                observed_at: chrono::Utc::now(),
                metadata,
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    tls: bool,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let source_ip: IpAddr = normalize_dual_stack(peer_addr).ip();
    let wan_ip = local_addr
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
    let record = async |obs: Observation| {
        let mut metadata = obs.metadata;
        stamp_tls(&mut metadata, tls);
        let _ = emitter
            .append(&identify(obs.signal_type, obs.authenticated, metadata))
            .await;
    };

    record(Observation {
        signal_type: SIGNAL_HONEYPOT_CONNECTION,
        authenticated: false,
        metadata: serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
    })
    .await;

    let started = Instant::now();
    let mut session = Session::default();
    let mut total_read: u64 = 0;
    for _ in 0..MAX_PACKETS {
        let idle = keepalive_idle(bounds.idle_timeout, session.keepalive);
        let mut head = Vec::new();
        let packet = match read_packet_within(
            &mut stream,
            &bounds,
            &mut total_read,
            idle,
            &mut head,
        )
        .await
        {
            Ok(packet) => packet,
            Err(err) => {
                if !session.connected() && total_read > 0 {
                    record(malformed_observation(err.reason(), total_read, &head)).await;
                }
                break;
            }
        };
        let was_connected = session.connected();
        let outcome = session.on_packet(&packet);
        for obs in outcome.events {
            record(obs).await;
        }
        if let Some(request) = outcome.capture {
            // The payload is the tail of the packet body (see `CaptureRequest`).
            let start = packet.body.len().saturating_sub(request.payload_len);
            let payload = packet.body.get(start..).unwrap_or_default();
            let _ = handoff.submit(capture_job(
                &handoff, request, payload, source_ip, wan_ip, session_id, tls,
            ));
        }
        if !was_connected && let Some(reason) = outcome.reject {
            record(malformed_observation(
                reason,
                total_read,
                &packet_head(&packet),
            ))
            .await;
        }
        if !outcome.reply.is_empty() {
            // Flushed inside the same bound: a TLS stream may hold the reply in its record buffer.
            let write = tokio::time::timeout(bounds.idle_timeout, async {
                stream.write_all(&outcome.reply).await?;
                stream.flush().await
            })
            .await;
            if !matches!(write, Ok(Ok(()))) {
                break;
            }
        }
        if outcome.close {
            break;
        }
    }
    record(session.end_observation(total_read, started.elapsed())).await;
    // Sends close_notify on a TLS stream so a real client sees a clean close, not a truncation.
    let _ = tokio::time::timeout(bounds.idle_timeout, stream.shutdown()).await;
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

    /// A 5.0 CONNECT body with an explicit properties block (`props` is the block content).
    fn connect_body_v5(flags: u8, props: &[u8], rest: &[u8]) -> Vec<u8> {
        let mut b = lenp(b"MQTT");
        b.push(5);
        b.push(flags);
        b.extend_from_slice(&60u16.to_be_bytes());
        b.extend(encode_varint(props.len()));
        b.extend_from_slice(props);
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

    fn connected_v5() -> Session {
        let mut s = Session::default();
        let out = s.on_packet(&pkt(1, 0, connect_body(5, 0x02, &lenp(b"cid5"))));
        assert!(!out.close);
        assert_eq!(out.reply, CONNACK_V5_ACCEPTED);
        s
    }

    /// `block` content = a properties block body; helpers build one property each.
    fn prop_u8(id: u8, v: u8) -> Vec<u8> {
        vec![id, v]
    }
    fn prop_u16(id: u8, v: u16) -> Vec<u8> {
        [vec![id], v.to_be_bytes().to_vec()].concat()
    }
    fn prop_u32(id: u8, v: u32) -> Vec<u8> {
        [vec![id], v.to_be_bytes().to_vec()].concat()
    }
    fn prop_str(id: u8, s: &[u8]) -> Vec<u8> {
        [vec![id], lenp(s)].concat()
    }
    fn prop_pair(k: &[u8], v: &[u8]) -> Vec<u8> {
        [vec![0x26], lenp(k), lenp(v)].concat()
    }

    /// A properties block as it appears on the wire: length varint, then the content.
    fn block(content: &[u8]) -> Vec<u8> {
        [encode_varint(content.len()), content.to_vec()].concat()
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
        assert!(
            out.events[0].metadata.get("auth_method").is_none(),
            "a 3.1.1 login carries no 5.0 property fields"
        );
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
    fn connect_level5_is_accepted_with_a_v5_connack_and_logged() {
        let out =
            Session::default().on_packet(&pkt(1, 0, connect_body(5, 0x02, &lenp(b"v5client"))));
        assert_eq!(out.reply, vec![0x20, 0x03, 0x00, 0x00, 0x00]);
        assert!(!out.close, "a 5.0 session stays engaged");
        assert_eq!(out.events.len(), 1);
        let m = &out.events[0].metadata;
        assert_eq!(m["protocol_level"], 5);
        assert_eq!(m["client_id"], "v5client");
        assert!(m.get("auth_method").is_none());
        assert!(m.get("properties_parse_error").is_none());
    }

    #[test]
    fn connect_level5_logs_properties_and_never_the_auth_data_or_password() {
        let mut props = prop_str(0x15, b"SCRAM-SHA-256");
        props.extend(prop_str(0x16, b"SECRET-AUTH-DATA"));
        props.extend(prop_u32(0x11, 3600));
        props.extend(prop_u16(0x21, 20));
        props.extend(prop_u32(0x27, 65_535));
        props.extend(prop_u16(0x22, 8));
        props.extend(prop_u8(0x19, 1));
        props.extend(prop_pair(b"agent", b"mqtt-scan/1.0"));
        let mut rest = lenp(b"v5-scanner");
        rest.extend(lenp(b"root"));
        rest.extend(lenp(b"toor-secret"));
        let body = connect_body_v5(0xC2, &props, &rest);

        let c = parse_connect(&body).unwrap();
        assert_eq!(c.username.as_deref(), Some("root"));
        let out = Session::default().on_packet(&pkt(1, 0, body));
        assert_eq!(out.reply, CONNACK_V5_ACCEPTED);
        let m = &out.events[0].metadata;
        assert_eq!(m["protocol_level"], 5);
        assert_eq!(m["auth_method"], "SCRAM-SHA-256");
        assert_eq!(m["session_expiry"], 3600);
        assert_eq!(m["receive_max"], 20);
        assert_eq!(m["max_packet_size"], 65_535);
        assert_eq!(m["topic_alias_max"], 8);
        assert_eq!(m["request_response_info"], 1);
        assert_eq!(m["user_properties"][0]["name"], "agent");
        assert_eq!(m["user_properties"][0]["value"], "mqtt-scan/1.0");
        let dump = serde_json::to_string(m).unwrap();
        assert!(
            !dump.contains("SECRET-AUTH-DATA"),
            "auth data leaked: {dump}"
        );
        assert!(!dump.contains("toor-secret"), "password leaked: {dump}");
        assert!(m.get("properties_parse_error").is_none());
    }

    #[test]
    fn connect_level5_will_properties_are_skipped_before_the_will_topic() {
        // Will properties (will delay + user property) sit before the will topic; wrongly
        // handling their length would shift the topic, payload, username and password.
        let will_props = [prop_u32(0x18, 30), prop_pair(b"k", b"v")].concat();
        let mut rest = lenp(b"c");
        rest.extend(block(&will_props));
        rest.extend(lenp(b"will/topic"));
        rest.extend(lenp(b"gone"));
        rest.extend(lenp(b"user"));
        rest.extend(lenp(b"pw"));
        let c = parse_connect(&connect_body_v5(0xC6, &prop_u16(0x21, 5), &rest)).unwrap();
        assert_eq!(c.client_id, "c");
        assert_eq!(c.will_topic.as_deref(), Some("will/topic"));
        assert_eq!(c.will_payload_len, Some(4));
        assert_eq!(c.username.as_deref(), Some("user"));
        assert_eq!(c.properties.receive_max, Some(5));
    }

    #[test]
    fn connect_level5_bad_property_is_flagged_but_the_packet_still_parses() {
        // Unknown identifier 0x7E inside a block that fits: flagged, the client id after it intact.
        let props = [prop_u32(0x11, 7), vec![0x7E, 0x01, 0x02]].concat();
        let body = connect_body_v5(0x02, &props, &lenp(b"after-props"));
        let c = parse_connect(&body).unwrap();
        assert_eq!(c.client_id, "after-props");
        assert!(c.properties.parse_error);
        assert_eq!(
            c.properties.session_expiry,
            Some(7),
            "read before the error"
        );
        let out = Session::default().on_packet(&pkt(1, 0, body));
        assert!(!out.close);
        assert_eq!(out.events[0].metadata["properties_parse_error"], true);
    }

    #[test]
    fn connect_level5_properties_length_past_the_packet_is_malformed() {
        let mut b = lenp(b"MQTT");
        b.push(5);
        b.push(0x02);
        b.extend_from_slice(&60u16.to_be_bytes());
        b.extend(encode_varint(500)); // declares 500 bytes, supplies a client id only
        b.extend(lenp(b"c"));
        assert!(parse_connect(&b).is_none());
        let out = Session::default().on_packet(&pkt(1, 0, b));
        assert!(out.close);
        assert_eq!(out.reject, Some("malformed_connect"));
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
        assert!(
            parse_connect(&connect_body(5, 0x42, &pw)).is_some(),
            "5.0 allows a password without a username"
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
    fn properties_decode_every_recon_field() {
        let content = [
            prop_u32(0x11, 0x0102_0304),
            prop_u16(0x21, 100),
            prop_u32(0x27, 1_048_576),
            prop_u16(0x22, 10),
            prop_u16(0x23, 3),
            prop_u8(0x19, 1),
            prop_str(0x15, b"K-AUTH"),
            prop_pair(b"a", b"b"),
            prop_pair(b"c", b"d"),
        ]
        .concat();
        let p = parse_properties(&content);
        assert!(!p.parse_error);
        assert_eq!(p.session_expiry, Some(0x0102_0304));
        assert_eq!(p.receive_max, Some(100));
        assert_eq!(p.max_packet_size, Some(1_048_576));
        assert_eq!(p.topic_alias_max, Some(10));
        assert_eq!(p.topic_alias, Some(3));
        assert_eq!(p.request_response_info, Some(1));
        assert_eq!(p.auth_method.as_deref(), Some("K-AUTH"));
        assert_eq!(
            p.user_properties,
            vec![("a".into(), "b".into()), ("c".into(), "d".into())]
        );
        assert_eq!(p.user_property_count, 2);
    }

    #[test]
    fn properties_skip_every_other_defined_type_by_wire_width() {
        // One of each non-recon property; a wrong width for any desynchronizes the final marker.
        let content = [
            prop_u8(0x01, 1),
            prop_u32(0x02, 9),
            prop_str(0x03, b"text/plain"),
            prop_str(0x08, b"resp/topic"),
            prop_str(0x09, &[0xDE, 0xAD]),
            vec![0x0B, 0x80, 0x01], // subscription identifier, 2-byte varint
            prop_u16(0x13, 30),
            prop_str(0x12, b"assigned"),
            prop_u8(0x17, 1),
            prop_u32(0x18, 5),
            prop_str(0x1A, b"info"),
            prop_str(0x1C, b"server-ref"),
            prop_str(0x1F, b"reason"),
            prop_u8(0x24, 1),
            prop_u8(0x25, 1),
            prop_u8(0x28, 1),
            prop_u8(0x29, 1),
            prop_u8(0x2A, 1),
            prop_u32(0x11, 777), // marker
        ]
        .concat();
        let p = parse_properties(&content);
        assert!(!p.parse_error, "{p:?}");
        assert_eq!(p.session_expiry, Some(777));
    }

    #[test]
    fn properties_read_authentication_data_to_advance_and_drop_it() {
        let content = [
            prop_str(0x15, b"GS2-KRB5"),
            prop_str(0x16, b"TOPSECRET-AUTH-BYTES"),
            prop_u16(0x21, 42), // only reachable if the auth data was stepped over exactly
        ]
        .concat();
        let p = parse_properties(&content);
        assert!(!p.parse_error);
        assert_eq!(p.auth_method.as_deref(), Some("GS2-KRB5"));
        assert_eq!(p.receive_max, Some(42));
        assert!(!format!("{p:?}").contains("TOPSECRET"));
    }

    #[test]
    fn properties_malformed_blocks_set_the_flag_and_never_panic() {
        // Unknown identifier.
        assert!(parse_properties(&[0x7E, 0x00]).parse_error);
        // A fixed-width value cut short.
        assert!(parse_properties(&[0x11, 0x00, 0x01]).parse_error);
        // A string whose 2-byte length overruns the block.
        assert!(parse_properties(&[0x15, 0x00, 0xFF, b'a']).parse_error);
        // A user property whose value is missing.
        assert!(parse_properties(&[0x26, 0x00, 0x01, b'k']).parse_error);
        // An identifier varint that never terminates inside the block.
        assert!(parse_properties(&[0x80, 0x80, 0x80]).parse_error);
        // Values read before the bad property survive.
        let p = parse_properties(&[prop_u16(0x21, 9), vec![0x7E]].concat());
        assert!(p.parse_error);
        assert_eq!(p.receive_max, Some(9));
        // The empty block is valid.
        assert_eq!(parse_properties(&[]), Properties::default());
    }

    #[test]
    fn properties_cap_the_property_count_and_the_logged_user_properties() {
        // 64 properties are read; the 65th trips the cap even though it is well-formed.
        let at_cap = prop_u8(0x01, 0).repeat(MAX_PROPERTIES);
        assert!(!parse_properties(&at_cap).parse_error);
        let over = prop_u8(0x01, 0).repeat(MAX_PROPERTIES + 1);
        assert!(parse_properties(&over).parse_error);

        let users: Vec<u8> = (0..40u8)
            .flat_map(|i| prop_pair(format!("k{i}").as_bytes(), b"v"))
            .collect();
        let p = parse_properties(&users);
        assert_eq!(p.user_properties.len(), MAX_LOGGED_USER_PROPERTIES);
        assert_eq!(p.user_property_count, 40);
        assert_eq!(p.user_properties[0].0, "k0");
        assert!(!p.parse_error);
    }

    #[test]
    fn properties_user_text_is_sanitized_and_bounded() {
        let long = vec![b'z'; 5000];
        let content = [
            prop_pair(b"na\x1b[2Jme", &long),
            prop_str(0x15, b"meth\r\nod"),
        ]
        .concat();
        let p = parse_properties(&content);
        let (name, value) = &p.user_properties[0];
        assert!(!name.contains('\x1b'));
        assert!(value.chars().count() <= MAX_FIELD_LEN);
        assert!(!p.auth_method.as_deref().unwrap().contains('\n'));
    }

    #[test]
    fn properties_truncated_anywhere_never_panic() {
        let full = [
            prop_str(0x15, b"M"),
            prop_str(0x16, b"D"),
            prop_pair(b"k", b"v"),
            prop_u32(0x11, 1),
            vec![0x0B, 0xFF, 0x7F],
        ]
        .concat();
        assert!(!parse_properties(&full).parse_error);
        for cut in 0..full.len() {
            let _ = parse_properties(&full[..cut]);
        }
    }

    #[test]
    fn publish_level5_payload_starts_after_the_properties_block() {
        // The block is 200+ bytes so its length is a two-byte varint (a one-byte assumption would
        // shift the boundary), and it carries user text, so a payload that began at the wrong
        // offset would differ in length, preview and hash.
        let content = [
            prop_u8(0x01, 1),
            prop_u16(0x23, 7),
            prop_pair(b"trace", &[b'x'; 200]),
        ]
        .concat();
        assert!(content.len() > 127);
        let mut body = lenp(b"a/b");
        body.extend_from_slice(&[0x12, 0x34]); // qos1 packet id
        body.extend(block(&content));
        body.extend_from_slice(b"hello");
        let mut s = connected_v5();
        let out = s.on_packet(&pkt(3, 0x02, body));
        assert_eq!(out.reply, vec![0x40, 0x02, 0x12, 0x34]);
        let m = &out.events[0].metadata;
        assert_eq!(m["topic"], "a/b");
        assert_eq!(m["payload_len"], 5);
        assert_eq!(m["payload_preview"], "hello");
        assert_eq!(
            m["payload_sha256"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(m["topic_alias"], 7);
    }

    #[test]
    fn publish_level5_with_an_empty_block_and_an_empty_payload() {
        let mut body = lenp(b"t");
        body.push(0x00);
        let p = parse_publish(5, 0, &body).unwrap();
        assert_eq!(p.payload, b"");
        assert!(!p.properties.parse_error);
    }

    #[test]
    fn publish_level4_does_not_skip_bytes_that_look_like_properties() {
        // The same bytes a 5.0 PUBLISH would treat as a properties block are payload at level 4.
        let mut body = lenp(b"t");
        body.extend(block(&prop_u8(0x01, 1)));
        body.extend_from_slice(b"hello");
        let mut s = connected();
        let out = s.on_packet(&pkt(3, 0, body));
        // 1 length byte + 2 property bytes + "hello": all payload at level 4.
        assert_eq!(out.events[0].metadata["payload_len"], 8);
        assert!(out.events[0].metadata.get("topic_alias").is_none());
    }

    #[test]
    fn publish_level5_topic_alias_with_an_empty_topic_is_recorded() {
        let mut s = connected_v5();
        let mut body = lenp(b"");
        body.extend(block(&prop_u16(0x23, 4)));
        body.extend_from_slice(b"x");
        let out = s.on_packet(&pkt(3, 0, body));
        assert!(!out.close);
        assert_eq!(out.events[0].metadata["topic"], "");
        assert_eq!(out.events[0].metadata["topic_alias"], 4);
    }

    #[test]
    fn publish_level5_properties_overrun_and_bad_property() {
        let mut s = connected_v5();
        let mut overrun = lenp(b"t");
        overrun.extend(encode_varint(300));
        overrun.extend_from_slice(b"short");
        assert!(s.on_packet(&pkt(3, 0, overrun)).close, "length past packet");
        let mut s = connected_v5();
        let mut bad = lenp(b"t");
        bad.extend(block(&[0x7E, 0x00]));
        bad.extend_from_slice(b"body");
        let out = s.on_packet(&pkt(3, 0, bad));
        assert!(!out.close, "a bad property does not fail the packet");
        assert_eq!(out.events[0].metadata["properties_parse_error"], true);
        assert_eq!(out.events[0].metadata["payload_len"], 4);
    }

    #[test]
    fn subscribe_level5_is_answered_in_v5_form() {
        let mut s = connected_v5();
        let mut body = vec![0x00, 0x2A];
        body.extend(block(&[vec![0x0B, 0x05], prop_pair(b"k", b"v")].concat()));
        body.extend(lenp(b"sensors/#"));
        body.push(0x02); // qos 2
        body.extend(lenp(b"a/+/b"));
        body.push(0x24); // qos 0, retain handling 2, no-local off
        body.extend(lenp(b"bad#filter"));
        body.push(0x01);
        let out = s.on_packet(&pkt(8, 2, body));
        // id, empty properties, then min(qos,1), 0, 0x8F topic-filter-invalid.
        assert_eq!(out.reply, vec![0x90, 6, 0x00, 0x2A, 0x00, 1, 0, 0x8F]);
        let m = &out.events[0].metadata;
        assert_eq!(m["command"], "SUBSCRIBE");
        assert_eq!(m["topics"][0], "sensors/#");
        assert_eq!(m["qos"][0], 2);
        assert_eq!(m["topic_count"], 3);
    }

    #[test]
    fn subscribe_level5_rejects_reserved_option_bits() {
        for options in [0x03u8, 0x40, 0x80, 0x30] {
            let mut s = connected_v5();
            let mut body = vec![0, 1, 0x00];
            body.extend(lenp(b"t"));
            body.push(options);
            assert!(s.on_packet(&pkt(8, 2, body)).close, "options {options:#x}");
        }
        // Properties length past the packet.
        let mut s = connected_v5();
        assert!(s.on_packet(&pkt(8, 2, vec![0, 1, 0x7F, 0x00])).close);
    }

    #[test]
    fn unsubscribe_level5_answers_one_reason_per_filter() {
        let mut s = connected_v5();
        let mut body = vec![0, 7];
        body.extend(block(&prop_pair(b"k", b"v")));
        body.extend(lenp(b"a/b"));
        body.extend(lenp(b"c/d"));
        let out = s.on_packet(&pkt(10, 2, body));
        assert_eq!(out.reply, vec![0xB0, 5, 0, 7, 0x00, 0x00, 0x00]);
        assert!(s.on_packet(&pkt(10, 2, vec![0, 7, 0])).close, "no filters");
    }

    #[test]
    fn level5_acks_are_parsed_and_pubrel_is_answered() {
        let mut s = connected_v5();
        // PUBREL: short form, reason only, and reason plus properties.
        assert_eq!(
            s.on_packet(&pkt(6, 2, vec![0, 9])).reply,
            vec![0x70, 2, 0, 9]
        );
        assert_eq!(
            s.on_packet(&pkt(6, 2, vec![0, 9, 0x00])).reply,
            vec![0x70, 2, 0, 9]
        );
        let with_props = [vec![0, 9, 0x92], block(&prop_str(0x1F, b"why"))].concat();
        assert_eq!(
            s.on_packet(&pkt(6, 2, with_props)).reply,
            vec![0x70, 2, 0, 9]
        );
        // Stray PUBACK/PUBREC/PUBCOMP (no server PUBLISH exists): accepted, no reply, no close.
        for t in [4u8, 5, 7] {
            let out = s.on_packet(&pkt(t, 0, vec![0, 3, 0x10, 0x00]));
            assert!(!out.close && out.reply.is_empty(), "type {t}");
        }
        // Trailing junk after the properties, or a properties length overrun, is malformed.
        assert!(s.on_packet(&pkt(6, 2, vec![0, 9, 0, 0, 0xFF])).close);
        assert!(s.on_packet(&pkt(4, 0, vec![0, 9, 0, 0x7F])).close);
    }

    #[test]
    fn level5_only_packet_types_stay_refused_at_level_4() {
        let mut s = connected();
        for t in [4u8, 5, 7, 15] {
            assert!(
                s.on_packet(&pkt(t, 0, vec![0, 1])).close,
                "type {t} at 3.1.1"
            );
        }
        // PUBREL at 3.1.1 keeps the strict two-byte body.
        let mut s = connected();
        assert!(s.on_packet(&pkt(6, 2, vec![0, 9, 0x00])).close);
    }

    #[test]
    fn auth_is_completed_with_success_and_the_data_is_dropped() {
        let mut s = connected_v5();
        let props = [
            prop_str(0x15, b"SCRAM-SHA-1"),
            prop_str(0x16, b"AUTHBLOB-SECRET"),
        ]
        .concat();
        let body = [vec![0x19], block(&props)].concat();
        let out = s.on_packet(&pkt(15, 0, body));
        assert_eq!(out.reply, vec![0xF0, 0x02, 0x00, 0x00]);
        assert!(!out.close);
        let m = &out.events[0].metadata;
        assert_eq!(m["command"], "AUTH");
        assert_eq!(m["reason_code"], 0x19);
        assert_eq!(m["auth_method"], "SCRAM-SHA-1");
        assert!(!serde_json::to_string(m).unwrap().contains("AUTHBLOB"));
        // The empty form is reason 0x00.
        assert_eq!(s.on_packet(&pkt(15, 0, vec![])).reply, AUTH_V5_SUCCESS);
        // A reason a client cannot send, and bad flags, close.
        assert!(s.on_packet(&pkt(15, 0, vec![0x04, 0x00])).close);
        let mut s = connected_v5();
        assert!(s.on_packet(&pkt(15, 1, vec![])).close);
    }

    #[test]
    fn level5_ping_disconnect_and_double_connect() {
        let mut s = connected_v5();
        assert_eq!(s.on_packet(&pkt(12, 0, vec![])).reply, PINGRESP);
        assert_eq!(
            s.on_packet(&pkt(1, 0, connect_body(5, 0x02, &lenp(b"x"))))
                .reject,
            Some("duplicate_connect")
        );
        let out = s.on_packet(&pkt(14, 0, vec![0x00, 0x00]));
        assert!(
            out.close && out.reject.is_none(),
            "DISCONNECT is a clean close"
        );
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
    fn rejections_carry_a_reason() {
        let mut s = Session::default();
        assert_eq!(
            s.on_packet(&pkt(12, 0, vec![])).reject,
            Some("first_packet_not_connect")
        );
        assert_eq!(
            s.on_packet(&pkt(0, 0, vec![])).reject,
            Some("first_packet_not_connect")
        );
        assert_eq!(
            s.on_packet(&pkt(1, 5, connect_body(4, 0x02, &lenp(b"c"))))
                .reject,
            Some("bad_fixed_header_flags")
        );
        assert_eq!(
            s.on_packet(&pkt(1, 0, connect_body(4, 0x03, &lenp(b"c"))))
                .reject,
            Some("malformed_connect")
        );
        let mut s = connected();
        assert_eq!(
            s.on_packet(&pkt(0, 0, vec![])).reject,
            Some("unsupported_packet_type")
        );
        assert_eq!(
            s.on_packet(&pkt(12, 1, vec![])).reject,
            Some("bad_fixed_header_flags")
        );
    }

    #[test]
    fn malformed_observation_is_bounded_hex_never_raw_text() {
        let raw = vec![0xFFu8; 500];
        let obs = malformed_observation("malformed_connect", 500, &raw);
        assert_eq!(obs.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert!(!obs.authenticated);
        let m = &obs.metadata;
        assert_eq!(m["malformed"], true);
        assert_eq!(m["reason"], "malformed_connect");
        assert_eq!(m["bytes_seen"], 500);
        assert_eq!(m["protocol_label"], "mqtt");
        assert_eq!(
            m["first_bytes_hex"].as_str().unwrap().len(),
            MALFORMED_SNIPPET_BYTES * 2
        );
        // A rejected packet is fingerprinted from its header, length and body prefix.
        let head = packet_head(&pkt(1, 0, vec![0xAB; 1000]));
        assert_eq!(&head[..3], &[0x10, 0xE8, 0x07]);
        assert_eq!(head.len(), 3 + MALFORMED_SNIPPET_BYTES);
    }

    #[test]
    fn keepalive_bounds_the_idle_wait() {
        let idle = Duration::from_secs(60);
        assert_eq!(keepalive_idle(idle, 0), idle, "0 disables the client bound");
        assert_eq!(keepalive_idle(idle, 10), Duration::from_secs(15));
        assert_eq!(keepalive_idle(idle, 1), Duration::from_millis(1500));
        assert_eq!(keepalive_idle(idle, 40), idle, "never above idle_timeout");
        assert_eq!(keepalive_idle(idle, 65_535), idle);
    }

    #[test]
    fn session_end_counts_packets_publishes_and_subscribes() {
        let mut s = connected_v5();
        s.on_packet(&pkt(3, 0, [lenp(b"t"), vec![0], b"x".to_vec()].concat()));
        s.on_packet(&pkt(3, 0, [lenp(b"t"), vec![0], b"y".to_vec()].concat()));
        let mut sub = vec![0, 1, 0];
        sub.extend(lenp(b"a"));
        sub.push(0);
        s.on_packet(&pkt(8, 2, sub));
        s.on_packet(&pkt(12, 0, vec![]));
        // A refused PUBLISH counts as a packet but not as a publish.
        s.on_packet(&pkt(3, 0x06, lenp(b"t")));
        let obs = s.end_observation(321, Duration::from_millis(1234));
        assert_eq!(obs.signal_type, SIGNAL_HONEYPOT_SESSION_END);
        let m = &obs.metadata;
        assert_eq!(m["packets"], 6);
        assert_eq!(m["publishes"], 2);
        assert_eq!(m["subscribes"], 1);
        assert_eq!(m["bytes_in"], 321);
        assert_eq!(m["duration_ms"], 1234);
        assert_eq!(m["client_id"], "cid5");
        assert_eq!(m["protocol_label"], "mqtt");

        let never = Session::default().end_observation(0, Duration::ZERO);
        assert!(never.metadata.get("client_id").is_none());
        assert_eq!(never.metadata["packets"], 0);
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
        assert!(s.on_packet(&pkt(15, 0, vec![])).close, "AUTH at 3.1.1");
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

    fn publish_outcome(topic: &[u8], payload: &[u8]) -> Outcome {
        connected().on_packet(&pkt(3, 0x01, [lenp(topic), payload.to_vec()].concat()))
    }

    #[test]
    fn binary_publish_requests_a_capture_and_text_does_not() {
        let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
        elf.extend_from_slice(&[0u8; 56]);
        let out = publish_outcome(b"fw/update", &elf);
        let req = out.capture.expect("an ELF payload is spooled");
        assert_eq!(req.payload_len, elf.len());
        assert_eq!(req.orig_name.as_deref(), Some("fw/update"));
        assert_eq!(req.fields["topic"], "fw/update");
        assert_eq!(req.fields["qos"], 0);
        assert_eq!(req.fields["retain"], true);
        assert_eq!(req.fields["dup"], false);
        assert_eq!(req.fields["capture_reason"], "binary_publish_payload");
        assert_eq!(out.events.len(), 1, "the metadata event is still emitted");
        assert_eq!(out.events[0].signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);

        for text in [
            br#"{"cmd":"reboot","delay":5}"#.as_slice(),
            b"hello\r\nworld\t!",
            b"",
        ] {
            assert!(publish_outcome(b"t", text).capture.is_none(), "{text:?}");
        }
    }

    #[test]
    fn capture_gate_flips_at_the_shared_looks_binary_threshold() {
        // looks_binary is strictly more than 30% non-printable: 3 of 10 is text, 4 of 10 is binary.
        let at_threshold = [b'a', b'a', b'a', b'a', b'a', b'a', b'a', 0, 0, 0];
        let over = [b'a', b'a', b'a', b'a', b'a', b'a', 0, 0, 0, 0];
        assert!(publish_outcome(b"t", &at_threshold).capture.is_none());
        assert!(publish_outcome(b"t", &over).capture.is_some());
        // Valid UTF-8 beyond ASCII is non-printable to the gate, exactly as for the shell sensors.
        assert!(publish_outcome(b"t", "ééééé".as_bytes()).capture.is_some());
    }

    #[test]
    fn capture_name_is_the_sanitized_bounded_topic_or_absent() {
        let bin = [0xFFu8; 8];
        let long = vec![b'z'; 5000];
        let out = publish_outcome(&[b"x\r\ny\x1b[2J".as_slice(), &long].concat(), &bin);
        let name = out.capture.unwrap().orig_name.unwrap();
        assert!(name.chars().count() <= MAX_FIELD_LEN);
        assert!(!name.contains('\n') && !name.contains('\x1b'));
        assert!(
            publish_outcome(b"", &bin)
                .capture
                .unwrap()
                .orig_name
                .is_none()
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
    async fn read_packet_records_the_head_for_a_fingerprint() {
        let b = test_bounds();
        let mut head = Vec::new();
        let five = [0x30u8, 0x80, 0x80, 0x80, 0x80, 0x01];
        let err = read_packet_within(&mut &five[..], &b, &mut 0, b.idle_timeout, &mut head)
            .await
            .unwrap_err();
        assert_eq!(err, ReadError::Malformed);
        assert_eq!(err.reason(), "bad_remaining_length");
        assert_eq!(head, vec![0x30, 0x80, 0x80, 0x80, 0x80]);
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

    #[tokio::test]
    async fn arbitrary_5_0_shaped_bytes_never_panic_and_stay_bounded() {
        // A valid 5.0 CONNECT whose properties block is random (with a correct length, so the
        // parser is genuinely reached), followed by 5.0 packets of every type carrying random
        // properties-shaped bodies.
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let b = test_bounds();
        let tail_firsts = [
            0x30u8, 0x32, 0x34, 0x40, 0x50, 0x62, 0x70, 0x82, 0xA2, 0xC0, 0xE0, 0xF0,
        ];
        for _ in 0..400 {
            let props_len = (next() % 80) as usize;
            let props: Vec<u8> = (0..props_len).map(|_| next() as u8).collect();
            let will = next() % 2 == 0;
            let flags = if will { 0x06 } else { 0x02 };
            let mut conn = connect_body_v5(flags, &props, &[]);
            conn.extend(lenp(b"id"));
            if will {
                let wp: Vec<u8> = (0..(next() % 20) as usize).map(|_| next() as u8).collect();
                conn.extend(block(&wp));
                conn.extend(lenp(b"w"));
                conn.extend(lenp(b"p"));
            }
            let mut data = vec![0x10];
            data.extend(encode_varint(conn.len()));
            data.extend(conn);
            for _ in 0..(next() % 6) {
                let first = tail_firsts[(next() % tail_firsts.len() as u64) as usize];
                let body: Vec<u8> = (0..(next() % 90) as usize).map(|_| next() as u8).collect();
                data.push(first);
                data.extend(encode_varint(body.len()));
                data.extend(body);
            }
            let mut session = Session::default();
            let mut total = 0u64;
            let mut input = &data[..];
            for _ in 0..MAX_PACKETS {
                let Ok(p) = read_packet(&mut input, &b, &mut total).await else {
                    break;
                };
                let out = session.on_packet(&p);
                assert!(out.reply.len() <= 6 + p.body.len());
                for obs in &out.events {
                    let dump = serde_json::to_string(&obs.metadata).unwrap();
                    assert!(dump.len() < 64 * 1024, "event unbounded: {}", dump.len());
                }
                if out.close {
                    break;
                }
            }
            assert!(total <= data.len() as u64);
        }
        // The properties parser alone, on raw random blocks of every small length.
        for len in 0..200 {
            let raw: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let p = parse_properties(&raw);
            assert!(p.user_properties.len() <= MAX_LOGGED_USER_PROPERTIES);
        }
    }
}
