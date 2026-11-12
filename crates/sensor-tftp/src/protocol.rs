//! TFTP wire format (RFC 1350) as far as this sensor speaks it: parse any inbound datagram, and
//! build the only two packet kinds the sensor ever sends, ACK and ERROR. There is deliberately no
//! DATA builder: the sensor has no way to serve file content.

/// Fixed block size. The sensor never negotiates options (RFC 2347: a server that does not
/// support options ignores them), so every transfer uses the RFC 1350 default.
pub const BLOCK_SIZE: usize = 512;

/// Largest legal DATA packet: opcode + block number + a full block.
pub const MAX_DATA_PACKET: usize = 4 + BLOCK_SIZE;

pub const OP_RRQ: u16 = 1;
pub const OP_WRQ: u16 = 2;
pub const OP_DATA: u16 = 3;
pub const OP_ACK: u16 = 4;
pub const OP_ERROR: u16 = 5;
pub const OP_OACK: u16 = 6;

pub const ERR_FILE_NOT_FOUND: u16 = 1;
pub const ERR_DISK_FULL: u16 = 3;
pub const ERR_ILLEGAL_OPERATION: u16 = 4;

/// Message carried by the one reply an RRQ ever gets. The wire text real tftpd-hpa uses.
pub const MSG_FILE_NOT_FOUND: &str = "File not found";
pub const MSG_DISK_FULL: &str = "Disk full or allocation exceeded";
pub const MSG_ILLEGAL_OPERATION: &str = "Illegal TFTP operation";

/// An ERROR packet is opcode (2) + code (2) + message + NUL.
const ERROR_OVERHEAD: usize = 5;

/// Longest ERROR packet the sensor ever builds: the "File not found" reply, 19 bytes. Disk-full and
/// illegal-operation messages are cut to fit the same ceiling, so no reply the sensor emits
/// exceeds a fixed, tiny size regardless of what the peer sent.
pub const MAX_ERROR_PACKET: usize = ERROR_OVERHEAD + MSG_FILE_NOT_FOUND.len();

/// Transfer mode named in a request (RFC 1350 section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Netascii,
    Octet,
    Mail,
}

impl Mode {
    /// Modes are case-insensitive on the wire.
    pub fn from_bytes(raw: &[u8]) -> Option<Mode> {
        if raw.eq_ignore_ascii_case(b"netascii") {
            Some(Mode::Netascii)
        } else if raw.eq_ignore_ascii_case(b"octet") {
            Some(Mode::Octet)
        } else if raw.eq_ignore_ascii_case(b"mail") {
            Some(Mode::Mail)
        } else {
            None
        }
    }
}

/// The fields an RRQ or WRQ carries. Anything after the mode (RFC 2347 options) is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub filename: &'a [u8],
    pub mode: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    Rrq(Request<'a>),
    Wrq(Request<'a>),
    Data { block: u16, payload: &'a [u8] },
    Ack { block: u16 },
    Error { code: u16, message: &'a [u8] },
    Oack { options: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    UnknownOpcode(u16),
    /// A request whose filename or mode is not NUL-terminated.
    Unterminated,
    /// An ACK that is not exactly four bytes.
    BadLength,
}

/// Parse one datagram. Total over arbitrary bytes: every input yields a packet or a `ParseError`,
/// never a panic, because the bytes come straight from an untrusted peer.
pub fn parse(buf: &[u8]) -> Result<Packet<'_>, ParseError> {
    let [hi, lo, rest @ ..] = buf else {
        return Err(ParseError::TooShort);
    };
    match u16::from_be_bytes([*hi, *lo]) {
        OP_RRQ => parse_request(rest).map(Packet::Rrq),
        OP_WRQ => parse_request(rest).map(Packet::Wrq),
        OP_DATA => match rest {
            [b0, b1, payload @ ..] => Ok(Packet::Data {
                block: u16::from_be_bytes([*b0, *b1]),
                payload,
            }),
            _ => Err(ParseError::TooShort),
        },
        OP_ACK => match rest {
            [b0, b1] => Ok(Packet::Ack {
                block: u16::from_be_bytes([*b0, *b1]),
            }),
            [] | [_] => Err(ParseError::TooShort),
            _ => Err(ParseError::BadLength),
        },
        OP_ERROR => match rest {
            [c0, c1, message @ ..] => {
                let end = message
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(message.len());
                Ok(Packet::Error {
                    code: u16::from_be_bytes([*c0, *c1]),
                    message: &message[..end],
                })
            }
            _ => Err(ParseError::TooShort),
        },
        OP_OACK => Ok(Packet::Oack { options: rest }),
        other => Err(ParseError::UnknownOpcode(other)),
    }
}

fn parse_request(body: &[u8]) -> Result<Request<'_>, ParseError> {
    let (filename, rest) = split_cstr(body).ok_or(ParseError::Unterminated)?;
    let (mode, _options) = split_cstr(rest).ok_or(ParseError::Unterminated)?;
    Ok(Request { filename, mode })
}

/// Split at the first NUL: the bytes before it and everything after it. `None` when there is no NUL.
fn split_cstr(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = bytes.iter().position(|&b| b == 0)?;
    Some((&bytes[..end], &bytes[end + 1..]))
}

pub fn ack(block: u16) -> [u8; 4] {
    let b = block.to_be_bytes();
    [0, OP_ACK as u8, b[0], b[1]]
}

/// Build an ERROR packet no longer than `max_len`, cutting the message to fit. `None` when even the
/// empty-message form (five bytes) does not fit, in which case the caller sends nothing.
pub fn error(code: u16, message: &str, max_len: usize) -> Option<Vec<u8>> {
    let ceiling = max_len.min(MAX_ERROR_PACKET);
    if ceiling < ERROR_OVERHEAD {
        return None;
    }
    let keep = message.len().min(ceiling - ERROR_OVERHEAD);
    let mut out = Vec::with_capacity(ERROR_OVERHEAD + keep);
    out.extend_from_slice(&OP_ERROR.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&message.as_bytes()[..keep]);
    out.push(0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rrq(filename: &[u8], mode: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 1];
        v.extend_from_slice(filename);
        v.push(0);
        v.extend_from_slice(mode);
        v.push(0);
        v
    }

    #[test]
    fn parses_rrq_and_wrq() {
        let frame = rrq(b"boot.bin", b"octet");
        assert_eq!(
            parse(&frame),
            Ok(Packet::Rrq(Request {
                filename: b"boot.bin",
                mode: b"octet"
            }))
        );
        let mut wrq = frame.clone();
        wrq[1] = 2;
        assert!(matches!(parse(&wrq), Ok(Packet::Wrq(_))));
    }

    #[test]
    fn request_options_after_the_mode_are_ignored() {
        let mut frame = rrq(b"f", b"octet");
        frame.extend_from_slice(b"blksize\x001428\x00");
        assert_eq!(
            parse(&frame),
            Ok(Packet::Rrq(Request {
                filename: b"f",
                mode: b"octet"
            }))
        );
    }

    #[test]
    fn unterminated_requests_are_rejected() {
        assert_eq!(parse(b"\x00\x01name"), Err(ParseError::Unterminated));
        assert_eq!(
            parse(b"\x00\x02name\x00octet"),
            Err(ParseError::Unterminated)
        );
        assert_eq!(parse(b"\x00\x01"), Err(ParseError::Unterminated));
    }

    #[test]
    fn parses_data_ack_error_oack() {
        assert_eq!(
            parse(&[0, 3, 0, 7, 0xAA, 0xBB]),
            Ok(Packet::Data {
                block: 7,
                payload: &[0xAA, 0xBB]
            })
        );
        assert_eq!(
            parse(&[0, 3, 0xFF, 0xFF]),
            Ok(Packet::Data {
                block: 65535,
                payload: &[]
            })
        );
        assert_eq!(parse(&[0, 4, 1, 2]), Ok(Packet::Ack { block: 258 }));
        assert_eq!(
            parse(b"\x00\x05\x00\x02denied\x00"),
            Ok(Packet::Error {
                code: 2,
                message: b"denied"
            })
        );
        assert_eq!(
            parse(b"\x00\x06blksize\x00512\x00"),
            Ok(Packet::Oack {
                options: b"blksize\x00512\x00"
            })
        );
    }

    #[test]
    fn truncated_and_oversized_frames_are_errors_not_panics() {
        assert_eq!(parse(&[]), Err(ParseError::TooShort));
        assert_eq!(parse(&[0]), Err(ParseError::TooShort));
        assert_eq!(parse(&[0, 3, 0]), Err(ParseError::TooShort));
        assert_eq!(parse(&[0, 4, 0]), Err(ParseError::TooShort));
        assert_eq!(parse(&[0, 4, 0, 1, 0]), Err(ParseError::BadLength));
        assert_eq!(parse(&[0, 5, 0]), Err(ParseError::TooShort));
        assert_eq!(parse(&[0, 0, 1, 2]), Err(ParseError::UnknownOpcode(0)));
        assert_eq!(parse(&[0xFF, 0xFF]), Err(ParseError::UnknownOpcode(0xFFFF)));
    }

    /// Every prefix of every valid frame, then a deterministic pseudo-random corpus, must parse or
    /// error without panicking. The corpus is seeded, so a failure reproduces.
    #[test]
    fn malformed_frame_fuzz_never_panics() {
        let seeds: Vec<Vec<u8>> = vec![
            rrq(b"a", b"octet"),
            rrq(b"", b""),
            {
                let mut v = rrq(b"x", b"netascii");
                v.extend_from_slice(b"tsize\x000\x00");
                v
            },
            vec![0, 3, 0, 1, 1, 2, 3],
            vec![0, 4, 0, 9],
            b"\x00\x05\x00\x01boom\x00".to_vec(),
            b"\x00\x06blksize\x00512\x00".to_vec(),
        ];
        let mut checked = 0usize;
        for seed in &seeds {
            for end in 0..=seed.len() {
                let _ = parse(&seed[..end]);
                checked += 1;
            }
        }
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 600) as usize;
            let mut frame: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Half the corpus gets a real opcode so the per-opcode branches are exercised, not
            // just UnknownOpcode.
            if frame.len() >= 2 && next() % 2 == 0 {
                frame[0] = 0;
                frame[1] = (next() % 7) as u8;
            }
            let _ = parse(&frame);
            checked += 1;
        }
        assert!(checked > 20_000);
    }

    #[test]
    fn ack_packet_is_four_bytes() {
        assert_eq!(ack(0), [0, 4, 0, 0]);
        assert_eq!(ack(0x0102), [0, 4, 1, 2]);
    }

    #[test]
    fn error_packet_fits_its_ceiling_and_round_trips() {
        let full = error(ERR_FILE_NOT_FOUND, MSG_FILE_NOT_FOUND, usize::MAX).unwrap();
        assert_eq!(full.len(), MAX_ERROR_PACKET);
        assert_eq!(MAX_ERROR_PACKET, 19);
        assert_eq!(
            parse(&full),
            Ok(Packet::Error {
                code: 1,
                message: MSG_FILE_NOT_FOUND.as_bytes()
            })
        );
        // A long message is cut to the fixed ceiling no matter what the caller allows.
        let capped = error(ERR_DISK_FULL, MSG_DISK_FULL, usize::MAX).unwrap();
        assert_eq!(capped.len(), MAX_ERROR_PACKET);
        // A tight budget shortens the message instead of exceeding it.
        let tight = error(ERR_FILE_NOT_FOUND, MSG_FILE_NOT_FOUND, 8).unwrap();
        assert_eq!(tight.len(), 8);
        assert_eq!(*tight.last().unwrap(), 0);
        let minimal = error(ERR_FILE_NOT_FOUND, MSG_FILE_NOT_FOUND, 5).unwrap();
        assert_eq!(minimal, vec![0, 5, 0, 1, 0]);
        // Under five bytes nothing can be sent.
        assert_eq!(error(ERR_FILE_NOT_FOUND, MSG_FILE_NOT_FOUND, 4), None);
        assert_eq!(error(ERR_FILE_NOT_FOUND, MSG_FILE_NOT_FOUND, 0), None);
    }

    #[test]
    fn modes_are_case_insensitive_and_closed() {
        assert_eq!(Mode::from_bytes(b"OCTET"), Some(Mode::Octet));
        assert_eq!(Mode::from_bytes(b"NetAscii"), Some(Mode::Netascii));
        assert_eq!(Mode::from_bytes(b"mail"), Some(Mode::Mail));
        assert_eq!(Mode::from_bytes(b"binary"), None);
        assert_eq!(Mode::from_bytes(b""), None);
    }
}
