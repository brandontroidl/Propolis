//! RESP (REdis Serialization Protocol) parsing and response encoding: pure, I/O-free logic with
//! no `TcpStream` of its own, mirroring sensor-telnet's `telnet` module and sensor-ssh's
//! `auth`/`channel` modules' own "no I/O of its own" convention so this logic is deterministic and
//! testable without a live socket. `handler.rs` is the only place that touches an actual
//! `TcpStream`; it feeds accumulated socket bytes through [`parse_command`] and writes the bytes
//! this module's encoders produce.
//!
//! Redis clients speak two wire forms of the same command stream (see
//! `internal/design/08-remaining-sensors.md`'s "sensor-redis" section): an inline form
//! (`PING\r\n`, whitespace-separated arguments on one line - what `redis-cli`'s piped mode and
//! ad-hoc `nc`/telnet-style probing use) and the multi-bulk array form
//! (`*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n` - what the real `redis-cli` and every client library send).
//! [`parse_command`] recognizes both from the leading byte (`*` selects multi-bulk, anything else
//! is inline) and returns identical `Vec<String>` args either way, so `handler.rs`'s dispatch
//! logic never needs to know which form a given command arrived in.
//!
//! **Every bound below rejects on the attacker's *claim* before buffering to match it.** A
//! multi-bulk count or a bulk string length is checked against its cap the instant it is parsed
//! out of the header, before this module waits for that many bytes to actually arrive - so a
//! single `*999999999\r\n` or `$999999999\r\n` header is a protocol error immediately, never an
//! invitation to buffer gigabytes waiting for data that may never come. This parses bytes from a
//! peer that has not proven anything about itself (Redis has no transport-level handshake), so no
//! path through here may panic on truncated, malformed, or adversarially large input - see the
//! `proptest` fuzz-lite guards at the bottom of this module's test suite, mirroring
//! `sensor-telnet::telnet::IacFilter` and `sensor-ssh::auth::parse_userauth_request`'s own
//! never-panics convention.

/// Ceiling on a multi-bulk array's declared element count. No real Redis command needs more than
/// a few dozen arguments; generous enough for any legitimate command, small enough that a header
/// alone can never be used to force a large allocation.
const MAX_ARRAY_LEN: i64 = 1024;

/// Ceiling on one bulk string's declared byte length. Bounds a single `SET`/`EVAL` argument this
/// sensor will ever buffer; independent of `sensor_framework::ConnectionBounds::max_captured_bytes`
/// (the whole-session cap `handler.rs`'s read loop enforces separately) - this is the per-header
/// sanity bound that rejects an absurd single-field claim before any of that budget is spent.
const MAX_BULK_LEN: i64 = 512 * 1024;

/// Ceiling on an inline request line's length before a terminator (`\n`, optionally preceded by
/// `\r`) has been seen. Matches real Redis's own `PROTO_INLINE_MAX_SIZE` (64 KiB): generous for
/// any real command line, bounded so a client that never sends a newline cannot grow the buffer
/// unboundedly while every `parse_command` call keeps reporting `Incomplete`.
const MAX_INLINE_LEN: usize = 64 * 1024;

/// Ceiling on a multi-bulk header line (`*N\r\n` or `$M\r\n`) before its terminating `\r\n` has
/// been seen. Real headers are a handful of bytes (`*1024\r\n` is 7); this is generous enough for
/// any legitimate header and small enough to reject a client streaming digits with no CRLF long
/// before `MAX_INLINE_LEN` would.
const MAX_HEADER_LINE: usize = 32;

/// A parsing outcome for [`parse_command`]: either not enough bytes are buffered yet to complete
/// one command (the caller should read more from the socket and retry), or exactly one command was
/// parsed from the front of the buffer, along with how many bytes to drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// The buffered bytes are a valid prefix of a command but do not yet contain a complete one.
    Incomplete,
    /// One full command was parsed. `args` is empty for a blank inline line or a zero/negative
    /// multi-bulk count (both valid RESP, neither naming a command) - `handler.rs`'s read loop
    /// skips these and reads the next command rather than dispatching an empty one.
    Complete { args: Vec<String>, consumed: usize },
}

/// A structural RESP violation that reading more bytes could never fix (as opposed to
/// [`ParseOutcome::Incomplete`], which more bytes might resolve). Carries a human-readable reason
/// for logging; `handler.rs` does not match on the reason text, only on the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespError {
    Protocol(String),
}

/// Attempt to parse exactly one command from the front of `buf`. Never consumes partial data: on
/// [`ParseOutcome::Complete`], `consumed` bytes belong to this command and the rest of `buf` (if
/// any - a pipelining client can send several commands in one write) is left for the next call.
/// See the module doc for the inline-vs-multi-bulk dispatch rule and the early-rejection bound
/// guarantee.
pub fn parse_command(buf: &[u8]) -> Result<ParseOutcome, RespError> {
    if buf.is_empty() {
        return Ok(ParseOutcome::Incomplete);
    }
    if buf[0] == b'*' {
        parse_multibulk(buf)
    } else {
        parse_inline(buf)
    }
}

/// Parse the inline form: a single line, terminated by `\n` (optionally preceded by `\r`), split
/// on ASCII whitespace into arguments. See the module doc: this is what a plain `nc`/telnet-style
/// probe or `redis-cli --pipe` sends.
fn parse_inline(buf: &[u8]) -> Result<ParseOutcome, RespError> {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        if buf.len() > MAX_INLINE_LEN {
            return Err(RespError::Protocol("inline request too long".to_string()));
        }
        return Ok(ParseOutcome::Incomplete);
    };
    let line_end = if nl > 0 && buf[nl - 1] == b'\r' {
        nl - 1
    } else {
        nl
    };
    let consumed = nl + 1;
    let args: Vec<String> = String::from_utf8_lossy(&buf[..line_end])
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect();
    Ok(ParseOutcome::Complete { args, consumed })
}

/// Parse the multi-bulk array form: `*<count>\r\n` followed by `<count>` bulk strings
/// (`$<len>\r\n<data>\r\n` each). See the module doc for the early-rejection guarantee on both
/// `count` and each element's `len`.
fn parse_multibulk(buf: &[u8]) -> Result<ParseOutcome, RespError> {
    let Some((line_end, mut cursor)) = find_header_crlf(buf, 1)? else {
        return Ok(ParseOutcome::Incomplete);
    };
    let count: i64 = std::str::from_utf8(&buf[1..line_end])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| RespError::Protocol("invalid multibulk count".to_string()))?;

    if count > MAX_ARRAY_LEN {
        return Err(RespError::Protocol(format!(
            "multibulk count {count} exceeds maximum {MAX_ARRAY_LEN}"
        )));
    }
    if count <= 0 {
        // A zero or negative count names no command (RESP's null-array encoding uses -1) - valid
        // wire content, not a protocol error, but not a dispatchable command either. See
        // ParseOutcome::Complete's doc.
        return Ok(ParseOutcome::Complete {
            args: Vec::new(),
            consumed: cursor,
        });
    }

    let mut args = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(&marker) = buf.get(cursor) else {
            return Ok(ParseOutcome::Incomplete);
        };
        if marker != b'$' {
            return Err(RespError::Protocol(format!(
                "expected '$' bulk marker, got {:?}",
                marker as char
            )));
        }

        let Some((len_end, data_start)) = find_header_crlf(buf, cursor + 1)? else {
            return Ok(ParseOutcome::Incomplete);
        };
        let len: i64 = std::str::from_utf8(&buf[cursor + 1..len_end])
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| RespError::Protocol("invalid bulk length".to_string()))?;
        if len < 0 {
            return Err(RespError::Protocol(format!("negative bulk length {len}")));
        }
        if len > MAX_BULK_LEN {
            return Err(RespError::Protocol(format!(
                "bulk length {len} exceeds maximum {MAX_BULK_LEN}"
            )));
        }
        let len = len as usize;

        let data_end = data_start + len;
        let term_end = data_end + 2;
        if buf.len() < term_end {
            return Ok(ParseOutcome::Incomplete);
        }
        if &buf[data_end..term_end] != b"\r\n" {
            return Err(RespError::Protocol(
                "missing CRLF terminator after bulk data".to_string(),
            ));
        }

        args.push(String::from_utf8_lossy(&buf[data_start..data_end]).into_owned());
        cursor = term_end;
    }

    Ok(ParseOutcome::Complete {
        args,
        consumed: cursor,
    })
}

/// Scan `buf[start..]` for the first `\r\n`, bounded by [`MAX_HEADER_LINE`]. Returns
/// `Some((index_of_cr, index_after_lf))` once found, `None` if not yet present but still within
/// bound (caller should treat as [`ParseOutcome::Incomplete`]), or `Err` if the unterminated
/// header has already grown past the bound - a header line that long can never be legitimate (see
/// the module doc's early-rejection guarantee).
fn find_header_crlf(buf: &[u8], start: usize) -> Result<Option<(usize, usize)>, RespError> {
    let window_end = buf.len().min(start + MAX_HEADER_LINE);
    let mut i = start;
    while i + 1 < window_end {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Ok(Some((i, i + 2)));
        }
        i += 1;
    }
    if buf.len() - start > MAX_HEADER_LINE {
        return Err(RespError::Protocol("header line too long".to_string()));
    }
    Ok(None)
}

/// Encode a RESP simple string: `+<s>\r\n`. Used for `+OK`, `+PONG`, and similar fixed replies -
/// `s` is always a static, operator-authored literal in this crate, never attacker-controlled.
pub fn simple_string(s: &str) -> Vec<u8> {
    format!("+{s}\r\n").into_bytes()
}

/// Encode a RESP error reply: `-<s>\r\n`.
pub fn error_reply(s: &str) -> Vec<u8> {
    format!("-{s}\r\n").into_bytes()
}

/// Encode a RESP bulk string: `$<len>\r\n<s>\r\n`, length-prefixed in bytes (not chars), so this is
/// correct for any UTF-8 `s` including multi-byte characters.
pub fn bulk_string(s: &str) -> Vec<u8> {
    let mut out = format!("${}\r\n", s.len()).into_bytes();
    out.extend_from_slice(s.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// Encode the RESP null bulk string (`$-1\r\n`) - the required `GET` reply for a key that was
/// never actually stored (this sensor never persists anything - see `handler.rs`).
pub fn nil_bulk_string() -> Vec<u8> {
    b"$-1\r\n".to_vec()
}

/// Encode a RESP array of bulk strings: `*<n>\r\n` followed by each item's own [`bulk_string`]
/// encoding, in order. Used for `CONFIG GET`'s canned reply.
pub fn array_of_bulk_strings(items: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", items.len()).into_bytes();
    for item in items {
        out.extend_from_slice(&bulk_string(item));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------------------
    // encoders
    // ---------------------------------------------------------------------------------------

    #[test]
    fn simple_string_encodes_plus_prefix_and_crlf() {
        assert_eq!(simple_string("PONG"), b"+PONG\r\n");
        assert_eq!(simple_string("OK"), b"+OK\r\n");
    }

    #[test]
    fn error_reply_encodes_minus_prefix_and_crlf() {
        assert_eq!(
            error_reply("ERR unknown command"),
            b"-ERR unknown command\r\n"
        );
    }

    #[test]
    fn bulk_string_encodes_length_prefix_data_and_crlf() {
        assert_eq!(bulk_string("hello"), b"$5\r\nhello\r\n");
    }

    #[test]
    fn bulk_string_handles_empty_string() {
        assert_eq!(bulk_string(""), b"$0\r\n\r\n");
    }

    #[test]
    fn bulk_string_length_is_byte_length_not_char_count() {
        // "café" is 4 chars but 5 bytes (é is 2 bytes in UTF-8).
        assert_eq!(bulk_string("café"), "$5\r\ncafé\r\n".as_bytes());
    }

    #[test]
    fn nil_bulk_string_is_dollar_minus_one() {
        assert_eq!(nil_bulk_string(), b"$-1\r\n");
    }

    #[test]
    fn array_of_bulk_strings_encodes_count_and_each_item() {
        assert_eq!(
            array_of_bulk_strings(&["a", "bb"]),
            b"*2\r\n$1\r\na\r\n$2\r\nbb\r\n"
        );
    }

    #[test]
    fn array_of_bulk_strings_handles_empty_slice() {
        assert_eq!(array_of_bulk_strings(&[]), b"*0\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // parse_command - inline form
    // ---------------------------------------------------------------------------------------

    #[test]
    fn parse_empty_buffer_is_incomplete() {
        assert_eq!(parse_command(b"").unwrap(), ParseOutcome::Incomplete);
    }

    #[test]
    fn parse_inline_simple_command() {
        assert_eq!(
            parse_command(b"PING\r\n").unwrap(),
            ParseOutcome::Complete {
                args: vec!["PING".to_string()],
                consumed: 6,
            }
        );
    }

    #[test]
    fn parse_inline_bare_lf_terminator() {
        // Some non-conformant clients send a bare \n with no \r - real Redis accepts this too.
        assert_eq!(
            parse_command(b"PING\n").unwrap(),
            ParseOutcome::Complete {
                args: vec!["PING".to_string()],
                consumed: 5,
            }
        );
    }

    #[test]
    fn parse_inline_multiple_args_with_extra_whitespace() {
        let buf: &[u8] = b"SET  foo   bar\r\n";
        let outcome = parse_command(buf).unwrap();
        assert_eq!(
            outcome,
            ParseOutcome::Complete {
                args: vec!["SET".to_string(), "foo".to_string(), "bar".to_string()],
                consumed: buf.len(),
            }
        );
    }

    #[test]
    fn parse_inline_incomplete_no_terminator_yet() {
        assert_eq!(parse_command(b"PIN").unwrap(), ParseOutcome::Incomplete);
    }

    #[test]
    fn parse_inline_blank_line_is_complete_with_empty_args() {
        assert_eq!(
            parse_command(b"\r\n").unwrap(),
            ParseOutcome::Complete {
                args: vec![],
                consumed: 2,
            }
        );
    }

    #[test]
    fn parse_inline_too_long_without_terminator_is_protocol_error() {
        let buf = vec![b'A'; MAX_INLINE_LEN + 10];
        assert!(matches!(parse_command(&buf), Err(RespError::Protocol(_))));
    }

    #[test]
    fn parse_inline_leaves_pipelined_remainder_for_next_call() {
        let buf = b"PING\r\nPING\r\n";
        let ParseOutcome::Complete { args, consumed } = parse_command(buf).unwrap() else {
            panic!("expected Complete");
        };
        assert_eq!(args, vec!["PING".to_string()]);
        assert_eq!(consumed, 6);
        assert_eq!(
            parse_command(&buf[consumed..]).unwrap(),
            ParseOutcome::Complete {
                args: vec!["PING".to_string()],
                consumed: 6,
            }
        );
    }

    // ---------------------------------------------------------------------------------------
    // parse_command - multi-bulk array form
    // ---------------------------------------------------------------------------------------

    #[test]
    fn parse_multibulk_single_element() {
        assert_eq!(
            parse_command(b"*1\r\n$4\r\nPING\r\n").unwrap(),
            ParseOutcome::Complete {
                args: vec!["PING".to_string()],
                consumed: 14,
            }
        );
    }

    #[test]
    fn parse_multibulk_two_elements() {
        let buf: &[u8] = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        assert_eq!(
            parse_command(buf).unwrap(),
            ParseOutcome::Complete {
                args: vec!["GET".to_string(), "key".to_string()],
                consumed: buf.len(),
            }
        );
    }

    #[test]
    fn parse_multibulk_incomplete_mid_count_header() {
        assert_eq!(parse_command(b"*2\r").unwrap(), ParseOutcome::Incomplete);
    }

    #[test]
    fn parse_multibulk_incomplete_waiting_on_second_element() {
        assert_eq!(
            parse_command(b"*2\r\n$3\r\nGET\r\n").unwrap(),
            ParseOutcome::Incomplete
        );
    }

    #[test]
    fn parse_multibulk_incomplete_mid_bulk_data() {
        // Second bulk declares 3 bytes but only 2 have arrived, no trailing CRLF yet.
        assert_eq!(
            parse_command(b"*2\r\n$3\r\nGET\r\n$3\r\nke").unwrap(),
            ParseOutcome::Incomplete
        );
    }

    #[test]
    fn parse_multibulk_zero_count_is_complete_with_empty_args() {
        assert_eq!(
            parse_command(b"*0\r\n").unwrap(),
            ParseOutcome::Complete {
                args: vec![],
                consumed: 4,
            }
        );
    }

    #[test]
    fn parse_multibulk_negative_count_is_complete_with_empty_args() {
        // RESP's null-array encoding; never a real command, but must not crash or error - just
        // resolve to nothing, like a zero count.
        assert_eq!(
            parse_command(b"*-1\r\n").unwrap(),
            ParseOutcome::Complete {
                args: vec![],
                consumed: 5,
            }
        );
    }

    #[test]
    fn parse_multibulk_non_numeric_count_is_protocol_error() {
        assert!(matches!(
            parse_command(b"*abc\r\n"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_count_exceeding_max_rejected_before_elements_arrive() {
        // Only the header has arrived - no element bytes at all - yet this must already be a
        // protocol error, not Incomplete: the claim alone is rejected, never buffered toward.
        assert!(matches!(
            parse_command(b"*99999\r\n"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_header_too_long_without_terminator_is_protocol_error() {
        let mut buf = vec![b'*'];
        buf.extend(std::iter::repeat_n(b'1', 100));
        assert!(matches!(parse_command(&buf), Err(RespError::Protocol(_))));
    }

    #[test]
    fn parse_multibulk_missing_dollar_marker_is_protocol_error() {
        assert!(matches!(
            parse_command(b"*1\r\nXYZ\r\n"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_non_numeric_bulk_length_is_protocol_error() {
        assert!(matches!(
            parse_command(b"*1\r\n$abc\r\n"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_negative_bulk_length_is_protocol_error() {
        assert!(matches!(
            parse_command(b"*1\r\n$-5\r\n"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_bulk_length_exceeding_max_rejected_before_data_arrives() {
        // Only the "$600000\r\n" header has arrived (600000 > MAX_BULK_LEN) - must already be a
        // protocol error, not Incomplete waiting for 600000 bytes that may never come.
        assert!(matches!(
            parse_command(b"*1\r\n$600000\r\n"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_missing_trailing_crlf_after_data_is_protocol_error() {
        // Declares 3 bytes of data; the 2 bytes after that data are "XY", not "\r\n".
        assert!(matches!(
            parse_command(b"*1\r\n$3\r\nabcXY"),
            Err(RespError::Protocol(_))
        ));
    }

    #[test]
    fn parse_multibulk_three_elements_set_command() {
        let buf: &[u8] = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
        assert_eq!(
            parse_command(buf).unwrap(),
            ParseOutcome::Complete {
                args: vec!["SET".to_string(), "foo".to_string(), "bar".to_string()],
                consumed: buf.len(),
            }
        );
    }

    #[test]
    fn parse_multibulk_binary_unsafe_bytes_lossy_decoded_without_panic() {
        // Declared length 2, but the two bytes are not valid UTF-8 on their own. Must not panic -
        // lossy decoding is fine, this crate's sanitize_value chokepoint runs on the result before
        // it can ever reach an event anyway.
        let mut buf = b"*1\r\n$2\r\n".to_vec();
        buf.extend_from_slice(&[0xFF, 0xFE]);
        buf.extend_from_slice(b"\r\n");
        let outcome = parse_command(&buf).unwrap();
        assert!(matches!(outcome, ParseOutcome::Complete { .. }));
    }

    #[test]
    fn parse_multibulk_leaves_pipelined_remainder_for_next_call() {
        let buf = b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n";
        let ParseOutcome::Complete { consumed, .. } = parse_command(buf).unwrap() else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, 14);
        assert_eq!(
            parse_command(&buf[consumed..]).unwrap(),
            ParseOutcome::Complete {
                args: vec!["PING".to_string()],
                consumed: 14,
            }
        );
    }

    // ---------------------------------------------------------------------------------------
    // fuzz-lite guards - mirrors sensor-telnet::telnet::IacFilter and
    // sensor-ssh::auth::parse_userauth_request's own never-panics convention: this parses bytes
    // from an unauthenticated peer, so arbitrary (including malformed or truncated) input must
    // never panic, whatever it resolves to.
    // ---------------------------------------------------------------------------------------

    proptest::proptest! {
        #[test]
        fn parse_command_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=1024)
        ) {
            let _ = parse_command(&bytes);
        }

        /// Feeding the same input incrementally, one growing prefix at a time (simulating a slow
        /// client whose bytes trickle in across many small socket reads), must never panic either.
        #[test]
        fn parse_command_never_panics_on_incremental_prefixes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256)
        ) {
            for i in 0..=bytes.len() {
                let _ = parse_command(&bytes[..i]);
            }
        }
    }
}
