//! Capture sanitization: the single shared chokepoint every sensor routes attacker-controlled
//! text through before it can enter an event record. See "Capture sanitization contract" in
//! `internal/design/02-sensor-framework.md` and part 3 of ADR-0010 for the threat this closes: an
//! uncompromised sensor talked into emitting a forged second event line via an unescaped
//! CR/LF, terminal escape, or bidirectional override in captured evidence.
//!
//! The order of operations below is load-bearing. Stripping control characters before collapsing
//! CR/LF/tab/VT/FF is the classic mistake: removing a character adjacent to a bare CR or LF can
//! leave it standing alone, and the record is forged anyway. So whitespace collapsing always runs
//! first, against the raw input, before anything else looks at it.

use unicode_normalization::UnicodeNormalization;

/// Neutralize one attacker-controlled value for safe inclusion in a wire event record.
///
/// Order of operations (see the module doc for why it is fixed):
/// 1. Collapse each run of CR/LF/tab/VT/FF to a single space.
/// 2. Strip ANSI CSI escape sequences, C0/C1 controls, line separators, bidirectional
///    overrides/isolates, and zero-width/invisible format characters.
/// 3. Normalize to NFC.
/// 4. Truncate to `max_len` bytes without splitting a UTF-8 character.
pub fn sanitize_value(input: &str, max_len: usize) -> String {
    let spaced = collapse_line_breaking_whitespace(input);
    let stripped = strip_dangerous(&spaced);
    let normalized: String = stripped.nfc().collect();
    truncate_to_len(&normalized, max_len)
}

/// Render a byte slice as lowercase hex, reading at most `max_bytes` of it. Byte-derived fields
/// (a captured sample, a protocol banner) carry only hex or a digest, never decoded text: hex
/// cannot express a newline, a control character, or a markup delimiter, so it is safe by its
/// alphabet rather than by a function call.
pub fn to_hex_bounded(bytes: &[u8], max_bytes: usize) -> String {
    let limit = max_bytes.min(bytes.len());
    bytes[..limit].iter().map(|b| format!("{b:02x}")).collect()
}

/// Collapse each maximal run of CR, LF, tab, vertical tab, or form feed into a single space.
/// Must run before any other stripping - see the module doc's order-of-operations rationale.
fn collapse_line_breaking_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_run = false;
    for ch in input.chars() {
        if matches!(ch, '\r' | '\n' | '\t' | '\x0B' | '\x0C') {
            if !in_run {
                out.push(' ');
                in_run = true;
            }
        } else {
            out.push(ch);
            in_run = false;
        }
    }
    out
}

/// Strip ANSI terminal escapes and the Unicode characters with no legitimate role in captured
/// evidence: control codes, bidirectional overrides/isolates, and invisible/zero-width format
/// characters. Combining marks (General Category Mn/Mc, e.g. U+0301 COMBINING ACUTE ACCENT) are
/// not in this set, so NFC/NFD text normalizes correctly in the step that follows.
fn strip_dangerous(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1B}' && chars.peek() == Some(&'[') {
            chars.next(); // consume the '['
            consume_csi_tail(&mut chars);
            continue;
        }
        if is_dangerous(ch) {
            continue;
        }
        out.push(ch);
    }
    out
}

/// Consume an ANSI CSI sequence's parameter/intermediate bytes (0x20-0x3F) up to and including
/// its final byte (0x40-0x7E), per ECMA-48. A tail with no final byte (truncated input) drains to
/// the first character outside that range instead of running away, so a malformed escape can
/// never hang the sanitizer or swallow unrelated trailing text.
fn consume_csi_tail(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&next) = chars.peek() {
        let cp = next as u32;
        if (0x40..=0x7E).contains(&cp) {
            chars.next();
            return;
        }
        if (0x20..=0x3F).contains(&cp) {
            chars.next();
            continue;
        }
        return;
    }
}

fn is_dangerous(ch: char) -> bool {
    matches!(ch as u32,
        // C0 controls (CR/LF/tab/VT/FF are already gone by this point) and DEL.
        0x00..=0x1F | 0x7F
        // C1 controls.
        | 0x80..=0x9F
        // Unicode line and paragraph separators.
        | 0x2028 | 0x2029
        // Bidi marks, embeddings/overrides, and isolates.
        | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
        // Zero-width space/joiner/non-joiner and the BOM (ZERO WIDTH NO-BREAK SPACE).
        | 0x200B..=0x200D | 0xFEFF
        // Remaining Cf format characters with no legitimate role here: word joiner and the
        // invisible math operators, and the Unicode tag block (the ASCII-smuggling vector built
        // on characters designed to ride along invisibly with a flag-emoji sequence).
        | 0x2060..=0x2064
        | 0xE0000..=0xE007F
    )
}

/// Truncate to at most `max_len` bytes, landing on a UTF-8 char boundary rather than splitting a
/// multi-byte code point - which would panic on a naive `&s[..max_len]` slice.
fn truncate_to_len(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_lf_replaced_with_space() {
        assert_eq!(sanitize_value("line1\r\nline2", 256), "line1 line2");
        assert_eq!(sanitize_value("a\nb\rc", 256), "a b c");
    }

    #[test]
    fn bare_cr_replaced() {
        assert_eq!(sanitize_value("before\rafter", 256), "before after");
    }

    #[test]
    fn tab_vt_ff_replaced() {
        assert_eq!(sanitize_value("a\tb\x0Bc\x0Cd", 256), "a b c d");
    }

    #[test]
    fn ansi_csi_stripped() {
        // ESC[31m = red color, ESC[0m = reset
        assert_eq!(sanitize_value("\x1b[31mred\x1b[0m", 256), "red");
    }

    #[test]
    fn c0_control_chars_stripped() {
        // BEL (0x07), BS (0x08), DEL (0x7F)
        assert_eq!(sanitize_value("hel\x07lo\x08wo\x7Frld", 256), "helloworld");
    }

    #[test]
    fn c1_control_range_stripped() {
        // C1 range: U+0080 - U+009F
        let input = "before\u{0085}after"; // NEL
        assert_eq!(sanitize_value(input, 256), "beforeafter");
    }

    #[test]
    fn unicode_line_separators_stripped() {
        assert_eq!(sanitize_value("a\u{2028}b\u{2029}c", 256), "abc");
    }

    #[test]
    fn bidi_overrides_stripped() {
        // LRO (U+202D), RLO (U+202E), LRI (U+2066), PDI (U+2069)
        assert_eq!(
            sanitize_value("normal\u{202D}evil\u{202E}text\u{2069}", 256),
            "normaleviltext"
        );
    }

    #[test]
    fn zero_width_chars_stripped() {
        // ZWSP (U+200B), ZWJ (U+200D), ZWNJ (U+200C), FEFF (BOM)
        assert_eq!(
            sanitize_value("a\u{200B}b\u{200D}c\u{200C}d\u{FEFF}e", 256),
            "abcde"
        );
    }

    #[test]
    fn nfc_normalization() {
        // e + combining acute (NFD) -> e-acute (NFC)
        let nfd = "e\u{0301}";
        let nfc = "\u{00E9}";
        assert_eq!(sanitize_value(nfd, 256), nfc);
    }

    #[test]
    fn length_cap() {
        let long = "a".repeat(500);
        let result = sanitize_value(&long, 100);
        assert!(result.len() <= 100);
    }

    #[test]
    fn combined_attack_single_line() {
        let attack = "cmd\r\n\x1b[31m{\"v\":1,\"signal_type\":\"evil\"}\x1b[0m\ttail\u{202E}";
        let result = sanitize_value(attack, 256);
        assert!(!result.contains('\n'));
        assert!(!result.contains('\r'));
        assert!(!result.contains('\x1b'));
        assert!(!result.contains('\u{202E}'));
    }

    #[test]
    fn empty_string_passthrough() {
        assert_eq!(sanitize_value("", 256), "");
    }

    #[test]
    fn valid_text_passthrough() {
        let valid = "normal command -flag value";
        assert_eq!(sanitize_value(valid, 256), valid);
    }

    #[test]
    fn order_of_operations_cr_lf_before_control_strip() {
        // If control strip happened first, a \r\n could survive if the strip
        // removed something adjacent. The spec's order: whitespace replacement
        // FIRST, then control strip. This test catches the classic mistake.
        let input = "a\x01\r\nb"; // SOH + CRLF
        let result = sanitize_value(input, 256);
        assert!(!result.contains('\n'), "newline survived");
        assert_eq!(result, "a b");
    }

    #[test]
    fn hex_bounded_encoding() {
        let bytes = b"\xde\xad\xbe\xef\xca\xfe";
        assert_eq!(to_hex_bounded(bytes, 4), "deadbeef");
        assert_eq!(to_hex_bounded(bytes, 6), "deadbeefcafe");
        assert_eq!(to_hex_bounded(bytes, 100), "deadbeefcafe");
        assert_eq!(to_hex_bounded(b"", 100), "");
    }

    // The two tests below are not in the task brief's given suite. Both cover a load-bearing
    // requirement stated in prose (truncate on a char boundary; a malformed escape must not hang
    // or panic) that none of the given fixtures exercise: every given ANSI/length input is either
    // well-formed or pure ASCII, so a naive implementation (byte-slice truncation, an unbounded
    // CSI scan) would pass the whole suite above and still be broken.

    #[test]
    fn truncate_respects_char_boundary() {
        // The euro sign (U+20AC) is 3 bytes in UTF-8; max_len=5 lands inside it. A naive byte
        // slice (`&s[..max_len]`) panics on a non-boundary index; a lossy cut could emit a
        // replacement character. The correct behavior is to back off to the last full character.
        let input = "aaaa\u{20AC}bbbb";
        let result = sanitize_value(input, 5);
        assert_eq!(result, "aaaa");
        assert!(result.len() <= 5);
    }

    #[test]
    fn malformed_csi_does_not_panic_or_hang() {
        // An escape sequence truncated before its final byte must not panic, hang, or leak the
        // raw ESC into the record.
        let result = sanitize_value("abc\x1b[", 256);
        assert!(!result.contains('\x1b'));
    }
}
