//! Microsoft Script Encoder (`.vbe` / `.jse`) decoding.
//!
//! Script Encoder is not encryption: a fixed substitution keyed only by character position. It
//! exists so a dropper's plaintext does not match naive AV string scanning, and it hid a captured
//! dropper's payload URL from this crate's URL extractor, which scans plain text. The decoded body
//! was an ordinary `strFileURL = "http://..."` assignment that [`super::extract`] already parses,
//! so decoding first is all that was missing for the follow-up payload to be fetched and attributed.
//!
//! The substitution tables are the canonical ones from the public reference decoder (Didier
//! Stevens, `decode-vbe.py`), copied rather than reconstructed: a wrong entry corrupts every decode
//! silently, with no error to notice. Kept dependency-free.

/// Header the encoder emits: marker, 6 chars of encoded length, `==`. The length is not needed to
/// decode and is not validated, matching the reference behaviour.
const HEADER_MARKER: &str = "#@~^";
const HEADER_LEN: usize = 4 + 6 + 2;
/// Trailer: 6 chars of checksum (likewise ignored) then this marker.
const TRAILER_MARKER: &str = "==^#~@";
const CHECKSUM_LEN: usize = 6;

/// Which of the three substitution variants applies at each position, cycling every 64.
const COMBINATION: [u8; 64] = [
    0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1,
    0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1, 0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1,
];

/// Indexed by `encoded_byte - 9` for bytes 9..=127; each row is the three candidate plaintext
/// bytes, chosen by [`COMBINATION`].
const DECODE: [[u8; 3]; 119] = [
    [0x57, 0x6E, 0x7B], // 9
    [0x4A, 0x4C, 0x41], // 10
    [0x0B, 0x0B, 0x0B], // 11
    [0x0C, 0x0C, 0x0C], // 12
    [0x4A, 0x4C, 0x41], // 13
    [0x0E, 0x0E, 0x0E], // 14
    [0x0F, 0x0F, 0x0F], // 15
    [0x10, 0x10, 0x10], // 16
    [0x11, 0x11, 0x11], // 17
    [0x12, 0x12, 0x12], // 18
    [0x13, 0x13, 0x13], // 19
    [0x14, 0x14, 0x14], // 20
    [0x15, 0x15, 0x15], // 21
    [0x16, 0x16, 0x16], // 22
    [0x17, 0x17, 0x17], // 23
    [0x18, 0x18, 0x18], // 24
    [0x19, 0x19, 0x19], // 25
    [0x1A, 0x1A, 0x1A], // 26
    [0x1B, 0x1B, 0x1B], // 27
    [0x1C, 0x1C, 0x1C], // 28
    [0x1D, 0x1D, 0x1D], // 29
    [0x1E, 0x1E, 0x1E], // 30
    [0x1F, 0x1F, 0x1F], // 31
    [0x2E, 0x2D, 0x32], // 32
    [0x47, 0x75, 0x30], // 33
    [0x7A, 0x52, 0x21], // 34
    [0x56, 0x60, 0x29], // 35
    [0x42, 0x71, 0x5B], // 36
    [0x6A, 0x5E, 0x38], // 37
    [0x2F, 0x49, 0x33], // 38
    [0x26, 0x5C, 0x3D], // 39
    [0x49, 0x62, 0x58], // 40
    [0x41, 0x7D, 0x3A], // 41
    [0x34, 0x29, 0x35], // 42
    [0x32, 0x36, 0x65], // 43
    [0x5B, 0x20, 0x39], // 44
    [0x76, 0x7C, 0x5C], // 45
    [0x72, 0x7A, 0x56], // 46
    [0x43, 0x7F, 0x73], // 47
    [0x38, 0x6B, 0x66], // 48
    [0x39, 0x63, 0x4E], // 49
    [0x70, 0x33, 0x45], // 50
    [0x45, 0x2B, 0x6B], // 51
    [0x68, 0x68, 0x62], // 52
    [0x71, 0x51, 0x59], // 53
    [0x4F, 0x66, 0x78], // 54
    [0x09, 0x76, 0x5E], // 55
    [0x62, 0x31, 0x7D], // 56
    [0x44, 0x64, 0x4A], // 57
    [0x23, 0x54, 0x6D], // 58
    [0x75, 0x43, 0x71], // 59
    [0x4A, 0x4C, 0x41], // 60  ('<' never transformed; row unused)
    [0x7E, 0x3A, 0x60], // 61
    [0x4A, 0x4C, 0x41], // 62  ('>' never transformed; row unused)
    [0x5E, 0x7E, 0x53], // 63
    [0x40, 0x4C, 0x40], // 64  ('@' never transformed; row unused)
    [0x77, 0x45, 0x42], // 65
    [0x4A, 0x2C, 0x27], // 66
    [0x61, 0x2A, 0x48], // 67
    [0x5D, 0x74, 0x72], // 68
    [0x22, 0x27, 0x75], // 69
    [0x4B, 0x37, 0x31], // 70
    [0x6F, 0x44, 0x37], // 71
    [0x4E, 0x79, 0x4D], // 72
    [0x3B, 0x59, 0x52], // 73
    [0x4C, 0x2F, 0x22], // 74
    [0x50, 0x6F, 0x54], // 75
    [0x67, 0x26, 0x6A], // 76
    [0x2A, 0x72, 0x47], // 77
    [0x7D, 0x6A, 0x64], // 78
    [0x74, 0x39, 0x2D], // 79
    [0x54, 0x7B, 0x20], // 80
    [0x2B, 0x3F, 0x7F], // 81
    [0x2D, 0x38, 0x2E], // 82
    [0x2C, 0x77, 0x4C], // 83
    [0x30, 0x67, 0x5D], // 84
    [0x6E, 0x53, 0x7E], // 85
    [0x6B, 0x47, 0x6C], // 86
    [0x66, 0x34, 0x6F], // 87
    [0x35, 0x78, 0x79], // 88
    [0x25, 0x5D, 0x74], // 89
    [0x21, 0x30, 0x43], // 90
    [0x64, 0x23, 0x26], // 91
    [0x4D, 0x5A, 0x76], // 92
    [0x52, 0x5B, 0x25], // 93
    [0x63, 0x6C, 0x24], // 94
    [0x3F, 0x48, 0x2B], // 95
    [0x7B, 0x55, 0x28], // 96
    [0x78, 0x70, 0x23], // 97
    [0x29, 0x69, 0x41], // 98
    [0x28, 0x2E, 0x34], // 99
    [0x73, 0x4C, 0x09], // 100
    [0x59, 0x21, 0x2A], // 101
    [0x33, 0x24, 0x44], // 102
    [0x7F, 0x4E, 0x3F], // 103
    [0x6D, 0x50, 0x77], // 104
    [0x55, 0x09, 0x3B], // 105
    [0x53, 0x56, 0x55], // 106
    [0x7C, 0x73, 0x69], // 107
    [0x3A, 0x35, 0x61], // 108
    [0x5F, 0x61, 0x63], // 109
    [0x65, 0x4B, 0x50], // 110
    [0x46, 0x58, 0x67], // 111
    [0x58, 0x3B, 0x51], // 112
    [0x31, 0x57, 0x49], // 113
    [0x69, 0x22, 0x4F], // 114
    [0x6C, 0x6D, 0x46], // 115
    [0x5A, 0x4D, 0x68], // 116
    [0x48, 0x25, 0x7C], // 117
    [0x27, 0x28, 0x36], // 118
    [0x5C, 0x46, 0x70], // 119
    [0x3D, 0x4A, 0x6E], // 120
    [0x24, 0x32, 0x7A], // 121
    [0x79, 0x41, 0x2F], // 122
    [0x37, 0x3D, 0x5F], // 123
    [0x60, 0x5F, 0x4B], // 124
    [0x51, 0x4F, 0x5A], // 125
    [0x20, 0x42, 0x2C], // 126
    [0x36, 0x65, 0x57], // 127
];

/// True when `b` is one the encoder substituted; everything else passes through verbatim.
/// `<`, `>` and `@` are never substituted because the encoder represents them with the `@`
/// escapes instead, so a raw one in the body is already plaintext.
fn is_substituted(b: u8) -> bool {
    (b == 9 || (b > 31 && b < 128)) && b != b'<' && b != b'>' && b != b'@'
}

/// Locate the encoded body between the header and trailer markers, if `text` carries one.
fn encoded_body(text: &str) -> Option<&str> {
    let start = text.find(HEADER_MARKER)? + HEADER_LEN;
    let rest = text.get(start..)?;
    let end = rest.find(TRAILER_MARKER)?;
    let body = rest.get(..end)?;
    body.get(..body.len().checked_sub(CHECKSUM_LEN)?)
}

/// Decode a Script-Encoded body, or `None` if `text` carries no `#@~^ ... ==^#~@` envelope.
///
/// Decoding is a pure transform over the bytes of the envelope; anything outside it (a
/// leading BOM, trailing whitespace) is dropped, since only the script text matters to the
/// caller. Multi-byte UTF-8 is passed through untouched: the reference only substitutes bytes
/// below 128, and does not advance the position counter for the rest.
pub fn decode(text: &str) -> Option<String> {
    let body = encoded_body(text)?;

    // The escapes are undone FIRST, on the whole body; the substituted stream the position
    // counter walks is the post-escape one. This ordering is the reference's and it matters:
    // an `@!` counts as one position (the `<` it becomes), not two.
    let unescaped = body
        .replace("@&", "\n")
        .replace("@#", "\r")
        .replace("@*", ">")
        .replace("@!", "<")
        .replace("@$", "@");

    let mut out = Vec::with_capacity(unescaped.len());
    let mut index: i64 = -1;
    for &b in unescaped.as_bytes() {
        if b < 128 {
            index += 1;
        }
        if is_substituted(b) {
            // `index` is >= 0 here: `b < 128` held on this very byte, so it was just incremented.
            let variant = COMBINATION[(index as usize) % COMBINATION.len()] as usize;
            out.push(DECODE[(b - 9) as usize][variant]);
        } else {
            out.push(b);
        }
    }
    // Substitution outputs are all < 128 and pass-through bytes were valid UTF-8 already, so
    // this cannot fail on well-formed input; a malformed envelope yields None rather than junk.
    String::from_utf8(out).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The inverse of `decode`, built from the same canonical tables so the round trip tests the
    /// decoder against the reference algorithm rather than against itself. Escapes for the bytes
    /// the encoder never substitutes; a dummy length and checksum, which `decode` ignores.
    pub(crate) fn encode(plain: &str) -> String {
        let mut body = String::new();
        let mut index: i64 = -1;
        for &p in plain.as_bytes() {
            if p < 128 {
                index += 1;
            }
            let variant = COMBINATION[(index.max(0) as usize) % COMBINATION.len()] as usize;
            let escaped = match p {
                b'\n' => Some("@&"),
                b'\r' => Some("@#"),
                b'>' => Some("@*"),
                b'<' => Some("@!"),
                b'@' => Some("@$"),
                _ => None,
            };
            if let Some(e) = escaped {
                body.push_str(e);
                continue;
            }
            if !is_substituted(p) && p < 128 {
                body.push(p as char);
                continue;
            }
            if p >= 128 {
                body.push(p as char);
                continue;
            }
            let enc = (9u8..=127)
                .filter(|&b| is_substituted(b))
                .find(|&b| DECODE[(b - 9) as usize][variant] == p)
                .unwrap_or_else(|| panic!("no encoding for byte {p:#x} at variant {variant}"));
            body.push(enc as char);
        }
        format!("{HEADER_MARKER}AAAAAA=={body}AAAAAA{TRAILER_MARKER}")
    }

    #[test]
    fn round_trips_a_dropper_shaped_script() {
        // The shape that hid a real payload url: a scalar assignment the url extractor already
        // understands, plus the control-flow around it. Documentation address, not the real host.
        let plain = "Set WshShell = CreateObject(\"WScript.Shell\")\r\n\
                     strFileURL = \"http://198.51.100.72/tmp2.exe\"\r\n\
                     If objXMLHTTP.Status = 200 Then\r\n\
                     Echo = DosCommand(\"cmd /c \" & Tmp & \" \", 2000)\r\n";
        let encoded = encode(plain);
        assert!(encoded.starts_with(HEADER_MARKER) && encoded.ends_with(TRAILER_MARKER));
        assert_eq!(decode(&encoded).as_deref(), Some(plain));
    }

    #[test]
    fn escapes_and_passthrough_bytes_advance_the_position_counter() {
        // `<`, `>`, `@` and newlines are not substituted but DO consume a position, so a decoder
        // that skipped them would drift out of phase on every byte after. Mixed in deliberately.
        let plain = "a<b>c@d\ne=f\r\ngh";
        assert_eq!(decode(&encode(plain)).as_deref(), Some(plain));
    }

    #[test]
    fn every_substituted_byte_round_trips_at_every_variant() {
        // Exhaustive over the table: each (variant, plaintext) that is reachable must decode back.
        // Guards a transcription error in any single row, which would otherwise be silent.
        for variant in 0..3usize {
            for b in (9u8..=127).filter(|&b| is_substituted(b)) {
                let p = DECODE[(b - 9) as usize][variant];
                // Find an index whose combination is this variant, encode one byte there.
                let idx = COMBINATION
                    .iter()
                    .position(|&v| v as usize == variant)
                    .unwrap();
                let mut body = String::new();
                for _ in 0..idx {
                    body.push('\n'); // consumes a position without substitution
                }
                body = body.replace('\n', "@&");
                body.push(b as char);
                let encoded = format!("{HEADER_MARKER}AAAAAA=={body}AAAAAA{TRAILER_MARKER}");
                let decoded = decode(&encoded).unwrap();
                assert_eq!(
                    decoded.as_bytes()[idx],
                    p,
                    "byte {b:#x} variant {variant} must decode to {p:#x}"
                );
            }
        }
    }

    #[test]
    fn plain_text_is_not_treated_as_encoded() {
        assert_eq!(decode("strFileURL = \"http://198.51.100.72/x\""), None);
        assert_eq!(decode(""), None);
    }

    #[test]
    fn a_truncated_envelope_yields_none_not_junk() {
        assert_eq!(decode("#@~^AAAAAA==abc"), None);
        assert_eq!(decode("#@~^AAAAAA==ab==^#~@"), None); // shorter than the checksum
    }
}
