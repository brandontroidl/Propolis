//! Single-byte-XOR command de-obfuscation. Some telnet loaders (e.g. the LZRD Mirai variant) XOR
//! their command payloads to dodge signature IDS while sending plaintext dictionary logins. This
//! recovers the key from anchor tokens so the fake shell can recognise the probe, respond correctly,
//! and record the decoded command. See internal/design/14-shell-grammar-deobfuscation.md.

/// High-signal, whole-token, case-sensitive anchors. Deliberately excludes short/common tokens
/// (`sh`, `shell`) to avoid locking a key on a random echo-probe token like the observed `RPMA`.
const ANCHORS: [&str; 5] = ["/bin/busybox", "busybox", "enable", "system", "/bin/sh"];

/// XOR every byte of `s` with `key`.
pub fn xor_bytes(s: &str, key: u8) -> Vec<u8> {
    s.bytes().map(|b| b ^ key).collect()
}

fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (0x20..0x7f).contains(&b))
}

/// True if `line` contains any anchor as a whole whitespace-delimited token.
fn contains_anchor(line: &str) -> bool {
    line.split_whitespace().any(|t| ANCHORS.contains(&t))
}

/// Detect a single-byte XOR key for an obfuscated command line. `None` if the raw line already
/// contains a plaintext anchor (nothing to decode) or no key yields an anchor.
pub fn detect_key(line: &str) -> Option<u8> {
    if contains_anchor(line) {
        return None; // already plaintext
    }
    for key in 1..=255u8 {
        let decoded = xor_bytes(line, key);
        if is_printable_ascii(&decoded)
            && let Ok(s) = std::str::from_utf8(&decoded)
            && contains_anchor(s)
        {
            return Some(key);
        }
    }
    None
}

/// How many key-less lines a session may cost before detection gives up. `detect_key` brute-forces
/// 255 keys per line, so retrying it on every non-anchor line is a CPU amplifier: an attacker
/// streaming ordinary commands that never happen to contain an anchor token (`uname -a`,
/// `cat /proc/mounts`, ...) would pay the full 255-key scan for the session's whole lifetime, with
/// no upstream byte cap on the SSH sensor to bound it. The obfuscating loaders this targets lead
/// with an anchor-bearing probe (`enable`, `/bin/busybox <applet>`) in their first command, so a
/// small cap catches every real case while bounding the worst case to a fixed `CAP * 255` trials per
/// session. Design 14 ("shell-grammar-deobfuscation") mandates this cap.
const MAX_DETECT_ATTEMPTS: u8 = 8;

/// One per session. Tracks a detected single-byte XOR obfuscation key and applies it to input
/// (decode) and output (encode/mirror).
#[derive(Default)]
pub struct CommandCodec {
    key: Option<u8>,
    /// Lines on which detection ran and found no key. Once it reaches [`MAX_DETECT_ATTEMPTS`] the
    /// codec stops attempting detection and treats the session as plaintext for good.
    misses: u8,
}

impl CommandCodec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode one input line. In Plain state, try to detect and lock a key (until the per-session
    /// attempt cap is spent); once locked, decode every line with it. Returns the (possibly decoded)
    /// line and the active key.
    pub fn decode(&mut self, line: &str) -> (String, Option<u8>) {
        if let Some(k) = self.key {
            return (
                String::from_utf8_lossy(&xor_bytes(line, k)).into_owned(),
                Some(k),
            );
        }
        if self.misses >= MAX_DETECT_ATTEMPTS {
            return (line.to_string(), None); // detection given up: this session reads as plaintext
        }
        if let Some(k) = detect_key(line) {
            self.key = Some(k);
            return (
                String::from_utf8_lossy(&xor_bytes(line, k)).into_owned(),
                Some(k),
            );
        }
        self.misses += 1;
        (line.to_string(), None)
    }

    /// Encode outbound bytes with the locked key (identity when no key is locked), so a symmetric-
    /// codec bot reads plaintext after its own de-obfuscation.
    pub fn encode(&self, bytes: &[u8]) -> Vec<u8> {
        match self.key {
            Some(k) => bytes.iter().map(|b| b ^ k).collect(),
            None => bytes.to_vec(),
        }
    }

    pub fn key(&self) -> Option<u8> {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_is_its_own_inverse() {
        let e = xor_bytes("enable", 0x09);
        assert_eq!(e, b"lghkel");
        assert_eq!(
            String::from_utf8(xor_bytes(std::str::from_utf8(&e).unwrap(), 0x09)).unwrap(),
            "enable"
        );
    }

    #[test]
    fn detects_the_lzrd_xor_09_key_from_an_obfuscated_anchor() {
        assert_eq!(detect_key("lghkel"), Some(0x09)); // "enable" ^ 0x09
        assert_eq!(detect_key("zpz}ld"), Some(0x09)); // "system" ^ 0x09
    }

    #[test]
    fn plaintext_anchor_needs_no_key() {
        assert_eq!(detect_key("enable"), None);
        assert_eq!(detect_key("/bin/busybox LZRD"), None);
    }

    #[test]
    fn random_probe_and_ordinary_command_do_not_lock_a_key() {
        // The observed echo-probe tokens and ordinary commands must not false-positive.
        assert_eq!(detect_key("RPMA"), None);
        assert_eq!(detect_key("AMOO"), None);
        assert_eq!(detect_key("cat /proc/mounts"), None);
        assert_eq!(detect_key("uname -a"), None);
    }

    #[test]
    fn locks_key_on_first_obfuscated_command_then_decodes_the_rest() {
        let mut c = CommandCodec::new();
        assert_eq!(c.decode("lghkel"), ("enable".to_string(), Some(0x09)));
        // "za" ^ 0x09 == "sh": not an anchor itself, but the locked key still decodes it.
        assert_eq!(c.decode("za"), ("sh".to_string(), Some(0x09)));
    }

    #[test]
    fn plaintext_session_stays_plain() {
        let mut c = CommandCodec::new();
        assert_eq!(c.decode("enable"), ("enable".to_string(), None));
        assert_eq!(c.decode("uname -a"), ("uname -a".to_string(), None));
        assert_eq!(c.encode(b"hello"), b"hello".to_vec());
    }

    #[test]
    fn encode_mirrors_the_locked_key() {
        let mut c = CommandCodec::new();
        c.decode("lghkel"); // locks 0x09
        assert_eq!(c.encode(b"enable"), b"lghkel".to_vec());
    }

    #[test]
    fn detection_gives_up_after_the_attempt_cap_so_a_flood_cannot_spin_it() {
        // A session that never sends an anchor token must not pay the 255-key brute force forever.
        // After MAX_DETECT_ATTEMPTS key-less lines the codec stops detecting: a later obfuscated
        // anchor line is left as-is rather than decoded. This bounds the worst-case CPU cost;
        // without the cap the same obfuscated line would still lock a key and decode.
        let mut capped = CommandCodec::new();
        for _ in 0..MAX_DETECT_ATTEMPTS {
            assert_eq!(capped.decode("cat /proc/mounts").1, None); // no anchor, no key
        }
        // Budget spent: this obfuscated `enable` is NOT decoded any more.
        assert_eq!(capped.decode("lghkel"), ("lghkel".to_string(), None));

        // Control: the identical line DOES decode when the cap has not been reached.
        let mut fresh = CommandCodec::new();
        assert_eq!(fresh.decode("lghkel"), ("enable".to_string(), Some(0x09)));
    }

    #[test]
    fn a_key_less_prefix_within_the_cap_still_locks_on_a_later_anchor() {
        // A few ordinary commands before the first obfuscated probe must not defeat detection.
        let mut c = CommandCodec::new();
        for _ in 0..(MAX_DETECT_ATTEMPTS - 1) {
            assert_eq!(c.decode("uname -a").1, None);
        }
        assert_eq!(c.decode("lghkel"), ("enable".to_string(), Some(0x09)));
    }
}
