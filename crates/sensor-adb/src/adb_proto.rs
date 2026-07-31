//! ADB (Android Debug Bridge) wire protocol: pure message framing, parsing, and building - no
//! socket I/O, no `CaptureHandoff`, nothing attacker-controlled reaches this module except as
//! plain bytes in, plain bytes/structs out. See `internal/design/08-remaining-sensors.md`'s
//! "sensor-adb" section for the protocol flow this implements. Verified live against AOSP's own
//! `adb/protocol.txt` (`docs/dev/protocol.md` in current AOSP) and the ADB SYNC sub-protocol's
//! `SYNC.TXT`, not reconstructed from memory.
//!
//! ## Message framing
//!
//! Every ADB message is a 24-byte header (six little-endian u32 words: `command`, `arg0`,
//! `arg1`, `data_length`, `data_crc32`, `magic`) optionally followed by `data_length` bytes of
//! payload. `magic` is always `command ^ 0xFFFFFFFF` - a self-consistency check, not a secret.
//! Each 4-byte command code is its ASCII name read as a little-endian u32
//! (`u32::from_le_bytes(*b"CNXN")` etc.) rather than a hand-computed hex literal, so the value
//! can never carry a transcription error; the task brief's own stated hex values (e.g. CNXN =
//! `0x4e584e43`) are locked in by this module's own tests.
//!
//! `data_crc32` is, despite the name, not a real CRC-32: real adb computes it as an unsigned sum
//! of the payload's bytes (see `checksum`, below), and newer protocol versions send/expect it as
//! 0 unconditionally. This sensor computes a correct checksum on every message it *sends* (so a
//! strict client, or a packet-capture-based fingerprinting attempt, sees a well-formed stream)
//! but never validates it on anything it *receives* - a honeypot must fail open on a field real
//! adb itself has deprecated, not reject an otherwise-usable session over it.
//!
//! ## No AUTH
//!
//! Real, modern adbd performs an RSA-challenge `A_AUTH` exchange before `CNXN` succeeds. This
//! module never implements it: the attack surface this sensor emulates is exactly the
//! already-authorized-or-auth-disabled `adbd` exposed on a routable port 5555 (the
//! ADB.Miner-worm target), where a real device answers `CNXN` immediately with no challenge.
//! Skipping `A_AUTH` is the accurate emulation, not a shortcut - see the task's own "ADB has NO
//! authentication" framing and `handler.rs`'s module doc.

// ---- Outer message commands ----

pub const A_CNXN: u32 = u32::from_le_bytes(*b"CNXN");
pub const A_OPEN: u32 = u32::from_le_bytes(*b"OPEN");
pub const A_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
pub const A_WRTE: u32 = u32::from_le_bytes(*b"WRTE");
pub const A_CLSE: u32 = u32::from_le_bytes(*b"CLSE");

/// Header size on the wire: six 4-byte little-endian words.
pub const HEADER_LEN: usize = 24;

/// This sensor's advertised protocol version and per-message payload ceiling, sent as `arg0`/
/// `arg1` of our own `CNXN` reply. `0x01000000` and `4096` are the values consistently
/// documented as the original ("legacy") ADB protocol constants across independent sources; a
/// smaller `maxdata` is also the more defensive choice for a honeypot. Whatever the client
/// advertises in its own `CNXN` is accepted but never enforced - see the module doc's leniency
/// policy.
pub const OUR_VERSION: u32 = 0x0100_0000;
pub const OUR_MAXDATA: u32 = 4096;

/// Hard ceiling on any single message's `data_length`, applied before ever allocating a buffer
/// to read it into. An attacker-declared `data_length` is a plain `u32` off the wire (up to
/// ~4 GiB); without this cap, reading it as declared is an unbounded-allocation DoS vector on an
/// internet-facing parser - same shape as `sensor-ssh`'s `transfer::SFTP_MAX_PACKET_SIZE`. 1 MiB
/// comfortably covers a `sync:` `DATA` chunk (spec max 64 KiB, see `SYNC_MAX_CHUNK`) plus margin
/// for a slightly-off client, while bounding worst-case allocation far below
/// `sensor_framework`'s own per-session `max_captured_bytes` budget.
pub const MAX_MESSAGE_DATA_LEN: u32 = 1_000_000;

/// A parsed 24-byte ADB message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_crc32: u32,
    pub magic: u32,
}

impl Header {
    /// Parse a header from exactly (or more than) `HEADER_LEN` bytes - only the first
    /// `HEADER_LEN` are read. Returns `None` on a short slice or a `magic` that does not equal
    /// `command ^ 0xFFFFFFFF`; either is treated by the caller as "not a well-formed ADB
    /// message," which drops the connection rather than guessing at what a corrupt header meant.
    pub fn parse(bytes: &[u8]) -> Option<Header> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let command = read_u32_le(bytes, 0);
        let arg0 = read_u32_le(bytes, 4);
        let arg1 = read_u32_le(bytes, 8);
        let data_length = read_u32_le(bytes, 12);
        let data_crc32 = read_u32_le(bytes, 16);
        let magic = read_u32_le(bytes, 20);
        if magic != command ^ 0xFFFF_FFFF {
            return None;
        }
        Some(Header {
            command,
            arg0,
            arg1,
            data_length,
            data_crc32,
            magic,
        })
    }

    /// Encode this header to its 24-byte wire form.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.command.to_le_bytes());
        out[4..8].copy_from_slice(&self.arg0.to_le_bytes());
        out[8..12].copy_from_slice(&self.arg1.to_le_bytes());
        out[12..16].copy_from_slice(&self.data_length.to_le_bytes());
        out[16..20].copy_from_slice(&self.data_crc32.to_le_bytes());
        out[20..24].copy_from_slice(&self.magic.to_le_bytes());
        out
    }
}

/// Real adb's "checksum": an unsigned sum of every payload byte, wrapping on overflow. Not a
/// real CRC-32 despite the wire field's `data_crc32` name - see the module doc.
pub fn checksum(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

/// Build one complete outbound message (header + payload) for `command`/`arg0`/`arg1`/`data`,
/// with a correctly computed checksum and magic.
pub fn build_message(command: u32, arg0: u32, arg1: u32, data: &[u8]) -> Vec<u8> {
    let header = Header {
        command,
        arg0,
        arg1,
        data_length: data.len() as u32,
        data_crc32: checksum(data),
        magic: command ^ 0xFFFF_FFFF,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + data.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(data);
    out
}

pub fn build_cnxn(banner: &str) -> Vec<u8> {
    build_message(A_CNXN, OUR_VERSION, OUR_MAXDATA, banner.as_bytes())
}

pub fn build_open(local_id: u32, destination: &str) -> Vec<u8> {
    build_message(A_OPEN, local_id, 0, destination.as_bytes())
}

pub fn build_okay(local_id: u32, remote_id: u32) -> Vec<u8> {
    build_message(A_OKAY, local_id, remote_id, &[])
}

pub fn build_wrte(local_id: u32, remote_id: u32, data: &[u8]) -> Vec<u8> {
    build_message(A_WRTE, local_id, remote_id, data)
}

pub fn build_clse(local_id: u32, remote_id: u32) -> Vec<u8> {
    build_message(A_CLSE, local_id, remote_id, &[])
}

/// Build this honeypot's device `CNXN` identity string: `device::` followed by
/// semicolon-separated `key=value` properties, mirroring a real Android device's banner shape
/// (`ro.product.model`, `ro.product.name`, ...), NUL-terminated like a real adbd's payload.
/// Every value is a static, fictional device identity - the same "internally consistent, never a
/// real host" convention `sensor_framework::fakefs::FakeFs` documents - not read from or
/// correlated with anything about the real host this sensor runs on. Deliberately does NOT claim
/// the `shell_v2` feature: this sensor only implements the plain v1 `shell:`/`shell:<command>`
/// framing, and a real `adb` client that saw `shell_v2` advertised would switch to a
/// length-framed multiplexed stdin/stdout/stderr/exit-code protocol this handler cannot parse,
/// corrupting capture instead of improving it. Omitting it is what makes a real client fall back
/// to the plain protocol this sensor actually speaks.
pub fn device_banner() -> String {
    "device::ro.product.name=hammerhead;ro.product.model=Nexus 5;ro.product.device=hammerhead;\
     ro.product.board=hammerhead;ro.build.version.release=6.0.1;ro.build.version.sdk=23;\0"
        .to_string()
}

/// This sensor's own `host::` identity string, used only by the test suite acting as a client.
pub fn host_banner() -> String {
    "host::\0".to_string()
}

// ---- OPEN destination classification ----

/// What kind of stream an `OPEN` destination string names, per the design spec's "sensor-adb"
/// section. `Shell`'s inner value is the one-shot command when the destination is
/// `shell:<command>` (per real adb, this runs once and the stream closes when it completes) or
/// `None` for a bare `shell:` (an interactive session that stays open, mirroring
/// `sensor_framework::shell::FakeShell`'s existing SSH/Telnet callers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Shell(Option<String>),
    Sync,
    Unsupported,
}

/// Classify an `OPEN` destination string. Tolerant of a trailing NUL (real adb payloads carry
/// one; this sensor's own inbound parsing does not require it) and of anything else this sensor
/// does not recognize, which becomes `Unsupported` rather than a parse error - there is no
/// destination string shape that can panic this function.
pub fn classify_destination(raw: &str) -> Destination {
    let s = raw.trim_end_matches('\0');
    if let Some(cmd) = s.strip_prefix("shell:") {
        if cmd.is_empty() {
            Destination::Shell(None)
        } else {
            Destination::Shell(Some(cmd.to_string()))
        }
    } else if s.starts_with("sync:") {
        Destination::Sync
    } else {
        Destination::Unsupported
    }
}

// ---- SYNC sub-protocol (carried inside WRTE payloads on a `sync:` stream) ----
//
// Each sync sub-message is its own tiny 8-byte header (4-byte ASCII id + 4-byte little-endian
// length) optionally followed by `length` bytes of payload - except `DONE`, whose `length` field
// *is* the file's mtime, with no further payload bytes. Per `SYNC.TXT`: "the first four bytes
// are an id ... the last four bytes are a Little-Endian integer ... called 'length'."

pub const SYNC_SEND: u32 = u32::from_le_bytes(*b"SEND");
pub const SYNC_RECV: u32 = u32::from_le_bytes(*b"RECV");
pub const SYNC_DATA: u32 = u32::from_le_bytes(*b"DATA");
pub const SYNC_DONE: u32 = u32::from_le_bytes(*b"DONE");
pub const SYNC_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
pub const SYNC_FAIL: u32 = u32::from_le_bytes(*b"FAIL");
pub const SYNC_STAT: u32 = u32::from_le_bytes(*b"STAT");

/// Sync sub-protocol header size: 4-byte id + 4-byte little-endian length.
pub const SYNC_HEADER_LEN: usize = 8;

/// Real adb caps a `SEND` `DATA` chunk at 64 KiB (`SYNC.TXT`: "Each chunk must not be larger
/// than 64k"). This sensor is deliberately more generous than that spec ceiling - large enough
/// to tolerate a slightly-off client without being unbounded - and enforces it independently of
/// `MAX_MESSAGE_DATA_LEN`: a `DATA` sub-message's `length` field is attacker-controlled
/// separately from the outer `WRTE`'s own `data_length` (a forged huge `length` can arrive
/// inside a small `WRTE`, to be "completed" by many subsequent small writes), so it needs its
/// own bound checked before the sync reassembly buffer ever accumulates toward it.
pub const SYNC_MAX_CHUNK: u32 = 128 * 1024;

/// Cap on a sync sub-message's declared `length` for path-like fields (`SEND`'s `path,mode`
/// header, `RECV`'s path, `STAT`'s path) - generous for any real filesystem path
/// (`PATH_MAX`-scale) while still bounding the same forged-length amplification `SYNC_MAX_CHUNK`
/// guards against for `DATA`.
pub const MAX_SYNC_PATH_LEN: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncHeader {
    pub id: u32,
    pub length: u32,
}

impl SyncHeader {
    pub fn parse(bytes: &[u8]) -> Option<SyncHeader> {
        if bytes.len() < SYNC_HEADER_LEN {
            return None;
        }
        Some(SyncHeader {
            id: read_u32_le(bytes, 0),
            length: read_u32_le(bytes, 4),
        })
    }

    pub fn encode(&self) -> [u8; SYNC_HEADER_LEN] {
        let mut out = [0u8; SYNC_HEADER_LEN];
        out[0..4].copy_from_slice(&self.id.to_le_bytes());
        out[4..8].copy_from_slice(&self.length.to_le_bytes());
        out
    }
}

/// Build a sync sub-message: an 8-byte `SyncHeader` followed by `payload`. Used for every sync
/// response this sensor sends (`OKAY`, `FAIL`, `STAT`) as well as, in the test suite acting as a
/// client, `SEND`/`RECV`/`DATA` requests.
pub fn build_sync_message(id: u32, payload: &[u8]) -> Vec<u8> {
    let header = SyncHeader {
        id,
        length: payload.len() as u32,
    };
    let mut out = Vec::with_capacity(SYNC_HEADER_LEN + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    out
}

/// Build a `sync:` `DONE` request as a client would send it: the mtime rides in the length
/// field, with no payload bytes at all - see the module doc.
pub fn build_sync_done(mtime: u32) -> Vec<u8> {
    SyncHeader {
        id: SYNC_DONE,
        length: mtime,
    }
    .encode()
    .to_vec()
}

/// Build the 12-byte `STAT` response body real adb uses for "path does not exist": mode, size,
/// and mtime all zero. A real `adb push` client that `STAT`s its destination before `SEND`ing
/// falls back to treating the destination as the literal target filename when `STAT` reports
/// nonexistence - so answering this way (rather than not answering `STAT` at all) is what lets a
/// real adb client's `push`, not just a raw bot driving the wire protocol directly, reach this
/// sensor's `SEND` capture path.
pub fn stat_not_found_body() -> [u8; 12] {
    [0u8; 12]
}

/// Parse a `SEND` request's payload: `<path>,<mode>` split on the *last* comma (mirrors
/// `sensor-ssh`'s `transfer::parse_scp_header` convention - a path may itself legitimately
/// contain a comma, the trailing `,<mode>` never does). Returns `(path, mode)`; `mode` is parsed
/// but never used for anything beyond being available to a caller - there is no real filesystem
/// underneath to apply permissions to.
pub fn parse_send_path(payload: &str) -> Option<(String, u32)> {
    let (path, mode_str) = payload.rsplit_once(',')?;
    let mode: u32 = mode_str.parse().ok()?;
    Some((path.to_string(), mode))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- header round-trip and the task brief's own stated hex values ----

    #[test]
    fn command_constants_match_task_brief_hex_values() {
        // Locks in the exact wire values named in the task brief and independently verified
        // against AOSP's protocol docs, so a future edit that breaks the ASCII-LE derivation
        // (e.g. an accidental byte-order flip) fails loudly here rather than only as a mysterious
        // real-client interop failure.
        assert_eq!(A_CNXN, 0x4e58_4e43);
        assert_eq!(A_OPEN, 0x4e45_504f);
        assert_eq!(A_WRTE, 0x4554_5257);
        assert_eq!(A_CLSE, 0x4553_4c43);
        assert_eq!(A_OKAY, 0x5941_4b4f);
    }

    #[test]
    fn header_round_trip() {
        let header = Header {
            command: A_CNXN,
            arg0: 1,
            arg1: 4096,
            data_length: 7,
            data_crc32: 42,
            magic: A_CNXN ^ 0xFFFF_FFFF,
        };
        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_LEN);
        let parsed = Header::parse(&encoded).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn parse_rejects_short_input() {
        assert!(Header::parse(&[0u8; 23]).is_none());
        assert!(Header::parse(&[]).is_none());
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&A_CNXN.to_le_bytes());
        // magic left as zero, which is not A_CNXN ^ 0xFFFFFFFF.
        assert!(Header::parse(&bytes).is_none());
    }

    #[test]
    fn build_message_sets_correct_magic_and_length() {
        let msg = build_message(A_OPEN, 5, 0, b"shell:");
        let header = Header::parse(&msg).unwrap();
        assert_eq!(header.command, A_OPEN);
        assert_eq!(header.magic, A_OPEN ^ 0xFFFF_FFFF);
        assert_eq!(header.data_length, 6);
        assert_eq!(&msg[HEADER_LEN..], b"shell:");
    }

    // ---- checksum ----

    #[test]
    fn checksum_empty_is_zero() {
        assert_eq!(checksum(&[]), 0);
    }

    #[test]
    fn checksum_sums_bytes() {
        assert_eq!(checksum(&[1, 2, 3]), 6);
        assert_eq!(checksum(b"AB"), (b'A' as u32) + (b'B' as u32));
    }

    #[test]
    fn checksum_wraps_on_overflow() {
        let data = vec![255u8; 20_000_000]; // sum far exceeds u32::MAX
        // Must not panic (debug-mode overflow would abort); wrapping_add is the contract.
        let _ = checksum(&data);
    }

    // ---- banners ----

    #[test]
    fn device_banner_has_expected_shape() {
        let banner = device_banner();
        assert!(banner.starts_with("device::"));
        assert!(banner.contains("ro.product.model=Nexus 5"));
        assert!(banner.contains("ro.product.name="));
        assert!(banner.ends_with('\0'));
        assert!(
            !banner.contains("shell_v2"),
            "must not claim shell_v2 - this sensor only speaks the plain v1 shell framing"
        );
    }

    #[test]
    fn host_banner_has_expected_shape() {
        assert_eq!(host_banner(), "host::\0");
    }

    // ---- destination classification ----

    #[test]
    fn classify_bare_shell_is_interactive() {
        assert_eq!(classify_destination("shell:"), Destination::Shell(None));
    }

    #[test]
    fn classify_shell_with_command_is_one_shot() {
        assert_eq!(
            classify_destination("shell:id"),
            Destination::Shell(Some("id".to_string()))
        );
    }

    #[test]
    fn classify_shell_with_command_strips_trailing_nul() {
        assert_eq!(
            classify_destination("shell:id\0"),
            Destination::Shell(Some("id".to_string()))
        );
    }

    #[test]
    fn classify_sync_is_sync() {
        assert_eq!(classify_destination("sync:"), Destination::Sync);
        assert_eq!(classify_destination("sync:\0"), Destination::Sync);
    }

    #[test]
    fn classify_unknown_destination_is_unsupported() {
        assert_eq!(classify_destination("tcp:1234"), Destination::Unsupported);
        assert_eq!(classify_destination(""), Destination::Unsupported);
        assert_eq!(
            classify_destination("reverse:forward"),
            Destination::Unsupported
        );
    }

    // ---- sync sub-protocol ----

    #[test]
    fn sync_header_round_trip() {
        let header = SyncHeader {
            id: SYNC_SEND,
            length: 12345,
        };
        let parsed = SyncHeader::parse(&header.encode()).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn sync_header_parse_rejects_short_input() {
        assert!(SyncHeader::parse(&[0u8; 7]).is_none());
    }

    #[test]
    fn build_sync_message_layout() {
        let msg = build_sync_message(SYNC_OKAY, &[]);
        assert_eq!(msg.len(), SYNC_HEADER_LEN);
        let header = SyncHeader::parse(&msg).unwrap();
        assert_eq!(header.id, SYNC_OKAY);
        assert_eq!(header.length, 0);
    }

    #[test]
    fn build_sync_done_has_no_payload_and_length_is_mtime() {
        let msg = build_sync_done(1_700_000_000);
        assert_eq!(msg.len(), SYNC_HEADER_LEN);
        let header = SyncHeader::parse(&msg).unwrap();
        assert_eq!(header.id, SYNC_DONE);
        assert_eq!(header.length, 1_700_000_000);
    }

    #[test]
    fn sync_command_constants_are_distinct() {
        let all = [
            SYNC_SEND, SYNC_RECV, SYNC_DATA, SYNC_DONE, SYNC_OKAY, SYNC_FAIL, SYNC_STAT,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "sync command constants must be pairwise distinct");
                }
            }
        }
        // SYNC_OKAY/SYNC_FAIL intentionally alias the outer A_OKAY - real adb sync literally
        // reuses the same 4-byte "OKAY"/"FAIL" tokens at both layers.
        assert_eq!(SYNC_OKAY, A_OKAY);
    }

    #[test]
    fn parse_send_path_splits_on_last_comma() {
        let (path, mode) = parse_send_path("/data/local/tmp/evil.bin,33188").unwrap();
        assert_eq!(path, "/data/local/tmp/evil.bin");
        assert_eq!(mode, 33188);
    }

    #[test]
    fn parse_send_path_handles_comma_in_path() {
        // A path containing a comma must not be mis-split; only the trailing ",<mode>" is the
        // delimiter, so splitting on the LAST comma is load-bearing here.
        let (path, mode) = parse_send_path("/tmp/a,b,file.txt,420").unwrap();
        assert_eq!(path, "/tmp/a,b,file.txt");
        assert_eq!(mode, 420);
    }

    #[test]
    fn parse_send_path_rejects_missing_comma() {
        assert!(parse_send_path("no-comma-here").is_none());
    }

    #[test]
    fn parse_send_path_rejects_non_numeric_mode() {
        assert!(parse_send_path("/tmp/x,not-a-number").is_none());
    }

    #[test]
    fn stat_not_found_body_is_all_zero_12_bytes() {
        assert_eq!(stat_not_found_body(), [0u8; 12]);
    }

    // ---- fuzz-lite: parsing must never panic on arbitrary attacker-controlled bytes ----

    proptest::proptest! {
        #[test]
        fn header_parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64)) {
            let _ = Header::parse(&bytes);
        }

        #[test]
        fn sync_header_parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=32)) {
            let _ = SyncHeader::parse(&bytes);
        }

        #[test]
        fn classify_destination_never_panics(s in ".{0,256}") {
            let _ = classify_destination(&s);
        }

        #[test]
        fn parse_send_path_never_panics(s in ".{0,256}") {
            let _ = parse_send_path(&s);
        }

        #[test]
        fn checksum_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=4096)) {
            let _ = checksum(&bytes);
        }
    }
}
