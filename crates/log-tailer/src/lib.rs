//! File tailing with a durable, rotation-aware cursor. Extracted from `intake` so the
//! collector-side shipper can tail sensor NDJSON logs without depending on the control-plane
//! DB stack. The low-trust-boundary hardening (MAX_LINE_BYTES over-length discard) lives here
//! and therefore applies to BOTH the shipper->gateway path and the gateway-spool->intake path.
mod cursor;
mod sensor_logs;
mod tailer;

pub use cursor::{CursorState, DurableCursor, RotationEvent, compute_fingerprint, get_inode};
pub use sensor_logs::{SensorLogConfig, SensorLogsError, parse_sensor_logs};
pub use tailer::{BatchLine, LogTailer, MAX_LINE_BYTES, StartAt, TailEntry};

/// Lowercase hex SHA-256 of `bytes`. Here because this crate already carries the hash; callers
/// that need a line's digest (intake's quarantine record) do not take a second dependency for it.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha256_hex_matches_the_fips_180_vectors() {
        assert_eq!(
            super::sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            super::sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
