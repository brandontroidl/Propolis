use crate::hash;

pub const MAGIC: &[u8; 4] = b"PBW1";
pub const VERSION: u8 = 1;
pub const MAX_RECORDS_PER_BATCH: u32 = 1024;
pub const MAX_RECORD_LEN: u32 = 1_048_576;
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

const HEADER_LEN: usize = 4 + 1 + 8 + 32 + 4; // magic+ver+seq+prev+count = 49
const TRAILER_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub seq: u64,
    pub prev_batch_hash: [u8; 32],
    pub records: Vec<Vec<u8>>,
    pub batch_hash: [u8; 32],
}

impl Batch {
    /// Build a batch and compute its batch_hash from seq + prev + records. Panics only on a
    /// programming error (empty records or a record over the cap): callers assemble records
    /// from bounded tailer lines, so these are invariants, not runtime input.
    pub fn new(seq: u64, prev_batch_hash: [u8; 32], records: Vec<Vec<u8>>) -> Self {
        assert!(!records.is_empty() && records.len() as u32 <= MAX_RECORDS_PER_BATCH);
        let mut b = Batch {
            seq,
            prev_batch_hash,
            records,
            batch_hash: [0u8; 32],
        };
        let prefix = encode_prefix(&b);
        b.batch_hash = hash::hash_prefix(&prefix);
        b
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("bad magic")]
    BadMagic,
    #[error("bad version")]
    BadVersion,
    #[error("truncated frame")]
    Truncated,
    #[error("too many records")]
    TooManyRecords,
    #[error("record too large")]
    RecordTooLarge,
    #[error("empty batch")]
    EmptyBatch,
    #[error("record contains newline")]
    RecordNewline,
    #[error("frame too large")]
    FrameTooLarge,
    #[error("batch hash mismatch")]
    HashMismatch,
}

/// Everything except the trailing batch_hash - the exact bytes that are hashed.
fn encode_prefix(b: &Batch) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&b.seq.to_be_bytes());
    out.extend_from_slice(&b.prev_batch_hash);
    out.extend_from_slice(&(b.records.len() as u32).to_be_bytes());
    for r in &b.records {
        out.extend_from_slice(&(r.len() as u32).to_be_bytes());
        out.extend_from_slice(r);
    }
    out
}

pub fn encode_frame(b: &Batch) -> Vec<u8> {
    let mut out = encode_prefix(b);
    out.extend_from_slice(&b.batch_hash);
    out
}

pub fn decode_frame(bytes: &[u8]) -> Result<Batch, FrameError> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(FrameError::FrameTooLarge);
    }
    // Only enough to read the fixed header (through record_count) is required here, so a
    // hand-crafted header claiming an over-cap count is rejected on the count itself, before
    // the trailer-length bound below and before any attempt to read that many records.
    if bytes.len() < HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    if &bytes[0..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    if bytes[4] != VERSION {
        return Err(FrameError::BadVersion);
    }
    let seq = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
    let prev_batch_hash: [u8; 32] = bytes[13..45].try_into().unwrap();
    let record_count = u32::from_be_bytes(bytes[45..49].try_into().unwrap());
    if record_count == 0 {
        return Err(FrameError::EmptyBatch);
    }
    if record_count > MAX_RECORDS_PER_BATCH {
        return Err(FrameError::TooManyRecords);
    }
    // Now that the count is bounded, require room for at least the trailer before the record
    // loop below subtracts TRAILER_LEN from bytes.len() (avoids an underflow panic on a short
    // buffer).
    if bytes.len() < HEADER_LEN + TRAILER_LEN {
        return Err(FrameError::Truncated);
    }

    let mut off = HEADER_LEN;
    let mut records = Vec::with_capacity(record_count as usize);
    for _ in 0..record_count {
        if off + 4 > bytes.len() - TRAILER_LEN {
            return Err(FrameError::Truncated);
        }
        let len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        if len == 0 || len > MAX_RECORD_LEN {
            return Err(FrameError::RecordTooLarge);
        }
        let end = off + len as usize;
        if end > bytes.len() - TRAILER_LEN {
            return Err(FrameError::Truncated);
        }
        let rec = &bytes[off..end];
        if rec.contains(&b'\n') {
            return Err(FrameError::RecordNewline);
        }
        records.push(rec.to_vec());
        off = end;
    }
    // Exactly the trailer must remain.
    if off != bytes.len() - TRAILER_LEN {
        return Err(FrameError::Truncated);
    }
    let claimed: [u8; 32] = bytes[off..].try_into().unwrap();
    let computed = hash::hash_prefix(&bytes[..off]);
    if computed != claimed {
        return Err(FrameError::HashMismatch);
    }

    Ok(Batch {
        seq,
        prev_batch_hash,
        records,
        batch_hash: claimed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Batch {
        Batch::new(
            1,
            hash::ZERO_HASH,
            vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()],
        )
    }

    #[test]
    fn round_trip_preserves_records_and_hash() {
        let b = sample();
        let bytes = encode_frame(&b);
        let decoded = decode_frame(&bytes).expect("valid frame decodes");
        assert_eq!(decoded.seq, 1);
        assert_eq!(decoded.prev_batch_hash, hash::ZERO_HASH);
        assert_eq!(decoded.records, b.records);
        assert_eq!(decoded.batch_hash, b.batch_hash);
    }

    #[test]
    fn a_single_flipped_byte_fails_the_hash_check() {
        let b = sample();
        let mut bytes = encode_frame(&b);
        bytes[20] ^= 0xff; // somewhere inside prev_batch_hash
        assert!(matches!(
            decode_frame(&bytes),
            Err(FrameError::HashMismatch)
        ));
    }

    #[test]
    fn a_record_containing_a_newline_is_rejected() {
        let b = Batch::new(1, hash::ZERO_HASH, vec![b"{\"a\":1}\n{\"b\":2}".to_vec()]);
        let bytes = encode_frame(&b);
        assert!(matches!(
            decode_frame(&bytes),
            Err(FrameError::RecordNewline)
        ));
    }

    #[test]
    fn too_many_records_is_rejected_before_allocation() {
        // Hand-craft a header claiming a record_count over the cap; decode must reject on the
        // count, not attempt to read that many records.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(1);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&hash::ZERO_HASH);
        bytes.extend_from_slice(&(MAX_RECORDS_PER_BATCH + 1).to_be_bytes());
        assert!(matches!(
            decode_frame(&bytes),
            Err(FrameError::TooManyRecords)
        ));
    }

    #[test]
    fn bad_magic_and_wrong_version_are_rejected() {
        let b = sample();
        let mut bytes = encode_frame(&b);
        bytes[0] = b'X';
        assert!(matches!(decode_frame(&bytes), Err(FrameError::BadMagic)));
        let mut bytes = encode_frame(&b);
        bytes[4] = 2;
        assert!(matches!(decode_frame(&bytes), Err(FrameError::BadVersion)));
    }
}
