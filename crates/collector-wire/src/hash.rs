use sha2::{Digest, Sha256};

pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Hash the bytes of a frame excluding the trailing 32-byte batch_hash field.
pub fn hash_prefix(frame_without_trailing_hash: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(frame_without_trailing_hash);
    h.finalize().into()
}
