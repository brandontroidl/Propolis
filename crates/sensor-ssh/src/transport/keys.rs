//! Session key derivation (RFC 4253 section 7.2) from the shared secret and exchange hash
//! produced by the key exchange in `kex.rs`. For `chacha20-poly1305@openssh.com` each direction
//! needs a 64-byte key (32 main + 32 header), derived with letters 'C' (client-to-server) and
//! 'D' (server-to-client). SHA-256 produces 32 bytes per hash, so each 64-byte key requires one
//! extension round: `K1 = HASH(K || H || letter || session_id)`, then
//! `K2 = HASH(K || H || K1)`, concatenated and truncated.

use sha2::{Digest, Sha256};

use super::cipher::TransportCipher;

/// The keys both sides of an SSH connection derive from a completed key exchange: one 64-byte
/// key per direction (split into 32-byte main + 32-byte header by each cipher constructor) and
/// the session ID that anchors all future re-keying.
pub struct SessionKeys {
    pub session_id: Vec<u8>,
    /// 64 bytes: main key [0..32] + header key [32..64] for client-to-server.
    pub client_to_server_key: Vec<u8>,
    /// 64 bytes: main key [0..32] + header key [32..64] for server-to-client.
    pub server_to_client_key: Vec<u8>,
}

impl SessionKeys {
    pub fn client_to_server_cipher(&self) -> TransportCipher {
        TransportCipher::new(
            self.client_to_server_key[..32].try_into().unwrap(),
            self.client_to_server_key[32..].try_into().unwrap(),
        )
    }

    pub fn server_to_client_cipher(&self) -> TransportCipher {
        TransportCipher::new(
            self.server_to_client_key[..32].try_into().unwrap(),
            self.server_to_client_key[32..].try_into().unwrap(),
        )
    }
}

/// Derive session keys from the raw shared secret, exchange hash, and session ID.
/// `shared_secret` is the raw 32-byte X25519 output; this function handles SSH mpint encoding
/// internally (RFC 4253 section 7.2: "K is encoded as mpint").
pub fn derive_keys(shared_secret: &[u8], exchange_hash: &[u8], session_id: &[u8]) -> SessionKeys {
    let k_mpint = super::kex::encode_mpint(shared_secret);
    let c2s = derive_one(&k_mpint, exchange_hash, b'C', session_id, 64);
    let s2c = derive_one(&k_mpint, exchange_hash, b'D', session_id, 64);
    SessionKeys {
        session_id: session_id.to_vec(),
        client_to_server_key: c2s,
        server_to_client_key: s2c,
    }
}

/// Derive a single key of `needed` bytes for the given letter.
/// RFC 4253 section 7.2:
///   K1 = HASH(K || H || letter || session_id)
///   Kn = HASH(K || H || K1 || ... || K(n-1))     (if key needs extension)
///   key = K1 || K2 || ... truncated to `needed`
fn derive_one(k_mpint: &[u8], h: &[u8], letter: u8, session_id: &[u8], needed: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(needed);

    // First block: HASH(K || H || letter || session_id)
    let k1: [u8; 32] = Sha256::new()
        .chain_update(k_mpint)
        .chain_update(h)
        .chain_update([letter])
        .chain_update(session_id)
        .finalize()
        .into();
    key.extend_from_slice(&k1);

    // Extension rounds: HASH(K || H || key_so_far)
    while key.len() < needed {
        let block: [u8; 32] = Sha256::new()
            .chain_update(k_mpint)
            .chain_update(h)
            .chain_update(&key)
            .finalize()
            .into();
        key.extend_from_slice(&block);
    }

    key.truncate(needed);
    key
}
