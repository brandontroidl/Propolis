//! Session key derivation (RFC 4253 section 7.2) from the shared secret and exchange hash
//! produced by the key exchange in `kex.rs`. Six keys come out of one exchange, each sized for the
//! algorithm negotiated for its direction:
//!
//! | letter | key |
//! |---|---|
//! | `A`, `B` | initial IV, client-to-server and server-to-client |
//! | `C`, `D` | encryption key |
//! | `E`, `F` | integrity (MAC) key |
//!
//! Each is `K1 = HASH(K || H || letter || session_id)`, extended with `Kn = HASH(K || H || K1 ||
//! ... || K(n-1))` until it is long enough, then truncated. Every key exchange this server speaks
//! hashes with SHA-256, so that is the HASH here.

use sha2::{Digest, Sha256};

use super::algorithms::{Cipher, Mac, Negotiated};
use super::packet_cipher::PacketCipher;

/// The key material of one direction. A field is empty when its algorithm needs none (an AEAD
/// has no MAC key, ChaCha20-Poly1305 no IV).
pub struct DirectionKeys {
    pub iv: Vec<u8>,
    pub key: Vec<u8>,
    pub mac_key: Vec<u8>,
}

/// The keys both sides of an SSH connection derive from a completed key exchange, and the
/// session ID that anchors all future re-keying.
pub struct SessionKeys {
    pub session_id: Vec<u8>,
    pub client_to_server: DirectionKeys,
    pub server_to_client: DirectionKeys,
    cipher_client_to_server: (Cipher, Option<Mac>),
    cipher_server_to_client: (Cipher, Option<Mac>),
}

impl SessionKeys {
    /// Packet protection for what the client sends.
    pub fn client_to_server_cipher(&self) -> PacketCipher {
        let (cipher, mac) = self.cipher_client_to_server;
        PacketCipher::new(cipher, mac, &self.client_to_server)
    }

    /// Packet protection for what the server sends.
    pub fn server_to_client_cipher(&self) -> PacketCipher {
        let (cipher, mac) = self.cipher_server_to_client;
        PacketCipher::new(cipher, mac, &self.server_to_client)
    }
}

/// Derive session keys from the raw shared secret, exchange hash, and session ID, sized for the
/// algorithms in `negotiated`. `shared_secret` is the key exchange's raw output as big-endian
/// bytes; this function handles SSH mpint encoding internally (RFC 4253 section 7.2: "K is
/// encoded as mpint").
pub fn derive_keys(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    negotiated: &Negotiated,
) -> SessionKeys {
    let k_mpint = super::kex::encode_mpint(shared_secret);
    let direction = |letters: [u8; 3], cipher: Cipher, mac: Option<Mac>| {
        let derive = |letter: u8, len: usize| {
            if len == 0 {
                Vec::new()
            } else {
                derive_one(&k_mpint, exchange_hash, letter, session_id, len)
            }
        };
        DirectionKeys {
            iv: derive(letters[0], cipher.iv_len()),
            key: derive(letters[1], cipher.key_len()),
            mac_key: derive(letters[2], mac.map_or(0, Mac::key_len)),
        }
    };
    let c2s = (
        negotiated.cipher_client_to_server,
        negotiated.mac_client_to_server,
    );
    let s2c = (
        negotiated.cipher_server_to_client,
        negotiated.mac_server_to_client,
    );
    SessionKeys {
        session_id: session_id.to_vec(),
        client_to_server: direction([b'A', b'C', b'E'], c2s.0, c2s.1),
        server_to_client: direction([b'B', b'D', b'F'], s2c.0, s2c.1),
        cipher_client_to_server: c2s,
        cipher_server_to_client: s2c,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::algorithms::{HostKeyAlgorithm, Kex};

    fn negotiated(cipher: Cipher, mac: Option<Mac>) -> Negotiated {
        Negotiated {
            kex: Kex::Curve25519Sha256,
            host_key: HostKeyAlgorithm::SshEd25519,
            cipher_client_to_server: cipher,
            cipher_server_to_client: cipher,
            mac_client_to_server: mac,
            mac_server_to_client: mac,
            discard_guess: false,
        }
    }

    #[test]
    fn each_direction_gets_keys_sized_for_its_own_algorithms() {
        let n = Negotiated {
            cipher_client_to_server: Cipher::Aes256Ctr,
            mac_client_to_server: Some(Mac::HmacSha512),
            cipher_server_to_client: Cipher::Aes128Gcm,
            mac_server_to_client: None,
            ..negotiated(Cipher::Chacha20Poly1305, None)
        };
        let keys = derive_keys(&[0x42; 32], &[0x43; 32], &[0x43; 32], &n);
        let c2s = &keys.client_to_server;
        assert_eq!(
            (c2s.iv.len(), c2s.key.len(), c2s.mac_key.len()),
            (16, 32, 64)
        );
        let s2c = &keys.server_to_client;
        assert_eq!(
            (s2c.iv.len(), s2c.key.len(), s2c.mac_key.len()),
            (12, 16, 0)
        );
        let chacha = derive_keys(
            &[0x42; 32],
            &[0x43; 32],
            &[0x43; 32],
            &negotiated(Cipher::Chacha20Poly1305, None),
        );
        let c = &chacha.client_to_server;
        assert_eq!((c.iv.len(), c.key.len(), c.mac_key.len()), (0, 64, 0));
    }

    /// Keys longer than one hash block extend by RFC 4253's `Kn` rule, and a key's prefix is the
    /// same however much of it is asked for (the property that lets a 16-byte key and a 32-byte
    /// one share a derivation).
    #[test]
    fn a_longer_key_extends_a_shorter_one() {
        let k = super::super::kex::encode_mpint(&[0x11; 32]);
        let short = derive_one(&k, &[0x22; 32], b'C', &[0x22; 32], 16);
        let mid = derive_one(&k, &[0x22; 32], b'C', &[0x22; 32], 32);
        let long = derive_one(&k, &[0x22; 32], b'C', &[0x22; 32], 64);
        assert_eq!(&mid[..16], &short[..]);
        assert_eq!(&long[..32], &mid[..]);
        assert_ne!(&long[32..], &long[..32]);
    }

    #[test]
    fn the_six_letters_give_six_different_keys() {
        let n = negotiated(Cipher::Aes256Ctr, Some(Mac::HmacSha256));
        let keys = derive_keys(&[0x01; 32], &[0x02; 32], &[0x02; 32], &n);
        let all = [
            &keys.client_to_server.iv,
            &keys.server_to_client.iv,
            &keys.client_to_server.key,
            &keys.server_to_client.key,
            &keys.client_to_server.mac_key,
            &keys.server_to_client.mac_key,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(&a[..16], &b[..16]);
            }
        }
    }
}
