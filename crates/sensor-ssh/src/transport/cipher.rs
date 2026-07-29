//! `chacha20-poly1305@openssh.com` transport encryption (ADR-0011's pinned cipher; the
//! encrypted transport RFC 4253 section 6's unencrypted framing in `transport::mod` gives way
//! to once Task 11's key exchange completes and `SSH_MSG_NEWKEYS` is sent).
//!
//! **This is not the IETF ChaCha20-Poly1305 AEAD (RFC 8439).** `chacha20poly1305::
//! ChaCha20Poly1305` in this crate's dependencies implements that IETF construction (96-bit
//! nonce, 32-bit block counter) and is unrelated to what real SSH clients speak here: OpenSSH's
//! `chacha20-poly1305@openssh.com` predates RFC 8439 and uses djb's original ChaCha20 (64-bit
//! nonce, 64-bit block counter, split across two state words) plus a raw, unpadded Poly1305
//! MAC - not the RFC 8439 AEAD framing. The two constructions produce different ciphertext and
//! a different tag for the same key/nonce/plaintext, so building this from the standard AEAD
//! wrapper would silently fail to interoperate with every unmodified attacker SSH client (see
//! "SSH handshake completes against a real client" in the design doc's testing strategy) while
//! still passing any test that only round-trips against itself. This module is instead a
//! direct, line-for-line port of OpenSSH's own reference implementation
//! (`cipher-chachapoly.c`, `chacha.c`, and `sshbuf.h`'s `POKE_U64` in openssh-portable),
//! verified against that source rather than against training-data recollection of "chacha20
//! poly1305", using RustCrypto's `chacha20::ChaCha20Legacy` (its name for djb's original,
//! pre-IETF construction) and the `poly1305` crate's unpadded one-time MAC.
//!
//! Per packet, two independently keyed `ChaCha20Legacy` instances:
//!
//! - **header** (last 32 bytes of the 64-byte cipher key): a plain stream cipher (no
//!   authentication of its own) over the 4-byte packet-length field, block counter 0.
//! - **main** (first 32 bytes): block 0 of its keystream for this nonce is never emitted as
//!   ciphertext - it is the one-time Poly1305 key. Payload encryption starts at block 1 (block
//!   0's other half discarded), mirroring `cipher-chachapoly.c`'s explicit
//!   `chacha_ivsetup(&ctx->main_ctx, seqbuf, one)` "set the block counter to 1" step.
//!
//! Nonce: the sequence number, widened from `u32` to `u64` (zero-extended, matching
//! `chachapoly_crypt`'s `u_int seqnr` argument being widened to `POKE_U64`'s `uint64_t`
//! parameter) and encoded big-endian - `(seq as u64).to_be_bytes()`. The Poly1305 tag is
//! computed over the encrypted length bytes followed by the encrypted payload bytes with no
//! extra padding or length fields (the pre-RFC8439 "unpadded" framing
//! `poly1305::Poly1305::compute_unpadded` implements, matching `poly1305_auth(tag, dest,
//! aadlen + len, poly_key)` in the C source), the encrypted length thereby serving as the
//! AEAD's associated data.
//!
//! `TransportCipher` itself is deliberately ignorant of SSH's own packet framing
//! (`padding_length` + payload + random padding): it treats whatever `payload` bytes it is
//! given as an opaque blob and prepends its own 4-byte length-of-that-blob field, so a later
//! task can feed it the full `padding_length || payload || padding` framing without this module
//! needing to know that structure exists.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20Legacy, Key as ChachaKey, LegacyNonce};
use poly1305::universal_hash::KeyInit as Poly1305KeyInit;
use poly1305::{Key as Poly1305Key, Poly1305};

/// Poly1305 authentication tag length (RFC 8439 section 2.5, unchanged by the
/// pre-standardization construction this module implements). `pub` because the
/// transport layer needs it to know how many bytes follow the encrypted payload on
/// the wire when reading an encrypted packet incrementally (4-byte encrypted length,
/// then `packet_length` encrypted body bytes, then `TAG_LEN` tag bytes).
pub const TAG_LEN: usize = 16;
/// SSH binary packet `packet_length` field width (RFC 4253 section 6).
const LENGTH_LEN: usize = 4;

/// Every error `TransportCipher::decrypt` can produce. `data` here is ciphertext a network peer
/// sent, so every variant comes from a checked condition, never a panic.
#[derive(Debug, PartialEq, Eq)]
pub enum CipherError {
    /// Shorter than `LENGTH_LEN + TAG_LEN`: not even large enough to hold the length field and
    /// the tag, let alone a payload.
    Truncated,
    /// The Poly1305 tag did not match. Covers both a corrupted/tampered wire byte and a
    /// decrypt attempted with the wrong `seq` (which derives a different nonce and thus a
    /// different one-time Poly1305 key) - both are "this is not an authentic packet for this
    /// sequence position" and are not distinguished further, so a caller cannot use the error
    /// variant itself as a padding/timing oracle.
    AuthenticationFailed,
    /// The tag verified, but the header cipher's decrypted length did not match the actual
    /// ciphertext length carried alongside it. Authentication happens first (see `decrypt`), so
    /// reaching this arm means the two encrypted fields were self-consistent under some other
    /// key/nonce than the caller expected only in a way that still happened to authenticate -
    /// vanishingly unlikely; this is a defense-in-depth check, not the primary integrity
    /// guarantee.
    LengthMismatch,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::Truncated => write!(f, "ciphertext too short to contain a valid packet"),
            CipherError::AuthenticationFailed => {
                write!(
                    f,
                    "Poly1305 authentication failed: tampered ciphertext or wrong sequence number"
                )
            }
            CipherError::LengthMismatch => {
                write!(
                    f,
                    "decrypted length field did not match the ciphertext length"
                )
            }
        }
    }
}

impl std::error::Error for CipherError {}

/// One direction's `chacha20-poly1305@openssh.com` cipher state: just the two 32-byte keys.
/// There is no other mutable state - every method derives its nonce fresh from the `seq` the
/// caller passes in, so one instance is safe to reuse across any sequence of `seq` values (see
/// `cipher_multiple_sequential_packets_round_trip` in the integration tests).
pub struct TransportCipher {
    main_key: [u8; 32],
    header_key: [u8; 32],
}

impl TransportCipher {
    pub fn new(main_key: &[u8; 32], header_key: &[u8; 32]) -> Self {
        Self {
            main_key: *main_key,
            header_key: *header_key,
        }
    }

    /// Decrypt the 4-byte encrypted packet-length field for a given sequence number, returning
    /// the plaintext `packet_length` value. Used by `read_packet_encrypted` to learn how many
    /// more bytes to read from the wire before passing the full blob to `decrypt` for
    /// authentication and payload decryption. This is a pure stateless derivation (header key +
    /// nonce from seq), so calling it before `decrypt` on the same seq does not interfere.
    pub fn decrypt_length(&self, seq: u32, encrypted_length: &[u8; 4]) -> u32 {
        let nonce = nonce_from_seq(seq);
        let mut buf = *encrypted_length;
        apply_header_keystream(&self.header_key, &nonce, &mut buf);
        u32::from_be_bytes(buf)
    }

    /// Encrypt `payload` for sequence number `seq`, returning
    /// `encrypted_length(4) || encrypted_payload(payload.len()) || tag(16)`.
    pub fn encrypt(&mut self, seq: u32, payload: &[u8]) -> Vec<u8> {
        let nonce = nonce_from_seq(seq);
        let poly_key = derive_poly_key(&self.main_key, &nonce);

        let length: u32 = payload
            .len()
            .try_into()
            .expect("payload length exceeds u32; caller must bound packet size upstream");
        let mut encrypted_length = length.to_be_bytes();
        apply_header_keystream(&self.header_key, &nonce, &mut encrypted_length);

        let mut encrypted_payload = payload.to_vec();
        apply_payload_keystream(&self.main_key, &nonce, &mut encrypted_payload);

        let mut out = Vec::with_capacity(LENGTH_LEN + encrypted_payload.len() + TAG_LEN);
        out.extend_from_slice(&encrypted_length);
        out.extend_from_slice(&encrypted_payload);

        let tag = Poly1305::new(&Poly1305Key::from(poly_key)).compute_unpadded(&out);
        out.extend_from_slice(tag.as_slice());
        out
    }

    /// Invert `encrypt`. Verifies the Poly1305 tag before touching plaintext (never decrypt an
    /// unauthenticated ciphertext), matching `chachapoly_crypt`'s own "if decrypting, check tag
    /// before anything else".
    pub fn decrypt(&mut self, seq: u32, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        if data.len() < LENGTH_LEN + TAG_LEN {
            return Err(CipherError::Truncated);
        }
        let (aad_and_ciphertext, received_tag) = data.split_at(data.len() - TAG_LEN);
        let (encrypted_length, encrypted_payload) = aad_and_ciphertext.split_at(LENGTH_LEN);

        let nonce = nonce_from_seq(seq);
        let poly_key = derive_poly_key(&self.main_key, &nonce);

        let expected_tag =
            Poly1305::new(&Poly1305Key::from(poly_key)).compute_unpadded(aad_and_ciphertext);
        if !constant_time_eq(expected_tag.as_slice(), received_tag) {
            return Err(CipherError::AuthenticationFailed);
        }

        let mut decrypted_length_bytes = [0u8; LENGTH_LEN];
        decrypted_length_bytes.copy_from_slice(encrypted_length);
        apply_header_keystream(&self.header_key, &nonce, &mut decrypted_length_bytes);
        let declared_length = u32::from_be_bytes(decrypted_length_bytes) as usize;
        if declared_length != encrypted_payload.len() {
            return Err(CipherError::LengthMismatch);
        }

        let mut decrypted_payload = encrypted_payload.to_vec();
        apply_payload_keystream(&self.main_key, &nonce, &mut decrypted_payload);
        Ok(decrypted_payload)
    }
}

/// `seqbuf` from `cipher-chachapoly.c`: the sequence number zero-extended to 64 bits and
/// encoded big-endian (`POKE_U64(seqbuf, (uint64_t)seqnr)` in `sshbuf.h`'s convention - verified
/// directly against that macro's definition, not assumed).
fn nonce_from_seq(seq: u32) -> [u8; 8] {
    u64::from(seq).to_be_bytes()
}

/// Derive the one-time Poly1305 key: block 0 of the **main** cipher's keystream for this nonce,
/// i.e. the keystream itself (XORed with 32 zero bytes). Mirrors
/// `chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL)` + `chacha_encrypt_bytes(&ctx->main_ctx,
/// poly_key, poly_key, sizeof(poly_key))`.
fn derive_poly_key(main_key: &[u8; 32], nonce: &[u8; 8]) -> [u8; 32] {
    let mut cipher = ChaCha20Legacy::new(&ChachaKey::from(*main_key), &LegacyNonce::from(*nonce));
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);
    poly_key
}

/// Encrypt/decrypt (XOR; symmetric) the 4-byte packet length in place with the **header**
/// cipher at block counter 0. Mirrors `chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL)` +
/// `chacha_encrypt_bytes(&ctx->header_ctx, ...)`. Independent key from `derive_poly_key`/
/// `apply_payload_keystream`, so both using block counter 0 does not reuse a keystream.
fn apply_header_keystream(header_key: &[u8; 32], nonce: &[u8; 8], length_bytes: &mut [u8; 4]) {
    let mut cipher = ChaCha20Legacy::new(&ChachaKey::from(*header_key), &LegacyNonce::from(*nonce));
    cipher.apply_keystream(length_bytes);
}

/// Encrypt/decrypt (XOR; symmetric) the payload in place with the **main** cipher starting at
/// block counter 1 (block 0 was consumed - and discarded here, exactly as the C reference
/// discards the half of it `derive_poly_key` did not use - by `derive_poly_key`). Mirrors
/// `chacha_ivsetup(&ctx->main_ctx, seqbuf, one)` where `one` sets the block counter to 1: a
/// fresh cipher instance's keystream is a continuous stream from block 0, so burning exactly
/// one 64-byte block (ChaCha20's block size) before the real payload reaches block 1 with no
/// dependency on a `seek()` API's block-vs-byte unit convention.
fn apply_payload_keystream(main_key: &[u8; 32], nonce: &[u8; 8], payload: &mut [u8]) {
    let mut cipher = ChaCha20Legacy::new(&ChachaKey::from(*main_key), &LegacyNonce::from(*nonce));
    let mut discard_block_zero = [0u8; 64];
    cipher.apply_keystream(&mut discard_block_zero);
    cipher.apply_keystream(payload);
}

/// Constant-time-ish equality: always compares every byte rather than short-circuiting, so
/// comparison time does not leak how many leading bytes of a forged tag happened to match.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against an independent implementation, not just this module's own
    /// round trip: a self-consistency test (encrypt with one instance, decrypt with another)
    /// cannot catch a systematic error shared by both sides of the same bug - e.g. a wrong
    /// endianness or an off-by-one block counter would still agree with itself. These bytes are
    /// the `ssh-cipher` crate's own `chacha20poly1305::tests::test_vector` (part of the
    /// `RustCrypto/ssh-key` project's independent `chacha20-poly1305@openssh.com`
    /// implementation, vendored transitively via this crate's `russh` dev-dependency ->
    /// `ssh-key` -> `ssh-cipher`): a real SSH_MSG_SERVICE_ACCEPT("ssh-userauth")
    /// packet body, K_2/main key, nonce = seq 3, and the 4-byte AAD standing in for an
    /// already-encrypted length field. This exercises exactly the two private helpers that
    /// matter for wire compatibility - `derive_poly_key` (block 0 of the main keystream) and
    /// `apply_payload_keystream` (block 1 onward) - against ciphertext and a tag this module
    /// never produced itself.
    #[test]
    fn matches_independent_reference_test_vector() {
        const KEY: [u8; 32] = [
            0x37, 0x9a, 0x8c, 0xa9, 0xe7, 0xe7, 0x05, 0x76, 0x36, 0x33, 0x21, 0x35, 0x11, 0xe8,
            0xd9, 0x2e, 0xb1, 0x48, 0xa4, 0x6f, 0x1d, 0xd0, 0x04, 0x5e, 0xc8, 0x16, 0x4e, 0x5d,
            0x23, 0xe4, 0x56, 0xeb,
        ];
        const NONCE: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        const AAD: [u8; 4] = [0x57, 0x09, 0xdb, 0x2d];
        const PT: [u8; 24] = [
            0x06, 0x05, 0x00, 0x00, 0x00, 0x0c, 0x73, 0x73, 0x68, 0x2d, 0x75, 0x73, 0x65, 0x72,
            0x61, 0x75, 0x74, 0x68, 0xde, 0x59, 0x49, 0xab, 0x06, 0x1f,
        ];
        const CT: [u8; 24] = [
            0x6d, 0xcf, 0xb0, 0x3b, 0xe8, 0xa5, 0x5e, 0x7f, 0x02, 0x20, 0x46, 0x56, 0x72, 0xed,
            0xd9, 0x21, 0x48, 0x9e, 0xa0, 0x17, 0x11, 0x98, 0xe8, 0xa7,
        ];
        const TAG: [u8; 16] = [
            0x3e, 0x82, 0xfe, 0x0a, 0x2d, 0xb7, 0x12, 0x8d, 0x58, 0xef, 0x8d, 0x90, 0x47, 0x96,
            0x3c, 0xa3,
        ];

        // NONCE is independently exactly `(3u64).to_be_bytes()`, confirming nonce_from_seq's
        // encoding against the reference vector's own nonce, not just against this crate's
        // derivation of it.
        assert_eq!(nonce_from_seq(3), NONCE);

        let poly_key = derive_poly_key(&KEY, &NONCE);
        let mut aad_and_ciphertext = Vec::new();
        aad_and_ciphertext.extend_from_slice(&AAD);
        aad_and_ciphertext.extend_from_slice(&CT);
        let tag = Poly1305::new(&Poly1305Key::from(poly_key)).compute_unpadded(&aad_and_ciphertext);
        assert_eq!(
            tag.as_slice(),
            &TAG,
            "Poly1305 tag did not match the reference vector"
        );

        let mut buf = PT;
        apply_payload_keystream(&KEY, &NONCE, &mut buf);
        assert_eq!(buf, CT, "ciphertext did not match the reference vector");

        // And the inverse: decrypting CT with the same key/nonce recovers PT.
        let mut buf = CT;
        apply_payload_keystream(&KEY, &NONCE, &mut buf);
        assert_eq!(
            buf, PT,
            "decrypting the reference ciphertext did not recover the plaintext"
        );
    }
}
