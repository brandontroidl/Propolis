//! Integration tests for `sensor_ssh::hostkey` and `sensor_ssh::transport::cipher`.
//!
//! The first six tests are this task's dictated interface tests. The remaining tests close
//! gaps the dictated suite leaves open, mirroring `transport_test.rs`'s own precedent of
//! adding coverage beyond a brief's given tests: the sequence number is part of the cipher's
//! authenticated nonce (a reordering/replay guard), so a wrong `seq` must fail exactly like
//! tampered ciphertext; both `TransportCipher::decrypt` and `HostKey::verify` parse
//! attacker-reachable bytes and must never panic, only the given tampered-ciphertext test
//! exercises that for the cipher and nothing exercises it for the host key signature blob.

#[test]
fn host_key_generate_save_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host_key");
    let key = sensor_ssh::hostkey::HostKey::generate();
    key.save(&path).unwrap();
    let loaded = sensor_ssh::hostkey::HostKey::load(&path).unwrap();
    assert_eq!(key.public_key_blob(), loaded.public_key_blob());
}

#[test]
fn host_key_sign_and_verify() {
    let key = sensor_ssh::hostkey::HostKey::generate();
    let data = b"exchange hash data";
    let sig = key.sign(data);
    assert!(key.verify(data, &sig));
    assert!(!key.verify(b"wrong data", &sig));
}

#[test]
fn host_key_public_blob_ssh_format() {
    let key = sensor_ssh::hostkey::HostKey::generate();
    let blob = key.public_key_blob();
    // SSH public key blob format: string "ssh-ed25519" + string <32 bytes public key>
    // Verify the blob starts with the correct algorithm name.
    let algo_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let algo = std::str::from_utf8(&blob[4..4 + algo_len]).unwrap();
    assert_eq!(algo, "ssh-ed25519");
}

#[test]
fn chacha20poly1305_encrypt_decrypt_round_trip() {
    use sensor_ssh::transport::cipher::TransportCipher;
    // Use test keys (32 bytes each for main key and header key).
    let main_key = [0x42u8; 32];
    let header_key = [0x43u8; 32];
    let mut enc = TransportCipher::new(&main_key, &header_key);
    let mut dec = TransportCipher::new(&main_key, &header_key);
    let payload = b"hello encrypted ssh";
    let seq: u32 = 0;
    let encrypted = enc.encrypt(seq, payload);
    let decrypted = dec.decrypt(seq, &encrypted).unwrap();
    assert_eq!(decrypted, payload);
}

#[test]
fn chacha20poly1305_tampered_ciphertext_fails() {
    use sensor_ssh::transport::cipher::TransportCipher;
    let main_key = [0x42u8; 32];
    let header_key = [0x43u8; 32];
    let mut enc = TransportCipher::new(&main_key, &header_key);
    let mut dec = TransportCipher::new(&main_key, &header_key);
    let mut encrypted = enc.encrypt(0, b"test");
    // Flip a bit in the ciphertext.
    if let Some(byte) = encrypted.last_mut() {
        *byte ^= 1;
    }
    let result = dec.decrypt(0, &encrypted);
    assert!(
        result.is_err(),
        "tampered ciphertext must fail authentication"
    );
}

#[test]
#[cfg(unix)]
fn host_key_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host_key");
    let key = sensor_ssh::hostkey::HostKey::generate();
    key.save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "host key file must be 0600, got {mode:o}");
}

// ---- Coverage beyond the brief's given suite ----

#[test]
fn cipher_wrong_sequence_number_fails_authentication() {
    use sensor_ssh::transport::cipher::TransportCipher;
    // The sequence number feeds the nonce and thus the per-packet Poly1305 key; decrypting
    // with the wrong seq must be rejected exactly like tampered ciphertext, or a
    // replayed/reordered packet could be accepted under the wrong sequence position.
    let main_key = [0x11u8; 32];
    let header_key = [0x22u8; 32];
    let mut enc = TransportCipher::new(&main_key, &header_key);
    let mut dec = TransportCipher::new(&main_key, &header_key);
    let encrypted = enc.encrypt(5, b"payload for packet five");
    let result = dec.decrypt(6, &encrypted);
    assert!(result.is_err(), "decrypting with the wrong seq must fail");
}

#[test]
fn cipher_truncated_ciphertext_returns_err_not_panic() {
    use sensor_ssh::transport::cipher::TransportCipher;
    let mut dec = TransportCipher::new(&[0u8; 32], &[0u8; 32]);
    // Shorter than the 4-byte length field + 16-byte tag; must be a clean Err, never a panic.
    assert!(dec.decrypt(0, &[]).is_err());
    assert!(dec.decrypt(0, &[0u8; 10]).is_err());
}

#[test]
fn cipher_multiple_sequential_packets_round_trip() {
    use sensor_ssh::transport::cipher::TransportCipher;
    // Proves the cipher is stateless with respect to the caller-supplied seq (no hidden
    // internal counter) and that the block-1-skip for payload encryption is re-derived
    // correctly on every call, not just the first, by reusing one enc/dec pair across
    // several non-consecutive sequence numbers.
    let main_key = [0x77u8; 32];
    let header_key = [0x88u8; 32];
    let mut enc = TransportCipher::new(&main_key, &header_key);
    let mut dec = TransportCipher::new(&main_key, &header_key);
    for seq in [0u32, 1, 5, 1000] {
        let payload = format!("packet number {seq}");
        let encrypted = enc.encrypt(seq, payload.as_bytes());
        let decrypted = dec.decrypt(seq, &encrypted).unwrap();
        assert_eq!(decrypted, payload.as_bytes());
    }
}

#[test]
fn host_key_verify_rejects_malformed_signature_blob() {
    let key = sensor_ssh::hostkey::HostKey::generate();
    assert!(!key.verify(b"data", &[]));
    assert!(!key.verify(b"data", &[0u8; 3]));
    // Claims a huge algorithm-name length that runs past the end of the buffer.
    assert!(!key.verify(b"data", &0xFFFF_FFFFu32.to_be_bytes()));
}

proptest::proptest! {
    /// Fuzz-lite guard mirroring `transport::parse_kexinit_never_panics_on_arbitrary_bytes`:
    /// `verify` parses a caller-supplied signature blob that may not have come from this
    /// key's own `sign`, so arbitrary (including truncated/malformed) bytes must never panic.
    #[test]
    fn host_key_verify_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256)
    ) {
        let key = sensor_ssh::hostkey::HostKey::generate();
        let _ = key.verify(b"some data", &bytes);
    }
}
