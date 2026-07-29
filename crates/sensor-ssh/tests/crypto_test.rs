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

// ---- Task 11: key exchange + encrypted channel ----

#[tokio::test]
async fn key_exchange_completes_and_encrypted_channel_works() {
    use sensor_ssh::hostkey::HostKey;
    use sensor_ssh::transport::kex::{
        build_client_ecdh_init, complete_kex_client, perform_kex_server,
    };
    use sensor_ssh::transport::{
        SSH_MSG_IGNORE, SSH_MSG_NEWKEYS, build_kexinit, read_packet_encrypted,
        read_packet_unencrypted, write_packet_encrypted, write_packet_unencrypted,
    };

    let host_key = HostKey::generate();
    let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

    // Server side: send KEXINIT, receive client KEXINIT + ECDH_INIT, perform key exchange.
    let server_task = tokio::spawn({
        let host_key = host_key.clone();
        async move {
            let server_kexinit = build_kexinit();
            write_packet_unencrypted(&mut server_stream, &server_kexinit)
                .await
                .unwrap();
            let client_kexinit_pkt = read_packet_unencrypted(&mut server_stream).await.unwrap();
            let client_ecdh_init = read_packet_unencrypted(&mut server_stream).await.unwrap();
            let session_keys = perform_kex_server(
                &mut server_stream,
                &host_key,
                &client_kexinit_pkt.payload,
                &server_kexinit,
                "SSH-2.0-TestClient",
                "SSH-2.0-TestServer",
                &client_ecdh_init.payload,
            )
            .await
            .unwrap();
            let _newkeys = read_packet_unencrypted(&mut server_stream).await.unwrap();
            write_packet_unencrypted(&mut server_stream, &[SSH_MSG_NEWKEYS])
                .await
                .unwrap();
            (server_stream, session_keys)
        }
    });

    // Client side: receive server KEXINIT, send client KEXINIT + ECDH_INIT, complete key exchange.
    let client_kexinit = build_kexinit();
    let server_kexinit_pkt = read_packet_unencrypted(&mut client_stream).await.unwrap();
    write_packet_unencrypted(&mut client_stream, &client_kexinit)
        .await
        .unwrap();
    let (client_ephemeral, client_ecdh_init) = build_client_ecdh_init();
    write_packet_unencrypted(&mut client_stream, &client_ecdh_init)
        .await
        .unwrap();
    let ecdh_reply = read_packet_unencrypted(&mut client_stream).await.unwrap();
    let client_keys = complete_kex_client(
        client_ephemeral,
        &ecdh_reply.payload,
        &client_kexinit,
        &server_kexinit_pkt.payload,
        "SSH-2.0-TestClient",
        "SSH-2.0-TestServer",
    )
    .unwrap();
    write_packet_unencrypted(&mut client_stream, &[SSH_MSG_NEWKEYS])
        .await
        .unwrap();
    let _newkeys = read_packet_unencrypted(&mut client_stream).await.unwrap();

    let (mut server_stream, server_keys) = server_task.await.unwrap();

    // Both sides must derive the same session keys.
    assert_eq!(client_keys.session_id, server_keys.session_id);

    // Test encrypted communication: server -> client.
    let mut server_enc = server_keys.server_to_client_cipher();
    let mut client_dec = client_keys.server_to_client_cipher();
    let test_payload = vec![SSH_MSG_IGNORE, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
    write_packet_encrypted(&mut server_stream, &mut server_enc, 0, &test_payload)
        .await
        .unwrap();
    let decrypted = read_packet_encrypted(&mut client_stream, &mut client_dec, 0)
        .await
        .unwrap();
    assert_eq!(decrypted, test_payload);
}

#[test]
fn session_key_derivation_deterministic() {
    use sensor_ssh::transport::keys::derive_keys;
    let shared_secret = [0x42u8; 32];
    let exchange_hash = [0x43u8; 32];
    let session_id = exchange_hash;
    let keys1 = derive_keys(&shared_secret, &exchange_hash, &session_id);
    let keys2 = derive_keys(&shared_secret, &exchange_hash, &session_id);
    assert_eq!(keys1.client_to_server_key, keys2.client_to_server_key);
    assert_eq!(keys1.server_to_client_key, keys2.server_to_client_key);
    assert_eq!(keys1.session_id, keys2.session_id);
}

#[test]
fn session_key_derivation_different_inputs_produce_different_keys() {
    use sensor_ssh::transport::keys::derive_keys;
    let keys_a = derive_keys(&[0x42u8; 32], &[0x43u8; 32], &[0x43u8; 32]);
    let keys_b = derive_keys(&[0x99u8; 32], &[0x43u8; 32], &[0x43u8; 32]);
    assert_ne!(
        keys_a.client_to_server_key, keys_b.client_to_server_key,
        "different shared secrets must produce different keys"
    );
}

#[test]
fn session_keys_cipher_split_is_correct_length() {
    use sensor_ssh::transport::keys::derive_keys;
    let keys = derive_keys(&[0x11u8; 32], &[0x22u8; 32], &[0x22u8; 32]);
    assert_eq!(keys.client_to_server_key.len(), 64);
    assert_eq!(keys.server_to_client_key.len(), 64);
    // Must be able to construct ciphers without panic.
    let _c2s = keys.client_to_server_cipher();
    let _s2c = keys.server_to_client_cipher();
}

#[test]
fn mpint_encoding_handles_leading_high_bit() {
    use sensor_ssh::transport::kex::encode_mpint;
    // Value with MSB set: must get a leading zero byte.
    let val = [0xFF; 32];
    let encoded = encode_mpint(&val);
    let len = u32::from_be_bytes(encoded[0..4].try_into().unwrap()) as usize;
    assert_eq!(len, 33, "MSB-set value needs a leading zero byte");
    assert_eq!(
        encoded[4], 0,
        "leading byte must be zero for positive mpint"
    );

    // Value with MSB clear: no padding needed.
    let mut val2 = [0u8; 32];
    val2[0] = 0x7F;
    val2[1] = 0xAB;
    let encoded2 = encode_mpint(&val2);
    let len2 = u32::from_be_bytes(encoded2[0..4].try_into().unwrap()) as usize;
    assert_eq!(len2, 32, "MSB-clear value needs no padding");
    assert_eq!(encoded2[4], 0x7F);
}

#[test]
fn mpint_encoding_strips_leading_zeros() {
    use sensor_ssh::transport::kex::encode_mpint;
    let mut val = [0u8; 32];
    val[30] = 0x01;
    val[31] = 0x02;
    let encoded = encode_mpint(&val);
    let len = u32::from_be_bytes(encoded[0..4].try_into().unwrap()) as usize;
    assert_eq!(len, 2, "leading zeros must be stripped");
    assert_eq!(&encoded[4..6], &[0x01, 0x02]);
}

#[test]
fn mpint_encoding_all_zeros() {
    use sensor_ssh::transport::kex::encode_mpint;
    let val = [0u8; 32];
    let encoded = encode_mpint(&val);
    // mpint zero: 4-byte length of 0, no value bytes
    assert_eq!(encoded, vec![0, 0, 0, 0]);
}
