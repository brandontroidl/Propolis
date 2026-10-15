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

use sensor_ssh::transport::algorithms::{Cipher, HostKeyAlgorithm, Kex, Mac, Negotiated};

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

#[tokio::test]
async fn key_exchange_completes_and_encrypted_channel_works() {
    use sensor_ssh::hostkey::HostKey;
    use sensor_ssh::transport::kex::{
        Transcript, build_client_ecdh_init, complete_kex_client, perform_kex_server,
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
                &Transcript {
                    client_version: "SSH-2.0-TestClient",
                    server_version: "SSH-2.0-TestServer",
                    client_kexinit: &client_kexinit_pkt.payload,
                    server_kexinit: &server_kexinit,
                },
                &client_ecdh_init.payload,
                &negotiated(Cipher::Chacha20Poly1305, None),
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
        &Transcript {
            client_version: "SSH-2.0-TestClient",
            server_version: "SSH-2.0-TestServer",
            client_kexinit: &client_kexinit,
            server_kexinit: &server_kexinit_pkt.payload,
        },
        &negotiated(Cipher::Chacha20Poly1305, None),
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
    let n = negotiated(Cipher::Chacha20Poly1305, None);
    let keys1 = derive_keys(&shared_secret, &exchange_hash, &session_id, &n);
    let keys2 = derive_keys(&shared_secret, &exchange_hash, &session_id, &n);
    assert_eq!(keys1.client_to_server.key, keys2.client_to_server.key);
    assert_eq!(keys1.server_to_client.key, keys2.server_to_client.key);
    assert_eq!(keys1.session_id, keys2.session_id);
}

#[test]
fn session_key_derivation_different_inputs_produce_different_keys() {
    use sensor_ssh::transport::keys::derive_keys;
    let n = negotiated(Cipher::Chacha20Poly1305, None);
    let keys_a = derive_keys(&[0x42u8; 32], &[0x43u8; 32], &[0x43u8; 32], &n);
    let keys_b = derive_keys(&[0x99u8; 32], &[0x43u8; 32], &[0x43u8; 32], &n);
    assert_ne!(
        keys_a.client_to_server.key, keys_b.client_to_server.key,
        "different shared secrets must produce different keys"
    );
}

#[test]
fn session_keys_cipher_split_is_correct_length() {
    use sensor_ssh::transport::keys::derive_keys;
    let n = negotiated(Cipher::Chacha20Poly1305, None);
    let keys = derive_keys(&[0x11u8; 32], &[0x22u8; 32], &[0x22u8; 32], &n);
    assert_eq!(keys.client_to_server.key.len(), 64);
    assert_eq!(keys.server_to_client.key.len(), 64);
    // Must be able to construct ciphers without panic.
    let _c2s = keys.client_to_server_cipher();
    let _s2c = keys.server_to_client_cipher();
}

/// Every cipher, with every MAC it can be paired with, carries packets of every size in both
/// directions over a long run of sequence numbers. Both ends derive their keys from the same
/// inputs, as a real exchange does, so this proves the framing and the key schedule are
/// self-consistent; the system OpenSSH client (`kex_negotiation.rs`) is what proves they are
/// the SSH ones.
#[tokio::test]
async fn every_negotiable_cipher_and_mac_round_trips_packets() {
    use sensor_ssh::transport::algorithms::Algorithm;
    use sensor_ssh::transport::keys::derive_keys;
    use sensor_ssh::transport::{read_packet_encrypted, write_packet_encrypted};

    let mut combos = Vec::new();
    for &cipher in Cipher::ALL {
        if cipher.is_aead() {
            combos.push((cipher, None));
        } else {
            combos.extend(Mac::ALL.iter().map(|&mac| (cipher, Some(mac))));
        }
    }
    // Three AEADs, and each of the three CTR key sizes with each of the six MACs.
    assert_eq!(combos.len(), 3 + 3 * 6, "{combos:?}");

    for (cipher, mac) in combos {
        let n = negotiated(cipher, mac);
        let keys = derive_keys(&[0x5au8; 32], &[0xa5u8; 32], &[0xa5u8; 32], &n);
        let peer = derive_keys(&[0x5au8; 32], &[0xa5u8; 32], &[0xa5u8; 32], &n);
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let (mut tx_c2s, mut rx_c2s) = (
            keys.client_to_server_cipher(),
            peer.client_to_server_cipher(),
        );
        let (mut tx_s2c, mut rx_s2c) = (
            keys.server_to_client_cipher(),
            peer.server_to_client_cipher(),
        );
        for seq in 0..40u32 {
            // The large sizes cost a debug build seconds across 21 combinations, and a size
            // class needs no more than a few sequence numbers.
            let sizes: &[usize] = if seq < 3 {
                &[1, 2, 15, 16, 17, 31, 32, 33, 100, 1000, 20_000]
            } else {
                &[1, 15, 16, 17, 33, 100]
            };
            for &len in sizes {
                let payload: Vec<u8> = (0..len).map(|i| (i as u32 ^ seq) as u8).collect();
                write_packet_encrypted(&mut a, &mut tx_c2s, seq, &payload)
                    .await
                    .unwrap();
                let got = read_packet_encrypted(&mut b, &mut rx_c2s, seq)
                    .await
                    .unwrap_or_else(|e| panic!("{cipher:?}/{mac:?} c2s seq {seq} len {len}: {e}"));
                assert_eq!(got, payload, "{cipher:?}/{mac:?}");
                write_packet_encrypted(&mut b, &mut tx_s2c, seq, &payload)
                    .await
                    .unwrap();
                let got = read_packet_encrypted(&mut a, &mut rx_s2c, seq)
                    .await
                    .unwrap_or_else(|e| panic!("{cipher:?}/{mac:?} s2c seq {seq} len {len}: {e}"));
                assert_eq!(got, payload, "{cipher:?}/{mac:?}");
            }
        }
    }
}

/// A packet altered anywhere on the wire, or presented at the wrong sequence number, is refused
/// by every cipher and MAC rather than decrypted to something.
#[tokio::test]
async fn every_cipher_and_mac_refuses_a_packet_that_was_altered() {
    use sensor_ssh::transport::algorithms::Algorithm;
    use sensor_ssh::transport::keys::derive_keys;
    use sensor_ssh::transport::{read_packet_encrypted, write_packet_encrypted};
    use tokio::io::AsyncWriteExt;

    let mut combos = Vec::new();
    for &cipher in Cipher::ALL {
        if cipher.is_aead() {
            combos.push((cipher, None));
        } else {
            combos.extend(Mac::ALL.iter().map(|&mac| (cipher, Some(mac))));
        }
    }
    for (cipher, mac) in combos {
        let n = negotiated(cipher, mac);
        let payload = vec![0x41u8; 40];
        // One wire image, then every byte of it flipped in turn, each against a fresh receiver.
        let keys = derive_keys(&[7u8; 32], &[8u8; 32], &[8u8; 32], &n);
        let mut tx = keys.client_to_server_cipher();
        let (mut w, mut r) = tokio::io::duplex(1 << 16);
        write_packet_encrypted(&mut w, &mut tx, 0, &payload)
            .await
            .unwrap();
        drop(w);
        let mut wire = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut wire)
            .await
            .unwrap();
        for i in 0..wire.len() {
            let mut altered = wire.clone();
            altered[i] ^= 0x01;
            let rx_keys = derive_keys(&[7u8; 32], &[8u8; 32], &[8u8; 32], &n);
            let mut rx = rx_keys.client_to_server_cipher();
            let (mut w, mut r) = tokio::io::duplex(1 << 16);
            w.write_all(&altered).await.unwrap();
            drop(w);
            let got = read_packet_encrypted(&mut r, &mut rx, 0).await;
            assert!(
                got.is_err(),
                "{cipher:?}/{mac:?}: a flip at byte {i} was accepted ({got:?})"
            );
        }
        // Wrong sequence number: the MAC, tag or nonce no longer fits.
        let rx_keys = derive_keys(&[7u8; 32], &[8u8; 32], &[8u8; 32], &n);
        let mut rx = rx_keys.client_to_server_cipher();
        let (mut w, mut r) = tokio::io::duplex(1 << 16);
        w.write_all(&wire).await.unwrap();
        drop(w);
        let got = read_packet_encrypted(&mut r, &mut rx, 1).await;
        // GCM binds the packet to its position by its invocation counter, not the sequence
        // number, so it alone accepts a repeat of seq 0 at "seq 1".
        let is_gcm = matches!(cipher, Cipher::Aes128Gcm | Cipher::Aes256Gcm);
        assert_eq!(got.is_err(), !is_gcm, "{cipher:?}/{mac:?}: wrong seq");
    }
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
