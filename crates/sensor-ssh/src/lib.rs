pub const VERSION_MARKER: &str = "sensor-ssh";

// Modules added incrementally by later tasks (9-14).
// Each task adds its module here as pub so integration tests can import it.
// pub mod transport;
// pub mod hostkey;
// pub mod auth;
// pub mod channel;
// pub mod shell;
// pub mod fakefs;
// pub mod transfer;
//
// pub fn start_test_server(...) for integration tests (Task 14).

#[cfg(test)]
mod tests {
    #[test]
    fn crypto_crates_available() {
        // Verify the crypto primitives are importable.
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{Nonce, ChaCha20Poly1305};
        use std::convert::TryFrom;

        // Verify each crypto crate can be imported and basic types are accessible
        let _ephemeral_secret_type = std::any::type_name::<x25519_dalek::EphemeralSecret>();
        let _signing_key_type = std::any::type_name::<ed25519_dalek::SigningKey>();
        let _cipher_type = std::any::type_name::<ChaCha20Poly1305>();

        // Test ChaCha20Poly1305 with a known key
        let key_bytes = [1u8; 32];
        let key = chacha20poly1305::Key::from(key_bytes);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::try_from(&b"unique nonce"[..]).unwrap();
        let ct = cipher.encrypt(&nonce, b"test".as_ref()).unwrap();
        let pt = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        assert_eq!(pt, b"test");
    }

    #[test]
    fn version_marker() {
        assert_eq!(super::VERSION_MARKER, "sensor-ssh");
    }
}
