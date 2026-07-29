pub const VERSION_MARKER: &str = "sensor-ssh";

// Modules added incrementally by later tasks (9-14).
// Each task adds its module here as pub so integration tests can import it.
pub mod auth;
pub mod channel;
pub mod fakefs;
pub mod hostkey;
pub mod server;
pub mod shell;
pub mod transfer;
pub mod transport;

pub use server::start_test_server;

#[cfg(test)]
mod tests {
    #[test]
    fn crypto_crates_available() {
        // Verify the crypto primitives are importable.
        let _ephemeral_secret_type = std::any::type_name::<x25519_dalek::EphemeralSecret>();
        let _signing_key_type = std::any::type_name::<ed25519_dalek::SigningKey>();

        // chacha20 + poly1305 are the primitives the transport cipher uses directly
        // (ADR-0011's pivot from the AEAD wrapper to raw primitives).
        let _chacha_type = std::any::type_name::<chacha20::ChaCha20Legacy>();
        let _poly_type = std::any::type_name::<poly1305::Poly1305>();
    }

    #[test]
    fn version_marker() {
        assert_eq!(super::VERSION_MARKER, "sensor-ssh");
    }
}
