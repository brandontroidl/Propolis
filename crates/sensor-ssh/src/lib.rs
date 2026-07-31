pub const VERSION_MARKER: &str = "sensor-ssh";

// Modules added incrementally by later tasks (9-14).
// Each task adds its module here as pub so integration tests can import it.
pub mod auth;
pub mod channel;
pub mod hostkey;
pub mod server;
pub mod transfer;
pub mod transport;

// FakeFs/FakeShell moved to sensor-framework (Task 1 of the remaining-sensors plan) so
// sensor-telnet/sensor-adb can reuse them without depending on sensor-ssh. Re-exported here so
// existing `sensor_ssh::fakefs`/`sensor_ssh::shell` imports (including this crate's own
// `crate::fakefs`/`crate::shell` uses in server.rs) keep resolving unchanged.
pub use sensor_framework::fakefs;
pub use sensor_framework::shell;

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
