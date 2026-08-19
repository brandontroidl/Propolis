//! Canonical byte encoding and SHA-256 hash chain for `EventInput`.
//!
//! # FROZEN ENCODING - DO NOT CHANGE
//!
//! `canonical_bytes` defines the on-disk/on-chain byte representation of an
//! `EventInput`. The field order, framing, and per-field encoding below are
//! FROZEN: every previously-computed `chain_hash` was computed against this
//! exact layout. Changing the field order, adding/removing a field, or
//! changing how a field is framed will silently change the hash of every
//! future event and break the hash chain for every event already persisted
//! (a re-derived hash for an old event will no longer match the stored one,
//! and the chain can no longer be verified). If the shape of `EventInput`
//! must change in a way that affects hashing, introduce a new, explicitly
//! versioned encoding function instead of editing this one.
//!
//! We deliberately do NOT hash `serde_json::to_string(event)` (or any
//! `Serialize` impl of the whole struct): JSON key order for a
//! `#[derive(Serialize)]` struct follows declaration order, which is an
//! incidental property of the struct definition, not a guaranteed contract,
//! and would be easy to invalidate via a harmless-looking field reorder.
//! Instead every field is written explicitly, in a fixed order, with
//! unambiguous framing (length-prefixed for anything variable-length) so
//! that two adjacent fields can never blur into each other.
//!
//! ## Frozen field order and encoding
//!
//! 1. `source_ip`  - `to_string()` bytes, length-prefixed (u64 LE length + bytes).
//! 2. `wan_ip`     - presence byte (`0` = `None`, `1` = `Some`), then if
//!    present, `to_string()` bytes, length-prefixed.
//! 3. `sensor`     - UTF-8 bytes, length-prefixed.
//! 4. `signal_type`- serde JSON encoding of the enum (a quoted variant
//!    label), length-prefixed.
//! 5. `protocol`   - serde JSON encoding of the enum, length-prefixed.
//! 6. `authenticated` - single byte, `0` or `1`.
//! 7. `category`   - serde JSON encoding of the enum, length-prefixed.
//! 8. `weight`     - `u32` little-endian, 4 bytes, no length prefix.
//! 9. `confidence` - `Decimal::to_string()` canonical string bytes, length-prefixed.
//! 10. `observed_at` - RFC3339 string bytes, length-prefixed.
//! 11. `metadata`  - `serde_json::to_vec(&metadata)` bytes, length-prefixed.
//!     Our `serde_json` dependency does not enable the `preserve_order`
//!     feature, so `serde_json::Map` is backed by a `BTreeMap` and object
//!     key serialization order is deterministic (sorted), not
//!     insertion-order-dependent.
//!
//! `chain_hash(prev, event)` hashes `prev.unwrap_or(&[])` followed by
//! `canonical_bytes(event)` through SHA-256, binding each event to the
//! hash of the event before it.

use sha2::{Digest, Sha256};

use crate::domain::types::EventInput;

/// Appends `bytes` to `buf` preceded by its length as a little-endian `u64`.
///
/// This is the framing primitive that keeps variable-length fields from
/// blurring together: a reader (or another encoder) always knows exactly
/// how many bytes belong to this field before the next one starts. The
/// length prefix is `u64` (not `u32`) so that a field at or beyond 4 GiB
/// cannot silently wrap and collide with a shorter field's encoding;
/// `bytes.len()` is `usize`, and the `as u64` cast is lossless on every
/// platform we support (no 128-bit-pointer targets).
fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Serializes `event` into the frozen canonical byte encoding.
///
/// See the module-level documentation for the exact frozen field order and
/// per-field framing. This function must remain deterministic: the same
/// `EventInput` value must always produce the same bytes.
pub fn canonical_bytes(event: &EventInput) -> Vec<u8> {
    let mut buf = Vec::new();

    // 1. source_ip
    push_len_prefixed(&mut buf, event.source_ip.to_string().as_bytes());

    // 2. wan_ip (presence byte then optional bytes)
    match event.wan_ip {
        Some(ip) => {
            buf.push(1);
            push_len_prefixed(&mut buf, ip.to_string().as_bytes());
        }
        None => buf.push(0),
    }

    // 3. sensor
    push_len_prefixed(&mut buf, event.sensor.as_bytes());

    // 4. signal_type
    let signal_type_json =
        serde_json::to_vec(&event.signal_type).expect("SignalType serialization is infallible");
    push_len_prefixed(&mut buf, &signal_type_json);

    // 5. protocol
    let protocol_json =
        serde_json::to_vec(&event.protocol).expect("Protocol serialization is infallible");
    push_len_prefixed(&mut buf, &protocol_json);

    // 6. authenticated
    buf.push(if event.authenticated { 1 } else { 0 });

    // 7. category
    let category_json =
        serde_json::to_vec(&event.category).expect("Category serialization is infallible");
    push_len_prefixed(&mut buf, &category_json);

    // 8. weight (fixed-width, no length prefix needed)
    buf.extend_from_slice(&event.weight.to_le_bytes());

    // 9. confidence
    push_len_prefixed(&mut buf, event.confidence.to_string().as_bytes());

    // 10. observed_at
    push_len_prefixed(&mut buf, event.observed_at.to_rfc3339().as_bytes());

    // 11. metadata
    let metadata_json =
        serde_json::to_vec(&event.metadata).expect("serde_json::Value serialization is infallible");
    push_len_prefixed(&mut buf, &metadata_json);

    buf
}

/// Computes the SHA-256 chain hash for `event`, binding it to `prev`.
///
/// Hashes `prev.unwrap_or(&[])` followed by `canonical_bytes(event)`, so
/// each event's hash depends on both its own content and the hash of the
/// event immediately before it in the chain (`prev = None` for the first
/// event in a chain).
pub fn chain_hash(prev: Option<&[u8]>, event: &EventInput) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev.unwrap_or(&[]));
    hasher.update(canonical_bytes(event));
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::enums::{Protocol, SignalType};
    use proptest::prelude::*;

    fn sample_event() -> EventInput {
        EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            Some("203.0.113.99".parse().unwrap()),
            "sensor-a".into(),
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z".parse().unwrap(),
            serde_json::json!({"note": "test", "count": 3}),
            None,
        )
    }

    #[test]
    fn hash_is_deterministic_for_same_event() {
        let e = sample_event();
        assert_eq!(chain_hash(None, &e), chain_hash(None, &e));
    }

    #[test]
    fn mutating_any_field_changes_the_hash() {
        let e = sample_event();
        let mut e2 = e.clone();
        e2.weight += 1;
        assert_ne!(chain_hash(None, &e), chain_hash(None, &e2));
    }

    #[test]
    fn prev_hash_is_bound_into_the_chain() {
        let e = sample_event();
        assert_ne!(chain_hash(None, &e), chain_hash(Some(&[9u8; 32]), &e));
    }

    #[test]
    fn wan_ip_none_differs_from_wan_ip_present() {
        let mut e = sample_event();
        e.wan_ip = None;
        let mut e2 = e.clone();
        e2.wan_ip = Some("203.0.113.50".parse().unwrap());
        assert_ne!(chain_hash(None, &e), chain_hash(None, &e2));
    }

    /// Pins the exact frozen-encoding output for a fixed `EventInput`.
    ///
    /// golden vector - if this changes, the frozen encoding changed; that
    /// breaks all chains and must be a deliberate, documented decision.
    #[test]
    fn golden_chain_hash_is_stable() {
        let event = EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-golden".into(),
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z".parse().unwrap(),
            serde_json::json!({}),
            None,
        );

        let hash = chain_hash(None, &event);

        let expected: [u8; 32] = [
            117, 64, 177, 139, 8, 38, 105, 160, 97, 173, 48, 168, 50, 243, 227, 136, 125, 143, 174,
            61, 242, 91, 114, 102, 155, 19, 250, 105, 18, 25, 120, 100,
        ];

        let hex_string: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hash, expected, "golden hash mismatch - hex: {}", hex_string);
    }

    proptest! {
        #[test]
        fn canonical_bytes_is_deterministic_for_arbitrary_sensor_and_weight(
            sensor in "[a-zA-Z0-9_-]{1,32}",
            weight in 0u32..10_000,
        ) {
            let mut e = sample_event();
            e.sensor = sensor;
            e.weight = weight;
            prop_assert_eq!(canonical_bytes(&e), canonical_bytes(&e));
        }

        #[test]
        fn changing_sensor_alone_changes_the_hash(
            sensor_a in "[a-zA-Z0-9_-]{1,32}",
            sensor_b in "[a-zA-Z0-9_-]{1,32}",
        ) {
            prop_assume!(sensor_a != sensor_b);
            let mut e1 = sample_event();
            e1.sensor = sensor_a;
            let mut e2 = e1.clone();
            e2.sensor = sensor_b;
            prop_assert_ne!(chain_hash(None, &e1), chain_hash(None, &e2));
        }
    }
}
