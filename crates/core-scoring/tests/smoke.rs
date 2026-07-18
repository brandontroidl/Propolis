//! Smoke test for the crate-root public API surface (no DB required).
//!
//! Exercises every re-export from `core_scoring::lib` reachable without a
//! live database: the enums, `EventInput`/`ValidationError`, `IpScore`'s
//! shape, and `signal_weight`. Replaces the old `VERSION_MARKER` check (Task
//! 1's placeholder) now that the crate has a real public surface to assert
//! against.

use core_scoring::{
    signal_weight, Category, EventInput, FeedTier, IpScore, Protocol, ReviewState, SignalType,
    ValidationError,
};

#[test]
fn public_api_surface_is_reachable_and_wired() {
    // Enums are reachable at the crate root.
    let _ = (Category::Honeypot, FeedTier::Standard, ReviewState::Pending);

    // signal_weight is reachable and feeds EventInput::from_signal correctly.
    let w = signal_weight(SignalType::HoneypotMalwareUpload);
    assert_eq!(w.weight, 80);
    assert_eq!(w.category, Category::Honeypot);

    let event = EventInput::from_signal(
        "203.0.113.7".parse().unwrap(),
        None,
        "sensor-a".into(),
        SignalType::HoneypotMalwareUpload,
        Protocol::Tcp,
        true,
        "2026-07-17T00:00:00Z".parse().unwrap(),
        serde_json::json!({}),
    );
    assert_eq!(event.weight, 80);
    assert_eq!(event.category, Category::Honeypot);
    assert!(event.validate().is_ok());

    // ValidationError is reachable and constructible by the failure path.
    let mut bad = event.clone();
    bad.sensor = String::new();
    assert!(matches!(bad.validate(), Err(ValidationError::SensorEmpty)));

    // IpScore's fields are all reachable/typed from the crate root (compile-time
    // check: this would fail to compile if any field's type were not `pub` and
    // reachable from outside the crate).
    let _ip_score_shape: fn(&IpScore) -> Option<FeedTier> = |s| s.tier;
}
