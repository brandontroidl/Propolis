//! Wire-to-domain conversion: `sensor_wire::SensorEvent` -> `core_scoring::EventInput`.
//!
//! Fails closed: an unrecognized signal type or protocol, a schema version this build does not
//! understand, or a value `EventInput::validate` rejects is returned as an error rather than
//! coerced, defaulted, or silently dropped.

use core_scoring::{EventInput, Protocol, SignalType, ValidationError};
use sensor_wire::{SampleRef, SensorEvent, WIRE_VERSION};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("unknown signal type: {0}")]
    UnknownSignalType(String),
    #[error("unknown protocol: {0}")]
    UnknownProtocol(String),
    #[error("unsupported wire schema version: {0}")]
    UnsupportedVersion(u32),
    #[error("event failed validation: {0:?}")]
    Validation(ValidationError),
}

/// Converts one wire-format sensor event into a validated `core-scoring` domain event.
///
/// `weight`, `confidence`, and `category` are derived solely from `signal_type` via
/// `EventInput::from_signal` (the signal weight table) - a sensor never supplies them, and
/// this function can never let one drift out of sync with the others.
pub fn convert(event: SensorEvent) -> Result<EventInput, ConvertError> {
    if event.v != WIRE_VERSION {
        return Err(ConvertError::UnsupportedVersion(event.v));
    }

    // signal_type/protocol ride the wire as plain strings (sensor-wire carries no core-scoring
    // dependency); route them through the enums' own deserialize-only rename_all so the known
    // wire vocabulary (sensor_wire::SIGNAL_*/PROTO_* constants) is the single source of truth
    // for what "known" means, rather than a hand-maintained match here that could drift from it.
    let signal_type: SignalType = serde_json::from_value(Value::String(event.signal_type.clone()))
        .map_err(|_| ConvertError::UnknownSignalType(event.signal_type))?;

    let protocol: Protocol = serde_json::from_value(Value::String(event.protocol.clone()))
        .map_err(|_| ConvertError::UnknownProtocol(event.protocol))?;

    let metadata = fold_sample_metadata(event.metadata, event.sample);

    let input = EventInput::from_signal(
        event.source_ip,
        event.wan_ip,
        event.sensor,
        signal_type,
        protocol,
        event.authenticated,
        event.observed_at,
        metadata,
        event.session_id,
    );

    input.validate().map_err(ConvertError::Validation)?;
    Ok(input)
}

/// Folds a captured-sample reference into an event's metadata object under `sample_sha256`,
/// `sample_size`, and `sample_orig_name`, preserving whatever fields the sensor already put
/// there. No sample, or a `metadata` that is not a JSON object, passes through unchanged.
pub fn fold_sample_metadata(mut metadata: Value, sample: Option<SampleRef>) -> Value {
    if let Some(sample) = sample
        && let Value::Object(map) = &mut metadata
    {
        map.insert("sample_sha256".into(), sample.sha256.into());
        map.insert("sample_size".into(), sample.size.into());
        map.insert("sample_orig_name".into(), sample.orig_name.into());
    }
    metadata
}
