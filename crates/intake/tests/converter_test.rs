use intake::converter::{ConvertError, convert};
use sensor_wire::*;

fn sample_wire_event() -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: "2026-07-20T14:03:11.482913Z".parse().unwrap(),
        metadata: serde_json::json!({"protocol_label": "ssh", "command": "uname -a"}),
        sample: None,
        session_id: None,
    }
}

#[test]
fn converts_known_signal_type() {
    let input = convert(sample_wire_event()).unwrap();
    assert_eq!(
        input.signal_type,
        core_scoring::SignalType::HoneypotCommandExec
    );
    assert_eq!(input.protocol, core_scoring::Protocol::Tcp);
    assert!(input.authenticated);
    assert_eq!(input.weight, 60); // from signal weight table
    assert_eq!(input.category, core_scoring::Category::Honeypot);
}

#[test]
fn rejects_unknown_signal_type() {
    let mut event = sample_wire_event();
    event.signal_type = "nonexistent_signal".into();
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::UnknownSignalType(_))));
}

#[test]
fn rejects_unknown_protocol() {
    let mut event = sample_wire_event();
    event.protocol = "quic".into();
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::UnknownProtocol(_))));
}

#[test]
fn rejects_empty_sensor() {
    let mut event = sample_wire_event();
    event.sensor = String::new();
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::Validation(_))));
}

#[test]
fn folds_sample_into_metadata() {
    let mut event = sample_wire_event();
    event.sample = Some(SampleRef {
        sha256: "a".repeat(64),
        size: 12345,
        orig_name: "evil.bin".into(),
        capture_id: None,
    });
    let input = convert(event).unwrap();
    assert_eq!(input.metadata["sample_sha256"], "a".repeat(64));
    assert_eq!(input.metadata["sample_size"], 12345);
    assert_eq!(input.metadata["sample_orig_name"], "evil.bin");
}

#[test]
fn preserves_existing_metadata_when_folding_sample() {
    let mut event = sample_wire_event();
    event.sample = Some(SampleRef {
        sha256: "b".repeat(64),
        size: 100,
        orig_name: "test.bin".into(),
        capture_id: None,
    });
    let input = convert(event).unwrap();
    // Original metadata fields preserved.
    assert_eq!(input.metadata["protocol_label"], "ssh");
    assert_eq!(input.metadata["command"], "uname -a");
    // Sample fields added.
    assert_eq!(input.metadata["sample_sha256"], "b".repeat(64));
}

#[test]
fn passes_session_id_through() {
    let sid = uuid::Uuid::now_v7();
    let mut event = sample_wire_event();
    event.session_id = Some(sid);
    let input = convert(event).unwrap();
    assert_eq!(input.session_id, Some(sid));
}

#[test]
fn none_session_id_passes_through_as_none() {
    let input = convert(sample_wire_event()).unwrap();
    assert_eq!(input.session_id, None);
}

#[test]
fn rejects_schema_version_mismatch() {
    let mut event = sample_wire_event();
    event.v = 99;
    let result = convert(event);
    assert!(matches!(result, Err(ConvertError::UnsupportedVersion(99))));
}

#[test]
fn all_sensor_wire_constants_convert_successfully() {
    // Every SIGNAL_* constant in sensor-wire must produce a valid EventInput.
    let signals = [
        (SIGNAL_CATCHALL_PROBE, PROTO_UDP, false),
        (SIGNAL_HONEYPOT_CONNECTION, PROTO_TCP, false),
        (SIGNAL_HONEYPOT_LOGIN_ATTEMPT, PROTO_TCP, true),
        (SIGNAL_HONEYPOT_COMMAND_EXEC, PROTO_TCP, true),
        (SIGNAL_HONEYPOT_MALWARE_UPLOAD, PROTO_TCP, true),
        (SIGNAL_HONEYPOT_FILE_DOWNLOAD, PROTO_TCP, true),
    ];
    for (signal, proto, auth) in signals {
        let mut event = sample_wire_event();
        event.signal_type = signal.into();
        event.protocol = proto.into();
        event.authenticated = auth;
        let result = convert(event);
        assert!(result.is_ok(), "failed to convert signal: {signal}");
    }
}
