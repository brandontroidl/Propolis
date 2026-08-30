//! The sensor-to-intake wire format: frozen NDJSON event record and sample side-channel
//! reference. One definition, imported by every sensor (producer) and by intake (SP3,
//! consumer), so the wire shape has a single source of truth and cannot drift into two
//! clones. See `internal/design/02-sensor-framework.md` for the frozen contract and
//! ADR-0010 for the integrity model this format participates in.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

pub const VERSION_MARKER: &str = "sensor-wire";
pub const WIRE_VERSION: u32 = 1;

// Signal type constants - the snake_case wire values matching core-scoring's SignalType serde.
// Only the subset a sensor built in this sub-project can emit; the remaining SignalType
// variants (Suricata, WAF, port scan, ...) originate from other layers.
pub const SIGNAL_CATCHALL_PROBE: &str = "catchall_probe";
pub const SIGNAL_HONEYPOT_CONNECTION: &str = "honeypot_connection";
pub const SIGNAL_HONEYPOT_LOGIN_ATTEMPT: &str = "honeypot_login_attempt";
pub const SIGNAL_HONEYPOT_COMMAND_EXEC: &str = "honeypot_command_exec";
pub const SIGNAL_HONEYPOT_MALWARE_UPLOAD: &str = "honeypot_malware_upload";
pub const SIGNAL_HONEYPOT_FILE_DOWNLOAD: &str = "honeypot_file_download";

// Protocol constants - lowercase wire values matching core-scoring's Protocol serde.
pub const PROTO_TCP: &str = "tcp";
pub const PROTO_UDP: &str = "udp";
pub const PROTO_ICMP: &str = "icmp";

/// One sensor-observed event, exactly the facts `core-scoring`'s `EventInput::from_signal`
/// needs and nothing derived: a sensor never computes `weight`, `confidence`, or `category`.
///
/// `signal_type` and `protocol` are plain `String`s rather than `core-scoring`'s enums so this
/// crate carries no dependency on `core-scoring` (or its database dependency); intake validates
/// the string against the known set on ingest. Use the `SIGNAL_*` / `PROTO_*` constants above
/// rather than hand-typing the literals.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SensorEvent {
    pub v: u32,
    pub source_ip: IpAddr,
    pub wan_ip: Option<IpAddr>,
    pub sensor: String,
    pub signal_type: String,
    pub protocol: String,
    pub authenticated: bool,
    // RFC 3339 via chrono's default serde (matches core-scoring's hashing.rs, which hashes
    // observed_at as RFC 3339 string bytes). Do NOT switch to chrono::serde::ts_microseconds:
    // that serializes as an integer timestamp, not RFC 3339, and would break the hash chain.
    pub observed_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
    pub sample: Option<SampleRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<uuid::Uuid>,
    /// UUIDv7 minted once per event at emit time (`EventEmitter::append`). Stable across replays so
    /// intake can dedup exactly. Optional + skipped so pre-SP-B-1b records still deserialize and a
    /// None never appears on the wire (no WIRE_VERSION bump), matching `session_id` / `capture_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence_id: Option<uuid::Uuid>,
}

/// Reference to a captured file body written to the quarantine spool, named by its SHA-256.
/// `orig_name` is attacker-controlled and carried as a sanitized indicator only; it is never
/// used as a path component.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SampleRef {
    pub sha256: String,
    pub size: u64,
    pub orig_name: String,
    /// The observation join key (SP-B): a stable, collector-minted id for this capture
    /// occurrence, minted at `QuarantineSpool::store`. `sha256` identifies content; `capture_id`
    /// identifies the observation. Optional + skipped so pre-SP-B records still deserialize and a
    /// None value never appears on the wire (backward/forward compatible, no WIRE_VERSION bump).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<uuid::Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: Some("198.51.100.4".parse().unwrap()),
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: "2026-07-20T14:03:11.482913Z".parse().unwrap(),
            metadata: serde_json::json!({ "protocol_label": "ssh", "command": "uname -a" }),
            sample: None,
            session_id: None,
            occurrence_id: None,
        }
    }

    #[test]
    fn round_trip_serde() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn ndjson_single_line() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains('\n'), "wire record must be a single line");
        assert!(!json.contains('\r'), "wire record must not contain CR");
    }

    #[test]
    fn sample_ref_round_trip() {
        let event = SensorEvent {
            sample: Some(SampleRef {
                sha256: "a".repeat(64),
                size: 12345,
                orig_name: "malware.bin".into(),
                capture_id: None,
            }),
            ..sample_event()
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.sample, back.sample);
    }

    #[test]
    fn null_wan_ip_serializes() {
        let event = SensorEvent {
            wan_ip: None,
            ..sample_event()
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"wan_ip\":null"));
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.wan_ip, None);
    }

    #[test]
    fn version_marker() {
        assert_eq!(VERSION_MARKER, "sensor-wire");
    }

    #[test]
    fn deserialize_without_session_id() {
        let json = r#"{"v":1,"source_ip":"1.2.3.4","sensor":"test","signal_type":"catchall_probe","protocol":"tcp","authenticated":false,"observed_at":"2024-01-01T00:00:00Z","metadata":{}}"#;
        let event: SensorEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, None);
    }

    #[test]
    fn serde_round_trip_with_session_id() {
        let sid = uuid::Uuid::now_v7();
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: "1.2.3.4".parse().unwrap(),
            wan_ip: None,
            sensor: "test".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
            session_id: Some(sid),
            occurrence_id: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, Some(sid));
    }

    #[test]
    fn sampleref_capture_id_round_trips_when_present() {
        let id = uuid::Uuid::now_v7();
        let s = SampleRef {
            sha256: "a".repeat(64),
            size: 10,
            orig_name: "x".into(),
            capture_id: Some(id),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains(&id.to_string()),
            "capture_id must serialize when present"
        );
        let back: SampleRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.capture_id, Some(id));
    }

    #[test]
    fn sampleref_without_capture_id_still_deserializes_as_none() {
        // A pre-SP-B record (no capture_id key) must still parse - backward compat.
        let legacy = r#"{"sha256":"aa","size":3,"orig_name":""}"#;
        let s: SampleRef = serde_json::from_str(legacy).unwrap();
        assert_eq!(s.capture_id, None);
        // And a None capture_id must be omitted from output (skip_serializing_if).
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("capture_id"),
            "None capture_id must be omitted"
        );
    }

    #[test]
    fn event_without_occurrence_id_still_deserializes_as_none() {
        // A pre-SP-B-1b record (no occurrence_id key) must still parse.
        let json = r#"{"v":1,"source_ip":"203.0.113.7","wan_ip":null,"sensor":"ssh","signal_type":"honeypot.command_exec","protocol":"tcp","authenticated":true,"observed_at":"2026-07-20T14:03:11.482913Z","metadata":{},"sample":null,"session_id":null}"#;
        let e: SensorEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.occurrence_id, None);
    }

    #[test]
    fn event_occurrence_id_round_trips_when_present() {
        let id = uuid::Uuid::now_v7();
        let mut e = sample_event();
        e.occurrence_id = Some(id);
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("occurrence_id"), "occurrence_id must serialize when present");
        let back: SensorEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.occurrence_id, Some(id));
    }

    #[test]
    fn event_without_occurrence_id_omits_the_key() {
        let e = sample_event();
        let s = serde_json::to_string(&e).unwrap();
        assert!(!s.contains("occurrence_id"), "a None occurrence_id must not appear on the wire");
    }
}
