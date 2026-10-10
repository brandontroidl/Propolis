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
/// How one interaction ended. TELEMETRY: it is recorded in the ledger but never scored, and
/// intake routes it to the unscored append path - see `core_scoring::SignalType::is_telemetry`.
pub const SIGNAL_HONEYPOT_SESSION_END: &str = "honeypot_session_end";

/// A sensor's own health counters. NOT attacker evidence and NOT a `core-scoring` signal type:
/// intake recognises it by this string before conversion and stores it in `sensor_stats`, never in
/// the ledger (see [`SensorStats`]).
pub const SIGNAL_SENSOR_STATS: &str = "sensor_stats";

/// The `source_ip` every `sensor_stats` event carries: the unspecified address, a sentinel that
/// names no host. Intake refuses a `sensor_stats` line with any other source, so the signal can
/// never be mistaken for, or smuggle in, an attacker address.
pub const SENSOR_STATS_SOURCE_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

/// The largest value any counter field may carry. 2^53 is the last integer a Prometheus float
/// holds exactly, and well inside the database's `bigint`.
pub const SENSOR_STATS_MAX_VALUE: u64 = 1 << 53;

/// The longest sensor name accepted in a `sensor_stats` event.
pub const SENSOR_STATS_MAX_NAME_LEN: usize = 64;

/// The metadata of a `sensor_stats` event: a fixed set of fields, no others (`deny_unknown_fields`),
/// every one required. One definition for the producer (`sensor-framework`) and the consumer
/// (`intake`), so the two cannot drift.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorStats {
    pub sensor: String,
    pub uptime_secs: u64,
    /// True on the one event a sensor writes as it shuts down: the values are final.
    #[serde(rename = "final")]
    pub is_final: bool,
    /// Captures `submit` refused because the queue was full.
    pub dropped: u64,
    /// Captures the spool refused (per-file cap or exhausted budget).
    pub spool_refused: u64,
    /// Captures kept as a prefix because the capture memory budget ran out.
    pub truncated: u64,
    /// Captures refused outright (zero bytes) because the capture memory budget was full.
    pub refused: u64,
    /// Capture bytes buffered in memory now.
    pub budget_current: u64,
    pub budget_high_water: u64,
    /// Reservations the capture memory budget refused.
    pub budget_refused: u64,
}

/// Why a `sensor_stats` line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsRejected {
    NotStats,
    BadSource(IpAddr),
    BadMetadata(String),
    BadName,
    OutOfBounds(&'static str),
}

impl std::fmt::Display for StatsRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStats => write!(f, "not a sensor_stats event"),
            Self::BadSource(ip) => write!(f, "source_ip {ip} is not the sentinel 0.0.0.0"),
            Self::BadMetadata(e) => {
                write!(f, "metadata is not the fixed sensor_stats field set: {e}")
            }
            Self::BadName => write!(
                f,
                "sensor name is empty, too long, not printable ASCII or differs from the event's"
            ),
            Self::OutOfBounds(field) => write!(f, "{field} is out of bounds"),
        }
    }
}

impl SensorStats {
    /// Builds the wire event for these stats.
    pub fn to_event(&self, observed_at: DateTime<Utc>) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: SENSOR_STATS_SOURCE_IP,
            wan_ip: None,
            sensor: self.sensor.clone(),
            signal_type: SIGNAL_SENSOR_STATS.to_string(),
            protocol: PROTO_TCP.to_string(),
            authenticated: false,
            observed_at,
            metadata: serde_json::to_value(self).unwrap_or(serde_json::Value::Null),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        }
    }

    /// Validates a `sensor_stats` event and returns its stats. Refuses: any other signal type, a
    /// source other than [`SENSOR_STATS_SOURCE_IP`], a `sample`, metadata that is not exactly the
    /// fixed field set, a name that is empty, over [`SENSOR_STATS_MAX_NAME_LEN`] or not printable
    /// ASCII, a name that differs from the event's own `sensor`, and any value over
    /// [`SENSOR_STATS_MAX_VALUE`]. Whether the name is the right sensor for the log it arrived in
    /// is the caller's check; this cannot know the log.
    pub fn from_event(event: &SensorEvent) -> Result<Self, StatsRejected> {
        if event.signal_type != SIGNAL_SENSOR_STATS {
            return Err(StatsRejected::NotStats);
        }
        if event.source_ip != SENSOR_STATS_SOURCE_IP {
            return Err(StatsRejected::BadSource(event.source_ip));
        }
        if event.sample.is_some() {
            return Err(StatsRejected::BadMetadata("carries a sample".into()));
        }
        let stats: SensorStats = serde_json::from_value(event.metadata.clone())
            .map_err(|e| StatsRejected::BadMetadata(e.to_string()))?;
        let name_ok = !stats.sensor.is_empty()
            && stats.sensor.len() <= SENSOR_STATS_MAX_NAME_LEN
            && stats.sensor.bytes().all(|b| b.is_ascii_graphic());
        if !name_ok || stats.sensor != event.sensor {
            return Err(StatsRejected::BadName);
        }
        let values = [
            ("uptime_secs", stats.uptime_secs),
            ("dropped", stats.dropped),
            ("spool_refused", stats.spool_refused),
            ("truncated", stats.truncated),
            ("refused", stats.refused),
            ("budget_current", stats.budget_current),
            ("budget_high_water", stats.budget_high_water),
            ("budget_refused", stats.budget_refused),
        ];
        for (field, value) in values {
            if value > SENSOR_STATS_MAX_VALUE {
                return Err(StatsRejected::OutOfBounds(field));
            }
        }
        Ok(stats)
    }
}

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
    /// What a fake shell answered to a command, on the `honeypot_command_exec` event of that
    /// command. Optional + skipped like `sample`, so every other event and every older record is
    /// unchanged on the wire. Intake folds the digest and length into the event's metadata (so the
    /// hash chain covers them) and keeps the text in `shell_output`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<ReplyRef>,
}

/// The most bytes of a shell reply a sensor keeps in [`ReplyRef::text`].
pub const REPLY_TEXT_CAP: usize = 4096;

/// A shell's answer to one command, as the sensor recorded it. `text` is what a bot would have
/// read, lossily decoded and sanitized line by line (control and format characters removed, line
/// breaks kept), and cut to [`REPLY_TEXT_CAP`] bytes; `len` is the full length printed. `sha256` is the digest of
/// `text` as stored (lowercase hex), which intake recomputes and refuses a line that disagrees
/// with. `text` is attacker-influenced (it can echo the command): render as escaped text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplyRef {
    pub sha256: String,
    pub len: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    pub text: String,
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
            reply: None,
        }
    }

    fn stats() -> SensorStats {
        SensorStats {
            sensor: "ssh".into(),
            uptime_secs: 61,
            is_final: false,
            dropped: 1,
            spool_refused: 2,
            truncated: 3,
            refused: 4,
            budget_current: 5,
            budget_high_water: 6,
            budget_refused: 7,
        }
    }

    fn stats_event() -> SensorEvent {
        stats().to_event("2026-10-09T00:00:00Z".parse().unwrap())
    }

    #[test]
    fn a_stats_event_round_trips_through_the_wire_and_validation() {
        let event = stats_event();
        assert_eq!(event.source_ip.to_string(), "0.0.0.0");
        let json = serde_json::to_string(&event).unwrap();
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(SensorStats::from_event(&back), Ok(stats()));
        assert_eq!(back.metadata["final"], false);
    }

    #[test]
    fn a_stats_event_from_any_other_source_is_refused() {
        for ip in ["203.0.113.7", "127.0.0.1", "::", "2001:db8::1"] {
            let event = SensorEvent {
                source_ip: ip.parse().unwrap(),
                ..stats_event()
            };
            assert!(
                matches!(
                    SensorStats::from_event(&event),
                    Err(StatsRejected::BadSource(_))
                ),
                "{ip}"
            );
        }
    }

    #[test]
    fn stats_metadata_must_be_exactly_the_fixed_field_set() {
        let mut extra = stats_event();
        extra.metadata["command"] = "rm -rf".into();
        assert!(matches!(
            SensorStats::from_event(&extra),
            Err(StatsRejected::BadMetadata(_))
        ));
        let mut missing = stats_event();
        missing.metadata.as_object_mut().unwrap().remove("dropped");
        assert!(matches!(
            SensorStats::from_event(&missing),
            Err(StatsRejected::BadMetadata(_))
        ));
        let mut negative = stats_event();
        negative.metadata["dropped"] = (-1).into();
        assert!(SensorStats::from_event(&negative).is_err());
        let with_sample = SensorEvent {
            sample: Some(SampleRef {
                sha256: "a".repeat(64),
                size: 1,
                orig_name: "x".into(),
                capture_id: None,
            }),
            ..stats_event()
        };
        assert!(SensorStats::from_event(&with_sample).is_err());
    }

    #[test]
    fn stats_names_and_values_are_bounded() {
        let long = "x".repeat(SENSOR_STATS_MAX_NAME_LEN + 1);
        for name in ["", long.as_str(), "ssh\n", "ssh node"] {
            let s = SensorStats {
                sensor: name.into(),
                ..stats()
            };
            let event = s.to_event("2026-10-09T00:00:00Z".parse().unwrap());
            assert_eq!(SensorStats::from_event(&event), Err(StatsRejected::BadName));
        }
        let mismatch = SensorEvent {
            sensor: "telnet".into(),
            ..stats_event()
        };
        assert_eq!(
            SensorStats::from_event(&mismatch),
            Err(StatsRejected::BadName)
        );
        let at_cap = SensorStats {
            dropped: SENSOR_STATS_MAX_VALUE,
            ..stats()
        };
        assert!(
            SensorStats::from_event(&at_cap.to_event("2026-10-09T00:00:00Z".parse().unwrap()))
                .is_ok()
        );
        let over = SensorStats {
            budget_high_water: SENSOR_STATS_MAX_VALUE + 1,
            ..stats()
        };
        assert_eq!(
            SensorStats::from_event(&over.to_event("2026-10-09T00:00:00Z".parse().unwrap())),
            Err(StatsRejected::OutOfBounds("budget_high_water"))
        );
    }

    #[test]
    fn another_signal_type_is_not_stats() {
        assert_eq!(
            SensorStats::from_event(&sample_event()),
            Err(StatsRejected::NotStats)
        );
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
            reply: None,
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
    fn reply_round_trips_and_is_omitted_when_absent() {
        let mut e = sample_event();
        let none = serde_json::to_string(&e).unwrap();
        assert!(!none.contains("reply"), "no reply, no key on the wire");
        let back: SensorEvent = serde_json::from_str(&none).unwrap();
        assert_eq!(back.reply, None, "a record without the key still parses");

        e.reply = Some(ReplyRef {
            sha256: "ab".repeat(32),
            len: 12,
            truncated: false,
            text: "Linux box".into(),
        });
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            !s.contains("truncated"),
            "an untruncated reply omits the flag"
        );
        let back: SensorEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.reply, e.reply);

        e.reply.as_mut().unwrap().truncated = true;
        let s = serde_json::to_string(&e).unwrap();
        let back: SensorEvent = serde_json::from_str(&s).unwrap();
        assert!(back.reply.unwrap().truncated);
    }

    #[test]
    fn event_occurrence_id_round_trips_when_present() {
        let id = uuid::Uuid::now_v7();
        let mut e = sample_event();
        e.occurrence_id = Some(id);
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            s.contains("occurrence_id"),
            "occurrence_id must serialize when present"
        );
        let back: SensorEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.occurrence_id, Some(id));
    }

    #[test]
    fn event_without_occurrence_id_omits_the_key() {
        let e = sample_event();
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            !s.contains("occurrence_id"),
            "a None occurrence_id must not appear on the wire"
        );
    }
}
