//! The origin policy: what a line in a sensor's log may claim about itself.
//!
//! Every shipped sensor runs as its own user and writes its own log, so the operating system
//! already proves which sensor wrote a file. The `sensor`, `signal_type`, `protocol` and
//! `authenticated` fields of a line prove nothing: they are whatever the writing process put
//! there. Without a check, a compromised low-interaction sensor could write lines that carry
//! another sensor's name, a signal it has no way to observe, an authentication it cannot perform,
//! or a summary that stands for a million events.
//!
//! This module is the one statement of what each sensor is able to write ([`SENSORS`]) and of
//! which log belongs to which sensor ([`bound_sensor`]). Two readers apply it, each at the last
//! point where a log is still one sensor's: intake, which tails the per-sensor logs on a
//! single node, and the shipper, which tails them on a collector before merging them into one
//! stream.
//!
//! The table must be complete, because a row that is too narrow drops real evidence. The sensors
//! prove it themselves: `sensor-framework`'s `EventEmitter::append`, the one path every sensor
//! writes through, asserts in debug builds that the event conforms to its own sensor's row
//! ([`conforms`]), so every sensor's test suite runs against the table.
//!
//! `sensor_stats` lines are a sensor's own health counters, not evidence, and are not part of
//! the table: intake validates them and compares them with the log's label on their own path
//! (see [`crate::SensorStats::from_event`]).

use crate::{
    PROTO_TCP, PROTO_UDP, SIGNAL_CATCHALL_PROBE, SIGNAL_HONEYPOT_COMMAND_EXEC,
    SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SIGNAL_HONEYPOT_SESSION_END, SensorEvent,
};

/// The metadata key that marks a connection or login summary (`event_summary: true`). Scoring
/// counts such a line as the `suppressed_count` events it stands for, which is why only a sensor
/// that folds events into summaries may write one ([`SensorRow::summarizes`]).
pub const EVENT_SUMMARY_KEY: &str = "event_summary";

/// What one sensor is able to write, keyed by the `sensor` name its events carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorRow {
    pub sensor: &'static str,
    /// Every `signal_type` the sensor emits.
    pub signals: &'static [&'static str],
    /// Every `protocol` its events carry.
    pub protocols: &'static [&'static str],
    /// Whether any of its events may carry `authenticated: true`.
    pub authenticates: bool,
    /// Whether it may write an event summary ([`EVENT_SUMMARY_KEY`]).
    pub summarizes: bool,
}

/// The signals of a sensor-cred protocol that only records the connection and the login.
const CRED_SIGNALS: &[&str] = &[SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT];

/// One row per sensor name the shipped sensors write. `sensor-cred` is one binary serving five
/// protocols, each writing its own log under its own name, so it has five rows; they are the only
/// sensors behind a per-source event budget (`sensor_framework::source_flood`) and so the only
/// ones that summarize.
///
/// A row lists what the sensor's code can emit, not what is typical: the shell-backed sensors
/// (ssh, telnet, adb) emit `honeypot_command_exec`, `honeypot_file_download` and, for a captured
/// payload, `honeypot_malware_upload` through the shared shell. When a sensor gains an event,
/// its row changes in the same commit; the emitter's assertion fails that sensor's tests until
/// it does.
pub const SENSORS: &[SensorRow] = &[
    SensorRow {
        sensor: "ssh",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            SIGNAL_HONEYPOT_FILE_DOWNLOAD,
            SIGNAL_HONEYPOT_MALWARE_UPLOAD,
            SIGNAL_HONEYPOT_SESSION_END,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: false,
    },
    // The telnet listener also answers non-telnet probes on its port, as a catchall would.
    SensorRow {
        sensor: "telnet",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            SIGNAL_HONEYPOT_FILE_DOWNLOAD,
            SIGNAL_HONEYPOT_MALWARE_UPLOAD,
            SIGNAL_CATCHALL_PROBE,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: false,
    },
    // adb has no login: its shell runs unauthenticated, so nothing it writes is authenticated.
    SensorRow {
        sensor: "adb",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            SIGNAL_HONEYPOT_FILE_DOWNLOAD,
            SIGNAL_HONEYPOT_MALWARE_UPLOAD,
        ],
        protocols: &[PROTO_TCP],
        authenticates: false,
        summarizes: false,
    },
    SensorRow {
        sensor: "redis",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: false,
    },
    SensorRow {
        sensor: "http",
        signals: &[SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_COMMAND_EXEC],
        protocols: &[PROTO_TCP],
        authenticates: false,
        summarizes: false,
    },
    SensorRow {
        sensor: "ftp",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            SIGNAL_HONEYPOT_MALWARE_UPLOAD,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: false,
    },
    SensorRow {
        sensor: "smtp",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: false,
    },
    SensorRow {
        sensor: "tftp",
        signals: &[SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_MALWARE_UPLOAD],
        protocols: &[PROTO_UDP],
        authenticates: false,
        summarizes: false,
    },
    SensorRow {
        sensor: "mqtt",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            SIGNAL_HONEYPOT_MALWARE_UPLOAD,
            SIGNAL_HONEYPOT_SESSION_END,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: false,
    },
    // A UDP query is a connection; a query over TCP or TLS is a command.
    SensorRow {
        sensor: "dns",
        signals: &[SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_COMMAND_EXEC],
        protocols: &[PROTO_UDP, PROTO_TCP],
        authenticates: false,
        summarizes: false,
    },
    SensorRow {
        sensor: "catchall",
        signals: &[SIGNAL_CATCHALL_PROBE],
        protocols: &[PROTO_TCP, PROTO_UDP],
        authenticates: false,
        summarizes: false,
    },
    SensorRow {
        sensor: "vnc",
        signals: CRED_SIGNALS,
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: true,
    },
    SensorRow {
        sensor: "mysql",
        signals: CRED_SIGNALS,
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: true,
    },
    SensorRow {
        sensor: "mssql",
        signals: CRED_SIGNALS,
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: true,
    },
    // The postgresql listener goes on to record the queries a client sends after its login.
    SensorRow {
        sensor: "postgresql",
        signals: &[
            SIGNAL_HONEYPOT_CONNECTION,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
        ],
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: true,
    },
    SensorRow {
        sensor: "mongodb",
        signals: CRED_SIGNALS,
        protocols: &[PROTO_TCP],
        authenticates: true,
        summarizes: true,
    },
];

/// The labels the shipped configuration gives the five sensor-cred logs
/// (`PROPOLIS_SENSOR_LOGS` in `deploy/propolis.env.example`), each with the sensor name the lines
/// of that log carry. Every other shipped log is labelled with its sensor's own name.
const CRED_LABELS: &[(&str, &str)] = &[
    ("cred-vnc", "vnc"),
    ("cred-mysql", "mysql"),
    ("cred-mssql", "mssql"),
    ("cred-pg", "postgresql"),
    ("cred-mongo", "mongodb"),
];

/// The row of the sensor named `sensor`, or `None` when no shipped sensor writes that name.
pub fn row(sensor: &str) -> Option<&'static SensorRow> {
    SENSORS.iter().find(|row| row.sensor == sensor)
}

/// The sensor a log label is bound to: the sensor of that name, or the sensor-cred protocol a
/// shipped `cred-*` label stands for. `None` for any other label (a collector id on a control
/// plane, a label an operator made up): such a log is not one sensor's, so it may carry any known
/// sensor's lines, each still held to its own row.
///
/// The match is exact. A log an operator labels differently from the shipped configuration is
/// unbound, and its lines are then checked against their own claimed sensor only.
pub fn bound_sensor(label: &str) -> Option<&'static str> {
    row(label).map(|row| row.sensor).or_else(|| {
        CRED_LABELS
            .iter()
            .find(|(cred_label, _)| *cred_label == label)
            .map(|(_, sensor)| *sensor)
    })
}

/// Whether the line is marked as an event summary. The same test scoring applies before it
/// credits a line with its `suppressed_count` (`core_scoring`'s `represented_events`): the key
/// set to the boolean `true`, nothing looser.
pub fn is_event_summary(event: &SensorEvent) -> bool {
    event.metadata.get(EVENT_SUMMARY_KEY) == Some(&serde_json::Value::Bool(true))
}

/// The most characters of a claimed value an error keeps. The value is the writer's own and a
/// line may be a megabyte long; the error goes to a log.
const MAX_CLAIM_CHARS: usize = 64;

fn claim(value: &str) -> String {
    value.chars().take(MAX_CLAIM_CHARS).collect()
}

/// The rule a line broke, with the sensor it claims to be from and the field at fault. Claimed
/// values are cut to 64 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The line names a sensor that is not in the table.
    UnknownSensor { sensor: String },
    /// The log is bound to `bound` and the line names another sensor.
    OtherSensor { sensor: String, bound: &'static str },
    /// The sensor does not emit this signal type.
    SignalType { sensor: String, signal_type: String },
    /// The sensor does not use this protocol.
    Protocol { sensor: String, protocol: String },
    /// The line is authenticated and the sensor never authenticates.
    Authenticated { sensor: String },
    /// The line is an event summary and the sensor does not summarize.
    EventSummary { sensor: String },
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSensor { sensor } => {
                write!(
                    f,
                    "the line names sensor {sensor:?}, which is not a known sensor"
                )
            }
            Self::OtherSensor { sensor, bound } => write!(
                f,
                "the line names sensor {sensor:?}, but this log belongs to sensor {bound:?}"
            ),
            Self::SignalType {
                sensor,
                signal_type,
            } => write!(
                f,
                "sensor {sensor:?} does not emit signal_type {signal_type:?}"
            ),
            Self::Protocol { sensor, protocol } => {
                write!(f, "sensor {sensor:?} does not use protocol {protocol:?}")
            }
            Self::Authenticated { sensor } => write!(
                f,
                "sensor {sensor:?} never authenticates, but the line has authenticated = true"
            ),
            Self::EventSummary { sensor } => write!(
                f,
                "sensor {sensor:?} does not write event summaries, but the line has \
                 {EVENT_SUMMARY_KEY} = true"
            ),
        }
    }
}

/// A line refused by [`check`]: the label of the log it was read from and the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginError {
    pub label: String,
    pub violation: Violation,
}

impl std::fmt::Display for OriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "log {:?}: {}", self.label, self.violation)
    }
}

impl std::error::Error for OriginError {}

/// Whether `event` is something the sensor it names is able to write: the sensor is in the
/// table, the signal type and protocol are in its row, it is authenticated only if that sensor
/// authenticates, and it is an event summary only if that sensor summarizes. This is the part of
/// the policy that needs no log: the emitter asserts it of every event a sensor writes.
pub fn conforms(event: &SensorEvent) -> Result<(), Violation> {
    let Some(row) = row(&event.sensor) else {
        return Err(Violation::UnknownSensor {
            sensor: claim(&event.sensor),
        });
    };
    within(row, event)
}

fn within(row: &SensorRow, event: &SensorEvent) -> Result<(), Violation> {
    let sensor = || row.sensor.to_string();
    if !row.signals.contains(&event.signal_type.as_str()) {
        return Err(Violation::SignalType {
            sensor: sensor(),
            signal_type: claim(&event.signal_type),
        });
    }
    if !row.protocols.contains(&event.protocol.as_str()) {
        return Err(Violation::Protocol {
            sensor: sensor(),
            protocol: claim(&event.protocol),
        });
    }
    if event.authenticated && !row.authenticates {
        return Err(Violation::Authenticated { sensor: sensor() });
    }
    if is_event_summary(event) && !row.summarizes {
        return Err(Violation::EventSummary { sensor: sensor() });
    }
    Ok(())
}

/// Whether a line read from the log labelled `label` may be believed about its origin.
///
/// 1. The line's sensor must be in the table, on every log: a name no shipped sensor writes
///    has no row to hold the line to.
/// 2. If the label is bound ([`bound_sensor`]), the line's sensor must be the bound one: a log
///    speaks for its own sensor only.
/// 3. The line's signal type, protocol and authentication must be within that sensor's row.
/// 4. A line marked as an event summary must come from a sensor that summarizes.
///
/// What this cannot refuse is a sensor forging events of its own kind under its own name.
pub fn check(label: &str, event: &SensorEvent) -> Result<(), OriginError> {
    let refused = |violation| OriginError {
        label: claim(label),
        violation,
    };
    let Some(row) = row(&event.sensor) else {
        return Err(refused(Violation::UnknownSensor {
            sensor: claim(&event.sensor),
        }));
    };
    if let Some(bound) = bound_sensor(label)
        && bound != row.sensor
    {
        return Err(refused(Violation::OtherSensor {
            sensor: row.sensor.to_string(),
            bound,
        }));
    }
    within(row, event).map_err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PROTO_ICMP, SIGNAL_SENSOR_STATS, WIRE_VERSION};

    /// Every signal type a sensor can put on the wire as evidence.
    const ALL_SIGNALS: &[&str] = &[
        SIGNAL_CATCHALL_PROBE,
        SIGNAL_HONEYPOT_CONNECTION,
        SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
        SIGNAL_HONEYPOT_COMMAND_EXEC,
        SIGNAL_HONEYPOT_MALWARE_UPLOAD,
        SIGNAL_HONEYPOT_FILE_DOWNLOAD,
        SIGNAL_HONEYPOT_SESSION_END,
    ];

    /// The table as the sensors' source gives it, written out a second time and by hand:
    /// (sensor, signals without the `honeypot_` prefix, protocols, authenticates, summarizes).
    /// The tests below hold [`SENSORS`] to it in both directions, so a row can be neither
    /// narrowed (real evidence dropped) nor widened (a forgery admitted) by an edit to one place.
    const EXPECTED: &[(&str, &str, &str, bool, bool)] = &[
        (
            "ssh",
            "connection login_attempt command_exec file_download malware_upload session_end",
            "tcp",
            true,
            false,
        ),
        (
            "telnet",
            "connection login_attempt command_exec file_download malware_upload catchall_probe",
            "tcp",
            true,
            false,
        ),
        (
            "adb",
            "connection command_exec file_download malware_upload",
            "tcp",
            false,
            false,
        ),
        (
            "redis",
            "connection login_attempt command_exec",
            "tcp",
            true,
            false,
        ),
        ("http", "connection command_exec", "tcp", false, false),
        (
            "ftp",
            "connection login_attempt command_exec malware_upload",
            "tcp",
            true,
            false,
        ),
        (
            "smtp",
            "connection login_attempt command_exec",
            "tcp",
            true,
            false,
        ),
        ("tftp", "connection malware_upload", "udp", false, false),
        (
            "mqtt",
            "connection login_attempt command_exec malware_upload session_end",
            "tcp",
            true,
            false,
        ),
        ("dns", "connection command_exec", "udp tcp", false, false),
        ("catchall", "catchall_probe", "tcp udp", false, false),
        ("vnc", "connection login_attempt", "tcp", true, true),
        ("mysql", "connection login_attempt", "tcp", true, true),
        ("mssql", "connection login_attempt", "tcp", true, true),
        (
            "postgresql",
            "connection login_attempt command_exec",
            "tcp",
            true,
            true,
        ),
        ("mongodb", "connection login_attempt", "tcp", true, true),
    ];

    fn wire_signal(short: &str) -> String {
        if short == SIGNAL_CATCHALL_PROBE {
            short.to_string()
        } else {
            format!("honeypot_{short}")
        }
    }

    fn expected_signals(sensor: &str) -> Vec<String> {
        let (_, signals, ..) = EXPECTED.iter().find(|row| row.0 == sensor).unwrap();
        signals.split(' ').map(wire_signal).collect()
    }

    fn expected_protocols(sensor: &str) -> Vec<&'static str> {
        let (_, _, protocols, ..) = EXPECTED.iter().find(|row| row.0 == sensor).unwrap();
        protocols.split(' ').collect()
    }

    fn event(sensor: &str, signal_type: &str, protocol: &str) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            sensor: sensor.into(),
            signal_type: signal_type.into(),
            protocol: protocol.into(),
            authenticated: false,
            observed_at: "2026-11-13T00:00:00Z".parse().unwrap(),
            metadata: serde_json::json!({ "protocol_label": sensor }),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        }
    }

    /// An event the named sensor does write: its first signal over its first protocol.
    fn honest(sensor: &str) -> SensorEvent {
        let row = row(sensor).unwrap();
        event(sensor, row.signals[0], row.protocols[0])
    }

    fn summary(sensor: &str) -> SensorEvent {
        let mut event = event(sensor, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, PROTO_TCP);
        event.authenticated = row(sensor).is_some_and(|row| row.authenticates);
        event.metadata[EVENT_SUMMARY_KEY] = true.into();
        event.metadata["suppressed_count"] = 1_000_000.into();
        event
    }

    #[test]
    fn the_table_has_one_row_for_each_sensor_name_the_shipped_sensors_write() {
        let mut names: Vec<&str> = SENSORS.iter().map(|row| row.sensor).collect();
        let mut expected: Vec<&str> = EXPECTED.iter().map(|row| row.0).collect();
        names.sort_unstable();
        expected.sort_unstable();
        assert_eq!(names, expected);
        names.dedup();
        assert_eq!(names.len(), SENSORS.len(), "a sensor has two rows");
    }

    #[test]
    fn each_sensor_passes_exactly_the_signals_it_emits() {
        for row in SENSORS {
            let allowed = expected_signals(row.sensor);
            for signal in ALL_SIGNALS {
                let line = event(row.sensor, signal, row.protocols[0]);
                if allowed.iter().any(|s| s == signal) {
                    assert_eq!(conforms(&line), Ok(()), "{} {signal}", row.sensor);
                    assert_eq!(check(row.sensor, &line), Ok(()), "{} {signal}", row.sensor);
                } else {
                    let refused = Violation::SignalType {
                        sensor: row.sensor.into(),
                        signal_type: (*signal).into(),
                    };
                    assert_eq!(conforms(&line), Err(refused.clone()), "{}", row.sensor);
                    assert_eq!(
                        check(row.sensor, &line).unwrap_err().violation,
                        refused,
                        "{} {signal}",
                        row.sensor
                    );
                }
            }
        }
    }

    #[test]
    fn a_signal_no_sensor_emits_is_refused_from_every_sensor() {
        // The scoring vocabulary is wider than what a sensor can observe (Suricata, WAF and
        // port-scan signals come from other layers), and a stats line is not evidence.
        for row in SENSORS {
            for signal in [
                "suricata_sev1",
                "waf_sqli_xss",
                "port_scan",
                "ssh_brute_force",
                "remote_auth_failure",
                SIGNAL_SENSOR_STATS,
                "",
            ] {
                let line = event(row.sensor, signal, row.protocols[0]);
                assert!(
                    matches!(conforms(&line), Err(Violation::SignalType { .. })),
                    "{} {signal}",
                    row.sensor
                );
            }
        }
    }

    #[test]
    fn each_sensor_passes_exactly_the_protocols_it_uses() {
        for row in SENSORS {
            let allowed = expected_protocols(row.sensor);
            for protocol in [PROTO_TCP, PROTO_UDP, PROTO_ICMP, "sctp"] {
                let line = event(row.sensor, row.signals[0], protocol);
                if allowed.contains(&protocol) {
                    assert_eq!(conforms(&line), Ok(()), "{} {protocol}", row.sensor);
                } else {
                    assert_eq!(
                        conforms(&line),
                        Err(Violation::Protocol {
                            sensor: row.sensor.into(),
                            protocol: protocol.into(),
                        }),
                        "{} {protocol}",
                        row.sensor
                    );
                }
            }
        }
    }

    #[test]
    fn authenticated_is_refused_from_a_sensor_that_never_authenticates() {
        for (sensor, _, _, authenticates, _) in EXPECTED {
            let mut line = honest(sensor);
            line.authenticated = true;
            if *authenticates {
                assert_eq!(check(sensor, &line), Ok(()), "{sensor}");
            } else {
                let refused = Violation::Authenticated {
                    sensor: (*sensor).into(),
                };
                assert_eq!(conforms(&line), Err(refused.clone()), "{sensor}");
                assert_eq!(check(sensor, &line).unwrap_err().violation, refused);
            }
        }
        let never: Vec<&str> = EXPECTED.iter().filter(|r| !r.3).map(|r| r.0).collect();
        assert_eq!(never, ["adb", "http", "tftp", "dns", "catchall"]);
    }

    #[test]
    fn a_summary_is_refused_from_a_sensor_that_does_not_summarize() {
        for (sensor, signals, _, _, summarizes) in EXPECTED {
            // Only a sensor that emits logins can even shape a login summary; the others are
            // refused for the signal first, which is the same line refused.
            if !signals.contains("login_attempt") {
                assert!(conforms(&summary(sensor)).is_err(), "{sensor}");
                continue;
            }
            if *summarizes {
                assert_eq!(check(sensor, &summary(sensor)), Ok(()), "{sensor}");
            } else {
                let refused = Violation::EventSummary {
                    sensor: (*sensor).into(),
                };
                assert_eq!(conforms(&summary(sensor)), Err(refused.clone()), "{sensor}");
                assert_eq!(
                    check(sensor, &summary(sensor)).unwrap_err().violation,
                    refused
                );
            }
        }
    }

    #[test]
    fn a_sensor_cred_summary_passes_under_its_shipped_label_and_as_either_signal() {
        for (label, sensor) in CRED_LABELS {
            assert_eq!(check(label, &summary(sensor)), Ok(()), "{label}");
            let mut connections = summary(sensor);
            connections.signal_type = SIGNAL_HONEYPOT_CONNECTION.into();
            connections.authenticated = false;
            connections.metadata["overflow_summary"] = true.into();
            assert_eq!(check(label, &connections), Ok(()), "{label}");
        }
    }

    #[test]
    fn only_the_boolean_true_marks_a_summary() {
        // A line scoring would count once is not a summary, whatever else the key holds.
        for value in [
            serde_json::json!(false),
            serde_json::json!("true"),
            serde_json::json!(1),
            serde_json::Value::Null,
        ] {
            let mut line = event("ssh", SIGNAL_HONEYPOT_LOGIN_ATTEMPT, PROTO_TCP);
            line.metadata[EVENT_SUMMARY_KEY] = value.clone();
            assert!(!is_event_summary(&line), "{value}");
            assert_eq!(conforms(&line), Ok(()), "{value}");
        }
        let mut line = event("ssh", SIGNAL_HONEYPOT_LOGIN_ATTEMPT, PROTO_TCP);
        line.metadata = serde_json::json!([{ "event_summary": true }]);
        assert!(!is_event_summary(&line), "metadata that is not an object");
    }

    #[test]
    fn a_bound_label_refuses_every_other_known_sensors_name() {
        for log in SENSORS {
            for other in SENSORS.iter().filter(|other| other.sensor != log.sensor) {
                assert_eq!(
                    check(log.sensor, &honest(other.sensor)),
                    Err(OriginError {
                        label: log.sensor.into(),
                        violation: Violation::OtherSensor {
                            sensor: other.sensor.into(),
                            bound: log.sensor,
                        },
                    }),
                    "log {} line {}",
                    log.sensor,
                    other.sensor
                );
            }
            assert_eq!(check(log.sensor, &honest(log.sensor)), Ok(()));
        }
    }

    #[test]
    fn the_shipped_cred_labels_are_bound_to_their_protocols() {
        let bound: Vec<(&str, Option<&str>)> = [
            "cred-vnc",
            "cred-mysql",
            "cred-mssql",
            "cred-pg",
            "cred-mongo",
        ]
        .into_iter()
        .map(|label| (label, bound_sensor(label)))
        .collect();
        assert_eq!(
            bound,
            [
                ("cred-vnc", Some("vnc")),
                ("cred-mysql", Some("mysql")),
                ("cred-mssql", Some("mssql")),
                ("cred-pg", Some("postgresql")),
                ("cred-mongo", Some("mongodb")),
            ]
        );
        assert_eq!(check("cred-vnc", &honest("vnc")), Ok(()));
        assert!(matches!(
            check("cred-vnc", &honest("mysql")).unwrap_err().violation,
            Violation::OtherSensor { bound: "vnc", .. }
        ));
        assert!(matches!(
            check("cred-pg", &honest("ssh")).unwrap_err().violation,
            Violation::OtherSensor {
                bound: "postgresql",
                ..
            }
        ));
    }

    #[test]
    fn an_unbound_label_accepts_any_known_sensor_and_refuses_an_unknown_one() {
        for label in [
            "collector-01",
            "test",
            "SSH",
            "ssh ",
            "cred",
            "cred-vnc2",
            "",
        ] {
            assert_eq!(bound_sensor(label), None, "{label:?}");
            for row in SENSORS {
                assert_eq!(check(label, &honest(row.sensor)), Ok(()), "{label:?}");
            }
            for unknown in ["probe", "cred-vnc", "Ssh", "ssh\n", "suricata", ""] {
                let mut line = honest("ssh");
                line.sensor = unknown.into();
                assert_eq!(
                    check(label, &line),
                    Err(OriginError {
                        label: label.into(),
                        violation: Violation::UnknownSensor {
                            sensor: unknown.into()
                        },
                    }),
                    "{label:?} {unknown:?}"
                );
            }
        }
    }

    #[test]
    fn an_unbound_label_still_holds_each_line_to_its_own_sensors_row() {
        let mut upload = event("catchall", SIGNAL_HONEYPOT_MALWARE_UPLOAD, PROTO_TCP);
        assert!(matches!(
            check("collector-01", &upload).unwrap_err().violation,
            Violation::SignalType { .. }
        ));
        upload.signal_type = SIGNAL_CATCHALL_PROBE.into();
        upload.authenticated = true;
        assert!(matches!(
            check("collector-01", &upload).unwrap_err().violation,
            Violation::Authenticated { .. }
        ));
        assert!(matches!(
            check("collector-01", &summary("ssh"))
                .unwrap_err()
                .violation,
            Violation::EventSummary { .. }
        ));
        assert_eq!(check("collector-01", &summary("vnc")), Ok(()));
    }

    #[test]
    fn an_unknown_sensor_is_refused_on_a_bound_log_too() {
        let mut line = honest("ssh");
        line.sensor = "sshd".into();
        assert!(matches!(
            check("ssh", &line).unwrap_err().violation,
            Violation::UnknownSensor { .. }
        ));
        assert!(matches!(
            conforms(&line),
            Err(Violation::UnknownSensor { .. })
        ));
    }

    #[test]
    fn every_label_the_shipped_configuration_uses_is_bound_to_a_sensor() {
        // The binding is exact, so a label renamed in the shipped files without this table would
        // silently leave that log unbound.
        let deploy = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let bound_by = |file: &str, key: &str| -> Vec<&'static str> {
            let text = std::fs::read_to_string(deploy.join(file)).unwrap();
            let value = text
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap_or_else(|| panic!("{file} sets {key}"));
            value
                .split(',')
                .map(|entry| {
                    let label = entry.split(':').next().unwrap_or_default().trim();
                    bound_sensor(label).unwrap_or_else(|| {
                        panic!("{file}: the log labelled {label:?} is not bound to a sensor")
                    })
                })
                .collect()
        };
        assert!(!bound_by("collector.env.example", "PROPOLIS_SHIPPER_SENSOR_LOGS=").is_empty());

        // The single-node file lists every shipped sensor's log, so between them its labels bind
        // every row of the table, each once.
        let mut single_node = bound_by("propolis.env.example", "PROPOLIS_SENSOR_LOGS=");
        let mut table: Vec<&str> = SENSORS.iter().map(|row| row.sensor).collect();
        single_node.sort_unstable();
        table.sort_unstable();
        assert_eq!(single_node, table);
    }

    #[test]
    fn an_error_names_the_log_the_sensor_and_the_field_and_stays_short() {
        let mut line = event("catchall", SIGNAL_HONEYPOT_MALWARE_UPLOAD, PROTO_TCP);
        assert_eq!(
            check("catchall", &line).unwrap_err().to_string(),
            "log \"catchall\": sensor \"catchall\" does not emit signal_type \
             \"honeypot_malware_upload\""
        );
        line.sensor = "ssh".into();
        assert_eq!(
            check("catchall", &line).unwrap_err().to_string(),
            "log \"catchall\": the line names sensor \"ssh\", but this log belongs to sensor \
             \"catchall\""
        );
        // A claimed value is the writer's own: it is escaped and cut, so a refused line cannot
        // forge a second log line or fill the journal.
        line.sensor = format!("x\n{}", "y".repeat(2_000_000));
        let text = check("catchall", &line).unwrap_err().to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.len() < 200, "{}", text.len());
        line.sensor = "catchall".into();
        line.signal_type = "z".repeat(2_000_000);
        assert!(check("catchall", &line).unwrap_err().to_string().len() < 200);
    }
}
