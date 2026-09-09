//! The listener inventory: what the control plane believes is listening, parsed from
//! `PROPOLIS_FLEET_LISTENERS`.
//!
//! No sensor has a compiled-in port, and the daemon binds none of them: every bind lives in a
//! per-sensor env file on the collector, one systemd unit per sensor. The control plane therefore
//! cannot discover its own fleet, and the console cannot report on listeners it was never told
//! about. This is the telling.
//!
//! **The name is the sensor's own self-reported name, not the intake log label.** `event.sensor`
//! is passed through from the sensor untouched, and `sensor-cred` reports its five protocols
//! individually (`vnc`, `mysql`, `mssql`, `postgresql`, `mongodb`) while its conventional
//! `PROPOLIS_SENSOR_LOGS` labels are `cred-vnc` and so on. An inventory keyed on the log label
//! would join to nothing. `deploy/fleet-listeners.sh` derives the list from the sensors' own bind
//! variables using the same mapping `sensor-cred/src/main.rs` uses, and
//! `tests/deploy_inventory_test.rs` carries a real generated file across that boundary.
//!
//! Fail closed: a malformed entry is an error, never a silently shortened list. An UNSET variable
//! is the caller's decision (both binaries read it as an empty inventory, so the pane reports
//! every check as unknown rather than reporting nothing at all); a value that is present but
//! unparseable stops the process.

/// Transport of a single listener. The two values are the ones the `listener_probe` table's
/// `CHECK` constraint admits, so a `Proto` can never fail to store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// The wire and database spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One listener the control plane believes exists on a collector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Listener {
    pub collector_id: String,
    pub sensor: String,
    pub protocol: Proto,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
    #[error("the listener inventory is empty; it must name at least one listener")]
    Empty,
    #[error("listener entry {entry:?} is malformed: {why}")]
    Malformed { entry: String, why: &'static str },
    #[error("listener entry {entry:?} has a port outside 1-65535")]
    BadPort { entry: String },
    #[error("listener entry {entry:?} names a protocol other than tcp or udp")]
    UnknownProto { entry: String },
}

/// Parses `collector/sensor/protocol/port` entries, comma separated.
///
/// Empty input is an error rather than an empty vector: "no listeners configured" and "the
/// operator meant to configure some and the value did not survive" look identical downstream, and
/// only the caller knows whether the variable was set at all.
pub fn parse_listeners(raw: &str) -> Result<Vec<Listener>, InventoryError> {
    let mut listeners = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let fields: Vec<&str> = entry.split('/').collect();
        if fields.len() != 4 {
            return Err(InventoryError::Malformed {
                entry: entry.to_string(),
                why: "expected collector/sensor/protocol/port",
            });
        }
        let (collector_id, sensor, proto_raw, port_raw) = (
            fields[0].trim(),
            fields[1].trim(),
            fields[2].trim(),
            fields[3].trim(),
        );
        if collector_id.is_empty() {
            return Err(InventoryError::Malformed {
                entry: entry.to_string(),
                why: "the collector id is empty",
            });
        }
        if sensor.is_empty() {
            return Err(InventoryError::Malformed {
                entry: entry.to_string(),
                why: "the sensor name is empty",
            });
        }
        let protocol = match proto_raw.to_ascii_lowercase().as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => {
                return Err(InventoryError::UnknownProto {
                    entry: entry.to_string(),
                });
            }
        };
        // `u16::from_str` already rejects 65536 and above; the explicit zero check is what stops
        // port 0, which parses fine and means "any port" to the kernel and nothing at all here.
        let port: u16 = port_raw.parse().map_err(|_| InventoryError::BadPort {
            entry: entry.to_string(),
        })?;
        if port == 0 {
            return Err(InventoryError::BadPort {
                entry: entry.to_string(),
            });
        }
        listeners.push(Listener {
            collector_id: collector_id.to_string(),
            sensor: sensor.to_string(),
            protocol,
            port,
        });
    }
    if listeners.is_empty() {
        return Err(InventoryError::Empty);
    }
    Ok(listeners)
}

/// How both binaries read `PROPOLIS_FLEET_LISTENERS`.
///
/// The two "no listeners" cases are not the same thing and are not treated the same way. An UNSET
/// or blank variable is a node that was never told its inventory: that is an empty inventory, the
/// pane reports every check as unknown, and the process starts. A variable that is SET but
/// unparseable is a configuration the operator meant to be real, so it stops the process rather
/// than degrading into a shorter list or a silent zero.
pub fn parse_listeners_env(raw: Option<&str>) -> Result<Vec<Listener>, InventoryError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(Vec::new()),
        Some(value) => parse_listeners(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_or_blank_inventory_variable_is_empty_but_a_malformed_one_is_an_error() {
        assert_eq!(parse_listeners_env(None), Ok(Vec::new()));
        assert_eq!(parse_listeners_env(Some("  ")), Ok(Vec::new()));
        assert!(parse_listeners_env(Some("local/ssh/tcp")).is_err());
        assert_eq!(
            parse_listeners_env(Some("local/ssh/tcp/22")).unwrap().len(),
            1
        );
    }

    #[test]
    fn parse_listeners_accepts_the_four_field_form() {
        let listeners = parse_listeners("local/ssh/tcp/22, local/catchall/udp/1024").unwrap();
        assert_eq!(
            listeners,
            vec![
                Listener {
                    collector_id: "local".into(),
                    sensor: "ssh".into(),
                    protocol: Proto::Tcp,
                    port: 22,
                },
                Listener {
                    collector_id: "local".into(),
                    sensor: "catchall".into(),
                    protocol: Proto::Udp,
                    port: 1024,
                },
            ]
        );
    }

    #[test]
    fn parse_listeners_rejects_an_entry_with_the_wrong_field_count() {
        assert!(matches!(
            parse_listeners("local/ssh/tcp"),
            Err(InventoryError::Malformed { .. })
        ));
        assert!(matches!(
            parse_listeners("local/ssh/tcp/22/extra"),
            Err(InventoryError::Malformed { .. })
        ));
        assert!(matches!(
            parse_listeners("local//tcp/22"),
            Err(InventoryError::Malformed { .. })
        ));
    }

    #[test]
    fn parse_listeners_rejects_a_port_outside_1_to_65535() {
        assert!(matches!(
            parse_listeners("local/ssh/tcp/0"),
            Err(InventoryError::BadPort { .. })
        ));
        assert!(matches!(
            parse_listeners("local/ssh/tcp/65536"),
            Err(InventoryError::BadPort { .. })
        ));
        assert!(matches!(
            parse_listeners("local/ssh/tcp/twenty-two"),
            Err(InventoryError::BadPort { .. })
        ));
    }

    #[test]
    fn parse_listeners_rejects_an_unknown_protocol() {
        assert!(matches!(
            parse_listeners("local/ssh/sctp/22"),
            Err(InventoryError::UnknownProto { .. })
        ));
    }

    #[test]
    fn parse_listeners_rejects_empty_input_rather_than_returning_none() {
        assert_eq!(parse_listeners(""), Err(InventoryError::Empty));
        assert_eq!(parse_listeners("   "), Err(InventoryError::Empty));
        assert_eq!(parse_listeners(" , , "), Err(InventoryError::Empty));
    }

    /// One malformed entry must never degrade into a shorter list: the whole value is rejected, so
    /// a typo cannot silently drop a listener out of the pane and make it look like it was never
    /// configured.
    #[test]
    fn one_bad_entry_rejects_the_whole_value_rather_than_shortening_it() {
        assert!(parse_listeners("local/ssh/tcp/22,local/telnet/tcp").is_err());
    }
}
