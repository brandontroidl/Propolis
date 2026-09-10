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

use std::collections::BTreeMap;

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

impl Listener {
    /// The `host:port` string the prober dials, or `None` when this listener's collector has no
    /// endpoint configured.
    ///
    /// `None` is a real answer, not a failure: the prober records it as `not_probeable` with a
    /// detail naming the missing endpoint, so an unconfigured collector shows on the pane as an
    /// unanswered question rather than vanishing from the row set or being guessed at. Guessing
    /// (localhost, the collector id as a hostname) would produce a green row for a socket nobody
    /// asked about.
    ///
    /// A bare IPv6 address is bracketed here so the result parses as a socket address. An endpoint
    /// that already carries brackets, or a hostname, is passed through untouched.
    pub fn target(&self, endpoints: &BTreeMap<String, String>) -> Option<String> {
        let addr = endpoints.get(&self.collector_id)?;
        if addr.parse::<std::net::Ipv6Addr>().is_ok() {
            Some(format!("[{addr}]:{}", self.port))
        } else {
            Some(format!("{addr}:{}", self.port))
        }
    }
}

/// Parses `collector=address` entries, comma separated, into the map [`Listener::target`] dials.
///
/// Unlike [`parse_listeners`], an empty value is NOT an error. A collector with no endpoint is
/// already a visible state on the pane (`not_probeable`, with the reason named), so an operator who
/// has configured no endpoints at all gets a page full of unanswered questions rather than a
/// refusal to start. A malformed entry is still an error: that is a value the operator meant to be
/// real, and silently dropping it would leave one collector unprobed for no stated reason.
pub fn parse_endpoints(raw: &str) -> Result<BTreeMap<String, String>, InventoryError> {
    let mut out = BTreeMap::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((collector, addr)) = entry.split_once('=') else {
            return Err(InventoryError::Malformed {
                entry: entry.to_string(),
                why: "expected collector=address",
            });
        };
        let (collector, addr) = (collector.trim(), addr.trim());
        if collector.is_empty() || addr.is_empty() {
            return Err(InventoryError::Malformed {
                entry: entry.to_string(),
                why: "both the collector id and the address must be non-empty",
            });
        }
        out.insert(collector.to_string(), addr.to_string());
    }
    Ok(out)
}

/// How the daemon reads `PROPOLIS_FLEET_COLLECTOR_ENDPOINTS`. Unset, blank, and "no entries" are
/// the same thing here, for the reason [`parse_endpoints`] gives.
pub fn parse_endpoints_env(raw: Option<&str>) -> Result<BTreeMap<String, String>, InventoryError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(BTreeMap::new()),
        Some(value) => parse_endpoints(value),
    }
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

    #[test]
    fn parse_endpoints_maps_collector_to_address() {
        let endpoints = parse_endpoints("local=198.51.100.7, edge = 203.0.113.9").unwrap();
        assert_eq!(endpoints.get("local"), Some(&"198.51.100.7".to_string()));
        assert_eq!(endpoints.get("edge"), Some(&"203.0.113.9".to_string()));
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn parse_endpoints_rejects_a_malformed_entry_rather_than_skipping_it() {
        assert!(matches!(
            parse_endpoints("local"),
            Err(InventoryError::Malformed { .. })
        ));
        assert!(matches!(
            parse_endpoints("=198.51.100.7"),
            Err(InventoryError::Malformed { .. })
        ));
        assert!(matches!(
            parse_endpoints("local="),
            Err(InventoryError::Malformed { .. })
        ));
        // A blank value is not the same as a malformed one: no endpoints configured is a state the
        // pane can render, so it must not stop the process.
        assert_eq!(parse_endpoints_env(None), Ok(BTreeMap::new()));
        assert_eq!(parse_endpoints_env(Some("  ")), Ok(BTreeMap::new()));
    }

    #[test]
    fn target_is_none_when_the_collector_has_no_endpoint() {
        let listener = Listener {
            collector_id: "local".into(),
            sensor: "ssh".into(),
            protocol: Proto::Tcp,
            port: 22,
        };
        assert_eq!(listener.target(&BTreeMap::new()), None);

        let other = parse_endpoints("edge=203.0.113.9").unwrap();
        assert_eq!(listener.target(&other), None);

        let matching = parse_endpoints("local=198.51.100.7").unwrap();
        assert_eq!(
            listener.target(&matching),
            Some("198.51.100.7:22".to_string())
        );
    }

    /// A bare IPv6 endpoint must come back bracketed or the result does not parse as a socket
    /// address and every probe against that collector fails as an `error` that looks like a
    /// network fault rather than the formatting bug it is.
    #[test]
    fn target_brackets_a_bare_ipv6_endpoint_and_leaves_a_hostname_alone() {
        let listener = Listener {
            collector_id: "local".into(),
            sensor: "ssh".into(),
            protocol: Proto::Tcp,
            port: 22,
        };
        let v6 = parse_endpoints("local=2001:db8::1").unwrap();
        assert_eq!(listener.target(&v6), Some("[2001:db8::1]:22".to_string()));
        assert!(
            listener
                .target(&v6)
                .unwrap()
                .parse::<std::net::SocketAddr>()
                .is_ok()
        );

        let host = parse_endpoints("local=collector.invalid").unwrap();
        assert_eq!(
            listener.target(&host),
            Some("collector.invalid:22".to_string())
        );
    }
}
