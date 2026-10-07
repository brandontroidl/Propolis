//! Which UDP sources a sensor may reply to at all.
//!
//! A UDP source address and port are whatever the sender wrote, so a sensor that answers over UDP
//! can be pointed at anything. [`check_reply_source`] refuses a source that cannot be a real
//! client (unspecified, broadcast, multicast) and a source port that belongs to a legacy UDP
//! service (echo, daytime, qotd, chargen, time, and port 0): a request spoofed "from" one of those
//! would make the sensor start a loop with a third party's service. Every sensor that sends UDP
//! (`sensor-dns`, `sensor-tftp`) runs this check before its send.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::listener::normalize_dual_stack;

pub const REFLECTIVE_SOURCE_PORTS: [u16; 6] = [0, 7, 13, 17, 19, 37];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRefusal {
    ReflectiveSourcePort,
    UnroutableSource,
}

impl SourceRefusal {
    /// The `suppress_reason` value recorded in an event.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceRefusal::ReflectiveSourcePort => "reflective_source_port",
            SourceRefusal::UnroutableSource => "unroutable_source",
        }
    }
}

/// Whether anything may be sent to `peer`. Pure: the decision depends only on the address, with
/// IPv4-mapped IPv6 judged as the IPv4 address it maps.
pub fn check_reply_source(peer: SocketAddr) -> Result<(), SourceRefusal> {
    let ip = normalize_dual_stack(peer).ip();
    let broadcast = ip == IpAddr::V4(Ipv4Addr::BROADCAST);
    if ip.is_unspecified() || broadcast || ip.is_multicast() {
        return Err(SourceRefusal::UnroutableSource);
    }
    if REFLECTIVE_SOURCE_PORTS.contains(&peer.port()) {
        return Err(SourceRefusal::ReflectiveSourcePort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn refuses_reflective_ports_and_unroutable_sources_and_allows_the_rest() {
        for port in REFLECTIVE_SOURCE_PORTS {
            assert_eq!(
                check_reply_source(SocketAddr::new("203.0.113.7".parse().unwrap(), port)),
                Err(SourceRefusal::ReflectiveSourcePort),
                "port {port}"
            );
        }
        for port in [1, 6, 8, 53, 69, 1024, 65535] {
            assert_eq!(
                check_reply_source(SocketAddr::new("203.0.113.7".parse().unwrap(), port)),
                Ok(()),
                "port {port}"
            );
        }
        for peer in [
            "0.0.0.0:5353",
            "255.255.255.255:5353",
            "224.0.0.1:5353",
            "239.255.255.250:1900",
            "[ff02::1]:5353",
            "[::]:5353",
            "[::ffff:255.255.255.255]:5353",
            "[::ffff:224.0.0.1]:5353",
            "[::ffff:0.0.0.0]:5353",
        ] {
            assert_eq!(
                check_reply_source(addr(peer)),
                Err(SourceRefusal::UnroutableSource),
                "{peer}"
            );
        }
        for peer in [
            "[2001:db8::1]:5353",
            "[::ffff:198.51.100.9]:5353",
            "198.51.100.255:5353",
        ] {
            assert_eq!(check_reply_source(addr(peer)), Ok(()), "{peer}");
        }
    }

    /// An unroutable source on a reflective port is reported as unroutable: the address alone
    /// already rules out any reply.
    #[test]
    fn an_unroutable_source_wins_over_its_port() {
        assert_eq!(
            check_reply_source(addr("255.255.255.255:7")),
            Err(SourceRefusal::UnroutableSource)
        );
    }

    #[test]
    fn reasons_have_stable_names() {
        assert_eq!(
            SourceRefusal::ReflectiveSourcePort.as_str(),
            "reflective_source_port"
        );
        assert_eq!(
            SourceRefusal::UnroutableSource.as_str(),
            "unroutable_source"
        );
    }
}
