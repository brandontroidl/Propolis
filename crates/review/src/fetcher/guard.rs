use core_scoring::is_reserved_ip;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EgressReject {
    Reserved,
    ExtraRange,
    OwnHost,
    Teredo,
    V4Compat,
}

fn canonicalize(ip: IpAddr) -> Result<IpAddr, EgressReject> {
    let IpAddr::V6(v6) = ip else {
        return Ok(ip);
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Ok(IpAddr::V4(v4)); // ::ffff:a.b.c.d
    }
    let seg = v6.segments();
    if seg[0] == 0x64 && seg[1] == 0xff9b {
        // NAT64 well-known prefix space (RFC 6052 / RFC 8215). Decode the well-known /96 form to its
        // embedded IPv4 and re-check; reject any other NAT64 address (e.g. the 64:ff9b:1::/48
        // local-use prefix) outright. Propolis has a v4 WAN (no NAT64 route), so a NAT64 address can
        // only be an attacker steering us at a translated target, and only the /96 form decodes
        // cleanly; over-blocking the rest is safe here.
        if seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                (seg[6] >> 8) as u8,
                seg[6] as u8,
                (seg[7] >> 8) as u8,
                seg[7] as u8,
            )));
        }
        return Err(EgressReject::ExtraRange);
    }
    if seg[0] == 0x2002 {
        // 6to4 2002::/16
        return Ok(IpAddr::V4(Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        )));
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        return Err(EgressReject::Teredo); // 2001::/32
    }
    // ::a.b.c.d IPv4-compatible (deprecated) -> reject outright
    if seg[0..6].iter().all(|&s| s == 0) && (seg[6] != 0 || seg[7] > 1) {
        return Err(EgressReject::V4Compat);
    }
    Ok(ip)
}

fn in_extra_egress_deny(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0                               // 0.0.0.0/8
              || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => v6 == Ipv6Addr::UNSPECIFIED, // ::
    }
}

pub fn is_forbidden_egress_target(ip: IpAddr, own: &HashSet<IpAddr>) -> Option<EgressReject> {
    let c = match canonicalize(ip) {
        Ok(c) => c,
        Err(r) => return Some(r),
    };
    if own.contains(&c) {
        return Some(EgressReject::OwnHost);
    }
    if is_reserved_ip(c) {
        return Some(EgressReject::Reserved);
    }
    if in_extra_egress_deny(c) {
        return Some(EgressReject::ExtraRange);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forbidden_targets_are_all_rejected() {
        let own: HashSet<IpAddr> = [ip("203.0.113.9")].into_iter().collect(); // pretend our WAN
        for bad in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1", // v4-mapped
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",   // NAT64
            "64:ff9b:1::7f00:1", // NAT64 local-use /48, not the well-known /96
            "2002:7f00:1::",     // 6to4 -> 127.0.0.1
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "fe80::1",
            "fc00::1",
            "224.0.0.1",
            "203.0.113.9", // last = own
        ] {
            assert!(
                is_forbidden_egress_target(ip(bad), &own).is_some(),
                "should reject {bad}"
            );
        }
    }
    #[test]
    fn public_targets_including_mapped_are_allowed() {
        let own = HashSet::new();
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "::ffff:8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            assert!(
                is_forbidden_egress_target(ip(ok), &own).is_none(),
                "should allow {ok}"
            );
        }
    }
    // Regression: document that the base is_reserved_ip misses the mapped form (F-1 target).
    #[test]
    fn base_is_reserved_ip_misses_v4_mapped() {
        assert!(!core_scoring::is_reserved_ip(ip("::ffff:10.0.0.1")));
    }
}
