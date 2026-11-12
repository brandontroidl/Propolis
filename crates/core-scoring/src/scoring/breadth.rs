use std::collections::HashSet;
use std::net::IpAddr;

use rust_decimal::Decimal;

use super::constants::{BREADTH_CAP, BREADTH_PER_WAN, SCORE_CAP};

/// One vantage point's observation of a WAN IP.
///
/// `saw_authenticated_tcp` gates whether this vantage counts toward breadth
/// at all: an attacker can spoof source IPs into unauthenticated traffic
/// (e.g. raw SYN floods) to manufacture apparent breadth, but cannot forge a
/// full authenticated TCP handshake from an IP it does not control.
#[derive(Debug, Clone)]
pub struct WanVantage {
    pub wan_ip: IpAddr,
    pub saw_authenticated_tcp: bool,
}

/// Mask an IP down to its dedupe prefix: /24 for IPv4, /64 for IPv6.
///
/// Two vantages inside the same prefix are assumed to be the same
/// network-operator-assigned block rather than independent vantage points,
/// so they collapse to a single entry before counting.
///
/// ASN-based dedupe (correlating vantages that share an origin AS even
/// across unrelated prefixes) is a documented extension point, deferred per
/// the ratified decision - out of scope for this task, no stub here.
fn dedupe_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _d] = v4.octets();
            IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for byte in &mut octets[8..16] {
                *byte = 0;
            }
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

/// Count distinct WAN vantage points, hardened against spoofed breadth.
///
/// Only vantages with `saw_authenticated_tcp == true` are counted
/// (authenticated-vantage filter), and vantages are deduped by their /24
/// (IPv4) or /64 (IPv6) prefix (correlated-vantage dedupe) before counting.
pub fn distinct_wan_count(vantages: &[WanVantage]) -> u32 {
    let prefixes: HashSet<IpAddr> = vantages
        .iter()
        .filter(|v| v.saw_authenticated_tcp)
        .map(|v| dedupe_prefix(v.wan_ip))
        .collect();
    prefixes.len() as u32
}

/// Score multiplier from distinct WAN breadth.
///
/// `1 + min(BREADTH_CAP, BREADTH_PER_WAN * max(0, n - 1))`.
///
/// `n.saturating_sub(1)` guards the `n == 0` case (no authenticated
/// vantages at all): a plain `n - 1` would underflow `u32` there. Both
/// `breadth_factor(0)` and `breadth_factor(1)` yield exactly `1.00`.
pub fn breadth_factor(distinct_wan_count: u32) -> Decimal {
    let extra_wans = distinct_wan_count.saturating_sub(1);
    Decimal::ONE + std::cmp::min(BREADTH_CAP, BREADTH_PER_WAN * Decimal::from(extra_wans))
}

/// Raw score scaled by breadth, clamped to the score cap.
pub fn effective_score(raw_score: Decimal, distinct_wan_count: u32) -> Decimal {
    std::cmp::min(SCORE_CAP, raw_score * breadth_factor(distinct_wan_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn one_wan_gives_factor_one() {
        assert_eq!(breadth_factor(1), dec!(1.00));
    }

    #[test]
    fn zero_wans_gives_factor_one() {
        assert_eq!(breadth_factor(0), dec!(1.00));
    }

    #[test]
    fn five_or_more_wans_saturate_at_1_60() {
        assert_eq!(breadth_factor(5), dec!(1.60));
        assert_eq!(breadth_factor(9), dec!(1.60));
    }

    #[test]
    fn spoofed_wan_without_authenticated_tcp_is_not_counted() {
        let v = vec![
            WanVantage {
                wan_ip: "198.51.100.1".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
            WanVantage {
                wan_ip: "203.0.113.9".parse().unwrap(),
                saw_authenticated_tcp: false,
            },
        ];
        assert_eq!(distinct_wan_count(&v), 1);
    }

    #[test]
    fn same_24_counts_once() {
        let v = vec![
            WanVantage {
                wan_ip: "198.51.100.1".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
            WanVantage {
                wan_ip: "198.51.100.9".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
        ];
        assert_eq!(distinct_wan_count(&v), 1);
    }

    #[test]
    fn same_64_counts_once() {
        // Two IPv6 addresses in the same /64 (first 8 bytes equal) collapse to one vantage.
        let v = vec![
            WanVantage {
                wan_ip: "2001:db8:1:2::1".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
            WanVantage {
                wan_ip: "2001:db8:1:2::ffff".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
        ];
        assert_eq!(distinct_wan_count(&v), 1);
    }

    #[test]
    fn different_64_counts_twice() {
        let v = vec![
            WanVantage {
                wan_ip: "2001:db8:1:2::1".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
            WanVantage {
                wan_ip: "2001:db8:1:3::1".parse().unwrap(),
                saw_authenticated_tcp: true,
            },
        ];
        assert_eq!(distinct_wan_count(&v), 2);
    }

    #[test]
    fn effective_score_clamps_at_score_cap() {
        // raw 90 * breadth_factor(5)=1.60 = 144 -> clamped to SCORE_CAP (100).
        assert_eq!(effective_score(dec!(90), 5), dec!(100));
        // Below the cap passes through: 40 * 1.60 = 64.
        assert_eq!(effective_score(dec!(40), 5), dec!(64));
    }
}
