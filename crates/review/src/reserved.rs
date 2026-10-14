//! The review crate's reserved-address test, shared by the gatekeeper and the review queue.
//!
//! In every normal build this is exactly [`core_scoring::is_reserved_ip`]. The `test-public-ranges`
//! cargo feature adds one test-only exception: the RFC 5737 block 203.0.113.0/24 (TEST-NET-3)
//! counts as public. The gatekeeper holds every reserved address as `Reserved` before it looks at
//! anything else, so a test of the Disabled, ScoreFloor, Cooldown or RateLimit holds, or of the
//! daemon's queue populate pass, needs an address that is not reserved. Using a documentation
//! address keeps a real, allocated address out of the public repository.
//!
//! The feature is off by default and must never be enabled in a release build. Its only enabler is
//! this crate's own `[dev-dependencies]` (a self-dependency), which cargo activates for test,
//! example and `--all-targets` builds and never for `cargo build --release`. It deliberately lives
//! here and not in `core-scoring`: the blocklist feed (`feed::exclusion`) and the fetcher's SSRF
//! guard (`fetcher::guard`) call `core_scoring::is_reserved_ip` directly and keep treating
//! 203.0.113.0/24 as reserved even when the feature is on.

use std::net::IpAddr;

// A release-profile build with the feature on would make the shipped binaries treat 203.0.113.0/24
// as public, and `cargo test --release` or `cargo build --release --all-targets` would put such a
// binary in target/release, which install.sh copies without rebuilding. Refuse to compile it.
#[cfg(all(feature = "test-public-ranges", not(debug_assertions)))]
compile_error!(
    "review's test-public-ranges feature is test-only and must not be built with the release \
     profile (it would make the shipped binaries treat 203.0.113.0/24 as public)"
);

/// True if `ip` must never be offered to the operator or reported to a vendor.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    #[cfg(feature = "test-public-ranges")]
    if is_test_public(ip) {
        return false;
    }
    core_scoring::is_reserved_ip(ip)
}

/// Plain IPv4 only: the IPv6 forms that wrap an IPv4 address stay reserved, so the exception cannot
/// widen beyond the literal dotted-quad addresses the tests write.
#[cfg(feature = "test-public-ranges")]
fn is_test_public(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[..3] == [203, 0, 113])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Whatever the feature, every other documentation block and every wrapped form of the
    /// exception block stays reserved.
    #[test]
    fn only_the_one_block_is_ever_opened() {
        for s in [
            "192.0.2.1",
            "198.51.100.1",
            "10.0.0.1",
            "127.0.0.1",
            "::ffff:203.0.113.5",
            "64:ff9b::cb00:7105",
            "2001:db8::1",
        ] {
            assert!(is_reserved_ip(ip(s)), "{s} must stay reserved");
        }
    }

    #[cfg(feature = "test-public-ranges")]
    #[test]
    fn with_the_feature_the_test_block_is_public() {
        for s in ["203.0.113.0", "203.0.113.1", "203.0.113.255"] {
            assert!(
                !is_reserved_ip(ip(s)),
                "{s} must be public under the feature"
            );
            assert!(
                core_scoring::is_reserved_ip(ip(s)),
                "{s} stays reserved in core-scoring"
            );
        }
    }

    #[cfg(not(feature = "test-public-ranges"))]
    #[test]
    fn without_the_feature_the_test_block_is_reserved() {
        for s in ["203.0.113.0", "203.0.113.1", "203.0.113.255"] {
            assert!(is_reserved_ip(ip(s)), "{s} must be reserved");
        }
    }
}
