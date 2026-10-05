//! Per-source admission cap. The listeners' global `max_concurrent` semaphore alone lets one source
//! IP take every permit and blind a sensor to all other sources; this limiter bounds how many of
//! those permits a single source can hold at once.
//!
//! The map holds only sources with at least one live admission (an entry is removed when its count
//! returns to zero), so its size is bounded by the global concurrency cap, not by the number of
//! distinct sources ever seen. IPv4-mapped IPv6 peers are normalized so a dual-stack listener
//! cannot count one host as two sources.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::listener::normalize_dual_stack;

/// Smallest per-source cap `default_per_source_cap` returns, so a small `max_concurrent` does not
/// collapse the cap to a value too low for a legitimate multi-connection client.
const MIN_PER_SOURCE_CAP: u32 = 2;

/// Derives the sensor default per-source cap: a quarter of `max_concurrent`, at least
/// `MIN_PER_SOURCE_CAP`, never above `max_concurrent` itself (a cap above the global one is inert).
pub fn default_per_source_cap(max_concurrent: u32) -> u32 {
    (max_concurrent / 4)
        .max(MIN_PER_SOURCE_CAP)
        .min(max_concurrent.max(1))
}

#[derive(Debug, Clone)]
pub struct PerSourceLimiter {
    counts: Arc<Mutex<HashMap<IpAddr, u32>>>,
    cap: u32,
}

impl PerSourceLimiter {
    pub fn new(cap: u32) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            cap,
        }
    }

    /// Admits one more holder for the peer's source IP unless it already holds `cap`. The returned
    /// guard releases the slot on drop.
    pub fn try_admit(&self, peer: SocketAddr) -> Option<SourceGuard> {
        let ip = normalize_dual_stack(peer).ip();
        // The critical section never awaits. A poisoned lock only means another holder panicked
        // mid-update of a plain counter map, so the data is still usable.
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.cap {
            return None;
        }
        *count += 1;
        Some(SourceGuard {
            counts: self.counts.clone(),
            ip,
        })
    }

    /// Number of sources currently holding at least one slot.
    pub fn tracked_sources(&self) -> usize {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Holds one per-source slot; dropping it (task end, panic, timeout, abort) frees the slot.
#[derive(Debug)]
pub struct SourceGuard {
    counts: Arc<Mutex<HashMap<IpAddr, u32>>>,
    ip: IpAddr,
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admits_up_to_cap_then_refuses_that_source_only() {
        let limiter = PerSourceLimiter::new(2);
        let a1 = limiter.try_admit(peer("203.0.113.1:1000"));
        let a2 = limiter.try_admit(peer("203.0.113.1:1001"));
        assert!(a1.is_some() && a2.is_some());
        assert!(limiter.try_admit(peer("203.0.113.1:1002")).is_none());
        assert!(limiter.try_admit(peer("203.0.113.2:1000")).is_some());
    }

    #[test]
    fn drop_frees_a_slot() {
        let limiter = PerSourceLimiter::new(1);
        let guard = limiter.try_admit(peer("203.0.113.1:1")).unwrap();
        assert!(limiter.try_admit(peer("203.0.113.1:2")).is_none());
        drop(guard);
        assert!(limiter.try_admit(peer("203.0.113.1:3")).is_some());
    }

    #[test]
    fn entry_removed_at_zero() {
        let limiter = PerSourceLimiter::new(3);
        let g1 = limiter.try_admit(peer("203.0.113.1:1")).unwrap();
        let g2 = limiter.try_admit(peer("203.0.113.1:2")).unwrap();
        let g3 = limiter.try_admit(peer("203.0.113.9:1")).unwrap();
        assert_eq!(limiter.tracked_sources(), 2);
        drop(g1);
        assert_eq!(limiter.tracked_sources(), 2);
        drop(g2);
        assert_eq!(limiter.tracked_sources(), 1);
        drop(g3);
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn ipv4_mapped_ipv6_and_plain_ipv4_are_one_source() {
        let limiter = PerSourceLimiter::new(1);
        let _g = limiter.try_admit(peer("203.0.113.7:1")).unwrap();
        assert!(limiter.try_admit(peer("[::ffff:203.0.113.7]:2")).is_none());
        assert_eq!(limiter.tracked_sources(), 1);
    }

    #[test]
    fn distinct_ipv6_sources_are_distinct() {
        let limiter = PerSourceLimiter::new(1);
        let _a = limiter.try_admit(peer("[2001:db8::1]:1")).unwrap();
        assert!(limiter.try_admit(peer("[2001:db8::2]:1")).is_some());
    }

    #[test]
    fn default_cap_is_quarter_with_floor_and_ceiling() {
        assert_eq!(default_per_source_cap(256), 64);
        assert_eq!(default_per_source_cap(8), 2);
        assert_eq!(default_per_source_cap(1), 1);
        assert_eq!(default_per_source_cap(2), 2);
        assert_eq!(default_per_source_cap(0), 1);
    }
}
