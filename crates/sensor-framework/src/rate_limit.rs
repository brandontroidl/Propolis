//! Reply rate limiting and flood summaries for sensors that answer over UDP.
//!
//! A UDP source address is whatever the sender wrote, so a sensor that replies over UDP can be
//! made to send its replies, one for one, at a victim. Bounding each reply's size (see
//! `sensor-dns`'s `guarded.rs`) removes amplification but not reflection itself: without a rate
//! limit one spoofer drives the sensor at line rate, laundering the flood's origin and making the
//! operator's address the source of unsolicited traffic. [`ReplyRateLimiter`] caps that rate per
//! source network and in total; [`FloodLedger`] lets a sensor stop writing one event per datagram
//! for a source over its budget and write one bounded summary per window instead
//! ([`rate_limited_event`], the same shape for every sensor), so a flood cannot turn into a log
//! flood either.
//!
//! Sources are aggregated to the network a single host can usually spoof or own wholesale: the
//! /24 for IPv4 (IPv4-mapped IPv6 is IPv4) and the /56 for IPv6, the smallest prefix commonly
//! delegated to one site. Each key holds a token bucket kept as a theoretical arrival time
//! (GCRA): one `Instant` per key, exact in integer nanoseconds, O(1) per check. A second bucket
//! of the same shape bounds the total across all keys, so spraying many networks cannot multiply
//! the budget.
//!
//! Every table here is allocated once at its fixed capacity and never grows with the number of
//! distinct sources: a full key table evicts the least recently seen of a few sampled slots, and
//! a full summary table folds new sources into one overflow summary. The locks are plain mutexes
//! held for a few field updates and never across an `.await`. Time is `tokio::time::Instant`, so
//! tests can drive it with a paused clock.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use sensor_wire::{PROTO_UDP, SIGNAL_HONEYPOT_CONNECTION, SensorEvent, WIRE_VERSION};
use serde_json::json;
use tokio::time::Instant;
use uuid::Uuid;

use crate::listener::normalize_dual_stack;
use crate::sanitize::sanitize_value;

/// Source networks the limiter tracks at once.
pub const DEFAULT_RATE_TABLE_CAPACITY: usize = 4096;
/// Source networks the flood ledger summarizes at once; any further network in the same window is
/// counted in one overflow summary.
pub const DEFAULT_SUMMARY_CAPACITY: usize = 1024;
/// How long a summary accumulates before it is emitted.
pub const DEFAULT_SUMMARY_WINDOW: Duration = Duration::from_secs(10);
/// Sample strings kept per summary.
pub const MAX_SUMMARY_SAMPLES: usize = 8;
/// Distinct source addresses counted per summary; beyond this the count is reported as capped.
pub const MAX_SUMMARY_SOURCES: usize = 32;
/// Longest sample string kept, after sanitization.
pub const MAX_SUMMARY_SAMPLE_LEN: usize = 1100;
/// Slots examined when a full key table must evict one.
const EVICTION_SAMPLES: usize = 4;
/// Bounds on [`FloodLedger::emit_interval`].
const MIN_EMIT_INTERVAL: Duration = Duration::from_millis(10);
const MAX_EMIT_INTERVAL: Duration = Duration::from_secs(1);

/// A source network: the /24 of an IPv4 address or the /56 of an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    V4([u8; 3]),
    V6([u8; 7]),
}

impl SourceKey {
    /// The key of `peer`'s address, with IPv4-mapped IPv6 treated as the IPv4 address it maps.
    pub fn of(peer: SocketAddr) -> Self {
        Self::of_ip(normalize_dual_stack(peer).ip())
    }

    pub fn of_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                SourceKey::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::of_ip(IpAddr::V4(v4)),
                None => {
                    let o = v6.octets();
                    SourceKey::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6]])
                }
            },
        }
    }
}

/// CIDR notation of the network, e.g. `198.51.100.0/24` or `2001:db8:0:ff00::/56`.
impl fmt::Display for SourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceKey::V4([a, b, c]) => write!(f, "{}/24", Ipv4Addr::new(*a, *b, *c, 0)),
            SourceKey::V6(prefix) => {
                let mut octets = [0u8; 16];
                octets[..7].copy_from_slice(prefix);
                write!(f, "{}/56", Ipv6Addr::from(octets))
            }
        }
    }
}

/// A sustained rate and a burst, both at least one: a zero cannot be expressed, so a rate can
/// never be configured into "disabled".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    per_second: NonZeroU32,
    burst: NonZeroU32,
}

impl Rate {
    pub const fn new(per_second: NonZeroU32, burst: NonZeroU32) -> Self {
        Self { per_second, burst }
    }

    pub fn per_second(self) -> u32 {
        self.per_second.get()
    }

    pub fn burst(self) -> u32 {
        self.burst.get()
    }

    /// Time one token takes to refill, at least a nanosecond so no rate rounds to "unlimited".
    fn interval(self) -> Duration {
        (Duration::from_secs(1) / self.per_second.get()).max(Duration::from_nanos(1))
    }

    /// How far ahead of now the arrival time may run: room for `burst - 1` more tokens.
    fn tolerance(self) -> Duration {
        self.interval()
            .checked_mul(self.burst.get() - 1)
            .unwrap_or(Duration::MAX)
    }
}

/// Everything [`ReplyRateLimiter`] and [`FloodLedger`] are built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub per_source: Rate,
    pub global: Rate,
    pub table_capacity: NonZeroUsize,
    pub summary_capacity: NonZeroUsize,
    pub summary_window: Duration,
}

impl RateLimitConfig {
    /// The two rates with the default table sizes and summary window.
    pub fn new(per_source: Rate, global: Rate) -> Self {
        Self {
            per_source,
            global,
            table_capacity: NonZeroUsize::new(DEFAULT_RATE_TABLE_CAPACITY)
                .unwrap_or(NonZeroUsize::MIN),
            summary_capacity: NonZeroUsize::new(DEFAULT_SUMMARY_CAPACITY)
                .unwrap_or(NonZeroUsize::MIN),
            summary_window: DEFAULT_SUMMARY_WINDOW,
        }
    }
}

/// The outcome of one [`ReplyRateLimiter::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Within both budgets; one token was taken from each.
    Allow,
    /// The source network is over its budget; nothing was taken.
    SourceLimited,
    /// The source network had a token but the global budget did not; nothing was taken.
    GlobalLimited,
}

/// A theoretical arrival time: the bucket is full when it is at or before now.
#[derive(Debug, Clone, Copy)]
struct Gcra {
    tat: Instant,
}

impl Gcra {
    /// The arrival time after taking one token at `now`, or `None` when the bucket is empty.
    fn try_take(self, rate: Rate, now: Instant) -> Option<Instant> {
        let tat = self.tat.max(now);
        // A tolerance past the clock's range is a burst no arrival time can exceed.
        if now
            .checked_add(rate.tolerance())
            .is_some_and(|limit| tat > limit)
        {
            return None;
        }
        Some(tat.checked_add(rate.interval()).unwrap_or(tat))
    }
}

#[derive(Debug)]
struct Slot {
    key: SourceKey,
    bucket: Gcra,
    last_seen: Instant,
}

#[derive(Debug)]
struct LimiterState {
    slots: Vec<Slot>,
    index: HashMap<SourceKey, usize>,
    global: Gcra,
    rng: u64,
}

impl LimiterState {
    fn next_random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// The slot for `key`, created full (or by evicting the least recently seen of a few sampled
    /// slots when the table is at capacity).
    fn slot_for(&mut self, key: SourceKey, now: Instant, capacity: usize) -> usize {
        if let Some(&at) = self.index.get(&key) {
            return at;
        }
        let fresh = Slot {
            key,
            bucket: Gcra { tat: now },
            last_seen: now,
        };
        if self.slots.len() < capacity {
            self.slots.push(fresh);
            let at = self.slots.len() - 1;
            self.index.insert(key, at);
            return at;
        }
        let len = self.slots.len() as u64;
        let mut victim = (self.next_random() % len) as usize;
        for _ in 1..EVICTION_SAMPLES {
            let candidate = (self.next_random() % len) as usize;
            if self.slots[candidate].last_seen < self.slots[victim].last_seen {
                victim = candidate;
            }
        }
        self.index.remove(&self.slots[victim].key);
        self.slots[victim] = fresh;
        self.index.insert(key, victim);
        victim
    }
}

/// Per-source-network and global reply budgets over a fixed-capacity table.
#[derive(Debug)]
pub struct ReplyRateLimiter {
    state: Mutex<LimiterState>,
    per_source: Rate,
    global: Rate,
    capacity: usize,
}

impl ReplyRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let capacity = config.table_capacity.get();
        Self {
            state: Mutex::new(LimiterState {
                slots: Vec::with_capacity(capacity),
                index: HashMap::with_capacity(capacity),
                global: Gcra {
                    tat: Instant::now(),
                },
                // Fixed seed: eviction choice only has to be spread, not secret, because the
                // least recently seen sample is evicted and an active flooder is never that.
                rng: 0x9E37_79B9_7F4A_7C15,
            }),
            per_source: config.per_source,
            global: config.global,
            capacity,
        }
    }

    /// Take one reply token for `peer`'s source network and one from the global budget, or
    /// neither.
    pub fn check(&self, peer: SocketAddr) -> RateDecision {
        self.check_at(SourceKey::of(peer), Instant::now())
    }

    pub fn check_at(&self, key: SourceKey, now: Instant) -> RateDecision {
        // A poisoned lock only means another holder panicked mid-update of plain values, which are
        // still usable.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let at = state.slot_for(key, now, self.capacity);
        state.slots[at].last_seen = now;
        let Some(source_tat) = state.slots[at].bucket.try_take(self.per_source, now) else {
            return RateDecision::SourceLimited;
        };
        let Some(global_tat) = state.global.try_take(self.global, now) else {
            return RateDecision::GlobalLimited;
        };
        state.slots[at].bucket.tat = source_tat;
        state.global.tat = global_tat;
        RateDecision::Allow
    }

    /// Source networks currently tracked; never more than the table capacity.
    pub fn tracked_keys(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .slots
            .len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// One source network's (or the overflow's) suppressed traffic over one window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloodSummary {
    /// `None` for the overflow summary: networks that arrived while the table was full.
    pub key: Option<SourceKey>,
    /// The first source address seen in the window.
    pub first_source: IpAddr,
    pub count: u64,
    pub bytes: u64,
    pub source_limited: u64,
    pub global_limited: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    /// At most [`MAX_SUMMARY_SAMPLES`], each sanitized and at most [`MAX_SUMMARY_SAMPLE_LEN`].
    pub samples: Vec<String>,
    /// Distinct source addresses seen, at most [`MAX_SUMMARY_SOURCES`].
    pub distinct_sources: usize,
    /// More distinct sources arrived than were counted.
    pub distinct_sources_capped: bool,
}

#[derive(Debug)]
struct LedgerEntry {
    summary: FloodSummary,
    sources: Vec<IpAddr>,
}

impl LedgerEntry {
    fn new(key: Option<SourceKey>, source: IpAddr, now: Instant) -> Self {
        Self {
            summary: FloodSummary {
                key,
                first_source: source,
                count: 0,
                bytes: 0,
                source_limited: 0,
                global_limited: 0,
                first_seen: now,
                last_seen: now,
                samples: Vec::with_capacity(MAX_SUMMARY_SAMPLES),
                distinct_sources: 0,
                distinct_sources_capped: false,
            },
            sources: Vec::with_capacity(MAX_SUMMARY_SOURCES),
        }
    }

    fn add(
        &mut self,
        source: IpAddr,
        decision: RateDecision,
        bytes: usize,
        now: Instant,
        sample: impl FnOnce() -> String,
    ) {
        let s = &mut self.summary;
        s.count = s.count.saturating_add(1);
        s.bytes = s.bytes.saturating_add(bytes as u64);
        match decision {
            RateDecision::GlobalLimited => s.global_limited = s.global_limited.saturating_add(1),
            _ => s.source_limited = s.source_limited.saturating_add(1),
        }
        s.last_seen = now;
        if s.samples.len() < MAX_SUMMARY_SAMPLES {
            s.samples
                .push(sanitize_value(&sample(), MAX_SUMMARY_SAMPLE_LEN));
        }
        if !self.sources.contains(&source) {
            if self.sources.len() < MAX_SUMMARY_SOURCES {
                self.sources.push(source);
            } else {
                s.distinct_sources_capped = true;
            }
        }
        s.distinct_sources = self.sources.len();
    }
}

#[derive(Debug)]
struct LedgerState {
    entries: HashMap<SourceKey, LedgerEntry>,
    overflow: Option<LedgerEntry>,
}

/// Bounded per-source-network summaries of datagrams a sensor did not answer or log one by one.
#[derive(Debug)]
pub struct FloodLedger {
    state: Mutex<LedgerState>,
    capacity: usize,
    window: Duration,
}

impl FloodLedger {
    pub fn new(config: &RateLimitConfig) -> Self {
        let capacity = config.summary_capacity.get();
        Self {
            state: Mutex::new(LedgerState {
                entries: HashMap::with_capacity(capacity),
                overflow: None,
            }),
            capacity,
            window: config.summary_window,
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    /// Count one datagram the limiter refused. `sample` runs only while the summary has room for
    /// another sample, so a flood allocates nothing per datagram beyond the fixed tables.
    pub fn record(
        &self,
        peer: SocketAddr,
        decision: RateDecision,
        bytes: usize,
        now: Instant,
        sample: impl FnOnce() -> String,
    ) {
        let source = normalize_dual_stack(peer).ip();
        let key = SourceKey::of_ip(source);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        let entry = if state.entries.len() < self.capacity || state.entries.contains_key(&key) {
            state
                .entries
                .entry(key)
                .or_insert_with(|| LedgerEntry::new(Some(key), source, now))
        } else {
            state
                .overflow
                .get_or_insert_with(|| LedgerEntry::new(None, source, now))
        };
        entry.add(source, decision, bytes, now, sample);
    }

    /// Remove and return every summary whose window has ended at `now`.
    pub fn take_due(&self, now: Instant) -> Vec<FloodSummary> {
        let window = self.window;
        let due = |e: &LedgerEntry| e.summary.first_seen + window <= now;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        state.entries.retain(|_, entry| {
            if due(entry) {
                out.push(entry.summary.clone());
                false
            } else {
                true
            }
        });
        if state.overflow.as_ref().is_some_and(due) {
            out.extend(state.overflow.take().map(|e| e.summary));
        }
        out
    }

    /// Remove and return every summary, due or not (shutdown).
    pub fn drain(&self) -> Vec<FloodSummary> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<FloodSummary> = state.entries.drain().map(|(_, e)| e.summary).collect();
        out.extend(state.overflow.take().map(|e| e.summary));
        out
    }

    /// Summaries currently accumulating, the overflow included.
    pub fn pending(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.len() + usize::from(state.overflow.is_some())
    }

    /// How often a sensor should look for due summaries: a tenth of the window, clamped, so a
    /// summary is written at most that late.
    pub fn emit_interval(&self) -> Duration {
        (self.window / 10).clamp(MIN_EMIT_INTERVAL, MAX_EMIT_INTERVAL)
    }
}

/// One source network's UDP datagrams that got no reply and no event of their own over one
/// window because the reply rate limit refused them, as the `honeypot_connection` over `udp` a
/// single datagram would be. `source_ip` is the first address seen from the network in the window
/// and `source_prefix` names the network (`"overflow"` for networks that arrived while the summary
/// table was full). `first_seen` and `last_seen` are wall-clock times reconstructed from the
/// monotonic instants at emission.
pub fn rate_limited_event(
    sensor: &str,
    protocol_label: &str,
    s: &FloodSummary,
    wan_ip: Option<IpAddr>,
    window: Duration,
    now: Instant,
    now_utc: DateTime<Utc>,
) -> SensorEvent {
    let wall = |at: Instant| {
        let ago = chrono::Duration::from_std(now.saturating_duration_since(at)).unwrap_or_default();
        (now_utc - ago).to_rfc3339_opts(SecondsFormat::Millis, true)
    };
    let source_prefix = match s.key {
        Some(key) => key.to_string(),
        None => "overflow".to_string(),
    };
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: s.first_source,
        wan_ip,
        sensor: sensor.into(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.into(),
        protocol: PROTO_UDP.into(),
        authenticated: false,
        observed_at: now_utc,
        metadata: json!({
            "protocol_label": protocol_label,
            "transport": "udp",
            "query_status": "rate_limited",
            "source_prefix": source_prefix,
            "suppressed_count": s.count,
            "suppressed_bytes": s.bytes,
            "per_source_limited": s.source_limited,
            "global_limited": s.global_limited,
            "first_seen": wall(s.first_seen),
            "last_seen": wall(s.last_seen),
            "window_secs": window.as_secs_f64(),
            "samples": s.samples,
            "distinct_sources": s.distinct_sources as u64,
            "distinct_sources_capped": s.distinct_sources_capped,
        }),
        sample: None,
        session_id: Some(Uuid::now_v7()),
        occurrence_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn config(per_second: u32, burst: u32, global: u32, global_burst: u32) -> RateLimitConfig {
        RateLimitConfig::new(
            Rate::new(nz(per_second), nz(burst)),
            Rate::new(nz(global), nz(global_burst)),
        )
    }

    fn peer(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn key(s: &str) -> SourceKey {
        SourceKey::of(peer(s))
    }

    fn allowed(limiter: &ReplyRateLimiter, k: SourceKey, now: Instant, n: usize) -> usize {
        (0..n)
            .filter(|_| limiter.check_at(k, now) == RateDecision::Allow)
            .count()
    }

    #[test]
    fn burst_then_the_sustained_rate() {
        let limiter = ReplyRateLimiter::new(&config(5, 10, 1000, 2000));
        let k = key("198.51.100.9:4000");
        let t0 = Instant::now();
        assert_eq!(allowed(&limiter, k, t0, 50), 10, "the burst, then nothing");
        assert_eq!(
            allowed(&limiter, k, t0 + Duration::from_millis(199), 5),
            0,
            "less than one interval refills nothing"
        );
        assert_eq!(allowed(&limiter, k, t0 + Duration::from_millis(200), 5), 1);
        assert_eq!(allowed(&limiter, k, t0 + Duration::from_secs(1), 5), 4);
        // Idle long enough and the bucket is full again, never fuller.
        assert_eq!(allowed(&limiter, k, t0 + Duration::from_secs(60), 50), 10);
    }

    #[test]
    fn a_steady_flood_gets_at_most_burst_plus_rate_times_elapsed() {
        let limiter = ReplyRateLimiter::new(&config(5, 10, 1000, 2000));
        let k = key("203.0.113.1:53");
        let t0 = Instant::now();
        // One query per millisecond for three seconds.
        let got = (0..3000u64)
            .filter(|ms| {
                limiter.check_at(k, t0 + Duration::from_millis(*ms)) == RateDecision::Allow
            })
            .count();
        assert_eq!(
            got,
            10 + 5 * 3 - 1,
            "10 at once, then one per 200 ms up to 2.8 s"
        );
        assert!(got <= 10 + 5 * 3);
    }

    #[test]
    fn ipv4_aggregates_to_the_24_and_mapped_ipv6_is_ipv4() {
        assert_eq!(key("198.51.100.1:1"), key("198.51.100.254:2"));
        assert_eq!(key("198.51.100.1:1"), key("[::ffff:198.51.100.77]:3"));
        assert_ne!(key("198.51.100.1:1"), key("198.51.101.1:1"));
        assert_eq!(key("198.51.100.1:1").to_string(), "198.51.100.0/24");

        let limiter = ReplyRateLimiter::new(&config(1, 2, 1000, 2000));
        let t0 = Instant::now();
        assert_eq!(
            limiter.check_at(key("198.51.100.1:1"), t0),
            RateDecision::Allow
        );
        assert_eq!(
            limiter.check_at(key("[::ffff:198.51.100.2]:1"), t0),
            RateDecision::Allow
        );
        assert_eq!(
            limiter.check_at(key("198.51.100.200:9"), t0),
            RateDecision::SourceLimited,
            "three hosts of one /24 share one budget"
        );
        assert_eq!(
            limiter.check_at(key("198.51.101.1:1"), t0),
            RateDecision::Allow
        );
    }

    #[test]
    fn ipv6_aggregates_to_the_56() {
        assert_eq!(key("[2001:db8:0:ff00::1]:1"), key("[2001:db8:0:ffff::9]:1"));
        assert_ne!(key("[2001:db8:0:ff00::1]:1"), key("[2001:db8:0:fe00::1]:1"));
        assert_ne!(key("[2001:db8:0:ff00::1]:1"), key("[2001:db8:1:ff00::1]:1"));
        assert_eq!(
            key("[2001:db8:0:ffab::1]:1").to_string(),
            "2001:db8:0:ff00::/56"
        );

        let limiter = ReplyRateLimiter::new(&config(1, 1, 1000, 2000));
        let t0 = Instant::now();
        assert_eq!(
            limiter.check_at(key("[2001:db8:0:ff00::1]:1"), t0),
            RateDecision::Allow
        );
        assert_eq!(
            limiter.check_at(key("[2001:db8:0:ffff::2]:1"), t0),
            RateDecision::SourceLimited
        );
        assert_eq!(
            limiter.check_at(key("[2001:db8:0:fe00::1]:1"), t0),
            RateDecision::Allow
        );
    }

    #[test]
    fn the_table_stays_bounded_under_100k_distinct_networks() {
        let limiter = ReplyRateLimiter::new(&config(5, 10, u32::MAX, u32::MAX));
        let t0 = Instant::now();
        for i in 0..100_000u32 {
            let [_, a, b, c] = i.to_be_bytes();
            let k = SourceKey::V4([a, b, c]);
            limiter.check_at(k, t0 + Duration::from_micros(u64::from(i)));
        }
        assert_eq!(limiter.tracked_keys(), DEFAULT_RATE_TABLE_CAPACITY);
        let state = limiter.state.lock().unwrap();
        assert_eq!(
            state.slots.capacity(),
            DEFAULT_RATE_TABLE_CAPACITY,
            "never reallocated"
        );
        assert_eq!(state.index.len(), DEFAULT_RATE_TABLE_CAPACITY);
        for (k, &at) in &state.index {
            assert_eq!(state.slots[at].key, *k, "index and slots agree");
        }
    }

    #[test]
    fn an_active_flooder_keeps_its_empty_bucket_through_a_spray() {
        let limiter = ReplyRateLimiter::new(&config(5, 10, u32::MAX, u32::MAX));
        let flooder = key("203.0.113.5:1");
        let t0 = Instant::now();
        assert_eq!(allowed(&limiter, flooder, t0, 10), 10);
        for i in 0..50_000u32 {
            let now = t0 + Duration::from_nanos(u64::from(i));
            let [_, a, b, c] = (i + 1).to_be_bytes();
            limiter.check_at(SourceKey::V4([a, b, c]), now);
            // The flooder keeps sending, so it is never the least recently seen.
            if i % 100 == 0 {
                assert_eq!(
                    limiter.check_at(flooder, now),
                    RateDecision::SourceLimited,
                    "{i}"
                );
            }
        }
    }

    #[test]
    fn the_global_budget_bounds_many_networks_and_charges_nothing_on_refusal() {
        let limiter = ReplyRateLimiter::new(&config(5, 10, 1000, 20));
        let t0 = Instant::now();
        let got = (0..100u8)
            .filter(|i| limiter.check_at(SourceKey::V4([10, 0, *i]), t0) == RateDecision::Allow)
            .count();
        assert_eq!(got, 20, "the global burst across 100 networks");
        assert_eq!(
            limiter.check_at(SourceKey::V4([10, 1, 0]), t0),
            RateDecision::GlobalLimited
        );
        // That refusal took no token from 10.1.0.0/24: after one global interval it still has
        // its whole burst minus the one allowed now.
        let later = t0 + Duration::from_millis(1);
        assert_eq!(
            limiter.check_at(SourceKey::V4([10, 1, 0]), later),
            RateDecision::Allow
        );
        let tenth = later + Duration::from_millis(9);
        assert_eq!(allowed(&limiter, SourceKey::V4([10, 1, 0]), tenth, 9), 9);
    }

    #[test]
    fn a_burst_of_one_allows_exactly_one_per_interval() {
        let limiter = ReplyRateLimiter::new(&config(2, 1, 1000, 2000));
        let k = key("192.0.2.1:1");
        let t0 = Instant::now();
        assert_eq!(allowed(&limiter, k, t0, 3), 1);
        assert_eq!(allowed(&limiter, k, t0 + Duration::from_millis(500), 3), 1);
    }

    #[test]
    fn extreme_rates_neither_panic_nor_round_to_unlimited() {
        let k = key("192.0.2.1:1");
        let t0 = Instant::now();
        let huge = ReplyRateLimiter::new(&config(u32::MAX, u32::MAX, u32::MAX, u32::MAX));
        assert_eq!(allowed(&huge, k, t0, 1000), 1000);
        let slow = ReplyRateLimiter::new(&config(1, u32::MAX, 1, u32::MAX));
        assert_eq!(allowed(&slow, k, t0, 1000), 1000);
        // u32::MAX per second still charges a nanosecond per token.
        let tight = ReplyRateLimiter::new(&config(u32::MAX, 1, u32::MAX, u32::MAX));
        assert_eq!(allowed(&tight, k, t0, 1000), 1);
    }

    fn ledger(capacity: usize, window: Duration) -> FloodLedger {
        let mut c = config(5, 10, 1000, 2000);
        c.summary_capacity = NonZeroUsize::new(capacity).unwrap();
        c.summary_window = window;
        FloodLedger::new(&c)
    }

    #[test]
    fn a_summary_aggregates_one_network_and_bounds_its_samples() {
        let l = ledger(16, Duration::from_secs(10));
        let t0 = Instant::now();
        let mut sampled = 0;
        for i in 0..100u64 {
            let host = 1 + (i % 40) as u8;
            l.record(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host)), 5000),
                if i % 10 == 0 {
                    RateDecision::GlobalLimited
                } else {
                    RateDecision::SourceLimited
                },
                29,
                t0 + Duration::from_millis(i),
                || {
                    sampled += 1;
                    format!("A q{i}.example.\n")
                },
            );
        }
        assert_eq!(
            sampled, MAX_SUMMARY_SAMPLES,
            "samples are built only while there is room"
        );
        assert_eq!(l.pending(), 1);
        assert!(l.take_due(t0 + Duration::from_millis(9_999)).is_empty());
        let due = l.take_due(t0 + Duration::from_secs(10));
        assert_eq!(due.len(), 1);
        let s = &due[0];
        assert_eq!(s.key, Some(SourceKey::V4([198, 51, 100])));
        assert_eq!(s.first_source, "198.51.100.1".parse::<IpAddr>().unwrap());
        assert_eq!((s.count, s.bytes), (100, 2900));
        assert_eq!((s.source_limited, s.global_limited), (90, 10));
        assert_eq!(s.first_seen, t0);
        assert_eq!(s.last_seen, t0 + Duration::from_millis(99));
        assert_eq!(s.samples.len(), MAX_SUMMARY_SAMPLES);
        assert_eq!(s.samples[0], "A q0.example. ", "samples are sanitized");
        assert_eq!(s.distinct_sources, MAX_SUMMARY_SOURCES);
        assert!(
            s.distinct_sources_capped,
            "40 hosts counted to the cap of 32"
        );
        assert_eq!(l.pending(), 0, "an emitted summary leaves the table");
    }

    #[test]
    fn a_full_ledger_folds_new_networks_into_one_overflow_summary() {
        let l = ledger(4, Duration::from_secs(10));
        let t0 = Instant::now();
        for i in 0..1000u32 {
            let [_, a, b, c] = i.to_be_bytes();
            l.record(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, 1)), 9),
                RateDecision::SourceLimited,
                40,
                t0,
                String::new,
            );
        }
        assert_eq!(l.pending(), 5);
        let mut all = l.drain();
        assert_eq!(all.len(), 5);
        all.sort_by_key(|s| s.key.is_none());
        let overflow = all.last().unwrap();
        assert_eq!(overflow.key, None);
        assert_eq!(overflow.count, 996);
        assert_eq!(all.iter().map(|s| s.count).sum::<u64>(), 1000);
        assert_eq!(l.pending(), 0);
    }

    #[test]
    fn take_due_keeps_windows_that_have_not_ended() {
        let l = ledger(16, Duration::from_secs(10));
        let t0 = Instant::now();
        let p = |s: &str| peer(s);
        l.record(
            p("192.0.2.1:1"),
            RateDecision::SourceLimited,
            1,
            t0,
            String::new,
        );
        l.record(
            p("198.51.100.1:1"),
            RateDecision::SourceLimited,
            1,
            t0 + Duration::from_secs(5),
            String::new,
        );
        let due = l.take_due(t0 + Duration::from_secs(10));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].key, Some(key("192.0.2.1:1")));
        assert_eq!(l.pending(), 1);
        assert_eq!(l.take_due(t0 + Duration::from_secs(15)).len(), 1);
    }

    #[test]
    fn the_emit_interval_is_a_tenth_of_the_window_clamped() {
        let at = |window: Duration| ledger(1, window).emit_interval();
        assert_eq!(at(Duration::from_millis(400)), Duration::from_millis(40));
        assert_eq!(at(Duration::from_secs(10)), Duration::from_secs(1));
        assert_eq!(at(Duration::from_secs(3600)), Duration::from_secs(1));
        assert_eq!(at(Duration::from_millis(50)), Duration::from_millis(10));
    }

    #[test]
    fn rate_limited_event_shape() {
        let now = Instant::now();
        let now_utc: DateTime<Utc> = "2026-10-07T12:00:10Z".parse().unwrap();
        let mut s = FloodSummary {
            key: Some(SourceKey::V4([198, 51, 100])),
            first_source: "198.51.100.9".parse().unwrap(),
            count: 500,
            bytes: 14_500,
            source_limited: 490,
            global_limited: 10,
            first_seen: now - Duration::from_secs(10),
            last_seen: now - Duration::from_millis(250),
            samples: vec!["ANY example.com.".into()],
            distinct_sources: 3,
            distinct_sources_capped: false,
        };
        let e = rate_limited_event(
            "dns",
            "dns",
            &s,
            None,
            Duration::from_secs(10),
            now,
            now_utc,
        );
        assert_eq!(e.sensor, "dns");
        assert_eq!(e.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(e.protocol, PROTO_UDP);
        assert!(!e.authenticated);
        assert!(e.session_id.is_some() && e.sample.is_none());
        assert_eq!(e.source_ip, s.first_source);
        let md = e.metadata.as_object().unwrap();
        let mut keys: Vec<&str> = md.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = vec![
            "protocol_label",
            "transport",
            "query_status",
            "source_prefix",
            "suppressed_count",
            "suppressed_bytes",
            "per_source_limited",
            "global_limited",
            "first_seen",
            "last_seen",
            "window_secs",
            "samples",
            "distinct_sources",
            "distinct_sources_capped",
        ];
        want.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(md["protocol_label"], "dns");
        assert_eq!(md["query_status"], "rate_limited");
        assert_eq!(md["transport"], "udp");
        assert_eq!(md["source_prefix"], "198.51.100.0/24");
        assert_eq!(md["suppressed_count"], 500);
        assert_eq!(md["suppressed_bytes"], 14_500);
        assert_eq!(md["per_source_limited"], 490);
        assert_eq!(md["global_limited"], 10);
        assert_eq!(md["first_seen"], "2026-10-07T12:00:00.000Z");
        assert_eq!(md["last_seen"], "2026-10-07T12:00:09.750Z");
        assert_eq!(md["window_secs"], 10.0);
        assert_eq!(md["samples"], json!(["ANY example.com."]));
        assert_eq!(md["distinct_sources"], 3);
        assert_eq!(md["distinct_sources_capped"], false);

        s.key = None;
        let overflow = rate_limited_event(
            "tftp",
            "tftp",
            &s,
            None,
            Duration::from_secs(10),
            now,
            now_utc,
        );
        assert_eq!(overflow.metadata["source_prefix"], "overflow");
        assert_eq!(
            (
                overflow.sensor.as_str(),
                overflow.metadata["protocol_label"].as_str()
            ),
            ("tftp", Some("tftp"))
        );
    }
}
