//! Refusing a source whose infection this sensor already let finish.
//!
//! A Mirai-family loader repeats the identical infection every minute or two for as long as the
//! target keeps answering telnet. On a real device the bot that `./i` started replaces telnetd, so
//! the port is closed and the loader marks the device infected and moves on; this sensor kept
//! answering, and one source wrote 252 events in 22 minutes of identical sessions. When a session
//! ends having run a fetched or assembled file natively (`FakeShell::infection_completed`), the
//! source is held: its new connections are reset instead of served, for [`DEFAULT_HOLD_SECS`]
//! unless configured otherwise. The first session is recorded exactly as before; only the repeats
//! go.
//!
//! Residual difference from a closed port: the connection is accepted by the kernel (a SYN-ACK is
//! sent) and reset straight after, where a real closed port answers the SYN with an RST. A
//! loader that connects and reads sees a reset either way; one that looks at the handshake alone
//! can tell. Closing that gap needs a firewall rule, which the sensor does not manage.
//!
//! State is a fixed-capacity table in memory: [`TABLE_CAPACITY`] sources, the one expiring
//! soonest evicted when a new source needs the room. A restart clears it, so a source is served
//! again after one. A source is an IPv4 address or an IPv6 /64: a /64 is the smallest unit one
//! subscriber cannot tell apart (privacy addresses rotate inside it), and anything coarser would
//! hold neighbours that infected nothing.
//!
//! Refusals are counted, never silent: per-source in the table, in total, and summarized to the
//! journal once per [`SUMMARY_INTERVAL`] by [`spawn_summary_writer`].

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

/// How long a finished infection's source is held when `PROPOLIS_TELNET_INFECTED_HOLD_SECS` is
/// unset: six hours, longer than any loader's retry cycle and short enough that a recycled
/// address is not shut out for good.
pub const DEFAULT_HOLD_SECS: u64 = 21_600;
/// The longest configurable hold: seven days.
pub const MAX_HOLD_SECS: u64 = 604_800;
/// Sources held at once.
pub const TABLE_CAPACITY: usize = 4096;
/// How often the refusal counts are written to the journal.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
/// Sources named in one summary line, most refused first.
pub const SUMMARY_TOP_SOURCES: usize = 5;

/// What the table keys a source by: a whole IPv4 address, or the /64 of an IPv6 one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoldKey {
    V4(Ipv4Addr),
    V6Prefix([u8; 8]),
}

impl HoldKey {
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4),
                None => {
                    let o = v6.octets();
                    Self::V6Prefix([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
                }
            },
        }
    }
}

impl fmt::Display for HoldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(v4) => write!(f, "{v4}"),
            Self::V6Prefix(p) => {
                let mut octets = [0u8; 16];
                octets[..8].copy_from_slice(p);
                write!(f, "{}/64", Ipv6Addr::from(octets))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    expires: Instant,
    /// Connections refused since the entry was made.
    refused: u64,
    /// Connections refused since the last summary.
    refused_in_window: u64,
}

#[derive(Debug, Default)]
struct State {
    entries: HashMap<HoldKey, Entry>,
    refused_total: u64,
    /// Held sources dropped from the table to make room, since start.
    evicted_total: u64,
}

/// Where the hold reads the time. A test supplies its own to move past a window.
pub type HoldClock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// One refusal summary: what was refused since the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalSummary {
    pub refused: u64,
    pub sources: usize,
    /// Up to [`SUMMARY_TOP_SOURCES`] sources, most refused first.
    pub top: Vec<(HoldKey, u64)>,
    pub held_now: usize,
    pub refused_total: u64,
}

/// The sensor's table of held sources. Disabled (every call a no-op that admits) when built with a
/// zero hold.
pub struct InfectedHold {
    hold: Option<Duration>,
    clock: HoldClock,
    state: Mutex<State>,
}

impl fmt::Debug for InfectedHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InfectedHold")
            .field("hold", &self.hold)
            .finish_non_exhaustive()
    }
}

impl InfectedHold {
    /// A hold of `hold_secs`; zero disables the feature.
    pub fn new(hold_secs: u64) -> Self {
        Self::with_clock(hold_secs, Arc::new(Instant::now))
    }

    pub fn with_clock(hold_secs: u64, clock: HoldClock) -> Self {
        Self {
            hold: (hold_secs > 0).then(|| Duration::from_secs(hold_secs)),
            clock,
            state: Mutex::new(State::default()),
        }
    }

    pub fn disabled() -> Self {
        Self::new(0)
    }

    pub fn hold(&self) -> Option<Duration> {
        self.hold
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hold `ip` from now on. A source already held has its expiry pushed out and keeps its count.
    pub fn mark(&self, ip: IpAddr) {
        let Some(hold) = self.hold else {
            return;
        };
        let now = (self.clock)();
        let expires = now + hold;
        let key = HoldKey::of(ip);
        let mut state = self.lock();
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.expires = entry.expires.max(expires);
            return;
        }
        if state.entries.len() >= TABLE_CAPACITY {
            state.entries.retain(|_, entry| entry.expires > now);
        }
        if state.entries.len() >= TABLE_CAPACITY {
            let oldest = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                state.entries.remove(&oldest);
                state.evicted_total = state.evicted_total.saturating_add(1);
            }
        }
        state.entries.insert(
            key,
            Entry {
                expires,
                refused: 0,
                refused_in_window: 0,
            },
        );
    }

    /// Whether a new connection from `ip` is to be refused; counts it when it is. An entry past
    /// its expiry is dropped here and the source served.
    pub fn refuses(&self, ip: IpAddr) -> bool {
        if self.hold.is_none() {
            return false;
        }
        let now = (self.clock)();
        let key = HoldKey::of(ip);
        let mut state = self.lock();
        let Some(entry) = state.entries.get_mut(&key) else {
            return false;
        };
        if entry.expires <= now {
            state.entries.remove(&key);
            return false;
        }
        entry.refused = entry.refused.saturating_add(1);
        entry.refused_in_window = entry.refused_in_window.saturating_add(1);
        state.refused_total = state.refused_total.saturating_add(1);
        true
    }

    pub fn held_sources(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn refused_total(&self) -> u64 {
        self.lock().refused_total
    }

    pub fn evicted_total(&self) -> u64 {
        self.lock().evicted_total
    }

    /// Connections refused from `ip`'s source since it was held; zero when it is not held.
    pub fn refused_from(&self, ip: IpAddr) -> u64 {
        self.lock()
            .entries
            .get(&HoldKey::of(ip))
            .map_or(0, |entry| entry.refused)
    }

    /// What was refused since the last call, and reset that count; `None` when nothing was.
    pub fn take_summary(&self) -> Option<RefusalSummary> {
        let mut state = self.lock();
        let mut top: Vec<(HoldKey, u64)> = Vec::new();
        let mut refused: u64 = 0;
        for (key, entry) in &mut state.entries {
            if entry.refused_in_window > 0 {
                refused = refused.saturating_add(entry.refused_in_window);
                top.push((*key, entry.refused_in_window));
                entry.refused_in_window = 0;
            }
        }
        if top.is_empty() {
            return None;
        }
        let sources = top.len();
        top.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.0.to_string().cmp(&b.0.to_string()))
        });
        top.truncate(SUMMARY_TOP_SOURCES);
        Some(RefusalSummary {
            refused,
            sources,
            top,
            held_now: state.entries.len(),
            refused_total: state.refused_total,
        })
    }
}

/// Write the refusal summary to the journal every `interval` ([`SUMMARY_INTERVAL`] in the
/// sensor). The task ends when the returned handle is aborted.
pub fn spawn_summary_writer(hold: Arc<InfectedHold>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Some(summary) = hold.take_summary() {
                log_summary(&summary);
            }
        }
    })
}

/// The summary as one journal line.
pub fn log_summary(summary: &RefusalSummary) {
    let top: Vec<String> = summary
        .top
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect();
    tracing::info!(
        refused = summary.refused,
        sources = summary.sources,
        held_now = summary.held_now,
        refused_total = summary.refused_total,
        top = %top.join(","),
        "telnet: connections from sources with a finished infection were reset"
    );
}

/// A configured hold the sensor refuses to start with.
#[derive(Debug, PartialEq, Eq)]
pub struct HoldConfigError {
    pub value: String,
}

impl fmt::Display for HoldConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PROPOLIS_TELNET_INFECTED_HOLD_SECS must be a whole number of seconds from 0 to \
             {MAX_HOLD_SECS} (0 disables the hold), got {:?}",
            self.value
        )
    }
}

impl std::error::Error for HoldConfigError {}

/// Parse `PROPOLIS_TELNET_INFECTED_HOLD_SECS`: unset takes [`DEFAULT_HOLD_SECS`], `0` is the
/// explicit off switch, and anything that is not plain digits or is past [`MAX_HOLD_SECS`] is an
/// error rather than a default.
pub fn parse_hold_secs(raw: Option<&str>) -> Result<u64, HoldConfigError> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_HOLD_SECS);
    };
    let invalid = || HoldConfigError {
        value: raw.to_string(),
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let secs: u64 = raw.parse().map_err(|_| invalid())?;
    if secs > MAX_HOLD_SECS {
        return Err(invalid());
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A clock the test advances by hand.
    fn manual_clock() -> (HoldClock, Arc<AtomicU64>) {
        let base = Instant::now();
        let offset = Arc::new(AtomicU64::new(0));
        let reader = offset.clone();
        (
            Arc::new(move || base + Duration::from_secs(reader.load(Ordering::SeqCst))),
            offset,
        )
    }

    #[test]
    fn a_marked_source_is_refused_until_the_window_ends_and_others_are_not() {
        let (clock, now) = manual_clock();
        let hold = InfectedHold::with_clock(100, clock);
        assert!(!hold.refuses(ip("203.0.113.7")));
        hold.mark(ip("203.0.113.7"));
        assert!(hold.refuses(ip("203.0.113.7")));
        assert!(!hold.refuses(ip("203.0.113.8")), "a neighbour is served");
        now.store(99, Ordering::SeqCst);
        assert!(hold.refuses(ip("203.0.113.7")));
        now.store(100, Ordering::SeqCst);
        assert!(!hold.refuses(ip("203.0.113.7")), "served again at expiry");
        assert_eq!(hold.held_sources(), 0, "an expired entry is dropped");
    }

    #[test]
    fn a_zero_hold_is_disabled_and_marks_nothing() {
        let hold = InfectedHold::disabled();
        hold.mark(ip("203.0.113.7"));
        assert!(!hold.refuses(ip("203.0.113.7")));
        assert_eq!(hold.held_sources(), 0);
        assert_eq!(hold.hold(), None);
    }

    #[test]
    fn ipv6_is_keyed_by_its_slash_64_and_a_mapped_v4_by_its_address() {
        let hold = InfectedHold::new(100);
        hold.mark(ip("2001:db8:1:2:aaaa::1"));
        assert!(hold.refuses(ip("2001:db8:1:2:bbbb::9")), "same /64");
        assert!(
            !hold.refuses(ip("2001:db8:1:3::1")),
            "the next /64 is another source"
        );
        hold.mark(ip("::ffff:203.0.113.9"));
        assert!(hold.refuses(ip("203.0.113.9")));
        assert_eq!(
            HoldKey::of(ip("2001:db8:1:2::5")).to_string(),
            "2001:db8:1:2::/64"
        );
    }

    #[test]
    fn marking_a_held_source_again_extends_it_and_keeps_its_count() {
        let (clock, now) = manual_clock();
        let hold = InfectedHold::with_clock(100, clock);
        hold.mark(ip("203.0.113.7"));
        assert!(hold.refuses(ip("203.0.113.7")));
        now.store(60, Ordering::SeqCst);
        hold.mark(ip("203.0.113.7"));
        now.store(150, Ordering::SeqCst);
        assert!(hold.refuses(ip("203.0.113.7")), "pushed out to 160");
        assert_eq!(hold.refused_from(ip("203.0.113.7")), 2);
        assert_eq!(hold.held_sources(), 1);
    }

    #[test]
    fn a_full_table_evicts_the_source_expiring_soonest() {
        let (clock, now) = manual_clock();
        let hold = InfectedHold::with_clock(1_000_000, clock);
        for i in 0..TABLE_CAPACITY {
            now.store(i as u64, Ordering::SeqCst);
            let n = u32::try_from(i).unwrap();
            hold.mark(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n)));
        }
        assert_eq!(hold.held_sources(), TABLE_CAPACITY);
        now.store(TABLE_CAPACITY as u64, Ordering::SeqCst);
        hold.mark(ip("203.0.113.200"));
        assert_eq!(hold.held_sources(), TABLE_CAPACITY, "capacity holds");
        assert_eq!(hold.evicted_total(), 1);
        assert!(
            !hold.refuses(IpAddr::V4(Ipv4Addr::from(0x0A00_0000))),
            "the earliest-expiring source went"
        );
        assert!(hold.refuses(IpAddr::V4(Ipv4Addr::from(0x0A00_0001))));
        assert!(hold.refuses(ip("203.0.113.200")));
    }

    #[test]
    fn a_full_table_drops_expired_entries_before_evicting_a_live_one() {
        let (clock, now) = manual_clock();
        let hold = InfectedHold::with_clock(10, clock);
        for i in 0..TABLE_CAPACITY {
            hold.mark(IpAddr::V4(Ipv4Addr::from(
                0x0A00_0000 + u32::try_from(i).unwrap(),
            )));
        }
        now.store(10, Ordering::SeqCst);
        hold.mark(ip("203.0.113.200"));
        assert_eq!(hold.held_sources(), 1);
        assert_eq!(hold.evicted_total(), 0, "expired entries are not evictions");
    }

    #[test]
    fn the_summary_counts_since_the_last_one_and_names_the_most_refused() {
        let hold = InfectedHold::new(100);
        for source in ["203.0.113.1", "203.0.113.2", "203.0.113.3"] {
            hold.mark(ip(source));
        }
        for _ in 0..3 {
            hold.refuses(ip("203.0.113.2"));
        }
        hold.refuses(ip("203.0.113.1"));
        let summary = hold.take_summary().unwrap();
        assert_eq!(summary.refused, 4);
        assert_eq!(summary.sources, 2);
        assert_eq!(summary.top[0], (HoldKey::of(ip("203.0.113.2")), 3));
        assert_eq!(summary.held_now, 3);
        assert_eq!(summary.refused_total, 4);
        assert_eq!(hold.take_summary(), None, "the window was reset");
        hold.refuses(ip("203.0.113.2"));
        assert_eq!(hold.take_summary().unwrap().refused_total, 5);
    }

    #[tokio::test]
    async fn the_summary_writer_takes_the_counts_each_interval() {
        let hold = Arc::new(InfectedHold::new(100));
        hold.mark(ip("203.0.113.1"));
        hold.refuses(ip("203.0.113.1"));
        let pending = || {
            hold.lock()
                .entries
                .values()
                .any(|e| e.refused_in_window > 0)
        };
        assert!(pending(), "the refusal is waiting to be summarized");
        let writer = spawn_summary_writer(hold.clone(), Duration::from_millis(20));
        let deadline = Instant::now() + Duration::from_secs(5);
        while pending() {
            assert!(
                Instant::now() < deadline,
                "the writer never took the counts"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        writer.abort();
    }

    #[test]
    fn the_hold_setting_defaults_accepts_zero_and_refuses_the_rest() {
        assert_eq!(parse_hold_secs(None), Ok(DEFAULT_HOLD_SECS));
        assert_eq!(parse_hold_secs(Some("0")), Ok(0));
        assert_eq!(parse_hold_secs(Some("3600")), Ok(3600));
        assert_eq!(parse_hold_secs(Some("604800")), Ok(MAX_HOLD_SECS));
        for bad in [
            "604801",
            "-1",
            "+5",
            "6h",
            "",
            " 5",
            "1.5",
            "99999999999999999999999",
        ] {
            assert!(
                parse_hold_secs(Some(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }
}
