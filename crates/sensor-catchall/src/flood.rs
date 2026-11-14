//! The catch-all's UDP budget.
//!
//! A UDP source address is whatever the sender wrote, and the catch-all records every datagram
//! it is sent. Without a budget, one sender at line rate writes one log line per packet under as
//! many forged addresses as it likes, and the log, the shipper and the ledger behind them fill at
//! the sender's rate. This module puts the two-level token bucket the UDP sensors that answer
//! already use (`sensor_framework::rate_limit`) in front of the per-datagram event: one bucket
//! per source network (the IPv4 /24, the IPv6 /56) and one for the whole process. A datagram
//! over either gets no event of its own. It is counted into its source network's summary, and
//! one `catchall_probe` summary line per network per window records how many were withheld and
//! shows a few of them.
//!
//! The allowance is shared by every UDP listener, so a sender sweeping many ports draws on one
//! budget, not one per port. The summaries are kept per bind address rather than per port for the
//! same reason: fifty ports swept from one network are one summary line, not fifty. A summary
//! line therefore carries no `local_port`; each of its samples names the port it arrived on.
//!
//! TCP is not budgeted here. A completed handshake proves the source, and `run_tcp_listener`
//! caps how many connections one source holds at once.

use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sensor_framework::{
    EventEmitter, FloodLedger, FloodSummary, Rate, RateDecision, RateLimitConfig, ReplyRateLimiter,
    Uuid, WanResolver, flood_summary_metadata, to_hex_bounded,
};
use sensor_wire::{PROTO_UDP, SIGNAL_CATCHALL_PROBE, SensorEvent, WIRE_VERSION};
use tokio::time::Instant;

/// Source networks summarized per bind address per window. Any further network in the same
/// window is counted in one overflow summary, so a flood under any number of forged networks
/// writes at most this many summary lines plus one, per window, for each address the sensor
/// binds.
pub const SUMMARY_CAPACITY: usize = 64;

/// Leading bytes of a withheld datagram shown in a summary sample.
const SAMPLE_BYTES: usize = 32;

/// Datagrams recorded one by one per second per source network, and the burst above that rate.
/// The burst lets one sweep of a couple of dozen ports through whole; the rate holds a sender
/// that keeps going to one event a second.
pub const DEFAULT_RATE_PER_SOURCE_PER_SECOND: u32 = 1;
pub const DEFAULT_BURST_PER_SOURCE: u32 = 20;
/// Datagrams recorded one by one per second across every source and listener, and the burst.
/// Unsolicited UDP reaches an address at a few datagrams a minute, so this is far above
/// background and far below what a sender can generate.
pub const DEFAULT_RATE_GLOBAL_PER_SECOND: u32 = 20;
pub const DEFAULT_BURST_GLOBAL: u32 = 100;

const fn rate(per_second: u32, burst: u32) -> Rate {
    match (NonZeroU32::new(per_second), NonZeroU32::new(burst)) {
        (Some(per_second), Some(burst)) => Rate::new(per_second, burst),
        _ => panic!("a default rate and burst are both at least one"),
    }
}

/// The shipped per-source-network and global budgets.
pub const DEFAULT_RATE_PER_SOURCE: Rate =
    rate(DEFAULT_RATE_PER_SOURCE_PER_SECOND, DEFAULT_BURST_PER_SOURCE);
pub const DEFAULT_RATE_GLOBAL: Rate = rate(DEFAULT_RATE_GLOBAL_PER_SECOND, DEFAULT_BURST_GLOBAL);

/// The two rates with the catch-all's summary table size and the default window.
pub fn budget_config(per_source: Rate, global: Rate) -> RateLimitConfig {
    let mut config = RateLimitConfig::new(per_source, global);
    config.summary_capacity = NonZeroUsize::new(SUMMARY_CAPACITY).unwrap_or(NonZeroUsize::MIN);
    config
}

/// The allowance every UDP listener of the process draws on.
#[derive(Debug)]
pub struct UdpBudget {
    limiter: ReplyRateLimiter,
    config: RateLimitConfig,
}

impl UdpBudget {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: ReplyRateLimiter::new(&config),
            config,
        }
    }
}

/// One bind address's share of the work: the process-wide allowance, and the summaries of what
/// that allowance withheld from the listeners on this address.
#[derive(Debug)]
pub struct UdpFlood {
    budget: Arc<UdpBudget>,
    ledger: FloodLedger,
    local_ip: IpAddr,
}

impl UdpFlood {
    pub fn new(budget: Arc<UdpBudget>, local_ip: IpAddr) -> Self {
        let ledger = FloodLedger::new(&budget.config);
        Self {
            budget,
            ledger,
            local_ip,
        }
    }

    /// The bind address these summaries belong to, which WAN attribution resolves against.
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// Whether a datagram from `peer` is within budget and gets an event of its own. One that is
    /// not is counted into its source network's summary here, and the caller writes nothing.
    pub fn admit(&self, peer: SocketAddr, local_port: Option<u16>, data: &[u8]) -> bool {
        let decision = self.budget.limiter.check(peer);
        if decision == RateDecision::Allow {
            return true;
        }
        self.ledger
            .record(peer, decision, data.len(), Instant::now(), || {
                sample(local_port, data)
            });
        false
    }

    /// Write every summary whose window has ended.
    pub async fn emit_due(&self, wan_resolver: &WanResolver, emitter: &EventEmitter) {
        let due = self.ledger.take_due(Instant::now());
        self.emit(due, wan_resolver, emitter).await;
    }

    /// Write every summary still accumulating, due or not. Bounded by the summary table's fixed
    /// capacity; called at shutdown so a flood in progress is not lost with the process.
    pub async fn flush(&self, wan_resolver: &WanResolver, emitter: &EventEmitter) {
        let pending = self.ledger.drain();
        self.emit(pending, wan_resolver, emitter).await;
    }

    async fn emit(
        &self,
        summaries: Vec<FloodSummary>,
        wan_resolver: &WanResolver,
        emitter: &EventEmitter,
    ) {
        if summaries.is_empty() {
            return;
        }
        let wan_ip = wan_resolver.resolve(self.local_ip);
        let (now, now_utc) = (Instant::now(), Utc::now());
        for summary in &summaries {
            let event = summary_event(summary, wan_ip, self.ledger.window(), now, now_utc);
            if let Err(e) = emitter.append(&event).await {
                tracing::error!(error = %e, "catchall: failed to append udp summary event");
            }
        }
    }
}

/// Write each summary as its window ends, forever. Holds no lock across the appends: the ledger
/// hands over the due summaries and forgets them first.
pub async fn run_summaries(
    flood: Arc<UdpFlood>,
    wan_resolver: Arc<WanResolver>,
    emitter: Arc<EventEmitter>,
) {
    let mut ticker = tokio::time::interval(flood.ledger.emit_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        flood.emit_due(&wan_resolver, &emitter).await;
    }
}

/// `"port <port> len <len> hex <leading bytes>"` for one withheld datagram. Runs only while the
/// summary has room for another sample. Hex is the only route captured bytes take into a record
/// (see `handler::MAX_HEX_SAMPLE_BYTES`), here as everywhere else in this sensor.
fn sample(local_port: Option<u16>, data: &[u8]) -> String {
    let port = match local_port {
        Some(port) => port.to_string(),
        None => "unknown".to_string(),
    };
    format!(
        "port {port} len {} hex {}",
        data.len(),
        to_hex_bounded(data, SAMPLE_BYTES)
    )
}

/// One source network's datagrams that got no event of their own over one window, as the
/// `catchall_probe` over `udp` a single datagram would be. `source_ip` is the first address seen
/// from the network in the window. `metadata.rate_limited` marks the line; it has no
/// `payload_hex` or `observed_len`, which describe one datagram. It is not an event summary in
/// scoring's sense (`sensor_wire::origin::EVENT_SUMMARY_KEY`): it counts as one sighting however
/// many datagrams it stands for, since none of them proved its source.
pub fn summary_event(
    summary: &FloodSummary,
    wan_ip: Option<IpAddr>,
    window: Duration,
    now: Instant,
    now_utc: DateTime<Utc>,
) -> SensorEvent {
    let mut metadata = flood_summary_metadata(summary, window, now, now_utc);
    metadata.insert("rate_limited".into(), true.into());
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: summary.first_source,
        wan_ip,
        sensor: "catchall".to_string(),
        signal_type: SIGNAL_CATCHALL_PROBE.to_string(),
        protocol: PROTO_UDP.to_string(),
        authenticated: false,
        observed_at: now_utc,
        metadata: serde_json::Value::Object(metadata),
        sample: None,
        session_id: Some(Uuid::now_v7()),
        occurrence_id: None,
        reply: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn flood(per_source: (u32, u32), global: (u32, u32)) -> UdpFlood {
        let config = budget_config(
            Rate::new(nz(per_source.0), nz(per_source.1)),
            Rate::new(nz(global.0), nz(global.1)),
        );
        UdpFlood::new(
            Arc::new(UdpBudget::new(config)),
            "192.0.2.1".parse().unwrap(),
        )
    }

    fn peer(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn one_source_network_gets_its_burst_and_the_rest_is_counted() {
        let flood = flood((1, 5), (1000, 1000));
        let admitted = (0..50)
            .filter(|i| flood.admit(peer(&format!("198.51.100.{i}:4000")), Some(5060), b"probe"))
            .count();
        assert_eq!(admitted, 5, "the /24 shares one burst of 5");
        let summaries = flood.ledger.drain();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].count, 45);
        assert_eq!(summaries[0].bytes, 45 * 5);
        assert_eq!(summaries[0].source_limited, 45);
        assert_eq!(summaries[0].global_limited, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn many_source_networks_share_the_global_burst() {
        let flood = flood((100, 100), (1, 7));
        let admitted = (0..200)
            .filter(|i| flood.admit(peer(&format!("198.51.{i}.9:4000")), Some(123), b"x"))
            .count();
        assert_eq!(admitted, 7, "200 networks, one global burst of 7");
        let summaries = flood.ledger.drain();
        assert_eq!(
            summaries.len(),
            SUMMARY_CAPACITY + 1,
            "the summary table holds SUMMARY_CAPACITY networks and one overflow"
        );
        assert_eq!(summaries.iter().map(|s| s.count).sum::<u64>(), 193);
        assert_eq!(summaries.iter().map(|s| s.global_limited).sum::<u64>(), 193);
    }

    #[tokio::test(start_paused = true)]
    async fn listeners_on_different_addresses_draw_on_one_allowance() {
        let config = budget_config(Rate::new(nz(1), nz(4)), Rate::new(nz(1000), nz(1000)));
        let budget = Arc::new(UdpBudget::new(config));
        let a = UdpFlood::new(budget.clone(), "192.0.2.1".parse().unwrap());
        let b = UdpFlood::new(budget, "192.0.2.2".parse().unwrap());
        let source = peer("203.0.113.5:9");
        let admitted = (0..10)
            .filter(|i| {
                let flood = if i % 2 == 0 { &a } else { &b };
                flood.admit(source, Some(53), b"x")
            })
            .count();
        assert_eq!(admitted, 4, "a second bind address is not a second burst");
        assert_eq!(a.ledger.drain()[0].count + b.ledger.drain()[0].count, 6);
    }

    #[tokio::test(start_paused = true)]
    async fn the_budget_refills_at_the_configured_rate() {
        let flood = flood((2, 3), (1000, 1000));
        let source = peer("203.0.113.5:9");
        let take = |n: usize| {
            (0..n)
                .filter(|_| flood.admit(source, Some(53), b"x"))
                .count()
        };
        assert_eq!(take(10), 3);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(take(10), 2, "two tokens a second");
    }

    #[tokio::test(start_paused = true)]
    async fn a_sample_names_the_port_and_shows_leading_bytes_as_hex() {
        let flood = flood((1, 1), (1000, 1000));
        let source = peer("203.0.113.5:9");
        assert!(flood.admit(source, Some(1900), b"first"));
        let long = vec![0xABu8; 500];
        assert!(!flood.admit(source, Some(1900), b"M-SEARCH\r\n\"}"));
        assert!(!flood.admit(source, None, &long));
        let summaries = flood.ledger.drain();
        assert_eq!(
            summaries[0].samples,
            vec![
                "port 1900 len 12 hex 4d2d5345415243480d0a227d".to_string(),
                format!("port unknown len 500 hex {}", "ab".repeat(SAMPLE_BYTES)),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_summary_is_a_catchall_probe_the_origin_policy_accepts() {
        let flood = flood((1, 1), (1000, 1000));
        let source = peer("203.0.113.5:9");
        assert!(flood.admit(source, Some(161), b"first"));
        for _ in 0..9 {
            assert!(!flood.admit(source, Some(161), b"again"));
        }
        let summaries = flood.ledger.drain();
        let wan: IpAddr = "198.51.100.77".parse().unwrap();
        let event = summary_event(
            &summaries[0],
            Some(wan),
            Duration::from_secs(10),
            Instant::now(),
            Utc::now(),
        );
        assert_eq!(event.sensor, "catchall");
        assert_eq!(event.signal_type, SIGNAL_CATCHALL_PROBE);
        assert_eq!(event.protocol, PROTO_UDP);
        assert_eq!(event.source_ip, source.ip());
        assert_eq!(event.wan_ip, Some(wan));
        assert!(!event.authenticated);
        assert_eq!(event.metadata["rate_limited"], true);
        assert_eq!(event.metadata["source_prefix"], "203.0.113.0/24");
        assert_eq!(event.metadata["suppressed_count"], 9);
        assert_eq!(event.metadata["suppressed_bytes"], 45);
        assert_eq!(event.metadata["per_source_limited"], 9);
        assert!(event.metadata.get("payload_hex").is_none());
        assert!(event.metadata.get("protocol_label").is_none());
        // Scoring counts a line marked as an event summary as every event it stands for. This
        // one must count once: no datagram it stands for proved where it came from.
        assert!(!sensor_wire::origin::is_event_summary(&event));
        assert_eq!(sensor_wire::origin::conforms(&event), Ok(()));
        assert_eq!(sensor_wire::origin::check("catchall", &event), Ok(()));
    }
}
