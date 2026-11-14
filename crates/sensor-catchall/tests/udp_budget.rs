//! The UDP budget, through the real socket and the real log.
//!
//! A UDP source address is whatever the sender wrote, so the number of lines a sender can make
//! the catch-all write has to be bounded by the sensor and not by the sender. These tests flood
//! a real listener and count lines: every datagram is either an event of its own or counted in a
//! summary, the events stay within the configured burst and rate, and the summaries stay within
//! the summary table however many source networks the flood claims.

use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::Path;
use std::time::Duration;

use sensor_catchall::flood::budget_config;
use sensor_framework::{ConnectionBounds, Rate, RateLimitConfig};
use sensor_wire::{PROTO_UDP, SIGNAL_CATCHALL_PROBE, SensorEvent};
use tokio::net::UdpSocket;
use tokio::time::Instant;

const WINDOW: Duration = Duration::from_millis(300);

fn rate(per_second: u32, burst: u32) -> Rate {
    let nz = |n| NonZeroU32::new(n).unwrap();
    Rate::new(nz(per_second), nz(burst))
}

fn budget(per_source: Rate, global: Rate) -> RateLimitConfig {
    let mut config = budget_config(per_source, global);
    config.summary_window = WINDOW;
    config
}

/// Roomy enough that the listener's own concurrency caps never drop a datagram these tests
/// send: a dropped datagram is in neither an event nor a summary, and the counts below are exact.
fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 4096,
        max_concurrent: 2000,
    }
}

/// The lines the sensor has finished writing. These tests read the log while the sensor is
/// still appending to it, and a read can land part-way through a line: whatever follows the last
/// newline is not a line yet, and is left for the next read.
fn events(log: &Path) -> Vec<SensorEvent> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let written = text.rfind('\n').map_or("", |end| &text[..=end]);
    written
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn is_summary(event: &SensorEvent) -> bool {
    event.metadata["rate_limited"] == true
}

fn suppressed(event: &SensorEvent) -> u64 {
    event.metadata["suppressed_count"].as_u64().unwrap()
}

/// Every datagram sent is in the log, as itself or inside a summary. Waits for that, and
/// returns the events of their own and the summaries.
async fn settle(log: &Path, sent: u64) -> (Vec<SensorEvent>, Vec<SensorEvent>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (summaries, own): (Vec<_>, Vec<_>) = events(log).into_iter().partition(is_summary);
        let accounted = own.len() as u64 + summaries.iter().map(suppressed).sum::<u64>();
        assert!(
            accounted <= sent,
            "{accounted} datagrams accounted for, only {sent} sent"
        );
        if accounted == sent {
            return (own, summaries);
        }
        assert!(
            Instant::now() < deadline,
            "{accounted} of {sent} datagrams accounted for: {} events, {} summaries",
            own.len(),
            summaries.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Lets the listener take what was just sent before the next datagram, so nothing queues past
/// the socket buffer or the listener's concurrency caps.
async fn pace(sent: usize) {
    tokio::task::yield_now().await;
    if sent.is_multiple_of(10) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// The most summaries one source network can have had in `elapsed`. A summary is written no
/// sooner than a whole window after its first datagram, and the network's next one starts after
/// that, so any stretch one window long holds the start of at most one.
///
/// `elapsed` has to run from before the first datagram was sent until after the last one was
/// counted. The listener counts a datagram some time after the sender sent it, so a time taken
/// when the sending stopped is too short whenever the two fall either side of a window's end.
fn windows(elapsed: Duration) -> usize {
    (elapsed.as_millis() / WINDOW.as_millis()) as usize + 1
}

#[tokio::test]
async fn a_flood_from_one_source_writes_its_burst_and_a_summary_not_a_line_per_datagram() {
    const SENT: usize = 300;
    const BURST: usize = 5;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = sensor_catchall::start_test_udp_listener_with_budget(
        any,
        bounds(),
        log.clone(),
        budget(rate(1, BURST as u32), rate(1000, 1000)),
    )
    .await
    .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let started = Instant::now();
    for i in 1..=SENT {
        client.send_to(b"flood-payload", addr).await.unwrap();
        pace(i).await;
    }
    let (own, summaries) = settle(&log, SENT as u64).await;
    let elapsed = started.elapsed();

    // One token a second on top of the burst, until the last datagram was counted.
    let allowed = BURST + elapsed.as_secs() as usize + 1;
    assert!(
        (BURST..=allowed).contains(&own.len()),
        "{} events of their own from {SENT} datagrams in {elapsed:?}; the budget allows {BURST} \
         to {allowed}",
        own.len()
    );
    assert!(
        (1..=windows(elapsed)).contains(&summaries.len()),
        "{} summaries for one source network over {elapsed:?}",
        summaries.len()
    );
    for event in &own {
        assert_eq!(event.metadata["payload_hex"], "666c6f6f642d7061796c6f6164");
        assert_eq!(event.metadata["local_port"], addr.port());
    }
    for summary in &summaries {
        assert_eq!(summary.sensor, "catchall");
        assert_eq!(summary.signal_type, SIGNAL_CATCHALL_PROBE);
        assert_eq!(summary.protocol, PROTO_UDP);
        assert!(!summary.authenticated);
        assert_eq!(summary.source_ip, client.local_addr().unwrap().ip());
        assert_eq!(summary.metadata["source_prefix"], "127.0.0.0/24");
        assert_eq!(summary.metadata["per_source_limited"], suppressed(summary));
        assert_eq!(summary.metadata["global_limited"], 0);
        assert_eq!(
            summary.metadata["suppressed_bytes"],
            suppressed(summary) * 13
        );
        assert_eq!(
            summary.metadata["samples"][0],
            format!("port {} len 13 hex 666c6f6f642d7061796c6f6164", addr.port()),
            "a summary spans ports, so each sample names its own"
        );
        assert!(summary.metadata.get("payload_hex").is_none());
        assert!(summary.metadata.get("local_port").is_none());
        assert_eq!(sensor_wire::origin::check("catchall", summary), Ok(()));
    }
    handle.abort();
}

#[tokio::test]
async fn a_flood_under_many_source_networks_stays_within_the_global_budget_and_summary_table() {
    const NETWORKS: usize = 40;
    const ROUNDS: usize = 3;
    const GLOBAL_BURST: usize = 10;
    const GLOBAL_RATE: usize = 2;
    const TABLE: usize = 4;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // Every network has room of its own; only the total is short.
    let mut config = budget(
        rate(100, 100),
        rate(GLOBAL_RATE as u32, GLOBAL_BURST as u32),
    );
    config.summary_capacity = NonZeroUsize::new(TABLE).unwrap();
    let (addr, handle) =
        sensor_catchall::start_test_udp_listener_with_budget(any, bounds(), log.clone(), config)
            .await
            .unwrap();

    // Loopback is a /8, so each 127.0.N.1 is a real local address in its own /24: the same
    // datagrams a spoofer would send, without having to forge anything.
    let mut clients = Vec::new();
    for n in 1..=NETWORKS {
        clients.push(UdpSocket::bind(format!("127.0.{n}.1:0")).await.unwrap());
    }
    let started = Instant::now();
    let mut sent = 0;
    for _ in 0..ROUNDS {
        for client in &clients {
            client.send_to(b"x", addr).await.unwrap();
            sent += 1;
            pace(sent).await;
        }
    }
    let (own, summaries) = settle(&log, sent as u64).await;
    let elapsed = started.elapsed();

    let allowed = GLOBAL_BURST + GLOBAL_RATE * (elapsed.as_secs() as usize + 1);
    assert!(
        (GLOBAL_BURST..=allowed).contains(&own.len()),
        "{} events of their own from {sent} datagrams under {NETWORKS} networks in {elapsed:?}; \
         the global budget allows {GLOBAL_BURST} to {allowed}",
        own.len()
    );
    // The table and the overflow bound how many summaries are open at once, and each stays open
    // a whole window, so that many is also the most that can start in one.
    assert!(
        summaries.len() <= (TABLE + 1) * windows(elapsed),
        "{} summaries over {elapsed:?}; the table holds {TABLE} networks and one overflow per \
         window",
        summaries.len()
    );
    let overflow: Vec<_> = summaries
        .iter()
        .filter(|s| s.metadata["source_prefix"] == "overflow")
        .collect();
    assert!(
        !overflow.is_empty(),
        "{NETWORKS} networks cannot fit a table of {TABLE}; the rest share an overflow summary"
    );
    assert!(
        overflow
            .iter()
            .any(|s| s.metadata["distinct_sources"].as_u64().unwrap() > 1),
        "an overflow summary counts the addresses it folded together"
    );
    for summary in &summaries {
        assert_eq!(summary.metadata["global_limited"], suppressed(summary));
        assert_eq!(summary.metadata["per_source_limited"], 0);
        assert_eq!(sensor_wire::origin::check("catchall", summary), Ok(()));
    }
    handle.abort();
}

#[tokio::test]
async fn the_shipped_budget_records_a_sweep_of_a_dozen_datagrams_one_by_one() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = sensor_catchall::start_test_udp_listener(any, bounds(), log.clone())
        .await
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 1..=12 {
        client.send_to(b"probe", addr).await.unwrap();
        pace(i).await;
    }
    let (own, summaries) = settle(&log, 12).await;
    assert_eq!(
        (own.len(), summaries.len()),
        (12, 0),
        "an ordinary scanner is far inside the default burst"
    );
    handle.abort();
}
