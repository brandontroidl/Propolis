//! The prober against real sockets.
//!
//! No mocks: the whole value of this probe is that it exercises the same path an attacker's packet
//! takes, so a test that stubbed the connect would assert nothing about the thing being built. Each
//! case binds (or deliberately does not bind) a real listener on loopback, or dials an address in
//! the documentation range that nothing routes to.
//!
//! The three outcomes tested here are the three the operator has to tell apart: a socket that
//! answers, a path that works with nothing behind it (`refused`), and a packet that vanished
//! (`timeout`). Collapsing any two of them would throw away the diagnosis.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet::inventory::{Listener, Proto};
use fleet::probe::{ProbeConfig, probe_once, run_probe_loop};
use fleet::store::{ProbeOutcome, read_all};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn listener(sensor: &str, protocol: Proto, port: u16) -> Listener {
    Listener {
        collector_id: "local".into(),
        sensor: sensor.into(),
        protocol,
        port,
    }
}

const TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn a_bound_listener_probes_reachable_with_a_latency() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bound.local_addr().unwrap().port();

    let record = probe_once(
        &listener("ssh", Proto::Tcp, port),
        Some(&format!("127.0.0.1:{port}")),
        TIMEOUT,
    )
    .await;

    assert_eq!(record.outcome, ProbeOutcome::Reachable);
    assert!(
        record.latency_ms.is_some(),
        "a completed connect must record how long it took: {record:?}"
    );
    assert_eq!(record.target, format!("127.0.0.1:{port}"));
    // Loopback is the hairpin case by definition, and the record must say so rather than let the
    // pane read a same-host connect as evidence that anything outside can reach this listener.
    assert!(
        record
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("hairpin")),
        "a connect that never left the host must be labelled a hairpin: {record:?}"
    );
}

#[tokio::test]
async fn a_closed_port_probes_refused_not_timeout() {
    // Bind to claim a port the kernel is not otherwise handing out, then release it, so the
    // connect lands on a port that is genuinely closed rather than on somebody else's service.
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bound.local_addr().unwrap().port();
    drop(bound);

    let started = Instant::now();
    let record = probe_once(
        &listener("ssh", Proto::Tcp, port),
        Some(&format!("127.0.0.1:{port}")),
        TIMEOUT,
    )
    .await;

    assert_eq!(
        record.outcome,
        ProbeOutcome::Refused,
        "a closed port on a reachable host is refused, not a timeout: {record:?}"
    );
    assert!(
        started.elapsed() < TIMEOUT,
        "a refusal must come back well inside the timeout, or the two states are not being told \
         apart at all"
    );
    assert!(
        record
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("nothing is listening")),
        "the detail is the diagnosis and must name what refused means: {record:?}"
    );
}

/// 192.0.2.1 is RFC 5737 TEST-NET-1: routed nowhere, so the SYN is dropped and nothing answers.
/// This is the firewall/host-down case, which must read as `timeout` and must respect the bound
/// the operator configured rather than hanging on the OS default connect timeout (over two
/// minutes on Linux).
#[tokio::test]
async fn an_unroutable_address_probes_timeout_within_the_configured_timeout() {
    let budget = Duration::from_millis(700);
    let started = Instant::now();
    let record = probe_once(
        &listener("ssh", Proto::Tcp, 22),
        Some("192.0.2.1:22"),
        budget,
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(
        record.outcome,
        ProbeOutcome::Timeout,
        "a dropped packet is a timeout: {record:?}"
    );
    assert!(
        elapsed >= budget,
        "the probe returned before its own deadline, so the deadline is not what ended it"
    );
    assert!(
        elapsed < budget * 4,
        "the configured timeout did not bound the connect (took {elapsed:?} against a {budget:?} \
         budget)"
    );
    assert!(record.latency_ms.is_none());
}

#[tokio::test]
async fn a_listener_with_no_configured_endpoint_probes_not_probeable() {
    let record = probe_once(&listener("ssh", Proto::Tcp, 22), None, TIMEOUT).await;

    assert_eq!(record.outcome, ProbeOutcome::NotProbeable);
    assert_eq!(
        record.detail.as_deref(),
        Some("no endpoint configured for collector"),
        "an unconfigured collector must name the configuration gap, not read as a network fault"
    );
    assert!(record.target.is_empty());
}

/// UDP is the third state the coverage figure depends on: excluded from the proven numerator,
/// included in the denominator. A connect decides nothing about it, and the record has to say that
/// rather than pick a colour.
#[tokio::test]
async fn udp_is_not_probeable_even_when_the_endpoint_is_configured() {
    let record = probe_once(
        &listener("catchall", Proto::Udp, 1024),
        Some("127.0.0.1:1024"),
        TIMEOUT,
    )
    .await;

    assert_eq!(record.outcome, ProbeOutcome::NotProbeable);
    assert_eq!(
        record.detail.as_deref(),
        Some("udp reachability is not provable by connect")
    );
}

#[sqlx::test(migrations = false)]
async fn the_loop_stores_a_row_per_listener_and_stops_promptly_on_cancellation(pool: PgPool) {
    fleet::migrator().run(&pool).await.unwrap();

    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bound.local_addr().unwrap().port();
    let endpoints: BTreeMap<String, String> =
        fleet::parse_endpoints("local=127.0.0.1,edge=127.0.0.1").unwrap();
    let listeners = Arc::new(vec![
        listener("ssh", Proto::Tcp, port),
        listener("catchall", Proto::Udp, 1024),
        // No endpoint for this collector, so the sweep must still write a row for it.
        Listener {
            collector_id: "elsewhere".into(),
            sensor: "telnet".into(),
            protocol: Proto::Tcp,
            port: 23,
        },
    ]);

    let cancel = CancellationToken::new();
    let handle = tokio::spawn(run_probe_loop(
        pool.clone(),
        listeners,
        Arc::new(endpoints),
        ProbeConfig {
            // Long enough that the loop is certainly parked in the sleep when it is cancelled, so
            // a prompt stop can only come from the cancellation and not from the interval elapsing.
            interval: Duration::from_secs(3600),
            timeout: TIMEOUT,
        },
        cancel.clone(),
    ));

    // Wait for the first sweep to land rather than sleeping a fixed amount: a poll predicate that
    // is already true when armed proves nothing, and this one starts false (the table is empty).
    let mut rows = Vec::new();
    for _ in 0..100 {
        rows = read_all(&pool).await.unwrap();
        if rows.len() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rows.len(), 3, "one row per configured listener: {rows:?}");

    let by_sensor = |name: &str| {
        rows.iter()
            .find(|r| r.listener.sensor == name)
            .unwrap_or_else(|| panic!("no row for {name}"))
    };
    assert_eq!(by_sensor("ssh").outcome, ProbeOutcome::Reachable);
    assert_eq!(by_sensor("catchall").outcome, ProbeOutcome::NotProbeable);
    assert_eq!(by_sensor("telnet").outcome, ProbeOutcome::NotProbeable);
    assert!(
        by_sensor("ssh").confirmed_at.is_none(),
        "the prober must never write a confirmation; only intake does"
    );

    let stopping = Instant::now();
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the probe loop must stop on cancellation, not run out its interval")
        .unwrap();
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "cancellation must not wait on the sweep interval"
    );
}
