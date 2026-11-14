//! The summaries the sensors write, through intake, into the ledger.
//!
//! A flood, a repeated command and a UDP burst are each folded by the sensor into one summary
//! line (`sensor_framework::source_summary_event`, `command_summary_event`,
//! `rate_limited_event`, and the catch-all's `sensor_catchall::flood::summary_event`). Those
//! lines are how a flood's volume reaches scoring. Each end has its
//! own tests against hand-written lines, which is how a validation rule that refused every one of
//! them (their `window_secs` is a float) passed the whole suite. So this drives the builders'
//! real output through `IntakeRunner` under the names the shipped units give the logs and checks
//! three things: the line is ingested, what it stands for is counted, and the ledger chain still
//! verifies with the line in it.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use core_scoring::{ChainStatus, read_score, verify_chain};
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use sensor_framework::command_flood::COMMAND_SUMMARY_WINDOW;
use sensor_framework::rate_limit::DEFAULT_SUMMARY_WINDOW;
use sensor_framework::source_flood::SOURCE_EVENT_WINDOW;
use sensor_framework::{
    CommandSummary, FloodSummary, SourceKey, SourceSummary, SummaryScope, command_summary_event,
    rate_limited_event, source_summary_event,
};
use sensor_wire::SensorEvent;
use sqlx::PgPool;
use tokio::time::Instant;

const FLOODER: &str = "203.0.113.90";
const SHELL: &str = "203.0.113.91";
const RESOLVER_ABUSER: &str = "203.0.113.92";
const DATAGRAM_FLOODER: &str = "203.0.113.93";

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

/// Writes `events` as the sensor does, one JSON object per line, and runs one intake batch over
/// the file under `label`. Returns `(ingested, rejected, errors)`.
async fn ingest(pool: &PgPool, label: &str, events: &[SensorEvent]) -> (usize, usize, usize) {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let body: String = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap() + "\n")
        .collect();
    std::fs::write(&log, body).unwrap();
    let mut runner = IntakeRunner::new(
        LogTailer::new(log, dir.path().join("cursors")),
        pool.clone(),
        label.into(),
        Arc::new(HashSet::new()),
        Duration::from_secs(600),
    );
    let result = runner.run_batch().await;
    (
        result.ingested as usize,
        result.rejected as usize,
        result.errors as usize,
    )
}

async fn stored_metadata(pool: &PgPool, ip: &str) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT metadata FROM event WHERE source_ip = $1::inet ORDER BY id DESC LIMIT 1",
    )
    .bind(ip)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn the_summaries_the_sensors_write_are_ingested_counted_and_leave_the_chain_intact(
    pool: PgPool,
) {
    migrate(&pool).await;
    let now = Instant::now();
    let now_utc = chrono::Utc::now();

    // A VNC connection flood, as sensor-cred folds it: 1,500 connections in one ten-minute window.
    let flood = source_summary_event(
        &SourceSummary {
            scope: SummaryScope::Address(SourceKey::V4([203, 0, 113])),
            source: FLOODER.parse().unwrap(),
            sensor: "vnc".into(),
            wan_ip: None,
            connections: 1500,
            attempts: 0,
            client_versions: vec!["RFB 003.008".into()],
            client_versions_capped: false,
            usernames: Vec::new(),
            usernames_capped: false,
            first_seen: now - Duration::from_secs(590),
            last_seen: now - Duration::from_secs(1),
            sessions: 32,
            sessions_capped: true,
        },
        SOURCE_EVENT_WINDOW,
        now,
        now_utc,
    );
    assert!(
        flood.metadata["window_secs"].is_f64(),
        "this test exists because the window is written as a float: {}",
        flood.metadata["window_secs"]
    );
    assert_eq!(
        ingest(&pool, "cred-vnc", std::slice::from_ref(&flood)).await,
        (1, 0, 0)
    );
    let score = read_score(&pool, FLOODER.parse::<IpAddr>().unwrap())
        .await
        .unwrap()
        .expect("the flooding address has a score row");
    assert_eq!(
        score.established_event_count, 1500,
        "the summary counts for the connections it stands for"
    );
    assert_eq!(
        serde_json::to_string(&stored_metadata(&pool, FLOODER).await).unwrap(),
        serde_json::to_string(&flood.metadata).unwrap(),
        "the ledger holds the summary as the sensor wrote it"
    );

    // A shell's repeated commands, as sensor-ssh and sensor-telnet fold them.
    let commands = command_summary_event(
        &CommandSummary {
            key: Some(SourceKey::V4([203, 0, 113])),
            first_source: SHELL.parse().unwrap(),
            sensor: "ssh".into(),
            wan_ip: None,
            authenticated: true,
            count: 420,
            distinct_commands: 3,
            distinct_commands_capped: false,
            samples: vec!["echo -ne '\\x7f\\x45' >> .d".into()],
            first_seen: now - Duration::from_secs(59),
            last_seen: now - Duration::from_secs(1),
            sessions: 2,
            sessions_capped: false,
            assembled_file: Some(".d".into()),
            max_chunk_index: Some(419),
        },
        COMMAND_SUMMARY_WINDOW,
        now,
        now_utc,
    );
    assert_eq!(
        ingest(&pool, "ssh", std::slice::from_ref(&commands)).await,
        (1, 0, 0)
    );
    assert_eq!(
        serde_json::to_string(&stored_metadata(&pool, SHELL).await).unwrap(),
        serde_json::to_string(&commands.metadata).unwrap()
    );

    // A UDP burst the DNS sensor did not answer, folded per network.
    let burst = rate_limited_event(
        "dns",
        "dns",
        &FloodSummary {
            key: Some(SourceKey::V4([203, 0, 113])),
            first_source: RESOLVER_ABUSER.parse().unwrap(),
            count: 500,
            bytes: 14_500,
            source_limited: 490,
            global_limited: 10,
            first_seen: now - Duration::from_secs(10),
            last_seen: now - Duration::from_millis(250),
            samples: vec!["ANY example.com.".into()],
            distinct_sources: 1,
            distinct_sources_capped: false,
        },
        None,
        DEFAULT_SUMMARY_WINDOW,
        now,
        now_utc,
    );
    assert_eq!(
        ingest(&pool, "dns", std::slice::from_ref(&burst)).await,
        (1, 0, 0)
    );
    assert_eq!(
        serde_json::to_string(&stored_metadata(&pool, RESOLVER_ABUSER).await).unwrap(),
        serde_json::to_string(&burst.metadata).unwrap()
    );

    // A UDP flood at the catch-all, as its budget folds it. Not built by hand: the budget
    // refuses real datagrams and the sensor's own emitter writes the line that is ingested.
    let catchall_line = {
        use sensor_catchall::flood::{UdpBudget, UdpFlood, budget_config};
        use sensor_framework::{EventEmitter, Rate, WanResolver};
        let one = std::num::NonZeroU32::MIN;
        let budget = budget_config(Rate::new(one, one), Rate::new(one, one));
        let flood = UdpFlood::new(
            Arc::new(UdpBudget::new(budget)),
            "192.0.2.1".parse().unwrap(),
        );
        let peer = format!("{DATAGRAM_FLOODER}:4000").parse().unwrap();
        assert!(
            flood.admit(peer, Some(1900), b"M-SEARCH"),
            "the burst of one"
        );
        for _ in 0..999 {
            assert!(!flood.admit(peer, Some(1900), b"M-SEARCH"));
        }
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        flood
            .flush(
                &WanResolver::new(Default::default()),
                &EventEmitter::new(log.clone()),
            )
            .await;
        let written = std::fs::read_to_string(&log).unwrap();
        let mut lines = written.lines();
        let line: SensorEvent = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(lines.next(), None, "one network, one summary");
        line
    };
    assert_eq!(catchall_line.metadata["suppressed_count"], 999);
    assert_eq!(
        ingest(&pool, "catchall", std::slice::from_ref(&catchall_line)).await,
        (1, 0, 0)
    );
    let score = read_score(&pool, DATAGRAM_FLOODER.parse::<IpAddr>().unwrap())
        .await
        .unwrap()
        .expect("the address the datagrams named has a score row");
    assert_eq!(
        (score.event_count, score.established_event_count),
        (1, 0),
        "a UDP summary is one sighting, not the 999 datagrams it stands for, and proves no source"
    );
    assert_eq!(
        serde_json::to_string(&stored_metadata(&pool, DATAGRAM_FLOODER).await).unwrap(),
        serde_json::to_string(&catchall_line.metadata).unwrap()
    );

    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}
