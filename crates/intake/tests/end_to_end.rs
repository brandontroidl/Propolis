// These tests require a running PostgreSQL instance. Each test owns a fresh database
// (`#[sqlx::test]`), so source IPs, event counts and the hash chain are never shared with another
// test, another run or another crate's suite.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use core_scoring::{ChainStatus, read_score, verify_chain};
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

/// How far back a probe attempt may be and still be the one a sighting belongs to. The daemon
/// passes twice the sweep interval; 600s is that for the default 300s cadence.
const PROBE_GRACE: Duration = Duration::from_secs(600);

/// The shape a node with no reachability probe configured runs in: nothing is filtered.
fn no_probe_sources() -> Arc<HashSet<IpAddr>> {
    Arc::new(HashSet::new())
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
}

fn write_event_line(path: &std::path::Path, event: &SensorEvent) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let line = serde_json::to_string(event).unwrap();
    writeln!(f, "{line}").unwrap();
}

#[sqlx::test(migrations = false)]
async fn ingest_single_event_appears_in_ledger(pool: PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    let event = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({"protocol_label": "ssh", "username": "root"}),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply: None,
    };
    write_event_line(&log_path, &event);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "test-ssh".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    let result = runner.run_batch().await;
    assert_eq!(result.ingested, 1);
    assert_eq!(result.rejected, 0);

    let score = read_score(&pool, "203.0.113.7".parse().unwrap())
        .await
        .unwrap();
    assert!(score.is_some());
    let score = score.unwrap();
    assert!(score.has_confirmed_real);
    // NOT eligible: `core_scoring::scoring::eligibility::eligible` requires event_count >= 2 (the
    // anti-spoof corroboration gate) and this batch ingested exactly one event. The gate is
    // deliberate and covered by its own tests, so this asserts the intended behaviour rather than
    // restating the implementation.
    //
    // This is why the test needs its own database: `event_count` accumulates permanently per
    // source IP, so on a database shared across runs a second run of this same test would push
    // the count to 2 and flip the assertion.
    assert!(!score.eligible);
}

/// A sensor's outcome record has to survive the whole path - written as NDJSON, parsed,
/// converted, routed - and land in the ledger without scoring anything. Intake sends every event
/// to `append_event`, which now REFUSES telemetry, so without the routing this line would be a
/// hard error that stops the batch. Calling the repository function directly would never have
/// caught that.
#[sqlx::test(migrations = false)]
async fn a_telemetry_line_reaches_the_ledger_through_intake_and_scores_nothing(pool: PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    let telemetry = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.44".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_SESSION_END.into(),
        protocol: PROTO_TCP.into(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": "ssh",
            "reason": "max_duration",
            "elapsed_ms": 30_000,
        }),
        sample: None,
        session_id: Some(uuid::Uuid::now_v7()),
        occurrence_id: None,
        reply: None,
    };
    write_event_line(&log_path, &telemetry);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "test-ssh".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    let result = runner.run_batch().await;
    assert_eq!(result.ingested, 1, "the outcome record was ingested");
    assert_eq!(result.rejected, 0);
    assert_eq!(
        result.errors, 0,
        "routing telemetry to the scoring path would fail the batch here"
    );

    // In the ledger, with its session and reason intact.
    let row = sqlx::query(
        "SELECT host(source_ip) AS ip, metadata, session_id IS NOT NULL AS has_session \
         FROM event WHERE signal_type = 'honeypot_session_end'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    use sqlx::Row;
    assert_eq!(row.get::<String, _>("ip"), "203.0.113.44");
    assert!(row.get::<bool, _>("has_session"), "tied to its session");
    let metadata: serde_json::Value = row.get("metadata");
    assert_eq!(metadata["reason"], "max_duration");

    // And no scoring state at all for that address.
    assert!(
        read_score(&pool, "203.0.113.44".parse().unwrap())
            .await
            .unwrap()
            .is_none(),
        "an outcome record must not score the address it describes"
    );
    assert!(matches!(
        verify_chain(&pool).await.unwrap(),
        ChainStatus::Intact
    ));
}

#[sqlx::test(migrations = false)]
async fn unknown_signal_type_rejected_cursor_advances(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    // Write a bad event followed by a good one.
    let bad = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.8".parse().unwrap(),
        wan_ip: None,
        sensor: "test".into(),
        signal_type: "nonexistent_signal".into(),
        protocol: PROTO_TCP.into(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({}),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply: None,
    };
    let good = SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.9".parse().unwrap(),
        wan_ip: None,
        sensor: "catchall".into(),
        signal_type: SIGNAL_CATCHALL_PROBE.into(),
        protocol: PROTO_UDP.into(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({}),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply: None,
    };
    write_event_line(&log_path, &bad);
    write_event_line(&log_path, &good);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "test".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    let result = runner.run_batch().await;
    assert_eq!(result.rejected, 1);
    assert_eq!(result.ingested, 1);

    // Bad event not in ledger.
    let score = read_score(&pool, "203.0.113.8".parse().unwrap())
        .await
        .unwrap();
    assert!(score.is_none());
    // Good event in ledger.
    let score = read_score(&pool, "203.0.113.9".parse().unwrap())
        .await
        .unwrap();
    assert!(score.is_some());
}

/// `verify_chain` is a whole-table assertion: it walks every row in `event` and checks the hash
/// linkage end to end, so it only means something on a database no other test has written to or
/// deleted from. Deleting any row from a hash-chained table severs the chain.
#[sqlx::test(migrations = false)]
async fn hash_chain_intact_after_ingestion(pool: PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    for i in 0..5 {
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("203.0.113.{}", 10 + i).parse().unwrap(),
            wan_ip: None,
            sensor: "catchall".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        };
        write_event_line(&log_path, &event);
    }

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "test".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    runner.run_batch().await;

    let status = verify_chain(&pool).await.unwrap();
    assert!(matches!(status, ChainStatus::Intact));
}

#[sqlx::test(migrations = false)]
async fn rotation_survival_no_events_lost(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursors");

    // Write first batch.
    for i in 0..3 {
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("203.0.113.{}", 20 + i).parse().unwrap(),
            wan_ip: None,
            sensor: "catchall".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        };
        write_event_line(&log_path, &event);
    }

    // Ingest first batch.
    let mut runner = IntakeRunner::new(
        LogTailer::new(log_path.clone(), cursor_dir.clone()),
        pool.clone(),
        "test".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    let r = runner.run_batch().await;
    assert_eq!(r.ingested, 3);
    runner.persist_cursor().unwrap();

    // Simulate copytruncate rotation.
    std::fs::write(&log_path, "").unwrap();

    // Write second batch.
    for i in 0..3 {
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("203.0.113.{}", 30 + i).parse().unwrap(),
            wan_ip: None,
            sensor: "catchall".into(),
            signal_type: SIGNAL_CATCHALL_PROBE.into(),
            protocol: PROTO_TCP.into(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        };
        write_event_line(&log_path, &event);
    }

    // Ingest second batch (new tailer simulating restart awareness).
    let mut runner2 = IntakeRunner::new(
        LogTailer::new(log_path, cursor_dir),
        pool.clone(),
        "test".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    let r2 = runner2.run_batch().await;
    assert_eq!(r2.ingested, 3);

    // All 6 events in ledger.
    for i in 20..23 {
        let ip = format!("203.0.113.{i}").parse().unwrap();
        assert!(
            read_score(&pool, ip).await.unwrap().is_some(),
            "missing IP 203.0.113.{i}"
        );
    }
    for i in 30..33 {
        let ip = format!("203.0.113.{i}").parse().unwrap();
        assert!(
            read_score(&pool, ip).await.unwrap().is_some(),
            "missing IP 203.0.113.{i}"
        );
    }
}

/// The lag inputs the daemon publishes per log: after a full batch the unread bytes are exactly
/// the line left behind, the last ingested `observed_at` is the 100th line's, and the sensor name
/// is the one the events carried rather than the log's label. A drained log reads 0 bytes behind.
#[sqlx::test(migrations = false)]
async fn runner_reports_backlog_last_observed_and_the_sensor_name_its_events_carried(pool: PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let start = chrono::Utc::now() - chrono::Duration::days(11);
    let events: Vec<SensorEvent> = (0..101i64)
        .map(|i| SensorEvent {
            v: WIRE_VERSION,
            source_ip: format!("198.51.100.{}", i + 1).parse().unwrap(),
            wan_ip: Some("203.0.113.4".parse().unwrap()),
            sensor: "vnc".into(),
            signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: start + chrono::Duration::seconds(i),
            metadata: serde_json::json!({"protocol_label": "vnc"}),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        })
        .collect();
    for event in &events {
        write_event_line(&log_path, event);
    }
    let last_line_bytes = serde_json::to_string(&events[100]).unwrap().len() as u64 + 1;

    let tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "cred-vnc".into(),
        no_probe_sources(),
        PROBE_GRACE,
    );
    assert_eq!(
        runner.backlog_bytes(),
        std::fs::metadata(&log_path).unwrap().len()
    );
    assert_eq!(runner.last_ingested_observed_at(), None);
    assert!(runner.reported_sensors().is_empty());

    assert_eq!(runner.run_batch().await.ingested, 100);
    assert_eq!(runner.backlog_bytes(), last_line_bytes);
    assert_eq!(
        runner.last_ingested_observed_at(),
        Some(events[99].observed_at)
    );
    assert_eq!(
        runner.reported_sensors().iter().collect::<Vec<_>>(),
        vec!["vnc"],
        "the event's own sensor name, not the cred-vnc log label"
    );

    assert_eq!(runner.run_batch().await.ingested, 1);
    assert_eq!(runner.backlog_bytes(), 0);
    assert_eq!(
        runner.last_ingested_observed_at(),
        Some(events[100].observed_at)
    );
}
