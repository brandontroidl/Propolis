// These tests require a running PostgreSQL instance (propolis-pg container) and share ONE
// database across the whole test binary (no per-test isolated database, unlike core-scoring's
// `#[sqlx::test]`). Every test therefore uses unique source IPs to avoid cross-test interference,
// and the suite must run with `--test-threads=1` since `append_event` serializes via a Postgres
// advisory lock that is scoped to a transaction, not a test.

use core_scoring::{ChainStatus, read_score, verify_chain};
use intake::runner::IntakeRunner;
use intake::tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
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

#[tokio::test]
async fn ingest_single_event_appears_in_ledger() {
    let pool = setup_pool().await;
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
    };
    write_event_line(&log_path, &event);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(tailer, pool.clone(), "test-ssh".into());
    let result = runner.run_batch().await;
    assert_eq!(result.ingested, 1);
    assert_eq!(result.rejected, 0);

    let score = read_score(&pool, "203.0.113.7".parse().unwrap())
        .await
        .unwrap();
    assert!(score.is_some());
    let score = score.unwrap();
    assert!(score.has_confirmed_real);
    // NOT eligible: core_scoring::scoring::eligibility::eligible requires event_count >= 2 AND
    // distinct_categories >= 2 (the anti-spoof two-corroborating-signals gate), and this batch
    // ingested exactly one event in one category. Asserting `eligible` here would mean either
    // this test or the gate is wrong; the gate is deliberate and covered by its own tests
    // (core-scoring's `eligibility_requires_all_three_legs` and the end-to-end scenario (B) in
    // core-scoring/tests/end_to_end.rs), so this test asserts the real, intended behavior instead.
    assert!(!score.eligible);
}

#[tokio::test]
async fn unknown_signal_type_rejected_cursor_advances() {
    let pool = setup_pool().await;
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
    };
    write_event_line(&log_path, &bad);
    write_event_line(&log_path, &good);

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(tailer, pool.clone(), "test".into());
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

#[tokio::test]
async fn hash_chain_intact_after_ingestion() {
    let pool = setup_pool().await;
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
        };
        write_event_line(&log_path, &event);
    }

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(tailer, pool.clone(), "test".into());
    runner.run_batch().await;

    let status = verify_chain(&pool).await.unwrap();
    assert!(matches!(status, ChainStatus::Intact));
}

#[tokio::test]
async fn rotation_survival_no_events_lost() {
    let pool = setup_pool().await;
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
        };
        write_event_line(&log_path, &event);
    }

    // Ingest first batch.
    let mut runner = IntakeRunner::new(
        LogTailer::new(log_path.clone(), cursor_dir.clone()),
        pool.clone(),
        "test".into(),
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
        };
        write_event_line(&log_path, &event);
    }

    // Ingest second batch (new tailer simulating restart awareness).
    let mut runner2 = IntakeRunner::new(
        LogTailer::new(log_path, cursor_dir),
        pool.clone(),
        "test".into(),
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
