//! The runner's batching end to end: file, tailer, adaptive batch size, one transaction per batch.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use core_scoring::{ChainStatus, verify_chain};
use intake::runner::{IntakeRunner, MAX_BATCH_BYTES, MIN_BATCH_LINES};
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

const PROBE_GRACE: Duration = Duration::from_secs(600);

fn line(n: usize, signal: &str, metadata: serde_json::Value) -> String {
    let event = SensorEvent {
        v: WIRE_VERSION,
        source_ip: format!("192.0.2.{}", 10 + n % 3).parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "telnet".into(),
        signal_type: signal.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: "2026-09-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            + chrono::Duration::seconds(n as i64 * 7),
        metadata,
        sample: None,
        session_id: None,
        occurrence_id: None,
    };
    serde_json::to_string(&event).unwrap()
}

fn runner(pool: &PgPool, dir: &std::path::Path) -> IntakeRunner {
    IntakeRunner::new(
        LogTailer::new(dir.join("events.jsonl"), dir.join("cursors")),
        pool.clone(),
        "telnet".into(),
        Arc::new(HashSet::<IpAddr>::new()),
        PROBE_GRACE,
    )
}

fn write_lines(dir: &std::path::Path, lines: &[String]) {
    let mut file = std::fs::File::create(dir.join("events.jsonl")).unwrap();
    for l in lines {
        writeln!(file, "{l}").unwrap();
    }
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
}

async fn ledger_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// 451 lines (scored, telemetry and one junk line) drain in batches of 100, 200 and the 151 left,
/// each one transaction: nothing is lost or duplicated, the junk line is rejected once, and the
/// chain verifies.
#[sqlx::test(migrations = false)]
async fn a_backlog_drains_in_growing_batches_and_the_chain_verifies(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let mut lines = Vec::new();
    for n in 0..450 {
        let signal = match n % 5 {
            0 => SIGNAL_HONEYPOT_SESSION_END,
            1 | 2 => SIGNAL_HONEYPOT_COMMAND_EXEC,
            3 => SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            _ => SIGNAL_HONEYPOT_CONNECTION,
        };
        lines.push(line(n, signal, serde_json::json!({ "n": n })));
        if n == 9 {
            lines.push("{ not json".into());
        }
    }
    write_lines(dir.path(), &lines);

    let mut runner = runner(&pool, dir.path());
    let mut outcomes = Vec::new();
    loop {
        let r = runner.run_batch().await;
        assert_eq!(r.errors, 0);
        if r.ingested == 0 && r.rejected == 0 {
            break;
        }
        outcomes.push((r.ingested, r.rejected));
    }
    assert_eq!(
        outcomes,
        [(99, 1), (200, 0), (151, 0)],
        "first batch reads {MIN_BATCH_LINES} lines, then 200, then what is left"
    );
    assert_eq!(ledger_rows(&pool).await, 450);
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}

/// A line the database refuses (a NUL in metadata, which `jsonb` cannot hold) stops the batch at
/// that line. The lines before it are committed once and the tailer moves past exactly them: the
/// next poll starts AT the refused line, reports nothing ingested (so the loops sleep instead of
/// spinning), and never appends the committed prefix again. Nothing is skipped: once the line is
/// fixed, everything behind it is ingested.
#[sqlx::test(migrations = false)]
async fn a_line_the_database_refuses_stops_the_batch_and_the_prefix_is_not_replayed(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let build = |poison: bool| -> Vec<String> {
        let mut lines: Vec<String> = (0..20)
            .map(|n| {
                if poison && n == 12 {
                    line(
                        n,
                        SIGNAL_HONEYPOT_COMMAND_EXEC,
                        serde_json::json!({ "command": "echo \u{0}" }),
                    )
                } else {
                    line(
                        n,
                        SIGNAL_HONEYPOT_COMMAND_EXEC,
                        serde_json::json!({ "n": n }),
                    )
                }
            })
            .collect();
        lines.insert(5, "{ not json".into());
        lines.push("{ not json".into());
        lines
    };
    write_lines(dir.path(), &build(true));

    let mut runner = runner(&pool, dir.path());
    let first = runner.run_batch().await;
    assert_eq!((first.ingested, first.errors, first.rejected), (12, 1, 1));
    assert_eq!(
        ledger_rows(&pool).await,
        12,
        "the lines before the bad one are durable"
    );

    for poll in 2..=3 {
        let again = runner.run_batch().await;
        assert_eq!(
            (again.ingested, again.rejected, again.errors),
            (0, 0, 1),
            "poll {poll}: nothing is re-appended or re-counted, so the loop sleeps"
        );
        assert_eq!(ledger_rows(&pool).await, 12, "poll {poll}: prefix replayed");
        assert_eq!(
            runner.wedged().is_some(),
            poll == 3,
            "reported on the third consecutive refusal of the same line"
        );
    }
    let why = runner.wedged().unwrap();
    assert!(
        why.contains("22P05") && why.contains("telnet"),
        "the report names the sensor and the SQLSTATE: {why}"
    );
    let counted: i32 = sqlx::query_scalar("SELECT event_count FROM ip_score ORDER BY source_ip")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(counted <= 4, "event counters inflated by replay: {counted}");

    // The operator fixes the line; everything behind it goes in and the report clears.
    write_lines(dir.path(), &build(false));
    let fixed = runner.run_batch().await;
    assert_eq!((fixed.ingested, fixed.errors, fixed.rejected), (8, 0, 1));
    assert_eq!(ledger_rows(&pool).await, 20);
    assert!(runner.wedged().is_none());
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}

/// After a batch has grown to its largest, a burst of near-megabyte lines must not be read a
/// thousand at a time: a batch stops at the byte budget, so memory is bounded by bytes, and every
/// line still gets ingested across batches.
#[sqlx::test(migrations = false)]
async fn a_burst_of_large_lines_after_growth_stays_inside_the_byte_budget(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let mut lines: Vec<String> = (0..450)
        .map(|n| {
            line(
                n,
                SIGNAL_HONEYPOT_COMMAND_EXEC,
                serde_json::json!({ "n": n }),
            )
        })
        .collect();
    let big = "x".repeat(900 * 1024);
    for n in 0..30 {
        lines.push(line(
            1000 + n,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            serde_json::json!({ "blob": big }),
        ));
    }
    write_lines(dir.path(), &lines);

    let mut runner = runner(&pool, dir.path());
    // 100, then 200, then the remaining 150 small lines and the large ones that fit the budget.
    let (mut sizes, mut total) = (Vec::new(), 0);
    loop {
        let r = runner.run_batch().await;
        assert_eq!(r.errors, 0);
        if r.ingested == 0 {
            break;
        }
        sizes.push(r.ingested);
        total += r.ingested;
    }
    assert_eq!(total, 480);
    let budget_lines = MAX_BATCH_BYTES / (900 * 1024);
    let large_batches: Vec<_> = sizes.iter().skip(2).collect();
    assert!(
        large_batches.iter().all(|&&n| n <= 150 + budget_lines + 1),
        "a batch of megabyte lines exceeded the byte budget: {sizes:?}"
    );
    assert!(
        sizes.len() >= 5,
        "30 lines of 900 KiB cannot fit fewer than four 8 MiB batches: {sizes:?}"
    );
}
