//! Real-Postgres tests for the transactional append path and read projection.
//!
//! Run with `DATABASE_URL` exported (see `.env`):
//!   set -a; . ./.env; set +a; cargo test -p core-scoring --test repository
//! `#[sqlx::test]` provisions a fresh, isolated database per test and applies
//! the migrations, so the tests never share state.

use core_scoring::domain::enums::{Protocol, SignalType};
use core_scoring::domain::types::EventInput;
use core_scoring::repository::{append_event, read_score, RepoError};

use rust_decimal_macros::dec;
use sqlx::PgPool;

/// A tcp + authenticated + honeypot event: latches `has_confirmed_real`.
fn auth_honeypot_input(ip: &str, ts: &str) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        "sensor-a".into(),
        SignalType::HoneypotCommandExec,
        Protocol::Tcp,
        true,
        ts.parse().unwrap(),
        serde_json::json!({}),
    )
}

/// A honeypot event whose weight is selected by `weight` (via the signal table,
/// so weight/confidence/category stay in sync). Only the weights used by the
/// tests are mapped.
fn honeypot_input(ip: &str, ts: &str, weight: u32) -> EventInput {
    let signal = match weight {
        40 => SignalType::HoneypotConnection,
        50 => SignalType::HoneypotLoginAttempt,
        60 => SignalType::HoneypotCommandExec,
        70 => SignalType::HoneypotFileDownload,
        80 => SignalType::HoneypotMalwareUpload,
        other => panic!("no honeypot signal with weight {other}"),
    };
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        "sensor-a".into(),
        signal,
        Protocol::Tcp,
        true,
        ts.parse().unwrap(),
        serde_json::json!({}),
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn append_updates_projection_atomically(pool: PgPool) -> Result<(), RepoError> {
    let s = append_event(&pool, auth_honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z")).await?;
    assert_eq!(s.event_count, 1);
    assert!(s.has_confirmed_real);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_event_is_rejected_without_writing(pool: PgPool) {
    let mut bad = auth_honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z");
    bad.confidence = dec!(9); // out of range
    assert!(matches!(
        append_event(&pool, bad).await,
        Err(RepoError::Invalid(_))
    ));
    // Nothing written on the error path: validation happens before the tx opens.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn double_decay_guard_across_one_half_life(pool: PgPool) -> Result<(), RepoError> {
    // event A at t0; READ at t0+6h (projects raw to ~half); event B at t0+6h.
    // The write path for B must read the UN-projected stored raw, not the
    // read-projected one.
    let _a = append_event(&pool, honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z", 40)).await?;
    // A pure read in between must NOT persist the projected value.
    let _ = read_score(&pool, "203.0.113.7".parse().unwrap()).await?;
    let b = append_event(&pool, honeypot_input("203.0.113.7", "2026-07-17T06:00:00Z", 40)).await?;
    // stored raw at B = decay(40, 6h) + 40 = 20 + 40 = 60 (NOT decay(decay(40)) + 40).
    assert!((b.raw_score - dec!(60)).abs() < dec!(0.01));
    Ok(())
}
