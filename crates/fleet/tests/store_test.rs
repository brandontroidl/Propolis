//! `listener_probe` behaviour against a real database.
//!
//! Every test runs against its own ephemeral database (`#[sqlx::test(migrations = false)]` plus
//! this crate's own migrator), matching `review/tests/queue_test.rs`'s pattern. The assertions
//! here are about the two writers not clobbering each other and about the table refusing to make a
//! stale row look fresh - the fail-closed half of `fleet::health`, seen from the storage side.

use chrono::{DateTime, TimeZone, Utc};
use fleet::health::{Level, reach_level};
use fleet::inventory::{Listener, Proto};
use fleet::store::{ProbeOutcome, ProbeRecord, confirm_sensor, read_all, upsert_probe};
use sqlx::PgPool;

/// Fixed, microsecond-clean timestamps: `Utc::now()` carries nanoseconds that Postgres truncates,
/// so a round-trip equality assertion on a `now()`-derived value would be comparing two different
/// numbers for reasons that have nothing to do with the code under test.
fn at(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 9, 12, minute, 0).unwrap()
}

fn ssh() -> Listener {
    Listener {
        collector_id: "local".into(),
        sensor: "ssh".into(),
        protocol: Proto::Tcp,
        port: 22,
    }
}

fn record(listener: Listener, attempted_at: DateTime<Utc>, outcome: ProbeOutcome) -> ProbeRecord {
    ProbeRecord {
        listener,
        target: "198.51.100.7:22".into(),
        attempted_at,
        outcome,
        detail: None,
        latency_ms: Some(7),
    }
}

async fn migrate(pool: &PgPool) {
    fleet::migrator().run(pool).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn upsert_replaces_the_row_for_the_same_listener_key(pool: PgPool) {
    migrate(&pool).await;

    upsert_probe(&pool, &record(ssh(), at(0), ProbeOutcome::Reachable))
        .await
        .unwrap();
    upsert_probe(&pool, &record(ssh(), at(5), ProbeOutcome::Refused))
        .await
        .unwrap();

    let rows = read_all(&pool).await.unwrap();
    assert_eq!(rows.len(), 1, "the listener key must not accumulate rows");
    assert_eq!(rows[0].outcome, ProbeOutcome::Refused);
    assert_eq!(rows[0].attempted_at, at(5));

    // A different protocol on the same port is a different listener, not the same row.
    let mut udp = ssh();
    udp.protocol = Proto::Udp;
    upsert_probe(&pool, &record(udp, at(5), ProbeOutcome::NotProbeable))
        .await
        .unwrap();
    assert_eq!(read_all(&pool).await.unwrap().len(), 2);
}

#[sqlx::test(migrations = false)]
async fn upsert_does_not_clear_a_previous_confirmation(pool: PgPool) {
    migrate(&pool).await;

    upsert_probe(&pool, &record(ssh(), at(0), ProbeOutcome::Reachable))
        .await
        .unwrap();
    confirm_sensor(&pool, "ssh", at(1), std::time::Duration::from_secs(600))
        .await
        .unwrap();
    upsert_probe(&pool, &record(ssh(), at(5), ProbeOutcome::Reachable))
        .await
        .unwrap();

    let rows = read_all(&pool).await.unwrap();
    assert_eq!(
        rows[0].confirmed_at,
        Some(at(1)),
        "a fresh attempt must leave the previous confirmation visible with its own timestamp"
    );
    assert_eq!(rows[0].attempted_at, at(5));
}

#[sqlx::test(migrations = false)]
async fn confirm_sensor_stamps_only_rows_probed_inside_the_grace_window(pool: PgPool) {
    migrate(&pool).await;

    let mut telnet = ssh();
    telnet.sensor = "telnet".into();
    telnet.port = 23;
    upsert_probe(&pool, &record(ssh(), at(9), ProbeOutcome::Reachable))
        .await
        .unwrap();
    upsert_probe(
        &pool,
        &record(telnet.clone(), at(9), ProbeOutcome::Reachable),
    )
    .await
    .unwrap();

    let stamped = confirm_sensor(&pool, "ssh", at(10), std::time::Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!(stamped, 1, "only the named sensor's row may be confirmed");

    let rows = read_all(&pool).await.unwrap();
    let ssh_row = rows.iter().find(|r| r.listener.sensor == "ssh").unwrap();
    let telnet_row = rows.iter().find(|r| r.listener.sensor == "telnet").unwrap();
    assert_eq!(ssh_row.confirmed_at, Some(at(10)));
    assert_eq!(
        telnet_row.confirmed_at, None,
        "one sensor's line must never confirm another sensor's listener"
    );
}

#[sqlx::test(migrations = false)]
async fn confirm_sensor_leaves_a_stale_row_unconfirmed(pool: PgPool) {
    migrate(&pool).await;

    // Probed at 12:00, seen at 12:30, grace 10 minutes: the sighting cannot belong to this
    // attempt, so retro-confirming it would paint a dead path green.
    upsert_probe(&pool, &record(ssh(), at(0), ProbeOutcome::Reachable))
        .await
        .unwrap();
    let stamped = confirm_sensor(&pool, "ssh", at(30), std::time::Duration::from_secs(600))
        .await
        .unwrap();

    assert_eq!(stamped, 0);
    assert_eq!(read_all(&pool).await.unwrap()[0].confirmed_at, None);
}

#[sqlx::test(migrations = false)]
async fn a_skipped_sweep_does_not_advance_attempted_at(pool: PgPool) {
    migrate(&pool).await;

    upsert_probe(&pool, &record(ssh(), at(0), ProbeOutcome::Reachable))
        .await
        .unwrap();
    confirm_sensor(&pool, "ssh", at(0), std::time::Duration::from_secs(600))
        .await
        .unwrap();

    // No second sweep. Nothing in the store may age the row forward on its own, so half an hour
    // later the same row is what `health` reads, and it reads it as an alarm rather than as the
    // reachable result it still literally contains.
    let rows = read_all(&pool).await.unwrap();
    assert_eq!(rows[0].attempted_at, at(0));
    assert_eq!(rows[0].outcome, ProbeOutcome::Reachable);
    assert_eq!(
        reach_level(Some(&rows[0]), at(30), std::time::Duration::from_secs(300)),
        Level::Alarm,
        "a sweep that never ran must age into an alarm, not stay green"
    );
}
