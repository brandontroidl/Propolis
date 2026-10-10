//! `sensor_stats` behaviour against a real database: the latest line per sensor wins, an older
//! line never moves a row backwards, and one sensor's line never touches another sensor's row.

use chrono::{DateTime, TimeZone, Utc};
use fleet::stats::{SensorStatsRow, read_all, upsert};
use sqlx::PgPool;

fn at(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 9, 12, minute, 0).unwrap()
}

fn row(sensor: &str, minute: u32, dropped: i64) -> SensorStatsRow {
    SensorStatsRow {
        sensor: sensor.into(),
        reported_at: at(minute),
        received_at: at(minute),
        uptime_secs: 60 * i64::from(minute),
        is_final: false,
        dropped,
        spool_refused: 2,
        truncated: 3,
        refused: 4,
        budget_current: 5,
        budget_high_water: 6,
        budget_refused: 7,
    }
}

async fn migrate(pool: &PgPool) {
    fleet::migrator().run(pool).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn a_newer_line_replaces_the_row_and_an_older_one_is_ignored(pool: PgPool) {
    migrate(&pool).await;
    assert!(upsert(&pool, &row("ssh", 5, 10)).await.unwrap());
    assert!(upsert(&pool, &row("ssh", 6, 11)).await.unwrap());
    assert!(
        !upsert(&pool, &row("ssh", 4, 99)).await.unwrap(),
        "an older line must not apply"
    );
    let rows = read_all(&pool).await.unwrap();
    assert_eq!(rows, vec![row("ssh", 6, 11)]);
}

#[sqlx::test(migrations = false)]
async fn each_sensor_has_its_own_row(pool: PgPool) {
    migrate(&pool).await;
    upsert(&pool, &row("ssh", 5, 1)).await.unwrap();
    upsert(&pool, &row("telnet", 5, 2)).await.unwrap();
    upsert(&pool, &row("telnet", 6, 3)).await.unwrap();
    let rows = read_all(&pool).await.unwrap();
    assert_eq!(rows, vec![row("ssh", 5, 1), row("telnet", 6, 3)]);
}

#[sqlx::test(migrations = false)]
async fn the_table_refuses_a_negative_counter(pool: PgPool) {
    migrate(&pool).await;
    assert!(upsert(&pool, &row("ssh", 5, -1)).await.is_err());
    assert!(read_all(&pool).await.unwrap().is_empty());
}
