//! Writers waiting for the ledger's append lock must not hold pooled connections while they wait.
//!
//! The lock is a Postgres advisory lock taken inside the append transaction, so before the
//! in-process gate (`repository/append_gate.rs`) every waiting writer was a checked-out connection
//! doing nothing: with as many tailers as pool slots, nothing else in the daemon (the console, the
//! review loops, the campaign indexer) could get a connection until the holder committed. The
//! daemon logged it as `acquired_after_secs=3.256`.
//!
//! The scenario is reproduced with a foreign session holding the advisory lock (what another
//! process, or a long batch, is to a writer in this process) and a deliberately small pool, then
//! asking whether a reader can still get a connection while writers are queued behind the lock.

use std::time::Duration;

use core_scoring::domain::enums::{Protocol, SignalType};
use core_scoring::domain::types::EventInput;
use core_scoring::repository::replay::ChainStatus;
use core_scoring::repository::{
    RepoError, append_event, append_events, append_telemetry_event, begin_exclusive, verify_chain,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};

/// `core_scoring`'s `APPEND_LOCK_KEY`, repeated here the way the soak harness and the append
/// benchmark repeat it: the tests hold the same lock a second process would.
const APPEND_LOCK_KEY: i64 = 7_265_646_772_697_400_001;

/// Slots in the pool the contending writers share. Fewer than the writers, so that without the
/// gate they exhaust it, and more than one, so that with the gate a reader has somewhere to go.
const POOL_SLOTS: u32 = 3;
const WRITERS: u32 = 8;

fn attack(n: u32) -> EventInput {
    EventInput::from_signal(
        format!("203.0.113.{}", 10 + n).parse().unwrap(),
        None,
        "sensor-a".into(),
        SignalType::HoneypotCommandExec,
        Protocol::Tcp,
        true,
        "2026-07-17T00:00:00Z".parse().unwrap(),
        serde_json::json!({ "n": n }),
        None,
    )
}

fn session_end(n: u32) -> EventInput {
    EventInput::from_signal(
        format!("203.0.113.{}", 10 + n).parse().unwrap(),
        None,
        "sensor-a".into(),
        SignalType::HoneypotSessionEnd,
        Protocol::Tcp,
        false,
        "2026-07-17T00:00:01Z".parse().unwrap(),
        serde_json::json!({ "reason": "peer_closed" }),
        None,
    )
}

/// A pool of its own onto the test's database, so the test can starve it without starving the
/// connection the harness uses to look at the database.
async fn small_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(POOL_SLOTS)
        .acquire_timeout(Duration::from_secs(30))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap()
}

/// A session outside every pool holding the append lock, as another process's writer would.
async fn foreign_holder(pool: &PgPool) -> PgConnection {
    let mut conn = PgConnection::connect_with(&pool.connect_options())
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(APPEND_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();
    conn
}

async fn release(mut conn: PgConnection) {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(APPEND_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();
}

/// Writers parked on the append lock in THIS test's database: `pg_locks` is cluster-wide and the
/// tests in this file run side by side, each holding the same key in a database of its own.
async fn waiting_for_the_lock(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks \
         WHERE locktype = 'advisory' AND NOT granted \
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Waits until at least one writer is parked on the advisory lock, then gives the rest time to
/// reach whatever they queue on.
async fn writers_have_queued(pool: &PgPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while waiting_for_the_lock(pool).await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no writer reached the append lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// Whether another user of the pool can get a connection right now.
async fn reader_gets_a_connection(pool: &PgPool) -> bool {
    match tokio::time::timeout(Duration::from_secs(2), pool.acquire()).await {
        Ok(Ok(mut conn)) => sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .is_ok(),
        _ => false,
    }
}

async fn event_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn queued_appenders_leave_the_pool_to_other_users(pool: PgPool) {
    let small = small_pool(&pool).await;
    let holder = foreign_holder(&pool).await;

    let writers: Vec<_> = (0..WRITERS)
        .map(|n| {
            let small = small.clone();
            tokio::spawn(async move { append_event(&small, attack(n)).await })
        })
        .collect();
    writers_have_queued(&pool).await;

    let served = reader_gets_a_connection(&small).await;
    let parked_on_the_lock = waiting_for_the_lock(&pool).await;

    release(holder).await;
    for w in writers {
        w.await
            .unwrap()
            .expect("a queued appender completes once the lock frees");
    }

    assert!(
        served,
        "{parked_on_the_lock} of {POOL_SLOTS} pooled connections were parked on the append lock, \
         so a reader could not get one"
    );
    assert_eq!(
        parked_on_the_lock, 1,
        "only the head of the queue may wait on the advisory lock"
    );
    assert_eq!(event_count(&pool).await, i64::from(WRITERS));
}

#[sqlx::test(migrations = "./migrations")]
async fn queued_batches_telemetry_and_exclusive_holders_leave_the_pool_to_other_users(
    pool: PgPool,
) {
    let small = small_pool(&pool).await;
    let holder = foreign_holder(&pool).await;

    // One of each kind of writer, repeated: the single path, the batched path, the telemetry path
    // and the console's exclusive transaction all queue the same way.
    let mut writers = Vec::new();
    for n in 0..2 {
        let p = small.clone();
        writers.push(tokio::spawn(async move {
            append_events(&p, vec![attack(n), session_end(n)])
                .await
                .failure
                .map_or(Ok(()), Err)
        }));
        let p = small.clone();
        writers.push(tokio::spawn(async move {
            append_telemetry_event(&p, session_end(n + 4)).await
        }));
        let p = small.clone();
        writers.push(tokio::spawn(async move {
            begin_exclusive(&p)
                .await
                .map_err(RepoError::from)?
                .commit()
                .await
                .map_err(RepoError::from)
        }));
    }
    writers_have_queued(&pool).await;

    let served = reader_gets_a_connection(&small).await;
    let parked_on_the_lock = waiting_for_the_lock(&pool).await;

    release(holder).await;
    for w in writers {
        w.await
            .unwrap()
            .expect("a queued writer completes once the lock frees");
    }

    assert!(
        served,
        "{parked_on_the_lock} of {POOL_SLOTS} pooled connections were parked on the append lock, \
         so a reader could not get one"
    );
    assert_eq!(parked_on_the_lock, 1);
    assert_eq!(event_count(&pool).await, 4 + 2);
}

/// A writer dropped while it waits, at either stage, must give its place to the next one: an
/// aborted task that left the gate held would wedge every append in the process.
#[sqlx::test(migrations = "./migrations")]
async fn an_aborted_appender_frees_its_turn(pool: PgPool) {
    let small = small_pool(&pool).await;
    let holder = foreign_holder(&pool).await;

    // `head` reaches the advisory lock holding the turn; `behind` waits for the turn.
    let head = {
        let small = small.clone();
        tokio::spawn(async move { append_event(&small, attack(0)).await })
    };
    writers_have_queued(&pool).await;
    let behind = {
        let small = small.clone();
        tokio::spawn(async move { append_event(&small, attack(1)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let last = {
        let small = small.clone();
        tokio::spawn(async move { append_event(&small, attack(2)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Abort the one waiting for the turn, then the one waiting on the lock.
    behind.abort();
    let _ = behind.await;
    head.abort();
    let _ = head.await;

    release(holder).await;
    tokio::time::timeout(Duration::from_secs(15), last)
        .await
        .expect("the turn was freed by the aborted writers")
        .unwrap()
        .expect("the remaining writer appends");
    assert_eq!(event_count(&pool).await, 1);
}

/// The gate is only a queue: whatever order it releases writers in, the ledger they leave is one
/// intact hash chain, with every event in it exactly once.
#[sqlx::test(migrations = "./migrations")]
async fn contending_writers_still_leave_one_intact_chain(pool: PgPool) {
    let small = small_pool(&pool).await;
    let mut writers = Vec::new();
    for n in 0..24u32 {
        let p = small.clone();
        writers.push(tokio::spawn(async move {
            match n % 3 {
                0 => append_event(&p, attack(n)).await.map(|_| ()),
                1 => append_telemetry_event(&p, session_end(n)).await,
                _ => append_events(&p, vec![attack(n), session_end(n)])
                    .await
                    .failure
                    .map_or(Ok(()), Err),
            }
        }));
    }
    for w in writers {
        w.await.unwrap().unwrap();
    }
    // 8 single events + 8 telemetry + 8 batches of two.
    assert_eq!(event_count(&pool).await, 8 + 8 + 16);
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}
