//! In-process queue for the ledger's append lock.
//!
//! Every writer to the ledger holds the Postgres advisory lock `APPEND_LOCK_KEY` for its whole
//! transaction. Taking it inside the transaction means a writer that has to wait is already
//! holding a pooled connection while it waits, so N concurrent writers in one process pin N
//! connections to do nothing, and every other user of the pool queues behind them: a daemon with a
//! tailer per sensor log, as many as its pool had connections, starved its own console and review
//! loops of connections for 3.256 s at a time (`acquired_after_secs` in the daemon's pool warnings).
//!
//! This gate puts the wait in front of the connection instead. A writer takes the gate first, so
//! within one process at most one writer per database holds a connection waiting on the advisory
//! lock (the one at the head of the queue), and every other writer waits here holding nothing. The
//! advisory lock stays: it is what serializes writers in different processes (a standalone
//! `intake` beside the daemon, a second node on the same database), which this gate cannot see.
//!
//! The gate is a plain queue in front of the lock, not a second lock with its own meaning, so it
//! cannot change what any writer reads or writes. It is fair (tokio's mutex wakes waiters in
//! arrival order), and it is released by drop, so a writer that is cancelled or errors out frees
//! it without ceremony.
//!
//! One gate per database, not one per process: the advisory lock is per database, and a process
//! holding pools to two databases (the test suites do, one scratch database per test) must not
//! make one database's writers wait for the other's.
//!
//! Ordering rule for callers: take the gate BEFORE `pool.begin()`. A writer that took the
//! connection first and the gate second would hold exactly what this exists to avoid holding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use sqlx::PgPool;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Held by the one writer in this process that may be waiting on, or holding, a database's
/// advisory lock.
#[derive(Debug)]
pub(super) struct AppendGate {
    _turn: OwnedMutexGuard<()>,
}

/// Waits for this process's turn at `pool`'s database's append lock, without holding a pooled
/// connection.
pub(super) async fn enter(pool: &PgPool) -> AppendGate {
    AppendGate {
        _turn: gate_for(pool).lock_owned().await,
    }
}

/// The database a pool talks to, as the advisory lock sees it: the lock is scoped to a database on
/// a server, so host, port or socket, and database name identify it.
fn database_key(pool: &PgPool) -> String {
    let options = pool.connect_options();
    format!(
        "{}:{}:{:?}/{:?}",
        options.get_host(),
        options.get_port(),
        options.get_socket(),
        options.get_database()
    )
}

fn gate_for(pool: &PgPool) -> Arc<Mutex<()>> {
    static GATES: OnceLock<StdMutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut gates = GATES
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    gates.entry(database_key(pool)).or_default().clone()
}
