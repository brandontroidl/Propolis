//! Row counts that stay cheap on a table that only grows. A `count(*)` reads every row, so a page
//! that shows one pays for the whole table on every load (the event ledger's panel did, and it is
//! polled). The count here is the planner's own estimate (`pg_class.reltuples`, refreshed by
//! autovacuum) once the table is known to be past [`COUNT_CAP`] rows, and a count that reads at
//! most that many rows otherwise. It says which through [`Count::exact`], so an estimate is never
//! shown as a count.

use sqlx::PgPool;

/// The most rows a count reads before it stops and falls back to an estimate.
pub(crate) const COUNT_CAP: i64 = 100_000;

/// A row count that is exact up to [`COUNT_CAP`] and an estimate past it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Count {
    pub(crate) value: i64,
    pub(crate) exact: bool,
}

/// Rows in `table`: counted, up to [`COUNT_CAP`], and past it the planner's estimate.
///
/// `table` is interpolated into the statement, so it is a `&'static str` that only a call site's
/// literal can supply; a name from a request can never reach it.
pub(crate) async fn capped_total(db: &PgPool, table: &'static str) -> Result<Count, sqlx::Error> {
    // Audited: `table` is a static literal and the cap a constant.
    let estimate: f32 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT reltuples FROM pg_class WHERE oid = '{table}'::regclass"
    )))
    .fetch_one(db)
    .await?;
    // A table the planner already knows is past the cap is not scanned at all: counting to the cap
    // would cost a read of 100,000 rows on every load for a number that is about to be an estimate.
    if estimate > COUNT_CAP as f32 {
        return Ok(Count {
            value: estimate as i64,
            exact: false,
        });
    }
    let counted: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM (SELECT 1 FROM {table} LIMIT {}) s",
        COUNT_CAP + 1
    )))
    .fetch_one(db)
    .await?;
    if counted <= COUNT_CAP {
        return Ok(Count {
            value: counted,
            exact: true,
        });
    }
    Ok(Count {
        // Never below what was just counted: an estimate that lags the table (or a -1 from a table
        // never analyzed) must not read as fewer rows than were seen.
        value: (estimate as i64).max(counted),
        exact: false,
    })
}
