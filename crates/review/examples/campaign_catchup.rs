//! Campaign indexer catch-up probe against a disposable database.
//!
//! Applies the core-scoring and review migrations, then runs the indexer batch after batch until
//! it has read the whole ledger, printing the rate. Run it next to `intake`'s `append_bench` to
//! measure what a catch-up costs the append path. It WRITES the campaign tables: point
//! `DATABASE_URL` at a scratch database, never a live one.
//!
//! ```text
//! DATABASE_URL=postgres://.../scratch cargo run --release -p review --example campaign_catchup
//! ```

use std::time::Instant;

use review::campaign::{self, BatchOutcome};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must name a scratch database");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .expect("core-scoring migrations");
    review::migrator()
        .run(&pool)
        .await
        .expect("review migrations");

    let start = Instant::now();
    let mut events = 0usize;
    let mut batches = 0usize;
    let mut slowest = std::time::Duration::ZERO;
    loop {
        let batch_start = Instant::now();
        match campaign::index_batch(&pool, campaign::BATCH_EVENTS)
            .await
            .expect("index_batch")
        {
            BatchOutcome::Indexed(0) => break,
            BatchOutcome::Indexed(n) => {
                events += n;
                batches += 1;
                slowest = slowest.max(batch_start.elapsed());
            }
            BatchOutcome::LockedOut => panic!("another indexer holds the campaign lock"),
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let campaigns: i64 = sqlx::query_scalar("SELECT count(*) FROM campaign")
        .fetch_one(&pool)
        .await
        .expect("count");
    println!(
        "catchup events={events} batches={batches} seconds={elapsed:.1} events_per_s={:.0} \
         slowest_batch_ms={:.0} campaigns={campaigns}",
        events as f64 / elapsed.max(f64::EPSILON),
        slowest.as_secs_f64() * 1e3,
    );
}
