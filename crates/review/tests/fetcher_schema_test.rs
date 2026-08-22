use sqlx::PgPool;
async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    review::migrator().run(&pool).await.unwrap();
    pool
}
#[tokio::test]
async fn fetch_attempt_table_exists_with_expected_columns() {
    let pool = pool().await;
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name='fetch_attempt' ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for c in [
        "url_hash",
        "url",
        "host",
        "scheme",
        "pinned_ip",
        "port",
        "source_ip",
        "parent_hash",
        "depth",
        "status",
        "reject_reason",
        "sha256",
        "bytes",
        "content_type",
        "attempts",
        "next_attempt",
        "first_seen",
        "last_attempt",
    ] {
        assert!(cols.iter().any(|x| x == c), "missing column {c}");
    }
}

// F-5: select_candidates orders the whole eligible set by `first_seen DESC` with no covering
// index (only host/last_attempt and status/next_attempt existed) - under a backlog larger than
// one cycle's batch this forces a sort over every qualifying row each cycle.
#[tokio::test]
async fn fetch_attempt_has_a_first_seen_index_for_the_selection_sort() {
    let pool = pool().await;
    let indexdefs: Vec<String> =
        sqlx::query_scalar("SELECT indexdef FROM pg_indexes WHERE tablename = 'fetch_attempt'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        indexdefs.iter().any(|d| d.contains("first_seen")),
        "expected an index covering fetch_attempt.first_seen, found: {indexdefs:?}"
    );
}
