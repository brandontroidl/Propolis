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
        "claim_expires",
        "transport_auth",
        "tls_verify_error",
    ] {
        assert!(cols.iter().any(|x| x == c), "missing column {c}");
    }
}

// F-5: claim_candidates orders the whole eligible set by `first_seen DESC` with no covering
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

#[tokio::test]
async fn fetch_daily_usage_is_one_non_negative_row_per_day() {
    let pool = pool().await;
    let day = "1999-01-01";
    sqlx::query("DELETE FROM fetch_daily_usage WHERE day = $1::date")
        .bind(day)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO fetch_daily_usage (day, used) VALUES ($1::date, 0)")
        .bind(day)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("INSERT INTO fetch_daily_usage (day, used) VALUES ($1::date, 0)")
            .bind(day)
            .execute(&pool)
            .await
            .is_err(),
        "a second row for the same day must be refused"
    );
    assert!(
        sqlx::query("UPDATE fetch_daily_usage SET used = -1 WHERE day = $1::date")
            .bind(day)
            .execute(&pool)
            .await
            .is_err(),
        "usage can never go negative"
    );
    sqlx::query("DELETE FROM fetch_daily_usage WHERE day = $1::date")
        .bind(day)
        .execute(&pool)
        .await
        .unwrap();
}

// Audit P-08: 0007 lands on a database that already holds rows written by the client that
// verified no certificate. Applied here to a fresh database carrying such rows (a capture and a
// pending one, written with the pre-0007 column list), so the upgrade itself is what is tested,
// not a row inserted afterwards.
#[sqlx::test(migrations = false)]
async fn migration_0007_marks_existing_rows_unknown_and_constrains_new_ones(pool: PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    for before in [
        include_str!("../migrations/0001_review_queue.sql"),
        include_str!("../migrations/0002_vendor_submission.sql"),
        include_str!("../migrations/0003_fetch_attempt.sql"),
        include_str!("../migrations/0004_backfill_fetch_attempt_source_ip.sql"),
        include_str!("../migrations/0005_fetch_attempt_first_seen_idx.sql"),
        include_str!("../migrations/0006_fetch_coordination.sql"),
    ] {
        sqlx::raw_sql(before).execute(&pool).await.unwrap();
    }
    for (url, status, sha) in [
        (
            "https://legacy.example/captured",
            "success",
            Some(vec![0xAB_u8; 32]),
        ),
        ("https://legacy.example/pending", "pending", None),
    ] {
        sqlx::query(
            "INSERT INTO fetch_attempt \
             (url_hash, url, host, scheme, status, sha256, attempts, last_attempt) \
             VALUES (sha256(convert_to($1, 'UTF8')), $1, 'legacy.example', 'https', $2, $3, 0, now())",
        )
        .bind(url)
        .bind(status)
        .bind(sha)
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::raw_sql(include_str!(
        "../migrations/0007_fetch_attempt_transport_auth.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT status, transport_auth, tls_verify_error FROM fetch_attempt ORDER BY status",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![
            ("pending".to_string(), "unknown".to_string(), None),
            ("success".to_string(), "unknown".to_string(), None),
        ],
        "no row fetched before 0007 may read as verified"
    );

    let write = |transport_auth: &'static str, error: Option<&'static str>| {
        sqlx::query(
            "UPDATE fetch_attempt SET transport_auth = $1, tls_verify_error = $2 \
             WHERE status = 'success'",
        )
        .bind(transport_auth)
        .bind(error)
        .execute(&pool)
    };
    assert!(write("bogus", None).await.is_err(), "unlisted state");
    assert!(
        write("unverified", None).await.is_err(),
        "unverified without the validation error"
    );
    assert!(
        write("verified", Some("x")).await.is_err(),
        "an error on a state that is not unverified"
    );
    assert!(write("unverified", Some("x")).await.is_ok());
    assert!(write("verified", None).await.is_ok());
    assert!(write("plaintext", None).await.is_ok());
}
