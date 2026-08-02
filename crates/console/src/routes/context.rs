//! `base_context`: the pending-count/uptime/version trio every authenticated page's route handler
//! merges into its own template context, so the shared nav/footer chrome can show them without
//! each page re-deriving them independently. Not exposed outside the crate -
//! `routes::dashboard`/`queue`/`detail`/`feed` are its only callers.

use chrono::Utc;
use sqlx::PgPool;

pub(crate) struct BaseContext {
    pub pending_count: i64,
    pub uptime: String,
    pub version: &'static str,
}

/// Queries the current sitewide pending-review count and computes process uptime from
/// `AppState::startup_time`. A failure on the count query falls back to 0 rather than
/// propagating: this trio is supplementary nav/footer chrome shown on every page, not a page's own
/// primary content (which already fails closed to a 503 via `AppError` on its own query errors), so
/// a transient hiccup here should not take down an otherwise-fine page render.
pub(crate) async fn base_context(
    db: &PgPool,
    startup_time: chrono::DateTime<Utc>,
    version: &'static str,
) -> BaseContext {
    let pending_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM review_queue WHERE state = 'pending'")
            .fetch_one(db)
            .await
            .unwrap_or(0);

    let elapsed = Utc::now() - startup_time;
    let hours = elapsed.num_hours();
    let minutes = elapsed.num_minutes() % 60;
    let uptime = if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    };

    BaseContext {
        pending_count,
        uptime,
        version,
    }
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    async fn migrate(pool: &PgPool) {
        sqlx::migrate!("../core-scoring/migrations")
            .run(pool)
            .await
            .unwrap();
        review::migrator().run(pool).await.unwrap();
    }

    async fn insert_pending(pool: &PgPool, ip: &str) {
        sqlx::query(
            "INSERT INTO review_queue (source_ip, score_at_surface, categories_at_surface) \
             VALUES ($1::inet, 0, '{}'::jsonb)",
        )
        .bind(ip)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = false)]
    async fn pending_count_reflects_pending_rows(pool: PgPool) {
        migrate(&pool).await;
        insert_pending(&pool, "203.0.113.1").await;
        insert_pending(&pool, "203.0.113.2").await;

        let ctx = super::base_context(&pool, chrono::Utc::now(), "0.1.0").await;

        assert_eq!(ctx.pending_count, 2);
    }

    #[sqlx::test(migrations = false)]
    async fn pending_count_excludes_non_pending_rows(pool: PgPool) {
        migrate(&pool).await;
        insert_pending(&pool, "203.0.113.3").await;
        sqlx::query(
            "UPDATE review_queue SET state = 'approved', decided_at = now() \
             WHERE source_ip = $1::inet",
        )
        .bind("203.0.113.3")
        .execute(&pool)
        .await
        .unwrap();

        let ctx = super::base_context(&pool, chrono::Utc::now(), "0.1.0").await;

        assert_eq!(ctx.pending_count, 0);
    }

    #[sqlx::test(migrations = false)]
    async fn uptime_formats_minutes_only_under_an_hour(pool: PgPool) {
        migrate(&pool).await;
        let startup_time = chrono::Utc::now() - chrono::Duration::minutes(5);

        let ctx = super::base_context(&pool, startup_time, "0.1.0").await;

        assert_eq!(ctx.uptime, "5m");
    }

    #[sqlx::test(migrations = false)]
    async fn uptime_formats_hours_and_minutes_over_an_hour(pool: PgPool) {
        migrate(&pool).await;
        // 125 minutes = 2h 5m - exercises both the hour and minute arms in one value.
        let startup_time = chrono::Utc::now() - chrono::Duration::minutes(125);

        let ctx = super::base_context(&pool, startup_time, "0.1.0").await;

        assert_eq!(ctx.uptime, "2h 5m");
    }

    #[sqlx::test(migrations = false)]
    async fn version_passes_through_unchanged(pool: PgPool) {
        migrate(&pool).await;

        let ctx = super::base_context(&pool, chrono::Utc::now(), "9.9.9").await;

        assert_eq!(ctx.version, "9.9.9");
    }
}
