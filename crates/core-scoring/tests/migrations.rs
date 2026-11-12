#[sqlx::test(migrations = "./migrations")]
async fn migrations_apply_and_expose_expected_columns(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'ip_score' ORDER BY column_name")
        .fetch_all(&pool).await?;
    assert!(cols.contains(&"recommended_for_vendor".to_string()));
    assert!(cols.contains(&"recommended_for_blocklist".to_string()));
    assert!(!cols.contains(&"recommended".to_string()));
    Ok(())
}
