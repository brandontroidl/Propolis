//! `propolis::db_roles` against a real PostgreSQL with two real roles: the split is only worth anything if the server
//! refuses the runtime role, so nothing here is mocked.

use core_scoring::{ChainStatus, EventInput, Protocol, SignalType, append_event, verify_chain};
use propolis::db_roles::*;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// The password every test role gets, so the tests pass whether the server trusts local
/// connections (CI) or asks for one.
const PASSWORD: &str = "test-only";

/// Test-only dynamic SQL: role and database names cannot be bound, and every name interpolated here
/// is derived from the test database's own name.
fn raw(sql: String) -> sqlx::RawSql {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
}

/// An owner and a runtime role for this test's database. Roles are cluster-wide, so they are
/// named after the database (one per test) and reused if a previous run left them behind; the
/// owner is given the database, which is what `deploy/db-roles.sh` does in production.
async fn roles(admin: &PgPool) -> (String, String) {
    let tag: String = sqlx::query_scalar("SELECT substr(md5(current_database()), 1, 12)")
        .fetch_one(admin)
        .await
        .unwrap();
    let owner = format!("pt_owner_{tag}");
    let runtime = format!("pt_run_{tag}");
    for role in [&owner, &runtime] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(role)
                .fetch_one(admin)
                .await
                .unwrap();
        if !exists {
            raw(format!("CREATE ROLE {role} LOGIN PASSWORD '{PASSWORD}'"))
                .execute(admin)
                .await
                .unwrap();
        }
    }
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(admin)
        .await
        .unwrap();
    raw(format!(
        "ALTER DATABASE \"{db}\" OWNER TO {owner}; \
         ALTER SCHEMA public OWNER TO {owner}; \
         REVOKE CREATE ON SCHEMA public FROM PUBLIC"
    ))
    .execute(admin)
    .await
    .unwrap();
    (owner, runtime)
}

async fn connect_as(admin: &PgPool, role: &str) -> PgPool {
    let options = (*admin.connect_options())
        .clone()
        .username(role)
        .password(PASSWORD);
    PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap()
}

fn attack(n: u8) -> EventInput {
    EventInput::from_signal(
        format!("203.0.113.{n}").parse().unwrap(),
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

/// The statement fails with PostgreSQL's `insufficient_privilege`.
async fn denied(pool: &PgPool, sql: &str) -> bool {
    match raw(sql.to_string()).execute(pool).await {
        Err(sqlx::Error::Database(e)) => e.code().as_deref() == Some("42501"),
        _ => false,
    }
}

/// A database migrated by the owner with the runtime role's grants set.
async fn split(admin: &PgPool) -> (PgPool, PgPool, String) {
    let (owner, runtime) = roles(admin).await;
    let owner_pool = connect_as(admin, &owner).await;
    run_migrations(&owner_pool).await.unwrap();
    reconcile_runtime_grants(&owner_pool, &runtime)
        .await
        .unwrap();
    let runtime_pool = connect_as(admin, &runtime).await;
    (owner_pool, runtime_pool, runtime)
}

#[sqlx::test(migrations = false)]
async fn the_runtime_role_appends_to_the_ledger_and_cannot_change_it(admin: PgPool) {
    let (_owner, runtime, role) = split(&admin).await;

    // The whole append path works: the ledger insert, the chain trigger's read of the head, the
    // projection upsert and the breadth sets.
    append_event(&runtime, attack(1)).await.unwrap();
    append_event(&runtime, attack(2)).await.unwrap();
    assert_eq!(verify_chain(&runtime).await.unwrap(), ChainStatus::Intact);

    for sql in [
        "UPDATE event SET sensor = 'x'",
        "DELETE FROM event",
        "TRUNCATE event",
        "ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage",
        "DROP TRIGGER trg_enforce_chain_linkage ON event",
        "DROP TABLE event",
        "CREATE TRIGGER t BEFORE INSERT ON event FOR EACH ROW EXECUTE FUNCTION enforce_chain_linkage()",
        "CREATE TABLE scratch (n int)",
        "DELETE FROM _sqlx_migrations",
    ] {
        assert!(denied(&runtime, sql).await, "the runtime role ran: {sql}");
    }
    // The step that undoes the control for a role that owns the table: granting it back. From a
    // role with no grant option PostgreSQL answers with a warning and grants nothing, so the
    // check is on the effect, not on an error.
    let _ = raw(format!("GRANT UPDATE, DELETE, TRUNCATE ON event TO {role}"))
        .execute(&runtime)
        .await;
    assert!(
        denied(&runtime, "DELETE FROM event").await,
        "the runtime role granted itself the ledger"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(rows, 2);

    let status = role_status(&runtime).await.unwrap();
    assert!(!status.is_owner());
    assert_eq!(status.exposure(), None);
    assert!(pending_migrations(&runtime).await.unwrap().is_empty());
    // The daemon starts on it without migrating.
    prepare_schema(&runtime).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn a_single_role_deployment_still_migrates_and_is_reported_as_unprotected(admin: PgPool) {
    let (owner, _runtime) = roles(&admin).await;
    let owner_pool = connect_as(&admin, &owner).await;

    // No ledger yet and the role may create one: this is the role that migrates.
    assert!(role_status(&owner_pool).await.unwrap().is_owner());
    prepare_schema(&owner_pool).await.unwrap();
    append_event(&owner_pool, attack(1)).await.unwrap();

    let status = role_status(&owner_pool).await.unwrap();
    assert!(status.is_owner());
    let why = status.exposure().expect("an owner is never protected from");
    assert!(why.contains("owns the event table"), "{why}");
}

/// Migration 0004 leaves a single role owning a ledger it holds no UPDATE, DELETE or TRUNCATE on,
/// and PostgreSQL 16 and earlier refuse such an owner the SHARE lock later migrations take. The
/// right is lent for the retry only to an owner in that position, and is gone again afterwards.
#[sqlx::test(migrations = false)]
async fn a_single_role_whose_own_rights_were_revoked_is_lent_the_lock_right_only_to_migrate(
    admin: PgPool,
) {
    let (owner, runtime, _) = split(&admin).await;
    // The runtime role is not the owner: nothing is lent, whatever it lacks.
    assert!(!lend_ledger_lock_right(&runtime).await.unwrap());
    // An owner with its rights intact needs nothing.
    assert!(!lend_ledger_lock_right(&owner).await.unwrap());

    sqlx::raw_sql("REVOKE UPDATE, DELETE, TRUNCATE ON event FROM CURRENT_USER")
        .execute(&owner)
        .await
        .unwrap();
    assert!(lend_ledger_lock_right(&owner).await.unwrap());
    sqlx::raw_sql("BEGIN; LOCK TABLE event IN SHARE MODE; COMMIT")
        .execute(&owner)
        .await
        .expect("the lent right is enough for the migrations' lock");

    // A run that needed no help does not touch the privileges...
    sqlx::raw_sql("REVOKE UPDATE, DELETE, TRUNCATE ON event FROM CURRENT_USER")
        .execute(&owner)
        .await
        .unwrap();
    migrate_single_role(&owner).await.unwrap();
    // ...so the ledger still carries exactly what migration 0004 left.
    let can_update: bool =
        sqlx::query_scalar("SELECT has_table_privilege(current_user, 'event', 'UPDATE')")
            .fetch_one(&owner)
            .await
            .unwrap();
    assert!(!can_update);
}

/// sqlx holds a session advisory lock for a migration run and releases it only on success. A
/// failed run must not leave it on an idle pooled connection: the retry in `migrate_single_role`
/// would then wait on it for ever from another connection (it did, on PostgreSQL 16).
#[sqlx::test(migrations = false)]
async fn a_failed_migration_run_leaves_no_lock_behind(admin: PgPool) {
    let (owner, _runtime, _) = split(&admin).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = 3")
        .execute(&owner)
        .await
        .unwrap();
    let err = run_migrations(&owner).await.unwrap_err();
    assert!(err.starts_with("core-scoring migrations failed"), "{err}");

    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database \
         WHERE l.locktype = 'advisory' AND d.datname = current_database()",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(held, 0, "the failed run still holds its advisory lock");
}

#[sqlx::test(migrations = false)]
async fn the_runtime_role_refuses_a_schema_the_owner_has_not_migrated(admin: PgPool) {
    let (owner, runtime) = roles(&admin).await;
    let runtime_pool = connect_as(&admin, &runtime).await;

    // Nothing applied at all: every migration is pending and the daemon must not try to run them.
    let err = prepare_schema(&runtime_pool).await.unwrap_err();
    assert!(err.contains("propolis migrate"), "{err}");
    assert!(err.contains("core-scoring 0001 is not applied"), "{err}");
    let total: usize = migration_sets()
        .iter()
        .map(|s| s.migrator.iter().count())
        .sum();
    assert_eq!(
        pending_migrations(&runtime_pool).await.unwrap().len(),
        total
    );

    // One migration short, as after an upgrade whose `propolis migrate` step was skipped.
    let owner_pool = connect_as(&admin, &owner).await;
    run_migrations(&owner_pool).await.unwrap();
    reconcile_runtime_grants(&owner_pool, &runtime)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM _sqlx_migrations_fleet \
         WHERE version = (SELECT max(version) FROM _sqlx_migrations_fleet)",
    )
    .execute(&owner_pool)
    .await
    .unwrap();
    let pending = pending_migrations(&runtime_pool).await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert!(pending[0].starts_with("fleet ") && pending[0].ends_with("is not applied"));
    assert!(prepare_schema(&runtime_pool).await.is_err());
}

#[sqlx::test(migrations = false)]
async fn a_changed_or_unknown_migration_is_reported(admin: PgPool) {
    let (owner, runtime, _) = split(&admin).await;
    sqlx::raw_sql(
        "UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = 1; \
         INSERT INTO _sqlx_migrations_review (version, description, success, checksum, execution_time) \
         VALUES (9999, 'from a newer release', true, '\\x00', 0)",
    )
    .execute(&owner)
    .await
    .unwrap();
    let pending = pending_migrations(&runtime).await.unwrap();
    assert_eq!(pending.len(), 2, "{pending:?}");
    assert!(pending[0].contains("core-scoring 0001 was applied from different SQL"));
    assert!(pending[1].contains("review 9999 is applied but unknown"));
}

#[sqlx::test(migrations = false)]
async fn a_grant_made_by_hand_is_reported_and_reset(admin: PgPool) {
    let (owner, runtime, role) = split(&admin).await;
    raw(format!(
        "GRANT UPDATE, DELETE, TRUNCATE, TRIGGER ON event TO {role}"
    ))
    .execute(&owner)
    .await
    .unwrap();

    let why = role_status(&runtime).await.unwrap().exposure().unwrap();
    assert!(
        why.contains("UPDATE, DELETE, TRUNCATE, TRIGGER"),
        "the hand-made grant is not named: {why}"
    );
    // Reported, not fatal: the daemon still starts, as it did before the roles were split.
    prepare_schema(&runtime).await.unwrap();

    reconcile_runtime_grants(&owner, &role).await.unwrap();
    assert_eq!(role_status(&runtime).await.unwrap().exposure(), None);
    assert!(denied(&runtime, "DELETE FROM event").await);
}

#[sqlx::test(migrations = false)]
async fn a_runtime_role_that_could_undo_its_grants_is_refused(admin: PgPool) {
    let (owner, runtime) = roles(&admin).await;
    let owner_pool = connect_as(&admin, &owner).await;
    run_migrations(&owner_pool).await.unwrap();

    let message = |e: sqlx::Error| e.to_string();
    let err = reconcile_runtime_grants(&owner_pool, "pt_no_such_role")
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("does not exist"), "{err}");

    let err = reconcile_runtime_grants(&owner_pool, &owner)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("member of, the owner role"), "{err}");

    raw(format!("GRANT {owner} TO {runtime}"))
        .execute(&admin)
        .await
        .unwrap();
    let err = reconcile_runtime_grants(&owner_pool, &runtime)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("member of, the owner role"), "{err}");
    raw(format!("REVOKE {owner} FROM {runtime}"))
        .execute(&admin)
        .await
        .unwrap();

    let superuser: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&admin)
        .await
        .unwrap();
    let err = reconcile_runtime_grants(&owner_pool, &superuser)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("is a superuser"), "{err}");

    // A role name is data, never statement text.
    let err = reconcile_runtime_grants(&owner_pool, "x; DROP TABLE event; --")
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("does not exist"), "{err}");
    let ledger: bool = sqlx::query_scalar("SELECT to_regclass('event') IS NOT NULL")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(ledger);
}

/// The upgrade path: one role owns a ledger with events in it, then the roles are split.
#[sqlx::test(migrations = false)]
async fn splitting_an_existing_deployment_keeps_the_ledger_and_takes_the_runtime_roles_ownership(
    admin: PgPool,
) {
    // The role names `roles` would make, with the runtime one set up as today's single role:
    // owner of the database, migrated by itself, with events in the ledger.
    let (_, runtime) = roles(&admin).await;
    let owner = format!("{runtime}_owner");
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&admin)
        .await
        .unwrap();
    raw(format!(
        "ALTER DATABASE \"{db}\" OWNER TO {runtime}; ALTER SCHEMA public OWNER TO {runtime}"
    ))
    .execute(&admin)
    .await
    .unwrap();
    let single = connect_as(&admin, &runtime).await;
    prepare_schema(&single).await.unwrap();
    append_event(&single, attack(1)).await.unwrap();
    append_event(&single, attack(2)).await.unwrap();
    assert!(role_status(&single).await.unwrap().exposure().is_some());
    // What migration 0004 does on a production database (named propolis, role propolis): the
    // owning role's own UPDATE, DELETE and TRUNCATE are revoked.
    raw(format!(
        "REVOKE UPDATE, DELETE, TRUNCATE ON event FROM {runtime}"
    ))
    .execute(&admin)
    .await
    .unwrap();

    // The daemon is still connected: refused, and nothing has moved.
    let err = init_roles(&admin, &owner, &runtime)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("stop propolis first"), "{err}");
    assert!(role_status(&single).await.unwrap().is_owner());
    single.close().await;

    init_roles(&admin, &owner, &runtime).await.unwrap();
    // Twice is the same as once.
    init_roles(&admin, &owner, &runtime).await.unwrap();
    raw(format!("ALTER ROLE {owner} PASSWORD '{PASSWORD}'"))
        .execute(&admin)
        .await
        .unwrap();

    // Ownership has moved and the runtime role holds nothing yet: it refuses to start rather
    // than run against tables it cannot read.
    let runtime_pool = connect_as(&admin, &runtime).await;
    assert!(!role_status(&runtime_pool).await.unwrap().is_owner());
    assert!(denied(&runtime_pool, "SELECT count(*) FROM event").await);
    let err = prepare_schema(&runtime_pool).await.unwrap_err();
    assert!(err.contains("may not read the migration history"), "{err}");
    assert!(err.contains("propolis migrate"), "{err}");

    let owner_pool = connect_as(&admin, &owner).await;
    assert!(role_status(&owner_pool).await.unwrap().is_owner());
    // The new owner inherited the reduced entry, and a later migration's SHARE lock needs one of
    // the revoked privileges on PostgreSQL 16 and earlier. `propolis migrate` restores them first.
    restore_owner_ledger_rights(&owner_pool).await.unwrap();
    sqlx::raw_sql("BEGIN; LOCK TABLE event IN SHARE MODE; COMMIT")
        .execute(&owner_pool)
        .await
        .expect("the owner can take the lock its migrations take");
    run_migrations(&owner_pool).await.unwrap();
    reconcile_runtime_grants(&owner_pool, &runtime)
        .await
        .unwrap();

    // The ledger came through, the chain still verifies and still extends, and the role that
    // used to own it can no longer change it.
    prepare_schema(&runtime_pool).await.unwrap();
    append_event(&runtime_pool, attack(3)).await.unwrap();
    assert_eq!(
        verify_chain(&runtime_pool).await.unwrap(),
        ChainStatus::Intact
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(&runtime_pool)
        .await
        .unwrap();
    assert_eq!(rows, 3);
    assert_eq!(role_status(&runtime_pool).await.unwrap().exposure(), None);
    for sql in [
        "DELETE FROM event",
        "ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage",
        "CREATE TABLE scratch (n int)",
    ] {
        assert!(
            denied(&runtime_pool, sql).await,
            "the runtime role ran: {sql}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn splitting_refuses_roles_that_would_not_be_separate(admin: PgPool) {
    let (owner, runtime) = roles(&admin).await;
    let message = |e: sqlx::Error| e.to_string();

    let err = init_roles(&admin, &runtime, &runtime)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("two different names"), "{err}");

    let err = init_roles(&admin, "propolis", &runtime)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("cannot be named propolis"), "{err}");

    let superuser: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&admin)
        .await
        .unwrap();
    let err = init_roles(&admin, &superuser, &runtime)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("may be a superuser"), "{err}");

    raw(format!("GRANT {owner} TO {runtime}"))
        .execute(&admin)
        .await
        .unwrap();
    let err = init_roles(&admin, &owner, &runtime)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("is a member of"), "{err}");
    raw(format!("REVOKE {owner} FROM {runtime}"))
        .execute(&admin)
        .await
        .unwrap();

    // Only a superuser can move ownership; the owner role itself is told so.
    let owner_pool = connect_as(&admin, &owner).await;
    let err = init_roles(&owner_pool, &owner, &runtime)
        .await
        .map_err(message)
        .unwrap_err();
    assert!(err.contains("is not a superuser"), "{err}");
}
