//! `propolis migrate` end to end, through the real binary and two real PostgreSQL roles: the owner
//! role migrates and sets the runtime role's grants, and `--check` reports what the role the
//! daemon connects as can do to the ledger. The binary runs with an environment holding nothing
//! but the database URLs, so a clean exit shows no daemon was started.

use std::process::{Command, Output};

use sqlx::PgPool;

const PASSWORD: &str = "test-only";

/// Test-only dynamic SQL: role and database names cannot be bound, and the names interpolated
/// here are derived from the test database's own name.
fn raw(sql: String) -> sqlx::RawSql {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
}

/// An owner role that owns the test database and a runtime role that owns nothing, as
/// `deploy/db-roles.sh` leaves them. Returns their names.
async fn roles(admin: &PgPool) -> (String, String) {
    let tag: String = sqlx::query_scalar("SELECT substr(md5(current_database()), 1, 12)")
        .fetch_one(admin)
        .await
        .unwrap();
    let (owner, runtime) = (format!("pc_owner_{tag}"), format!("pc_run_{tag}"));
    for role in [&owner, &runtime] {
        raw(format!(
            "DO $$ BEGIN \
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                 CREATE ROLE {role} LOGIN PASSWORD '{PASSWORD}'; \
               END IF; \
             END $$"
        ))
        .execute(admin)
        .await
        .unwrap();
    }
    let db = admin.connect_options().get_database().unwrap().to_string();
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

/// A URL for the per-test database on the server `DATABASE_URL` names, as `role`.
fn url_as(admin: &PgPool, role: &str) -> String {
    let options = admin.connect_options();
    format!(
        "postgres://{role}:{PASSWORD}@{}:{}/{}",
        options.get_host(),
        options.get_port(),
        options.get_database().unwrap()
    )
}

fn migrate(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_propolis"))
        .arg("migrate")
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[sqlx::test(migrations = false)]
async fn the_owner_migrates_and_the_runtime_role_is_left_unable_to_change_the_ledger(
    admin: PgPool,
) {
    let (owner, runtime) = roles(&admin).await;
    let (owner_url, runtime_url) = (url_as(&admin, &owner), url_as(&admin, &runtime));

    // Before: nothing is applied and the runtime role says so.
    let out = migrate(&["--check"], &[("DATABASE_URL", &runtime_url)]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("schema: NOT current"));

    let out = migrate(
        &[],
        &[
            ("PROPOLIS_MIGRATE_DATABASE_URL", &owner_url),
            ("DATABASE_URL", &runtime_url),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("schema is current"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "role {runtime} can append to the ledger and cannot change it"
        )),
        "{stdout}"
    );
    // Neither URL's password is printed.
    assert!(!stdout.contains(PASSWORD) && !text(&out.stderr).contains(PASSWORD));

    let out = migrate(&["--check"], &[("DATABASE_URL", &runtime_url)]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains(&format!("role: {runtime}")), "{stdout}");
    assert!(stdout.contains("schema: current"), "{stdout}");
    assert!(stdout.contains("ledger: protected"), "{stdout}");

    // The same check as the owner fails: the owner is exactly who the ledger is not protected
    // from, which is why the daemon must not connect as it.
    let out = migrate(&["--check"], &[("DATABASE_URL", &owner_url)]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("ledger: NOT protected"), "{stdout}");

    // Running it again changes nothing and still succeeds.
    let out = migrate(
        &[],
        &[
            ("PROPOLIS_MIGRATE_DATABASE_URL", &owner_url),
            ("DATABASE_URL", &runtime_url),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[sqlx::test(migrations = false)]
async fn with_one_role_it_migrates_and_says_the_ledger_is_not_protected(admin: PgPool) {
    let (owner, _) = roles(&admin).await;
    let owner_url = url_as(&admin, &owner);

    let out = migrate(&[], &[("DATABASE_URL", &owner_url)]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(stdout.contains("no separate runtime role"), "{stdout}");

    // Both URLs naming the same role is the same case, not a split.
    let out = migrate(
        &[],
        &[
            ("PROPOLIS_MIGRATE_DATABASE_URL", &owner_url),
            ("DATABASE_URL", &owner_url),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("no separate runtime role"));
}

/// `--check` is what `deploy/rollback.sh` runs after restoring a database on a node with split
/// roles, and what an operator runs after restoring one by hand. A database owned by the role the
/// daemon connects as must fail it, although every grant on the tables is as the split left it,
/// and the owner's migration run must not be what makes it pass.
#[sqlx::test(migrations = false)]
async fn the_check_fails_for_a_runtime_role_that_owns_the_database(admin: PgPool) {
    let (owner, runtime) = roles(&admin).await;
    let (owner_url, runtime_url) = (url_as(&admin, &owner), url_as(&admin, &runtime));
    let both = [
        ("PROPOLIS_MIGRATE_DATABASE_URL", owner_url.as_str()),
        ("DATABASE_URL", runtime_url.as_str()),
    ];
    let out = migrate(&[], &both);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = migrate(&["--check"], &[("DATABASE_URL", &runtime_url)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));

    let db = admin.connect_options().get_database().unwrap().to_string();
    raw(format!("ALTER DATABASE \"{db}\" OWNER TO {runtime}"))
        .execute(&admin)
        .await
        .unwrap();

    for _ in 0..2 {
        let out = migrate(&["--check"], &[("DATABASE_URL", &runtime_url)]);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "{stdout}");
        assert!(stdout.contains("schema: current"), "{stdout}");
        assert!(
            stdout.contains(&format!(
                "ledger: NOT protected: role {runtime} owns the database"
            )),
            "{stdout}"
        );
        // The second time round, after the owner has migrated and reset the grants again.
        let out = migrate(&[], &both);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
}

#[test]
fn it_refuses_unknown_arguments_and_a_missing_url_without_starting_anything() {
    let out = migrate(&["--force"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("usage: propolis migrate"));

    let out = migrate(&[], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("neither PROPOLIS_MIGRATE_DATABASE_URL nor DATABASE_URL"));

    let out = migrate(&["--check"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("DATABASE_URL is not set"));
}
