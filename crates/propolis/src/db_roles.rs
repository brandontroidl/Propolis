//! Database roles: who may change the schema, and who may only use it.
//!
//! The ledger's append-only control is a `REVOKE UPDATE, DELETE, TRUNCATE ON event`
//! (`crates/core-scoring/migrations/0004_harden_event_table.sql`). A revoke binds every role except
//! the table's owner, who can grant the privilege back, disable the chain trigger or drop the
//! table. While the daemon connects as the role that ran the migrations it IS the owner, so the
//! control stops a bug or an injected statement but not a daemon that has been taken over.
//!
//! The split this module implements:
//!
//! - an **owner** role runs the migrations (`propolis migrate`, from a root-only env file the
//!   daemon's unit cannot read) and owns every table;
//! - the **runtime** role the daemon connects as owns nothing, cannot create objects in the
//!   schema, holds `SELECT, INSERT` on `event` and ordinary read/write on the other tables.
//!
//! [`reconcile_runtime_grants`] is the single definition of the runtime role's privileges; it runs
//! after every migration so a table a migration adds is covered. A daemon that finds itself the
//! runtime role never migrates: it checks that every migration this binary embeds is applied
//! ([`pending_migrations`]) and refuses to start otherwise.
//!
//! A deployment that never splits the roles keeps working exactly as before (the daemon migrates
//! at startup) and is told at startup that the ledger is not protected from its own role.

use sqlx::PgPool;
use sqlx::Row;
use sqlx::migrate::Migrator;

/// One migration set: the name used in messages and the migrator that owns its bookkeeping table.
pub struct MigrationSet {
    pub name: &'static str,
    pub migrator: Migrator,
    /// Reads the set's bookkeeping table. One literal per table: table names cannot be bound, and
    /// no query text in this workspace is built at runtime.
    applied_sql: &'static str,
}

/// Every migration set, in the order they must run (review and fleet depend on core-scoring's
/// enum types).
pub fn migration_sets() -> [MigrationSet; 3] {
    [
        MigrationSet {
            name: "core-scoring",
            migrator: sqlx::migrate!("../core-scoring/migrations"),
            applied_sql: "SELECT version, checksum, success FROM _sqlx_migrations",
        },
        MigrationSet {
            name: "review",
            migrator: review::migrator(),
            applied_sql: "SELECT version, checksum, success FROM _sqlx_migrations_review",
        },
        MigrationSet {
            name: "fleet",
            migrator: fleet::migrator(),
            applied_sql: "SELECT version, checksum, success FROM _sqlx_migrations_fleet",
        },
    ]
}

/// Run every migration set. The error names the set that failed.
///
/// All of it runs on one connection, which is released with its session locks dropped. sqlx
/// takes a session-level advisory lock for a run and gives it back only when the run succeeds; a
/// failed run on a pooled connection would leave the lock held by an idle connection, and the
/// next run, on another connection of the same pool, would wait on it for ever
/// ([`migrate_single_role`] runs twice).
pub async fn run_migrations(pool: &PgPool) -> Result<(), String> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| format!("cannot get a connection to migrate on: {e}"))?;
    let mut result = Ok(());
    for set in migration_sets() {
        if let Err(e) = set.migrator.run(&mut *conn).await {
            result = Err(format!("{} migrations failed: {e}", set.name));
            break;
        }
    }
    // Best effort: if this fails the connection is broken and the pool discards it, which
    // releases the lock too.
    let _ = sqlx::query("SELECT pg_advisory_unlock_all()")
        .execute(&mut *conn)
        .await;
    result
}

/// PostgreSQL's `undefined_table`: the bookkeeping table does not exist yet.
const UNDEFINED_TABLE: &str = "42P01";

/// PostgreSQL's `insufficient_privilege`.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// What separates this database from the schema this binary embeds, one line per difference,
/// empty when they agree. Read-only: unlike `Migrator::run` it creates no bookkeeping table and
/// takes no lock, so the runtime role (which cannot create anything) can call it.
pub async fn pending_migrations(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let mut out = Vec::new();
    for set in migration_sets() {
        let rows = match sqlx::query(set.applied_sql).fetch_all(pool).await {
            Ok(rows) => rows,
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNDEFINED_TABLE) => {
                Vec::new()
            }
            // Ownership has moved to the owner role and the runtime role's grants are not set
            // yet: the state `propolis migrate --init-roles` leaves until `propolis migrate` runs.
            Err(sqlx::Error::Database(e))
                if e.code().as_deref() == Some(INSUFFICIENT_PRIVILEGE) =>
            {
                out.push(format!(
                    "{}: this role may not read the migration history",
                    set.name
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut applied = std::collections::BTreeMap::new();
        for row in rows {
            let version: i64 = row.try_get("version")?;
            let checksum: Vec<u8> = row.try_get("checksum")?;
            let success: bool = row.try_get("success")?;
            applied.insert(version, (checksum, success));
        }
        for m in set
            .migrator
            .iter()
            .filter(|m| !m.migration_type.is_down_migration())
        {
            match applied.remove(&m.version) {
                None => out.push(format!("{} {:04} is not applied", set.name, m.version)),
                Some((_, false)) => {
                    out.push(format!("{} {:04} failed part-way", set.name, m.version))
                }
                Some((checksum, true)) if checksum != m.checksum.as_ref() => out.push(format!(
                    "{} {:04} was applied from different SQL than this binary embeds",
                    set.name, m.version
                )),
                Some(_) => {}
            }
        }
        // What is left is in the database and not in this binary: an older binary started
        // against a newer schema, which `Migrator::run` refuses too.
        for version in applied.keys() {
            out.push(format!(
                "{} {:04} is applied but unknown to this binary (the database is newer)",
                set.name, version
            ));
        }
    }
    Ok(out)
}

/// What the connected role is to the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStatus {
    /// The role this connection runs as.
    pub role: String,
    /// The `event` table exists.
    pub ledger_exists: bool,
    /// The role is a superuser, or owns `event` (directly or through membership). Either can
    /// undo every ledger control.
    pub controls_ledger: bool,
    /// The role may create objects in the current schema.
    pub can_create: bool,
    /// The role holds `SELECT` and `INSERT` on `event`: what appending takes.
    pub can_append: bool,
    /// The ledger privileges, beyond `SELECT` and `INSERT`, the role holds on `event`.
    pub ledger_write_privileges: Vec<&'static str>,
}

impl RoleStatus {
    /// This role is the one that migrates: it owns the ledger, or there is no ledger yet and it
    /// may create one.
    pub fn is_owner(&self) -> bool {
        if self.ledger_exists {
            self.controls_ledger
        } else {
            self.can_create
        }
    }

    /// Why the ledger is not protected from this role, or `None` when it is.
    pub fn exposure(&self) -> Option<String> {
        if !self.ledger_exists {
            return None;
        }
        if self.controls_ledger {
            return Some(format!(
                "role {} owns the event table (or is a superuser), so it can grant itself UPDATE \
                 and DELETE, disable the chain trigger or drop the table",
                self.role
            ));
        }
        if !self.ledger_write_privileges.is_empty() {
            return Some(format!(
                "role {} holds {} on the event table",
                self.role,
                self.ledger_write_privileges.join(", ")
            ));
        }
        None
    }
}

/// Read [`RoleStatus`] for the role `pool` connects as.
pub async fn role_status(pool: &PgPool) -> Result<RoleStatus, sqlx::Error> {
    let row = sqlx::query(
        "SELECT current_user::text AS role, \
                e.oid IS NOT NULL AS ledger_exists, \
                (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) \
                  OR COALESCE(pg_has_role(current_user, e.relowner, 'USAGE'), false) \
                  AS controls_ledger, \
                has_schema_privilege(current_user, current_schema(), 'CREATE') AS can_create, \
                COALESCE(has_table_privilege(current_user, e.oid, 'SELECT') \
                         AND has_table_privilege(current_user, e.oid, 'INSERT'), false) \
                  AS can_append, \
                COALESCE(has_table_privilege(current_user, e.oid, 'UPDATE'), false) AS can_update, \
                COALESCE(has_table_privilege(current_user, e.oid, 'DELETE'), false) AS can_delete, \
                COALESCE(has_table_privilege(current_user, e.oid, 'TRUNCATE'), false) \
                  AS can_truncate, \
                COALESCE(has_table_privilege(current_user, e.oid, 'TRIGGER'), false) \
                  AS can_trigger \
         FROM (SELECT 1) AS one \
         LEFT JOIN pg_class e ON e.oid = to_regclass('event')",
    )
    .fetch_one(pool)
    .await?;
    let mut ledger_write_privileges = Vec::new();
    for (column, name) in [
        ("can_update", "UPDATE"),
        ("can_delete", "DELETE"),
        ("can_truncate", "TRUNCATE"),
        ("can_trigger", "TRIGGER"),
    ] {
        if row.try_get::<bool, _>(column)? {
            ledger_write_privileges.push(name);
        }
    }
    Ok(RoleStatus {
        role: row.try_get("role")?,
        ledger_exists: row.try_get("ledger_exists")?,
        controls_ledger: row.try_get("controls_ledger")?,
        can_create: row.try_get("can_create")?,
        can_append: row.try_get("can_append")?,
        ledger_write_privileges,
    })
}

/// The role name migration `0004_harden_event_table.sql` revokes ledger privileges from, in a
/// database of the same name. That migration is applied-once and cannot be changed.
const LEGACY_REVOKED_ROLE: &str = "propolis";

/// Give the owner role its full rights on the ledger back, before it migrates.
///
/// On a node that ran with one role, migration 0004 revoked `UPDATE, DELETE, TRUNCATE ON event`
/// from that role while it was the owner, and `REASSIGN OWNED` hands the new owner the same
/// reduced entry. Later migrations take `LOCK TABLE event IN SHARE MODE`, which PostgreSQL 16 and
/// earlier allow only to a role holding one of those privileges, owner or not, so the owner's
/// migrations would fail there. The owner is the role the ledger is not protected from by design
/// (its credential is what the daemon cannot read), so its holding them changes nothing.
pub async fn restore_owner_ledger_rights(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "DO $$ BEGIN \
           IF to_regclass('event') IS NOT NULL THEN \
             GRANT ALL ON event TO CURRENT_USER; \
           END IF; \
         END $$",
    )
    .execute(pool)
    .await
    .map(|_| ())
}

/// Migrate as the one role of a deployment that has not split its roles.
///
/// In a database named `propolis`, migration 0004 revokes `UPDATE, DELETE, TRUNCATE ON event` from
/// the role `propolis`, which here is the table's owner, and migrations 0014 and 0025 then take
/// `LOCK TABLE event IN SHARE MODE`. PostgreSQL 16 and earlier refuse that lock to a role holding
/// none of the three, owner or not, so on those servers a new database stopped at 0014 with
/// `permission denied for table event`. When a run fails and this role is an owner in exactly that
/// position, it is lent `UPDATE` for one more run and the revoke is put back afterwards, whatever
/// that run's result: the ledger ends with the privileges 0004 left.
pub async fn migrate_single_role(pool: &PgPool) -> Result<(), String> {
    let first = match run_migrations(pool).await {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    let lent = lend_ledger_lock_right(pool)
        .await
        .map_err(|e| format!("{first} (and reading this role's ledger rights failed: {e})"))?;
    if !lent {
        return Err(first);
    }
    let second = run_migrations(pool).await;
    sqlx::raw_sql("REVOKE UPDATE, DELETE, TRUNCATE ON event FROM CURRENT_USER")
        .execute(pool)
        .await
        .map_err(|e| format!("cannot put the ledger's revoke back: {e}"))?;
    second
}

/// Grant the connected role `UPDATE ON event` if it owns the table and holds none of `UPDATE`,
/// `DELETE` and `TRUNCATE` on it. Returns whether it did.
pub async fn lend_ledger_lock_right(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let revoked_owner: bool = sqlx::query_scalar(
        "SELECT COALESCE(( \
           SELECT pg_get_userbyid(c.relowner) = current_user \
              AND NOT has_table_privilege(current_user, c.oid, 'UPDATE') \
              AND NOT has_table_privilege(current_user, c.oid, 'DELETE') \
              AND NOT has_table_privilege(current_user, c.oid, 'TRUNCATE') \
           FROM pg_class c WHERE c.oid = to_regclass('event')), false)",
    )
    .fetch_one(pool)
    .await?;
    if revoked_owner {
        sqlx::raw_sql("GRANT UPDATE ON event TO CURRENT_USER")
            .execute(pool)
            .await?;
    }
    Ok(revoked_owner)
}

/// Set the runtime role's privileges to exactly what the daemon needs, as the owner role.
///
/// Everything the role holds on the schema's tables and sequences is revoked first, so a privilege
/// granted by hand does not survive. Then: read and write on every table, read-only on the
/// migration bookkeeping tables, and on `event` only `SELECT` and `INSERT`. The role name reaches
/// the statements through a transaction-local setting and `format('%I')`, so it is quoted by
/// PostgreSQL and no statement text is assembled here.
///
/// Refuses a runtime role that could undo the result: a superuser, the connected role itself, or
/// a member of it.
pub async fn reconcile_runtime_grants(
    pool: &PgPool,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('propolis.runtime_role', $1, true)")
        .bind(runtime_role)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(RECONCILE_SQL).execute(&mut *tx).await?;
    tx.commit().await
}

const RECONCILE_SQL: &str = r#"
DO $reconcile$
DECLARE
  r text := current_setting('propolis.runtime_role');
  s text := current_schema();
  super boolean;
BEGIN
  SELECT rolsuper INTO super FROM pg_roles WHERE rolname = r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'runtime role % does not exist', r;
  END IF;
  IF super THEN
    RAISE EXCEPTION 'runtime role % is a superuser; no grant can restrict it', r;
  END IF;
  IF pg_has_role(r, current_user, 'USAGE') THEN
    RAISE EXCEPTION 'runtime role % is, or is a member of, the owner role %; it would keep the owner''s rights', r, current_user;
  END IF;

  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', s, r);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', s, r);
  EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', s, r);
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s, r);
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I', s, r);
  EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', s, r);

  -- The ledger: append and read, nothing else.
  EXECUTE format('REVOKE UPDATE, DELETE ON event FROM %I', r);
  -- The migration history is the owner's record of what it applied.
  EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations FROM %I', r);
  EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations_review FROM %I', r);
  EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations_fleet FROM %I', r);
END
$reconcile$;
"#;

/// Split a database into an owner role and a runtime role, as a superuser, in one transaction.
///
/// Creates either role that does not exist (login, no password: authentication is the operator's
/// to set), hands everything the runtime role owns in this database, and the database itself, to
/// the owner, and takes the runtime role's right to create objects. It grants the runtime role
/// nothing on the tables: [`reconcile_runtime_grants`] does that, as the owner, right after.
/// Running it again changes nothing.
///
/// Refuses while the runtime role has connections open to the database: the moment ownership
/// moves that role can no longer read a table, so a running daemon would start failing.
pub async fn init_roles(admin: &PgPool, owner: &str, runtime: &str) -> Result<(), sqlx::Error> {
    let mut tx = admin.begin().await?;
    sqlx::query(
        "SELECT set_config('propolis.owner_role', $1, true), \
                set_config('propolis.runtime_role', $2, true)",
    )
    .bind(owner)
    .bind(runtime)
    .execute(&mut *tx)
    .await?;
    sqlx::raw_sql(INIT_ROLES_SQL).execute(&mut *tx).await?;
    tx.commit().await
}

const INIT_ROLES_SQL: &str = r#"
DO $init$
DECLARE
  o text := current_setting('propolis.owner_role');
  r text := current_setting('propolis.runtime_role');
  db text := current_database();
  s text := current_schema();
BEGIN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'role % is not a superuser; splitting the roles moves ownership, which only a superuser can do', current_user;
  END IF;
  IF o = '' OR r = '' OR o = r THEN
    RAISE EXCEPTION 'the owner role and the runtime role must be two different names';
  END IF;
  IF o = 'propolis' THEN
    RAISE EXCEPTION 'the owner role cannot be named propolis: an applied migration revokes ledger privileges from a role of that name. Keep propolis as the runtime role and name the owner something else (propolis_owner)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    EXECUTE format('CREATE ROLE %I LOGIN', r);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = o) THEN
    EXECUTE format('CREATE ROLE %I LOGIN', o);
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN (o, r) AND rolsuper) THEN
    RAISE EXCEPTION 'neither % nor % may be a superuser', o, r;
  END IF;
  IF pg_has_role(r, o, 'USAGE') THEN
    RAISE EXCEPTION 'role % is a member of %; it would keep the owner''s rights. Revoke the membership first', r, o;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_stat_activity
             WHERE datname = db AND usename = r AND pid <> pg_backend_pid()) THEN
    RAISE EXCEPTION 'role % has connections open to database %; stop propolis first', r, db;
  END IF;

  -- A role that can create roles can make itself a member of the owner.
  EXECUTE format('ALTER ROLE %I NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  EXECUTE format('REASSIGN OWNED BY %I TO %I', r, o);
  EXECUTE format('ALTER DATABASE %I OWNER TO %I', db, o);
  EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', s);
  EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', s, r);
  EXECUTE format('GRANT ALL ON SCHEMA %I TO %I', s, o);
  EXECUTE format('REVOKE CREATE ON DATABASE %I FROM %I', db, r);
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', db, r);
END
$init$;
"#;

/// What the daemon does about the schema at startup. `Err` is a message to log before exiting.
pub async fn prepare_schema(pool: &PgPool) -> Result<(), String> {
    let status = role_status(pool)
        .await
        .map_err(|e| format!("cannot read this role's privileges: {e}"))?;
    if status.is_owner() {
        migrate_single_role(pool).await?;
        tracing::warn!(
            role = %status.role,
            "propolis: connected as the role that owns the schema, so the ledger's append-only \
             control does not bind this process; see docs/operations/database-roles.md"
        );
        return Ok(());
    }
    let pending = pending_migrations(pool)
        .await
        .map_err(|e| format!("cannot read the migration history: {e}"))?;
    if !pending.is_empty() {
        return Err(format!(
            "role {} cannot migrate and the schema is not the one this binary expects ({}); run \
             `propolis migrate` as the owner role first",
            status.role,
            pending.join("; ")
        ));
    }
    match status.exposure() {
        Some(why) => tracing::warn!(
            reason = %why,
            "propolis: the ledger is not protected from this role; run `propolis migrate` as the \
             owner role to reset its grants"
        ),
        None => tracing::info!(
            role = %status.role,
            "propolis: schema is current; this role can append to the ledger and cannot change it"
        ),
    }
    Ok(())
}

pub const MIGRATE_USAGE: &str = "usage: propolis migrate [--check | --init-roles --owner ROLE --runtime ROLE]\n  \
     (no flag)     apply pending migrations as PROPOLIS_MIGRATE_DATABASE_URL, then reset the \
     grants of the role DATABASE_URL names\n  \
     --check       report, as DATABASE_URL, whether the schema is current and the ledger \
     protected\n  \
     --init-roles  as the superuser PROPOLIS_ADMIN_DATABASE_URL names, create the two roles if \
     missing and move ownership of the database from the runtime role to the owner role";

async fn connect(url: &str) -> Result<PgPool, String> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await
        .map_err(|e| format!("cannot connect to PostgreSQL: {e}"))
}

/// The role `DATABASE_URL` names. `None` when it names none: the driver would then use the
/// caller's operating-system user, which is root when the upgrade runs this and not the user the
/// daemon's unit runs as.
fn url_role(url: &str) -> Result<Option<String>, String> {
    use std::str::FromStr;
    if !crate::pg_exec::names_user(url)? {
        return Ok(None);
    }
    let options = sqlx::postgres::PgConnectOptions::from_str(url)
        .map_err(|e| format!("DATABASE_URL does not parse: {e}"))?;
    Ok(Some(options.get_username().to_string()))
}

/// `propolis migrate`, see [`MIGRATE_USAGE`]. Returns the process exit code: 0 done or healthy,
/// 1 failed or not healthy, 2 usage.
pub async fn run_cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let env = |name: &str| std::env::var(name).ok().filter(|u| !u.is_empty());
    let result = match args.as_slice() {
        [] => {
            migrate_cli(
                env("PROPOLIS_MIGRATE_DATABASE_URL").as_deref(),
                env("DATABASE_URL").as_deref(),
            )
            .await
        }
        ["--check"] => match env("DATABASE_URL") {
            Some(url) => check_cli(&url).await,
            None => Err("DATABASE_URL is not set".to_string()),
        },
        ["--init-roles", "--owner", owner, "--runtime", runtime]
        | ["--init-roles", "--runtime", runtime, "--owner", owner] => {
            match env("PROPOLIS_ADMIN_DATABASE_URL") {
                Some(url) => init_roles_cli(&url, owner, runtime).await,
                None => Err("PROPOLIS_ADMIN_DATABASE_URL is not set".to_string()),
            }
        }
        _ => {
            eprintln!("{MIGRATE_USAGE}");
            return 2;
        }
    };
    match result {
        Ok(healthy) => i32::from(!healthy),
        Err(e) => {
            eprintln!("propolis migrate: {e}");
            1
        }
    }
}

async fn init_roles_cli(admin_url: &str, owner: &str, runtime: &str) -> Result<bool, String> {
    let pool = connect(admin_url).await?;
    let outcome = init_roles(&pool, owner, runtime).await;
    pool.close().await;
    outcome.map_err(|e| format!("cannot split the roles: {e}"))?;
    println!(
        "propolis migrate: role {owner} now owns the database and role {runtime} owns nothing \
         in it. Role {runtime} cannot read a table until `propolis migrate` has run as {owner}; \
         run it before starting propolis"
    );
    Ok(true)
}

async fn check_cli(url: &str) -> Result<bool, String> {
    let pool = connect(url).await?;
    let status = role_status(&pool).await.map_err(|e| e.to_string())?;
    let pending = pending_migrations(&pool).await.map_err(|e| e.to_string())?;
    pool.close().await;
    println!("role: {}", status.role);
    if pending.is_empty() {
        println!("schema: current");
    } else {
        println!("schema: NOT current");
        for line in &pending {
            println!("  {line}");
        }
    }
    let exposure = status.exposure();
    match &exposure {
        Some(why) => println!("ledger: NOT protected: {why}"),
        None if !status.ledger_exists => println!("ledger: no event table yet"),
        None if !status.can_append => println!(
            "ledger: this role cannot append to it yet (its grants are set by `propolis migrate`)"
        ),
        None => println!("ledger: protected (this role can append and read, nothing else)"),
    }
    Ok(pending.is_empty() && exposure.is_none() && status.can_append)
}

async fn migrate_cli(owner_url: Option<&str>, runtime_url: Option<&str>) -> Result<bool, String> {
    let Some(url) = owner_url.or(runtime_url) else {
        return Err("neither PROPOLIS_MIGRATE_DATABASE_URL nor DATABASE_URL is set".to_string());
    };
    let pool = connect(url).await?;
    let outcome = migrate_as(&pool, owner_url.is_some(), runtime_url).await;
    pool.close().await;
    outcome
}

/// Migrate over `pool`. With an owner URL and a `DATABASE_URL` naming another role, the roles are
/// split: the owner migrates and the runtime role's grants are reset. Otherwise this is the one
/// role migrating, as the daemon does at startup.
async fn migrate_as(
    pool: &PgPool,
    has_owner_url: bool,
    runtime_url: Option<&str>,
) -> Result<bool, String> {
    let owner = role_status(pool).await.map_err(|e| e.to_string())?.role;
    let runtime = match runtime_url {
        Some(runtime_url) if has_owner_url => url_role(runtime_url)?.filter(|r| *r != owner),
        _ => None,
    };
    let Some(runtime) = runtime else {
        migrate_single_role(pool).await?;
        println!("propolis migrate: schema is current");
        println!(
            "propolis migrate: no separate runtime role (set PROPOLIS_MIGRATE_DATABASE_URL to the \
             owner role and DATABASE_URL to the role the daemon connects as), so the ledger is \
             not protected from role {owner}"
        );
        return Ok(true);
    };
    if owner == LEGACY_REVOKED_ROLE {
        return Err(format!(
            "the owner role cannot be named {LEGACY_REVOKED_ROLE}: an applied migration revokes \
             ledger privileges from a role of that name. Keep {LEGACY_REVOKED_ROLE} as the \
             runtime role and name the owner something else"
        ));
    }
    restore_owner_ledger_rights(pool)
        .await
        .map_err(|e| format!("cannot restore role {owner}'s rights on the ledger: {e}"))?;
    run_migrations(pool).await?;
    println!("propolis migrate: schema is current");
    reconcile_runtime_grants(pool, &runtime)
        .await
        .map_err(|e| format!("cannot set the grants of role {runtime}: {e}"))?;
    println!(
        "propolis migrate: role {runtime} can append to the ledger and cannot change it; role \
         {owner} owns the schema"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::url_role;

    // Everything that needs a database is in `tests/db_roles.rs`.
    #[test]
    fn the_runtime_role_is_read_from_the_url_only_when_the_url_names_one() {
        assert_eq!(
            url_role("postgres://propolis:pw@localhost/propolis").unwrap(),
            Some("propolis".to_string())
        );
        assert_eq!(
            url_role("postgres:///propolis?host=/run/postgresql&user=propolis").unwrap(),
            Some("propolis".to_string())
        );
        assert_eq!(url_role("postgres://localhost/propolis").unwrap(), None);
        assert_eq!(
            url_role("postgres:///propolis?host=/run/postgresql").unwrap(),
            None
        );
    }
}
