//! The parts of the `propolis` daemon that its integration tests call directly, and that the
//! binary (`src/main.rs`) uses like any other dependency.
//!
//! They are a library because they need a real PostgreSQL to test, and the binary's own unit
//! tests cannot host that: the configuration tests there replace `DATABASE_URL` in the process
//! environment while they run, which is what `sqlx::test` connects with.

pub mod db_roles;
pub mod pg_exec;
