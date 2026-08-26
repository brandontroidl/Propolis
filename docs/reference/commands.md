<!--
title: Commands reference
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Commands

Runnable commands verified against the repository. Exact env-var defaults and
bounds live in [`environment-variables.md`](environment-variables.md); ports in
[`ports-and-protocols.md`](ports-and-protocols.md); paths in
[`filesystem-paths.md`](filesystem-paths.md). This page owns only the command
invocations.

The toolchain is pinned to Rust `1.96.1` with `clippy` + `rustfmt`
(`rust-toolchain.toml:6-7`); cargo selects it automatically inside the repo.
Every workspace crate is edition 2024.

## Build

```
cargo build            # debug build, all 18 workspace members
cargo build --release  # release binaries into target/release/
```

`cargo build --release` is the documented build step (`README.md:65`,
`INSTALL.md:15`); the install script expects those release binaries in
`target/release/` (`deploy/install.sh:56,205-209`).

## The gate

CI is authoritative. It runs three **independent** jobs (not one chained
sequence, deliberately, so a cheap failure cannot mask an expensive one) on
every push and pull request (`.github/workflows/ci.yml`):

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
set -o pipefail
cargo test --workspace --locked -- --test-threads=1 2>&1 | tee /tmp/test-output.txt
```

- `--all-targets` in clippy compiles test targets, so a non-compiling test file
  fails there rather than silently vanishing from the suite.
- `--test-threads=1` runs the suite serially; `set -o pipefail` is mandatory so
  the `tee` pipe cannot report green over a red suite.
- `--locked` enforces the committed `Cargo.lock` frozen.

`CONTRIBUTING.md:11` gives a shorter chained form
(`cargo fmt --check && cargo clippy -- -D warnings && cargo test`); it omits the
scope flags above and bails on first failure, so treat CI as authoritative. See
[`../development/build-and-test.md`](../development/build-and-test.md) for the
full test taxonomy.

### Single crate / single test

```
cargo test -p console                       # one crate
cargo test -p console -- --ignored rdns     # the one #[ignore]d live rDNS test (egress, see below)
```

> **Egress warning.** `cargo test -p console -- --ignored rdns` performs a live
> reverse-DNS lookup (`crates/console/src/rdns.rs:186-191`). It is `#[ignore]`d
> precisely so the default suite stays offline-deterministic. Run it only when a
> real DNS query is acceptable.

## Test database

DB-backed tests use `sqlx::test`, which provisions a fresh database per test.
Provide `DATABASE_URL` and a reachable PostgreSQL 18 server. Local dev uses a
disposable, localhost-only, trust-auth container
(`.env`, gitignored via `.gitignore:7`):

```
podman run -d --name propolis-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 \
  docker.io/library/postgres:18
# then, on later sessions:
podman start propolis-pg
```

`DATABASE_URL` differs across sources (CI `postgres@localhost/postgres`, `.env`
`postgres@127.0.0.1/postgres`, `CONTRIBUTING.md:10`
`propolis:...@localhost/propolis_test`). Match your local `.env`; see
[`environment-variables.md`](environment-variables.md).

## Running a component locally

Each crate that produces a binary is runnable with `cargo run -p <crate>`.
Every binary reads its configuration from environment variables **only** and
refuses to start on a malformed value rather than substituting a default
(`crates/sensor-catchall/src/main.rs:6-13`,
`crates/review/src/main.rs` module doc). Set the required vars first; see
[`environment-variables.md`](environment-variables.md).

### A single sensor

```
cargo run -p sensor-ssh        # binds its configured TCP/UDP address, writes NDJSON event logs
```

The nine sensor binaries are `sensor-{catchall,ssh,telnet,redis,adb,http,ftp,smtp,cred}`.
A sensor has no compiled-in default port; the bind address comes from its env
config (`/etc/propolis/<x>.env` in production).

### The unified daemon

```
cargo run -p propolis          # intake + review + feed + console + VT + fetcher + ops-monitor
```

`propolis` connects the `PgPool`, applies migrations (see below), then spawns
each subsystem as a supervised tokio task. The console listens on
`config.console_bind` (default `127.0.0.1:8080`,
`crates/propolis/src/main.rs`/`config.rs:29`). Review, feed, VirusTotal,
fetcher, and the ops-monitor are each **opt-in** and default OFF; when enabled,
several are outbound paths (see warning under Operations). See
[`../architecture/process-topology.md`](../architecture/process-topology.md).

## Migrations

There is no standalone migrate command in the shipped surface. The `propolis`
daemon applies both migration histories against the one database at startup,
in order: core-scoring (`crates/core-scoring/migrations/`, 11 files) then review
(`crates/review/migrations/`, 3 files), each exiting `1` on failure
(`crates/propolis/src/main.rs:555-566`). Review carries its own migrator that
renames its bookkeeping table to `_sqlx_migrations_review`
(`crates/review/src/lib.rs:25-49`) because both histories number from `0001`.
See [`../development/schema-and-migrations.md`](../development/schema-and-migrations.md)
and [`database.md`](database.md).

## Vendoring

All dependencies are vendored in-tree under `vendor/`. After adding or updating
a dependency:

> **Egress warning.** `cargo vendor` and any dependency add/update fetches from
> the network (crates.io). Do this on a workstation, not on the honeypot node.

```
cargo vendor                                  # re-materialize vendor/ from Cargo.lock
cargo build --release --locked                # MUST re-verify release after re-vendoring
```

The release build after re-vendoring is load-bearing: EOL normalization has
mangled vendored checksums before. See
[`dependencies.md`](dependencies.md).

## Deploy / install

> **Production warning.** The following touch a production host. Read
> [`../operations/installation.md`](../operations/installation.md) first. Build
> release binaries before running the installer.

```
sudo ./deploy/install.sh --dry-run    # prints every action, needs no privilege, touches nothing
sudo ./deploy/install.sh              # installs binaries + units; starts/enables NOTHING
```

`install.sh` provisions OS users, directories, spool mountpoints, the release
binaries, `propolis.service` + the 9 sensor units, and a logrotate config. It
does **not** start or enable any service, create/migrate the database, or write
any `/etc/propolis/*.env` file (`deploy/install.sh:19-32,229-234`). Starting a
service is a separate operator action taken only after populating the env files:

> **Production warning.** Enabling a unit starts a live honeypot and, if the
> corresponding subsystems are turned on, activates operator-gated egress paths.

```
sudo systemctl enable --now propolis.service      # example, per unit
```

The spool directories still need `noexec,nosuid,nodev` mounts added to
`/etc/fstab` by hand; the installer prints the exact lines and stops there
(`deploy/install.sh:171-193`). Verify with `findmnt <path>` that the mount
options are actually in effect.

## Operations

The `review` binary is the operator CLI for the review queue and vendor
submission history (`crates/review/src/cli.rs`). Queries are local; approvals
arm egress.

```
review list                       # every Pending queue entry, oldest-surfaced first
review history <ip>               # vendor submission history for an IP, most recent first
review approve <ip> --notes "..." # mark Approved
review reject  <ip> --notes "..." # never reported, not re-surfaced by a later scan
review snooze  <ip> --notes "..." # defer
review daemon                     # long-running: populate/withdraw queue + submit approved entries
```

> **Egress warning.** `review approve <ip>` does not itself send anything, but
> the submission daemon (`review daemon`, or the review subsystem inside
> `propolis` when `review_enabled`) picks up Approved entries on its next poll
> and submits them to the configured abuse vendors (AbuseIPDB / DShield / OTX).
> These are outbound reports about third parties. They are opt-in and default
> off; see [`../security/outbound-controls.md`](../security/outbound-controls.md)
> and [`integrations.md`](integrations.md).

There is no `Makefile` or `justfile` in the repository.
