<!--
title: Build and test
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Build and test

The authoritative gate is CI (`.github/workflows/ci.yml`). Treat CI as the source
of truth; the chained one-liner in `CONTRIBUTING.md:11` states the same intent but
omits scope flags (see [drift](#contributing-vs-ci) below).

## Build

```
cargo build            # debug
cargo build --release  # release binaries (README.md:65, INSTALL.md:15)
```

> **After any `cargo vendor`, build in release too.** A debug/test build can pass
> while a release build fails on vendored-checksum issues. Run
> `cargo build --release --locked` after re-vendoring. See
> [schema-and-migrations](schema-and-migrations.md#vendoring).

## The gate (three independent CI jobs)

CI runs **three separate jobs**, deliberately not one sequential job: a single
chained job bailed on the first failure, so an unformatted tree once meant clippy
and the whole suite never ran for 30+ commits (`ci.yml:7-13`). Split this way, a
cheap failure cannot hide an expensive one.

| Job | Exact command | Needs DB |
|---|---|---|
| **fmt** | `cargo fmt --all --check` | no |
| **clippy** | `cargo clippy --workspace --all-targets --locked -- -D warnings` | no |
| **tests** | `cargo test --workspace --locked -- --test-threads=1` (under `set -o pipefail`) | yes |

Details that are load-bearing:

- **`--all-targets` on clippy** compiles the test targets, so a test file that no
  longer compiles fails at clippy rather than silently vanishing from the suite
  (`ci.yml:66-68`).
- **`--test-threads=1`** runs the suite serially.
- **`set -o pipefail`** is mandatory in the tests job: without it, piping `cargo
  test` through `tee` would report `tee`'s success and pass a red suite
  (`ci.yml:103-108`).
- **`--locked`** enforces the committed `Cargo.lock` frozen (clippy + tests jobs).
- An advisory `Report test totals` step (`if: always()`) sums passed/failed/ignored
  and counts test binaries into the run summary; it never fails the job
  (`ci.yml:115-143`). It exists so a sudden drop in how much ran is visible to a
  human.

Running the gate locally mirrors CI:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
```

The tests job needs the test PostgreSQL running — see
[toolchain-and-environment](toolchain-and-environment.md#test-postgresql).

<a id="contributing-vs-ci"></a>
### CONTRIBUTING vs CI

`CONTRIBUTING.md:11` gives the gate as
`cargo fmt --check && cargo clippy -- -D warnings && cargo test`. That is the
intent, but it omits `--all`, `--workspace`, `--all-targets`, `--locked`,
`--test-threads=1`, and its chained `&&` bails on first failure — the exact
anti-pattern the split CI jobs exist to avoid. Use the CI commands.

## Test taxonomy

Counted by `#[test]` / `#[tokio::test]` / `#[sqlx::test]` attributes. "Unit" = under
`crates/<c>/src/` (`#[cfg(test)]`); "integration" = under `crates/<c>/tests/`.

- **Total: 1165 test functions** (681 unit + 484 integration).
- **DB-backed (`sqlx::test`): 116** — console 87, core-scoring 23, intake 3,
  propolis 2, feed 1. These provision a fresh database per test.
- **Ignored: exactly 1** — `crates/console/src/rdns.rs:190`, a live reverse-lookup
  test `#[ignore]`d so the default suite stays offline-deterministic. Run it
  manually: `cargo test -p console -- --ignored rdns` (`rdns.rs:186-191`).

> The prior memory index cited "~946 tests"; the current attribute count is 1165.
> These counts are static attribute counts, not a live `cargo test --list` run.

Per-crate breakdown:

| Crate | Unit | Integration | Integration files |
|---|---|---|---|
| console | 68 | 101 | auth_test, routes_test |
| core-scoring | 63 | 24 | end_to_end, migrations, replay, repository, smoke |
| feed | 32 | 55 | builder_test, exclusion_test, export_test, publisher_test |
| geoip | 4 | 0 | — |
| intake | 11 | 42 | converter_test, cursor_test, end_to_end, tailer_test |
| propolis | 79 | 3 | docs_agreement, smoke_test |
| review | 76 | 59 | cli_test, fetcher_schema_test, gatekeeper_test, queue_test, submit_test, vendor_test |
| sensor-adb | 48 | 16 | integration |
| sensor-catchall | 17 | 6 | integration |
| sensor-cred | 13 | 8 | integration |
| sensor-framework | 98 | 26 | deploy_test, listener_integration, spool_integration |
| sensor-ftp | 4 | 10 | integration |
| sensor-http | 8 | 13 | integration |
| sensor-redis | 75 | 17 | integration |
| sensor-smtp | 6 | 10 | integration |
| sensor-ssh | 40 | 84 | auth_test, crypto_test, integration, shell_test, transport_test |
| sensor-telnet | 32 | 10 | integration |
| sensor-wire | 7 | 0 | — |
| **Total** | **681** | **484** | |

### Test styles by layer

- **Sensor crates** test with **real TCP** against an ephemeral `:0` listener per
  connection (`CONTRIBUTING.md:25-27`), plus static-check tests that enforce the
  sensor contract (see [adding-a-sensor](adding-a-sensor.md#the-tests-a-sensor-must-pass)).
- **DB crates** use `sqlx::test`. Migrations are applied one of two ways:
  `#[sqlx::test(migrations = "./migrations")]` auto-applies that crate's own set
  (20 uses); `#[sqlx::test(migrations = false)]` provisions an empty DB and the test
  applies migrations manually (88 uses) — needed wherever both the core-scoring and
  review histories are required in one database. See
  [schema-and-migrations](schema-and-migrations.md).

### Notable enforcement test: doc/code agreement

`crates/propolis/tests/docs_agreement.rs` fails CI if any `PROPOLIS_*` / `CATCHALL_*`
env-var name that appears as a string literal in non-test source is missing from
`INSTALL.md` (direction: code → docs). It guards a real twice-shipped drift
(`PROPOLIS_CATCHALL_BIND` vs `CATCHALL_BIND_ADDRS`) where a sensor refused to start
with no hint why (`docs_agreement.rs:1-10`).

Runnable command reference lives in [`reference/commands`](../reference/commands.md).
