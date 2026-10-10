<!--
title: Build and test
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-09
-->

# Build and test

The authoritative gate is CI (`.github/workflows/ci.yml`). Treat CI as the source
of truth; the chained one-liner in [the merge gate](../governance/contribution.md#the-merge-gate) states the
same intent but omits scope flags (see [drift](#contributing-vs-ci) below).

## Build

```
cargo build            # debug
cargo build --release  # release binaries (README.md:42, docs/operations/installation.md:25)
```

> **After any `cargo vendor`, build in release too.** A debug/test build can pass
> while a release build fails on vendored-checksum issues. Run
> `cargo build --release --locked` after re-vendoring. See
> [schema-and-migrations](schema-and-migrations.md#vendoring-and-rebuild-after-vendor).

## The gate (independent CI jobs)

CI runs **separate jobs**, deliberately not one sequential job: a single chained
job bailed on the first failure, so an unformatted tree once meant clippy and the
whole suite never ran for 30+ commits (see the header of `ci.yml`). Split this
way, a cheap failure cannot hide an expensive one.

| Job | Exact command | Needs DB |
|---|---|---|
| **fmt** | `cargo fmt --all --check` | no |
| **clippy** | `cargo clippy --workspace --all-targets --locked -- -D warnings` | no |
| **tests** | `cargo test --workspace --locked -- --test-threads=1` (under `set -o pipefail`) | yes |
| **release build** | `cargo build --release --workspace --locked` | no |
| **dependency policy** | `cargo deny check --all-features` against `deny.toml` (see [supply chain](../security/supply-chain.md#dependency-policy-denytoml)) | no |
| **shellcheck** | `shellcheck -x deploy/*.sh scripts/**/*.sh`, the `koalaman/shellcheck` v0.11.0 image pinned by digest | no |

The release job compiles the profile `deploy/upgrade.sh` ships. The other three
compile the dev profile, so a release-only break (the vendored-crate checksum
regression of 2026-08-22, which `cargo test` passed) reached the box with CI
green. It is CI-only: the local pre-push gate below stays three steps, and a
release build is run locally when packaging or vendoring changes.

Details that are load-bearing:

- **`--all-targets` on clippy** compiles the test targets, so a test file that no
  longer compiles fails at clippy rather than silently vanishing from the suite
  (`.github/workflows/ci.yml#Clippy (deny warnings)`).
- **`--test-threads=1`** runs the suite serially.
- **`set -o pipefail`** is mandatory in the tests job: without it, piping `cargo
  test` through `tee` would report `tee`'s success and pass a red suite
  (`.github/workflows/ci.yml#Tests (serial, frozen lockfile)`).
- **`--locked`** enforces the committed `Cargo.lock` frozen (clippy + tests jobs).
- An advisory `Report test totals` step (`if: always()`) sums passed/failed/ignored
  and counts test binaries into the run summary; it never fails the job
  (`.github/workflows/ci.yml#Report test totals`). It exists so a sudden drop in how much ran is visible to a
  human.

Running the gate locally mirrors CI:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
```

The tests job needs the test PostgreSQL running - see
[toolchain-and-environment](toolchain-and-environment.md#test-postgresql).

<a id="contributing-vs-ci"></a>
### CONTRIBUTING vs CI

[the merge gate](../governance/contribution.md#the-merge-gate) gives the gate as
`cargo fmt --check && cargo clippy -- -D warnings && cargo test`. That is the
intent, but it omits `--all`, `--workspace`, `--all-targets`, `--locked`,
`--test-threads=1`, and its chained `&&` bails on first failure - the exact
anti-pattern the split CI jobs exist to avoid. Use the CI commands.

## Test taxonomy

Counted by `#[test]` / `#[tokio::test]` / `#[sqlx::test]` attributes. "Unit" = under
`crates/<c>/src/` (`#[cfg(test)]`); "integration" = under `crates/<c>/tests/`.

- **Total: 4119 test functions** (2613 unit + 1506 integration).
- **DB-backed (`sqlx::test`): 411** - console 213, review 97, core-scoring 44,
  intake 30, feed 11, fleet 9, propolis 7. These provision a fresh database per test.
- **Ignored: exactly 3.** `live_forward_confirmed_reverse_lookup_of_a_stable_public_ip`
  in `crates/console/src/rdns.rs`, a live reverse-lookup test `#[ignore]`d so the
  default suite stays offline-deterministic; run it manually with
  `cargo test -p console -- --ignored rdns`.
  `crates/propolis/tests/restore_rehearsal.rs`, the populated backup and restore
  rehearsal, which needs PostgreSQL server binaries CI does not install; its
  command and last recorded result are in
  [backup and restore](../operations/backup-and-restore.md#restore-rehearsal). And
  `private_sessions_replay_byte_for_byte` in
  `crates/sensor-framework/tests/shell_replay.rs`, which replays session fixtures
  kept outside the repository; run it with `PROPOLIS_PRIVATE_SESSIONS=<dir> cargo test
  -p sensor-framework --test shell_replay -- --ignored`.
- **Outside the suite entirely: one browser fixture.** The console's stale-poll
  handling has to be checked in a real browser against a real hung socket - the
  suite can only check that the guarding code ships. Run by hand when the console's
  polled panels or the vendored HTMX change; see
  [browser-fixtures](browser-fixtures.md).
- **Outside the suite as well: the intake soak.** Hours of sustained load through the real intake
  path, with rotation and faults, is a harness you run by hand
  (`crates/propolis/examples/soak/main.rs`); see [intake-soak](intake-soak.md).

These are static attribute counts, not a live `cargo test --list` run. Every figure
in this section, and the table below row for row, is recomputed from the source and
`cargo metadata` by `crates/propolis/tests/docs_agreement.rs`, so a change that adds,
removes or ignores a test fails the suite until this page says so.

Per-crate breakdown:

| Crate | Unit | Integration | Integration files |
|---|---|---|---|
| collector-wire | 9 | 0 | - |
| console | 165 | 236 | auth_test, campaigns_test, ledger_count_test, routes_test, samples_transport_test, server_test, timeline_test |
| core-scoring | 80 | 38 | batch_equivalence, coverage, end_to_end, migrations, replay, repository, smoke, telemetry |
| feed | 35 | 66 | builder_test, exclusion_test, export_test, publisher_test |
| fleet | 26 | 35 | deploy_inventory_test, probe_test, stats_test, store_test |
| gateway | 11 | 13 | handshake, spool, verify |
| geoip | 4 | 0 | - |
| intake | 29 | 49 | audit_regressions, batched_runner, converter_test, end_to_end, probe_filter, quarantine, sensor_stats, shell_reply |
| log-tailer | 7 | 88 | copytruncate_drain_test, cursor_test, cursorless_test, tailer_test |
| propolis | 140 | 33 | capture_to_console, coverage, docs_agreement, restore_rehearsal, shadow_diff, shell_explain, smoke_test, ssh_capture_to_console |
| provision-certs | 0 | 16 | provision |
| review | 196 | 102 | allowlist_test, attack_test, campaign_replica_test, campaign_test, cli_test, fetcher_proxy_test, fetcher_schema_test, fetcher_trust_store_test, gatekeeper_test, queue_test, submit_test, vendor_test, virustotal_upload_filter_test |
| sensor-adb | 61 | 45 | arrival, env_strict, integration, shutdown_tracking |
| sensor-catchall | 18 | 9 | arrival, env_strict, integration |
| sensor-cred | 32 | 40 | arrival, env_strict, integration, tls_integration |
| sensor-dns | 64 | 70 | arrival, env_strict, integration, tls |
| sensor-framework | 1347 | 177 | arrival_coverage, budget_product_test, build_stamp_test, command_flood, config_check_test, deploy_test, listener_integration, shell_replay, spool_integration, stats_wiring_test, tls_integration |
| sensor-ftp | 14 | 53 | arrival, env_strict, integration, tls_config |
| sensor-http | 19 | 41 | arrival, env_strict, integration, tls |
| sensor-mqtt | 65 | 57 | arrival, env_strict, integration, shutdown_tracking, tls |
| sensor-redis | 89 | 39 | arrival, env_strict, integration, tls |
| sensor-smtp | 12 | 41 | arrival, env_strict, integration, tls |
| sensor-ssh | 66 | 129 | arrival, auth_test, crypto_test, env_strict, integration, shell_test, shutdown_tracking, transport_test |
| sensor-telnet | 51 | 42 | arrival, echo_loader, env_strict, infected_hold, integration, shutdown_tracking |
| sensor-tftp | 37 | 42 | arrival, env_strict, integration, shutdown |
| sensor-wire | 18 | 0 | - |
| shipper | 4 | 24 | acceptance, audit_regressions, batcher, config, end_to_end |
| watch | 14 | 21 | config, read_only, status, stream |
| **Total** | **2613** | **1506** | |

### Test styles by layer

- **Sensor crates** test with **real TCP** against an ephemeral `:0` listener per
  connection (e.g. `crates/sensor-catchall/tests/integration.rs#tcp_probe_emits_catchall_probe_event`), plus static-check tests that enforce the
  sensor contract (see [adding-a-sensor](adding-a-sensor.md#the-tests-a-sensor-must-pass)).
- **DB crates** use `sqlx::test`. Migrations are applied one of two ways:
  `#[sqlx::test(migrations = "./migrations")]` auto-applies that crate's own set
  (43 uses); `#[sqlx::test(migrations = false)]` provisions an empty DB and the test
  applies migrations manually (365 uses) - needed wherever a test needs more than
  one migration history in one database, a history that keeps its own
  bookkeeping table (review, fleet), or a history applied only part of the way
  (`crates/core-scoring/src/repository/breadth_sets_tests.rs#migration_0014_backfills_the_sets_from_the_ledger`
  stops at `0013`, writes a ledger, then applies the rest). A bare
  `#[sqlx::test]` (3 uses, the console's `/ready` tests) also gets an empty
  database, because the console crate has no `migrations/` directory; those tests
  need only a live connection. See
  [schema-and-migrations](schema-and-migrations.md).

### Notable enforcement test: doc/code agreement

`crates/propolis/tests/docs_agreement.rs` fails CI when the docs and the tree
disagree on a fact that has drifted before:

- any `PROPOLIS_*` / `CATCHALL_*` env-var name that appears as a string literal in
  non-test source but is missing from the
  [environment variable reference](../reference/environment-variables.md)
  (direction: code to docs). It guards a real twice-shipped drift
  (`PROPOLIS_CATCHALL_BIND` vs `CATCHALL_BIND_ADDRS`) where a sensor refused to
  start with no hint why;
- an em dash in live docs or source;
- a documented `tar` command that names the same tree twice;
- a current page whose `applies-to` front matter is not the workspace version;
- a count of crates, members or binaries in a current page that is not the workspace
  total from `cargo metadata` (counts qualified as sensor, protocol, installed, test
  or archive figures are exempt);
- a backticked version beside "tree", "currently" or "Crate version" that is not the
  workspace version, or one beside "Rust" or "toolchain" that is not the
  `rust-toolchain.toml` pin (other versions, such as dependencies', are exempt);
- a [component inventory](../architecture/components.md) row or dependency edge that
  differs from `cargo metadata`;
- a [migration change map](../reference/database.md#migration-change-map) that does
  not list exactly the migration files on disk;
- any figure in the test taxonomy above;
- a citation of code by line number, in any form: `path:N`, `file.rs:N`, a `:N`
  span, or a `name:N` span naming a Rust item. Code is cited as `path#symbol`
  ([documentation policy](../documentation-policy.md#citing-code));
- a `path#symbol` citation whose file does not exist or does not contain the
  symbol. A path is resolved from the workspace root, from `crates/`, or as the
  tail of a path in the workspace (`routes/mod.rs`); a tail several files share
  passes if any of them has the symbol, and `crates/*/` requires it in every crate.
  A Rust symbol must appear as a whole word; any other anchor, such as a systemd
  directive or a heading, verbatim.

Historical pages, `CHANGELOG.md`, the dated claim ledger and the sanitizer record
are exempt from the version, count and citation checks: they record what was true
when they were written.

Runnable command reference lives in [`reference/commands`](../reference/commands.md).
