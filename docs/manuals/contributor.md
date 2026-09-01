<!--
title: Contributor manual
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Contributor manual

A guided path through the canonical developer documentation for someone landing
a change in Propolis. It sequences the corpus and calls out the invariants a
change must not break; the exact values live in the pages it links, not here.

Propolis is **source-available under the PolyForm Noncommercial License 1.0.0**,
not open source. Contributions are welcome for noncommercial use and are made
under that same license. Read [contribution terms](#contribution-governance-and-license)
before opening a pull request.

## 1. Get oriented: the repository

Start with the [repository tour](../development/repository-tour.md). It maps the
tree and the 18 workspace crates by concern (foundation libraries, the sensor
layer, the data plane, the unified daemon), and points at the canonical owner for
each class of fact. There is no `Makefile` or `justfile`: build and test are
plain `cargo`.

The full component inventory with binaries and dependency edges is in
[`architecture/components`](../architecture/components.md); the system context is
[`architecture/index`](../architecture/index.md).

## 2. Set up the toolchain and test database

The [toolchain and environment](../development/toolchain-and-environment.md) page
owns setup. In short:

- The Rust toolchain is pinned to the **exact** version in
  `rust-toolchain.toml` (not `stable`), with `clippy` and `rustfmt`; `rustup`
  supplies the matched components. All crates are edition 2024.
- The suite is **not fully offline**: the database-backed crates test against a
  real PostgreSQL via `sqlx::test`, which provisions a fresh database per test.
  Use the committed `.env` value for `DATABASE_URL`, not the different form in
  `CONTRIBUTING.md` (the page documents the discrepancy).

> **Trust-auth dev container.** The documented local PostgreSQL recipe is a
> throwaway `trust`-auth container bound to `127.0.0.1` only. Do not expose it or
> reuse that posture for any real database.

## 3. Run the gate

The authoritative gate is CI (`.github/workflows/ci.yml`), documented in
[build and test](../development/build-and-test.md). It runs **three independent
jobs** rather than one chained job, so a cheap failure (fmt) cannot hide an
expensive one (the suite) - a single chained job once left clippy and tests
un-run for 30+ commits. Run all three locally before pushing:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
```

The tests job needs the test PostgreSQL running. Use these commands, not the
shorter chained one-liner in `CONTRIBUTING.md`: that intent form omits `--all` /
`--workspace` / `--all-targets` / `--locked` / `--test-threads=1` and its chained
`&&` bails on the first failure - the exact anti-pattern the split jobs exist to
avoid.

> **After any `cargo vendor`, also build in release.** A vendored-checksum break
> surfaces only in a release build: run `cargo build --release --locked`, not just
> `cargo test`. See [step 6](#6-schema-and-dependency-changes).

## 4. Understand the test taxonomy

[Build and test](../development/build-and-test.md#test-taxonomy) owns the counts
and structure. The shape you need to match:

- **Sensor crates** test with **real TCP** against an ephemeral `:0` listener per
  connection, plus static-check tests that enforce the sensor contract.
- **DB crates** use `sqlx::test`, applying migrations either from a single crate's
  own history or manually where both the core-scoring and review histories are
  needed in one database.
- New invariants get a test that **would fail without the change** - prove
  behavior, not the implementation.

## 5. Follow the conventions

[Coding conventions](../development/coding-conventions.md) owns these. The
enforced ones (fmt, `clippy -D warnings`) are CI gates; the rest are observable in
the tree:

- **Rust 2024**, default `rustfmt` (no `rustfmt.toml`), LF endings via
  `.editorconfig`.
- **Comment the why, never the what.**
- **Lowercase conventional commits** with a why-focused body; small, bisectable
  increments.
- `unsafe` is used sparingly and each block carries a `SAFETY` justification; the
  workspace does not `#![forbid(unsafe_code)]`. Only two non-vendored `unsafe`
  sites exist (the console rDNS FFI and test-only env mutation).

## 6. Schema and dependency changes

Two workflows have extra rules:

- **Migrations are additive and forward-only.** Never edit an already-applied
  migration in place; add a new numbered migration. Scoring logic stays in Rust,
  not SQL. See [schema and migrations](../development/schema-and-migrations.md);
  the tables/enums/migration map are owned by
  [`reference/database`](../reference/database.md).
- **Dependencies are vendored in-tree** (`vendor/`, committed). After adding or
  updating one, run `cargo vendor` then `cargo build --release --locked`, and
  commit the vendor changes with `Cargo.lock`. Vendoring mechanics:
  [`reference/dependencies`](../reference/dependencies.md); supply-chain posture:
  [`security/supply-chain`](../security/supply-chain.md).

## 7. Adding a sensor

If your change is a new sensor, [adding or modifying a sensor](../development/adding-a-sensor.md)
is the full contract: the framework harness a sensor composes, the frozen
`sensor-wire` NDJSON format it emits, the required systemd unit, and the tests it
must pass. Sensor architecture is [`architecture/sensors`](../architecture/sensors.md);
per-protocol capture behavior is [`reference/sensor-behavior`](../reference/sensor-behavior.md).

## The invariants a change must not break

These are guarded by tests and CI; a change that violates one fails the gate (or
should be rejected in review). They are the contracts the system depends on:

| Invariant | What it protects | Enforced by |
|---|---|---|
| **Sensors are egress-free by construction** | Each attacker-facing sensor crate has no HTTP client in its dependency tree | Per-sensor test banning `reqwest`/`hyper`/`ureq`/`curl`/`isahc`/`surf`/`attohttpc` (explicit in `sensor-ssh`; by construction elsewhere - add an equivalent test to a new sensor). See [adding-a-sensor](../development/adding-a-sensor.md#the-tests-a-sensor-must-pass). |
| **Sensors never execute captured content** | No process-spawning code in a sensor crate | `never_exec_static_check` greps the crate `src/`; `tokio` `process` feature stays off. See [`security/never-execute`](../security/never-execute.md). |
| **The wire + hash-chain encoding is frozen** | Every historical ledger hash stays valid; the ledger is tamper-evident | Golden chain-hash vector; enum-serialize casing tests (bare Rust identifiers, not snake/lowercase); `observed_at` stays RFC 3339. See [schema-and-migrations](../development/schema-and-migrations.md#the-frozen-wire-contract) and [`architecture/storage`](../architecture/storage.md). |
| **Migrations are additive, never edited in place** | Persisted state is not corrupted; the current shape is what the runtime reads | Additive-change rule; a later migration explicitly refuses to duplicate tier logic in SQL. See [schema-and-migrations](../development/schema-and-migrations.md#additive-change-rule). |
| **Passwords are read-to-advance-then-dropped** | No submitted password is stored, logged, or placed on any event | `password_never_in_event` asserts absence from serialized JSON; no password field exists on the wire type. See [`security/sample-and-credential-privacy`](../security/sample-and-credential-privacy.md). |
| **Env-var names stay in sync with `INSTALL.md`** | A sensor never refuses to start over an undocumented/misnamed var | `crates/propolis/tests/docs_agreement.rs` fails CI if a `PROPOLIS_*`/`CATCHALL_*` literal in source is missing from `INSTALL.md` (code -> docs). Update `INSTALL.md` in the same change. |
| **Signal weights are total** | A new signal type cannot ship without a weight/confidence/category row | `every_signal_type_has_exactly_one_weight_row` has no default arm - a missing row fails to compile. See [`reference/events-and-signals`](../reference/events-and-signals.md#signal-weight-table). |

Maintainer-side review expectations are in
[documentation and review](../development/documentation-and-review.md).

## Contribution governance and license

- **PR flow, merge gate, and contribution terms**:
  [`governance/contribution`](../governance/contribution.md). Open PRs against
  `main`; the full gate must be green before merge.
- **License**: [`governance/licensing`](../governance/licensing.md) - PolyForm
  Noncommercial 1.0.0; noncommercial use free, commercial use needs a separate
  license. The authoritative legal text is [`LICENSE.md`](../../LICENSE.md).
- **Maintenance and support model** (single-maintainer, best-effort, no SLA):
  [`governance/maintenance-and-support`](../governance/maintenance-and-support.md).
