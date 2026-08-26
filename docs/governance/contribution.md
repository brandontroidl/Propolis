<!--
title: Contribution governance
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Contribution governance

Canonical contribution terms for Propolis. This is the successor to the root
`CONTRIBUTING.md` pointer.

## License terms for contributions

Propolis is **source-available under the PolyForm Noncommercial License 1.0.0**,
not open source. Contributions are welcome for noncommercial use. By
contributing, you contribute under that same license; commercial use of the
project (yours or anyone's) requires a separate license from the maintainer. See
[licensing.md](licensing.md) and [`LICENSE.md`](../../LICENSE.md).

## PR flow

1. Set up the development environment — Rust toolchain (pinned in
   `rust-toolchain.toml`) and a PostgreSQL instance for the database-backed
   crates. Setup and toolchain details:
   [../development/toolchain-and-environment.md](../development/toolchain-and-environment.md).
2. Make focused, independently-verifiable commits. Commit style is lowercase
   conventional commits with a why-focused body; see
   [../development/coding-conventions.md](../development/coding-conventions.md).
3. Open a pull request against `main`.
4. CI runs the full gate on every push and pull request; the gate must be green
   before merge.

## The merge gate

Every contribution must pass the same gate CI enforces:

```
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

The gate command, its PostgreSQL requirement, the test taxonomy, and fixtures
are owned by
[../development/build-and-test.md](../development/build-and-test.md). Adding a
sensor or changing the schema has extra requirements documented under
[../development/](../development/) (see
[adding-a-sensor.md](../development/adding-a-sensor.md) and
[schema-and-migrations.md](../development/schema-and-migrations.md)).

## Dependencies

All dependencies are vendored in-tree (`vendor/`). Dependency and vendoring
policy is owned by
[../reference/dependencies.md](../reference/dependencies.md) and
[../security/supply-chain.md](../security/supply-chain.md).

## Reviewer path

Maintainer-side review expectations are in
[../development/documentation-and-review.md](../development/documentation-and-review.md);
the curated contributor walkthrough is
[../manuals/contributor.md](../manuals/contributor.md).
