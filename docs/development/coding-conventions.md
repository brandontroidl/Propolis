<!--
title: Coding conventions
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Coding conventions

The enforced conventions (fmt, clippy-deny-warnings) are checked by CI on every
push and pull request - see [build-and-test](build-and-test.md). The rest are
stated in `CONTRIBUTING.md` and observable in the tree.

## Language and formatting

- **Rust 2024 edition** on every crate (`crates/*/Cargo.toml:4`, `CONTRIBUTING.md:18`).
- **Pinned toolchain** `1.96.1` - see [toolchain-and-environment](toolchain-and-environment.md).
- **`cargo fmt`** with default rustfmt config (no `rustfmt.toml` in the tree).
  `cargo fmt --all --check` is a CI gate (`CONTRIBUTING.md:18`, `ci.yml:49`).
- **Line endings LF**, final newline, trimmed trailing whitespace, UTF-8, 4-space
  Rust indent - enforced by `.editorconfig`.

## Lint

`cargo clippy --workspace --all-targets --locked -- -D warnings` must pass - clippy
runs with **warnings denied**, so any lint is a hard failure (`CONTRIBUTING.md:19`,
`ci.yml:70`). `--all-targets` means test code is linted too.

## Comments

Comment the **why**, never the **what**. `CONTRIBUTING.md:21`: "No comments
restating what the code does. Comment only the non-obvious why." The tree follows
this - comments explain constraints, invariants, and workarounds (e.g. the frozen
hash-chain encoding, the serde casing asymmetry, `pipefail` in CI), not line-by-line
narration.

## Commits

Conventional commits, **lowercase**, with a why-focused body (`CONTRIBUTING.md:20`).
Example subject line (example only):

```
fix(sensor-ftp): validate the passive data peer against the control source IP
```

## `unsafe`

`unsafe` is used **sparingly and deliberately**, each block carrying a `SAFETY`
justification; the workspace does **not** apply `#![forbid(unsafe_code)]`. Verified
uses in project (non-vendored) source:

- `crates/console/src/rdns.rs` - libc FFI for the forward-confirmed reverse-DNS
  resolver (`getnameinfo`, `CStr::from_ptr`, zeroed `sockaddr`), `SAFETY`-commented
  (`rdns.rs:107-138`).
- `crates/propolis/src/config.rs` - `unsafe { env::set_var / remove_var }` inside
  `#[cfg(test)]` only; Rust 2024 marks these functions `unsafe` because process
  environment mutation is global cross-thread state (`config.rs:699-768`).

No other project source contains `unsafe` blocks. Sensor crates additionally keep
`tokio`'s `process` feature off and are guarded by static tests that reject
process-spawning code - see
[adding-a-sensor](adding-a-sensor.md#the-tests-a-sensor-must-pass).

## Types and structure

Observable patterns (not a written style guide, `[inferred]` from the tree):
precise domain types with `sqlx::Type` enums mirroring the DB enums; fail-closed
config parsing that rejects malformed or zero-valued bounds at startup rather than
substituting a default; single-source-of-truth tables (e.g. `signal_weight`) that
callers derive from rather than recompute. See [`reference/database`](../reference/database.md)
and [`reference/events-and-signals`](../reference/events-and-signals.md) for the
concrete shapes these produce.
