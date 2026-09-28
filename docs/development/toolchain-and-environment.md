<!--
title: Toolchain and environment
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Toolchain and environment

## Rust toolchain (pinned)

The toolchain is pinned to an **exact** version, not a channel (`rust-toolchain.toml:6`):

```toml
[toolchain]
channel = "1.96.1"
components = ["clippy", "rustfmt"]
```

Rationale in-file (`rust-toolchain.toml:1-5`): reproducible builds for a security
platform; a local floating `stable` resolved to a newer toolchain that did not
compile this tree cleanly. Bump the pin deliberately and re-run the full gate.
`rustup` provides matched `rustc` + `clippy` + `rustfmt` for the pinned version.

All 24 crates are **edition 2024** (each `crates/*/Cargo.toml:4`).

CI installs this toolchain via `dtolnay/rust-toolchain` pinned to commit SHA
`2fe4ca74464c5902a4f6e302d0a619b4ea911ccc` (`.github/workflows/ci.yml:44,61,100,155`).

## Test PostgreSQL

The suite is not fully offline: database-backed crates (`core-scoring`, `intake`,
`review`, `feed`, `console`) test against a real PostgreSQL using
[`sqlx`](https://crates.io) `sqlx::test`, which provisions a **fresh database per
test**. `sqlx` version is `0.9.0` (`crates/core-scoring/Cargo.toml:15`).

### Local dev container (podman)

The dev database is a disposable, localhost-only, trust-auth container named
`propolis-pg`, the same recipe as the [quickstart](../manuals/quickstart.md). A local
`.env` can hold the settings below, but it is gitignored (`.gitignore:7`) and never
committed. Create the container with:

```
podman run -d --name propolis-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 \
  docker.io/library/postgres:18
```

> **Warning - trust auth.** The container accepts any connection with no password.
> It binds `127.0.0.1` only and is a throwaway test fixture. Do not expose it, and
> do not reuse this posture for any real database. Production DB setup is a separate
> concern - see [`operations/installation`](../operations/installation.md) and
> [`operations/secret-management`](../operations/secret-management.md).

Then `podman start propolis-pg` on later sessions.

### `DATABASE_URL`

`sqlx::test` reads `DATABASE_URL` to reach the server, then creates its own
per-test database. The dev value (`docs/manuals/quickstart.md:45`):

```
DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres
```

**Documented discrepancy.** Four different URLs appear across the repo and they
are not interchangeable:

| Source | `DATABASE_URL` |
|---|---|
| `docs/manuals/quickstart.md:45` (dev) | `postgres://postgres@127.0.0.1:5432/postgres` |
| CI (`.github/workflows/ci.yml:93`) | `postgres://postgres@localhost:5432/postgres` |
| `docs/archive/2026-08-26/root/CONTRIBUTING.md:10` | `postgres://propolis:...@localhost:5432/propolis_test` |
| `deploy/propolis.env.example:35` (production) | `postgres://propolis:CHANGE_ME@localhost:5432/propolis` |

The `propolis`-user / `propolis_test`-db form in the archived `CONTRIBUTING.md` is **not** what
CI or the dev setup use - the working test setup is the superuser/`trust`
form. Use the dev value for local development.

Local-gate caveats (toolchain PATH ordering, starting the container) are
environment-specific and out of scope here; the canonical build/test commands are
in [build-and-test](build-and-test.md).

## Editor conventions

`.editorconfig`: LF line endings, final newline, trim trailing whitespace, UTF-8;
Rust and TOML 4-space indent, YAML 2-space, `.service` 4-space, Makefile tab.
Markdown keeps trailing whitespace. Line-ending and coding conventions are covered
in [coding-conventions](coding-conventions.md).
