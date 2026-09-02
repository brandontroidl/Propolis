<!--
title: Toolchain and environment
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
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

All 18 crates are **edition 2024** (each `crates/*/Cargo.toml:4`).

CI installs this toolchain via `dtolnay/rust-toolchain` pinned to commit SHA
`2fe4ca74464c5902a4f6e302d0a619b4ea911ccc` (`.github/workflows/ci.yml:42,59,98`).

## Test PostgreSQL

The suite is not fully offline: database-backed crates (`core-scoring`, `intake`,
`review`, `feed`, `console`) test against a real PostgreSQL using
[`sqlx`](https://crates.io) `sqlx::test`, which provisions a **fresh database per
test**. `sqlx` version is `0.9.0` (`crates/core-scoring/Cargo.toml:14`).

### Local dev container (podman)

The committed `.env` (gitignored, `.gitignore:7`) uses a disposable, localhost-only,
trust-auth container named `propolis-pg`. Recreate it with the recipe recorded in
`.env`:

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

Then `podman start propolis-pg` on later sessions (`CONTRIBUTING.md:9`).

### `DATABASE_URL`

`sqlx::test` reads `DATABASE_URL` to reach the server, then creates its own
per-test database. The committed dev value (`.env`):

```
DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres
```

**Documented discrepancy.** Three different URLs appear across the repo and they
are not interchangeable:

| Source | `DATABASE_URL` |
|---|---|
| `.env` (dev, committed) | `postgres://postgres@127.0.0.1:5432/postgres` |
| CI (`.github/workflows/ci.yml:91`) | `postgres://postgres@localhost:5432/postgres` |
| `CONTRIBUTING.md:10` | `postgres://propolis:...@localhost:5432/propolis_test` |
| `INSTALL.md:130` (production) | `postgres://propolis:YOUR_PASSWORD@localhost:5432/propolis` |

The `propolis`-user / `propolis_test`-db form in `CONTRIBUTING.md` is **not** what
CI or the committed `.env` use - the working test setup is the superuser/`trust`
form. Use the `.env` value for local development.

Local-gate caveats (toolchain PATH ordering, starting the container) are
environment-specific and out of scope here; the canonical build/test commands are
in [build-and-test](build-and-test.md).

## Editor conventions

`.editorconfig`: LF line endings, final newline, trim trailing whitespace, UTF-8;
Rust and TOML 4-space indent, YAML 2-space, `.service` 4-space, Makefile tab.
Markdown keeps trailing whitespace. Line-ending and coding conventions are covered
in [coding-conventions](coding-conventions.md).
