# Contributing

Propolis is source-available under the PolyForm Noncommercial License. Contributions are welcome
for noncommercial use.

## Development setup

1. Install the Rust toolchain (the pinned version is in `rust-toolchain.toml`).
2. Start PostgreSQL (e.g., `podman start propolis-pg` if using the dev container).
3. Set `DATABASE_URL=postgres://propolis:...@localhost:5432/propolis_test`.
4. Run the gate: `cargo fmt --check && cargo clippy -- -D warnings && cargo test`.

All dependencies are vendored in-tree (`vendor/`). Use `cargo vendor` after adding or updating a
dependency, and commit the vendor changes.

## Code style

- Rust 2024 edition. Format with `cargo fmt`.
- `cargo clippy -- -D warnings` must pass.
- Conventional commits, lowercase, why-focused body.
- No comments restating what the code does. Comment only the non-obvious why.

## Testing

Every crate has unit and integration tests. Sensor crates test with real TCP connections against
an ephemeral listener (`:0`). Database-dependent crates (core-scoring, intake, review, feed,
console) test against a real PostgreSQL instance.

The CI workflow (`.github/workflows/ci.yml`) runs the full gate on every push and pull request.

## Architecture

Design docs are in `internal/design/`. Architecture decision records are in
`internal/architecture/adr/`. Read these before proposing structural changes.

The build follows a foundation-first sequencing (ADR-0007): each layer is built complete before
the next. See `internal/roadmap.md` for the sub-project breakdown.
