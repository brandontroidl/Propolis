<!--
title: Documentation and review expectations
audience: maintainer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Documentation and review expectations

What a contribution must satisfy before merge, and how documentation is kept in sync
with the code.

## The gate is the bar

Every change passes the CI gate — fmt, clippy (`-D warnings`), and the full test suite
against a real PostgreSQL — on every push and pull request; nothing merges un-gated
(`.github/workflows/ci.yml`, `CONTRIBUTING.md:29`). See
[build-and-test](build-and-test.md) for the exact commands and why the three jobs are
independent.

Review expectations that follow from the tree's conventions:

- **Prove behavior with tests, not the implementation.** Sensor changes test over real
  TCP; DB changes test with `sqlx::test`. New invariants get a test that would fail
  without the change.
- **Conventional, lowercase commits** with a why-focused body; small, bisectable
  increments (`CONTRIBUTING.md:20`). See [coding-conventions](coding-conventions.md).
- **Comment the why, not the what** (`CONTRIBUTING.md:21`).
- **Additive migrations only**; never edit an applied migration in place. See
  [schema-and-migrations](schema-and-migrations.md).
- **Sensor changes keep the never-exec / no-fetch guarantees** and their static tests.
  See [adding-a-sensor](adding-a-sensor.md#the-tests-a-sensor-must-pass).
- **Re-vendor + release-build** after any dependency change
  ([schema-and-migrations](schema-and-migrations.md#vendoring)); dependency changes are
  a supply-chain surface ([`security/supply-chain`](../security/supply-chain.md)).

## Documentation stays in sync mechanically, where it can

The repo enforces one class of doc/code agreement in CI rather than by convention:

**`crates/propolis/tests/docs_agreement.rs`** fails the build if any `PROPOLIS_*` /
`CATCHALL_*` env-var name that appears as a string literal in non-test source is missing
from `INSTALL.md`. Direction is code → docs (the reverse would false-positive on
`INSTALL.md`'s own corrective prose that quotes deliberately-wrong names). It exists
because the project twice shipped `INSTALL.md` documenting an env-var name the code did
not read, and a sensor refused to start with no hint why (`docs_agreement.rs:1-10`).

Practical consequence: **when you add or rename an env var, update `INSTALL.md` in the
same change** or CI fails.

## Published documentation corpus

The narrative and reference documentation under `docs/` follows a **one-canonical-owner**
model: each fact has exactly one home (reference pages own exact values; guides explain
and link). When adding docs:

- Reference pages own the exact values — env vars, ports, paths, tables, routes,
  scoring constants. Guides cite them, they do not re-list.
- Every published `.md` starts with the metadata header (title / audience / status /
  owner / applies-to / last-verified).
- Cross-link with repository-relative Markdown links to the canonical paths.
- Distinguish implemented behavior from inference (`[inferred]`) or planned work
  (`[planned]`); never present a comment, plan, or intention as shipped behavior.

The corpus map is [`DOCUMENTATION.md`](../../DOCUMENTATION.md); the policy for
current/historical/superseded/draft/planned status and the metadata standard is
[`documentation-policy`](../documentation-policy.md). The claim-to-source mapping lives
in [`claim-to-source-ledger`](../claim-to-source-ledger.md).

Design docs and architecture decision records referenced from `CONTRIBUTING.md`
(`internal/design/`, `internal/architecture/adr/`) are gitignored private material and
are not part of the published corpus; the code-evidenced decisions surface in
[`architecture/decisions`](../architecture/decisions.md).
