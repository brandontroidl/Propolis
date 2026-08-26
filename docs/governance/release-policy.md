<!--
title: Release policy
audience: maintainer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Release policy

How releases are cut for Propolis. This states the policy; the step-by-step
mechanics live in
[../development/release-procedure.md](../development/release-procedure.md).

## What a release is

A release is an **annotated git tag** (`vMAJOR.MINOR.PATCH`) on a commit in
`main`. Tagging is the release act; there is no separate published package.
The current tree is `0.3.0` but the only tag is `v0.1.0` — the version and the
latest tag differ. See
[compatibility-and-versioning.md](compatibility-and-versioning.md) and
[../overview/maturity-and-status.md](../overview/maturity-and-status.md).

## Release gate — must be green

No release is cut on a red gate. The full gate must pass first:

```
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

The gate requires a real PostgreSQL instance for the database-backed crates. The
gate command, its toolchain requirements, and the test taxonomy are owned by
[../development/build-and-test.md](../development/build-and-test.md); CI runs the
same gate on every push and pull request.

Because packaging, module boundaries, or dynamic imports can change between
commits, a release build must additionally be produced and verified, not
inferred from a green test run.

## Changelog

Release notes are maintained in [../history/changelog.md](../history/changelog.md).
As of this writing the changelog is a single undated `## Unreleased` section and
is **not** version-partitioned — it does not map entries to `v0.1.0` versus later
work, and does not yet list the post-tag V12 operator-console interface. Cutting
a release includes moving `Unreleased` entries under a dated version heading.
