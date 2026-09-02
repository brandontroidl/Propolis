<!--
title: Release procedure
audience: maintainer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Release procedure

An evidence-based account of how releases are cut, and the current version/tag state.
There is no release-automation job in CI (the workflow runs only fmt, clippy, and
tests) and no `RELEASING.md`; the steps below are reconstructed from the repository's
observable state and marked `[inferred]` where the mechanism is not documented in-repo.

## Current state (read this first)

| Fact | Value | Source |
|---|---|---|
| Crate version (all 18) | `0.3.0` | each `crates/*/Cargo.toml:3` |
| Only release tag | `v0.1.0` ("v0.1.0: initial release") | `git tag` |
| Tags `v0.2.0` / `v0.3.0` | do not exist | `git tag` |
| `CHANGELOG.md` | a single, undated `## Unreleased` section | `CHANGELOG.md:3` |

So the working tree is **`0.3.0` but untagged**: the crate manifests moved ahead of the
tags across two unreleased version bumps, and `CHANGELOG.md` accumulates all changes
since `v0.1.0` under one `Unreleased` heading. Describe maturity as source-available,
actively developed, **one tagged release (`v0.1.0`)**, current tree `0.3.0` untagged - not certified or production-blessed. The V12 operator console (theme system, evidence
drawer, self-hosted fonts) merged **after** the `v0.1.0` tag (at `dbf8c053`) and is not
mentioned in `CHANGELOG.md`.

Version/maturity narrative for readers lives in
[`overview/maturity-and-status`](../overview/maturity-and-status.md); versioning policy in
[`governance/compatibility-and-versioning`](../governance/compatibility-and-versioning.md)
and [`governance/release-policy`](../governance/release-policy.md).

## Procedure

### 1. Bump the version

The workspace has **no `[workspace.package]`** table, so version is declared
per-crate - all 18 crates currently read `version = "0.3.0"`. A version bump updates
each crate manifest (kept in lockstep in the current tree). Run `cargo build --locked`
afterward so `Cargo.lock` reflects the new versions, and commit both.

### 2. Finalize the changelog

Rename the `## Unreleased` section to the version and date, and open a fresh
`## Unreleased` above it. `CHANGELOG.md` is the retained pointer to
[`history/changelog`](../history/changelog.md); keep them consistent. `[inferred]` - the
single-`Unreleased` structure implies this rename-on-release convention; it is not
written down.

### 3. Run the full gate

The release commit must be green on the complete gate, not a subset:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
```

Also build the release binaries, since a release build exercises checks a debug/test
build does not (notably vendored-checksum integrity - see
[schema-and-migrations](schema-and-migrations.md#vendoring)):

```
cargo build --release --locked
```

See [build-and-test](build-and-test.md) for why these are the authoritative commands.

### 4. Tag

Tags follow the `vMAJOR.MINOR.PATCH` form (`v0.1.0` is annotated: "v0.1.0: initial
release"). Create an annotated tag on the release commit:

```
git tag -a v0.3.0 -m "v0.3.0: <summary>"
```

> **Pushing a tag is an outward, effectively-irreversible publish.** A pushed tag is
> what downstream users and any deploy step resolve against. Confirm the tag points at
> the intended, fully-gated commit before `git push origin v0.3.0`. Deleting or moving a
> published tag is disruptive to anyone who already fetched it.

### 5. Deploy

Deployment is a separate operator procedure (build release binaries, `deploy/install.sh`,
populate `/etc/propolis/*.env`, enable units). It is not part of tagging. See
[`operations/installation`](../operations/installation.md) and
[`operations/service-lifecycle`](../operations/service-lifecycle.md), and the
upgrade/rollback path in
[`operations/upgrade-rollback-and-dr`](../operations/upgrade-rollback-and-dr.md).

## Gaps

- No CI release job, no `RELEASING.md`, and no `cargo-release`/`cargo-workspaces` config
  in the tree - the version-bump and tagging steps are performed by hand. The lockstep
  bump and changelog-rename conventions are `[inferred]` from the current state, not
  documented.
