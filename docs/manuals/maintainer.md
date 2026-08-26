<!--
title: Maintainer manual
audience: maintainer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Maintainer manual

A guided path through the release, versioning, documentation, and supply-chain
discipline for whoever cuts releases and merges changes. Exact commands and
values live in the pages this links; this manual sequences them and states the
current release state a maintainer must know first.

## Current version and tag state (read this first)

The version signals diverge across surfaces - read them together:

| Fact | Value |
|---|---|
| Crate version (all 18 crates) | `0.3.0`, each crate pins it independently (no `[workspace.package]`) |
| Only release tag | `v0.1.0` (annotated, commit `e0bfd513`, 2026-08-02) |
| Tags `v0.2.0` / `v0.3.0` | do not exist |
| `CHANGELOG.md` | a single undated `## Unreleased` section |
| Post-tag work not in the changelog | the V12 operator console (theme system, evidence drawer, self-hosted fonts) merged at `dbf8c053`, after `v0.1.0` |

So the working tree is **`0.3.0` but untagged**: roughly two unreleased minor
bumps sit ahead of the tagged release. Describe maturity as source-available,
actively developed, **one tagged release (`v0.1.0`)**, current tree `0.3.0`
untagged - never certified or production-blessed. Canonical status page:
[`overview/maturity-and-status`](../overview/maturity-and-status.md).

## Release procedure

The mechanics are owned by
[release procedure](../development/release-procedure.md); the policy is
[`governance/release-policy`](../governance/release-policy.md). There is **no CI
release job and no `RELEASING.md`** - the bump and tag are done by hand, and the
lockstep-bump and changelog-rename conventions are `[inferred]` from the current
state. The sequence:

1. **Bump the version** in each of the 18 crate manifests (kept in lockstep),
   then `cargo build --locked` so `Cargo.lock` reflects the new versions; commit
   both.
2. **Finalize the changelog**: rename `## Unreleased` to the version and date,
   open a fresh `## Unreleased` above it. Moving `Unreleased` entries under a
   dated heading is part of cutting a release.
3. **Run the full gate green** - the whole gate, not a subset:

   ```
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked -- --test-threads=1
   ```

   Then build release binaries, because a release build exercises checks a
   debug/test build does not (notably vendored-checksum integrity):

   ```
   cargo build --release --locked
   ```

4. **Tag** an annotated `vMAJOR.MINOR.PATCH` on the fully-gated commit.

> **Pushing a tag is an outward, effectively-irreversible publish.** A pushed tag
> is what downstream users and any deploy step resolve against. Confirm the tag
> points at the intended, fully-gated commit before `git push origin <tag>`;
> deleting or moving a published tag disrupts anyone who already fetched it.

Deployment is a **separate** operator procedure (build release binaries,
`deploy/install.sh`, populate `/etc/propolis/*.env`, enable units); it is not part
of tagging. See [`operations/installation`](../operations/installation.md),
[`operations/service-lifecycle`](../operations/service-lifecycle.md), and the
upgrade/rollback path in
[`operations/upgrade-rollback-and-dr`](../operations/upgrade-rollback-and-dr.md).

## Compatibility and versioning

Owned by
[`governance/compatibility-and-versioning`](../governance/compatibility-and-versioning.md).
The compatibility surfaces a maintainer must hold stable:

- **Version scheme**: SemVer-shaped `MAJOR.MINOR.PATCH`, every crate pinned
  independently, currently all moving together. No `rust-version`/MSRV is
  declared. Pre-1.0, treat minor bumps as potentially breaking.
- **Sensor wire contract is frozen** - guarded by its own tests; changes are
  compatibility-sensitive and not made casually. See
  [schema-and-migrations](../development/schema-and-migrations.md#the-frozen-wire-contract).
- **Database schema is additive** - new columns optional so existing rows still
  validate; stored data transformed only via explicit migration code, never a
  silent runtime shim. Tables/enums/migrations owned by
  [`reference/database`](../reference/database.md).
- **Configuration is additive** - new config ships with safe defaults so an
  existing deployment keeps working. Env-var defaults/bounds owned by
  [`reference/environment-variables`](../reference/environment-variables.md).

## Documentation policy

The published corpus follows a **one-canonical-owner** model: each fact has
exactly one home. Reference pages own exact values (env vars, ports, paths,
tables, routes, scoring constants); guides and manuals explain and link, they do
not re-list. Maintainer obligations when merging doc changes
([documentation and review](../development/documentation-and-review.md)):

- Every published `.md` starts with the metadata header (title / audience /
  status / owner / applies-to / last-verified).
- Distinguish implemented behavior from `[inferred]` or `[planned]`; never
  present a comment, plan, or intention as shipped behavior.
- One class of doc/code agreement is enforced **mechanically** in CI:
  `crates/propolis/tests/docs_agreement.rs` fails the build if a `PROPOLIS_*` /
  `CATCHALL_*` env-var literal in source is missing from `INSTALL.md`. When an env
  var is added or renamed, update `INSTALL.md` in the same change.

The corpus map is [`DOCUMENTATION.md`](../../DOCUMENTATION.md); the status/metadata
standard is [`documentation-policy`](../documentation-policy.md); the material
claims are traced in [`claim-to-source-ledger`](../claim-to-source-ledger.md).
Design docs and ADRs referenced from `CONTRIBUTING.md` are gitignored private
material and are not part of the published corpus; the code-evidenced decisions
surface in [`architecture/decisions`](../architecture/decisions.md).

## Supply-chain discipline and vendoring

Owned by [`security/supply-chain`](../security/supply-chain.md) (posture) and
[`reference/dependencies`](../reference/dependencies.md) (mechanics). The controls
a maintainer enforces:

- **Fully vendored dependencies.** All dependencies are vendored in-tree under
  `vendor/` (514 top-level directories) and committed; `.cargo/config.toml`
  redirects crates-io to that tree. A build reaches no network to resolve crates,
  and a dependency add/bump appears as a **reviewable diff**. Review the
  `Cargo.lock` diff and the `vendor/` changes together (guidance, not an automated
  gate).

  > **`cargo vendor` fetches from crates.io.** Run it on a workstation, never on
  > the honeypot node.

- **Rebuild in release after re-vendoring.** `.gitattributes` marks `vendor/**`
  `-text` so EOL normalization cannot mangle `.cargo-checksum.json`; a checksum
  break surfaces only in a **release** build. After any `cargo vendor`, run
  `cargo build --release --locked`, not just `cargo test`.
- **Frozen lockfile.** `Cargo.lock` is committed; the clippy and test jobs pass
  `--locked` so resolution cannot drift between CI and a developer machine.
- **Pinned build inputs.** Every GitHub Action and container image in CI is
  pinned to an immutable SHA/digest, not a moving tag; the Rust toolchain is
  pinned to an exact version.
- **Memory-safety posture, stated accurately.** The workspace is safe Rust with
  two narrow, audited `unsafe` exceptions (the off-by-default console rDNS FFI and
  test-only env mutation). The claim "zero unsafe in the project" is **not**
  accurate and must not be made.

## Maintenance model

Propolis is single-maintainer, source-available, best-effort: no SLA, no
warranty, best-effort security handling. See
[`governance/maintenance-and-support`](../governance/maintenance-and-support.md),
[`governance/licensing`](../governance/licensing.md), and the disclosure process
in [`security/vulnerability-disclosure`](../security/vulnerability-disclosure.md).
Roadmap direction is the maintainer's call, decided against the actual state of
code and tests rather than aspirational plans
([`governance/roadmap`](../governance/roadmap.md)).
