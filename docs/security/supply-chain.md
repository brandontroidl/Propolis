<!--
title: Supply chain
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Supply chain

How Propolis controls the code it builds from and the tools that build it. The
dependency/vendoring model reference is
[../reference/dependencies.md](../reference/dependencies.md); this page covers the
security posture.

## Fully vendored dependencies

All dependencies are vendored in-tree under `vendor/` (514 top-level directories)
and committed to the repository. `.cargo/config.toml` redirects crates-io to that
directory:

```toml
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
```

Consequences:

- Builds do not reach crates.io at build time; the exact bytes of every
  dependency are in the repo and reviewable in a diff.
- `vendor/** linguist-vendored -text` in `.gitattributes` disables EOL
  normalization for vendored sources, because `eol=lf` mangling corrupts
  `.cargo-checksum.json` and breaks release builds. After any `cargo vendor`, run
  `cargo build --release --locked` (not just `cargo test`) to catch checksum
  breakage - a debug/test gate misses it.

## Frozen lockfile

`Cargo.lock` is committed. The clippy and test CI jobs pass `--locked`, which
fails the build if `Cargo.lock` is out of date or would change - dependency
resolution cannot drift silently between CI and a developer machine. See
[../development/build-and-test.md](../development/build-and-test.md) for the full
gate.

## Pinned build inputs (CI)

Every third-party GitHub Action and container image in `.github/workflows/ci.yml`
is pinned to an immutable identifier, not a moving tag:

| Input | Pin |
|---|---|
| `dtolnay/rust-toolchain` | commit SHA `2fe4ca74464c5902a4f6e302d0a619b4ea911ccc` (1.96.1 branch) |
| `Swatinem/rust-cache` | commit SHA `c19371144df3bb44fab255c43d04cbc2ab54d1c4` (v2.9.1) |
| `actions/checkout` | commit SHA `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` (v7.0.0) |
| PostgreSQL test container | `postgres:18` by digest `sha256:32ca0af8...ad5500` |

The Rust toolchain itself is pinned to exact version `1.96.1` (not `stable`) in
`rust-toolchain.toml`, for reproducible builds.

## Memory-safety posture

Propolis is written in Rust; the workspace is safe Rust with two narrow, audited
exceptions. No crate sets `#![forbid(unsafe_code)]`.

- **Non-test `unsafe`:** only the console reverse-DNS resolver
  (`crates/console/src/rdns.rs`) - libc FFI (`getnameinfo`, `sockaddr_in/6`,
  `CStr`) for a PTR lookup. This path is off by default and gated behind
  `PROPOLIS_CONSOLE_RDNS_ENABLED` (see
  [outbound-controls.md](./outbound-controls.md)); the result is display-only and
  never used as a scoring signal.
- **Test-only `unsafe`:** `env::set_var` / `env::remove_var` blocks in
  `crates/propolis/src/config.rs` test functions - Rust 2024 made those calls
  `unsafe`; they run only under `#[cfg(test)]`.

The claim "zero unsafe in the project" is **not** accurate and should not be made;
the accurate statement is that project code is safe Rust apart from the audited
rDNS FFI above.

## Reviewing dependency changes

Because `vendor/` is committed, a dependency add or bump appears as a reviewable
diff. Recommended maintainer practice (not an automated gate in this repo):
review the `Cargo.lock` diff and the `vendor/` changes together, and re-run the
full gate including a release build after re-vendoring. This is guidance, not a
shipped control.

## Related

- [Dependencies reference](../reference/dependencies.md)
- [Build and test](../development/build-and-test.md)
- [Outbound controls](./outbound-controls.md)
- [Residual risks](./residual-risks.md)
