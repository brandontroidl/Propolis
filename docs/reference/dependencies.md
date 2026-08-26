<!--
title: Dependencies and vendoring
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Dependencies and vendoring

How third-party code enters the build and how it is kept byte-exact and
reproducible. Supply-chain posture and review requirements are covered in
[`../security/supply-chain.md`](../security/supply-chain.md); this page owns the
vendoring mechanics and the notable-dependency inventory.

## Vendored in-tree

All dependencies are vendored under `vendor/` and committed to the repository
(514 top-level dependency directories, `vendor/`). `vendor/` is **not**
gitignored; only `/target` is (`.gitignore:2`). `.cargo/config.toml` redirects
crates.io to the vendored copy:

```
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

Consequences:

- A build needs no network access to resolve or download crates; the vendored
  tree is the only source. (The compiler and toolchain themselves are a separate
  concern.)
- `Cargo.lock` is committed (`Cargo.lock`) and enforced frozen by `--locked` in
  the clippy and test gate jobs; a dependency change that is not reflected in
  the lockfile fails CI.

## The `cargo vendor` workflow

After adding or updating a dependency
(`CONTRIBUTING.md:13-14`):

> **Egress warning.** `cargo vendor` fetches from crates.io. Run it on a
> workstation, never on the honeypot node.

```
cargo vendor                    # re-materialize vendor/ from the updated Cargo.lock
cargo build --release --locked  # re-verify the release build after re-vendoring
git add vendor Cargo.lock       # commit the vendor changes together with the lockfile
```

The release build after re-vendoring is not optional. A prior regression
mangled cargo's vendored `.cargo-checksum.json` files via end-of-line
normalization, which passed the debug/test gate but broke `--release` builds.
The `.gitattributes` rule below is the durable fix; re-running `--release` is
the verification.

## `.gitattributes` protections

`.gitattributes` guards the byte-exactness the checksums depend on:

| Pattern | Rule | Why |
|---|---|---|
| `*` | `text=auto eol=lf` | Global newline normalization for source. |
| `vendor/**` | `linguist-vendored -text` | Disables EOL normalization for vendored sources; `eol=lf` mangling corrupts `.cargo-checksum.json` and breaks release builds. |
| `*.woff2` | `binary` | Self-hosted console fonts are binary; text/EOL normalization would corrupt the woff2. |
| `Cargo.lock` | `-diff linguist-generated` | Marks the lockfile generated; suppresses diff noise. |

The `.editorconfig` sets LF endings, final newline, trailing-whitespace
trimming, and UTF-8 across the tree (`.editorconfig`).

## Notable dependencies

Verified from the build. Exact versions are in `Cargo.lock`; only the
load-bearing ones and their roles are listed here.

| Crate | Version | Role |
|---|---|---|
| `axum` | — | Console web server (`crates/console`). Plain HTTP on a loopback `TcpListener` via `axum::serve`; there is **no in-process TLS** (no rustls). Any TLS is operator-provided (e.g. a reverse proxy). |
| `minijinja` | — | Server-side HTML templating for the console. |
| htmx | — | Client-side interactivity in the console (vendored front-end asset, not a Rust crate). |
| Chart.js | — | Console dashboard charts (vendored front-end asset). |
| `reqwest` / `hyper` | — | HTTP clients present in `Cargo.lock`, used **only** by the review/enrichment paths (VirusTotal, vendor abuse submitters, the SSRF-guarded malware fetcher). |
| `sqlx` | 0.9.0 | Async PostgreSQL access, compile-time-checked queries, migrations, and the `sqlx::test` harness. Features differ per crate (core-scoring includes `uuid`; console omits it — `crates/core-scoring/Cargo.toml:14`, `crates/console/Cargo.toml:24`). |

`sensor-ssh` additionally carries its own cryptographic primitives
(x25519 / ed25519-dalek, chacha20, poly1305) so it can complete a real SSH
handshake without a general SSH library (`crates/sensor-ssh/Cargo.toml:24-30`).

### HTTP clients and the egress model

`reqwest` and `hyper` being in the lockfile does **not** make the platform
outbound-by-default, and it does not weaken the sensor guarantee:

- **Sensors are egress-free by construction.** Each attacker-facing sensor crate
  has no HTTP client in its own dependency tree, enforced by per-sensor tests
  that ban `reqwest`/`hyper`/`ureq`/`curl`/`isahc`/`surf`/`attohttpc`.
- The HTTP clients live only in the platform-level review/enrichment code. Every
  outbound path built on them is opt-in and defaults **off**. See
  [`../security/outbound-controls.md`](../security/outbound-controls.md) for the
  enumerated egress paths and [`integrations.md`](integrations.md) for the
  wire contracts.

No workspace crate uses a fetched CDN at runtime; the console's front-end assets
(htmx, Chart.js, fonts) are vendored and self-hosted.
