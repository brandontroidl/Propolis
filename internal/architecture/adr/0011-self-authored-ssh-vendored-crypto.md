# ADR-0011: Self-authored SSH honeypot over vendored, pinned crypto primitives

Status: accepted (2026-07-20)

## Context

Sub-project 2's first TCP-authenticated honeypot is an SSH server (`design/02-sensor-framework.md`).
The rebuild's founding principle (`propolis-new-vision`) is native, self-authored sensors with no
dependence on third-party honeypot projects, because such projects go stale and cannot be trusted to
remain maintained — the old system's git history was largely third-party-honeypot build fixes, which
is a primary reason for the rewrite.

An SSH honeypot must speak real SSH: a client cryptographically verifies the key exchange and message
authentication, so the crypto cannot be faked or stubbed. That raises where to draw the line between
"self-authored" and reusing existing code, against the countervailing security rule that
cryptographic primitives (elliptic-curve arithmetic, ciphers, hashes) must not be reimplemented, since
subtle, exploitable bugs (timing side channels, incorrect field arithmetic) live exactly there and the
math is stable — it gains nothing from a rewrite. The core scoring layer already ships one such
primitive crate (`sha2`) for its hash chain, so the project's real line was never "zero dependencies"
but "no stale-prone application projects."

## Decision

1. **Self-author the entire SSH server.** The binary packet protocol, version and key-exchange
   orchestration, the authentication state machine, the fake shell, the SCP/SFTP capture, and all
   event emission are Propolis code. No third-party SSH server library and no honeypot library is
   used.

2. **Use small, foundational crypto-primitive crates for the raw math** — the RustCrypto family
   (curve25519 key exchange, an ed25519 host key, ChaCha20-Poly1305, the hashes), the same family as
   the `sha2` already in the tree. The primitives are not reimplemented.

3. **Vendor the pinned primitive source in-tree** via `cargo vendor` plus `.cargo/config.toml`, so
   the build never fetches them and an abandoned or yanked upstream cannot break or remove them. This
   satisfies the "everything within the program, nothing that can go stale on us" requirement for the
   primitives without incurring the reimplementation hazard. Vendored crates remain under the
   dependency-vetting discipline (pinned versions, lockfile review, release-age quarantine); a future
   security patch is applied to the vendored copy deliberately.

## Consequences

- The honeypot is fully self-authored where the risk and the staleness concern actually live (the
  protocol, the shell, the capture), and reuses only stable, foundational math that is copied into the
  tree and cannot vanish.
- The build is offline-reproducible for the crypto primitives; no runtime dependence on any external
  registry for them.
- The SSH host key the honeypot generates and persists is intrinsic to being an SSH server. It is not
  a platform secret (no vendor, database, session, or push credential reaches a sensor), and host-key
  compromise is immaterial — impersonating a honeypot has no value. The no-secrets posture is
  unchanged.

## Rejected alternatives

- **Build on a third-party SSH server library (e.g. `russh`)** — rejected: a large, application-level
  dependency that can go stale, exactly the risk the native-sensor principle exists to avoid.
- **Reimplement the crypto primitives in Propolis** — rejected: reintroduces the roll-your-own-crypto
  hazard (side-channel and arithmetic bugs) for stable math that gains nothing from a rewrite; the
  vendoring decision already removes the staleness concern the reimplementation was meant to address.
