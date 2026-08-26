<!--
title: Threat model and trust assumptions
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Threat model and trust assumptions

Propolis is a single-node honeypot and threat-intel platform. Its attacker-facing
sensors are deliberately exposed to hostile internet traffic; everything downstream
is built on the assumption that all sensor input is adversary-controlled and must be
neutralized before it touches an event record, the database, or the operator.

This page states who the adversary is, what is being protected, and what the design
trusts versus distrusts. It links to the pages that own each control; it does not
restate their exact values.

## Adversary

The primary adversary is an **unauthenticated internet attacker** reaching a sensor
listener with fully attacker-chosen bytes: probe traffic, credential-stuffing, exploit
attempts, malware upload, and worm/botnet kill-chains. The honeypot's purpose is to let
that attacker proceed far enough to be observed (accept any credential, present a
convincing persona), so the adversary is assumed to control:

- Every byte of protocol input on a sensor connection (banners, commands, filenames,
  credentials, uploaded sample bytes, URLs the attacker asks the box to fetch).
- The source address framing to the extent the network allows (spoofing, proxying).
- Content designed to attack *downstream consumers* of captured evidence: forged log
  lines (CR/LF, ANSI, bidi overrides), path-traversal filenames, SSRF-shaped fetch
  URLs, oversized inputs aimed at memory exhaustion.

Out of scope as adversaries: a malicious operator, a compromised host kernel, and
supply-chain compromise of the toolchain (supply-chain controls are covered separately
in [supply-chain.md](supply-chain.md); they are risk-reduction, not a trusted boundary).

## Assets

| Asset | What protects it |
|---|---|
| **The host** (no attacker code ever runs) | never-execute invariant + deployment W^X / non-root / capability caps — see [never-execute.md](never-execute.md), [filesystem-and-db-protections.md](filesystem-and-db-protections.md) |
| **Evidence integrity** (captured events are tamper-evident and cannot be forged by input) | SHA-256 event hash chain + boundary sanitization — see [input-handling.md](input-handling.md), [../architecture/storage.md](../architecture/storage.md) |
| **The database** (no injection, no unbounded growth) | parameterized SQL + bounded reads/spool budget — see [input-handling.md](input-handling.md), [filesystem-and-db-protections.md](filesystem-and-db-protections.md) |
| **Captured malware custody** (samples stored sterile, never executed, human-gated before egress) | SHA-256-named quarantine spool + approval gate — see [malware-custody.md](malware-custody.md) |
| **Credential / sample privacy** (submitted passwords never recorded; internal fields never in the public feed) | password-drop invariant + feed field selection — see [sample-and-credential-privacy.md](sample-and-credential-privacy.md) |
| **The operator** (the one trusted human at the console) | Argon2id auth + session/CSRF boundary + loopback-default bind — see [authn-authz.md](authn-authz.md) |
| **Third parties** (the box must not become an attack proxy) | SSRF vetter on the one attacker-directed fetch + forbidden-egress guard — see [outbound-controls.md](outbound-controls.md) |

## Trust assumptions

### Trusted

- **The operator.** The single human running the console is trusted. The console is a
  single-operator tool: one password, sessions held in memory only, loopback bind by
  default ([authn-authz.md](authn-authz.md)).
- **PostgreSQL.** The database is a trusted backend on the same node; the trust boundary
  is that no *attacker input* reaches it except as bound query parameters
  ([input-handling.md](input-handling.md)).
- **The host OS and systemd.** Deployment-layer controls (non-root users, W^X,
  `ProtectSystem=strict`, capability bounding, `noexec` spool mounts) are trusted to
  hold; they are documented in [filesystem-and-db-protections.md](filesystem-and-db-protections.md).
  Note two residual gaps carried there and in [residual-risks.md](residual-risks.md):
  the systemd `SystemCallFilter` shipped is a broad development **placeholder**, not a
  tightened per-binary seccomp allowlist, and the `noexec,nosuid,nodev` spool mounts are
  printed as operator fstab guidance, not enforced from source.

### Not trusted

- **All sensor input, unconditionally.** Every attacker-controlled string is routed
  through the shared `sanitize_value` chokepoint before it can enter an event, and every
  captured sample is named by its own SHA-256 rather than any attacker-supplied filename
  ([input-handling.md](input-handling.md), [malware-custody.md](malware-custody.md)).
- **Attacker-supplied URLs.** The one path that fetches an attacker-chosen URL (the
  optional, default-off malware fetcher) treats the URL as hostile and vets it — scheme
  allowlist, forbidden-target check, DNS-rebinding defense, pinned address — on the
  initial request and every redirect hop ([outbound-controls.md](outbound-controls.md)).
- **The source IP as an identity or authorization signal.** Forward-confirmed reverse DNS
  is display-only and never used as a suppression signal (it is spoofable); the honeypot's
  own WAN ingress address is internal-only and never appears in the public feed
  ([sample-and-credential-privacy.md](sample-and-credential-privacy.md)).

## What the design does not promise

- **Not "egress-free."** Sensors are egress-free by construction, but the platform has
  five outbound paths — every one opt-in and defaulting **off**. See
  [outbound-controls.md](outbound-controls.md) for the exact list and gating.
- **No built-in TLS.** The console is plain HTTP on a loopback `TcpListener`; any TLS is
  operator-provided (for example a reverse proxy). See [authn-authz.md](authn-authz.md)
  and [../operations/networking-tls.md](../operations/networking-tls.md).
- **Not production-certified.** Source-available, actively developed, one tagged release
  (`v0.1.0`); the current tree is `0.3.0`, untagged. See
  [../overview/maturity-and-status.md](../overview/maturity-and-status.md).

Full list of accepted residual risks: [residual-risks.md](residual-risks.md).
