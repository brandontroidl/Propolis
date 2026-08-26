# Security Policy

## Reporting a vulnerability

If you find a security issue in Propolis, report it **privately** rather than opening a
public issue.

**Contact:** the maintainer via their [GitHub profile](https://github.com/brandontroidl)
(open a private Security Advisory on the repository, or reach out through the profile).

Include a description and impact, steps to reproduce (or a proof-of-concept), and the
version or commit hash you tested. You will receive an acknowledgment within 72 hours;
fixes for confirmed vulnerabilities are committed and tagged before any public
disclosure.

## Scope

The Propolis codebase: the sensor framework, all sensor binaries, the intake pipeline,
the review/gatekeeper system, the feed builder, the console, the unified daemon, and the
deployment scripts.

## Full policy and design posture

The complete, canonical version of this policy - including the security design posture
and what is deliberately **not** guaranteed (no in-process TLS, the placeholder syscall
filter, single-node blast radius) - is at
**[docs/security/vulnerability-disclosure.md](docs/security/vulnerability-disclosure.md)**.

See also the [threat model](docs/security/threat-model.md),
[hardening checklist](docs/security/hardening-checklist.md), and
[residual risks](docs/security/residual-risks.md).
