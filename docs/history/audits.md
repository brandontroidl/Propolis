<!--
title: Audits
audience: security
status: historical
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Audits

Security and quality reviews performed against the codebase. Summaries are kept at a
public-safe level: they record outcomes and the classes of change that landed, but do
**not** publish live detection-tell specifics, which would help an attacker
fingerprint the honeypot.

## Sensor adversarial audit (2026-08-25 / 2026-08-26)

A read-only adversarial audit of the sensor surface was performed, and its
remediations merged into `main` as **"sensor fidelity + observability hardening from
the adversarial audit"** (merge commit `2ed77827`).

**Outcome, public-safe:**

- **Dangerous vulnerability classes came back clean.** The audit did not find
  exploitable memory-safety, remote-code-execution, sandbox-escape, or injection
  defects in the audited sensor surface. [Reported audit outcome; the fixes below are
  commit-evidenced, this summary of the clean classes reflects the audit's own
  conclusion.]
- **Fidelity fixes merged.** Changes that removed observable inconsistencies in the
  sensors' protocol and shell emulation, so the honeypot behaves more like the real
  services it presents. The specific inconsistencies are intentionally not detailed
  here.
- **Observability fixes merged.** Changes that surface previously silent
  capture-loss under overload and log emit failures on command-execution paths, so
  operators are not blind to dropped captures.

These are hardening and realism improvements, not fixes for attacker-exploitable
holes. Current sensor behavior is documented in
[reference/sensor-behavior](../reference/sensor-behavior.md) and
[architecture/sensors](../architecture/sensors.md); the sensor threat model is in
[security/threat-model](../security/threat-model.md).

## Pentest claim (to be verified)

The root [`README.md`](../../README.md) and the `v0.1.0` tag message state the
project was tested with a **"172-test authorized pentest"** with "all findings
remediated," covering protocol fuzzing, brute force, connection flooding, log
injection, XSS/SQLi/CSRF, corroboration-gate bypass, hash-chain integrity, rogue
collector injection, score manipulation, and resource exhaustion.

**This claim is not verifiable from the public tree in the status/history pass** - no
pentest harness or test corpus corresponding to it was located under `crates/`. Treat
it as an **unverified maintainer claim** until its artifacts or a report are located
and confirmed. It should be corroborated (or restated with a pointer to its evidence)
before being relied on. Note also that the "172-test" and "770+ tests" figures in the
tag message predate later work; see
[overview/maturity-and-status](../overview/maturity-and-status.md) for the current
test-corpus figure and its caveats.

## Related

- [security/residual-risks](../security/residual-risks.md) - known residual risks,
  including that the systemd `SystemCallFilter` is a placeholder broad allowlist, not
  a hardened syscall filter.
- [security/hardening-checklist](../security/hardening-checklist.md).
