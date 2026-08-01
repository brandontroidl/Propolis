# Security Policy

## Reporting a vulnerability

If you find a security issue in Propolis, please report it privately rather than opening a public
issue.

**Email:** brandonstroidl@icloud.com

Include:
- A description of the issue and its impact
- Steps to reproduce (or a proof-of-concept if possible)
- The version or commit hash you tested against

You will receive an acknowledgment within 72 hours. Fixes for confirmed vulnerabilities will be
committed and tagged before any public disclosure.

## Scope

This policy covers the Propolis codebase: the sensor framework, all sensor binaries, the intake
pipeline, the review/gatekeeper system, the feed builder, the console, the unified daemon, and
the deployment scripts.

## Design posture

Propolis is designed to run on the public internet receiving hostile traffic. Its security model:

- Sensors are unprivileged, hold no database handle, and carry no secrets.
- Captured passwords are dropped at parse time; captured file bodies are quarantined under
  noexec mounts.
- All attacker-controlled input passes through `sanitize_value` before reaching logs or events.
- Each sensor runs as a dedicated OS user under a hardened systemd unit with
  `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, restricted address
  families, and resource caps.
- The unified daemon runs migrations and connects to PostgreSQL; sensors do not.
- Nothing is reported to a vendor or published to the feed without explicit operator approval.
