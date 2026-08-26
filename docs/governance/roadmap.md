<!--
title: Roadmap policy
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Roadmap policy

This page states **how the roadmap is decided**, not the detailed plan. The
detailed roadmap and prioritization live in the project's private internal
design material and are not part of the public documentation corpus.

## How direction is decided

- **The maintainer sets priorities.** As a single-maintainer, best-effort
  project (see [maintenance-and-support.md](maintenance-and-support.md)), roadmap
  direction is the maintainer's call; there is no committed delivery schedule.
- **Evidence over intent.** What ships is decided against the actual state of the
  code, tests, and observed behavior — not against aspirational plans. Planned
  work is not presented as delivered.
- **Additive and reversible first.** New capability is preferred in forms that
  keep existing deployments working (safe defaults, additive schema, opt-in and
  default-off egress) per
  [compatibility-and-versioning.md](compatibility-and-versioning.md).

## What this page does not contain

- Dated milestones or feature commitments.
- The private prioritized backlog.

For what exists **today** versus what is partial or opt-in, use the code-evidenced
status page, not a roadmap:
[../overview/maturity-and-status.md](../overview/maturity-and-status.md).
Completed and superseded work is recorded in
[../history/completed-and-superseded.md](../history/completed-and-superseded.md).
