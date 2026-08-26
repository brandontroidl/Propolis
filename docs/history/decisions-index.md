<!--
title: Decisions index
audience: all
status: historical
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Decisions index

Propolis's authoritative Architecture Decision Records (ADRs) live in the project's
**private, gitignored internal design tree** and are not part of the public
repository. They are not reproduced, quoted, or linked here.

What the public corpus documents instead is the set of **code-observable
decisions** - design choices that can be read directly from the source, tests,
migrations, and deploy units, independent of the private ADRs. Those are owned by
[architecture/decisions](../architecture/decisions.md); this page is only an index
pointing to them and noting where the private records sit conceptually.

## Where the private ADRs sit (conceptually)

The private ADR set covers the same decision space that the public architecture
section reconstructs from code - the sensor/intake/scoring/review/feed/console
boundaries, the append-only hash-chained ledger, the anti-spoofing and eligibility
model, the opt-in/default-off posture of every outbound path, and the deployment
topology. The public documents state these as **evidenced from the code** rather
than from the ADRs, so no private material is required to understand them. Where a
decision's *rationale* is only recorded privately, the public page says so and stops
at what the code shows.

The former root `CONTRIBUTING.md` pointed at `internal/architecture/adr/` and
related private paths; those are gitignored and deliberately not referenced by the
new corpus. See [old-to-new-map](old-to-new-map.md).

## Code-observable decisions

For the full, source-cited list see
[architecture/decisions](../architecture/decisions.md). Representative decisions,
each verifiable from the tracked tree:

- **Sensors are egress-free by construction.** Each attacker-facing sensor crate
  carries no HTTP client in its dependency tree, enforced by per-sensor tests that
  ban outbound-client crates. The platform's few enrichment/reporting egress paths
  are separate, operator-gated, and default off - see
  [security/outbound-controls](../security/outbound-controls.md).
- **Append-only, hash-chained event ledger** for tamper-evidence -
  [architecture/storage](../architecture/storage.md).
- **Human-approval gate before any vendor abuse submission** -
  [architecture/pipeline](../architecture/pipeline.md).
- **Fail-closed feed publisher** and two-tier export -
  [reference/scoring-and-feed](../reference/scoring-and-feed.md).
- **Frozen sensor wire contract** shared across sensors -
  [architecture/sensors](../architecture/sensors.md).
- **Single-node unified daemon** supervising intake/review/feed/console over one
  connection pool - [architecture/process-topology](../architecture/process-topology.md).

Where a decision's provenance is an *inference from the implementation* rather than
a stated record, the architecture page tags it accordingly.
