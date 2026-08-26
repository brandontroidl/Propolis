<!--
title: Maturity and status
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Maturity and status

Propolis is **source-available and actively developed**. It is **not** certified,
production-blessed, or compliance-validated. Treat it as software you evaluate and
operate at your own risk.

## Version and release state

The version signals diverge across surfaces; read them together, not in isolation:

- **Crate version: `0.3.0`** across all 18 workspace crates. There is no shared
  `[workspace.package]` version key - each crate pins `0.3.0` independently.
- **Only one release tag exists: `v0.1.0`** (annotated, at commit `e0bfd513`,
  dated 2026-08-02). There is no `v0.2.0` or `v0.3.0` tag, so the current `0.3.0`
  tree is **untagged / unreleased**, roughly two unpublished minor bumps of work
  past the tagged release.
- **`CHANGELOG.md` is a single undated `## Unreleased` section.** It carries no
  per-version partitions or dates, so entries cannot be mapped to `v0.1.0` versus
  later from the changelog alone. See [`../history/changelog.md`](../history/changelog.md).
- **Edition 2024**; no `rust-version` / MSRV is declared in any crate
  `[documented absence]`.

## Implemented and substantial

The following subsystems are implemented and carry substantial test suites
(declared-test counts by source attribute, not a verified green run in this pass):

- **Core scoring** - hash-chained event ledger, decayed scoring, eligibility gates.
- **Intake** - rotation-aware NDJSON tailer with a durable cursor.
- **Review/reporting** - approval gate plus AbuseIPDB/DShield/OTX vendor adapters.
- **Feed** - two-tier export, ASN suppression, fail-closed publisher.
- **Console** - axum + minijinja + HTMX, the V12 theme system and evidence drawer,
  offline MaxMind enrichment, self-hosted fonts.
- **12-protocol sensor surface** - nine sensor crates (see [Capabilities](capabilities.md)).
- **Unified daemon** - supervises intake/review/feed/console plus ops-monitor
  self-alerting.
- **Shared geoip crate** - extracted GeoLite2 reader.

The **V12 operator-console interface** (theme system, evidence drawer, self-hosted
fonts) merged **after the `v0.1.0` tag**, at commit `dbf8c053` (2026-08-25), and is
**not mentioned in `CHANGELOG.md`**. It is present in the current tree.

## Partial / opt-in / conditional

Off-by-default does not mean absent. These features are implemented but conditional:

- **Reverse DNS enrichment** - default off; display-only, never a suppression signal.
- **ASN suppression** - opt-in, empty allowlist by default.
- **MaxMind GeoLite2 geo/ASN** - requires a configured database directory; databases
  are not bundled and the feature degrades to "not configured" when absent.
- **Ops self-alerting** - opt-in.

The `geoip` and `sensor-wire` crates have the thinnest test suites (thin by scope,
not a maturity gap in themselves).

## Claims not verified from source

The `v0.1.0` tag message and README cite a **"172-test authorized pentest … all
findings remediated"**; no pentest harness is located in `crates/`, so this is
recorded as a **claim, not source-evidenced here**. Test-count figures elsewhere
(the tag's "770+") predate ~180 commits of subsequent work and are stale relative to
the current tree.

For the release model and versioning policy, see
[`../governance/release-policy.md`](../governance/release-policy.md) and
[`../governance/compatibility-and-versioning.md`](../governance/compatibility-and-versioning.md).
