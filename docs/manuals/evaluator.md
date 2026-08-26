<!--
title: Evaluator manual
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Evaluator manual

For deciding whether Propolis fits your needs before you invest in a deployment.
This is a curated path through the canonical pages; it links rather than
restates. Budget roughly an hour: read the framing below, then run the fast eval
path if the fit looks right.

## What Propolis is (in one read)

A self-hosted, single-node honeypot and threat-intelligence platform. Native
protocol sensors impersonate common services, record what attackers do against
WAN addresses you own, score each source on corroborated evidence, and - only
after you approve each case - publish a firewall blocklist and file vendor abuse
reports. It is defensive tooling for infrastructure you own or are authorized to
monitor.

- Full framing: [`../overview/index.md`](../overview/index.md)
- Feature inventory (9 sensor crates / 12 protocols, scoring, feed, console,
  opt-in enrichment): [`../overview/capabilities.md`](../overview/capabilities.md)
- What it deliberately is **not** (not an IDS/IPS, not SaaS, not offensive, not
  fully egress-free): [`../overview/non-goals.md`](../overview/non-goals.md)

## Honest maturity and status

Read this before forming an opinion - the version signals diverge and the
marketing-grade claims are called out where they are not source-evidenced.

- **Source-available and actively developed; not certified or
  production-blessed.** Crate version is `0.3.0` across the workspace, but the
  only release tag is `v0.1.0` - the current tree is untagged, roughly two
  unpublished minor bumps past the tag. `CHANGELOG.md` is a single undated
  `## Unreleased` section. Details, plus which subsystems are substantial vs
  partial/opt-in, and which cited claims (e.g. the "authorized pentest") are
  **not** source-verified: [`../overview/maturity-and-status.md`](../overview/maturity-and-status.md).

## Key cautions before you commit

These are the load-bearing constraints an evaluator most often misses. None is a
defect to discover later - each is stated plainly up front.

- **No in-process TLS.** The console is plain HTTP on a loopback `TcpListener`.
  Any transport encryption is operator-provided (e.g. a reverse proxy). See
  [`../overview/limitations.md`](../overview/limitations.md) and
  [`../operations/networking-tls.md`](../operations/networking-tls.md).
- **Sensors are egress-free by construction; the platform is not.** The platform
  has a small set of enrichment/reporting egress paths (VirusTotal, vendor abuse
  submitters, reverse DNS, ntfy alerts) - every one operator-gated and
  defaulting **off**. See
  [`../security/outbound-controls.md`](../security/outbound-controls.md).
- **The shipped systemd `SystemCallFilter` is a placeholder**, a broad dev
  allowlist the unit header says to tighten - a residual risk you must close, not
  a delivered control.
- **Single-node blast radius, no built-in HA**; backup/restore is your
  responsibility. **Manual feed publish** - the blocklist-sync cron is an
  operator setup step, not a shipped timer. **Honeypot detectability** is
  inherent. Full list:
  [`../overview/limitations.md`](../overview/limitations.md).
- **Captured samples are live, hostile code** and your custody responsibility;
  and deployment is **defensive/authorized use only**. See
  [`../overview/ethical-use.md`](../overview/ethical-use.md).
- Security-owned treatment of what Propolis does not protect against:
  [`../security/residual-risks.md`](../security/residual-risks.md) and
  [`../security/threat-model.md`](../security/threat-model.md).

## Fast eval path

A minimal, loopback-only bring-up that captures a first event - **not a
production deployment**. It makes no outbound requests beyond PostgreSQL.

1. Confirm you can build and run: [`../getting-started/prerequisites.md`](../getting-started/prerequisites.md)
   (Linux + systemd, pinned Rust `1.96.1`, PostgreSQL 15+).
2. Build, provision a throwaway database, run the daemon plus one sensor on
   loopback, reach the console:
   [`../getting-started/evaluation-deployment.md`](../getting-started/evaluation-deployment.md).
3. Generate and trace your first captured event through ledger, score, and
   console: [`../getting-started/first-capture.md`](../getting-started/first-capture.md).
4. Walk the operator console:
   [`../getting-started/console-tour.md`](../getting-started/console-tour.md).
5. Tear the eval down cleanly:
   [`../getting-started/safe-teardown.md`](../getting-started/safe-teardown.md).

The [quickstart manual](quickstart.md) is the condensed version of this path.

## If it fits

- Understand what production actually requires before exposing any listener:
  [`../getting-started/production-readiness-checklist.md`](../getting-started/production-readiness-checklist.md).
- Then move to the [deployment manual](deployment.md).
