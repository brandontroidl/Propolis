<!--
title: Documentation index
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Propolis documentation

Start with the [README](../README.md) if you have not read it. This page is the index
for everything else.

## I want to

- **Try it on one machine** - [quickstart](manuals/quickstart.md), then
  [your first capture](getting-started/first-capture.md) and the
  [console tour](getting-started/console-tour.md).
- **Deploy it for real** - [installation](operations/installation.md), then the
  [production-readiness checklist](getting-started/production-readiness-checklist.md).
  The [deployment manual](manuals/deployment.md) walks the whole path.
- **Run a node day to day** - [routine procedures](operations/routine-procedures.md),
  [health and observability](operations/health-and-observability.md),
  [retention](operations/retention.md),
  [backup and restore](operations/backup-and-restore.md),
  [upgrade, rollback and DR](operations/upgrade-rollback-and-dr.md).
- **Understand what it is safe to expose** - [threat model](security/threat-model.md),
  [attack surfaces](security/attack-surfaces.md),
  [outbound controls](security/outbound-controls.md),
  [malware custody](security/malware-custody.md),
  [residual risks](security/residual-risks.md).
- **Respond to an incident on the box** - [incident response manual](manuals/incident-response.md).
- **Fix something that is broken** - [troubleshooting](troubleshooting/index.md), by symptom.
- **Change the code** - [repository tour](development/repository-tour.md),
  [build and test](development/build-and-test.md),
  [adding a sensor](development/adding-a-sensor.md),
  [schema and migrations](development/schema-and-migrations.md).
- **Look something up** - [environment variables](reference/environment-variables.md),
  [ports](reference/ports-and-protocols.md),
  [filesystem paths](reference/filesystem-paths.md),
  [database](reference/database.md),
  [events and signals](reference/events-and-signals.md),
  [sensor behavior](reference/sensor-behavior.md),
  [console routes](reference/console-routes.md),
  [scoring and feed](reference/scoring-and-feed.md),
  [integrations](reference/integrations.md),
  [commands](reference/commands.md),
  [glossary](reference/glossary.md).

## How it works

[Architecture](architecture/index.md): [components](architecture/components.md),
[process topology](architecture/process-topology.md),
[event and sample lifecycle](architecture/event-and-sample-lifecycle.md),
[scoring and feed pipeline](architecture/pipeline.md),
[console](architecture/console.md), [storage](architecture/storage.md),
[trust boundaries and data flows](architecture/trust-boundaries-and-data-flows.md).

## Project

[Overview](overview/index.md) with [capabilities](overview/capabilities.md),
[non-goals](overview/non-goals.md), [maturity](overview/maturity-and-status.md),
[limitations](overview/limitations.md) and [ethical use](overview/ethical-use.md).
[Governance](governance/maintenance-and-support.md): versioning, releases, roadmap,
contribution, [licensing](governance/licensing.md).
[History](history/changelog.md): changelog, decisions, audits.

## Audit material

These are generated review artifacts, not reader documentation. They record a
verification snapshot of the tree as of the date in their header and are not kept
current with every commit.

- [Claim-to-source ledger](claim-to-source-ledger.md): documentation claims mapped to
  the code that supports them.
- [Handoff binder](binder/HANDOFF-BINDER.md): the whole project in one linear document.
- [Coverage matrix](coverage-matrix.md) and [documentation policy](documentation-policy.md).
- [Pre-rewrite archive](archive/2026-08-26/MANIFEST.md), frozen.
