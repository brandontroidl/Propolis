<!--
title: Documentation index
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Propolis documentation

The canonical documentation corpus. See [`../DOCUMENTATION.md`](../DOCUMENTATION.md) for
the role-based entry map, or the [handoff binder](binder/HANDOFF-BINDER.md) for one linear
read.

## Sections

- **[overview/](overview/index.md)** - what Propolis is, who it is for, capabilities, non-goals, maturity, limitations, ethics.
- **[getting-started/](getting-started/evaluation-deployment.md)** - prerequisites, evaluation bring-up, first capture, console tour, production-readiness, safe teardown.
- **[architecture/](architecture/index.md)** - components, process topology, sensors, event/sample lifecycle, pipeline, console, storage, trust boundaries, concurrency, decisions.
- **[operations/](operations/installation.md)** - deployment models, installation, configuration, secrets, networking/TLS, service lifecycle, observability, capacity, queue/spool, retention, backup, upgrade/DR, routine procedures.
- **[security/](security/threat-model.md)** - threat model, attack surfaces, authn/authz, input handling, never-execute, outbound controls, malware custody, privacy, filesystem/DB protections, supply chain, hardening, residual risks, disclosure.
- **[development/](development/repository-tour.md)** - repository tour, toolchain, build/test, conventions, adding a sensor, schema/migrations, docs & review, release.
- **[reference/](reference/environment-variables.md)** - environment variables, ports, paths, database, events/signals, sensor behavior, console routes, scoring/feed, integrations, rate limits/budgets, commands, dependencies, glossary.
- **[governance/](governance/maintenance-and-support.md)** - maintenance & support, compatibility & versioning, release policy, roadmap, contribution, licensing.
- **[troubleshooting/](troubleshooting/index.md)** - symptom-based diagnosis.
- **[history/](history/changelog.md)** - changelog, decisions index, completed/superseded work, audits, archive map.

## Manuals

Curated, role-specific paths through the corpus (they link, they do not duplicate):

- [Evaluator](manuals/evaluator.md) · [Quickstart](manuals/quickstart.md) · [Deployment](manuals/deployment.md) · [Operations](manuals/operations.md)
- [Security](manuals/security.md) · [Incident response](manuals/incident-response.md)
- [Contributor](manuals/contributor.md) · [Maintainer](manuals/maintainer.md) · [Researcher](manuals/researcher.md)

## Binder and controls

- [Handoff binder](binder/HANDOFF-BINDER.md) ([about](binder/README.md)) - complete linear reading experience.
- [Documentation policy](documentation-policy.md) · [Coverage matrix](coverage-matrix.md) · [Claim-to-source ledger](claim-to-source-ledger.md).
- [Old-to-new map](history/old-to-new-map.md) · [Immutable archive](archive/2026-08-26/MANIFEST.md).
