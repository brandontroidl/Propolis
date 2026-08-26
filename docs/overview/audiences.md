<!--
title: Audiences
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Audiences

Propolis documentation is organized by role. Each audience has a curated manual
under [`../manuals/`](../manuals/evaluator.md) that guides you through the relevant
canonical pages without duplicating them.

| You are... | Start here | Then |
|---|---|---|
| **Evaluating** whether Propolis fits | [`../manuals/evaluator.md`](../manuals/evaluator.md) | [Capabilities](capabilities.md), [Non-goals](non-goals.md), [Maturity and status](maturity-and-status.md), [Limitations](limitations.md) |
| **Trying it quickly** (non-production) | [`../manuals/quickstart.md`](../manuals/quickstart.md) | [`../getting-started/evaluation-deployment.md`](../getting-started/evaluation-deployment.md), [`../getting-started/first-capture.md`](../getting-started/first-capture.md) |
| **Deploying** to real infrastructure | [`../manuals/deployment.md`](../manuals/deployment.md) | [`../operations/deployment-models.md`](../operations/deployment-models.md), [`../getting-started/production-readiness-checklist.md`](../getting-started/production-readiness-checklist.md) |
| **Operating** a running instance | [`../manuals/operations.md`](../manuals/operations.md) | [`../operations/routine-procedures.md`](../operations/routine-procedures.md), [`../operations/health-and-observability.md`](../operations/health-and-observability.md) |
| **Assessing security** posture | [`../manuals/security.md`](../manuals/security.md) | [`../security/threat-model.md`](../security/threat-model.md), [`../security/outbound-controls.md`](../security/outbound-controls.md), [`../security/residual-risks.md`](../security/residual-risks.md) |
| **Responding to an incident** | [`../manuals/incident-response.md`](../manuals/incident-response.md) | [`../security/malware-custody.md`](../security/malware-custody.md), [`../troubleshooting/index.md`](../troubleshooting/index.md) |
| **Contributing** code or docs | [`../manuals/contributor.md`](../manuals/contributor.md) | [`../development/repository-tour.md`](../development/repository-tour.md), [`../development/build-and-test.md`](../development/build-and-test.md) |
| **Maintaining** the project | [`../manuals/maintainer.md`](../manuals/maintainer.md) | [`../development/release-procedure.md`](../development/release-procedure.md), [`../governance/release-policy.md`](../governance/release-policy.md) |
| **Researching** captured data | [`../manuals/researcher.md`](../manuals/researcher.md) | [`../reference/events-and-signals.md`](../reference/events-and-signals.md), [`../reference/database.md`](../reference/database.md) |

## Reference and history

Exact values (env vars, ports, paths, database schema, scoring constants, console
routes) live in [`../reference/`](../reference/environment-variables.md); every other
page links to those rather than restating them. Project history, changelog, and
superseded material live in [`../history/`](../history/changelog.md).
