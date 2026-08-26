# Propolis documentation map

Propolis ships three coordinated documentation surfaces. This page tells you which to
use and where to start.

1. **The canonical corpus** under [`docs/`](docs/README.md) - the layered source of truth,
   one page per topic, each fact with a single owner.
2. **Audience manuals** under [`docs/manuals/`](docs/README.md#manuals) - curated,
   role-specific paths *through* the corpus (they link, they do not duplicate).
3. **The handoff binder** -
   [`docs/binder/HANDOFF-BINDER.md`](docs/binder/HANDOFF-BINDER.md) - one linear document
   for offline reading, project transfer, audit, and AI ingestion.

Documentation follows the code: the current source, tests, migrations, and `deploy/`
files are authoritative (see the [documentation policy](docs/documentation-policy.md) and
the [claim-to-source ledger](docs/claim-to-source-ledger.md)).

## Start by role

| You are a... | Start here |
|---|---|
| First-time visitor / evaluator | [manuals/evaluator](docs/manuals/evaluator.md), then [overview](docs/overview/index.md) |
| Just want to try it | [manuals/quickstart](docs/manuals/quickstart.md) |
| Deploying to production | [manuals/deployment](docs/manuals/deployment.md) + [production-readiness checklist](docs/getting-started/production-readiness-checklist.md) |
| Operating a live node | [manuals/operations](docs/manuals/operations.md) |
| Security reviewer / defender | [manuals/security](docs/manuals/security.md), [threat model](docs/security/threat-model.md) |
| Incident responder | [manuals/incident-response](docs/manuals/incident-response.md) |
| Contributor | [manuals/contributor](docs/manuals/contributor.md) |
| Maintainer | [manuals/maintainer](docs/manuals/maintainer.md) |
| Researcher | [manuals/researcher](docs/manuals/researcher.md) |
| AI agent / auditor (whole picture) | [the handoff binder](docs/binder/HANDOFF-BINDER.md) |

## The corpus at a glance

| Section | Contents |
|---|---|
| [overview/](docs/overview/index.md) | mission, audiences, capabilities, non-goals, maturity, limitations, ethics |
| [getting-started/](docs/getting-started/evaluation-deployment.md) | prerequisites, evaluation bring-up, first capture, console tour, readiness, teardown |
| [architecture/](docs/architecture/index.md) | components, process topology, sensors, event/sample lifecycle, pipeline, console, storage, trust boundaries, concurrency, decisions |
| [operations/](docs/operations/installation.md) | deployment models, installation, configuration, secrets, networking/TLS, lifecycle, observability, capacity, retention, backup, upgrade/DR, procedures |
| [security/](docs/security/threat-model.md) | threat model, attack surfaces, authn/authz, input handling, never-execute, outbound controls, malware custody, privacy, hardening, residual risks, disclosure |
| [development/](docs/development/repository-tour.md) | repo tour, toolchain, build/test, conventions, adding a sensor, schema/migrations, release |
| [reference/](docs/reference/environment-variables.md) | env vars, ports, paths, database, events/signals, sensor behavior, routes, scoring/feed, integrations, budgets, commands, dependencies, glossary |
| [governance/](docs/governance/maintenance-and-support.md) | maintenance, versioning, release policy, roadmap, contribution, licensing |
| [troubleshooting/](docs/troubleshooting/index.md) | symptom-based diagnosis across startup, DB, queue/spool, sensors, console, integrations, backup |
| [history/](docs/history/changelog.md) | changelog, decisions index, completed/superseded work, audits, archive map |

## Corpus controls

- [Documentation policy](docs/documentation-policy.md) - status vocabulary, metadata standard, one-owner-per-fact rule.
- [Coverage matrix](docs/coverage-matrix.md) - component x documentation coverage.
- [Claim-to-source ledger](docs/claim-to-source-ledger.md) - material claims mapped to code evidence.
- [Glossary](docs/reference/glossary.md) - terminology standard.
- [Old-to-new map](docs/history/old-to-new-map.md) and the immutable
  [pre-rewrite archive](docs/archive/2026-08-26/MANIFEST.md).

## A note on scope and honesty

Propolis keeps private design/threat-model material out of the public repository
(gitignored) because publishing a honeypot's detection blueprint would defeat it. The
public corpus therefore stands on code evidence alone and states residual risks plainly;
it does not imply legal, regulatory, or production certification. See
[limitations](docs/overview/limitations.md) and
[residual risks](docs/security/residual-risks.md).
