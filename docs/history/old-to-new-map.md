<!--
title: Old-to-new document map
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Old-to-new document map

Where each pre-rewrite public document's content now lives. The 2026-08-26
documentation rewrite replaced a small root-level doc set with the layered corpus
under `docs/`. GitHub and plain Markdown cannot perform HTTP redirects, so obsolete
root paths are handled with **explicit compatibility stubs** (a short file pointing to
the canonical successor), not silent redirects.

The verbatim originals are preserved, immutable, under
[`docs/archive/2026-08-26/`](../archive/2026-08-26/MANIFEST.md).

| Former public document | Canonical successor(s) | Old path today |
|---|---|---|
| `README.md` | `README.md` (rewritten as a concise front door) + [`DOCUMENTATION.md`](../../DOCUMENTATION.md) | Replaced in place |
| `INSTALL.md` | [getting-started/evaluation-deployment](../getting-started/evaluation-deployment.md), [operations/installation](../operations/installation.md), [operations/configuration](../operations/configuration.md), [operations/networking-tls](../operations/networking-tls.md), [security/hardening-checklist](../security/hardening-checklist.md) | Compatibility stub at `INSTALL.md` |
| `SECURITY.md` | [security/vulnerability-disclosure](../security/vulnerability-disclosure.md) | `SECURITY.md` kept at root (GitHub security-policy file) as a short pointer |
| `CHANGELOG.md` | [history/changelog](changelog.md) | `CHANGELOG.md` retained at root as the canonical changelog file, with a pointer into the corpus |
| `CONTRIBUTING.md` | [governance/contribution](../governance/contribution.md), [development/](../development/repository-tour.md), [manuals/contributor](../manuals/contributor.md) | `CONTRIBUTING.md` kept at root (GitHub contribution file) as a short pointer |
| `LICENSE.md` | `LICENSE.md` (unchanged - exact legal text preserved) | Left unchanged |
| `deploy/blocklist-README.md` | [reference/integrations](../reference/integrations.md) / [operations/routine-procedures](../operations/routine-procedures.md) | Retained in place with a pointer |

## Notes

- The former `CONTRIBUTING.md` pointed readers at `internal/design/`,
  `internal/architecture/adr/`, and `internal/roadmap.md`. Those paths are **private
  (gitignored)** and are not referenced by the new corpus; the public architecture and
  development sections replace them. See
  [architecture/decisions](../architecture/decisions.md) and
  [history/decisions-index](decisions-index.md).
- No former public document was deleted without a successor or a preserved archive
  copy.
