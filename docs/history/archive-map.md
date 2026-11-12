<!--
title: Archive map
audience: all
status: historical
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Archive map

The pre-rewrite public documentation is preserved, byte-exact and immutable, under
[`docs/archive/2026-08-26/`](../archive/2026-08-26/MANIFEST.md). Do not edit files
under `docs/archive/`; corrections belong in the current corpus, never in the
archive. For where each old document's content now lives, see
[old-to-new-map](old-to-new-map.md).

## What the archive holds

Source commit: `2ed7782753a1ac4ca5d59286d4f1c22f1616a779` (branch `main`), working
tree clean at archive time. The archive captures byte-exact copies of the
repository's **public (git-tracked) documentation surface** at that commit:

| Archived path | Original repository path |
|---|---|
| `root/README.md` | `README.md` |
| `root/INSTALL.md` | `INSTALL.md` |
| `root/SECURITY.md` | `SECURITY.md` |
| `root/CHANGELOG.md` | `CHANGELOG.md` |
| `root/CONTRIBUTING.md` | `CONTRIBUTING.md` |
| `root/LICENSE.md` | `LICENSE.md` |
| `docs/deploy/blocklist-README.md` | `deploy/blocklist-README.md` |

Alongside these it carries `MANIFEST.md` (provenance and the archived-file list),
`CHECKSUMS.sha256` (a SHA-256 over every archived file), and `internal/NOTICE.md`
(recording what was deliberately excluded).

## Verifying integrity

The archive ships a SHA-256 manifest. From the archive directory:

```
cd docs/archive/2026-08-26
sha256sum -c CHECKSUMS.sha256
```

Every listed file must report `OK`. This is a read-only verification; it changes
nothing.

## Deliberately excluded: the private blueprint

The archive's `internal/` slot is **intentionally empty of source material** - it
carries only a `NOTICE.md`. The project's internal design, threat-model, and
detection/logging blueprint documents (`internal/**`, and the gitignored
`docs/superpowers/**` and `.superpowers/**`) were **not archived**, because copying
them into the git-tracked archive would re-publish material that was deliberately
removed from the public repository. Publishing the detection/logging blueprint would
hand an attacker the honeypot's fingerprinting playbook.

The live `.env` (which holds a database connection string) was likewise **never
archived** - it is a secret and is excluded on those grounds.

Those files remain in their original local paths, unchanged and private. The archive
records only their existence and the reason for exclusion; no content, secret,
address, or hostname from them is disclosed. See
[`docs/archive/2026-08-26/MANIFEST.md`](../archive/2026-08-26/MANIFEST.md) and its
`internal/NOTICE.md`.
