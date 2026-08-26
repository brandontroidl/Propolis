<!--
status: historical
immutable: true
archived: 2026-08-26
-->

# Documentation Archive - 2026-08-26

**This archive is historical and immutable.** It preserves the repository's public
documentation exactly as it existed immediately before the 2026-08-26 documentation
rewrite. Do not edit files under `docs/archive/` - they are a point-in-time record.
Corrections belong in the current canonical corpus under `docs/`, never here.

## Provenance

| Field | Value |
|---|---|
| Source commit | `2ed7782753a1ac4ca5d59286d4f1c22f1616a779` (branch `main`) |
| Working tree at archive time | clean (no uncommitted changes) |
| Archived by | documentation rewrite, 2026-08-26 |
| Integrity | `CHECKSUMS.sha256` (SHA-256 over every archived file) |

Verify integrity from this directory with:

```
sha256sum -c CHECKSUMS.sha256
```

## What was archived

Byte-exact copies of every file that was part of the repository's **public
(git-tracked) documentation surface** at the source commit:

| Archived path | Original repository path |
|---|---|
| `root/README.md` | `README.md` |
| `root/INSTALL.md` | `INSTALL.md` |
| `root/SECURITY.md` | `SECURITY.md` |
| `root/CHANGELOG.md` | `CHANGELOG.md` |
| `root/CONTRIBUTING.md` | `CONTRIBUTING.md` |
| `root/LICENSE.md` | `LICENSE.md` |
| `docs/deploy/blocklist-README.md` | `deploy/blocklist-README.md` |

## What was deliberately NOT archived here, and why

The `internal/` subdirectory of this archive is intentionally empty of source
material (it carries only `internal/NOTICE.md`). Several categories of local files
were **excluded from this public archive on safety grounds**, because copying them
into the git-tracked `docs/archive/` tree would publish material that is deliberately
kept private:

| Excluded (local-only) | Reason |
|---|---|
| `internal/**` | Design, threat-model, and detection/logging blueprint docs. `.gitignore` records that these were *removed from tracking after being found on the public repo* - publishing them hands an attacker the honeypot's detection blueprint. Kept local-only. |
| `docs/superpowers/**` | Internal build plans and design specs (gitignored). |
| `.superpowers/**` | Internal subagent build-ledger artifacts (gitignored). |
| `.env` | Contains a live connection string (`DATABASE_URL=...`). A secret; never archived, never published. |

These files remain in their original local locations, unchanged and still private.
This archive does not reproduce their contents; only their existence and exclusion is
recorded here. No secret or private value is disclosed by this notice.

This exclusion is required by the rewrite's public-repository-safety rule
("do not publish private addresses, hostnames, identifying logs, or captured
malware") and by the project's standing decision to keep the internal blueprint
out of the tracked tree.

## Old-to-new successor map

Where each archived public document's content now lives in the canonical corpus.
GitHub and plain Markdown cannot perform HTTP redirects, so obsolete root paths are
handled with explicit **compatibility stubs** (a short file that points to the
canonical successor), not silent redirects.

| Archived document | Canonical successor(s) | Handling of the old path |
|---|---|---|
| `README.md` | `README.md` (rewritten as a concise front door) + `DOCUMENTATION.md` (corpus map) | Replaced in place |
| `INSTALL.md` | `docs/getting-started/evaluation-deployment.md`, `docs/operations/installation.md`, `docs/operations/configuration.md`, `docs/operations/networking-tls.md`, `docs/security/hardening-checklist.md` | Compatibility stub at `INSTALL.md` |
| `SECURITY.md` | `docs/security/vulnerability-disclosure.md` | `SECURITY.md` kept at root (GitHub security-policy file) as a short pointer |
| `CHANGELOG.md` | `docs/history/changelog.md` | Compatibility stub / retained pointer at `CHANGELOG.md` |
| `CONTRIBUTING.md` | `docs/development/` + `docs/manuals/contributor.md` | `CONTRIBUTING.md` kept at root (GitHub contribution file) as a short pointer |
| `LICENSE.md` | `LICENSE.md` (unchanged - exact legal text preserved) | Left unchanged |
| `deploy/blocklist-README.md` | `docs/reference/feed-formats.md` / `docs/operations/` | Retained pointer |

The authoritative, always-current version of this map is
`docs/history/old-to-new-map.md`; this table is the archive-time snapshot.
