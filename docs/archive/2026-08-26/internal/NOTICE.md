<!--
status: historical
immutable: true
-->

# internal/ - intentionally not archived

The rewrite's archive template reserves an `internal/` slot for the project's
internal design and threat-model documentation. That material is **deliberately
excluded from this public, git-tracked archive.**

`internal/**` (and `docs/superpowers/**`, `.superpowers/**`) are gitignored and kept
local-only. The project's `.gitignore` records the reason verbatim:

> Internal design, threat-model, and process docs - kept local only, never committed.
> These describe how the honeypot detects and logs; publishing them hands an attacker
> the blueprint. Removed from tracking after they were found on the public repo.

Copying those files into `docs/archive/` would re-publish exactly what was
deliberately removed from the public repository. They therefore live only in their
original local paths and are not reproduced anywhere in the tracked tree.

No content, secret, address, or hostname from those files is disclosed here. See
`../MANIFEST.md` ("What was deliberately NOT archived here, and why").
