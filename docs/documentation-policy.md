<!--
title: Documentation policy
audience: maintainer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Documentation policy

How this repository's documentation is organized, labeled, and kept honest. This
policy governs the corpus under `docs/`; it is itself a `current` document.

## Source of truth

The **current source code, tests, config parsing, SQL migrations, and `deploy/`
files are authoritative.** Documentation describes what the code does, not what a plan
or comment intended. When a doc and the code disagree, the code is right and the doc
is a bug. Material claims are backed by the [claim-to-source ledger](claim-to-source-ledger.md).

The project keeps additional **private** design, threat-model, and roadmap material
that is deliberately gitignored (`internal/`, `docs/superpowers/`) and is never a
source for, nor referenced by, the public corpus - publishing that material would
hand an attacker the honeypot's detection blueprint. Public docs stand on their own
from code evidence.

## Status vocabulary

Every published document **under `docs/`** carries a metadata header (below) whose
`status` is one of:

| Status | Meaning | Where it lives |
|---|---|---|
| `current` | Describes the code as it is now; maintained. | `docs/` (most pages) |
| `historical` | A point-in-time record, not maintained. | `docs/history/`, `docs/archive/` |
| `superseded` | Replaced by a newer document; kept for continuity, points forward. | anywhere, links to successor |
| `draft` | Incomplete; not yet trustworthy as reference. | temporary |
| `planned` | Describes intended, not-yet-implemented behavior. | rare; always labeled inline too |

Within any document, an individual claim that is not directly evidenced by code is
tagged inline `[inferred]`; not-yet-shipped behavior is tagged `[planned]`. Shipped
behavior carries no tag.

## Document metadata header

Every published `.md` **under `docs/`** begins with an HTML comment (invisible when
rendered):

```
<!--
title: <short title>
audience: <evaluator|operator|deployer|developer|security|maintainer|researcher|all>
status: <current|historical|superseded|draft|planned>
owner: maintainer
applies-to: <release the doc describes>
last-verified: <YYYY-MM-DD>
-->
```

`applies-to` currently reads `0.3.0 (untagged; latest tag v0.1.0)` across the corpus,
reflecting the real version state (see
[overview/maturity-and-status](overview/maturity-and-status.md)).

Root-level files that follow GitHub placement conventions - `README.md`,
`DOCUMENTATION.md`, `INSTALL.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`LICENSE.md` - are **exempt** from the metadata-header rule; it governs the `docs/`
corpus only. They are still bound by the source-of-truth and public-safety rules
above.

## One canonical owner per fact

Each fact has exactly one home to prevent drift. Reference pages own exact values;
narrative and guide pages explain and link to them. The ownership map is in the
[coverage matrix](coverage-matrix.md); the reference owners are listed in
`docs/reference/`. Do not restate an owned value in a second page - link to it.

## Corpus controls

- [Coverage matrix](coverage-matrix.md) - component x documentation coverage.
- [Claim-to-source ledger](claim-to-source-ledger.md) - material claims mapped to code.
- [Glossary](reference/glossary.md) - the terminology standard.
- [Old-to-new map](history/old-to-new-map.md) - where former public docs went.
- [Archive map](history/archive-map.md) - the immutable pre-rewrite archive.

## Change discipline

When code changes in a way that affects a documented fact, update the owning page and
its `last-verified` date in the same change. When a page is replaced, set the old
page's status to `superseded` and add a forward link rather than deleting it, unless
it is being folded into the archive.

## Public-repository safety

No live credential, token, private address, real hostname, identifying log line, or
captured-malware sample appears anywhere in the published corpus or the archive.
Necessary historical material is preserved with harmful specifics redacted; every
redaction is noted without disclosing the redacted value. See
[security/residual-risks](security/residual-risks.md) for what is deliberately not
claimed.
