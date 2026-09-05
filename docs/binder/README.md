<!--
title: Binder
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Binder

The binder is a generated review artifact from the 2026-08-26 documentation pass; it
is not updated with every commit, the pages it links are.

The **[handoff binder](HANDOFF-BINDER.md)** is a single linear document that
assembles the whole Propolis picture in reading order across 17 numbered sections
- identity, status, architecture, security, deployment, configuration, operations,
data lifecycle, incident response, development, maintenance, troubleshooting,
governance, limitations, reference, and provenance.

## Who it is for

- **Offline reading** - one document to read top to bottom without navigating the
  corpus.
- **Project transfer** - a new owner's day-one orientation.
- **Audit** - a linear pass over posture, controls, and known limitations.
- **AI ingestion** - a single self-contained file for a downstream tool.

## How it is assembled

The binder is a **synthesis and index, not a second source of truth.** Each
section summarizes the canonical pages that own its facts and links to them for
full depth; it does not restate the exact values those pages own (env vars, ports,
paths, schema, scoring constants, routes). The canonical corpus under
[`docs/`](../README.md) remains the single source of truth - where the binder and
a canonical page ever disagree, the canonical page wins.

Start reading: **[HANDOFF-BINDER.md](HANDOFF-BINDER.md)**.
