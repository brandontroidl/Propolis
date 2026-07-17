# 05 - Feed builder + exporters + publisher

Status: design pending (not yet brainstormed)

## Scope

The two-tier, collateral-safe public blocklist built from approved IPs. Entries are host routes by default; a whole block collapses to an aggregate entry only when the entire block is independently listed, so aggregation never blocks an unlisted address. Covers build-time and publish-time exclusions, the export formats, and out-of-band publication.

## Goals

Publish only what the operator has approved, in a form that cannot collateral-block a third party. Exclusions apply at build and are re-validated at publish, fail-closed, so a private, reserved, allowlisted, or delisted address can never reach the feed. Publication is out-of-band from the scoring node.

## Dependencies

Sub-project 1 (core spine): the score and snapshot the builder reads. Sub-project 4 (review + reporting): the approved-IP set that is the feed's only source.

## Key open questions

- Exporter set: which machine-readable and firewall formats to emit per tier.
- Expiry policy: per-tier lifetime and the anchor it decays from.
- Publish transport: the out-of-band channel and how the push credential is held.
