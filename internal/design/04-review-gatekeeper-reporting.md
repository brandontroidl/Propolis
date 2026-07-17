# 04 - Review queue + gatekeeper + reporting

Status: design pending (not yet brainstormed)

## Scope

The human review queue with one open item per IP driven by a state machine, the per-vendor submission gate (cooldown, rate-limit, per-vendor policy), and the vendor adapters (AbuseIPDB, DShield, OTX). This layer holds the mandatory human-approval gate: nothing reaches a vendor without explicit operator approval.

## Goals

Turn a recommended IP into a ratified report without ever auto-firing. The queue surfaces recommended IPs and holds exactly one open decision per IP. The gatekeeper is the second, per-vendor gate that a candidate clears at submission time, distinct from the eligibility floor. Reporting is idempotent under retry so a transient failure never double-submits or silently drops a charge.

## Dependencies

Sub-project 1 (core spine): the score, snapshot, and eligibility/weight/recommendation model the queue reads.

## Key open questions

- Gate predicate details: the ordered per-vendor checks and their fail-closed defaults.
- Idempotency of retries: how a retried submission is deduplicated against one that may already have landed.
- Category mapping from internal signal categories to each vendor's abuse taxonomy.
