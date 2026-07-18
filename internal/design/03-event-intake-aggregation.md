# 03 - Event intake + multi-node aggregation

Status: design pending (not yet brainstormed)

## Scope

How signed events from N WAN-IP collectors land in the one shared PostgreSQL score, each hit carrying its WAN attribution. Covers the intake path from sensor output into the append-only event ledger and the multi-node aggregation transport that feeds every collector's signal into one shared attacker score, so cross-WAN and cross-sensor breadth counts toward weight.

## Goals

One shared score, not per-node scores. Breadth across the operator's WAN IPs raises an attacker's weight and recommendation while the eligibility floor stays unchanged: breadth never makes an ineligible IP eligible. Per-hit WAN attribution is preserved for operator inspection but stays off the external feed and vendor reports.

## Dependencies

Sub-project 1 (core scoring layer): the ledger, scoring, and breadth model. Sub-project 2 (sensor framework): the signed-event producers this layer consumes.

## Key open questions

- Transport: direct PostgreSQL write from each collector versus a broker in front of intake.
- Backpressure when a collector outruns intake.
- Deduplication of the same hit observed across nodes.
- Leader election for the scorer so cluster nodes do not double-count or double-score.
