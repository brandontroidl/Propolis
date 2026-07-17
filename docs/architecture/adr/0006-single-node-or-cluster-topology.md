# ADR 0006: One codebase runs single-node or as a cluster

Status: Accepted 2026-07-16

## Context

The operator has several WAN IPs NAT'd to them and wants every hit attributed to
the WAN IP it arrived on, with cross-WAN breadth folded into one attacker score
(ADR 0004). Some deployments are a single multi-homed host; others spread
collection across several nodes. The purpose of running more than one collector
is signal aggregation, so an attacker's breadth counts, not uptime. High
availability from PostgreSQL replication is a welcome secondary benefit, not the
driver.

## Decision

Ship one codebase that runs unchanged as a single node or as a multi-node
cluster.

- Single node: one instance bound to one WAN IP, or one multi-homed node bound
  to several WAN IPs. This is the common single-operator deployment.
- Cluster: multiple collector nodes, each bound to its own WAN IPs, all feeding
  one shared PostgreSQL score (ADR 0002). Every WAN-IP collector appends to the
  same event ledger (ADR 0003), so breadth aggregates into one weight regardless
  of how many hosts do the collecting.

The cluster's defining purpose is breadth aggregation. Replication and failover
are a secondary benefit that the shared Postgres store makes available.

## Alternatives considered

- Per-node independent scores reconciled later. Rejected: breadth must land in
  one shared score at write time, not be stitched together after the fact, or
  cross-WAN corroboration is lost or delayed.
- A cluster justified primarily by high availability. Rejected as a framing:
  uptime is a benefit, but designing for it first would not deliver the breadth
  requirement that actually motivates multiple collectors.

## Consequences

The same binary and configuration model serves both shapes; topology is a
deployment choice, not a code fork. All collectors depend on reaching the shared
store. Per-WAN attribution is surfaced to the operator internally but kept off
external feeds and vendor reports, preserving the collateral and privacy stance
for destination addresses.
