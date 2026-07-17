# 06 - Web console + observability

Status: design pending (not yet brainstormed)

## Scope

The single-operator web console for review and inspection, with per-WAN attribution surfaced to the operator, plus the observability layer: structured logging with secret and PII redaction, metrics, and health and readiness endpoints. Console security covers authentication and CSRF.

## Goals

Give the operator one place to review recommended IPs, act on the approval gate, and inspect an IP's evidence and its per-WAN breadth. Per-WAN attribution is internal-only and never crosses to the feed or vendor reports. Observability makes the running system legible: logs redact secrets and attacker-controlled content, metrics carry bounded labels, and readiness fails closed.

## Dependencies

Sub-project 1 (core spine). Consumes sub-project 3 (intake and aggregation) for the per-WAN attribution it surfaces and sub-project 4 (review and reporting) for the queue it drives.

## Key open questions

- Console framework and rendering approach.
- Bind and exposure model in cluster mode: which node serves the console and how it is reached without widening the attack surface across nodes.
