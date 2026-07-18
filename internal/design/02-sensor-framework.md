# 02 - Native sensor framework + catch-all + first TCP-auth sensor

Status: design pending (not yet brainstormed)

## Scope

The safe-by-construction harness for self-authored passive honeypots, plus two sensors built on it: the catch-all listener across many TCP and UDP ports, and one TCP-authenticated honeypot (SSH or Telnet). Every sensor emits structured, signed events and nothing else. The harness fixes the shared contract: unprivileged process, no database handle, no secrets, passive-only (no active response, no hack-back), and passwords and payloads dropped at capture time.

## Goals

Give the pipeline a non-spoofable leg. The catch-all supplies breadth signal; the TCP-authenticated honeypot supplies the completed-handshake event that the eligibility floor requires, since only a confirmed-real event can make an IP eligible. Sensors carry the hardened deployment shape by construction, never a weakly-sandboxed third-party unit.

## Dependencies

Sub-project 1 (core scoring layer): the event schema, signal categories, and hash-chained ledger the sensors target.

## Key open questions

- Signed-event format and transport from sensor to intake.
- Sandboxing and isolation model that keeps an internet-facing listener free of secrets and database reach.
- Which SSH and Telnet interactions to emulate, and to what depth, to earn an authenticated event without real command execution.
