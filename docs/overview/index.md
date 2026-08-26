<!--
title: Overview
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Propolis

Propolis is a self-hosted, single-node honeypot and threat-intelligence platform.
It runs native protocol sensors that impersonate common services, records what
attackers do against your own WAN addresses, scores each source by corroborated
evidence, and - only after you approve each case - publishes a firewall blocklist
and files vendor abuse reports.

It is defensive tooling for infrastructure you own or are authorized to monitor.
See [Ethical use](ethical-use.md) for the boundaries this depends on.

## What it is

- A **honeypot layer**: nine sensor crates presenting twelve protocol listeners
  (SSH, Telnet, HTTP, FTP, SMTP, Redis, ADB, plus VNC/MySQL/MSSQL/PostgreSQL/MongoDB
  from the credential sensor), each a separate OS process. See
  [Capabilities](capabilities.md).
- A **scoring and review pipeline**: a hash-chained event ledger, a time-decayed
  per-IP score with a confirmed-real gate, an operator review queue, and a two-tier
  blocklist feed.
- An **operator console**: a loopback web dashboard for triage, review, and feed status.
- A **single Rust workspace** deployed as one unified daemon plus the sensor
  processes. See [`../architecture/index.md`](../architecture/index.md).

## What it does

- Captures attacker traffic (credentials, commands, uploaded samples) on services
  you deliberately expose as decoys.
- Corroborates activity across multiple WAN addresses and multiple sensor protocols
  to distinguish genuine attackers from spoofed or incidental traffic.
- Gates every outbound action (feed listing, vendor report) behind operator approval.
- Publishes a blocklist you sync to your own firewall.

## What it does NOT do

- It is **not a network IDS or IPS** - it observes traffic delivered to its own
  decoy listeners, not arbitrary traffic on the wire, and it does not block inline.
- It is **not multi-tenant SaaS or a managed service** - it is a single node you
  operate yourself.
- It is **not an offensive or exploitation tool**.
- It ships **no built-in TLS** - the console is plain HTTP on loopback; any
  transport encryption is operator-provided. See [Limitations](limitations.md).
- It is **not "egress-free" as a whole** - sensors are egress-free by construction,
  but the platform has a few enrichment/reporting egress paths, all operator-gated
  and defaulting off. See [`../security/outbound-controls.md`](../security/outbound-controls.md).

## Use cases

- Running attacker-facing decoys on your own WAN IPs to collect first-party threat
  intelligence.
- Producing a firewall blocklist grounded in evidence you captured, not a
  third-party feed.
- Capturing malware samples dropped by attackers for later analysis under your own
  custody. See [`../security/malware-custody.md`](../security/malware-custody.md).

## Where to go next

- Pick your path in [Audiences](audiences.md).
- Detailed feature inventory: [Capabilities](capabilities.md).
- What it deliberately excludes: [Non-goals](non-goals.md).
- Current maturity and release state: [Maturity and status](maturity-and-status.md).
- Known limitations and residual risks: [Limitations](limitations.md).
