<!--
title: Overview
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Overview

Propolis runs decoy services on addresses you own, records what attackers do to
them, scores each source address from that evidence, and turns the result into a
firewall blocklist and, if you choose, abuse reports to third-party vendors. It is a
single node: one PostgreSQL database, one daemon, and one hardened process per sensor.

Use it on infrastructure you own or are authorized to monitor. [Ethical use](ethical-use.md)
sets out the boundaries this depends on.

## What comes out of it

- **Evidence.** Login attempts, shell commands, uploaded files and downloaded droppers,
  stored in an append-only ledger and viewable per source IP in the console.
- **A blocklist.** Two score-based tiers, `aggressive` and `standard`, plus retention
  feeds that list everything seen within a window. You sync the files to your own
  firewall; nothing is pushed anywhere unless you set that up.
- **Vendor reports.** Optional submissions to AbuseIPDB, DShield and OTX, off until
  configured.

## What needs your approval, and what does not

Score-based tier entries and every vendor report wait in the review queue for you to
approve, reject or snooze them. One path is automatic: a source that has completed a
thousand or more TCP connections and was seen in the last day is added to the
retention feeds without review, so a flood is blocked even when it never tried a login.
Such a source is never reported to a vendor on volume alone. The exact rule is in the
[scoring and feed reference](../reference/scoring-and-feed.md).

## What it is not

- Not an IDS or IPS. It sees only traffic sent to its own listeners and blocks nothing
  inline.
- Not multi-tenant and not a hosted service.
- Not an offensive tool. Captured payloads are stored and may be looked up, never run.
- Not TLS-terminating. The console is plain HTTP on loopback; put a proxy in front.

## Where next

[Capabilities](capabilities.md) lists the sensors and features. [Non-goals](non-goals.md),
[maturity](maturity-and-status.md) and [limitations](limitations.md) say what to expect
before exposing it. The [documentation index](../README.md) covers everything else.
