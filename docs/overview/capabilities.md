<!--
title: Capabilities
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Capabilities

This page inventories what Propolis does. Exact values (ports, thresholds, env
vars, routes) are owned by the [`../reference/`](../reference/ports-and-protocols.md)
pages and linked, not restated here.

## Sensors: 9 crates, 12 protocols

Nine sensor crates present twelve protocol listeners. Seven crates are one protocol
each; the credential sensor (`sensor-cred`) serves five database/remote protocols
from separate modules.

| Sensor crate | Protocol(s) | Captures (summary) |
|---|---|---|
| `sensor-ssh` | SSH | Handshake, login attempts, shell commands, SCP/SFTP uploads |
| `sensor-telnet` | Telnet | Login attempts, shell commands (incl. XOR-deobfuscated Mirai payloads) |
| `sensor-http` | HTTP | Request paths, headers, POST bodies |
| `sensor-ftp` | FTP | Login attempts, STOR uploads |
| `sensor-smtp` | SMTP | AUTH credentials, message envelope/body |
| `sensor-redis` | Redis | AUTH, config/command probes |
| `sensor-adb` | ADB | Shell commands, `sync:` push capture |
| `sensor-cred` | VNC, MySQL, MSSQL, PostgreSQL, MongoDB | Authentication / username capture |
| `sensor-catchall` | protocol-agnostic TCP/UDP | Unprompted traffic (`catchall_probe`) |

Each sensor runs as a **separate OS process** under its own systemd unit. Sensors
are **egress-free by construction** - each attacker-facing crate has no HTTP client
in its dependency tree, enforced by per-sensor tests that ban outbound HTTP
libraries. Sensors hold no database handle and no secrets, and drop captured
passwords at capture time. Per-protocol capture behavior:
[`../reference/sensor-behavior.md`](../reference/sensor-behavior.md). Sensors have no
compiled-in default port; the standard port mapping (SSH 22, etc.) is what the
deploy units configure - [`../reference/ports-and-protocols.md`](../reference/ports-and-protocols.md).

## Scoring with a confirmed-real gate

Each attacker IP accumulates a time-decayed score from corroborated evidence,
recorded in a hash-chained event ledger.

- **Confirmed-real gate**: an IP earns a feed tier or a vendor report only after a
  completed TCP handshake authenticated against a sensor proves the source is
  genuine. Spoofable UDP or lone-SYN traffic never latches this.
- **Cross-sensor breadth**: hitting multiple WAN addresses and multiple protocols
  weighs more than a single port.
- **Eligibility latch**: an IP becomes feed-eligible once confirmed-real with at
  least two recorded events; the latch is sticky until explicit delisting.

Exact weights, thresholds, half-life, and retention windows are owned by
[`../reference/scoring-and-feed.md`](../reference/scoring-and-feed.md) and
[`../reference/events-and-signals.md`](../reference/events-and-signals.md).

## Operator review

A review queue state machine gatekeeps every outbound action. Nothing is listed or
reported automatically: an operator approves, rejects, or snoozes each case, via the
console or the `review` CLI. See [`../architecture/pipeline.md`](../architecture/pipeline.md).

## Two-tier blocklist feed

Approved IPs are published as a two-tier feed (`aggressive` and `standard`), each
tier its own file with its own TTL, exported as text/JSON/CSV/CIDR with an atomic
publish and a checksummed manifest. Feed membership is decided by retention windows,
not the live decaying score. Trusted-org ASN suppression is available (opt-in, empty
by default). Feed publishing to a remote repository is an operator setup step, **not**
a shipped timer or cron. See [`../reference/scoring-and-feed.md`](../reference/scoring-and-feed.md).

## Operator console

A server-rendered web dashboard (axum + minijinja + HTMX + Chart.js) on a loopback
`TcpListener`, plain HTTP (no built-in TLS). It exposes 30 routes (7 public,
23 session-gated). Features: a six-card stat strip, timelines and distribution
charts, the review queue, per-IP detail with an evidence drawer, feed status, a
theme system (graphite/cream/system/hacker), `/metrics`, and a live `/logs` viewer.
Auth is Argon2id passwords with HMAC session cookies, CSRF protection, and login
rate-limiting. The console sets no global CSP (only `/samples/download` sets one).
Routes are owned by [`../reference/console-routes.md`](../reference/console-routes.md);
console architecture in [`../architecture/console.md`](../architecture/console.md).

## Opt-in enrichment and reporting

All of the following are **operator-gated and default OFF**:

- **VirusTotal** scanning of captured samples.
- **Vendor abuse submitters** (AbuseIPDB, DShield, OTX).
- **Forward-confirmed reverse DNS** on the IP-detail page (`PROPOLIS_CONSOLE_RDNS_ENABLED`);
  display-only, never a suppression signal.
- **Operational self-alerting** over ntfy (`PROPOLIS_OPS_ENABLED`).
- **Offline MaxMind GeoLite2** geo/ASN enrichment (`PROPOLIS_GEOIP_DIR`) - **local
  file reads, not network**; degrades to "not configured" when the databases are absent.

The four network-egress paths above and the reverse-DNS lookup are the platform's
only outbound paths beyond PostgreSQL, each subject to a forbidden-egress guard that
rejects own-host/reserved targets. Full treatment:
[`../security/outbound-controls.md`](../security/outbound-controls.md) and
[`../reference/integrations.md`](../reference/integrations.md).
