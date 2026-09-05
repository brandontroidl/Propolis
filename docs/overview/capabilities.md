<!--
title: Capabilities
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Capabilities

What Propolis does, in enough detail to decide whether it fits. Exact ports,
thresholds and variable names are in the [reference](../reference/ports-and-protocols.md)
pages.

## Sensors

Nine sensor programs cover twelve protocols. Each runs as its own systemd service under
its own user.

| Sensor | Protocol | What it records |
|---|---|---|
| `sensor-ssh` | SSH | Handshake, login attempts, shell commands, SCP and SFTP uploads |
| `sensor-telnet` | Telnet | Login attempts, shell commands, including XOR-obfuscated Mirai payloads |
| `sensor-http` | HTTP | Request paths, headers, POST bodies |
| `sensor-ftp` | FTP | Login attempts, STOR uploads |
| `sensor-smtp` | SMTP | AUTH credentials, message envelope and body |
| `sensor-redis` | Redis | AUTH, config and command probes |
| `sensor-adb` | ADB | Shell commands, pushed files |
| `sensor-cred` | VNC, MySQL, MSSQL, PostgreSQL, MongoDB | Authentication attempts and usernames |
| `sensor-catchall` | any TCP or UDP port | Unsolicited probes, without ever replying |

Sensors make no outbound connections: the attacker-facing crates have no HTTP client
in their dependency tree, and a workspace test over every sensor manifest fails the
build if one appears.
They hold no database connection and no secrets, and they drop captured passwords at
capture time. Per-protocol behavior, including what each sensor impersonates and the
byte caps on what it keeps, is in [sensor behavior](../reference/sensor-behavior.md).

## Scoring

Each event is appended to a hash-chained ledger in PostgreSQL and folded into a
per-IP score that decays with a six-hour half-life. Two things shape it:

- An IP only becomes eligible for a tier or a vendor report after a completed TCP
  handshake has authenticated against a sensor. UDP traffic and bare SYNs cannot do
  that, so a spoofed source cannot be pushed into the feed by someone else's packets.
- Activity across more than one of your addresses, and across more than one protocol,
  weighs more than repeated hits on a single port.

Weights, thresholds and the half-life are in
[scoring and feed](../reference/scoring-and-feed.md).

## Review and output

An IP that reaches a tier lands in the review queue. You approve, reject or snooze it
in the console or with the `review` command. Approval is what lets it into the
`aggressive` or `standard` feed files and, if a vendor is configured, what allows a
report to be filed.

The retention feeds (`all-24h`, `all-7d` and so on) are different: they hold every
approved entry seen within the window, and also any source that completed a thousand
or more TCP connections in the last day. That volume rule needs no approval; it exists
so a flood is blocked promptly. Volume alone never triggers a vendor report.

The feed builder writes text, JSON, CSV, CIDR, ipset, nftables, pf, alias, hosts and
RPZ formats to a local directory with a checksummed manifest, atomically, every fifteen
minutes by default. Getting those files to a firewall or a public repository is your
step; a sync script is provided but not scheduled for you.

## Console

A server-rendered web console on loopback, plain HTTP: dashboard, review queue,
per-IP evidence with session grouping, samples, feed status, integrity check, live
logs, and Prometheus metrics. Login is password-based with Argon2id, signed session
cookies, CSRF protection and rate limiting. There is no built-in TLS.

## Optional integrations

All off until configured:

- VirusTotal hash lookups for captured samples; uploading unknown bodies is a further
  opt-in.
- Fetching a dropper from a URL an attacker pasted into a fake shell, behind an SSRF
  guard, into the same quarantine spool.
- Abuse reports to AbuseIPDB, DShield and OTX.
- Forward-confirmed reverse DNS on the IP page, display only.
- Push alerts over ntfy when the node degrades.
- Offline GeoLite2 geo and ASN lookup from local files, used for display and for
  suppressing trusted-organisation ASNs from the feed.

Which of these send anything off the box, and what they send, is set out in
[outbound controls](../security/outbound-controls.md).
