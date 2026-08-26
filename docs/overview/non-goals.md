<!--
title: Non-goals
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Non-goals

What Propolis deliberately does not attempt. These are scope decisions, not missing
features; see [Limitations](limitations.md) for residual risks within scope.

- **Not a network IDS/IPS.** Propolis observes traffic that reaches its own decoy
  listeners. It does not inspect arbitrary traffic on the wire and does not block
  inline. The blocklist it produces is synced to your firewall out of band.

- **Not multi-tenant or SaaS.** It is a single-node platform you run yourself. There
  is no tenant isolation model, no per-customer separation, no hosted control plane.

- **Not a managed service.** There is no vendor operating it for you, no SLA, and no
  remote support plane. You own deployment, upgrades, backups, and incident response.
  See [`../operations/`](../operations/routine-procedures.md).

- **Not an offensive or exploitation tool.** Propolis captures and characterizes
  hostile activity against your own infrastructure. It does not attack, scan, or
  exploit third parties. See [Ethical use](ethical-use.md).

- **No built-in TLS.** The console serves plain HTTP on a loopback listener. Transport
  encryption, if needed, is operator-provided (e.g. a reverse proxy) `[inferred]`.
  See [`../operations/networking-tls.md`](../operations/networking-tls.md).

- **Not fully egress-free.** Sensors are egress-free by construction, but the platform
  has a small number of enrichment/reporting egress paths. Every one is operator-gated
  and defaults off. See [`../security/outbound-controls.md`](../security/outbound-controls.md).

- **No automatic public action.** No IP is added to the feed and no vendor abuse
  report is filed without explicit operator approval per case.

- **No bundled threat-intel data.** GeoLite2 databases are not shipped; enrichment
  degrades gracefully to "not configured" when absent. The feed is built from your
  own captures, not aggregated third-party feeds.

- **No certification claims.** Propolis is source-available software provided as-is;
  it is not production-blessed, certified, or compliance-validated. See
  [Maturity and status](maturity-and-status.md).
