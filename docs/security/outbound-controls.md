<!--
title: Outbound controls
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Outbound controls

This page owns the egress narrative for the whole platform.

**The accurate framing.** The sensor crates are egress-free by construction; the
platform's few enrichment and reporting egress paths are operator-gated and
default off. The workspace is **not** egress-free as a whole - `Cargo.lock`
contains `reqwest` (line 3203) and `hyper` (line 1796), used by the `review`
crate and the malware fetcher. Do not describe the system as making no outbound
requests. The real invariant has two parts: attacker-facing sensors carry no
HTTP client in their own dependency closure, and every platform-level outbound
path is opt-in and defaults off.

## Sensors carry no HTTP client

An attacker-facing sensor has no HTTP client crate in its resolved dependency
tree. `sensor-ssh` asserts this directly:
`sensor_ssh_has_no_http_client_dependency`
(`crates/sensor-ssh/tests/shell_test.rs:364`) fails if its `Cargo.toml` names
any of `reqwest, hyper, ureq, curl, isahc, surf, attohttpc` (banned list lines
372-380). The test is scoped to the sensor because `review` legitimately uses
`reqwest` for vendor reporting (its own comment states this, lines 365-371).

This explicit per-crate dependency assertion currently exists only for
`sensor-ssh`. Other sensors carry the never-execute guard (see
[never-execute.md](never-execute.md)) but not an HTTP-client-dependency test.
[inferred] Extending the assertion to the other sensor crates would make the
"sensors are egress-free" claim machine-checked for all of them rather than one.
See [residual-risks.md](residual-risks.md).

## The five outbound paths

Every path below is opt-in and defaults **off**. Several also fail closed if
their credential or topic is missing - an operator who enables a path without
supplying its secret gets a disabled path or a refused startup, never a silent
half-configured egress. Exact env-var names, defaults, and bounds are owned by
[../reference/environment-variables.md](../reference/environment-variables.md);
integration wire details by
[../reference/integrations.md](../reference/integrations.md).

### 1. VirusTotal (`review`)

Sample-hash lookups (and optionally uploads) against
`https://www.virustotal.com/api/v3/...` via a `reqwest` client
(`crates/review/src/virustotal.rs:102,190,253`). Enabled only when the flag is
on **and** a key is present:

```
vt_enabled = parse_bool_flag("PROPOLIS_VT_ENABLED", false) && !vt_api_key.is_empty()
```

(`crates/propolis/src/config.rs:521`) - default off, fail-closed to off with no
key. Uploading unknown samples is a separate flag, `PROPOLIS_VT_UPLOAD`, also
default false (`config.rs:522`). A per-UTC-day request cap bounds volume
(`virustotal.rs:22`, `RequestBudget`).

### 2. Vendor abuse submitters (`review`)

AbuseIPDB, DShield, and OTX submitters, each gated by its own
`PROPOLIS_VENDOR_<NAME>_ENABLED` flag, default false
(`crates/review/src/main.rs:149`). Fail-closed: an enabled vendor with no API
key is logged "enabled but no API key configured; treating as disabled" and
skipped (`review/src/main.rs:150-155`). Only rows the operator has **Approved**
in the review queue are ever submitted - the runner reads `list_approved` and
never touches Pending, Rejected, or Snoozed entries
(`crates/review/src/submit.rs:6-20`). See
[malware-custody.md](malware-custody.md) for the human-approval gate.

### 3. Malware fetcher (`review::fetcher`)

The one path that fetches an **attacker-supplied URL**. Gated
`fetch_enabled = parse_bool_flag("PROPOLIS_FETCH_ENABLED", false)`
(`crates/propolis/src/config.rs:527`, default false); the daemon spawns it only
`if config.fetch_enabled` (`crates/propolis/src/main.rs:794`). Because it
dereferences attacker input, it is guarded by a dedicated SSRF vetter - see the
[forbidden-egress-target guard](#the-forbidden-egress-target-guard) below.

> **Warning - egress.** Enabling the fetcher makes the honeypot retrieve a URL
> chosen by an attacker. The SSRF guard below constrains where it may connect,
> but this is a deliberate outbound request to an untrusted target. Leave it off
> unless malware retrieval is an intended operation.

### 4. Console reverse DNS (`console`)

Opt-in `PROPOLIS_CONSOLE_RDNS_ENABLED`, default disabled - the resolver is
constructed via `RdnsResolver::disabled()` (`crates/console/src/rdns.rs`, ~line
34). When enabled it issues one PTR query per address through the system
resolver. The module doc calls it "the ONE outbound lookup in the console's
otherwise egress-free enrichment" and forbids using PTR as a suppression signal
(spoofable, display-only).

### 5. Ops-alert ntfy (`propolis`)

A `reqwest` POST to the operator's own ntfy server
(`crates/propolis/src/ops_alert/dispatch.rs`). Gated `enabled`, default false;
when enabled, `ntfy_url` and `ntfy_topic` become **required** and startup fails
closed otherwise - "a monitor that cannot page must not start silently"
(`crates/propolis/src/ops_alert/config.rs:10-15`). Alert body text is sanitized
before send (`dispatch.rs:4`); each attempt carries a 30s timeout backstop
(`dispatch.rs:22`).

### Not an egress path: GeoLite2

Offline GeoLite2 enrichment is **local file reads, not network**. It is listed
here only to correct the common assumption that geo-enrichment implies a lookup
service. No request leaves the host for it. See
[../reference/integrations.md](../reference/integrations.md).

### What makes no outbound requests

The console, sensors, intake, feed, and core-scoring make no outbound requests
beyond the PostgreSQL connection - and, for the console only, the opt-in rDNS
query above.

## The forbidden-egress-target guard

The fetcher's URL vetter (`crates/review/src/fetcher/guard.rs`, `vet()` at line
144) is a load-bearing SSRF guard run on the initial URL and on every redirect
hop, failing closed at each step. Its `is_forbidden_egress_target` check (line
68) rejects own-host and reserved destinations before any connection:

- **Reserved / private / loopback IPs** via `core_scoring::is_reserved_ip`, plus
  `0.0.0.0/8`, CGNAT `100.64/10`, and `::` (lines 57-83).
- **IPv6 canonicalization first** - v4-mapped `::ffff:`, NAT64 `64:ff9b::/96`,
  6to4 `2002::/16`, Teredo/`2001::/32`, and deprecated v4-compat forms are folded
  or rejected (lines 14-55) so a mapped-loopback cannot slip past the base
  checker.
- **Scheme allowlist** http/https/tftp only, everything else `BadScheme`; tftp
  only on the initial fetch, never a redirect (lines 159-164).
- **`user:pass@host` rejected** outright (`Userinfo`, lines 152-157) - defeats
  naive host extraction.
- **DNS-rebinding defence** - if a host resolves to a mixed public+internal set,
  the whole host is rejected, not just the surviving public IP (lines 189-195).
- **Pinned connect** - the connection uses the vetted IP and never re-resolves
  the host (`Pinned`, doc line 94).
- **IP-literal hosts skip DNS** (decimal/octal/hex folded by the `url` crate) so
  a reserved literal is caught without a resolver call (lines 168-183).
- **tftp forced to port 69** - any explicit non-69 port is `TftpPortForbidden`
  (lines 206-210) so tftp cannot aim UDP at another service.
- **Empty resolve set fails closed** `ResolveFailed` (lines 185-187).

At the daemon boundary the fetcher refuses to run if `own_ips` is empty
(`crates/propolis/src/main.rs:828-835`) and warns if `own_ips` has no public
address (a NAT'd node, where self-targeting cannot be fully excluded;
`main.rs:843-852`).

The same forbidden-target concept also bounds where the platform will connect at
all: the guard rejects own-host and reserved targets rather than admitting them.
This is an accident-and-abuse-prevention control on the one attacker-directed
egress path, not a substitute for network-layer egress filtering, which remains
an operator responsibility (see
[../operations/networking-tls.md](../operations/networking-tls.md)).
