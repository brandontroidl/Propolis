<!--
title: Outbound controls
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-01
-->

# Outbound controls

This page lists every way Propolis sends anything off the host: the sensors (which
send nothing), the daemon's five optional integrations, and the two connections a
deployment can add outside the daemon.

Do not describe the system as making no outbound requests. The workspace as a whole
is not egress-free: `reqwest` and `hyper` are in `Cargo.lock`, used by the `review`
crate for vendor reporting and by the malware fetcher. The accurate statement has two
parts: attacker-facing sensors carry no HTTP client in their dependency closure, and
every daemon-level outbound path is opt-in and defaults off.

## Sensors carry no HTTP client

No sensor crate names an HTTP client crate in its manifest. Two tests hold that:
`sensor_ssh_has_no_http_client_dependency` in `crates/sensor-ssh/tests/shell_test.rs`
checks that crate's own manifest, and `no_sensor_crate_depends_on_an_http_client` in
`crates/sensor-framework/tests/deploy_test.rs` walks every `crates/sensor-*/Cargo.toml`
in the workspace against the same banned list (`reqwest, hyper, ureq, curl, isahc,
surf, attohttpc`), so a sensor added later is covered without anyone remembering to
copy the test. The `review` crate is not a sensor and is not walked. Each sensor's
integration tests also assert that a fake shell's `wget` or `curl` opens no
connection, and the never-execute guard is described in [never-execute.md](never-execute.md).

## The five daemon integrations

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
(`crates/propolis/src/ops_alert/dispatch.rs`). Gated `enabled`, default false.

**Enabling alerting does not by itself create an egress path.** With
`PROPOLIS_OPS_ENABLED=true` and no ntfy target configured, alerts are delivered
to a local sink that logs them at ERROR level (`dispatch.rs`'s `LogPoster`) and
**nothing leaves the host**. Requiring an external service was previously the
condition of alerting at all, which meant a node without one ran with no
self-monitoring; the local sink removes that trade.

A **half**-configured target still fails closed: a url without a topic (or the
reverse) aborts startup, because that is an operator mistake rather than a
choice of sink, and silently downgrading it would page nothing while looking
configured (`crates/propolis/src/ops_alert/config.rs`). Egress happens only when
both `ntfy_url` and `ntfy_topic` are set. Alert body text is sanitized before
send (`dispatch.rs:4`); each attempt carries a 30s timeout backstop
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

## Two connections outside the daemon

Neither of these is an integration with a third party, and neither runs inside the
`propolis` daemon, but both send data off the host and both are yours to set up.

### 6. Collector to gateway (split deployment only)

In the collector/control-plane split, the `shipper` service on a collector opens an
mTLS connection to your own `gateway` service on the control plane and streams the
sensor event logs to it (`PROPOLIS_SHIPPER_GATEWAY_ADDR`, with the CA and client
certificate paths beside it). It connects only to the address you configure, with
the certificate you provisioned, and it does not exist in a single-node install.
The variables are in the
[environment reference](../reference/environment-variables.md); the provisioning and
enrollment procedure is documented in `deploy/collector.env.example` and
`deploy/control-plane.env.example`, and the wire contract in
[evidence provenance and artifact custody](../architecture/evidence-provenance-and-artifact-custody.md).

### 7. Feed publication (operator cron)

`deploy/blocklist-sync.sh` copies the built feed into a git checkout and pushes it to
the remote you configured, using the deploy key you name. Nothing in the daemon or
the shipped units schedules it; it runs when your cron runs it. Publishing exposes
the listed IP addresses and, through the repository, that you operate a honeypot.
The push is monitored by the `feed-push-stale` condition once configured; see
[routine procedures](../operations/routine-procedures.md).

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
