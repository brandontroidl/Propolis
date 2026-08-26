<!--
title: Security reviewer manual
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Security reviewer manual

A curated path through the security corpus for someone evaluating Propolis' security
posture. It orders the canonical pages and links to them; each linked page owns its
facts. Read the [threat model](../security/threat-model.md) first - it frames
everything below.

Propolis is source-available and actively developed, one tagged release (`v0.1.0`),
current tree `0.3.0` untagged, not production-certified. Do not read any control below
as a certification. See [maturity and status](../overview/maturity-and-status.md).

## Threat model in one paragraph

The adversary is an **unauthenticated internet attacker** who controls every byte of
protocol input on a sensor connection, the source-address framing to the extent the
network allows, and content designed to attack downstream consumers of the evidence
(forged log lines, path-traversal filenames, SSRF-shaped fetch URLs, memory-exhaustion
inputs). Trusted: the single operator, PostgreSQL as a same-node backend, the host OS
and systemd controls. Distrusted unconditionally: all sensor input, attacker-supplied
URLs, and the source IP as any identity or authorization signal. Out of scope as
adversaries: a malicious operator, a compromised kernel, toolchain supply-chain
compromise. Full statement, with the asset-to-control table:
[threat model](../security/threat-model.md).

## The load-bearing invariants

### Never-execute

The honeypot captures what an attacker sends and **never runs it**. No source under
`crates/*/src/**` invokes any process-spawning facility; the capability is absent from
the dependency tree, not a runtime guard that could be misconfigured off. Reinforced by
per-sensor static-check regression tests, deployment-layer `MemoryDenyWriteExecute`, and
no-execute spool permissions. Owned by [never-execute](../security/never-execute.md).
Note the one coverage asymmetry: `sensor-catchall` has no per-crate
`never_exec_static_check` guard (its source is still clean by whole-workspace grep) -
carried as a residual item.

### Egress is scoped, not absent

The accurate framing: **sensors are egress-free by construction; the platform's few
enrichment/reporting egress paths are operator-gated and default off.** The workspace is
**not** egress-free as a whole - `Cargo.lock` contains `reqwest` and `hyper`, used by the
`review` crate and the malware fetcher. The five outbound paths - VirusTotal, vendor
abuse submitters (AbuseIPDB/DShield/OTX), console reverse DNS, the malware fetcher, and
ops-alert ntfy - are each opt-in and default off, and several fail closed if their
credential or topic is missing. GeoLite2 enrichment is **local file reads, not network**.
The full list, gating flags, and the fail-closed SSRF/forbidden-egress guard on the one
attacker-directed fetch are owned by [outbound controls](../security/outbound-controls.md).

## Attack surfaces

Every boundary where untrusted or externally reachable data enters or leaves, and the
control that contains each, is owned by [attack surfaces](../security/attack-surfaces.md).
The inbound and outbound surfaces:

- **Sensor listeners** (9 crates / 12 protocols, no compiled-in default port): never-execute,
  boundary `sanitize_value` on every attacker string, no HTTP client in the sensor closure,
  credential drop-at-parse. See [input handling](../security/input-handling.md) and
  [sample and credential privacy](../security/sample-and-credential-privacy.md).
- **Malware fetcher** (opt-in, default off): the SSRF vetter - scheme allowlist, userinfo
  rejection, DNS-rebinding defense, pinned-address connect, forbidden-target/reserved-IP
  checks with IPv6 canonicalization first - run on the initial URL and every redirect hop.
- **Console (HTTP)** (30 routes: 7 public, 23 session-gated; loopback bind by default):
  Argon2id auth, HMAC session cookie, per-session CSRF on the mutating routes, login rate
  limiting, `X-Frame-Options: DENY` + `nosniff` on every response. There is **no global
  CSP**; the only route that sets one is `/samples/download/{sha256}`. See
  [authn/authz](../security/authn-authz.md) and [console routes](../reference/console-routes.md).
- **Database**: parameterized SQL only - no query text built with string formatting in
  non-test source. See [input handling](../security/input-handling.md).
- **Quarantine spool**: SHA-256 naming (path traversal structurally impossible), `0640`,
  per-file cap + global byte budget, re-hash on read fail-closed. See
  [malware custody](../security/malware-custody.md).
- **Feed publish**: selects only attacker `source_ip` plus tier/first-seen/last-seen/
  categories; **zero** `wan_ip` (the honeypot's own ingress attribution) by construction.

## Evidence integrity

The `event` table is an append-only, hash-chained ledger. Each event's SHA-256 hash is
computed over a frozen, length-prefixed canonical encoding (not JSON) and chained to the
prior hash; a golden test vector pins the encoding. Two database-layer controls back it:
a `BEFORE INSERT` trigger that rejects any insert whose `prev_hash` does not match the
chain head (fail-closed), and, in the production database only, a `REVOKE UPDATE, DELETE,
TRUNCATE ON event` from the application role. Appends serialize against one advisory lock
so the chain cannot fork. What it guarantees is **tamper-evidence**, not confidentiality
or protection against a DB superuser deleting rows. Owned by
[storage](../architecture/storage.md) and [database reference](../reference/database.md).

## Hardening

The actionable pre-exposure sequence is owned by
[hardening checklist](../security/hardening-checklist.md): derive the real syscall filter,
enforce the noexec spool mounts, lock down network exposure and keep the console
loopback-only, terminate TLS in a reverse proxy, treat every egress path as opt-in,
provision secrets correctly, decide the feed-repo visibility deliberately, and verify DB
privileges and a tested backup. Filesystem/DB protection detail (W^X, `ProtectSystem=strict`,
capability caps, the DB privilege model) is owned by
[filesystem and DB protections](../security/filesystem-and-db-protections.md); the
dependency/vendoring surface by [supply chain](../security/supply-chain.md).

## Residual risks (read before trusting the posture)

Stated plainly and owned by [residual risks](../security/residual-risks.md):

- The systemd `SystemCallFilter` shipped is a broad **development placeholder**, not a
  tightened per-binary seccomp allowlist - treat the syscall sandbox as effectively absent
  until an operator derives it.
- **No in-process TLS** - the console is plain HTTP; any transport encryption is operator-provided.
- The `noexec,nosuid,nodev` spool mounts are printed as fstab guidance, not enforced from
  source - whether they are mounted on a given box is not verifiable from the code.
- **Single-node blast radius** - no built-in redundancy, failover, or off-host replication.
- Enabled egress paths are real egress (the fetcher deliberately dials attacker-supplied hosts).
- **Honeypot-detection tells** - no emulation is indistinguishable to a determined adversary;
  IP rotation is the practical recovery lever.
- `/health`, `/ready`, `/metrics` are unauthenticated - safe only because the console
  defaults to loopback.

## Disclosure

Report privately per the [vulnerability disclosure policy](../security/vulnerability-disclosure.md)
(acknowledgment within 72 hours; fixes committed and tagged before public disclosure). For
reading and preserving captured evidence during an incident, see the
[incident-response manual](./incident-response.md).
