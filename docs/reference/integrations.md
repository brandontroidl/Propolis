<!--
title: External integrations reference
audience: all
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# External integrations reference

The platform's outbound integrations: VirusTotal, the abuse-reporting vendor
submitters (AbuseIPDB / DShield / OTX), the ops-alert ntfy POST, and offline
GeoLite2 enrichment.

> **Egress warning.** Sensors are egress-free by construction (each
> attacker-facing sensor crate has no HTTP client in its dependency tree,
> enforced by per-sensor tests). Every integration on this page except GeoLite2
> produces outbound network traffic, and **every one is opt-in and defaults
> OFF.** GeoLite2 is local file reads, not network. See
> [../security/outbound-controls.md](../security/outbound-controls.md) for the
> complete set of gated egress paths and the forbidden-egress guard.

Env-var defaults and bounds are owned by
[environment-variables.md](environment-variables.md); rate/budget caps are owned
by [rate-limits-and-budgets.md](rate-limits-and-budgets.md). This page owns the
wire contracts and gating semantics.

## VirusTotal (file/hash scanning)

VirusTotal is a **file/hash scanner, not a reporting vendor** - it receives
sample hashes (and, only if explicitly enabled, sample bytes), never IP abuse
reports. Implemented in `crates/review/src/virustotal.rs`.

### Gating

Enabled iff `PROPOLIS_VT_ENABLED` is set AND `PROPOLIS_VT_KEY` is non-empty; an
empty key forces it off, fail-closed (`vt_enabled`/`vt_api_key` in
`load_config`, `crates/propolis/src/config.rs:612-613`).

| Setting | Value | Source |
|---|---|---|
| `PROPOLIS_VT_ENABLED` | default false | `config.rs:613` |
| `PROPOLIS_VT_UPLOAD` (upload unknown samples) | default false | `config.rs:614` |
| `PROPOLIS_VT_SCAN_INTERVAL_SECS` | default 300 | `config.rs:615` |
| Request delay | 15000 ms (hard-coded) | `crates/propolis/src/main.rs:922` |
| Daily cap | 450 (hard-coded) | `main.rs:923` |

### Endpoints

- **Lookup** - `GET /api/v3/files/{sha256}` with an `x-apikey` header. `404`
  means "not in VT's database" (returns `None`); a non-200 is an error.
  `detected = malicious + suspicious`;
  `total = malicious + suspicious + undetected + harmless`
  (`lookup_hash`, `virustotal.rs:301-345`).
- **Upload** (only if `PROPOLIS_VT_UPLOAD`) - `POST /api/v3/files` multipart;
  stores a pending row with `detected = -1, total = -1`
  (`NextStep::Upload` arm, `upload_sample`, `pending_result`, `virustotal.rs:223-258,290-299,347-386`).

The documented free-tier limit is 4 req/min, 500/day, verified live against the
VT v3 API 2026-08-19 (`virustotal.rs:5-6`). The daily cap is enforced by a
single `DailyBudget` owned across every scan cycle - a counter local to one
`scan_spool` call would reset each cycle and never enforce a per-day cap
(`DailyBudget`, `virustotal.rs:74-103`, `main.rs:936-940`). See
[rate-limits-and-budgets.md](rate-limits-and-budgets.md#virustotal-daily-cap).

`scan_spool` walks each spool dir, filters to 64-hex-char (SHA-256) filenames,
skips samples already analyzed, and consumes one budget unit per new sample; on
exhaustion it logs and returns early (`virustotal.rs:171-268`; filename filter
in `list_samples`, `crates/review/src/spool.rs:34-39`). Spool dirs scanned:
`/var/spool/propolis/{ssh,adb,ftp,telnet}` (`crates/review/src/spool.rs:78-83`)
plus the fetcher spool tagged `fetched`. Samples older than 30 days are checked hourly by the
`sample-retention` task, independent of whether VirusTotal is enabled
(`main.rs:958-980`).

## Vendor abuse submitters

Three adapters, all implementing `VendorAdapter`. The API key lives only on the
adapter struct and is never placed on a report, response, error, or log line
(`crates/review/src/vendor/mod.rs:60-70`). All three vendors are always
constructed; the gatekeeper's `Disabled` check is what holds a disabled vendor,
and a vendor enabled with an empty API key is forced disabled, fail-closed
(`crates/review/src/main.rs:150-156,261-299`).

### Wire contracts

| Vendor | Endpoint | Auth | Base |
|---|---|---|---|
| AbuseIPDB | `POST /api/v2/report` (form-encoded) | `Key` header | `https://api.abuseipdb.com` |
| DShield / SANS ISC | `POST /submitapi/` | `X-ISC-Authorization: ISC-HMAC-SHA256 ...` | `https://www.dshield.org` |
| OTX (AlienVault / LevelBlue) | `POST /api/v1/pulses/create` (JSON) | `X-OTX-API-Key` | `https://otx.alienvault.com` |

- **AbuseIPDB** (`vendor/abuseipdb.rs:21,57-84`) - a `429` is treated as
  SUCCESS ("duplicate report within per-IP cooldown", verified live).
  Categories are numeric strings (e.g. ssh -> `["22"]`).
- **DShield** (`vendor/dshield.rs`) - HMAC-SHA256 auth
  (`Credentials = base64(HMAC-SHA256(key = nonce+userid, msg = api_key))`).
  Log type `cowrie`; the `LogEntry` carries
  `{timestamp, source_ip, user, password, lastcommand, hassh, banner}` - every
  key present, because DShield silently drops a cowrie record missing any key.
  **`password` is ALWAYS empty**: the honeypot drops captured passwords by
  design (`dshield.rs:66-113,132-144`). The API key is supplied as
  `"userid:apikey"`, split on the first `:`; a missing user or key, or a
  response body starting `ERROR`, is a permanent error (`dshield.rs:10-12,121-159`).
  The DShield wire contract is flagged in-code as provisional - the live
  endpoint 403'd during implementation, and the `"user:key"` single-slot
  composition is a noted open decision `[inferred]` (`main.rs:220-236`).
- **OTX** (`OtxAdapter::submit`, `vendor/otx.rs:84-106`) - pulses are forced
  `public: true` (OTX rejects private). `name = "propolis: {ip} ({timestamp})"`,
  one indicator `{indicator: ip, type, description}` where `type` is `"IPv4"`
  or `"IPv6"` by the address family (`indicator_type`, `vendor/otx.rs:34-39`).

### Idempotency

The idempotency key is `"{source_ip}:{vendor}:{date}"` where `date` is the UTC
calendar day of the poll (`idempotency_key`, `submit.rs:328-333`). The runner
INSERTs a `success = false` row `ON CONFLICT (idempotency_key) DO NOTHING`
BEFORE the HTTP call, then UPDATEs that row with the outcome after
(`submit.rs:273-306`). The date scoping means a new UTC day permits
re-reporting. Only an ATTEMPTED
submission writes a `vendor_submission` row; a held (ip, vendor) pair writes
nothing (`submit.rs:14-19`).

Error classification (`vendor/mod.rs:243-269`): 2xx is success; a connection
failure (no response, `status:0`) or 5xx is `Transient` (retried next poll); any
other 4xx is `Permanent` (marked failed, not auto-retried).

### Gating (the gatekeeper)

Before any submission, `gatekeeper::check` runs an ordered, fail-closed sequence
that short-circuits on the first hold (`gatekeeper.rs:85-138`): **Reserved**
(reserved-range IP, first and not overridable) -> **Disabled** -> **Stale**
(last activity older than the 48 h freshness window) -> **Cooldown** ->
**RateLimit** -> **ScoreFloor** -> **CategoryFilter**. Exact values and the full
sequence are owned by
[rate-limits-and-budgets.md](rate-limits-and-budgets.md#vendor-submission-gatekeeper).

### What is never sent

The `VendorReport` carries only
`{source_ip, categories, comment, evidence_window}`
(`vendor/mod.rs:29-35`). **No WAN / vantage IP, no raw score, no confidence, and
no per-vantage breakdown is ever placed in a report.** The multi-WAN vantage
data feeds only the internal breadth multiplier (see
[scoring-and-feed.md](scoring-and-feed.md#breadth-multiplier)) and never leaves
the system. `[inferred from absence]`: none of the three adapter payload structs
(`ReportPayload`, `LogEntry`, `PulsePayload`/`Indicator`) has any field that
could carry a WAN vantage address - confirmed by reading all three
(`vendor/mod.rs:297`).

The report comment is
`"propolis: {ip} - {N} event(s) across {M} categor{y/ies} since {first_seen}, current score {raw.round_dp(1)}"`,
and `evidence_window = (first_seen, last_seen)` (`build_report`, `submit.rs:407-422`).

## Ops-alert ntfy

Operational alerting posts to an ntfy topic. It is gated by
`PROPOLIS_OPS_ENABLED` (default off) and is one of the platform's five
operator-gated egress paths. Full trigger and payload detail live under
[../operations/health-and-observability.md](../operations/health-and-observability.md);
the gated-egress inventory is owned by
[../security/outbound-controls.md](../security/outbound-controls.md).

## GeoLite2 offline enrichment

GeoLite2 enrichment (including the GeoLite2-ASN reads that back
[ASN suppression](scoring-and-feed.md#exclusions-and-asn-suppression)) is
**local file reads, not network egress.** The ASN allowlist loads the ASN DB via
`GeoIp::load_asn_only`; an empty allowlist short-circuits before any lookup
(`crates/propolis/src/main.rs:845,852,867`,
`crates/feed/src/exclusion.rs:53-61`). No MaxMind or other host is contacted at
runtime; keeping the database current is an operator file-management task.

## See also

- [reference/scoring-and-feed.md](scoring-and-feed.md) - how recommendations and tiers gate what reaches these integrations
- [reference/rate-limits-and-budgets.md](rate-limits-and-budgets.md) - every cap and budget with exact values
- [security/outbound-controls.md](../security/outbound-controls.md) - the five gated egress paths and the forbidden-egress guard
- [troubleshooting/integrations-and-feed.md](../troubleshooting/integrations-and-feed.md) - VirusTotal, vendor, and feed troubleshooting
