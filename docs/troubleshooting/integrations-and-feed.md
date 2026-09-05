<!--
title: Troubleshooting - integrations and feed
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Integrations and feed

Covers the platform's operator-gated outbound paths (VirusTotal, vendor abuse
submitters, the malware fetcher, ops alerts) and blocklist feed generation.

> **Egress note.** Sensors are egress-free by construction. The platform's few
> enrichment/reporting egress paths are **operator-gated and default off**:
> VirusTotal, the vendor submitters (AbuseIPDB/DShield/OTX), console
> forward-confirmed rDNS, and the ops-alert ntfy POST. GeoLite2 enrichment is
> local file reads, not network. Enabling any of these sends data off the box - > review [Outbound controls](../security/outbound-controls.md) first. Wire
> contracts and keys are owned by [Integrations](../reference/integrations.md).

## VirusTotal not scanning

VT is doubly gated: it runs only when `PROPOLIS_VT_ENABLED=true` **and**
`PROPOLIS_VT_KEY` is non-empty (`crates/propolis/src/config.rs:520-521`). Either
missing → VT stays off with no error. Checklist:

1. Both the enable flag and a non-empty key are set.
2. VT is a unified-daemon feature; the standalone `review` binary does not read
   VT vars.

### VT stops partway through the day

The scanner enforces a per-UTC-day budget. In the unified daemon this is
hardcoded `daily_limit = 450` with a `request_delay_ms = 15000` pacing delay
(`crates/propolis/src/main.rs:751-752`). When the day's budget is exhausted the
scanner logs and returns early, resuming after the UTC date rolls over
(`crates/review/src/virustotal.rs:28-58`). This is the intended cap, not a fault - the free-tier VT limit is 4 req/min, 500/day. The one `DailyBudget` is owned
across all scan cycles so the cap actually holds; a per-cycle counter would reset
and never enforce it.

### VT lookups error

`lookup_hash` treats a 404 as "not in VT's DB" (returns none); any non-200 is an
error. A wrong or revoked key surfaces as auth errors in the log. Uploads happen
only when `PROPOLIS_VT_UPLOAD=true`, and upload sends the sample file off the box.

> **Warning - egress.** `PROPOLIS_VT_UPLOAD=true` transmits captured, possibly
> live malware samples to VirusTotal (a third party). Keep it off unless you
> intend that disclosure.

## Vendor submissions never sent / everything held

Three adapters exist (AbuseIPDB, DShield, OTX) and are always constructed; a
disabled vendor is held by the gatekeeper, not skipped at construction. A vendor
`_ENABLED=true` with an empty `_KEY` is force-disabled fail-closed with a warning
(`crates/propolis/src/config.rs:399-405`). If nothing is being reported, walk the
gatekeeper's ordered checks - it short-circuits on the first hold
(`crates/review/src/vendor/gatekeeper.rs:85-138`):

| Order | Hold reason | Meaning |
|---|---|---|
| 1 | `Reserved` | target IP is in a reserved/private range - never reportable |
| 2 | `Disabled` | vendor not enabled (or empty key forced it off) |
| 3 | `Stale` | last-seen older than the 48h freshness window |
| 4 | `Cooldown` | a prior successful report to this vendor for this IP within `cooldown_hours` (default 24) |
| 5 | `RateLimit` | vendor-wide successful reports within `rate_window_hours` reached `rate_limit` (default 100/1h) |
| 6 | `ScoreFloor` | below `score_floor` (default none) |
| 7 | `CategoryFilter` | category filter set and no match (default none) |
| - | `DbError` | a DB read failed - fail-closed, held |

A vendor is also only reached for IPs that are `recommended_for_vendor` (eligible
and tiered) - a bare volume-flood IP is blocklisted locally but never reported
upstream. Thresholds and defaults:
[Rate limits and budgets](../reference/rate-limits-and-budgets.md) and
[Scoring and feed](../reference/scoring-and-feed.md).

Notes on specific vendors:

- **AbuseIPDB** - a `429` is treated as **success** (duplicate within the vendor's
  own per-IP cooldown), not a failure.
- **DShield** - the key is `PROPOLIS_VENDOR_DSHIELD_USER` + `_KEY` composed as
  `user:key`; user alone (no key) is ignored, and the vendor stays disabled. The
  DShield wire contract is flagged provisional in code.
- Connection failure or 5xx is transient (retried next poll); other 4xx is
  permanent (marked failed, not auto-retried).

## Malware fetcher does nothing

The fetcher is off by default (`PROPOLIS_FETCH_ENABLED=false`) and, even when
enabled, is **fail-closed on self-target protection**:

- If `PROPOLIS_FETCH_OWN_IPS` is unset **and** interface enumeration returns
  empty, the fetcher refuses to run and logs an error
  (`crates/propolis/src/main.rs:828-835`). Set `PROPOLIS_FETCH_OWN_IPS` to the
  box's public egress IP.
- If the resolved own-IPs contain only private/loopback/link-local addresses (a
  NAT'd node whose public IP is on no interface), it **warns but runs**
  (`main.rs:843-852`) - set the public IP explicitly so the SSRF guard can
  protect it.
- Fetches are bounded (per-host/hour, daily cap, byte cap, hop/depth caps, spool
  budget) and target-vetted by the SSRF guard, which rejects reserved/own-host
  targets. A URL that is all being rejected as `Rejected`/`skipped_bucket` in the
  log means a guard or budget is doing its job, not a bug. Bounds:
  [Rate limits and budgets](../reference/rate-limits-and-budgets.md).

> **Warning - egress + live malware.** The fetcher makes outbound requests to
> attacker-supplied URLs and stores live malware under
> `/var/spool/propolis/fetched`. Only enable it with the SSRF self-target guard
> correctly configured, and handle the spool per
> [Malware custody](../security/malware-custody.md).

## Feed directory empty / no output

In-process feed publishing runs when `PROPOLIS_FEED_ENABLED=true` (default), on
`PROPOLIS_FEED_BUILD_INTERVAL_SECS` (default 900s), writing atomically to
`PROPOLIS_FEED_OUTPUT_DIR` (default `/var/lib/propolis/feed/current`). If output
is missing:

- **Feed disabled** - `PROPOLIS_FEED_ENABLED=false` stops the builder.
- **Output dir suffix** - the atomic swap needs the trailing `/current` (staging
  and previous siblings live inside the writable parent). A dir without it can
  break the swap; keep the default shape.
- **No eligible entries** - tier files require operator-approved, eligible,
  tiered IPs; retention-window files also include volume-flood entries. An empty
  feed still publishes normally (a zero-entry tier renders), so an empty
  `manifest.json` with the daemon healthy means "nothing qualifies yet", not a
  failure.
- **A failed publish leaves the previous feed in place** - the publisher aborts
  before touching `output_dir` on any error (including an exclusion violation or
  a staged-file checksum mismatch), so a stale-but-intact feed after an error is
  expected.

Membership rules, tiers, TTLs, and export formats:
[Scoring and feed](../reference/scoring-and-feed.md).

## Public blocklist repo not updating

Publishing the feed to the public git repo is a **separate operator setup step**,
not a shipped systemd timer or cron. `deploy/blocklist-sync.sh` is meant to be run
from cron on the honeypot node after each atomic feed swap; the crontab entry
itself is an operator action referenced only by comment - nothing in `deploy/`
wires it up. With the ops monitor enabled, the `feed-push-stale` condition pages
when the local feed has moved on from the script's last successful push by more
than `PROPOLIS_OPS_FEED_STALE_MULTIPLE` build cycles. A box that has never pushed
is paged only with `PROPOLIS_OPS_FEED_PUSH_EXPECTED=true`, and then only once the
stale threshold has elapsed since the daemon started; set it once the cron is
installed, so a push that has never succeeded is reported rather than read as
"syncing is optional". If the public repo is stale:

- Confirm the cron entry exists and runs as a user whose SSH agent/key can push.
  The classic failure is cron lacking the push credential; the script always
  attempts `git push origin HEAD` (to ship any previously-stranded commit) and
  exits non-zero with a diagnostic if the push fails.
- The script is fail-closed: it aborts if the source has no `manifest.json`, is
  not a git checkout, or has no tier files. Read its output for which guard
  fired.

## Ops alerts never fire, or the daemon won't start with ops enabled

Ops self-alerting is opt-in (`PROPOLIS_OPS_ENABLED=false` by default). When you
enable it, `PROPOLIS_OPS_NTFY_URL` and `PROPOLIS_OPS_NTFY_TOPIC` become
**required** - enabled-but-missing aborts startup, fail-closed, because a monitor
that cannot page must not run silently
(`crates/propolis/src/ops_alert/config.rs:122-134`). So:

- Daemon won't start after enabling ops → you set `PROPOLIS_OPS_ENABLED=true` but
  left the ntfy URL or topic empty. Set both (and optionally
  `PROPOLIS_OPS_NTFY_TOKEN` for a protected topic).
- Alerts never fire → confirm ops is actually enabled, the ntfy endpoint is
  reachable, and the degradation thresholds (capacity, feed staleness, vendor
  failure rate, backlog, chain verify) are configured as intended. This ntfy POST
  is a gated egress path.

The ops monitor is distinct from the host-compromise Guardian; use a separate
ntfy topic for each.
