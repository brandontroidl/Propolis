<!--
title: Troubleshooting - integrations and feed
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
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
`PROPOLIS_VT_KEY` is non-empty (`crates/propolis/src/config.rs#load_config`). Either
missing → VT stays off with no error. Checklist:

1. Both the enable flag and a non-empty key are set.
2. VT is a unified-daemon feature; the standalone `review` binary does not read
   VT vars.

### VT stops partway through the day

The scanner enforces a per-UTC-day budget. In the unified daemon this is
hardcoded `daily_limit = 450` with a `request_delay_ms = 15000` pacing delay
(`crates/propolis/src/main.rs#main`). When the day's budget is exhausted the
scanner logs and returns early, resuming after the UTC date rolls over
(`scan_spool`, `crates/review/src/virustotal.rs#scan_spool`). This is the intended cap, not a fault - the free-tier VT limit is 4 req/min, 500/day. The one `DailyBudget` is owned
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
(`load_vendor_config`, `crates/propolis/src/config.rs#load_vendor_config`). If nothing is being reported, walk the
gatekeeper's ordered checks - it short-circuits on the first hold
(`check`, `crates/review/src/gatekeeper.rs#check`,
`crates/review/src/gatekeeper.rs#check_with`).

You do not have to guess which check holds: each submission pass logs one INFO line,
`review: submission pass complete`, whose `held` count is split in `held_by` by reason
(`reserved`, `disabled`, `stale`, `cooldown`, `rate_limit`, `score_floor`,
`category_filter`, `db_error`, plus `allowlisted` for an address on the operator
allowlist, `delisted` for one on the operator delist (`PROPOLIS_FEED_DELIST`) or carrying the
console's delist latch, and `no_vendor_config` for an adapter with no gate configuration;
`crates/review/src/submit.rs#HeldBreakdown`). `delisted` is printed after `allowlisted`. At
startup a vendor that is off logs one warning naming the variable to set, and a second
warning if no vendor is enabled at all. The per-address, per-vendor reason stays at
debug level.

| Order | Hold reason | Meaning |
|---|---|---|
| 1 | `Reserved` | target IP is in a reserved/private range - never reportable |
| 2 | `Delisted` | the address carries the delist latch - reported to no one until relisted |
| 3 | `Disabled` | vendor not enabled (or empty key forced it off) |
| 4 | `Stale` | the address has not earned a tier within the 48h freshness window, or ever (measured on the last time it earned a tier, not on `last_seen`) |
| 5 | `Cooldown` | a prior successful report to this vendor for this IP within `cooldown_hours` (default 24) |
| 6 | `Stale` | the cooldown is over but the address has not earned a tier after the earned time the last report this vendor accepted was sent for |
| 7 | `RateLimit` | vendor-wide successful reports within `rate_window_hours` reached `rate_limit` (default 100/1h) |
| 8 | `ScoreFloor` | below `score_floor` (default none) |
| 9 | `CategoryFilter` | category filter set and no match (default none) |
| - | `DbError` | a DB read failed - fail-closed, held |

A vendor is only reached for an IP approved in the review queue, which offers only an
address that is eligible (confirmed-real) and has earned a tier, and the gate then holds it
as `Stale` unless it earned a tier within the last 48 hours and after the earned time this
vendor's last successful report covered. So activity that stops produces one report per
vendor, activity that goes on after a report produces one more when the cooldown ends (while
the pass counts it under `cooldown`, then under `stale` until it earns a tier again), and an
approved address that has been named since only by datagrams, or by weak connections that
left it below its tier, is not reported again. A bare volume-flood IP can be blocklisted
locally, once approved as a volume candidate, but is never reported upstream: the
submission runner reads the review queue only. A `stale` count that keeps growing for
approved addresses is this rule working, not a fault. Thresholds and defaults:
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
  (`crates/propolis/src/main.rs#main`). Set `PROPOLIS_FETCH_OWN_IPS` to the
  box's public egress IP.
- If the resolved own-IPs contain only private/loopback/link-local addresses (a
  NAT'd node whose public IP is on no interface), it **warns but runs**
  (`own_ips_lack_a_public_address`, `crates/propolis/src/main.rs#own_ips_lack_a_public_address`) - set the public IP explicitly so the SSRF guard can
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
- **No eligible entries** - tier files require operator-approved IPs that earned that
  tier within its TTL (24 h aggressive, 48 h standard); retention-window files hold
  approved IPs that earned a tier within the window, and also volume-flood entries an
  operator approved on the queue page's volume tab whose last completed TCP connection is
  within the window. An approved address named since only by datagrams drops out when its
  TTL runs out. A flooding address missing from `all-*`
  is usually a pending volume candidate (`propolis_volume_review_pending` on
  `/metrics`), or the review subsystem is off (`PROPOLIS_REVIEW_ENABLED=false`), in
  which case no candidate is ever offered. An empty
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

- Confirm the cron entry exists, runs as `propolis-blocklist` (`crontab -u
  propolis-blocklist -l`), and that its key can push. The classic failure is cron
  lacking the push credential; the script always attempts `git push origin HEAD`
  (to ship any previously-stranded commit) and exits non-zero with a diagnostic if
  the push fails. Moved from root? The checkout must be owned by the account, or
  git refuses it as dubious ownership.
- The script is fail-closed: it aborts if the source has no `manifest.json`, the
  target is not a git checkout, or the feed directory holds anything the
  publisher does not write (an unexpected name, a missing format, a link, a FIFO,
  a file over 32 MiB, or a file whose contents are not, line for line, what the
  publisher writes for that format). Each refusal names the file and ends
  "refusing to push"; one that names a link, an unexpected file or a line that "is
  not what the publisher writes" means something other than the publisher wrote
  there, so investigate the daemon before clearing it. The exception is a `.hosts`
  file right after an upgrade, which the old daemon wrote:
  `blocklist-sync: unexpected entry aggressive.hosts in <feed dir> - refusing to push`
  happens once if the sync runs between `upgrade.sh` installing the new script and
  the upgraded daemon's first build, and clears by itself at that build. The reverse,
  `blocklist-sync: <feed>.hosts missing from <feed dir> - malformed feed output -
  refusing to push` (the feed it names varies), means the installed script is older
  than the daemon: re-run the upgrade so both are replaced. Run
  `deploy/blocklist-sync.sh --check` to repeat the checks without pushing.
- `feed-push-stale` firing while pushes succeed: the log says "could not update
  push marker". `/var/lib/propolis/blocklist-status` must exist (re-run
  `deploy/provision.sh`), be owned by `propolis-blocklist` (a root cron drops to
  that owner for the write, which needs `setpriv`), and be writable by no one
  else. Do not chown it to root: `deploy/provision.sh` resets it on every upgrade.
- `PROPOLIS_FEED_WINDOWS` labels the script refuses: it accepts `all-<n>h|d` with
  `n` of one to five digits and no leading zero, and at most 16 windows. The
  daemon accepts more (`024h`, `+24h`, a count of 100000 or more, any number of
  windows) and builds them, but the sync then refuses the whole build, so
  `feed-push-stale` is the only signal. Keep the setting within those limits.
- "Permission denied" running the script as `propolis-blocklist`: the script, its
  sibling `blocklist-README.md` and every directory above them must be readable
  and traversable by that account. Use the root-owned copy under
  `/usr/local/lib/propolis/` that `deploy/install.sh` and `deploy/upgrade.sh` install.

## Ops alerts never fire, or the daemon won't start with ops enabled

Ops self-alerting is opt-in (`PROPOLIS_OPS_ENABLED=false` by default). Setting
`PROPOLIS_OPS_NTFY_URL` and `PROPOLIS_OPS_NTFY_TOPIC` is optional even once
enabled - with neither set, alerts go to a local log sink instead of ntfy, and
the daemon says so at startup. It is still fail-closed on a **half-configured**
target: enabled with a URL but no topic (or vice versa) aborts startup, because
a mistake there must not silently downgrade to the log sink
(`parse_ops_alert`, `crates/propolis/src/ops_alert/config.rs#parse_ops_alert`). So:

- Daemon won't start after enabling ops - you set `PROPOLIS_OPS_ENABLED=true` and
  set only one of the ntfy URL or topic. Set both (and optionally
  `PROPOLIS_OPS_NTFY_TOKEN` for a protected topic), or leave both unset to use
  the local log sink.
- Alerts never fire → confirm ops is actually enabled, the ntfy endpoint is
  reachable, and the degradation thresholds (capacity, feed staleness, vendor
  failure rate, backlog, chain verify) are configured as intended. This ntfy POST
  is a gated egress path.

The ops monitor is distinct from the host-compromise Guardian; use a separate
ntfy topic for each.
