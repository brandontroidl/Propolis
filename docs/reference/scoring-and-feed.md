<!--
title: Scoring and feed reference
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Scoring and feed reference

Canonical owner of every scoring constant, tier threshold, eligibility rule,
recommendation gate, retention window, and exclusion rule. Other pages link
here rather than restating these values.

All constants below are fixed in source (not runtime-configurable) unless the
row explicitly names an environment variable. Env-var defaults and bounds are
owned by [environment-variables.md](environment-variables.md); this page owns
the scoring/feed semantics they feed. Signal weights and event fields are owned
by [events-and-signals.md](events-and-signals.md).

## Score model

A source IP's score is a decaying, capped accumulation of signal weights.
`apply_event` is a pure fold: it decays prior state to the new event's
`observed_at`, adds the event's weight (unless deduped), and recomputes all
derived flags (`crates/core-scoring/src/scoring/engine.rs:56-173`).

### Constants (`crates/core-scoring/src/scoring/constants.rs`)

| Constant | Value | Meaning |
|---|---|---|
| `HALF_LIFE_SECONDS` | 21600 (6 h) | Decay half-life for raw score and per-category weight (`constants.rs:5`) |
| `DEDUP_WINDOW_SECONDS` | 60 | A repeat `(source_ip, signal_type)` within 60 s records the event but adds no weight (`constants.rs:10`) |
| `SCORE_CAP` | 100 | Clamp ceiling for raw and effective score (`constants.rs:13`) |
| `BREADTH_PER_WAN` | 0.15 | Breadth-factor increment per extra distinct WAN vantage (`constants.rs:16`) |
| `BREADTH_CAP` | 0.60 | Max breadth bonus; factor saturates at 1.60 (`constants.rs:19`) |
| `BLOCKLIST_FLOOR` | 50 | Minimum effective score for blocklist recommendation (`constants.rs:22`) |
| `PERSIST_PER_DAY` | 0.55 | Persistence bonus points per active day beyond grace (`constants.rs:34`) |
| `PERSIST_GRACE_DAYS` | 2 | Active days that earn no persistence bonus (`constants.rs:38`) |
| `PERSIST_CAP` | 60 | Max persistence bonus in points (`constants.rs:41`) |
| `VOLUME_LIST_THRESHOLD` | 1000 | Cumulative established `event_count` for volume-blocklisting (`constants.rs:51`) |
| `VOLUME_LIST_WINDOW_SECONDS` | 86400 (24 h) | Recency gate for volume-blocklisting (`constants.rs:52`) |
| `LIVE_FLOOR` | 0.5 | A category contributes to `distinct_categories` / `max_confidence` only while its decayed weight is strictly `> 0.5` (`engine.rs:45`) |

### Decay

`factor = 0.5 ^ (elapsed_seconds / HALF_LIFE_SECONDS)`. Non-positive elapsed
returns the prior state unchanged (clock-skew clamp; decay only shrinks)
(`crates/core-scoring/src/scoring/decay.rs:13-20`). On add,
`new_raw = min(SCORE_CAP, decayed_raw + weight)` (`engine.rs:141`).
`max_confidence` per category is a running MAX and does not decay
(`engine.rs:133-140`).

### Breadth multiplier

```
breadth_factor(n) = 1 + min(0.60, 0.15 * max(0, n - 1))
effective_score(raw, n) = min(SCORE_CAP, raw * breadth_factor(n))
```

`breadth_factor(0) = breadth_factor(1) = 1.00`; it saturates at 1.60 for
`n >= 5` (`crates/core-scoring/src/scoring/breadth.rs:66-95`).

The distinct WAN count is hardened: only vantages with
`saw_authenticated_tcp == true` are counted, and vantages dedup by /24 (IPv4) or
/64 (IPv6) prefix before counting - a spoofed source cannot complete an
authenticated TCP handshake, and same-prefix vantages are treated as one
operator block (`breadth.rs:9-57`). ASN-based dedup is a documented deferred
extension, not shipped `[planned]` (`breadth.rs:24-28`). The engine does not
recompute breadth; `distinct_wan_count` is supplied by the repository and
threaded through verbatim (`engine.rs:52-55,164-165`).

The WAN vantage data feeds only this internal multiplier. It is never placed in
any vendor report - see [integrations.md](integrations.md#what-is-never-sent).

### Persistence bonus

```
persistence_points(active_days) = min(PERSIST_CAP, PERSIST_PER_DAY * max(0, active_days - PERSIST_GRACE_DAYS))
```

`active_days` is an unbounded, non-decaying count of distinct UTC calendar days
seen (`engine.rs:116-127`). The bonus is 0 up to and including 2 days, then
linear at 0.55/day, saturating at 60 points
(`crates/core-scoring/src/scoring/persistence.rs:21-24`).

The bonus is applied only to a gate-facing score, never the stored raw:
`gated_raw = min(SCORE_CAP, raw_score + persistence_points(active_days))`
(`engine.rs:217-220`). The stored `raw_score` stays the decayed accumulation so
the next decay cannot double-count the bonus. Confidence and eligibility gates
still apply, so a persistent low-confidence scanner is lifted but never promoted
(`engine.rs:214-216`).

Calibration documented in code: a once-a-day command-exec source (base ~60)
reaches STANDARD (75) at ~30 active days and AGGRESSIVE (90) at ~60
(`constants.rs:31-33`).

## Tier

`tier(raw_score, max_confidence)` (`crates/core-scoring/src/scoring/tier.rs:9-19`),
evaluated aggressive-first with inclusive (`>=`) floors:

| Tier | Requires |
|---|---|
| Aggressive | `raw_score >= 90` AND `max_confidence >= 0.95` |
| Standard | `raw_score >= 75` AND `max_confidence >= 0.70` |
| (none) | otherwise |

The `FeedTier` enum has only `Aggressive` and `Standard` (`enums.rs:48-51`).

Tier runs on the **gated raw** (base + persistence), NOT the breadth-multiplied
effective score: `tier(gated_raw, max_confidence)` (`engine.rs:222`).
`max_confidence` is live-decayed - only categories whose decayed weight is
`> LIVE_FLOOR (0.5)` contribute; an empty breakdown yields 0, fail-closed
(`engine.rs:196-204`).

## Eligibility latch

```
eligible(has_confirmed_real, event_count, _distinct_categories, delisted)
    = !delisted && has_confirmed_real && event_count >= 2
```

(`crates/core-scoring/src/scoring/eligibility.rs:1-8`). The
`distinct_categories` argument is ignored (leading underscore): the older
two-category gate was dropped 2026-08-19 (migration `0006_relax_eligibility.sql`).
Eligibility takes no score input, so a decayed score can never revoke it; it is
sticky until an explicit delist.

### Confirmed-real gate

`is_confirmed_real(protocol, authenticated, category) = (protocol == Tcp) && authenticated && (category == Honeypot)`
(`crates/core-scoring/src/domain/enums.rs:115-117`). The latch is sticky:
`has_confirmed_real = prev || is_confirmed_real(...)` - once set, never unset
(`engine.rs:145-146`). UDP/ICMP and unauthenticated or non-honeypot traffic
never latch it.

## Recommendation gates

Derived in `derive_projection`, the single source of truth shared by
`apply_event` (write) and `project_to_now` (read) (`engine.rs:175-300`).

| Gate | Rule | Source |
|---|---|---|
| `recommended_for_vendor` | `eligible && tier.is_some()` | `tier.rs:21-23` |
| `recommended_for_blocklist` | `eligible && effective_score >= 50` **OR** the volume path below | `tier.rs:25-27`, `engine.rs:231-236` |
| `recommended_by_volume` | `!delisted && established_event_count >= 1000 && seconds_since_last_seen <= 86400` | `tier.rs:34-42` |

The volume path is independent of confirmed-real and score. It counts ONLY
`established_event_count` (completed-TCP events: `prev + (protocol == Tcp)`,
`engine.rs:152-153`), so a spoofed UDP/ICMP flood cannot volume-list an innocent
third party. Vendor reporting always gates on `recommended_for_vendor`
(confirmed-real), so a bare flood is blocked locally but never reported upstream
(`engine.rs:223-229`).

## Feed membership and retention

Owned by the feed builder (`crates/feed/src/builder.rs`). Membership is decided
by RETENTION windows, not a live-decayed score. All fields are read as stored (as
of the IP's last event), so a tier cannot slide between builds
(`builder.rs:110-153`).

### Candidate sources

- **Tier candidates** (aggressive / standard files) require operator approval:
  `s.recommended_for_blocklist = true AND s.eligible = true AND q.state = 'approved' AND s.tier IS NOT NULL`
  (`builder.rs:168-179`). See the [review queue](../architecture/pipeline.md).
- **Volume candidates** are auto-published (no approval):
  `s.recommended_for_blocklist = true AND s.eligible = false` (tier = none). They
  land ONLY in retention windows, never the tier files
  (`builder.rs:219-234,263-268`).

### TTLs and windows

| Setting | Default | Env var | Source |
|---|---|---|---|
| Aggressive tier TTL | 24 h | `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` | `config.rs:23,489-496` |
| Standard tier TTL | 48 h | `PROPOLIS_FEED_STANDARD_TTL_HOURS` | `config.rs:24` |
| Retention windows | `24h,7d,30d,60d,90d` | `PROPOLIS_FEED_WINDOWS` | `config.rs:29,505` |
| Build interval | 15 min (900 s) | `PROPOLIS_FEED_BUILD_INTERVAL_SECS` | `config.rs:22` |
| Feed enabled | true | `PROPOLIS_FEED_ENABLED` | `config.rs:476` |
| Output dir | `/var/lib/propolis/feed/current` | (config) | `config.rs:21` |

Retention windows ignore tier and hold every approved entry (and volume floods)
whose `last_seen` is inside the window, published as `all-{label}.*` and nested
by construction (`builder.rs:92-96,269-277`). A candidate is kept iff
`now - last_seen < ttl`; each entry's `valid_from = coarsen_to_hour(last_seen)`
and `valid_until = valid_from + ttl` (`builder.rs:302-328`). Every exported
timestamp is coarsened to the hour boundary (anti-deanonymization)
(`builder.rs:330-340`).

Full default/bound detail for these env vars is owned by
[environment-variables.md](environment-variables.md).

## Exclusions and ASN suppression

`ExclusionEngine.is_excluded(ip)` (`crates/feed/src/exclusion.rs:66-71`):

```
is_reserved(ip) || allowlist_cidr_contains(ip) || delist_contains(ip) || asn_allowlisted(ip)
```

- `is_reserved` delegates to the shared reserved-range guard (below).
- Allowlist / delist / ASN allowlist are operator-supplied via
  `PROPOLIS_FEED_ALLOWLIST` (CIDR), `PROPOLIS_FEED_DELIST` (IPs), and
  `PROPOLIS_FEED_ASN_ALLOWLIST` (AS numbers) - all empty by default
  (`crates/propolis/src/config.rs:497-505`).
- **ASN suppression** is opt-in with an empty default; it suppresses
  trusted-org infrastructure (e.g. Microsoft AS8075, Google AS15169) keyed off
  offline GeoLite2-ASN reads (see [integrations.md](integrations.md#geolite2-offline-enrichment)).
  ASN ownership is RIR-registered, not per-IP spoofable. An empty allowlist
  short-circuits before any DB lookup; a non-empty allowlist with no ASN DB
  loaded means suppression is configured but INERT
  (`exclusion.rs:8-11,53-61,76-81,104-109`).

The publisher re-validates every entry against exclusions at publish time; the
FIRST violation rejects the WHOLE build, unlike the builder which drops
offending rows (`crates/feed/src/publisher.rs:95-101,173-205`).

## Reserved-range guard (`crates/core-scoring/src/net.rs`)

`is_reserved_ip(ip)` is one definition shared by BOTH outbound paths (feed
publish and vendor submit); it was previously feed-only, which left the vendor
path unguarded (`net.rs:1-9,57-59`). The ranges are fixed and not
operator-configurable (`net.rs:21-53`):

| Class | Ranges |
|---|---|
| RFC1918 private | `10/8`, `172.16/12`, `192.168/16` |
| RFC5737 doc | `192.0.2/24`, `198.51.100/24`, `203.0.113/24` |
| Loopback | `127/8`, `::1/128` |
| Link-local | `169.254/16`, `fe80::/10` |
| Multicast | `224/4`, `ff00::/8` |
| Broadcast | `255.255.255.255/32` |
| IPv6 ULA | `fc00::/7` |
| IPv6 doc | `2001:db8::/32` |

The malware fetcher's SSRF guard extends this with additional deny ranges
(`0.0.0.0/8`, CGNAT `100.64.0.0/10`, `::`, Teredo, deprecated v4-compat,
own-host) - see [integrations.md](integrations.md) and
[../security/outbound-controls.md](../security/outbound-controls.md).

## See also

- [reference/rate-limits-and-budgets.md](rate-limits-and-budgets.md) - caps and budgets across the pipeline
- [reference/integrations.md](integrations.md) - VirusTotal, vendor submitters, ntfy, GeoLite2
- [reference/database.md](database.md) - `ip_score`, `review_queue` schema
- [architecture/pipeline.md](../architecture/pipeline.md) - how scoring, review, and feed connect
