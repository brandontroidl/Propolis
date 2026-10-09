<!--
title: Scoring and feed reference
audience: all
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-28
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
derived flags (`crates/core-scoring/src/scoring/engine.rs#apply_event`).

### Constants

Defined in `crates/core-scoring/src/scoring/constants.rs`.

| Constant | Value | Meaning |
|---|---|---|
| `HALF_LIFE_SECONDS` | 21600 (6 h) | Decay half-life for raw score and per-category weight (`crates/core-scoring/src/scoring/constants.rs#HALF_LIFE_SECONDS`) |
| `DEDUP_WINDOW_SECONDS` | 60 | A repeat `(source_ip, signal_type)` within 60 s records the event but adds no weight (`crates/core-scoring/src/scoring/constants.rs#DEDUP_WINDOW_SECONDS`) |
| `SCORE_CAP` | 100 | Clamp ceiling for raw and effective score (`crates/core-scoring/src/scoring/constants.rs#SCORE_CAP`) |
| `BREADTH_PER_WAN` | 0.15 | Breadth-factor increment per extra distinct WAN vantage (`crates/core-scoring/src/scoring/constants.rs#BREADTH_PER_WAN`) |
| `BREADTH_CAP` | 0.60 | Max breadth bonus; factor saturates at 1.60 (`crates/core-scoring/src/scoring/constants.rs#BREADTH_CAP`) |
| `BLOCKLIST_FLOOR` | 50 | Minimum effective score for blocklist recommendation (`crates/core-scoring/src/scoring/constants.rs#BLOCKLIST_FLOOR`) |
| `PERSIST_PER_DAY` | 0.55 | Persistence bonus points per active day beyond grace (`crates/core-scoring/src/scoring/constants.rs#PERSIST_PER_DAY`) |
| `PERSIST_GRACE_DAYS` | 2 | Active days that earn no persistence bonus (`crates/core-scoring/src/scoring/constants.rs#PERSIST_GRACE_DAYS`) |
| `PERSIST_CAP` | 60 | Max persistence bonus in points (`crates/core-scoring/src/scoring/constants.rs#PERSIST_CAP`) |
| `VOLUME_LIST_THRESHOLD` | 1000 | Cumulative established `event_count` for volume-blocklisting (`crates/core-scoring/src/scoring/constants.rs#VOLUME_LIST_THRESHOLD`) |
| `VOLUME_LIST_WINDOW_SECONDS` | 86400 (24 h) | Recency gate for volume-blocklisting (`crates/core-scoring/src/scoring/constants.rs#VOLUME_LIST_WINDOW_SECONDS`) |
| `LIVE_FLOOR` | 0.5 | A category contributes to `distinct_categories` / `max_confidence` only while its decayed weight is strictly `> 0.5` (`crates/core-scoring/src/scoring/engine.rs#LIVE_FLOOR`) |

### Decay

`factor = 0.5 ^ (elapsed_seconds / HALF_LIFE_SECONDS)`. Non-positive elapsed
returns the prior state unchanged (clock-skew clamp; decay only shrinks)
(`crates/core-scoring/src/scoring/decay.rs#decay`). On add,
`new_raw = min(SCORE_CAP, decayed_raw + weight)` (`crates/core-scoring/src/scoring/engine.rs#apply_event`).
`max_confidence` per category is a running MAX and does not decay
(`crates/core-scoring/src/scoring/engine.rs#apply_event`).

### Breadth multiplier

```
breadth_factor(n) = 1 + min(0.60, 0.15 * max(0, n - 1))
effective_score(raw, n) = min(SCORE_CAP, raw * breadth_factor(n))
```

`breadth_factor(0) = breadth_factor(1) = 1.00`; it saturates at 1.60 for
`n >= 5` (`crates/core-scoring/src/scoring/breadth.rs#breadth_factor`).

The distinct WAN count is hardened: only vantages with
`saw_authenticated_tcp == true` are counted, and vantages dedup by /24 (IPv4) or
/64 (IPv6) prefix before counting - a spoofed source cannot complete an
authenticated TCP handshake, and same-prefix vantages are treated as one
operator block (`crates/core-scoring/src/scoring/breadth.rs#distinct_wan_count`,
`crates/core-scoring/src/scoring/breadth.rs#WanVantage`,
`crates/core-scoring/src/scoring/breadth.rs#dedupe_prefix`). ASN-based dedup is a documented deferred
extension, not shipped `[planned]` (`crates/core-scoring/src/scoring/breadth.rs#dedupe_prefix`). The engine does not
recompute breadth; `distinct_wan_count` is supplied by the repository and
threaded through verbatim (`crates/core-scoring/src/scoring/engine.rs#apply_event`).

The WAN vantage data feeds only this internal multiplier. It is never placed in
any vendor report - see [integrations.md](integrations.md#what-is-never-sent).

### Persistence bonus

```
persistence_points(active_days) = min(PERSIST_CAP, PERSIST_PER_DAY * max(0, active_days - PERSIST_GRACE_DAYS))
```

`active_days` is an unbounded, non-decaying count of distinct UTC calendar days
seen (`crates/core-scoring/src/scoring/engine.rs#apply_event`). The bonus is 0 up to and including 2 days, then
linear at 0.55/day, saturating at 60 points
(`crates/core-scoring/src/scoring/persistence.rs#persistence_points`).

The bonus is applied only to a gate-facing score, never the stored raw:
`gated_raw = min(SCORE_CAP, raw_score + persistence_points(active_days))`
(`crates/core-scoring/src/scoring/engine.rs#derive_projection`). The stored `raw_score` stays the decayed accumulation so
the next decay cannot double-count the bonus. Confidence and eligibility gates
still apply, so a persistent low-confidence scanner is lifted but never promoted
(`crates/core-scoring/src/scoring/engine.rs#derive_projection`).

Calibration documented in code: a once-a-day command-exec source (base ~60)
reaches STANDARD (75) at ~30 active days and AGGRESSIVE (90) at ~60
(`crates/core-scoring/src/scoring/constants.rs#PERSIST_PER_DAY`).

## Tier

`tier(raw_score, max_confidence)` (`crates/core-scoring/src/scoring/tier.rs#tier`),
evaluated aggressive-first with inclusive (`>=`) floors:

| Tier | Requires |
|---|---|
| Aggressive | `raw_score >= 90` AND `max_confidence >= 0.95` |
| Standard | `raw_score >= 75` AND `max_confidence >= 0.70` |
| (none) | otherwise |

The `FeedTier` enum has only `Aggressive` and `Standard` (`crates/core-scoring/src/domain/enums.rs#FeedTier`).

Tier runs on the **gated raw** (base + persistence), NOT the breadth-multiplied
effective score: `tier(gated_raw, max_confidence)` (`crates/core-scoring/src/scoring/engine.rs#derive_projection`).
`max_confidence` is live-decayed - only categories whose decayed weight is
`> LIVE_FLOOR (0.5)` contribute; an empty breakdown yields 0, fail-closed
(`crates/core-scoring/src/scoring/engine.rs#derive_projection`).

## Eligibility latch

```
eligible(has_confirmed_real, event_count, _distinct_categories, delisted)
    = !delisted && has_confirmed_real && event_count >= 2
```

(`crates/core-scoring/src/scoring/eligibility.rs#eligible`). The
`distinct_categories` argument is ignored (leading underscore): the older
two-category gate was dropped 2026-08-19 (migration `0006_relax_eligibility.sql`).
Eligibility takes no score input, so a decayed score can never revoke it; it is
sticky until an explicit delist.

### Confirmed-real gate

`is_confirmed_real(protocol, authenticated, category) = (protocol == Tcp) && authenticated && (category == Honeypot)`
(`crates/core-scoring/src/domain/enums.rs#is_confirmed_real`). The latch is sticky:
`has_confirmed_real = prev || is_confirmed_real(...)` - once set, never unset
(`crates/core-scoring/src/scoring/engine.rs#apply_event`). UDP/ICMP and unauthenticated or non-honeypot traffic
never latch it.

## Recommendation gates

Derived in `derive_projection`, the single source of truth shared by
`apply_event` (write) and `project_to_now` (read) (`crates/core-scoring/src/scoring/engine.rs#derive_projection`).

| Gate | Rule | Source |
|---|---|---|
| `recommended_for_vendor` | `eligible && tier.is_some()` | `crates/core-scoring/src/scoring/tier.rs#recommended_for_vendor` |
| `recommended_for_blocklist` | `eligible && effective_score >= 50` **OR** the volume path below | `crates/core-scoring/src/scoring/tier.rs#recommended_for_blocklist`, `crates/core-scoring/src/scoring/engine.rs#derive_projection` |
| `recommended_by_volume` | `!delisted && established_event_count >= 1000 && seconds_since_last_seen <= 86400` | `crates/core-scoring/src/scoring/tier.rs#recommended_by_volume` |

The volume path is independent of confirmed-real and score. It counts ONLY
`established_event_count` (completed-TCP events: `prev + (protocol == Tcp)`,
`crates/core-scoring/src/scoring/engine.rs#apply_event`), so a spoofed UDP/ICMP flood cannot volume-list an innocent
third party. Vendor reporting always gates on `recommended_for_vendor`
(confirmed-real), so a bare flood is blocked locally but never reported upstream
(`crates/core-scoring/src/scoring/engine.rs#derive_projection`).

## Feed membership and retention

Owned by the feed builder (`crates/feed/src/builder.rs`). Membership is decided
by RETENTION windows, not a live-decayed score. All fields are read as stored (as
of the IP's last event), so a tier cannot slide between builds
(`crates/feed/src/builder.rs#Candidate`, `crates/feed/src/builder.rs#build`).

### Candidate sources

- **Tier candidates** (aggressive / standard files) require operator approval:
  `s.recommended_for_blocklist = true AND s.eligible = true AND q.state = 'approved' AND s.tier IS NOT NULL`
  (`crates/feed/src/builder.rs#build`). See the [review queue](../architecture/pipeline.md).
- **Volume candidates** are auto-published (no approval):
  `s.recommended_for_blocklist = true AND s.eligible = false` (tier = none). They
  land ONLY in retention windows, never the tier files
  (`crates/feed/src/builder.rs#build`).

### TTLs and windows

| Setting | Default | Env var | Source |
|---|---|---|---|
| Aggressive tier TTL | 24 h | `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` | `crates/propolis/src/config.rs#DEFAULT_AGGRESSIVE_TTL_HOURS`, `crates/propolis/src/config.rs#load_config` |
| Standard tier TTL | 48 h | `PROPOLIS_FEED_STANDARD_TTL_HOURS` | `crates/propolis/src/config.rs#DEFAULT_STANDARD_TTL_HOURS` |
| Retention windows | `24h,7d,30d,60d,90d` | `PROPOLIS_FEED_WINDOWS` | `crates/propolis/src/config.rs#DEFAULT_FEED_WINDOWS`, `crates/propolis/src/config.rs#load_config` |
| Build interval | 15 min (900 s) | `PROPOLIS_FEED_BUILD_INTERVAL_SECS` | `crates/propolis/src/config.rs#DEFAULT_FEED_BUILD_INTERVAL_SECS` |
| Feed enabled | true | `PROPOLIS_FEED_ENABLED` | `crates/propolis/src/config.rs#load_config` |
| Output dir | `/var/lib/propolis/feed/current` | (config) | `crates/propolis/src/config.rs#DEFAULT_FEED_OUTPUT_DIR` |

Retention windows ignore tier and hold every approved entry (and volume floods)
whose `last_seen` is inside the window, published as `all-{label}.*` and nested
by construction (`crates/feed/src/builder.rs#FeedConfig`, `crates/feed/src/builder.rs#build`). A candidate is kept iff
`now - last_seen < ttl`; each entry's `valid_from = coarsen_to_hour(last_seen)`
and `valid_until = valid_from + ttl` (`crates/feed/src/builder.rs#materialize`). Every exported
timestamp is coarsened to the hour boundary (anti-deanonymization)
(`crates/feed/src/builder.rs#coarsen_to_hour`).

Full default/bound detail for these env vars is owned by
[environment-variables.md](environment-variables.md).

## Exclusions and ASN suppression

`ExclusionEngine.is_excluded(ip)` (`crates/feed/src/exclusion.rs#is_excluded`):

```
is_reserved(ip) || allowlist_cidr_contains(ip) || delist_contains(ip) || asn_allowlisted(ip)
```

- `is_reserved` delegates to the shared reserved-range guard (below).
- Allowlist / delist / ASN allowlist are operator-supplied via
  `PROPOLIS_FEED_ALLOWLIST` (CIDR), `PROPOLIS_FEED_DELIST` (IPs), and
  `PROPOLIS_FEED_ASN_ALLOWLIST` (AS numbers) - all empty by default
  (`crates/propolis/src/config.rs#load_config`).
- **ASN suppression** is opt-in with an empty default; it suppresses
  trusted-org infrastructure (e.g. Microsoft AS8075, Google AS15169) keyed off
  offline GeoLite2-ASN reads (see [integrations.md](integrations.md#geolite2-offline-enrichment)).
  ASN ownership is RIR-registered, not per-IP spoofable. An empty allowlist
  short-circuits before any DB lookup; a non-empty allowlist with no ASN DB
  loaded means suppression is configured but INERT
  (`crates/feed/src/exclusion.rs#with_asn_allowlist`, `crates/core-scoring/src/allowlist.rs#lookup_asn`,
  `crates/feed/src/exclusion.rs#asn_db_loaded`).
- The CIDR and ASN allowlist is one definition, `OperatorAllowlist`
  (`crates/core-scoring/src/allowlist.rs#contains`), because the review stage applies it too:
  `ExclusionEngine` delegates to it for the feed, and the review queue and submission runner use
  the same value for vendor reporting (see [Declared crawlers](#declared-crawlers)).

The publisher re-validates every entry against exclusions at publish time; the
FIRST violation rejects the WHOLE build, unlike the builder which drops
offending rows (`revalidate`, `crates/feed/src/publisher.rs#revalidate`).

### Declared crawlers

Research and AI crawlers (ClaudeBot, Claude-User, Claude-SearchBot, Googlebot,
CensysInspect and similar) reach the HTTP sensor. Two separate mechanisms apply,
and only the first can change what is published:

- **Exemption is by address, from a file the operator maintains.**
  `PROPOLIS_FEED_ALLOWLIST_FILE` names a local text file with one CIDR per line
  (blank lines and `#` comments allowed). Its entries are merged into
  `PROPOLIS_FEED_ALLOWLIST`. To exempt a crawler, copy the address ranges its
  operator publishes into that file and restart; the daemon never fetches them.
  The file is read once at startup and is all-or-nothing
  (`crates/core-scoring/src/allowlist.rs#parse_allowlist_text`,
  `crates/core-scoring/src/allowlist.rs#load_allowlist_file`): an unreadable file, a
  line that is not a CIDR (a bare address is rejected), an entry wider than /8
  (IPv4) or /16 (IPv6), more than 50,000 entries, more than 1 MiB, or non-UTF-8
  content refuses to start the daemon. A corrupted list therefore cannot exclude
  everything, and cannot silently exclude nothing either.
- **A User-Agent exempts nothing.** The HTTP sensor adds `claimed_crawler` to the
  event metadata when the User-Agent contains a known crawler token
  (`crates/sensor-http/src/crawler.rs#claimed_crawler`). The value is a fixed
  label, shown in the event's raw metadata; no scoring, queue or feed code reads
  it. Any client can send "ClaudeBot", so such a request from an address outside
  the file is scored and published like any other
  (`crates/feed/tests/builder_test.rs#a_claimed_crawler_is_published_unless_its_address_is_in_an_operator_range_file`).

The allowlist is applied when the feed is built and published, and again by the
review stage: `ReviewQueue::populate` never queues a listed address,
`ReviewQueue::withdraw` removes a Pending one (logged with the reason
`allowlisted`), and `SubmissionRunner::run_once` refuses a listed address before
any vendor call, as a second line of defence for an entry queued or approved
before the list covered it
(`crates/review/src/queue.rs#populate`, `crates/review/src/queue.rs#withdraw`,
`crates/review/src/submit.rs#run_once`;
`crates/review/tests/allowlist_test.rs`). It does not change scoring: a listed
address is still scored and shown in the console. The list is read once at
startup, so an edit needs a restart.

## Reserved-range guard (`crates/core-scoring/src/net.rs`)

`is_reserved_ip(ip)` is one definition shared by BOTH outbound paths (feed
publish and vendor submit); it was previously feed-only, which left the vendor
path unguarded (the `net.rs` module doc). The ranges are fixed and not
operator-configurable (`RESERVED_RANGES`):

| Class | Ranges |
|---|---|
| RFC1918 private | `10/8`, `172.16/12`, `192.168/16` |
| Shared address space (CGNAT, RFC 6598) | `100.64/10` |
| This network, unspecified | `0/8`, `::/128` |
| Documentation | `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `2001:db8::/32`, `3fff::/20` |
| Loopback | `127/8`, `::1/128` |
| Link-local | `169.254/16`, `fe80::/10` |
| Multicast | `224/4`, `ff00::/8` |
| Broadcast and future use | `255.255.255.255/32`, `240/4` |
| IPv6 ULA | `fc00::/7` |
| IETF protocol assignments | `192.0.0/24`, `2001::/23` (includes Teredo `2001::/32` and benchmarking `2001:2::/48`) |
| Benchmarking | `198.18/15` |
| 6a44 relay anycast | `192.88.99.2/32` |
| NAT64 local-use | `64:ff9b:1::/48` |
| IPv6 discard-only and dummy | `100::/64`, `100:0:0:1::/64` |
| SRv6 segment identifiers | `5f00::/16` |

The list matches the IANA IPv4 and IPv6 Special-Purpose Address Registries
(both last updated 2025-10-09; compared 2026-09-28): every block they mark not
globally reachable is in it except the IPv4-mapped prefix `::ffff:0:0/96`.
`is_reserved_ip` also judges an IPv6 address by the IPv4 host it carries, for
the three forms that carry one (`embedded_ipv4`: IPv4-mapped, the well-known NAT64
`64:ff9b::/96` and 6to4 `2002::/16`), so `::ffff:10.0.0.1`, `64:ff9b::7f00:1` and
`2002:a00:1::` are reserved while the same forms around a public address are not.
Two calls go beyond the registries' reachability column:

- `192.0.0.0/24` and `2001::/23` are listed whole, although a few members are
  marked globally reachable: anycast service addresses (PCP, TURN, DNS-SD, AMT, AS112)
  and identifier prefixes (ORCHIDv2, drone entity tags). None of them is an
  attacking host's own address.
- 6to4 (`2002::/16`, reachability "N/A") is not listed: a 6to4 address belongs
  to whoever holds its embedded IPv4 address, so it is judged by that address.

The malware fetcher's SSRF guard applies this same list and adds own-host
addresses, rejection of Teredo, deprecated v4-compat and non-`/96` NAT64 forms,
decoding of the same embedded-IPv4 forms (the shared `embedded_ipv4`), and a
fetch-only list repeating `0.0.0.0/8`, `100.64.0.0/10` and `::` - see
[integrations.md](integrations.md) and
[../security/outbound-controls.md](../security/outbound-controls.md).

## See also

- [reference/rate-limits-and-budgets.md](rate-limits-and-budgets.md) - caps and budgets across the pipeline
- [reference/integrations.md](integrations.md) - VirusTotal, vendor submitters, ntfy, GeoLite2
- [reference/database.md](database.md) - `ip_score`, `review_queue` schema
- [architecture/pipeline.md](../architecture/pipeline.md) - how scoring, review, and feed connect
