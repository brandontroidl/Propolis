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
derived flags (`crates/core-scoring/src/scoring/engine.rs#apply_event`). It does all of
that only for an established event.

### Established and forgeable events

An event is established when it came over a completed TCP connection
(`crates/core-scoring/src/scoring/engine.rs#is_established`): a sender cannot finish the
handshake from an address it does not hold. Any other event (UDP or ICMP; in the shipped sensors
that means DNS over UDP, TFTP, and the catch-all's UDP listener) carries a source address the
sender chose. Such a forgeable sighting is stored in the ledger, counted and shown, but on the
`ip_score` row it changes only `event_count`, `last_seen` (and `first_seen` when it opens the row)
and `distinct_sensor_count` (`crates/core-scoring/src/scoring/engine.rs#record_sighting`). It
adds no weight, no category and no active day, takes no decay step and re-derives nothing. It
cannot set the confirmed-real latch, cannot change `eligible`, `tier`, `recommended_for_vendor`
or `recommended_for_blocklist`, and moves none of the clocks a listing or a vendor report runs
on (`established_last_seen`, `aggressive_earned_at`, `standard_earned_at`).

A row that only forgeable sightings have touched has a score of 0, `active_days` 0 and no tier.
The first established event starts that row over, keeping only the count and the dates of the
sightings (`crates/core-scoring/src/scoring/engine.rs#apply_event`), so a history scores the
same with its forgeable sightings removed. So a TFTP upload, which arrives over UDP, no longer
scores. DNS over TCP and DNS over TLS are TCP and are unaffected.

### Constants

Defined in `crates/core-scoring/src/scoring/constants.rs`.

| Constant | Value | Meaning |
|---|---|---|
| `HALF_LIFE_SECONDS` | 21600 (6 h) | Decay half-life for raw score and per-category weight (`crates/core-scoring/src/scoring/constants.rs#HALF_LIFE_SECONDS`) |
| `DEDUP_WINDOW_SECONDS` | 60 | A repeat `(source_ip, signal_type)` within 60 s of the newest established event of that type records the event but adds no weight (`crates/core-scoring/src/scoring/constants.rs#DEDUP_WINDOW_SECONDS`) |
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

An event never moves time backwards. The new `decay_anchor` is the later of the event's
`observed_at` and the stored anchor, the new `last_seen` the later of `observed_at` and the stored
`last_seen`, and the decay runs from the old anchor to the new one. An event dated before the
anchor (a backlog read late, a collector with a slow clock, a forged timestamp) is still counted,
and adds what its own age leaves of its weight: the weight decayed from `observed_at` to the
anchor, as everything already in the score has been. It used to become the anchor, so the next
event or read decayed the whole score across the gap, and it used to become `last_seen`, which
took a listed address out of every feed window.

That does not make a score independent of the order events are read in. A backlog read after
newer events for the same address can score differently from the same events in order, in
three ways:

- **Dedup.** A repeat is deduped against the newest established event of its signal type
  already stored (`crates/core-scoring/src/repository/events.rs#DEDUP_PRIOR_SQL`,
  `crates/core-scoring/src/repository/batch.rs#DEDUP_PRIORS_SQL`, and the same rule in replay),
  not against its neighbours in time. A datagram is never the event a repeat is measured
  against, so it cannot make a real connection a no-weight duplicate; the partial index
  `event_dedup_tcp_idx` (migration `0027_established_sightings.sql`) serves the read. A burst
  of repeats read in order adds the weight of one; read after a newer event of that type, none
  of its lines is within sixty seconds of the newest, so each adds its own decayed weight.
- **The cap.** It is applied at each step. In order, a burst that reaches 100 loses the excess
  before it decays; read late, each line is decayed first and then added under the cap.
- **Persistence.** The [bonus](#persistence-bonus) counts a day only when it is later than
  the newest day already seen, so a backlog earns no active days.

The first two score a late-read backlog higher than in order, by tens of points for a backlog
a few hours old (ten connections twelve hours back plus one now: 100 read late, about 66 in
order), never above 100, and by next to nothing for one days old, which has decayed away. The
third scores it lower. `first_seen` stays the time of the first
event folded. Replay folds the same events in ledger order through the same function, so it
still equals the stored row for rows written since this rule; a row written before it from
out-of-order events keeps the times it had, and nothing rebuilds it
(`crates/core-scoring/src/scoring/engine.rs#apply_event`). The other direction is closed at
intake, which refuses a line dated more than an hour ahead
([events and signals](events-and-signals.md#what-a-log-line-may-claim-the-origin-policy)).

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
with an established event, counted as events are read (a forgeable sighting adds no day): a day adds one only when it is later than the newest day
already counted, so an older day read late (a backlog) adds none
(`crates/core-scoring/src/scoring/engine.rs#apply_event`). The bonus is 0 up to and including 2 days, then
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
eligible(has_confirmed_real, established_event_count, _distinct_categories, delisted)
    = !delisted && has_confirmed_real && established_event_count >= 2
```

(`crates/core-scoring/src/scoring/eligibility.rs#eligible`). Both sightings must be
established events: a forged datagram cannot be the second sighting of an address that
authenticated once. The
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
| `recommended_by_volume` | `!delisted && established_event_count >= 1000 && seconds_since_established <= 86400`, where `seconds_since_established` is measured from the last established sighting and an address with none is never listed on volume | `crates/core-scoring/src/scoring/tier.rs#recommended_by_volume` |

The volume path is independent of confirmed-real and score. It counts ONLY
`established_event_count` (completed-TCP events: `prev + (protocol == Tcp)`,
`crates/core-scoring/src/scoring/engine.rs#apply_event`) and measures recency from the last
established sighting, so a spoofed UDP/ICMP flood can neither volume-list an innocent third party
nor keep a stopped TCP flood listed. A cred sensor's connection or login summary
(`event_summary: true`) counts as the `suppressed_count` events it replaces, in both
`event_count` and `established_event_count`, so a flooder whose events a per-source budget kept
out of the log reaches the threshold as before
(`crates/core-scoring/src/scoring/engine.rs#represented_events`;
[keys](events-and-signals.md#connection-and-login-summary-keys)). The overflow and per-network
summaries (`overflow_summary: true`) stand for many addresses and count as one event with no
weight and no confirmed-real latch (`crates/core-scoring/src/scoring/engine.rs#apply_event`).
A bare flood can be listed in the retention feeds, once an operator approves it, but is never
reported upstream: the review queue offers only an address that is eligible (confirmed-real)
and has earned a tier (`crates/review/src/queue.rs#OFFERED_SQL`), a volume approval lives in
its own table, which the submission runner never reads, and the vendor gate holds an address
that has not earned a tier within its freshness window
(`crates/review/src/gatekeeper.rs#check_with`;
[gatekeeper](rate-limits-and-budgets.md#vendor-submission-gatekeeper)).

The flag is a recommendation, not a publication. A volume-listed address is published only
through the [volume candidates](#candidate-sources) path below, which by default needs an
operator's approval.

### Earned tiers and listing clocks

The stored `tier`, `eligible` and `recommended_*` columns are whatever the last established
event left. They are still stored and shown, but they no longer decide publication or
reporting. Three columns on `ip_score` (migration `0027_established_sightings.sql`, fields on
`crates/core-scoring/src/domain/types.rs#IpScore`) carry the clocks that do:

| Column | Meaning | Read by |
|---|---|---|
| `established_last_seen` | the latest `observed_at` of an established event; NULL if there is none | volume recency, the volume approval's lapse, the attack time sent to vendors |
| `aggressive_earned_at` | the last time an established event that added its weight left the address eligible and holding the aggressive tier | the aggressive file, the retention windows, the vendor gate |
| `standard_earned_at` | the same for the standard tier | the standard file, the retention windows, the vendor gate |

An earned time is set to the decay anchor after the event, and only by an event that added its
weight: a repeat inside the dedup window and an overflow summary earn nothing
(`crates/core-scoring/src/scoring/engine.rs#apply_event`). It never moves back: on a row an
earlier version left with an earned time ahead of its anchor (migration `0027` seeds the clocks
from the latest established sighting, which on a row read out of order is later than the
anchor), earning the tier again keeps the later time. An event that leaves the address below
the tier neither clears nor advances it, so a listing runs its full TTL from the last time it was
earned: a later weak event cannot end it early, and only earning the tier again extends it.
`IpScore::tier_earned_at` is the later of the two
(`crates/core-scoring/src/domain/types.rs#IpScore::tier_earned_at`). Delisting does not clear
the earned times, so relisting resumes a listing that still has time to run; every consumer
checks the `delisted` latch itself.

## Feed membership and retention

Owned by the feed builder (`crates/feed/src/builder.rs`). Membership is decided
by RETENTION windows, not a live-decayed score. All fields are read as stored, never
re-derived against the clock, so a tier cannot slide between builds, and what decides a listing
is when the address last earned it ([earned tiers](#earned-tiers-and-listing-clocks);
`crates/feed/src/builder.rs#Candidate`, `crates/feed/src/builder.rs#build`).

### Candidate sources

- **Tier candidates** (aggressive / standard files and the retention windows) require operator
  approval and an earned tier:
  `q.state = 'approved' AND NOT s.delisted AND GREATEST(s.aggressive_earned_at, s.standard_earned_at) > $1`,
  where `$1` is the oldest earned time the longest feed can still publish
  (`crates/feed/src/builder.rs#merit_candidates_sql`). See the
  [review queue](../architecture/pipeline.md).
- **Volume candidates** require operator approval by default:
  `NOT s.delisted AND s.established_event_count >= 1000` and an `approved` row in
  `volume_review` or in `review_queue`, with recency taken from `s.established_last_seen > $1`,
  never from `last_seen` (`crates/feed/src/builder.rs#volume_candidates_sql`; the threshold is
  bound from `crates/core-scoring/src/scoring/constants.rs#VOLUME_LIST_THRESHOLD`). They land
  ONLY in retention windows, never the tier files.

An address that is both a tier candidate and a volume candidate is published once, and a
window holds it while either clock (the later earned time or the last established sighting) is
inside it (`crates/feed/src/builder.rs#build`, `crates/feed/src/builder.rs#Candidate::window_listing`).

What an entry says about the address rests on completed connections too: its published
`events` is `established_event_count`, and its `signals` are the signal types of its established
events only (`crates/feed/src/builder.rs#CATEGORIES_SQL`, served by `event_dedup_tcp_idx`), so a
forged datagram naming a listed address can neither add a signal type to its entry nor raise
its count. Its `first_seen` is still the first sighting of any kind.

Neither source reads the stored `tier`, `eligible` or `recommended_*` columns, which are whatever
the last established event left. An entry stays listed for its full TTL after the last time the
address earned the tier: a later weak event neither removes nor extends it, and a datagram
naming the address changes nothing. An approved address that has not earned a tier within a
window is in that window only if it is also a volume candidate. See
[residual risks](../security/residual-risks.md#a-compromised-sensor-can-forge-its-own-kind-of-evidence).

### Volume review

The count behind a volume listing is what sensor log lines declare, and one summary line can
stand for a thousand events, so a volume candidate waits for a decision in its own queue,
`volume_review` (`crates/review/src/volume.rs#VolumeQueue`; schema in
[database.md](database.md)).

| Step | Rule | Source |
|---|---|---|
| Offered (pending) | not delisted, `established_event_count >= 1000`, `established_last_seen` (the last established sighting) within 86400 s of now, no `volume_review` row in any state, no `approved` `review_queue` row, not reserved, not on the operator allowlist or the operator delist (`PROPOLIS_FEED_DELIST`) | `crates/review/src/volume.rs#populate` |
| Withdrawn | a pending row whose address has no `ip_score` row, is delisted, is below the threshold, is now `approved` in `review_queue`, or has come under the operator allowlist or `PROPOLIS_FEED_DELIST` since it was offered (approving it could never publish anything). Decided rows are left alone | `crates/review/src/volume.rs#withdraw` |
| Lapsed | a pending or approved row whose address has made no established connection for the longest configured retention window (`PROPOLIS_FEED_WINDOWS`), and never for less than 90 days, which is also what the standalone `review daemon` uses; a row whose address has no established sighting at all lapses at once. The row is removed and logged, and the address's next flood is offered as a new candidate. A rejected row never lapses. The row is deleted for every node that shares the database, by whichever node's scan gets there first: nodes that publish windows longer than 90 days must all be given the same `PROPOLIS_FEED_WINDOWS` | `crates/review/src/volume.rs#withdraw`, `crates/review/src/volume.rs#lapsing_after`, `crates/review/src/volume.rs#VOLUME_DECISION_LAPSE_DAYS` |
| Approve | publishes the address in the retention feeds from the next build; it is not reported to any vendor. The approval stands until it is reopened, the address is delisted, or it lapses: while it stands, any established (completed-TCP) connection from the address, from any sensor, renews the listing; a datagram naming it does not | `crates/review/src/volume.rs#approve` |
| Reject | not published on volume; the row stays, so the address is not offered again | `crates/review/src/volume.rs#reject` |
| Reopen | back to pending; an approved address leaves the retention feeds at the next build | `crates/review/src/volume.rs#reopen` |

The scan runs with the review queue's, every `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS`, and only
when `PROPOLIS_REVIEW_ENABLED` is true (`crates/propolis/src/main.rs#run_queue_scan_loop`).
With the review subsystem off no candidate is offered, so nothing new can be approved; an
address approved earlier is still published, and the feed build runs the withdrawal and lapse
itself before each build, so such an approval still ends
(`crates/propolis/src/main.rs#run_feed_loop`). Decisions are made
on the console's volume tab ([console routes](console-routes.md)) or with `review volume`
([commands](commands.md)). A delist or delete removes the address's `volume_review` row with
its `review_queue` row. The vendor submission runner reads `review_queue` only
(`crates/review/src/submit.rs#run_once`), so a volume approval never causes a report.

`PROPOLIS_FEED_VOLUME_AUTO_PUBLISH=true` is the opt-in that removes the approval. The
builder then also publishes every address with `s.recommended_for_blocklist = true AND
s.eligible = false`, with no operator decision: any address whose log lines add up to a
thousand TCP events, none of them authenticated, reaches the public retention feeds on that
count alone. It still publishes everything the default does, so setting it never takes an
approved address out. With it set the volume tab is not a view of what is published:

- an address that never authenticated is published whatever is decided there, a rejected one
  included, and delisting is the way to take it out;
- one that went quiet more than a day before a scan saw it is published for as long as a
  window holds it without ever being offered;
- a candidate that has authenticated (`eligible = true`) is not covered by the automatic
  condition and is published on volume only once approved, there or in the review queue.

The feed page and the `all-*` files are what say which addresses are out. The opt-in is off
by default, only the exact word `true` turns it on, and the daemon logs a warning at startup
when it is set (`crates/propolis/src/config.rs#load_config`,
`crates/feed/src/builder.rs#FeedConfig`, `crates/feed/src/builder.rs#volume_candidates_sql`).

### TTLs and windows

| Setting | Default | Env var | Source |
|---|---|---|---|
| Aggressive tier TTL | 24 h | `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` | `crates/propolis/src/config.rs#DEFAULT_AGGRESSIVE_TTL_HOURS`, `crates/propolis/src/config.rs#load_config` |
| Standard tier TTL | 48 h | `PROPOLIS_FEED_STANDARD_TTL_HOURS` | `crates/propolis/src/config.rs#DEFAULT_STANDARD_TTL_HOURS` |
| Retention windows | `24h,7d,30d,60d,90d` | `PROPOLIS_FEED_WINDOWS` | `crates/propolis/src/config.rs#DEFAULT_FEED_WINDOWS`, `crates/propolis/src/config.rs#load_config` |
| Build interval | 15 min (900 s) | `PROPOLIS_FEED_BUILD_INTERVAL_SECS` | `crates/propolis/src/config.rs#DEFAULT_FEED_BUILD_INTERVAL_SECS` |
| Feed enabled | true | `PROPOLIS_FEED_ENABLED` | `crates/propolis/src/config.rs#load_config` |
| Publish volume listings without approval | false | `PROPOLIS_FEED_VOLUME_AUTO_PUBLISH` | `crates/propolis/src/config.rs#load_config` |
| Output dir | `/var/lib/propolis/feed/current` | (config) | `crates/propolis/src/config.rs#DEFAULT_FEED_OUTPUT_DIR` |

Each entry runs from its listing time, the time the address last earned its place in that
file:

- **Aggressive file:** `aggressive_earned_at`, kept while `now - aggressive_earned_at` is under
  the aggressive TTL.
- **Standard file:** `standard_earned_at`, kept while `now - standard_earned_at` is under the
  standard TTL, and only while the address is not in the aggressive file. The two files never
  hold the same address, so one that earned both runs out its aggressive TTL and is then carried
  in the standard file for what is left of the standard one
  (`crates/feed/src/builder.rs#Candidate::standard_listing`).
- **Retention windows** ignore tier and hold every approved entry while the later of its two
  earned times is inside the window, and an approved volume listing while its
  `established_last_seen` is (`crates/feed/src/builder.rs#Candidate::window_listing`). They are
  published as `all-{label}.*` and nested by construction (`crates/feed/src/builder.rs#FeedConfig`,
  `crates/feed/src/builder.rs#build`).

A candidate is kept iff `now - listing_time < ttl`; each entry's
`valid_from = coarsen_to_hour(listing_time)`, `valid_until = valid_from + ttl`, and the
published `last_seen` field is the same coarsened listing time
(`crates/feed/src/builder.rs#materialize`). A listing time later than `now` is read as `now`, so
an entry dated ahead of the clock is never valid past `now + ttl`. Every exported
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
- The delist (`PROPOLIS_FEED_DELIST`) reaches the review side too: an address on it is not
  offered for review, a Pending entry for it is withdrawn (logged with the reason `delisted`),
  it is not offered as a volume candidate, and an Approved one is held from every vendor
  (`crates/review/src/queue.rs#ReviewQueue::with_delist`,
  `crates/review/src/volume.rs#VolumeQueue::with_delist`,
  `crates/review/src/submit.rs#SubmissionRunner::with_delist`). The unified daemon passes its
  own value through; the standalone `review` binary reads the variable itself
  (`crates/review/src/main.rs#ENV_DELIST`), so a node that runs the standalone `feed` and
  `review` services must give `review.env` the same value as `feed.env`.

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

The review stage also never offers a reserved address (`is_reserved_ip`): `populate`
skips it, and each scan rejects, with a recorded note, any such entry already
queued in a state other than Rejected
(`crates/review/src/queue.rs#resolve_reserved`). The submission gatekeeper holds
a reserved address as `Reserved` regardless, so this only keeps the operator
from approving something that can never be reported.

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
