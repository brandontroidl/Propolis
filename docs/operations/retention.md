<!--
title: Retention
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Retention

What Propolis keeps and for how long: blocklist-feed retention windows, captured-sample
cleanup, and event/score storage. Exact constants and thresholds are owned by
[scoring and feed reference](../reference/scoring-and-feed.md) and
[environment variables](../reference/environment-variables.md); this page is the operational
view and its interaction with database and disk growth ([capacity
planning](./capacity-planning.md)).

## Feed retention windows and tier TTLs

Blocklist-feed membership is decided by **retention windows and tier TTLs, not by a
live-decayed score**. Every field is read as stored (as of the IP's last event) and never
re-derived against the wall clock, so an entry cannot slide between builds
(`crates/feed/src/builder.rs:110-153`). The feed loop rebuilds every
`PROPOLIS_FEED_BUILD_INTERVAL_SECS` (default **900 s** / 15 min) and publishes atomically; a
failed build leaves the previous feed in place (`crates/propolis/src/main.rs:305-350`).

Two kinds of retention apply:

- **Tier TTLs** bound how long a merit-tiered entry stays in the per-tier files after its last
  sighting:
  - `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` - default **24 h** (`config.rs:23,489`);
  - `PROPOLIS_FEED_STANDARD_TTL_HOURS` - default **48 h** (`config.rs:24,493`).
  An entry is kept iff `now - last_seen < ttl`; `valid_until = coarsen_to_hour(last_seen) + ttl`
  (`builder.rs:302-328`).
- **Retention windows** publish `all-{label}` feeds that ignore tier and hold every approved
  entry (and auto-published volume floods) whose `last_seen` falls inside the window:
  `PROPOLIS_FEED_WINDOWS`, default **`24h,7d,30d,60d,90d`**, nested by construction
  (`config.rs:29,505`, `builder.rs:269-277`). A malformed window entry is fail-closed.

Tiers themselves (aggressive: score >= 90, confidence >= 0.95; standard: >= 75, >= 0.70) and
the eligibility/volume rules are owned by [scoring and feed
reference](../reference/scoring-and-feed.md).

Retention windows and TTLs govern only what the local feed under
`/var/lib/propolis/feed/current` contains. Publishing that feed to a public repository is a
separate operator step: `deploy/blocklist-sync.sh` run from cron on the node, **not** wired
into any shipped systemd timer or cron file (`deploy/blocklist-sync.sh:9`). See
[deployment models](./deployment-models.md) and [outbound
controls](../security/outbound-controls.md).

## Captured-sample cleanup (30 days)

Spooled sample files are removed after **30 days** by the VirusTotal scanner's cleanup pass:
`cleanup_old_samples(spool_dirs, 30)` runs each scan cycle over the sensor and fetcher spools
(`crates/review/src/virustotal.rs:293-320`, wired `crates/propolis/src/main.rs:781`). The
30-day age is a compile-time argument, not an env var. The cleanup itself performs no egress
(it is local file deletion).

> **Important - the 30-day cleanup only runs when VirusTotal is enabled.** The cleanup pass
> lives inside the VT scanner loop, which the daemon spawns only when `PROPOLIS_VT_ENABLED` is
> true and a non-empty key is set (`crates/propolis/src/main.rs:745,781`). With VirusTotal
> disabled, **no age-based sample cleanup runs at all**; spooled files are then bounded only by
> the per-spool global byte budget (see below), not by age. If you run without VirusTotal and
> want age-based sample expiry, prune the spool directories with your own job.

Note that the sample-analysis DB rows (`sample_analysis`) recording VT verdicts are not deleted
by this pass; only the spooled file bytes are. See [integrations](../reference/integrations.md)
and [queue and spool](./queue-and-spool.md).

Independently of age, each spool is capped by a global byte budget (100 MB per spooling sensor,
1 GB for the fetcher), enforced fail-closed at store time; a burst can be trimmed by budget
refusal regardless of whether the cleanup pass runs. See [capacity
planning](./capacity-planning.md).

## Event and score retention

There is **no built-in pruning of the `event` table**: captured events accumulate and are never
auto-deleted. Scoring decays on read (6-hour half-life), so an old event stops contributing to a
score long before it stops consuming storage. `ip_score` holds one durable row per source IP;
eligibility is sticky until an explicit delist, so a score row is not removed when its weight
decays away (`crates/core-scoring/src/scoring/doc_truth.rs:49-64`).

Consequences for an operator:

- plan database storage for sustained ingest; if you need bounded event history, run your own
  periodic pruning job against the `event` table (there is no shipped one);
- delisting an IP (`PROPOLIS_FEED_DELIST`) removes it from feed output but does not delete its
  events or score row;
- the hash-chained event ledger means deletions break chain continuity, so prune with that
  trade-off in mind. See [storage](../architecture/storage.md) and [database
  reference](../reference/database.md).

## Log rotation

Sensor NDJSON logs under `/var/log/propolis/` are rotated by logrotate at `size 100M`,
`rotate 5`, with `compress`/`delaycompress` (`deploy/logrotate-sensors.conf`). Rotation is
size-based, not calendar-based, to bound a flood-driven disk-fill; five compressed generations
are kept per sensor. This is disk hygiene, not event retention: the authoritative event record
is the database, not the rotated log files.
