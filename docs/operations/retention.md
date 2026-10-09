<!--
title: Retention
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
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
(`crates/feed/src/builder.rs#FeedBuilder::build`). The feed loop rebuilds every
`PROPOLIS_FEED_BUILD_INTERVAL_SECS` (default **900 s** / 15 min) and publishes atomically; a
failed build leaves the previous feed in place (`run_feed_loop`, `crates/propolis/src/main.rs#run_feed_loop`).

Two kinds of retention apply:

- **Tier TTLs** bound how long a merit-tiered entry stays in the per-tier files after its last
  sighting:
  - `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` - default **24 h** (`crates/propolis/src/config.rs#DEFAULT_AGGRESSIVE_TTL_HOURS`);
  - `PROPOLIS_FEED_STANDARD_TTL_HOURS` - default **48 h** (`crates/propolis/src/config.rs#DEFAULT_STANDARD_TTL_HOURS`).
  An entry is kept iff `now - last_seen < ttl`; `valid_until = coarsen_to_hour(last_seen) + ttl`
  (`crates/feed/src/builder.rs#materialize`).
- **Retention windows** publish `all-{label}` feeds that ignore tier and hold every approved
  entry (and auto-published volume floods) whose `last_seen` falls inside the window:
  `PROPOLIS_FEED_WINDOWS`, default **`24h,7d,30d,60d,90d`**, nested by construction
  (`crates/propolis/src/config.rs#DEFAULT_FEED_WINDOWS`, `crates/feed/src/builder.rs#FeedBuilder::build`). A malformed window entry is fail-closed.

Tiers themselves (aggressive: score >= 90, confidence >= 0.95; standard: >= 75, >= 0.70) and
the eligibility/volume rules are owned by [scoring and feed
reference](../reference/scoring-and-feed.md).

Retention windows and TTLs govern only what the local feed under
`/var/lib/propolis/feed/current` contains. Publishing that feed to a public repository is a
separate operator step: `deploy/blocklist-sync.sh` run from cron on the node, **not** wired
into any shipped systemd timer or cron file (`deploy/blocklist-sync.sh`). See
[deployment models](./deployment-models.md) and [outbound
controls](../security/outbound-controls.md).

## Captured-sample cleanup (30 days)

Spooled sample files are removed after **30 days** by the daemon's `sample-retention`
subsystem: `cleanup_old_samples(spool_dirs, 30)` runs hourly over every body directory
(`review::spool::all_body_dirs`: the sensor spools plus the fetcher's `fetched` bucket;
`crates/review/src/virustotal.rs` `cleanup_old_samples`, wired in `crates/propolis/src/main.rs`
as `SAMPLE_RETENTION_DAYS` / `SAMPLE_RETENTION_INTERVAL`). The 30-day age and the hourly cadence
are compile-time constants, not env vars. The cleanup itself performs no egress (it is local
file deletion). It has no hold mechanism: a file that must be kept (for example one that may
be illegal material) has to be moved out of the spool first, see [captured content
handling](./captured-content-handling.md#quarantine-one-sample).

The subsystem is always spawned, independent of VirusTotal. It used to be a step of the VT scan
cycle, so a deployment without a VT key never aged out a sample and its spools were bounded only
by the byte budgets below, which then refused new evidence once old samples had filled them.

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
decays away (`crates/core-scoring/src/scoring/doc_truth.rs#readme_eligibility_is_not_derived_from_a_decaying_score`,
`crates/core-scoring/src/scoring/doc_truth.rs#readme_delist_is_the_only_removal`).

Consequences for an operator:

- plan database storage for sustained ingest; if you need bounded event history, run your own
  periodic pruning job against the `event` table (there is no shipped one);
- delisting an IP (`PROPOLIS_FEED_DELIST`) removes it from feed output but does not delete its
  events or score row;
- the hash-chained event ledger means deletions break chain continuity, so prune with that
  trade-off in mind. See [storage](../architecture/storage.md) and [database
  reference](../reference/database.md);
- the per-source WAN and sensor sets (`ip_vantage`, `ip_sensor`) are kept by the append path
  and are not pruned with the ledger: after deleting events, rebuild them from what remains
  ([breadth sets](../reference/database.md#breadth-sets)), or later appends keep counting the
  deleted events' WANs and sensors.

## Log rotation

Sensor NDJSON logs under `/var/log/propolis/` are rotated by logrotate at `size 100M`,
`rotate 5`, with `compress`/`delaycompress` (`deploy/logrotate-sensors.conf`). Rotation is
size-based, not calendar-based, to bound a flood-driven disk-fill; five compressed generations
are kept per sensor. This is disk hygiene, not event retention: the authoritative event record
is the database, not the rotated log files.

### What runs the rotation

Propolis runs logrotate itself and does not depend on the distribution's `logrotate.timer`.
`propolis-logrotate.timer` fires hourly (`OnCalendar=hourly`, a two-minute random delay,
`Persistent=true` so a missed hour runs at the next boot, and one run two minutes after the
timer is enabled) and starts `propolis-logrotate.service`, which runs
`logrotate --state /var/lib/propolis/logrotate.state /etc/logrotate.d/propolis-sensors`
(`deploy/propolis-logrotate.timer`, `deploy/propolis-logrotate.service`). Both `install.sh` and
`upgrade.sh` install the two units and run `systemctl enable --now propolis-logrotate.timer`, so
a normal upgrade is the whole rollout. The own state file keeps this run independent of the
distribution's `/var/lib/logrotate/logrotate.status`; logrotate rewrites it on every run, which
is what the `rotation-stale` alert reads.

This exists because the distribution timer is not Propolis's to keep alive: in October 2026 it
was inactive for eleven days on the production box, nothing rotated, one telnet log reached
6.6 GB and `/var` reached 80% used. If the distribution's timer is also active it runs the same
policy against its own state file. The policy is size-triggered, so neither run touches a log
under the size; two runs that both find a log over it at the same moment could rotate it twice
and push a generation out early `[inferred]`.

Check it:

```
systemctl list-timers propolis-logrotate.timer
systemctl status propolis-logrotate.service
journalctl -u propolis-logrotate.service --since -1d
```

### Free-space guard

`copytruncate` rotates by copying the live log to `events.jsonl.1` before truncating the
original, so rotating a log needs free space equal to the log. A log that has outgrown its
filesystem cannot be rotated: the copy fills the volume that also holds the database and every
other sensor log, fails, and the truncate never happens.

The policy therefore runs `/usr/local/sbin/propolis-logrotate-guard` (`deploy/logrotate-guard.sh`)
in a `prerotate` hook, once per log that is due. It admits a log only when the space available
to an unprivileged writer covers the log, a quarter of it more for compressing the previous
generation, and a 512 MiB reserve (`PROPOLIS_LOGROTATE_RESERVE_BYTES` overrides the reserve). A
refused log is left untouched, a line naming it and the shortfall goes to the journal, and
logrotate exits non-zero so the unit shows failed in `systemctl --failed`.

A `prerotate` hook was chosen over an `ExecStartPre` check on the service because logrotate
documents that a failing `prerotate` script skips only the log it ran for, while an
`ExecStartPre` check can only allow or block the whole run, which would let one oversized log
keep every healthy sensor from rotating. The free-space check is a `stat` and a `statfs`.

### Rotation while intake is behind

`copytruncate` moves whatever the reader has not read into `events.jsonl.1`, and the tailer reads
it from there before the new file
([concurrency and failure](../architecture/concurrency-and-failure.md#log-rotation-under-a-reader-that-is-behind)).
That works only while `.1` is still the uncompressed copy: the next rotation renames it to `.2`
and compresses it, and the tailer opens only `.1`. After the free-space check, the guard therefore
reads the reader's saved cursor (read-only; `<cursor dir>/<sha256 of the log path>.json`, in
`PROPOLIS_CURSOR_DIR`, default `/var/lib/propolis/cursors`, and `PROPOLIS_SHIPPER_CURSOR_DIR`,
default `/var/lib/propolis/shipper/cursors`, so an intake node and a collector node are both
covered) and skips the log when either holds:

- `.1` has not been fully read: the cursor still carries `.1`'s fingerprint and sits short of its
  size. The tailer keeps its saved cursor in the old content until the drain of `.1` ends, so this
  is also true for the moment between a rotation and the reader noticing it.
- the live file holds more than 64 MiB the reader has not read
  (`PROPOLIS_LOGROTATE_MAX_UNREAD_BYTES` overrides the bound). The bound is a judgement, not a
  measurement: two thirds of the shipped `size 100M`, so a log is skipped only when its reader has
  fallen most of a rotation behind, and far under the 300 MiB at which `sensor-log-oversized` pages.

A skipped log is left untouched, the journal line names the reason and the cursor file, and
logrotate exits non-zero so `propolis-logrotate.service` shows failed until the next run rotates
it (logrotate cannot skip one log and report success). Skipping lets the log grow past its
`size`; `sensor-log-oversized` is the backstop that pages if intake does not catch up.

If no cursor can be read for a log (none under either directory, an unreadable or malformed one, or
one for a different inode of the log, as when a cursor directory was moved off the default and the
unit does not see the override) the log is **rotated**, as it was before this check existed, and
the journal says why. That is deliberately the opposite of the free-space check: refusing on a
missing cursor would turn a misplaced cursor directory, or an intake that never started, into a
rotation that never runs and a log that fills the disk, which is the October 2026 incident. If you
move the cursor directory, give `propolis-logrotate.service` the same `PROPOLIS_CURSOR_DIR` in a
drop-in. The tailer's own check (a verified `.1`) is the second line of defence, and
`intake-rotation-loss` reports what slips through.

### Alerts

With the ops monitor enabled, `sensor-log-oversized` pages when a configured sensor log is more
than three times the rotation size (300 MiB with the shipped `size 100M`, read from
`/etc/logrotate.d/propolis-sensors`) or the filesystem under `/var/log/propolis` is over 85% used,
`rotation-stale` pages when the state file has not been rewritten for three hours, and
`intake-rotation-loss` pages when a rotation took lines the intake had not read and `.1` could not
supply them. See
[health and observability](health-and-observability.md#ops-alert-monitor-opt-in).

### A log too large to rotate

When the guard refuses a log (the journal says `refusing to rotate`) or `sensor-log-oversized`
names one, archive it and truncate it by hand. This is the recovery used on the production box
after the October 2026 incident. The archive is compressed as it is written, so it needs a small
fraction of the log's size, not a full copy; put it on another filesystem if the log volume is
short on space.

```
LOG=/var/log/propolis/telnet/events.jsonl
ARCHIVE=/var/log/propolis/telnet/events.jsonl.archive-$(date -u +%Y%m%dT%H%M%SZ).gz
df -h /var/log/propolis
sudo sh -c 'gzip -c "$1" > "$2"' sh "$LOG" "$ARCHIVE"
gzip -t "$ARCHIVE" && ls -l "$ARCHIVE"
sudo truncate -s 0 "$LOG"
sudo systemctl start propolis-logrotate.service
```

Run `truncate` only after `gzip -t` succeeds: it discards the log. Lines a sensor appends between
the end of the `gzip` read and the `truncate` are lost, as with `copytruncate` itself. Lines
intake has not yet read are archived but never reach the ledger (see [intake
backlog](../troubleshooting/intake-backlog.md#recovering-a-backlog-too-large-to-drain)); if
intake is keeping up, wait for the fleet pane's `behind:` badge to clear before truncating. The
intake cursor notices the truncation and resumes at the start of the file; when it was behind,
the tailer reports the discarded lines as a rotation loss (a journal WARN and an
`intake-rotation-loss` page for an hour), which here is the expected record of a decision you
made. The last command confirms the next scheduled run is healthy; delete the archive once you
no longer need it.
