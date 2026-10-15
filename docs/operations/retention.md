<!--
title: Retention
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-14
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

Spooled sample files are removed after **30 days**, by whichever process owns the spool:

- **Each spooling sensor ages out its own spool** (ssh, telnet, adb, ftp, tftp, mqtt): once when it
  starts and then hourly, `QuarantineSpool::prune_older_than(SAMPLE_RETENTION)`, started by
  `CaptureHandoff::start_worker` so a sensor that stores samples through the framework has it
  (`crates/sensor-framework/src/spool.rs#prune_older_than`,
  `crates/sensor-framework/src/handoff.rs#start_worker`). It removes only entries named with a
  canonical SHA-256 directly in the spool directory (a planted link is removed as a link, never
  followed; the outbox manifest below the root is not touched) and recounts the spool's byte
  budget, so the freed space is usable by the next capture.
- **The daemon's `sample-retention` subsystem** does the same hourly for the one spool it owns,
  the malware fetcher's `fetched` bucket (`review::spool::daemon_retention_dirs`;
  `crates/review/src/virustotal.rs` `cleanup_old_samples`, wired in `crates/propolis/src/main.rs`
  as `SAMPLE_RETENTION_DAYS` / `SAMPLE_RETENTION_INTERVAL`, both derived from the sensors'
  `SAMPLE_RETENTION` / `SAMPLE_RETENTION_INTERVAL`).

The 30-day age and the hourly cadence are compile-time constants, not env vars. Neither pass
performs egress (it is local file deletion). There is no hold mechanism: a file that must be kept
(for example one that may be illegal material) has to be moved out of the spool first, see
[captured content handling](./captured-content-handling.md#quarantine-one-sample). A pass that finds
a sample past retention and cannot remove it logs a WARN with the directory in its `spool` field (the sensor's text is `samples past retention could
not be removed from the spool`, the daemon's `a sample past retention could not be removed`; grep for
`past retention could not be removed` to match both); a spool whose passes keep logging it is not being trimmed, and
the cause is that directory's owner or mode.

The daemon's pass is always spawned, independent of VirusTotal. It used to be a step of the VT scan
cycle, so a deployment without a VT key never aged out a sample and its spools were bounded only
by the byte budgets below, which then refused new evidence once old samples had filled them.

### Why the sensors prune their own spools

Until this change the daemon's pass walked every sensor spool, and under the shipped units it could
not delete from any of them, with no log line to say so. Two independent causes, either enough:

1. **The sandbox.** `deploy/propolis.service` runs with `ProtectSystem=strict` and lists only
   `/var/lib/propolis` and `/var/spool/propolis/fetched` in `ReadWritePaths`, so
   `/var/spool/propolis/<sensor>` is a read-only mount in the daemon's namespace and `unlink`
   fails with `EROFS`.
2. **The directory mode.** `deploy/provision.sh` creates each sensor spool `0750` for the sensor's
   own user and group. The daemon's user reaches it as a member of that group (so it can read the
   samples), and `unlink` needs write permission on the directory, which the group does not have.

The sensors' own units already list their spool in `ReadWritePaths`, and the directory belongs to
the sensor's user at `0700` or wider, so a sensor can delete there with **no change to any unit or
directory**. Letting the daemon do it instead would have meant adding six sensor spools to
`propolis.service`'s `ReadWritePaths` and giving the group (or the daemon) write access to
directories owned by the internet-facing sensors, which lets a compromised daemon unlink or replace
entries there (the cross-account write `install_script_var_lib_root_is_root_owned` exists to
prevent for `/var/lib/propolis`). Pruning in the sensor loosens nothing, also covers a collector in
a [split deployment](./split-deployment.md) that runs no daemon, and releases the sensor's budget
directly. **Unit and provisioning changes made: none.**

**Open policy question for a collector.** Sample bodies never leave a collector (the shipper sends log
lines only), so on a collector the sensor's 30-day pass deletes the only copy of each body, whether or
not the control plane ever saw its event. The planned custody design says a collector may delete its
only copy of a body only on `CustodyComplete`
([evidence provenance and artifact custody](../architecture/evidence-provenance-and-artifact-custody.md));
that handshake is not implemented, so the pass does not consult the outbox. Until the owner decides
between limiting the sensor-side pass to non-collector roles and gating it on `CustodyComplete` once
that handshake lands, an operator who needs a collector's bodies for longer must copy them off within
30 days. A deleted body keeps its event (hash, size, name) in the log and the ledger.

`crates/propolis/tests/retention_deploy.rs` keeps this true: for every spool a retention pass
walks, the account that runs the pass owns the directory with `rwx` in `provision.sh` and has the
path in `ReadWritePaths` in its unit, the daemon's list is limited to spools its unit can write,
and `propolis.service` grants nothing more under `/var/spool/propolis`. If you relocate a sensor's
spool with `PROPOLIS_<SENSOR>_SPOOL_DIR`, give that sensor's unit the new path in `ReadWritePaths`
(a drop-in), or the sensor cannot write there at all.

A sensor that is stopped does not prune its spool, and a sensor started with samples already past
retention removes them in its first pass. The fetcher spool stays as before.

Note that the sample-analysis DB rows (`sample_analysis`) recording VT verdicts are not deleted
by this pass; only the spooled file bytes are. See [integrations](../reference/integrations.md)
and [queue and spool](./queue-and-spool.md).

Independently of age, each spool is capped by a global byte budget (100 MB per spooling sensor,
1 GB for the fetcher), enforced fail-closed at store time; a burst can be trimmed by budget
refusal regardless of whether the cleanup pass runs. A refused sensor upload still leaves its event
in the ledger, marked `stored: false` with a `not_stored_reason`, so the observation is kept and
only the body is lost ([queue and spool](./queue-and-spool.md#spool-refusals-spool_refused_count)).
See [capacity planning](./capacity-planning.md).

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

## Quarantined intake lines

When the database refuses the same log line on three polls in a row, intake appends it to
`/var/lib/propolis/quarantine/<sensor-label>.jsonl` and moves on
(`PROPOLIS_QUARANTINE_DIR`; what the records hold and how to inspect or re-ingest one:
[health and observability](./health-and-observability.md#quarantined-intake-lines)). These
files are **never cleaned automatically**: nothing rotates, prunes or compresses them, and
nothing but you reads them. They are bounded instead: once the directory holds 64 MiB or 10,000
records, nothing more is quarantined, and the next refused line holds that sensor's intake until
you make room (`crates/intake/src/quarantine.rs#MAX_QUARANTINE_BYTES`,
`crates/intake/src/quarantine.rs#MAX_QUARANTINE_RECORDS`; both fixed, not variables). A line is
typically a few hundred bytes to a few KiB, so the cap is a sign something is producing refused
lines in bulk, not ordinary use. To make room, look at what is there first, then move or delete
the files you are done with (`sudo -u propolis`, since the directory is `0750 propolis`); the
next poll of a held sensor picks up the freed space without a restart. The records carry
attacker-supplied text, so treat the files as captured evidence and keep them off any shared
share. They are listed with the other on-disk state under [backup and
restore](./backup-and-restore.md); do not confuse this directory with the malware fetcher's
`fetched` spool, which has its own budget and cleanup above.

## Stored shell replies

The text of what the fake shell answered is kept once per distinct reply in `shell_output`
([database reference](../reference/database.md#shell-output-table)). The ledger rows name a reply
by digest and are never pruned, so a reply a ledger row names is kept for as long as the row. What
the daemon removes is the **orphans**: a reply no event names (its batch's append failed, or its
line was quarantined) that intake has not stored for 24 hours. The pass runs hourly inside the
`sample-retention` subsystem and logs a count when it deletes any
(`crates/core-scoring/src/repository/shell_output.rs#prune_orphan_outputs`,
`crates/propolis/src/main.rs#SHELL_OUTPUT_ORPHAN_GRACE`; the grace period is a compile-time
constant, not a variable). A reply that arrives again has its age refreshed at most once an hour,
so a row a batch is about to name is never the one deleted.

**Growth bound.** The table grows with the number of distinct replies, not with sessions or
events, and each reply is at most 4 KiB (`REPLY_TEXT_CAP`). Per source, the sensor admits at most
12 command events a minute after a burst of 200 for each /24, with at most 128 distinct command
shapes tracked per 60-second window
(`crates/sensor-framework/src/command_flood.rs#DEFAULT_COMMAND_EVENTS_PER_MIN`,
`crates/sensor-framework/src/command_flood.rs#DEFAULT_COMMAND_EVENT_BURST`,
`crates/sensor-framework/src/command_flood.rs#MAX_TRACKED_COMMANDS`), and a flood of one command
is one row when its reply is always the same. The worst case is an attacker who varies the reply
text on purpose: about 128 distinct shapes every 60 seconds from one /24, which at
the 4 KiB cap is at most about 0.5 MiB a minute, 30 MiB an hour and 0.7 GiB a day from that
source, before the ledger's own growth for the events that name them. A reply an event names is
never pruned, so under such a flood the table grows with the ledger, and has the same remedy:
archive or prune old events yourself and then the orphan pass removes their replies after 24 hours.
`/metrics` reports `propolis_shell_output_rows` (planner estimate) and `propolis_shell_output_bytes`
(table plus indexes) so growth is visible before it matters
([health and observability](health-and-observability.md#metrics)).

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
The next rotation renames `.1` to `.2` and compresses it, so the copy is only readable in place
while it is `.1`; the tailer also finds it in `.2` or `.2.gz` when it restarts after a second
rotation that skipped the guard (a gzip is expanded to a scratch file, capped at 512 MiB). After the free-space check, the guard therefore
reads the reader's saved cursor (read-only; `<cursor dir>/<sha256 of the resolved log path>.json`
(symlinks, `//` and `..` resolved, as the daemon names it), in
`PROPOLIS_CURSOR_DIR`, default `/var/lib/propolis/cursors`, and `PROPOLIS_SHIPPER_CURSOR_DIR`,
default `/var/lib/propolis/shipper/cursors`, so an intake node and a collector node are both
covered) and skips the log when either holds:

- `.1` has not been fully read: the cursor still carries `.1`'s fingerprint and sits short of its
  size. The tailer keeps its saved cursor in the old content until the drain of `.1` ends, so this
  is also true for the moment between a rotation and the reader noticing it. A cursor that still
  carries `.2`'s (or `.2.gz`'s, by its first 256 decompressed bytes) fingerprint means `.1` was
  rotated after it and has not been read at all.
- the live file holds more than 64 MiB the reader has not read
  (`PROPOLIS_LOGROTATE_MAX_UNREAD_BYTES` overrides the bound). The bound is a judgement, not a
  measurement: two thirds of the shipped `size 100M`, so a log is skipped only when its reader has
  fallen most of a rotation behind, and far under the 300 MiB at which `sensor-log-oversized` pages.

A skipped log is left untouched, the journal line names the reason and the cursor file, and
logrotate exits non-zero so `propolis-logrotate.service` shows failed until the next run rotates
it (logrotate cannot skip one log and report success). Skipping lets the log grow past its
`size`; `sensor-log-oversized` is the backstop that pages if intake does not catch up. The run
still rewrites the state file, so a skip does not trip `rotation-stale`.

If no cursor can be read for a log (none under either directory, an unreadable or malformed one, or
one for a different inode of the log, as when a cursor directory was moved off the default and the
unit does not see the override) the log is **rotated**, as it was before this check existed, and
the journal says why, at warning priority. `deploy/config-check.sh` flags a log with content and no
cursor, and a cursor directory set in `propolis.env` that the unit cannot see. That is deliberately the opposite of the free-space check: refusing on a
missing cursor would turn a misplaced cursor directory, or an intake that never started, into a
rotation that never runs and a log that fills the disk, which is the October 2026 incident. If you
move the cursor directory, give `propolis-logrotate.service` the same `PROPOLIS_CURSOR_DIR` in a
drop-in (`/etc/systemd/system/propolis-logrotate.service.d/cursor-dir.conf`, `[Service]` with
`Environment=PROPOLIS_CURSOR_DIR=...`); the unit deliberately does not read `propolis.env`, which
holds the database URL. The tailer's own check (a verified `.1`) is the second line of defence, and
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
made. The same holds if you truncate while intake is stopped: on its next start the generation its
saved position was in cannot be found, which is reported as a loss, and nothing older is read in
its place (a rotated `events.jsonl.1` left from an earlier rotation is not re-ingested). The last
command confirms the next scheduled run is healthy; delete the archive once you no longer need it.
