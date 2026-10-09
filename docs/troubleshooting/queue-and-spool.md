<!--
title: Troubleshooting - queue and spool
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
-->

# Queue and spool

Covers capture pressure under flood, the review queue, and the sample/malware
spool filling up. Capacity guidance and the normal-operation model live in
[Queue and spool operations](../operations/queue-and-spool.md) and
[Capacity planning](../operations/capacity-planning.md); this page is symptoms.

## Events look dropped or under-counted during a flood

Several bounds intentionally shed load rather than let a flood exhaust the box.
When traffic looks under-recorded, check which bound is biting.

- **Per-connection capture bounds** - each sensor caps a single connection:
  `<P>_MAX_CAPTURED_BYTES` (default 1 MB; `cred` 100 KB), `<P>_MAX_DURATION_SECS`
  (default 600s; `cred`/catchall much lower), and idle/read timeouts. A capture
  that hits `MAX_CAPTURED_BYTES` stops recording further bytes for that
  connection - expected, not a bug. Values:
  [Environment variables](../reference/environment-variables.md).
- **Concurrency cap** - `<P>_MAX_CONCURRENT` (default 256; `http` 512) bounds
  simultaneous connections per sensor. Beyond it, new connections are refused;
  under a flood this is the deliberate backpressure point.
- **Dedup window** - a repeat `(source_ip, signal_type)` within
  `DEDUP_WINDOW_SECONDS = 60` records the event but adds no score weight
  (`crates/core-scoring/src/scoring/constants.rs#DEDUP_WINDOW_SECONDS`). So "event count rose but
  score did not" during rapid repeats is correct behavior, not a lost event.
- **Command-event budget** - on ssh, telnet and adb, a source network repeating commands past
  its budget (default burst 200, then 12 a minute) stops getting one `honeypot_command_exec` per
  command; its repeats are counted in one `command_summary` event per minute instead. See
  [below](#a-telnet-or-ssh-bot-loop-floods-the-event-log).

### Counters to read

The console `/metrics` endpoint exposes process counters derived per scrape:

- `propolis_events_ingested_total` and `propolis_events_rejected_total` come from
  in-process atomics (`metrics`, `crates/console/src/routes/metrics.rs#metrics`). A rising
  `rejected` total during load is where dropped/invalid events surface.
- `propolis_review_queue_pending` gauges the review backlog.

`/metrics` is unauthenticated but only because the console binds loopback by
default. Scrape it locally:

```
curl -s localhost:8080/metrics | grep -E 'events_(ingested|rejected)_total|review_queue_pending'
```

Field ownership and the full metric list:
[Health and observability](../operations/health-and-observability.md).

## A telnet or ssh bot loop floods the event log

Symptom: one sensor, usually telnet, writes several events a second, nearly all
`honeypot_command_exec` from a few addresses running the same loader session over and over,
several at once. On 2026-10-07 a handful of Mirai-family echo loaders made telnet 97% of all
events at about 15 a second, one address wrote 2,555 in ten minutes, and the log outran log
rotation and intake until the backlog reached 6.6 GB.

What prevents a recurrence: the per-source command-event budget
([sensor behavior](../reference/sensor-behavior.md#command-event-budget-ssh-telnet-adb)). Each
source network gets a burst of command events and then a steady rate; past that, a command whose
shape the network has already run this minute (the line with its escapes and encoded payload
taken out, so every echo chunk is one shape) is counted into one summary event per minute, while
the first of each new shape, each address's first command, every login, connection, capture and
download keeps its own event. Echo-loader chunks are never kept for being new: the capture holds
their bytes. The bot is answered exactly as before, so it does not notice. In the tests, the
observed loop (four parallel sessions every 30 s) drops from 4,240 command events in ten minutes
to 407 plus 10 summaries.

To confirm it is working, look for summaries in the sensor's log:

```
grep -c '"command_summary":true' /var/log/propolis/telnet/events.jsonl
grep '"command_summary":true' /var/log/propolis/telnet/events.jsonl | tail -n 1
```

Each carries `suppressed_count`, `source_prefix` and up to eight sample commands. The defaults
still let a loop through at 12 command events a minute per network, plus the first of each
shape and each address per minute. If intake is still behind, lower the rate in the sensor's
environment file (`/etc/propolis/telnet.env`; ssh and adb read `/etc/propolis/ssh.env` and
`/etc/propolis/adb.env`), for example:

```
PROPOLIS_TELNET_COMMAND_EVENT_RATE_PER_MIN=4
PROPOLIS_TELNET_COMMAND_EVENT_BURST=100
```

and restart that sensor; zero or a non-number refuses to start
([environment variables](../reference/environment-variables.md#standard-sensors-strict-parse---ssh-telnet-http-ftp-redis-adb-catchall-tftp-mqtt-dns)).
A backlog that already exists does not shrink by itself; draining or archiving it is a separate
step ([intake backlog](intake-backlog.md#recovering-a-backlog-too-large-to-drain)).

## Log rotation can lose the events written between the copy and the truncate

Sensor event logs (`events.jsonl`) rotate via logrotate with `copytruncate`
(`deploy/logrotate-sensors.conf`). `copytruncate` was chosen so the sensor's
append-only file descriptor keeps writing without a reopen, at the cost of the
lines written after logrotate copies the file and before it truncates it: they
are in neither the rotated copy nor the new file. That is a documented
trade-off, not a fault, and it is all a rotation costs while intake is caught
up. Input intake had not yet read is not part of that window: the tailer reads
it from `events.jsonl.1`
([concurrency and failure](../architecture/concurrency-and-failure.md#log-rotation-under-a-reader-that-is-behind)).
An `intake-rotation-loss` page means that recovery failed for a log.
Rotation is `size 100M`, `rotate 5`, size-based (not
calendar) specifically to bound a flood-driven disk-fill. If logs are rotating
constantly, the box is under sustained flood; that is the signal, not the log
config.

## Review queue: entries not appearing or not clearing

The review queue is populated/withdrawn by the `review` loop on
`PROPOLIS_QUEUE_SCAN_INTERVAL_SECS` (default 60s), so expect up to one scan
interval of lag.

- **Nothing surfaces** - `populate` only inserts `ip_score` rows where
  `recommended_for_vendor = TRUE AND eligible = TRUE`
  (`crates/review/src/queue.rs#populate`). If a source never becomes eligible
  (eligibility needs a confirmed-real honeypot event and `event_count >= 2`),
  it never enters the queue. Eligibility and tier rules are owned by
  [Scoring and feed](../reference/scoring-and-feed.md).
- **A rejected/snoozed entry keeps its state** - Rejected and Snoozed rows
  persist so `populate` does not re-surface them (`reject`/`snooze`, `crates/review/src/queue.rs#reject`, `crates/review/src/queue.rs#snooze`). This is
  intentional; use approve/reject/snooze from the console, not a manual delete.
- **Review disabled** - `PROPOLIS_REVIEW_ENABLED=false` stops the loop entirely.

## Malware/sample spool filling up

Sensors that capture uploaded files spool them under `/var/spool/propolis/<name>`
and the in-daemon fetcher writes to `/var/spool/propolis/fetched`. Canonical
paths: [Filesystem paths](../reference/filesystem-paths.md).

- **Fetcher spool budget** - the fetcher enforces a hardcoded global budget of
  1 GB on `/var/spool/propolis/fetched` (`FETCH_SPOOL_GLOBAL_BUDGET`,
  `crates/propolis/src/main.rs#FETCH_SPOOL_GLOBAL_BUDGET`). At the budget it stops writing new
  fetched samples; this is a cap, not an error. It is not operator-configurable.
- **Sample retention** - `cleanup_old_samples` removes spool files older than 30
  days each cycle, run by the `sample-retention` supervised task
  (`crates/propolis/src/main.rs#main`, `crates/propolis/src/main.rs#SAMPLE_RETENTION_DAYS`;
  `cleanup_old_samples`, `crates/review/src/virustotal.rs#cleanup_old_samples`). This runs unconditionally,
  independent of whether VT scanning is enabled, so a box with VT disabled still
  ages out old spool files; only the standalone `review` binary (which does not
  run this task) needs you to prune manually or rely on logrotate/disk policy.
  Plan retention accordingly: [Retention](../operations/retention.md).
- **Disk full** - the spool mounts are recommended `noexec,nosuid,nodev` but
  `install.sh` does not create them; it prints fstab guidance. A full spool
  filesystem will surface as write errors in sensor/fetcher logs. Monitor free
  space; if ops-alerting is enabled, `PROPOLIS_OPS_CAPACITY_FREE_PCT` (default
  15%) pages on low capacity.

> **Warning - live malware.** Files under `/var/spool/propolis/fetched` and the
> sensor spools are unanalyzed, potentially live malware samples. Do not open,
> execute, or copy them onto a general-purpose host. The daemon mounts
> `NoExecPaths=/var/spool/propolis/fetched` as defense in depth; preserve that
> posture when handling them. See
> [Malware custody](../security/malware-custody.md).
