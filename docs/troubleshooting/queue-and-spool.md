<!--
title: Troubleshooting - queue and spool
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
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
  (`crates/core-scoring/src/scoring/constants.rs:10`). So "event count rose but
  score did not" during rapid repeats is correct behavior, not a lost event.

### Counters to read

The console `/metrics` endpoint exposes process counters derived per scrape:

- `propolis_events_ingested_total` and `propolis_events_rejected_total` come from
  in-process atomics (`crates/console/src/routes/metrics.rs:177-188`). A rising
  `rejected` total during load is where dropped/invalid events surface.
- `propolis_review_queue_pending` gauges the review backlog.

`/metrics` is unauthenticated but only because the console binds loopback by
default. Scrape it locally:

```
curl -s localhost:8080/metrics | grep -E 'events_(ingested|rejected)_total|review_queue_pending'
```

Field ownership and the full metric list:
[Health and observability](../operations/health-and-observability.md).

## Log rotation can lose a small window of events

Sensor event logs (`events.jsonl`) rotate via logrotate with `copytruncate`
(`deploy/logrotate-sensors.conf`). `copytruncate` was chosen so the sensor's
append-only file descriptor keeps writing without a reopen, at the cost of a
small copy-to-truncate window in which events can be lost - a documented
trade-off, not a fault. Rotation is `size 100M`, `rotate 5`, size-based (not
calendar) specifically to bound a flood-driven disk-fill. If logs are rotating
constantly, the box is under sustained flood; that is the signal, not the log
config.

## Review queue: entries not appearing or not clearing

The review queue is populated/withdrawn by the `review` loop on
`PROPOLIS_QUEUE_SCAN_INTERVAL_SECS` (default 60s), so expect up to one scan
interval of lag.

- **Nothing surfaces** - `populate` only inserts `ip_score` rows where
  `recommended_for_vendor = TRUE AND eligible = TRUE`
  (`crates/review/src/queue.rs:74-91`). If a source never becomes eligible
  (eligibility needs a confirmed-real honeypot event and `event_count >= 2`),
  it never enters the queue. Eligibility and tier rules are owned by
  [Scoring and feed](../reference/scoring-and-feed.md).
- **A rejected/snoozed entry keeps its state** - Rejected and Snoozed rows
  persist so `populate` does not re-surface them (`queue.rs:129-148`). This is
  intentional; use approve/reject/snooze from the console, not a manual delete.
- **Review disabled** - `PROPOLIS_REVIEW_ENABLED=false` stops the loop entirely.

## Malware/sample spool filling up

Sensors that capture uploaded files spool them under `/var/spool/propolis/<name>`
and the in-daemon fetcher writes to `/var/spool/propolis/fetched`. Canonical
paths: [Filesystem paths](../reference/filesystem-paths.md).

- **Fetcher spool budget** - the fetcher enforces a hardcoded global budget of
  1 GB on `/var/spool/propolis/fetched` (`FETCH_SPOOL_GLOBAL_BUDGET`,
  `crates/propolis/src/main.rs:41,55`). At the budget it stops writing new
  fetched samples; this is a cap, not an error. It is not operator-configurable.
- **VirusTotal cleanup** - when VT scanning is enabled, `cleanup_old_samples`
  removes spool files older than 30 days each cycle
  (`crates/review/src/virustotal.rs:293-320`, wired at
  `crates/propolis/src/main.rs:781`). If VT is **disabled**, that cleanup does
  not run and captured samples accumulate until you prune them or logrotate/disk
  policy intervenes. Plan retention accordingly:
  [Retention](../operations/retention.md).
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
