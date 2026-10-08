<!--
title: Troubleshooting - intake backlog
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# A sensor shows its last event days ago

The fleet pane says a busy sensor's **Last event** was hours or days ago, and the sensor is
plainly still taking connections: its listener answers the probe, and its log under
`/var/log/propolis/<sensor>/` keeps growing. The sensor is fine. Intake is behind its log.

**Last event** is the newest event in the ledger, and an event reaches the ledger only when
intake reads its line, so while intake is behind, the column shows how far intake has read,
not when the sensor last saw traffic. The same backlog usually slows every other sensor too,
because all appends share one lock (see [why it happens](#why-it-happens)).

## What the console and the alerts show

- The listener row carries a badge under **Last event**, `behind: 6.6 GB / 11 d`: the unread
  bytes of the log and how long its oldest unread line has waited. It appears once the wait
  passes ten minutes or three intake polls, whichever is longer
  ([behind badge](../operations/health-and-observability.md#behind-badge)).
- `/metrics` carries the same two numbers per log, `propolis_intake_bytes_behind{sensor}` and
  `propolis_intake_oldest_unread_age_seconds{sensor}`, labelled with the `PROPOLIS_SENSOR_LOGS`
  name ([metrics](../operations/health-and-observability.md#metrics)):

  ```
  curl -s localhost:8080/metrics | grep '^propolis_intake_'
  ```

- With the ops monitor enabled, `intake-lagging` pages within minutes of a log starting to run
  away (its unread bytes rising at three consecutive monitor polls) or once lines have waited
  past the threshold for ten minutes. `intake-stalled` stays silent, by design: it fires only
  when intake stops, and a lagging intake keeps moving
  ([ops-alert monitor](../operations/health-and-observability.md#ops-alert-monitor-opt-in)).
- The journal shows that sensor's batches arriving full and slowly: `intake: batch processed`
  with `ingested=100` every minute or two, where a caught-up sensor shows small batches.

  ```
  journalctl -u propolis --since '1 hour ago' | grep 'batch processed' | grep 'sensor=telnet'
  ```

## Why it happens

Intake appends one event at a time, each in its own transaction under a single append lock
that keeps the hash chain in order (`crates/core-scoring/src/repository/events.rs#append_event`).
Whatever one append costs, every sensor waits for. Two costs used to grow without bound:

1. **The dedup read, while behind. Fixed by migration `0013`.** Each scored append looks up the
   newest prior event of the same source and signal. Before `event_dedup_idx` existed the
   database found it by walking the whole ledger backwards from the newest row, one row per
   event newer than that source's last sighting. An intake that is behind appends old events,
   so the walk grew with the lag and the lag grew with the walk. A telnet bot loop wrote about
   7.5 lines a second, intake managed about 0.8, and the log reached 6.6 GB over eleven days
   with every other sensor held up behind it. A daemon at or past migration `0013` has the
   index; to confirm it:

   ```
   psql "$DATABASE_URL" -c "SELECT indexname FROM pg_indexes WHERE indexname = 'event_dedup_idx'"
   ```

2. **The per-event history reads. Fixed by migration `0014`.** Each scored append also counts
   the distinct WAN vantages and sensors of its source. It used to read every earlier event of
   the source to do it, so a long-running bot loop on one address cost seconds per event whether
   or not intake was behind: 0.7 s at 100k events and 9 s at 1.5M on a test ledger. The counts
   now come from the `ip_vantage` and `ip_sensor` tables, a few rows per source, and the same
   appends take about 3 ms ([breadth sets](../reference/database.md#breadth-sets)). To confirm
   a daemon has them:

   ```
   psql "$DATABASE_URL" -c "SELECT to_regclass('ip_vantage'), to_regclass('ip_sensor')"
   ```

What is left is the per-event round trips and commit, one transaction per line, which holds the
node to a few hundred events a second in total
([limitations](../overview/limitations.md#intake-appends-one-event-per-transaction)). A sensor
whose log grows faster than that falls behind, and the badge and `intake-lagging` show it.

A log that is not rotated makes it worse but does not cause it: rotation caps the file size,
not the rate. If `/var/log/propolis/<sensor>/events.jsonl` is far past the 100 MB rotation size,
check that the distribution's logrotate timer is running (`systemctl status logrotate.timer`);
the installers install the policy (`/etc/logrotate.d/propolis-sensors`) but not the timer.

What keeps a bot loop from building the backlog in the first place is on the sensor side: ssh,
telnet and adb hold a per-source command-event budget, so past it a loader's repeated commands
become one summary event per source network per minute instead of one line each, while its new
commands, logins, connections, captures and downloads keep their own events
([a telnet or ssh bot loop floods the event log](queue-and-spool.md#a-telnet-or-ssh-bot-loop-floods-the-event-log)).
That cuts the rate a loop writes; it does not drain a backlog that already exists.

## Recovering a backlog too large to drain

If intake cannot catch up in a time you can accept, archive the backlog and truncate the log so
intake starts over at its end. Forcing the shipped rotation policy does exactly that:

```
sudo logrotate --force /etc/logrotate.d/propolis-sensors
```

The policy uses `copytruncate` (`deploy/logrotate-sensors.conf`): logrotate copies the log to
`events.jsonl.1` beside it (compressed at the next rotation) and truncates the original in
place. The tailer sees its offset past the end of the file and resumes from the start of the
now-empty file (`crates/log-tailer/src/cursor.rs#detect_rotation`), so lag falls to zero within a
poll and the badge, the metrics and the alert clear.

What this costs, stated plainly:

- **The unread lines never reach the ledger.** They are in the archive only, unscored and absent
  from every console view, the feed and vendor reports. Keep the archive.
- The archive also holds every line intake had already ingested from that file, so it is not
  the backlog alone.
- There is no re-import tool `[planned]`.

The same happens without anyone asking: a scheduled `copytruncate` rotation of a log intake is
behind on drops the unread part from ingest in the same way, and the lag metrics then read
small again because the new file is short. A badge or page that clears right after a rotation,
on a sensor that had been behind, is that.

## See also

- [Health and observability](../operations/health-and-observability.md) - the badge, the
  metrics and the `intake-lagging` condition.
- [Database reference](../reference/database.md) - `event_dedup_idx` (migration `0013`) and
  the breadth sets (migration `0014`).
- [Retention](../operations/retention.md) - the log rotation policy.
- [Queue and spool](queue-and-spool.md#a-telnet-or-ssh-bot-loop-floods-the-event-log) - the
  command-event budget that summarizes a bot loop's repeated commands.
