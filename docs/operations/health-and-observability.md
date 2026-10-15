<!--
title: Health and observability
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-09
-->

# Health and observability

The health, readiness, and metrics endpoints; what the fleet pane's per-listener activity
counts; how the daemon logs; the drop and spool-refusal
counters an operator watches under load; and the opt-in ops-alert monitor. Route details are
owned by [console routes](../reference/console-routes.md); this page is the operational view.

## Endpoints

The console router exposes three public (no session) probe endpoints plus `/login` and the
font assets; every other route is session-gated (`crates/console/src/routes/mod.rs#router`).
The console binds loopback-only by default (`127.0.0.1:8080`); there is **no in-process TLS**
(plain HTTP on a `TcpListener`), so any TLS termination and any exposure beyond loopback is an
operator-provided reverse proxy. See [networking and TLS](./networking-tls.md).

| Endpoint | Purpose | Success | Failure | Cite |
|---|---|---|---|---|
| `GET /health` | Liveness only; does not touch the DB | `200 {"status":"ok"}` (always) | none | `crates/console/src/routes/health.rs#health` |
| `GET /ready` | Readiness; pings Postgres `SELECT 1`, then checks no supervised subsystem has given up (unified daemon only; the standalone console supervises nothing) | `200` | **`503 {"status":"unavailable"}`** on any DB error (fail-closed); **`503 {"status":"unavailable","gave_up":[...]}`** naming the dead subsystems | `crates/console/src/routes/health.rs#ready` |
| `GET /metrics` | Prometheus text (`version=0.0.4`) | `200` | derived live per scrape | `crates/console/src/routes/metrics.rs` |

Use `/health` for a liveness check that a process is up, and `/ready` for a
load-balancer/monitor readiness check that also proves the DB is reachable. `/metrics` carries
no session gate and, unless `PROPOLIS_CONSOLE_METRICS_TOKEN` is set, no bearer check; leaving it
open is acceptable only because the console is loopback-only
(`crates/console/src/routes/metrics.rs`, `crates/console/src/routes/metrics.rs#metrics`). If you proxy the console, do not expose `/metrics` publicly.

## Fleet pane: listener activity

The fleet pane (`/fleet`, session-gated) has one row per listener in the inventory
(`PROPOLIS_FLEET_LISTENERS`, see [environment variables](../reference/environment-variables.md)).
A listener is a sensor name, a transport and a port. Its **Last event** and **24h** columns count
the events whose `sensor`, `protocol` and `metadata.local_port` match it; `local_port` is
stamped on every event by the sensor framework (see
[events and signals](../reference/events-and-signals.md#arrival-metadata-key)). So HTTP's 80 and
443, two Redis ports, or the catch-all's TCP and UDP listeners on one port number each show
their own numbers (`crates/console/src/routes/fleet.rs#attribute`).

Both columns read bounded ranges of the ledger, never the whole of it, on every load and every
30-second refresh (`crates/console/src/routes/fleet.rs#listener_activity`):

| Column | Reads | Outside the range |
|---|---|---|
| 24h | events with `observed_at` in the last 24 hours | not counted |
| Last event | the newest event in the last 30 days (`crates/console/src/routes/fleet.rs#ACTIVITY_LOOKBACK`) | `none in 30d`, which is also what a listener that never produced an event shows: the pane cannot tell the two apart without reading the whole ledger, so it does not claim `never` |

The **Ledger** cell and the Evidence chain panel's **Events** row do not count the table either
(`crates/console/src/routes/fleet.rs#ledger_head`, `crates/console/src/routes/rowcount.rs#capped_total`).
Up to 100,000 events the number is a count and is shown bare. Past that it is the planner's row
estimate (`pg_class.reltuples`, refreshed by autovacuum), shown as `about N` with the label
`(estimate)`; it is never below the rows a count had already seen. The newest-ingest time is read
off the newest row by `id` rather than `max(ingested_at)`, which has no index and reads every row.
The Attackers page's total uses the same rule.

Events recorded before sensors stamped `local_port` have no port. A sensor whose inventory
declares exactly one listener received all of them there, so they count on that row. A sensor
with several declared listeners gets one extra row labelled `port not recorded` holding those
events, rather than a guess at which port they came in on. That row is not a listener: it is left
out of the listener total and the headline, its dots stay neutral, and it disappears once the
pre-upgrade history is older than 30 days.

A listener present in the ledger but not in the inventory gets an `undeclared listener` row with
its transport and port. A sensor the inventory does not name at all keeps one such row with no
port for its pre-upgrade events.

### Behind badge

**Last event** is the newest event in the ledger, so when intake is behind a sensor's log it
shows how far intake has read, not when the sensor last saw traffic. A listener row whose log is
behind says so under that column, as `behind: 6.6 GB / 11 d`: the unread bytes of the log and
how long its oldest unread line has waited (see the two intake metrics below). The badge appears
only while that wait exceeds the `intake-lagging` age threshold, ten minutes or three intake
polls, whichever is longer, so a caught-up or idle sensor shows nothing
(`crates/console/src/routes/fleet.rs#behind_by_sensor`). It is matched to rows by the sensor names
the log's events carried, not by the `PROPOLIS_SENSOR_LOGS` label (a `cred-vnc` log's events say
`vnc`), so a log that has not appended an event since the daemon started cannot badge a row yet.
It is the instantaneous reading; the ops alert below adds persistence and a growth rule. The
standalone `console` binary tails nothing and never shows it. What to do about it:
[intake backlog](../troubleshooting/intake-backlog.md).

## Metrics

`/metrics` derives everything from live DB queries plus the feed `manifest.json` on every
scrape; there are no pre-aggregated counters, so a scrape reflects current state
(`crates/console/src/routes/metrics.rs#metrics`). Emitted series (`crates/console/src/routes/metrics.rs#metrics`):

- Gauges: `propolis_ips_scored`, `propolis_ips_eligible`, `propolis_ips_recommended_vendor`,
  `propolis_ips_recommended_blocklist`, `propolis_review_queue_pending`, and the stored shell
  reply table's `propolis_shell_output_rows` (planner estimate) and `propolis_shell_output_bytes`
  (table plus indexes), read from the catalog so a scrape never reads the table
  ([retention](retention.md#stored-shell-replies)).
- Counter: `propolis_vendor_submissions_total{vendor,status}`.
- Malware pipeline (the work, not the process): `propolis_fetch_attempts{status}`,
  `propolis_fetch_pending_oldest_age_seconds`, `propolis_sample_analysis{state}`
  (`pending` = uploaded to VirusTotal, no verdict yet; `scanned`; `not_uploaded` = kept
  local because the content is not executable or script content),
  `propolis_sample_analysis_pending_oldest_age_seconds`, and, where the process can read
  the spools (the unified daemon, not the standalone console), `propolis_spool_samples{spool}`
  and `propolis_spool_oldest_sample_age_seconds{spool}`. An age gauge is `0` when nothing
  is waiting; a spool series is absent, not zero, when unreadable.
- Feed (from `manifest.json` when a feed dir is configured): `propolis_feed_entries{tier}`,
  `propolis_feed_window_entries{window}`, `propolis_feed_last_build_timestamp`.
- In-memory process counters: `propolis_events_ingested_total`, `propolis_events_rejected_total`,
  and `propolis_intake_lines_quarantined_total` (lines intake set aside in the quarantine
  directory, see [Quarantined intake lines](#quarantined-intake-lines); zero in the standalone
  console, which tails nothing).
- Intake backlog, one series per intake log, labelled `sensor` with its `PROPOLIS_SENSOR_LOGS`
  name, from what each intake loop recorded after its latest poll (unified daemon only; the
  standalone console tails nothing and publishes neither, rather than a zero that would claim a
  caught-up log; `crates/console/src/routes/metrics.rs#push_intake_lag`):
  - `propolis_intake_bytes_behind{sensor}` - unread bytes of the log: the file past the read
    offset, plus the remainder of any rotated-out file still being drained, plus an unfinished
    last line (`crates/log-tailer/src/tailer.rs#backlog_bytes`). Absent until the log's first
    poll finishes.
  - `propolis_intake_oldest_unread_age_seconds{sensor}` - how long the oldest unread line has
    waited. `0` when the latest poll read every complete line. While complete lines are waiting,
    now minus the `observed_at` of the last event appended from the log, which bounds the wait
    of the next unread line. Absent while lines wait and no event has been appended since the
    daemon started, because there is nothing to measure from
    (`crates/propolis/src/ops_alert/conditions/intake_lag.rs#oldest_unread_age`).

  There is no append-latency histogram: the metrics endpoint emits gauges and counters only.
- Sensor capture health, one series per capturing sensor, labelled `sensor`, from the latest
  `sensor_stats` line each wrote (see [Sensor stats](#sensor-stats); absent for a sensor that
  never reported, never a zero; `crates/console/src/routes/metrics.rs#push_sensor_stats`):
  counters `propolis_sensor_capture_queue_dropped_total`,
  `propolis_sensor_capture_spool_refused_total`, `propolis_sensor_capture_truncated_total`,
  `propolis_sensor_capture_refused_total`, `propolis_sensor_capture_budget_refused_total`;
  gauges `propolis_sensor_capture_budget_bytes`,
  `propolis_sensor_capture_budget_high_water_bytes`, `propolis_sensor_uptime_seconds`; and the
  freshness trio `propolis_sensor_stats_age_seconds`, `propolis_sensor_stats_stale` (1 past 180 s)
  and `propolis_sensor_stats_final` (1 when the last line was the sensor's shutdown line). The
  counters count since the sensor started and reset when it restarts.
- Console saturation counters, each moving only when a bound refused work (a steady rate
  means a login spray or a connection flood, not ordinary use):
  `propolis_console_login_refused_per_ip_total`, `propolis_console_login_refused_global_total`,
  `propolis_console_login_verify_busy_total`, `propolis_console_connections_shed_total`,
  `propolis_console_body_timeouts_total`. Limits: [rate limits and
  budgets](../reference/rate-limits-and-budgets.md#console-connection-bounds).

`propolis_feed_last_build_timestamp` is the primary signal that the feed loop is still
publishing; see [retention](./retention.md) and [scoring and feed
reference](../reference/scoring-and-feed.md).

### Sensor stats

Each capturing sensor (ssh, telnet, adb, ftp, mqtt, tftp) appends a `sensor_stats` line to its
own event log every 60 s and a last one, with `final` true, when it shuts down. The line carries
the capture hand-off counters and the capture-memory budget that used to be readable only inside
the process; intake stores the latest per sensor, and `/metrics` publishes them (above).

- **Staleness, not zeros.** A sensor that stops writing keeps its last values and its age grows;
  `propolis_sensor_stats_stale` turns 1 after 180 s (three missed lines). `propolis_sensor_stats_final`
  says whether the last line was a clean shutdown, which separates a stop from silence. Age is
  measured from the sensor's own clock, so a stalled shipper or intake shows as stale too.
- **Not evidence.** The line is not in the ledger and not an event: its `source_ip` is the sentinel
  `0.0.0.0`, intake stores it in the `sensor_stats` table instead of converting it, and nothing
  that scores, feeds or reports reads that table.
- **Refused lines.** A `sensor_stats` line from any other source, with extra or missing fields,
  with a value past 2^53, or naming a sensor other than the log's `PROPOLIS_SENSOR_LOGS` label is
  counted as a rejected line with a WARN `malformed sensor_stats line, refused` (or `names a
  different sensor than this log's label`) and is not stored. The label rule means a sensor whose
  log label differs from its event name (the cred sensors, which have no capture hand-off and
  write no stats) would have its stats refused.
- **Nothing to configure.** The interval is a constant
  (`crates/sensor-framework/src/handoff.rs#STATS_INTERVAL`).

## Logging

The daemon and sensors log through `tracing` to the systemd journal; read with
`journalctl -u propolis` (see [service lifecycle](./service-lifecycle.md)). Sensors also
append captured events as NDJSON to per-sensor log files under `/var/log/propolis/`, rotated
by logrotate (`size 100M`, `rotate 5`, `copytruncate`; `deploy/logrotate-sensors.conf`), run
hourly by `propolis-logrotate.timer` ([retention](./retention.md#log-rotation)). Paths are owned by [filesystem paths](../reference/filesystem-paths.md).

The console has a session-gated live log viewer at `/logs`, backed by an in-memory ring of the
**1000** most recent tracing events (`crates/propolis/src/main.rs#LOG_BUFFER_CAPACITY`,
`crates/console/src/log_buffer.rs#LogBuffer`), fewer when they are large: the ring is also held
to 2 MiB charged from the entries' allocated size
(`crates/console/src/log_buffer.rs#RING_BYTE_BUDGET`). Each entry keeps its structured fields,
capped at 512 bytes a value, 32 fields and a 2 KiB message
(`crates/console/src/log_buffer.rs#MAX_FIELD_VALUE_BYTES`,
`crates/console/src/log_buffer.rs#MAX_FIELDS`, `crates/console/src/log_buffer.rs#MAX_MESSAGE_BYTES`).
It is a convenience tail, not a durable log store; the journal and the NDJSON files are
authoritative.

For a live view of the NDJSON files themselves, every event as the sensor wrote it plus a
10-second heartbeat naming each configured log as `following`, `missing` or `unreadable`, run
the read-only `propolis-watch`, locally or over a forced-command SSH key; see
[live watch](./live-watch.md).

### Logging and journal priorities

Every binary installs one output format, the `log-format` crate
(`crates/log-format/src/lib.rs#init`, `crates/log-format/src/lib.rs#layer`), so the journal
carries the real level of each line and plain text:

| `tracing` level | journal `PRIORITY` | `journalctl -p` name |
|---|---|---|
| `ERROR` | 3 | `err` |
| `WARN` | 4 | `warning` |
| `INFO` | 6 | `info` |
| `DEBUG`, `TRACE` | 7 | `debug` |

`journalctl -u 'sensor-*' -u propolis -p warning` therefore lists the warnings and errors, and any
alert keyed on journal priority sees them. Before this, every line was priority 6 with ANSI colour
escapes in the message, so a priority filter matched nothing.

The mechanism is the `<N>` line prefix of sd-daemon(3). Under a service, systemd connects stdout
to the journal and journald strips a leading `<N>` into the entry's priority unless the unit sets
`SyslogLevelPrefix=false` (default on; systemd.exec(5)). No unit in `deploy/` turns it off; with it
off the prefix would show as text at the start of each message. The prefix is written only when
`$JOURNAL_STREAM` names this process's own stdout (device and inode, as systemd.exec(5)
prescribes), so a process whose stdout was redirected to a file or pipe, or one that merely
inherited the variable, writes plain lines (`crates/log-format/src/lib.rs#is_journal_stream`).

- **Terminal:** unchanged, the stock coloured format. `NO_COLOR` set to a non-empty value turns the
  colour off.
- **File or pipe:** the same text with no colour and no prefix.
- **Journal:** the same text with the prefix and no colour.

Off a terminal each event is also one line: control characters in a message or field value, a
newline above all, are written as `\n`, `\u{1b}` and so on. The stock formatter leaves a newline in
message text alone, and journald reads a priority prefix at the start of every line, so a captured
attacker string containing a newline and `<0>` would otherwise forge an emergency entry
(`crates/log-format/tests/format.rs#journal_mode_cannot_be_made_to_forge_a_priority_line`).
A line is also cut at 16 KiB with a `...[truncated N bytes]` marker, because journald splits a
line that reaches `LineMax` (48K by default, journald.conf(5)) and reads a priority prefix again
at the start of the tail
(`crates/log-format/tests/process.rs#a_field_past_journald_line_max_stays_one_capped_line`).

The timestamp the format prints stays, although journald stamps each entry itself, so the text is
identical whether it was read from the journal or from a captured stdout. Entries journaled before
the upgrade keep priority 6.

### Overload counters

Two capture-hand-off counters, surfaced as journal WARNs, tell an operator that samples are
being lost under load. Both are covered operationally in [queue and
spool](./queue-and-spool.md); in summary:

- **Dropped (queue full).** When the bounded capture queue is full, `submit` drops the job
  rather than blocking, increments `dropped_count`, and logs a WARN at **power-of-two totals**
  (first drop, then 2, 4, 8, ...) so a sustained flood degrades to logarithmic noise instead of
  filling the log partition (`crates/sensor-framework/src/handoff.rs#submit`).
- **Spool-refused.** A body the spool rejects (per-file cap or exhausted global budget)
  increments `spool_refused_count` and logs a WARN at power-of-two totals. No sample results, but
  the upload event is still emitted, marked `stored: false` with a `not_stored_reason`
  (`crates/sensor-framework/src/handoff.rs#process_job`).

A rising drop or spool-refused count means the capture layer is shedding load; it is expected
behavior under a flood (covertness over completeness), not a crash. Separately, the ops-alert
monitor's capacity condition watches free space on the spool volume (`CAPACITY_FREE_PCT`), a
related but distinct signal from these counters.

### Runtime scheduling lag

sqlx reports a statement's elapsed time as everything between the task issuing it and the task
being polled with the answer. If the daemon's async runtime has no free worker for a while, a
trivial statement (`COMMIT`, a primary-key lookup) logs one or two seconds with the database
idle. The daemon therefore runs a small probe (`crates/propolis/src/runtime_lag.rs`) that sleeps
100 ms at a time and measures how much later than that it was polled. When the lag passes 250 ms
it logs one WARN, at most one per 10 s. A stall that lands inside the 10 s window is held back and
logged by the first wake-up after the window (or at shutdown), so the line carries the worst lag
since the last line and how many wake-ups were late. It also carries the runtime's worker count and
queued-task depth, and the process cgroup's growth over the same window:

```text
WARN runtime: the async runtime was slow to poll a ready task; ...  worst_lag_ms=1840 late_wakeups=7
workers=4 queued_tasks=12 cgroup_visible=true cgroup_nr_throttled=0 cgroup_throttled_ms=0
cgroup_mem_high=0 cgroup_mem_max=0 cgroup_mem_oom=0
```

Reading it: lag alone does not name the cause, because three different things freeze task polling
and look the same to the probe:

| Lag with | Cause | Fix |
|---|---|---|
| all `cgroup_*` deltas zero | workers held in synchronous code (or a host-level stall) | move the step off the workers (`cpu_budget` below) |
| `cgroup_nr_throttled` / `cgroup_throttled_ms` above zero | the unit's `CPUQuota=` ran out; every thread was frozen, whatever it was doing | raise `CPUQuota=` or cut the load; moving work to another thread does not help |
| `cgroup_mem_max` / `cgroup_mem_high` above zero | direct reclaim at `MemoryMax=` | raise `MemoryMax=` or cut memory use |

`cgroup_visible=false` means the process is not under a readable cgroup v2 hierarchy, so the
deltas are not available and read zero. Slow statements **with** this warning in the same window
are the process, not the database; slow statements **without** it point at the database (check
`log_min_duration_statement`, `log_lock_waits` and `log_checkpoints` on the server). The probe is a
measurement, not a subsystem: it is not in `/ready` or the monitor's subsystem conditions, and its
failure restarts nothing. With several workers, a single blocked worker is visible only when the
probe's wake-up lands on it, so a quiet probe does not prove that no step ever ran long.

The steps that run synchronously inside async tasks are timed by an example that needs no
database and no network, on inputs at the limits the daemon enforces (a 1 MiB log line, an 8 MiB
intake batch, a 16 MiB captured body, a 20,000-file spool):

```text
cargo run --release --example cpu_budget -p propolis
```

It marks every step over 10 ms that still runs on an async worker. Measured in a release build
on the development machine (a shared 28-core host; the quietest of several runs is shown, and a
busy run was up to five times slower, 464 ms against 85 ms for the spool walk, so run it on the
box that matters), the steps over 10 ms were:

| Step | Worst-case input | Median | Now |
|---|---|---|---|
| Digest of a fetched body | 16 MiB | 142 ms | off the worker |
| Spool write of a fetched body (hash, write, fsync) | 16 MiB | 242 ms (fsync outliers 950 ms) | off the worker |
| Feed publish (render, write, fsync) | 5,000 / 50,000 entries | 167 ms / 905 ms | off the worker |
| Ledger chain hash of one intake batch | 8 MiB | 77 ms | off the worker |
| Intake tailer read of one batch | 8 MiB, warm cache | 13 ms | off the worker |
| Ops-monitor spool walk | 20,000 files | 85 ms | off the worker |
| Campaign indexer: shape, indicators, tags of one command | 64 KiB / 1 MiB line | 16 ms / 60 ms | off the worker above 16 KiB (sensors cap a line at 1 KiB: 0.4 ms) |
| `redact_secrets` | 1 MiB of `authorization: ` | 8,185 ms | linear (a few ms) |
| Console IP detail: build, group and render one evidence page | 200 events, 64 KiB body each (about 27 MB of HTML) | 225 ms (1 KiB bodies: 5 ms) | off the worker |
| Console feed Entries tab: read, parse, render one load | 5,000 / 50,000 entries | 19 ms / 165 ms | off the worker |

Everything else measured, including the ATT&CK tagger (bounded to 4 KiB of shell and 8 KiB of SQL
per line, under 0.3 ms), indicator extraction at its 64 KiB cap, dropper URL extraction (2 ms at
64 KiB), JSON parsing of a full batch (3 ms) and the upload type filter, stayed under 10 ms. The
captured-artifact scan (65-107 ms for a 16 MiB binary) already ran under `spawn_blocking`. A step
moved "off the worker" runs under `core_scoring::off_worker`, which hands the rest of that
worker's queue to another thread for the duration.

## Ops-alert monitor (opt-in)

The daemon can run an internal monitor that pages via [ntfy](https://ntfy.sh) when the system
degrades. It is **off by default** and is one of the platform's operator-gated egress paths
(see [outbound controls](../security/outbound-controls.md)). It is distinct from the Guardian
host-compromise monitor and should use a separate topic
(`docs/archive/2026-08-26/root/INSTALL.md#Environment variable reference`; the live `INSTALL.md` is now a redirect
stub).

> **Warning - outbound egress.** Enabling the ops-alert monitor makes the daemon POST to your
> configured ntfy server. That is the only network egress this feature performs, and it is off
> until you set `PROPOLIS_OPS_ENABLED=true`.

Configuration is **fail-closed only on a half-configured target**: when
`PROPOLIS_OPS_ENABLED=true`, setting exactly one of `PROPOLIS_OPS_NTFY_URL` /
`PROPOLIS_OPS_NTFY_TOPIC` makes the daemon refuse to start, because a target that looks
configured but cannot page is worse than a loud config error; leaving both unset is
accepted and falls back to alerting through the local log sink instead of ntfy
(`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`). Exact defaults and bounds for every
`PROPOLIS_OPS_*` var are owned by [environment
variables](../reference/environment-variables.md); the monitor watches (defaults):

- spool free space below `CAPACITY_FREE_PCT` (15%);
- an intake/feed stall for `STALL_FOR_SECS` (600 s), and feed staleness at
  `FEED_STALE_MULTIPLE` (2x) the build interval - both for the local publish
  (`feed-stale`) and for the public repo falling that far behind the local feed
  (`feed-push-stale`, read from the marker `/var/lib/propolis/blocklist-status/last-pushed`
  that `deploy/blocklist-sync.sh` rewrites after each successful push; a box that has never pushed is paged only when
  `FEED_PUSH_EXPECTED` is set, and then only after the same threshold has elapsed
  since the daemon started, since without the flag the monitor cannot tell a broken
  cron from no cron and a fresh deployment must not page before its first cron run);
- an intake falling behind its log (`intake-lagging`, Warning). `intake-stalled` fires only when
  a sensor's cursor stops moving with input waiting. When the database refused the same line on
  three consecutive polls, its detail quotes `intake wedged at <sensor>` with that event's
  `observed_at` and the SQLSTATE: one line the ledger will not accept (for example a NUL
  character in a command, which `jsonb` cannot store). Intake sets such a line aside and moves
  past it in that same poll ([`intake-line-quarantined`](#quarantined-intake-lines) below), so
  `intake-stalled` quoting a wedge means the line could NOT be quarantined: the quoted text ends
  with the reason (the quarantine directory is not writable, or it is full), and intake stays on
  the line, skipping nothing, until that is fixed. An intake that keeps moving but more slowly
  than its sensor writes never trips it, and that is how a telnet log once grew to 6.6 GB over
  eleven days unnoticed. `intake-lagging` reads the two intake metrics above and fires when
  either rule holds for a log
  (`crates/propolis/src/ops_alert/conditions/intake_lag.rs#IntakeLagging`):
  - **age**: its oldest unread line has waited longer than ten minutes or three intake polls
    (`PROPOLIS_POLL_INTERVAL_MS`), whichever is longer, continuously for ten minutes;
  - **growth**: its unread bytes rose at each of three consecutive monitor polls, each of which
    found complete lines waiting. This fires within minutes of a log starting to run away.

  The page names each log with its backlog, as `telnet (6.6 GB / 11 d)`. It clears when the log
  is read to the end, or when the wait is back under the threshold and the backlog has not grown
  for three consecutive polls, so a backlog hovering at the edge does not page and recover in
  turn. An idle log never fires: with nothing unread there is no wait and no growth, and an
  unfinished last line neither ages nor grows. The thresholds are fixed, not `PROPOLIS_OPS_*`
  variables. While a log has not finished its first poll the condition reads it as unknown, not
  healthy, and the monitor's own stale-probe warning covers a log that never reports;
- sensor logs outgrowing rotation (`sensor-log-oversized`; Warning, Critical when the disk
  half holds). It fires, after a two-minute hold, when any log in `PROPOLIS_SENSOR_LOGS` is more
  than three times the rotation size, or when the filesystem under `/var/log/propolis` is more
  than 85% used (`df`'s Use%)
  (`crates/propolis/src/ops_alert/conditions/sensor_log.rs#SensorLogOversized`). The rotation
  size is the `size` line of `/etc/logrotate.d/propolis-sensors`, read on each poll, so
  300 MiB with the shipped `100M`; if the file is unreadable or has no `size` line the daemon
  assumes 100 MiB. A log that does not exist yet is not oversized. Once firing it clears only
  when every log is back under twice the rotation size and the disk at or under 80% used, so a
  log hovering at the line does not page and recover in turn. This is the alert that would have
  caught the October 2026 incident, where the distribution's rotation timer stopped and a telnet
  log reached 6.6 GB; `capacity` watches the cursor and spool volumes, which are the log volume
  only when they share a filesystem, and `intake-lagging` watches an intake that falls behind,
  not a log that grows. The page names each log with
  its size; recovery is [a log too large to rotate](./retention.md#a-log-too-large-to-rotate).
  On a control-plane box tailing a collector's gateway spool file, which no policy rotates
  ([split deployment](./split-deployment.md#disk-space)), a spool past 300 MiB fires it too;
  that is the spool growing, not rotation failing;
- log rotation not running (`rotation-stale`, Warning): the logrotate state file
  `/var/lib/propolis/logrotate.state` has not been rewritten for more than three hours
  (`crates/propolis/src/ops_alert/conditions/sensor_log.rs#RotationStale`).
  `propolis-logrotate.service` rewrites it on every hourly run, whether or not a log was due, so
  its modification time is the last run. The daemon does not ask systemd whether the timer is
  active; a file that stops moving is a timer that stopped firing. It clears on the next run. A
  node where the file does not exist yet (the timer never ran) reads as unknown, not firing, and
  the monitor's stale-probe warning raises it after half an hour. A run in which the guard refuses
  a log (for free space, or because intake has not read it) still rewrites the file, so that case
  surfaces as `sensor-log-oversized` and a failed unit, not as this alert
  (`crates/sensor-framework/tests/deploy_test.rs#a_log_skipped_for_unread_input_still_refreshes_the_state_file_and_fails_the_run`). The thresholds of both are fixed, not `PROPOLIS_OPS_*` variables;
- a rotation that took unread input (`intake-rotation-loss`, Warning;
  `crates/propolis/src/ops_alert/conditions/intake.rs#IntakeRotationLoss`). When a `copytruncate`
  rotation lands while a log is unread, the tailer reads the rest from `<log>.1`
  ([concurrency and failure](../architecture/concurrency-and-failure.md#log-rotation-under-a-reader-that-is-behind)).
  This pages, immediately, when it could not: `.1` was missing, only `.1.gz` existed, or `.1` was
  not the old content, so the unread lines are gone. The page names each log with the number of
  such rotations and a lower bound on the bytes lost (`at least 0 bytes` when the tailer had not
  yet polled the old content, as after a restart). It holds for one hour after the last loss and
  then recovers by itself, since a loss does not clear; the journal WARN `a copytruncate rotation
  discarded input that was never read` is the permanent record, and the counts reset when the
  daemon restarts. A rotation that finds the reader caught up and no `.1` is silent: the lines
  written between the copy and the truncate are the accepted loss. A truncation you made by hand
  while intake was behind also raises it. The hold is fixed, not a `PROPOLIS_OPS_*` variable;
- a log line quarantined (`intake-line-quarantined`, Warning): intake set aside a line the
  database refused on three polls in a row and moved past it, so a real sensor line is not in
  the ledger. It fires on the next monitor poll with no hold, naming the sensor, the line's byte
  offset, the SQLSTATE and the quarantine file, and clears (with a recovered notice) once
  `REPAGE_COOLDOWN_SECS` has passed with no further quarantine, so one line pages once and a
  second line inside that window extends it
  (`crates/propolis/src/ops_alert/conditions/intake_quarantine.rs#IntakeLineQuarantined`). What
  to do: [Quarantined intake lines](#quarantined-intake-lines);
- vendor submission failure rate over `VENDOR_FAIL_PCT` (50%) within `VENDOR_WINDOW_SECS`
  (3600 s), gated by `VENDOR_MIN_SAMPLES` (20);
- review backlog over `BACKLOG_MAX` (500) held for `BACKLOG_FOR_SECS` (900 s);
- malware work stalled: a spooled body unscanned or a VirusTotal upload unverdicted for
  `SCAN_STALE_SECS` (6 h; `scan-stale`, only with VirusTotal enabled), or a fetch url
  pending for `FETCH_STALE_SECS` (1 h; `fetch-stale`, only with the fetcher enabled) -
  the fetcher retires a url after three attempts, so an old pending row means it is not
  attempting;
- periodic hash-chain verification every `CHAIN_VERIFY_INTERVAL_SECS` (6 h). The whole-ledger
  scan runs as a task of its own and the monitor serves its last verdict, so a scan that takes
  minutes never holds up the other conditions or the heartbeat
  (`crates/propolis/src/ops_alert/conditions/chain.rs#ChainVerify`); before the first scan
  finishes the condition reads as unknown;
- no good backup (`backup-stale`, Warning): the newest set the
  [nightly backup](backup-and-restore.md#the-nightly-backup) wrote is older than
  `BACKUP_MAX_AGE_SECS` (36 h), so one failed night pages before a second is missed; the page
  names the last set and the step the last failed run stopped at. With no good backup yet it fires
  once the status directory is older than the limit, or at once if a run has already failed
  (`crates/propolis/src/ops_alert/conditions/backup.rs#BackupStale`);
- re-page suppression `REPAGE_COOLDOWN_SECS` (5400 s); poll `POLL_INTERVAL_SECS` (30 s).

`PROPOLIS_OPS_NTFY_TOKEN` is an optional bearer token for a protected topic. See
[integrations](../reference/integrations.md) and [troubleshooting: integrations and
feed](../troubleshooting/integrations-and-feed.md).

### Unreadable probes and undeliverable alerts

Two failures used to be silent; neither is now.

**A probe that cannot read its source does not clear an alert.** A condition whose query or
file read fails reports unknown, which is neither firing nor healthy
(`crates/propolis/src/ops_alert/debounce.rs#Signal::Unknown`). Unknown holds the condition
exactly where it was: it never pages, never re-pages, never cancels or restarts a debounce in
progress, and in particular never sends a `[recovered]` notice for an incident that is still
open. Only a reading that says healthy recovers an incident, once. A probe that stays unknown
for 30 minutes raises its own `probe-stale` warning, and when an earlier page for that condition
is still open the warning says so ("an earlier page for it is still open: it cannot be confirmed
cleared until the probe reads again"). It recovers, with the incident's own notice if the
condition is now clear, on the first reading that works
(`crates/propolis/src/ops_alert/monitor.rs#Monitor::process_tick`). The threshold is fixed.

**A failed delivery is retried and reported.** The dispatcher makes four attempts per alert
(0.2 s, 0.4 s, 0.8 s apart). An alert that still fails is no longer dropped after one journal
line: it is queued and retried at the end of later monitor ticks, 30 s after the failure and
then at doubling intervals up to 15 minutes. A tick's retry pass stops at its first failure (the
other queued alerts share the transport that just failed), makes at most four attempts and is cut
off after 20 s in all; an alert cut off that way backs off like any failure
(`crates/propolis/src/ops_alert/undelivered.rs`, `monitor.rs#RETRY_PASS_BUDGET`). The newest state per condition wins, so a
`[recovered]` notice replaces a queued page that never went out. The queue holds 64 alerts; a
full queue drops the oldest with a WARN. What to look for in the journal
(`journalctl -u propolis`):

| Message | Level | Meaning |
|---|---|---|
| `ops-alert: delivery failed; will retry` | ERROR | the first delivery of an alert failed; it is queued |
| `ops-alert: retry failed; will retry again` | WARN | a queued alert failed again; carries `attempts` and `error` |
| `ops-alert: delivered after earlier failures` | INFO | a queued alert finally went out |
| `ops-alert: an alert was never delivered before the previous run ended` | WARN | at startup, one per alert the previous run left queued |

The queue is written to `ops-alert-undelivered.json` in `PROPOLIS_CURSOR_DIR` (key, title,
severity, when it first failed, attempts, last error; never the alert body). If the daemon stops
with alerts queued, the next run logs the WARN above for each and sends one summary alert,
"propolis: alerts were not delivered", listing each with its age, attempt count and the failure;
the summary is itself queued and persisted until it is delivered. With only the local log sink
(`PROPOLIS_OPS_NTFY_URL` unset) delivery cannot fail and the file is never written.

The dead-man's switch is independent of all of this. Retries run after the heartbeat in each
tick and are capped at 20 s per tick, so a dead ntfy server cannot suppress the ping and delays
the next round (its ping included) by at most that long, and the ping is not conditional on
alerts having been delivered. Each ntfy attempt has its own 30 s deadline and the heartbeat
request 15 s. A page raised in the same tick as an outage is not covered by the retry cap: its
dispatch can wait about two minutes per alert (four attempts of 30 s) before it is queued, so a
round in which many conditions newly fire against a hung host is slow; that is the cost of
trying to deliver a new page at once. That a `ping` stops arriving is still how the service on
the other end learns the daemon is down.

### When the daemon or the host is down

The monitor runs inside the daemon, so it cannot report the daemon's own death, nor the host's.
Two pieces cover that:

- **The failure hook.** Every Propolis unit (the daemon, each sensor, the gateway, the shipper,
  the backup and log rotation) names `OnFailure=propolis-alert@%n.service`. When a unit enters
  the failed state, systemd runs `/usr/local/sbin/propolis-alert` (`deploy/alert.sh`), which
  posts "`<unit>` failed on `<host>`" with the unit's last journal lines to the same ntfy topic,
  read from `propolis.env`, or writes it to the journal at err priority when there is none or the
  post fails. A unit with `Restart=` passes through the failed state on every crash, so the hook
  sends at most one alert per unit per 30 minutes. It does not need `PROPOLIS_OPS_ENABLED`.
- **The heartbeat.** Set `PROPOLIS_OPS_HEARTBEAT_URL` to a dead-man's switch check: a service
  that alerts you when it stops hearing from you, such as a healthchecks.io check or one you run
  elsewhere. The monitor requests the URL after every complete evaluation round, at most every
  `HEARTBEAT_INTERVAL_SECS` (300 s); set the check's period to that and its grace to a few
  minutes. When the pings stop, because the daemon is down, the monitor is stuck in a probe, or
  the host or its network is gone, the service raises the alarm. The URL is a secret: it must be
  `https://` and is never logged. Like ntfy, this is outbound egress you opt into.

`deploy/config-check.sh` reports, under `alerting`, a monitor that is off, alerts that go only to
the journal, no heartbeat and a missing failure hook, under `backup` and `clock` the backup
state and whether the clock is NTP-synchronized, and under `env-files` an env file whose mode
lets another account read it.

### Quarantined intake lines

The ledger can refuse a line for a reason of the line itself: a NUL character in a captured
command (`jsonb` cannot store it, SQLSTATE `22P05`), a value out of range, a constraint
violation. Retrying never helps, and before this existed such a line held its sensor's intake
at that line until an operator removed it from the log. Now, when the database has refused the
same line on three polls in a row (`WEDGE_POLLS`) with an error that belongs to the line
(SQLSTATE class 22 or 23, a failed validation, a stored-state decode failure; never a lost
connection or a timeout), intake:

1. appends one JSON record to `/var/lib/propolis/quarantine/<sensor-label>.jsonl`
   (`PROPOLIS_QUARANTINE_DIR`; the label is the `PROPOLIS_SENSOR_LOGS` name, with anything
   outside letters, digits, `_` and `-` replaced by `_`) and fsyncs it;
2. only then moves its read position past exactly that line and saves the cursor
   (`crates/intake/src/runner.rs#quarantine_line`). The position moves by the line lengths
   recorded when the batch was read, never by reading again, so a `copytruncate` landing at that
   moment cannot make it step over a line of the new file;
3. logs `intake: line quarantined` at WARN, increments the `propolis_intake_lines_quarantined_total`
   counter on `/metrics` (process lifetime, all logs), and raises `intake-line-quarantined`.

If step 1 fails (the disk is full, the directory is not writable) intake does NOT skip: it stays
on the line, `intake-stalled` quotes the write error, and the next poll tries again, so fixing
the directory unsticks it without a restart. The store is bounded at 64 MiB and 10,000 records
across all its files (`crates/intake/src/quarantine.rs#MAX_QUARANTINE_BYTES`,
`crates/intake/src/quarantine.rs#MAX_QUARANTINE_RECORDS`); at the cap nothing more is quarantined
and the next refused line wedges intake as above, with the cap in the alert text. The standalone
`intake` binary does the same but has no ops monitor, so there the WARN log line is the only
signal.

Each record is one line of JSON:

| Field | Meaning |
|---|---|
| `quarantined_at` | UTC time the line was set aside |
| `sensor` | the `PROPOLIS_SENSOR_LOGS` label |
| `log_path` | the log it was read from |
| `byte_offset` | offset of the line's first byte in the file it was read from (the rotated-out file if rotation had already moved the log) |
| `line_sha256` | SHA-256 of the line's exact bytes, newline excluded |
| `sqlstate` | the database's SQLSTATE, or `null` when the refusal was not a database error |
| `error` | the error text, flattened to one line and capped at 512 characters |
| `line_encoding` | `utf8`, or `base64` when the line is not valid UTF-8 (the bytes are kept exactly) |
| `line_truncated` | true when the line passed the tailer's 1 MiB line cap and `line` holds only its first MiB |
| `line` | the line, in `line_encoding` |

To look at them (the directory is `0750 propolis`):

```sh
sudo -u propolis tail -n 5 /var/lib/propolis/quarantine/telnet.jsonl
sudo -u propolis jq -r '[.quarantined_at, .sqlstate, .byte_offset] | @tsv' /var/lib/propolis/quarantine/*.jsonl
```

The skipped event is not in the ledger and nothing re-reads it. To ingest it after all, correct
whatever the database refused (for the NUL case, delete the `\u0000` escape from the line text),
check the result is still one valid sensor event, and append it as one more line, with its
newline, to that sensor's log as the sensor's own user or root; intake reads it as a new line and
the event keeps its original `observed_at`. Editing a captured value is the operator's decision,
and a line quarantined as `base64` has to be decoded first (`jq -r .line | base64 -d`). Records
are never removed by Propolis: see [retention](./retention.md#quarantined-intake-lines).
