<!--
title: Health and observability
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
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
  `propolis_ips_recommended_blocklist`, `propolis_review_queue_pending`.
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
- In-memory process counters: `propolis_events_ingested_total`, `propolis_events_rejected_total`.
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
- Console saturation counters, each moving only when a bound refused work (a steady rate
  means a login spray or a connection flood, not ordinary use):
  `propolis_console_login_refused_per_ip_total`, `propolis_console_login_refused_global_total`,
  `propolis_console_login_verify_busy_total`, `propolis_console_connections_shed_total`,
  `propolis_console_body_timeouts_total`. Limits: [rate limits and
  budgets](../reference/rate-limits-and-budgets.md#console-connection-bounds).

`propolis_feed_last_build_timestamp` is the primary signal that the feed loop is still
publishing; see [retention](./retention.md) and [scoring and feed
reference](../reference/scoring-and-feed.md).

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

### Overload counters

Two capture-hand-off counters, surfaced as journal WARNs, tell an operator that samples are
being lost under load. Both are covered operationally in [queue and
spool](./queue-and-spool.md); in summary:

- **Dropped (queue full).** When the bounded capture queue is full, `submit` drops the job
  rather than blocking, increments `dropped_count`, and logs a WARN at **power-of-two totals**
  (first drop, then 2, 4, 8, ...) so a sustained flood degrades to logarithmic noise instead of
  filling the log partition (`crates/sensor-framework/src/handoff.rs#submit`).
- **Spool-refused.** A body the spool rejects (per-file cap or exhausted global budget)
  increments `spool_refused_count` and logs a per-refusal WARN; no sample and no event result
  (`crates/sensor-framework/src/handoff.rs#process_job`).

A rising drop or spool-refused count means the capture layer is shedding load; it is expected
behavior under a flood (covertness over completeness), not a crash. Separately, the ops-alert
monitor's capacity condition watches free space on the spool volume (`CAPACITY_FREE_PCT`), a
related but distinct signal from these counters.

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
  (`feed-push-stale`, read from the marker `deploy/blocklist-sync.sh` touches after
  each successful push; a box that has never pushed is paged only when
  `FEED_PUSH_EXPECTED` is set, and then only after the same threshold has elapsed
  since the daemon started, since without the flag the monitor cannot tell a broken
  cron from no cron and a fresh deployment must not page before its first cron run);
- an intake falling behind its log (`intake-lagging`, Warning). `intake-stalled` fires only when
  a sensor's cursor stops moving with input waiting. When the database refused the same line on
  three consecutive polls, its detail quotes `intake wedged at <sensor>` with that event's
  `observed_at` and the SQLSTATE: one line the ledger will not accept (for example a NUL
  character in a command, which `jsonb` cannot store) is holding that sensor, and intake does
  not skip or quarantine it, so the line has to be removed from the log by the operator. An
  intake that keeps moving but more slowly
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
  the monitor's stale-probe warning raises it after half an hour. A run that the free-space guard
  refuses still rewrites the file, so that case surfaces as `sensor-log-oversized` and a failed
  unit, not as this alert. The thresholds of both are fixed, not `PROPOLIS_OPS_*` variables;
- vendor submission failure rate over `VENDOR_FAIL_PCT` (50%) within `VENDOR_WINDOW_SECS`
  (3600 s), gated by `VENDOR_MIN_SAMPLES` (20);
- review backlog over `BACKLOG_MAX` (500) held for `BACKLOG_FOR_SECS` (900 s);
- malware work stalled: a spooled body unscanned or a VirusTotal upload unverdicted for
  `SCAN_STALE_SECS` (6 h; `scan-stale`, only with VirusTotal enabled), or a fetch url
  pending for `FETCH_STALE_SECS` (1 h; `fetch-stale`, only with the fetcher enabled) -
  the fetcher retires a url after three attempts, so an old pending row means it is not
  attempting;
- periodic hash-chain verification every `CHAIN_VERIFY_INTERVAL_SECS` (6 h);
- re-page suppression `REPAGE_COOLDOWN_SECS` (5400 s); poll `POLL_INTERVAL_SECS` (30 s).

`PROPOLIS_OPS_NTFY_TOKEN` is an optional bearer token for a protected topic. See
[integrations](../reference/integrations.md) and [troubleshooting: integrations and
feed](../troubleshooting/integrations-and-feed.md).
