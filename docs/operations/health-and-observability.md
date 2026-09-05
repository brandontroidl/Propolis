<!--
title: Health and observability
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Health and observability

The health, readiness, and metrics endpoints; how the daemon logs; the drop and spool-refusal
counters an operator watches under load; and the opt-in ops-alert monitor. Route details are
owned by [console routes](../reference/console-routes.md); this page is the operational view.

## Endpoints

The console router exposes three public (no session) probe endpoints plus `/login` and the
font assets; every other route is session-gated (`crates/console/src/routes/mod.rs:33-57`).
The console binds loopback-only by default (`127.0.0.1:8080`); there is **no in-process TLS**
(plain HTTP on a `TcpListener`), so any TLS termination and any exposure beyond loopback is an
operator-provided reverse proxy. See [networking and TLS](./networking-tls.md).

| Endpoint | Purpose | Success | Failure | Cite |
|---|---|---|---|---|
| `GET /health` | Liveness only; does not touch the DB | `200 {"status":"ok"}` (always) | none | `crates/console/src/routes/health.rs:14-24` |
| `GET /ready` | Readiness; pings Postgres `SELECT 1`, then checks no supervised subsystem has given up (unified daemon only; the standalone console supervises nothing) | `200` | **`503 {"status":"unavailable"}`** on any DB error (fail-closed); **`503 {"status":"unavailable","gave_up":[...]}`** naming the dead subsystems | `health.rs` `ready` |
| `GET /metrics` | Prometheus text (`version=0.0.4`) | `200` | derived live per scrape | `crates/console/src/routes/metrics.rs:1-11` |

Use `/health` for a liveness check that a process is up, and `/ready` for a
load-balancer/monitor readiness check that also proves the DB is reachable. `/metrics` is
unauthenticated; that is acceptable only because the console is loopback-only
(`metrics.rs:8-11`). If you proxy the console, do not expose `/metrics` publicly.

## Metrics

`/metrics` derives everything from live DB queries plus the feed `manifest.json` on every
scrape; there are no pre-aggregated counters, so a scrape reflects current state
(`metrics.rs:43,190-198`). Emitted series (`metrics.rs:46-188`):

- Gauges: `propolis_ips_scored`, `propolis_ips_eligible`, `propolis_ips_recommended_vendor`,
  `propolis_ips_recommended_blocklist`, `propolis_review_queue_pending`.
- Counter: `propolis_vendor_submissions_total{vendor,status}`.
- Feed (from `manifest.json` when a feed dir is configured): `propolis_feed_entries{tier}`,
  `propolis_feed_window_entries{window}`, `propolis_feed_last_build_timestamp`.
- In-memory process counters: `propolis_events_ingested_total`, `propolis_events_rejected_total`.

`propolis_feed_last_build_timestamp` is the primary signal that the feed loop is still
publishing; see [retention](./retention.md) and [scoring and feed
reference](../reference/scoring-and-feed.md).

## Logging

The daemon and sensors log through `tracing` to the systemd journal; read with
`journalctl -u propolis` (see [service lifecycle](./service-lifecycle.md)). Sensors also
append captured events as NDJSON to per-sensor log files under `/var/log/propolis/`, rotated
by logrotate (`size 100M`, `rotate 5`, `copytruncate`; `deploy/logrotate-sensors.conf`).
Paths are owned by [filesystem paths](../reference/filesystem-paths.md).

The console has a session-gated live log viewer at `/logs`, backed by an in-memory ring of the
**1000** most recent tracing events (`LOG_BUFFER_CAPACITY`, `crates/propolis/src/main.rs:165`,
`routes/mod.rs:43`). It is a convenience tail, not a durable log store; the journal and the
NDJSON files are authoritative.

### Overload counters

Two capture-hand-off counters, surfaced as journal WARNs, tell an operator that samples are
being lost under load. Both are covered operationally in [queue and
spool](./queue-and-spool.md); in summary:

- **Dropped (queue full).** When the bounded capture queue is full, `submit` drops the job
  rather than blocking, increments `dropped_count`, and logs a WARN at **power-of-two totals**
  (first drop, then 2, 4, 8, ...) so a sustained flood degrades to logarithmic noise instead of
  filling the log partition (`crates/sensor-framework/src/handoff.rs:125-148`).
- **Spool-refused.** A body the spool rejects (per-file cap or exhausted global budget)
  increments `spool_refused_count` and logs a per-refusal WARN; no sample and no event result
  (`handoff.rs:150-216`).

A rising drop or spool-refused count means the capture layer is shedding load; it is expected
behavior under a flood (covertness over completeness), not a crash. Separately, the ops-alert
monitor's capacity condition watches free space on the spool volume (`CAPACITY_FREE_PCT`), a
related but distinct signal from these counters.

## Ops-alert monitor (opt-in)

The daemon can run an internal monitor that pages via [ntfy](https://ntfy.sh) when the system
degrades. It is **off by default** and is one of the platform's operator-gated egress paths
(see [outbound controls](../security/outbound-controls.md)). It is distinct from the Guardian
host-compromise monitor and should use a separate topic (`INSTALL.md:502-533`).

> **Warning - outbound egress.** Enabling the ops-alert monitor makes the daemon POST to your
> configured ntfy server. That is the only network egress this feature performs, and it is off
> until you set `PROPOLIS_OPS_ENABLED=true`.

Configuration is **fail-closed**: when `PROPOLIS_OPS_ENABLED=true`, both
`PROPOLIS_OPS_NTFY_URL` and `PROPOLIS_OPS_NTFY_TOPIC` become required and the daemon refuses to
start without them, because a monitor that cannot page is worse than a loud config error
(`crates/propolis/src/ops_alert/config.rs:119-134`). Exact defaults and bounds for every
`PROPOLIS_OPS_*` var are owned by [environment
variables](../reference/environment-variables.md); the monitor watches (defaults):

- spool free space below `CAPACITY_FREE_PCT` (15%);
- an intake/feed stall for `STALL_FOR_SECS` (600 s), and feed staleness at
  `FEED_STALE_MULTIPLE` (2x) the build interval - both for the local publish
  (`feed-stale`) and for the public repo falling that far behind the local feed
  (`feed-push-stale`, read from the marker `deploy/blocklist-sync.sh` touches after
  each successful push; a box that never syncs is never paged);
- vendor submission failure rate over `VENDOR_FAIL_PCT` (50%) within `VENDOR_WINDOW_SECS`
  (3600 s), gated by `VENDOR_MIN_SAMPLES` (20);
- review backlog over `BACKLOG_MAX` (500) held for `BACKLOG_FOR_SECS` (900 s);
- periodic hash-chain verification every `CHAIN_VERIFY_INTERVAL_SECS` (6 h);
- re-page suppression `REPAGE_COOLDOWN_SECS` (5400 s); poll `POLL_INTERVAL_SECS` (30 s).

`PROPOLIS_OPS_NTFY_TOKEN` is an optional bearer token for a protected topic. See
[integrations](../reference/integrations.md) and [troubleshooting: integrations and
feed](../troubleshooting/integrations-and-feed.md).
