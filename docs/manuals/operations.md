<!--
title: Operator manual
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Operator manual

A curated path through the operations corpus for the person running a Propolis node
day to day. It orders the canonical pages into a workflow and links to them; it does
not restate their values. Each linked page is the single owner of the facts it
carries.

Propolis is source-available and actively developed, with one tagged release
(`v0.1.0`); the current tree is `0.3.0`, untagged, and not production-certified. See
[maturity and status](../overview/maturity-and-status.md) before you depend on it.

## Mental model

One unified daemon (`propolis.service`) holds intake, review, feed, and console as
concurrent tasks over one PostgreSQL pool; nine sensor binaries run as separate,
unprivileged units and append NDJSON logs the daemon tails. PostgreSQL is the single
datastore. See [process topology](../architecture/process-topology.md) and
[storage](../architecture/storage.md).

## Service lifecycle

Start, stop, restart, ordering, the fail-fast startup sequence, and the in-place
upgrade path are owned by [service lifecycle](../operations/service-lifecycle.md).
Key points to internalize:

- The daemon fails fast (exit 1) on bad config, an unreachable DB, or a migration
  error rather than starting degraded - visible as an immediate exit in
  `journalctl`, not a silent partial run.
- The daemon uses `Restart=on-failure` (its in-process supervisor restarts panicked
  subsystems); sensors use `Restart=always`. A daemon process exit is therefore a
  fail-fast or a clean operator stop, not something to auto-restart into the same
  failure.
- `deploy/upgrade.sh` restarts live services and runs migrations - a maintenance-window
  action, gated on a verified backup.

## Health and observability

`/health` (liveness, never touches the DB), `/ready` (503 fail-closed when Postgres is
unreachable - use this to gate "is it actually serving"), and `/metrics` (Prometheus
text, derived live each scrape) plus logging, the in-console log viewer, the overload
counters, and the opt-in ntfy monitor are owned by
[health and observability](../operations/health-and-observability.md).

Watch, at minimum:

- `propolis_review_queue_pending` - so surfaced IPs do not accumulate undecided;
- `propolis_feed_last_build_timestamp` - the primary signal the feed loop is still
  publishing;
- the `dropped`/`spool-refused` journal WARNs - a rising count means the capture layer
  is shedding load under a flood (expected: covertness over completeness), not a crash.

`/metrics` is unauthenticated and safe only because the console is loopback-only; do not
expose it if you proxy the console.

## The review-and-publish loop

This is the core daily task. The full procedure - working the queue, the four review
states, and the two distinct feed-publish stages - is owned by
[routine procedures](../operations/routine-procedures.md). The gates in brief:

- Publication of any IP requires **all** of: an authenticated console session, the IP
  seen more than once, above the score floor, and an explicit human approval. There is
  no auto-publish path.
- **Stage 1** (in-process feed build) is automated by the daemon: it builds a snapshot
  from `ip_score` and writes it atomically to the feed directory each build interval; a
  failed build leaves the previous feed in place.
- **Stage 2** (publish to a public repository) is an operator cron step
  (`deploy/blocklist-sync.sh`), **not** wired into any shipped timer.

> **Stage 2 produces egress.** It `git push`es approved IPs to a public repository.
> Run it only when you intend the feed to be public, and confirm the push credential is
> available to cron (a headless deploy key). The egress posture is owned by
> [outbound controls](../security/outbound-controls.md).

Console routes, the CSRF model, and the queue mutations are owned by
[console routes](../reference/console-routes.md); the eligibility and tier gates by
[scoring and feed](../reference/scoring-and-feed.md).

## Retention

Feed retention windows and tier TTLs, the 30-day captured-sample cleanup, and event/
score storage are owned by [retention](../operations/retention.md). Two facts that bite
operators:

- The 30-day sample cleanup runs hourly in the daemon's always-on `sample-retention`
  subsystem, independent of VirusTotal; the global byte budget bounds a burst between
  passes.
- There is **no built-in pruning of the `event` table** - it grows with ingest and never
  self-truncates. Plan DB storage for sustained ingest; deletions break hash-chain
  continuity, so prune with that trade-off in mind.

## Capacity

Database connections, the bounded capture queue, per-sensor concurrency caps, spool
budgets, per-unit systemd resource ceilings, and what drives DB growth are owned by
[capacity planning](../operations/capacity-planning.md) and the
[rate limits and budgets](../reference/rate-limits-and-budgets.md) reference. Spool
sizing rule of thumb: plan `/var/spool/propolis` for roughly 1 GB (fetcher) + 100 MB per
spooling sensor, plus rotated logs under `/var/log/propolis`. Queue and spool overload
behavior is detailed in [queue and spool](../operations/queue-and-spool.md).

## Backup

Propolis ships **no backup or restore tool**. What holds durable state (PostgreSQL first,
then the spool directories and SSH host key, then `/etc/propolis/*.env` secrets), a
recommended procedure built from `pg_dump`/`tar`, the restore steps, and the verification
checklist are owned by [backup and restore](../operations/backup-and-restore.md).

> **Recovery is unverified until you restore from it.** A single-node deployment has no
> built-in redundancy - rehearse the restore end to end against a scratch environment
> and record the date and result.

## Routine procedures and config changes

- Working the queue, publishing, rotating secrets, and health checks:
  [routine procedures](../operations/routine-procedures.md).
- Secret handling (per-service `0600` env files, created by hand, never by `install.sh`):
  [secret management](../operations/secret-management.md).
- Configuration surface: [configuration](../operations/configuration.md); exact values in
  [environment variables](../reference/environment-variables.md).
- Networking and TLS (no in-process TLS; front with an operator-provided reverse proxy):
  [networking and TLS](../operations/networking-tls.md).
- Upgrade, rollback, and DR context: [upgrade, rollback and DR](../operations/upgrade-rollback-and-dr.md).
- Safe teardown (preserve or deliberately wipe evidence): [safe teardown](../getting-started/safe-teardown.md).

## When something is wrong

Start at [troubleshooting](../troubleshooting/index.md) (symptom-based). Before exposing a
node to hostile traffic, run the [hardening checklist](../security/hardening-checklist.md);
for the security responsibilities that stay with the operator, read the
[operator security manual](./security.md).
