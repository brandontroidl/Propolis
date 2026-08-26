<!--
title: Troubleshooting
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Troubleshooting

Symptom-first index. Find the row that matches what you observe, then follow the
page link. Exact defaults, bounds, and failure behavior are owned by the
[reference section](../reference/environment-variables.md); these pages explain
symptoms and link there for values.

Most Propolis config is **fail-closed**: a required variable that is missing or
empty, or a numeric bound that is present-but-invalid or (usually) zero, aborts
startup rather than running degraded. So the single most common class of problem
is a service that exits immediately at boot with a logged reason. Start with
`journalctl -u <unit>` in every case.

## Symptom table

| Symptom | Likely cause | Page |
|---|---|---|
| `propolis`/sensor exits immediately at start | missing/invalid required env var (fail-fast) | [Startup and config](startup-and-config.md) |
| "invalid configuration; refusing to start" in log | bad numeric bound, missing `DATABASE_URL`/password | [Startup and config](startup-and-config.md) |
| Address already in use / bind error | port conflict on a sensor or console bind | [Startup and config](startup-and-config.md) |
| "failed to connect to PostgreSQL" at start | wrong `DATABASE_URL`, DB down, `pg_hba` | [Database](database.md) |
| "migrations failed" at start | schema drift, partial/edited migration, permissions | [Database](database.md) |
| `/ready` returns 503 | database ping failing (fail-closed readiness) | [Database](database.md) |
| Integrity page reports the chain broken | hash-chain verification failed over the `event` ledger | [Database](database.md) |
| Events being dropped under load | capture bounds hit, queue/spool pressure, disk | [Queue and spool](queue-and-spool.md) |
| Samples not appearing / spool filling | spool budget, disk, sensor not spooling | [Queue and spool](queue-and-spool.md) |
| Nothing captured on a protocol | sensor not started, bind address, firewall | [Sensors and networking](sensors-and-networking.md) |
| Port not listening | bind var unset/wrong, capability, conflict | [Sensors and networking](sensors-and-networking.md) |
| "Distinct WAN vantages" reads 0 / `wan_ip` null | `*_WAN_MAP` not mapping the bind address | [Sensors and networking](sensors-and-networking.md) |
| Cannot reach the console / login fails | bind is loopback-only, wrong password, rate-limited | [Console](console.md) |
| Logged out after every restart | in-memory sessions are dropped by design | [Console](console.md) |
| CSRF "invalid or missing csrf token" 403 | stale form after restart, missing token | [Console](console.md) |
| Fonts/styles look wrong offline | self-hosted font route or proxy stripping assets | [Console](console.md) |
| Console pages show empty states | no events yet, or supplementary query soft-failed | [Console](console.md) |
| VirusTotal not scanning / stops mid-day | not enabled, empty key, daily cap reached | [Integrations and feed](integrations-and-feed.md) |
| Vendor reports never sent / all held | vendor disabled, gate hold (stale/cooldown/rate) | [Integrations and feed](integrations-and-feed.md) |
| Malware fetcher does nothing | disabled by default, or refuses to run (own-IPs) | [Integrations and feed](integrations-and-feed.md) |
| Feed directory empty / no output | feed disabled, output dir, no eligible entries | [Integrations and feed](integrations-and-feed.md) |
| Public blocklist repo not updating | `blocklist-sync.sh` cron / SSH-agent (operator setup) | [Integrations and feed](integrations-and-feed.md) |
| Ops alerts never fire / daemon won't start | ops disabled, or enabled without ntfy URL/topic | [Integrations and feed](integrations-and-feed.md) |
| Restore/backup uncertainty | verifying the recovery path end-to-end | [Backup and recovery](backup-and-recovery.md) |

## Cross-cutting first checks

1. `systemctl status <unit>` and `journalctl -u <unit> -n 100` — the fail-fast
   reason is logged before exit.
2. `curl -s localhost:8080/ready` — distinguishes "process up" from "database
   reachable" (see [Database](database.md)).
3. `curl -s localhost:8080/health` — liveness only; always 200 if the process is
   serving at all.
4. Confirm which run mode is deployed: the unified `propolis` daemon or the
   standalone `intake`/`review`/`feed`/`console` set. The env surface differs
   (see [Environment variables](../reference/environment-variables.md)).
