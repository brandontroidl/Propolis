<!--
title: Safe Teardown
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Safe teardown

How to stop Propolis, remove its listeners, and either preserve or deliberately wipe the
captured evidence. Read the whole page before running the destructive steps - captured
evidence cannot be recovered once wiped unless you took a backup first.

## 1. Stop the listeners first

Stop the sensors before the daemon so no new events arrive mid-teardown.

```bash
# EXAMPLE - systemd deployment
sudo systemctl stop sensor-ssh sensor-telnet sensor-cred ...   # every sensor you enabled
sudo systemctl stop propolis.service
```

A `SIGTERM`/`SIGINT` triggers a graceful shutdown: the daemon cancels all subsystems,
waits up to a 30s `SHUTDOWN_TIMEOUT` for in-flight work, then force-exits and closes the
pool (`crates/propolis/src/main.rs:160,480-507`). For a local evaluation run, Ctrl-C on
each process does the same. Service lifecycle detail is owned by
[service lifecycle](../operations/service-lifecycle.md).

## 2. Remove the listeners (permanent stop)

To stop the sensors from restarting on boot:

```bash
# EXAMPLE
sudo systemctl disable --now sensor-ssh sensor-telnet sensor-cred ...
sudo systemctl disable --now propolis.service
```

The sensor units use `Restart=always` (`deploy/sensor-ssh.service`), so `stop` alone is
not enough to keep them down across a reboot - `disable` is required. This closes the
attacker-facing ports; confirm nothing is still listening before considering the box
quiet.

## 3. Decide: preserve or wipe evidence

Propolis holds captured evidence in three places. Decide what to keep **before** removing
anything.

| Evidence | Location | Notes |
|---|---|---|
| Event ledger + score projection | PostgreSQL (`event`, `ip_score`, `review_queue`, ...) | Append-only, hash-chained `event` ledger; owned by [reference/database.md](../reference/database.md) |
| Captured samples | `/var/spool/propolis/{ssh,adb,ftp,telnet,catchall,fetched}` | Live payloads - may be malware |
| Sensor + daemon logs | `/var/log/propolis/<sensor>/events.jsonl` | Rotated by logrotate; paths owned by [reference/filesystem-paths.md](../reference/filesystem-paths.md) |

### To preserve

Take (and verify) a backup before touching anything - follow
[backup and restore](../operations/backup-and-restore.md). A backup you have never
restored is not a recovery path. The hash-chained ledger lets you prove the preserved
evidence was not altered; verify it via the console's `/integrity` page or
`core_scoring::verify_chain` (`crates/console/src/routes/integrity.rs:36-66`).

### To wipe

> [!WARNING]
> The following destroys captured evidence permanently. There is no undo. Confirm you
> have any backup you intend to keep, and that you are on the correct host and database,
> before running these.

Samples (live malware - handle in an isolated environment; see
[malware custody](../security/malware-custody.md)):

```bash
# EXAMPLE - destructive: removes all captured samples
sudo rm -rf /var/spool/propolis/*/    # per-sensor spool subdirs
```

Logs:

```bash
# EXAMPLE - destructive: removes captured sensor logs
sudo rm -rf /var/log/propolis/*/
```

Database - drop the whole database, or truncate the capture tables. Owned by
[reference/database.md](../reference/database.md); do this only against the correct
`DATABASE_URL` target:

```bash
# EXAMPLE - destructive: drop the entire Propolis database
dropdb propolis    # or: psql "$DATABASE_URL" -c 'TRUNCATE event, ip_score, review_queue CASCADE;'
```

For a disposable evaluation database:

```bash
podman rm -f propolis-pg
```

## 4. Full uninstall (optional)

Removing binaries, units, users, and directories laid down by `deploy/install.sh` is a
separate step beyond stopping services. `install.sh` does not ship an uninstaller; reverse
its steps manually (units in `/etc/systemd/system/`, binaries in `/usr/local/bin/`, the
`propolis*` system users, and the `/etc/propolis`, `/var/lib/propolis`, `/var/log/propolis`,
`/var/spool/propolis` trees). Owner: [installation](../operations/installation.md).

## Public feed

If you published a blocklist, decide whether to leave the last-published feed in place or
retract it - that is a change to the external repo, independent of tearing down the node.
See the feed-repo item in the
[production-readiness checklist](production-readiness-checklist.md).
