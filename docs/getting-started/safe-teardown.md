<!--
title: Safe teardown
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Safe teardown

How to stop Propolis, close its listeners, and either keep or deliberately destroy the
evidence it captured. Read the whole page before the destructive steps; captured
evidence cannot be recovered after it is wiped unless you took a backup first.

## 1. Stop the listeners first

Stop the sensors before the daemon, so nothing new arrives while you work.

```bash
sudo systemctl stop sensor-ssh sensor-telnet sensor-cred   # every sensor you enabled
sudo systemctl stop propolis.service
```

The daemon shuts down gracefully on `SIGTERM`: it cancels its subsystems, waits up to
30 seconds for in-flight work, then exits and closes the database pool. Ctrl-C does the
same for an evaluation run.

## 2. Keep them stopped

The sensor units restart on failure and at boot, so `stop` alone is not enough:

```bash
sudo systemctl disable --now sensor-ssh sensor-telnet sensor-cred
sudo systemctl disable --now propolis.service
```

Confirm nothing is still listening on the sensor ports before you treat the host as
quiet.

## 3. Decide what happens to the evidence

Propolis holds evidence in three places:

| Evidence | Where |
|---|---|
| Event ledger and scores | PostgreSQL: `event`, `ip_score`, `review_queue` and the other tables |
| Captured samples | `/var/spool/propolis/<sensor>/` and `/var/spool/propolis/fetched/`; live malware |
| Sensor and daemon logs | `/var/log/propolis/<sensor>/events.jsonl` |

**To keep it**, take a backup and restore it somewhere to prove it worked before you
touch anything, following [backup and restore](../operations/backup-and-restore.md).
The ledger's hash chain lets you show later that what you kept was not altered: run the
Integrity check in the console before the backup and again after the restore.

**To wipe it**, there is no undo. Check you have the backup you meant to keep and that
you are on the right host and database, then:

```bash
sudo rm -rf /var/spool/propolis/*/     # samples: live malware, handle in isolation
sudo rm -rf /var/log/propolis/*/       # sensor logs
dropdb propolis                        # or truncate event, ip_score, review_queue
```

For an evaluation, `podman rm -f propolis-pg` and `rm -rf /tmp/propolis-eval` remove
everything.

## 4. Uninstall

There is no uninstaller. Reverse `install.sh` by hand: the unit files in
`/etc/systemd/system/`, the binaries in `/usr/local/bin/`, the `propolis*` system users,
and the `/etc/propolis`, `/var/lib/propolis`, `/var/log/propolis` and
`/var/spool/propolis` trees.

## The published feed

If you published a blocklist, the last published copy stays in that repository until
you remove it. That is a separate decision from tearing down the node; a stale public
feed keeps blocking addresses you are no longer watching.
