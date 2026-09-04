<!--
title: Service lifecycle
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Service lifecycle

How the systemd units start, stop, and restart, and in what order. This page describes
lifecycle mechanics only; exact env vars, ports, and paths are owned by the
[reference section](../reference/environment-variables.md).

## Production surface

Production runs **one unified daemon plus nine sensor binaries**, all as systemd units
installed by `deploy/install.sh`:

- `propolis.service` runs `/usr/local/bin/propolis`, a single process holding the
  intake, review, feed, and console subsystems as concurrent tasks over one shared
  PostgreSQL pool (`deploy/propolis.service:110-115`,
  `crates/propolis/src/main.rs:1-5`).
- `sensor-<name>.service` for `catchall, ssh, telnet, redis, adb, http, ftp, smtp, cred`,
  each running its own binary as its own system user (`deploy/install.sh:198`,
  `deploy/sensor-ssh.service`).

The standalone `intake.service`, `review.service`, `feed.service`, and `console.service`
units also exist in the repo but are **superseded by `propolis.service` in production and
are not installed by `install.sh`** (`deploy/install.sh:14-17`). They remain for dev and
testing only; do not enable them alongside the unified daemon.

See [process topology](../architecture/process-topology.md) for what runs inside the
daemon and [deployment models](./deployment-models.md) for single-node vs cluster.

## Start and enable

Configuration and secrets must exist first (`install.sh` never writes any
`/etc/propolis/*.env` file, and never starts, enables, or migrates anything). See
[configuration](./configuration.md) and [secret management](./secret-management.md).

Once every service has its `/etc/propolis/*.env`:

```sh
# Example - enable and start every unit
sudo systemctl enable --now propolis.service
sudo systemctl enable --now sensor-catchall sensor-ssh sensor-telnet sensor-redis \
  sensor-adb sensor-http sensor-ftp sensor-smtp sensor-cred
```

`enable --now` both starts the unit and sets it to start at boot. Source:
`INSTALL.md:332-346`. Runnable commands are collected in
[commands reference](../reference/commands.md).

Ordering: `propolis.service` declares `After=network.target postgresql.service`
(`deploy/propolis.service:108`), so systemd starts it after the database. Sensors carry no
dependency on the daemon; they append to local log files and the daemon tails those logs,
so start order between sensors and daemon does not matter for correctness.

## Status and logs

```sh
# Example
systemctl status propolis sensor-ssh
journalctl -u propolis -u sensor-ssh -f
```

Source: `INSTALL.md:350-362`. For health and readiness endpoints, the in-console log
viewer, and metrics, see [health and observability](./health-and-observability.md).

## Startup sequence (daemon)

`propolis` fails fast (`std::process::exit(1)`) at any of these steps rather than starting
degraded (`crates/propolis/src/main.rs:511-577`):

1. init tracing;
2. `load_config()` - exit 1 on any missing-required or malformed-bound value;
3. connect the PgPool at `PROPOLIS_DB_MAX_CONNECTIONS` - exit 1 if the DB is unreachable;
4. run embedded migrations (core-scoring, then `review::migrator()`) - exit 1 on failure;
5. `create_dir_all(cursor_dir)` - exit 1 on failure;
6. spawn subsystems.

Migrations run at startup from within the binary (`sqlx::migrate!`); there is no separate
migrate step (`main.rs:554-565`, confirmed `install.sh:22-24`). A config, DB, or migration
error is therefore visible as an immediate exit in `journalctl`, not a silent partial run.
See [troubleshooting: startup and config](../troubleshooting/startup-and-config.md).

## Stop and graceful shutdown

Stopping a unit sends SIGTERM (SIGINT on Ctrl-C); the daemon treats both as a clean
shutdown request (`crates/propolis/src/main.rs:160`, `:480-507`, `:1063-1089`):

1. cancel all subsystems;
2. await their task handles, bounded by a **30 s `SHUTDOWN_TIMEOUT`**
   (`main.rs:160`), then force-exit if any handle has not finished;
3. `pool.close()`.

A clean stop exits 0.

## Restart policy

The two unit families restart differently on purpose:

| Unit | `Restart=` | `RestartSec=` | Cite |
|---|---|---|---|
| `propolis.service` | `on-failure` | 5 s | `deploy/propolis.service:123-124` |
| `sensor-*.service` | `always` | 10 s | `deploy/sensor-ssh.service`, `deploy/sensor-*.service` |

The daemon uses `on-failure`, **not** `Restart=always`, because its in-process supervisor
(`crates/propolis/src/supervisor.rs`) restarts a panicked subsystem with backoff without
the process exiting. A process exit is therefore only a fail-fast (bad config, DB
unreachable, migration failure) or an operator-requested clean stop, and neither should be
auto-restarted into the same failure (`deploy/propolis.service:116-122`). Sensors are
independent listeners with no such internal supervisor, so they use `always`. Failure
modes are covered in [concurrency and failure](../architecture/concurrency-and-failure.md).

## Live upgrade

`deploy/upgrade.sh` (run as root, `sudo ./deploy/upgrade.sh`) performs an in-place upgrade:
it rebuilds as the repo-owning user, reinstalls the binaries, runs `provision.sh`, reinstalls
the unit files and logrotate config, runs `daemon-reload`, restarts each **sensor** unit that
is enabled, then restarts `propolis.service` so sensors reconnect and migrations run against
the new schema (`deploy/upgrade.sh`). See
[upgrade, rollback, and DR](./upgrade-rollback-and-dr.md).

> **Warning - production impact.** `upgrade.sh` restarts live services and runs migrations.
> Run it during a maintenance window and confirm a working backup first (see
> [backup and restore](./backup-and-restore.md)).
