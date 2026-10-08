<!--
title: Service lifecycle
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Service lifecycle

How the systemd units start, stop, and restart, and in what order. This page describes
lifecycle mechanics only; exact env vars, ports, and paths are owned by the
[reference section](../reference/environment-variables.md).

## Production surface

Production runs **one unified daemon plus twelve sensor binaries**, all as systemd units
installed by `deploy/install.sh`:

- `propolis.service` runs `/usr/local/bin/propolis`, a single process holding the
  intake, review, feed, and console subsystems as concurrent tasks over one shared
  PostgreSQL pool (`deploy/propolis.service#Description=Propolis unified daemon`,
  `deploy/propolis.service#ExecStart=/usr/local/bin/propolis`,
  `crates/propolis/src/main.rs`).
- `sensor-<name>.service` for `catchall, ssh, telnet, redis, adb, http, ftp, smtp, tftp, mqtt, dns, cred`,
  each running its own binary as its own system user, created by `deploy/install.sh`'s
  delegation to `deploy/provision.sh` (`deploy/provision.sh#ensure_user`,
  `deploy/sensor-ssh.service#User=propolis-ssh`).

The standalone `intake.service`, `review.service`, `feed.service`, and `console.service`
units also exist in the repo but are **superseded by `propolis.service` in production and
are not installed by `install.sh`** (`deploy/install.sh#deliberately NOT installed here`). They remain for dev and
testing only; do not enable them alongside the unified daemon.

See [process topology](../architecture/process-topology.md) for what runs inside the
daemon and [deployment models](./deployment-models.md) for single-node vs cluster.

## Start and enable

Configuration and secrets must exist first (`install.sh` never writes any
operator-owned `/etc/propolis/*.env` file - it only generates the secret-free
`fleet-listeners.env` - and never starts, enables, or migrates anything). See
[configuration](./configuration.md) and [secret management](./secret-management.md).

Once every service has its `/etc/propolis/*.env`:

```sh
# Example - enable and start every unit
sudo systemctl enable --now propolis.service
sudo systemctl enable --now sensor-catchall sensor-ssh sensor-telnet sensor-redis \
  sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred
```

`sensor-tftp`, `sensor-mqtt` and `sensor-dns` are the sensors that are safe to leave out of that
command: each is off until its env file (`/etc/propolis/tftp.env`, `/etc/propolis/mqtt.env`,
`/etc/propolis/dns.env`) sets `PROPOLIS_TFTP_BIND`, `PROPOLIS_MQTT_BIND` or
`PROPOLIS_DNS_BIND`, and without a bind it exits instead of listening. Enable `sensor-tftp` only
on a host where inbound UDP/69 is meant to be open, `sensor-mqtt` only where inbound TCP/1883 is
(and TCP/8883, if `PROPOLIS_MQTT_TLS_BIND` is set), and `sensor-dns` only where inbound UDP and
TCP/53 are (and TCP/853, if `PROPOLIS_DNS_TLS_BIND` is set).

The TLS listeners (HTTPS 443, Redis 6380, MQTTS 8883, SMTPS 465, submission 587, FTPS 990, DNS
over TLS 853) are
off until their `*_TLS_BIND` (or `PROPOLIS_SMTP_SUBMISSION_BIND`) variable is set, so starting a
sensor never opens one implicitly; sensor-cred's TLS runs on its existing ports. A sensor with a
bad TLS setting exits 1 at start with `refusing to start`. See
[networking-tls.md](networking-tls.md#sensor-tls-attacker-facing-listeners) for the variables
and the failure modes.

### Enabling one sensor later

Forwarding a port on the router only delivers packets to the host; nothing answers, and the
fleet pane shows nothing, until the sensor is configured, running, and known to the daemon. To
add one sensor to a running node (sensor-tftp as the example):

1. Set its bind in its env file, for example `PROPOLIS_TFTP_BIND=0.0.0.0:69` in
   `/etc/propolis/tftp.env`. Without a bind the sensor exits instead of listening.
2. Start it and keep it across reboots: `sudo systemctl enable --now sensor-tftp`, then check
   `systemctl status sensor-tftp` shows it running and its journal has a `listening` line.
3. Make sure the daemon tails its event log: `PROPOLIS_SENSOR_LOGS` in
   `/etc/propolis/propolis.env` must list `tftp:/var/log/propolis/tftp/events.jsonl`. A
   `propolis.env` written before that sensor existed will not have it (compare with
   `deploy/propolis.env.example#PROPOLIS_SENSOR_LOGS`).
4. Regenerate the fleet listener inventory and restart the daemon so the fleet pane lists the
   new listener: `sudo deploy/fleet-listeners.sh && sudo systemctl restart propolis`. The pane
   only knows the listeners derived from the `*_BIND` variables at that moment
   (`deploy/fleet-listeners.sh`); `upgrade.sh` reruns it for you on the next upgrade.
5. Open the port where it is reachable from outside: on the router, forward the right protocol
   (UDP for sensor-tftp, both UDP and TCP on 53 for sensor-dns, TCP for the rest), and allow
   it in any host firewall. sensor-tftp also answers each transfer from its own ephemeral UDP port, so a host
   firewall must allow those replies.

A UDP listener's reachability always reads `unknown` in the fleet pane: a connect probe cannot
prove a UDP port is answering, so the pane judges it by events arriving instead
(`crates/fleet/src/probe.rs#UDP_NOT_PROBEABLE`).

`enable --now` both starts the unit and sets it to start at boot. Source:
`docs/archive/2026-08-26/root/INSTALL.md#6. Start services` (the live `INSTALL.md` is now a redirect
stub). Runnable commands are collected in
[commands reference](../reference/commands.md).

Ordering: `propolis.service` declares `After=network.target postgresql.service`
(`deploy/propolis.service#After=network.target postgresql.service`), so systemd starts it after the database. Sensors carry no
dependency on the daemon; they append to local log files and the daemon tails those logs,
so start order between sensors and daemon does not matter for correctness.

## Status and logs

```sh
# Example
systemctl status propolis sensor-ssh
journalctl -u propolis -u sensor-ssh -f
```

Source: `docs/archive/2026-08-26/root/INSTALL.md#7. Verify`. For health and readiness endpoints, the in-console log
viewer, and metrics, see [health and observability](./health-and-observability.md).

## Startup sequence (daemon)

`propolis` fails fast (`std::process::exit(1)`) at any of these steps rather than starting
degraded (`crates/propolis/src/main.rs#main`):

1. init tracing;
2. `load_config()` - exit 1 on any missing-required or malformed-bound value;
3. connect the PgPool at `PROPOLIS_DB_MAX_CONNECTIONS` - exit 1 if the DB is unreachable;
4. run embedded migrations (core-scoring, then `review::migrator()`) - exit 1 on failure;
5. `create_dir_all(cursor_dir)` - exit 1 on failure;
6. spawn subsystems.

Migrations run at startup from within the binary (`sqlx::migrate!`); there is no separate
migrate step (`crates/propolis/src/main.rs#main`, confirmed `deploy/install.sh#runs its own migrations`). A config, DB, or migration
error is therefore visible as an immediate exit in `journalctl`, not a silent partial run.
See [troubleshooting: startup and config](../troubleshooting/startup-and-config.md).

## Stop and graceful shutdown

Stopping a unit sends SIGTERM (SIGINT on Ctrl-C); the daemon treats both as a clean
shutdown request (`crates/propolis/src/main.rs#SHUTDOWN_TIMEOUT`, `crates/propolis/src/main.rs#shutdown_signal`, `crates/propolis/src/main.rs#main`):

1. cancel all subsystems;
2. await their task handles concurrently (`crates/propolis/src/main.rs#drain_subsystems`), bounded by a **30 s
   `SHUTDOWN_TIMEOUT`** (`crates/propolis/src/main.rs#SHUTDOWN_TIMEOUT`);
3. **abort** any subsystem still running after that and give it up to **2 s** to unwind
   (`crates/propolis/src/main.rs#ABORT_WAIT`). Aborting a supervised subsystem also aborts the task
   underneath it (`crates/propolis/src/supervisor.rs#spawn_supervised`), so its pooled database
   connection is released;
4. `pool.close()`, bounded by **5 s** (`crates/propolis/src/main.rs#POOL_CLOSE_TIMEOUT`); if it times out the
   daemon logs a warning and exits with connections open.

The stop is therefore bounded at **37 s** in the worst case (30 + 2 + 5,
`crates/propolis/src/main.rs#WORST_CASE_STOP`), well inside systemd's default 90 s stop timeout; the unit
sets no `TimeoutStopSec`, so that default applies. A build-time assertion keeps the sum under it.
A normal stop finishes as soon as every subsystem has returned, usually in well under a second.

When a subsystem had to be aborted, the journal names it in one warning:

```
propolis: shutdown timed out waiting for: <name>[, <name>...]; aborted
```

The names are the subsystem names used in the supervisor's own log lines (a sensor's configured
name, `listener-probe`, `review`, `feed`, `virustotal`, `sample-retention`, `campaigns`, `fetcher`,
`console`, `ops-monitor`). Per-subsystem completion is logged at debug. A clean stop exits 0.

## Restart policy

The two unit families restart differently on purpose:

| Unit | `Restart=` | `RestartSec=` | Cite |
|---|---|---|---|
| `propolis.service` | `on-failure` | 5 s | `deploy/propolis.service#Restart=on-failure` |
| `sensor-*.service` | `always` | 10 s | `deploy/sensor-ssh.service`, `deploy/sensor-*.service` |

The daemon uses `on-failure`, **not** `Restart=always`, because its in-process supervisor
(`crates/propolis/src/supervisor.rs`) restarts a panicked subsystem with backoff without
the process exiting. A process exit is therefore only a fail-fast (bad config, DB
unreachable, migration failure) or an operator-requested clean stop, and neither should be
auto-restarted into the same failure (`deploy/propolis.service#Unlike the retired units' Restart=always`). Sensors are
independent listeners with no such internal supervisor, so they use `always`. Failure
modes are covered in [concurrency and failure](../architecture/concurrency-and-failure.md).

## Configuration check

`deploy/config-check.sh` compares what is **configured** with what is **running**. It is
read-only: it changes no file, restarts nothing, edits no firewall rule, and never executes an
installed binary. Run it after any change to an env file, a unit, the firewall, or after an
upgrade:

```
sudo ./deploy/config-check.sh              # table, one row per listener, then findings
sudo ./deploy/config-check.sh --json       # the same, as one JSON document
sudo ./deploy/config-check.sh --no-events  # skip the database query
```

The listener list comes from the same derivation that builds the fleet inventory
(`deploy/listeners-lib.sh`, used by `deploy/fleet-listeners.sh`), so the two cannot disagree
about which listeners exist. Each row is one sensor, protocol and bind (`sensor-dns` is two
rows, `sensor-catchall` two per port, `sensor-cred` one per protocol), and each row answers:

| Column | Question | Failure it catches |
|---|---|---|
| UNIT | Is `sensor-<name>.service` installed, enabled and active? | a unit never installed, masked, not enabled, or crash-looping |
| LISTEN | Is the configured port bound, and by the sensor? | `held by another process <name>` (a host service on the port) versus `nothing listening` (the sensor's bind failed) |
| FIREWALL | Does the active host firewall (ufw, firewalld or nftables) allow it? | a port nothing can reach, and the dangerous case below |
| LOG | Does the sensor's log exist, how old is it, how big against the logrotate `size`? | a log never written, silent for a day, or more than 3x the rotation size (warning from 2x) |
| INTAKE | Is that log path in `PROPOLIS_SENSOR_LOGS`, as the daemon parses it? | a sensor whose events are never ingested |
| EVENTS | When did the ledger last receive an event from this sensor? | intake not following a log that is growing |

The INTAKE check applies the daemon's own grammar (comma separated `label:path`, entries
trimmed, blank ones skipped, split at the first colon, both halves non-empty;
`crates/log-tailer/src/sensor_logs.rs`). A malformed entry makes the daemon refuse to start,
so it is a failure, reported with the corrected entry where one can be inferred; a repeated
label is a failure, a repeated path or a relative path a warning, and a misspelled variable
name (`PROPOLIS_SENSOR_LOG`, `SENSOR_LOGS`, a space before the `=`) is reported by name. The
EVENTS column is keyed by the name the sensor reports in `event.sensor` (`postgresql`, not the
`cred-pg` label) and is skipped without a readable `DATABASE_URL`, without `psql`, or when the
read-only query fails; the password is handed to `psql` through its environment, never on a
command line.

**The dangerous row.** A port that is open in the firewall and held, on a non-loopback
address, by a process that is not the expected sensor is reported first, as `DANGEROUS`, for
example a host PostgreSQL listening on `0.0.0.0:5432` while `sensor-cred` is configured for it
and the firewall exposes 5432. Its fix line names the firewall command that closes the port. A
foreign holder behind a closed firewall is still a failure, but not that one.

Exposure is judged from the address the other process actually listens on, not from the
sensor's configured address. A host PostgreSQL on `127.0.0.1:5432` and `[::1]:5432` (the
Debian default) is not reachable from the network, but it still stops `sensor-cred` binding
`0.0.0.0:5432`, so the row fails as `held on loopback only`. The fix is to leave the database
on loopback and bind the sensor to the host's network address
(`PROPOLIS_CRED_PG_BIND=<address>:5432`): a specific address can share a port with a
loopback listener, a wildcard cannot. That address must not change, so reserve it if it comes
from DHCP.

Below the table, HOST rows cover what no single listener owns: the log rotation timer, its
state file (older than three hours fails, the daemon's `rotation-stale` threshold) and the
installed policy and guard; the `INSTALL_BINS` set from `deploy/upgrade.sh` present in
`/usr/local/bin` and equal to the build in `target/release`, and the deploy stamp's recorded
`propolis` revision against its own commit and the checkout (an upgrade whose first run
installed no new binary shows here); `PROPOLIS_SENSOR_LOGS` as a whole; sensor units that are
enabled with no bind variable set (the look of a misspelled `*_BIND` name); and, where
`propolis-watch` is installed, `watch.env` against `propolis.env` and the watcher's
authorized key.

Every finding carries the next step, in one of two labelled forms, and the explanation lives in
the finding text above it, never in the step itself:

- `fix:` is a command line, or several joined with `&&` or `;`, to paste exactly as printed
  from a non-root shell in any directory. Root-only actions carry their own `sudo` (reading
  `/etc/propolis/*.env`, `journalctl`, `systemctl`, `ss -p`, `ufw`, `install`), and nothing in
  it is a placeholder or prose. The ledger query for an `EVENTS` finding reads `DATABASE_URL`
  out of `propolis.env` with `sudo` and runs `psql` as the `propolis` account, because that
  variable is not set in an operator's shell. The URL is then an argument of that `psql`, so it
  is visible in the process list for the length of the query (the report's own query avoids
  this by using `PG*` variables, which a pasted line cannot).
- `do:` is a manual step, not a command: edit a file, change a bind address, install a firewall
  or a key. It names the file and the value, and any restart that follows is written in the same
  line as `then run: ...`. Do not paste a `do:` line.

In `--json` each finding has `id` (the check that raised it), `fix`, and `fix_kind` (`run`,
`manual`, or empty when there is no step). `crates/sensor-framework/tests/config_check_test.rs`
raises every finding id against stub commands and executes each `fix` in bash, failing on a
parse error, any output on stderr, or a root-only command or env-file read without `sudo`; a new
finding with no fixture fails it.

The exit status is `0` all ok, `1` warnings or checks
that could not be answered, `2` at least one failure; a usage error is `64`.

**Without root** it still runs, and says what it could not see under `LIMITED CHECKS`. Sensor
env files are mode 0600 and owned by each sensor's account, so as an ordinary user part of the
inventory may be unreadable; `ss` cannot name another account's process, so a bound port shows
`bound, owner unknown (run as root to name it)`; `ufw` and `nft` cannot list rules; and
`/var/log/propolis/*` is not traversable. These are reported as `?`, which is neither a pass
nor a failure and raises the exit status to `1`. One case is still proved without root: a
port bound while the sensor's own unit is not running cannot be the sensor. A missing tool
(`systemctl`, `ss`, `psql`) makes its checks `?` the same way. The firewall reading handles the
common rule shapes (ufw `ALLOW IN` rules and default policy, firewalld ports and services of
the active zones, nftables `dport ... accept` rules in input-hook chains); a rule written another
way reads as closed, so treat a `closed` warning as a prompt to look, not a verdict.

`upgrade.sh` runs it last, with `--report-only` (full report, exit status always `0`), so a
finding is for you to read and never fails the upgrade. The sensors were restarted seconds
earlier; if a LISTEN row shows `nothing listening` straight after an upgrade, run the check
again once the units have settled.

## Live upgrade

`deploy/upgrade.sh` (run as root, `sudo ./deploy/upgrade.sh`) performs an in-place upgrade:
it rebuilds as the repo-owning user, reinstalls the binaries, runs `provision.sh`, reinstalls
the unit files and logrotate config, runs `daemon-reload`, restarts each **sensor** unit that
is enabled, then restarts `propolis.service` so sensors reconnect and migrations run against
the new schema, and finishes with the report-only [configuration check](#configuration-check)
(`deploy/upgrade.sh`). See
[upgrade, rollback, and DR](./upgrade-rollback-and-dr.md).

> **Warning - production impact.** `upgrade.sh` restarts live services and runs migrations.
> Run it during a maintenance window and confirm a working backup first (see
> [backup and restore](./backup-and-restore.md)).
