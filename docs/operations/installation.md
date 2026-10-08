<!--
title: Installation
audience: deployer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Installation

This is the canonical installation procedure and successor to the root
`INSTALL.md`. It covers building the binaries, running `deploy/install.sh`, the
systemd units it installs, and how database migrations run.

The single-node unified-daemon model described here is what `install.sh`
provisions. For the model overview see
[deployment-models.md](deployment-models.md).

## 1. Build

From the repository root:

```
cargo build --release
```

This produces the release binaries in `target/release/`: `propolis`, the
twelve sensor binaries `sensor-catchall`, `sensor-ssh`, `sensor-telnet`,
`sensor-redis`, `sensor-adb`, `sensor-http`, `sensor-ftp`, `sensor-smtp`,
`sensor-tftp`, `sensor-mqtt`, `sensor-dns`, `sensor-cred`, and the read-only
live watcher `propolis-watch` (`deploy/install.sh#4/9 installing binaries to /usr/local/bin`). `install.sh` errors if any expected
source binary is missing or non-executable, so build before you install
(`deploy/install.sh#not found or not executable`). The build host must have the pinned Rust
toolchain (`1.96.1`, `rust-toolchain.toml`); see
[../development/build-and-test.md](../development/build-and-test.md).

## 2. Install

```
sudo ./deploy/install.sh [--dry-run]
```

`install.sh` uses `set -euo pipefail` and is idempotent and self-correcting: it
routes every mutating command through a `run()` wrapper (so real and dry-run
modes cannot drift, `deploy/install.sh#run`) and delegates user and directory
provisioning to `deploy/provision.sh`, whose `ensure_dir` reasserts directory
mode/owner/group on re-runs via `install -d` (`deploy/provision.sh#ensure_dir`).

### Privilege model

- **Real install requires root** (`deploy/install.sh#must run as root`). It creates OS
  users, writes into `/etc`, `/var/log`, `/var/lib`, `/var/spool`, and
  `/usr/local/bin`, and installs systemd units - all root-owned operations.
- **`--dry-run` needs no privilege and no built binaries.** It prints what would
  happen; it is what `crates/sensor-framework/tests/deploy_test.rs` runs in CI
  (`deploy/install.sh#Print every action this script would take without touching the system`).

### What it does (9 steps)

Steps 1-3 are delegated to `deploy/provision.sh` (shared with `upgrade.sh` so both entry
points provision identically, `deploy/install.sh#run_provision`); steps 4-9 run directly in
`install.sh`:

| Step | Action | Cite |
|---|---|---|
| 1/9 | Creates 13 system users (`propolis` + one per each of the twelve sensors) with `useradd --system --no-create-home --shell /usr/sbin/nologin --user-group`, then adds `propolis` to each sensor's group so the daemon can read group-readable sensor logs. Also creates `propolis-watch`, the SSH login for the read-only live watcher: home `/var/lib/propolis-watch`, shell `/bin/sh` (sshd runs a forced command through it), password field `*`, and the same sensor groups as `propolis`, for read access only. Its home and `.ssh` are root-owned so it cannot change its own keys, and `deploy/watch-env.sh` derives `/etc/propolis/watch.env` (the one `PROPOLIS_SENSOR_LOGS` line from `propolis.env`; nothing is written until that file sets it); see [live-watch.md](live-watch.md) | `deploy/provision.sh#ensure_user`, `deploy/provision.sh#usermod -aG`, `deploy/provision.sh#propolis-watch` |
| 2/9 | Creates config/log/state directories with specific owners and modes (see [../reference/filesystem-paths.md](../reference/filesystem-paths.md)) | `deploy/provision.sh#2/9 creating directories` |
| 3/9 | Creates spool mountpoints; **prints fstab guidance for the `noexec,nosuid,nodev` mounts but does not create them** | `deploy/provision.sh#3/9 creating spool directories (mountpoints only)`, fstab guidance `deploy/install.sh#NOT DONE BY THIS SCRIPT` |
| 4/9 | `install -m 0755` each binary to `/usr/local/bin/`, then mints the per-sensor self-signed TLS pairs into `/etc/propolis/tls` with `deploy/provision-tls.sh` (idempotent; needs the release `provision-certs` binary, so it runs after the build, not inside `provision.sh`). Minting turns nothing on: a sensor uses its pair only once its TLS variables are set; see [networking-tls.md](networking-tls.md#sensor-tls-attacker-facing-listeners) | `deploy/install.sh#4/9 installing binaries to /usr/local/bin`, `deploy/install.sh#run_provision_tls` |
| 5/9 | `install -m 0644` the 13 production units (`propolis.service` and the 12 sensor units) to `/etc/systemd/system/` | `deploy/install.sh#5/9 installing systemd units` |
| 6/9 | Installs `logrotate-sensors.conf` to `/etc/logrotate.d/propolis-sensors`, the free-space guard `logrotate-guard.sh` to `/usr/local/sbin/propolis-logrotate-guard` (0755; the policy calls it), and `propolis-logrotate.service` and `propolis-logrotate.timer` to `/etc/systemd/system/`. See [retention](retention.md#log-rotation) | `deploy/install.sh#6/9 installing logrotate config, free-space guard, and the Propolis rotation timer` |
| 7/9 | Derives the fleet listener inventory from the sensors' own bind variables (`deploy/fleet-listeners.sh`) | `deploy/install.sh#7/9 deriving the fleet listener inventory` |
| 8/9 | Records the deploy stamp (commit this box last deployed) for the console's fleet pane (`deploy/deploy-stamp.sh`) | `deploy/install.sh#8/9 recording the deploy stamp` |
| 9/9 | `systemctl daemon-reload`, then `systemctl enable --now propolis-logrotate.timer`: the one unit `install.sh` enables, because it needs no env file and an unrotated sensor log fills the disk | `deploy/install.sh#9/9 reloading systemd unit files`, `deploy/install.sh#systemctl enable --now propolis-logrotate.timer` |

Notable directory choices (`deploy/provision.sh#2/9 creating directories`,
`deploy/provision.sh#3/9 creating spool directories (mountpoints only)`): `/var/lib/propolis` is
**0755 root-owned deliberately** so a compromised daemon cannot unlink or swap
the sibling SSH host-key directory; `/var/lib/propolis/feed` is 0755 so a public
feed can be published by an unrelated distribution user; per-sensor log and
spool subdirs are 0750 owned by each sensor user. The exact owner/mode table is
owned by [../reference/filesystem-paths.md](../reference/filesystem-paths.md).

### What `install.sh` deliberately does NOT do

It does not start or enable any service (apart from `propolis-logrotate.timer`, above), does not create or migrate the
database, and **does not create or edit any operator-owned `/etc/propolis/*.env` file** -
those carry secrets the script "has no business fabricating"; the one file it
generates, the secret-free `/etc/propolis/fleet-listeners.env`, comes from
`deploy/fleet-listeners.sh` in step 7
(`deploy/install.sh#fleet-listeners.env`). Its final message states that services are
installed but not started, and the database is untouched
(`deploy/install.sh#Services are installed but NOT started or enabled (except propolis-logrotate.timer), and the database is untouched.`).
You must author the
`.env` files yourself before starting anything - see
[configuration.md](configuration.md) and
[secret-management.md](secret-management.md).

## 3. Systemd units

`install.sh` installs 13 production units to `/etc/systemd/system/` (`deploy/install.sh#for unit in propolis.service`):

- **`propolis.service`** - the unified daemon: `Type=simple`, `User=propolis`,
  `EnvironmentFile=/etc/propolis/propolis.env`, `ExecStart=/usr/local/bin/propolis`,
  `After=network.target postgresql.service` (`deploy/propolis.service#ExecStart=/usr/local/bin/propolis`).
  `Restart=on-failure`, `RestartSec=5` - not `Restart=always`, because the
  daemon's internal supervisor restarts a panicked subsystem in-process, so a
  full process exit only ever means a fail-fast (bad config / DB unreachable /
  migration failure) or an operator stop (`deploy/propolis.service#Restart=on-failure`).
- **Twelve `sensor-*.service` units** - `Type=simple`, per-sensor `User`/`Group`,
  `EnvironmentFile=/etc/propolis/<name>.env`, `ExecStart=/usr/local/bin/sensor-<name>`,
  `Restart=always`, `RestartSec=10` (`deploy/sensor-ssh.service` is the
  reference unit).

All units apply a least-authority sandbox (`NoNewPrivileges`,
`ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`,
and a supplementary hardening block). Two important caveats:

> **The `SystemCallFilter` in every shipped unit is a PLACEHOLDER, not a
> hardened filter.** It is `@system-service` minus `@privileged @resources` - a
> broad development allowlist. The unit header instructs you to derive the real
> syscall allowlist with `strace -c -f` under representative load before
> production (`deploy/propolis.service#SystemCallFilter=@system-service`). Treat it as a residual risk you must
> close, not a delivered control.

Capability grants differ per sensor: sensors that bind privileged ports
(catchall/ssh/telnet/http/ftp/smtp/tftp/dns) get `AmbientCapabilities=CAP_NET_BIND_SERVICE`;
redis/adb/mqtt/cred and the unified daemon carry an empty `CapabilityBoundingSet`
(no privileged port: MQTT's 1883 and 8883 and Redis's 6379 and 6380 are unprivileged, and
sensor-cred's TLS shares its plain ports). http, ftp, smtp and dns keep the capability for their
TLS ports too (443; 990; 465 and 587; 853). The full per-sensor cap/resource table lives in the
evidence and in [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md).

The **standalone** `intake`/`review`/`feed`/`console` units are not installed by
`install.sh`; they are dev-only (see [deployment-models.md](deployment-models.md)).

## 4. Database and migrations

`install.sh` does not create or migrate the database. Provisioning PostgreSQL,
its reachability, and `pg_hba` are an operator/DBA concern (`deploy/propolis.service#independent operator/DBA concern`).

The daemon runs its own migrations at startup - there is no separate migrate
step. On boot it loads config, connects the PgPool, then applies the
core-scoring migrations followed by `review::migrator()` and `fleet::migrator()`,
embedded via `sqlx::migrate!` (`crates/propolis/src/main.rs#main`). A migration
failure is a fail-fast: the process exits 1 at each of the three steps
(`crates/propolis/src/main.rs#main`). The migration set is owned
by [../reference/database.md](../reference/database.md); see also
[../development/schema-and-migrations.md](../development/schema-and-migrations.md).

## 5. First start

After the `.env` files exist and the database is reachable, enable and start the
units (operator action):

> **Warning - the honeypot sensors are internet-facing attacker listeners.** Do
> not enable them until the box is positioned as intended (isolated VLAN,
> firewalled, out-of-band admin access). See
> [networking-tls.md](networking-tls.md) and
> [../getting-started/production-readiness-checklist.md](../getting-started/production-readiness-checklist.md).

```
sudo systemctl enable --now propolis.service
sudo systemctl enable --now sensor-ssh.service   # ...and each other sensor unit
```

Verify with `systemctl status` and `journalctl -u propolis -u sensor-ssh`.
Startup, health/readiness, and shutdown behavior are owned by
[service-lifecycle.md](service-lifecycle.md) and
[health-and-observability.md](health-and-observability.md). Runnable command
forms are collected in [../reference/commands.md](../reference/commands.md).

## Upgrades

In-place upgrades use `sudo ./deploy/upgrade.sh` (requires root): it pulls, runs
`cargo build --release --workspace --locked` as the repo-owner user, reinstalls the binaries, runs
`provision.sh`, runs `provision-tls.sh` (idempotent; keeps any existing TLS pair), reinstalls the unit files, logrotate config and free-space guard, runs
`daemon-reload`, enables the `propolis-logrotate.timer` (idempotent), restarts only the enabled sensor units, and restarts
`propolis.service` last so migrations run and sensors reconnect
(`deploy/upgrade.sh`). Rollback and DR are owned by
[upgrade-rollback-and-dr.md](upgrade-rollback-and-dr.md).
