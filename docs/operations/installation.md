<!--
title: Installation
audience: deployer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
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

This produces the release binaries in `target/release/`: `propolis` plus the
nine sensor binaries `sensor-catchall`, `sensor-ssh`, `sensor-telnet`,
`sensor-redis`, `sensor-adb`, `sensor-http`, `sensor-ftp`, `sensor-smtp`,
`sensor-cred` (`deploy/install.sh:120`). `install.sh` errors if any expected
source binary is missing or non-executable, so build before you install
(`deploy/install.sh:127-130`). The build host must have the pinned Rust
toolchain (`1.96.1`, `rust-toolchain.toml`); see
[../development/build-and-test.md](../development/build-and-test.md).

## 2. Install

```
sudo ./deploy/install.sh [--dry-run]
```

`install.sh` uses `set -euo pipefail` and is idempotent and self-correcting: it
routes every mutating command through a `run()` wrapper (so real and dry-run
modes cannot drift, `deploy/install.sh:66-74`) and delegates user and directory
provisioning to `deploy/provision.sh`, whose `ensure_dir` reasserts directory
mode/owner/group on re-runs via `install -d` (`deploy/provision.sh:79-87`).

### Privilege model

- **Real install requires root** (`deploy/install.sh:78-81`). It creates OS
  users, writes into `/etc`, `/var/log`, `/var/lib`, `/var/spool`, and
  `/usr/local/bin`, and installs systemd units - all root-owned operations.
- **`--dry-run` needs no privilege and no built binaries.** It prints what would
  happen; it is what `crates/sensor-framework/tests/deploy_test.rs` runs in CI
  (`deploy/install.sh:39-42`).

### What it does (9 steps)

Steps 1-3 are delegated to `deploy/provision.sh` (shared with `upgrade.sh` so both entry
points provision identically, `deploy/install.sh:89-90`); steps 4-9 run directly in
`install.sh`:

| Step | Action | Cite |
|---|---|---|
| 1/9 | Creates 10 system users (`propolis` + one per sensor) with `useradd --system --no-create-home --shell /usr/sbin/nologin --user-group`, then adds `propolis` to each sensor's group so the daemon can read group-readable sensor logs | `deploy/provision.sh:55,60-70,75` |
| 2/9 | Creates config/log/state directories with specific owners and modes (see [../reference/filesystem-paths.md](../reference/filesystem-paths.md)) | `deploy/provision.sh:89-115` |
| 3/9 | Creates spool mountpoints; **prints fstab guidance for the `noexec,nosuid,nodev` mounts but does not create them** | `deploy/provision.sh:129-140`, fstab guidance `deploy/install.sh:92-115` |
| 4/9 | `install -m 0755` each binary to `/usr/local/bin/` | `deploy/install.sh:119-132` |
| 5/9 | `install -m 0644` the 10 production units to `/etc/systemd/system/` | `deploy/install.sh:134-139` |
| 6/9 | Installs `logrotate-sensors.conf` to `/etc/logrotate.d/propolis-sensors` | `deploy/install.sh:141-144` |
| 7/9 | Derives the fleet listener inventory from the sensors' own bind variables (`deploy/fleet-listeners.sh`) | `deploy/install.sh:146-154` |
| 8/9 | Records the deploy stamp (commit this box last deployed) for the console's fleet pane (`deploy/deploy-stamp.sh`) | `deploy/install.sh:156-162` |
| 9/9 | `systemctl daemon-reload` | `deploy/install.sh:164-167` |

Notable directory choices (`deploy/provision.sh:89-140`): `/var/lib/propolis` is
**0755 root-owned deliberately** so a compromised daemon cannot unlink or swap
the sibling SSH host-key directory; `/var/lib/propolis/feed` is 0755 so a public
feed can be published by an unrelated distribution user; per-sensor log and
spool subdirs are 0750 owned by each sensor user. The exact owner/mode table is
owned by [../reference/filesystem-paths.md](../reference/filesystem-paths.md).

### What `install.sh` deliberately does NOT do

It does not start or enable any service, does not create or migrate the
database, and **does not create or edit any operator-owned `/etc/propolis/*.env` file** -
those carry secrets the script "has no business fabricating"; the one file it
generates, the secret-free `/etc/propolis/fleet-listeners.env`, comes from
`deploy/fleet-listeners.sh` in step 7
(`install.sh:19-32,153-154,172-173`). Its final message states that services are
installed but not started, and the database is untouched. You must author the
`.env` files yourself before starting anything - see
[configuration.md](configuration.md) and
[secret-management.md](secret-management.md).

## 3. Systemd units

`install.sh` installs 10 production units to `/etc/systemd/system/`:

- **`propolis.service`** - the unified daemon: `Type=simple`, `User=propolis`,
  `EnvironmentFile=/etc/propolis/propolis.env`, `ExecStart=/usr/local/bin/propolis`,
  `After=network.target postgresql.service` (`propolis.service:106-121`).
  `Restart=on-failure`, `RestartSec=5` - not `Restart=always`, because the
  daemon's internal supervisor restarts a panicked subsystem in-process, so a
  full process exit only ever means a fail-fast (bad config / DB unreachable /
  migration failure) or an operator stop (`propolis.service:122-130`).
- **Nine `sensor-*.service` units** - `Type=simple`, per-sensor `User`/`Group`,
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
> production (`propolis.service:182-194`). Treat it as a residual risk you must
> close, not a delivered control.

Capability grants differ per sensor: sensors that bind privileged ports
(catchall/ssh/telnet/http/ftp/smtp) get `AmbientCapabilities=CAP_NET_BIND_SERVICE`;
redis/adb/cred and the unified daemon carry an empty `CapabilityBoundingSet`
(no privileged port). The full per-sensor cap/resource table lives in the
evidence and in [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md).

The **standalone** `intake`/`review`/`feed`/`console` units are not installed by
`install.sh`; they are dev-only (see [deployment-models.md](deployment-models.md)).

## 4. Database and migrations

`install.sh` does not create or migrate the database. Provisioning PostgreSQL,
its reachability, and `pg_hba` are an operator/DBA concern (`propolis.service:101-103`).

The daemon runs its own migrations at startup - there is no separate migrate
step. On boot it loads config, connects the PgPool, then applies the
core-scoring migrations followed by `review::migrator()` and `fleet::migrator()`,
embedded via `sqlx::migrate!` (`crates/propolis/src/main.rs:665-680`). A migration
failure is a fail-fast: the process exits 1 at each of the three steps
(`main.rs:671,675,679`). The migration set is owned
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
`provision.sh`, reinstalls the unit files and logrotate config, runs
`daemon-reload`, restarts only the enabled sensor units, and restarts
`propolis.service` last so migrations run and sensors reconnect
(`deploy/upgrade.sh`). Rollback and DR are owned by
[upgrade-rollback-and-dr.md](upgrade-rollback-and-dr.md).
