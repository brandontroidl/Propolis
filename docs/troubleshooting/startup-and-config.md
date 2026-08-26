<!--
title: Troubleshooting — startup and config
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Startup and config failures

Propolis config parsing is **fail-fast**: on any missing required variable or any
invalid numeric bound the process logs a reason and calls `std::process::exit(1)`
rather than starting in a degraded state (`crates/propolis/src/main.rs:532-539`).
Under systemd with `Restart=on-failure`/`Restart=always` the unit then restarts,
fails again, and back-off/`journalctl` is where you see why. Always read the log
before changing anything.

Exact variable names, defaults, and bounds are owned by
[Environment variables](../reference/environment-variables.md). This page maps
what you observe to the cause.

## First step, every time

```
systemctl status propolis
journalctl -u propolis -n 100 --no-pager
```

The daemon logs `propolis: invalid configuration; refusing to start` with the
underlying error before exiting (`crates/propolis/src/main.rs:536`). Sensors log
an analogous reason and exit 1.

## Missing required variables

These abort startup when unset or empty:

| Variable | Read by | Symptom |
|---|---|---|
| `DATABASE_URL` | all DB-touching binaries | `ConfigError::Missing("DATABASE_URL")`; empty string counts as missing |
| `PROPOLIS_CONSOLE_PASSWORD` | unified daemon, standalone `console` | refuses to start; no console without it |
| `PROPOLIS_SENSOR_LOGS` | unified daemon, `intake` | required; empty list or an entry missing name or path aborts |
| `<P>_BIND` (per sensor) | each standard sensor | e.g. `PROPOLIS_SSH_BIND` unset → `NoBind` abort |
| `CATCHALL_BIND_ADDRS` | `sensor-catchall` | note the **unprefixed** name; empty list refuses to start |

`sensor-cred` needs at least one of its five bind vars
(`PROPOLIS_CRED_{VNC,MYSQL,MSSQL,PG,MONGO}_BIND`); none set → exit 1.

Values and the full required/optional matrix:
[Environment variables](../reference/environment-variables.md).

## Invalid numeric bounds

Two parse idioms exist and they are **not uniform**:

- **Strict** (unified daemon, `intake`, `review`, `feed`, `console`, and sensors
  `ssh`/`telnet`/`http`/`ftp`/`redis`/`adb`/`catchall`): a present-but-invalid or
  present-but-zero numeric bound **aborts startup**. Zero is rejected on most
  bounds because "zero never means unlimited"
  (`crates/propolis/src/config.rs:185-192`). A few bounds allow 0 with a defined
  meaning (e.g. `PROPOLIS_FETCH_MAX_HOPS=0` = no redirects,
  `PROPOLIS_FETCH_MAX_DEPTH=0` = no recursion,
  `PROPOLIS_OPS_CAPACITY_FREE_PCT` rejects 0).
- **Lenient** (sensors `cred` and `smtp` only): an invalid or zero bound
  **silently falls back to the default** instead of aborting
  (`crates/sensor-cred/src/main.rs:29-33`,
  `crates/sensor-smtp/src/main.rs:28-32`). If you set a `cred`/`smtp` bound and it
  seems ignored, this is why — the value was rejected and the default used.

Fetcher bounds also enforce an upper clamp; a value above the max aborts (e.g.
`PROPOLIS_FETCH_MAX_BYTES` max 500 MB, and `=0` aborts because it would disable
the byte guard). See
[Rate limits and budgets](../reference/rate-limits-and-budgets.md).

## Session-secret format

`PROPOLIS_CONSOLE_SESSION_SECRET` is optional, but **if set** it must be exactly
64 hex characters (32 bytes) or startup fails
(`crates/propolis/src/config.rs:371-389`). If unset, a fresh random key is
generated each start — sessions then do not survive a restart (expected; see
[Console](console.md)).

## Bind conflicts (address already in use)

A sensor or the console fails to bind when the port is already held. Causes:

- Two Propolis units configured for the same `ip:port`.
- A real service on the box already owns the port (e.g. a real `sshd` on 22 while
  `sensor-ssh` is also bound to `0.0.0.0:22`). Move the real service or the sensor.
- Privileged ports (< 1024): the sensor units that need them carry
  `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  (catchall/ssh/telnet/http/ftp/smtp); redis/adb/cred have no privileged-port
  capability by design. If you rebind one of the no-capability sensors to a
  port < 1024 it will fail to bind. The console binds unprivileged `8080` and
  needs no capability.

Ports are **not compiled-in defaults** — every `*_BIND` is a required,
operator-chosen value in the `.env` file. The "standard" port map (SSH 22,
telnet 23, and so on) is what the `deploy/` example config sets, not a code
default. Canonical mapping:
[Ports and protocols](../reference/ports-and-protocols.md).

## Startup order and what each phase means

The unified daemon boots in a fixed sequence; an exit 1 tells you which phase
failed (`crates/propolis/src/main.rs:532-575`):

1. Parse/validate config → `invalid configuration; refusing to start`.
2. Connect the PgPool → `failed to connect to PostgreSQL` (see
   [Database](database.md)).
3. Run migrations (core-scoring then review) → `migrations failed`.
4. `create_dir_all` on the cursor directory → `failed to create cursor
   directory` (check ownership/permissions of `PROPOLIS_CURSOR_DIR`, default
   `/var/lib/propolis/cursors`).

Only after all four does it spawn subsystems and log `starting unified daemon`.

## `.env` files are operator-authored

`deploy/install.sh` deliberately does **not** create or edit any
`/etc/propolis/*.env` file — it prints `Next: populate /etc/propolis/*.env
files` and stops (`deploy/install.sh:233`). A freshly installed but unconfigured
box will fail every startup on the missing required variables above until you
author those files (mode 0600, owned by the service user). See
[Secret management](../operations/secret-management.md).
