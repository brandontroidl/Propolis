<!--
title: Ports and protocols
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Ports and protocols

Canonical owner of every listening port and bind in Propolis. Env-var exact
defaults and bounds are owned by
[environment-variables.md](environment-variables.md); this page owns the
port/bind facts and links there.

## No sensor has a compiled-in default port

Every sensor requires its bind address to be set explicitly via an env var and
**fails closed** (refuses to start) if the value is missing or unparseable.
There is no hardcoded `0.0.0.0:22`-style default anywhere in the source. The
operator supplies `ip:port` per sensor in `/etc/propolis/<sensor>.env`
(`crates/sensor-ssh/src/main.rs:23,130-134`; `crates/sensor-cred/src/main.rs:93-97`).
`install.sh` creates users and directories but sets **no** bind port
(`deploy/install.sh:25,233`).

The IP portion is whatever the operator writes (`0.0.0.0`, a specific address,
`127.0.0.1`). The software does not force a bind address. The "standard" port
map below is what a `deploy/`-based setup conventionally configures, not a
default the binaries carry.

## Two deployment shapes bind differently

- **Per-service binaries** (one systemd unit each): each sensor binds its own
  listener(s); `console` binds the web UI; `intake`, `review`, and `feed` are
  PostgreSQL-client daemons that bind **no** network listener
  (`crates/intake`, `crates/review`, `crates/feed` mains).
- **Aggregated single-node binary** `propolis` (`crates/propolis`, ExecStart
  `/usr/local/bin/propolis`, `deploy/propolis.service:115`): embeds intake +
  review + feed + the console web server + an outbound fetcher in one process.
  It binds **only** the console (`crates/propolis/src/config.rs:509-513`;
  listener at `crates/propolis/src/main.rs:413`). It does **not** bind any
  sensor ports; sensors always run as their own binaries.

## Attacker-facing listeners (honeypot)

Nine sensor crates cover twelve protocols (the `cred` sensor serves five). All
are internet-exposed honeypot listeners with an operator-chosen `ip:port` and no
default.

| Sensor | Bind env | Protocol(s) | Conventional port | Notes |
|---|---|---|---|---|
| sensor-ssh | `PROPOLIS_SSH_BIND` (single `ip:port`) | SSH | 22 | Unit grants `CAP_NET_BIND_SERVICE` for privileged bind (`deploy/sensor-ssh.service`). Missing bind => `ConfigError::NoBind`, exit (`crates/sensor-ssh/src/main.rs:23,73,130-134`). |
| sensor-telnet | `PROPOLIS_TELNET_BIND` (single) | Telnet | 23 | `crates/sensor-telnet/src/main.rs:20,149-153` |
| sensor-http | `PROPOLIS_HTTP_BIND` (single) | HTTP | 80 | `crates/sensor-http/src/main.rs:10,121-125` |
| sensor-ftp | `PROPOLIS_FTP_BIND` (single) | FTP | 21 | Also opens passive-mode data ports at runtime (see below). `crates/sensor-ftp/src/main.rs:10,61-65` |
| sensor-smtp | `PROPOLIS_SMTP_BIND` (single) | SMTP | 25 | Missing => error + exit (`crates/sensor-smtp/src/main.rs:10,44-58`) |
| sensor-redis | `PROPOLIS_REDIS_BIND` (single) | Redis | 6379 | `crates/sensor-redis/src/main.rs:21,150-154` |
| sensor-adb | `PROPOLIS_ADB_BIND` (single) | ADB | 5555 | `crates/sensor-adb/src/main.rs:21,153-157` |
| sensor-catchall | `CATCHALL_BIND_ADDRS` (comma-sep list) | TCP + UDP, any port | (multi) | Both TCP and UDP attempted per address. Empty => `ConfigError::NoBindAddrs`, exit. Per-port bind failure is **non-fatal** (logged + skipped, sensor stays up). Unit grants `CAP_NET_BIND_SERVICE`. `crates/sensor-catchall/src/main.rs:29,60-61,187,248-294` |
| sensor-cred | five per-protocol envs (below) | VNC / MySQL / MSSQL / PostgreSQL / MongoDB | (multi) | No single bind env; at least one required. `crates/sensor-cred/src/main.rs:75-99` |

### sensor-cred per-protocol binds

Each is an independent `ip:port`; at least one must be set. An invalid value or
no env set at all exits with code 1 (`crates/sensor-cred/src/main.rs:83-98`).

| Protocol | Bind env | Conventional port |
|---|---|---|
| VNC | `PROPOLIS_CRED_VNC_BIND` | 5900 |
| MySQL | `PROPOLIS_CRED_MYSQL_BIND` | 3306 |
| MSSQL | `PROPOLIS_CRED_MSSQL_BIND` | 1433 |
| PostgreSQL | `PROPOLIS_CRED_PG_BIND` | 5432 |
| MongoDB | `PROPOLIS_CRED_MONGO_BIND` | 27017 |

> Conventional ports are the well-known ports these services normally use; they
> are examples of what an operator typically configures, not values the binary
> carries.

### FTP passive-mode data ports

`sensor-ftp` opens passive-mode (PASV) data connections on dynamic ephemeral
ports negotiated per session, in addition to its control-port listener (commits
`94a62ae1`, `016721e1`). The data-port range is not an env-configured fixed port
[inferred from PASV semantics; the exact range was not confirmed to be
fixed/configurable vs. OS-ephemeral in this pass].

### WAN attribution override (per sensor)

Each attacker-facing sensor also reads a `*_WAN_MAP` env var (comma-separated
`local=wan`) that maps a local bind to the public address reported in events.
Not a listener. See [environment-variables.md](environment-variables.md) for the
exact per-sensor names (`PROPOLIS_SSH_WAN_MAP`, `PROPOLIS_TELNET_WAN_MAP`,
`PROPOLIS_HTTP_WAN_MAP`, `PROPOLIS_FTP_WAN_MAP`, `PROPOLIS_SMTP_WAN_MAP`,
`PROPOLIS_REDIS_WAN_MAP`, `PROPOLIS_ADB_WAN_MAP`, `CATCHALL_WAN_MAP`,
`PROPOLIS_CRED_WAN_MAP`).

`sensor-wire` is a decoder/library crate with no network listener [inferred: no
bind/listen code found in its source].

## Operator-facing listener (console web UI)

- **`PROPOLIS_CONSOLE_BIND`**, default **`127.0.0.1:8080`** (loopback only)
  (`crates/console/src/main.rs:28,38`). Unprivileged port (>1024); the unit
  grants no bind capability (`deploy/console.service` `CapabilityBoundingSet=`).
- The console binds non-localhost **only** if the operator overrides the
  default; the design intent is to place it behind the operator's own reverse
  proxy (`crates/console/src/main.rs:35-37`).
- The aggregated `propolis` binary uses the same default and env var
  (`DEFAULT_CONSOLE_BIND = "127.0.0.1:8080"`,
  `crates/propolis/src/config.rs:30,509-513`).

> The console is plain HTTP on a loopback `TcpListener` (`axum::serve`, no
> rustls). There is **no in-process TLS**. Any TLS is operator-provided (e.g. a
> reverse proxy) [inferred]. See
> [operations/networking-tls.md](../operations/networking-tls.md).

## Machine-facing endpoints (health / ready / metrics)

These share the **same** bind as the console (`PROPOLIS_CONSOLE_BIND`, default
`127.0.0.1:8080`) - there is **no** separate metrics/health port. All three are
merged onto the single console router and mounted **outside** the auth
middleware (`crates/console/src/routes/mod.rs:49-51`).

| Route | Purpose | Behavior | Source |
|---|---|---|---|
| `GET /health` | Liveness | Always 200 | `crates/console/src/routes/health.rs:14-30` |
| `GET /ready` | Readiness | Pings Postgres; 200 ok / 503 fail-closed | `crates/console/src/routes/health.rs:14-30` |
| `GET /metrics` | Prometheus text | Derived from DB queries per scrape | `crates/console/src/routes/metrics.rs:7,40` |

Full console route inventory is owned by
[console-routes.md](console-routes.md).

## No listener

- **intake / review / feed** are PostgreSQL clients only; they connect out via
  `DATABASE_URL` and bind no network listener.
- The `propolis` aggregated binary's outbound fetcher (malware/artifact
  retrieval) is **outbound only** - no inbound bind
  (`crates/propolis/src/config.rs:34-64`).

## Admin / SSH

There is **no** application-level admin or management SSH port. The honeypot's
port 22 (when configured) is the **fake** SSH sensor, not a real admin channel.
Host administration is out-of-band (Proxmox console / the real host sshd) and is
not part of this software.

## Standard deploy port map (example)

The mapping a conventional `deploy/`-based single-node setup configures. These
are **not** compiled-in defaults - each is set by the operator in
`/etc/propolis/<sensor>.env`.

| Port | Facing | Service | Bind env |
|---|---|---|---|
| 21 | attacker | FTP (+ dynamic PASV data ports) | `PROPOLIS_FTP_BIND` |
| 22 | attacker | SSH | `PROPOLIS_SSH_BIND` |
| 23 | attacker | Telnet | `PROPOLIS_TELNET_BIND` |
| 25 | attacker | SMTP | `PROPOLIS_SMTP_BIND` |
| 80 | attacker | HTTP | `PROPOLIS_HTTP_BIND` |
| 1433 | attacker | MSSQL (cred) | `PROPOLIS_CRED_MSSQL_BIND` |
| 3306 | attacker | MySQL (cred) | `PROPOLIS_CRED_MYSQL_BIND` |
| 5432 | attacker | PostgreSQL (cred) | `PROPOLIS_CRED_PG_BIND` |
| 5555 | attacker | ADB | `PROPOLIS_ADB_BIND` |
| 5900 | attacker | VNC (cred) | `PROPOLIS_CRED_VNC_BIND` |
| 6379 | attacker | Redis | `PROPOLIS_REDIS_BIND` |
| 27017 | attacker | MongoDB (cred) | `PROPOLIS_CRED_MONGO_BIND` |
| (any) | attacker | Catchall (TCP+UDP, multi-port) | `CATCHALL_BIND_ADDRS` |
| 8080 | operator + machine | Console UI + `/health` `/ready` `/metrics` (loopback default) | `PROPOLIS_CONSOLE_BIND` |

## Sockets

The application uses **no** Unix domain sockets. `console.service` deliberately
omits `AF_UNIX` from `RestrictAddressFamilies` (only `AF_INET AF_INET6`),
confirming no local-socket path. No `UnixListener`/`.sock` usage exists in any
sensor or daemon main.

## See also

- [filesystem-paths.md](filesystem-paths.md) - every path (logs, spool, state,
  config).
- [environment-variables.md](environment-variables.md) - exact env-var defaults
  and bounds.
- [../operations/networking-tls.md](../operations/networking-tls.md) - reverse
  proxy / TLS placement.
