<!--
title: Ports and protocols
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-06
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
(`crates/sensor-ssh/src/main.rs#load_config_from_env`; `crates/sensor-cred/src/main.rs#main`).
`install.sh` creates users and directories but sets **no** bind port
(`deploy/install.sh#run_provision`, `deploy/install.sh#This script does NOT`).

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
  `/usr/local/bin/propolis`, `deploy/propolis.service#ExecStart=/usr/local/bin/propolis`): embeds intake +
  review + feed + the console web server + an outbound fetcher in one process.
  It binds **only** the console (`crates/propolis/src/config.rs#load_config`;
  listener in `run_console`, `crates/propolis/src/main.rs#run_console`). It does **not** bind any
  sensor ports; sensors always run as their own binaries.

## Attacker-facing listeners (honeypot)

Eleven sensor crates cover fourteen protocols (the `cred` sensor serves five). All
are internet-exposed honeypot listeners with an operator-chosen `ip:port` and no
default. Every one is TCP except `sensor-tftp` (UDP only) and the UDP half of
`sensor-catchall`.

| Sensor | Bind env | Protocol(s) | Conventional port | Notes |
|---|---|---|---|---|
| sensor-ssh | `PROPOLIS_SSH_BIND` (single `ip:port`) | SSH | 22 | Unit grants `CAP_NET_BIND_SERVICE` for privileged bind (`deploy/sensor-ssh.service`). Missing bind => `ConfigError::NoBind`, exit (`crates/sensor-ssh/src/main.rs#load_config_from_env`). |
| sensor-telnet | `PROPOLIS_TELNET_BIND` (single) | Telnet | 23 | `crates/sensor-telnet/src/main.rs#load_config_from_env` |
| sensor-http | `PROPOLIS_HTTP_BIND` (single); `PROPOLIS_HTTP_TLS_BIND` (single, optional) | HTTP; HTTPS (implicit TLS) | 80; 443 | `crates/sensor-http/src/main.rs#load_config_from_env`. The HTTPS listener runs in the same process and writes the same event log, and exists only when `PROPOLIS_HTTP_TLS_BIND` is set, with `PROPOLIS_HTTP_TLS_CERT` and `PROPOLIS_HTTP_TLS_KEY` (`crates/sensor-http/src/main.rs#parse_tls`). Unit grants `CAP_NET_BIND_SERVICE` for both privileged ports and `ReadOnlyPaths=/etc/propolis/tls` for the pair. |
| sensor-ftp | `PROPOLIS_FTP_BIND` (single) | FTP | 21 | Also opens passive-mode data ports at runtime (see below). `crates/sensor-ftp/src/main.rs#load_config_from_env` |
| sensor-smtp | `PROPOLIS_SMTP_BIND` (single); `PROPOLIS_SMTP_SUBMISSION_BIND` (single, optional); `PROPOLIS_SMTP_TLS_BIND` (single, optional) | SMTP; SMTP submission; SMTP over implicit TLS (SMTPS) | 25; 587; 465 | Missing `PROPOLIS_SMTP_BIND` => error + exit (`crates/sensor-smtp/src/main.rs#main`). All listeners run in one process and write one event log; 587 and 465 exist only when their bind is set (`crates/sensor-smtp/src/lib.rs#plan_listeners`). With `PROPOLIS_SMTP_TLS_CERT` and `PROPOLIS_SMTP_TLS_KEY` set, STARTTLS upgrades sessions on 25 and 587 (otherwise the unchanged `454` reply); 465 requires the pair (`crates/sensor-smtp/src/lib.rs#tls_from_env`). The unit keeps `CAP_NET_BIND_SERVICE` for 25, 465 and 587 and adds `ReadOnlyPaths=/etc/propolis/tls` for the pair. |
| sensor-tftp | `PROPOLIS_TFTP_BIND` (single, UDP) | TFTP | 69/udp | Off until set: missing or invalid => error + exit 1, nothing bound (`crates/sensor-tftp/src/main.rs#load_config_from`). The one sensor that replies over UDP, bounded so bytes sent never exceed bytes received. Each transfer answers from its own ephemeral UDP port on the bind IP, so a host firewall must allow replies from, and a client may send to, ports other than 69. Unit grants `CAP_NET_BIND_SERVICE`. |
| sensor-mqtt | `PROPOLIS_MQTT_BIND` (single); `PROPOLIS_MQTT_TLS_BIND` (single, optional) | MQTT; MQTT over implicit TLS (MQTTS) | 1883; 8883 | Off until set: missing or invalid => error + exit 1, nothing bound (`crates/sensor-mqtt/src/main.rs#load_config_from_env`). It never delivers, retains or forwards a PUBLISH, and spools a payload only when it looks binary. Ports 1883 and 8883 are unprivileged, so the unit grants no `CAP_NET_BIND_SERVICE` (it carries an empty `CapabilityBoundingSet`). It speaks MQTT 3.1, 3.1.1 and 5.0. The TLS listener runs in the same process, shares the plain listener's capture hand-off and budget, writes the same event log, and exists only when `PROPOLIS_MQTT_TLS_BIND` is set, with `PROPOLIS_MQTT_TLS_CERT` and `PROPOLIS_MQTT_TLS_KEY` (`crates/sensor-mqtt/src/main.rs#parse_tls`); the unit adds `ReadOnlyPaths=/etc/propolis/tls` for the pair. |
| sensor-redis | `PROPOLIS_REDIS_BIND` (single); `PROPOLIS_REDIS_TLS_BIND` (single, optional) | Redis; Redis over implicit TLS (`rediss://`) | 6379; 6380 | `crates/sensor-redis/src/main.rs#load_config_from_env`. The TLS listener runs in the same process and writes the same event log, and exists only when `PROPOLIS_REDIS_TLS_BIND` is set, with `PROPOLIS_REDIS_TLS_CERT` and `PROPOLIS_REDIS_TLS_KEY` (`crates/sensor-redis/src/main.rs#parse_tls`). Both ports are unprivileged: the unit grants no capability, and `ReadOnlyPaths=/etc/propolis/tls` for the pair. |
| sensor-adb | `PROPOLIS_ADB_BIND` (single) | ADB | 5555 | `crates/sensor-adb/src/main.rs#load_config_from_env` |
| sensor-catchall | `PROPOLIS_CATCHALL_BIND_ADDRS` (comma-sep list) | TCP + UDP, any port | (multi) | Both TCP and UDP attempted per address. Empty => `ConfigError::NoBindAddrs`, exit. Per-port bind failure is **non-fatal** (logged + skipped, sensor stays up). Unit grants `CAP_NET_BIND_SERVICE`. `crates/sensor-catchall/src/main.rs#parse_bind_addrs`, `crates/sensor-catchall/src/main.rs#main` |
| sensor-cred | five per-protocol envs (below) | VNC / MySQL / MSSQL / PostgreSQL / MongoDB | (multi) | No single bind env; at least one required. `crates/sensor-cred/src/main.rs#main` |

### sensor-cred per-protocol binds

Each is an independent `ip:port`; at least one must be set. An invalid value or
no env set at all exits with code 1 (`crates/sensor-cred/src/main.rs#main`).

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
`PROPOLIS_HTTP_WAN_MAP`, `PROPOLIS_FTP_WAN_MAP`, `PROPOLIS_SMTP_WAN_MAP`, `PROPOLIS_TFTP_WAN_MAP`,
`PROPOLIS_MQTT_WAN_MAP`, `PROPOLIS_REDIS_WAN_MAP`, `PROPOLIS_ADB_WAN_MAP`, `PROPOLIS_CATCHALL_WAN_MAP`,
`PROPOLIS_CRED_WAN_MAP`).

`sensor-wire` is a decoder/library crate with no network listener [inferred: no
bind/listen code found in its source].

## Operator-facing listener (console web UI)

- **`PROPOLIS_CONSOLE_BIND`**, default **`127.0.0.1:8080`** (loopback only)
  (`ENV_BIND`, `DEFAULT_BIND`, `crates/console/src/main.rs#ENV_BIND`, `crates/console/src/main.rs#DEFAULT_BIND`). Unprivileged port (>1024); the unit
  grants no bind capability (`deploy/console.service` `CapabilityBoundingSet=`).
- The console binds non-localhost **only** if the operator overrides the
  default; the design intent is to place it behind the operator's own reverse
  proxy (`crates/console/src/main.rs#DEFAULT_BIND`).
- The aggregated `propolis` binary uses the same default and env var
  (`DEFAULT_CONSOLE_BIND = "127.0.0.1:8080"`,
  `crates/propolis/src/config.rs#DEFAULT_CONSOLE_BIND`, `crates/propolis/src/config.rs#load_config`).

> The console is plain HTTP on a loopback `TcpListener` (`console::server::serve`, HTTP/1.1, no
> rustls). There is **no in-process TLS**. Any TLS is operator-provided (e.g. a
> reverse proxy) [inferred]. See
> [operations/networking-tls.md](../operations/networking-tls.md).

## Collector-facing listener (split deployment only)

In a [split deployment](../operations/split-deployment.md) the control plane runs `gateway`,
which listens on **`PROPOLIS_GATEWAY_BIND`**, a literal `ip:port` with no compiled-in default
(`crates/gateway/src/config.rs#load_config_from_env`); the examples use 9443. It speaks mutual
TLS and accepts only collectors whose client certificate its CA signed. Its unit grants no bind
capability and restricts no source address, so keep the port at 1024 or above and allow it in the host
firewall from collector addresses only. The collector's `shipper` only dials out.

## Machine-facing endpoints (health / ready / metrics)

These share the **same** bind as the console (`PROPOLIS_CONSOLE_BIND`, default
`127.0.0.1:8080`) - there is **no** separate metrics/health port. All three are
merged onto the single console router and mounted **outside** the auth
middleware (`router`'s outer merge chain, `crates/console/src/routes/mod.rs#router`).

| Route | Purpose | Behavior | Source |
|---|---|---|---|
| `GET /health` | Liveness | Always 200 | `crates/console/src/routes/health.rs#health` |
| `GET /ready` | Readiness | Pings Postgres; 200 ok / 503 fail-closed | `crates/console/src/routes/health.rs#ready` |
| `GET /metrics` | Prometheus text | Derived from DB queries per scrape | `crates/console/src/routes/metrics.rs#metrics` |

Full console route inventory is owned by
[console-routes.md](console-routes.md).

## No listener

- **intake / review / feed** are PostgreSQL clients only; they connect out via
  `DATABASE_URL` and bind no network listener.
- The `propolis` aggregated binary's outbound fetcher (malware/artifact
  retrieval) is **outbound only** - no inbound bind
  (`crates/propolis/src/config.rs#PropolisConfig`).

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
| 69 (UDP) | attacker | TFTP (transfers continue on ephemeral UDP ports) | `PROPOLIS_TFTP_BIND` |
| 80 | attacker | HTTP | `PROPOLIS_HTTP_BIND` |
| 443 | attacker | HTTPS (http, implicit TLS) | `PROPOLIS_HTTP_TLS_BIND` |
| 465 | attacker | SMTPS (smtp, implicit TLS) | `PROPOLIS_SMTP_TLS_BIND` |
| 587 | attacker | SMTP submission (smtp, plain + STARTTLS) | `PROPOLIS_SMTP_SUBMISSION_BIND` |
| 1433 | attacker | MSSQL (cred) | `PROPOLIS_CRED_MSSQL_BIND` |
| 1883 | attacker | MQTT | `PROPOLIS_MQTT_BIND` |
| 3306 | attacker | MySQL (cred) | `PROPOLIS_CRED_MYSQL_BIND` |
| 5432 | attacker | PostgreSQL (cred) | `PROPOLIS_CRED_PG_BIND` |
| 5555 | attacker | ADB | `PROPOLIS_ADB_BIND` |
| 5900 | attacker | VNC (cred) | `PROPOLIS_CRED_VNC_BIND` |
| 6379 | attacker | Redis | `PROPOLIS_REDIS_BIND` |
| 6380 | attacker | Redis over implicit TLS (redis) | `PROPOLIS_REDIS_TLS_BIND` |
| 8883 | attacker | MQTTS (mqtt, implicit TLS) | `PROPOLIS_MQTT_TLS_BIND` |
| 27017 | attacker | MongoDB (cred) | `PROPOLIS_CRED_MONGO_BIND` |
| (any) | attacker | Catchall (TCP+UDP, multi-port) | `PROPOLIS_CATCHALL_BIND_ADDRS` |
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
