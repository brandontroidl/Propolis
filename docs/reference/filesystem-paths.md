<!--
title: Filesystem paths
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Filesystem paths

Canonical owner of every filesystem path Propolis uses: event logs, spool /
quarantine dirs, persistent state, GeoIP, config, and sockets. Env-var exact
semantics are owned by
[environment-variables.md](environment-variables.md); this page owns the path
facts. Directory ownership/mode is created by `deploy/install.sh`.

## Event logs (per sensor, JSONL append)

Every log-path env is an **override**; the default is the value shown. Each
sensor appends newline-delimited JSON events.

| Sensor | Log-path env | Default | install.sh dir (mode 0750) |
|---|---|---|---|
| ssh | `PROPOLIS_SSH_LOG_PATH` | `/var/log/propolis/ssh/events.jsonl` (`crates/sensor-ssh/src/main.rs:46`) | `/var/log/propolis/ssh` propolis-ssh (`install.sh:124`) |
| telnet | `PROPOLIS_TELNET_LOG_PATH` | `/var/log/propolis/telnet/events.jsonl` (`sensor-telnet/src/main.rs:29`) | `/var/log/propolis/telnet` (`install.sh:125`) |
| http | `PROPOLIS_HTTP_LOG_PATH` | `/var/log/propolis/http/events.jsonl` (`sensor-http/src/main.rs:19`) | `/var/log/propolis/http` (`install.sh:128`) |
| ftp | `PROPOLIS_FTP_LOG_PATH` | `/var/log/propolis/ftp/events.jsonl` (`sensor-ftp/src/main.rs:20`) | `/var/log/propolis/ftp` (`install.sh:129`) |
| smtp | `PROPOLIS_SMTP_LOG_PATH` | `/var/log/propolis/smtp/events.jsonl` (`sensor-smtp/src/main.rs:14`) | `/var/log/propolis/smtp` (`install.sh:130`) |
| redis | `PROPOLIS_REDIS_LOG_PATH` | `/var/log/propolis/redis/events.jsonl` (`sensor-redis/src/main.rs:30`) | `/var/log/propolis/redis` (`install.sh:126`) |
| adb | `PROPOLIS_ADB_LOG_PATH` | `/var/log/propolis/adb/events.jsonl` (`sensor-adb/src/main.rs:31`) | `/var/log/propolis/adb` (`install.sh:127`) |
| catchall | `CATCHALL_LOG_PATH` | **`catchall-events.jsonl`** (relative, not absolute) (`sensor-catchall/src/main.rs:38`) | `/var/log/propolis/catchall` (`install.sh:123`) |
| cred | `PROPOLIS_CRED_LOG_DIR` (a **directory**) | `/var/log/propolis/cred`; writes one file per protocol `<protocol>.jsonl` (e.g. `mysql.jsonl`) (`sensor-cred/src/main.rs:10,102`) | `/var/log/propolis/cred` (`install.sh:131`) |

Two paths differ from the pattern:

- **catchall**'s default is a **relative** path (`catchall-events.jsonl`), so in
  production `CATCHALL_LOG_PATH` must be set to an absolute path inside
  `/var/log/propolis/catchall` (the unit comment requires it match logrotate).
- **cred** uses a **directory** default and derives per-protocol filenames,
  unlike every other sensor which names a single file.

logrotate config `deploy/logrotate-sensors.conf` rotates `/var/log/propolis/*`
event logs.

## Spool / quarantine (uploaded-artifact capture)

> **Mount requirement:** spool dirs must be backed by `noexec,nosuid,nodev`
> mounts. `install.sh` does **not** do this - the operator must add fstab
> entries (`install.sh:172-187` lists example tmpfs entries). Captured artifacts
> may be live malware.

| Purpose | Env | Default | install.sh dir |
|---|---|---|---|
| ssh uploads | `PROPOLIS_SSH_SPOOL_DIR` | `/var/spool/propolis/ssh` (`sensor-ssh/src/main.rs:47`) | 0750 propolis-ssh (`install.sh:163`) |
| ftp uploads | `PROPOLIS_FTP_SPOOL_DIR` | `/var/spool/propolis/ftp` (`sensor-ftp/src/main.rs:21`) | 0750 propolis-ftp (`install.sh:165`) |
| adb uploads | `PROPOLIS_ADB_SPOOL_DIR` | `/var/spool/propolis/adb` (`sensor-adb/src/main.rs:32`) | 0750 propolis-adb (`install.sh:164`) |
| telnet uploads | `PROPOLIS_TELNET_SPOOL_DIR` | `/var/spool/propolis/telnet` (`sensor-telnet/src/main.rs:35`) | 0750 propolis-telnet (`install.sh:166`) |
| catchall | (dir granted for symmetry, **unused** - catchall spools no bodies) | `/var/spool/propolis/catchall` | 0750 propolis-catchall (`install.sh:162`) |
| fetcher output | const `FETCH_SPOOL_DIR` | `/var/spool/propolis/fetched` (`crates/propolis/src/main.rs:41`) | 0750 propolis (`install.sh:169`) |
| ops spool root | const `OPS_SPOOL_ROOT` | `/var/spool/propolis` (`crates/propolis/src/main.rs:46`) | 0755 root (`install.sh:161`) |

- The fetcher output dir has a global byte budget of 1_000_000_000 bytes
  (`crates/propolis/src/main.rs:55`).
- **smtp, redis, http, cred** have **no** spool dir (no `*_SPOOL_DIR` env);
  they capture inline only. Telnet spools only when the shell phase sees a
  binary payload (a Mirai/Gafgyt dropper), never the login/password phase.

Each of ssh/ftp/adb/telnet also writes a durable per-capture custody manifest
row (`PROPOLIS_<SENSOR>_OUTBOX_DIR`) as soon as a body is sealed - defaults to
`<its own spool dir>/outbox` (e.g. `/var/spool/propolis/ssh/outbox`), not a
separate path, so the write always lands inside that unit's own
`ReadWritePaths` grant. See [environment-variables.md](environment-variables.md#outbox-manifest-sp-b-1b)
for the full variable reference.

## Persistent state

| Purpose | Env | Default | install.sh dir |
|---|---|---|---|
| SSH host key (generated first run, reused) | `PROPOLIS_SSH_HOST_KEY_PATH` | `/var/lib/propolis/ssh/host_key` (`sensor-ssh/src/main.rs:48`) | `/var/lib/propolis/ssh` 0750 propolis-ssh (`install.sh:146`) |
| intake cursors (log tail position) | `PROPOLIS_CURSOR_DIR` | `/var/lib/propolis/cursors` (`intake/src/main.rs:24`; `propolis/src/config.rs:17`) | 0750 propolis (`install.sh:138`) |
| feed publish output | `PROPOLIS_FEED_OUTPUT_DIR` | `/var/lib/propolis/feed/current` (`feed/src/main.rs:36`; `propolis/src/config.rs:21`) | `/var/lib/propolis/feed` 0755 propolis (`install.sh:142`) |
| GeoIP databases | `PROPOLIS_GEOIP_DIR` | **no default - enrichment disabled when unset** (`console/src/main.rs:131-134`; `feed/src/main.rs:211-214`) | not created by install.sh |
| aggregated-node writable state | (unit grant) | `/var/lib/propolis` (`propolis.service:146` ReadWritePaths) | `/var/lib/propolis` 0755 root (`install.sh:137`) |
| ops spool bounded-buffer dir | (const) | `/var/lib/propolis/spool` (`install.sh:160`) | 0750 propolis |

- **GeoIP** expects `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb` under
  `PROPOLIS_GEOIP_DIR` (`geoip/src/lib.rs:61-62,71`). When the var is unset,
  GeoIP enrichment is simply disabled - GeoLite2 lookups are **local file
  reads, not network requests**. Not created by `install.sh`; the operator
  provisions the files.
- The aggregated node's `ReadWritePaths=/var/lib/propolis` is deliberately wider
  than intake's cursors-only grant, because the single process owns cursors,
  feed output, and spool together.

## Config

- **Config root `/etc/propolis`** (0755 root, `install.sh:121`). Per-service env
  files `/etc/propolis/<service>.env` (mode 0600, service-owned) carry all
  config **including secrets**, named in each unit's `EnvironmentFile=` (e.g.
  `console.env`, `ssh.env`, `catchall.env`, `propolis.env` at
  `propolis.service:114`). `install.sh` does **not** create these env files
  (`install.sh:25`) - the operator populates them.
- **Feed status:** the console reads (read-only)
  `PROPOLIS_FEED_OUTPUT_DIR`/`manifest.json` for its feed-status page; the unit
  grants `ReadOnlyPaths=/var/lib/propolis/feed` (`console.service`).

## Console writes nothing to local disk

Console sessions are in-memory only (`console.service` header: `UMask=0077`, no
`ReadWritePaths`). The console persists no session or state files locally.

## Sockets

The application uses **no** Unix domain sockets. `console.service` omits
`AF_UNIX` from `RestrictAddressFamilies`; no `UnixListener`/`.sock` usage exists
in any sensor or daemon main.

## Database

`DATABASE_URL` (required) is the PostgreSQL connection string for console,
intake, review, feed, and the aggregated `propolis` binary; missing => fail-closed
startup error. The database is the primary data sink but not a filesystem path;
schema is owned by [database.md](database.md).

## See also

- [ports-and-protocols.md](ports-and-protocols.md) - every port and bind.
- [environment-variables.md](environment-variables.md) - exact env-var defaults
  and bounds.
- [../operations/queue-and-spool.md](../operations/queue-and-spool.md) - spool
  lifecycle and mount hardening.
- [../operations/retention.md](../operations/retention.md) - log/spool retention
  and rotation.
