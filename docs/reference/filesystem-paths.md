<!--
title: Filesystem paths
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Filesystem paths

Canonical owner of every filesystem path Propolis uses: event logs, spool /
quarantine dirs, persistent state, GeoIP, config, and sockets. Env-var exact
semantics are owned by
[environment-variables.md](environment-variables.md); this page owns the path
facts. Directory ownership/mode is created by `deploy/provision.sh`
(`ensure_dir`, invoked by both `install.sh` and `upgrade.sh`).

## Event logs (per sensor, JSONL append)

Every log-path env is an **override**; the default is the value shown. Each
sensor appends newline-delimited JSON events.

| Sensor | Log-path env | Default | install.sh dir (mode 0750) |
|---|---|---|---|
| ssh | `PROPOLIS_SSH_LOG_PATH` | `/var/log/propolis/ssh/events.jsonl` (`crates/sensor-ssh/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/ssh` propolis-ssh (`deploy/provision.sh#ensure_dir /var/log/propolis/ssh`) |
| telnet | `PROPOLIS_TELNET_LOG_PATH` | `/var/log/propolis/telnet/events.jsonl` (`sensor-telnet/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/telnet` (`deploy/provision.sh#ensure_dir /var/log/propolis/telnet`) |
| http | `PROPOLIS_HTTP_LOG_PATH` | `/var/log/propolis/http/events.jsonl` (`sensor-http/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/http` (`deploy/provision.sh#ensure_dir /var/log/propolis/http`) |
| ftp | `PROPOLIS_FTP_LOG_PATH` | `/var/log/propolis/ftp/events.jsonl` (`sensor-ftp/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/ftp` (`deploy/provision.sh#ensure_dir /var/log/propolis/ftp`) |
| smtp | `PROPOLIS_SMTP_LOG_PATH` | `/var/log/propolis/smtp/events.jsonl` (`sensor-smtp/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/smtp` (`deploy/provision.sh#ensure_dir /var/log/propolis/smtp`) |
| redis | `PROPOLIS_REDIS_LOG_PATH` | `/var/log/propolis/redis/events.jsonl` (`sensor-redis/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/redis` (`deploy/provision.sh#ensure_dir /var/log/propolis/redis`) |
| adb | `PROPOLIS_ADB_LOG_PATH` | `/var/log/propolis/adb/events.jsonl` (`sensor-adb/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/adb` (`deploy/provision.sh#ensure_dir /var/log/propolis/adb`) |
| catchall | `PROPOLIS_CATCHALL_LOG_PATH` | **`catchall-events.jsonl`** (relative, not absolute) (`sensor-catchall/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/catchall` (`deploy/provision.sh#ensure_dir /var/log/propolis/catchall`) |
| cred | `PROPOLIS_CRED_LOG_DIR` (a **directory**) | `/var/log/propolis/cred`; writes one file per protocol `<protocol>.jsonl` (e.g. `mysql.jsonl`) (`sensor-cred/src/main.rs#DEFAULT_LOG_DIR`, `sensor-cred/src/main.rs#main`) | `/var/log/propolis/cred` (`deploy/provision.sh#ensure_dir /var/log/propolis/cred`) |

Two paths differ from the pattern:

- **catchall**'s default is a **relative** path (`catchall-events.jsonl`), so in
  production `PROPOLIS_CATCHALL_LOG_PATH` must be set to an absolute path inside
  `/var/log/propolis/catchall` (the unit comment requires it match logrotate).
- **cred** uses a **directory** default and derives per-protocol filenames,
  unlike every other sensor which names a single file.

logrotate config `deploy/logrotate-sensors.conf` rotates `/var/log/propolis/*`
event logs.

## Spool / quarantine (uploaded-artifact capture)

> **Mount requirement:** spool dirs must be backed by `noexec,nosuid,nodev`
> mounts. `install.sh` does **not** do this - the operator must add fstab
> entries (`deploy/install.sh#NOT DONE BY THIS SCRIPT` lists example tmpfs entries). Captured artifacts
> may be live malware.

| Purpose | Env | Default | install.sh dir |
|---|---|---|---|
| ssh uploads | `PROPOLIS_SSH_SPOOL_DIR` | `/var/spool/propolis/ssh` (`sensor-ssh/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-ssh (`deploy/provision.sh#ensure_dir /var/spool/propolis/ssh`) |
| ftp uploads | `PROPOLIS_FTP_SPOOL_DIR` | `/var/spool/propolis/ftp` (`sensor-ftp/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-ftp (`deploy/provision.sh#ensure_dir /var/spool/propolis/ftp`) |
| adb uploads | `PROPOLIS_ADB_SPOOL_DIR` | `/var/spool/propolis/adb` (`sensor-adb/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-adb (`deploy/provision.sh#ensure_dir /var/spool/propolis/adb`) |
| telnet uploads | `PROPOLIS_TELNET_SPOOL_DIR` | `/var/spool/propolis/telnet` (`sensor-telnet/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-telnet (`deploy/provision.sh#ensure_dir /var/spool/propolis/telnet`) |
| catchall | (dir granted for symmetry, **unused** - catchall spools no bodies) | `/var/spool/propolis/catchall` | 0750 propolis-catchall (`deploy/provision.sh#ensure_dir /var/spool/propolis/catchall`) |
| fetcher output | `PROPOLIS_SPOOL_ROOT` + `/fetched` (fn `fetch_spool_dir()`) | `/var/spool/propolis/fetched` (`crates/propolis/src/main.rs#fetch_spool_dir`; root `crates/review/src/spool.rs#DEFAULT_SPOOL_ROOT`) | 0750 propolis (`deploy/provision.sh#ensure_dir /var/spool/propolis/fetched`) |
| ops spool root | `PROPOLIS_SPOOL_ROOT` (fn `ops_spool_root()`) | `/var/spool/propolis` (`crates/propolis/src/main.rs#ops_spool_root`; default `crates/review/src/spool.rs#DEFAULT_SPOOL_ROOT`) | 0755 root (`deploy/provision.sh#3/9 creating spool directories (mountpoints only)`) |

- The fetcher output dir has a global byte budget of 1_000_000_000 bytes
  (`FETCH_SPOOL_GLOBAL_BUDGET`, `crates/propolis/src/main.rs#FETCH_SPOOL_GLOBAL_BUDGET`).
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
| SSH host key (generated first run, reused) | `PROPOLIS_SSH_HOST_KEY_PATH` | `/var/lib/propolis/ssh/host_key` (`sensor-ssh/src/main.rs#DEFAULT_HOST_KEY_PATH`) | `/var/lib/propolis/ssh` 0750 propolis-ssh (`deploy/provision.sh#ensure_dir /var/lib/propolis/ssh`) |
| intake cursors (log tail position) | `PROPOLIS_CURSOR_DIR` | `/var/lib/propolis/cursors` (`intake/src/main.rs#DEFAULT_CURSOR_DIR`; `propolis/src/config.rs#DEFAULT_CURSOR_DIR`) | 0750 propolis (`deploy/provision.sh#ensure_dir /var/lib/propolis/cursors`) |
| feed publish output | `PROPOLIS_FEED_OUTPUT_DIR` | `/var/lib/propolis/feed/current` (`feed/src/main.rs#DEFAULT_OUTPUT_DIR`; `propolis/src/config.rs#DEFAULT_FEED_OUTPUT_DIR`) | `/var/lib/propolis/feed` 0755 propolis (`deploy/provision.sh#ensure_dir /var/lib/propolis/feed`) |
| GeoIP databases | `PROPOLIS_GEOIP_DIR` | **no default - enrichment disabled when unset** (`geoip_dir` parse, `console/src/main.rs#load_config_from_env`; `feed/src/main.rs#load_config_from_env`) | not created by install.sh |
| aggregated-node writable state | (unit grant) | `/var/lib/propolis` (`deploy/propolis.service#ReadWritePaths=/var/lib/propolis`) | `/var/lib/propolis` 0755 root (`deploy/provision.sh#root-owned, NOT propolis`) |
| ops spool bounded-buffer dir | (const) | `/var/lib/propolis/spool` (`deploy/provision.sh#ensure_dir /var/lib/propolis/spool`) | 0750 propolis |

- **GeoIP** expects `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb` under
  `PROPOLIS_GEOIP_DIR` (`crates/geoip/src/lib.rs#load`, `crates/geoip/src/lib.rs#load_asn_only`). When the var is unset,
  GeoIP enrichment is simply disabled - GeoLite2 lookups are **local file
  reads, not network requests**. Not created by `install.sh`; the operator
  provisions the files.
- The aggregated node's `ReadWritePaths=/var/lib/propolis` is deliberately wider
  than intake's cursors-only grant, because the single process owns cursors,
  feed output, and spool together.

## Config

- **Config root `/etc/propolis`** (0755 root, `deploy/provision.sh#ensure_dir /etc/propolis`). Per-service env
  files `/etc/propolis/<service>.env` (mode 0600, service-owned) carry all
  config **including secrets**, named in each unit's `EnvironmentFile=` (e.g.
  `console.env`, `ssh.env`, `catchall.env`, `propolis.env` at
  `deploy/propolis.service#EnvironmentFile=/etc/propolis/propolis.env`). `install.sh` does **not** create these env files
  (`deploy/install.sh#OPERATOR-owned /etc/propolis/*.env file`) - the operator populates them.
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
