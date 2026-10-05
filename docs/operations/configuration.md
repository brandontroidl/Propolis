<!--
title: Configuration model
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Configuration model

Propolis is configured entirely through environment variables loaded from
per-service files under `/etc/propolis/`. There is no config file format, no
CLI flags for runtime settings, and no config in the database. This page
explains the model and points at the reference table that owns every exact
default and bound.

> The exhaustive list of variables - names, defaults, bounds, and
> fail-on-invalid behavior - is owned by
> [../reference/environment-variables.md](../reference/environment-variables.md).
> This page does not restate those values; it explains how the surface is
> organized and which file configures what.

## Where configuration lives

Each systemd unit reads one `EnvironmentFile`:

- `deploy/propolis.service` → `/etc/propolis/propolis.env` (the unified daemon:
  intake + review + feed + console + VirusTotal + fetcher + ops-alert)
- each `sensor-<name>.service` → `/etc/propolis/<name>.env` (that sensor's binds
  and connection bounds)

These `.env` files are **operator-authored**. `deploy/install.sh` does not
create them - it only prints "Next: populate /etc/propolis/*.env files"
(`deploy/install.sh#populate /etc/propolis`). They are mode `0600` and owned by the service user.
The defaults documented in the reference table are the **code** defaults applied
when a variable is unset or blank; they are authoritative for runtime behavior
even though the `.env` files themselves are not in the repo.

Keep `.env` files out of version control. See
[secret-management.md](secret-management.md) for the values that carry secrets.

## Which variable configures what

Grouped by subsystem. Names below are indicative; consult the reference table
for the complete set and exact values.

| Area | Configures | Key variables |
|---|---|---|
| Database | PgPool connection and size | `DATABASE_URL` (required), `PROPOLIS_DB_MAX_CONNECTIONS` |
| Intake | which sensor logs to tail, cursor state, poll cadence | `PROPOLIS_SENSOR_LOGS` (required), `PROPOLIS_CURSOR_DIR`, `PROPOLIS_POLL_INTERVAL_MS` |
| Review | scoring/review loop cadence and vendor submitters | `PROPOLIS_REVIEW_ENABLED`, `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS`, `PROPOLIS_VENDOR_<V>_*` |
| Feed | blocklist output dir, build cadence, tiers/windows, allow/delist | `PROPOLIS_FEED_ENABLED`, `PROPOLIS_FEED_OUTPUT_DIR`, `PROPOLIS_FEED_BUILD_INTERVAL_SECS`, `PROPOLIS_FEED_WINDOWS`, `PROPOLIS_FEED_ALLOWLIST`, `PROPOLIS_FEED_ASN_ALLOWLIST`, `PROPOLIS_FEED_DELIST` |
| Console | bind address, auth, session, enrichment | `PROPOLIS_CONSOLE_BIND`, `PROPOLIS_CONSOLE_PASSWORD` (required), `PROPOLIS_CONSOLE_SESSION_SECRET`, `PROPOLIS_GEOIP_DIR`, `PROPOLIS_CONSOLE_RDNS_ENABLED` |
| VirusTotal | sample scanning (opt-in egress) | `PROPOLIS_VT_ENABLED`, `PROPOLIS_VT_KEY`, `PROPOLIS_VT_UPLOAD`, `PROPOLIS_VT_SCAN_INTERVAL_SECS` |
| Malware fetcher | artifact retrieval (opt-in egress) | `PROPOLIS_FETCH_ENABLED` and the `PROPOLIS_FETCH_*` bounds |
| Ops self-alerting | ntfy paging on degradation (opt-in egress) | `PROPOLIS_OPS_ENABLED` and the `PROPOLIS_OPS_*` set |
| Sensors | each sensor's listener(s) and connection limits | `<PREFIX>_BIND` (required), `<PREFIX>_WAN_MAP`, `<PREFIX>_LOG_PATH`, and `*_TIMEOUT_MS` / `*_MAX_*` bounds |

Outbound-capable subsystems (vendors, VirusTotal, fetcher, ops-alert, console
rDNS) all default **off**; see [../security/outbound-controls.md](../security/outbound-controls.md).

## Fail-fast validation

Configuration is validated at startup. Most binaries (`propolis`, `intake`,
`review`, `feed`, `console`, and sensors `ssh/telnet/http/ftp/tftp/redis/adb/catchall`)
**abort startup** on a missing required variable or a present-but-invalid /
present-but-zero numeric bound - "zero never means unlimited"
(`crates/propolis/src/config.rs#require_env`, `crates/propolis/src/config.rs#parse_positive_u64`). A misconfiguration cannot silently
disable a guard.

Two exceptions: the `cred` and `smtp` sensors are **lenient** - an invalid or
zero bound silently falls back to the default rather than aborting
(`crates/sensor-cred/src/main.rs#parse_positive_u64`,
`crates/sensor-smtp/src/main.rs#parse_positive_u64`). Their bind variables still fail-close.

Fail-closed pairings worth noting (all owned by the reference table):

- A vendor or VirusTotal `*_ENABLED=true` with an empty key is forced disabled
  and logged (`crates/propolis/src/config.rs#load_vendor_config`, `crates/propolis/src/config.rs#load_config`,
  `crates/propolis/src/main.rs#main`).
- `PROPOLIS_OPS_ENABLED=true` with only one of `PROPOLIS_OPS_NTFY_URL` /
  `PROPOLIS_OPS_NTFY_TOPIC` set fails closed (a half-configured target looks
  configured but would page nothing); with neither set, alerts fall back to the
  local log sink instead of aborting startup
  (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`).
- `PROPOLIS_FEED_WINDOWS` fails closed on any malformed entry rather than
  skipping it (`crates/propolis/src/config.rs#parse_window_list`).
- `PROPOLIS_FEED_ASN_ALLOWLIST` is inert unless `PROPOLIS_GEOIP_DIR` is set and
  the GeoLite2-ASN database loads (`crates/propolis/src/config.rs#parse_asn_list`, `crates/propolis/src/main.rs#main`).

## Sensor binds and WAN attribution

Every sensor requires its bind variable (`<PREFIX>_BIND`, or
`PROPOLIS_CATCHALL_BIND_ADDRS` for catchall, or the five `PROPOLIS_CRED_*_BIND` vars for
cred) and refuses to start without it - there is **no compiled-in default
port**. The "standard" port mapping (SSH 22, telnet 23, etc.) is whatever the
operator writes into the `.env` files, not a code default. Ports are owned by
[../reference/ports-and-protocols.md](../reference/ports-and-protocols.md).

`<PREFIX>_WAN_MAP` maps a local bind address to its public WAN IP for
multi-vantage breadth scoring, as `private=public` (NAT/DNAT) or `public=public`
(direct bind). An unmapped local address yields a null `wan_ip` - no WAN
attribution - which is a valid, non-fatal state.

## Related

- [../reference/environment-variables.md](../reference/environment-variables.md) - every variable, default, and bound (canonical)
- [secret-management.md](secret-management.md) - the secret-bearing variables
- [networking-tls.md](networking-tls.md) - bind exposure and TLS
- [../reference/rate-limits-and-budgets.md](../reference/rate-limits-and-budgets.md) - fetcher/vendor budgets
