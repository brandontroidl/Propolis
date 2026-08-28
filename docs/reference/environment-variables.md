<!--
title: Environment variables
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Environment variables

Authoritative table of every environment variable read by any Propolis binary:
name, the binary that reads it, required/optional, exact code default, valid
form, bounds/validation, and fail behavior. This page owns these facts; other
docs link here rather than restating defaults.

Defaults listed are the **code** defaults applied when a variable is unset or
blank. All `/etc/propolis/*.env` files are operator-authored; `deploy/install.sh`
does not generate them (it only prints a reminder to populate them,
`deploy/install.sh:233`).

## Run modes and where variables are read

Propolis ships two ways to run the platform, and the env surface differs:

1. **Unified daemon** `propolis` — one `load_config()`
   (`crates/propolis/src/config.rs:429`) parses intake, review, feed, console,
   VirusTotal, malware-fetcher, and ops-alert config from a single env set
   (`EnvironmentFile=/etc/propolis/propolis.env`). It does **not** read sensor
   `*_BIND`/`*_WAN_MAP` variables; it consumes sensor **log files** via
   `PROPOLIS_SENSOR_LOGS`.
2. **Standalone service binaries** — `intake`, `review`, `feed`, `console` —
   each with its own `load_config_from_env()` and its own
   `/etc/propolis/<name>.env`. Their variables are a strict subset of the unified
   daemon's (e.g. standalone `feed` does not read `PROPOLIS_FEED_WINDOWS`;
   standalone `review` does not read the VT or fetch variables).
3. **Sensor binaries** — always separate processes regardless of run mode, each
   with its own `/etc/propolis/<name>.env`.

Which run mode a given deployment uses is an operator choice; both sets of
`.service` units exist.

## Parse and fail semantics

Two fail-closed idioms recur; they are **not** uniform:

- **Strict parse** — `propolis`, `intake`, `review`, `feed`, `console`, and
  sensors `ssh`/`telnet`/`http`/`ftp`/`redis`/`adb`/`catchall`: a
  present-but-invalid or present-but-zero numeric bound **aborts startup**.
- **Lenient parse** — sensors `cred` and `smtp` **only**: an invalid or zero
  bound silently falls back to the default (`parse_positive_u64` filters `>0`
  then `unwrap_or(default)`, `crates/sensor-cred/src/main.rs:29-33`,
  `crates/sensor-smtp/src/main.rs:28-32`).

Unified daemon (`config.rs`) parse helpers:

| Helper | Unset/empty | Invalid | Zero | Other |
|---|---|---|---|---|
| `require_env` (`:168`) | `Missing` (abort) | — | — | — |
| `parse_positive_u64` (`:175`) | default | `Invalid` (abort) | `Invalid` (abort) — "zero never means unlimited" | — |
| `parse_bounded_positive_u64` (`:199`) | default | abort | abort | `> max` → abort |
| `parse_u32` (`:215`) | default | abort | allowed | — |
| `parse_bounded_u8` (`:351`) | default | abort | allowed (0 = maximally strict) | `> 255` → abort (no wrap) |
| `parse_bool_flag` (`:227`) | default | — | — | case-insensitive `true`/`false` only; **any** other value (incl. `1`, `yes`) → default |

Note `parse_bool_flag` does **not** accept `1`/`yes`; ops-alert `get_bool` and
console rDNS parse booleans more broadly (called out below).

---

## Universal / cross-cutting

### `DATABASE_URL`
- Read by: `propolis` (`config.rs:430`), `console` (`main.rs:113`), `feed`
  (`main.rs:183`), `intake` (`main.rs:146`), `review` (`main.rs:199`).
- Required: **yes**, for every binary that touches PostgreSQL. No default.
- Form: PostgreSQL connection string (not validated at parse time; `sqlx`
  validates on connect).
- Fail: absent **or** empty string → **abort** (empty treated as missing via
  `.filter(|s| !s.is_empty())`).

### `RUST_LOG`
- Read by: `propolis` (`main.rs:524`), `console` (`main.rs:194`), and the
  sensors via `tracing_subscriber`.
- Required: no. Default filter `info` on unset or parse failure.
- Standard `tracing_subscriber::EnvFilter` default-env name. Sensors `cred`/`smtp`
  honor it via `tracing_subscriber::fmt::init()`; other sensors honor it the
  same way [inferred] (not individually verified).

### `PROPOLIS_HOSTNAME`
- Read by: `sensor-framework::persona::hostname()`
  (`crates/sensor-framework/src/persona.rs:46`); used by every sensor presenting
  a host identity (SSH/telnet shell, fake-fs `/etc/hostname`, redis `INFO`,
  SMTP/FTP greeting).
- Required: no. Default `server01` (`persona.rs:22`).
- Validation: trimmed; blank after trim → default (`persona.rs:48-50`). Always
  resolves.

---

## Unified daemon `propolis`

Full env surface, `crates/propolis/src/config.rs`. This binary reads every
variable in this section plus the universal ones above.

### Database

| Variable | Req | Default | Bounds / validation | Fail |
|---|---|---|---|---|
| `PROPOLIS_DB_MAX_CONNECTIONS` | no | `10` (`config.rs:16`) | positive u64 → cast u32 | zero/unparseable → abort |

### Intake

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_SENSOR_LOGS` | **yes** | — | comma-separated `name:path` pairs (`config.rs:236-262`). Empty list, or an entry missing name/path → **abort**. At least one pair required. |
| `PROPOLIS_CURSOR_DIR` | no | `/var/lib/propolis/cursors` (`config.rs:17`) | any path; no validation |
| `PROPOLIS_POLL_INTERVAL_MS` | no | `1000` (`config.rs:18`) | positive u64 ms; zero/unparseable → abort |

### Review

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_REVIEW_ENABLED` | no | `true` (`config.rs:444`) | bool_flag |
| `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS` | no | `60` (`config.rs:19`) | positive u64; zero → abort |
| `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS` | no | `30` (`config.rs:20`) | positive u64; zero → abort |

### Vendor abuse submitters (`config.rs:454-474`, `load_vendor_config:391`)

Each vendor `<V>` ∈ {`ABUSEIPDB`, `DSHIELD`, `OTX`}. These are opt-in egress
paths, default off. See [outbound controls](../security/outbound-controls.md)
and [integrations](integrations.md).

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_VENDOR_<V>_KEY` | no | `""` | empty key + enabled → vendor forced **disabled** (fail-closed, warns) (`:399-405`) |
| `PROPOLIS_VENDOR_<V>_URL` | no | vendor base URL (below) | no validation |
| `PROPOLIS_VENDOR_<V>_ENABLED` | no | `false` (`:398`) | bool_flag; stays disabled unless key present |
| `PROPOLIS_VENDOR_<V>_COOLDOWN_HOURS` | no | `24` (`config.rs:31`) | parse_u32; zero allowed; unparseable → abort |
| `PROPOLIS_VENDOR_<V>_RATE_LIMIT` | no | `100` (`config.rs:32`) | parse_u32 |
| `PROPOLIS_VENDOR_<V>_RATE_WINDOW_HOURS` | no | `1` (`config.rs:33`) | parse_u32 |
| `PROPOLIS_VENDOR_DSHIELD_USER` | no | none | DShield only (`:460`); if set with a key, composed as `{user}:{key}` into the single key slot (`:463-466`). User alone (no key) is ignored. |

Concrete literal names the code reads (the `<V>` rows above, instantiated for each vendor):
`PROPOLIS_VENDOR_ABUSEIPDB_KEY`, `PROPOLIS_VENDOR_ABUSEIPDB_URL`,
`PROPOLIS_VENDOR_DSHIELD_KEY`, `PROPOLIS_VENDOR_DSHIELD_URL`,
`PROPOLIS_VENDOR_OTX_KEY`, `PROPOLIS_VENDOR_OTX_URL`.

Default base URLs (`crates/review/src/vendor/*.rs`):
- abuseipdb: `https://api.abuseipdb.com` (`abuseipdb.rs:21`)
- dshield: `https://www.dshield.org` (`dshield.rs:21`)
- otx: `https://otx.alienvault.com` (`otx.rs:16`)

### Feed

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_FEED_ENABLED` | no | `true` (`config.rs:476`) | bool_flag |
| `PROPOLIS_FEED_OUTPUT_DIR` | no | `/var/lib/propolis/feed/current` (`config.rs:21`) | path |
| `PROPOLIS_FEED_BUILD_INTERVAL_SECS` | no | `900` (`config.rs:22`) | positive u64; zero → abort |
| `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` | no | `24` (`config.rs:23`) | positive u64; ×3600 → Duration; zero → abort |
| `PROPOLIS_FEED_STANDARD_TTL_HOURS` | no | `48` (`config.rs:24`) | positive u64; zero → abort |
| `PROPOLIS_FEED_ALLOWLIST` | no | `""` | comma-sep CIDR list (`parse_cidr_list:264`); **bare IP without prefix is rejected**; invalid entry → abort |
| `PROPOLIS_FEED_DELIST` | no | `""` | comma-sep IP list (`parse_ip_list:332`); invalid → abort |
| `PROPOLIS_FEED_ASN_ALLOWLIST` | no | `""` | comma-sep AS numbers, optional `AS`/`as` prefix (`parse_asn_list:280`); invalid → abort. Inert unless the GeoIP ASN DB loads (see [interactions](#interactions)). |
| `PROPOLIS_FEED_WINDOWS` | no | `24h,7d,30d,60d,90d` (`config.rs:29`) | comma-sep `<count>h`/`<count>d` (`parse_window_list:308`). Only `h`/`d` units; count must be a positive int; **any malformed entry → abort** (fails closed, not skipped). Empty string → no retention feeds. **Unified daemon only.** |

### Console

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_CONSOLE_BIND` | no | `127.0.0.1:8080` (`config.rs:30`) | must parse as `ip:port` SocketAddr; invalid → abort (`:512`) |
| `PROPOLIS_CONSOLE_PASSWORD` | **yes** | — | `require_env`; absent/empty → **abort** (`:517`) |
| `PROPOLIS_CONSOLE_SESSION_SECRET` | no | random 32 bytes generated at startup (`:374-377`) | if set, must be exactly 64 hex chars (32 bytes), else abort (`:379-388`). Sessions are in-memory, so a fresh secret per restart only invalidates sessions already dropped on restart. |
| `PROPOLIS_GEOIP_DIR` | no | none (`Option`, `:480`) | directory of GeoLite2 `.mmdb` files; empty string treated as unset; missing dir/file degrades gracefully. GeoIP enrichment is **local file reads, not network**. |
| `PROPOLIS_CONSOLE_RDNS_ENABLED` | no | `false` (`config.rs:484`) | bool_flag; opt-in forward-confirmed reverse DNS — the one outbound DNS lookup. Default off. See [outbound controls](../security/outbound-controls.md). |
| `PROPOLIS_CONSOLE_TRUSTED_PROXY` | no | `false` | bool_flag; set when the console sits behind a TLS reverse proxy so session cookies are always marked `Secure` (a same-host proxy connects over loopback, which would otherwise drop the flag on a real HTTPS hop). |
| `PROPOLIS_CONSOLE_METRICS_TOKEN` | no | none | if set, `/metrics` requires `Authorization: Bearer <token>` (constant-time compare); unset leaves `/metrics` open — safe only on a loopback bind. Defense in depth for a non-loopback bind. |

The console serves plain HTTP on a loopback `TcpListener`; there is no in-process
TLS. Any TLS is operator-provided (e.g. a reverse proxy) [inferred]. See
[networking and TLS](../operations/networking-tls.md).

### VirusTotal (unified daemon only)

Opt-in egress, default off. See [integrations](integrations.md) and
[outbound controls](../security/outbound-controls.md).

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_VT_KEY` | no | `""` (`config.rs:520`) | empty → VT disabled regardless of `_ENABLED` |
| `PROPOLIS_VT_ENABLED` | no | `false` (`:521`) | bool_flag; **and** a non-empty key required to actually enable (`&& !vt_api_key.is_empty()`) |
| `PROPOLIS_VT_UPLOAD` | no | `false` (`:522`) | bool_flag; upload-unknown-samples opt-in |
| `PROPOLIS_VT_SCAN_INTERVAL_SECS` | no | `300` (`:523`) | parse_u32 (zero allowed); unparseable → abort. No `PROPOLIS_VT_URL` override exists. |

### Malware fetcher (unified daemon only)

Opt-in egress, off by default. See [outbound controls](../security/outbound-controls.md)
and [rate limits and budgets](rate-limits-and-budgets.md).

| Variable | Req | Default | Max | Bounds / fail |
|---|---|---|---|---|
| `PROPOLIS_FETCH_ENABLED` | no | `false` (`config.rs:527`) | — | bool_flag |
| `PROPOLIS_FETCH_INTERVAL_SECS` | no | `10` (`:34`) | `86400` (`:60`) | bounded positive u64; zero/over-max → abort |
| `PROPOLIS_FETCH_MAX_BYTES` | no | `10_000_000` (`:35`) | `500_000_000` (`:52`) | bounded positive u64 → usize; **zero → abort** (would disable the byte guard); over-max → abort |
| `PROPOLIS_FETCH_MAX_PER_HOST_HOUR` | no | `12` (`:36`) | `1000` (`:56`) | bounded positive u64 → u32 |
| `PROPOLIS_FETCH_MAX_HOPS` | no | `3` (`:37`) | `255` (u8) | bounded_u8; **zero allowed** (no redirects); >255 → abort |
| `PROPOLIS_FETCH_MAX_DEPTH` | no | `2` (`:38`) | `255` (u8) | bounded_u8; zero allowed (no recursion) |
| `PROPOLIS_FETCH_DAILY_CAP` | no | `200` (`:39`) | `10_000` (`:57`) | bounded positive u64 → u32 |
| `PROPOLIS_FETCH_BATCH_SIZE` | no | `20` (`:40`) | `1000` (`:58`) | bounded positive u64 → usize |
| `PROPOLIS_FETCH_CONNECT_TIMEOUT_SECS` | no | `10` (`:41`) | `300` (`:55`) | bounded positive u64 |
| `PROPOLIS_FETCH_READ_TIMEOUT_SECS` | no | `10` (`:42`) | `300` | bounded positive u64 |
| `PROPOLIS_FETCH_TOTAL_TIMEOUT_SECS` | no | `30` (`:43`) | `300` | bounded positive u64 |
| `PROPOLIS_FETCH_USER_AGENT` | no | `Wget/1.21.3` (`:64`) | — | blank → default |
| `PROPOLIS_FETCH_OWN_IPS` | no | `""` | — | comma-sep IP list (`parse_ip_list`); invalid → abort. Unioned with live-interface IPs for the SSRF self-target guard. |

Fetcher runtime fail-closed (`main.rs:828-835`): if `PROPOLIS_FETCH_OWN_IPS` is
unset **and** interface enumeration returns empty, the fetcher **refuses to run**
(logs an error and returns). If the own-IPs set has only private/loopback/
link-local addresses (a NAT'd node whose public WAN IP is on no interface), it
**warns but runs** (`main.rs:843-852`); set `PROPOLIS_FETCH_OWN_IPS` to the
public egress IP for self-target protection.

### Operational self-alerting (ops-alert)

`crates/propolis/src/ops_alert/config.rs`. Opt-in ntfy POST egress, default off.
Parsed via an injectable getter over `env::var` that treats blank as absent.
Helpers: `get_bool` (`:35`) accepts `true|1|yes|on` (case-insensitive), else
default — broader than `parse_bool_flag`. `get_u64`/`get_secs` (`:55`/`:45`):
unset → default; unparseable → abort; **below min → abort**. `get_pct` (`:96`):
enforces `1..=100`; 0 and >100 → abort. `get_u32` (`:81`): u64 range-checked to
u32.

| Variable | Req | Default | Min/bounds | Notes |
|---|---|---|---|---|
| `PROPOLIS_OPS_ENABLED` | no | `false` (`config.rs:119`) | — | opt-in; a deployment predating ops-alert still starts |
| `PROPOLIS_OPS_NTFY_URL` | **yes if enabled** | `""` when disabled | — | enabled + missing → **abort** (`:125`). A monitor that cannot page must not start silently. |
| `PROPOLIS_OPS_NTFY_TOPIC` | **yes if enabled** | `""` when disabled | — | enabled + missing → abort (`:127`). The `propolis-ops` value seen in tests is not a runtime default. |
| `PROPOLIS_OPS_NTFY_TOKEN` | no | none (`:140`) | — | optional bearer token |
| `PROPOLIS_OPS_POLL_INTERVAL_SECS` | no | `30` (`:141`) | min 1 | |
| `PROPOLIS_OPS_REPAGE_COOLDOWN_SECS` | no | `5400` (`:142`) | min 1 | |
| `PROPOLIS_OPS_STALL_FOR_SECS` | no | `600` (`:143`) | min 1 | |
| `PROPOLIS_OPS_CAPACITY_FREE_PCT` | no | `15` (`:144`) | 1..=100 | 0/>100 → abort |
| `PROPOLIS_OPS_FEED_STALE_MULTIPLE` | no | `2` (`:145`) | min 1 | u32 |
| `PROPOLIS_OPS_VENDOR_WINDOW_SECS` | no | `3600` (`:146`) | min 1 | |
| `PROPOLIS_OPS_VENDOR_FAIL_PCT` | no | `50` (`:147`) | 1..=100 | |
| `PROPOLIS_OPS_VENDOR_MIN_SAMPLES` | no | `20` (`:148`) | min 1 | u32 |
| `PROPOLIS_OPS_BACKLOG_MAX` | no | `500` (`:149`) | min 1 | u64 |
| `PROPOLIS_OPS_BACKLOG_FOR_SECS` | no | `900` (`:150`) | min 1 | |
| `PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS` | no | `21600` (`:151`) | min 1 | |

---

## Standalone service binaries

Each reads a strict subset of the unified daemon's variables with the same
defaults and the same strict-parse/fail-closed rules unless noted.

- **`console`** (`crates/console/src/main.rs:112`): `DATABASE_URL` (req),
  `PROPOLIS_CONSOLE_BIND`, `PROPOLIS_CONSOLE_PASSWORD` (req, empty→abort),
  `PROPOLIS_CONSOLE_SESSION_SECRET`, `PROPOLIS_FEED_OUTPUT_DIR`,
  `PROPOLIS_GEOIP_DIR`, `PROPOLIS_CONSOLE_RDNS_ENABLED`, `RUST_LOG`. Two
  divergences from the unified daemon: `PROPOLIS_FEED_OUTPUT_DIR` is **not**
  empty-filtered (`main.rs:130`), so an explicitly-empty value becomes
  `Some(PathBuf::from(""))`; and `PROPOLIS_CONSOLE_RDNS_ENABLED` accepts
  `true|1|yes` case-insensitive (`main.rs:136`), broader than `bool_flag`.
- **`feed`** (`crates/feed/src/main.rs:182`): `DATABASE_URL` (req),
  `PROPOLIS_FEED_OUTPUT_DIR`, `PROPOLIS_FEED_BUILD_INTERVAL_SECS`,
  `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS`, `PROPOLIS_FEED_STANDARD_TTL_HOURS`,
  `PROPOLIS_FEED_ALLOWLIST`, `PROPOLIS_FEED_DELIST`,
  `PROPOLIS_FEED_ASN_ALLOWLIST`, `PROPOLIS_GEOIP_DIR`. **Does not read
  `PROPOLIS_FEED_WINDOWS`** (no `all-{label}` retention feeds in standalone).
- **`intake`** (`crates/intake/src/main.rs:145`): `DATABASE_URL` (req),
  `PROPOLIS_CURSOR_DIR`, `PROPOLIS_POLL_INTERVAL_MS`, `PROPOLIS_SENSOR_LOGS`
  (req, empty→abort).
- **`review`** (`crates/review/src/main.rs:198`): `DATABASE_URL` (req),
  `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS`, `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS`, and
  the full `PROPOLIS_VENDOR_*` set (`_KEY`/`_URL`/`_ENABLED`/`_COOLDOWN_HOURS`/
  `_RATE_LIMIT`/`_RATE_WINDOW_HOURS` for abuseipdb/dshield/otx plus
  `PROPOLIS_VENDOR_DSHIELD_USER`), same defaults as unified. **Does not read the
  VT or FETCH variables.**

---

## Sensor binaries

Sensors are always separate processes. They have **no compiled-in default port**;
the bind address comes from config/env set by the deploy units. See
[ports and protocols](ports-and-protocols.md).

### Standard sensors (strict parse) — ssh, telnet, http, ftp, redis, adb, catchall

Shared `ConnectionBounds` pattern via each crate's local
`parse_positive_u64`/`parse_positive_u32`: unset → default; **present-but-zero or
unparseable → abort startup** (no upper clamp — a very large timeout/bytes value
is accepted). `parse_wan_map` (e.g. `sensor-ssh/src/main.rs:110`): comma-sep
`local_ip=wan_ip`; empty/absent → empty map (valid: no WAN attribution, stamps a
null `wan_ip`); invalid entry → abort.

| Sensor | Prefix `<P>` | Bind variable (required) | Log path default |
|---|---|---|---|
| ssh | `PROPOLIS_SSH_` | `PROPOLIS_SSH_BIND` (unset → abort, `main.rs:130`) | `/var/log/propolis/ssh/events.jsonl` |
| telnet | `PROPOLIS_TELNET_` | `PROPOLIS_TELNET_BIND` | `/var/log/propolis/telnet/events.jsonl` |
| http | `PROPOLIS_HTTP_` | `PROPOLIS_HTTP_BIND` | `/var/log/propolis/http/events.jsonl` |
| ftp | `PROPOLIS_FTP_` | `PROPOLIS_FTP_BIND` | `/var/log/propolis/ftp/events.jsonl` |
| redis | `PROPOLIS_REDIS_` | `PROPOLIS_REDIS_BIND` | `/var/log/propolis/redis/events.jsonl` |
| adb | `PROPOLIS_ADB_` | `PROPOLIS_ADB_BIND` | `/var/log/propolis/adb/events.jsonl` |
| catchall | `CATCHALL_` (not `PROPOLIS_`) | `CATCHALL_BIND_ADDRS` (comma-sep list, empty→abort) | `catchall-events.jsonl` (relative) |

Common per-sensor variables (each uses its own prefix; catchall uses `CATCHALL_`):

| Variable | Req | Default | Notes |
|---|---|---|---|
| `<P>WAN_MAP` (catchall `CATCHALL_WAN_MAP`) | no | empty map | invalid entry → abort |
| `<P>LOG_PATH` (catchall `CATCHALL_LOG_PATH`) | no | see table above | |
| `<P>READ_TIMEOUT_MS` | no | `30_000` (catchall `5_000`) | ms; zero → abort |
| `<P>IDLE_TIMEOUT_MS` | no | `60_000` (catchall `5_000`) | ms; zero → abort |
| `<P>MAX_DURATION_SECS` | no | `600` (catchall `30`) | secs; zero → abort |
| `<P>MAX_CAPTURED_BYTES` | no | `1_000_000` (catchall `4_096`) | bytes; zero → abort |
| `<P>MAX_CONCURRENT` | no | `256` (http `512`) | u32; zero → abort |

Literal names for the sensors whose `main.rs` defines these as explicit constants (the `<P>` rows
above, instantiated): ssh — `PROPOLIS_SSH_READ_TIMEOUT_MS`, `PROPOLIS_SSH_IDLE_TIMEOUT_MS`,
`PROPOLIS_SSH_MAX_DURATION_SECS`, `PROPOLIS_SSH_MAX_CAPTURED_BYTES`, `PROPOLIS_SSH_MAX_CONCURRENT`,
`PROPOLIS_SSH_LOG_PATH`, `PROPOLIS_SSH_WAN_MAP`; catchall — `CATCHALL_READ_TIMEOUT_MS`,
`CATCHALL_IDLE_TIMEOUT_MS`, `CATCHALL_MAX_DURATION_SECS`, `CATCHALL_MAX_CAPTURED_BYTES`,
`CATCHALL_MAX_CONCURRENT`.

Sensor-specific extras:
- **ssh** (`crates/sensor-ssh/src/main.rs`): `PROPOLIS_SSH_HOST_KEY_PATH`
  (default `/var/lib/propolis/ssh/host_key`, `:48`), `PROPOLIS_SSH_SPOOL_DIR`
  (default `/var/spool/propolis/ssh`, `:47`), `PROPOLIS_SSH_BANNER` (default =
  persona `OPENSSH_VERSION` = `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`, `main.rs:44` +
  `persona.rs:41`; blank → default).
- **ftp** (`crates/sensor-ftp/src/main.rs`): `PROPOLIS_FTP_SPOOL_DIR` (default
  `/var/spool/propolis/ftp`, `:21`).
- **adb** (`crates/sensor-adb/src/main.rs`): `PROPOLIS_ADB_SPOOL_DIR` (default
  `/var/spool/propolis/adb`, `:32`).
- **http**: `MAX_CONCURRENT` default is `512` (`crates/sensor-http/src/main.rs:24`).
- **catchall**: no spool variable (never spools file bodies, `main.rs:47-49`).

### Lenient sensors — cred, smtp

Invalid or zero bound → **silent default**, not abort.

- **sensor-smtp** (`crates/sensor-smtp/src/main.rs`): `PROPOLIS_SMTP_BIND` (req;
  unset → `exit(1)` `:47`, invalid → `exit(1)` `:54`), `PROPOLIS_SMTP_WAN_MAP`
  (invalid entries silently skipped, `:16-26`), `PROPOLIS_SMTP_LOG_PATH` (default
  `/var/log/propolis/smtp/events.jsonl`), `PROPOLIS_SMTP_READ_TIMEOUT_MS`
  (`30_000`), `_IDLE_TIMEOUT_MS` (`60_000`), `_MAX_DURATION_SECS` (`600`),
  `_MAX_CAPTURED_BYTES` (`1_000_000`), `_MAX_CONCURRENT` (`256`).
- **sensor-cred** (`crates/sensor-cred/src/main.rs`): multi-protocol
  (VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Bind variables `PROPOLIS_CRED_VNC_BIND`,
  `_MYSQL_BIND`, `_MSSQL_BIND`, `_PG_BIND`, `_MONGO_BIND` (`main.rs:77-81`). At
  least one required — none set → `exit(1)` (`:93-98`); a set-but-invalid bind →
  `exit(1)` (`:87-88`); all-configured-fail-to-bind → `exit(1)` (`:122-125`).
  `PROPOLIS_CRED_WAN_MAP` (invalid skipped), `PROPOLIS_CRED_LOG_DIR` (default
  `/var/log/propolis/cred`, per-protocol file `<protocol>.jsonl`). Bounds:
  `PROPOLIS_CRED_READ_TIMEOUT_MS` (`30_000`), `_IDLE_TIMEOUT_MS` (`60_000`),
  `_MAX_DURATION_SECS` (**`60`**, differs from others' 600), `_MAX_CAPTURED_BYTES`
  (**`100_000`**, differs from others' 1_000_000), `_MAX_CONCURRENT` (`256`).

---

## Interactions

- **VT enable requires both**: `PROPOLIS_VT_ENABLED=true` **and** a non-empty
  `PROPOLIS_VT_KEY` (`config.rs:521`). Either missing → VT off.
- **Vendor enable requires key**: `PROPOLIS_VENDOR_<V>_ENABLED=true` with an
  empty `_KEY` → forced disabled and warns (`config.rs:399-405`, review
  `main.rs:150-156`).
- **DShield user+key composition**: `PROPOLIS_VENDOR_DSHIELD_USER` +
  `PROPOLIS_VENDOR_DSHIELD_KEY` compose to `{user}:{key}` in the single key slot
  (`config.rs:463-466`). User alone is ignored.
- **ASN suppression needs GeoIP**: `PROPOLIS_FEED_ASN_ALLOWLIST` is inert unless
  `PROPOLIS_GEOIP_DIR` is set and the GeoLite2-ASN DB loads. The unified daemon
  warns when the ASN allowlist is set but `GEOIP_DIR` is unset (`main.rs:686`) or
  the ASN DB failed to load (`main.rs:693`).
- **Fetcher SSRF guard vs OWN_IPS**: `PROPOLIS_FETCH_OWN_IPS` unions with live
  interface IPs; an empty union → the fetcher refuses to run; a union without any
  public address → warn-only.
- **Console session secret**: regenerated per restart if unset; harmless because
  sessions are in-memory (dropped on restart anyway).
- **TTL/interval units**: feed TTL variables are HOURS (×3600 → Duration); most
  timeouts are MS or SECS as named in the variable suffix.

## Related

- [Ports and protocols](ports-and-protocols.md) — bind addresses/ports
- [Filesystem paths](filesystem-paths.md) — log/spool/cursor/feed directories
- [Integrations](integrations.md) — VirusTotal, vendor submitters, ntfy, GeoLite2
- [Rate limits and budgets](rate-limits-and-budgets.md) — fetcher/vendor budgets
- [Outbound controls](../security/outbound-controls.md) — the gated egress paths
- [Configuration](../operations/configuration.md) — operator configuration guide
