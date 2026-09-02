<!--
title: Environment variables
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-01
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

1. **Unified daemon** `propolis` - one `load_config()`
   (`crates/propolis/src/config.rs:429`) parses intake, review, feed, console,
   VirusTotal, malware-fetcher, and ops-alert config from a single env set
   (`EnvironmentFile=/etc/propolis/propolis.env`). It does **not** read sensor
   `*_BIND`/`*_WAN_MAP` variables; it consumes sensor **log files** via
   `PROPOLIS_SENSOR_LOGS`.
2. **Standalone service binaries** - `intake`, `review`, `feed`, `console` - each with its own `load_config_from_env()` and its own
   `/etc/propolis/<name>.env`. Their variables are a strict subset of the unified
   daemon's (e.g. standalone `feed` does not read `PROPOLIS_FEED_WINDOWS`;
   standalone `review` does not read the VT or fetch variables).
3. **Sensor binaries** - always separate processes regardless of run mode, each
   with its own `/etc/propolis/<name>.env`.

Which run mode a given deployment uses is an operator choice; both sets of
`.service` units exist.

## Parse and fail semantics

Two fail-closed idioms recur; they are **not** uniform:

- **Strict parse** - `propolis`, `intake`, `review`, `feed`, `console`, and
  sensors `ssh`/`telnet`/`http`/`ftp`/`redis`/`adb`/`catchall`: a
  present-but-invalid or present-but-zero numeric bound **aborts startup**.
- **Lenient parse** - sensors `cred` and `smtp` **only**: an invalid or zero
  bound silently falls back to the default (`parse_positive_u64` filters `>0`
  then `unwrap_or(default)`, `crates/sensor-cred/src/main.rs:29-33`,
  `crates/sensor-smtp/src/main.rs:28-32`).

Unified daemon (`config.rs`) parse helpers:

| Helper | Unset/empty | Invalid | Zero | Other |
|---|---|---|---|---|
| `require_env` (`:168`) | `Missing` (abort) | - | - | - |
| `parse_positive_u64` (`:175`) | default | `Invalid` (abort) | `Invalid` (abort) - "zero never means unlimited" | - |
| `parse_bounded_positive_u64` (`:199`) | default | abort | abort | `> max` → abort |
| `parse_u32` (`:215`) | default | abort | allowed | - |
| `parse_bounded_u8` (`:351`) | default | abort | allowed (0 = maximally strict) | `> 255` → abort (no wrap) |
| `parse_bool_flag` (`:227`) | default | - | - | case-insensitive `true`/`false` only; **any** other value (incl. `1`, `yes`) → default |

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
| `PROPOLIS_SENSOR_LOGS` | **yes** | - | comma-separated `name:path` pairs (`config.rs:236-262`). Empty list, or an entry missing name/path → **abort**. At least one pair required. |
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
| `PROPOLIS_CONSOLE_PASSWORD` | **yes** | - | `require_env`; absent/empty → **abort** (`:517`) |
| `PROPOLIS_CONSOLE_SESSION_SECRET` | no | random 32 bytes generated at startup (`:374-377`) | if set, must be exactly 64 hex chars (32 bytes), else abort (`:379-388`). Sessions are in-memory, so a fresh secret per restart only invalidates sessions already dropped on restart. |
| `PROPOLIS_CONSOLE_MAX_SOURCE_IPS` | no | `3` (`routes/samples.rs`) | how many attacker IPs the Samples page shows inline per sample before collapsing to "+N more"; blank/zero/unparseable falls back to the default (zero never means unlimited) |
| `PROPOLIS_SPOOL_ROOT` | no | `/var/spool/propolis` (`review/src/spool.rs`) | root of the spool tree. Per-sensor spool dirs default under it, but each sensor's own `PROPOLIS_<SENSOR>_SPOOL_DIR` still wins, so the platform side (VT scan, retention, console) resolves the same directory the sensor actually writes to. Must match what `deploy/install.sh` provisions and what the units grant in `ReadWritePaths`. |
| `PROPOLIS_GEOIP_DIR` | no | none (`Option`, `:480`) | directory of GeoLite2 `.mmdb` files; empty string treated as unset; missing dir/file degrades gracefully. GeoIP enrichment is **local file reads, not network**. |
| `PROPOLIS_CONSOLE_RDNS_ENABLED` | no | `false` (`config.rs:484`) | bool_flag; opt-in forward-confirmed reverse DNS - the one outbound DNS lookup. Default off. See [outbound controls](../security/outbound-controls.md). |
| `PROPOLIS_CONSOLE_TRUSTED_PROXY` | no | `false` | bool_flag; set when the console sits behind a TLS reverse proxy so session cookies are always marked `Secure` (a same-host proxy connects over loopback, which would otherwise drop the flag on a real HTTPS hop). |
| `PROPOLIS_CONSOLE_METRICS_TOKEN` | no | none | if set, `/metrics` requires `Authorization: Bearer <token>` (constant-time compare); unset leaves `/metrics` open - safe only on a loopback bind. Defense in depth for a non-loopback bind. |

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
| `PROPOLIS_FETCH_ENABLED` | no | `false` (`config.rs:527`) | - | bool_flag |
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
| `PROPOLIS_FETCH_USER_AGENT` | no | `Wget/1.21.3` (`:64`) | - | blank → default |
| `PROPOLIS_FETCH_OWN_IPS` | no | `""` | - | comma-sep IP list (`parse_ip_list`); invalid → abort. Unioned with live-interface IPs for the SSRF self-target guard. |

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
default - broader than `parse_bool_flag`. `get_u64`/`get_secs` (`:55`/`:45`):
unset → default; unparseable → abort; **below min → abort**. `get_pct` (`:96`):
enforces `1..=100`; 0 and >100 → abort. `get_u32` (`:81`): u64 range-checked to
u32.

| Variable | Req | Default | Min/bounds | Notes |
|---|---|---|---|---|
| `PROPOLIS_OPS_ENABLED` | no | `false` (`config.rs:119`) | - | opt-in; a deployment predating ops-alert still starts |
| `PROPOLIS_OPS_NTFY_URL` | **yes if enabled** | `""` when disabled | - | enabled + missing → **abort** (`:125`). A monitor that cannot page must not start silently. |
| `PROPOLIS_OPS_NTFY_TOPIC` | **yes if enabled** | `""` when disabled | - | enabled + missing → abort (`:127`). The `propolis-ops` value seen in tests is not a runtime default. |
| `PROPOLIS_OPS_NTFY_TOKEN` | no | none (`:140`) | - | optional bearer token |
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

## Collector/control-plane split binaries (SP-A)

Two additional binaries, each its own process with its own `load_config_from_env()` and its own
`/etc/propolis/<name>.env` - the disposable-collector / control-plane topology
(`deploy/gateway.service`, `deploy/shipper.service`, `deploy/collector.env.example`,
`deploy/control-plane.env.example`). Neither reads `DATABASE_URL` or any vendor/VT/console
variable; that boundary is the entire point of the split.

### `gateway`

`crates/gateway/src/config.rs`. Control-plane-side mTLS ingest listener. All fields are strict
parse (present-but-zero or unparseable → **abort**), matching the sensor pattern.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_GATEWAY_BIND` | **yes** | - | single `ip:port`; absent → abort (`ConfigError::NoBind`); unparseable → abort (`ConfigError::InvalidBind`) |
| `PROPOLIS_GATEWAY_CA_CERT_PATH` | **yes** | - | PEM path used to verify collector client certificates; absent → abort |
| `PROPOLIS_GATEWAY_SERVER_CERT_PATH` | **yes** | - | PEM path the gateway presents in the TLS handshake; absent → abort |
| `PROPOLIS_GATEWAY_SERVER_KEY_PATH` | **yes** | - | PEM path, private key for the server cert above; absent → abort |
| `PROPOLIS_GATEWAY_SPOOL_DIR` | no | `/var/spool/propolis/gateway` | root of the per-collector spool tree; one `events.jsonl` per collector under `<root>/<collector_id>/` (`crates/gateway/src/spool.rs`) |
| `PROPOLIS_GATEWAY_STATE_DIR` | no | `/var/lib/propolis/gateway` | gateway's own state directory |
| `PROPOLIS_GATEWAY_MAX_CONCURRENT` | no | `64` | positive u32; zero/unparseable → abort |
| `PROPOLIS_GATEWAY_MAX_DURATION_SECS` | no | `120` | positive u64 secs; zero/unparseable → abort |
| `PROPOLIS_GATEWAY_READ_TIMEOUT_MS` | no | `30000` | positive u64 ms; zero/unparseable → abort |
| `PROPOLIS_GATEWAY_IDLE_TIMEOUT_MS` | no | `60000` | positive u64 ms; zero/unparseable → abort |

The gateway's own read loop bounds every frame at `collector_wire::frame::MAX_FRAME_LEN` before
allocating, so `ConnectionBounds`'s `max_captured_bytes` field is fixed to that ceiling internally
and is **not** exposed as a separate env var.

### `shipper`

`crates/shipper/src/config.rs`. Collector-side process that tails this collector's sensor logs and
ships batches to the gateway over mTLS. All fields are strict parse; the collector id below is
additionally cross-checked against the client certificate's CommonName at startup.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_SHIPPER_GATEWAY_ADDR` | **yes** | - | `host:port` socket address of the gateway; absent/unparseable → abort |
| `PROPOLIS_SHIPPER_GATEWAY_DNS` | **yes** | - | DNS name checked against the gateway's TLS server certificate during the mTLS handshake; absent → abort |
| `PROPOLIS_SHIPPER_CA_CERT_PATH` | **yes** | - | PEM path used to verify the gateway's server certificate; absent → abort |
| `PROPOLIS_SHIPPER_CLIENT_CERT_PATH` | **yes** | - | PEM path, this collector's client certificate; absent → abort |
| `PROPOLIS_SHIPPER_CLIENT_KEY_PATH` | **yes** | - | PEM path, private key for the client cert above; absent → abort |
| `PROPOLIS_COLLECTOR_ID` (deprecated alias `PROPOLIS_SHIPPER_COLLECTOR_ID`, still read) | **yes** | - | this collector's identity; **must equal** the CommonName baked into `PROPOLIS_SHIPPER_CLIENT_CERT_PATH` or the shipper refuses to start (`validate_collector_id`, `ConfigError::CollectorIdMismatch`). Same variable the four body-capturing sensors read (see "Outbox manifest" below) - it must be the SAME value everywhere on this collector, or the provenance join on `(collector_id, occurrence_id)` silently breaks attribution. |
| `PROPOLIS_SHIPPER_SENSOR_LOGS` | **yes** | - | comma-separated `name:path` pairs, same grammar as `PROPOLIS_SENSOR_LOGS`; empty or a malformed entry → abort; at least one pair required |
| `PROPOLIS_SHIPPER_CURSOR_DIR` | no | `/var/lib/propolis/shipper/cursors` | per-log tail cursor persistence |
| `PROPOLIS_SHIPPER_STATE_DIR` | no | `/var/lib/propolis/shipper/state` | shipper's own state directory |
| `PROPOLIS_SHIPPER_POLL_INTERVAL_MS` | no | `1000` | positive u64 ms; zero/unparseable → abort |
| `PROPOLIS_SHIPPER_MAX_RECORDS_PER_BATCH` | no | `15` (`batcher::MAX_RECORDS_FRAME_SAFE`) | positive u64 → usize; zero/unparseable → abort |
| `PROPOLIS_SHIPPER_RETRY_BACKOFF_MS` | no | `2000` | positive u64 ms; zero/unparseable → abort |

`PROPOLIS_SHIPPER_SENSOR_LOGS`'s `name` is used only for cursor keying and logging - every sensor
log on a collector ships through one seq/hash chain keyed by `PROPOLIS_COLLECTOR_ID`
(via the gateway's verified client-certificate CommonName), not by the per-log name.

On the control-plane side, intake's `PROPOLIS_SENSOR_LOGS` is re-pointed at the gateway's
per-collector spool (one `name:path` entry per collector, not per sensor) - see
[filesystem paths](filesystem-paths.md) and `deploy/control-plane.env.example`.

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

### Standard sensors (strict parse) - ssh, telnet, http, ftp, redis, adb, catchall

Shared `ConnectionBounds` pattern via each crate's local
`parse_positive_u64`/`parse_positive_u32`: unset → default; **present-but-zero or
unparseable → abort startup** (no upper clamp - a very large timeout/bytes value
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
| catchall | `PROPOLIS_CATCHALL_` (bare `CATCHALL_` still read, deprecated) | `PROPOLIS_CATCHALL_BIND_ADDRS` (comma-sep list, empty→abort) | `catchall-events.jsonl` (relative) |

Common per-sensor variables (each uses its own prefix; catchall uses `PROPOLIS_CATCHALL_`, with the bare `CATCHALL_` spelling still read but deprecated):

| Variable | Req | Default | Notes |
|---|---|---|---|
| `<P>WAN_MAP` (catchall `PROPOLIS_CATCHALL_WAN_MAP`) | no | empty map | invalid entry → abort |
| `<P>LOG_PATH` (catchall `PROPOLIS_CATCHALL_LOG_PATH`) | no | see table above | |
| `<P>READ_TIMEOUT_MS` | no | `30_000` (catchall `5_000`) | ms; zero → abort |
| `<P>IDLE_TIMEOUT_MS` | no | `60_000` (catchall `5_000`) | ms; zero → abort |
| `<P>MAX_DURATION_SECS` | no | `600` (catchall `30`) | secs; zero → abort |
| `<P>MAX_CAPTURED_BYTES` | no | `1_000_000` (catchall `4_096`) | bytes; zero → abort |
| `<P>MAX_CONCURRENT` | no | `256` (http `512`) | u32; zero → abort |

The `<P>` rows above, instantiated per sensor (each name is read literally by that sensor's
`main.rs`):

- ssh: `PROPOLIS_SSH_READ_TIMEOUT_MS`, `PROPOLIS_SSH_IDLE_TIMEOUT_MS`,
  `PROPOLIS_SSH_MAX_DURATION_SECS`, `PROPOLIS_SSH_MAX_CAPTURED_BYTES`, `PROPOLIS_SSH_MAX_CONCURRENT`,
  `PROPOLIS_SSH_LOG_PATH`, `PROPOLIS_SSH_WAN_MAP`.
- telnet: `PROPOLIS_TELNET_READ_TIMEOUT_MS`, `PROPOLIS_TELNET_IDLE_TIMEOUT_MS`,
  `PROPOLIS_TELNET_MAX_DURATION_SECS`, `PROPOLIS_TELNET_MAX_CAPTURED_BYTES`,
  `PROPOLIS_TELNET_MAX_CONCURRENT`, `PROPOLIS_TELNET_LOG_PATH`, `PROPOLIS_TELNET_WAN_MAP`.
- adb: `PROPOLIS_ADB_READ_TIMEOUT_MS`, `PROPOLIS_ADB_IDLE_TIMEOUT_MS`,
  `PROPOLIS_ADB_MAX_DURATION_SECS`, `PROPOLIS_ADB_MAX_CAPTURED_BYTES`, `PROPOLIS_ADB_MAX_CONCURRENT`,
  `PROPOLIS_ADB_LOG_PATH`, `PROPOLIS_ADB_WAN_MAP`.
- ftp: `PROPOLIS_FTP_READ_TIMEOUT_MS`, `PROPOLIS_FTP_IDLE_TIMEOUT_MS`,
  `PROPOLIS_FTP_MAX_DURATION_SECS`, `PROPOLIS_FTP_MAX_CAPTURED_BYTES`, `PROPOLIS_FTP_MAX_CONCURRENT`,
  `PROPOLIS_FTP_LOG_PATH`, `PROPOLIS_FTP_WAN_MAP`.
- http: `PROPOLIS_HTTP_READ_TIMEOUT_MS`, `PROPOLIS_HTTP_IDLE_TIMEOUT_MS`,
  `PROPOLIS_HTTP_MAX_DURATION_SECS`, `PROPOLIS_HTTP_MAX_CAPTURED_BYTES`,
  `PROPOLIS_HTTP_MAX_CONCURRENT`, `PROPOLIS_HTTP_LOG_PATH`, `PROPOLIS_HTTP_WAN_MAP`.
- redis: `PROPOLIS_REDIS_READ_TIMEOUT_MS`, `PROPOLIS_REDIS_IDLE_TIMEOUT_MS`,
  `PROPOLIS_REDIS_MAX_DURATION_SECS`, `PROPOLIS_REDIS_MAX_CAPTURED_BYTES`,
  `PROPOLIS_REDIS_MAX_CONCURRENT`, `PROPOLIS_REDIS_LOG_PATH`, `PROPOLIS_REDIS_WAN_MAP`.
- catchall: `PROPOLIS_CATCHALL_READ_TIMEOUT_MS`, `PROPOLIS_CATCHALL_IDLE_TIMEOUT_MS`,
  `PROPOLIS_CATCHALL_MAX_DURATION_SECS`, `PROPOLIS_CATCHALL_MAX_CAPTURED_BYTES`,
  `PROPOLIS_CATCHALL_MAX_CONCURRENT`.
- smtp and cred: listed under "Lenient sensors" below, since their invalid-value behavior differs.

The gate `every_env_var_the_code_reads_is_documented_in_the_env_var_reference`
(`crates/propolis/tests/docs_agreement.rs`) checks each of these names literally against this file,
so a shorthand such as `_IDLE_TIMEOUT_MS` does not count as documentation.

### Deprecated catchall aliases (still read, do not use in new configs)

`sensor-catchall` originally shipped with bare, unprefixed names - the only sensor that did. It now
uses the `PROPOLIS_CATCHALL_` prefix like every other sensor, and still reads the bare spelling as a
migration path, logging a deprecation warning naming the canonical replacement. An existing config
keeps working; write new ones with the prefix. The bare names read are `CATCHALL_BIND_ADDRS`,
`CATCHALL_WAN_MAP`, `CATCHALL_LOG_PATH`, `CATCHALL_READ_TIMEOUT_MS`, `CATCHALL_IDLE_TIMEOUT_MS`,
`CATCHALL_MAX_DURATION_SECS`, `CATCHALL_MAX_CAPTURED_BYTES`, `CATCHALL_MAX_CONCURRENT`.

Why this is documented rather than quietly dropped: the mismatch between the bare names the binary
read and the prefixed names an operator would reasonably write left a deployed catch-all sensor dead
through roughly 4000 restart attempts, its fail-closed config check rejecting an empty bind list
because nothing read its env file.

### Deprecated collector-id aliases (still read, do not use in new configs)

`ssh`, `ftp`, `adb`, `telnet`, and `shipper` all read `PROPOLIS_COLLECTOR_ID` for the same
identity value (see "Outbox manifest" below and the `shipper` section above) - before this rename
the four sensors read the bare `COLLECTOR_ID` and `shipper` read `PROPOLIS_SHIPPER_COLLECTOR_ID`,
two different names for one value that a config written against one and not the other would
silently diverge on. Each binary still reads its own pre-rename name via
`sensor_framework::env_with_legacy` when `PROPOLIS_COLLECTOR_ID` is unset, logging a deprecation
warning naming the canonical replacement; if both the canonical name and the old one are set to
different values, the canonical value wins and the warning names the ignored legacy value. An
existing config keeps working; write new ones with `PROPOLIS_COLLECTOR_ID`.

Why this is documented rather than quietly dropped: the upcoming provenance join keys on
`(collector_id, occurrence_id)`, so a sensor and `shipper` configured under different collector-id
env var names (and so, in practice, different values) would silently break attribution - the same
divergence risk the bare catchall names above already caused once.

Sensor-specific extras:
- **ssh** (`crates/sensor-ssh/src/main.rs`): `PROPOLIS_SSH_HOST_KEY_PATH`
  (default `/var/lib/propolis/ssh/host_key`, `:48`), `PROPOLIS_SSH_SPOOL_DIR`
  (default `/var/spool/propolis/ssh`, `:47`), `PROPOLIS_SSH_BANNER` (default =
  persona `OPENSSH_VERSION` = `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`, `main.rs:44` +
  `persona.rs:41`; blank → default), `PROPOLIS_SSH_OUTBOX_DIR` (default
  `/var/spool/propolis/ssh/outbox`; see "Outbox manifest" below).
- **ftp** (`crates/sensor-ftp/src/main.rs`): `PROPOLIS_FTP_SPOOL_DIR` (default
  `/var/spool/propolis/ftp`, `:21`), `PROPOLIS_FTP_OUTBOX_DIR` (default
  `/var/spool/propolis/ftp/outbox`; see "Outbox manifest" below).
- **adb** (`crates/sensor-adb/src/main.rs`): `PROPOLIS_ADB_SPOOL_DIR` (default
  `/var/spool/propolis/adb`, `:32`), `PROPOLIS_ADB_OUTBOX_DIR` (default
  `/var/spool/propolis/adb/outbox`; see "Outbox manifest" below).
- **telnet** (`crates/sensor-telnet/src/main.rs`): `PROPOLIS_TELNET_SPOOL_DIR`
  (default `/var/spool/propolis/telnet`), `PROPOLIS_TELNET_OUTBOX_DIR` (default
  `/var/spool/propolis/telnet/outbox`; see "Outbox manifest" below).
- **http**: `MAX_CONCURRENT` default is `512` (`crates/sensor-http/src/main.rs:24`).
- **catchall**: no spool variable (never spools file bodies, `main.rs:47-49`); no
  outbox variable either (captures no file bodies, so nothing for SP-B-1b's
  manifest to record).

#### Outbox manifest (SP-B-1b)

Every sensor that spools captured file bodies (ssh, ftp, adb, telnet) also writes a durable
per-capture custody manifest row under its outbox directory as soon as the body is sealed - see
`sensor_framework::outbox` and `sensor_framework::handoff::process_job`. Two variables govern it,
read identically by each of those four sensors' `main.rs`:

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_COLLECTOR_ID` (deprecated alias `COLLECTOR_ID`, still read; shared across all five binaries, not `PROPOLIS_<SENSOR>_*`) | no | `local` | Stamped onto every manifest row this sensor writes. **Must equal** the CommonName of the client certificate `shipper`'s `PROPOLIS_COLLECTOR_ID` presents to the gateway on this box, because a later stage joins the gateway's cert-derived collector id against this manifest on `(collector_id, occurrence_id)`. A single-node deployment with no shipper leaves this at `local`. |
| `PROPOLIS_<SENSOR>_OUTBOX_DIR` | no | `<PROPOLIS_<SENSOR>_SPOOL_DIR>/outbox` | Root of the per-capture manifest JSON files (`<dir>/<capture_id>.json`). The default is derived from the sensor's own resolved spool directory (not a fixed shared path) so it always lands inside the writable root the sensor's systemd unit grants - a fixed shared `/var/lib/propolis/outbox` default is unwritable under `ProtectSystem=strict` and was the SP-B-1c regression this fixed. Manifest rows are keyed by a globally-unique `capture_id`, so even where two sensors' outbox dirs happened to coincide, writes would never collide. |

### Lenient sensors - cred, smtp

Invalid or zero bound → **silent default**, not abort.

- **sensor-smtp** (`crates/sensor-smtp/src/main.rs`): `PROPOLIS_SMTP_BIND` (req;
  unset → `exit(1)` `:47`, invalid → `exit(1)` `:54`), `PROPOLIS_SMTP_WAN_MAP`
  (invalid entries silently skipped, `:16-26`), `PROPOLIS_SMTP_LOG_PATH` (default
  `/var/log/propolis/smtp/events.jsonl`), `PROPOLIS_SMTP_READ_TIMEOUT_MS`
  (`30_000`), `PROPOLIS_SMTP_IDLE_TIMEOUT_MS` (`60_000`),
  `PROPOLIS_SMTP_MAX_DURATION_SECS` (`600`), `PROPOLIS_SMTP_MAX_CAPTURED_BYTES`
  (`1_000_000`), `PROPOLIS_SMTP_MAX_CONCURRENT` (`256`).
- **sensor-cred** (`crates/sensor-cred/src/main.rs`): multi-protocol
  (VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Bind variables `PROPOLIS_CRED_VNC_BIND`,
  `PROPOLIS_CRED_MYSQL_BIND`, `PROPOLIS_CRED_MSSQL_BIND`, `PROPOLIS_CRED_PG_BIND`,
  `PROPOLIS_CRED_MONGO_BIND` (`main.rs:77-81`). At
  least one required - none set → `exit(1)` (`:93-98`); a set-but-invalid bind →
  `exit(1)` (`:87-88`); all-configured-fail-to-bind → `exit(1)` (`:122-125`).
  `PROPOLIS_CRED_WAN_MAP` (invalid skipped), `PROPOLIS_CRED_LOG_DIR` (default
  `/var/log/propolis/cred`, per-protocol file `<protocol>.jsonl`). Bounds:
  `PROPOLIS_CRED_READ_TIMEOUT_MS` (`30_000`), `PROPOLIS_CRED_IDLE_TIMEOUT_MS` (`60_000`),
  `PROPOLIS_CRED_MAX_DURATION_SECS` (**`60`**, differs from others' 600),
  `PROPOLIS_CRED_MAX_CAPTURED_BYTES` (**`100_000`**, differs from others' 1_000_000),
  `PROPOLIS_CRED_MAX_CONCURRENT` (`256`).

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

## Deploy-script variables (`deploy/blocklist-sync.sh`)

Read by the blocklist publish script, not by any daemon, so they are set in the
**cron environment** rather than an `/etc/propolis/*.env` file the units load.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_FEED_OUTPUT_DIR` | no | auto-detected | the publisher output holding `manifest.json`; when unset the script probes `<spool>/feed/current` then the older flat `<spool>/feed`, so both layouts work |
| `PROPOLIS_BLOCKLIST_REPO` | no | `/var/lib/propolis/blocklist-repo` | the git checkout that is committed and pushed |
| `PROPOLIS_BLOCKLIST_SSH_KEY` | no | unset | path to a **passphraseless** deploy key for the push. Set for cron: cron has no ssh-agent, so a passphrase-protected key cannot be used non-interactively. When set, the script exports `GIT_SSH_COMMAND` with `IdentitiesOnly=yes`; a configured-but-unreadable key **fails closed (exit 1)** rather than falling back to another identity, since a fallback that succeeds by hand and fails under cron is the exact trap being avoided. When unset in a non-interactive run with no agent, the script warns before pushing. |

Naming the key here rather than in the checkout's `core.sshCommand` is
deliberate: that git config is box-local state outside version control, and it
has reverted to a passphrase-protected key in practice, silently restoring the
cron failure it was meant to fix.

## Related

- [Ports and protocols](ports-and-protocols.md) - bind addresses/ports
- [Filesystem paths](filesystem-paths.md) - log/spool/cursor/feed directories
- [Integrations](integrations.md) - VirusTotal, vendor submitters, ntfy, GeoLite2
- [Rate limits and budgets](rate-limits-and-budgets.md) - fetcher/vendor budgets
- [Outbound controls](../security/outbound-controls.md) - the gated egress paths
- [Configuration](../operations/configuration.md) - operator configuration guide
