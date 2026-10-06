<!--
title: Environment variables
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-28
-->

# Environment variables

Authoritative table of every environment variable read by any Propolis binary:
name, the binary that reads it, required/optional, exact code default, valid
form, bounds/validation, and fail behavior. This page owns these facts; other
docs link here rather than restating defaults.

Defaults listed are the **code** defaults applied when a variable is unset or
blank. All `/etc/propolis/*.env` files except the generated `fleet-listeners.env`
(`deploy/install.sh#7/9 deriving the fleet listener inventory`,
`deploy/fleet-listeners.sh#OUT_FILE`) are operator-authored; `deploy/install.sh`
does not generate them (it only prints a reminder to populate them,
`deploy/install.sh#Next: populate`).

## Run modes and where variables are read

Propolis ships two ways to run the platform, and the env surface differs:

1. **Unified daemon** `propolis` - one `load_config()`
   (`crates/propolis/src/config.rs#load_config`) parses intake, review, feed, console,
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
  sensors `ssh`/`telnet`/`http`/`ftp`/`redis`/`adb`/`catchall`/`tftp`/`mqtt`: a
  present-but-invalid or present-but-zero numeric bound **aborts startup**.
- **Lenient parse** - sensors `cred` and `smtp` **only**: an invalid or zero
  bound silently falls back to the default (`parse_positive_u64` filters `>0`
  then `unwrap_or(default)`, `crates/sensor-cred/src/main.rs#parse_positive_u64`,
  `crates/sensor-smtp/src/main.rs#parse_positive_u64`).

Unified daemon (`config.rs`) parse helpers:

| Helper | Unset/empty | Invalid | Zero | Other |
|---|---|---|---|---|
| `require_env` (`crates/propolis/src/config.rs#require_env`) | `Missing` (abort) | - | - | - |
| `parse_positive_u64` (`crates/propolis/src/config.rs#parse_positive_u64`) | default | `Invalid` (abort) | `Invalid` (abort) - "zero never means unlimited" | - |
| `parse_bounded_positive_u64` (`crates/propolis/src/config.rs#parse_bounded_positive_u64`) | default | abort | abort | `> max` → abort |
| `parse_u32` (`crates/propolis/src/config.rs#parse_u32`) | default | abort | allowed | - |
| `parse_bounded_u8` (`crates/propolis/src/config.rs#parse_bounded_u8`) | default | abort | allowed (0 = maximally strict) | `> 255` → abort (no wrap) |
| `parse_bool_flag` (`crates/propolis/src/config.rs#parse_bool_flag`) | default | - | - | case-insensitive `true`/`false` only; **any** other value (incl. `1`, `yes`) → default |

Note `parse_bool_flag` does **not** accept `1`/`yes`; ops-alert `get_bool` and
console rDNS parse booleans more broadly (called out below).

---

## Universal / cross-cutting

### `DATABASE_URL`
- Read by: `propolis` (`crates/propolis/src/config.rs#load_config`), `console`
  (`console/src/main.rs#load_config_from_env`), `feed`
  (`feed/src/main.rs#load_config_from_env`), `intake`
  (`intake/src/main.rs#load_config_from_env`), `review`
  (`review/src/main.rs#load_config_from_env`).
- Required: **yes**, for every binary that touches PostgreSQL. No default.
- Form: PostgreSQL connection string (not validated at parse time; `sqlx`
  validates on connect).
- Fail: absent **or** empty string → **abort** (empty treated as missing via
  `.filter(|s| !s.is_empty())`).

### `RUST_LOG`
- Read by: every binary except `provision-certs`, as `tracing_subscriber`'s standard `EnvFilter`
  variable.
- Required: no. When it is unset or does not parse, `propolis` and `console` log at `info`
  (`propolis/src/main.rs#main`, `console/src/main.rs#main`). Every other binary - the sensors,
  `gateway`, `shipper`, and the standalone `intake`, `review` and `feed` - logs **errors only**.
  Each calls `tracing_subscriber::fmt::init()` (for example `crates/gateway/src/main.rs#main`),
  whose default filter is `error` once the `env-filter` feature is on, and a workspace build
  (`cargo build --release` at the workspace root, as the deployment manual has you run it before
  `deploy/install.sh`, or `cargo build --release --workspace --locked` as `deploy/upgrade.sh` runs
  it) turns the feature on for every member because `propolis`, `console` and `sensor-catchall`
  enable it. Set
  `RUST_LOG=info` in a unit's env file to see its startup and warning lines: with it unset, a
  healthy release-built `gateway` prints nothing at all (observed 2026-09-28).

### `PROPOLIS_HOSTNAME`
- Read by: `sensor-framework::persona::hostname()`
  (`crates/sensor-framework/src/persona.rs#hostname`); used by every sensor presenting
  a host identity (SSH/telnet shell, fake-fs `/etc/hostname`, redis `INFO`,
  SMTP/FTP greeting).
- Required: no. Default `server01` (`sensor-framework/src/persona.rs#DEFAULT_HOSTNAME`).
- Validation: trimmed; blank after trim → default (`sensor-framework/src/persona.rs#hostname`). Always
  resolves.

### `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`
- Read by: `reqwest` itself when each HTTP client is built, not by Propolis
  config code. Upper case wins over lower case (`http_proxy` and the rest).
- Honored by: the VirusTotal, vendor-submitter and ops-alert ntfy clients, whose
  destinations are fixed vendor endpoints or URLs you configured.
- Ignored by: the malware fetcher, always. A proxy resolves the URL's host
  itself, so a proxied fetch would bypass the address the SSRF guard pinned; see
  [outbound controls](../security/outbound-controls.md).

---

## Unified daemon `propolis`

Full env surface, `crates/propolis/src/config.rs`. This binary reads every
variable in this section plus the universal ones above.

### Database

| Variable | Req | Default | Bounds / validation | Fail |
|---|---|---|---|---|
| `PROPOLIS_DB_MAX_CONNECTIONS` | no | `10` (`crates/propolis/src/config.rs#DEFAULT_DB_MAX_CONNECTIONS`) | positive u64 → cast u32 | zero/unparseable → abort |

### Intake

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_SENSOR_LOGS` | **yes** | - | comma-separated `name:path` pairs (`crates/propolis/src/config.rs#parse_sensor_logs`). Empty list, or an entry missing name/path → **abort**. At least one pair required. |
| `PROPOLIS_CURSOR_DIR` | no | `/var/lib/propolis/cursors` (`crates/propolis/src/config.rs#DEFAULT_CURSOR_DIR`) | any path; no validation |
| `PROPOLIS_POLL_INTERVAL_MS` | no | `1000` (`crates/propolis/src/config.rs#DEFAULT_POLL_INTERVAL_MS`) | positive u64 ms; zero/unparseable → abort |

### Review

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_REVIEW_ENABLED` | no | `true` (`crates/propolis/src/config.rs#load_config`) | bool_flag |
| `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS` | no | `60` (`crates/propolis/src/config.rs#DEFAULT_QUEUE_SCAN_INTERVAL_SECS`) | positive u64; zero → abort |
| `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS` | no | `30` (`crates/propolis/src/config.rs#DEFAULT_SUBMIT_POLL_INTERVAL_SECS`) | positive u64; zero → abort |

### Vendor abuse submitters (`crates/propolis/src/config.rs#load_config`, `crates/propolis/src/config.rs#load_vendor_config`)

Each vendor `<V>` ∈ {`ABUSEIPDB`, `DSHIELD`, `OTX`}. These are opt-in egress
paths, default off. See [outbound controls](../security/outbound-controls.md)
and [integrations](integrations.md).

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_VENDOR_<V>_KEY` | no | `""` | empty key + enabled → vendor forced **disabled** (fail-closed, warns) (`crates/propolis/src/config.rs#load_vendor_config`) |
| `PROPOLIS_VENDOR_<V>_URL` | no | vendor base URL (below) | no validation |
| `PROPOLIS_VENDOR_<V>_ENABLED` | no | `false` (`crates/propolis/src/config.rs#load_vendor_config`) | bool_flag; stays disabled unless key present |
| `PROPOLIS_VENDOR_<V>_COOLDOWN_HOURS` | no | `24` (`crates/propolis/src/config.rs#DEFAULT_COOLDOWN_HOURS`) | parse_u32; zero allowed; unparseable → abort |
| `PROPOLIS_VENDOR_<V>_RATE_LIMIT` | no | `100` (`crates/propolis/src/config.rs#DEFAULT_RATE_LIMIT`) | parse_u32 |
| `PROPOLIS_VENDOR_<V>_RATE_WINDOW_HOURS` | no | `1` (`crates/propolis/src/config.rs#DEFAULT_RATE_WINDOW_HOURS`) | parse_u32 |
| `PROPOLIS_VENDOR_DSHIELD_USER` | no | none | DShield only (`crates/propolis/src/config.rs#load_config`); if set with a key, composed as `{user}:{key}` into the single key slot (`crates/propolis/src/config.rs#load_config`). User alone (no key) is ignored. |

Concrete literal names the code reads (the `<V>` rows above, instantiated for each vendor):
`PROPOLIS_VENDOR_ABUSEIPDB_KEY`, `PROPOLIS_VENDOR_ABUSEIPDB_URL`,
`PROPOLIS_VENDOR_DSHIELD_KEY`, `PROPOLIS_VENDOR_DSHIELD_URL`,
`PROPOLIS_VENDOR_OTX_KEY`, `PROPOLIS_VENDOR_OTX_URL`.

Default base URLs (`crates/review/src/vendor/*.rs`):
- abuseipdb: `https://api.abuseipdb.com` (`review/src/vendor/abuseipdb.rs#DEFAULT_BASE_URL`)
- dshield: `https://www.dshield.org` (`review/src/vendor/dshield.rs#DEFAULT_BASE_URL`)
- otx: `https://otx.alienvault.com` (`review/src/vendor/otx.rs#DEFAULT_BASE_URL`)

### Feed

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_FEED_ENABLED` | no | `true` (`crates/propolis/src/config.rs#load_config`) | bool_flag |
| `PROPOLIS_FEED_OUTPUT_DIR` | no | `/var/lib/propolis/feed/current` (`crates/propolis/src/config.rs#DEFAULT_FEED_OUTPUT_DIR`) | path |
| `PROPOLIS_FEED_BUILD_INTERVAL_SECS` | no | `900` (`crates/propolis/src/config.rs#DEFAULT_FEED_BUILD_INTERVAL_SECS`) | positive u64; zero → abort |
| `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS` | no | `24` (`crates/propolis/src/config.rs#DEFAULT_AGGRESSIVE_TTL_HOURS`) | positive u64; ×3600 → Duration; zero → abort |
| `PROPOLIS_FEED_STANDARD_TTL_HOURS` | no | `48` (`crates/propolis/src/config.rs#DEFAULT_STANDARD_TTL_HOURS`) | positive u64; zero → abort |
| `PROPOLIS_FEED_ALLOWLIST` | no | `""` | comma-sep CIDR list (`crates/propolis/src/config.rs#parse_cidr_list`); **bare IP without prefix is rejected**; invalid entry → abort |
| `PROPOLIS_FEED_DELIST` | no | `""` | comma-sep IP list (`crates/propolis/src/config.rs#parse_ip_list`); invalid → abort |
| `PROPOLIS_FEED_ASN_ALLOWLIST` | no | `""` | comma-sep AS numbers, optional `AS`/`as` prefix (`crates/propolis/src/config.rs#parse_asn_list`); invalid → abort. Inert unless the GeoIP ASN DB loads (see [interactions](#interactions)). |
| `PROPOLIS_FEED_WINDOWS` | no | `24h,7d,30d,60d,90d` (`crates/propolis/src/config.rs#DEFAULT_FEED_WINDOWS`) | comma-sep `<count>h`/`<count>d` (`crates/propolis/src/config.rs#parse_window_list`). Only `h`/`d` units; count must be a positive int; **any malformed entry → abort** (fails closed, not skipped). Empty string → no retention feeds. **Unified daemon only.** |

### Console

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_CONSOLE_BIND` | no | `127.0.0.1:8080` (`crates/propolis/src/config.rs#DEFAULT_CONSOLE_BIND`) | must parse as `ip:port` SocketAddr; invalid → abort (`crates/propolis/src/config.rs#load_config`) |
| `PROPOLIS_CONSOLE_PASSWORD` | **yes** | - | `require_env`; absent/empty → **abort** (`crates/propolis/src/config.rs#load_config`) |
| `PROPOLIS_CONSOLE_SESSION_SECRET` | no | random 32 bytes generated at startup (`crates/propolis/src/config.rs#load_session_secret`) | if set, must be exactly 64 hex chars (32 bytes), else abort (`crates/propolis/src/config.rs#load_session_secret`). Sessions are in-memory, so a fresh secret per restart only invalidates sessions already dropped on restart. |
| `PROPOLIS_CONSOLE_MAX_SOURCE_IPS` | no | `3` (`routes/samples.rs`) | how many attacker IPs the Samples page shows inline per sample before collapsing to "+N more"; blank/zero/unparseable falls back to the default (zero never means unlimited) |
| `PROPOLIS_SPOOL_ROOT` | no | `/var/spool/propolis` (`review/src/spool.rs`) | root of the spool tree. Per-sensor spool dirs default under it, but each sensor's own `PROPOLIS_<SENSOR>_SPOOL_DIR` still wins, so the platform side (VT scan, retention, console) resolves the same directory the sensor actually writes to. Must match what `deploy/install.sh` provisions and what the units grant in `ReadWritePaths`. |
| `PROPOLIS_GEOIP_DIR` | no | none (`Option`, `crates/propolis/src/config.rs#load_config`) | directory of GeoLite2 `.mmdb` files; empty string treated as unset; missing dir/file degrades gracefully. GeoIP enrichment is **local file reads, not network**. |
| `PROPOLIS_CONSOLE_RDNS_ENABLED` | no | `false` (`crates/propolis/src/config.rs#load_config`) | bool_flag; opt-in forward-confirmed reverse DNS - the one outbound DNS lookup. Default off. See [outbound controls](../security/outbound-controls.md). |
| `PROPOLIS_CONSOLE_TRUSTED_PROXY` | no | `false` | bool_flag; set when the console sits behind a TLS reverse proxy so session cookies are always marked `Secure` (a same-host proxy connects over loopback, which would otherwise drop the flag on a real HTTPS hop). |
| `PROPOLIS_CONSOLE_METRICS_TOKEN` | no | none | if set, `/metrics` requires `Authorization: Bearer <token>` (constant-time compare); unset leaves `/metrics` open - safe only on a loopback bind. Defense in depth for a non-loopback bind. |

The console serves plain HTTP on a loopback `TcpListener`; there is no in-process
TLS. Any TLS is operator-provided (e.g. a reverse proxy) [inferred]. See
[networking and TLS](../operations/networking-tls.md).

### Fleet health (the console's `/fleet` pane)

Read by BOTH the unified daemon and the standalone `console` binary: the daemon
renders the pane through its embedded console, and the standalone binary is a
viewer of the same data.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_FLEET_LISTENERS` | no | none (empty inventory) | comma-separated `collector/sensor/protocol/port` entries, e.g. `local/ssh/tcp/22,local/catchall/udp/1024`. Unset or blank means "this node was told no inventory": the pane then reports every check as unknown rather than reporting nothing at all. A value that IS set and malformed aborts startup - never a silently shortened list. `protocol` is `tcp` or `udp`; `port` is 1-65535. |
| `PROPOLIS_FLEET_DEPLOY_STAMP` | no | `/var/lib/propolis/deploy-stamp.json` | path to the deploy stamp JSON, written by `deploy/deploy-stamp.sh` on every install and upgrade. A missing, unreadable, or malformed file leaves the version panel reading `not recorded`, never `current`. Set it only to move the file; the default is the path the deploy scripts write. The file records the deployed checkout's commit, the last fetched `origin/main`, the branch, two timestamps, and an `installed` map holding what each installed binary reports for its own `--version` - the daemon and the standalone console separately, because they are installed separately and either one can be left behind. A stamp written before that map existed, or one whose entry for this binary is empty or not a clean commit id, reads as `not recorded` on that line AND in the verdict: `current` asserts what is on disk as well as what this process runs, and nothing observed the disk. Redeploying with the current `deploy-stamp.sh` records it. |
| `PROPOLIS_FLEET_COLLECTOR_ENDPOINTS` | no | none | comma-separated `collector=address`, e.g. `local=198.51.100.7`. The address the control plane dials for that collector's listeners. A listener whose collector is absent here is recorded `not probeable` with the reason named, never guessed at. A malformed entry aborts startup. |
| `PROPOLIS_FLEET_PROBE_INTERVAL` | no | `300` | sweep cadence in seconds, 60-86400. Rejected rather than clamped outside that range. Also the unit the console measures probe staleness in: a row older than twice this alarms, whatever its last outcome was. The standalone `console` binary reads it too, purely to size that rule. |
| `PROPOLIS_FLEET_PROBE_TIMEOUT` | no | `5` | per-connect deadline in seconds, 1-60. Rejected rather than clamped outside that range. Bounds each connect so a blackholed address cannot hold a sweep open on the OS default connect timeout. |

The next two turn the active probe on, and they go together.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_FLEET_PROBE_ENABLED` | no | `false` | whether the daemon runs the reachability sweep. Unified daemon only; the standalone `console` never probes. |
| `PROPOLIS_FLEET_PROBE_SOURCE_IPS` | when the probe is on | none | comma-separated IP addresses this node's own connects arrive from. Intake drops sensor lines from these before conversion. **Required whenever `PROPOLIS_FLEET_PROBE_ENABLED=true`: startup refuses without it.** Read by the unified daemon and by the standalone `intake` binary. |

Why that refusal exists. Every TCP sensor emits `honeypot_connection` the moment it accepts a
connection, before reading a byte, and that signal weighs 40 at confidence 0.900. A five-minute
sweep across a dozen listeners is a few thousand such events a day, all from one address: this
node's own. Unless intake recognises and drops them, the control plane scores itself into the
review queue and out into the published blocklist, and nothing downstream can retract that. There
is no safe default to guess here, because only the operator knows which address this node's
connects arrive from, so the daemon refuses to start rather than probe unfiltered.

What a `reachable` verdict does and does not prove. The connect proves a socket answered on the
path the control plane took. On the current single-box deployment the control plane and the
collector are the same host, so that path is a **hairpin**: the packets never leave the machine,
and the result is evidence that the listener is up locally, not that anything on the internet can
reach it. The prober detects this at the socket level and labels the row, so the pane says so
rather than implying external reachability. A separated control plane, dialling a collector across
the real network path, is what turns the same check into evidence about external reachability.

The other half of the answer is the intake confirmation. A row reads `ok` only when the socket
answered AND the resulting sensor line reached intake within two sweep intervals. `reachable` with
no recent confirmation is a warning, not health: the listener is up and something between the log
file and intake is broken.

`sensor` is the sensor's OWN reported name, which is what lands in
`event.sensor` - not the `PROPOLIS_SENSOR_LOGS` label. `sensor-cred` reports its
five protocols individually, so its names are `vnc`, `mysql`, `mssql`,
`postgresql` and `mongodb` while its conventional log labels are `cred-vnc` and
so on. An inventory keyed on the log label would join to nothing.

Do not hand-maintain `PROPOLIS_FLEET_LISTENERS`: it is a second copy of the
binds that already live in each sensor's own env file, and a hand-kept copy
drifts invisibly. `deploy/fleet-listeners.sh` derives it from those files and
writes `/etc/propolis/fleet-listeners.env`, which `propolis.service` and
`console.service` load BEFORE their operator-owned env file (so an explicit
operator setting still wins). `deploy/install.sh` and `deploy/upgrade.sh` run
the generator, so drift is possible only between deploys - and a sensor
producing events while absent from the inventory shows on the pane as
`undeclared listener`, which is what catches that window. The exception is a
[split deployment](../operations/split-deployment.md): the sensor env files live on the collector, the
generator on the control plane writes an empty inventory, and the list has to be
set in the control plane's `propolis.env`.

`PROPOLIS_FLEET_COLLECTOR_ID` (default `local`) is read by
`deploy/fleet-listeners.sh` itself, not by any binary: it stamps the collector
id onto each generated entry. `PROPOLIS_DEPLOY_PULLED_AT` is read by
`deploy/deploy-stamp.sh` in the same way: `deploy/upgrade.sh` passes the time it
pulled, so the stamp's `pulled_at` and `built_at` are two facts rather than one
number written twice.

#### Compile-time, not configuration

`PROPOLIS_GIT_SHA` and `PROPOLIS_BUILD_TIMESTAMP` are **not** operator
variables. Each binary's build script (`crates/propolis/build.rs`,
`crates/console/build.rs`, sharing `crates/build-stamp.rs`) sets them at compile
time from `git`, and setting them in the environment of a running process has no
effect. They are listed here only because they read like environment variables
in the source.

`PROPOLIS_GIT_SHA` is the short commit id, with `+dirty` appended when the
working tree had uncommitted changes (in the crate being built or in any
workspace crate it depends on), or the literal `unknown` when the build could
not run git at all (a tarball, a container with no git, a checkout with no
`.git`). The version panel treats `unknown` and `+dirty` the same way it treats
a missing stamp: `not recorded`. A build that cannot say which commit it is must
never be presented as a build that matches the deploy.

Both binaries print these two values, plus their crate version, in response to
`--version`, before any configuration, database or network work - so an operator
can ask a binary what it is on a box whose environment is not populated yet, and
so `deploy/deploy-stamp.sh` can read back what an install actually left on disk.

### VirusTotal (unified daemon only)

Opt-in egress, default off. See [integrations](integrations.md) and
[outbound controls](../security/outbound-controls.md).

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_VT_KEY` | no | `""` (`crates/propolis/src/config.rs#load_config`) | empty → VT disabled regardless of `_ENABLED` |
| `PROPOLIS_VT_ENABLED` | no | `false` (`crates/propolis/src/config.rs#load_config`) | bool_flag; **and** a non-empty key required to actually enable (`&& !vt_api_key.is_empty()`) |
| `PROPOLIS_VT_UPLOAD` | no | `false` (`crates/propolis/src/config.rs#load_config`) | bool_flag; upload-unknown-samples opt-in |
| `PROPOLIS_VT_SCAN_INTERVAL_SECS` | no | `300` (`crates/propolis/src/config.rs#load_config`) | parse_u32 (zero allowed); unparseable → abort. No `PROPOLIS_VT_URL` override exists. |
| `PROPOLIS_VT_PENDING_RECHECK_SECS` | no | `900` | parse_u32; how long an uploaded sample with no verdict yet (`detected = -1`) waits before its hash is looked up again. Each recheck costs one daily-budget unit. Zero → every scan cycle. unparseable → abort. |

### Malware fetcher (unified daemon only)

Opt-in egress, off by default. See [outbound controls](../security/outbound-controls.md)
and [rate limits and budgets](rate-limits-and-budgets.md).

| Variable | Req | Default | Max | Bounds / fail |
|---|---|---|---|---|
| `PROPOLIS_FETCH_ENABLED` | no | `false` (`crates/propolis/src/config.rs#load_config`) | - | bool_flag |
| `PROPOLIS_FETCH_INTERVAL_SECS` | no | `10` (`crates/propolis/src/config.rs#DEFAULT_FETCH_INTERVAL_SECS`) | `86400` (`crates/propolis/src/config.rs#MAX_FETCH_INTERVAL_SECS`) | bounded positive u64; zero/over-max → abort |
| `PROPOLIS_FETCH_MAX_BYTES` | no | `10_000_000` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_BYTES`) | `500_000_000` (`crates/propolis/src/config.rs#MAX_FETCH_MAX_BYTES`) | bounded positive u64 → usize; **zero → abort** (would disable the byte guard); over-max → abort |
| `PROPOLIS_FETCH_MAX_PER_HOST_HOUR` | no | `12` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_PER_HOST_HOUR`) | `1000` (`crates/propolis/src/config.rs#MAX_FETCH_MAX_PER_HOST_HOUR`) | bounded positive u64 → u32 |
| `PROPOLIS_FETCH_MAX_HOPS` | no | `3` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_HOPS`) | `255` (u8) | bounded_u8; **zero allowed** (no redirects); >255 → abort |
| `PROPOLIS_FETCH_MAX_DEPTH` | no | `2` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_DEPTH`) | `255` (u8) | bounded_u8; zero allowed (no recursion) |
| `PROPOLIS_FETCH_DAILY_CAP` | no | `200` (`crates/propolis/src/config.rs#DEFAULT_FETCH_DAILY_CAP`) | `10_000` (`crates/propolis/src/config.rs#MAX_FETCH_DAILY_CAP`) | bounded positive u64 → u32 |
| `PROPOLIS_FETCH_BATCH_SIZE` | no | `20` (`crates/propolis/src/config.rs#DEFAULT_FETCH_BATCH_SIZE`) | `1000` (`crates/propolis/src/config.rs#MAX_FETCH_BATCH_SIZE`) | bounded positive u64 → usize |
| `PROPOLIS_FETCH_CONNECT_TIMEOUT_SECS` | no | `10` (`crates/propolis/src/config.rs#DEFAULT_FETCH_CONNECT_TIMEOUT_SECS`) | `300` (`crates/propolis/src/config.rs#MAX_FETCH_TIMEOUT_SECS`) | bounded positive u64 |
| `PROPOLIS_FETCH_READ_TIMEOUT_SECS` | no | `10` (`crates/propolis/src/config.rs#DEFAULT_FETCH_READ_TIMEOUT_SECS`) | `300` | bounded positive u64 |
| `PROPOLIS_FETCH_TOTAL_TIMEOUT_SECS` | no | `30` (`crates/propolis/src/config.rs#DEFAULT_FETCH_TOTAL_TIMEOUT_SECS`) | `300` | bounded positive u64 |
| `PROPOLIS_FETCH_USER_AGENT` | no | `Wget/1.21.3` (`crates/propolis/src/config.rs#DEFAULT_FETCH_USER_AGENT`) | - | blank → default |
| `PROPOLIS_FETCH_OWN_IPS` | no | `""` | - | comma-sep IP list (`parse_ip_list`); invalid → abort. Unioned with live-interface IPs for the SSRF self-target guard. |

Fetcher runtime fail-closed (`own_ips.is_empty()` check, `propolis/src/main.rs#main`): if
`PROPOLIS_FETCH_OWN_IPS` is unset **and** interface enumeration returns empty, the fetcher **refuses to run**
(logs an error and returns). If the own-IPs set has only private/loopback/
link-local addresses (a NAT'd node whose public WAN IP is on no interface), it
**warns but runs** (`own_ips_lack_a_public_address` check, `propolis/src/main.rs#main`); set `PROPOLIS_FETCH_OWN_IPS` to the
public egress IP for self-target protection.

### Operational self-alerting (ops-alert)

`crates/propolis/src/ops_alert/config.rs`. Opt-in ntfy POST egress, default off.
Parsed via an injectable getter over `env::var` that treats blank as absent.
Helpers: `get_bool` (`crates/propolis/src/ops_alert/config.rs#get_bool`) accepts `true|1|yes|on` (case-insensitive), else
default - broader than `parse_bool_flag`. `get_u64`/`get_secs` (`crates/propolis/src/ops_alert/config.rs#get_u64`/`crates/propolis/src/ops_alert/config.rs#get_secs`):
unset -> default; unparseable -> abort; **below min -> abort**. `get_pct` (`crates/propolis/src/ops_alert/config.rs#get_pct`):
enforces `1..=100`; 0 and >100 -> abort. `get_u32` (`crates/propolis/src/ops_alert/config.rs#get_u32`): u64 range-checked to
u32.

| Variable | Req | Default | Min/bounds | Notes |
|---|---|---|---|---|
| `PROPOLIS_OPS_ENABLED` | no | `false` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | - | opt-in; a deployment predating ops-alert still starts |
| `PROPOLIS_OPS_NTFY_URL` | no | `""` (unset reads as empty, `crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | - | enabled and set with the other unset -> abort (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`); enabled and both unset -> alerts go to the local log sink (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) |
| `PROPOLIS_OPS_NTFY_TOPIC` | no | `""` (unset reads as empty, `crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | - | enabled and set with the other unset -> abort (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`); enabled and both unset -> alerts go to the local log sink (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`). The `propolis-ops` value seen in tests is not a runtime default. |
| `PROPOLIS_OPS_NTFY_TOKEN` | no | none (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | - | optional bearer token |
| `PROPOLIS_OPS_POLL_INTERVAL_SECS` | no | `30` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | |
| `PROPOLIS_OPS_REPAGE_COOLDOWN_SECS` | no | `5400` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | |
| `PROPOLIS_OPS_STALL_FOR_SECS` | no | `600` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | |
| `PROPOLIS_OPS_CAPACITY_FREE_PCT` | no | `15` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | 1..=100 | 0/>100 -> abort |
| `PROPOLIS_OPS_FEED_STALE_MULTIPLE` | no | `2` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | u32 |
| `PROPOLIS_OPS_FEED_PUSH_EXPECTED` | no | `false` | bool | set once `deploy/blocklist-sync.sh` is in cron: `feed-push-stale` then pages when the feed has gone unpushed for the stale threshold (`FEED_STALE_MULTIPLE` build cycles) since the daemon started, instead of treating "no push marker" as grace forever |
| `PROPOLIS_OPS_VENDOR_WINDOW_SECS` | no | `3600` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | |
| `PROPOLIS_OPS_VENDOR_FAIL_PCT` | no | `50` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | 1..=100 | |
| `PROPOLIS_OPS_VENDOR_MIN_SAMPLES` | no | `20` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | u32 |
| `PROPOLIS_OPS_BACKLOG_MAX` | no | `500` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | u64 |
| `PROPOLIS_OPS_BACKLOG_FOR_SECS` | no | `900` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | |
| `PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS` | no | `21600` (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`) | min 1 | |
| `PROPOLIS_OPS_SCAN_STALE_SECS` | no | `21600` | min 1 | `scan-stale`: a spooled body unscanned, or a VirusTotal upload unverdicted, this long; silent unless VirusTotal is enabled |
| `PROPOLIS_OPS_FETCH_STALE_SECS` | no | `3600` | min 1 | `fetch-stale`: a fetch url pending this long; silent unless the fetcher is enabled |

---

## Collector/control-plane split binaries (SP-A)

Two additional binaries, each its own process with its own `load_config_from_env()` and its own
`/etc/propolis/<name>.env` - the disposable-collector / control-plane topology
(`deploy/gateway.service`, `deploy/shipper.service`, `deploy/collector.env.example`,
`deploy/control-plane.env.example`). Neither reads `DATABASE_URL` or any vendor/VT/console
variable; that boundary is the entire point of the split. Setting them up and running them:
[split deployment](../operations/split-deployment.md).

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
| `PROPOLIS_GATEWAY_STATE_DIR` | no | `/var/lib/propolis/gateway` | each collector's position in its batch chain, `<dir>/<collector_id>.json` holding `last_seq` and `last_batch_hash` (`crates/gateway/src/state.rs#CollectorState`). The gateway holds this in memory while it runs, so removing a file takes effect at its next restart, and then only together with the shipper's state, see [split deployment](../operations/split-deployment.md#rebuilding-a-collector) |
| `PROPOLIS_GATEWAY_MAX_CONCURRENT` | no | `64` | positive u32; zero/unparseable → abort |
| `PROPOLIS_GATEWAY_MAX_DURATION_SECS` | no | `120` | positive u64 secs; zero/unparseable → abort |
| `PROPOLIS_GATEWAY_READ_TIMEOUT_MS` | no | `30000` | positive u64 ms; zero/unparseable → abort. Validated but **not applied**: the connection handler sets no read timeout (`crates/gateway/src/server.rs#handle_connection`) |
| `PROPOLIS_GATEWAY_IDLE_TIMEOUT_MS` | no | `60000` | positive u64 ms; zero/unparseable → abort. Validated but **not applied**, like the read timeout; only `PROPOLIS_GATEWAY_MAX_CONCURRENT` and `PROPOLIS_GATEWAY_MAX_DURATION_SECS` bound a connection |

The gateway's own read loop bounds every frame at `collector_wire::frame::MAX_FRAME_LEN` before
allocating, so `ConnectionBounds`'s `max_captured_bytes` field is fixed to that ceiling internally
and is **not** exposed as a separate env var.

### `shipper`

`crates/shipper/src/config.rs`. Collector-side process that tails this collector's sensor logs and
ships batches to the gateway over mTLS. All fields are strict parse; the collector id below is
additionally cross-checked against the client certificate's CommonName at startup.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_SHIPPER_GATEWAY_ADDR` | **yes** | - | literal `ip:port` socket address of the gateway; nothing is resolved, so a host name is refused; absent/unparseable → abort (`crates/shipper/src/config.rs#load_config_from_env`) |
| `PROPOLIS_SHIPPER_GATEWAY_DNS` | **yes** | - | name checked against the gateway's TLS server certificate during the mTLS handshake; only compared, never resolved, so it need not exist in DNS (`crates/shipper/src/client.rs#ShipperClient::connect`); absent → abort |
| `PROPOLIS_SHIPPER_CA_CERT_PATH` | **yes** | - | PEM path used to verify the gateway's server certificate; absent → abort |
| `PROPOLIS_SHIPPER_CLIENT_CERT_PATH` | **yes** | - | PEM path, this collector's client certificate; absent → abort |
| `PROPOLIS_SHIPPER_CLIENT_KEY_PATH` | **yes** | - | PEM path, private key for the client cert above; absent → abort |
| `PROPOLIS_COLLECTOR_ID` (deprecated alias `PROPOLIS_SHIPPER_COLLECTOR_ID`, still read) | **yes** | - | this collector's identity; **must equal** the CommonName baked into `PROPOLIS_SHIPPER_CLIENT_CERT_PATH` or the shipper refuses to start (`validate_collector_id`, `ConfigError::CollectorIdMismatch`). Same variable the four body-capturing sensors read (see "Outbox manifest" below) - set the same value on every unit of this collector. Today the sensors only stamp it on their outbox manifest rows, which nothing reads yet; the planned provenance join on `(collector_id, occurrence_id)` depends on it matching. |
| `PROPOLIS_SHIPPER_SENSOR_LOGS` | **yes** | - | comma-separated `name:path` pairs, same grammar as `PROPOLIS_SENSOR_LOGS`; empty or a malformed entry → abort; at least one pair required |
| `PROPOLIS_SHIPPER_CURSOR_DIR` | no | `/var/lib/propolis/shipper/cursors` | one cursor file per log, named by the SHA-256 of the log's path (`crates/log-tailer/src/cursor.rs#DurableCursor::cursor_file_path`) |
| `PROPOLIS_SHIPPER_STATE_DIR` | no | `/var/lib/propolis/shipper/state` | this collector's position in its batch chain, `<dir>/<collector_id>.json` (`crates/shipper/src/state.rs#ConfirmedState`) |
| `PROPOLIS_SHIPPER_POLL_INTERVAL_MS` | no | `1000` | positive u64 ms; zero/unparseable → abort |
| `PROPOLIS_SHIPPER_MAX_RECORDS_PER_BATCH` | no | `15` (`batcher::MAX_RECORDS_FRAME_SAFE`) | positive u64 → usize; zero/unparseable → abort; a value above 15 is lowered to 15 (`crates/shipper/src/batcher.rs#Batcher::next_batch`) |
| `PROPOLIS_SHIPPER_RETRY_BACKOFF_MS` | no | `2000` | positive u64 ms; zero/unparseable → abort. The wait before resending a batch the gateway answered with Retry, at most 5 times in a row (`crates/shipper/src/main.rs#MAX_CONSECUTIVE_RETRIES`); a failed connection is retried on the next poll instead |

`PROPOLIS_SHIPPER_SENSOR_LOGS`'s `name` only labels log lines: it is not sent to the gateway, and each
log's cursor is keyed by its path. Every sensor log on a collector ships through one seq/hash chain
keyed by `PROPOLIS_COLLECTOR_ID`
(via the gateway's verified client-certificate CommonName), not by the per-log name.

On the control-plane side, intake's `PROPOLIS_SENSOR_LOGS` is re-pointed at the gateway's
per-collector spool (one `name:path` entry per collector, not per sensor) - see
[split deployment](../operations/split-deployment.md), [filesystem paths](filesystem-paths.md#split-deployment-gateway-and-shipper)
and `deploy/control-plane.env.example`.

---

## Standalone service binaries

Each reads a strict subset of the unified daemon's variables with the same
defaults and the same strict-parse/fail-closed rules unless noted.

- **`console`** (`load_config_from_env`, `crates/console/src/main.rs#load_config_from_env`): `DATABASE_URL` (req),
  `PROPOLIS_CONSOLE_BIND`, `PROPOLIS_CONSOLE_PASSWORD` (req, empty→abort),
  `PROPOLIS_CONSOLE_SESSION_SECRET`, `PROPOLIS_FEED_OUTPUT_DIR`,
  `PROPOLIS_GEOIP_DIR`, `PROPOLIS_CONSOLE_RDNS_ENABLED`, `RUST_LOG`. Two
  divergences from the unified daemon: `PROPOLIS_FEED_OUTPUT_DIR` is **not**
  empty-filtered (`console/src/main.rs#load_config_from_env`), so an explicitly-empty value becomes
  `Some(PathBuf::from(""))`; and `PROPOLIS_CONSOLE_RDNS_ENABLED` accepts
  `true|1|yes` case-insensitive (`console/src/main.rs#load_config_from_env`), broader than `bool_flag`.
- **`feed`** (`crates/feed/src/main.rs#load_config_from_env`): `DATABASE_URL` (req),
  `PROPOLIS_FEED_OUTPUT_DIR`, `PROPOLIS_FEED_BUILD_INTERVAL_SECS`,
  `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS`, `PROPOLIS_FEED_STANDARD_TTL_HOURS`,
  `PROPOLIS_FEED_ALLOWLIST`, `PROPOLIS_FEED_DELIST`,
  `PROPOLIS_FEED_ASN_ALLOWLIST`, `PROPOLIS_GEOIP_DIR`. **Does not read
  `PROPOLIS_FEED_WINDOWS`** (no `all-{label}` retention feeds in standalone).
- **`intake`** (`crates/intake/src/main.rs#load_config_from_env`): `DATABASE_URL` (req),
  `PROPOLIS_CURSOR_DIR`, `PROPOLIS_POLL_INTERVAL_MS`, `PROPOLIS_SENSOR_LOGS`
  (req, empty→abort).
- **`review`** (`crates/review/src/main.rs#load_config_from_env`): `DATABASE_URL` (req),
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

### Standard sensors (strict parse) - ssh, telnet, http, ftp, redis, adb, catchall, tftp, mqtt

Shared `ConnectionBounds` pattern via each crate's local
`parse_positive_u64`/`parse_positive_u32`: unset → default; **present-but-zero or
unparseable → abort startup** (no upper clamp - a very large timeout/bytes value
is accepted). `parse_wan_map` (e.g. `sensor-ssh/src/main.rs#parse_wan_map`): comma-sep
`local_ip=wan_ip`; empty/absent → empty map (valid: no WAN attribution, stamps a
null `wan_ip`); invalid entry → abort.

| Sensor | Prefix `<P>` | Bind variable (required) | Log path default |
|---|---|---|---|
| ssh | `PROPOLIS_SSH_` | `PROPOLIS_SSH_BIND` (unset → abort, `sensor-ssh/src/main.rs#load_config_from_env`) | `/var/log/propolis/ssh/events.jsonl` |
| telnet | `PROPOLIS_TELNET_` | `PROPOLIS_TELNET_BIND` | `/var/log/propolis/telnet/events.jsonl` |
| http | `PROPOLIS_HTTP_` | `PROPOLIS_HTTP_BIND` | `/var/log/propolis/http/events.jsonl` |
| ftp | `PROPOLIS_FTP_` | `PROPOLIS_FTP_BIND` | `/var/log/propolis/ftp/events.jsonl` |
| tftp | `PROPOLIS_TFTP_` | `PROPOLIS_TFTP_BIND` (UDP; unset aborts startup, `sensor-tftp/src/main.rs#load_config_from`) | `/var/log/propolis/tftp/events.jsonl` |
| mqtt | `PROPOLIS_MQTT_` | `PROPOLIS_MQTT_BIND` (unset aborts startup, `sensor-mqtt/src/main.rs#load_config_from_env`) | `/var/log/propolis/mqtt/events.jsonl` |
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
| `<P>MAX_CONCURRENT` | no | `256` (http `512`, tftp `128`) | u32; zero → abort |

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
- tftp: `PROPOLIS_TFTP_READ_TIMEOUT_MS`, `PROPOLIS_TFTP_IDLE_TIMEOUT_MS`,
  `PROPOLIS_TFTP_MAX_DURATION_SECS`, `PROPOLIS_TFTP_MAX_CAPTURED_BYTES`,
  `PROPOLIS_TFTP_MAX_CONCURRENT`, `PROPOLIS_TFTP_LOG_PATH`, `PROPOLIS_TFTP_WAN_MAP`.
  Unlike the other sensors, `PROPOLIS_TFTP_MAX_CAPTURED_BYTES` has an upper bound: a value above
  `10_000_000` (the spool's per-file limit) **aborts startup** instead of being accepted.
  The `128` default for `PROPOLIS_TFTP_MAX_CONCURRENT` is sized so `max_concurrent` full-cap bodies,
  the 64-job capture queue and about 15 MB of baseline stay within the unit's `MemoryMax=256M`
  (`sensor-tftp/src/main.rs#DEFAULT_MAX_CONCURRENT`). Raising `PROPOLIS_TFTP_MAX_CAPTURED_BYTES`
  toward the 10 MB hard cap requires lowering `PROPOLIS_TFTP_MAX_CONCURRENT` to stay under
  `MemoryMax`; the worst case is roughly `(max_concurrent + 64) * max_captured_bytes + 15 MB`.
- mqtt: `PROPOLIS_MQTT_READ_TIMEOUT_MS`, `PROPOLIS_MQTT_IDLE_TIMEOUT_MS`,
  `PROPOLIS_MQTT_MAX_DURATION_SECS`, `PROPOLIS_MQTT_MAX_CAPTURED_BYTES`,
  `PROPOLIS_MQTT_MAX_CONCURRENT`, `PROPOLIS_MQTT_LOG_PATH`, `PROPOLIS_MQTT_WAN_MAP`,
  `PROPOLIS_MQTT_SPOOL_DIR` (default `/var/spool/propolis/mqtt`,
  `sensor-mqtt/src/main.rs#DEFAULT_SPOOL_DIR`), `PROPOLIS_MQTT_OUTBOX_DIR` (default
  `/var/spool/propolis/mqtt/outbox`; see "Outbox manifest" below), `PROPOLIS_COLLECTOR_ID`
  and `PROPOLIS_MQTT_CAPTURE_MEMORY_BYTES` (see "Capture memory budget" below). A PUBLISH
  payload is spooled only when it looks binary; text payloads stay metadata-only.
  `PROPOLIS_MQTT_MAX_CAPTURED_BYTES` (default `1_000_000`) bounds the total bytes read per
  connection; a single packet is separately capped at 262144 bytes of declared remaining length
  (`sensor-mqtt/src/handler.rs#MAX_PACKET_BYTES`) and a connection at 1024 packets
  (`sensor-mqtt/src/handler.rs#MAX_PACKETS`), neither configurable.
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
  (default `/var/lib/propolis/ssh/host_key`, `sensor-ssh/src/main.rs#DEFAULT_HOST_KEY_PATH`), `PROPOLIS_SSH_SPOOL_DIR`
  (default `/var/spool/propolis/ssh`, `sensor-ssh/src/main.rs#DEFAULT_SPOOL_DIR`), `PROPOLIS_SSH_BANNER` (default =
  persona `OPENSSH_VERSION` = `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`, `sensor-ssh/src/main.rs#DEFAULT_BANNER` +
  `sensor-framework/src/persona.rs#OPENSSH_VERSION`; unset → default, a set-but-blank value is sent as-is (`sensor-ssh/src/main.rs#load_config_from_env`)), `PROPOLIS_SSH_OUTBOX_DIR` (default
  `/var/spool/propolis/ssh/outbox`; see "Outbox manifest" below).
- **ftp** (`crates/sensor-ftp/src/main.rs`): `PROPOLIS_FTP_SPOOL_DIR` (default
  `/var/spool/propolis/ftp`, `sensor-ftp/src/main.rs#DEFAULT_SPOOL_DIR`), `PROPOLIS_FTP_OUTBOX_DIR` (default
  `/var/spool/propolis/ftp/outbox`; see "Outbox manifest" below).
- **adb** (`crates/sensor-adb/src/main.rs`): `PROPOLIS_ADB_SPOOL_DIR` (default
  `/var/spool/propolis/adb`, `sensor-adb/src/main.rs#DEFAULT_SPOOL_DIR`), `PROPOLIS_ADB_OUTBOX_DIR` (default
  `/var/spool/propolis/adb/outbox`; see "Outbox manifest" below).
- **telnet** (`crates/sensor-telnet/src/main.rs`): `PROPOLIS_TELNET_SPOOL_DIR`
  (default `/var/spool/propolis/telnet`), `PROPOLIS_TELNET_OUTBOX_DIR` (default
  `/var/spool/propolis/telnet/outbox`; see "Outbox manifest" below).
- **tftp** (`crates/sensor-tftp/src/main.rs`): `PROPOLIS_TFTP_SPOOL_DIR` (default
  `/var/spool/propolis/tftp`, `sensor-tftp/src/main.rs#DEFAULT_SPOOL_DIR`), `PROPOLIS_TFTP_OUTBOX_DIR` (default
  `/var/spool/propolis/tftp/outbox`; see "Outbox manifest" below). `PROPOLIS_COLLECTOR_ID` is
  read by its canonical name only; there is no legacy bare spelling for this sensor.
  `PROPOLIS_TFTP_BIND` is the only switch: the sensor is off until an operator sets it, and with no
  bind (or an unparseable one) it logs the error and exits 1 without binding anything.
- **http**: `MAX_CONCURRENT` default is `512` (`crates/sensor-http/src/main.rs#DEFAULT_MAX_CONCURRENT`).
- **catchall**: no spool variable (never spools file bodies,
  `crates/sensor-catchall/src/main.rs#Config`); no
  outbox variable either (captures no file bodies, so nothing for SP-B-1b's
  manifest to record).

#### Outbox manifest (SP-B-1b)

Every sensor that spools captured file bodies (ssh, ftp, adb, telnet, tftp) also writes a durable
per-capture custody manifest row under its outbox directory as soon as the body is sealed - see
`sensor_framework::outbox` and `sensor_framework::handoff::process_job`. Two variables govern it,
read identically by each of those five sensors' `main.rs`:

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_COLLECTOR_ID` (deprecated alias `COLLECTOR_ID`, still read; shared across all six binaries, not `PROPOLIS_<SENSOR>_*`) | no | `local` | Stamped onto every manifest row this sensor writes. **Must equal** the CommonName of the client certificate `shipper`'s `PROPOLIS_COLLECTOR_ID` presents to the gateway on this box, because a later stage joins the gateway's cert-derived collector id against this manifest on `(collector_id, occurrence_id)`. A single-node deployment with no shipper leaves this at `local`. |
| `PROPOLIS_<SENSOR>_OUTBOX_DIR` | no | `<PROPOLIS_<SENSOR>_SPOOL_DIR>/outbox` | Root of the per-capture manifest JSON files (`<dir>/<capture_id>.json`). The default is derived from the sensor's own resolved spool directory (not a fixed shared path) so it always lands inside the writable root the sensor's systemd unit grants - a fixed shared `/var/lib/propolis/outbox` default is unwritable under `ProtectSystem=strict` and was the SP-B-1c regression this fixed. Manifest rows are keyed by a globally-unique `capture_id`, so even where two sensors' outbox dirs happened to coincide, writes would never collide. |

#### Capture memory budget

Each of the six body-capturing sensors holds a process-wide ceiling on the bytes of captured
bodies buffered in memory at once (`sensor_framework::capture_budget::CaptureMemoryBudget`), so
many concurrent uploads cannot together push the process past its systemd `MemoryMax`. A body is
charged in 64 KiB chunks from its first byte and refunded as soon as the hand-off worker has
spooled it (`sensor_framework::handoff::process_job`). One variable per sensor, read by that
sensor's `main.rs`:

| Variable | Req | Default | Notes |
|---|---|---|---|
| `PROPOLIS_SSH_CAPTURE_MEMORY_BYTES` | no | `214748364` (40% of the unit's `MemoryMax=512M`, `sensor-ssh/src/server.rs#DEFAULT_CAPTURE_BUDGET_BYTES`) | positive u64 bytes; zero or unparseable aborts startup |
| `PROPOLIS_FTP_CAPTURE_MEMORY_BYTES` | no | `107374182` (40% of `MemoryMax=256M`, `sensor-framework/src/capture_budget.rs#DEFAULT_CAPTURE_BUDGET_BYTES_256M`) | positive u64 bytes; zero or unparseable aborts startup |
| `PROPOLIS_ADB_CAPTURE_MEMORY_BYTES` | no | `107374182` | positive u64 bytes; zero or unparseable aborts startup |
| `PROPOLIS_TELNET_CAPTURE_MEMORY_BYTES` | no | `107374182` | positive u64 bytes; zero or unparseable aborts startup |
| `PROPOLIS_TFTP_CAPTURE_MEMORY_BYTES` | no | `107374182` | positive u64 bytes; zero or unparseable aborts startup |
| `PROPOLIS_MQTT_CAPTURE_MEMORY_BYTES` | no | `107374182` | positive u64 bytes; zero or unparseable aborts startup |

When a capture hits the ceiling it keeps the prefix already buffered, stops growing, and the
transfer is ended the way the protocol ends a full disk (FTP `451`, TFTP ERROR 3, SCP error byte,
SFTP `FAILURE`, ADB sync `FAIL`; a shell-stream capture just stops growing). The sample's event
metadata carries `truncated: true`, `complete: false` and `end_reason: "capture_memory_budget"`. A
capture that cannot buffer even one byte submits no sample and no `malware_upload` event (the
ordinary connection event is unaffected); the hand-off counts it as refused. The 40% share is an
unmeasured choice that leaves the rest of `MemoryMax` for the runtime, parsers, fake-filesystem
state and allocator overhead, none of which this budget charges. Raise the variable only together
with the unit's `MemoryMax`.

### Lenient sensors - cred, smtp

Invalid or zero bound → **silent default**, not abort.

- **sensor-smtp** (`crates/sensor-smtp/src/main.rs`): `PROPOLIS_SMTP_BIND` (req;
  unset → `exit(1)`, invalid → `exit(1)`, `sensor-smtp/src/main.rs#main`), `PROPOLIS_SMTP_WAN_MAP`
  (invalid entries silently skipped, `sensor-smtp/src/main.rs#parse_wan_map`), `PROPOLIS_SMTP_LOG_PATH` (default
  `/var/log/propolis/smtp/events.jsonl`), `PROPOLIS_SMTP_READ_TIMEOUT_MS`
  (`30_000`), `PROPOLIS_SMTP_IDLE_TIMEOUT_MS` (`60_000`),
  `PROPOLIS_SMTP_MAX_DURATION_SECS` (`600`), `PROPOLIS_SMTP_MAX_CAPTURED_BYTES`
  (`1_000_000`), `PROPOLIS_SMTP_MAX_CONCURRENT` (`256`).
- **sensor-cred** (`crates/sensor-cred/src/main.rs`): multi-protocol
  (VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Bind variables `PROPOLIS_CRED_VNC_BIND`,
  `PROPOLIS_CRED_MYSQL_BIND`, `PROPOLIS_CRED_MSSQL_BIND`, `PROPOLIS_CRED_PG_BIND`,
  `PROPOLIS_CRED_MONGO_BIND` (`sensor-cred/src/main.rs#main`). At
  least one required - none set → `exit(1)` (`sensor-cred/src/main.rs#main`); a set-but-invalid bind →
  `exit(1)` (`sensor-cred/src/main.rs#main`); all-configured-fail-to-bind → `exit(1)` (`sensor-cred/src/main.rs#main`).
  `PROPOLIS_CRED_WAN_MAP` (invalid skipped), `PROPOLIS_CRED_LOG_DIR` (default
  `/var/log/propolis/cred`, per-protocol file `<protocol>.jsonl`). Bounds:
  `PROPOLIS_CRED_READ_TIMEOUT_MS` (`30_000`), `PROPOLIS_CRED_IDLE_TIMEOUT_MS` (`60_000`),
  `PROPOLIS_CRED_MAX_DURATION_SECS` (**`60`**, differs from others' 600),
  `PROPOLIS_CRED_MAX_CAPTURED_BYTES` (**`100_000`**, differs from others' 1_000_000),
  `PROPOLIS_CRED_MAX_CONCURRENT` (`256`).

---

## Interactions

- **VT enable requires both**: `PROPOLIS_VT_ENABLED=true` **and** a non-empty
  `PROPOLIS_VT_KEY` (`crates/propolis/src/config.rs#load_config`). Either missing → VT off.
- **Vendor enable requires key**: `PROPOLIS_VENDOR_<V>_ENABLED=true` with an
  empty `_KEY` → forced disabled and warns (`crates/propolis/src/config.rs#load_vendor_config`, review
  `review/src/main.rs#load_vendor_config`).
- **DShield user+key composition**: `PROPOLIS_VENDOR_DSHIELD_USER` +
  `PROPOLIS_VENDOR_DSHIELD_KEY` compose to `{user}:{key}` in the single key slot
  (`crates/propolis/src/config.rs#load_config`). User alone is ignored.
- **ASN suppression needs GeoIP**: `PROPOLIS_FEED_ASN_ALLOWLIST` is inert unless
  `PROPOLIS_GEOIP_DIR` is set and the GeoLite2-ASN DB loads. The unified daemon
  warns when the ASN allowlist is set but `GEOIP_DIR` is unset (`propolis/src/main.rs#main`) or
  the ASN DB failed to load (`propolis/src/main.rs#main`).
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
