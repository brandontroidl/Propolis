# Installing Propolis

Propolis runs on Linux with systemd. These instructions cover a single-node deployment; for
multi-node (cluster), repeat on each node pointing at the same PostgreSQL database.

## Prerequisites

- Linux with systemd (tested on Fedora 43; any systemd-based distro works)
- PostgreSQL 15+ (local or remote; one database shared by all nodes)
- Rust toolchain (for building from source; see `rust-toolchain.toml` for the pinned version)

## 1. Build

```bash
cargo build --release
```

This produces binaries in `target/release/`:

| Binary | Purpose |
|---|---|
| `propolis` | Unified daemon (intake + review + feed + console) |
| `sensor-catchall` | Port-scan detection sensor |
| `sensor-ssh` | SSH honeypot |
| `sensor-telnet` | Telnet honeypot |
| `sensor-redis` | Redis honeypot |
| `sensor-adb` | ADB honeypot (Android Debug Bridge) |
| `sensor-http` | HTTP request-logging honeypot |
| `sensor-ftp` | FTP honeypot with upload capture |
| `sensor-smtp` | SMTP honeypot (open-relay detection) |
| `sensor-cred` | Multi-protocol credential capture (VNC, MySQL, MSSQL, PostgreSQL, MongoDB) |

## 2. Run the install script

```bash
sudo ./deploy/install.sh
```

This provisions OS users, directories, systemd units, and logrotate. It is idempotent (safe to
re-run). Use `--dry-run` to preview without making changes.

What it creates:

- **Users:** `propolis`, `propolis-catchall`, `propolis-ssh`, `propolis-telnet`, `propolis-redis`,
  `propolis-adb`, `propolis-http`, `propolis-ftp`, `propolis-smtp`, `propolis-cred` (all system
  users, no login shell, no home directory)
- **Log dirs:** `/var/log/propolis/{catchall,ssh,telnet,redis,adb,http,ftp,smtp,cred}/`
- **Spool dirs:** `/var/spool/propolis/{catchall,ssh,adb,ftp}/` (for captured file uploads)
- **State dirs:** `/var/lib/propolis/{cursors,feed,spool}/`
- **Config dir:** `/etc/propolis/`
- **Binaries:** installed to `/usr/local/bin/`
- **Units:** installed to `/etc/systemd/system/`

## 3. Back the spool directories with noexec mounts

The quarantine spool directories hold attacker-uploaded files. They must be backed by
`noexec,nosuid,nodev` mounts so captured binaries cannot be executed even if permission bits are
misconfigured. Add to `/etc/fstab`:

```
tmpfs /var/spool/propolis/catchall tmpfs noexec,nosuid,nodev,size=256M 0 0
tmpfs /var/spool/propolis/ssh      tmpfs noexec,nosuid,nodev,size=256M 0 0
tmpfs /var/spool/propolis/adb      tmpfs noexec,nosuid,nodev,size=256M 0 0
tmpfs /var/spool/propolis/ftp      tmpfs noexec,nosuid,nodev,size=256M 0 0
tmpfs /var/lib/propolis/spool      tmpfs noexec,nosuid,nodev,size=256M 0 0
```

Then:

```bash
mount -a
findmnt /var/spool/propolis/ssh   # verify noexec is in effect
```

Size each mount for your expected upload volume. A dedicated partition works identically.

## 4. Create the database

Propolis runs its own migrations at startup. You only need to create the database and role:

```sql
CREATE ROLE propolis WITH LOGIN PASSWORD '...';
CREATE DATABASE propolis OWNER propolis;
```

**Important:** If running PostgreSQL in a container (podman/docker), ensure `pg_hba.conf` does
NOT contain `host all all all trust`. Replace it with a scoped rule for the container network
only (e.g., `host all all 10.88.0.0/16 md5` for the default podman network). The `trust` rule
means any process that can reach the container's port has full database access without a
password.

## 5. Configure the services

Create environment files in `/etc/propolis/`. Each file should be mode `0600`, owned by its
respective service user.

**Generate secrets first** (you will need these for `propolis.env` below):

```bash
# Console login password - pick something strong
CONSOLE_PW="$(openssl rand -base64 24)"
echo "Console password: $CONSOLE_PW"

# Session signing secret - must be exactly 64 hex characters (32 bytes)
SESSION_SECRET="$(openssl rand -hex 32)"
echo "Session secret:   $SESSION_SECRET"
```

### `/etc/propolis/propolis.env` (the unified daemon)

Replace `YOUR_PASSWORD`, `$CONSOLE_PW`, and `$SESSION_SECRET` with the real values.
Do not use the placeholder strings literally - the daemon validates the session secret
format and will refuse to start.

```bash
# Database (required)
DATABASE_URL=postgres://propolis:YOUR_PASSWORD@localhost:5432/propolis
PROPOLIS_DB_MAX_CONNECTIONS=10

# Intake - comma-separated name:path pairs for each sensor log to tail
PROPOLIS_SENSOR_LOGS=catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl,telnet:/var/log/propolis/telnet/events.jsonl,redis:/var/log/propolis/redis/events.jsonl,adb:/var/log/propolis/adb/events.jsonl,http:/var/log/propolis/http/events.jsonl,ftp:/var/log/propolis/ftp/events.jsonl,smtp:/var/log/propolis/smtp/events.jsonl,cred-vnc:/var/log/propolis/cred/vnc.jsonl,cred-mysql:/var/log/propolis/cred/mysql.jsonl,cred-mssql:/var/log/propolis/cred/mssql.jsonl,cred-pg:/var/log/propolis/cred/postgresql.jsonl,cred-mongo:/var/log/propolis/cred/mongodb.jsonl
PROPOLIS_CURSOR_DIR=/var/lib/propolis/cursors
PROPOLIS_POLL_INTERVAL_MS=1000

# Review (set PROPOLIS_REVIEW_ENABLED=false to disable on this node)
PROPOLIS_REVIEW_ENABLED=true
PROPOLIS_QUEUE_SCAN_INTERVAL_SECS=60
PROPOLIS_SUBMIT_POLL_INTERVAL_SECS=30
# Vendor API keys (set per vendor)
# PROPOLIS_VENDOR_ABUSEIPDB_ENABLED=true
# PROPOLIS_VENDOR_ABUSEIPDB_KEY=...

# Feed (set PROPOLIS_FEED_ENABLED=false to disable on this node)
PROPOLIS_FEED_ENABLED=true
# Note the trailing /current, and do not drop it. The publisher swaps a whole directory into place
# atomically, which means creating sibling staging/previous directories NEXT TO this one - so this
# path must sit one level inside the writable root, not at it. Pointing it at /var/lib/propolis/feed
# puts those siblings in /var/lib/propolis: that happens to work under propolis.service, which
# grants the wider ReadWritePaths=/var/lib/propolis, and fails under feed.service, which grants only
# /var/lib/propolis/feed. This file previously documented the shorter path.
PROPOLIS_FEED_OUTPUT_DIR=/var/lib/propolis/feed/current
PROPOLIS_FEED_BUILD_INTERVAL_SECS=900
# Retention feeds, published as all-{label}.* alongside the two tiers. Each carries every approved
# address whose last activity falls inside the window, regardless of tier, so the windows nest.
# The label is parsed for its own duration (<count>h or <count>d), so a filename cannot advertise a
# window the builder does not apply. Set empty to publish only the two tiered feeds.
PROPOLIS_FEED_WINDOWS=24h,7d,30d,60d,90d

# Console (loopback only by default)
PROPOLIS_CONSOLE_BIND=127.0.0.1:8080
PROPOLIS_CONSOLE_PASSWORD=<your console password>
PROPOLIS_CONSOLE_SESSION_SECRET=<output of openssl rand -hex 32>
```

### `/etc/propolis/ssh.env` (SSH sensor)

```bash
PROPOLIS_SSH_BIND=0.0.0.0:22
PROPOLIS_SSH_WAN_MAP=10.0.0.1=198.51.100.1
PROPOLIS_SSH_LOG_PATH=/var/log/propolis/ssh/events.jsonl
PROPOLIS_SSH_SPOOL_DIR=/var/spool/propolis/ssh
# Connection bounds. Optional - these are the defaults, shown because raising max_concurrent or
# max_duration on an internet-facing listener is how descriptors run out. A value of 0 is
# rejected at startup rather than treated as "unlimited".
PROPOLIS_SSH_READ_TIMEOUT_MS=30000
PROPOLIS_SSH_IDLE_TIMEOUT_MS=60000
PROPOLIS_SSH_MAX_DURATION_SECS=600
PROPOLIS_SSH_MAX_CAPTURED_BYTES=1000000
PROPOLIS_SSH_MAX_CONCURRENT=256
# The software-version sent in the SSH banner (SSH-2.0-<this>). Default is a common current
# OpenSSH-on-Ubuntu string so the honeypot blends into the internet's largest SSH population; a
# unique constant banner would let one Shodan/Censys query enumerate every node. Set this per host
# so the fleet does not share one value. (The key-exchange offer is a minimal fixed set, so a
# determined HASSH probe can still fingerprint the server regardless of this banner.)
PROPOLIS_SSH_BANNER=OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
```

### `/etc/propolis/catchall.env` (catch-all sensor)

```bash
# NOTE: the catch-all is the one sensor whose variables are NOT prefixed PROPOLIS_, and it takes
# a comma-separated LIST of addresses rather than a single one. This file previously documented
# PROPOLIS_CATCHALL_BIND=0.0.0.0:0, which the binary does not read: it would refuse to start with
# "CATCHALL_BIND_ADDRS must name at least one bind address". Check `systemctl status
# sensor-catchall` if you configured this host from the older instructions.
CATCHALL_BIND_ADDRS=0.0.0.0:23,0.0.0.0:102,0.0.0.0:445,0.0.0.0:1433,0.0.0.0:3389
CATCHALL_WAN_MAP=10.0.0.1=198.51.100.1
CATCHALL_LOG_PATH=/var/log/propolis/catchall/events.jsonl
```

Bind whichever unserved ports you want recorded. Port 102 is worth including: it is Siemens S7comm,
and the sequential scanning of it that five US agencies flagged on 2026-08-19 (NSA, CISA, FBI, DOE,
EPA) is exactly what a catch-all listener is for. Note the limit, though - a catch-all records a
`catchall_probe`, which is `Category::Network` and never `authenticated`, so it cannot satisfy the
`confirmed_real` gate on its own. A host that only ever scans port 102 is visible in the console and
corroborates other signals from the same address, but is never published or reported by itself.
Making S7comm reconnaissance publishable in its own right needs a sensor that speaks enough of the
protocol to record which data blocks were read or written.

### Remaining sensor env files

Each sensor follows the same pattern: the env var prefix matches the sensor name, only
`*_BIND` is required, and `*_WAN_MAP`, `*_LOG_PATH`, `*_SPOOL_DIR` (for sensors with upload
capture), and timeout/concurrency overrides are optional. **Every sensor needs its env file
created before starting the service, even if it contains only the bind address.**

`/etc/propolis/telnet.env`:

```bash
PROPOLIS_TELNET_BIND=0.0.0.0:23
# PROPOLIS_TELNET_WAN_MAP=10.0.0.1=198.51.100.1
```

`/etc/propolis/redis.env`:

```bash
PROPOLIS_REDIS_BIND=0.0.0.0:6379
# PROPOLIS_REDIS_WAN_MAP=10.0.0.1=198.51.100.1
```

`/etc/propolis/adb.env`:

```bash
PROPOLIS_ADB_BIND=0.0.0.0:5555
# PROPOLIS_ADB_WAN_MAP=10.0.0.1=198.51.100.1
```

`/etc/propolis/http.env`:

```bash
PROPOLIS_HTTP_BIND=0.0.0.0:80
# PROPOLIS_HTTP_WAN_MAP=10.0.0.1=198.51.100.1
```

`/etc/propolis/ftp.env`:

```bash
PROPOLIS_FTP_BIND=0.0.0.0:21
# PROPOLIS_FTP_WAN_MAP=10.0.0.1=198.51.100.1
```

`/etc/propolis/smtp.env`:

```bash
PROPOLIS_SMTP_BIND=0.0.0.0:25
# PROPOLIS_SMTP_WAN_MAP=10.0.0.1=198.51.100.1
```

`/etc/propolis/cred.env` (one binary, multiple protocol listeners):

```bash
PROPOLIS_CRED_VNC_BIND=0.0.0.0:5900
PROPOLIS_CRED_MYSQL_BIND=0.0.0.0:3306
PROPOLIS_CRED_MSSQL_BIND=0.0.0.0:1433
PROPOLIS_CRED_PG_BIND=0.0.0.0:5432
PROPOLIS_CRED_MONGO_BIND=0.0.0.0:27017
# PROPOLIS_CRED_WAN_MAP=10.0.0.1=198.51.100.1
PROPOLIS_CRED_LOG_DIR=/var/log/propolis/cred
```

Set ownership and permissions on each file:

```bash
for sensor in catchall ssh telnet redis adb http ftp smtp cred; do
    chown "propolis-${sensor}:propolis-${sensor}" "/etc/propolis/${sensor}.env"
    chmod 0600 "/etc/propolis/${sensor}.env"
done
chown propolis:propolis /etc/propolis/propolis.env
chmod 0600 /etc/propolis/propolis.env
```

The `WAN_MAP` value is a comma-separated list of `local_ip=wan_ip` pairs mapping this host's
local (private) addresses to the WAN IPs they are NAT'd behind. This is how Propolis knows which
of your public addresses each hit arrived on. If the host binds WAN IPs directly (no NAT), leave
`WAN_MAP` empty.

## 6. Start services

```bash
# Start the unified daemon
systemctl enable --now propolis.service

# Start sensors (enable whichever you want to run on this node)
systemctl enable --now sensor-catchall.service
systemctl enable --now sensor-ssh.service
systemctl enable --now sensor-telnet.service
systemctl enable --now sensor-redis.service
systemctl enable --now sensor-adb.service
systemctl enable --now sensor-http.service
systemctl enable --now sensor-ftp.service
systemctl enable --now sensor-smtp.service
systemctl enable --now sensor-cred.service
```

## 7. Verify

```bash
# Check all services are running
systemctl status propolis sensor-ssh sensor-telnet sensor-redis

# Check the console is up (loopback)
curl -s http://127.0.0.1:8080/health

# Watch sensor events arriving
tail -f /var/log/propolis/ssh/events.jsonl

# Check the journal for any startup errors
journalctl -u propolis -u sensor-ssh --since "5 minutes ago"
```

## Multi-node deployment

For a cluster of N nodes sharing one PostgreSQL database:

1. Run steps 1-6 on each node.
2. Point every node's `DATABASE_URL` at the same PostgreSQL instance.
3. Set each node's `WAN_MAP` to its own local-to-WAN mapping.
4. Optionally disable review submission and feed builds on all but one node
   (`PROPOLIS_REVIEW_ENABLED=false`, `PROPOLIS_FEED_ENABLED=false`) to avoid duplicate vendor API
   calls. This is a convenience, not a correctness requirement - both are idempotent.

Cross-node breadth accumulates automatically: the shared database aggregates every node's events
into one score per attacker IP.

## Firewall considerations

Sensors need inbound access on their configured ports. The unified daemon needs:
- Outbound HTTPS to vendor APIs (AbuseIPDB, DShield, OTX) if review submission is enabled
- Outbound PostgreSQL (port 5432) to the database if remote
- Loopback TCP for the console (default 127.0.0.1:8080)

Sensors make no outbound connections by design.

## Environment variable reference

Every environment variable the binaries read, grouped by component. Required vars are noted
in the sections above; the rest are optional overrides with sensible defaults. The per-sensor
`*_READ_TIMEOUT_MS` / `*_IDLE_TIMEOUT_MS` / `*_MAX_DURATION_SECS` / `*_MAX_CAPTURED_BYTES` /
`*_MAX_CONCURRENT` bounds all default to the same values shown for SSH above.

**shared persona (all sensors)**

- `PROPOLIS_HOSTNAME` - the hostname the fake shell, fake filesystem (`/etc/hostname`, `/etc/hosts`),
  and `uname` present. Defaults to `server01`. Set it once, globally (in a shared env sourced by
  every sensor), so the sensors cannot disagree with each other on the host identity.

**intake / database**

- `PROPOLIS_CURSOR_DIR`
- `PROPOLIS_DB_MAX_CONNECTIONS`
- `PROPOLIS_POLL_INTERVAL_MS`
- `PROPOLIS_SENSOR_LOGS`

**review**

- `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS`
- `PROPOLIS_REVIEW_ENABLED`
- `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS`

**vendor reporting**

- `PROPOLIS_VENDOR_ABUSEIPDB_KEY`
- `PROPOLIS_VENDOR_ABUSEIPDB_URL`
- `PROPOLIS_VENDOR_DSHIELD_KEY`
- `PROPOLIS_VENDOR_DSHIELD_URL`
- `PROPOLIS_VENDOR_DSHIELD_USER`
- `PROPOLIS_VENDOR_OTX_KEY`
- `PROPOLIS_VENDOR_OTX_URL`

**virustotal sample scanning**

- `PROPOLIS_VT_ENABLED`
- `PROPOLIS_VT_KEY`
- `PROPOLIS_VT_SCAN_INTERVAL_SECS`
- `PROPOLIS_VT_UPLOAD`

**feed builder**

- `PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS`
- `PROPOLIS_FEED_ALLOWLIST`
- `PROPOLIS_FEED_BUILD_INTERVAL_SECS`
- `PROPOLIS_FEED_DELIST`
- `PROPOLIS_FEED_ENABLED`
- `PROPOLIS_FEED_OUTPUT_DIR`
- `PROPOLIS_FEED_STANDARD_TTL_HOURS`
- `PROPOLIS_FEED_WINDOWS`

**console**

- `PROPOLIS_CONSOLE_BIND`
- `PROPOLIS_CONSOLE_PASSWORD`
- `PROPOLIS_CONSOLE_SESSION_SECRET`

**ssh sensor**

- `PROPOLIS_SSH_BANNER`
- `PROPOLIS_SSH_BIND`
- `PROPOLIS_SSH_HOST_KEY_PATH`
- `PROPOLIS_SSH_IDLE_TIMEOUT_MS`
- `PROPOLIS_SSH_LOG_PATH`
- `PROPOLIS_SSH_MAX_CAPTURED_BYTES`
- `PROPOLIS_SSH_MAX_CONCURRENT`
- `PROPOLIS_SSH_MAX_DURATION_SECS`
- `PROPOLIS_SSH_READ_TIMEOUT_MS`
- `PROPOLIS_SSH_SPOOL_DIR`
- `PROPOLIS_SSH_WAN_MAP`

**telnet sensor**

- `PROPOLIS_TELNET_BIND`
- `PROPOLIS_TELNET_IDLE_TIMEOUT_MS`
- `PROPOLIS_TELNET_LOG_PATH`
- `PROPOLIS_TELNET_MAX_CAPTURED_BYTES`
- `PROPOLIS_TELNET_MAX_CONCURRENT`
- `PROPOLIS_TELNET_MAX_DURATION_SECS`
- `PROPOLIS_TELNET_READ_TIMEOUT_MS`
- `PROPOLIS_TELNET_WAN_MAP`

**redis sensor**

- `PROPOLIS_REDIS_BIND`
- `PROPOLIS_REDIS_IDLE_TIMEOUT_MS`
- `PROPOLIS_REDIS_LOG_PATH`
- `PROPOLIS_REDIS_MAX_CAPTURED_BYTES`
- `PROPOLIS_REDIS_MAX_CONCURRENT`
- `PROPOLIS_REDIS_MAX_DURATION_SECS`
- `PROPOLIS_REDIS_READ_TIMEOUT_MS`
- `PROPOLIS_REDIS_WAN_MAP`

**adb sensor**

- `PROPOLIS_ADB_BIND`
- `PROPOLIS_ADB_IDLE_TIMEOUT_MS`
- `PROPOLIS_ADB_LOG_PATH`
- `PROPOLIS_ADB_MAX_CAPTURED_BYTES`
- `PROPOLIS_ADB_MAX_CONCURRENT`
- `PROPOLIS_ADB_MAX_DURATION_SECS`
- `PROPOLIS_ADB_READ_TIMEOUT_MS`
- `PROPOLIS_ADB_SPOOL_DIR`
- `PROPOLIS_ADB_WAN_MAP`

**http sensor**

- `PROPOLIS_HTTP_BIND`
- `PROPOLIS_HTTP_IDLE_TIMEOUT_MS`
- `PROPOLIS_HTTP_LOG_PATH`
- `PROPOLIS_HTTP_MAX_CAPTURED_BYTES`
- `PROPOLIS_HTTP_MAX_CONCURRENT`
- `PROPOLIS_HTTP_MAX_DURATION_SECS`
- `PROPOLIS_HTTP_READ_TIMEOUT_MS`
- `PROPOLIS_HTTP_WAN_MAP`

**ftp sensor**

- `PROPOLIS_FTP_BIND`
- `PROPOLIS_FTP_IDLE_TIMEOUT_MS`
- `PROPOLIS_FTP_LOG_PATH`
- `PROPOLIS_FTP_MAX_CAPTURED_BYTES`
- `PROPOLIS_FTP_MAX_CONCURRENT`
- `PROPOLIS_FTP_MAX_DURATION_SECS`
- `PROPOLIS_FTP_READ_TIMEOUT_MS`
- `PROPOLIS_FTP_SPOOL_DIR`
- `PROPOLIS_FTP_WAN_MAP`

**smtp sensor**

- `PROPOLIS_SMTP_BIND`
- `PROPOLIS_SMTP_IDLE_TIMEOUT_MS`
- `PROPOLIS_SMTP_LOG_PATH`
- `PROPOLIS_SMTP_MAX_CAPTURED_BYTES`
- `PROPOLIS_SMTP_MAX_CONCURRENT`
- `PROPOLIS_SMTP_MAX_DURATION_SECS`
- `PROPOLIS_SMTP_READ_TIMEOUT_MS`
- `PROPOLIS_SMTP_WAN_MAP`

**cred sensor**

- `PROPOLIS_CRED_IDLE_TIMEOUT_MS`
- `PROPOLIS_CRED_LOG_DIR`
- `PROPOLIS_CRED_MAX_CAPTURED_BYTES`
- `PROPOLIS_CRED_MAX_CONCURRENT`
- `PROPOLIS_CRED_MAX_DURATION_SECS`
- `PROPOLIS_CRED_MONGO_BIND`
- `PROPOLIS_CRED_MSSQL_BIND`
- `PROPOLIS_CRED_MYSQL_BIND`
- `PROPOLIS_CRED_PG_BIND`
- `PROPOLIS_CRED_READ_TIMEOUT_MS`
- `PROPOLIS_CRED_VNC_BIND`
- `PROPOLIS_CRED_WAN_MAP`

**catchall sensor**

- `CATCHALL_BIND_ADDRS`
- `CATCHALL_IDLE_TIMEOUT_MS`
- `CATCHALL_LOG_PATH`
- `CATCHALL_MAX_CAPTURED_BYTES`
- `CATCHALL_MAX_CONCURRENT`
- `CATCHALL_MAX_DURATION_SECS`
- `CATCHALL_READ_TIMEOUT_MS`
- `CATCHALL_WAN_MAP`
