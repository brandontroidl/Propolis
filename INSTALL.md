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
PROPOLIS_FEED_OUTPUT_DIR=/var/lib/propolis/feed
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
```

### `/etc/propolis/catchall.env` (catch-all sensor)

```bash
PROPOLIS_CATCHALL_BIND=0.0.0.0:0
PROPOLIS_CATCHALL_WAN_MAP=10.0.0.1=198.51.100.1
PROPOLIS_CATCHALL_LOG_PATH=/var/log/propolis/catchall/events.jsonl
```

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
