# Sub-project 8: remaining native sensors

Detailed design spec for the Propolis-new additional sensor layer (Rust). Seven new sensor crates
built on the sub-project 2 framework harness, each a thin protocol handler that inherits the
shared isolation contract, capture sanitization, event emission, and quarantine spool.

## Purpose and scope

This layer adds seven protocol-specific honeypot sensors that broaden the attack surface coverage
to match the major honeypot platforms (T-Pot, Cowrie, Dionaea, Heralding, ADBHoney,
RedisHoneypot). Each sensor follows the same pattern as sensor-ssh but is simpler (most need no
cryptography).

All sensors inherit from sensor-framework and share these properties:
- Passive-only (no outbound traffic, no exec, no hack-back)
- Unprivileged, no database handle, no secrets
- PII dropped at capture (passwords read to advance the parser, then discarded)
- Capture sanitization through sanitize_value (the single chokepoint)
- Quarantine spool for captured file bodies
- One-directional log flow (sensor writes, intake reads)
- Hardened systemd unit per sensor

All sensors emit existing `Honeypot*` signal types from core-scoring's frozen enum. No new
signal types are needed.

## Architecture

Seven new crates, added to the workspace:

| Crate | Port(s) | Protocol | Emulation depth |
|---|---|---|---|
| `sensor-telnet` | 23 | Telnet (RFC 854) | Fake shell (reuse FakeFs/FakeShell) |
| `sensor-redis` | 6379 | RESP (Redis protocol) | INFO/CONFIG/AUTH/SET/GET responses |
| `sensor-adb` | 5555 | ADB over TCP | Shell + push capture |
| `sensor-http` | 80, 8080, 8443 | HTTP/1.1 | Request logging, canned responses |
| `sensor-ftp` | 21 | FTP (RFC 959) | Auth + STOR capture, RETR/PORT refused |
| `sensor-smtp` | 25 | SMTP (RFC 5321) | Auth + DATA capture, never relay |
| `sensor-cred` | 5900,3306,1433,5432,27017 | VNC/MySQL/MSSQL/PostgreSQL/MongoDB | Auth exchange only |

Each crate has a binary target (the sensor process) and a lib.rs for testing.

### Shared code extraction

`sensor-telnet` reuses `FakeFs` and `FakeShell` from sensor-ssh. Rather than duplicating, extract
these into `sensor-framework` as shared modules (or have sensor-telnet depend on sensor-ssh as a
library). The recommended approach: move `FakeFs` and `FakeShell` into `sensor-framework` since
they are protocol-independent (the shell is the same whether reached via SSH or Telnet), and have
both sensor-ssh and sensor-telnet depend on them from there.

## Per-sensor design

### sensor-telnet (port 23)

Telnet is the simplest sensor: no cryptography, no key exchange. The protocol is a byte stream
with optional Telnet option negotiation (IAC sequences).

**Emulation:**
1. Accept TCP connection, emit `honeypot_connection` (authenticated=false).
2. Negotiate basic Telnet options (WILL/WONT ECHO, SGA). Refuse all others.
3. Present a login prompt. Capture username and password (drop password immediately).
4. Accept all credentials, emit `honeypot_login_attempt` (authenticated=true).
5. Present the fake shell (same FakeShell as SSH). Capture commands as
   `honeypot_command_exec`.
6. Never exec, never fetch.

**protocol_label:** `telnet`

### sensor-redis (port 6379)

Redis uses the RESP (Redis Serialization Protocol) - a text-based protocol that is trivial to
parse. Attackers scan for unauthenticated Redis instances to write cron jobs, SSH authorized_keys,
and webshells.

**Emulation:**
1. Accept TCP connection, emit `honeypot_connection`.
2. Parse RESP commands. Respond to:
   - `PING` -> `+PONG`
   - `INFO` -> canned server info (fake Redis version, OS, memory)
   - `CONFIG GET *` -> canned config
   - `AUTH <password>` -> capture password (drop), respond `+OK`
   - `SET <key> <value>` -> respond `+OK`, capture key+value as indicators
   - `GET <key>` -> respond `$-1` (nil)
   - `SLAVEOF` / `REPLICAOF` -> log as indicator, respond `+OK`
   - `CONFIG SET dir/dbfilename` -> log as indicator (filesystem write attempt), respond `+OK`
   - `EVAL` / `SCRIPT` -> log as indicator (Lua execution attempt), respond error
   - Unknown commands -> respond `-ERR unknown command`
3. An AUTH command sets `authenticated = true` and emits `honeypot_login_attempt`.
4. SET/CONFIG SET/SLAVEOF/EVAL commands emit `honeypot_command_exec` with the command as
   metadata.

**protocol_label:** `redis`

### sensor-adb (port 5555)

ADB (Android Debug Bridge) over TCP has no authentication. Attackers use it to push malware and
recruit IoT botnets.

**Emulation:**
1. Accept TCP connection. ADB uses a simple header-based protocol:
   `CNXN` (connect), `OPEN` (open stream), `WRTE` (write data), `CLSE` (close).
2. Respond to `CNXN` with a device banner (fake Android device: model, product, features).
3. Emit `honeypot_connection` (authenticated=false). ADB has no auth, but the connection itself
   is the confirmed-real event (TCP handshake completed).
4. Handle `OPEN shell:` -> present a fake shell (reuse FakeShell with Android-flavored paths).
   Commands captured as `honeypot_command_exec`.
5. Handle `OPEN push:` (file push) -> capture body to quarantine spool, emit
   `honeypot_malware_upload`.
6. Handle `OPEN pull:` -> refuse (no outbound data), log as indicator.

**protocol_label:** `adb`

**Note:** ADB's `authenticated` field is always `false` (no auth exchange). The TCP handshake
itself is the confirmed-real signal. Since `is_confirmed_real` requires `authenticated = true AND
category = Honeypot`, ADB events alone do not make an IP eligible. They contribute breadth and
weight but not eligibility. This is correct: ADB probes are often UDP-discovered then TCP-attacked,
and the confirmed-real gate exists precisely to prevent spoofed/unauthenticated signal from
manufacturing eligibility.

### sensor-http (port 80, 8080, 8443)

HTTP scanning is the highest-volume traffic after SSH/Telnet. Attackers probe for path traversal,
webshells, JNDI injection, exposed admin panels, and vulnerable frameworks.

**Emulation:**
1. Accept TCP connection, emit `honeypot_connection`.
2. Parse HTTP/1.1 request line + headers. Capture:
   - Method, path, query string
   - Host, User-Agent, Content-Type headers
   - Request body (truncated, sanitized)
3. Log suspicious paths as indicators (e.g., `/wp-login.php`, `/.env`, `/actuator`,
   `/${jndi:ldap://...}`, `/../../../etc/passwd`).
4. Return canned responses:
   - `/` -> 200 with a minimal HTML page (generic server)
   - `/robots.txt` -> 200 with `Disallow: /`
   - Everything else -> 404
5. POST/PUT with a body -> capture body content as metadata indicator.
6. No outbound requests. No server-side execution. No CGI, no proxy.

**protocol_label:** `http`

**Note:** HTTP events use `authenticated = false` (HTTP basic auth is not emulated in the initial
implementation). Like ADB, HTTP probes contribute weight and breadth but not eligibility.

### sensor-ftp (port 21)

FTP is a well-known malware staging protocol. Attackers brute-force FTP credentials and use STOR
to upload webshells and malware.

**Emulation:**
1. Accept TCP connection, send `220 FTP server ready` banner, emit `honeypot_connection`.
2. Handle FTP commands:
   - `USER <name>` -> capture username, respond `331 Password required`
   - `PASS <password>` -> capture password (drop), respond `230 Login successful`,
     emit `honeypot_login_attempt` (authenticated=true)
   - `LIST` / `NLST` -> respond with canned directory listing (fake files)
   - `STOR <filename>` -> accept upload, capture body to quarantine spool,
     emit `honeypot_malware_upload`
   - `RETR <filename>` -> respond `550 Permission denied` (never serve files)
   - `PORT` / `EPRT` -> respond `502 Not implemented` (never connect back - the
     no-attacker-directed-fetch rule, same as SSH)
   - `PASV` / `EPSV` -> open a data listener for STOR only
   - `QUIT` -> close
   - Unknown -> respond `502 Not implemented`
3. Never connect to attacker-named hosts (PORT/EPRT refused, RETR refused).

**protocol_label:** `ftp`

### sensor-smtp (port 25)

SMTP honeypots capture open relay probes, credential harvesting, and spam infrastructure
indicators.

**Emulation:**
1. Accept TCP connection, send `220 mail.example.com ESMTP` banner, emit `honeypot_connection`.
2. Handle SMTP commands:
   - `EHLO/HELO` -> respond with capabilities (8BITMIME, SIZE, AUTH PLAIN LOGIN)
   - `AUTH PLAIN/LOGIN` -> capture credentials (drop), respond `235 OK`,
     emit `honeypot_login_attempt` (authenticated=true)
   - `MAIL FROM:<addr>` -> respond `250 OK`, capture sender
   - `RCPT TO:<addr>` -> respond `250 OK`, capture recipient
   - `DATA` -> accept until `.` terminator, capture body (sanitized, truncated to max),
     emit `honeypot_command_exec` with sender/recipient/subject as metadata
   - `QUIT` -> close
3. Never actually relay. The captured email body is an indicator, not a forwarded message.

**protocol_label:** `smtp`

### sensor-cred (ports 5900, 3306, 1433, 5432, 27017)

Multi-protocol credential capture sensor modeled on Heralding. Implements just enough of each
protocol to reach the authentication exchange, captures the offered credentials, then closes the
connection. No post-auth emulation.

**Protocols:**
- **VNC (5900):** RFB protocol. Send ProtocolVersion + SecurityType(VNC Authentication).
  Receive encrypted password response. Cannot extract the plaintext (challenge-response), but the
  attempt itself is the signal. Emit `honeypot_login_attempt`.
- **MySQL (3306):** MySQL handshake protocol. Send greeting with auth challenge. Receive
  HandshakeResponse with username (capture) + auth response. Respond with OK or ERR.
  Emit `honeypot_login_attempt`.
- **MSSQL (1433):** TDS pre-login + login7. Parse Login7 packet for username. Respond with
  LOGINACK. Emit `honeypot_login_attempt`.
- **PostgreSQL (5432):** Startup message + AuthenticationMD5Password challenge. Receive
  PasswordMessage. Capture username from startup message. Respond with AuthenticationOk.
  Emit `honeypot_login_attempt`.
- **MongoDB (27017):** Wire protocol OP_MSG. Parse `isMaster` and `authenticate` commands.
  Capture username. Respond with a canned OK.

All five share one binary (`sensor-cred`) with per-port protocol detection based on the configured
port number. Each port gets its own listener.

**protocol_label:** `vnc`, `mysql`, `mssql`, `postgresql`, `mongodb` (per protocol)

## Signal type mapping

All sensors use existing `Honeypot*` signal types:

| Event | Signal type | authenticated |
|---|---|---|
| TCP connection established | `honeypot_connection` | false |
| Successful auth (any protocol) | `honeypot_login_attempt` | true |
| Command captured | `honeypot_command_exec` | true (or false if no auth, e.g., ADB/HTTP) |
| File uploaded | `honeypot_malware_upload` | true (or false) |
| File download refused | `honeypot_file_download` | true (or false) |

## Testing strategy

Each sensor follows the same testing pattern as sensor-ssh:

- **Protocol round-trip.** Connect, complete the protocol handshake, verify events emitted with
  correct signal types and protocol_label.
- **Credential capture.** Offer a known credential, verify it does NOT appear in any emitted event.
- **Command capture.** (Where applicable) Type commands, verify `honeypot_command_exec` events
  with sanitized metadata.
- **Upload capture.** (Where applicable) Upload a file, verify it appears in the quarantine spool
  by SHA-256 and the event references it.
- **No outbound fetch.** (FTP RETR/PORT, ADB pull) Verify the sensor refuses and opens zero
  outbound connections.
- **Never exec.** Static source scan (same as sensor-ssh's `never_exec_static_check`).
- **Accept loop resilience.** Malformed input drops the connection, never crashes the listener.

## Deployment

Each sensor gets its own hardened systemd unit following the SP2 pattern:
- Dedicated OS user per sensor
- `CAP_NET_BIND_SERVICE` for privileged ports (23, 21, 25, 80)
- `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`
- Per-sensor log directory and spool directory

The install script from SP7 (`deploy/install.sh`) is extended to provision the additional users
and directories.

## Decisions closed by this spec

1. Sensor set: **Telnet, Redis, ADB, HTTP, FTP, SMTP, credential multi-protocol (VNC, MySQL,
   MSSQL, PostgreSQL, MongoDB).**
2. Emulation depth: **protocol-specific, enough to capture credentials + commands + uploads.
   No real execution, no outbound fetch.**
3. Signal types: **existing Honeypot* enum, no additions.**
4. FakeShell reuse: **extract into sensor-framework for Telnet/ADB sharing with SSH.**
5. Credential sensor: **one binary, per-port protocol detection, five protocols.**
