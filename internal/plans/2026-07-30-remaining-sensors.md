# Remaining Native Sensors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 8 - seven new sensor crates (telnet, redis, adb, http, ftp, smtp, credential multi-protocol) on the existing sensor-framework harness, plus extraction of FakeFs/FakeShell into the shared framework for reuse.

**Architecture:** Each sensor is a thin protocol handler over sensor-framework. All inherit listener lifecycle, capture sanitization, WAN attribution, event emission, quarantine spool, and capture hand-off. All emit existing Honeypot* signal types. Canonical spec: `internal/design/08-remaining-sensors.md`.

**Tech Stack:** Rust (2024 edition), `sensor-wire` (wire types), `sensor-framework` (harness), `tokio` (async), `tracing`. No crypto needed (unlike sensor-ssh). No database dependency.

## Global Constraints

- **Rust 2024 edition.** New crates at `crates/sensor-{telnet,redis,adb,http,ftp,smtp,cred}`.
- **No database dependency.** Sensors have no DB handle.
- **No secrets.** No API keys, no vendor tokens.
- **No outbound network.** No HTTP client, no outbound fetch, no process spawning.
- **Passive-only.** No active response beyond protocol-required server messages.
- **PII dropped at capture.** Passwords read and immediately discarded.
- **Capture sanitization.** All attacker-controlled values through sanitize_value.
- **Never exec.** Static source scan test per sensor crate.
- **Each sensor follows the sensor-ssh pattern:** lib.rs + main.rs, tests with real TCP connections.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: Extract FakeFs + FakeShell into sensor-framework

**Files:**
- Move: `crates/sensor-ssh/src/fakefs.rs` -> `crates/sensor-framework/src/fakefs.rs`
- Move: `crates/sensor-ssh/src/shell.rs` -> `crates/sensor-framework/src/shell.rs`
- Modify: `crates/sensor-ssh/src/lib.rs` (re-export from sensor-framework instead)
- Modify: `crates/sensor-framework/src/lib.rs` (add pub mod fakefs, shell)
- Modify: `crates/sensor-ssh/tests/shell_test.rs` (update imports)

The FakeFs and FakeShell are protocol-independent. Moving them to sensor-framework lets sensor-telnet and sensor-adb reuse them without depending on sensor-ssh.

**IMPORTANT:** sensor-ssh's existing tests must still pass after the move. The public API (FakeFs::new, FakeShell::new, handle_input) stays identical. sensor-ssh re-exports them from sensor-framework so existing imports work.

Tests: all existing sensor-ssh shell_test.rs tests pass. No new tests needed.

---

### Task 2: sensor-telnet

**Files:**
- Create: `crates/sensor-telnet/Cargo.toml`, `crates/sensor-telnet/src/{lib.rs,main.rs,handler.rs,telnet.rs}`
- Test: `crates/sensor-telnet/tests/integration.rs`

Telnet is the simplest sensor: no crypto, line-based shell over raw TCP with optional IAC negotiation.

**Protocol:** accept connection, negotiate WILL ECHO + WILL SGA, present login prompt, capture username+password (drop password), accept all, present FakeShell, capture commands.

**Tests:** login + command capture, password not in events, protocol_label="telnet", never-exec static check, accept loop resilience.

---

### Task 3: sensor-redis

**Files:**
- Create: `crates/sensor-redis/Cargo.toml`, `crates/sensor-redis/src/{lib.rs,main.rs,handler.rs,resp.rs}`
- Test: `crates/sensor-redis/tests/integration.rs`

Redis uses the text-based RESP protocol. Parse commands, respond with canned data, capture AUTH credentials and suspicious commands.

**Protocol:** parse `*N\r\n$M\r\n...` RESP arrays. Respond to PING, INFO, CONFIG GET, AUTH, SET, GET, SLAVEOF, EVAL. Log CONFIG SET dir/dbfilename as filesystem write indicators.

**Tests:** PING/PONG round-trip, AUTH credential capture (password not in events), SET/GET response, CONFIG SET logged as indicator, protocol_label="redis", never-exec.

---

### Task 4: sensor-adb

**Files:**
- Create: `crates/sensor-adb/Cargo.toml`, `crates/sensor-adb/src/{lib.rs,main.rs,handler.rs,adb_proto.rs}`
- Test: `crates/sensor-adb/tests/integration.rs`

ADB over TCP uses a header-based binary protocol (24-byte headers: command, arg0, arg1, data_length, data_crc, magic).

**Protocol:** respond to CNXN with device banner, handle OPEN shell: (FakeShell), handle OPEN push: (capture to spool), refuse OPEN pull:.

**Tests:** CNXN handshake, shell command capture, push file capture in spool, pull refused, protocol_label="adb", never-exec, no outbound connection.

---

### Task 5: sensor-http

**Files:**
- Create: `crates/sensor-http/Cargo.toml`, `crates/sensor-http/src/{lib.rs,main.rs,handler.rs}`
- Test: `crates/sensor-http/tests/integration.rs`

HTTP is the highest-volume scanning protocol. Parse request line + headers, log everything, return canned responses.

**Protocol:** parse `METHOD /path HTTP/1.1\r\n` + headers until `\r\n\r\n`. Log method, path, query, User-Agent, body. Return canned HTML for /, robots.txt for /robots.txt, 404 for everything else.

**Tests:** GET / returns 200, GET /nonexistent returns 404, path traversal attempt logged as indicator, POST body captured, protocol_label="http", never-exec, no outbound.

---

### Task 6: sensor-ftp

**Files:**
- Create: `crates/sensor-ftp/Cargo.toml`, `crates/sensor-ftp/src/{lib.rs,main.rs,handler.rs}`
- Test: `crates/sensor-ftp/tests/integration.rs`

FTP for credential capture and malware upload (STOR). RETR and PORT/EPRT are refused (no outbound fetch, same as SSH).

**Protocol:** send 220 banner, handle USER/PASS (credential capture), LIST (canned), STOR (capture to spool via PASV data connection), RETR/PORT/EPRT refused.

**Tests:** login + credential capture, STOR upload in spool, RETR refused, PORT refused, protocol_label="ftp", never-exec, no outbound connection.

---

### Task 7: sensor-smtp

**Files:**
- Create: `crates/sensor-smtp/Cargo.toml`, `crates/sensor-smtp/src/{lib.rs,main.rs,handler.rs}`
- Test: `crates/sensor-smtp/tests/integration.rs`

SMTP for open-relay detection and credential capture. Never actually relays.

**Protocol:** send 220 banner, handle EHLO (advertise AUTH), AUTH PLAIN/LOGIN (credential capture), MAIL FROM/RCPT TO/DATA (capture email body as indicator), QUIT.

**Tests:** EHLO + AUTH credential capture, DATA capture with sender/recipient, never relays (no outbound SMTP), protocol_label="smtp", never-exec.

---

### Task 8: sensor-cred (multi-protocol credential capture)

**Files:**
- Create: `crates/sensor-cred/Cargo.toml`, `crates/sensor-cred/src/{lib.rs,main.rs,vnc.rs,mysql.rs,mssql.rs,postgresql.rs,mongodb.rs}`
- Test: `crates/sensor-cred/tests/integration.rs`

One binary, five protocol handlers, per-port detection. Each protocol implements just enough to reach the auth exchange.

**Protocols:**
- VNC (5900): RFB version + SecurityType(2=VNC Auth) + challenge/response
- MySQL (3306): greeting packet + HandshakeResponse parsing
- MSSQL (1433): TDS PreLogin + Login7 parsing
- PostgreSQL (5432): StartupMessage + AuthenticationMD5Password + PasswordMessage
- MongoDB (27017): OP_MSG isMaster + authenticate command parsing

**Tests:** per-protocol: connect, attempt auth, verify honeypot_login_attempt emitted, password not in events, correct protocol_label. Plus never-exec static check across all source.

---

### Task 9: Deployment (systemd units + install script update + re-vendor)

**Files:**
- Create: `deploy/sensor-telnet.service`, `deploy/sensor-redis.service`, `deploy/sensor-adb.service`, `deploy/sensor-http.service`, `deploy/sensor-ftp.service`, `deploy/sensor-smtp.service`, `deploy/sensor-cred.service`
- Modify: `deploy/install.sh` (add new users, directories, units)
- Modify: `crates/sensor-framework/tests/deploy_test.rs` (add tests for all 7 new units)
- Re-vendor: `cargo vendor`

Each unit follows the SP2 sensor pattern: dedicated user, CAP_NET_BIND_SERVICE for privileged ports (23, 21, 25, 80), NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute=yes, SystemCallFilter placeholder.
