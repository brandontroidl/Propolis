# Propolis

Self-hosted honeypot and threat-intelligence platform. Runs native protocol sensors, scores attackers by corroborated evidence across your WAN IPs, and publishes a firewall blocklist - only after you approve each case.

## Sensors

12 protocol listeners in one deployment, each a dedicated hardened systemd service:

| Sensor | Port | What it captures |
|---|---|---|
| SSH | 22 | Key exchange, login attempts, shell commands, file uploads |
| Telnet | 23 | Login attempts, shell commands |
| HTTP | 80 | Request paths, headers, POST bodies, path traversal attempts |
| FTP | 21 | Login attempts, file uploads (STOR), RETR/PORT refused |
| SMTP | 25 | AUTH credentials, email sender/recipient/subject/body |
| Redis | 6379 | AUTH, CONFIG SET, SLAVEOF, SET/GET, EVAL attempts |
| ADB | 5555 | Shell commands, file push capture, pull refused |
| VNC | 5900 | Authentication attempts (challenge-response) |
| MySQL | 3306 | Handshake username capture |
| MSSQL | 1433 | TDS Login7 username capture |
| PostgreSQL | 5432 | StartupMessage username capture |
| MongoDB | 27017 | SCRAM authentication username capture |

Every sensor is passive-only (no outbound connections, no execution of captured content), unprivileged (no database handle, no secrets), and drops passwords at capture time.

## Scoring

Each attacker IP accumulates a time-decayed score from corroborated evidence:

- **Confirmed-real gate**: an IP is reportable only after a completed TCP handshake proves the source address is genuine. Spoofable UDP and lone SYN traffic never manufactures a report.
- **Cross-sensor breadth**: an IP that hits multiple WAN addresses and multiple sensor protocols weighs more than one that pokes a single port.
- **Multi-category corroboration**: eligibility requires signals from at least two distinct categories (honeypot + IDS, honeypot + WAF, etc.), not just volume on one.
- **6-hour half-life decay**: scores decay continuously, so a quiet attacker drops out of the feed without manual intervention.

## Operator console

A server-rendered web dashboard (axum + minijinja + HTMX + Chart.js) on loopback:

- Six-card stat strip with sparklines (pending review, scored IPs, events/hr, feed entries, top attacker)
- 24-hour events timeline chart
- Protocol distribution and top-attackers bar charts
- Review queue with approve/reject/snooze (HTMX live updates)
- Per-IP detail page with evidence timeline, category breakdown, WAN breadth, and 7-day activity chart
- Feed status with tier counts and TTLs
- Argon2id password auth, HMAC session cookies, CSRF protection, rate-limited login

## Pipeline

```
sensors (passive capture)
  -> NDJSON event logs (append-only, per-sensor)
  -> intake tailer (parses, attributes, appends to hash-chained ledger)
  -> scoring projection (decayed weight, breadth, eligibility gates)
  -> review queue (operator approves / rejects / snoozes)
  -> vendor reports (AbuseIPDB, DShield, OTX) + blocklist feed
```

Evidence is an append-only, hash-chained PostgreSQL ledger. Every score is reproducible by replaying it. The chain is enforced at the database layer with a BEFORE INSERT trigger.

## Deployment

Single node or cluster. Each node runs its sensors and the unified daemon (`propolis`), which composes intake, review, feed, and console as supervised tokio tasks sharing one PgPool. See [INSTALL.md](INSTALL.md) for the full deployment guide.

```
cargo build --release
sudo ./deploy/install.sh
# configure /etc/propolis/*.env
sudo systemctl enable --now propolis sensor-ssh sensor-telnet ...
```

## Architecture

- **Rust** (2024 edition), all dependencies vendored in-tree
- **PostgreSQL** as the single canonical datastore
- **Zero unsafe code** in the project (all unsafe is in vendored dependencies)
- **Hardened systemd units**: `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `CapabilityBoundingSet`, per-sensor OS users, noexec spool mounts
- **No third-party honeypots**: every sensor is self-authored, so the deployment carries one license and no dependency on upstream honeypot projects

## Security

Tested with a 172-test authorized pentest covering protocol fuzzing, brute force, connection flooding, log injection, XSS/SQLi/CSRF, corroboration gate bypass, hash chain integrity, rogue collector injection, score manipulation, and resource exhaustion. See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). Free for personal, home-lab, research, educational, nonprofit, and government use. Commercial use requires a separate license.
