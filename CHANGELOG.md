# Changelog

## Unreleased

### Added

- **IP detail: network profile** - a "Services probed" panel (what each address did to us, grouped
  by sensor, with per-service auth state and activity window) and a "Network profile" panel with
  egress-free operator lookup links (Shodan, GreyNoise, AbuseIPDB, VirusTotal) plus optional offline
  MaxMind GeoLite2 geo/ASN enrichment via `PROPOLIS_GEOIP_DIR` (read locally, never queried over the
  network; degrades to "not configured" when the databases are absent).
- **Telnet XOR de-obfuscation** - the fake shell recovers single-byte-XOR-obfuscated command probes
  (e.g. the LZRD Mirai variant) so it responds in-persona, recording both the raw wire bytes and the
  decoded command; the console shows a "de-obfuscated (xor 0xNN)" badge.
- **Operational self-alerting** - a supervised `ops-monitor` polling intake, sensor heartbeat, DB/
  spool capacity, feed freshness, vendor health, and hash-chain integrity, paging over ntfy
  (opt-in via `PROPOLIS_OPS_ENABLED`).

- **SP8: 7 new honeypot sensors** - telnet, redis, adb, http, ftp, smtp, and credential
  multi-protocol (VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Each runs as a dedicated hardened systemd
  service. 251 tests across the 7 crates.
- **SP7: unified daemon** (`propolis`) - composes intake, review, feed, and console as supervised
  tokio tasks sharing one PgPool. Hardened systemd unit and idempotent install script.
- **SP6: web console** - operator dashboard with review queue, IP detail, feed status, metrics,
  and rate-limited login.
- **SP5: blocklist feed** - two-tier export (aggressive/standard) with anti-deanonymization
  coarsening, fail-closed publisher.
- **SP4: review queue and reporting** - human-approval gate, per-vendor submission gatekeeper,
  AbuseIPDB/DShield/OTX vendor adapters.
- **SP3: event intake** - sensor log tailer with durable cursor, rotation-aware, direct-PG
  aggregation.
- **SP2: sensor framework + SSH** - shared sensor harness (TCP/UDP listener, EventEmitter,
  CaptureHandoff, QuarantineSpool, WanResolver, FakeFs, FakeShell), catch-all port-scan sensor,
  SSH honeypot with vendored crypto. Wire contract frozen.
- **SP1: core scoring layer** - domain model, PostgreSQL schema, append-only hash-chained event
  ledger, time-decayed scoring projection, eligibility/weight/recommendation gates, multi-WAN
  breadth model. 60 tests against real PostgreSQL.
