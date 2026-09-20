# Changelog

## Unreleased

### Added

- **Forward-confirmed reverse DNS** on the IP-detail page (`PROPOLIS_CONSOLE_RDNS_ENABLED`, default
  off - the one outbound lookup in the console's enrichment). A shown hostname is forward-confirmed
  (PTR must resolve back to the IP) and marked verified/unverified; display-only, never a suppression
  signal. On-demand, cached, system resolver via libc (no async DNS dependency).

- **Trusted-org ASN suppression** - an optional `PROPOLIS_FEED_ASN_ALLOWLIST` keeps a trusted
  organization's own infrastructure or a known scanner (by AS number) off every published feed,
  keyed off the offline GeoLite2-ASN database. ASN ownership is not per-IP spoofable, unlike reverse
  DNS. Empty (opt-in) by default. The GeoLite2 reader is now a shared `geoip` crate used by both the
  console and the feed.
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

### Fixed

- **Evidence is no longer lost when a log rotates mid-batch** - the tailer recorded a displaced
  inode's rewind offset as the cursor's live position, which was already past whatever the
  uncommitted batch had read from that inode. A rewind then resumed beyond those lines, so they
  were handed out, never committed, and never re-read - contradicting `rewind_batch`'s contract of
  putting back every read since the last commit.
- **The published feed survives a failed or interrupted swap** - publishing moves the live
  directory aside and then moves staging into its place. A failed second rename left the public
  path absent with no rollback, and a crash between the two renames left it absent until some later
  build happened to succeed. The failure case now rolls the previous build straight back, and
  `recover_interrupted_publish` restores a parked build at daemon startup and at the head of every
  publish.
- **OTX indicators carry their real address family** - the pulse payload declared every indicator
  `IPv4` while reports accept either family, so an IPv6 address was submitted mislabelled against
  an API that validates the value against its declared type.
- **The fleet page no longer reports what it did not measure** - the headline was chosen from the
  combined severity of the reachability and event-age checks, so a fully probed and confirmed fleet
  with one quiet listener read as "evidence path unconfirmed". A failed capture query rendered as
  "no malware captures", and a failed event count as `0 events`. A failed refresh left the previous
  reading on screen with server-computed ages that never moved again; a stalled panel now says how
  long ago its numbers were actually measured.

### Changed

- **A snooze can be finished and a delist undone** - the Snoozed tab had no decision controls and
  nothing re-surfaces a decided entry, so deferring a decision quietly meant never making one; the
  history tabs also rendered rows with an empty CSRF token. The tab now carries Approve, Reject and
  Return to pending. `POST /ip/{ip}/relist` undoes a delist by clearing the latch and re-deriving
  the gates, so an address rejoins the feed on its current merit rather than because it was once
  listed. Also `review unsnooze` and `review snoozed` on the CLI.
