# Changelog

## Unreleased

### Fixed

- **SSH bare connects, banner grabs and bad version strings are now recorded** - the SSH sensor
  emitted `honeypot_connection` only after key exchange, so a Shodan/Censys-style scanner that
  read the banner and left, a client that sent a malformed identification line, and a bare TCP
  probe left no event (the fleet probe reported "socket answered, no line reached intake" for
  tcp/22). The event is now emitted at accept, once per connection, like the other TCP sensors.
  A connection that ends before key exchange completes also emits one `honeypot_session_end`
  (telemetry, unscored) with `end_reason`, `phase`, `duration_ms` and the sanitized
  `client_version` when received. Consequence: such connections now carry the same
  `honeypot_connection` weight (40) as a telnet connect did already. No migration or wire change.

### Added

- **Propolis rotates its own sensor logs, and alerts when rotation fails** - the policy in
  `/etc/logrotate.d/propolis-sensors` relied on the distribution's `logrotate.timer`, which was
  inactive for eleven days on the production box; nothing rotated, one telnet log reached 6.6 GB
  and `/var` reached 80% used. `propolis-logrotate.timer` (hourly, persistent) now runs
  `logrotate` on that policy with its own state file, and `install.sh` and `upgrade.sh` install
  and enable it, so a normal upgrade is the rollout. A `prerotate` free-space guard
  (`/usr/local/sbin/propolis-logrotate-guard`) refuses to `copytruncate` a log that does not fit
  on its filesystem, leaving it untouched while the other logs still rotate. Two ops-alert
  conditions: `sensor-log-oversized` (a configured sensor log over three times the rotation size,
  or the log filesystem over 85% used; clears below twice the size and 80%) and `rotation-stale`
  (the rotation state file not rewritten for three hours). The monitor now evaluates fourteen
  conditions. The hand recovery for a log too large to rotate is in
  [retention](docs/operations/retention.md#a-log-too-large-to-rotate). A collector host that
  installs by hand (split deployment) must also install the guard, units and timer; its page lists
  the commands.
- **Console log view keeps fields and folds repeats** - the `/logs` ring now keeps each event's
  structured fields (`statement`, `elapsed`, `reason`, `sensor`, ...), so "slow statement" and
  "submission held" say what was slow and why it was held. Values are capped at 512 bytes, 32
  fields and a 2 KiB message, and the ring is held to 2 MiB charged from allocated capacity as
  well as to its 1000 entries. The view shows fields inline and expands to all of them, folds
  adjacent identical INFO entries from one target into one row with a count and the values each
  field took, and opens filtered to warnings and errors with a count of the rows it hides; the
  live stream folds by the same rule.
- **Attackers pages through every scored address** - `/ips` stopped silently at 500 rows. It now
  pages 500 at a time with a keyset cursor (`?after=` / `?before=`, the address the page
  continues from) and says "showing 501-1,000 of N", exact to 100,000 rows and a labelled
  estimate past that. The score sort orders by a key equal in order to the live score but
  constant over time, so rows clamped at 100 do not trade places between pages. A note above
  the table states the tier rule and why tier and live score can disagree.
- **Review rows say what the address did** - each pending row has a context line: the sensors
  it reached, its session count, its three most frequent signals, and its first upload or
  download, else its first command after the Mirai shell-entry preamble. Counts come from at
  most 5,000 of the address's events and say so when that is not all of them.
- **Recent activity folds a flooding source** - the dashboard reads the newest 1,000 events and
  folds consecutive events with one source, sensor and signal into one row with a count,
  keeping the newest 20 runs, so one source can no longer fill the panel.
- **IP page folds retries and echo-loader chunks** - consecutive sessions from one sensor that
  ran the same commands fold into one card with a count and the usernames tried, and a run of
  echo-loader chunk writes to one file (`assembled_file` / `chunk_index`) is one row,
  "N echo chunks to FILE", with the lines behind an expander.
- **Per-source command-event budget with flood summaries (ssh, telnet, adb)** - a handful of
  Mirai-family echo loaders, each running the same ~53-command session around the clock and
  several at once, made telnet 97% of all events (~15 a second, 2,555 from one address in ten
  minutes), outran log rotation and put intake 6.6 GB behind. The per-connection cap of 256 could
  not see it. Each of the three sensors now holds a token bucket per source network (/24 or /56)
  charged by `honeypot_command_exec` events only (`CommandEventGate` in
  `sensor_framework::command_flood`, reached through `ConnectionBudget::with_command_gate`):
  burst 200, then 12 a minute, set by `PROPOLIS_<SSH|TELNET|ADB>_COMMAND_EVENT_RATE_PER_MIN` and
  `_BURST` (a positive integer; zero or garbage exits 1; `Rate::per_minute` is new in
  `sensor_framework::rate_limit`). Past it, a command event is not written but counted into one
  `honeypot_command_exec` per network per 60 s window with `command_summary: true`,
  `suppressed_count`, `distinct_commands` (shapes), up to 8 samples, first and last seen,
  `session_count` and, for echo-loader chunks, `assembled_file` and `max_chunk_index`; it is
  written when the window ends and at shutdown. Never summarized: logins, connections, downloads
  and derived URLs, every capture upload, the per-session flood markers, the first command of each
  shape per network per window (`command_shape` takes out `\xNN`/`\NNN` escape runs, hex runs of
  16+ and base64-looking runs of 24+, so the observed 53-line session is 16 shapes whatever its
  marker), and each address's first command event per window (scoring is per address). An
  echo-loader chunk (a command event with `assembled_file`) is never a first: its bytes are in the
  capture. Replies are unchanged: only logging is summarized. The summary scores as one command
  event; the merit path is unaffected (60 s dedup), the volume path reaches its threshold later.
  The observed loop, four parallel sessions every 30 s for ten minutes, drops from 4,240 command
  events to 407 plus 10 summaries. Additive metadata: no migration or wire version change.
- **Intake lag is visible and pages** - each intake poll records how many bytes of its log are
  unread (`LogTailer::backlog_bytes`: the file past the read offset plus any rotated-out file
  still being drained) and the `observed_at` of the last event it appended. `/metrics` publishes
  `propolis_intake_bytes_behind{sensor}` and `propolis_intake_oldest_unread_age_seconds{sensor}`,
  labelled with the `PROPOLIS_SENSOR_LOGS` name; the age is 0 when the poll read every complete
  line and absent when lines wait but nothing has been appended since start, and a process that
  tails nothing publishes neither. A new ops-alert condition, `intake-lagging`, pages when lines
  have waited past max(10 min, 3 intake polls) for 10 minutes, or when the unread bytes rose at
  three consecutive monitor polls that each found complete lines waiting; it clears when the log
  is drained, or after three polls without growth once the wait is back under the threshold, and
  never fires on an idle log. The fleet pane shows `behind: <bytes> / <age>` under LAST EVENT on
  the listener rows of a log over the age threshold. No append-latency histogram: `/metrics` has
  no histogram support. See `docs/operations/health-and-observability.md` and
  `docs/troubleshooting/intake-backlog.md`.
- **Echo-loader uploads are reassembled and captured** - a Mirai/Mozi telnet loader with no
  usable `wget` uploads its downloader as some forty `busybox echo -ne '\xNN...' >> .i` lines,
  runs `chmod 777 .i` and `./.i a b c d port`. Each line was logged but the file was never
  captured, and the loader retried the whole session every few minutes. The shared shell (SSH,
  telnet, ADB) now notes every file built from `echo`/`printf` output, chunk by chunk, and
  captures it as one `honeypot_malware_upload` with `capture_reason` `echo_loader`,
  `chunk_count` and `destination`, once the line that makes it executable or runs it has run, or
  at the session's end for an assembly of two or more chunks never run. It goes through the
  per-session stdin capture set (`StdinCaptures::record_assembled`; sensors pass it with
  `FakeShell::with_captures` and report the ending with `StdinCaptures::end_session`), so one body
  is one sample per session and the memory budget applies; a file is recognized by content, so
  the loader's `cp /bin/ls .j && cat .i>.j && rm .i && cp .j .i` fallback is the same sample.
  Each chunk's command event carries `assembled_file` and `chunk_index`. Running an assembled ELF
  that holds a `GET <path> HTTP/1.x` request line with four octets and a port as arguments
  executes nothing, answers as a downloader that cannot reach its server (no output, status 1),
  and emits the stage-2 URL as a `honeypot_file_download` with `derived_from` `echo_loader_args`
  and `derived_sha256`, which the review fetcher vets like any URL; the sensor makes no
  connection. Additive metadata: no migration or wire version change.
- **`propolis-watch`, a read-only live view of the sensors** - new crate `watch`, binary
  `propolis-watch`. It streams every event log named in `PROPOLIS_SENSOR_LOGS` as JSON Lines on
  stdout: a `start` record with the resolved sources, one `event` record per log line (the
  sensor's JSON embedded byte for byte, or `raw` text when a line is not a JSON object), a
  `dropped` record in place of each line over the 1 MiB cap, and a `heartbeat` every 10 s giving
  each log's status (`following`, `missing` or `unreadable`), size and lines seen, so a quiet
  node is distinguishable from a dead stream and a mistyped log path shows on the first
  heartbeat. It starts at the end of each log by default (`--since-start` replays the current
  file), follows `copytruncate` rotation, filters with `--sensor`, `--signal` and
  `--source-ip`, and with `--journal` adds the `sensor-*` and `propolis` units' journal from a
  `journalctl` child with a fixed argument vector. It writes no file, opens no socket and needs
  no database or credential; a static test holds its source to that. Arguments also come from
  `SSH_ORIGINAL_COMMAND`, split on whitespace only through the same allowlist, so it can run as
  an SSH forced command: `deploy/provision.sh` now creates a `propolis-watch` login account
  (home `/var/lib/propolis-watch`, shell `/bin/sh`, password field `*`, read-only membership in
  every sensor group, no journal access unless added by hand), with its home, `.ssh` and
  `authorized_keys` owned by root so the account cannot add a key to itself; `install.sh` and
  `upgrade.sh` install the binary; and `deploy/watch-authorized-keys.example` shows the
  `restrict`ed forced-command key line, `command="/usr/local/bin/propolis-watch"`. When
  `PROPOLIS_SENSOR_LOGS` is not in its environment the watcher reads that one key from
  `/etc/propolis/watch.env`, which the new `deploy/watch-env.sh` derives from `propolis.env` on
  every provision (so every install and upgrade), copying only that line, root:propolis-watch
  0640, atomically; the start record and heartbeat say which source the list came from. No key
  is generated or installed. See `docs/operations/live-watch.md`.
- **`log-tailer` gains a cursorless mode and owns the sensor-log list parser** -
  `LogTailer::without_cursor` reads and follows rotation like the cursor-backed tailer but has
  no cursor to load or save, and `read_batch_entries` reports each over-length discard in place.
  `parse_sensor_logs` replaces the three copies of the `name:path` grammar in `propolis`,
  `intake` and `shipper`; their behavior and error messages are unchanged.
- **Every event records the port it arrived on** - the sensor framework stamps
  `metadata.local_port` (an integer: the accepted TCP socket's local port, or the bound UDP
  socket's port) on every event every sensor emits, uploads and the DNS and TFTP rate-limit
  summaries included, without any sensor building the key. The transport stays in `protocol`.
  Additive metadata: no migration, no wire or schema version change, and the hash chain is
  unaffected. Each sensor crate gains a `tests/arrival.rs` that checks it against its real
  listeners, and a coverage test fails for a sensor crate without one.
- **`sensor-tftp` rate limits its request socket and refuses reflector and unroutable
  sources** - the byte budget already kept every reply no larger than what the peer sent, but a
  spoofed request flood still drew one ERROR per request at line rate toward the forged source,
  and one event per request in the log. Every datagram on the request socket, malformed ones
  included, now takes a token from its source network's bucket (IPv4 /24, IPv6 /56: 5 per
  second, burst 10) and a global one (1000 per second, burst 2000), the same `ReplyRateLimiter`
  and defaults as `sensor-dns`, set by `PROPOLIS_TFTP_REPLY_RATE_PER_SOURCE`,
  `PROPOLIS_TFTP_REPLY_BURST_PER_SOURCE`, `PROPOLIS_TFTP_REPLY_RATE_GLOBAL` and
  `PROPOLIS_TFTP_REPLY_BURST_GLOBAL` (positive integers; zero or garbage refuses to start). A
  datagram over the limit gets no reply and no event of its own; each source network gets one
  `query_status` `rate_limited` summary event per 10 s, the same event `sensor-dns` writes, with
  samples of `"<rrq|wrq> <filename>"` or `malformed`, and shutdown writes the summaries still
  accumulating. The packets of a running transfer arrive on its own socket and are not charged.
  A request from source port 0, 7, 13, 17, 19 or 37, or from an unspecified, broadcast or
  multicast address, now gets no transfer socket and no packet at all, not even the first ERROR
  or ACK 0; its probe event carries `suppress_reason` (`reflective_source_port` or
  `unroutable_source`). The transfer's send re-checks the same rule. The check
  (`check_reply_source`) and the summary event (`rate_limited_event`) moved into
  `sensor-framework`, and `sensor-dns` now uses the same implementations; its behavior is
  unchanged. `start_test_server` and `start_test_server_with_capture_budget` (formerly
  `start_test_server_with_handoff`) take the rate configuration and return a `TftpServer`.
- **DNS honeypot sensor (default off)** - new crate and binary `sensor-dns`. `PROPOLIS_DNS_BIND`
  serves DNS over UDP and TCP on the same address (conventionally 53); if either transport cannot
  bind, the sensor exits 1 with nothing left listening. `PROPOLIS_DNS_TLS_BIND` adds DNS over TLS
  (conventionally 853) with `PROPOLIS_DNS_TLS_CERT` and `PROPOLIS_DNS_TLS_KEY`, under the same
  fail-closed rules as the other TLS sensors. It serves no records: every query that parses gets
  REFUSED, the query's header rewritten (ID kept, RD and CD copied) and its first question echoed,
  nothing appended, so a UDP reply is never larger than its query; the crate's one UDP `send_to`
  re-checks that with a byte budget and refuses unspecified, broadcast and multicast sources and
  the source ports 0, 7, 13, 17, 19 and 37 (recorded as `suppressed`). A message with QR set, a
  non-zero opcode (NOTIFY, UPDATE), QDCOUNT other than 1, a compression pointer or bad label in
  the question, a name over 255 bytes, a truncated question, or an answer or authority record
  (except exactly one SOA authority record on an IXFR over TCP; an unparseable one is
  `malformed_authority`) is recorded as `rejected` and gets no reply; on TCP and DoT it also
  closes the connection, as does a length prefix under 12 or over 4096, a message that would pass
  `PROPOLIS_DNS_MAX_CAPTURED_BYTES` (`byte_cap`; default 262272, 64 maximum-size queries with
  their 2-byte prefixes), and a body cut short or not arriving within the read timeout
  (`truncated_body`, `body_timeout`), each recorded with its `declared_len`. A connection carries
  at most 64 queries, and a reply must be written within the read timeout. UDP replies are rate
  limited per source network (IPv4 /24, IPv6 /56: 5 per second, burst 10) and in total (1000 per
  second, burst 2000), set by `PROPOLIS_DNS_REPLY_RATE_PER_SOURCE`,
  `PROPOLIS_DNS_REPLY_BURST_PER_SOURCE`, `PROPOLIS_DNS_REPLY_RATE_GLOBAL` and
  `PROPOLIS_DNS_REPLY_BURST_GLOBAL` (positive integers; zero refuses to start). A datagram over
  the limit gets no reply and no event of its own; each source network gets one
  `query_status` `rate_limited` summary event per 10 s with counts, bytes, first and last seen
  and up to 8 sample questions, so a flood cannot become a log flood. The limiter
  (`ReplyRateLimiter`, `FloodLedger`) lives in `sensor-framework` with fixed-size tables. A UDP
  query is a `honeypot_connection` over `udp`; a TCP or DoT connection is one
  `honeypot_connection` plus one `honeypot_command_exec` per message, with `command`
  `"<QTYPE> <qname>"`, or `malformed` for a message whose question did not parse. Metadata
  records the header, the question (qname in escaped presentation form, sanitized), the EDNS
  buffer size, DO bit and option codes (never option data), and `probe_signals`:
  `amplification_probe`, `open_resolver_probe` (RD with class IN or ANY), `zone_transfer_probe`,
  `chaos_fingerprint_probe`. DoT events carry `"tls": true`. A bind failure names the transport
  (`udp`, `tcp`, `dot`) and the address. The unit
  `deploy/sensor-dns.service` grants `CAP_NET_BIND_SERVICE` and
  `ReadOnlyPaths=-/etc/propolis/tls`; `provision.sh` creates `propolis-dns` and its log
  directory, `provision-tls.sh` mints a `dns` pair, and the fleet inventory derives
  `dns/udp/<port>` and `dns/tcp/<port>` from the one bind plus `dns/tcp/<port>` from the TLS
  bind. Known fingerprint costs: no OPT record is returned even when the query carried one, and
  a denied zone transfer gets REFUSED, which some real servers answer with NOTAUTH.
- **`sensor-cred` PostgreSQL answers a GSSENCRequest with `N`** - libpq sends a GSSENCRequest
  (code 80877104) before anything else when built with GSSAPI, and a real server without GSS
  encryption answers one `N` byte and keeps reading. The sensor did not handle it, so such a client
  never reached the StartupMessage and its credentials were not captured. It now answers `N`, with
  or without a TLS pair, and continues with the client's SSLRequest (answered `S` over TLS when
  configured, tagged `"tls": true`) or plain StartupMessage. As in PostgreSQL, each negotiation
  request is honoured once per connection and none inside TLS, so at most two precede the
  StartupMessage and a repeated one closes the connection. A repeated SSLRequest on a plaintext
  connection used to be read as a malformed StartupMessage; it now closes the connection too.
- **In-band TLS on `sensor-cred` (default off)** - `PROPOLIS_CRED_TLS_CERT` and
  `PROPOLIS_CRED_TLS_KEY` (the pair `provision-tls.sh` mints, key mode `0600`) enable TLS on the
  existing PostgreSQL, MySQL, MSSQL and MongoDB ports. There is no TLS bind and no new port, so
  the fleet inventory is unchanged; VNC is unchanged. PostgreSQL answers an SSLRequest `S` (until
  now always `N`) and continues over TLS; a second SSLRequest inside TLS closes the connection and
  plaintext sent after the `S` fails the handshake. MySQL advertises `CLIENT_SSL` and switches to
  TLS on a client SSLRequest, answering the HandshakeResponse with OK at sequence id 3. MSSQL runs
  the handshake inside TDS PRELOGIN packets, then Login7 and LOGINACK as raw TLS records, with TLS
  1.3 session tickets off for MSSQL only: a client offering `ENCRYPT_ON` or `ENCRYPT_REQ` is
  answered `ENCRYPT_ON` and gets TLS, a client offering `ENCRYPT_OFF` gets the pre-TLS PRELOGIN
  response byte for byte and a plaintext session (a real server would answer `ENCRYPT_REQ`; the
  honeypot keeps the credentials of scanners that cannot do TLS; for the same reason a client
  that asked for encryption but then sends a plaintext Login7 is captured in plaintext), and
  `ENCRYPT_NOT_SUP` or no option gets `ENCRYPT_NOT_SUP` and plaintext. MongoDB peeks the first two
  bytes and serves `0x16 0x03` (a TLS record header) over TLS on the plaintext port, so a
  plaintext first message whose length's low byte is `0x16` is no longer mistaken for TLS; its
  connection event is written before the handshake, so a failed handshake is still recorded.
  Plaintext clients keep working on every port. Events from a TLS session carry `"tls": true`
  (for PostgreSQL, MySQL and MSSQL the pre-negotiation connection event stays untagged). The
  startup line names only the TLS-capable protocols that are bound. Fail-closed: when either variable is set (a
  blank value counts as unset), exactly one set, a non-UTF-8 value, or an unusable pair makes the
  sensor exit 1 before binding anything. A bind failure on one protocol is still logged and skipped. The unit gains
  `ReadOnlyPaths=-/etc/propolis/tls`. The MSSQL TDS-TLS adapter is validated against a rustls
  client and the MS-TDS text only; the owner smoke tests against real drivers are listed in
  `docs/operations/networking-tls.md`.
- **FTPS and AUTH TLS on `sensor-ftp` (default off)** - `PROPOLIS_FTP_TLS_CERT` and
  `PROPOLIS_FTP_TLS_KEY` (the pair `provision-tls.sh` mints, key mode `0600`) enable AUTH TLS on
  the plain listener, which until now answered `500`. One optional listener in the same process,
  writing the same event log and sharing the capture hand-off and memory budget, exists only when
  its bind is set (no compiled default): `PROPOLIS_FTP_TLS_BIND` (deploy convention
  `0.0.0.0:990`, implicit TLS, requires the pair). `AUTH TLS`, `TLS-C`, `SSL` and `TLS-P` answer
  `234` and upgrade, other AUTH types get `504`, AUTH inside TLS gets `503`. Plaintext pipelined
  behind AUTH TLS is refused before any `234` with one `honeypot_command_exec` event
  (`starttls_refused: pipelined_plaintext`, the byte count, never the bytes), a
  `504 Pipelined commands after AUTH TLS refused.` and a close. The upgrade resets the session as
  REIN would (user, login, PBSZ, PROT, passive listener) and keeps the captured-byte count.
  PBSZ is accepted inside TLS only (`200 PBSZ set to 0.`), PROT takes `C` and `P` after PBSZ
  (`S` and `E` get `536`), FEAT lists AUTH, PBSZ and PROT only when TLS is configured, and with no
  pair set AUTH, PBSZ and PROT still answer `500`. After `PROT P` the passive data socket is
  wrapped in TLS once the data peer passed the source-IP check (handshake bounded by the read
  timeout, a failure gets `425`), STOR over it is spooled exactly like plaintext, and a data close
  without `close_notify` counts as end of file. Connection, login and upload events from a session
  whose control channel is TLS carry `"tls": true`; plain events are unchanged. QUIT now shuts the
  stream down after `221`. Fail-closed: exactly one of cert and key, a TLS bind without both, an
  invalid bind, or an unusable pair makes the sensor exit 1 before binding anything, and a bind
  failure on any listener stops the others and exits 1. Cert and key without a TLS bind enable
  AUTH TLS and open no 990 listener. `fleet-listeners.sh` derives an `ftp` tcp listener from
  `PROPOLIS_FTP_TLS_BIND`, and the unit gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **SMTPS, SMTP submission and STARTTLS on `sensor-smtp` (default off)** - `PROPOLIS_SMTP_TLS_CERT`
  and `PROPOLIS_SMTP_TLS_KEY` (the pair `provision-tls.sh` mints, key mode `0600`) turn STARTTLS
  from the old `454` reply into a real upgrade on the plain listeners. Two optional listeners in
  the same process, writing the same event log, exist only when their bind is set (no compiled
  default): `PROPOLIS_SMTP_SUBMISSION_BIND` (deploy convention `0.0.0.0:587`, plain with
  STARTTLS) and `PROPOLIS_SMTP_TLS_BIND` (`0.0.0.0:465`, implicit TLS, requires the pair).
  STARTTLS replies `220 2.0.0 Ready to start TLS`, refuses plaintext pipelined behind it with
  one `honeypot_command_exec` event (`starttls_refused: pipelined_plaintext`, the byte count,
  never the bytes) and a `554` before any handshake, forces a fresh EHLO and resets MAIL, RCPT
  and BDAT state after the upgrade, answers a second STARTTLS inside TLS with `503`, and answers
  STARTTLS with parameters with `501` (only when TLS is configured). EHLO inside TLS omits
  STARTTLS. Connection, login and data events from a TLS session carry `"tls": true`; plain
  events are unchanged, and with no TLS variable set the sensor is byte-identical (STARTTLS
  advertised, `454`). Fail-closed: exactly one of cert and key, a TLS bind without both, an
  invalid bind, or an unusable pair makes the sensor exit 1 before binding anything, and a bind
  failure on any listener stops the others and exits 1. Cert and key without a TLS bind enable
  STARTTLS and open no 465 listener. `fleet-listeners.sh` derives an `smtp` tcp listener from
  each of the two new bind variables, and the unit gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **MQTTS on `sensor-mqtt` (default off)** - a second, implicit-TLS listener in the same process,
  serving the same persona into the same event log, enabled by `PROPOLIS_MQTT_TLS_BIND` (no
  compiled default; the deploy convention is `0.0.0.0:8883`) together with
  `PROPOLIS_MQTT_TLS_CERT` and `PROPOLIS_MQTT_TLS_KEY` (the pair `provision-tls.sh` mints, key
  mode `0600`). MQTT 3.1, 3.1.1 and 5.0 work over it, there is no STARTTLS, and binary-PUBLISH
  spooling, the capture memory budget and the shutdown drain are shared with the plain listener.
  Events from a TLS session (connection, login, command, malformed first packet, malware upload,
  session end) carry `"tls": true`; plain events are unchanged. A failed or stalled handshake is
  dropped with no event and cut at the read timeout. Fail-closed: exactly one of cert and key, a
  TLS bind without both, an invalid bind, or an unusable pair makes the sensor exit 1 before
  binding anything. Cert and key without a TLS bind load and validate the pair, start no TLS
  listener and log one warning, so a TLS listener never opens implicitly. Every session now ends
  with a stream shutdown (`close_notify` on TLS, a FIN on a plain connection). `fleet-listeners.sh`
  derives an `mqtt` tcp listener from `PROPOLIS_MQTT_TLS_BIND`, and the unit gains
  `ReadOnlyPaths=-/etc/propolis/tls`.
- **Redis over TLS on `sensor-redis` (default off)** - a second, implicit-TLS (`rediss://`)
  listener in the same process, serving the same persona into the same event log, enabled by
  `PROPOLIS_REDIS_TLS_BIND` (no compiled default; the deploy convention is `0.0.0.0:6380`)
  together with `PROPOLIS_REDIS_TLS_CERT` and `PROPOLIS_REDIS_TLS_KEY` (the pair
  `provision-tls.sh` mints, key mode `0600`). There is no STARTTLS. Events from a TLS session
  (connection, login, command) carry `"tls": true`; plain events are unchanged, and the AUTH
  password is never captured. A failed or stalled handshake is dropped with no event and cut at
  the read timeout. Fail-closed: exactly one of cert and key, a TLS bind without both, an invalid
  bind, or an unusable pair makes the sensor exit 1 before binding anything. Cert and key without
  a TLS bind load and validate the pair, start no TLS listener and log one warning, so a TLS
  listener never opens implicitly. `fleet-listeners.sh` derives a `redis` tcp listener from
  `PROPOLIS_REDIS_TLS_BIND`, and the unit gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **HTTPS on `sensor-http` (default off)** - a second, implicit-TLS listener in the same process,
  serving the same nginx persona into the same event log, enabled by `PROPOLIS_HTTP_TLS_BIND`
  (no compiled default; the deploy convention is `0.0.0.0:443`) together with
  `PROPOLIS_HTTP_TLS_CERT` and `PROPOLIS_HTTP_TLS_KEY` (the pair `provision-tls.sh` mints, key
  mode `0600`). Events from a TLS session carry `"tls": true`; plain events are unchanged. A
  failed or stalled handshake is dropped with no event and cut at the read timeout. Fail-closed:
  exactly one of cert and key, a TLS bind without both, an invalid bind, or an unusable pair makes
  the sensor exit 1 before binding anything. Cert and key without a TLS bind load and validate the
  pair, start no TLS listener and log one warning, so a TLS listener never opens implicitly.
  `fleet-listeners.sh` derives an `http` tcp listener from `PROPOLIS_HTTP_TLS_BIND`, and the unit
  gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **Sensor TLS foundation** - `sensor-framework` gains
  a `tls` module: a fail-closed loader for a per-sensor certificate and key (a missing, oversized,
  non-regular, malformed or mismatched file, or a key readable by group or other, is an error and
  never a fallback), an implicit-TLS listener that reuses the plain TCP listener's connection
  bounds and cuts the handshake at the read timeout, and a plaintext-to-TLS stream type for
  STARTTLS-style upgrades. No client certificates are requested. `provision-certs` gains
  `--sensor-tls <out-dir> <sensor>...`, which mints one self-signed pair per sensor and keeps a
  pair that already exists. New `deploy/provision-tls.sh`, run by `install.sh` and `upgrade.sh`
  after the binaries are installed, mints the pairs into `/etc/propolis/tls`
  (`0711` root-owned, created by `provision.sh`; keys `0600`, certificates `0644`, both owned by
  the sensor's user); a real certificate placed at those paths survives re-runs. A minted pair is
  used only once its sensor's TLS variables are set (the six entries above).
- **MQTT binary PUBLISH payloads are now spooled** - `sensor-mqtt` still records every PUBLISH as
  metadata, and now also hands a payload that passes the shared `looks_binary` gate to the framework
  capture hand-off, emitting a `honeypot_malware_upload` event (`capture_reason`
  `binary_publish_payload`). Text payloads stay metadata-only. New `PROPOLIS_MQTT_SPOOL_DIR`
  (default `/var/spool/propolis/mqtt`), `PROPOLIS_MQTT_OUTBOX_DIR` and
  `PROPOLIS_MQTT_CAPTURE_MEMORY_BYTES` variables; the unit grants the spool in `ReadWritePaths`,
  `provision.sh` creates it, and the review spool walk (`BODY_SPOOLERS`) now includes `mqtt`.
  Operators with an existing install should back `/var/spool/propolis/mqtt` with a
  noexec,nosuid,nodev mount like the other spools.
- **MQTT 5.0 on `sensor-mqtt`, and a session summary** - the sensor first declined a 5.0 CONNECT
  with CONNACK reason `0x84`, so a strict 5.0 scanner stopped at CONNECT and none of its
  SUBSCRIBE or PUBLISH recon was captured. It now speaks 5.0 in full: CONNECT (with its will
  properties), PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PUBREL and AUTH are parsed and answered in 5.0 wire
  form, and 3.1 and 3.1.1 behave as before. A properties block is parsed strictly inside its
  declared length (at most 64 properties, no panic on any input), so a malformed property sets
  `properties_parse_error` but can neither corrupt the packet boundary nor fail the packet. The
  recon-relevant properties are logged (session expiry, receive and packet-size maxima, topic alias
  and its maximum, request-response-information, the authentication-method name, and the first 16
  user properties with a full count); Authentication-Data is a credential and, like the password,
  is never stored or logged. Also new: a connection whose first packet is malformed or not a
  CONNECT now emits a second `honeypot_connection` event (`malformed`, a `reason`, a bounded hex
  snippet) instead of closing silently; every connection ends with a `honeypot_session_end`
  summary (packets, publishes, subscribes, bytes, duration, client id); and the idle wait after
  CONNECT is bounded by 1.5 times the client keepalive.
- **MQTT honeypot sensor (`sensor-mqtt`, default-off)** - a recon trap for TCP/1883 that records
  MQTT CONNECT credentials (never the password), SUBSCRIBE topics and PUBLISH topic and payload
  metadata (length, a bounded preview, a SHA-256), and answers just enough of the protocol that a
  client carries on. It never delivers, retains or forwards a message, opens no outbound
  connection and executes nothing; a binary PUBLISH payload is quarantined, never run (see the
  entries above). The parser caps a packet at 256 KiB of declared length, a connection at 1024
  packets and the configured byte budget, and refuses a malformed or oversize packet by closing
  the connection. The sensor is off until `PROPOLIS_MQTT_BIND` is set, and its unit grants no
  `CAP_NET_BIND_SERVICE` (1883 is unprivileged).
- **Fake shell: a real grammar and faithful command modeling** - the shell the SSH, Telnet and ADB
  sensors present now lexes, parses and evaluates a shell-command subset (quotes, expansions,
  arithmetic, real pipelines, `&&`/`||`, subshells and `if`/`for`/`while`) instead of matching whole
  lines, dispatches every command through a shared registry, and bounds each connection with a shared
  resource budget (overlay bytes and nodes, command and download events, wire egress, per-line work
  and a recursion depth cap). The filesystem is a node model over a persona snapshot with symlinks,
  devices, modes and mount flags. The commands the highest-volume observed attacker chains use now
  answer faithfully: reading the ELF header of `/bin/ls` (`cat | head`, `hexdump -n 52`, `dd bs=52`)
  and of `/proc/self/exe` (resolved to the executable of the reading process, so the `|| cat`
  fallback is suppressed), the Telnet `.fxcat` writable-directory sweep, and the real
  BusyBox v1.30.1 multi-call banner and its 263-applet set. Shell identity (bash login versus a
  `bash -c` exec versus nested `su`/`sh`/dash levels versus Android mksh) drives every prompt, error
  prefix and `$0`. A per-line internal trace records why the shell answered as it did and can never
  reach the wire, and the never-exec and no-fetch guarantees hold by construction: the emulator has
  no process, evaluation or network facility and the synthetic binary bytes are generated, never a
  host file read or run. Attacker-facing behavior is checked by a byte-for-byte session-replay corpus.
- **Protocol-correct shell transports** - SSH now tracks up to ten independent channels, obeys each
  peer's receive window and maximum packet size, replenishes its own receive window, separates
  non-PTY stderr, and completes exec channels with exit status, EOF and close. ADB obeys negotiated
  maxdata and waits for an OKAY before each subsequent WRTE, including large one-shot replies.
  Telnet routes banner, prompts, echo and command output through one NVT encoder that applies ONLCR,
  the session XOR codec and IAC escaping in wire order. Writes on all three transports are bounded
  by the connection idle timeout.
- **Split deployment: collectors ship to a gateway over mTLS** - a honeypot collector no longer
  needs database access. `shipper` tails each sensor's log through the shared `log-tailer` crate and
  ships length-prefixed batches to a `gateway` over mutually authenticated TLS. The gateway verifies
  a per-collector sequence number and rolling hash against durable state, spools accepted records as
  byte-exact sensor NDJSON for intake, and acknowledges; the shipper advances its cursor only on
  that acknowledgement. Frame, acknowledgement and mTLS config live in a shared `collector-wire`
  crate so the two ends cannot drift.
- **Certificate minting for a split deployment** - `provision-certs` mints the CA, gateway and
  collector certificates the mTLS transport needs. Bootstrap only: addition, rotation and revocation
  are not implemented.
- **Operator runbook for the split deployment** - `docs/operations/split-deployment.md` covers
  creating the certificates, setting up both hosts by hand (no script creates the gateway's or the
  shipper's users, directories or units), checking the path end to end, and upgrading, rotating,
  rebuilding, backing up and troubleshooting it, with the limits the split still has. Its commands
  and claims were checked against the code by independent reviewers, and the chain behaviour it
  describes (the reset procedure, a one-sided reset, a foreign CA, a blank log line) was run on
  loopback with the release binaries.
- **Malware fetcher** - retrieves the payload behind a URL a captured dropper points at, under
  deliberately paranoid egress rules: scheme allowlist, URL vetting, IP pinning, an egress deny-set
  that canonicalizes mapped/NAT64/6to4 forms, per-hop redirect re-vetting performed by hand rather
  than by the HTTP client, a byte cap on the streamed response, and peer-pinned TFTP for the RRQ
  case. Embedded URLs are extracted from dropper scripts, including Script-Encoded (`.vbe`) ones.
  Attempts and their outcomes are recorded in `fetch_attempt` and shown on the IP detail page.
- **Listener reachability pane** - the console names every declared listener and what has actually
  been proven about it, from a sweep that dials each one from the control plane. The sweep's own
  connections are filtered at intake, so answering the reachability question cannot score the node
  into its own blocklist. Off by default (`PROPOLIS_FLEET_PROBE_ENABLED`), and it refuses to start
  without the source addresses that filter needs.
- **Deploy identity** - `deploy-stamp.sh` records what a deploy actually left on disk, and the
  console compares four identities usually collapsed into one: what this process runs, what the
  deploy installed, what was checked out, and what `main` held at the last fetch. Idempotent
  provisioning moved into `provision.sh`.
- **Per-occurrence and per-capture identity** - sensors mint an `occurrence_id` at the emit
  chokepoint and a `capture_id` at the spool chokepoint, and write a durable per-capture outbox
  manifest, so a captured sample can be tied back to the event that produced it. Both fields are
  additive on the sensor wire.
- **Volume-based blocklisting** - a high-volume connection flood is recommended for the blocklist on
  volume alone, since same-signal dedup otherwise collapses a flood into a single scored event. It
  counts only completed-TCP events, never spoofable datagrams, and volume-listed addresses publish
  into the retention windows rather than the tiered files.
- **Per-subsystem liveness** - the supervisor publishes each subsystem's state, `/ready` answers 503
  once one has given up, and the ops-monitor pages on it.
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

- **A host survey gets the answers an Ubuntu 22.04 server gives (T9)** - a fingerprinting
  script run twice against the fleet on 2026-10-07 (45 commands: `nproc`, `/proc/cpuinfo`,
  `top -bn1 | grep '^%Cpu'`, `free | grep -i '^Mem:' | awk ...`, `cut`, `ip addr`, `which apt`,
  `time dd ...`) got empty or `command not found` answers no real host gives. Every new format
  below was recorded the same day from a systemd-booted `ubuntu:22.04` reference (grep 3.7,
  coreutils 8.32, mawk 1.3.4 20200120); a format that could not be recorded is marked
  `[unverified]` where it is written. `grep` matches basic, extended and fixed patterns (it
  printed nothing for anything but `-F`) through a new linear-time POSIX matcher
  (`shell/regex.rs`) with GNU's options, context lines and compile errors; `cut`, `tee` and
  `awk`/`mawk` (an interpreter for the language, whose `system()` and command pipes run through
  the fake shell itself) are new; `od -c` is modeled. `tee` and `mawk` join the recorded binary
  table, and `/usr/bin/awk` is the alternatives link to `mawk` as on the reference. bash's
  `time [-p]` keyword reports in bash 5.1's format on the shell's stderr from the time the timed
  commands claim (`sleep`'s interval, `dd`'s own elapsed figure, a fixed per-process cost), so
  `time dd` agrees with dd's summary; `history` lists the interactive shell's lines and nothing
  under `bash -c`. `dd if=/dev/zero of=FILE` writes its zeros as an O(1) fill (the survey's 10 MB
  probe answered `File too large`), and dd's byte-count sizes keep a decimal below 10 only
  (`(10 MB, 10 MiB)`, it printed `(10.5 MB, 10.0 MiB)`). The host itself is one model the
  commands agree on: the process table holds a 22.04 server's kernel threads and services
  (journald, resolved, networkd, cron, dbus, rsyslogd, logind, the getty pair, the session's
  `systemd --user`) with their real owners, so `ps aux`, `top -bn1`, `pgrep`, `/proc/PID` and
  `/proc/loadavg` (now present, as is a ticking `/proc/uptime`) count the same rows; `ss` lists
  resolved's stub on 127.0.0.53 beside sshd in iproute2 5.15's recorded layout, and
  `/proc/net/udp` the same socket. `/proc/cpuinfo` lists every field (the `model name` grep was
  empty), `/etc/shadow`, `/etc/gshadow`, `/etc/group` and the installer's netplan file exist
  (root's hash is a random yescrypt-shaped string that hashes no password), root's dotfiles
  are the stock ones, the root disk is `/dev/root` on the Xen `xvda` the CPU implies, `/tmp` is
  sticky and `/proc`/`/sys` read-only, and `/lib32`/`/libx32` join the usrmerge links. An SSH
  session's environment carries `SSH_CLIENT`, `SSH_CONNECTION`, `LANG`, `SHLVL`, the `XDG_*`
  set and, interactively, `SSH_TTY`, `TERM` and `LS_COLORS`, in bash's own hash order (`env` printed
  four variables); `MAIL` is set over telnet only, because a jammy SSH login has none (recorded).
  `ls -a` lists `.` and `..` and the short listing is one name a line off a terminal, a file
  the session writes is dated now rather than 2024, and `uname -a` and `/proc/version` carry the
  kernel's build date [unverified]. `systemctl`, `crontab`, `apt`/`apt-get`/`dpkg`, `ssh`,
  `lspci`, `lshw`, `who` and `w` exist (`which apt` and `ssh -V` answered nothing):
  `systemctl list-units --state=running` lists the services whose processes `ps` shows, `status`
  reads their PID and memory from the same rows, and enabling is the `.wants` symlink the
  filesystem holds, so a dropped `kworker.service` is linked with systemd's own `Created
  symlink` message and never started. `crontab` keeps its table in cron's spool with Debian's
  header and errors. One package table recorded from a 22.04 server install answers `dpkg -l`,
  `dpkg -s` and `apt list`, with `openssh-*` at the banner's version; `apt install` of anything
  not installed cannot be located and nothing is fetched. `ping` prints iputils' report of
  replies it never sent (it printed BusyBox's layout on Ubuntu) and fails names the box cannot
  resolve as `getent` does; `ssh` times out on connect. A file the session writes now runs as
  itself whatever its name (`/tmp/w` used to run `w`), and a copy of a modeled binary runs as
  that binary; `ls -d` lists a directory operand itself. At an interactive terminal (SSH with a
  pty, telnet, ADB) `read x` and `head -n 1` answer when Enter hands them their line, where they
  waited for Ctrl-D: each Enter reruns the waiting line on the input so far (at most 64 times, on
  at most 64 KiB) and keeps the run only if nothing still wants more, so `cat > f` still reads to
  Ctrl-D and what is typed after a finished `read` is the next command. An SSH shell without a pty
  reads a pipe as bash does: a bare `sh` reads the rest of the input as its script (it opened a
  nested interactive level), there is no prompt, history or terminal variable, and the client's
  EOF ends the shell with the last command's status (the session used to stay open).
- **Console labels** - protocols read `TCP` / `UDP` instead of the enum names `Tcp` / `Udp`; the
  feed status tab's build and valid-until times use the console's `YYYY-MM-DD HH:MM UTC` form
  instead of raw RFC 3339; credential-sensor listeners read as their service (`VNC`, `MySQL`,
  ...) instead of `Cred-vnc`; IP-page sessions ending in the same minute keep their real order.
- **An intake that fell behind no longer slowed down because it was behind** - the dedup read
  every scored append makes inside the global append lock (the newest prior observation of one
  source and signal) had no index of its own, so the planner walked `event_observed_at_idx` down
  from the newest row until it met the source: one row per event newer than that source's last
  sighting. A lagging intake appends old `observed_at` values, so the walk grew with the lag and
  the lag with the walk. A telnet stream from a bot loop ran at about one event a second for days
  and, holding the append lock that long, held up every other sensor. Migration `0013` adds
  `event_dedup_idx (source_ip, signal_type, observed_at)`, and the read passes the address through
  a scalar subquery so the planner costs a hot source like any other: with the index alone it
  still chose the walk for the two hottest sources of a test ledger. On a 7.5M-row ledger with
  telnet 11 days behind the read went from 840 to 1060 ms to about 0.13 ms for those sources,
  and the lagged append of a 100k-row source from 1.7 s to 0.69 s, its cost when caught up; the
  rest is the per-event history aggregates, which are still to be made incremental. The index is
  built inside the migration transaction at startup, before intake runs: 12 to 20 s for that
  ledger held in RAM, longer on disk. Plan guards hold the read to the index on a ledger shaped
  like the incident.
- **An append no longer costs more the longer its source has been seen** - every scored append
  counted the source's distinct WAN vantages and distinct sensors by reading every earlier event
  of that source (a `GROUP BY wan_ip` and a `COUNT(DISTINCT sensor)`), inside the global append
  lock. On a 7.5M-row ledger that was 0.73 s per event for a source with 100k events, 3.5 s at
  200k, 7.1 s at 800k and 9.4 s at 1.5M, and a long-running bot loop on one address set the pace
  for every sensor: three fresh sources appending beside a 1.5M-event one managed about one
  event a second between them. Migration `0014` adds two projection tables, `ip_vantage
  (source_ip, wan_ip, saw_authenticated_tcp)` and `ip_sensor (source_ip, sensor)`, which the
  append folds each scored event into under the same lock and reads by primary key; telemetry
  never writes them. The same appends now take 2.8 to 3.3 ms whatever the history, against 3.1
  ms for a source never seen, and the four mixed sources together reach 358 events a second.
  The migration backfills both tables from the ledger at startup, before intake runs: 23 to 26 s
  for that ledger held in RAM, longer on disk. `rebuild_projection` still counts from the ledger
  rows, so a replay checks the tables; a property test compares the tables with the old
  aggregates after every append of random multi-source sequences with telemetry and
  out-of-order events.
- **`echo` and `printf` escapes write the bytes they name** - `\xNN` and octal escapes from
  0x80 to 0xff came out as the UTF-8 encoding of that code point (two bytes), so a Mirai/Mozi
  echo loader that assembles its downloader as `busybox echo -ne '\x7f\x45...' >> .i` chunks
  left a file that was not the one it sent. Both now produce one raw byte per escape, and an
  octal escape past 0xff keeps its low eight bits. `busybox wget` with no URL prints BusyBox
  1.30.1's wget usage on stderr and exits 1 (it printed a download transcript for an empty URL),
  and dash answers a path that does not exist with `sh: N: ./x: not found`, as its `errmsg`
  does, instead of bash's `No such file or directory`.
- **`upgrade.sh` no longer finishes an upgrade with the copy of itself it started from** - bash
  reads a script as it runs, so after `git pull` replaced `deploy/upgrade.sh` the rest of the
  upgrade ran the old text: a release that added `propolis-watch` to the binary list built it
  and then installed from the list without it, leaving `/usr/local/bin/propolis-watch` missing.
  When the pull changes the script, `upgrade.sh` now re-executes the new one with
  `PROPOLIS_UPGRADE_REEXEC=1`, which makes that run skip the pull (it cannot loop) and carries
  the first run's pull timestamp in `PROPOLIS_UPGRADE_PULLED_AT`, so the deploy stamp still
  records when the pull happened. The binary install now checks each built binary exists
  before installing it and, afterwards, that every listed binary is present in
  `/usr/local/bin` before anything is stamped or restarted (`install.sh` does the same check
  after its install). Both scripts keep the list in one `INSTALL_BINS` array, and a new test
  compares it with the workspace's binary targets, so a binary added to the workspace but not
  to the lists fails the build.
- **The live-watch documentation no longer sends the reader to the honeypot's SSH sensor** -
  its examples connected to port 22, which on a honeypot host is usually `sensor-ssh`; one
  attempt landed in the fake shell. Every example now names the real sshd with
  `-p <admin-port>`, `docs/operations/live-watch.md` warns against the sensor's listener and
  shows `sudo ss -ltnp | grep sshd` to find the real port, and notes that a passphrase-protected
  key needs `ssh-add` for unattended use.
- **A command's standard input reaches it, and is captured** - an SSH exec ran at the request
  and closed the channel, so the payload a bot streamed after `cat > astats` or `cat > w.sh`
  hit a closed channel: the file stayed empty, nothing was captured, and the bot retried and
  left. The fake shell now decides, by running the line against its own model of the commands
  and rolling back what that run did (`FakeShell::start_line`), whether a line reads its input
  (`cat`, `cat > f`, `dd` without `if=`, `base64 -d`, `head`, `read`, a bare `sh` on a pipe,
  the same inside `sh -c`, a group or a pipeline). Such an SSH exec is held with the channel
  open until the client's EOF (or CLOSE, the idle timeout, `max_captured_bytes`, the session's
  end) and then runs once on the input, followed by its output, exit status, EOF and CLOSE; a
  command that reads no input still completes at the request. At the SSH, telnet and ADB
  shells a typed `cat > f` takes the lines after it until Ctrl-D, as a terminal does (Ctrl-C
  kills it, status 130), and an ADB `shell:<command>` that reads input holds its stream until
  the client closes it. Every consumed body, text or binary, becomes one
  `honeypot_malware_upload` per distinct SHA-256 per session, with `capture_reason`
  `exec_stdin` or `shell_stdin`, the `command`, the `destination` file and a `repeat_count`
  for retried uploads; those bytes are no longer also offered to the binary-payload shell
  capture. `ls` now lists a file operand (it said `No such file` for a file `wc` read) and has
  a `-l` long listing from the facts `stat` prints, and `sh -lc`/`bash -ec` find their
  clustered `-c` script instead of running the script text as a file name.
- **Every captured upload records why it ended** - the fleet pane's capture panel gave
  `unrecorded` as the end reason of incomplete captures (ten of ten for SSH), because
  `upload_metadata` took only a `complete` flag and `end_reason` was added by hand at the three
  shell-capture sites. SCP, SFTP, ADB sync, FTP STOR, TFTP WRQ and MQTT PUBLISH captures never
  carried it. `upload_metadata` now takes a required `UploadEnd` and writes both `complete` and
  `end_reason` from it, so neither can be omitted or disagree. A finished transfer reads
  `transfer_complete`; a transfer cut off before its end of file carries what cut it
  (`peer_closed`, `client_logout`, `idle_timeout`, `session_cancelled`, `transport_error`,
  `malformed_input`, `capture_budget`, and for a TFTP peer ERROR the new `peer_aborted`) with
  `complete` false, even where the same label makes a shell capture complete. SSH passes each open
  SCP or SFTP transfer the session's real ending, or `peer_closed` when its channel is closed; an
  ADB sync stream the client closes records `peer_closed`; FTP records an idle data connection as
  `idle_timeout` and a failed one as `transport_error`. The shell-capture labels are unchanged.
  Events already stored keep no `end_reason` and still read `unrecorded`; nothing is backfilled.
- **The IP detail page shows a catch-all probe's port** - the evidence row read
  `metadata.port`, which no sensor has ever written, so every catch-all probe showed `-`. It now
  reads the stamped `metadata.local_port`.
- **The fleet pane counts each listener, not each sensor** - LAST EVENT and 24H are per listener
  row, but the query grouped by sensor, so every port of a sensor showed the sensor's total (two
  Redis ports with the same count, HTTP 80 and 443 alike, every catch-all row identical). Activity
  is now keyed by sensor, `protocol` and the new `metadata.local_port`. The query also aggregated
  the whole event ledger on every load and 30-second refresh; it now reads the last 24 hours for
  the count and the 30 days before that for LAST EVENT, both ranges on `observed_at`. A listener
  with nothing in those 30 days reads `none in 30d` instead of `never`, which the page can no
  longer prove. Events recorded before the upgrade have no port: they count on the sensor's row
  when it declares exactly one listener, and otherwise on one `port not recorded` row per sensor,
  which is not a listener and ages out after 30 days. A port present in the ledger but missing
  from `PROPOLIS_FLEET_LISTENERS` gets its own `undeclared listener` row.
- **`propolis` stops in at most 37 s, and the journal names a subsystem that would not stop** -
  after the shutdown signal the daemon waited 30 s for its subsystems, logged "shutdown timed
  out", then called `pool.close()`, which waits for every checked-out connection to be returned.
  A subsystem that ignored cancellation was never aborted (and aborting the supervisor task
  would have left the task under it running), so it kept its connection, `pool.close()` never
  returned, and `systemctl restart propolis` (and so `deploy/upgrade.sh`) sat until systemd's 90 s
  stop timeout SIGKILLed the process. Shutdown now aborts every subsystem still running after
  the 30 s grace (including the task beneath a supervised subsystem and the children of a
  supervised group), allows 2 s for them to unwind, bounds `pool.close()` at 5 s, and logs
  `propolis: shutdown timed out waiting for: <names>; aborted`. A build-time assertion keeps the
  total under systemd's default stop timeout.
- **`deploy/sensor.env.example` lists the real `sensor-catchall` defaults** - the example block
  showed the shell sensors' bounds (30000 ms read, 60000 ms idle, 600 s duration, 1000000 bytes)
  and the deprecated bare `CATCHALL_MAX_CONCURRENT` name. The sensor's compiled defaults are 5000
  ms, 5000 ms, 30 s and 4096 bytes (`crates/sensor-catchall/src/main.rs`), and the block now says
  so, uses the `PROPOLIS_` name throughout, and notes that the compiled default log path is
  relative.
- **A non-UTF-8 environment variable is a startup error in every sensor, never read as unset** -
  most sensor variables were read with `env::var(..).ok()` or `if let Ok(..)`, so a value that was
  not valid UTF-8 silently fell back to the default or skipped the work: a bound or a timeout
  reverted to its default, a log path or collector id was replaced, and `sensor-cred` skipped a
  protocol's `PROPOLIS_CRED_*_BIND` listener the fleet inventory still claimed. All eleven sensors
  (and the collector id read in `shipper`) now read every variable through
  `sensor_framework::strict_env_var` (renamed from `tls_env_var`, with its error type
  `EnvError`, and moved from `tls.rs` to `env.rs`; no alias is kept), which exits 1 before any
  bind with `environment variable <NAME> is not valid UTF-8`. `env_with_legacy` now applies the
  same rule to both spellings. Side effects of the shared reader on valid UTF-8: a value is
  trimmed of ASCII whitespace (a numeric bound written with a stray space now parses), and a
  value blank after the trim counts as unset: an optional variable falls back to its default
  where it used to error or be used as an empty string (a blank `PROPOLIS_CRED_*_BIND` now skips
  that protocol, a blank `PROPOLIS_SSH_BANNER` or collector id takes the default), and a blank
  required bind is still a startup error.
- **`sensor-ftp` treats `pasv` and `nlst` like their uppercase forms** - the PASV/EPSV and
  LIST/NLST replies were chosen by a case-sensitive comparison, so lowercase `pasv` got the EPSV
  style `229` reply and lowercase `nlst` got the long LIST output. Every other verb was already
  case-insensitive. The TLS reset, data-peer and bind-failure guards that were correct but
  unguarded by tests now each have a test.
- **A malformed PEM error never carries key bytes** - the PEM parser's own error prints the
  offending line or section label as a byte list, and for a key written header, body and footer on
  one line that label is the whole key, which every TLS sensor then logged at error level. The
  error now names the file and a fixed description of the fault (for example
  `missing section end marker`) for both the certificate and the key file, and keeps no parser
  error in its source chain.
- **Sensors log at `info` by default** - every sensor called `tracing_subscriber::fmt::init()`,
  whose default is `error` once a workspace build unifies the `env-filter` feature in, so a
  deployed sensor logged no listening lines and no warnings. All eleven now default to `info`, and
  `RUST_LOG` still overrides it, however the binary is built.
- **Sensor TLS finalize** - a TLS variable (or sensor-smtp's submission bind) holding a non-UTF-8
  value is now invalid on every TLS sensor, and the sensor exits 1 before any bind. sensor-ftp and
  sensor-smtp read such a value as unset, which silently skipped the 990, 465 or 587 listener or
  turned TLS off; http, redis and mqtt converted it lossily. The six TLS units grant the TLS
  directory as `ReadOnlyPaths=-/etc/propolis/tls`, so a host without `/etc/propolis/tls` no longer
  fails every one of those units with `226/NAMESPACE`, TLS used or not; a configured pair that
  cannot be read still refuses to start. A deploy test now holds the units carrying that line
  equal to the sensors `provision-tls.sh` mints for. `deploy/sensor.env.example` showed
  sensor-cred's `MAX_DURATION_SECS` and `MAX_CAPTURED_BYTES` defaults as 600 and 1000000; the code
  defaults are 60 and 100000. The component inventory still called sensor-mqtt metadata-only
  with MQTT 5.0 declined, and the troubleshooting page said sensors terminate no TLS. The
  networking and TLS guide is reorganized around one table of every TLS surface.
- **Split-deployment examples and references match the code** - the example env files named
  certificate files `provision-certs` never writes and called every one 0600, described the
  gateway address as `host:port` (only a literal IP and port is accepted), called the client
  certificate revocable (nothing revokes one), and gave a re-provisioning recipe for more
  collectors that the tool cannot carry out. The environment variable reference said the sensors
  log at `info` without `RUST_LOG`; they then logged only errors (the sensors now default to
  `info`, see above), and every binary except `propolis`, `console` and the sensors still does.
  The gateway unit suggested a capability grant for a port below 1024 that `PrivateUsers=yes`
  makes useless. These, the reference's gateway and shipper tables, and the backup, upgrade and
  compatibility pages are corrected.
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
  publish - before the new snapshot is re-validated or staged, so a build that is rejected or
  cannot stage costs that build and not the availability of the feed already published.
- **OTX indicators carry their real address family** - the pulse payload declared every indicator
  `IPv4` while reports accept either family, so an IPv6 address was submitted mislabelled against
  an API that validates the value against its declared type.
- **A polled page survives the session expiring underneath it** - protected routes answered an
  HTMX request with a 303 to `/login`. The XHR followed it, `/login` returned 200 with a whole HTML
  document, and HTMX swapped that document into the container that issued the poll - leaving
  `<html>`, `<head>`, a password field and a second copy of every vendored script nested inside a
  `<div>`, with nothing about it looking like an error. Sessions are in-memory and a restart clears
  them, so this happened after every upgrade on any page left open. HTMX requests now get a 401
  with `HX-Redirect` and no swappable body.
- **The fleet page no longer reports what it did not measure** - the headline was chosen from the
  combined severity of the reachability and event-age checks, so a fully probed and confirmed fleet
  with one quiet listener read as "evidence path unconfirmed". A failed capture query rendered as
  "no malware captures", and a failed event count as `0 events`. A failed refresh left the previous
  reading on screen with server-computed ages that never moved again; a stalled panel now says how
  long ago its numbers were actually measured. A poll that is accepted and then never answered
  raises no error event at all, and HTMX's default request timeout is unlimited, so the panel is
  bounded by a real request timeout AND aged on its own clock rather than waiting for an event that
  may never come. A failed end-reason query no longer renders as "nothing incomplete" beside a row
  that is counting incomplete captures.
- **Queue decisions are all-or-nothing** - delist, relist and delete-ip each issued two or three
  autocommit statements, so a failure part-way left an address half changed (a queue row dropped
  with the feed latch kept, `delisted` cleared without the gates recomputed, vendor rows deleted
  while the score row survived). Each now runs in one transaction.
- **Upgrades build what CI tested** - `upgrade.sh` built with a bare `cargo build --release`, which
  could resolve a dependency graph CI never ran and relied on default members covering every
  installed binary. It now builds with `--workspace --locked`, as the CI release job does.
- **The backup stores each sample once and restores owners by name** - the documented archive named
  the fetched-sample directory and its parent, so every fetched sample was stored and restored
  twice, and `--numeric-owner` recorded only numbers, which a rebuilt host whose service users got
  different UIDs would hand to the wrong accounts. Restore now runs `provision.sh` before
  extracting. `crates/propolis/tests/restore_rehearsal.rs` (ignored by default; it needs PostgreSQL
  server binaries) restores a populated backup into a fresh cluster and checks the ledger, its
  grants and sequences, and the spooled samples.
- **The docs state the tree they describe** - current pages said 18 crates at `0.3.0`, 15 binaries
  and 1165 tests against a tree of 24 crates, 17 binaries and over 1600 tests, and the component
  inventory lacked six crates. The docs agreement test now recomputes the version, crate, member and
  binary totals, the component inventory and dependency graph, the test taxonomy and the migration
  list from `cargo metadata` and the source, and fails when a current page disagrees.
- **Code citations point at the code again** - the docs cited code by `path:line`, and about 450
  citations had drifted as the cited files changed, including every directory citation into
  `install.sh` after provisioning moved to `provision.sh`. All were re-read against the current
  source and sentences the code had outgrown were rewritten. Every citation now names a symbol
  instead of a line (`crates/sensor-framework/src/spool.rs#store`), which an edit elsewhere in the
  file cannot move. The docs agreement test fails on a line citation in any form, and on a
  `path#symbol` whose file is gone or no longer contains the symbol.
- **Two stores of the same sample at once both succeed** - the spool wrote a body straight to its
  digest name, so a second store of the same bytes during that write (the malware fetcher runs
  several fetches at once, and two URLs can serve one payload) re-hashed the half-written file
  and failed it as corrupt, recording a failed fetch. A body is now written to a staging file,
  synced, and given its name with a hard link, which never replaces an existing name, so a
  digest name only ever holds a complete body. Staged files a stopped process left behind are
  removed at the next start.
- **Smaller console hardening** - the reverse-DNS cache holds at most 4096 entries, sweeping expired
  ones and evicting the oldest; search refuses a control character or a value over 512 bytes with
  400 instead of passing it to PostgreSQL.

### Changed

- **One reading rule for every sensor TLS variable** - all six TLS sensors read each
  `*_TLS_BIND`, `*_TLS_CERT`, `*_TLS_KEY` and `PROPOLIS_SMTP_SUBMISSION_BIND` the same way: the
  value is trimmed of ASCII whitespace and a blank one counts as unset, as
  `deploy/fleet-listeners.sh` already treated a blank bind. Until now a blank TLS bind made http,
  redis and mqtt exit 1 as an invalid address, a blank cert or key made sensor-cred exit 1, and
  smtp and ftp did not trim paths. A non-UTF-8 value is still invalid.
- **One bind-failure message** - a listener that fails to start after its configuration validated
  is logged by every sensor as
  `<sensor>: cannot start listener on <ip:port>: <OS error>; refusing to start` (catchall and cred,
  which skip one failed address, end that line `; skipping ...` and refuse only when every address
  failed). The behavior is unchanged.
- **A snooze can be finished and a delist undone** - the Snoozed tab had no decision controls and
  nothing re-surfaces a decided entry, so deferring a decision quietly meant never making one; the
  history tabs also rendered rows with an empty CSRF token. The tab now carries Approve, Reject and
  Return to pending. `POST /ip/{ip}/relist` undoes a delist by clearing the latch and re-deriving
  the gates, so an address rejoins the feed on its current merit rather than because it was once
  listed. Also `review unsnooze` and `review snoozed` on the CLI.

### Security

Remediation of an external audit (findings P-01 to P-15). Upgrading applies review migrations
`0006` and `0007`.

- **Spool reads no longer follow links** - the console's sample download and the VirusTotal
  uploader opened a digest-named spool entry by name, so a symlink planted in a spool (which the
  internet-facing sensors write) made them read whatever local file it named, and the uploader
  could send it to a third party when unknown-sample upload was on. Entries are now opened without
  following links, must be regular files within the 500 MB sample cap, and are re-hashed against
  their names; a mismatch answers 409.
- **Nodes sharing a database share the fetcher's limits** - each node picked its own fetch rows and
  kept the per-host and daily budgets in memory, so two nodes could fetch the same malware URL at
  once, N nodes spent N times each cap, and a restart reset the daily count. Rows are now claimed
  with a lease (`claim_expires`) and the budgets are spent in the database under a row lock
  (migration `0006`, new table `fetch_daily_usage`).
- **Captured bodies record how their transport was authenticated** - the fetcher never validated
  certificates, so an https capture carried no evidence that its bytes came from the named host.
  It now validates first and fetches again without validation only after a certificate failure,
  to the same pinned address, and labels every captured body `verified`, `unverified` (with the
  validation error), `plaintext` or `unknown` (migration `0007`); the samples page shows the label.
  Cost: a TLS 1.2 server that can sign its handshake only with SHA-1 is no longer captured.
  Plain-http hops build no certificate verifier, so they neither load the system trust store
  nor fail on a host without one.
- **The fetcher ignores proxy settings in its environment** - reqwest reads `HTTP_PROXY`,
  `HTTPS_PROXY` and `ALL_PROXY` by default, and a proxy resolves and dials the host itself, so a
  fetch would have bypassed the address the SSRF guard vetted.
- **Every special-purpose address block is kept out of the feed** - the reserved list gains the
  IANA special-purpose blocks it lacked (carrier-grade NAT `100.64.0.0/10` among them), and an IPv6
  address that embeds an IPv4 host (mapped, NAT64 `64:ff9b::/96`, 6to4) is judged by that host.
  Such addresses are never published, reported or dialed. Existing rows are not rewritten: the next
  feed build drops them, an approved queue row for one is held as reserved and warns on every
  poll, and a fetch row resolving into one is rejected on its next attempt.
- **The console bounds what one client can hold** - `axum::serve` armed no header timeout and
  capped nothing, so slow or idle connections could be held indefinitely. The console now runs its
  own HTTP/1.1 accept loop (64 connections, 10 s for headers, 10 s and 2 MiB for a body), checks
  passwords in two bounded slots so a login flood cannot take the CPU, and limits login attempts
  to 30 a minute across all addresses as well as 5 per address. `propolis_console_*` metrics count
  what was refused.
- **A Content-Security-Policy on every page** - scripts and styles are served as files, templates
  carry no inline script, style or event handler, and every response carries a policy that allows
  script and style only from the console itself. The error pages the console builds without a
  template follow it too, and Relist, Delist and Delete, which used to confirm through an inline
  handler, render disabled until the script that asks for confirmation has loaded.
- **Chart data cannot end its script element** - the dashboard's protocol chart labels are
  sensor names, which intake takes as any non-empty string and a split deployment receives from
  its collectors. Placed raw in the chart's JSON data element, a name holding `</script>` ended
  the element and put the rest into the operator's page as markup (before the policy, as script).
  Chart data now escapes `<`, `>` and `&` as JSON unicode escapes.
- **Chain verification needs a CSRF token** - `POST /integrity/verify` reads the whole ledger but
  took no token; it now requires one like every other console POST, and a second run while one is
  in progress answers 409.
- **Certificates are written without following links** - `provision-certs` wrote each PEM and
  tightened key modes afterwards, following any link already at the target and joining the
  collector id into the path unchecked. Files are now created new with their final mode, and a
  collector id that is not a plain name is refused.
- **Dependency policy** - `event-listener` 5.4.2 (RUSTSEC-2026-0221), two yanked crates replaced,
  unused and unmaintained crates removed. `deny.toml` fails CI on a vulnerable, unsound,
  unmaintained or yanked crate, a licence outside the allowlist, or an unknown registry or git
  source, with one reviewed exception (RUSTSEC-2023-0071 in `rsa`, reachable only from a test
  client).
