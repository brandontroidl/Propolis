<!--
title: Events and signals reference
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-09
-->

# Events and signals reference

Canonical owner of the sensor-to-intake wire format, the sample side-channel
reference, the signal types and their meanings, and the signal weight table. The
persisted schema those events land in is owned by [database.md](database.md); scoring
math is owned by [scoring-and-feed.md](scoring-and-feed.md).

## SensorEvent wire format (`crates/sensor-wire/src/lib.rs`)

A frozen NDJSON record - one line per event, no embedded `\n` or `\r` (test
`ndjson_single_line`, `crates/sensor-wire/src/lib.rs#ndjson_single_line`). A single definition is shared by every sensor
(producer) and by intake (consumer), so the wire shape has one source of truth.
`WIRE_VERSION = 1` (`crates/sensor-wire/src/lib.rs#WIRE_VERSION`), `VERSION_MARKER = "sensor-wire"` (`crates/sensor-wire/src/lib.rs#VERSION_MARKER`).

`SensorEvent` struct (`crates/sensor-wire/src/lib.rs#SensorEvent`), 12 fields:

| field | type | notes |
|---|---|---|
| `v` | u32 | wire version (`WIRE_VERSION`, currently 1) |
| `source_ip` | IpAddr | attacker source |
| `wan_ip` | Option\<IpAddr\> | serializes as `"wan_ip":null` when None (test `null_wan_ip_serializes`, `crates/sensor-wire/src/lib.rs#null_wan_ip_serializes`) |
| `sensor` | String | sensor name |
| `signal_type` | String | plain string, **not** the enum - keeps sensor-wire free of a core-scoring dependency; intake validates it against the known set (`crates/sensor-wire/src/lib.rs#SensorEvent`) |
| `protocol` | String | plain string, same rationale |
| `authenticated` | bool | |
| `observed_at` | DateTime\<Utc\> | RFC 3339 via chrono's default serde - **must** match `hashing.rs`; switching to `ts_microseconds` (integer timestamp) would break the hash chain (`crates/sensor-wire/src/lib.rs#SensorEvent`) |
| `metadata` | serde_json::Value | free-form per-signal detail |
| `sample` | Option\<SampleRef\> | side-channel file reference (see below) |
| `session_id` | Option\<Uuid\> | `#[serde(default, skip_serializing_if = "Option::is_none")]` - omitted from JSON when None; older records without the key still deserialize (test `deserialize_without_session_id`, `crates/sensor-wire/src/lib.rs#deserialize_without_session_id`) |
| `occurrence_id` | Option\<Uuid\> | `#[serde(default, skip_serializing_if = "Option::is_none")]` - UUIDv7 minted once per event at emit time (`EventEmitter::append`), stable across replays so intake can dedup exactly (`crates/sensor-wire/src/lib.rs#SensorEvent`) |

A sensor emits raw facts only. `weight`, `confidence`, and `category` are **not** on
the wire - they are derived downstream by `EventInput::from_signal` from the [signal
weight table](#signal-weight-table), so a sensor never computes them.

`signal_type` and `protocol` are plain strings so the crate needs no dependency on
core-scoring or its database layer. The wire values match core-scoring's serde
Deserialize casing exactly; see the [serde casing note](database.md#serde-casing-asymmetry-hash-chain-critical).
Sensor-emittable constants are provided so literals are not hand-typed:

- Signal (`crates/sensor-wire/src/lib.rs#SIGNAL_CATCHALL_PROBE`, `crates/sensor-wire/src/lib.rs#SIGNAL_HONEYPOT_CONNECTION`, `crates/sensor-wire/src/lib.rs#SIGNAL_HONEYPOT_LOGIN_ATTEMPT`, `crates/sensor-wire/src/lib.rs#SIGNAL_HONEYPOT_COMMAND_EXEC`, `crates/sensor-wire/src/lib.rs#SIGNAL_HONEYPOT_MALWARE_UPLOAD`, `crates/sensor-wire/src/lib.rs#SIGNAL_HONEYPOT_FILE_DOWNLOAD`), the subset a sensor can emit: `catchall_probe`,
  `honeypot_connection`, `honeypot_login_attempt`, `honeypot_command_exec`,
  `honeypot_malware_upload`, `honeypot_file_download`, plus the telemetry constant
  `honeypot_session_end` (`crates/sensor-wire/src/lib.rs#SIGNAL_HONEYPOT_SESSION_END`) - recorded in the ledger but never scored;
  only `sensor-mqtt` (every session) and `sensor-ssh` (a connection that ends before key exchange completes) emit it so far. The remaining signal types (Suricata, WAF, port scan,
  and so on) originate from other layers, not sensor-wire.
- `sensor_stats` (`crates/sensor-wire/src/lib.rs#SIGNAL_SENSOR_STATS`) is **not a ledger signal
  type** and has no `SignalType` variant. It is a sensor's own health line: the capture hand-off
  counters (`dropped`, `spool_refused`, `truncated`, `refused`), the capture memory budget
  (`budget_current`, `budget_high_water`, `budget_refused`), `uptime_secs`, `final` and `sensor`
  (`crates/sensor-wire/src/lib.rs#SensorStats`). Its `source_ip` is always `0.0.0.0`
  (`crates/sensor-wire/src/lib.rs#SENSOR_STATS_SOURCE_IP`), a sentinel naming no host. The six
  capturing sensors (ssh, telnet, adb, ftp, mqtt, tftp) write one every 60 s
  (`crates/sensor-framework/src/handoff.rs#STATS_INTERVAL`) and one more with `final` true as they
  shut down. Intake takes it out of the line stream before conversion and stores the latest per
  sensor in the `sensor_stats` table (`fleet` migration `0002`); it is never in the ledger, so it
  is never scored, fed, clustered into a campaign or submitted to a vendor. Intake refuses (counts
  as rejected, WARN) a line whose source is not `0.0.0.0`, whose metadata is not exactly the fixed
  field set, whose values pass 2^53, or whose sensor name is not the label of the log it was read
  from. The `propolis-watch` feed prints it like any other line.
- Protocol (`crates/sensor-wire/src/lib.rs#PROTO_TCP`, `crates/sensor-wire/src/lib.rs#PROTO_UDP`, `crates/sensor-wire/src/lib.rs#PROTO_ICMP`): `tcp`, `udp`, `icmp`.

### SampleRef

A reference to a captured file body written to the quarantine spool, named by its
SHA-256. The body travels out-of-band (the spool); only this reference rides the wire.

| field | type | notes |
|---|---|---|
| `sha256` | String | content hash; the spool filename |
| `size` | u64 | body size in bytes |
| `orig_name` | String | attacker-controlled; carried as a **sanitized indicator only**, never used as a path component (`crates/sensor-wire/src/lib.rs#SampleRef`) |
| `capture_id` | Option\<Uuid\> | `#[serde(default, skip_serializing_if = "Option::is_none")]` - observation join key minted at `QuarantineSpool::store`; `sha256` identifies content, `capture_id` identifies the observation (`crates/sensor-wire/src/lib.rs#SampleRef`) |

The `sha256` here is the key into [`sample_analysis`](database.md#table-sample_analysis-0009_sample_analysissql).

Body-capturing sensors cap what they retain (10 MB for SCP, SFTP, ADB and FTP
STOR; `PROPOLIS_TELNET_MAX_CAPTURED_BYTES` for a telnet binary-payload capture; the
sensor's `max_captured_bytes` for a command's standard input)
and drain the rest to keep the protocol aligned. Their `honeypot_malware_upload`
metadata therefore also carries `wire_size` (bytes the client actually sent) and
`truncated` (`wire_size > size`), built by `sensor_framework::upload_metadata`.
When `truncated` is true the `sha256` and `size` describe a prefix, not the file;
the IP detail page shows such rows with status `truncated` instead of `captured`.
FTP drains at most a further 10 MB past its cap before closing the data
connection, so a `wire_size` of 20 MB on an FTP row is a floor, not the total.
Every upload row also carries `complete`: false when the transfer did not end the way
its protocol defines the end of a file (FTP's data connection stalled or failed, or
hit the drain cap; SCP ended before its trailer; an SFTP handle was never closed; an
ADB SEND got no DONE), so the captured bytes are a fragment of whatever was being sent.
The fragment is submitted whichever way the session ends, including the listener's
`max_duration` cut-off, which cancels the handler outright. The same applies to the
binary shell-phase captures on SSH and telnet: each is submitted by the destructor of
the buffer that holds it, not by code after the session loop, which a cancelled handler
never reaches. The IP detail page shows such
rows with status `incomplete`.

#### `end_reason`

Every upload row also carries `end_reason`, what ended the capture. `upload_metadata` takes it as a
required `UploadEnd` and derives `complete` from the same value, so the two keys are always
present together and cannot disagree (`crates/sensor-framework/src/handoff.rs#UploadEnd`,
`crates/sensor-framework/src/handoff.rs#upload_metadata`). A file transfer is complete only at its
own end of file; cut off before it, it carries the label of what cut it with `complete` false,
even where the same label makes a shell capture complete. The cut-off labels are the session
endings of `crates/sensor-framework/src/handoff.rs#CaptureEnd`.

| value | meaning |
|---|---|
| `transfer_complete` | the transfer reached its protocol's end of file (always `complete` true) |
| `peer_closed` | the peer closed the connection, or the channel or stream carrying the transfer |
| `client_logout` | the peer asked to end the session (`exit`/`logout`, SSH DISCONNECT) |
| `idle_timeout` | nothing arrived within `idle_timeout` (or `read_timeout` for the first read) |
| `transport_error` | the socket failed, or a reply could not be written |
| `malformed_input` | the peer sent something the protocol could not parse |
| `capture_budget` | a sensor-side read bound: `max_captured_bytes`, or a per-transfer cap derived from it |
| `peer_aborted` | the peer aborted the transfer with its protocol's error message, or with Ctrl-C at a terminal |
| `session_cancelled` | the listener cancelled the handler at `max_duration`; no code observed another ending |
| `capture_memory_budget` | the process-wide capture memory budget ran out; overrides any other value (`crates/sensor-framework/src/handoff.rs#mark_budget_truncated`) |

What each sensor writes:

| capture | `complete` true | `complete` false |
|---|---|---|
| ssh SCP, SFTP | `transfer_complete` (SCP trailer, SFTP CLOSE) | the session's ending: `peer_closed` (socket or the transfer's channel closed), `client_logout`, `idle_timeout`, `transport_error`, `malformed_input`, `session_cancelled` |
| adb sync push | `transfer_complete` (DONE) | `peer_closed` (CLSE of the sync stream, or the socket), `idle_timeout`, `transport_error`, `malformed_input` (including a sync message the stream cannot parse), `capture_budget`, `session_cancelled` |
| ftp STOR | `transfer_complete` (data connection closed) | `idle_timeout`, `transport_error`, `capture_budget` (the drain cap), `session_cancelled` |
| tftp WRQ | `transfer_complete` (short final block) | `capture_budget` (body cap or packet allowance), `idle_timeout`, `peer_aborted` (ERROR from the peer), `malformed_input` (oversized DATA), `transport_error`, `session_cancelled` |
| mqtt PUBLISH | `transfer_complete` (the packet is read whole) | only `capture_memory_budget` |
| ssh, telnet, adb binary shell payload | `peer_closed`, `client_logout` | `idle_timeout`, `transport_error`, `malformed_input` (ssh, adb), `capture_budget` (telnet, adb), `session_cancelled` |
| ssh, telnet, adb standard input of a command (`exec_stdin`, `shell_stdin`) | `transfer_complete` (the SSH channel's EOF, Ctrl-D at the start of a terminal line) | `peer_aborted` (Ctrl-C), `capture_budget` (the input reached `max_captured_bytes`), `peer_closed` (the channel or ADB stream closed before end of input), `client_logout`, `idle_timeout`, `transport_error`, `malformed_input`, `session_cancelled` |
| ssh, telnet, adb file assembled from `echo`/`printf` chunks (`echo_loader`) | `transfer_complete` (the file was made executable or run); for one never run, taken when the session ends, `peer_closed` or `client_logout` | the session's other endings, for a file never run: `idle_timeout`, `transport_error`, `malformed_input`, `capture_budget`, `session_cancelled` |

Any of them can instead read `capture_memory_budget`. Events stored before `end_reason` was
written for every capture (shell captures carried it earlier, the transfers did not) have no
key; the fleet pane's capture panel counts those as `unrecorded`
(`crates/console/src/routes/fleet.rs#top_end_reasons`), and they are not backfilled.

#### `capture_reason` and the standard-input keys

Captures that are not a protocol's own file transfer say why the bytes were kept:

| `capture_reason` | sensors | what was captured |
|---|---|---|
| `binary_shell_payload` | ssh, telnet, adb | bytes typed at an interactive shell that look binary (a dropper streamed at the prompt) |
| `binary_publish_payload` | mqtt | a PUBLISH payload that looks binary |
| `exec_stdin` | ssh (exec channel), adb (`shell:<command>`) | the standard input a command read: the data sent on its channel or stream |
| `shell_stdin` | ssh, telnet, adb (interactive shell) | the input a typed line read: what was typed after it (`cat > f` takes the lines up to Ctrl-D) |

Standard input is captured text and binary alike, once per distinct body (SHA-256 of the bytes
kept) per session, when the session ends, including by the listener's `max_duration`
cancellation (`crates/sensor-framework/src/held_input.rs#StdinCaptures`). Each body is held to
`max_captured_bytes`, the rest counted in `wire_size`. Bytes a command consumed are captured
only as its input, never also as a `binary_shell_payload`. The `exec_stdin` and `shell_stdin`
rows carry three more keys:

| key | type | meaning |
|---|---|---|
| `command` | string | the line that read the input, sanitized and capped at 1024 characters, as `metadata.command` records it |
| `destination` | string or null | the first file the reading command wrote (`cat > f`, `dd of=f`, `base64 -d > f`), sanitized and capped at 512 characters; null when the input went to no file (a bare `sh` ran it). `orig_name` is its last component |
| `repeat_count` | integer | how many times the session sent this exact body: a bot retrying an upload yields one sample with a count, not one sample per attempt. When a later copy arrived whole, the capture takes that copy's `end_reason` |

A session holds at most 16 distinct bodies (`crates/sensor-framework/src/held_input.rs#MAX_HELD_CAPTURES`);
a further distinct one is submitted at once with `repeat_count` 1.

#### Echo-loader captures and their keys

A file the shell built from the output of `echo` or `printf` redirected into it (an echo loader's
`busybox echo -ne '\xNN...' > .i`, then `>> .i` per chunk) is captured with `capture_reason`
`echo_loader` through the same per-session set (`crates/sensor-framework/src/shell/loader.rs`,
`crates/sensor-framework/src/held_input.rs#CAPTURE_REASON_ECHO_LOADER`). An assembly starts with a
write to an empty file and grows by appends to the content its last chunk left; appending to any
other file starts none. It is submitted once the line that makes it executable (`chmod`) or runs
it has run, at most once per distinct SHA-256 per session, a body already captured as standard
input included. A file is recognized by content, so a copy of the assembly made under another
name (the loader's `cp /bin/ls .j && cat .i>.j && rm .i && cp .j .i` fallback) is the same
sample. An assembly of two or more chunks that was never made executable or run is taken when the
session ends, if it still holds what its last chunk left
(`crates/sensor-framework/src/held_input.rs#MIN_UNRUN_CHUNKS`); a one-chunk `echo x > f` is not.
The row carries `command` (the line that wrote the last chunk), `destination` (the file's path,
`orig_name` its last component), `repeat_count` 1, and:

| key | type | meaning |
|---|---|---|
| `chunk_count` | integer | how many `echo`/`printf` writes built the file |

A loader that sends the file as base64 text (`echo -n '<base64>' >> f.b64` per chunk, then
`base64 -d f.b64 > f.dec`) builds two assemblies: the text, and the bytes it decodes to. The
decode of a file an assembly left, or of standard input piped from `echo` or `printf`, is itself
an assembly counting as many chunks as its input did, so the decoded file is submitted under the
same rules: when it is made executable or run, when `pm install` is given it (Android shell), or
when the session ends. Both are `echo_loader` rows, told apart by `sha256`; the decode's `command` is
the `base64 -d` line. On ADB every `shell:<command>` is its own shell, so assemblies are shared
across the shells of one connection
(`crates/sensor-framework/src/shell/loader.rs#FakeShell::import_assembled`).

The command event of every line that wrote a chunk carries two keys that link it to the capture
(same `session_id`, `assembled_file` equal to the capture's `destination`), so the chunks can be
read as one upload:

| key | type | meaning |
|---|---|---|
| `assembled_file` | string | the file the line wrote a chunk of, sanitized and capped at 512 characters |
| `chunk_index` | integer | that chunk's number, 1 for the write that started the file |

Running an assembled ELF as `PROG a b c d port` (four decimal octets and a port), when its bytes
hold a `GET <path> HTTP/1.x` request line, emits a `honeypot_file_download` whose `url` is
`http://a.b.c.d:port<path>`, the stage-2 URL the downloader would request, with two more keys:

| key | type | meaning |
|---|---|---|
| `derived_from` | string | `echo_loader_args`: the URL was read off the downloader's arguments and request line, not typed |
| `derived_sha256` | string | the SHA-256 of the downloader it came from, the `sha256` of its `echo_loader` capture |

The event counts against the connection's download allowance like any other
(`crates/sensor-framework/src/shell/loader.rs#FakeShell::flush_loader`).

A shell `honeypot_file_download` otherwise carries `url` (the address a fetch the line executed
named, after expansion) or, when that address could not be read or still held an unexpanded
variable, `command` (the fetch as written) and no `url`. Text that only contains a fetch, such as
an `echo` writing a script, emits none
(`crates/sensor-framework/src/shell/fetch.rs#FakeShell::append_downloads`).

#### Command summary keys

A shell command event (ssh, telnet, adb) over its source network's command-event budget is not
written; it is counted into one `honeypot_command_exec` per source network per 60 s window,
marked `command_summary: true` (`crates/sensor-framework/src/command_flood.rs#command_summary_event`;
when and why in [sensor-behavior](sensor-behavior.md#command-event-budget-ssh-telnet-adb)). Its
`source_ip`, `wan_ip`, `sensor` and `authenticated` are those of the first suppressed event, its
protocol is `tcp`, and its `session_id` is fresh: the commands came from several sessions, none
of which it belongs to. `command` is a readable line for the timeline, `<N repeated commands from
<prefix> summarized; the first of each command shape is logged in full>`.

| key | type | meaning |
|---|---|---|
| `command_summary` | boolean | always `true`; marks the event as a summary |
| `source_prefix` | string | the source network in CIDR form (`198.51.100.0/24`), or `overflow` for networks that arrived while the summary table was full |
| `suppressed_count` | integer | command events this summary stands for |
| `distinct_commands` | integer | distinct command shapes among them (escapes, hex and base64 runs taken out, `crates/sensor-framework/src/command_flood.rs#command_shape`), so all of a loader's echo chunks count once |
| `distinct_commands_capped` | boolean | more shapes arrived than the window could tell apart (always `true` for `overflow`) |
| `samples` | array of strings | one suppressed command per shape, up to 8, sanitized, at most 256 characters each |
| `first_seen`, `last_seen` | string | RFC 3339 times of the first and last suppressed command |
| `window_secs` | number | the window length, 60 |
| `session_count` | integer | distinct sessions the suppressed commands came from, at most 32 |
| `session_count_capped` | boolean | more sessions than that |
| `assembled_file` | string | when an echo-loader chunk was suppressed: the file of the highest suppressed chunk |
| `max_chunk_index` | integer | that chunk's `chunk_index` |

Scoring treats a summary as one `honeypot_command_exec` from its `source_ip`; `suppressed_count`
is data for the analyst, not a weight. The merit path loses nothing: a same-signal event from
one address within 60 s of the previous one adds no weight anyway (`DEDUP_WINDOW_SECONDS`, see
[scoring-and-feed](scoring-and-feed.md)), and every address that runs a command other than an
echo-loader chunk keeps its own first command event of each window, so its weight and its 0.950
confidence still arrive. The volume path does slow, since it counts established events: past its
budget a source adds about 12 command events a minute plus its first sightings, on top of its
connections, logins, downloads and captures, which are never summarized
([rate limits](rate-limits-and-budgets.md#shell-command-event-budget-ssh-telnet-adb)). For the
observed loop that is roughly 60 established events a minute instead of about 450, so it reaches
the 1000-event threshold in about a quarter of an hour instead of a few minutes [inferred:
arithmetic from the observed loop, not a measured scoring run].

### Arrival metadata key

Every event a sensor emits carries the local port of the listener its connection or datagram
arrived on. It is ordinary metadata, not a wire-format field, so no schema or wire version changed;
a JSON integer survives the `JSONB` round trip the hash chain re-reads (see
[database.md](database.md)).

| key | type | meaning |
|---|---|---|
| `local_port` | integer | The accepted TCP socket's local port, or the bound UDP socket's port. Written by `EventEmitter::append` from the listener the emitting task serves (`crates/sensor-framework/src/arrival.rs#scope`, `crates/sensor-framework/src/emit.rs#append`), never by a sensor: `run_tcp_listener`, `run_tls_listener` and `run_udp_listener` set it for every handler. An upload carries the port of the connection that submitted it (`crates/sensor-framework/src/handoff.rs#submit`). sensor-dns stamps its UDP port on query and `rate_limited` summary events, and sensor-tftp stamps the request socket's port (69 in a deployment) on every event of a request, its upload included, though the transfer itself runs on an ephemeral port, and on its `rate_limited` summaries from the summary task and the shutdown flush (`crates/sensor-tftp/src/lib.rs#flush_rate_limited`). |

The transport is `protocol` (`tcp` or `udp`), not a metadata key. The pair (`protocol`,
`local_port`) names one listener: the catch-all's TCP and UDP listeners on the same port number
are told apart only by `protocol`. Events written before this key existed have no `local_port`;
how the fleet pane attributes them is in
[health and observability](../operations/health-and-observability.md#fleet-pane-listener-activity).
Every sensor crate's `tests/arrival.rs` drives its real listeners and checks the key, and
`crates/sensor-framework/tests/arrival_coverage.rs#every_sensor_crate_tests_its_arrival_stamp`
fails when a workspace sensor crate has no such test.

### TLS metadata keys

Events from the seven TLS sensors (http, redis, mqtt, smtp, ftp, cred, dns) carry these keys in
`metadata`. They are ordinary metadata, not wire-format fields.

| key | type | meaning |
|---|---|---|
| `tls` | bool | Present, and always `true`, only on events of a TLS session. It is **absent** on plaintext events, never `false`, so a consumer tests for the key, not its value (`crates/sensor-smtp/src/handler.rs#tag_tls`, `crates/sensor-ftp/src/handler.rs#tag_tls`, `crates/sensor-mqtt/src/handler.rs#stamp_tls`, `crates/sensor-cred/src/lib.rs#with_tls`, `crates/sensor-dns/src/events.rs#stamp_tls`; http and redis set it inline in their handlers). |
| `starttls_refused` | string | Only on the refusal event described below; always `"pipelined_plaintext"` today. |
| `pipelined_bytes` | integer | Only on the refusal event: how many plaintext bytes the client sent behind the upgrade command. The bytes themselves are never captured. |

Scope of the `tls` tag: for sensor-smtp and sensor-ftp it covers a session upgraded by `STARTTLS`
or `AUTH TLS` from the upgrade on (earlier events stay untagged, and the ftp tag describes the
control channel only); for sensor-cred's PostgreSQL, MySQL and MSSQL the connection event is
written before negotiation and stays untagged, while every MongoDB event of a TLS session is
tagged. Per-sensor details are in [sensor-behavior.md](sensor-behavior.md) and
[networking-tls.md](../operations/networking-tls.md#tls-surfaces).

**Protocol refusal events.** `starttls_refused` and `pipelined_bytes` appear on one
`honeypot_command_exec` event that sensor-smtp (`command` `STARTTLS`) and sensor-ftp (`command`
`AUTH`) write when a client pipelined plaintext behind the upgrade command. The upgrade is
refused and the connection closed. The event belongs to the plaintext phase, so it carries no
`tls` key (`crates/sensor-smtp/src/handler.rs#starttls_refused_event`,
`crates/sensor-ftp/src/handler.rs#auth_refused_event`). Its `authenticated` is `false` for smtp and
the session's login state for ftp.

**`honeypot_command_exec` is not only shell commands.** Across the sensors it records protocol
commands too: sensor-smtp's `DATA` and its `STARTTLS` refusal, sensor-ftp's `AUTH` refusal, MQTT
`SUBSCRIBE`, `PUBLISH` and `AUTH`, Redis and HTTP requests, and DNS queries over TCP and DoT,
alongside the shell lines of the SSH, telnet and ADB sensors. Its weight and category are the
same whichever produced it.

**DNS probe signals are metadata.** sensor-dns classifies each parsed query into zero or more of
`amplification_probe`, `open_resolver_probe`, `zone_transfer_probe` and
`chaos_fingerprint_probe`, recorded in the `probe_signals` metadata array
(`crates/sensor-dns/src/events.rs#probe_signals`). They are never `signal_type` values and carry
no weight of their own: a UDP query is a `honeypot_connection` and a TCP or DoT query a
`honeypot_command_exec`, whatever its probe signals. The rules are in
[sensor-behavior.md](sensor-behavior.md#sensor-dns).

### Metadata the campaign indexer reads

The [campaign indexer](../operations/campaigns.md) reads these persisted keys and nothing else:
`command` on `honeypot_command_exec` (skipped when `flood` or `command_summary` is present),
`sample_sha256` and `sample_orig_name` on `honeypot_malware_upload` (folded in by intake from the
SampleRef), `capture_reason`, and `url` on `honeypot_file_download`. It groups command events by
`session_id`, so a sensor that sends none produces no command-sequence campaigns
(`crates/review/src/campaign/mod.rs#command_of`). `honeypot_session_end` is telemetry and is
skipped by every rule. The [ATT&CK tag rules](attack-tagging.md) read the same keys, plus the
event's `sensor` and `signal_type`; the `command_decoded` text replaces `command` when present.

## Signal types

17 signal types (`signal_type_enum`, mirrored by Rust `SignalType`). Sixteen of them
accuse an address and carry weight; the seventeenth, `honeypot_session_end`, is
**telemetry** and never moves a score - see below. The enum
definition and its DB type are owned by
[database.md](database.md#enum-types); this page owns their meaning and weight.

The `meaning` column below is **[inferred]** from each identifier and its weight -
only `weight`, `confidence`, and `category` are directly evidenced in code. Which
sensor actually emits a given signal is not asserted here.

## Signal weight table

`signal_weight(SignalType) -> { weight: u32, confidence: Decimal, category: Category }`
is the single source of truth (`crates/core-scoring/src/domain/weights.rs#signal_weight`).
`EventInput::from_signal` derives `weight`/`confidence`/`category` from it
(`crates/core-scoring/src/domain/types.rs#from_signal`), so these three values are never computed by a sensor. `confidence`
is stored as `NUMERIC(4,3)` in `event`.

| signal_type | weight | confidence | category | meaning [inferred] |
|---|---|---|---|---|
| `honeypot_connection` | 40 | 0.900 | honeypot | TCP connection established to a honeypot service, or a UDP probe (tftp request, dns query) |
| `honeypot_login_attempt` | 50 | 0.920 | honeypot | credential submitted to a fake service |
| `honeypot_command_exec` | 60 | 0.950 | honeypot | command run in the fake shell, or a protocol command (smtp DATA, the STARTTLS and AUTH TLS refusals, MQTT SUBSCRIBE and PUBLISH) |
| `honeypot_malware_upload` | 80 | 0.980 | honeypot | file uploaded to a honeypot (highest weight/confidence) |
| `honeypot_file_download` | 70 | 0.960 | honeypot | attacker pulled a file / fetched a payload |
| `suricata_sev1` | 30 | 0.700 | ids | Suricata alert, severity 1 |
| `suricata_sev2` | 15 | 0.500 | ids | Suricata alert, severity 2 |
| `suricata_sev3` | 5 | 0.300 | ids | Suricata alert, severity 3 (lowest IDS) |
| `port_scan` | 20 | 0.600 | network | port scan detected |
| `syn_flood` | 25 | 0.700 | network | SYN flood detected |
| `blocked_connection` | 3 | 0.150 | network | firewall-blocked connection (lowest weight overall) |
| `waf_sqli_xss` | 35 | 0.850 | waf | WAF SQLi/XSS block |
| `waf_generic_block` | 15 | 0.500 | waf | WAF generic block |
| `ssh_brute_force` | 20 | 0.600 | auth | SSH brute-force |
| `catchall_probe` | 15 | 0.400 | network | probe hit the catch-all listener |
| `remote_auth_failure` | 12 | 0.400 | auth | remote auth failure (corroborating sensor) |
| `honeypot_session_end` | 0 | 0.000 | honeypot | **telemetry**: how one interaction ended |

### Telemetry signals never score

`honeypot_session_end` records what happened to an exchange - why it ended, how long it
ran, what the attacker was told. It is evidence about the interaction, so it is written
to the same hash-chained ledger, but it is not an accusation and must not move a score.

A zero weight alone would not achieve that. The append path derives an address's
distinct-sensor count and per-WAN vantages from **every** ledger row for that source, so
a zero-weight row would still have widened the breadth inputs of the *next* real event,
and `rebuild_projection` would have folded it too. Four things enforce the separation,
keyed on the explicit `SignalType::TELEMETRY` list rather than on the weight number:

- `append_event` refuses a telemetry signal (`RepoError::NotScorable`);
- `append_telemetry_event` is the only way one reaches the ledger, and it writes no
  projection at all, so an address seen only through telemetry has no `ip_score` row;
- the incremental breadth and distinct-sensor aggregates exclude these rows;
- `rebuild_projection` excludes them identically, so replay still equals the incremental
  projection.

`verify_chain` still reads them: a telemetry record is part of the chain, just not part
of a score. Tests in `crates/core-scoring/tests/telemetry.rs` compare
attack -> telemetry -> attack against attack -> attack field by field, through both the
incremental path and a rebuild.

Coverage is guarded by `every_signal_type_has_exactly_one_weight_row` (`crates/core-scoring/src/domain/weights.rs#every_signal_type_has_exactly_one_weight_row`),
which has no default match arm, so a new variant that lacks a row fails to compile.

### Confirmed-real predicate

`is_confirmed_real(p, authenticated, c) = p==Tcp && authenticated && c==Honeypot`
(`crates/core-scoring/src/domain/enums.rs#is_confirmed_real`). Only an authenticated TCP honeypot event latches
`ip_score.has_confirmed_real`; the weight and confidence above do not by themselves
set it.

### How these values become a persisted event

The wire record carries the raw facts; `EventInput::from_signal` looks up the row
above to attach `weight`, `confidence`, and `category`; the result is hashed into the
[append-only ledger](database.md#table-event-append-only-ledger) via the
[hash chain](database.md#hash-chain-cratescore-scoringsrchashingrs). The `signal_type`
and `protocol` strings are serialized into the hash at the bare-Rust-identifier casing,
which is why the wire strings are Deserialize-only aliases - see the
[serde casing note](database.md#serde-casing-asymmetry-hash-chain-critical).
