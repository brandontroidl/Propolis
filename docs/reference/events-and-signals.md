<!--
title: Events and signals reference
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Events and signals reference

Canonical owner of the sensor-to-intake wire format, the sample side-channel
reference, the signal types and their meanings, and the signal weight table. The
persisted schema those events land in is owned by [database.md](database.md); scoring
math is owned by [scoring-and-feed.md](scoring-and-feed.md).

## SensorEvent wire format (`crates/sensor-wire/src/lib.rs`)

A frozen NDJSON record - one line per event, no embedded `\n` or `\r` (test
`ndjson_single_line`, `lib.rs:94`). A single definition is shared by every sensor
(producer) and by intake (consumer), so the wire shape has one source of truth.
`WIRE_VERSION = 1` (`lib.rs:12`), `VERSION_MARKER = "sensor-wire"` (`lib.rs:11`).

`SensorEvent` struct (`lib.rs:36-53`), 11 fields:

| field | type | notes |
|---|---|---|
| `v` | u32 | wire version (`WIRE_VERSION`, currently 1) |
| `source_ip` | IpAddr | attacker source |
| `wan_ip` | Option\<IpAddr\> | serializes as `"wan_ip":null` when None (test `null_wan_ip_serializes`, `lib.rs:117`) |
| `sensor` | String | sensor name |
| `signal_type` | String | plain string, **not** the enum - keeps sensor-wire free of a core-scoring dependency; intake validates it against the known set (`lib.rs:33-35`) |
| `protocol` | String | plain string, same rationale |
| `authenticated` | bool | |
| `observed_at` | DateTime\<Utc\> | RFC 3339 via chrono's default serde - **must** match `hashing.rs`; switching to `ts_microseconds` (integer timestamp) would break the hash chain (`lib.rs:45-48`) |
| `metadata` | serde_json::Value | free-form per-signal detail |
| `sample` | Option\<SampleRef\> | side-channel file reference (see below) |
| `session_id` | Option\<Uuid\> | `#[serde(default, skip_serializing_if = "Option::is_none")]` - omitted from JSON when None; older records without the key still deserialize (test `deserialize_without_session_id`, `lib.rs:134`) |

A sensor emits raw facts only. `weight`, `confidence`, and `category` are **not** on
the wire - they are derived downstream by `EventInput::from_signal` from the [signal
weight table](#signal-weight-table), so a sensor never computes them.

`signal_type` and `protocol` are plain strings so the crate needs no dependency on
core-scoring or its database layer. The wire values match core-scoring's serde
Deserialize casing exactly; see the [serde casing note](database.md#serde-casing-asymmetry-hash-chain-critical).
Sensor-emittable constants are provided so literals are not hand-typed:

- Signal (`lib.rs:17-22`), the subset a sensor can emit: `catchall_probe`,
  `honeypot_connection`, `honeypot_login_attempt`, `honeypot_command_exec`,
  `honeypot_malware_upload`, `honeypot_file_download`. The remaining signal types
  (Suricata, WAF, port scan, and so on) originate from other layers, not sensor-wire.
- Protocol (`lib.rs:25-27`): `tcp`, `udp`, `icmp`.

### SampleRef (`lib.rs:59-63`)

A reference to a captured file body written to the quarantine spool, named by its
SHA-256. The body travels out-of-band (the spool); only this reference rides the wire.

| field | type | notes |
|---|---|---|
| `sha256` | String | content hash; the spool filename |
| `size` | u64 | body size in bytes |
| `orig_name` | String | attacker-controlled; carried as a **sanitized indicator only**, never used as a path component (`lib.rs:56-57`) |

The `sha256` here is the key into [`sample_analysis`](database.md#table-sample_analysis-0009_sample_analysissql).

Body-capturing sensors cap what they retain (10 MB for SCP, SFTP, ADB and FTP
STOR; `PROPOLIS_TELNET_MAX_CAPTURED_BYTES` for a telnet binary-payload capture)
and drain the rest to keep the protocol aligned. Their `honeypot_malware_upload`
metadata therefore also carries `wire_size` (bytes the client actually sent) and
`truncated` (`wire_size > size`), built by `sensor_framework::upload_metadata`.
When `truncated` is true the `sha256` and `size` describe a prefix, not the file;
the IP detail page shows such rows with status `truncated` instead of `captured`.
FTP drains at most a further 10 MB past its cap before closing the data
connection, so a `wire_size` of 20 MB on an FTP row is a floor, not the total.

## Signal types

16 signal types (`signal_type_enum`, mirrored by Rust `SignalType`). The enum
definition and its DB type are owned by
[database.md](database.md#enum-types); this page owns their meaning and weight.

The `meaning` column below is **[inferred]** from each identifier and its weight -
only `weight`, `confidence`, and `category` are directly evidenced in code. Which
sensor actually emits a given signal is not asserted here.

## Signal weight table

`signal_weight(SignalType) -> { weight: u32, confidence: Decimal, category: Category }`
is the single source of truth (`crates/core-scoring/src/domain/weights.rs:11-37`).
`EventInput::from_signal` derives `weight`/`confidence`/`category` from it
(`types.rs:26-55`), so these three values are never computed by a sensor. `confidence`
is stored as `NUMERIC(4,3)` in `event`.

| signal_type | weight | confidence | category | meaning [inferred] |
|---|---|---|---|---|
| `honeypot_connection` | 40 | 0.900 | honeypot | TCP connection established to a honeypot service |
| `honeypot_login_attempt` | 50 | 0.920 | honeypot | credential submitted to a fake service |
| `honeypot_command_exec` | 60 | 0.950 | honeypot | command run in the fake shell |
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

Coverage is guarded by `every_signal_type_has_exactly_one_weight_row` (`weights.rs:44`),
which has no default match arm, so a new variant that lacks a row fails to compile.

### Confirmed-real predicate

`is_confirmed_real(p, authenticated, c) = p==Tcp && authenticated && c==Honeypot`
(`enums.rs:115-117`). Only an authenticated TCP honeypot event latches
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
