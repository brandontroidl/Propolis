<!--
title: Rate limits and budgets reference
audience: all
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Rate limits and budgets reference

Every rate limit, budget, cap, and bound across the platform, with exact values
and where each is enforced. Values marked *(hard-coded)* are fixed in source and
not operator-configurable; values with an env var are configurable and their
defaults/bounds are owned by
[environment-variables.md](environment-variables.md).

## Console login rate limit

Sliding-window limiter keyed by source IP plus a budget across all sources,
enforced in the console auth layer (`RateLimiter` in `crates/console/src/auth.rs`,
applied first in `login_submit`, `crates/console/src/routes/login.rs`).

| Item | Value | Notes |
|---|---|---|
| Max attempts per source IP | 5 per 60 s *(hard-coded default)* | `RateLimiter::default` |
| Max attempts across all sources | 30 per 60 s *(hard-coded default)* | `DEFAULT_GLOBAL_LOGIN_ATTEMPTS`; bounds guessing spread over many addresses |
| Reset | per-IP window on successful login; the global window is never reset | `login_submit` |
| Blocked-attempt accounting | a rejected attempt is recorded in neither window | cannot extend either window |
| Map cleanup trigger | > 10000 tracked IPs | prunes expired entries |
| Hard reject ceiling | > 50000 tracked IPs -> all attempts denied | backstop; new entries are already limited by the global budget |
| Concurrent password verifications | 2, on the blocking pool | `MAX_CONCURRENT_VERIFICATIONS`; an attempt waits up to 5 s for a slot, then `503` |

The limiter keys on the TCP peer address. Behind a same-host reverse proxy every
attempt arrives from the proxy's address, so the per-IP limit then acts as a second
global limit; the proxy should apply its own per-client limit.

## Console connection bounds

Enforced by the console's accept loop (`console::server::ServeLimits::default`,
`crates/console/src/server.rs`), in both the standalone console and the unified daemon.

| Item | Value | On breach |
|---|---|---|
| Open connections | 64 | a new connection is closed on accept (`propolis_console_connections_shed_total`) |
| Header read | 10 s per request, re-armed while a kept-alive connection waits | connection closed |
| Body read | 10 s | `408` (`propolis_console_body_timeouts_total`) |
| Body size | 2 MiB | `413` |
| Shutdown grace | 10 s for open connections to finish | remaining connections dropped |

## UDP reply rate limit (sensor-dns, sensor-tftp)

A UDP source address can be forged, so every reply `sensor-dns` or `sensor-tftp` sends over UDP
can be aimed at a victim. Each reply is already no larger than what the peer sent; this bounds
how many there are. Each sensor has its own token buckets keyed on the source network plus one
global bucket (`crates/sensor-framework/src/rate_limit.rs#ReplyRateLimiter`, wired in
`crates/sensor-dns/src/udp.rs#serve` and `crates/sensor-tftp/src/lib.rs#serve`). Behavior and
the summary events are owned by [sensor-behavior.md](sensor-behavior.md#sensor-dns) and
[sensor-behavior.md](sensor-behavior.md#sensor-tftp).

| Item | Value | Source |
|---|---|---|
| Per source network | 5 per s, burst 10 | `PROPOLIS_DNS_REPLY_RATE_PER_SOURCE`, `PROPOLIS_DNS_REPLY_BURST_PER_SOURCE`; `PROPOLIS_TFTP_REPLY_RATE_PER_SOURCE`, `PROPOLIS_TFTP_REPLY_BURST_PER_SOURCE` |
| Global | 1000 per s, burst 2000 | `PROPOLIS_DNS_REPLY_RATE_GLOBAL`, `PROPOLIS_DNS_REPLY_BURST_GLOBAL`; `PROPOLIS_TFTP_REPLY_RATE_GLOBAL`, `PROPOLIS_TFTP_REPLY_BURST_GLOBAL` |
| Source network | IPv4 /24 (IPv4-mapped IPv6 included), IPv6 /56 *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#SourceKey` |
| Networks tracked | 4096, allocated once; a full table evicts the least recently seen of 4 sampled entries *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#DEFAULT_RATE_TABLE_CAPACITY` |
| Over budget | no reply, no per-datagram event; counted in a summary | `crates/sensor-framework/src/rate_limit.rs#FloodLedger` |
| Summary window | one `rate_limited` event per network per 10 s *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#DEFAULT_SUMMARY_WINDOW` |
| Summaries held | 1024 networks, then one overflow summary; 8 samples and 32 distinct sources each *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#DEFAULT_SUMMARY_CAPACITY`, `crates/sensor-framework/src/rate_limit.rs#MAX_SUMMARY_SAMPLES`, `crates/sensor-framework/src/rate_limit.rs#MAX_SUMMARY_SOURCES` |
| Shutdown flush | pending summaries written within 2 s *(hard-coded)* | `crates/sensor-dns/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT`, `crates/sensor-tftp/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT` |

`sensor-dns` charges every UDP datagram of at least a 12-byte header, including ones that are
rejected or suppressed rather than answered, because each would otherwise cost an event.
`sensor-tftp` charges every datagram on its request socket before parsing it, malformed ones
included; the DATA and ACK packets of a running transfer arrive on that transfer's own socket and
are not charged. A zero or non-numeric rate aborts startup; no value turns the limit off. DNS
over TCP and DoT is not rate limited (its per-connection bounds are in
[sensor-behavior.md](sensor-behavior.md#sensor-dns)).

## Shell command-event budget (ssh, telnet, adb)

Bounds how many `honeypot_command_exec` events one source network writes, not what the shell
does: every command is answered the same, and the events over the budget are counted into one
summary per network per window. One budget per sensor process
(`crates/sensor-framework/src/command_flood.rs#CommandEventGate`). Behavior, what is never
summarized and why are owned by
[sensor-behavior.md](sensor-behavior.md#command-event-budget-ssh-telnet-adb); the summary's keys
by [events-and-signals.md](events-and-signals.md#command-summary-keys).

| Item | Value | Source |
|---|---|---|
| Per source network | 2 per s, burst 200 | `PROPOLIS_SSH_COMMAND_EVENT_RATE`, `PROPOLIS_SSH_COMMAND_EVENT_BURST`; `PROPOLIS_TELNET_COMMAND_EVENT_RATE`, `PROPOLIS_TELNET_COMMAND_EVENT_BURST`; `PROPOLIS_ADB_COMMAND_EVENT_RATE`, `PROPOLIS_ADB_COMMAND_EVENT_BURST` |
| Global | none: only the per-network bucket refuses *(hard-coded)* | `crates/sensor-framework/src/command_flood.rs#CommandEventGate::new` |
| Source network | IPv4 /24 (IPv4-mapped IPv6 included), IPv6 /56 *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#SourceKey` |
| Networks tracked (buckets) | 4096, with eviction *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#DEFAULT_RATE_TABLE_CAPACITY` |
| Summary window | 60 s per network, checked each second *(hard-coded)* | `crates/sensor-framework/src/command_flood.rs#COMMAND_SUMMARY_WINDOW` |
| Always written per window | each distinct command's first sighting (128 tracked) and each address's first command event (64 tracked) *(hard-coded)* | `crates/sensor-framework/src/command_flood.rs#MAX_TRACKED_COMMANDS`, `crates/sensor-framework/src/command_flood.rs#MAX_TRACKED_ADDRESSES` |
| Summaries held | 1024 networks, then one overflow summary; 8 samples of 256 bytes and 32 sessions each *(hard-coded)* | `crates/sensor-framework/src/rate_limit.rs#DEFAULT_SUMMARY_CAPACITY`, `crates/sensor-framework/src/command_flood.rs#MAX_COMMAND_SAMPLE_LEN`, `crates/sensor-framework/src/command_flood.rs#MAX_SUMMARY_SESSIONS` |
| Shutdown flush | pending summaries written within 2 s *(hard-coded)* | `crates/sensor-telnet/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT`, `crates/sensor-ssh/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT`, `crates/sensor-adb/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT` |

The per-connection cap of 256 command events
(`crates/sensor-framework/src/shell/mod.rs#MAX_COMMANDS_PER_SESSION`) still applies first; this
budget is what a source spreading its commands over many sessions meets. A zero or non-numeric
rate or burst aborts startup; no value turns the budget off.

## VirusTotal daily cap

Enforced by a single `DailyBudget` owned across every scan cycle
(`crates/review/src/virustotal.rs#DailyBudget`;
`crates/propolis/src/main.rs#main`).
A per-cycle counter would reset each cycle and never enforce a per-day cap.

| Item | Value | Source |
|---|---|---|
| Daily cap | 450 requests / UTC day *(hard-coded)* | `crates/propolis/src/main.rs#main` |
| Request delay | 15000 ms before each lookup and before each upload *(hard-coded)* | `crates/propolis/src/main.rs#main`, applied in `virustotal.rs::scan_spool` |
| Upload cost | one budget unit per upload, in addition to the lookup that preceded it | `virustotal.rs::scan_spool` (`NextStep::Upload`) |
| Pending recheck | 900 s default before an uploaded, unverdicted sample is looked up again; one budget unit per recheck; never re-uploaded | `PROPOLIS_VT_PENDING_RECHECK_SECS`, `virustotal.rs::needs_lookup` |
| Scan interval | 300 s default | `PROPOLIS_VT_SCAN_INTERVAL_SECS` (`crates/propolis/src/config.rs#load_config`) |
| Documented VT free-tier limit | 4 req/min, 500/day | reference only, verified live 2026-08-19 (`crates/review/src/virustotal.rs`) |

`try_consume` resets `used = 0` when the UTC date rolls over, else refuses
(returns false) once `used >= limit`. Gating detail in
[integrations.md](integrations.md#virustotal-filehash-scanning).

## Vendor submission gatekeeper

Ordered, fail-closed per-vendor check sequence run at submission time, after
operator approval; short-circuits on the first hold
(`crates/review/src/gatekeeper.rs#check`).

| # | Check | Rule | Default |
|---|---|---|---|
| 1 | Reserved | `is_reserved_ip(ip)` (first, not overridable) | always on |
| 2 | Disabled | `!config.enabled` | vendor off unless enabled + non-empty key |
| 3 | Stale | last activity older than freshness window | 48 h *(hard-coded, vendor-agnostic)* (`crates/review/src/gatekeeper.rs#FRESHNESS_WINDOW_HOURS`) |
| 4 | Cooldown | prior SUCCESSFUL submit for this (ip, vendor) within `cooldown_hours` | 24 h |
| 5 | RateLimit | vendor-WIDE successful submits within `rate_window_hours` `>= rate_limit` | 100 per 1 h |
| 6 | ScoreFloor | `current_score.raw_score < floor` | `None` (no extra floor) |
| 7 | CategoryFilter | no breakdown key matches configured filter | `None` (any category) |

Runtime defaults for both the `review` binary and `propolis`:
`cooldown_hours = 24`, `rate_limit = 100`, `rate_window_hours = 1`
(`crates/review/src/main.rs#DEFAULT_COOLDOWN_HOURS`/`crates/review/src/main.rs#DEFAULT_RATE_LIMIT`/`crates/review/src/main.rs#DEFAULT_RATE_WINDOW_HOURS`,
`crates/propolis/src/config.rs#DEFAULT_COOLDOWN_HOURS`/`crates/propolis/src/config.rs#DEFAULT_RATE_LIMIT`/`crates/propolis/src/config.rs#DEFAULT_RATE_WINDOW_HOURS`).
`score_floor` and `category_filter` are `None` in the shipped config loaders
(`crates/review/src/main.rs#load_vendor_config`, `crates/propolis/src/config.rs#load_vendor_config`). A database error on the cooldown or rate-limit query holds
the submission (`DbError`), fail-closed (`crates/review/src/gatekeeper.rs#check_cooldown`/`crates/review/src/gatekeeper.rs#check_rate_limit`). Per-vendor
overrides:
`PROPOLIS_VENDOR_<NAME>_{ENABLED,COOLDOWN_HOURS,RATE_LIMIT,RATE_WINDOW_HOURS,KEY,URL}`
(plus `PROPOLIS_VENDOR_DSHIELD_USER`) - see
[environment-variables.md](environment-variables.md).

## Malware fetcher budgets and bounds

The fetcher is opt-in (`PROPOLIS_FETCH_ENABLED`, default false) and off by
default (`fetch_enabled` parse, `crates/propolis/src/config.rs#load_config`). Its egress is bounded at several
layers.

### Per-cycle and per-host

| Item | Value | Env var / source |
|---|---|---|
| In-flight concurrency | 8 per cycle *(hard-coded semaphore)* | `CONCURRENCY` (`crates/review/src/fetcher/mod.rs#CONCURRENCY`/`crates/review/src/fetcher/mod.rs#run_cycle_with`) |
| Max attempts per URL | 3, then terminal `Dead` *(hard-coded)* | `MAX_ATTEMPTS` (`crates/review/src/fetcher/mod.rs#MAX_ATTEMPTS`/`crates/review/src/fetcher/mod.rs#record_failure`) |
| Retry backoff | `5 * 4^(attempts-1)` min after the first and second failures (5, then 20); the third failure is terminal, so no longer delay is ever scheduled *(hard-coded)* | `backoff_delay` (`crates/review/src/fetcher/mod.rs#backoff_delay`) |
| Per-host hourly budget | default 12, max 1000 | `PROPOLIS_FETCH_MAX_PER_HOST_HOUR` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_PER_HOST_HOUR`/`crates/propolis/src/config.rs#MAX_FETCH_MAX_PER_HOST_HOUR`) |
| Daily cap | default 200, max 10000 | `PROPOLIS_FETCH_DAILY_CAP` (`crates/propolis/src/config.rs#DEFAULT_FETCH_DAILY_CAP`/`crates/propolis/src/config.rs#MAX_FETCH_DAILY_CAP`) |
| Batch size per cycle | default 20, max 1000 | `PROPOLIS_FETCH_BATCH_SIZE` (`crates/propolis/src/config.rs#DEFAULT_FETCH_BATCH_SIZE`/`crates/propolis/src/config.rs#MAX_FETCH_BATCH_SIZE`) |
| Cycle interval | default 10 s, max 86400 s | `PROPOLIS_FETCH_INTERVAL_SECS` (`crates/propolis/src/config.rs#DEFAULT_FETCH_INTERVAL_SECS`/`crates/propolis/src/config.rs#MAX_FETCH_INTERVAL_SECS`) |

The per-host and daily budgets live in PostgreSQL, not in process memory, so
they survive a restart and hold across every node sharing the database. Each
cycle claims its rows in one transaction (`store::claim_candidates`): it locks
today's `fetch_daily_usage` row (serializing claims across nodes), selects
eligible rows that no other cycle has claimed (`FOR UPDATE SKIP LOCKED`),
counts each host's completed attempts in the trailing hour plus its rows
currently claimed by any node, sets `claim_expires` on the rows it takes, and
charges the daily cap exactly that many. A cycle that claims nothing costs the
daily cap nothing. A claim is released when the outcome is recorded; a node
that dies mid-fetch leaves its claims to lapse after a lease sized to the
slowest possible cycle (every redirect hop at its full DNS and total timeout,
per wave of 8). A DB error fails the whole claim - nothing is fetched that
cycle (fail-closed). Each candidate is isolated behind `catch_unwind`, so one
panic never aborts the batch.

### Size and timeout caps

| Item | Value | Env var / source |
|---|---|---|
| Max body bytes | default 10 MB (10000000), max 500 MB | `PROPOLIS_FETCH_MAX_BYTES` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_BYTES`/`crates/propolis/src/config.rs#MAX_FETCH_MAX_BYTES`) |
| Redirect hops followed | default 3 | `PROPOLIS_FETCH_MAX_HOPS` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_HOPS`) |
| Recursion depth | default 2 | `PROPOLIS_FETCH_MAX_DEPTH` (`crates/propolis/src/config.rs#DEFAULT_FETCH_MAX_DEPTH`) |
| Connect timeout | default 10 s | `PROPOLIS_FETCH_CONNECT_TIMEOUT_SECS` (`crates/propolis/src/config.rs#DEFAULT_FETCH_CONNECT_TIMEOUT_SECS`) |
| Read timeout | default 10 s | `PROPOLIS_FETCH_READ_TIMEOUT_SECS` (`crates/propolis/src/config.rs#DEFAULT_FETCH_READ_TIMEOUT_SECS`) |
| Total timeout | default 30 s, max 300 s | `PROPOLIS_FETCH_TOTAL_TIMEOUT_SECS` (`crates/propolis/src/config.rs#DEFAULT_FETCH_TOTAL_TIMEOUT_SECS`/`crates/propolis/src/config.rs#MAX_FETCH_TIMEOUT_SECS`) |

The byte cap is enforced mid-stream: the transfer aborts to `TooBig` as soon as
`body.len() + chunk.len() > max_bytes`, never buffering the whole oversized body
(`fetch_once_inner` in `crates/review/src/fetcher/http.rs`).

The total timeout bounds a whole hop, not one connection. When an https
certificate fails validation, the second attempt without validation (see
[malware custody](../security/malware-custody.md#transport-authentication-of-fetched-samples))
spends what is left of the same timeout, so the retry never lengthens a hop
(`Hop` in `crates/review/src/fetcher/http.rs`).

### Dropper-script URL extraction

Amplification defenses on recursive URL extraction
(`crates/review/src/fetcher/extract.rs`):

A body in Microsoft Script Encoder form (`.vbe`/`.jse`, the `#@~^ ... ==^#~@`
envelope) is decoded before scanning (`crates/review/src/fetcher/vbe.rs`).
The encoding is a fixed positional substitution, not encryption; a captured
dropper used it to hide an ordinary `strFileURL = "http://..."` assignment,
which the extractor could not see until decoded. Unencoded bodies pass through
unchanged. No other encoding (base64, UTF-16) is decoded.

| Item | Value | Source |
|---|---|---|
| Max body scanned | 64 KiB *(hard-coded)* | `MAX_BODY_LEN` (`crates/review/src/fetcher/extract.rs#MAX_BODY_LEN`) |
| Max URLs emitted | 256 *(hard-coded)* | `MAX_URLS` (`crates/review/src/fetcher/extract.rs#MAX_URLS`) |
| Variable-resolution passes | 8 *(hard-coded)* | `MAX_RESOLVE_PASSES` (`crates/review/src/fetcher/extract.rs#MAX_RESOLVE_PASSES`) |

### TFTP fetch

`crates/review/src/fetcher/tftp.rs#BLOCK_SIZE`/`crates/review/src/fetcher/tftp.rs#PER_BLOCK_TIMEOUT`/`crates/review/src/fetcher/tftp.rs#MAX_RETRIES`: block size 512 bytes, per-block
timeout 2 s, max retries 5 per wait, whole transfer wrapped in the fetcher's
total timeout (hard outer cap). All *(hard-coded)*.

## Pipeline loop intervals

Daemon loop cadences (not egress-producing on their own):

| Loop | Interval | Env var / source |
|---|---|---|
| Review queue populate/withdraw | default 60 s | `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS` (`crates/review/src/main.rs#DEFAULT_QUEUE_SCAN_INTERVAL_SECS`) |
| Submission poll (`run_once`) | default 30 s | `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS` (`crates/review/src/main.rs#DEFAULT_SUBMIT_POLL_INTERVAL_SECS`) |
| VirusTotal scan | default 300 s | `PROPOLIS_VT_SCAN_INTERVAL_SECS` |
| Feed build | 900 s (15 min) | `PROPOLIS_FEED_BUILD_INTERVAL_SECS` |
| Fetcher cycle | default 10 s | `PROPOLIS_FETCH_INTERVAL_SECS` |

A zero interval is rejected for the review loops (would busy-loop)
(`crates/review/src/main.rs#parse_positive_u64`).

## Spool cleanup

| Item | Value | Source |
|---|---|---|
| Sample spool max age | 30 days, checked hourly by the `sample-retention` task regardless of whether VirusTotal is enabled *(hard-coded)* | `SAMPLE_RETENTION_DAYS` (`crates/propolis/src/main.rs#SAMPLE_RETENTION_DAYS`); cleanup call in `crates/propolis/src/main.rs#main` |

Operational spool and queue sizing (disk headroom, backpressure) is covered in
[../operations/queue-and-spool.md](../operations/queue-and-spool.md).

## Score-model dedup window

A repeat `(source_ip, signal_type)` within 60 s records the event but adds no
weight (`DEDUP_WINDOW_SECONDS`, fixed). This is a scoring constant owned by
[scoring-and-feed.md](scoring-and-feed.md#constants),
noted here because it bounds how fast a single source can accrue score.

## See also

- [reference/environment-variables.md](environment-variables.md) - every env var's default, bounds, and fail behavior
- [reference/integrations.md](integrations.md) - the integrations these caps protect
- [reference/scoring-and-feed.md](scoring-and-feed.md) - scoring constants and feed retention
- [security/outbound-controls.md](../security/outbound-controls.md) - egress gating context
