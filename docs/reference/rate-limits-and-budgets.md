<!--
title: Rate limits and budgets reference
audience: all
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-01
-->

# Rate limits and budgets reference

Every rate limit, budget, cap, and bound across the platform, with exact values
and where each is enforced. Values marked *(hard-coded)* are fixed in source and
not operator-configurable; values with an env var are configurable and their
defaults/bounds are owned by
[environment-variables.md](environment-variables.md).

## Console login rate limit

Sliding-window limiter keyed by source IP, enforced in the console auth layer
(`crates/console/src/auth.rs:200-256`, applied at
`crates/console/src/routes/login.rs:65`).

| Item | Value | Notes |
|---|---|---|
| Max attempts | 5 per 60 s per source IP *(hard-coded default)* | `auth.rs:251-256` |
| Reset | on successful login | `login.rs:77` |
| Blocked-attempt accounting | a rejected attempt is not itself recorded | cannot extend the window past the original 5 (`auth.rs:217-243`) |
| Map cleanup trigger | > 10000 tracked IPs | prunes expired entries (`auth.rs:224-229`) |
| Hard reject ceiling | > 50000 tracked IPs -> all attempts denied | fail-closed DoS bound (`auth.rs:231-233`) |

The limiter keys on the TCP peer address, so it must sit behind a proxy that
sets the peer correctly in production (`login.rs:21-26`).

## VirusTotal daily cap

Enforced by a single `DailyBudget` owned across every scan cycle
(`crates/review/src/virustotal.rs:22-58`, `crates/propolis/src/main.rs:771-774`).
A per-cycle counter would reset each cycle and never enforce a per-day cap.

| Item | Value | Source |
|---|---|---|
| Daily cap | 450 requests / UTC day *(hard-coded)* | `main.rs:752` |
| Request delay | 15000 ms before each lookup and before each upload *(hard-coded)* | `main.rs`, applied in `virustotal.rs::scan_spool` |
| Upload cost | one budget unit per upload, in addition to the lookup that preceded it | `virustotal.rs::scan_spool` (`NextStep::Upload`) |
| Pending recheck | 900 s default before an uploaded, unverdicted sample is looked up again; one budget unit per recheck; never re-uploaded | `PROPOLIS_VT_PENDING_RECHECK_SECS`, `virustotal.rs::needs_lookup` |
| Scan interval | 300 s default | `PROPOLIS_VT_SCAN_INTERVAL_SECS` (`config.rs:523`) |
| Documented VT free-tier limit | 4 req/min, 500/day | reference only, verified live 2026-08-19 (`virustotal.rs:5-6`) |

`try_consume` resets `used = 0` when the UTC date rolls over, else refuses
(returns false) once `used >= limit`. Gating detail in
[integrations.md](integrations.md#virustotal-file-hash-scanning).

## Vendor submission gatekeeper

Ordered, fail-closed per-vendor check sequence run at submission time, after
operator approval; short-circuits on the first hold
(`crates/review/src/gatekeeper.rs:85-138`).

| # | Check | Rule | Default |
|---|---|---|---|
| 1 | Reserved | `is_reserved_ip(ip)` (first, not overridable) | always on |
| 2 | Disabled | `!config.enabled` | vendor off unless enabled + non-empty key |
| 3 | Stale | last activity older than freshness window | 48 h *(hard-coded, vendor-agnostic)* (`gatekeeper.rs:23-25`) |
| 4 | Cooldown | prior SUCCESSFUL submit for this (ip, vendor) within `cooldown_hours` | 24 h |
| 5 | RateLimit | vendor-WIDE successful submits within `rate_window_hours` `>= rate_limit` | 100 per 1 h |
| 6 | ScoreFloor | `current_score.raw_score < floor` | `None` (no extra floor) |
| 7 | CategoryFilter | no breakdown key matches configured filter | `None` (any category) |

Runtime defaults for both the `review` binary and `propolis`:
`cooldown_hours = 24`, `rate_limit = 100`, `rate_window_hours = 1`
(`crates/review/src/main.rs:42-44`, `crates/propolis/src/config.rs:31-33`).
`score_floor` and `category_filter` are `None` in the shipped config loaders
(`main.rs:185-186`). A database error on the cooldown or rate-limit query holds
the submission (`DbError`), fail-closed (`gatekeeper.rs:143-189`). Per-vendor
overrides:
`PROPOLIS_VENDOR_<NAME>_{ENABLED,COOLDOWN_HOURS,RATE_LIMIT,RATE_WINDOW_HOURS,KEY,URL}`
(plus `PROPOLIS_VENDOR_DSHIELD_USER`) - see
[environment-variables.md](environment-variables.md).

## Malware fetcher budgets and bounds

The fetcher is opt-in (`PROPOLIS_FETCH_ENABLED`, default false) and off by
default (`crates/propolis/src/config.rs:527`). Its egress is bounded at several
layers.

### Per-cycle and per-host

| Item | Value | Env var / source |
|---|---|---|
| In-flight concurrency | 8 per cycle *(hard-coded semaphore)* | `CONCURRENCY` (`crates/review/src/fetcher/mod.rs:86,260`) |
| Max attempts per URL | 3, then terminal `Dead` *(hard-coded)* | `MAX_ATTEMPTS` (`mod.rs:81,409-413`) |
| Retry backoff | `5 * 4^(attempts-1)` min (5, 20, 80) *(hard-coded)* | `mod.rs:88-94` |
| Per-host hourly budget | default 12, max 1000 | `PROPOLIS_FETCH_MAX_PER_HOST_HOUR` (`config.rs:36,58`) |
| Daily cap | default 200, max 10000 | `PROPOLIS_FETCH_DAILY_CAP` (`config.rs:39,60`) |
| Batch size per cycle | default 20, max 1000 | `PROPOLIS_FETCH_BATCH_SIZE` (`config.rs:40,61`) |
| Cycle interval | default 10 s, max 86400 s | `PROPOLIS_FETCH_INTERVAL_SECS` (`config.rs:34`) |

The per-host budget is seeded once per cycle from one real
`host_count_last_hour` read; a DB error treats the host as at capacity
(fail-closed). Each candidate is isolated behind `catch_unwind`, so one panic
never aborts the batch (`mod.rs:238-278`).

### Size and timeout caps

| Item | Value | Env var / source |
|---|---|---|
| Max body bytes | default 10 MB (10000000), max 500 MB | `PROPOLIS_FETCH_MAX_BYTES` (`config.rs:35,52`) |
| Redirect hops followed | default 3 | `PROPOLIS_FETCH_MAX_HOPS` (`config.rs:37`) |
| Recursion depth | default 2 | `PROPOLIS_FETCH_MAX_DEPTH` (`config.rs:38`) |
| Connect timeout | default 10 s | `PROPOLIS_FETCH_CONNECT_TIMEOUT_SECS` (`config.rs:41`) |
| Read timeout | default 10 s | `PROPOLIS_FETCH_READ_TIMEOUT_SECS` (`config.rs:42`) |
| Total timeout | default 30 s, max 300 s | `PROPOLIS_FETCH_TOTAL_TIMEOUT_SECS` (`config.rs:43,54`) |

The byte cap is enforced mid-stream: the transfer aborts to `TooBig` as soon as
`body.len() + chunk.len() > max_bytes`, never buffering the whole oversized body
(`crates/review/src/fetcher/http.rs:170-176`).

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
| Max body scanned | 64 KiB *(hard-coded)* | `MAX_BODY_LEN` (`extract.rs:36`) |
| Max URLs emitted | 256 *(hard-coded)* | `MAX_URLS` (`extract.rs:42`) |
| Variable-resolution passes | 8 *(hard-coded)* | `MAX_RESOLVE_PASSES` (`extract.rs:100`) |

### TFTP fetch

`crates/review/src/fetcher/tftp.rs:44-50`: block size 512 bytes, per-block
timeout 2 s, max retries 5 per wait, whole transfer wrapped in the fetcher's
total timeout (hard outer cap). All *(hard-coded)*.

## Pipeline loop intervals

Daemon loop cadences (not egress-producing on their own):

| Loop | Interval | Env var / source |
|---|---|---|
| Review queue populate/withdraw | default 60 s | `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS` (`crates/review/src/main.rs:36-44`) |
| Submission poll (`run_once`) | default 30 s | `PROPOLIS_SUBMIT_POLL_INTERVAL_SECS` (`main.rs:36-44`) |
| VirusTotal scan | default 300 s | `PROPOLIS_VT_SCAN_INTERVAL_SECS` |
| Feed build | 900 s (15 min) | `PROPOLIS_FEED_BUILD_INTERVAL_SECS` |
| Fetcher cycle | default 10 s | `PROPOLIS_FETCH_INTERVAL_SECS` |

A zero interval is rejected for the review loops (would busy-loop)
(`main.rs:85-100`).

## Spool cleanup

| Item | Value | Source |
|---|---|---|
| Sample spool max age | 30 days, removed each VT cycle *(hard-coded)* | `crates/propolis/src/main.rs:781` |

Operational spool and queue sizing (disk headroom, backpressure) is covered in
[../operations/queue-and-spool.md](../operations/queue-and-spool.md).

## Score-model dedup window

A repeat `(source_ip, signal_type)` within 60 s records the event but adds no
weight (`DEDUP_WINDOW_SECONDS`, fixed). This is a scoring constant owned by
[scoring-and-feed.md](scoring-and-feed.md#constants-crates-core-scoring-src-scoring-constants-rs),
noted here because it bounds how fast a single source can accrue score.

## See also

- [reference/environment-variables.md](environment-variables.md) - every env var's default, bounds, and fail behavior
- [reference/integrations.md](integrations.md) - the integrations these caps protect
- [reference/scoring-and-feed.md](scoring-and-feed.md) - scoring constants and feed retention
- [security/outbound-controls.md](../security/outbound-controls.md) - egress gating context
