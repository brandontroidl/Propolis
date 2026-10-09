<!--
title: Intake soak test
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
-->

# Intake soak test

The acceptance test for the intake pipeline under sustained load. The bar it encodes: after a
telnet backlog of several gigabytes froze intake for eleven days, intake has to keep every sensor
current while one sensor is flooded at ten times the peak rate that was observed, for hours, with
a multi-gigabyte log, rotation running, and the review and submission loop contending for the
same database.

The harness is `crates/propolis/examples/soak/main.rs` (an example binary, not part of the
shipped daemon). This page is how to run it, what each check means, and what it does not cover.

## What it runs

| Part | Where | What it stands for |
|---|---|---|
| Writers, one thread per sensor | the harness process | the sensors: one `O_APPEND` write per line, to `logs/<sensor>/events.jsonl` |
| Rotator thread | the harness process | `deploy/logrotate-sensors.conf` (`copytruncate`, size-gated, hourly) and a rename variant |
| Intake | a child process, this binary with the `intake-child` role | the daemon's intake loop |
| Review loop | the harness process | queue scan, an operator stand-in that approves what surfaces, and `review::submit::SubmissionRunner` with a vendor that only counts calls |
| Append-lock probe | the harness process | a second writer queueing on the ledger's append lock, timing the wait |
| Sampler | the harness process | reads the intake's status file, `/proc`, and the database every `--sample-secs` |

The intake child runs the real `crates/intake/src/runner.rs#IntakeRunner` per sensor, in a loop
that mirrors `crates/propolis/src/main.rs#run_intake_sensor` step for step (read a batch, publish
progress, persist the cursor when the position moved, sleep only when idle). It is a copy of the
loop, not the daemon's own function, because the daemon is a binary and cannot be linked: when
that loop changes, change the child's loop with it. It is a separate process so the harness can
`SIGKILL` it, restart it on the same cursor directory the way systemd would, and read its resident
memory without the generator's.

Every generated line carries `metadata.soak_run` and `metadata.soak_seq`, a per-sensor sequence
number. At the end the harness matches each line it wrote against the ledger by that number, so
loss and duplication are counted from the source side rather than from the ledger's own counters.

### Traffic

All sources are RFC 5737 addresses, plus `2001:db8::/32` for the long tail; the WAN addresses are
RFC 5737 too. Telnet carries 40% of its lines from five hot sources (shares 50, 27, 13, 7 and 3
percent), 20% from 500 warm sources and 40% from a long tail of 300000, the tiers the intake
performance work measured. Its signal mix is 45% command, 40% login, 13% connection and 2%
session end. Command text is what bot loops send: short probes, download-and-run chains, and echo
loaders that carry a binary as `\xNN` escapes, which are the long lines (up to about 64 KB). Lines
average about 0.9 KB.

The other sensors run at a fraction of the telnet rate. The defaults (ssh 0.08, http 0.06, cred
0.03, adb 0.02) are an assumption, not a measured ratio: set them from the live journal with
`--mix`.

Designed absences, each tracked by sequence number so the accounting expects them:

- one **malformed** line per `--malformed-every` (default 5000): the runner must reject it;
- one **over-length** line per `--overlength-every` (default 50000), 1.15 MB: the tailer must
  discard it (`crates/log-tailer/src/tailer.rs#MAX_LINE_BYTES`);
- one **near-limit** line per `--nearmax-every` (default 100000), 0.9 MB: valid, must be ingested.

## What it does not cover

- **A vendor call.** The gatekeeper holds every reserved address before any vendor call
  (`crates/review/src/gatekeeper.rs#GateReason::Reserved`), and RFC 5737 and `2001:db8::/32` are
  reserved. So the counting vendor is not expected to be called, and the submission check
  measures the loop, not a send: each pass still runs `read_score` and the protocol-label
  query on `event` for every approved address, which is the part that contends with intake.
- **The rest of the daemon.** No campaign indexer, feed build, console, fleet probe, or
  ops-monitor runs, so the database sees less read traffic than the daemon puts on it.
- **The sensors.** Lines are generated, not produced by the sensor code, so sensor-side costs
  (the command-event budget, capture spooling) are not exercised.
- **The disk.** The cluster the validation runs used keeps its data directory on tmpfs, where
  fsync is free. Per-commit cost on a real disk is higher; judge the long run on a disk-backed
  cluster.

## Before a long run

Size the disk. Measured on the validation runs, a ledger row costs about 0.75 to 1 KB with its
indexes, and the logs grow at about 0.9 KB per line. At `--rate 750` the total is about 890
lines per second, so one hour is roughly 3.2 million events, 2.5 to 3.2 GB of ledger and 2.9 GB
of log, plus `--keep` rotated generations (default 2) of the largest log. Check the free space
of both the database volume and `--dir`, and use a database whose name contains `soak`, `scratch`
or `test`: the harness refuses anything else.

The final accounting walks the whole run in the ledger twice and then verifies the hash chain,
which takes minutes on tens of millions of rows.

## Running it

```
cargo build --release -p propolis --example soak
DATABASE_URL=postgres://postgres@127.0.0.1:5432/propolis_soak \
  ./target/release/examples/soak run --dir /var/tmp/propolis-soak-1 \
  --rate 750 --duration 14400 --prefill-bytes 3G \
  --rotate-secs 3600 --rotate-min-bytes 100M --rotation alternate \
  --verify-every-secs 3600 --catchup-secs 1800 --sample-secs 30
```

`--rate` is the telnet rate in lines per second; the observed peak was about 75, so 750 is ten
times it. `--prefill-bytes` writes a backdated backlog to the logs before the intake starts, split
across sensors by their mix, the way a stalled intake leaves one. `--dir` must be new or empty and
outside the repository; the logs are deleted at the end unless `--keep-logs 1` is given, and
`samples.jsonl`, `report.txt` and `child.log` are kept.

The exit status is 0 for PASS, 1 for FAIL and 2 when the harness itself could not run.

The report's per-sample line shows, every interval: ingest rate against written rate, each
sensor's lag, bytes behind, intake RSS and CPU, append-lock wait, ledger size, submission pass
age, wedge count and restarts. `samples.jsonl` has the same fields per sample as JSON, with each
sensor's batch time.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--dir` | required | output directory |
| `--database-url` | `DATABASE_URL` | scratch database |
| `--rate` | 750 | telnet lines per second |
| `--mix` | `ssh=0.08,http=0.06,cred=0.03,adb=0.02` | other sensors, as fractions of `--rate`; `name=0` removes one |
| `--duration` | 600 | seconds of live load |
| `--prefill-bytes` | 0 | backdated backlog written first (`K`, `M`, `G` suffixes) |
| `--sample-secs` | 10 | sampling interval |
| `--poll-ms`, `--pool-size` | 1000, 10 | the daemon's intake poll interval and pool size defaults |
| `--rotate-secs`, `--rotate-min-bytes` | 3600, 100M | rotation pass interval, and the size a log must reach (logrotate's `size`) |
| `--rotation` | `alternate` | `copytruncate`, `rename`, or one then the other |
| `--keep` | 2 | rotated generations kept |
| `--fault` | none | `kill@S`, `cursor-loss@S`, `poison@S`, comma separated |
| `--restart-delay-secs` | 5 | gap between a kill and the restart |
| `--verify-every-secs` | 0 | a chain walk during the run, as the daemon does every six hours |
| `--queue-secs`, `--submit-secs`, `--approve-secs`, `--approve-max` | 60, 30, 10, 500 | review loop cadence; the operator stand-in approves up to `--approve-max` entries |
| `--malformed-every`, `--overlength-every`, `--nearmax-every` | 5000, 50000, 100000 | designed lines, one per N |
| `--spike-every-secs`, `--spike-secs`, `--spike-x` | 0, 0, 1 | a burst of `--spike-x` times the rate |
| `--seed` | 1 | generator seed |

### Faults

- `kill@S`: SIGKILL the intake at second S and restart it after `--restart-delay-secs`. The
  cursor is persisted only after a batch commits, so a kill between commit and persist replays at
  most one batch: the report allows `--dup-per-restart` duplicate rows per restart per sensor.
- `cursor-loss@S`: a kill plus deleting the cursor files, so the restart reads every log from the
  start. This is a deliberate failure; the report must show it as duplicates beyond the allowance.
- `poison@S`: one line the database always refuses (a NUL in a jsonb string) into the telnet log.
  Intake stops at it and reports a wedge; the lines behind it are counted as blocked, not lost.

## The checks and their thresholds

Every threshold is a flag of the same name. "Steady state" starts, for each sensor, at the first
sample whose lag is within `--lag-p95-secs`; everything after it is judged, so a later spike
(a restart, a stall) counts. The catch-up period before it is reported, and judged only by
`caught up`.

| Check | Passes when | Flag, default |
|---|---|---|
| harness healthy | writers, rotator and intake ran to the end; the intake did not exit unasked | |
| caught up | every sensor gets within the p95 limit, within this long of the start | `--catchup-secs` 600 |
| lag bounded | per sensor, steady-state lag p95 and maximum (seconds since the `observed_at` of the last event ingested) | `--lag-p95-secs` 10, `--lag-max-secs` 60 |
| keeps up | steady-state ingest rate is at least this fraction of the rate written | `--keep-up-ratio` 0.9 |
| memory bounded | intake RSS stays under the cap, and the last quarter of the steady state is within a factor and slack of the first (skipped after a restart) | `--rss-max-mb` 1024, `--rss-growth-factor` 1.5, `--rss-growth-slack-mb` 64 |
| append lock wait | steady-state wait of a second writer on the ledger's append lock (`crates/core-scoring/src/repository/events.rs#APPEND_LOCK_KEY`): worst per-interval p95 and maximum | `--lock-p95-ms` 500, `--lock-max-ms` 2000 |
| no wedge reported | no sensor ever reports a wedge | |
| no append errors | no batch ends in a database error | |
| no unexplained loss | every line written is in the ledger, a designed absence, behind a poison line, or inside a copytruncate window; no designed line was ingested | |
| duplicates within at-least-once | ledger duplicates per sensor do not exceed restarts times the allowance | `--dup-per-restart` 1000 |
| copytruncate loss within window | lines lost per copytruncate rotation do not exceed this many seconds of that sensor's traffic | `--rotation-loss-secs` 5 |
| rejects are the designed ones | the malformed lines the intake rejected are counted from the ledger (each sits alone between ingested neighbours; one inside a stretch of lost lines, or behind a poison line, is not counted), because the intake's own counter reaches the harness through a status file written once a second and a SIGKILL loses the increments since. The counter must not exceed the malformed lines it could have read, and may fall short only after a restart | |
| final drain | after the writers stop, every log is read to its end | `--drain-secs` 120 |
| chain verifies | `core_scoring::verify_chain` is intact at the end and at every mid-run walk | |
| submission passes keep flowing | at least one pass, and none overdue by more than this | `--submit-gap-secs` 120 |

Why these values. Lag: the daemon's own `intake-lagging` condition waits for ten minutes of
delay, so an intake that is only a few seconds behind in steady state has not started to run
away; the p95 of 10 s is about five poll intervals, and 60 s is the longest a single hiccup (a
rotation, a restart) may show. Lock wait: a sensor's writer polls once a second, so a wait
under half a poll interval does not starve it; the figures measured at the benchmark's batch cap
are tens of milliseconds. Memory: the cap is generous on purpose, and the growth rule is what
catches a leak. Duplicates: one batch of `crates/intake/src/runner.rs#MAX_BATCH_LINES` is the
most a crash between commit and cursor save can replay.

### The copytruncate rule

A copytruncate copies the log and truncates the original; the intake never reads the copy. Any
line the intake had not read when the truncate happened is therefore not ingested. The
harness records, for every rotation, the sequence numbers that were in the live file, and counts
the missing ones inside that range as rotation loss. With the intake caught up the loss is the
lines written since its last poll; the check allows `--rotation-loss-secs` of traffic. A rename
rotation keeps the old inode readable, so any loss inside a rename window counts as unexplained.

The same rule is why a rotation that lands while the intake is behind is a failure: it drops the
whole unread backlog, not a poll's worth. Start rotation after the intake has caught up
(`--rotate-secs` later than the catch-up), or the run reports it.

## Reading a failure

| Failing check | Look at |
|---|---|
| caught up, lag bounded | `samples.jsonl`: bytes behind and batch times per sensor; `child.log` for append errors |
| append lock wait | batch times in `samples.jsonl` against the submission pass duration; the database's own load |
| no wedge reported | the first report names the sensor, the time the refused line was observed and the SQLSTATE; the line is in that sensor's log |
| no unexplained loss | the report prints the first missing ranges per sensor; find them with `soak_seq` in the log (`--keep-logs 1`) |
| memory bounded | `rss_kb` and `hwm_kb` over time; a steady climb is a leak |

## Unit tests for the report logic

The accounting classifier and the evaluation are unit tested. Cargo does not run example tests
in the suite, so run them directly:

```
cargo test --release -p propolis --example soak
```

## Validation record

2026-10-08, main `f4036d58` plus this harness, a disk-less (tmpfs) local cluster, other builds
running on the same host.

| Run | Setup | Result |
|---|---|---|
| Target rate | telnet 750 lines/s (about 890 in all), 600 MB backlog prefilled, 440 s, one copytruncate after catch-up | PASS. Catch-up 190 s; steady lag p95 at most 1.9 s, max 2.0 s per sensor; intake RSS 76 MB flat; lock wait p95 161 ms, max 267 ms; 0 unexplained, 0 duplicates, 48 lines lost to the copytruncate; chain intact over 1.0 M rows |
| 2x rate | telnet 1500 lines/s, 120 s, one copytruncate and one rename | PASS. Lag max 1.9 s; 570 lines lost to the copytruncate; lock wait p95 492 ms (limit 500) |
| Kill | intake SIGKILLed at 40 s and restarted | PASS. Telnet lag peaked at 5.8 s, no loss, no duplicates (the kill fell between batches) |
| Kill and poison | kill at 40 s, one poison line at 70 s | FAIL as intended: wedge reported (SQLSTATE 22P05, line named), 37498 telnet lines blocked behind it, 65 append errors, telnet lag to 50 s, no final drain. The other four sensors stayed within 2.5 s |
| Cursor loss | kill and cursor files deleted at 50 s | FAIL as intended: 36814 duplicate telnet rows (allowance 1000), telnet lag 51 s |
| Backlog and rotation | the target run with the first copytruncate (at 150 s to 200 s) landing before telnet had caught up, three times | FAIL, each time: the whole unread telnet backlog was dropped from the live stream (822979, 442378 and 71150 lines) |

The last row is a finding, not a harness fault: a copytruncate while the intake is behind sends
the entire unread backlog to the rotated copy, and nothing in the intake pipeline notices.
