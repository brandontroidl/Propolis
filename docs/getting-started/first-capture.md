<!--
title: First Capture
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Your first capture

This follows on from [evaluation deployment](evaluation-deployment.md): with the daemon
and the SSH sensor running on loopback, generate one event and watch it flow to the
ledger and the console.

## Produce an event

Connect to the local sensor's high port. Any TCP client that speaks (or attempts) the
protocol works - the sensor records the connection and whatever the client sends:

```bash
# EXAMPLE - trigger the SSH sensor bound at 127.0.0.1:2222
ssh -p 2222 root@127.0.0.1        # offer a banner + a login attempt, then disconnect
# or, a raw connection:
nc 127.0.0.1 2222
```

The sensor is a honeypot: it presents a persona and captures the interaction; no real
shell or login exists. Per-protocol capture behavior (what each sensor records, bounds,
timeouts) is owned by [reference/sensor-behavior.md](../reference/sensor-behavior.md).

## Where it lands

1. **Sensor log.** The sensor writes a JSON event line to its log file - in the eval
   setup, `/tmp/propolis-eval/ssh/events.jsonl` (`PROPOLIS_SSH_LOG_PATH`,
   `crates/sensor-ssh/src/main.rs:26,46`). You can watch it directly:

   ```bash
   tail -f /tmp/propolis-eval/ssh/events.jsonl
   ```

2. **Ledger.** The daemon's intake subsystem tails every file named in
   `PROPOLIS_SENSOR_LOGS` (`crates/propolis/src/config.rs:236-262`) and appends each
   event to the append-only, hash-chained `event` ledger, from which the scoring
   projection is derived. The capture -> ledger -> score path is described in
   [event and sample lifecycle](../architecture/event-and-sample-lifecycle.md); the
   `event` table and hash chain are owned by
   [reference/database.md](../reference/database.md). Event fields and signal types are
   owned by [reference/events-and-signals.md](../reference/events-and-signals.md).

3. **Score.** The source IP (here `127.0.0.1`) is scored and appears as an attacker row.
   Scoring constants, tiers, and eligibility thresholds are owned by
   [reference/scoring-and-feed.md](../reference/scoring-and-feed.md).

## Observe it in the console

Open `http://127.0.0.1:8080/` and log in. The event surfaces across several pages:

- **Live logs** - `/logs` streams the daemon's own tracing events (SSE), so you can see
  intake pick the event up in near real time (`crates/console/src/routes/logs.rs:35-91`).
- **Attackers** - `/ips` lists scored source IPs (`crates/console/src/routes/ips.rs:14`).
- **IP detail** - `/ip/{ip}` shows the evidence timeline, session grouping, and per-WAN
  breakdown for that address; open it as a drawer with `?drawer=1`
  (`crates/console/src/routes/detail.rs:76,198-401`).
- **Review queue** - `/queue` lists IPs awaiting an approve/reject/snooze decision once
  they cross the review threshold (`crates/console/src/routes/queue.rs:41`).

Route details are owned by
[reference/console-routes.md](../reference/console-routes.md); see the
[console tour](console-tour.md) for a walkthrough.

## Observe a captured sample

A bare connection produces an event but no file. Sample capture happens when a client
uploads a payload (e.g. an `scp`/upload attempt against an upload-capable sensor). The
SSH sensor spools captured payloads to its spool directory (default
`/var/spool/propolis/ssh`, `PROPOLIS_SSH_SPOOL_DIR`, `crates/sensor-ssh/src/main.rs:27,47`).
For the eval, point the spool at a writable temp dir:

```bash
# EXAMPLE - eval spool override before starting sensor-ssh
export PROPOLIS_SSH_SPOOL_DIR='/tmp/propolis-eval/ssh-spool'
mkdir -p /tmp/propolis-eval/ssh-spool
```

Captured samples then appear in the console at `/samples`, listed by their sha256 and
downloadable as an `application/octet-stream` attachment served with a hardened
`Content-Security-Policy: default-src 'none'`
(`crates/console/src/routes/samples.rs:81-168`).

> [!WARNING]
> Downloaded samples are live captured payloads and may be malware. Treat them as
> hostile: never execute them, and handle only in an isolated analysis environment. See
> [malware custody](../security/malware-custody.md).
