<!--
title: Console tour
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Console tour

The console is a plain-HTTP web application on `127.0.0.1:8080`, served by the daemon.
It has no TLS of its own; if it must be reachable from another machine, put a reverse
proxy in front and set `PROPOLIS_CONSOLE_TRUSTED_PROXY` so session cookies are marked
secure (see [networking and TLS](../operations/networking-tls.md)). The route table is
in [console routes](../reference/console-routes.md); this page is about what each screen
is for.

## Logging in

One shared password, from `PROPOLIS_CONSOLE_PASSWORD`. A successful login sets a signed
session cookie good for 24 hours; sessions live in memory and end when the daemon
restarts unless you set `PROPOLIS_CONSOLE_SESSION_SECRET`. Five failed attempts from one
address in a minute blocks that address for the rest of the minute. Every page except
login, the health probes, metrics and the font files needs a session.

## Dashboard

The front page: scored addresses, pending reviews and approvals today; events in the
last hour and the last 24 hours with the age of the newest event as a pipeline-health
signal; the current feed size; a 24-hour events chart with 1h, 7d and 30d ranges; the
protocol breakdown; the most active addresses with an hourly activity strip; and the
most recent events and vendor submissions. Recent activity folds consecutive events from
one source with the same sensor and signal into one row with a count (`x37`), so one
source flooding the honeypot takes one row; it reads the newest 1,000 events, and a run
that reaches back past them shows its count as `x1000+`.

If a panel's query fails, the page still renders and an amber banner at the top names
the panels that are showing placeholders. A zero on the dashboard with no banner is a
real zero.

## Review

Addresses that have reached a tier and are waiting for a decision. Under each pending
row a context line says what the address did: the sensors it reached, how many sessions,
its three most frequent signals, and its first upload or download, or failing that its
first command after the `enable` / `system` / `shell` / `sh` preamble Mirai-family
loaders open with. For an address with more than 5,000 events the counts describe 5,000
of them, and the line says so. For each you can approve, reject or snooze. Approve is what lets an address into the `aggressive` or
`standard` feed files and, if a vendor is configured, allows a report. The Approved,
Rejected and Snoozed tabs show past decisions.

The **Snoozed tab is where a deferred decision gets made**. Nothing puts a snoozed
entry back in the pending queue on its own, so that tab carries its own Approve and
Reject controls, plus **Return to pending** to hand the entry back to the working
queue. Acting on a row there moves it to another tab and tells you which one.

Two per-address actions go further. **Delist** removes the address from the queue and
keeps it out of the feed until you say otherwise - **Relist**, which replaces the
Delist button once an address is delisted, is how you say otherwise. Relisting clears
the hold and re-derives the ordinary gates, so the address rejoins the feed only if it
still qualifies on its current score. **Delete** removes its score, queue and
submission rows so it starts from nothing; the event ledger is never touched, so the
score can be rebuilt from it.

## Attackers

Every scored address, sortable by score, events, first seen or last seen, 500 to a page,
with Previous and Next links and a "showing 501-1,000 of N" line. Pages resume from the
last address shown, so an address scored while you page does not repeat or skip a row.
Past 100,000 addresses the total is the database's estimate and says so.

The **score** column is the live score: decayed since the address's last event and
weighted for how many of your WAN addresses it hit. The **tier** was set when the address
was last scored, from its raw score and its strongest signal's confidence, so a standard
address can show 100.0 while an aggressive one shows 99.9. A note above the table states
the thresholds; their owner is [scoring and feed](../reference/scoring-and-feed.md#tier).

## Address detail

One address: score and tier, the gates it has passed, the activity chart, and the
evidence timeline grouped into sessions where the sensor recorded one. Consecutive
sessions that ran the same commands (a loader retrying under a new username) fold into
one card marked `x3 identical sessions` with the usernames tried, each session still
inside it, and an echo loader's chunk writes to one file are one row, `40 echo chunks
to /tmp/.i`, with the lines behind an expander. Below that,
which of your WAN addresses it hit, which services it probed, vendor submissions, and
the malware linked to it, marked as uploaded directly or fetched from a URL it
reported. A truncated upload is labelled as such.

Clicking an address from a list opens the same content as a slide-in drawer, with a
link to the full page. The external-lookup links open in your browser; the daemon never
contacts those services on your behalf. Reverse DNS is shown only if you enabled it.

## Feed

The **Status** tab reads the published manifest: entry counts per tier and per
retention window, when it was built, and what the exclusions removed. The **Entries**
tab lists the addresses in the published files, read from those files rather than the
database, so it cannot disagree with what was published. Every feed is downloadable in
ten formats, from plain text to nftables, pf and RPZ.

## Samples

Captured files by SHA-256, with size, which sensor took them, the addresses they are
linked to, and the VirusTotal verdict if one exists. Downloads are served as opaque
attachments. Above the table, a strip shows the dropper fetcher's outcomes by status.

## Search

Events by free text, sensor, signal type, address and date range, and addresses by
the same filters. At least one filter is required.

## Integrity

Runs the hash-chain verification over the whole ledger and reports intact or broken,
with the first bad row if broken. The same check runs on a schedule in the daemon; this
is the on-demand version.

## Logs

The daemon's own log, streamed live, for watching intake and the subsystems work. Each
row shows its structured fields (`sensor=telnet`, `elapsed=1.5s`, `reason=...`) and
expands to all of them. Adjacent identical INFO lines from one target fold into one row
with a count and the values each field took (`batch processed x42 sensor=telnet/vnc`).
The view opens showing warnings and errors, with a line saying how many lower-level rows
it hides and a button to show everything.

## Themes

Graphite (dark, the default), cream, system, and a green-phosphor hacker theme, from
the switcher in the top bar. The choice is stored in your browser. Fonts are served by
the console itself; the page loads nothing from a CDN.

## Probes and metrics

`/health` always answers 200 while the process is up. `/ready` answers 503 if the
database is unreachable or any supervised subsystem has died, naming the dead ones.
`/metrics` is Prometheus text. All three are unauthenticated, which is only acceptable
on loopback; `PROPOLIS_CONSOLE_METRICS_TOKEN` adds a bearer token to `/metrics` if you
expose it. See [health and observability](../operations/health-and-observability.md).
