<!--
title: Console tour
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
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
most recent events and vendor submissions.

If a panel's query fails, the page still renders and an amber banner at the top names
the panels that are showing placeholders. A zero on the dashboard with no banner is a
real zero.

## Review

Addresses that have reached a tier and are waiting for a decision. For each you can
approve, reject or snooze. Approve is what lets an address into the `aggressive` or
`standard` feed files and, if a vendor is configured, allows a report. The Approved,
Rejected and Snoozed tabs show past decisions.

Two per-address actions go further. **Delist** removes the address from the queue and
keeps it out of the feed until you say otherwise. **Delete** removes its score,
queue and submission rows so it starts from nothing; the event ledger is never touched,
so the score can be rebuilt from it.

## Attackers

Every scored address, sortable, up to 500 rows. The Search page covers the rest.

## Address detail

One address: score and tier, the gates it has passed, the activity chart, and the
evidence timeline grouped into sessions where the sensor recorded one. Below that,
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

The daemon's own log, streamed live, for watching intake and the subsystems work.

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
