<!--
title: Routine operating procedures
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Routine operating procedures

Day-to-day operator tasks for a running Propolis node. Exact values (env vars,
routes, thresholds) are owned by the reference pages; this page links to them
rather than restating them.

## Reviewing the queue

IPs that clear the eligibility gate are surfaced into the review queue for a
human decision before any publication or vendor submission. The queue snapshots
the score and categories at surface time; the review-queue table is owned by
[reference/database.md](../reference/database.md), the eligibility and tier gates
by [reference/scoring-and-feed.md](../reference/scoring-and-feed.md).

Publication of any IP requires **all** of: an authenticated console session, the
IP seen more than once, above the score floor, and an explicit human approval.
There is no auto-publish path. Nothing leaves the node to a public feed or a
vendor without an operator decision.

Work the queue from the console:

1. Sign in to the console (session-gated; loopback-bound by default). Routes and
   the auth model are owned by
   [reference/console-routes.md](../reference/console-routes.md) and
   [security/authn-authz.md](../security/authn-authz.md).
2. Open the review queue and inspect each pending IP: its score, category
   breakdown, distinct WAN vantages and sensors, and the evidence drawer.
3. Decide.

### Approving and rejecting

Each queued IP resolves to one of the review states `pending`, `approved`,
`rejected`, or `snoozed` (the `review_state_enum`, owned by
[reference/database.md](../reference/database.md)):

- **Approve** - the IP is eligible for the feed and/or vendor submission per its
  tier. Approval is the human gate the publication path requires.
- **Reject** - the IP is withheld from publication and vendor submission.
- **Snooze** - defer the decision; the IP stays out of publication until revisited.

A decision records `decided_at` and optional notes on the queue row. Approval
makes an IP *eligible* to be published on the next feed build; it does not itself
push anything off the node.

### Revisiting a snoozed decision

Nothing re-surfaces a snoozed entry on its own - a population scan never reopens
a decision an operator already took - so a snooze is revisited from the **Snoozed
tab**, which carries the same Approve and Reject controls as the pending queue
plus **Return to pending** for an entry you want back in the working queue.

From the CLI: `review snoozed` lists what is waiting, and
`review approve|reject|unsnooze <ip>` acts on it. `unsnooze` also undoes an
approval or rejection made in error; it clears `decided_at` and keeps the notes.

### Delisting and relisting

**Delist** keeps an address out of the feed and the queue regardless of score.
**Relist** (the address's detail page, on a delisted address) removes that hold.
Relisting does not force the address back into the feed: it clears the latch and
re-derives the ordinary gates from the current projection, so an address whose
score has since decayed stays out on its own merits.

## Publishing the feed

Feed publication has two distinct stages. Keep them straight - only the first is
automated by the platform.

### Stage 1 - in-process build (automated)

The daemon's feed subsystem builds a snapshot from `ip_score` and writes it
**atomically** to the feed output directory (default
`/var/lib/propolis/feed/current`) on each build interval (default 900 s;
env vars owned by
[reference/environment-variables.md](../reference/environment-variables.md)). A
failed build leaves the previous feed in place; a successful build touches the
ops-monitor "last-published" marker. This runs inside the daemon with no operator
action. Tiers, windows, and output formats are owned by
[reference/scoring-and-feed.md](../reference/scoring-and-feed.md).

### Stage 2 - publish to a public repository (operator cron)

Shipping the built feed to a public blocklist repository is done by
`deploy/blocklist-sync.sh`, run **from cron on an interval you configure**. This
cron entry is an **operator setup step**: it is referenced by comment only and is
**not wired into any shipped systemd timer or cron file** in `deploy/`. The
platform does not schedule it for you - you install the crontab.

> **This step produces egress.** `blocklist-sync.sh` runs `git push` to a public
> repository, exposing the published IPs. Run it only after the in-process
> publisher's atomic swap, and only when you intend the feed to be public. Confirm
> the push credential is available to cron (a headless deploy key, not an
> interactive agent) or the push silently strands commits. The general egress
> posture is owned by
> [security/outbound-controls.md](../security/outbound-controls.md).

**Run it as `propolis-blocklist`, not root.** The feed directory belongs to the
daemon, the process that parses attacker input, and this script reads it. Run as
root, any gap in its checks would let a compromised daemon have root copy a file
only root can read into the public repository. `deploy/provision.sh` creates the
`propolis-blocklist` account (home `/var/lib/propolis-blocklist`, no login shell)
and its status directory; it can read the world-readable feed and its own files,
nothing of root's. Set it up once (`<remote>` is your repository's SSH URL):

```
sudo install -d -o propolis-blocklist -g propolis-blocklist -m 0755 /var/lib/propolis/blocklist-repo
sudo -u propolis-blocklist ssh-keygen -t ed25519 -N '' -f /var/lib/propolis-blocklist/deploy_key
# add deploy_key.pub to the repository as a deploy key with write access, then:
sudo -u propolis-blocklist env GIT_SSH_COMMAND='ssh -i /var/lib/propolis-blocklist/deploy_key' \
    git clone <remote> /var/lib/propolis/blocklist-repo   # accept the host key once
sudo crontab -u propolis-blocklist -e
```

The account must be able to read the script and its sibling `blocklist-README.md`, and
it must not be able to change them: a checkout under `/root` or a `0700` home fails
with "Permission denied", and a script the account could edit would run as the account
on the next tick. Install a root-owned copy where every account can read it, and repeat
this after any upgrade that changes `deploy/blocklist-sync.sh`:

```
sudo install -d -o root -g root -m 0755 /usr/local/lib/propolis
sudo install -o root -g root -m 0755 deploy/blocklist-sync.sh /usr/local/lib/propolis/blocklist-sync.sh
sudo install -o root -g root -m 0644 deploy/blocklist-README.md /usr/local/lib/propolis/blocklist-README.md
```

with a crontab entry such as:

```
PROPOLIS_BLOCKLIST_SSH_KEY=/var/lib/propolis-blocklist/deploy_key
5 * * * * /usr/local/lib/propolis/blocklist-sync.sh >> /var/lib/propolis-blocklist/sync.log 2>&1
```

Moving an existing root crontab: `chown -R propolis-blocklist:propolis-blocklist`
the checkout, move the deploy key into `/var/lib/propolis-blocklist` owned by the
account (mode `0600`), copy root's `known_hosts` entry for the remote into
`/var/lib/propolis-blocklist/.ssh/known_hosts`, and move the crontab entry. The script still runs
as root, with a warning in its log, so an old crontab keeps publishing until then. A root run
still records the push: it drops to the owner of the status directory
(`propolis-blocklist`) for that one write, using `setpriv` (util-linux), so the marker
stays owned by the account and `feed-push-stale` keeps working.

The script is fail-closed: it aborts if the source has no `manifest.json` or the
target is not a git checkout, and refuses the whole build, touching nothing in the
checkout, if anything in the feed directory is not exactly what the publisher
writes:

- the feed directory itself is a symbolic link;
- an entry is not `manifest.json` or `aggressive`, `standard` or `all-<n>h|d`
  with one of the publisher's ten formats, a feed is missing one of those
  formats, or there are more than 16 retention windows;
- a file is not a regular file with exactly one link (a symlink, a hard link, a
  FIFO, a device), is over 32 MiB, or the build is over 256 MiB in all;
- a file is replaced between its check and its copy: each one is opened without
  following a link and without blocking, and checked again after it is read.

It always attempts a push (to ship any commit stranded by a prior failed run) and
exits non-zero with a diagnostic if the push fails. After a successful push it
rewrites the marker `/var/lib/propolis/blocklist-status/last-pushed`, in a
directory only `propolis-blocklist` writes (a root run writes it as that account),
never the daemon's feed directory; it skips the marker, with a warning, if that directory is writable by
anyone else. The ops monitor's `feed-push-stale` condition pages when the local
feed has moved on from that marker by more than `FEED_STALE_MULTIPLE` build cycles
(see [health and observability](health-and-observability.md)). Schedule it to run
after a build interval so it never races the atomic swap; a run that does race it
refuses that build and the next run publishes.

## Rotating secrets

Secrets live in per-service `/etc/propolis/*.env` files (mode `0600`, owned by
the service user), created and edited **by hand** - never by `install.sh`. The
full inventory and handling rules are owned by
[secret management](secret-management.md); edit those files per that page, then
restart the affected service.

General rotation shape (see [service lifecycle](service-lifecycle.md) for the
restart commands):

- **Console password** (`PROPOLIS_CONSOLE_PASSWORD`, required) - update the env
  file, restart `propolis.service`. Existing sessions are unaffected until they
  expire or the process restarts.
- **Console session secret** (`PROPOLIS_CONSOLE_SESSION_SECRET`, optional) -
  rotating it (or leaving it unset, which regenerates a random key each start)
  invalidates existing sessions on restart. Must be exactly 64 hex characters if
  set.
- **Database password** - rotate in PostgreSQL, update the inline password in
  `DATABASE_URL`, restart. A wrong `DATABASE_URL` fails the daemon fast at
  startup.
- **Vendor / VirusTotal / ntfy keys** - update the relevant env var and restart.
  A vendor marked enabled with an empty key is forced disabled (fail-closed),
  which is a safe but silent way to disable an integration.

> **Never place these values in a repository, a commit, argv, or a subagent
> prompt.** No secret is read from argv; all are read from the environment at
> startup. After editing, confirm the file is still `0600` and owned by the
> service user.

## Checking health

Liveness, readiness, and metrics are exposed by the console (loopback-bound by
default); the endpoints and their semantics are owned by
[health and observability](health-and-observability.md). In brief:

- `GET /health` - liveness only; always 200, does not touch the database.
- `GET /ready` - 200 if PostgreSQL answers `SELECT 1`, **503** (fail-closed) on
  any database error. Use this, not `/health`, to gate "is the platform actually
  serving".
- `GET /metrics` - Prometheus text format, derived from live queries on each
  scrape (scored/eligible/recommended counts, review-queue depth, vendor
  submissions, feed entries and last-build timestamp, ingest/reject counters).

Routine checks:

- `systemctl status propolis sensor-ssh ...` and
  `journalctl -u propolis` for service state (see
  [service lifecycle](service-lifecycle.md)).
- Watch the review-queue depth metric so surfaced IPs do not accumulate
  undecided.
- Watch the feed last-build timestamp to confirm Stage 1 is still building.
- If enabled, the optional operational self-alerting subsystem pages via ntfy on
  degradation (stall, capacity, backlog, feed staleness, vendor failure rate,
  chain-verify). It is **off by default** and, when enabled, requires its ntfy
  URL and topic or it refuses to start (a monitor that cannot page must not run).
  See [health and observability](health-and-observability.md).
