<!--
title: Health and observability
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-09
-->

# Health and observability

The health, readiness, and metrics endpoints; what the fleet pane's per-listener activity
counts; how the daemon logs; the drop and spool-refusal
counters an operator watches under load; and the opt-in ops-alert monitor. Route details are
owned by [console routes](../reference/console-routes.md); this page is the operational view.
It starts with the one command to run when something is wrong, and what each of its next steps
means.

## Where to look first

On the host an alert named, run `sudo propolis-status` (`deploy/propolis-status.sh#status_walk`;
forms and exit codes in [commands](../reference/commands.md#status-walk)). It changes nothing:
it writes nothing except a temporary header file for the metrics token, removed on exit, takes
no lock and restarts nothing, so it is safe to run first, before any other step. It prints, in
this order:

- the host line (the alias the host has on the channel, the host name, its role), the alert
  target, the daemon's monitor and alert queue, how many units' failure alerts are still
  undelivered, when the witness's light pass last completed, where the root alerting state was
  last written, when the login banner was last written and, once a light pass has run, whether a
  heartbeat URL is set and when it was last asked or skipped (never the URL itself), and whether
  a test page proved the alert path (`VERIFIED` or `NOT VERIFIED`, see
  [the witness](#witness));
- `OPEN`: the incidents the witness has open, acknowledged or pending, PAGE first, then ACT,
  then NOTICE, each with its stage, the unit's opaque id and name, since when it is open, its
  cause as systemd gave it (`proc.exit 1`, `proc.signal 9`, `proc.oom`...), when the next
  reminder would go out, and what today's failure hook did with the latest firing
  (`[legacy hook: delivered]`, `undelivered`, `cooldown`, `journal`), or `[not pushed: legacy]`
  for something only the witness saw. An open PAGE makes the exit status 2 and an open ACT 1.
  A firing the hook could not record (the lock was busy, or its time nearly spent) and wrote to
  its spool instead is listed too, marked `[spooled, not yet in the record]`, until the next
  light pass takes it in. On a host where no witness pass has completed yet, the block is
  `RECENT FAILURES` instead: the hook's records listed as failures that happened, newest first,
  which never change the exit status, because nothing has judged them;
- the pipeline, stage by stage: `listen`, `source`, `ship`, `gateway`, `intake`, `ledger`,
  `review`, `reports`, `feed`, `publish`, each with its last progress, then the rails beside it
  (`alert`, `backup`, `chain`, `host`, `monitor`, `witness`, `peers`), then the installed
  config-check's findings, run live;
- `NEXT`: the view to open and the runbook section below for the first thing to look at.

**The marker.** The first stage whose own facts say it stopped is marked `>`
(`deploy/propolis-status.sh#first_stopped`). Only a fault the row can see directly (a unit that
is enabled and not running, a log the reader cannot open, a failed database connection, a
config-check finding that stops capture) or a stage with work waiting and no progress for longer
than `PROPOLIS_OPS_STALL_FOR_SECS` can take it. A parked sensor (disabled with its bind still
set) only warns, so it never takes the marker from a real fault further down. A stage after the
marker that stopped only for lack of input reads `starved`; one with a fault of its own stays
`FAIL (also)`. One exception: when the daemon is down, the database refuses connections and the
daemon's last run logged `propolis: failed to connect to PostgreSQL` (matched by unit, uid and
invocation id, which no other process can forge), the marker goes on `ledger` and `intake` reads
`starved`. A row that could not be read shows `?` with the reason and never takes the marker.
Stages 7 to 10 are shown, not judged.

**What shell cannot see before step 3.** Whether the ledger accepts writes (a ledger that
answers reads and refuses writes shows as intake stopped and the ledger row `ok`), the daemon's
own causes for what it is doing, the hash-chain verdict, whether the daemon's alerts are answered,
and other nodes on the same database. The rows say so instead of guessing.

`sudo propolis-status <stage>` opens one row: every unit's properties, the cursor of every log,
the config-check findings for that row with their fix lines, and the last 20 journal lines of a
unit that is not running. Text a unit or the database wrote is shown cleaned of every byte
outside printable ASCII and marked `[untrusted]`.

<a id="listen-down"></a>
### A listener is not capturing

A sensor unit that is enabled is not running, or config-check found its port held by another
process, bound only on loopback, not listening, or closed by the firewall. `sudo propolis-status
listen` shows each unit's state, the findings with their fix lines, and the last journal lines
of a unit that is not running. Fix what the journal says, then `sudo systemctl restart
sensor-<name>.service`.

<a id="daemon-down"></a>
### The daemon is down

Step 0: do not restart anything until the walk shows where it stopped. `propolis.service` is
enabled and not running, or `/ready` names a subsystem that gave up. `sudo propolis-status
intake` shows the unit, how far behind each log is (from the cursor files, which work with the
daemon dead) and its last journal lines. When the walk marks `ledger` instead, the daemon cannot
start because the database does not answer: see [db-unreachable](#db-unreachable).

The witness records `daemon-down` (PAGE) when the daemon is failed, stopped, waiting to be
restarted, or starting for over half an hour, on two light passes in a row, and when it has been
running for half an hour and its console does not answer `/ready` on two (cause `net.connect` or
`net.timeout`). A daemon running for less than half an hour without an answer is still starting
(migrations can take that long) and nothing is recorded. It resolves only when `/ready` answers 200
on two passes at least five minutes apart with no restart between (`monitor ready twice`), not on
the daemon merely running. `/ready` is believed only from a listener the daemon holds (its main
process, or a socket of the `propolis` account, by `ss`): an answer from anything else on the port
reads unknown and resolves nothing, and nothing listening reads as no answer. Where
`PROPOLIS_CONSOLE_BIND` is not a loopback address `/ready` is not asked at all, and `daemon-down`
resolves once the daemon has run ten minutes without a restart (`active10`). A daemon that answers
`/ready` 503 on two passes while the witness's own database probe succeeds, or cannot run at all,
is `daemon-degraded` (ACT, key `ready:local`, cause `ready.db`, or `ready.gave_up` when the answer
names a subsystem that gave up). While the database probe fails and the daemon's last completed
run logged that it could not connect (the newest of that line and its start line, so a fresh
attempt that has logged nothing yet still counts), the daemon's record waits pending and folds
under `db-unreachable`, so a database outage is recorded once, under its cause. A folded record
sends nothing while `db-unreachable` is open. Once that resolves, a daemon that is ready again is
dropped as a healed restart, and one still not up half an hour later opens as its own incident.

<a id="db-unreachable"></a>
### The database does not answer

`SELECT 1` through `propolis pg-exec` failed with `db.unreachable`, `db.auth` or `db.timeout`.
`sudo propolis-status ledger` shows psql's own error, cleaned. For a local database check
`systemctl status postgresql`; for `db.auth`, the role and `pg_hba.conf`
([database roles](database-roles.md)). A `tool.exec` is not an outage: psql itself could not run
(see [tool](#tool)).

Every light pass of the witness asks the same question as the daemon's own role,
`SELECT pg_is_in_recovery()` through `propolis pg-exec` (read-only, with 5 s limits to connect
and per statement); the database URL goes only to that one process, and psql's error text is
dropped, never stored. A failure with `db.unreachable`, `db.auth` or `db.timeout` on two passes in
a row opens `db-unreachable` (PAGE, key `db:local` or `db:remote`, `ledger` stage), which resolves
when the database answers on two passes (`database answered twice`). Neither it nor
`db-readonly` opens in the first 15 minutes after a boot, while a database is still recovering,
nor under a marker written with `sudo propolis-status --maint MINUTES` (reason `manual`), which is
how planned database work is announced. `tool.exec` and `config.invalid` never open it: they count
toward `tool-unusable` on `tool:pg` instead. When the probe has not been able to tell for six hours
(72 passes) while a database record is open, the record is flagged `cannotverify`: it cannot
resolve until the probe works again. The same flag marks an open `daemon-down` or
`daemon-degraded` whose `/ready` could not be asked, or timed out, for six hours.

<a id="db-state"></a>
### The database answers, in a state that blocks writes

A standby (`pg_is_in_recovery()` true), transaction ids near wraparound, connection slots nearly
full, or lock waits. `sudo propolis-status ledger` prints each of these read-only probes. The
witness's light pass records a standby seen on two passes as `db-readonly` (PAGE, key
`db:recovery`): the daemon points at a server that refuses writes. It resolves when the database
is writable on two passes.

The witness's hourly pass reads the rest once an hour, as the daemon's own role, in one read-only
session through the daemon binary (`deploy/witness.sh#pg_state_read`): the age of the database's
oldest unfrozen transaction id, the client connections (the server's own background processes
take no slot and are not counted) against `max_connections` less
`superuser_reserved_connections`, the lock waits older than 120 s (from `pg_locks.waitstart` on
server 14 and later, before that the sessions waiting on a lock since their state last changed),
and the database's size, which is recorded only. The walk's `ledger` row shows the last reading
(`hourly <time>: xid age <n>, slots <n> of <n>, lock waits <n>, size <bytes>`). Each condition
seen on two hourly passes in a row opens a record on the `ledger` stage: `db-xid` (ACT, key
`dbstate:xid`) for a transaction id over 1,000,000,000 old, half way to wraparound and far past
autovacuum's own 200 million (run `VACUUM` on the database, and look for a long transaction or an
abandoned prepared transaction holding it back); `db-slots` (ACT, `dbstate:slots`) at 90% of the
usable slots (a client leaking connections, or `max_connections` too low for the fleet); `db-locks`
(NOTICE, `dbstate:locks`) for any lock wait over 120 s. None opens in the first 15 minutes after a
boot or under a manual maintenance marker; two clean hourly passes resolve each. While one is open
the `ledger` row warns (`open: xid slots locks`) and never takes the marker. Lock holders are not
named yet.

<a id="alert-path"></a>
### Alerts are not leaving the host

The failure hook kept an undelivered file under `/run/propolis-alert/undelivered/`, or the
daemon's queue `ops-alert-undelivered.json` holds alerts. `sudo propolis-status alert` counts
both and the hook's journal lines of the last 24 h. Check the ntfy URL, topic and token in
`propolis.env` and that the host can reach the server.

The witness opens `alert-path` (PAGE, key `alert:shell`, the `alert` rail FAIL) on first sight of
the legacy hook's own journal line for an alert it could not deliver (`...; alert follows` or
`... still undelivered since ...`, cause `nocurl`, `net.connect` or `unknown` from the reason the
line gives), and of a failure hook that itself failed or timed out (a failed
`propolis-alert@` instance whose failure is newer than the last open or resolve; its own cause).
The hook's lines are read only from entries journald itself tied to a `propolis-alert@` unit, and
only the first line of each, so text a sensor logged and the hook quoted cannot count. It resolves
(`an alert got through`) only on proof that an alert went out after it opened: the legacy hook's
delivered stamp `/run/propolis-alert/<unit>` dated after the open, a failure hook's record of a
firing that delivered its alert (or, with no push target, logged it to the journal), or, with no
push target, a failure alert logged with no undelivered line; and then only with no undelivered
file left and no failure hook failed since the open. Nothing seen is never the proof, and the
proof holds across a reboot. A failed hook instance stays failed until `sudo systemctl
reset-failed 'propolis-alert@*'`, so reset it once you have read its journal; one that failed
before the open does not hold the resolve back. While `alert-path` is open the heartbeat URL is not
asked, so an external dead-man check notices.

<a id="ship-down"></a>
### The shipper is down

On a collector, `shipper.service` is enabled and not running. `sudo propolis-status ship` shows
its properties and its last journal lines.

<a id="ship-failing"></a>
### The shipper has bytes it cannot send

On a collector, a log has unread bytes and the gateway has accepted no batch for longer than
`PROPOLIS_OPS_STALL_FOR_SECS`. `sudo propolis-status ship` shows each log's cursor against the
file; check that the gateway is reachable and the certificates ([split
deployment](split-deployment.md)).

The witness's light pass on that collector also reads the shipper's journal (by
`shipper.service` and the `propolis-shipper` account's uid): an ERROR line that means nothing is
being shipped (`shipper: failed to connect to gateway`; `shipper: ship cycle IO error`, a batch it
cannot record in its state directory, or a gateway that keeps answering Retry; `shipper: gateway
rejected a batch`, the collector's chain has diverged from the gateway's, or the line it logs
before every exit on a permanent stop) on three light passes in a row opens `ship-failing` (ACT,
key `ship:local`, cause `ship.connect`, `ship.io` or `ship.rejected` in that order, the worst
seen), which two passes without one resolve. After a permanent stop the unit restarts and stops
again, so the unit's own record is open beside this one: `ship-failing` gives the cause. The lines the shipper logs at WARN when it
drops a line (shown only with `RUST_LOG` set) open the NOTICE `ship-dropped`, resolved after a day
without one. A line counts by its own level and message, never by a text its fields quote (a WARN
line quoting the sensor name a refused line claimed is still a WARN line). The `ship` row fails
while `ship-failing` is open. `journalctl -u shipper.service`
shows the lines themselves; the witness keeps only counts.

<a id="spool-quiet"></a>
### A collector has gone quiet

On a control node, a collector has sent nothing for a while. The control node cannot see the
collector's side, where a quiet honeypot and a dead shipper look the same: run `sudo
propolis-status` on that collector.

The witness's light pass on a control node or gateway lists the gateway spool every five minutes,
as the `propolis-gateway` account when the spool is that account's, and opens `spool-quiet` (ACT,
`ship` stage, key `spool:<opaque id>`) for a collector `PROPOLIS_SENSOR_LOGS` lists (its
`<spool>/<id>/events.jsonl`) whose spool file has not been written for longer than twice the
longest gap between two of its writes this week, and never under half an hour, on two passes in a
row. It waits for that week to be a day old (or for a week before it), for `gateway.service` to
have been up fifteen minutes, and holds while a maintenance marker with reason `manual` is set:
`sudo propolis-status --maint MINUTES` on the control node is how to say a collector is off on
purpose. Two passes on which the spool was written resolve it; a collector taken off the list
resolves it as disabled. A listed collector whose spool file is gone is judged from the last
write seen; a modification time ahead of the clock counts as neither quiet nor a write. A spool
of more than 1024 entries leaves a listed collector past them unknown for that pass. A spool
directory nobody listed gets no record here; that is config-check's `spool-unlisted`. The walk marks that collector's `ship` row while it is open.
What it cannot tell: a collector whose sensors died while their stats lines still ship is not
quiet.

<a id="gateway-down"></a>
### The gateway is down

`gateway.service` is enabled and not running on a control node or gateway. `sudo
propolis-status gateway` shows its properties, each collector's spool and the gateway's error
lines of the last 24 h.

<a id="gateway-dup"></a>
### The gateway dropped a rebuilt batch

The gateway logged `gateway: batch reuses the last accepted seq with different content;
acknowledged as Duplicate without storing it`: a collector sent a batch number again with other
content, and those records were not stored. `sudo propolis-status gateway` counts the gateway's
error lines of the last 24 h; the line's `collector_id` names the collector whose shipper state
to check.

The witness's light pass reads this line by `gateway.service` and the `propolis-gateway`
account's uid and opens `gateway-dup` (ACT, `gateway` stage) on first sight, keyed by the
collector's opaque id when `collector_id` is a listed collector (`gwdup:<id>`) and `gwdup:unlisted`
otherwise. It adds up the line's `records` and `suppressed_records` (read as digits only) since the
record opened, an upper bound of the evidence lost, which the `gateway` row shows as `rebuilt batch
dropped from {<collector>}, <n> records counted lost` and warns. A day without the line resolves
it: no further loss in 24 h, never "recovered". Only a batch that reuses the last accepted number
can be seen this way.

<a id="backup-failed"></a>
### The backup failed or is old

The last backup run failed after the last good one, the last good one is older than
`PROPOLIS_OPS_BACKUP_MAX_AGE_SECS`, the timer is not enabled, or config-check has a backup
finding. `sudo propolis-status backup` prints both status files, including the step a failed run
was in; see [backup and restore](backup-and-restore.md).

<a id="backup-hung"></a>
### A backup run does not end

A run that does not end holds the backup lock, so the next nightly run waits behind it.
`systemctl status propolis-backup.service` shows whether one is running and since when, and
`journalctl -u propolis-backup.service` the last step it logged.

The witness's light pass opens `backup-hung` (ACT, key `backup:run`) when
`propolis-backup.service` has been activating for longer than three times the last run's length,
and never under two hours, on two passes in a row; the run's length is kept as `meta backup_dur`
from each pass that sees the unit inactive after a run. It resolves once the unit is no longer
activating. The unit's own `TimeoutStartSec=6h` still ends such a run; this says so earlier while
the usual run is short (up to four hours earlier), and not at all once the usual run takes two
hours or more, when three times its length is that timeout and the unit's failure speaks first.
The `backup` rail fails while it is open.

The hourly pass also counts the scheduled sets in the backup directory (the backup unit's
`PROPOLIS_BACKUP_DIR` and `PROPOLIS_BACKUP_KEEP`, default 7): fewer than KEEP while the oldest is
dated more than KEEP days ago opens the NOTICE `backup-retention` (`meta backup_sets` holds
`<sets>/<KEEP>`). With an off-host pull configured (a key line in
`/var/lib/propolis-backup-pull/.ssh/authorized_keys`, read as that account), the forced command
logs `served <set> <file>` for each file it serves, which the light pass keeps as `meta
pull_last`. A scheduled set that has waited over 72 hours for the pull opens the NOTICE
`backup-offhost`, resolved by the next served line: a set waits when it was made after the later
of the last served line and the first hourly pass that saw the pull configured (`meta
pull_since`). The pull fetches only the newest set and logs nothing when it already holds it, so
the age of the last line alone says nothing while no new set appears; and a pull that never
served anything is reported once a set made since it was first seen is three days old. While the
installed serve script is an older one that logs no line, nothing opens. A failed backup whose last step read the database folds
under an open `db-unreachable`, and one that failed checking free space under the open volume
record of the backup directory's filesystem, each only when the failure came while that record's
fault was there.

<a id="rotation"></a>
### Log rotation is late or refused

config-check reports rotation stale, a log over its rotation size, or the free-space guard
missing. `sudo propolis-status source` shows the logrotate state file's age and counts the
guard's skip and refusal lines of the last 24 h; `systemctl status propolis-logrotate.timer`
shows the timer ([retention](retention.md#log-rotation)).

<a id="push-failing"></a>
### The public feed push is not happening

`/var/lib/propolis/blocklist-status/last-pushed` is old or missing. `sudo propolis-status
publish` shows the marker's time and whether a crontab line or an enabled timer runs
`deploy/blocklist-sync.sh`; run that by hand as `propolis-blocklist` to see its error.

The witness's hourly pass, on a single box or control node, opens `push-failing` (ACT, `publish`
stage, key `push:cron` or `push:timer`) on two hourly passes in a row when a scheduler runs the
push, the feed was published after the last push (the daemon's `.<name>.last_published` marker
beside `PROPOLIS_FEED_OUTPUT_DIR`, read as `propolis`) and that push is over six hours old; or,
with no push marker yet, when the scheduler has been seen for over six hours (`meta
push_sched_since`) and a publish came after. A feed that did not change is not stale, and a short
outage of the remote does not open it. A schedule that runs the push less often than every six
hours is reported as failing between its runs, so keep the interval under that. Its onset is the push marker's time, and the next push
resolves it. With the feed enabled and nothing to run the push it opens `push-unscheduled` (ACT)
when `PROPOLIS_OPS_FEED_PUSH_EXPECTED` is set, and the NOTICE `push-off` when it is not. The
`publish` row fails while `push-failing` is open.

<a id="volume"></a>
### A volume is filling

A filesystem Propolis writes to (`/var/lib/propolis`, `/var/log/propolis`,
`/var/spool/propolis`) has less than 15% of its space or inodes free. `sudo propolis-status
host` shows which; freeing space or moving the store is the fix.

The witness's hourly pass watches every store (`deploy/witness.sh#vol_sample`, the list in
`deploy/alert-lib.sh#pa_vol_stores`): those three, the gateway's spool
(`PROPOLIS_GATEWAY_SPOOL_DIR` in `gateway.env`, else `/var/spool/propolis/gateway`), the journal
in `/var/log/journal`, the backups (`PROPOLIS_BACKUP_DIR` from the backup unit's environment, else
`/var/backups/propolis`), with a local database the PostgreSQL data directory, and the directory
of each sensor log `PROPOLIS_SENSOR_LOGS` names. Each existing store is placed on its filesystem,
links followed, and each filesystem gets one `df` an hour, kept for seven days as a sample under an
opaque mount id (`m` and 5 hex digits); two stores `df` reports on one mount point are one volume.
The data directory is placed and sized as the `postgres` account and a configured log directory as
`propolis`, never as root, since those accounts could put a link on the path. A `df` that does not
answer within 10 s (a hung mount) is unknown for that hour, never a value, and so is a pass on which
a store's path could not be learnt (systemd did not say where the backups go, `gateway.env` could
not be read, where the database is was not found, or a local database's data directory was never
read: `SHOW data_directory` as the `postgres` account failed, with the cause `tool.exec` where
`psql` cannot be run from the witness's unit and `db.unreachable` where the server refused the
connection) or a store could not be checked for another reason than being absent: a filesystem
missing from such a pass is not taken as free of stores, so an open record stays open and its
samples are kept. While that lasts the other stores are still sampled and judged, and after three
such passes the NOTICE `tool-unusable` on `tool:volume` carries the cause. On two hourly
passes in a row a filesystem opens `volume-filling` (ACT, key `vol:<mount id>`, `host` rail) when
its free space is under `PROPOLIS_OPS_CAPACITY_FREE_PCT` (the daemon's setting, 15% by default),
its free inodes under 10% (never on a filesystem that reports no inodes, such as btrfs), or when it
would fill to its last GiB within 72 hours at the current rate; and `volume-full-soon` (PAGE, the
same record, its rise a change) when that is under 12 hours, its free space under 1 GiB plus the
rotation guard's 512 MiB reserve on a filesystem that is also under half free (a small volume with
room is under that size even when empty), or its free inodes under 2%. A record opens at the lower tier of
its two passes, so one reading of `volume-full-soon` alone pages nothing. The rate is the larger of
the fall of free space over the week of samples and its fall over the last day (over at least 12
hours of samples), measured over the time that really passed, and used only with 72 hours of
samples and a week in which free space fell. A nightly backup's dip that comes back is no fall over
the week; a one-off copy counts in the last day's rate until it is a day old, and can open a volume
record for that day. Room again on two hourly passes resolves it. A rotation the guard refused for
want of space, while a filesystem holding the sensor logs has such a record open, folds under it.

The walk's `host` rail warns with `volume <id> filling` or `volume <id> full soon`, and `sudo
propolis-status host` lists each filesystem by its id and mount point with its last sample, how far
back its samples reach and, once they span 72 hours of falling space, the rate and the time it
would fill (`at risk by`, with its year once that is not the current one, or `at risk in more than
a year`). It maps ids back by the same list of stores, the data directory and the log directories
sized as their accounts; an id it cannot map reads `mount point not known here` when a store's path
could not be learnt or checked, else `no store here is on it now`. With a remote database it prints
`data volume: not readable here (remote database)`. The mount point is shown only there, never
stored in a record.

<a id="finding"></a>
### config-check found something

The row names config-check finding ids. Run `sudo /usr/local/lib/propolis/config-check.sh`: each
finding has a `fix:` line to paste or a `do:` line to follow.

The witness's hourly pass runs the same check and records what it finds: a finding seen on two
runs in a row opens a `finding` record, at the tier its row of `deploy/witness.sh#WITNESS_CC_TABLE`
gives (sixteen ids that nothing else sees are PAGE or ACT; the rest are NOTICEs, or not recorded),
and resolves once it is absent from two runs in a row that could check it. A run could not check
a finding when its group's `G` row, a listener cell or one of its `L` (limit) lines says that part
was not checked (an `L` line the witness does not know holds every group), or when it printed a
finding line out of form that could have been that finding; a first sighting such a run did not
show is dropped, since seen again it is not on two runs in a row. A `unit-down` whose unit systemd
calls failed (the unit's own failure pages it) and a `listen-foreign` on a port a `danger` finding
holds are recorded as NOTICEs for that run; once the fault is the finding's alone its tier rises
to the table's. Every unlisted collector spool folds into one record that counts them; config-check
names at most 20, so 20 or more reads `20+`. The walk's OPEN block shows the listener, log or
collector each record is about.

<a id="tool"></a>
### A program a check needs cannot run

For example psql through pg-exec (`tool.exec`), blocked by a sandbox or missing. That is not an
outage of what it checks: fix the program, and the row reads again. A check of the witness that
cannot tell on three passes in a row opens `tool-unusable` (NOTICE, key `tool:<check>`: `units`,
`pg`, `ready`, `alertunit`, `journal:hook`, `journal:guard`, `journal:journald` or
`journal:daemon` of the light pass; `readcheck`, `volume`, `pgstate` or `changes` of the hourly
pass), and the `host` rail warns with `a check cannot run: <check>` until two clean
results resolve it. On a host whose psql lives where the witness's sandbox does not allow it (the
PGDG layout under `/usr/pgsql-<N>/bin`), `tool:pg` stays open; a database outage there is still
seen through the daemon's `/ready` answer (`daemon-degraded`).

`cc-stopped` on the `witness` rail is the one case that is not a NOTICE: the installed config-check
did not complete on two hourly passes in a row (it timed out after 300 s, is missing, failed the
ownership check every program root runs must pass, as must the `listeners-lib.sh` it sources
beside itself and an `alert-lib.sh` there, or printed an incomplete report), so every
finding it would record goes unseen. Run `sudo /usr/local/lib/propolis/config-check.sh` and read
`journalctl -t propolis-witness`; two completed runs resolve it.

<a id="state"></a>
### The alerting state is not on disk

The last write of the root alerting state could not reach `/var/lib/propolis/witness`: the walk
shows `state not persisted (run)` (written to `/run` only, lost at reboot) or `(none)`. Free
space or make `/var` writable; `sudo propolis-status host` shows where the last write landed.

<a id="witness"></a>
### The witness

The witness (`deploy/witness.sh#light_pass`, installed as `/usr/local/sbin/propolis-witness`) is
a root oneshot with two passes: `propolis-witness@light.timer` runs the light pass
every five minutes, and `propolis-witness@hourly.timer` the hourly pass
(`deploy/witness.sh#hourly_pass`) once an hour, first 3 to 13 minutes after the timer is enabled; `install.sh` and `upgrade.sh` enable
both timers. It records and shows, and sends no incident: in the default profile each
transition the new paging would send adds one to the record's `would_push`. The one message it
sends is [the daily message](#the-daily-message), once a day and only to a topic proven to refuse
anonymous reads. Beside that and the read check's GETs (below), the only request that leaves the
host is the optional heartbeat URL's GET, which carries no message. Each light pass:

- first asks the database, as the daemon's own role, whether it answers and takes writes (see
  [db-unreachable](#db-unreachable)), before anything else is read, so a database outage is known
  before the daemon's failure is judged;
- asks systemd once for the state of every Propolis unit;
- asks the daemon's console `/ready` once, over plain HTTP on its loopback address (the address in
  `PROPOLIS_CONSOLE_BIND`, `0.0.0.0` asked as `127.0.0.1` and `[::]` as `[::1]`; any other address
  is not asked and the check reads unknown), with no credentials and no proxy, while
  `propolis.service` is enabled and running and only when `ss` shows the daemon holds the port;
  only the status code and whether the body holds `"gave_up"` are judged (see
  [daemon-down](#daemon-down));
- reads the journal lines nobody else reads, each narrowed first by fields journald sets itself
  (the unit, the uid, the run's invocation id) and then matched against fixed text
  (`deploy/alert-lib.sh#PA_JOURNAL_CLASSES`): the legacy hook's lines for alerts it could not
  deliver and failed failure hooks (see [alert-path](#alert-path)), in the compact json of current
  journalctl and the spaced form older releases print; journald's notice that it suppressed lines
  from a Propolis unit (`Suppressed <n> messages from <unit>`, the unit named as journald names it
  since systemd 236, or by a cgroup path whose last part is the unit), which opens the NOTICE
  `journal-dropped` (key `journal:<unit>`, resolved after a day without one); the rotation guard's
  refusals and skips, counted; and, while the database probe fails, whether the daemon's last
  completed run logged that it could not connect. Each class reads on from its own cursor in
  `/var/lib/propolis/witness/jcursor/` (in `/run/propolis-witness/jcursor/` while the disk refuses
  writes), or the last 15 minutes without one; a cursor file or directory that is a link is not
  used. A cursor moves on only once the lines read were judged and the result written, so a pass
  cut short by its deadline, or one whose records could not be written, leaves the lines for the
  next pass. It reads to the end of the new entries and keeps only lines that carry its text, so a
  flood of other lines costs time, never a line it looks for. A read cut off by its time limit, or
  whose kept lines pass 1 MiB (a flood of lines that carry the text), is unknown for that pass,
  since a line past the cap would be lost unseen; after two in a row the class starts again
  from the last 15 minutes and the `witness` rail says `journal class <class>: lines may have been
  skipped`. No line, nor any part of one, is kept or shown: only counts (in `meta jlines`). Three
  more classes, each read by its account's uid: the gateway's line that it dropped a rebuilt batch
  (`gateway.service`, `propolis-gateway`; see [gateway-dup](#gateway-dup)), the shipper's ERROR and
  WARN lines on a collector (`shipper.service`, `propolis-shipper`; see
  [ship-failing](#ship-failing)), and the off-host pull's `served` line (`propolis-backup-pull`,
  identifier `propolis-backup-serve`), kept as `meta pull_last`;
- on a control node or gateway, lists the gateway spool's collector directories, as the gateway
  account where the spool is that account's, and judges each collector `PROPOLIS_SENSOR_LOGS`
  lists (see [spool-quiet](#spool-quiet)); a directory nobody listed is never read further, and a
  record or an `observe` line names a collector only by its opaque id;
- watches the backup run: one activating for longer than three times the last run's length, and
  never under two hours, opens `backup-hung` (see [backup-hung](#backup-hung));
- takes in the failure hook's spool files, then judges the first sightings the hook left
  pending for units that restart themselves: one restart that healed (systemd's `NRestarts`
  one above what the hook read, the unit up for over a minute) is dropped and counted as a
  restart that healed, never opened, also when the record goes back to the resolve it had; a
  unit still down, or restarting again, is opened. A oneshot's first sighting is dropped when
  its next run succeeded and opened while it is still failed. A sighting recorded after the
  pass read systemd waits for the next pass;
- opens a crash loop (`unit-crashloop`, `daemon-down` for the daemon) when `NRestarts` rose by
  three or more since the last pass, or by six within six hours, on two passes in a row, and a
  unit left in the failed state on two passes (`unit-failed`); a sensor that loops while
  config-check says its bind is not set opens `unit-nobind` (ACT, never reminded) instead;
- reminds each open incident at 1 h, 4 h and 12 h after it opened (PAGE) or 4 h and 12 h (ACT),
  once for reminders that came due while no pass ran, and resolves it with the proof of its
  kind: a long-running unit up 10 minutes without a restart (the daemon: `/ready` 200 on two
  passes five minutes apart, a few seconds' rounding of the passes' stamps allowed), a crash loop
  quiet for 30 minutes
  (the restarts before those 30 minutes then no longer count toward the six-in-six-hours rule),
  a oneshot's next run succeeding after the failure, or a unit disabled on purpose (a oneshot
  whose timer is disabled or no longer exists, a unit systemd no longer knows). The third
  reopen within a day holds the next resolve for an hour;
- judges the hourly pass (below);
- writes its line in `/run/propolis-witness/heartbeat`, `meta light_last`, and the login banner;
- last, when `PROPOLIS_WITNESS_HEARTBEAT_URL` is set, asks that URL once (below).

Every probe of a light pass runs before it takes the state lock, and none starts unless its whole
time limit (the account lookup and journal read of the daemon's tie, the `ss` lookup and GET of
`/ready`, the listing of the undelivered files, the spool listing and each class's account lookup
and journal read among them) ends within 160 s of the pass's start;
one that cannot is unknown for that pass. Only the ownership checks' `stat` and `readlink` of the
daemon binary's path have no limit of their own, as the reads of the state files have none.

**Under profile v2 (no host can set it in this release; only the tests reach it).** Each
transition that adds to `would_push` in the default profile is sent as an incident message
(`deploy/witness.sh#send_admit`, `deploy/witness.sh#send_post`), and nothing else changes:

- Under the state lock, in the same locked section that applied the transitions, the gate is
  asked once; with it short of full nothing is admitted or sent and the transition is only
  recorded. Otherwise each transition is put to the send budget
  (`deploy/alert-lib.sh#pa_incident_admit`): an admitted one gets its `pending` line in the send
  ledger and then its pending transition in the record, both written before anything is posted;
  a withheld one gets a `W` line in the incidents file naming the budget's reason (none for a
  RESOLVED whose open never got through). No pass reads the `W` lines yet: the library holds the
  storm notice and the hourly summary that will list them
  (`deploy/alert-lib.sh#pa_withheld_since`, each counted against its own cap and never against
  the pool, the listener caps or a key), which count every line since the last notice, name the
  new incidents ten at most and count the rest, and, for a withheld open or reopen of a PAGE
  incident, name it in the title at priority 5; a line or a record out of form is counted and
  never named. The library also holds the pointer message for a topic not proven private, with a
  ref and nothing else (`deploy/alert-lib.sh#pa_render`), and can admit and record it in its own
  budget class (`deploy/alert-lib.sh#pa_notice_admit`). Nothing sends it yet: the rules for when
  a pointer is sent come with its senders. A record that is not whole, a kind the tables do not
  know and a send ledger no copy of which can be read are each withheld, never sent. A change or
  a reminder of an incident whose open or reopen is still pending is only recorded: the retry of
  that open renders the record as it then is. One message per incident and pass.
- With the lock released, each admitted message, oldest admission first, is claimed again under
  the lock just before its post (`deploy/witness.sh#send_claim`): the record must still hold that
  transition and its ledger line must still be the untried admission, and the line then takes
  this attempt, so no other pass posts it within 120 s. It is rendered from the record as it then
  is and posted, and its result is written under the lock by
  `deploy/alert-lib.sh#pa_incident_result`, the rule the failure hook writes its own by: `ok` and a
  refusal end the pending transition, a transient answer keeps it, and `ok` marks the incident
  delivered for an open, a reopen or a reminder, so a late open (the reminder of a withheld
  open) that gets through lets its RESOLVED follow; a change that gets through does not, so an
  incident whose open the operator never had sends no RESOLVED.
- `alert-path` opens on the next light pass when a server refused a message for good
  (`perm:<code>`, the cause the message names, such as `http.auth:403`) or when a transition has
  been undelivered for more than 15 minutes (the cause its last answer names: `http.server:<code>`
  for a 5xx, `net.connect` for no answer). A later incident message or daily message that gets
  through resolves it (`sent2xx`).
- Each pending transition, the hook's among them, in id order: at least 120 s after its
  admission and its last attempt it is claimed again under the lock (its ledger line rewritten,
  none added, so a retry is never counted twice) and posted. An hour after its admission, at once
  when its admission stamp is out of form, and at once when its ledger line is gone (a damaged
  send ledger replaced by an empty one), it is dropped, and the incident waits for its next
  reminder; a transition dropped for a lost line is no message waiting on the alert path and
  opens no `alert-path`. In the default profile none of this runs, and a pending transition is
  left as the previous release leaves it.
- No claim starts once the pass has run 200 s, and its wait for the lock ends by then; what is
  claimed is posted, and what is left stays as it was admitted for a later pass. Each post is
  bounded by the sender's 40 s, each lock wait by 10 s and each journal line by 5 s, so a light
  pass ends by 365 s with the daily message and the heartbeat URL, inside the unit's 15 minutes.
- A message the failure hook sent without the lock is charged to the send ledger once, when the
  pass takes in its spool file, in the class the budget would have given it, its last attempt the
  hook's firing and its transition word `hook-open`, so it is never taken for the admission of
  that incident's own open, which the same pass can make in the same second when the hook's post
  was refused; the file is removed once a write of the records holds it, the first being an
  admission's when there is one, so a later write that fails cannot have it counted twice. One
  that got through opens its record and marks it delivered, so no second open follows. One whose
  result never came (`sending`) may not have gone: its line is a claim (`pending`) and the open
  of its record is pending, so a retry after the 120 s floor sends it (at most one duplicate).
- A record folded under a parent that resolved, and still failing half an hour later, opens on
  its own and its message says `was folded under <id>`.
- Each pass posts what it admitted itself: the hourly pass its own kinds' transitions, claimed
  with itself as the sender, since no other pass judges them. An admission no pass ever posted (a
  pass stopped between admitting and posting) is not dropped at the hour: the next pass that
  retries posts it.
  While the light pass is stale (as for the daily message) the hourly pass stands in for it for
  the hook's records and its own kinds: it samples the units when the whole sample (43 s) fits
  before its soft deadline, takes in the hook's spool files, judges the first sightings the hook
  left pending by the light pass's rule, sends the reminders that fall due on the hook's records
  and its own kinds, posts what it admitted and retries what is pending; its sends stop at 720 s
  and it ends by 870 s.

**The heartbeat URL.** `PROPOLIS_WITNESS_HEARTBEAT_URL` is the ping URL of an external dead-man
check, such as a private healthchecks.io check with no public status page. Put it in
`/etc/propolis/alert.env`, which only root reads and the daemon does not load. It is read from
`propolis.env` when `alert.env` does not set it, but `propolis.env` is the daemon's
`EnvironmentFile`, so a URL there is also in the environment of the internet-facing daemon
process, readable by the `propolis` account through `/proc`. After a light pass that was complete
and clean, the witness sends it one GET (no body, no redirect, 10 s at most); the check's service
alerts when the GETs stop. It is skipped while systemd could not be asked, the state lock could not
be had or no state could be written, while `alert-path` is open, while a transition has waited
over 15 minutes (only profile v2 sends one; under v2 one is dropped an hour after its
admission), or when a check could not tell on that pass and no `tool-unusable` record says so
yet; after a skip it resumes only once 30 minutes have passed clean. A pass that could not write
`meta` keeps its skip in `/run/propolis-witness/hbskip` (0600), and the next pass that can moves it
into `meta`, so the 30 minutes hold for those passes too. A standing limitation that is already
recorded (`tool-unusable` open) does not stop it, or the dead-man check would fire every day.
Skipping is the only signal: there is no failure URL. The URL is a secret, since whoever has it can
keep the check quiet: it reaches curl only through a file only root can read, and is never written
to a state file, the journal, the banner or the walk. Only `https://` URLs are asked; any other is
refused with one journal line and the walk reads `heartbeat URL refused (not an https URL)`. `meta
hb_last` keeps the time and the result of the last GET, `meta hb_skip` the time and reason of the
last skip.

Each hourly pass, all slow work first and without the state lock:

- runs the installed config-check (`/usr/local/lib/propolis/config-check.sh --tsv --no-events
  --report-only`, under `timeout 300`, only after the same ownership check every program root
  runs must pass) and records its findings (see [config-check found something](#finding)); a
  run that does not complete on two hourly passes in a row opens `cc-stopped` (ACT, `witness`
  rail). `meta cc_last` holds when the hourly pass that ran it started, its exit status (`-`
  when it was not run: missing or not trusted) and how long it took; `meta cc_skipped` holds how
  many of its lines the last completed run printed out of form, which the `witness` rail shows;
- runs the anonymous-read check: three GET requests without credentials to the configured
  ntfy server for the alert topic (its `json`, `raw` and `sse` read paths, each asking only for
  the last second, so nothing stored is fetched), and one more with the token when one is set.
  A user and password written into the URL are taken off those three, and without a token one
  more request carries them, to learn whether they can read the topic. Over plain `http://` no
  request carries a credential: the gate never gives `full` there whatever the answer, and the
  request would carry the credential in clear.
  The topic and the token go to curl in files only root can read, never on a command line. A
  401 or 403 on all three is `refused`; a readable answer, a login page, a redirect, a 404 or
  anything else is recorded by that name; a 429, a 5xx or no answer at all changes nothing
  already decided, except that a definite answer about the credential got in the same attempt is
  kept. The answer is stored in `/var/lib/propolis/witness/readcheck` with a hash of the URL and
  topic, and with a salted hash naming the credential it is about, so a changed target, token or
  URL user is checked again by the next light pass. With a target in `/etc/propolis/alert.env`
  the check is made of both targets, the shell senders' (line of role `shell`) and
  `propolis.env`'s, where the daemon and today's failure hook post (role `daemon`); a change of
  either voids only its own line;
- checks the light pass: its timer active and enabled, and a pass completed within 20 minutes;
- samples the free space and inodes of every store's filesystem (see [volume](#volume));
- on a single box or control node, reads whether a crontab line or an enabled timer runs the
  public push, the push marker and the feed's publish marker, and records `push-failing`,
  `push-unscheduled` or `push-off` (see [push-failing](#push-failing));
- on a single box or control node, counts the scheduled backup sets against
  `PROPOLIS_BACKUP_KEEP`, reads whether an off-host pull is configured, and records
  `backup-retention` and `backup-offhost`; a failed backup folds under `db-unreachable` or the
  backup volume's record by the step it failed in (see [backup-hung](#backup-hung));
- when config-check reported exactly one unlisted spool, names its collector by opaque id in the
  folded finding's instance, found by matching config-check's key hash against the spool's names;
- where `DATABASE_URL` is set, reads the database's state in one read-only session (see
  [db-state](#db-state)), and once a day, for a local database, `SHOW data_directory` as the
  `postgres` account through `setpriv` (never as root, and with a reset environment), kept in
  `meta pg_datadir` and `pg_datadir_stamp`; psql's error text is never kept;
- hashes the files that configure Propolis, one `H` line each in `observe`: the env files in
  `/etc/propolis` and `backup-recipients.txt`, the Propolis unit files and their drop-ins in
  `/etc/systemd/system`, `/etc/logrotate.d/propolis-sensors`, `/etc/tmpfiles.d/propolis.conf`,
  `/var/lib/propolis/deploy-stamp.json`, `/usr/local/sbin/propolis-*` and
  `/usr/local/lib/propolis/*` (sha256 of the content), and the binaries `deploy/upgrade.sh`
  installs in `/usr/local/bin` (their inode, size and modification time). Only files root owns
  are read, never through a link. Of an env file it keeps a hash of the whole file and the first 8
  hex digits of a hash of its sorted key names: no value, nor a hash of one, is stored, and no line
  of it is printed or logged. Each line keeps when the current content was first seen, and when the
  content before it was last seen;
- asks systemd, for each Propolis unit, which env files it loads, whether it needs a daemon reload
  and its main process, and reads that process's `/proc/<pid>/exe` link. The NOTICE
  `change-pending` (key `change:<unit>`, `host` rail) opens on two hourly passes in a row for a
  running unit an env file of which changed after it started (the content before the change was
  still seen after the unit's start, in the same boot; or, when the unit started between the pass
  that last saw the old content and the one that first saw the new, or that last pass was in
  another boot, the file's last change time is later than the start; once the clock was stepped
  since the start, the pass that first saw the new content decides: a unit restarted after the edit
  already runs with it), for a unit systemd needs a daemon reload for, and for one whose binary
  was replaced while it runs (`(deleted)`); two clean passes resolve it. A pass that could read no
  running unit's `/proc/<pid>/exe` link reads the check as unknown (`tool.exec`), since a replaced
  binary could not be seen. The `host` rail notes `changed, not in
  force: <n> units`, and `sudo propolis-status host` names each and the fix (restart it, or `sudo
  systemctl daemon-reload`).

Then, under the lock, it reads the state files again and changes only its own records, its own
lines of `observe` (the `Z` and `H` lines and its own `P` lines) and its own `meta` keys, so what
the light pass or the failure hook recorded meanwhile is kept. Every read of the stores, the
database, the watched files, the push and the backups starts only when its whole time limit still ends within 570 s of the
pass's start; one that cannot is unknown for that pass. A pass that has run for 720 s judges
nothing more and marks itself `partial`.

Each pass judges the other one from outside: a timer that is not active and enabled, or a pass
older than 3 hours (the hourly pass) or 20 minutes (the light pass), seen on two checks in a row,
opens `witness-stale` (ACT, key `witness:hourly` or `witness:light`), which resolves when the
other pass is fresh on two checks. The age of a pass is the newer of its heartbeat line and its
`meta` stamp, because a reboot empties `/run`. A pass that has never run counts from when its
timer started, so a host just upgraded gives the new hourly timer its three hours. Nothing is
judged in the first 30 minutes after a boot, when the hourly timer's first run may still be
minutes away; a first sighting such a check cannot judge is dropped, so the two stale checks
that open it are two in a row.

A failure is recorded only under a unit name as systemd gives one (`sensor-ssh.service`, not
`sensor-ssh`), and the witness asks systemd about no other word. The hook started by hand as
`propolis-alert@sensor-ssh.service` is passed the bare word `sensor-ssh`: its alert goes out as
before, nothing is recorded, and the journal says `incident not recorded for -: the unit name is
not one systemd gives` under tag `propolis-witness`.

The witness opens nothing in the first ten minutes after a boot, while a maintenance marker
holds (an upgrade, a rollback, or `sudo propolis-status --maint MINUTES` for planned work: see
[commands](../reference/commands.md#status-walk)), or in the ten minutes after a pass last saw a
marker (`meta maint_seen`), so the restarts planned work causes have settled first, and
restarts made under a marker or in those ten minutes no longer count toward the
six-in-six-hours rule afterwards. A first sighting held then stays pending, a spooled one
included. One held under a marker is flagged `maint`, by the hook or by a pass, and a record
flagged `maint` is held for ten minutes from its sighting even when no pass saw the marker; a
sighting held only by the boot grace is not flagged and opens on the first pass after the
grace. A fault that comes back inside its reopen window carries the flag only when this
sighting came under a marker. (The failure hook itself still opens a oneshot's failure at once
in the first ten minutes after a boot and in the ten minutes after a marker ends.) In the first
half hour after a boot a sensor's loop stays pending until
a config-check result exists, since without one an unset bind cannot be told from a crash. A
check that cannot run marks the pass `partial` and the pass still exits 0; three in a row open
the NOTICE `tool-unusable`. A pass that has run for 240 s judges nothing more, keeps what it
did and marks itself `partial`. When the state lock is not free within 60 s the pass writes no
state, logs `state lock busy for 60 s; pass skipped` under tag `propolis-witness`, marks its
heartbeat line `partial`, and the walk's header and the banner say `state lock busy` until a
pass gets it again; when no lock file can be opened at all the banner says `state NOT
PERSISTED`.

The walk's `witness` rail is FAIL when `propolis-witness@light.timer` or
`propolis-witness@hourly.timer` is not active, when no light pass has completed for 15 minutes
(not judged in the first 30 minutes after a boot), when `cc-stopped` is open, or when the banner
is missing or older than 15 minutes while the pass itself is fresh: `banner not written` means the
pass runs but `/run/motd.d` is missing or refuses the write (`sudo systemd-tmpfiles --create
/etc/tmpfiles.d/propolis.conf` recreates it). It warns when the hourly pass is over two hours and
ten minutes old, when its timer fired over 15 minutes ago and no hourly pass has ever completed
(`no hourly pass has completed (the timer fired at <time>)`), when the last config-check exited
with a status above 2 or was not run at all (`last config-check not run (missing or not
trusted)`), when the last completed run printed lines out of form (`config-check printed <n>
lines out of form`), and when a hook spool file has waited over 10 minutes. First check `systemctl status propolis-witness@light.timer
propolis-witness@hourly.timer` and `journalctl -t propolis-witness`; `sudo propolis-status
witness` shows the timer, the heartbeat lines, every `meta` key, the restarts that healed, the
spool, the lock count and the maintenance marker.

**The gate.** The `ALERTS` line of the walk shows `gate full`, `gate pointer:<reason>` or `gate
none:notarget`, with when the read check last ran. It is worked out from the stored answer alone,
without asking the server: `full` only when the stored answer is for the target in use, is
`refused`, was decided within 24 hours, an attempt was made within 3 hours, the URL is `https://`
(over plain HTTP anyone on the path could answer 403 and read the rest), and, on a collector or a
host whose role cannot be told, the credential a post carries (its token, or without one a user
and password written into the URL) is proven unable to read the topic, or there is none. The
gate reads the stored line of the shell senders' own target (role `shell`, or `both`), never the
daemon's, so a refusal of one target never makes the other's gate full. Proven means a stored
`noread` about that very credential: an answer of unknown, an answer about another token (one
changed since the check), and a line from before credentials were named all hold pointer
(`pointer:token-unknown`), as does a credential that reads (`pointer:token-reads`). A
credential's GET that got no answer keeps what was known of the same credential, so a timeout
cannot lift a collector out of pointer mode. The daily message is sent only while the gate is
`full`, and only from the host that runs the daemon. The
`alert` rail warns while the gate is not `full`, and while the daemon's own topic (in
`propolis.env`, where today's failure hook sends this host's name and the failed unit) is not
proven private on the same terms (refused within 24 hours, an attempt within 3 hours, over
`https://`), and it lists what each stored answer was.

**The login banner.** At the end of every light pass the witness writes `/run/motd.d/propolis`,
which `pam_motd` shows at login: four lines of closed words and counts, each with the time it was
written, for example:

```
[propolis 15:20 UTC] 2 open (PAGE 1, ACT 1); profile legacy
[propolis 15:20 UTC] alerts: topic not checked yet
[propolis 15:20 UTC] run: sudo propolis-status
[propolis 15:20 UTC] rewritten every 5 min; older means the witness stopped
```

The alerts line reads `topic READABLE by anyone` when the stored read check of the alert topic
found it readable, and `topic not proven private (<answer>)` (`redirect`, `not found`, `not a push
server` or `unexpected`) for any other definite answer that is not a refusal; when the gate holds the refusal proven (refused within 24
hours, an attempt within 3 hours, over `https://`), what the last test page proved:
`VERIFIED <dur> (shell)` or `NOT VERIFIED (<word>)` (below), followed by `; daemon not verified`
where the daemon is enabled; `topic not proven private (plain http)` for a refusal over plain
HTTP, which anyone on the path could have given, `topic check is stale` when the refusal or the
last attempt is too old, `topic not checked yet` while there is no answer for the target in use,
and `NO PUSH TARGET (journal only)` without a target. Where the shell senders have no target
(a URL and topic split across files, or a value `alert.env` sets that is not valid) and
`propolis.env` still names one, the daemon and today's failure hook post there: the line then
gives that topic's answer (`topic READABLE by anyone`, or not proven private) and otherwise
`no shell target; failure hook still posts` while the hook's own reader finds a URL and a topic
(`deploy/alert-lib.sh#_pa_banner_daemon`).

**Setup, the test page and VERIFIED.** `sudo propolis-status --setup` says what reaches you and
why: the alias the test page and the daily message name this host by (today's failure alerts name
it by its host name), the push target (never the topic or the token), the anonymous-read check
made then and there with its answer in words, the gate, which governs the daily message, what the
daemon and today's failure hook, which are not gated, reveal on a topic that does not refuse
anonymous reads or over plain http, where the alias comes from, when the daily message goes, and
the private heartbeat URL it recommends. With a target in `/etc/propolis/alert.env` the target
line names `alert.env`, and a `daemon` line names `propolis.env`'s target, where the daemon and
today's failure hook still post, with its own anonymous-read answer; a URL in one file and the
topic in the other is no target, and `--setup` says the target is split across files. Over
plain http the token line reads `not asked`. The walk says `shell target from alert.env: test
pages and the daily message go there` and lists the answer for each topic, and names a mistyped
`PROPOLIS_ALERT_PROFILE`, or `v2`, which this release does not put in force.
`sudo propolis-status --test-page` sends one test page
through the failure-alert unit (at most three a day), and `sudo propolis-status --ack-test <code>`
types back the code it carried ([commands](../reference/commands.md#status-walk)). Apart from
today's failure alerts, which the hook sends as before, the shell code sends only the test page
and [the daily message](#the-daily-message).

`VERIFIED` (`deploy/alert-lib.sh#pa_verified`) means: a test page sent by this host's
failure-alert unit, to the target and with the token now in the files, reached a phone whose owner
typed the code back, at most 30 days ago, and since then no message was refused for good, no
`alert-path` incident opened and the failure hook left no alert undelivered. The page proves the
unit, the network and the shell senders' target (`alert.env`'s when it names one, else
`propolis.env`'s). Where that target is `propolis.env`'s, today's failure hook reads that file
with a rule of its own (the last line that starts with `KEY=`), so VERIFIED also requires the
hook to read the same URL, topic and token, and none of them to be ignored as invalid
(`deploy/alert-lib.sh#pa_hook_differs`, which compares the hook's reading with the library's
reading of `propolis.env`, never with `alert.env`); with the target in `alert.env` the page says
nothing of where the hook posts. Otherwise the walk says `NOT VERIFIED` with the
first rule that fails: `never` (no test page), `pending` (not typed back), `changed` (another URL,
topic or token since, or one today's hook reads otherwise), `expired` (over 30 days or dated
after now), `refused`, `path-failed`, `undelivered`, or `unreadable` when a file it needs cannot
be read; the banner says the same once the gate is `full` or held at `pointer:token-reads` or
`pointer:token-unknown` (`deploy/alert-lib.sh#_pa_banner_alert`), and before that the reason the gate gives. A send that
failed only for now (a timeout, a 429 or a 5xx) undoes nothing. It does not prove the daemon's
sender, which read its settings when it started, runs in its own sandbox and may hold an older
topic or token: the walk and `--setup` say `daemon not verified` wherever the daemon is enabled,
and the banner wherever it shows VERIFIED, and the walk adds `the daemon loaded an older
configuration: restart propolis to apply it` when `propolis.env` changed after the running daemon
started. Nor does it prove that later pages arrive: a token revoked tomorrow shows as `NOT
VERIFIED` only after a send fails.

It names no host, unit or log, and it is root-only (`0600`): it says whether alerting works right
now, which a compromised sensor that can read `/run` must not learn. `pam_motd` reads it as root.
An older time means the witness stopped. `sudo propolis-status --banner` prints the same text.

### The daily message

Once a day the witness on the host that runs the daemon (a single box, or the control node of a
split deployment) sends one low-priority message (ntfy priority 2) to the push target, so
that its absence tells you to look (`deploy/witness.sh#daily_prepare`,
`deploy/alert-lib.sh#_pa_render_daily`). A collector or a gateway-only host sends none: a
deployment gets one a day, and the control node's counts the collectors it lists. It looks like
this:

```text
Title: host-3fa2: daily
open: 2 (PAGE 0, ACT 1) w#12 w#14
resolved 24 h: 1; withheld by budget 24 h: 0
new notices 24 h: 1; clock step +300 s
alerts: VERIFIED 3 d (shell); profile legacy
v2 would have pushed 4 in 24 h
state: persisted
Do: status
```

The title is the alias (`PROPOLIS_OPS_HOST_ALIAS`, else the fallback from the id salt) and the
word `daily`. The body holds only counts, opaque incident ids (`w#<n>`, which `sudo
propolis-status` maps to what they are), VERIFIED, the profile and whether the state is kept:
the open incidents by tier with up to ten ids, the resolves and withheld messages of the last 24
hours, the notices opened in the last 24 hours (a standing notice is in the walk, not here) with a
clock step of that time, what the `v2` profile would have pushed in 24 hours (counted from the
times each record keeps: its last open, its reminders by their schedule, its last change and its
resolve), on a control node the listed collectors and how many are quiet, and `state:
persisted`, `not persisted (run)` or `not persisted (none)`. It never holds the host name, a unit,
sensor or collector name, a finding, a cause, a path, an address, the topic, the token, a journal
line, the word that names the software (`Do: status` stands for `sudo propolis-status`) or any
text another account or a remote party chose. It has no `daemon not verified` line: nothing can
clear that before the daemon gets a test page of its own, so it stays in the walk and the banner.

**When it is sent.** By the light pass, once the host's local time of day (its own zone, not the
UTC the witness uses for everything else) is past `PROPOLIS_OPS_DAILY_AT` (default `08:41`), on
a local date it was not sent on, and at least 20 hours after the last one (so a summer-time change
or a late message never brings two close together). The hourly pass sends it only while the
light pass is over 15 minutes stale, and both decide under the state lock from `meta` and the
send ledger, so only one of them sends. It is counted before it goes (`meta daily_last` and
`daily_last_stamp`, then a ledger line of class `daily` already claimed as `sending`), so a send
that failed, timed out or was cut short by a killed pass is not tried again that day.

**When it is not sent.** On a collector, a gateway-only host or a host whose role cannot be told
(the walk says `daily off: only the host that runs the daemon sends it`);
`PROPOLIS_OPS_DAILY_AT=off` (it is never sent, and the walk and
`--setup` say so; `off` in any letter case, and `false`, `no`, `n`, `0`, `none`, `never`, `stop`,
`disable` or `disabled`, alone or with a blank or a punctuation mark after the word, such as a
comment or a quote, are all read as `off`); the gate is not `full`:
no target, a URL that is not `https://` (over plain
http anyone on the path can answer the read check's 403 and read what is sent), a topic that is
readable or not proven to refuse anonymous reads, or a read check whose refusal is over a day old
or whose last attempt is over three hours old;
no state can be kept (`state NOT PERSISTED` with nowhere to write, which would forget that it was
sent); the send ledger cannot be read (a count that cannot be made is not zero); there is no
alias yet because the id salt could not be written; curl is not installed; the host's local time
cannot be told; the pass is past its time limit; neither pass ran. An empty
`PROPOLIS_OPS_DAILY_AT` is the default, and any other value that is not `HH:MM`
keeps `08:41`, and the walk and `--setup` say so. The walk's `ALERTS` block has a `daily` line:
the host's time of day, then, in UTC like every time the walk prints, when the last one went with
the server's answer (`last sent <time> UTC (ok)`, `last sent <time> UTC (result not recorded)`
when the pass never wrote the answer, `last tried <time> UTC, not delivered (<result>)`, or `last
counted <time> UTC (the send ledger holds no line for it)` when the message was counted and its
ledger line could not be written, so nothing went, or is over two days old) and, while the 20
hours since it hold the next one back, `next not before <time>
UTC`; or `daily off (PROPOLIS_OPS_DAILY_AT=off)`,
`daily off: topic readable`, or `daily off: gate <gate>`; and, when `PROPOLIS_OPS_HOST_ALIAS` is
refused, `invalid value ignored: PROPOLIS_OPS_HOST_ALIAS (the fallback alias is used)`. Both
settings take effect at the witness's next pass with no restart; where the daemon runs,
`propolis.env` is also its `EnvironmentFile`, so editing it opens the change-pending notice and
the walk's older-configuration line until `propolis` is next restarted, which can wait. A time after
`23:50` may skip days, since a pass must fall between it and midnight.

**What its absence means.** The first message goes on the first light pass after the upgrade
that installs it, whatever the time of day, once the local time is past `PROPOLIS_OPS_DAILY_AT`
(on an afternoon upgrade, that afternoon). A message is never sent within 20 hours of the one
before, so one that went late (that first one, or one after a day the witness was down until
late) moves the next one later by as much: after a message at 15:05 the next goes at 11:05 the
day after, not at 08:41, and the walk's `next not before` says when. Otherwise, if you get it
every morning and it has not come an hour after `PROPOLIS_OPS_DAILY_AT`, one of these holds: the
host, its witness or its way out to the push server is down; the topic became readable or is no
longer proven private; or the setting changed. Each needs a look, and `sudo propolis-status` says
which. On a private topic its absence
tells an outsider nothing, since they cannot read the topic. On a readable topic it is never
sent, so there its absence means nothing; that is one reason `--setup` recommends a private topic
and a private heartbeat URL (`PROPOLIS_WITNESS_HEARTBEAT_URL`), which notices a host that stops
within minutes rather than by the next morning.

## Endpoints

The console router exposes three public (no session) probe endpoints plus `/login` and the
font assets; every other route is session-gated (`crates/console/src/routes/mod.rs#router`).
The console binds loopback-only by default (`127.0.0.1:8080`); there is **no in-process TLS**
(plain HTTP on a `TcpListener`), so any TLS termination and any exposure beyond loopback is an
operator-provided reverse proxy. See [networking and TLS](./networking-tls.md).

| Endpoint | Purpose | Success | Failure | Cite |
|---|---|---|---|---|
| `GET /health` | Liveness only; does not touch the DB | `200 {"status":"ok"}` (always) | none | `crates/console/src/routes/health.rs#health` |
| `GET /ready` | Readiness; pings Postgres `SELECT 1`, then checks no supervised subsystem has given up (unified daemon only; the standalone console supervises nothing) | `200` | **`503 {"status":"unavailable"}`** on any DB error (fail-closed); **`503 {"status":"unavailable","gave_up":[...]}`** naming the dead subsystems | `crates/console/src/routes/health.rs#ready` |
| `GET /metrics` | Prometheus text (`version=0.0.4`) | `200` | derived live per scrape | `crates/console/src/routes/metrics.rs` |

Use `/health` for a liveness check that a process is up, and `/ready` for a
load-balancer/monitor readiness check that also proves the DB is reachable. `/metrics` carries
no session gate and, unless `PROPOLIS_CONSOLE_METRICS_TOKEN` is set, no bearer check; leaving it
open is acceptable only because the console is loopback-only
(`crates/console/src/routes/metrics.rs`, `crates/console/src/routes/metrics.rs#metrics`). If you proxy the console, do not expose `/metrics` publicly.

## Fleet pane: listener activity

The fleet pane (`/fleet`, session-gated) has one row per listener in the inventory
(`PROPOLIS_FLEET_LISTENERS`, see [environment variables](../reference/environment-variables.md)).
A listener is a sensor name, a transport and a port. Its **Last event** and **24h** columns count
the events whose `sensor`, `protocol` and `metadata.local_port` match it; `local_port` is
stamped on every event by the sensor framework (see
[events and signals](../reference/events-and-signals.md#arrival-metadata-key)). So HTTP's 80 and
443, two Redis ports, or the catch-all's TCP and UDP listeners on one port number each show
their own numbers (`crates/console/src/routes/fleet.rs#attribute`).

Both columns read bounded ranges of the ledger, never the whole of it, on every load and every
30-second refresh (`crates/console/src/routes/fleet.rs#listener_activity`):

| Column | Reads | Outside the range |
|---|---|---|
| 24h | events with `observed_at` in the last 24 hours | not counted |
| Last event | the newest event in the last 30 days (`crates/console/src/routes/fleet.rs#ACTIVITY_LOOKBACK`) | `none in 30d`, which is also what a listener that never produced an event shows: the pane cannot tell the two apart without reading the whole ledger, so it does not claim `never` |

The **Ledger** cell and the Evidence chain panel's **Events** row do not count the table either
(`crates/console/src/routes/fleet.rs#ledger_head`, `crates/console/src/routes/rowcount.rs#capped_total`).
Up to 100,000 events the number is a count and is shown bare. Past that it is the planner's row
estimate (`pg_class.reltuples`, refreshed by autovacuum), shown as `about N` with the label
`(estimate)`; it is never below the rows a count had already seen. The newest-ingest time is read
off the newest row by `id` rather than `max(ingested_at)`, which has no index and reads every row.
The Attackers page's total uses the same rule.

Events recorded before sensors stamped `local_port` have no port. A sensor whose inventory
declares exactly one listener received all of them there, so they count on that row. A sensor
with several declared listeners gets one extra row labelled `port not recorded` holding those
events, rather than a guess at which port they came in on. That row is not a listener: it is left
out of the listener total and the headline, its dots stay neutral, and it disappears once the
pre-upgrade history is older than 30 days.

A listener present in the ledger but not in the inventory gets an `undeclared listener` row with
its transport and port. A sensor the inventory does not name at all keeps one such row with no
port for its pre-upgrade events.

### Behind badge

**Last event** is the newest event in the ledger, so when intake is behind a sensor's log it
shows how far intake has read, not when the sensor last saw traffic. A listener row whose log is
behind says so under that column, as `behind: 6.6 GB / 11 d`: the unread bytes of the log and
how long its oldest unread line has waited (see the two intake metrics below). The badge appears
only while that wait exceeds the `intake-lagging` age threshold, ten minutes or three intake
polls, whichever is longer, so a caught-up or idle sensor shows nothing
(`crates/console/src/routes/fleet.rs#behind_by_sensor`). It is matched to rows by the sensor names
the log's events carried, not by the `PROPOLIS_SENSOR_LOGS` label (a `cred-vnc` log's events say
`vnc`), so a log that has not appended an event since the daemon started cannot badge a row yet.
It is the instantaneous reading; the ops alert below adds persistence and a growth rule. The
standalone `console` binary tails nothing and never shows it. What to do about it:
[intake backlog](../troubleshooting/intake-backlog.md).

## Metrics

`/metrics` derives everything from live DB queries plus the feed `manifest.json` on every
scrape; there are no pre-aggregated counters, so a scrape reflects current state
(`crates/console/src/routes/metrics.rs#metrics`). Emitted series (`crates/console/src/routes/metrics.rs#metrics`):

- Gauges: `propolis_ips_scored`, `propolis_ips_eligible`, `propolis_ips_recommended_vendor`,
  `propolis_ips_recommended_blocklist`, `propolis_review_queue_pending`,
  `propolis_volume_review_pending` (pending volume candidates, counted apart from the review
  queue), and the stored shell
  reply table's `propolis_shell_output_rows` (planner estimate) and `propolis_shell_output_bytes`
  (table plus indexes), read from the catalog so a scrape never reads the table
  ([retention](retention.md#stored-shell-replies)).
- Counter: `propolis_vendor_submissions_total{vendor,status}`.
- Malware pipeline (the work, not the process): `propolis_fetch_attempts{status}`,
  `propolis_fetch_pending_oldest_age_seconds`, `propolis_sample_analysis{state}`
  (`pending` = uploaded to VirusTotal, no verdict yet; `scanned`; `not_uploaded` = kept
  local because the content is not executable or script content),
  `propolis_sample_analysis_pending_oldest_age_seconds`, and, where the process can read
  the spools (the unified daemon, not the standalone console), `propolis_spool_samples{spool}`
  and `propolis_spool_oldest_sample_age_seconds{spool}`. An age gauge is `0` when nothing
  is waiting; a spool series is absent, not zero, when unreadable.
- Feed (from `manifest.json` when a feed dir is configured): `propolis_feed_entries{tier}`,
  `propolis_feed_window_entries{window}`, `propolis_feed_last_build_timestamp`.
- In-memory process counters: `propolis_events_ingested_total`, `propolis_events_rejected_total`,
  and `propolis_intake_lines_quarantined_total` (lines intake set aside in the quarantine
  directory, see [Quarantined intake lines](#quarantined-intake-lines); zero in the standalone
  console, which tails nothing).
- Intake backlog, one series per intake log, labelled `sensor` with its `PROPOLIS_SENSOR_LOGS`
  name, from what each intake loop recorded after its latest poll (unified daemon only; the
  standalone console tails nothing and publishes neither, rather than a zero that would claim a
  caught-up log; `crates/console/src/routes/metrics.rs#push_intake_lag`):
  - `propolis_intake_bytes_behind{sensor}` - unread bytes of the log: the file past the read
    offset, plus the remainder of any rotated-out file still being drained, plus an unfinished
    last line (`crates/log-tailer/src/tailer.rs#backlog_bytes`). Absent until the log's first
    poll finishes.
  - `propolis_intake_oldest_unread_age_seconds{sensor}` - how long the oldest unread line has
    waited. `0` when the latest poll read every complete line. While complete lines are waiting,
    now minus the `observed_at` of the last event appended from the log, which bounds the wait
    of the next unread line. Absent while lines wait and no event has been appended since the
    daemon started, because there is nothing to measure from
    (`crates/propolis/src/ops_alert/conditions/intake_lag.rs#oldest_unread_age`).

  There is no append-latency histogram: the metrics endpoint emits gauges and counters only.
- Sensor capture health, one series per capturing sensor, labelled `sensor` (and, for a row read
  from a log whose `PROPOLIS_SENSOR_LOGS` name is bound to no sensor, which on a control plane
  means a collector's spool in a [split deployment](./split-deployment.md), also `collector`, set
  to that name; a name longer than 31 bytes is shortened to at most 14 bytes, `~` and a hash,
  the same for all of that log's sensors, `crates/fleet/src/stats.rs#collector_key`), from the
  latest `sensor_stats` line each wrote (see [Sensor stats](#sensor-stats); absent for a sensor
  that never reported, never a zero; `crates/console/src/routes/metrics.rs#push_sensor_stats`):
  counters `propolis_sensor_capture_queue_dropped_total`,
  `propolis_sensor_capture_spool_refused_total`, `propolis_sensor_capture_truncated_total`,
  `propolis_sensor_capture_refused_total`, `propolis_sensor_capture_budget_refused_total`;
  gauges `propolis_sensor_capture_budget_bytes`,
  `propolis_sensor_capture_budget_high_water_bytes`, `propolis_sensor_uptime_seconds`; and the
  freshness trio `propolis_sensor_stats_age_seconds`, `propolis_sensor_stats_stale` (1 past 180 s)
  and `propolis_sensor_stats_final` (1 when the last line was the sensor's shutdown line). The
  counters count since the sensor started and reset when it restarts.
- Console saturation counters, each moving only when a bound refused work (a steady rate
  means a login spray or a connection flood, not ordinary use):
  `propolis_console_login_refused_per_ip_total`, `propolis_console_login_refused_global_total`,
  `propolis_console_login_verify_busy_total`, `propolis_console_connections_shed_total`,
  `propolis_console_body_timeouts_total`. Limits: [rate limits and
  budgets](../reference/rate-limits-and-budgets.md#console-connection-bounds).
- `propolis_console_rollup_refresh_failures` (gauge): refreshes of the console's hourly event
  roll-up that failed in a row since the last one that worked. Above zero the dashboard and the
  fleet pane stay exact but read more of the ledger; at 3 they say so in the degraded banner. It
  moves only when a page that reads the roll-up is loaded.

`propolis_feed_last_build_timestamp` is the primary signal that the feed loop is still
publishing; see [retention](./retention.md) and [scoring and feed
reference](../reference/scoring-and-feed.md).

### Sensor stats

Each capturing sensor (ssh, telnet, adb, ftp, mqtt, tftp) appends a `sensor_stats` line to its
own event log every 60 s and a last one, with `final` true, when it shuts down. The line carries
the capture hand-off counters and the capture-memory budget that used to be readable only inside
the process; intake stores the latest per sensor, and `/metrics` publishes them (above). On a
[split deployment](./split-deployment.md) the control plane keeps one row per collector and
sensor, so the same sensor on two collectors is two sets of series, each with its own age:
`propolis_sensor_stats_stale{collector="collector-01",sensor="ssh"}` says whether that one sensor
is still reporting, whatever the others do.

- **Staleness, not zeros.** A sensor that stops writing keeps its last values and its age grows;
  `propolis_sensor_stats_stale` turns 1 after 180 s (three missed lines). `propolis_sensor_stats_final`
  says whether the last line was a clean shutdown, which separates a stop from silence. Age is
  measured from the sensor's own clock, so a stalled shipper or intake shows as stale too.
- **Not evidence.** The line is not in the ledger and not an event: its `source_ip` is the sentinel
  `0.0.0.0`, intake stores it in the `sensor_stats` table instead of converting it, and nothing
  that scores, feeds or reports reads that table.
- **Which log may report which sensor.** The line must name a sensor this system knows (the
  [origin policy](../reference/events-and-signals.md#what-a-log-line-may-claim-the-origin-policy)
  table). A log whose `PROPOLIS_SENSOR_LOGS` label is bound to a sensor (a single host's own
  logs) reports that sensor only, and its row is keyed by the sensor name. A log whose label is
  bound to no sensor (a collector's spool on a control plane, named after the collector, or a log
  under a label of your own) may report any known sensor, and its rows are keyed by the label and
  the sensor together (`crates/intake/src/runner.rs#stats_key`,
  `crates/fleet/src/stats.rs#collector_key`). Each rule is enforced in one place:
  - *Which collector.* The gateway appends a batch to the spool of the collector named in its
    client certificate, and intake keys the rows by that spool's label, so a collector writes
    only under its own label, at most one row per known sensor. Its rows stay apart from another
    collector's and from the control plane's own only while no spool's entry is named after a
    sensor or a `cred-*` label: such an entry binds the spool, its own sensor's rows are stored
    under the bare name, over the control plane's row, and `config-check` fails it as
    `spool-label-sensor` ([split deployment](./split-deployment.md#how-it-fits-together) names
    the entry after the collector id).
  - *Which sensor of a collector.* The control plane cannot tell, because the spool merges all of
    a collector's logs. The collector's shipper checks it, in each sensor's own log before it
    ships: a stats line that is malformed, names an unknown sensor or, in a bound log, names
    another sensor is dropped there, with the shipper's WARN `shipper: dropping a line the origin
    policy refuses for this log` (`crates/shipper/src/batcher.rs#admit`). A collector still
    running a shipper from before this check does not do it, so any sensor on that collector can
    write any other's row, and its counters are only as trustworthy as its least trusted sensor
    until its shipper is upgraded ([upgrading](./split-deployment.md#upgrading)). A collector
    compromised as a whole can write any of its rows either way.
- **Refused lines.** On a host whose intake reads the sensor's own log, a `sensor_stats` line
  from any other source, with extra or missing fields, or with a value past 2^53 is counted as a
  rejected line with a WARN `malformed sensor_stats line, refused`. On a collector the shipper
  drops such a line first, so it shows in the shipper's journal there and not in the control
  plane's count. One naming a sensor this system does not know logs `names a sensor this system
  does not know`, and one in a bound log naming another sensor logs `names a different sensor
  than this log's label`. None of them is stored.
- **A collector that is gone keeps its series.** Nothing deletes a `sensor_stats` row: several
  nodes can share one database, and no node knows every other node's labels. A collector that was
  removed, or [rebuilt under a new id](./split-deployment.md#rebuilding-a-collector), leaves its
  rows, and `/metrics` keeps publishing them, each with `propolis_sensor_stats_stale` 1 and an age
  that only grows, for example
  `propolis_sensor_stats_stale{collector="collector-01",sensor="ssh"} 1` beside the new id's
  series, so an alert on `stale == 1` keeps firing. Once intake has read the collector's spool to
  its end, its `PROPOLIS_SENSOR_LOGS` entry is gone for good and `propolis.service` is restarted
  (reading the rest of the spool would store its last stats lines again), delete its rows by hand with the daemon's
  `DATABASE_URL` from `/etc/propolis/propolis.env` (its runtime role may delete from this table,
  `crates/propolis/src/db_roles.rs#reconcile_runtime_grants`; the owner role may too). Set
  `collector` to the `collector` label exactly as `/metrics` prints it, which for a shortened
  id includes its `~` and hash; the statement matches the part of each key before its last `/`,
  so it deletes no other collector's rows and none of the control plane's own:

  ```sh
  # Example - collector-01 is the collector label of the series to remove.
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -v collector='collector-01' <<'SQL'
  DELETE FROM sensor_stats
   WHERE substring(sensor FROM '^(.*)/[^/]*$') = :'collector'
   RETURNING sensor;
  SQL
  ```

  It prints each key it deleted. Run it for a collector that still ships and its rows come
  back with its next line, a minute later.
- **Nothing to configure.** The interval is a constant
  (`crates/sensor-framework/src/handoff.rs#STATS_INTERVAL`).

## Logging

The daemon and sensors log through `tracing` to the systemd journal; read with
`journalctl -u propolis` (see [service lifecycle](./service-lifecycle.md)). Sensors also
append captured events as NDJSON to per-sensor log files under `/var/log/propolis/`, rotated
by logrotate (`size 100M`, `rotate 5`, `copytruncate`; `deploy/logrotate-sensors.conf`), run
hourly by `propolis-logrotate.timer` ([retention](./retention.md#log-rotation)). Paths are owned by [filesystem paths](../reference/filesystem-paths.md).

The console has a session-gated live log viewer at `/logs`, backed by an in-memory ring of the
**1000** most recent tracing events (`crates/propolis/src/main.rs#LOG_BUFFER_CAPACITY`,
`crates/console/src/log_buffer.rs#LogBuffer`), fewer when they are large: the ring is also held
to 2 MiB charged from the entries' allocated size
(`crates/console/src/log_buffer.rs#RING_BYTE_BUDGET`). Each entry keeps its structured fields,
capped at 512 bytes a value, 32 fields and a 2 KiB message
(`crates/console/src/log_buffer.rs#MAX_FIELD_VALUE_BYTES`,
`crates/console/src/log_buffer.rs#MAX_FIELDS`, `crates/console/src/log_buffer.rs#MAX_MESSAGE_BYTES`).
It is a convenience tail, not a durable log store; the journal and the NDJSON files are
authoritative.

For a live view of the NDJSON files themselves, every event as the sensor wrote it plus a
10-second heartbeat naming each configured log as `following`, `missing` or `unreadable`, run
the read-only `propolis-watch`, locally or over a forced-command SSH key; see
[live watch](./live-watch.md).

### Logging and journal priorities

Every binary installs one output format, the `log-format` crate
(`crates/log-format/src/lib.rs#init`, `crates/log-format/src/lib.rs#layer`), so the journal
carries the real level of each line and plain text:

| `tracing` level | journal `PRIORITY` | `journalctl -p` name |
|---|---|---|
| `ERROR` | 3 | `err` |
| `WARN` | 4 | `warning` |
| `INFO` | 6 | `info` |
| `DEBUG`, `TRACE` | 7 | `debug` |

`journalctl -u 'sensor-*' -u propolis -p warning` therefore lists the warnings and errors, and any
alert keyed on journal priority sees them. Before this, every line was priority 6 with ANSI colour
escapes in the message, so a priority filter matched nothing.

The mechanism is the `<N>` line prefix of sd-daemon(3). Under a service, systemd connects stdout
to the journal and journald strips a leading `<N>` into the entry's priority unless the unit sets
`SyslogLevelPrefix=false` (default on; systemd.exec(5)). No unit in `deploy/` turns it off; with it
off the prefix would show as text at the start of each message. The prefix is written only when
`$JOURNAL_STREAM` names this process's own stdout (device and inode, as systemd.exec(5)
prescribes), so a process whose stdout was redirected to a file or pipe, or one that merely
inherited the variable, writes plain lines (`crates/log-format/src/lib.rs#is_journal_stream`).

- **Terminal:** unchanged, the stock coloured format. `NO_COLOR` set to a non-empty value turns the
  colour off.
- **File or pipe:** the same text with no colour and no prefix.
- **Journal:** the same text with the prefix and no colour.

Off a terminal each event is also one line: control characters in a message or field value, a
newline above all, are written as `\n`, `\u{1b}` and so on. The stock formatter leaves a newline in
message text alone, and journald reads a priority prefix at the start of every line, so a captured
attacker string containing a newline and `<0>` would otherwise forge an emergency entry
(`crates/log-format/tests/format.rs#journal_mode_cannot_be_made_to_forge_a_priority_line`).
A line is also cut at 16 KiB with a `...[truncated N bytes]` marker, because journald splits a
line that reaches `LineMax` (48K by default, journald.conf(5)) and reads a priority prefix again
at the start of the tail
(`crates/log-format/tests/process.rs#a_field_past_journald_line_max_stays_one_capped_line`).

The timestamp the format prints stays, although journald stamps each entry itself, so the text is
identical whether it was read from the journal or from a captured stdout. Entries journaled before
the upgrade keep priority 6.

### Overload counters

Two capture-hand-off counters, surfaced as journal WARNs, tell an operator that samples are
being lost under load. Both are covered operationally in [queue and
spool](./queue-and-spool.md); in summary:

- **Dropped (queue full).** When the bounded capture queue is full, `submit` drops the job
  rather than blocking, increments `dropped_count`, and logs a WARN at **power-of-two totals**
  (first drop, then 2, 4, 8, ...) so a sustained flood degrades to logarithmic noise instead of
  filling the log partition (`crates/sensor-framework/src/handoff.rs#submit`).
- **Spool-refused.** A body the spool rejects (per-file cap or exhausted global budget)
  increments `spool_refused_count` and logs a WARN at power-of-two totals. No sample results, but
  the upload event is still emitted, marked `stored: false` with a `not_stored_reason`
  (`crates/sensor-framework/src/handoff.rs#process_job`).

A rising drop or spool-refused count means the capture layer is shedding load; it is expected
behavior under a flood (covertness over completeness), not a crash. Separately, the ops-alert
monitor's capacity condition watches free space on the spool volume (`CAPACITY_FREE_PCT`), a
related but distinct signal from these counters.

### Runtime scheduling lag

sqlx reports a statement's elapsed time as everything between the task issuing it and the task
being polled with the answer. If the daemon's async runtime has no free worker for a while, a
trivial statement (`COMMIT`, a primary-key lookup) logs one or two seconds with the database
idle. The daemon therefore runs a small probe (`crates/propolis/src/runtime_lag.rs`) that sleeps
100 ms at a time and measures how much later than that it was polled. When the lag passes 250 ms
it logs one WARN, at most one per 10 s. A stall that lands inside the 10 s window is held back and
logged by the first wake-up after the window (or at shutdown), so the line carries the worst lag
since the last line and how many wake-ups were late. It also carries the runtime's worker count and
queued-task depth, and the process cgroup's growth since the last on-time wake-up that had nothing
pending (so the deltas begin at most one 100 ms interval before the first stall the line reports; a
stall held back by the 10 s limit widens the window to the moment of the report):

```text
WARN runtime: the async runtime was slow to poll a ready task; ...  worst_lag_ms=1840 late_wakeups=7
workers=4 queued_tasks=12 cgroup_visible=true cgroup_nr_throttled=0 cgroup_throttled_ms=0
cgroup_mem_high=0 cgroup_mem_max=0 cgroup_mem_oom=0
```

Reading it: lag alone does not name the cause, because three different things freeze task polling
and look the same to the probe:

| Lag with | Cause | Fix |
|---|---|---|
| all `cgroup_*` deltas zero | workers held in synchronous code (or a host-level stall) | move the step off the workers (`cpu_budget` below) |
| `cgroup_nr_throttled` / `cgroup_throttled_ms` above zero | the unit's `CPUQuota=` ran out; every thread was frozen, whatever it was doing (`cgroup_throttled_ms` is throttled time summed across CPUs, so it can exceed the lag; it is not the length of the freeze) | raise `CPUQuota=` or cut the load; moving work to another thread does not help |
| `cgroup_mem_max` / `cgroup_mem_high` above zero | direct reclaim at `MemoryMax=` | raise `MemoryMax=` or cut memory use |

`cgroup_visible=false` means the process is not under a readable cgroup v2 hierarchy, so the
deltas are not available and read zero. Slow statements logged around the time of this warning
are the process, not the database; slow statements **without** it point at the database (check
`log_min_duration_statement`, `log_lock_waits` and `log_checkpoints` on the server). The probe is a
measurement, not a subsystem: it is not in `/ready` or the monitor's subsystem conditions, and its
failure restarts nothing. With several workers, a single blocked worker is visible only when the
probe's wake-up lands on it, so a quiet probe does not prove that no step ever ran long.

The steps that run synchronously inside async tasks are timed by an example that needs no
database and no network, on inputs at the limits the daemon enforces (a 1 MiB log line, an 8 MiB
intake batch, a 16 MiB captured body, a 20,000-file spool, a 200-event evidence page with 64 KiB
bodies, a 50,000-entry feed):

```text
cargo run --release --example cpu_budget -p propolis
```

It marks every step over 10 ms that still runs on an async worker. Measured in a release build
on the development machine (a shared 28-core host; the quietest of several runs is shown, and a
busy run was up to five times slower, 464 ms against 85 ms for the spool walk, so run it on the
box that matters), the steps over 10 ms were:

| Step | Worst-case input | Median | Now |
|---|---|---|---|
| Digest of a fetched body | 16 MiB | 142 ms | off the worker |
| Spool write of a fetched body (hash, write, fsync) | 16 MiB | 242 ms (fsync outliers 950 ms) | off the worker |
| Feed publish (render, write, fsync) | 5,000 / 50,000 entries | 167 ms / 905 ms | off the worker |
| Ledger chain hash of one intake batch | 8 MiB | 77 ms | off the worker |
| Intake tailer read of one batch | 8 MiB, warm cache | 13 ms | off the worker |
| Ops-monitor spool walk | 20,000 files | 85 ms | off the worker |
| Campaign indexer: shape, indicators, tags of one command | 64 KiB / 1 MiB line | 16 ms / 60 ms | off the worker above 16 KiB (sensors cap a line at 1 KiB: 0.4 ms) |
| `redact_secrets` | 1 MiB of `authorization: ` | 8,185 ms | linear (a few ms) |
| Console IP detail: build, group and render one evidence page | 200 events, 64 KiB body each (about 27 MB of HTML) | 225 ms (1 KiB bodies: 5 ms) | off the worker |
| Console feed Entries tab: read, parse, render one load | 5,000 / 50,000 entries | 19 ms / 165 ms | off the worker |

Everything else measured, including the ATT&CK tagger (bounded to 4 KiB of shell and 8 KiB of SQL
per line, under 0.3 ms), indicator extraction at its 64 KiB cap, dropper URL extraction (2 ms at
64 KiB), JSON parsing of a full batch (3 ms) and the upload type filter, stayed under 10 ms; the exceptions are the rows in the table above, console pages included. The
captured-artifact scan (65-107 ms for a 16 MiB binary) already ran under `spawn_blocking`. A step
moved "off the worker" runs under `core_scoring::off_worker`, which hands the rest of that
worker's queue to another thread for the duration.

## Ops-alert monitor (opt-in)

The daemon can run an internal monitor that pages via [ntfy](https://docs.ntfy.sh/) when the system
degrades. It is **off by default** and is one of the platform's operator-gated egress paths
(see [outbound controls](../security/outbound-controls.md)). It is distinct from the Guardian
host-compromise monitor and should use a separate topic
(`docs/archive/2026-08-26/root/INSTALL.md#Environment variable reference`; the live `INSTALL.md` is now a redirect
stub).

> **Warning - outbound egress.** Enabling the ops-alert monitor makes the daemon POST to your
> configured ntfy server. That is the only network egress this feature performs, and it is off
> until you set `PROPOLIS_OPS_ENABLED=true`.

Configuration is **fail-closed only on a half-configured target**: when
`PROPOLIS_OPS_ENABLED=true`, setting exactly one of `PROPOLIS_OPS_NTFY_URL` /
`PROPOLIS_OPS_NTFY_TOPIC` makes the daemon refuse to start, because a target that looks
configured but cannot page is worse than a loud config error; leaving both unset is
accepted and falls back to alerting through the local log sink instead of ntfy
(`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`). Exact defaults and bounds for every
`PROPOLIS_OPS_*` var are owned by [environment
variables](../reference/environment-variables.md); the monitor watches (defaults):

- spool free space below `CAPACITY_FREE_PCT` (15%);
- an intake/feed stall for `STALL_FOR_SECS` (600 s), and feed staleness at
  `FEED_STALE_MULTIPLE` (2x) the build interval - both for the local publish
  (`feed-stale`) and for the public repo falling that far behind the local feed
  (`feed-push-stale`, read from the marker `/var/lib/propolis/blocklist-status/last-pushed`
  that `deploy/blocklist-sync.sh` rewrites after each successful push; a box that has never pushed is paged only when
  `FEED_PUSH_EXPECTED` is set, and then only after the same threshold has elapsed
  since the daemon started, since without the flag the monitor cannot tell a broken
  cron from no cron and a fresh deployment must not page before its first cron run);
- an intake falling behind its log (`intake-lagging`, Warning). `intake-stalled` fires only when
  a sensor's cursor stops moving with input waiting. When the database refused the same line on
  three consecutive polls, its detail quotes `intake wedged at <sensor>` with that event's
  `observed_at` and the SQLSTATE: one line the ledger will not accept (for example a NUL
  character in a command, which `jsonb` cannot store). Intake sets such a line aside and moves
  past it in that same poll ([`intake-line-quarantined`](#quarantined-intake-lines) below), so
  `intake-stalled` quoting a wedge means the line could NOT be quarantined: the quoted text ends
  with the reason (the quarantine directory is not writable, or it is full), and intake stays on
  the line, skipping nothing, until that is fixed. An intake that keeps moving but more slowly
  than its sensor writes never trips it, and that is how a telnet log once grew to 6.6 GB over
  eleven days unnoticed. `intake-lagging` reads the two intake metrics above and fires when
  either rule holds for a log
  (`crates/propolis/src/ops_alert/conditions/intake_lag.rs#IntakeLagging`):
  - **age**: its oldest unread line has waited longer than ten minutes or three intake polls
    (`PROPOLIS_POLL_INTERVAL_MS`), whichever is longer, continuously for ten minutes;
  - **growth**: its unread bytes rose at each of three consecutive monitor polls, each of which
    found complete lines waiting. This fires within minutes of a log starting to run away.

  The page names each log with its backlog, as `telnet (6.6 GB / 11 d)`. It clears when the log
  is read to the end, or when the wait is back under the threshold and the backlog has not grown
  for three consecutive polls, so a backlog hovering at the edge does not page and recover in
  turn. An idle log never fires: with nothing unread there is no wait and no growth, and an
  unfinished last line neither ages nor grows. The thresholds are fixed, not `PROPOLIS_OPS_*`
  variables. While a log has not finished its first poll the condition reads it as unknown, not
  healthy, and the monitor's own stale-probe warning covers a log that never reports;
- sensor logs outgrowing rotation (`sensor-log-oversized`; Warning, Critical when the disk
  half holds). It fires, after a two-minute hold, when any log in `PROPOLIS_SENSOR_LOGS` is more
  than three times the rotation size, or when the filesystem under `/var/log/propolis` is more
  than 85% used (`df`'s Use%)
  (`crates/propolis/src/ops_alert/conditions/sensor_log.rs#SensorLogOversized`). The rotation
  size is the `size` line of `/etc/logrotate.d/propolis-sensors`, read on each poll, so
  300 MiB with the shipped `100M`; if the file is unreadable or has no `size` line the daemon
  assumes 100 MiB. A log that does not exist yet is not oversized. Once firing it clears only
  when every log is back under twice the rotation size and the disk at or under 80% used, so a
  log hovering at the line does not page and recover in turn. This is the alert that would have
  caught the October 2026 incident, where the distribution's rotation timer stopped and a telnet
  log reached 6.6 GB; `capacity` watches the cursor and spool volumes, which are the log volume
  only when they share a filesystem, and `intake-lagging` watches an intake that falls behind,
  not a log that grows. The page names each log with
  its size; recovery is [a log too large to rotate](./retention.md#a-log-too-large-to-rotate).
  On a control-plane box tailing a collector's gateway spool file, which no policy rotates
  ([split deployment](./split-deployment.md#disk-space)), a spool past 300 MiB fires it too;
  that is the spool growing, not rotation failing;
- log rotation not running (`rotation-stale`, Warning): the logrotate state file
  `/var/lib/propolis/logrotate.state` has not been rewritten for more than three hours
  (`crates/propolis/src/ops_alert/conditions/sensor_log.rs#RotationStale`).
  `propolis-logrotate.service` rewrites it on every hourly run, whether or not a log was due, so
  its modification time is the last run. The daemon does not ask systemd whether the timer is
  active; a file that stops moving is a timer that stopped firing. It clears on the next run. A
  node where the file does not exist yet (the timer never ran) reads as unknown, not firing, and
  the monitor's stale-probe warning raises it after half an hour. A run in which the guard refuses
  a log (for free space, or because intake has not read it) still rewrites the file, so that case
  surfaces as `sensor-log-oversized` and a failed unit, not as this alert
  (`crates/sensor-framework/tests/deploy_test.rs#a_log_skipped_for_unread_input_still_refreshes_the_state_file_and_fails_the_run`). The thresholds of both are fixed, not `PROPOLIS_OPS_*` variables;
- a rotation that took unread input (`intake-rotation-loss`, Warning;
  `crates/propolis/src/ops_alert/conditions/intake.rs#IntakeRotationLoss`). When a `copytruncate`
  rotation lands while a log is unread, the tailer reads the rest from `<log>.1`
  ([concurrency and failure](../architecture/concurrency-and-failure.md#log-rotation-under-a-reader-that-is-behind)).
  This pages, immediately, when it could not: `.1` was missing, only `.1.gz` existed, or `.1` was
  not the old content, so the unread lines are gone. The page names each log with the number of
  such rotations and a lower bound on the bytes lost (`at least 0 bytes` when the tailer had not
  yet polled the old content, as after a restart). It holds for one hour after the last loss and
  then recovers by itself, since a loss does not clear; the journal WARN `a copytruncate rotation
  discarded input that was never read` is the permanent record, and the counts reset when the
  daemon restarts. A rotation that finds the reader caught up and no `.1` is silent: the lines
  written between the copy and the truncate are the accepted loss. A truncation you made by hand
  while intake was behind also raises it. The hold is fixed, not a `PROPOLIS_OPS_*` variable;
- a log line quarantined (`intake-line-quarantined`, Warning): intake set aside a line the
  database refused on three polls in a row and moved past it, so a real sensor line is not in
  the ledger. It fires on the next monitor poll with no hold, naming the sensor, the line's byte
  offset, the SQLSTATE and the quarantine file, and clears (with a recovered notice) once
  `REPAGE_COOLDOWN_SECS` has passed with no further quarantine, so one line pages once and a
  second line inside that window extends it
  (`crates/propolis/src/ops_alert/conditions/intake_quarantine.rs#IntakeLineQuarantined`). What
  to do: [Quarantined intake lines](#quarantined-intake-lines);
- vendor submission failure rate over `VENDOR_FAIL_PCT` (50%) within `VENDOR_WINDOW_SECS`
  (3600 s), gated by `VENDOR_MIN_SAMPLES` (20);
- review backlog over `BACKLOG_MAX` (500) held for `BACKLOG_FOR_SECS` (900 s);
- malware work stalled: a spooled body unscanned or a VirusTotal upload unverdicted for
  `SCAN_STALE_SECS` (6 h; `scan-stale`, only with VirusTotal enabled), or a fetch url
  pending for `FETCH_STALE_SECS` (1 h; `fetch-stale`, only with the fetcher enabled) -
  the fetcher retires a url after three attempts, so an old pending row means it is not
  attempting;
- periodic hash-chain verification every `CHAIN_VERIFY_INTERVAL_SECS` (6 h). The whole-ledger
  scan runs as a task of its own and the monitor serves its last verdict, so a scan that takes
  minutes never holds up the other conditions or the heartbeat
  (`crates/propolis/src/ops_alert/conditions/chain.rs#ChainVerify`); before the first scan
  finishes the condition reads as unknown;
- no good backup (`backup-stale`, Warning): the newest set the
  [nightly backup](backup-and-restore.md#the-nightly-backup) wrote is older than
  `BACKUP_MAX_AGE_SECS` (36 h), so one failed night pages before a second is missed; the page
  names the last set and the step the last failed run stopped at. With no good backup yet it fires
  once the status directory is older than the limit, or at once if a run has already failed
  (`crates/propolis/src/ops_alert/conditions/backup.rs#BackupStale`);
- re-page suppression `REPAGE_COOLDOWN_SECS` (5400 s); poll `POLL_INTERVAL_SECS` (30 s).

`PROPOLIS_OPS_NTFY_TOKEN` is an optional bearer token for a protected topic. Point
`PROPOLIS_OPS_NTFY_URL` at your own ntfy server or one where the topic's read access is
restricted to you. Where it is not (an unreserved topic on a public server, or a self-hosted
server left at its default open access), anyone who knows the topic name can read every alert,
which says when this host's pipeline is down. A token says who publishes; it does not stop others reading unless the server restricts the
topic, so it alone does not make a topic private. The shipped `deploy/propolis.env.example`
leaves the URL empty for that reason. See
[integrations](../reference/integrations.md) and [troubleshooting: integrations and
feed](../troubleshooting/integrations-and-feed.md).

### Unreadable probes and undeliverable alerts

Two failures used to be silent; neither is now.

**A probe that cannot read its source does not clear an alert.** A condition whose query or
file read fails reports unknown, which is neither firing nor healthy
(`crates/propolis/src/ops_alert/debounce.rs#Signal::Unknown`). Unknown holds the condition
exactly where it was: it never pages, never re-pages, never cancels or restarts a debounce in
progress, and in particular never sends a `[recovered]` notice for an incident that is still
open. Only a reading that says healthy recovers an incident, once. A probe that stays unknown
for 30 minutes raises its own `probe-stale` warning, and when an earlier page for that condition
is still open the warning says so ("an earlier page for it is still open: it cannot be confirmed
cleared until the probe reads again"). It recovers, with the incident's own notice if the
condition is now clear, on the first reading that works
(`crates/propolis/src/ops_alert/monitor.rs#Monitor::process_tick`). The threshold is fixed.

**A failed delivery is retried and reported.** The dispatcher makes four attempts per alert
(0.2 s, 0.4 s, 0.8 s apart). An alert that still fails is no longer dropped after one journal
line: it is queued and retried at the end of later monitor ticks, 30 s after the failure and
then at doubling intervals up to 15 minutes. A tick's retry pass stops at its first failure (the
other queued alerts share the transport that just failed), makes at most four attempts and is cut
off after 20 s in all; an alert cut off that way backs off like any failure
(`crates/propolis/src/ops_alert/undelivered.rs`, `monitor.rs#RETRY_PASS_BUDGET`). The newest state per condition wins, so a
`[recovered]` notice replaces a queued page that never went out. The queue holds 64 alerts; a
full queue drops the oldest with a WARN. What to look for in the journal
(`journalctl -u propolis`):

| Message | Level | Meaning |
|---|---|---|
| `ops-alert: delivery failed; will retry` | ERROR | the first delivery of an alert failed; it is queued |
| `ops-alert: retry failed; will retry again` | WARN | a queued alert failed again; carries `attempts` and `error` |
| `ops-alert: delivered after earlier failures` | INFO | a queued alert finally went out |
| `ops-alert: an alert was never delivered before the previous run ended` | WARN | at startup, one per alert the previous run left queued |

The queue is written to `ops-alert-undelivered.json` in `PROPOLIS_CURSOR_DIR` (key, title,
severity, when it first failed, attempts, last error; never the alert body). If the daemon stops
with alerts queued, the next run logs the WARN above for each and sends one summary alert,
"propolis: alerts were not delivered", listing each with its age, attempt count and the failure;
the summary is itself queued and persisted until it is delivered. With only the local log sink
(`PROPOLIS_OPS_NTFY_URL` unset) delivery cannot fail and the file is never written.

The dead-man's switch is independent of all of this. Retries run after the heartbeat in each
tick and are capped at 20 s per tick, so a dead ntfy server cannot suppress the ping and delays
the next round (its ping included) by at most that long, and the ping is not conditional on
alerts having been delivered. Each ntfy attempt has its own 30 s deadline and the heartbeat
request 15 s. A page raised in the same tick as an outage is not covered by the retry cap: its
dispatch can wait about two minutes per alert (four attempts of 30 s) before it is queued, so a
round in which many conditions newly fire against a hung host is slow; that is the cost of
trying to deliver a new page at once. That a `ping` stops arriving is still how the service on
the other end learns the daemon is down.

### When the daemon or the host is down

The monitor runs inside the daemon, so it cannot report the daemon's own death, nor the host's.
Two pieces cover that:

- **The failure hook.** Every Propolis unit (the daemon, each sensor, the gateway, the shipper,
  the backup and log rotation) names `OnFailure=propolis-alert@%n.service`. When a unit enters
  the failed state, systemd runs `/usr/local/sbin/propolis-alert` (`deploy/alert.sh`), which
  posts "`<unit>` failed on `<host>`" with the unit's last journal lines to the same ntfy topic,
  read from `propolis.env`, or writes it to the journal at err priority when there is none, in
  which case the journal line is the alert. A unit with `Restart=` passes through the failed
  state on every crash, so once an alert for a unit has been delivered the hook sends no other
  for that unit for 30 minutes (`PROPOLIS_ALERT_COOLDOWN_SECS`, 1800). An alert that was not
  delivered (the post failed, or curl is not installed, which the journal line then says) does
  not arm that cooldown: the next failure of the unit posts again once a short retry hold has
  passed (`PROPOLIS_ALERT_RETRY_SECS`, 120), so a crash loop cannot hammer ntfy. While it stays
  undelivered, the full alert goes to the journal at most once per cooldown, and each failure in
  between writes one short err line saying since when the unit's alert is undelivered; the alert
  that finally gets through also says how many earlier failures went undelivered and since when. A
  stamp dated after the current time, as a clock stepped back leaves it, counts as expired. Both
  variables are read from the hook unit's environment (an `Environment=` drop-in for
  `propolis-alert@.service`), not from `propolis.env`. It does not need `PROPOLIS_OPS_ENABLED`.
- **The heartbeat.** Set `PROPOLIS_OPS_HEARTBEAT_URL` to a dead-man's switch check: a service
  that alerts you when it stops hearing from you, such as a healthchecks.io check or one you run
  elsewhere. The monitor requests the URL after every complete evaluation round, at most every
  `HEARTBEAT_INTERVAL_SECS` (300 s); set the check's period to that and its grace to a few
  minutes. When the pings stop, because the daemon is down, the monitor is stuck in a probe, or
  the host or its network is gone, the service raises the alarm. The URL is a secret: it must be
  `https://` and is never logged. Like ntfy, this is outbound egress you opt into.

`deploy/config-check.sh` reports, under `alerting`, a monitor that is off, alerts that go only to
the journal (`ops-no-push`), no heartbeat and a missing failure hook. It counts a push target only
when both `PROPOLIS_OPS_NTFY_URL` and `PROPOLIS_OPS_NTFY_TOPIC` are set, since the daemon and the
failure hook both need the two. With the monitor on and only one of them set it fails the check
as `ops-push-half`, naming the empty one, because the daemon will not start with that file; with
the monitor off and only one set, the failure hook writes its alerts to the journal, and the check
reports that as `ops-no-push`. It reads the two values the way each reader gets them: for the
daemon as systemd hands them over, with unquoted surrounding whitespace trimmed, so a value of
only spaces counts as empty; for the failure hook as `deploy/alert.sh` reads the file, from lines
that start with the name, with quotes removed and nothing trimmed, so a value set on an indented
line reaches the daemon but not the hook, which the check also reports as `ops-no-push` and
names the indentation only when the line is indented. Where the two readers disagree the other
way, the hook posting with a value the daemon does not get (unquoted spaces, say), then with the
monitor off the row reads `ntfy for the failure hook only` and the check reports that as
`ops-no-push` too; with the monitor on and the daemon left with only one of the two values, it
is `ops-push-half` as above. Under `backup` and `clock` it reports the backup state and whether
the clock is NTP-synchronized, and under `env-files` an env file whose mode lets another account
read it.

### Quarantined intake lines

The ledger can refuse a line for a reason of the line itself: a NUL character in a captured
command (`jsonb` cannot store it, SQLSTATE `22P05`), a value out of range, a constraint
violation. Retrying never helps, and before this existed such a line held its sensor's intake
at that line until an operator removed it from the log. Now, when the database has refused the
same line on three polls in a row (`WEDGE_POLLS`) with an error that belongs to the line
(SQLSTATE class 22 or 23, a failed validation, a stored-state decode failure; never a lost
connection or a timeout), intake:

1. appends one JSON record to `/var/lib/propolis/quarantine/<sensor-label>.jsonl`
   (`PROPOLIS_QUARANTINE_DIR`; the label is the `PROPOLIS_SENSOR_LOGS` name, with anything
   outside letters, digits, `_` and `-` replaced by `_`) and fsyncs it;
2. only then moves its read position past exactly that line and saves the cursor
   (`crates/intake/src/runner.rs#quarantine_line`). The position moves by the line lengths
   recorded when the batch was read, never by reading again, so a `copytruncate` landing at that
   moment cannot make it step over a line of the new file;
3. logs `intake: line quarantined` at WARN, increments the `propolis_intake_lines_quarantined_total`
   counter on `/metrics` (process lifetime, all logs), and raises `intake-line-quarantined`.

If step 1 fails (the disk is full, the directory is not writable) intake does NOT skip: it stays
on the line, `intake-stalled` quotes the write error, and the next poll tries again, so fixing
the directory unsticks it without a restart. The store is bounded at 64 MiB and 10,000 records
across all its files (`crates/intake/src/quarantine.rs#MAX_QUARANTINE_BYTES`,
`crates/intake/src/quarantine.rs#MAX_QUARANTINE_RECORDS`); at the cap nothing more is quarantined
and the next refused line wedges intake as above, with the cap in the alert text. The standalone
`intake` binary does the same but has no ops monitor, so there the WARN log line is the only
signal.

Each record is one line of JSON:

| Field | Meaning |
|---|---|
| `quarantined_at` | UTC time the line was set aside |
| `sensor` | the `PROPOLIS_SENSOR_LOGS` label |
| `log_path` | the log it was read from |
| `byte_offset` | offset of the line's first byte in the file it was read from (the rotated-out file if rotation had already moved the log) |
| `line_sha256` | SHA-256 of the line's exact bytes, newline excluded |
| `sqlstate` | the database's SQLSTATE, or `null` when the refusal was not a database error |
| `error` | the error text, flattened to one line and capped at 512 characters |
| `line_encoding` | `utf8`, or `base64` when the line is not valid UTF-8 (the bytes are kept exactly) |
| `line_truncated` | true when the line passed the tailer's 1 MiB line cap and `line` holds only its first MiB |
| `line` | the line, in `line_encoding` |

To look at them (the directory is `0750 propolis`):

```sh
sudo -u propolis tail -n 5 /var/lib/propolis/quarantine/telnet.jsonl
sudo -u propolis jq -r '[.quarantined_at, .sqlstate, .byte_offset] | @tsv' /var/lib/propolis/quarantine/*.jsonl
```

The skipped event is not in the ledger and nothing re-reads it. To ingest it after all, correct
whatever the database refused (for the NUL case, delete the `\u0000` escape from the line text),
check the result is still one valid sensor event, and append it as one more line, with its
newline, to that sensor's log as the sensor's own user or root; intake reads it as a new line and
the event keeps its original `observed_at`. Editing a captured value is the operator's decision,
and a line quarantined as `base64` has to be decoded first (`jq -r .line | base64 -d`). Records
are never removed by Propolis: see [retention](./retention.md#quarantined-intake-lines).
