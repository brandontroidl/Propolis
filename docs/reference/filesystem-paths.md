<!--
title: Filesystem paths
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Filesystem paths

Canonical owner of every filesystem path Propolis uses: event logs, spool /
quarantine dirs, persistent state, GeoIP, config, and sockets. Env-var exact
semantics are owned by
[environment-variables.md](environment-variables.md); this page owns the path
facts. Directory ownership/mode is created by `deploy/provision.sh`
(`ensure_dir`, invoked by both `install.sh` and `upgrade.sh`).

## Event logs (per sensor, JSONL append)

Every log-path env is an **override**; the default is the value shown. Each
sensor appends newline-delimited JSON events.

| Sensor | Log-path env | Default | install.sh dir (mode 0750) |
|---|---|---|---|
| ssh | `PROPOLIS_SSH_LOG_PATH` | `/var/log/propolis/ssh/events.jsonl` (`crates/sensor-ssh/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/ssh` propolis-ssh (`deploy/provision.sh#ensure_dir /var/log/propolis/ssh`) |
| telnet | `PROPOLIS_TELNET_LOG_PATH` | `/var/log/propolis/telnet/events.jsonl` (`sensor-telnet/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/telnet` (`deploy/provision.sh#ensure_dir /var/log/propolis/telnet`) |
| http | `PROPOLIS_HTTP_LOG_PATH` | `/var/log/propolis/http/events.jsonl` (`sensor-http/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/http` (`deploy/provision.sh#ensure_dir /var/log/propolis/http`) |
| ftp | `PROPOLIS_FTP_LOG_PATH` | `/var/log/propolis/ftp/events.jsonl` (`sensor-ftp/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/ftp` (`deploy/provision.sh#ensure_dir /var/log/propolis/ftp`) |
| smtp | `PROPOLIS_SMTP_LOG_PATH` | `/var/log/propolis/smtp/events.jsonl` (`sensor-smtp/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/smtp` (`deploy/provision.sh#ensure_dir /var/log/propolis/smtp`) |
| tftp | `PROPOLIS_TFTP_LOG_PATH` | `/var/log/propolis/tftp/events.jsonl` (`sensor-tftp/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/tftp` (`deploy/provision.sh#ensure_dir /var/log/propolis/tftp`) |
| mqtt | `PROPOLIS_MQTT_LOG_PATH` | `/var/log/propolis/mqtt/events.jsonl` (`sensor-mqtt/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/mqtt` (`deploy/provision.sh#ensure_dir /var/log/propolis/mqtt`) |
| dns | `PROPOLIS_DNS_LOG_PATH` | `/var/log/propolis/dns/events.jsonl` (`sensor-dns/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/dns` (`deploy/provision.sh#ensure_dir /var/log/propolis/dns`) |
| redis | `PROPOLIS_REDIS_LOG_PATH` | `/var/log/propolis/redis/events.jsonl` (`sensor-redis/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/redis` (`deploy/provision.sh#ensure_dir /var/log/propolis/redis`) |
| adb | `PROPOLIS_ADB_LOG_PATH` | `/var/log/propolis/adb/events.jsonl` (`sensor-adb/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/adb` (`deploy/provision.sh#ensure_dir /var/log/propolis/adb`) |
| catchall | `PROPOLIS_CATCHALL_LOG_PATH` | **`catchall-events.jsonl`** (relative, not absolute) (`sensor-catchall/src/main.rs#DEFAULT_LOG_PATH`) | `/var/log/propolis/catchall` (`deploy/provision.sh#ensure_dir /var/log/propolis/catchall`) |
| cred | `PROPOLIS_CRED_LOG_DIR` (a **directory**) | `/var/log/propolis/cred`; writes one file per protocol `<protocol>.jsonl` (e.g. `mysql.jsonl`) (`sensor-cred/src/main.rs#DEFAULT_LOG_DIR`, `sensor-cred/src/main.rs#main`) | `/var/log/propolis/cred` (`deploy/provision.sh#ensure_dir /var/log/propolis/cred`) |

Two paths differ from the pattern:

- **catchall**'s default is a **relative** path (`catchall-events.jsonl`), so in
  production `PROPOLIS_CATCHALL_LOG_PATH` must be set to an absolute path inside
  `/var/log/propolis/catchall` (the unit comment requires it match logrotate).
- **cred** uses a **directory** default and derives per-protocol filenames,
  unlike every other sensor which names a single file.

logrotate config `deploy/logrotate-sensors.conf` rotates `/var/log/propolis/*`
event logs, run hourly by `propolis-logrotate.timer` with its state in
`/var/lib/propolis/logrotate.state` (root-written; the daemon only reads its modification time).
The policy's `prerotate` hook is `/usr/local/sbin/propolis-logrotate-guard`. See
[retention](../operations/retention.md#log-rotation).

## Backups

The nightly backup (`/usr/local/sbin/propolis-backup`, from `deploy/backup.sh`, run by
`propolis-backup.timer`) writes one set per run under `/var/backups/propolis`
(0750 root:propolis-backup-pull; `deploy/provision.sh#ensure_dir /var/backups/propolis`). A
plaintext set is 0700 root with 0600 files; an encrypted set is 0750 with 0640 files in group
`propolis-backup-pull`, the account the off-host pull logs into, whose home
`/var/lib/propolis-backup-pull` (and its `.ssh`) are root-owned like `propolis-watch`'s. Its status files are in `/var/lib/propolis/backup-status`
(0755 root, files 0644; `deploy/provision.sh#ensure_dir /var/lib/propolis/backup-status`):
`last-success`, `last-failure`, `ledger-reset` (written when an operator accepts a restored
ledger), and the `lock` that keeps two runs apart. Age recipients
for encrypted sets are read from `/etc/propolis/backup-recipients.txt`. See
[backup and restore](../operations/backup-and-restore.md#the-nightly-backup).

Where the [database roles are split](../operations/database-roles.md),
`/etc/propolis/migrate.env` (0600 root:root, created by the operator) holds the schema owner's
`PROPOLIS_MIGRATE_DATABASE_URL`. Two scripts read it, both as root:
`/usr/local/sbin/propolis-migrate` (`deploy/migrate.sh`), and `deploy/rollback.sh --with-database`
to learn the owner role's name before a restore. No unit loads it and
`deploy/propolis.service#InaccessiblePaths=-/etc/propolis/migrate.env` and the sensor units deny
it.

Each upgrade keeps the release it replaces in `/var/lib/propolis/rollback/<UTC time>-<commit>`
(0700 root; `deploy/rollback.sh#save`): its binaries, `propolis-*` helpers (among them the alert
library `propolis-alert-lib`, which a rollback restores only when it fits the scripts left in
place, `deploy/rollback.sh#check_alert_lib`), the installed config-check's `config-check.sh`,
`listeners-lib.sh` and `install-bins` in `lib/` (`deploy/rollback.sh#LIB_HELPERS`; `repo-dir` is
not kept), unit files, deploy
stamp, and a `manifest` naming the commit and the pre-upgrade backup set. The newest 3 are
kept. See [rollback](../operations/upgrade-rollback-and-dr.md#rollback).

## Alerting state and runtime directories

Provisioned for the root shell alerting code. Two programs write the state: the failure hook's
record step (`deploy/alert-lib.sh#pa_hook_record`), which `propolis-alert@.service` runs after
each alert and which records the failure, and the witness's two passes, the light pass
(`deploy/witness.sh#light_pass`), which `propolis-witness@light.timer` runs every five minutes,
and the hourly pass (`deploy/witness.sh#hourly_pass`), which `propolis-witness@hourly.timer` runs
once an hour, all under the one state lock. The hourly pass reads every file afresh under the
lock and changes only its own records (config-check findings, `cc-stopped`, `witness-stale` for
the light pass, `volume-filling` and `volume-full-soon`, `db-xid`, `db-slots` and `db-locks`,
`change-pending`, `push-failing`, `push-unscheduled` and `push-off`, `backup-retention` and
`backup-offhost`, `tool-unusable` for its own checks, the fold of a rotation the guard refused
for want of space under a volume record, and the fold of a failed backup under `db-unreachable`
or the backup volume's record), its own `observe` lines and its own `meta` keys. `deploy/upgrade.sh`, `deploy/rollback.sh` and
`propolis-status --maint` write the maintenance marker. The configuration check sources the same
library and only reads.

The light pass is what judges the records and clears what the hook leaves behind. Under the
lock it takes in each hook spool file (`hook/<unit>`, `fallback/hook-<unit>`): it first renames
the file to `.ingest.<pid>.<name>` beside it, so a firing the hook spools meanwhile starts a new
file, and removes that copy once the records are written (a copy it could not finish is put
back, or taken in by the next pass). It drops a first sighting whose unit healed, opens, reminds and resolves records, and removes
resolved records seven days after their resolve (`deploy/alert-lib.sh#pa_incident_prune`). It
also removes the temporary files (`*.tmp.<pid>`) a writer killed between writing and renaming
left in either state directory, once they are older than ten minutes. A fallback copy of a state
file stays until a later write of that file reaches the persistent directory, which then removes
it, and every fallback file is gone at the next reboot. A file a writer holding the lock cannot
read is set aside as `<name>.unreadable.<time>` (only the newest is kept) and the writer starts
it empty.

`propolis-status` (`deploy/propolis-status.sh#status_walk`) reads the records, `meta`, the
heartbeat, the maintenance marker, `id-salt`, `/run/propolis-witness/lockwait`, the hook spool
files, the fallback copies and the banner's time, without the lock and without writing anything:
once a light pass has completed it lists the open incidents (`deploy/propolis-status.sh#print_open`),
before that the records and the spooled firings as recent failures
(`deploy/propolis-status.sh#print_recent`, `deploy/propolis-status.sh#load_hook_spool`). A file
the walk cannot read is named in its output, never renamed. `propolis-status --maint` writes or
removes the maintenance marker and rewrites the banner, and nothing else.

| Path | Mode | Owner | Created by |
|---|---|---|---|
| `/var/lib/propolis/witness/` | 0750 | root:propolis | `deploy/provision.sh#ensure_dir /var/lib/propolis/witness` |
| `/var/lib/propolis/witness/state.lock` | 0600, empty | root:root | `deploy/provision.sh#WITNESS_LOCK`, only when missing |
| `/var/lib/propolis/witness/incidents` | 0600, one `I` line per failure record (`#incidents v1`) | root:root | `deploy/alert-lib.sh#pa_incident_put`, under the lock, the first time a unit fails |
| `/var/lib/propolis/witness/id-salt` | 0600, 32 hex digits | root:root | `deploy/alert-lib.sh#pa_salt_ensure`, by the first record; deleting it renames every opaque id |
| `/var/lib/propolis/witness/meta` | 0600, `M` lines (`#meta v1`): `where` (the directory the last write went to: `persistent`, `run` or `none`), `clock` and `clock_step`, `light_last` and `hourly_last` (when the last light and hourly pass completed), `healed` (how many first sightings healed, and the latest), `maint_seen` (when a light pass last saw an active maintenance marker), `cc_last` (when the hourly pass that ran the last config-check started, its exit status, `-` when it was not run, and its seconds), `cc_fail` (how many hourly passes in a row it did not complete), `cc_skipped` (how many lines the last completed run printed out of form), `pgexec_id` and `pgexec_ok` (the daemon binary's inode, size and mtime, and whether it carried pg-exec's guard, so the same binary is not read again), `jlines` (running counts of the journal lines the light pass looks for: the legacy hook's undelivered lines, failure alerts that went only to the journal, the rotation guard's lines, journald's suppression notices; never their text), `jskip` (when a journal class last started again without its cursor, and which), `hb_last` (when the heartbeat URL was last asked and the result, never the URL), `hb_skip` (when it was last skipped and why), `pg_state` (when the hourly pass last read the database's state, then the oldest transaction id's age, the connections, the usable slots, the lock waits over 120 s and the database's size in bytes, joined by `/`), and `pg_datadir` and `pg_datadir_stamp` (the local PostgreSQL data directory as `SHOW data_directory` gave it to the `postgres` account, and when it was read; read again after a day), `backup_dur` (the seconds the last backup run took, from a light pass that saw the unit inactive after a run), `pull_last` (the light pass that last saw the off-host pull's `served` line), `pull_since` (since when an off-host pull counts as configured: the first hourly pass that saw it, or the last served line when one was already kept; `-` while there is none or the installed serve script logs no line), `push_sched_since` (since when the hourly pass has seen a scheduler of the public push, `-` while there is none) and `backup_sets` (the scheduled backup sets the hourly pass counted, and KEEP, as `<sets>/<keep>`) | root:root | `deploy/alert-lib.sh#pa_hook_record` (`where`, after each record it writes), `deploy/witness.sh#light_pass` and `deploy/witness.sh#hourly_pass`, under the lock |
| `/var/lib/propolis/witness/observe` | 0600, `U`, `R`, `S`, `Z`, `H` and `P` lines (`#observe v1`): each unit's last sample, its restart baseline; on a control node or gateway, one line per listed collector (`S <collector id> <last write> <last advance> <longest gap> <week start> <the week before's longest gap> <writes in a row>`, under its opaque id and never its name, the last write the spool file's modification time); the hourly pass's samples of every store's filesystem (`Z <mount id> <stamp> <size> <avail> <inodes> <free inodes>`, bytes and counts, under an opaque mount id and never the mount point, kept seven days, at most one per filesystem in 45 minutes, at most 224 per filesystem, and dropped once no store lives on that filesystem, which only a pass that learnt and checked every store's path can tell); one line per watched file (`H <path> <sha16> <changed> <keys8> <seen> <before>`: the first 16 hex of sha256 of the content, or of `inode/size/mtime` for a binary, the pass that first saw it (`-` for a file first seen), for an env file the first 8 hex of sha256 of its sorted key names (no value is kept), the last pass that saw it, and the last pass that saw the content before it); and per check how many results in a row it had (the hourly pass's `config-check`, `readcheck`, `witness-light`, `volume`, `pgstate`, `changes`, `push`, `backups` and one `clean:<record>` line per open finding, volume, database state, change, push or backup record; the light pass's `units`, `witness-hourly`, `pg`, `ready`, `alertunit` and `journal:<class>`, and its last database answer `db`, `/ready` status `ready-code`, what it saw of the daemon `daemon`, and one `seen:journal:<unit>` line per open `journal-dropped` record, `spool` and `shipfail` (the spool listing, and the passes in a row whose shipper journal held an error or none), and one `seen:<record>` line per open `gateway-dup` or `ship-dropped` record, the first with the records the gateway counted lost since the open) | root:root | `deploy/witness.sh#light_pass` and `deploy/witness.sh#hourly_pass`, under the lock, each replacing only its own lines |
| `/var/lib/propolis/witness/readcheck` | 0600, one `R` line per alert target (`#readcheck v1`): a hash of its URL and topic (never the topic), when the anonymous-read check last ran and its class, the last definite answer and when, the token's class, and the status code of each read path | root:root | `deploy/witness.sh#rc_store`, under the lock, after each hourly pass and after a light pass that found the target changed |
| `/var/lib/propolis/witness/hook/<unit>` | 0700 directory; 0600 files (`#hook v1`) | root:root | `deploy/alert-lib.sh#_pa_hook_spool`, only when the record step could not take the lock or had little time left; removed by the next light pass once taken in |
| `/var/lib/propolis/witness/jcursor/<class>` | 0700 directory; 0600 files, one journal cursor each (`hook`, `guard`, `journald`, `gateway`, `shipper`, `pull`) | root:root | `deploy/witness.sh#jcursor_store`, under the lock, after each light pass whose journal read finished and whose judgement of what it read was written; read back only as a cursor for `journalctl`, after its form is checked and only when neither the file nor the directory is a link; removed when a class's read could not finish on two passes in a row |
| `/run/propolis-witness/` | 0750 | root:propolis | systemd-tmpfiles, from `/etc/tmpfiles.d/propolis.conf` |
| `/run/propolis-witness/hbskip` | 0600, one line: when the heartbeat URL was skipped and why (`core`), never the URL | root:root | `deploy/witness.sh#hbskip_put`, only with a heartbeat URL set, by a light pass that missed the state lock or could write no state (in `/var/lib/propolis/witness/hbskip` when `/run` refuses it too); moved into `meta hb_skip` and removed by the next pass that writes `meta`; lost at reboot |
| `/run/propolis-witness/jcursor/<class>` | 0700 directory; 0600 files | root:root | `deploy/witness.sh#jcursor_store`, in place of the persistent copy while the disk refuses state writes; removed once the persistent copy is written again; lost at reboot |
| `/run/propolis-witness/state.lock` | 0600, empty | root:root | `deploy/alert-lib.sh#pa_lock`, only when the persistent lock cannot be opened |
| `/run/propolis-witness/fallback/` | 0700 | root:root | `deploy/alert-lib.sh#pa_state_write` and `deploy/alert-lib.sh#_pa_hook_spool`, when the persistent directory refuses a write; lost at reboot |
| `/run/propolis-witness/maintenance` | 0600, two lines (`#maintenance v1`) | root:root | `deploy/upgrade.sh` and `deploy/rollback.sh#maint_write` while they restart services, removed when they finish; `deploy/alert-lib.sh#pa_maint_write` for `propolis-status --maint MINUTES`, removed by `--maint 0` |
| `/run/propolis-witness/heartbeat` | 0600, one `B` line per witness pass instance (`#heartbeat v1`): when it last ran, where its state went, `ok` or `partial` | root:root | `deploy/witness.sh#write_heartbeat`, under the lock, every pass |
| `/run/propolis-witness/lockwait` | 0600, one line per witness pass instance: how many passes in a row could not take the lock | root:root | `deploy/witness.sh#lockwait_set`, without the lock, on a pass that missed it; removed by the next pass that gets it |
| `/run/motd.d/` | 0755 | root:root | systemd-tmpfiles, from `/etc/tmpfiles.d/propolis.conf` |
| `/run/motd.d/propolis` | 0600, the four-line login banner | root:root | `deploy/alert-lib.sh#pa_banner_write`, at the end of every light pass and by `propolis-status --maint`; `pam_motd` reads it as root at login |
| `/etc/tmpfiles.d/propolis.conf` | 0644 | root:root | `deploy/provision.sh#propolis-tmpfiles.conf`, from `deploy/propolis-tmpfiles.conf` |
| `/usr/local/sbin/propolis-alert-lib` | 0644 | root:root | `deploy/install.sh#alert-lib.sh` and `deploy/upgrade.sh#alert-lib.sh`, from `deploy/alert-lib.sh` |
| `/usr/local/sbin/propolis-status` | 0755 | root:root | `deploy/install.sh#propolis-status.sh` and `deploy/upgrade.sh#propolis-status.sh`, from `deploy/propolis-status.sh`; the walk reads and never writes |
| `/usr/local/sbin/propolis-witness` | 0755 | root:root | `deploy/install.sh#witness.sh` and `deploy/upgrade.sh#witness.sh`, from `deploy/witness.sh`; run by `propolis-witness@light.service` and `propolis-witness@hourly.service` |
| `/etc/systemd/system/propolis-witness@.service`, `propolis-witness@light.timer`, `propolis-witness@hourly.timer` | 0644 | root:root | `deploy/install.sh#propolis-witness@hourly.timer` and `deploy/upgrade.sh#propolis-witness@hourly.timer`; both scripts enable both timers |
| `/usr/local/lib/propolis/config-check.sh` | 0755 | root:root | `deploy/install.sh#config-check.sh` and `deploy/upgrade.sh#config-check.sh`, from `deploy/config-check.sh` |
| `/usr/local/lib/propolis/listeners-lib.sh` | 0644 | root:root | `deploy/install.sh#listeners-lib.sh` and `deploy/upgrade.sh#listeners-lib.sh`, from `deploy/listeners-lib.sh` |
| `/usr/local/lib/propolis/repo-dir` | 0644, one line: the checkout's absolute path | root:root | `deploy/install.sh#install_generated` and `deploy/upgrade.sh#install_generated` |
| `/usr/local/lib/propolis/install-bins` | 0644, one line: `deploy/upgrade.sh`'s `INSTALL_BINS=(...)` | root:root | `deploy/install.sh#install_generated` and `deploy/upgrade.sh#install_generated` |

- Only root writes in `/var/lib/propolis/witness` and `/run/propolis-witness`. Group `propolis`
  may enter and read them and never write them, and their parents, `/var/lib/propolis` and
  `/run`, are root-owned, so the daemon can neither plant nor replace anything there.
- The lock is root-only because any account that can open it can hold it and stall every root
  writer. `provision.sh` creates it only when it is missing and never replaces it (a new file
  while a writer holds the old one would let a second writer in); one left with another owner
  or mode is corrected in place, and a link or other non-regular file in its place is reported
  and left alone.
- `/run` is empty after every boot, so the two `/run` directories come from the tmpfiles entry,
  which systemd applies at boot and `provision.sh` applies on every install and upgrade
  (`systemd-tmpfiles --create`). They do not come from a unit's `RuntimeDirectory=`, which
  systemd removes when that unit stops. If installing or applying the entry fails,
  `provision.sh` prints a warning and goes on (`deploy/provision.sh#apply_tmpfiles_entry`): no
  service needs either directory in order to start, and stopping there would leave an upgrade
  half done. Fix the cause it shows, then run `sudo ./deploy/provision.sh` again.

## Spool / quarantine (uploaded-artifact capture)

> **Mount requirement:** spool dirs must be backed by `noexec,nosuid,nodev`
> mounts. `install.sh` does **not** do this - the operator must add fstab
> entries (`deploy/install.sh#NOT DONE BY THIS SCRIPT` lists example tmpfs entries). Captured artifacts
> may be live malware.

| Purpose | Env | Default | install.sh dir |
|---|---|---|---|
| ssh uploads | `PROPOLIS_SSH_SPOOL_DIR` | `/var/spool/propolis/ssh` (`sensor-ssh/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-ssh (`deploy/provision.sh#ensure_dir /var/spool/propolis/ssh`) |
| ftp uploads | `PROPOLIS_FTP_SPOOL_DIR` | `/var/spool/propolis/ftp` (`sensor-ftp/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-ftp (`deploy/provision.sh#ensure_dir /var/spool/propolis/ftp`) |
| adb uploads | `PROPOLIS_ADB_SPOOL_DIR` | `/var/spool/propolis/adb` (`sensor-adb/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-adb (`deploy/provision.sh#ensure_dir /var/spool/propolis/adb`) |
| telnet uploads | `PROPOLIS_TELNET_SPOOL_DIR` | `/var/spool/propolis/telnet` (`sensor-telnet/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-telnet (`deploy/provision.sh#ensure_dir /var/spool/propolis/telnet`) |
| tftp uploads | `PROPOLIS_TFTP_SPOOL_DIR` | `/var/spool/propolis/tftp` (`sensor-tftp/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-tftp (`deploy/provision.sh#ensure_dir /var/spool/propolis/tftp`) |
| mqtt uploads | `PROPOLIS_MQTT_SPOOL_DIR` | `/var/spool/propolis/mqtt` (`sensor-mqtt/src/main.rs#DEFAULT_SPOOL_DIR`) | 0750 propolis-mqtt (`deploy/provision.sh#ensure_dir /var/spool/propolis/mqtt`) |
| catchall | (dir granted for symmetry, **unused** - catchall spools no bodies) | `/var/spool/propolis/catchall` | 0750 propolis-catchall (`deploy/provision.sh#ensure_dir /var/spool/propolis/catchall`) |
| fetcher output | `PROPOLIS_SPOOL_ROOT` + `/fetched` (fn `fetch_spool_dir()`) | `/var/spool/propolis/fetched` (`crates/propolis/src/main.rs#fetch_spool_dir`; root `crates/review/src/spool.rs#DEFAULT_SPOOL_ROOT`) | 0750 propolis (`deploy/provision.sh#ensure_dir /var/spool/propolis/fetched`) |
| ops spool root | `PROPOLIS_SPOOL_ROOT` (fn `ops_spool_root()`) | `/var/spool/propolis` (`crates/propolis/src/main.rs#ops_spool_root`; default `crates/review/src/spool.rs#DEFAULT_SPOOL_ROOT`) | 0755 root (`deploy/provision.sh#3/9 creating spool directories (mountpoints only)`) |

- The fetcher output dir has a global byte budget of 1_000_000_000 bytes
  (`FETCH_SPOOL_GLOBAL_BUDGET`, `crates/propolis/src/main.rs#FETCH_SPOOL_GLOBAL_BUDGET`).
- **smtp, redis, http, cred, dns** have **no** spool dir (no `*_SPOOL_DIR` env);
  they capture inline only. Telnet spools only when the shell phase sees a
  binary payload (a Mirai/Gafgyt dropper), never the login/password phase. MQTT
  spools only a PUBLISH payload that passes the `looks_binary` gate, never a text one.

Each of ssh/ftp/adb/telnet/tftp/mqtt also writes a durable per-capture custody manifest
row (`PROPOLIS_<SENSOR>_OUTBOX_DIR`) as soon as a body is sealed - defaults to
`<its own spool dir>/outbox` (e.g. `/var/spool/propolis/ssh/outbox`), not a
separate path, so the write always lands inside that unit's own
`ReadWritePaths` grant. See [environment-variables.md](environment-variables.md#outbox-manifest-sp-b-1b)
for the full variable reference.

## Persistent state

| Purpose | Env | Default | install.sh dir |
|---|---|---|---|
| SSH host key (generated first run, reused) | `PROPOLIS_SSH_HOST_KEY_PATH` | `/var/lib/propolis/ssh/host_key` (`sensor-ssh/src/main.rs#DEFAULT_HOST_KEY_PATH`) | `/var/lib/propolis/ssh` 0750 propolis-ssh (`deploy/provision.sh#ensure_dir /var/lib/propolis/ssh`) |
| intake cursors (log tail position) | `PROPOLIS_CURSOR_DIR` | `/var/lib/propolis/cursors` (`intake/src/main.rs#DEFAULT_CURSOR_DIR`; `propolis/src/config.rs#DEFAULT_CURSOR_DIR`) | 0750 propolis (`deploy/provision.sh#ensure_dir /var/lib/propolis/cursors`) |
| intake quarantine (log lines the database always refuses) | `PROPOLIS_QUARANTINE_DIR` | `/var/lib/propolis/quarantine` (`intake/src/main.rs#DEFAULT_QUARANTINE_DIR`; `propolis/src/config.rs#DEFAULT_QUARANTINE_DIR`) | 0750 propolis (`deploy/provision.sh#ensure_dir /var/lib/propolis/quarantine`); files 0640, never cleaned, capped at 64 MiB / 10,000 records |
| feed publish output | `PROPOLIS_FEED_OUTPUT_DIR` | `/var/lib/propolis/feed/current` (`feed/src/main.rs#DEFAULT_OUTPUT_DIR`; `propolis/src/config.rs#DEFAULT_FEED_OUTPUT_DIR`) | `/var/lib/propolis/feed` 0755 propolis (`deploy/provision.sh#ensure_dir /var/lib/propolis/feed`) |
| GeoIP databases | `PROPOLIS_GEOIP_DIR` | **no default - enrichment disabled when unset** (`geoip_dir` parse, `console/src/main.rs#load_config_from_env`; `feed/src/main.rs#load_config_from_env`) | not created by install.sh |
| aggregated-node writable state | (unit grant) | `/var/lib/propolis` (`deploy/propolis.service#ReadWritePaths=/var/lib/propolis`) | `/var/lib/propolis` 0755 root (`deploy/provision.sh#root-owned, NOT propolis`) |
| ops spool bounded-buffer dir | (const) | `/var/lib/propolis/spool` (`deploy/provision.sh#ensure_dir /var/lib/propolis/spool`) | 0750 propolis |
| public-repo push marker (`last-pushed`, read by `feed-push-stale`) | `PROPOLIS_BLOCKLIST_STATUS_DIR` (the sync script only; the daemon reads the fixed path) | `/var/lib/propolis/blocklist-status/last-pushed` (`propolis/src/ops_alert/conditions/feed.rs#PUSH_MARKER_PATH`) | 0755 propolis-blocklist (`deploy/provision.sh#ensure_dir /var/lib/propolis/blocklist-status`): outside the daemon's feed directory, so the cron never writes where the daemon can plant a link |
| `propolis-blocklist` home (the push's `known_hosts` and deploy key) | (provisioned) | `/var/lib/propolis-blocklist` (`deploy/provision.sh#ensure_dir /var/lib/propolis-blocklist`) | 0750 propolis-blocklist; the operator's checkout (`PROPOLIS_BLOCKLIST_REPO`, default `/var/lib/propolis/blocklist-repo`) is created owned by this account (see [routine procedures](../operations/routine-procedures.md#stage-2---publish-to-a-public-repository-operator-cron)) |
| `propolis-watch` login home (holds `.ssh/authorized_keys` for the forced-command key) | (provisioned) | `/var/lib/propolis-watch` (`deploy/provision.sh#ensure_dir /var/lib/propolis-watch`) | 0750 root:propolis-watch; `.ssh` 0755 root:root; the operator creates `authorized_keys` root:root 0644, so the account can read its keys but never change them (see [live watch](../operations/live-watch.md)) |

- **GeoIP** expects `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb` under
  `PROPOLIS_GEOIP_DIR` (`crates/geoip/src/lib.rs#load`, `crates/geoip/src/lib.rs#load_asn_only`). When the var is unset,
  GeoIP enrichment is simply disabled - GeoLite2 lookups are **local file
  reads, not network requests**. Not created by `install.sh`; the operator
  provisions the files.
- The aggregated node's `ReadWritePaths=/var/lib/propolis` is deliberately wider
  than intake's cursors-and-quarantine grant, because the single process owns cursors,
  quarantine, feed output, and spool together.

## TLS material (per sensor)

Self-signed certificate and key per TLS-capable sensor (http, mqtt, redis, smtp, ftp, cred,
dns), minted by `deploy/provision-tls.sh` (`deploy/provision-tls.sh#TLS_SENSORS`). All seven read
their pair (`PROPOLIS_HTTP_TLS_CERT` and `PROPOLIS_HTTP_TLS_KEY`, `PROPOLIS_MQTT_TLS_CERT` and
`PROPOLIS_MQTT_TLS_KEY`, `PROPOLIS_REDIS_TLS_CERT` and `PROPOLIS_REDIS_TLS_KEY`,
`PROPOLIS_SMTP_TLS_CERT` and `PROPOLIS_SMTP_TLS_KEY`, `PROPOLIS_FTP_TLS_CERT` and
`PROPOLIS_FTP_TLS_KEY`, `PROPOLIS_CRED_TLS_CERT` and `PROPOLIS_CRED_TLS_KEY`,
`PROPOLIS_DNS_TLS_CERT` and `PROPOLIS_DNS_TLS_KEY`, through the read-only
`ReadOnlyPaths=-/etc/propolis/tls` in `deploy/sensor-http.service`,
`deploy/sensor-mqtt.service`, `deploy/sensor-redis.service`, `deploy/sensor-smtp.service`,
`deploy/sensor-ftp.service`, `deploy/sensor-cred.service` and `deploy/sensor-dns.service`). The leading `-` makes the directory
optional to systemd, so a unit still starts where it is absent; a configured pair that cannot be
read refuses to start in-process. See [../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).

| Path | Mode | Owner | Created by |
|---|---|---|---|
| `/etc/propolis/tls` | 0711 | root:root | `deploy/provision.sh#ensure_dir /etc/propolis/tls` |
| `/etc/propolis/tls/<sensor>.key` | 0600 | propolis-`<sensor>` | `deploy/provision-tls.sh#provision-certs`, ownership and mode reasserted by `deploy/provision-tls.sh#chmod "$mode" "$path"` |
| `/etc/propolis/tls/<sensor>.crt` | 0644 | propolis-`<sensor>` | same as the key |

The directory is traverse-only (no read bit) so a sensor opens its own key by name but nobody
can list the directory. A real certificate placed at these paths is kept on re-runs; a symlink
at a path is operator-managed and is not re-owned or re-permissioned.

## Split deployment (gateway and shipper)

Only in a [split deployment](../operations/split-deployment.md). No script creates these
directories; the runbook gives the owners and modes. Both units name their directories in
`ReadWritePaths=` or `ReadOnlyPaths=` without the `-` prefix, so each named directory must exist
before its unit starts: the gateway's spool and state directories and `/etc/propolis/certs`, and
on the collector `/var/lib/propolis/shipper` (the shipper creates `cursors/` and `state/` under it
itself) and `/var/log/propolis`.

| Purpose | Env | Default | Host |
|---|---|---|---|
| gateway spool, one `<collector_id>/events.jsonl` per collector, tailed by intake | `PROPOLIS_GATEWAY_SPOOL_DIR` | `/var/spool/propolis/gateway` (`crates/gateway/src/config.rs#DEFAULT_SPOOL_DIR`) | control plane |
| gateway chain state, `<collector_id>.json` | `PROPOLIS_GATEWAY_STATE_DIR` | `/var/lib/propolis/gateway` (`crates/gateway/src/config.rs#DEFAULT_STATE_DIR`) | control plane |
| shipper read positions, one file per log | `PROPOLIS_SHIPPER_CURSOR_DIR` | `/var/lib/propolis/shipper/cursors` (`crates/shipper/src/config.rs#DEFAULT_CURSOR_DIR`) | collector |
| shipper chain state, `<collector_id>.json`; the batch in flight, `<collector_id>.pending`, present only from before a batch is first sent until its acknowledgement is recorded (at most one frame, under 16 MiB); an unreadable record set aside, `<collector_id>.pending.damaged` | `PROPOLIS_SHIPPER_STATE_DIR` | `/var/lib/propolis/shipper/state` (`crates/shipper/src/config.rs#DEFAULT_STATE_DIR`) | collector |
| mTLS certificates and keys | the `*_CERT_PATH` and `*_KEY_PATH` variables | no default; `/etc/propolis/certs` by convention, read-only to both units (`deploy/gateway.service#ReadOnlyPaths=/etc/propolis/certs`) | both |

## Config

- **Config root `/etc/propolis`** (0755 root, `deploy/provision.sh#ensure_dir /etc/propolis`). Per-service env
  files `/etc/propolis/<service>.env` (mode 0600, `root:root`) carry all
  config **including secrets**, named in each unit's `EnvironmentFile=` (e.g.
  `console.env`, `ssh.env`, `catchall.env`, `propolis.env` at
  `deploy/propolis.service#EnvironmentFile=/etc/propolis/propolis.env`). `install.sh` writes no value into them
  (`deploy/install.sh#OPERATOR-owned /etc/propolis/*.env file`): provisioning (`deploy/env-files.sh`)
  creates each missing one empty and closes any that is open, and the operator populates them.
  Each sensor unit makes every env file it does not load, plus `watch.env`, `migrate.env`,
  `alert.env` and `certs/`, inaccessible by mount (`InaccessiblePaths=`, `-`-prefixed so an
  absent file does not fail the unit); the unit's own file is read by systemd before the
  namespace exists. `alert.env` is reserved for the root shell alert senders, named by
  `deploy/alert-lib.sh#PA_ALERT_ENV_NAME`; nothing reads it yet, no unit loads it and nothing
  creates it, so the sensors are denied it before it holds anything.
- **Derived, secret-free env files** written by deploy scripts, never by hand:
  `/etc/propolis/fleet-listeners.env` (`deploy/fleet-listeners.sh`) and
  `/etc/propolis/watch.env`, root:propolis-watch 0640, holding only the `PROPOLIS_SENSOR_LOGS` line
  copied from `propolis.env` for the live watcher (`deploy/watch-env.sh`, run by `provision.sh`;
  see [live watch](../operations/live-watch.md)).
- **Feed status:** the console reads (read-only)
  `PROPOLIS_FEED_OUTPUT_DIR`/`manifest.json` for its feed-status page; the unit
  grants `ReadOnlyPaths=/var/lib/propolis/feed` (`console.service`).

## Console writes nothing to local disk

Console sessions are in-memory only (`console.service` header: `UMask=0077`, no
`ReadWritePaths`). The console persists no session or state files locally.

## Sockets

The application uses **no** Unix domain sockets. `console.service` omits
`AF_UNIX` from `RestrictAddressFamilies`; no `UnixListener`/`.sock` usage exists
in any sensor or daemon main.

## Database

`DATABASE_URL` (required) is the PostgreSQL connection string for console,
intake, review, feed, and the aggregated `propolis` binary; missing => fail-closed
startup error. The database is the primary data sink but not a filesystem path;
schema is owned by [database.md](database.md).

## See also

- [ports-and-protocols.md](ports-and-protocols.md) - every port and bind.
- [environment-variables.md](environment-variables.md) - exact env-var defaults
  and bounds.
- [../operations/queue-and-spool.md](../operations/queue-and-spool.md) - spool
  lifecycle and mount hardening.
- [../operations/retention.md](../operations/retention.md) - log/spool retention
  and rotation.
