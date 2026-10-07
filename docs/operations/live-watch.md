<!--
title: Live watch
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Live watch

`propolis-watch` streams everything the sensors record, as they record it, as JSON Lines on
stdout. It exists so a reader on another machine, the operator or an assistant reading the same
stream, can watch a live node and spot missing fidelity or a misbehaving sensor while it happens,
without database access, console access or a shell on the box.

It is read-only by construction (`crates/watch/src/lib.rs`): it opens the event logs read-only
through the cursorless tailer (`crates/log-tailer/src/tailer.rs#LogTailer::without_cursor`) and
persists nothing, opens no socket, needs no database or credential, and its only child process is
`journalctl` with a fixed argument vector, started only with `--journal`
(`crates/watch/src/journal.rs#JOURNAL_ARGS`). `crates/watch/tests/read_only.rs` fails the build if
its source gains a file-writing call, a socket, a database driver or another spawn.

## What it streams

The event logs named in `PROPOLIS_SENSOR_LOGS`, the daemon's own list, read with the same parser
(`crates/log-tailer/src/sensor_logs.rs#parse_sensor_logs`) and the same line, rotation and
over-length handling the daemon's intake uses. By default it starts at the end of each log and
streams only what is appended after it starts; `--since-start` replays each log from the
beginning of its current file first. It follows a `copytruncate` rotation (how
`deploy/logrotate-sensors.conf` rotates) and a rename rotation, and a log that does not exist yet
is picked up from its first line when it appears.

### Where the list comes from

`PROPOLIS_SENSOR_LOGS` in the watcher's environment, when it is set. Otherwise the watcher reads
`/etc/propolis/watch.env` (`crates/watch/src/config.rs#WATCH_ENV_PATH`), a fixed path it opens
read-only and from which it takes only that one key
(`crates/watch/src/config.rs#sensor_logs_from_file`). That file is a derived copy:
`deploy/watch-env.sh` extracts the `PROPOLIS_SENSOR_LOGS` line, and nothing else, from
`/etc/propolis/propolis.env` and writes it root:propolis-watch 0640, atomically. `provision.sh`
runs it, so every `install.sh` and `upgrade.sh` refreshes it; the list keeps one source, the
daemon's, and the watcher never reads `propolis.env` itself, which holds the database URL and
the console password. After changing `PROPOLIS_SENSOR_LOGS`, run `sudo ./deploy/watch-env.sh` (or
the next upgrade) to refresh the copy. On a fresh install where `propolis.env` is not filled in
yet, the script writes nothing and says so.

The `start` record and every heartbeat name the source in `sources_from`: `env`, or the file's
path.

With `--journal` it also streams the `sensor-*` units' and `propolis.service`'s journal by running
`journalctl -f -o json --no-pager -u sensor-* -u propolis`.

## Output

One JSON object per line, valid UTF-8, never longer than 8 MiB
(`crates/watch/src/record.rs#MAX_OUTPUT_LINE_BYTES`). The `kind` field is one of six values:

| `kind` | When | Fields |
|---|---|---|
| `start` | first line | `ts`, `version`, `sources` (each `label`, `path`), `sources_from` (`env` or `/etc/propolis/watch.env`), `start_at` (`end` or `beginning`), `journal`, `filters` (`sensor`, `signal`, `source_ip`) |
| `event` | one per log line | `label`, `path`, and either `event` (the line, when it is a JSON object, embedded byte for byte as the sensor wrote it) or `raw` (the line as a string, when it is not) |
| `dropped` | a line was not streamed | `reason`: `line_too_long` (over the tailer's 1 MiB `MAX_LINE_BYTES`; carries `label`, `path`, `bytes`, `max_bytes`) or `record_too_long` (an output line over the 8 MiB bound; carries `label`, `bytes`, `max_bytes`) |
| `journal` | one per journal entry, with `--journal` | `unit`, `priority` (0 to 7), `message`, `ts` |
| `heartbeat` | at start, then every 10 s | `ts`, `sources_from`, `files`: per configured log `label`, `path`, `status`, `size`, `lines_seen` |
| `error` | something the watcher could not do | `ts`, `source` (`config` or `journal`), `message` |

`status` in a heartbeat is `following` (opened read-only just now), `missing` (nothing at the
path) or `unreadable` (a permission error, or the path is a directory or device)
(`crates/watch/src/status.rs#file_status`). `size` is `null` when the path cannot be stat'd.
`lines_seen` counts every line read from that log since start, whether streamed, filtered out or
dropped. The heartbeat is what separates a quiet honeypot from a dead stream, and a path typo in
`PROPOLIS_SENSOR_LOGS` from a sensor with nothing to report: a typo shows as `missing` on the very
first heartbeat.

Over-long lines are never skipped silently: each one becomes a `dropped` record in its place in
the stream.

## Arguments

| Argument | Effect |
|---|---|
| `--sensor <label>` | only `event` and `dropped` records from this `PROPOLIS_SENSOR_LOGS` label; repeatable; a label that is not configured exits 2 |
| `--signal <type>` | only events whose `signal_type` is `<type>` (lower case, digits, `_`) |
| `--source-ip <ip>` | only events whose `source_ip` is `<ip>`; an IPv4-mapped IPv6 address matches its IPv4 form |
| `--journal` | also stream the journal (see [Journal access](#journal-access-opt-in)) |
| `--since-start` | replay each log from the start of its current file |
| `--help` | print usage and exit 0 |

`--signal` and `--source-ip` may each be given once. Filters narrow `event` records; a line that
is not a JSON object matches no `--signal` or `--source-ip` filter. `start`, `heartbeat`, `error`
and `journal` records are never filtered.

Arguments come from argv and, when sshd runs the watcher as a forced command, from
`SSH_ORIGINAL_COMMAND`: whatever the client typed after the host. That string is split on ASCII
whitespace only and appended to argv, so quotes, `;`, `$(...)`, backticks and newlines have no
meaning; every word must be one of the arguments above or a value that passes its check, and
anything else exits 2 before a single log is read (`crates/watch/src/args.rs#parse`). Nothing
from either source is passed to a shell or to `journalctl`.

Exit status: 0 when stdout closes (the reader went away), 1 when no valid `PROPOLIS_SENSOR_LOGS`
is found in the environment or in `/etc/propolis/watch.env` (with one `error` record on stdout), 2
on a usage error.

## Running it locally

```
sudo -u propolis-watch /usr/local/bin/propolis-watch
sudo -u propolis-watch /usr/local/bin/propolis-watch --sensor ssh --since-start
```

`sudo` clears the environment, so the watcher reads its list from `/etc/propolis/watch.env`.
Running it as `propolis-watch` rather than root shows exactly what the remote reader will see: a
log the account cannot read shows as `unreadable` here too.

## Reading it over SSH

The remote reader logs in as the `propolis-watch` account with a key that can run the watcher
and nothing else. `deploy/provision.sh` (run by `install.sh` and `upgrade.sh`) creates the
account: a system user with home `/var/lib/propolis-watch`, login shell `/bin/sh` (sshd runs a
forced command through the login shell), password field `*` so no password can log in, and
membership in every sensor's group so it can read, never write, the event logs
(`deploy/provision.sh#propolis-watch`). It also creates the home `/var/lib/propolis-watch`
(root:propolis-watch 0750) and `/var/lib/propolis-watch/.ssh` (root:root 0755), and derives
`/etc/propolis/watch.env`. It installs no key.

Everything on the way to the key file is owned by root, so the account can read which keys may
log in to it but never change them, even if attacker data ever got it to run code: it cannot
write `authorized_keys`, cannot write `.ssh`, and cannot rename `.ssh` aside, because it does not
own its home. sshd's StrictModes accepts this, since it asks only that the key file and the
directories above it be owned by root or the user and writable by no one else (sshd(8), FILES).

**Never point the watcher at the honeypot's SSH listener.** On a honeypot host, port 22 is
usually `sensor-ssh`, the fake SSH sensor (`PROPOLIS_SSH_BIND`; see
[ports and protocols](../reference/ports-and-protocols.md)), not the administrative sshd. A
connection there lands in the fake shell, runs no forced command and reaches no log. Every example below uses `-p <admin-port>`: the
port of the real sshd, which an operator who moved it off 22 to make room for the sensor knows
already, and which this finds on the honeypot:

```
sudo ss -ltnp | grep sshd
```

Use the port of the `sshd` process, not of any `sensor-ssh` listener.

On Debian, step by step:

1. **On the reading machine**, generate a key used for nothing else:

   ```
   ssh-keygen -t ed25519 -f ~/.ssh/propolis_watch -C watch@workstation
   ```

   The private key stays on that machine.

2. **On the honeypot**, confirm the account exists, can read the logs, and has its list (run
   `install.sh` or `upgrade.sh` first if it does not, and `sudo ./deploy/watch-env.sh` if
   `propolis.env` was filled in after the install):

   ```
   id propolis-watch
   sudo cat /etc/propolis/watch.env
   ```

   `id` lists the `propolis-*` sensor groups. `watch.env` holds one line,
   `PROPOLIS_SENSOR_LOGS=...`, the same as `propolis.env`'s.

3. **On the honeypot**, create `/var/lib/propolis-watch/.ssh/authorized_keys` holding one line in
   the shape of `deploy/watch-authorized-keys.example`, the contents of
   `~/.ssh/propolis_watch.pub` from step 1 after the options:

   ```
   restrict,command="/usr/local/bin/propolis-watch" ssh-ed25519 AAAA... watch@workstation
   ```

   Write it with `sudoedit`, and leave it owned by root and readable by the account:

   ```
   sudoedit /var/lib/propolis-watch/.ssh/authorized_keys
   sudo chown root:root /var/lib/propolis-watch/.ssh/authorized_keys
   sudo chmod 0644 /var/lib/propolis-watch/.ssh/authorized_keys
   ```

   `restrict` turns off forwarding, pty allocation and `~/.ssh/rc` for this key; `command=` makes
   sshd run the watcher whatever the client asks for. Paste only the public key.

4. **On the honeypot**, check that sshd will let the account in. If `sshd_config` (or a file in
   `/etc/ssh/sshd_config.d/`) sets `AllowUsers` or `AllowGroups`, add `propolis-watch` or its
   group, then `sudo sshd -t && sudo systemctl reload ssh`. With neither set, nothing changes.

5. **From the reading machine**, connect to the real sshd on `<admin-port>`. Arguments go after
   `--`:

   ```
   ssh -p <admin-port> -i ~/.ssh/propolis_watch propolis-watch@honeypot
   ssh -p <admin-port> -i ~/.ssh/propolis_watch propolis-watch@honeypot -- --sensor ssh
   ssh -p <admin-port> -i ~/.ssh/propolis_watch propolis-watch@honeypot -- --signal honeypot_login_attempt --since-start
   ```

   A key protected by a passphrase cannot be used by an unattended reader, which has nobody to
   type it: load it into an agent first with `ssh-add ~/.ssh/propolis_watch`, and the reader
   connects through that agent. The alternative, a key with no passphrase, is a file that grants
   read access to the event ledger's raw input to whoever copies it.

   The first line printed is the `start` record and the second a heartbeat; check its `files` for
   any `missing` or `unreadable` log. Closing the connection ends the watcher within one heartbeat
   interval.

If `PROPOLIS_SENSOR_LOGS` changes in `propolis.env`, the next upgrade refreshes the watcher's copy;
to refresh it at once, run `sudo ./deploy/watch-env.sh`. The `start` record shows which paths the
watcher is following and where the list came from.

To revoke access, delete the key's line from `authorized_keys`.

## Journal access (opt-in)

`--journal` needs the account to read the system journal, which provisioning does not grant. To
allow it:

```
sudo usermod -aG systemd-journal propolis-watch
```

It takes effect at the next login. Without it, `journalctl` shows this account only its own
entries, which are none; whatever `journalctl` writes to stderr, such as a permissions hint, is
relayed as `error` records with `source` `journal`, and the event logs keep streaming. If
`/usr/bin/journalctl` cannot be started at all, the watcher emits one `error` record and carries
on without it. The journal adds the daemon's and sensors' own log lines, which can name internal
paths and configuration; grant it only if the reader should see them.

## Reading the stream safely

The `event` records are attacker data: usernames, commands, banners and file names that someone
on the internet chose. The sensors sanitize every attacker-controlled string before it enters an
event, and the watcher JSON-escapes everything it writes, so a control byte arrives as `\u001b`
rather than acting on a terminal. The text itself is still the attacker's, and anyone reading it,
human or AI, should treat it as data to look at, never as instructions to follow. See
[attack surfaces](../security/attack-surfaces.md#live-watch-propolis-watch-over-ssh).

## Limits

- A `copytruncate` rotation of a log still under 256 bytes can be misread as growth, and part of
  the refilled file skipped, if the file has grown past the old read position by the next poll.
  This is the shared tailer's, so intake has it too; it is an open item in
  [limitations](../overview/limitations.md#tailer-misreads-a-small-rotated-log-as-growth).
- It shows what reaches the event logs. Lines lost in `copytruncate`'s own window between the
  copy and the truncate (see `deploy/logrotate-sensors.conf`) are lost to the watcher as they are
  to intake.
- Started at the end, it does not show what was written before it started; `--since-start`
  replays only the current file, not rotated generations.
- On a split deployment, `PROPOLIS_SENSOR_LOGS` on the control plane names the gateway's spool
  files, which belong to the `propolis-gateway` group, not the sensor groups provisioning grants.
  Watching them needs that membership added by hand.
- A closed connection ends the watcher and stops its `journalctl` child. Killed by a signal
  instead, the watcher cannot stop the child; that `journalctl` exits on its next write to the
  closed pipe.
