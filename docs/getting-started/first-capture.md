<!--
title: Your first capture
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Your first capture

With the daemon and the SSH sensor from the [quickstart](../manuals/quickstart.md)
running, this is what one event looks like on its way through the system.

## Produce an event

```bash
ssh -p 2222 root@127.0.0.1
```

Any password is accepted. You get a fake shell that answers common commands with
plausible output; nothing you type runs anywhere. A bare connection with `nc` works too
and records a connection without a login.

## Follow it

**The sensor log.** The sensor appends one JSON line per event to the file you pointed
`PROPOLIS_SSH_LOG_PATH` at. The connection, the login and each command are separate
events:

```bash
tail -f /tmp/propolis-eval/ssh/events.jsonl
```

**The ledger.** The daemon tails that file and appends each event to the `event` table.
Each row carries a hash chained to the previous row, which is what the console's
Integrity page later verifies. Table layout is in the
[database reference](../reference/database.md); the event fields and signal names are in
[events and signals](../reference/events-and-signals.md).

**The score.** The source address, `127.0.0.1` here, gets an `ip_score` row. An
authenticated SSH login over TCP marks the address confirmed-real, and after a second
event it is eligible; whether it then reaches a tier depends on how much weight it
accumulates. The weights and thresholds are in
[scoring and feed](../reference/scoring-and-feed.md).

## See it in the console

Open <http://127.0.0.1:8080/> and log in.

- **Live logs** streams the daemon's own log, so you can watch intake pick the event up.
- **Attackers** lists the scored address.
- The address's page shows the login, the commands, and the session they belong to.
- **Review** shows the address once it reaches a tier, waiting for a decision.

## Capture a file

A connection produces an event; an upload produces a sample. Push a file to the same
port:

```bash
scp -P 2222 /etc/hostname root@127.0.0.1:/tmp/
```

The sensor keeps the body in the spool directory, named by its SHA-256, and records an
upload event carrying that hash. The **Samples** page lists it, and the file can be
downloaded from there.

Anything a real attacker uploads through this path is live malware. The spool in a
production install is mounted so nothing in it can execute, and the samples page serves
downloads as opaque attachments, but the file is still whatever the attacker sent.
Handle it only in an isolated analysis environment; see
[malware custody](../security/malware-custody.md).
