<!--
title: Quickstart
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Quickstart

Build Propolis, run it against a throwaway database on one machine, capture one event,
and look at it in the console. Everything binds to loopback. Nothing here is a
production setup: no systemd sandboxing, no secret files, no TLS, no backups. Do not
expose these listeners to a network you do not control.

You need Linux, the Rust toolchain pinned in `rust-toolchain.toml` (install it with
`rustup`; the pin is picked up automatically), and either podman or Docker for the
database. Building does not need root.

## 1. Build

```bash
cargo build --release
```

This produces `target/release/propolis` and one binary per sensor.

## 2. Start a throwaway database

```bash
podman run -d --name propolis-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 \
  docker.io/library/postgres:18
```

Trust auth with no password is fine only because the container listens on loopback and
will be deleted at the end. The daemon creates its own schema on first start.

## 3. Configure and start the daemon

```bash
mkdir -p /tmp/propolis-eval/ssh /tmp/propolis-eval/cursors /tmp/propolis-eval/spool
export DATABASE_URL='postgres://postgres@127.0.0.1:5432/postgres'
export PROPOLIS_CONSOLE_PASSWORD='choose-a-strong-value'
export PROPOLIS_SENSOR_LOGS='ssh:/tmp/propolis-eval/ssh/events.jsonl'
export PROPOLIS_CURSOR_DIR='/tmp/propolis-eval/cursors'
./target/release/propolis
```

The daemon refuses to start if the console password is empty or the database is
unreachable, and says why. Leave it running and open a second terminal.

## 4. Start one sensor

```bash
export PROPOLIS_SSH_BIND='127.0.0.1:2222'
export PROPOLIS_SSH_LOG_PATH='/tmp/propolis-eval/ssh/events.jsonl'
export PROPOLIS_SSH_SPOOL_DIR='/tmp/propolis-eval/spool'
export PROPOLIS_SSH_HOST_KEY_PATH='/tmp/propolis-eval/ssh/host_key'
./target/release/sensor-ssh
```

Port 2222 avoids needing the capability to bind port 22. The log path is the same file
the daemon was told to tail. The sensor generates a host key on first start and keeps
it at the given path, so the honeypot's fingerprint stays stable across restarts.

## 5. Capture an event

In a third terminal:

```bash
ssh -p 2222 root@127.0.0.1
```

Type any password. The sensor accepts it, presents a fake shell, and records the login
and every command; there is no real shell behind it. Type `exit` when done. The event
appears in the log file within a second:

```bash
tail -n 3 /tmp/propolis-eval/ssh/events.jsonl
```

## 6. Look at it

Open <http://127.0.0.1:8080/> and log in with the password from step 3.

- **Attackers** lists `127.0.0.1` with its score.
- The IP page shows the login and the commands you typed.
- **Live logs** shows the daemon picking the event up.

An `scp` upload to the same port lands a file in `/tmp/propolis-eval/spool`, named by
its SHA-256, and shows on the **Samples** page. Anything a real attacker uploads there
is live malware; this directory is only safe because you put the file in it.

## 7. Tear down

Ctrl-C the sensor, then the daemon, then:

```bash
podman rm -f propolis-pg
rm -rf /tmp/propolis-eval
```

## Next

For a real deployment start from [installation](../operations/installation.md) and
work through the
[production-readiness checklist](../getting-started/production-readiness-checklist.md).
The [console tour](../getting-started/console-tour.md) explains each page.
